"""E-D -- why post-commit editing matters: laundering ANOTHER principal's
actuation.

E-C shows a resident adversary can forge attribution at WRITE TIME (mint a
Context(user_id=member)) and no commitment can catch it. That is the adversary's
own actuation. This experiment is the complement the review asks for: an
actuation the adversary did NOT control at write time -- a household member's app
unlock, or a second integration's service call -- is already on disk with the
true principal. To relabel it the adversary must EDIT the committed row, and that
edit is exactly what an anchored commitment detects.

Two honest actuations are planted in each deployment and anchored, then
laundered post-commit:
  user_click        : lock state carrying context_user_id_bin=<member>, no parent
  second_integration: lock state caused by a second integration's context
The adversary re-points each to an innocent automation (and, for the user case,
strips the person id). We report misattribution (the framed principal), ops
(db writes), and detection by HOMEPROV and the content-only baseline B2.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, verify, baselines, stats, capability
from rig.commit import commit_full

WORK = "/tmp/homeprov_ed"
SEEDS = [201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212]
MEMBER = bytes.fromhex("11" * 16)          # a household member's user id
INTEG = bytes.fromhex("22" * 16)           # a second integration's context id


def _lock_entity(db):
    con = sqlite3.connect(db)
    r = con.execute("SELECT entity_id FROM states_meta WHERE entity_id LIKE 'lock.%' "
                    "ORDER BY metadata_id LIMIT 1").fetchone()
    con.close()
    return r[0] if r else None


def _innocent_auto_ctx(db, before_ts):
    """An automation's own context, to frame it as the cause."""
    con = sqlite3.connect(db)
    r = con.execute("""SELECT e.context_id_bin FROM events e
                         JOIN event_types et ON et.event_type_id=e.event_type_id
                        WHERE et.event_type='automation_triggered'
                          AND e.time_fired_ts < ? AND e.context_id_bin IS NOT NULL
                        ORDER BY e.time_fired_ts DESC LIMIT 1""", (before_ts,)).fetchone()
    con.close()
    return r[0] if r else None


def _plant(db, entity, ts, ctx, usr, par):
    con = sqlite3.connect(db); cur = con.cursor()
    m = cur.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?",
                    (entity,)).fetchone()[0]
    prev = cur.execute("SELECT state_id FROM states WHERE metadata_id=? "
                       "AND last_updated_ts<? ORDER BY last_updated_ts DESC LIMIT 1",
                       (m, ts)).fetchone()
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                     last_reported_ts,context_id_bin,context_user_id_bin,
                     context_parent_id_bin,origin_idx,old_state_id)
                   VALUES (?,?,?,?,?,?,?,?,0,?)""",
                (m, "unlocked", ts, ts, ts, ctx, usr, par, prev[0] if prev else None))
    sid = cur.lastrowid; con.commit(); con.close()
    return sid


def _row(db, sid):
    con = sqlite3.connect(db)
    r = con.execute("SELECT context_user_id_bin, context_parent_id_bin FROM states "
                    "WHERE state_id=?", (sid,)).fetchone()
    con.close(); return r


def _launder(db, sid, frame_ctx, strip_user):
    con = sqlite3.connect(db); cur = con.cursor()
    if strip_user:
        cur.execute("UPDATE states SET context_user_id_bin=NULL, context_parent_id_bin=? "
                    "WHERE state_id=?", (frame_ctx, sid))
    else:
        cur.execute("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                    (frame_ctx, sid))
    n = cur.rowcount; con.commit(); con.close()
    return n


def run(cfg=None):
    os.makedirs(WORK, exist_ok=True)
    variants = {"user_click": {"det": 0, "n": 0, "mis": 0, "ops": []},
                "second_integration": {"det": 0, "n": 0, "mis": 0, "ops": []},
                "_b2_det": {"user_click": 0, "second_integration": 0}}
    per_seed = []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3, "rate_hr": 100,
             "history": "1d", "bg_ratio": 4.4, "target_nodes": 5000, "span_s": 1800.0,
             "max_nodes": 10**9}
        clean = os.path.join(WORK, "c.db")
        gen.generate(clean, p, seed=seed)
        ent = _lock_entity(clean)
        base = graph.load(clean)
        head = max(n.ts for n in base)
        ts = head - 1.0
        frame = _innocent_auto_ctx(clean, head)
        if not (ent and frame):
            os.remove(clean); continue
        for var in ("user_click", "second_integration"):
            db = clean + "." + var
            shutil.copy(clean, db)
            if var == "user_click":
                sid = _plant(db, ent, ts, os.urandom(16), MEMBER, None)
                true_principal = "user:member"
                strip = True
            else:
                sid = _plant(db, ent, ts, INTEG, None, None)
                true_principal = "integration:second"
                strip = False
            # anchor AFTER the honest actuation exists
            after_plant = graph.load(db)
            anchor_ts = math.floor(head) + 1.0
            phi_hp = commit_full(after_plant, "homeprov")
            phi_b2 = commit_full(after_plant, "b2")
            before = _row(db, sid)
            ops = _launder(db, sid, frame, strip)
            after_row = _row(db, sid)
            misattributed = before != after_row     # the row's principal columns changed
            after_nodes = graph.load(db)
            hp = verify.verify(after_nodes, phi_hp, anchor_ts, "homeprov")
            b2 = baselines.b2_record_level(after_nodes, phi_b2, anchor_ts)
            v = variants[var]
            v["n"] += 1
            v["det"] += 1 if hp["detected"] else 0
            v["mis"] += 1 if misattributed else 0
            v["ops"].append(ops)
            variants["_b2_det"][var] += 1 if b2["detected"] else 0
            per_seed.append({"seed": seed, "variant": var,
                             "true_principal": true_principal,
                             "framed_principal": "automation (innocent)",
                             "ops": ops, "misattributed": misattributed,
                             "homeprov_detected": hp["detected"],
                             "homeprov_violations": hp["n_violations"],
                             "b2_detected": b2["detected"]})
            os.remove(db)
        os.remove(clean)

    out = {"experiment": "E-D",
           "what": "post-commit laundering of an actuation performed by a DIFFERENT "
                   "principal the adversary did not control at write time",
           "why_post_commit_is_forced": "the actuation is already on disk with the "
               "true principal; there is no write-time forgery for a row the "
               "adversary never authored, so relabelling requires editing the "
               "committed row, which the anchored commitment detects",
           "per_seed": per_seed}
    for var in ("user_click", "second_integration"):
        v = variants[var]
        out[var] = {
            "n": v["n"],
            "misattribution": stats.clopper_pearson(v["mis"], v["n"]),
            "homeprov_detection": stats.clopper_pearson(v["det"], v["n"]),
            "b2_content_detection": stats.clopper_pearson(variants["_b2_det"][var], v["n"]),
            "ops_needed_db_writes": {"min": min(v["ops"]), "max": max(v["ops"]),
                                     "typical": v["ops"][0] if v["ops"] else None}}
    out["capability"] = capability.record(
        actor_id="post_commit_launderer", actor_position="in_process_integration",
        seed=SEEDS[0], budget_writes=1, window_s=None,
        knowledge={"controlled_target_actuation_at_write_time": False},
        constraints={"anchor_key_access": False},
        substrate={"kind": "generated_deployment (in-process rig)",
                   "note": "renderer confirmation is the E-C/real-deployment job; "
                           "detection here is HOMEPROV verify() over anchored phi"},
        mission="E-D why post-commit matters")
    return out


if __name__ == "__main__":
    r = run()
    dig = capability.stamp(r, os.path.join(os.path.dirname(__file__), "..", "out",
                                           "e_d_other_principal.json"))
    for var in ("user_click", "second_integration"):
        v = r[var]
        print("%-20s n=%d  misattr=%d/%d  HOMEPROV det=%d/%d CI[%.3f,%.3f]  "
              "B2 det=%d/%d  ops=%s"
              % (var, v["n"], v["misattribution"]["k"], v["n"],
                 v["homeprov_detection"]["k"], v["n"],
                 v["homeprov_detection"]["ci_lo"], v["homeprov_detection"]["ci_hi"],
                 v["b2_content_detection"]["k"], v["n"],
                 v["ops_needed_db_writes"]["typical"]))
    print("digest", dig)
