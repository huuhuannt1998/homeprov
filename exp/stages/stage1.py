"""STAGE 1 — Thrust A atomic forgeries FT-1..FT-9.
GATE: at least one class succeeds at SEV-1 or above, else EXIT 3."""
import math, os, shutil
from rig import graph, forge, verify, baselines, metrics, truth, capability
from rig.commit import commit_full
from rig.conf_import import FORGERY_CATALOG


def _adv_context(db):
    """Locate the adversary's actuation context in the snapshot."""
    import sqlite3, json
    con = sqlite3.connect(db)
    r = con.execute(
        """SELECT s.context_id_bin FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id='lock.kitchen_door'
            ORDER BY s.last_updated_ts DESC LIMIT 1""").fetchone()
    con.close()
    return r[0] if r else None


def run(cfg):
    snap = cfg["snapshot"]
    if not os.path.exists(snap):
        return {"stage": 1, "error": "no snapshot at %s; run stage0 first" % snap}
    os.makedirs(cfg["work"], exist_ok=True)

    base_nodes = graph.load(snap)
    anchor_ts = math.floor(max(n.ts for n in base_nodes)) + 1.0
    phi = {s: commit_full(base_nodes, s) for s in ("homeprov", "b2", "b4")}
    adv = _adv_context(snap)
    lo = min(n.ts for n in base_nodes)

    arms = []
    for ft in [k for k, v in FORGERY_CATALOG.items() if v["cls"] in ("del", "rep", "inj")]:
        db = os.path.join(cfg["work"], "s1_%s.db" % ft)
        shutil.copy(snap, db)
        f = forge.Forger(db)
        try:
            if ft == "FT-1":  f.ft1_delete_own_action(adv)
            elif ft == "FT-2": f.ft2_delete_intermediate(adv)
            elif ft == "FT-3": f.ft3_delete_segment(anchor_ts - 3.0, anchor_ts)
            elif ft == "FT-4": f.ft4_reparent(adv, b"P" * 16, "lock.kitchen_door")
            elif ft == "FT-5": f.ft5_reparent_branch(adv, b"P" * 16)
            elif ft == "FT-6":
                import sqlite3
                con = sqlite3.connect(db)
                ids = [r[0] for r in con.execute(
                    "SELECT state_id FROM states ORDER BY last_updated_ts DESC LIMIT 2")]
                con.close()
                if len(ids) == 2: f.ft6_swap_siblings(*ids)
            elif ft == "FT-7":
                f.inject_state("input_boolean.owner_present", "on",
                               b"T" * 16, None, anchor_ts - 2.0)
            elif ft == "FT-8":
                f.inject_event("call_service", {"domain": "person", "service": "see"},
                               b"U" * 16, None, anchor_ts - 2.0)
            elif ft == "FT-9":
                f.inject_event("automation_triggered",
                               {"entity_id": "automation.arrive_home", "name": "Arrive Home"},
                               b"V" * 16, None, anchor_ts - 2.0)
                f.inject_state("lock.kitchen_door", "unlocked", b"V" * 16, None, anchor_ts - 1.5)
        except Exception as e:
            arms.append({"ft": ft, "error": "%s: %s" % (type(e).__name__, e)}); continue

        after = graph.load(db)
        T = truth.truth_set(snap, db)
        hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
        b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
        b4 = baselines.b4_no_edge_binding(after, phi["b4"], anchor_ts)
        from rig import localize
        Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
        universe = len(after)
        arms.append({
            "ft": ft, "sev": FORGERY_CATALOG[ft]["sev"], "cls": FORGERY_CATALOG[ft]["cls"],
            "writes_b": f.writes, "T_size": len(T),
            "HOMEPROV_detected": hp["detected"], "HOMEPROV_violations": hp["n_violations"],
            "B2_detected": b2["detected"], "B4_detected": b4["detected"],
            "LR": metrics.lr_regions(localize.greedy_regions(after, hp["violations"]),
                                     [n.ts for n in base_nodes if n.key in T]) if hp["detected"] else 0.0,
            "LR_elem": metrics.lr(Q, T), "LP": metrics.lp(Q, T),
            "OQ": metrics.oq(Q, T, universe),
            "prop2": localize.check_prop2(after, hp["violations"]) if hp["detected"] else None,
        })

    det = [a for a in arms if a.get("HOMEPROV_detected")]
    return {"stage": 1, "n_arms": len(arms), "arms": arms,
            "GATE_PASS": bool(det),
            "capability": capability.record("mal_integration_v1", "in_process_integration",
                                            cfg.get("seed", 0), 7, cfg.get("window_s", 5))}
