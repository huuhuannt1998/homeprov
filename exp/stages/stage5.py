"""STAGE 5 — benign. BE-1..BE-11 with T = {}. GATE: BFP <= 0.01."""
import math, os, shutil
from rig import graph, verify, benign, baselines, metrics, capability, markers
from rig.commit import commit_full, GRAN


def _earlier_snapshot(snap, cfg, span):
    """A genuinely EARLIER state, so BE-4 is a real restore and not an identity."""
    import sqlite3
    p = os.path.join(cfg["work"], "s5_earlier.db")
    os.makedirs(cfg["work"], exist_ok=True)
    shutil.copy(snap, p)
    con = sqlite3.connect(p)
    cut = con.execute("SELECT MAX(last_updated_ts) FROM states").fetchone()[0] - span / 3.0
    con.execute("DELETE FROM states WHERE last_updated_ts > ?", (cut,))
    con.execute("DELETE FROM events WHERE time_fired_ts > ?", (cut,))
    con.commit(); con.close()
    return p


def _marker_for(be, snap, span):
    """The lifecycle marker a well-behaved hub would anchor before the operation."""
    import sqlite3
    con = sqlite3.connect(snap)
    mx = con.execute("SELECT MAX(last_updated_ts) FROM states").fetchone()[0]
    con.close()
    if be == "BE-2":
        return markers.marker(markers.PURGE, cutoff_ts=mx - span / 2.0)
    if be == "BE-4":
        return markers.marker(markers.RESTORE, restore_point_ts=mx - span / 3.0)
    if be == "BE-5b":
        return markers.marker(markers.CLOCK_STEP, window=(mx - 200.0, mx + 1.0))
    if be == "BE-3":
        return markers.marker(markers.MIGRATE)
    return None


def run(cfg):
    snap = cfg["snapshot"]
    if not os.path.exists(snap):
        return {"stage": 5, "error": "no snapshot; run stage0 first"}
    os.makedirs(cfg["work"], exist_ok=True)
    base = graph.load(snap)
    anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
    phi = {s: commit_full(base, s) for s in ("homeprov", "b2")}

    # DB-level benign events only; container-level ones (BE-1/6/9) need a live hub
    # Each arm MUST actually stress the system. Earlier revisions silently
    # no-opped (BE-2 purged 0 rows; BE-4 restored an identical file; BE-5 stepped
    # the clock FORWARD, which lands past the anchor and is trivially legitimate)
    # and produced a meaningless BFP = 0.000.
    span = max(n.ts for n in base) - min(n.ts for n in base)
    db_level = {
        "BE-2":  lambda d: benign.be2_purge(d, keep_s=span / 2.0),      # really purges
        "BE-3":  lambda d: benign.be3_migrate(d),
        "BE-4":  lambda d: benign.be4_restore(d, _earlier_snapshot(snap, cfg, span)),
        "BE-5f": lambda d: benign.be5_clock_step(d, +120.0),            # forward: benign
        "BE-5b": lambda d: benign.be5_clock_step(d, -120.0),            # BACKWARD: the hard case
        "BE-7":  lambda d: benign.be7_unavailable(d, "lock.kitchen_door"),
        "BE-11": lambda d: benign.be11_template_context_loss(d, "lock.kitchen_door")}
    arms, fp_hp, fp_b2 = [], 0, 0
    for be, fn in db_level.items():
        db = os.path.join(cfg["work"], "s5_%s.db" % be)
        shutil.copy(snap, db)
        mk = _marker_for(be, snap, span)          # anchored BEFORE the operation
        try:
            applied = fn(db)
        except Exception as e:
            arms.append({"be": be, "error": str(e)}); continue
        after = graph.load(db)
        raw = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
        hp = dict(raw)
        if mk:
            hp.update(markers.filter_violations(raw["violations"], [mk], GRAN, nodes=after))
        b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
        fp_hp += 1 if hp["detected"] else 0
        fp_b2 += 1 if b2["detected"] else 0
        arms.append({"be": be, "applied": applied,
                     "marker": (mk or {}).get("marker"),
                     "excused": hp.get("n_excused", 0),
                     "raw_violations": raw["n_violations"],
                     "HOMEPROV_false_alarm": hp["detected"],
                     "HOMEPROV_violations": hp["n_violations"],
                     "B2_false_alarm": b2["detected"]})
    n = len([a for a in arms if "error" not in a]) or 1
    bfp_hp, bfp_b2 = fp_hp / n, fp_b2 / n
    return {"stage": 5, "arms": arms, "n_benign": n,
            "BFP_homeprov": bfp_hp, "BFP_b2": bfp_b2,
            "GATES": [metrics.gate("BFP", bfp_hp)],
            "GATE_PASS": bfp_hp <= 0.01,
            "note": "container-level BE-1/6/9/10 require a live hub; run in the "
                    "live-hub arm, not the snapshot arm",
            "capability": capability.record("none", "in_process_integration",
                                            cfg.get("seed", 0), 0, cfg.get("window_s", 5))}
