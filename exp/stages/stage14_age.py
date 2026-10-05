"""STAGE 14 — OQ as a function of EVENT AGE (the laminar retention trade-off).

Laminar retention DELIBERATELY degrades localization granularity with age:
seconds kept 1 hour, minutes 1 day, hours 90 days. The design states the cost
("OQ must be reported as a function of event age") but never measured it.

PREDICTION: OQ is flat while second-granularity is retained, then steps up when
the second segments are pruned and the innermost surviving granularity becomes
minute, then again at hour. It should be a STAIRCASE, not a smooth curve.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, localize, metrics, truth, capability
from rig.commit import commit_full, prune, RETENTION, GRAN

WORK = "/tmp/homeprov_age"
SEEDS = [71, 72, 73]
# age of the tampered event at verification time, in seconds
AGES = [60.0, 900.0, 3000.0, 7200.0, 40000.0, 200000.0]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 4.4,
             "target_nodes": 9000, "span_s": 300000.0, "max_nodes": 10**9}
        clean = os.path.join(WORK, "c.db")
        gen.generate(clean, p, seed=seed)
        base = graph.load(clean)
        head = max(n.ts for n in base)
        phi_full = commit_full(base, "homeprov")

        for age in AGES:
            target_ts = head - age
            con = sqlite3.connect(clean)
            r = con.execute("""SELECT s.context_id_bin, sm.entity_id FROM states s
                                 JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                                WHERE sm.entity_id LIKE 'lock.%'
                                  AND s.context_parent_id_bin IS NOT NULL
                                ORDER BY ABS(s.last_updated_ts - ?) LIMIT 1""",
                            (target_ts,)).fetchone()
            con.close()
            if not r:
                continue
            db = clean + ".f"
            shutil.copy(clean, db)
            f = forge.Forger(db)
            res = f.ft4_reparent(r[0], os.urandom(16), r[1])
            if res.get("rows", 0) == 0:
                os.remove(db); continue
            after = graph.load(db)
            T = truth.truth_set(clean, db)

            # RETENTION APPLIED: prune the commitment as a deployed hub would
            phi_kept = prune(phi_full, head)
            surviving = {g: len(phi_kept.get(g, {})) for g in GRAN}
            v = verify.verify(after, phi_kept, math.floor(head) + 1.0, "homeprov",
                              retention=RETENTION)
            Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
            inner = sorted({x["gran"] for x in v["violations"]},
                           key=lambda g: GRAN[g])[:1]
            rows.append({"seed": seed, "age_s": age, "detected": v["detected"],
                         "innermost_gran": inner[0] if inner else None,
                         "Q": len(Q), "T": len(T),
                         "OQ": metrics.oq(Q, T, len(after)),
                         "LR": metrics.lr_regions(
                             localize.greedy_regions(after, v["violations"]),
                             [n.ts for n in base if n.key in T]) if v["detected"] else 0.0,
                         "surviving_segments": surviving})
            os.remove(db)
        os.remove(clean)

    by_age = {}
    for age in AGES:
        rs = [r for r in rows if r["age_s"] == age]
        if rs:
            by_age["age_%gs" % age] = {
                "n": len(rs),
                "detected": sum(1 for r in rs if r["detected"]),
                "innermost": sorted({r["innermost_gran"] for r in rs}),
                "mean_Q": sum(r["Q"] for r in rs) / len(rs),
                "mean_OQ": sum(r["OQ"] for r in rs) / len(rs),
                "min_LR": min(r["LR"] for r in rs)}
    return {"stage": 14, "rows": rows, "by_age": by_age,
            "retention_policy": {k: v for k, v in RETENTION.items()},
            "prediction": "staircase: OQ steps up as finer granularities are pruned",
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 2, 5)}
