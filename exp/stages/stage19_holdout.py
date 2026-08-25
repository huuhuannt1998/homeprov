"""STAGE 19 — THE HOLDOUT. Run ONCE, at the very end. Never tune against it.

The 60/40 split was fixed in stage 7 with seed 0 and has been SEALED since:
every design choice made after it -- the corrected laminar subsumption, parent
identity binding, per-context counts, lifecycle markers, the retention-aware
verify, the narrowed CLOCK_STEP bound -- was made against the TUNE deployments
and against the measured HA deployment, never against these eight.

This is the honest test of whether those choices generalise or were fitted to
the data that produced them. If holdout results track the tune set, the design
did not overfit. If they diverge, that divergence is the finding and must be
reported as such rather than explained away.
"""
import math, os, shutil, sqlite3
from rig import (gen, graph, forge, verify, localize, reconstruct, metrics,
                 baselines, truth, stats, deployment, capability)
from rig.commit import commit_full, context_counts, tainted_contexts

WORK = "/tmp/homeprov_holdout"
BG = 24.0


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    # reproduce the SEALED split exactly: same grid, same seed as stage 7
    grid = deployment.grid(limit=18, seed=0)
    ids = [deployment.deployment_id(p) for p in grid]
    split = stats.holdout_split(ids, frac=0.6, seed=0)
    held = set(split["holdout"])

    rows = []
    for i, params in enumerate(grid):
        did = deployment.deployment_id(params)
        if did not in held:
            continue                       # TUNE deployments are not touched here
        p = dict(params); p["bg_ratio"] = BG
        clean = os.path.join(WORK, "h%02d.db" % i)
        gen.generate(clean, p, seed=1000 + i)
        base = graph.load(clean)
        if len(base) < 100:
            os.remove(clean); continue
        anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
        phi = {s: commit_full(base, s) for s in ("homeprov", "b2", "b4")}
        ctx_ref = context_counts(base)
        tattr = truth.attribution_truth(clean)
        con = sqlite3.connect(clean)
        r = con.execute("""SELECT s.context_id_bin, sm.entity_id, MIN(s.last_updated_ts)
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
             WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
               AND s.last_updated_ts < ? GROUP BY s.context_id_bin
             ORDER BY 3 DESC LIMIT 1""", (anchor_ts - 2.0,)).fetchone()
        con.close()
        if not r:
            os.remove(clean); continue
        adv, ent, bts = r

        for scen, apply in (
            ("FT-4", lambda f: f.ft4_reparent(adv, os.urandom(16), ent)),
            ("FT-1", lambda f: f.ft1_delete_own_action(adv)),
            ("FT-10", lambda f: f.ft10_causal_laundering(
                adv, ent, "automation.auto_00", "input_boolean.trigger_00", bts)),
        ):
            db = clean + "." + scen
            shutil.copy(clean, db)
            f = forge.Forger(db)
            try:
                apply(f)
            except Exception:
                os.remove(db); continue
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            if not T:
                os.remove(db); continue
            hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
            b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
            b4 = baselines.b4_no_edge_binding(after, phi["b4"], anchor_ts)
            Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
            if hp["detected"]:
                Q = localize.context_closure(after, hp["violations"], Q)
            R = localize.greedy_regions(after, hp["violations"]) if hp["detected"] else []
            Tt = [n.ts for n in base if n.key in T]
            b3 = baselines.b3_whole_log_void(after, hp["detected"])
            acct = reconstruct.reconstruct(after, Q, hp["violations"],
                                           tainted_ctxs=tainted_contexts(ctx_ref, after))
            mt = metrics.miss_taxonomy(hp["detected"], Q, T, acct, tattr,
                                       Q_regions=R, T_times=Tt)
            rows.append({"deployment": did, "scenario": scen,
                         "hp": 1.0 if hp["detected"] else 0.0,
                         "b2": 1.0 if b2["detected"] else 0.0,
                         "b4": 1.0 if b4["detected"] else 0.0,
                         "LR": metrics.lr_regions(R, Tt) if hp["detected"] else 0.0,
                         "OQ": metrics.oq(Q, T, len(after)),
                         "OQ_B3": metrics.oq(b3["Q"], T, len(after)),
                         "RA": metrics.ra(acct, tattr),
                         "miss_assert": mt["Miss-R-assert"]})
            os.remove(db)
        os.remove(clean)

    def col(k): return [r[k] for r in rows]
    rep = [r for r in rows if r["scenario"] == "FT-4"]
    out = {"stage": 19, "n_holdout_deployments": len(held),
           "n_rows": len(rows), "held_ids": sorted(held)}
    if rows:
        out["LR_exact"] = stats.clopper_pearson(
            sum(1 for r in rows if r["LR"] >= 1.0), len(rows))
        out["MissRassert_exact"] = stats.clopper_pearson(
            sum(1 for r in rows if r["miss_assert"] == 0), len(rows))
        out["OQ"] = stats.ci(col("OQ"))
        out["RA"] = stats.ci(col("RA"))
        out["C2_OQ_vs_B3"] = stats.paired_bootstrap(col("OQ_B3"), col("OQ"))
    if rep:
        out["C1_vs_B2"] = stats.binary_contrast([r["hp"] for r in rep],
                                                [r["b2"] for r in rep])
        out["C3_vs_B4"] = stats.binary_contrast([r["hp"] for r in rep],
                                                [r["b4"] for r in rep])
    out["GATE_PASS"] = (all(r["LR"] >= 1.0 for r in rows)
                        and all(r["miss_assert"] == 0 for r in rows)) if rows else None
    out["capability"] = capability.record("mal_integration_v1",
                                          "in_process_integration", 0, 7, 5)
    return out
