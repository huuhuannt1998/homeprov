"""STAGE 7 — the section 11.2 deployment sweep with section 11.5 statistics.

This is what turns n=1 point estimates into the six PREREGISTERED CONTRASTS with
intervals. Every prior stage measured ONE deployment; nothing there carried an
interval, which the design forbids ("no bare point estimate appears in any table
or figure, including the abstract").

PAIRED BY CONSTRUCTION: HOMEPROV and every baseline see the IDENTICAL
deployment, event stream and forgery instance.
HOLDOUT: 60/40. All design choices were tuned on the measured deployment and the
generator's tuning set; the holdout is touched once, at the end.
"""
import math, os, shutil, sqlite3
from rig import (gen, graph, forge, verify, localize, reconstruct, metrics,
                 baselines, truth, stats, deployment, capability)
from rig.commit import commit_full, context_counts, tainted_contexts

WORK = "/tmp/homeprov_sweep"
BG = 4.4          # calibrated: structural error 0.066 vs the real deployment


def _adv_ctx(db):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin, MIN(s.last_updated_ts) FROM states s
                         JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
                        GROUP BY s.context_id_bin ORDER BY 2 DESC LIMIT 1""").fetchone()
    con.close()
    return (r[0], r[1]) if r else (None, None)


def _one(db, kind):
    """Apply one forgery; return (T, forger)."""
    adv, bts = _adv_ctx(db)
    if adv is None:
        return None, None
    f = forge.Forger(db)
    lock = sqlite3.connect(db).execute(
        """SELECT sm.entity_id FROM states s JOIN states_meta sm
             ON sm.metadata_id=s.metadata_id WHERE s.context_id_bin=?
              AND sm.entity_id LIKE 'lock.%' LIMIT 1""", (adv,)).fetchone()
    ent = lock[0] if lock else "lock.dev_00"
    if kind == "FT-4":
        f.ft4_reparent(adv, os.urandom(16), ent)
    elif kind == "FT-1":
        f.ft1_delete_own_action(adv)
    else:                                        # FT-10 composed
        auto = sqlite3.connect(db).execute(
            "SELECT entity_id FROM states_meta WHERE entity_id LIKE 'automation.%' LIMIT 1").fetchone()
        trg = sqlite3.connect(db).execute(
            "SELECT entity_id FROM states_meta WHERE entity_id LIKE 'input_boolean.%' LIMIT 1").fetchone()
        f.ft10_causal_laundering(adv, ent, auto[0] if auto else "automation.auto_00",
                                 trg[0] if trg else "input_boolean.trigger_00", bts)
    return adv, f


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    grid = deployment.grid(limit=cfg.get("n_deployments", 18), seed=cfg.get("seed", 0))
    split = stats.holdout_split([deployment.deployment_id(p) for p in grid],
                                frac=0.6, seed=cfg.get("seed", 0))
    rows, failures = [], []

    for i, params in enumerate(grid):
        did = deployment.deployment_id(params)
        params = dict(params); params["bg_ratio"] = BG
        clean = os.path.join(WORK, "d%02d.db" % i)
        try:
            info = gen.generate(clean, params, seed=1000 + i)
        except Exception as e:
            failures.append({"deployment": did, "error": str(e)}); continue
        base = graph.load(clean)
        if len(base) < 20:
            failures.append({"deployment": did, "error": "too few nodes"}); continue
        anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
        phi = {s: commit_full(base, s) for s in ("homeprov", "b2", "b4")}
        ctx_ref = context_counts(base)
        tattr = truth.attribution_truth(clean)

        for kind in ("FT-4", "FT-1", "FT-10"):
            db = os.path.join(WORK, "d%02d_%s.db" % (i, kind))
            shutil.copy(clean, db)
            adv, f = _one(db, kind)
            if adv is None:
                continue
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            if not T:
                continue
            hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
            b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
            b4 = baselines.b4_no_edge_binding(after, phi["b4"], anchor_ts)
            Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
            if hp["detected"]:
                Q = localize.context_closure(after, hp["violations"], Q)
            R = localize.greedy_regions(after, hp["violations"]) if hp["detected"] else []
            Ttimes = [n.ts for n in base if n.key in T]
            b3 = baselines.b3_whole_log_void(after, hp["detected"])
            acct = reconstruct.reconstruct(after, Q, hp["violations"],
                                           tainted_ctxs=tainted_contexts(ctx_ref, after))
            mt = metrics.miss_taxonomy(hp["detected"], Q, T, acct, tattr,
                                       Q_regions=R, T_times=Ttimes)
            rows.append({
                "deployment": did, "split": "tune" if did in split["tune"] else "holdout",
                "scenario": kind, "seed": 1000 + i, "nodes": len(after),
                "rate_hr": params["rate_hr"], "history": params["history"],
                "interlock": params["interlock"],
                "hp_detect": 1.0 if hp["detected"] else 0.0,
                "b2_detect": 1.0 if b2["detected"] else 0.0,
                "b4_detect": 1.0 if b4["detected"] else 0.0,
                "LR": metrics.lr_regions(R, Ttimes),
                "OQ": metrics.oq(Q, T, len(after)),
                "OQ_B3": metrics.oq(b3["Q"], T, len(after)),
                "RA": metrics.ra(acct, tattr),
                "miss_assert": mt["Miss-R-assert"], "miss_abstain": mt["Miss-R-abstain"],
                "budget_b": f.writes,
            })
            os.remove(db)
        os.remove(clean)

    # ---------------- preregistered contrasts, paired, with intervals ----------
    def col(rs, k): return [r[k] for r in rs]
    rep = [r for r in rows if r["scenario"] == "FT-4"]
    contrasts = {}
    if rep:
        # binary outcomes -> EXACT proportions, not a degenerate bootstrap
        contrasts["C1 HOMEPROV vs B2 on F_rep detection"] = stats.binary_contrast(
            col(rep, "hp_detect"), col(rep, "b2_detect"))
        contrasts["C3 HOMEPROV vs B4 on F_rep detection"] = stats.binary_contrast(
            col(rep, "hp_detect"), col(rep, "b4_detect"))
    if rows:
        contrasts["C2 OQ: HOMEPROV vs B3"] = stats.paired_bootstrap(
            col(rows, "OQ_B3"), col(rows, "OQ"), n=10000)
    summary = {k: stats.ci(col(rows, k), n=10000) for k in ("LR", "OQ", "RA")} if rows else {}
    if rows:   # LR and RA are effectively binary/constant -> exact intervals too
        summary["LR_exact"] = stats.clopper_pearson(
            sum(1 for r in rows if r["LR"] >= 1.0), len(rows))
        summary["MissRassert_exact"] = stats.clopper_pearson(
            sum(1 for r in rows if r["miss_assert"] == 0), len(rows))
    # CONFOUND CHECK: the generator's max_nodes cap downscales high-rate
    # deployments, which can flatten the rate variable and make any
    # OQ-versus-rate model uninformative. Measure the realised spread.
    realised = sorted({r["nodes"] for r in rows})
    rate_spread = sorted({r["rate_hr"] for r in rows})
    # The mixed model needs LONG format: one row per (deployment, scenario,
    # system). The wide rows above carry hp_/b2_/b4_ as separate columns.
    long = []
    for r in rows:
        for sysname, key in (("homeprov", "hp_detect"), ("b2", "b2_detect"),
                             ("b4", "b4_detect")):
            long.append({"deployment": r["deployment"], "scenario": r["scenario"],
                         "seed": r["seed"], "system": sysname, "detect": r[key]})
    me_detect = (stats.mixed_effects(long, "detect") if len(long) > 8
                 else {"available": False})
    # OQ is HOMEPROV-vs-B3 and is already paired; model it against graph shape.
    oq_rows = [{"deployment": r["deployment"], "scenario": r["scenario"],
                "system": "homeprov", "OQ": r["OQ"], "rate_hr": r["rate_hr"]}
               for r in rows]
    me_oq = (stats.mixed_effects(oq_rows, "OQ", fixed="rate_hr")
             if len(oq_rows) > 8 else {"available": False})
    me = {"detection": me_detect, "OQ_vs_rate": me_oq}

    hard_lr = all(r["LR"] >= 1.0 for r in rows)
    hard_assert = all(r["miss_assert"] == 0 for r in rows)
    return {"stage": 7, "n_deployments": len(grid), "n_rows": len(rows),
            "failures": failures, "holdout": {"tune": len(split["tune"]),
                                              "holdout": len(split["holdout"])},
            "generator": {"bg_ratio": BG, "calibration_note":
                          "structural error 0.066 vs the real deployment; residual "
                          "gap with_parent 0.049 generated vs 0.012 real"},
            "summary_ci": summary, "contrasts": contrasts, "mixed_effects": me,
            "confound_check": {"realised_node_counts": realised[:12],
                               "nominal_rates": rate_spread,
                               "note": "if node counts cluster despite varied rates, "
                                       "the max_nodes cap flattened the rate variable "
                                       "and OQ-vs-rate is uninformative"},
            "HARD_GATE_LR": hard_lr, "HARD_GATE_MISS_R_ASSERT": hard_assert,
            "GATE_PASS": hard_lr and hard_assert,
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration",
                                            cfg.get("seed", 0), 7, cfg.get("window_s", 5))}
