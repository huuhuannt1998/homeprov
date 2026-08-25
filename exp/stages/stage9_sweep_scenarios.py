"""STAGE 9 — sweep the results that were still n=1.

Stages 3, 4 and 5 measured reconstruction (S1-S5), BFP and W(f) on ONE
deployment. Those are the numbers a reader would quote, and none carried an
interval. This stage runs them across the generated deployment grid so they
become contrasts C4/C5/C6 with real uncertainty.
"""
import math, os, shutil, sqlite3
from rig import (gen, graph, forge, verify, localize, reconstruct, metrics,
                 baselines, truth, benign, markers, stats, capability)
from rig.commit import commit_full, context_counts, tainted_contexts, GRAN

WORK = "/tmp/homeprov_s9"
BG = 24.0
# spans chosen so minute AND hour segments close, and occupancy varies
ARMS = [(1800.0, 6000), (7200.0, 9000), (21600.0, 12000)]
SEEDS = [21, 22, 23]
FREQS = [1.0, 5.0, 15.0, 60.0]


def _victim(db, before_ts):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin, sm.entity_id, MIN(s.last_updated_ts)
                         FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%'
                          AND s.context_parent_id_bin IS NOT NULL
                          AND s.last_updated_ts < ?
                        GROUP BY s.context_id_bin ORDER BY 3 DESC LIMIT 1""",
                    (before_ts,)).fetchone()
    con.close()
    return r


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    scen_rows, bfp_rows, w_rows = [], [], []

    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": BG,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "d_%d_%d.db" % (int(span), seed))
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            if len(base) < 200:
                os.remove(clean); continue
            dep = "gen_%d_%d" % (int(span), seed)
            anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
            phi = {s: commit_full(base, s) for s in ("homeprov", "b2")}
            ctx_ref = context_counts(base)
            tattr = truth.attribution_truth(clean)
            v0 = _victim(clean, anchor_ts - 2.0)

            # ---- S1..S5 reconstruction ----------------------------------
            if v0:
                adv, ent, bts = v0
                for scen, apply in (
                    ("S1", lambda f: f.ft10_causal_laundering(
                        adv, ent, "automation.auto_00", "input_boolean.trigger_00", bts)),
                    ("S2", lambda f: f.ft11_branch_laundering(adv, os.urandom(16))),
                    ("S3", lambda f: f.ft12_segment_substitution(
                        bts - 2.0, bts + 2.0, ent, "automation.auto_00",
                        "input_boolean.trigger_00")),
                    ("S4", lambda f: f.ft1_delete_own_action(adv)),
                    ("S5", lambda f: f.ft4_reparent(adv, os.urandom(16), ent)),
                ):
                    db = clean + ".%s" % scen
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
                    Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
                    if hp["detected"]:
                        Q = localize.context_closure(after, hp["violations"], Q)
                    R = localize.greedy_regions(after, hp["violations"]) if hp["detected"] else []
                    Tt = [n.ts for n in base if n.key in T]
                    b3 = baselines.b3_whole_log_void(after, hp["detected"])
                    acct = reconstruct.reconstruct(
                        after, Q, hp["violations"],
                        tainted_ctxs=tainted_contexts(ctx_ref, after))
                    mt = metrics.miss_taxonomy(hp["detected"], Q, T, acct, tattr,
                                               Q_regions=R, T_times=Tt)
                    scen_rows.append({
                        "deployment": dep, "scenario": scen, "seed": seed,
                        "nodes": len(after), "detected": 1.0 if hp["detected"] else 0.0,
                        "b2_detected": 1.0 if b2["detected"] else 0.0,
                        "LR": metrics.lr_regions(R, Tt),
                        "OQ": metrics.oq(Q, T, len(after)),
                        "OQ_B3": metrics.oq(b3["Q"], T, len(after)),
                        "RA": metrics.ra(acct, tattr),
                        "miss_assert": mt["Miss-R-assert"],
                        "miss_abstain": mt["Miss-R-abstain"], "budget_b": f.writes})
                    os.remove(db)

            # ---- BFP over the snapshot-arm benign catalog ----------------
            # Anchor the BFP arm at the LAST EXISTING ROW, so anything a benign
            # event appends afterwards is in the anchor's FUTURE -- which is what
            # happens on a live hub. Anchoring past the head made ordinary
            # appends look backdated and produced a spurious BFP of 0.64.
            bfp_anchor = max(n.ts for n in base)
            for be, fn, mk in (
                ("BE-2", lambda d: benign.be2_purge(d, keep_s=span / 2.0),
                 lambda mx: markers.marker(markers.PURGE, cutoff_ts=mx - span / 2.0)),
                ("BE-3", lambda d: benign.be3_migrate(d), lambda mx: markers.marker(markers.MIGRATE)),
                ("BE-5b", lambda d: benign.be5_clock_step(d, -120.0),
                 lambda mx: markers.marker(markers.CLOCK_STEP, window=(mx - 200.0, mx + 1.0))),
                ("BE-7", lambda d: benign.be7_unavailable(d, "lock.dev_00"), lambda mx: None),
            ):
                db = clean + ".%s" % be
                shutil.copy(clean, db)
                mx = max(n.ts for n in base)
                try:
                    applied = fn(db)
                except Exception:
                    os.remove(db); continue
                # a marker must declare the cutoff the operation ACTUALLY used
                if isinstance(applied, dict) and applied.get("cutoff") is not None:
                    mx_eff = applied["cutoff"] + span / 2.0
                else:
                    mx_eff = mx
                after = graph.load(db)
                raw = verify.verify(after, phi["homeprov"], bfp_anchor, "homeprov")
                m = mk(mx_eff)
                filt = (markers.filter_violations(raw["violations"], [m], GRAN, nodes=after)
                        if m else raw)
                b2 = baselines.b2_record_level(after, phi["b2"], bfp_anchor)
                bfp_rows.append({"deployment": dep, "be": be, "seed": seed,
                                 "hp_alarm": 1.0 if filt["detected"] else 0.0,
                                 "b2_alarm": 1.0 if b2["detected"] else 0.0,
                                 "raw_violations": raw["n_violations"]})
                os.remove(db)

            # ---- W(f) ----------------------------------------------------
            t0 = min(n.ts for n in base)
            for period in FREQS:
                ws = [((int((n.ts - t0) // period) + 1) * period) - (n.ts - t0) for n in base]
                ws.sort()
                w_rows.append({"deployment": dep, "seed": seed, "period_s": period,
                               "mean_W": sum(ws) / len(ws),
                               "p95_W": ws[int(len(ws) * 0.95)],
                               "theory_half_period": period / 2.0,
                               "ratio_to_theory": (sum(ws) / len(ws)) / (period / 2.0)})
            os.remove(clean)

    def col(rs, k): return [r[k] for r in rs]
    out = {"stage": 9, "n_scenario_rows": len(scen_rows),
           "n_bfp_rows": len(bfp_rows), "n_w_rows": len(w_rows)}

    if scen_rows:
        out["scenario_ci"] = {k: stats.ci(col(scen_rows, k)) for k in ("LR", "OQ", "RA")}
        out["LR_exact"] = stats.clopper_pearson(
            sum(1 for r in scen_rows if r["LR"] >= 1.0), len(scen_rows))
        out["MissRassert_exact"] = stats.clopper_pearson(
            sum(1 for r in scen_rows if r["miss_assert"] == 0), len(scen_rows))
        out["C2_OQ_vs_B3"] = stats.paired_bootstrap(
            col(scen_rows, "OQ_B3"), col(scen_rows, "OQ"))
        per = {}
        for s in ("S1", "S2", "S3", "S4", "S5"):
            rs = [r for r in scen_rows if r["scenario"] == s]
            if rs:
                per[s] = {"n": len(rs), "OQ": stats.ci(col(rs, "OQ")),
                          "detected": stats.clopper_pearson(
                              int(sum(col(rs, "detected"))), len(rs))}
        out["per_scenario"] = per
    if bfp_rows:
        out["C6_BFP"] = {"homeprov": stats.clopper_pearson(
                             int(sum(col(bfp_rows, "hp_alarm"))), len(bfp_rows)),
                         "b2": stats.clopper_pearson(
                             int(sum(col(bfp_rows, "b2_alarm"))), len(bfp_rows))}
    if w_rows:
        out["C5_W_of_f"] = {}
        for p_ in FREQS:
            rs = [r for r in w_rows if r["period_s"] == p_]
            out["C5_W_of_f"]["period_%gs" % p_] = {
                "mean_W": stats.ci(col(rs, "mean_W")),
                "ratio_to_theory": stats.ci(col(rs, "ratio_to_theory"))}
    hard = (all(r["LR"] >= 1.0 for r in scen_rows) and
            all(r["miss_assert"] == 0 for r in scen_rows)) if scen_rows else None
    out["GATE_PASS"] = hard
    out["capability"] = capability.record("mal_integration_v1",
                                          "in_process_integration", 0, 7, 5)
    return out
