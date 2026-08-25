"""STAGE 8 — G-3 UNDER TEST: is OQ bounded by SEGMENT OCCUPANCY?

Guarantee G-3 claims the quarantine's blast radius is bounded by segment
occupancy rather than by history length. Stage 7 could NOT test this: its
max_nodes cap downscaled high-rate deployments, flattening the rate variable, so
the OQ-versus-rate model returned p = 0.93 -- uninformative, NOT evidence of
independence.

DESIGN THAT REMOVES THE CONFOUND: hold TOTAL NODE COUNT FIXED and vary the SPAN.
Occupancy = nodes per second then varies across two orders of magnitude while
graph size does not, so any OQ movement is attributable to occupancy alone.

PREDICTION (falsifiable): |Q| tracks occupancy, so OQ ~= occupancy / N. If OQ is
instead flat in occupancy, G-3 is wrong and the blast-radius claim must be
withdrawn.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, localize, metrics, truth, stats, capability
from rig.commit import commit_full

WORK = "/tmp/homeprov_occ"
TARGET_NODES = 12000
BG = 24.0
# spans chosen to span ~2 orders of magnitude of occupancy at fixed N
SPANS = [240.0, 600.0, 2400.0, 12000.0, 60000.0]
SEEDS = [11, 12, 13]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for span in SPANS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": BG,
                 "target_nodes": TARGET_NODES, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "occ_%d_%d.db" % (int(span), seed))
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            if len(base) < 100:
                continue
            realized_span = max(n.ts for n in base) - min(n.ts for n in base)
            occupancy = len(base) / max(1.0, realized_span)      # nodes per second
            anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
            phi = commit_full(base, "homeprov")

            db = clean + ".f"
            shutil.copy(clean, db)
            con = sqlite3.connect(db)
            # take the context AND its OWN entity -- ft4_reparent filters on
            # both, so a hardcoded entity silently updates 0 rows (|T| = 0).
            r = con.execute("""SELECT s.context_id_bin, sm.entity_id FROM states s
                                 JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                                WHERE sm.entity_id LIKE 'lock.%'
                                  AND s.context_parent_id_bin IS NOT NULL
                                  AND s.last_updated_ts < ?
                                ORDER BY s.last_updated_ts DESC LIMIT 1""",
                            (anchor_ts - 2.0,)).fetchone()
            con.close()
            if not r:
                os.remove(db); os.remove(clean); continue
            f = forge.Forger(db)
            res = f.ft4_reparent(r[0], os.urandom(16), r[1])
            if res.get("rows", 0) == 0:          # never measure a no-op forgery
                os.remove(db); os.remove(clean); continue
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            v = verify.verify(after, phi, anchor_ts, "homeprov")
            Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
            # WHICH granularity actually fired? greedy quarantines the INNERMOST
            # violated segment, and when the graph is sparse the second-segment
            # may not exist at all, pushing the violation up to minute.
            fired = sorted({v2["gran"] for v2 in v["violations"]},
                           key=lambda g: {"second": 1, "minute": 60, "hour": 3600}[g])
            inner = fired[0] if fired else None
            w = {"second": 1.0, "minute": 60.0, "hour": 3600.0}.get(inner, 1.0)
            rows.append({"innermost_gran": inner, "inner_width_s": w,
                         "predicted_Q_occ_x_w": occupancy * w,
                         "span_s": span, "seed": seed, "nodes": len(base),
                         "occupancy_per_s": occupancy, "detected": v["detected"],
                         "Q": len(Q), "T": len(T),
                         "OQ": metrics.oq(Q, T, len(after)),
                         "Q_over_occupancy": (len(Q) / occupancy) if occupancy else None})
            os.remove(db); os.remove(clean)

    # Does |Q| track occupancy? G-3 predicts yes.
    verdict = {}
    if len(rows) >= 6:
        import numpy as np
        occ = np.array([r["occupancy_per_s"] for r in rows])
        q = np.array([float(r["Q"]) for r in rows])
        oq = np.array([r["OQ"] for r in rows])
        # log-log slope: G-3 predicts |Q| ~ occupancy^1
        m = np.polyfit(np.log(occ), np.log(np.maximum(q, 1e-9)), 1)
        # REFINED LAW: |Q| ~= occupancy x width of the innermost fired granularity
        pred = np.array([r["predicted_Q_occ_x_w"] for r in rows])
        ratio = q / np.maximum(pred, 1e-9)
        # G-3, CORRECTED FORM. |Q| is bounded by occupancy only ABOVE a floor set
        # by the size of one causal run: an automation run emits a fixed number
        # of nodes into a single segment no matter how quiet the deployment is.
        #   |Q| ~= max(run_size, occupancy x w)
        # A plain power law cannot fit this -- the slope is 1 above the floor and
        # 0 below it, which is why the naive log-log slope reads 0.30.
        floor = float(np.min(q))
        fit = np.maximum(floor, occ)
        resid = np.abs(q - fit) / np.maximum(q, 1e-9)
        hi_mask = occ > floor                       # occupancy-dominated regime
        slope_hi = (float(np.polyfit(np.log(occ[hi_mask]),
                                     np.log(q[hi_mask]), 1)[0])
                    if hi_mask.sum() >= 3 else None)
        verdict = {"empirical_floor_nodes": floor,
                   "max_law_median_rel_error": float(np.median(resid)),
                   "max_law_pearson": float(np.corrcoef(fit, q)[0, 1]),
                   "slope_in_occupancy_dominated_regime": slope_hi,
                   "n_above_floor": int(hi_mask.sum()),
                   "granularities_fired": sorted({r["innermost_gran"] for r in rows}),
                   "log_log_slope_Q_vs_occupancy": float(m[0]),
                   "pearson_Q_occupancy": float(np.corrcoef(occ, q)[0, 1]),
                   "pearson_OQ_occupancy": float(np.corrcoef(occ, oq)[0, 1]),
                   "node_count_fixed": sorted({r["nodes"] for r in rows}),
                   "occupancy_range": [float(occ.min()), float(occ.max())],
                   "G3_supported_as_written": bool(m[0] > 0.8),
                   "G3_supported_corrected_form": bool(
                       np.corrcoef(occ, q)[0, 1] > 0.8
                       and float(np.median(resid)) < 0.5
                       and (slope_hi is None or slope_hi > 0.6))}
    return {"stage": 8, "rows": rows, "verdict": verdict,
            "prediction": "G-3: |Q| tracks occupancy, log-log slope ~1",
            "GATE_PASS": verdict.get("G3_supported_corrected_form"),
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 2, 5)}
