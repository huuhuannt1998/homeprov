"""STAGE 27 (E23) -- detection-window / cost curve.

The abstract asserts a detection-window-versus-cost relationship. This measures
it across the anchor periods the review lists, rather than at the single
five-second point the paper currently reports.

Exposure window W(f): how long a forgery committed at a uniformly random instant
remains un-anchored. Theory says mean = period/2, max = period.
"""
import os, random, time
from rig import gen, graph
from rig.commit import commit_full

WORK = "/tmp/homeprov_w"
PERIODS = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 15.0, 60.0]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
         "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
         "target_nodes": 4000, "span_s": 1800.0, "max_nodes": 10**9}
    db = os.path.join(WORK, "w.db")
    gen.generate(db, p, seed=401)
    nodes = graph.load(db)
    lo, hi = min(n.ts for n in nodes), max(n.ts for n in nodes)
    span = hi - lo
    rnd = random.Random(4)
    phi_full = commit_full(nodes, "homeprov2")
    phi_bytes = sum(len(str(v)) for g in phi_full.values() for v in g.values())
    rows = []
    for period in PERIODS:
        W = [period - ((t - lo) % period) for t in
             (lo + rnd.random() * span for _ in range(4000))]
        anchors_per_day = 86400.0 / period
        chunk = max(1, int(len(nodes) * period / span))
        per_anchor = []
        for k in range(0, min(len(nodes), 40 * chunk), chunk):
            sub = nodes[k:k + chunk] or nodes[:1]
            t0 = time.perf_counter()
            commit_full(sub, "homeprov2")
            per_anchor.append((time.perf_counter() - t0) * 1000.0)
        per_anchor.sort()
        p50 = per_anchor[len(per_anchor) // 2] if per_anchor else 0.0
        p95 = per_anchor[int(len(per_anchor) * 0.95)] if per_anchor else 0.0
        bytes_per_anchor = phi_bytes / max(1.0, span / period)
        rows.append({
            "period_s": period,
            "mean_W_s": sum(W) / len(W),
            "p95_W_s": sorted(W)[int(len(W) * 0.95)],
            "max_W_s": max(W),
            "theory_mean": period / 2.0,
            "anchors_per_day": anchors_per_day,
            "p50_ms": round(p50, 4), "p95_ms": round(p95, 4),
            "duty_cycle_pct": round(100.0 * (p50 / 1000.0) / period, 5),
            "bytes_per_day": round(bytes_per_anchor * anchors_per_day),
        })
    os.remove(db)
    return {"stage": 27, "rows": rows}
