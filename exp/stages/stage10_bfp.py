"""STAGE 10 — BFP at a sample size that can actually clear the threshold.

Stage 9 measured 0/36 false alarms. By the rule of three, zero events in n
trials bounds the rate at 3/n, so 36 trials bound BFP only at 0.097 -- an order
of magnitude short of the predeclared <= 0.01. The point estimate was already
zero; what was missing was SAMPLES, not performance.

n >= 300 is required. This runs 7 benign event types across a deployment grid
until that is comfortably exceeded.
"""
import math, os, shutil, sys
from rig import (gen, graph, verify, benign, markers, baselines, stats, capability)
from rig.commit import commit_full, GRAN

WORK = "/tmp/homeprov_bfp"
BG = 24.0
ARMS = [(1800.0, 4000), (7200.0, 6000), (21600.0, 8000), (43200.0, 8000)]
SEEDS = list(range(31, 47))     # n = 4 arms x 16 seeds x 7 events = 448
                                # rule of three: 0/448 bounds BFP at ~0.0067 <= 0.01


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": BG,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "b.db")
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            if len(base) < 200:
                os.remove(clean); continue
            phi = {s: commit_full(base, s) for s in ("homeprov", "b2")}
            head = max(n.ts for n in base)      # anchor AT the head: appends are future
            dep = "gen_%d_%d" % (int(span), seed)

            events = [
                ("BE-2", lambda d: benign.be2_purge(d, keep_s=span / 2.0), "purge"),
                ("BE-3", lambda d: benign.be3_migrate(d), None),
                ("BE-4", lambda d: _restore_from(d, clean, span), "restore"),
                ("BE-5f", lambda d: benign.be5_clock_step(d, +120.0), None),
                ("BE-5b", lambda d: benign.be5_clock_step(d, -120.0), "clock"),
                ("BE-7", lambda d: benign.be7_unavailable(d, "lock.dev_00"), None),
                ("BE-11", lambda d: benign.be11_template_context_loss(d, "lock.dev_00"), None),
            ]
            restore_cut = {"v": None}

            def _restore_from(d, src, sp):
                path, cut = _earlier(src, sp)
                restore_cut["v"] = cut
                benign.be4_restore(d, path)
                return {"be": "BE-4", "cutoff": cut}

            for be, fn, kind in events:
                db = clean + "." + be
                shutil.copy(clean, db)
                try:
                    applied = fn(db)
                except Exception:
                    if os.path.exists(db): os.remove(db)
                    continue
                after = graph.load(db)
                mk = None
                if kind == "purge" and isinstance(applied, dict):
                    mk = markers.marker(markers.PURGE, cutoff_ts=applied["cutoff"])
                elif kind == "restore":
                    # declare the point the restore ACTUALLY used
                    mk = markers.marker(markers.RESTORE,
                                        restore_point_ts=(restore_cut["v"]
                                                          if restore_cut["v"] is not None
                                                          else head - span / 3.0))
                elif kind == "clock":
                    mk = markers.marker(markers.CLOCK_STEP,
                                        window=(head - 200.0, head + 1.0))
                raw = verify.verify(after, phi["homeprov"], head, "homeprov")
                filt = (markers.filter_violations(raw["violations"], [mk], GRAN, nodes=after)
                        if mk else raw)
                b2 = baselines.b2_record_level(after, phi["b2"], head)
                rows.append({"deployment": dep, "be": be, "seed": seed,
                             "hp_alarm": 1.0 if filt["detected"] else 0.0,
                             "b2_alarm": 1.0 if b2["detected"] else 0.0,
                             "raw": raw["n_violations"]})
                os.remove(db)
            os.remove(clean)

    n = len(rows)
    k_hp = int(sum(r["hp_alarm"] for r in rows))
    k_b2 = int(sum(r["b2_alarm"] for r in rows))
    hp = stats.clopper_pearson(k_hp, n)
    b2 = stats.clopper_pearson(k_b2, n)
    per_be = {}
    for be in sorted({r["be"] for r in rows}):
        rs = [r for r in rows if r["be"] == be]
        per_be[be] = {"n": len(rs),
                      "hp": int(sum(r["hp_alarm"] for r in rs)),
                      "b2": int(sum(r["b2_alarm"] for r in rs))}
    return {"stage": 10, "n_trials": n, "BFP_homeprov": hp, "BFP_b2": b2,
            "per_benign_event": per_be,
            "threshold_cleared": hp["ci_hi"] <= 0.01,
            "rule_of_three_note": "zero events in n trials bounds the rate at ~3/n",
            "GATE_PASS": hp["ci_hi"] <= 0.01,
            "capability": capability.record("none", "in_process_integration", 0, 0, 5)}


def _earlier(snap, span):
    """Build a genuinely earlier snapshot AND return the cutoff it used.

    The marker must declare the point the RESTORE actually happened at. Deriving
    it independently (states-only head vs the graph head over states AND events)
    made the marker's claim false, the marker was refused, and BE-4 alarmed in
    17 of 48 deployments -- the same class of defect already fixed for BE-2.
    """
    import sqlite3
    p = os.path.join(WORK, "earlier.db")
    shutil.copy(snap, p)
    con = sqlite3.connect(p)
    a = con.execute("SELECT MAX(last_updated_ts) FROM states").fetchone()[0] or 0.0
    b = con.execute("SELECT MAX(time_fired_ts) FROM events").fetchone()[0] or 0.0
    cut = max(a, b) - span / 3.0
    con.execute("DELETE FROM states WHERE last_updated_ts > ?", (cut,))
    con.execute("DELETE FROM events WHERE time_fired_ts > ?", (cut,))
    con.commit(); con.close()
    return p, cut
