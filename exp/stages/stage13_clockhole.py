"""STAGE 13 — quantify the CLOCK_STEP detection hole as a CURVE, like W(f).

Non-guarantee 11 states that a CLOCK_STEP marker opens a detection hole equal to
its declared window: pure injection inside that window is not detected, because
a genuine backward clock step really does write into recently-sealed time and
the two are information-theoretically indistinguishable there.

That was DISCLOSED but never QUANTIFIED. The design says to measure it exactly
as W(f) is measured. This does that: sweep the declared window and measure the
fraction of injections that escape.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, markers, stats, capability
from rig.commit import commit_full, GRAN

WORK = "/tmp/homeprov_ch"
WINDOWS = [0.0, 10.0, 30.0, 60.0, 120.0, 300.0]     # declared marker window (s)
BACKDATES = [5.0, 20.0, 60.0, 150.0, 400.0]         # how far back the injection sits
SEEDS = [61, 62, 63]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
             "target_nodes": 6000, "span_s": 3600.0, "max_nodes": 10**9}
        clean = os.path.join(WORK, "c.db")
        gen.generate(clean, p, seed=seed)
        base = graph.load(clean)
        head = max(n.ts for n in base)
        anchor_ts = math.floor(head) + 1.0
        phi = commit_full(base, "homeprov")

        for back in BACKDATES:
            db = clean + ".f"
            shutil.copy(clean, db)
            f = forge.Forger(db)
            A, T = os.urandom(16), os.urandom(16)
            ts = head - back
            f.inject_state("input_boolean.trigger_00", "on", T, None, ts - 0.2, "FT-7")
            f.inject_event("automation_triggered",
                           {"entity_id": "automation.auto_00", "name": "auto"},
                           A, T, ts - 0.1, "FT-7")
            after = graph.load(db)
            raw = verify.verify(after, phi, anchor_ts, "homeprov")
            for w in WINDOWS:
                mk = (markers.marker(markers.CLOCK_STEP, window=(head - w, head + 1.0))
                      if w > 0 else None)
                filt = (markers.filter_violations(raw["violations"], [mk], GRAN, nodes=after)
                        if mk else raw)
                rows.append({"seed": seed, "declared_window_s": w,
                             "backdate_s": back,
                             "inside_window": back <= w,
                             "detected": 1.0 if filt["detected"] else 0.0,
                             "raw_violations": raw["n_violations"]})
            os.remove(db)
        os.remove(clean)

    # the hole: injections that ESCAPE detection, by declared window
    curve = {}
    for w in WINDOWS:
        rs = [r for r in rows if r["declared_window_s"] == w]
        escaped = sum(1 for r in rs if r["detected"] == 0.0)
        inside = [r for r in rs if r["inside_window"]]
        outside = [r for r in rs if not r["inside_window"]]
        curve["window_%gs" % w] = {
            "n": len(rs),
            "escaped": escaped,
            "escape_rate": stats.clopper_pearson(escaped, len(rs)),
            "inside_escaped": sum(1 for r in inside if r["detected"] == 0.0),
            "inside_n": len(inside),
            "outside_escaped": sum(1 for r in outside if r["detected"] == 0.0),
            "outside_n": len(outside)}
    return {"stage": 13, "rows": rows, "curve": curve,
            "claim_under_test": ("the hole equals the DECLARED WINDOW exactly: "
                                 "injections inside it escape, injections outside "
                                 "it are always caught"),
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 2, 5)}
