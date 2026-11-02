#!/usr/bin/env python3
"""E1: re-run every GENERATED-substrate stage under the calibrated generator
(bg_ratio 4.4, fitted to the real deployment's parent-context fraction) and
write results beside the published ones so every number can be diffed.

Published artifacts in exp/out/ are NEVER touched: output goes to exp/out_recal/.
Resumable -- a stage whose output already exists is skipped.
"""
import os, sys, json, time, traceback
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import importlib

OUT = os.path.join(HERE, "out_recal")
os.makedirs(OUT, exist_ok=True)
CFG = {"config_dir": os.path.join(os.path.dirname(HERE), "testbed", "ha-config"),
       "work": "/tmp/homeprov_recal",
       "snapshot": os.path.join(os.path.dirname(HERE), "testbed", "ha-config",
                                "homeprov_out", "snapshot_B.db"),
       "envelope": "pi5_4g", "seed": 0, "window_s": 5, "out": OUT}
os.makedirs(CFG["work"], exist_ok=True)

# cheapest-first so a long tail never blocks the diff of the headline stages
STAGES = sys.argv[1:] or [
    "stage34_realchar", "stage11_ce", "stage10_bfp", "stage13_clockhole",
    "stage14_age", "stage8_occupancy", "stage17_s4s5", "stage22_ft6_rootcause",
    "stage23_fixed", "stage29_marker_abuse", "stage31_b2c", "stage32_budget",
    "stage20_fairbaseline", "stage24_recon_baselines", "stage27_window",
    "stage7_sweep", "stage9_sweep_scenarios", "stage15_ftsweep",
    "stage33_mincost", "stage25_batch", "stage19_holdout",
    "stage16_scale", "stage28_scale",
]

for name in STAGES:
    dst = os.path.join(OUT, "%s.json" % name)
    if os.path.exists(dst):
        print("SKIP  %s (already done)" % name, flush=True); continue
    t0 = time.time()
    print("RUN   %s ..." % name, flush=True)
    try:
        r = importlib.import_module("stages.%s" % name).run(dict(CFG))
        with open(dst, "w") as f:
            json.dump(r, f, indent=1, default=str)
        print("OK    %s  %.0fs" % (name, time.time() - t0), flush=True)
    except Exception as e:
        with open(dst + ".FAILED", "w") as f:
            f.write(traceback.format_exc())
        print("FAIL  %s  %.0fs  %s: %s" % (name, time.time()-t0, type(e).__name__, e), flush=True)
print("done", flush=True)
