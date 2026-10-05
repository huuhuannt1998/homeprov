#!/usr/bin/env python3
"""Run stage0's checks against the ALREADY-RUNNING hub (no reset -- that would
wipe the snapshot stages 1-6 depend on), then stages 1,2,4,5,6 in order."""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from rig import substrate, capability, anchor
import importlib

CFG = {"config_dir": os.path.join(os.path.dirname(HERE), "testbed", "ha-config"),
       "work": "/tmp/homeprov_exp",
       "snapshot": os.path.join(os.path.dirname(HERE), "testbed", "ha-config",
                                "homeprov_out", "snapshot_B.db"),
       "envelope": "pi5_4g", "seed": 0, "window_s": 5,
       "out": os.path.join(HERE, "out")}
os.makedirs(CFG["out"], exist_ok=True)

def emit(name, res):
    p = os.path.join(CFG["out"], "%s_%d.json" % (name, int(time.time())))
    capability.stamp(res, p); print("   -> %s" % p, flush=True)

print("=== stage0 (verification only; hub already running) ===", flush=True)
s0 = {"stage": 0, "host": capability.host_facts(),
      "determinism": substrate.determinism_check(CFG["config_dir"]),
      "note": "reset/boot already performed; not repeated so the snapshot survives"}
s0["GATE_PASS"] = bool(s0["determinism"].get("byte_identical"))
print(json.dumps({k: v for k, v in s0.items() if k != "capability"}, indent=2)[:900], flush=True)
emit("stage0", s0)

for st in ("stage1", "stage2", "stage4", "stage5", "stage6"):
    print("\n=== %s ===" % st, flush=True)
    t0 = time.time()
    try:
        res = importlib.import_module("stages.%s" % st).run(CFG)
    except Exception as e:
        import traceback; res = {"stage": st, "error": traceback.format_exc()[-1500:]}
    res["_elapsed_s"] = round(time.time() - t0, 1)
    print("GATE_PASS=%s  elapsed=%ss" % (res.get("GATE_PASS"), res["_elapsed_s"]), flush=True)
    emit(st, res)
print("\nDRIVER COMPLETE", flush=True)
