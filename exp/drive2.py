#!/usr/bin/env python3
"""Re-run every Docker-free stage with all fixes, then stage3 (needs Docker)."""
import importlib, json, os, sys, time
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
from rig import capability
CFG={"config_dir":os.path.join(os.path.dirname(HERE),"testbed","ha-config"),
     "work":"/tmp/homeprov_exp",
     "snapshot":os.path.join(os.path.dirname(HERE),"testbed","ha-config",
                             "homeprov_out","snapshot_B.db"),
     "envelope":"pi5_4g","seed":0,"window_s":5,"out":os.path.join(HERE,"out")}
os.makedirs(CFG["out"],exist_ok=True)
summary={}
for st in ("stage1","stage2","stage4","stage5","stage6","stage3"):
    print("\n=== %s ==="%st,flush=True); t0=time.time()
    try: res=importlib.import_module("stages.%s"%st).run(CFG)
    except Exception:
        import traceback; res={"stage":st,"error":traceback.format_exc()[-1200:]}
    res["_elapsed_s"]=round(time.time()-t0,1)
    p=os.path.join(CFG["out"],"%s_final.json"%st); capability.stamp(res,p)
    summary[st]={"GATE_PASS":res.get("GATE_PASS"),"elapsed":res["_elapsed_s"],
                 "error":("error" in res)}
    print("GATE_PASS=%s elapsed=%ss%s"%(res.get("GATE_PASS"),res["_elapsed_s"],
          "  ERROR" if "error" in res else ""),flush=True)
    if "error" in res: print(res["error"][-600:],flush=True)
print("\n=== SUMMARY ==="); print(json.dumps(summary,indent=2))
