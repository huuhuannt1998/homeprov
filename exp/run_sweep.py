#!/usr/bin/env python3
import json, os, sys, time
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
import importlib
from rig import capability
CFG={'work':'/tmp/homeprov_exp','snapshot':os.path.join(os.path.dirname(HERE),
     'testbed','ha-config','homeprov_out','snapshot_B.db'),
     'seed':0,'window_s':5,'n_deployments':int(sys.argv[1]) if len(sys.argv)>1 else 18}
t0=time.time()
r=importlib.import_module('stages.stage7_sweep').run(CFG)
r['_elapsed_s']=round(time.time()-t0,1)
capability.stamp(r, os.path.join(HERE,'out','stage7_final.json'))
print("deployments=%s rows=%s failures=%s elapsed=%ss" %
      (r['n_deployments'],r['n_rows'],len(r['failures']),r['_elapsed_s']))
print("gates: LR=%s  Miss-R-assert=%s  GATE_PASS=%s" %
      (r['HARD_GATE_LR'],r['HARD_GATE_MISS_R_ASSERT'],r['GATE_PASS']))
print()
print("SUMMARY (bootstrap 95% CI):")
for k,v in r['summary_ci'].items():
    print("   %-4s mean=%.5f  CI [%.5f, %.5f]  n=%d" % (k,v['mean'],v['ci_lo'],v['ci_hi'],v['n']))
print()
print("PREREGISTERED CONTRASTS (paired bootstrap):")
for k,v in r['contrasts'].items():
    print("   %-42s diff=%+.4f  CI [%+.4f, %+.4f]  excludes 0: %s  n=%d" %
          (k,v['mean_diff'],v['ci_lo'],v['ci_hi'],v['excludes_zero'],v['n_pairs']))
if r['failures']: print(); print("failures:", r['failures'][:3])
