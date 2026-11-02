#!/usr/bin/env python3
"""E10: totals of the frozen scorer's per-trial agreement (A1-BDT, A2-CTX, A3-DEL, A3-DEL-PH), per arm and monitor and
overall, summed from exp/out/e10_main_score.json arms.<ARM>.per_level|per_delay.<lev>.<m>.prediction_agrees {k, n}
(ambiguous trials are already left out of n by the scorer) and cross-checked against the per-trial 'agrees' fields.
A restatement of the scorer's numbers (no new rule). Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_agreement_totals.py [--out exp/out/r16_e10_agreement_totals.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SCORE = os.path.join(ROOT, "exp", "out", "e10_main_score.json")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_agreement_totals.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    s = json.load(open(SCORE))
    out = {"score": {"path": "exp/out/e10_main_score.json", "sha256": sha(SCORE)}, "per_arm": {}, "overall": {}}
    K = N = AMB = T = 0
    for arm in ("BDT", "CTX", "DEL", "DEL-PH"):
        A = s["arms"][arm]
        lv = A.get("per_level") or A.get("per_delay")
        for m in ("direct", "copy"):
            k = sum(v[m]["prediction_agrees"]["k"] for v in lv.values() if v[m]["prediction_agrees"])
            n = sum(v[m]["prediction_agrees"]["n"] for v in lv.values() if v[m]["prediction_agrees"])
            pt = A["per_trial"]
            ag = [r[m]["agrees"] for r in pt]
            amb = sum(1 for x in ag if x is None)
            assert k == sum(1 for x in ag if x is True) and n == sum(1 for x in ag if x is not None), (arm, m)
            out["per_arm"]["%s_%s" % (arm, m)] = {"trials": len(pt), "ambiguous": amb, "scored": n, "agree": k, "disagree": n - k}
            K, N, AMB, T = K + k, N + n, AMB + amb, T + len(pt)
    out["overall"] = {"trial_monitor_pairs": T, "ambiguous": AMB, "scored": N, "agree": K, "disagree": N - K}
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))
    print(json.dumps(out["per_arm"]), json.dumps(out["overall"]))


if __name__ == "__main__":
    main()
