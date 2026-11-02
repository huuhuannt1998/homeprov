#!/usr/bin/env python3
"""E9 exploratory analyses B1 and B2 (E9_ANALYSIS_PLAN.md; review r5 Z2, Z1). Labelled exploratory in the paper.

B1  benign false-violation rate with block units instead of i.i.d. seconds: per day, monitor and granularity
    (one-second, minute and hour segments), the untouched anchored segments and the unexcused attributable violations
    among them, with exact (Clopper-Pearson) 95% intervals; pooled over the week; the number of days with any violation
    (k of 7, the day as the unit); and, for comparison, the late-row rule used before coverage on the same seconds
    (existing_rule_violated). The minute and hour units absorb the dependence between neighbouring seconds.
B2  segment-level confusion matrix for the attack batches at one-second granularity: touched (a trial wrote, edited or
    named a row in it) or untouched anchored, by flagged (a violation) or not, per day and monitor and pooled.

Inputs: the frozen scorer's files, read only: the per-day verifier outputs it saved under <run>/verify/ (the
benign_floor block, flagged_seconds, trials) and the score file (<tag>_score.json: touched_seconds, the floor). The
untouched counts are the verifier's own (its counting rule); the touched count is the score file's (the harness reports
against the end-of-day snapshot). Output: one JSON file.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from rig import stats  # noqa: E402  (exp/rig/stats.py: the exact interval the verifier and scorer use)


def cp(k, n):
    """Exact 95% (Clopper-Pearson) interval, as exp/stages/e7_verify.py cp() but kept to six decimals."""
    if n in (None, 0):
        return None
    r = stats.clopper_pearson(k, n)
    return [round(r["ci_lo"], 6), round(r["ci_hi"], 6)]


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def day_file(vdir, m, n):
    fs = [f for f in glob.glob(os.path.join(vdir, "%s_day%d_*.json" % (m, n)))
          if re.fullmatch(r"%s_day%d_[0-9a-f]{12}\.json" % (m, n), os.path.basename(f))]
    assert len(fs) <= 1, fs
    return fs[0] if fs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--score", required=True, help="the frozen scorer's <tag>_score.json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    S = json.load(open(a.score))
    vdir = os.path.join(a.run_dir, "verify")
    res = {"analysis": "E9 exploratory B1 (block intervals for the benign floor) and B2 (segment confusion matrix)",
           "label": "exploratory", "inputs": {os.path.basename(a.score): sha(a.score)}, "days": {}, "week": {},
           "script": "exp/sp2027/r16_e9_floor_matrix.py", "generated_at": iso(time.time())}
    pool = {}
    for n in sorted(int(x) for x in S["days"]):
        d = S["days"][str(n)]
        res["days"][str(n)] = {"touched_seconds_score": d.get("touched_seconds"), "by_monitor": {}}
        for m in ("direct", "copy"):
            f = day_file(vdir, m, n)
            if not f:
                res["days"][str(n)]["by_monitor"][m] = {"missing": True}
                continue
            res["inputs"]["verify/" + os.path.basename(f)] = sha(f)
            v = json.load(open(f))
            bf = v.get("benign_floor") or {}
            sc = ((d.get("by_monitor") or {}).get(m) or {}).get("floor") or {}
            us = (bf.get("untouched_flagged_seconds") or {})
            n_s = bf.get("untouched_anchored_seconds")
            # The verifier lists flagged seconds over the WHOLE chain (earlier days' attack seconds stay flagged and are
            # untouched with respect to this day's trials), while its untouched anchored seconds are the day's; both
            # are scoped here to the day's window [t0, t1), as the scorer's floor is (the Appendix D distinction).
            t0, t1 = d["window"]["t0"], d["window"]["t1"]
            inw = lambda s: t0 <= int(s) < t1
            k_s = sum(1 for s in us.get("seconds") or [] if inw(s))
            assert len(us.get("seconds") or []) == us.get("n", 0), "untouched flagged list truncated"
            k_m = (bf.get("minute") or {}).get("attributable", 0)
            n_m = (bf.get("minute") or {}).get("untouched_anchored")
            k_h = (bf.get("hour") or {}).get("attributable", 0)
            n_h = (bf.get("hour") or {}).get("untouched_anchored")
            flagged = {str(x) for x in v.get("flagged_seconds") or [] if inw(x)}
            unt_flagged = {str(x) for x in us.get("seconds") or [] if inw(x)}
            touched_flagged = len(flagged - unt_flagged)
            touched = d.get("touched_seconds")
            trials = v.get("trials") or []
            row = {
                "B1": {"second": {"k": k_s, "n": n_s, "ci": cp(k_s, n_s)},
                       "minute": {"k": k_m, "n": n_m, "ci": cp(k_m, n_m)},
                       "hour": {"k": k_h, "n": n_h, "ci": cp(k_h, n_h)},
                       "score_file_unexcused_untouched": {g: (sc.get(g) or {}).get("unexcused_untouched")
                                                          for g in ("second", "minute", "hour")},
                       "late_row_rule_untouched_violations": bf.get("existing_rule_violated"),
                       "late_row_rule_cases_in_window": sum(1 for s in bf.get("existing_rule_cases") or [] if inw(s)),
                       "whole_chain_untouched_flagged_seconds_verifier": us.get("n", 0),
                       "whole_chain_note": "earlier days' attack seconds, still flagged, untouched w.r.t. this day's "
                                           "trials; outside this day's window"},
                "B2": {"touched_flagged": touched_flagged,
                       "touched_not_flagged": (touched - touched_flagged) if touched is not None else None,
                       "untouched_flagged": k_s, "untouched_not_flagged": (n_s - k_s) if n_s is not None else None,
                       "trials": len(trials), "trials_detected": sum(1 for t in trials if t.get("detected")),
                       "flagged_seconds_total": len(flagged)}}
            res["days"][str(n)]["by_monitor"][m] = row
            p = pool.setdefault(m, {"s": [0, 0], "m": [0, 0], "h": [0, 0], "late": 0, "days_any": 0, "days": 0,
                                    "tf": 0, "tnf": 0, "uf": 0, "unf": 0, "trials": 0, "det": 0})
            for g, k, nn in (("s", k_s, n_s), ("m", k_m, n_m), ("h", k_h, n_h)):
                p[g][0] += k or 0
                p[g][1] += nn or 0
            p["late"] += bf.get("existing_rule_violated") or 0
            p["days"] += 1
            p["days_any"] += 1 if (k_s or k_m or k_h) else 0
            p["tf"] += touched_flagged
            p["tnf"] += (touched - touched_flagged) if touched is not None else 0
            p["uf"] += k_s
            p["unf"] += (n_s - k_s) if n_s is not None else 0
            p["trials"] += len(trials)
            p["det"] += sum(1 for t in trials if t.get("detected"))
    for m, p in pool.items():
        res["week"][m] = {
            "B1": {"second": {"k": p["s"][0], "n": p["s"][1], "ci": cp(*p["s"])},
                   "minute": {"k": p["m"][0], "n": p["m"][1], "ci": cp(*p["m"])},
                   "hour": {"k": p["h"][0], "n": p["h"][1], "ci": cp(*p["h"])},
                   "days_with_any_violation": {"k": p["days_any"], "n": p["days"], "ci": cp(p["days_any"], p["days"])},
                   "late_row_rule_untouched_violations": p["late"]},
            "B2": {"touched_flagged": p["tf"], "touched_not_flagged": p["tnf"], "untouched_flagged": p["uf"],
                   "untouched_not_flagged": p["unf"], "trials": p["trials"], "trials_detected": p["det"]}}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))
    for m, w in res["week"].items():
        b1, b2 = w["B1"], w["B2"]
        print("%-6s B1 s %d/%d %s | min %d/%d %s | h %d/%d %s | days %d/%d | late-row rule %d" % (
            m, b1["second"]["k"], b1["second"]["n"], b1["second"]["ci"], b1["minute"]["k"], b1["minute"]["n"],
            b1["minute"]["ci"], b1["hour"]["k"], b1["hour"]["n"], b1["hour"]["ci"],
            b1["days_with_any_violation"]["k"], b1["days_with_any_violation"]["n"], b1["late_row_rule_untouched_violations"]))
        print("       B2 touched flagged %d / not %d | untouched flagged %d / not %d | trials %d/%d" % (
            b2["touched_flagged"], b2["touched_not_flagged"], b2["untouched_flagged"], b2["untouched_not_flagged"],
            b2["trials_detected"], b2["trials"]))


if __name__ == "__main__":
    main()
