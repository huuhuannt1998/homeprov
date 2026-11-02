#!/usr/bin/env python3
"""R14c (S&P 2027 round 14c, 2026-10-12): the two-host benign floor, reported separately (E1 and E5).

Answers internal review r4, R2 W4: "Report the two-host floor separately: the artifact's r14 file gives 4 of 821 for E1
and E5." Verifies that figure against the runs' own files rather than against the r14 file alone.

WHAT IT READS (saved files only):
  * exp/out/e1_psr_clo_two_host.json (paper_counting_rule.benign_floor: reproduce/verify_all.py's counting rule) and the
    detection file it names (exp/out/e1_psr_clo_detection.json; sha256 checked against the file's record);
  * exp/out/e5_psr_lnk_paper_rule.json (benign_floor, the same rule) and exp/out/e5_psr_lnk_detection.json (its result
    file; sha256 checked against inputs.result_sha256), exp/out/e5_psr_lnk_linked.json (placement);
  * exp/out/r14_benign_rates.json: the r14 pool closure_two_host_E1_E5 that R2 cites, checked against the above;
  * sections/A6_sp_appf.tex: the printed E1 sentence, quoted.
Rates as r14_benign_rates.py: per untouched hour = k / n x 3600; per wall-clock hour = k / window duration x 3600; exact
(Clopper-Pearson, exp/rig/stats.py) intervals scaled the same way.

    python3 exp/sp2027/r14c_two_host_floor.py   -> exp/out/r14c_two_host_floor.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import datetime
import hashlib
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
PAPER = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13", "sections")
DST = os.path.join(os.environ.get("R14C_DRYRUN_DIR") or OUT, "r14c_two_host_floor.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import stats  # noqa: E402

INPUTS = {}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(p):
    INPUTS[os.path.relpath(p, REPO)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def rates(k, n, dur):
    r = stats.clopper_pearson(k, n)
    lo, hi = r["ci_lo"], r["ci_hi"]
    return {"k": k, "n": n, "proportion": k / n, "exact_interval": [lo, hi], "method": r["method"],
            "window_duration_s": dur,
            "per_untouched_hour": {"rate": 3600.0 * k / n, "exact_interval": [3600.0 * lo, 3600.0 * hi]},
            "per_wallclock_hour": {"rate": 3600.0 * k / dur,
                                   "exact_interval": [3600.0 * lo * n / dur, 3600.0 * hi * n / dur]},
            "per_wallclock_day": {"rate": 86400.0 * k / dur,
                                  "exact_interval": [86400.0 * lo * n / dur, 86400.0 * hi * n / dur]}}


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    e1 = read_json(os.path.join(OUT, "e1_psr_clo_two_host.json"))
    e1d_path = os.path.join(REPO, e1["detection_file"]["path"])
    e1d = read_json(e1d_path)
    assert INPUTS[e1["detection_file"]["path"]] == e1["detection_file"]["sha256"], "E1 detection file changed"
    e5 = read_json(os.path.join(OUT, "e5_psr_lnk_paper_rule.json"))
    e5d = read_json(os.path.join(OUT, "e5_psr_lnk_detection.json"))
    assert INPUTS["exp/out/e5_psr_lnk_detection.json"] == e5["inputs"]["result_sha256"], "E5 result file changed"
    e5l = read_json(os.path.join(OUT, "e5_psr_lnk_linked.json"))
    r14 = read_json(os.path.join(OUT, "r14_benign_rates.json"))

    runs = {}
    for tag, rule, det, placement, rule_file in (
            ("e1_psr_clo", e1["paper_counting_rule"], e1d, e1["placement"], "exp/out/e1_psr_clo_two_host.json"),
            ("e5_psr_lnk", e5, e5d, e5l["placement"], "exp/out/e5_psr_lnk_paper_rule.json")):
        bf = rule["benign_floor"]["second"]
        w = det["window"]
        runs[tag] = {"rule_file": rule_file, "rule": rule["rule"], "encoding": rule.get("encoding"),
                     "placement": placement, "window": w,
                     "second": {**rates(bf["k"], bf["n"], w["duration_s"]), "mechanisms": bf.get("mechanisms"),
                                "ci_as_saved": bf.get("ci")},
                     "minute": {"k": rule["benign_floor"]["minute"]["k"], "n": rule["benign_floor"]["minute"]["n"],
                                "exact_interval": [stats.clopper_pearson(rule["benign_floor"]["minute"]["k"],
                                                                         rule["benign_floor"]["minute"]["n"])[x]
                                                   for x in ("ci_lo", "ci_hi")]},
                     "detection": {"flagged": rule["flagged"], "attributable": rule["attributable"],
                                   "ambiguous": rule["ambiguous"], "n_trials": rule["n_trials"]}}
        # the saved rounded interval must be the exact one, rounded to three decimals
        lo, hi = runs[tag]["second"]["exact_interval"]
        assert [round(lo, 3), round(hi, 3)] == bf["ci"], (tag, lo, hi, bf["ci"])
    runs["e1_psr_clo"]["shipped_aggregator_floor_not_the_paper_rule"] = e1["benign_violation_floor_shipped_aggregator"]["second"]

    k = sum(r["second"]["k"] for r in runs.values())
    n = sum(r["second"]["n"] for r in runs.values())
    dur = sum(r["window"]["duration_s"] for r in runs.values())
    pooled = {**rates(k, n, dur), "mechanisms": {}}
    for r in runs.values():
        for m, c in (r["second"]["mechanisms"] or {}).items():
            pooled["mechanisms"][m] = pooled["mechanisms"].get(m, 0) + c
    p14 = r14["pools"]["closure_two_host_E1_E5"]
    check = {"r14_pool": "exp/out/r14_benign_rates.json pools.closure_two_host_E1_E5",
             "r14_k_n": [p14["k"], p14["n_untouched_anchored_one_second_segments"]],
             "recomputed_k_n": [k, n],
             "four_of_821_holds": (k, n) == (p14["k"], p14["n_untouched_anchored_one_second_segments"]) == (4, 821),
             "per_run_matches_r14": all(
                 (r14["runs"][t]["k"], r14["runs"][t]["n_untouched_anchored_one_second_segments"])
                 == (runs[t]["second"]["k"], runs[t]["second"]["n"]) for t in runs)}
    assert check["four_of_821_holds"] and check["per_run_matches_r14"], check
    single = r14["pools"]["nine_run_pool_closure_scheme"]
    tex = os.path.join(PAPER, "A6_sp_appf.tex")
    INPUTS[os.path.relpath(tex, REPO)] = sha256_file(tex)
    printed = [s.strip() + "." for line in open(tex) for s in line.split(". ") if "untouched one-second segments failed" in s]
    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14c: the two-host benign floor (closure scheme, authenticated, no coverage; Home Assistant OS VM with a "
                "privileged core, monitor and anchor on a second VM on the same Mac) per run and pooled, with exact "
                "intervals, verified against each run's own counting-rule file",
        "answers": ["R2 W4 (r4): 'Report the two-host floor separately: the artifact's r14 file gives 4 of 821 for E1 "
                    "and E5.'"],
        "runs": runs,
        "pooled_E1_E5": pooled,
        "check_against_r14": check,
        "context_single_host_closure_without_coverage": {
            "source": "exp/out/r14_benign_rates.json pools.nine_run_pool_closure_scheme",
            "k": single["k"], "n": single["n_untouched_anchored_one_second_segments"],
            "exact_interval": single["exact_interval"]},
        "paper_sentences": {"file": "sections/A6_sp_appf.tex", "text": printed,
                            "note": "the paper prints E1's 2 of 530 [0.000, 0.014]; E5's floor and the pooled 4 of 821 "
                                    "are not printed"},
        "caveats": e1["caveats"],
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14c_two_host_floor.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, sha256_file(DST))
    for t, r in runs.items():
        s = r["second"]
        print(t, s["k"], s["n"], s["exact_interval"], s["per_wallclock_hour"], s["mechanisms"])
    print("pooled", k, n, pooled["exact_interval"], pooled["per_untouched_hour"], pooled["per_wallclock_hour"])
    print(printed)


if __name__ == "__main__":
    main()
