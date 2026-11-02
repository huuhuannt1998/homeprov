"""R13 (round 13): the recorder's write rate on the real deployment during each evaluated run's window.

Section 7 says the benign floor and the late rows that make a trial ambiguous are measured "at the lab write rate" but
gives no rate. This script measures it from the same saved recorder copies the verifier re-checks (reproduce/verify_all.py
runs; the round-12 runs E3 e3_g0_clo / e3_g2_clo and E1 e1_psr_clo from their folders, vouched for by the sha256 the
round-12 result files recorded), reading rows with the shipped monitor's load() so that a row here is a row the monitor
commits (a states row joined to states_meta, an events row joined to event_types).

For each run, over its window [t_start, t_end) from the run's result file:
  - state rows per minute and event rows per minute (rows whose last_updated_ts / time_fired_ts falls in the window,
    divided by the window length in minutes);
  - rows per one-second segment: over the seconds that hold at least one row (a second with no row gets no segment),
    mean, median, 90th percentile and maximum; the same over every second of the window, empty ones counted as 0;
  - the share of the window's seconds that hold at least one row;
  - the three busiest seconds.
Percentiles interpolate linearly between order statistics (as exp/sp2027/r6_window_latency_real.py does). The rows are
those in the saved copy, which was taken after the run: the window's own trial traffic is included, rows deleted by a
trial are not.

    python3 exp/sp2027/r13_write_rate.py [--snapshots DIR | --extracts DIR] [--exp DIR] [--out FILE]

Writes exp/out/r13_write_rate.json and never overwrites.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
import math
import os
import statistics
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_all as VA  # noqa: E402
import r13_subset_test as R13  # noqa: E402  (input resolution and checksum vouching for the round-12 runs)


def q(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def dist(xs):
    return {"n": len(xs), "mean": round(sum(xs) / len(xs), 3), "median": statistics.median(xs),
            "p90": round(q(xs, 0.9), 3), "max": max(xs)}


def measure(rid, cfg, db, scratch):
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    w = res["window"]
    t0, t1 = float(w["t_start"]), float(w["t_end"])
    M = VA.load_monitor(cfg["scheme"], scratch)
    nodes = M.load(db, since=(int(t0 // 3600) - 1) * 3600.0)
    secs = list(range(int(math.ceil(t0)), int(math.floor(t1))))
    lo, hi = secs[0], secs[-1] + 1
    per = collections.Counter()
    kinds = collections.Counter()
    per_kind = collections.defaultdict(collections.Counter)
    for n in nodes:
        if lo <= n[0] < hi:
            s = int(n[0] // 1)
            per[s] += 1
            kinds[n[1][0]] += 1
            per_kind[s][n[1][0]] += 1
    minutes = (hi - lo) / 60.0
    seg = [per[s] for s in secs if per[s] > 0]
    allsec = [per[s] for s in secs]
    busiest = sorted(per.items(), key=lambda x: (-x[1], x[0]))[:3]
    return {"scheme": cfg["scheme"], "window": [t0, t1], "seconds_in_window": len(secs), "minutes": round(minutes, 3),
            "state_rows": kinds["s"], "event_rows": kinds["e"], "rows": kinds["s"] + kinds["e"],
            "state_rows_per_minute": round(kinds["s"] / minutes, 2), "event_rows_per_minute": round(kinds["e"] / minutes, 2),
            "rows_per_minute": round((kinds["s"] + kinds["e"]) / minutes, 2),
            "rows_per_one_second_segment": dist(seg),
            "rows_per_second_including_empty": dist(allsec),
            "seconds_with_at_least_one_row": {"k": len(seg), "n": len(secs), "share": round(len(seg) / len(secs), 4)},
            "busiest_seconds": [{"second": s, "rows": c, "state_rows": per_kind[s]["s"], "event_rows": per_kind[s]["e"]}
                                for s, c in busiest]}, (seg, allsec, kinds, minutes)


def pool(parts):
    seg = [x for p in parts for x in p[0]]
    allsec = [x for p in parts for x in p[1]]
    s = sum(p[2]["s"] for p in parts)
    e = sum(p[2]["e"] for p in parts)
    m = sum(p[3] for p in parts)
    return {"runs": len(parts), "minutes": round(m, 3), "state_rows": s, "event_rows": e,
            "state_rows_per_minute": round(s / m, 2), "event_rows_per_minute": round(e / m, 2),
            "rows_per_minute": round((s + e) / m, 2), "rows_per_one_second_segment": dist(seg),
            "rows_per_second_including_empty": dist(allsec),
            "seconds_with_at_least_one_row": {"k": len(seg), "n": len(allsec), "share": round(len(seg) / len(allsec), 4)}}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None)
    ap.add_argument("--extracts", default=None)
    ap.add_argument("--exp", default=R13.DEFAULT_EXP)
    ap.add_argument("--out", default=os.path.join(OUT, "r13_write_rate.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    tick = time.time()
    src = VA.Inputs(snapshots=a.snapshots) if a.snapshots else (
        VA.Inputs(extracts=a.extracts) if a.extracts else VA.Inputs(snapshots=VA.DEFAULT_SNAP))
    extras = R13.extra_runs(a.exp)
    runs, parts, inputs = {}, {}, {}
    with tempfile.TemporaryDirectory() as scratch:
        for rid in list(VA.RUNS) + list(extras):
            cfg, db, chain, info = R13.resolve(rid, src, extras)
            info.pop("chain", None)
            runs[rid], parts[rid] = measure(rid, cfg, db, scratch)
            runs[rid]["inputs"] = info
            r = runs[rid]
            print(rid, r["state_rows_per_minute"], r["event_rows_per_minute"], r["rows_per_one_second_segment"],
                  r["seconds_with_at_least_one_row"], flush=True)
    single = [p for r, p in parts.items() if r != "e1_psr_clo"]
    wins = sorted((runs[r]["window"][0], runs[r]["window"][1], r) for r in runs)
    overlaps = [[x[2], y[2]] for i, x in enumerate(wins) for y in wins[i + 1:] if y[0] < x[1]]
    out = {"item": "R13: recorder write rate on the real deployment during each evaluated run's window",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "script_sha256": VA.sha256_file(os.path.abspath(__file__)),
           "code_sha256": {"monitor/monitor.py": VA.sha256_file(os.path.join(REPO, "monitor", "monitor.py")),
                           "monitor/monitor_wholerow.py": VA.sha256_file(os.path.join(REPO, "monitor", "monitor_wholerow.py")),
                           "reproduce/verify_all.py": VA.sha256_file(os.path.join(REPO, "reproduce", "verify_all.py")),
                           "exp/sp2027/r13_subset_test.py": VA.sha256_file(os.path.join(REPO, "exp", "sp2027", "r13_subset_test.py"))},
           "result_files_sha256": {"exp/out/" + f: VA.sha256_file(os.path.join(OUT, f)) for f in
                                   sorted({(VA.RUNS.get(r) or extras[r])["result"] for r in runs}
                                          | {"e3_grace_sealing.json", "e1_psr_clo_two_host.json"})},
           "inputs_mode": src.mode,
           "definitions": {"row": "a node of monitor.load(): a states row joined to states_meta or an events row joined "
                                  "to event_types, timestamped by last_updated_ts / time_fired_ts",
                           "window": "[t_start, t_end) of the run's result file, whole seconds",
                           "one_second_segment": "a second of the window holding at least one row (an empty second has "
                                                 "no segment)",
                           "percentiles": "linear interpolation between order statistics"},
           "pooled_single_host_real_deployment": pool(single),
           "pooled_single_host_runs": [r for r in parts if r != "e1_psr_clo"],
           "e1_two_host": "reported per run only (another hub: Home Assistant OS VM, Core 2026.10.0)",
           "runs": runs,
           "not_measured": {"e_c_write_time": "no saved verifier snapshot",
                            "e_d_other_principal_real": "no saved verifier snapshot",
                            "e2_auth": "no run window in its result file (exp/out/e2_auth_real_external.json)"},
           "caveats": ["e_d_auth: the verifier's own snapshot is not in the set; the later recorder copy hp_d2/live is "
                       "used, as verify_all.py does.",
                       "The windows include the trial traffic of each run (actuations and the adversary's edits); rows a "
                       "trial deleted are absent from the saved copy.",
                       "The single-host runs share one deployment; overlapping run windows (listed in "
                       "window_overlaps, empty when none) would count a row twice in the pooled figures."],
           "window_overlaps": overlaps,
           "runtime_s": round(time.time() - tick, 1)}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out["pooled_single_host_real_deployment"], indent=1))


if __name__ == "__main__":
    main()
