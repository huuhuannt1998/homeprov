#!/usr/bin/env python3
"""E9 exploratory analysis B4 (E9_ANALYSIS_PLAN.md; review r5 Z12): each monitor's I/O as a placement cost.

From the harness hostlog (one sample a minute of each monitor container's /proc/1/io), per monitor and per day window
and over the week: bytes through system calls (rchar, wchar; these include reads and writes to tmpfs and the page
cache) and bytes at the block layer (read_bytes, write_bytes; what reaches the disk), with hourly rates (median and max
over the per-sample deltas scaled to an hour). Counter decreases (a container restart) are counted and the new value is
taken as the delta, as the frozen scorer does. Also the host's power source over the run (samples on AC, on battery,
lid closed, minimum battery percent). Inputs are read only; the output is one JSON file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time

KEYS = ("rchar", "wchar", "read_bytes", "write_bytes")


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def q(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def day_windows(run_dir):
    s = json.load(open(os.path.join(run_dir, "schedule.json")))
    w = {"day%d" % e["day"]: tuple(e["window"]) for e in s["events"] if e.get("type") == "day_end"}
    w["week"] = (min(a for a, _ in w.values()), max(b for _, b in w.values()))
    return w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--prefix", default="e9")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    hp = os.path.join(a.run_dir, "hostlog.jsonl")
    hl = [json.loads(l) for l in open(hp)]
    samples = [r for r in hl if r.get("kind") == "sample"]
    wins = day_windows(a.run_dir)
    res = {"analysis": "E9 exploratory B4 (monitor I/O as a placement cost) and host power", "label": "exploratory",
           "inputs": {"hostlog.jsonl": sha(hp), "schedule.json": sha(os.path.join(a.run_dir, "schedule.json"))},
           "windows": {k: [iso(x), iso(y)] for k, (x, y) in wins.items()}, "monitors": {}, "power": {},
           "script": "exp/sp2027/r16_e9_io.py", "generated_at": iso(time.time())}
    for m in ("direct", "copy"):
        c = "io_%s-monitor-%s" % (a.prefix, m)
        samp = [(r["ts"], r[c]) for r in samples if r.get(c)]
        mo = {"samples_with_io": len(samp), "samples_without_io": sum(1 for r in samples if not r.get(c))}
        for name, (x, y) in wins.items():
            sel = [(t, v) for t, v in samp if x <= t < y]
            tot = {k: 0 for k in KEYS}
            rate = {k: [] for k in KEYS}
            resets = 0
            for (t0, v0), (t1, v1) in zip(sel, sel[1:]):
                dt = t1 - t0
                for k in KEYS:
                    d = (v1.get(k) or 0) - (v0.get(k) or 0)
                    if d < 0:
                        resets += 1
                        d = v1.get(k) or 0
                    tot[k] += d
                    if dt > 0:
                        rate[k].append(d * 3600.0 / dt)
            span = sel[-1][0] - sel[0][0] if len(sel) > 1 else 0
            mo[name] = {"samples": len(sel), "span_h": round(span / 3600.0, 3), "counter_resets": resets,
                        "bytes": tot, "GB": {k: round(v / 1e9, 3) for k, v in tot.items()},
                        "GB_per_hour_mean": {k: (round(tot[k] / 1e9 / (span / 3600.0), 3) if span else None) for k in KEYS},
                        "GB_per_hour_median_sample": {k: (round(q(rate[k], 0.5) / 1e9, 3) if rate[k] else None) for k in KEYS},
                        "GB_per_hour_max_sample": {k: (round(max(rate[k]) / 1e9, 3) if rate[k] else None) for k in KEYS}}
        res["monitors"][m] = mo
    for name, (x, y) in wins.items():
        pw = [r.get("power") or {} for r in samples if x <= r["ts"] < y]
        res["power"][name] = {"samples": len(pw), "on_ac": sum(1 for p in pw if p.get("source") == "AC Power"),
                              "on_battery": sum(1 for p in pw if p.get("source") and p.get("source") != "AC Power"),
                              "lid_closed": sum(1 for p in pw if p.get("lid_closed")),
                              "min_percent": min((p["percent"] for p in pw if p.get("percent") is not None), default=None)}
    ts = [r["ts"] for r in samples]
    gaps = [y - x for x, y in zip(ts, ts[1:])]
    res["sampling"] = {"n": len(samples), "median_gap_s": round(q(gaps, 0.5), 3) if gaps else None,
                       "max_gap_s": round(max(gaps), 3) if gaps else None, "gaps_over_300s": sum(1 for g in gaps if g > 300)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))
    for m, mo in res["monitors"].items():
        w = mo["week"]
        print("%-6s week GB %s | GB/h mean %s | resets %d | samples %d (without io %d)" % (
            m, w["GB"], w["GB_per_hour_mean"], w["counter_resets"], w["samples"], mo["samples_without_io"]))
    print("power week", res["power"]["week"], "sampling", res["sampling"])


if __name__ == "__main__":
    main()
