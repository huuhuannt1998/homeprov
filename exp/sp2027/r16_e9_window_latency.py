#!/usr/bin/env python3
"""E9 exploratory analyses B5 and B6 (E9_ANALYSIS_PLAN.md; review r5 Z6, Z2, Z12). Labelled exploratory in the paper.

B5  observation window: for each monitor, from its anchored chain, the time a committed row can stay unsealed. For two
    consecutive poll records i-1 and i (whole-poll records, not the parts of the full-history seal), a row committed
    just after record i-1's sealed boundary ("through", an integer second) is first covered by record i, whose anchor
    receipt is recv_ts[i]; the exposure bound for that interval is recv_ts[i] - through[i-1]. Reported: its
    distribution per day and over the week, the gap between consecutive receipts, the seal delay recv_ts - through, and
    every record the monitor itself marked evidence_unobservable (reason and detail).
B6  latency tail: per-poll cost from <monitor>_cost.jsonl (copy_ms is the copy or the direct snapshot with its checks,
    then load, commit, append), with p99, p99.9 and threshold counts the frozen scorer does not report (it gives median,
    p90 and max), the slowest polls with their dominant component, and inter-poll intervals. The first poll (the
    full-history seal, seq_local 1) is reported separately and left out of the steady-state figures.

Day windows are the schedule's day_end windows (schedule.json). Inputs are read only; the output is one JSON file.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import time

MONITORS = ("direct", "copy")


def q(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)


def dist(xs):
    return {"n": len(xs), "median": q(xs, 0.5), "p90": q(xs, 0.9), "p99": q(xs, 0.99), "p999": q(xs, 0.999),
            "max": round(max(xs), 3) if xs else None}


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def day_windows(run_dir):
    s = json.load(open(os.path.join(run_dir, "schedule.json")))
    w = {}
    for e in s["events"]:
        if e.get("type") == "day_end":
            w["day%d" % e["day"]] = tuple(e["window"])
    w["week"] = (min(a for a, _ in w.values()), max(b for _, b in w.values()))
    return w


def chain_polls(path):
    """Whole-poll records of the external monitor (no parts), in chain order: (seq, recv_ts, ts, through, seq_local)."""
    polls, unobs, parts = [], [], 0
    with open(path) as f:
        for l in f:
            r = json.loads(l)
            p = r.get("payload") or {}
            if p.get("observer") != "external-monitor":
                continue
            if p.get("part"):
                parts += 1
                continue
            if p.get("evidence_unobservable"):
                unobs.append({"seq": r.get("seq"), "utc": iso(p.get("ts") or r.get("recv_ts")),
                              "reason": p.get("reason"), "detail": p.get("detail")})
                continue
            if p.get("through") is None or r.get("recv_ts") is None:
                continue
            polls.append((r.get("seq"), float(r["recv_ts"]), float(p.get("ts") or 0), float(p["through"]),
                          p.get("seq_local")))
    return polls, unobs, parts


def b5(polls, unobs, wins):
    out = {}
    for name, (a, b) in wins.items():
        exp, gap, delay = [], [], []
        worst = []
        for (s0, r0, t0, th0, _), (s1, r1, t1, th1, _) in zip(polls, polls[1:]):
            if not (a <= r1 < b):
                continue
            e = r1 - th0
            exp.append(e)
            gap.append(r1 - r0)
            delay.append(r1 - th1)
            worst.append((e, s1, r1))
        worst.sort(reverse=True)
        out[name] = {"exposure_bound_s": dist(exp), "receipt_gap_s": dist(gap), "seal_delay_s": dist(delay),
                     "exposure_over_30s": sum(1 for x in exp if x > 30), "exposure_over_60s": sum(1 for x in exp if x > 60),
                     "largest": [{"exposure_s": round(e, 3), "seq": s, "receipt_utc": iso(r)} for e, s, r in worst[:10]],
                     "unobservable_records": [u for u in unobs if u["utc"] >= iso(a) and u["utc"] < iso(b)]}
    return out


def b6(cost_path, wins):
    rows = []
    with open(cost_path) as f:
        for l in f:
            rows.append(json.loads(l))
    first = [r for r in rows if r.get("seq_local") == 1]
    steady = [r for r in rows if r.get("seq_local") != 1 and r.get("ts") is not None]
    out = {"first_poll": first[:1], "n_rows": len(rows)}
    comps = ("copy_ms", "load_ms", "commit_ms", "append_ms")
    for name, (a, b) in wins.items():
        sel = [r for r in steady if a <= float(r["ts"]) < b]
        tot = [sum((r.get(k) or 0) for k in comps) for r in sel]
        ts = sorted(float(r["ts"]) for r in sel)
        iv = [y - x for x, y in zip(ts, ts[1:])]
        slow = sorted(sel, key=lambda r: -sum((r.get(k) or 0) for k in comps))[:15]
        out[name] = {
            "n_polls": len(sel), "failed": sum(1 for r in sel if r.get("ok") is False),
            "read_path": dict(collections.Counter(str(r.get("read", "copy")) for r in sel)),
            "per_poll_ms": {k: dist([r[k] for r in sel if r.get(k) is not None]) for k in comps},
            "total_ms": dist(tot),
            "total_over_1s": sum(1 for x in tot if x >= 1000), "total_over_5s": sum(1 for x in tot if x >= 5000),
            "append_over_1s": sum(1 for r in sel if (r.get("append_ms") or 0) >= 1000),
            "append_over_5s": sum(1 for r in sel if (r.get("append_ms") or 0) >= 5000),
            "inter_poll_s": dist(iv), "inter_poll_over_30s": sum(1 for x in iv if x > 30),
            "slowest": [{"utc": iso(float(r["ts"])), "seq_local": r.get("seq_local"),
                         "total_ms": round(sum((r.get(k) or 0) for k in comps), 3),
                         "dominant": max(comps, key=lambda k: r.get(k) or 0),
                         **{k: r.get(k) for k in comps}} for r in slow],
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wins = day_windows(a.run_dir)
    res = {"analysis": "E9 exploratory B5 (observation window) and B6 (latency tail)",
           "label": "exploratory", "run_dir": os.path.basename(a.run_dir.rstrip("/")),
           "windows": {k: [iso(x), iso(y)] for k, (x, y) in wins.items()}, "inputs": {}, "monitors": {},
           "script": "exp/sp2027/r16_e9_window_latency.py", "generated_at": iso(time.time())}
    for m in MONITORS:
        cp = os.path.join(a.run_dir, "%s_chain.jsonl" % m)
        cc = os.path.join(a.run_dir, "%s_cost.jsonl" % m)
        res["inputs"][os.path.basename(cp)] = sha(cp)
        res["inputs"][os.path.basename(cc)] = sha(cc)
        polls, unobs, parts = chain_polls(cp)
        res["monitors"][m] = {"chain_poll_records": len(polls), "chain_part_records": parts,
                              "unobservable_records_total": len(unobs),
                              "B5_observation_window": b5(polls, unobs, wins), "B6_latency": b6(cc, wins)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))
    for m in MONITORS:
        mo = res["monitors"][m]
        w5, w6 = mo["B5_observation_window"]["week"], mo["B6_latency"]["week"]
        print("%-6s polls %d unobs %d | exposure med %s p99 %s max %s >30s %d | total_ms med %s p99 %s p999 %s max %s "
              ">=1s %d >=5s %d | inter-poll med %s max %s" % (
                  m, w6["n_polls"], mo["unobservable_records_total"], w5["exposure_bound_s"]["median"],
                  w5["exposure_bound_s"]["p99"], w5["exposure_bound_s"]["max"], w5["exposure_over_30s"],
                  w6["total_ms"]["median"], w6["total_ms"]["p99"], w6["total_ms"]["p999"], w6["total_ms"]["max"],
                  w6["total_over_1s"], w6["total_over_5s"], w6["inter_poll_s"]["median"], w6["inter_poll_s"]["max"]))


if __name__ == "__main__":
    main()
