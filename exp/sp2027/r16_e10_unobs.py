#!/usr/bin/env python3
"""E10 exploratory: details of the unobservability arms (A4) and of the registered distinguishability rule that the
frozen scorer's file does not carry. Labelled EXPLORATORY except where a field restates a scorer outcome.

  1. unobservable polls by reason, per stack (e10s, e10u) and monitor, from the chains (H15: no
     schema_object_not_a_table / quick_check_failed), and the maximal runs of unobservable polls;
  2. UL-SHM: every direct poll whose copy began inside each hold [t_hold_start, lock.t_end], with its observability,
     reason and read path (cost log), and the lock's own sampling record;
  3. UL-W: the rows timestamped inside each hold [t_acquired, t_released] and their verdicts under the patched and the
     E9 verifier (the scorer's cached a_end and a_end_e9 verifications), with the largest committed-after lower bound;
  4. INF-T: every poll of both monitors from the start of the inflation to 120 s after the repack (cost log and
     chain), and summaries over the phase in which the 3 GiB table was present;
  5. the registered rule (unobservable run >= 60 s and no hub start within 120 s) on E9's benign week, computed the
     way exp/stages/e10_score.py e9_fp() would have (the scorer was run without --e9-run-dir, so its file has none);
  6. host-log sample gaps (the registered exclusion: a wall-clock gap above 90 s) for e10s and e10u.

Inputs are read only; chains are streamed. Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_unobs.py [--run-dir DIR] [--e9-run-dir DIR] [--out exp/out/r16_e10_unobs.json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
E9RUN = "<research-dir>/HOMEPROV-P13-exp/e9/e9_main2"
MONITORS = ("direct", "copy")
RULE_MIN_S, RULE_HUB_S = 60.0, 120.0


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def jl(path):
    out = []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def dist(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    q = lambda f: xs[min(len(xs) - 1, int(f * (len(xs) - 1) + 0.5))]   # noqa: E731  (the scorer's quantile)
    return {"n": len(xs), "median": q(0.5), "p90": q(0.9), "max": xs[-1], "min": xs[0]}


def stream_polls(chain):
    polls = {}
    with open(chain) as fh:
        for line in fh:
            if not line.strip():
                continue
            cr = json.loads(line)
            p = cr.get("payload") or {}
            if p.get("observer") != "external-monitor" or "coverage" not in p or "seq_local" not in p:
                continue
            for h, own in [(h, False) for h in (p.get("backlog") or [])] + [(p, True)]:
                s = int(h["seq_local"])
                cur = polls.get(s)
                if cur is None or (cur.get("through") is None and h.get("through") is not None) \
                        or (own and not cur.get("own") and h.get("through") is not None):
                    polls[s] = {"seq_local": s, "ts": h.get("ts"), "copy_at": h.get("copy_at"), "wm": h.get("wm"),
                                "through": h.get("through"),
                                "unobservable": bool(h.get("evidence_unobservable") or h.get("unobservable")),
                                "reason": h.get("reason") or (h.get("unobservable") if isinstance(h.get("unobservable"), str) else None),
                                "own": own or bool(cur and cur.get("own"))}
    return polls


def runs(polls):
    """Maximal runs of consecutive unobservable polls in copy_at order (exp/stages/e10_score.py Polls.unobservable_runs)."""
    ps = sorted(polls.values(), key=lambda p: (p.get("copy_at") or 0))
    out, cur = [], None
    for p in ps:
        if p.get("unobservable"):
            t = p.get("copy_at") or p.get("ts")
            if cur is None:
                cur = {"from": t, "to": t, "n": 0, "reasons": collections.Counter(), "seq_first": p["seq_local"]}
            cur["to"] = t
            cur["n"] += 1
            cur["reasons"][str(p.get("reason"))] += 1
        elif cur is not None:
            cur["next_observable"] = p.get("copy_at")
            out.append(cur)
            cur = None
    if cur is not None:
        out.append(cur)
    for r in out:
        r["reasons"] = dict(r["reasons"])
        r["duration_s"] = round(((r.get("next_observable") or r["to"]) - r["from"]), 3) if r["from"] else None
    return out


def cost_by_seq(path):
    return {int(d["seq_local"]): d for d in jl(path) if "seq_local" in d}


def total_ms(c):
    return (c.get("copy_ms") or 0) + (c.get("load_ms") or 0) + (c.get("commit_ms") or 0) + (c.get("append_ms") or 0)


def top_slice(path, key):
    """The value of one top-level key of an indented, key-sorted JSON object, without loading the whole file."""
    import mmap
    with open(path, "rb") as fh:
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        tag = b'\n "%s": ' % key.encode()
        i = m.find(tag)
        if i < 0:
            return None
        j = m.find(b'\n "', i + len(tag))
        if j < 0:
            j = m.rfind(b"\n}")
        s = m[i + len(tag):j].decode().rstrip().rstrip(",")
        return json.loads(s)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--e9-run-dir", default=E9RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_unobs.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    t_begin = time.time()
    inputs = {}
    out = {"what": "E10 unobservability arms and distinguishability rule details (EXPLORATORY)", "inputs": inputs}

    # 1. unobservable polls by reason
    P, C = {}, {}
    out["unobservable_by_stack"] = {}
    for st in ("e10s", "e10u"):
        for m in MONITORS:
            ch = os.path.join(a.run_dir, st, "%s_chain.jsonl" % m)
            co = os.path.join(a.run_dir, st, "%s_cost.jsonl" % m)
            inputs["%s_%s_chain" % (st, m)] = {"path": ch, "sha256": sha(ch)}
            inputs["%s_%s_cost" % (st, m)] = {"path": co, "sha256": sha(co)}
            polls = stream_polls(ch)
            P[(st, m)], C[(st, m)] = polls, cost_by_seq(co)
            rs = runs(polls)
            out["unobservable_by_stack"]["%s_%s" % (st, m)] = {
                "polls": len(polls), "unobservable": sum(1 for p in polls.values() if p["unobservable"]),
                "reasons": dict(collections.Counter(str(p["reason"]) for p in polls.values() if p["unobservable"])),
                "runs": rs}

    # 2. UL-SHM holds
    hold_rows = []
    for f in sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_lock_shm.json"))):
        inputs.setdefault("lock_shm", []).append({"path": f, "sha256": sha(f)})
        r = json.load(open(f))
        lk = r.get("lock") or {}
        t0, t1 = r.get("t_hold_start"), lk.get("t_end")
        d = {"file": os.path.basename(f), "mode": (r.get("command") or {}).get("mode"), "t_hold_start": t0, "lock_t_start": lk.get("t_start"),
             "lock_t_end": t1, "lock_attempts": lk.get("attempts"), "lock_held_samples": lk.get("held_samples"),
             "lock_errors": lk.get("errors"), "polls": {}}
        for m in MONITORS:
            ps = sorted((p for p in P[("e10s", m)].values() if p.get("copy_at") is not None and t0 <= p["copy_at"] < t1),
                        key=lambda p: p["copy_at"])
            d["polls"][m] = []
            for p in ps:
                c = C[("e10s", m)].get(p["seq_local"]) or {}
                cm = c.get("copy_ms")
                d["polls"][m].append({"seq_local": p["seq_local"], "copy_at": p["copy_at"], "s_into_hold": round(p["copy_at"] - t0, 3),
                                      "s_before_end": round(t1 - p["copy_at"], 3), "unobservable": p["unobservable"],
                                      "reason": p["reason"], "read": c.get("read"), "copy_ms": cm,
                                      "read_end_minus_lock_end_s": (round(p["copy_at"] + cm / 1000.0 - t1, 3) if cm is not None else None)})
            d["polls_in_hold_" + m] = len(ps)
            d["unobservable_in_hold_" + m] = sum(1 for p in ps if p["unobservable"])
        hold_rows.append(d)
    out["ul_shm_holds"] = hold_rows

    # 3. UL-W holds: rows timestamped inside the hold, verdicts in a_end (patched) and a_end_e9
    vfiles = {}
    for m in MONITORS:
        for lab in ("a_end", "a_end_e9"):
            import re
            pat = re.compile(r"^e10s_%s_%s_[0-9a-f]{12}\.json$" % (m, lab))
            fs = sorted(x for x in glob.glob(os.path.join(a.run_dir, "verify", "e10s_%s_%s_*.json" % (m, lab)))
                        if pat.match(os.path.basename(x)))
            assert len(fs) == 1, (m, lab, fs)
            vfiles[(m, lab)] = fs[0]
            inputs["verify_%s_%s" % (m, lab)] = {"path": fs[0], "sha256": sha(fs[0])}
    V = {}
    for k, f in vfiles.items():
        V[k] = {name: (top_slice(f, name) or []) for name in ("attributable_rows", "benign_late_rows", "unobserved_late_rows")}
        V[k]["flagged_seconds"] = set(top_slice(f, "flagged_seconds") or [])
    ulw = []
    for f in sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_lock_write.json"))):
        inputs.setdefault("lock_write", []).append({"path": f, "sha256": sha(f)})
        r = json.load(open(f))
        t0, t1 = r["t_acquired"], r["t_released"]
        d = {"file": os.path.basename(f), "t_acquired": t0, "t_released": t1, "hold_s": round(t1 - t0, 3),
             "wm_before": r.get("wm_before"), "wm_after": r.get("wm_after"), "verdicts": {}}
        for (m, lab), vv in V.items():
            sel = collections.Counter()
            lbs, keys = [], []
            for name in ("attributable_rows", "benign_late_rows", "unobserved_late_rows"):
                for x in vv[name]:
                    if x.get("ts") is not None and t0 - 1.0 <= x["ts"] <= t1:
                        sel[name] += 1
                        keys.append(x["key"])
                        if x.get("committed_after_lower_bound_s") is not None:
                            lbs.append(x["committed_after_lower_bound_s"])
            fl = sorted(s for s in vv["flagged_seconds"] if t0 - 1 <= int(s) <= t1)
            d["verdicts"]["%s_%s" % (m, lab)] = {"late_rows_by_verdict": dict(sel), "max_lower_bound_s": max(lbs) if lbs else None,
                                                  "min_lower_bound_s": min(lbs) if lbs else None,
                                                  "flagged_seconds_in_hold": len(fl)}
        for m in MONITORS:
            ps = [p for p in P[("e10s", m)].values() if p.get("copy_at") is not None and t0 <= p["copy_at"] < t1]
            d["polls_" + m] = {"n": len(ps), "unobservable": sum(1 for p in ps if p["unobservable"])}
        ulw.append(d)
    out["ul_w_holds"] = ulw

    # 4. INF-T
    ev = jl(os.path.join(a.run_dir, "events.jsonl"))
    inputs["events"] = {"path": os.path.join(a.run_dir, "events.jsonl"), "sha256": sha(os.path.join(a.run_dir, "events.jsonl"))}
    inf = json.load(open(glob.glob(os.path.join(a.run_dir, "e10", "*_inflate_table.json"))[0]))
    dfl = json.load(open(glob.glob(os.path.join(a.run_dir, "e10", "*_deflate_table.json"))[0]))
    rep = next(e for e in ev if e.get("type") == "repack" and e.get("stack") == "e10s")
    t_a, t_full, t_drop0, t_drop1, t_rep = inf["t_start"], inf["t_end"], dfl["t_started"], dfl["t"], rep["published_ts"]
    inft = {"t_inflate_start": t_a, "t_inflate_end": t_full, "t_drop_started": t_drop0, "t_drop_done": t_drop1,
            "t_repack_published": t_rep, "bytes_inserted": inf.get("bytes_inserted"), "db_bytes_after_inflate": inf.get("db_bytes"),
            "db_bytes_after_drop": dfl.get("db_bytes"), "monitors": {}}
    for m in MONITORS:
        cs = C[("e10s", m)]
        polls = P[("e10s", m)]
        rows = []
        for s, c in sorted(cs.items()):
            t = c.get("ts")
            if t is None or not (t_a - 10 <= t <= t_rep + 120):
                continue
            p = polls.get(s) or {}
            rows.append({"seq_local": s, "ts": t, "copy_ms": c.get("copy_ms"), "load_ms": c.get("load_ms"),
                         "commit_ms": c.get("commit_ms"), "append_ms": c.get("append_ms"), "total_ms": round(total_ms(c), 3),
                         "read": c.get("read"), "ok": c.get("ok"), "unobservable": p.get("unobservable"), "reason": p.get("reason"),
                         "copy_at": p.get("copy_at")})
        phase = [r for r in rows if r["copy_at"] is not None and t_full <= r["copy_at"] < t_rep]
        # the scorer's UNOBS_cost window for inflate_table is [t_start, t_end + 1200] on the cost log's ts
        sw = [c for s, c in sorted(cs.items()) if c.get("ts") is not None and t_a <= float(c["ts"]) < t_full + 1200]
        inft.setdefault("scorer_window_intervals_over_30s", {})[m] = [
            {"from_seq": x["seq_local"], "to_seq": b["seq_local"], "from_ts": x["ts"], "to_ts": b["ts"],
             "interval_s": round(float(b["ts"]) - float(x["ts"]), 3), "to_copy_ms": b.get("copy_ms")}
            for x, b in zip(sw, sw[1:]) if float(b["ts"]) - float(x["ts"]) > 30]
        inft["monitors"][m] = {
            "polls_listed": rows,
            "phase_table_present": {"window": [t_full, t_rep], "n": len(phase),
                                    "unobservable": sum(1 for r in phase if r["unobservable"]),
                                    "reasons": dict(collections.Counter(str(r["reason"]) for r in phase if r["unobservable"])),
                                    "copy_ms": dist([r["copy_ms"] for r in phase]), "total_ms": dist([r["total_ms"] for r in phase]),
                                    "polls_over_5s": sum(1 for r in phase if r["total_ms"] > 5000),
                                    "polls_over_30s": sum(1 for r in phase if r["total_ms"] > 30000),
                                    "interval_s": dist([b["copy_at"] - x["copy_at"] for x, b in zip(phase, phase[1:])])},
            "slowest": sorted(rows, key=lambda r: -r["total_ms"])[:5],
            # quick_check runs at seq_local % 720 == 1 in direct mode (HOMEPROV_QUICK_CHECK_EVERY=720), every poll in copy mode
            "phase_quick_check_due_polls": ([{"seq_local": r["seq_local"], "copy_ms": r["copy_ms"], "total_ms": r["total_ms"]}
                                             for r in phase if r["seq_local"] % 720 == 1] if m == "direct" else "every poll"),
            "phase_polls_over_1s_without_due_quick_check": ([{"seq_local": r["seq_local"], "copy_at": r["copy_at"],
                                                              "copy_ms": r["copy_ms"], "append_ms": r["append_ms"],
                                                              "total_ms": r["total_ms"]}
                                                             for r in phase if r["total_ms"] > 1000 and r["seq_local"] % 720 != 1]
                                                            if m == "direct" else None)}
    out["inf_t"] = inft

    # 5. the registered rule on E9's benign week
    e9 = {"run_dir": a.e9_run_dir, "monitors": {}}
    ev9p = os.path.join(a.e9_run_dir, "events.jsonl")
    inputs["e9_events"] = {"path": ev9p, "sha256": sha(ev9p)}
    starts = [e["ts"] for e in jl(ev9p) if e.get("type") == "hub_restart"]
    e9["hub_restarts"] = len(starts)
    for m in MONITORS:
        ch = os.path.join(a.e9_run_dir, "%s_chain.jsonl" % m)
        inputs["e9_%s_chain" % m] = {"path": ch, "sha256": sha(ch)}
        pl = stream_polls(ch)
        iv = runs(pl)
        flagged = [r for r in iv if (r["duration_s"] or 0) >= RULE_MIN_S and not any(
            abs(s_ - r["from"]) <= RULE_HUB_S or abs(s_ - r["to"]) <= RULE_HUB_S for s_ in starts)]
        e9["monitors"][m] = {"polls": len(pl), "intervals": len(iv), "suspicious": len(flagged),
                             "durations_s": dist([r["duration_s"] for r in iv]),
                             "reasons": dict(collections.Counter(k for r in iv for k in r["reasons"])),
                             "intervals_list": iv[:50],
                             "near_hub_start": sum(1 for r in iv if any(abs(s_ - r["from"]) <= RULE_HUB_S or abs(s_ - r["to"]) <= RULE_HUB_S
                                                                         for s_ in starts))}
    out["distinguishability_e9_benign_week"] = e9

    # 6. host-log gaps
    hg = {}
    for st in ("e10s", "e10u"):
        hp = os.path.join(a.run_dir, st, "hostlog.jsonl")
        if not os.path.exists(hp):
            hg[st] = None
            continue
        inputs["%s_hostlog" % st] = {"path": hp, "sha256": sha(hp)}
        ts = sorted(d["ts"] for d in jl(hp) if d.get("kind") == "sample" and d.get("ts") is not None)
        gaps = [b - x for x, b in zip(ts, ts[1:])]
        hg[st] = {"samples": len(ts), "first": ts[0] if ts else None, "last": ts[-1] if ts else None,
                  "max_gap_s": max(gaps) if gaps else None, "gaps_over_90s": [(x, b - x) for x, b in zip(ts, ts[1:]) if b - x > 90]}
    out["hostlog_gaps"] = hg
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["wall_s"] = round(time.time() - t_begin, 1)
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
