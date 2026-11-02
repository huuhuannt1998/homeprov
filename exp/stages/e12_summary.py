"""E12 (review r5, Z2/Z3) -- E12's own outcomes, after exp/stages/e9_score.py (used unchanged) has verified the run.

E12 (testbed/e12/run_e12.sh, drafts/round13/E12_DESIGN.md) runs the recommended configuration for 48 h on the lab
installation at Home Assistant's default recorder commit interval with routine operations and no attacks, so every
anchored segment is untouched and every unexcused violation is a false violation. e9_score.py verifies each day against
its end-of-day snapshot and each night's purge (cached in <run dir>/verify/<monitor>_<label>_<key>.json). This file adds:

  rates     per day and per run, per monitor: unexcused violations (second, minute, hour, keylog) and their rate with
            BLOCK-level exact intervals (META item 3; R3 W2): a minute fails if it holds a flagged second, an
            unexcused minute violation or a keylog violation's second; a poll fails if it is the first observable poll
            to copy after a failed second ended (the poll that sealed it). k of n blocks, Clopper-Pearson 95%, and the
            upper bound converted to failures per day (blocks per day x upper bound). Blocks are still not independent;
            the interval is reported as the block-level bound the reviewers asked for, not as a model.
  cadence   the recorder's commit cadence observed outside the hub (commit_cadence events): bursts and intervals
  late      late-row delays (benign_late, unobserved_late) per day and monitor: count, max, over 25 s
  backup    Home Assistant's backup window [requested - 10 s, done + 60 s]: row verdicts, flagged seconds, unobservable
            polls, the commit pause measured by the cadence probe (largest interval between bursts), and whether the
            verdicts agree with the verifier rule given that pause (rule_consistency below)
  restart   the planned restart's window [restart - 30 s, restart + 120 s]: row verdicts, flagged seconds, polls
  unobs     unobservable intervals and the distinguishability rule (>= 60 s and no hub start within 120 s)

    python3 exp/stages/e12_summary.py --run-dir <run dir> --tag e12_main [--out-dir exp/out]
Writes <out-dir>/<tag>_e12_summary.json; never overwrites (--overwrite).
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "exp"))
LATE_BOUND, GAP_S = 30.0, 30.0
MONITORS = ("direct", "copy")
UNOBS_RULE_MIN_S, UNOBS_RULE_HUB_S = 60.0, 120.0
COMMIT_DEFAULT_S = 5.0


def cp(k, n):
    from rig import stats                      # noqa: PLC0415
    if not n:
        return None
    r = stats.clopper_pearson(k, n)
    return {"k": k, "n": n, "interval": [r["ci_lo"], r["ci_hi"]]}


def per_day_bound(ci, blocks_per_day):
    """The 95% interval's upper end converted to failures per day."""
    return None if not ci else round(ci["interval"][1] * blocks_per_day, 3)


def failed_seconds(v):
    """Seconds that count as failures in a verification: flagged seconds, the seconds of unexcused second-granularity
    violations, and the seconds keylog violations name."""
    if not v or "error" in v:
        return None
    out = {int(s) for s in v.get("flagged_seconds") or []}
    for x in v.get("violations") or []:
        if x.get("violation") and x.get("attributable") and x.get("gran") == "second":
            out.add(int(x["seg"]))
    for kv in v.get("keylog_violations") or []:
        out |= {int(s) for s in kv.get("seconds") or []}
    return out


def failed_minutes(v):
    if not v or "error" in v:
        return None
    m = {s // 60 for s in failed_seconds(v)}
    for x in v.get("violations") or []:
        if x.get("violation") and x.get("attributable") and x.get("gran") == "minute":
            m.add(int(x["seg"]))
    return m


def minute_blocks(fmin, window):
    lo, hi = int(window[0] // 60), int((window[1] - 1) // 60)
    n = hi - lo + 1
    return sum(1 for m in fmin if lo <= m <= hi), n


def poll_blocks(fsec, copy_times, window):
    """(failed polls, observable polls in the window): a failed second fails the first observable poll copying at or
    after its end."""
    ct = sorted(t for t in copy_times if window[0] <= t < window[1])
    failed = set()
    import bisect                                  # noqa: PLC0415
    for s in fsec:
        if window[0] <= s < window[1]:
            i = bisect.bisect_left(ct, s + 1)
            if i < len(ct):
                failed.add(i)
    return len(failed), len(ct)


def rows_window(v, lo, hi):
    """Row verdicts whose second is in [lo, hi]: counts and the largest delay."""
    if not v or "error" in v:
        return None
    c, delays = collections.Counter(), []
    for name, rows in (("attributable", v.get("attributable_rows")), ("benign_late", v.get("benign_late_rows")),
                       ("unobserved_late", v.get("unobserved_late_rows"))):
        for r in rows or []:
            sec = r.get("second")
            if sec is not None and lo <= int(sec) <= hi:
                c[name] += 1
                d = r.get("lat", r.get("lower_bound_s", r.get("late_s")))
                if isinstance(d, (int, float)):
                    delays.append(d)
    return {"by_verdict": dict(c), "max_delay_s": max(delays) if delays else None}


def late_rows(v, window):
    if not v or "error" in v:
        return None
    out = {}
    for name in ("benign_late_rows", "unobserved_late_rows"):
        ds = [r.get("lat", r.get("lower_bound_s", r.get("late_s"))) for r in v.get(name) or []
              if r.get("second") is not None and window[0] <= int(r["second"]) < window[1]]
        ds = [d for d in ds if isinstance(d, (int, float))]
        out[name] = {"n": len(ds), "max_s": max(ds) if ds else None, "over_25_s": sum(1 for d in ds if d > 25.0)}
    return out


def rule_consistency(pause_s, attributable, commit_s=COMMIT_DEFAULT_S, late_bound=LATE_BOUND):
    """Does the backup window's verdict agree with the verifier's rule, given the measured commit pause? A row written at
    the start of a pause of p seconds commits about p (+ up to one commit interval) seconds late; the verifier makes it
    attributable when that exceeds LATE_BOUND. Predicted: none attributable if p + commit_s < LATE_BOUND - 5; some
    attributable if p > LATE_BOUND + 5; in between, either."""
    if pause_s is None or attributable is None:
        return {"predicted": None, "agrees": None}
    if pause_s + commit_s < late_bound - 5.0:
        pred = "none_attributable"
        ok = attributable == 0
    elif pause_s > late_bound + 5.0:
        pred = "some_attributable"
        ok = attributable > 0
    else:
        pred = "either"
        ok = True
    return {"pause_s": pause_s, "predicted": pred, "attributable": attributable, "agrees": ok}


def load_verify(sp, m, label):
    pat = re.compile(r"^%s_%s_[0-9a-f]{12}\.json$" % (re.escape(m), re.escape(label)))
    files = sorted((f for f in glob.glob(os.path.join(sp, "verify", "%s_%s_*.json" % (m, label)))
                    if pat.match(os.path.basename(f))), key=os.path.getmtime)
    if not files:
        return None
    try:
        return json.load(open(files[-1]))
    except ValueError:
        return None


def jl(path):
    out = []
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            if line.strip().startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "exp", "out"))
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    dst = os.path.join(a.out_dir, "%s_e12_summary.json" % a.tag)
    if os.path.exists(dst) and not a.overwrite:
        raise SystemExit("REFUSING: %s exists" % dst)
    sys.path.insert(0, HERE)
    import e10_score as S10                    # noqa: PLC0415  (Polls: the chain's poll timeline, the patched verifier)
    sp = a.run_dir
    sched = json.load(open(os.path.join(sp, "schedule.json")))
    events = jl(os.path.join(sp, "events.jsonl"))
    days = [e for e in sched["events"] if e["type"] == "day_end"]
    polls = {m: S10.Polls(os.path.join(sp, "%s_chain.jsonl" % m)) for m in MONITORS}
    hub_starts = [e["ts"] for e in events if e.get("type") == "hub_restart"]
    res = {"experiment": "E12 (review r5): 48 h of the recommended configuration at the default commit interval",
           "tag": a.tag, "parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "commit_default_s": COMMIT_DEFAULT_S,
                                        "unobservable_rule": [UNOBS_RULE_MIN_S, UNOBS_RULE_HUB_S]},
           "days": {}, "run": {}, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    tot = {m: collections.Counter() for m in MONITORS}
    for d in days:
        n, w = d["day"], d["window"]
        row = {"window": w}
        for m in MONITORS:
            v = load_verify(sp, m, "day%d" % n)
            fs, fm = failed_seconds(v), failed_minutes(v)
            if fs is None:
                row[m] = {"verify": "missing or failed"}
                continue
            kmin, nmin = minute_blocks(fm, w)
            kp, np_ = poll_blocks(fs, [p["copy_at"] for p in polls[m].obs], w)
            gr = collections.Counter(x["gran"] for x in v.get("violations") or [] if x.get("violation") and x.get("attributable"))
            row[m] = {"unexcused": {"second": gr.get("second", 0), "minute": gr.get("minute", 0), "hour": gr.get("hour", 0),
                                    "keylog": len(v.get("keylog_violations") or []), "flagged_seconds": len(fs)},
                      "minute_blocks": cp(kmin, nmin), "per_day_upper_minute": per_day_bound(cp(kmin, nmin), 1440),
                      "poll_blocks": cp(kp, np_),
                      "per_day_upper_poll": per_day_bound(cp(kp, np_), np_ * 86400.0 / max(1.0, w[1] - w[0])),
                      "late_rows": late_rows(v, w), "excused": len(v.get("excused_violations") or []),
                      "root_unknown_segments": len(v.get("root_unknown_segments") or [])}
            for k, x in (("kmin", kmin), ("nmin", nmin), ("kp", kp), ("np", np_)):
                tot[m][k] += x
        res["days"][str(n)] = row
    for m in MONITORS:
        t = tot[m]
        res["run"][m] = {"minute_blocks": cp(t["kmin"], t["nmin"]),
                         "per_day_upper_minute": per_day_bound(cp(t["kmin"], t["nmin"]), 1440),
                         "poll_blocks": cp(t["kp"], t["np"]),
                         "per_day_upper_poll": per_day_bound(cp(t["kp"], t["np"]), t["np"] / max(1, len(days)))}
    res["cadence"] = [{"label": e.get("label"), **{k: (e.get("result") or {}).get(k) for k in (
        "bursts", "interval_median_s", "interval_p10_s", "interval_p90_s", "interval_max_s", "error")}}
                      for e in events if e.get("type") == "commit_cadence"]
    last_day = load_verify(sp, "direct", "day%d" % days[-1]["day"]) if days else None
    vlast = {m: load_verify(sp, m, "day%d" % days[-1]["day"]) for m in MONITORS} if days else {}
    req = next((e for e in events if e.get("type") == "backup_requested"), None)
    done = next((e for e in events if e.get("type") == "backup"), None)
    if req and done and req.get("published_ts"):
        lo, hi = float(req["published_ts"]) - 10.0, float(done.get("done_ts") or req["published_ts"]) + 60.0
        cad = next((e.get("result") or {} for e in events if e.get("type") == "commit_cadence" and e.get("label") == "backup"), {})
        bk = {"window": [lo, hi], "new_files": done.get("new_files"), "commit_pause_s": cad.get("interval_max_s")}
        for m in MONITORS:
            # the backup falls on the day whose verification covers it; the last day's covers day 2's 20:00
            day_v = next((load_verify(sp, m, "day%d" % d["day"]) for d in days if d["window"][0] <= lo < d["window"][1]),
                         vlast.get(m))
            rw = rows_window(day_v, int(lo), int(hi))
            ps = [p for p in polls[m].polls if p.get("copy_at") and lo <= p["copy_at"] <= hi]
            bk[m] = {"rows": rw, "flagged_seconds": None if day_v is None else
                     sum(1 for s in day_v.get("flagged_seconds") or [] if lo <= int(s) <= hi),
                     "polls": len(ps), "unobservable": sum(1 for p in ps if p.get("unobservable")),
                     "rule_consistency": rule_consistency(cad.get("interval_max_s"),
                                                          None if rw is None else rw["by_verdict"].get("attributable", 0))}
        res["backup"] = bk
    rs = [e for e in events if e.get("type") == "hub_restart" and "planned" in str(e.get("cause"))]
    if rs:
        t = float(rs[0]["ts"])
        rr = {"restart_ts": t, "window": [t - RESTART_PRE, t + RESTART_POST]}
        for m in MONITORS:
            day_v = next((load_verify(sp, m, "day%d" % d["day"]) for d in days if d["window"][0] <= t < d["window"][1]), None)
            ps = [p for p in polls[m].polls if p.get("copy_at") and t - RESTART_PRE <= p["copy_at"] <= t + RESTART_POST]
            rr[m] = {"rows": rows_window(day_v, int(t - RESTART_PRE), int(t + RESTART_POST)), "polls": len(ps),
                     "unobservable": sum(1 for p in ps if p.get("unobservable"))}
        res["planned_restart"] = rr
    un = {}
    for m in MONITORS:
        iv = polls[m].unobservable_runs()
        sus = [r for r in iv if (r.get("duration_s") or 0) >= UNOBS_RULE_MIN_S and not any(
            abs(s - (r.get("from") or 0)) <= UNOBS_RULE_HUB_S or abs(s - (r.get("to") or 0)) <= UNOBS_RULE_HUB_S
            for s in hub_starts)]
        un[m] = {"intervals": len(iv), "suspicious": len(sus), "reasons": dict(collections.Counter(
            k for r in iv for k in r["reasons"])), "suspicious_intervals": sus[:20]}
    res["unobservable"] = un
    res["predictions"] = {"unexcused_violations_per_day": 0, "suspicious_intervals": 0,
                          "planned_restart_attributable_rows": 0, "cadence_median_s": [4.0, 6.5],
                          "backup": "per rule_consistency (the pause is measured, not predicted)"}
    res["_last_day_verify_present"] = last_day is not None
    os.makedirs(a.out_dir, exist_ok=True)
    with open(dst, "w" if a.overwrite else "x") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
    print("wrote", dst)


RESTART_PRE, RESTART_POST = 30.0, 120.0

if __name__ == "__main__":
    main()
