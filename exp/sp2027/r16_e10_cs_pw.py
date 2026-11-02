#!/usr/bin/env python3
"""E10 exploratory: the clock-step arm (A6-CS, H10) and the purge-window arm (A5-PW, H6) beyond the frozen scorer.

CS  The frozen scorer (exp/stages/e10_score.py score_cs) counts the verdicts of the STATE rows whose key lies between the
    step's watermarks. In the run, the emulated step (time.time() in the hub's process) moved the timestamps of EVENT
    rows (time_fired_ts) but not of state rows (rows_written in the trial records). Here, per step and per table, the
    rows written during the step (keys in (wm_before, wm_after], read from the cs_end snapshot, opened immutable) and
    their verdicts in the scorer's cached cs verification: excused_clock_step (clock_step.excused_rows), attributable,
    benign_late, unobserved_late, or none (on time); and how far each row's timestamp lies behind the step's start.
PW  For each declared purge (keep 29 d, tolerance 60 s): the rows of the band [c0, c1) and of [c1, c1 + 30 s) present
    in the snapshot taken before the purge (pw<i>_pre) and after it (pw<i>_post), and the oldest row before the purge,
    i.e. whether the PW-B, PW-U and PW-X variants had any row to act on.

Inputs read only (snapshots opened with mode=ro&immutable=1; their -wal files are empty). Output: one new JSON file.

    python3 exp/sp2027/r16_e10_cs_pw.py [--run-dir DIR] [--out exp/out/r16_e10_cs_pw.json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import sqlite3
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
MONITORS = ("direct", "copy")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def ro(db):
    for side in ("-wal",):
        p = db + side
        assert not os.path.exists(p) or os.path.getsize(p) == 0, p
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)


def snapshot(run, label):
    for line in open(os.path.join(run, "events.jsonl")):
        e = json.loads(line)
        if e.get("type") == "snapshot" and e.get("ok") and e.get("stack") == "e10s" and e.get("label") == label:
            return os.path.join(run, e["file"]), e["t_snapshot"]
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_cs_pw.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    t_begin = time.time()
    inputs = {"events": {"path": os.path.join(a.run_dir, "events.jsonl"), "sha256": sha(os.path.join(a.run_dir, "events.jsonl"))}}
    out = {"what": "E10 A6-CS and A5-PW details (EXPLORATORY)", "inputs": inputs}

    # ------------------------------------------------------------------ CS
    db, tsnap = snapshot(a.run_dir, "cs_end")
    inputs["cs_end_db"] = {"path": db, "sha256": sha(db)}
    con = ro(db)
    V = {}
    for m in MONITORS:
        pat = re.compile(r"^e10s_%s_cs_[0-9a-f]{12}\.json$" % m)
        fs = [x for x in glob.glob(os.path.join(a.run_dir, "verify", "e10s_%s_cs_*.json" % m)) if pat.match(os.path.basename(x))]
        assert len(fs) == 1, fs
        inputs["verify_cs_" + m] = {"path": fs[0], "sha256": sha(fs[0])}
        v = json.load(open(fs[0]))
        idx = {}
        for r in (v.get("clock_step") or {}).get("excused_rows") or []:
            idx.setdefault(r["key"], ("excused_clock_step", r.get("committed_after_lower_bound_s")))
        for name, rows in (("attributable", v.get("attributable_rows")), ("benign_late", v.get("benign_late_rows")),
                           ("unobserved_late", v.get("unobserved_late_rows"))):
            for r in rows or []:
                idx.setdefault(r["key"], (name, r.get("committed_after_lower_bound_s")))
        V[m] = {"idx": idx, "markers_accepted": len((v.get("clock_step") or {}).get("accepted") or []),
                "markers_rejected": (v.get("clock_step") or {}).get("rejected"),
                "flagged_seconds": set(v.get("flagged_seconds") or []),
                "second_violations": sum(1 for x in v.get("violations") or [] if x.get("gran") == "second"
                                         and x.get("violation") and x.get("attributable"))}
    steps = []
    for f in sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_clock_step.json"))):
        inputs.setdefault("clock_step", []).append({"path": f, "sha256": sha(f)})
        r = json.load(open(f))
        cmd = r.get("command") or {}
        d = {"file": os.path.basename(f), "step": cmd.get("step"), "step_s": r.get("step_s"), "marker": bool(cmd.get("marker")),
             "t_on": r["t_on"], "t_off": r["t_off"], "tables": {}}
        for table, kcol, tcol, pre in (("states", "state_id", "last_updated_ts", "s"), ("events", "event_id", "time_fired_ts", "e")):
            lo, hi = r["wm_before"][table], r["wm_after"][table]
            rows = con.execute("SELECT %s, %s FROM %s WHERE %s > ? AND %s <= ? ORDER BY %s" % (kcol, tcol, table, kcol, kcol, kcol),
                               (lo, hi)).fetchall()
            behind = [r["t_on"] - t for _k, t in rows if t is not None]
            e = {"keys": [lo + 1, hi], "rows_in_snapshot": len(rows),
                 "rows_timestamped_before_t_on": sum(1 for _k, t in rows if t is not None and t < r["t_on"]),
                 "max_s_behind_t_on": round(max(behind), 3) if behind else None}
            for m in MONITORS:
                c = collections.Counter()
                lbs = collections.defaultdict(list)
                for k, _t in rows:
                    verd, lb = V[m]["idx"].get("%s:%s" % (pre, k), ("none_on_time", None))
                    c[verd] += 1
                    if lb is not None:
                        lbs[verd].append(lb)
                e[m] = {"verdicts": dict(c), "lower_bound_s_range": {k: [round(min(v), 3), round(max(v), 3)] for k, v in lbs.items()}}
            d["tables"][table] = e
        win = range(int(r["t_on"]) - 61, int(r["t_off"]) + 2)
        d["flagged_seconds_in_step_window"] = {m: sum(1 for s in win if str(s) in V[m]["flagged_seconds"]) for m in MONITORS}
        steps.append(d)
    out["cs"] = {"snapshot": "cs_end", "t_snapshot": tsnap, "steps": steps,
                 "verification": {m: {"markers_accepted": V[m]["markers_accepted"], "markers_rejected": V[m]["markers_rejected"],
                                      "attributable_second_violations_in_window": V[m]["second_violations"]} for m in MONITORS}}
    con.close()

    # ------------------------------------------------------------------ PW
    pws = []
    for f in sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_pw.json"))):
        inputs.setdefault("pw", []).append({"path": f, "sha256": sha(f)})
        r = json.load(open(f))
        i = (r.get("command") or {}).get("event")
        c0, c1 = r["c0"], r["c1"]
        d = {"event": i, "variants": r.get("variants"), "scheduled_ts": r["scheduled_ts"], "c0": c0, "c1": c1,
             "oldest_state_after_purge": r.get("oldest_state_after_purge"),
             "rows_deleted_by_variant": {v: (len(act.get("states_deleted") or []) + len(act.get("events_deleted") or [])
                                             if "states_deleted" in act else act.get("rows_deleted"))
                                         for v, act in (r.get("actions") or {}).items()}}
        for lab in ("pw%s_pre" % i, "pw%s_post" % i):
            sdb, st = snapshot(a.run_dir, lab)
            inputs[lab] = {"path": sdb, "sha256": sha(sdb)}
            cc = ro(sdb)
            q = lambda sql, *p: cc.execute(sql, p).fetchone()[0]   # noqa: E731
            d[lab] = {"t_snapshot": st,
                      "states_in_band": q("SELECT COUNT(*) FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?", c0, c1),
                      "events_in_band": q("SELECT COUNT(*) FROM events WHERE time_fired_ts >= ? AND time_fired_ts < ?", c0, c1),
                      "states_in_c1_plus_30": q("SELECT COUNT(*) FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?", c1, c1 + 30),
                      "events_in_c1_plus_30": q("SELECT COUNT(*) FROM events WHERE time_fired_ts >= ? AND time_fired_ts < ?", c1, c1 + 30),
                      "states_within_1h_before_c0": q("SELECT COUNT(*) FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?", c0 - 3600, c0),
                      "oldest_state_ts": q("SELECT MIN(last_updated_ts) FROM states"),
                      "oldest_event_ts": q("SELECT MIN(time_fired_ts) FROM events"),
                      "first_state_ts_at_or_after_c0": q("SELECT MIN(last_updated_ts) FROM states WHERE last_updated_ts >= ?", c0)}
            cc.close()
        pws.append(d)
    out["pw"] = pws
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["wall_s"] = round(time.time() - t_begin, 1)
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
