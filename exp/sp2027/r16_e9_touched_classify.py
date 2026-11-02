#!/usr/bin/env python3
"""E9 exploratory B2 follow-up (E9_ANALYSIS_PLAN.md): why touched one-second segments are not flagged.

A segment is touched under the paper's counting rule (reproduce/verify_all.py touched_segments, plus the trials' own
deleted events, e7_verify.touched_by_deletions) when it holds a row a trial wrote, edited or NAMED: the trial's row
second, the seconds of its before/judged/forged rows, its laundered or swapped rows, and every event carrying the
original actuation's context id (or, with no such event, the span from the context ULID's time to the row). Only rows
changed after their segment was sealed can fail. This script recomputes the rule with a label per source, per day and
monitor, against the window-scoped flagged seconds of the frozen scorer's verifier outputs, and reports the touched
seconds that are not flagged by source, and whether each trial's own target second is flagged.

Inputs (read only): the day reports exp/out/e9_main2_d<n>_report_*.json, the end-of-day snapshots and the per-day
verifier outputs in the run directory, the compact score file (windows). Output: one JSON file.
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

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


import sys                                                # noqa: E402
sys.path.insert(0, os.path.join(R, "reproduce"))
from verify_all import ulid_bytes, ulid_s, row_ts         # noqa: E402  (the counting rule's own helpers)


def labelled_touched(trials, con):
    """{second: set(labels)} under the counting rule, each source labelled."""
    lab = collections.defaultdict(set)
    st = lambda sid: (con.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (sid,)).fetchone() or [None])[0]
    for t in trials:
        ts = row_ts(t)
        if ts is None:
            continue
        lab[int(ts // 1)].add("trial_row")
        for k in ("row_before", "judged_row", "forged_row"):
            r = t.get(k)
            if isinstance(r, dict) and r.get("state_id"):
                x = st(r["state_id"]) or r.get("ts")
                if x:
                    lab[int(float(x) // 1)].add(k)
        for k in ("laundered_state_ids", "swapped_state_ids"):
            for sid in t.get(k) or []:
                x = st(sid)
                if x:
                    lab[int(x // 1)].add(k[:-4])
        r = t.get("row_before") or t.get("forged_row") or t.get("judged_row") or {}
        for cid in (r.get("context_id_bin"), t.get("fabricated_event_context")):
            if not cid:
                continue
            b = bytes.fromhex(cid) if len(cid) == 32 else ulid_bytes(cid)
            evs = [x[0] for x in con.execute("SELECT time_fired_ts FROM events WHERE context_id_bin=?", (b,))]
            if evs:
                for x in evs:
                    if x:
                        lab[int(x // 1)].add("context_event")
            else:
                c = ulid_s(cid)
                if c is not None:
                    lo, hi = sorted((c, ts))
                    for s in range(int(lo // 1), int(hi // 1) + 1):
                        lab[s].add("context_span")
        for x in t.get("deleted_event_seconds") or []:
            lab[int(float(x) // 1)].add("deleted_event")
    return lab


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--score", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    S = json.load(open(a.score))
    vdir = os.path.join(a.run_dir, "verify")
    res = {"analysis": "E9 B2 follow-up: touched seconds not flagged, by counting-rule source", "label": "exploratory",
           "inputs": {os.path.basename(a.score): sha(a.score)}, "days": {}, "week": {},
           "script": "exp/sp2027/r16_e9_touched_classify.py",
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    week = {m: {"touched": 0, "flagged": 0, "not_flagged_by_source": collections.Counter(),
                "trials": 0, "target_flagged": 0} for m in ("direct", "copy")}
    for n in sorted(int(x) for x in S["days"]):
        d = S["days"][str(n)]
        t0, t1 = d["window"]["t0"], d["window"]["t1"]
        files = [os.path.join(R, "exp", "out", f) for f in d["reports"]]
        for f in files:
            res["inputs"][os.path.basename(f)] = sha(f)
        trials = [t for f in files for t in json.load(open(f)).get("trials", []) if not (t.get("err") or t.get("error"))]
        snap = os.path.join(a.run_dir, "snapshots", "day%d_end.db" % n)
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % snap, uri=True)
        lab = labelled_touched(trials, con)
        con.close()
        targets = {int(row_ts(t) // 1) for t in trials if row_ts(t) is not None}
        res["days"][str(n)] = {"touched_seconds": len(lab), "score_file_touched_seconds": d.get("touched_seconds"),
                               "by_monitor": {}}
        for m in ("direct", "copy"):
            f = [p for p in glob.glob(os.path.join(vdir, "%s_day%d_*.json" % (m, n)))
                 if re.fullmatch(r"%s_day%d_[0-9a-f]{12}\.json" % (m, n), os.path.basename(p))][0]
            res["inputs"]["verify/" + os.path.basename(f)] = sha(f)
            v = json.load(open(f))
            flagged = {int(s) for s in v.get("flagged_seconds") or [] if t0 <= int(s) < t1}
            nf = {s: sorted(l) for s, l in lab.items() if s not in flagged}
            src = collections.Counter("+".join(l) for l in nf.values())
            tf = sum(1 for s in targets if s in flagged)
            res["days"][str(n)]["by_monitor"][m] = {
                "touched": len(lab), "touched_flagged": sum(1 for s in lab if s in flagged),
                "touched_not_flagged": len(nf), "not_flagged_by_source": dict(src),
                "trial_target_seconds": len(targets), "trial_target_seconds_flagged": tf,
                "not_flagged_holding_a_trial_row": sorted(s for s, l in nf.items() if "trial_row" in l)[:50]}
            w = week[m]
            w["touched"] += len(lab)
            w["flagged"] += sum(1 for s in lab if s in flagged)
            w["not_flagged_by_source"].update(src)
            w["trials"] += len(targets)
            w["target_flagged"] += tf
    for m, w in week.items():
        res["week"][m] = {"touched": w["touched"], "touched_flagged": w["flagged"],
                          "touched_not_flagged": w["touched"] - w["flagged"],
                          "not_flagged_by_source": dict(w["not_flagged_by_source"].most_common()),
                          "trial_target_seconds": w["trials"], "trial_target_seconds_flagged": w["target_flagged"]}
    with open(a.out, "x") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))
    for m, w in res["week"].items():
        print(m, json.dumps(w))


if __name__ == "__main__":
    main()
