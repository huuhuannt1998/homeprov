#!/usr/bin/env python3
"""E10 (EXPLORATORY, saved data only): where inside its window does a copy-mode poll take its view of the WAL?

For every E10 A1-BDT trial and every poll of either monitor whose observation window (E10b's rule: direct
[copy_at, copy_at], copy [copy_at, record ts], both widened by 50 ms) overlaps the trial's write window
[t_insert, t_commit], this lists the window's start and end relative to t_insert and t_commit, and whether the poll's
content held the forged row (its states watermark >= the row's key). If copies that end after t_commit hold the row
and copies that end before it do not, a copy's view is taken late in its window (the -wal is read after the database
file), which is what E10b's rule leaves ambiguous.

Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_copyview.py [--run-dir DIR] [--out exp/out/r16_e10_copyview.json]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
sys.path.insert(0, os.path.join(ROOT, "testbed", "e10b"))
import e10b_score as SC               # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_copyview.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    run, inputs = a.run_dir, {}
    f_bdt = glob.glob(os.path.join(run, "e10", "*_bdt.json"))[0]
    inputs["bdt"] = {"path": f_bdt, "sha256": sha(f_bdt)}
    trials = [t for t in json.load(open(f_bdt))["trials"] if not t.get("err")]
    ev_path = os.path.join(run, "events.jsonl")
    inputs["events"] = {"path": ev_path, "sha256": sha(ev_path)}
    snap = next(json.loads(x) for x in open(ev_path) if '"snap_del"' in x and '"snapshot"' in x)
    out_rows, summary = [], {}
    for m in ("direct", "copy"):
        ch = os.path.join(run, "e10s", "%s_chain.jsonl" % m)
        inputs["%s_chain" % m] = {"path": ch, "sha256": sha(ch)}
        polls = [p for p in SC.chain_polls(ch, snap["t_snapshot"]) if SC.tl_valid(p)]
        rows = []
        for t in trials:
            ti, tc, key = t["t_insert"], t["t_commit"], int(t["forged_state_id"])
            for p in polls:
                lo, hi = SC.obs_window(p, m)
                if hi < ti or lo > tc:
                    continue
                end = p["copy_at"] if m == "direct" else max(p["copy_at"], p.get("ts") or p["copy_at"])
                rows.append({"monitor": m, "trial": t["trial"], "age_s": t["age_s"], "seq": p["seq"],
                             "write_s": round(tc - ti, 6),
                             "copy_at_minus_t_insert_s": round(p["copy_at"] - ti, 6),
                             "window_end_minus_t_insert_s": round(end - ti, 6),
                             "window_end_minus_t_commit_s": round(end - tc, 6),
                             "held_row": (p["wm"].get("states") or -1) >= key})
        out_rows += rows
        summary[m] = {"overlapping_polls": len(rows),
                      "held_row": sum(1 for r in rows if r["held_row"]),
                      "window_ends_after_commit": sum(1 for r in rows if r["window_end_minus_t_commit_s"] > 0),
                      "ends_after_commit_and_held": sum(1 for r in rows if r["window_end_minus_t_commit_s"] > 0
                                                         and r["held_row"]),
                      "ends_before_commit_and_held": sum(1 for r in rows if r["window_end_minus_t_commit_s"] <= 0
                                                          and r["held_row"]),
                      "starts_before_insert_and_held": sum(1 for r in rows if r["copy_at_minus_t_insert_s"] < 0
                                                            and r["held_row"])}
    out = {"what": "EXPLORATORY: polls whose observation window overlaps an E10 BDT write, and whether they held the row",
           "script": {"path": "exp/sp2027/r16_e10_copyview.py", "sha256": sha(os.path.abspath(__file__))},
           "code": {"testbed/e10b/e10b_score.py": sha(SC.__file__)}, "inputs": inputs, "t_snapshot": snap["t_snapshot"],
           "summary": summary, "rows": out_rows, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    text = json.dumps(out, indent=1) + "\n"
    with open(a.out, "x") as fh:
        fh.write(text)
    print("wrote", a.out, hashlib.sha256(text.encode()).hexdigest())


if __name__ == "__main__":
    main()
