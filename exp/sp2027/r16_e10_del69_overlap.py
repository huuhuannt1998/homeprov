#!/usr/bin/env python3
"""E10 follow-up to r16_e10_del69.py (EXPLORATORY, saved data only): did copy-mode polls see the adversary's write
transactions BEFORE those commits became visible to a live reader?

Each in-hub adversary write (A1-BDT insert: t_insert .. t_commit; A3-DEL / DEL-PH delete: t_delete_start ..
t_delete_commit) runs on a fresh Python sqlite3 connection and records its start just before BEGIN IMMEDIATE and its
end after COMMIT returns. For every copy-mode poll whose copy window [copy_at, copy_at + copy_ms] overlaps such a write
window, and for every direct poll whose snapshot (copy_at) falls inside one, this lists whether the poll's content
already reflects the write:
  insert  the poll's states watermark >= the forged key (the row is in the poll's view);
  delete  only when decidable from watermarks: the deleted key was the largest key both in the poll before the write
          and in the poll after the commit returned minus the deletion, i.e. a poll watermark below the key means the
          row is absent (keys reused later are excluded by requiring the next poll after the commit to be below too).
If copy polls show writes whose commits had not yet returned (and direct polls never do), the DEL 69 view is the same
phenomenon: a copy that read the WAL after the in-flight transaction's frames were written but before the commit was
published to live readers.

Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_del69_overlap.py [--run-dir DIR] [--out exp/out/r16_e10_del69_overlap.json]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def polls_of(chain, cost_path):
    cost = {}
    for line in open(cost_path):
        if line.strip().startswith("{"):
            d = json.loads(line)
            if "seq_local" in d:
                cost[int(d["seq_local"])] = d.get("copy_ms")
    polls = {}
    with open(chain) as fh:
        for line in fh:
            if not line.strip():
                continue
            p = (json.loads(line).get("payload") or {})
            if p.get("observer") != "external-monitor" or "coverage" not in p or "seq_local" not in p:
                continue
            s = int(p["seq_local"])
            if s not in polls and p.get("copy_at") is not None and isinstance(p.get("wm"), dict) \
                    and not p.get("evidence_unobservable"):
                cm = cost.get(s)
                polls[s] = {"seq_local": s, "copy_at": p["copy_at"], "copy_end": p["copy_at"] + (cm or 0) / 1000.0,
                            "copy_ms": cm, "wm_states": p["wm"].get("states")}
    return sorted(polls.values(), key=lambda x: x["copy_at"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_del69_overlap.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    run, inputs = a.run_dir, {}
    P = {}
    for m in ("direct", "copy"):
        ch, co = os.path.join(run, "e10s", "%s_chain.jsonl" % m), os.path.join(run, "e10s", "%s_cost.jsonl" % m)
        inputs["%s_chain" % m] = {"path": ch, "sha256": sha(ch)}
        inputs["%s_cost" % m] = {"path": co, "sha256": sha(co)}
        P[m] = polls_of(ch, co)
    writes = []
    f = glob.glob(os.path.join(run, "e10", "*_bdt.json"))[0]
    inputs["bdt"] = {"path": f, "sha256": sha(f)}
    for t in json.load(open(f))["trials"]:
        writes.append({"kind": "insert", "arm": "BDT", "trial": t["trial"], "key": int(t["forged_state_id"]),
                       "t_start": t["t_insert"], "t_end": t["t_commit"]})
    for op, arm in (("del", "DEL"), ("delph", "DEL-PH")):
        f = glob.glob(os.path.join(run, "e10", "*_%s.json" % op))[0]
        inputs[op] = {"path": f, "sha256": sha(f)}
        for t in json.load(open(f))["trials"]:
            writes.append({"kind": "delete", "arm": arm, "trial": t["trial"], "key": int(t["deleted_row"]["state_id"]),
                           "t_start": t["t_delete_start"], "t_end": t["t_delete_commit"]})
    # Decidability. insert: the poll before the write lacked the key (wm < key), so wm >= key in the overlapping poll
    # means the forged row is in its view. delete: the direct monitor's last poll before and first poll after the
    # overlapping poll's end both have wm == key (the key is the largest key and present in the published database on
    # both sides), so an overlapping poll with wm < key does not contain the row; wm == key means it does.
    D = P["direct"]
    rows = []
    for w in writes:
        for m in ("copy", "direct"):
            ps = P[m]
            if m == "copy":
                ov = [p for p in ps if p["copy_at"] < w["t_end"] and p["copy_end"] > w["t_start"]]
            else:
                ov = [p for p in ps if w["t_start"] <= p["copy_at"] < w["t_end"]]
            for p in ov:
                if w["kind"] == "insert":
                    before = [q for q in ps if q["copy_end"] <= w["t_start"]]
                    decidable = bool(before) and before[-1]["wm_states"] < w["key"]
                    reflects = p["wm_states"] >= w["key"]
                else:
                    db_ = [q for q in D if q["copy_at"] < p["copy_at"] and q["seq_local"] != p["seq_local"]]
                    da_ = [q for q in D if q["copy_at"] > p["copy_end"] and q["copy_at"] <= w["t_end"]]
                    decidable = bool(db_) and bool(da_) and db_[-1]["wm_states"] == w["key"] and da_[0]["wm_states"] == w["key"] \
                        and p["wm_states"] <= w["key"]
                    if p["wm_states"] == w["key"]:
                        decidable = True          # the largest key in the poll's view is the row's own: the row is present
                    reflects = (p["wm_states"] < w["key"]) if decidable else None
                rows.append({"monitor": m, "kind": w["kind"], "arm": w["arm"], "trial": w["trial"], "key": w["key"],
                             "write_duration_s": round(w["t_end"] - w["t_start"], 6), "seq_local": p["seq_local"],
                             "poll_wm_states": p["wm_states"], "copy_ms": p["copy_ms"],
                             "copy_at_minus_write_start_s": round(p["copy_at"] - w["t_start"], 6),
                             "copy_end_minus_write_start_s": round(p["copy_end"] - w["t_start"], 6),
                             "commit_returned_after_copy_end_s": round(w["t_end"] - p["copy_end"], 6),
                             "commit_returned_after_copy_end": w["t_end"] > p["copy_end"],
                             "decidable": decidable, "poll_reflects_write": reflects})
    summ = {}
    for m in ("copy", "direct"):
        for kind in ("insert", "delete"):
            rs = [r for r in rows if r["monitor"] == m and r["kind"] == kind and r["decidable"]]
            early = [r for r in rs if r["commit_returned_after_copy_end"]]
            summ["%s_%s" % (m, kind)] = {
                "overlapping_polls_decidable": len(rs),
                "polls_ending_before_the_commit_returned": len(early),
                "of_those_reflecting_the_write": sum(1 for r in early if r["poll_reflects_write"]),
                "cases": [{k: r[k] for k in ("arm", "trial", "seq_local", "write_duration_s", "copy_ms",
                                             "copy_at_minus_write_start_s", "copy_end_minus_write_start_s",
                                             "commit_returned_after_copy_end_s", "poll_reflects_write")} for r in rs]}
    summ["undecidable"] = [{k: r[k] for k in ("monitor", "arm", "trial", "seq_local", "poll_wm_states", "key")}
                           for r in rows if not r["decidable"]]
    out = {"what": "copy and direct polls overlapping in-hub adversary write transactions (EXPLORATORY)", "inputs": inputs,
           "summary": summ, "rows": rows, "writes": len(writes),
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "script": {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
