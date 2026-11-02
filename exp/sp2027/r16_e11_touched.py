#!/usr/bin/env python3
"""E11 (e11_main), EXPLORATORY: verdicts of the touched seconds that no arm or benign operation edited.

The frozen scorer (exp/stages/e11_score.py) excludes every touched second from the floor: a second an arm wrote, edited
or named (relock, unlock, mark) or a benign operation changed or listed (re-sent, backfilled, removed points, the
rows_before the harness read, every Label_Probe second). H7 predicts attributable violations on EXACTLY the seconds an
operation changes; a touched second that no operation changed is outside both the floor and the per-operation counts.
This script lists the verdict classes of those seconds per scheme, so that "exactly" can be checked. It imports the
frozen scorer's functions (not its main()) and rebuilds the scorer's verdicts from the run's saved files.

    taskpolicy -b <home>/miniconda3/bin/python3 -B exp/sp2027/r16_e11_touched.py \
        --run /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e11/e11_main --tag e11_main
Read only (the final snapshot and registry are copied to a temporary directory); writes one new JSON file (mode "x").
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True          # never write __pycache__ into the run folder
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
SCORER = os.path.join(REPO, "exp", "stages", "e11_score.py")
SCORER_SHA = "94d58da534eabe16857bd6b16737c15e55bc72ad4fe8e4446aea4f38a1267112"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def iso(t):
    return datetime.datetime.fromtimestamp(float(t), datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--tag", default="e11_main")
    ap.add_argument("--out", default=os.path.join(OUT, "r16_e11_touched.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    if sha(SCORER) != SCORER_SHA:
        raise SystemExit("e11_score.py is not at its registered sha256")
    spec = importlib.util.spec_from_file_location("e11_score_frozen", SCORER)
    S = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(S)
    tick = time.time()
    run = a.run
    t0 = float(open(os.path.join(run, "t_start")).read())
    t1 = float(open(os.path.join(run, "t_end")).read())
    chain_p, arch_p, benign_p = (os.path.join(run, x) for x in ("chain.jsonl", "archive.jsonl", "benign.jsonl"))
    lines = open(chain_p).read().splitlines()
    reports = {arm: json.load(open(os.path.join(OUT, "%s_report_%s.json" % (a.tag, arm)))) for arm in S.ARMS}
    ops = [json.loads(x) for x in open(benign_p) if x.strip()]
    score_path = os.path.join(OUT, "%s_score.json" % a.tag)
    score = json.load(open(score_path))
    res = {"script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "label": "exploratory",
           "inputs": {"score_sha256": sha(score_path), "scorer_sha256": sha(SCORER), "run_chain": sha(chain_p),
                      "run_archive": sha(arch_p), "run_benign": sha(benign_p),
                      "run_final_db": sha(os.path.join(run, "snapshots", "final.db")),
                      "reports": {arm: sha(os.path.join(OUT, "%s_report_%s.json" % (a.tag, arm))) for arm in S.ARMS}}}
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "final.db")
        shutil.copy2(os.path.join(run, "snapshots", "final.db"), db)
        jd = os.path.join(tmp, "jsondb")
        shutil.copytree(os.path.join(run, "snapshots", "jsondb_final"), jd)
        scratch = os.path.join(tmp, "scratch")
        os.makedirs(scratch)
        A = S.load_reader(os.path.join(run, "code"), os.path.join(run, "code", "oh_monitor.py"), scratch)
        polls, roots = S.parse_chain(lines)
        cov = S.Coverage(polls)
        data = S.read_db(A, db, jd)
        finals = {sch: A.nodes_from_rows(sch, data, with_meta=True) for sch in S.SCHEMES}
        recon, _rstat = S.reconstruct(A, arch_p, lines, polls)
        roots_by = {"closure": roots, "rows": recon["rows"], "wholerow": recon["wholerow"]}
        verd = {sch: S.verdicts(A, cov, roots_by[sch], finals[sch], t0, t1) for sch in S.SCHEMES}
        label_item = next((op.get("item") for op in ops if op["op"] == "B-LABEL"), "Label_Probe")
        label_secs = {int(m["ts"]) for _n, m in finals["closure"] if m.get("item") == label_item}
        ts_, _tm = S.touched_sets(reports, ops, label_secs)
        assert len(ts_) == score["touched_seconds"]
        edited = {int(t["row_ts"]) for rep in reports.values() for t in rep["trials"]}       # the edited row's second
        changed = {int(x[0]) // 1000 for op in ops for x in (op.get("affected_past") or [])}
        rest = sorted(ts_ - edited - changed - set(label_secs))
        why_touched = {}
        for k in rest:
            src = []
            for arm, rep in reports.items():
                for t in rep["trials"]:
                    for f in ("mark", "target"):
                        if t.get(f) and int(t[f]["time_ms"]) // 1000 == k:
                            src.append("%s %s" % (arm, f))
                    rl = (t.get("relock") or {}).get("row")
                    if rl and int(rl[0]) // 1000 == k:
                        src.append("%s relock" % arm)
            for op in ops:
                for x in ((op.get("result") or {}).get("rows_before") or []):
                    if int(x[0]) // 1000 == k:
                        src.append("%s rows_before" % op["op"])
            why_touched[k] = sorted(set(src))
        per = {}
        for sch in S.SCHEMES:
            cls = collections.Counter((verd[sch]["second"].get(k) or {"class": "absent"})["class"] for k in rest)
            att = [{"second": k, "utc": iso(k), "touched_by": why_touched[k],
                    "why": verd[sch]["second"][k].get("why")} for k in rest
                   if (verd[sch]["second"].get(k) or {}).get("class") == "attributable"]
            absent = [{"second": k, "utc": iso(k), "touched_by": why_touched[k], "in_scored_window": int(t0) <= k <= int(t1)}
                      for k in rest if verd[sch]["second"].get(k) is None]
            per[sch] = {"classes": dict(cls), "attributable": att, "absent": absent}
        res["note"] = "the four set sizes below are intersections with the touched set and overlap; they are not a partition"
        res["touched_seconds"] = len(ts_)
        res["edited_by_an_arm"] = len(edited & ts_)
        res["changed_by_a_benign_operation"] = len(changed & ts_)
        res["label_probe_seconds"] = len(set(label_secs) & ts_)
        res["touched_not_edited_not_changed"] = len(rest)
        res["touched_by_kind"] = dict(collections.Counter(s.split(" ", 1)[1] if " " in s else s
                                                          for k in rest for s in why_touched[k]))
        res["per_scheme"] = per
    res["seconds"] = round(time.time() - tick, 1)
    res["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(a.out, "x") as fh:
        json.dump(res, fh, indent=1, default=str)
    print("->", a.out, sha(a.out))


if __name__ == "__main__":
    main()
