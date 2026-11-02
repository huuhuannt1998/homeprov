#!/usr/bin/env python3
"""E11 (openHAB, e11_main): per-second verdicts behind the frozen scorer's counts, and the exploratory diagnoses for
E11_RESULTS_NOTES.md (round 16). Read only; writes one new JSON file (mode "x", never overwrites).

The frozen scorer exp/stages/e11_score.py (registered sha256 94d58da534ea...) reports per benign operation only the
COUNT of verdict classes over the seconds the operation changed. This script imports that same file (its functions,
not its main()), rebuilds exactly the scorer's verdicts from the run's saved files, checks that it reproduces the score
file's counts, and lists the verdict of every second behind each count. Everything else here is EXPLORATORY:
  - B-REPLACE-SAME: which of its seconds a later operation re-wrote (overlap with B-REPLACE-NEW), the rows' rowid,
    time text and value as sealed, just after the operation, and in the final snapshot (per-poll archive and final
    snapshot), and the three schemes' roots of the one second the archive holds after the operation;
  - B-BACKFILL: which sent points were stored and which were ignored (INSERT OR IGNORE on PRIMARY KEY(time)), the
    seconds two backfills share, and the late-row lags next to A-BD's;
  - B-LABEL and B-RETAIN: each second's position relative to the scored window and to the rename;
  - single-write denominators (seconds holding a row of the written item), the offline schemes' benign-late seconds
    and unmatched archive records, poll gaps over the whole session, and the hub logs' coverage.

    taskpolicy -b <home>/miniconda3/bin/python3 -B exp/sp2027/r16_e11_verdicts.py \
        --run /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e11/e11_main --tag e11_main
Inputs are opened read-only; the final snapshot and the registry files are copied to a temporary directory first.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import datetime
import hashlib
import importlib.util
import json
import os
import re
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
    return None if t is None else datetime.datetime.fromtimestamp(float(t), datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def ms_text(ms):
    """The DAO's stored time text for an epoch-millisecond time (UTC hub)."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ms // 1000)) + ".%03d" % (ms % 1000)


def load_scorer():
    if sha(SCORER) != SCORER_SHA:
        raise SystemExit("e11_score.py is not at its registered sha256")
    spec = importlib.util.spec_from_file_location("e11_score_frozen", SCORER)
    S = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(S)
    return S


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--tag", default="e11_main")
    ap.add_argument("--out", default=os.path.join(OUT, "r16_e11_verdicts.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    tick = time.time()
    run = a.run
    S = load_scorer()
    score_path = os.path.join(OUT, "%s_score.json" % a.tag)
    score = json.load(open(score_path))
    chain_p, arch_p = os.path.join(run, "chain.jsonl"), os.path.join(run, "archive.jsonl")
    benign_p = os.path.join(run, "benign.jsonl")
    inputs = {"score": {"path": os.path.relpath(score_path, REPO), "sha256": sha(score_path)},
              "scorer": {"path": os.path.relpath(SCORER, REPO), "sha256": sha(SCORER)},
              "run_chain": sha(chain_p), "run_archive": sha(arch_p), "run_benign": sha(benign_p),
              "run_final_db": sha(os.path.join(run, "snapshots", "final.db")),
              "run_reader": sha(os.path.join(run, "code", "oh_monitor.py")),
              "run_monitor": sha(os.path.join(run, "code", "monitor.py")),
              "run_plan": sha(os.path.join(run, "plan.json"))}
    t0 = float(open(os.path.join(run, "t_start")).read())
    t1 = float(open(os.path.join(run, "t_end")).read())
    lines = open(chain_p).read().splitlines()
    reports = {arm: json.load(open(os.path.join(OUT, "%s_report_%s.json" % (a.tag, arm)))) for arm in S.ARMS}
    for arm in S.ARMS:
        inputs["report_" + arm] = sha(os.path.join(OUT, "%s_report_%s.json" % (a.tag, arm)))
    ops = [json.loads(x) for x in open(benign_p) if x.strip()]
    res = {"script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "label": "exploratory except where a field reproduces a registered count of the frozen scorer",
           "inputs": inputs, "window": {"t_start": t0, "t_end": t1, "t_start_utc": iso(t0), "t_end_utc": iso(t1),
                                        "scored_seconds": [int(t0), int(t1)]}}

    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "final.db")
        shutil.copy2(os.path.join(run, "snapshots", "final.db"), db)
        jd = os.path.join(tmp, "jsondb")
        shutil.copytree(os.path.join(run, "snapshots", "jsondb_final"), jd)
        scratch = os.path.join(tmp, "scratch")
        os.makedirs(scratch)
        A = S.load_reader(os.path.join(run, "code"), os.path.join(run, "code", "oh_monitor.py"), scratch)
        M = A.M
        polls, roots = S.parse_chain(lines)
        cov = S.Coverage(polls)
        data = S.read_db(A, db, jd)
        finals = {sch: A.nodes_from_rows(sch, data, with_meta=True) for sch in S.SCHEMES}
        recon, rstat = S.reconstruct(A, arch_p, lines, polls)
        roots_by = {"closure": roots, "rows": recon["rows"], "wholerow": recon["wholerow"]}
        verd = {sch: S.verdicts(A, cov, roots_by[sch], finals[sch], t0, t1) for sch in S.SCHEMES}
        label_item = next((op.get("item") for op in ops if op["op"] == "B-LABEL"), "Label_Probe")
        label_secs = {int(m["ts"]) for _n, m in finals["closure"] if m.get("item") == label_item}
        ts_, tm_ = S.touched_sets(reports, ops, label_secs)
        bs = {sch: S.by_seg(finals[sch], 1) for sch in S.SCHEMES}

        # ---------------------------------------------------------------- reproduction of the score file's counts
        bo = S.benign_outcomes(ops, verd, label_secs)
        fl = S.floor(verd, ts_, tm_)
        det = {arm: {sch: S.score_arm(arm, reports[arm], verd)["detection"][sch]["second"]["k"] for sch in S.SCHEMES}
               for arm in S.ARMS}
        res["reproduces_score"] = {
            "O4_benign_operations_per_scheme": [x["per_scheme"] for x in bo] == [x["per_scheme"] for x in
                                                                                 score["O4_benign_operations"]],
            "O4_floor_second": all(fl[s]["second"]["untouched_anchored"]["k"] == score["O4_floor"][s]["second"]
                                   ["untouched_anchored"]["k"] and fl[s]["second"]["untouched_anchored"]["n"] ==
                                   score["O4_floor"][s]["second"]["untouched_anchored"]["n"] for s in S.SCHEMES),
            "O3_detection_second_k": all(det[arm][s] == score["O3_detection"][arm]["detection"][s]["second"]["k"]
                                         for arm in S.ARMS for s in S.SCHEMES),
            "touched_seconds": len(ts_) == score["touched_seconds"],
            "offline_reconstruction": rstat == score["offline_reconstruction"]["records"]}

        def row_meta(sch, k, item=None):
            return [{"table": m["table"], "rowid": m["rowid"], "time": m["time"], "item": m.get("item")}
                    for _n, m in bs[sch].get(int(k), []) if item is None or m.get("item") == item]

        def value_of(table, rowid):
            tab = data["tables"].get(table) or {}
            ci = {c.lower(): i for i, c in enumerate(tab.get("cols") or [])}
            for r in tab.get("rows") or []:
                if r[ci["rowid"]] == rowid:
                    return r[ci["value"]]
            return None

        def second_record(k, item=None):
            out = {"second": int(k), "utc": iso(k), "in_scored_window": int(t0) <= int(k) <= int(t1),
                   "closure_first_root_sealed_utc": iso((roots.get(("second", str(k))) or {}).get("seal_ts")),
                   "per_scheme": {}}
            for sch in S.SCHEMES:
                v = verd[sch]["second"].get(int(k))
                e = {"class": v["class"] if v else "absent"}
                if v:
                    for f in ("why", "delta_n", "root_n", "rows_now"):
                        if f in v:
                            e[f] = v[f]
                    if v.get("late"):
                        e["late_lags_s"] = [x["lag_s"] for x in v["late"]]
                out["per_scheme"][sch] = e
            out["final_rows_of_item"] = [dict(r, value=value_of(r["table"], r["rowid"])) for r in row_meta("closure", k, item)]
            return out

        # ---------------------------------------------------------------- per benign operation, per second
        aff = {}
        per_op = []
        for i, op in enumerate(ops):
            secs = sorted({int(ms) // 1000 for ms, *_ in (op.get("affected_past") or [])})
            if op["op"] == "B-LABEL":
                secs = sorted(label_secs)
            aff[i] = set(secs)
            per_op.append({"index": i, "op": op["op"], "item": op.get("item"), "t_start_utc": iso(op.get("t_start")),
                           "seconds": [second_record(k, op.get("item")) for k in secs]})
        for i, rec in enumerate(per_op):
            rec["seconds_shared_with_other_ops"] = {
                "%d:%s" % (j, ops[j]["op"]): sorted(aff[i] & aff[j]) for j in aff if j != i and aff[i] & aff[j]}
        res["benign_operations_per_second"] = per_op

        # ---------------------------------------------------------------- B-REPLACE-SAME diagnosis
        i_same = next(i for i, op in enumerate(ops) if op["op"] == "B-REPLACE-SAME")
        i_new = next(i for i, op in enumerate(ops) if op["op"] == "B-REPLACE-NEW")
        same, new = ops[i_same], ops[i_new]
        item = same["item"]
        iid = next(r[0] for r in data["items"] if r[1] == item)
        table = A.table_for(iid, item)
        tpost_same, tpost_new = same["result"]["t_post"], new["result"]["t_post"]
        sent_same = {int(ms): v for ms, v in same["points"]}
        sent_new = {int(ms): v for ms, v in new["points"]}
        before_same = {int(ms): v for ms, v in same["result"]["rows_before"]}
        arch = []
        for x in open(arch_p):
            try:
                r = json.loads(x)
            except ValueError:
                continue
            arch.append(r)
        arch.sort(key=lambda r: r["t_load"])

        def arch_row(rec, text):
            tab = rec["tables"].get(table)
            if not tab:
                return None
            ci = {c.lower(): j for j, c in enumerate(tab["cols"])}
            for r in tab["rows"]:
                if r[ci["time"]] == text:
                    return {"rowid": r[ci["rowid"]], "time": r[ci["time"]], "value": r[ci["value"]]}
            return None

        def arch_data(rec):
            return {k: rec[k] for k in ("items_cols", "items", "mapped", "tables", "registry")}

        def first_root(sch, k):
            r = roots_by[sch].get(("second", str(k)))
            return {"acc": r["acc"], "n": r["n"]} if r else None

        rs = []
        for ms in sorted(int(x[0]) for x in same["affected_past"]):
            text = ms_text(ms)
            k = ms // 1000
            seen = collections.defaultdict(set)
            for rec in arch:
                row = arch_row(rec, text)
                if row is None:
                    continue
                phase = ("before_B-REPLACE-SAME" if rec["t_load"] < tpost_same else
                         "after_B-REPLACE-SAME_before_B-REPLACE-NEW" if rec["t_load"] < tpost_new else
                         "after_B-REPLACE-NEW")
                seen[phase].add(json.dumps(row, sort_keys=True))
            fin = [dict(r, value=value_of(r["table"], r["rowid"])) for r in row_meta("closure", k, item)]
            rs.append({"time_ms": ms, "time_text": text, "second": k, "utc": iso(k),
                       "value_stored_before_B-REPLACE-SAME (harness rows_before)": before_same.get(ms),
                       "value_sent_by_B-REPLACE-SAME": sent_same.get(ms),
                       "value_sent_by_B-REPLACE-NEW": sent_new.get(ms),
                       "also_affected_by_B-REPLACE-NEW": k in aff[i_new],
                       "closure_first_root_sealed_utc": iso((roots.get(("second", str(k))) or {}).get("seal_ts")),
                       "sealed_before_B-REPLACE-SAME": (roots.get(("second", str(k))) or {}).get("seal_ts", 1e18) < tpost_same,
                       "archive_rows_by_phase": {p: [json.loads(s) for s in sorted(v)] for p, v in seen.items()},
                       "final_snapshot_rows": fin,
                       "scorer_classes": {sch: (verd[sch]["second"].get(k) or {"class": "absent"})["class"]
                                          for sch in S.SCHEMES}})
        # roots of each affected second recomputed from every archive record between the two REPLACE operations
        roots_between = {}
        for x in rs:
            k = x["second"]
            cmp_ = collections.Counter()
            n_rec = 0
            for rec in arch:
                if not (tpost_same <= rec["t_load"] < tpost_new) or arch_row(rec, x["time_text"]) is None:
                    continue
                if rec["t_load"] - 180 > k:          # the archive window must hold the whole second
                    continue
                n_rec += 1
                d = arch_data(rec)
                for sch in S.SCHEMES:
                    phi = M.commit(A.nodes_from_rows(sch, d))
                    v = (phi.get("second") or {}).get(str(k))
                    cmp_["%s:%s" % (sch, "equal_to_first_sealed_root" if v and {"acc": v["acc"], "n": v["n"]} ==
                                    first_root(sch, k) else "different")] += 1
            if n_rec:
                roots_between[str(k)] = {"utc": iso(k), "archive_records": n_rec, "comparisons": dict(cmp_)}
        wm_series = []
        for p in sorted(polls.values(), key=lambda p: p["seq"]):
            if p["ts"] and (abs(p["ts"] - tpost_same) < 12 or abs(p["ts"] - tpost_new) < 12):
                wm_series.append({"seq": p["seq"], "utc": iso(p["ts"]), "wm_" + table: (p["wm"] or {}).get(table)})
        final_rows = []
        tab = data["tables"][table]
        ci = {c.lower(): j for j, c in enumerate(tab["cols"])}
        for r in sorted(tab["rows"], key=lambda r: r[ci["rowid"]]):
            final_rows.append([r[ci["rowid"]], r[ci["time"]], r[ci["value"]]])
        res["B_REPLACE_SAME"] = {
            "label": "exploratory",
            "item": item, "table": table, "t_post_B-REPLACE-SAME_utc": iso(tpost_same),
            "t_post_B-REPLACE-NEW_utc": iso(tpost_new),
            "affected_seconds": rs,
            "affected_seconds_also_affected_by_B-REPLACE-NEW": sum(1 for x in rs if x["also_affected_by_B-REPLACE-NEW"]),
            "roots_recomputed_from_archive_between_the_two_operations": roots_between,
            "watermark_around_the_two_operations": wm_series,
            "final_table_rows_by_rowid": final_rows}

        # ---------------------------------------------------------------- B-BACKFILL: stored or ignored points
        bf = []
        i_bf = [i for i, op in enumerate(ops) if op["op"] == "B-BACKFILL"]
        for i in i_bf:
            op = ops[i]
            after = {int(ms): v for ms, v in op["result"]["rows_after"]}
            before = {int(ms): v for ms, v in op["result"]["rows_before"]}
            pts = []
            for ms, v in op["points"]:
                ms = int(ms)
                pts.append({"time_ms": ms, "sent": v, "row_before": before.get(ms), "row_after": after.get(ms),
                            "stored": ms not in before})
            bf.append({"index": i, "t_start_utc": iso(op["t_start"]), "points_sent": len(pts),
                       "points_stored": sum(p["stored"] for p in pts),
                       "points_ignored_time_already_present": [p for p in pts if not p["stored"]]})
        distinct = set().union(*(aff[i] for i in i_bf))
        res["B_BACKFILL"] = {"label": "exploratory", "ops": bf, "distinct_seconds": len(distinct),
                             "distinct_seconds_closure_classes": dict(collections.Counter(
                                 (verd["closure"]["second"].get(k) or {"class": "absent"})["class"] for k in distinct)),
                             "why_closure": dict(collections.Counter(
                                 (verd["closure"]["second"].get(k) or {}).get("why") for k in distinct)),
                             "min_lag_s_closure": min(min(x["lag_s"] for x in verd["closure"]["second"][k]["late"])
                                                      for k in distinct if verd["closure"]["second"].get(k, {}).get("late"))}

        # ---------------------------------------------------------------- arms: why classes and lags (closure)
        arms = {}
        for arm in S.ARMS:
            whys, lags = collections.Counter(), []
            for t in reports[arm]["trials"]:
                v = verd["closure"]["second"].get(int(t["row_ts"]))
                whys[(v or {}).get("why")] += 1
                for x in (v or {}).get("late") or []:
                    lags.append(x["lag_s"])
            arms[arm] = {"why_closure": dict(whys), "late_rows": len(lags),
                         "lag_s": {"min": min(lags), "max": max(lags)} if lags else None}
        res["arms_closure_why_and_lag"] = arms

        # ---------------------------------------------------------------- B-LABEL
        lab = next(op for op in ops if op["op"] == "B-LABEL")
        lrows = sorted(((m["ts"], m["time"], m["table"], m["rowid"]) for _n, m in finals["closure"]
                        if m.get("item") == label_item))
        lab_rows = []
        for ts, text, tbl, rid in lrows:
            k = int(ts)
            rt = (roots.get(("second", str(k))) or {}).get("seal_ts")
            lab_rows.append({"time": text, "second": k, "written_before_rename": ts < lab["t_start"],
                             "in_scored_window": int(t0) <= k <= int(t1),
                             "closure_first_root_sealed_utc": iso(rt),
                             "sealed_before_rename": (rt is not None and rt < lab["t_start"]),
                             "value": value_of(tbl, rid),
                             "classes": {sch: (verd[sch]["second"].get(k) or {"class": "absent"})["class"]
                                         for sch in S.SCHEMES}})
        sealed_before = [x for x in lab_rows if x["written_before_rename"] and x["in_scored_window"]]
        res["B_LABEL"] = {"label": "exploratory (per-second view of the registered count)",
                          "rename_utc": iso(lab["t_start"]), "rows": lab_rows,
                          "in_window_written_before_rename": len(sealed_before),
                          "in_window_written_before_rename_wholerow_attributable":
                              sum(1 for x in sealed_before if x["classes"]["wholerow"] == "attributable"),
                          "in_window_written_after_rename": sum(1 for x in lab_rows if not x["written_before_rename"]
                                                                and x["in_scored_window"]),
                          "outside_window": [x["time"] for x in lab_rows if not x["in_scored_window"]]}

        # ---------------------------------------------------------------- B-RETAIN
        ret = next(op for op in ops if op["op"] == "B-RETAIN")
        rsecs = sorted({int(ms) // 1000 for ms, *_ in ret["affected_past"]})
        inside = [k for k in rsecs if int(t0) <= k <= int(t1)]
        outside = [k for k in rsecs if not (int(t0) <= k <= int(t1))]
        pre = {}
        for sch in S.SCHEMES:
            pre[sch] = dict(collections.Counter(S.verify(M, cov, roots_by[sch], bs[sch], "second", 1, k)["class"]
                                                for k in outside))
        rid = next(r[0] for r in data["items"] if r[1] == ret["item"])
        rtab = data["tables"][A.table_for(rid, ret["item"])]
        rci = {c.lower(): j for j, c in enumerate(rtab["cols"])}
        left_old = sum(1 for r in rtab["rows"] if A.parse_time(r[rci["time"]]) is not None and
                       A.parse_time(r[rci["time"]]) * 1000 < ret["result"]["until_ms"])
        res["B_RETAIN"] = {"label": "exploratory (per-second view of the registered count)",
                           "until_utc": iso(ret["result"]["until_ms"] / 1000), "rows_removed": len(ret["affected_past"]),
                           "seconds": len(rsecs), "inside_scored_window": len(inside),
                           "outside_scored_window": len(outside),
                           "outside_first_last_utc": [iso(outside[0]), iso(outside[-1])] if outside else None,
                           "outside_all_before_t_start": all(k < int(t0) for k in outside),
                           "inside_classes": {sch: dict(collections.Counter(
                               (verd[sch]["second"].get(k) or {"class": "absent"})["class"] for k in inside))
                               for sch in S.SCHEMES},
                           "outside_seconds_closure_root_anchored": sum(1 for k in outside if ("second", str(k)) in roots),
                           "outside_seconds_verify_applied_exploratory": pre,
                           "final_rows_older_than_until": left_old}

        # ---------------------------------------------------------------- single-write denominators (H3)
        def secs_holding(name):
            return len({int(m["ts"]) for _n, m in finals["closure"] if m.get("item") == name
                        and t0 - 1 <= int(m["ts"]) <= t1 + 1})
        res["single_write_denominators"] = {
            "rule": "seconds k with t0-1 <= k <= t1+1 (the scorer's single_writes window) holding a row of the item",
            "FrontDoor_Lock": secs_holding("FrontDoor_Lock"), "Kitchen_Temp": secs_holding("Kitchen_Temp"),
            "Label_Probe": secs_holding("Label_Probe")}

        # ---------------------------------------------------------------- floor detail (offline schemes)
        fd = {}
        for sch in ("rows", "wholerow"):
            un = [(k, r) for k, r in verd[sch]["second"].items() if k not in ts_ and r["class"] == "benign_late"]
            fd[sch] = [{"second": k, "utc": iso(k), "why": r.get("why"), "lags_s": [x["lag_s"] for x in r.get("late") or []],
                        "closure_class": (verd["closure"]["second"].get(k) or {"class": "absent"})["class"],
                        "closure_root_n": (verd["closure"]["second"].get(k) or {}).get("root_n"),
                        "offline_root_exists": ("second", str(k)) in roots_by[sch]} for k, r in un]
        # which chain records the archive did not match (reconstruct()'s matching, repeated with the record ids)
        loads = [r["t_load"] for r in arch]
        unmatched = []
        for line in lines:
            rec = json.loads(line)
            p = rec.get("payload") or {}
            if p.get("observer") != "external-monitor" or p.get("evidence_unobservable") or not p.get("sealed"):
                continue
            own = {(g, str(k)): v for g, segs in p["sealed"].items() if g in dict(S.GRANS) for k, v in segs.items()
                   if isinstance(v, dict) and "sealed_at" not in v}
            if not own:
                continue
            j = bisect.bisect_left(loads, (p.get("ts") or 0) - 0.01)
            ok = False
            for cand in arch[j:j + 3]:
                if cand["t_load"] > (p.get("ts") or 0) + 10:
                    break
                phi = M.commit(A.nodes_from_rows("closure", arch_data(cand)))
                if all((phi.get(g) or {}).get(s) == {"acc": v["acc"], "n": v["n"]} for (g, s), v in own.items()):
                    ok = True
                    break
            if not ok:
                unmatched.append({"seq_local": p.get("seq_local"), "utc": iso(p.get("ts")),
                                  "sealed": {g: sorted(int(k) for k in segs) for g, segs in p["sealed"].items()
                                             if isinstance(segs, dict)},
                                  "nearest_archive_t_load_delta_s": round(min((abs(x - p["ts"]) for x in loads)), 3)})
        res["floor_detail_offline_schemes"] = {"benign_late_untouched_seconds": fd,
                                               "archive_records_not_matched": unmatched}

        # ---------------------------------------------------------------- persisted schema (H2) and household rows
        res["persisted_schema"] = {"items": data["items_cols"],
                                   "item_tables": sorted({json.dumps(t["cols"]) for t in data["tables"].values()})}
        plan = json.load(open(os.path.join(run, "plan.json")))
        restarts = [datetime.datetime.fromisoformat(op["restart"]["started_at"][:26] + "+00:00").timestamp()
                    for op in ops if op["op"] == "B-RESTART"]
        hh = {}
        for name in ("Kitchen_Temp", "Hallway_Temp", "Power_Meter"):
            per = plan["schedule"][name]["period_s"] if name != "Power_Meter" else 60.0   # Power_Meter: cron everyMinute
            tss = sorted(m["ts"] for _n, m in finals["closure"] if m.get("item") == name)
            big = [(b - a_, a_, b) for a_, b in zip(tss, tss[1:]) if b - a_ > 1.5 * per]
            hh[name] = {"rows": len(tss), "first_utc": iso(tss[0]), "last_utc": iso(tss[-1]), "expected_period_s": per,
                        "gaps_over_1.5_periods": [{"gap_s": round(g, 3), "from_utc": iso(a_), "to_utc": iso(b),
                                                   "spans_a_restart": any(a_ - 5 <= r <= b + 5 for r in restarts)}
                                                  for g, a_, b in big]}
        res["household_row_gaps"] = {"label": "exploratory proxy for lost hub writes (the hub log before 13:25:49Z "
                                              "was not saved)", "items": hh}

        # ---------------------------------------------------------------- polls over the whole session
        oc = sorted(p["copy_at"] for p in polls.values() if p["observable"] and p.get("copy_at") is not None)
        gaps = sorted(((b - a_), a_, b) for a_, b in zip(oc, oc[1:]))
        res["polls_whole_session"] = {"observable_polls": len(oc), "first_utc": iso(oc[0]), "last_utc": iso(oc[-1]),
                                      "max_gap_s": round(gaps[-1][0], 3), "max_gap_between_utc": [iso(gaps[-1][1]),
                                                                                                  iso(gaps[-1][2])],
                                      "gaps_over_30s": sum(1 for g in gaps if g[0] > 30)}

    # -------------------------------------------------------------------- hub logs' coverage
    def span(p):
        if not os.path.exists(p):
            return None
        ts = [x[:23] for x in open(p, errors="replace") if re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}", x)]
        busy = sum(1 for x in open(p, errors="replace") if "SQLITE_BUSY" in x or "database is locked" in x)
        return {"sha256": sha(p), "lines": sum(1 for _ in open(p, errors="replace")), "first": ts[0] if ts else None,
                "last": ts[-1] if ts else None, "lines_busy_or_locked": busy}
    res["hub_logs"] = {"openhab.log": span(os.path.join(run, "logs", "openhab.log")),
                       "events.log": span(os.path.join(run, "logs", "events.log")),
                       "hub_stdout.log": span(os.path.join(run, "logs", "hub_stdout.log")),
                       "restarts": [{"started_at": op["restart"]["started_at"], "started_before": op["restart"]
                                     ["started_before"]} for op in ops if op["op"] == "B-RESTART"]}
    res["seconds"] = round(time.time() - tick, 1)
    res["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(a.out, "x") as fh:
        json.dump(res, fh, indent=1, default=str)
    print("->", a.out, sha(a.out))


if __name__ == "__main__":
    main()
