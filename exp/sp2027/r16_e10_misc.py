#!/usr/bin/env python3
"""E10 exploratory: small derived quantities the notes cite that no frozen output carries directly.

  timing     completion times (st_mtime, UTC) of the files run_e10.sh writes in sequence after the run (score, r5 score,
             collusion direct, collusion copy, migration offline), so each step's duration is the gap to the previous
             file; O-MIG's is mtime(migration) - mtime(collusion_copy). The scorer's per-verification wall times are
             summed from exp/out/e10_main_score.json verifications.<k>.wall_s.
  restarts   arm R per trial (kind, target, landed, fire error, late rows by verdict under both verifiers, polls,
             largest gap, unobservable polls) from exp/out/e10_main_r5_score.json R_restart.per_trial.
  sham       arm S per variant: listed, displayed cause changed, rows deleted, db writes (per_trial).
  deletion   A3-DEL and A3-DEL-PH: visible time distribution, dangling successors (residue), DEL-PH sensor error
             (exp/out/e10_main_score.json arms.DEL / DEL-PH per_trial).
  pi4        arm E: quick_check outcomes, poll errors and read paths per run; copy-mode bytes written per poll over the
             recorder's size (exp/out/e10_pi4_cost_<profile>.json).

Inputs read only. Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_misc.py [--out exp/out/r16_e10_misc.json]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def dist(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    q = lambda f: xs[min(len(xs) - 1, int(f * (len(xs) - 1) + 0.5))]   # noqa: E731
    return {"n": len(xs), "median": q(0.5), "p90": q(0.9), "max": xs[-1], "min": xs[0]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(OUT, "r16_e10_misc.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    inputs, out = {}, {"what": "E10 small derived quantities (EXPLORATORY)"}
    score_p = os.path.join(OUT, "e10_main_score.json")
    r5_p = os.path.join(OUT, "e10_main_r5_score.json")
    for k, p in (("score", score_p), ("r5_score", r5_p)):
        inputs[k] = {"path": os.path.relpath(p, ROOT), "sha256": sha(p)}
    score, r5 = json.load(open(score_p)), json.load(open(r5_p))

    # timing
    seq = ["e10_main_score.json", "e10_main_r5_score.json", "e10_main_collusion_direct.json",
           "e10_main_collusion_copy.json", "e10_main_migration_offline.json"]
    tm, prev = [], None
    for f in seq:
        p = os.path.join(OUT, f)
        mt = os.stat(p).st_mtime
        tm.append({"file": f, "mtime_utc": iso(mt), "mtime": mt, "s_since_previous": round(mt - prev, 1) if prev else None})
        prev = mt
    out["timing"] = {"order_in_run_e10_sh": seq, "files": tm,
                     "o_mig_duration_s_from_mtimes": round(tm[4]["mtime"] - tm[3]["mtime"], 1),
                     "scorer_verifications_wall_s_sum": round(sum((v.get("wall_s") or 0) for v in score["verifications"].values()), 1),
                     "scorer_verifications_n": len(score["verifications"]),
                     "note": "the harness log has no per-step timestamps after 'scoring with exp/stages/e10_score.py' "
                             "(13:51:23Z) and 'score exit' (15:25:48Z) until 'done' (17:45:43Z); mtimes are the files' last writes"}

    # restarts
    R = []
    for t in r5["R_restart"]["per_trial"]:
        d = {"trial": t["trial"], "kind": t["kind"], "target": t["target"], "landed_in_target": t["landed_in_target"],
             "landed": t.get("landed"), "fire_error_s": round(t["fire_error_s"], 4), "ok": t.get("ok")}
        for m in ("direct", "copy"):
            x = t[m]
            d[m] = {"polls": x["polls"], "unobservable": x["unobservable"], "max_gap_s": x["max_gap_s"],
                    "gap_above_gap_s": x["gap_above_gap_s"], "flagged_e9": x["flagged_seconds_e9"],
                    "flagged_patched": x["flagged_seconds_patched"], "late_e9": x["rows_e9"]["by_verdict"],
                    "late_patched": x["rows_patched"]["by_verdict"]}
        R.append(d)
    out["restarts"] = {"per_trial": R, "landed_in_target": sum(1 for d in R if d["landed_in_target"]),
                       "fire_error_s": dist([d["fire_error_s"] for d in R]),
                       "late_rows_total": {m: {v: sum(d[m][v].get("benign_late", 0) for d in R) for v in ("late_e9", "late_patched")}
                                           for m in ("direct", "copy")},
                       "unobserved_late_total": {m: sum(d[m]["late_patched"].get("unobserved_late", 0) for d in R) for m in ("direct", "copy")},
                       "after": [{k: e.get(k) for k in ("trial", "corrupt_files", "monitor_restarts")} for e in r5["R_restart"]["after"]],
                       "db_log_distinct_lines": sorted({l for e in r5["R_restart"]["after"] for l in e.get("db_log") or []})}

    # sham
    S = collections.defaultdict(lambda: collections.Counter())
    for t in r5["S_sham"]["per_trial"]:
        v = t["variant"]
        S[v]["n"] += 1
        S[v]["listed"] += bool(t.get("listed"))
        S[v]["displayed_cause_changed_admin_true"] += t.get("displayed_cause_changed_admin") is True
        S[v]["displayed_cause_changed_admin_none"] += t.get("displayed_cause_changed_admin") is None
        S[v]["rows_deleted_nonzero"] += bool(t.get("rows_deleted"))
        S[v]["db_writes_nonzero"] += bool(t.get("db_writes"))
        for m in ("direct", "copy"):
            S[v]["%s_violation" % m] += bool((t.get(m) or {}).get("violation"))
            S[v]["%s_own_row_%s" % (m, ((t.get(m) or {}).get("own_row") or {}).get("outcome"))] += 1
    out["sham"] = {k: dict(v) for k, v in S.items()}

    # deletion
    dl = {}
    for arm in ("DEL", "DEL-PH"):
        pt = score["arms"][arm]["per_trial"]
        e = {"n": len(pt), "visible_for_s": dist([r["visible_for_s"] for r in pt]),
             "trials_with_dangling_successors": sum(1 for r in pt if r["dangling_successors"]),
             "dangling_successors_total": sum(r["dangling_successors"] for r in pt),
             "attack_success": sum(1 for r in pt if r["attack_success"])}
        if arm == "DEL-PH":
            e["sensor_error_s"] = dist([(r.get("sensor") or {}).get("error_s") for r in pt])
            e["sensor_abs_error_le_0_5s"] = sum(1 for r in pt if (r.get("sensor") or {}).get("error_s") is not None
                                                and abs(r["sensor"]["error_s"]) <= 0.5)
            e["visible_for_s_list"] = [round(r["visible_for_s"], 4) for r in pt]
            e["direct_detected_trials"] = [r["trial"] for r in pt if r["direct"]["outcome"] == "detected"]
        else:
            e["by_delay_dangling"] = {str(dly): sum(1 for r in pt if r["delay_s"] == dly and r["dangling_successors"])
                                      for dly in sorted({r["delay_s"] for r in pt})}
        dl[arm] = e
    out["deletion"] = dl

    # pi4
    pi = {}
    for prof in ("ref", "pi4", "pi4cpu_half", "pi4cpu_eighth"):
        p = os.path.join(OUT, "e10_pi4_cost_%s.json" % prof)
        inputs["pi4_" + prof] = {"path": os.path.relpath(p, ROOT), "sha256": sha(p)}
        d = json.load(open(p))
        for name, r in d["runs"].items():
            q = r.get("quick_check_outcomes") or {}
            wb = (r.get("per_poll_bytes") or {})
            pi[name] = {"master_bytes": r.get("master_bytes"), "mode": r.get("mode"), "k": r.get("k"),
                        "poll_errors": len(r.get("poll_errors") or []), "unobservable_polls": r.get("unobservable_polls"),
                        "failed_appends": r.get("failed_appends"), "read_path_counts": r.get("read_path_counts"),
                        "polls_with_quick_check": q.get("polls_with_quick_check"), "quick_check_failed": q.get("failed")}
    summ = json.load(open(os.path.join(OUT, "e10_pi4_cost.json")))
    inputs["pi4_summary"] = {"path": "exp/out/e10_pi4_cost.json", "sha256": sha(os.path.join(OUT, "e10_pi4_cost.json"))}
    for name, r in summ["runs"].items():
        if r["mode"] == "copy" and name in pi and pi[name]["master_bytes"]:
            pi[name]["write_bytes_per_poll_median_over_master_bytes"] = round(r["write_bytes_per_poll"]["median"] / pi[name]["master_bytes"], 4)
    out["pi4"] = pi
    out["inputs"] = inputs
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
