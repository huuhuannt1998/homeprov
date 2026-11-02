"""E10 review-r5 arms S (sham) and R (hub restart mid-poll): score one run of testbed/e10/run_e10.sh against
drafts/round13/E10_ADDENDUM_R5.md (sections A and B) and the pre-registration's arms S and R.

It reuses exp/stages/e10_score.py unchanged (Run, verify_job, sets, row_outcome, deletion_outcome, Polls), so the
verifications are the same patched verifier with the same parameters (LATE_BOUND 30 s, GAP_S 30 s, purge tolerance
60 s), cached in the same <run dir>/verify/:

  sham      e10s, both monitors, snapshot snap_sham (taken right after the sham block, before LOWKEY's insertions)
  restart   e10s, both monitors, snapshot snap_restart, with the patched verifier AND the E9 verifier (D1 comparison)

  S   per trial and monitor: the would-be target second (the second the real attack would have written: BDT 45 s,
      CTX 45 s) or row (DEL 10 s) -- violated / unknown / no violation; the trial's own actuation row's verdict; a keylog
      violation naming the trial's key. Prediction: no violation attributable to any trial, on either monitor (0 of 90).
      Plus the confusion matrix at the target seconds: the attack arms' trials at the same levels (A1-BDT 45 s, A2-CTX
      45 s, A3-DEL 10 s, scored against snap_del) against the sham trials.
  R   per restart: where its effect landed (the target monitor's read or copy window from that monitor's own cost log,
      on the VM clock), the polls around it (unobservable and why, the largest gap), the rows whose second lies in the
      restart's window and their verdicts under both verifiers, flagged seconds there, the monitors' restarts, and the
      distinguishability rule. Predictions (per verifier rule, FORMAL_DRAFT D1): no attributable row and no flagged
      second; late rows are benign_late (E9 verifier) and benign_late or unobserved_late (patched verifier, the latter
      exactly when an unobservable or missing poll or a gap above GAP_S lies in the row's bracket); no interval flagged
      by the rule (each is shorter than 60 s or within 120 s of a hub start).

    python3 exp/stages/e10r5_score.py --run-dir <run dir> --tag e10_main [--out-dir exp/out] [--jobs 2]

Writes <out-dir>/<tag>_r5_score.json; never overwrites (--overwrite).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "testbed", "e10"))
import e10_score as S10                      # noqa: E402  (unchanged; its verify_job, sets, Polls, outcome rules)
import e10ops                                # noqa: E402  (cost_windows_of, landed: the same window definition as the firing)

MONITORS = S10.MONITORS
SHAM_ATTACK_LEVELS = {"S-BDT": ("bdt", 45.0), "S-CTX": ("ctx", 45.0), "S-DEL": ("del", 10.0)}
RESTART_PRE_S, RESTART_POST_S = 30.0, 120.0     # a restart's window: [effect - 30 s, hub start + 120 s]


# ------------------------------------------------------------------------------------------------ arm S
def sham_trial_outcome(t, S, observed_keys=None):
    """One sham trial on one monitor. S = e10_score.sets(...) of the snap_sham verification (None: verification failed).
    Returns a dict with 'violation' True when anything is attributable to the trial: its would-be second or its own
    actuation second flagged, its actuation row attributable, or a keylog violation naming its key."""
    if S is None:
        return {"outcome": "verification_failed", "violation": None}
    ws = t.get("would_be_second")
    out = {"would_be_second": ws}
    if ws is None:
        return {"outcome": "no_target", "violation": None}
    sec = str(int(ws))
    out["would_be_second_outcome"] = ("violated" if sec in S["flagged"] else
                                      "unknown" if sec in S["unknown"] else "no_violation")
    viol = sec in S["flagged"]
    row = t.get("unlock_row") or t.get("deleted_row")
    if row and row.get("state_id") is not None:
        key, rsec = "s:%s" % row["state_id"], row.get("ts")
        o = S10.row_outcome(S, key, rsec)
        out["own_row"] = {"key": key, "outcome": o, "keylog_named": key in S["keylog"]}
        if observed_keys is not None:
            out["own_row"]["observed_by_keylog"] = row["state_id"] in observed_keys
        viol = viol or o == "detected" or key in S["keylog"]
    out["violation"] = bool(viol)
    out["outcome"] = "violation" if viol else ("unknown" if out["would_be_second_outcome"] == "unknown" else "no_violation")
    return out


def attack_target_violated(op, t, S):
    """The matching attack trial's target second on one monitor (scored against snap_del): violated or not."""
    if S is None:
        return None
    if op == "bdt":
        return str(int(t["forged_row_ts"])) in S["flagged"] or S["verdict"].get("s:%s" % t["forged_state_id"], ("",))[0] == "attributable"
    if op == "ctx":
        return str(int(t["inserted_ts"])) in S["flagged"] or S["verdict"].get("e:%s" % t["inserted_event_id"], ("",))[0] == "attributable"
    r = t.get("deleted_row") or {}
    return str(int(r.get("ts", 0))) in S["flagged"] or ("s:%s" % r.get("state_id")) in S["keylog"]


def score_sham(sham_trials, attack_trials, S_sham, S_del, observed=None):
    """sham_trials: the sham op's trials (err trials are listed, not scored); attack_trials: {"bdt": [...], ...};
    S_sham / S_del: {monitor: sets(...)}; observed: {monitor: set of state ids observed by an observable poll}."""
    out = {"per_trial": [], "per_variant": {}, "errors": [t for t in sham_trials if t.get("err")],
           "confusion_at_target_seconds": {}, "prediction": "no violation attributable to any trial (0 of n), each monitor"}
    good = [t for t in sham_trials if not t.get("err")]
    for t in good:
        row = {"trial": t.get("trial"), "variant": t.get("arm"), "level": t.get("age_s", t.get("delay_s")),
               "db_writes": t.get("db_writes", 0), "rows_deleted": t.get("rows_deleted", 0),
               "displayed_cause_changed_admin": t.get("displayed_cause_changed_admin"), "listed": t.get("listed")}
        for m in MONITORS:
            row[m] = sham_trial_outcome(t, S_sham.get(m), (observed or {}).get(m))
        out["per_trial"].append(row)
    for v in sorted({r["variant"] for r in out["per_trial"]}):
        rs = [r for r in out["per_trial"] if r["variant"] == v]
        d = {"n": len(rs), "writes": sum(int(r["db_writes"] or 0) + int(r["rows_deleted"] or 0) for r in rs),
             "display_changed": sum(1 for r in rs if r["displayed_cause_changed_admin"])}
        for m in MONITORS:
            k = sum(1 for r in rs if r[m].get("violation"))
            d[m] = {"violations": S10.cp(k, len(rs)), "unknown": sum(1 for r in rs if r[m].get("outcome") == "unknown"),
                    "verification_failed": sum(1 for r in rs if r[m].get("outcome") == "verification_failed")}
        out["per_variant"][v] = d
    for m in MONITORS:
        k = sum(1 for r in out["per_trial"] if r[m].get("violation"))
        out.setdefault("overall", {})[m] = S10.cp(k, len(out["per_trial"]))
        cm = {}
        for v, (op, lev) in SHAM_ATTACK_LEVELS.items():
            att = [t for t in attack_trials.get(op, []) if float(t.get("age_s", t.get("delay_s", -1))) == lev]
            av = [attack_target_violated(op, t, S_del.get(m)) for t in att]
            sv = [r[m].get("violation") for r in out["per_trial"] if r["variant"] == v]
            tp, fn = sum(1 for x in av if x), sum(1 for x in av if x is False)
            fp, tn = sum(1 for x in sv if x), sum(1 for x in sv if x is False)
            cm[v] = {"attack_level": [op, lev], "attack_violated": tp, "attack_not_violated": fn,
                     "sham_violated": fp, "sham_not_violated": tn,
                     "sensitivity": S10.cp(tp, tp + fn), "specificity": S10.cp(tn, tn + fp)}
        out["confusion_at_target_seconds"][m] = cm
    return out


# ------------------------------------------------------------------------------------------------ arm R
def restart_effect_vm(res):
    """The restart's effect on the VM clock: a kill's delivery (the command time on the VM clock), a graceful restart's
    container exit (State.FinishedAt, which follows the recorder's last commit and close)."""
    if not res or not res.get("ok"):
        return None
    if res.get("kind") == "kill":
        return float(res["t_fire_mac"]) + float(res["vm_offset_s"])
    return res.get("finished_at_ts")


def rows_in_window(S, lo, hi):
    """Row verdicts whose second lies in [lo, hi]: counts per verdict, and the rows themselves (first 50)."""
    if S is None:
        return None
    c, rows = collections.Counter(), []
    for key, (name, r) in S["verdict"].items():
        sec = r.get("second")
        if sec is not None and lo <= int(sec) <= hi:
            c[name] += 1
            if len(rows) < 50:
                rows.append({"key": key, "verdict": name, "second": sec, "lat": r.get("lat"), "why": r.get("why")})
    return {"by_verdict": dict(c), "rows": rows}


def polls_around(polls, lo, hi):
    ps = [p for p in polls.polls if p.get("copy_at") is not None and lo <= p["copy_at"] <= hi]
    obs = sorted(p["copy_at"] for p in ps if not p.get("unobservable"))
    gaps = [b - a for a, b in zip(obs, obs[1:])]
    return {"polls": len(ps), "unobservable": sum(1 for p in ps if p.get("unobservable")),
            "reasons": dict(collections.Counter(str(p.get("reason")) for p in ps if p.get("unobservable"))),
            "max_gap_s": round(max(gaps), 3) if gaps else None,
            "gap_above_gap_s": sum(1 for g in gaps if g > S10.GAP_S)}


def score_restarts(trials, cost_lines, S_patched, S_e9, polls, hub_starts):
    """trials: the run's restart_trial events (with 'result'); cost_lines: {monitor: [cost log lines]};
    S_patched / S_e9: {monitor: sets(...)} of the snap_restart verification; polls: {monitor: e10_score.Polls}."""
    wins = {m: e10ops.cost_windows_of(cost_lines.get(m) or [], m) for m in MONITORS}
    out = {"per_trial": [], "prediction": {"attributable_rows": 0, "flagged_seconds": 0, "monitor_restarts": 0,
                                           "late_rows": "benign_late (E9 verifier); benign_late or unobserved_late "
                                                        "(patched, D1)", "suspicious_intervals": 0}}
    for e in trials:
        res = e.get("result") or {}
        eff = restart_effect_vm(res)
        row = {"trial": e.get("trial"), "kind": e.get("kind"), "target": e.get("target"), "ok": bool(res.get("ok")),
               "effect_vm": eff, "fire_error_s": res.get("fire_error_s"), "started_by_harness": res.get("started_by_harness")}
        if eff is None:
            row["unscored"] = "no effect time (restart failed or no FinishedAt)"
            out["per_trial"].append(row)
            continue
        row["landed"] = {m: e10ops.landed(eff, wins[m]) is not None for m in MONITORS}
        row["landed_in_target"] = row["landed"].get(e.get("target"))
        start = res.get("started_at_ts") or eff
        lo, hi = eff - RESTART_PRE_S, max(start, eff) + RESTART_POST_S
        row["window_vm"] = [lo, hi]
        for m in MONITORS:
            p = polls_around(polls[m], lo, hi)
            vp, ve = S_patched.get(m), S_e9.get(m)
            p["rows_patched"] = rows_in_window(vp, int(lo), int(hi))
            p["rows_e9"] = rows_in_window(ve, int(lo), int(hi))
            p["flagged_seconds_patched"] = None if vp is None else sum(1 for s in vp["flagged"] if lo <= int(s) <= hi)
            p["flagged_seconds_e9"] = None if ve is None else sum(1 for s in ve["flagged"] if lo <= int(s) <= hi)
            runs = [r for r in polls[m].unobservable_runs() if r.get("from") and lo <= r["from"] <= hi]
            for r in runs:
                near = any(abs((s or 0) - r["from"]) <= S10.UNOBS_RULE_HUB_S or abs((s or 0) - r["to"]) <= S10.UNOBS_RULE_HUB_S
                           for s in hub_starts)
                r["suspicious"] = (r.get("duration_s") or 0) >= S10.UNOBS_RULE_MIN_S and not near
            p["unobservable_runs"] = runs
            row[m] = p
        out["per_trial"].append(row)
    sc = [r for r in out["per_trial"] if "unscored" not in r]
    out["summary"] = {"n": len(out["per_trial"]), "scored": len(sc),
                      "landed_in_target": sum(1 for r in sc if r.get("landed_in_target")),
                      "by_kind_target": dict(collections.Counter("%s->%s" % (r["kind"], r["target"]) for r in sc))}
    for m in MONITORS:
        att = sum((r[m]["rows_patched"] or {}).get("by_verdict", {}).get("attributable", 0) for r in sc if r[m]["rows_patched"])
        att9 = sum((r[m]["rows_e9"] or {}).get("by_verdict", {}).get("attributable", 0) for r in sc if r[m]["rows_e9"])
        out["summary"][m] = {
            "attributable_rows_patched": att, "attributable_rows_e9": att9,
            "flagged_seconds_patched": sum(r[m]["flagged_seconds_patched"] or 0 for r in sc),
            "unobservable_polls": sum(r[m]["unobservable"] for r in sc),
            "suspicious_intervals": sum(1 for r in sc for x in r[m]["unobservable_runs"] if x.get("suspicious")),
            "trials_with_unobserved_late_patched": sum(1 for r in sc if ((r[m]["rows_patched"] or {}).get("by_verdict") or {})
                                                       .get("unobserved_late"))}
    return out


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "exp", "out"))
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    dst = os.path.join(a.out_dir, "%s_r5_score.json" % a.tag)
    if os.path.exists(dst) and not a.overwrite:
        raise SystemExit("REFUSING: %s exists" % dst)
    run = S10.Run(a.run_dir)
    sp = a.run_dir
    t0 = run.t("e10s", "t_start")
    common = ["--purge-keep-s", str(29 * 86400.0), "--purge-tol-s", str(S10.PURGE_TOL_S),
              "--restore-tol-s", str(S10.RESTORE_TOL_S)]
    jobs = []
    for label, snap, verifier in (("sham", "snap_sham", S10.E7_VERIFY), ("del", "snap_del", S10.E7_VERIFY),
                                  ("restart", "snap_restart", S10.E7_VERIFY), ("restart_e9", "snap_restart", S10.E9_VERIFY)):
        db, ts = run.snap("e10s", snap)
        if db and t0 and os.path.exists(verifier):
            for m in MONITORS:
                jobs.append((sp, "e10s", m, label, db, ts, [t0, ts], common, verifier))
    V = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for k, out in ex.map(lambda j: S10.verify_job(*j), jobs):
            V[k] = out
    polls = {m: S10.Polls(os.path.join(sp, "e10s", "%s_chain.jsonl" % m)) for m in MONITORS}
    sets_of = lambda lab: {m: S10.sets(V.get(("e10s", m, lab))) for m in MONITORS}   # noqa: E731
    res = {"experiment": "E10 review-r5 arms S (sham) and R (hub restart mid-poll)", "tag": a.tag,
           "plan_sha256": S10.sha(os.path.join(sp, "plan.json")),
           "verifications": {"/".join(k): ({"error": v.get("error")} if "error" in v else
                                           {"flagged_seconds": len(v.get("flagged_seconds") or [])}) for k, v in V.items()},
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    sham = run.trials("sham") + [t for d in run.results.get("sham", []) for t in d.get("trials", []) if t.get("err")]
    res["sham_db_writes_total"] = [d.get("db_writes_total") for d in run.results.get("sham", [])]
    try:
        res["S_sham"] = score_sham(sham, {op: run.trials(op) for op in ("bdt", "ctx", "del")}, sets_of("sham"),
                                   sets_of("del"), {m: polls[m].observed_keys["states"] for m in MONITORS})
    except Exception as exc:                          # noqa: BLE001
        res["S_sham"] = {"error": repr(exc)[:500]}
    try:
        cost = {m: S10.jl(os.path.join(sp, "e10s", "%s_cost.jsonl" % m)) for m in MONITORS}
        tr = [e for e in run.events if e.get("type") == "restart_trial"]
        res["R_restart"] = score_restarts(tr, cost, sets_of("restart"), sets_of("restart_e9"), polls,
                                          run.hub_starts("e10s"))
        res["R_restart"]["after"] = [e for e in run.events if e.get("type") == "restart_after"]
    except Exception as exc:                          # noqa: BLE001
        res["R_restart"] = {"error": repr(exc)[:500]}
    os.makedirs(a.out_dir, exist_ok=True)
    with open(dst, "w" if a.overwrite else "x") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
    print("wrote", dst)


if __name__ == "__main__":
    main()
