"""E10b -- score one run of testbed/e10b/run_e10b.sh against its pre-registration (exp/out/e10b_preregistration.json).

The authoritative verification is E10's: exp/stages/e7_verify.py (patched, frozen with E10), run per monitor through
exp/stages/e10_score.py's verify_job (imported, unchanged) against the snapshot taken right after the BDT block
(snap_bdt), the snapshot after the clock-step block (snap_cs_end) and the final snapshot, with E10's parameters
(LATE_BOUND 30 s, GAP_S 30 s). What E10b changes is the scoring (drafts/round13/E10B_DESIGN.md section 4):

  H1b   per trial and monitor, from the trial's OWN forged row: its row verdict (attributable = detected,
        benign_late = reported_late, unobserved_late = unknown, none = no_evidence; unknown also when its second has
        no root), compared with the prediction of the E10b rule from that monitor's own polls (below).
  H1b-seg  the segment verdict as a consistency check: the own row detected <=> its second is flagged.
  H1b-lb   the predicted lower bound equals the verifier's committed_after_lower_bound_s (secondary).
  H1b-late-view  copy mode only (secondary): the prediction when an overlapping copy holds the row iff the copy ended
        (its record ts) after t_insert, i.e. its view of the -wal is taken late in the copy (E10, exploratory:
        exp/out/r16_e10_copyview.json); scored on every copy-mode trial and reported for the ambiguous ones.
  H10b  the clock-step arm with the hub's state rows stepped too (homeprov_e10b op clock_step_all).
  floor flagged seconds and attributable rows that neither a BDT trial nor a clock step explains (predicted 0).
Secondary, for comparison only: E10's frozen prediction (e10_score.predicted_insertion) and E10's frozen segment-based
outcome (e10_score.row_outcome) on the same trials.

THE E10b PREDICTION RULE. A poll lacks the forged row if its view of the recorder was taken before the insertion
began, holds it if taken after the commit returned, and may do either if the two overlap. A poll's view is taken at
an instant inside its observation window: direct read [copy_at, copy_at] (the read transaction's snapshot is pinned
by the first read right after copy_at); copy mode [copy_at, copy end] where the copy end is the record's own ts (the
copy of the database file, then the -wal, then the -shm: the WAL is read somewhere inside). Both windows are widened by
AMBIGUOUS_S = 50 ms on each side (E10's registered ambiguity), and the write window is [t_insert, t_commit] (the hub's
times just before BEGIN IMMEDIATE and after COMMIT returned). Every split of the overlapping polls into a lacking
prefix and a holding rest is evaluated exactly as the verifier evaluates a late row:
  no_evidence    the first poll covering the row's second (through >= second + 1) holds it, or none covers it
  detected       max copy_at over the lacking polls minus the row's timestamp > LATE_BOUND
  unknown        else, no valid poll holds the row, or a break (unobservable / missing / backlogged poll, monitor
                 restart, more than GAP_S between copies) lies between the last lacking and the first holding poll
  reported_late  otherwise.
One outcome for every split: that is the prediction; more than one: "ambiguous" (counted, left out of agreement),
also when the lower bound is within 1 ms of LATE_BOUND.

    python3 testbed/e10b/e10b_score.py --run-dir <run dir> --tag e10b_main [--out-dir exp/out] [--jobs 2] [--no-floor]

Writes <out-dir>/<tag>_score.json with mode "x" (never overwrites).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import hashlib
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
STAGES = os.path.join(REPO, "exp", "stages")
sys.path.insert(0, STAGES)
sys.path.insert(0, os.path.join(REPO, "exp"))
import e10_score as S10                        # noqa: E402  (frozen with E10; imported, never changed)

LATE_BOUND = S10.LATE_BOUND                    # 30 s (E10)
GAP_S = S10.GAP_S                              # 30 s (E10)
AMBIGUOUS_S = S10.AMBIGUOUS_S                  # 50 ms (E10)
BOUNDARY_EPS_S = 1e-3                          # a lower bound this close to LATE_BOUND is ambiguous
CS_BAND_S = 5.0                                # clock-step rows with ts in [t_on - 5 s, t_off) are boundary rows
STACK = "e10bs"
MONITORS = S10.MONITORS
OUTCOMES = ("detected", "reported_late", "no_evidence", "unknown")


def sha(p):
    if not p or not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------------ polls (streamed)
def chain_polls(path, tsnap=None):
    """The monitor's polls from its chain, streamed line by line (the chain is not held in memory): one entry per
    (epoch, seq_local) as e7_verify.parse_chain keys them, with copy_at, the record's ts, wm, since/through,
    unobservable, own, in_backlog. Heads stamped after tsnap are left out, as the verifier leaves them out."""
    polls = {}
    epoch, max_seq, max_ts = 0, 0, None
    if not os.path.exists(path):
        return []
    with open(path, errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                cr = json.loads(line)
            except ValueError:
                continue
            p = cr.get("payload") or {}
            if p.get("observer") != "external-monitor" or "coverage" not in p or "seq_local" not in p:
                continue
            ts = p.get("ts") or cr.get("recv_ts") or 0.0
            if tsnap is not None and ts > tsnap and not p.get("backlog"):
                continue
            cont = isinstance(p.get("part"), int) and p["part"] >= 2
            s_ = int(p["seq_local"])
            same = (epoch, s_) in polls and polls[(epoch, s_)]["ts"] == ts
            if s_ <= max_seq and not cont and not same and (max_ts is None or ts > max_ts):
                epoch, max_seq, max_ts = epoch + 1, 0, None
            max_seq = max(s_, max_seq)
            heads = [(h, False) for h in (p.get("backlog") or [])] + [(p, True)]
            for h, own in heads:
                if tsnap is not None and h.get("ts") is not None and h["ts"] > tsnap:
                    continue
                if h.get("ts") is not None:
                    max_ts = h["ts"] if max_ts is None else max(max_ts, h["ts"])
                k = (epoch, int(h["seq_local"]))
                cur = polls.get(k)
                if cur is None or (own and not cur["own"] and h.get("through") is not None) \
                        or (cur.get("through") is None and h.get("through") is not None):
                    polls[k] = {"key": k, "epoch": k[0], "seq": k[1], "ts": h.get("ts"), "copy_at": h.get("copy_at"),
                                "wm": h.get("wm") if isinstance(h.get("wm"), dict) else None,
                                "since": h.get("since"), "through": h.get("through"),
                                "unobservable": bool(h.get("evidence_unobservable") or h.get("unobservable")),
                                "reason": h.get("reason") or h.get("unobservable"),
                                "own": own or bool(cur and cur["own"]),
                                "in_backlog": bool(cur and cur.get("in_backlog"))}
                    cur = polls[k]
                if own and not cont:
                    cur["own"] = True
                if not own and not h.get("keylog_part"):
                    cur["in_backlog"] = True
    return [polls[k] for k in sorted(polls)]


def tl_valid(p):
    """A poll the verifier's Timeline uses (coverage and the late-row lower bound)."""
    return p.get("through") is not None and p.get("wm") is not None and p.get("copy_at") is not None


def br_valid(p):
    """A poll the verifier's ObservationBreaks accepts as an end of a late row's bracket (LATE_BREAK_BACKLOG on)."""
    return tl_valid(p) and not p.get("unobservable") and not p.get("in_backlog")


def obs_window(p, mode):
    """[lo, hi] in which the poll's view of the recorder was taken, widened by AMBIGUOUS_S."""
    c = p["copy_at"]
    end = c if mode == "direct" else max(c, p.get("ts") or c)
    return c - AMBIGUOUS_S, end + AMBIGUOUS_S


# ------------------------------------------------------------------------------------------------ the E10b rule
def _verdict_for(polls, hold, ts, table="states"):
    """The verifier's verdict on a row timestamped ts, given which polls hold it (hold: dict key -> bool for every
    tl_valid poll). Returns (outcome, lower_bound, why)."""
    sec = int(ts // 1.0)
    valid = [p for p in polls if tl_valid(p)]
    seal = None
    for p in valid:                                   # the first poll (in poll order) covering the row's second
        if int(p["since"] if p.get("since") is not None else 0) <= sec and sec + 1 <= int(p["through"]):
            seal = p
            break
    if seal is None:
        return "no_evidence", None, "second_never_covered"
    if hold[seal["key"]]:
        return "no_evidence", None, "first_cover_held_the_row"
    lacking = [p["copy_at"] for p in valid if not hold[p["key"]]]
    lb = (max(lacking) - ts) if lacking else None
    if lb is not None and lb > LATE_BOUND:
        return "detected", lb, "lower_bound_above_late_bound"
    if not any(hold[p["key"]] for p in valid):
        return "unknown", lb, "no_known_poll_holds_the_row"
    keys = [p["key"] for p in polls]
    bv = [p for p in polls if br_valid(p)]
    q = [p for p in bv if not hold[p["key"]]]
    z = next((p for p in bv if hold[p["key"]]), None)
    if q and z is not None:
        a, b = keys.index(q[-1]["key"]), keys.index(z["key"])
        for j in range(a + 1, b + 1):
            p, pp = polls[j], polls[j - 1]
            if p["epoch"] != pp["epoch"]:
                return "unknown", lb, "observation_break:monitor_restarted"
            if p["seq"] - pp["seq"] > 1:
                return "unknown", lb, "observation_break:poll_missing_from_the_chain"
            if p.get("copy_at") is not None and pp.get("copy_at") is not None and p["copy_at"] - pp["copy_at"] > GAP_S:
                return "unknown", lb, "observation_break:gap_above_gap_s"
            if j < b and (p.get("unobservable") or not tl_valid(p) or p.get("in_backlog")):
                return "unknown", lb, "observation_break:poll_" + ("unobservable" if p.get("unobservable") else
                                                                  "backlogged" if p.get("in_backlog") else
                                                                  "without_its_watermark")
    # (no bracket -- no lacking or no holding poll the break rule accepts -- leaves the verifier's late_within_bound)
    return "reported_late", lb, "late_within_bound"


def predict(polls, mode, t_insert, t_commit, ts):
    """The E10b prediction for one trial and monitor (see the module docstring)."""
    valid = [p for p in polls if tl_valid(p)]
    before, overlap, after = [], [], []
    for p in valid:
        lo, hi = obs_window(p, mode)
        if hi < t_insert:
            before.append(p)
        elif lo > t_commit:
            after.append(p)
        else:
            overlap.append(p)
    order = sorted(overlap, key=lambda p: p["copy_at"])
    alts = collections.OrderedDict()
    for k in range(len(order) + 1):                   # the first k overlapping polls lack the row, the rest hold it
        hold = {p["key"]: False for p in before}
        hold.update({p["key"]: True for p in after})
        hold.update({p["key"]: (i >= k) for i, p in enumerate(order)})
        out, lb, why = _verdict_for(polls, hold, ts)
        alts.setdefault(out, (lb, why, k))
    lbs = [v[0] for v in alts.values() if v[0] is not None]
    boundary = any(abs(x - LATE_BOUND) < BOUNDARY_EPS_S for x in lbs)
    res = {"overlap_polls": [{"seq": p["seq"], "epoch": p["epoch"], "copy_at": p["copy_at"],
                              "window": list(obs_window(p, mode))} for p in order],
           "alternatives": {o: {"lower_bound_s": v[0], "why": v[1], "lacking_overlap_polls": v[2]}
                            for o, v in alts.items()}}
    if len(alts) == 1 and not boundary:
        o, (lb, why, _k) = next(iter(alts.items()))
        res.update(predicted=o, lower_bound_s=lb, why=why)
    else:
        res.update(predicted="ambiguous", lower_bound_s=None,
                   why="boundary_within_1ms" if boundary and len(alts) == 1 else "overlap_alternatives_differ")
    return res


def e10_frozen_prediction(polls, t_commit, ts):
    """E10's registered rule, unchanged (e10_score.predicted_insertion), on the same polls."""
    shell = object.__new__(S10.Polls)
    shell.polls = polls
    shell.obs = sorted((p for p in polls if not p.get("unobservable") and p.get("copy_at") is not None
                        and isinstance(p.get("wm"), dict)), key=lambda p: p["copy_at"])
    shell.observed_keys = {}
    return S10.predicted_insertion(shell, t_commit, ts)


def predict_late_view(polls, mode, t_insert, t_commit, ts):
    """H1b-late-view (secondary): a copy-mode poll whose window overlaps the write holds the row iff its record ts (the
    copy's end) is after t_insert; direct read keeps the primary rule. One outcome, or 'ambiguous' (direct overlap, or
    a lower bound within 1 ms of LATE_BOUND)."""
    if mode != "copy":
        return predict(polls, mode, t_insert, t_commit, ts)["predicted"]
    hold = {}
    for p in polls:
        if not tl_valid(p):
            continue
        lo, hi = obs_window(p, mode)
        hold[p["key"]] = False if hi < t_insert else True if lo > t_commit else \
            (max(p["copy_at"], p.get("ts") or p["copy_at"]) > t_insert)
    out, lb, _why = _verdict_for(polls, hold, ts)
    return "ambiguous" if lb is not None and abs(lb - LATE_BOUND) < BOUNDARY_EPS_S else out


def score_late_view(sec, trials, polls):
    """Per copy-mode trial: the late-view prediction against the own-row outcome (non-excluded trials)."""
    by = {t.get("trial"): t for t in trials}
    rows = []
    for r in sec["per_trial"]:
        t = by.get(r["trial"])
        if t is None or r["excluded"] or "copy" not in r:
            continue
        lv = predict_late_view(polls["copy"], "copy", t["t_insert"], t["t_commit"], t["forged_row_ts"])
        obs = r["copy"]["observed"]["outcome"]
        rows.append({"trial": r["trial"], "age_s": r["age_s"], "primary": r["copy"]["predicted"], "late_view": lv,
                     "observed": obs, "agrees": None if lv == "ambiguous" or obs == "verification_failed" else lv == obs})
    amb = [x for x in rows if x["primary"] == "ambiguous"]
    return {"per_trial": rows,
            "all_trials": {"n": len(rows), "agree": sum(1 for x in rows if x["agrees"]),
                           "disagree": [x["trial"] for x in rows if x["agrees"] is False]},
            "primary_ambiguous_trials": {"n": len(amb), "agree": sum(1 for x in amb if x["agrees"]),
                                         "disagree": [x["trial"] for x in amb if x["agrees"] is False]}}


# ------------------------------------------------------------------------------------------------ the observed outcome
def own_outcome(S, v, key, ts):
    """The trial's own row: (outcome, verdict, lower bound, second flagged)."""
    if S is None:
        return {"outcome": "verification_failed", "verdict": None, "lower_bound_s": None, "second_flagged": None}
    sec = str(int(ts // 1.0))
    verd, row = S["verdict"].get(key, (None, None))
    m = {"attributable": "detected", "benign_late": "reported_late", "unobserved_late": "unknown",
         "excused_clock_step": "excused_clock_step"}
    out = m.get(verd) or ("unknown" if sec in S["unknown"] else "no_evidence")
    return {"outcome": out, "verdict": verd, "lower_bound_s": (row or {}).get("committed_after_lower_bound_s"),
            "second_flagged": sec in S["flagged"], "why": [w.get("why") for w in (row or {}).get("why") or []][:4]}


def score_bdt(trials, polls, V, modes=MONITORS):
    """Per trial and monitor (polls: monitor -> chain_polls list; V: monitor -> verifier output)."""
    targets = [t.get("forged_row_ts") for t in trials]
    from importlib import util as _u                  # the plan module's realised check (one definition)
    spec = _u.spec_from_file_location("e10b_plan_for_score", os.path.join(HERE, "e10b_plan.py"))
    plan_mod = _u.module_from_spec(spec)
    spec.loader.exec_module(plan_mod)
    sep = plan_mod.realised_separation(targets)
    collided = {i for pair in sep["collisions"] for i in pair}
    rows = []
    for i, t in enumerate(trials):
        key, ts = "s:%s" % t.get("forged_state_id"), t.get("forged_row_ts")
        r = {"trial": t.get("trial"), "age_s": t.get("age_s"), "key": key, "ts": ts, "second": int(ts // 1.0),
             "t_insert": t.get("t_insert"), "t_commit": t.get("t_commit"),
             "commit_s": round(t["t_commit"] - t["t_insert"], 6), "excluded": None,
             "attack_success_admin": t.get("attack_success_admin"), "listed": t.get("listed")}
        if i in collided:
            r["excluded"] = "target_second_shared_or_adjacent"
        for m in modes:
            S = S10.sets(V.get(m))
            obs = own_outcome(S, V.get(m), key, ts)
            pr = predict(polls[m], m, t["t_insert"], t["t_commit"], ts)
            e10_pred, e10_lb = e10_frozen_prediction(polls[m], t["t_commit"], ts)
            held = [{"seq": p["seq"], "copy_at": p["copy_at"], "held_row": (p.get("wm") or {}).get("states") is not None
                     and p["wm"]["states"] >= int(t["forged_state_id"])} for p in polls[m] if tl_valid(p)
                    and any(o["seq"] == p["seq"] and o["epoch"] == p["epoch"] for o in pr["overlap_polls"])]
            agree = None if (pr["predicted"] == "ambiguous" or r["excluded"] or obs["outcome"] == "verification_failed") \
                else pr["predicted"] == obs["outcome"]
            seg_ok = None if obs["second_flagged"] is None or r["excluded"] \
                else (obs["outcome"] == "detected") == bool(obs["second_flagged"])
            lb_ok = None
            if agree and pr["lower_bound_s"] is not None and obs["lower_bound_s"] is not None:
                lb_ok = abs(pr["lower_bound_s"] - obs["lower_bound_s"]) < 1e-5
            r[m] = {"observed": obs, "predicted": pr["predicted"], "predicted_lower_bound_s": pr["lower_bound_s"],
                    "predicted_why": pr["why"], "alternatives": pr["alternatives"], "agrees": agree,
                    "segment_consistent": seg_ok, "lower_bound_equal": lb_ok, "overlap_polls_held_row": held,
                    "e10_frozen": {"predicted": e10_pred, "lower_bound_s": e10_lb,
                                   "row_outcome": S10.row_outcome(S, key, ts) if S is not None else
                                   "verification_failed"}}
        rows.append(r)
    return {"per_trial": rows, "realised_separation": sep}


def summarise_bdt(sec, modes=MONITORS):
    rows = sec["per_trial"]
    out = {"per_level": {}, "hypotheses": {}}
    for lev in sorted({r["age_s"] for r in rows}):
        rs = [r for r in rows if r["age_s"] == lev]
        d = {"n": len(rs), "excluded": sum(1 for r in rs if r["excluded"])}
        for m in modes:
            inc = [r for r in rs if not r["excluded"]]
            c = collections.Counter(r[m]["observed"]["outcome"] for r in inc)
            p = collections.Counter(r[m]["predicted"] for r in inc)
            ag = [r[m]["agrees"] for r in inc if r[m]["agrees"] is not None]
            d[m] = {"observed": dict(c), "predicted": dict(p), "detected": S10.cp(c.get("detected", 0), len(inc)),
                    "agreement": S10.cp(sum(ag), len(ag)), "ambiguous": p.get("ambiguous", 0),
                    "segment_consistent": sum(1 for r in inc if r[m]["segment_consistent"]),
                    "segment_checked": sum(1 for r in inc if r[m]["segment_consistent"] is not None),
                    "e10_frozen_rule_agrees_with_observed": sum(
                        1 for r in inc if r[m]["e10_frozen"]["predicted"] == r[m]["observed"]["outcome"]),
                    "e10_frozen_row_outcome_equals_own_row": sum(
                        1 for r in inc if r[m]["e10_frozen"]["row_outcome"] == r[m]["observed"]["outcome"])}
        out["per_level"][str(lev)] = d
    for m in modes:
        inc = [r for r in rows if not r["excluded"]]
        dis = [r["trial"] for r in inc if r[m]["agrees"] is False]
        seg = [r["trial"] for r in inc if r[m]["segment_consistent"] is False]
        lbb = [r["trial"] for r in inc if r[m]["lower_bound_equal"] is False]
        out["hypotheses"][m] = {
            "H1b_all_non_ambiguous_trials_agree": not dis, "H1b_disagreeing_trials": dis,
            "H1b_ambiguous_trials": [r["trial"] for r in inc if r[m]["predicted"] == "ambiguous"],
            "H1b_seg_all_consistent": not seg, "H1b_seg_inconsistent_trials": seg,
            "H1b_lb_all_equal": not lbb, "H1b_lb_unequal_trials": lbb,
            "excluded_trials": [r["trial"] for r in rows if r["excluded"]],
            "verification_failed_trials": [r["trial"] for r in inc
                                           if r[m]["observed"]["outcome"] == "verification_failed"]}
    return out


# ------------------------------------------------------------------------------------------------ H10b clock steps
CS_PREDICTED = {("60", True): "every stepped row excused_clock_step, none attributable",
                ("60", False): "every stepped row attributable",
                ("10", False): "no attributable row among the step's keys and no flagged second in [t_on - 11, t_off + 1]"}


def step_rows(db, r):
    """Rows the step's key range holds, per table: (key, ts, class) with class stepped / boundary / after."""
    lo = {t: ((r.get("wm_before") or {}).get(t) or 0) for t in ("states", "events")}
    hi = {t: ((r.get("wm_after") or {}).get(t) or 0) for t in ("states", "events")}
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    out = {}
    try:
        for t, kc, tc, pfx in (("states", "state_id", "last_updated_ts", "s"), ("events", "event_id", "time_fired_ts", "e")):
            rows = c.execute("SELECT %s, %s FROM %s WHERE %s > ? AND %s <= ?" % (kc, tc, t, kc, kc), (lo[t], hi[t])).fetchall()
            out[t] = [("%s:%d" % (pfx, k), ts, "stepped" if ts is not None and ts < r["t_on"] - CS_BAND_S else
                       "after" if ts is not None and ts >= r["t_off"] else "boundary") for k, ts in rows]
    finally:
        c.close()
    return out


def score_cs2(results, db, V, modes=MONITORS):
    out = []
    for r in results:
        cmd = r.get("command") or {}
        st = float(r.get("step_s") or cmd.get("step_s") or 0)
        mk = bool(cmd.get("marker"))
        row = {"step": cmd.get("step"), "step_s": st, "marker": mk, "t_on": r.get("t_on"), "t_off": r.get("t_off"),
               "patched": r.get("patched"), "prediction": CS_PREDICTED.get(("%d" % st, mk))}
        if db is None or r.get("t_on") is None:
            row["error"] = "no cs_end snapshot or no step times"
            out.append(row)
            continue
        R = step_rows(db, r)
        row["rows"] = {t: dict(collections.Counter(x[2] for x in R[t])) for t in R}
        # manipulation check: state rows of the step's key range stamped more than 2 s before t_on can only come from
        # the stepped clock (the hub commits once a second; E10's step left every state row at the real time)
        row["manipulation_stepped_state_rows"] = sum(1 for x in R["states"] if x[1] is not None
                                                     and x[1] < r["t_on"] - 2.0)
        row["manipulation_stepped_event_rows"] = sum(1 for x in R["events"] if x[1] is not None
                                                     and x[1] < r["t_on"] - 2.0)
        row["evaluable"] = row["manipulation_stepped_state_rows"] > 0
        for m in modes:
            v = V.get(m)
            S = S10.sets(v)
            if S is None:
                row[m] = "verification_failed"
                continue
            per = {}
            for t in ("states", "events"):
                stepped = [x for x in R[t] if x[2] == "stepped"]
                cnt = collections.Counter(S["verdict"].get(k, ("none",))[0] for k, _ts, _c in stepped)
                allc = collections.Counter(S["verdict"].get(k, ("none",))[0] for k, _ts, _c in R[t])
                bnd = collections.Counter(S["verdict"].get(k, ("none",))[0] for k, _ts, c_ in R[t] if c_ == "boundary")
                if st >= 30 and mk:
                    ok = bool(stepped) and cnt.get("excused_clock_step", 0) == len(stepped)
                elif st >= 30:
                    ok = bool(stepped) and cnt.get("attributable", 0) == len(stepped)
                else:
                    ok = allc.get("attributable", 0) == 0
                per[t] = {"stepped": len(stepped), "verdicts_stepped": dict(cnt), "verdicts_all": dict(allc),
                          "verdicts_boundary": dict(bnd), "agrees": ok if stepped or st < 30 else None}
            fl = [s for s in S["flagged"] if r["t_on"] - st - 1 <= int(s) <= r["t_off"] + 1]
            per["flagged_seconds_in_step_window"] = len(fl)
            if st < 30:
                per["agrees_10s_flagged"] = len(fl) == 0
            row[m] = per
        out.append(row)
    return out


# ------------------------------------------------------------------------------------------------ floor
def score_floor(v, trials, cs_results, db):
    S = S10.sets(v)
    if S is None:
        return {"error": "verification failed or absent"}
    explained_keys = {"s:%s" % t.get("forged_state_id") for t in trials}
    for r in cs_results or []:
        if db and r.get("t_on") is not None:
            for t, rows in step_rows(db, r).items():
                explained_keys |= {k for k, _ts, _c in rows}
    att = [r for r in (v.get("attributable_rows") or [])]
    unexpl_rows = [r for r in att if r["key"] not in explained_keys]
    expl_secs = {r["second"] for r in att if r["key"] in explained_keys and r.get("second")}
    unexpl_secs = sorted((s for s in S["flagged"] if s not in expl_secs), key=int)
    return {"flagged_seconds": len(S["flagged"]), "unexplained_flagged_seconds": len(unexpl_secs),
            "unexplained_flagged_seconds_list": unexpl_secs[:200], "unexplained_attributable_rows": len(unexpl_rows),
            "unexplained_attributable_rows_list": unexpl_rows[:50],
            "root_unknown_segments": len(v.get("root_unknown_segments") or [])}


# ------------------------------------------------------------------------------------------------ block conditions
def block_conditions(events, hostlog_path, blocks=("A1_BDT", "A6_CS2"), wall_gap_s=90.0, hub_cause_s=180.0):
    """The registered block exclusion (as E10): a host-log wall-clock gap above 90 s, a hub start without a harness
    cause, or a monitor restart during the block -> its trials are scored and reported separately, not pooled."""
    span = {}
    for e in events:
        if e.get("type") in ("block_begin", "block_end") and e.get("block") in blocks:
            span.setdefault(e["block"], {})[e["type"]] = e
    harness = [e["ts"] for e in events if e.get("type") == "hub_restart"]
    gaps, starts = [], []
    if hostlog_path and os.path.exists(hostlog_path):
        with open(hostlog_path, errors="replace") as fh:
            for line in fh:
                if '"wall_gap"' not in line and '"hub_state"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("kind") == "wall_gap":
                    gaps.append(d)
                elif d.get("kind") == "hub_state" and d.get("previous_started_at") and \
                        d.get("started_at") != d.get("previous_started_at"):
                    starts.append(d)
    out = {}
    for b, d in span.items():
        t0, t1 = (d.get("block_begin") or {}).get("ts"), (d.get("block_end") or {}).get("ts")
        if t0 is None or t1 is None:
            out[b] = {"complete": False, "pooled": False}
            continue
        r0, r1 = (d["block_begin"].get("restarts") or {}), (d["block_end"].get("restarts") or {})
        mr = {m: (r1.get(m) or 0) - (r0.get(m) or 0) for m in MONITORS if isinstance(r1.get(m), int)}
        g = [x for x in gaps if t0 <= x.get("ts", 0) <= t1 and (x.get("gap_s") or 0) > wall_gap_s]
        hs = [x for x in starts if t0 <= x.get("ts", 0) <= t1 and not any(abs(h - x["ts"]) <= hub_cause_s for h in harness)]
        out[b] = {"complete": True, "t_begin": t0, "t_end": t1, "monitor_restarts": mr, "wall_gaps_over_90s": g,
                  "hub_starts_without_cause": hs,
                  "hub_started_at_changed": r0.get("hub_started_at") != r1.get("hub_started_at"),
                  "pooled": not g and not hs and not any(mr.values())}
    return out


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(REPO, "exp", "out"))
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--no-floor", action="store_true")
    a = ap.parse_args()
    dst = os.path.join(a.out_dir, "%s_score.json" % a.tag)
    if os.path.exists(dst):
        raise SystemExit("REFUSING: %s exists" % dst)
    sp = a.run_dir
    run = S10.Run(sp)
    t0 = run.t(STACK, "t_start")
    common = ["--purge-keep-s", str(29 * 86400.0), "--purge-tol-s", str(S10.PURGE_TOL_S),   # E10's e10s settings
              "--restore-tol-s", str(S10.RESTORE_TOL_S)]
    jobs, snaps = [], {}

    def add(label, snap, window):
        db, ts = run.snap(STACK, snap)
        snaps[label] = (db, ts)
        if db and t0:
            for m in MONITORS:
                if os.path.exists(os.path.join(sp, STACK, "%s_chain.jsonl" % m)):
                    jobs.append((sp, STACK, m, label, db, ts, [window[0], ts if window[1] is None else window[1]],
                                 list(common), S10.E7_VERIFY))

    cs = run.results.get("clock_step_all", [])
    if t0:
        add("bdt", "snap_bdt", [t0, None])
        if cs and all(r.get("t_on") for r in cs):
            add("cs2", "snap_cs_end", [min(r["t_on"] for r in cs) - 600, None])
        if not a.no_floor:
            add("floor", "final", [t0, None])
    V = {}
    print("== E10b score %s: %d verifications" % (a.tag, len(jobs)), flush=True)
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for k, out in ex.map(lambda j: S10.verify_job(*j), jobs):
            V[k] = out
            print("  %-30s %s" % ("/".join(k), "ERROR " + out.get("stderr", "")[-200:] if "error" in out
                                  else "ok (%ss)" % (out.get("_e10") or {}).get("verify_wall_s")), flush=True)

    def vm(label):
        return {m: V.get((STACK, m, label)) for m in MONITORS}

    trials = run.trials("bdt")
    err_trials = [dict(trial=t.get("trial"), err=t.get("err")) for d in run.results.get("bdt", [])
                  for t in d.get("trials", []) if t.get("err")]
    res = {"experiment": "E10b: E10's A1-BDT arm (H1) re-run with spaced trials and own-row scoring; H10b clock steps",
           "tag": a.tag, "plan_sha256": sha(os.path.join(sp, "plan.json")),
           "parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "ambiguous_s": AMBIGUOUS_S,
                          "boundary_eps_s": BOUNDARY_EPS_S, "cs_band_s": CS_BAND_S},
           "code": {"e10b_score.py": sha(os.path.abspath(__file__)), "e10_score.py": sha(S10.__file__),
                    "e7_verify.py": sha(S10.E7_VERIFY)},
           "verifications": {"/".join(k): ({"error": v.get("error"), "rc": v.get("rc")} if "error" in v else
                                           {"flagged_seconds": len(v.get("flagged_seconds") or []),
                                            "attributable_rows": len(v.get("attributable_rows") or []),
                                            "unobserved_late_rows": len(v.get("unobserved_late_rows") or []),
                                            "root_unknown_segments": len(v.get("root_unknown_segments") or []),
                                            "wall_s": (v.get("_e10") or {}).get("verify_wall_s")})
                             for k, v in V.items()},
           "excluded_err_trials": err_trials, "arms": {}, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def section(name, fn):
        try:
            res["arms"][name] = fn()
        except Exception as exc:                          # noqa: BLE001
            res["arms"][name] = {"error": repr(exc)[:800]}

    ctx = {}

    def bdt():
        tsnap = snaps.get("bdt", (None, None))[1]
        ctx["polls"] = {m: chain_polls(os.path.join(sp, STACK, "%s_chain.jsonl" % m), tsnap) for m in MONITORS}
        sec = score_bdt(trials, ctx["polls"], vm("bdt"))
        sec["summary"] = summarise_bdt(sec)
        ctx["sec"] = sec
        return sec
    section("block_conditions", lambda: block_conditions(run.events, os.path.join(sp, STACK, "hostlog.jsonl")))
    section("H1b_BDT", bdt)
    section("H1b_late_view_copy", lambda: score_late_view(ctx["sec"], trials, ctx["polls"]))
    section("H10b_CS2", lambda: score_cs2(cs, snaps.get("cs2", (None, None))[0], vm("cs2")))
    if not a.no_floor:
        section("floor", lambda: {m: score_floor(V.get((STACK, m, "floor")), trials, cs, snaps.get("cs2", (None,))[0])
                                  for m in MONITORS})
    text = json.dumps(res, indent=1, default=str) + "\n"
    with open(dst, "x") as fh:
        fh.write(text)
    print("wrote", dst, hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
