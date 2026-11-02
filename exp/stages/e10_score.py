"""E10 (round 14) -- score one run of testbed/e10/run_e10.sh against its pre-registration (exp/out/e10_preregistration.json).

The authoritative verification is exp/stages/e7_verify.py (with monitor/hardening_e10.patch and
exp/stages/verifier_e10.patch applied), run per monitor (direct, copy) and per block against the snapshot taken at the
block's end, as E9's scorer does (cached in <run dir>/verify/). For the D1 comparison the block of the hub's
unobservability arms is verified a second time with the E9 verifier (exp/stages/e7_verify_e9.py, kept byte for byte).
What this file adds, per arm (drafts/round13/E10_DESIGN.md section 4 defines each outcome and its prediction):

  BDT, CTX       per trial and monitor: the inserted row's verdict (attributable = detected; benign_late = reported as a
                 late commit; unobserved_late; or no evidence when the row was in the sealing copy), the predicted verdict
                 from the monitor's own poll times (copy_at of the last observable poll before the insertion committed
                 minus the row's timestamp, against LATE_BOUND 30 s), agreement, and attack success by the frontend
                 display rule (stored by homeprov_e10; its DISPLAY_SRC asserted equal to r14c_e8_attack_success.py's)
  DEL, DEL-PH    per trial and monitor: observed (an observable poll's keylog entry lists the key), detected (the deleted
                 row's second flagged, or a keylog violation names the key), the prediction from the poll times (an
                 observable poll copied in [visible, delete committed), ambiguous within 50 ms of either end), agreement;
                 detection rate per delay; DEL-PH: how well the sensor predicted the direct monitor's next read
  LOWKEY, WIPE   detected per trial and monitor (prediction: always)
  CS (D3)        rows the stepped clock wrote: excused under the CLOCK_STEP marker, attributable without it (step 60 s),
                 benign without it (step 10 s)
  PW             per declared purge and variant: detected or excused, and the verifier's reason (prediction per variant)
  UL-*, INF-*    per hold and monitor: polls, unobservable polls and their reasons, the hub's rows during the hold; the
                 blind-window launder and deletion; the D1 stall-then-backdate under both verifiers; per-poll cost and
                 seal delay during the inflation arms; the distinguishability rule on every unobservable interval of
                 E10 (and of E9's chains when the E9 run directory is given)
  B1-B4, U       violations predicted from the recorder (B1, B3: the segments holding the renamed / purged entity's rows;
                 B2, B4, U: none) against the unexcused ones; name-map transitions and their markers; schema evidence
  floor          unexcused violations on untouched seconds of the whole main session (prediction 0)

    python3 exp/stages/e10_score.py --run-dir <run dir> --tag e10_main [--out-dir exp/out] [--e9-run-dir DIR] [--jobs 2]

Writes <out-dir>/<tag>_score.json; never overwrites (--overwrite).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import glob
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
E7_VERIFY = os.path.join(HERE, "e7_verify.py")
E9_VERIFY = os.path.join(HERE, "e7_verify_e9.py")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "exp"))
import e7_verify as EV                       # noqa: E402
from rig import stats                        # noqa: E402

LATE_BOUND, GAP_S, PURGE_TOL_S, RESTORE_TOL_S = 30.0, 30.0, 60.0, 30.0
AMBIGUOUS_S = 0.05                     # pre-registered: a poll copy within 50 ms of a trial's boundary is ambiguous
UNOBS_RULE_MIN_S, UNOBS_RULE_HUB_S = 60.0, 120.0    # pre-registered distinguishability rule (E10_DESIGN.md section 7)
MONITORS = ("direct", "copy")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if p and os.path.exists(p) else None


def jl(path):
    out = []
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def cp(k, n):
    if not n:
        return None
    r = stats.clopper_pearson(k, n)
    return {"k": k, "n": n, "interval": [r["ci_lo"], r["ci_hi"]]}


def dist(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    q = lambda f: xs[min(len(xs) - 1, int(f * (len(xs) - 1) + 0.5))]   # noqa: E731
    return {"n": len(xs), "median": q(0.5), "p90": q(0.9), "max": xs[-1], "min": xs[0]}


# ------------------------------------------------------------------------------------------------ inputs
class Run:
    def __init__(self, sp):
        self.sp = sp
        self.events = jl(os.path.join(sp, "events.jsonl"))
        self.plan = json.load(open(os.path.join(sp, "plan.json")))
        self.results = collections.defaultdict(list)
        for f in sorted(glob.glob(os.path.join(sp, "e10", "*.json"))):
            try:
                d = json.load(open(f))
            except ValueError:
                continue
            d["_file"] = os.path.basename(f)
            self.results[d.get("op")].append(d)
        for v in self.results.values():
            v.sort(key=lambda d: d.get("t_started") or 0)

    def snap(self, stack, label):
        for e in self.events:
            if e.get("type") == "snapshot" and e.get("ok") and e.get("stack") == stack and e.get("label") == label:
                p = os.path.join(self.sp, e["file"])
                return (p, e["t_snapshot"]) if os.path.exists(p) else (None, None)
        return None, None

    def t(self, stack, name):
        p = os.path.join(self.sp, stack, name)
        return float(open(p).read().strip()) if os.path.exists(p) else None

    def trials(self, op):
        out = []
        for d in self.results.get(op, []):
            out += [t for t in d.get("trials", []) if not t.get("err")]
        return out

    def hub_starts(self, stack):
        out = []
        for e in self.events:
            if e.get("stack") == stack and e.get("type") in ("hub_restart",):
                out.append(e["ts"])
            if e.get("stack") == stack and e.get("type") == "upgrade":
                r = e.get("result") or {}
                out += [r.get("t_stopped"), r.get("t_started")]
        return [x for x in out if x]


# ------------------------------------------------------------------------------------------------ verification jobs
def verify_job(sp, stack, m, label, db, tsnap, window, extra, verifier=E7_VERIFY):
    vd = os.path.join(sp, "verify")
    os.makedirs(vd, exist_ok=True)
    key = hashlib.sha256(json.dumps([stack, extra, window, tsnap, sha(db), sha(verifier)]).encode()).hexdigest()[:12]
    dst = os.path.join(vd, "%s_%s_%s_%s.json" % (stack, m, label, key))
    if os.path.exists(dst):
        try:
            return (stack, m, label), json.load(open(dst))
        except ValueError:
            os.rename(dst, dst + ".bad")
    cmd = [sys.executable, verifier, "verify", "--chain", os.path.join(sp, stack, "%s_chain.jsonl" % m), "--db", db,
           "--late-bound", str(LATE_BOUND), "--gap-s", str(GAP_S), "--snapshot-at", str(tsnap), "--scheme", "stable",
           "--window", str(window[0]), str(window[1]), "--out", dst,
           "--sign-pubkey", os.path.join(sp, stack, "%s_sign_pub.pem" % m),
           "--operator-pubkey", os.path.join(sp, stack, "operator_sign_pub.pem")]
    esc = os.path.join(sp, stack, "escrow_%s" % m, "escrow.jsonl")
    if os.path.exists(esc) and os.path.getsize(esc) > 0:
        cmd += ["--escrow", esc]
    cmd += extra
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dst):
        return (stack, m, label), {"error": "e7_verify failed", "rc": r.returncode, "stderr": r.stderr[-3000:],
                                   "stdout": r.stdout[-2000:], "cmd": " ".join(cmd)}
    out = json.load(open(dst))
    out.setdefault("_e10", {})["verify_wall_s"] = round(time.time() - t0, 1)
    return (stack, m, label), out


def sets(v):
    """flagged seconds, unknown seconds, verdict per row key, keylog keys named by violations."""
    if not v or "error" in v:
        return None
    unknown = {x["seg"] for x in v.get("root_unknown_segments") or [] if x["gran"] == "second"}
    verdict = {}
    for name, rows in (("attributable", v.get("attributable_rows")), ("benign_late", v.get("benign_late_rows")),
                       ("unobserved_late", v.get("unobserved_late_rows")),
                       ("excused_clock_step", (v.get("clock_step") or {}).get("excused_rows"))):
        for r in rows or []:
            verdict.setdefault(r["key"], (name, r))
    for r in v.get("unobserved_late_rows") or []:
        if r.get("second"):
            unknown.add(r["second"])
    kl = set()
    for kv in v.get("keylog_violations") or []:
        for f in ("removed", "suspects", "added", "changed", "likely"):
            for x in kv.get(f) or []:
                kl.add(x if isinstance(x, str) else x.get("key"))
    return {"flagged": set(v.get("flagged_seconds") or []), "unknown": unknown, "verdict": verdict, "keylog": kl,
            "keylog_seconds": {s for kv in v.get("keylog_violations") or [] for s in kv.get("seconds") or []}}


def row_outcome(S, key, sec):
    if S is None:
        return "verification_failed"
    sec = str(int(sec))
    if sec in S["flagged"] or S["verdict"].get(key, ("",))[0] == "attributable":
        return "detected"
    if S["verdict"].get(key, ("",))[0] == "excused_clock_step":
        return "excused_clock_step"
    if sec in S["unknown"] or S["verdict"].get(key, ("",))[0] == "unobserved_late":
        return "unknown"
    if S["verdict"].get(key, ("",))[0] == "benign_late":
        return "reported_late"
    return "no_evidence"


def deletion_outcome(S, key, sec):
    if S is None:
        return "verification_failed"
    if str(int(sec)) in S["flagged"] or key in S["keylog"]:
        return "detected"
    if str(int(sec)) in S["unknown"]:
        return "unknown"
    return "no_evidence"


# ------------------------------------------------------------------------------------------------ the poll timeline
class Polls:
    """The monitor's polls from its chain: copy time, observability, watermark, keylog keys first observed."""

    def __init__(self, chain):
        lines = open(chain).read().splitlines() if os.path.exists(chain) else []
        P = EV.parse_chain(lines)
        self.polls = sorted(P["polls"].values(), key=lambda p: (p.get("copy_at") or 0))
        self.obs = [p for p in self.polls if not p.get("unobservable") and p.get("copy_at") is not None
                    and isinstance(p.get("wm"), dict)]
        self.observed_keys = collections.defaultdict(set)
        for p in self.polls:
            for (t, lo, _hi), e in (p.get("keylog_chunks") or {}).items():
                for x in e.get("rows") or []:
                    self.observed_keys[t].add(lo + int(x[0]))

    def copies_in(self, a, b):
        return [p["copy_at"] for p in self.obs if a <= p["copy_at"] < b]

    def last_copy_before(self, t):
        xs = [p["copy_at"] for p in self.obs if p["copy_at"] < t]
        return max(xs) if xs else None

    def first_copy_after(self, t):
        xs = [p["copy_at"] for p in self.obs if p["copy_at"] >= t]
        return min(xs) if xs else None

    def unobservable_runs(self):
        """Maximal runs of consecutive unobservable polls: (first copy, last copy, n, reasons)."""
        out, cur = [], None
        for p in self.polls:
            if p.get("unobservable"):
                if cur is None:
                    cur = {"from": p.get("copy_at") or p.get("ts"), "to": p.get("copy_at") or p.get("ts"), "n": 0,
                           "reasons": collections.Counter()}
                cur["to"] = p.get("copy_at") or p.get("ts")
                cur["n"] += 1
                cur["reasons"][str(p.get("reason"))] += 1
            elif cur is not None:
                cur["next_observable"] = p.get("copy_at")
                out.append(cur)
                cur = None
        if cur is not None:
            out.append(cur)
        for r in out:
            r["reasons"] = dict(r["reasons"])
            r["duration_s"] = round(((r.get("next_observable") or r["to"]) - r["from"]), 3) if r["from"] else None
        return out


def predicted_insertion(polls, t_commit, ts):
    """BDT/CTX: the verdict the design predicts from the monitor's own poll times: the last observable copy before the
    insertion committed bounds the commit time from below; attributable iff that minus the row's timestamp exceeds
    LATE_BOUND; no evidence iff no observable poll sealed the row's second before the insertion (its first cover read
    the row); ambiguous when a copy lies within 50 ms of the commit."""
    sec = int(ts)
    sealing = polls.first_copy_after(sec + 1)
    if sealing is None or sealing >= t_commit:
        return "no_evidence", None
    q = polls.last_copy_before(t_commit)
    lat = None if q is None else q - ts
    amb = any(abs(c - t_commit) < AMBIGUOUS_S for c in polls.copies_in(t_commit - 1, t_commit + 1))
    if lat is not None and lat > LATE_BOUND:
        return ("ambiguous" if amb else "detected"), lat
    return ("ambiguous" if amb else "reported_late"), lat


def predicted_deletion(polls, t_vis, t_del):
    xs = polls.copies_in(t_vis - AMBIGUOUS_S, t_del + AMBIGUOUS_S)
    if any(abs(c - t_vis) < AMBIGUOUS_S or abs(c - t_del) < AMBIGUOUS_S for c in xs):
        return "ambiguous"
    return "detected" if any(t_vis <= c < t_del for c in xs) else "no_evidence"


# ------------------------------------------------------------------------------------------------ scoring sections
def score_insertions(run, V, polls, op, label, key_of, ts_of, group):
    out = {"per_trial": [], "per_level": {}}
    for t in run.trials(op):
        key, ts, tc = key_of(t), ts_of(t), t.get("t_commit")
        row = {"trial": t.get("trial"), "level": t.get(group), "key": key, "ts": ts, "t_commit": tc,
               "backdate_at_commit_s": t.get("backdate_at_commit_s"), "listed": t.get("listed"),
               "display_admin": t.get("display_admin"), "display_non_admin": t.get("display_non_admin"),
               "attack_success_admin": t.get("attack_success_admin")}
        for m in MONITORS:
            S = sets(V.get(("e10s", m, label)))
            pred, lat = predicted_insertion(polls[m], tc, ts) if tc and ts else (None, None)
            got = row_outcome(S, key, ts)
            row[m] = {"outcome": got, "predicted": pred, "lower_bound_s": lat,
                      "agrees": (pred == got) if pred not in (None, "ambiguous") else None}
        out["per_trial"].append(row)
    for lev in sorted({r["level"] for r in out["per_trial"]}, key=lambda x: (x is None, x)):
        rs = [r for r in out["per_trial"] if r["level"] == lev]
        d = {"n": len(rs), "attack_success_admin": cp(sum(1 for r in rs if r["attack_success_admin"]), len(rs)),
             "listed": sum(1 for r in rs if r["listed"])}
        for m in MONITORS:
            c = collections.Counter(r[m]["outcome"] for r in rs)
            ag = [r[m]["agrees"] for r in rs if r[m]["agrees"] is not None]
            d[m] = {"outcomes": dict(c), "detected": cp(c.get("detected", 0), len(rs)),
                    "prediction_agrees": cp(sum(ag), len(ag)), "ambiguous": sum(1 for r in rs if r[m]["predicted"] == "ambiguous")}
        out["per_level"][str(lev)] = d
    return out


def score_deletions(run, V, polls, op, label):
    out = {"per_trial": [], "per_delay": {}}
    for t in run.trials(op):
        r0 = t.get("deleted_row") or {}
        key, ts = "s:%s" % r0.get("state_id"), r0.get("ts")
        row = {"trial": t.get("trial"), "delay_s": t.get("delay_s"), "key": key, "ts": ts,
               "visible_for_s": t.get("visible_for_s"), "attack_success": t.get("attack_success"),
               "dangling_successors": len(t.get("dangling_successors") or [])}
        if op == "delph":
            nxt = polls["direct"].first_copy_after(t.get("sensor_last_read_start", 0) + 0.5)
            row["sensor"] = {"predicted_next_read": t.get("predicted_next_read"), "actual_next_copy": nxt,
                             "error_s": (nxt - t["predicted_next_read"]) if nxt and t.get("predicted_next_read") else None}
        for m in MONITORS:
            S = sets(V.get(("e10s", m, label)))
            pred = predicted_deletion(polls[m], t["t_visible"], t["t_delete_commit"])
            got = deletion_outcome(S, key, ts)
            obs = r0.get("state_id") in polls[m].observed_keys["states"]
            row[m] = {"outcome": got, "predicted": pred, "observed_by_keylog": obs,
                      "agrees": (pred == got) if pred != "ambiguous" else None,
                      "detected_iff_observed": (got == "detected") == obs}
        out["per_trial"].append(row)
    for dly in sorted({r["delay_s"] for r in out["per_trial"]}, key=lambda x: (x is None, x)):
        rs = [r for r in out["per_trial"] if r["delay_s"] == dly]
        d = {"n": len(rs), "attack_success": cp(sum(1 for r in rs if r["attack_success"]), len(rs))}
        for m in MONITORS:
            ag = [r[m]["agrees"] for r in rs if r[m]["agrees"] is not None]
            d[m] = {"detected": cp(sum(1 for r in rs if r[m]["outcome"] == "detected"), len(rs)),
                    "prediction_agrees": cp(sum(ag), len(ag)),
                    "detected_iff_observed": cp(sum(1 for r in rs if r[m]["detected_iff_observed"]), len(rs))}
        out["per_delay"][str(dly)] = d
    return out


def score_simple_rows(run, V, op, label, key_fn, sec_fn, kind="insert"):
    out = []
    for t in run.trials(op):
        row = {"trial": t.get("trial"), "key": key_fn(t), "second": sec_fn(t)}
        for m in MONITORS:
            S = sets(V.get(("e10s", m, label)))
            row[m] = (row_outcome if kind == "insert" else deletion_outcome)(S, row["key"], row["second"])
        out.append(row)
    return {"per_trial": out, **{m: cp(sum(1 for r in out if r[m] == "detected"), len(out)) for m in MONITORS}}


def score_wipe(run, V):
    out = []
    for t in run.trials("wipe"):
        sec = str(t["second"])
        row = {"second": sec, "states_deleted": len(t.get("states_deleted") or []),
               "events_deleted": len(t.get("events_deleted") or [])}
        for m in MONITORS:
            S = sets(V.get(("e10s", m, "wipe")))
            row[m] = "verification_failed" if S is None else ("detected" if sec in S["flagged"] else
                                                               "unknown" if sec in S["unknown"] else "no_evidence")
        out.append(row)
    return {"per_trial": out, **{m: cp(sum(1 for r in out if r[m] == "detected"), len(out)) for m in MONITORS},
            "collusion": "offline: exp/stages/e10_collusion.py (D2, D1 host variant)"}


def score_cs(run, V):
    out = []
    for r in run.results.get("clock_step", []):
        lo_k, hi_k = (r.get("wm_before") or {}).get("states") or 0, (r.get("wm_after") or {}).get("states") or 0
        row = {"step": (r.get("command") or {}).get("step"), "marker": bool((r.get("command") or {}).get("marker")),
               "step_s": r.get("step_s"), "rows_written": r.get("rows_written")}
        for m in MONITORS:
            v = V.get(("e10s", m, "cs"))
            S = sets(v)
            if S is None:
                row[m] = "verification_failed"
                continue
            c = collections.Counter()
            for key, (verd, _r) in S["verdict"].items():
                t, k = EV.kparse(key)
                if t == "states" and lo_k < k <= hi_k:
                    c[verd] += 1
            row[m] = {"verdicts_of_rows_written_during_the_step": dict(c),
                      "clock_step_markers": {"accepted": len((v.get("clock_step") or {}).get("accepted") or []),
                                             "rejected": (v.get("clock_step") or {}).get("rejected")}}
        out.append(row)
    return out


PW_PREDICTED = {"PW-B": "excused", "PW-R": "detected", "PW-F-in": "no_evidence_or_excused", "PW-U": "detected",
                "PW-X": "detected", "PW-F-out": "detected"}


def score_pw(run, V):
    out = []
    for r in run.results.get("pw", []):
        i = (r.get("command") or {}).get("event")
        ev = {"event": i, "scheduled_ts": r.get("scheduled_ts"), "c0": r.get("c0"), "c1": r.get("c1"), "variants": {}}
        for var, act in (r.get("actions") or {}).items():
            if var.startswith("PW-F"):
                keys = ["s:%s" % act["insert"]["forged_state_id"]]
                secs = [int(act["insert"]["forged_row_ts"])]
            elif var == "PW-R":
                keys, secs = ["s:%s" % act.get("state_id")], []
            else:
                keys = ["s:%s" % k for k in act.get("states_deleted") or []] + ["e:%s" % k for k in act.get("events_deleted") or []]
                secs = []
            d = {"predicted": PW_PREDICTED.get(var), "rows": len(keys)}
            for m in MONITORS:
                det = None
                for lab in ("pw%s_hist" % i, "pw%s_sess" % i):
                    v = V.get(("e10s", m, lab))
                    S = sets(v)
                    if S is None:
                        continue
                    hit = [k for k in keys if k in S["keylog"]] + [s for s in secs if str(s) in S["flagged"]]
                    det = (det or 0) + len(hit)
                    if var in ("PW-U", "PW-X", "PW-B"):
                        d.setdefault("not_excused_reasons_" + m, sorted({w for x in (v.get("purge") or {}).get("not_excused") or []
                                                                         for w in ([x["why"]] if isinstance(x.get("why"), str) else x.get("why") or [])}))
                d[m] = {"keys_or_seconds_flagged": det, "detected": bool(det)}
            ev["variants"][var] = d
        out.append(ev)
    return out


def score_unobs(run, V, polls):
    holds = []
    for r in run.results.get("lock_shm", []) + run.results.get("lock_write", []):
        a = r.get("t_hold_start") or r.get("t_acquired") or r.get("t_request")
        b = (r.get("lock") or {}).get("t_end") or r.get("t_released") or (a + float(r.get("hold_s") or 0) if a else None)
        if not a or not b:
            continue
        h = {"op": r.get("op"), "mode": (r.get("command") or {}).get("mode"), "from": a, "to": b}
        for m in MONITORS:
            ps = [p for p in polls[m].polls if p.get("copy_at") and a <= p["copy_at"] < b]
            h[m] = {"polls": len(ps), "unobservable": sum(1 for p in ps if p.get("unobservable")),
                    "reasons": dict(collections.Counter(str(p.get("reason")) for p in ps if p.get("unobservable")))}
        if r.get("wm_before"):
            h["hub_rows_during_hold"] = {"wm_before": r["wm_before"], "wm_after": r.get("wm_after")}
        for part in ("launder", "blind_delete", "d1_backdate"):
            x = r.get(part)
            if not x or x.get("err"):
                continue
            if part == "launder":
                key, sec = "s:%s" % x["state_id"], x.get("ts")
            elif part == "blind_delete":
                key, sec = "s:%s" % (x.get("deleted_row") or {}).get("state_id"), (x.get("deleted_row") or {}).get("ts")
            else:
                key, sec = "s:%s" % x["forged_state_id"], x["forged_row_ts"]
            h[part] = {}
            for m in MONITORS:
                for lab, verifier in (("a_end", "patched"), ("a_end_e9", "e9")):
                    S = sets(V.get(("e10s", m, lab)))
                    if S is None:
                        continue
                    if part == "launder":
                        got = ("detected" if key in S["keylog"] or (sec is not None and str(int(sec)) in S["flagged"])
                               else "unknown" if sec is not None and str(int(sec)) in S["unknown"] else "no_evidence")
                    elif part == "blind_delete":
                        got = deletion_outcome(S, key, sec)
                    else:
                        got = row_outcome(S, key, sec)
                    h[part]["%s_%s" % (m, verifier)] = got
        holds.append(h)
    return holds


def distinguishability(run, polls, stack="e10s", hold_windows=()):
    starts = run.hub_starts(stack)
    out = {"rule": {"min_duration_s": UNOBS_RULE_MIN_S, "no_hub_start_within_s": UNOBS_RULE_HUB_S}, "intervals": []}
    for m in MONITORS:
        for r in polls[m].unobservable_runs():
            near = any(abs((s or 0) - r["from"]) <= UNOBS_RULE_HUB_S or abs((s or 0) - r["to"]) <= UNOBS_RULE_HUB_S
                       for s in starts)
            flagged = (r["duration_s"] or 0) >= UNOBS_RULE_MIN_S and not near
            attack = any(a - 5 <= r["from"] <= b + 5 for a, b in hold_windows)
            out["intervals"].append(dict(r, monitor=m, near_hub_start=near, suspicious=flagged, during_attack_hold=attack))
    iv = out["intervals"]
    out["true_positive"] = cp(sum(1 for x in iv if x["during_attack_hold"] and x["suspicious"]),
                              sum(1 for x in iv if x["during_attack_hold"]))
    out["false_positive"] = {"k": sum(1 for x in iv if not x["during_attack_hold"] and x["suspicious"]),
                             "n_benign_intervals": sum(1 for x in iv if not x["during_attack_hold"])}
    return out


def cost_windows(sp, stack, windows):
    out = {}
    for m in MONITORS:
        rows = jl(os.path.join(sp, stack, "%s_cost.jsonl" % m))
        out[m] = {}
        for name, (a, b) in windows.items():
            sel = [r for r in rows if r.get("ts") is not None and a <= float(r["ts"]) < b]
            out[m][name] = {"n_polls": len(sel), "total_ms": dist([(r.get("copy_ms") or 0) + (r.get("load_ms") or 0)
                                                                   + (r.get("commit_ms") or 0) + (r.get("append_ms") or 0)
                                                                   for r in sel]),
                            "unobservable": sum(1 for r in sel if r.get("evidence_unobservable")),
                            "interval_s": dist([float(b_["ts"]) - float(a_["ts"]) for a_, b_ in zip(sel, sel[1:])])}
    return out


def entity_segments(db, entity_id, before_ts=None):
    """Distinct seconds, minutes and hours holding a state row of the entity timestamped before before_ts (when given):
    the segments a change of that entity's committed values makes fail (prediction for B1 and B3)."""
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    q = "SELECT s.last_updated_ts FROM states s JOIN states_meta m ON m.metadata_id = s.metadata_id WHERE m.entity_id=?"
    ts = [r[0] for r in c.execute(q, (entity_id,)) if isinstance(r[0], (int, float))
          and (before_ts is None or r[0] < before_ts)]
    c.close()
    return {"rows": len(ts), "second": len({int(t) for t in ts}), "minute": len({int(t // 60) for t in ts}),
            "hour": len({int(t // 3600) for t in ts})}


def violations_by_gran(v):
    if not v or "error" in v:
        return None
    c = collections.Counter(x["gran"] for x in v.get("violations") or [] if x.get("violation") and x.get("attributable"))
    return {"second": c.get("second", 0), "minute": c.get("minute", 0), "hour": c.get("hour", 0),
            "keylog_violations": len(v.get("keylog_violations") or []), "flagged_seconds": len(v.get("flagged_seconds") or []),
            "namemap": (v.get("namemap") or {}).get("verdict"),
            # e7_verify's namemap.unexcused_changes is a count (fix of 2026-10-19, smoke e10_smoke3: len() of an int)
            "namemap_unexcused": (lambda u: u if isinstance(u, int) else len(u or []))(
                (v.get("namemap") or {}).get("unexcused_changes"))}


def display_src_identity():
    a = open(os.path.join(ROOT, "testbed", "real", "ha-config", "custom_components", "homeprov_e10", "__init__.py")).read() \
        if os.path.exists(os.path.join(ROOT, "testbed", "real", "ha-config", "custom_components", "homeprov_e10", "__init__.py")) else ""
    b = open(os.path.join(ROOT, "exp", "sp2027", "r14c_e8_attack_success.py")).read()
    grab = lambda s: (re.search(r"DISPLAY_SRC = '''(.*?)'''", s, re.S) or [None, None])[1]   # noqa: E731
    return grab(a) is not None and grab(a) == grab(b)


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "exp", "out"))
    ap.add_argument("--e9-run-dir", default=None, help="E9's run directory: its chains enter the distinguishability FP")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    dst = os.path.join(a.out_dir, "%s_score.json" % a.tag)
    if os.path.exists(dst) and not a.overwrite:
        raise SystemExit("REFUSING: %s exists" % dst)
    run = Run(a.run_dir)
    sp = a.run_dir
    keep_s = {"e10s": 29 * 86400.0, "e10u": 30 * 86400.0}
    common = lambda st: ["--purge-keep-s", str(keep_s[st]), "--purge-tol-s", str(PURGE_TOL_S),   # noqa: E731
                         "--restore-tol-s", str(RESTORE_TOL_S)]
    jobs = []

    def add(stack, label, snap, window, extra=(), verifier=E7_VERIFY):
        db, ts = run.snap(stack, snap)
        if db:
            for m in MONITORS:
                if os.path.exists(os.path.join(sp, stack, "%s_chain.jsonl" % m)):
                    jobs.append((sp, stack, m, label, db, ts, [window[0], ts if window[1] is None else window[1]],
                                 common(stack) + list(extra), verifier))

    t0 = run.t("e10s", "t_start")
    hist_lo = None
    sdb, _st = run.snap("e10s", "start")
    if sdb:
        c = sqlite3.connect("file:%s?mode=ro" % sdb, uri=True)
        hist_lo = min(x for x in (c.execute("select min(last_updated_ts) from states").fetchone()[0],
                                  c.execute("select min(time_fired_ts) from events").fetchone()[0]) if x is not None)
        c.close()
    if t0:
        add("e10s", "del", "snap_del", [t0, None])
        add("e10s", "timing", "snap_timing", [t0, None])
        add("e10s", "wipe", "snap_wipe", [t0, None])
        cs = run.results.get("clock_step", [])
        if cs:
            add("e10s", "cs", "cs_end", [min(r["t_on"] for r in cs) - 600, None])
        for r in run.results.get("pw", []):
            i = (r.get("command") or {}).get("event")
            add("e10s", "pw%s_hist" % i, "pw%s_post" % i, [r["c0"] - 3600, r["c1"] + 3600])
            add("e10s", "pw%s_sess" % i, "pw%s_post" % i, [t0, None])
        add("e10s", "a_end", "snap_a_end", [t0, None])
        if os.path.exists(E9_VERIFY):
            add("e10s", "a_end_e9", "snap_a_end", [t0, None], verifier=E9_VERIFY)
        if hist_lo is not None:
            for lab, snap in (("b1", "b1_end"), ("b2", "b2_end"), ("b3", "b3_end"), ("b4", "b4_post")):
                add("e10s", lab, snap, [int(hist_lo) - 3600, None])
        add("e10s", "floor", "final", [t0, None])
    u_t0 = run.t("e10u", "t_start")
    udb, _ = run.snap("e10u", "start")
    if u_t0 and udb:
        c = sqlite3.connect("file:%s?mode=ro" % udb, uri=True)
        ulo = c.execute("select min(last_updated_ts) from states").fetchone()[0] or u_t0
        c.close()
        for lab, snap in (("pre", "pre_upgrade"), ("post", "post_upgrade"), ("final", "final")):
            add("e10u", lab, snap, [int(ulo) - 3600, None])
    V = {}
    print("== E10 score %s: %d verifications" % (a.tag, len(jobs)), flush=True)
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for k, out in ex.map(lambda j: verify_job(*j), jobs):
            V[k] = out
            print("  %-40s %s" % ("/".join(k), "ERROR " + out.get("stderr", "")[-200:] if "error" in out
                                  else "ok (%ss)" % (out.get("_e10") or {}).get("verify_wall_s")), flush=True)

    polls = {m: Polls(os.path.join(sp, "e10s", "%s_chain.jsonl" % m)) for m in MONITORS}
    res = {"experiment": "E10 (round 14): adaptive arms on the stated boundaries, and routine operations, scratch stacks",
           "tag": a.tag, "plan_sha256": sha(os.path.join(sp, "plan.json")),
           "pre_registered_parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "purge_tol_s": PURGE_TOL_S,
                                         "restore_tol_s": RESTORE_TOL_S, "ambiguous_s": AMBIGUOUS_S,
                                         "unobservable_rule": [UNOBS_RULE_MIN_S, UNOBS_RULE_HUB_S],
                                         "keep_days": {"e10s": 29, "e10u": 30}},
           "verifier": {"patched": {"path": "exp/stages/e7_verify.py", "sha256": sha(E7_VERIFY)},
                        "e9": {"path": "exp/stages/e7_verify_e9.py", "sha256": sha(E9_VERIFY)}},
           "display_rule_identical_to_r14c": display_src_identity(),
           "verifications": {"/".join(k): ({"error": v.get("error"), "rc": v.get("rc")} if "error" in v else
                                           {"flagged_seconds": len(v.get("flagged_seconds") or []),
                                            "violations": violations_by_gran(v),
                                            "unobserved_late_rows": len(v.get("unobserved_late_rows") or []),
                                            "root_unknown_segments": len(v.get("root_unknown_segments") or []),
                                            "wall_s": (v.get("_e10") or {}).get("verify_wall_s")})
                             for k, v in V.items()},
           "arms": {}, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def section(name, fn):
        try:
            res["arms"][name] = fn()
        except Exception as exc:                          # noqa: BLE001
            res["arms"][name] = {"error": repr(exc)[:500]}

    section("BDT", lambda: score_insertions(run, V, polls, "bdt", "del", lambda t: "s:%s" % t["forged_state_id"],
                                            lambda t: t["forged_row_ts"], "age_s"))
    section("CTX", lambda: score_insertions(run, V, polls, "ctx", "del", lambda t: "e:%s" % t["inserted_event_id"],
                                            lambda t: t["inserted_ts"], "delay_s"))
    section("DEL", lambda: score_deletions(run, V, polls, "del", "del"))
    section("DEL-PH", lambda: score_deletions(run, V, polls, "delph", "del"))
    section("LOWKEY", lambda: score_simple_rows(run, V, "lowkey", "timing", lambda t: "s:%s" % t["forged_state_id"],
                                                lambda t: t["forged_row_ts"]))
    section("WIPE", lambda: score_wipe(run, V))
    section("CS", lambda: score_cs(run, V))
    section("PW", lambda: score_pw(run, V))
    holds = []
    for r in run.results.get("lock_shm", []) + run.results.get("lock_write", []):
        a_ = r.get("t_hold_start") or r.get("t_acquired")
        b_ = (r.get("lock") or {}).get("t_end") or r.get("t_released")
        if a_ and b_:
            holds.append((a_, b_))
    section("UNOBS", lambda: score_unobs(run, V, polls))
    section("UNOBS_distinguishability", lambda: distinguishability(run, polls, "e10s", holds))

    def e9_fp():
        """The rule on every unobservable interval of E9's week (benign: no hold), from E9's own chains and events."""
        if not a.e9_run_dir:
            return {"note": "no --e9-run-dir given"}
        ev9 = jl(os.path.join(a.e9_run_dir, "events.jsonl"))
        starts = [e["ts"] for e in ev9 if e.get("type") == "hub_restart"]
        out = {}
        for m in MONITORS:
            pl = Polls(os.path.join(a.e9_run_dir, "%s_chain.jsonl" % m))
            iv = pl.unobservable_runs()
            flagged = [r for r in iv if (r["duration_s"] or 0) >= UNOBS_RULE_MIN_S and not any(
                abs(s_ - r["from"]) <= UNOBS_RULE_HUB_S or abs(s_ - r["to"]) <= UNOBS_RULE_HUB_S for s_ in starts)]
            out[m] = {"intervals": len(iv), "suspicious": len(flagged), "durations_s": dist([r["duration_s"] for r in iv]),
                      "reasons": dict(collections.Counter(k for r in iv for k in r["reasons"])),
                      "suspicious_intervals": flagged[:50]}
        return out
    section("UNOBS_distinguishability_E9_benign_week", e9_fp)
    for nm in ("journal_mode", "inflate_table", "deflate_table", "inflate_window"):
        res["arms"].setdefault("UNOBS_" + nm, [{k: v for k, v in r.items() if k not in ("command",)}
                                              for r in run.results.get(nm, [])])

    def inflation_cost():
        w = {}
        for nm in ("inflate_table", "inflate_window"):
            for r in run.results.get(nm, []):
                w[nm] = (r.get("t_start") or r["t_started"], (r.get("t_end") or r["t_finished"]) + 1200)
        if t0:
            w["baseline_first_hour"] = (t0, t0 + 3600)
        return cost_windows(sp, "e10s", w)
    section("UNOBS_cost", inflation_cost)

    def routine():
        out = {}
        b1 = (run.results.get("rename_entity") or [None])[0]
        db, _ = run.snap("e10s", "b1_end")
        if b1 and db:
            out["B1_entity_id_rename"] = {"entity_id": b1["entity_id"], "new_entity_id": b1["new_entity_id"],
                                          "predicted_segments": entity_segments(db, b1["new_entity_id"], b1["t"] - 10.0),
                                          **{m: violations_by_gran(V.get(("e10s", m, "b1"))) for m in MONITORS}}
        b2 = (run.results.get("remove_device") or [None])[0]
        if b2:
            out["B2_device_removal"] = {k: b2.get(k) for k in ("device_id", "entities", "device_present_after",
                                                               "entities_after", "integration_allowed")}
            out["B2_device_removal"].update({m: violations_by_gran(V.get(("e10s", m, "b2"))) for m in MONITORS})
            out["B2_device_removal"]["predicted"] = {"violations": 0, "namemap": "changed_with_declared_renames"}
        b3 = (run.results.get("purge_entities") or [None])[0]
        db3, _ = run.snap("e10s", "b3_end")
        db_pre, _ = run.snap("e10s", "b2_end")
        if b3 and db_pre:
            out["B3_purge_entities"] = {"entity_ids": b3["entity_ids"],
                                        "predicted_segments": {e: entity_segments(db_pre, e, b3["t"] - 10.0)
                                                               for e in b3["entity_ids"]},
                                        **{m: violations_by_gran(V.get(("e10s", m, "b3"))) for m in MONITORS}}
        up = next((e.get("result") for e in run.events if e.get("type") == "upgrade" and e.get("stack") == "e10s"), None)
        out["B4_upgrade_2026_7_4_to_2026_10_1"] = {"upgrade": up, "predicted": {"violations": 0},
                                                   **{m: violations_by_gran(V.get(("e10s", m, "b4"))) for m in MONITORS}}
        upu = next((e.get("result") for e in run.events if e.get("type") == "upgrade" and e.get("stack") == "e10u"), None)
        out["U_schema_upgrade_2025_11_1_to_2026_7_4"] = {
            "upgrade": upu, "predicted": {"violations": 0, "schema_after": [51, 52, 53]},
            **{"%s_%s" % (m, lab): violations_by_gran(V.get(("e10u", m, lab))) for m in MONITORS
               for lab in ("pre", "post", "final")}}
        return out
    section("ROUTINE", routine)

    def floor():
        """Every flagged second of the main session must be explained by an arm: a trial's own second or row, or a second
        inside the window of a block that changes rows (UL, INF, CS, PW, WIPE, B). Unexplained flagged seconds are the
        benign floor's failures (prediction: 0 on both monitors)."""
        out = {}
        touched = set()
        for op in ("bdt", "lowkey"):
            touched |= {str(int(t["forged_row_ts"])) for t in run.trials(op)}
        touched |= {str(int(t["inserted_ts"])) for t in run.trials("ctx")}
        touched |= {str(int(t["unlock_row"]["ts"])) for t in run.trials("ctx")}
        touched |= {str(int((t.get("deleted_row") or {}).get("ts", 0))) for t in run.trials("del") + run.trials("delph")}
        touched |= {str(t["second"]) for t in run.trials("wipe")}
        for r in run.results.get("pw", []):
            for act in (r.get("actions") or {}).values():
                for k in ("insert",):
                    if isinstance(act.get(k), dict):
                        touched.add(str(int(act[k]["forged_row_ts"])))
        windows, open_ = [], {}
        for e in run.events:
            if e.get("type") == "block_begin":
                open_[e["block"]] = e["ts"]
            elif e.get("type") == "block_end" and e.get("block") in open_:
                b = e["block"]
                if b.startswith(("A4_", "A5_", "A6_", "A7_", "B")):
                    windows.append((b, open_[b] - 60, e["ts"] + 120))
        for m in MONITORS:
            v = V.get(("e10s", m, "floor"))
            if not v or "error" in v:
                out[m] = None
                continue
            f = set(v.get("flagged_seconds") or [])
            unexplained = sorted((s_ for s_ in f - touched if not any(a <= int(s_) <= b for _n, a, b in windows)), key=int)
            out[m] = {"flagged_seconds": len(f), "explained_by_trial_rows": len(f & touched),
                      "inside_block_windows": {n: sum(1 for s_ in f - touched if a <= int(s_) <= b) for n, a, b in windows},
                      "unexplained": len(unexplained), "unexplained_seconds": unexplained[:200],
                      "predicted_unexplained": 0}
        return out
    section("floor", floor)
    os.makedirs(a.out_dir, exist_ok=True)
    with open(dst, "w" if a.overwrite else "x") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
    print("wrote", dst)


if __name__ == "__main__":
    main()
