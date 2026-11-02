"""E9 (round 13), part B -- score one run of testbed/e9/run_e9.sh (seven days of the deployed configuration).

The authoritative per-record verification is exp/stages/e7_verify.py (watermark, sealed-through, keylog, LATE_BOUND,
GAP_S, escrow recovery, signatures, the benign floor with the paper's counting rule) with the E9 additions of part A
(purge-disconnect rule A1, per-row binding A2, name-map check A3, operator-signed markers A6). This file runs it, once
per MONITOR (direct, copy) and WINDOW, and adds what it does not cover:

  day d     [d_start, d_end) (24 h from 12:00 UTC), against the end-of-day snapshot: detection per arm (k of n, exact
            95% interval, from the day's harness reports), unexcused violations on UNTOUCHED segments (second, minute,
            hour), excused purge disconnects, segments inside the declared restore, suspect seconds with and without the
            per-row binding, name-map transitions and their outcome, per-poll cost (median, p90, max) and bytes read and
            written per monitor, host sleep, every hub start with its cause, the markers issued;
  night n   the nightly purge: DB-level evidence from the 03:55 and 04:45 snapshots (rows older than the cutoff before and
            after, statistics_runs, recorder_runs, the retained state rows the purge disconnected: old_state_id set to
            NULL), the operator PURGE marker for that night (anchored before 04:12, signature), and the verifier's NEW
            violations over the historical window (segments sealed by the full-history initial seal) between the two
            snapshots, each classified;
  start     full-history seal coverage: the seconds holding a row in the start snapshot without an anchored root;
  overall   pooled detection per arm, floor totals, cost and bytes over the week, witness checks, refusals, alarms.

Classification of a violation (per monitor and window). When the verifier reports its own marker verdicts (part A), those
are used and listed under "verifier"; the harness-side rule below is reported next to them, labelled PROVISIONAL, and is
the only one before part A lands:
  purge_scoped     a segment that lost rows, wholly older than the scoped cutoff of an operator PURGE marker anchored
                   before the purge (cutoff = scheduled_ts - keep_s + 60 s, rig.markers.explains_scoped), or the one
                   straddling segment per granularity;
  purge_disconnect a sealed second whose only change (escrow vs now, e7_verify's recovery) is old_state_id -> NULL on
                   retained state rows, every original predecessor absent now and (with the pre-purge snapshot) older
                   than the cutoff; a minute or hour violation all of whose flagged seconds are such;
  restore          a segment in (restore_point_ts, hub start after the restore], or a keylog range above the backup's
                   watermark, under an operator RESTORE marker anchored before the restore;
  unexcused        everything else.
A segment is touched when it holds a row any trial wrote, edited or named (the paper's counting rule, as E7/E8).

    python3 exp/stages/e9_score.py --run-dir <run dir> --tag e9_main [--out-dir exp/out] [--keep-days 30]

e7_verify outputs are cached in <run dir>/verify/. Writes <out-dir>/<tag>_score.json; never overwrites (--overwrite).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import glob
import hashlib
import importlib.util
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
E7_VERIFY = os.environ.get("E9_VERIFY") or os.path.join(HERE, "e7_verify.py")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "exp"))
sys.path.insert(0, os.path.join(ROOT, "testbed", "anchord"))
import e8_score as E8                        # noqa: E402  (dist, read_chain, witness_checks, refusals, ...)
import e7_verify as EV                       # noqa: E402
from rig import markers as RM               # noqa: E402

LATE_BOUND = float(os.environ.get("E9_LATE_BOUND", "30"))
GAP_S = float(os.environ.get("E9_GAP_S", "30"))
TOL_S = float(os.environ.get("E9_PURGE_TOL_S", "60"))   # scoped PURGE tolerance (pre-registered; E9_IMPL_NOTES.md 10.2)
MONITORS = ("direct", "copy")
GRAN_W = {"second": 1, "minute": 60, "hour": 3600}


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


def cp_ci(k, n):
    return EV.cp(k, n) if n else None


# ------------------------------------------------------------------------------------------------ verifier capabilities
def verify_options():
    """The options this e7_verify accepts (part A may add marker, operator-key, keep-days and name-map options)."""
    return set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', open(E7_VERIFY).read()))


# Part A's E9 verifier options (exp/stages/e7_verify.py): the operator's public key (only operator-signed markers count),
# the retention policy and PURGE tolerance (scoped cutoffs and the purge-disconnect rule A1), RESTORE markers with a commit
# lag tolerance, the name-map storage (the current name map against the last anchored digest), and --no-rowbind (the
# suspects without the per-row binding, for comparison). Passed only when the verifier has them.
RESTORE_TOL_S = float(os.environ.get("E9_RESTORE_TOL_S", "30"))
RESTORE_MAX_AGE_S = float(os.environ.get("E9_RESTORE_MAX_AGE_S", "86400"))
RESTORE_DONE_MAX_S = float(os.environ.get("E9_RESTORE_DONE_MAX_S", "600"))


def e9_args(sp, opts, keep_days, storage_dir):
    args, used = [], {}
    pub = os.path.join(sp, "keys", "operator_sign_pub.pem")
    if "--operator-pubkey" in opts and os.path.exists(pub):
        args += ["--operator-pubkey", pub]
        used["operator_pubkey"] = os.path.relpath(pub, sp)
    if "--purge-keep-s" in opts:
        args += ["--purge-keep-s", str(keep_days * 86400.0), "--purge-tol-s", str(TOL_S)]
        used["purge_keep_s"], used["purge_tol_s"] = keep_days * 86400.0, TOL_S
    if "--restore-tol-s" in opts:
        args += ["--restore-tol-s", str(RESTORE_TOL_S)]
        used["restore_tol_s"] = RESTORE_TOL_S
    if "--restore-max-age-s" in opts:
        args += ["--restore-max-age-s", str(RESTORE_MAX_AGE_S)]
        used["restore_max_age_s"] = RESTORE_MAX_AGE_S
    if "--restore-done-max-s" in opts:            # review N1: a RESTORE excuses nothing without its RESTORE_DONE
        args += ["--restore-done-max-s", str(RESTORE_DONE_MAX_S)]
        used["restore_done_max_s"] = RESTORE_DONE_MAX_S
    nm = []
    if "--namemap-storage" in opts and storage_dir and os.path.isdir(storage_dir):
        # the storage is the name map at the END of the run: given to the last day's verification only (an earlier
        # day's snapshot predates later declared changes, whose markers that verification rejects as after_snapshot)
        nm = ["--namemap-storage", storage_dir]
        used["namemap_storage_last_day"] = os.path.relpath(storage_dir, sp)
    extra = shlex.split(os.environ.get("E9_VERIFY_ARGS", ""))
    return args + extra, dict(used, extra=extra), nm


def verify_job(sp, m, label, db, tsnap, window, trials, extra):
    os.makedirs(os.path.join(sp, "verify"), exist_ok=True)
    # the cache is keyed on everything that changes the verdict: arguments, window, snapshot, verifier code
    key = hashlib.sha256(json.dumps([extra, window, tsnap, sha(db), sha(E7_VERIFY),
                                     sorted(os.path.basename(t) for t in trials or [])]).encode()).hexdigest()[:12]
    dst = os.path.join(sp, "verify", "%s_%s_%s.json" % (m, label, key))
    if os.path.exists(dst):
        try:
            return m, label, json.load(open(dst)), True
        except ValueError:
            os.rename(dst, dst + ".bad.%d" % int(time.time()))
    cmd = [sys.executable, E7_VERIFY, "verify", "--chain", os.path.join(sp, "%s_chain.jsonl" % m), "--db", db,
           "--late-bound", str(LATE_BOUND), "--gap-s", str(GAP_S), "--snapshot-at", str(tsnap), "--scheme", "stable",
           "--window", str(window[0]), str(window[1]), "--out", dst,
           "--sign-pubkey", os.path.join(sp, "keys", "%s_sign_pub.pem" % m)]
    esc = os.path.join(sp, "escrow_%s" % m, "escrow.jsonl")
    if os.path.exists(esc) and os.path.getsize(esc) > 0:
        cmd += ["--escrow", esc]
    if trials:
        cmd += ["--trials", *trials]
    cmd += extra
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dst):
        return m, label, {"error": "e7_verify failed", "rc": r.returncode, "stderr": r.stderr[-3000:],
                          "cmd": " ".join(cmd)}, False
    out = json.load(open(dst))
    out.setdefault("_e9", {})["verify_wall_s"] = round(time.time() - t0, 1)
    return m, label, out, False


# ------------------------------------------------------------------------------------------------ inputs
class Run:
    def __init__(self, sp, tag, out):
        self.sp, self.tag, self.out = sp, tag, out
        self.schedule = json.load(open(os.path.join(sp, "schedule.json")))
        self.events = jl(os.path.join(sp, "events.jsonl"))
        self.hostlog = jl(os.path.join(sp, "hostlog.jsonl"))
        self.snaps = {e["label"]: e for e in self.events if e.get("type") == "snapshot" and e.get("ok")}
        self.days = [e for e in self.schedule["events"] if e["type"] == "day_end"]
        self.start = self.schedule["start"]
        self.meta = [l.rstrip("\n") for l in open(os.path.join(sp, "auth_meta.log"))] \
            if os.path.exists(os.path.join(sp, "auth_meta.log")) else []

    def snap(self, label):
        e = self.snaps.get(label)
        if not e:
            return None, None
        p = os.path.join(self.sp, e["file"])
        return (p, e["t_snapshot"]) if os.path.exists(p) else (None, None)

    def day_reports(self, d):
        return sorted(glob.glob(os.path.join(self.out, "%s_d%d_report_*.json" % (self.tag, d))))


def load_trials(files):
    out = []
    for f in files:
        dd = json.load(open(f))
        for t in dd.get("trials", []):
            out.append(dict(t, _file=os.path.basename(f)))
    return out


# ------------------------------------------------------------------------------------------------ markers
def chain_markers(recs, sp):
    """Operator markers on a chain; with the operator's public key, only those whose operator signature verifies."""
    path = os.path.join(ROOT, "exp", "rig", "marker_issuer.py")
    spec = importlib.util.spec_from_file_location("e9s_marker_issuer", path)
    MI = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MI)
    pub_p = os.path.join(sp, "keys", "operator_sign_pub.pem")
    kinds = ("PURGE", "RESTORE", "RESTORE_DONE", "RENAME", "NAMEMAP_CHANGE", "MIGRATE")
    allm = MI.markers_from_chain(recs, None, kinds=kinds)
    signed = None
    if os.path.exists(pub_p) and hasattr(MI, "load_pubkey"):
        try:
            signed = MI.markers_from_chain(recs, None, kinds=kinds, pubkey=MI.load_pubkey(pub_p))
        except Exception as exc:                          # noqa: BLE001
            signed = {"error": repr(exc)[:200]}
    ok_seqs = {m["seq"] for m in signed} if isinstance(signed, list) else None
    for m in allm:
        m["operator_signature_ok"] = (m["seq"] in ok_seqs) if ok_seqs is not None else None
    return allm


def purge_cutoffs(markers):
    """(cutoff, scheduled_ts, recv_ts) of every signed PURGE marker anchored before its scheduled purge."""
    out = []
    for m in markers:
        if m.get("marker") != "PURGE" or m.get("operator_signature_ok") is False:
            continue
        c = RM.scoped_cutoff(m, float(m.get("keep_s", 0.0)), TOL_S)
        if c is not None and m.get("recv_ts") is not None and float(m["recv_ts"]) < float(m["scheduled_ts"]):
            out.append((c, float(m["scheduled_ts"]), float(m["recv_ts"])))
    return out


def restore_ranges(markers, events):
    """(restore_point_ts, end_ts, backup_wm) of every signed RESTORE marker anchored before the hub restart that ran it."""
    starts = [e for e in events if e.get("type") == "hub_restart" and str(e.get("cause", "")).startswith("restore")]
    out = []
    for m in markers:
        if m.get("marker") != "RESTORE" or m.get("operator_signature_ok") is False:
            continue
        after = [e for e in starts if e["ts"] >= float(m.get("recv_ts") or 0)]
        end = after[0]["ts"] if after else None
        out.append((float(m["restore_point_ts"]), end, m.get("backup_wm") or {}))
    return out


# ------------------------------------------------------------------------------------------------ RESTORE_DONE check
def restore_done_check(markers, run):
    """Every anchored, operator-signed RESTORE_DONE (pre-registered rule, review re-check 2): it must carry hub_started_ts
    H and a post_restart_wm consistent with the restored recorder the run observed afterwards (the first recorder
    snapshot taken after the RESTORE_DONE was anchored): post_restart_wm >= the RESTORE marker's signed backup_wm in each
    table, the snapshot holds the keys up to post_restart_wm, and every row with a key above backup_wm was written at
    or after H. A RESTORE_DONE lacking H, or failing a check, is INVALID, and the restore it closes counts as not
    excused. Also the time from the RESTORE marker's issued_ts to the RESTORE_DONE's anchoring (recv_ts)."""
    restores = {m.get("nonce"): m for m in markers if m.get("marker") == "RESTORE"}
    out = []
    for d in (m for m in markers if m.get("marker") == "RESTORE_DONE"):
        why = []
        r = restores.get(d.get("restore_nonce"))
        h, wm = d.get("hub_started_ts"), d.get("post_restart_wm") or {}
        bw = (r or {}).get("backup_wm") or {}
        if d.get("operator_signature_ok") is False:
            why.append("operator_signature_invalid")
        if r is None:
            why.append("names_no_restore_marker_on_the_chain")
        if h is None:
            why.append("no_hub_started_ts")
        if not all(isinstance(wm.get(t), int) for t in ("states", "events")):
            why.append("no_post_restart_wm")
        if not all(isinstance(bw.get(t), int) for t in ("states", "events")):
            why.append("restore_marker_without_backup_wm")
        row = {"chain_seq": d.get("seq"), "restore_nonce": d.get("restore_nonce"), "hub_started_ts": h,
               "post_restart_wm": wm, "backup_wm": bw,
               "restore_issued_ts": (r or {}).get("issued_ts"), "done_recv_ts": d.get("recv_ts"),
               "restore_to_done_anchored_s": (round(float(d["recv_ts"]) - float(r["issued_ts"]), 3)
                                              if r and d.get("recv_ts") is not None else None)}
        snap = None
        if d.get("recv_ts") is not None:
            later = sorted((e["t_snapshot"], e["label"]) for e in run.snaps.values() if e["t_snapshot"] > float(d["recv_ts"]))
            snap = run.snap(later[0][1])[0] if later else None
            row["checked_against_snapshot"] = later[0][1] if later else None
        if snap and not why:
            c = sqlite3.connect("file:%s?mode=ro" % snap, uri=True)
            for t, key, ts in (("states", "state_id", "last_updated_ts"), ("events", "event_id", "time_fired_ts")):
                if wm[t] < bw[t]:
                    why.append("post_restart_wm_below_backup_wm:%s" % t)
                mx = c.execute("SELECT max(%s) FROM %s" % (key, t)).fetchone()[0] or 0
                if mx < wm[t]:
                    why.append("recorder_lacks_keys_up_to_post_restart_wm:%s" % t)
                n_before_h = c.execute("SELECT count(*) FROM %s WHERE %s > ? AND NOT (%s >= ?)" % (t, key, ts),
                                       (bw[t], float(h))).fetchone()[0]
                row["rows_above_backup_wm_before_H_" + t] = n_before_h
                if n_before_h:
                    why.append("rows_above_backup_wm_written_before_H:%s" % t)
            c.close()
        elif not snap:
            why.append("no_snapshot_after_the_restore_done")
        row["valid"] = not why
        row["why_invalid"] = why
        out.append(row)
    return out


# ------------------------------------------------------------------------------------------------ classification
def _db_lookup(db):
    if not db or not os.path.exists(db):
        return None
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)

    def f(state_id):
        r = c.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (state_id,)).fetchone()
        return r[0] if r else None
    return f


def _disconnect_only(entry):
    """A recovery entry of one second: every change is old_state_id -> NULL on a state row, nothing added or removed.
    Returns the original predecessors, or None."""
    if not entry or entry.get("added") or entry.get("removed"):
        return None
    preds = []
    for ch in entry.get("changed") or []:
        o = ((ch.get("original") or {}).get("columns") or {})
        c = ((ch.get("current") or {}).get("columns") or {})
        if not str(ch.get("key", "")).startswith("s:"):
            return None
        diff = {k for k in set(o) | set(c) if o.get(k) != c.get(k)}
        if diff != {"old_state_id"} or c.get("old_state_id") is not None or not isinstance(o.get("old_state_id"), int):
            return None
        preds.append(o["old_state_id"])
    return preds or None


def classify(v, markers, events, db_now, db_pre=None):
    """PROVISIONAL harness-side classification of the attributable violations and keylog violations of one verify output."""
    cuts = purge_cutoffs(markers)
    rest = restore_ranges(markers, events)
    now_ts, pre_ts = _db_lookup(db_now), _db_lookup(db_pre)
    rec_secs = {}
    for e in ((v.get("recovery") or {}).get("seconds") or []):
        s = e.get("second", e.get("seg"))
        if s is not None:
            rec_secs[str(s)] = e

    def is_disconnect(sec):
        preds = _disconnect_only(rec_secs.get(str(sec)))
        if not preds or not cuts:
            return False
        for p in preds:
            if now_ts and now_ts(p) is not None:
                return False                                  # the predecessor still exists: not a purge
            t = pre_ts(p) if pre_ts else None
            if t is not None and not any(t < c for c, _s, _r in cuts):
                return False
        return True

    def in_restore(lo, hi):
        return any(lo >= rp and (end is None or lo < end) for rp, end, _wm in rest)

    out = collections.defaultdict(list)
    for x in v.get("violations") or []:
        if not x.get("attributable"):
            continue
        g, seg = x["gran"], int(x["seg"])
        w = GRAN_W.get(g, 1)
        lo, hi = seg * w, seg * w + w
        mech = x.get("mechanism")
        if mech == "sealed_rows_removed":
            vv = {"why": "SEGMENT_GONE" if not x.get("n_sealed_now") else "COUNT", "was": x.get("anchored_n", 0),
                  "now": x.get("n_sealed_now", 0)}
        else:
            vv = {"why": "ACC"}
        row = {"gran": g, "seg": str(seg), "mechanism": mech}
        if vv["why"] != "ACC" and any(RM.explains_scoped(c, vv, lo, hi) for c, _s, _r in cuts):
            out["purge_scoped"].append(row)
        elif g == "second" and is_disconnect(seg):
            out["purge_disconnect"].append(dict(row, rows=len((rec_secs.get(str(seg)) or {}).get("changed") or [])))
        elif g != "second" and x.get("explained_by_flagged_seconds") and all(
                is_disconnect(s) for s in x["explained_by_flagged_seconds"]):
            out["purge_disconnect"].append(row)
        elif in_restore(lo, hi):
            out["restore"].append(row)
        else:
            out["unexcused"].append(row)
    kl = collections.defaultdict(list)
    for kv in v.get("keylog_violations") or []:
        t = "states" if any(str(s.get("key", "")).startswith("s:") for s in (kv.get("suspects") or [])) else "events"
        rng = kv.get("range") or [None, None]
        secs = [int(s) for s in kv.get("seconds") or []]
        row = {"range": rng, "table_guess": t, "n_seconds": len(secs)}
        if rng[0] is not None and any(int(rng[0]) >= int((wm or {}).get(t) or 10 ** 18) for _rp, _e, wm in rest):
            kl["restore"].append(row)
        elif secs and all(is_disconnect(s) for s in secs if str(s) in rec_secs) and any(str(s) in rec_secs for s in secs):
            kl["purge_disconnect"].append(row)
        elif secs and cuts and kv.get("removed") and not kv.get("changed") and not kv.get("added") and all(
                s < max(c for c, _s, _r in cuts) for s in secs):
            kl["purge_scoped"].append(row)
        else:
            kl["unexcused"].append(row)
    return {"segments": {k: {"n": len(v_), "by_granularity": dict(collections.Counter(r["gran"] for r in v_)),
                             "first": v_[:20]} for k, v_ in out.items()},
            "keylog": {k: {"n": len(v_), "first": v_[:10]} for k, v_ in kl.items()},
            "purge_cutoffs": [{"cutoff": c, "scheduled_ts": s, "marker_recv_ts": r} for c, s, r in cuts],
            "restore_ranges": [{"restore_point_ts": rp, "end_ts": e, "backup_wm": wm} for rp, e, wm in rest],
            "label": "PROVISIONAL harness-side classification (exp/stages/e9_score.py classify); the verifier's own "
                     "verdicts, when present, are under 'verifier'"}, out, kl


def verifier_marker_fields(v):
    """Whatever the verifier itself reports about markers, purge disconnects, restore and the name map (part A)."""
    keys = [k for k in v if any(w in k for w in ("marker", "purge", "excus", "restore", "namemap", "rowbind", "binding"))]
    return {k: v[k] for k in keys} or None


def floor(v, window, touched, cls_out):
    """Unexcused attributable violations on untouched segments, per granularity (second, minute, hour)."""
    exc = {(r["gran"], r["seg"]) for k in ("purge_scoped", "purge_disconnect", "restore") for r in cls_out.get(k, [])}
    t0, t1 = window
    res = {}
    for g, w in GRAN_W.items():
        bad = []
        for x in v.get("violations") or []:
            if x["gran"] != g or not x.get("attributable"):
                continue
            seg = int(x["seg"])
            lo = seg * w
            if not (t0 - w <= lo < t1 + 1) or (g, str(seg)) in exc:
                continue
            if any(s in touched for s in range(lo, lo + w)):
                continue
            bad.append(str(seg))
        res[g] = {"unexcused_untouched": len(bad), "segments": bad[:50]}
    rows = [r for r in v.get("attributable_rows") or [] if r.get("second") is not None
            and t0 <= int(r["second"]) < t1 and int(r["second"]) not in touched and ("second", str(r["second"])) not in exc]
    res["second"]["untouched_seconds_with_an_attributable_row"] = len({r["second"] for r in rows})
    bf = v.get("benign_floor") or {}
    res["untouched_anchored"] = {"second": bf.get("untouched_anchored_seconds"),
                                 "minute": (bf.get("minute") or {}).get("untouched_anchored"),
                                 "hour": (bf.get("hour") or {}).get("untouched_anchored")}
    res["e7_verify_benign_floor"] = {"violated": bf.get("violated"), "violated_ci": bf.get("violated_ci"),
                                     "minute_attributable": (bf.get("minute") or {}).get("attributable"),
                                     "hour_attributable": (bf.get("hour") or {}).get("attributable")}
    return res


def verifier_excused(v, window):
    """The verifier's own excusals (part A): violations it moved to excused_violations, by marker and rule, those in the
    window; the purge-disconnect rows and seconds; RESTORE excusals; keylog ranges excused."""
    t0, t1 = window
    inw = lambda x: t0 - GRAN_W.get(x.get("gran"), 1) <= int(x["seg"]) * GRAN_W.get(x.get("gran"), 1) < t1 + 1
    ex = [x for x in v.get("excused_violations") or [] if "seg" in x and inw(x)]
    by = collections.Counter("%s:%s:%s" % ((x.get("excused_by") or {}).get("marker"), (x.get("excused_by") or {}).get("rule"),
                                           x.get("gran")) for x in ex)
    pr = v.get("purge") or {}
    dis = [d for d in pr.get("disconnected_rows") or [] if d.get("second") is not None and t0 <= int(d["second"]) < t1]
    return {"source": "verifier (exp/stages/e7_verify.py, operator-signed markers)", "segments_by_marker_rule": dict(by),
            "purge_disconnect": {"rows": len(dis), "seconds": len({d["second"] for d in dis}),
                                 "rows_whole_chain": (pr.get("disconnects") or {}).get("n_rows"),
                                 "seconds_whole_chain": (pr.get("disconnects") or {}).get("n_seconds")},
            "purge_report": {k: pr.get(k) for k in ("cutoffs", "disconnect_rule", "excused")},
            "restore_report": {k: (v.get("restore") or {}).get(k) for k in ("restores", "excused")},
            "keylog_ranges_excused": len(v.get("excused_keylog_violations") or []),
            "markers": {k: (v.get("markers") or {}).get(k) for k in ("checked", "accepted", "rejected", "marker_records")}}


def scoped_suspects(v, window, touched, excused_secs):
    """Untouched suspect seconds of the window: every second a failed keylog range's suspects sit in or sat in (with the
    per-row binding the verifier lists only the rows that differ; with --no-rowbind it ranks them by 32-bit prefixes and
    lists the range's rows), plus the keylog suspect rows in those seconds."""
    if not isinstance(v, dict):
        return None
    t0, t1 = window
    secs, rows = set(), set()
    for kv in v.get("keylog_violations") or []:
        for s_ in kv.get("seconds") or []:
            s_ = int(s_)
            if t0 - 1 <= s_ <= t1 + 1 and s_ not in touched and str(s_) not in excused_secs:
                secs.add(s_)
        for r in kv.get("suspects") or []:
            if any(r.get(f) is not None and int(r[f]) in secs for f in ("second", "first_observed_second")):
                rows.add(r.get("key"))
    return {"n_seconds": len(secs), "seconds": sorted(secs)[:100], "n_suspect_rows": len(rows),
            "keylog_violations": len(v.get("keylog_violations") or []),
            "rowbind": (v.get("params") or {}).get("rowbind", True)}


# ------------------------------------------------------------------------------------------------ name map
def namemap_transitions(recs, markers, window=None):
    """Digest transitions on a chain, each with its changed parts and the operator RENAME (or NAMEMAP_CHANGE) marker
    anchored before it whose part digests equal the new ones; a transition without one is unexcused (detected)."""
    out, prev = [], None
    for r in recs:
        p = r.get("payload") or {}
        if p.get("observer") != "external-monitor":
            continue
        nm = p.get("namemap")
        if not isinstance(nm, dict) or "digest" not in nm:
            continue
        if prev is not None and nm["digest"] != prev["digest"]:
            changed = sorted(k for k in nm.get("parts", {}) if (nm["parts"][k] or {}).get("digest")
                             != ((prev.get("parts") or {}).get(k) or {}).get("digest"))
            new = {k: nm["parts"][k]["digest"] for k in changed}
            hit = [m for m in markers if m.get("marker") in ("RENAME", "NAMEMAP_CHANGE")
                   and m.get("operator_signature_ok") is not False and (m.get("seq") or 0) < (r.get("seq") or 0)
                   and all((m.get("parts") or {}).get(k) == d for k, d in new.items())]
            ts = p.get("ts")
            if window is None or (ts is not None and window[0] <= ts < window[1]):
                out.append({"chain_seq": r.get("seq"), "ts": ts, "changed_parts": changed,
                            "excused_by_marker_seq": hit[0]["seq"] if hit else None,
                            "marker_step": (hit[0].get("step") if hit else None), "outcome": "excused" if hit else "unexcused"})
        prev = nm
    return out


# ------------------------------------------------------------------------------------------------ cost, bytes, host
def cost(path, windows):
    rows = jl(path)
    out = {"available": bool(rows), "n_polls_total": len(rows)}
    for name, (a, b) in windows.items():
        sel = [r for r in rows if r.get("ts") is not None and a <= float(r["ts"]) < b]
        cols = collections.defaultdict(list)
        reads = collections.Counter()
        for r in sel:
            c, l, m, ap = (r.get("copy_ms") or 0), (r.get("load_ms") or 0), (r.get("commit_ms") or 0), r.get("append_ms")
            for k in ("copy_ms", "load_ms", "commit_ms", "read_ms", "snapshot_ms", "quick_check_ms"):
                if r.get(k) is not None:
                    cols[k].append(r[k])
            if ap is not None:
                cols["append_ms"].append(ap)
            cols["total_ms"].append(c + l + m + (ap or 0))
            reads[str(r.get("read", "copy"))] += 1
        out[name] = {"n_polls": len(sel), "failed_appends": sum(1 for r in sel if r.get("ok") is False),
                     "unobservable": sum(1 for r in sel if r.get("evidence_unobservable")),
                     "read_path": dict(reads), "per_poll_ms": {k: E8.dist(v) for k, v in cols.items()}}
    return out


def quick_check_every(run, m):
    """The monitor's pre-registered HOMEPROV_QUICK_CHECK_EVERY: from the run script (E9_QC_DIRECT / E9_QC_COPY), else its
    configuration log line ("monitor env: direct=[...] copy=[...]"), else 1 (the monitor's default)."""
    v = os.environ.get("E9_QC_%s" % m.upper())
    if v:
        return int(v)
    for l in run.meta:
        if "monitor env:" in l:
            seg = l.split("%s=[" % m, 1)[-1].split("]", 1)[0]
            hit = re.search(r"HOMEPROV_QUICK_CHECK_EVERY=(\d+)", seg)
            if hit:
                return int(hit.group(1))
    return 1


def quick_check_report(recs, cost_path, n_every, windows):
    """quick_check per monitor and window: the polls at which it was due (seq_local % N == 1, or every poll for N = 1,
    the monitor's own rule), the per-poll cost of those polls against the others (copy_ms holds the copy or the direct
    snapshot with its checks, quick_check included when due), and the polls the monitor itself reported unobservable,
    by reason, from its signed records (quick_check_failed among them; read_raced, after_read, direct_open_failed and the
    file checks for direct reads)."""
    rows = jl(cost_path)
    due = (lambda q: True) if n_every == 1 else (lambda q: int(q) % n_every == 1)
    unobs = []
    for r in recs:
        p = r.get("payload") or {}
        if p.get("observer") == "external-monitor" and p.get("evidence_unobservable") and not p.get("part"):
            unobs.append((p.get("ts") or r.get("recv_ts") or 0, str(p.get("reason")), (p.get("detail") or {})))
    out = {"quick_check_every": n_every}
    for name, (a, b) in windows.items():
        sel = [r for r in rows if r.get("ts") is not None and a <= float(r["ts"]) < b and r.get("seq_local") is not None]
        d = [r for r in sel if due(r["seq_local"])]
        nd = [r for r in sel if not due(r["seq_local"])]
        tot = lambda r: (r.get("copy_ms") or 0) + (r.get("load_ms") or 0) + (r.get("commit_ms") or 0) + (r.get("append_ms") or 0)
        u = [x for x in unobs if a <= x[0] < b]
        out[name] = {"polls": len(sel), "quick_check_due": len(d),
                     "copy_or_snapshot_ms_due": E8.dist([r.get("copy_ms") or 0 for r in d]),
                     "copy_or_snapshot_ms_not_due": E8.dist([r.get("copy_ms") or 0 for r in nd]),
                     "total_ms_due": E8.dist([tot(r) for r in d]), "total_ms_not_due": E8.dist([tot(r) for r in nd]),
                     "unobservable_polls": len(u), "unobservable_by_reason": dict(collections.Counter(x[1] for x in u)),
                     "quick_check_failed": sum(1 for x in u if x[1] == "quick_check_failed"),
                     "quick_check_failed_details": [x[2] for x in u if x[1] == "quick_check_failed"][:10]}
    return out


def io_bytes(hostlog, container, windows):
    """Bytes read and written by the monitor process (/proc/1/io: rchar/wchar through system calls, read_bytes/write_bytes
    at the block layer) per window, summed over increasing runs (a counter reset after a container restart is noted)."""
    samp = [(r["ts"], r.get("io_" + container)) for r in hostlog if r.get("kind") == "sample" and r.get("io_" + container)]
    out = {}
    for name, (a, b) in windows.items():
        sel = [(t, x) for t, x in samp if a <= t < b]
        tot, resets = collections.Counter(), 0
        for (t0, x0), (t1, x1) in zip(sel, sel[1:]):
            for k in ("rchar", "wchar", "read_bytes", "write_bytes"):
                d = (x1.get(k) or 0) - (x0.get(k) or 0)
                if d < 0:
                    resets += 1
                    d = x1.get(k) or 0
                tot[k] += d
        out[name] = {"samples": len(sel), "bytes": dict(tot), "counter_resets": resets,
                     "span_s": round(sel[-1][0] - sel[0][0], 1) if len(sel) > 1 else 0}
    return out


def host(run, windows):
    hl = run.hostlog
    out = {}
    starts = [r for r in hl if r.get("kind") == "hub_state"]
    restarts = [e for e in run.events if e.get("type") == "hub_restart"]
    for name, (a, b) in windows.items():
        gaps = [r for r in hl if r.get("kind") == "wall_gap" and a <= r["ts"] < b]
        vm = [(r["ts"], r["vm_offset"]) for r in hl if r.get("kind") == "sample" and r.get("vm_offset") is not None and a <= r["ts"] < b]
        jumps = [{"utc": E8_iso(t1), "jump_s": round(o1 - o0, 3)} for (t0, o0), (t1, o1) in zip(vm, vm[1:]) if abs(o1 - o0) > 5]
        pw = [r.get("power") or {} for r in hl if r.get("kind") == "sample" and a <= r["ts"] < b]
        hs = []
        for s in starts:
            if not (a <= s["ts"] < b) or not s.get("previous_started_at"):
                continue
            cause = next((e.get("cause") for e in restarts if e.get("started_at") == s.get("started_at")),
                         "not started by the harness")
            hs.append({"utc": s["utc"], "started_at": s.get("started_at"), "status": s.get("status"), "cause": cause})
        pm = [r for f in glob.glob(os.path.join(run.sp, "pmset_day*.jsonl")) for r in jl(f) if a <= r.get("ts", 0) < b]
        seen = set()
        pm = [r for r in pm if not (r["utc"] + r["event"] in seen or seen.add(r["utc"] + r["event"]))]
        out[name] = {"wall_gaps": [{"since_utc": g.get("since_utc"), "gap_s": g.get("gap_s")} for g in gaps],
                     "pmset_sleep_entries": [r for r in pm if r["event"] == "Sleep"],
                     "pmset_wake_entries": len([r for r in pm if r["event"] in ("Wake", "DarkWake")]),
                     "vm_offset_jumps": jumps, "hub_starts": hs,
                     "on_battery_samples": sum(1 for p in pw if p.get("source") and "AC" not in p["source"]),
                     "lid_closed_samples": sum(1 for p in pw if p.get("lid_closed")), "power_samples": len(pw)}
    return out


def E8_iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


# ------------------------------------------------------------------------------------------------ purge evidence (DB)
def purge_evidence(pre, post, cutoff):
    def q(db, s, a=()):
        c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
        try:
            return c.execute(s, a).fetchall()
        finally:
            c.close()
    ev = {}
    for name, db in (("pre", pre), ("post", post)):
        ev[name] = {"states_older_than_cutoff": q(db, "select count(*) from states where last_updated_ts<?", (cutoff,))[0][0],
                    "events_older_than_cutoff": q(db, "select count(*) from events where time_fired_ts<?", (cutoff,))[0][0],
                    "oldest_state": q(db, "select min(last_updated_ts) from states")[0][0],
                    "statistics_runs_min_start": q(db, "select min(start) from statistics_runs")[0][0],
                    "recorder_runs": q(db, "select count(*), min(run_id) from recorder_runs")[0]}
    # retained state rows whose old_state_id the purge set to NULL (recorder/purge.py _purge_state_ids)
    c = sqlite3.connect("file:%s?mode=ro" % post, uri=True)
    c.execute("ATTACH DATABASE ? AS pre", ("file:%s?mode=ro" % pre,))
    rows = c.execute("""SELECT p.state_id, p.last_updated_ts, b.old_state_id, ob.last_updated_ts
                        FROM states p JOIN pre.states b ON b.state_id = p.state_id
                        LEFT JOIN pre.states ob ON ob.state_id = b.old_state_id
                        WHERE p.old_state_id IS NULL AND b.old_state_id IS NOT NULL""").fetchall()
    gone = {r[0] for r in c.execute("SELECT b.state_id FROM pre.states b WHERE b.state_id IN (%s) AND NOT EXISTS "
                                    "(SELECT 1 FROM main.states s WHERE s.state_id=b.state_id)" % ",".join(
                                        str(r[2]) for r in rows) if rows else "SELECT 1 WHERE 0")}
    c.close()
    disc = [{"state_id": r[0], "ts": r[1], "predecessor": r[2], "predecessor_ts": r[3], "predecessor_gone": r[2] in gone}
            for r in rows]
    secs = sorted({int(r["ts"]) for r in disc})
    ev["disconnected"] = {"rows": len(disc), "seconds": len(secs),
                          "rows_more_than_1h_after_cutoff": sum(1 for r in disc if r["ts"] > cutoff + 3600),
                          "predecessor_gone_and_older_than_cutoff": sum(1 for r in disc if r["predecessor_gone"]
                                                                        and r["predecessor_ts"] is not None
                                                                        and r["predecessor_ts"] < cutoff),
                          "first": disc[:20]}
    ev["ran"] = (ev["post"]["states_older_than_cutoff"] == 0 and ev["pre"]["states_older_than_cutoff"] > 0) or \
        ev["post"]["statistics_runs_min_start"] != ev["pre"]["statistics_runs_min_start"]
    return ev


def new_violations(v_pre, v_post):
    k = lambda x: (x["gran"], x["seg"], x.get("mechanism"))
    pre = {k(x) for x in v_pre.get("violations") or [] if x.get("attributable")}
    new = [x for x in v_post.get("violations") or [] if x.get("attributable") and k(x) not in pre]
    kpre = {tuple(kv.get("range") or ()) for kv in v_pre.get("keylog_violations") or []}
    knew = [kv for kv in v_post.get("keylog_violations") or [] if tuple(kv.get("range") or ()) not in kpre]
    return dict(v_post, violations=new, keylog_violations=knew)


# ------------------------------------------------------------------------------------------------ seal coverage
def seal_coverage(recs, db, t_start):
    sealed = set()
    for r in recs:
        p = r.get("payload") or {}
        if p.get("observer") != "external-monitor":
            continue
        for s in ((p.get("sealed") or {}).get("second") or {}):
            sealed.add(int(s))
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    rows = set()
    for (s,) in c.execute("SELECT DISTINCT CAST(last_updated_ts AS INTEGER) FROM states WHERE typeof(last_updated_ts)"
                          " IN ('real','integer')"):
        rows.add(int(s))
    for (s,) in c.execute("SELECT DISTINCT CAST(time_fired_ts AS INTEGER) FROM events WHERE typeof(time_fired_ts)"
                          " IN ('real','integer')"):
        rows.add(int(s))
    c.close()
    rows = {s for s in rows if s < t_start}
    miss = sorted(rows - sealed)
    return {"seconds_with_a_row_before_start": len(rows), "of_which_sealed": len(rows) - len(miss),
            "unsealed": len(miss), "oldest_row_second": min(rows) if rows else None,
            "oldest_sealed_second": min(sealed) if sealed else None, "first_unsealed": miss[:20],
            "unsealed_by_day": dict(collections.Counter(time.strftime("%Y-%m-%d", time.gmtime(s)) for s in miss))}


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "exp", "out"))
    ap.add_argument("--keep-days", type=int, default=30)
    ap.add_argument("--jobs", type=int, default=int(os.environ.get("E9_VERIFY_JOBS", "2")))
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = Run(a.run_dir, a.tag, a.out_dir)
    dst = os.path.join(a.out_dir, "%s_score.json" % a.tag)
    if os.path.exists(dst) and not a.overwrite:
        raise SystemExit("REFUSING: %s exists" % dst)
    opts = verify_options()
    storage_dir = os.path.join(a.run_dir, "namemap_storage")       # display fields only (run_e9.sh freeze)
    extra, used, nm_args = e9_args(a.run_dir, opts, a.keep_days, storage_dir)
    norb = ["--no-rowbind"] if "--no-rowbind" in opts else None
    print("== E9 score %s: %d days, monitors %s; verifier E9 options used: %s" % (a.tag, len(run.days), MONITORS, used),
          flush=True)

    # ---- the verify jobs: each day against its end-of-day snapshot; each night pre/post over the historical window
    jobs, windows = [], {}
    t_start_snap = run.snap("start")
    hist_lo = None
    if t_start_snap[0]:
        c = sqlite3.connect("file:%s?mode=ro" % t_start_snap[0], uri=True)
        hist_lo = min(x for x in (c.execute("select min(last_updated_ts) from states").fetchone()[0],
                                  c.execute("select min(time_fired_ts) from events").fetchone()[0]) if x is not None)
        c.close()
    for d in run.days:
        n = d["day"]
        db, ts = run.snap("day%d_end" % n)
        windows["day%d" % n] = tuple(d["window"])
        last = n == run.days[-1]["day"]
        if db:
            for m in MONITORS:
                jobs.append((a.run_dir, m, "day%d" % n, db, ts, d["window"], run.day_reports(n),
                             extra + (nm_args if last else [])))
                if norb:
                    jobs.append((a.run_dir, m, "day%d_norowbind" % n, db, ts, d["window"], run.day_reports(n), extra + norb))
        for lab in ("night%d_pre" % n, "night%d_post" % n):
            db, ts = run.snap(lab)
            if db and hist_lo is not None:
                for m in MONITORS:
                    jobs.append((a.run_dir, m, lab, db, ts, [int(hist_lo) - 3600, run.start], [], extra))
                    if lab.endswith("_post") and "--no-purge-disconnect" in opts:
                        # the round-12 retention-scoped rule alone (no purge-disconnect rule), for comparison
                        jobs.append((a.run_dir, m, lab + "_nodisconnect", db, ts, [int(hist_lo) - 3600, run.start], [],
                                     extra + ["--no-purge-disconnect"]))
    V = collections.defaultdict(dict)
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for m, lab, out, cached in ex.map(lambda j: verify_job(*j), jobs):
            V[m][lab] = out
            print("  e7_verify %-6s %-12s %s" % (m, lab, "cached" if cached else
                                                  ("ERROR " + out.get("stderr", "")[-300:] if "error" in out else
                                                   "ok (%ss)" % out.get("_e9", {}).get("verify_wall_s"))), flush=True)
    print("  verify wall time %.0f s" % (time.time() - t0), flush=True)

    chains = {m: E8.read_chain(os.path.join(a.run_dir, "%s_chain.jsonl" % m)) for m in MONITORS
              if os.path.exists(os.path.join(a.run_dir, "%s_chain.jsonl" % m))}
    mk = {m: chain_markers(recs, a.run_dir) for m, recs in chains.items()}
    rd_checks = {m: restore_done_check(mk[m], run) for m in mk}
    whole = (run.start, run.days[-1]["window"][1]) if run.days else None
    res = {"experiment": "E9 (round 13): the deployed configuration for seven days on the lab installation",
           "tag": a.tag, "mode": run.schedule.get("mode"), "start_utc": run.schedule.get("start_utc"),
           "pre_registered_parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "purge_tol_s": TOL_S,
                                         "restore_tol_s": RESTORE_TOL_S, "restore_max_age_s": RESTORE_MAX_AGE_S,
                                         "restore_done_max_s": RESTORE_DONE_MAX_S,
                                         "keep_days": a.keep_days},
           "verifier": {"path": os.path.relpath(E7_VERIFY, ROOT), "sha256": sha(E7_VERIFY), "e9_options_used": used,
                        "jobs": a.jobs, "purge_seen_slack_s": next((
                            (vv.get("params") or {}).get("purge_seen_slack_s") for mm in V.values() for vv in mm.values()
                            if isinstance(vv, dict) and (vv.get("params") or {}).get("purge_seen_slack_s") is not None), None)},
           "days": {}, "nights": {}, "monitors": {}, "events": {}, "generated_at": E8_iso(time.time())}

    # ---- per day
    scratch = tempfile.mkdtemp(prefix="e9t_")
    try:
        for d in run.days:
            n = d["day"]
            w = tuple(d["window"])
            files = run.day_reports(n)
            db, _ts = run.snap("day%d_end" % n)
            touched = set()
            if db and files:
                touched = {int(x) for x in E8.window_touched(files, EV._private_copy(db, scratch))}
            trials = load_trials(files)
            day = {"window": {"t0": w[0], "t1": w[1], "utc": [E8_iso(w[0]), E8_iso(w[1])]},
                   "reports": [os.path.basename(f) for f in files], "touched_seconds": len(touched),
                   "harness": E8.report_context(trials) if trials else {}, "by_monitor": {}}
            for m in MONITORS:
                v = V[m].get("day%d" % n)
                if not isinstance(v, dict) or "error" in v:
                    day["by_monitor"][m] = {"verify_error": (v or {}).get("stderr", "missing")[-800:] if isinstance(v, dict) else "missing"}
                    continue
                pre_db = run.snap("night%d_pre" % (n - 1))[0] if n > 1 else None
                applied = "excused_violations" in v                  # part A's verifier applied the operator markers
                rdc = rd_checks.get(m) or []
                if applied and any(not x["valid"] for x in rdc):
                    # an invalid RESTORE_DONE: the restore it closes counts as not excused (pre-registered)
                    back = [x for x in v.get("excused_violations") or [] if (x.get("excused_by") or {}).get("marker") == "RESTORE"]
                    v = dict(v, violations=(v.get("violations") or []) + back,
                             excused_violations=[x for x in v.get("excused_violations") or [] if x not in back])
                cls, segs, _kl = classify(v, mk.get(m, []), run.events, db, pre_db)
                if applied:
                    segs = {}                                           # the verifier already removed what it excuses
                exc_secs = set() if applied else {r["seg"] for k in ("purge_scoped", "purge_disconnect", "restore")
                                                  for r in segs.get(k, []) if r["gran"] == "second"}
                vn = V[m].get("day%d_norowbind" % n)
                sg = v.get("signatures") or {}
                day["by_monitor"][m] = {
                    "arms": v.get("arms"),
                    "floor": floor(v, w, touched, segs),
                    "excused": verifier_excused(v, w) if applied else {
                        "purge_disconnect": {"segments": (cls["segments"].get("purge_disconnect") or {}).get("n", 0),
                                             "rows": sum(r.get("rows", 0) for r in segs.get("purge_disconnect", []))},
                        "purge_scoped": (cls["segments"].get("purge_scoped") or {}).get("n", 0),
                        "restore": (cls["segments"].get("restore") or {}).get("n", 0),
                        "source": "PROVISIONAL harness-side classification (the verifier applied no markers)"},
                    "classification_provisional": cls,
                    "verifier": verifier_marker_fields(v),
                    "suspect_seconds": {"with_rowbind": scoped_suspects(v, w, touched, exc_secs),
                                        "without_rowbind": scoped_suspects(vn, w, touched, exc_secs)
                                        if isinstance(vn, dict) and "error" not in vn else None},
                    "namemap": ([t for t in (v.get("namemap") or {}).get("transitions", []) if w[0] <= (t.get("ts") or 0) < w[1]]
                                if v.get("namemap") else namemap_transitions(chains.get(m, []), mk.get(m, []), w)),
                    "namemap_verdict_whole_run": ((v.get("namemap") or {}).get("verdict")
                                                  if n == run.days[-1]["day"] else "reported with the last day"),
                    "namemap_pending_at_end": (v.get("namemap") or {}).get("pending") if n == run.days[-1]["day"] else None,
                    "signatures": {"signed_ok": sg.get("signed_ok"), "unsigned_excluded": len(sg.get("unsigned_excluded") or []),
                                   "bad": len(sg.get("bad_signature") or []), "wrong_key": len(sg.get("wrong_key") or [])},
                    "root_unknown_segments": len(v.get("root_unknown_segments") or []),
                    "intervals_by_kind": dict(collections.Counter(s.get("kind") for s in v.get("stalls") or [])),
                    "benign_late_rows": len(v.get("benign_late_rows") or []),
                    "verify_wall_s": (v.get("_e9") or {}).get("verify_wall_s")}
            day["markers_issued"] = [e.get("result", {}).get("marker", {}).get("marker") if isinstance(e.get("result"), dict) else None
                                     for e in run.events if e.get("type") == "marker" and w[0] <= e["ts"] < w[1]]
            res["days"][str(n)] = day

        # ---- per night
        for d in run.days:
            n = d["day"]
            pre, _ = run.snap("night%d_pre" % n)
            post, _ = run.snap("night%d_post" % n)
            sch = next((e for e in run.schedule["events"] if e["type"] == "purge_marker" and e["day"] == n), None)
            if not (pre and post and sch):
                continue
            cutoff = sch["scheduled_ts"] - sch["keep_days"] * 86400.0
            night = {"scheduled_utc": E8_iso(sch["scheduled_ts"]), "keep_days": sch["keep_days"], "cutoff_utc": E8_iso(cutoff),
                     "db": purge_evidence(pre, post, cutoff), "by_monitor": {}}
            fp = [e for e in run.events if e.get("type") == "forced_purge" and e.get("ts", 0) >= sch["t"] - 600
                  and e.get("ts", 0) <= sch["scheduled_ts"] + 600]
            if fp:
                night["forced_purge_smoke"] = fp
            for m in MONITORS:
                vp, vq = V[m].get("night%d_pre" % n), V[m].get("night%d_post" % n)
                pm = [x for x in mk.get(m, []) if x.get("marker") == "PURGE" and abs(float(x.get("scheduled_ts", 0)) - sch["scheduled_ts"]) < 1]
                row = {"marker": [{"seq": x["seq"], "recv_utc": E8_iso(x["recv_ts"]) if x.get("recv_ts") else None,
                                   "before_purge": bool(x.get("recv_ts") and x["recv_ts"] < sch["scheduled_ts"]),
                                   "operator_signature_ok": x.get("operator_signature_ok")} for x in pm]}
                if isinstance(vp, dict) and isinstance(vq, dict) and "error" not in vp and "error" not in vq:
                    nv = new_violations(vp, vq)
                    applied = "excused_violations" in vq
                    cls, _s, _k = classify(nv, mk.get(m, []), run.events, post, pre)
                    pre_ex = {(x["gran"], x["seg"]) for x in vp.get("excused_violations") or []}
                    new_ex = [x for x in vq.get("excused_violations") or [] if (x["gran"], x["seg"]) not in pre_ex]
                    pr = vq.get("purge") or {}
                    row.update({"historical_window": [int(hist_lo) - 3600, run.start],
                                "unexcused_new_attributable_violations": len(nv["violations"]),
                                "unexcused_new_keylog_violations": len(nv["keylog_violations"]),
                                "unexcused_first": [{k: x.get(k) for k in ("gran", "seg", "mechanism")} for x in nv["violations"][:20]],
                                "excused_new": dict(collections.Counter("%s:%s:%s" % (
                                    (x.get("excused_by") or {}).get("marker"), (x.get("excused_by") or {}).get("rule"),
                                    x.get("gran")) for x in new_ex)) if applied else None,
                                "excused_disconnects": {"rows": (pr.get("disconnects") or {}).get("n_rows"),
                                                        "seconds": (pr.get("disconnects") or {}).get("n_seconds")}
                                if applied else None,
                                "verifier_applied_markers": applied,
                                "round12_rule_without_purge_disconnect": (lambda vz: {
                                    "unexcused_new_attributable_violations": len(new_violations(vp, vz)["violations"]),
                                    "unexcused_new_keylog_violations": len(new_violations(vp, vz)["keylog_violations"])}
                                    if isinstance(vz, dict) and "error" not in vz else None)(V[m].get("night%d_post_nodisconnect" % n)),
                                "classification_provisional": cls, "verifier": verifier_marker_fields(vq)})
                else:
                    row["verify_error"] = True
                night["by_monitor"][m] = row
            res["nights"][str(n)] = night

        # ---- per monitor, whole run
        wins = {"day%d" % d["day"]: tuple(d["window"]) for d in run.days}
        if whole:
            wins["week"] = whole
        prefix = next((l.split("prefix=")[1].split()[0] for l in run.meta if "prefix=" in l), "e9")
        for m in MONITORS:
            mon = {"cost": cost(os.path.join(a.run_dir, "%s_cost.jsonl" % m), wins),
                   "quick_check": quick_check_report(chains.get(m, []), os.path.join(a.run_dir, "%s_cost.jsonl" % m),
                                                     quick_check_every(run, m), wins),
                   "io": io_bytes(run.hostlog, "%s-monitor-%s" % (prefix, m), wins),
                   "seal_delay_s": E8.seal_delay(chains.get(m, []), wins),
                   "witness": E8.witness_checks(a.run_dir, m) if m in chains else None,
                   "anchor_refusals_by_reason": E8.refusals(os.path.join(a.run_dir, "%s_refusals.jsonl" % m)),
                   "monitor_log": E8.monitor_log_counts(os.path.join(a.run_dir, "%s_monitor.log" % m)),
                   "markers_on_chain": [{k: x.get(k) for k in ("seq", "marker", "recv_ts", "operator_signature_ok",
                                                               "scheduled_ts", "restore_point_ts", "parts", "step",
                                                               "nonce", "restore_nonce", "hub_started_ts")}
                                        for x in mk.get(m, [])],
                   "namemap_transitions": namemap_transitions(chains.get(m, []), mk.get(m, [])),
                   "restore_done": rd_checks.get(m),
                   "detection_pooled": {}}
            if t_start_snap[0] and m in chains:
                mon["full_history_seal"] = seal_coverage(chains[m], t_start_snap[0], run.start)
            pooled = collections.defaultdict(lambda: [0, 0])
            for dd in res["days"].values():
                for arm, x in ((dd["by_monitor"].get(m) or {}).get("arms") or {}).items():
                    pooled[arm][0] += x.get("e7_detected", 0)
                    pooled[arm][1] += x.get("n", 0)
            mon["detection_pooled"] = {arm: {"k": k, "n": nn, "ci": cp_ci(k, nn)} for arm, (k, nn) in pooled.items()}
            res["monitors"][m] = mon
        res["host"] = host(run, wins)
        res["events"] = {"counts": dict(collections.Counter(e.get("type") for e in run.events)),
                         "monitor_memory": [{k: e.get(k) for k in ("type", "monitor", "memory_peak_bytes", "wait_s",
                                                                     "records", "restarts")}
                                            for e in run.events if e.get("type") in ("initial_seal", "monitor_memory_peak")],
                         "restore_done_timing": [e for e in run.events if e.get("type") == "restore_done_timing"],
                         "snapshot_methods": {e.get("label"): e.get("method", "hub_tmp (before the read-only-mount path)")
                                              for e in run.events if e.get("type") == "snapshot" and e.get("ok")},
                         "markers": [{"utc": e["utc"], "all_ok": (e.get("result") or {}).get("all_ok"),
                                      "kind": ((e.get("result") or {}).get("marker") or {}).get("marker")}
                                     for e in run.events if e.get("type") == "marker"],
                         "hub_restarts": [{"utc": e["utc"], "cause": e.get("cause")} for e in run.events
                                          if e.get("type") == "hub_restart"],
                         "late_events": [{"id": e["id"], "late_s": e["late_s"], "type": e["event"]["type"]}
                                         for e in run.events if e.get("type") == "event_begin" and e.get("late_s", 0) > 60],
                         "restore": [e for e in run.events if e.get("type") in ("backup", "restore", "restore_refused", "restore_done_withheld")],
                         "namemap_steps": [{"step": e.get("step"), "declared": e.get("declared"),
                                            "ops_ok": [r.get("ok") for r in (e.get("results") or [e.get("result") or {}])],
                                            "errors": [r.get("err") for r in (e.get("results") or [e.get("result") or {}]) if r.get("err")]}
                                           for e in run.events if e.get("type") == "namemap_step"]}
        res["code_sha256"] = {p: sha(os.path.join(ROOT, p)) for p in (
            "exp/stages/e7_verify.py", "exp/stages/e9_score.py", "exp/stages/e8_score.py", "exp/rig/markers.py",
            "exp/rig/marker_issuer.py", "monitor/monitor.py", "testbed/e9/run_e9.sh", "testbed/e9/e9ops.py")}
    finally:
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(a.out_dir, exist_ok=True)
    with open(dst, "w" if a.overwrite else "x") as fh:
        json.dump(res, fh, indent=1, default=str)

    # ---- printed summary
    for n, dd in res["days"].items():
        for m, x in dd["by_monitor"].items():
            if "verify_error" in x:
                print("day %s %-6s verify ERROR %s" % (n, m, x["verify_error"][-200:]))
                continue
            arms = {k: "%d/%d" % (v_["e7_detected"], v_["n"]) for k, v_ in (x.get("arms") or {}).items()}
            fl = x["floor"]
            sus = x["suspect_seconds"]
            print("day %s %-6s arms %s | unexcused untouched s/m/h %d/%d/%d of %s | excused %s | suspects with/without "
                  "binding %s/%s | namemap %s | sig ok %s"
                  % (n, m, arms, fl["second"]["unexcused_untouched"], fl["minute"]["unexcused_untouched"],
                     fl["hour"]["unexcused_untouched"], fl["untouched_anchored"],
                     json.dumps({k: v_ for k, v_ in x["excused"].items() if k in ("segments_by_marker_rule", "purge_disconnect",
                                                                                   "purge_scoped", "restore", "keylog_ranges_excused")})[:400],
                     (sus.get("with_rowbind") or {}).get("n_seconds"), (sus.get("without_rowbind") or {}).get("n_seconds"),
                     [(t.get("parts_changed") or t.get("changed_parts"), t.get("excused_by_rename_marker", t.get("outcome")))
                      for t in x["namemap"]], x["signatures"]["signed_ok"]))
    for n, nt in res["nights"].items():
        db = nt["db"]
        print("night %s (cutoff %s): ran=%s rows older than cutoff %s -> %s; disconnected rows %s (%s seconds, %s > 1 h "
              "after the cutoff)" % (n, nt["cutoff_utc"], db["ran"], db["pre"]["states_older_than_cutoff"],
                                     db["post"]["states_older_than_cutoff"], db["disconnected"]["rows"],
                                     db["disconnected"]["seconds"], db["disconnected"]["rows_more_than_1h_after_cutoff"]))
        for m, x in nt["by_monitor"].items():
            print("   %-6s marker %s; unexcused new violations %s keylog %s; excused new %s; disconnects %s; provisional %s" % (
                m, x.get("marker"), x.get("unexcused_new_attributable_violations"), x.get("unexcused_new_keylog_violations"),
                x.get("excused_new"), x.get("excused_disconnects"),
                {k: v_["n"] for k, v_ in ((x.get("classification_provisional") or {}).get("segments") or {}).items()}))
    for m, mon in res["monitors"].items():
        for x in mon.get("restore_done") or []:
            print("%-6s RESTORE_DONE seq %s: valid %s %s; RESTORE -> DONE anchored %s s; rows above backup_wm before H %s/%s"
                  % (m, x["chain_seq"], x["valid"], x["why_invalid"], x["restore_to_done_anchored_s"],
                     x.get("rows_above_backup_wm_before_H_states"), x.get("rows_above_backup_wm_before_H_events")))
        qk = (mon["quick_check"].get("week") or {})
        print("%-6s quick_check every %s polls: due %s of %s polls, failed %s; unobservable polls %s %s; snapshot ms due %s "
              "/ not due %s" % (m, mon["quick_check"]["quick_check_every"], qk.get("quick_check_due"), qk.get("polls"),
                                qk.get("quick_check_failed"), qk.get("unobservable_polls"), qk.get("unobservable_by_reason"),
                                (qk.get("copy_or_snapshot_ms_due") or {}).get("median"),
                                (qk.get("copy_or_snapshot_ms_not_due") or {}).get("median")))
        wk = (mon["cost"].get("week") or {})
        print("%-6s cost total ms %s; read path %s; io %s; full-history seal %s; witness ok %s; markers %d" % (
            m, (wk.get("per_poll_ms") or {}).get("total_ms"), wk.get("read_path"), (mon["io"].get("week") or {}).get("bytes"),
            {k: (mon.get("full_history_seal") or {}).get(k) for k in ("seconds_with_a_row_before_start", "unsealed")},
            (mon.get("witness") or {}).get("ok"), len(mon["markers_on_chain"])))
    print("host (week): %s" % {k: (v_ if not isinstance(v_, list) else len(v_)) for k, v_ in (res["host"].get("week") or {}).items()})
    print("-> %s" % dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
