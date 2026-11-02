"""R2 (S&P 2027) -- the paper's quarantine on the SAVED real-deployment verifier snapshots.

WHAT THIS MEASURES. Published localization results exist only for generated
deployments (stage25 E13: 480/480 sound; stage24: over-quarantine 0.00179 for
the paper's policy vs 0.00193 for the connected-causal-component policy). This
script runs the same policies on the real deployment's saved evidence:

  * the anchored chain each run wrote (first-write-wins roots, chain records
    whose payload ts lies in [t_start, recorder_snapshot_at], evidence-
    unobservable records skipped) -- exactly exp/stages/e_c_write_time.py
    anchored_roots() and hp_d2/floor_rescore.py;
  * the verifier's own saved recorder snapshot, opened READ-ONLY and IMMUTABLE
    (file:<path>?mode=ro&immutable=1), loaded and committed with the SHIPPED
    monitor's load()/commit() for the run's scheme (closure | row | wholerow);
  * verification = verify_window() of e_c_write_time.py: every anchored segment
    whose start lies in [t_start - w, t_end + w] is recomputed and compared
    (acc and n). No new runs, no docker.

POLICIES (all given the SAME violation set; definitions are stage24's code):
  R5_homeprov  localize.greedy / greedy_regions  (the paper's policy)
  R4_component stage24._r4_component(U, R5 nodes)
  R2_segments  stage24._r2_segments_only        (node set: union of ALL violated
               segments, every granularity -- what stage24's code does)
  R1_1s/1min/1h stage24._r1_window
  R0_void      every node of U
  R3_ceiling   exactly the tampered surviving nodes

SOUNDNESS (metrics.lr_regions / stage24 interval coverage). A tampered element
is covered when its CLEAN timestamp lies inside a quarantined time region.
Updated state rows keep their timestamp (the arms never touch
last_updated_ts), so their clean timestamp is read from the snapshot.
Deleted events are absent from the snapshot; each is identified exactly as a
missing events.event_id (an id gap) and its clean timestamp is bounded by the
interval [ULID time of the trial's context, the trial's row_before] (the
floor_rescore.py rule, with row_before -- a state row in the deleted events'
own context -- as the upper end) intersected with [time of the previous
present event_id, time of the next present event_id]. An element whose interval is
fully inside the quarantine is covered; partly inside is 'indeterminate'.
A trial is sound when every element it tampered is covered.

OVER-QUARANTINE (metrics.oq, as stage24): |Q minus T| / |U|, Q the policy's
node set, T the tampered keys, U the surviving nodes in the time span of the
verified anchored segments of the run (stage24 uses the whole generated
deployment; on the real hub the anchor vouches only for the run's segments).

Usage:  python3 r2_localize.py RUN_ID        -> exp/out/r2_<RUN_ID>_localization.json
        python3 r2_localize.py --summary     -> exp/out/r2_localization_summary.json
Never overwrites; never writes outside exp/out/r2_*.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True          # no .pyc may be (over)written in the repo

import collections
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import time
import types
import urllib.parse

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EXP = os.path.join(REPO, "exp")
OUT = os.path.join(EXP, "out")
SCRATCH = os.path.join(os.environ.get("HOMEPROV_SCRATCH_DIR", os.path.join(__import__("tempfile").gettempdir(),
                                                                          "homeprov-scratch")), "r2", "monitor_scratch")
# R2_DRYRUN=1 writes to the scratch directory instead of exp/out (for development only); R2_OUTDIR names any other.
OUTDIR = (os.environ.get("R2_OUTDIR") or
          (os.path.join(os.path.dirname(SCRATCH), "dryrun") if os.environ.get("R2_DRYRUN") else OUT))

# ------------------------------------------------------------------ hard guard
_real_run, _real_popen = subprocess.run, subprocess.Popen


def _guard(args):
    s = args if isinstance(args, str) else " ".join(map(str, args))
    if "docker" in s:
        raise RuntimeError("R2 forbids docker: %r" % s[:120])


def _run(args, *a, **k):
    _guard(args)
    return _real_run(args, *a, **k)


class _Popen(_real_popen):
    def __init__(self, args, *a, **k):
        _guard(args)
        super().__init__(args, *a, **k)


subprocess.run, subprocess.Popen = _run, _Popen

sys.path.insert(0, EXP)
sys.path.insert(0, os.path.join(REPO, "reproduce"))
from rig import localize, metrics, stats                       # noqa: E402
import verify_all as VA                                         # noqa: E402
# Inputs: $HOMEPROV_SNAPSHOTS (the full verifier snapshot set), else the per-run window extracts in
# reproduce/snapshots (the released artifact), else the snapshot set beside the repository (verify_all's rule).
SRC = VA.default_inputs(os.environ.get("HOMEPROV_SNAPSHOTS"), os.environ.get("HOMEPROV_EXTRACTS"))
SNAP = SRC.base
from stages import stage24_recon_baselines as S24               # noqa: E402

RUNS = {
    # ---- primary: closure monitor, authenticated anchor
    "e_d_clo": dict(scheme="closure", db="hp-clo/e_d_clo/ec_verify/recorder.db",
                    chain="hp-clo/e_d_clo/chain.jsonl",
                    result="e_d_clo_other_principal_real.json",
                    floor="e_d_clo_floor_rescore.json"),
    "e_c_clo": dict(scheme="closure", db="hp-clo/e_c_clo/ec_verify/recorder.db",
                    chain="hp-clo/e_c_clo/chain.jsonl",
                    result="e_c_clo_other_principal_real.json",
                    floor="e_c_clo_floor_rescore.json"),
    "e_ps_clo": dict(scheme="closure", db="hp-clo/e_ps_clo/ps_verify/recorder.db",
                     chain="hp-clo/e_ps_clo/chain.jsonl",
                     result="e_ps_clo_detection.json",
                     floor="e_ps_clo_floor_rescore.json"),
    "e_psr_clo": dict(scheme="closure", db="hp-clo/e_psr_clo/ps_verify/recorder.db",
                      chain="hp-clo/e_psr_clo/chain.jsonl",
                      result="e_psr_clo_detection.json",
                      floor="e_psr_clo_floor_rescore.json"),
    # ---- secondary: row scheme, authenticated anchor
    "e_d_auth": dict(scheme="row", db="hp_d2/live/recorder.db",
                     chain=os.path.join(OUT, "e_d_auth_anchor_chain.jsonl.gz"),
                     result="e_d_auth_other_principal_real.json",
                     floor="e_d_auth_floor_rescore.json",
                     deviation="the verifier's own e_d_auth snapshot (2026-09-26) is not in the "
                               "snapshot set; the later live snapshot hp_d2/live/recorder.db "
                               "(taken_at 1791117788, 2026-10-04) is used, as "
                               "e_d_auth_floor_rescore.json did. Admitted only if it reproduces "
                               "the published verdict counts and the event-gap check."),
    "e_c_auth": dict(scheme="row", db="hp-ec-auth/ec_verify/recorder.db",
                     chain="hp-ec-auth/e_c_auth_chain.jsonl",
                     result="e_c_auth_other_principal_real.json",
                     floor="e_c_auth_floor_rescore.json"),
    "e_ps_auth": dict(scheme="row", db="hp-ps-auth/ps_verify/recorder.db",
                      chain="hp-ps-auth/e_ps_auth_chain.jsonl",
                      result="e_ps_auth_detection.json",
                      floor="e_ps_auth_floor_rescore.json"),
    # ---- tertiary: whole-row baseline monitor
    "e_d_whr": dict(scheme="wholerow", db="hp-whr/e_d_whr/ec_verify/recorder.db",
                    chain="hp-whr/e_d_whr/chain.jsonl",
                    result="e_d_whr_other_principal_real.json",
                    floor="e_d_whr_floor_rescore.json"),
    "e_ps_whr": dict(scheme="wholerow", db="hp-whr/e_ps_whr/ps_verify/recorder.db",
                     chain="hp-whr/e_ps_whr/chain.jsonl",
                     result="e_ps_whr_detection.json",
                     floor="e_ps_whr_floor_rescore.json"),
    "e_psr_whr": dict(scheme="wholerow", db="hp-whr/e_psr_whr/ps_verify/recorder.db",
                      chain="hp-whr/e_psr_whr/chain.jsonl",
                      result="e_psr_whr_detection.json",
                      floor="e_psr_whr_floor_rescore.json"),
}
POST_COMMIT_ARMS = ("P", "PU", "PI", "PS", "PSR")
WRITE_TIME_ARMS = ("W1", "W2", "W2b", "W3")
POLICIES = ["R0_void", "R1_1s", "R1_1min", "R1_1h", "R2_segments", "R3_ceiling",
            "R4_component", "R5_homeprov"]


# ------------------------------------------------------------------ helpers
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*a):
    return _real_run(["git", "-C", REPO, *a], capture_output=True, text=True).stdout.strip()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def shasums():
    return dict(SRC.sums)


def _ro_connect(db, timeout=30, **_kw):
    """Every SQLite open in this script: read-only, immutable, no sidecar files."""
    p = os.path.abspath(db)
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(p),
                           uri=True, timeout=timeout)


SHIM = types.SimpleNamespace(connect=_ro_connect)


def load_monitor(scheme):
    """The SHIPPED monitor's load()/commit(), with sqlite3.connect forced read-only."""
    os.makedirs(SCRATCH, exist_ok=True)
    os.environ["HOMEPROV_SCRATCH"] = SCRATCH
    os.environ["HOMEPROV_DB"] = os.path.join(SCRATCH, "unused.db")
    if scheme == "wholerow":
        sys.path.insert(0, os.path.join(REPO, "monitor"))
        import monitor_wholerow as WR                              # noqa: PLC0415
        WR.sqlite3 = SHIM
        WR.M.sqlite3 = SHIM
        M = WR.M
        assert M.SCHEME == "wholerow" and M.load is WR.load
        return M, {"monitor_py_sha256": sha256_file(os.path.join(REPO, "monitor", "monitor.py")),
                   "monitor_wholerow_py_sha256": sha256_file(
                       os.path.join(REPO, "monitor", "monitor_wholerow.py"))}
    os.environ["HOMEPROV_SCHEME"] = scheme
    spec = importlib.util.spec_from_file_location("hp_monitor_" + scheme,
                                                  os.path.join(REPO, "monitor", "monitor.py"))
    M = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(M)
    M.sqlite3 = SHIM
    assert M.SCHEME == scheme
    return M, {"monitor_py_sha256": sha256_file(os.path.join(REPO, "monitor", "monitor.py"))}


def read_chain(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt").read().splitlines()
    return open(path).read().splitlines()


def anchored_roots(lines, t0, tsnap):
    """e_c_write_time.anchored_roots(), over a saved chain file."""
    roots, n_rec, n_win, unobs, ever = {}, 0, 0, [], set()
    grans_all, grans_win, schemes = collections.Counter(), collections.Counter(), collections.Counter()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        n_rec += 1
        p = rec.get("payload") or {}
        schemes[p.get("scheme", "unrecorded")] += 1
        for g, segs in (p.get("sealed") or {}).items():
            grans_all[g] += 1
            if isinstance(segs, dict):
                for s in segs:
                    ever.add((g, str(s)))
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap):
            continue
        n_win += 1
        if p.get("evidence_unobservable"):
            unobs.append({"ts": ts, "reason": p.get("reason")})
            continue
        for g, segs in (p.get("sealed") or {}).items():
            if not isinstance(segs, dict):
                continue
            grans_win[g] += len(segs)
            for s, v in segs.items():
                k = (g, str(s))
                if k not in roots and isinstance(v, dict):
                    roots[k] = {"acc": v.get("acc"), "n": v.get("n"), "anchored_at": ts,
                                "seq": rec.get("seq"), "encoding": p.get("encoding", "v1")}
    return roots, ever, {"chain_records_total": n_rec, "chain_records_in_window": n_win,
                   "evidence_unobservable_records": unobs,
                   "granularities_in_chain_records": dict(grans_all),
                   "segments_sealed_in_window_by_granularity": dict(grans_win),
                   "chain_schemes": dict(schemes)}


def verify_window(phi, roots, widths, t0, t1):
    """e_c_write_time.verify_window(), on a precomputed phi."""
    out = {}
    for (g, seg), a in roots.items():
        w = widths.get(g)
        if w is None:
            continue
        if not (t0 - w <= int(seg) * w <= t1 + w):
            continue
        got = (phi.get(g) or {}).get(str(seg))
        if got is None:
            out[(g, seg)] = {"violation": True, "why": "segment_absent_now",
                             "mechanism": "segment_vanished", "delta_n": None}
        elif got["acc"] != a["acc"] or got["n"] != a["n"]:
            dn = got["n"] - a["n"]
            out[(g, seg)] = {"violation": True, "why": "root_mismatch", "delta_n": dn,
                             "mechanism": ("rows_arrived_after_seal" if dn > 0 else
                                           "rows_removed_after_seal" if dn < 0 else
                                           "content_changed_in_place")}
        else:
            out[(g, seg)] = {"violation": False}
    return out


class N:
    __slots__ = ("key", "ts", "ctx", "par")

    def __init__(self, key, ts, ctx, par):
        self.key, self.ts, self.ctx, self.par = key, ts, ctx, par


B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid_s(v):
    if not v:
        return None
    if len(v) == 32:
        return int(v[:12], 16) / 1000.0
    if len(v) == 26:
        n = 0
        for ch in v[:10].upper():
            n = n * 32 + B32.index(ch)
        return n / 1000.0
    return None


def ulid_bytes(v):
    n = 0
    for ch in v.upper():
        n = n * 32 + B32.index(ch)
    return n.to_bytes(16, "big")


def row_ts(t):
    for k in ("judged_row", "forged_row", "row_before"):
        r = t.get(k)
        if isinstance(r, dict) and r.get("ts"):
            return float(r["ts"])
    return None


def touched_new_rule(trials, con, W):
    """hp_d2/floor_rescore.py NEW counting rule (and the old one), verbatim logic."""
    def state_ts(sid):
        return (con.execute("SELECT last_updated_ts FROM states WHERE state_id=?",
                            (sid,)).fetchone() or [None])[0]
    old = {g: set() for g in W}
    new = {g: set() for g in W}
    for t in trials:
        ts = row_ts(t)
        if ts is None:
            continue
        secs = {int(ts // 1)}
        for k in ("row_before", "judged_row", "forged_row"):
            r = t.get(k)
            if isinstance(r, dict) and r.get("state_id"):
                x = state_ts(r["state_id"]) or r.get("ts")
                if x:
                    secs.add(int(float(x) // 1))
        for sid in (t.get("laundered_state_ids") or []) + (t.get("swapped_state_ids") or []):
            x = state_ts(sid)
            if x:
                secs.add(int(x // 1))
        if t.get("arm") == "W3":
            for e in t.get("residual_adversary_call_service") or []:
                if e.get("ts"):
                    secs.add(int(float(e["ts"]) // 1))
        else:
            r = t.get("row_before") or t.get("forged_row") or t.get("judged_row") or {}
            for cid in (r.get("context_id_bin"), t.get("fabricated_event_context")):
                if not cid:
                    continue
                b = bytes.fromhex(cid) if len(cid) == 32 else ulid_bytes(cid)
                evs = [x[0] for x in con.execute(
                    "SELECT time_fired_ts FROM events WHERE context_id_bin=?", (b,))]
                if evs:
                    secs |= {int(x // 1) for x in evs if x}
                else:
                    c = ulid_s(cid)
                    if c is not None:
                        lo, hi = sorted((c, ts))
                        secs |= set(range(int(lo // 1), int(hi // 1) + 1))
        for s in secs:
            for g, w in W.items():
                new[g].add(str(int(s * 1.0 // w)))
        for g, w in W.items():
            old[g].add(str(int(ts // w)))
    return old, new


def floor_counts(verd, touched, g):
    segs = [s for (gg, s) in verd if gg == g and s not in touched]
    fails = [s for s in segs if verd[(g, s)]["violation"]]
    return {"k": len(fails), "n": len(segs),
            "mechanisms": dict(collections.Counter(verd[(g, s)]["mechanism"] for s in fails))}


def merge_regions(regions):
    rs = sorted((float(a), float(b)) for a, b in regions)
    out = []
    for a, b in rs:
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def cover_status(lo, hi, merged, closed=False):
    """Is [lo, hi] inside the union of regions? Regions half-open [a, b) unless closed."""
    def inside(t, a, b):
        return (a <= t <= b) if closed else (a <= t < b)
    full = any(a <= lo and (hi <= b if closed else hi < b) for a, b in merged)
    if full:
        return "covered"
    if lo == hi:
        return "uncovered"
    part = any(inside(lo, a, b) or inside(hi, a, b) or (lo <= a <= hi) for a, b in merged)
    return "indeterminate" if part else "uncovered"


def trial_status(stats_list):
    if all(s == "covered" for s in stats_list):
        return "sound"
    if any(s == "uncovered" for s in stats_list):
        return "unsound"
    return "indeterminate"


def cp(k, n):
    return stats.clopper_pearson(k, n) if n else {"k": 0, "n": 0, "prop": None}


# ------------------------------------------------------------------ one run
def run_one(run_id):
    t_begin = now()
    cfg = RUNS[run_id]
    dst = os.path.join(OUTDIR, "r2_%s_localization.json" % run_id)
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    sums = shasums()
    db, chain = SRC.paths(run_id)
    resf = os.path.join(OUT, cfg["result"])
    floorf = os.path.join(OUT, cfg["floor"])
    inputs = {}
    for label, p in (("snapshot_db", db), ("chain", chain)):
        rel = os.path.relpath(p, SNAP)
        inputs[label] = {"path": p, "sha256_listed_in_SHA256SUMS": sums.get(rel),
                         "sha256_at_run": sha256_file(p)}
    for label, p in (("published_result", resf), ("published_floor_rescore", floorf)):
        inputs[label] = {"path": p, "sha256_at_run": sha256_file(p)}
    for label in ("snapshot_db", "chain"):
        lst = inputs[label]["sha256_listed_in_SHA256SUMS"]
        if lst is not None and lst != inputs[label]["sha256_at_run"]:
            raise SystemExit("snapshot integrity failure on %s" % label)

    res = json.load(open(resf))
    pub_floor = json.load(open(floorf))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    is_det = "homeprov_detection_second" in res

    M, mon_info = load_monitor(cfg["scheme"])
    W = dict(M.GRAN)
    lines = read_chain(chain)
    roots, ever_sealed, chain_info = anchored_roots(lines, t0, tsnap)
    since = (int(t0 // 3600) - 1) * 3600.0
    tl = time.time()
    tuples = M.load(db, since=since)
    encs = {a["encoding"] for a in roots.values()}   # records without one were sealed with 'v1'
    if len(encs) > 1:
        raise SystemExit("chain mixes node-hash encodings %s" % sorted(encs))
    phi = M.commit(tuples, encoding=(encs.pop() if encs else "v1"))
    load_s = time.time() - tl
    verd = verify_window(phi, roots, W, t0, t1)
    viol = [{"gran": g, "seg": s, "why": v["why"], "mechanism": v["mechanism"],
             "delta_n": v["delta_n"]} for (g, s), v in sorted(verd.items()) if v["violation"]]

    # ---------------- reproduction gates against the published aggregate
    gates = {}
    an_pub = (res.get("detection_method") or {}).get("anchored_segments_in_window") or {}
    an_me = {g: sum(1 for (gg, _s) in roots if gg == g) for g in W}
    gates["anchored_segments_in_window"] = {"published": an_pub, "recomputed": an_me,
                                            "match": all(an_pub.get(g) == an_me[g] for g in an_pub)}
    vi_pub = (res.get("detection_method") or {}).get("violating_segments_in_window")
    vi_me = {g: sum(1 for (gg, _s), v in verd.items() if gg == g and v["violation"]) for g in W}
    if vi_pub is not None:
        gates["violating_segments_in_window"] = {"published": vi_pub, "recomputed": vi_me,
                                                 "match": all(vi_pub.get(g) == vi_me[g] for g in vi_pub)}
    all_trials = res["trials"]
    floor_trials = ([t for t in all_trials if t.get("arm") in ("PS", "PSR")] if is_det
                    else all_trials)
    con = _ro_connect(db)
    old_t, new_t = touched_new_rule(floor_trials, con, W)
    mech_pub = res.get("violation_mechanisms") or {}
    mech_me = {}
    for g in ("second", "minute"):
        c = collections.Counter()
        for (gg, s), v in verd.items():
            if gg != g or not v["violation"]:
                continue
            c[v["mechanism"]] += 1
            if not is_det:
                c["untouched_" + v["mechanism"]] += (0 if s in old_t[g] else 1)
        mech_me[g] = dict(c)
    gates["violation_mechanisms"] = {
        "published": mech_pub, "recomputed": mech_me,
        "match": all({k: v for k, v in mech_pub.get(g, {}).items()} ==
                     {k: v for k, v in mech_me.get(g, {}).items()} for g in ("second", "minute"))}
    fo = {g: floor_counts(verd, old_t[g], g) for g in ("second", "minute")}
    fn = {g: floor_counts(verd, new_t[g], g) for g in ("second", "minute")}
    gates["floor_old_rule_vs_floor_rescore"] = {
        "published": {g: [pub_floor["old_rule_floor"][g]["k"], pub_floor["old_rule_floor"][g]["n"]]
                      for g in ("second", "minute")},
        "recomputed": {g: [fo[g]["k"], fo[g]["n"]] for g in ("second", "minute")},
        "match": all((fo[g]["k"], fo[g]["n"]) == (pub_floor["old_rule_floor"][g]["k"],
                                                  pub_floor["old_rule_floor"][g]["n"])
                     for g in ("second", "minute"))}
    gates["floor_new_rule_vs_floor_rescore"] = {
        "published": {g: [pub_floor["new_rule_floor"][g]["k"], pub_floor["new_rule_floor"][g]["n"]]
                      for g in ("second", "minute")},
        "recomputed": {g: [fn[g]["k"], fn[g]["n"]] for g in ("second", "minute")},
        "match": all((fn[g]["k"], fn[g]["n"]) == (pub_floor["new_rule_floor"][g]["k"],
                                                  pub_floor["new_rule_floor"][g]["n"])
                     for g in ("second", "minute"))}
    # per-trial published second verdict vs ours
    agree = disagree = 0
    for t in all_trials:
        d = ((t.get("_detection") or {}).get("second") or {})
        if d.get("segment") is None or d.get("violation") is None:
            continue
        mine = verd.get(("second", d["segment"]))
        if mine is None:
            disagree += 1
        elif bool(mine["violation"]) == bool(d["violation"]):
            agree += 1
        else:
            disagree += 1
    gates["per_trial_second_verdicts"] = {"agree": agree, "disagree": disagree,
                                          "match": disagree == 0}

    # ---------------- the universe U: surviving nodes in the verified span
    ver_keys = list(verd)
    span_lo = min(int(s) * W[g] for g, s in ver_keys)
    span_hi = max((int(s) + 1) * W[g] for g, s in ver_keys)
    U = [N(n[1], n[0], n[3], n[4]) for n in tuples if span_lo <= n[0] < span_hi]
    Ukeys = {n.key for n in U}
    n_runwin = sum(1 for n in tuples if t0 <= n[0] <= t1)
    del tuples, phi

    # ---------------- ground truth per trial
    evrows = con.execute("SELECT event_id, time_fired_ts FROM events "
                         "WHERE time_fired_ts BETWEEN ? AND ? ORDER BY event_id",
                         (t0 - 900, tsnap + 900)).fetchall()
    inversions = sum(1 for a, b in zip(evrows, evrows[1:]) if b[1] < a[1])
    gaps = []
    for a, b in zip(evrows, evrows[1:]):
        for missing in range(a[0] + 1, b[0]):
            gaps.append({"event_id": missing, "prev_ts": a[1], "next_ts": b[1]})
    gap_used = {}
    trials_gt = []
    elig = [t for t in all_trials if t.get("arm") in POST_COMMIT_ARMS]

    def edited_sids(t):
        if t["arm"] == "P":
            return [(t.get("row_before") or {}).get("state_id")]
        if t["arm"] in ("PU", "PI"):
            return list(t.get("laundered_state_ids") or [])
        return list(t.get("swapped_state_ids") or [])
    # A row edited by more than one trial carries the LAST edit. res["trials"] is in
    # execution order (rooms in sequence, arms in sequence, phase-2 edits in trial
    # order), so the last writer of a row is the last trial in that list naming it.
    last_writer = {}
    for t in elig:
        if t.get("edited_after_anchoring"):
            for sid in edited_sids(t):
                last_writer[sid] = t
    for t in elig:
        rec = {"room": t.get("room"), "arm": t.get("arm"), "trial": t.get("trial"),
               "edited_after_anchoring": bool(t.get("edited_after_anchoring")),
               "err": t.get("err") or t.get("error")}
        if not t.get("edited_after_anchoring"):
            rec["excluded"] = "no post-commit edit was performed (%s)" % rec["err"]
            trials_gt.append(rec)
            continue
        arm = t["arm"]
        rb = t.get("row_before") or {}
        sids = edited_sids(t)
        elems, checks = [], []
        for sid in sids:
            r = con.execute("SELECT last_updated_ts, context_id_bin, context_parent_id_bin, "
                            "context_user_id_bin FROM states WHERE state_id=?", (sid,)).fetchone()
            if r is None:
                elems.append({"key": "s:%d" % sid, "kind": "state_update", "lo": None, "hi": None,
                              "missing_from_snapshot": True})
                checks.append(False)
                continue
            ts, ctx, par, usr = r
            lw = last_writer[sid]
            if lw["arm"] in ("P", "PU", "PI"):
                ok = (ctx is not None and ctx.hex()[:16] == lw.get("cover_context") and par is None
                      and (lw["arm"] != "PU" or usr is None))
            else:
                ok = usr is not None and usr.hex() == lw.get("swap_user_id_hex")
            checks.append(ok)
            elems.append({"key": "s:%d" % sid, "kind": "state_update", "lo": ts, "hi": ts,
                          "edit_visible_in_snapshot": ok,
                          "edited_by_n_trials": sum(1 for x in elig if x.get("edited_after_anchoring")
                                                    and sid in edited_sids(x)),
                          "last_writer": "%s/%s/%s" % (lw.get("room"), lw["arm"], lw.get("trial"))})
        n_del = (t.get("operations_used") or {}).get("delete", 0) or 0
        if n_del:
            cts = ulid_s(rb.get("context_id_bin"))
            # Upper bound: the trial's row_before, a state row carrying the deleted
            # events' context (adv = row_before.context_id_bin by construction). Home
            # Assistant fires call_service before the handler writes any state in that
            # context, so the deleted event precedes it (checked on the surviving
            # lock-domain pairs below: deleted_event_time_bound_support).
            hi_bound = (rb or {}).get("ts") or (t.get("judged_row") or {}).get("ts")
            mine = [gp for gp in gaps if cts is not None and hi_bound is not None
                    and gp["next_ts"] >= cts and gp["prev_ts"] <= hi_bound]
            for gp in mine:
                gap_used.setdefault(gp["event_id"], []).append(
                    "%s/%s/%s" % (t.get("room"), arm, t.get("trial")))
                elems.append({"key": "e:%d" % gp["event_id"], "kind": "event_delete",
                              "lo": max(cts, gp["prev_ts"]), "hi": min(hi_bound, gp["next_ts"]),
                              "span_ulid_to_row": [cts, hi_bound],
                              "span_id_neighbours": [gp["prev_ts"], gp["next_ts"]]})
            rec["n_deleted_events_reported"] = n_del
            rec["n_deleted_events_identified"] = len(mine)
            checks.append(len(mine) == n_del)
        rec["elements"] = elems
        rec["ground_truth_exact"] = all(checks)
        trials_gt.append(rec)
    n_del_total = sum((t.get("operations_used") or {}).get("delete", 0) or 0
                      for t in elig if t.get("edited_after_anchoring"))
    # The scan reaches 900 s either side of the run so a deleted event's neighbours
    # are always present; gaps wholly before t_start belong to the PREVIOUS run on
    # the same hub (runs were back to back) and are reported, not assigned.
    in_run = [g for g in gaps if g["next_ts"] >= t0 and g["prev_ts"] <= tsnap]
    out_run = [g for g in gaps if g not in in_run]
    gap_check = {"scan_range": [t0 - 900, tsnap + 900], "events_in_scan": len(evrows),
                 "time_inversions_by_event_id": inversions,
                 "missing_event_ids_in_scan": len(gaps),
                 "missing_event_ids_in_[t_start,recorder_snapshot_at]": len(in_run),
                 "missing_event_ids_outside_run": {
                     "n": len(out_run),
                     "all_before_t_start": all(g["next_ts"] < t0 for g in out_run),
                     "latest_bracket_end": max((g["next_ts"] for g in out_run), default=None)},
                 "deletions_reported_by_trials": n_del_total,
                 "gaps_assigned_to_exactly_one_trial": sum(1 for v in gap_used.values() if len(v) == 1),
                 "gaps_assigned_to_several_trials": sum(1 for v in gap_used.values() if len(v) > 1),
                 "in_run_gaps_unassigned": [g["event_id"] for g in in_run
                                            if g["event_id"] not in gap_used],
                 "match": (len(in_run) == n_del_total and inversions == 0 and
                           all(len(v) == 1 for v in gap_used.values()) and
                           set(gap_used) == {g["event_id"] for g in in_run})}
    # empirical support for the ULID-to-row bound: surviving call_service events vs
    # the state rows they caused (same context), in this run's window
    lag = con.execute(
        """SELECT s.last_updated_ts - e.time_fired_ts FROM states s
             JOIN states_meta sm ON sm.metadata_id = s.metadata_id
             JOIN events e ON e.context_id_bin = s.context_id_bin
             JOIN event_types et ON et.event_type_id = e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id = e.data_id
            WHERE et.event_type='call_service' AND sm.entity_id LIKE 'lock.%'
              AND ed.shared_data LIKE '%"domain":"lock"%'
              AND s.last_updated_ts BETWEEN ? AND ?""",
        (t0, t1)).fetchall()
    lag = [x[0] for x in lag if x[0] is not None]
    ulid_lag = con.execute(
        """SELECT e.time_fired_ts, hex(e.context_id_bin) FROM events e
             JOIN event_types et ON et.event_type_id = e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id = e.data_id
            WHERE et.event_type='call_service' AND e.time_fired_ts BETWEEN ? AND ?
              AND ed.shared_data LIKE '%"domain":"lock"%'
              AND e.context_id_bin IS NOT NULL""", (t0, t1)).fetchall()
    ulid_d = [ts - ulid_s(h.lower()) for ts, h in ulid_lag if h and len(h) == 32]
    bound_support = {
        "call_service_to_state_row_lag_s": ({"n": len(lag), "min": min(lag), "max": max(lag)}
                                            if lag else {"n": 0}),
        "call_service_minus_context_ulid_s": ({"n": len(ulid_d), "min": min(ulid_d),
                                               "max": max(ulid_d)} if ulid_d else {"n": 0}),
        "scope": "lock-domain call_service events and lock state rows sharing their context, in [t_start, t_end]",
        "reading": "lag >= 0 supports event <= its state row; ulid delta >= 0 supports "
                   "context creation <= event"}
    con.close()

    T = {e["key"] for r in trials_gt for e in r.get("elements", [])}
    T_surv = T & Ukeys

    # ---------------- policies, all violations
    def policies(vl):
        segs = S24._viol_segments(vl)
        R5n = localize.greedy(U, vl)
        R5r = localize.greedy_regions(U, vl)
        R4n = S24._r4_component(U, R5n)
        nodes = {
            "R0_void": set(Ukeys),
            "R1_1s": S24._r1_window(U, vl, 1.0),
            "R1_1min": S24._r1_window(U, vl, 60.0),
            "R1_1h": S24._r1_window(U, vl, 3600.0),
            "R2_segments": S24._r2_segments_only(U, vl),
            "R3_ceiling": set(T_surv),
            "R4_component": R4n,
            "R5_homeprov": R5n}
        mw = min((hi - lo for lo, hi in segs), default=None)
        ivs = {
            "R0_void": ([(min(n.ts for n in U), max(n.ts for n in U))], True),
            "R1_1s": ([(lo - 1.0, hi + 1.0) for lo, hi in segs], True),
            "R1_1min": ([(lo - 60.0, hi + 60.0) for lo, hi in segs], True),
            "R1_1h": ([(lo - 3600.0, hi + 3600.0) for lo, hi in segs], True),
            "R2_segments": ([(lo, hi) for lo, hi in segs if (hi - lo) == mw], True),
            "R5_homeprov": (R5r, False),
            "R5_homeprov_closed": (R5r, True),
        }
        return nodes, ivs, R5r

    nodes_all, ivs_all, R5r_all = policies(viol)
    oq = {}
    for p in POLICIES:
        Q = nodes_all[p]
        oq[p] = {"Q": len(Q), "Q_and_T": len(Q & T), "Q_minus_T": len(Q - T),
                 "OQ": metrics.oq(Q, T, len(U))}

    # ---------------- soundness per trial, per policy
    merged = {p: merge_regions(iv) for p, (iv, _c) in ivs_all.items()}
    viol_keys = {(v["gran"], v["seg"]) for v in viol}
    closed = {p: c for p, (_iv, c) in ivs_all.items()}
    R4keys = nodes_all["R4_component"]
    per_trial = []
    for r in trials_gt:
        if "elements" not in r:
            per_trial.append(r)
            continue
        st = {}
        for p in list(merged) + ["R4_component", "R3_ceiling"]:
            ss = []
            for e in r["elements"]:
                if e["lo"] is None:
                    ss.append("uncovered")
                    continue
                if p == "R3_ceiling":
                    ss.append("covered")
                    continue
                if p == "R4_component":
                    if e["key"] in R4keys:
                        ss.append("covered")
                    else:
                        ss.append(cover_status(e["lo"], e["hi"], merged["R5_homeprov"], False))
                    continue
                ss.append(cover_status(e["lo"], e["hi"], merged[p], closed[p]))
            st[p] = trial_status(ss)
        # element detail for the paper's policy, with the verdict of its own segments
        for e in r["elements"]:
            if e["lo"] is None:
                continue
            e["R5_cover"] = cover_status(e["lo"], e["hi"], merged["R5_homeprov"], False)
            secs = sorted({int(e["lo"] // 1), int(e["hi"] // 1)})
            e["own_second_segments"] = [
                {"segment": str(s), "anchored": ("second", str(s)) in roots,
                 "verified": ("second", str(s)) in verd,
                 "ever_sealed_in_chain": ("second", str(s)) in ever_sealed,
                 "mechanism": (verd.get(("second", str(s))) or {}).get("mechanism"),
                 "delta_n": (verd.get(("second", str(s))) or {}).get("delta_n")}
                for s in secs]
        # ANCHOR-RESOLVED (secondary). An indeterminate deleted event lies in one of
        # the seconds its interval meets. A second the monitor NEVER sealed (no root
        # for it anywhere in the chain) held no row while the event existed (the event
        # was on disk for the whole seal wait, and the monitor seals every closed
        # second that holds a row), so it is excluded. The element is covered when
        # every remaining candidate part of its interval is quarantined. Assumes the
        # monitor's sealing was complete between the event's write and its deletion.
        ar = []
        for e in r["elements"]:
            if e["lo"] is None:
                ar.append("uncovered")
                continue
            c = cover_status(e["lo"], e["hi"], merged["R5_homeprov"], False)
            if c != "indeterminate":
                ar.append(c)
                continue
            parts = []
            for sec in range(int(e["lo"] // 1), int(e["hi"] // 1) + 1):
                if ("second", str(sec)) not in ever_sealed:
                    continue
                parts.append(cover_status(max(e["lo"], float(sec)),
                                          min(e["hi"], float(sec) + 0.999999),
                                          merged["R5_homeprov"], False))
            e["R5_cover_anchor_resolved"] = (
                "unresolved_no_candidate_second_sealed" if not parts else
                "covered" if all(x == "covered" for x in parts) else
                "uncovered" if all(x == "uncovered" for x in parts) else "indeterminate")
            ar.append(e["R5_cover_anchor_resolved"] if parts else "indeterminate")
        st["R5_homeprov_anchor_resolved"] = trial_status(ar)
        r["status"] = st
        # metrics.miss_taxonomy, per trial: Miss-D = no violated segment contains any
        # element the trial tampered; Miss-L = detected but the quarantine misses one.
        det = any((g, str(int(sec * 1.0 // w))) in viol_keys
                  for e in r["elements"] if e["lo"] is not None
                  for sec in range(int(e["lo"] // 1), int(e["hi"] // 1) + 1)
                  for g, w in W.items())
        r["detected_own_segments"] = det
        r["miss_R5"] = (None if st["R5_homeprov"] == "sound" else
                        "Miss-D" if not det else
                        "Miss-L" if st["R5_homeprov"] == "unsound" else "indeterminate")
        per_trial.append(r)

    # ---------------- per-arm summaries
    arms = collections.OrderedDict()
    for arm in POST_COMMIT_ARMS:
        rows = [r for r in per_trial if r.get("arm") == arm]
        if not rows:
            continue
        scored = [r for r in rows if "status" in r]
        a = {"n_trials": len(rows), "n_scored": len(scored),
             "n_excluded_no_edit": len(rows) - len(scored),
             "n_ground_truth_exact": sum(1 for r in scored if r["ground_truth_exact"]),
             "n_tampered_elements": sum(len(r["elements"]) for r in scored),
             "n_deleted_events": sum(1 for r in scored for e in r["elements"]
                                     if e["kind"] == "event_delete"),
             "n_detected_own_segments": sum(1 for r in scored if r["detected_own_segments"]),
             "R5_miss_taxonomy": dict(collections.Counter(r["miss_R5"] for r in scored
                                                          if r["miss_R5"])),
             "per_room": {}}
        for p in ["R5_homeprov", "R5_homeprov_anchor_resolved", "R5_homeprov_closed",
                  "R4_component", "R2_segments",
                  "R1_1s", "R1_1min", "R1_1h", "R0_void"]:
            k = sum(1 for r in scored if r["status"][p] == "sound")
            ind = sum(1 for r in scored if r["status"][p] == "indeterminate")
            uns = sum(1 for r in scored if r["status"][p] == "unsound")
            a["soundness_" + p] = {**cp(k, len(scored)), "indeterminate": ind, "unsound": uns,
                                   "upper_if_indeterminate_sound": cp(k + ind, len(scored))}
        for room in ("porch", "hallway", "kitchen"):
            rr = [r for r in scored if r.get("room") == room]
            a["per_room"][room] = {"n": len(rr), "sound_R5": sum(
                1 for r in rr if r["status"]["R5_homeprov"] == "sound")}
        # per-trial quarantine attributable to the trial (R5 regions its elements touch)
        sizes = []
        for r in scored:
            regs = set()
            for e in r["elements"]:
                if e["lo"] is None:
                    continue
                for lo, hi in R5r_all:
                    if lo <= e["hi"] and e["lo"] < hi:
                        regs.add((lo, hi))
            q = {n.key for n in U if any(lo <= n.ts < hi for lo, hi in regs)}
            sizes.append({"Q": len(q), "Q_minus_T": len(q - T),
                          "regions": sorted(regs)})
        if sizes:
            qs = [s["Q"] for s in sizes]
            qm = [s["Q_minus_T"] for s in sizes]
            a["per_trial_R5_quarantine"] = {
                "what": "surviving nodes in the R5 regions that this trial's own tampered "
                        "elements fall in (regions may be shared with other trials)",
                "Q_mean": statistics.mean(qs), "Q_median": statistics.median(qs), "Q_max": max(qs),
                "Q_minus_T_mean": statistics.mean(qm), "Q_minus_T_median": statistics.median(qm),
                "Q_minus_T_max": max(qm),
                "region_widths_s": dict(collections.Counter(
                    hi - lo for s in sizes for lo, hi in s["regions"]))}
        # PER-TRIAL OVER-QUARANTINE (stage24 analogue: one forgery per instance).
        # Each policy is applied to the violations of the segments that contain this
        # trial's own tampered elements (second, its minute, its hour), with the same
        # U; numerator excludes every tampered key of the run.
        pt = {p: [] for p in POLICIES}
        pt_abs = {p: [] for p in POLICIES}
        for r in scored:
            mine = set()
            for e in r["elements"]:
                if e["lo"] is None:
                    continue
                for sec in range(int(e["lo"] // 1), int(e["hi"] // 1) + 1):
                    for g, w in W.items():
                        mine.add((g, str(int(sec * 1.0 // w))))
            vl = [v for v in viol if (v["gran"], v["seg"]) in mine]
            if not vl:
                for p in POLICIES:
                    pt[p].append(None)
                    pt_abs[p].append(None)
                continue
            nd, _iv, _rr = policies(vl)
            for p in POLICIES:
                pt[p].append(metrics.oq(nd[p], T, len(U)))
                pt_abs[p].append(len(nd[p] - T))
        a["per_trial_OQ"] = {
            "what": "each policy applied to the violated segments that contain this trial's "
                    "own tampered elements; mean over trials of |Q - T| / |U|",
            **{p: {"mean": (statistics.mean([x for x in v if x is not None])
                            if any(x is not None for x in v) else None),
                   "max": (max([x for x in v if x is not None])
                           if any(x is not None for x in v) else None),
                   "n_trials_with_own_violations": sum(1 for x in v if x is not None),
                   "Q_minus_T_mean": (statistics.mean([x for x in pt_abs[p] if x is not None])
                                      if any(x is not None for x in pt_abs[p]) else None)}
               for p, v in pt.items()}}
        arms[arm] = a

    write_time = {}
    for arm in WRITE_TIME_ARMS:
        rows = [t for t in all_trials if t.get("arm") == arm]
        if not rows:
            continue
        own, own_mech = [], []
        for t in rows:
            ts = row_ts(t)
            v = verd.get(("second", str(int(ts // 1)))) if ts else None
            own.append(None if v is None else v["violation"])
            if v is not None and v["violation"]:
                own_mech.append({"room": t.get("room"), "trial": t.get("trial"),
                                 "segment": str(int(ts // 1)), "mechanism": v["mechanism"],
                                 "delta_n": v["delta_n"]})
        write_time[arm] = {
            "n_trials": len(rows),
            "post_commit_edits": sum((t.get("operations_used") or {}).get("delete", 0) or 0
                                     for t in rows) or 0,
            "db_writes_reported": sorted({t.get("db_writes") for t in rows}, key=str),
            "own_second_anchored_and_violated": sum(1 for x in own if x),
            "own_second_violation_detail": own_mech,
            "own_second_anchored_not_violated": sum(1 for x in own if x is False),
            "own_second_not_verified": sum(1 for x in own if x is None),
            "status": "not localizable: write-time forgery leaves no post-commit edit, so "
                      "T is empty and there is nothing for a quarantine to cover; not scored"}

    # ---------------- benign-floor contribution (new counting rule)
    touched_viol = [v for v in viol if v["seg"] in new_t[v["gran"]]]
    floor_viol = [v for v in viol if v["seg"] not in new_t[v["gran"]]]
    nodes_t, _ivs_t, _r5t = policies(touched_viol) if touched_viol else ({p: set() for p in POLICIES}, {}, [])
    floor_contrib = {}
    for p in POLICIES:
        if p in ("R0_void", "R3_ceiling"):
            continue
        Qa, Qt = nodes_all[p], nodes_t.get(p, set())
        floor_contrib[p] = {
            "OQ_all_violations": metrics.oq(Qa, T, len(U)),
            "OQ_trial_touched_violations_only": metrics.oq(Qt, T, len(U)),
            "untampered_nodes_added_by_floor": len((Qa - Qt) - T),
            "untampered_nodes_removed_by_floor_subsumption": len((Qt - Qa) - T)}
    floor_segments = {g: sorted(({"segment": v["seg"], "mechanism": v["mechanism"],
                                  "delta_n": v["delta_n"]} for v in floor_viol if v["gran"] == g),
                                key=lambda x: x["segment"]) for g in W}

    viol_by_gran = collections.Counter(v["gran"] for v in viol)
    out = {
        "experiment": "R2 (S&P 2027): quarantine soundness and over-quarantine on the saved "
                      "real-deployment verifier snapshots",
        "run_id": run_id, "scheme": cfg["scheme"], "deviation": cfg.get("deviation"),
        "window": win, "published_result_kind": ("e_ps_detection" if is_det else "e_c_write_time"),
        "granularities": {
            "monitor_GRAN": list(W.items()),
            "anchored_in_window": an_me,
            "verified_in_window": {g: sum(1 for (gg, _s) in verd if gg == g) for g in W},
            "violated": {g: viol_by_gran.get(g, 0) for g in W}},
        "chain": chain_info,
        "reproduction_gates": gates,
        "all_gates_pass": all(v["match"] for v in gates.values()),
        "event_gap_check": gap_check,
        "deleted_event_time_bound_support": bound_support,
        "universe": {"definition": "surviving snapshot nodes (states + events, the monitor's "
                                   "load()) with ts in [span_lo, span_hi), the time span of the "
                                   "verified anchored segments",
                     "span_lo": span_lo, "span_hi": span_hi, "U": len(U),
                     "nodes_in_[t_start,t_end]": n_runwin},
        "T": {"n_keys": len(T), "n_surviving_in_U": len(T_surv),
              "n_deleted": len([k for k in T if k.startswith("e:")])},
        "over_quarantine": oq,
        "R5_regions_by_width_s": dict(collections.Counter(hi - lo for lo, hi in R5r_all)),
        "benign_floor": {"rule": "hp_d2/floor_rescore.py NEW counting rule",
                         "floor_new_rule": fn, "floor_old_rule": fo,
                         "floor_violations": floor_segments,
                         "contribution_by_policy": floor_contrib},
        "arms": arms,
        "write_time_arms": write_time,
        "trials": per_trial,
        "definitions": {
            "soundness": "trial sound iff every element it tampered (updated state rows: "
                         "snapshot ts; deleted events: id gap, ts interval [max(ULID(ctx), "
                         "ts(prev id)), min(ts(row_before), ts(next id))]) lies inside the policy's "
                         "quarantined time regions; R5 regions = localize.greedy_regions, "
                         "half-open [lo,hi) as metrics.lr_regions (R5_homeprov_closed: "
                         "stage24's closed-interval check); R1 = stage24 win(w) closed; R2 = "
                         "stage24 innermost() (minimum-width violated segments) closed; R0 = "
                         "[min ts, max ts] of U; R4 = R5 regions plus R4's node set "
                         "(DEVIATION: stage24 uses one hull interval over R4's nodes, which on a "
                         "multi-trial run spans the whole run and is vacuous)",
            "indeterminate": "a deleted event whose bounding interval is only partly quarantined",
            "over_quarantine": "metrics.oq: |Q - T| / |U|",
            "policies": {p: "stage24 pol_nodes['%s'] applied to U" % p for p in POLICIES},
            "verification": "e_c_write_time.verify_window semantics; first-write-wins roots "
                            "from chain records with payload ts in [t_start, "
                            "recorder_snapshot_at]; segments with start in [t_start-w, t_end+w]"},
        "provenance": {
            "script": os.path.abspath(__file__), "script_sha256": sha256_file(os.path.abspath(__file__)),
            "python": sys.version, "platform": platform.platform(),
            "git_head": git("rev-parse", "HEAD"),
            "exp_rig_dirty": bool(git("status", "--porcelain", "--", "exp/rig")),
            "exp_rig_status": git("status", "--porcelain", "--", "exp/rig"),
            "code_sha256": {p: sha256_file(os.path.join(REPO, p)) for p in (
                "exp/rig/localize.py", "exp/rig/metrics.py", "exp/rig/stats.py",
                "exp/stages/stage24_recon_baselines.py", "exp/stages/e_c_write_time.py")},
            **mon_info,
            "inputs": inputs,
            "sqlite_open": "file:<path>?mode=ro&immutable=1 (uri=True) for every open, "
                           "including the shipped monitor's load() via a sqlite3 shim",
            "load_since": since, "load_commit_seconds": round(load_s, 2),
            "started": t_begin, "finished": now(),
            "loadavg_1_5_15": list(os.getloadavg())},
    }
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1, default=str)
    print(json.dumps({"run": run_id, "gates": out["all_gates_pass"],
                      "gate_detail": {k: v["match"] for k, v in gates.items()},
                      "gap_check": gap_check["match"], "U": len(U),
                      "arms": {k: (v["soundness_R5_homeprov"]["k"], v["soundness_R5_homeprov"]["n"],
                                   v["soundness_R5_homeprov"]["indeterminate"])
                               for k, v in arms.items()},
                      "OQ": {p: round(oq[p]["OQ"], 6) for p in POLICIES}}))
    return dst


# ------------------------------------------------------------------ summary
def summary():
    dst = os.path.join(OUTDIR, "r2_localization_summary.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    rows, files = [], {}
    pooled = collections.defaultdict(lambda: [0, 0, 0])
    pooled_ar = collections.defaultdict(lambda: [0, 0])
    for run_id in RUNS:
        f = os.path.join(OUTDIR, "r2_%s_localization.json" % run_id)
        if not os.path.exists(f):
            rows.append({"run_id": run_id, "status": "no result file"})
            continue
        files[os.path.basename(f)] = sha256_file(f)
        d = json.load(open(f))
        admitted = d["all_gates_pass"] and d["event_gap_check"]["match"]
        for arm, a in d["arms"].items():
            s = a["soundness_R5_homeprov"]
            row = {"run_id": run_id, "scheme": d["scheme"], "arm": arm, "admitted": admitted,
                   "n_scored": a["n_scored"], "n_ground_truth_exact": a["n_ground_truth_exact"],
                   "R5_sound": [s["k"], s["n"]], "R5_ci95": [s.get("ci_lo"), s.get("ci_hi")],
                   "R5_indeterminate": s["indeterminate"], "R5_unsound": s["unsound"],
                   "R5_sound_anchor_resolved": [a["soundness_R5_homeprov_anchor_resolved"]["k"],
                                                a["soundness_R5_homeprov_anchor_resolved"]["n"]],
                   "R5_anchor_resolved_ci95": [a["soundness_R5_homeprov_anchor_resolved"].get("ci_lo"),
                                               a["soundness_R5_homeprov_anchor_resolved"].get("ci_hi")],
                   "per_trial_OQ_mean": {p: a["per_trial_OQ"][p]["mean"] for p in POLICIES},
                   "R4_sound": [a["soundness_R4_component"]["k"], a["soundness_R4_component"]["n"]],
                   "R2_sound": [a["soundness_R2_segments"]["k"], a["soundness_R2_segments"]["n"]],
                   "per_trial_R5_Q_minus_T_mean": (a.get("per_trial_R5_quarantine") or {}).get(
                       "Q_minus_T_mean")}
            rows.append(row)
            if admitted:
                for key in ((d["scheme"], "all_post_commit_arms"), (d["scheme"], arm)):
                    pooled[key][0] += s["k"]
                    pooled[key][1] += s["n"]
                    pooled[key][2] += s["indeterminate"]
                    sa = a["soundness_R5_homeprov_anchor_resolved"]
                    pooled_ar[key][0] += sa["k"]
                    pooled_ar[key][1] += sa["n"]
        rows.append({"run_id": run_id, "scheme": d["scheme"], "kind": "run",
                     "admitted": admitted, "gates": {k: v["match"] for k, v in
                                                     d["reproduction_gates"].items()},
                     "event_gap_check": d["event_gap_check"]["match"],
                     "U": d["universe"]["U"],
                     "OQ": {p: d["over_quarantine"][p]["OQ"] for p in POLICIES},
                     "Q_minus_T": {p: d["over_quarantine"][p]["Q_minus_T"] for p in POLICIES},
                     "floor_new_rule_second": [d["benign_floor"]["floor_new_rule"]["second"]["k"],
                                               d["benign_floor"]["floor_new_rule"]["second"]["n"]],
                     "R5_floor_contribution": d["benign_floor"]["contribution_by_policy"]["R5_homeprov"],
                     "R4_floor_contribution": d["benign_floor"]["contribution_by_policy"]["R4_component"],
                     "granularities": d["granularities"],
                     "write_time_arms": {k: {kk: v[kk] for kk in (
                         "n_trials", "own_second_anchored_and_violated")}
                         for k, v in d["write_time_arms"].items()}})
    s24f = os.path.join(OUT, "stage24_final.json")
    s25f = os.path.join(OUT, "stage25_final.json")
    s24 = json.load(open(s24f))
    s25 = json.load(open(s25f))
    det = [r for r in s24["rows"] if r.get("detected")]
    gen = {"stage24_final_sha256": sha256_file(s24f), "stage25_final_sha256": sha256_file(s25f),
           "stage24_n_detected_instances": len(det),
           "stage25_E13": {k: s25["E13_exhaustive"][k] for k in ("instances", "sound")}}
    for p in ("R5_homeprov", "R4_component", "R2_segments", "R1_1min", "R0_void"):
        gen[p] = {"mean_OQ_published": s24["summary"][p]["mean_OQ"],
                  "mean_Q_published": s24["summary"][p]["mean_Q"],
                  "mean_Q_minus_T_from_rows": statistics.mean(
                      round(r[p]["OQ"] * r["U"]) for r in det),
                  "mean_U_from_rows": statistics.mean(r["U"] for r in det)}
    out = {"experiment": "R2 summary", "rows": rows,
           "generated_deployment_reference": gen,
           "pooled_R5_soundness_admitted_runs": {
               "%s/%s" % k: {**cp(v[0], v[1]), "indeterminate": v[2]} for k, v in pooled.items()},
           "pooled_R5_soundness_anchor_resolved_admitted_runs": {
               "%s/%s" % k: cp(v[0], v[1]) for k, v in pooled_ar.items()},
           "result_files_sha256": files,
           "provenance": {"script": os.path.abspath(__file__),
                          "script_sha256": sha256_file(os.path.abspath(__file__)),
                          "python": sys.version, "git_head": git("rev-parse", "HEAD"),
                          "exp_rig_dirty": bool(git("status", "--porcelain", "--", "exp/rig")),
                          "written": now()}}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1, default=str)
    print(dst)


if __name__ == "__main__":
    if sys.argv[1:] == ["--summary"]:
        summary()
    elif len(sys.argv) == 2 and sys.argv[1] in RUNS:
        run_one(sys.argv[1])
    else:
        raise SystemExit("usage: r2_localize.py RUN_ID | --summary   RUN_ID in %s" % list(RUNS))
