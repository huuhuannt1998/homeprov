"""E7 -- aggregate and score the coverage-gap, backdating and anchor-stall run.

This is the ORCHESTRATOR. The authoritative verification is exp/stages/e7_verify.py
(the monitor/verifier agent's tool): watermark-aware violation, empty-sealed-time
with LATE_BOUND, heartbeat/stall gaps with GAP_S, escrow recovery, the restored
copy, per-arm scoring and the benign floor. This file:

  1. runs e7_verify over the CLOSURE monitor's chain (with --escrow and
     --restore-out) and over the STABLE-columns monitor's chain, both with the
     PRE-REGISTERED parameters LATE_BOUND = 30 s and GAP_S = 30 s (lead,
     2026-10-08), and records them;
  2. adds the parts e7_verify does not cover: the per-poll monitor cost (copy,
     load, commit, append) from the closure monitor's own cost log; the STALL
     arm's live measurement (did the monitor's appends keep succeeding during the
     stall, and the anchor stay responsive); and the OUTAGE arm summary;
  3. folds in the recovery RENDER (e7_recovery_render.json), produced by the run
     script in a throwaway Home Assistant container on e7_verify's --restore-out
     copy, which answers how many laundered/swapped trials show the true author
     again (e7_verify makes and checks the copy but does not run HA's logbook).

Usage (the run script calls it; it can also be run offline on a saved run dir):
    E7_SP=<run dir> python3 exp/stages/e7_score.py --tag e7_main porch hallway kitchen
Writes exp/out/<tag>_score.json. Never overwrites.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")
E7_VERIFY = os.path.join(HERE, "e7_verify.py")

# PRE-REGISTERED verifier parameters (lead, 2026-10-08). Fixed before the run.
LATE_BOUND = float(os.environ.get("E7_LATE_BOUND", "30"))
GAP_S = float(os.environ.get("E7_GAP_S", "30"))


def run_e7_verify(chain, db, t0, t1, tsnap, trials, scheme=None, escrow=None,
                  restore_out=None, out_path=None):
    """Invoke exp/stages/e7_verify.py and return its parsed JSON."""
    cmd = [sys.executable, E7_VERIFY, "verify", "--chain", chain, "--db", db,
           "--late-bound", str(LATE_BOUND), "--gap-s", str(GAP_S),
           "--snapshot-at", str(tsnap), "--window", str(t0), str(t1)]
    if scheme:
        cmd += ["--scheme", scheme]
    if escrow and os.path.exists(escrow):
        cmd += ["--escrow", escrow]
    if restore_out:
        cmd += ["--restore-out", restore_out]
    if trials:
        cmd += ["--trials", *trials]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if out_path:
        try:
            with open(out_path, "w") as fh:
                fh.write(r.stdout)
        except OSError:
            pass
    if r.returncode != 0:
        return {"error": "e7_verify failed", "rc": r.returncode,
                "stderr": r.stderr[-2000:], "cmd": " ".join(cmd)}
    try:
        return json.loads(r.stdout)
    except ValueError as exc:
        return {"error": "e7_verify output not JSON: %r" % exc,
                "stdout_tail": r.stdout[-2000:], "stderr": r.stderr[-1000:]}


def chain_recv_ts(chain_path):
    """(seq, recv_ts) for every record, for the STALL appends-in-window check."""
    out = []
    try:
        with open(chain_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                p = r.get("payload") or {}
                out.append((r.get("seq"), r.get("recv_ts") or p.get("ts")))
    except OSError:
        pass
    return out


def monitor_cost(cost_log, fallback_stdout_log=None):
    """Per-poll copy/load/commit/append cost: median, p90, max, from the monitor's
    dedicated cost log (HOMEPROV_COST_LOG), falling back to the per-poll JSON lines
    printed on stdout (which carry copy/load/commit but not append)."""
    def q(xs, p):
        if not xs:
            return None
        xs = sorted(xs)
        k = (len(xs) - 1) * p
        lo = int(k)
        hi = min(lo + 1, len(xs) - 1)
        return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)

    src = cost_log if (cost_log and os.path.exists(cost_log)) else fallback_stdout_log
    if not src or not os.path.exists(src):
        return {"available": False}
    cols = {k: [] for k in ("copy_ms", "load_ms", "commit_ms", "append_ms", "total_ms")}
    with open(src, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if "copy_ms" not in d:
                continue
            c, l, m = d.get("copy_ms") or 0, d.get("load_ms") or 0, d.get("commit_ms") or 0
            a = d.get("append_ms")
            cols["copy_ms"].append(c); cols["load_ms"].append(l); cols["commit_ms"].append(m)
            if a is not None:
                cols["append_ms"].append(a)
            cols["total_ms"].append(c + l + m + (a or 0))
    n = len(cols["total_ms"])
    if not n:
        return {"available": True, "n_polls": 0, "source": os.path.basename(src)}
    return {"available": True, "n_polls": n, "source": os.path.basename(src),
            "per_poll_ms": {k: {"median": q(v, 0.5), "p90": q(v, 0.9), "max": round(max(v), 3)}
                            for k, v in cols.items() if v}}


def stall_extras(trials, closure_chain, stalls):
    """For STALL trials: appends during each stall window (closure chain records
    whose recv_ts falls inside it), and whether the anchor stayed responsive.
    With the hardened anchor the expected result is appends kept flowing (chain
    grew in the window) and no stall interval overlapped it."""
    recv = [t for (_s, t) in chain_recv_ts(closure_chain) if t]
    srows = [t for t in trials if t.get("arm") == "STALL" and not (t.get("err") or t.get("error"))]
    appends = []
    responsive = 0
    overlapped = 0
    intervals = stalls if isinstance(stalls, list) else ((stalls or {}).get("intervals") or [])
    for t in srows:
        sw = t.get("stall_window") or {}
        lo, hi = sw.get("start_ts"), sw.get("release_ts")
        if lo and hi:
            appends.append(sum(1 for x in recv if lo <= x <= hi))
            for iv in intervals:
                a, b = iv.get("from_ts"), iv.get("to_ts")
                if a is not None and b is not None and a <= hi and b >= lo:
                    overlapped += 1
                    break
        if t.get("anchor_responsive_during_stall"):
            responsive += 1
    return {"n_stall_trials": len(srows),
            "appends_during_stall": {"min": min(appends) if appends else None,
                                     "median": int(statistics.median(appends)) if appends else None,
                                     "max": max(appends) if appends else None,
                                     "n_trials_with_any_append": sum(1 for a in appends if a > 0)},
            "anchor_responsive_during_stall": responsive,
            "stall_intervals_overlapping_a_trial_window": overlapped,
            "connections_opened_total": sum(t.get("connections_opened_total", 0) for t in srows),
            "connections_cut_by_server": sum(t.get("connections_cut_by_server", 0) for t in srows),
            "expected_with_hardened_anchor": "appends keep succeeding (any_append > 0 for every "
                                             "trial), the anchor stays responsive, and no stall "
                                             "interval overlaps a trial window"}


def outage_summary(trials, closure_verify):
    """OUTAGE trials: how many had their edited second sealed during an
    anchor_unreachable interval (frozen root, anchored after the outage with its
    sealed_at) and the edit detected (e7_verify's per-arm score)."""
    orows = [t for t in trials if t.get("arm") == "OUTAGE" and not (t.get("err") or t.get("error"))]
    arm = (closure_verify.get("arms") or {}).get("OUTAGE") or {}
    stalls = closure_verify.get("stalls") or []
    frozen = 0
    for t in orows:
        sec = str(t.get("edited_second"))
        if any(iv.get("kind") == "anchor_unreachable" and sec in (iv.get("seconds_sealed_during") or [])
               for iv in stalls):
            frozen += 1
    return {"n_valid": len(orows), "simulated_outage": True,
            "edited_second_sealed_during_anchor_outage": frozen,
            "anchor_unreachable_intervals": sum(1 for iv in stalls if iv.get("kind") == "anchor_unreachable"),
            "e7_detected": arm.get("e7_detected"), "e7_detected_ci": arm.get("e7_detected_ci"),
            "note": "the run script paused this run's e7 anchor (never the stock anchor) while the "
                    "monitor sealed the edited row's second; the frozen root is anchored on unpause "
                    "with sealed_at and the edit is a detected violation"}


def load_trials(tag, rooms):
    trials, files = [], []
    for room in rooms:
        for pat in ("%s_report_%s.json" % (tag, room), "%s_outage_%s.json" % (tag, room)):
            f = os.path.join(OUT, pat)
            if os.path.exists(f):
                files.append(f)
                d = json.load(open(f))
                for t in d.get("trials", []):
                    t["room"] = room
                    trials.append(t)
    return trials, files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="e7")
    ap.add_argument("--run-dir", default=os.environ.get("E7_SP", ""))
    ap.add_argument("rooms", nargs="*")
    args = ap.parse_args()
    tag = args.tag
    sp = args.run_dir
    rooms = args.rooms or ["porch", "hallway", "kitchen"]

    def rf(name):
        return os.path.join(sp, name) if sp else name

    snapshot = rf("recorder.db")
    closure_chain = rf("closure_chain.jsonl")
    stable_chain = rf("stable_chain.jsonl")
    escrow = rf(os.path.join("escrow", "escrow.jsonl"))
    cost_log = rf("closure_cost.jsonl")
    closure_stdout = rf("closure_monitor.log")
    restored = rf("restored_closure.db")

    t0 = float(open(os.path.join(OUT, "%s_t_start" % tag)).read().strip())
    t1 = float(open(os.path.join(OUT, "%s_t_end" % tag)).read().strip())
    tsnap = os.path.getmtime(snapshot) if os.path.exists(snapshot) else t1 + 300

    trials, report_files = load_trials(tag, rooms)
    if not trials:
        raise SystemExit("no per-room E7 reports found under tag %r" % tag)

    # 1. Authoritative verification, both monitors, pre-registered parameters.
    closure_v = run_e7_verify(closure_chain, snapshot, t0, t1, tsnap, report_files,
                              scheme="closure", escrow=escrow, restore_out=restored,
                              out_path=rf("closure_verify.json"))
    stable_v = None
    if os.path.exists(stable_chain) and os.path.getsize(stable_chain) > 0:
        stable_v = run_e7_verify(stable_chain, snapshot, t0, t1, tsnap, report_files,
                                 scheme=None, out_path=rf("stable_verify.json"))

    # 2. Cost, stall extras, outage summary.
    cost = monitor_cost(cost_log, closure_stdout)
    stalls = (closure_v.get("stalls") if isinstance(closure_v, dict) else None)
    stall = stall_extras(trials, closure_chain, stalls)
    outage = outage_summary(trials, closure_v if isinstance(closure_v, dict) else {})

    # 3. Recovery render (produced by the run script in an e7r- container).
    recov_render = None
    rr = rf("e7_recovery_render.json")
    if os.path.exists(rr):
        try:
            recov_render = json.load(open(rr))
        except ValueError:
            recov_render = {"error": "recovery render file not JSON"}

    result = {
        "experiment": "E7",
        "tag": tag,
        "what": "coverage-gap (forced ambiguity), backdating into empty sealed time, "
                "anchor-stall (live) and anchor-outage (simulated) arms on the real "
                "deployment, scored by e7_verify under the E7 closure monitor "
                "(watermark + sealed-through + escrow) and a stable-columns monitor",
        "pre_registered_parameters": {
            "late_bound_s": LATE_BOUND, "gap_s": GAP_S,
            "fixed_before_run_by": "the lead, 2026-10-08",
            "backdating_min_age_rule": "each backdating trial inserts its row at "
                                       "least ~120 s before now (row_age_s recorded "
                                       "per trial), older than LATE_BOUND + one poll"},
        "window": {"t_start": t0, "t_end": t1, "duration_s": round(t1 - t0, 1),
                   "recorder_snapshot_at": tsnap},
        "rooms": rooms, "report_files": [os.path.relpath(f, ROOT) for f in report_files],
        "closure_monitor": {
            "scheme": "closure", "verifier": "exp/stages/e7_verify.py",
            "arms": (closure_v.get("arms") if isinstance(closure_v, dict) else None),
            "benign_floor": (closure_v.get("benign_floor") if isinstance(closure_v, dict) else None),
            "stalls": (closure_v.get("stalls") if isinstance(closure_v, dict) else None),
            "recovery": (closure_v.get("recovery") if isinstance(closure_v, dict) else None),
            "chain": (closure_v.get("chain") if isinstance(closure_v, dict) else None),
            "verify_error": (closure_v.get("error") if isinstance(closure_v, dict) else None),
            "per_poll_cost": cost},
        "stable_monitor": ({
            "scheme": (stable_v.get("params", {}).get("scheme") if isinstance(stable_v, dict) else None),
            "arms": (stable_v.get("arms") if isinstance(stable_v, dict) else None),
            "benign_floor": (stable_v.get("benign_floor") if isinstance(stable_v, dict) else None),
            "verify_error": (stable_v.get("error") if isinstance(stable_v, dict) else None)}
            if stable_v else {"available": False, "note": "no stable-columns chain"}),
        "stall_arm": stall,
        "outage_arm": outage,
        "recovery_render": recov_render or {"available": False,
                                            "note": "no e7_recovery_render.json; the run script "
                                                    "renders e7_verify's --restore-out copy in a "
                                                    "throwaway e7r- Home Assistant container"},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    path = os.path.join(OUT, "%s_score.json" % tag)
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)

    print("\n== E7 score (LATE_BOUND=%.0fs GAP_S=%.0fs) ==" % (LATE_BOUND, GAP_S))
    ca = result["closure_monitor"]["arms"] or {}
    if result["closure_monitor"]["verify_error"]:
        print("  closure verify ERROR:", result["closure_monitor"]["verify_error"])
    for arm in ("INS-L", "INS-M", "BD-S", "BD-M", "BD-PARK", "BD-JOIN", "BD-GAP", "STALL", "OUTAGE"):
        a = ca.get(arm)
        if not a:
            continue
        print("  %-7s n=%-3d e7_detected=%d  existing: flagged=%d attributable=%d ambiguous=%d"
              % (arm, a["n"], a["e7_detected"], a["existing_flagged"],
                 a["existing_attributable"], a["existing_ambiguous"]))
    bf = result["closure_monitor"]["benign_floor"] or {}
    print("  benign floor (closure): violated %s / %s untouched anchored seconds"
          % (bf.get("violated"), bf.get("untouched_anchored_seconds")))
    print("  stall: appends/window %s, anchor_responsive %d/%d, intervals overlapping %d"
          % (stall["appends_during_stall"], stall["anchor_responsive_during_stall"],
             stall["n_stall_trials"], stall["stall_intervals_overlapping_a_trial_window"]))
    if cost.get("available") and cost.get("per_poll_ms"):
        print("  per-poll cost (ms):", {k: v.get("median") for k, v in cost["per_poll_ms"].items()})
    if recov_render:
        print("  recovery render:", {k: recov_render.get(k) for k in
                                      ("true_author_recovered", "n_trials") if k in recov_render})
    print("  -> %s" % path)
    return result


if __name__ == "__main__":
    main()
