#!/usr/bin/env python3
"""E10b design basis, from E10's SAVED data only (no Docker): the quantities drafts/round13/E10B_DESIGN.md uses, and an
EXPLORATORY dry run of E10b's scoring code on E10's own BDT trials.

  jitter        per BDT trial, an upper bound of delta_i (the time from the trial's start to its t_insert):
                t_insert_i - t_started - spacing * i (op_bdt starts trial i no earlier than t_started + spacing * i);
                commit durations t_commit - t_insert; consecutive t_insert differences minus the spacing
  collisions    E10's realised target pairs whose one-second segments are equal or adjacent (e10b_plan.realised_separation)
  polls         per monitor, during E10's A1-BDT block: poll intervals (copy_at differences), observation-window lengths
                (record ts - copy_at), unobservable polls
  dry_run       testbed/e10b/e10b_score.py score_bdt/summarise_bdt on E10's 100 BDT trials, E10's chains (polls up to the
                snap_del snapshot) and E10's own 'del' verifications (the BDT trials were verified there): the E10b
                prediction, the own-row outcome, agreement, segment consistency, lower-bound equality. EXPLORATORY: E10
                was registered with another scoring; this only shows what E10b's scorer does on real data.
  timeline      E10's main-phase durations (stack, seals, install, A1 block, A6 block, freeze) and the verifier's wall
                time of every e10s verification (E10's score.log; two ran at a time), for E10b's time estimate

Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_e10b_basis.py [--run-dir DIR] [--out exp/out/r16_e10_e10b_basis.json]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
sys.path.insert(0, os.path.join(ROOT, "testbed", "e10b"))
import e10b_plan as P                 # noqa: E402
import e10b_score as SC               # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def dist(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    q = lambda f: xs[min(len(xs) - 1, int(f * (len(xs) - 1) + 0.5))]   # noqa: E731
    return {"n": len(xs), "min": xs[0], "median": q(0.5), "p90": q(0.9), "p99": q(0.99), "max": xs[-1]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_e10b_basis.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    run, inputs = a.run_dir, {}
    f_bdt = glob.glob(os.path.join(run, "e10", "*_bdt.json"))[0]
    inputs["bdt"] = {"path": f_bdt, "sha256": sha(f_bdt)}
    bdt = json.load(open(f_bdt))
    trials = [t for t in bdt["trials"] if not t.get("err")]
    spacing = float((bdt.get("command") or {}).get("spacing_s"))
    ev_path = os.path.join(run, "events.jsonl")
    inputs["events"] = {"path": ev_path, "sha256": sha(ev_path)}
    events = [json.loads(x) for x in open(ev_path) if x.strip().startswith("{")]

    # ---- jitter and commit durations
    U = [t["t_insert"] - bdt["t_started"] - spacing * t["trial"] for t in trials]
    diffs = [b["t_insert"] - a_["t_insert"] - spacing for a_, b in zip(trials, trials[1:])]
    commit = [t["t_commit"] - t["t_insert"] for t in trials]
    jitter = {"spacing_s": spacing, "t_started": bdt["t_started"],
              "delta_upper_bound_s": dist(U),
              "delta_upper_bound_note": "t_insert_i - t_started - spacing * i bounds delta_i from above (it also holds "
                                        "the op's name lookup before the first trial and any earlier overrun)",
              "consecutive_t_insert_diff_minus_spacing_s": dist(diffs), "commit_s": dist(commit),
              "commit_above_0_05_s": sum(1 for c in commit if c > 0.05)}

    # ---- E10's realised collisions
    sep = P.realised_separation([t["forged_row_ts"] for t in trials])
    collisions = {"pairs": [[trials[i]["trial"], trials[j]["trial"]] for i, j in sep["collisions"]],
                  "n_pairs": len(sep["collisions"]),
                  "trials_in_a_pair": sorted({trials[i]["trial"] for pr in sep["collisions"] for i in pr}),
                  "min_gap_between_targets_s": sep["min_gap_s"]}

    # ---- the snapshot the BDT trials were verified against, and E10's polls up to it
    snap = next(e for e in events if e.get("type") == "snapshot" and e.get("label") == "snap_del" and e.get("ok"))
    tsnap = snap["t_snapshot"]
    blk = {(e.get("type"), e.get("block")): e["ts"] for e in events if e.get("type") in ("block_begin", "block_end")}
    w0, w1 = min(t["t_insert"] for t in trials) - 60, max(t["t_commit"] for t in trials) + 60
    polls, pstats, V = {}, {}, {}
    vfiles = sorted(os.listdir(os.path.join(run, "verify")))
    for m in ("direct", "copy"):
        ch = os.path.join(run, "e10s", "%s_chain.jsonl" % m)
        inputs["%s_chain" % m] = {"path": ch, "sha256": sha(ch)}
        polls[m] = SC.chain_polls(ch, tsnap)
        win = [p for p in polls[m] if p.get("copy_at") is not None and w0 <= p["copy_at"] <= w1]
        cat = sorted(p["copy_at"] for p in win)
        pstats[m] = {"window": [w0, w1], "polls": len(win),
                     "unobservable": sum(1 for p in win if p.get("unobservable")),
                     "interval_s": dist([b - a_ for a_, b in zip(cat, cat[1:])]),
                     "record_ts_minus_copy_at_s": dist([(p.get("ts") or p["copy_at"]) - p["copy_at"] for p in win])}
        iv = pstats[m]["interval_s"]
        # the a priori share of 33 s trials detected: a lacking poll copied within the 3 s before the insertion
        pstats[m]["three_over_median_interval"] = (3.0 / iv["median"]) if iv else None
        vf = [x for x in vfiles if re.match(r"^e10s_%s_del_[0-9a-f]{12}\.json$" % m, x)]
        if len(vf) != 1:
            raise SystemExit("expected one del verification for %s, found %s" % (m, vf))
        vp = os.path.join(run, "verify", vf[0])
        inputs["%s_verify_del" % m] = {"path": vp, "sha256": sha(vp)}
        V[m] = json.load(open(vp))

    # ---- EXPLORATORY dry run of the E10b scorer on E10's trials
    sec = SC.score_bdt(trials, polls, V)
    summ = SC.summarise_bdt(sec)
    dis = {m: [{"trial": r["trial"], "age_s": r["age_s"], "excluded": r["excluded"], "predicted": r[m]["predicted"],
                "observed": r[m]["observed"]["outcome"], "alternatives": r[m]["alternatives"],
                "overlap_polls_held_row": r[m]["overlap_polls_held_row"]}
               for r in sec["per_trial"] if r[m]["agrees"] is False or r[m]["predicted"] == "ambiguous"
               or r[m]["segment_consistent"] is False]
           for m in ("direct", "copy")}
    inflight = {m: {"overlap_polls": sum(len(r[m]["overlap_polls_held_row"]) for r in sec["per_trial"]),
                    "overlap_polls_holding_the_row": sum(1 for r in sec["per_trial"] for x in r[m]["overlap_polls_held_row"]
                                                         if x["held_row"])} for m in ("direct", "copy")}

    # ---- E10 timeline and verification wall times
    def first(typ, **kw):
        for e in events:
            if e.get("type") == typ and all(e.get(k) == v for k, v in kw.items()):
                return e
        return None
    seals = [e for e in events if e.get("type") == "initial_seal" and str(e.get("monitor", "")).startswith("e10s-")]
    tl = {"phase_main_begin": (first("phase_begin", phase="main") or {}).get("ts"),
          "stack_up": (first("stack_up", stack="e10s") or {}).get("ts"),
          "initial_seal_wait_s": {e["monitor"]: e.get("wait_s") for e in seals},
          "e10_installed": (first("e10_installed") or {}).get("ts"),
          "snapshot_start": (first("snapshot", stack="e10s", label="start") or {}).get("ts"),
          "A1_BDT_s": (blk.get(("block_end", "A1_BDT"), 0) - blk.get(("block_begin", "A1_BDT"), 0)) or None,
          "A6_CS_s": (blk.get(("block_end", "A6_CS"), 0) - blk.get(("block_begin", "A6_CS"), 0)) or None,
          "snapshot_final": (first("snapshot", stack="e10s", label="final") or {}).get("ts"),
          "phase_main_end": (first("phase_end", phase="main") or {}).get("ts")}
    if tl["phase_main_begin"] and tl["snapshot_start"]:
        tl["setup_s"] = tl["snapshot_start"] - tl["phase_main_begin"]
    if tl["snapshot_final"] and tl["phase_main_end"]:
        tl["freeze_s"] = tl["phase_main_end"] - tl["snapshot_final"]
    walls = {}                                       # E10's score.log: "  e10s/<monitor>/<label>  ok (<s>s)"
    slog = os.path.join(run, "score.log")
    inputs["score_log"] = {"path": slog, "sha256": sha(slog)}
    for line in open(slog, errors="replace"):
        mm = re.match(r"^\s+e10s/(direct|copy)/(\S+)\s+ok \(([0-9.]+)s\)", line)
        if mm:
            walls["%s/%s" % (mm.group(1), mm.group(2))] = float(mm.group(3))

    out = {"what": "E10b design basis from E10's saved data; dry_run is EXPLORATORY",
           "script": {"path": "exp/sp2027/r16_e10_e10b_basis.py", "sha256": sha(os.path.abspath(__file__))},
           "code": {"testbed/e10b/e10b_score.py": sha(SC.__file__), "testbed/e10b/e10b_plan.py": sha(P.__file__)},
           "inputs": inputs, "jitter": jitter, "e10_collisions": collisions, "polls_during_A1_BDT": pstats,
           "dry_run_exploratory": {"snapshot": "snap_del", "t_snapshot": tsnap, "summary": summ,
                                   "realised_separation": sec["realised_separation"],
                                   "disagreeing_ambiguous_or_inconsistent": dis, "overlap_polls": inflight},
           "e10_timeline": tl, "verify_wall_s": walls,
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    text = json.dumps(out, indent=1, default=str) + "\n"
    with open(a.out, "x") as fh:
        fh.write(text)
    print("wrote", a.out, hashlib.sha256(text.encode()).hexdigest())


if __name__ == "__main__":
    main()
