"""E10b pre-registration: hypotheses, the prediction rule, the plan (with its sha256), outcomes, scoring, exclusions,
stopping rules, analysis plan, known limits, and the sha256 of every file the run executes or scores with.

    python3 testbed/e10b/e10b_prereg.py                       DRAFT -> exp/out/e10b_preregistration_draft.json (mode "x")
    python3 testbed/e10b/e10b_prereg.py --final               REGISTERED -> exp/out/e10b_preregistration.json (mode "x"),
                                                              then stamp it: ots stamp exp/out/e10b_preregistration.json
    python3 testbed/e10b/e10b_prereg.py --check exp/out/e10b_preregistration.json
                                                              {"ok": ...}: status REGISTERED and every file at its sha256

Neither mode overwrites a file. run_e10b.sh refuses the real run unless --check passes and the plan it generates has the
registered sha256. drafts/round13/E10B_DESIGN.md explains every choice.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.abspath(os.path.join(HERE, "..", ".."))
PAPER = os.path.join(R, "[READY] (TDSC) HOMEPROV - P13")
DESIGN = os.path.join(PAPER, "drafts", "round13", "E10B_DESIGN.md")
E10_REG = os.path.join(R, "exp", "out", "e10_preregistration.json")
E10_NOTES = os.path.join(PAPER, "drafts", "round13", "E10_RESULTS_NOTES.md")
BASIS = os.path.join(R, "exp", "out", "r16_e10_e10b_basis.json")
BASIS_SCRIPT = os.path.join(R, "exp", "sp2027", "r16_e10_e10b_basis.py")
COPYVIEW = os.path.join(R, "exp", "out", "r16_e10_copyview.json")
COPYVIEW_SCRIPT = os.path.join(R, "exp", "sp2027", "r16_e10_copyview.py")
DRAFT_OUT = os.path.join(R, "exp", "out", "e10b_preregistration_draft.json")
FINAL_OUT = os.path.join(R, "exp", "out", "e10b_preregistration.json")
sys.path.insert(0, HERE)
import e10b_plan as PL                       # noqa: E402

FILES = [
    # E10b's own code
    "testbed/e10b/run_e10b.sh", "testbed/e10b/e10b_plan.py", "testbed/e10b/e10b_score.py", "testbed/e10b/e10b_prereg.py",
    "testbed/e10b/test_e10b.py", "testbed/e10b/homeprov_e10b/__init__.py", "testbed/e10b/homeprov_e10b/manifest.json",
    # E10's stack, helpers and in-hub harness (frozen with E10; executed unchanged)
    "testbed/e10/e10_stack.sh", "testbed/e10/e10ops.py", "testbed/e10/e10_prereg.py", "testbed/e10/test_e10_patches.py",
    "testbed/real/ha-config/custom_components/homeprov_e10/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_e10/manifest.json",
    "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_ec/manifest.json",
    "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_e7/manifest.json",
    "testbed/real/ha-config/custom_components/homeprov_scenario/__init__.py",
    "testbed/real/mosquitto/mosquitto.conf",
    # the monitor and its image
    "monitor/monitor.py", "monitor/Dockerfile.sign", "monitor/requirements-sign.txt", "monitor/hardening_e10.patch",
    # the verifier and the scorer it is called through
    "exp/stages/e7_verify.py", "exp/stages/verifier_e10.patch", "exp/stages/e10_score.py", "exp/rig/stats.py",
    # markers, host log
    "exp/rig/marker_issuer.py", "exp/rig/markers.py", "testbed/e9/e9ops.py",
    # anchors and head witnesses
    "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py", "testbed/anchord/headwitness.py",
    "testbed/anchord/chainverify.py", "testbed/e8/anchord-e8.Dockerfile",
] + sorted(os.path.relpath(p, R) for p in glob.glob(os.path.join(R, "monitor", "test_*.py"))
           + glob.glob(os.path.join(R, "testbed", "anchord", "test_*.py")))


def h(p):
    if not os.path.exists(p):
        return None
    x = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            x.update(b)
    return x.hexdigest()


def basis_fields():
    """The E10 quantities the design uses, read from the basis file (exp/out/r16_e10_e10b_basis.json)."""
    if not os.path.exists(BASIS):
        return None
    b = json.load(open(BASIS))
    pol = b["polls_during_A1_BDT"]
    dr = b["dry_run_exploratory"]
    return {"file": "exp/out/r16_e10_e10b_basis.json", "sha256": h(BASIS),
            "script": {"file": "exp/sp2027/r16_e10_e10b_basis.py", "sha256": h(BASIS_SCRIPT)},
            "e10_delta_upper_bound_s": b["jitter"]["delta_upper_bound_s"],
            "e10_commit_s": b["jitter"]["commit_s"],
            "e10_poll_interval_s": {m: pol[m]["interval_s"] for m in pol},
            "e10_observation_window_s": {m: pol[m]["record_ts_minus_copy_at_s"] for m in pol},
            "three_over_median_poll_interval": {m: pol[m]["three_over_median_interval"] for m in pol},
            "e10_realised_collisions": {k: b["e10_collisions"][k] for k in ("n_pairs", "trials_in_a_pair")},
            "dry_run_on_e10_exploratory": {"what": "testbed/e10b/e10b_score.py on E10's 100 BDT trials, chains and 'del' "
                                                   "verifications (E10 was registered with another scoring; not a result)",
                                           "hypotheses": dr["summary"]["hypotheses"]},
            "e10_timeline": b["e10_timeline"], "e10_verify_wall_s": b["verify_wall_s"],
            "dry_run_scorer_version": {"e10b_score.py": b["code"]["testbed/e10b/e10b_score.py"],
                                       "note": "the dry run used this version; the registered scorer adds "
                                               "predict_late_view, score_late_view and one section of main() (H1b-late-"
                                               "view); every function the dry run exercised is unchanged"},
            "copy_view_exploratory": (None if not os.path.exists(COPYVIEW) else {
                "file": "exp/out/r16_e10_copyview.json", "sha256": h(COPYVIEW),
                "script": {"file": "exp/sp2027/r16_e10_copyview.py", "sha256": h(COPYVIEW_SCRIPT)},
                "summary": json.load(open(COPYVIEW))["summary"],
                "note": "H1b-late-view was derived from these E10 polls, so E10 cannot test it; E10b can"})}


RATIONALE = (
    "E10's A1-BDT arm (H1) was NOT MET as scored, and every deviation traced to the arm's plan and its registered "
    "scorer, not to the verifier (drafts/round13/E10_RESULTS_NOTES.md): with trials 15 s apart and ages 15, 30 and "
    "45 s, a later trial's forged row could land in the same or the neighbouring one-second segment as an earlier one; "
    "the registered row_outcome scored a trial as detected whenever its second was flagged, so a benign row in a second "
    "flagged by another trial's attributable row counted as detected; and the registered prediction ignored copy "
    "mode's observation window (a copy can capture a transaction still in flight). E10b re-runs the same arm on the "
    "same stack and monitors, spaced so that no two forged rows share or neighbour a second, and scores each trial from "
    "its own row, with the segment verdict as a consistency check. It is a confirmatory test of H1's stated boundary "
    "with the scorer fixed in advance; re-scoring E10's data with it is exploratory (the dry run in the basis file).")

HYPOTHESES = {
    "H1b_backdating_boundary_own_row": (
        "Per trial and monitor, the verdict on the trial's own forged row equals the outcome the E10b prediction rule "
        "gives from that monitor's own polls; every non-excluded trial whose prediction is not ambiguous agrees. "
        "Consequences per level (prediction_per_level): a row backdated by 5, 15 or 30 s is never attributable; 45 s is "
        "attributable in every trial; 33 s is attributable exactly in the trials in which the last poll lacking the "
        "row copied within the 3 s before the insertion."),
    "H1b_seg_segment_consistency": (
        "For every non-excluded trial and monitor, the own row is attributable if and only if its one-second segment "
        "is flagged."),
    "H1b_lb_lower_bound (secondary)": (
        "For every trial whose prediction is a non-ambiguous late verdict, the verifier's committed_after_lower_bound_s "
        "of the own row equals the predicted lower bound (max copy_at over the polls lacking the row, minus the row's "
        "timestamp) within 10 microseconds."),
    "H1b_late_view (secondary)": (
        "Copy mode takes its view of the -wal late in the copy: for every non-excluded copy-mode trial, the own-row "
        "outcome equals the prediction obtained when a copy whose observation window overlaps the write holds the row "
        "if and only if the copy ended (its record ts) after t_insert; reported in particular for the trials the "
        "primary rule calls ambiguous."),
    "H10b_clock_step_state_rows (secondary arm)": (
        "With homeprov_e10b's clock_step_all (time.time and homeassistant.helpers.entity.timer stepped), the hub's state "
        "rows and event rows written during a 60 s backward step and stamped more than 5 s before the step began are "
        "excused_clock_step under an operator CLOCK_STEP marker and attributable without one; a 10 s step leaves no "
        "attributable row in the step's key range and no flagged second in [t_on - 11 s, t_off + 1 s]."),
}

PREDICTION_RULE = {
    "views": "a poll lacks the forged row if its view of the recorder was taken before the insertion began "
             "(t_insert, the hub's time just before BEGIN IMMEDIATE), holds it if taken after COMMIT returned "
             "(t_commit), and may do either if the two overlap",
    "observation_window": {
        "direct": "[copy_at, copy_at]: the read transaction's snapshot is pinned by the first read right after copy_at "
                  "(monitor.py direct_snapshot)",
        "copy": "[copy_at, record ts]: copy_at is the copy's start; the copy reads the database file, then the -wal "
                "(where the trial's frames are), then the -shm, and the record's ts is taken right after; the WAL is "
                "read somewhere inside, and a copy can capture a transaction whose COMMIT has not returned yet "
                "(E10 DEL 69 investigation, exp/out/r16_e10_del69_overlap.json)",
        "ambiguous_s": "both windows widened by 50 ms on each side (E10's registered ambiguous_s)"},
    "evaluation": "every split of the overlapping polls into a lacking prefix and a holding rest is evaluated as the "
                  "verifier evaluates a late row (testbed/e10b/e10b_score.py _verdict_for, mirroring e7_verify.py "
                  "Timeline, ObservationBreaks and the late-row test)",
    "outcomes": {
        "no_evidence": "the first poll covering the row's second (through >= second + 1) holds the row, or no poll covers it",
        "detected": "max copy_at over the polls lacking the row, minus the row's timestamp, exceeds LATE_BOUND (30 s)",
        "unknown": "otherwise, no valid poll holds the row, or an observation break (unobservable, missing or backlogged "
                   "poll, monitor restart, more than GAP_S = 30 s between copies) lies between the last lacking and the "
                   "first holding poll",
        "reported_late": "otherwise"},
    "ambiguous": "the splits give more than one outcome, or the lower bound lies within 1 ms of 30 s: counted, left out "
                 "of agreement, observed outcome reported",
    "a_priori_bound": "a poll lacking the row copied before t_commit + 50 ms, so the predicted lower bound is below "
                      "age + (t_commit - t_insert) + 0.05 s: below 30 s at 5 and 15 s; at 30 s above 30 s only through a "
                      "poll whose view overlaps the insertion's own write (ambiguous by construction)",
}

PREDICTION_PER_LEVEL = {
    "5": "never detected: reported_late, or no_evidence when no poll lacking the row covered its second (copied at or "
         "after second + 1 before the insertion); unknown only after an observation break",
    "15": "never detected: reported_late (no_evidence only if no poll copied in the 14 s before the insertion)",
    "30": "never detected: reported_late; ambiguous when a poll's view overlaps the insertion's write window",
    "33": "detected iff the last poll lacking the row copied after t_insert - 3 s (a priori about 3/T of trials, T the "
          "monitor's poll interval; not a hypothesis); ambiguous when a copy-mode poll that copied in those 3 s "
          "overlaps the write",
    "45": "detected in every trial (some poll lacking the row copied in the 15 s before the insertion), unless a "
          "monitor did not observe in those 15 s",
}

ARMS = [
    {"id": "A1-BDT (H1b)", "n": "20 per age; ages 5, 15, 30, 33, 45 s (100, order from seed 20261024), 50 s apart",
     "what": "homeprov_e10 op bdt, unchanged (one forged 'unlocked' lock row per trial, timestamped age seconds before "
             "its insertion, attributed to a genuine automation run, old_state_id = the lock's latest genuine 'locked' "
             "row); 60 s wait before the first trial, as E10",
     "scored": "per trial and monitor against snap_bdt (taken right after the block), window [t0, snap_bdt]"},
    {"id": "A6-CS2 (H10b)", "n": "5 steps: 60 s with a CLOCK_STEP marker x3, 60 s without x1, 10 s without x1; 60 s "
                                 "each, 120 s apart (E10's steps)",
     "what": "homeprov_e10b op clock_step_all: E10's clock step with homeassistant.helpers.entity.timer stepped too; "
             "the operator's CLOCK_STEP marker (window [t - step, t]) posted 150 s before t, as E10",
     "scored": "against snap_cs_end, window [first t_on - 600 s, snap_cs_end]; runs after snap_bdt, so it cannot touch "
               "H1b's verification"},
]

OUTCOMES = {
    "primary": ["H1b: per-trial agreement of the own-row outcome with the prediction, per monitor; detection per level "
                "with exact 95% intervals; the disagreeing and the ambiguous trials listed",
                "H1b-seg: per-trial consistency of the own-row verdict with the segment verdict, per monitor"],
    "secondary": ["H1b-lb: lower-bound equality",
                  "H1b-late-view: agreement of the late-view prediction on copy-mode trials (all, and those the primary "
                  "rule calls ambiguous)",
                  "H10b: per step and table, the verdicts of the stepped rows against the prediction; the manipulation "
                  "check (state rows of the step's key range stamped more than 2 s before t_on)",
                  "E10's frozen prediction (e10_score.predicted_insertion) and E10's frozen segment-based outcome "
                  "(e10_score.row_outcome) on the same trials, against the own-row outcome",
                  "attack success by the frontend display rule per trial (stored by homeprov_e10)",
                  "floor: flagged seconds and attributable rows in [t0, final] that neither a BDT trial's own row nor a "
                  "clock step's key range explains (predicted 0)"],
    "exploratory": ["copy mode's observation instant: overlapping polls and whether they held the forged row (their "
                    "watermark), per trial",
                    "the realised minimum separation of the forged rows' timestamps"],
}

SCORING = {
    "own_row_outcome": "from the verifier's row verdicts for key s:<forged_state_id>: attributable -> detected, "
                       "benign_late -> reported_late, unobserved_late -> unknown, no verdict -> no_evidence (unknown "
                       "if its second has no root)",
    "segment_check": "the own row's second (floor of its timestamp) in flagged_seconds",
    "verifier": "exp/stages/e7_verify.py (E10's patched verifier, frozen) through exp/stages/e10_score.py verify_job, "
                "with E10's parameters (late bound 30 s, gap 30 s, purge keep 29 days, purge tolerance 60 s, restore "
                "tolerance 30 s, stable scheme, record signatures, operator key, escrow)",
    "scorer": "testbed/e10b/e10b_score.py --run-dir <run> --tag <tag> (writes <tag>_score.json, mode x)",
}

EXCLUSIONS = [
    "a trial the integration reports with err (no row, lock unavailable, no cover): listed, not scored",
    "a pair of trials whose forged rows' seconds are equal or adjacent (realised from their own timestamps): both "
    "excluded from H1b and H1b-seg, listed (the schedule makes this impossible while delta <= 8 s)",
    "a trial whose prediction is ambiguous: counted, left out of agreement, observed outcome reported",
    "a monitor whose verification failed: H1b not evaluable for that monitor (listed)",
    "a block during which the host log shows a wall-clock gap above 90 s, or a hub start without a harness cause, or a "
    "monitor restart: its trials are scored and reported separately, not pooled (as E10)",
    "smoke runs are not results",
]

STOPPING_RULES = [
    "a preflight failure (E10's frozen files or this registration's files changed, tests failing, image contents "
    "differing from the repository, plan sha256 differing) stops the run before any trial: no data",
    "no interim look at any verdict; the run is never stopped for an outcome",
    "an infrastructure failure (hub not writing, a monitor's seal not anchored within 5400 s, the bdt command not "
    "acknowledged within n * spacing + 1800 s, the SSD or Docker failing) leaves the run incomplete: reported as "
    "incomplete; at most one re-run under a new tag (e10b_main2), after an amendment registered and stamped before it "
    "starts; trials of an incomplete run are reported, never pooled with the re-run",
    "a failure of A6-CS2 does not affect H1b (snap_bdt is taken before it); H10b is then not evaluable",
]

ANALYSIS_PLAN = [
    "Both monitors are scored and reported separately; nothing is pooled across them",
    "H1b is met for a monitor only if every non-excluded trial with a non-ambiguous prediction agrees; any "
    "disagreement is reported with its trial (never averaged away); detection per level with exact 95% "
    "Clopper-Pearson intervals; no other hypothesis test",
    "H1b-seg is met for a monitor only if every non-excluded trial is consistent",
    "The secondary and exploratory outcomes are reported as such; E10's frozen rule and outcome serve as comparison only",
    "Every deviation from this registration (plan, parameters, code) is written to an amendment before it is used",
]

LIMITS = [
    "One scratch stack on one Mac with virtual devices (E10's configuration path: the lab configuration cloned "
    "read-only at run time, which may differ from E10's clone; E9's final recorder snapshot, sha256 recorded by "
    "e10_stack.sh); the hub and the monitors share Docker's VM clock",
    "Background load differs from E10's: the lab installation's own containers (hpr-hass, hpr-monitor, hpr-anchord) "
    "were running during E10 and are stopped during E10b (stopped 2026-10-24 to free memory for another project's run; "
    "the preflight records the count of running hpr-* containers); the other projects' runs on this Mac ended before "
    "E10b (2026-10-26 02:07Z and 02:20Z, by their end messages) and nothing else is scheduled during it",
    "HOMEPROV detects rewriting after the monitor sealed a segment; it does not prevent it: the forged rows stay in the "
    "recorder, and a row backdated by less than about 30 s plus the poll interval remains outside the guarantee by "
    "design (H1b tests that boundary, it does not move it)",
    "Copy mode's observation instant is resolved only to the copy's duration ([copy_at, record ts]); trials whose "
    "outcome depends on where the WAL was read are ambiguous and not scored",
    "The schedule assumes delta_i <= 8 s (time from a trial's start to its insertion); E10's upper bound is in the "
    "basis file; a realised violation is caught (exclusion), not prevented",
    "The 33 s detection share depends on the poll timing of this run; only the per-trial prediction is a hypothesis",
    "The clock step is emulated inside the hub's process (time.time and helpers.entity.timer), not a host clock step; "
    "helpers/event.py's time_tracker_timestamp (the scheduler's clock) is left unpatched on purpose; an integration "
    "binding time.time itself would keep real timestamps",
    "homeprov_e10b is unit-tested offline against Home Assistant 2026.2.3 (the newest release this Mac's Python 3.13 "
    "can install); the scratch hub runs 2026.7.4, whose helpers/entity.py (timer = time.time, time_now = timer() passed "
    "to async_set_internal) and core.py (Event: time.time()) were read from its PyPI wheel; the smoke checks it at run "
    "time (manipulation check)",
    "E10b runs after another project's long run on the same Mac; CPU contention would change poll intervals, which the "
    "prediction takes from the chain, not from an assumed interval",
]

ALTERNATIVES = [
    {"if": "the smoke's manipulation check finds no stepped state row in a step, or homeprov_e10b does not register "
           "clock_step_all", "then": "A6_CS2 and H10b are removed from the plan and the registration before --final"},
    {"if": "the smoke's realised delta (t_insert - t_started - spacing * i) exceeds 4 s",
     "then": "the spacing is raised to 60 s before --final (the plan and its sha256 change accordingly)"},
]

SMOKE = {
    "tag": "e10b_smoke1 (then e10b_smoke2, ... if needed); HPR_E10B_SMOKE=1; outputs under "
           "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/smoke_out; not results",
    "plan": "2 trials per level (10, 50 s apart), 2 clock steps (60 s with a marker, 60 s without)",
    "checks": ["the run completes and e10b_score.py writes a score", "every BDT trial without err; realised separation "
               ">= 2 s", "e10b_ready lists clock_step_all; manipulation check > 0 stepped state rows in both steps",
               "no REFUSING, no malformed event line, no TIMEOUT in auth_meta.log"],
}


def document(final):
    plan = PL.make_plan(PL.SEED)
    plan_text = json.dumps(plan, indent=1, sort_keys=True) + "\n"
    out = subprocess.run([sys.executable, os.path.join(HERE, "e10b_plan.py"), "plan", "--seed", str(PL.SEED)],
                         capture_output=True, text=True)
    if out.stdout != plan_text:
        raise SystemExit("REFUSING: e10b_plan.py plan does not print the plan this registration embeds")
    now = dt.datetime.now(dt.timezone.utc)
    pre = {
        "experiment": "E10b: E10's A1-BDT arm (H1) re-run with the trials 50 s apart and scored from each trial's own "
                      "row; H10's clock step with the hub's state rows stepped (secondary arm)",
        "status": "REGISTERED" if final else "DRAFT",
        "registered_at": now.isoformat() if final else None,
        "registered_before": "any event of the real run (tag e10b_main; run directory "
                             "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_main); smoke runs precede it and "
                             "are not results",
        "approval": {"pi": "2026-10-24 about 17:45Z, verbatim: 'Let's do it' (relayed by the coordinating session)"},
        "rationale": RATIONALE,
        "design": {"file": "drafts/round13/E10B_DESIGN.md", "sha256": h(DESIGN)},
        "relation_to_e10": {"e10_preregistration": {"file": "exp/out/e10_preregistration.json", "sha256": h(E10_REG)},
                            "e10_results_notes": {"file": "drafts/round13/E10_RESULTS_NOTES.md", "sha256": h(E10_NOTES)},
                            "unchanged": ["backdate levels and trials per level", "the in-hub op bdt", "the stack "
                                          "(e10_stack.sh up-lab, Home Assistant 2026.7.4, E9's final recorder)",
                                          "both monitors and their settings", "anchors, witnesses, signatures, escrow",
                                          "the verifier and its parameters", "the clock steps' sizes, markers, timing"],
                            "changed": ["spacing 15 s -> 50 s; seed 20261020 -> 20261024; BDT and CS only (no other arm)",
                                        "scored against snap_bdt, right after the BDT block (E10: snap_del, after DEL-PH)",
                                        "per-trial scoring from the own row (E10: the second flagged); the segment "
                                        "verdict is a consistency check",
                                        "the prediction rule takes copy mode's observation window into account and "
                                        "evaluates the verifier's own late-row logic (E10: copy_at < t_commit)",
                                        "clock_step_all steps helpers.entity.timer too; H10b scored on state and event "
                                        "rows (E10: op clock_step; H10 scored on state rows)",
                                        "stack prefix e10bs, witness ports 19986/19987, image tags :e10b (same "
                                        "Dockerfiles and contents)"]},
        "stacks": {"e10bs": "testbed/e10/e10_stack.sh up-lab e10bs (unchanged): broker, device simulator hpr-devices:1, "
                            "homeassistant/home-assistant:2026.7.4 on an internal network; configuration cloned "
                            "read-only from the lab volume homeprov-real_hpr-config; recorder = E9's final snapshot"},
        "monitors": {"both": "hardened monitor.py, stable columns, coverage, keylog, per-row binding, escrow, Ed25519 "
                             "record signatures, name-map digest, full-history initial seal, keylog rewind; linked "
                             "anchor each, head witness outside Docker's VM; PERIOD 5 s (E10)",
                     "M-direct": "HOMEPROV_READ=direct, HOMEPROV_QUICK_CHECK_EVERY=720",
                     "M-copy": "HOMEPROV_READ=copy, HOMEPROV_QUICK_CHECK_EVERY=1"},
        "parameters": {"late_bound_s": 30.0, "gap_s": 30.0, "ambiguous_s": 0.05, "boundary_eps_s": 0.001,
                       "period_s": 5.0, "spacing_s": PL.SPACING_S, "pre_wait_s": PL.PRE_WAIT_S,
                       "delta_max_s": PL.DELTA_MAX_S, "min_separation_s": PL.MIN_SEPARATION_S, "seed": PL.SEED,
                       "cs_band_s": 5.0, "start_window_utc": "04:50-23:30 (the scratch hub's 04:12 purge never inside)"},
        "schedule_arithmetic": {"argument": "start_j >= start_i + (j - i) * spacing (op_bdt waits for nxt = start + "
                                            "spacing); t_ins = start + delta; target = t_ins - age; so target_j - "
                                            "target_i >= (j - i) * spacing - delta_max - (age_j - age_i) >= 50 - 8 - 40 "
                                            "= 2 s, and a difference of 2 s or more puts the rows in seconds at least "
                                            "2 apart (neither shared nor adjacent)",
                                "registered_plan": plan["schedule"]},
        "plan": {"generated_by": "testbed/e10b/e10b_plan.py plan --seed %d" % PL.SEED,
                 "sha256": hashlib.sha256(plan_text.encode()).hexdigest(), "plan": plan},
        "hypotheses": HYPOTHESES, "prediction_rule": PREDICTION_RULE, "prediction_per_level": PREDICTION_PER_LEVEL,
        "arms": ARMS, "outcomes": OUTCOMES, "scoring": SCORING, "exclusions": EXCLUSIONS,
        "stopping_rules": STOPPING_RULES, "analysis_plan": ANALYSIS_PLAN, "known_limits_stated_in_advance": LIMITS,
        "registered_alternatives": ALTERNATIVES, "smoke": SMOKE, "basis": basis_fields(),
        "code_sha256": {"computed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "files": {f: h(os.path.join(R, f)) for f in FILES}},
    }
    if not final:
        pre["code_sha256"]["note"] = "DRAFT: the hashes to freeze are computed at --final, after the smoke runs"
    return pre


def check(path):
    pre = json.load(open(path))
    bad = [] if pre.get("status") == "REGISTERED" else ["status %r" % pre.get("status")]
    for f, s in pre["code_sha256"]["files"].items():
        if h(os.path.join(R, f)) != s:
            bad.append(f)
    print(json.dumps({"ok": not bad, "mismatch": bad}))
    return 0 if not bad else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--check")
    a = ap.parse_args()
    if a.check:
        return check(a.check)
    out = a.out or (FINAL_OUT if a.final else DRAFT_OUT)
    doc = document(a.final)
    if a.final:
        missing = [f for f, s in doc["code_sha256"]["files"].items() if s is None]
        if missing or doc["basis"] is None or doc["design"]["sha256"] is None:
            raise SystemExit("REFUSING --final: missing %s" % (missing or "the basis file or the design"))
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    with open(out, "x") as fh:                        # never overwrites (draft or final)
        fh.write(text)
    print("wrote", out, hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
