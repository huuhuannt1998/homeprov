"""E10 pre-registration: writes the draft (default) or the registered file (--final) from the run's parameters, the plan
testbed/e10/e10ops.py generates from the registered seed, and the sha256 of every file the run executes or scores with;
--check verifies a registered file against the working tree (run_e10.sh's preflight).

    <home>/miniconda3/bin/python3 testbed/e10/e10_prereg.py --out "<PAPER>/drafts/round13/E10_PREREG_DRAFT.json"
    <home>/miniconda3/bin/python3 testbed/e10/e10_prereg.py --final --out exp/out/e10_preregistration.json
    <home>/miniconda3/bin/python3 testbed/e10/e10_prereg.py --check exp/out/e10_preregistration.json
After --final: ots stamp exp/out/e10_preregistration.json (OpenTimestamps, as E9), then ots upgrade a few hours later.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
PAPER = R + "/[READY] (TDSC) HOMEPROV - P13"
sys.path.insert(0, os.path.join(R, "testbed", "e10"))
import e10ops  # noqa: E402

SEED = 20261020
FILES = [
    # the monitor and the verifier as E10 runs them (both patches applied), the E9 versions kept byte for byte, patches
    "monitor/monitor.py", "monitor/monitor_e9.py", "monitor/hardening_e10.patch", "monitor/Dockerfile.sign",
    "monitor/requirements-sign.txt", "exp/stages/e7_verify.py", "exp/stages/e7_verify_e9.py",
    "exp/stages/verifier_e10.patch",
    # anchors, witness, chain checks (unchanged since E9)
    "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py", "testbed/anchord/headwitness.py",
    "testbed/anchord/chainverify.py", "testbed/e8/anchord-e8.Dockerfile",
    # operator markers (unchanged), the E9 helpers E10 imports (unchanged)
    "exp/rig/marker_issuer.py", "exp/rig/markers.py", "testbed/e9/e9ops.py",
    # E10 harness, stacks, plan, scorer, outcome rule, offline checks, generator
    "testbed/e10/run_e10.sh", "testbed/e10/e10_stack.sh", "testbed/e10/e10ops.py", "testbed/e10/fresh_configuration.yaml",
    "testbed/e10/e10_prereg.py", "testbed/e10/reverify_patched.py", "exp/stages/e10_score.py",
    "exp/stages/e10_outcome.py", "exp/stages/e10_collusion.py", "exp/stages/e10_migration_offline.py",
    # rules E10's scoring reuses: the display rule's source, the E9 outcome rule (frozen), the E8/E9 scorers it imports
    "exp/sp2027/r14c_e8_attack_success.py", "exp/stages/e9_dishonest_anchor.py", "exp/stages/e9_score.py",
    "exp/stages/e8_score.py",
    # the in-hub integrations (never released): homeprov_e10, and homeprov_ec / homeprov_e7 as its import dependencies
    "testbed/real/ha-config/custom_components/homeprov_e10/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_e10/manifest.json",
    "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py",
    "testbed/real/ha-config/custom_components/homeprov_scenario/__init__.py",
    # tests the preflight runs
    "monitor/test_coverage.py", "monitor/test_node_hash.py", "monitor/test_e9.py", "monitor/test_e9_dishonest.py",
    "testbed/anchord/test_anchor_chain.py", "testbed/anchord/test_anchor_e8.py", "testbed/anchord/test_anchor_e9.py",
    "testbed/anchord/test_anchor_cache.py", "testbed/anchord/test_anchor_stall.py", "testbed/e10/test_e10_patches.py",
    # review r5 additions (drafts/round13/E10_ADDENDUM_R5.md): S and R in run_e10.sh; C, D, E in run_e10_r5.sh
    "exp/stages/e10r5_score.py", "testbed/e10/run_e10_r5.sh", "testbed/e10/run_dz_switchtype.sh",
    "testbed/e10/dz_switchtype.py", "exp/stages/e10_dz_switchtype.py", "exp/stages/dz_detection.py",
    "exp/stages/dz_offline_checks.py", "testbed/domoticz/monitor/dz_monitor.py", "testbed/domoticz/harness/dz_api.py",
    "testbed/domoticz/run_dz.sh", "reproduce/verify_all.py", "exp/stages/e10_pairwise_closure.py",
    "exp/stages/e8_closure_real.py", "exp/out/e8_closure_real.json", "exp/sp2027/e10_pi4_cost.py",
    "exp/sp2027/e9_cost_scale.py", "testbed/e10/test_e10_r5.py",
]
DESIGN = PAPER + "/drafts/round13/E10_DESIGN.md"
ADDENDUM = PAPER + "/drafts/round13/E10_ADDENDUM_R5.md"
sys.path.insert(0, os.path.join(R, "exp", "stages"))
sys.path.insert(0, os.path.join(R, "exp", "sp2027"))


def h(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None


def r5_plans():
    """The review-r5 arms' registered plans that are fixed offline: arm D's units (from exp/out/e8_closure_real.json and
    the seed) and arm E's run matrix and profiles."""
    import e10_pairwise_closure as P            # noqa: PLC0415
    import e10_pi4_cost as C                    # noqa: PLC0415
    e8 = json.load(open(os.path.join(R, "exp", "out", "e8_closure_real.json")))
    p = P.make_plan(e8)
    text = json.dumps(p, sort_keys=True)
    return {"D_pairwise": {"generated_by": "exp/stages/e10_pairwise_closure.py make_plan (seed %d)" % P.SEED,
                           "sha256": hashlib.sha256(text.encode()).hexdigest(), "population": p["population"],
                           "units_per_stratum": p["units_per_stratum"], "n_v": p["n_v"], "n_x": p["n_x"],
                           "cap_s": p["cap_s"], "cross_window_s": p["cross_window_s"],
                           "pristine_sha256": e8["plan"]["pristine_sha256"]},
            "E_pi4_cost": {"matrix": [C.tag_of(*m) for m in C.MATRIX], "profiles": C.PROFILES,
                           "assumed_values": C.ASSUMED, "image": C.IMAGE}}


def document(final):
    plan = e10ops.make_plan(SEED)
    plan_text = json.dumps(plan, indent=1, sort_keys=True) + "\n"
    now = dt.datetime.now(dt.timezone.utc)
    pre = {
        "experiment": ("E10: adaptive arms on the stated boundaries of the deployed configuration (backdated "
                       "insertions inside the late-commit window, deletions inside the observation window, a "
                       "phase-aware deletion, a reused lower key, deletions around a declared purge, sustained "
                       "unobservability of the direct-read monitor, the verifier gaps D1-D3 of the formal draft) and "
                       "routine operations with the monitor live (an upgrade across a recorder schema change, an "
                       "entity-id rename, a device removal, an entity-history purge, a routine upgrade), on scratch "
                       "stacks, with the hardened monitor and the patched verifier; review-r5 additions: a 90-trial "
                       "sham arm (S), hub restarts timed into a monitor poll (R), a benign Domoticz switch-type change "
                       "(C), pairwise closure mutation with logbook branch coverage (D) and the per-poll cost under a "
                       "Raspberry Pi 4-class cap (E)"),
        "status": "REGISTERED" if final else "DRAFT",
        "registered_at": now.isoformat() if final else None,
        "registered_before": ("any event of the real run (tag e10_main); smoke runs (prefix e10s/e10u, outputs under "
                              "HOMEPROV-P13-exp/e10/smoke, never exp/out) precede it and are not results"),
        "approval": {
            "pi": "2026-10-12, verbatim option label: 'Run E10 after E9 (Recommended)' (drafts/round13/TRIAGE_R4.md, PI "
                  "answers, item 1: adaptive boundary arms and an upgrade across a recorder schema change, an entity-id "
                  "rename and a device removal with the monitor live; pre-registered and stamped; after E9 ends)",
            "lead_scope_2026_10_12": ["SQLite hardening per drafts/round13/r4_sources.md section 9 (trusted_schema, "
                                      "quick_check first, cell_size_check, mmap_size, object types)",
                                      "verifier gaps D1-D5 of drafts/round13/FORMAL_DRAFT.md section 6, with arms for D1, "
                                      "D2 (offline collusion) and D3",
                                      "capture by context and attack success by the display rule "
                                      "(drafts/round13/R14C_ANALYSIS_NOTES.md items 4, 5)"],
            "pi_review_r5": "2026-10-16, verbatim option label: 'Add all (Recommended)' (TDSC_PLAN.md decision log: "
                            "E10 gains a 90-trial sham arm, a hub restart mid-poll, a Domoticz SwitchType change, a "
                            "pairwise closure-mutation sample and the cost under a Raspberry Pi 4-class CPU/IO cap)"},
        "design": {"file": "drafts/round13/E10_DESIGN.md", "sha256": h(DESIGN)},
        "addendum_review_r5": {"file": "drafts/round13/E10_ADDENDUM_R5.md", "sha256": h(ADDENDUM)},
        "review_r5_offline_plans": r5_plans(),
        "stacks": {
            "main (e10s)": {"what": "a scratch copy of the lab stack: broker, device simulator hpr-devices:1, "
                                    "homeassistant/home-assistant:2026.7.4 on an internal network; configuration "
                                    "cloned read-only from the lab volume homeprov-real_hpr-config after E9 ended "
                                    "(fallback e6-config); recorder = E9's final snapshot (consistent online-backup "
                                    "copy); scratch-only MQTT automations for Home Assistant's own purge and repack",
                            "seed_recorder": "HOMEPROV-P13-exp/e9/e9_main2/snapshots/final.db (sha256 recorded at "
                                             "setup in the run's stack.json)"},
            "upgrade (e10u)": {"what": "a fresh homeassistant/home-assistant:2025.11.1 (recorder schema 51) with the "
                                       "YAML-only testbed/e10/fresh_configuration.yaml, upgraded with the monitors live "
                                       "to 2026.7.4 (schema 53)",
                               "why_not_a_lab_copy": "the lab recorder is at schema 53 and Home Assistant does not "
                                                     "downgrade a recorder; no release after 2026.7.4 changes the "
                                                     "schema (2026.7.4 through 2026.10.1 and dev on 2026-10-12: 53)"}},
        "monitors": {"both": "hardened monitor.py (monitor/hardening_e10.patch), stable columns, coverage, keylog, "
                             "per-row binding, escrow, Ed25519 record signatures, name-map digest, full-history initial "
                             "seal, keylog rewind; linked anchor each (append key, separate operator key, tagged "
                             "replies), head witness outside Docker's VM; PERIOD 5 s",
                     "M-direct": "HOMEPROV_READ=direct, HOMEPROV_QUICK_CHECK_EVERY=720 (and, with hardening, the "
                                 "first poll of every process and every poll after a failed quick_check)",
                     "M-copy": "HOMEPROV_READ=copy, HOMEPROV_QUICK_CHECK_EVERY=1"},
        "parameters": {"late_bound_s": 30.0, "gap_s": 30.0, "period_s": 5.0, "purge_tol_s": 60.0,
                       "purge_keep_days": {"e10s_forced_purges": e10ops.PW_KEEP_DAYS, "e10u": 30},
                       "restore_tol_s": 30.0, "ambiguous_s": 0.05,
                       "unobservable_rule": {"min_duration_s": 60.0, "no_hub_start_within_s": 120.0},
                       "max_clock_step_s": 300.0, "clock_step_seen_s": 600.0, "late_break_backlog": True,
                       "inf_t_size_rule": "3 GiB if the Docker VM has at least 20 GiB free at preflight, else 1 GiB",
                       "seed": SEED, "collusion_cases_per_check": 5,
                       "start_window_utc": "main phase starts between 04:50 and 15:00 UTC (the scratch hubs' own "
                                           "04:12 purge never falls inside it)"},
        "plan": {"generated_by": "testbed/e10/e10ops.py plan --seed %d" % SEED,
                 "sha256": hashlib.sha256(plan_text.encode()).hexdigest(), "plan": plan},
        "hypotheses": HYPOTHESES,
        "arms": ARMS,
        "offline_checks": OFFLINE,
        "outcomes": OUTCOMES,
        "exclusions": EXCLUSIONS,
        "analysis_plan": ANALYSIS,
        "known_limits_stated_in_advance": LIMITS,
        "code_sha256": {"computed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "files": {f: h(os.path.join(R, f)) for f in FILES}},
    }
    if not final:
        pre["code_sha256"]["note"] = ("DRAFT: monitor.py and e7_verify.py are the E9-frozen versions until "
                                      "2026-10-19 16:01Z; monitor_e9.py / e7_verify_e9.py do not exist yet; the hashes "
                                      "to freeze are computed at --final, after both patches are applied")
    return pre


HYPOTHESES = {
    "H1_backdating_boundary": "An insertion backdated by d <= 30 s into a sealed second is never attributable (the "
                              "verifier reports it as a late commit, or has no evidence when the second was not sealed "
                              "yet); d = 45 s is always attributable; at d = 33 s exactly when the monitor copied the "
                              "recorder within the 3 s before the insertion committed.",
    "H2_insertion_only_reattribution": "An automation_triggered event sharing a sealed actuation's context, inserted "
                                       "with a timestamp just before it at 5, 15 or 25 s after the actuation, moves the "
                                       "actuation's displayed cause (frontend display rule) to the automation and is "
                                       "not attributable; at 45 s it is attributable (R3 Q2).",
    "H3_observation_window": "A deletion is detected if and only if an observable poll read the row before it was "
                             "deleted; the detection rate rises with the delay as about delay / poll interval and is 1 "
                             "for delays above the longest poll interval.",
    "H4_phase_aware_deletion": "An in-hub adversary senses the direct-read monitor's reads (another process's lock on "
                               "the recorder's -shm) and, deleting 0.3 s before the predicted next read, escapes "
                               "M-direct at visible times at which the non-adaptive deletion is mostly detected.",
    "H5_reused_lower_key": "A row inserted with a reused lower key into a sealed second is always detected (R1 Q1).",
    "H6_purge_window": "Under a declared purge (tolerance 60 s): purge-shaped deletion of the tolerance band is excused "
                       "(by design); deletion of a recent row, of rows just beyond the band, an out-of-order band "
                       "deletion, and a forged old row first observed after scheduled + 120 s are detected; a forged "
                       "old row inserted and deleted inside the 120 s window is not detected (excused as a purged "
                       "row, or no evidence if no poll saw it).",
    "H7_sustained_unobservability": "A write lock held by a second connection blinds neither monitor (WAL readers) "
                                    "but delays the hub's commits, and rows committed more than 30 s late are "
                                    "attributable; a POSIX write lock on the -shm DMS byte makes every direct read "
                                    "unobservable for the hold without stopping the hub, while copy mode observes; "
                                    "an unread table of about 3 GiB added to the recorder blinds copy mode "
                                    "(copy_raced) until a repack and not direct mode; window inflation slows polls without unobservability. An edit of a "
                                    "row sealed before a blind window is detected; a row written and deleted inside it "
                                    "is not detected by the blinded monitor. The pre-registered rule flags every "
                                    "attack-caused unobservable interval and no interval of E9's benign week.",
    "H8_D1_live": "A row backdated across a blind window of M-direct into a second sealed before it is a late commit "
                  "for the E9 verifier (escape), unknown for the patched verifier, and attributable on M-copy.",
    "H9_D2_D1h_offline_collusion": "With the record(s) carrying an emptied second's root and keylog ranges withheld, "
                                   "the E9 verifier reads the second as match and the patched verifier as unknown; "
                                   "with the polls between a 45 s-backdated row's sealing and its insertion withheld, "
                                   "the E9 verifier reads match and the patched verifier unknown.",
    "H10_D3_clock_step": "Rows the hub writes during a 60 s backward clock step are attributable without a marker and "
                         "excused under an operator CLOCK_STEP marker; a 10 s step raises no violation.",
    "H11_entity_id_rename": "Renaming an entity id fails every sealed second, minute and hour holding a row of that "
                            "entity, in the numbers predicted from the recorder, and no marker excuses it; the RENAME "
                            "marker excuses its name-map transition.",
    "H12_device_removal": "Removing a device changes no recorder row (no violation); its name-map transition is "
                          "excused by the declared RENAME marker.",
    "H13_entity_history_purge": "Purging an entity's history fails every sealed segment holding its rows (predicted "
                                "from the recorder); no marker excuses it.",
    "H14_upgrades": "2025.11.1 -> 2026.7.4 (schema 51 -> 53) and 2026.7.4 -> 2026.10.1 (53) change no committed row: no "
                    "violation over the whole sealed history; schema_changes gains 52 and 53 in the first.",
    "H15_hardening": "On honest recorders the hardened monitor's records equal E9's (tests) and no E10 poll fails with "
                     "schema_object_not_a_table or quick_check_failed; re-verifying E7, E8 and E9 with the patched "
                     "verifier changes no flagged second and every other difference has a listed reason.",
    "H16_benign_floor": "No flagged second of the main session is unexplained by an arm.",
    # review r5 (drafts/round13/E10_ADDENDUM_R5.md)
    "H17_sham_specificity": "With the attack integration's write rolled back on the code paths of A1-BDT (45 s), A2-CTX "
                            "(45 s) and A3-DEL (10 s), at the same timing and in the same session, no violation is "
                            "attributable to any of the 90 sham trials on either monitor: its would-be target second is "
                            "not flagged, its own actuation row is not attributable and no keylog violation names it "
                            "(0 of 90 per monitor); at the same levels the attack trials' target seconds are violated.",
    "H18_restart_mid_poll": "A hub restart, graceful or killed, whose effect lands inside a monitor's read (direct) or "
                            "copy (copy) window, raises no attributable row and no flagged second on either monitor and "
                            "restarts no monitor; rows committed around it are benign_late under the E9 verifier and "
                            "benign_late or unobserved_late under the patched verifier (unobserved_late exactly when an "
                            "unobservable or missing poll or a gap above GAP_S lies in the row's bracket, D1); no "
                            "unobservable interval it causes is flagged by the distinguishability rule; the recorder is "
                            "never moved away.",
    "H19_dz_switchtype": "A benign switch-type change of the Domoticz lock (19 -> 20) by its owner through the hub's own "
                         "API makes every anchored second, minute and hour segment that holds a log row of the lock and "
                         "was first anchored before the change a violation, and no other segment; the offline root "
                         "comparison changes exactly those seconds; the platform's renderer shows the lock's earlier "
                         "rows differently; no marker excuses it (a measured limit of a closure that commits a "
                         "configuration field).",
    "H20_pairwise_closure": "No pair of mutations (exhaustive same-target pairs at E8B's primary values; samples of "
                            "1,000 other-value pairs and 1,000 cross-row pairs) changes the rendered output while "
                            "leaving the deployed stable-columns commitment unchanged; no pair of fields that each leave "
                            "the output unchanged changes it jointly; no field outside E8B's 27-field closure changes "
                            "the output once another field changed. Line and branch coverage of the logbook package is "
                            "reported, with the branch sites never taken.",
    "H21_pi4_cost": "Under the Pi 4-class profile the direct-read monitor's median poll stays below PERIOD (5 s) at "
                    "0.19 GB and 0.96 GB with no poll above GAP_S (30 s) except a due quick_check; copy mode writes about "
                    "the recorder's size per poll (bytes written per hour reported); the pi4 / ref ratio of the median "
                    "poll time is reported per size. Exploratory where it depends on the assumed limits (no prediction "
                    "at 2.94 GB).",
}

ARMS = [
    {"id": "A1-BDT", "n": "20 per age; ages 5, 15, 30, 33, 45 s (100, randomised order, 15 s apart)",
     "what": "homeprov_e10 bdt: one forged 'unlocked' lock row per trial, timestamped age seconds before its insertion, "
             "attributed to a genuine run of the room's motion-light automation (its context), old_state_id = the "
             "lock's latest genuine 'locked' row (so the logbook lists it)",
     "expected": {"5": "no detection; reported as a late commit if a poll sealed its second before the insertion "
                       "(about (age - 1)/T of trials, T the monitor's poll interval), else no evidence",
                  "15": "no detection; reported as a late commit (M-direct); M-copy: a late commit, or no evidence "
                        "when no copy fell between the second's end and the insertion",
                  "30": "no detection (a copy within the insertion's few-ms commit is ambiguous)",
                  "33": "detected iff an observable copy fell in the 3 s before the insertion committed (about 3/T: "
                        "about 0.6 for M-direct, 0.3 for M-copy at the cost runs' poll intervals)",
                  "45": "detected, every trial, when an observable copy fell in the 15 s before the insertion (every "
                        "trial for M-direct; M-copy unless a poll took more than 15 s)"},
     "scored": "per trial and monitor: verdict of the inserted row against the snapshot after DEL-PH (snap_del); "
               "prediction from that monitor's copy times; attack success = forged row listed with an automation "
               "cause (display rule, admin and non-admin)", "why_n": "deterministic per-trial prediction; 0/20 bounds an "
               "unpredicted outcome at a level by 0.168 (one-sided 95% Clopper-Pearson)"},
    {"id": "A2-CTX", "n": "10 per delay; delays 5, 15, 25, 45 s (40)",
     "what": "an actuation under the integration's own Context; at delay seconds after its row committed, an "
             "automation_triggered event of the innocent automation with that context id, timestamped 50 ms before "
             "the actuation's first row (insertion only; nothing edited)",
     "expected": {"5,15,25": "displayed cause moves from integration:lock to automation:<innocent> (display rule); "
                             "not detected (late commit or no evidence)", "45": "displayed cause moves; detected"},
     "scored": "as A1 on the inserted event; display before and after", "why_n": "R3 Q2 asks whether it works at all; "
     "10 per delay with a deterministic detection prediction"},
    {"id": "A3-DEL", "n": "10 per delay; delays 1, 2, 3, 4, 5, 6, 8, 10 s (80)",
     "what": "an actuation (captured by its context id); its 'unlocked' row deleted at the delay after the adversary "
             "saw it committed (5 ms polling)",
     "expected": "detected iff an observable poll copied in [committed, deleted); rate about min(1, delay/T), T the "
                 "monitor's poll interval (PERIOD 5 s plus the poll's own time: about 5.1 s for M-direct and about 9 s "
                 "for M-copy on a 0.19 GB recorder, exp/out/e9_cost_scale*.json), so 1 from 6 s for M-direct; every "
                 "observed row's deletion detected",
     "scored": "per trial and monitor: detected, observed (its key in an observable poll's keylog entry), prediction "
               "from copy times (50 ms ambiguity), agreement; attack success = the unlock no longer displayed; residue: "
               "the next lock row's old_state_id (the adversary evicts the deleted row from the recorder's cache, as "
               "Home Assistant's purge does, so it is NULL; without the eviction the recorder, which runs SQLite with "
               "foreign keys on, fails to insert that row and stops recording the lock: smokes 3 and 5, 2026-10-20) "
               "and whether the hub kept recording", "why_n": "a detection-vs-delay curve over 8 delays"},
    {"id": "A3-DEL-PH", "n": "20",
     "what": "phase-aware deletion: the integration samples (2 ms) whether another process locks the -shm's WAL lock "
             "bytes or DMS byte, predicts M-direct's next read, actuates after a read ends, deletes 0.3 s before the "
             "predicted next read",
     "expected": "M-direct: detected in at most 4 of 20 (predicted near 0); M-copy: as A3 at the realised visible time",
     "alternative": "if the smoke shows the sensor does not see M-direct's reads (POSIX locks are per process: the "
                    "hub's own connections are invisible to it, another process's are not), the arm is reported as "
                    "sensor-failed and the registration says so before the run",
     "scored": "as A3; sensor error (predicted minus actual next copy)"},
    {"id": "A3-LOWKEY", "n": "up to 10 (keys A3 deleted)", "what": "a forged row inserted with a key A3 freed, into a "
     "second sealed 90 s earlier", "expected": "detected, every trial, both monitors", "scored": "against snap_timing"},
    {"id": "A7-WIPE", "n": "10", "what": "every state and event row of a sealed second holding an A2 actuation deleted",
     "expected": "detected, every trial (honest chains); the D2 offline check uses 5", "scored": "against snap_wipe"},
    {"id": "A6-CS (D3)", "n": "5 steps: 60 s with a CLOCK_STEP marker x3, 60 s without x1, 10 s without x1; 60 s each",
     "what": "in the hub's process time.time() returns the wall clock minus the step for 60 s (the monitor's clock is "
             "not stepped); the operator's CLOCK_STEP marker (window [t - step, t]) is posted 120 s before",
     "expected": {"60 s, marker": "every row of the step excused_clock_step; none attributable",
                  "60 s, no marker": "rows of the step attributable (false violations)",
                  "10 s, no marker": "late commits; no violation"}, "scored": "against cs_end"},
    {"id": "A5-PW", "n": "6 declared purges (forced, keep 29 days), 15 min apart; 3 per variant",
     "what": "PW-B band rows the hub kept, deleted in purge order (to c1 - 0.5 s); PW-X purge-shaped rows in [c1, c1 + 30 "
             "s); PW-U one band row out of order; PW-R a recent sealed unlock row; PW-F-in a forged row 10.5 s before "
             "c0 inserted at S + 30 s and deleted at S + 90 s; PW-F-out inserted at S + 150 s and deleted at S + 175 s",
     "expected": {"PW-B": "excused", "PW-X": "detected", "PW-U": "detected (band_deletion_not_purge_shaped)",
                  "PW-R": "detected", "PW-F-in": "not detected (excused as purged, or no evidence)", "PW-F-out": "detected (removed_row_written_after_the_purge)"},
     "scored": "against pw<i>_post (before the next purge's marker), historical and session windows"},
    {"id": "A4-UL-W", "n": "2 holds of 60 s", "what": "BEGIN IMMEDIATE on a second connection",
     "expected": "no unobservable poll on either monitor; the hub's rows of the hold committed after it, those more "
                 "than 30 s late attributable on both monitors (or lost: reported)", "scored": "against snap_a_end"},
    {"id": "A4-UL-SHM", "n": "5 holds of 60 s", "what": "POSIX write lock on the -shm DMS byte (128), re-asserted every "
     "5 ms; inside each: an INS-L-shaped launder of an A2 row sealed before, an actuation deleted 8 s after it "
     "committed, and 2 s before the end a forged row backdated into a second sealed 12 s before the hold (D1)",
     "expected": {"M-direct": "every poll in the hold unobservable (direct_open_failed); launder detected; blind "
                              "deletion not detected; D1 row: E9 verifier late commit, patched verifier unknown",
                  "M-copy": "no unobservable poll; launder detected; blind deletion detected; D1 row attributable",
                  "hub": "rows committed throughout"},
     "alternative": "if the smoke shows M-direct still observing under the DMS lock, the arm is reported as not "
                    "blinding, D1 is covered by the offline checks only, and the registration says so before the run"},
    {"id": "A4-UL-SHM-OFD", "n": "1 hold of 60 s", "what": "open-file-description write locks on the read-mark bytes "
     "123-127 (they also conflict with the hub's own locks)", "expected": "exploratory: no prediction"},
    {"id": "A4-UL-JM", "n": "1", "what": "PRAGMA journal_mode=DELETE from a second connection",
     "expected": "refused while the hub holds the recorder (exploratory)"},
    {"id": "A4-INF-T", "n": "1", "what": "an unread junk table of the size rule's bytes (random blobs, 16 MiB per "
     "commit) added to the recorder, held 300 s, dropped, then Home Assistant's own repack", "expected": {
         "M-copy": "3 GiB added: every poll unobservable (copy_raced) once the file passes about 3 GB, until the repack "
                   "shrinks it (the E8 monitor's copy at 2.94 GB: 30 of 30 copy_raced, exp/out/e9_cost_scale.json); "
                   "1 GiB added: no prediction of copy_raced (between the measured sizes); polls of at least about "
                   "30 s (0.96 GB copy runs: 30.3 s and 42.7 s median), so poll gaps above GAP_S",
         "M-direct": "observable throughout; per poll under a second when no quick_check is due (0.633 ms median "
                     "snapshot phase at 2.94 GB); a due quick_check takes about a minute at 3 GiB (58,568 ms median, "
                     "exp/out/e9_cost_scale_direct_final.json)"}},
    {"id": "A4-INF-W", "n": "1", "what": "300,000 junk state rows with current timestamps at 500 rows/s",
     "expected": "no unobservable poll; per-poll time grows with the rows in the two-hour re-read window; no poll gap "
                 "above 30 s (if one occurs, late rows in it are unknown under D1)"},
    {"id": "B1-ENTITY-ID-RENAME", "n": "1", "what": "light.porch_light -> light.porch_lamp_e10 through the entity "
     "registry, after an operator RENAME marker with the predicted part digests and the entity_id pair",
     "expected": "unexcused violations on exactly the sealed seconds, minutes and hours holding a row of that entity "
                 "(counted from b1_end, rows timestamped 10 s or more before the rename), every keylog range holding "
                 "one; name-map transition excused"},
    {"id": "B2-DEVICE-REMOVE", "n": "1", "what": "the kitchen motion sensor's device removed as the frontend does it, "
     "after a RENAME marker with the predicted digests", "expected": "no recorder violation; name-map transition "
     "excused; a re-announcement by the simulator is a second, undeclared transition"},
    {"id": "B3-PURGE-ENTITIES", "n": "1", "what": "recorder.purge_entities on the INF-W junk entity",
     "expected": "violations on every sealed segment holding a junk row (counted from b2_end); none excused"},
    {"id": "B4-UPGRADE", "n": "1", "what": "2026.7.4 -> 2026.10.1 on the lab copy, monitors live, no marker",
     "expected": "no recorder violation over the whole history; schema 53 unchanged; name map: no prediction"},
    {"id": "U-SCHEMA-UPGRADE", "n": "1", "what": "e10u: 2025.11.1 (schema 51), one hour, 2026.7.4 (schema 53), one hour",
     "expected": "no recorder violation over the whole history; schema_changes 51 -> 51, 52, 53; statistics_meta "
                 "gains unit_class; states and events columns unchanged; name map: no prediction"},
    # ---- review r5 (drafts/round13/E10_ADDENDUM_R5.md)
    {"id": "S-SHAM", "n": "90: 30 each of S-BDT (A1 code path, 45 s), S-CTX (A2, 45 s), S-DEL (A3, 10 s), seeded order",
     "what": "homeprov_e10 op sham: each trial runs the attack arm's own code path (same reads, same BEGIN IMMEDIATE at "
             "the same moment, same spacing; CTX and DEL actuate the lock under their own Context and capture the row by "
             "context) and rolls the write transaction back instead of committing the edit; block after SNAP_DEL, "
             "scored against SNAP_SHAM",
     "expected": {"each monitor": "0 of 90 trials with a violation attributable to the trial (would-be second flagged, "
                                  "own actuation row attributable, or a keylog violation naming its key)",
                  "integrity": "db_writes_total 0; displayed cause unchanged (S-CTX); the unlock still listed (S-DEL)",
                  "confusion": "at the same levels the attack trials' target seconds are violated (A1 45 s, A2 45 s, "
                               "A3 10 s: detected, every trial, per H1-H3)"},
     "scored": "exp/stages/e10r5_score.py S_sham: per trial, per variant and overall with exact 95% intervals; the "
               "confusion matrix at the target seconds (sensitivity from the attack arms against snap_del, specificity "
               "from the sham against snap_sham)",
     "why_n": "R3 W3 and META item 4 ask for 90; 0 of 90 bounds the per-trial false-violation rate at the target seconds "
              "by 0.0327 (one-sided 95% Clopper-Pearson) per monitor"},
    {"id": "R-RESTART", "n": "10 restarts, seeded order: 4 graceful aimed at M-direct's read, 3 killed (SIGKILL, then "
                             "docker start) aimed at M-direct's read, 3 graceful aimed at M-copy's copy",
     "what": "testbed/e10/e10ops.py restart-trial: the target monitor's next read (direct: open to the end of load and "
             "commit) or copy window predicted from the last 16 lines of its cost log on the VM clock; the command is "
             "sent so that its effect (graceful: the container's exit, which follows the recorder's close; kill: the "
             "signal) lands at the window's middle (graceful lag: first 2.0 s, then the running median of the measured "
             "lags); 150 s settle after the hub writes again; block after SNAP_WIPE, scored against SNAP_RESTART",
     "expected": {"per verifier rule": "attributable rows 0 and flagged seconds 0 in every restart's window "
                                       "[effect - 30 s, hub start + 120 s], both monitors and both verifiers; late rows "
                                       "benign_late (E9 verifier), benign_late or unobserved_late (patched; "
                                       "unobserved_late iff a D1 break lies in the row's bracket)",
                  "observability": "unobservable polls allowed (no count predicted; each reported with its reason); none "
                                   "flagged by the distinguishability rule; monitor restarts 0",
                  "recorder": "never moved away (no *corrupt* file); hub log lines about the database reported",
                  "landing": "reported per trial (effect inside the target window, from the full cost log); not a "
                             "condition of the predictions, which hold for any restart"},
     "scored": "exp/stages/e10r5_score.py R_restart"},
    {"id": "C-DZ-SWITCHTYPE", "n": "1 change (19 -> 20) in 20 min of benign lock traffic (10 min before, 10 after)",
     "what": "testbed/e10/run_dz_switchtype.sh (copied from testbed/domoticz/run_dz.sh): the owner's Edit-Device request "
             "(param=setused, every other field unchanged) on the Domoticz test stack, closure monitor live; snapshots "
             "just before the change and at the end",
     "expected": "violations on exactly the anchored segments holding a lock log row first anchored before the change "
                 "(seconds within 10 s of the change ambiguous); none elsewhere; the offline pre/post root comparison "
                 "changes exactly the predicted seconds; the renderer's text log of the lock changes; no marker excuses "
                 "it",
     "scored": "exp/stages/e10_dz_switchtype.py"},
    {"id": "D-PAIRWISE", "n": "W exhaustive (every same-target field pair at E8B's primary values, 40 targets); V 1,000 "
                              "and X 1,000 seeded samples; registered plan sha256 under review_r5_offline_plans",
     "what": "exp/stages/e10_pairwise_closure.py on a throwaway hub serving a working copy of E8B's pristine copy of the "
             "lab recorder; each unit applies two mutations, renders the three forms, recomputes the closure, stable "
             "and row commitments, restores and checks the restore; singles re-measured; sys.monitoring line and branch "
             "coverage of homeassistant.components.logbook",
     "expected": {"undetected_render_change": 0, "joint_only": 0, "conditional_noncl": 0,
                  "masking": "no prediction (descriptive)", "coverage": "reported, no prediction"},
     "stopping_rule": "W in seeded order, then V, then X; no outcome-dependent stop; stop at the end of the units or at "
                      "3.0 h of measurement, whichever is first; the units done are reported",
     "scored": "exp/stages/e10_pairwise_closure.py summarize -> exp/out/e10_pairwise_closure.json"},
    {"id": "E-PI4-COST", "n": "10 runs x 30 measured polls (registered matrix under review_r5_offline_plans)",
     "what": "exp/sp2027/e10_pi4_cost.py through exp/sp2027/e9_cost_scale.py (unchanged): the same synthetic recorders, "
             "writer and harness as C1, the hardened E10 monitor image, monitor container limits per profile (ref = C1; "
             "pi4 = 0.25 CPU, 512 MiB without swap, 40/10 MB/s, 1,500/500 IOPS -- assumed values, stated in the file)",
     "expected": "H21; exploratory where it depends on the assumed limits",
     "scored": "exp/sp2027/e10_pi4_cost.py summarize -> exp/out/e10_pi4_cost.json"},
]

OFFLINE = [
    {"id": "D2", "what": "exp/stages/e10_collusion.py on 5 A7-WIPE seconds per monitor", "expected": "honest: violation; "
     "withheld: E9 verifier match, patched unknown"},
    {"id": "D1h", "what": "exp/stages/e10_collusion.py on 5 A1 45 s trials per monitor", "expected": "honest: violation; "
     "withheld: E9 verifier match, patched unknown"},
    {"id": "O-MIG", "what": "exp/stages/e10_migration_offline.py on the final snapshot", "expected": "m52 and a new index: "
     "no violation; a states column: every sealed segment holding a state row and every states keylog range fail"},
    {"id": "REVERIFY", "what": "testbed/e10/reverify_patched.py: E7 and E8 (reproduce/verify_e7e8.py --escrow with the "
     "patched verifier and hardened monitor; reproduce/verify_all.py) and every E9 verification of e9_score.py with the "
     "patched verifier", "expected": "no flagged second changes; every other difference listed with its reason"},
]

OUTCOMES = {
    "primary": ["per-trial agreement of the verdict with the design's prediction, per arm and monitor (A1, A2, A3, "
                "A3-DEL-PH, LOWKEY, WIPE, PW, CS)", "detection per level / delay / variant with exact 95% intervals",
                "UL-SHM: unobservable polls per hold and monitor, the hub's rows during the hold, launder / blind "
                "deletion / D1 outcomes", "B1, B3: violated segments against the predicted counts; B2, B4, U: violations "
                "(predicted 0)", "D2, D1h, O-MIG, REVERIFY as listed"],
    "secondary": ["attack success by the display rule per trial (A1, A2, A3)", "the forensic residue of A3 (the next "
                  "lock row's old_state_id after the adversary's cache eviction)", "the lower bounds of the late commits in A1/A2 against the largest benign late "
                  "delay of E9's week", "per-poll cost, poll interval and seal delay during INF-T and INF-W",
                  "the distinguishability rule on E10 and on E9's week", "name-map transitions of B4 and U",
                  "untouched floor: unexplained flagged seconds (predicted 0)",
                  "review r5: S per-variant counts and the confusion matrix; R landing and unobservable polls; D "
                  "coverage; E costs, overruns and bytes written"],
    "primary_review_r5": ["S: trials with a violation attributable to the trial, per monitor (predicted 0 of 90)",
                          "R: attributable rows and flagged seconds in the restart windows, per monitor and verifier "
                          "(predicted 0)",
                          "C: agreement of the violated segments with the predicted set, per granularity",
                          "D: undetected render changes, joint-only and conditional_noncl units, per stratum "
                          "(predicted 0)",
                          "E: per-poll median, p90 and max, overruns above PERIOD and GAP_S, bytes written, per run"]}

EXCLUSIONS = ["a trial the integration reports with err (no row, lock unavailable, no cover): listed, not scored",
              "per-trial agreement leaves out trials whose boundary falls within 50 ms of a copy (ambiguous): counted",
              "a block during which the host log shows a wall-clock gap above 90 s, or a hub start without a harness "
              "cause, or a monitor restart: its trials are scored and reported separately, not pooled",
              "smoke runs are not results",
              "review r5: S trials returned with err are listed, not scored; an R restart without an effect time (failed "
              "command or no FinishedAt) is listed, not scored; D units with an apply error or a missing single are "
              "counted per stratum, not classified; E runs with poll errors are reported as such"]

ANALYSIS = ["No hypothesis test beyond the exact intervals; every prediction is stated per trial or per count above "
            "and is confirmed only if every non-excluded trial agrees (an unpredicted outcome is reported with its "
            "trial, not averaged away)", "Both monitors are scored separately; nothing is pooled across them",
            "Every deviation from this registration (plan, parameters, code) is written to an amendment before it is "
            "used, as for E9"]

LIMITS = ["Scratch stacks on one Mac with virtual devices; the lab installation is not touched",
          "The clock step is emulated inside the hub's process (time.time), not a host clock step",
          "No release after 2026.7.4 changes the recorder schema; the schema arm crosses 51 -> 53 on a fresh install, "
          "whose SQLite steps touch statistics_meta only",
          "The phase sensor is specific to direct read on one kernel (the hub and the monitor share Docker's VM)",
          "Lock-based blinding depends on SQLite's unix VFS behaviour (3.40.1 in the monitor image); exploratory arms "
          "carry no prediction",
          "review r5: the sham runs as one block, not interleaved with the attack trials; it shares their session, "
          "monitors and hub but not their minutes",
          "review r5: a restart's landing inside a direct read (about 80 ms of every 5 s) depends on Docker's command "
          "latency; landing is measured and reported, the predictions do not depend on it",
          "review r5: the Pi 4 profile is Docker CPU, memory and I/O quotas on this Mac with assumed values, not a Pi 4; "
          "a CPU quota throttles in 100 ms periods rather than slowing every instruction",
          "review r5: pairwise mutation covers E8B's 40 targets and mutation values only; branches no target reaches "
          "stay unexercised (listed)"]


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
    doc = document(a.final)
    if a.final:
        missing = [f for f, s in doc["code_sha256"]["files"].items() if s is None]
        if missing:
            raise SystemExit("REFUSING --final: missing %s" % missing)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    with open(a.out, "x" if a.final else "w") as fh:
        fh.write(text)
    print("wrote", a.out, hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
