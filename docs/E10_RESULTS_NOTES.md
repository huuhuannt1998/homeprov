# E10 results notes (run e10_main, 2026-10-21 04:55Z to 19:57Z; scored 2026-10-21; analysed 2026-10-24)

Source for the round's text and for NUMBERS.md. Every number names its file and field, with the file's sha256 prefix in
parentheses on first use; files are under <artifact-root>/exp/out unless a path is given. RUN is
/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main; HLOG is <research-dir>/HOMEPROV-P13-exp/e10.
Confirmatory outcomes (A) come only from the frozen scorers' files and their per-trial agreement; exploratory analyses
(B) are labelled EXPLORATORY and come from new r16_e10_* files written for these notes (never overwriting anything).
HOMEPROV detects post-commit rewriting; it does not prevent it. Times are UTC.

## Registration, code, run facts
- Pre-registration exp/out/e10_preregistration.json (59aab5dad69a), registered_at 2026-10-20T21:34:16Z, stamped
  (.ots beside it). Design E10_DESIGN.md and addendum E10_ADDENDUM_R5.md match their registered sha256 (137f8a5d0a8c,
  9709aa4a5db4). Every file in code_sha256.files was at its registered sha256 at run start (HLOG/e10_main.out
  (e0f0fe9d7d82), 04:55:09Z "every frozen file at its registered sha256") and again when checked on 2026-10-24.
- Tests before the run (e10_main.out): monitor 180 passed, testbed/anchord 81 passed, test_e10_patches.py 28 passed.
- Timeline (e10_main.out; HLOG/e10_main_r5.log (f414d108f3ba)): e10u upgrade phase 04:57-07:02Z; e10s session start
  t_start 1792566557 = 07:09:17Z (RUN/e10s/t_start; r16_e10_routine_floor.json floor.t0); blocks A1 07:09:17, A2 07:35:19,
  A3 07:58:00, A3-DEL-PH 08:26:21, S 08:35:28, LOWKEY 09:24:32, WIPE 09:25:37, R 09:26:19, CS 09:54:07, PW 10:22:06,
  UL-W 11:52:07, UL-SHM 11:56:22, OFD 12:09:19, JM 12:11:49, INF-T 12:11:52, INF-W 12:37:31, snap_a_end 13:07:47, B1
  13:07:50, B2 13:10:49, B3 13:14:33, B4 13:16:06, final snapshot 13:50:27; scoring 13:51:23 to "score exit: 0" at
  15:25:48; run_e10.sh done 17:45:43; arm C 17:45:44-18:09:16, arm D 18:09:17-18:49:06, arm E 18:49:07-19:57:38, all exit 0.
- Hub starts on e10s: 12, each with a harness cause (RUN/events.jsonl = exp/out/e10_main_events.jsonl (2eee0740724e),
  type hub_restart: activate homeprov_e10, 10 R trials, deactivate). Monitor restarts 0 (events monitor_memory_peak
  restarts 0; e10_main_r5_score.json R_restart.after.monitor_restarts). Host-log sample gaps: max 61.99 s (e10s),
  61.05 s (e10u), none above 90 s (r16_e10_unobs.json (664cf1f0c4d5) hostlog_gaps). Monitor memory peak e10s:
  direct 2,953,003,008 B, copy 2,621,898,752 B (events monitor_memory_peak). INF-T size 3 GiB (events inft_size
  target_bytes 3221225472; vm_free_kib 814,057,764).
- Polls (r16_e10_unobs.json unobservable_by_stack.*.polls): e10s direct 4,508, copy 4,038; e10u direct 1,424, copy 1,410.

## Exclusions and harness errors (registered rules)
- err trials, listed and not scored: A3-LOWKEY 6 of 10 (trials 0, 1, 4, 6, 7, 9: "key ... is present", the key A3 freed
  had been reused by a later row; RUN/e10/c0025e8b54_lowkey.json); no other arm had an err trial (bdt 100, ctx 40,
  del 80, delph 20, sham 90, wipe 10: err 0). A4-UL-JM returned OperationalError('database is locked'), which is its
  predicted refusal, not a harness error (e10_main_score.json arms.UNOBS_journal_mode).
- Ambiguous trials (copy within 50 ms; counted, left out of agreement; r16_e10_trial_deviations.json (37024fea15bf)
  scorer.agrees null): BDT direct trial 98 (30 s); BDT copy 7 (45 s), 26 (33 s), 46 (33 s), 96 (45 s); CTX direct 15
  (15 s); DEL direct 3 (6 s), 57 (2 s), 63 (8 s), 69 (5 s); DEL copy 26 (4 s), 37 (5 s), 47 (8 s), 76 (6 s);
  DEL-PH copy 17. Total 15 of 480 trial-monitor pairs (r16_e10_agreement_totals.json (e8b6123ecb04) overall.ambiguous).
- Blocks scored separately: none (no host gap above 90 s, no hub start without a cause, no monitor restart).
- R: all 10 restarts had an effect time and were scored (e10_main_r5_score.json (345baf7021f1) R_restart.summary.scored 10).
  S: no err (S_sham.errors []). D: apply_errors [], restore_failures [] (e10_pairwise_closure.json (9c8a8cd52c37)).
  E: poll_errors 0 in every run (r16_e10_misc.json (65fdffc5f568) pi4.*.poll_errors).
- Harness: no WARN line in e10_main.out, e10_main_r5.log or RUN/score.log (8bf1503fdb6d); all scorers exited 0.
  Arm C: 4 anchor refusals, which are the four probes logged at 17:46:52Z (missing / bad signature, HTTP 401;
  HOMEPROV-P13-exp/dz/runs/e10_main_dzst/refusals.jsonl), and 4 hub log errors besides the dzVents latitude/longitude
  warnings (e10_main_r5.log line 52): 2 mDNS socket errors and 2 dzVents runtime errors (EventHelpers.lua:442, nil
  hardwareName), at 17:45:46-17:46:12, before the arm started at 17:47:32 (dz/runs/e10_main_dzst/logs/domoticz.log).
- Not errors but limits of the frozen scorer, found in this analysis and reported, not corrected (each detailed in B):
  (1) the BDT/CTX outcome counts a flagged one-second segment as detection of every trial row in it, and the A1 plan put
  10 trials' rows in the same second as a 45 s trial's row; (2) predicted_insertion() uses the last copy_at before the
  commit without the design's watermark condition (E10_DESIGN.md section 4), and in copy mode copy_at is the copy's
  START (monitor.py: copy_at = copy_start); (3) the CS section counts state rows only, and the emulated step moved event
  timestamps only; (4) the floor uses the verifier's whole-chain flagged seconds with block windows in session time;
  (5) the scorer was run without --e9-run-dir, so the distinguishability rule was not applied to E9's week. Plan limit:
  every A5-PW band was empty (B6).

## Verdict table (per hypothesis; details in A)
| H | Short | Verdict |
|---|---|---|
| H1 | backdating boundary | NOT MET as scored (23 deviations, both monitors; see B1: 19 shared-second, 4 copy timing) |
| H2 | insertion-only reattribution | MET |
| H3 | observation window | PARTLY MET (direct 76/76 agree; copy 75/76) |
| H4 | phase-aware deletion | MET (direct detected 1/20) |
| H5 | reused lower key | MET (4/4 scored; 6 of 10 err-excluded) |
| H6 | purge window | PARTLY MET (PW-R, PW-F-in, PW-F-out as predicted; PW-B, PW-U, PW-X NOT EVALUABLE: empty band) |
| H7 | sustained unobservability | PARTLY MET (INF-T did not blind copy mode; rule flagged 4 of 6 attack intervals; E9 week not run by scorer) |
| H8 | D1 live | MET (5/5 holds) |
| H9 | D2 / D1h offline collusion | PARTLY MET (D2 E9-verifier outcome violation_coarse_only, not match, 10/10) |
| H10 | D3 clock step | NOT MET as scored (scorer counts state rows; the step moved event rows only; B4) |
| H11 | entity-id rename | PARTLY MET (exploratory sets: seconds exact, minutes 2-3 and hours 1 short of the predicted counts) |
| H12 | device removal | MET |
| H13 | entity history purge | MET (exploratory set comparison; the scorer gives cumulative counts only) |
| H14 | upgrades | PARTLY MET (no violation, schema 51/52/53; but unit_class was already present at schema 51) |
| H15 | hardening and re-verification | MET |
| H16 | benign floor | NOT MET as scored (73,349 / 73,348 unexplained; exploratory: 0 after accounting, B2) |
| H17 | sham specificity | MET (0/90 each monitor) |
| H18 | restart mid-poll | MET |
| H19 | Domoticz switch type | MET |
| H20 | pairwise closure | PARTLY MET (0 undetected render changes; joint_only 6, predicted 0) |
| H21 | Pi 4-class cost | MET |

Per-trial agreement over the four scored per-trial arms (r16_e10_agreement_totals.json, a restatement of
e10_main_score.json (342232f771d0) prediction_agrees): 440 of 465 scored trial-monitor pairs agree, 25 disagree, 15
ambiguous. Per arm (agree / scored): BDT direct 90/99, copy 82/96; CTX direct 39/39, copy 40/40; DEL direct 76/76,
copy 75/76; DEL-PH direct 20/20, copy 18/19. Every one of the 25 is listed in B1.

## A. Confirmatory (frozen scorers: exp/stages/e10_score.py, e10r5_score.py, e10_collusion.py, e10_migration_offline.py, e10_dz_switchtype.py, e10_pairwise_closure.py; exp/sp2027/e10_pi4_cost.py)

### H1 backdating boundary (A1-BDT, 20 per age; e10_main_score.json arms.BDT)
Registered: d <= 30 s never attributable (late commit, or no evidence when the second was not sealed yet); 45 s always
attributable; 33 s exactly when the monitor copied within the 3 s before the insertion committed.
Observed (per_level.<age>.<m>.outcomes, prediction_agrees, detected):
- 5 s: direct reported_late 20, detected 0/20, agree 20/20; copy reported_late 18, no_evidence 2, detected 0/20, agree 19/20.
- 15 s: both monitors detected 4/20 [0.057, 0.437], reported_late 16; agree 16/20 on each.
- 30 s: both detected 6/20 [0.119, 0.543]; agree direct 14/19 (1 ambiguous), copy 14/20.
- 33 s: direct detected 13/20, agree 20/20; copy detected 7/20, agree 15/18 (2 ambiguous).
- 45 s: detected 20/20 [0.832, 1.0] on both; agree direct 20/20, copy 18/18 (2 ambiguous).
- Attack success by the display rule (forged unlock listed with an automation cause, admin): 20/20 at every age
  (per_level.<age>.attack_success_admin); listed 20 at every age.
Verdict: NOT MET as scored: 10 trials at 15 or 30 s are "detected" on both monitors and 4 copy-mode trials disagree
(33 s x3, 5 s x1). B1 lists them and tests explanations (EXPLORATORY: every one of the 10 shares its second with a 45 s
trial's attributable row and its own row is benign_late; at row level 0 of 60 rows at 5/15/30 s are attributable on
either monitor).

### H2 insertion-only reattribution (A2-CTX, 10 per delay; arms.CTX)
Registered: at 5/15/25 s the displayed cause moves to the automation and the insertion is not attributable; at 45 s it
moves and is attributable.
Observed: displayed cause moved (attack_success_admin) 10/10 at every delay; detected 0/10 at 5, 15, 25 s and 10/10 at
45 s on both monitors; outcomes at 5 s copy reported_late 9, no_evidence 1; agreement direct 39/39 (1 ambiguous at 15 s),
copy 40/40. Verdict: MET.

### H3 observation window (A3-DEL, 10 per delay; arms.DEL)
Registered: detected iff an observable poll read the row before it was deleted; rate about delay / poll interval; 1 above
the longest poll interval.
Observed, detected per delay 1/2/3/4/5/6/8/10 s (per_delay.<d>.<m>.detected.k of 10): direct 2, 5, 6, 8, 10, 10, 10, 10;
copy 2, 3, 5, 4, 6, 10, 10, 10. Per-trial agreement with the scorer's prediction (an observable copy_at in [visible,
deleted)): direct 76/76 (4 ambiguous), copy 75/76 (4 ambiguous; trial 69 at 5 s predicted detected, observed
no_evidence). Attack success (unlock no longer displayed) 80/80. Verdict: PARTLY MET (one copy-mode disagreement, B1).
The scorer's detected_iff_observed field is confounded by key reuse (B1); with the original row's keylog observation,
detected iff observed holds in 80/80 trials on each monitor (EXPLORATORY, r16_e10_trial_deviations.json
summary.deletion.DEL.<m>.detected_iff_observed_original).

### H4 phase-aware deletion (A3-DEL-PH, 20; arms.DEL-PH)
Registered: M-direct detected in at most 4 of 20 (predicted near 0); M-copy as A3 at the realised visible time.
Observed: direct detected 1/20 [0.0013, 0.2487] (trial 1), agreement 20/20; copy detected 15/20, agreement 18/19
(1 ambiguous; trial 7 disagrees, B1). Visible time median 4.242 s, range 0.0022-4.707 s; sensor error (actual minus
predicted next direct copy) median 0.0042 s, 19 of 20 within 0.5 s (r16_e10_misc.json deletion.DEL-PH). Attack success
20/20. For comparison the non-adaptive A3 at 4 s and 5 s was detected 8/10 and 10/10 by M-direct. Verdict: MET.

### H5 reused lower key (A3-LOWKEY; arms.LOWKEY)
Registered: always detected. Observed: 4/4 on both monitors [0.398, 1.0] (trials 2, 3, 5, 8); 6 trials err-excluded
(above). Verdict: MET, on 4 trials only.

### H6 purge window (A5-PW, 6 declared purges, 3 per variant; arms.PW; r16_e10_cs_pw.json (8a167e3fd0f5) pw)
Registered: PW-B excused; PW-X, PW-U, PW-R, PW-F-out detected; PW-F-in not detected.
Observed (arms.PW.<event>.variants.<v>.<m>.detected): PW-R detected 3/3 on both monitors (keys_or_seconds_flagged 2
each); PW-F-out detected 3/3 (4 each); PW-F-in not detected 3/3. PW-B "not detected" 3/3, PW-U and PW-X "not detected"
3/3, but rows 0 in all 9: the band [c0, c1) and [c1, c1 + 30 s) held 0 state and 0 event rows in every pre-purge
snapshot (r16_e10_cs_pw.json pw.*.pw<i>_pre.states_in_band, events_in_band, states_in_c1_plus_30), so these variants
deleted nothing (rows_deleted_by_variant 0). Verdict: PARTLY MET; PW-B, PW-U, PW-X NOT EVALUABLE (empty band, B6).

### H7 sustained unobservability (A4; arms.UNOBS, UNOBS_cost, UNOBS_distinguishability, UNOBS_inflate_*)
Registered (parts): UL-W blinds neither monitor and rows more than 30 s late are attributable; UL-SHM makes every direct
read unobservable without stopping the hub, copy observes; a ~3 GiB unread table blinds copy mode (copy_raced) until a
repack, not direct mode; window inflation slows polls without unobservability; an edit sealed before a blind window is
detected, a row written and deleted inside it is not detected by the blinded monitor; the rule flags every attack-caused
unobservable interval and no interval of E9's week.
- UL-W (2 holds, 60.011 s and 60.004 s; r16_e10_unobs.json ul_w_holds.hold_s): unobservable polls 0 of 12 and 0 of 11 (direct), 0 of 11 and 0 of 11 (copy) (arms.UNOBS).
  MET. EXPLORATORY detail (r16_e10_unobs.json ul_w_holds): rows timestamped inside the holds, hold 1: 17 attributable
  and 19 benign_late on both monitors and both verifiers, largest lower bound 59.34 s (direct); hold 2: 14 / 10 (copy),
  9 / 15 (direct), largest 51.26 s (copy).
- UL-SHM (5 holds): direct polls with copy_at in the hold 4 per hold, unobservable 3, 4, 4, 4, 3 (direct_open_failed);
  copy 0 unobservable of 10-11 per hold (arms.UNOBS.<i>.direct/copy). Strictly, 22 of 24 in-hold direct polls were
  unobservable; the 2 observable ones (holds 1 and 5) began 9.85 s and 9.69 s before the lock ended and their opens,
  which take about 10 s under the lock, completed 0.232 s and 0.288 s after it ended (EXPLORATORY, r16_e10_unobs.json
  ul_shm_holds.*.polls.direct.read_end_minus_lock_end_s). The lock was held for every sample (held_samples = attempts,
  errors {} in all 5 posix holds). Launder detected on both monitors under both verifiers 5/5; blind deletion
  not detected by direct 5/5 (no_evidence), detected by copy 5/5. The hub kept committing (hold 1: the blind-delete
  actuation was visible at 1792583793.23 and the D1 row committed at 1792583841.12, inside 1792583783.11-1792583843.11;
  RUN/e10/c011219e9e_lock_shm.json). MET except the "every poll" wording (22/24 by copy_at).
- INF-T (3 GiB added at 12:11:52-12:12:10; dropped 12:17:11-12:17:28; repack published 12:17:31): copy mode was
  unobservable in 1 of 19 polls whose copy began between the end of the inflation and the repack (copy_raced, at
  12:12:13Z), copy_ms median 5,619.64 ms, max
  20,243.346 ms, poll interval max 21.43 s (r16_e10_unobs.json inf_t.monitors.copy.phase_table_present); predicted:
  every poll copy_raced. NOT MET. Direct: 54 polls, 0 unobservable (observable throughout, MET); the one due quick_check
  (seq 3601) took 7,674.306 ms (predicted about a minute); 9 polls took over 1 s without a due quick_check, 7 dominated
  by the append (995.8-7,367.8 ms) and 2 by the snapshot during the DROP TABLE (seq 3603, 784.8 ms; seq 3604,
  14,107.4 ms) (inf_t.monitors.direct.phase_polls_over_1s_without_due_quick_check). In the scorer's window (inflation to
  end + 1,200 s) copy-mode poll interval max 30.50 s, one interval above GAP_S (arms.UNOBS_cost.copy.inflate_table;
  r16_e10_unobs.json inf_t.scorer_window_intervals_over_30s).
- INF-W (300,000 rows between 12:37:32 and 12:47:42; arms.UNOBS_inflate_window): unobservable 0 on both; per-poll median 4,542.217 ms (direct) and 4,576.854 ms (copy)
  against 54.562 / 172.355 ms in the first session hour; poll interval max 14.10 s (direct), 11.34 s (copy)
  (arms.UNOBS_cost). MET. The junk seconds were not flagged at a_end (EXPLORATORY, r16_e10_routine_floor.json
  (2aca5a9ba665) inf_w_at_a_end: 0 flagged, 0 attributable rows in the window).
- Distinguishability rule: attack-caused intervals 6 (all direct), flagged 4 of 6 [0.223, 0.957]; the two unflagged
  lasted 46.055 s and 45.855 s (holds 1 and 5, cut short by the observable poll above); benign intervals 1 (copy_raced,
  12.398 s), flagged 0 (arms.UNOBS_distinguishability). "Flags every attack-caused interval": NOT MET. E9's week:
  arms.UNOBS_distinguishability_E9_benign_week = "no --e9-run-dir given" (not evaluated by the scorer); EXPLORATORY,
  same rule on E9's chains: 2 intervals (direct, 5.025 s and 5.019 s, direct_open_failed, both within 120 s of a hub
  start), copy 0, flagged 0 (r16_e10_unobs.json distinguishability_e9_benign_week).
- UL-JM refused ("database is locked"); UL-SHM-OFD (exploratory, no prediction): direct 4 of 4 unobservable, copy 0 of 11;
  the lock saw BlockingIOError in 241 of 8,118 attempts (r16_e10_unobs.json ul_shm_holds[5]).
Verdict: PARTLY MET (UL-W, UL-SHM, INF-W, launder/blind deletion as predicted; INF-T copy blinding and the rule's
true-positive clause not met; the E9-week clause not run by the scorer).

### H8 D1 live (UL-SHM D1 row; arms.UNOBS.<i>.d1_backdate)
Registered: E9 verifier late commit (escape), patched verifier unknown, attributable on M-copy.
Observed in 5/5 holds: direct_e9 reported_late, direct_patched unknown, copy_e9 and copy_patched detected (hold 1: row
backdated 70.01 s at commit). Verdict: MET.

### H9 D2 and D1h offline collusion (e10_main_collusion_direct.json (cddd7afcb34a), _copy.json (5ab9565d17ee))
Registered: honest violation; withheld, E9 verifier match, patched unknown (both checks).
- D1h (5 A1 45 s trials per monitor; 7-8 polls withheld direct, 7 copy): honest violation / violation, withheld E9 match,
  patched unknown, 5/5 on each monitor. MET.
- D2 (5 A7-WIPE seconds per monitor; 2 records withheld each): honest violation 5/5, withheld patched unknown 5/5, but
  withheld E9 verifier "violation_coarse_only" 5/5 on each monitor (cases.D2.withheld.e9), not "match". Under the
  outcome rule (e10_outcome.py, e9_dishonest_anchor.py) that label means the one-second segment reads as not flagged
  while a minute or hour root over it is flagged; the host withheld only records carrying the second's root or a keylog
  entry listing a deleted row (e10_collusion.py payload_carries).
Verdict: PARTLY MET (the registered E9 outcome for D2 was not observed).

### H10 D3 clock step (A6-CS; arms.CS)
Registered: rows written during a 60 s backward step attributable without a marker, excused under a CLOCK_STEP marker;
a 10 s step raises no violation.
Observed as scored (verdicts_of_rows_written_during_the_step, state keys only): steps 0-2 (60 s, marker): copy
benign_late 1, 0, 2; direct 0, 1, 0; no excused_clock_step and no attributable state row; step 3 (60 s, no marker): {} on
both (no attributable state row); step 4 (10 s): copy benign_late 1, direct benign_late 3. Markers accepted 3, rejected 0.
Verdict: NOT MET as scored. EXPLORATORY (B4): the emulated step moved the event rows' time_fired_ts but no state row's
last_updated_ts; for the moved rows every prediction held.

### H11 entity-id rename (B1; arms.ROUTINE.B1_entity_id_rename)
Registered: every sealed second, minute and hour holding a row of the entity fails, in the numbers predicted from the
recorder; no marker excuses it; the RENAME marker excuses the name-map transition.
Scorer: predicted_segments second 73,810, minute 27,015, hour 658 (rows 75,253); b1 attributable violations second
73,890 / 73,904, minute 27,017, hour 657 (direct / copy), which include the session's attack segments, so they are not
the comparison; namemap changed_with_declared_renames, namemap_unexcused 0. EXPLORATORY set comparison
(r16_e10_routine_floor.json routine.<m>.B1): flagged seconds 73,810 of 73,810 predicted (both monitors); violated
minutes 27,013 (direct) / 27,012 (copy) of 27,015; hours 657 of 658; new violations outside the predicted segments 0;
predicted segments excused 0. The unviolated hour is the rename's own (13:00Z; an hour seals only after it ends, after
b1_end) and the unviolated minutes are 11:52Z (both; sealed with 1 row while 33 rows were late, UL-W hold), 12:09Z
(copy; sealed with 9 rows, 24 late, OFD hold) and 13:08Z (the rename's minute, which could seal only after 13:09:00, i.e.
after the rename at 13:08:22; no entry in b1's violations list) (predicted_not_violated_entries_in_b1_violations). The
scorer's entity_segments rule counts every row timestamped 10 s before the rename, including rows that were late at
sealing or sealed after the rename. Keylog ranges were not
enumerated (b1 keylog_violations 6,728 vs 127 / 135 at a_end). Verdict: PARTLY MET (seconds exact; minute and hour
counts short of the scorer's predicted counts; name-map transition excused; nothing excused).

### H12 device removal (B2; arms.ROUTINE.B2_device_removal)
Registered: no recorder violation; name-map transition excused. Observed: b2 counts equal b1's on both monitors, and
the sets are equal (EXPLORATORY: routine.<m>.B2 flagged_equal_b1 and segs_equal_b1 true, 0 added, 0 removed);
device_present_after false; entities_after binary_sensor.kitchen_motion false; namemap changed_with_declared_renames,
namemap_unexcused 0 (no re-announcement transition). Verdict: MET.

### H13 entity history purge (B3; arms.ROUTINE.B3_purge_entities)
Registered: every sealed segment holding the purged entity's rows fails; no marker excuses it.
Scorer: predicted_segments sensor.homeprov_e10_junk second 610, minute 11, hour 1 (rows 300,000); cumulative counts only.
EXPLORATORY set comparison (routine.<m>.B3): in b3, 610 of 610 junk seconds flagged, 11 of 11 minutes and 1 of 1 hour
violated on both monitors; 25 seconds, 10 minutes and the hour had already been violated before B3 by B1 (rows of the
renamed light in the same segments; junk_*_before_b3_in_b2), so b3 - b2 adds 585 seconds and 1 minute; new violations
outside the junk segments 0; b3's excused violations are all PURGE-marker excusals of the forced purges (hour 79,
minute 3,468, second 40,629 segment_older_than_cutoff_gone, 3 purge_disconnect). Verdict: MET (on the exploratory set
comparison).

### H14 upgrades (B4, U; arms.ROUTINE)
Registered: no violation over the whole sealed history; schema_changes gains 52 and 53 in 2025.11.1 -> 2026.7.4; (U arm)
statistics_meta gains unit_class, states/events columns unchanged.
Observed: U verifications pre/post/final all 0 violations, 0 flagged, 0 keylog on both monitors; schema_changes 51, 52, 53
(U_schema_upgrade.upgrade.after). B4: schema_changes [53] before and after, columns equal; b4 counts equal b3's and the
sets are equal (EXPLORATORY routine.<m>.B4 true, 0 added). But the fresh 2025.11.1 recorder already had
statistics_meta.unit_class before the upgrade (U's upgrade record has before null; EXPLORATORY
r16_e10_u_schema.json (83d1592dd136) pairs.U.before.statistics_meta and columns_changed {} for states, events,
statistics_meta). Name map: U unchanged; B4 adds no unexcused transition. Verdict: PARTLY MET ("gains unit_class" not
observed; the 51 -> 52 ADD COLUMN was not executed in E10, live or offline (O-MIG m52 skipped: column already present)).

### H15 hardening and re-verification (e10_reverify_patched.json (5a7342783ee7); unobservable reasons)
Registered: hardened records equal E9's (tests); no E10 poll fails with schema_object_not_a_table or quick_check_failed;
re-verifying E7, E8, E9 changes no flagged second and every other difference has a listed reason.
Observed: tests passed (above); unobservable reasons in every E10 chain: e10s direct direct_open_failed 22 (all in the
UL-SHM holds), e10s copy copy_raced 1, e10u 0 (r16_e10_unobs.json unobservable_by_stack); E arm quick_check failed 0
(r16_e10_misc.json pi4.*.quick_check_failed). REVERIFY totals: flagged_seconds_changed 0, unattributed 0,
verdict_changes_by_patch D1 21, comparisons_failed [], refused_by_hardening [], verify_all_status ok. Verdict: MET.

### H16 benign floor (arms.floor)
Registered: no flagged second of the main session unexplained by an arm (predicted 0).
Observed: unexplained 73,349 (direct) / 73,348 (copy) of 74,553 / 74,567 flagged seconds; the first listed are
historical seconds (2026-09-22). Verdict: NOT MET as scored. EXPLORATORY (B2): every one of them is a second holding a
row of the renamed entity (73,322), in a keylog range naming a trial key (13 / 12) or holding the successor of a row
WIPE deleted (14); 0 remain.

### H17 sham specificity (S, 90; e10_main_r5_score.json S_sham)
Registered: 0 of 90 per monitor with a violation attributable to the trial; db_writes 0; S-CTX display unchanged; S-DEL
unlock listed; attack trials at the same levels violated.
Observed: overall 0/90 on each monitor, exact 95% [0, 0.0402] (two-sided, as in the file; the registration's one-sided
bound is 0.0327); per variant 0/30 [0, 0.1157]; sham_db_writes_total [0]; S-CTX displayed cause changed 0 of 30, S-DEL
listed 30 of 30 (r16_e10_misc.json sham); confusion at the target seconds: attack violated 20/20 (BDT 45 s), 10/10
(CTX 45 s), 10/10 (DEL 10 s), sham not violated 30/30 per variant, both monitors. Verdict: MET.

### H18 restart mid-poll (R, 10; R_restart)
Registered: no attributable row, no flagged second, no monitor restart; late rows benign_late (E9) and benign_late or
unobserved_late (patched, the latter iff a D1 break); no flagged unobservable interval; recorder never moved away.
Observed: attributable rows 0 (E9 and patched), flagged seconds 0, unobservable polls 0, suspicious intervals 0 on both
monitors (summary); monitor restarts 0, corrupt files 0 after every trial (after); late rows benign_late 65 (direct) and
43 (copy) under both verifiers, unobserved_late 0, gap_above_gap_s 0 in every window (r16_e10_misc.json restarts).
Landing in the target window 1 of 10 (trial 9, kill -> M-direct); fire error median 0.092 s, max 2.18 s. The hub logged
"could not validate that the sqlite3 database ... was shutdown cleanly" after each kill (09:40:23, 09:45:53, 09:51:25).
Verdict: MET (landing reported; not a condition).

### H19 Domoticz switch type (C; e10_main_dzst_switchtype_score.json (9b04e7848836))
Registered: violations on exactly the anchored segments holding a lock log row first anchored before the change; offline
roots change exactly those seconds; the renderer changes; no marker.
Observed: change applied (SwitchType 19 -> 20, reply OK); violations second 20, minute 10, hour 0 against predicted 20, 10,
0, agree at every granularity, 0 ambiguous, 0 predicted-not-observed, 0 observed-not-predicted; offline pre vs final:
20 seconds changed, equal to the predicted set; rendered rows changed owner 20, member 20, guest 20; markers none.
Verdict: MET.

### H20 pairwise closure (D; e10_pairwise_closure.json)
Registered: undetected_render_change 0, joint_only 0, conditional_noncl 0 per stratum; coverage reported.
Observed: all 12,513 units done in 2,342.4 s (stopped "all units done"); restore checks equal before and after.
undetected_render_change 0 in W (10,513), V (1,000), X (1,000) (one-sided 95% upper bounds 0.000285, 0.002991, 0.002991);
conditional_noncl 0; joint_only W 5, V 1, X 0 (per_stratum). The six (examples.joint_only): last_changed_ts with
old_state_id (T15), last_changed_ts with state (T39, T11, T12), old_state_id with state (T28), attributes_id with attributes
(T38), all closure fields, and none left the stable commitment unchanged (undetected 0). Coverage of the logbook package
(coverage.marks): lines 436 of 1,107 and branch outcomes 171 of 584 after the singles; W, V, X added none; 229 branch
sites never taken. Verdict: PARTLY MET (primary 0 met; joint_only predicted 0, observed 6).

### H21 Pi 4-class cost (E; e10_pi4_cost.json (17b34d27d82e), per-profile files)
Registered: under the pi4 profile the direct monitor's median poll stays below 5 s at 0.19 and 0.96 GB with no poll above
30 s except a due quick_check; copy mode writes about the recorder's size per poll; pi4/ref ratio reported; exploratory
at 2.94 GB.
Observed (runs.<run>.per_poll_total_ms, overruns): pi4 direct 0.19 GB median 282.012 ms, max 752.886 ms; 0.96 GB median
781.471 ms, max 2,033.69 ms; over PERIOD 0, over GAP_S 0 in both (no quick_check in the measured polls). Copy, 0.19 GB:
write per poll median 196,237,312 B (pi4) and 194,078,720 B (ref) for a 191,459,328 B recorder (ratio 1.025 and 1.0137,
r16_e10_misc.json pi4); bytes written per hour 28,691,128,659 (pi4) and 80,152,715,458 (ref). Median ratios pi4/ref:
direct 3.133 (0.19 GB), 2.468 (0.96 GB), 2.655 (2.94 GB); copy 5.131; pi4cpu_half 1.255; pi4cpu_eighth 8.213.
Exploratory parts: pi4 2.94 GB median 2,107.651 ms, max 5,371.601 ms, 1 poll over PERIOD; pi4 copy median 20,467.936 ms,
30 of 30 over PERIOD, 1 over GAP_S (41.96 s); unobservable 0 in all 10 runs. The profile is an assumed Docker cap, not a
measured Pi 4. Verdict: MET.

### Offline O-MIG (e10_main_migration_offline.json (a0aed96879b7))
Registered: m52 and a new index no violation; a states column fails every sealed segment holding a state row and every
states keylog range.
Observed (shapes.<s>.violations; baseline "none" = no statement: second 115,108, minute 30,486, hour 736, keylog 10,043,
on the final snapshot that holds the arms, B1, B3 and the forced purges): index identical to none (no added violation);
m52 identical to none because it was skipped ("column already present"); column: second 413,161 of 419,143 checked,
minute 35,341 of 35,343, hour 738 of 738, keylog 12,354 of 18,299 ranges. The file does not list which segments hold a
state row; EXPLORATORY consistency: in the final snapshot 371,982 seconds hold a state row and 378,011 hold any row
(r16_e10_routine_floor.json o_mig_final_snapshot); the checked seconds left unviolated under the column shape are fewer
than the seconds holding only event rows, which is consistent with the prediction. Verdict: index met; m52 not
evaluable on this snapshot; column consistent with the prediction, "every" not checkable from the saved counts.
Duration 5,063.5 s (B8).

## B. Exploratory

### B1 Every deviating per-trial outcome (r16_e10_trial_deviations.json summary.deviations; script exp/sp2027/r16_e10_trial_deviations.py)
Inputs: the score's per_trial, the scorer's cached 'del' verifications (RUN/verify/e10s_<m>_del_2ce8d89407a1.json), the
e10s chains and cost logs (streamed), the trial records. "lag" = t_commit - forged row ts (the actual backdate at commit);
"scorer lb" = the scorer's predicted lower bound (last copy_at before t_commit minus ts); "verifier" = the row's own
verdict and committed_after_lower_bound_s in the verification.

(a) Shared second with a 45 s trial's attributable row: 19 of 25 (BDT only)
| trial | age | monitor | predicted -> observed | lag s | scorer lb s | verifier row | row in the same second |
|---|---|---|---|---|---|---|---|
| 22 | 30 | direct / copy | reported_late -> detected | 30.002 | 29.783 / 26.956 | benign_late 29.783 / 26.956 | BDT 23 (45 s) |
| 40 | 15 | direct / copy | reported_late -> detected | 15.005 | 12.803 / 14.871 | benign_late 12.803 / 8.785 | BDT 42 |
| 45 | 15 | direct / copy | reported_late -> detected | 15.001 | 13.862 / 13.319 | benign_late 13.862 / 13.319 | BDT 47 |
| 53 | 15 | direct / copy | reported_late -> detected | 15.009 | 10.392 / 12.401 | benign_late 10.392 / 12.401 | BDT 55 |
| 60 | 30 | direct / copy | reported_late -> detected | 30.002 | 26.655 / 25.558 | benign_late 26.655 / 25.558 | BDT 61 |
| 62 | 30 | direct / copy | reported_late -> detected | 30.008 | 27.296 / 29.300 | benign_late 27.296 / 29.300 | BDT 63 |
| 65 | 30 | direct / copy | reported_late -> detected | 30.009 | 27.820 / 24.245 | benign_late 27.820 / 24.245 | BDT 66 |
| 94 | 15 | direct / copy | reported_late -> detected | 15.003 | 13.995 / 11.016 | benign_late 13.995 / 11.016 | BDT 96 |
| 95 | 30 | direct / copy | reported_late -> detected | 30.001 | 29.145 / 28.107 | benign_late 29.145 / 28.107 | BDT 96 |
| 98 | 30 | copy (direct ambiguous) | reported_late -> detected | 30.018 | 28.649 | benign_late 28.649 | BDT 99 |
Pattern: the scorer's row_outcome() returns "detected" when the row's second is flagged; each of these 10 trials' forged
row lies in the same one-second segment as a 45 s trial's forged row, which is attributable and flags that second. The
plan inserts a forged row every 15 s and timestamps it insertion minus age, so a 45 s trial targets the second of the
30 s trial inserted before it or the 15 s trial two before. The deviations therefore cluster at 30 s (6 trials) and
15 s (4 trials) because those ages collide with 45 s, not because the lag approached the 30 s bound: every one of these
rows is benign_late with a verifier lower bound of 8.785-29.783 s, below 30 s, and lags of 15.001-15.009 s and
30.001-30.018 s.

(b) Copy mode: the prediction poll began before t_commit but already held the row: 4 of 25 (BDT)
| trial | age | predicted -> observed | lag s | scorer lb s | verifier | prediction poll copy_ms / held key | commit duration s |
|---|---|---|---|---|---|---|---|
| 10 | 33 | detected -> reported_late | 33.375 | 32.954 | benign_late 27.527 | 268.6 / yes | 0.3747 |
| 29 | 33 | detected -> reported_late | 33.341 | 32.841 | benign_late 27.433 | 169.6 / yes | 0.3412 |
| 79 | 33 | detected -> reported_late | 33.056 | 32.873 | benign_late 27.290 | 132.6 / yes | 0.0564 |
| 34 | 5 | reported_late -> no_evidence | 5.308 | 4.828 | none (row in its sealing copy) | 213.9 / yes | 0.3077 |
Pattern: in copy mode copy_at is the time the copy began (monitor.py: copy_at = copy_start); the copy's watermark already
held the forged key, so the row was in it, and the verifier's lower bound comes from the poll before (27.3-27.5 s, below
the bound). In all four the forged insert's commit was slow (t_commit - t_insert 0.056-0.375 s; median over the 100 BDT
trials 0.0036 s, 9 trials above 0.05 s: summary.bdt_commit_duration_s), so the recorded t_commit trails the moment the
row became readable. Here the deviations do lie near the bound: the copy-start bound put 32.8-32.95 s on the far side of
30 s while the content-based bound was below it. In direct mode no prediction poll held the key (summary
scorer_poll_held_key: BDT_direct held [], copy held trials 7, 10, 26, 29, 34, 40, 46, 79, of which 7, 26, 46 are
ambiguous and 40 is in (a)).

(c) Deletions, copy mode: 2 of 25
- DEL trial 69 (5 s), predicted detected, observed no_evidence. Visible 1792570948.368, deletion committed
  1792570953.621. Copy poll 790 began 1792570953.125 (copy_ms 257.9) with states watermark 1268167, below the row's key
  1268168: the copy did not contain the row. The direct monitor's polls 916 (1792570948.396) and 917 (1792570953.526)
  both held the key (watermark 1268168 in both). A scan of all 3,629 copy-mode polls of the A phase for a
  watermark below one the direct monitor had already read, not explained by a trial deletion committed before the copy
  ended, finds exactly this poll (summary.copy_staleness_scan.n_hits 1). Not explained by the saved data. Candidate
  (EXPLORATORY, untested): the copy (database file, then -wal) interleaved with a checkpoint or WAL restart that the
  salt check did not catch. The scorer's prediction was right that a copy began in the window; that copy lacked the row.
- DEL-PH trial 7, predicted no_evidence, observed detected. Visible 1792571399.380, deleted 1792571403.625; copy poll 867
  began 1792571398.874 (before the row was visible), copy_ms 964.3, watermark 1268363 = the key: it held the row and
  is the first keylog observation of it. Same mechanism as (b).

Tests against saved data (EXPLORATORY; summary.insertion_by_level, summary.deletion):
- Row-level reading (the inserted row's own verifier verdict, ignoring other rows in its second): attributable at
  5 / 15 / 30 s 0 of 20 at each age on both monitors; 33 s 13/20 (direct), 7/20 (copy); 45 s 20/20 on both; CTX 0/10 at
  5, 15, 25 s and 10/10 at 45 s on both.
- The design's watermark-aware rule (latest observable copy among polls whose watermark is below the key, computed from
  the chain) agrees with the verifier's row verdict in 280 of 280 insertion trial-monitor pairs; its lower bound equals
  the verifier's committed_after_lower_bound_s within 5e-7 s at every level (max_abs_diff_design_lb_vs_verifier_lb).
  This shows the verifier implements the registered rule; the 23 BDT deviations come from the scorer's reading of a
  shared second and from its copy-start timing, not from the verifier.
- Deletions: detected iff an observable poll's keylog listed the original row (key and its own second) in 80/80 DEL and
  20/20 DEL-PH trials on each monitor. The scorer's observed_by_keylog is confounded by key reuse: DEL 12 (direct) / 18
  (copy) and DEL-PH 11 / 2 trials were marked observed only through a later row that reused the freed key
  (scorer_observed_but_only_by_reused_key; the LOWKEY err trials show the same reuse).

### B2 Benign floor re-scoped (r16_e10_routine_floor.json floor; script exp/sp2027/r16_e10_routine_floor.py)
The scorer's rule recomputed reproduces its unexplained counts (73,349 direct, 73,348 copy). Split: 73,322 hold a row of
the renamed entity (72,963 before t0, 359 in the session); 0 hold a junk row; the remaining 27 (direct) / 26 (copy) are
all in the session (07:35-08:33Z), all already flagged at a_end and all inside an a_end keylog violation: 13 / 12 in a
range naming a trial key, 14 in a range holding the successor of a row WIPE deleted (old_state_id before WIPE was a
wiped state row in 16 of 16 / 18 of 18 rows; not_explained_detail). The keylog rule flags every second the changed
range's rows sit in, and WIPE nulls the successors' old_state_id as Home Assistant's purge does. 0 seconds remain
unexplained on either monitor. Restricted to the session window, flagged seconds were 1,589 (direct) / 1,603 (copy).

### B3 Routine operations as sets (same file, routine) - summarised under H11-H14.

### B4 Clock step, all tables (r16_e10_cs_pw.json cs.steps; script exp/sp2027/r16_e10_cs_pw.py)
Rows written during each step (keys between the step's watermarks, cs_end snapshot) and their verdicts in the cs
verification, both monitors identical unless noted:
- Steps 0, 1, 2 (60 s, marker): events 13, 14, 14 rows, all timestamped before the step's start (up to 55.4 s), all
  excused_clock_step (lower bounds 55.3-60.3 s); states 25, 27, 28 rows, none timestamped before the start, on time
  except 1-2 benign_late with lower bounds under 1 s.
- Step 3 (60 s, no marker): events 10 of 12 attributable (lower bounds 55.2-60.1 s), 2 on time; states 23 on time;
  7 flagged seconds in the step window.
- Step 4 (10 s, no marker): events 13 benign_late (lower bounds 5.1-10.2 s), 2 on time; states benign_late 1 (copy) / 3
  (direct); 0 flagged seconds.
So in Home Assistant 2026.7.4 the emulation (time.time() in the hub's process) moved time_fired_ts but not
last_updated_ts, contrary to the design's assumption that both are stamped with time.time(); for the rows it moved, the
registered predictions held. The confirmatory scorer counted state rows only.

### B5 UL-SHM, INF-T, INF-W details - under H7 (r16_e10_unobs.json; script exp/sp2027/r16_e10_unobs.py).

### B6 A5-PW bands (r16_e10_cs_pw.json pw)
c0 = scheduled - 29 d fell between 2026-09-22T10:26:06Z (event 0, c0 1790072766) and 11:41:07Z (event 5, c0
1790077267), where the seed recorder (E9's final snapshot) is sparse: in every pre-purge snapshot the band [c0, c1) and
[c1, c1 + 30 s) held 0 state and 0 event rows, and the first state at or after c0 lies after c1 in every event
(pw.*.pw<i>_pre.first_state_ts_at_or_after_c0). PW-B, PW-U and PW-X therefore deleted 0 rows (RUN/e10/*_pw.json
actions.*.states_deleted []); the registration has no rule for an empty band, so the three variants are reported as not
evaluable, not as misses.

### B7 Copy staleness scan (r16_e10_trial_deviations.json summary.copy_staleness_scan): 1 hit in 3,629 copy polls (B1 c).

### B8 Timing, including O-MIG (r16_e10_misc.json timing; script exp/sp2027/r16_e10_misc.py)
run_e10.sh writes, in order, the score, r5 score, collusion (direct), collusion (copy) and migration files; their last
writes were 15:25:31, 15:29:33, 15:55:23, 16:21:19 and 17:45:42Z, so the r5 score took 242.3 s, the collusion checks
1,549.3 s and 1,556.2 s, and O-MIG 5,063.5 s. O-MIG runs four whole-history verifications of the final
snapshot in sequence (e10_migration_offline.py); for comparison the scorer's whole-history b3/b4 verifications took
998.2-1,155.0 s each (e10_main_score.json verifications.*.wall_s). The scorer's 52 verifications sum to 11,017.4 s of
verifier time on 2 parallel jobs.

### B9 Residue and recorder behaviour (r16_e10_misc.json deletion)
After the adversary's cache eviction, the hub kept recording (every later trial captured its own actuation row: err 0 in
del, delph, sham). A forensic residue remained in some trials: a later row whose old_state_id still named the deleted row
(dangling_successors) in 14 of 80 DEL trials and 5 of 20 DEL-PH trials.

### Files written for these notes (all new; scripts in exp/sp2027, outputs in exp/out opened with mode "x"; inputs read only, run folder untouched)
| output (sha256) | script (sha256) | content |
|---|---|---|
| r16_e10_trial_deviations.json (37024fea15bf) | r16_e10_trial_deviations.py (0808a4539b3e) | B1, B7 |
| r16_e10_agreement_totals.json (e8b6123ecb04) | r16_e10_agreement_totals.py (73e76d62074e) | agreement totals |
| r16_e10_unobs.json (664cf1f0c4d5) | r16_e10_unobs.py (9f3f9211b10e) | H7, H15, host gaps, E9-week rule |
| r16_e10_cs_pw.json (8a167e3fd0f5) | r16_e10_cs_pw.py (64db4b35ee8a) | B4, B6 |
| r16_e10_routine_floor.json (2aca5a9ba665) | r16_e10_routine_floor.py (031e5d66b10b) | B2, H11-H14 sets, INF-W, O-MIG counts |
| r16_e10_misc.json (65fdffc5f568) | r16_e10_misc.py (e09c50364e41) | B8, B9, R, S, E details |
| r16_e10_u_schema.json (83d1592dd136) | r16_e10_u_schema.py (34c2de225d9b) | H14 schema before/after |
Other cited files: e10_main_dzst_switchtype_report.json (4d803801c194), e10_main_dzst_config.json (55d7f2723fce),
e10_pi4_cost_ref.json (7cf6af36f7ae), _pi4 (36e3946a12a4), _pi4cpu_half (ac13921ba2ef), _pi4cpu_eighth (2d276038e525),
e10_main_plan.json (ea0fdc20e534), HLOG/e10_main_r5.out (c19ad53f9771).

### Not computed (registered secondary outcomes)
- A1/A2 late-commit lower bounds against the largest benign late delay of E9's week; seal delay during INF-T and INF-W;
  the keylog-range part of B1's prediction. Each can be added from the saved files if the paper needs it.

## Open questions for the PI
1. H1 and H16 are NOT MET as scored, and B1/B2 show both misses come from the frozen scorer's counting (shared seconds
   in A1's plan; whole-chain floor), with the verifier's row verdicts as predicted. How should the paper report them:
   the scored verdicts with the exploratory row-level reading beside them (recommended by the registration's own rule),
   and should a corrected scorer be written as an amendment for future runs only?
2. H10: the clock-step arm did not move state timestamps in 2026.7.4. Report as NOT MET with B4's event-row result, and
   state the emulation limit (only time_fired_ts moved)?
3. Copy mode: one validated copy (began 1792570953.125) lacked a committed row that the direct monitor had read at
   1792570948.396 (DEL 69, B1 c).
   Investigate the copy procedure (db file then WAL, salt check) before the paper claims copy mode's observation window?
4. H6: PW-B, PW-U, PW-X were not exercised (empty bands). Re-run A5-PW with a keep value whose band holds rows, as an
   amended arm, or report as not evaluable?
5. H14 / O-MIG: no E10 step executed the 51 -> 52 ALTER on statistics_meta (present at 51 already). The paper should not
   say E10 crossed that ALTER live.
6. H7: INF-T did not blind copy mode at 3 GiB (1 of 19 copy_raced, copies of about 5.6 s); the E8-era prediction does not
   carry to the hardened monitor. The distinguishability rule missed 2 of 6 attack intervals of about 46 s. Keep the
   rule as a discussion heuristic with these numbers?
7. H9 D2: the E9 verifier was not fooled to "match" because the coarse minute/hour roots were not withheld. Present D2
   as "one-second segment reads clean, coarse segments still flag" rather than the registered "match"?
8. H20: six joint-only pairs, all of closure fields and all changing the stable commitment. The stated property
   "no pair of fields that each leave the output unchanged changes it jointly" does not hold; the security-relevant one
   (undetected render change) does.

## DEL 69 investigation (2026-10-24)
PI-approved follow-up on the copy-mode anomaly of B1 (c) / B7 / open question 3. Saved data only; EXPLORATORY. Files:
exp/out/r16_e10_del69.json (2e5c86d5fc04; script exp/sp2027/r16_e10_del69.py, 086caf52dac8) and
exp/out/r16_e10_del69_overlap.json (db8c9f6fa183; script exp/sp2027/r16_e10_del69_overlap.py, cf9e88bed501). This
section supersedes the "not explained" and "staleness" readings in B1 (c), B7 and open question 3; nothing above is edited.

How the copy is taken (frozen monitor/monitor.py, registered sha256 4b9931cb7d1c): snapshot() copies the recorder file,
then -wal, then -shm into scratch with shutil.copy2, one after the other, while the hub keeps writing; the poll records
copy_at = the time the copy began; the WAL header salts are read before and after the copy and the copy is repeated up to
3 times if they differ (else copy_raced); validate_files() checks the database header and the -wal size against the
-shm frame count; quick_check runs at every copy-mode poll (HOMEPROV_QUICK_CHECK_EVERY=1, e10_main.out). Each read of
the copy then opens its own connection to the static scratch files. Poll 790 was a single attempt (copy_at minus the poll
start from the cost log 1e-06 s; polls_window.copy.790.copy_at_minus_poll_start_s), validated and observable; it ended
at 1792570953.382827 (cost ts; copy_ms 257.917).

The row (trial_69; row_in_snapshots): state 1268168 is DEL trial 69's own actuation row (lock.front_door "unlocked",
ts 1792570948.3302, old_state_id 1268159, context 01a15d8d...), written with the call_service event 702801 (ts
1792570948.3285, same context), readable to the adversary at 1792570948.368. The deletion transaction began at
1792570953.3702 (t_delete_start, taken just before BEGIN IMMEDIATE) and COMMIT returned at 1792570953.6212: 0.251 s,
the 5th slowest of the 100 DEL / DEL-PH delete transactions (median 0.004 s; 11 above 0.05 s;
delete_transaction_durations). Key 1268168 was then reused by a "locked" row at 1792570955.643 (another context;
row_in_snapshots.snap_del), which is the key copy poll 791 lists (row second 1792570955; keylog_listings_of_key_1268168).
No copy poll ever listed the original row; direct poll 916 did (row second 1792570948).

What the two monitors read (polls_window; escrow_second_1792570948):
- direct 916 (copy_at 1792570948.396): wm states 1268168, events 702801.
- copy 790 (copy began 1792570953.125, ended 1792570953.383): wm states 1268167, events 702801; its keylog lists event
  702801 (second 948) and no new state row; it sealed second 1792570948 with n = 1, and the escrow shows the one folded
  node is e:702801.
- direct 917 (copy_at 1792570953.526, inside the deletion's transaction window): wm states 1268168, events 702801; it
  sealed second 1792570948 with n = 2, nodes e:702801 and s:1268168. The live database still showed the row after
  poll 790 had ended.
- copy 791 / direct 918 (1792570958.757 / .638): identical watermarks (states 1268172, events 702804).
So copy 790's content is exactly the database after the deletion (event kept, its state row gone, states watermark one
below), and the verifier finds second 1792570948 unflagged on the copy chain against the post-deletion snapshot
(verifier_del.copy), i.e. 790's root equals the post-deletion content; on the direct chain the deletion is detected
(second flagged; keylog violation "changed" on s:1268168, first observed in 948, now a row of 955).

Was it stale? No. The deletion's write began 12.6 ms before copy 790 ended (1792570953.3702 vs 1792570953.3828), and the
-wal and -shm are the last things copied; live readers did not see the deletion until after 1792570953.526 (direct 917).
The copy therefore contained a commit that had not yet been published to live readers. The same happened in every
decidable case (r16_e10_del69_overlap.json summary): of the copy polls that ended after an adversary write had begun
but before its COMMIT returned, 5 of 5 already reflected the write (BDT inserts 10, 29, 34, 79, ending 0.0053-0.222 s
after the write began and 0.051-0.330 s before the commit returned; DEL 69); the 2 direct polls whose snapshot fell
inside an adversary write window (DEL 69 poll 917, DEL-PH 1 poll 975) did not reflect it. These are the same four BDT
trials as B1 (b). The whole-session scan of r16_e10_del69.json (copy polls whose watermark is below one the direct
monitor had read before the copy began) found one hit in 5,447 copy polls (e10s 4,037, e10u 1,410;
staleness_scan_whole_session): poll 790. It was listed only because the scan filtered deletions by the time their COMMIT
returned (1792570953.6212); the deletion began before the copy ended (copy_end_minus_write_start_s 0.012623 in the
overlap file). So no copy poll in E10 lacked a row that the direct monitor had read before the copy began, other than
through a deletion already under way.

Checkpoints: not visible in the saved data (no WAL or -shm sizes, salts or backfill counts are logged; the hub log is
silent at 08:22Z; the host log samples I/O once a minute). The explanation above does not depend on one. A torn-copy
alternative (a checkpoint rewriting the database file during the copy) was considered: it needs a concurrent write the
data do not show, and it would have to reproduce the post-deletion content exactly by chance.

Conclusion: (a) cause identified. Copy 790 did not miss a row that existed; it captured DEL trial 69's own deletion,
whose WAL frames were written while the copy was being taken, before the deletion was published to live readers (and
before its COMMIT returned, 0.251 s after it began). The scorer predicted "detected" from copy_at (the copy's start), but
the copy's content postdates the deletion. Residual, not checkable from saved data: the SQLite-internal step (a copy of
the -wal holding frames of a commit that live readers do not yet see, counted as committed when the copy is opened) is
inferred from 5 of 5 copy and 0 of 2 direct cases, not observed directly; the frames' exact write time is not recorded.
An offline reproduction (copy a WAL database with shutil while another connection commits slowly) would confirm it and
needs a separate approval. Why the adversary's commits were slow is not determined.

Consequence for copy mode's guarantee. A copy's content is a state at, or slightly after, copy_at: it can include any
write whose WAL frames are in the file when the -wal is copied, up to the copy's end (copy_ms; 257.9 ms here) and even
before that write's commit is visible to other readers; in E10 no copy lacked a row the direct monitor had read before
the copy began, except through a deletion already under way. Hence:
- What it can hide: a row whose whole life (commit to deletion) contains no copy whose -wal read falls between the
  row's commit and the deletion's write. The observation condition for copy mode is that window, not "copy_at between
  commit and deletion" (the scorer's rule, over-optimistic at the window's end by up to one copy duration plus the
  in-flight commit time, and over-pessimistic at its start, as DEL-PH 7 shows). A row never observed by copy mode can
  also be rewritten undetected by copy mode before it is deleted (copy mode never observed row 1268168 at all; the
  direct monitor did, and detected the deletion).
- What it cannot hide: any change to a row an earlier poll already observed (sealed roots and keylog entries are frozen
  at first observation and never recomputed), and anything at the next poll, which copies the files again from scratch
  (poll 791 matched the direct monitor). The verifier's rules use the watermark (what the copy held), not copy_at, for
  presence; a row absent from a copy that began before the row's commit returned is still bounded correctly from below by
  that copy's copy_at, so the late-row test is not loosened. If a copy's content were older than copy_at (not seen in the scan), the
  rows it omitted would reach the verifier as late rows with an overstated committed-after bound, which errs toward
  attributable (false alarms), not toward escape.
- For the paper: describe the copy-mode observation instant as "the moment the copy read the WAL (between copy_at and
  copy_at + copy_ms, possibly including a commit then in progress)", and do not claim from E10 that copy mode observes a
  row that lives through a copy's start. The recommended direct mode is unaffected: its snapshot is taken at the read and
  showed no write before it was published (2 of 2).
