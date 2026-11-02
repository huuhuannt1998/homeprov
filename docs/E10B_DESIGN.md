# E10b design: E10's backdating arm (H1) re-run, spaced, scored from each trial's own row; H10's clock step with state rows

Prepared 2026-10-24 (UTC), after the PI's approval ("Let's do it", 2026-10-24 about 17:45Z, relayed by the coordinating
session). Nothing in this document has been run on Docker; the unit tests and the draft registration were run.
E10b runs after another project's long run on this Mac has ended.

Pre-registration generator: `testbed/e10b/e10b_prereg.py` (draft `exp/out/e10b_preregistration_draft.json`; the
registered file will be `exp/out/e10b_preregistration.json`). Code: `testbed/e10b/`. Basis from E10's saved data:
`exp/out/r16_e10_e10b_basis.json` (sha256 e070155a59b1, script `exp/sp2027/r16_e10_e10b_basis.py` b0500c9ff3c2) and
`exp/out/r16_e10_copyview.json` (58da5d1686f3, script `exp/sp2027/r16_e10_copyview.py` bdc20463c3f1). Every number below
names its file and field; "basis" means `r16_e10_e10b_basis.json`, "copyview" means `r16_e10_copyview.json`.

HOMEPROV detects rewriting after the monitor has sealed a segment; it does not prevent it. E10b tests the stated
backdating boundary again; it does not move it.

## 1. Why E10b

E10's A1-BDT arm (H1) was NOT MET as scored (`E10_RESULTS_NOTES.md`, sha256 03fd59c453d7). The deviations traced to the
arm's plan and to its registered scorer, not to the verifier:

1. **Plan collisions.** Trials were 15 s apart with ages 5 to 45 s, so a later trial's forged row could land in the same
   or the neighbouring one-second segment as an earlier one. In E10's realised trials, 15 pairs of forged rows had equal
   or adjacent seconds, involving 27 trials; the closest two targets were 0.0033 s apart (basis `e10_collisions.n_pairs`,
   `trials_in_a_pair`, `min_gap_between_targets_s`).
2. **Segment-based scoring.** The registered `row_outcome` (frozen `exp/stages/e10_score.py`) counts a trial as detected
   whenever its second is flagged, so a benign row in a second flagged by another trial's attributable row counted as
   detected.
3. **Copy mode's observation instant.** The registered prediction used `copy_at < t_commit`. A copy-mode poll starts at
   `copy_at` but reads the `-wal` later, and can hold a transaction whose COMMIT has not yet returned (the DEL 69
   investigation, `exp/out/r16_e10_del69_overlap.json`, db8c9f6fa183).

E10b re-runs the same arm on the same stack and monitors, spaced so that no two forged rows share or neighbour a second.
Each trial is scored from its own row, and the segment verdict is kept as a consistency check. This makes it a
confirmatory test of H1's boundary with the scorer fixed in advance. Re-scoring E10's own data with the new scorer is
exploratory; section 5 reports that dry run.

## 2. What stays the same and what changes

| | E10 (A1-BDT, A6-CS) | E10b |
|---|---|---|
| levels, n | 5, 15, 30, 33, 45 s; 20 each | same (imported from frozen `testbed/e10/e10ops.py`) |
| in-hub op | homeprov_e10 `bdt` | same op, unchanged |
| stack | `e10_stack.sh up-lab`, HA 2026.7.4, E9's final recorder | same script, prefix `e10bs` |
| monitors | direct (quick_check every 720), copy (every poll), E10 settings | same settings; images rebuilt from the same Dockerfiles under tags `:e10b`, contents checked against the repository |
| verifier | patched `e7_verify.py`, late bound 30 s, gap 30 s | same file and parameters (called through E10's `verify_job`) |
| spacing / seed | 15 s / 20261020 | **50 s / 20261024** |
| snapshot scored | `snap_del` (after A2-A3) | **`snap_bdt`, right after the BDT block** |
| per-trial outcome | the second flagged (`row_outcome`) | **the own row's verdict**; segment flag = consistency check |
| prediction | last copy before `t_commit` minus ts > 30 s | **the verifier's late-row logic over every lacking/holding split of the polls whose observation window overlaps the write** (section 4) |
| clock step | `clock_step` (time.time only); H10 scored on state rows | **`clock_step_all`** (time.time and `helpers.entity.timer`); scored on state and event rows (secondary arm) |
| other arms | CTX, DEL, PW, UL, INF, B1-B4, S, R | none |

## 3. Schedule arithmetic (no shared or adjacent second)

[Withheld from the artifact: how the in-hub adversary's backdating op paces its trials and what it does before each insertion; for the bound below, trial i starts at start_i with start_j >= start_i + (j - i) * spacing for j > i, and inserts at t_ins_i = start_i + delta_i, where delta_i >= 0 is the time from the trial's start to its insertion. See README.md, "What is deliberately not here".] It timestamps its row `target_i = t_ins_i - age_i`. Hence, for j > i:

    target_j - target_i  >=  (j - i) * spacing - delta_i - (age_j - age_i)
                         >=  (j - i) * spacing - DELTA_MAX - 40          (ages span 5..45 s)
                         >=  50 - 8 - 40 = 2 s                            (spacing 50 s, DELTA_MAX 8 s, j = i + 1)

A difference of at least 2 s gives `floor(target_j) >= floor(target_i) + 2`, so the two rows are never in the same or in
neighbouring seconds. For pairs further apart the bound only grows (j - i = 2 gives 52 s).

- For the registered order, `e10b_plan.py schedule` gives a guaranteed minimum of 2.0 s, attained by trials 31 and 32 (a
  5 s trial followed by a 45 s one). The worst case over any order is also 2.0 s, and the largest delta the schedule
  tolerates is 8.0 s (draft registration `plan.plan.schedule`).
- **The assumption DELTA_MAX = 8 s is generous.** In E10 the upper bound `t_insert_i - t_started - 15 i` of `delta_i` had
  median 0.586 s and maximum 1.075 s (basis `jitter.delta_upper_bound_s`). Consecutive insertions departed from the
  15 s spacing by -0.282 to +0.300 s (`jitter.consecutive_t_insert_diff_minus_spacing_s`).
- **The scorer re-checks the realised timestamps.** Any pair with equal or adjacent seconds is a registered exclusion.
- [Withheld from the artifact: a unit test that simulates the backdating op's trial timing (300 runs, random delta in [0, 8] s, random overruns); it found no collision. See README.md, "What is deliberately not here".]

The block lasts 60 s + 100 x 50 s = 5060 s, about 84 min (E10's block took 1562 s at 15 s spacing, basis
`e10_timeline.A1_BDT_s`).

## 4. Predictions and scoring

### 4.1 Own-row outcome (primary)

The verifier output for the snapshot `snap_bdt`, window [t0, snap_bdt], is read for the key `s:<forged_state_id>`:

| verdict | outcome |
|---|---|
| attributable | detected |
| benign_late | reported_late |
| unobserved_late | unknown |
| no verdict | no_evidence (unknown if its second has no root) |

**Consistency check (H1b-seg).** The own row is detected if and only if its second is in `flagged_seconds`, for every
non-excluded trial. Spacing makes this a clean check: no other trial's row can flag the second.

### 4.2 The E10b prediction rule (from the monitor's own polls)

A poll *lacks* the forged row if its view of the recorder was taken before the write began. It *holds* the row if the
view was taken after COMMIT returned. It may do either if the two overlap. The write window is
[t_insert, t_commit], the hub's times just before BEGIN IMMEDIATE and after COMMIT returned.

**Observation windows.**
- **Direct read:** [copy_at, copy_at]. The read transaction's snapshot is pinned by the first read right after `copy_at`.
- **Copy mode:** [copy_at, record ts]. The copy reads the database file, then the `-wal` (where the trial's frames are),
  then the `-shm`. The record's `ts` is taken right after the copy, so the WAL is read somewhere inside this window.
- **Band:** both windows are widened by 50 ms on each side, E10's registered `ambiguous_s`.
- **E10's window lengths during A1-BDT** (basis `polls_during_A1_BDT.*.record_ts_minus_copy_at_s`, `interval_s`):

  | | window median | window max | poll interval median |
  |---|---|---|---|
  | copy | 0.113 s | 0.755 s | 5.676 s |
  | direct | 0.00055 s | | 5.048 s |

The scorer (`e10b_score.py predict`) evaluates every split of the overlapping polls into a lacking prefix and a holding
rest. It does so exactly as the verifier evaluates a late row (`_verdict_for` mirrors `e7_verify.py`'s Timeline, its
ObservationBreaks and its late-row test):

| outcome | condition |
|---|---|
| no_evidence | the first poll covering the row's second (through >= second + 1) holds the row, or no poll covers it |
| detected | max copy_at over the lacking polls, minus the row's timestamp, exceeds 30 s |
| unknown | otherwise, if no valid poll holds the row, or if an observation break (an unobservable, missing or backlogged poll, a monitor restart, or more than 30 s between copies) lies between the last lacking and the first holding poll |
| reported_late | otherwise |

If the splits give more than one outcome, or the lower bound is within 1 ms of 30 s, the trial is **ambiguous**. It is
counted, left out of agreement, and its observed outcome is reported.

### 4.3 Predicted outcomes per level (from the registered 30 s late bound)

A poll that lacks the row copied before t_commit + 50 ms, so the lower bound is below age + (t_commit - t_insert) +
0.05 s. In E10, (t_commit - t_insert) had median 0.0036 s and maximum 0.505 s, and 9 trials exceeded 0.05 s (basis
`jitter.commit_s`, `commit_above_0_05_s`).

| age | prediction |
|---|---|
| 5 s | never detected: reported_late, or no_evidence when no lacking poll covered its second before the insertion |
| 15 s | never detected: reported_late |
| 30 s | never detected: reported_late. The lower bound exceeds 30 s only through a poll that copied after t_insert while lacking the row, i.e. one overlapping the write, which the rule calls ambiguous |
| 33 s | detected iff the last lacking poll copied after t_insert - 3 s. A priori about 3/T: 0.594 direct, 0.529 copy (basis `polls_during_A1_BDT.*.three_over_median_interval`). This share is not a hypothesis; the per-trial prediction is |
| 45 s | detected in every trial, unless a monitor did not observe in the 15 s before the insertion (E10's largest poll interval during A1: 10.127 s direct, 6.619 s copy, basis `interval_s.max`) |

### 4.4 Copy mode's observation instant

The primary rule only knows that a copy's view lies somewhere in [copy_at, record ts]. Where it lies matters only for
polls that overlap the write. E10's data shows what happens there (copyview, exploratory, `summary`):

- **Copy mode:** 10 copy-mode polls overlapped an E10 BDT write.
  - 9 of the 10 held the row.
  - The 5 whose window ended after t_commit all held it.
  - 4 whose window ended *before* t_commit also held it: an in-flight transaction captured, as in DEL 69.
  - The one copy whose window ended before t_insert lacked it.
- **Direct read:** one direct poll overlapped, and it held the row.

A copy therefore takes its view late in the copy (the `-wal` is read after the database file). E10b registers this as a
**secondary hypothesis H1b-late-view**: an overlapping copy holds the row iff the copy ended (record ts) after t_insert.
It is scored on every copy-mode trial and reported for the ones the primary rule calls ambiguous. The hypothesis was
derived from those 10 E10 polls, so E10 cannot test it; E10b can.

### 4.5 H10b (secondary arm, after `snap_bdt`)

E10's five steps are kept: 60 s with a CLOCK_STEP marker x3, 60 s without x1, 10 s without x1; each 60 s long, 120 s
apart, with the marker posted 150 s before the step. The op is `clock_step_all`. "Stepped rows" are the rows in the
step's key range (wm_before, wm_after] stamped more than 5 s before t_on. The 5 s band keeps out pre-step real-time rows
committed late (the hub commits once a second) and the last rows of the step, which reach the marker window's end.

| step | prediction |
|---|---|
| 60 s, marker | every stepped state row and event row is excused_clock_step; none is attributable |
| 60 s, no marker | every stepped row is attributable |
| 10 s, no marker | no attributable row in the key range, and no flagged second in [t_on - 11, t_off + 1] |

**Manipulation check.** State rows of the key range stamped more than 2 s before t_on. If there are none, the step is
not evaluable.

### 4.6 Other outcomes

**Secondary.**
- H1b-lb: the predicted lower bound equals `committed_after_lower_bound_s` within 10 microseconds.
- E10's frozen rule and E10's frozen `row_outcome` on the same trials, for comparison.
- Attack success by the display rule.
- Floor: flagged seconds or attributable rows in [t0, final] that no BDT trial's own row and no clock step's key range
  explains (predicted 0).

**Exploratory.**
- Overlapping polls and whether they held the row (their watermark).
- The realised minimum separation.

### 4.7 Exclusions, stopping rules, analysis

These are as in the registration, in E10's style.

**Exclusions.**
- err trials are listed and not scored.
- Pairs of trials with equal or adjacent seconds are both excluded.
- Ambiguous trials are counted, not scored.
- A monitor whose verification failed is not evaluable.
- A block with a host-log wall-clock gap above 90 s, an uncaused hub start or a monitor restart is scored and reported
  separately, not pooled. The scorer computes this as `block_conditions`.
- Smoke runs are not results.

**Stopping rules.**
- A preflight failure stops the run before any trial.
- There is no interim look at any verdict.
- An infrastructure failure leaves the run incomplete. At most one re-run is allowed, under a new tag and after a
  registered amendment, and it is never pooled with the incomplete run.
- A CS2 failure leaves H1b untouched and makes H10b not evaluable.

**Analysis.**
- The monitors are scored separately, with no pooling.
- H1b is met for a monitor only if every non-excluded, non-ambiguous trial agrees.
- H1b-seg is met only if every non-excluded trial is consistent.
- Detection per level is reported with exact 95% Clopper-Pearson intervals.
- Any deviation from the registration is written as an amendment before it is used.

## 5. Dry run of the E10b scorer on E10's saved BDT data (EXPLORATORY)

This applies `score_bdt` and `summarise_bdt` to E10's 100 BDT trials, E10's chains up to `snap_del`, and E10's own `del`
verifications (basis `dry_run_exploratory`). The realised-collision rule excluded 27 trials. On the remaining 73:

**Direct read.**
- 0 disagreements and 0 ambiguous trials.
- Segment check consistent in every trial; lower bounds equal in every trial.
- Per level (`summary.per_level`):

  | level | observed |
  |---|---|
  | 5 s | 20 reported_late |
  | 15 s | 12 reported_late |
  | 30 s | 10 reported_late |
  | 33 s | 13 detected, 7 reported_late, all as predicted |
  | 45 s | 11 detected |

**Copy mode.**
- 0 disagreements and 7 ambiguous trials: 10, 18, 26, 29, 34, 46, 79. Six are at 33 s and one is at 5 s.
- Segment check consistent and lower bounds equal in every trial.
- At 33 s: 7 detected and 13 reported_late observed; predicted 6 detected, 8 reported_late, 6 ambiguous.
- E10's frozen rule agreed with the own-row outcome in 15 of those 20 trials.

**Reading.** The verifier's own-row verdicts matched the rule wherever the rule could decide. The E10 deviations were
plan collisions and scoring, as the notes found. **This is not a result:** E10 was registered with another scorer. The
dry run used `e10b_score.py` at sha256 915e611038dc (basis `code`). The registered scorer only adds
`predict_late_view`, `score_late_view` and one section of `main()`; the diff is additive.

## 6. H10 fix: included as a secondary arm

**Mechanism.** Home Assistant stamps events with `time.time()` (`core.py`, `Event`). It stamps an entity's state with
`homeassistant/helpers/entity.py`'s module-level alias `timer = time.time`, bound at import:
`_async_write_ha_state` passes `time_now = timer()` to `async_set_internal`. E10's step replaced only `time.time`, so it
moved event rows and left state rows at the real time. H10, scored on state rows, could not hold.

**Fix.** [Withheld from the artifact: how the E10b add-on is built, how it adds its op to the E10 in-hub adversary, and how the op installs and removes the stepped clock (the op steps time.time and homeassistant.helpers.entity.timer, as registered). See README.md, "What is deliberately not here".]
- `helpers/event.py`'s `time_tracker_timestamp`, the scheduler's clock, is left alone, as E10 left it.

**Tested offline**, against Home Assistant 2026.2.3, the newest release this Mac's Python 3.13 can install. These tests
use real HA objects: a `HomeAssistant` core, an `Entity`, `async_write_ha_state`, and `Event`.
- E10's patch leaves the state timestamp within 1 s of real time and moves the event by -60 s. This reproduces E10's H10
  failure.
- E10b's patch moves both by -60 s, and both clocks are restored afterwards.
- The scheduler clock is untouched.
- [Withheld from the artifact: two further offline checks of the add-on's internals (its patching condition and how its op is registered with the E10 in-hub adversary). See README.md, "What is deliberately not here".]

**The scratch hub runs 2026.7.4.** Its `helpers/entity.py` (`timer = time.time`, `time_now = timer()` passed to
`async_set_internal`), `core.py` (`time.time()` in `Event`) and `helpers/event.py` (`time_tracker_timestamp =
time.time`) were read from its PyPI wheel. The wheel was downloaded on 2026-10-24 and has sha256 4c41607a8b67.
`test_other_release_has_the_alias_the_add_on_patches` passes on that source tree.

**Smoke gate.** The smoke must show stepped state rows (the manipulation check). Otherwise A6-CS2 and H10b are removed
before registration; this is a registered alternative.

**Why include it.** The fix is small and testable offline, and it runs after `snap_bdt`, so it cannot affect H1b. It
adds about 28 min (E10's A6 block: 1679 s, basis `e10_timeline.A6_CS_s`).

## 7. Files (new; nothing frozen by E10 or in `exp/out` was modified)

| file | role |
|---|---|
| `testbed/e10b/e10b_plan.py` | plan, schedule bound, realised-separation check (imports E10's levels, n and steps) |
| `testbed/e10b/run_e10b.sh` | the runner (E10's stack, monitors, snapshots, harness command channel; blocks A1_BDT, SNAP_BDT, A6_CS2, SNAP_CS_END) |
| `testbed/e10b/e10b_score.py` | the scorer (imports E10's `verify_job`, `sets`, `row_outcome`, `predicted_insertion` unchanged) |
| `testbed/e10b/e10b_prereg.py` | draft / `--final` / `--check`; hashes 44 files the run executes or scores with |
| `testbed/e10b/homeprov_e10b/` | the H10b add-on (`__init__.py`, `manifest.json`) |
| `testbed/e10b/test_e10b.py` | offline unit tests |
| `exp/sp2027/r16_e10_e10b_basis.py`, `r16_e10_copyview.py` | E10 saved-data basis (outputs above) |

**Lessons of the E10 and E11 smokes, encoded in the runner.**
- **No editing a running script:** the whole script is one function, read before it runs. A test checks that its first
  and last lines are `main() {` and `main "$@"; exit $?`.
- **No stdin prompts:** `exec </dev/null` for every command (the macOS `patch` prompt).
- **Interpreter guard:** `e10ops.py pyguard`, refusing anything but the pinned python.
- **One JSON object per event line:** the `ev` guard is byte-identical to E10's. A test runs it on a malformed payload.
- **bash 3.2 nested-brace quoting:** harness commands are built with single-quoted Python (`bcmd`). A test scans every
  command substitution for a brace list inside a double-quoted string, and it catches the e10_smoke1 shape.
- **No overwriting:** the runner refuses an existing run directory or any output starting with the tag. Output writes
  are guarded, and the scorer and the registration open files with mode "x".
- **Tags:** only `e10b_main` (real run) or `e10b_smokeN` (smoke) are accepted. The tag must match the smoke flag, and no
  file in `exp/out` may already start with it.
- **Busy guard:** it refuses while another HOMEPROV runner, another `run_e10b.sh`, or `HPR_E10B_BUSY_PATTERN` is running.
- **Run start and Docker state:**
  - optional `HPR_E10B_NOT_BEFORE`;
  - start only between 04:50 and 23:30 UTC (00:50-19:30 EDT), so the scratch hub's own 04:12 purge never falls inside;
  - it refuses if `e10s-`, `e10u-` or `e10bs-` containers exist.

## 8. Smoke and real run: exact commands and Mac time

**Compressed smoke plan** (`e10b_plan.py plan --smoke`):
- 2 trials per level (10 trials, 50 s apart).
- 2 clock steps (60 s with a marker, 60 s without).
- Same blocks and snapshots as the real run.
- Outputs go under the SSD's `e10b/smoke_out`. A smoke is not a result.

```
cd <artifact-root>
mkdir -p /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b
# smoke (after the other project's run has ended)
HPR_E10B_SMOKE=1 nohup testbed/e10b/run_e10b.sh e10b_smoke1 \
  > /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_smoke1.out 2>&1 &
# smoke gate: completes; no REFUSING / TIMEOUT / malformed line; trials without err; realised separation >= 2 s;
# e10b_ready lists clock_step_all; stepped state rows > 0 in both steps
grep -E "FAIL|REFUSING|TIMEOUT" /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_smoke1/auth_meta.log
<home>/miniconda3/bin/python3 -c 'import json; d=json.load(open("/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/smoke_out/e10b_smoke1_score.json")); a=d["arms"]; print(a["H1b_BDT"]["realised_separation"], a["H1b_BDT"]["summary"]["hypotheses"], [(s["step_s"], s["marker"], s.get("manipulation_stepped_state_rows")) for s in a["H10b_CS2"]], a["block_conditions"])'
# registration (after the smoke and the PI's go; then stamp)
<home>/miniconda3/bin/python3 testbed/e10b/e10b_prereg.py --final
ots stamp exp/out/e10b_preregistration.json
<home>/miniconda3/bin/python3 testbed/e10b/e10b_prereg.py --check exp/out/e10b_preregistration.json
# real run
nohup testbed/e10b/run_e10b.sh e10b_main > /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_main.out 2>&1 &
# (re-score by hand only if the runner's scoring step failed)
taskpolicy -b <home>/miniconda3/bin/python3 testbed/e10b/e10b_score.py \
  --run-dir /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_main --tag e10b_main
```

**Mac time.** E10's components come from basis `e10_timeline` and `verify_wall_s`; E10's verifications ran two at a
time. The E10b blocks are plan arithmetic.

| phase | smoke | real run | source |
|---|---|---|---|
| preflight (tests, two image builds, checks) | 5-10 min | 5-10 min | not in E10's saved data (estimate) |
| stack up to the start snapshot (incl. full-history seals) | about 7 min | about 7 min | E10 `setup_s` 429 s (seals 156 s, 166 s) |
| A1_BDT | 60 s + 10 x 50 s, about 9.5 min | 60 s + 100 x 50 s, about 84 min | plan |
| A6_CS2 | 2 steps, about 11 min | 5 steps, about 28 min | E10 `A6_CS_s` 1679 s for 5 steps |
| snapshots, freeze (90 s settle, final snapshot, collection) | about 5 min | about 5 min | E10 `freeze_s` 56 s plus the waits in the script |
| scoring: bdt, cs2, floor x 2 monitors | about 5 min | about 5-6 min | E10 del 76.0 s / 75.7 s, cs 76.0 s / 76.0 s, a_end 102.6 s per verification |
| **total** | **about 45-50 min** | **about 2 h 15 min - 2 h 25 min** | |

## 9. Known limits (stated in the registration)

- **One scratch stack, one clock.** One scratch stack on one Mac, with virtual devices. The lab configuration is cloned
  at run time and may differ from E10's clone. The hub and the monitors share Docker's VM clock.
- **Copy-mode resolution.** Copy mode's view is resolved only to the copy's duration. In E10's dry run, 6 of the 20
  copy-mode 33 s trials were ambiguous, so copy mode will have fewer decidable trials at 33 s. H1b-late-view addresses
  this as a secondary hypothesis.
- **The delta assumption.** The schedule assumes delta <= 8 s. The realised check catches a violation; it cannot prevent
  one.
- **The 33 s share.** The 33 s detection share depends on this run's poll timing.
- **Emulated clock step.** The clock step is emulated in the hub's process. Integrations that bind `time.time`
  themselves would keep real timestamps; none of the lab's core integrations do (checked in 2026.2.3 and in 2026.7.4's
  wheel: mqtt, template, automation and recorder have no such binding, apart from `recorder/statistics.py` and
  `recorder/migration.py`, which do not stamp state or event rows).
- **Version gap.** The add-on is tested offline on 2026.2.3; 2026.7.4 is covered by reading its source and by the smoke.
- **Another project's load.** E10b follows another project's long run. Contention would change poll intervals, which
  the rule reads from the chain.

## 10. Open questions for the PI

1. **H1b-late-view.** Keep this secondary hypothesis? It was derived post hoc from E10's 10 overlapping copy polls, and
   E10b gives it a fresh test. Or keep only the primary rule.
2. **Copy-mode ambiguity at 33 s.** About 6 of 20 trials were ambiguous in E10. Accept fewer decidable copy-mode trials
   at 33 s, or add trials at 33 s? Adding them would change "same trial count as E10" and the run length (each trial
   adds 50 s).
3. **H10b.** Include it as the secondary arm (+28 min, smoke-gated) or drop it?
4. **The other project's run.** When does it end (for `HPR_E10B_NOT_BEFORE`), and what process pattern should the busy
   guard watch (`HPR_E10B_BUSY_PATTERN`)? Preferred start time: allowed 00:50-19:30 EDT.
5. **Seed.** A new seed, 20261024, means a different order from E10. Or reuse E10's order?
6. **Floor verification.** Keep the floor verification (about 2 min of scoring) as a secondary outcome?

## PI decisions (2026-10-24 ~19:00Z, verbatim option labels)
- H10b clock-step arm: "Include it (Recommended)" (gated by the smoke: dropped before registration if no state rows move).
- H1b-late-view secondary hypothesis: "Keep, labelled as derived (Recommended)" (formed from E10's polls; tested on new data).
- Start: "Monday 10-26, 9 AM EDT (Recommended)": smoke from 13:00Z, then --final and OpenTimestamps, then the real run.
- Lead's defaults on the remaining questions: new seed 20261024 (independent order); n = 20 per level as in E10 (ambiguous
  copy-mode trials at 33 s are reported, not replaced); floor verification kept as a secondary outcome; busy guard
  watches another project's run (its launcher and its model server).
- 2026-10-24 ~19:45Z (lead): the other project's run now ends about 10-27 morning EDT and pauses for E10b's window, so
  HOMEPROV's lab containers stay STOPPED through E10b (E10b builds its own stack from images and only records the count
  of running hpr-* containers). Added to the registration's known limits: background load differs from E10's (lab
  containers running in E10, stopped in E10b). Restart them after the other project's run ends.
- 2026-10-26 ~03:00Z (PI, verbatim option label): "Full E10b tonight (Recommended)", in answer to "Run E10b tonight
  instead of 9 AM Monday?". The option read: smoke at 12:50 AM EDT (04:50Z, the runner's earliest start); the lead
  reviews it against section 8's smoke gate and, only if it is clean, registers (--final), stamps (OpenTimestamps) and
  starts the real run (about 1:50-4:10 AM EDT); at any problem the lead stops and nothing is registered. This answer is
  also the PI's go for the registration that section 8 requires. Both other projects had ended by then (by
  02:42Z), so the registration's background-load limit was corrected before
  the smoke: the clause "another project's run pauses for E10b's window" now states that the other projects' runs
  ended before E10b and nothing else is scheduled during it. The lab hub's containers stay stopped (PI "Keep stopped
  until needed"); hpr-broker and hpr-devices run, as recorded by the preflight's hpr-* count.
- 2026-10-26 04:53-04:55Z (lead, run log before registration): the smoke's first start failed with exit 126 because
  testbed/e10b/run_e10b.sh had been saved without the execute bit (mode 644; E10's runners are 755). Fixed by chmod 755
  only: content unchanged (sha256 93b035316645). Two further starts were refused by the runner's own one-instance guard,
  which matched the lead's starting shell (its command text named the runner); nothing was created by any of the three
  (outputs kept as e10b_smoke1_attempt{0,1,2}_*.out on the SSD). The smoke started through a wrapper whose command line
  does not name the runner (scratchpad start_e10b_smoke1.sh, exec of the documented command) at 04:54:46Z. The real run
  must likewise be started from a shell whose command text does not contain the runner's name.
