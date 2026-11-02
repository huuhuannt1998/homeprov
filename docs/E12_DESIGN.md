# E12 design: 48 hours of the recommended configuration at Home Assistant's default commit interval

Status: DESIGN, 2026-10-16. Nothing has run. E12 runs after E10 and its review-r5 arms (E10_ADDENDUM_R5.md).

PI, 2026-10-16 (TDSC_PLAN.md decision log): "48-hour run at 5 s (Recommended)". This is a 48 h benign run at Home
Assistant's default commit interval, after E10.

Why it is needed:
- TRIAGE_R5 Z3: E9 ran at a non-default 1 s commit interval.
- META item 2: "the default 5 s commit interval".
- META §6: "a week-scale false-violation rate for the recommended configuration at the default commit interval".
- R2 Q3: "With the default 5 s commit_interval, what are the late-row rate, the benign floor and the observation
  window?"

## 1. What runs

The **lab installation** (`hpr-hass`, Home Assistant 2026.7.4, virtual devices, `purge_keep_days: 30`, auto purge
on), as E9 ran it. The only configuration change is that the recorder's `commit_interval: 1` line is removed, so Home
Assistant's default applies.

**Monitors** (the recommended configuration, as E9 runs it):
- M-direct: direct read, the primary.
- M-copy: copy mode, secondary.
- Both use stable columns, coverage, keylog, per-row binding, escrow, Ed25519 record signatures, the name-map digest,
  the full-history initial seal and keylog rewind, with period 5 s.
- quick_check every 720 polls (direct) and every poll (copy).
- Each has a linked anchor (separate operator key, tagged replies) and a head witness outside Docker's VM.

The code is the tree's after E10 (both E10 patches applied), frozen by E12's registration. The scorer is
`exp/stages/e9_score.py`, unchanged, with the patched verifier.

**Days:** 2. The registered START is 2026-10-21T00:00:00Z.

**Routine operations** (from `testbed/e12/e12ops.py e12_schedule`):

| When | Operation |
|---|---|
| each night, 03:40 | sleep guard |
| each night, 03:55 | snapshot |
| each night, 04:10 | operator PURGE marker for the hub's own 04:12 purge |
| each night, 04:45 | snapshot |
| each day's end + 30 s | end-of-day snapshot |
| day 1, 20:00 | one planned hub restart (`docker restart`, as E9) |
| day 2, 20:00 | one Home Assistant backup (§3) |

There are no attacks, no name-map session and no restore. The schedule generator and the event loop each refuse any
other event type (tested).

**Commit-cadence probes** run at set-up (120 s), around the backup (60 s before to 600 s after) and at each day's end
(120 s). A throwaway container on the read-only configuration mount samples the recorder's `-wal` file every 50 ms
(size and mtime). The intervals between commit bursts show the hub's commit interval from outside it.

## 2. Launcher: a copy of E9's

`testbed/e12/run_e12.sh` and `testbed/e12/e12ops.py` are new files COPIED from `testbed/e9/run_e9.sh` and
`testbed/e9/e9ops.py`. Both E9 files are frozen until 2026-10-19 16:01Z; neither was edited. The copies change only
what E12 needs.

**`e12ops.py`.**
- The schedule (`e12_schedule`, `e12_smoke_schedule`).
- Three new commands:
  - `e12-config`: removes exactly one `commit_interval` line inside the top-level `recorder:` block and appends the
    harness automation. It refuses anything else.
  - `commit-cadence`.
  - `default-commit-interval`.
- Every other function of `e9ops.py` is unchanged; a test compares the ASTs function by function.

**`run_e12.sh`.**

| Area | Change |
|---|---|
| Header | rewritten for E12 |
| Defaults | prefix `e12`, images `:e12`, START 2026-10-21T00:00Z, 2 days, witness ports 19986/19987, the pinned Python with E10's `pyguard` |
| Helper | `e12ops.py` in place of `e9ops.py` |
| Preflight | requires no attack integration. Refuses while E9 or E10 runs or their containers exist. Reads the recorder's `DEFAULT_COMMIT_INTERVAL` from the hub's installed source and refuses unless it is 5. Requires the backup integration's manager-state sensor in the entity registry, and a broker that accepts a publish. Runs `test_e12.py` and the registration check. |
| Set-up | the E12 configuration and one hub restart, instead of `person:` and the E6 person set-up |
| Backup event | Home Assistant's own, instead of E9's outside snapshot held for a restore |
| Refusals | of attack, name-map and restore events |
| Probes | the cadence probes |
| Summary | `exp/stages/e12_summary.py` after `e9_score.py` |

Environment overrides keep E9's names (`HPR_E9_*`), so the diff stays small. Teardown restores `configuration.yaml`
byte for byte, restarts the hub, and hashes and removes the backup archive E12 caused.

Smoke: `testbed/e9/smoke_stack.sh up` (used unchanged), then `HPR_E9_SCRATCH=1 ... run_e12.sh e12s_smoke` with
`HPR_E9_PREFIX=e12s` (header). It compresses two days into 2 × 18 min, with a forced purge behind a marker, the
restart and the backup.

## 3. The backup and its prediction

The configuration gains:

```yaml
automation e12:
  - id: e12_backup_harness
    alias: "E12 backup (harness)"
    triggers:
      - trigger: mqtt
        topic: "hpr/e12/ops/backup"
    actions:
      - action: backup.create
```

At day 2, 20:00 the harness publishes to that topic. It then waits up to 30 min for a new archive in
`/config/backups`, whose size must be stable for 10 s.

**From memory, unverified this session:** Home Assistant's backup holds the recorder's database while it archives the
configuration, so the recorder queues events and commits them afterwards with their original timestamps. This must be
confirmed against the 2026.7.4 source and in the smoke (open question 2).

The pause is **measured, not predicted**: it is the largest interval between commit bursts in the backup probe. The
prediction is conditional, per the verifier rule (H6):
- if pause + 5 s < 25 s: no row in the backup window is attributable; late rows are `benign_late` (or
  `unobserved_late` under D1);
- if pause > 35 s: rows written early in the pause are attributable. These are false violations, because no marker
  declares a backup;
- in between: either.

`e12_summary.py rule_consistency` checks that the verdicts agree with the rule.

## 4. Hypotheses and outcomes (E12_PREREG_DRAFT.json)

| Id | Hypothesis | Label |
|---|---|---|
| H1 floor | no unexcused violation (second, minute, hour, keylog) on either monitor over both days; every segment is untouched | confirmatory |
| H2 cadence | median commit-burst interval between 4.0 and 6.5 s at set-up and at each day's end (manipulation check; E9's 1 s setting would give about 1 s) | confirmatory |
| H3 late rows | outside the backup window none attributable; delays and counts reported and compared with E9 | exploratory |
| H4 purges | no unexcused new violation per night; disconnects excused | confirmatory |
| H5 restart | 0 attributable rows and 0 flagged seconds in [restart − 30 s, + 120 s] | confirmatory |
| H6 backup | conditional on the measured pause (§3) | conditional |
| H7 cost | per poll, bytes, quick_check; compared with E9 | exploratory |
| H8 rule | no unobservable interval flagged (≥ 60 s and no hub start within 120 s) | confirmatory |

**Rates with block intervals (META item 3; R3 W2).** `e12_summary.py` reports, per day and per run and per monitor:
- the unexcused-violation counts;
- k of n **minute** blocks: a minute fails if it holds a flagged second, an unexcused minute violation or a keylog
  violation's second;
- k of n **poll** blocks: a poll fails if it is the first observable poll copying after a failed second ended;
- exact 95% intervals, with the upper end converted to failures per day.

With no failure over 2,880 minutes the bound is 1.84 per day (computed with `rig.stats`). Blocks are not independent;
the interval is the reporting unit asked for, not a model. M-direct is primary, and nothing is pooled across monitors.

**Secondary outcomes:**
- late-row delays (count, max, over 25 s);
- the backup window (row verdicts, flagged seconds, unobservable polls, pause, rule consistency);
- the planned restart's window;
- every `e9_score.py` section (days, nights, cost and io, quick_check, witness, refusals, markers, host).

## 5. Threats and limits (stated in the registration)

- **48 h, not a week.** Alone, 0 failures bound the rate at about 1.8 per day. A week-scale statement at the default
  interval needs E9 (1 s) and E12 together, and the paper must say so (open question 1).
- **One lab installation.** Virtual devices and the lab's write rate.
- **One backup.** Its pause depends on the configuration directory's size at that moment.
- **The configuration is changed.** The line is removed and the automation added, with one extra restart at set-up
  before START. Both are restored afterwards.
- **The default commit interval is read from the hub's own installed source at preflight.** It was not read from
  upstream in this session. If Home Assistant sets the default elsewhere than a `DEFAULT_COMMIT_INTERVAL =` line, the
  preflight refuses and the lead must confirm it.

## 6. Machine time (estimate)

| Step | Time |
|---|---|
| Set-up | 1-1.5 h. `MIN_SETUP_S` = 3,600 requires START at least 1 h after launch; the configuration restart; two sequential full-history seals of a recorder that grew during E9 |
| The run | 48 h |
| Freeze | about 2 min |
| Scoring | `e9_score.py`: 2 days × 2 monitors × 2 jobs + 2 nights × 2 monitors × 3 jobs = 20 verifications at 2 in parallel, 0.5-1 h, plus the summary |
| **Total** | **about 50.5 h** |

Sequence: launched about 22:00-23:00 on 10-20, START 10-21 00:00, END 10-23 00:01, scored by about 01:30 on 10-23.

## 7. Files

New:
- `testbed/e12/run_e12.sh` and `testbed/e12/e12ops.py` (copies, §2);
- `testbed/e12/e12_prereg.py` (draft, `--final`, `--check`);
- `exp/stages/e12_summary.py`;
- `testbed/e12/test_e12.py` (15 static tests);
- `drafts/round13/E12_PREREG_DRAFT.json`.

Nothing is committed or pushed.

## 8. Open questions (for the lead)

1. **48 h vs the AE's "week-scale".** The AE's ACCEPT condition asks for a week-scale rate at the default interval.
   E12's 48 h (PI's choice) plus E9's week at 1 s is not literally that. Accept, and say so in the paper? Or extend E12
   to 7 days (about 5 more calendar days)?
2. **Which backup.** Home Assistant's own (`backup.create`, chosen: a routine household operation that interacts with
   the recorder) or E9's outside snapshot (no interaction)? The recorder's lock behaviour during a backup is from
   memory and must be confirmed in the 2026.7.4 source before `--final`. If the pause exceeds about 30 s, should a
   BACKUP marker be designed (as MIGRATE was considered), or is this stated as a limit?
3. **START.** 00:00Z on 10-21 is tight after E10 and its arms on 10-20. 12:00Z gives slack for 12 h more calendar time.
4. **Configuration after E10.** If E10's DMS-lock result changes the recommended configuration (E10_DECISIONS #4:
   direct read with a copy-mode fallback), does E12 wait for that implementation, or run the current code and report?
5. **The lab hub, not a scratch copy.** E12 changes the lab's configuration for two days, restored afterwards. A scratch
   copy, like E10's e10s, would leave the lab untouched but is not "the real platform" the reviewers asked about. The
   lab was chosen.
