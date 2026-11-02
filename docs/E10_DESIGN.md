# E10 design (round 14): adaptive boundary arms, verifier gaps D1-D3, routine operations, SQLite hardening

Status: DESIGN, 2026-10-12. Nothing of E10 has run. It runs after E9 ends (2026-10-19 16:01Z); until then no Docker
is used for E10. The PI approved it on 2026-10-12 with the option label "Run E10 after E9 (Recommended)".

**Review r5 addendum (2026-10-16):** five arms were added after review r5 (PI: "Add all (Recommended)"). They are S
(a 90-trial sham), R (hub restarts timed into a monitor poll), C (a Domoticz switch-type change), D (pairwise closure
mutation with branch coverage) and E (cost under a Raspberry Pi 4-class cap). Their design, predictions, run times and
open questions are in `E10_ADDENDUM_R5.md`, and their registration entries are in `E10_PREREG_DRAFT.json` (H17-H21).
The sections below are unchanged except that the main-session order now includes `S_SHAM` and `R_RESTART`.

Scope, from TRIAGE_R4.md and the lead's updates:
- Y11: adaptive attacks on the stated boundaries.
- Y12: an upgrade across a recorder schema change, an entity-id rename and a device removal, with the monitor live.
- Y7: the SQLite untrusted-file hardening (r4_sources.md section 9) as a patch with tests, applied after E9.
- FORMAL_DRAFT.md section 6: verifier patches for D1-D5; live arms for D1 and D3, and an offline collusion check for
  D2 on E10's own chains.
- R14C_ANALYSIS_NOTES.md items 4 and 5: capture each trial's own row by context or watermark, score attack success by
  the frontend display rule, and make sure the logbook lists each backdated insertion.

Every number below is either read from a saved result file (path given), from Home Assistant's source at a release
tag (URL given), or a parameter fixed here. Nothing here is a result.

Files (all new, except the two edits listed in section 11):

| File | Role |
|---|---|
| `monitor/hardening_e10.patch` | SQLite hardening of `monitor/monitor.py` and the verifier's own reads in `exp/stages/e7_verify.py` (sha256 `ff37854a…`) |
| `exp/stages/verifier_e10.patch` | D1-D5 in `exp/stages/e7_verify.py`, and one updated expectation in `monitor/test_e9.py`; applies after the first patch (sha256 `df90b1f9…`) |
| `testbed/e10/test_e10_patches.py` | 28 tests of both patches; they build the patched tree in a temporary copy until the patches are applied |
| `exp/stages/e10_outcome.py` | the corrected per-second outcome rule (D2), replacing `e9_dishonest_anchor.py outcome()` for E10 (that file stays frozen) |
| `testbed/real/ha-config/custom_components/homeprov_e10/` | the in-hub adversary and operator actions (never released; git-ignored; FORBIDDEN in the artifact build) |
| `testbed/e10/run_e10.sh` | the harness (two phases, scratch stacks, refusals, preflight, scoring) |
| `testbed/e10/e10_stack.sh` | the scratch stacks: lab copy, fresh install, upgrade, teardown |
| `testbed/e10/fresh_configuration.yaml` | the fresh install's YAML-only configuration (upgrade phase) |
| `testbed/e10/e10ops.py` | the plan (seeded), CLOCK_STEP markers, name-map predictions, interpreter guard; everything else is delegated to `testbed/e9/e9ops.py` by import |
| `exp/stages/e10_score.py` | the scorer |
| `exp/stages/e10_collusion.py` | offline D2 and D1 (host variant) on E10's chains |
| `exp/stages/e10_migration_offline.py` | offline schema-migration shapes on a copy of E10's final recorder (O-MIG) |
| `testbed/e10/reverify_patched.py` | E7, E8 and E9 re-verified with the patched code (section 6) |
| `testbed/e10/e10_prereg.py` | the pre-registration generator (`--out` draft, `--final`, `--check`) |
| `drafts/round13/E10_PREREG_DRAFT.json` | the generated draft |

No E9-frozen file is modified before 2026-10-19 16:01Z. All 36 hashes in `exp/out/e9_preregistration.json` still
match, except `testbed/e9/e9ops.py`, which amendment 1 changed on 10-10 and which matches the hash
`e9_preregistration_amendment1.json` registers (checked 2026-10-12).

## 1. Questions and hypotheses

The hypotheses are stated in full, with their predictions, in `E10_PREREG_DRAFT.json` (`hypotheses`, H1-H16). In
short:
- Where exactly does each stated boundary lie on the deployed configuration?
  - the late-commit window (H1, H2);
  - the observation window for deletions (H3, H4);
  - the purge tolerance (H6);
  - sustained unobservability (H7).
- Does each verifier gap of the formal draft show up live (D1, D3) and in E10's own signed chains (D2), and do the
  patches close it (H8-H10)?
- What does each routine operation do to the verdicts (H11-H14)?
- Does hardening change no honest verdict, in E10 and in the saved E7-E9 results (H15)?

Some arms escape by design (backdating within the window, deletion before any poll, purge-shaped deletion in the
tolerance band, a write-and-delete inside a blind window). They measure the boundary the paper states; they are not
failures.

## 2. Hub stacks, monitors, schedule

**No hpr-\* container is touched.** E10 uses two scratch stacks. Each is a compose-free set of containers with the
prefix `e10s-` (main) or `e10u-` (upgrade) on its own internal network, created and removed by
`testbed/e10/e10_stack.sh`.

- **Main stack, e10s.** A copy of the lab stack:
  - containers: broker, the device simulator `hpr-devices:1`, and `homeassistant/home-assistant:2026.7.4`;
  - configuration: cloned read-only from the lab volume `homeprov-real_hpr-config` after E9 ended (fallback
    `e6-config`);
  - recorder: seeded with E9's final snapshot, `HOMEPROV-P13-exp/e9/e9_main2/snapshots/final.db`, a consistent
    online-backup copy whose sha256 is recorded in the run's `stack.json`;
  - two automations on scratch-only MQTT topics, which trigger Home Assistant's own purge and repack.
- **Upgrade stack, e10u.** A fresh `homeassistant/home-assistant:2025.11.1` with the YAML-only
  `fresh_configuration.yaml`:
  - `input_boolean`s, a counter, and a template temperature sensor with `state_class: measurement`, so long-term
    statistics, and hence `statistics_meta`, exist;
  - `time_pattern` automations that write state and event rows every few seconds.
  - It is upgraded to 2026.7.4 with the monitors live (section 3).

**Monitors, both stacks.** Two hardened monitors per stack, configured as in E9:
- stable columns, coverage, keylog, per-row binding, escrow, Ed25519 record signatures, name-map digest, full-history
  initial seal, keylog rewind, period 5 s;
- **M-direct**: direct read, `HOMEPROV_QUICK_CHECK_EVERY=720`;
- **M-copy**: copy mode, `HOMEPROV_QUICK_CHECK_EVERY=1`;
- each with a linked anchor (append key, separate operator key, tagged replies) and a head witness outside Docker's
  VM. Witness ports are 19982/19983 for e10s and 19984/19985 for e10u.

Operator markers (PURGE, RENAME, CLOCK_STEP) are signed with a fresh operator key for each stack. Only fingerprints
are recorded; the private keys stay in Docker volumes, which are removed at teardown.

**Order and windows.** Run with `run_e10.sh TAG all`:
1. the upgrade phase (about 2.2 h);
2. then the main phase (about 6.5-7 h).

The real main phase refuses to start outside 04:50-15:00 UTC. Every scratch hub keeps the lab configuration's nightly
purge (04:12 local in the container, UTC), and the start window keeps it out of the session. The harness refuses in
each of these cases:
- before 2026-10-19 16:01Z;
- while `run_e9.sh` runs or any `e9-`/`e9s-` container exists;
- when `e10s-`/`e10u-` containers exist;
- when the run directory or outputs exist;
- when the interpreter guard fails.

The guard, `e10ops.py pyguard`, requires the pinned `<home>/miniconda3/bin/python3`, Python 3.12 or later,
and a read-only open of a WAL copy. It was tested on 2026-10-12: miniconda gives ok; `/usr/bin/python3` (3.9.6) is
refused. This is E9 amendment 3's failure mode.

**Main-phase blocks** (`e10ops.py make_plan`, seed 20261020; the order inside each block is randomized from the seed
and fixed by the pre-registration):

```
A1_BDT  A2_CTX  A3_DEL  A3_DELPH  SNAP_DEL  A3_LOWKEY  SNAP_TIMING  A7_WIPE  SNAP_WIPE  A6_CS  A5_PW
A4_ULW  A4_ULSHM  A4_ULSHM_OFD  A4_ULJM  A4_INFT  A4_INFW  SNAP_A_END  B1  B2  B3  B4
```

The order is chosen so that:
- the destructive or blinding arms (A4) come after the timing arms they would disturb;
- every arm is scored against a snapshot taken before the next arm that could change its rows;
- the routine operations (B1-B4) come last because they change names (B1, B2) or the image (B4).

## 3. The schema-upgrade arm: which release and why

Home Assistant's recorder `SCHEMA_VERSION` comes from `homeassistant/components/recorder/const.py` at each release
tag. It was read on 2026-10-12 from
`https://raw.githubusercontent.com/home-assistant/core/<tag>/homeassistant/components/recorder/const.py`:

| Releases | SCHEMA_VERSION |
|---|---|
| 2025.1 - 2025.3 | 48 |
| 2025.4.0 - 2025.10.0 | 50 |
| 2025.11.0, 2025.11.1 | 51 |
| 2025.11.2, 2025.11.3 | 52 |
| 2025.12.0b0 - 2026.10.1, and dev | 53 |

The lab runs 2026.7.4, schema 53. **No release after 2026.7.4 changes the schema** (checked through 2026.10.1 and
dev). `recorder/migration.py` has the same sha256 (`b5eae370…`) at 2026.7.4 and 2026.10.1. Home Assistant does not
downgrade a recorder. So no upgrade of the lab recorder crosses a schema change, and the only way to cross one that
ends at the lab version is a fresh install at an older schema.

**Choice: 2025.11.1 (schema 51) to 2026.7.4 (schema 53), on the fresh stack e10u.**
- It crosses the two most recent migrations, 51 to 52 and 52 to 53.
- 2025.11.1 is the last release at schema 51.
- At 2026.7.4, `_SchemaVersion52Migrator` (SQLite branch) runs `ALTER TABLE statistics_meta ADD COLUMN unit_class`
  and an `UPDATE` of that table. `_SchemaVersion53Migrator` changes only MySQL character sets, so on SQLite it writes
  only the `schema_changes` row.
- `LIVE_MIGRATION_MIN_SCHEMA_VERSION = 48`, so the recorder keeps recording while it migrates, and the monitors read
  it throughout.

**Prediction:**
- no recorder violation over the whole sealed history;
- `schema_changes` goes from 51 to 51, 52, 53;
- `statistics_meta` gains `unit_class`;
- the `states` and `events` columns are unchanged;
- name map: no prediction.

The commitment covers `PRAGMA table_info` of `states` and `events` (minus `states.last_reported_ts`) and four joined
values (`states_meta.entity_id`, `state_attributes.shared_attrs`, `event_types.event_type`,
`event_data.shared_data`). So a migration that touches only `statistics_meta` cannot change a root. The live arm
tests that it does not in practice: the upgrade also rewrites rows, rebuilds indexes and restarts.

**Routine upgrade B4** on the lab copy: 2026.7.4 to 2026.10.1 (same schema), no marker. Prediction: no recorder
violation over the whole history; name map: no prediction.

**MIGRATE.** No real upgrade in range needs a MIGRATE rule. The offline check O-MIG (`e10_migration_offline.py`)
shows what one would need: it applies three shapes to a copy of E10's final recorder and verifies each against the
same chain.
- `m52`: the real 51 to 52 SQLite step.
- `index`: a new index on `states`.
- `column`: `ALTER TABLE states ADD COLUMN`.

Prediction: `m52` and `index` add no violation over the `none` baseline. `column` fails every sealed segment holding
a state row and every `states` keylog range. The unit tests `OMIG` (3, passing) confirm this on a synthetic recorder.
Whether to add a MIGRATE rule is open question Q1.

## 4. Arms, n and expected outcomes

T denotes a monitor's poll interval: the period of 5 s plus the poll's own duration. From the cost runs:
- M-direct, 0.19 GB recorder: total per-poll median 83.239 ms (`exp/out/e9_cost_scale_direct_final.json`,
  `k1_direct_qc720`), so T is about 5.1 s;
- M-copy, same size: 3,922.763 ms (`exp/out/e9_cost_scale.json`, `k1_copy_m38370b2a`), so T is about 9 s.

Both were measured under the cost runs' container limits. The lab recorder's size sets T in E10; the scorer predicts
every trial from the realized copy times, not from these averages.

The per-trial prediction rules, applied by `e10_score.py`:
- **Insertion.** A row inserted at commit time c with timestamp t is attributable iff the latest observable copy
  before c, among the polls whose watermark is below its key, lies more than 30 s after t (the verifier's
  `committed_after` rule).
- **Deletion.** A deletion is detected iff an observable copy fell in [committed, deleted).
- **Ambiguity.** Copies within 50 ms of a boundary make a trial ambiguous; ambiguous trials are counted and left out
  of agreement.

| Arm | n | What the in-hub adversary or operator does | Expected |
|---|---|---|---|
| A1-BDT | 20 per age; ages 5, 15, 30, 33, 45 s (100) | A forged `unlocked` lock row, backdated by `age`, carries the context of a genuine run of the room's motion-light automation. `old_state_id` is set to the lock's latest genuine `locked` row and [Withheld from the artifact: a further column value the integration gives the forged row so that the logbook lists it. See README.md, "What is deliberately not here".] | 5, 15, 30: never attributable (a late commit, or no evidence when no copy sealed the second first). 33: attributable iff a copy fell in the 3 s before the commit (about 3/T: 0.6 M-direct, 0.3 M-copy). 45: attributable, every trial (T < 15 s). |
| A2-CTX | 10 per delay; 5, 15, 25, 45 s (40) | Insertion only (R3 Q2): an actuation under the integration's own Context, then, at `delay`, an `automation_triggered` event of the innocent automation with that context id. Its timestamp is 50 ms before the actuation's first row, [Withheld from the artifact: which further field of the genuine run the inserted event copies. See README.md, "What is deliberately not here".]. | The displayed cause moves from the integration to the automation (the logbook keeps the first row per context in time order) at every delay. Detection as A1: 5, 15, 25 not attributable; 45 attributable. |
| A3-DEL | 10 per delay; 1, 2, 3, 4, 5, 6, 8, 10 s (80) | An actuation, captured by its context id; its `unlocked` row is deleted `delay` after it committed. | Detected iff an observable poll copied in [committed, deleted): about min(1, delay/T), so 1 from 6 s for M-direct. Every observed row's deletion is detected. Residue: the next lock row's dangling `old_state_id`. |
| A3-DEL-PH | 20 | Phase-aware deletion. The integration samples [Withheld from the artifact: the system call and the lock bytes with which the integration samples another process's locks every 2 ms. See README.md, "What is deliberately not here".], predicts M-direct's next read, actuates just after a read and deletes 0.3 s before the predicted next one. | M-direct: detected in at most 4 of 20 (predicted near 0). M-copy: as A3 at the realized visible time. Alternative, if the smoke shows the sensor cannot see the direct monitor: reported as sensor-failed, registered so before the run. |
| A3-LOWKEY | up to 10 | A row inserted with a key A3 freed, into a second sealed 90 s earlier (R1 Q1). | Detected, every trial, both monitors. |
| A7-WIPE | 10 | Every state and event row of a sealed second holding an A2 actuation is deleted. | Detected, every trial (honest chains). |
| A6-CS (D3) | 5 steps: 60 s with marker ×3, 60 s without, 10 s without | In the hub's process `time.time()` returns the wall clock minus the step for 60 s. Home Assistant stamps states and events with `time.time()`; the monitor's clock is not stepped. The operator's CLOCK_STEP marker (window [I − step, I]) is anchored 120 s before. | 60 s with marker: every row of the step `excused_clock_step`, none attributable. 60 s without: those rows attributable (false violations, as FORMAL_DRAFT D3 states). 10 s without: late commits, no violation. |
| A5-PW | 6 declared purges (keep 29 d, tolerance 60 s), 15 min apart; 3 per variant | Six variants, each run around a PURGE marker and Home Assistant's own forced purge. S is the scheduled time, c0 = S − keep, c1 = c0 + 60 s. PW-B: band rows the hub kept, deleted in purge order up to c1 − 0.5 s. PW-X: purge-shaped rows in [c1, c1 + 30 s). PW-U: one band row out of order. PW-R: a recent sealed unlock. PW-F-in: a forged row 10.5 s before c0, inserted at S + 30 s and deleted at S + 90 s. PW-F-out: the same, inserted at S + 150 s and deleted at S + 175 s. | PW-B: excused (by design). PW-X, PW-U, PW-R: detected. PW-F-in: not detected (first observed before S + 120 s, so excused as a purged row; or no evidence if no poll saw it). PW-F-out: detected (`removed_row_written_after_the_purge`). Scored before the next purge's marker. |
| A4-UL-W | 2 holds of 60 s | `BEGIN IMMEDIATE` on a second connection. | No unobservable poll on either monitor (WAL readers). The hub's commits wait; rows committed more than 30 s after their timestamp are attributable on both monitors (false violations; Q3), or lost, which is reported. |
| A4-UL-SHM (D1 live) | 5 holds of 60 s | A POSIX write lock on the `-shm` DMS byte (128), held from the hub's own process and re-asserted every 5 ms (POSIX locks are per process and never conflict with the hub's own). Inside each hold: (i) an INS-L-shaped launder of an A2 unlock sealed before the hold; (ii) an actuation whose row is deleted 8 s after commit; (iii) 2 s before the end, a forged row backdated into a second sealed 12 s before the hold began. | M-direct: every poll in the hold unobservable (`direct_open_failed`); (i) detected; (ii) not detected; (iii) E9 verifier `benign_late`, patched verifier unknown (`observation_break:unobservable_poll`). M-copy: no unobservable poll; (i), (ii) detected; (iii) attributable. Hub: rows committed throughout. Alternative, if the smoke shows M-direct still observing: reported as not blinding, D1 covered offline only (D1h), registered so before the run. |
| A4-UL-SHM-OFD | 1 hold of 60 s | Open-file-description write locks on bytes 123-127 (they also conflict with the hub's own SQLite). | Exploratory, no prediction. |
| A4-UL-JM | 1 | `PRAGMA journal_mode=DELETE` from a second connection. | Exploratory; expected refused while the hub holds the recorder. |
| A4-INF-T | 1 | An unread junk table of 3 GiB (1 GiB if the Docker VM has under 20 GiB free at preflight), random 16 MiB blobs, is added, held 300 s, dropped, then Home Assistant's own repack runs. | M-copy, 3 GiB: every poll `copy_raced` once the file passes about 3 GB, until the repack (the E8 monitor's copy at 2.94 GB: 30 of 30 `copy_raced`, `exp/out/e9_cost_scale.json`). M-copy, 1 GiB: no `copy_raced` prediction; polls of at least about 30 s (0.96 GB: 30,332 ms and 42,670 ms medians). M-direct: observable throughout (0.633 ms median snapshot phase at 2.94 GB without a quick_check); a due quick_check takes about a minute at 3 GB (58,567.883 ms median). |
| A4-INF-W | 1 | 300,000 junk state rows with current timestamps, at 500 rows/s. | No unobservable poll; per-poll time grows with the two-hour re-read window; no gap above 30 s predicted (if one occurs, late rows in it become unknown under D1). |
| B1 entity-id rename | 1 | `light.porch_light` becomes `light.porch_lamp_e10` through the entity registry, after an operator RENAME marker with the predicted part digests. | Unexcused violations on exactly the sealed seconds, minutes and hours holding a row of that entity, and every keylog range holding one, as counted from `b1_end` (rows timestamped 10 s or more before the rename): `states_meta.entity_id` is committed. Name-map transition excused. |
| B2 device removal | 1 | The kitchen motion sensor's device is removed as the frontend does it (`async_remove_config_entry_device`, then `async_update_device(remove_config_entry_id=…)`), after a RENAME marker. | No recorder violation; name-map transition excused. A re-announcement by the simulator is a second, undeclared transition (Q6). |
| B3 entity history purge | 1 | `recorder.purge_entities` on the INF-W junk entity. | Violations on every sealed segment holding a junk row; none excused (an operator action the markers do not declare). |
| B4 routine upgrade | 1 | 2026.7.4 to 2026.10.1 on e10s, no marker. | No recorder violation over the whole history; name map: no prediction (Q7). |
| U schema upgrade | 1 | e10u: 2025.11.1 for one hour, then 2026.7.4 for one hour. | No recorder violation over the whole history; `schema_changes` 51 to 51, 52, 53; `statistics_meta.unit_class` added; `states`/`events` columns unchanged. |

**Offline checks on E10's own chains** (no Docker, after the run):
- **D2** (`e10_collusion.py`), on 5 A7-WIPE seconds per monitor: the host withholds every record carrying the
  second's root or a keylog entry listing a deleted row. Predicted: honest chain, violation; withheld, E9 verifier
  `match` (the defect); withheld, patched verifier with `e10_outcome.py`, unknown.
- **D1h** (`e10_collusion.py`), on 5 A1 45 s trials per monitor: the host withholds the polls between the one that
  sealed the forged row's second and the insertion. Predicted: honest, violation; withheld, E9 verifier `match`
  (`benign_late`); patched, unknown (`poll_missing_from_the_chain`).
- **O-MIG**: as in section 3.

**Why these n.**
- Every scored arm has a deterministic per-trial prediction from the realized copy times, so the question is
  agreement, not a rate. With 20 trials at a level, 0 disagreements bound the per-trial disagreement rate at 0.168
  (one-sided 95% Clopper-Pearson, (1 − 0.05)^(1/20) = 0.8609...).
- A3 needs a curve over 8 delays (10 each).
- A2 answers R3 Q2 ("does it work at all"), so 10 per delay suffices.
- UL-SHM's 5 holds cover the 3 per-hold outcomes and the D1 row 5 times.
- The purge variants are 3 each because each needs a 15-min purge cycle.
- The total adversarial actions in the main phase are about 300 within a 7 h session; that is the time budget's
  constraint.

**Attack success (R14C item 5).** A1, A2, A3 and UL-SHM record the frontend display rule's result per trial:
- the rule is `DISPLAY_SRC`: user, then automation, then integration, then none;
- it is computed on the logbook's own rendering, for an admin and a non-admin user, before and after;
- [Withheld from the artifact: how the in-hub adversary's own copy of the display rule is checked against the released one. See README.md, "What is deliberately not here".]
- detection and success are reported side by side, never merged.

**Capture (R14C item 4).**
- Every actuation is run under a Context the integration creates.
- Its row is found by that context id and by [Withheld from the artifact: a second capture criterion and the name of the integration's internal capture routine. See README.md, "What is deliberately not here".], never as
  "the newest unlocked row".
- A trial whose row is not found within 30 s is an `err` trial, listed and not scored.

## 5. SQLite hardening (Y7; r4_sources.md section 9)

`monitor/hardening_e10.patch`, monitor side:
- On every connection (`harden()`):
  - `SQLITE_DBCONFIG_DEFENSIVE` on, `TRUSTED_SCHEMA` off, `ENABLE_VIEW` off, `ENABLE_TRIGGER` off. These use
    `Connection.setconfig`, Python 3.12 or later; the monitor image is `python:3.12-slim`. Without `setconfig` the
    flags are skipped and reported; this fallback is tested.
  - `PRAGMA trusted_schema=0`, `cell_size_check=1`, `mmap_size=0`, each read back.
- **Object-type check** (`check_objects`): in `sqlite_master`, `states` and `events` must each be exactly one
  `table`. A view, a virtual table or a duplicate fails closed with `schema_object_not_a_table`, so the poll is
  unobservable. A missing table is left to the existing probes.
- **quick_check first** (see the decision below).
- `hardening_report()` is printed once at start: the flags read back, and the SQLite and Python versions.
- `HOMEPROV_HARDEN=0` restores E9's behaviour exactly; this is tested.

Verifier side (the same patch, in `e7_verify.py`): the verifier's own reads of the recorder copy are hardened the same
way (`vconnect`). `refuse_untrusted()` runs `quick_check` first and then the object check on the private copy before
anything else. A failing copy is refused (`RecorderRefused`; CLI exit status 3, `{"refused": {reason, detail, db}}`);
it is never verified. `--no-harden` restores the E9 verifier's reads.

**The quick_check-first decision for direct mode.** SQLite's guidance (security page, Sec. 1.2, item 11) is to run
`quick_check` "as the first SQL statement after opening the database files" and to refuse a file with errors. Direct
mode opens a new read transaction every poll, and E9 runs it with `HOMEPROV_QUICK_CHECK_EVERY=720`, about once an
hour. The cost of a per-poll quick_check is read from `exp/out/e9_cost_scale_direct_final.json` (E9 monitor
8ad9e2d7, 30 polls per run, under the cost runs' container limits). `phase_direct_snapshot` median:

| Recorder | quick_check every poll | every 720th poll |
|---|---|---|
| 0.19 GB | 251.585 ms | 0.567 ms |
| 0.96 GB | 1,227.704 ms | 0.498 ms |
| 2.94 GB | 58,567.883 ms | 0.633 ms |

An earlier E9 monitor with a per-poll quick_check at 2.94 GB had 30 of 30 polls unobservable (`quick_check_failed`;
`exp/out/e9_cost_scale.json`, `k15_direct_m38370b2a`). A per-poll check at that size makes T about a minute,
above `GAP_S` = 30 s. Under D1 every late row would then be unknown, and the deletion window would grow to a
minute. So the patch keeps the 720-poll cadence and changes three things:
1. **When a check is due, `PRAGMA quick_check` is the first statement of the poll's read transaction.** It is issued
   after `BEGIN` and before any other read, so it pins the snapshot the poll then reads: the check covers exactly the
   bytes committed. `OperationalError` means `direct_open_failed`; any other `DatabaseError` means
   `quick_check_failed`. Either way the poll is unobservable.
2. **A check is also due on the first poll of every monitor process**, so a restart never reads an unchecked file.
   **After a failed check, every poll is due until one passes** (latch). Under the guidance, the file is refused
   until it checks clean.
3. **When no check is due, the object check is the first read.** Hardening then guards the parse:
   - `cell_size_check` catches malformed b-tree cells early;
   - `trusted_schema=OFF`, with no views and no triggers, means a crafted schema cannot run anything in the monitor
     (which registers no SQL functions);
   - `mmap_size=0` means a concurrent truncation cannot fault mapped pages.

Copy mode keeps a quick_check on every poll, as in E9. The copy is private, so one check per poll covers every
connection to it; the check is the first statement on the copy, followed by the object check.

Residual, stated as such: between due checks, a crafted file is parsed with only `cell_size_check`'s partial
checks. That departs from the guidance on 719 of 720 direct polls. The guidance calls these precautions "an extra
layer of defense against zero-day exploits", not a requirement (Sec. 2). Corruption that changes committed rows also
fails the roots at the verifier, which refuses unchecked copies. Lowering the cadence by recorder size is Q12.

Tests (`testbed/e10/test_e10_patches.py`, H1-H12):
- settings read back, and the fallback without `setconfig`;
- byte-identical records, state and escrow from the hardened monitor, the unhardened one and the E9 monitor, in both
  modes;
- a view in place of `states` or `events` fails closed in both modes; a virtual table fails closed;
- `quick_check` is the first statement, checked with a statement trace;
- the latch, with real index-page corruption;
- the verifier refuses a corrupt or view-bearing copy, and the CLI returns exit status 3;
- identical verdicts with and without hardening on an honest recorder.

## 6. Verifier patches D1-D5, and the re-verification of E7, E8 and E9

`exp/stages/verifier_e10.patch` (after the hardening patch). Each item cites FORMAL_DRAFT.md section 6.

- **D1** (`ObservationBreaks`). A late row (`lat > L` stays attributable) is judged on the bracket between the last
  observable poll lacking its key and the first holding it. If there is a break in that bracket, the row is
  `unobserved_late` with `why = observation_break:<reason>`, not `benign_late`. Breaks:
  - a monitor restart;
  - a poll missing from the chain (`seq_local` gap);
  - a gap above `GAP_S` between observable polls;
  - an unobservable poll;
  - a poll without its watermark;
  - a backlogged poll (`LATE_BREAK_BACKLOG = True`; see Q2).
  Tests: P2 (stall then backdate: `benign_late` before, unknown after), a gap above `GAP_S`, a backlogged poll, and P1
  (the 29.9/30.1 s boundary unchanged).
- **D2.** Every segment first covered by a poll whose roots are incomplete, or that follows a missing `seq_local`, is
  root-unknown even when it holds no row now (`why …:no_row_now`). Separately, `exp/stages/e10_outcome.py` replaces
  `outcome()`: a second is unknown when it is root-unknown, holds unobserved rows, or is first covered by an
  incomplete or gapped poll without a root. A CLI JSON without the timeline reads `match_or_unsealed`. Test: P3
  (emptied second plus a withheld record: `match` before, unknown after).
- **D3** (CLOCK_STEP rule). An operator-signed marker with window [lo, hi]:
  - hi − lo ≤ `MAX_CLOCK_STEP_S` = 300;
  - the window must end at the marker's issue time I.
  It excuses a late row with lo ≤ t < hi first held by a copy in (I, I + 600 s] (`excused_clock_step`). Malformed,
  empty, too-long and misplaced windows are rejected and listed. Tests cover the arm with and without a marker and
  the bounds.
- **D4.** A `RESTORE_DONE` without `hub_started_ts` is rejected (`no_hub_started_ts`). E9's harness always sends it
  (`e9ops.py` refuses without it). `monitor/test_e9.py`'s N1[False] expectation is updated in the patch: the DONE is
  rejected, and the second at T0+115 is flagged. This is the one change to a frozen test file; it applies after E9.
- **D5.** The segment straddling a PURGE cutoff is excused for removed rows and valid purge disconnects only. Every
  sealed row still in it must verify per row (escrowed tuple, else the per-row binding). A changed row keeps the
  violation (`a_row_in_the_straddling_segment_changed`). So does a row that cannot be checked
  (`…cannot_be_checked_without_binding_or_escrow`). With `--no-purge-disconnect` the round-12 rule is kept, for
  comparison. Test: tol 0, a changed row in the straddling segment is not excused.

All 28 tests pass on a temporary patched tree (2026-10-12; `pytest -q testbed/e10/test_e10_patches.py`, Python
3.13 at the pinned path). With both patches applied in that tree, the existing suites pass: `monitor/` 180 and
`testbed/anchord/` 81.

**Applying the patches** (after E9 ends and after `run_e9.sh` has scored E9 with the frozen code):

```
cd <artifact-root>
cp monitor/monitor.py monitor/monitor_e9.py            # sha256 8ad9e2d7... (E9 monitor, kept byte for byte)
cp exp/stages/e7_verify.py exp/stages/e7_verify_e9.py  # sha256 9c42fad9... (E9 verifier, kept byte for byte)
patch -p1 --dry-run < monitor/hardening_e10.patch  && patch -p1 < monitor/hardening_e10.patch
patch -p1 --dry-run < exp/stages/verifier_e10.patch && patch -p1 < exp/stages/verifier_e10.patch
<home>/miniconda3/bin/python3 -m pytest -q monitor testbed/anchord testbed/e10/test_e10_patches.py
```

`run_e10.sh`'s preflight refuses in these cases:
- the patches are not applied;
- `monitor_e9.py` or `e7_verify_e9.py` is missing or differs;
- the pre-registration check fails;
- any test fails;
- the in-image hashes of the built monitor and anchor differ from the tree.

**Re-verification** (`testbed/e10/reverify_patched.py`, no Docker; run before `--final`, so that a patch defect is
fixed before anything is frozen). Every pair compares the E9 code with the patched code on the same inputs, so every
difference is a patch's.
- **E7, E8.** `reproduce/verify_e7e8.py`'s eight verifier runs, with `--escrow`: once with
  `e7_verify_e9.py`/`monitor_e9.py` and once with the patched code. Each pass also reports its own MATCH against the
  published files; the E9 pass should reproduce E9_IMPL_NOTES.md section 6, 8 of 8.
- **verify_all.** `reproduce/verify_all.py` with the hardened monitor: the ten real-deployment runs.
- **E9.** Every job `e9_score.py` runs:
  - each day against its end-of-day snapshot;
  - both night snapshots over the historical window;
  - the no-rowbind and no-disconnect comparisons.
  The jobs use `e9_score.py`'s own arguments. The E9 output is taken from E9's cache (same key, E9 verifier digest)
  or recomputed with the E9 code.

For each pair, every field except `params` is compared, and the changed verdicts are listed one by one: flagged
seconds, attributable and excused violations, late-row verdicts, root-unknown segments, RESTORE_DONE acceptances,
arms, the benign floor. Each change carries its patch (D1-D5, hardening) and its evidence. Anything `unattributed` is
explained by hand before a number is used.

Expected changes (registered in H15: no flagged second changes; every other difference listed):

| Patch | Can it change an honest verdict? | Expected on E7/E8/E9 |
|---|---|---|
| Hardening | No (honest files pass quick_check and the object check; the commitments are byte-identical, H5-H7, H12) | none |
| D1 | `benign_late` becomes `unobserved_late` where a break lies inside a late row's bracket. Neither flags a second. | possible, around E9's monitor restarts, unobservable polls and slow polls; counted |
| D2 | Empty segments first covered by a gapped or incomplete poll become root-unknown. A coarse violation containing one is no longer localized, so its localized seconds leave `flagged_seconds` (fewer flagged, never more). | none expected (honest chains have no `seq_local` gaps); any is listed |
| D3 | Only with CLOCK_STEP markers; E7-E9 have none | none |
| D4 | Only for a DONE without `hub_started_ts`; E9's always have it; E7/E8 have none | none |
| D5 | A straddling segment whose sealed rows cannot all be checked per row loses its excuse | none expected (E9 runs escrow and the per-row binding with tol 60 s); any is listed |

## 7. Outcomes and scoring (`exp/stages/e10_score.py`)

**Verification jobs.** One per snapshot and monitor, cached under the run's `verify/`:
- e10s: `del`, `timing`, `wipe`, `cs`, `pw<i>` (historical and session windows), `a_end` (also with the E9 verifier,
  for UL-SHM's D1 row), `b1`-`b4` over the whole history, and the floor;
- e10u: `pre`, `post`, `final`.
Parameters as E9: `LATE_BOUND` 30 s, `GAP_S` 30 s, purge tolerance 60 s (keep 29 d on e10s, 30 d on e10u), RESTORE
tolerance 30 s, the operator public key.

**Per arm.**
- Per-trial agreement with the prediction rule, per monitor (nothing pooled across monitors).
- Detection per level, delay or variant, with exact 95% intervals.
- Display-rule success per trial, and A3's forensic residue.
- For UL-SHM, per hold:
  - unobservable polls and their reasons per monitor;
  - the hub's rows committed during the hold;
  - the three in-hold outcomes under both verifiers.

**Distinguishability (Y11).** The registered rule flags an unobservable interval as adversarial if it lasts at least
60 s and no hub start lies within 120 s of it. It is evaluated on E10 (every attack-caused interval should be flagged)
and on E9's benign week (no interval should be), as true and false positives. The rule is a heuristic for the
discussion, not part of the verifier.

**Cost.** Per-poll time, poll interval and seal delay during INF-T and INF-W.

**Routine operations.** B1 and B3 violated segments against counts predicted from the recorder before the operation
(`entity_segments`); B2, B4 and U violations (predicted 0); name-map transitions.

**Floor.** Flagged seconds of the main session not explained by any arm (predicted 0).

The offline checks (D2, D1h, O-MIG) run at the end of `run_e10.sh`; REVERIFY runs before registration (section 6).

**Exclusions** (registered):
- a trial the integration returns with `err`: listed, not scored;
- ambiguous trials (50 ms): counted, left out of agreement;
- blocks with a wall-clock gap above 90 s in the host log, an unexplained hub start, or a monitor restart: scored
  and reported separately, not pooled;
- smoke runs are not results.

## 8. Threats to validity

- **Scratch stacks, one Mac, virtual devices.** The lab installation is not touched. The lab copy has the lab's
  configuration, history and integrations, but not its physical devices' timing.
- **The clock step is emulated in the hub's process** (`time.time`), not a host clock step. It exercises the verifier
  rule exactly; it does not test other components' reactions to a host step.
- **The schema arm crosses 51 to 53 on a fresh install, not on the lab history.** No release after 2026.7.4 changes
  the schema. The real SQLite steps touch only `statistics_meta`. O-MIG covers the shapes a future migration could
  take.
- **Lock-based blinding and the phase sensor depend on SQLite's unix VFS** (3.40.1 in the monitor image) and on the
  hub and monitor sharing Docker's Linux VM. Each has a registered alternative if the smoke shows it does not work as
  designed, and exploratory arms carry no prediction.
- **Prediction rules use the monitor's own recorded copy times.** A wrong record would bias agreement toward 1. The
  copy times come from the signed chain, and the 50 ms ambiguity band absorbs clock resolution.
- **The arms share one session.** Each arm is scored against a snapshot before the next arm that could change its
  rows, and the floor reports anything unexplained.
- **Cost numbers** quoted as context come from synthetic recorders under the cost runs' limits. The scorer uses only
  realized times.
- **D1h and D2 emulate the anchor host offline** by withholding signed records. The host cannot forge a record; it
  can only withhold, delay or reorder, and withholding is the strongest of these for these cases.

## 9. Time budget

| Phase | What | Estimate |
|---|---|---|
| 0 | E9 ends (2026-10-19 16:01Z); `run_e9.sh` freezes and scores itself with the frozen code | as E9's own scoring |
| 1 | copy the E9 files, apply the patches, tests; pull 2025.11.1 and 2026.10.1, build `hpr-monitor:e10`/`hpr-anchord:e10`; REVERIFY | about 1 h + REVERIFY 1-3 h (about 70 E9 jobs and 16 E7/E8 runs at 2 jobs in parallel; not measured) |
| 2 | smokes: `SMOKE=1` upgrade (900 s + 900 s) and main (0.2 scale) on scratch prefixes, outputs under `HOMEPROV-P13-exp/e10/smoke` | about 3-3.5 h |
| 3 | `e10_prereg.py --final`, `ots stamp`; amendments only if a smoke forced a registered alternative | about 15 min |
| 4 | `run_e10.sh e10_main all` started between 04:50 and 15:00 UTC: upgrade phase about 2.2 h, then main about 6.5-7 h | about 9 h |
| 5 | scoring and offline checks (`e10_score.py`, D2, D1h, O-MIG), `ots upgrade` | about 1.5-2 h |

Machine time is about 16-19 h. Calendar time is about one day after E9's end: phases 1-3 run on the evening and night
of 10-19, phase 4 on 10-20 from about 05:00 UTC, and results come about 17:00 UTC on 10-20. This fits the 1-2 day
target. The main session's length is set by the purge arm (6 × 15 min), the INF arms (about 1 h) and B4's 30-min
observation.

## 10. Open questions (decisions that change the threat model or the guarantee; not decided here)

1. **MIGRATE.** No real migration in range needs a rule. A migration that adds a `states` or `events` column would
   fail every sealed segment (O-MIG). Should the verifier get an operator-declared MIGRATE rule that re-derives sealed
   roots under the pre-migration column set? Its exact semantics change what "committed" means.
2. **D1's backlog clause.** Read literally, "a backlogged poll between the brackets" never fires, because the
   bracketing polls are observable. The patch therefore excludes backlogged polls from the valid brackets
   (`LATE_BREAK_BACKLOG = True`), which is conservative: more rows become unknown. Keep it, or the literal reading?
3. **UL-W false violations.** An in-hub write lock delays the hub's own commits past `L`, which yields attributable
   violations on honest rows. The hub adversary can thus manufacture false positives. Does the threat model say so,
   or does (P2) need a qualifier?
4. **DMS-lock blinding of direct mode.** If A4-UL-SHM blinds M-direct while the hub keeps writing, the deployed
   direct mode can be blinded on demand by an in-hub adversary; copy mode is not. Should the recommended
   configuration change (both modes, or copy mode)? This is a design-level choice for the PI.
5. **CLOCK_STEP licence.** A declared step excuses late rows in [I − step, I) first seen within 600 s after I. During
   that window an in-hub adversary can backdate into it undetected. Accept the licence (operator-declared, bounded by
   300 s and 600 s), or tighten it?
6. **Device re-announcement.** MQTT discovery can re-create a removed device, which gives a second, undeclared
   name-map transition. Does the operator declare both, or does the rule treat re-announcement as part of the
   removal?
7. **Name map across upgrades.** B4 and U carry no marker. If an upgrade changes the name map (for example, a
   registry format change), is that an undeclared change (a violation) or should upgrades carry a declared marker?
8. **INF-T size rule.** 3 GiB or 1 GiB by free VM disk is registered. If the lead prefers one fixed size, it must be
   decided before `--final`.
9. **D5 without evidence.** A straddling segment whose rows cannot be checked per row is no longer excused. That is
   stricter for monitors without binding or escrow (the E7-era configurations). Accept, or keep the round-12 rule for
   them?
10. **N1 expectation.** `verifier_e10.patch` changes one expectation in the frozen `monitor/test_e9.py` (D4 makes the
    DONE without `hub_started_ts` invalid). Acceptable after E9 ends?
11. **Lab configuration source.** `homeprov-real_hpr-config` after E9 (preferred) or the older `e6-config`; the stack
    script falls back automatically and records which was used.
12. **quick_check cadence by size.** Keep 720 for direct mode (section 5), or scale it with recorder size (for
    example, every poll below 0.2 GB)? The paper should say which.
13. **Hourly quick_check and D1.** On a 3 GB recorder, a due quick_check makes one poll take about a minute (above
    `GAP_S`). Under D1 that is a break, so late rows bracketed by it become unknown once an hour. Treat a
    quick_check poll as a break (current patch) or exempt it?

## 11. Edits outside the new files

- `<artifact-root>-artifact-prep/round13_build.py` line 27:
  `FORBIDDEN = R12.FORBIDDEN + ("HPLock", "homeprov_e7", "homeprov_e10")`. `homeprov_e10` is never released;
  round13d and round14 inherit it through `R13.FORBIDDEN`.
- `testbed/real/.gitignore`: `ha-config/custom_components/homeprov_e10/` (confirmed with `git check-ignore`).
- Nothing was committed or pushed. The manuscript is not edited.
