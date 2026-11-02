# E7 code review: coverage monitor, E7 verifier, hardened anchor (2026-10-08)

Scope: `git diff monitor/monitor.py`, `exp/stages/e7_verify.py`, `monitor/test_coverage.py`, `testbed/anchord/anchord.py`
compared with `anchord_r12.py`, read against E7_DESIGN.md, E7_IMPL_NOTES.md and E7_ANCHOR_NOTES.md. No repository file
was modified and no container was touched. Every finding marked "reproduced" has a throwaway test in
`<scratch>/e7review/`
(the file list and commands are under "Reproduction" at the end).

## Verdict: REQUEST CHANGES

Edits, deletions and low-key insertions in a sealed second are handled soundly: step 1 recomputes over keys <= wm, so
any change in the set of rows that were present at sealing, or in their content, changes the root. The stall-proof
re-send, the record split and the escrow work as described, and `HOMEPROV_COVERAGE=0` is byte-identical to the pre-E7
monitor (I checked this directly). There is one blocker: the insertion bound for late rows can be evaded. An in-hub
adversary can make a backdated row a "benign late row" by reserving its key early. This changes what the live chain
has to contain, so it must be decided before the run. There are also four major findings and ten minor ones.

| ID | Severity | Where | One line |
|---|---|---|---|
| B1 | **Blocker** (decide before the run) | e7_verify.py:268-272, 320-336; monitor.py:614-621 | A row whose key is reserved early (future timestamp, unjoinable metadata, or a key gap) can be backdated into a sealed second and is scored benign |
| M1 | Major | e7_verify.py:396-397, 603-606, 633-643 | Attributable minute and hour violations are dropped from `flagged_seconds`, trial scores and the benign floor |
| M2 | Major | monitor.py:254-270 (and 315-333, monitor_wholerow.py:56-73) | One row with a TEXT, BLOB or infinite timestamp stops every poll and crashes the verifier |
| M3 | Major (latent) | e7_verify.py:144, 384-388 | A root that is not on the chain yet is read as "sealed empty", so benign rows are attributed |
| M4 | Major | e7_verify.py:401-438, 767; monitor.py:711-716, 759 | Intervals of unobservable polls, and seconds sealed late after any gap, are not reported |
| m1-m10 | Minor | see below | 413 arrives as a reset; torn copies; whole-row default; golden test opt-in; and others |

---

## Blocker

### B1. Reserved-key backdating: a forged row in a sealed second is scored "benign late" (reproduced, 3 variants)

**Where.** `e7_verify.py:268-272` (`committed_after`), `320-336` (`judge_late`) and `385-388` (step 2), together with
the record format (`monitor.py:614-621`, `718-743`). The verifier dates a late row by its key: "inserted after the
latest copy whose wm < key". A key is assigned when the row is first written, but the row's timestamp, content and
visibility can all change later. While a row sits in an open segment, nothing commits it.

**Failing scenarios** (`test_e7_review.py`; each one passes, so each attack succeeds). Second T0+3 is sealed empty
by the poll at T0+5. The forged unlock enters T0+3 forty seconds later, before the minute containing it is sealed:
- `test_B1_parked_key_backdating_is_benign`: at about T0+5 the hub writes a row with a far-future timestamp (FAR =
  T0+5 h). Its key is reserved and its segments stay open. At T0+40 it sets that row's timestamp to T0+3.5 and its
  content to the forged unlock.
- `test_B1_invisible_row_backdating_is_benign`: the row is written at once into T0+3, but with a `metadata_id` that
  does not exist yet. The monitor's inner join never loads it, while `wm` counts its key. At T0+40 the hub creates
  the `states_meta` row.
- `test_B1_key_gap_backdating_is_benign`: right after the seal, the hub writes one ordinary row with an explicit key
  1000 above the maximum, and the recorder continues above it. At T0+40 the forged row goes into the gap.

In all three, `flagged_seconds == []`, there are no violations at any granularity, and the row is listed as
`benign_late` with a lower bound of 1.5 s. The control `test_B1_naive_backdating_is_attributable` (the same row with a
fresh key) is flagged. The forgery is not detected:
- if the reserved row is moved in before its minute is sealed (up to about 60 s plus GRACE_S after the target
  second);
- if it is moved in later, step 1 does find an attributable minute (later also hour) violation, but M1 drops it, so
  the trial is still scored as missed at any delay (`test_M1_minute_violation_is_not_a_flagged_second`).

The adversary only needs to reserve the key within LATE_BOUND of the target second's sealing poll. It can keep a
standing reservation: one parked or invisible row per poll, with unused ones deleted while still in an open segment,
which the current design cannot detect. E7_DESIGN.md "Verifier" step 2 claims "ATTRIBUTABLE backdated insertion",
and that is false against the stated adversary, who can "write rows with any timestamp" and rewrite rows.

**Why a blocker.** Only the live monitor can produce the commitment that closes this. It cannot be added to the chain
after the run.

**Fix (prototyped in scratch, `test_keylog_proto.py`, 5 passed): a per-poll key-range commitment ("keylog").** In
every record, per table, commit the rows whose key lies in (previous high-water, wm], in key order:
- read them with the monitor's own node hash, using LEFT JOINs, so an unjoinable row is committed too;
- record them as `"keylog": {"states": {"from", "to", "n", "acc"}, "events": {...}}`;
- freeze it in `pending` with the segment roots, so it is stall-proof (a gran named "keylog", keyed by seq);
- keep the high-water at its maximum, so a falling wm never re-opens a range.

The verifier recomputes each range over the current rows. A mismatch means a row first observed at that poll was
changed, deleted, re-timed, made visible, or inserted into a key gap; it is attributable. The prototype catches all
three variants, with the mismatching range given in each case. It reports nothing on the shipped benign-late scenario
or on a 40 s replay with rows up to 0.95 s late. The cost per poll is one indexed range query over new rows only.
With it, every row is bound at its first observation, and the late-row bound becomes exact.

**If the keylog is not added**, narrow the claim before the run and declare one of the variants as a negative arm.
The narrowed claim is: a row is attributable when it is absent from the copy at sealing and its key was assigned
more than LATE_BOUND after its timestamp; rows whose keys are reserved earlier are outside the guarantee.

---

## Major

### M1. Attributable minute and hour violations never reach `flagged_seconds`, the trial scores or the benign floor (reproduced)

**Where.**
- `e7_verify.py:396-397`: `flagged_seconds` takes violations with `gran == "second"` only.
- `603-606`: `score_trials` looks up `("second", seg)` only.
- `633-643`: `benign_floor` lists second-level cases only.

**Scenario.** `test_M1_minute_violation_is_not_a_flagged_second`. A parked row is moved into T0+3 after its minute is
sealed. Step 1 reports minute T0//60 as `violation=True, attributable=True,
mechanism=row_inserted_with_low_key_or_moved_in`, yet `flagged_seconds == []` and `score_trials` gives
`e7_detected = 0`. Minute- and hour-only violations come precisely from rows that are late for their second but under
the minute's wm, which is B1's class. A benign process that produced them would also be invisible in the floor.

**Fix (verifier only; fine after the run, required before reporting).**
- Map each attributable minute or hour violation to its seconds. Mark a trial detected when any segment containing
  its second is attributable.
- Report minute and hour floor cases next to the second-level ones.
- Keep "detected at second granularity" as a separate column if the paper's unit stays the second.

### M2. One malformed timestamp stops the monitor permanently and crashes the verifier (reproduced; pre-existing, but it defeats the E7 stall claim)

**Where.** In `monitor.py:254/266`, `WHERE last_updated_ts >= ?` loads rows whose timestamp is TEXT or BLOB, because
SQLite orders TEXT and BLOB after every number. `round(ts or 0.0, 6)` at `258/270` then raises TypeError. An infinite
timestamp passes the filter and later raises in `int(ts // width)`. The same code is at `315-333` (stable) and
`monitor_wholerow.py:56-73`. `main()` (`monitor.py:952`) prints the error and sleeps. No record is appended, so there
is no heartbeat and nothing is sealed until a person intervenes.

**Scenario.** `test_M2_one_malformed_timestamp_stops_every_poll_and_the_verifier[abc|\x00|inf]`. One
`INSERT INTO states (..., last_updated_ts, ...) VALUES (..., 'abc', ...)`, written from the hub:
- every later poll raises;
- the chain stops at one record;
- `e7_verify.verify` also raises in `M.load`, so the investigator gets no verdict at all, not even the
  `monitor_silent` stall.

This is a cheaper way to stop sealing than stalling the hardened anchor, and E7's stall arm is meant to show that
the hub cannot do this.

**Fix (monitor change: before the run).**
1. Load only rows with `typeof(ts) IN ('real','integer')` and `abs(ts) < 1e12`.
2. Commit the keys of the other rows in the record (`"malformed": {"states": [...], "events": [...]}`, capped, with a
   count), so they are visible rather than silently skipped. With B1's keylog they are committed anyway.
3. Wrap the body of `tick_coverage` after validation in try/except, appending an `evidence_unobservable` record with
   reason `load_failed`, so the heartbeat continues.
4. Use the same guarded load in the verifier, and report malformed rows as anomalies.
5. NULL timestamps are already excluded by `>= ?`. That is another way to hide a row (B1 class), which the keylog also
   covers.

### M3. A root that has not reached the chain is read as "the segment was empty", which makes benign rows attributable (reproduced; latent in the planned configuration)

**Where.**
- `e7_verify.py:384-388`: if a segment's first-cover poll P is known but no root from P is in `all_roots`, every
  current row with key <= wm(P) becomes `present_when_sealed_empty`, which is attributable.
- `parse_chain` (`:144`) drops every record after `--snapshot-at`, including records that re-send roots sealed before
  it.
- The monitor sends a poll's head and its roots in separate parts or polls when a later part fails, after a 409, or
  when `HOMEPROV_MAX_PARTS` is reached.

**Scenario.** `test_M3_missing_root_is_read_as_sealed_empty_and_attributed`. 60 seconds of benign rows, with
`HOMEPROV_MAX_RECORD_BYTES=2048`. Part 1 of the poll at T0+65 is anchored; part 2 times out and is re-sent at T0+70.
- Verified on the full chain: 0 attributable rows.
- Verified with `--snapshot-at T0+67`: at least 10 benign rows are attributable. The same happens without
  `--snapshot-at` if the monitor is stopped while such roots are pending.

With the default sizes (1 MiB records, 16 MiB anchor), a split needs more than 1 MiB of items, so this is unlikely in
E7. But the inference fails toward accusation, which is the wrong default for a forensic tool.

**Fix.**
- Monitor (before the run, cheap): put per-granularity counts of the segments sealed by each poll (or a digest of
  their ids) into every head. The verifier then infers "empty at first cover" only when it holds all of P's roots;
  otherwise the segment is `root_unknown` and is not attributed.
- Verifier stopgap: collect roots from all records, ignoring `--snapshot-at`, and apply `--snapshot-at` only to the
  poll timeline. A root sealed before the snapshot is valid even if it was anchored after it.

### M4. Unobservable intervals, and seconds sealed late after any gap, are not reported (reproduced)

**Where.**
- `e7_verify.py:401-438`: stalls come only from time gaps and `seq_local` jumps between coverage records.
  Unobservable records keep the heartbeat regular, so a run of them is never a stall. It appears only as the count
  `unobservable_records` (`:767`).
- `segments_sealed_during` (`:425`) lists only frozen roots of polls inside a gap. It does not list the seconds that
  the poll ending a `monitor_silent`, `monitor_restarted` or unobservable gap sealed from the current copy, which are
  the seconds that were not protected.
- Monitor side: frozen roots are re-sent only from observable polls (`monitor.py:759`, `711-716`). The hub can
  therefore keep them off the chain by keeping copies unobservable. For example, appending one byte to the -wal gives
  `wal_partial_frame` while SQLite in the hub ignores the trailing byte.

**Scenario.** `test_M4_unobservable_interval_is_not_reported`, run with `HOMEPROV_GRACE_S=2`:
1. The unlock at T0+11.31 is observed but not yet sealed.
2. The hub puts a garbage -wal next to the recorder, and three polls are `wal_header_corrupt`.
3. The hub launders the row and removes the -wal.
4. The next poll seals T0+11 in its edited form.

Result: `flagged_seconds == []`, `stalls == []`. With GRACE_S=0, the rows exposed are only those in the current
second at the last observable poll. Rows committed during the interval are never observed, but the hub still chooses
how long the interval lasts.

**Fix.**
- Verifier (fine after the run): report each maximal run of unobservable polls as a stall of kind
  `evidence_unobservable`. For every gap of any kind, list the seconds in [through(last observable poll before the
  gap), through(first poll after it)), that is, the seconds sealed late from a copy taken after the gap.
- Monitor (optional): send frozen roots from unobservable polls in their own continuation record.

---

## Minor

**m1. A 413 can arrive as a reset, and the monitor then never halves (reproduced).** `anchord.py:252` refuses an
oversized body unread and closes the connection (`:278`). Against the real hardened daemon with `MAX_BODY=8192`,
`monitor.append()` got http 413 for bodies of 9 KB and 200 KB, and
`URLError(BrokenPipeError(32, 'Broken pipe'))` for 4 MB (`test_m_413_reaches_the_monitor_as_a_reset_for_a_large_body`,
macOS loopback). An `err` takes the `break` at `monitor.py:836`. The budget is never halved, the same oversized record
is retried every poll, and the backlog grows behind it with one alarm per poll. The in-memory test anchor
(`test_coverage.py:114`) always returns a clean 413, so the shipped test cannot catch this. This only applies when
`HOMEPROV_ANCHOR_MAX_BODY` is below the monitor's record size; it cannot happen with the defaults (16 MiB vs 1 MiB).
Fixes:
- in the run, never set the anchor limit below about 4x `HOMEPROV_MAX_RECORD_BYTES` (records overshoot the budget by
  up to about 500 bytes);
- in code, treat a reset or broken pipe on a body above half the budget as a 413;
- or have the anchor drain the body for a bounded time before replying (lingering close, RFC 7230 §6.6).

**m2. A torn copy now gives an attributable false positive instead of an ambiguous one (not reproduced; likelihood
uncertain).** `snapshot()` (`monitor.py:140-150`) copies the db, then the -wal, then the -shm. Suppose a checkpoint
writes into the db while it is being copied, and the next commit restarts the WAL before the -wal is copied. The copy
then lacks rows committed before `copy_at`, while newer keys are present, so the lost rows are under wm. Afterwards
step 1 reports `row_inserted_with_low_key_or_moved_in`, or step 2 reports `present_when_sealed_empty`; both are
attributable. The existing rule called this ambiguous. Fix: read the db change counter (header offset 24) and the WAL
salts before and after the copy, and re-copy or fail closed with `copy_raced` if they changed. Check the benign floor
of the run for this mechanism.

**m3. The whole-row baseline now runs with coverage by default.** `monitor_wholerow.py` imports `monitor`, whose
`HOMEPROV_COVERAGE` now defaults to 1. A re-run of the whole-row baseline therefore emits coverage records, unlike the
evaluated runs. Set `HOMEPROV_COVERAGE=0` for reproduction. The comment at `monitor_wholerow.py:29` ("accepts only
'closure' or 'row'") is stale.

**m4. The byte-identity baseline is the pre-E7 working copy, not git HEAD, and its test is opt-in.** The baseline file
is present at `<artifact-root>-artifact-prep/r13_tree/monitor/monitor.py` (sha256 2eb8f872...).
I ran `HOMEPROV_PRE_E7_MONITOR=<that file> pytest -k byte_identical`, and it passed. The diff also leaves the old
`tick()` body untouched. Without the variable, the test only checks a constant (`test_coverage.py:682`); point it at
that file by default. Byte identity holds against that file (which has v2 and E6), not against `c28cf41`/`hpr-monitor:1`,
whose records have no `encoding` field. Name this baseline wherever the paper or artifact says "byte for byte".

**m5. Stall reporting cost.** `during` (`e7_verify.py:425`) scans all roots for every stall. With GAP_S = 15 s and
e3_g0's sealing delay (p90 20.6 s, E7_IMPL_NOTES §8), a day can produce thousands of `monitor_silent` stalls times
about 86k roots. Index roots by sealing poll, and fix GAP_S from the observed poll-interval distribution.

**m6. Configuration is not validated.** `HOMEPROV_MAX_PARTS <= 0` means no record is ever sent (part 0 forever, the
backlog grows). Validate it at import as `HOMEPROV_COVERAGE` is. `test_coverage.py:149` clears the stale
`HOMEPROV_MAX_ITEMS` but not `HOMEPROV_MAX_RECORD_BYTES` or `HOMEPROV_MAX_PARTS`, so values exported in a developer's
shell change test results.

**m7. What "attributable backdated insertion" means.** The verdict means "absent from the copy at the seal, present
now". The hub can produce it for a genuine row by deleting it from its open second before the seal poll and
re-inserting it afterwards. The paper should say that the history was altered at this row, not that the event was
fabricated.

**m8. LATE_BOUND and Home Assistant restarts.** The evidence in `e7_late_delays_prior.json` comes from runs without
an HA restart. A restart (the recorder replaying its queue) or a recorder backlog inside the window would produce
attributable rows in the benign floor. Log HA restarts in the run and report those rows separately, or keep the
window restart-free.

**m9. Limits of `restore()`** (`e7_verify.py:512`). Rows added into seconds that were sealed empty are kept, and only
the closure columns are written back (not attributes or other columns). The restored copy is therefore not the
original database. Say so wherever the recovery result is described.

**m10. Records can exceed the budget.** The part-1 base record carries the whole `conflicted` list, and `fill()` takes
at least one item, so a record can exceed the budget regardless of halving. This is harmless with the default sizes;
it matters only together with m1.

## Nits
- `e7_verify.py` docstring, step 2: "If no segment was sealed at P, the segment held no row then". Per M3 this holds
  only when all of P's roots are known.
- `test_coverage.py` docstring "the earlier monitor misses it": it is the earlier monitor's behaviour run from the
  same file with `HOMEPROV_COVERAGE=0`, not the image `hpr-monitor:1`.

---

## What is done well
- Step 1 (keys <= the sealing wm, per table) is sound for every edit, deletion, re-keying, move or low-key insertion of
  a row that was present at sealing. The "ambiguous" class disappears, and the edit plus K inserted rows case is
  attributable, tested at K = 9 and 20. Key reuse after deleting the newest rows is handled (`under()` together with
  the max-copy bracket).
- Frozen pending roots are never recomputed. The state is saved before the append, they survive restarts and the
  re-read window, and the COVERAGE=0 contrast test shows the old monitor missing the stall laundering.
- The record split keeps order (backlog heads first, then by sealing poll) and completeness. 409s are quarantined
  under a key the anchor does not read, so one conflict cannot block the chain.
- Escrow: typed JSON (`jt`/`from_jt`) round-trips exactly. The verifier accepts an escrow line only when its
  recomputed root equals both its own stated root and the anchored root. No key or secret is written anywhere (escrow
  lines, state file and alarm lines all checked).
- Anchor hardening: one thread per connection, a deadline reader covering headers and body, the tag checked before
  parsing, and the conflict check and append in one critical section. All 50 anchor tests pass.
- LATE_BOUND and GAP_S are required parameters with no default, and they are recorded in the output.

## Answers to the five focus questions
1. **Soundness.**
   - Edits and deletions are sound.
   - Insertions into a sealed second are sound with a fresh key or a low key, but not with a reserved key (B1), and
     not when they are detected only at minute or hour level (M1).
   - Future timestamps are B1's parking variant.
   - Deleting and re-inserting is attributable with a fresh key; with a reserved key it falls under B1.
   - A restart with the state file kept is handled, and state loss is reported as a restart.
   - 409 is handled well; 413 is m1.
   - The two tables are handled correctly (separate wm and separate brackets).
   - A benign row can be made to look attributable in three ways: M3 (missing roots), m2 (torn copies), and m8 (a
     LATE_BOUND below a real delay). Under m7, a genuine row hidden at the seal is reported correctly as altered
     history.
2. **Stall-proofing.**
   - Frozen roots are never recomputed (verified).
   - The split keeps order and completeness (verified).
   - Nothing is dropped, but progress can stop in three ways: M2 (one row stops every poll), m1 (a 413 seen as a
     reset), and M4 (frozen roots withheld during unobservable polls).
3. **Backward compatibility.** COVERAGE=0 is byte-identical to the pre-E7 file (verified directly; see m4 for the
   baseline). The evaluated e_psr_clo chain gives the same violations and 90/90 through the existing-rule fallback
   (the shipped test, run). The whole-row entry point's default changed (m3).
4. **Escrow.** It is verifiable against the anchored root (shipped test, and the code read). No secret or key is
   written.
5. **Tests.** They exercise every claim they name, and a mutation probe (dropping `since` from `first_cover`) is
   caught by `test_frozen_roots_outlive_the_reread_window`. Gaps:
   - nothing covers reserved keys (B1), minute-only violations (M1), malformed rows (M2), truncated chains or pending
     roots (M3), or unobservable intervals (M4);
   - the 413 is modelled more cleanly than the real anchor delivers it (m1);
   - the golden comparison is opt-in (m4).

## Reproduction
Scratch folder: `<scratch>/e7review/`
- `test_e7_review.py`: B1 (control plus 3 variants), M1, M2 (3 values), M3, M4, m1. **11 passed**, which means every
  failure scenario reproduces. It reuses the shipped harness in `monitor/test_coverage.py` unchanged.
- `test_keylog_proto.py`: the suggested fix for B1. It catches all 3 variants and stays quiet on 2 benign late-row
  scenarios. **5 passed**.
- `test_mutants.py`: re-runs the shipped tests with one verifier rule broken (`E7_MUTANT=no_since`: 1 failure;
  `last_not_max`: none, because the two rules are equivalent when copy times are monotone, so this is not a finding).
- Command: `cd <artifact-root> && python3 -m pytest -q -p no:cacheprovider <file>`.
- Shipped suites run on 2026-10-08: `monitor/test_coverage.py` and `monitor/test_node_hash.py`, 38 passed;
  `testbed/anchord`, 50 passed (57 s); golden test with `HOMEPROV_PRE_E7_MONITOR` set, passed.

---

# Re-review of the fixes (2026-10-08, evening)

Scope: the fixes in E7_IMPL_NOTES.md §9. Files reviewed, by sha256: `monitor/monitor.py` 9b0970d7..., `exp/stages/e7_verify.py`
6764e8e4..., and `monitor/test_coverage.py` 0fc09322... (48 tests). The anchor daemon is unchanged (fa662e94...). No
repository file was modified. Scratch tests are in the same folder as before: `test_rereview.py` (18 tests, all
passing) together with the earlier files.

## Verdict: READY for the live run, with two small monitor patches recommended before it and one verifier fix required before results are reported

Every blocker and major finding of the first review is fixed, and I re-checked each one against the new code (table
below). The keylog closes B1 in all three variants. Running the shipped suites gives 60 passed (48 + 12). The golden
test now compares against the pre-E7 file by default and passes. The `no_since` mutant is now caught by 2 tests.

Trying to break the keylog produced three new major findings and three minor ones. None of them invalidates the
measurements planned for tomorrow: laundering, member swap, the insertion variants, backdating and the stall arm.
- **R1** is fixable in the verifier after the run, but must be fixed before any result is reported.
- **R2** and **R3** need a monitor change, because the monitor writes the records. Both patches are a few lines.
  Apply them before the run if the paper is to claim that the hub cannot stop sealing (R2), or that a row is
  localised to its second from its first observation (R3). Otherwise run as is and state these two limits.

## 1. The first review's scenarios against the new code

| Finding | Earlier scratch test (asserts that the attack succeeds) | Now | Positive check in `test_rereview.py` |
|---|---|---|---|
| B1 parked | `test_B1_parked_key_backdating_is_benign` | fails, so the attack is caught | `test_P1_B1_parked_is_caught`: T0+3 flagged, keylog `changed` |
| B1 invisible | `test_B1_invisible_row_backdating_is_benign` | fails, caught | `test_P1_B1_invisible_is_caught` |
| B1 key gap | `test_B1_key_gap_backdating_is_benign` | fails, caught | `test_P1_B1_key_gap_is_caught`: keylog `added` |
| M1 | `test_M1_minute_violation_is_not_a_flagged_second` | fails, caught | `test_P1_M1_minute_only_is_scored` (keylog off): localised second flagged, `e7_detected` 1 |
| M2 | `test_M2_...[abc, \x00, inf]` | fails, so polling continues | `test_P1_M2_...[abc, \x00, inf, NULL]`: no unobservable record, key in the record's `malformed`, listed by the verifier |
| M3 | `test_M3_missing_root_...` | fails, no accusation | `test_P1_M3_...`: with `tsnap`, 0 attributable rows |
| M4 | `test_M4_unobservable_interval_is_not_reported` | fails, reported | `test_P1_M4_...`: `evidence_unobservable` gap and stall, laundering of the observed row flagged |
| m1 | `test_m_413_...` (tests `append()` alone; still a reset at 4 MB) | as before | `test_P1_m1_reset_on_large_body_halves`: backlog drained when every body above 6000 B is reset |
| keylog prototype | `test_keylog_proto.py` | 5 passed | |
| mutants | `test_mutants.py` | `no_since`: 2 failures (was 1); `last_not_max`: 0 | |

The author is right about my M4 scenario. With a `-wal` present, SQLite switched the test's rollback-mode connection
to WAL, so my UPDATE went into the stray file and was lost when it was deleted. The corrected scenario reopens the
connection after removing the file.

## 2. Attempts on the keylog

**Change between the keylog read and the segment read in the same poll: not possible.** `snapshot()` copies the
recorder once into the monitor's scratch. `watermark()`, `keylog_poll()` (through `keylog_rows`) and `load()` all
open that same private copy (`monitor.py:893-905`), and the hub cannot write to it. When the copy is repeated because
of a copy race, the last copy is used for everything. When a reader connection closes, SQLite checkpoints the
copy's own WAL into the copy, which preserves its content.

**Key reuse after deleting the newest rows: caught** (`test_A4`). The high-water only rises, so a reused key falls
into an already committed range and shows as `changed`.

**Rows whose outer join changes later: caught** (`test_P1_B1_invisible_is_caught`). Every join target is a primary
key, so the LEFT JOIN yields exactly one row per key. A rename of `states_meta.entity_id` or an edit of shared
`event_data` changes the keylog, and the segments as well.

### R1 (Major). The 8-hex localisation can be steered: a birthday collision plus a decoy row hides the forged second (reproduced)

**Where.** In `e7_verify.py:411-427`, `changed` is decided by comparing 32-bit prefixes (`monitor.py:716`). When any
row of a violated range is localised (changed, added or removed), only `changed + added` become suspects.

**Scenario.** `test_A1_prefix_birthday_plus_decoy_hides_the_forged_second`. The adversary controls both forms of the
row, the parked one and the forged one, and varies the 16-byte `context_id_bin`. A birthday search over the 32-bit
prefix took 131,072 + 24,988 hashes, well under a second. The steps:
1. Park the colliding row, plus a decoy row in the same key range.
2. 40 s later, move the parked row into T0+3. Its prefix does not change, so it is not `changed`.
3. Delete the decoy, so the range is `localized` and shows `removed: [decoy]`.

Result: `suspects == []` and `flagged_seconds == []`. The keylog violation itself is still listed, so tampering is on
record, but the per-second score misses the forgery. The note "a prefix collision only loses the localisation" holds
for a single colliding row; it fails when the adversary adds a decoy.

**Fix.**
- Verifier (enough for soundness, can be done after the run): when a range fails, every current row of the range is
  a suspect. Report the prefix matches only as "likely cause". A violated range holds a handful of rows (at most
  128), so the extra flagging is small.
- Monitor (optional, cheap, before the run): use prefixes of at least 128 bits (32 hex), so the localisation itself
  can be trusted. A 64-bit prefix still falls to a 2^32 birthday search.

### R2 (Major). One TEXT value that is not valid UTF-8 stops sealing for the rest of the run and crashes the verifier (reproduced)

**Where.** Python's `sqlite3` raises `OperationalError: Could not decode to UTF-8` when it reads such a value. The
timestamp guard covers timestamps only. The keylog reads every committed column of every row in (hw, wm]
(`monitor.py:685-708`), and the high-water cannot pass a range that fails to read. The verifier reads the same
columns (`e7_verify.py:405`, and `M.load`).

**Scenario.** `test_A2_invalid_utf8_text_stops_sealing_for_good_and_crashes_the_verifier`. The hub inserts one row with
`state = CAST(x'ff41' AS TEXT)` and a timestamp two hours back, outside the re-read window. From then on every poll
is `load_failed`, so nothing is sealed and the unlock at T0+6.3 is never sealed. The verifier raises, so there is no
verdict at all.

Before the keylog, a row like this blocked polls only while it sat in the re-read window. Now it blocks them for
good. The chain shows the unobservable polls, so the stop is not silent, but the hub can stop sealing at will.

**Fix (monitor, before the run).**
- Under `COVERAGE`, set `con.text_factory = lambda b: b.decode("utf-8", "surrogateescape")` on every connection the
  monitor opens: `watermark`, `keylog_rows`, `keylog_poll`, `load`, `load_stable`.
- `tlv()` already encodes such strings with `surrogatepass`, so the encoding stays injective, and valid UTF-8 hashes
  exactly as before. Keeping the change out of COVERAGE=0 preserves the golden identity.
- Use the same `text_factory` in the verifier, and list rows that hold such text next to `malformed_rows`.

### R3 (Major). A row observed in its open second and then deleted, re-timed or made malformed is never localised to that second (reproduced)

**Where.**
- The keylog's `rows` entries hold `[offset, prefix]`, with no time, so the verifier cannot tell which second a
  changed or removed row was first observed in.
- `check_keylog` uses the current timestamp: `second` is None for a malformed row, and a removed row is never a
  suspect.
- The original second is sealed without the row, so its segment root matches.

**Scenarios.**
- `test_A3_real_row_malformed_in_its_open_second_flags_no_second`: a genuine unlock at T0+5.2 is observed at T0+5.5,
  then gets `last_updated_ts='gone'`. It is listed in `malformed_rows`, and its keylog violation shows `changed` with
  second None. `flagged_seconds == []`.
- `test_A3b_real_row_deleted_in_its_open_second_flags_no_second`: the same unlock is deleted instead. The recorder
  reuses its key for the next row, so the violation is localised to that row's second (T0+7), not to T0+5. Without
  the reuse, the row would be `removed` and nothing would be flagged.

**Answer to question (3).** A row marked bad is never silently skipped. Every row with a malformed timestamp is
committed by the keylog; it is named in the record (capped at 50 keys per table per poll, with the exact count); and
the verifier lists every such row in the final database. But it can be used to hide a real row's *second*, and so can
a plain deletion or a re-timing. Rows that are hit in the window between their first observation and the sealing of
their second (up to one second plus GRACE_S at each poll) are reported only as an unlocalised keylog violation.

**Fix.**
- Monitor (before the run): add each row's first-observed second, `int(ts)` or null when malformed, to the keylog
  `rows` entries. The verifier then flags that second for every changed or removed row.
- Verifier-only fallback: flag the seconds in [copy_at(previous poll) - LATE_BOUND, copy_at(P)] for each changed or
  removed row of a range committed by P.

### R4 (Minor). After a restart with the state file lost, a key hole goes unreported (reproduced)

**Where.** `keylog_poll` (`monitor.py:749-758`) starts a monitor with no high-water above the largest key of a sealed
row. `check_keylog` (`e7_verify.py:429-435`) exempts that start from hole detection.

**Scenario.** `test_A5_restart_with_state_loss_leaves_an_unreported_key_hole`. A row parked during the downtime gets
a key below the next sealed row. After the restart it is moved into T0+19, the last second sealed before the downtime.
Nothing is flagged, `uncommitted_key_ranges == []`, and only a `monitor_restarted` stall is shown. The hub cannot
cause a state loss, and with the state kept the keylog stays continuous (`test_A6`).

**Fix.** When an earlier epoch exists, report the keys between its last range and the next epoch's start as
uncommitted.

### R5 (Minor). Epoch inference can misassign polls

**Where.** `e7_verify.py:184-186`. The new rule is "a lower counter starts an epoch only when its time is later". It
misassigns polls in two cases:
- a record the anchor commits late from before a restart with state loss, arriving after the new epoch's first
  record;
- a backward clock step across such a restart.

Both are contrived, and neither occurs without state loss.

### R6 (Minor). A decoy edit suppresses the minute and hour localisation

**Where.** `e7_verify.py:572-575`. A flagged second anywhere in a minute suppresses the localisation of that minute's
violation. With the keylog this matters only together with R1.

## 3. What is now sound

- Edits, deletions, re-keying and low-key insertions of rows that were present at sealing are caught by step 1.
- Rows that are re-timed, made visible, or inserted into an observed key range after their first observation are
  caught by the keylog. All three B1 variants and key reuse are in this class.
- Frozen roots and keylog ranges survive appends that fail or are committed late, monitor restarts with the state
  kept, splitting, and unobservable polls.
- Missing roots and missing key ranges are reported (`root_unknown_segments`, `uncommitted_key_ranges`), never
  attributed.
- Rows with a malformed timestamp are always listed and never folded.
- `HOMEPROV_COVERAGE=0` is byte-identical to the pre-E7 file.

What remains outside the guarantee, and should be stated:
- the pre-observation window of one poll;
- backdating by less than about LATE_BOUND plus one poll period;
- write-time forgery;
- columns outside the committed set;
- R1 (until the verifier fix), R2 and R3 (until the monitor patches).

---

# Final check (2026-10-08, night): GO for the live run

**Code checked** (sha256): `monitor/monitor.py` af8fd5b7..., `exp/stages/e7_verify.py` 7fef951f..., `monitor/test_coverage.py`
4a0cf6a0... (55 tests).

**Tests.**
- Shipped suites: 67 passed (55 + 12).
- `test_rereview.py`: the five attack tests (A1 prefix birthday plus decoy, A2 invalid UTF-8, A3 malformed in the open
  second, A3b deletion in the open second, A5 key hole after a state-loss restart) now fail, which means each attack
  is caught. The 13 positive checks, A4 and A6 pass.
- `test_e7_review.py`: all 9 first-round attacks are caught. The 2 remaining tests pass as before: the fresh-key
  control and `append()`'s raw reset at 4 MB, which the loop now handles.
- `no_since` mutant: now caught by 3 tests.
- `test_keylog_proto.py` is obsolete. The shipped verifier now flags its attacks, and its wrapper does not read the
  monitor's own keylog format.

**R1 on real data** (`replay_real.py`). All 8,880 real rows of `e_d_clo` were replayed through the current monitor:
5 s polls, keys assigned by SQLite, commit lag of 0.05 to 0.95 s, and HA's in-place `last_reported_ts` rewrite.
- Benign run: 1,288 polls, 1,949 key ranges, 0 keylog violations, 0 flagged seconds, 0 attributable rows, 1,295
  benign late rows, no stalls.
- With one parked-row attack: 1 failed range of 2 rows, and 3 seconds flagged:
  - the target second;
  - one neighbour, whose row is listed as a `keylog_suspect_rows` entry and not called attributable;
  - the far-future second the parked row first sat in.

  So the conservative flagging covers the seconds the rows sit in now and the seconds they sat in when first
  observed, without a benign flood.

**Left open, none blocking.**
- R5: epoch inference, which needs a state loss.
- m3: whole-row default.
- m7: wording of "attributable".
- m8: HA restarts during the window.
- m9: limits of `restore()`.
- E7_IMPL_NOTES §10 now gives LATE_BOUND as 30 s, against benign evidence of at most about 6 s. Any paper claim
  about backdating must name the resulting window: backdating by less than about 35 s passes as benign.

---

# E8 review (2026-10-09, before the live run)

**Scope.** E8_DESIGN.md §A (A1-A4), E8_ANCHOR_NOTES.md, E7_IMPL_NOTES.md §11, and review r2 R1 W1. Files and
sha256: `monitor/monitor.py` 06cee7e4..., `exp/stages/e7_verify.py` 69d528e8..., `reproduce/verify_all.py`
674dc865..., `testbed/anchord/anchord.py` 53d1ac92..., `anchord_linked.py` 966d2b35..., `headwitness.py`
0d8a83c8..., `chainverify.py` 38cfa5e9..., `test_anchor_e8.py` 614d2e99..., `e8_witness_gap_check.py` b310e1d7...,
`exp/out/e8_witness_gap_check.json` 5f1cfe0b....

**Suites run.** `monitor/`: 79 passed. `testbed/anchord/test_anchor_e8.py`: 14 passed.

**Scratch tests.** `test_e8_review.py`, 5 tests, all passing; each one reproduces the attack it names.

## Verdict: GO for the live run. NO-GO for scoring or claiming A2 until BE8 and ME8 are fixed in the verifier

The monitor signs every record, so the run collects the evidence A2 needs. Both blocking problems are in how the
verifier reads that evidence, and both are verifier-only fixes that can be applied after the run.

## Blocker for the A2 claim (verifier fix, before scoring)

### BE8. With `--sign-pubkey`, an UNSIGNED monitor-format record is still accepted, so the anchor host can substitute any record (reproduced)

**Where.**
- `e7_verify.py:510-513` (`check_signatures`): `if st in ("ok", "unsigned"): keep.append(line)`.
- `verify_all.py:338-341` (`signed_lines`): the same rule.

**Scenario.** `test_BE8_unsigned_substitute_record_is_accepted_under_the_public_key`. The host that runs the anchor
holds the append key. For the poll that seals T0+6, it stores an unsigned record with the same fields instead of the
monitor's signed one. The substitute carries the sealed roots and keylog of the recorder *after* a laundering that
the hub performs later. The host answers the monitor with an "ok" whose reply tag is valid, since it holds the key.
After the hub launders the sealed unlock:
- `e7_verify --sign-pubkey` reports `unsigned: 1`, `excluded_from_verification: []`, no keylog violation, and
  `flagged_seconds == []`;
- the control without substitution flags T0+6.

The witness does not help. It checks links, not content, and the substitute is pushed in sync like any other record.
`e8_score.py` passes `--sign-pubkey`, so the "signatures" column would show `unsigned = 1` while detection silently
uses the forged roots.

The shipped test `test_E8_a_record_altered_after_signing_is_reported_and_excluded` covers a record that is altered
and keeps its signature. Removing the signature passes.

**Fix.**
- When a public key is given, an unsigned monitor-format record is not the monitor's. Exclude it and report it as
  `unsigned_excluded` (anchor-side evidence of tampering).
- Keep an explicit `--allow-unsigned` for the ten evaluated legacy chains, or exclude unsigned records only once the
  chain holds any signed record.
- Apply the same rule in `verify_all.py`, and test it with the stripped-signature case.

With this rule (`test_BE8_fix_sketch_excluding_unsigned_records`), the substitute is excluded. The verifier then
reports a `polls_unrecorded` stall and two key ranges marked `keylog_not_on_chain`.

## Major

### ME8. A record missing from the chain is read as "the second was sealed empty", so a dropping anchor host makes benign rows attributable (reproduced)

**Where.** `e7_verify.py` step 2. The first cover of the seconds the missing poll sealed falls to the next known
poll, and that poll's `n_sealed` counts only its own roots. So `roots_complete` holds, and the rows are judged
`present_when_sealed_empty`.

**Scenario.** `test_ME8_dropped_record_turns_benign_rows_attributable`. The recorder is never tampered with. The
anchor host answers poll 2 with a tagged "ok" and never stores the record. The monitor discards its frozen roots.
The verifier reports a `polls_unrecorded` stall and the uncommitted key ranges, and it also puts T0+6 in
`flagged_seconds`, attributing benign rows. The same happens under BE8's fix, whose exclusion leaves a missing poll.

**Fix (verifier).** When the chain shows a missing poll (a `seq_local` jump, or a key range marked
`keylog_not_on_chain`), the seconds that poll could have sealed are `root_unknown`, not empty. These are the seconds
in [through(last known poll before the gap), through(first known poll after it)). Report them as evidence the anchor
did not hold. Never attribute them.

The monitor cannot detect a dropping anchor host from its replies. Only the gap on the chain shows it.

## Minor

**mE8a. The reply tag is an oracle for replies to requests that did not authenticate** (reproduced,
`test_mE8_anchor_tags_its_401_and_413_for_any_offered_request_tag`).
- **Where.** `anchord.py` `_send` tags every reply under the append key, over the request's `X-HP-Auth` value as
  sent, even when that value did not verify. This includes 401, 413 and the `GET /head` 200.
- **Effect.** A keyless host that sees the monitor's `X-HP-Auth` can get a valid tag for a 413 answer to the
  monitor's own request. The monitor then halves and *remembers* its record budget.
- **What it cannot do.** No reply obtainable this way carries `"ok": true`, so a keyless host still cannot make the
  monitor drop a frozen root. Replays are bound to the request tag, and the monitor never sends one body twice.
- **Fix.** Do not tag replies to unauthenticated requests, or tag them under a separate domain. Use a separate domain
  for GET replies as well.

**mE8b. The witness pins only what the anchor host chooses to push, and when.**
- The extension check and the every-head check are correct. The E5 check reproduces it: the old witness accepted
  225/225 relinked rewrites, and the new witness refused 225/225. The every-head rule failed 225/225, even on the old
  witness's log. A restarted witness reloads its log.
- But in sync mode a failed push never refuses an append, and a fresh witness accepts any history from record 1. So
  the host can delay pushes, then drop or reorder records before a catch-up.
- With signatures enforced (BE8 fixed), what the host can still do is reduced to dropping records (ME8) and
  reordering identical roots, which is harmless.
- **Fix.** Report the witness lag per record: the witness_recv_ts of the first head covering it, minus the record's
  signed `ts`. Publish the witness's first head out of band, so that a replacement witness log is detectable.

**mE8c. Canonical bytes.**
- The signature covers `SIG_TAG + json.dumps(record without sig, sort_keys=True)`, computed on the final record just
  before each append (`monitor.py:1191, 1300, 1329`). The HMAC then covers the bytes with the signature. The order is
  right, and the Python round trip through the anchor's re-serialisation reproduces the bytes: ASCII-escaped, floats
  printed by `repr`, keys sorted.
- A non-Python third party must reproduce Python's `json.dumps` conventions exactly: `", "`/`": "` separators,
  `ensure_ascii`, `repr` floats, `NaN`. Specify them in the artifact (or use RFC 8785 JCS) if the paper says
  "third-party verifiable".

## Answers to the questions

1. **Accepting a root the monitor did not produce, or hiding a rewrite.**
   - A host running the anchor: yes, today, by stripping the signature (BE8). After BE8's fix it can only drop or
     delay records. A drop shows as a gap, which must not become an accusation (ME8).
   - Code in the hub, with no key: no.
   - A rewrite after a record is witnessed is caught by the every-head check, also across witness restarts with the
     log kept. Gaps and batch catch-ups are covered in mE8b.
   - Signing-key rotation is not supported: a second key's records count as `wrong_key`.
2. **Signed bytes.** The signature is over exactly the bytes the verifier rebuilds, and the HMAC is computed after
   the signature (mE8c).
3. **A spoofed or replayed reply.** Neither can make the monitor drop a frozen root unless the sender holds the
   append key. Valid-looking 401 and 413 replies can be obtained (mE8a), but they cause only failed appends and a
   smaller record budget. The run sets `HOMEPROV_REPLY_TAGS=1`, which avoids `auto`'s trust in the first reply seen.
4. **Markers with the append key alone.** No.
   - The anchor refuses them (403 `marker_needs_operator_key`, tested).
   - `e2_night.py` keeps only markers whose `marker_tag` verifies under the operator key (`markers_from_chain(recs,
     key)`).
   - `e7_verify.py` excuses no violation with a marker at all.
   - The anchor host holds the operator key, so it can still mint markers (the stated HMAC caveat).
5. **Do the tests fail on the old code?**
   - Anchor side: yes. The old witness accepted 225/225 attacks in the E5 check, and E8_ANCHOR_NOTES reports 14/14 of
     `test_anchor_e8.py` failing on the pre-E8 files.
   - Monitor side: I could not run them, because no pre-E8 monitor copy is on disk. By construction, the spoofed-reply
     test fails without the tag check.
   - No shipped test covers the stripped-signature case (BE8) or the dropped record (ME8).
