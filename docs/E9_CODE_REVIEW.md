# E9 code review: excuse rules, per-row binding, streamed seal, direct read, operator markers, anchor cache (2026-10-09)

Scope: the E9 part-A code as frozen candidates, by sha256:

| File | sha256 | Compared with |
|---|---|---|
| `monitor/monitor.py` | `a60cdf59...` | `monitor/monitor_e8.py` (`3e479ae0...`) |
| `exp/stages/e7_verify.py` | `428e229b...` | the pinned E8 copy `HOMEPROV-P13-artifact-prep/pinned/exp/stages/e7_verify.py` (`7e036386...`) |
| `exp/rig/marker_issuer.py` | `05bde4e4...` | `artifact-prep/r13d_tree/exp/rig/marker_issuer.py` (`d38276fc...`, the E2 issuer) |
| `testbed/anchord/anchord.py`, `anchord_linked.py` | `8b35448d...`, `f6252e24...` | `anchord_e8.py`, `anchord_linked_e8.py` |
| tests | `test_e9.py` `89451ac4...`, `test_e9_dishonest.py` `84ed49c5...`, `test_anchor_e9.py` `f886aa0d...`, `test_anchor_cache.py` `54a3e52c...` | |

Read against E9_DESIGN.md, E9_IMPL_NOTES.md (sections 3-4a and 8-10), E9_RUN_NOTES.md, E9_PREREG_DRAFT.json and the
earlier reviews in E7_CODE_REVIEW.md. No repository file was modified, nothing in `exp/out` was written, no container
was touched, and no key was printed or recorded (the scratch tests make throwaway keys in pytest temporary
directories). The shipped suites pass as claimed: `python3 -m pytest -q monitor testbed/anchord`, **224 passed**.

Every finding marked "reproduced" has a test in
`<scratch>/e9review/test_e9_review.py`.
Each `test_ATTACK_*` asserts that the attack SUCCEEDS, so a pass means the finding reproduces; each `test_CONTROL_*` is
its control. All 12 pass (`cd <artifact-root> && python3 -m pytest -q -p no:cacheprovider <file>`).
They reuse the shipped rig (`monitor/test_coverage.py`, `monitor/test_e9.py`) unchanged.

## Verdict: NO-GO for the freeze until R1 is fixed and R2 is measured

The purge-disconnect rule itself (A1) held against every edit I tried that changes a displayed cause in a segment
after the cutoff. The per-row binding (A2) localises soundly. The streamed seal reproduces the single pass. The anchor
cache changes no record. But the RESTORE rule has no end in time. After the declared restore on day 4, every edit,
deletion or low-key insertion of any later row is excused, at the segment level and in the keylog. The pre-registered
run has attack batches on days 5, 6 and 7, after that restore. With the code as it is, the PU and PSR trials of those
days (and the edit part of INS-L) would be scored as missed. Any tampering of untouched seconds would also be excused.
The smoke runs could not show this, because their last batch ran before their restore.

| ID | Severity | Where | One line |
|---|---|---|---|
| R1 | **Critical** | e7_verify.py:1250-1270, 1296-1321 | A RESTORE marker excuses every later edit, deletion and low-key insertion for the rest of the chain (reproduced, 3 variants) |
| R2 | **High** (scoring pipeline) | e7_verify.py:2199, 1797, 1837; e9_score.py:147, 610 | Each verification parses the whole 1.6-2.6 GB full-history escrow, about 7 bytes of heap per byte, twice, with 2 jobs in parallel (measured ratio; full scale not measured) |
| R3 | Medium | e7_verify.py:1155-1165; anchord.py:455-486; marker_issuer.py:141, 283 | A replayed or duplicated RENAME marker defeats "consumed on first use" (reproduced, verifier and live anchor) |
| R4 | Medium (bounded) | e7_verify.py:908-929, 950, 1003, 1055 | The tolerance-band check does nothing in a windowed (daily) verification, and a successor's disconnect is excused without the band check (reproduced, 2 tests) |
| R5 | Medium | e7_verify.py:589-631 (markers read from the chain only) | A dishonest anchor host that withholds or reorders operator markers turns benign purges, restores and renames into violations; A7's per-party claim does not cover markers |
| R6 | Medium (latent) | monitor.py:1079, 1192; e7_verify.py:702, 704, 783 | After a restore, rows with reused keys are not keylog-bound (B1/R3 attacks reopen for them), and the evidence index assumes keys are unique |
| R7 | Low | e7_verify.py:1055, 807-820 | A row written after the purge, backdated before its cutoff and later deleted, is excused as "purged" (reproduced) |
| m1-m7 | Low / Info | see below | `--no-rowbind` still uses the binding in the purge rule; K not taken from the signed backup watermark; no direct-read post-check; RENAME digest is absolute; `HOMEPROV_SINCE` edge cases; anchor cache limit; stale documents |

---

## Critical

### R1. The RESTORE rule has no upper time bound: after a restore, every later edit, deletion or low-key insertion is excused (reproduced)

**Where.**
- `e7_verify.py:1250-1270` (segment rule of `apply_restore`). Line 1252 bounds the rule from below only
  (`if hi <= r0: continue`). Line 1256 counts every row timestamped at or after the marker's `issued_ts` I as
  acceptable (`True if new_row(n, x)`), and never checks its content. An emptied segment passes too (`all([])`). The
  coarse branch `segment_after_restore_point` (1263-1264) is unbounded in the same way.
- `e7_verify.py:1296-1321` (keylog rule). A changed, removed or added row above K passes when its first-observed
  second is at or after R - tol and its current timestamp is at or after I. Every row written after the restore meets
  both conditions.
- `e7_verify.py:1237`: K is the largest key among current rows timestamped before I.

**Scenario.** `test_ATTACK_restore_marker_excuses_a_laundering_900s_after_the_restore`. The steps:
1. The shipped `restore_scenario`: backup at T0+60, RESTORE marker with I = T0+105, the backup put back, new rows to
   T0+130.
2. The hub runs on. An honest app unlock in second T0+1001 (state row and its service call) is sealed by later polls,
   900 s after the restore.
3. The hub launders it (S1: the user context is rewritten, the service call deleted).

Verified with `--restore-tol-s 30`, as `e9_score.py:117` passes it: T0+1001 is not flagged. The second is in
`excused_violations` with `{"marker": "RESTORE", "rule": "rows_new_or_from_the_backup"}`. `keylog_violations == []`,
because the keylog range that first observed both rows is excused as well (`restore.excused.keylog_ranges >= 1`).

The same holds:
- with the escrow instead of the binding, for an edit of the state (`test_ATTACK_restore_marker_excuses_an_edit_with_escrow_too`);
- for deleting both rows (`test_ATTACK_restore_marker_excuses_deleting_every_row_of_a_later_second`;
  `attributable_rows == []`).

Controls:
- Without `--restore-tol-s`, the laundered second is flagged (`test_CONTROL_laundering_after_the_restore_is_flagged_without_restore_tol`).
- A fresh-key insertion after the restore stays flagged, through the late-row judgement, which the RESTORE rule does
  not touch (`test_CONTROL_fresh_key_insertion_after_the_restore_stays_flagged`).
- By reading the code: an insertion with a low key, for example a lost key reused inside a second in [I, restore), is
  excused at both levels.

**Effect on E9.**
- The restore is on 2026-10-14 at 20:30. The attack batches of 10-15, 10-16 and 10-17 at 14:00 follow it.
- Each later day's verification accepts the RESTORE marker (it was anchored before the day's snapshot) and applies
  the rule to the whole day.
- `score_trials` counts a trial as detected only when its second is in `flagged_seconds`, which is computed after the
  excused violations and keylog ranges are removed.
- So PU (laundering) and PSR (member swap) trials on days 5-7, 15 of 35 per arm per monitor, would be scored as
  missed. The edit part of INS-L would be missed too; its inserted fresh-key rows stay flagged. BD-S stays detected.
- The benign floor would also hide any tampering of untouched seconds after the restore.
- No test or smoke covers this. The smoke's last batch ran before its restore (E9_RUN_NOTES.md 4.1: "day 3 a batch,
  the backup and the restore"). The shipped RESTORE tests check only the restore itself.

**Fix (verifier, before the freeze).**
1. **Bound the window.** Let B be the `copy_at` of the first observable poll after I whose `wm`, in either table, is
   below the largest `wm` of the polls before I. That is the first poll that read the restored database. If there is
   no such poll, the marker excuses nothing and is reported as `restore_not_observed`. Optionally, have the operator
   issue a second marker after the hub is back (RESTORE_DONE), and use the earlier of the two.
2. **Segment rule.** Apply it only to segments whose sealing poll's `copy_at` is before B and whose end is after
   R - tol. Every row present must be a backup row (key <= K) exactly as committed (escrow or binding). Drop
   `True if new_row(...)`. In the coarse branch, require the segment to be empty.
3. **Keylog rule.** Apply it only to ranges committed by polls with `copy_at` before B. A row at a lost key that now
   holds a post-restore row is not judged by the old range. List it. Its content is bound by its own post-restore
   segment root, which no RESTORE rule may excuse.
4. **K.** Take K from the marker. The harness already signs `backup_wm` into the RESTORE marker (`run_e9.sh:815`,
   `e9ops.py` `m.update(extra)`), but the verifier ignores it. Fail closed when the database's largest key below I
   disagrees with it.
5. **Tests.** Keep the three attack tests above as regression tests (each must then flag T0+1001), alongside the
   shipped restore tests (each must stay excused).

---

## High

### R2. Each verification loads and parses the whole full-history escrow, about 7 bytes of heap per escrow byte, with two jobs in parallel (measured ratio; full scale not measured)

**Where.**
- `e7_verify.py:2199`: `read_lines(a.escrow)` reads the file into one string, then splits it into lines.
- `recover()`, line 1797: `read_escrow()` parses every segment line and converts every node.
- Line 1837: when any keylog violation exists (attack days always have some), `read_escrow_keylog()` parses every
  keylog line too, while the segment index is still alive.
- `e9_score.py:147` passes `--escrow` to every verification. `e9_score.py:610` runs 2 jobs by default.

**Evidence.** `escrow_mem.py` (scratch) measures tracemalloc peaks on a synthetic stable-scheme full-history escrow of
65.5 MB (30,000 state rows, binding on):
- `read_escrow`: 6.82 bytes per byte of segment line;
- `read_escrow_keylog`: 7.31 bytes per byte of keylog line.

The E9 escrow after the full-history seal is 2.59-2.64 GB per monitor (E9_IMPL_NOTES.md 5.2, 5.3). Extrapolating
(this is an estimate, not a measurement), one verification process holds:
- about 2.6 GB for the raw lines;
- about 10 GB for the parsed segment lines;
- about 8 GB for the parsed keylog lines.

Two such processes run at once on the 24 GB Mac. There are about 40 verifications: days, nights, `--no-rowbind`,
`--no-purge-disconnect`. E9_RUN_NOTES.md 7.13 says the full-scale verification time and memory were not measured.
The run notes also allow scoring during the week on a copy of the run directory. That would put this memory load on
the host of the run.

**Fix.**
- Before the freeze, run one verification at full scale: the E8 recorder with a full-history escrow, under
  `/usr/bin/time -l`. Record its peak RSS and wall time.
- Make `recover()` lazy, as `PurgeEvidence` already is: index the escrow lines by second and by key range with the
  regexes `PurgeEvidence.__init__` uses, and parse only the flagged seconds and the failed ranges.
- Read the escrow by byte offsets instead of `read_lines`.
- Keep `E9_VERIFY_JOBS=1` until the measurement is in.

The outputs are unchanged by this. Show it with the E7/E8 byte-identity re-runs.

---

## Medium

### R3. A replayed or duplicated RENAME marker defeats "consumed on first use" (reproduced: verifier, and the live linked anchor)

**Where.**
- `e7_verify.py:1155-1165`: a marker is consumed by `chain_seq`, so two records with the same marker are two
  markers.
- `marker_issuer.py:141`: the signature covers only the marker dict. There is no nonce, and nothing binds it to an
  anchor or monitor.
- `anchord.py:455-486`: no duplicate or nonce check.
- `marker_issuer.py:283`: `issue()` resends the same body after an unverified reply. If the first attempt was in fact
  appended, an honest network fault leaves a duplicate.
- The anchor host holds the operator's HMAC key, so it can also append a copy of a signed marker.

**Scenario.**
- `test_ATTACK_a_replayed_rename_marker_excuses_the_repeated_change` is the shipped consumption test (rename,
  declared; rename back, declared; the same rename again, undeclared) with one verbatim replay of the first RENAME
  record. All three transitions are excused, and the verdict is `changed_with_declared_renames`.
- `test_ATTACK_the_linked_anchor_appends_a_byte_identical_operator_request_twice`: the real `anchord_linked.py`, with
  an append key, an operator key and a sync witness, appends a captured operator request twice (seq 1, 2).
- The threat model lets the hub observe markers on the network. It can reach the anchors: the smoke's probes got 401s
  from the hub. Docker grants NET_RAW by default, which is enough to intercept traffic on a shared bridge.

**Effect on E9.** Small for the planned session, whose order (attack first) does not depend on consumption. But the
property claimed in E9_IMPL_NOTES.md 10.4 does not hold against this adversary. Note that E9_PREREG_DRAFT.json still
says RENAME markers are "not consumed".

**Fix.**
- Verifier: deduplicate accepted markers by the SHA-256 of their canonical marker JSON, and report the duplicates.
- Issuer: add a random `nonce` and an `anchor` (or monitor-key fingerprint) field to every marker. The verifier
  rejects a marker whose `anchor` names another chain.
- Anchor: refuse an operator marker whose nonce it already holds (409 `duplicate_marker`, recorded as a refusal).

### R4. The PURGE tolerance band: its check is vacuous in a windowed verification, and successor disconnects skip it (reproduced)

**Where.**
- `band_ok()` (`e7_verify.py:908-929`) takes `r_min`, the earliest row still in the band, from `groups`. `groups`
  holds only rows loaded since `(t0 // 3600 - 1) * 3600` (`:1359`).
- `e9_score.py:143` passes `--window` to every daily verification. The band lies 30 days before that window, so
  `r_min` is None and `band_ok` returns True.
- The keylog rule (`:1055`) then excuses any removal in [c0, c1).
- Separately, the disconnect rule (`restore_rows`, `:950` with `c = c1` from `:1003`) accepts a predecessor committed
  anywhere in [c0, c1) without asking whether its deletion was purge-shaped.

**Scenarios.**
- `test_ATTACK_band_check_is_vacuous_when_the_band_is_outside_the_verified_window`: the shipped out-of-order band
  deletion (d4 deleted while d3 stays). Verified as a day is, with `t0`/`t1`, its key range is excused as purged.
  Control: flagged without the window (`test_CONTROL_out_of_order_band_deletion_is_flagged_without_a_window`).
- `test_ATTACK_successor_disconnect_is_excused_although_its_predecessor_was_not_purge_shaped`: e1 is a retained band
  row (CUT+50; the hub purged at CUT+20, d3 at CUT+30 retained). Its successor e2 records a state change in the
  verified day. The adversary deletes e1 and nulls `e2.old_state_id`, which hides e2's change from the logbook (no old
  state to compare with). Results:
  - Whole-chain verification: e2's second is excused as a disconnect. Only e1's 30-day-old band second is flagged.
  - The day's verification: nothing at all.

**Bound.** Only band rows (tol = 60 s of 30-day-old rows per night) and their successors are affected. Home Assistant
disconnects those successors itself at the next night's purge, so the hiding comes at most about 24 h early. This is
why it is Medium and not High. It is still a pre-registered rule that does nothing in every daily verification.

**Fix.**
- Compute `r_min` with a query over the whole recorder, not from `groups`:
  `min(ts)` over states and events with `c0 <= ts < c1` (TS_OK).
- In `restore_rows`, `row_verdict` and the keylog disconnect check: when the restored predecessor's committed
  timestamp is at least c0, also require `band_ok(cut)` and that timestamp to be below `r_min`.

### R5. A dishonest anchor host that withholds or reorders operator markers creates false accusations; A7 does not cover markers

**Where.** `chain_markers()` (`e7_verify.py:589-631`) reads markers from the chain only.

**Scenario.**
- If the host drops the night's PURGE marker, every disconnect and every deleted segment of that purge stays a
  violation. The shipped `test_A1_not_excused_without_a_valid_marker[none]` shows the mechanism.
- If it places a RENAME marker after the record carrying the new digest, the declared rename becomes "undeclared".
- If it drops the RESTORE marker, the restore becomes a mass violation.

A7's summary states that the host "can turn evidence into unknown ... or change nothing", and that no untouched
second becomes a violation. That was measured on E8 chains, which hold no operator-signed marker. With markers, the
host can also turn benign events into violations, and with R3 it can excuse a repeated rename.

**Fix.**
- Accept operator-signed markers from the operator's own issuance log as well (`--markers issuer.jsonl`, checked by
  signature alone).
- Report every marker in that log that is missing from the chain, or late on it, as anchor-side evidence.
- State this in the per-party table: the host can withhold markers; without the operator's log, that becomes a false
  accusation.

### R6. After a restore, rows with reused keys are not keylog-bound, and the verifier's evidence assumes unique keys (latent)

**Where.**
- `monitor.py:1079` (and `:1192`): when `wm <= hw` the range is empty, and the high-water never comes back down.
- `e7_verify.py:702, 704, 783`: `first_sec`, `row_hash` and `seg_tuple` are keyed by key with `setdefault`, so the
  first (pre-restore) row at a key wins.

**Effect.**
- Every row the hub writes after the restore with a key in (K, old high-water] is bound only by its segment root.
  In the smoke, that was every key from 935,348 up to the old high-water.
- So the attacks the keylog closed (E7 B1 park, invisible and gap; re-review R3, a delete or re-time before the
  second is sealed) are open again for those rows, until the keys pass the old high-water. E9_IMPL_NOTES.md 9.5
  notes the binding gap but not this consequence.
- Evidence lookups for such a row can return the lost row's tuple or hash. With only the binding, a later purge
  disconnect of a reused-key row is then `committed_value_not_found` (a false alarm). With the escrow, the result
  depends on load order.
- It stays latent in E9. Home Assistant's `StatesManager.load_from_db` (2026.x source, `recorder/table_managers/states.py`)
  does not reload the last committed ids, so the first state of each entity after a restart has `old_state_id` NULL.

**Fix.**
- Monitor: when an observable poll sees `wm[t] < hw[t]`, record `keylog_rewind: {t: {"from": hw, "to": wm}}` and set
  `hw = wm`, so post-restore rows are committed again.
- Verifier: key evidence by (key epoch, key).
- Or state the limit for the first post-restore rows in the pre-registration.

---

## Low

### R7. A row written after the purge, backdated before the cutoff, then deleted, is excused as purged (reproduced)

**Where.** `e7_verify.py:1055`: a removed row is "purged" if its first-observed second is before a cutoff. Nothing
asks whether the row existed when the purge ran.

**Scenario.** `test_ATTACK_a_row_written_after_the_purge_and_deleted_is_excused_as_purged`. After the purge, the
adversary writes a forged unlock backdated to CUT-500 with a fresh key:
- while it exists, it is an attributable row;
- after it is deleted, the removal is excused (`rows_purged`);
- without a marker, the removal is flagged.

No lasting change remains, so the effect is that a transient forgery can be erased without trace.

**Fix.** A removed row counts as purged only if the poll that first observed it has a `copy_at` at or before the
cut's `scheduled_ts` plus a small slack. Otherwise the reason is `removed_row_written_after_the_purge`.

### Minor and info

- **m1.** `--no-rowbind` is not passed into `apply_purge`/`PurgeEvidence` (`e7_verify.py:698, 1044`). In
  purge-touched ranges, the suspects "without per-row binding" are narrowed using the binding, so the comparison
  number is understated. Pass `rowbind` through, or document it.
- **m2.** `restore_points` puts no upper bound on I - R. A marker with an old R excuses a long range. Pre-register a
  maximum.
- **m3.** Direct read has no consistency check after the read: the snapshot's integrity rests on SQLite's read lock
  across containers. The smoke (591 direct reads, 0 untouched violations) supports it. A cheap defence in depth: read
  the WAL salts and the database change counter before `BEGIN` and after the rows, and fail closed (`read_raced`) if
  they moved.
- **m4.** A RENAME marker declares an absolute part digest, computed from the hub's storage at issuance
  (`marker_issuer.py:328`). An undeclared change that is already in storage then, and that no poll has yet seen, is
  folded into the declaration. With 5 s polls and the issuer's latency this is impractical in E9. To harden it, add
  the expected `from` digest and require `transition.from == marker.from`.
- **m5.** `HOMEPROV_SINCE`:
  - `inf` passes validation (`monitor.py:977`), then every poll fails on `int(inf)` (`:1401`). Reject non-finite
    values.
  - With `0`, the first high-water is the largest key of a row with a negative timestamp (`:1073`, `:1186`; TS_OK
    allows `abs(ts) < 1e12`), and such rows are never sealed. Use `hw = 0` and no lower bound when SINCE is 0.
    There is no benign effect.
- **m6.** Anchor cache. The documented limit also covers rewrites at rest that keep the size and the last line but
  change the line count: `seq` and the push offsets then diverge from the file. Only an anchor-host adversary can do
  this, and the every-head witness check still catches rewrites of witnessed records. Information only.
- **m7.** Stale documents:
  - E9_PREREG_DRAFT.json says RENAME markers are "not consumed" (fixed in 10.4).
  - E9_IMPL_NOTES.md 3 says "use both operator keys in E9", while `e9_score.py` passes only `--operator-pubkey`.
    The signature alone is the stronger check, so only the note needs to change.

---

## What holds (attacks tried and stopped)

- **Purge-disconnect rule (A1), segments after the cutoff.** Each of these keeps the violation:
  - nulling `old_state_id` together with any other edit in the segment (the fold over the restored rows fails);
  - a predecessor still present, or newer than the cutoff;
  - another value written instead of NULL;
  - re-timing a disconnected row.

  Nulling the `old_state_id` of a row whose predecessor was legitimately purged gains nothing: Home Assistant already
  nulls every such row (`disconnect_states_rows`), and new states written after a purge carry NULL
  (`evict_purged_state_ids`).
- **Deleting a row just after the band, timed with the real purge.** Flagged at the second and in the keylog
  (`test_CONTROL_deleting_a_row_just_after_the_band_during_the_purge_is_flagged`). Its minute and hour reach into the
  band and are excused under `tolerance_band`, so the second level carries the detection.
- **Editing a row inside the band** is flagged (shipped tests). With the whole recorder loaded, the band's ordering
  check works (control above).
- **Per-row binding (A2).** The full hash is fold-checked against the signed `acc` before it is used; an inconsistent
  binding keeps every row a suspect; localisation is exact. No decoy or collision attack is open.
- **Streamed full-history seal.** The 128-row cut with one row of lookahead matches `keylog_chunks`. The escrow order
  matches. In direct mode, one read transaction covers the whole pass. A failed pass adds nothing to `pending` or the
  state.
- **Markers.**
  - Only operator-signed markers count when the public key is given.
  - PURGE needs `issued_ts <= scheduled_ts`, and its cutoff comes from the verifier's own policy.
  - A marker received and issued after the snapshot is rejected.
  - Name-map records after the snapshot are left out.
  - All four name-map parts are always present in a record, so a transition with an empty change list cannot occur.
- **Anchor cache.**
  - The lock is an `RLock`, so a sync push that reads lines under it does not deadlock.
  - Appends write and fsync before the state is updated, and a failed write drops the state.
  - Records, heads and pushes match the E8 daemon (`test_anchor_cache.py`).

## Reproduction

Scratch folder: `<scratch>/e9review/`.
- `test_e9_review.py`, **12 passed**: R1 (control plus 3 attacks, plus the fresh-key control), R3 (verifier replay;
  live `anchord_linked.py` replay), R4 (control plus 2 attacks), R7 (1 attack), and the after-the-band control.
- `escrow_mem.py`: the R2 heap-per-byte measurement (prints a JSON line; nothing written to the repository).
- `shipped_suites.txt`: `monitor` and `testbed/anchord`, 224 passed.
- Diffs: `monitor.diff`, `verify.diff`, `anchord.diff`, `linked.diff`, `issuer.diff`.

---

# Re-check of the fixes (2026-10-10)

Scope: E9_IMPL_NOTES.md section 11. Files by sha256:
- `monitor/monitor.py` `3f277d39...`
- `exp/stages/e7_verify.py` `59a1b228...`
- `exp/rig/marker_issuer.py` `0c644d43...`
- `monitor/test_e9.py` `bfac176d...`
- `testbed/anchord/test_anchor_e9.py` `a9401be5...`
- `exp/stages/e9_dishonest_markers.py` `77156058...`
- the anchors, unchanged: `8b35448d...`, `f6252e24...`

Each was diffed against the reviewed versions kept in `scratchpad/ref_review/`. The shipped suites pass:
`python3 -m pytest -q monitor testbed/anchord`, **251 passed**. No repository file was modified, no container was
touched, and no key was recorded.

Scratch tests are in `scratchpad/e9review/`:
- **The first review's `test_e9_review.py`, re-run on the new code.** The 6 attacks the fixes target now FAIL, which
  means they are caught: R1 x3, R4 x2, R3 verifier replay. Two still pass, both as expected:
  - the live-anchor replay, because the anchor was deliberately left unchanged and the verifier now counts the copy
    once;
  - R7, because my forged row was first observed 25 s after the scheduled purge, inside the documented 120 s
    `first_seen_by` window.

  All 4 controls pass.
- **`recheck/test_recheck.py`** (new attack, 3 tests, all pass, so the attack reproduces) and
  **`recheck/m3_probe.py`** (direct-read stamp probe, with the hub in a separate process).

## Verdict: freeze after one more verifier fix (N1); N2 is recommended

The fixes close the original attacks, and the lock fix is correct. One new soundness hole is open: the RESTORE end
point B can be postponed (N1). With B postponed, deleting a whole second after the restore leaves no evidence at all.

N1 does not change the pre-registered arms. PU, PSR and INS-L edit a row that stays present, and the new rule never
excuses a present row above K. BD-S inserts rows with fresh keys. But N1 is in the threat model, and the fix needs a
pre-registered parameter (or a harness action during the run). So it has to be settled before the freeze.

N2 is a false fail-closed in direct mode: availability, not soundness.

| Finding | Verdict | Evidence |
|---|---|---|
| R1 RESTORE without end | **closed for edits, deletions and low-key insertions; new issue N1** (B can be postponed) | my 3 R1 attacks are caught; `test_ATTACK_dummy_max_keys_*` |
| R2 escrow memory | **closed** | lazy `Escrow` index; the impl notes measure 1.81 GB max RSS for a full-history night verification (I did not re-run at full scale); outputs unchanged per the suites and 11.15 |
| R3 marker replay | **closed** in the verifier (deduplicated by canonical hash; nonces on RESTORE and RENAME; `monitors` binding is optional and unused by the harness). The anchor still appends replays (left unchanged on purpose) | my replay test is caught; issuer retries now produce harmless duplicates |
| R4 band check | **closed** | `r_min` from the whole recorder; band predecessors checked in all three places; both my R4 attacks are caught |
| R5 withheld or moved markers | **open, documented** (no design change; `e9_dishonest_anchor_markers.json`; the per-party table must say it) | no `--markers` operator log |
| R6 reused keys after a restore | **closed** with `HOMEPROV_KEYLOG_REWIND=1` (set in `run_e9.sh:104`) | key epochs in `PurgeEvidence`; the old ranges are still checked by `check_keylog`, so epoch evidence cannot clear a change |
| R7 removed after the purge | **closed, with a residual** of `scheduled + tol + 60 s` (stated in 11.7) | my test row, first observed at sched+25 s, is still excused, as designed |
| m1 `--no-rowbind` | closed | |
| m2 restore age | closed (`--restore-max-age-s 86400`) | |
| m3 direct-read check | **lock fix correct; new issue N2** (false `read_raced` on slot-0 reads) | `m3_probe.py` case B |
| m4 RENAME `from` | closed (optional; the harness's markers carry no `from`) | |
| m5 `HOMEPROV_SINCE` | closed | |
| m6 anchor cache | information, unchanged | |
| m7 documents | closed for the draft: `E9_PREREG_DRAFT.json` (23:07) carries `KEYLOG_REWIND`, the restore maximum age and the seen slack, and no longer says "not consumed" | |

## N1 (High). The RESTORE end point B can be postponed, and a later whole-second deletion is then excused with no trace (reproduced)

**Where.**
- `restore_read_back` (`e7_verify.py`): B is the first observable poll after I whose watermark falls below the
  pre-restore maximum in *either* table.
- `apply_restore`: a segment sealed before B passes when every row present is an unchanged backup row. An emptied
  second passes. A gone sealed row above K is fine.
- In a key range committed before B, a removed row above K, first observed after R - tol, raises no objection.

**Scenario.** `test_ATTACK_dummy_max_keys_postpone_B_and_a_later_whole_second_deletion_is_excused` and
`..._deletion_before_the_minute_is_sealed_leaves_no_violation`.
1. The restored recorder also holds one state and one event whose keys equal the pre-restore maximum + 1, with a
   timestamp after I. That keeps the K check intact (`recorder_last_key_before_marker == backup_wm`), and no poll sees
   the watermark fall.
   - In E9, the hub can do this by rewriting the archive. The archive sits in the hub's own `/config/backups` from
     20:00 to 20:30, and `backup_restore.py` does not check its hash. Inserting the rows at start-up before the
     monitor's next poll would also work, but that is a race.
2. The hub runs on. An honest unlock in second T0+1001 (state row and service call) is sealed.
3. The adversary deletes both rows: after the second is sealed and before its minute is sealed.
4. Much later, it deletes the two dummy rows. B becomes that poll (T0+1065, against I = T0+105).

Verified with `--restore-tol-s 30`, with the escrow and with the binding:
- second T0+1001 is excused (`rows_from_the_backup`);
- `flagged_seconds == []`, `violations == []`, `keylog_violations == []`, `attributable_rows == []`.

With a later deletion, after the minute is sealed, only that minute stays violated, and it is unlocalised
(`localized_seconds == []`). Control: without the dummy rows the same deletion is flagged.

**Side effect on honest runs.** If Home Assistant writes more rows in both tables than the restore lost before the
monitor's first post-restore poll, B is never found. The status is then `restore_not_observed`, and the honest restore
becomes a set of violations. The smoke found B, but that was a race the monitor won.

**Fix (before the freeze).**
1. **Verifier.** Pre-register a maximum restore duration D (for example 600 s). If B - I > D, the marker excuses
   nothing. Better still, the harness issues an operator-signed RESTORE_DONE marker once Home Assistant logs "Restore
   complete", carrying the hub's start time. The verifier then uses B = min(read-back poll, DONE), or DONE when no
   read-back poll exists, and excuses a gone row only if its committed timestamp is before the hub's start. That
   closes N1 and the honest `restore_not_observed` case.
2. **Harness.** Copy the archive into the hub immediately before writing `.HA_RESTORE`, not 30 min earlier, and check
   its sha256 inside the hub right before the restart against the `archive_sha256` the marker signs.

## N2 (Low to Medium, availability). Direct read fails closed on a legitimate WAL restart when it reads on slot 0 (reproduced)

**Where.** `direct_finish()` compares the WAL header (checkpoint sequence and salts) and the database change counter,
read just after the snapshot was pinned and again after the rows were read.

**Probe.** `recheck/m3_probe.py`: the repository's monitor functions, with the hub in a separate process.
- **Case A.** The reader pins while the WAL has un-backfilled frames, so it holds a read-mark slot of 1 or above. A
  PASSIVE checkpoint during the read backfills 97 of 118 frames. The stamp is unchanged, and `direct_finish` returns
  None. This agrees with the impl notes' probe.
- **Case B.** The WAL is fully backfilled when the reader pins, so SQLite gives the reader slot 0 and it reads only
  the database file, which no checkpoint can change while that lock is held. The hub's next commit then legitimately
  restarts the WAL: new salts, checkpoint sequence 0 to 1. `direct_finish` returns `read_raced`, although the
  snapshot's watermark is unchanged.

**Effect.** This can happen once per completed checkpoint, when a poll pins between the checkpoint and the hub's next
commit and that commit lands during the read. The rate on the lab installation is not measured. It affects M-direct
only (copy mode retries its salt check three times). So it would show as evidence-unobservable polls and observation
gaps in one arm, and could be misread in the comparison of the two read modes.

**Fix.** On `read_raced`, repeat the direct read, up to 3 times as copy mode does. Optionally, read the `-shm`'s
`nBackfill` and `mxFrame` through a descriptor opened before the connection, and skip the WAL part of the stamp when
the read began on a fully backfilled WAL. Count `read_raced` in the smoke.

## The lock fix (11.0) against POSIX fcntl semantics: correct

I traced every path of a direct poll:
- **Before the connection.** `validate_files()` (open, read, close of the database, `-wal` and `-shm`) runs before
  the connection exists. `direct_close(None)` first closes any stamp descriptor left from an earlier poll.
- **The m3 descriptors.** Two raw descriptors (database and `-wal`, never the `-shm`) are opened before
  `sqlite3.connect`, read only with `pread()`, and closed only after the connection: in `direct_close()`, after
  `con.close()`. That order holds on every exit:
  - `check_connection` failing in `direct_snapshot`;
  - an exception during the read (`load_failed`, which goes through `direct_close`);
  - the normal end (`direct_finish`).
- **While the read is held.** Every read goes through the one connection: `watermark`, `keylog_poll`, its new rewind
  branch, `_next_row_ts_any`, `seal_stream`, `keylog_stream`, `load`/`load_stable` all receive the connection, and
  `_open()` returns it without opening a file. No other code touches `SRC`: `_wal_salt()` and `snapshot()` run only on
  the copy path. `namemap_seal`, the escrow and the state file are other files, and the name map is read after the
  connection is closed.
- **SQLite's own descriptors.** SQLite opens and closes only its own descriptors, at connect and close. The raw
  descriptors hold no lock, so closing them, or SQLite closing its own, drops nothing a still-held read needs.
- **The after-read check.** `validate_files()` after the read runs only after the connection is closed.

## Smaller notes on the new code

- **Adversary-induced false accusations, R5 class (Low).** The hub can make the restore excusal fail closed:
  - by deleting the backup's largest-key row, or inserting a backdated row with a higher key, which trips
    `backup_wm_disagrees_with_the_recorder`;
  - and, since `r_min` now comes from the whole recorder, by inserting one backdated row early in the purge band, which
    makes the band "not purge-shaped" and leaves that night's band disconnects unexcused.

  In each case the hub's own write is flagged, so this produces violations, never exoneration.
- **Forced rewinds (information).** The hub can force a keylog rewind outside a restore by deleting the newest rows.
  That deletion is itself flagged by the earlier ranges, which `check_keylog` still checks. The latest-incarnation
  evidence then never clears a change: the purge and restore rules still require the old range's binding or the
  anchored root. I found no way to turn a rewind into an excuse.
- **Deduplication and nonces (information).** A duplicate is skipped only after its signature and HMAC have verified.
  `nonce_reused` can only be triggered by a second marker the operator signed. `issue()` retries reuse the same nonce,
  so they deduplicate. The RENAME markers e9ops issues for each intermediate state get distinct nonces, so they are
  not merged.

## Reproduction

- `cd <artifact-root> && python3 -m pytest -q -p no:cacheprovider <scratchpad>/e9review/recheck/test_recheck.py`:
  3 passed (the control; N1 with a later deletion, escrow; N1 with a deletion before the minute is sealed, escrow and binding).
- `python3 <scratchpad>/e9review/recheck/m3_probe.py`: case A `direct_finish: null`; case B `read_raced` with the
  watermark unchanged.
- `<scratchpad>/e9review/test_e9_review.py` on the new code: 6 failed (attacks caught), 6 passed (4 controls, the
  live-anchor replay, the R7 row inside the slack).
- `<scratchpad>/e9review/recheck/shipped_suites.txt`: 251 passed.
- Diffs: `<scratchpad>/e9review/recheck/{monitor,verify,issuer}.diff`.

---

# Re-check 2: N1 and N2 (2026-10-10)

Scope: E9_IMPL_NOTES.md section 12, and what the two fixes could open. Files by sha256:
- `monitor/monitor.py` `8ad9e2d7...`
- `exp/stages/e7_verify.py` `9c42fad9...`
- `exp/rig/marker_issuer.py` `fcf66817...`
- `monitor/test_e9.py` `9d9f034d...`
- the harness: `testbed/e9/run_e9.sh` `20d89d78...`, `e9ops.py` `1a2d9929...`

Each was diffed against the re-check versions (`scratchpad/ref_recheck/`). The shipped suites pass:
`python3 -m pytest -q monitor testbed/anchord`, **261 passed**. The repository's N1, N2 and A4 tests pass (11). No
repository file was modified, no container was touched, and no key was recorded. My new scratch tests are in
`scratchpad/e9review/recheck2/test_recheck2.py`: 4 tests, all passing; the one attack test asserts the documented
residual.

## Verdict: the code can be frozen

Both fixes close what I reproduced. Neither opens a soundness hole within the threat model, given that the harness:
- passes `hub_started_ts` (it always does);
- holds the archive outside the hub (it does);
- pre-registers `--restore-done-max-s 600` (in `e9_prereg.py`).

What remains is small and listed below. None of it needs a code change before the freeze; two items are worth one
line each in the pre-registration.

| Item | Verdict | Evidence |
|---|---|---|
| N1 planted keys postpone B | **closed** | `test_N1_dummy_keys_no_longer_postpone_B` (escrow and binding): B = the first poll after RESTORE_DONE (T0+120), and the deletion at T0+1001 is flagged |
| Forged RESTORE_DONE | **closed** | only operator-signed markers count; the anchor host and the hub hold no signing key |
| Replayed RESTORE_DONE | **closed** | a second copy is deduplicated by canonical hash. A copy from another run names a different RESTORE (fresh operator key per run, `run_e9.sh:326-350`), and its `recv_ts` on a later chain fails `restore_done_anchored_after_the_maximum`. Posting the same DONE to both anchors is intended |
| One RESTORE_DONE closing a different RESTORE | **closed** | the DONE must name its RESTORE by nonce and/or canonical sha256, each must match, and nonces are unique (`nonce_reused`) |
| H chosen by the adversary | **closed** | H is signed by the operator and comes from Docker's `State.StartedAt` of the restarted container (`run_e9.sh`), which the Home Assistant process cannot set. H must lie in [I, the DONE's issued_ts]. Rows the restored hub writes have timestamps at or after H, and lost rows were committed before the stop, so before H |
| A late DONE | **closed** | rejected after 600 s by `issued_ts` and by `recv_ts` (`test_N1_a_done_..._too_late_closes_nothing`) |
| The harness | **closed** | the archive is held outside the hub; with the hub stopped, the copy is placed, hashed inside the container and refused on a mismatch. The planted-key attack therefore needs a rewritten archive, which is now refused |
| N2 retry and lock rule | **closed** | each attempt ends with `direct_finish` (connection, then the stamp descriptors, then `validate_files()`) before the next attempt's `validate_files()` and connect, so no file of the recorder is opened or closed while a read is held. Nothing in an attempt changes the poll's state (`st`, `pending`, the high-water); state is updated only after the loop |
| N2 escrow cut | **closed** | the cut size is taken once before the loop, at a line boundary (earlier appends are complete lines). The cut happens on every raced attempt, the last one included. Only a full-history pass writes escrow during the read; other polls write it after the loop. A pass that fails for another reason keeps its lines, as before; they are unused, since a line counts only if it reproduces an anchored root or a committed range |
| 12.3 regression (`malformed` lost in direct mode) | **closed** | `fin` replaces the reused variable; test added |

## Residuals (none blocks the freeze)

1. **No H, with planted keys (Low).** Without `hub_started_ts`, the window between the restart and B stays open for
   whole-second deletions of rows the restored hub wrote. This needs B to be the DONE poll, that is, keys planted so
   the watermark does not fall. My `test_ATTACK_N1_without_H_...` reproduces it only with planted keys and no H; with
   H the same deletion is flagged (`test_CONTROL_N1_with_H_...`); without planted keys the falling watermark gives B
   at once. The harness always sends H and refuses a changed archive. Suggestion: make H mandatory in the verifier, or
   pre-register that a DONE without H leaves this window.
2. **`post_restart_wm` is checked for shape only (Info).** It could also flag a restored recorder whose keys reach the
   pre-restore maximum in both tables, which is the signature of planted keys.
3. **Early B forced by the hub (Low, R5 class: false accusation only).** Between I and the stop, the hub can delete
   its newest row. The watermark then falls before the restore, so B comes early, and the rows lost by the restore in
   seconds sealed after that B become violations. The deletion itself is erased by the restore. This produces
   violations on the honest restore, never exoneration.
4. **Timing margin (operational).** The harness's worst case from the RESTORE marker to an anchored DONE is about
   300 s: a 30 s lead, a stop of up to 60 s, 45 s for the restart, two container starts of up to 60 s each, issuer
   retries. The limit is 600 s. A late DONE leaves the restore unexcused, which means false violations, not hidden
   ones. The final smoke should confirm the margin, as `e9_prereg.py` says.
5. **N2 under an active adversary (Info).** The hub can make all three reads of a poll race, by checkpointing to an
   empty WAL before each read and committing during it. That poll is then unobservable, which the hub could already
   cause; a poll costs at most three reads.
6. **The stamp's coverage (Info, unchanged since 11.10).** The stamp detects a WAL restart. It does not detect an
   over-backfill, which could happen only if the read lock were lost; the lock rule is what prevents that. The
   coordinator's measurement (quick_check failing in 11 of 18 reads with the lock dropped, 0 of 18 with it held) is
   the evidence for the lock rule.

## Reproduction

- `cd <artifact-root> && python3 -m pytest -q -p no:cacheprovider <scratchpad>/e9review/recheck2/test_recheck2.py`:
  4 passed.
- `python3 -m pytest -q monitor/test_e9.py -k "N1 or N2 or A4_malformed or A4_a_direct"`: 11 passed.
- `<scratchpad>/e9review/recheck2/shipped_suites.txt`: 261 passed.
- Diffs: `<scratchpad>/e9review/recheck2/{monitor,verify,issuer}.diff`.
