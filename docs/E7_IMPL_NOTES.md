# E7 implementation notes: monitor and verifier (2026-10-08)

Sections 1-8 describe the first version; section 9 is the code-review round (E7_CODE_REVIEW.md) and the E7 dry-run fix; section 10 is the re-review round. Later sections supersede earlier ones where they differ.

Scope: E7_DESIGN.md sections "Design" 1-4 and "Verifier", plus the coordinator's record-size constraint from
E7_ANCHOR_NOTES.md. Code only, no paper text. Paths are relative to the repository. Nothing was committed. No container,
image or VM was touched. The anchor daemon, `monitor_wholerow.py` and the attack integrations were not modified.

## 1. Files

| File | Status | sha256 (after) |
|---|---|---|
| `monitor/monitor.py` | modified (was `2eb8f872...`, the working copy with v2 encoding and name map) | `b148dda4...` (after section 10.2; re-review round `af8fd5b7...`; review round `9b0970d7...`; first version `1863ae9d...`) |
| `exp/stages/e7_verify.py` | new: E7 verifier, plus the `late-delays` tool for fixing LATE_BOUND | `98c551b6...` (review round `6764e8e4...`; first version `fa6da9ee...`) |
| `monitor/test_coverage.py` | new: 57 tests (48 after the review round, 26 before it) | `4a0cf6a0...` |
| `monitor/monitor_wholerow.py` | unchanged (`6bd82630...`) | |

The monitor Dockerfile copies only `monitor.py`. E7 therefore needs a NEW image tag (for example `hpr-monitor:e7`). Do not
rebuild `hpr-monitor:1`. The image runs Python 3.12. The tests pass under 3.11 and 3.13, and both files parse as 3.9.

## 2. What changed in monitor.py

All of it is additive. The node-hash encoding v2, the `row` and `closure` schemes, `load()` and `commit()` keep their
output. `commit()` now dispatches through a new `node_digest()`; the golden vectors in `test_node_hash.py` still pass.

1. **Coverage (`HOMEPROV_COVERAGE=1`, the default).** `tick()` calls `tick_coverage()`. With `HOMEPROV_COVERAGE=0`, the
   earlier body runs unchanged. Every poll appends a record (the heartbeat), carrying these fields:
   - `wm`: max(state_id) and max(event_id) of the copy;
   - `through`: `int((now - GRACE_S) // 1)`, the sealing cutoff;
   - `since`: the start of the re-read window (NEW, see section 7);
   - `copy_at`: the time the copy began (NEW; in clock-file mode, the replica's request time);
   - `seq_local`: a persisted poll counter;
   - `coverage: 1`.
   An unobservable poll (fail-closed, or clock file unreadable) appends `evidence_unobservable` with no `sealed` key.
   Before, an unreadable clock file appended nothing.
2. **Stall-proof sealing.**
   - Frozen pending state: at first seal, `{acc, n, sealed_at, seal_seq, wm}` is written to `state["pending"]`. The state
     is saved before the append, so it survives a restart. Later polls never recompute these entries, and they do not
     expire with the re-read window.
   - Re-sent roots and the backlog: a re-sent root carries `sealed_at`, `seal_seq` and `wm`. The heads of polls whose own
     record failed go into `backlog`, so the verifier still sees every poll's wm, through and copy time.
   - Local alarm: every failed or refused append prints a JSON alarm line.
   - Bounded state: `state["anchored"]` is pruned to the re-read window. Before this change it grew forever.
3. **Record size (coordinator's constraint).**
   - Splitting: a poll sends its items (backlog heads first, then frozen roots ordered by sealing poll) in records of at
     most `HOMEPROV_MAX_RECORD_BYTES` (default 1 MiB, 1/16 of the anchor's default limit). The first record is the poll's
     own. The rest go out at once as continuation records with the same poll fields and `"part": 2, 3, ...`.
   - On 413: the monitor halves the size, keeps it in the state (floor 1 KiB) and re-splits the same items in the same
     poll. It does not retry the same record.
   - Limit per poll: at most `HOMEPROV_MAX_PARTS` (64) records. Any remainder stays frozen until the next poll.
4. **409 handling (not in the design).** If one refused root were retried, every later record would be refused. Instead,
   the refused root moves to `state["conflicted"]` and is carried under `conflicted`, which the anchor's first-write-wins
   check does not read. The rest is re-sent in the same poll.
5. **Escrow (`HOMEPROV_ESCROW_DIR`, off by default).** At sealing, the monitor appends one line per sealed second to
   `<dir>/escrow.jsonl`. The line holds:
   - the exact node tuples it folded, in typed JSON (`jt`/`from_jt`: hex BLOBs, `float.hex`);
   - the second's acc and n;
   - `sealed_at`, `seal_seq` and `wm`.
   The file is fsynced. A write error raises an alarm but does not block sealing. On the e_d_clo extract this came to
   about 455 bytes per row.
6. **Stable scheme (`HOMEPROV_SCHEME=stable`, v2 only).** Implemented in `monitor.py` and not in `monitor_wholerow.py`:
   - `verify_all.load_monitor`, e_c's `_load_monitor` and `e7_verify` load `monitor.py` by name with `HOMEPROV_SCHEME`,
     and they assert `M.SCHEME == scheme`. A native scheme therefore runs and verifies through the same loader, with no
     shim.
   - Coverage, the frozen roots and the escrow handle every node shape in one place.
   - `monitor_wholerow.py` is the evaluated whole-row baseline and stays byte-identical.
   Node format: the 7-tuple `(ts, key, content, ctx, par, label, fields)`. The tuple `fields` is the table name, then
   every column from `PRAGMA table_info` as name/value pairs, then `states_meta.entity_id` and
   `state_attributes.shared_attrs` (for states) or `event_types.event_type` and `event_data.shared_data` (for events).
   It reads the same rows as the closure (same joins), so segments and counts are equal (tested). Records carry
   `"stable_exclude": ["states.last_reported_ts"]`.
7. **Cost log.** `HOMEPROV_COST_LOG=<path>` writes one JSON line per poll with copy, load, commit and append times in ms,
   for the cost item of the E7 run.

**Stable exclusion list: `states.last_reported_ts` only.** Sources:
- `exp/out/e_d_whr_floor_preimage_d2.json`, `e_ps_whr_floor_preimage_d2.json` and `e_psr_whr_floor_preimage_d2.json`
  (their `stable_columns_bound` and the embedded script). Restoring this one column reproduced 403/432, 186/203 and
  202/218 of the untouched whole-row failures. No other column was implicated. The remaining cases "cannot be decided
  from the final snapshot".
- The HA recorder source (`core.py` `_process_state_changed_event_into_session` → `update_pending_last_reported` →
  `_commit_event_session` `update(States)`, read in 2026.2.3). It writes the previous row's `last_reported_ts` in place
  when the entity's next state is recorded.
- Also seen: purge rewrites `old_state_id` in place (`queries.py` `disconnect_states_rows`), only next to the retention
  cutoff. The closure commits that column too.

## 3. Record format (examples from the stall test, `T0 = 1790280000`)

A normal record that seals rows:
```json
{"copy_at": 1790280005.0, "coverage": 1, "encoding": "v2", "observer": "external-monitor", "scheme": "closure",
 "sealed": {"second": {"1790280001": {"acc": "a3e2e414...1c90", "n": 2}, "...": "..."}},
 "seq_local": 1, "since": 1790276400.0, "through": 1790280005, "ts": 1790280005.0, "wm": {"events": 1, "states": 3}}
```

The first record after a 4-poll outage. It carries the frozen root of a second sealed during the outage and the heads of
the failed polls:
```json
{"backlog": [{"copy_at": 1790280010.0, "seq_local": 2, "since": 1790276400.0, "through": 1790280010,
              "ts": 1790280010.0, "wm": {"events": 2, "states": 4}}, "... seq_local 3, 4, 5 ..."],
 "copy_at": 1790280030.0, "coverage": 1, "encoding": "v2", "observer": "external-monitor", "scheme": "closure",
 "sealed": {"second": {"1790280006": {"acc": "90fc726a...79d3", "n": 2, "seal_seq": 2, "sealed_at": 1790280010.0,
                                      "wm": {"events": 2, "states": 4}}}},
 "seq_local": 6, "since": 1790276400.0, "through": 1790280030, "ts": 1790280030.0, "wm": {"events": 1, "states": 4}}
```

A heartbeat is the same record with `"sealed": {}`. A continuation record adds `"part": 2`. Every record that re-sends a
root names that root's own `sealed_at`.

## 4. Verifier: `exp/stages/e7_verify.py`

```
e7_verify.py verify --chain C --db R --late-bound S --gap-s S [--snapshot-at T] [--window T0 T1] [--scheme ...]
                    [--escrow F] [--trials RESULT.json ...] [--restore-out DB] [--out F]
e7_verify.py late-delays --chain C --db R [--window T0 T1] [--snapshot-at T]
```

- **Loading.** The verifier loads the shipped monitor the way `e6_namemap.py` does (`wholerow` through
  `monitor_wholerow.py`), and works on a private checkpointed copy of the recorder.
- **Records without coverage fields** use the existing rule: verify_window, attributable iff delta_n <= 0, and records
  without `scheme` are row. On the e_d_clo extract this reproduces verify_all exactly: PU 90/90, PI 89 + 1 ambiguous,
  floor 1/560 under `touched_segments`.
- **Step 1.** The root over the current rows with key <= the sealing poll's wm. A mismatch is attributable. Rows with a
  larger key are late rows.
- **Step 2.**
  - First cover of a segment: the first known poll with `since <= start` and `end <= through`. If the segment had no
    root, or its root came from a later poll, it was empty at that first cover.
  - In that case, a row with key <= wm(first cover) counts as `present_when_sealed_empty`, which is attributable.
  - Late rows: their lower bound is the maximum `copy_at` over polls with wm < key. If that bound minus the row's ts
    exceeds `LATE_BOUND`, the row is attributable; otherwise it is a benign late row and is listed.
  - This works at every granularity.
- **Step 3.** Stalls: consecutive non-continuation coverage records more than `GAP_S` apart, or a `seq_local` jump. Each
  stall reports its kind (`anchor_unreachable` / `polls_unrecorded` / `monitor_silent` / `monitor_restarted`), the polls
  in the backlog, and the segments sealed inside it with their verdicts.
- **Step 4.** Escrow: the verifier takes the escrow line whose recomputed root equals both its own acc and the anchored
  root. It reports changed fields (original next to current), removed rows and added rows. `--restore-out` writes a copy
  with the escrowed closure fields restored, and checks that its roots reproduce. Rendering the displayed cause from that
  copy needs HA's logbook processor, which this script does not run.
- **Step 5.** Benign floor: untouched violated seconds and untouched attributable rows, each listed, next to the
  existing-rule count.
- **Scoring hooks.** `score_trials(res, trials)` scores each trial's one-second segment (`_detection.second.segment`,
  else the judged/forged/before row, as e_c_write_time.py does). It sets `t["_e7"]` and gives per-arm detected counts
  with Clopper-Pearson intervals, next to the existing rule's flagged/attributable/ambiguous.
- **Parameters.** `--late-bound` and `--gap-s` are required, have no default, and are recorded in `params`.

## 5. Tests and checks (all run 2026-10-08)

**`pytest monitor/ testbed/anchord/`: 88 passed.** That is 26 new tests, 12 in test_node_hash.py and 50 in
testbed/anchord (the hardening agent's tests included). The new tests cover these cases:
- plain edit;
- edit + 9 and + 20 rows inserted into the edited second (existing rule: ambiguous, delta_n 8 / 19; E7: attributable);
- rows backdated into an empty second, minute and hour (attributable at each granularity);
- benign late rows 0.1 s and 1.05 s late (not attributed; the existing rule calls one ambiguous);
- forged low key into a key gap, into a sealed second and into an empty second;
- anchor down for 4 polls while a sealed row is laundered:
  - after the anchor returns: detected, stall `anchor_unreachable` (4 polls in the backlog);
  - with `HOMEPROV_COVERAGE=0`: missed;
- frozen roots that outlive a 2-hour re-read window;
- restart with the state file kept;
- state loss, reported as a restart;
- escrow round trip:
  - the root recomputed from the escrow equals the anchored root;
  - recovery lists the original user_id and parent_id and the removed service call;
  - the restored copy reproduces the roots;
- 409, two ways: quarantined and re-sent in the same poll; when the conflicting root came from another appender, the
  monitor's own root is the one checked;
- **backlog larger than the anchor limit:**
  - 406 frozen roots and 81 heads against an 8000-byte anchor;
  - 8 × 413 halved the record budget to 4096 bytes; the backlog went out in 24 records, each under the 8000-byte limit;
  - all anchored in one poll, with the original roots, oldest sealing poll first across records;
  - one stall reported;
- a bound of 3 parts per poll (the rest follows at the next polls);
- clock-file mode;
- stable scheme:
  - in-place `last_reported_ts` gives no flag;
  - `origin_idx` is flagged by stable and not by closure;
  - a closure field is flagged by both;
  - stable+v1 refused;
- existing-rule fallback;
- `late-delays` brackets a late row exactly;
- `HOMEPROV_COVERAGE=0` gives byte-identical records and state file (golden digest computed from the pre-E7 file);
- the evaluated e_psr_clo chain: same violations as `verify_all.verify_window`, PSR 90/90.

Extra checks run from my scratchpad (not saved as files):
- `HOMEPROV_COVERAGE=0` gives byte-identical records and state against the pre-E7 file on 12 real-extract cases (3 runs
  × 4 clock times) and for `monitor_wholerow.py`.
- `reproduce/verify_all.py`: all 10 runs MATCH, with numbers identical to before.
- Against the hardened `anchord_linked.py` over loopback HTTP with a key:
  - unsigned appends get 401;
  - a 409 is quarantined;
  - with `HOMEPROV_ANCHOR_MAX_BODY=8192`, an 80-poll backlog took 7 × 413 and 11 parts, all anchored;
  - chainverify reports linked, ok.
- A replay of the e_d_clo rows through a coverage monitor, under a 0.9 s commit-lag model:
  - 0 E7 violations, against 29 seconds failing under the existing rule;
  - 986 benign late rows, with the largest lower bound 0.899 s;
  - this is a code check, not a measurement.
- Per-poll cost on that extract: coverage costs about the same as legacy (median about 86-90 ms, dominated by the copy;
  indicative only).

## 6. Evidence for LATE_BOUND

Saved as `exp/out/e7_late_delays_prior.json` (sha256 `2d7b74c8...8d39`): the per-run outputs of `e7_verify.py late-delays`, with input paths and sha256, the commit-order check, and the script hashes. No LATE_BOUND is chosen there. The late rows are those whose removal reproduces the anchored root (the late-row hypothesis). Their delay is bracketed as follows:
- lower bound: sealing record ts − row ts;
- upper bound: the time of the last record before one provably holding the row.

Every late-row segment of every run is explained by late rows. Maximum lower / upper bound per run, in seconds:

| Run | Late rows | Max lower / upper (s) |
|---|---|---|
| e_d_clo | 9 | 0.934 / 0.934 |
| e_c_clo | 2 | 0.456 / 0.456 |
| e_ps_clo | 9 | 0.258 / 5.781 |
| e_psr_clo | 2 | 0.599 / 5.991 |
| e_c_auth | 14 | 0.788 / 0.788 |
| e_ps_auth | 4 | 0.809 / 0.809 |
| e3_g0_clo | 9 | 3.926 / 3.926 |
| e3_g2_clo | 0 | none |
| e1_psr_clo | 4 | 0.584 / 0.584 |

The e1 and e3 runs used the saved copies under `../HOMEPROV-P13-exp/`. Their sha256 match the values recorded in `e3_grace_sealing.json` and `e1_psr_clo_two_host.json`.

In addition, none of the 10 shipped extracts has a row whose timestamp is older than that of an earlier-keyed row of the
same table. This supports the commit-order key assumption.

## 7. What I found wrong or missing in the design

1. **Step 2's insertion bound.**
   - The design bounds insertion by `t(R_a)`, but a record's `ts` is taken after the copy, so the sound bound is the copy
     start. Hence the new `copy_at`.
   - The design uses "the last record with wm < key". It should be the maximum copy time over all known polls with
     wm < key, including backlog heads, because wm can decrease. It did in the tests: deleting the newest event lowered
     `wm.events`, and SQLite reuses that key.
2. **"Sealed as empty" needs `since`.** A monitor restarted after a long downtime has a `through` far past seconds it
   never read. Without `since`, rows from the downtime would be falsely attributed.
3. **Late segments.** The monitor (old and new) itself seals a segment that appears after its second was sealed empty.
   "No segment in any record" is therefore wrong. The verifier instead compares the segment's seal poll with its first
   cover.
4. **Missing cases.** The design covered neither 409 (one conflict blocks every later record) nor 413. Both are handled
   now (section 2).
5. **Detection window for backdating.** A backdated row is attributable only once a poll has missed it for longer than
   LATE_BOUND. Backdating by less than about LATE_BOUND plus one poll period is a benign late row. The paper should state
   that window if it claims backdating detection.
6. **Recovery.** E7 needs a rendering step: HA's logbook processor in a throwaway container, run on the
   `--restore-out` copy. `e7_verify` produces and checks the copy but does not render.

## 8. Open issues for the lead

- **LATE_BOUND and GAP_S** have to be fixed before the run.
  - LATE_BOUND: section 6 gives the evidence. In a two-host placement it must also cover the clock offset between hub
    and monitor, because `copy_at` is on the monitor's clock and the row ts on the hub's.
  - GAP_S: 3 × period (15 s) will report `monitor_silent` stalls in normal operation. In `e3_grace_sealing.json`, e3_g0's
    sealing delay has a p90 of 20.633 s and a max of 66.07 s.
- **The E7 stall arm.** The hardened anchor no longer stalls under slow connections (E7_ANCHOR_NOTES §5). To exercise the
  frozen roots, run that arm against `anchord_r12.py` or block the anchor at the network level.
- **Chain growth.** With one record per poll, a 5 s period gives 17,280 records a day. The anchor counts or reads the
  whole chain on every append. That is fine for E7 but not for long deployments.
- **Risks to the stable baseline.**
  - A recorder migrated from an older schema can run legacy-column cleanups that rewrite stable columns in place. The E7
    run's benign floor will show it.
  - The 28/17/15 undecided whole-row cases cannot exclude another column. Only the live run can.
- **e6 self-test.** `e6_namemap.py selftest` compares default records byte for byte with a pre-E6 file. Run it with
  `HOMEPROV_COVERAGE=0` exported; its env_off list does not clear that variable.
- **Escrow placement.** The escrow is written next to the monitor. For E7, mount `HOMEPROV_ESCROW_DIR` on a volume the
  hub never mounts.


## 9. Code-review round (E7_CODE_REVIEW.md) and the dry-run stall fix

All findings were reproduced first. Each one is now a test in `monitor/test_coverage.py`; there are 22 new tests, 48 in
total.

**Proof that the tests fail on the previous code.** I ran the 22 new tests under Python 3.11 against the bytecode of my
previous `monitor.py` and `e7_verify.py`. The bytecode comes from the 3.11 caches written at 11:18 from the
pre-review sources, loaded through stub modules. Results:
- 20 fail, each for the defect it targets.
- The 2 that pass are expected to pass: the fresh-key control, which was detected before, and a regression guard for
  the review's `no_since` mutant.

**Regression checks:**
- `pytest monitor/ testbed/anchord/`: 110 passed (48 + 12 node-hash + 50 anchor).
- `HOMEPROV_COVERAGE=0` is byte-identical to the pre-E7 file. The golden test now finds that file by default and checks
  its sha256. Identity also holds on the 12 real-extract cases and for `monitor_wholerow.py`.
- `reproduce/verify_all.py`: all 10 runs MATCH, with numbers and floats identical to before.

**Real-data checks:**
- Replay of e_d_clo's real rows (0.9 s commit lag): the keylog checked 1,939 ranges and found 0 violations; 0 flagged.
- Per-poll cost on the extract: still a median of about 91 ms (copy-dominated). The median record grows from 471 to 638
  bytes.

### 9.1 B1 (blocker): the keylog

**What it commits.**
- At every observable poll, per table (states, events), the key range `(previous high-water, wm]`, i.e. the rows the
  monitor sees for the first time.
- The rows are read from the table itself with LEFT JOINs. An unjoinable row is therefore committed, and so is one with
  a malformed or far-future timestamp.
- Each row is committed in key order as the v2 typed encoding (tag `keylog`) of `state_id`, `state`,
  `last_updated_ts` (raw, unrounded), `last_changed_ts`, `old_state_id`, the three context BLOBs and the joined
  `states_meta.entity_id`.
- For events: `event_id`, `time_fired_ts` (raw), the three context BLOBs, `event_types.event_type` and
  `event_data.shared_data`.
- Under the stable scheme: every stable column plus the joined values, including `shared_attrs`.
- The rows are folded like a segment into `{from, to, n, acc}`, plus `rows: [[key-from, 8 hex of the row hash], ...]`
  for localisation. Security comes from the 256-bit fold; a prefix collision only loses the localisation, and the
  verifier then flags every row of the range.
- A range is split into sub-ranges of at most 128 rows, which together cover every key. A key gap is committed as
  empty, so a row inserted into it later changes the range.
- The high-water only rises, so a falling wm never reopens a range.
- `last_reported_ts` is not committed, because the recorder rewrites it in place.
- The first poll of a monitor starts above the largest key of an already-sealed row (timestamp < through), so every row
  not yet sealed is bound at that first observation.
- The ranges ride in the record, are split like the roots, and if the append fails they are stored in the backlog head,
  as pieces when large. They are therefore stall-proof.

Example record:
```json
{"copy_at": 1790280005.0, "coverage": 1, "encoding": "v2",
 "keylog": {"events": [{"acc": "7b33ee60...9c1d", "from": 1, "n": 1, "rows": [[1, "dda140a9"]], "to": 2}],
            "states": [{"acc": "5ea95d28...5a05", "from": 3, "n": 1, "rows": [[1, "58ec1c7f"]], "to": 4}]},
 "n_sealed": {"hour": 0, "minute": 0, "second": 1}, "observer": "external-monitor", "scheme": "closure",
 "sealed": {"second": {"1790280004": {"acc": "a86cf76a...7ba8", "n": 2}}}, "seq_local": 2, "since": 1790276400.0,
 "through": 1790280005, "ts": 1790280005.0, "wm": {"events": 2, "states": 4}}
```

**The check.**
- `check_keylog` recomputes every range over the current rows. A mismatch is attributable, localised to its changed,
  added or removed rows, and their current seconds are flagged.
- It also reports ranges that never reached the chain (`uncommitted_key_ranges`).
- All three variants (parked, invisible, key gap) are attributable and localised to the forged row.
- It stays quiet on rows up to 0.95 s late every second and on in-place `last_reported_ts` rewrites, under both the
  closure and the stable scheme.
- `HOMEPROV_KEYLOG=0` turns it off, for comparison.

**What the keylog adds to the guarantee.** For the committed fields, a row is protected from its first observation, not
only from its segment's sealing. The guarantee paragraph is unchanged; this is for the lead to decide.

**What remains undetectable:**
- A row inserted and changed between two polls, which the monitor never sees in its first form: the pre-observation
  window of one poll period.
- A row inserted with a timestamp at most about LATE_BOUND before the copy that first holds it. It is a benign late row,
  so a backdating of less than about LATE_BOUND plus one poll period passes.
- A row written with false content from the start: write-time forgery, as before.
- Rows that existed before the monitor's first poll and whose segments were already sealed or older than the re-read
  window, as before.
- Columns outside the committed set, e.g. `attributes_id` under the closure scheme.
- Rows of a key range whose keylog never reached the chain (listed as `uncommitted_key_ranges`).

**Benign causes that the keylog does flag:**
- the nightly purge, which deletes old rows and rewrites `old_state_id` next to the cutoff (only for ranges older than
  keep_days);
- an `entity_id` rename (`states_meta`), which the closure roots flag as well;
- `recorder.purge_entities` deleting an entity's newest rows.
None of these occurs within an E7 run window.

### 9.2 Major findings
- **M1.**
  - An attributable minute or hour violation is localised to the seconds of its late rows, unless a flagged second
    inside it already explains it. In the dry runs, a laundered second's minute otherwise flagged a benign late row of
    the same minute; this is tested.
  - It reaches `flagged_seconds`, `score_trials` (`e7_detected`) and `benign_floor` (new `minute`/`hour` blocks and
    `untouched_flagged_seconds`).
  - New output keys: `flagged_segments`; per trial `detected_second_unit`, `coarse_segments_attributable` and
    `detected_any_granularity`. The any-granularity count marks every trial in a coarse segment, so read it only with
    one trial per segment.
- **M2.**
  - With coverage on, the monitor folds only finite numeric timestamps (`typeof IN ('real','integer') AND abs < 1e12`).
    The SQL with `HOMEPROV_COVERAGE=0` is unchanged.
  - Malformed rows are committed by the keylog and named in the record (`"malformed"`, capped at 50 keys per table),
    with an alarm.
  - Any exception while loading makes the poll `evidence_unobservable` with reason `load_failed`; polling continues.
  - The verifier lists malformed rows (`malformed_rows`) and loads from a copy without them, so `wholerow` is safe as
    well.
- **M3.**
  - Every head carries `n_sealed` (segments frozen by that poll, per granularity).
  - The verifier infers "empty at first cover" only when it holds all of that poll's roots; otherwise the segment is
    reported in `root_unknown_segments` and not attributed.
  - Coverage roots are dated by their sealing poll, so roots sealed before `--snapshot-at` and anchored after it are
    used.
- **M4.**
  - Unobservable runs are reported as intervals of kind `evidence_unobservable`.
  - Every interval lists `seconds_sealed_after_gap`, the seconds sealed from a copy taken after it, with the non-empty
    ones named.
  - New `observation_gaps` output.
  - The monitor now re-sends frozen roots during unobservable polls, in a continuation record that is not itself marked
    unobservable.
  - The reviewer's own M4 scenario never actually laundered: the UPDATE went into the stray `-wal` and vanished when it
    was deleted. The new test launders after removing it; the keylog catches that laundering.

### 9.3 Dry-run stall listing (coordinator, artifacts in HOMEPROV-P13-exp/e7/dryrun_2026-10-08)

**Cause.** In both dry runs, three appends timed out at the monitor but the anchor committed them late anyway. In dry 1 they
were committed out of poll order (seq_local 73 before 72).
- The old epoch rule read the lower counter as a restart (spurious `monitor_restarted`).
- The old stall rule looked at record spacing in chain order, so polls about 15 s apart hid a 50 s outage (dry 2).

**Fix.**
- A lower counter starts a new epoch only when its time is later than every poll seen.
- Intervals are built on the poll timeline. A poll counts as affected when its head is in a backlog (the monitor saw the
  append fail), and each interval reports `late_committed_polls` and `max_commit_delay_s`.
- Re-verified from the artifacts:
  - dry 1: one `anchor_unreachable` interval of 50.463 s (3 polls, all committed late, max delay 29.47 s) and no
    restart;
  - dry 2: one interval of 50.286 s (3 polls, max delay 44.838 s).
- In both, `flagged_seconds` is identical to the earlier output. Benign gaps over GAP_S are listed as intervals with
  their cause, never as detections (tested).
- The scorer's keys (`stalls[].from_ts/to_ts/kind/seconds_sealed_during`, `arms`, `benign_floor`) are unchanged. New
  keys were only added: `causes`, `late_committed_polls`, `max_commit_delay_s`, `unobservable_polls`, `reasons`,
  `seconds_sealed_after_gap`.

### 9.4 Minor findings

**Fixed:**
- m1: a reset or broken pipe on a body over 4 KiB is taken as a 413 for that poll. The next size is half the refused
  body; a 413 is also remembered in the state.
- m2: the copy is repeated while the WAL header salts change; if they never settle, the poll fails closed with
  `copy_raced`.
- m4: the golden test compares with the pre-E7 file by default and checks its sha256.
- m5: segments are indexed by sealing poll.
- m6: `HOMEPROV_MAX_PARTS`, `HOMEPROV_MAX_RECORD_BYTES` and `HOMEPROV_KEYLOG` are validated, and the tests clear them.
- m10 (partly): keylog items are at most about 2.5 KB, so items stay small.

**Open:**
- m3: the whole-row entry point now runs with coverage by default. Set `HOMEPROV_COVERAGE=0` to reproduce the evaluated
  whole-row runs. I did not touch `monitor_wholerow.py` (its comment at line 29 is stale).
- m7: "attributable backdated insertion" means the history was altered at that row, not that the event was fabricated.
- m8: an HA restart or a recorder backlog inside the window can exceed LATE_BOUND. Log restarts and report those rows
  separately.
- m9: `restore()` writes back only the closure columns and keeps rows added into seconds that were sealed empty, so the
  restored copy is not the original database.
- m10: a single frozen root or head piece larger than an anchor limit below about 4 KB can still not be sent.
- A 413 lowers the remembered budget for good; nothing restores it.


## 10. Re-review round (E7_CODE_REVIEW.md "Re-review": R1-R4)

Each attack of the re-review (`e7review/test_rereview.py` A1, A2, A3, A3b and A5) is now a test in
`monitor/test_coverage.py`. There are 7 new tests, 55 in total.

**Proof that the tests fail on the re-reviewed code.** I reconstructed that code exactly by reverting this round's
edits, and the sha256 of both files match the re-reviewed versions (monitor `9b0970d7...`, verifier `6764e8e4...`).
- All 7 new tests fail on it.
- Of the earlier 48 tests, only the three B1 parametrisations fail there, because they now assert the new `likely` key.
- The five re-review attack tests (A1, A2, A3, A3b, A5) now fail, i.e. the attacks are caught. Its positive checks and
  A4 and A6 still pass.

**Regression checks:**
- `pytest monitor/ testbed/anchord/`: 117 passed (55 + 12 + 50).
- `HOMEPROV_COVERAGE=0` is byte-identical to the pre-E7 file: golden test, 12 real-extract cases, and the whole-row
  entry point.
- `reproduce/verify_all.py`: all 10 runs MATCH, identical numbers and floats.
- E7 dry runs: flagged seconds and stall intervals unchanged.
- Replay of real rows: 1,939 keylog ranges checked, 0 violations, 0 flagged.
- Per-poll cost: median about 89 ms on the extract, as before.

**R1 (verifier). The prefixes only rank.**
- When a keylog range fails, every row of it is a suspect. That means every current row of the range, plus every row
  it held when committed.
- Every second those rows sit in now, or sat in when first observed, is flagged (`seconds` per violation, merged into
  `flagged_seconds`).
- `likely` (changed, added, removed by prefix) only ranks them. The likely rows are attributable rows. The other current
  rows are listed as `keylog_suspect_rows` (new key) and are not called attributable.
- A failed range holds at most 128 rows, first observed in the same poll.
- The benign floor names untouched seconds that are flagged only through a range that also holds a touched second
  (`via_a_key_range_that_holds_a_touched_second`): these are neighbours of an attack, not benign failures.
- Test: a birthday collision plus a decoy row still flags T0+3.

**R2 (monitor and verifier). Lenient text.**
- With coverage on, every connection the monitor opens (copy validation, watermark, keylog, `load`, `load_stable`)
  decodes TEXT with `surrogateescape`. The verifier does the same on all its connections.
- Valid UTF-8 decodes to the same str as before, so every existing hash is unchanged (verify_all identical).
- A byte that is not UTF-8 becomes a lone surrogate. `tlv()` encodes it with `surrogatepass`, so the commitment is a
  deterministic, injective function of the raw bytes.
- The record names such rows (`"invalid_text": {table: {n, keys}}`, with an alarm). The verifier lists them
  (`invalid_text_rows`, new key).
- `HOMEPROV_COVERAGE=0` keeps the strict default.
- Test: sealing continues and the verifier answers; changing the raw bytes later is detected.

**R3 (monitor and verifier). The first-observed second.**
- Every keylog row entry is `[key offset, 8-hex prefix, first-observed second]`. The second is null if the timestamp
  was malformed when first observed.
- The verifier flags that second for every row of a failed range.
- Test: a genuine unlock observed in its open second and then made malformed, deleted (with and without key reuse) or
  re-timed flags its own second.
- Records from earlier monitors have no third element. For them only the current seconds are known.

**R4 (verifier). The key hole after a state loss is reported.**
- When a monitor restarts without its state, the keys between the last range of the previous epoch and the new epoch's
  first range are listed in `uncommitted_key_ranges` with `why: monitor_restarted_without_its_state`.
- Ranges whose keylog never reached the chain carry `why: keylog_not_on_chain`.

R5 (epoch inference with a late commit across a state-loss restart, or a backward clock step across one) is
unchanged and open. It needs a state loss.

### What is still undetectable (supersedes §9.1)
- **The pre-observation window.** A row written and changed (or deleted) between two polls is never seen in its first
  form; that is one poll period (5 s).
- **Benign-looking lateness.** A row whose timestamp, when first observed, is at most about LATE_BOUND (30 s) before
  the last copy that lacked it is a benign late row. Backdating by less than about LATE_BOUND plus one poll period
  passes.
- **Write-time forgery.** A row written with false content from the start.
- **Rows the monitor never saw.** Rows that existed before the monitor's first poll whose segments were already sealed
  or older than the re-read window. Also rows in key ranges listed in `uncommitted_key_ranges` (a keylog that never
  reached the chain, or a restart without state): these are reported, and bound only by the segment roots.
- **Columns outside the committed set**, e.g. `attributes_id` and `shared_attrs` under the closure scheme.
- **Hub-written values the monitor cannot read** never stop sealing any more. Rows with malformed timestamps or non-UTF-8
  text are committed and reported, not hidden.
- **Benign causes that are flagged** (§9.1): the nightly purge, an `entity_id` rename, `recorder.purge_entities`.

### 10.1 Benign floor: a trial's own deletions (E7 smoke run)

**Defect.** In the smoke run, the floor listed e:502043, e:502176 and e:502186 among the untouched attributable rows.
These are the laundering trials' own deletions of the author's service calls, first observed in each trial's
`edited_second`. A removed row has no current second, so the floor did not see it as touched.

**Fix.**
- A keylog row (removed or changed) counts as touched when its current second or its `first_observed_second` is a
  touched second. That field is now also set on attributable rows.
- A trial's `deleted_event_ids` and `deleted_event_seconds` (optional report keys) count as touched rows and seconds.
- `keylog_violations_untouched` uses every second a failed range's rows sit in or sat in.
- The trial's own evidence now includes rows by their first-observed second, plus the new
  `deleted_event_rows_attributable`.
- The spillover list `via_a_key_range_that_holds_a_touched_second` is unchanged.
- Test: `test_floor_a_trials_own_deleted_events_are_touched_not_benign`.

**Smoke run re-scored into scratch, not exp/out.**
- `untouched_attributable_rows`: 3 → 0.
- `keylog_violations_untouched`: 2 → 0.
- Unchanged: `violated` 0/180, `untouched_flagged_seconds` 7 (all 7 via a range holding a touched second), minute 0,
  per-arm `e7_detected`, and `flagged_seconds`.

### 10.2 Escrow of first-observation tuples (E7 main run: recovery 119 of 120)

**Defect.** The one miss, porch INS-L trial 4, row s:878801, reached the recorder after its second was sealed. No
sealed-segment escrow line held it, although the keylog had committed it at first sight (poll 65) and detected the
edit.

**Monitor.** With `HOMEPROV_ESCROW_DIR` set and the keylog on, each poll also appends one escrow line per committed
keylog sub-range:
```json
{"kind": "keylog", "seq_local", "poll_ts", "table", "from", "to", "n", "acc", "rows": [[key, typed field tuple], ...]}
```
The field tuples are exactly what the keylog hash covers.

**Verifier.**
- A keylog line is used only if its tuples re-fold to its own acc and count, and a poll on the chain committed exactly
  that sub-range (`keylog_lines_verified` / `keylog_lines_rejected`).
- For each failed range, `recovery.keylog` lists the original fields of changed and removed rows, and the rows added
  later.
- `--restore-out` writes changed and removed rows back from their first-observation tuple, and deletes added rows,
  whenever no verified sealed-segment tuple holds the row (a segment tuple takes precedence). Where several lines cover
  a range, the earliest is used.
- Every restored range must reproduce its keylog commitment (`keylog_range_reproduced`).

**Test.** `test_escrow_restores_a_late_row_from_its_first_observation` fails on the previous code and passes now.

**The E7 main run's saved artifacts cannot support it.** Their escrow has 2,683 lines and no keylog line. Re-run
offline into scratch, the failed range (878800, 878804] of poll 65 shows `escrow: absent`, and s:878801 stays without
its author in the restored copy, as in the run's own `restored_closure.db`. Only a run with the new monitor carries the
tuples.

## 11. E8 (E8_DESIGN.md A2 and A4): record signatures and tagged replies

**Files.**

| File | Change |
|---|---|
| `monitor/monitor.py` | Signing and reply-tag check (sha256 `06cee7e4...`). |
| `exp/stages/e7_verify.py` | `--sign-pubkey`, new output key `signatures` (`69d528e8...`). |
| `reproduce/verify_all.py` | Optional `--sign-pubkey` (`674dc865...`). Without it, the report rows are unchanged; with it, each row gains `signatures`. |
| `monitor/requirements-sign.txt` | New: `cryptography==46.0.3`, `cffi==2.1.1`, `pycparser==3.1`. |
| `monitor/Dockerfile.sign` | New: python:3.12-slim, pip install of the requirements file, then `monitor.py`. |
| `monitor/test_coverage.py` | 67 tests (`81185774...`). |

The original `monitor/Dockerfile` is untouched.

### A2: signatures
- `HOMEPROV_SIGN_KEY` is the path of an Ed25519 private key, PKCS#8 PEM, kept only on the monitor host.
  `cryptography` is imported only when it is set.
- Every record, in both the coverage and the earlier tick paths, gains these fields:
  - `sig_alg`: `"ed25519"`;
  - `sig_fp`: SHA-256 of the raw 32-byte public key, in hex;
  - `sig`: 128 hex characters, a detached signature over `b"HOMEPROV-record-sig-v1\0"` followed by the record's
    sort_keys JSON without `sig`.
- The HMAC then tags the bytes including the signature. The anchor's parse and re-serialisation reproduces the signed
  bytes, which was tested through the anchor agent's current daemon over loopback.
- Unset, records are unchanged. `HOMEPROV_COVERAGE=0` is byte-identical (golden test, 12 real extracts, and the
  whole-row entry point).
- The verifier checks every monitor record against the published public key (PEM SubjectPublicKeyInfo):
  - It reports `signed_ok`, `unsigned`, `bad_signature` and `wrong_key` (by chain seq).
  - Bad or foreign records are left out of verification.
  - Unsigned records verify as before. All ten evaluated runs are unsigned and verify unchanged.

### A4: tagged replies
- `HOMEPROV_REPLY_TAGS`:
  - `1` requires a valid `X-HP-Reply-Auth` on every reply.
  - `auto` (the default) requires it once a validly tagged reply has been seen from the anchor. This is remembered in
    the state as `reply_tags_seen`, so older anchors still work.
  - `0` never checks.
- The tag bytes are the anchor's: `HMAC(append key, b"homeprov-anchor-reply-v1\n" + request X-HP-Auth + b"\n" + status
  + b"\n" + body)`. A test checks them against `testbed/anchord/anchord.py` `reply_tag()`.
- An untagged or wrongly tagged reply, whether a success or a refusal, is a failed append:
  - the frozen roots are re-sent;
  - a forged 409 quarantines nothing;
  - a forged 413 does not shrink the records.

**Tests.** 10 new E8 tests: signature round trip, a record altered after signing (it verifies without the key; with the
key it is `bad_signature` and excluded), a record signed under another key (`wrong_key`), unsigned records verify as
before, spoofed replies (untagged ok, wrongly tagged ok, untagged 409), the auto mode, an anchor that does not tag, and
the byte agreement with the anchor.

| Suite | Result |
|---|---|
| `monitor/` | 79 passed |
| `testbed/anchord/` | 63 passed, 1 failed: `test_head_witness_has_the_same_limits` |
| E8 tests with the pinned cryptography 46.0.3 (scratch venv) | 10 passed |
| Full suite with the system Python's cryptography 43.0.0 | passes |

The anchord failure is in the anchor agent's in-progress A1 work (headwitness MAX_BODY is now 64 MiB; the older test
expects 64 KiB). I did not touch testbed/anchord.

**What the E8 run script must set:**
- Build the monitor image from `monitor/Dockerfile.sign` under a NEW tag.
- Mount the private key read-only from the monitor host and set `HOMEPROV_SIGN_KEY` to its path in the container.
  Publish the public key PEM and its fingerprint (`monitor.SIGN_FP`) in the run log.
- Set `HOMEPROV_REPLY_TAGS=1` with a tagging anchor: `auto` trusts the first contact.
- Pass `--sign-pubkey <public key PEM>` to `e7_verify.py` (and to `verify_all.py` if used).

Key generation:
```
python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; \
from cryptography.hazmat.primitives import serialization as s; k=K.generate(); \
open('mon.pem','wb').write(k.private_bytes(s.Encoding.PEM,s.PrivateFormat.PKCS8,s.NoEncryption())); \
open('mon.pub.pem','wb').write(k.public_key().public_bytes(s.Encoding.PEM,s.PublicFormat.SubjectPublicKeyInfo))"
```

**Also changed.** The golden byte-identity test now finds the pre-E7 file by its sha256: the artifact-prep copy had
been refreshed with a newer monitor. The verifier no longer fails on an interval at the very start of a chain (found by
the altered-record test).

### 11.1 E8 review (BE8, ME8, mE8a)

**Files after this round.** `exp/stages/e7_verify.py` `7e036386...`, `monitor/monitor.py` `3e479ae0...`,
`reproduce/verify_all.py` `bd979ae8...`, `monitor/test_coverage.py` `84d5029d...` (70 tests).

**BE8 (verifier).**
- With `--sign-pubkey`, only records whose signature verifies under that key are used, for roots, keylog, coverage and
  heads.
- Unsigned, foreign-key and badly signed records are listed and excluded:
  - new keys `unsigned_excluded` and `allow_unsigned`;
  - `excluded_from_verification` now includes unsigned records.
- `--allow-unsigned` (in `e7_verify.py` and `verify_all.py`) keeps unsigned records, for chains written before
  signatures existed. Without a key, nothing changes.
- An excluded record leaves a missing poll (see ME8).

**ME8 (verifier).**
- A poll the monitor's own sequence skips, with no backlog head for it, is a missing poll: a dropped or excluded record.
- The seconds first covered by the next known poll are then `root_unknown` (`why:
  a_poll_before_its_first_cover_is_missing_from_the_chain`) and never attributed. Its key range is listed as
  uncommitted, and its interval is reported as `polls_unrecorded`.

**mE8a (monitor).**
- A 413 is remembered only down to a floor of 64 KiB (`REMEMBERED_RECORD_BYTES_FLOOR`). Below it, the smaller record
  size holds for the current poll only.
- A host that obtains a validly tagged 413 for the monitor's request tag can therefore cost extra requests in one poll,
  but cannot shrink the records for good.
- It can never produce an "ok", so frozen roots are safe.

**Tests (4, all failing on the pre-fix code):**
- the unsigned substitute record (excluded; its seconds unknown; the gap reported);
- a dropped record (no attribution; the seconds unknown);
- a tagged 413 (the remembered size stays at the floor);
- the unsigned-records test (strict versus `--allow-unsigned`).

**Results:**

| Check | Result |
|---|---|
| `monitor/` | 82 passed |
| `testbed/anchord/` | 64 passed |
| E8 tests with cryptography 46.0.3 | 13 passed |
| `HOMEPROV_COVERAGE=0` | byte-identical |
| `verify_all.py`, default and with `--sign-pubkey --allow-unsigned` | ten runs unchanged |
| E7 main run re-verified | flagged seconds unchanged (523), 0 unknown |

**Still open: mE8c.** A non-Python third party must reproduce Python's `json.dumps` conventions to rebuild the signed
bytes. Specify them in the artifact, or move to RFC 8785.
