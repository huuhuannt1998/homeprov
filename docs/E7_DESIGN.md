# E7 design: sealed coverage by row watermark, stall-proof sealing, escrow, stable-columns baseline

Written 2026-10-08 by the lead. PI approval 2026-10-08: "Approve E7 in full" and "Include in E7" (escrow).
Read AGENT_BRIEF.md section 2 first; its hard rules apply (numbers only from result files, attack integrations never
released, do not touch `hpr-*` / `e2-*` containers before 2026-10-09 05:00 UTC, no commits, no external services).

## Why (internal review round 1, all three reviewers)

1. Forced ambiguity: the anchor keeps only (root, row count) per segment, so an edit plus more than eight rows inserted
   into the edited second is "ambiguous" (counted as undetected). The subset test (exp/sp2027/r13_subset_test.py)
   only searches up to eight added rows.
2. Empty time is not committed: a row backdated into a second (or minute, hour) that held no row when it was sealed
   has no anchored segment, and the live verifier never examines it (the generated-deployment verifier's
   UNCOMMITTED_HISTORICAL check has no live counterpart).
3. Anchor stall: the anchor daemon is single-threaded and reads a request body with no timeout, so code in the hub
   can block every append. While appends fail, `monitor.tick()` recomputes unanchored segments from the CURRENT copy at
   each poll, so rows edited during the stall are sealed in their edited form, and segments older than the one-hour
   re-read window are never anchored. Nothing records the gap.
4. Baseline: the renderer closure has never been compared live with committing every stable column.
5. Recovery: HOMEPROV shows that a second was altered, not who really caused the actuation.

## Design (monitor/monitor.py; additive, the node-hash encoding v2 is unchanged)

### 1. Row watermark and sealed-through time (default on; `HOMEPROV_COVERAGE=0` restores the old record)
Every poll's record carries, read from the same consistent copy the roots are computed from:
- `wm`: `{"states": max(state_id), "events": max(event_id)}` in the copy;
- `through`: the sealing cutoff of this poll in seconds since the epoch (every second `s < through` is sealed at or
  before this record; equal to `int(now - GRACE_S)` at second granularity, and the analogous cutoffs per granularity
  if needed);
- `seq_local`: the monitor's own poll counter (detects a missing record together with the anchor's sequence).
A record is appended at EVERY poll, also when no segment is newly sealed (the heartbeat); `sealed` may then be empty.

Why it works: the recorder is the single writer and assigns `state_id` / `event_id` in commit order (SQLite INTEGER
PRIMARY KEY, VACUUM does not renumber), so the copy at a poll holds exactly the rows with key <= `wm`. For a segment
sealed by record R, the rows present at sealing are exactly the segment's rows with key <= wm(R) (per table).

### 2. Stall-proof sealing (default on)
When a segment is sealed (first poll whose cutoff passes it) its root and row count are FROZEN in the monitor's
persistent state (`pending`), together with `sealed_at` (the poll time) and the record's `wm`/`through`. If the append
fails, later polls re-send the frozen pending roots; they never recompute them. Pending entries are not dropped when
they leave the re-read window. The appended record lists each segment with its `sealed_at` when that differs from the
record's own time. The monitor logs every failed append with its error (local alarm).

### 3. Escrow (optional, `HOMEPROV_ESCROW_DIR`, default off)
At sealing, the monitor writes the renderer-closure tuples of every row of each sealed second (the exact fields it
hashed, with the row key and table) to an append-only file in the escrow directory (outside the hub), one JSON line
per sealed second, plus that second's root. Recomputing the root from the escrowed tuples must reproduce the anchored
root (so the escrow is verifiable against the anchor). Privacy: the escrow is a copy of the activity history's closure
fields outside the hub; it is off by default.

### 4. Stable-columns scheme (`HOMEPROV_SCHEME=stable`, for the baseline)
Every stored column of `states` and `events` and of the rows they join (`states_meta.entity_id`,
`event_types.event_type`, `event_data.shared_data`, `state_attributes.shared_attrs`), except the columns the recorder
rewrites in place for untouched rows (on Home Assistant 2026.7.4: `states.last_reported_ts`; confirm from the
whole-row runs' failure analysis before fixing the list, and record it). Node hash with the v2 typed encoding and
scheme tag "stable". Same coverage fields as above.

## Verifier (new: exp/stages/e7_verify.py; reuses monitor.load/commit; old chains still verify as before)

For each record R in chain order (records without `wm`/`through` use the existing rules):
1. Sealed segments: for each segment sealed by R, recompute the root over the CURRENT rows of that segment whose key
   is <= wm(R) (per table). Mismatch -> the segment is VIOLATED and the violation is ATTRIBUTABLE (a sealed row was
   edited, deleted, re-keyed, or a row was inserted with a forged low key). Rows of the segment with key > wm(R) are
   LATE rows and do not enter the recomputation; extra late rows never make a violation ambiguous.
2. Empty sealed time: a current row whose timestamp falls in a second sealed as empty (no segment in any record whose
   `through` passed it) with key <= wm(R_seal) -> ATTRIBUTABLE insertion (it existed at sealing but was not sealed:
   impossible without a forged key). With key > wm(R_seal): it was inserted after the seal. Its insertion time is
   bounded by the records whose watermarks bracket its key: inserted after t(R_a) where R_a is the last record with
   wm < key. If t(R_a) - ts > LATE_BOUND (a constant fixed before the run from the benign late-row delays of earlier
   runs, recorded in the result file) -> ATTRIBUTABLE backdated insertion; else a benign late row (reported, outside
   the guarantee).
   The same rule applies to late rows in non-empty sealed segments (step 1), so a backdated row inserted into a
   non-empty sealed second is also attributable when it is later than LATE_BOUND.
3. Heartbeat gaps: consecutive records more than GAP_S apart (GAP_S fixed before the run, e.g. 3 x the poll period)
   or a `seq_local` jump -> a STALL interval is reported with its bounds; segments sealed during it carry `sealed_at`
   and are verified like any other.
4. Recovery (escrow present): for every violated second, report the escrowed closure tuples of the changed rows next
   to the current ones and render the original displayed cause from them (the investigator's offline rendering path:
   the release's own logbook processor run outside the hub on a verified copy with the escrowed fields restored).
5. Benign floor: untouched sealed segments violated under step 1 (expected 0 for the closure scheme once late rows are
   excluded; report the count and every case).

## Anchor hardening (testbed/anchord/; protocol and record format unchanged)
Threaded server (ThreadingHTTPServer), a per-connection socket timeout (e.g. 5 s) covering header and body reads, a
maximum body size, and the tag checked before any parsing. A slow or stalled client must not block another client's
append. Earlier chains stay valid (record format unchanged). Document the version change.

## E7 run (one real-deployment run on the default deployment, after the E2 night ends)
Monitors: closure v2 with coverage + escrow (the evaluated configuration) and, in parallel, a stable-columns monitor,
each with its own hardened anchor (fresh append keys; record only fingerprints). Arms (laundering of another
principal's unlock and member-account swap, 30 trials each, 10 per configuration), each also with an insertion
variant (the edit plus K >= 9 rows inserted into the edited second, K recorded); backdating arms (a forged unlock row
inserted into a sealed second that held no row, and into a sealed minute that held no row if one exists in the window;
30 each if possible); an anchor-stall arm (the hub stalls the anchor with slow connections for a fixed interval while
the edit happens; the edit's segment is sealed during the stall). Benign floor over the run window for both monitors.
Per-poll monitor cost (copy, load, commit, append) for the closure monitor with coverage, median, p90 and max.
Recovery: the original displayed cause recovered from the escrow for every laundered trial.
