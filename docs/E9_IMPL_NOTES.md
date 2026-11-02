# E9 implementation notes, part A (A1-A7): monitor, verifier, operator tool (2026-10-09; code review fixes 2026-10-10, sections 11 and 12)

Scope: E9_DESIGN.md part A, items A1-A7. Code, tests and three check scripts; no paper text. Paths are relative to the
repository. Nothing was committed or pushed. No container, image or VM was started, stopped, exec'd into or changed
(the Home Assistant 2026.7.4 source was read with `docker exec hpr-hass cat`/`grep`, as allowed). The attack
integrations were not touched. No key was printed or recorded: the scripts make throwaway keys in temporary
directories and record only public-key fingerprints or file hashes.

## 1. Files

| File | Status | sha256 |
|---|---|---|
| `monitor/monitor_e8.py` | NEW: the E8 monitor, byte for byte | `3e479ae01caf299e697b0274a22ddddbaa6b57b9bf4b730a8774b2d7c5b5282b` |
| `monitor/monitor.py` | A2, A4, A5, three speed-ups with identical output (2.5), the streamed full-history seal (10.1), the code review fixes (11: direct-read lock, m3, m5, R6; 12: N2 retry) | `8ad9e2d77f2d098af1e81ed509445631dc3d3ba2d349fddff75bfd920a7ab8ae` (re-checked: `3f277d39...`; reviewed: `a60cdf59...`; first report: `8d0c1040...`) |
| `exp/stages/e7_verify.py` | A1, A2, A3, RESTORE, A7 fixes, the smoke fixes (10.2-10.5), the code review fixes (11, 12: RESTORE_DONE) (was `7e036386...`) | `9c42fad983a00e43083359339bc185c11d31ab7cdec7781f0e2cdee94ebea885` (re-checked: `59a1b228...`; reviewed: `428e229b...`; first report: `b610ffd9...`) |
| `exp/rig/marker_issuer.py` | A6 (was the E2 issuer); review: nonce, `backup_wm`, `from`, `monitors` (11), RESTORE_DONE (12) | `fcf668178b1506ad8e279095c260ac9656dfca780b3c9c37f081df102f544a03` (re-checked: `0c644d43...`; reviewed: `05bde4e4...`) |
| `monitor/test_coverage.py` | its env list also clears the new settings | `5857010438783e6f4378735685ae26615934872075759504e56d34663e2e65db` |
| `monitor/test_e9.py` | NEW: A1-A5, RESTORE, byte identity with the E8 monitor, the smoke fixes, the code review regressions (11, 12) | `9d9f034d5a3ea596c809d013b07e83d2a9833f16fab5e9c72318927827424752` |
| `monitor/test_e9_dishonest.py` | NEW: A7 | `84ed49c5c6ce46eb02fe5b9ec541c98f0c3db1fb1e4deeb1c51fafe8401ea857` |
| `testbed/anchord/test_anchor_e9.py` | NEW: A6 against a linked anchor; review R3 | `a9401be5925be8d8a53006e5042e4755b8bca824e911775adbfeab13eb638a72` |
| `exp/stages/e9_dishonest_anchor.py` | NEW: A7 on the saved E8 chains -> `exp/out/e9_dishonest_anchor.json` | `cb52853ab38d245b8d777f6acd75021291a712b5733df3c4d2697ef1ed792224` |
| `exp/stages/e9_purge_disconnect_offline.py` | NEW: A1 offline -> `exp/out/e9_purge_disconnect_offline.json` | `08cf47c1a530d6cd63400d751068df17acd874032b19987d3f87e6e3e30fa03f` (`--purge-tol-s`, default 60; `--pre-at`/`--post-at`; reads the escrow lazily, 11.2) |
| `exp/stages/e9_dishonest_markers.py` | NEW (review R5): marker cases on the smoke-3 chains -> `exp/out/e9_dishonest_anchor_markers.json` | `77156058e0e9da0992a4214ffc7e2d13e6d95657ea076565e169795e1929c34d` |
| `exp/sp2027/e9_direct_read_identity.py` | NEW: A4 on saved recorders -> `exp/out/e9_direct_read_identity.json` | `be1b16f79b02e195cb9f9aed4df3e97c496841f8affe9fa7591b1d4a0f7352ec` |
| `testbed/anchord/anchord_e8.py` | NEW: the E8 `anchord.py`, byte for byte | `53d1ac92ebbca11e7d3aeda742c1bd790ccb98edb913ad0f4eda8b664af96dfd` |
| `testbed/anchord/anchord_linked_e8.py` | NEW: the E8 `anchord_linked.py`, byte for byte | `966d2b351cec120538e059eb293293892cf5bb312fc7b310ffb8888f0fad9b5c` |
| `testbed/anchord/anchord.py` | chain state in memory (section 4a; lead's decision) | `8b35448dcf86df8bd1291b6fec6ff39e045bacbc3b083b09f61d035c1f251421` |
| `testbed/anchord/anchord_linked.py` | uses it for append, head and witness pushes | `f6252e245b0f963fbefd4c511b51187985386870c745b8321c917152486ee1e1` |
| `testbed/anchord/test_anchor_cache.py` | NEW: the anchor against the E8 daemon, restarts | `54a3e52cbafe65b824a1074c9b6aed36ffdf5e0f2d7654e4fb628405f859526b` |

`anchord_r12.py`, `headwitness.py`, `chainverify.py`, `reproduce/*`, `monitor/monitor_wholerow.py` and the Dockerfiles
are unchanged. The monitor images copy only `monitor.py` and the anchor images `anchord.py` and `anchord_linked.py`, so
E9 needs new image tags for both. `anchord_linked_e8.py` imports `anchord`, as it did in E8: to rerun the E8 anchor,
copy the two `_e8` files under their E8 names (as E8's image did).

## 2. Monitor (`monitor/monitor.py`): settings and record fields

Every behaviour change is behind a setting; with all of them unset, the records, the state file and the escrow are
byte-identical to `monitor_e8.py`'s (test `test_new_settings_unset_records_are_byte_identical_to_the_e8_monitor`,
coverage, keylog, escrow and signatures on, stable scheme, a laundering in between). New settings, all validated at
start (an invalid value stops the monitor):

| Variable | Values (default) | Effect |
|---|---|---|
| `HOMEPROV_ROWBIND` | `0` or `1` (`0`) | A2 per-row keylog binding (2.1) |
| `HOMEPROV_SINCE` | finite unix seconds >= 0 (unset) | A5 full-history first poll (2.2); `0`: no lower bound at all (11.12) |
| `HOMEPROV_READ` | `copy` or `direct` (`copy`) | A4 direct read (2.3); `direct` needs `HOMEPROV_COVERAGE=1` and no `HOMEPROV_CLOCK_FILE` |
| `HOMEPROV_QUICK_CHECK_EVERY` | integer >= 1 (`1`) | quick_check at polls with `seq_local % N == 1` (always the first); both read modes |
| `HOMEPROV_KEYLOG_REWIND` | `0` or `1` (`0`) | review R6: re-commit the keys a restore made fall (11.6); the state gains `keylog_copy_at` |

`HOMEPROV_NAMEMAP_DIR` (A3) is unchanged: when set, every observable poll's record carries
`"namemap": {"v": 1, "digest", "n", "parts": {auth|person|entity|device: {"digest", "n"}}}` (or
`{"v": 1, "unobservable": true, "reason"}`); the E9 monitors must have it set to the hub's `.storage` on a read-only
mount.

### 2.1 A2: per-row binding (`HOMEPROV_ROWBIND=1`)
- Each keylog entry's `rows` element becomes `[key offset, full row hash as 64 lowercase hex, first-observed second or
  null]` (before: an 8-hex prefix), and the entry gains `"bind": "row_sha256"`. The entry's `from`, `to`, `n`, `acc`
  and `start` are unchanged; `acc` is still the fold `H(...H(H(0^32 || h1) || h2)...)` over exactly these row hashes,
  and the row hash is still `SHA-256(encode_node_v2("keylog", fields))`. Empty ranges written as
  `{"from", "to", "n": 0}` (no new key range) carry no `bind`.
- Why the full hash and not the design's 32-bit prefix: the prefixes are already in every keylog entry since E7, and
  the E7 re-review (R1, `test_R1_prefix_collision_plus_decoy_still_flags_the_forged_second`) showed a writer can make a
  changed row keep its prefix (a 2^32 search, or a 2^16 birthday search for a row it writes itself) and add a decoy, so
  localising by prefix would let a forged row escape while a decoy is flagged. With the full hash that needs a SHA-256
  second preimage. The cost is 56 more bytes per first-observed row in the record (in the A1 scratch test of 5.3, the full-history first poll over 1,176,999 rows wrote 77,535,893 bytes of records without the binding and 143,653,637 with it).
- Escrow lines (`"kind": "keylog"`) are unchanged.

### 2.2 A5: full-history initial seal (`HOMEPROV_SINCE=<t>`)
- The first observable poll of a monitor (state without `"since_applied"`) reads from `floor(t / 3600) * 3600`
  instead of the usual window (the previous and the current hour): every segment from there to the cutoff is sealed
  by that poll, its record's `since` says so, and the keylog's first range starts above the largest key of a row
  timestamped before that boundary (`HOMEPROV_SINCE=0`: from key 0, every row whatever its timestamp, including rows
  with malformed timestamps). The state then holds `"since_applied": true`; later polls read the usual window.
- The roots and keylog sub-ranges go out through the existing splitting: records of at most
  `HOMEPROV_MAX_RECORD_BYTES` (default 1 MiB, the anchor's limit is 16 MiB), at most `HOMEPROV_MAX_PARTS` (64) records
  per poll, the rest frozen and sent at the next polls. With the escrow on, the escrow receives every row twice (sealed
  seconds, and first-observation keylog tuples).
- A monitor that loses its state seals the full history again (a first-write-wins anchor accepts identical roots; a
  root that differs is carried as `conflicted`).
- Measured cost of the first poll on real recorders: sections 5.2 and 5.3.

### 2.3 A4: direct read (`HOMEPROV_READ=direct`)
- One connection per poll: `sqlite3.connect("file:<HOMEPROV_DB>?mode=ro&readonly_shm=1", uri=True, timeout=10,
  isolation_level=None)`, lenient text decoding, `PRAGMA query_only=ON`, then `BEGIN` and a first read
  (`SELECT count(*) FROM sqlite_master`) that pins the snapshot. `copy_at` is the time just before that first read.
  The watermark, the keylog and the segment rows are all read through that connection (`_open()` accepts a path or a
  connection), so they see one snapshot while the hub writes. The connection is rolled back and closed right after the
  rows are read, before the escrow and the append.
- `readonly_shm=1`: the monitor never opens the hub's `-shm` for writing, even on a writable mount; SQLite then builds
  the WAL index in the monitor's own memory and takes only a shared lock, which holds off a checkpoint's backfill for
  the read's duration and never blocks a write. A test runs the hub in a separate process and checks that the
  database, `-wal` and `-shm` bytes are unchanged by the direct-read polls (in one process the reader would share the
  writer's WAL index, which is why the test needs two processes).
- Evidence checks (changed 2026-10-10, section 11.0): `validate_files()` (the file part of `validate_copy()`: database
  header, WAL magic, frame stride, WAL size against the `-shm`'s frame count) on the live files BEFORE the connection is
  opened, repeated up to 3 times 20 ms apart if it fails, and again AFTER the connection is closed (a failure then fails
  the poll closed, detail `after_read`); never while the read is held. Then `check_connection()`: quick_check when due
  and the two schema probes, on the same connection. While the read is held, the WAL header's checkpoint sequence and
  salts and the database header's change counter are read twice through two descriptors opened before the connection
  and closed after it (right after the snapshot is pinned and after the rows); if they moved, the poll fails closed
  (`read_raced`, review m3). Any failure, or an exception while opening, makes the poll `evidence_unobservable` with the
  same record format as copy mode; reasons: `direct_open_failed`, the `validate_files()` reasons, `quick_check_failed`,
  `schema_unreadable`, `load_failed`, `read_raced`. A raced read is repeated, up to 3 reads (12.2).
- Fallback: when the hub's `-wal` or `-shm` does not exist (hub stopped, or closed cleanly), the poll copies as in
  copy mode.
- Records do not name the read path (they are byte-identical across the modes); the cost log line gains
  `"read": "direct" | "copy_fallback"` in direct mode, and so does the poll's printed summary.
- Copy mode stays the default.

### 2.4 Unchanged record format otherwise
No other record field changed. The state file gains `since_applied` only with `HOMEPROV_SINCE`.

### 2.5 Speed-ups with identical output
Found while running A1 offline (a full-history first poll over 1.18 M rows did not finish in 20 minutes):
- `escrow_keylog()` filtered all first-observed rows once per sub-range (quadratic); it now slices by key (bisect).
- `commit()` computed each node hash once per granularity (3 times); it now computes it once.
- `has_raw_bytes()` scanned every character of every string; it now tries a strict UTF-8 encode first.
The outputs are identical: all monitor tests (including the golden coverage-off digests and the E8 byte-identity
test), `reproduce/verify_all.py` (10 runs MATCH) and `reproduce/verify_e7e8.py` (8 of 8 MATCH) after the change.

## 3. Verifier (`exp/stages/e7_verify.py`)

Without the new options the output of an E7 or E8 verification is identical to before (section 6). New options of
`e7_verify.py verify` (and the same keyword arguments of `verify()`):

| Option | Meaning |
|---|---|
| `--operator-key FILE` | the operator's HMAC key file (hex); a marker counts only if its `marker_tag` verifies |
| `--operator-pubkey PEM` | the operator's Ed25519 public key; a marker counts only if its `marker_sig` verifies |
| `--purge-keep-s S` | the verifier's own retention policy (`purge_keep_days * 86400`); PURGE markers are applied only with it |
| `--purge-tol-s S` | added to every PURGE cutoff (default 0) |
| `--no-purge-disconnect` | PURGE markers with the round-12 retention-scoped rule only (for the comparison) |
| `--restore-tol-s S` | apply RESTORE markers, allowing rows timestamped S seconds before the restore point to be lost |
| `--restore-max-age-s S` | the largest `issued_ts - restore_point_ts` a RESTORE marker may declare (default 86400; review m2) |
| `--no-rowbind` | read per-row-bound keylog entries by their prefixes (suspects "without per-row binding") |
| `--namemap-storage DIR` | the hub's `.storage` (read only), to compare the current name map with the last anchored digest |

With neither operator key, no marker is considered (an excuse is never taken on the anchor host's word). With both,
both must verify. In E9 pass `--operator-pubkey` (as `e9_score.py` does); `--operator-key` adds nothing a third party
can rely on: the anchor host holds the operator's HMAC key (it checks markers with it), so only the signature shows
that the operator issued a marker (A7 case `forged_marker_hmac_only`). (Corrected 2026-10-10, review m7: this section
said "use both".) A marker that reached the chain twice counts once (review R3, 11.3).

### 3.1 A1: markers and the purge-disconnect rule
Accepted PURGE markers need `"scope": "retention_policy"`, a `scheduled_ts` and `issued_ts <= scheduled_ts`; the
cutoff is `scheduled_ts - purge_keep_s + purge_tol_s` (the record's own `cutoff_ts` is ignored). Then, before anything
is attributed or flagged:
- a segment wholly before a cutoff is excused only if it holds no row now (a purge leaves nothing older than its
  cutoff; a partial deletion is not excused);
- the segment of each granularity that straddles a cutoff is excused for removed or changed rows, never for inserted
  ones (as `exp/rig/markers.py explains_scoped`);
- a segment wholly at or after the latest cutoff before it (the purge-disconnect rule): for every current state row
  whose `old_state_id` is now NULL, the value committed at first read is taken from the escrow (the sealed tuple of its
  second, from an escrow line that reproduces the anchored root; else its first-observation keylog tuple), else from
  the per-row binding (the value v for which the row's current keylog fields with `old_state_id = v` hash to the bound
  row hash: the entity's previous row if it is still there, else every absent key the keylog bound); the segment is
  excused only if the root over the rows with those values restored equals the anchored root, and every restored v
  names a state row that is absent now and was committed with a timestamp before the cutoff (evidence: its escrowed
  tuple, its escrowed keylog tuple, or the keylog's first-observed second s with s + 1 <= cutoff);
- a failed keylog range: each row is explained if it is gone and was first observed before a cutoff (purged), or is
  present and differs only by such a disconnect (exactly: per-row binding, or the escrowed first-observation tuples).
  A range is excused when every row is explained; otherwise it stays, and with an exact check its suspects are
  narrowed to the unexplained rows. Without the binding or the escrow, only a range none of whose rows is left can be
  excused.
Output (only when an operator key is given): `markers` (`accepted`, `rejected` with `why`), `purge`
(`cutoffs`, `disconnect_rule`, `excused` counts per rule and granularity, `disconnects`
`{"n_rows", "n_seconds", "seconds"}`, `disconnected_rows` `[{"key", "second", "restored_old_state_id", "source",
"referenced_row", "cutoff", "where"}]`, `not_excused` with reasons), `excused_violations`, `excused_keylog_violations`;
violations and keylog violations carry `excused_by` or `not_excused_by_purge`; `segments[g]["excused_by_marker"]`.
Reasons that keep a violation: `rows_left_in_a_segment_older_than_the_cutoff`, `rows_inserted_into_the_straddling_segment`,
`referenced_row_still_present`, `referenced_row_not_committed_before_cutoff`,
`restoring_the_disconnects_does_not_reproduce_the_anchored_root`,
`committed_value_not_found_for_a_row_whose_old_state_id_is_null`, `no_disconnected_row`, `purge_disconnect_rule_off`;
keylog: `row_added_to_the_range`, `removed_row_not_older_than_the_cutoff`, `row_changed`,
`changed_row_is_not_a_purge_disconnect`, `rows_left_and_no_per_row_binding_or_escrow_to_check_them`.

### 3.2 RESTORE markers (A6 issues them; E9 plans a restore)
**Replaced by the rule of section 11.1 (review R1, 2026-10-10)**: the rule ends when the restored recorder is first
read, K comes from the marker's signed `backup_wm`, and only unchanged backup rows may remain in the segments and key
ranges it excuses. What follows is the earlier rule, kept for the record: accepted RESTORE markers needed
`restore_point_ts` R <= `issued_ts` I; K = the largest key per table among current rows timestamped before I; with
`--restore-tol-s` tol, a segment starting at or after R - tol was excused if every row it held was timestamped at or
after I (no end in time: R1); a failed keylog range likewise. Not covered (still true): an `entity_id` change (RENAME with `entity_id`) rewrites `states_meta.entity_id`, a committed joined value of
every row of that entity, and no rule excuses it; E9's benign rename should change a display name (entity registry
`name`), which only the name map sees.

### 3.3 A2 in the verifier
For an entry with `"bind": "row_sha256"` whose listed hashes fold to its `acc` and `n` (keys inside the range,
ascending), a failed range is localised exactly: `suspects` = changed + added + removed rows, `seconds` only theirs,
`"localization": "exact"`. If the listed hashes do not fold: every row stays a suspect,
`"localization": "row_binding_inconsistent"`. With `--no-rowbind`: `"prefix_ranked"`, as before. A prefix-ranked range
that failed with no differing prefix carries `"prefix_collision": true` (reported as such; every row a suspect).

### 3.4 A3: the name map
`namemap` (present when any used record carries one): `records_with_namemap`, `n_unobservable`,
`records_namemap_unobservable`, `first`, `last`, `transitions`
`[{"chain_seq", "ts", "prev_chain_seq", "prev_ts", "from", "to", "parts_changed", "excused_by_rename_marker",
"marker_chain_seq"}]`, `pending` (with `--namemap-storage`), `rename_markers`, `unexcused_changes`, `verdict`
(`unchanged` | `changed_with_declared_renames` | `display_input_changed_after_seal`). A transition is excused only by
an accepted RENAME marker on the chain before the first record carrying the new digest, whose `parts` give exactly the
new digest of every part that changed. Records are taken after the signature check. Since 10.4 a marker excuses one
transition (consumed); since the review (11.3, 11.11) a marker that reached the chain twice counts once, and a marker
that also names the digest a part had before (`from`) excuses only a change from exactly that digest.

### 3.5 Found by A7 and fixed (no effect on the E7 and E8 results, section 6)
- A row backdated into a sealed second and held by no known poll (the chain ends, or was cut, before any poll saw
  it) was judged a benign late row, because only a lower bound on its commit time is known. It is now
  `unobserved_late` (neither benign nor attributable), listed in `unobserved_late_rows` (printed only when non-empty).
  Before the fix, A7's `truncate` case turned one detected trial second of the stable E8 chain into a verified one
  (its rows were first observed by poll 540, the first poll the cut removed).
- An attributable minute or hour violation was localised to the seconds of its late rows unless a flagged second
  explained it. When the host withholds the record of a tampered second, that second is root-unknown and the coarse
  violation could be pinned on an untouched neighbour. If a second inside it is root-unknown, the coarse violation is
  no longer localised (`unlocalized_root_unknown_seconds`).

## 4. Operator tool (`exp/rig/marker_issuer.py`, A6)

The earlier calls behave as before (`append()` still raises on a refusal; `markers_from_chain(records, key)` still
returns PURGE markers only; the PURGE loop without `--reply-tags` and `--sign-key` is the E2 issuer). Added:
- `post()` (never raises) and `issue()` (retries until ok, `--attempts`, or the scheduled time; stops on the anchor's
  own validly tagged refusal). `--reply-tags 1`: a reply counts only with a valid `X-HP-Reply-Auth` under the key the
  request was tagged with (the operator key; `anchord.py reply_tag()` bytes); `auto` checks a tag when one is sent;
  `0` never.
- `--sign-key PEM` (operator Ed25519, PKCS#8): the marker record gains `marker_sig_alg` `"ed25519"`, `marker_sig_fp`
  (SHA-256 of the raw public key, hex) and `marker_sig` (hex, over `b"HOMEPROV-marker-sig-v1\0"` + the marker's
  sort_keys JSON). The HMAC `marker_tag` is unchanged (the anchor checks it).
- Waiting is on the wall clock (`wait_until()`: steps of at most 30 s).
- `--kind RESTORE --restore-point-ts T` -> `{"marker": "RESTORE", "restore_point_ts", "issued_ts", "issuer":
  "operator", "note"?}`; `--kind RENAME` with `--rename-part P --rename-digest D` (repeatable), or `--storage DIR
  --rename-part P --rename-match FIELD=VALUE --rename-field F --rename-to V` (the new part digest computed with the
  monitor's own `namemap_commitment()`), optionally `--entity-id-from/--entity-id-to` -> `{"marker": "RENAME",
  "parts": {P: D}, "issued_ts", "issuer": "operator", "entity_id"?, "note"?}`. PURGE markers keep their format.
- `markers_from_chain(records, key, kinds=None, pubkey=pub)` for every kind and the signature check.
Tested against `anchord_linked.py` with an append key, a separate operator key, sync pushes to a head witness and
tagged replies (`test_anchor_e9.py`).

## 4a. Anchor: chain state in memory (after the first report; the lead's decision)

Every append of the E8 daemon read the whole chain file (`anchord.py _append` to count the lines; `anchord_linked.py
_append` to find the last line, and `_chain_lines()` again for the head-witness push), and so did every `GET /head` and
every publication (each 5 s). Now `anchord.py` scans the file once, at its first use, and keeps in memory the (start,
end) offsets of the non-empty lines, the size, the line count and the last line (`_chain["state"]`, read and changed
under the chain lock). An accepted append writes its line with O_APPEND and flushes and fsyncs it before anyone is
answered, exactly as before, and only then updates the state; a write that raises drops the state, so the next call
scans the file. Before each use the state is checked against the file: its size, and the bytes of the last line read
from their offset; anything else that changed the file (a rewrite at rest, an append behind the daemon's back, a
restore) makes the daemon scan it again, so it still appends to the file as it is on disk (the E8 anchor tests of the
reviewer's rewrite-and-relink attack depend on this, and pass). A witness push reads only the records it pushes, at
their offsets. The first-root index was already in memory. The record format, the replies, the head, the publication
and the pushes are those of the E8 daemon. Limit: a rewrite at rest that keeps the file's size and its last line
byte for byte is not noticed until the next restart; it changes no record the daemon writes, since a linked record
depends only on the last line and on the line count.

Tests (`test_anchor_cache.py`, 9): the same appends at the same clock on the E8 pair (`anchord_e8.py` +
`anchord_linked_e8.py`) and the current pair give the same chain bytes, replies, heads and witnessed heads: linked with
a witness; unlinked; a restarted anchor (two restarts, one of them before a 300 KB record), also equal to a run without
restarts; a legacy unlinked prefix then linked records across a restart; the `anchord.py` entry point across a
restart; a last record rewritten at rest with the same size, and a record appended behind the daemon (both scanned
again, 2 scans in total); a failed write (state dropped, the next append consistent with the file); a push reads one
record, never the file; one scan for 29 appends.

Measured in my scratch (`anchor_bench/anchor_append_latency.json`, not a result file): a linked chain of 186,411,284
bytes in 182 records of up to 1 MiB (the size of the E9 full-history first poll, 185,549,779 bytes in
`exp/out/e9_direct_read_identity.json`), then 60 appends of an E8-sized record (1,713 bytes) with a sync push to an
in-process head witness, in-process on this laptop:

| Daemon | first append (includes the scan) | append median / p90 / max | head median / max |
|---|---|---|---|
| E8 (`anchord_e8.py` + `anchord_linked_e8.py`) | 392.2 ms | 201.86 / 235.28 / 266.82 ms | 132.24 / 170.31 ms |
| current | 142.3 ms | 0.63 / 0.80 / 1.27 ms | 0.03 / 0.16 ms |

Both chains verify and hold 243 records.

## 5. Check scripts and result files

### 5.1 A7: `exp/out/e9_dishonest_anchor.json`
`python3 exp/stages/e9_dishonest_anchor.py` (2 min; sha256 of the result
`69b6a781d50bf87067e97b63d136ebac79835ee0c416eb89745d5df479866b88`). Inputs: the E8 run's chains, recorder copy
(sha256 `756270...9bd4`, as in `e8_main_config.json`), public keys and witness logs in
`HOMEPROV-P13-exp/e8/e8_main/` (the chains and heads are byte-identical to the `exp/out/e8_main_*` copies), the arms
window and E8's parameters. The host's chain is relinked in every case, so its own links verify. 630 trials over 629
trial seconds; the untouched population is the E8 floor's 1,435 untouched anchored seconds. Honest outcomes: every
trial second a violation; untouched seconds (stable / closure): violation 791 / 768 (keylog suspects: E8's chains have
no per-row binding), violation_coarse_only 548 / 571, match 96 / 96.

| Case | stable: trial seconds (violation / unknown / match) | untouched newly violation | closure: trial seconds | untouched newly violation | chainverify (every witnessed head) |
|---|---|---|---|---|---|
| `honest` | 629 / 0 / 0 | - | 629 / 0 / 0 | - | stable: ok; closure: ok |
| `drop` | 105 / 524 / 0 | 0 | 107 / 522 / 0 | 0 | stable: fails (919 mismatched, 568 beyond the end); closure: fails (948, 570) |
| `drop_all_evidence` | 0 / 629 / 0 | 0 | 0 / 629 / 0 | 0 | stable: fails (891, 596); closure: fails (912, 606) |
| `withhold` | 569 / 60 / 0 | 0 | 569 / 60 / 0 | 0 | stable: fails (1237, 154); closure: fails (1267, 155) |
| `truncate` | 309 / 320 / 0 | 0 | 310 / 319 / 0 | 0 | stable: fails (0, 968); closure: fails (0, 994) |
| `reorder` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | stable: fails (1494, 0); closure: fails (1525, 0) |
| `replay` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | ok on both: the 50 records are after the last witnessed head |
| `forge_unsigned` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | stable: fails (1494, 0); closure: fails (1525, 0) |
| `forge_unsigned_no_key` | 270 / 0 / 359 | 0 | 270 / 0 / 359 | 0 | as `forge_unsigned` |
| `cross_monitor` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | stable: fails (1507, 0); closure: fails (1539, 0) |
| `alter_signed` | 105 / 524 / 0 | 0 | 107 / 522 / 0 | 0 | stable: fails (1487, 0); closure: fails (1518, 0) |
| `forged_marker` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | stable: fails (447, 0); closure: fails (459, 0) |
| `forged_marker_hmac_only` | 629 / 0 / 0 | 0 | 629 / 0 / 0 | 0 | as `forged_marker` |

("untouched newly violation": untouched seconds that were match or violation_coarse_only in the honest case and are
violations in this case.) Under the monitor's public key, in every case on both chains, no trial second goes from
violation to match and no untouched second becomes a violation: the host can turn evidence into "unknown" (drop,
withhold, truncate, alter) or change nothing (reorder, replay, unsigned or foreign records, an unsigned marker); without
the key (`forge_unsigned_no_key`), 359 of the 629 trial seconds become matches. In `forged_marker` the host's PURGE
marker is rejected (`unsigned`); in `forged_marker_hmac_only` it is accepted and excuses 2 one-second violations and 13
(stable) and 15 (closure) failed key ranges, while every second keeps its outcome (the same seconds stay flagged by
other evidence). The witness every-head check fails in every case that rewrites the chain, except `replay`, whose
records come after the last witnessed head. E8's own operator probe marker (MIGRATE, chain seq 7) is rejected in the
marker cases because the host key here is not E8's operator key (not available; nothing depends on it).
Two verifier fixes came out of this check (3.5); the table is with them. Before them, `truncate` made one trial second
of the stable chain (1791527040, arm P) a match, and `drop`/`alter_signed` moved one closure minute violation onto an
untouched second.

### 5.2 A4: `exp/out/e9_direct_read_identity.json`
`python3 exp/sp2027/e9_direct_read_identity.py` (sha256 of the result
`172d586ab482e6ee425fc54c0ed74de61dfc1cf7f95286157239930d2653749e`): `all_identical: true`. On scratch copies of the
E8 and E7 recorders, a separate hub process committed 200 rows per table into the WAL and kept the database open
(852,872 and 968,232 bytes of WAL); two monitors that differ only in `HOMEPROV_READ` polled 3 times at the same clock.
For both recorders and both configurations (E9: stable, keylog, per-row binding, escrow, full history; E8: closure,
keylog, escrow) the records, the state files and the escrow files are byte-identical, every direct poll read directly,
and the hub's database, `-wal` and `-shm` are byte-identical after the direct reads. Measured per-poll wall times (one
laptop, both checks running at once, not the cost study): E8 recorder, E9 configuration, first poll (full history)
150,636.7 ms copy and 104,501.0 ms direct, then 5,688.2 / 5,708.8 and 3,294.9 / 3,683.8 ms; E8 configuration 728.8 /
408.6, 455.3 / 328.8, 421.4 / 372.2 ms. The full-history first poll over the E8 recorder wrote 185,549,779 bytes of
records (179 records of at most 1 MiB) and 2,642,197,406 bytes of escrow; over the E7 recorder 180,463,744 and
2,566,469,329.

### 5.3 A1 offline: `exp/stages/e9_purge_disconnect_offline.py`
**Result on the real 2026-10-10 purge: `exp/out/e9_purge_disconnect_offline.json`** (sha256
`76a9a8140cd10ca9502bd3dfde64455f9a087b8c3adc49483d59f6e5d4035505`; written 2026-10-10 04:46-04:59 UTC with the final
code of section 12: monitor `8ad9e2d7...`, verifier `9c42fad9...`, as recorded in the file; inputs `pre_oct10.db`
`015213e3...` at 03:55:12 and `post_oct10.db` `2f081049...` at 04:45:02 UTC, read from copies). Home Assistant's
nightly purge (scheduled 04:12 UTC, cutoff 2026-09-10 04:12 UTC, keep 30 days) removed 34,790 states and 20,999 events,
all older than the cutoff (none younger, none older left), disconnected 16 retained states in 11 seconds (6 of them more
than an hour after the cutoff; every referenced row was older than the cutoff and is gone), and changed no other
retained row in any committed column. The emulated monitor sealed all 1,231,178 rows of the pre copy in one poll
(escrow source: 79.5 s, 10 records, 80,890,402 bytes of records, 2,711,042,819 bytes of escrow; binding source: 43.2 s,
19 records, 150,051,920 bytes). Verified against the post copy, `--purge-tol-s` 60, both sources the same:

| Verification | seconds / minutes / hours violated | failed key ranges | flagged seconds | attributable rows |
|---|---|---|---|---|
| no marker | 17,584 / 1,467 / 32 | 444 | 17,584 (binding); 18,060 (escrow source, prefix-ranked suspects) | 55,805 |
| marker, round-12 retention rule only | 11 / 8 / 5 | 8 (all `purge_disconnect_rule_off`) | 11 | 16 |
| marker and purge-disconnect rule | 0 / 0 / 0 | 0 | 0 | 0 |

With the rule, the excused disconnects are exactly the ground truth's 16 rows in its 11 seconds (escrow source: the
committed value from the escrowed keylog tuples; binding source: from the per-row binding), excused under the rules
`segment_older_than_cutoff_gone` (17,573 seconds, 1,459 minutes, 27 hours), `tolerance_band` (4, 1, 1),
`purge_disconnect` (7, 7, 4), 436 key ranges purged and 8 with disconnects. 6 rows committed after the pre snapshot with
earlier timestamps are reported as unobserved late rows, as they must be (no emulated poll saw them). One run,
`/usr/bin/time -l`: 801.1 s wall, 2,745,270,272 B maximum resident, 5,149,102,496 B peak footprint (six verifications in
one process). The text below, written before the snapshots existed, describes the script.

**(Before the run:) script written and tested; the 2026-10-10 snapshots did not exist yet** (the night
driver writes `pre_oct10.db` at 03:55 and `post_oct10.db` at 04:45 UTC, then runs its own analysis). After 04:50 UTC:
```
cd <artifact-root> && python3 exp/stages/e9_purge_disconnect_offline.py --tag oct10
```
(on the oct9 pair it took 1,073.65 s of wall time with a peak memory footprint of 8,975,785,016 bytes, before the
streamed seal of 10.1; it reads copies only, and writes `exp/out/e9_purge_disconnect_offline.json`, refusing to
overwrite). It verifies with `--purge-tol-s` 60 by default (section 10.2), recorded in `parameters`. What it does: the emulation described in
its docstring, labelled "offline emulation" in the output, with two committed-value sources (escrow on with the binding
off; binding on with the escrow off), three verifications each (no marker; the round-12 retention rule; with the
purge-disconnect rule), and the ground truth from the two copies (`ground_truth.n_disconnected_rows`,
`disconnected_seconds`, `n_disconnected_more_than_an_hour_after_cutoff`, the referenced rows, retained rows changed in
any other committed column, removed rows older and not older than the cutoff). The fields to read: per source,
`marker_with_purge_disconnect_rule.flagged_seconds` and `left` (what is left), `purge.disconnects`
(excused disconnects: count, seconds, rows), against `marker_retention_rule_only` (violations without the rule).

Test on the 2026-10-09 pair (no purge ran that night, E2_PURGE_DIAGNOSIS.md; output in my scratch, not in exp/out):
ground truth 0 disconnected rows, 0 retained rows changed in any committed column other than `last_reported_ts`
(states) or in any column (events), 0 rows removed; with both sources and all three verifications 0 violations,
0 failed key ranges, 0 flagged seconds, 0 attributable rows (3 rows committed after the pre snapshot with earlier
timestamps are reported as unobserved late rows, as they must be: no emulated poll saw them). The emulated monitor's
first poll sealed 1,176,999 rows (escrow source: 134.8 s, 10 records, 77,535,893 bytes of records, 2,593,609,383 bytes
of escrow; binding source: 44.4 s, 18 records, 143,653,637 bytes). The disconnect rule itself is exercised on synthetic
recorders by the A1 tests (section 7), with Home Assistant 2026.7.4's purge order (disconnect, delete, then unused
attributes, data and metadata).

Dry run on real rows with an emulated purge (scratch `sim10/result.json`, not a result file): a copy of `pre_oct9.db`
purged with Home Assistant 2026.7.4's own statements at the 2026-10-10 cutoff (2026-09-10 04:12 UTC: disconnect and
delete in batches of 4,000 states, then events, unused attributes, event data, entity metadata and event types), then
the same pipeline with `--post-at` after the scheduled purge. Ground truth: 34,790 states and 20,999 events removed,
all older than the cutoff; 16 retained rows disconnected in 11 seconds, 6 of them more than an hour after the cutoff;
no other retained row changed. Both sources gave the same:

| Verification | seconds / minutes / hours violated, failed key ranges | excused |
|---|---|---|
| no marker | 17,584 / 1,467 / 32, 444 | none |
| marker, round-12 retention rule only | 11 / 8 / 4, 8 (all `purge_disconnect_rule_off`) | 17,573 / 1,459 / 28, 436 |
| marker and purge-disconnect rule | 0 / 0 / 0, 0 | all; disconnects: 16 rows in the 11 seconds of the ground truth |

The first version of this dry run rejected the marker as `after_snapshot`, because the emulated post snapshot carried
the 2026-10-09 time while the marker was for 2026-10-10; the real post snapshot (04:45) follows the marker (04:10).

## 6. E7 and E8 verify as before

Re-run with the code above and no new option (`e7_verify.py verify` with the parameters, trial reports, escrow and,
for E8, the public keys `HOMEPROV-P13-exp/e8/e8_main/keys/{stb,clo}_sign_pub.pem`, which are byte-identical to
`exp/out/e8_main_{stb,clo}_sign_pub.pem`, both present), into my scratch (`reverify/final/`, comparison in
`reverify/comparison.json`):

| Run | flagged seconds | e7_detected / trials | floor violated / untouched | untouched flagged | key-range violations | root-unknown | fields that differ from the saved file |
|---|---|---|---|---|---|---|---|
| E8 stable, arms | 1,688 | 630 / 630 | 0 / 1,435 | 922 | 945 | 0 | none (except `params`, the paths) |
| E8 closure, arms | 1,662 | 630 / 630 | 0 / 1,435 | 898 | 949 | 0 | none |
| E7 closure | 523 | 270 / 270 | 0 / 1,212 | 169 | 233 | 0 | `recovery`, `signatures` |
| E7 stable | 484 | 270 / 270 | 0 / 1,212 | 129 | 231 | 0 | `signatures` |

Every value equals the saved one. The E7 differences predate E9: the verifier of 2026-10-08 evening (before any E9
change) gives exactly the same output (E7's file was written before the keylog escrow and the signatures field), and
the E9 code's output is identical to it, field for field. Also: `reproduce/verify_all.py` status ok, 10 runs MATCH;
`reproduce/verify_e7e8.py --escrow` 8 of 8 verifier runs MATCH, 219 of 219 printed-number checks MATCH (reports in my
scratch). An early version of `_open()` broke `verify_all.py`, which replaces the monitor's `sqlite3` by a read-only
shim; fixed (it now tests for a path, not for `sqlite3.Connection`).

## 7. Tests

`python3 -m pytest -q monitor testbed/anchord`: **261 passed** (after the re-check fixes of section 12; 251 after
section 11; 224 before it). Per file: `test_coverage.py` 70, `test_node_hash.py` 12, `test_e9.py` 86 (new),
`test_e9_dishonest.py` 12 (new), `test_anchor_chain.py` 37, `test_anchor_stall.py` 13, `test_anchor_e8.py` 14,
`test_anchor_e9.py` 8 (new), `test_anchor_cache.py` 9 (new). The 146 tests from before E9 all pass; 115 are new (27 of
them in section 11, 10 in section 12). `test_e9.py` also passes under Python 3.9.6. The E9 tests of the first report also
pass under Python 3.9.6. `reproduce/verify_all.py` (status ok, 10 MATCH) and `reproduce/verify_e7e8.py --escrow` (8 of 8
MATCH, 219 of 219) were rerun after the anchor change.

New tests:
- A1 (16): a purge disconnect excused and reported, with the committed value from the escrow and from the per-row
  binding, stable and closure (4); not excused when another field also changed (2; the key range then keeps only the
  edited row as a suspect), when the referenced row still exists (2), when it is newer than the cutoff (2); without a
  valid marker: none, signed by another key, wrong HMAC, issued after its scheduled time, no retention policy given
  (5); a partial deletion of an old segment under a marker (1). The purge is emulated in Home Assistant 2026.7.4's
  order (disconnect, delete states and events, then unused attributes, data and metadata).
- A2 (4): exact localisation to the edited row (and the same chain read by prefixes: every row a suspect); no binding,
  records as before; an inconsistent binding keeps every row a suspect; the re-review's prefix-collision-plus-decoy
  attack localised exactly.
- A3 (5): a name-map change excused only by a prior operator RENAME with the right digest (declared, undeclared,
  wrong digest, declared after); a person re-link pending against the hub's storage.
- A4 (5): direct read and copy give byte-identical records, state and escrow on the same snapshot, with the hub in
  another process and its files unchanged (2 configurations); one snapshot per poll while the hub writes; fallback to
  a copy without a WAL, and fail-closed; quick_check cadence and the configuration checks.
- A5 (3): the full-history seal split under a 64 KiB anchor limit, every row bound by key, an edit of a row three days
  older than the monitor detected and localised; default records below 1 MiB; without `HOMEPROV_SINCE` the window as
  before.
- RESTORE (3); byte identity with `monitor_e8.py` with every new setting unset (1).
- A6 (7, anchord): a signed PURGE marker through a linked anchor with an operator key, tagged replies and a witness,
  read back by `markers_from_chain` and the verifier only under the operator's keys; RESTORE and RENAME from the
  command line, the RENAME digest equal to the monitor's after the rename; spoofed replies (untagged, wrong tag, a tag
  replayed from another request) not believed (3); the anchor's authenticated refusal stops the retries; waiting on the
  wall clock across a simulated host sleep.
- A7 (12): drop, drop_all_evidence, withhold, truncate, reorder, replay, forge_unsigned, alter_signed on a signed chain
  (the laundered second never a match, no untouched second a violation); without the key forged records hide it;
  another monitor's records excluded; a prefix collision reported as such; a row backdated after the last kept poll
  not called benign.

## 8. What the E9 harness must set

Monitors (both; build from `monitor/Dockerfile.sign` under new tags, and check the in-image `monitor.py` hash):

| Variable | M-direct | M-copy |
|---|---|---|
| `HOMEPROV_SCHEME` | `stable` | `stable` |
| `HOMEPROV_COVERAGE`, `HOMEPROV_KEYLOG` | `1` (defaults) | `1` |
| `HOMEPROV_SIGN_KEY` | private key path (own volume, read only) | same, its own key |
| `HOMEPROV_REPLY_TAGS` | `1` | `1` |
| `HOMEPROV_ANCHOR_KEY`, `HOMEPROV_ANCHOR` | its anchor's | its anchor's |
| `HOMEPROV_ESCROW_DIR` | a volume the hub never mounts | same |
| `HOMEPROV_NAMEMAP_DIR` | the hub's `.storage` on a read-only mount (e.g. `/cfg/.storage`) | same |
| `HOMEPROV_ROWBIND` | `1` | `1` |
| `HOMEPROV_SINCE` | `0` | `0` |
| `HOMEPROV_READ` | `direct` | `copy` (default) |
| `HOMEPROV_KEYLOG_REWIND` | `1` (review R6, 11.6) | `1` |
| `HOMEPROV_QUICK_CHECK_EVERY` | a pre-registered N (default 1: every poll) | the same N |
| `HOMEPROV_COST_LOG` | a file (gains `"read"`) | a file |
| `HOMEPROV_DB` | the hub's recorder on the read-only mount | same |

Start the monitors long enough before t_start for the full-history first poll and its follow-up records to finish
(section 5.3), with fresh state and empty escrow, and confirm `read: direct` (not `copy_fallback`, no
`direct_open_failed`) in M-direct's cost log during the smoke run.

Operator (the issuer runs outside the hub, with the operator's HMAC key file and Ed25519 key, never on the hub):
```
python3 -m rig.marker_issuer --kind PURGE --keep-days 30 --tz UTC --anchor URL --key-file operator.key \
    --sign-key operator.pem --reply-tags 1 --lead-s 120 --until T_END --log issuer.jsonl     # one per anchor
python3 -m rig.marker_issuer --kind RESTORE --restore-point-ts T_BACKUP --anchor URL --key-file operator.key \
    --sign-key operator.pem --reply-tags 1 --log issuer.jsonl                               # before the restore
python3 -m rig.marker_issuer --kind RENAME --storage <hub .storage, read only> --rename-part entity \
    --rename-match entity_id=<id> --rename-field name --rename-to "<new name>" --anchor URL \
    --key-file operator.key --sign-key operator.pem --reply-tags 1 --log issuer.jsonl       # before the rename
```
Each anchor needs `HOMEPROV_OPERATOR_KEY` = the hex content of `operator.key` (E8 A3); each anchor gets its own
marker. Publish the operator's public key and its fingerprint in the run log. A RESTORE marker must carry the backup's
`backup_wm` {"states", "events"} signed with it (the harness's `e9ops.py issue --extra` already does; the issuer has
`--backup-wm`): without it the verifier rejects the marker (11.1). Once the restored hub is up, the operator issues a
RESTORE_DONE marker naming that RESTORE marker, with the restored recorder's keys read after the restart and the hub's
start time (`--kind RESTORE_DONE --restore-marker '<RESTORE marker JSON as issued>' --post-restart-wm '{...}'
--hub-started-ts T`, or `MI.restore_done_marker()`), within `--restore-done-max-s` (600 s) of the RESTORE marker:
without it the RESTORE marker excuses nothing (12.1). The archive's sha256 should be checked inside the hub right
before the restart against the `archive_sha256` the RESTORE marker signs (harness; review N1). RESTORE and RENAME markers now carry a random
`nonce` (added by the issuer's constructors, so `e9ops.py` inherits it). Optional, not used by the harness: `monitors`
(record-signing key fingerprints; a verifier given `--sign-pubkey` rejects the marker on another monitor's chain) and,
for RENAME, `from` (the digests before the change, review m4).

Verifier, per monitor and window (`exp/stages/e7_verify.py verify`): the E8 options (`--sign-pubkey`, `--late-bound`,
`--gap-s`, `--snapshot-at`, `--window`, `--scheme stable`, `--escrow`, `--trials`) plus `--operator-key operator.key
--operator-pubkey operator_pub.pem --purge-keep-s 2592000 --purge-tol-s <pre-registered> --restore-tol-s
<pre-registered> [--restore-max-age-s <pre-registered, default 86400>] [--restore-done-max-s <pre-registered, default
600>] --namemap-storage <copy of the hub's .storage at
the snapshot>`; once more with `--no-rowbind` for "suspect seconds without per-row binding" (now without the binding in
the purge rule too, 11.8), and once with `--no-purge-disconnect` for the comparison with the round-12 rule. Excused
disconnects: `purge.disconnects` and `purge.disconnected_rows`; per-day counts follow from their `second`. Memory of
one verification at full scale: 11.2 (1.8 GB resident for a whole-history window, 1.2 GB for a day).

## 9. Open issues

1. *(Resolved.)* The lead moved the E7/E8 extracts to `reproduce/snapshots/e7e8/`, so
   `test_saved_evaluation_chains_verify_as_v1` passes again.
2. *(Resolved, section 4a.)* The anchor no longer reads its whole chain on every append.
3. **Direct read was tested on macOS** (Python 3.13 and 3.9, SQLite 3.51) with the hub in a second process; not yet in
   the E9 image (python:3.12-slim, Debian's SQLite 3.40.1, which has `readonly_shm`, added in 3.22) on a read-only
   Docker volume. The smoke run must show `read: direct` and no `direct_open_failed`. A hub that has just started and
   not yet initialised its WAL index can make a direct read fail (`SQLITE_READONLY_CANTINIT`); that poll is then
   unobservable and the next one retries.
4. **quick_check in direct mode** reads the whole live database inside the read transaction, so with
   `HOMEPROV_QUICK_CHECK_EVERY=1` every poll holds a checkpoint's backfill off for that long (writes are never
   blocked). The cadence is a pre-registration choice; C1 measures the cost.
5. *(Resolved with `HOMEPROV_KEYLOG_REWIND=1`, 11.6.)* After a restore the monitor's keylog high-water stayed above the
   restored keys, so rows the hub wrote with keys that reuse the lost ones were bound by their segment roots only.
6. **`entity_id` renames are not excused** (3.2). A RENAME marker with `entity_id` is issued and listed, but the
   recorder rows it rewrites stay violations. Use a display-name rename in E9.
7. **HMAC-only markers.** The anchor host holds the operator's HMAC key, so a verifier given only `--operator-key`
   accepts markers the host could have made (A7 `forged_marker_hmac_only`). In E8 no operator signature existed; in E9
   pass `--operator-pubkey` as well.
8. **Records after the last witnessed head** are not pinned by the witness yet: the A7 `replay` case appends records
   after the last head and `chainverify` against every head still passes (the verifier's outcome does not change:
   duplicates of signed records). The result file reports `records_after_the_last_witnessed_head`.
9. **A delayed purge** (the host slept, E2_PURGE_DIAGNOSIS.md) deletes rows younger than the declared cutoff, which no
   rule excuses; `--purge-tol-s` does not bound that delay. E9's plan keeps the Mac awake and logs every sleep.
10. **Unobserved late rows at the end of an honest chain** appear only if a row is backdated into a sealed second after
   the last poll; E9's freeze (snapshot, then polls, then stop) avoids it, as E8's did.
11. A monitor that loses its state with `HOMEPROV_SINCE` set seals the full history again (2.2).
12. RESTORE was tested on synthetic recorders (now 14 tests, 11.1) and on the smoke-3 restore (11.1); E9's restore is
   its first use under the pre-registered rule.
13. A replayed marker is counted once by the verifier (11.3), but the anchor still appends a byte-identical operator
   request twice (by design: the issuer resends after a reply it could not verify, and a 409 for the copy would make an
   honest resend report failure). The chain therefore holds both; the verifier lists the copy in `markers.duplicates`.
14. The escrow recovery uses the roots of the verified window: a flagged second outside the window (a keylog second
   20 days back) is reported `no_anchored_root` in `recovery.seconds`, while its rows are recovered from the keylog
   escrow (`recovery.keylog`); seen in the full-scale run of 11.2. Unchanged from E7/E8.

## 10. After the E9 smoke runs (2026-10-10; E9_RUN_NOTES.md 6.1, 7.1-7.4, 7.12)

E7 and E8 still verify exactly as in section 6 with the code below (re-run into my scratch `reverify/final2/`: both E8
arms windows identical to the saved files except `params`, both E7 runs identical to the pre-E9 verifier's output);
`reproduce/verify_all.py` status ok (10 MATCH) and `reproduce/verify_e7e8.py --escrow` 8 of 8 MATCH, 219 of 219.
A7 re-run with this code into scratch: every outcome equal to `exp/out/e9_dishonest_anchor.json`; the result differs
only in the throwaway operator key's fingerprint and in the new, empty `tolerance_band` counter and `c0`/`c1` fields.
A4 re-run (E8 recorder) into scratch: still byte-identical across read modes, same record and escrow sizes as the
saved file. 13 new tests in `test_e9.py`.

### 10.1 Memory: the full-history first poll streams (monitor)
The first poll read every row of the history at once, twice (segment nodes and keylog rows), and built every escrow
line in memory. Now (STREAMED FULL-HISTORY SEAL in `monitor.py`): the segments one span of `STREAM_SPAN_S` = 3600 s at a
time (every second, minute and hour segment lies inside one hour, so each span's roots are exactly a single pass's;
empty spans are skipped by asking for the next timestamp), the keylog in batches of `STREAM_KEYLOG_BATCH` = 8,192 rows
(128-row sub-ranges cut where `keylog_chunks()` cuts them: a sub-range ends at its last key unless it is the range's
last, which ends at the watermark; one sub-range of lookahead decides that), and the escrow written per span and per
batch, segment lines first, then keylog lines, as before. The frozen roots join `pending` only when the whole pass
succeeded. No setting: the full-history first poll always streams; other polls are unchanged.
Proof on the saved E8 recorder (199 MB, 1,198,652 rows; scratch `stream_proof/`, not a result file), each monitor in
its own process, stable scheme, keylog, per-row binding, escrow, default record limits, fixed clock, polled until
nothing was pending (3 polls): the streaming monitor (`a60cdf59...`) and the first report's (`8d0c1040...`) gave the same
177 record bodies (182,949,570 bytes, one sha256 over all), the same state file after each poll and the same escrow
(2,639,029,262 bytes). **Peak resident memory: 750,043,136 bytes streaming, 4,282,318,848 before**; wall 85.8 s and
95.2 s. What still grows with the history: the frozen roots and the keylog entries (the records and, after a failed
append, the backlog need them) until they are anchored; with the default limits (64 records of 1 MiB per poll) they
leave within 3 polls here. Test: `test_streamed_full_history_seal_equals_one_pass` (span by span and in 256-row batches
against one span and one batch, with and without the binding, including a row with a malformed timestamp: same bodies,
state and escrow; every first-poll read at most one hour). Not measured inside Docker's VM (the harness's smoke).

### 10.2 PURGE tolerance band (verifier, A1)
With `--purge-tol-s tol`, each accepted PURGE marker now gives c0 = scheduled - keep and c1 = c0 + tol (the record's
`cutoff` stays c1). The hub's own cutoff lies in [c0, c1]: a row in that band is purged or retained (and then perhaps
disconnected), and everything below the hub's cutoff is deleted. So:
- a segment wholly before c0 must be gone (as before, now against c0, not c1);
- a segment reaching into the band (lo < c1 and hi > c0) is excused (`rule: tolerance_band`) only if no row older than
  c0 is left in it, nothing was inserted, every row still in it is exactly as committed or a valid purge disconnect
  (checked per row: its escrowed tuple, else its per-row binding; the predecessor must be absent and committed before
  min(c1, the row's timestamp)), and the band's deletions are purge-shaped: the latest row deleted from the band (its
  escrowed timestamp, else the second the keylog first observed it in) is not after the earliest row still in the band
  (ties in one second allowed when only the second is known). Otherwise it stays, with reason
  `band_deletion_not_purge_shaped`, `rows_left_in_a_segment_older_than_the_cutoff`, `rows_inserted_into_the_band_segment`,
  `a_row_in_the_band_segment_changed` or `a_row_in_the_band_segment_cannot_be_checked_without_binding_or_escrow`;
- key ranges: a removed row is purge-shaped if first observed before c0, or in the band when the band is purge-shaped;
  a changed row may be a disconnect if its timestamp is at least c0, its predecessor absent and committed before
  min(c1, its timestamp);
- with tol = 0 nothing changes (the straddling rule of round 12 applies to the one segment that straddles the cutoff).
Note: with tol = 0 a purge that fires even a fraction of a second late deletes rows of the second starting at c0,
which no rule then excuses; pre-register tol > 0 (the smoke used 60, which the offline script now uses by default).
Tests (7): retained and disconnected band rows excused (escrow; binding); the same late purge with tol = 0 flagged; a
band row deleted after a retained one flagged (escrow; binding); a band row edited flagged (escrow; binding).
Dry run on real rows (scratch `sim10b/`, not a result file): the `pre_oct9.db` copy purged with Home Assistant's
statements at c0 + 45 s (as if the purge had fired 45 s late: 18 states and 9 events of the band deleted, 8 states
of the band kept), verified with tol 60: without the disconnect rule 11 seconds, 9 minutes, 5 hours and 8 key
ranges left; with it nothing left, 11 band seconds, 1 band minute and 1 band hour excused, 16 disconnects in 11
seconds (both sources).

### 10.3 RESTORE (verifier)
A segment that reaches past R - tol is now excused (`rule: rows_new_or_from_the_backup`) when every row in it is either
written after the marker (timestamp >= I) or a backup row (key <= K) exactly as committed (escrowed tuple, else the
per-row binding), so the minute holding the restore point, which keeps the backup's rows from before R, is excused at
every granularity. A segment wholly before R - tol is never excused by a RESTORE. Without per-row evidence the earlier
rules apply. Test: `test_restore_point_inside_a_minute_is_excused_at_every_granularity` (R inside a minute that was
sealed before the restore; the minute fails without the marker and is excused with it; escrow and binding).

### 10.4 RENAME markers are consumed (verifier)
A RENAME marker now excuses one transition: the first transition (in record time order) whose changed parts it matches,
issued before it; it is then consumed (`namemap.rename_markers_consumed`). A declared change, reverted and applied again,
is flagged the second time. Test: rename (declared), rename back (declared), the same rename again (undeclared): excused,
excused, flagged.

### 10.5 Name-map records after the snapshot (verifier; E9_RUN_NOTES.md 7.12)
`check_namemap` now leaves out records timestamped after `--snapshot-at`, as markers after it are left out, so a day's
verification no longer reports a rename declared after its snapshot as an undeclared change. Test:
`test_namemap_records_after_the_snapshot_are_left_out`.

### 10.6 For the harness
- No new setting. The streamed seal is always on for the full-history first poll; `HOMEPROV_SINCE=0` as before.
- Pre-register `--purge-tol-s` > 0 (the offline check uses 60).
- `--restore-tol-s` as planned (30).

## 11. Code review fixes (2026-10-10; E9_CODE_REVIEW.md R1-R7, m1-m7, and the direct-read lock defect)

Scratch for everything below: `<scratch>`
($SP). The reviewed versions are kept there (`ref_review/`: monitor `a60cdf59...`, verifier `428e229b...`, issuer
`05bde4e4...`, anchors unchanged). Every reproduction of the review is now a repository test that asserts the attack is
DETECTED (`monitor/test_e9.py`, section "E9 code review"; one in `testbed/anchord/test_anchor_e9.py`), plus a test for the
lock defect: 27 new tests. Run against the reviewed code (a scratch tree `$SP/before_tree/` with the reviewed monitor and
verifier, the new issuer, the new tests; outcomes in `$SP/before_tree_outcomes.txt`, reasons in
`$SP/before_tree_reasons.txt`): **22 fail, 5 pass**, and the 5 that pass are the controls (laundering after a restore
flagged without `--restore-tol-s`; the reused-key deletion with the rewind setting off; the out-of-order band deletion
without a window; a purge-shaped band still excusing its successor's disconnect; a RENAME marker with the right `from`).
With the code below all 251 tests pass.

### 11.0 Direct read held no lock after validate_files() (coordinator; exp/out/e9_readonly_shm_lockdrop.json)
`direct_snapshot()` ran `validate_files()` (open, read, close of the live database, `-shm` and `-wal`) after pinning the
read transaction. Closing any descriptor of a file drops every POSIX advisory lock the process holds on it, so SQLite's
read lock was gone for the rest of the poll and a checkpoint could tear the snapshot. Now (monitor, NO FILE IS OPENED AND
CLOSED WHILE THE READ IS HELD): `validate_files()` runs before the connection is opened (3 tries, 20 ms apart) and again
after it is closed (`direct_finish()`: a failure then fails the poll closed, detail `after_read`, its rows unused); while
the read is held the files are read only through SQLite and through two descriptors opened before the connection and
closed after it (`direct_close()` closes them after the connection). Test
`test_A4_a_direct_read_keeps_its_snapshot_while_the_hub_checkpoints`: the hub (another process) rewrites 400 rows the
snapshot reads and runs `PRAGMA wal_checkpoint(TRUNCATE)` while the direct read is held; it must get busy = 1, the WAL
must not be reset, the snapshot's watermark and roots must be unchanged and quick_check "ok", and the checkpoint must
succeed once the read has ended. On the reviewed monitor the checkpoint returned busy = 0 (the lock was lost); now it
passes. A4 re-run with this code into scratch (`$SP/a4_identity_review.json`): `all identical: true`, for both recorders
and both configurations, with the record and escrow sizes of `exp/out/e9_direct_read_identity.json` (E8 recorder, E9
configuration: 179 records, 185,549,779 bytes, escrow 2,642,197,406 bytes; E7 recorder: 174, 180,463,744, 2,566,469,329),
hub files unchanged, every direct poll read directly. C1's direct mode should be measured again on this code.

### 11.1 R1 (critical): the RESTORE rule ends when the restored recorder is read; K from the signed backup_wm
(The end point B below was refined by the re-check: 12.1. A falling watermark alone no longer ends the rule, and
`restore_not_observed` no longer exists; without a RESTORE_DONE marker nothing is excused.)
Verifier (`restore_points`, `restore_read_back`, `apply_restore`):
- A RESTORE marker counts only with `backup_wm` {"states", "events"} signed into it (else rejected,
  `no_signed_backup_wm`), R <= I, and I - R <= `--restore-max-age-s` (11.9). K = `backup_wm`. If the recorder's largest
  key among rows timestamped before I differs from K, the marker excuses nothing (`backup_wm_disagrees_with_the_recorder`).
- B = the copy time of the first observable poll after I whose watermark, in either table, is below the largest
  watermark of the polls before I (the first poll that read the restored recorder). No such poll: the marker excuses
  nothing (`restore_not_observed`). Reported per marker: `status`, `read_back_at`, `read_back_poll`, `backup_last_key`,
  `recorder_last_key_before_marker`.
- Segments: only a segment whose sealing poll copied before B and which ends after R - tol, and only if every row it
  holds now is a backup row (key <= K) exactly as committed (escrowed tuple, else the per-row binding) and, for a second
  with a verified escrow line, every sealed row that is gone had a key above K (rule `rows_from_the_backup`; it replaces
  `rows_new_or_from_the_backup`, `segment_after_restore_point` and `straddling_segment`: no row counts as acceptable for
  being "new", and the coarse branch is gone, an emptied segment passing as `all([])`). Reasons otherwise:
  `segment_wholly_before_the_restore_point`, `segment_sealed_after_the_restored_recorder_was_read`,
  `a_row_that_is_not_an_unchanged_backup_row`, `a_backup_row_cannot_be_checked_without_binding_or_escrow`,
  `a_backup_row_is_gone`.
- Key ranges: only ranges committed by a poll that copied before B (`range_committed_after_the_restored_recorder_was_read`
  otherwise); every row at or below K present and unchanged; every logged row above K first observed no earlier than
  R - tol; a row above K present now (a lost key the hub reused) must be timestamped at or after I and is listed in
  `restore_reused_keys`, its content being bound by its own post-restore segment root (and, with
  `HOMEPROV_KEYLOG_REWIND=1`, by the ranges committed from B on), which no RESTORE rule excuses.
Tests (all fail on the reviewed verifier except the control): `test_R1_control_laundering_after_the_restore_is_flagged_without_restore_tol`;
`test_R1_a_restore_marker_does_not_excuse_a_laundering_after_the_restore[0, 1]` (the review's S1 laundering 900 s after
the restore: flagged seconds exactly the laundered second; with the rewind setting the laundering also fails a key range
the marker cannot excuse); `..._an_edit_with_escrow`; `..._deleting_every_row_of_a_later_second`;
`test_R1_a_low_key_row_in_a_second_sealed_before_the_restore_was_read_is_not_excused` (the review's "lost key reused in a
second in [I, restore)" case); `test_R1_a_restore_marker_without_a_restore_excuses_nothing`;
`test_R1_K_comes_from_the_signed_backup_wm_and_a_mismatch_fails_closed[disagrees, absent]`. The shipped restore tests
pass unchanged except the rule name in `test_restore_point_inside_a_minute_is_excused_at_every_granularity`
(`rows_from_the_backup`); `restore_scenario` now signs the backup's keys into the marker.
On the smoke-3 restore (real Home Assistant restore, `HOMEPROV-P13-exp/e9/smoke/e9s_smoke3`, copy monitor, day-3
verification as `e9_score.py` ran it), the reviewed verifier and this one give the same 8 flagged seconds and the same
key-range violations; B = poll 638, copy 1791592070.52 s (I = 1791592033.35; the hub restarted at 00:27:45 UTC); K from
`backup_wm` = recorder (935,470 states, 525,472 events); excused 32 seconds, 2 minutes and 43 key ranges (reviewed code:
33, 2, 43; the one second no longer excused, 1791592069, was sealed by the read-back poll itself and is not an
attributable violation: its coverage root reproduces). Outputs in `$SP/r5/ref/` and `$SP/r5/new/`.

### 11.2 R2 (high): the escrow is indexed and read lazily; full-scale measurement
Verifier: class `Escrow` indexes the escrow file in one pass by byte offset (per sealed second, per keylog sub-range,
found with regular expressions on the raw line; the monitor writes sort_keys JSON and node values are lists, so these keys
occur only at the top level); `PurgeEvidence` and `recover()` read and parse only the seconds and ranges they need;
`escrow_keylog_ranges()` streams every keylog line once for the counts `keylog_lines_verified`/`rejected` and keeps only
the wanted ranges' lines (the earlier order: smallest `seq_local`, then file order); `recovery.escrow_lines` is the
index's count of sealed-second lines. `verify()` still accepts a list of lines (tests, scripts); `run()` passes the path.
The output is unchanged: E7 and E8 verify byte-for-byte as before (11.15).
Measured in scratch (`$SP/r2/full_scale_verify.json`; input built by `$SP/r2/build.py`): the E8 recorder (766,994 states,
431,658 events) sealed from its full history by this monitor (stable, keylog, per-row binding, escrow, rewind, signed
records: escrow 2,643,627,518 bytes, 301 records), two hours of hub rows polled every 60 s, Home Assistant's purge of the
oldest day under a signed PURGE marker (30,683 states), and five new and two 20-day-old rows edited. One verification
with every E9 option (`--escrow`, operator keys, purge keep and tolerance 60 s, restore tolerance 30 s, the monitor's key),
`/usr/bin/time -l`, one process, nothing else of mine running:

| Window | wall | max resident | peak footprint | flagged seconds | recovery |
|---|---|---|---|---|---|
| the two hours (a "day" verification) | 64.8 s | 1,168,932,864 B | 1,355,925,112 B | 6 (the 5 edited new rows' seconds, the old rows' second) | 5 seconds and both failed key ranges verified against the anchor |
| the whole history (a "night" verification) | 140.3 s | 1,811,660,800 B | 2,985,429,800 B | the same 6 | all 6 seconds and both ranges verified |

Same input, reviewed verifier against this one (smoke-3, 352,946,741-byte escrow, copy monitor): night1_post 27.4 s /
2,876,276,736 B against 14.6 s / 398,344,192 B; day2 20.8 s / 3,094,872,064 B against 8.5 s / 293,306,368 B; day3
15.6 s / 3,098,968,064 B against 9.2 s / 280,805,376 B (wall / max resident); flagged seconds equal in all three. The
reviewed verifier was not run at full scale (by the review's ratio it needs about 20 GB; the E2 night was running on
this Mac). With these numbers two jobs in parallel need at most about 6 GB of footprint; `E9_VERIFY_JOBS` is the
lead's call (e9_score.py is not mine and was not changed).

### 11.3 R3: a replayed or duplicated marker counts once
Verifier (`chain_markers`): a marker is identified by the SHA-256 of its canonical JSON; only its first copy on the chain
counts, later copies are listed in `markers.duplicates` (`chain_seq`, `kind`, `duplicate_of`); two different markers
with the same `nonce` are not one issuance (the later is rejected, `nonce_reused`); a marker naming `monitors` (record-
signing key fingerprints) is rejected on another monitor's chain when `--sign-pubkey` is given
(`marker_for_another_monitor`). Issuer: RESTORE and RENAME markers carry a random 128-bit `nonce`
(`restore_marker`, `rename_marker`; PURGE markers keep their format, a duplicate PURGE excusing nothing more), and
optional `monitors` (`--monitors`). Anchor: unchanged (see 9.13). Tests: `test_R3_a_replayed_rename_marker_counts_once`
(the review's replay: excused, excused, flagged; one duplicate listed);
`test_R3_a_byte_identical_operator_request_appended_twice_counts_as_one_marker` (the real `anchord_linked.py` appends the
resent request at seq 2; the verifier accepts seq 1 only and lists seq 2 as its duplicate).

### 11.4 R4: the tolerance band in windowed verifications, and for a successor's disconnect
Verifier (`apply_purge`): the earliest row still in the band, r_min, is read from the whole recorder (`min(ts)` over
states and events with c0 <= ts < c1, finite timestamps) instead of the loaded window. A deleted predecessor committed at
or after c0 (in the band) is accepted in the purge-disconnect rule (`restore_rows`, reason
`referenced_row_in_the_band_not_purge_shaped`), in the band segments' per-row check (`row_verdict`'s predecessor check)
and in the key-range disconnect check (`predecessor_in_the_band_not_purge_shaped`) only if the band is purge-shaped
(`band_ok`) and the predecessor precedes r_min. Tests: `test_R4_an_out_of_order_band_deletion_is_flagged_in_a_windowed_verification_too[False, True]`;
`test_R4_a_successor_disconnect_needs_a_purge_shaped_predecessor[rowbind, escrow]` (whole chain and the day's window);
`test_R4_control_a_purge_shaped_band_still_excuses_the_successor_disconnect`.

### 11.5 R5: a host that withholds or moves markers (result file, no change of design)
`exp/stages/e9_dishonest_markers.py` -> `exp/out/e9_dishonest_anchor_markers.json` (sha256
`8b3bf4606246d6ba4cb764a3ea016deab67b71b9e13bd3a74cc8299eab8e18ba`), on the smoke-3 chains of both monitors (real
signed PURGE, RENAME and RESTORE markers), verified as `e9_score.py` verified them; every case's chain relinked and
checked against every witnessed head. Same numbers for both monitors:

| Verification | case | flagged seconds | seconds newly violation | violation -> not violation | name map unexcused | chainverify |
|---|---|---|---|---|---|---|
| night1_post (47,528 seconds classified) | honest | 3 | - | - | 0 | ok |
| | withhold_purge | 23,809 | 23,806 | 0 | 0 | fails |
| | replay_markers | 3 | 0 | 0 | 0 | ok (12 records after the last witnessed head) |
| day2 (225) | honest | 3 | - | - | 1 (the undeclared attack swap) | ok |
| | withhold_rename | 3 | 0 | 0 | 5 | fails |
| | reorder_rename | 3 | 0 | 0 | 3 | fails |
| | replay_markers | 3 | 0 | 0 | 1 | ok (12 after) |
| day3 (217) | honest | 8 | - | - | 1 | ok |
| | withhold_restore | 51 | 43 | 0 | 1 | fails |
| | replay_markers | 8 | 0 | 0 | 1 | ok (12 after) |

So the host can turn a benign purge, restore or rename into violations (a false accusation, detectable by the witness's
every-head check unless the markers were never appended), never a violation into a match; a replayed marker changes
nothing. A7's per-party statement holds for monitor records only; with markers, "the host can withhold markers; without
the operator's own issuance log that becomes a false accusation" belongs in the per-party table. Accepting markers from
the operator's issuance log (`--markers issuer.jsonl`) was not implemented (design unchanged, as asked). The mechanisms
are also covered by the shipped tests `test_A1_not_excused_without_a_valid_marker[none]` and
`test_A3_namemap_change_is_excused_only_by_a_prior_operator_rename[declared_after]`.

### 11.6 R6: the keylog after a restore (monitor setting, and key epochs in the verifier)
Monitor, `HOMEPROV_KEYLOG_REWIND=1` (KEYLOG REWIND): an observable poll that finds a table's watermark below its
high-water restarts that table's keylog at the largest key of a row timestamped before the copy time of the last poll
that advanced the keylog (the state's `keylog_copy_at`; after a restore that is exactly the backup's last key, since the
backup's rows predate that poll and the hub's later rows follow it), commits every row above it from this first
observation on, and records `"keylog_rewind": {table: {"from", "to", "wm"}}` in the record and the head (alarm line
`keylog_rewind`). The review proposed `hw = wm`; that leaves the rows the hub wrote between the restart and the first
poll bound by segment roots only, so the bound above is used. Verifier (`PurgeEvidence`, KEY EPOCHS): keys in a rewound
interval (to, from] have a new incarnation from the rewinding poll on; their evidence (first-observed second, row hash,
escrowed tuple of that exact second, keylog tuple of that exact range) is the latest incarnation's. Without rewind
records nothing changes. Tests: `test_R6_a_reused_key_row_deleted_before_its_second_is_sealed[0, 1]` (a post-restore row
with a reused key deleted before its second is sealed: undetected with the setting off, the gap of the review; flagged
with it on; the rewind record is `{"from": 100, "to": 60, "wm": 65}` for states, `{"from": 15, "to": 9, "wm": 9}` for
events); `test_R6_the_evidence_of_a_reused_key_is_its_post_restore_row` (all 20 reused keys: first-observed second of
the new row, `row_verdict` True). The harness must set `HOMEPROV_KEYLOG_REWIND=1` (section 8).

### 11.7 R7: a row written after the purge and deleted is not "purged"
Verifier: a removed row counts as purged only if the poll that first observed it copied the recorder at or before the
cut's `first_seen_by` = scheduled_ts + purge_tol_s + `PURGE_SEEN_SLACK_S` (60 s; recorded in each cutoff and in
`params.purge_seen_slack_s`), else `removed_row_written_after_the_purge`. Bound: a row forged and deleted within that
window (2 minutes after the scheduled time with tol 60) is still excused, as one the purge itself deleted would be. Test:
`test_R7_a_row_written_after_the_purge_and_deleted_is_not_excused_as_purged`.

### 11.8 m1: `--no-rowbind` uses no binding anywhere
`PurgeEvidence(rowbind=False)` keeps no row hash, and the purge and restore key-range rules ignore `bind` with it. Test:
`test_m1_without_rowbind_the_purge_rule_does_not_use_the_binding` (the purge's disconnects are excused with the binding,
not without it; every failed range prefix-ranked).

### 11.9 m2: the restore point's age is bounded
`--restore-max-age-s` (default 86,400 s; `RESTORE_MAX_AGE_S`): a marker with I - R above it is rejected
(`restore_point_older_than_the_maximum`, in `restore.rejected`). E9's restore has I - R of a few minutes (smoke 3: 120.7
s); pre-register the value. Test: `test_m2_a_restore_marker_older_than_the_maximum_is_rejected`.

### 11.10 m3: direct read fails closed when its snapshot moved
See 11.0: `read_raced` when the WAL header's checkpoint sequence and salts or the database header's change counter
differ between the read right after the snapshot is pinned and the read after the rows. Both reads are inside the read
transaction (not before `BEGIN`, as the review suggested: between an earlier read and the pin a legitimate WAL restart
can happen, a false alarm). A probe in scratch (`$SP/m3probe/`, SQLite 3.51): while a reader holds a snapshot a passive
checkpoint backfilled 2,213 frames and changed neither the salts nor the counter, and a RESTART checkpoint returned busy;
only after the read ended did a RESTART and the next write change them. Test:
`test_m3_direct_read_fails_closed_when_the_read_raced_or_the_files_changed_during_it` (a moved stamp: `read_raced`, no
roots or keylog in the record; a file check failing after the read: `after_read`; `validate_files()` never called
while the read is held; an untouched direct poll leaves no descriptor open).

### 11.11 m4: a RENAME marker may name the digest before the change
Issuer: `rename_marker(..., from_parts=)`; with `--storage` the CLI computes it (`current_part_digests`). Verifier: a
marker with `from` excuses a part's change only from exactly that digest. Optional (the harness's markers have no
`from`; the absolute-digest race of the review stays impractical with 5 s polls). Test:
`test_m4_a_rename_marker_with_a_from_digest[right, wrong]`.

### 11.12 m5: HOMEPROV_SINCE
Non-finite values (`inf`, `-inf`, `nan`, `1e400`) stop the monitor at start. With `0`, the keylog's first range starts
at key 0 and the first poll reads from the hour of the smallest finite timestamp when that is negative (unchanged
records otherwise). Test: `test_m5_since_must_be_finite_and_zero_has_no_lower_bound` (a row at -7200.5 s is sealed, its
edit flagged).

### 11.13 m6: anchor cache (information)
Documented limit kept (4a): a rewrite at rest that keeps the file's size and last line but changes the line count makes
`seq` and the push offsets diverge from the file until a restart; only the anchor host can do it, and the every-head
witness check still catches a rewrite of witnessed records. No change.

### 11.14 m7: stale documents
This file: section 3 no longer says to use both operator keys (only the signature counts for a third party; e9_score.py
passes `--operator-pubkey`). `E9_PREREG_DRAFT.json` is the lead's and was not edited; it is stale in: lines 28 and 483
(RENAME markers "not consumed"; they are consumed since 10.4 and counted once since 11.3), line 514 (the three smoke-3
items, all fixed), and it needs the RESTORE rule of 11.1 (with `--restore-max-age-s`), `PURGE_SEEN_SLACK_S` (11.7) and
the monitors' `HOMEPROV_KEYLOG_REWIND=1` (11.6).

### 11.15 Re-runs with this code (all into scratch)
- E8 (`$SP/reverify/final3/`): both arms windows identical to `exp/out/e8_main_{stable,closure}_verify_main.json` except
  `params`. E7: both runs identical to the pre-E9 verifier's output (`$SP/reverify/before/`) except `params`.
- `reproduce/verify_all.py`: status ok, 10 runs MATCH (`$SP/repro/va6.json`). `reproduce/verify_e7e8.py --escrow`: 8 of
  8 verifier runs MATCH, 219 of 219 printed-number checks MATCH (`$SP/repro/e7e8_6.json`).
- A4 (`$SP/a4_identity_review.json`): 11.0.
- A7 (`$SP/a7/review_recheck.json`): every outcome, transition and property equal to `exp/out/e9_dishonest_anchor.json`;
  differences only in the throwaway operator key's fingerprint and new fields (`c0`, `c1`, `first_seen_by` in the
  cutoffs, empty `markers.duplicates`, the empty `tolerance_band` counter).
- A1 offline on the 2026-10-10 pair: run with the code of section 12 after the night driver finished (5.3).

## 12. Re-check fixes (2026-10-10; E9_CODE_REVIEW.md "Re-check": N1, N2)

The re-check closed R1-R4, R6, m1-m5 and m7 and confirmed the lock fix; R5 stays a documented property (11.5) and R7's
residual window (scheduled + tol + 60 s) is documented (11.7). Its two findings are fixed below. The pre-re-check
versions were rebuilt exactly from the reviewer's diffs (`$SP/ref_recheck/`: monitor `3f277d39...`, verifier
`59a1b228...`, issuer `0c644d43...`). 10 new tests; on that code (scratch tree `$SP/before_tree2/`, with the new issuer;
`$SP/before_tree2_outcomes.txt`) all 10 fail, and they pass now. 261 tests pass.

### 12.1 N1 (high): planted keys could postpone the end of the RESTORE excuse; RESTORE_DONE ends it
The reviewer's attack: the restored recorder also holds a state and an event with keys above the pre-restore maximum and
timestamps after the marker (a rewritten archive in `/config/backups`), so no poll sees the watermark fall; B came only
when the adversary deleted them, and a whole second deleted after the restore was excused with no trace. Fix (verifier
`restore_points`, `restore_done_poll`, `apply_restore`; issuer `restore_done_marker`, `--kind RESTORE_DONE`):
- RESTORE_DONE marker: `{"marker": "RESTORE_DONE", "restore_nonce", "restore_sha256"` (the RESTORE marker it closes: its
  nonce and the SHA-256 of its canonical JSON; each must match when present, at least one present)`, "post_restart_wm"`
  (the restored recorder's largest keys the operator read after the restart)`, "hub_started_ts"?, "issued_ts",
  "issuer": "operator", "nonce"}`, signed like every marker.
- A RESTORE marker excuses nothing without a RESTORE_DONE that was issued at or after its I and issued and anchored
  (`recv_ts`) at most `--restore-done-max-s` (default 600 s, `RESTORE_DONE_MAX_S`, pre-register it) after I
  (`restore_done_missing`; late or malformed ones are in `restore.rejected`).
- B = the copy time of the first poll anchored after the RESTORE_DONE record (no poll after it: the DONE's issued_ts),
  or the falling-watermark poll when that is earlier (`read_back_by`: `restore_done` | `falling_watermark`; both times
  reported). This also fixes the honest case the re-check named: a hub that writes past the old maxima before the
  monitor's first post-restore poll left B unfound and the restore unexcused.
- With `hub_started_ts` H (between I and the DONE's issued_ts): a segment starting at or after H is never excused
  (`segment_starts_after_the_hub_restarted`), a gone row (escrowed tuple of a second, or a key range's logged row) must
  have been committed before H, and a row at a reused key must be timestamped at or after H. Without H the window
  between the restart and B stays open for whole-second deletions of rows the restored hub wrote (a test shows both);
  the harness should pass the hub's start time.
Tests: `test_N1_planted_max_keys_cannot_postpone_the_end_of_the_restore_excuse[escrow-False, escrow-True, rowbind-True]`
(the re-check's two attacks: flagged, the restore itself still excused); `test_N1_without_a_restore_done_marker_the_restore_excuses_nothing`;
`test_N1_a_restore_done_marker_later_than_the_maximum_is_rejected`; `test_N1_an_honest_restore_whose_watermark_never_falls_is_excused_under_its_restore_done`;
`test_N1_the_hub_start_in_restore_done_closes_the_window_before_the_restore_done_poll[True, False]`. `restore_scenario`
issues the RESTORE_DONE (with the hub's start) by default. The smoke-3 chains hold no RESTORE_DONE, so under this code
their restore is no longer excused; `exp/out/e9_dishonest_anchor_markers.json` (11.5) was written with the verifier of
section 11 (`59a1b228...`, recorded in the file) and is not re-run.

### 12.2 N2 (low-medium, availability): a direct read that raced a legitimate WAL restart is repeated
A read that begins on a fully checkpointed WAL holds read mark 0 and reads only the database file; the hub's next commit
then legitimately restarts the WAL, and the stamp check (11.10) failed the poll closed (`read_raced`) although the
snapshot was intact. Monitor (DIRECT READ RETRY): a direct poll whose read raced is read again, up to 3 reads
(`DIRECT_READ_ATTEMPTS`), as copy mode repeats a raced copy; escrow lines a raced full-history pass wrote are dropped
(the escrow file is cut back to its size before the read); `read_attempts` is in the poll's summary and cost log when
above 1, and in the record's `detail` when every read raced. Records are unchanged otherwise. Test:
`test_N2_a_direct_read_that_raced_a_legitimate_wal_restart_is_repeated` (the re-check's probe case B inside a poll:
two reads, the second succeeds, and its records and escrow equal a copy-mode poll's). Found on the way, macOS's system
SQLite (Python 3.9.6) truncates the WAL to 32 KiB at a restart (a compiled-in journal size limit), which
`validate_files()` reads as a partial frame; Home Assistant does not set `journal_size_limit` and Debian's SQLite has
no limit, so the test pins `journal_size_limit=-1` on its hub.

### 12.3 A regression of 11.0, found while fixing N2
From the lock fix on, the end of a direct read (`direct_finish`) was assigned to the variable that held the poll's
first-observed malformed and invalid-text rows, so a direct poll's record lacked `malformed`/`invalid_text` where a
copy poll's had it (no E9 run used that code). Fixed; test `test_A4_malformed_rows_are_reported_in_direct_mode_as_in_copy_mode`.

### 12.4 Re-runs with this code (scratch)
E8 both arms identical to the saved files except `params`; E7 both runs identical to the pre-E9 output
(`$SP/reverify/final4/`). `reproduce/verify_all.py` status ok, 10 MATCH (`$SP/repro/va7.json`);
`reproduce/verify_e7e8.py --escrow` 8 of 8, 219 of 219 MATCH (`$SP/repro/e7e8_7.json`). A4: all identical, the same
record and escrow sizes as the saved file (`$SP/a4_identity_recheck.json`). A7: every outcome equal to
`exp/out/e9_dishonest_anchor.json`, differences only in the throwaway key's fingerprint and the new fields of 11.15
(`$SP/a7/recheck_n1.json`). The full-scale verification of 11.2 was not repeated (the escrow and evidence code did not
change).

