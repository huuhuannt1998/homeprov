# E9 pre-run notes (part C: C1, C2, C3) — for the lead

Written 2026-10-09 by the E9 part-C agent. Nothing committed or pushed; the paper was not touched. No `hpr-*`, `e1-*`,
`e2-*`, `rka-*`, `ds-*`, `delaysteer-*` container, the QEMU VM, or `HOMEPROV-P13-exp/e2night/` was started, stopped,
exec'd into, rebuilt or modified, and the default anchor was not touched. The E2 night (`driver_oct10.sh`) owns the
default deployment until 2026-10-10 05:00 UTC; this work used only its own containers and images.

Hard rules (AGENT_BRIEF section 2): every number below is read from a saved result file under `exp/out/`, named with
its script; no estimates; no key recorded (only fingerprints / public keys). The attack is a controlled harness, not a
released integration (see C2).

## Containers / images / scratch used (all removable, none of the protected set)
- `e9k-anchord`, `e9k-monitor`, `e9k-writer`, `e9k-copy`, `e9k-keygen` (C1); `e9shm-writer`, `e9shm-reader`,
  `e9shm-copy` (C1 probe); `e9dc-anc-ext`, `e9dc-anc-ip` (C2). All created with these prefixes and removed at the end of
  each run (teardown trap). The volumes `e9k-master-k{1,5,15}` were removed after the direct-mode re-run
  (2026-10-10 05:46 UTC); no `e9k-`, `e9dc-` or `e9shm-` container or volume remains. Images left: `e9c1-mon:8ad9e2d77f2d`
  (the re-run's monitor; `e9c1-mon:38370b2a51ea` was removed). The script that produced `e9_cost_scale.json` is kept as
  `HOMEPROV-P13-exp/e9pre/c1/e9_cost_scale_at_4101120995aa.py` (the repository script has since gained the
  quick_check, read_attempts and WAL fields used by the re-run).
- Images: `hpr-monitor:e8` (monitor.py `3e479ae0`, the evaluated copy-mode monitor) for the copy scaling curve;
  `e9c1-mon:38370b2a51ea` built from the working-tree `monitor/monitor.py` (sha256 `38370b2a51ea47b5…`), which carries
  the parallel code agent's `HOMEPROV_READ=direct` mode, for the copy-vs-direct comparison and direct mode. Both built
  from `monitor/Dockerfile.sign` (pinned `cryptography`). `hpr-anchord:e8` is reused read-only as the anchor image.
- Work tree: `<research-dir>/HOMEPROV-P13-exp/e9pre/` (source copy, synthetic masters, run dirs). The source
  recorder `src/pre_oct9.db` is a byte copy of `e2night/pre_oct9.db` made `chmod 444`; `e2night/pre_oct9.db` was only
  read.

---

## C1 — cost at scale (R1 W5, R2 W4, R3 W5)

Result: `exp/out/e9_cost_scale.json`. Script: `exp/sp2027/e9_cost_scale.py` (subcommands `generate`, `writer`,
`harness`, `run`, `summarize`).

### Method
1. **Synthetic recorders** (`generate`), real 2026.7.4 schema (schema_changes version 53) and value distributions,
   derived from the read-only source: the schema is copied verbatim (every `CREATE`), then the lab's 25-entity
   population is replicated K times. K = 1, 5, 15 give **0.19, 0.96 and 2.9 GB** (`masters` in the result file). Each
   replica gets its own `states_meta`, `state_attributes` (friendly names renamed, `hash` recomputed FNV-1a-32 as the
   recorder does) and `event_data`; every `states`/`events` row is copied with its timestamps shifted cyclically within
   the source span by a per-replica offset, context ids re-derived (the 48-bit ms prefix shifted the same way, the other
   80 bits from BLAKE2b so rows that shared a context still share one), `old_state_id` re-linked, every other column as
   in the source. Rows inserted in global time order into the source's own indexes; `ANALYZE`; WAL. Validation (checked
   on K=1): `quick_check ok`; identical row counts and null/shared-context structure to the source.
2. **Write load** (`writer`, in its own unlimited container): replays the recorder's own rows of one day earlier,
   second by second (so the rate is K× the lab's), new keys, fresh shared contexts, `old_state_id` chained, one
   transaction per second, recorder pragmas (WAL, `cache_size=-16384`, `synchronous=NORMAL`, `foreign_keys=ON`).
   Measured lab rate ≈ 35 rows/min (writer `rows_per_minute`), matching E8's lab window.
3. **Harness** (`harness`, inside the monitor container): loads `/app/monitor.py` exactly as the monitor runs it
   (E9 config: stable scheme, coverage, keylog, escrow, Ed25519 signatures, tagged replies) and calls `tick()`
   WARMUP+POLLS times. Each monitor phase function (`snapshot`/`validate_copy`/`watermark`/`keylog_poll`/`load`/
   `commit`/`escrow_*`/`append`/`save_state`, and the `direct_*`/`quick_check` functions) is timed; per poll it records
   `tick()`'s wall time and its own `copy_ms`/`load_ms`/`commit_ms`/`append_ms`, the deltas of `/proc/self/io` (`rchar`,
   `wchar`, `read_bytes`, `write_bytes`) and of the container cgroup `io.stat` (`rbytes`, `wbytes`). A clock offset makes
   the synthetic history end where the writer starts, so the open window holds the last hours, as on a hub.
4. **Fixed load**: POLLS = 30 measured + WARMUP = 3, PERIOD = 5 s. **Stated Docker limits on the monitor container**:
   `--cpus 1`, `--memory 1g`, `--device-read-bps /dev/vda:100mb`, `--device-write-bps /dev/vda:50mb` (the VM's data
   disk; the limits are recorded in the result as `limits_monitor_container`). The live recorder volume is a fresh copy
   per run via `dd … iflag=direct oflag=direct` (uncached). The writer container is unlimited (it stands in for the hub).

### Commands
```
python3 exp/sp2027/e9_cost_scale.py generate --k {1,5,15} --out …/master_k{1,5,15}.db
python3 exp/sp2027/e9_cost_scale.py run --k K --mode {copy,direct} --image IMG --tag TAG
python3 exp/sp2027/e9_cost_scale.py summarize --runs RUNDIR … --out exp/out/e9_cost_scale.json
```
Copy mode: image `hpr-monitor:e8` (3e479ae0) for the scaling curve, and `e9c1-mon:38370b2a51ea` at K=1,5 as a
same-code cross-check. Direct mode (`HOMEPROV_READ=direct`): `e9c1-mon:38370b2a51ea` at K=1,5,15, with `quick_check` at
every poll (the code's default, `HOMEPROV_QUICK_CHECK_EVERY=1`) and once per hour (`=720` at 5 s polls, i.e. only the
first of the 33 polls). Copy K=5 also at the hourly cadence. Both modes read the recorder read-only (direct uses
`mode=ro&readonly_shm=1`, so the read-only mount is kept). Runs were made 2026-10-09 21:33 to 2026-10-10 01:35 UTC.

### Results (`exp/out/e9_cost_scale.json`, sha256 `8733d81cd38beea9…`; 30 measured polls per run; MB = 10^6 bytes)
The direct-mode rows of this table were measured on 38370b2a (before the lock fix) and are superseded by the re-run on
8ad9e2d7 below; the copy-mode rows stand.
Masters: K=1 191,459,328 B (1,176,999 rows); K=5 961,363,968 B (5,884,995); K=15 2,935,984,128 B (17,654,985).
"Observable" = polls that sealed (not `evidence_unobservable`). Bytes are per-poll medians.

| run (K, mode, monitor) | observable | total s median / p90 / max | storage read MB | written MB (cgroup) | writer rows/min |
|---|---|---|---|---|---|
| K=1 copy, 3e479ae0 | 30/30 | 4.13 / 4.51 / 4.72 | 0.0 | 194.0 | 35.27 |
| K=5 copy, 3e479ae0 | 30/30 | 42.67 / 64.63 / 76.72 | 1788.5 | 967.8 | 144.29 |
| K=15 copy, 3e479ae0 | **0/30** (`copy_raced` 30) | 175.17 / 181.30 / 188.22 | 8739.1 | 8833.7 | 447.21 |
| K=1 copy, 38370b2a | 30/30 | 3.92 / 4.00 / 4.31 | 0.0 | 193.9 | 34.91 |
| K=5 copy, 38370b2a | 30/30 | 30.33 / 54.79 / 56.67 | 1799.4 | 966.9 | 144.50 |
| K=5 copy, 38370b2a, qc hourly | 30/30 | 22.39 / 42.32 / 45.92 | 953.5 | 966.8 | 146.01 |
| K=1 direct, qc every poll | 30/30 | 0.37 / 0.44 / 0.51 | 0.0 | 0.1 | 36.09 |
| K=5 direct, qc every poll | 30/30 | 1.77 / 2.41 / 4.30 | 0.0 | 0.2 | 144.97 |
| K=15 direct, qc every poll | **0/30** (`quick_check_failed` 30) | 53.36 / 73.68 / 136.17 | 3246.3 | 0.0 | 421.49 |
| K=1 direct, qc hourly | 30/30 | 0.19 / 0.26 / 0.48 | 0.0 | 0.1 | 35.66 |
| K=5 direct, qc hourly | 30/30 | 0.56 / 0.60 / 0.61 | 0.0 | 0.2 | 147.08 |
| K=15 direct, qc hourly | 30/30 (its first, warm-up poll failed `quick_check`) | 1.75 / 1.97 / 2.96 | 0.0 | 0.3 | 464.69 |

What it says (all from the file):
- **Copy mode writes the whole recorder every poll** (194 MB at 0.19 GB, 967 MB at 0.96 GB, 8.8 GB at 2.9 GB, the
  last being three attempts) and its time grows with size; the copy-mode monitor's measured write rate is 78.3 GB per
  hour at K=1 and 82.7 GB per hour at K=5 (3e479ae0 runs, `bytes_written_per_hour_cgroup`). At 0.19 GB the per-poll time is dominated by
  `quick_check` (`phase_validate_copy` median 3.72 s of 4.13 s).
- **At 2.9 GB under these limits copy mode seals nothing**: each copy attempt outlasts the writer's WAL restart, so all
  30 polls fail closed as `copy_raced` (the monitor working as designed, but evidence is unobservable throughout).
- **Direct read removes the copy**: written bytes fall to 0.1-0.3 MB per poll at every size, and with `quick_check`
  hourly the poll takes 0.19 / 0.56 / 1.75 s (median) at 0.19 / 0.96 / 2.9 GB, every poll observable.
- With `quick_check` at every poll, direct read at 2.9 GB failed every poll (`quick_check_failed`) on 38370b2a; this was
  the defect below (fixed; see the re-run), not slowness alone: the masters pass `quick_check` offline (K=15 716,793 pages, K=5 234,708 pages), and the
  failing cell pointed to page 716,804, beyond the master's last page, i.e. a page the writer appended during the read.

### Direct-mode re-run on the fixed code (2026-10-10, lead's request) — supersedes the direct rows above
Result: `exp/out/e9_cost_scale_direct_final.json` (sha256 `bce6e87118f9e4de660d5b3673a755cebffe323cb80e1650b1eda13f2774f498`;
`e9_cost_scale.json` is unchanged). Code: a pinned copy of `monitor/monitor.py` sha256
`8ad9e2d77f2d098af1e81ed509445631dc3d3ba2d349fddff75bfd920a7ab8ae` (the lock fix of E9_IMPL_NOTES.md 11.0 plus the N2
retry of raced reads), image `e9c1-mon:8ad9e2d77f2d`, in-image hash checked before any run. Same masters, limits, 30
measured polls after 3 warm-up polls, 5 s period, writer load and monitor environment as the first C1 run
(ROWBIND and the name map not set). Runs 2026-10-10 04:46-05:44 UTC, started after the E2 driver's `driver_done`
(04:45:28 UTC); runs dir `HOMEPROV-P13-exp/e9pre/c1/runs/k*_direct_qc*_m8ad9e2d7`. Bytes are per-poll medians
(MB = 10^6 B); WAL = the live recorder's `-wal` file size after each measured poll.

| size, quick_check | observable | read_raced / reads per poll | quick_check (measured polls) | total s median / p90 / max | storage read MB | written MB | WAL bytes (median; max) |
|---|---|---|---|---|---|---|---|
| 0.19 GB, every poll | 30/30 | 0 / 30×1 | ran 30, passed 30 | 0.34 / 0.50 / 0.61 | 0.0 | 0.07 | 1,217,492; 2,138,312 |
| 0.96 GB, every poll | 30/30 | 0 / 29×1, 1×2 | ran 30 (31 checks), passed 31 | 1.52 / 1.96 / 5.05 | 0.0 | 0.17 | 4,342,512; 4,342,512 |
| 2.9 GB, every poll | 30/30 | 0 / 30×1 | ran 30, passed 30 | 59.23 / 61.52 / 68.71 | 5340.1 | 1.01 | 12,545,432; 12,545,432 |
| 0.19 GB, hourly | 30/30 | 0 / 30×1 | not due (warm-up poll 1 ran it, passed) | 0.08 / 0.09 / 0.16 | 0.0 | 0.07 | 1,178,352; 2,072,392 |
| 0.96 GB, hourly | 30/30 | 0 / 30×1 | not due (warm-up poll 1 passed) | 0.29 / 0.30 / 0.32 | 0.0 | 0.16 | 4,223,032; 4,223,032 |
| 2.9 GB, hourly | 30/30 | 0 / 30×1 | not due (warm-up poll 1 passed) | 0.78 / 0.83 / 0.87 | 0.0 | 0.28 | 9,677,912; 9,677,912 |

Copy-mode WAL baseline at the same sizes and load (`reference_wal_runs`, runs of `e9_cost_scale.json`, no read held on
the live recorder): median 2,072,392 / 4,194,192 / 4,626,792 bytes at 0.19 / 0.96 / 2.9 GB (max 3,469,072 / 4,214,792
/ 4,787,472).

What it says:
- **The defect is gone in these runs**: at 2.9 GB with quick_check at every poll, 30 of 30 polls are observable and
  quick_check passes on all 30 (it failed on all 30 before the fix); no poll failed as `read_raced`, and one read in
  180 measured polls was retried (0.96 GB, every-poll cadence).
- **E9's settings** (M-direct with `HOMEPROV_QUICK_CHECK_EVERY=720`, M-copy with 1): direct at the hourly cadence takes
  0.08 / 0.29 / 0.78 s per poll (median) and writes 0.07-0.28 MB per poll at 0.19 / 0.96 / 2.9 GB; copy mode at every
  poll is the first run's table above (4.13 s and 194 MB per poll at 0.19 GB; fails closed at 2.9 GB).
- **WAL growth**: the read held during quick_check delays backfill, and at 2.9 GB the WAL file reached 12,545,432 bytes
  with quick_check at every poll and 9,677,912 bytes with it hourly (that once, in the warm-up poll), against 4.6-4.8 MB
  in copy mode; it did not grow further over the 30 measured polls in either run (the file is a high-water mark). At
  0.19 and 0.96 GB the WAL stays at the copy-mode level.
- The every-poll quick_check at 2.9 GB costs 59 s per poll and 5.3 GB of storage reads per poll under the 1 GB memory
  limit, so it is the hourly cadence, not the read path, that makes direct read cheap at that size.

### Direct-read defect found (fixed by the code agent in 3f277d39; re-run above on 8ad9e2d7)
`exp/sp2027/e9_readonly_shm_probe.py` isolates it on the C1 masters, with a writer checkpointing aggressively
(`wal_autocheckpoint=8`):
- `exp/out/e9_readonly_shm_probe.json` (sha256 `da4184c8…`): the `mode=ro&readonly_shm=1` reader alone keeps a
  consistent snapshot — **0 failed `quick_check`s** in every condition (host K=1 20/20, host K=15 6/6 at ~30 s reads,
  docker K=1 20/20, docker K=5 10/10, docker with the C1 limits and a read-only mount K=15 4/4).
- `exp/out/e9_readonly_shm_lockdrop.json` (sha256 `d88748eb…`): the same reader plus exactly what
  `monitor.py validate_files()` does inside `direct_snapshot()` after `BEGIN` and the first read — an ordinary
  `open()`/read/close of the live database, `-shm` and `-wal` — fails **11 of 18** (docker-limited K=15 2/4, host K=15
  2/4, docker K=5 7/10) with torn-snapshot reports ("invalid page number …", "2nd reference to page …", "wrong # of
  entries in index …"); the control without it fails 0 of 18.
Interpretation (consistent with POSIX advisory-lock semantics, which drop all of a process's `fcntl` locks on a file
when any descriptor to it is closed): `validate_files()` releases SQLite's WAL read lock, so for the rest of the poll
the writer's checkpoint can overwrite pages the snapshot still needs. With `quick_check` on, a torn read fails closed
(what the K=15 direct runs show); **with `quick_check` skipped (`HOMEPROV_QUICK_CHECK_EVERY` > 1) a torn view can reach
`load()`/keylog and the roots unchecked** — the hourly-cadence direct runs above were not verified for that. Suggested
fix for the code agent (not made here; the code agent owns `monitor.py`): run the file checks before opening the read
connection, or through descriptors held open for the process's lifetime and never closed during a read transaction,
then re-run its identity proof and this probe (`python3 exp/sp2027/e9_readonly_shm_probe.py lockdrop --out …`).

### Caveats / open items for the lead
- The copy-mode scaling curve uses the evaluated E8 monitor (`3e479ae0`). Direct mode uses the working-tree
  `monitor.py` (`38370b2a`), which the parallel code agent was still finishing (no `E9_IMPL_NOTES.md` and no
  `exp/sp2027/e9_direct_read_identity.py` when these runs were made; `monitor.py` has changed again since, to
  `a60cdf59…`). Those direct-mode rows are superseded by the re-run on `8ad9e2d7` (section above). Copy mode on `38370b2a` matches
  `3e479ae0` at K=1 (3.92 vs 4.13 s median; 193.9 vs 194.0 MB written).
- The A4 root-identity proof (same snapshot → identical node hashes, roots and records in both modes) is the code
  agent's, not this script's; C1 measures cost and, with the probe, consistency.
- `rows_in_open_window` differs between runs of one size (e.g. K=5 copy 10,381 vs direct 16,847 median) because the
  monitor re-reads from the start of the previous hour and long runs cross an hour boundary; load/commit scale with it,
  copy and check do not.
- Storage reads are cache misses only; the monitor container's 1 GB memory limit bounds its cache, and pages the writer
  touched may come from the VM's cache (hence 0.0 MB storage reads at K=1/K=5 direct while `proc_rchar` shows the bytes
  read through system calls).
- The Mac was shared with other agents during the runs; per-run load averages and per-container CPU are in
  `runs[*].steps`.
- `bytes_written_per_hour` is the run's measured rate expressed per hour, not an hour-long measurement.

---

## C2 — deferred-choice attack on an in-process committer (R1 W2)

Result: `exp/out/e9_deferred_choice.json` (sha256 `963b989ba7ed8f4f…`). Script: `exp/stages/e9_deferred_choice.py`.

### What it shows
R1 W2 asks what external placement protects that an in-process committer feeding the same first-write-wins anchor would
not, conceding that the only case is a **resident adversary that chooses its target later**. This is that case, with
**placement as the only variable**: both commitment paths run `monitor/monitor.py` unchanged (sha256 `38370b2a…`,
recorded; both read through its copy path, `HOMEPROV_READ` unset, so the direct-read defect of C1 does not apply), stable scheme, coverage, keylog, Ed25519 signatures, tagged replies, each with its own first-write-wins
anchor (`testbed/anchord/anchord.py` via `hpr-anchord:e8`) and append key.
- **M-ext** (external monitor): reads the recorder itself; its read path is not reachable from the hub process.
- **C-inproc** (in-process committer): the same `monitor.py` in the resident's interpreter, so the resident controls
  when its read path reveals each row — the "module-level rebinding of its read path" R1 W2 names. The resident
  releases the target second to C-inproc only after rewriting it.

30 trials (fixed, stated up front). Per trial, on a shared real-schema scratch recorder, on a virtual clock: (1) an
honest household-member (member A) unlock is written as the recorder stores it (state row + `call_service` event, one
context); (2) M-ext polls at t+1 and seals second t with the **honest** root (anchored first-write-wins); (3) the
resident picks that actuation and applies the paper's **PSR member-account swap** — `UPDATE context_user_id_bin A→B` on
the context's state and event rows, the public primitive in `exp/rig/forge.py` and testbed arm PSR; (4) **stolen-key
probe**: the resident, holding M-ext's append key, posts the rewritten root for second t to M-ext's anchor; (5) C-inproc
polls now (its read path released post-rewrite) and seals second t with the **rewritten** root, anchored first-write-wins
on its own anchor. Both chains are then scored by `exp/stages/e7_verify.py` against the final (rewritten) recorder.
Exact 95% Clopper-Pearson intervals (`exp/rig/stats.py`). The verifier is the working-tree `exp/stages/e7_verify.py`
at run time (sha256 `d7fb73cc…`, recorded; the code agent was extending it for E9, so it differs from E8's `7e036386…`).

**This is a controlled harness, not a live Home Assistant stack, and no deployable attack integration was created**
(the safe realization of the design's scratch-stack intent): the recorder is real 2026.7.4 bytes (a C1 synthetic master,
read-only source), the honest write and the rewrite use the primitives the artifact already ships, and the "blinding" is
realized by the resident choosing, per poll, which recorder state the in-process committer's read path reveals — on the
exact `monitor.py` the external monitor runs. The attack never left `HOMEPROV-P13-exp/e9pre/c2/`; nothing was placed
under a released path, and the two anchor containers were removed at teardown.

### Results (30/30 unless noted; `results_summary`)
| quantity | k/n | 95% CI |
|---|---|---|
| external monitor sealed the honest second | 30/30 | [0.884, 1.000] |
| external monitor **detected** the rewrite (attributable 1 s violation) | 30/30 | [0.884, 1.000] |
| stolen-key re-anchor on the external anchor → **409** (withhold, not forge) | 30/30 | [0.884, 1.000] |
| in-process committer anchored the **rewritten** second | 30/30 | [0.884, 1.000] |
| in-process committer **detected** the rewrite | **0/30** | [0.000, 0.116] |

Signatures: 34/34 records verify under each path's published key (0 bad, 0 wrong-key). Conclusion in the file:
against a resident that chooses its target later, an in-process committer can be blinded from installation and made to
certify the rewritten history to a first-write-wins anchor; only the external monitor, whose read path the hub process
cannot reach, sealed the honest row and detects the rewrite, and a stolen append key lets the resident withhold or
stall the external anchor, not forge a sealed root (409). This backs the Section 5 per-party table and the R1 W2 fix
"state which adversary needs the external placement, then demonstrate the deferred-choice attack on an in-process
committer."

---

## C3 — off-hub replica baseline (R2 W3)

Result: `exp/out/e9_replica_baseline.json` (sha256 `16cd30c80437bbfc…`). Script: `exp/sp2027/e9_replica_baseline.py`.
The folds were recomputed with the working-tree `monitor.py` at run time (sha256 `91e5e8e8…`, recorded as
`monitor_code`; E8 ran `3e479ae0`) and E8's own verifier `e7_verify.py` (`7e036386…`); every escrow line and signature
still reproduced E8's anchored values (below), so the encoding was unchanged for these checks. Computed entirely from the E8 files (`exp/out/e8_main_{stable,closure}_chain.jsonl.gz`,
`e8_main_{stable,closure}_escrow.jsonl.gz`, `e8_main_{stb,clo}_sign_pub.pem`, `e8_main_score.json`,
`e8_main_config.json`); no new run. The escrow (`HOMEPROV_ESCROW_DIR`) is the full off-hub replica of the committed
fields that R2 asks the anchor chain to be compared with.

### Storage per day (bytes/day at each window's measured write rate; escrow ÷ chain)
| scheme | window | anchor chain | escrow (off-hub replica) | escrow/chain |
|---|---|---|---|---|
| stable (evaluated) | arms (main) | 22.5 MB | 267 MB | 11.86× |
| stable | base (lab rate) | 18.5 MB | 127 MB | 6.87× |
| stable | stress (≈4.6× rate) | 28.6 MB | 563 MB | 19.68× |
| closure | arms (main) | 22.1 MB | 126 MB | 5.68× |
| closure | base | 17.8 MB | 60 MB | 3.38× |
| closure | stress | 28.5 MB | 256 MB | 8.99× |

(The chain's per-day figure is dominated by the heartbeat record every poll; the escrow scales with the rows written,
so the ratio rises with the write rate. Whole-file sizes and gzip figures are in the result.)

### What each lets a third party verify (`what_each_lets_a_third_party_verify`, checks on the stable monitor)
- **Anchor chain alone**: the monitor's records are authentic (Ed25519 under the published key — 1508/1508 stable,
  1538/1538 closure verify) and linked; it holds no row content, so alone it shows neither what a row said nor whether a
  recorder is unchanged.
- **Chain + recorder (or a window extract)**: whether each sealed segment reproduces the anchored root (match /
  violation / unknown); a changed row is detected, its original content is not recovered.
- **Chain + escrow**: every escrow line is authenticated by reproducing an anchored root or keylog sub-range
  (**4892/4892** sealed-second lines reproduce their anchored root; **2717/2717** keylog lines verified), after which the
  original committed fields of every sealed second are recoverable. **Control**: one escrow line with a single committed
  value changed and its own `acc` recomputed stays self-consistent but **no longer matches the anchored root** — a plain
  replica, lacking the commitment, has only this self-consistency.
- **Escrow / replica alone**: self-consistency only; its host (or anyone who can write it) can change a line and
  recompute its fold, so a third party must trust that host for integrity.

### What the anchor host learns (`what_the_anchor_host_learns`)
Roots, per-segment row counts, poll times and watermarks (row keys), and per first-observed row its key offset, a 32-bit
hash prefix and the second it was in. So it learns **when** rows were written and how many (the activity timeline:
anchored non-empty seconds equal the recorder's seconds-with-a-row to within one per window), and **no committed value**
— a search for every distinct TEXT ≥ 8 chars (386 stable / 362 closure) and every BLOB ≥ 8 bytes (≈32.7k) from the
escrowed tuples finds **0** of them in the chain text. The escrow's host, by contrast, holds every committed value of
every sealed row. This is the privacy/verifiability trade R2 W3 asks be argued: commitment buys third-party
verifiability and content privacy at the anchor; the replica buys recovery but requires trusting its host.

---

## File hashes (sha256)
- `exp/out/e9_deferred_choice.json` — `963b989ba7ed8f4fc48664242b9dca7f7605139ef4157809969b305ee314dc6f`
- `exp/out/e9_replica_baseline.json` — `16cd30c80437bbfca6549037c6d7bd2676587f9b04dcc3c47823c9d2317abac2`
- `exp/out/e9_cost_scale.json` — `8733d81cd38beea93bbfcd918344de817187ad7dbb7d03a8e6c8d3e289a94e6d`
- `exp/out/e9_cost_scale_direct_final.json` — `bce6e87118f9e4de660d5b3673a755cebffe323cb80e1650b1eda13f2774f498`
  (direct mode on monitor.py `8ad9e2d7…`)
- `exp/out/e9_readonly_shm_probe.json` — `da4184c8fe7645322cf038ec86c7d5233f6f87d7f7e4d53dad8215f7bb4ff583`
- `exp/out/e9_readonly_shm_lockdrop.json` — `d88748ebb03ebfa440a2c9c6cb270c6534256704ff28ed6243cf382511b993a7`

Scripts (new, untracked): `exp/sp2027/e9_cost_scale.py`, `exp/sp2027/e9_readonly_shm_probe.py`,
`exp/sp2027/e9_replica_baseline.py`, `exp/stages/e9_deferred_choice.py`. Raw C1 run directories (per-poll JSON lines,
writer logs, sizes, load context) are kept under `HOMEPROV-P13-exp/e9pre/c1/runs/`; the synthetic masters
(`master_k{1,5,15}.db`, 4.1 GB in all) under `HOMEPROV-P13-exp/e9pre/c1/` can be deleted to free disk once the lead
no longer needs re-runs.
