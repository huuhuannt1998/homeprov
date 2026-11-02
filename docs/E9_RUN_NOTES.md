# E9 run (part B): notes for the lead and the PI (2026-10-09)

Written by the E9 harness agent. Nothing committed or pushed. No `hpr-*` or `e2-*` container, volume or network and no
default anchor was started, stopped, exec'd into, rebuilt, mounted or read, apart from `docker ps` listings; the E2
driver script was read (not changed) to learn its process name, and the real-mode guards were run once each and refused
(clock; then the running `driver_oct10.sh`) before touching anything. All
smoke containers, volumes and networks had the prefix `e9s-` and were removed at the end. Smoke outputs are under
`<research-dir>/HOMEPROV-P13-exp/e9/smoke/`, never `exp/out/`. Keys never left their containers or volumes;
only fingerprints and public keys were written.

## 1. Files

| File | What |
|---|---|
| `testbed/e9/run_e9.sh` | NEW. The seven-day harness: preflight, setup, the week (an event list on the wall clock), freeze, scoring. Every target is overridable (`HPR_E9_*`), which is how the smoke drove the scratch stack. |
| `testbed/e9/e9ops.py` | NEW helpers (standard library): `schedule` (the event list), `issue` (one operator marker, built and signed with part A's `rig.marker_issuer`, to both anchors, reply tags checked), `namemap` (display fields and the predicted part digests of a planned change, with the monitor's own code), `namemap-sanitize` (a storage copy holding only the name map's display fields, same digest, for the verifier), `ha-backup` (Home Assistant's backup archive around a consistent SQLite copy), `hostlog` (wall-clock gaps, VM clock offset, hub starts, power, lid, monitors' `/proc/1/io` and memory), `sleep-guard`, `pmset`. |
| `testbed/e9/smoke_stack.sh` | NEW. The `e9s-` scratch stack (`up` / `down`): broker, simulator, Home Assistant 2026.7.4; configuration cloned read-only from the E6 volume `e6-config` (never from the default deployment), recorder = the E8 run's real snapshot trimmed to its last 3 days, and one scratch-only MQTT-triggered automation that calls `recorder.purge` (the forced purge). |
| `exp/stages/e9_score.py` | NEW scorer. Runs part A's `exp/stages/e7_verify.py` per monitor and window with the E9 options it finds (`--operator-pubkey`, `--purge-keep-s`, `--purge-tol-s`, `--restore-tol-s`, `--namemap-storage`; each day a second time with `--no-rowbind`), and adds the per-day, per-night and whole-run outcomes listed in the pre-registration draft. Reuses `exp/stages/e8_score.py` helpers. |
| `testbed/e9/e9_prereg.py` | NEW. Writes the pre-registration from the run's parameters, the generated schedule and the current file hashes: the draft now, `--final --out exp/out/e9_preregistration.json` at registration (refuses to overwrite). |
| `drafts/round13/E9_PREREG_DRAFT.json` | Pre-registration draft (parameters, schedule in UTC, arms and counts per day, benign events, outcomes and how each is scored, exclusions, known limits, code hashes to re-freeze). |

No attack code was written or changed. The attack batches use `homeprov_ec` (PU, PSR) and `homeprov_e7` (INS-L, BD-S)
from `testbed/real/ha-config/custom_components/` as they are; the name-map session uses the E6 in-hub harness
`homeprov_e6` from `<research-dir>/HOMEPROV-P13-exp/e6/code/homeprov_e6` (outside the repository; never
released). Each is copied into the hub only while it is needed, and its hash is logged.

## 2. What the week does

Start 2026-10-11 12:00:00 UTC (`HPR_E9_START`), seven days of 24 h from 12:00 UTC, then the freeze. All times UTC.

| When | Event |
|---|---|
| setup (before START) | stock `hpr-monitor`/`hpr-anchord` stopped and renamed (restored at the end); `person:` added to `configuration.yaml`; `homeprov_e6` on (restart), one person per household account [Withheld from the artifact: how the in-hub harness creates the persons. The attack integrations and the E6 in-hub harness are not released (README.md, "What is deliberately not here").], `homeprov_e6` off (restart); keys; witnesses; anchors; M-direct started and its full-history seal anchored, THEN M-copy (staggered, see 6.1); probes |
| daily 14:00 | attack batch: `homeprov_ec` PU, PSR (5 each), then `homeprov_e7` INS-L, BD-S (5 each); three hub restarts; rooms porch, hallway, kitchen, porch, hallway, kitchen, porch |
| nightly 03:40 | sleep guard: if the Docker VM's clock offset grew by more than 30 s since the hub's last start (the VM slept, so the hub's 04:12 purge is late), restart the hub to re-arm it on the wall clock |
| nightly 03:55 / 04:45 | recorder snapshots `night<d>_pre` / `night<d>_post`, read OUTSIDE the hub: a throwaway container on the read-only mount runs SQLite's online backup API from a read-only connection (`mode=ro&readonly_shm=1`, one read transaction) into the run directory; the hub's `/tmp` only as a recorded fallback (`method` in the event) |
| nightly 04:07:00 / 04:10:00 | operator PURGE marker (scoped: scheduled 04:12:00, keep 30 days), operator-signed: the issuer container starts at 04:07 (Docker took up to a minute to start a container in the smoke runs) and posts to both anchors at 04:10:00, retrying until 04:12 |
| daily 12:00:30 | snapshot `day<d>_end`; chains, refusals and cost logs copied; `pmset` sleep entries of the day |
| day 2 (10-12) 20:00 | the planned hub restart |
| day 3 (10-13) 17:00 | name-map session, in this order: benign rename of `light.porch_light` to "Porch lamp" under a RENAME marker; the person re-link as a MOVE (hpr has one household account, "Alex Rivera (household)"): Alex's `user_id` moves from Alex's person to the account-less person "Jordan Rivera (household)" created at setup (unlink P1, link P2), declared under RENAME markers for every intermediate state, and moved back the same way; then the ATTACK, the same move with no marker and no recorder row written, held 180 s; its declared move back. The run log names the mode (`move`; a swap only on a hub without the account-less person) |
| day 4 (10-14) 20:00 / 20:30 | backup (consistent SQLite copy wrapped in Home Assistant's backup format and hashed, held OUTSIDE the hub in the run directory) / RESTORE marker (signed `backup_wm`, archive and database sha256; `e9ops.py issue` refuses a RESTORE without `backup_wm`); 30 s later the hub is stopped, the archive and `.HA_RESTORE` placed, the archive's copy in the hub read back and checked against the signed sha256 (else no restore), the hub started; Home Assistant's own start-up restore; then an operator RESTORE_DONE marker (review N1) |
| 10-18 12:01 | freeze: 90 s settle, final snapshot, monitors stopped, chains, witness logs, escrow, name-map snapshots, a sanitized name-map storage; scoring |

No hub restart is allowed in [03:50, 04:45); a restart that falls there waits. A PURGE marker that would be issued after
its purge is skipped and logged as missed. The schedule is in the pre-registration draft (`schedule.events`).

**The restore.** Home Assistant documents a restore path for a Container install: Settings > System > Backups, restore
on the current system, choosing settings and/or history (home-assistant.io/common-tasks/general/#restoring-a-backup).
For Core and Container installs the backup manager writes `/config/.HA_RESTORE` (path, password, `restore_database`,
`restore_homeassistant`) and restarts; at start-up `homeassistant/backup_restore.py` (read in the 2026.7.4 image)
extracts the archive and, with `restore_database=true, restore_homeassistant=false`, deletes `home-assistant_v2.db` and
`home-assistant_v2.db-wal` and copies the archive's two files in (it does not touch `-shm`). Creating the backup and
starting the restore through the backup manager needs an access token, which the lab installation does not have (E2
diagnosis 4: minting one is a PI decision). So E9 does exactly the start-up half Home Assistant runs, on an archive the
operator builds: at 20:00 a consistent copy of the recorder (SQLite online backup, read-only connection) wrapped in Home
Assistant's layout (`backup.json` with `homeassistant.version` and `compressed: true`, and `homeassistant.tar.gz`
holding `data/home-assistant_v2.db` and an empty `data/home-assistant_v2.db-wal`; the copy itself is read outside the
hub through the read-only mount, as every snapshot), hashed and HELD OUTSIDE THE HUB
(run directory, read-only); at 20:30 an operator RESTORE marker (`restore_point_ts` = the copy's start, plus the backup's
row watermark, archive and database hashes) and, 30 s after it is anchored, the hub is STOPPED, the archive is copied
into `/config/backups`, its copy is read back from the stopped container and must match the signed sha256 (otherwise
the hub is started without a restore and no RESTORE_DONE follows), `.HA_RESTORE` is written and the hub started (review
N1: an archive left in the hub's directory for 30 minutes could be rewritten to keep the RESTORE excuse open; with the
hub stopped no hub process runs between the check and the start-up restore); Home Assistant's own log lines ("Restoring ...",
"Restore complete") and the post-restart watermark are logged (the backup integration consumes `.HA_RESTORE_RESULT` at
start-up, so the file is read only if it is still there). The operator then reads the restored recorder's watermark
from OUTSIDE the hub (a throwaway container on the read-only mount) and, if the restore log says complete, issues an
operator-signed RESTORE_DONE built by `rig.marker_issuer.restore_done_marker()` from the RESTORE marker as issued
(`restore_nonce`, `restore_sha256`), with that watermark (`post_restart_wm`) and the restored hub's container start
`hub_started_ts` H (the verifier never excuses a segment starting at or after H; E9_IMPL_NOTES.md 12.1); without RESTORE_DONE within `--restore-done-max-s 600` the verifier excuses nothing
(smoke 3: 78 s from the RESTORE marker to the post-restart observation). The rows
of 20:00-20:30 are lost; keys above the backup's watermark are reused by new rows. The verifier's RESTORE rule (part A,
E9_IMPL_NOTES.md 11.1; `--restore-tol-s 30 --restore-max-age-s 86400`) excuses only segments sealed before the first poll
that read the restored recorder, holding only unchanged backup rows (key <= the signed `backup_wm`); with
`HOMEPROV_KEYLOG_REWIND=1` on both monitors the rows written with reused keys are bound at first observation.

## 3. Before the real run (gates)

1. Part A finished and reviewed. Its notes (`drafts/round13/E9_IMPL_NOTES.md`, section 8 "What the E9 harness must
   set") were checked on 2026-10-10 00:50 UTC: the monitor settings (`HOMEPROV_READ`, `HOMEPROV_SINCE=0`,
   `HOMEPROV_ROWBIND=1`, `HOMEPROV_NAMEMAP_DIR`, signatures, reply tags, escrow, cost log), the operator issuer
   (`rig.marker_issuer`: operator HMAC key file + Ed25519 signature, reply tags, PURGE/RESTORE/RENAME) and the verifier
   options (`--operator-pubkey`, `--purge-keep-s`, `--purge-tol-s`, `--restore-tol-s`, `--namemap-storage`,
   `--no-rowbind`, `--no-purge-disconnect`) are what the harness uses. Re-check after the final review.
2. Memory (6.1, 7.4): decide how the full-history initial seals fit; and the three verifier findings 7.1-7.3 (fix,
   or pre-register the parameter).
3. `python3 -m pytest -q monitor` and `python3 -m pytest -q testbed/anchord` pass (the real run refuses otherwise):
   on 2026-10-10 00:50 UTC, 131 and 80 passed (the earlier fixture failure, 7.6, is resolved).
4. A second smoke run with the final part-A code (command in 4.1); it must exit 0 and score.
5. The pre-registration: `E9_PREREG_DRAFT.json` -> `exp/out/e9_preregistration.json` with the final hashes and
   `registered_at`; then try `pip install opentimestamps-client && ots stamp exp/out/e9_preregistration.json`
   (anonymous calendars; if it fails from this machine, put the sha256 in the run log only).
6. The E2 night is over (the script refuses before 2026-10-10 05:00 UTC, while `driver_oct*.sh` or an `e2-issuer*`
   container runs).

## 4. Commands

### 4.1 Smoke (scratch stack; about 75 min)

```bash
cd <artifact-root>
testbed/e9/smoke_stack.sh up            # e9s-broker, e9s-devices, e9s-hass (2026.7.4), seeded as in section 1
mkdir -p <research-dir>/HOMEPROV-P13-exp/e9/smoke
HPR_E9_SCRATCH=1 HPR_E9_SMOKE=1 HPR_E9_PREFIX=e9s HPR_E9_HUB=e9s-hass HPR_E9_NET=e9s-net HPR_E9_CFGVOL=e9s-config \
HPR_E9_DEVICES=e9s-devices HPR_E9_BROKER=e9s-broker HPR_E9_STOCK_MONITOR= HPR_E9_STOCK_ANCHOR= \
HPR_E9_OUT=<research-dir>/HOMEPROV-P13-exp/e9/smoke/out \
HPR_E9_SP=<research-dir>/HOMEPROV-P13-exp/e9/smoke/e9s_smoke4 \
HPR_E9_MONITOR_IMAGE=hpr-monitor:e9s HPR_E9_ANCHOR_IMAGE=hpr-anchord:e9s \
HPR_E9_WITNESS_PORT_DIRECT=19990 HPR_E9_WITNESS_PORT_COPY=19991 \
HPR_E9_TRIALS=1 HPR_E9_SEAL_WAIT_S=45 HPR_E9_BD_MIN_AGE_S=60 HPR_E9_NAMEMAP_STEP_S=40 HPR_E9_NAMEMAP_ATTACK_HOLD_S=60 \
HPR_E9_QUICK_CHECK_DIRECT=12 \
HPR_E9_SMOKE_LEAD_S=720 HPR_E9_SMOKE_KEEP_DAYS=2 HPR_E9_SEAL_WAIT_MAX_S=900 \
nohup testbed/e9/run_e9.sh e9s_smoke4 > <research-dir>/HOMEPROV-P13-exp/e9/smoke/e9s_smoke4.out 2>&1 &
# afterwards:
testbed/e9/smoke_stack.sh down
```

The preflight runs both test suites (the smokes here skipped them with `HPR_E9_RUN_TESTS=0` while the anchor fixture
of 7.6 was failing; it passes now). The smoke compresses three days into 18-minute days: day 1 an attack batch (1 trial per arm), then the forced purge
(`recorder.purge` with keep_days 2 through the scratch-only MQTT automation) behind a PURGE marker, with pre/post
snapshots; day 2 the planned restart and the name-map session; day 3 a batch, the backup and the restore.

### 4.2 Real run

```bash
cd <artifact-root>
mkdir -p <research-dir>/HOMEPROV-P13-exp/e9
nohup caffeinate -i -s -m testbed/e9/run_e9.sh e9_main > <research-dir>/HOMEPROV-P13-exp/e9/e9_main.out 2>&1 &
```

Start it on 2026-10-11 between 09:00 and 10:30 UTC: the script refuses less than `HPR_E9_MIN_SETUP_S` (3,600 s) before
START, and the setup (tests, builds, two hub restarts for the persons, two staggered full-history seals of the ~200 MB
recorder) needs most of that (6.1, 7.4). If the code is not ready, move the whole run by whole days: `HPR_E9_START=2026-10-12T12:00:00Z`
(and re-issue the pre-registration). The script runs `caffeinate -i -s -m -w <its pid>` itself as well.

Watching it (read-only): `tail -f <research-dir>/HOMEPROV-P13-exp/e9/e9_main.out`;
`tail -3 <research-dir>/HOMEPROV-P13-exp/e9/e9_main/hostlog.jsonl`; `grep -c . .../events.jsonl`. Each day
at 12:00:30 the run directory receives `snapshots/day<d>_end.db`, fresh copies of both chains and cost logs and
`pmset_day<d>.jsonl`. Scoring can be repeated at any time on a COPY of the run directory:
`python3 exp/stages/e9_score.py --run-dir <copy> --tag e9_main --out-dir <somewhere else>`.

Stopping early: `kill <pid of run_e9.sh>` (TERM). The EXIT trap stops the host log and the witnesses, removes the E9
containers, destroys the signing-key and operator volumes, removes the attack integrations from the hub, restores
`configuration.yaml` byte for byte (one restart) and restarts the stock monitor and anchor. Nothing is scored then;
the run directory keeps what was collected so far.

Outputs: run directory `<research-dir>/HOMEPROV-P13-exp/e9/e9_main/` (configuration log, `events.jsonl`,
`schedule.json`, `hostlog.jsonl`, snapshots, chains, refusals, cost logs, monitor and anchor logs, escrow, witness
logs, keys/*_pub.pem, name-map snapshots, sanitized name-map storage, `verify/` cache, `score.log`); `exp/out/`:
`e9_main_t_start`, `_t_end`, `e9_main_d<d>_report_{ec,e7}_<room>.json`, `e9_main_d<d>_window.json`,
`e9_main_{direct,copy}_chain.jsonl.gz`, `..._witness_heads.jsonl.gz`, `e9_main_events.jsonl`, `e9_main_schedule.json`,
`e9_main_hostlog.jsonl.gz`, `e9_main_score.json`, `e9_main_config.json`.

## 5. What the PI must do for seven days (2026-10-11 09:00 to 2026-10-18 about 13:00 UTC)

1. **Power and lid.** Keep the MacBook on its charger and the lid OPEN the whole week. A closed lid sleeps the Mac
   whatever caffeinate says (this is what stopped the 2026-10-09 purge). The script refuses to start on battery or
   with the lid closed, and logs power source and lid state every minute.
2. **No sleep.** The script holds caffeinate (idle, system and disk sleep) while it runs. In System Settings > Battery >
   Options, set "Prevent automatic sleeping on power adapter when the display is off" on. The display may sleep.
3. **No restarts.** Turn off automatic macOS updates for the week (System Settings > General > Software Update >
   Automatic updates: off for "Install macOS updates" and "Install Security Responses and system files"), and in Docker
   Desktop turn off "Automatically check for updates" / automatic download and the Resource Saver. A Docker or macOS
   restart ends the run (the completed days are still scored).
4. **Do not touch the E9 containers or `hpr-*`, and run nothing Docker-heavy** (no builds, no other stacks) on this Mac
   during the week; the per-poll costs are measured. Do not log out (the run is a child of the terminal session).
5. If the Mac does sleep anyway: nothing to do. The host log records it, the 03:40 sleep guard restarts the hub so its
   04:12 purge runs on time, and the scorer reports the sleep and any late purge.
6. On 10-18 after about 13:00 UTC the run has finished when `e9_main.out` ends with `done; results under ...`.

## 6. Smoke runs (scratch stack `e9s-`, 2026-10-09)

Scratch only; these are plumbing checks, not results. Stack: `testbed/e9/smoke_stack.sh` (section 1). Code: the
working tree at each start (part A's monitor, verifier, anchor and issuer as they were then; in-image `monitor.py`
sha256 `4e2c2fac...` in smoke 1, `38370b2a...` in smoke 2, `8d0c1040...` in smoke 3 with `anchord.py` `8b35448d...` and
`anchord_linked.py` `f6252e24...`; verifier `e7_verify.py` `4897daa1...` / `b610ffd9...`; each run's
`auth_meta.log` has the full hashes), images `hpr-monitor:e9s` / `hpr-anchord:e9s` (removed at the end). Test gate skipped
(`HPR_E9_RUN_TESTS=0`): at the time monitor 82 passed and the anchor suite 66 passed, 2 failed (7.6). Artifacts:
`<research-dir>/HOMEPROV-P13-exp/e9/smoke/` (`e9s_smoke{1,2,3}/`, `*.out`, `out/`; `out_rescore2/` and
`out_rescore3/` hold the re-scorings with the corrected scorer).

### 6.1 Smoke 1 (aborted): the full-history seal does not fit in Docker's memory

Seeded with the E8 run's whole recorder (199 MB, 30 days). Both monitors started their full-history first poll at once;
the copy monitor was OOM-killed after about 2 min (`docker events`: oom, exit 137), restarted (`--restart
unless-stopped`) and began again; the direct monitor alone was then OOM-killed 5 times in a row (no record ever reached
its anchor). The Docker VM has 7.75 GB; `hpr-*`, `rka-*`, `delaysteer-ha`, `ds-readpath-ha` and another agent's
`e9k-*` stack held about 3.6 GB. Measured natively on the Mac (outside Docker, a private copy of the same recorder, the
working-tree `monitor.py` `38370b2a...`, anchor unreachable): the first poll loaded 1,198,652 rows (9.1 s), computed the
roots in 41.3 s, sealed 385,027 seconds, 32,567 minutes and 727 hours, wrote 1.6 GB of escrow and 9,366 keylog
sub-ranges; maximum resident set 4.24 GB over 13.7 min (an upper bound for the first poll: the later polls, with the
anchor down, held 418,321 pending roots and rewrote a 187 MB state file each poll). Run aborted; teardown clean.

Fixes: the harness starts M-copy only after M-direct's history is anchored (`wait_sealed`, 6 polls past its first
record, at most 5,400 s, else the real run does not start) and the host log now records each monitor's memory. The smoke
seed is trimmed to the last 3 days (`seed_last3d.db`, 24 MB, 96,192 states). The decision for the real run is in 7.4.

### 6.2 Smoke 2 (complete; 2026-10-09 21:53-23:12 UTC)

Figures from the re-scoring with the smoke's keep_days (`out_rescore2/`); the run's own scoring used 30 days (bug (b)
below) and excused nothing at the purge.

| | M-direct | M-copy |
|---|---|---|
| full-history seal (3-day seed) | anchored after 62 s, 25 records | after 75 s, 25 records (started after M-direct's) |
| seconds holding a row at START without an anchored root | 0 of 47,473 | 0 of 47,473 |
| detection, days 1 and 3 (PU, PSR, INS-L, BD-S, 1 trial each per day) | 2/2 each arm | 2/2 each arm |
| unexcused violations on untouched segments, second/minute/hour, days 1/2/3 | 0/0/0 of 227/17, 213/19, 215/16 untouched anchored | same |
| suspect seconds with / without per-row binding | 0 / 0 each day | 0 / 0 |
| forced purge (keep_days 2, 22:22:47): the verifier's NEW violations in the historical window | 0 unexcused; excused: 22,320 second, 1,902 minute, 38 hour segments older than the cutoff, 1 straddling minute and hour, 1 purge-disconnect second (2 rows) | same |
| database evidence of that purge | states older than the cutoff 44,088 -> 0; 2 retained rows disconnected (old_state_id -> NULL) in 1 second | |
| restore (backup 22:53:50, restore 22:57) | excused under RESTORE: 39 seconds, 3 minutes + 1 straddling minute; 0 unexcused | same |
| name map | the benign rename's transition excused by its RENAME marker | same |
| markers | PURGE, 4 RENAME, RESTORE: all accepted (200, reply tag ok), operator signature valid | same |
| records / signatures | 757 records; 751 monitor records signed ok, 0 bad | 733; 727 signed ok |
| witness | every head matches, final head = chain head, 0 never witnessed, 0 forks | same |
| per-poll total ms, median / p90 / max (whole smoke) | 308 / 668 / 3,325; read path direct 591, copy fallback 8 (hub stopped) | 259 / 600 / 3,268 |
| bytes read / written by the process (whole smoke, /proc/1/io rchar / wchar) | 15.5 GB / 0.24 GB | 32.5 GB / 16.2 GB |
| seal delay median / max (s) | 3.1 / 61.0 | 3.3 / 61.9 |

Probes as expected: from the hub every untagged or forged record and marker refused (401) by both anchors, no route to
either witness; a marker under the append key refused (403, marker_needs_operator_key), a record under the operator key
refused (403, operator_key_for_markers_only), reply tags valid. Hub starts 10 in the smoke week, each matched to its
harness cause; no wall-clock gap, no pmset sleep, no VM clock jump. Home Assistant's restore ran ("Restoring ... Restore
complete, restarting" in its log); no state row between the backup and the restart is left; new rows reuse keys from
935,348 (backup watermark 935,347).

Bugs found and fixed by smoke 2: (a) the person re-link failed, "User already taken": once every household account
has a person, Home Assistant refuses to link a person to another person's account; the re-link is now a SWAP of two
persons' accounts (three person_update calls), and a declared swap carries one RENAME marker per intermediate name-map
state; (b) the scorer passed the hub's 30 days to the verifier while the forced purge used 2, so nothing was excused
(the verifier recomputes every cutoff from its own policy, by design): the smoke now scores with its keep_days, and the
verify cache is keyed on its arguments, snapshot and verifier hash; (c) `docker run` sometimes took 41-57 s to start a
container on this Mac: the PURGE marker's issuer now starts at 04:09:00 and posts at 04:10:00 (`--not-before`); the
smoke's forced purge is published by `docker exec` into the scratch broker; (d) `.HA_RESTORE_RESULT` is consumed by the
backup integration at start-up, so the restore outcome is read from Home Assistant's own log lines; (e) the touched
seconds were compared as strings against integers (3 attack seconds showed as untouched); (f) the name-map storage is
given to the last day's verification only, and hub starts are matched to the harness's restarts by StartedAt.

### 6.3 Smoke 3 (the patched script)

Same stack (re-created), the patched script, 2026-10-09 23:19 to 2026-10-10 00:39 UTC; exit 0, scored. The PURGE
marker was posted at its declared second (`--not-before`), the forced purge published at its scheduled second, the
person swap ran (all 13 `person_update` calls ok), the restore outcome came from Home Assistant's log ("Restore
complete"), and the sanitized name-map storage reproduced the hub's digest.

| | M-direct | M-copy |
|---|---|---|
| full-history seal | anchored after 51 s; 0 of 47,525 seconds unsealed | 0 of 47,525 |
| detection, days 1 and 3 | 2/2 each of PU, PSR, INS-L, BD-S | same |
| unexcused on untouched segments, s/m/h: day 1 / 2 / 3 | 0/0/0 of 230/15; 0/0/0 of 222/18/1; **0/1/0** of 199/14 (finding 7.2) | same |
| suspect seconds with / without binding | 0 / 0 each day | same |
| forced purge (keep_days 2, on time) | **5 unexcused new violations and 1 keylog range** (finding 7.1); excused: 23,798 s, 1,993 min, 39 h segments older than the cutoff, 1 straddling hour, purge disconnects in 4 s / 4 min / 3 h (4 rows). The round-12 rule alone (`--no-purge-disconnect`): 16 unexcused and 5 keylog ranges | same |
| database evidence of that purge | states older than the cutoff 47,054 -> 0; 13 retained rows disconnected in 8 seconds, 3 of them more than 1 h after the cutoff, every predecessor gone and older than the cutoff | |
| restore | excused 33 s + 1 min and 42 keylog ranges; the minute holding the restore point unexcused (7.2) | same |
| name map | 5 transitions (rename, 4 swaps), all excused, the ATTACK swap included (finding 7.3) | same |
| markers | PURGE, 10 RENAME, RESTORE, all accepted with valid reply tags and operator signatures | same |
| witness | ok; final head = chain head; 0 forks; 1 record without its own head (covered by a later extension push) | same |
| per-poll total ms, median / p90 / max | 131 / 203 / 5,176 (direct 622, copy fallback 5) | 110 / 181 / 5,111 |
| bytes read / written (rchar / wchar) | 15.5 GB / 0.15 GB | 33.5 GB / 16.9 GB |
| escrow at the end | 353 MB | 353 MB |

The scratch figures above are plumbing checks on a 24 MB recorder, not results (cost and bytes depend on the recorder's
size). Teardown left no `e9s-` container, volume, network or image, the witness ports free, and `hpr-*` and the E2
driver running as before.

### 6.6 Registration and the timed start (2026-10-10)

- `exp/out/e9_preregistration.json` registered 2026-10-10T08:52:19Z (status REGISTERED, 36 repository files plus
  homeprov_e6 frozen), sha256 `3d64b2e5288479bd06dfada94402ffa53359b51c84a074de62986d9d58a0a16f`.
- OpenTimestamps: `exp/out/e9_preregistration.json.ots` (opentimestamps-client 0.7.2, venv under scratch), submitted to
  4 calendars and pending Bitcoin confirmation at stamp time. Run `ots upgrade exp/out/e9_preregistration.json.ots`
  a few hours later (any time; it only adds the block attestation), then `ots verify`.
- `testbed/e9/start_e9_at.sh` started detached at 08:53:14Z (log `HOMEPROV-P13-exp/e9/start_e9_at.log`). It holds
  caffeinate, waits on the wall clock for 2026-10-11T09:15:00Z, re-checks the registered hashes, then runs
  `nohup caffeinate -i -s -m testbed/e9/run_e9.sh e9_main > HOMEPROV-P13-exp/e9/e9_main.out 2>&1 &`. It exits without
  starting if the pre-registration is missing or not registered, if any frozen file changed (so do not edit the
  frozen files before then), or if `e9_main` already exists or runs. A dry run against the registered file passed.
- 2026-10-10 13:25Z: the wrapper was STOPPED by hand (PI "go" at 13:22 UTC: start today). Nothing was started and no
  amendment was written: the frozen `e9ops.py real_schedule` places each night at day start + 16:12 and the special
  events at day start + offsets, i.e. it assumes START = 12:00 UTC; any START today would put every PURGE marker, sleep
  guard and night snapshot 16:12 after START instead of at the hub's 04:12 purge.
- 2026-10-10 13:28:34Z: lead decision (option 1): the registered START 2026-10-11T12:00Z stands, no amendment, no
  frozen-file edit, no setup today. The same wrapper was re-armed (pid 80684, same log; hash check ok, 37 files).
- 2026-10-10 16:08:50Z: the PI asked again, verbatim, "Can you run it?"; lead: option 2. The wrapper was stopped again
  (logged). `testbed/e9/e9ops.py` real_schedule changed (sha256 6860faec... -> 497fb462...): each night at the first
  04:12 UTC inside its day, the special events at their registered day and UTC time of day, batches at START + 2 h;
  byte-identical to the registered schedule for START 2026-10-11T12:00Z (both 1c1bfae1...; proof files in
  `HOMEPROV-P13-exp/e9/amendment1/`); tests 180 + 81 pass; run_e9.sh not edited (it reads no pre-registration).
- `exp/out/e9_preregistration_amendment1.json` registered 16:15Z, sha256
  `cad4f5eb504a7731f611509ab000ab6d20af400177398732b4dbe5a261fdd085`, .ots pending (4 calendars; `ots upgrade` later):
  new START 2026-10-10T19:00:00Z, end event 2026-10-17T19:01:00Z, schedule sha256 2792564...; run_e9.sh to start
  before 17:00Z with `HPR_E9_START=2026-10-10T19:00:00Z` (hard limit 18:00Z, MIN_SETUP_S).
- The first proof `exp/out/e9_preregistration.json.ots` was upgraded at 16:16Z: complete, Bitcoin blocks 970748 /
  970753 / 970754 (verify against a Bitcoin node or a block explorer).
- 16:15Z: starting run_e9.sh from the agent session was denied by the session's permission system; the start is
  left to the PI/lead (command in 4.2 with `HPR_E9_START=2026-10-10T19:00:00Z`).

### 6.5 Targeted smoke of the person move (2026-10-10 08:05-08:48 UTC; exit 0, scored)

Setup and the day-3 session only (`HPR_E9_SMOKE_ONLY=namemap`), scratch hub seeded as in 6.4 (full 30-day recorder).
The setup created the persons of the household accounts that had none and the account-less "Jordan Rivera
(household)"; the run log says `person re-link mode = move`; all 8 `person_update` calls ok. On both monitors the
verifier lists 5 name-map transitions: the rename, the declared move and move back, and the declared clean-up excused
(4 RENAME markers consumed; the markers for intermediate states no seal caught stay unconsumed), the undeclared attack
move flagged (`unexcused_changes` 1). Floors 0/0/0 on untouched segments; full-history seals 144 s / 156 s, cgroup peaks
949,215,232 B / 1,180,508,160 B, no restart; quick_check failures 0. Scratch stack, images and ports removed afterwards.

### 6.4 Final smoke on the frozen code (2026-10-10 05:48-07:56 UTC; exit 0, scored)

Code: monitor `8ad9e2d7...`, verifier `9c42fad9...`, issuer `fcf66817...`, `test_e9.py` `9d9f034d...` (preflight: 180
monitor and 81 anchor tests pass; in-image hashes equal). Stack re-created with the FULL 30-day seed (199 MB, 1.2 M
rows); `HPR_E9_QUICK_CHECK_DIRECT=12` (smoke only); 22-minute days; day 3 = backup, restore, then an attack batch.
Run directory `HOMEPROV-P13-exp/e9/smoke/e9s_final/`, score `smoke/out/e9s_final_score.json`.

| Check | M-direct | M-copy |
|---|---|---|
| streamed full-history seal inside Docker | 145 s, 184 records, cgroup memory.peak 946,692,096 B, 0 restarts | 146 s, 183 records, 1,161,584,640 B, 0 restarts |
| seconds with a row at START without an anchored root | 0 of 385,520 | 0 of 385,520 |
| snapshots | all 8 `readonly_mount` (outside the hub; 199 MB in about 4 s) | |
| detection: day 1 (before) and day 3 (after the restore), PU, PSR, INS-L, BD-S | 1/1 each, both days | same |
| unexcused on untouched segments s/m/h, days 1/2/3 | 0/0/0 of 252/19, 266/22/1, 272/18 | same |
| forced purge (keep 29 d, on time; DB: 71,523 states older than the cutoff -> 0, 16 rows disconnected in 11 s, 6 of them > 1 h after the cutoff) | 0 unexcused new violations, 0 keylog; excused 36,129 s / 3,032 min / 53 h older than the cutoff, tolerance band 4 s / 2 min / 1 h, purge disconnects 7 s / 6 min / 5 h = 16 rows in 11 s | same |
| PURGE marker | posted 06:49:07 (its declared second), operator signature valid, before the purge | same |
| restore | RESTORE_DONE valid (H present, post_restart_wm consistent, 0 rows above backup_wm before H); RESTORE -> anchored RESTORE_DONE 82.50 s; read back by the falling watermark 37.8 s after the marker; excused 30 s + 2 min, all between restore point - 30 s (07:15:38) and H (07:18:43), latest 07:18:38; the post-restore attack seconds not excused (`segment_sealed_after_the_restored_recorder_was_read`) | 82.53 s; same |
| name map | rename, benign swap, benign swap back, clean-up excused; the undeclared attack swap flagged; 4 RENAME markers consumed | same |
| quick_check | every 12 polls: due 64 of 769, 0 failed, 0 unobservable; snapshot stage median 242.6 ms due / 1.3 ms not due | every poll: 705, 0 failed; median 124.3 ms |
| per-poll total ms median / p90 / max | 100 / 279 / 1,768 (direct 762, copy fallback 7 while the hub was down) | 217 / 510 / 1,535 |
| bytes read / written (whole smoke) | 19.4 GB / 1.43 GB | 335 GB / 141 GB |
| suspect seconds with / without binding | 0 / 0 each day | same |
| witness, signatures | ok; 1,406 records signed ok | ok; 1,280 |
| host | no wall-clock gap, no pmset sleep, no VM clock jump; 10 hub starts, each with its harness cause | |

Scoring: 18 verifications with 2 jobs in 877 s. Teardown: configuration restored byte for byte; no `e9s-` container,
volume, network or image left; witness ports free; `hpr-*` untouched.

**Readiness for 2026-10-11 12:00 UTC: yes, on the harness side.** Remaining before the start: register the
pre-registration (`python3 testbed/e9/e9_prereg.py --final --out exp/out/e9_preregistration.json`, then the external
timestamp); the PI's power/lid/update settings (section 5); start the script between 09:00 and 10:30 UTC; and, for
the name-map session, at least two household accounts on `hpr` (the setup creates their persons; with fewer it skips
the re-link and logs it).

## 7. Open points for the lead

**Update 2026-10-10 (part A final, pending its re-check; harness updated offline, no Docker run).** Findings 7.1-7.3 are
fixed in the verifier (tolerance band c0..c0+tol with per-row checks, E9_IMPL_NOTES.md 10.2 and 11.4; RESTORE rule
11.1 with the signed `backup_wm`; RENAME markers consumed and deduplicated, 10.4 and 11.3); 7.4 by the streamed
full-history seal (10.1: 0.75 GB peak natively, not yet measured in Docker); 7.12 by 10.5. The harness now sets
`HOMEPROV_KEYLOG_REWIND=1` on both monitors and `HOMEPROV_QUICK_CHECK_EVERY` per monitor (lead: M-direct 720, once
an hour; M-copy 1, every poll; the preflight refuses other values in the real run and logs each container's own
setting; the scorer reports quick_check due polls, their cost and unobservable polls by reason per monitor), passes `--purge-tol-s 60`,
`--restore-tol-s 30`, `--restore-max-age-s 86400` (and the verifier's fixed 60 s purge first-seen slack is recorded),
runs the benign swap before the attack again, and scores with `E9_VERIFY_JOBS=2` on the host (at most about 6 GB of
footprint by 11.2). Review N1 (re-check): the day-4 archive is held outside the hub, placed and checked with the hub
stopped, and closed by an operator RESTORE_DONE marker (`--restore-done-max-s 600`; the real run's preflight requires
`restore_done_marker` in the issuer and `--restore-done-max-s` in the verifier; `e9ops.py` wraps
`restore_done_marker()`, part A's final code: monitor `8ad9e2d7...`, verifier `9c42fad9...`, issuer `fcf66817...`). The smoke uses `HPR_E9_QUICK_CHECK_DIRECT=12` so M-direct's quick_check runs once a
minute; the real run keeps 720. Every recorder snapshot (nightly, end of day, the restore's backup) is now read outside
the hub through the read-only mount (online backup API, `mode=ro&readonly_shm=1`); tested here only against a local WAL
database with a live writer (6,000 rows, WAL rows included, quick_check ok); inside the container (SQLite 3.40, read-only
Docker mount) the final smoke must show `method: readonly_mount`, else the recorded fallback is the hub's `/tmp`. The
final smoke run on the frozen code starts only on the lead's go, after the E2 driver's
`driver_done` and the direct-mode cost re-run. The items below are kept as found.

1. **Verifier, PURGE tolerance band (part A, A1).** With `--purge-tol-s 60` the scoped cutoff is the scheduled time
   minus keep plus 60 s, while Home Assistant's own cutoff is its fire time minus keep. Retained rows that the purge
   disconnects in that band sit in segments "older than the cutoff", which the rule requires to be gone, so they stay
   unexcused (`rows_left_in_a_segment_older_than_the_cutoff`, keylog `changed_row_older_than_every_cutoff`). Smoke 3: 5
   unexcused violations and 1 keylog range per monitor; smoke 2 hid it only because its purge fired 57 s late. On the
   lab installation this would recur at every nightly purge. Fix in the verifier (rows left in [cutoff - tol, cutoff)
   may be unchanged or disconnected only), or pre-register a tolerance of a few seconds (Home Assistant fired at
   04:12:00.47 in E2's reproduction; the sleep guard keeps the timer on time).
2. **Verifier, RESTORE straddle (part A, A6).** A segment starting in [restore point - tol, restore point) still holds
   the backup's rows from before the restore point, but the rule excuses such a segment only if every row in it is new;
   the minute holding the restore point stayed unexcused in smoke 3 (1 untouched minute on day 3, both monitors).
3. **Verifier, RENAME replay (part A, A3/A6).** A RENAME marker is matched by its part digests and is not consumed, so it
   excuses any later change to the same state: in smoke 3 the attack swap, identical to the benign swap declared
   earlier, was excused. The harness now runs the attack before every marker for its state, but the gap stays (a declared
   change, reverted, can be re-applied unseen later). Consuming a marker at its first matching transition would close it.
4. **Memory: blocker for the real run.** The full-history first poll of a recorder of the lab installation's size
   (199 MB, 1.2 M rows) was OOM-killed in Docker's 7.75 GB VM (6.1); natively it peaked at up to 4.24 GB. The
   harness now seals one monitor at a time, but one monitor alone was also killed while the other stacks held about
   3.6 GB (stopping `hpr-monitor` for the week frees 0.45 GB). Options: (a) the PI raises Docker Desktop's memory
   (Settings > Resources, e.g. 14-16 GB of the Mac's 24 GB); this restarts Docker and so every container, `hpr-*`
   included, and must happen after the E2 night and before the week; (b) part A lowers the first poll's peak (seal the
   history in slices over several polls, stream the escrow); (c) stop the unrelated stacks (`delaysteer-*`, `ds-*`,
   `e9k-*`) for the week, which is not mine to decide. The 1.6 GB of escrow per monitor for the initial seal is fine on
   disk (224 GB free).
5. **Docker latency.** On this Mac, with the current load, `docker run` sometimes took 40-60 s to start a container
   (the smoke setups took 12-13 min mostly for that). The PURGE issuer now starts 3 min early and posts at 04:10:00; other
   events tolerate it (their lateness is logged). Running nothing else Docker-heavy during the week (5.4) matters.
6. **Anchor tests (resolved).** `test_saved_evaluation_chains_verify_as_v1` failed during the smokes on E8 chain
   snapshots added to `reproduce/snapshots/`; the lead moved them (E9_IMPL_NOTES.md 9.1) and both suites pass again.
7. **Restore.** Home Assistant documents a restore for a Container install, but starting it through the backup manager
   needs an access token. E9 runs Home Assistant's own start-up restore (`backup_restore.py`) on an archive the operator
   builds from a consistent SQLite copy (section 2). If the PI prefers the UI path exactly, a token must be minted in the live
   deployment (a PI decision, E2_PURGE_DIAGNOSIS.md 4).
8. **Person re-link = swap.** With a person for every household account, Home Assistant refuses a link to an account
   another person holds; the attack is therefore a swap of two persons' accounts (E6 re-linked a person to an account
   without one). If the lead prefers E6's form, leave one household account without a person in the setup.
9. **Accounts on `hpr`.** I did not read `hpr`'s storage (E2 night). The setup creates a person for every active,
   non-system household account without one, and the swap needs at least two; with fewer the name-map session runs the
   benign rename only and logs "person re-link skipped". Check after 05:00 UTC 10-10 (read-only) how many accounts `hpr`
   has; [Withheld from the artifact: what an attack integration does when that account is missing. The attack integrations and the E6 in-hub harness are not released (README.md, "What is deliberately not here").]
10. **Effects on the default deployment** (by design, as E7/E8): stock monitor and anchor stopped for the week (a 7-day
   gap in the default chain); `person:` added for the week and removed at the end (the persons stay in
   `.storage/person`, inert without it); about 3 hub restarts a day, 2 in setup, 2 for the name-map session, 1 planned,
   1 restore, 1 at teardown.
11. **Counts.** 5 trials per arm per day (35 per arm and monitor). 10 a day would cost about 10 more minutes a day.
12. **For part A** (seen in the smoke, not fixed by me): `e7_verify.check_namemap` reads name-map records past
   `--snapshot-at` while markers after the snapshot are rejected (`after_snapshot`), so a day's verification reports a
   later declared rename as an undeclared change; the scorer works around it (name-map storage on the last day only,
   per-day transitions restricted to the day's window).
13. **Scoring time.** On the 24 MB smoke recorder each verification took 30-70 s (16 of them: 7 min). The real run has a
    ~200 MB recorder, a 30-day historical window per night and a 7-day chain with the full-history seal: expect much
    longer (not measured). The scorer caches every verification and can run on a copy of the run directory during the
    week (4.2).
14. **External timestamp.** I did not try OpenTimestamps (AGENT_BRIEF rule 8: nothing is sent to external services);
    the lead or the PI does it at registration (3.5).
15. **Smoke configuration.** The scratch hub ran 2026.7.4 on the E6 configuration (made with 2026.10.0b2), so two storage
    files it could not read (`http`, `core.device_registry`) were dropped from the clone; the real run uses `hpr`'s own.
