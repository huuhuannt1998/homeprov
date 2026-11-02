# E2: why the 2026-10-09 nightly purge deleted nothing

Written 2026-10-09 (UTC). Internal diagnosis note, not text for the paper. Source read from the image
`homeassistant/home-assistant:2026.7.4` (the image hpr-hass runs) with `docker run --rm --entrypoint tar`. I did
not exec into hpr-hass, open its volume, or change any hpr-* container. The only things I read from the live
deployment were `docker logs`/`docker inspect` output. Line numbers below refer to that image's
`homeassistant/components/recorder/*` and `homeassistant/helpers/event.py`.

## 1. Cause

**The PurgeTask never ran on 2026-10-09.** The recorder did not run a purge that found nothing to delete.

1. HA schedules the nightly task as an asyncio timer. `_async_setup_periodic_tasks` (core.py 619-653) calls
   `async_track_time_change(..., hour=4, minute=12, second=0)` (core.py 644-647). This happens once, when the
   recorder becomes ready (core.py 499). The helper turns the wall-clock target into a **monotonic** deadline at
   arming time: `loop.call_at(loop.time() + expected_fire_timestamp - time.time(), self)` (helpers/event.py 1461-1466).
   When the callback fires, it re-checks only whether it is early (1482-1488), not whether it is late. After firing,
   it re-arms for the next day (1781-1795).
2. In Docker Desktop's VM, CLOCK_MONOTONIC stops while the Mac sleeps, and the wall clock is resynced on wake. A
   fresh container showed `time.time() - time.monotonic()` = 1789300446.2 (2026-09-13 11:54:06 UTC). That equals
   `/proc/stat btime`. The VM process (`com.apple.Virtualization.VirtualMachine`) started at 2026-09-04 20:03:36 UTC
   (host `ps`). The guest monotonic clock is therefore 8.66 days behind wall time, which is the host's sleep time
   since then.
3. The HA instance that was live that night started on 2026-10-08 at 20:24:55 UTC (recorder run 180). `pmset -g log`
   then shows `Clamshell Sleep` from 20:42:39 to 21:52:41 UTC: 12 sleep intervals totalling **3,835 s**, separated
   by dark wakes. There is no Sleep entry after that up to 05:03 UTC on 10-09. The 04:12:00 timer was therefore due
   at about **05:15:55 UTC**.
4. `docker logs hpr-hass` shows `legacy-services: stopping` at **2026-10-09T05:03:11Z**, a restart about 13 minutes
   before the delayed fire. `_async_shutdown` → `_async_stop_listeners` cancels `_nightly_listener` (core.py 433-438,
   399-413). Every later instance that day (restarts at 05:03, 05:13, 05:18 … 07:56:58) arms its timer for
   2026-10-10 04:12. As a result, no PurgeTask was queued on 2026-10-09.

Contrast with the night before. The instance started at 2026-10-07 23:17:00 UTC, and pmset shows no sleep until
2026-10-08 15:47 UTC. That purge ran on time (see 2.1).

## 2. Evidence

### 2.1 No purge executed (snapshots, opened read-only from scratch copies; sha256 matches night_log.jsonl)

| | pre_oct9 (03:55) | post_oct9 (04:45) | an on-time purge would give |
|---|---|---|---|
| states / events older than 2026-09-09 04:12 | 4,937 / 5,700 | 4,937 / 5,700 | 0 / 0 |
| min(statistics_runs.start) | 2026-09-08 04:15 | 2026-09-08 04:15 | 2026-09-09 04:15 |
| recorder_runs min run_id (run 63 ended 2026-09-09 01:24:40) | 63 | 63 | run 63 deleted (`end < purge_before`, queries.py 253-265) |

The same PurgeTask pass also deletes statistics_runs (purge.py 93-103), and those were untouched as well. Compare
the 2026-10-08 night: min(statistics_runs.start) moved from 2026-09-07 04:15 (pre_oct8) to 2026-09-08 04:15
(post_oct8), so that purge ran between 03:55 and 04:40 with a cutoff of about 2026-09-08 04:12. It deleted no
states or events because none were older than its cutoff (the oldest state is 2026-09-09 01:17:55).

The logger is set to `default: warning`. Every purge failure path logs at ERROR: `Error executing purge`
(util.py 631), `Unhandled database error while processing task` and `SQLAlchemyError error processing task`
(core.py 899-904). None of these appear in the log.

### 2.2 The stalled monotonic clock is visible in the recorder itself (post_oct9.db)

- The states have gaps exactly at the sleep windows: 20:42:55–20:44:44, 20:45:03–20:46:05, 20:46:55–20:48:31,
  20:49:27–20:50:26, 20:51:51–21:45:13 and 21:47:36–21:52:53. States at 21:45–21:47 match pmset's three 45 s
  dark wakes, which started at 21:45:12.
- statistics_runs runs 20:45, then 21:45, with no 21:40 row. If the monotonic clock had kept running, the overdue
  5-minute timer would have fired on resume at 21:45:13 and compiled the 21:40 period. A stalled clock predicts
  that it fires at about 21:54 instead and compiles 21:45, which is what the database holds. The 20:40 and 20:45
  rows also fit the stalled-clock timing.

### 2.3 Other candidate causes, ruled out

- **Guard on the last purge time:** there is none. `async_nightly_tasks` (core.py 503-513) checks only `auto_purge`
  and stores no last-purge state.
- **Task queue:** PurgeTask shares the recorder queue, and the queue drained all night (5-minute statistics tasks
  ran through 04:35; commit_interval is 1).
- **Locks from the monitors' copies or homeprov's `_graph()` reader:** in WAL mode, readers do not block the
  writer. A SQLite lock error would be an OperationalError logged at ERROR (util.py 619-634), and none was logged.
  In any case, the purge never started.
- **keep_days arithmetic:** `purge_before = dt_util.utcnow() - timedelta(days=self.keep_days)` (core.py 510). On
  time, this gives 2026-09-09 04:12:00, which the reproduction confirms (3b).
- **Batching:** states are processed in batches of 4,000 (max_bind_vars), 20 batches per pass (purge.py 50-51,
  173-207). 4,937 rows take a single pass; the reproduction finished in under 1 s.

### 2.4 Earlier nights: purged, not recreated

- `schema_changes` has one row (schema 53, 2026-08-31 07:36:00). `recorder_runs` starts at run_id 63
  (2026-09-09 01:17:55). min(states.state_id) is 135,553.
- `docker logs hpr-hass` begins at **2026-08-31T14:29:09Z**, not 2026-09-03; the container was created then. HA
  started 57 times before it was stopped at 2026-09-04T19:52:32Z, and it next started at 2026-09-09T01:17:51Z.
  Nothing was recorded in between.
- Everything older was deleted by nightly purges once their cutoff passed 2026-09-04 19:52, that is, by the purges
  from 2026-10-05 onward. Runs 1-62 were removed by `delete_recorder_runs_rows`. The base_oct7 and pre_oct8 copies
  show min statistics_runs = 2026-09-07 04:15, so the 2026-10-07 purge also ran.

## 3. Reproduction

Setup: throwaway containers `e2p-*` using the same image, run with `--network none`. Each used its own volume
holding a copy of pre_oct9.db (sha256 07b21122…). The configuration had the deployment's `homeassistant:` block
(time_zone UTC), `recorder:` block (commit_interval 1, purge_keep_days 30, auto_purge default), `http:`,
`logbook:` and `history:`. It had no custom components or MQTT, and `homeassistant.components.recorder.purge` was
logged at debug. Everything was removed at the end: 0 e2p containers and 0 e2p volumes remain.

**(a) Service call over REST.** I onboarded a user in the throwaway instance, minted a long-lived token over the
websocket API in that instance only, and sent `POST /api/services/recorder/purge {"keep_days": 30}` at
2026-10-09 08:14:10 UTC. The response was HTTP 200. The purge target was 2026-09-09 08:14:10, and within 1 s the
result was:

- states older than 2026-09-09 04:12: 4,937 → 0
- events older than 2026-09-09 04:12: 5,700 → 0
- total states: 755,041 → 744,412
- min(statistics_runs.start): 2026-09-09 08:15

**(b) Nightly path with a faked clock.** I used Alpine's libfaketime (`libfaketimeMT.so.1` via LD_PRELOAD). The
wall clock was set through `FAKETIME_TIMESTAMP_FILE`, and `FAKETIME_DONT_FAKE_MONOTONIC=1` left the monotonic clock
real, which is the VM's behaviour. HA's own log timestamps confirmed that HA saw the faked time.

- **b1, control.** Started at fake 04:10:05 with no clock jump. The listener fired at 04:12:00.47 with target
  2026-09-09 04:12:00. Old rows went from 4,937/5,700 to 0/0, and min(statistics_runs.start) became
  2026-09-09 04:15.
- **b2, simulated host sleep.** Started at fake 04:05. Once the recorder was up, I jumped the wall clock +600 s
  (04:05:3x → 04:15:34) and left the monotonic clock untouched. Nothing was deleted in polls from 04:15:34 to
  04:21:35. The listener fired at **04:22:00.45** with **target 2026-09-09 04:22:00**. It deleted the old rows and
  also 236 states and 126 events in [04:12, 04:22) on 2026-09-09.
- **b3, as b2 plus a restart.** `docker restart` at fake 04:18:06, before the delayed fire. There was no purge
  through 04:26, and all 4,937/5,700 old rows remained. This matches what the real night produced.

## 4. Getting the next real night to purge

- **Keep the host awake** from hpr-hass's last start until after 04:12 UTC. Leave the lid open on AC power with
  `caffeinate -i -s` running. With the lid closed on battery, the Mac sleeps regardless (this is what happened at
  20:42 on 10-08).
- **Check the next morning:** `pmset -g log` should show no Sleep entry between hpr-hass `StartedAt` and 04:12.
- **If the host did sleep:** restarting hpr-hass after the wake and before about 04:10 re-arms the timer against
  the wall clock and removes the lag.
- **Never restart hpr-hass between 04:12 and the purge.**
- **Read-only check that the purge ran, on a snapshot:** min(statistics_runs.start) should advance to
  (date − 30 d) 04:15, and runs with `end` before the cutoff should be gone.
- **Tonight:** hpr-hass started at 2026-10-09 07:56:58 UTC and is armed for 2026-10-10 04:12. Its on-time cutoff is
  2026-09-10 04:12; post_oct9.db holds 34,790 states and 20,999 events older than that.
- **Heads-up for 2026-10-11:** that date is the second Sunday of the month. `auto_repack` defaults to True, so the
  04:12 purge that day will also repack (VACUUM) the database (core.py 509; util.py 762-775).
- **An operator-triggered `recorder.purge` takes the same code path.** `_async_handle_purge_service`
  (services.py 90-98) computes `purge_before = utcnow - keep_days` and queues the same `PurgeTask`
  (tasks.py 115-136 → `purge.purge_old_data`). The defaults `repack=False, apply_filter=False` (services.py 36-42)
  equal the nightly call except for the second-Sunday repack. Only the trigger differs: there is no timer, so the
  call is immune to the stall if the caller fires on wall time. Its cutoff is the call time minus keep_days.
  Using this on hpr-hass needs a token minted in the live deployment, which is a change for the PI to approve.

## 5. Implications for E2 (for the PI; nothing changed)

1. **The 2026-10-09 real-night arm is vacuous.** `exp/out/e2_scoped_markers_real_night.json` reports
   `new_violations_after_purge: 0` with scoped excused 0 / remaining 0, but no purge happened that night. The
   2026-10-08 purge ran, yet no state or event was older than its cutoff. So no real night has yet exercised a
   marker against rows the hub actually deleted.
2. **A delayed purge breaks the scoped marker's timing assumption.** The issuer declares `scheduled_ts` = 04:12,
   and the verifier uses cutoff = `scheduled_ts - keep_s + tol_s` (exp/rig/markers.py 172-175; tol_s = 60 in the
   result file). HA's actual cutoff is fire time − 30 d, and the fire time is 04:12 plus the host sleep since HA
   last started. That delay is unbounded. In b2, a 600 s delay deleted 236 states and 126 events younger than the
   declared cutoff. Had the 10-09 timer fired at about 05:15:55, it would have deleted 1,473 states and 759 events
   with timestamps in [2026-09-09 04:13:00, 05:15:55), counted in pre_oct9.db. These would surface as unexcused
   violations, which are false alarms.
3. **A restart in the window cancels the purge.** A restart between 04:12 and the delayed fire (10-09's case) means
   no purge, and the 04:10 marker goes unconsumed.
4. **The issuer has the same exposure.** Its `time.sleep(nxt - lead_s - now)` (marker_issuer.py `main`) also runs on
   the VM monotonic clock. Both markers were on time (issued 04:10:00.18 on 10-08 and 04:10:00.10 on 10-09) only
   because the issuer started after the last host sleep (2026-10-08 21:53:44).
5. **Options, not applied.** All four are for the PI to choose; none is applied.
   - (i) Keep the host awake (operational; keeps the default-deployment story).
   - (ii) Set `auto_purge: false` and have the operator call `recorder.purge` at the scheduled instant. Schedule
     and purge then share one clock and code path, but the deployment is no longer default.
   - (iii) Bind the marker to the observed purge rather than the schedule. This weakens the scoping argument.
   - (iv) A larger tol_s does not bound the delay and widens what a marker excuses.
