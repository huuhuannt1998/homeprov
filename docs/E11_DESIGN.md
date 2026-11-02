# E11 design (round 15): does the principle carry to a third hub family? openHAB, measured

Status: DESIGN, 2026-10-14. Nothing of E11 has run. No Docker is used for E11 until E10 has been scored
(`exp/out/e10_main_score.json` exists, no `run_e9.sh`/`run_e10.sh` process, no `e9*`/`e10*` container); every E11 script
refuses otherwise (`testbed/e11/e11_stack.sh guard`). The PI approved E11 on 2026-10-14 with the option label
"Reframe + openHAB (E11)". The PI's framing, verbatim: "We are doing research and finding a scientific contribution, not
a pentester".

E11 answers RQ4 of SP2027_ACCEPT_PLAN.md section 0, "Does the principle carry across hubs?", for a third hub family:
- **(a)** Can the evidence openHAB shows be measured as a renderer closure?
- **(b)** Do a schema-chosen commitment and a whole-row commitment fail there in the same two directions as on Home
  Assistant and Domoticz?
- **(c)** Does the out-of-process monitor, with a closure-checked commitment and only its read path replaced, detect
  post-commit rewrites of the persisted history, at a low benign floor and a feasible cost?

The instrument that makes post-commit rewrites is kept minimal: the three smallest edits of the persisted history that
openHAB's documented persistence extensions allow, on one item. No other openHAB weakness is explored.

Every number below is a parameter fixed here, read from a saved result file (path given), or read from openHAB's
documentation or source at a release tag (URL in section 12). Nothing here is a result.

| File (all new) | Role |
|---|---|
| `testbed/e11/monitor/oh_monitor.py` | the openHAB row reader: imports `monitor/monitor.py` unchanged and replaces its read path (section 6) |
| `testbed/e11/run_e11.sh` | the harness: phases build, closure, main; refusals; interpreter guard; closure gate; scoring |
| `testbed/e11/e11_stack.sh` | the scratch openHAB stacks (prefix `e11*`): up, console, restart, snapshot, down, guard |
| `testbed/e11/e11ops.py` | plan (seeded), provisioning, the closure driver, the instrument arms, the benign operations, UI capture, pyguard |
| `testbed/e11/build_bundles.sh` | builds the two OSGi bundles against the jars in the pinned hub image, with a JDK in a container |
| `testbed/e11/fixture/` | benign fixture bundle: simulated devices, TimeSeries writes, housekeeping removal (releasable) |
| `testbed/e11/attack/` | the instrument bundle (never released: git-ignored, FORBIDDEN in the artifact build) |
| `testbed/e11/conf/` | openHAB configuration: `services/addons.cfg`, `services/jdbc.cfg`, `services/runtime.cfg`, `persistence/jdbc.persist` |
| `testbed/e11/test_e11.py` | 27 static tests with fake data (section 11) |
| `testbed/e11/e11_prereg.py` | the pre-registration generator (`--out` draft, `--final`, `--check`) |
| `exp/stages/e11_score.py` | the scorer, with E11's verification rule and the closure gate |
| `drafts/round13/E11_PREREG_DRAFT.json` | the generated draft (status DRAFT) |

## 1. Hypotheses

Stated in full in `E11_PREREG_DRAFT.json` (`hypotheses`, H1-H8). In short:

| | Question | Hypothesis | Measured by |
|---|---|---|---|
| H1 | (a) | The rendered history is a deterministic function of a measurable field set: {items.ItemId, items.ItemName (both only after the index reload), `<table>`.time, `<table>`.value (Number values only to 3 decimals), the table's name, registry.itemType, registry.meta.unit, the registry entry itself}. rowid, label, category, tags and groups are outside it. | E11-CLO (section 3) |
| H2 | (a) | Neither the rendered history nor the persisted rows carry a cause, user or source field: on openHAB the closure protects the integrity of a history **without attribution**. | E11-CLO: the rendered fields |
| H3 | (b) | A commitment chosen from the persistence schema (`rows`: every stored column of every item table, nothing joined) misses closure fields: single writes of ItemName, ItemId, itemType, unit or a registry deletion change the rendered history and every closure root of that item, and 0 `rows` roots. | single-write checks |
| H4 | (b) | openHAB rewrites no persisted field in place, so the whole-row floor on untouched segments is 0: unlike Home Assistant (`last_reported_ts`) and Domoticz (DeviceStatus columns), that failure direction does not carry; it is conditional on in-place rewrites. Whole-row still over-commits: rowid and label writes, B-LABEL and B-REPLACE-SAME change whole-row roots and not the rendered history. | in-place probe, floor, single writes, benign operations |
| H5 | (c) | The closure monitor detects 30 of 30 trials per arm (A-BD, A-RM, A-CHG), at the second and the minute. | E11-DET |
| H6 | (c) | No attributable violation on any untouched anchored second, across two restarts and an index clean. | E11-DET |
| H7 | (c) | B-BACKFILL, B-REPLACE-NEW and B-RETAIN produce attributable violations on exactly the seconds they change (a backfilled row is indistinguishable from an A-BD row under the rule); B-REPLACE-SAME, B-LABEL, B-RESTART, B-CLEAN produce none. | E11-DET |
| H8 | (c) | The port is feasible: monitor.py unchanged; one reader module replacing five functions; median poll below 1 s; no observable-poll gap above 30 s; no hub write failure. | cost log, hub log |

H4 is the hypothesis most likely to change the paper's text: if it holds, the lesson "whole-row hashing breaks on columns
the writer rewrites in place" is conditional on the hub, and openHAB is the hub where the condition is absent (Q9).

## 2. Hub, persistence service, stacks

**Release.** openHAB **5.2.3**, released 2026-10-10 (openhab-distro releases page), the current release (5.3.0 is at
milestone M3). Image `openhab/openhab:5.2.3@sha256:fa50a6934dfd5bcbf21db18af66f2558f58c6c493ba23bdeb7a894e764507a99`
(manifest list; arm64 manifest `sha256:1423029b…5fc7a93`), read from Docker Hub on 2026-10-14. The 5.2.2 and 5.2.3
release notes list no change to persistence, JDBC, REST persistence, the persistence extensions or TimeSeries; the
DAO strings E11 depends on were re-read at the 5.2.3 tag. (`openhab/openhab:5.2.1` and `4.3.2` are present on this Mac
from earlier work; 5.2.3 is pulled in the build phase, after E10.)

**Persistence service: JDBC on SQLite.** Choice and why:
- It stores one row per persisted state in tables a reader outside the hub can open: an index table `items`
  (`ItemId INTEGER PRIMARY KEY AUTOINCREMENT`, `ItemName`) and one table per item, named `item` + zero-padded ItemId
  (`item0001`), with `time` (declared `TIMESTAMP`, SQLite text `'YYYY-MM-DD HH:MM:SS.mmm'` in the hub's local time,
  `strftime(..., 'localtime')`) and `value`, `PRIMARY KEY(time)`, written with `INSERT OR IGNORE` (JdbcSqliteDAO,
  JdbcBaseDAO, NamingStrategy at 5.2.3).
- SQLite is listed by the JDBC page as "supported and tested" (`sqlite-jdbc-3.53.1.0`), as the feature
  `openhab-persistence-jdbc-sqlite`. A file database needs no second server; the monitor reads it through the same
  SQLite path it uses for Home Assistant and Domoticz.
- The service implements `ModifiablePersistenceService`, so the documented persistence extensions that persist
  back-dated states and remove persisted ones (Section 9's claim) work on it.
- Not chosen: **H2** (a Java database; no reader outside the JVM without the H2 jar); **MariaDB/MySQL** (a second server
  whose own access path a monitor would read instead); **rrd4j** ("replacing ten readings with the average of the ten
  readings as the data gets older", tutorial: consolidation rewrites history by design); **mapdb** (last state only).

**What the renderer reads (from the source, to be confirmed by E11-CLO).** `GET /rest/persistence/items/{item}`
(PersistenceResource; roles user and administrator) returns `{name, datapoints, unit, data: [{time, state}]}`
(ItemHistoryDTO). The JDBC service maps the item to its table through the index, **cached** in memory ("Manual changes
in the index table, Items, will not be picked up automatically for performance reasons", JDBC page; `jdbc reload`
reloads it). It selects `time, value` (Number: `ROUND(value, 3)`, `numberDecimalcount` default 3) with second-resolution
text bounds (`TIME>='yyyy-MM-dd HH:mm:ss'`), parses `time` with `Timestamp.valueOf` (JVM time zone) and builds the state
from `value` with the item's type and, for Number items, its unit (objectAsState). Main UI's Analyze view draws this
response; its exact request is captured in the smoke (`e11ops.py uicapture`) and registered.

**Configuration** (`testbed/e11/conf`, everything else at the distribution's defaults): `addons.cfg` installs only
`jdbc-sqlite`; `jdbc.cfg` sets only `url` (database in the userdata volume); `runtime.cfg` adds regional time zone UTC
(the container also runs with `TZ=UTC`), default persistence `jdbc`, `implicitUserRole=false` (every REST read is
authenticated), `allowBasicAuth=true` (the harness reads as each account). `jdbc.persist` gives each item a strategy
(openHAB 5.1 and later have no default strategies): everyChange, everyUpdate, a cron everyMinute, restoreOnStartup,
forecast.

**Stacks** (`e11_stack.sh`; nothing outside the `e11*` prefix is touched):
- `e11c` (closure instance, E11-CLO) and `e11s` (run stack, E11-DET); smoke prefixes `e11cs`, `e11ss`.
- Hub `PREFIX-hub` on the internal network `PREFIX-net`. It is attached to a provisioning network only while the
  add-on is downloaded, then detached. Volumes conf/userdata/addons are initialised from the image's own
  `/openhab/dist` (registered alternative if absent).
- `PREFIX-harness` (python:3.13-slim) is the household's client: the host reaches the hub through the Domoticz run's
  tunnel (`testbed/domoticz/harness/tunnel.py` and `relay.py`, reused unchanged).
- Accounts `owner` (administrator) and `member` (user) are created with the Karaf console, with per-run random
  passwords in a 0600 file; only fingerprints are logged. openHAB has no viewer role.
- E11-CLO only: a database helper `PREFIX-dbh` (uid 9001, userdata read-write) for the per-field writes.

**Household workload (main stack).** 14 managed items (`e11ops.ITEMS`), six motion-light rules (light on when motion
opens, off when it closes), and the fixture bundle's device schedule: two temperatures every 10 s (everyUpdate), power
every 3 s (persisted by the cron each minute), three motions every 60-90 s, a retention probe every 30 s, an energy
counter every 60 s, a label probe every 7 min. About 15 seconds with rows per minute (an estimate from the schedule,
not a result).

## 3. E11-CLO: the renderer closure (H1, H2, H4's in-place probe)

The Domoticz method (`exp/stages/dz_closure.py`), repeated on openHAB, on the closure instance only (never the run hub).
Implemented in `e11ops.py closure`.

- **Fixtures.** One item per rendering path of the DAO: Switch, a second Switch (the swap partner), Contact, Number,
  Number:Temperature with unit metadata °C, Dimmer, String, DateTime. Each gets a predecessor row and then the target
  row, 1.5 s apart, through the fixture bundle.
- **Render.** `GET /rest/persistence/items/{item}` over an explicit window of ±1 day, as owner and as member, with the
  UI's parameters once captured (`E11_RENDER_PARAMS`). The comparison covers the status and the full body.
- **Mutations**, each followed by a render, a restore, a render and a restore check against the baseline (the run
  aborts if a restore differs):
  - target row `time`: +1 s, −3 days, milliseconds dropped, ISO `T`, integer milliseconds;
  - target row `value`: suffix, empty, NULL, the predecessor's valid value, and for Number +1 and +0.0004 (below the
    rendered precision);
  - target row `rowid`: a fresh key;
  - the table's name [Withheld from the artifact: the SQL statement of this mutation. See README.md, "What is deliberately not here".];
  - the index row: ItemName suffix, ItemName swapped with the other Switch, ItemId fresh. Each is rendered immediately
    and after `openhab:jdbc reload`; rows the service adds to the index while an item is hidden are removed and logged;
  - the registry through its REST API, as in-runtime code would use the registry: itemType changed, label, category,
    tags, groups, `stateDescription` pattern (rendered with and without `displayState=true`), unit metadata changed or
    added, and the item deleted.
- **Controls.** Determinism (two baseline renders equal); positive control (the predecessor's value changes the
  rendered state); same render for both accounts; every restore equal to the baseline.
- **Attribution (H2).** The rendered keys are recorded (`dto_top_level_keys`, `dto_point_keys`).
  `HistoricItem` (read at 5.2.1) has `getTimestamp`, `getState` and `getName` only; no stored column names a cause.
- **In-place probe (H4).** Every stored row of every table and every registry entry is dumped before and after benign
  traffic: commands from both accounts, one update of every fixture, a minute of the device schedule, a hub restart.
  The dumps are diffed column by column. Predicted: no column of any existing row changed; rows only added.
- **Gate.** Before E11-DET, `e11_score.py --closure-gate` requires every measured field to be one the reader commits
  and the controls to hold. Otherwise the run stops, the reader is amended (registered and stamped), then E11-DET runs.

## 4. The instrument (minimal)

**Third-party code path: an OSGi bundle (binding-shaped), not a JSR223 script.**
- Main UI's add-on page distinguishes "official bindings from the openHAB Distribution, which have been thoroughly
  reviewed by the maintainers" from "bindings independently released by the community on the Community Marketplace".
- The marketplace's "Bundles" category (forum category 73) serves `.jar`/`.kar` files. `MarketplaceBundleInstaller`
  (read at 5.2.1) installs them with `bundleContext.installBundle(...)` and `bundle.start()`, with no signature or
  checksum check in that class: into the core's OSGi framework, the same Java runtime.
- The documented manual equivalent is a `.jar` in the `addons` folder ("Place the .jar file in the addons folder"), which
  E11 uses; the privilege is the same.
- This is the analogue of Home Assistant custom integrations and Domoticz Python plugins, and it is what Section 9
  and Table 7 name.
- Rule templates and JSR223 scripts are also third-party paths into the same JVM, but they are user automation and
  E11 does not measure them.

**What it does** (`testbed/e11/attack`, `org.homeprov.e11.lockbridge`, never released):
[Withheld from the artifact: the instrument bundle's implementation: how it acts as the lock's binding and the openHAB calls it uses to insert a back-dated state, remove a stored state and change a stored value of that one item (arms A-BD, A-RM, A-CHG), with its constraints, acknowledgement channel and action log. See README.md, "What is deliberately not here".]

**Arms** (`e11ops.py arm`; order drawn from seed 20261021: A-BD, A-RM, A-CHG; 30 trials each, 3 s apart; seal wait 130 s, as Domoticz):

| Arm | Phase 1 (genuine) | Phase 2 (after 130 s) | Rendered (both accounts) | Closure | rows | wholerow |
|---|---|---|---|---|---|---|
| A-BD | a mark t (seeded ms offset) at which nothing happens to the lock | a back-dated OFF point inserted at t [Withheld from the artifact: the instrument's call. See README.md, "What is deliberately not here".] | a new OFF point at t, all others unchanged: 30/30 | attributable 30/30 (late row after seal, or rows in a second sealed empty; lag ≥ 130 s) | 30/30 | 30/30 |
| A-RM | instrument relocks (ON); member unlocks through REST (OFF) at t | remove t's second | the OFF point gone: 30/30 | attributable 30/30 (sealed row removed) | 30/30 | 30/30 |
| A-CHG | as A-RM | the value stored at t changed to ON [Withheld from the artifact: how the instrument makes the change. See README.md, "What is deliberately not here".] | the point at t shows ON: 30/30 | attributable 30/30 (sealed row changed) | 30/30 | 30/30 |

**Why n = 30 per arm.** As Domoticz (30 per arm). Each trial has a deterministic prediction. 30 of 30 gives the exact
interval [0.884, 1.000] the paper reports for Domoticz. 0 misses in 30 bounds the per-trial miss rate at
1 − 0.05^(1/30) = 0.0950 (one-sided 95%). Three arms cover the three documented edit kinds.

**UI (secondary).** Before the arms and after each arm, Main UI's Analyze view of the lock is loaded in a headless
browser as each account. Every `/rest/persistence` request it makes is recorded and compared with the harness's own
read of the same query (`uicapture`).

## 5. Benign operations specific to openHAB, and what needs a declaration (H6, H7, H4)

| Op | What | Closure | rows | wholerow | Needs a declaration? |
|---|---|---|---|---|---|
| B-STRAT | all session: everyChange, everyUpdate, cron everyMinute, restoreOnStartup, forecast; the rules | none (floor) | none | none | no |
| B-REPLACE-SETUP | REPLACE TimeSeries of 12 future 5-min points (Price_Forecast) at t_start | no past point | | | no |
| B-REPLACE-SAME | REPLACE over the last 30 min and next hour; past points re-sent unchanged | **none** (no rowid in the closure) | attributable per point | attributable per point | no (closure) |
| B-REPLACE-NEW | as SAME, past values + 1.0 | attributable per changed point | same | same | **yes**: a forecast correcting its past |
| B-BACKFILL ×3 | ADD TimeSeries of ≤10 past states, one per minute over the last 10 min (Energy_Backfill) | attributable per point (lag ≥ 60 s) | same | same | **yes**: "persisting historic state" is a documented use |
| B-LABEL | owner renames Label_Probe's label (REST) | none | none | attributable on every second holding a Label_Probe row sealed before the rename | no (closure) |
| B-RESTART ×2 | docker restart; the household resumes | none | none | none | no |
| B-CLEAN | `openhab:jdbc tables clean` (removes index rows of missing tables and empty tables of deleted items) | none (no orphan) | none | none | no |
| B-RETAIN | housekeeping: remove Retention_Probe states older than 20 min (whole-second bound) | attributable per removed row's second | same | same | **yes**: as Home Assistant's PURGE |

Background, from the source and documentation:
- **No retention.** The JDBC persistence documents no retention setting; users write housekeeping rules with the
  removal extensions.
- **TimeSeries.** "The TimeSeries is used to transport a set of states together with their timestamp. It can be used for
  persisting historic state or forecasts" (javadoc). Bindings send one with `ThingHandlerCallback.sendTimeSeries`; it
  reaches the item as an `ItemTimeSeriesEvent` (ItemUpdater → `setTimeSeries`). PersistenceManagerImpl stores every entry,
  past or future, for items with an update or forecast strategy. Under REPLACE it first removes `[begin, end]`. [Withheld from the artifact: how the fixture bundle submits its TimeSeries writes. See README.md, "What is deliberately not here".]
- **Restart.** restoreOnStartup restores with `setState` while the manager's own listener is detached: no row is
  expected.
- **Offline (single writes).** A unit change and the deletion of an item also change the rendered history and the
  closure. They need a declaration, as Home Assistant's RENAME does.

## 6. The monitor port (H8): how the reader plugs in

`testbed/e11/monitor/oh_monitor.py` is the container's entry point (`python -u /ohm/oh_monitor.py`), like
`testbed/domoticz/monitor/dz_monitor.py`. It imports `monitor.py` from `HOMEPROV_MONITOR_DIR`: the image's `/app`, whose
hash the harness checks against `monitor/monitor.py` and the run's copy. It then replaces five module-level functions;
`monitor.py` is not edited:

| Replaced | Why |
|---|---|
| `snapshot()` | A consistent copy through SQLite's online backup API from a read-only connection. The SQLite DAO sets no journal mode, so SQLite's default rollback journal applies unless the driver is configured otherwise (the snapshot records the mode); there a file copy can tear pages, and monitor.py's copy is built for a WAL recorder. The backup works in either mode. |
| `validate_copy()` | Wraps the shipped function; only adds `snapshot_failed`, so a failed backup becomes an unobservable poll on the chain. |
| `check_connection()` | quick_check as monitor.py; the hardened monitor's quick_check latch kept; with the hardened monitor, an object check that `items` and every mapped item table is one ordinary table; an openHAB schema probe. |
| `watermark()` | `{"items": max(ItemId), "<table>": max(rowid)}`: SQLite assigns rowid max+1, the arrival order the late-row test needs. |
| `load()` | Persisted rows as closure nodes. Key `o:<table>:<time>`. Content: the v2 typed encoding of (table, ItemId, ItemName, time, value, registry itemType, registry unit), with the registry read from the hub's JSON database. Rows the index does not map are not rendered and not folded. |

Everything else is monitor.py's code: sealing, the laminar second/minute/hour segments, coverage records, the HMAC
append, Ed25519 record signatures, reply tags and the state file.
- **Settings.** `HOMEPROV_SCHEME=closure`, `HOMEPROV_COVERAGE=1`, `HOMEPROV_KEYLOG=0`, `HOMEPROV_READ=copy`,
  `HOMEPROV_QUICK_CHECK_EVERY=1`, `HOMEPROV_PERIOD=5`.
- **Refused at start:** keylog, direct read, `HOMEPROV_SINCE`, escrow, name map, clock file and a non-UTC hub. Each
  would run a Home Assistant path.
- **Compatibility.** The same module runs with the E9-frozen monitor (8ad9e2d7) and with the E10-hardened one. Tested:
  `test_reader_with_e10_hardened_monitor` applies `monitor/hardening_e10.patch` to a copy and runs a tick.
- **Anchor and witness as E8/E9.** A linked anchor (`hpr-anchord:e11` built from `testbed/e8/anchord-e8.Dockerfile`)
  with an append key and a separate operator key; a head witness on the host at port 19986, outside Docker's VM.
  Fresh keys per run, fingerprints only. The signing key lives in a Docker volume that is destroyed at teardown.
- **Read-only.** The hub's userdata volume is mounted read-only, and the monitor is on the hub's internal network with
  the anchor.
- **Offline-scheme archive.** `load()` also writes, on the monitor's scratch, every column of the rows dated in the last
  180 s of every table, the index and the registry. As in the Domoticz run, the scorer validates each archived read by
  reproducing the anchored closure roots before using it for `rows` and `wholerow`.

## 7. Outcomes and scoring (`exp/stages/e11_score.py`)

**Verification rule** (the scorer's docstring has the full statement; unit-tested). It is the Home Assistant
verifier's late-row test, with the per-table rowid watermark in place of the recorder's keys. For segment k:
- c = the first observable poll covering k;
- R = k's first anchored root, frozen with watermark W_R;
- F = k's rows in the final snapshot;
- a row's lag = the copy time of the latest observable poll whose watermark is below the row's rowid, minus the row's
  timestamp.

| Case | Verdict |
|---|---|
| commit(F) = R | no violation. If R was frozen after c, the rows that arrived after c are classified by lag. |
| commit(F) ≠ R, and removing the rows with rowid above W_R reproduces R | those rows are late arrivals, classified by lag |
| commit(F) ≠ R otherwise | **attributable** (a sealed row removed or changed) |
| no R and F not empty | F's rows are classified by lag |

Classified by lag: attributable if any lag > L = 30 s, else benign_late. Detected means attributable.

**Outcomes:**
- **O1** closure: fields, controls, rendered fields, in-place probe.
- **O2** schemes: detection, floor and benign verdicts per scheme; single writes on copies of the final snapshot
  (value, time, rowid, ItemName, ItemId, itemType, unit, label, registry deletion → changed one-second roots per scheme).
- **O3** detection per arm and scheme, second and minute, exact intervals; instrument effect rendered for both accounts;
  UI agreement.
- **O4** floor: attributable violations over untouched anchored seconds and minutes; benign-late segments; per benign
  operation, the verdict classes of the seconds it changed.
- **O5** port: lines of monitor.py changed (0), reader size and the functions replaced, per-poll cost (median, p90,
  max), observable-poll gaps, hub-log lines with `SQLITE_BUSY` or `database is locked`.
- **Characterisation, not a result about attacks:** events.log lines carrying `(source: ...)`, counted by sender kind.
  ItemCommandEvent and ItemStateChangedEvent `toString()` append the source when the sender set one; REST commands
  carry `org.openhab.core.io.rest$<user>`.

**Touched set and floor.** As in Domoticz, a second is touched if it holds a row an arm wrote, edited or named (relock,
unlock, mark), or a row a benign operation changed: re-sent, backfilled or removed points, and every Label_Probe second
for B-LABEL. The floor counts untouched seconds only, with restarts and the index clean inside. Expected size: about
1,300 untouched anchored seconds over a session of about 110 min (an estimate from the schedule). 0 of 1,300 would bound
the rate at 0.0028 (one-sided 95%).

**Exclusions:** trials returned with `err` are listed, not scored. Smoke runs are not results. Polls made unobservable
by a restart are reported, not excluded.

**Comparison:** side by side with the saved Domoticz files (`exp/out/dz_closure.json`, `dz_*_detection.json`: closure of
11 fields, 30/30 per arm, closure floor 0/169, whole-row 169/169) and the Home Assistant results, never pooled.

## 8. Threats to validity

- **Scope.** One release (5.2.3), one persistence service (JDBC on SQLite, defaults), one Mac, virtual devices from a
  fixture bundle, compressed time. rrd4j, mapdb and InfluxDB are not measured; rrd4j consolidates history by design.
- **The instrument uses only the persistence extensions.** Other write paths that in-runtime code has (SQL on the file,
  the registry API, events.log) are not exercised, by the framing. The closure's mutations do write those fields, but on
  the closure instance, as measurement.
- **The registry.** The reader reads managed items from the JSON database (the harness provisions through REST). Items
  defined in `.items` files are not read: for them the registry part of the closure is not committed.
- **The keylog is not ported.** Coverage records give sealed-empty seconds and late-row dating, but not the per-row
  first-observation binding that, on Home Assistant, closes rows parked in the future or unjoinable rows. E11 does not
  exercise those.
- **E11's verification rule is new code** (unit-tested on fake data: 6 rule tests covering 7 cases), not `exp/stages/e7_verify.py`, which
  reads Home Assistant tables. Rowid reuse after deleting a table's newest row changes the rule's label (removal or
  change instead of late insertion), not detection.
- **Lock-held backup.** The backup holds a shared lock on a rollback-journal database while it copies; a hub write waits
  (xerial's busy timeout) and could fail if the copy were slow. This is measured (O5), not assumed.
- **Time zone.** 'localtime' text is ambiguous in a daylight-saving fall-back hour; E11 runs in UTC, where it is not.
- **Index cache.** An index edit changes the rendered history only after `jdbc reload` or a restart. The monitor commits
  the stored index, so it reports the change before the hub shows it (Q7).
- **Timing.** The A-BD lag (≥ 130 s) is far above L; E10 measures the late-commit boundary on Home Assistant, and E11
  does not repeat it.
- **Workload.** Benign traffic comes from a fixture bundle and REST commands, not physical bindings. The floor's
  denominator is an estimate until the run.

## 9. Time budget (target: under 2 days of machine time including smoke)

| Phase | What | Estimate |
|---|---|---|
| 0 | wait until E10 is scored (`exp/out/e10_main_score.json`), about 2026-10-20 18:00Z; ledger entry in MAC_COORDINATION.md | — |
| 1 | build: pull openHAB 5.2.3 (about 350 MB) and, if the hub image has no javac, eclipse-temurin:21-jdk; compile both bundles; build `hpr-monitor:e11`, `hpr-anchord:e11`; in-image hashes | 20-30 min |
| 2 | smoke: `HPR_E11_SMOKE=1 run_e11.sh e11_smoke1 all`. Closure on 3 fixtures; main at 0.2 scale (n = 3 per arm); `uicapture` fixes the render request; outputs under HOMEPROV-P13-exp/e11/smoke | about 1.5 h |
| 3 | registered alternatives (if any), `e11_prereg.py --final`, `ots stamp` | 15 min |
| 4 | real: `run_e11.sh e11 all`. Build reused or rebuilt; closure (8 fixtures, about 45 mutations each, index reloads) about 45-60 min; closure gate; main about 2.3 h (provisioning 10 min, warm-up 10, window 1 25, arms about 25, benign about 35, window 2 30, settle and snapshot 3) | about 3.5 h |
| 5 | scoring (archive reconstruction of about 1,500 records), `ots upgrade` | 20-30 min |

About 6 h of machine time in total, about one calendar day (10-21, inside the plan's 10-21 to 10-23 slot). Load: the
openHAB JVM uses 1-2 cores at start and well under one after; memory is about 1.5 GB in the 8 GB VM; the monitor reads
a database of a few MB. Per MAC_COORDINATION.md rule 1 the harness is started with `taskpolicy -b` (host-side processes; Docker's VM share is Docker Desktop's), and the run gets a ledger line before it starts.

## 10. Open questions for the lead (decisions that change the threat model, the guarantee or the paper's claim)

1. **Benign back-dated writes.** Persisting historic state is a documented use on openHAB (TimeSeries ADD), and so are
   REPLACE forecasts that correct past points. The rule flags B-BACKFILL rows exactly like A-BD rows. Options:
   (i) the guarantee covers items without time-series writers, stated as a limit;
   (ii) an operator-declared per-item window, which an in-hub adversary could then forge into;
   (iii) a new marker kind.
   Each option changes the guarantee.
2. **Housekeeping removal** (B-RETAIN) needs a PURGE-like declaration, per item and cutoff. Home Assistant's PURGE marker
   is recorder-wide with keep-days. Define an openHAB marker, or state the limit?
3. **Attribution on openHAB.** The persisted history has none (H2). events.log lines do carry a sender-set
   `(source: …)`, including the REST account (`org.openhab.core.io.rest$<user>`); the event-bus page calls it
   informational only. Main UI's Log Viewer shows the in-memory log service buffer, not events.log. Section 9 says
   openHAB "documents no displayed cause". Should the hub model separate a history without a cause from an event log
   with a sender-set source? E11 neither protects nor edits events.log.
4. **Persistence-service scope.** The paper's openHAB claim would hold for the JDBC persistence. rrd4j (suggested by
   the tutorial) consolidates in place by design, so no commitment over its stored archive can be stable. Scope the
   claim to JDBC, or extend E11?
5. **Registry source.** Commit managed items only (JSON database), or also parse `.items` files? This is a scope
   statement in the paper.
6. **Keylog.** The openHAB port seals segments with coverage records but has no first-observation binding. Paper
   wording for "the monitor port", or port the keylog (row tables per item) first?
7. **Cached index.** The monitor flags an index edit at its next poll; the hub shows the change after a reload or
   restart. Is a change flagged before it is rendered "detected" or "pending"? (Wording.)
8. **Verifier.** E11 scores with its own rule (`e11_score.py`), not `e7_verify.py`. Is "the same monitor, a verifier
   with the same late-row rule" acceptable for the paper, or should the verifier get a row-reader abstraction?
9. **The general lesson.** If H4 holds, "whole-row hashing breaks on columns the writer rewrites in place" is a property
   of Home Assistant and Domoticz, not of every hub. On openHAB whole-row over-commits only to fields the renderer does
   not read (rowid, labels, re-sent points). The L1 framing of the two failure directions would need that qualification.

## 11. Static work done (2026-10-14; no Docker)

- `py_compile` passes for every Python file; `bash -n` passes for `run_e11.sh`, `e11_stack.sh` and `build_bundles.sh`.
- `pytest -q testbed/e11/test_e11.py`: **27 passed** with `<home>/miniconda3/bin/python3` (3.13). The tests cover:
  - the reader on a synthetic JDBC-shaped database: nodes, join, watermark, backup snapshot, `snapshot_failed`, the
    object check;
  - the shipped `tick_coverage()` end to end with the reader: records carry the per-table watermark and seal;
  - the same tick on the E10-hardened monitor, applied to a copy;
  - the two failure directions in miniature (9 single-write cases);
  - the verification rule: unchanged, removed, changed by remove-and-reinsert, back-dated insert, benign late row,
    insert into a sealed-empty second, REPLACE-SAME;
  - chain parsing and coverage; the scorer's single writes, arm scoring, floor and closure summary;
  - the scorer's `main()` end to end on a synthetic run (one shipped-monitor poll, one sealed row removed): the
    trial is detected under all three schemes and the offline schemes are rebuilt from the archive (fake data,
    not a result);
  - plan determinism; the interpreter guard, which refuses `/usr/bin/python3`.
- The Java sources are not compiled yet (the Mac has no JDK). They compile in the build phase; a compile error is fixed
  in the smoke, before `--final`.
- No E9-frozen file and no E10 patch file was modified. Of the 36 `code_sha256` entries of
  `exp/out/e9_preregistration.json`, 35 match; `testbed/e9/e9ops.py` matches the hash E9 amendment 1 registers, as
  E10_DESIGN.md notes. `monitor/hardening_e10.patch` (`ff37854a…`) and `exp/stages/verifier_e10.patch`
  (`df90b1f9…`) are unchanged.
- One edit outside the new files: `<artifact-root>-artifact-prep/round13_build.py` FORBIDDEN gains
  `"testbed/e11/attack"`; round13d and round14 inherit it through `R13.FORBIDDEN`. Also `testbed/e11/.gitignore`
  ignores `attack/`.
- Nothing was committed or pushed. The manuscript is not edited.

## 12. Sources opened (2026-10-14)

Documentation:
- https://www.openhab.org/docs/configuration/persistence.html (strategies, filters, persist/remove extensions; "5.1 and
  above no longer support default strategies")
- https://www.openhab.org/addons/persistence/jdbc/ (databases and drivers, table naming, index cache, console commands,
  parameters, no retention setting)
- https://www.openhab.org/docs/tutorial/persistence.html (rrd4j averaging)
- https://www.openhab.org/docs/configuration/addons.html (manual `.jar` installation)
- https://www.openhab.org/docs/mainui/addons.html (distribution vs Community Marketplace bindings)
- https://www.openhab.org/docs/developer/utils/events.html (event source: sender-set, informational only)
- https://www.openhab.org/docs/mainui/developer/log-viewer
- https://www.openhab.org/javadoc/latest/org/openhab/core/types/timeseries
- https://www.openhab.org/javadoc/latest/org/openhab/core/thing/binding/thinghandlercallback
- https://raw.githubusercontent.com/openhab/openhab-docker/main/README.md (volumes, TZ, Karaf client, user 9001)

Source, openhab-addons (`bundles/org.openhab.persistence.jdbc/...` at tag 5.2.1, and the two DAO files again at 5.2.3):
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.1/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/db/JdbcSqliteDAO.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.3/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/db/JdbcSqliteDAO.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.1/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/db/JdbcBaseDAO.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.3/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/db/JdbcBaseDAO.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.1/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/NamingStrategy.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.1/bundles/org.openhab.persistence.jdbc/src/main/java/org/openhab/persistence/jdbc/internal/JdbcPersistenceService.java
- https://raw.githubusercontent.com/openhab/openhab-addons/5.2.1/bundles/org.openhab.persistence.jdbc/src/main/feature/feature.xml

Source, openhab-core (`bundles/...`):
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.io.rest.core/src/main/java/org/openhab/core/io/rest/core/internal/persistence/PersistenceResource.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.persistence/src/main/java/org/openhab/core/persistence/dto/ItemHistoryDTO.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.persistence/src/main/java/org/openhab/core/persistence/HistoricItem.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.persistence/src/main/java/org/openhab/core/persistence/extensions/PersistenceExtensions.java (and at 5.2.3)
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.persistence/src/main/java/org/openhab/core/persistence/internal/PersistenceManagerImpl.java (and at 5.2.3)
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core/src/main/java/org/openhab/core/types/TimeSeries.java (and at 5.2.3)
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.3/bundles/org.openhab.core/src/main/java/org/openhab/core/items/events/ItemEventFactory.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.3/bundles/org.openhab.core/src/main/java/org/openhab/core/internal/items/ItemUpdater.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.3/bundles/org.openhab.core.io.rest.core/src/main/java/org/openhab/core/io/rest/core/internal/item/ItemResource.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.3/bundles/org.openhab.core/src/main/java/org/openhab/core/items/events/ItemCommandEvent.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.3/bundles/org.openhab.core/src/main/java/org/openhab/core/items/events/ItemStateChangedEvent.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.addon.marketplace/src/main/java/org/openhab/core/addon/marketplace/internal/community/CommunityMarketplaceAddonService.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.addon.marketplace/src/main/java/org/openhab/core/addon/marketplace/internal/community/CommunityBundleAddonHandler.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.addon.marketplace/src/main/java/org/openhab/core/addon/marketplace/MarketplaceBundleInstaller.java
- https://raw.githubusercontent.com/openhab/openhab-core/5.2.1/bundles/org.openhab.core.io.websocket/src/main/java/org/openhab/core/io/websocket/log/LogWebSocket.java

Releases and images:
- https://github.com/openhab/openhab-distro/releases
- https://github.com/openhab/openhab-distro/releases/tag/5.2.2
- https://github.com/openhab/openhab-distro/releases/tag/5.2.3
- https://hub.docker.com/v2/repositories/openhab/openhab/tags/5.2.1
- https://hub.docker.com/v2/repositories/openhab/openhab/tags/5.2.3
- https://hub.docker.com/v2/repositories/openhab/openhab/tags?page_size=25&ordering=last_updated
