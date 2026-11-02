# HomeProv

Tamper-evident actuation provenance for Home Assistant.

A home-automation hub that answers "what caused this" creates evidence worth
forging. Home Assistant derives that answer from three columns of its recorder
database — `context_id_bin`, `context_parent_id_bin`, `context_user_id_bin` —
and `context_parent_id_bin` is not a description of the causal edge but the edge
itself, an ordinary mutable column bound to nothing. Any integration running in
the hub process can rewrite it.

This repository holds the defensive implementation, the testbed configuration
and the evaluation harness with its result files.

Author: Huan Bui, University of North Carolina at Charlotte (hbui11@charlotte.edu).

## Coordinated disclosure

Some files of the artifact are withheld until the dates stated in `DATA.md`:
those that implement or describe step by step the issues reported privately to
Home Assistant and to the Domoticz maintainers, until 25 January 2027, and two
files on Home Assistant Supervisor, reported on 30 October 2026, until 28 January 2027.
`DATA.md` lists each withheld file with its size and sha256, so the copies
published later can be checked against this release.

## What is here

| Path | What it is |
|---|---|
| `monitor/monitor.py` | External monitor. Observes recorder state from outside the hub process and commits it; closure scheme by default, row and stable-columns schemes selectable. This is the version E10, E10b, E11 and E12 ran: E9's monitor with the SQLite hardening of `monitor/hardening_e10.patch` applied (defensive connection settings, a check that `states` and `events` are tables, `quick_check` as the first statement when one is due and on a process's first poll; `HOMEPROV_HARDEN=0` restores E9's reads). E9's settings are unchanged: per-row keylog binding (`HOMEPROV_ROWBIND`), the full-history first poll (`HOMEPROV_SINCE`), direct read of the live recorder (`HOMEPROV_READ=direct`), `HOMEPROV_QUICK_CHECK_EVERY` and `HOMEPROV_KEYLOG_REWIND` (after a restore) are settings, and a test (`monitor/test_e9.py`) checks that with all of them unset its records, state file and escrow are byte-identical to `monitor_e8.py`'s. |
| `monitor/monitor_e9.py`, `exp/stages/e7_verify_e9.py` | The monitor and the verifier the E9 run used, kept byte for byte (sha256 `8ad9e2d7...`, `9c42fad9...`; E10's registration froze them under these names). |
| `monitor/hardening_e10.patch`, `exp/stages/verifier_e10.patch` | The two E10 patches, as applied to E9's monitor and verifier to give `monitor.py` and `e7_verify.py` (`testbed/e10/test_e10_patches.py` tests them). |
| `monitor/pinned_columns.py`, `monitor/monitor_v2.py`, `exp/stages/verify_v2.py`, `monitor/test_verify_v2.py` | Version 2 of the monitor and the verifier (exploratory, offline; added in round 17). **No registered run used version 2**: every registered verdict and number comes from `monitor.py` and `e7_verify.py`, which version 2 imports and runs unchanged (it checks their registered digests, `4b9931cb...` and `ae9d9c42...`, and refuses other bytes). Under stable columns it recomputes each root over the committed column list in force when the segment was sealed: the list monitor version 2 signs into every record or, for a record without one, a list given with its source, such as a run's start snapshot (`--pinned-columns-db`, `--pinned-columns-json`). A column added later is not read for earlier segments and is reported with its count of non-NULL rows; a committed column that disappears still fails every root over a row of its table. It also reports a segment as a violation when two validly signed records carry different roots for it, in either order (`--conflict-rule off` gives the registered verifier's output). `pinned_columns.py` is the single implementation of the monitor's stable-columns loads with the column list passed in; `test_verify_v2.py` holds version 2's unit tests. |
| `exp/stages/r17_v2_*.py`, `exp/out/r17_v2_*.json` | Version 2 run offline on saved data (no registered run used it): `r17_v2_migration.py` repeats E10's offline migration check (`e10_migration_offline.py`) on E10's final snapshot with and without a states column added, given the start snapshot's column list (`r17_v2_migration.json`); `r17_v2_regress.py` re-runs verifications the registered scorers saved for E10, E10b, E12 and E9 and compares each output byte for byte and second by second with the saved one (`r17_v2_regress_e10.json`, `_e10b.json`, `_e12.json`, `_e9.json`; the checks that were not run are listed in each file's `summary.not_run`); `r17_v2_two_roots.py` builds the synthetic chain of exception (X8), a monitor that loses its state and re-seals an edited second, with a test key made for the run and deleted after it (`r17_v2_two_roots.json`; only key fingerprints are recorded). They read the run directories, which are not here. |
| `monitor/monitor_e8.py`, `exp/stages/e7_verify_e8.py` | The monitor and the verifier the E8 run used, kept byte for byte (sha256 `3e479ae0...`, `7e036386...`); the published E7 and E8 verify files are reproduced with them (`reproduce/verify_e7e8.py`). |
| `monitor/monitor_wholerow.py` | Whole-row baseline entry point (commits every stored column). |
| `monitor/test_node_hash.py` | Node-hash encoding tests: the collision case, a decoder-based injectivity property test, v1 compatibility vectors. |
| `reproduce/` | `verify_all.py` re-verifies the ten real-deployment runs, `verify_e7e8.py` E7 and E8, `recount_floats.py` recounts every other float; `snapshots/` holds the per-run window extracts and anchor chains they read; `reference_reports/` holds the reports this tree produced. |
| `exp/sp2027/` | Drivers and analyses added for this revision (`r1_*` and `r2_*` rendered displayed cause on the newer releases, the second set on fresh stacks with an integrity gate before and after each phase, `exp/out/r2_integrity/`; the six render scripts that edit the recorder are withheld until 25 January 2027 (see "Coordinated disclosure"), their result files are here; `r2_localize.py` real-deployment localization; `r6_*` node-hash encoding analyses, `r7_*` the anchor link and head witness (the Marketplace delivery driver is withheld, see "Coordinated disclosure"), `r9_*` reruns and bootstrap, `r10_coarse_roots.py` the offline minute- and hour-root check on the window extracts). |
| `testbed/anchord/` | Append-only anchor daemon, run in a separate container; appends accepted only with a valid HMAC-SHA256 tag. `anchord_r12.py` is the daemon every run before E7 used, kept byte for byte; `anchord.py` is the hardened version (a thread per connection, read timeouts, a request deadline and a body limit; E7 ran it before the operator key and tagged replies were added; E8 ran the version kept as `anchord_e8.py` with `anchord_linked_e8.py`, which imports `anchord`, so copy both under their E8 names to rerun it; the current version, which E9 runs, also keeps the chain state in memory, and `test_anchor_cache.py` compares it with the E8 daemon); `anchord_linked.py` wraps it with hash-linked records (`prev_digest`, `HOMEPROV_ANCHOR_LINK=v2`) and pushes its head to `headwitness.py` on another host; `chainverify.py` checks a chain (and an externally held head), `test_anchor_chain.py` tests both. Every chain an evaluated run wrote verifies as unlinked `v1`, except the chains of the E5 and E8 runs, which are linked (`v2`); E8's records are also signed (verify with `--sign-pubkey`). |
| `testbed/e1/`, `exp/stages/e1_two_host.py` | Two-host placement (E1): the hub in a Home Assistant OS virtual machine with a privileged core, the monitor and anchor in a second virtual machine on the same computer standing in for another host; the monitor reads a recorder copy replicated every 2 s (`replicator/`) and seals with the hub's clock (`HOMEPROV_CLOCK_FILE`). |
| `testbed/e5/`, `exp/stages/e5_linked.py` | One run with the linked anchor (`anchord_linked.py`) and the head witness outside both virtual machines; checks the witnessed heads and the truncation and relinking controls. |
| `exp/stages/e6_namemap.py` | Name-map digest check: with `HOMEPROV_NAMEMAP_DIR` set (default off), the monitor anchors a digest of the inputs the displayed cause reads outside the recorder; this verifies it and its lifecycle markers. |
| `exp/sp2027/r13_*.py` | Subset test and insertion experiment (offline), lab write rate, monitor cost, the paper's counting rule for the benign floor. |
| `reproduce/NUMBERS.md` | Every number the paper's prose prints, with the result file and locator it is read from (generated from the evidence records the manuscript is written from). |
| `testbed/e7/`, `exp/stages/e7_verify.py`, `exp/stages/e7_score.py` | E7: sealed coverage (each record names the time sealed through and the highest row keys; a per-poll keylog commits each row at its first read), frozen roots re-sent until anchored, optional escrow (`HOMEPROV_ESCROW_DIR`), and the stable-columns scheme (`HOMEPROV_SCHEME=stable`); the run's pre-registration is `exp/out/e7_preregistration.json` with one amendment. The run used `monitor.py` sha256 af8fd5b7...; its E8 version (`monitor/monitor_e8.py`) also escrows the keylog's first-read rows (a fix after the run; with `HOMEPROV_COVERAGE=0` it reproduces the earlier monitor byte for byte). The published E7 verify files are reproduced with the verifier kept as `exp/stages/e7_verify_e8.py`; `exp/stages/e7_verify.py` is the current (E10) version. `monitor/test_coverage.py` holds the coverage tests. The integration that performed E7's edits is not here (see below). |
| `testbed/domoticz/`, `exp/stages/dz_*.py` | The Domoticz 2026.3 run: renderer-closure measurement (`HPFixture`, per-field mutation of a snapshot copy), benign traffic (`HPSensors`, dzVents automations), the Domoticz row reader for the monitor (`monitor/dz_monitor.py`) and the harness. |
| `testbed/e8/`, `exp/stages/e8_score.py` | E8: the stable-columns scheme (deployed) and the closure scheme, both with coverage, escrow and Ed25519 record signatures (`HOMEPROV_SIGN_KEY`; `monitor/requirements-sign.txt`, `Dockerfile.sign`), each with its own linked anchor (`anchord_linked_e8.py` over `anchord_e8.py`, the E8 versions, with a separate operator key for lifecycle markers and tagged replies) and a head witness that accepts only a head extending its last; seven arms of 90 trials, a baseline window and a write-rate stress window (`stress_publisher.py`). The pre-registration is `exp/out/e8_preregistration.json`; the run's monitor and verifier are `monitor/monitor_e8.py` and `exp/stages/e7_verify_e8.py` (the files of these names without `_e8` are the current, E10, versions; E9's are kept with `_e9`). The published signing keys are `exp/out/e8_main_{stb,clo}_sign_pub.pem`. The integrations that performed E8's edits are not here (see below). |
| `exp/stages/e8_closure_real.py` | E8 part B: the renderer closure re-measured by per-field mutation of a copy of the real deployment's recorder, rendered by the release's own logbook processor in a throwaway hub. |
| `testbed/anchord/e8_witness_gap_check.py`, `test_anchor_e8.py` | The witness accepts a head only if it extends its last and the verifier checks the chain against every witnessed head; the check replays a rewrite-relink-append attack at every position of E5's saved chain under the earlier and the current rule. |
| `reproduce/verify_e7e8.py`, `reproduce/make_e7e8_extracts.py` | E7 and E8 from recorder rows: `reproduce/snapshots/e7e8/e7_main.db` and `e8_main.db` hold every row the verifier reads for each scored window (each run's saved recorder copy reduced by `make_e7e8_extracts.py`; listed in `EXTRACTS_E7E8_SHA256SUMS`, described in `extract_manifest_e7e8.json`), next to each monitor's anchor chain. `verify_e7e8.py` re-runs the E8 verifier (`exp/stages/e7_verify_e8.py`, with `monitor/monitor_e8.py` as its monitor; `--verifier` and `--monitor` run other code, and its report names the code that ran) on them with the published parameters (and E8's public keys) and compares its output, field by field and number by number (detection per arm, the earlier rule's counts, the benign floors, the suspect seconds, E8's signature, cross-key and witness checks), with `exp/out/e7_main_*_verify.json` and `exp/out/e8_main_*_verify_*.json`; with `--escrow` it also compares the recovery sections (E7's from `exp/out/e7_main_escrow_scored.jsonl.gz`, the 2,680 escrow lines the run's verifier read, of which `exp/out/e7_main_escrow.jsonl.gz` holds the first 2,674; `exp/out/e7_main_escrow_scored.json`). |
| `docs/` | The design documents and run notes the E7, E8 and E9 pre-registrations cite, and the E9 code review, with `docs/README.md`: which pre-registration cites which, when each was last modified relative to the registrations, what was masked and what was withheld. |
| `exp/stages/e7_verify.py`, `exp/rig/marker_issuer.py` | The verifier (E9's, with E10's patch: observation breaks make a late row unknown rather than benign (D1), a second first covered by an incomplete or gapped poll is root-unknown (D2, with `exp/stages/e10_outcome.py`), operator CLOCK_STEP markers excuse rows a declared backward clock step made late (D3), a RESTORE_DONE without the hub's start is rejected (D4), and a row changed in the segment that straddles a purge cutoff keeps its violation (D5); its own reads of a recorder copy are hardened and it refuses a copy that fails them) and the operator tool. E9's verifier adds the checks of per-row binding, operator-signed lifecycle markers (`--operator-pubkey`), the purge-disconnect rule (a PURGE marker also excuses a retained state row whose `old_state_id` the purge cleared, when restoring the value committed at first read reproduces the anchored root and the row it named is gone and was committed before the cutoff), the RESTORE rule closed by an operator RESTORE_DONE marker, and RENAME markers for the name map, each consumed at its first matching transition (`--purge-keep-s`, `--purge-tol-s`, `--restore-tol-s`, `--restore-max-age-s`, `--restore-done-max-s`, `--namemap-storage`, `--no-rowbind`, `--no-purge-disconnect`). `marker_issuer.py` issues PURGE, RESTORE, RESTORE_DONE and RENAME markers from outside the hub under an operator key, with tagged replies checked. |
| `testbed/e9/`, `exp/stages/e9_score.py` | E9: the deployed configuration for seven days on the lab installation (a direct-read and a copy-mode monitor with per-row binding, the full-history first seal, escrow and signatures, linked anchors with head witnesses; nightly purges under PURGE markers, a planned restart, a name-map session, a backup and restore under RESTORE and RESTORE_DONE markers, a daily attack batch). `run_e9.sh` is the harness (`smoke_stack.sh` the scratch stack of its smoke runs, `start_e9_at.sh` a timed start), `e9ops.py` its helpers (schedule, markers, name-map digests, backup, host log), `e9_prereg.py` wrote the pre-registration, `exp/out/e9_preregistration.json`, with three amendments (`e9_preregistration_amendment1.json`, `_amendment2.json`, `_amendment3.json`), each with its OpenTimestamps proof (`.ots`). Of the 36 repository files the pre-registration froze (`e9ops.py` at amendment 1's digest), 31 are here at their registered digests or with machine paths rewritten, the two attack integrations are not, and 3 paths now hold the versions E10 to E12 ran (`exp/stages/e7_verify.py`, `monitor/monitor.py`, `monitor/test_e9.py`); E9's monitor and verifier are kept byte for byte as `monitor/monitor_e9.py` and `exp/stages/e7_verify_e9.py` (`reproduce/SANITIZED_r16.json`, `e9_frozen`, gives each file's status). Its results are `exp/out/e9_main2_*` (the next row). |
| `monitor/test_e9.py`, `monitor/test_e9_dishonest.py`, `testbed/anchord/test_anchor_e9.py`, `testbed/anchord/test_anchor_cache.py` | The E9 tests: per-row binding, the full-history seal, direct read, the purge-disconnect, RESTORE and RENAME rules, byte identity with `monitor_e8.py` with the new settings unset, a dishonest anchor host against signed records, operator markers against a linked anchor, and the anchor's in-memory chain state against the E8 daemon. |
| `exp/stages/e9_*.py`, `exp/sp2027/e9_*.py` | The measurements before E9 (`exp/out/e9_*.json`): monitor cost on 0.2, 1 and 3 GB recorders in copy and direct mode (`e9_cost_scale.py`; `e9_cost_scale_direct_final.json`, on the frozen monitor, supersedes the preliminary direct-mode rows of `e9_cost_scale.json`), the direct read's lock (`e9_readonly_shm_probe.py`: `e9_readonly_shm_probe.json`, `e9_readonly_shm_lockdrop.json`), direct and copy reads of saved recorders compared (`e9_direct_read_identity.py`), the escrow as a replica baseline (`e9_replica_baseline.py`), the deferred choice of a resident adversary against an in-process committer and an external monitor (`e9_deferred_choice.py`: a controlled harness on recorder bytes; its recorder edit is the member-account-swap primitive of `exp/rig/forge.py`; no hub integration), the purge-disconnect rule on the real deployment's 2026-10-10 purge (`e9_purge_disconnect_offline.py`), and a dishonest anchor host against the saved E8 chains and the smoke chains with markers (`e9_dishonest_anchor.py`, `e9_dishonest_markers.py`). Inputs outside `exp/out` (run directories, the E2 night's recorder snapshots) are not here; each result file names them with their digests. |
| `exp/stages/e2_night.py` | The E2 real night. The 2026-10-09 night's purge never ran (`docs/E2_PURGE_DIAGNOSIS.md`), so its file is not here; `exp/out/e2_scoped_markers_real_night_2026-10-10.json` is the night on which it ran (`E2_NIGHT=2026-10-10`). The night's driver and snapshots stay in its run directory. |
| `exp/sp2027/r14_*.py` | Analyses from saved files: localization per edited trial of E7 and E8 in the deployed configuration (`r14_localization_deployed.py`, from `reproduce/snapshots/e7e8`), benign failure rates per hour with a block bootstrap (`r14_benign_rates.py`; two of its runs read a chain from the full snapshot set, which is not here), and which printed outcomes follow by construction and which are measured (`r14_by_construction.py`; it reads the manuscript, which is not here; `exp/out/r14_by_construction.json` holds the sentences it classified). |
| `exp/out/e9_main2_*`, `exp/sp2027/r16_e9_*.py` | E9's results: the second launch (`e9_main2`, 2026-10-12 to 10-19; the first launch, `e9_main`, was stopped, amendment 3): `e9_main2_config.json`, the scorer's output `e9_main2_score.json` (2.6 GB, as written by `exp/stages/e9_score.py`), each monitor's chain and witnessed heads, the schedule, events, windows, the daily attack batches' reports and the host log. `r16_e9_*.py` derive the compact score, the floor matrix, the read and write counts, the window latency and the classification of touched seconds (`exp/out/r16_e9_*.json`); they read the score file and the run directory, which is not here. The records are signed; the public keys are not here (the configs give their fingerprints). |
| `testbed/e10/`, `exp/stages/e10_*.py`, `exp/stages/e10r5_score.py`, `exp/sp2027/e10_pi4_cost.py` | E10: adaptive arms on the stated boundaries of the deployed configuration and routine operations with the monitor live, on scratch stacks (`run_e10.sh`, `e10_stack.sh`, `e10ops.py`; the pre-registration `exp/out/e10_preregistration.json` with its OpenTimestamps proof): backdating, context insertion, deletion (also phase-aware), key reuse, wipes, a declared and undeclared clock step, purge-shaped deletions, locks and inflation that blind a monitor, an entity-id rename, a device removal, an entity purge, upgrades across a recorder schema change; the review-r5 arms: 90 sham trials, 10 hub restarts timed into a poll, a Domoticz switch-type change (`run_dz_switchtype.sh`, `dz_switchtype.py`), pairwise closure mutation with branch coverage (`e10_pairwise_closure.py`, on a working copy of the lab recorder in a throwaway hub, as `e8_closure_real.py`), and the cost under a Raspberry Pi 4-class cap (`e10_pi4_cost.py`); E7, E8 and E9 re-verified with the patched code (`reverify_patched.py`). Results are `exp/out/e10_*`; `exp/sp2027/r16_e10_*.py` derive the paper's E10 tables from them (`exp/out/r16_e10_*.json`; they read the run directories, which are not here). The in-hub adversary that performed the arms is not here (see below); `run_e10.sh` names it, and two static tests that read its source are withheld from `test_e10_r5.py`. |
| `testbed/e10b/` | E10b: E10's backdating arm repeated with a finer level grid and a new seed, and the clock-step arm with the hub's state rows stepped too (`run_e10b.sh`, `e10b_plan.py`, `e10b_score.py`; `exp/out/e10b_preregistration.json` with its proof; results `exp/out/e10b_main_*`). The add-on that stepped the hub's clocks (`homeprov_e10b`) is not here, and the tests that load it are withheld from `test_e10b.py`. |
| `testbed/e11/`, `exp/stages/e11_score.py`, `exp/sp2027/r16_e11_*.py` | E11: openHAB 5.2.3 with JDBC persistence on SQLite: the renderer closure measured on a scratch instance (E11-CLO), three instrument arms (a back-dated point, a removed point, a changed value; 30 trials each) and benign operations, with the monitor reading openHAB's persistence database through `testbed/e11/monitor/oh_monitor.py` (the shipped `monitor.py` with its read path replaced). `exp/out/e11_preregistration.json` with its proof; results `exp/out/e11_main_*`. The instrument bundle (`testbed/e11/attack`) is not here; in `e11ops.py` the helper's write operations on the persistence database, and in the fixture bundle the code that writes and removes persisted history, are withheld in place (see below). |
| `testbed/e12/`, `exp/stages/e12_summary.py`, `exp/sp2027/r16_e12_late_rows.py` | E12: 48 hours of the recommended configuration on the lab installation at Home Assistant's default commit interval (`run_e12.sh`, `e12ops.py`; `exp/out/e12_preregistration.json` with its proof; results `exp/out/e12_main_*`, scored by `exp/stages/e9_score.py` with the patched verifier). |
| `exp/sp2027/r14c_*.py` | Analyses from saved files: attack success of the E8 arms by the frontend's display rule, benign failures per segment, absolute localization, the two-host floor, and the member-swap spill-over (`exp/out/r14c_*.json`). Two of them tie each harness field to the line of an attack integration that set it; the quoted lines are withheld (file and line number stay), and they cannot run without the integrations. |
| `addons/homeprov_monitor/`, `addons/homeprov_anchor/` | Supervisor add-on manifests for the monitor and the anchor. |
| `exp/rig/` | Commitment schemes, verifier, localization, reconstruction, metrics, statistics, the recorder-mutation primitives (`forge.py`) and the capability record. |
| `exp/stages/` | One module per experiment; each emits a JSON report under `exp/out/`. |
| `exp/out/`, `exp/out_recal/`, `exp/out_precalib/` | Result reports. `exp/out/` is the published arm; see `exp/out/AUTHORITATIVE.md` for which file is authoritative and `exp/out/SCHEME_KEYS.md` for the artifact-key → label map. |
| `results/` | Bundled result units (the laundered-unlock write-up and the bundle that embeds it are withheld until 25 January 2027, see "Coordinated disclosure"). |
| `analysis/` | Result-processing and benchmarking scripts. |
| `testbed/ha-config/` | Testbed configuration and the defender / measurement integrations (`homeprov`, `homeprov_bench`, `homeprov_e4`; `homeprov_e5` is withheld until 25 January 2027, see "Coordinated disclosure"). |
| `testbed/real/` | Real-substrate deployment: `docker-compose.yml`, Mosquitto broker, device simulator, the real-substrate HA config and run scripts. |
| `witness/` | Cross-producer broker-witness script for the deletion-launder signature. |
| `exp/README.md`, `testbed/real/EXPERIMENTS.md` | What each experiment asks and how to run it. |

Every experiment runs in local Docker containers with virtual devices. No
physical device is actuated and no real household is involved.

## Large files on Zenodo

Ten result files of 50 MB or more are not in this repository; they are on Zenodo (https://doi.org/10.5281/zenodo.23874619). `DATA.md` gives each file's size, sha256 and role, and which steps need it. Put each at its path below to restore the full tree.

| Path | Bytes | sha256 |
|---|---:|---|
| `exp/out/e10_main_e10s_copy_chain.jsonl.gz` | 91,391,072 | `5d1c09317224157fb81892a53397120709db30eb061eb79957e3720895a39be1` |
| `exp/out/e10_main_e10s_direct_chain.jsonl.gz` | 91,484,045 | `4de782e09dc6796cc23317b53e0a31acbd38a631bb21b56a2e589bf035920072` |
| `exp/out/e10b_main_e10bs_copy_chain.jsonl.gz` | 77,214,632 | `28530102629f0c3483d431454cca489e5664e7690b9b27a2adde5979f7da7436` |
| `exp/out/e10b_main_e10bs_direct_chain.jsonl.gz` | 77,239,251 | `fd375fe3880ad39280e89a9cb9d00561ccf4fa5982100b727e46f951026a9930` |
| `exp/out/e12_main_copy_chain.jsonl.gz` | 91,931,692 | `86494c1fa08d21b97a0f1ae90cddb2d9ee85b0b57bedd4f5a0d6b010882346f8` |
| `exp/out/e12_main_direct_chain.jsonl.gz` | 92,696,813 | `843da57c1315610cc13a6dbf019a3c4acb12fad7afdfd50495af267ee32dedc9` |
| `exp/out/e12_main_score.json` | 90,961,983 | `851efccda08f6bc504584eb8770537dd3ef37058ea48bb759f6855e770792ce1` |
| `exp/out/e9_main2_copy_chain.jsonl.gz` | 123,159,948 | `de0f347c89d0aa116eca4849829368f1667557da067378d555ce5b218ba7829c` |
| `exp/out/e9_main2_direct_chain.jsonl.gz` | 124,961,582 | `4d5b8384df3605358320128d6ac9f5dd38cc7735d5dd60be73f5d23209cbda85` |
| `exp/out/e9_main2_score.json` | 2,617,583,736 | `dd0dda21a7b55dcb5fe11cf0699504b68305a6d703fff47d01565150371ae657` |

No command under "Re-verifying the reported numbers" needs them. The paper's float-source check needs six of them (E9's and E12's score and chains), Table S6's prefixes for E9 and E12 need the two score files, and the NUMBERS.md rows that cite `exp/out/e12_main_score.json` need that file.

## What is deliberately not here

**No offensive integrations.** The gap between an attack harness and an
installable extension is the only thing that makes this work publishable without
arming a reader. Ten offensive components that ran inside the hub process are
therefore *not* in this repository:

- the integrations that performed the laundering (deletion / re-parenting of a
  committed row);
- the post-commit writes used in the detection runs;
- the write-time strategies (minted contexts and the write-path hook);
- the module-level rebinding that blinded an in-process defender;
- the E7 integration (`homeprov_e7`) that inserted, backdated and laundered rows in the E7, E8 and E9 runs; `testbed/e7/run_e7.sh`, `testbed/e8/run_e8.sh` and `testbed/e9/run_e9.sh` name it (E9's attack batches also use `homeprov_ec`);
- the Domoticz integration that rewrote a committed row's `LightingLog.User` (`testbed/domoticz/integration/HPLock`); `testbed/domoticz/run_dz.sh` names it, and its arm driver (`harness/dz_arms.py`) is withheld until 25 January 2027;
- the E6 in-hub harness (`homeprov_e6`, kept outside the repository) that re-attributed actuations through the name map in E6 and in E9's name-map session; `testbed/e9/run_e9.sh` names it;
- the E10 in-hub adversary (`homeprov_e10`) that backdated, inserted and deleted rows, blinded the monitors and stepped the hub's clock in E10 and E10b; `testbed/e10/run_e10.sh` and `testbed/e10b/run_e10b.sh` name it;
- the E10b add-on (`testbed/e10b/homeprov_e10b`) that stepped the hub's state-row clock as well; `run_e10b.sh` names it;
- E11's instrument bundle for openHAB (`testbed/e11/attack`) that inserted, removed and changed persisted history points; `testbed/e11/build_bundles.sh`, `e11_stack.sh` and `run_e11.sh` name it.

Withheld in place, the rest of each file released: in `testbed/e11/e11ops.py` the write operations of the helper that edits the closure instance's persistence database, and in the E11 fixture bundle (`testbed/e11/fixture/.../Activator.java`) the code that writes time series into and removes persisted history (the benign operations B-BACKFILL, B-REPLACE and B-RETAIN); the tests that load or read the E10 and E10b components (`testbed/e10/test_e10_r5.py`, `testbed/e10b/test_e10b.py`); the attack-integration source lines quoted in `exp/sp2027/r14c_e8_attack_success.py`, `r14c_swap_spillover.py` and their result files. Each place carries a line beginning "[Withheld from the artifact:"; `reproduce/SANITIZED_r16.json` (`withheld_code`, `withheld_results`) gives the digest of each file before and after.

The evaluation scripts (`testbed/real/run_experiments.sh`, `testbed/real/run_all.sh`
and some `exp/stages/*.py`) still name these components (`homeprov_s1real`,
`homeprov_ec`, `homeprov_e2`, `homeprov_redteam`): those arms will not run
without them, by design. The same holds, until 25 January 2027, for the arms that
call `homeprov_e5` (`testbed/real/run_experiments.sh`, `witness/e3_broker_witness.sh`). What takes their place is sufficient for reproduction
and no more: the recorder-mutation primitives in `exp/rig/forge.py`, the twelve
predeclared forgery definitions, the generated-deployment stages that reproduce
each database transformation on synthetic recorders, and the measurement
harness `homeprov_e4`, which mutates one field and immediately rolls it back to read
the platform's own renderer (the renderer-backed harness `homeprov_e5` is withheld
until 25 January 2027). The forgery taxonomy
and the capability records describe the adversary in enough detail to
reimplement it for defensive evaluation.

**No manuscript.** The paper is maintained separately.

**No credentials, no full recorder databases, no third-party paper text.** The only
recorder data are the per-run window extracts in `reproduce/snapshots/` (virtual devices;
the rows of each run window that the verifier reads, built by
`reproduce/make_window_extracts.py`, and for E7 and E8, in `reproduce/snapshots/e7e8/`, by `reproduce/make_e7e8_extracts.py`). The
working `configuration.yaml` for the demo testbed is excluded because it enables
the offensive integrations; `testbed/ha-config/configuration.example.yaml` is the
released equivalent. The real-substrate `testbed/real/ha-config/configuration.yaml`
loads only the defender and measurement integrations.

## Reproducing

Start with the rig self-test, which is side-effect free:

```bash
python3 exp/run.py selftest   # behavioural invariants, no side effects
python3 exp/run.py plan       # every gate, threshold, baseline, contrast
```

Each stage under `exp/stages/` is self-contained and writes a JSON report to
`exp/out/`. Results that need a live platform drive a Home Assistant container
through a command file; `exp/e6_crossversion.sh` shows the pattern, including the
named-volume requirement (SQLite writes from a second process across a macOS
bind mount return `SQLITE_IOERR` rather than blocking). The real-substrate
deployment and its run scripts live under `testbed/real/`. Every result ships
with a machine-readable capability record stating the exact powers the adversary
held when it was produced; anything absent from that record was not assumed.

### Re-verifying the reported numbers

```bash
python3 reproduce/verify_all.py              # 10 real-deployment runs from reproduce/snapshots; writes reproduce/verify_all_report.json
python3 reproduce/recount_floats.py          # every other float, from exp/out and the report above
python3 reproduce/verify_e7e8.py             # E7 and E8 from reproduce/snapshots/e7e8 with the E8 verifier and monitor and the E8 public keys; writes reproduce/verify_e7e8_report.json
python3 -m pytest -q monitor testbed/anchord  # every monitor and anchor test, the E9, E10 and version-2 ones included (the signature tests need cryptography)
python3 -m pytest -q testbed/e10/test_e10_patches.py   # E10's patches (hardening, D1-D5)
python3 -m pytest -q testbed/e10/test_e10_r5.py testbed/e10b/test_e10b.py testbed/e11/test_e11.py testbed/e12/test_e12.py   # E10's review-r5 arms, E10b, E11, E12; two tests need components that are not here (test_display_rule_still_identical, test_draft_registration)
python3 exp/sp2027/r6_reverify_v2.py --out /tmp/r6.json   # the same runs re-verified with the typed node encoding
for r in e_d_clo e_c_clo e_ps_clo e_psr_clo e_d_auth e_c_auth e_ps_auth e_d_whr e_ps_whr e_psr_whr; do
  R2_OUTDIR=/tmp/r2 python3 exp/sp2027/r2_localize.py $r; done
R2_OUTDIR=/tmp/r2 python3 exp/sp2027/r2_localize.py --summary   # real-deployment localization (the paper's localization figure)
python3 exp/sp2027/r10_coarse_roots.py --out /tmp/r10.json  # minute and hour roots (Appendix G)
```

None of these commands reads a file held out on Zenodo (`DATA.md`).

Each run's recorder extract and anchor chain are checked against `reproduce/snapshots/EXTRACTS_SHA256SUMS`
(E7 and E8: `reproduce/snapshots/e7e8/EXTRACTS_E7E8_SHA256SUMS`) before use; `reproduce/reference_reports/` has the reports this tree produced.

### Node-hash encoding

`monitor/monitor.py` hashes each recorder row with a canonical typed, length-prefixed
encoding (`HOMEPROV_ENCODING=v2`, the default). The earlier encoding (`v1`) joined the
fields with the byte `|` and is not injective; it is kept only because every anchor chain
in `reproduce/snapshots/` was sealed with it. Anchored records name their encoding, a record
without one was sealed with `v1`, and the verifiers select the encoding from the chain.
`exp/out/r6_*.json` record the effect on every reported detection result (none changed).

## How this tree was prepared

This tree was prepared from the research repository by the rules below. The notes
record what that preparation removed, rewrote and withheld, so that every digest the
paper prints can still be checked.

- Removed: documents that carried venue, review or planning history
  (`EXPERIMENTS.md`, `FEEDBACK_CHECKLIST.md`, `research_design_detailed.md`) and
  the git pre-push hook (`.githooks/`). The reproduction content of the removed
  `EXPERIMENTS.md` is covered by `exp/README.md` and `testbed/real/EXPERIMENTS.md`.
- Added: `docs/` holds the design documents and run notes the E7, E8 and E9 pre-registrations cite, and the E9
  code review. They name internal design and code-review rounds by label and roles, not people; machine
  paths and labels are rewritten as below, and the parts of two of them that describe an attack integration's
  arms or code, or what the E6 in-hub harness does internally, are withheld in place (`docs/README.md`).
- Added in round 16: `docs/` also holds the design and results notes the E10, E10b, E11 and E12 registrations cite, masked as
  above, with passages that describe the in-hub components' internals withheld in place (`docs/README.md`).
- The E10, E10b and E12 registrations are the registered files byte for byte, so their OpenTimestamps proofs verify on the
  released copies. The E11 registration names one machine path, rewritten as below, so its released copy differs
  from the bytes its proof commits to; `reproduce/SANITIZED_r16.json` (`opentimestamps`) gives both digests. E9's
  amendment 3 is as in round 14; its proof is the upgraded one.
- Paths on the external research volume (`/Volumes/...`) carry no user name and are not rewritten.
- The E9 pre-registration's two amendments name run-directory paths, rewritten as below, so their released
  copies differ from the bytes their OpenTimestamps proofs (`.ots`) commit to; `reproduce/SANITIZED_r14.json`
  gives the digest of each before the rewrite (the one its proof commits to; for amendment 1 also the one
  amendment 2 cites) and after. `exp/out/e9_preregistration.json` holds no path and is the registered file byte for
  byte, so its proof verifies on the released copy.
- Replaced: absolute machine paths in result, config and log files — the author's
  home directory and session scratch directories were rewritten to the
  placeholders `<artifact-root>` and `<scratch>`. This is a textual substitution
  of path strings only; **no measured value, result row or number was changed.**
  The paper's run-provenance table prints the SHA-256 prefix of each result file as measured. Every
  such file is byte-for-byte unchanged except `exp/out/dz_config.json`, `exp/out/e10_main_collusion_copy.json`, `exp/out/e10_main_collusion_direct.json`, `exp/out/e10_main_dzst_config.json`, `exp/out/e10_main_events.jsonl`, `exp/out/e10_pi4_cost_pi4.json`, `exp/out/e10_reverify_patched.json`, `exp/out/e10b_main_events.jsonl`, `exp/out/e11_main_config.json`, `exp/out/e11_preregistration.json`, `exp/out/e1_psr_clo_config.json`, `exp/out/e2_auth_config.json`, `exp/out/e5_psr_lnk_config.json`, `exp/out/e5_psr_lnk_linked.json`, `exp/out/e6_namemap_attack.json`, `exp/out/e6_namemap_detection.json`, `exp/out/e7_late_delays_prior.json`, `exp/out/e7_main_closure_verify.json`, `exp/out/e7_main_config.json`, `exp/out/e7_main_score.json`, `exp/out/e7_main_stable_verify.json`, `exp/out/e8_closure_real.json`, `exp/out/e8_main_closure_verify_main.json`, `exp/out/e8_main_config.json`, `exp/out/e8_main_score.json`, `exp/out/e8_main_score_rescored.json`, `exp/out/e8_main_stable_verify_main.json`, `exp/out/e9_cost_scale.json`, `exp/out/e9_cost_scale_direct_final.json`, `exp/out/e9_deferred_choice.json`, `exp/out/e9_direct_read_identity.json`, `exp/out/e9_dishonest_anchor.json`, `exp/out/e9_dishonest_anchor_markers.json`, `exp/out/e9_main2_config.json`, `exp/out/e9_main2_score.json`, `exp/out/e9_purge_disconnect_offline.json`, `exp/out/e9_readonly_shm_lockdrop.json`, `exp/out/e_c_auth_config.json`, `exp/out/e_c_clo_config.json`, `exp/out/e_d_auth_config.json`, `exp/out/e_d_clo_config.json`, `exp/out/e_d_whr_config.json`, `exp/out/e_ps_auth_config.json`, `exp/out/e_ps_clo_config.json`, `exp/out/e_ps_whr_config.json`, `exp/out/e_psr_clo_config.json`, `exp/out/e_psr_whr_config.json`, `exp/out/r13_monitor_cost.json`, `exp/out/r16_e10_unobs.json`, `exp/out/r16_e9_score_compact.json`, whose
  released copies differ only in rewritten paths or labels; `reproduce/SANITIZED_r13.json`,
  `reproduce/SANITIZED_r13d.json`, `reproduce/SANITIZED_r14.json` and `reproduce/SANITIZED_r16.json` give the
  digest of each before (the printed one) and after the rewrite.
  NOTE: the label pass (the revision branch's name and an internal review label) runs after the path
  rules. From `reproduce/SANITIZED_r13d.json` on, the `files` record of a file it rewrote gives the final
  digest as `sha256_after`, the digest after the path rules alone as `sha256_after_path_rules`, and
  `"rewritten_by_label_pass": true`; `extra_files` gives that pass's own before and after. In
  `SANITIZED_r12.json` and `SANITIZED_r13.json`, `files` gives the digest after the path rules alone. In
  this tree the label pass rewrote `exp/out/r13_monitor_cost.json` (printed `39b5bee526bc`, released `e5da0e1c3d5f`), `exp/sp2027/r13_monitor_cost.py` (before `d8dd5c5a3c0d`, released `3139040739c5`). A result file that records
  a script's `script_sha256` records the digest the script had before the rewrite. A few stage reports
  carry an embedded content digest that was computed before the path rewrite; no
  check in this repository re-verifies that field, and it is not quoted anywhere.
- Files added in this revision were rewritten with the same rule and a few more placeholders
  (`<snapshots>`, `<home>`, `<research-dir>`, `<python-prefix>`); `reproduce/SANITIZED_r6.json`
  lists each rewritten file with its digest before and after.
- Round 17 changed how a rewritten root reads in code, so that the shell runners stay valid bash and the scripts and tests
  that hard-code the root find this tree (`reproduce/SANITIZED_r17.json`, `path_rule_r17`, lists every file and line with
  its digest as registered or before, in round 16 and now). In shell scripts, `REPO=<artifact-root>` (which bash reads as a
  redirection) became `REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"`, the tree
  root taken from the script's location unless `ARTIFACT_ROOT` is set; other assignments whose value begins with a
  placeholder are quoted (`X="<research-dir>/HOMEPROV-P13-exp/e10"`: set them to your own directories); the runners'
  embedded Python reads the root as `R = __import__("os").environ["ARTIFACT_ROOT"]`; and in Python files an assignment of
  the root (`R = "<artifact-root>"` and the like) now takes `ARTIFACT_ROOT` or the root computed from the file's own
  location. Other placeholder paths in code, for example `"<artifact-root>/exp/out/..."` in older analysis scripts, are
  as round 6 wrote them and must be replaced by hand. The rule changes no result file and no float source.
- The words "reviewer" and "disclosed" appear in a handful of code comments as
  ordinary vocabulary.
