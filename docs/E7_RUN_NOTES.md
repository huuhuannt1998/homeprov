# E7 run: notes for the lead (2026-10-08)

Written by the E7 run-preparation agent. Nothing committed. No `hpr-*`, `e1-*`, `e2-*`, `rka-*`, `ds-*`,
`delaysteer-*` container and no QEMU VM was started, stopped, exec'd into, rebuilt or modified; the dry run used only
`e7d-*` containers (and the throwaway `e7r-*` render hub), all removed afterwards. Keys never leave the containers; the
configuration log records only `sha256(key)[:16]`.

## 1. Files

| File | What |
|---|---|
| `testbed/real/ha-config/custom_components/homeprov_e7/` | [Withheld from the artifact: the description of the attack integration that performed the arms. The attack integrations are not released (README.md, "What is deliberately not here").] |
| `testbed/real/.gitignore` | `homeprov_e7/` added next to `homeprov_ec/`. |
| `testbed/e7/run_e7.sh` | NEW run script (real-deployment defaults; every target overridable by `HPR_E7_*` env, which is how the dry run drove the scratch stack). |
| `exp/stages/e7_score.py` | NEW orchestrator: runs `exp/stages/e7_verify.py` (the authoritative verifier) on both chains with LATE_BOUND = 30 s and GAP_S = 30 s, adds per-poll cost, the STALL measurement, the OUTAGE summary and the recovery render. |

## 2. Arms

[Withheld from the artifact: how the attack integration implements each arm. The arms, their parameters and their counts are in exp/out/e7_preregistration.json and in the paper. The attack integrations are not released (README.md, "What is deliberately not here").]

## 3. How to start the real run

Prerequisites: the default deployment up (`hpr-hass`, `hpr-devices`, `hpr-broker`); laptop on mains power (about 2 h
of continuous load); nothing else heavy running. The script builds `hpr-monitor:e7` and `hpr-anchord:e7` itself, from
the repository's current `monitor/` and `testbed/anchord/` (new tags only; it never runs `docker compose build` in
`testbed/real`, which would re-tag `hpr-monitor:1` / `hpr-anchord:1`):

```bash
cd <artifact-root>
mkdir -p <research-dir>/HOMEPROV-P13-exp/e7
nohup testbed/e7/run_e7.sh e7_main > <research-dir>/HOMEPROV-P13-exp/e7/e7_main.out 2>&1 &
```

Preflight (refuses to start otherwise): the E2 night is not running (no `e2-issuer` container, no
`e2night/driver.sh` process); hub and devices up; `python3 -m pytest -q monitor/test_coverage.py
monitor/test_node_hash.py` passes; the images build; their `/app/monitor.py` and `/app/anchord.py` are byte-identical
(sha256) to the repository's files; the monitor advertises coverage. The in-image hashes are recorded in the
configuration log and in `e7_main_config.json` (`HPR_E7_BUILD_IMAGES=0` uses existing images, still hash-checked). It also refuses if the run directory, any `exp/out/e7_main_*` output, or an `e7-*` container
already exists.

What the script does to the default deployment, by design (as `run_clo_grace.sh` did): stops and renames
`hpr-monitor`/`hpr-anchord` for the run and restores them on exit (so the default chain has a gap bounded by
`e7_main_t_start`/`_t_end`); pauses `hpr-devices` for 200 s once per configuration (BD-M); restarts `hpr-hass` twice per
configuration (install and remove `homeprov_e7`). Monitors: `e7-monitor-clo` (closure, coverage, escrow to
`<run dir>/escrow/`, cost log) with `e7-anchord-clo`, and `e7-monitor-stb` (stable columns) with `e7-anchord-stb`, each
with a fresh key; both read the config volume read-only.

Knobs (env): `HPR_E7_TRIALS` (10 per configuration), `HPR_E7_ROOMS`, `HPR_E7_ARMS`, `HPR_E7_WANT_OUTAGE` (1),
`HPR_E7_OUTAGE_TRIALS` (10), `HPR_E7_OUTAGE_PAUSE_S` (90), `HPR_E7_K` (9), `HPR_E7_STALL_CONNS` (8), `HPR_E7_STALL_S`
(40), `HPR_E7_BD_MIN_AGE_S` (130), `HPR_E7_PAUSE_DEVICES_S` (200), `HPR_E7_RECOVERY_RENDER` (1), `HPR_E7_LATE_BOUND_S`
(30), `HPR_E7_GAP_S` (30).

## 4. Expected duration

About **2 h** (range roughly 1 h 50 min to 2 h 15 min), derived from the dry runs' measured per-arm times (hub log
timestamps, `dryrun_2026-10-08/dry1/run_e7.out`) scaled to the real defaults (10 trials per configuration, seal wait
130 s, STALL seal wait 25 s, OUTAGE pause 90 s, device pause 200 s, hub restart wait 45 s):

| Per configuration | ~seconds |
|---|---|
| device pause + settle (BD-M) | 220 |
| install + restart + warm-up | 55 |
| INS-L (10 x ~5 s + 130 s seal wait + edits) | 190 |
| INS-M | 190 |
| BD-S + BD-M (10 x ~2 s each) | 50 |
| BD-PARK + BD-JOIN + BD-GAP (3 x [prepare ~10 x 1 s + 130 s move wait + moves]) | 420 |
| STALL (10 x ~36 s) | 360 |
| OUTAGE (10 x ~96 s: 90 s pause + handshake) | 960 |
| remove + restart | 45 |
| **total** | **~2,490 (~42 min)** |

Three configurations ~2 h 5 min, plus set-up (~1.5 min), settle (1.5 min), snapshot, two scoring passes over the
~190 MB recorder for two chains and the recovery render (~10 min): about **2 h 20 min** overall (range ~2 h 10 min to
2 h 35 min). The reserved-key variants add ~7 min per configuration (the 130 s move wait is per batch, not per trial).
OUTAGE is still about 40% of each configuration; `HPR_E7_OUTAGE_TRIALS=3` saves about 35 min.

## 5. Outputs

Run directory `<research-dir>/HOMEPROV-P13-exp/e7/e7_main/`: `auth_meta.log` (configuration log),
`recorder.db` (consistent snapshot), `closure_chain.jsonl`, `stable_chain.jsonl`, `closure_refusals.jsonl`,
`escrow/escrow.jsonl`, `closure_cost.jsonl` (per-poll copy/load/commit/append ms), both monitors' and anchors' logs,
`closure_verify.json` / `stable_verify.json` (raw `e7_verify` output), `render_targets.json`,
`recovery_render_raw.json`, `e7_recovery_render.json`, `score_pass1.log`, `score.log`.

`exp/out/`:
- `e7_main_report_{porch,hallway,kitchen}.json` -- the component's per-trial reports (all arms incl. OUTAGE).
- `e7_main_t_start`, `e7_main_t_end` -- run window.
- `e7_main_closure_chain.jsonl.gz`, `e7_main_stable_chain.jsonl.gz`, `e7_main_escrow.jsonl.gz`.
- `e7_main_closure_verify.json`, `e7_main_stable_verify.json` -- `e7_verify` output: per-arm `e7_detected` (with
  Clopper-Pearson interval) for every arm including BD-PARK / BD-JOIN / BD-GAP, next to the existing rule's
  flagged / attributable / ambiguous counts, violations,
  attributable rows (incl. backdated), benign late rows, stalls (with kind and seconds sealed during), recovery, benign
  floor (counting rule of `reproduce/verify_all.py`), and the parameters.
- `e7_main_recovery_render.json` -- trials whose restored copy renders the true (clean, pre-edit) principal again.
- `e7_main_score.json` -- the combined result: pre-registered parameters, both monitors' arms and floors, per-poll cost
  (median/p90/max of copy, load, commit, append, total), STALL (appends during each stall window, anchor responsiveness,
  overlapping stall intervals, connections opened/cut), OUTAGE (edited second sealed during an `anchor_unreachable`
  interval, detection), recovery render.
- `e7_main_config.json` -- images, in-image monitor.py/anchord.py hashes, file hashes (homeprov_e7/ec, e7_verify,
  e7_score, this script),
  key fingerprints, chain hashes, LATE_BOUND/GAP_S.

## 6. Dry run (scratch stack, 2026-10-08)

Scratch stack: `e7d-broker`, `e7d-devices`, `e7d-hass` (homeassistant/home-assistant:2026.7.4, the `hpr-hass` tag read
with `docker inspect`, not exec), on its own internal network and config volume (cloned read-only from the default
deployment's config with its recorder removed; no host ports published, like the base deployment), plus the E7 pairs
and the `e7r-` render hub that `run_e7.sh` creates. Images `hpr-monitor:e7d` / `hpr-anchord:e7d` built from the
repository files (monitor.py sha256 `1863ae9d...`, anchord.py `fa662e94...`, e7_verify.py `fa6da9ee...`), all removed
afterwards. Artifacts (run dirs, logs, chains, verify outputs, reports): `HOMEPROV-P13-exp/e7/dryrun_2026-10-08/`
(kept out of `exp/out/`; these are plumbing checks, not results). LATE_BOUND = 30 s, GAP_S = 30 s. Porch only.

Dry run 1 (2 trials per arm, 1 OUTAGE trial with a 45 s pause), dry run 2 after fixes (3 trials of INS-L, INS-M,
BD-S, BD-M, 1 OUTAGE trial). `e7_detected` is e7_verify's verdict; "existing rule" is its flagged / attributable /
ambiguous count under the evaluated row-count rule:

| Arm | Dry run 1 | Dry run 2 |
|---|---|---|
| INS-L | 2/2 detected; existing 2 / 0 / 2 | 3/3; existing 3 / 0 / 3 |
| INS-M | 2/2; existing 2 / 0 / 2 | 3/3; existing 3 / 0 / 3; timeline names the swapped-in member 3/3 |
| BD-S | 2/2; existing 0 flagged; row age 130.3, 134.3 s | 3/3; existing 0; age 130.3-136.4 s |
| BD-M | 1 valid, 1/1 (2nd trial: no automation run before an older empty minute) | 3/3; existing 0; all in the one empty minute a 130 s pause gave; age 307.5-313.4 s |
| BD-PARK / BD-JOIN / BD-GAP | not in dry runs 1-2 (added later) | dry run 3: each 2/2 e7_detected; existing rule 0/0/0; keylog violations 3; benign floor 0/90 |
| STALL | 2/2 detected; 5 closure appends inside each stall window; anchor answered every GET /head; no stall interval overlapped | (not re-run) |
| OUTAGE | 1/1 detected, but the edited second sealed just before the pause | 1/1; appends of polls 78-80 timed out (10 s) during the pause; edited second sealed by poll 79 during the outage, edited 26 s later |
| Benign floor, closure / stable | 0/65 / 0/65 | 0/59 / 0/59 |
| Recovery render (true author again) | 7/7 | 7/7 (INS-L shows the member again; INS-M no longer shows the swapped account) |
| Per-poll cost, closure (scratch recorder, small) | -- | total median 54.9 ms, p90 96.5 ms, max 10,064.9 ms (append timeouts during the outage) |

[Withheld from the artifact: the fixes made to the attack integration after the dry runs. The attack integrations are not released (README.md, "What is deliberately not here").]

Earlier smoke runs (before the hardened anchor's STALL rework and the switch to e7_verify) were superseded and are not
kept. Offline, `exp/stages/e7_score.py`'s first version was checked against a real recorder snapshot with a synthesized
coverage chain (INS: delta_n = +9 but attributable under the watermark; BD-S: backdated attributable; a 40 s heartbeat
gap found; escrow root reproduced); scoring is now delegated to `e7_verify.py`.

## 7. Risks and open points

1. [Withheld from the artifact: how the reserved-key backdating arms were built and checked in the attack integration. The attack integrations are not released (README.md, "What is deliberately not here").]
2. **Monitor and verifier are changing now** (keylog and review fixes). The dry runs used monitor.py `1863ae9d...` and
   e7_verify.py `fa6da9ee...`; the final versions were not dry-run by this agent. `run_e7.sh` builds both images from the
   repository files at start, refuses to start if `monitor/test_coverage.py` / `test_node_hash.py` fail, and records the
   in-image hashes. A short smoke on the real deployment first is cheap and now also exercises the three reserved-key
   variants: `HPR_E7_TRIALS=1 HPR_E7_ROOMS=porch HPR_E7_OUTAGE_TRIALS=1 testbed/e7/run_e7.sh e7_smoke` (~15 min; writes
   `exp/out/e7_smoke_*`). To skip the reserved-key move waits in the smoke, set
   `HPR_E7_ARMS='"INS-L","INS-M","BD-S","STALL"'`.
3. **Verifier stall reporting looked inconsistent** (raise with the verifier agent): dry run 1 listed a
   `monitor_restarted` interval during the outage although the monitor's seq_local ran 71-75 without a restart; dry run
   2 listed no stall at all although the closure monitor's own records 77 and 81 are 50 s apart with a seq_local jump of
   4 (polls 78-80 failed). The OUTAGE edit was detected both times. `outage_arm.edited_second_sealed_during_anchor_outage`
   reads e7_verify's stalls and so showed 0 in both; the cost log (`closure_cost.jsonl`, `ok: false`) is the direct
   evidence.
4. **GAP_S = 30 s vs benign delays**: e3_g0's sealing delay reached 66.07 s (E7_IMPL_NOTES section 8), so benign stall
   intervals are likely in the real run. Each is listed with its kind; STALL's "overlapping interval" count can pick
   one up by coincidence.
5. **BD-M trials share empty minutes**: a 200 s device pause gives 2-3 empty minutes per configuration, so 10 trials
   share them (distinct seconds; distinct minutes recorded). For independent minutes, raise `HPR_E7_PAUSE_DEVICES_S`
   (about one minute per extra empty minute) or lower the trial count.
6. **Effects on the default deployment** (by design): stock monitor/anchor stopped for ~2 h (gap in the default chain,
   bounded by `e7_main_t_start/_t_end`); `hpr-devices` paused 200 s per configuration; `hpr-hass` restarted six times.
7. **Power**: needs mains power (about 2 h of sustained load); the dry runs ran on battery only because they were short.
8. [Withheld from the artifact: a note on how the attack integration computes its own success fields; what it implies for arm PSR is stated in exp/stages/e8_score.py (report_context). The attack integrations are not released (README.md, "What is deliberately not here").]
9. [Withheld from the artifact: a note on the attack integrations' code. The attack integrations are not released (README.md, "What is deliberately not here").]
