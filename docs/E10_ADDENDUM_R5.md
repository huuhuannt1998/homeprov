# E10 addendum (review r5): arms S, R, C, D, E

Status: DESIGN, 2026-10-16. Nothing here has run. Everything waits until E9 ends (2026-10-19 16:01Z), like the rest of E10.

PI, 2026-10-16 (TDSC_PLAN.md decision log): "Add all (Recommended)". This means a 90-trial sham arm, a hub restart
mid-poll, a Domoticz SwitchType change, a pairwise closure-mutation sample, and the cost under a Raspberry Pi 4-class
CPU/IO cap. Sources: TRIAGE_R5.md Z4, Z5, Z11, Z12; R3 W3, W7, W8; R2 W1, W2; META items 2, 4, 10, 11.

Number sources:
- Every number below is read from a saved result file (path given), is a parameter fixed here, or is labelled an
  assumption.
- Run-time figures are estimates, not measurements.

## Files

| File | Role |
|---|---|
| `testbed/real/ha-config/custom_components/homeprov_e10/__init__.py` | [Withheld from the artifact: which internal functions of the in-hub adversary were changed for arm S, and a fix to its command handling. See README.md, "What is deliberately not here".] |
| `testbed/e10/e10ops.py` | edited: plan blocks `S_SHAM`, `SNAP_SHAM`, `R_RESTART`, `SNAP_RESTART`; restart timing (`predict_window`, `fire_time_vm`, `landed`, `restart-trial`) |
| `testbed/e10/run_e10.sh` | edited: the S and R blocks; `e10r5_score.py` after `e10_score.py` |
| `exp/stages/e10r5_score.py` | new: scorer for S and R (reuses `e10_score.py` unchanged) |
| `testbed/e10/run_e10_r5.sh` | new: runs C, D, E in sequence, with refusals; smoke mode |
| `testbed/e10/run_dz_switchtype.sh` | new: a COPY of `testbed/domoticz/run_dz.sh`, changed only in usage, outputs, driver and scorer (arm C) |
| `testbed/e10/dz_switchtype.py`, `exp/stages/e10_dz_switchtype.py` | new: the C driver (owner's API) and its scorer |
| `exp/stages/e10_pairwise_closure.py` | new: arm D (plan, in-hub runner on E8B's `Inner`, `sys.monitoring` coverage, classifier, summary) |
| `exp/sp2027/e10_pi4_cost.py` | new: arm E. Wraps `e9_cost_scale.py` unchanged; profiles; run matrix; merge |
| `testbed/e10/test_e10_r5.py` | new: 26 static tests |
| `testbed/e10/e10_prereg.py` | edited: H17-H21, arms S/R/C/D/E, files, `review_r5_offline_plans` (D's units, E's matrix) |

No E9-frozen file is edited.
- `run_dz.sh` and `e9_cost_scale.py` are used and copied, never changed.
- `e8_closure_real.py` rides along unchanged as a module.

Defect found and fixed:
- [Withheld from the artifact: a defect found in the in-hub adversary's command handling, its effect on two arms, and its fix. See README.md, "What is deliberately not here".]

Release note:
- No new attack path exists. The sham is a flag inside `homeprov_e10`, which is already git-ignored and FORBIDDEN in the
  artifact build (`round13_build.py`).
- C, D and E contain no attack code. C is the owner's configuration change through Domoticz's own API. D mutates a
  throwaway copy, as `e8_closure_real.py` does.

## Main-session order (`e10ops.make_plan`, seed 20261020)

```
A1_BDT A2_CTX A3_DEL A3_DELPH SNAP_DEL  S_SHAM SNAP_SHAM  A3_LOWKEY SNAP_TIMING A7_WIPE SNAP_WIPE
R_RESTART SNAP_RESTART  A6_CS A5_PW A4_ULW A4_ULSHM A4_ULSHM_OFD A4_ULJM A4_INFT A4_INFW SNAP_A_END B1 B2 B3 B4
```

The new random draws come after the original three shuffles, so every A1-A3 order is the 2026-10-12 draft's (tested).
S and R are not floor windows in `e10_score.floor()`: a flagged second in them counts as unexplained (tested).

## A. Arm S: sham (Z5; R3 W3; META 4)

**Procedure.** 90 trials in seeded interleaved order, 30 per variant. Each runs one attack arm's own code path, at the
level where that attack is predicted detected:

| Variant | Code path | Level | Spacing |
|---|---|---|---|
| S-BDT | A1-BDT | 45 s | 15 s |
| S-CTX | A2-CTX: actuation under its own Context, capture by context id, wait, insertion | 45 s | 5 s |
| S-DEL | A3-DEL | 10 s | 8 s |

What stays the same: the reads, the cover lookup, `BEGIN IMMEDIATE` at the same moment, and the renders. The only
change is that the transaction is rolled back instead of committed. An AST test checks this:
- [Withheld from the artifact: the code-level properties of the integration's sham and attack branches that the static test checks. See README.md, "What is deliberately not here".]

Rooms: E10's arms use the scenario's configured room (`homeprov_scenario`, `HPR_INNOCENT_ROOM`). The sham uses the same
lock and automation. Scored against `SNAP_SHAM`, with the same patched verifier and parameters.

**Prediction (H17).**
- Per monitor, 0 of 90 trials have a violation attributable to the trial. A trial counts if its would-be second is
  flagged, its own actuation row is attributable, or a keylog violation names its key.
- 0/90 bounds the rate at 0.0327 (one-sided 95%) and 0.0402 (two-sided Clopper-Pearson; computed with `rig.stats`).
- Integrity: `db_writes_total` is 0, S-CTX's displayed cause is unchanged, and S-DEL's unlock stays listed.
- Confusion matrix at the target seconds:
  - sensitivity from A1 at 45 s, A2 at 45 s and A3 at 10 s (against `snap_del`; predicted all detected, H1-H3);
  - specificity from the sham.

**Run time.** About 50 min, estimated: 30×15 s, plus 30×about 58 s, plus 30×about 28 s. The actuation and relock
times are assumed at 2-3 s.

## B. Arm R: hub restart mid-poll (Z4; R2 W1, R3 W2; META 2)

**Procedure.** 10 restarts, seeded order:

| Restarts | Kind | Aimed at |
|---|---|---|
| 4 | graceful (`docker restart -t 30`) | M-direct's read |
| 3 | `docker kill -s KILL`, then `docker start` (a crash) | M-direct's read |
| 3 | graceful | M-copy's copy |

`e10ops.py restart-trial` reads the target monitor's last 16 cost-log lines. Each line's `ts` is the snapshot time
(`tick_coverage`), followed by `copy_ms`, `load_ms` and `commit_ms`. From them it predicts the next window on the VM
clock:
- direct: the read's open to the end of load and commit;
- copy: the file copy.

It measures the Mac-VM offset (the shortest of five `docker exec` round trips) and fires so that the effect lands at
the window's middle:
- kill: the signal;
- graceful: the container's exit, which follows the recorder's last commit and close. The lag starts at 2.0 s, then
  becomes the running median of the measured `FinishedAt` lags.

After each restart:
- the harness waits for the hub to write and for `homeprov_e10` to be ready;
- it logs the corrupt-file count, the database lines in the hub log, and the monitor restart counts;
- it waits 150 s before the next restart.

Saved timing context (`exp/out/e9_cost_scale_direct_final.json`, `k1_direct_qc720`): the direct poll's total median is
83.239 ms. So a direct read is about 80 ms of every about 5.1 s, and landing depends on Docker's latency. Landing is
measured and reported per trial. It is not a condition of the predictions.

**Predictions (H18, per verifier rule; FORMAL_DRAFT D1).**
- In each restart's window [effect − 30 s, hub start + 120 s], both monitors and both verifiers report 0 attributable
  rows and 0 flagged seconds.
- Rows committed around the restart:
  - under the E9 verifier: `benign_late`;
  - under the patched verifier: `benign_late`, or `unobserved_late` exactly when an unobservable or missing poll, or a
    gap above `GAP_S`, lies in the row's bracket. A hub restart is not itself a D1 break.
- Unobservable polls are allowed (count not predicted; reasons reported). None is flagged by the rule (≥ 60 s and no
  hub start within 120 s).
- Monitor restarts: 0. The recorder is never moved away.

**Run time.** About 40 min (10 × about 4 min; Home Assistant's start-up time assumed at 30-60 s).

## C. Domoticz SwitchType change (Z4; R3 W2; META 2)

**Procedure.** `run_e10_r5.sh dz` → `run_dz_switchtype.sh TAG exp/out 600 600`. The stack, provisioning, anchor,
closure monitor and snapshot are E-DZ's, unchanged. The steps:
1. 10 min of benign lock traffic: the member's API switch every 30 s, plus the HPSensors motion traffic.
2. A consistent snapshot.
3. The renders for owner, member and guest.
4. The owner's Edit-Device request (`param=setused`, every other field copied), which changes the lock from 19 (Door
   Lock) to 20 (Door Lock Inverted).
5. The renders again.
6. 10 min more of traffic, a settle, the final snapshot, then `e10_dz_switchtype.py`.

19 → 20 is the write `exp/out/dz_offline_checks.json` tested offline (`single_write[3]`). It changed 120 of 294
one-second closure roots in the E-DZ window.

**Prediction (H19), stated as a measured limit.**
- Violations fall on exactly the anchored second, minute and hour segments that hold a lock log row first anchored
  before the change; segments within 10 s of the change are ambiguous. There are none elsewhere.
- The offline pre/post root comparison changes exactly the predicted seconds.
- The renderer shows the lock's earlier rows differently. `dz_closure.json`: SwitchType mutations changed the rendered
  output on 8 fixtures.
- No marker can declare it. The Domoticz adapter has none, and the verifier's five kinds (PURGE, RESTORE,
  RESTORE_DONE, RENAME, CLOCK_STEP) declare a purge, a restore, a name-map change or a clock step, not a committed
  configuration field.
- How an investigator tells it from an attack, for the paper: every sealed row of one device fails at once, with no log
  row changed, and the device's current type matches its configuration. A targeted rewrite needs neither pattern, but
  an adversary could imitate it. Without a declared marker the two are not distinguishable at the verifier.

**Run time.** About 30 min (smoke 2+2 min, about 12 min).

## D. Pairwise closure mutation with branch coverage (Z11; R3 W8; META 10)

**Frame.** The same pristine copy of the lab recorder, release image, 40 targets (22 roles), render forms, mutation
values and commitment code as E8B (`exp/out/e8_closure_real.json`):
- 45 fields and 1,744 single mutations;
- 27 fields changed the output, the same set as the compiled SQL's read set (`static.union`).

Each unit applies two mutations, with a row's key change last:
- it renders the three forms;
- it recomputes the closure, stable and row commitments;
- it restores and checks the restore (rows, renders, commitments).

Each single a unit uses is re-measured in the run (2,259 singles).

**Sample and stopping rule** (plan from the saved file and seed 20261021; sha256 registered under
`review_r5_offline_plans`):

| Stratum | Units | Population |
|---|---|---|
| W, every same-target field pair at E8B's primary values (exhaustive) | 10,513 | 10,513 |
| V, other-value pairs (uniform sample) | 1,000 | 26,293 |
| X, cross-row pairs (B's row inside A's ±300 s window) | 1,000 | 28,230 |

- Order: W in seeded order, then V, then X.
- There is no stop on any outcome.
- The run stops when all units are done or after 3.0 h of measurement, whichever comes first, and reports the units
  done. The completed parts of V and X stay random samples.
- With 0 events, n = 1,000 bounds a stratum's rate at 0.0037 (two-sided 95%).

**Coverage.** A `sys.monitoring` (PEP 669) tracer on every code object of `homeassistant.components.logbook` records:
- lines executed out of lines executable;
- branch outcomes taken out of possible (two per conditional jump).

It marks the totals cumulatively after the baselines, the singles, W, V and X, and lists every branch site never taken.
The display rule's four outcomes are counted from the classified renders. The tracer passes a toy test on the pinned
Python 3.13.11.

**Predictions (H20).**
- `undetected_render_change` (output changed, deployed stable commitment unchanged): 0. This is primary.
- `joint_only`: 0.
- `conditional_noncl` (a field outside the 27 changes the output once another changed): 0.
- `masking`: descriptive only.
- Basis: no statement reads a non-closure column, and the stable scheme commits every states/events column except
  `last_reported_ts`, plus the four joined values.

**Run time.** E8B took 260.9 s for 1,744 mutations, about 0.15 s each (sum of `targets[].seconds`). About 14,800
measurements give about 37 min. The tracer's overhead is assumed to at most double this, so about 1.3 h with hub
set-up. The cap is 3 h.

## E. Cost under a Raspberry Pi 4-class cap (Z12; R2 W2, R3 W7; META 11)

**Method.** `e9_cost_scale.py` runs unchanged, with the same synthetic recorders, writer (one transaction per second)
and phase-timing harness as C1. The image is the hardened `hpr-monitor:e10`, so within the arm only the limits differ.
The C1 limits are module globals; `e10_pi4_cost.py` sets them per profile and inserts `--memory-swap` and the IOPS
limits into the monitor's `docker run` only (tested).

| Profile | CPUs | Memory | Read / write | IOPS r / w |
|---|---|---|---|---|
| ref (= C1, saved files) | 1 | 1 GiB | 100 / 50 MB/s | none |
| pi4 | 0.25 | 512 MiB, no swap | 40 / 10 MB/s | 1,500 / 500 |
| pi4cpu_half, pi4cpu_eighth | 0.5, 0.125 | as pi4 | as pi4 | as pi4 |

**Every pi4 value is an ASSUMPTION; none was read from a source in this session.**
- CPU: one Cortex-A72 core at 1.5 GHz (the Pi 4's CPU class) has at most about a quarter of the single-thread speed of
  one core of this Mac.
- Memory: the share left on a 2 GB Pi 4 that also runs Home Assistant.
- SD: the A1 application class's 1,500/500 IOPS minimums, the Class 10 / U1 10 MB/s write minimum, and about 40 MB/s
  read on a Pi 4.

A CPU quota throttles in 100 ms CFS periods; it is not a uniformly slower core.

**Matrix (10 runs × 30 polls).**
- Direct read, quick_check every 720 polls, at k1/k5/k15 (0.19/0.96/2.94 GB), × {ref, pi4}.
- Copy mode, quick_check every poll, at k1, × {ref, pi4}.
- Direct read at k1 for pi4cpu_half and pi4cpu_eighth.

Outputs: median, p90 and max per poll; T; overruns above `PERIOD` and `GAP_S`; unobservable polls; bytes written per
poll and per hour; the pi4/ref ratio.

**Context and H21.** At ref limits (saved files):

| Run | Median poll | Bytes written |
|---|---|---|
| direct, 0.19 GB | 83.239 ms | 45.8 MB/h |
| direct, 0.96 GB | 290.5 ms | 112.5 MB/h |
| direct, 2.94 GB | 777.663 ms | 192.8 MB/h |
| copy, 0.19 GB | 3,922.763-4,128.53 ms | about 78-81 GB/h |

Sources: `e9_cost_scale_direct_final.json` `k*_direct_qc720`; `e9_cost_scale.json` `k1_copy_*`.

H21:
- Direct read under pi4 should keep its median below 5 s at 0.19 and 0.96 GB, with no poll above 30 s except a due
  quick_check.
- Copy mode is bounded below by size divided by the write cap: about 19 s per poll at the assumed 10 MB/s. This part
  is exploratory.
- No prediction at 2.94 GB.

**Run time.** About 1.5 h, estimated: about 55 min of polls, plus per-run set-up, plus creating the master volumes
once.

## Machine time and schedule (estimates)

| Item | Time |
|---|---|
| E10 as designed (E10_DESIGN.md §9) | 16-19 h |
| + S and R, inside the main phase | about 1.5 h (main phase 8-8.5 h; still inside the 04:50-15:00 start window) |
| + C, D, E (`run_e10_r5.sh`) | about 3.3 h |
| + smokes of the additions | about 1 h |
| **E10 with additions** | **about 22-25 h** |
| E12 (E12_DESIGN.md) | about 50.5 h |

Proposed sequence, UTC:

| When | What |
|---|---|
| 10-19 16:01 | E9 ends and scores itself |
| 10-19 evening/night | E10 phases 1-3 (patches, REVERIFY, smokes including `HPR_E10R5_SMOKE=1 run_e10_r5.sh`, `--final`, stamp) |
| 10-20 05:00 | `run_e10.sh e10_main all` (upgrade 2.2 h, main about 8.3 h, scoring) |
| 10-20 about 17:30 | `run_e10_r5.sh e10_main all` (C, D, E), ends about 21:00 |
| 10-20 about 21:30 | E12 `--final` and stamp; `run_e12.sh` launched by 23:00 |
| 10-21 00:00 | E12 START |
| 10-23 00:01 | E12 END; scored by about 01:30 |

**Calendar:** about 3.4 days after E9's end.

## Open questions (for the lead)

1. **Pi 4 limits.** Replace the five assumed pi4 values with cited ones (Raspberry Pi 4 product brief; SD Association
   A1 / speed-class definitions), or measure a Pi. Is the 0.5/0.25/0.125 CPU bracket enough?
2. **Sham layout.** The sham is one block in the same session, not interleaved with the attack trials. Interleaving
   would blind timing better, but it changes the registered A1-A3 timing. Keep the block?
3. **R landing.** A graceful restart lands inside an about 80 ms direct read only with luck plus the lag estimate.
   Accept "landing reported", or register an adaptive rule (extra restarts until 5 graceful landings, at most 16)?
4. **R kills.** Three of the ten are crashes (SIGKILL). They answer R3's "restart or crash during a poll". Keep them
   within the PI's "about 10 restarts"?
5. **SwitchType.** The predicted outcome is unexcused violations with no marker. Design a CONFIG marker (an
   operator-declared change of a committed configuration field, as MIGRATE was considered), or state it as a limit
   only?
6. **Pairwise frame.** Units are confined to E8B's 40 targets and values. Branches no target reaches stay unexercised
   (listed). Add targets aimed at never-taken branches afterwards, as exploratory work?
