# Which artifact is authoritative

Convention: `stageN_final.json` is the result. Timestamped siblings
(`stageN_<epoch>.json`) are intermediate runs kept for audit and are NOT results.
Verified across stages 0-6: `_final` is the newest file in every case.

## Which ARM — `exp/out` or `exp/out_recal` (and the `out_precalib` backup)

The E1 recalibration re-ran every generated-substrate stage into `exp/out_recal/`.
Both arms are valid; they answer different questions, and **a figure must not be
mixed across them.**

- `exp/out/` is the **published arm**. The manuscript reports this arm, and takes
  every companion number for a figure from the same row of the same file.
- `exp/out_recal/` is the **refit arm**, used to show which results survive
  recalibration. Quote it only when the text says it is the refit.
- `exp/out_precalib/` is a **byte-identical backup of `exp/out`**, taken before
  the recalibration run so the published arm could not be overwritten. Verified
  2026-09-18: all 80 shared files compare equal, and nothing exists only there.
  It is not a third arm and nothing should ever be quoted from it. It is listed
  here because `exp/out*/` globs match it, so a search for a value will report
  the same number twice and can look like corroboration when it is one file.

Stage 16 is the worked example of getting this wrong. Three values for one
figure were in circulation: 679,932 (`stage16_final.json`, published), 728,390
(`out_recal/stage16_scale.json`, refit), and 680,932 (`EXPERIMENTS.md`, matching
neither). The manuscript now uses 679,932 with the 10,000 anchors and the
0.209 ms / 0.658 ms latencies from that same row; the register names both arms.

The same rule settles the marker-abuse denominator: the published arm has four
vacuous case-instances (seeds 503 and 504 wrote zero rows), the refit arm has
none, and the manuscript reports the published arm and says so explicitly.

## One exception — stage 18

**`stage18_corrected.json` is authoritative, NOT `stage18_final.json`.**

| file | written | n | errored arms | GATE_PASS as written |
|---|---|---|---|---|
| `stage18_final.json` | 2026-08-22 07:21 | 2 | **3** (`snapshot failed`) | **true** |
| `stage18_merged.json` | 2026-08-22 07:23 | 5 | 0 | (none) |
| `stage18_corrected.json` | 2026-08-22 07:53 | 5 | 0 | true |

`stage18_final.json` is a *degraded* run: three of the five live benign arms
(BE-6, BE-8, BE-10) never snapshotted the hub, and the gate passed anyway because
it counted only the arms that succeeded — **an arm that did not run was credited
as an arm that raised no false alarm.** The manuscript's "the other five — BE-1,
BE-6, BE-8, BE-9, BE-10 — are properties of a running hub, exercised live" rests
on `stage18_corrected.json`, which has all five with real acknowledgements.

The gate in `exp/stages/stage18_livehub.py` has since been changed to require
every declared arm to have run (`n_failed` and `failed_arms` are now reported, and
`GATE_PASS` is false if any arm errored). Replaying the degraded artifact under
the new gate gives `GATE_PASS = false`, as it should have originally.

Artifacts are never edited retroactively, so `stage18_final.json` is left exactly
as written. Read it as a record of a failed run, not as a result.

## Trial denominators are POOLED across configurations, and the per-configuration
## n is not the same in every experiment

A denominator in this project is pooled over the three real configurations
(`porch`, `hallway`, `kitchen`) unless it says otherwise. The pooled number is
what the paper prints; the per-configuration number is in `per_room` in the
aggregate. They are not the same, and the ratio is not constant across
experiments:

| Experiment | trials per arm per configuration | pooled per arm |
|---|---|---|
| E-C write-time arms `W1 W2 W2b W3` and control `P` | 10 | **30** |
| E-D other-principal arms `PU PI` | 30 | **90** |

So E-C's `30/30` and E-D's `90/90` are the same *kind* of evidence — one
harness, one substrate, the platform's own logbook processor scoring both — but
not the same weight of it. E-D carries three times the trials per configuration.
Writing `90/90` next to `30/30` in one table without saying so invites the
reader to assume the arms were run at equal depth.

Two rules follow. Never compare a `k/n` across experiments without checking
`per_room` first. Never describe two arms as "directly comparable" on the
strength of a shared harness alone; the harness makes them commensurable, the
denominator decides how much each one weighs. (This session did exactly that
before checking, and the check is what caught it.)

Clopper-Pearson for reference: `12/12` is `[0.735, 1.000]`, `30/30` is
`[0.884, 1.000]`, `90/90` is `[0.960, 1.000]`.


## Which results come from the REFIT arm, and where the manuscript says so

The whole reconstruction and holdout block is refit-arm. Audited 2026-09-18;
every site now names the generator in the text, as the rule above requires.

| manuscript | figure | published | refit |
|---|---|---|---|
| `evaluation.tex` this work / causal component | 0.00157 / 0.00159 | 0.00179 / 0.00193 | quoted |
| `appendix` voiding / one-minute | 0.99966 / 0.04076 | 0.99962 / 0.07761 | quoted |
| `appendix` holdout / tuned | 0.00082 / 0.00094 | *not present in the published arm* | quoted |

The choice is deliberate: the published arm's generator carried a known-wrong
causal-density parameter, and the refit generator is fitted to the real
deployment. `stage19b_holdout2.json` and `stage7_sweep.json` exist **only** in
`out_recal`, so for the holdout sentence there is no published-arm alternative.

It is not cosmetic. At row 0 the published arm quarantines 98 nodes under the
innermost-segment policy against 6 under this work; the refit arm gives 4 and 4.
"Returns the identical node set" is true only in the refit arm.

**Open for the PI:** ratified claim C4 states the PUBLISHED arm's figures
(0.99962, 0.0776, 0.0327, 0.00193, 0.00179) for quantities the manuscript
reports from the refit arm. The manuscript and its own ratified claim disagree
numerically until one of them moves.

## The `real` block of `out_recal/stage34_realchar.json` is CONTAMINATED

Do not use it, and do not "correct" the manuscript against it.

| `stage34_realchar.json` `real` | `out` | `out_recal` |
|---|---|---|
| written | 2026-08-31 | 2026-09-03 |
| `n_nodes` | 3,229 | 129,916 |
| `parent_context_fraction` | 0.3227 | 0.4784 |
| `mean_causal_run` | 1.1507 | 1.9250 |
| `actuation_share` | 0.053 | 0.271 |

The refit arm's characterization was taken on the same day as the E2 boundary
run, which records the deployment at 133,088 rows, and on a database that by
then contained the adversarial experiments' own ~130k writes. Laundering writes
parent links, so `parent_context_fraction` is inflated by the measurement
including the thing being measured; the actuation share rising fivefold says the
same.

**The manuscript is correct.** "A parent-context fraction of 0.324 against a
real 0.323" pairs the recalibrated generator against the PRE-EXPERIMENT benign
baseline, which is the only valid calibration target. Same for "mean causal run
1.20 against a real 1.15". This is a legitimate cross-arm pairing rather than a
mixed figure: the whole meaning of the refit is that the generator was fitted to
that real measurement.

**Reproducibility hazard, which is why this is written down.** Re-running
stage 34 against the live deployment today returns 0.478 and 1.92, not 0.323 and
1.15, because the deployment now contains the experiments. An artifact evaluator
doing the obvious thing will get numbers that do not match the paper and will be
right to ask. The answer is the date and the row count, not a correction.

Audited 2026-09-18. The first reading of this was that the manuscript mixed
arms; the file timestamps and the actuation share overturned it.

## `out/stage26_final.json` is a FAILED RUN that reads like a clean defence

Second instance of the stage-18 hazard, and a worse-looking one.

Every one of its 16 rows carries `accepted: false`, `appended: 0`, `http: null`
and `resp: "URLError(ConnectionRefusedError(61, 'Connection refused'))"`. The
anchor daemon was not running. Skimmed, it looks like an anchor that refused
sixteen attacks out of sixteen. It refused nothing; nothing reached it.

The real measurement is `out_recal/stage26_anchor_attacks.json`, where the
unauthenticated daemon accepts 12 of 16 rows. One of those twelve is
`GET head (read)`, a read probe rather than an accepted attack, which is why the
manuscript says **11 of 16 attacks** and is right to. The four refusals are
`PUT`, `DELETE`, `PATCH` and path traversal, all HTTP 405 — rewrite verbs, not
append-path defences.

Never quote stage 26 from the published arm. The manuscript does not; its
"Rerunning the attack matrix" sentence now also names the generator.
