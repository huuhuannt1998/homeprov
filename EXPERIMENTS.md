# HOMEPROV — experiment register

Status as of 2026-08-24. **C3 REFUTED; ARCHITECTURE CORRECTED.** The mock IEEE
S&P review's P0 work showed the paper's B2 baseline was too weak: `content`
excluded the context columns the attack edits. A fair full-row baseline (B2b)
matches HOMEPROV on every catalogue class and beats it on FT-6. See the
Stage 20/21 block; `dec_01M0SH41J4DFSCRP86QHH6F5WA`. The paper must be
re-centred before further experiments are worth running.
M2/M3 gates were GO under the superseded baseline and no longer certify C3.
Tally: **155 items · 149 DONE · 6 OPEN**.
Source of truth for what has run, what is invalid, and what is left.
Legend: **DONE** generalizable · **n=1** measured on one deployment only, no interval ·
**INVALID** ran but the result is an artifact · **TODO** not run.

## Stage 0 — Substrate
- [x] S0.1 HA 2026.7.4 stands up, native aarch64, Pi-shaped cgroup envelope — DONE
- [x] S0.2 Determinism gate: A1 canonical serialization byte-identical — DONE
- [x] S0.3 Host/capability facts recorded (CapEff, binfmt, LINUX_IMMUTABLE, BPF) — DONE

## Stage 1 — Atomic forgeries (Thrust A, the floor)
- [x] FT-1..FT-9 all demonstrated on stock HA — DONE
- [x] Per-class minimum privilege recorded — DONE
- [x] L0 verification against HA's own logbook renderer — DONE
- [x] FT-1 / FT-4 swept across 18 deployments — DONE
- [x] FT-1..FT-12 all swept across deployments — DONE (stage 15, 144 rows)

## Stage 2 — Composed forgery + CE_b
- [x] FT-10 causal laundering, L0-verified, b=7 — DONE
- [x] FT-11, FT-12 — n=1
- [x] CE_b = 1 by exact single-class enumeration at matched budget — DONE (swept, stage 11)  [C4]
- [x] A9 necessity with budget redistributed to survivors — n=1
- [x] CE_b swept across deployments — DONE (stage 11): 18/18, CI [0.815, 1.000]

## Stage 3 — Anchor placement + performance (Thrust C)
- [x] P1 install (chattr +a) and adversarial attack at HA's exact capability set — DONE
- [x] P1 sensitivity: CAP_LINUX_IMMUTABLE and --privileged both defeat it — DONE
- [x] P4 eBPF probe; CAP_BPF absent, placement demoted — DONE
- [x] P2 separate-container anchor — DONE (stage 12): holds under all capability grants
- [x] P3 local off-process anchor — DONE (stage 12): P2 + periodic head publication
- [x] rho vs anchoring frequency f — n=1  [contrast C5]
- [x] Storage ratio, laminar retention projection — n=1
- [x] W(f) detection-window curve — DONE (swept, stage 9)
- [x] Edge-binding cost vs B2 (7-10%) — DONE

## Stage 4 — Reconstruction (Thrust B, the ceiling)
- [x] S1 laundered unlock — DONE (swept, stage 9)
- [x] S2 agent's alibi — DONE (swept, stage 9)
- [x] S3 segment substitution — DONE (swept, stage 9)
- [x] Metrics M1-M6 + miss taxonomy + conditionals — DONE (swept, stage 9)
- [x] Exact ILP vs greedy localization — DONE
- [x] S4 real t_c sweep — DONE (stage 17): pre-anchor blind spot = 25% of history
- [x] S5 real anchor compromise — DONE (stage 17): G-1 fails totally, as designed

## Stage 5 — Benign operation / BFP
- [x] BE-2 purge, BE-3 migrate, BE-4 restore, BE-5 clock step (fwd+back), BE-7, BE-11 — DONE
- [x] Anchored lifecycle markers implemented (PURGE/RESTORE/CLOCK_STEP/MIGRATE) — DONE
- [x] Adversarial marker-abuse test: FT-10 survives all forged markers — DONE
- [x] BFP vs B2 — DONE (stage 10): 0/448 CI [0,0.0082] vs B2 192/448  [C6]
- [x] BE-1, BE-6, BE-8, BE-9, BE-10 — DONE (stage 18, live hub, RE-RUN 2026-08-22): 0/5 both schemes
- [x] CLOCK_STEP marker hole quantified as a curve — DONE (stage 13); non-guarantee NARROWED

## Stage 6 — Scale
- [x] Incremental vs full recompute to 200k nodes — DONE
- [x] AB-1 on the corrected soundness objective — DONE
- [x] Scale to 680k nodes — DONE (stage 16); 10^7 not attempted, see ACCEPTED LIMIT

## Stage 19 — THE HOLDOUT (run once, last)  [NEW]
- [x] 8 sealed deployments, 24 rows, never touched since the stage-7 split — DONE
- [x] **OQ 0.000685 [0.000525, 0.000873] vs 0.00068 on the sweep — 0.7% apart** — DONE
- [x] LR 24/24, Miss-R-assert 24/24, RA 1.000 — hard gates hold at full strength — DONE
- [x] C1 8/8 vs B2 0/8, C3 8/8 vs B4 0/8, both 8/8 discordant — DONE
- [x] **THE DESIGN DID NOT OVERFIT** — all six post-split changes generalise — DONE
- [x] Holdout is now SPENT and must not be reused — DONE

## Stage 18 — Live-hub benign arms  [RE-RUN 2026-08-22 — first run was partly vacuous]
- [x] BE-1 restart, BE-6 reload, BE-8 interleave, BE-9 shutdown, BE-10 write failure — DONE
- [x] HOMEPROV 0/5 CI [0.000, 0.522]; B2 also 0/5 — DONE
      HONEST: B2 passes here because restarts APPEND rather than delete/backdate.
      The B2 contrast is specific to purge/restore/clock-step, not general.
- [x] 11-entry benign catalog now fully covered (7 snapshot @ n=448, 5 live-hub) — DONE
- [x] Harness flake found+closed: silent 'snapshot failed' now retries and reports — DONE

### Correction — three of the five arms were NOT testing anything (found 2026-08-22)
The first stage-18 run reported 0/5 and passed. On re-reading the harness before
letting the number into the manuscript, three arms turned out to be no-ops:
- **BE-6** executed `python -c "import urllib.request as u;pass"`. That cannot fail
  and cannot act. It recorded **0 new nodes** — the signature of a vacuous arm.
- **BE-8** was a bare `sleep(12)` hoping the hub's own automations would overlap.
  They did not: **2 new nodes**.
- **BE-10** ran `chmod a-w /config` as root; root bypasses the DAC write bits, so
  the recorder never saw a write failure. **4 new nodes**, i.e. normal operation.
An arm in which nothing happens cannot produce a false positive, so "no alarm"
from it was not evidence. Additionally the run left the ADVERSARY integration
loaded, which fires a full forgery scenario on every HA start — a benign-arm
measurement must not have an adversary in-process, whatever the outcome.

Fixes, all re-run:
- [x] `homeprov_bench` driver added (separate from BOTH defender and adversary);
      commands are executed in-process and must ACK, since the testbed mints no
      long-lived API token — DONE
- [x] BE-6 now calls `automation.reload` (real YAML integration reload, no restart);
      ack `{"ok":true,"did":"automation.reload"}`; **4 new nodes** — DONE
- [x] BE-8 now issues 8 concurrent service calls so chains genuinely overlap;
      ack confirmed; **32 new nodes** (was 2) — DONE
- [x] BE-10 now holds a `BEGIN EXCLUSIVE` transaction from a second process; probe
      returned **`BUSY OperationalError`**, so the write failure was real;
      **34 new nodes** (was 4) — DONE
- [x] Adversary integration DISABLED for the measurement, restored afterwards — DONE
- [x] `measure()` refuses to score an arm whose operation did not ack — DONE
- [x] Snapshot validation strengthened: a size-only check passed a truncated copy
      that then read as "database disk image is malformed". The copy is now opened
      and queried (integrity_check + non-empty events/states) before acceptance — DONE
- [x] Host-side path bug fixed (stages run with cwd=exp/, so `testbed/ha-config`
      resolved to `exp/testbed/ha-config`) — DONE

RESULT AFTER CORRECTION — all five arms genuinely exercised, all five silent:
      BE-6 4 nodes | BE-8 32 | BE-10 34 | BE-1 532 | BE-9 1038
      HOMEPROV 0/5, B2 0/5, Clopper-Pearson CI [0.000, 0.522]. GATE_PASS.
      Artifact: `exp/out/stage18_corrected.json`. The headline BFP claim is
      unaffected: it rests on the 448-trial snapshot arm, not on these five.

## Stage 17 — S4 and S5 as REAL scenarios (were proxies)
- [x] S4 real t_c sweep: pre-anchor blind spot QUANTIFIED — at t_c before the first
      anchor, 451 of 1794 rewritten rows (25%, exactly the pre-anchor fraction) are
      SILENTLY rewritable. Non-guarantee 2 is now a number a deployer can read off
      their install date. — DONE
- [x] S5 real anchor compromise: G-1 fails TOTALLY (honest anchor 2 violations ->
      compromised anchor 0), all 3 seeds. Trust assumption tested, not assumed. — DONE

## Stage 16 — Scale  [NEW]
- [x] 680,932 nodes reached; incremental p95 drift 1.08x over a 20x scale increase
      -> O(new nodes) CONFIRMED, flat in history length — DONE
- [x] Investigator costs at 680k: verify 4.5s, localize 0.36s, |Q| 15-26 — DONE
- [x] ~~HONEST SHORTFALL: 10^7 not attempted~~ — **CLOSED 2026-08-24 (E18/stage 28)**:
      reached 10^7 nodes, 70.6s commit at 141,620 nodes/s, 285 MB peak RSS,
      0 verify mismatches. Memory is O(open segments): 100x nodes -> 14.5x RSS.
- [ ] (superseded) design target was 10^6-10^7; reached 6.8e5, and 10^7 NOT
      attempted. Report the figure reached. — ACCEPTED LIMIT

## Stage 15 — Full FT-1..FT-12 catalog swept  [NEW]
- [x] 144 rows, 12 per class, all with exact intervals — DONE
- [x] **FT-4 and FT-5 (pure re-parent): HOMEPROV 12/12, B2 0/12, B4 0/12** —
      complete separation falls on exactly those two classes and nowhere else — DONE
- [x] LR = 1.000 on every detected instance — DONE
- [x] HONEST GAP: FT-6 sibling swap escaped ALL THREE schemes in 1/12 — DONE

## Stage 14 — OQ vs event age (laminar retention)  [NEW]
- [x] Staircase measured: OQ flat while a finer granularity survives, ~15x step
      when the event ages past the minute horizon (0.00087 -> 0.0132) — DONE
- [x] Detection and LR UNAFFECTED by age (3/3, LR=1.000 throughout) — DONE
- [x] **DESIGN GAP FOUND**: retention and the UNCOMMITTED-REGIONS check are
      incompatible if combined naively — pruning drove OQ to 0.988. verify() is now
      retention-aware. Retention is only safe BECAUSE the family is laminar (5th
      thing nesting buys). Neither mechanism mentioned the other in the design. — DONE

## Stage 13 — CLOCK_STEP hole quantified as a curve
- [x] Swept declared window x injection backdate — DONE
- [x] **Non-guarantee 11 OVERSTATED the exposure** — effective hole is
      min(window, distance to previous minute boundary), not the window — DONE
- [x] Laminar nesting NARROWS the hole (4th thing nesting buys) — DONE
- [x] MAX_CLOCK_STEP_S bound verified working (301s window refused outright) — DONE
- [x] Design non-guarantee 11 narrowed accordingly — DONE
      CAUTION: hole is real and non-zero — a 5s backdate in a 60s window escapes cleanly.

## Stage 12 — Anchor placements P1..P4 attacked side by side (AB-5 completed)  [NEW]
- [x] P2 built for real: append-only daemon in its OWN container, hub never mounts the volume — DONE
- [x] P3 built: P2 + periodic head publication to a second local volume — DONE
- [x] **P2/P3 HOLD under every capability grant incl. --privileged; P1 FALLS** — DONE
      P1 bounded by a filesystem flag; P2/P3 bounded by a PROTOCOL (one verb: append)
- [x] P2/P3 STRICTLY DOMINATE P1 -> ship separate-container as DEFAULT, P1 as fallback — DONE
- [x] Harness error caught: P1 was attacked without being installed first — DONE
- [x] NEW non-guarantee 13 added to the design: P2/P3 assume the anchor container is
      uncompromised; an adversary reaching the Docker socket defeats both — DONE

## Stage 11 — CE_b swept (contrast C4, the last n=1 result)  [NEW]
- [x] Adversary actuation PLANTED (generator has none) + baseline asserted INTEGRATION — DONE
- [x] **CE_b = 1 in 18/18 deployments, exact 95% CI [0.815, 1.000]** — DONE
- [x] Three single-class failure modes replicate M1 exactly in every deployment — DONE
      del -> UNKNOWN/plausible · rep -> NAMED_INNOCENT/implausible · inj -> INTEGRATION/plausible
- [x] Setup error caught: first run gave CE_b=0 in 18/18 because the victim was
      already a legitimate automation chain (no adversary existed) — DONE
- [ ] Renderer-backed CE_b remains n=1 BY DESIGN — no logbook renderer on generated
      deployments; SI-4/SI-5 proxy used for the sweep. Report both. — ACCEPTED LIMIT
- [ ] `Plaus` stability across HA patch versions UNTESTED — the plausibility verdict
      is read off the 2026.7.4 logbook renderer, and three of its invariants were
      found only by testing (cause must precede effect in wall-clock order;
      `old_state_id` must be chained; the automation's own entity state row must
      exist, else SEV-1 not SEV-2). Whether those hold on other patch releases was
      not measured, and a renderer change could move the verdict without any change
      to the forgery. Must be stated as a limitation. — ACCEPTED LIMIT

## Stage 10 — BFP at a sample size that can clear the threshold  [NEW]
- [x] n raised 36 -> 448 (rule of three: 0/36 bounds only at 0.097, not 0.01) — DONE
- [x] **BFP = 0/448, exact 95% CI [0.0000, 0.0082] — threshold <=0.01 CLEARED** — DONE
- [x] B2 = 192/448 (0.429): alarms 64/64 on purge, restore, backward clock step — DONE
- [x] 3rd instance of the states-only-head defect found+fixed (BE-4 restore point) — DONE

## Stage 9 — Sweep the n=1 results (S1-S5, BFP, W(f))  [NEW]
- [x] S1-S5 swept, 45 rows: all detected 9/9, LR 45/45, Miss-R-assert 45/45 — DONE
- [x] C2 OQ vs B3 +0.9857 CI [+0.982, +0.989], n=45 — DONE
- [x] C6 BFP: HOMEPROV 0/36 vs B2 18/36 — a NEW contrast, favours HOMEPROV — DONE
      RESOLVED in stage 10 at n=448.
- [x] C5 W(f) swept: ratio to theory 1.00-1.01 across 1/5/15/60s — DONE
      NOTE: contradicts the n=1 result (3.70s vs 2.50s). Both true — theory holds under
      uniform arrival; the REAL hub clusters events and deviates upward. Report both.
- [x] 4 harness defects fixed: anchor past head, CLOCK_STEP too narrow, straddling
      segments, states-only head. BFP 0.639 -> 0.583 -> 0.194 -> 0.000 — DONE
- [x] Marker abuse re-verified after every widening — DONE

## Stage 8 — Occupancy sweep (guarantee G-3 under test)
- [x] Confound removed: node count PINNED (8,160), span varied so occupancy spans 250x — DONE
- [x] 5 spans x 3 seeds, occupancy 0.136–34.0 nodes/s — DONE
- [x] **G-3 AS WRITTEN: FALSIFIED** — log-log slope 0.297, not ~1 — DONE
- [x] **G-3 CORRECTED FORM SUPPORTED**: |Q| = max(run_size, occupancy x w),
      floor = 6 nodes (one causal run), Pearson 0.982, slope above floor 0.809 — DONE
- [x] BUG FOUND+FIXED: laminar subsumption test was INVERTED, inflating blast
      radius up to 25x; soundness re-verified (LR=1.000 all scenarios) — DONE

## Stage 7 — Deployment sweep + statistics
- [x] 18 deployments x 3 forgery classes, 0 failures — DONE
- [x] Generator calibrated against the real deployment (structural error 0.066) — DONE
- [x] C1 HOMEPROV vs B2 on F_rep: 18/18 vs 0/18, exact CI — DONE
- [x] C2 OQ vs B3: +0.9991, CI [+0.9990,+0.9993], n=54 — DONE
- [x] C3 HOMEPROV vs B4 on F_rep: 18/18 vs 0/18 — DONE
- [x] Clopper-Pearson exact intervals for constant binary outcomes — DONE
- [x] Mixed effects on detection, random effect on deployment — DONE
- [x] OQ vs segment occupancy (guarantee G-3) — DONE in Stage 8; G-3 corrected, not merely confirmed
- [x] OQ vs event age — DONE (stage 14): ~15x staircase step past the minute horizon
- [x] Holdout 40% (8 deployments) — DONE (stage 19): tracks the tune set, SPENT

## Ablations
- [x] AB-1 greedy soundness + minimality (corrected objective) — DONE
- [x] AB-3 edge binding on/off, via the B4 self-baseline — DONE
- [x] AB-6 L4 leak test: algorithm output byte-identical with the oracle zeroed — DONE
- [x] AB-7 abstention disabled: 3 abstentions bought 0 wrong asserts vs 1 — DONE
- [x] AB-2 segment granularity — DONE (re-run on 6h history): second->hour inflates OQ 345x
      (0.00049 -> 0.169) and shrinks phi 980x. The OQ/storage dial, quantified.
- [x] AB-4 nesting on/off — DONE: laminar 0.00049 vs flat-hour 0.169. NOTE flat-hour is still
      ~6x better than B3, so nesting earns 2.5 of the 3.3 orders, not all of them.
- [x] AB-5 full placement matrix — DONE (stage 12): P1/P2/P3/P4 all measured


## Stage 20/21 — MOCK REVIEW P0: the fair baseline REFUTES the headline  [2026-08-24]

The mock IEEE S&P review (Reviewer 2, 4.1) alleged that B2 was too weak because
`content` excludes the three context columns, which are physically part of the
recorder row the attack edits. **The allegation is correct and the headline
result does not survive it.**

- [x] E3 / stage 20 — B2b implemented: commits the FULL physical row
      (content | context_id | parent_context_id | label), given HOMEPROV's own
      anchor and segmentation. Stage 15 re-run verbatim with B2b added, so the
      deployments, seeds and forgeries are identical — DONE
      ```
      FT       HOMEPROV   B2(content)  B2b(full row)  B4
      FT-4     12/12      0/12         12/12          0/12
      FT-5     12/12      0/12         12/12          0/12
      FT-6     11/12      11/12        12/12          11/12
      all others: 12/12 across all four schemes
      ```
      **B2b matches HOMEPROV everywhere and BEATS it on FT-6.**
- [x] E3b / stage 21 — the one structural difference that survives (HOMEPROV folds
      the parent's HASH into the child; a full-row scheme covers only the parent's
      IDENTITY) tested across 5 parent-child separations x 2 tamper types — DONE.
      Delta appears in **1 cell of 10**: deleting a parent older than the 90-day
      hour-retention horizon, caught via a surviving child. The rig itself notes
      causal parents are "almost always seconds old", so the condition is
      effectively unreachable. Artifact: `exp/out/stage21_final.json`.
- [x] CONSEQUENCE — C3 is refuted; `dec_01M0SH41J4DFSCRP86QHH6F5WA`;
      cluster `ecl_01M0MKXKJ61N83R51YG9SBV7GG` flagged RED — DONE

## Stage E2 — in-process defender subversion  [2026-08-24, PARTIAL]
- [x] Censoring hook installed by rebinding `homeprov._graph` from a second
      integration. Verified live: same module object, defender's view returned
      475 rows where the true graph had 477, excluding exactly the adversary's 2 — DONE
- [x] With the context censored BEFORE actuation, the anchor contains **no sealed
      segment at all** for the second the adversary acted in, while the database
      held 2 rows there. The anchor is silent about a real actuation — DONE
- [ ] End-to-end zero-violation verification after deletion — NOT SHOWN. Hiding a
      node without its transitive closure perturbs children, because HOMEPROV
      folds the parent hash into the child. Would require censoring the closure.
- [x] Ordering finding: censoring AFTER acting leaves a window up to one anchor
      period wide, and the append-only anchor then keeps the true rows forever.
      A real adversary mints its own context and censors before acting — DONE

## Live-implementation defects found while running the above  [2026-08-24]
- [x] **Anchor runaway**: the live `anchor_append()` wrote the FULL phi every 5s.
      Measured 66.9 GB in 3.2 days against a 4.4 MB recorder (~1.3 MB/anchor).
      C2 claims 1.005x the recorder; that is a RIG property the artifact did not
      exhibit. Fixed to append only newly sealed segments: **207 bytes/anchor**,
      a ~6,300x reduction. `jrn_01M0SESNWBCDBKZJWDPVZ93GYM` — DONE
- [x] **Live scheme differs from the rig**: the deployed defender hashes
      `content | parent_hash | label` and does NOT bind parent identity, which is
      the very hole the rig fixed (AB-1, 2026-08-20). The artifact is a weaker
      scheme than the one evaluated — DONE (recorded, not yet fixed)
- [x] **Restart re-seals all history**: `_STATE` is in-memory, so every restart
      re-commits from scratch (~3.5 MB). Per-anchor cost is flat in history; cost
      ACROSS RESTARTS is not — DONE (recorded)
- [ ] HA crashes with SIGBUS (exit 135) when an external process deletes recorder
      rows while the recorder holds the DB open — availability artifact, recorded


## Mock-review experiment programme  [2026-08-24]

PI chose: re-centre on attack + anchor + recovery, report the refutation, and run
everything feasible on this laptop.

### Done
- [x] **E3 / stage 20** — fair full-row baseline (B2b). **REFUTES the headline.**
      B2b 12/12 on FT-4 and FT-5 where content-only B2 scored 0/12 — DONE
- [x] **E3b / stage 21** — the parent-hash recursion buys a delta in 1 of 10
      cells, and only past the 90-day retention horizon — DONE
- [x] **E16 / stage 22-23** — FT-6 root-caused: the commitment never bound the
      node's OWN identity, so two same-entity rows swap hashes when their
      timestamps are exchanged, leaving every accumulator unchanged. Fixed
      (`homeprov2`); catalogue now 12/12 on every class — DONE
- [x] **E12 / stage 24** — six reconstruction policies on the same violation set.
      Coverage measured over TIME INTERVALS (node-set recall scores void-all at
      0.5). vs causal component 0.00193, this work 0.00179: **+8%, not 550x** — DONE
- [x] **E13 / stage 25** — exhaustive: 480 instances, soundness 480/480. But 257
      of 480 quarantines have a proper subset that would also have sufficed, so
      "minimal" is not "tight" — DONE
- [x] **E11 / stage 25** — fuzzing, 400 trials, 15 malformed classes. No crash, no
      hang. **1 class still evades**: duplicate context, 6/27, because the scheme
      does not bind a node's own context id (third identity omission) — DONE
- [x] **E15 / stage 25** — generator sensitivity. Only bg_ratio moves the
      parent-context fraction; the other four parameters do nothing. Standard arm
      runs at 0.049 vs 0.012 measured on the real testbed — DONE
- [x] **E22 / stage 26** — anchor protocol matrix. Append-only HOLDS (rewrite verbs
      and traversal refused, chain never shortens) but the anchor accepts
      conflicting roots, fake markers, malformed bodies, and 300 unauthenticated
      appends at 1229/s. First-write-wins now specified — DONE
- [x] **E23 / stage 27** — detection-window curve over 9 periods. Mean W = period/2
      exactly; duty cycle FLAT at 0.0003% from 1s up, so a 1s window costs what a
      5s window costs — DONE
- [x] **E2 (partial)** — in-process defender subversion. Hook verified live
      (defender saw 475 of 477 rows, excluding exactly the adversary's); anchor
      contained NO segment for the second the adversary acted in — DONE (partial)

### ARCHITECTURAL CORRECTION BUILT  [2026-08-24]
- [x] **External monitor** built and deployed. Own container, own network, hub
      config mounted `:ro`, receives nothing from the hub process — DONE
- [x] **WAL trap found and handled**: read-only open of a live WAL DB fails, and
      `immutable=1` opens but SILENTLY IGNORES THE WAL, missing exactly the newest
      rows. Monitor copies DB + sidecars to scratch and reads the copy — DONE
- [x] **Determinism gate PASSED**: monitor vs rig, 5,406 segments, 0 mismatches.
      Artifact and evaluated design now agree byte-for-byte — DONE
- [x] **Incremental folding**, with the unsound version rejected: filtering on a
      high-water mark would let a backdated insert (FT-9) slip past. Re-reads from
      the oldest open segment. 10,141 rows/tick -> 827; commit 38ms -> 5ms — DONE
- [x] **E2 re-run: the attack is now DETECTED.** 5 violations / 5,480 segments,
      including 2 the anchor holds and the DB no longer does — DONE
- [x] **E1 pre-observation window measured.** Latency p50 1.77s / p95 5.02s at a
      5s period; P(never observed) 0.975 @0.5s dwell, 0.620 @2s, 0.183 @5s,
      0.000 @10s. Bounded by ~1+P. First attempt discarded (p50 21,305s) because
      the monitor's first tick backfills all history — DONE
- [x] P1/P2 placement divergence fixed as a side effect: the monitor anchors to
      the P2 daemon the hub could not previously even reach — DONE

### Done since the architectural correction
- [x] **E18 / stage 28 — SCALE TO 10^7.** Closes the accepted limit carried since
      the original design. 100k -> 10M: throughput 199k -> 142k nodes/s (-29%),
      RSS 19.6 -> 285 MB (14.5x for 100x nodes), anchor 0.5 -> 52 MB unpruned,
      verify 0.47s -> 60.3s, zero mismatches at every point. Run at the MEASURED
      parent-context fraction 0.012, not the sweep's 0.049 — DONE
- [x] **E14 — formal appendix.** 13 definitions, 3 assumptions, 6 theorems.
      A3 (observer not adversarially controlled) is stated AND flagged false for
      an in-process observer — the soundness theorem depends on it. Theorem 3 is
      minimality over transformations consistent with the evidence, with the
      measured 257/480 hindsight gap noted — DONE

### Not yet run
- [ ] E4 renderer dependency closure · E5 large renderer-backed evaluation ·
      E6 cross-version Home Assistant · E8 attack-budget models ·
      E9 minimum-laundering search

### Excluded by the PI's scope choice
E7 multi-database, E17 independent workload family, E19 macro load,
E20 resource-envelope sensitivity, E21 crash consistency.

## Baselines
- [x] B0 stock recorder, no integrity — DONE
- [x] B1 in-database hash chain, DEMONSTRATED broken (not asserted) — DONE
- [x] B2 record-level (CONTENT-ONLY), given HOMEPROV's anchor — DONE
      **SUPERSEDED as the hardest baseline**: content excludes the context columns.
- [x] B2b FULL PHYSICAL ROW, given HOMEPROV's anchor — DONE (stage 20). This is
      the real hardest baseline and it refutes the headline separation.
- [x] B3 whole-log-void — DONE
- [x] B4 HOMEPROV minus edge binding — DONE

## Priority order for what remains
1. ~~Fix the rate confound; test G-3~~ — **DONE 2026-08-22.** G-3 as written is FALSE;
   corrected form |Q| = max(run_size, occupancy x w) is supported. Design must be updated.
2. ~~Re-run AB-2 / AB-4 on long histories~~ — **DONE 2026-08-22**
3. ~~Sweep S1-S5, BFP and W(f)~~ — **DONE 2026-08-22** (stage 9)
4. ~~CE_b swept~~ — **DONE 2026-08-22** (stage 11). All six contrasts now carry intervals.
5. ~~P2 and P3 anchor placements~~ — **DONE 2026-08-22** (stage 12). AB-5 complete.
6. ~~Live-hub benign arms BE-1/6/8/9/10~~ — **DONE 2026-08-22**, then **RE-DONE**
   after three arms were found vacuous (see the Stage 18 correction block).
7. ~~Scale to 10^6~~ — **DONE** (stage 16), reached 6.8x10^5; 10^7 is an accepted limit.
8. ~~Holdout, once, last~~ — **DONE** (stage 19). SPENT. Design did not overfit.
