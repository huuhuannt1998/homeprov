# Earlier runs: the record that left the paper in round 14c

This file holds, verbatim, the earlier-run results that the paper printed in its Appendices B and G until round 14 and that moved to the artifact in round 14c (PI decision of 2026-10-12 on internal review round 4: "Move to artifact (Recommended)"): the runs on the lab installation before coverage, the per-arm results of E7 (the first run with coverage), the per-run benign floors, and the re-verification of the earlier-encoding runs with the typed encoding. The paper keeps a one-paragraph summary in Appendix B and lists every run, with its result-file hash, in its run table (`tab:runs`). In the round-14 PDF (main.pdf `740198a60680`) Tables A and B below were printed as Tables 9 and 10. Nothing here is new: each sentence is the accepted round-14 text (authoring graph realization named below), each table the round-14 float.

Every file is given with the first 12 hex digits of its sha256, computed when this file was written (2026-10-12) and checked against the hash that the paper's evidence record or float manifest recorded. Check a prefix with `shasum -a 256 <file> | cut -c1-12` from the repository root. LaTeX references are rendered in words.

## Table A. Earlier runs without coverage: detection (the paper's `tab:detect`)

Caption as printed: Earlier runs without coverage: confirmed misattributions (90 of 90: [0.960, 1.000]), flags at one second, detections after the late-row test, ambiguous trials; floors in Table B below and Section 7 of the paper. Arms have 90 trials, the own-actuation controls 30; the row-scheme laundering run's snapshot is gone, its member-account row recomputed offline.

| Arm | Misattributed | Flagged at 1 s | Detected (late-row test) |
|---|---|---|---|
| *Closure monitor* |  |  |  |
| Other principal (two arms) | 90/90, 90/90 | 90/90, 90/90 | 179/180, 1 ambiguous |
| Own actuation (control) | not scored | 30/30 | 30/30 |
| Random-id swap | the paper's Table 2 (`tab:swap`) | 90/90 | 89/90, 1 ambiguous |
| Member-account swap | the paper's Table 2 (`tab:swap`) | 90/90 | 90/90 |
| *Row-scheme monitor (baseline)* |  |  |  |
| Other principal (two arms) | 90/90, 90/90 | 90/90, 90/90 | not computable |
| Own actuation (control) | not scored | 30/30 | 30/30 |
| Random-id swap | the paper's Table 2 (`tab:swap`) | 1/90 | 0/90 |
| Member-account swap, offline | the paper's Table 2 (`tab:swap`) | 0/90 | 0/90 |
| *Whole-row scheme (baseline)* |  |  |  |
| Other principal (two arms) | 90/90, 90/90 | 90/90, 90/90 | not separable |
| Random-id swap | not re-derived | 90/90 | not separable |
| Member-account swap | not re-derived | 90/90 | not separable |

Source files (float manifest `SP-TAB3`; `reproduce/recount_floats.py` recomputes every cell):
  - `exp/out/e_d_clo_other_principal_real.json` `5f09fb190026`
  - `exp/out/e_d_clo_late_row_check.json` `865069e15e84`
  - `exp/out/e_c_clo_late_row_check.json` `6692837af0c1`
  - `exp/out/e_c_clo_other_principal_real.json` `8239953b65a9`
  - `exp/out/e_ps_detection_rescored.json` `66eb237c3331`
  - `exp/out/e_psr_clo_detection.json` `220d8e24248c`
  - `exp/out/e_d_auth_other_principal_real.json` `a3b42023dd7f`
  - `exp/out/e_c_auth_other_principal_real.json` `7c8bf5df715c`
  - `exp/out/e_c_auth_late_row_check.json` `8cf7a5b3ae8b`
  - `exp/out/e_ps_clo_detection.json` `bf8dc6895a33`
  - `exp/out/e_ps_auth_detection.json` `df2e535ffee1`
  - `exp/out/e_d_whr_other_principal_real.json` `9b5d81446ed3`
  - `exp/out/e_ps_whr_detection.json` `88e948fd980b`
  - `exp/out/e_psr_whr_detection.json` `d048c791aeae`
  - `exp/out/r6_reverify_v2.json` `020344bc1f22`

## Table B. Per-run benign floors of the nine runs without coverage (the paper's `tab:floors`)

Caption as printed: Per-run one-second floors of the nine runs without coverage lie between 1 of 714 and 3 of 711 untouched segments, every failure a late row; every minute floor is zero.

| Run | Scheme | Auth. | One-second floor | Minute | Load start/end |
|---|---|---|---|---|---|
| Write-time | row | no | 3/744 [0.001, 0.012] | 0/10 | not logged |
| Other principal | row | no | 1/558 [0.000, 0.010] | 0/14 | not logged |
| Other principal | row | yes | 1/527 [0.000, 0.011] | 0/14 | 2.41/1.75 |
| Write-time | row | yes | 3/711 [0.001, 0.012] | 0/8 | 3.08/2.30 |
| Random-id | row | yes | 1/308 [0.000, 0.018] | 0/7 | 2.74/10.09 |
| Random-id | closure | yes | 1/312 [0.000, 0.018] | 0/8 | 18.97/16.35 |
| Other principal | closure | yes | 1/560 [0.000, 0.010] | 0/14 | 18.14/12.38 |
| Write-time | closure | yes | 1/714 [0.000, 0.008] | 0/9 | 12.38/59.20 |
| Member acct. | closure | yes | 1/299 [0.000, 0.018] | 0/8 | 4.62/4.06 |
| Pooled (nine) |  |  | 13/4,733 [0.001, 0.005] | zero |  |

Load start/end is the host's one-minute load average at the start and end of each run. The pooled row (13 of 4,733) stays in the paper's `tab:benign` table. Source files (float manifest `SP-TAB-B`):
  - `exp/out/e_c_write_time.json` `377a335091ce`
  - `exp/out/e_c_write_time_floor_rescore.json` `c4b20df2755e`
  - `exp/out/e_d_other_principal_real.json` `644574c60e6b`
  - `exp/out/e_d_other_principal_real_floor_rescore.json` `c2bb7a637094`
  - `exp/out/e_d_auth_other_principal_real.json` `a3b42023dd7f`
  - `exp/out/e_d_auth_floor_rescore.json` `78347878fe34`
  - `exp/out/e_d_auth_config.json` `7d053a94a160`
  - `exp/out/e_c_auth_other_principal_real.json` `7c8bf5df715c`
  - `exp/out/e_c_auth_floor_rescore.json` `e488bd80755d`
  - `exp/out/e_c_auth_config.json` `eb633c8224ee`
  - `exp/out/e_ps_auth_detection.json` `df2e535ffee1`
  - `exp/out/e_ps_auth_floor_rescore.json` `bd5d7fc1dcba`
  - `exp/out/e_ps_auth_config.json` `59c3f8ed9336`
  - `exp/out/e_ps_clo_detection.json` `bf8dc6895a33`
  - `exp/out/e_ps_clo_floor_rescore.json` `bed92df26d09`
  - `exp/out/e_ps_clo_config.json` `ef720f11ae82`
  - `exp/out/e_d_clo_other_principal_real.json` `5f09fb190026`
  - `exp/out/e_d_clo_floor_rescore.json` `a781f6c300ed`
  - `exp/out/e_d_clo_config.json` `21219c7598b7`
  - `exp/out/e_c_clo_other_principal_real.json` `8239953b65a9`
  - `exp/out/e_c_clo_floor_rescore.json` `8d2de389b9d1`
  - `exp/out/e_c_clo_config.json` `244648ea3e1e`
  - `exp/out/e_psr_clo_detection.json` `220d8e24248c`
  - `exp/out/e_psr_clo_floor_rescore.json` `a9dc3e34b836`
  - `exp/out/e_psr_clo_config.json` `1ecd2df3aefc`

## Moved sentences

### Appendix B, earlier runs without coverage (contract PC-S078)

- **SI-S121-01** (realization `R-S121-01@2`): Before coverage, runs on the lab installation scored the closure monitor under the late-row test of Section 7.2 of the paper (Table A below) and found every member-account flag an in-place change.
  - `exp/out/e_psr_clo_detection.json` `220d8e24248c` (matches the evidence record): member-account flags, all in-place changes
  - `exp/out/e_d_clo_late_row_check.json` `865069e15e84` (matches the evidence record): late-row test, other-principal laundering
  - `exp/out/e_ps_detection_rescored.json` `66eb237c3331` (matches the evidence record): late-row test, random-id swap

- **SI-S121-02** (realization `R-S121-02@2`): The ambiguous laundering trial's edited row was itself a late row, and the ambiguous random-id swap's was among 8 late rows.
  - `exp/out/e_d_clo_late_row_check.json` `865069e15e84` (matches the evidence record): the ambiguous laundering trial (net +1 row, a late row)
  - `exp/out/e_ps_detection_rescored.json` `66eb237c3331` (matches the evidence record): the ambiguous random-id swap (+8 rows)
  - `exp/out/r13_subset_test.json` `88b7f1a6f393`: the 8 late rows of that trial

- **SI-S121-03** (realization `R-S121-03@2`): The row scheme detected no random-id swap live and no member-account swap offline (Table A below), since it omits the user column.
  - `exp/out/e_ps_detection_rescored.json` `66eb237c3331` (matches the evidence record): row scheme, random-id swap live: 0/90 after the late-row test
  - `exp/out/r6_reverify_v2.json` `020344bc1f22` (matches the evidence record): row scheme offline on the member-account swap: 0/90 [0.000, 0.040]

- **SI-S078-04** (realization `R-S078-04@1`): Every evaluated run but two used unlinked anchor records: 16 of the 18 authenticated runs by their saved chains, the three earlier runs by the daemon's commit history.
  - `exp/out/r13d_chain_link_census.json` `1becfa610c15` (matches the evidence record): 16 of the 18 authenticated runs' saved chains hold no linked record
  - `exp/out/r7_anchor_link_scope.json` `9be458c3bbe8`: the three earlier, unauthenticated runs (daemon's commit history)

- **SI-S078-05** (realization `R-S078-05@1`): In E5, a run with the linked anchor and a witness outside both virtual machines of Section 8 of the paper, chain copies truncated or relinked failed only against the witness's 225 heads.
  - `exp/out/e5_psr_lnk_linked.json` `ce36a1da9b8e` (matches the evidence record): 225 witnessed heads; truncated or relinked copies

### Appendix B, benign floors of the nine runs without coverage (contract PC-S079)

- **SI-S056-03** (realization `R-S056-03@7`): Every benign failure of the nine runs was a late row, because the recorder commits a row about a second after its event while the monitor sealed each second with no grace period, and in the seven runs with logged host load the one-second floor does not rise with load (Table B below).
  - `exp/out/e_c_write_time.json` `377a335091ce` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_write_time_floor_rescore.json` `c4b20df2755e` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_other_principal_real.json` `644574c60e6b` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_other_principal_real_floor_rescore.json` `c2bb7a637094` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_auth_other_principal_real.json` `a3b42023dd7f` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_auth_floor_rescore.json` `78347878fe34` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_auth_config.json` `7d053a94a160`: per-run floor and logged host load (Table B)
  - `exp/out/e_c_auth_other_principal_real.json` `7c8bf5df715c` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_auth_floor_rescore.json` `e488bd80755d` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_auth_config.json` `eb633c8224ee`: per-run floor and logged host load (Table B)
  - `exp/out/e_ps_auth_detection.json` `df2e535ffee1` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_ps_auth_floor_rescore.json` `bd5d7fc1dcba` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_ps_auth_config.json` `59c3f8ed9336`: per-run floor and logged host load (Table B)
  - `exp/out/e_ps_clo_detection.json` `bf8dc6895a33` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_ps_clo_floor_rescore.json` `bed92df26d09` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_ps_clo_config.json` `ef720f11ae82`: per-run floor and logged host load (Table B)
  - `exp/out/e_d_clo_other_principal_real.json` `5f09fb190026` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_clo_floor_rescore.json` `a781f6c300ed` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_d_clo_config.json` `21219c7598b7` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_clo_other_principal_real.json` `8239953b65a9` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_clo_floor_rescore.json` `8d2de389b9d1` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_c_clo_config.json` `244648ea3e1e` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_psr_clo_detection.json` `220d8e24248c` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_psr_clo_floor_rescore.json` `a9dc3e34b836` (matches the evidence record): per-run floor and logged host load (Table B)
  - `exp/out/e_psr_clo_config.json` `1ecd2df3aefc`: per-run floor and logged host load (Table B)

- **SI-S079-01** (realization `R-S079-01@6`): A rule counting the state row alone pooled 15 of 4,956 untouched one-second segments as failing, two of them the adversary's own service-call deletions, which Section 7 of the paper excludes.
  - `exp/out/e_c_write_time.json` `377a335091ce` (matches the evidence record): earlier rule 3/810
  - `exp/out/e_d_other_principal_real.json` `644574c60e6b` (matches the evidence record): 1/558
  - `exp/out/e_d_auth_other_principal_real.json` `a3b42023dd7f` (matches the evidence record): 2/543
  - `exp/out/e_c_auth_other_principal_real.json` `7c8bf5df715c` (matches the evidence record): 3/779
  - `exp/out/e_ps_auth_detection.json` `df2e535ffee1` (matches the evidence record): 1/309
  - `exp/out/e_ps_clo_detection.json` `bf8dc6895a33` (matches the evidence record): 1/312
  - `exp/out/e_d_clo_other_principal_real.json` `5f09fb190026` (matches the evidence record): 2/564
  - `exp/out/e_c_clo_other_principal_real.json` `8239953b65a9` (matches the evidence record): 1/775
  - `exp/out/e_psr_clo_detection.json` `220d8e24248c` (matches the evidence record): 1/306; pooled 15 of 4,956

- **SI-S079-03** (realization `R-S079-03@2`): Offline, rows inserted into edited seconds left none of the 838 attributable closure-scheme trials attributable under the late-row test and 838 of 838 [0.996, 1.000] under the subset test, which attributed no untouched second of 3,506.
  - `exp/out/r13_subset_test.json` `88b7f1a6f393`: 838 of 838 [0.996, 1.000] under the subset test, 0 of 838 under the late-row test (count_above_anchored), 0 of 3,506 untouched seconds attributed

### Appendix B, E7, the first run with coverage (contract PC-S165)

- **SI-S113-01** (realization `R-S113-01@3`): E7, the first run with coverage (the paper's run table (`tab:runs`)), detected all 30 trials of each of nine arms under both monitors, including unlocks backdated into an empty sealed minute or given a reserved key and moved into sealed time at least 130 s later.
  - `exp/out/e7_main_closure_verify.json` `d2e1319c5242` (matches the evidence record): closure monitor, 30 of 30 in each of nine arms
  - `exp/out/e7_main_stable_verify.json` `5502f25e2034` (matches the evidence record): stable-columns monitor, 30 of 30 in each of nine arms
  - `exp/out/e7_main_score.json` `3a4a356007a6` (matches the evidence record): per-arm detection
  - `exp/out/e7_preregistration.json` `85593490b5f7` (matches the evidence record): 130 s (bd_min_age_s, bd_move_delay_s)

- **SI-S113-03** (realization `R-S113-03@3`): The earlier rule found every insertion trial ambiguous and flagged no backdated unlock.
  - `exp/out/e7_main_score.json` `3a4a356007a6` (matches the evidence record): earlier rule: INS-L and INS-M 30 of 30 ambiguous, BD arms 0 flagged

- **SI-S113-05** (realization `R-S113-05@3`): Appends kept succeeding while the hub held slow connections to the anchor, and edits during a 90 s anchor pause were attributed once their frozen roots were anchored, in 30 of 30.
  - `exp/out/e7_main_score.json` `3a4a356007a6` (matches the evidence record): STALL: appends in every trial; OUTAGE: 30 of 30 detected
  - `exp/out/e7_preregistration.json` `85593490b5f7` (matches the evidence record): outage_pause_s 90

- **SI-S113-06** (realization `R-S113-06@3`): Both monitors had a benign floor of 0 of 1,212 untouched seconds [0.000, 0.003], and a closure-monitor poll took 271 ms at the median.
  - `exp/out/e7_main_score.json` `3a4a356007a6` (matches the evidence record): benign floor 0 of 1,212 [0.000, 0.003] both monitors; poll 270.968 ms median

- **SI-S113-07** (realization `R-S113-07@3`): The one edited unlock its escrow could not restore (Section 7.2 of the paper) reached the recorder after its second was sealed, so the escrow held no copy.
  - `exp/out/e7_main_score.json` `3a4a356007a6` (matches the evidence record): recovery 119 of 120 (recovery_render)
  - `exp/out/e7_main_escrow_scored.json` `75246d511360`: escrow lines scored against the anchor

### Appendix G, re-verification of the earlier-encoding runs (contract PC-S090)

- **SI-S090-01** (realization `R-S090-01@12`): Ten of the fourteen earlier-encoding runs of the paper's run table (`tab:runs`) were re-verified with the typed encoding: 1,290 trials and 1,046 edited rows, distinct state rows rewritten post-commit.
  - `exp/out/r6_reverify_scope.json` `05eaca2fb8d5`: 10 runs, 1,290 trials, 1,046 edited rows
  - `exp/out/r6_reverify_v2.json` `020344bc1f22` (matches the evidence record): the re-verified verdicts

- **SI-S090-17** (realization `R-S090-17@1`): Every row has at least one NULL context column, which the earlier encoding wrote like an empty one, and it rounded `last_changed_ts` to six decimals.
  - `exp/out/r6_node_hash_exposure.json` `6c68280b59b9` (matches the evidence record): every one of 1,090,765 rows has a NULL among its hashed context columns
  - `monitor/monitor.py` `8ad9e2d77f2d` (matches the evidence record): the encoding comment: last_changed_ts rounded to six decimals under the earlier encoding

- **SI-S090-10** (realization `R-S090-10@5`): Write-time runs edit rows only in their 30 post-commit controls, and 12 of the 90 whole-row random-id swaps also wrote an earlier trial's row.
  - `exp/out/r6_reverify_v2.json` `020344bc1f22` (matches the evidence record): write-time runs: only the 30 controls edit rows
  - `exp/out/e_ps_whr_detection.json` `88e948fd980b` (matches the evidence record): 12 of the 90 whole-row random-id swaps also wrote an earlier trial's row

- **SI-S090-11** (realization `R-S090-11@5`): Per run in table order (trials, edited rows, rows with the separator byte in a context field): 180, 180, 21; 150, 30, 0; 90, 90, 7; 90, 90, 7; 180, 180, 9; 150, 27, 0; 90, 90, 1; 90, 89, 10; 180, 180, 25; and 90, 90, 6.
  - `exp/out/r6_reverify_scope.json` `05eaca2fb8d5`: per run: trials, edited rows, rows with the separator byte

- **SI-S090-04** (realization `R-S090-04@9`): The 26 September run was re-verified from a later recorder copy, every other run from its verifier snapshot.
  - `exp/out/r6_reverify_v2.json` `020344bc1f22` (matches the evidence record): 26 September run from a later recorder copy
  - `reproduce/verify_all_report.json` `9f459dbc7d90`: run dates

- **SI-S090-05** (realization `R-S090-05@9`): Of the 1,290 verdicts, 594 were recomputed and 696 flagged ones carry over, since their deleted rows are gone and an earlier-encoding mismatch over the same fields implies a typed one.
  - `exp/out/r6_reverify_v2.json` `020344bc1f22` (matches the evidence record): 594 recomputed, 696 carried over

- **SI-S090-02** (realization `R-S090-02@12`): No verdict changed, and every edit, including the 86 edited rows with the separator byte, changed its row's node hash under the earlier encoding.
  - `exp/out/r6_reverify_scope.json` `05eaca2fb8d5`: 0 verdict changes; 86 edited rows with the separator byte; 0 hashes unchanged

- **SI-S090-03** (realization `R-S090-03@10`): The other four runs keep their earlier-encoding verdicts: the authenticated blinding run's seal check was recomputed under both encodings, and the unauthenticated runs kept no verifier snapshot.
  - `exp/out/r6_reverify_scope.json` `05eaca2fb8d5`: the four runs outside the 1,290 (not_in_the_1290)

## What the paper keeps

- Appendix B: one paragraph saying what the earlier runs scored, that all 13 benign failures in the 4,733 untouched one-second segments of the nine runs without coverage were late rows (the `tab:benign` table pools them), and that this file holds the rest; the `tab:runs` table lists every run.
- Section 7.2: E7 detected every trial of nine arms and its escrow restored the true author in 119 of 120 edited trials; E7's and E8's 3,972 untouched seconds had no failure.
- Section 7.7 and Appendix A: the write-time runs (Table `tab:writetime`).
- Appendix G: the minute-root insertion check on the seven closure- and row-scheme runs, the grace-period pair, the anchor test census and the E7/E8 re-verification.

