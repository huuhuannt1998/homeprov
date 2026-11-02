# Design documents cited by the E7 to E12 pre-registrations

## E7 and E8

`exp/out/e7_preregistration.json` and `exp/out/e8_preregistration.json` cite these documents by their working path (`drafts/round13/<name>`, the manuscript's working folder, which is not released); each is here as `docs/<name>`. They are the documents as they stood when this tree was built, not copies taken at registration. Registration times: `exp/out/e7_preregistration.json` 2026-10-08T17:53:09.068797+00:00; `exp/out/e7_preregistration_amendment1.json` 2026-10-08T18:20:38.848120+00:00; `exp/out/e8_preregistration.json` 2026-10-09T02:13:47.437436+00:00.

| Document | Cited by (pre-registration field) | Last modified (UTC) | Relative to the registration that cites it | sha256 of the working copy (prefix) | Withheld |
|---|---|---|---|---|---|
| `E7_CODE_REVIEW.md` | e7_preregistration.json `design.code_review` | 2026-10-09T00:31:59Z | after the E7 registration | 61a71e36f5e6 | none |
| `E7_DESIGN.md` | e7_preregistration.json `design.doc` | 2026-10-08T14:38:18Z | before the E7 registration | e4a09399d3a1 | none |
| `E7_IMPL_NOTES.md` | e7_preregistration.json `design.impl_notes`; e8_preregistration.json `design.impl_notes` | 2026-10-09T00:37:13Z | after the E7 registration, before the E8 registration | 3746c5de00f3 | none |
| `E7_RUN_NOTES.md` | e7_preregistration.json `design.run_notes` | 2026-10-08T17:48:06Z | before the E7 registration | e7519419ba82 | 5 part(s) withheld |
| `E8_ANCHOR_NOTES.md` | e8_preregistration.json `design.impl_notes` | 2026-10-09T00:23:00Z | before the E8 registration | 7f37f4723c58 | none |
| `E8_DESIGN.md` | e8_preregistration.json `approval`; e8_preregistration.json `design.doc` | 2026-10-09T00:03:52Z | before the E8 registration | 4cb4569b3095 | none |
| `E8_RUN_NOTES.md` | e8_preregistration.json `design.run_notes`; e8_preregistration.json `parameters.stress_factor_open_decision` | 2026-10-09T02:12:41Z | before the E8 registration | d3bd9f5fdfd1 | none |

A document modified after a registration that cites it holds sections written later; their own headings and dates say so (for example `E7_IMPL_NOTES.md` section 11 and the "E8 review" of `E7_CODE_REVIEW.md` were written for E8). Every document `e8_preregistration.json` cites was last modified before E8 was registered.

How these copies differ from the working copies, and nothing else:
- machine paths are rewritten with the tree's path rules (`reproduce/SANITIZED_r6.json`), the revision branch's name and an internal review label are masked as everywhere in the tree, and a session scratch directory's path becomes `<scratch>` (`reproduce/SANITIZED_r13d.json`, `docs_rules`);
- in `E7_RUN_NOTES.md`, the parts that describe how the attack integration implements the arms, or its code, are replaced in place by a line beginning "[Withheld from the artifact:" (the table above counts them; `reproduce/SANITIZED_r13d.json` gives the first words of each part and its length in lines).

The documents name internal design and code-review rounds by their labels (B1, M3, R1, BE8, ...) and the people involved by role only (the lead, the PI, an agent). Documents and files they mention that are not in this artifact: `E7_ANCHOR_NOTES.md`, `AGENT_BRIEF.md`, `E8_PREREG_DRAFT.json` (its final form is `exp/out/e8_preregistration.json`), the internal reviews under `drafts/round13/reviews/`, the scratch test files of the code reviews, the run directories (`HOMEPROV-P13-exp/e7`, `e8`; their recorder rows that the verifier reads are `reproduce/snapshots/e7e8/e7_main.db` and `e8_main.db`) and the attack integrations.

## E9

`exp/out/e9_preregistration.json` cites these documents by their working path (`drafts/round13/<name>`); its two amendments cite none. `E9_CODE_REVIEW.md` is added because the E9 code was frozen after it. As above, they are the documents as they stood when this tree was built. Registration times: `exp/out/e9_preregistration.json` 2026-10-10T08:52:19.673470+00:00; `exp/out/e9_preregistration_amendment1.json` 2026-10-10T16:15:15.534510+00:00; `exp/out/e9_preregistration_amendment2.json` 2026-10-12T03:07:45.903773+00:00.

| Document | Cited by (pre-registration field) | Last modified (UTC) | Relative to the E9 registration | sha256 of the working copy (prefix) | Withheld |
|---|---|---|---|---|---|
| `E2_PURGE_DIAGNOSIS.md` | e9_preregistration.json `design.purge_timer_diagnosis` | 2026-10-09T08:32:38Z | before the E9 registration | 28f12887208a | none |
| `E9_CODE_REVIEW.md` | not cited; the review of the E9 code before it was frozen; E9_IMPL_NOTES.md sections 11 and 12 answer it | 2026-10-10T03:47:23Z | before the E9 registration | 23f63c52ae7f | none |
| `E9_DESIGN.md` | e9_preregistration.json `approval`; e9_preregistration.json `design.doc` | 2026-10-09T21:05:51Z | before the E9 registration | c8e0ce781560 | none |
| `E9_IMPL_NOTES.md` | e9_preregistration.json `design.impl_notes`; e9_preregistration.json `outcomes.secondary.restore`; e9_preregistration.json `parameters.quick_check_every_basis`; e9_preregistration.json `parameters.scorer_jobs_basis`; e9_preregistration.json `parameters.settings_checked`; e9_preregistration.json `parameters.verifier_purge_tol_basis`; e9_preregistration.json `schedule.special.2026-10-14 20:00 / 20:30` | 2026-10-10T05:00:43Z | before the E9 registration | 2dc42d199764 | none |
| `E9_PRE_NOTES.md` | e9_preregistration.json `parameters.quick_check_every_basis` | 2026-10-10T05:46:39Z | before the E9 registration | fc86df774908 | none |
| `E9_RUN_NOTES.md` | e9_preregistration.json `design.run_notes` | 2026-10-10T16:17:06Z | after the E9 registration | ad7bbf050f99 | 2 part(s) withheld |

Modified after the E9 registration: `E9_RUN_NOTES.md` (after amendment 1; before amendment 2); their dated sections say what was written after it (`E9_RUN_NOTES.md` section 6.6, "Registration and the timed start"). Masked and withheld as above (`reproduce/SANITIZED_r14.json`, `docs` and `docs_rules`); in `E9_RUN_NOTES.md`, two passages that describe what the E6 in-hub harness or an attack integration does internally are replaced in place by a line beginning "[Withheld from the artifact:". The released, unchanged files `exp/out/e9_preregistration.json` (which its OpenTimestamps proof covers) and `testbed/e9/run_e9.sh` name the operations the harness accepts, not its code.

Documents and files they mention that are not in this artifact: `E9_PREREG_DRAFT.json` (its final form is `exp/out/e9_preregistration.json`), `TRIAGE.md`, `AGENT_BRIEF.md`, the internal reviews under `drafts/round13/reviews/`, the scratch test files of the code review, the run directories (`HOMEPROV-P13-exp/e9` with its smoke runs, keys and the amendment proof files; `HOMEPROV-P13-exp/e2night`; `HOMEPROV-P13-exp/e6`), the artifact preparation folder `HOMEPROV-P13-artifact-prep` (its `pinned/` copies are this tree's `monitor/monitor_e8.py` and `exp/stages/e7_verify_e8.py`), the E6 in-hub harness `homeprov_e6` and the attack integrations.

## E10, E10b, E11 and E12

These registrations cite their design and results notes by working path (`drafts/round13/<name>`) and record the sha256 of the file at registration; the table says whether the working copy as this tree was built still has that digest (the released copy differs from it by the masking and withholding below). Registration times: `exp/out/e10_preregistration.json` 2026-10-20T21:34:16.748849+00:00; `exp/out/e10b_preregistration.json` 2026-10-26T05:30:14.250513+00:00; `exp/out/e11_preregistration.json` 2026-10-24T11:53:41.451334+00:00; `exp/out/e12_preregistration.json` 2026-10-21T21:52:27.295647+00:00.

| Document | Cited by (registration field) | Last modified (UTC) | Working copy = the registered digest | sha256 of the working copy (prefix) | Withheld |
|---|---|---|---|---|---|
| `E10B_DESIGN.md` | e10b_preregistration.json `design.file` | 2026-10-26T04:55:14Z | yes | 47fa01f3c076 | 4 part(s) withheld |
| `E10_ADDENDUM_R5.md` | e10_preregistration.json `addendum_review_r5.file` | 2026-10-16T15:32:21Z | yes | 9709aa4a5db4 | 3 part(s) withheld |
| `E10_DESIGN.md` | e10_preregistration.json `design.file` | 2026-10-16T15:32:24Z | yes | 137f8a5d0a8c | 5 part(s) withheld |
| `E10_RESULTS_NOTES.md` | e10b_preregistration.json `rationale`; e10b_preregistration.json `relation_to_e10.e10_results_notes.file` | 2026-10-24T16:39:19Z | yes | 03fd59c453d7 | none |
| `E11_DECISIONS.md` | e11_preregistration.json `amendments_before_registration.log` | 2026-10-24T15:06:44Z | no (registered 7602d0c74c61) | b6a371ed4320 | none |
| `E11_DESIGN.md` | e11_preregistration.json `design.file` | 2026-10-14T05:51:23Z | yes | 9d021130c7b1 | 5 part(s) withheld |
| `E12_DESIGN.md` | e12_preregistration.json `design.file` | 2026-10-16T15:33:05Z | yes | 3ef17eb0c7d2 | none |

Masked and withheld as above (`reproduce/SANITIZED_r16.json`, `docs` and `docs_rules`). In addition, the names of other projects that shared the machine are replaced by generic words in `E10B_DESIGN.md` and `E11_DECISIONS.md`. Passages that describe how the E10 in-hub adversary, the E10b add-on or E11's instrument bundle is built (internal function names, the calls they make, a defect and its fix, how the add-on installs its clock), the instrument's code-level calls in E11's arms table, the SQL of one closure mutation and how the fixture bundle submits its writes are replaced in place by a line beginning "[Withheld from the artifact:". The arms themselves, their parameters, counts and predictions are in the registrations, which are released. Paths on the external research volume (`/Volumes/...`) carry no user name and are not rewritten.

Cited but not here: `FORMAL_DRAFT.md` (the draft of the paper's formal model (manuscript material; the paper's appendix is its form)); `R14C_ANALYSIS_NOTES.md` (describes the attack integrations' code line by line (which rows each arm deletes or updates); the round-14c result files carry its numbers); `SP2027_ACCEPT_PLAN.md` (the paper's earlier plan (manuscript folder, venue and decision log)); `TDSC_PLAN.md` (the paper's plan (manuscript folder, venue and decision log)); `TRIAGE_R4.md` (the triage of an internal review round (internal reviews are not released, as in round 14)). Also not here: the results notes that no registration cites (`E9_RESULTS_NOTES.md`, `E9_ANALYSIS_PLAN.md`, `E10B_RESULTS_NOTES.md`, `E11_RESULTS_NOTES.md`, `E12_RESULTS_NOTES.md`), the registration drafts (`E10_PREREG_DRAFT.json` and the others; their final forms are in `exp/out/`), the run directories under `HOMEPROV-P13-exp/` and the external research volume, and the components named in the README's "What is deliberately not here".
