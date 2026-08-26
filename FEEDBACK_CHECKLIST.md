# Mock-review compliance checklist

Tracks every actionable item in
`manuscripts/feedback/homeprov_sp2027_comprehensive_mock_review.md` (2,548 lines)
against what has actually been done. Verified by inspection on 2026-08-25, not
from memory.

**Legend:** `[x]` done and verified · `[~]` partial · `[ ]` not done ·
`[-]` excluded by PI scope decision

**Updated 2026-08-25, third pass. Every actionable item is closed.** 61 done,
1 partial, 0 not done, 6 excluded by PI scope.

The two entries that are not `[x]`: Q8 generator transfer is bounded rather than
answered, because validating the generator against a real household trace is
impossible under the project's resource constraints, and the paper states that as
a limitation; Q9 and Q15 map to E7 and E21, which the PI excluded.

**The session's most consequential finding.** E4 measured the renderer dependency
closure and it exposed three consumed fields that the paper's own recommended
commitment scheme omits, plus two attack classes it misses 0/12 that the closure
scheme catches 12/12. Recorded as `dec_01M0W9661FWX0GE20T3VD98S6W`, **awaiting PI
ratification**: it revises the concrete scheme attached to contribution C3. The
design and evaluation sections have been written to the proposed option so they
are mutually consistent; reverting is a localized edit if the PI decides
otherwise.

**A tension worth the PI's attention.** E5 (renderer-backed, 440 instances) finds
that two single-primitive attacks reach misattribution at 0.50 against the
renderer, while E9 (systematic search) finds nothing plausible at four primitives
against an oracle that also applies the semantic invariants. Composition is
essential against the predeclared catalogue and against a plausibility-aware
oracle, and not essential against renderer output alone. §7 states this rather
than smoothing it.

Manuscript: 19 pages, body ends p13 (limit 13), references and appendix beyond.
Gates: compile 0 errors, provenance 0 BLOCK, citations PASS, ai-tic 0 BLOCK/0 WARN.
The P0 items are all closed and the thesis survived re-centring. The bulk of
what remains is section 8 (writing and definitions) and the live-platform
experiments E4/E5/E6.

---

## Reviewer 1 — systems security / threat model (§3)

- [x] **3.1 Trusted observation path compromised.** Option A taken: commitment
      moved out of the hub interpreter into an external monitor. E2 verified the
      subversion, then verified the fix detects it. `jrn_01M0TT14JJRFV02N6GVN2SS9CS`
- [x] **3.2 Attack before next anchor.** E1 measured; paper states the window.
- [x] **3.3 Secret anchoring schedule.** Removed. Capability record v2 sets
      `anchor_schedule_known: true`; §3 states the adversary shares an interpreter
      with whatever schedules anchoring and the E1 exposure results assume it.
- [x] **3.4 Anchor key.** Removed entirely. There is no anchor key; the guarantee
      rests on append-only and container isolation, not a secret the hub holds.
      `rebind_in_process_symbols: true` added as a declared power.
- [x] **3.5 Append-only API semantics.** Appendix: record format (nine fields)
      plus a five-rule acceptance policy — segment identity, sequence
      monotonicity, conflicting roots retained as evidence, chain continuity,
      future segments rejected — and two marker rules. Flooding is named as an
      undischarged deployment obligation rather than claimed safe.

## Reviewer 2 — novelty / crypto / provenance (§4)

- [x] **4.1 B2 too weak.** Confirmed and reported as a refutation.
- [x] **4.2a B2a content-only baseline** (the original B2, now reported as a strawman)
- [x] **4.2b B2b full physical-row baseline** — refutes the headline
- [x] **4.2c B2c renderer-closure baseline.** Stage 31. Identical to B2b and Row
      on all twelve predeclared classes, so the negative result stands; the only
      scheme that detects the two classes E4 exposed (1.000 vs 0.000 for every
      other scheme, including our own recommendation).
- [x] **4.3 Secure-provenance prior art.** Reorganised by security assumption;
      dedicated subsections on authenticated provenance/causal structure and on
      verifiable causal investigation, each distinguishing this setting by
      adversary model and deployment.
- [x] **4.4 Formal terminology deserves proofs.** E14 appendix: 13 definitions,
      3 assumptions, 6 theorems.

## Reviewer 3 — experimental methodology (§5)

- [x] **5.1 Renderer-backed result is n=1** → E5: 440 instances across twelve
      variants and forty targets against the live logbook processor. Still one
      home configuration, stated as such.
- [x] **5.2 One Home Assistant renderer version** → E6 done (static arm across four
      releases); the limitation now states exactly what the static instrument does
      and does not establish.
- [x] **5.3 Generator mismatch** → E15 done; measured fraction now used in E18.
- [x] **5.4 Holdout framed as internal.** Retitled "generator-family holdout" and
      states explicitly that it establishes no overfitting to the tuning
      deployments and nothing about real homes or other deployment families.
- [x] **5.5 "Pi-class" wording.** The phrase no longer appears; the substrate is
      described as a Pi-shaped cgroup envelope, which is what it is.
- [x] **5.6 Scale stops below target** → E18 reached 10^7.
- [x] **5.7 FT-6 must be root-caused** → E16: node-identity omission, fixed.

---

## Experiments E1–E23

| # | Experiment | State | Evidence |
|---|---|---|---|
| E1 | Pre-anchor timing window | `[x]` | latency p50 1.77s; P(undetected) 0.975@0.5s → 0@10s |
| E2 | In-process defender subversion | `[x]` | subverted, then fixed and re-verified |
| E3 | Strong full-row baselines | `[x]` | B2a+B2b+B2c, 5 schemes x 12 classes x 12 deployments + cost |
| E4 | Renderer dependency closure | `[x]` | 14 attribution-relevant fields on 2026.7.4; static + mutation with positive control |
| E5 | Large renderer-backed evaluation | `[x]` | 440 renderer-backed instances, 12 variants x 40 targets; misattribution 0.159 |
| E6 | Cross-version Home Assistant | `[x]` | closure identical across 2024.12.5 / 2026.6.4 / 2026.7.4 / 2026.8.3 (static arm) |
| E7 | Database backend diversity | `[-]` | excluded by PI scope |
| E8 | Attack-budget robustness | `[x]` | 3 budget models; atomic classes at the composition's full budget: 0/12 severe |
| E9 | Minimum-cost laundering search | `[x]` | 6,741 sequences/deployment; 1 row vs attribution, nothing vs plausibility |
| E10 | Lifecycle-marker abuse | `[x]` | stage 29: 11 cases x 4 deployments. All abuse fails; honoured purge costs 51% of history |
| E11 | Graph fuzzing | `[x]` | 400 trials, 15 classes; 1 open failure (dup context) |
| E12 | Reconstruction baselines | `[x]` | 6 policies; +8% vs causal component |
| E13 | Exhaustive small-graph | `[x]` | 480 instances, sound 480/480 |
| E14 | Formal proofs | `[x]` | appendix A |
| E15 | Generator sensitivity | `[x]` | only bg_ratio moves parent fraction |
| E16 | FT-6 root cause | `[x]` | node identity omitted; fixed |
| E17 | Independent workload family | `[-]` | excluded by PI scope |
| E18 | Scale to 10^7 | `[x]` | 10M nodes, 141k nodes/s, 285MB RSS |
| E19 | Macro performance under load | `[-]` | excluded by PI scope |
| E20 | Resource-envelope sensitivity | `[-]` | excluded by PI scope; the §5.5 wording fix it owed is done (`Pi-class` appears nowhere) |
| E21 | Crash consistency / anchor durability | `[-]` | excluded by PI scope |
| E22 | Anchor protocol attack matrix | `[x]` | append-only holds; 4 weaknesses found |
| E23 | Detection-window cost curve | `[x]` | 9 periods; W = P/2; duty flat ≥1s |

---

## §8 Writing and framing revisions

- [x] **8.1 Introduce "HomeProv" immediately.** Named in the abstract and in a
      dedicated first-page paragraph describing the three components.
- [x] **8.2 Novelty reframed** to the review's framing: the same hub process both
      generates the provenance and runs untrusted extensions with write access to
      the evidence store, so the problem is a trustworthy commitment boundary
      outside a compromised producer, plus recovery after partial tampering.
- [x] **8.3 Careful with "physical actuation."** Phrase does not appear.
- [x] **8.4 Define the guarantee near the beginning.** The review's exact form is
      now in both the abstract and the first page.
- [x] **8.5 Reduce rhetorical language.** Both flagged phrases removed.
- [x] **8.6 Threat timeline.** Table in §3 giving t0–t6 and what is detectable at
      each, with the three claims it rules out spelled out.
- [x] **8.7 Precisely define `content(v)`.** §2.2 gives the exact canonical
      encoding field by field, and states explicitly which columns it excludes.
- [x] **8.8 Edge label `ℓ(v)`.** Defined as derived, with source, domain and
      full value mapping.
- [x] **8.9 Segment-root construction.** §2.3 covers ordering and tie-breaking,
      the fold, count commitment, domain separators, missing parents, duplicates,
      and cross-segment edges.
- [x] **8.10 Name the five scenarios.** Table added: S1 Laundered Unlock, S2
      Agent's Alibi, S3 Segment Substitution, S4 Early Arrival, S5 Anchor
      Compromise, with why each is included.
- [x] **8.11 All twelve forgery classes.** Full-width table with severity,
      mutation, fields changed, renderer effect, class and detection rate.
- [x] **8.12 All benign catalogue entries.** Table of all eleven with expected
      discontinuity, marker type, arm and trial count.
- [x] **8.13 Explain FT-6 in the main text.** Done via E16.
- [x] **8.14 Clarify statistical units.** Unit of analysis and the
      generated-vs-world distinction stated; budget recorded in three units
      (rows, SQL statements, wall-clock); post-predeclaration classes are
      reported in a separate table and explicitly never pooled with the
      catalogue rates.

## §9 Related work rewrite strategy

- [x] Reorganised by security assumption and integrity object. Subsections:
      tamper-evident logging · trigger-action integrity · authenticated provenance
      and causal structure · verifiable causal investigation and the root of trust ·
      IoT/smart-home forensics · provenance IDS. Comparison table extended to the
      review's seven columns (producer compromised? store writable? detects edge
      rewrite? partial reconstruction?) and moved to the appendix for width.

## §10 Formal security model

- [x] Appendix A now has a Trust boundary subsection: explicit trusted and
      untrusted component lists, plus the post-commit integrity property stated
      formally with an explicit note on what the quantifier placement excludes.

## §11 Revised contribution structure

- [x] Restated in the review's five-contribution form: attack characterization ·
      trusted commitment boundary · causal provenance commitment (with the
      negative result) · sound partial reconstruction · empirical validation.

## §12 Evaluation organisation by RQ

- [x] Evaluation opens with an RQ1–RQ6 roadmap and every subsection is tagged
      with the questions it serves. Subsection titles keep the finding rather than
      being replaced by bare RQ labels.

## §13 Ethics and disclosure

- [x] Disclosure status stated exactly: maintainers not contacted, no
      acknowledgement, no tracking issue, no advisory, with both reasons (it is
      the documented extension model rather than a patchable defect, and outbound
      contact needs authorization that has not been given) and the intent to open
      a public design discussion before camera-ready.

## §14 Artifact evaluation strategy

- [x] Itemised release list and the sanitised-harness policy are both written
      out. Enforced in practice: the public repository excludes the adversary
      integrations, credentials, recorder databases and third-party paper text.

## §15 Rebuttal questions (15)

- [x] Q1 in-process subversion · Q2 why baseline omitted the column ·
      Q4 laundering before next anchor · Q6 conflicting appends ·
      Q7 FT-6 · Q12 quarantine soundness · Q13 voiding baseline ·
      Q14 physical vs recorded
- [x] Q5 secret anchor schedule (assumption removed, §3) ·
      Q11 exact fields influencing attribution (E4, closure table)
- [x] Q3 novelty vs secure provenance DAGs (§9 restructure + intro reframing)
- [~] Q8 generator transfer (bounded by the fidelity limitation; no real trace
      is obtainable under the project's resource constraints)
- [x] Q10 current HA releases (E6, four releases)
- [-] Q9 PostgreSQL/MariaDB · Q15 anchor crash / duplicate retry. Both map to
      experiments (E7, E21) the PI excluded from scope; the paper says so rather
      than answering them.

---

## Work order for the remainder

Cheap and high-value, do first:
1. §8.5 rhetorical language · §8.1 name the system · §5.5 "Pi-class" wording
2. §8.7 `content(v)` (mandatory) · §8.8 `ℓ(v)` · §8.9 segment-root
3. §8.10 scenarios · §8.11 forgery table · §8.12 benign catalogue
4. §3.3 / §3.4 remove secret-schedule and anchor-key assumptions
5. **E10 lifecycle-marker abuse** (P1, never run)
6. §8.6 threat timeline · §10 trusted/untrusted lists

Done this pass: E10, E4 (P0), E3-B2c (P0), §8.14, §5.5, §3.3, §3.4, §8.1,
§8.4, §8.5, §8.7--§8.13, plus a page-limit recovery (catalogues moved to the
appendix, four limitation paragraphs consolidated).

Remaining, in order:
7. **PI ratification of `dec_01M0W9661FWX0GE20T3VD98S6W`** (B2c as the
   recommended scheme). Blocks binding the revised C3 claim version.
8. §12 RQ reorganisation · §11 contribution restructure · §9 related-work
   restructure by security assumption · §10 trusted/untrusted lists
9. E6 cross-version HA — now higher value than before, because E4 established
   that the closure is a per-release property and E6 is what tests its stability
10. E5 large renderer-backed, E8 attack-budget models, E9 minimum-laundering
11. §8.6 threat timeline (needs a page trade) · §3.5 full protocol semantics ·
    §5.4 holdout framing
12. §13 disclosure concreteness · §14 artifact list
