# HOMEPROV — Detailed Technical Research Design

**Project** `prj_01M0E264P0Q0KKHCG51YEXS8H4` · **Manuscript** `man_01M0E2K141EC0EEKZ2WBTKEP8N`
**Venue** IEEE S&P 2027 Cycle 2 (inferred from RKA manuscript record; security venue confirmed by the
adversarial reframe — the descriptive contribution belonged at a systems venue and no longer exists)
**Thrusts** 2 (one measurement, one hypothesis) + 1 supporting infrastructure thrust
**Constraint (PI, `dec_01M0EE5RQP5E2HETFZWPZQT7H7`)** — self-contained only: open-source software,
local Docker, no hardware beyond a MacBook Pro M4 24GB, **no request or email to any person or
organisation for access to resources**. No third-party service, no transparency log, no timestamping
authority, no TPM/HSM, no Pi acquisition.

**Written** 2026-08-19 · **Substrate** native aarch64 Docker under a Pi-shaped cgroup envelope
(no hardware; revised from QEMU after host measurement — `dec_01M0EAA37PJJFGXHV4V2CPJRAV`)

---

## Status and discipline

**Read this before any number in this document is quoted anywhere.**

*Every quantity stated in this design is a **target**, not a finding* — **with one exception, added
2026-08-19 after M1 closed: the §10.1 flagship trace, its forgery step-table, its
$\mathrm{CE}_7 = 1$ enumeration, and the §11.1 substrate measurements ARE MEASURED RESULTS.** They
are labelled MEASURED wherever they appear. Everything else remains a target.
The rest of the record is the RKA graph. Where RKA contains an assertion
derived from the sibling project HOMEGRAFT (`prj_01KY1J5KE6AYQ6MKATNJ29W1QC`) — specifically that
HACS integrations execute as first-class Python inside the Home Assistant core process — that is
marked **measured fact from a sibling project**, and is *directional for HOMEPROV* until re-verified
under this design's own substrate (Stage 0). Everything else is a hypothesis.

**Thrust A is a measurement study. Thrust B is a hypothesis under test.**

- **Act I (Thrust A) is the paper's floor.** It measures whether, and how, Home Assistant 2026.7's
  causal timeline can be rewritten from ordinary in-process integration privilege. It stands as a
  publishable result even if every defensive component of this project fails.
- **Act II (Thrust B) is the paper's ceiling.** It tests the hypothesis that a partially forged
  causal provenance graph admits *sound, tightly localized* reconstruction — that an investigator
  gets a defensible partial account rather than a binary "log is void."
- **Thrust C (anchor placement) is infrastructure for Act II** plus one standalone measurement:
  the detection window as a function of anchoring frequency.

**The gate is M1** (`mis_01M0E29N6GVECW5N1E1WSRT1JM`). **Build nothing below the gate until it
resolves.** Its three exits and the paper each writes are in §13.

**Predeclaration.** The forgery taxonomy (§9.1), the severity classes (§9.2), the benign-event
catalog (§9.3), the statistical contrast set (§11.5), and every success threshold are declared here,
**before** any run. This is deliberate: it is what stops "damage," "detection," and "plausible" from
being defined after the fact to match whatever the prototype happened to achieve.

**Guarantee discipline, inherited from `dec_01M0E28ZS3MY8SP1F8PQ3YQQGR` and not to be relaxed
anywhere in this document or the manuscript:** HOMEPROV claims **tamper-evidence, not
tamper-prevention**. An adversary holding hub privilege can halt future logging, corrupt the
database, or destroy the device. What it cannot do is *silently rewrite history that has already been
anchored*. Every guarantee statement in §5.9 is followed by its non-guarantees in §5.10.

**Boundary discipline, inherited from `dec_01M0E28ZS8AZCF4R5P8WJM9GXD`:** HOMEPROV does **not** claim
hash chaining, forward-secure logging, or Merkle audit trails as contributions. Those are decades
old. In this design that boundary is not a rhetorical paragraph — it is **baseline B2** (§11.3), a
strong out-of-process record-level tamper-evident log that HOMEPROV must beat on two named metrics or
there is no paper.

---

## Spine (one line)

> Home automation platforms now tell you *who caused* a physical actuation, and compute that answer
> from a database any installed integration can rewrite — so HOMEPROV makes the **causal graph**, not
> the record, the object of integrity, and asks what an investigator can still soundly conclude once
> part of that graph has been forged.

## Spine (thesis)

HOMEPROV asserts three things, in dependency order.

**(A) — The exposure is real and structural, not incidental.**
Home Assistant 2026.7 shipped causal attribution: person avatar for manual action, trigger shown for
automation, integration icon for integration-originated action. It is a UI over the recorder
database. A custom integration — the ordinary, sanctioned extension mechanism, installed by millions
through HACS — executes as first-class Python inside the core process with unmediated access to that
database. Therefore the attribution the platform now displays is computed over a substrate the
attacker controls. Thrust A measures exactly what that buys an adversary.

**(B) — The object of integrity is the graph, and that is what generic audit logging does not
protect.**
Home automation does not produce a linear log. It produces a causal graph: a principal or agent
triggers a rule, the rule evaluates conditions, invokes an integration, the integration actuates a
device, the device state change triggers another rule. Record-level tamper-evidence — even
state-of-the-art, even correctly anchored out-of-process — detects that a *record* changed. It does
not detect that an *edge* was re-pointed, because re-parenting need not alter any record's own
content. An adversary that re-parents the causal edge from its own service call onto an innocent
automation's action node produces a graph in which every record is authentic and the attribution is
a lie. HOMEPROV binds edges into the commitment so that the causal structure itself is what is
committed.

**(C) — The novel technical core is graceful degradation, not detection.**
Detection is table stakes. The forensically interesting question begins *after* detection: which
subgraph is still trustworthy? Generic tamper-evident logging answers "none" — a single broken link
voids the log. That is a binary alarm, not a forensic tool. HOMEPROV chooses a **laminar** (nested,
multi-granularity) commitment topology specifically so that minimum-quarantine localization is both
*tractable* (§1.7, Proposition 2) and *tight* (§1.6, metric OQ), yielding a trust-annotated partial
account with explicit abstention where the evidence does not reach.

**Structural analogy, used for shape only.** The composed forgery of §10.1 has the shape of a
**laundering** chain — value (here, blame) is moved through intermediaries until its origin is
unrecoverable from the record. We use the word for the *shape of the mechanism* and for nothing else.
We are **not** claiming a formal correspondence with financial-crime laundering models, we are **not**
importing any detection technique from that literature, and no result in this design depends on the
analogy holding. A second, weaker analogy: edge re-parenting is *TOCTOU-shaped* only in that the
record and its causal interpretation are checked at different times by different components — we
claim no TOCTOU race, no concurrency argument, and no reuse of TOCTOU defenses.

---

## 1. Problem statement and formal model

### 1.1 Informal problem

A homeowner opens the Home Assistant timeline and sees "Front door unlocked, 03:14, by Automation:
Arrive Home, triggered by Presence: Owner phone." That sentence is the platform's answer to the
forensic question, and it is computed by joining rows in a SQLite database that sits on the hub's
filesystem, writable by every integration the user has ever installed. A malicious integration that
unlocked the door itself can delete its own service-call record, re-point the lock's state-change
record onto the innocent automation, and inject a presence event to make that automation's firing at
03:14 explicable. Each step is an ordinary database write. The resulting timeline is internally
consistent, renders without complaint, and is false. The question this project answers is: what
integrity structure makes that forgery *evident*, at what cost on a hub-class device, and — once
evident — how much of the surrounding history remains soundly usable as evidence.

### 1.2 State spaces and the objects that move

Let a deployment $H$ consist of an entity set $\mathcal{E}$ partitioned into

$$\mathcal{E} \;=\; \mathcal{E}_{dev} \;\uplus\; \mathcal{E}_{aut} \;\uplus\; \mathcal{E}_{int} \;\uplus\; \mathcal{E}_{prin}$$

(devices, automations, integrations, principals — persons and agents). The hub state space is
$\Sigma = \prod_{e \in \mathcal{E}} S_e$, with $\sigma_t \in \Sigma$ the state at time $t$.

The object that moves is the **actuation-provenance graph**

$$G \;=\; (V, A), \qquad A \subseteq V \times V \times L$$

a time-ordered directed acyclic graph. Each $v \in V$ is a provenance node with type
$\text{ty}(v) \in \{\pi, \tau, \kappa, \alpha, \delta\}$:

| type | meaning |
|---|---|
| $\pi$ | principal act — a person, agent, or integration originating an action |
| $\tau$ | trigger firing |
| $\kappa$ | condition evaluation (with outcome) |
| $\alpha$ | action / service call |
| $\delta$ | device state change (the physical actuation's record) |

Each node carries $\text{content}(v) = \langle \text{ty}(v), t(v), \text{ent}(v), \text{payload}(v)\rangle$.
Edge labels $L = \{\textsf{triggers}, \textsf{evaluates}, \textsf{invokes}, \textsf{actuates}, \textsf{causes}\}$.

$G$ is *materialized* in the recorder database $D$; the timeline UI is a rendering $\text{UI}(D)$.
Write $G(D)$ for the graph recoverable from a database state. The platform's attribution function is

$$\mathrm{Attr}_G(\alpha) \;=\; \text{the } \pi\text{-node at the root of the causal ancestry of } \alpha \text{ in } G$$

taking value $\bot$ ("unknown") when no $\pi$-ancestor exists. **$\mathrm{Attr}$ is the thing the
adversary attacks and the thing HOMEPROV protects.** Everything else in this design is machinery in
service of $\mathrm{Attr}$.

### 1.3 The actor as a constrained function

The adversary $\mathcal{A}$ is a malicious custom integration, compromised at time $t_c$, modelled as

$$\mathcal{A}\;:\;(G,\,C)\;\longmapsto\;G'$$

where $C$ is its **capability record** (§2.3 — the machine-readable object shipped with every result).
$\mathcal{A}$ is *constrained*, and the constraints are the design's load-bearing assumptions. They
are listed here so that a reviewer can attack them directly:

- **(F1) Reach.** $\mathcal{A}$ may read and write any row of $D$, read and write the filesystem as
  the `homeassistant` uid, execute arbitrary Python in the core process, register event-bus
  listeners, and call any service. It may modify any part of $G(D)$ still resident in $D$,
  irrespective of timestamp.
- **(F2) Plausibility.** $\mathcal{A}$'s output must satisfy $\mathrm{Plaus}(G') = 1$: it must render
  in the HA 2026.7 timeline without error, satisfy the recorder's schema and foreign-key
  constraints, and violate no *semantic invariant* of the deployment (§9.4 lists the invariants —
  e.g. a lock cannot transition `locked → locked`; an automation cannot act while `disabled`; a
  presence event cannot originate from a device that was `unavailable`). An implausible forgery is a
  detected forgery for free and is not interesting.
- **(F3) Budget.** $\mathcal{A}$ is charged $b(\mathcal{A})$ = number of database write operations,
  and is bounded by a wall-clock window $\omega$ before the next anchor. **$b$ is the headline
  budget** — see §5.7 for why.
- **(F4) Non-capabilities (predeclared).** $\mathcal{A}$ does **not** hold: root on the host; the
  ability to write files owned by a different uid when POSIX permissions forbid it; the anchor
  daemon's signing key; the ability to retract an external anchor already published; the ability to
  modify the host clock (this is *deliberately* excluded and revisited as a lifted assumption in
  §7.6). Anything absent from $C$ **was not assumed**.

The **reachable set** from a true graph $G$ under budget $b$ is

$$\mathcal{R}_b(G) \;=\; \{\,G' : \exists\,\mathcal{A} \text{ satisfying F1–F4},\; \mathcal{A}(G,C)=G',\; b(\mathcal{A}) \le b,\; \mathrm{Plaus}(G')=1 \,\}$$

### 1.4 Forgery classes, and the distinguishing formal device

Three atomic forgery classes, predeclared (full catalog in §9.1):

$$F_{del}: \text{delete node(s) and incident edges} \qquad
  F_{rep}: \text{re-point edge endpoints} \qquad
  F_{inj}: \text{insert fabricated node(s)/edge(s)}$$

Write $\mathcal{R}^{i}_b(G)$ for the reachable set using **only** class $i$ within budget $b$.

The whole non-triviality of Thrust A rests on one definition. A forgery that any single class already
achieves teaches nothing; the claim worth defending is that some re-attributions are reachable **only
by composition**. Define the **composition-essential indicator**, for a true graph $G$, a forged
graph $G'$, an actuation $\alpha$, and a budget $b$:

$$
\mathrm{CE}_b(G,G',\alpha) \;=\;
\begin{cases}
1 & \text{if } \mathrm{Attr}_{G'}(\alpha) \neq \mathrm{Attr}_{G}(\alpha)
      \;\wedge\; \mathrm{Plaus}(G')=1 \\
  & \quad \wedge\;\; \forall i \in \{del, rep, inj\}\;\;
      \nexists\, G'' \in \mathcal{R}^{i}_b(G) \;\text{ with }\;
      \mathrm{Attr}_{G''}(\alpha) = \mathrm{Attr}_{G'}(\alpha) \\[2pt]
0 & \text{otherwise}
\end{cases}
$$

$\mathrm{CE}_b = 1$ **exactly when** the achieved, plausible re-attribution is unreachable by any
single forgery class at the *same budget*. The budget subscript is not decoration: without it,
"composition wins" degenerates into "composition spent more writes." $\mathrm{CE}$ is decided by
algorithm **A10 `CE-CHECK`** (§5.8), which is exact by enumeration at the scales we run it.

### 1.5 The novel mechanism, formalized

We name the mechanism **causal laundering** and state it as an existential, not a description.

> **Claim CL (∃-statement, under test in Thrust A).**
> There exist a Home Assistant 2026.7 deployment $H$, a true provenance graph $G$ arising from $H$'s
> ordinary operation, an actuation $\alpha \in V$ with true attribution
> $\mathrm{Attr}_G(\alpha) = \pi_{\text{mal}}$ (a malicious integration), a write budget $b$
> achievable within one inter-anchor window, and a composed adversary
> $\mathcal{A}^\ast = F_{inj} \circ F_{rep} \circ F_{del}$ satisfying F1–F4, such that
> $G' = \mathcal{A}^\ast(G,C)$ has
>
> 1. $\mathrm{Attr}_{G'}(\alpha) = \pi_{\text{inn}} \neq \pi_{\text{mal}}$ — blame lands on a named
>    innocent principal, not merely on $\bot$;
> 2. $\mathrm{Plaus}(G') = 1$ — it renders cleanly in the stock 2026.7 timeline and violates no
>    semantic invariant of §9.4;
> 3. $\mathrm{CE}_b(G,G',\alpha) = 1$ — no single forgery class reaches that attribution at budget $b$.

Condition (1) is what separates causal laundering from vandalism. Deleting evidence yields $\bot$
("unknown cause"), which is *suspicious*. Laundering yields a named, innocent, plausible cause, which
is *not*. **Claim CL is the specific thing the gate tests.** If CL is false — if the timeline is
forgeable only into $\bot$, or only atomically — the paper narrows (Exit 2, §13).

### 1.6 The metric instrument

Six metrics. Each is defined here, before it appears in any scenario (§10) or evaluation stage (§11).
Let $T \subseteq V \cup A$ be the ground-truth tampered set (available only at observability level L4,
§2.2 — an oracle for evaluation, never to any algorithm), and let $Q$ be the set HOMEPROV
**quarantines** (declares unverifiable).

| # | Metric | Definition | Direction |
|---|---|---|---|
| M1 | **TDR** — tamper detection rate | $\Pr[\,\text{VERIFY reports violation} \mid T \neq \emptyset\,]$ | ↑ |
| M2 | **LP** — localization precision | $\lvert Q \cap T\rvert / \lvert Q\rvert$ | ↑ |
| M3 | **LR** — localization recall | $\lvert Q \cap T\rvert / \lvert T\rvert$ | ↑ (**must be 1**, see below) |
| M4 | **OQ** — over-quarantine ratio | $\lvert Q \setminus T\rvert \,/\, \lvert V \cup A\rvert$ | ↓ |
| M5 | **RA** — reconstruction accuracy | fraction of actuations in $V\setminus Q$ with $\mathrm{Attr}$ reported correctly | ↑ |
| M6 | **BFP** — benign false-positive rate | $\Pr[\,\text{VERIFY reports violation} \mid T = \emptyset\,]$ over the §9.3 benign catalog | ↓ |

**M4 (OQ) is the headline metric of the paper.** It is precisely where generic tamper-evident
logging fails: baseline B3 (whole-log-void) has $\mathrm{OQ} \to 1$ by construction. A design that
detects perfectly and quarantines everything has produced an alarm, not evidence. OQ is the number
that has to be small.

**LR = 1 is a soundness requirement, not a target.** If any genuinely tampered element escapes the
quarantine set, HOMEPROV will report an attribution computed over forged data — the unsound failure
mode. LR < 1 in any run is a **design defect**, not a poor score, and triggers the checkpoint in §7.3.

**Conditionals that localize failure.** Reporting only end-to-end RA would leave a failure
unattributable. We therefore decompose:

$$\underbrace{\mathrm{RA}_{\text{e2e}}}_{\text{what an investigator gets}}
\;=\;
\underbrace{\Pr[\text{detect}]}_{\text{M1: anchor}}
\;\times\;
\underbrace{\Pr[\text{LR}=1 \mid \text{detect}]}_{\text{M3: localizer soundness}}
\;\times\;
\underbrace{\Pr[\text{correct} \mid \text{LR}=1]}_{\text{M5: reconstructor}}$$

A drop in $\mathrm{RA}_{\text{e2e}}$ is thereby assigned to the **anchor**, the **localizer**, or the
**reconstructor**, never left ambiguous.

**Breakdown of misses into meaningfully different kinds.** Not all failures are equal, and collapsing
them would hide the only one that matters:

| Miss kind | Condition | Severity |
|---|---|---|
| **Miss-D** | forgery undetected ($\mathrm{TDR}$ miss) | high — anchor failed |
| **Miss-L** | detected, but $\mathrm{LR}<1$ | **critical** — unsound; forged data enters the account |
| **Miss-R-assert** | detected, $\mathrm{LR}=1$, but reconstruction **asserts a wrong attribution** | **critical** — confidently wrong forensics |
| **Miss-R-abstain** | detected, $\mathrm{LR}=1$, reconstruction **declines to attribute** | **not a failure of soundness** — a loss of completeness only |

The distinction between **abstain** and **assert-wrong** is the analogue of "resisted" versus
"failed-to-complete," and it is the axis on which HOMEPROV's guarantee lives:

> **Soundness** = HOMEPROV never asserts an attribution it cannot support (Miss-R-assert $= 0$).
> **Completeness** = HOMEPROV rarely abstains (Miss-R-abstain small).
> **HOMEPROV claims soundness and measures completeness.** A design that abstains everywhere is
> trivially sound and useless; OQ and Miss-R-abstain are what stop us claiming victory that way.

### 1.7 Tractability — the hard problem, named and bounded

**The genuinely hard problem, stated honestly.** Deciding, from a database state $D$ alone, whether
$G(D)$ is the true history is **not merely intractable — it is impossible**. An adversary with F1
reach can fabricate any internally consistent history; no function of $D$ distinguishes it from the
truth. This is not a weakness of our algorithm; it is why *anchoring outside the adversary's reach is
the whole design*.

> **CORRECTED 2026-08-20, after AB-1 was executed.** This section previously claimed
> **Prop 1** (MIN-QUARANTINE is NP-hard by reduction from MINIMUM HITTING SET) and **Prop 2**
> (laminarity makes it exactly greedy-solvable). **Both were built on the wrong objective, and AB-1
> falsified Prop 2 exactly as it was predeclared to.** They are replaced below. The original claims
> are retained here, struck through, because a design that quietly edits its own falsified
> propositions is not a design.
>
> ~~Prop 1: MIN-QUARANTINE is NP-hard via MINIMUM HITTING SET.~~
> ~~Prop 2: under a laminar family it is exactly greedy-solvable in $O(n\log n)$.~~

**Why the hitting-set objective is wrong — measured counterexample.** Minimum-cardinality hitting set
answers *"what is the smallest set whose removal makes the commitments verify again?"* That restores
**consistency**. The forensic question is *"which elements can I still trust?"*, which demands
$Q \supseteq T$. With three elements tampered inside one second-segment:

| localizer | $\lvert Q\rvert$ | LR | verdict |
|---|---|---|---|
| A6 greedy — quarantine the whole violated segment | 393 | **1.000** | **SOUND** |
| A5 exact ILP — minimum hitting set | 1 | **0.000** | **UNSOUND** — selected an *untampered* element and missed all three |

The ILP satisfied every commitment while identifying nothing. An aggregate segment accumulator gives
**no intra-segment discrimination**: if a segment disagrees, any element inside it could be the
altered one, so excluding any of them risks admitting forged data into the account — a violation of
the hard soundness gate.

> **Proposition A (sound quarantine).** The union of the **innermost** violated segments satisfies
> $Q \supseteq T$ **by construction**, because A2 commits every node at every granularity, so any
> tampered element lies inside some violated segment.
>
> **Proposition B (minimality among sound quarantines).** No sound quarantine derivable from
> segment-level evidence is smaller. Excluding any element of a violated segment forfeits the
> $Q \supseteq T$ guarantee, since the commitment is aggregate over the segment.
>
> **Proposition C (cost).** The sound quarantine is computable in $O(n\log n)$ by A6's interval
> sweep, and $\lvert Q\rvert$ is bounded by **segment occupancy**, not by history length — confirming
> guarantee G-3. Laminar nesting is precisely what makes the innermost violated segment small, so
> **nesting is what minimizes OQ**.

This is a stronger position than the original: the propositions are now true, provable from the
construction, and tied directly to the soundness gate — rather than an NP-hardness claim about a
problem the system does not solve.

**Consequences for the evaluation.** The ILP is **retained but re-cast as a diagnostic** that
demonstrates why consistency-restoration is unsound; it is no longer ground truth. **AB-1's question
becomes** "is the greedy quarantine minimal among *sound* quarantines?", not "does greedy equal the
ILP?". OQ is a function of **event rate** (via occupancy), which the §11.2 deployment sweep already
varies — so OQ must be reported against event rate as well as against event age.

**Exact at small scale, heuristic at large.** A6 is exact for the sound objective at every scale, so
no scenario result depends on an approximation. Its cost is bounded by segment occupancy.

### 1.8 Notation summary

| Symbol | Meaning |
|---|---|
| $H$ | a deployment (entities, automations, integrations, principals) |
| $\mathcal{E}_{dev},\mathcal{E}_{aut},\mathcal{E}_{int},\mathcal{E}_{prin}$ | device / automation / integration / principal entities |
| $\Sigma,\ \sigma_t$ | hub state space; state at time $t$ |
| $G=(V,A)$ | actuation-provenance graph; nodes and labelled causal edges |
| $\text{ty}(v)\in\{\pi,\tau,\kappa,\alpha,\delta\}$ | node type: principal / trigger / condition / action / device-state |
| $L$ | edge labels: triggers, evaluates, invokes, actuates, causes |
| $D$, $G(D)$, $\text{UI}(D)$ | recorder database; graph recovered from it; rendered timeline |
| $\mathrm{Attr}_G(\alpha)$ | attribution of actuation $\alpha$; $\bot$ if unknown |
| $\mathcal{A}$, $C$ | adversary; its capability record |
| $t_c,\ \omega,\ b$ | compromise time; inter-anchor window; write budget (**headline budget**) |
| $\mathrm{Plaus}(\cdot)$ | plausibility predicate (renders + schema-valid + §9.4 invariants) |
| $\mathcal{R}_b(G),\ \mathcal{R}^i_b(G)$ | reachable forged graphs, all classes / class $i$ only |
| $F_{del},F_{rep},F_{inj}$ | forgery classes: deletion, re-parenting, injection |
| $\mathrm{CE}_b(G,G',\alpha)$ | composition-essential indicator |
| $h(v)$ | node commitment hash (binds content **and** parents **and** edge labels) |
| $\Phi$, $\varphi$ | commitment family (laminar); a single segment commitment |
| $T$, $Q$ | ground-truth tampered set (L4 oracle); quarantined set |
| M1–M6 | TDR, LP, LR, OQ, RA, BFP |
| $W(\alpha)$, $\bar W$, $f$ | detection window for $\alpha$; expected window; anchoring frequency |
| $\rho$ | relative overhead ratio (HOMEPROV / baseline), the substrate-invariant cost metric |
| L0–L4 | observability lattice levels (§2.2) |

---

## 2. System model in the notation

### 2.1 Components

```
                    ┌───────────────────────── HA core process (one Python VM) ──────────────────────────┐
   principals ────► │  event bus  ──►  automation engine  ──►  service registry  ──►  integrations       │
   (person, agent)  │       │                  │                       │                    │            │
                    │       └──────────────────┴───────────────────────┴────────┐           │            │
                    │                                                    EMIT-PROV (A1)     │            │
                    │                                                           │           ▼            │
                    │                                              ┌────────────▼──────┐   devices       │
                    │   ADVERSARY LIVES HERE  ◄────────────────────│  recorder  →  D   │   (virtual)     │
                    │   (malicious HACS integration, F1 reach)     └────────────┬──────┘                 │
                    └───────────────────────────────────────────────────────────┼────────────────────────┘
                                                                                │ append-only IPC
                                    ┌───────────────────────────────────────────▼──────────────────┐
                                    │  ANCHOR DAEMON  (separate uid / separate container)          │  ← A2 placement
                                    │  holds laminar segment roots Φ; append-only; signs           │
                                    └───────────────────────────────┬──────────────────────────────┘
                                                                    │ periodic publish
                                                        ┌───────────▼───────────┐
                                                        │  EXTERNAL ANCHOR      │  ← A3 placement
                                                        │  (off-box transcript) │
                                                        └───────────────────────┘
```

**Actor positions.** The adversary is *inside* the box, co-resident with the emitter. This is the
whole difficulty: `EMIT-PROV` and `FORGE-COMPOSED` execute in the same address space, with the same
privileges, against the same database. No in-process defense is meaningful — the adversary can patch
our Python at import time. **The only defensible boundary is the process/uid boundary at the anchor
daemon, and the only irrevocable one is the external anchor.** Anchor placement is therefore the
load-bearing design decision, not an implementation detail (`jrn_01M0E28502KWYSZN0YMF6TB6B1`).

### 2.2 Observability lattice

Nested levels. **Every algorithm in §5 declares the maximum level it consumes, and consumes nothing
above it.** Violating this is how a forensic evaluation accidentally uses an oracle and reports
impossible accuracy.

| Level | Contents | Who has it | Used by |
|---|---|---|---|
| **L0** | rendered timeline `UI(D)` only | homeowner | plausibility check $\mathrm{Plaus}$ |
| **L1** | L0 + full recorder database $D$ | investigator with disk access; **also the adversary** | baselines B0, B1 |
| **L2** | L1 + local anchor daemon's commitment log $\Phi_{loc}$ | investigator, post-incident | VERIFY, MIN-QUARANTINE, RECONSTRUCT under placement A2 |
| **L3** | L2 + external anchor transcript $\Phi_{ext}$ | investigator with off-box access | same, under placement A3 |
| **L4** | L3 + ground-truth event trace and true $T$ | **nobody in deployment — evaluation harness only** | metric computation only |

> **L4 is an upper bound, not a capability.** It exists so the harness can compute M1–M6. No
> algorithm in §5 reads L4. Any reported number that would require L4 at inference time is a bug in
> the harness, and AB-6 (§11.6) is the leak test that checks for it.

### 2.3 The capability record — machine-readable, shipped with every result

Every forgery instance, every scenario run, and every reported metric carries this object. **Anything
not in the record was not assumed.** A reviewer should be able to reconstruct the exact adversary
from it without reading prose.

```yaml
# capability_record.schema.yaml  — v1, predeclared 2026-08-19
capability_record:
  schema_version: 1
  actor_id:            str            # e.g. "mal_integration_v3"
  actor_position:      enum[in_process_integration, llm_agent, local_intruder,
                            replay_network, compromised_anchor]      # §10 scenarios
  compromise_time_tc:  iso8601
  powers:                              # F1 — each must be exercised or removed
    db_read:           bool
    db_write:          bool
    fs_read_as_ha_uid: bool
    fs_write_as_ha_uid: bool
    python_exec_in_core: bool
    event_bus_listen:  bool
    event_bus_emit:    bool
    service_call:      bool
    network_egress:    bool
  knowledge:                           # what the adversary knows, not just what it can do
    deployment_topology: enum[none, partial, full]
    automation_configs:  enum[none, partial, full]
    anchor_schedule_known: bool        # ← materially changes achievable forgery
    anchor_key_known:      bool        # ← must be false except in scenario S5
    victim_routine_model:  enum[none, coarse, fine]
  budget:                              # F3
    db_writes_max:     int             # HEADLINE BUDGET
    wallclock_window_s: int            # ω, inter-anchor window
    cpu_seconds_max:   float
  constraints:                         # F4 — explicit non-capabilities
    host_root:         false
    cross_uid_write:   false
    anchor_key_access: false
    external_anchor_retraction: false
    clock_control:     false           # lifted only in the §7.6 sensitivity arm
  substrate:
    kind:              enum[qemu_aarch64_icount, x86_container]
    ha_version:        str             # "2026.7.x" pinned
    icount_shift:      str             # determinism setting; null for x86
  provenance:
    rka_mission:       str             # mis_...
    seed:              int
    commit:            str
```

### 2.4 Trust assumptions, and what is *not* silently included

**Trusted (stated, so it can be attacked):**
- **T-1** The anchor daemon's process boundary holds against a non-root in-process adversary — i.e.
  POSIX uid separation is not bypassed. *Not* trusted against host root.
- **T-2** The anchor daemon's signing key is not readable by the HA uid.
- **T-3** Cryptographic primitives (SHA-256, Ed25519) are sound.
- **T-4** The external anchor, once published, cannot be retracted or rewritten by the adversary.
- **T-5** The host clock is monotonic and not adversary-controlled (lifted in §7.6).

**Explicitly NOT assumed — these are the ones a reviewer will reach for:**
- ✗ HA core is not compromised — **it is** (that is the threat model).
- ✗ Integrations are vetted — they are not; HACS is unreviewed by design.
- ✗ The recorder database is protected — it is fully writable by the adversary.
- ✗ Devices report their own state honestly — **not assumed**; a device that lies is outside scope
  (§7.7) and HOMEPROV's guarantee explicitly excludes it (§5.10).
- ✗ The adversary is present from boot — **not assumed**; $t_c$ is a parameter, and history *before*
  $t_c$ is protected, history before the *first anchor* is not (§5.10).
- ✗ A hardware root of trust exists — **not assumed and not available** (no hardware, §11.1).

---

## 3. Motivation, state of the art, and the gap

**The motivating fact.** Home Assistant 2026.7 (stable 1 July 2026) rebuilt the logbook as a vertical
timeline with causal attribution — person avatar for a manual action, the firing trigger for an
automation, the integration's own icon for integration-originated action — and the release coverage
uses the same 3 a.m. door example that motivates this line of work. **Causal attribution in the open
smart-home hub is now a default platform feature, not a research contribution**
(`jrn_01M0E26WT1ZDQ0D6C4E7RXBKS7`). The descriptive half of this project is dead and is not proposed
anywhere in this design. What the platform did *not* build is any integrity underneath it: no
chaining, no append-only guarantee, no tamper detection, and no adversary in the design at all.

Prior work, grouped by line, each with what it does **and does not** do:

| Line | Representative | Does | Does **not** do |
|---|---|---|---|
| **Platform attribution** | HA 2026.7 timeline (`lit_01M0E284ZCW4F7414DKFPKKKBV`) | Answers "who caused this?" for a cooperative system; ships to millions | No adversary; computed over an adversary-writable DB; no integrity of any kind |
| **TAP execution integrity** | **Ruledger**, arXiv 2402.19011 (`lit_01M0E284ZR1WJPDGY07PJ7MN97`) | Ensures trigger-action *rules executed correctly* in TAP platforms | **[GATE — M1-T1 must settle this]** Believed to concern execution-time integrity, not after-the-fact forgery of the *record* on a local hub. If it does cover record forgery, Exit 2 fires |
| **IoT provenance collection** | ProvThings lineage | Collects IoT data provenance; lineage across app/device | Assumes a trustworthy collector and store; no adversary editing the provenance itself |
| **IoT forensics / reconstruction** | ForenThings, ACM TIoT 7:1, 2026 (`lit_01M0E284ZV12X1W25W6D4WDFZM`) | Interactive crime-scene reconstruction from IoT evidence | Assumes the evidence is authentic; no forgery model, no partial-trust reconstruction |
| **Tamper-evident audit logging** | Schneier–Kelsey forward-secure logs; Crosby–Wallach history trees; Merkle audit trails (`lit_01M0E284ZYB66Y0MDTX1Q1V9KC`) | Strong, mature record-level integrity; efficient membership + consistency proofs | Protects a **linear sequence of records**; no notion of causal edges; a violation voids the log (OQ → 1); assumes an out-of-process or remote verifier is already available |
| **Sibling: in-process privilege** | HOMEGRAFT `prj_01KY1J5KE6AYQ6MKATNJ29W1QC` (`lit_01M0E28500XNEPFPEX3ZMBTNAB`) | **Measures** that HACS integrations run as first-class Python in-process with full hub privilege | Does not consider the forensic record as an attack target |
| **PI's own prior work** | VESPER (testbed/dataset), ProVSafe (policy enforcement) | Boundary to defend, per `dec_01M0E28ZS8AZCF4R5P8WJM9GXD` | HOMEPROV builds **no** testbed and **no** dataset (VESPER), and does **no** policy enforcement (ProVSafe) |

**The 4-dimension intersection.** No prior line holds these jointly, and HOMEPROV must hold all four
or it collapses into one of the rows above:

1. **Causal-graph integrity covering EDGES, not just nodes** — record-level schemes are defeated by
   re-parenting, which alters no record's own content.
2. **An in-process adversary with direct database access** — not a remote attacker, not a malicious
   client; the collector and the attacker share an address space. This is measured fact from
   HOMEGRAFT, not an assumption.
3. **A hub-class resource budget** — the defense must run alongside HA on a device in the Raspberry
   Pi envelope. (**Substrate note, §11.1**: with no hardware available this is evaluated on *native*
   aarch64 under a Pi-shaped cgroup envelope, with crypto parity on the commit hot path; absolute
   latency is not claimed as Pi latency.)
4. **Sound reconstruction under PARTIAL forgery** — the field's default answer, "the log is void," is
   forensically useless; OQ ≪ 1 with zero assert-wrong is the contribution.

Dimension 4 is the technical core; dimension 1 is what makes 4 *possible* (you cannot localize what
you cannot detect); dimensions 2 and 3 are what make it a home-automation paper rather than a logging
paper. **This intersection is exactly what baseline B2 (§11.3) operationalizes**: B2 holds
dimensions 2 and 3 and half of 1, and HOMEPROV must beat it on the other half of 1 and on 4.

---

## 4. Insight

Five mechanisms, not motivations.

**I-1. Binding parents into the child's hash converts edge integrity into node integrity.**
Define $h(v) = \mathrm{H}\big(\text{content}(v)\ \Vert\ \langle \mathrm{id}(u_i),\, h(u_i),\, \ell_i\rangle_i \big)$
over $v$'s parents in canonical order. **The parent's IDENTITY must be bound, not only its hash**
(corrected 2026-08-20): an unresolvable parent hashes to a zero sentinel that is byte-identical to
*having no parent*, so re-parenting onto a **dangling** context was invisible — the same class of
flaw this work attributes to B2, present in our own defence until AB-1 exposed it. Re-parenting an edge changes the *child's* hash even though no
record's own fields changed. This is the single mechanical step that lifts a record-level scheme to a
graph-level one, and it is why B2 — which commits to record content only — cannot see $F_{rep}$.

**I-2. The adversary can recompute everything inside $D$; therefore only what is outside $D$ counts.**
A chain rooted in the same database is worthless — the adversary deletes and recomputes. The design's
degrees of freedom are exactly the placements where a root can live that the HA uid cannot rewrite:
a separate-uid append-only daemon, and an off-box publication. Everything else is engineering.

**I-3. Nesting the commitments buys tractability and tightness with the same structure.**
*(Measured 2026-08-22, AB-4: laminar OQ 0.00049 vs flat-hour 0.169 — a 345× gain. Honest split:
flat per-segment commitment alone already beats whole-log-void ~6×, so nesting earns 2.5 of the 3.3
orders, not all of them. Also: the implementation's laminar subsumption test was **inverted** until
2026-08-22, inflating blast radius up to 25× — the tightness claim was not being achieved in code
until that was fixed.)*
A laminar family of segment commitments confines a violation to the innermost segment containing it,
which both bounds $\lvert Q\rvert$ by segment occupancy and makes the **sound** quarantine computable
by a single interval sweep (Props. A–C, corrected 2026-08-20 after AB-1). The commitment topology is chosen for **forensic** properties, not just security
properties. This is the design's most transferable idea.

**I-4. Abstention is a first-class output, and it is what makes soundness achievable.**
A forensic tool that must answer every question is forced to guess over quarantined regions.
HOMEPROV's reconstructor emits three annotations per actuation — `verified`, `unverifiable`,
`contradicted` — and abstains on the latter two. Soundness then becomes provable *by construction*
(never assert over $Q$), and the interesting empirical question moves to completeness, where it can
be measured honestly (Miss-R-abstain).

**I-5. Blame must land on a *named innocent*, not on "unknown," for the attack to be interesting —
and that requirement is what forces composition.**
Deletion alone yields $\bot$, which reads as suspicious. Re-parenting alone leaves the malicious node
present and the innocent automation firing without a trigger — implausible. Injection alone leaves two
competing causes. The plausibility predicate $\mathrm{Plaus}$ is what makes the single-class attacks
fail and the composed one succeed; **$\mathrm{CE}_b$ is the formal statement of that intuition**, and
$\mathrm{Plaus}$ is the reason it can be 1 at matched budget rather than merely at higher budget.

---

## 5. Proposed system and algorithms

### 5.1 Components

| Component | Placement | Trusted? |
|---|---|---|
| **PROV-EMIT** | HA custom component, in-process | ✗ — co-resident with adversary |
| **COMMIT** | in-process, streaming | ✗ |
| **ANCHOR-DAEMON** | separate uid / container, append-only IPC | ✓ (T-1, T-2) |
| **EXT-ANCHOR** | off-box transcript | ✓ (T-4) |
| **VERIFY / LOCALIZE / RECONSTRUCT** | offline investigator tooling | ✓ (runs post-incident, off the compromised hub) |

**Scope constraint from `mis_01M0E2A7G390FBFFCS9F5E17E4`:** do **not** fork HA Core. The artifact must
install on stock HA 2026.7 as a custom component plus a sidecar, or it will neither be adopted nor
independently evaluated.

### 5.2 A1 — `EMIT-PROV` (the deterministic primitive everything calls)

*Consumes: in-process event context. Emits: provenance node + edges. Determinism is required so that
two independent replays of the same event stream produce byte-identical hashes.*

```
ALGORITHM A1  EMIT-PROV(evt, ctx)
 1  ty   ← classify(evt)                       # π | τ | κ | α | δ
 2  ent  ← entity_of(evt)
 3  t    ← monotonic_ts()                      # T-5; NOT wall clock
 4  par  ← []                                  # parents WITH labels — this is I-1
 5  for (u, ℓ) in causal_parents(ctx) do       # from HA 2026.7's own context chain
 6        par.append( ⟨h[u], ℓ⟩ )
 7  sort par by canonical_order                # determinism: stable, label-then-hash
 8  content ← ⟨ty, t, ent, canonical_payload(evt)⟩
 9  h[v] ← H( SER(content) ‖ SER(par) )        # binds content AND structure
10  v ← ⟨id, content, par, h[v]⟩
11  append v to D                              # adversary-writable — deliberate
12  STREAM-COMMIT(v)                           # A2; the part that leaves the DB
13  return v
```

*Note line 5:* HA 2026.7 already computes the causal context for its timeline. A1 **consumes** that
rather than duplicating it — HOMEPROV adds integrity to a capability the platform now provides. That
is both the honest framing and the smaller diff.

### 5.3 A2 — `COMMIT-LAMINAR` (nested segment commitments over nodes and edges)

```
ALGORITHM A2  COMMIT-LAMINAR(stream of nodes v)
    GRAN ← [minute, hour, day, epoch]          # laminar: each pair nested or disjoint
 1  for each granularity g in GRAN do
 2       maintain open segment  S_g  = ⟨g, start_g, count_g, acc_g⟩
 3  on STREAM-COMMIT(v):
 4       for g in GRAN do
 5            acc_g   ← H(acc_g ‖ h[v])        # order-sensitive: deletion breaks it
 6            count_g ← count_g + 1
 7       for g in GRAN with segment_boundary(g, t(v)) do
 8            φ ← ⟨ g, start_g, t(v), count_g, acc_g,
 9                  child_roots(g) ⟩            # nesting: hour commits its minutes
10            ANCHOR-APPEND(φ)                  # A3 — crosses the uid boundary
11            reset S_g
```

Three properties of $\varphi$, each defeating one forgery class:
- `acc_g` (order-sensitive accumulator over $h[v]$, which by I-1 includes parents) ⇒ **$F_{rep}$
  detected**, because re-parenting changes $h[v]$.
- `count_g` ⇒ **$F_{del}$ detected**, because deletion changes the count even if the adversary
  recomputes the accumulator over what remains.
- `child_roots(g)` (nesting) ⇒ **$F_{inj}$ localized**, because an injected node either falls outside
  every committed segment (visible as an uncommitted region) or inside one whose accumulator now
  disagrees.

### 5.4 A3 — `ANCHOR` (the three placements, compared not assumed)

```
ALGORITHM A3  ANCHOR-APPEND(φ)                 # MEASURED in M2, not assumed
  P1  OS append-only (chattr +a on ext4/xfs):
        installer (privileged, ONCE) : chattr +a  <chain>
        hub        (unprivileged)    : append-only extension of <chain>
        MEASURED against a container holding HA's EXACT capability set, uid 0:
           APPEND allowed · TRUNCATE refused · DELETE refused
           CLEAR +a refused · IN-PLACE EDIT refused        --> ANCHOR HOLDS
        WHY: HA's container is root but WITHOUT CAP_LINUX_IMMUTABLE
             (CapEff=0xa80425fb, Docker's default set).
        VOID IF the deployment grants CAP_LINUX_IMMUTABLE or --privileged
             (both measured to defeat it) --> ship a capability self-check.
  P2  Separate container holding the chain head (namespace isolation).
        *** RECOMMENDED DEFAULT (measured 2026-08-22, stage 12) ***
        The hub's only reach is a socket with ONE mutating verb: append.
        MEASURED to hold under HA default caps, +CAP_LINUX_IMMUTABLE, AND
        --privileged -- capability grants change nothing, because the bound is
        a PROTOCOL and not a filesystem flag. STRICTLY DOMINATES P1, which
        falls under both grants. Also the platform-native shape: HA OS already
        runs add-ons as separate containers.
        NOTE: uid separation INSIDE the HA container is meaningless -- HA runs
        as root. The real boundary is the container, which is also how HA OS
        already runs add-ons.
  P3  Periodic anchoring to a SEPARATE LOCAL container + volume, every P_ext s.
        Re-scoped by dec_01M0EE5RQP5E2HETFZWPZQT7H7: off-box publication to a
        phone, second device, or external service is NOT built and NOT
        evaluated -- named as a deployment option only.
  P4  eBPF / kernel-resident state (from Nitro, CCS 2025):
        DEMOTED to a note. CAP_BPF is NOT held by the HA container, so this
        needs a privileged add-on -- and P1 achieves the same isolation far
        more cheaply. The same measurement means the ADVERSARY cannot use
        eBPF either.

**The detection window, defined before it is measured.** For actuation $\alpha$,
$W(\alpha) = t_{\text{anchor}}(\alpha) - t(\alpha)$ is the interval in which $\alpha$'s record is
forgeable without evidence at that placement's granularity. For periodic external anchoring at
frequency $f$, $\mathbb{E}[W] = 1/(2f)$ under uniform arrival. **$W$ is a result, not a limitation to
bury** — it tells a deployer exactly what they are buying, and the $W$-versus-overhead curve is one
of the paper's figures (§12, Fig. 5).

### 5.5 A4 — `VERIFY` (consumes L2 or L3; never L4)

```
ALGORITHM A4  VERIFY(D, Φ) → Ψ                 # Ψ = violated commitments
 1  G ← reconstruct_graph(D)
 2  recompute h[v] for all v ∈ V in topological order   # I-1: needs parents
 3  Ψ ← ∅
 4  for φ = ⟨g, t0, t1, count, acc, children⟩ ∈ Φ do
 5       V_φ ← { v : t0 ≤ t(v) < t1 }
 6       if |V_φ| ≠ count           then Ψ ← Ψ ∪ {⟨φ, COUNT⟩}      # F_del / F_inj
 7       if fold(H, h[V_φ]) ≠ acc   then Ψ ← Ψ ∪ {⟨φ, ACC⟩}        # F_rep / content
 8       if roots(children) ≠ φ.children then Ψ ← Ψ ∪ {⟨φ, NEST⟩}  # structural
 9  Ψ ← Ψ ∪ UNCOMMITTED-REGIONS(V, Φ)          # nodes in no segment at all
10  return Ψ
```

### 5.6 A5 / A6 — `MIN-QUARANTINE`, exact and greedy

```
ALGORITHM A5  MIN-QUARANTINE-EXACT(G, Ψ)  → Q          # |V∪A| ≤ 10^4 ; all scenarios
 1  ILP:  minimise Σ_x q_x        over x ∈ V ∪ A,  q_x ∈ {0,1}
 2        s.t.     Σ_{x ∈ S_φ} q_x ≥ 1     for every ⟨φ,·⟩ ∈ Ψ
 3        S_φ = elements covered by φ  (its segment's nodes and their incident edges)
 4  return { x : q_x = 1 }

ALGORITHM A6  MIN-QUARANTINE-GREEDY(G, Ψ) → Q          # deployment scale, Prop. 2
 1  sort Ψ by segment granularity ASCENDING  (minute first — innermost)
 2  Q ← ∅ ; covered ← ∅
 3  for ⟨φ,·⟩ ∈ Ψ do
 4       if φ ∈ covered then continue                   # laminarity: parent handled
 5       Q ← Q ∪ S_φ                                    # quarantine innermost only
 6       covered ← covered ∪ ancestors_in_Φ(φ)          # nested parents subsumed
 7  return Q
```

**Soundness of the quarantine (proof obligation, Thrust B).** $Q \supseteq T$ must hold —
i.e. LR $=1$ — because every tampered element lies inside some violated segment (A2 commits every
node at every granularity) and A6 quarantines the whole of that segment. The corresponding *loss* is
that $Q$ also contains untampered co-residents of the segment, which is exactly what OQ measures and
what finer minimum granularity reduces (ablation AB-2).

### 5.7 A7 / A9 — the anti-triviality machinery

```
ALGORITHM A7  FORGE-COMPOSED(G, α, π_inn, C) → G'      # the adversary; Thrust A
 1  P ← causal_path(G, π_mal → α)
 2  G' ← G
 3  G' ← F_del (G', {p ∈ P : ty(p) ∈ {π, α} ∧ ent(p) = mal})   # remove own trace
 4  G' ← F_rep (G', edge(·→α), new_parent = action_node(π_inn)) # re-point blame
 5  G' ← F_inj (G', trigger_node making π_inn's firing explicable at t(α))
 6  assert PLAUS(G')                                    # F2 — else the forgery is free to detect
 7  assert writes(G') ≤ C.budget.db_writes_max          # F3 — headline budget
 8  return G'

ALGORITHM A9  NECESSITY(G, G', α, C)  → {essential_i}  # counterfactual necessity
 1  for i ∈ {del, rep, inj} do                          # remove ONE component
 2       G'_{-i} ← A7 with step i skipped, budget REDISTRIBUTED to the others
 3       essential_i ← ¬( PLAUS(G'_{-i}) ∧ Attr(G'_{-i}, α) = π_inn )
 4  return {essential_i}

ALGORITHM A10 CE-CHECK(G, G', α, b)   → {0,1}          # the §1.4 indicator, EXACT
 1  if Attr(G',α) = Attr(G,α) ∨ ¬PLAUS(G') then return 0
 2  for i ∈ {del, rep, inj} do
 3       enumerate  R_i ← R^i_b(G)                      # exhaustive at scenario scale
 4       if ∃ G'' ∈ R_i : Attr(G'',α)=Attr(G',α) ∧ PLAUS(G'') then return 0
 5  return 1
```

**Matched-budget comparison, and which budget is the headline.** A9 line 2 is the crux: when a
component is removed, its write budget is **redistributed to the remaining components**, not
discarded. Without redistribution, "the composed attack wins" reduces to "the composed attack spent
three times as many writes," which is not a finding. Likewise A10 line 3 enumerates single-class
forgeries at the *same* $b$.

> **The headline budget is $b$ = database write count.** Justification: $b$ is the resource that the
> defense actually rations. Anchoring frequency $f$ bounds how many writes an adversary can make
> before its work is committed, so $b$ and $f$ are duals — an overhead result in $f$ translates
> directly into an adversary-capability bound in $b$. Wall-clock and CPU budgets are reported as
> secondary and are *not* substrate-invariant under QEMU (§11.1), which is a second reason not to
> headline them.

### 5.8 A8 — `RECONSTRUCT` (consumes L2/L3; abstention is an output)

```
ALGORITHM A8  RECONSTRUCT(G, Q, Ψ) → account            # the forensic product
 1  account ← []
 2  for each actuation δ ∈ V, ty(δ)=δ, in time order do
 3       anc ← causal_ancestry(G, δ)
 4       if anc ∩ Q = ∅ then
 5            emit ⟨δ, Attr(δ), trust = VERIFIED, evidence = witness_path(δ)⟩
 6       else if ∃ two distinct maximal ancestries then
 7            emit ⟨δ, ⊥,        trust = CONTRADICTED, conflict = ...⟩    # abstain
 8       else
 9            emit ⟨δ, ⊥,        trust = UNVERIFIABLE,
                    reason = innermost_violated_segment(anc, Ψ)⟩          # abstain
10  account ← COMPACT(account)      # dependence-preserving: merge runs that share
11                                  # an ancestry, so output is an explanation not a dump
12  return account
```

### 5.9 Informal guarantee

> **G-1 (Anchored-history evidence).** For any actuation $\alpha$ whose provenance node was committed
> to a segment $\varphi$ that reached the anchor at level P2 (separate uid) or P3 (external) before
> the adversary acted, any modification to $\alpha$'s content, to $\alpha$'s causal parents, to any
> node in $\alpha$'s committed ancestry, or to the *count* of nodes in $\varphi$, causes `VERIFY` to
> report a violation covering $\alpha$ — under trust assumptions T-1..T-5 and the non-capabilities
> F4.
>
> **G-2 (Sound partial account).** `RECONSTRUCT` never asserts an attribution for an actuation whose
> causal ancestry intersects $Q$. Consequently, conditional on LR $=1$, **Miss-R-assert $=0$ by
> construction**: every attribution HOMEPROV asserts is computed entirely over anchored, verified
> structure.
>
> **G-3 (Bounded blast radius) — CORRECTED 2026-08-22 after Stage 8 measured it.** Under a laminar
> commitment family, a violation confined to one segment quarantines that segment and its incident
> edges, not the containing hour, day, or epoch (Prop. C).
>
> ~~OQ is bounded by segment occupancy, not by history length.~~ **That form is FALSIFIED**: measured
> log-log slope of $\lvert Q\rvert$ against occupancy is **0.297**, not the $\approx 1$ a pure
> occupancy law requires. The measured law is
>
> $$\lvert Q\rvert \;\approx\; \max\big(\text{run\_size},\; \text{occupancy} \times w\big)$$
>
> with an empirical **floor of one causal run** (6 nodes: trigger state, `automation_triggered`,
> `call_service`, automation state, two actuation states). Pearson 0.982; median relative error
> 0.143; slope 0.809 in the occupancy-dominated regime. A power law cannot fit a `max()` — the slope
> is ~1 above the floor and ~0 below it, which is exactly why the naive full-range slope reads 0.30.
>
> **Deployment consequence, and it is not a technicality:** a *quiet* home does not get better
> localization than one automation run's worth of nodes. OQ is bounded **below** by
> $\text{run\_size}/N$. Run size is a property of how the user writes their automations, so it is a
> deployment parameter and the paper must report it as one.

### 5.10 Non-guarantees — what G-1..G-3 do **not** cover

Stated as a list, in the manuscript, adjacent to the guarantee. A design that lists only guarantees
is marketing.

1. **No prevention.** The adversary can stop logging, corrupt $D$, or destroy the device. HOMEPROV
   makes that *evident*; it does not make it impossible. Availability is not claimed.
2. **Nothing before the first anchor.** An adversary that compromises the hub before the first
   segment ever reaches the anchor can fabricate a fully consistent history from origin. Anchoring
   establishes integrity **from the anchor forward, only**.
3. **Nothing inside the detection window.** Forgery of records not yet committed at a given placement
   is invisible at that placement. $W$ (§5.4) is the size of that hole and is reported, not hidden.
4. **Nothing against host root.** Placement P1 falls to root and to CAP_LINUX_IMMUTABLE; P2 falls to
   root. Only P3 (external) survives root, and only for already-published epochs.
5. **Nothing if the anchor key leaks.** T-2 broken ⇒ G-1 void. Scenario S5 exercises this explicitly
   so the failure is characterized rather than assumed away.
6. **No ground truth about the physical world.** If a device *reports* a state it is not in, HOMEPROV
   faithfully anchors a false report. Provenance integrity is not sensor integrity.
7. **No intent, no maliciousness judgement.** HOMEPROV attributes *causation*, not purpose. "Which
   integration caused this" is answerable; "was it malicious" is not.
8. **No completeness guarantee.** HOMEPROV may abstain (Miss-R-abstain) on regions it cannot verify.
   How often is an empirical question (M4, M5), not a proved property.
9. **The P1 anchor is void under a permissive capability set.** Measured: granting
   `CAP_LINUX_IMMUTABLE`, or running `--privileged` (as some deployments do for USB/Bluetooth
   passthrough), lets the adversary clear `+a` and rewrite the chain. The guarantee is conditional
   on the deployment's capabilities, and the artifact ships a self-check that says so.
10. **P1 requires ext4/xfs and does not survive offline access.** The append-only attribute is
   unavailable on bind mounts (measured: the macOS `fakeowner` mount rejects `chattr` outright), so
   the anchor must live on a real volume. And append-only is a *running-kernel* property: anyone who
   can mount the volume from outside the running system can rewrite it.
11. **A `CLOCK_STEP` lifecycle marker opens a detection hole — NARROWED 2026-08-22 after
   measurement.** ~~A hole equal to its declared window.~~ **Measured smaller than that claim.** An
   injection escapes only when *every* granularity's segment containing it lies wholly inside the
   declared window: at a 20 s backdate inside a 60 s window the second-segment is excused but the
   **minute** segment extends past the window edge and is not, so the injection is caught anyway.
   The effective hole is ≈ `min(declared window, distance back to the previous minute boundary)`.
   **Laminar nesting bounds the hole well below the window** — a fourth thing the nesting buys,
   alongside tractability, tight localization and bounded storage; a flat commitment would expose
   the full window.
   The hole is nonetheless **real and non-zero**: a 5 s backdate inside a 60 s window escapes
   cleanly, and within it a genuine backward clock step and a forged insert are information-
   theoretically indistinguishable. Bounded at `MAX_CLOCK_STEP_S = 300 s` — measured working: a
   301 s-wide window is refused outright. Mitigations unchanged: the marker is **anchored and
   therefore visible**, and repeated markers are themselves an alarm.
12. **Lifecycle markers are part of the trusted design, not an afterthought.** BFP was measured at
   **0.429** without them — recorder purge, backup restore and a backward clock step each produce
   exactly the signature of `F_del` or backdated `F_inj`. Markers bring BFP to 0.000, but only
   because a marker is **honoured** solely when the graph exhibits the wholesale discontinuity it
   claims (PURGE: nothing older than the cutoff survives; RESTORE: nothing newer than the point
   survives). Abusing one therefore costs the adversary the entire declared range — converting a
   silent targeted rewrite into a visible mass deletion. Verified: FT-10 is detected under forged
   PURGE, RESTORE, CLOCK_STEP, MIGRATE and RESTART markers, and all of them combined.
13. **P2/P3 assume the anchor container itself is uncompromised.** Measured 2026-08-22: the
   separate-container anchor holds under every capability grant including `--privileged`, because
   the hub's only reach is a socket whose sole mutating verb is *append* and the chain volume is
   never mounted into the hub. But an adversary who can **start containers on the host**, or who
   reaches the **Docker socket**, defeats P2 and P3 alike — and some Home Assistant setups do expose
   the Docker socket to add-ons. This sits alongside host root as a boundary the design does not
   cross.
14. **Clock control breaks segment boundaries.** T-5 is assumed; §7.6 measures what happens when it is
   lifted, and the honest outcome may be an additional non-guarantee.

---

## 6. Methods by thrust

### Thrust A — MEASUREMENT: is the causal timeline forgeable, and how? *(the floor; RQ1)*

Maps to RKA `dec_01M0E28ZRNCYASGFT34BFNAPXS`, mission M1 Job B.

| Step | Method | Algorithms | Output |
|---|---|---|---|
| A.1 | Stand up stock HA 2026.7 under the Stage-0 substrate with virtual devices and a synthetic-but-realistic automation set (§11.2) | — | Reproducible deployment $H$ |
| A.2 | Write a benign-looking custom integration; instrument every privilege it exercises into a capability record | §2.3 schema | $C$ per forgery |
| A.3 | Demonstrate the three atomic classes independently, each with the *minimum* privilege that suffices | $F_{del},F_{rep},F_{inj}$ | Privilege-per-class table (paper Tab. 1) |
| A.4 | Demonstrate composed causal laundering | **A7** | Flagship scenario S1 |
| A.5 | Establish $\mathrm{CE}_b=1$ by exhaustive single-class enumeration at matched $b$ | **A10** | The claim-CL result |
| A.6 | Counterfactual necessity: remove each component with budget redistributed | **A9** | Necessity table (paper Tab. 2) |
| A.7 | Sweep $b$ and $\omega$; find the minimum budget at which CL becomes achievable | A7,A10 | $b^\ast$ curve — feeds anchoring frequency in Thrust C |

**Thrust A stands alone.** Even under Exit 3 (§13), A.1–A.3 constitute a measurement result about the
integrity properties of the most widely deployed open smart-home hub.

### Thrust B — HYPOTHESIS: sound reconstruction under partial forgery *(the ceiling; RQ3, RQ4)*

Maps to `dec_01M0E28ZRXECP42D9GDCW4M7VW`, `dec_01M0E28ZS0PTEEQNGBT6EGNEX0`, mission M3.

> **H-B.** For forgeries drawn from the §9.1 catalog against a laminar-committed provenance graph,
> localization achieves LR $=1$ with $\mathrm{OQ}$ an order of magnitude below the whole-log-void
> baseline B3, and reconstruction achieves Miss-R-assert $=0$ with Miss-R-abstain small enough that
> the surviving account still answers the attribution question for the majority of actuations.

| Step | Method | Algorithms |
|---|---|---|
| B.1 | Implement edge-binding emission and laminar commitment | **A1, A2** |
| B.2 | Verification over L2/L3 only; audit for L4 leakage | **A4**, ablation AB-6 |
| B.3 | Exact ILP localization on every scenario; greedy at deployment scale; check Prop. 2 empirically | **A5, A6**, AB-1 |
| B.4 | Trust-annotated reconstruction with abstention and dependence-preserving compaction | **A8** |
| B.5 | Measure M1–M6 across the §10 scenarios and the §9.3 benign catalog | harness |
| B.6 | Ablate: minimum granularity, edge binding on/off, nesting on/off | AB-2, AB-3, AB-4 |

### Thrust C — INFRASTRUCTURE + one measurement: anchor placement and the detection window *(RQ2)*

Maps to `dec_01M0E28ZRTHMPA520PHB91MEG9`, mission M2.

| Step | Method |
|---|---|
| C.1 | Implement placements P1, P2, P3 (§5.4) |
| C.2 | For each placement × each §9.1 forgery class, record **stopped / detected-late / undetected** |
| C.3 | Characterize $W$ as a function of $f$; produce the $W$-vs-overhead curve |
| C.4 | Measure $\rho$ (relative overhead) and storage growth under the Stage-0 substrate, honoring §11.1's invariance rules |
| C.5 | Report P1's expected failure as a **negative result**, not omit it |

---

## 7. Challenges and mitigations

**7.1 The adversary can patch our emitter at import time.** `EMIT-PROV` runs in the same VM as the
adversary; a malicious integration loaded earlier can monkey-patch A1 to emit nothing, or to emit a
lie, from the outset. *Mitigation:* this is not defended and must not be claimed as defended. It is
covered by non-guarantee 2 (nothing before the first anchor) and by the explicit statement that
HOMEPROV protects history *from $t_c$ backward*, where $t_c$ is the adversary's arrival. The design
turns this into a **measured quantity**: scenario S4 varies $t_c$ and reports the fraction of history
that remains verifiable as a function of how early the adversary arrived. That curve is a result.

**7.2 Host timing is not Pi timing.** The host executes aarch64 natively — timing is real, not
emulated (§11.1, measured) — but Apple M-series IPC far exceeds a Cortex-A76 and `cpu.max` caps
throughput rather than IPC, so absolute latency still does not transfer. *Mitigation:* §11.1 declares
a substrate-invariance partition; only invariant metrics enter headline claims; the performance claim
is the *ratio* $\rho$ plus tail-latency **shape**, never absolute milliseconds-on-a-Pi. Crypto parity
(both substrates use ARMv8 `sha2` hardware instructions for the commit hot path) is what makes $\rho$
transfer; that parity is stated in the paper, not assumed.

**7.3 LR could fall below 1, silently.** An unsound localizer is worse than none. *Mitigation:*
LR $<1$ in any run is treated as a **design defect**, not a datum; it fires the M3 checkpoint. The
harness asserts LR $=1$ per-run and fails loudly. AB-6 additionally verifies no algorithm reads L4.

**7.4 Benign operations may look like attacks.** HA restarts, recorder purges, database migrations,
backup restores, and clock changes all mutate $D$ in ways that resemble $F_{del}$. A system with high
BFP is unusable regardless of its security properties. *Mitigation:* the benign catalog (§9.3) is
**predeclared** and run as a first-class evaluation stage with its own threshold; the commitment
schema includes explicit, *anchored* lifecycle markers (`RESTART`, `PURGE`, `MIGRATE`, `RESTORE`) so
that a legitimate discontinuity is itself committed. If BFP exceeds the §11.4 threshold the M3
checkpoint fires.

**7.5 Ruledger may already cover this.** *Mitigation:* this is the gate, not a background worry. M1-T1
is a full read with a written scope determination, and Exit 2 is pre-authored (§13).

**7.6 The clock assumption (T-5) is doing real work.** Segment boundaries are temporal; an adversary
with clock control could straddle or collapse segments. *Mitigation:* a dedicated sensitivity arm
lifts `constraints.clock_control` to `true` in the capability record and re-runs the §9.1 catalog. The
honest possible outcome is a tenth non-guarantee; predeclaring the arm means we cannot quietly drop it.

**7.7 Sensor lying is out of scope but reviewers will ask.** *Mitigation:* non-guarantee 6, stated in
the guarantee paragraph itself rather than buried in limitations, plus one sentence in the threat
model naming it as the boundary between provenance integrity and sensor integrity.

**7.8 Synthetic deployments may be unrepresentative.** Forgeability and OQ both depend on graph shape
— how densely automations interlock. *Mitigation:* deployment generator parameters (§11.2) are swept,
not fixed; deployments are a **random effect** in the mixed model (§11.5); and configurations are
seeded from publicly documented HA blueprint patterns rather than invented, with the fidelity gap
declared. **We do not build a labelled dataset** — that collides with VESPER
(`mis_01M0E2AWQY71FZ5PMCGY54QS67` T5).

**7.9 The contribution could collapse into B2.** If a strong record-level log with an out-of-process
anchor matches HOMEPROV on edge re-parenting *and* on OQ, dimension 1 and dimension 4 both evaporate.
*Mitigation:* B2 is implemented as a real baseline, not described; the comparison is the paper's
central table; and §13 Exit 2 pre-states the narrowed paper if it happens.

**7.10 Overhead could make it undeployable.** HA's own audience judges on exactly this. *Mitigation:*
$\rho$ and storage growth are Stage-3 gates with predeclared thresholds (§11.4), and the anchoring
frequency $f$ is the tuning knob whose cost/benefit curve is a figure rather than a chosen constant.

---

## 8. Contributions

| # | Contribution | Survives the gate? |
|---|---|---|
| **C-A** | **A forgery taxonomy for platform-computed causal attribution**, with per-class minimum privilege, demonstrated against stock HA 2026.7 from an ordinary custom integration | ✅ **Yes — gate-independent.** Stands under all three exits |
| **C-B** | **Causal laundering**: the formal $\mathrm{CE}_b$ device plus a demonstrated composed forgery that re-attributes an actuation to a *named innocent* principal and is unreachable by any single class at matched budget | ⚠️ Requires Exit 1; downgraded to "atomic classes only" under Exit 2 |
| **C-C** | **Edge-binding commitment** (I-1) that lifts record-level tamper-evidence to causal-graph tamper-evidence, with the B2 comparison establishing that record-level schemes cannot see $F_{rep}$ | ✅ Yes, provided B2 loses on $F_{rep}$ — which is a *mechanical* property, not an empirical bet |
| **C-D** | **Laminar commitments for forensic tractability**: Propositions 1 and 2, and the empirical demonstration that OQ ≪ 1 where generic schemes give OQ → 1 | ⚠️ The paper's ceiling; this is Thrust B's hypothesis |
| **C-E** | **Anchor-placement comparison and the detection-window characterization** $W(f)$, including P1's negative result, on a hub-class budget | ✅ Yes — gate-independent measurement |
| **C-F** | **Artifact**: installable on stock HA 2026.7 (custom component + sidecar, no core fork), plus the forgery harness, released with the capability-record schema | ✅ Yes |

C-A, C-C, C-E, C-F stand regardless of gate outcome. C-B and C-D are what make it a strong paper.

---

## 9. Predeclared catalog

**Declared 2026-08-19, before any run.** Nothing below may be edited after data collection begins;
additions are permitted only as a clearly labelled post-hoc appendix.

### 9.1 Forgery template catalog

| ID | Class | Template | Target metric |
|---|---|---|---|
| **FT-1** | $F_{del}$ | Delete the adversary's own $\alpha$-node | TDR via `count` |
| **FT-2** | $F_{del}$ | Delete an intermediate $\tau$ or $\kappa$ node, orphaning a subtree | TDR, OQ |
| **FT-3** | $F_{del}$ | Delete an entire minute-segment's worth of nodes | TDR, OQ (worst case) |
| **FT-4** | $F_{rep}$ | Re-point $\textsf{actuates}$ edge from adversary's $\alpha$ to an innocent automation's $\alpha$ | TDR via `acc` — **B2 must fail here** |
| **FT-5** | $F_{rep}$ | Re-point a $\tau \to \kappa$ edge to change which condition branch appears taken | TDR, RA |
| **FT-6** | $F_{rep}$ | Swap two sibling edges so ordering (and therefore causation) inverts | TDR |
| **FT-7** | $F_{inj}$ | Inject a fabricated $\tau$ node making an innocent automation's firing explicable | TDR via `nest` |
| **FT-8** | $F_{inj}$ | Inject a fabricated $\pi$ node (a person who was not there) | TDR, RA |
| **FT-9** | $F_{inj}$ | Inject an entire plausible automation run that never occurred | TDR, OQ |
| **FT-10** | **composed** | **FT-1 ∘ FT-4 ∘ FT-7 — causal laundering (flagship, S1)** | $\mathrm{CE}_b$, TDR, OQ, RA |
| **FT-11** | **composed** | FT-2 ∘ FT-5 — branch laundering: make a condition appear to have failed | $\mathrm{CE}_b$ |
| **FT-12** | **composed** | FT-3 ∘ FT-9 — segment substitution: replace a window with a fabricated one | $\mathrm{CE}_b$, OQ |

### 9.2 Severity classes (declared so "damage" is never defined after the fact)

| Class | Definition | Example |
|---|---|---|
| **SEV-0 Cosmetic** | Timeline differs; $\mathrm{Attr}$ unchanged for every actuation | Reordered display of two independent events |
| **SEV-1 Obscuring** | $\mathrm{Attr}(\alpha) \to \bot$ for some $\alpha$ | Deletion leaving "unknown cause" |
| **SEV-2 Misattributing** | $\mathrm{Attr}(\alpha) \to \pi_{inn}$, a **named innocent** | Causal laundering (FT-10) |
| **SEV-3 Fabricating** | An actuation appears that never physically occurred, or a real one vanishes entirely | FT-9, FT-12 |
| **SEV-4 Systemic** | The forgery is self-consistent across the full anchored epoch | Pre-first-anchor compromise (non-guarantee 2) |

**SEV-2 is the paper's centre of gravity.** SEV-1 is suspicious and therefore weak; SEV-2 is
persuasive and therefore dangerous.

### 9.3 Benign-event catalog (BFP must be measured against all of these)

`BE-1` HA restart · `BE-2` recorder auto-purge at retention boundary · `BE-3` schema migration on
version upgrade · `BE-4` backup restore to an earlier snapshot · `BE-5` NTP step / DST transition ·
`BE-6` integration reload · `BE-7` device becomes unavailable mid-automation · `BE-8` concurrent
automation runs interleaving in the same segment · `BE-9` clean shutdown mid-segment ·
`BE-10` disk-full write failure · **`BE-11` template-entity context loss — MEASURED in M1: a
*template* lock's derived state row carries `context_parent_id = NULL` even for a genuine
automation-driven actuation. Attribution loss here is benign and adversary-independent; a defender
treating a missing parent as suspicious false-positives on every template entity.**

### 9.4 Semantic invariants defining $\mathrm{Plaus}$

> **Revised after M1 (measured).** $\mathrm{Plaus}$ is **defined as agreement with Home Assistant's
> own logbook renderer**, not as a checklist we author. In M1 a hand-built structural verifier
> *passed* a forgery that HA's renderer still displayed as unattributed. An authored plausibility
> oracle is not a substitute for the platform's rendering path. The invariants below are the
> *additional* semantic checks layered on top of renderer agreement — and M1 established that
> **SI-4 and SI-5 carry the entire composition-necessity argument** (§10.1).

`SI-1` no state transition to the state already held · `SI-2` no automation action while the
automation is `disabled` · `SI-3` no event originating from an entity in state `unavailable` ·
`SI-4` every $\alpha$ has at least one $\tau$ or $\pi$ ancestor within the window · `SI-5` monotonic
timestamps within an entity's own history · `SI-6` device capability match (a `light` cannot emit a
`lock` transition) · `SI-7` referenced automation/integration entity ids exist in the config at that
time.

### 9.5 Success thresholds (predeclared)

| Metric | Threshold | Consequence if missed |
|---|---|---|
| **LR** | $= 1.0$, every run | Design defect → M3 checkpoint |
| **Miss-R-assert** | $= 0$, every run | Design defect → M3 checkpoint |
| **TDR** (post-anchor forgeries) | $\ge 0.99$ | Anchor/commitment redesign |
| **OQ** | $\le 0.10$, and $\le 0.1\times$ B3 | Contribution C-D fails → Exit 2 framing |
| **BFP** | $\le 0.01$ over §9.3 | M3 checkpoint (usability) |
| **RA** on $V\setminus Q$ | $\ge 0.95$ | Reconstructor redesign |
| **$\rho$** (relative overhead) | $\le 1.15$ | M2 checkpoint (deployability) |
| **Storage growth** | $\le 1.5\times$ baseline recorder | M2 checkpoint |

---

## 10. Scenarios

Each scenario states: **mechanism path**, **parameter** (composition depth), **property violated**,
**setup**, **capability required**, and a **CLEAN vs ATTACK trace**.

### 10.1 S1 — *The Laundered Unlock* (FLAGSHIP, FT-10)

- **Mechanism path:** $F_{del}$ (erase own action) → $F_{rep}$ (re-point actuation edge to innocent
  automation) → $F_{inj}$ (fabricate the trigger that makes the innocent automation's firing explicable)
- **Parameter:** composition depth 3
- **Property violated:** SEV-2 (misattribution to a **named innocent**)
- **Setup (as run):** HA 2026.7.4, `lock.kitchen_door` (demo platform), automation `Arrive Home`
  unlocking on `input_boolean.owner_present`, and a malicious custom integration presenting as
  "Weather Plus" (`homeprov_redteam`).
- **Capability required — measured:** `db_write`, `python_exec_in_core`, `service_call`,
  `knowledge.automation_configs = full`, `anchor_schedule_known = false`,
  `budget.db_writes_max = 7`. Installation is a directory dropped into
  `/config/custom_components` plus one `configuration.yaml` line — **no root, no container escape,
  no core modification, no credential theft, no network egress.**

```
MEASURED on stock Home Assistant 2026.7.4 — rendered by HA's OWN logbook processor
─────────────────────────────────────────────────────────────────────────────────
CLEAN  (what actually happened)        ATTACK (what the homeowner sees)
  01:35:51 unlocking  call_service       01:35:49 owner_present=on   (none)
  01:35:53 unlocked   call_service       01:35:49 automation.arrive_home
                                                  "triggered by state of
                                                   input_boolean.owner_present"
                                         01:35:51 unlocking  Arrive Home
                                         01:35:53 unlocked   Arrive Home

  Attr = the integration                 Attr = automation.arrive_home  ← SEV-2
                                                (a NAMED INNOCENT)
```

**The forgery, measured — matched budget b = 7 row-writes.**

| # | Class | Operation | Rows |
|---|---|---|---|
| 1 | `F_inj` | INSERT trigger state `owner_present='on'` @ `ctx=T_fake`, `old_state_id` chained | 1 |
| 2 | `F_inj` | INSERT event `automation_triggered` "Arrive Home" @ `ctx=A_fake, par=T_fake` | 1 |
| 3 | `F_inj` | INSERT state `automation.arrive_home='on'` @ `ctx=A_fake, par=T_fake` | 1 |
| 4 | `F_inj` | INSERT event `call_service` `lock.unlock` @ `ctx=A_fake, par=T_fake` | 1 |
| 5 | `F_rep` | `UPDATE states SET context_id_bin=A_fake, context_parent_id_bin=T_fake WHERE context_id_bin=X` | 2 |
| 6 | `F_del` | `DELETE FROM events WHERE context_id_bin=X` | 1 |

Step 5 writes **only context columns**: `content_byte_identical = true` was measured across every
re-parented row — `state_id`, state value, and `last_updated_ts` unchanged. **A commitment over
record content observes nothing.** Insight I-1, measured rather than argued.

**Three undocumented renderer-level invariants a working forgery must satisfy** — none visible from
the schema, each found because a check *failed*: (i) a fabricated cause must **precede** its effect
in wall-clock order, because HA's logbook builds its context lookup from rows streaming in time
order; (ii) `old_state_id` must be chained or an injected row is invisible; (iii) the automation's
own entity state row must be injected, or the actuation ends up **unattributed (SEV-1)** rather than
**misattributed (SEV-2)**. The difference between a suspicious gap and a convincing lie is one
`INSERT`.

**Why no simpler version reaches it** — see the measured enumeration below. One prediction was
*wrong* and the correction matters: the design expected `F_rep` alone to fail because the innocent
automation would fire *with no trigger*. It does not. It fails because the innocent automation
**already has its own history**, so borrowing its context makes one `mode:single` run actuate twice.
That is why the composed attack must fabricate a *fresh* automation context rather than reuse a real
one — a sharper mechanism than the one originally argued.

**Necessity — MEASURED, $\mathrm{CE}_7 = 1$.** Exact enumeration, every class given its strongest
variant at the same budget:

| Arm | Writes | $\mathrm{Attr}(\alpha)$ | $\mathrm{Plaus}$ | Reaches it? |
|---|---|---|---|---|
| `F_del` erase naming event | 1 | ⊥ UNKNOWN | ✗ | No — SEV-1; the gap *is* the alarm |
| `F_del` erase the actuation | 3 | ABSENT | ✗ | No — nothing vanishes onto an innocent |
| `F_rep` onto the *real* innocent automation | 3 | **NAMED_INNOCENT** | ✗ | No — one `mode:single` run would actuate twice, 13.4 s apart |
| `F_inj` full decoy chain | 5 | INTEGRATION *(decoy: innocent)* | ✗ | No — the true chain survives; competing causes |

The three classes fail in three *different* ways, each the complement of what another supplies:
deletion removes the cause but offers no replacement; injection offers a replacement but does not
remove the cause; re-parenting redirects blame but inherits the innocent automation's existing
history. Only the composition satisfies every constraint at once.

> **The honest caveat, and it is load-bearing.** $\mathrm{CE}_b=1$ holds *under the §9.4 invariant
> catalog*. `F_rep` alone **reached the correct attribution** and failed only on SI-4 and SI-5.
> Against a checker that does not test for duplicate actuation episodes under one automation run,
> `F_rep` alone suffices at **3 writes** and $\mathrm{CE}_b \to 0$. **SI-4 and SI-5 carry the entire
> necessity argument** — which makes them the first thing an upstream proposal should ask the
> platform to enforce, and converts the plausibility predicate from an assumption into a measured
> dependency.

### 10.2 S2 — *The Agent's Alibi* (compromised LLM agent, FT-11)

- **Mechanism path:** $F_{del}$ (remove the agent's own $\pi$ node) → $F_{rep}$ (re-point a
  $\tau \to \kappa$ edge so a safety condition appears to have evaluated `false` when it evaluated `true`)
- **Parameter:** depth 2 · **Property:** SEV-2 · **Setup:** an LLM agent integration with
  `service_call` scope, an automation gated on `condition: occupancy = false` before running the oven.
- **Capability:** as S1 plus `actor_position = llm_agent`, `victim_routine_model = coarse`.

```
CLEAN:  τ agent_request → κ occupancy=TRUE → [BLOCKED, no action]
        π llm_agent → α oven.turn_on  (direct call, bypassing the gate)   ← the real cause
ATTACK: π llm_agent ✗DELETED ; α oven.turn_on re-parented under
        τ schedule_timer → κ occupancy=FALSE → α oven.turn_on
UI:     "Oven turned on 02:40 — Scheduled Preheat (occupancy clear)"      ← SEV-2
```

### 10.3 S3 — *Segment Substitution* (local intruder with hub access, FT-12)

- **Mechanism path:** $F_{del}$ (delete a whole minute-segment) → $F_{inj}$ (write a fabricated
  segment of ordinary evening activity in its place)
- **Parameter:** depth 2, but at **segment granularity** rather than node granularity ·
  **Property:** SEV-3
- **Purpose in the design:** this is the **OQ stress case**. A whole-segment forgery is exactly where
  a laminar scheme's blast radius is largest, and where B3 (whole-log-void) and HOMEPROV should
  differ most. If OQ is not ≪ 1 here, C-D is in trouble.
- **Capability:** `fs_write_as_ha_uid`, `db_write`, `budget.db_writes_max = 200`.

### 10.4 S4 — *Early Arrival* (the $t_c$ sweep, non-guarantee 2 made measurable)

Not a forgery template but a **parameter sweep**: vary $t_c$ from "before first anchor" to "after N
epochs" and report the fraction of history that remains verifiable. Converts non-guarantee 2 from a
caveat into the figure that tells a deployer what anchoring frequency buys them.

### 10.5 S5 — *Anchor Compromise* (T-2 lifted, deliberate failure characterization)

`anchor_key_known = true` in the capability record. **Expected result: total failure of G-1.** Run and
reported so that the failure mode is characterized rather than assumed away — and so the paper cannot
be accused of never testing its own trust assumption.

### 10.6 S6 — *Benign Storm* (BFP, no adversary at all)

$T = \emptyset$. Runs the entire §9.3 catalog, including the nastiest combination (BE-4 backup restore
across a BE-5 DST transition during a BE-3 migration). Measures M6 only.

### 10.7 Scenario → instrument map

| Scenario | FT | SEV | Primary metrics | Secondary | Baseline it must beat |
|---|---|---|---|---|---|
| **S1** flagship | FT-10 | SEV-2 | $\mathrm{CE}_b$, TDR, OQ, RA | LP, LR | **B2** (must miss $F_{rep}$), B3 (OQ) |
| **S2** agent | FT-11 | SEV-2 | $\mathrm{CE}_b$, TDR, RA | OQ | B2 |
| **S3** segment | FT-12 | SEV-3 | **OQ**, LR, TDR | RA | **B3** (OQ→1) |
| **S4** early $t_c$ | — | SEV-4 | verifiable-fraction($t_c$) | TDR | B0 |
| **S5** key leak | FT-4 | — | TDR (expected 0) | — | — |
| **S6** benign | — | — | **BFP** | OQ under benign | B1, B2 (their BFP too) |

---

## 11. Evaluation design

### 11.1 Stage 0 — substrate, and its honest limits

**Hard constraint: no hardware is available for this project and none is budgeted.**
Substrate revised 2026-08-19 after measuring the host (`dec_01M0EAA37PJJFGXHV4V2CPJRAV`, superseding
`dec_01M0E8DFWA5J2X5NQ7KW3ZP67V`; evidence `jrn_01M0EA9D3TT6XT84AGK3709NYC`).

**Measured host facts, not assumptions.** The development host is Apple-Silicon `arm64`; Docker
reports `linux/aarch64`; `/proc/sys/fs/binfmt_misc` is **empty**, so no `qemu-user` translation is in
the path; containers expose the real ARMv8 `aes pmull sha1 sha2 sha3 sha512 crc32` crypto extensions;
and `openssl speed -evp sha256` measures **2.77–2.99 GB/s** on large blocks across three runs with
~5% spread. QEMU TCG software emulation of SHA-256 lands near 50–100 MB/s. Being 30–60× above that is
dispositive: containers execute **natively** under hardware-assisted virtualization.

```
SUBSTRATE  S = native aarch64 Docker under a Pi-shaped cgroup envelope
  host           Apple Silicon arm64; Docker linux/aarch64; binfmt_misc EMPTY (verified)
  cores          --cpus shaped toward a Pi 5 quota;  arms {1, 2, 4}
  memory         --memory arms {2g, 4g, 8g}          # cgroup v2 memory.max verified
  storage        --device-read-bps / --device-write-bps shaped to a Class-A2 microSD profile
  guest          Home Assistant container, version PINNED to 2026.7.x
  devices        virtual only — demo/template/MQTT-backed; NEVER a real home
  cross-check    qemu-system-aarch64 -icount, Stage 0 ONLY, for hash-determinism replay
```

**Why not full-system QEMU.** The earlier decision chose QEMU for ISA fidelity, assuming the container
option meant x86. On an aarch64 host that assumption is false, and native containers dominate on
every axis that matters here:

| Axis | Native container | Full-system QEMU |
|---|---|---|
| ISA | aarch64, native | aarch64, emulated |
| **Crypto extensions (the hot path)** | **real ARMv8 `sha2` silicon** | **software-emulated** |
| Wall-clock timing | real, ~5% run-to-run | uninterpretable |
| Resource shaping | cgroup v2 cpu / memory / **blkio** | `-smp`/`-m` only, no IO shaping |
| Deterministic replay | ✗ | ✓ (`-icount`) — **the one QEMU advantage** |

QEMU is therefore retained for exactly one job: a Stage-0 determinism cross-check. And even that is a
belt-and-braces measure, because HOMEPROV's determinism requirement is on **canonical serialization
producing identical hashes** (A1 lines 7–9), not on timing, and is testable directly.

**Crypto parity is the load-bearing fidelity point.** HOMEPROV's overhead is dominated by SHA-256 in
the A1/A2 commit path. A Pi 5's Cortex-A76 implements the **same** ARMv8 `sha2` extensions as the
host. Both substrates run the hot path as hardware crypto instructions on real silicon, so the ratio
$\rho$ transfers. Under emulation it would not have: the hot path would be software on one side and
hardware on the other, inflating $\rho$ in an uncontrolled direction.

**The substrate-invariance partition — declared before measurement, and the reason $\rho$ rather than
milliseconds is the reported quantity:**

| Metric | Invariant on this substrate? | Why |
|---|---|---|
| TDR, LP, LR, OQ, RA, BFP | ✅ **Yes** | Purely functional; no timing dependence |
| $\mathrm{CE}_b$, necessity | ✅ **Yes** | Combinatorial |
| Storage growth, DB size, memory footprint | ✅ **Yes** | Byte counts, not rates |
| **$\rho$ = ratio of wall-clock cost, HOMEPROV / baseline** | ✅ **Invariant modulo microarchitecture** | Real timing on both sides; same crypto instruction class; ratio cancels platform speed to first order. *Upgraded from "partially invariant" under the superseded QEMU substrate* |
| Event-loop **tail-latency distribution** (p50/p95/p99 shape) | ⚠️ **Shape yes, scale no** | Newly reportable — real distributions, not emulator artifacts |
| Absolute wall-clock latency (ms) as *Pi* latency | ❌ **No** | M-series IPC ≫ Cortex-A76; `cpu.max` caps throughput, **not IPC** |
| Memory-bandwidth-bound effects | ❌ **No** | Higher on M-series; unmodelled by cgroups |

**Residual gap to a Pi 5 — shrunk, not eliminated.** (a) Apple M-series IPC far exceeds Cortex-A76,
and a one-core `cpu.max` quota is still a *faster* core, so absolute latency is not Pi latency;
(b) memory bandwidth is higher and cgroups do not model it; (c) NVMe vs Class-A2 microSD, partially
narrowed by explicit blkio shaping — the one place we can actively close the gap.

**Consequences, applied throughout the paper:**
1. **No absolute latency is claimed as Pi latency.** The performance claim is $\rho$ plus a tail-shape
   figure, worded "on native aarch64 under a Pi-shaped cgroup envelope," never "on a Raspberry Pi."
2. Dimension 3 of the §3 intersection reads **"hub-class budget, evaluated on native aarch64 under a
   Pi-shaped cgroup envelope"** — strengthened from the superseded "evaluated under emulation."
3. A **sensitivity band** is reported around $\rho$ using published Pi 5 cache and IO parameters,
   labelled as an analytic projection, not a measurement.
4. **Falsifier, unchanged and explicit:** a later Pi 5 run with a Class-A2 card must find $\rho$
   within the stated band. If a Pi becomes available before submission, Stage 3 re-runs on it and the
   caveat is deleted.

### 11.2 Stage 1 — deployment generation

Parameterized synthetic deployments; parameters **swept, not fixed**:
$n_{dev} \in \{10,25,50,100\}$ · $n_{aut} \in \{5,15,40\}$ · $n_{int} \in \{5,10,20\}$ · interlock
density (fraction of automations triggered by another automation's effect) $\in \{0.1, 0.3, 0.6\}$ ·
event rate $\in \{10, 100, 1000\}$/hr · history length $\in \{1\text{d}, 7\text{d}, 90\text{d}\}$.
Automation logic seeded from publicly documented HA blueprint patterns. **No labelled dataset is
constructed or released** (VESPER boundary, §7.8).

### 11.3 Baselines — including the mandatory hardest one

| ID | Baseline | Purpose | HOMEPROV must beat it on |
|---|---|---|---|
| **B0** | Stock HA 2026.7 recorder, no integrity | Floor; establishes the exposure | TDR (B0 = 0) |
| **B1** | Naive **in-database** hash chain | The strawman RKA already identifies as worthless; shown broken, not assumed broken | TDR (B1 → 0 under F1) |
| **B2** | ★ **Strong record-level tamper-evident log, anchored out-of-process** — Crosby–Wallach-style history tree over the HA event stream, roots held by the same P2/P3 anchor HOMEPROV uses, with membership and consistency proofs | **THE HARDEST BASELINE.** It concedes HOMEPROV's anchor and its threat model, and differs *only* in committing to record content rather than to causal structure | **(a) $F_{rep}$ detection** — mechanically B2 cannot see re-parenting; **(b) OQ** |
| **B3** | Whole-log-void policy on any violation (generic tamper-evident behaviour) | The field's default forensic response | **OQ** — B3 has OQ → 1 by construction |
| **B4** | HOMEPROV with edge binding disabled (self-baseline) | Isolates I-1's contribution | $F_{rep}$ detection |

> **B2 is the paper.** It is the operational form of the boundary paragraph M1-T2 must write. If B2
> matches HOMEPROV on both (a) and (b), then dimensions 1 and 4 of the §3 intersection collapse and
> the honest conclusion is that HOMEPROV is a re-instantiation of known audit logging. That outcome
> is pre-authored as Exit 2.

### 11.4 Stages

| Stage | What | Gate to proceed |
|---|---|---|
| **0** | Substrate stands up; stock HA 2026.7 runs; virtual devices act; **A1 canonical serialization reproduces byte-identical hashes** across two runs at the same seed (native), cross-checked once under `qemu -icount` | Byte-identical hashes, else canonicalization is non-deterministic and every commitment result is suspect |
| **1** | **Thrust A.** Atomic forgeries FT-1..FT-9 demonstrated with per-class minimum privilege | ≥1 class succeeds at SEV-1 or above — **else Exit 3** |
| **2** | **Thrust A flagship.** FT-10..FT-12, $\mathrm{CE}_b$ by A10, necessity by A9 | $\mathrm{CE}_b = 1$ for FT-10 — **else Exit 2** |
| **3** | **Thrust C.** P1/P2/P3 implemented; per-placement × per-class stop/detect matrix; $W(f)$; $\rho$ and storage | $\rho \le 1.15$, storage $\le 1.5\times$ (§9.5) |
| **4** | **Thrust B.** VERIFY + localization (exact and greedy) + reconstruction across S1–S5 | LR $=1$, Miss-R-assert $=0$, TDR $\ge 0.99$ |
| **5** | **Benign.** S6 over the full §9.3 catalog | BFP $\le 0.01$ |
| **6** | **Scale.** $10^6$–$10^7$-node graphs; greedy-vs-exact agreement on the overlap | Prop. 2 holds empirically (AB-1) |

### 11.5 Statistics

- **Exact arms need no testing.** $\mathrm{CE}_b$, necessity, and MIN-QUARANTINE-EXACT are computed by
  enumeration/ILP. They are reported as *facts about the instance*, with no p-values, and the paper
  says so explicitly rather than decorating them with statistics.
- **Sampled arms** (TDR, OQ, RA, BFP, $\rho$ across deployments × scenarios × seeds) use
  **paired** comparisons: HOMEPROV and every baseline see the *identical* deployment, event stream,
  and forgery instance. Paired bootstrap (10k resamples) for differences.
- **Mixed-effects model** for each sampled metric:
  `metric ~ system + scenario + (1 | deployment) + (1 | seed) + (1 | deployment:scenario)`
  — random effects on **deployment** and **seed** because deployments are a sample from a population
  we are generalizing to, and seeds are nuisance variation. Treating deployment as fixed would
  overstate precision.
- **Held-out split:** deployment parameters are split 60/40; all design choices (segment granularity,
  compaction rules, thresholds) are tuned on the 60% only; the 40% is touched once, at the end.
- **Preregistered contrast set (6 contrasts, no more):**
  1. HOMEPROV vs **B2** on $F_{rep}$ detection (S1, S2) — *the paper's central contrast*
  2. HOMEPROV vs **B3** on OQ (S3) — *the paper's headline number*
  3. HOMEPROV vs **B4** on $F_{rep}$ detection — *isolates edge binding, I-1*
  4. Composed vs best single class on SEV achieved, **at matched $b$** (S1)
  5. $\rho$ vs anchoring frequency $f$ (Stage 3)
  6. BFP: HOMEPROV vs B2 (S6)
- **Intervals throughout.** Every reported quantity carries a 95% interval. **No bare point estimate
  appears in any table or figure**, including in the abstract.

### 11.6 Key ablations

| ID | Ablation | Question it answers |
|---|---|---|
| **AB-1** | Greedy (A6) vs exact ILP (A5) on all instances ≤ $10^4$ | Is Proposition 2 true? A divergence falsifies it |
| **AB-2** | Minimum segment granularity ∈ {second, minute, hour} | The OQ / overhead knob — how tight can localization get before cost bites |
| **AB-3** | Edge binding on/off (= B4) | Isolates I-1 |
| **AB-4** | Nesting on/off (flat segments vs laminar) | Isolates I-3; flat should degrade OQ toward B3 |
| **AB-5** | Anchor placement P1/P2/P3 | Which forgery classes each actually stops |
| **AB-6** | **L4-leak test** — run every algorithm with L4 inputs zeroed | Verifies no oracle leakage (§2.2). Any metric that changes is a harness bug |
| **AB-7** | Abstention disabled (force an attribution over $Q$) | Quantifies exactly what soundness costs in completeness |

---

## 12. Detailed paper outline

Written for the strongest ceiling (Exit 1). §13 names which section re-centers under each other exit.

| § | Section | Thrust | Driving question | Primary figure / table |
|---|---|---|---|---|
| 1 | **Introduction** | — | The platform now answers "who caused this?" over a database the attacker owns. What is that answer worth? | **Fig. 1** — the S1 laundered-unlock timeline, clean vs forged, side by side. One figure that makes the whole paper obvious |
| 2 | **Background: causal attribution without integrity** | — | What did HA 2026.7 actually ship, and what did it not? | **Tab. 1** — attribution features present vs integrity properties absent |
| 3 | **Threat model: the in-process adversary** | A | What does a HACS integration actually get? (measured, via HOMEGRAFT) | **Fig. 2** — the §2.1 architecture with the adversary drawn inside the box; **capability-record schema inset** |
| 4 | **Forgery taxonomy and causal laundering** | A | Which forgeries are achievable, at what privilege, and which require composition? | **Tab. 2** — FT-1..FT-12 × {privilege, SEV, $\mathrm{CE}_b$}; **Tab. 3** — necessity at matched budget |
| 5 | **The causal graph as the object of integrity** | B | Why does record-level tamper-evidence miss re-parenting? | **Fig. 3** — I-1 edge binding: identical records, different child hash. **Contrast 1 (vs B2) lives here** |
| 6 | **Laminar commitments and forensic tractability** | B | Why this commitment topology and not a chain? | **Prop. 1 / Prop. 2**; **Fig. 4** — nesting confining a violation to one minute |
| 7 | **Anchor placement and the detection window** | C | Where can a root live that the adversary cannot reach, and what does that cost? | **Fig. 5** — $W$ vs $f$ vs $\rho$, three placements; P1's negative result marked |
| 8 | **Sound reconstruction under partial forgery** | B | After detection, what survives? | **Fig. 6** — trust-annotated account, `VERIFIED` / `UNVERIFIABLE` / `CONTRADICTED`; **Tab. 4** — the Miss-D/L/R-assert/R-abstain breakdown |
| 9 | **Evaluation** | A+B+C | Does it hold across scenarios, deployments, and benign operation? | **Fig. 7** — **OQ: HOMEPROV vs B3 vs B2** (the headline); **Tab. 5** — M1–M6 across S1–S6 with intervals |
| 10 | **Performance under a hub-class budget** | C | Is it deployable? | **Fig. 8** — $\rho$ and storage growth vs $f$, **with the §11.1 substrate caveat in the caption, not the appendix** |
| 11 | **Discussion, non-guarantees, disclosure** | — | What does this *not* protect, and who has been told? | The §5.10 list, verbatim. Coordinated disclosure with HOMEGRAFT and Open Home Foundation (M4) |
| 12 | **Related work** | — | Where is the boundary against audit logging, Ruledger, and IoT forensics? | The §3 table + the 4-dimension intersection |

**Figure 1 and Figure 7 carry the paper.** Fig. 1 is why a reviewer keeps reading; Fig. 7 is the
number they remember. If either cannot be produced, the corresponding thrust has failed and §13
applies.

---

## 13. The arc and the gate

### The arc

**Act I — measurement (the floor).** Thrust A. Home Assistant 2026.7 computes and displays causal
attribution over a database that any installed integration can rewrite. We taxonomize what an
ordinary custom integration can do to that record, at what privilege, and show that some plausible
misattributions require *composition* of forgery classes rather than any single edit. This yields
C-A, C-E, C-F and is a publishable measurement result on its own.

**Act II — hypothesis (the ceiling).** Thrust B. If integrity is extended from records to causal
*edges* and committed in a *laminar* topology, then a partially forged provenance graph admits
localization that is sound (LR $=1$), tight (OQ ≪ 1), and tractable (Prop. 2) — producing a
trust-annotated partial account instead of the field's default "the log is void." This is C-C and
C-D, and it is what makes the paper strong rather than merely correct.

**Thrust C is infrastructure for Act II** and contributes one standalone measurement of its own: the
detection window $W(f)$ and the placement comparison, including P1's expected failure.

### The gate

**M1 (`mis_01M0E29N6GVECW5N1E1WSRT1JM`) is the gate. Build nothing below it until it resolves.**
Concretely: do not implement A2 `COMMIT-LAMINAR`, A3 `ANCHOR`, A5/A6, or A8 before M1 returns.
M1 resolves two questions jointly — the boundary (Ruledger + audit-logging literature + any
announced HA log-integrity work) and the threat (is the timeline actually forgeable, and is
$\mathrm{CE}_b=1$ reachable).

| Exit | Trigger | Paper that gets written | Section that re-centers | Claim ceiling |
|---|---|---|---|---|
| **Exit 1 — GO** | Ruledger covers execution integrity only; HA has announced no log-integrity work; FT-1..FT-9 reproduce **and** FT-10 achieves SEV-2 with $\mathrm{CE}_b=1$ | **The full paper as designed.** Acts I + II; contributions C-A..C-F | none | Sound, tight reconstruction under partial forgery of a causal graph, against an in-process adversary, on a hub-class budget |
| **Exit 2 — NARROW** | Ruledger (or a B2-class scheme) already covers after-the-fact record forgery; **or** only atomic forgeries reproduce ($\mathrm{CE}_b=0$ for all composed templates); **or** B2 matches HOMEPROV on OQ | **Causal-graph integrity + reconstruction only.** Drop the causal-laundering claim (C-B) and the composition framing. Acts collapse into one: the paper becomes "record-level tamper-evidence is insufficient for causal attribution, and here is the localization that generic schemes lack" | **§4 re-centers**: from "composition is necessary" to "edge integrity is the gap" — the taxonomy becomes an enumeration serving §5, and Tab. 3 (necessity) is cut. §9's headline shifts entirely to OQ | Edge-level integrity + tight localization. Weaker, still novel against B2 *provided* contrast 1 holds |
| **Exit 3 — PIVOT** | Home Assistant has announced or shipped log-integrity work; **or** the timeline turns out **not** to be forgeable from integration-level privilege | **An evaluation paper, not a proposal.** Evaluate the platform's (or the literature's) integrity design against the §9.1 catalog; retain the reconstruction algorithm as an independent contribution applicable to *any* attributed timeline | **§3 re-centers**: the threat model becomes the platform's own stated adversary rather than ours, and §5–§7 become an assessment of their design | Localization and sound reconstruction as a standalone forensic contribution, decoupled from any integrity scheme we propose |

**Where the current data leans.** Toward **Exit 1**, but on incomplete evidence, and the design says
so rather than assuming it:
- *For Exit 1:* HOMEGRAFT establishes in-process first-class privilege as **measured fact**, not
  assumption (`lit_01M0E28500XNEPFPEX3ZMBTNAB`); the 2026.7 timeline is documented as a UI over the
  recorder with no chaining, no append-only guarantee, and no adversary in its design
  (`jrn_01M0E26WT1ZDQ0D6C4E7RXBKS7` F2).
- *Against, and unresolved:* **Ruledger has not been read in full.** It is recorded in RKA as
  `status: reading`. It is the single most likely source of overlap and the most likely trigger of
  Exit 2. Nothing below the gate should be built until it has been read.

### Floor / ceiling / which paper gets written

> **Floor.** A measurement study showing that the causal attribution now shipped by default on the
> most widely deployed open smart-home hub is computed over an adversary-writable substrate, with a
> privilege-indexed taxonomy of what an ordinary custom integration can forge, plus a
> detection-window characterization for three anchor placements. *This survives all three exits.*
>
> **Ceiling.** That the causal graph — not the record — can be made the object of integrity, and that
> a laminar commitment topology yields localization which is simultaneously sound, tight, and
> tractable, so that a partially forged provenance graph still yields a defensible forensic account
> with explicit abstention rather than a binary alarm.
>
> **Which paper gets written.** Exit 1 → the full adversarial-provenance paper for S&P 2027 Cycle 2.
> Exit 2 → the narrower edge-integrity-and-localization paper, still S&P-plausible if contrast 1
> (vs B2) holds, otherwise a strong systems-security venue. Exit 3 → an evaluation-and-forensics
> paper, with the reconstruction algorithm as the surviving contribution.

---

## Appendix A — Execution mapping to RKA

| Design element | RKA object |
|---|---|
| Thrust A / §6 Thrust A | `dec_01M0E28ZRNCYASGFT34BFNAPXS` (RQ1) · `mis_01M0E29N6GVECW5N1E1WSRT1JM` (M1, gate) |
| Thrust C / §5.4, §6 Thrust C | `dec_01M0E28ZRTHMPA520PHB91MEG9` (RQ2) · `mis_01M0E2A7G390FBFFCS9F5E17E4` (M2) |
| §5.2–5.3, I-1, C-C | `dec_01M0E28ZRXECP42D9GDCW4M7VW` (RQ3) |
| Thrust B / §5.6–5.8, C-D | `dec_01M0E28ZS0PTEEQNGBT6EGNEX0` (RQ4) · `mis_01M0E2AWQY71FZ5PMCGY54QS67` (M3) |
| §5.9–5.10 guarantee discipline | `dec_01M0E28ZS3MY8SP1F8PQ3YQQGR` (D1) |
| §3 boundary, baseline B2 | `dec_01M0E28ZS8AZCF4R5P8WJM9GXD` (D2) · `mis_01M0E2BK9HF7DS2FP9FM23MZX7` (M4) |
| §11.1 substrate constraint | PI direction 2026-08-19 — no hardware; QEMU aarch64 selected |
| Scoop risk, ongoing | `mis_01M0E3KF4N2RGEQ0QWPQ74EEV8` (M0, biweekly, portfolio-wide — never mark complete) |

**Suggested gates to instantiate in RKA** (`create_gate` / `evaluate_gate`), one per stage boundary
in §11.4, with `pass_criteria` taken verbatim from §9.5 so that `advance_rq` on RQ1/RQ3/RQ4 can only
fire when the predeclared thresholds are met, and `submit_checkpoint` fires otherwise. The
iterate-or-escalate loop then runs on the thresholds declared *here*, before any data exists —
which is the point of predeclaration.

---

*End of design. Every number above is a target. Nothing has been measured.*
