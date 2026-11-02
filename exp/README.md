# HOMEPROV experiment rig

Everything needed to run every experiment in `research_design_detailed.md`.
**Nothing runs without `--run`.** `selftest` and `plan` are side-effect free.

```bash
python3 exp/run.py selftest        # 23 checks, no side effects  <- run this first
python3 exp/run.py plan            # every gate, threshold, baseline, contrast
python3 exp/run.py stage0          # DRY RUN (describes only)
python3 exp/run.py stage0 --run    # execute
python3 exp/run.py all --run
```

## Constraints honoured (`dec_01M0EE5RQP5E2HETFZWPZQT7H7`)

Open-source only, local Docker, **no hardware beyond the MacBook Pro M4 24GB**,
**no request or email to anyone for access to resources**. No third-party service,
no transparency log, no timestamping authority, no TPM/HSM, no Pi acquisition.

Dependencies are all already present — `numpy`, `scipy` (exact ILP via
`scipy.optimize.milp`), `statsmodels` (mixed-effects), `pandas`, `networkx`,
`matplotlib`, `pytest`. **Nothing needs installing.** The rig core is stdlib-only;
those libraries are used in analysis, never inside the algorithms under test.

## Layout

```
exp/
  conf/catalog.py    FROZEN 2026-08-19 — FT-1..FT-12, SEV-0..4, BE-1..BE-11,
                     SI-1..SI-7, thresholds, baselines, ablations, contrasts
  rig/
    graph.py         A1  provenance graph from the recorder; Attr()
    commit.py        A2  laminar commitment — homeprov | b2 | b4; full + incremental
    anchor.py        A3  placements P1..P4, adversarial test, W(f)
    verify.py        A4  closed-segment comparison + UNCOMMITTED-REGIONS
    localize.py      A5 exact ILP / A6 laminar greedy / AB-1 Prop-2 check
    reconstruct.py   A8  trust-annotated account with abstention
    metrics.py       M1..M6, miss taxonomy, conditionals, gate checks
    forge.py         FT-1..FT-12 with per-forgery write accounting (budget b)
    benign.py        BE-1..BE-11
    baselines.py     B0..B4
    deployment.py    parameter sweep (11.2); NO dataset is built or released
    substrate.py     container lifecycle + CLEAN-STATE ENFORCEMENT
    capability.py    the machine-readable capability record
    stats.py         paired bootstrap, mixed-effects, 60/40 holdout
  stages/stage0..6   the staged pathway of section 11.4
  run.py             orchestrator
  out/               results, each stamped with a capability record + digest
```

## Two standing requirements, both learned the hard way

**1. Reset BOTH the database and the anchor volume between runs.** The anchor is
append-only and therefore *deliberately* survives container restarts — the very
property that makes it useful in production and treacherous in a harness. M2
initially reported `FORGERY MISSED` purely because a restart left a dirty DB and
a chain mixing two runs. `substrate.reset_state()` enforces this.

**2. Wait for `EVENT_HOMEASSISTANT_STARTED`.** HA does not attach automation
triggers until then — measured at ~96 s. Acting earlier silently produces a home
in which no automation ever fires, i.e. confidently wrong negative results.
`substrate.wait_started()` enforces this.

## What the selftest actually guards

Not smoke tests — behavioural invariants that would otherwise regress silently:

- **edge binding detects a re-parent AND B2 does not** — the paper's central
  contrast, asserted as an invariant rather than hoped for
- **backdated injection is detected** — the `F_inj` gap M2 found, where injections
  landed in a second with no prior activity and the whole class went invisible
- **incremental == full recompute** — the O(n) fix must not change the mathematics
- **no false positive on a clean graph**
- **reconstruct abstains over Q** — soundness by construction

## Honest notes carried into the rig

- `Plaus` is **defined as agreement with HA's own logbook renderer**, not a
  checklist we author. In M1 a hand-built structural verifier *passed* a forgery
  the renderer still showed as unattributed.
- **SI-4 and SI-5 carry the entire composition-necessity argument.** Against a
  checker omitting them, `F_rep` alone suffices at 3 writes and `CE_b` drops to 0.
- **OQ must be reported as a function of event age.** Laminar retention degrades
  localization granularity with age by design: 1 s blast radius under an hour,
  1 min under a day, 1 h out to 90 days.
- Absolute latency is **never** claimed as Pi latency. The performance claim is
  the ratio ρ plus tail-latency *shape*, on native aarch64 under a Pi-shaped
  cgroup envelope, with crypto parity on the commit hot path.
