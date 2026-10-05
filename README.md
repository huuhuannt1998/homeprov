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

## What is here

| Path | What it is |
|---|---|
| `monitor/monitor.py` | External monitor. Observes recorder state from outside the hub process and commits it; closure scheme by default, row scheme selectable. |
| `monitor/monitor_wholerow.py` | Whole-row baseline entry point (commits every stored column). |
| `testbed/anchord/` | Append-only anchor daemon, run in a separate container; appends accepted only with a valid HMAC-SHA256 tag. |
| `addons/homeprov_monitor/`, `addons/homeprov_anchor/` | Supervisor add-on manifests for the monitor and the anchor. |
| `exp/rig/` | Commitment schemes, verifier, localization, reconstruction, metrics, statistics, the recorder-mutation primitives (`forge.py`) and the capability record. |
| `exp/stages/` | One module per experiment; each emits a JSON report under `exp/out/`. |
| `exp/out/`, `exp/out_recal/`, `exp/out_precalib/` | Result reports. `exp/out/` is the published arm; see `exp/out/AUTHORITATIVE.md` for which file is authoritative and `exp/out/SCHEME_KEYS.md` for the artifact-key → label map. |
| `results/` | Bundled result units and the laundered-unlock write-up. |
| `analysis/` | Result-processing and benchmarking scripts. |
| `testbed/ha-config/` | Testbed configuration and the defender / measurement integrations (`homeprov`, `homeprov_bench`, `homeprov_e4`, `homeprov_e5`). |
| `testbed/real/` | Real-substrate deployment: `docker-compose.yml`, Mosquitto broker, device simulator, the real-substrate HA config and run scripts. |
| `witness/` | Cross-producer broker-witness script for the deletion-launder signature. |
| `exp/README.md`, `testbed/real/EXPERIMENTS.md` | What each experiment asks and how to run it. |

Every experiment runs in local Docker containers with virtual devices. No
physical device is actuated and no real household is involved.

## What is deliberately not here

**No offensive integrations.** The gap between an attack harness and an
installable extension is the only thing that makes this work publishable without
arming a reader. Four offensive components that ran inside the hub process are
therefore *not* in this repository:

- the integrations that performed the laundering (deletion / re-parenting of a
  committed row);
- the post-commit writes used in the detection runs;
- the write-time strategies (minted contexts and the write-path hook);
- the module-level rebinding that blinded an in-process defender.

The evaluation scripts (`testbed/real/run_experiments.sh`, `testbed/real/run_all.sh`
and some `exp/stages/*.py`) still name these components (`homeprov_s1real`,
`homeprov_ec`, `homeprov_e2`, `homeprov_redteam`): those arms will not run
without them, by design. What takes their place is sufficient for reproduction
and no more: the recorder-mutation primitives in `exp/rig/forge.py`, the twelve
predeclared forgery definitions, the generated-deployment stages that reproduce
each database transformation on synthetic recorders, and the measurement
harnesses (`homeprov_e4`, `homeprov_e5`) that mutate and immediately roll back a
copy of the recorder to read the platform's own renderer. The forgery taxonomy
and the capability records describe the adversary in enough detail to
reimplement it for defensive evaluation.

**No manuscript.** The paper is maintained separately.

**No credentials, no recorder databases, no third-party paper text.** The
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

## Anonymization

This is an anonymized mirror prepared for double-anonymous review.

- Removed: documents that carried venue, review or planning history
  (`EXPERIMENTS.md`, `FEEDBACK_CHECKLIST.md`, `research_design_detailed.md`) and
  the git pre-push hook (`.githooks/`). The reproduction content of the removed
  `EXPERIMENTS.md` is covered by `exp/README.md` and `testbed/real/EXPERIMENTS.md`.
- Replaced: absolute machine paths in result, config and log files — the author's
  home directory and session scratch directories were rewritten to the
  placeholders `<artifact-root>` and `<scratch>`. This is a textual substitution
  of path strings only; **no measured value, result row or number was changed.**
  The result files whose hashes the paper prints (the run-provenance table) do
  not contain any such path and are byte-for-byte unchanged. A few stage reports
  carry an embedded content digest that was computed before the path rewrite; no
  check in this repository re-verifies that field, and it is not quoted anywhere.
- The word "reviewer" and "disclosed" appear in a handful of code comments as
  ordinary vocabulary; no venue, author, institution or identifier is present.
