# HomeProv

Tamper-evident actuation provenance for Home Assistant.

A home-automation hub that answers "what caused this" creates evidence worth
forging. Home Assistant derives that answer from three columns of its recorder
database — `context_id_bin`, `context_parent_id_bin`, `context_user_id_bin` —
and `context_parent_id_bin` is not a description of the causal edge but the edge
itself, an ordinary mutable column bound to nothing. Any integration running in
the hub process can rewrite it.

This repository holds the defensive implementation and the evaluation harness.

## What is here

| Path | What it is |
|---|---|
| `monitor/` | External monitor. Observes recorder state from outside the hub process and commits it. |
| `testbed/anchord/` | Append-only anchor daemon, run in a separate container. |
| `exp/rig/` | Commitment schemes, verifier, localization, reconstruction, metrics, statistics. |
| `exp/stages/` | One module per experiment; each emits a JSON report under `exp/out/`. |
| `exp/out/` | Result reports, including the renderer dependency closure. |
| `testbed/ha-config/custom_components/homeprov/` | The defender integration. |
| `testbed/ha-config/custom_components/homeprov_e4/` | Renderer dependency-closure measurement harness. |
| `testbed/ha-config/custom_components/homeprov_bench/` | Benign-workload driver for false-alarm measurement. |
| `analysis/`, `results/` | Result processing and bundled result units. |
| `EXPERIMENTS.md` | What each experiment asks and how to run it. |

Every experiment runs in local Docker containers with virtual devices. No
physical device is actuated and no real household is involved.

## What is deliberately not here

**No deployable malicious integration.** The gap between an attack harness and
an installable extension is the only thing that makes this work publishable
without arming a reader, so the adversary integrations are not in this
repository. What takes their place is sufficient for reproduction and no more:
the recorder mutation primitives in `exp/rig/forge.py`, the twelve predeclared
forgery definitions, synthetic attack traces, and container-scoped scripts that
reproduce each database transformation. The forgery taxonomy and the capability
records describe the adversary in enough detail to reimplement it for defensive
evaluation.

**No manuscript.** The paper is maintained separately.

**No credentials, no recorder databases, no third-party paper text.**

## Reproducing

Each stage under `exp/stages/` is self-contained and writes a JSON report to
`exp/out/`. Results that need a live platform drive a Home Assistant container
through a command file; `exp/e6_crossversion.sh` shows the pattern, including
the named-volume requirement (SQLite writes from a second process across a macOS
bind mount return `SQLITE_IOERR` rather than blocking).

Every result ships with a machine-readable capability record stating the exact
powers the adversary held when it was produced. Anything absent from that record
was not assumed.
