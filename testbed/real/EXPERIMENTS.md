# The real-substrate experiment suite

Everything runs against the real deployment: eclipse-mosquitto as the broker,
devices announcing over Home Assistant's real MQTT discovery, and automations
instantiated from `motion_light.yaml`, the blueprint the platform ships. No
synthetic demo platform, no hardware, no real household.

## Running it

```bash
cd testbed/real
./run_all.sh --check      # preflight only: touches nothing, tells you if the machine is ready
./run_all.sh --list       # what will run, what is already done, and why anything is pending
./run_all.sh              # run everything still pending, in order
./run_all.sh --only E5    # one stage
./run_all.sh --force      # redo everything, including completed stages
```

**Start with `--check`.** It refuses to run if Docker is down or disk headroom is
under 15 GB, and it warns — loudly — if other container workloads are up. Running
five projects at once is what crashed the machine mid-sweep; this suite drives
five containers for roughly two hours and wants the machine to itself.

**Nothing runs in parallel, deliberately.** The hub is one container with one
SQLite recorder. Two stages mutating it at once interleave their writes and make
the restore unverifiable. Sequential is a correctness requirement, not a
performance choice.

**It resumes.** Each stage is skipped when its output already exists *and passes a
content check*. Kill it, restart it, and it picks up where it stopped.

## Stages

| Stage | ~min | Establishes |
|---|---|---|
| `binding` | 1 | The scenario's entities resolve. If this fails, every later stage silently measures nothing. |
| `E25` | 2 | Real-vs-generated deployment characterisation — the generator's parent-context fraction against the real one. |
| `E4` | 15 | Renderer dependency closure: which fields the logbook actually reads. |
| `E4ROLES` | 10 | Conditional-role retests, and which roles this substrate exhibits at all. |
| `E4PARENT` | 10 | Constructive test for `states.context_parent_id_bin`. |
| `E5` | 45 | Twelve-variant renderer-backed sweep across three configurations. |
| `E2` | 10 | In-process defender subversion, and the external monitor catching what it misses. |
| `S1` | 35 | The flagship laundering, three configurations. |
| `BENIGN` | 10 | False alarms under real device churn. |

Roughly 2h20 if everything is pending.

## The failure mode this suite is built against

**A stage that measures nothing writes a file and exits zero.** That has cost this
project several runs and one nearly went into the paper:

- `e4_real_roles.json` held three `null`s and read as a completed stage. It was
  not a finding that the fields do not matter — the substrate never exhibited the
  roles that reach them.
- The first real E5 run reported `full_laundering` at 0/40 with `changed=0` on
  seven of twelve variants. Its targets were the motion-light automations turning
  their own lights on, already attributed to the automation the forgery was meant
  to move them onto. Nothing to launder. Meanwhile S1, on the same substrate,
  reached 30/30 with the same two operations — two of our own experiments
  contradicting each other, and E5 was the wrong one.
- An aggregator counted `t["misattributed"]`; no trial carries that key. Every
  configuration would have scored 0/10 while the component's own ack said 10/10.

So `run_all.sh` does not treat "the file exists" as "the stage ran". Each stage
carries a **validity predicate** over its own output, and a stage that exits
cleanly but fails its predicate is reported as a failure with the predicate
printed. `_check_stage.py` evaluates them; `--list` shows exactly why anything is
pending.

If you add a stage, give it a predicate that would be false for a run that
measured nothing. A predicate of `True` is worse than none, because it looks like
a check.

## What is deliberately not here

- **Real households.** Out of scope by constraint: local containers and virtual
  devices only, on one laptop, no new hardware.
- **Cross-version dynamic confirmation.** Only 2026.7.4 gets the mutation test.
  Components reached transitively from the demo platform stall during setup on a
  network isolated enough to satisfy the testbed constraint, so the other three
  releases get the weaker static instrument, labelled as such.
- **The offensive components.** `homeprov_s1real` and `homeprov_e2` are
  gitignored. The forgery taxonomy, capability records and recorder-mutation
  primitives in `exp/rig/forge.py` are enough to reimplement them for defensive
  evaluation.

## After a run

- `exp/out/run_all_manifest.json` — what ran, status, wall time.
- `exp/out/run_all_logs/<stage>.log` — full output per stage.
- `./run_all.sh --list` — the fastest way to see what still needs doing.
