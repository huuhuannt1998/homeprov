"""R13 (2026-10-08): the monitor's cost on a realistic recorder, read from the live default deployment.

The default deployment (hpr-hass 2026.7.4, purge_keep_days 30, running since 2026-08-31) holds a 30-day recorder. Its
monitor (hpr-monitor:1, row scheme, encoding v1, 5 s interval) logs, every twelfth poll, the time to copy the
recorder, to load the rows of the open window and to fold them into segment roots. This script reads only: the
monitor's log, the sizes of the recorder and of the monitor's state file, and the container's CPU share sampled with
`docker stats` once every 5 s for 60 s. It writes nothing into any container.

    python3 exp/sp2027/r13_monitor_cost.py      # writes exp/out/r13_monitor_cost.json (never overwrites)
"""
import datetime as dt
import hashlib
import json
import os
import statistics
import subprocess
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DST = os.path.join(REPO, "exp", "out", "r13_monitor_cost.json")
C = "hpr-monitor"


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True).stdout


def summ(xs):
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(p * (len(xs) - 1)))]
    return {"n": len(xs), "median": round(statistics.median(xs), 3), "p90": round(q(0.9), 3), "max": round(xs[-1], 3),
            "min": round(xs[0], 3)}


if os.path.exists(DST):
    raise SystemExit("refusing to overwrite " + DST)
SINCE = "24h"     # the recorder has held about 30 days (purge_keep_days 30) throughout this period
ticks = []
_lg = subprocess.run(["docker", "logs", "--since", SINCE, C], capture_output=True, text=True)
for line in _lg.stdout.splitlines() + _lg.stderr.splitlines():
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if "tick" in r and r.get("copy_ms") is not None and r["tick"] > 3:      # skip start-up ticks
        ticks.append(r)
sizes = sh("docker", "exec", C, "sh", "-c",
           "stat -c '%n %s' /cfg/home-assistant_v2.db /cfg/home-assistant_v2.db-wal /scratch/monitor_state.json")
cpu = []
for _ in range(12):
    out = sh("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", C).strip().rstrip("%")
    try:
        cpu.append(float(out))
    except ValueError:
        pass
    time.sleep(5)
out = {
    "item": "R13: monitor cost on a 30-day recorder of the live default deployment",
    "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
    "script": os.path.relpath(os.path.abspath(__file__), REPO),
    "script_sha256": hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest(),
    "monitor": {"container": C, "image": sh("docker", "inspect", C, "--format", "{{.Config.Image}} {{.Image}}").strip(),
                "started": sh("docker", "inspect", C, "--format", "{{.State.StartedAt}}").strip(),
                "interval_s": 5, "scheme": "row (hpr-monitor:1), encoding v1"},
    "sizes_bytes": {l.split()[0]: int(l.split()[1]) for l in sizes.splitlines() if len(l.split()) == 2},
    "per_poll_ms": {"copy": summ([t["copy_ms"] for t in ticks]), "load": summ([t["load_ms"] for t in ticks]),
                    "commit": summ([t["commit_ms"] for t in ticks]),
                    "rows_in_open_window": summ([t["n_nodes"] for t in ticks if t.get("n_nodes")])},
    "logged_polls": len(ticks), "log_window": "last " + SINCE,
    "cpu_percent_one_core_sampled_every_5s_for_60s": ({**summ(cpu), "mean": round(sum(cpu) / len(cpu), 2)}
                                                        if cpu else None),
    "host_load_average": sh("uptime").strip(),
    "caveats": ["The log covers every twelfth poll of the last 24 h; the state-file write after each "
                "accepted append is not in the logged times and is inside the sampled CPU share.",
                "The default monitor commits the row scheme with encoding v1; the closure scheme hashes about 1.4 "
                "times the input (Appendix C), and the copy, which dominates, does not depend on the scheme.",
                "Other workloads ran on the evaluation host while sampling (see host_load_average)."],
}
with open(DST, "x") as fh:
    json.dump(out, fh, indent=1)
print(json.dumps({k: out[k] for k in ("sizes_bytes", "per_poll_ms", "logged_polls",
                                      "cpu_percent_one_core_sampled_every_5s_for_60s", "host_load_average")}, indent=1))
