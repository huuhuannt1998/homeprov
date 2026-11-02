"""E10 arm E (review r5 Z12; R2 W2, R3 W7; META item 11): the monitor's per-poll cost under a Raspberry Pi 4-class CPU,
memory and block-I/O cap, with the SD card as the storage.

It reuses exp/sp2027/e9_cost_scale.py UNCHANGED (its synthetic recorders k1 / k5 / k15 of about 0.19, 0.96 and 2.94 GB,
its writer -- the recorder's own rows of one day earlier, one transaction per second --, its in-container harness that
times every phase of monitor.tick() and reads /proc/self/io and the cgroup's io.stat, and its summarizer). Only the
monitor container's limits, the container-name prefix and the run tags change: the C1 limits are module globals there
(LIMITS, PREFIX); this file sets them per profile, and adds the I/O-operation limits and --memory-swap, which the C1 code
does not pass, by inserting them into the one `docker run` of the monitor container (wrap_sh below; nothing else is
touched). The monitor image is the hardened E10 monitor (hpr-monitor:e10, built by testbed/e10/run_e10.sh's preflight),
so within this arm the profiles differ only in their limits.

PROFILES. Every number below that is not from a saved result is an ASSUMPTION, stated as such (nothing was read from a
datasheet or a measurement in this session; the lead should replace each with a cited value before registration, open
question E1 in drafts/round13/E10_ADDENDUM_R5.md):
  ref     the C1 limits (exp/out/e9_cost_scale*.json limits_monitor_container): 1 CPU, 1 GiB, 100 MB/s read, 50 MB/s
          write, no IOPS limit -- the reference, so the Pi-4 runs compare with the same harness and image
  pi4     cpus 0.25: ASSUMPTION that one Cortex-A72 core at 1.5 GHz (the Raspberry Pi 4 Model B's CPU class, from
          the product's public description; not read here) has at most about a quarter of the single-thread speed of
          one core of this Mac (Apple arm64; uname in the result files); memory 512 MiB, swap off: ASSUMPTION of the
          share left to the monitor on a 2 GB Pi 4 that also runs Home Assistant; read 40 MB/s, write 10 MB/s,
          1,500 read and 500 write IOPS: ASSUMPTION from the SD Association's A1 application-performance class minimums
          (1,500 / 500 random 4 KiB IOPS) and Class 10 / U1 sequential-write minimum (10 MB/s), and a typical Pi 4 SD
          read rate of about 40 MB/s -- not verified against the specification or a Pi in this session
  pi4cpu_half, pi4cpu_eighth   the pi4 profile with cpus 0.5 and 0.125: a sensitivity bracket on the CPU assumption
Docker's CPU quota throttles in 100 ms periods (CFS), which is not a uniformly slower core: short phases can stall for
up to the rest of a period. This is stated as a threat to validity, not corrected for.

MATRIX (registered; 10 runs, 30 measured polls after 3 warm-up polls each, PERIOD 5 s, as C1):
  direct-read, quick_check every 720 polls (the recommended configuration): k1, k5, k15 x {ref, pi4}
  copy mode, quick_check every poll (E9's M-copy):                         k1 x {ref, pi4}
  direct-read, qc 720, k1 x {pi4cpu_half, pi4cpu_eighth}
Outcomes per run: per-poll total time (median, p90, max), the poll interval T = PERIOD + poll time, overruns (polls
longer than PERIOD, and longer than GAP_S = 30 s, which open an observation break under D1), unobservable polls and
why, bytes written per poll and per hour (process and cgroup), peak memory if reported; per profile pair the ratio
pi4 / ref of the median poll time.

    python3 exp/sp2027/e10_pi4_cost.py matrix                    # print the registered runs (no Docker)
    python3 exp/sp2027/e10_pi4_cost.py run [--only TAG ...]      # each run through e9_cost_scale.run (Docker)
    python3 exp/sp2027/e10_pi4_cost.py summarize                 # exp/out/e10_pi4_cost_<profile>.json + e10_pi4_cost.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
DST = os.path.join(OUT, "e10_pi4_cost.json")
PREFIX = "e10e"
IMAGE = "hpr-monitor:e10"
NOT_BEFORE = 1792425660                         # 2026-10-19T16:01:00Z
GAP_S, PERIOD = 30.0, 5.0
_CORE = ("cpus", "memory", "device_read_bps", "device_write_bps", "device")
PROFILES = {
    "ref": {"cpus": "1", "memory": "1g", "device_read_bps": "100mb", "device_write_bps": "50mb", "device": "/dev/vda"},
    "pi4": {"cpus": "0.25", "memory": "512m", "memory_swap": "512m", "device_read_bps": "40mb",
            "device_write_bps": "10mb", "device_read_iops": "1500", "device_write_iops": "500", "device": "/dev/vda"},
}
PROFILES["pi4cpu_half"] = dict(PROFILES["pi4"], cpus="0.5")
PROFILES["pi4cpu_eighth"] = dict(PROFILES["pi4"], cpus="0.125")
ASSUMED = {"pi4": ["cpus", "memory", "memory_swap", "device_read_bps", "device_write_bps", "device_read_iops",
                   "device_write_iops"], "pi4cpu_half": "as pi4", "pi4cpu_eighth": "as pi4"}
MATRIX = ([("ref", "direct", k, "720") for k in (1, 5, 15)] + [("pi4", "direct", k, "720") for k in (1, 5, 15)]
          + [("ref", "copy", 1, "1"), ("pi4", "copy", 1, "1")]
          + [("pi4cpu_half", "direct", 1, "720"), ("pi4cpu_eighth", "direct", 1, "720")])


def tag_of(profile, mode, k, qc):
    return "e10pi4_%s_k%d_%s_qc%s" % (profile, k, mode, qc)


def cost_scale():
    spec = importlib.util.spec_from_file_location("e9_cost_scale", os.path.join(HERE, "e9_cost_scale.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def extra_args(p):
    """The limits C1's run() does not pass (inserted into the monitor's docker run)."""
    out = []
    if p.get("memory_swap"):
        out += ["--memory-swap", p["memory_swap"]]
    if p.get("device_read_iops"):
        out += ["--device-read-iops", "%s:%s" % (p["device"], p["device_read_iops"])]
    if p.get("device_write_iops"):
        out += ["--device-write-iops", "%s:%s" % (p["device"], p["device_write_iops"])]
    return out


def wrap_sh(orig, extra, monitor_name):
    """C1's sh() with `extra` inserted right after `--name <monitor>` in the monitor container's `docker run -d`; every
    other command passes through unchanged."""
    def sh(*args, **kw):
        a = list(args)
        if a[:3] == ["docker", "run", "-d"] and "--name" in a and a[a.index("--name") + 1] == monitor_name:
            i = a.index("--name") + 2
            a = a[:i] + list(extra) + a[i:]
        return orig(*a, **kw)
    sh.__wrapped__ = orig
    return sh


def install(CS, profile):
    p = PROFILES[profile]
    CS.LIMITS = {k: p[k] for k in _CORE}
    CS.PREFIX = PREFIX
    orig = getattr(CS.sh, "__wrapped__", CS.sh)
    CS.sh = wrap_sh(orig, extra_args(p), "%s-monitor" % PREFIX)
    return p


def overruns(rundir):
    """Measured polls longer than PERIOD and than GAP_S, and the poll interval T = PERIOD + poll time, from the run's
    monitor.jsonl (the harness's own lines)."""
    tot = []
    p = os.path.join(rundir, "monitor.jsonl")
    if os.path.exists(p):
        for line in open(p):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if "poll" in r and not r.get("warmup"):
                tot.append(float(r["total_ms"]) / 1000.0)
    tot.sort()
    med = tot[len(tot) // 2] if tot else None
    return {"n": len(tot), "over_period": sum(1 for x in tot if x > PERIOD), "over_gap_s": sum(1 for x in tot if x > GAP_S),
            "max_s": tot[-1] if tot else None, "poll_interval_median_s": (PERIOD + med) if med is not None else None}


def merge(per_profile, run_dirs):
    """The arm's result document from the per-profile summaries ({profile: summary JSON}) and the run directories
    ({tag: dir}): per run the cost and overruns; per (mode, k) the pi4 / ref median ratio."""
    runs = {}
    for prof, doc in per_profile.items():
        for tag, r in (doc.get("runs") or {}).items():
            tot = ((r.get("per_poll_ms") or {}).get("total") or {})
            mw = r.get("measured_window") or {}
            runs[tag] = {"profile": prof, "mode": r.get("mode"), "k": r.get("k"), "limits": r.get("limits"),
                         "extra_limits": extra_args(PROFILES[prof]), "per_poll_total_ms": tot,
                         "unobservable_polls": r.get("unobservable_polls"), "reasons": r.get("unobservable_reasons"),
                         "bytes_written_per_hour_proc": mw.get("bytes_written_per_hour_proc"),
                         "bytes_written_per_hour_cgroup": mw.get("bytes_written_per_hour_cgroup"),
                         "write_bytes_per_poll": (r.get("per_poll_bytes") or {}).get("proc_write_bytes"),
                         "overruns": overruns(run_dirs[tag]) if tag in run_dirs else None}
    ratios = {}
    for (mode, k) in sorted({(r["mode"], r["k"]) for r in runs.values()}):
        ref = [r for r in runs.values() if r["profile"] == "ref" and (r["mode"], r["k"]) == (mode, k)]
        for prof in ("pi4", "pi4cpu_half", "pi4cpu_eighth"):
            pi = [r for r in runs.values() if r["profile"] == prof and (r["mode"], r["k"]) == (mode, k)]
            if ref and pi and ref[0]["per_poll_total_ms"].get("median") and pi[0]["per_poll_total_ms"].get("median"):
                ratios["%s_k%d_%s_over_ref" % (mode, k, prof)] = round(pi[0]["per_poll_total_ms"]["median"]
                                                                     / ref[0]["per_poll_total_ms"]["median"], 3)
    return {"runs": runs, "median_ratio": ratios}


def cmd_matrix(_a):
    for prof, mode, k, qc in MATRIX:
        print(tag_of(prof, mode, k, qc), json.dumps({"profile": prof, "mode": mode, "k": k, "qc": qc,
                                                     "limits": PROFILES[prof], "extra": extra_args(PROFILES[prof])}))


def cmd_run(a):
    if time.time() < NOT_BEFORE:
        raise SystemExit("REFUSING: before 2026-10-19T16:01:00Z (E9 owns Docker on this Mac)")
    CS = cost_scale()
    for prof, mode, k, qc in MATRIX:
        tag = tag_of(prof, mode, k, qc)
        if a.only and tag not in a.only:
            continue
        install(CS, prof)
        if a.smoke:                                  # smokes: 1 + 3 polls, tags *_smoke (never summarized)
            tag += "_smoke"
        ns = argparse.Namespace(k=str(k), mode=mode, image=a.image, tag=tag,
                                env=["HOMEPROV_QUICK_CHECK_EVERY=%s" % qc], rw_mount=False,
                                polls=3 if a.smoke else None, warmup=1 if a.smoke else None)
        print("== run", tag, flush=True)
        CS.run(ns)
        rd = os.path.join(CS.EXP, "c1", "runs", tag)
        with open(os.path.join(rd, "e10_profile.json"), "x") as fh:
            json.dump({"profile": prof, "limits": PROFILES[prof], "extra_args": extra_args(PROFILES[prof]),
                       "assumed": ASSUMED.get(prof, [])}, fh, indent=1)


def cmd_summarize(a):
    if os.path.exists(DST):
        raise SystemExit("REFUSING: %s exists" % DST)
    CS = cost_scale()
    per, dirs = {}, {}
    for prof in PROFILES:
        tags = [tag_of(*m) for m in MATRIX if m[0] == prof]
        rds = [os.path.join(CS.EXP, "c1", "runs", t) for t in tags if os.path.exists(os.path.join(CS.EXP, "c1", "runs", t))]
        if not rds:
            continue
        dirs.update({os.path.basename(d): d for d in rds})
        CS.LIMITS = {k: PROFILES[prof][k] for k in _CORE}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(["E10 arm E (review r5): profile %s; limits %s plus %s; assumed values: %s" % (
                prof, CS.LIMITS, extra_args(PROFILES[prof]), ASSUMED.get(prof, "none (the C1 limits)")),
                "Docker's CPU quota throttles in 100 ms CFS periods; a quota is not a uniformly slower core.",
                "Monitor image hpr-monitor:e10 (the hardened E10 monitor); writer, recorders and harness as C1."], fh)
        out = os.path.join(OUT, "e10_pi4_cost_%s.json" % prof)
        CS.summarize(argparse.Namespace(runs=rds, out=out, item="E10 arm E: monitor per-poll cost, profile %s" % prof,
                                        caveats_file=fh.name, reference_runs=None))
        per[prof] = json.load(open(out))
    doc = {"experiment": "E10 arm E: per-poll cost under a Raspberry Pi 4-class cap (review r5 Z12)",
           "profiles": PROFILES, "assumed_values": ASSUMED, "matrix": [tag_of(*m) for m in MATRIX],
           "sources": {p: "exp/out/e10_pi4_cost_%s.json" % p for p in per}, **merge(per, dirs),
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(DST, "x") as fh:
        json.dump(doc, fh, indent=1)
    print("wrote", DST)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("matrix")
    r = sub.add_parser("run")
    r.add_argument("--only", nargs="*")
    r.add_argument("--image", default=IMAGE)
    r.add_argument("--smoke", action="store_true")
    sub.add_parser("summarize")
    a = ap.parse_args()
    return {"matrix": cmd_matrix, "run": cmd_run, "summarize": cmd_summarize}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
