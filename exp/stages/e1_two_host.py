"""E1 (round 12, 2026-10-08): TWO-HOST PLACEMENT -- aggregate one run of testbed/e1/run_e1.sh.

Detection is scored by the SHIPPED aggregator, exp/stages/e_ps_detection.py, with its scoring code unchanged. Only
transport and labels are substituted, because the hub is no longer a local container:

  - the recorder snapshot is a consistent SQLite backup taken inside host A's Core container over SSH
    (testbed/e1/replicator/hub_backup.py, the same backup API the shipped snapshot uses);
  - the anchor and monitor are the containers e1-anchord and e1-monitor on host B;
  - the capability record states the privileged Core and the two-host placement.

The snapshot's time bound is the time the snapshot was REQUESTED (this host's clock), so no root anchored from a
later replica is compared with it.

Then exp/out/<tag>_two_host.json records what the placement adds, from the run's own logs and chain:

  - replication: cycles, failures, period, replica age at install (install minus request), and request-to-backup
    time on the hub's clock (transport plus clock skew);
  - observation window, with the definitions of exp/sp2027/r6_window_latency_real.py (Section 7's window): for each
    anchored one-second segment of the run whose root still recomputes, close-to-anchor = receipt minus segment end,
    and for each of its rows write-to-anchor = receipt minus row timestamp;
  - the placement facts from the run's configuration log (privileged Core, hub probes of the anchor).

    E1_SP=<run dir> python3 exp/stages/e1_two_host.py --tag e1_psr_clo porch hallway kitchen
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")
sys.path.insert(0, os.path.join(ROOT, "exp"))

VMDIR = os.environ.get("E1_VMDIR", "<artifact-root>-e1vm")
SSH = ["ssh", "-F", os.path.join(VMDIR, "ssh_config"), "e1a"]
HUB_LABEL = "e1-hostA-homeassistant"           # host A's container is "homeassistant", reached over SSH
MAGIC = b"SQLite format 3\x00"

# The SAME module objects e_ps_detection uses (it imports stages.e_c_write_time); importing the files under another
# name would create second copies whose globals the scoring code never reads.
import stages.e_c_write_time as EC              # noqa: E402
import stages.e_ps_detection as PS              # noqa: E402
from rig import capability                       # noqa: E402


def _ssh(cmd: str, binary=False):
    p = subprocess.run(SSH + [cmd], capture_output=True, timeout=300)
    return p.stdout if binary else p.stdout.decode(errors="replace").strip()


def snapshot_recorder_host_a():
    dst = os.path.join(EC.SCRATCH, "recorder.db")
    os.makedirs(EC.SCRATCH, exist_ok=True)
    t_req = time.time()
    data = _ssh("docker exec homeassistant python3 /config/.e1_hub_backup.py", binary=True)
    if not data.startswith(MAGIC):
        raise SystemExit("host A recorder snapshot failed (%d bytes)" % len(data))
    with open(dst, "wb") as fh:
        fh.write(data)
    for side in ("-wal", "-shm"):
        if os.path.exists(dst + side):
            os.remove(dst + side)
    return dst, t_req


def sh(cmd):
    if cmd.startswith("docker inspect %s " % HUB_LABEL):
        return _ssh(cmd.replace(HUB_LABEL, "homeassistant", 1))
    return EC.sh(cmd)


class _Capability:
    """capability.record with the privileged Core and the two-host placement stated."""

    @staticmethod
    def record(**kw):
        kw["constraints"] = {**(kw.get("constraints") or {}), "host_root": True,
                             "host_root_scope": "host A only: Core runs privileged on Home Assistant OS (all "
                                                "capabilities, host A's block devices); the monitor, its key and "
                                                "the anchor are on host B"}
        kw["substrate"] = {"kind": "Home Assistant OS 18.3 VM (host A, privileged Core); monitor, anchor and "
                                   "replicator on Docker Desktop's VM (host B), a second VM on the same Mac",
                           "monitor": "shipped external monitor (closure, v2) reading a replica copied every 2 s",
                           "anchor": "shipped append-only anchor daemon, authenticated"}
        return capability.record(**kw)

    stamp = staticmethod(capability.stamp)


def _q(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def _summary(xs):
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "median": round(statistics.median(xs), 3), "p90": round(_q(xs, 0.9), 3),
            "p99": round(_q(xs, 0.99), 3), "max": round(max(xs), 3), "min": round(min(xs), 3)}


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def meta_lines(sp):
    return [l.rstrip("\n") for l in open(os.path.join(sp, "auth_meta.log"))]


def two_host(tag, sp, det_path):
    det = json.load(open(det_path))
    t0, t1 = det["window"]["t_start"], det["window"]["t_end"]
    tsnap = det["window"]["recorder_snapshot_at"]

    # Replication log.
    cyc = [json.loads(l) for l in open(os.path.join(sp, "replog", "replication.jsonl")) if l.strip()]
    run = [c for c in cyc if t0 <= c["t_req"] <= t1]
    ok = [c for c in run if c.get("ok")]
    gaps = [b["t_req"] - a["t_req"] for a, b in zip(ok, ok[1:])]
    age = [c["t_installed"] - c["t_req"] for c in ok]
    req_to_backup = [c["hub_t_backup"] - c["t_req"] for c in ok]
    fail_reasons = collections.Counter((c.get("err") or "rc=%s" % c.get("rc"))[:80] for c in run if not c.get("ok"))
    # Longest stretch without a fresh replica (e.g. while Core restarted between configurations).
    longest = max(gaps) if gaps else None

    # Observation window, r6 definitions, on the recorder snapshot and the chain of this run.
    sys.path.insert(0, os.path.join(ROOT, "monitor"))
    M = EC._load_monitor()
    db = os.path.join(EC.SCRATCH, "recorder.db")
    lines = [l for l in open(os.path.join(sp, "chain.jsonl")) if l.strip()]
    first = {}
    for line in lines:
        rec = json.loads(line)
        p = rec.get("payload") or {}
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap) or p.get("evidence_unobservable"):
            continue
        for g, segs in (p.get("sealed") or {}).items():
            for s, v in (segs or {}).items():
                first.setdefault((g, str(s)), (rec.get("recv_ts"), p.get("ts"), p.get("monitor_ts"),
                                               v.get("acc"), v.get("n"), p.get("encoding", "v1")))
    nodes = M.load(db, since=(int(t0 // 3600) - 1) * 3600.0)
    by = collections.defaultdict(list)
    for n in nodes:
        by[str(int(n[0] // 1))].append(n)
    phis = {e: M.commit(nodes, encoding=e)["second"] for e in {f[5] for f in first.values()}}
    # Configuration phases from the run log ("-- configuration: X --" lines): each phase runs from its line to the
    # next phase's line, the last one to the end of the run. Used only to break the window down by phase.
    import datetime as _dt
    phases = []
    for l in meta_lines(sp):
        if "-- configuration: " in l:
            t = _dt.datetime.strptime(l[:20], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp()
            phases.append([l.split("-- configuration: ")[1].split(" --")[0], t, None])
    for k, ph in enumerate(phases):
        ph[2] = phases[k + 1][1] if k + 1 < len(phases) else t1
    by_phase = {ph[0]: {"close": [], "write": [], "from": ph[1], "to": ph[2]} for ph in phases}
    close, write, used, skipped = [], [], 0, collections.Counter()
    clock_lag = []
    for (g, s), (recv, pts, mts, acc, n, enc) in first.items():
        if g != "second" or not (t0 - 1 <= int(s) <= t1 + 1):
            continue
        got = phis[enc].get(s)
        if not got or got["acc"] != acc or got["n"] != n:
            skipped["root_differs_now"] += 1
            continue
        if recv is None:
            skipped["no_recv_ts"] += 1
            continue
        used += 1
        close.append(recv - (int(s) + 1))
        write.extend(recv - x[0] for x in by[s])
        for name, ph in by_phase.items():
            if ph["from"] <= int(s) < ph["to"]:
                ph["close"].append(recv - (int(s) + 1))
                ph["write"].extend(recv - x[0] for x in by[s])
        if mts is not None and pts is not None:
            clock_lag.append(mts - pts)

    # The paper's counting rule (reproduce/verify_all.py, as E3's scorer uses it): a trial is flagged when its
    # one-second segment is a violation, attributable when that segment did not gain rows after its seal; the benign
    # floor is over anchored one-second segments that no trial touched, where a trial touches every one-second
    # segment holding a row it wrote (touched_segments). The shipped aggregator above counts only the judged row's
    # second as touched, so its floor can include seconds of rows the arm itself rewrote.
    sys.path.insert(0, os.path.join(ROOT, "reproduce"))
    import verify_all as V                                                   # noqa: PLC0415
    W = dict(M.GRAN)
    vroots = V.anchored_roots(lines, t0, tsnap)
    vencs = sorted({a["encoding"] for a in vroots.values()})
    vphi = M.commit(M.load(db, since=(int(t0 // 3600) - 1) * 3600.0), encoding=vencs[0])
    verd = V.verify_window(vphi, vroots, W, t0, t1)
    vtrials = [t for t in det["trials"] if not (t.get("err") or t.get("error"))]
    fl = at = am = 0
    for t in vtrials:
        seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
        v = verd.get(("second", str(seg))) if seg is not None else None
        if not (v and v["violation"]):
            continue
        fl += 1
        if v["delta_n"] is not None and v["delta_n"] > 0:
            am += 1
        else:
            at += 1
    touched = V.touched_segments(vtrials, V.ro_connect(db), W)
    paper_floor = {}
    for g in ("second", "minute"):
        segs = [s2 for (gg, s2) in verd if gg == g and s2 not in touched[g]]
        k = sum(1 for s2 in segs if verd[(g, s2)]["violation"])
        def _mech(v):
            d = v.get("delta_n")
            return ("segment_vanished" if d is None else "rows_arrived_after_seal" if d > 0
                    else "rows_removed_after_seal" if d < 0 else "content_changed_in_place")
        mech = collections.Counter(_mech(verd[(g, s2)]) for s2 in segs if verd[(g, s2)]["violation"])
        paper_floor[g] = {"k": k, "n": len(segs), "ci": V.cp(k, len(segs)), "mechanisms": dict(mech)}
    paper_rule = {"rule": "reproduce/verify_all.py: anchored_roots, verify_window, touched_segments, cp",
                  "encoding": vencs, "n_trials": len(vtrials), "flagged": fl, "attributable": at, "ambiguous": am,
                  "attributable_ci": V.cp(at, len(vtrials)), "benign_floor": paper_floor,
                  "verify_all_py_sha256": _sha(os.path.join(ROOT, "reproduce", "verify_all.py"))}

    r6_path = os.path.join(OUT, "r6_window_latency_real.json")
    r6 = json.load(open(r6_path))
    meta = meta_lines(sp)
    pick = lambda key: next((l.split(key, 1)[1].strip() for l in meta if key in l), None)
    out = {
        "experiment": "E1: two-host placement (round 12, 2026-10-08)",
        "tag": tag,
        "run_date": _dt.datetime.fromtimestamp(t0, _dt.timezone.utc).strftime("%Y-%m-%d"),
        "placement": {
            "host_a": "Home Assistant OS 18.3 (generic-aarch64) in a QEMU/HVF VM on the evaluation Mac; Core run by "
                      "the Supervisor",
            "host_b": "Docker Desktop's Linux VM on the same Mac, standing in for another host: anchor, monitor, "
                      "replicator (and the MQTT broker and device simulator)",
            "core_container": pick("hostA_core:"),
            "core_privilege_on_hostA": pick("core_privilege_on_hostA:"),
            "probe_from_hub": pick("probe_from_hub:"),
            "key_fingerprint_sha256_16": pick("key_fingerprint_sha256_16:"),
            "clock_skew_check": pick("clock_skew:"),
        },
        "detection_file": {"path": os.path.relpath(det_path, ROOT), "sha256": _sha(det_path)},
        "detection": {k: {kk: vv for kk, vv in det[k].items() if kk != "hit_detail"}
                      for k in ("homeprov_detection_second", "homeprov_detection_minute")},
        "renderer_confirmed_misattribution": det["renderer_confirmed_misattribution"],
        "benign_violation_floor_shipped_aggregator": det["benign_violation_floor"],
        "paper_counting_rule": paper_rule,
        "n_trials": det["n_trials"], "n_valid": det["n_valid"],
        "replication": {
            "period_target_s": 2.0,
            "cycles_in_run": len(run), "cycles_ok": len(ok), "cycles_failed": len(run) - len(ok),
            "failure_reasons": dict(fail_reasons),
            "interval_between_installed_replicas_s": _summary(gaps),
            "longest_interval_s": None if longest is None else round(longest, 3),
            "replica_age_at_install_s": _summary(age),
            "request_to_backup_start_on_hub_clock_s": _summary(req_to_backup),
            "replica_bytes_last": ok[-1]["bytes"] if ok else None,
        },
        "observation_window": {
            "definitions": "exp/sp2027/r6_window_latency_real.py (Section 7's window): close-to-anchor = anchor "
                           "receipt minus segment end; write-to-anchor = anchor receipt minus row timestamp; only "
                           "one-second segments whose recomputed root equals the anchored root",
            "segments_used": used, "segments_skipped": dict(skipped),
            "close_to_anchor_s": _summary(close), "write_to_anchor_s": _summary(write),
            "monitor_seal_minus_replica_request_s": _summary(clock_lag),
            "by_configuration": {name: {"from_utc": _dt.datetime.fromtimestamp(ph["from"], _dt.timezone.utc).strftime("%H:%M:%S"),
                                        "to_utc": _dt.datetime.fromtimestamp(ph["to"], _dt.timezone.utc).strftime("%H:%M:%S"),
                                        "close_to_anchor_s": _summary(ph["close"]),
                                        "write_to_anchor_s": _summary(ph["write"])}
                                 for name, ph in by_phase.items()},
            "host_load": {"before": pick("load_before:"), "after": pick("load_after:"),
                          "note": "An unrelated workload ran on the evaluation host from before the run until about "
                                  "01:25 UTC, when the PI stopped it; the monitor's per-poll load of the replica took "
                                  "up to 4.6 s during it and 23-50 ms after it (monitor.log, every twelfth poll). The "
                                  "configuration phases include the hub restarts between configurations, during which "
                                  "no replica is taken."},
            "single_host_reference": {"file": "exp/out/r6_window_latency_real.json", "sha256": _sha(r6_path),
                                      "pooled": r6["pooled"], "e_psr_clo": r6["per_run"].get("e_psr_clo")},
        },
        "inputs": {"chain": {"file": "exp/out/%s_anchor_chain.jsonl.gz" % tag,
                             "sha256_uncompressed": _sha(os.path.join(sp, "chain.jsonl"))},
                   "recorder_snapshot_sha256": _sha(db),
                   "replication_log_sha256": _sha(os.path.join(sp, "replog", "replication.jsonl"))},
        "code": {p: _sha(os.path.join(ROOT, p)) for p in (
            "exp/stages/e1_two_host.py", "exp/stages/e_ps_detection.py", "exp/stages/e_c_write_time.py",
            "monitor/monitor.py", "testbed/e1/replicator/replicator.py", "testbed/e1/replicator/hub_backup.py",
            "testbed/e1/run_e1.sh")},
        "caveats": [
            "Both hosts are virtual machines on one Mac; the network between them is the Mac's loopback through the "
            "QEMU gateway, so replication latency is lower than between two physical hosts would be.",
            "Host A runs Core 2026.10.0 (the release Home Assistant OS installed), the single-host runs 2026.7.4.",
            "The replica is a full consistent copy each cycle; its cost grows with the recorder.",
        ],
    }
    dst = os.path.join(OUT, "%s_two_host.json" % tag)
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({"detection_second": out["detection"]["homeprov_detection_second"].get("k"),
                      "n": out["detection"]["homeprov_detection_second"].get("n"),
                      "write_to_anchor": out["observation_window"]["write_to_anchor_s"],
                      "close_to_anchor": out["observation_window"]["close_to_anchor_s"],
                      "replication": {k: out["replication"][k] for k in ("cycles_ok", "cycles_failed",
                                                                         "longest_interval_s")}}, indent=1))
    print("  ->", dst)
    return out


def main():
    args = sys.argv[1:]
    tag = "e1_psr_clo"
    if "--tag" in args:
        i = args.index("--tag")
        tag = args[i + 1]
        args = args[:i] + args[i + 2:]
    only = "--two-host-only" in args          # recompute the derived file from the saved run (no rescoring)
    args = [a for a in args if a != "--two-host-only"]
    rooms = args or ["porch", "hallway", "kitchen"]
    sp = os.environ.get("E1_SP") or os.path.join(os.path.dirname(ROOT), "HOMEPROV-P13-exp", "e1", tag)
    if only:
        two_host(tag, sp, os.path.join(OUT, "%s_detection.json" % tag))
        return

    for mod in (EC, PS):
        mod.HUB, mod.ANCHORD, mod.MONITOR = HUB_LABEL, "e1-anchord", "e1-monitor"
    assert PS.anchored_roots.__globals__["ANCHORD"] == "e1-anchord"
    PS.snapshot_recorder = snapshot_recorder_host_a
    PS.sh = sh
    PS.capability = _Capability
    PS.main(rooms, tag=tag)
    two_host(tag, sp, os.path.join(OUT, "%s_detection.json" % tag))


if __name__ == "__main__":
    main()
