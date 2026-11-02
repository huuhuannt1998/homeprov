"""E5 (round 13): LINKED ANCHOR WITH A HEAD WITNESS -- aggregate one run of testbed/e5/run_e5.sh.

Detection is scored by the SHIPPED aggregator, exp/stages/e_ps_detection.py, with its scoring code unchanged and with
exactly the substitutions E1 made (exp/stages/e1_two_host.py): the recorder snapshot is a consistent SQLite backup
taken inside host A's Core container over SSH, the anchor and the monitor are the containers e5-anchord and e5-monitor
on host B, and the capability record states the privileged Core and the placement. The SAME module objects that
e_ps_detection uses are patched (it imports stages.e_c_write_time), so its anchored_roots() reads e5-anchord's chain.

Then exp/out/<tag>_linked.json records what the linked anchor and the witness add, from the run's own files:

  - link check: testbed/anchord/chainverify.py over the saved chain (every record linked to the previous one);
  - witness check: the chain against the witness's last head, taken as headwitness.py takes it (the head with the
    highest sequence number in its own log, which GET /head returned at the end of the run), and every head the
    witness accepted against the chain record of that sequence number; refused forks; sequence numbers never
    witnessed;
  - controls on copies of the saved chain: a truncated tail, an unrelinked root rewrite and a relinked root rewrite
    (what the anchor host itself could produce), each checked alone and against the witness head;
  - push latency: the anchor's synchronous push time as returned in its append replies (in the monitor's log, which
    keeps ticks 1-3 and every twelfth tick), and witness receipt minus anchor receipt for every head (two clocks:
    Docker's VM and the Mac; their offset is measured in the run log);
  - placement facts from the run log (privileged Core, hub probes of the anchor and of the witness, key fingerprints),
    the replication summary, and SHA-256 of every input and of the code.

    E5_SP=<run dir> EC_SCRATCH=<run dir>/ps_verify python3 exp/stages/e5_linked.py --tag e5_psr_lnk porch hallway kitchen
    ... --linked-only      recompute <tag>_linked.json from an existing <tag>_detection.json (no rescoring)

Never overwrites an output.
"""
from __future__ import annotations

import collections
import gzip
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
sys.path.insert(0, os.path.join(ROOT, "testbed", "anchord"))

VMDIR = os.environ.get("E1_VMDIR", "<artifact-root>-e1vm")
SSH = ["ssh", "-F", os.path.join(VMDIR, "ssh_config"), "e1a"]
HUB_LABEL = "e5-hostA-homeassistant"           # host A's container is "homeassistant", reached over SSH
ANCHORD, MONITOR = "e5-anchord", "e5-monitor"
MAGIC = b"SQLite format 3\x00"

# The SAME module objects e_ps_detection uses (see e1_two_host.py).
import stages.e_c_write_time as EC              # noqa: E402
import stages.e_ps_detection as PS              # noqa: E402
from rig import capability                       # noqa: E402
import chainverify as CV                         # noqa: E402  (the module e_c_write_time.anchored_roots imports)


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
    """capability.record with the privileged Core, the placement and the linked anchor stated."""

    @staticmethod
    def record(**kw):
        kw["constraints"] = {**(kw.get("constraints") or {}), "host_root": True,
                             "host_root_scope": "host A only: Core runs privileged on Home Assistant OS (all "
                                                "capabilities, host A's block devices); the monitor, its key and "
                                                "the anchor are on host B, the head witness and its key on the Mac"}
        kw["substrate"] = {"kind": "Home Assistant OS 18.3 VM (host A, privileged Core); monitor, anchor and "
                                   "replicator on Docker Desktop's VM (host B); head witness as a process on the Mac "
                                   "outside both VMs",
                           "monitor": "shipped external monitor (closure, v2) reading a replica copied every 2 s",
                           "anchor": "linked anchor (anchord_linked.py over the unmodified anchord.py), "
                                     "authenticated, head pushed synchronously under a separate key to the witness"}
        return capability.record(**kw)

    stamp = staticmethod(capability.stamp)


def _q(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def _summary(xs, nd=3):
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "median": round(statistics.median(xs), nd), "mean": round(statistics.fmean(xs), nd),
            "p90": round(_q(xs, 0.9), nd), "p99": round(_q(xs, 0.99), nd), "max": round(max(xs), nd),
            "min": round(min(xs), nd)}


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def _ranges(xs):
    """[1,2,3,7,9,10] -> '1-3,7,9-10'."""
    out, xs = [], sorted(xs)
    i = 0
    while i < len(xs):
        j = i
        while j + 1 < len(xs) and xs[j + 1] == xs[j] + 1:
            j += 1
        out.append(str(xs[i]) if i == j else "%d-%d" % (xs[i], xs[j]))
        i = j + 1
    return ",".join(out)


def _lines(data: bytes):
    return [l for l in data.split(b"\n") if l.strip()]


def _join(lines):
    return b"\n".join(lines) + b"\n"


def _ser(rec) -> bytes:
    return json.dumps(rec, sort_keys=True).encode()          # what anchord_linked writes


def witness_latest(heads):
    """headwitness._load(): the latest head is the accepted head with the highest sequence number."""
    latest = {"seq": 0, "head_digest": None}
    for h in heads:
        if h["seq"] >= latest["seq"]:
            latest = {"seq": h["seq"], "head_digest": h["head_digest"]}
    return latest


def controls(data: bytes, head: dict):
    """Edits of COPIES of the saved chain, each checked alone and against the witness head."""
    ls = _lines(data)
    recs = [json.loads(l) for l in ls]
    reser_identical = all(_ser(r) == l for r, l in zip(recs, ls))
    # The record to rewrite: the middle record that seals one-second segments.
    hs = int(head.get("seq") or 0)
    cand = [i for i, r in enumerate(recs[:hs]) if ((r.get("payload") or {}).get("sealed") or {}).get("second")]
    k = cand[len(cand) // 2] if cand else None
    out = {"reserialization_reproduces_every_line": reser_identical}

    def both(name, d, what):
        a, w = CV.verify_chain(d), CV.verify_chain(d, head)
        out[name] = {"what": what, "chain_alone_ok": a["ok"], "against_witness_head_ok": w["ok"],
                     "problems_against_witness_head": [p["problem"] for p in w["problems"]][:3]}

    if hs >= 1:
        both("truncated_tail", _join(ls[:hs - 1]), "chain cut to the %d records before the witness's latest head "
                                                    "(seq %d)" % (hs - 1, hs))
    if k is not None:
        seg = sorted(recs[k]["payload"]["sealed"]["second"])[0]
        r2 = json.loads(ls[k])
        r2["payload"]["sealed"]["second"][seg]["acc"] = "f" * 64
        un = list(ls)
        un[k] = _ser(r2)
        both("rewritten_root_unrelinked", _join(un), "record %d: root of second-segment %s replaced, later links "
                                                    "left as they were" % (k + 1, seg))
        re = list(un)
        for i in range(k + 1, len(re)):
            ri = json.loads(re[i])
            ri["prev_digest"] = CV.record_digest(re[i - 1])
            re[i] = _ser(ri)
        both("rewritten_root_relinked", _join(re), "record %d: root of second-segment %s replaced and every later "
                                                  "prev_digest recomputed (an anchor-host rewrite)" % (k + 1, seg))
    return out


def meta_lines(sp):
    return [l.rstrip("\n") for l in open(os.path.join(sp, "auth_meta.log"))]


def _clock(line):
    """'mac=A hostB=B mac_after=C' -> offset of host B's clock from the Mac's, with its bracket half-width."""
    if not line:
        return None
    try:
        kv = dict(x.split("=", 1) for x in line.split())
        mac, hb, mac2 = float(kv["mac"]), float(kv["hostB"]), float(kv["mac_after"])
        return {"hostB_minus_mac_ms": round((hb - (mac + mac2) / 2) * 1000, 3),
                "bracket_half_width_ms": round((mac2 - mac) / 2 * 1000, 3)}
    except Exception:                                                      # noqa: BLE001
        return {"unparsed": line}


def linked(tag, sp, det_path):
    det = json.load(open(det_path))
    t0, t1 = det["window"]["t_start"], det["window"]["t_end"]
    chain_path = os.path.join(sp, "chain.jsonl")
    wdir = os.path.join(sp, "witness")
    heads_path = os.path.join(wdir, "heads.jsonl")
    final_path = os.path.join(wdir, "head_final.json")
    forks_path = os.path.join(wdir, "forks.jsonl")
    data = open(chain_path, "rb").read()
    ls = _lines(data)
    recs = [json.loads(l) for l in ls]
    heads = [json.loads(l) for l in open(heads_path) if l.strip()]
    forks = [json.loads(l) for l in open(forks_path) if l.strip()] if os.path.exists(forks_path) else []
    head_final = json.load(open(final_path))

    # Link check, alone.
    alone = CV.verify_chain(data)
    # Witness check: the witness's last head, from its own log, and as GET /head returned it at the freeze.
    latest = witness_latest(heads)
    against = CV.verify_chain(data, latest)
    per_head = {"match": 0, "mismatch": [], "beyond_chain": []}
    for h in heads:
        s = int(h["seq"])
        if s > len(ls):
            per_head["beyond_chain"].append(s)
        elif CV.record_digest(ls[s - 1]) == h["head_digest"]:
            per_head["match"] += 1
        else:
            per_head["mismatch"].append(s)
    witnessed = {int(h["seq"]) for h in heads}
    unwitnessed = sorted(set(range(1, len(ls) + 1)) - witnessed)
    recv_equal = sum(1 for h in heads if int(h["seq"]) <= len(recs)
                     and recs[int(h["seq"]) - 1].get("recv_ts") == h.get("anchor_recv_ts"))

    # Push latency.
    meta = meta_lines(sp)
    pick = lambda key: next((l.split(key, 1)[1].strip() for l in meta if key in l), None)  # noqa: E731
    sync_ms, sync_fail, ticks_with_append = [], [], 0
    mon_path = os.path.join(sp, "monitor.log")
    for l in open(mon_path, errors="replace"):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        a = r.get("anchor") if isinstance(r, dict) else None
        if not isinstance(a, dict):
            continue
        ticks_with_append += 1
        wp = a.get("witness_push")
        if isinstance(wp, dict):
            if wp.get("ok") and isinstance(wp.get("ms"), (int, float)):
                sync_ms.append(wp["ms"])
            else:
                sync_fail.append({"tick": r.get("tick"), **wp})
    lag_all = [(h["witness_recv_ts"] - h["anchor_recv_ts"]) * 1000 for h in heads
               if h.get("anchor_recv_ts") is not None and h.get("witness_recv_ts") is not None]
    lag_run = [(h["witness_recv_ts"] - h["anchor_recv_ts"]) * 1000 for h in heads
               if h.get("anchor_recv_ts") is not None and t0 <= h["anchor_recv_ts"] <= t1]

    # The NTP-style probe (run_e5.sh clock_probe): mac_minus_hostB_ms with the shortest round trip of 25 exchanges;
    # the lag corrected by the mean of the probes before and after the run, uncertain by half the longer round trip.
    def _probe(key):
        try:
            return json.loads(pick(key) or "null")
        except ValueError:
            return {"unparsed": pick(key)}
    probe_before, probe_after = _probe("clock_probe_before:"), _probe("clock_probe_after:")
    probes = [p for p in (probe_before, probe_after) if isinstance(p, dict) and "mac_minus_hostB_ms" in p]
    corrected = None
    if probes:
        off = statistics.fmean(p["mac_minus_hostB_ms"] for p in probes)
        corrected = {"offset_used_mac_minus_hostB_ms": round(off, 3),
                     "uncertainty_ms": round(max(p["min_rtt_ms"] for p in probes) / 2
                                             + abs(probes[0]["mac_minus_hostB_ms"] - probes[-1]["mac_minus_hostB_ms"]) / 2, 3),
                     "all_heads": _summary([x - off for x in lag_all]),
                     "heads_in_run_window": _summary([x - off for x in lag_run])}

    # Replication (as E1 summarizes it).
    cyc = [json.loads(l) for l in open(os.path.join(sp, "replog", "replication.jsonl")) if l.strip()]
    run = [c for c in cyc if t0 <= c["t_req"] <= t1]
    ok = [c for c in run if c.get("ok")]
    gaps = [b["t_req"] - a["t_req"] for a, b in zip(ok, ok[1:])]

    refusals_path = os.path.join(sp, "refusals.jsonl")
    refusals = [json.loads(l) for l in open(refusals_path) if l.strip()] if os.path.exists(refusals_path) else []
    dm = det.get("detection_method") or {}
    scored = dm.get("chain_link_check") or {}

    out = {
        "experiment": "E5: linked anchor with a head witness (round 13)",
        "tag": tag,
        "placement": {
            "host_a": "Home Assistant OS 18.3 (generic-aarch64) in a QEMU/HVF VM on the evaluation Mac; Core run "
                      "privileged by the Supervisor (as E1)",
            "host_b": "Docker Desktop's Linux VM on the same Mac: linked anchor (hpr-anchord:linked), monitor "
                      "(hpr-monitor:e1), replicator (hpr-e1-replicator:1), and E1's MQTT broker and device simulator",
            "witness": "testbed/anchord/headwitness.py as a python3 process on the Mac itself, outside both VMs, "
                       "bound to 127.0.0.1; the anchor reaches it through host.docker.internal",
            "core_container": pick("hostA_core:"),
            "core_privilege_on_hostA": pick("core_privilege_on_hostA:"),
            "probe_from_hub": pick("probe_from_hub:"),
            "witness_reachable_from_anchor_container": pick("witness_reachable_from_anchor_container:"),
            "witness_process": pick("witness: "),
            "key_fingerprint_sha256_16": pick("key_fingerprint_sha256_16:"),
            "witness_key_fingerprint_sha256_16": pick("witness_key_fingerprint_sha256_16:"),
            "anchor_image": pick("anchor image built:"),
            "monitor_in_image_sha256_16": (pick("monitor_in_image_sha256:") or "")[:16] or None,
            "monitor_py_at_run_start_sha256_16": pick("monitor_py_sha256:"),
            "clock_skew_hostA_check": pick("clock_skew:"),
        },
        "detection_file": {"path": os.path.relpath(det_path, ROOT), "sha256": _sha(det_path)},
        "detection": {k: {kk: vv for kk, vv in det[k].items() if kk != "hit_detail"}
                      for k in ("homeprov_detection_second", "homeprov_detection_minute")},
        "renderer_confirmed_misattribution": det["renderer_confirmed_misattribution"],
        "benign_violation_floor": det["benign_violation_floor"],
        "n_trials": det["n_trials"], "n_valid": det["n_valid"],
        "chain_schemes": det.get("chain_schemes"),
        "scored_chain": {"chain_link_check_in_detection_file": scored,
                         "same_head_as_saved_chain": scored.get("head") == alone["head"]},
        "link_check": {k: alone[k] for k in ("records", "link", "linked_records", "head", "ok", "problems",
                                             "integrity")},
        "witness_check": {
            "rule": "headwitness.py: the latest head is the accepted head with the highest sequence number; the chain "
                    "must hold at least that many records and its record at that sequence number must have that "
                    "digest (chainverify.verify_chain with the external head)",
            "witness_latest_head_from_log": latest,
            "witness_get_head_at_freeze": head_final,
            "log_and_get_agree": (head_final.get("seq") == latest["seq"]
                                  and head_final.get("head_digest") == latest["head_digest"]),
            "against_latest_head": {k: against.get(k) for k in ("ok", "problems", "external_head",
                                                                "records_after_external_head", "integrity")},
            "heads_accepted": len(heads),
            "every_accepted_head_vs_chain": {"match": per_head["match"],
                                             "mismatch_seqs": per_head["mismatch"],
                                             "beyond_chain_seqs": per_head["beyond_chain"]},
            "chain_records_never_witnessed": {"n": len(unwitnessed), "seqs": _ranges(unwitnessed)},
            "anchor_recv_ts_in_head_equals_chain_record": recv_equal,
            "forks_refused_and_logged": len(forks),
            "ok": bool(alone["ok"] and against["ok"] and not per_head["mismatch"] and not per_head["beyond_chain"]
                       and not forks),
        },
        "controls_on_copies_of_the_saved_chain": controls(data, latest),
        "push_latency": {
            "mode": "sync (pushed before the append is acknowledged; a failed push never refuses an append)",
            "sync_push_ms_from_anchor_replies": {
                "source": "the anchor's append replies as the monitor logged them (ticks 1-3 and every twelfth "
                          "tick, so a sample of the appends)",
                "monitor_ticks_logged_with_an_append": ticks_with_append,
                "ok": _summary(sync_ms),
                "failed": sync_fail},
            "witness_receipt_minus_anchor_receipt_ms": {
                "what": "witness_recv_ts (Mac clock) minus anchor_recv_ts (host B clock, taken before the record is "
                        "written and fsynced), for every accepted head; includes the write, the fsync, the push and "
                        "the clock offset below",
                "all_heads": _summary(lag_all), "heads_in_run_window": _summary(lag_run),
                "negative_samples": sum(1 for x in lag_all if x < 0),
                "clock_hostB_vs_mac_before": _clock(pick("clock_hostB_vs_mac:")),
                "clock_hostB_vs_mac_after": _clock(pick("clock_hostB_vs_mac_after:")),
                "clock_probe_before": probe_before, "clock_probe_after": probe_after,
                "corrected_for_clock_probe": corrected},
        },
        "replication": {"period_target_s": 2.0, "cycles_in_run": len(run), "cycles_ok": len(ok),
                        "cycles_failed": len(run) - len(ok),
                        "longest_interval_s": round(max(gaps), 3) if gaps else None},
        "anchor_refusals": {"n": len(refusals),
                            "reasons": dict(collections.Counter("%s/%s" % (r.get("reason"), r.get("http"))
                                                                for r in refusals))},
        "inputs": {
            "chain": {"file": "exp/out/%s_linked_chain.jsonl.gz" % tag, "sha256_uncompressed": _sha(chain_path)},
            "witness_heads": {"file": "exp/out/%s_witness_heads.jsonl.gz" % tag,
                              "sha256_uncompressed": _sha(heads_path)},
            "witness_head_final_sha256": _sha(final_path),
            "monitor_log_sha256": _sha(mon_path),
            "recorder_snapshot_sha256": (_sha(os.path.join(EC.SCRATCH, "recorder.db"))
                                         if os.path.exists(os.path.join(EC.SCRATCH, "recorder.db")) else None),
            "replication_log_sha256": _sha(os.path.join(sp, "replog", "replication.jsonl")),
            "run_log_sha256": _sha(os.path.join(sp, "auth_meta.log"))},
        "code": {p: _sha(os.path.join(ROOT, p)) for p in (
            "exp/stages/e5_linked.py", "exp/stages/e_ps_detection.py", "exp/stages/e_c_write_time.py",
            "monitor/monitor.py", "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py",
            "testbed/anchord/headwitness.py", "testbed/anchord/chainverify.py",
            "testbed/e1/replicator/replicator.py", "testbed/e1/replicator/hub_backup.py",
            "testbed/e5/run_e5.sh", "testbed/e5/anchord-linked.Dockerfile")},
        "caveats": [
            "The monitor container runs hpr-monitor:e1's monitor.py (placement.monitor_in_image_sha256_16); the "
            "verifier imports the repository's monitor/monitor.py (code below). They are the same file only if the "
            "two hashes agree; otherwise only the commitment code they share bears on the detection result.",
            "Witness receipt minus anchor receipt is taken on two clocks; negative samples show moments when the "
            "clocks disagreed by more than the push time, so the single-clock push times in the anchor's replies are "
            "the measurement of the push itself.",
            "All three machine contexts (host A's VM, Docker's VM, the Mac) run on one Mac; the witness is outside "
            "the anchor host's VM but shares the physical machine and its owner.",
            "Host A's Core can reach the witness's port through the QEMU gateway (probe_from_hub); it holds no "
            "witness key, so it cannot push a head.",
            "The links and the witness bind the chain's records; that a first anchored root describes the rows the "
            "monitor read still rests on the anchor host being honest when it appends.",
        ],
    }
    for key, src in (("chain", chain_path), ("witness_heads", heads_path)):
        f = os.path.join(ROOT, out["inputs"][key]["file"])
        out["inputs"][key]["gz_matches_run_dir"] = (hashlib.sha256(gzip.open(f).read()).hexdigest() == _sha(src)
                                                    if os.path.exists(f) else None)
    dst = os.path.join(OUT, "%s_linked.json" % tag)
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    wc = out["witness_check"]
    print(json.dumps({"detection_second": out["detection"]["homeprov_detection_second"].get("k"),
                      "n": out["detection"]["homeprov_detection_second"].get("n"),
                      "link": {k: alone[k] for k in ("records", "link", "linked_records", "ok")},
                      "witness": {"latest": latest, "ok": wc["ok"],
                                  "never_witnessed": wc["chain_records_never_witnessed"]["n"]},
                      "sync_push_ms": out["push_latency"]["sync_push_ms_from_anchor_replies"]["ok"],
                      "controls": {k: (v["chain_alone_ok"], v["against_witness_head_ok"])
                                   for k, v in out["controls_on_copies_of_the_saved_chain"].items()
                                   if isinstance(v, dict)}}, indent=1))
    print("  ->", dst)
    return out


def main():
    args = sys.argv[1:]
    tag = "e5_psr_lnk"
    if "--tag" in args:
        i = args.index("--tag")
        tag = args[i + 1]
        args = args[:i] + args[i + 2:]
    only = "--linked-only" in args
    args = [a for a in args if a != "--linked-only"]
    rooms = args or ["porch", "hallway", "kitchen"]
    sp = os.environ.get("E5_SP") or os.path.join(os.path.dirname(ROOT), "HOMEPROV-P13-exp", "e5", tag)
    EC.SCRATCH = os.environ.get("EC_SCRATCH") or os.path.join(sp, "ps_verify")
    det_path = os.path.join(OUT, "%s_detection.json" % tag)
    dst = os.path.join(OUT, "%s_linked.json" % tag)
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite %s" % dst)
    if only:
        linked(tag, sp, det_path)
        return
    if os.path.exists(det_path):
        raise SystemExit("refusing to overwrite %s" % det_path)

    for mod in (EC, PS):
        mod.HUB, mod.ANCHORD, mod.MONITOR = HUB_LABEL, ANCHORD, MONITOR
    assert PS.anchored_roots.__globals__["ANCHORD"] == ANCHORD
    assert PS.anchored_roots.__globals__ is EC.__dict__ and sys.modules["chainverify"] is CV
    PS.snapshot_recorder = snapshot_recorder_host_a
    PS.sh = sh
    PS.capability = _Capability
    PS.main(rooms, tag=tag)
    linked(tag, sp, det_path)


if __name__ == "__main__":
    main()
