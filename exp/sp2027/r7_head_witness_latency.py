"""R7 (round-2 triage N2): cost of hash linking and of holding the anchor head on another host, measured locally.

A stand-in for a second host on one machine: the head witness runs in its own container on its own bridge network
(r7a-net-witness), which the anchor daemons join only to push heads; the anchors and the client sit on another bridge
(r7a-net-anchor). Four anchor daemons (python:3.13-slim, code bind-mounted read-only):
  v1     testbed/anchord/anchord.py, the unmodified daemon every evaluated run used (unlinked records);
  (the other three run testbed/anchord/anchord_linked.py, which wraps it)
  plain  linked records (v2), no witness;
  sync   linked, head pushed to witness r7a-witness-sync before the append is acknowledged;
  async  linked, head pushed to witness r7a-witness-async from a background thread.
A client container replays the steady-state monitor records of a saved chain (reproduce/snapshots/e_c_clo.chain.jsonl,
records 2..408) into all four, interleaved with a rotating order, HMAC-tagged as the monitor does, and times each
authenticated append (the monitor's write-to-anchor step). Afterwards every chain is checked with chainverify.py
(the sync and async chains against their witness's head), and the async witness log gives the head lag.

New containers are started with --rm and stopped at the end; the two networks are created here and removed at the end.
No existing container, image or volume is touched.

    python3 exp/sp2027/r7_head_witness_latency.py     # writes exp/out/r7_head_witness_latency.json (never overwrites)
"""
import datetime
import hashlib
import json
import os
import secrets
import statistics
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import chainverify as CV  # noqa: E402

IMG = "python:3.13-slim"
NA, NW = "r7a-net-anchor", "r7a-net-witness"
AD = os.path.join(REPO, "testbed", "anchord")
CHAIN = os.path.join(REPO, "reproduce", "snapshots", "e_c_clo.chain.jsonl")


def sh(*a, check=True):
    r = subprocess.run(list(a), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError("%s: %s" % (" ".join(a[:4]), r.stderr[-400:]))
    return r.stdout


def q(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p; lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def stat(xs):
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 3), "p90_ms": round(q(xs, .9), 3),
            "p99_ms": round(q(xs, .99), 3), "max_ms": round(max(xs), 3), "mean_ms": round(statistics.mean(xs), 3)}


def main():
    dst = os.path.join(OUT, "r7_head_witness_latency.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    names = ["r7a-witness-sync", "r7a-witness-async", "r7a-anchord-v1", "r7a-anchord-plain", "r7a-anchord-sync",
             "r7a-anchord-async", "r7a-client"]
    existing = set(sh("docker", "ps", "-a", "--format", "{{.Names}}").split())
    nets = set(sh("docker", "network", "ls", "--format", "{{.Name}}").split())
    if existing & set(names) or {NA, NW} & nets:
        raise SystemExit("name collision with an existing container or network; nothing started")
    akey, wkey = secrets.token_hex(32), secrets.token_hex(32)
    started, created_nets = [], []
    load0 = os.getloadavg()
    try:
        for n in (NA, NW):
            sh("docker", "network", "create", n); created_nets.append(n)
        for w in ("r7a-witness-sync", "r7a-witness-async"):
            sh("docker", "run", "-d", "--rm", "--name", w, "--network", NW, "-v", AD + ":/app:ro",
               "-e", "HOMEPROV_WITNESS_KEY=" + wkey, "-e", "WITNESS_LOG=/witness/heads.jsonl",
               "-e", "WITNESS_FORKS=/witness/forks.jsonl", IMG, "python", "-u", "/app/headwitness.py")
            started.append(w)
        conf = {"v1": {"HOMEPROV_ANCHOR_LINK": "v1"}, "plain": {"HOMEPROV_ANCHOR_LINK": "v2"},
                "sync": {"HOMEPROV_ANCHOR_LINK": "v2", "HEAD_WITNESS_URL": "http://r7a-witness-sync:9910/head",
                         "HEAD_WITNESS_MODE": "sync"},
                "async": {"HOMEPROV_ANCHOR_LINK": "v2", "HEAD_WITNESS_URL": "http://r7a-witness-async:9910/head",
                          "HEAD_WITNESS_MODE": "async"}}
        for k, env in conf.items():
            n = "r7a-anchord-" + k
            args = ["docker", "run", "-d", "--rm", "--name", n, "--network", NA, "-v", AD + ":/app:ro",
                    "-e", "HOMEPROV_ANCHOR_KEY=" + akey, "-e", "HOMEPROV_WITNESS_KEY=" + wkey]
            for kk, vv in env.items():
                args += ["-e", "%s=%s" % (kk, vv)]
            sh(*args, IMG, "python", "-u", "/app/anchord.py" if k == "v1" else "/app/anchord_linked.py")
            started.append(n)
            if "HEAD_WITNESS_URL" in env:
                sh("docker", "network", "connect", NW, n)
        time.sleep(3)
        client = sh("docker", "run", "--rm", "--name", "r7a-client", "--network", NA,
                    "-v", os.path.join(REPO, "exp", "sp2027") + ":/drv:ro", "-v", CHAIN + ":/snap/chain.jsonl:ro",
                    IMG, "python", "-u", "/drv/r7_head_witness_client.py", "/snap/chain.jsonl", akey,
                    *["%s=http://r7a-anchord-%s:9900/append" % (k, k) for k in conf])
        rows = [json.loads(l) for l in client.splitlines() if l.startswith("{")]
        apps = [r for r in rows if "target" in r]
        time.sleep(2)
        with tempfile.TemporaryDirectory() as tmp:
            chains, wheads, wlogs = {}, {}, {}
            for k in conf:
                p = os.path.join(tmp, k + ".jsonl")
                sh("docker", "cp", "r7a-anchord-%s:/anchor/chain.jsonl" % k, p)
                chains[k] = open(p, "rb").read()
            for k in ("sync", "async"):
                p = os.path.join(tmp, "w_" + k + ".jsonl")
                sh("docker", "cp", "r7a-witness-%s:/witness/heads.jsonl" % k, p)
                wlogs[k] = [json.loads(l) for l in open(p) if l.strip()]
                last = max(wlogs[k], key=lambda h: h["seq"])
                wheads[k] = {"seq": last["seq"], "head_digest": last["head_digest"]}
        checks = {k: {kk: v for kk, v in CV.verify_chain(chains[k], wheads.get(k)).items()
                      if kk in ("ok", "link", "records", "linked_records", "problems")} for k in conf}
    finally:
        for n in started:
            subprocess.run(["docker", "stop", "-t", "2", n], capture_output=True)
        for n in created_nets:
            subprocess.run(["docker", "network", "rm", n], capture_output=True)
    by = {k: [r["ms"] for r in apps if r["target"] == k and r["ok"]] for k in conf}
    idx = {k: {r["i"]: r["ms"] for r in apps if r["target"] == k and r["ok"]} for k in conf}
    paired = {}
    for a, b in (("plain", "v1"), ("sync", "plain"), ("async", "plain"), ("sync", "v1")):
        d = [idx[a][i] - idx[b][i] for i in idx[a] if i in idx[b]]
        paired["%s_minus_%s" % (a, b)] = {"n": len(d), "median_ms": round(statistics.median(d), 3),
                                          "p90_ms": round(q(d, .9), 3), "mean_ms": round(statistics.mean(d), 3)}
    wpush = [r["witness_ms"] for r in apps if r["target"] == "sync" and r.get("witness_ms") is not None]
    lag = [h["witness_recv_ts"] - h["anchor_recv_ts"] for h in wlogs["async"] if h.get("anchor_recv_ts")]
    out = {"item": "R7/N2: append latency with hash linking and with the head held on a second (local stand-in) host",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "code_sha256": {f: hashlib.sha256(open(os.path.join(AD, f), "rb").read()).hexdigest()
                           for f in ("anchord.py", "anchord_linked.py", "headwitness.py", "chainverify.py")},
           "setup": {"image": IMG, "anchor_network": NA, "witness_network": NW,
                     "stand_in": "separate containers and bridge networks on one machine (Docker Desktop VM); not a "
                                 "physically separate host", "payloads": "records 2..408 of "
                     "reproduce/snapshots/e_c_clo.chain.jsonl (steady-state monitor ticks), replayed with fresh ts",
                     "client": "own container on the anchor network, HMAC-tagged appends, urllib, interleaved order",
                     "load_avg_start": load0, "load_avg_end": os.getloadavg()},
           "append_round_trip": {k: stat(v) for k, v in by.items()},
           "paired_differences": paired,
           "sync_witness_push_ms_inside_append": stat(wpush) if wpush else None,
           "async_head_lag_ms": stat([x * 1000 for x in lag]) if lag else None,
           "body_bytes": stat([float(r["body_bytes"]) for r in apps if r["target"] == "v1"]),
           "chain_checks": checks,
           "context": "the monitor appends once per 5 s observation interval; real-deployment write-to-anchor latency "
                      "is median 3.811 s, max 17.75 s (exp/out/r6_window_latency_real.json)"}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({k: out[k] for k in ("append_round_trip", "paired_differences",
                                          "sync_witness_push_ms_inside_append", "async_head_lag_ms", "chain_checks")},
                     indent=1))


if __name__ == "__main__":
    main()
