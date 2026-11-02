#!/usr/bin/env python3
"""Integrity gate for the fresh R1 stacks (hpr2-*), run before and after every measurement phase.

    python3 exp/sp2027/r2_integrity.py REL LABEL [--prev PATH_OF_THE_PREVIOUS_CHECK]

REL is the stack suffix (994 or 10b2). Checks, all read-only:
  containers  every hpr2-*-REL container is running, not paused, not OOM-killed, and its restart count is unchanged
              since --prev (a hub restart during a phase invalidates the phase);
  hub         no "received signal", no non-empty Python fault log written since the hub started, no ERROR-level record in
              the hub log since --prev (or since start), and the hub core start time unchanged since --prev;
  recorder    PRAGMA quick_check = ok on a read-only connection;
  anchor      /anchor/chain.jsonl of hpr2-anchord-REL: seq 1..n contiguous, receive times monotone, no segment root
              that differs from its first anchored root, head.json seq = n, the last append less than 60 s old, and,
              with --prev, the first n_prev lines byte-identical to the previous check (append-only) and n >= n_prev;
              refusals.jsonl is counted (it should only grow with deliberate probes).
Writes exp/out/r2_integrity/REL_LABEL_<UTC>.json (a new file each time) and exits 0 only if every check passes.
"""
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
OUTD = os.path.join(ROOT, "exp", "out", "r2_integrity")
SERVICES = ("broker", "hass", "devices", "anchord", "monitor")


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd[:4])}: {r.stderr.strip()[:300]}")
    return r.stdout


def inspect(name):
    j = json.loads(sh("docker", "inspect", name))[0]
    st = j["State"]
    return {"running": st["Running"], "paused": st["Paused"], "oom_killed": st["OOMKilled"],
            "exit_code": st["ExitCode"], "started_at": st["StartedAt"], "restart_count": j["RestartCount"],
            "image": j["Config"]["Image"], "image_id": j["Image"]}


def main():
    rel, label = sys.argv[1], sys.argv[2]
    prev = None
    if "--prev" in sys.argv:
        prev = json.load(open(sys.argv[sys.argv.index("--prev") + 1]))
    now = time.time()
    res = {"rel": rel, "label": label, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
           "script_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
           "prev": sys.argv[sys.argv.index("--prev") + 1] if prev else None, "checks": {}, "fail": []}
    C = res["checks"]

    def fail(msg):
        res["fail"].append(msg)

    # containers
    C["containers"] = {s: inspect(f"hpr2-{s}-{rel}") for s in SERVICES}
    for s, st in C["containers"].items():
        if not st["running"] or st["paused"] or st["oom_killed"]:
            fail(f"{s}: running={st['running']} paused={st['paused']} oom={st['oom_killed']}")
        if prev and prev["checks"]["containers"][s]["started_at"] != st["started_at"]:
            fail(f"{s}: restarted since the previous check ({prev['checks']['containers'][s]['started_at']} -> {st['started_at']})")
        if prev and prev["checks"]["containers"][s]["restart_count"] != st["restart_count"]:
            fail(f"{s}: restart count changed")

    # hub log and fault log
    hass = f"hpr2-hass-{rel}"
    since = prev["checked_at"] if prev else C["containers"]["hass"]["started_at"]
    log = sh("docker", "logs", "--since", since, hass, check=False) + \
        subprocess.run(["docker", "logs", "--since", since, hass], capture_output=True, text=True).stderr
    lines = log.splitlines()
    sig = [l for l in lines if "received signal" in l]
    err = [l for l in lines if " ERROR (" in l]          # log records at ERROR level
    tb = [l for l in lines if "Traceback" in l]          # informational: HA prints stacks for blocking-call warnings
    legacy = [l for l in lines if "anchor/chain" in l]
    fault = sh("docker", "exec", hass, "sh", "-c",
               "[ -s /config/home-assistant.log.fault ] && stat -c %Y /config/home-assistant.log.fault || echo none",
               check=False).strip()
    C["hub"] = {"log_since": since, "log_lines": len(lines), "signal_lines": sig[:5], "error_lines": len(err),
                "error_examples": [l[:240] for l in err[:5]], "traceback_lines": len(tb), "legacy_inhub_anchor_lines": len(legacy),
                "fault_log_mtime": fault}
    if sig:
        fail(f"hub: {len(sig)} 'received signal' line(s)")
    if err:
        fail(f"hub: {len(err)} ERROR line(s) since {since}")
    if fault not in ("none", ""):
        started = dt.datetime.fromisoformat(C["containers"]["hass"]["started_at"].replace("Z", "+00:00")[:26] + "+00:00")
        if float(fault) >= started.timestamp():
            fail("hub: a fault log was written since the hub started")

    # recorder
    qc = sh("docker", "exec", hass, "python3", "-c",
            "import sqlite3,json;c=sqlite3.connect('file:/config/home-assistant_v2.db?mode=ro',uri=True,timeout=30);"
            "print(json.dumps({'quick_check':c.execute('pragma quick_check').fetchall()[0][0],"
            "'journal_mode':c.execute('pragma journal_mode').fetchone()[0],"
            "'states':c.execute('select count(*) from states').fetchone()[0],"
            "'events':c.execute('select count(*) from events').fetchone()[0]}))")
    C["recorder"] = json.loads(qc)
    if C["recorder"]["quick_check"] != "ok":
        fail(f"recorder: quick_check {C['recorder']['quick_check']}")

    # anchor
    anc = f"hpr2-anchord-{rel}"
    raw = subprocess.run(["docker", "exec", anc, "cat", "/anchor/chain.jsonl"], capture_output=True).stdout
    head = json.loads(sh("docker", "exec", anc, "cat", "/published/head.json"))
    refusals = subprocess.run(["docker", "exec", anc, "sh", "-c", "cat /anchor/refusals.jsonl 2>/dev/null | wc -l"],
                              capture_output=True, text=True).stdout.strip()
    rl = raw.splitlines(keepends=True)
    recs = [json.loads(l) for l in rl]
    seq_ok = [r["seq"] for r in recs] == list(range(1, len(recs) + 1))
    mono = all(b["recv_ts"] >= a["recv_ts"] for a, b in zip(recs, recs[1:]))
    first, conflicts = {}, 0
    for r in recs:
        for g, segs in (r["payload"].get("sealed") or {}).items():
            for k, v in segs.items():
                if (g, k) in first and first[(g, k)] != v["acc"]:
                    conflicts += 1
                first.setdefault((g, k), v["acc"])
    age = now - recs[-1]["recv_ts"] if recs else None
    C["anchor"] = {"n": len(recs), "seq_contiguous": seq_ok, "recv_monotone": mono, "first_root_conflicts": conflicts,
                   "head_seq": head.get("seq"), "last_append_age_s": round(age, 1) if age is not None else None,
                   "refusals": int(refusals or 0), "chain_sha256": hashlib.sha256(raw).hexdigest(),
                   "segments_anchored": len(first)}
    if not recs:
        fail("anchor: empty chain")
    if not seq_ok or not mono or conflicts:
        fail(f"anchor: contiguous={seq_ok} monotone={mono} conflicts={conflicts}")
    if head.get("seq") is not None and abs(head["seq"] - len(recs)) > 2:
        fail(f"anchor: head seq {head.get('seq')} vs {len(recs)} records")
    if age is None or age > 60:
        fail(f"anchor: last append {age} s ago")
    if prev:
        pn = prev["checks"]["anchor"]["n"]
        pre = hashlib.sha256(b"".join(rl[:pn])).hexdigest()
        C["anchor"]["prefix_of_prev"] = {"n_prev": pn, "sha256": pre, "matches": pre == prev["checks"]["anchor"]["chain_sha256"]}
        if len(recs) < pn or pre != prev["checks"]["anchor"]["chain_sha256"]:
            fail("anchor: the chain is not an append-only extension of the previous check")

    res["ok"] = not res["fail"]
    os.makedirs(OUTD, exist_ok=True)
    path = os.path.join(OUTD, f"{rel}_{label}_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    if os.path.exists(path):
        raise SystemExit(f"refusing to overwrite {path}")
    json.dump(res, open(path, "w"), indent=1, sort_keys=True)
    print(("PASS " if res["ok"] else "FAIL ") + path + ("" if res["ok"] else "\n  " + "\n  ".join(res["fail"])))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
