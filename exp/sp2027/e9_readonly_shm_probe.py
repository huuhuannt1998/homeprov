"""E9 C1 supplement (2026-10-10): does a readonly_shm reader keep a consistent snapshot while the writer checkpoints?

Why: in exp/out/e9_cost_scale.json the direct-read mode (monitor.py HOMEPROV_READ=direct: one connection opened with
mode=ro&readonly_shm=1 on the live recorder, one read transaction per poll) failed quick_check on the 2.9 GB recorder
("invalid page number" pointing beyond the master's last page), while the same masters pass quick_check offline. In
those runs the monitor container mounted the recorder volume READ-ONLY, so it could not write the -shm, and the writer
(the hub's stand-in) ran in another container. This probe isolates the reader's consistency from cost:

  writer   WAL, wal_autocheckpoint=8 pages, inserting state rows in small transactions every 5 ms for the whole probe
           (checkpoints and WAL restarts happen many times during each read);
  reader   N times per variant: open, BEGIN, first read, PRAGMA quick_check, ROLLBACK, close, recording the outcome
           (ok / the quick_check report's first lines / the exception); variants alternate under the same writer load:
             readonly_shm  file:...?mode=ro&readonly_shm=1   (the direct-read mode's connection)
             ro            file:...?mode=ro                  (an ordinary read-only connection)
Conditions:
  host     both processes on the Mac (SQLite of the machine's Python), database on APFS, -shm writable for both;
  docker   the deployment pattern of the C1 runs: writer in a python:3.12-slim container with the volume read-write,
           reader in a python:3.12-slim container (the monitor image's base; SQLite 3.46.1) with the volume mounted
           READ-ONLY; no CPU or IO limits;
  docker_limited  the same, with the reader container under the C1 monitor limits (--cpus 1, --memory 1g, 100 MB/s
           read, 50 MB/s write on the VM disk), so a quick_check of the 2.9 GB recorder lasts tens of seconds as in
           the failing C1 runs. Containers e9shm-*, removed at the end.

    python3 exp/sp2027/e9_readonly_shm_probe.py all     # host K=1, K=15; docker K=1, K=5; docker_limited K=15
                                                        # -> exp/out/e9_readonly_shm_probe.json (never overwrites)
    python3 exp/sp2027/e9_readonly_shm_probe.py lockdrop  # with/without validate_files()'s open-read-close
                                                        # -> exp/out/e9_readonly_shm_lockdrop.json (never overwrites)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DST = os.path.join(REPO, "exp", "out", "e9_readonly_shm_probe.json")
C1 = "<research-dir>/HOMEPROV-P13-exp/e9pre/c1"
PREFIX = "e9shm"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------------ the two roles
def writer(db, stop):
    c = sqlite3.connect(db, timeout=30, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA wal_autocheckpoint=8")
    m = c.execute("SELECT metadata_id FROM states_meta LIMIT 1").fetchone()[0]
    n = 0
    while not os.path.exists(stop):
        c.execute("BEGIN")
        for _ in range(20):
            c.execute("INSERT INTO states (metadata_id, state, last_updated_ts, origin_idx, context_id_bin) "
                      "VALUES (?,?,?,0,?)", (m, "on", time.time(), os.urandom(16)))
            n += 1
        c.execute("COMMIT")
        time.sleep(0.005)
    print(json.dumps({"rows_inserted": n, "sqlite": sqlite3.sqlite_version}), flush=True)


def _rawclose(db):
    """What monitor.py validate_files() does after the snapshot is pinned: open, read a header and close the database,
    its -shm and its -wal with ordinary file descriptors."""
    for path, nbytes in ((db, 100), (db + "-shm", 96), (db + "-wal", 12)):
        if os.path.exists(path):
            with open(path, "rb") as fh:
                fh.read(nbytes)


VARIANTS = {"readonly_shm": ("file:%s?mode=ro&readonly_shm=1", False), "ro": ("file:%s?mode=ro", False),
            "readonly_shm_rawclose": ("file:%s?mode=ro&readonly_shm=1", True)}


def reader(db, n, variants=("readonly_shm", "ro")):
    res = {v: [] for v in variants}
    for i in range(n):
        for var in variants:
            uri, rawclose = VARIANTS[var][0] % db, VARIANTS[var][1]
            t0 = time.time()
            try:
                con = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
                con.execute("BEGIN")
                con.execute("SELECT count(*) FROM sqlite_master").fetchone()
                if rawclose:
                    _rawclose(db)
                qc = str(con.execute("PRAGMA quick_check").fetchone()[0])
                con.execute("ROLLBACK")
                con.close()
                lines = qc.splitlines()
                outcome = "ok" if qc == "ok" else "quick_check: " + " | ".join(x[:160] for x in lines[:2])
            except Exception as exc:                      # noqa: BLE001
                outcome = "exception: " + repr(exc)[:160]
            res[var].append({"i": i, "outcome": outcome, "seconds": round(time.time() - t0, 3)})
    return {"sqlite": sqlite3.sqlite_version, "python": sys.version.split()[0], "trials": res}


def summarize(res):
    return {v: {"n": len(r), "ok": sum(1 for x in r if x["outcome"] == "ok"),
                "failed": sum(1 for x in r if x["outcome"] != "ok"),
                "failure_kinds": sorted({x["outcome"].split(":")[0] + ": " + x["outcome"].split(":", 1)[1][:90]
                                         for x in r if x["outcome"] != "ok"})[:5],
                "seconds_median": sorted(x["seconds"] for x in r)[len(r) // 2] if r else None}
            for v, r in res.items()}


# ------------------------------------------------------------------------------------------------ conditions
def host(src, n, variants=("readonly_shm", "ro")):
    work = tempfile.mkdtemp(prefix="e9shm_")
    db = os.path.join(work, "rec.db")
    shutil.copy2(src, db)
    stop = os.path.join(work, "stop")
    w = subprocess.Popen([sys.executable, os.path.abspath(__file__), "writer", db, stop], stdout=subprocess.PIPE,
                         text=True)
    time.sleep(2.0)
    try:
        r = reader(db, n, variants)
    finally:
        open(stop, "w").close()
        wout = (w.communicate(timeout=120)[0] or "").strip().splitlines()
        shutil.rmtree(work, ignore_errors=True)
    r["writer"] = json.loads(wout[-1]) if wout else None
    return r


def sh(*a, check=True):
    p = subprocess.run(list(a), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError("%s -> %s %s" % (" ".join(a)[:160], p.returncode, p.stderr[-300:]))
    return p.stdout.strip()


def docker(src, n, limits=None, variants=("readonly_shm", "ro")):
    vol, wr, rd, cp = PREFIX + "-vol", PREFIX + "-writer", PREFIX + "-reader", PREFIX + "-copy"
    for c in (wr, rd, cp):
        if sh("docker", "ps", "-aq", "-f", "name=^%s$" % c, check=False):
            raise SystemExit("refusing: container %s exists" % c)
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        sh("docker", "volume", "create", vol)
        sh("docker", "run", "--rm", "--name", cp, "-v", "%s:/src:ro" % os.path.dirname(src), "-v", "%s:/d" % vol,
           "python:3.12-slim", "sh", "-c", "cp /src/%s /d/rec.db && chmod 666 /d/rec.db && chmod 777 /d"
           % os.path.basename(src))
        sh("docker", "run", "-d", "--name", wr, "-v", "%s:/d" % vol, "-v", "%s:/h:ro" % here, "python:3.12-slim",
           "python", "-u", "/h/" + os.path.basename(__file__), "writer", "/d/rec.db", "/d/stop")
        time.sleep(3.0)
        lim = []
        if limits:
            lim = ["--cpus", limits["cpus"], "--memory", limits["memory"],
                   "--device-read-bps", "%s:%s" % (limits["device"], limits["device_read_bps"]),
                   "--device-write-bps", "%s:%s" % (limits["device"], limits["device_write_bps"])]
        out = sh("docker", "run", "--rm", "--name", rd, *lim, "-v", "%s:/d:ro" % vol, "-v", "%s:/h:ro" % here,
                 "python:3.12-slim", "python", "-u", "/h/" + os.path.basename(__file__), "reader", "/d/rec.db", str(n),
                 ",".join(variants))
        r = json.loads(out.splitlines()[-1])
        sh("docker", "exec", wr, "touch", "/d/stop")
        sh("docker", "wait", wr, check=False)
        wl = sh("docker", "logs", wr, check=False).splitlines()
        r["writer"] = json.loads(wl[-1]) if wl else None
        r["reader_mount"] = "read-only (-v vol:/d:ro)"
        r["reader_limits"] = limits
        return r
    finally:
        for c in (wr, rd, cp):
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True)


LIMITS = {"cpus": "1", "memory": "1g", "device_read_bps": "100mb", "device_write_bps": "50mb", "device": "/dev/vda"}


def lockdrop():
    """Second experiment: the same reader, with and without validate_files()'s open-read-close of the database, -shm
    and -wal between pinning the snapshot and quick_check (variant readonly_shm_rawclose), in the conditions where
    direct-read polls failed (docker_limited K=15) and two more. -> exp/out/e9_readonly_shm_lockdrop.json"""
    out_path = os.path.join(REPO, "exp", "out", "e9_readonly_shm_lockdrop.json")
    if "--out" in sys.argv:
        out_path = os.path.abspath(sys.argv[sys.argv.index("--out") + 1])
    if os.path.exists(out_path):
        raise SystemExit("refusing to overwrite " + out_path)
    v = ("readonly_shm", "readonly_shm_rawclose")
    plan = [("docker_limited", 15, 4), ("host", 15, 4), ("docker", 5, 10)]
    conds = {}
    for where, k, n in plan:
        src = os.path.join(C1, "master_k%d.db" % k)
        r = (host(src, n, v) if where == "host" else docker(src, n, LIMITS if where == "docker_limited" else None, v))
        r["source"] = {"path": src, "sha256": sha(src), "bytes": os.path.getsize(src)}
        r["summary"] = summarize(r["trials"])
        conds["%s_k%d" % (where, k)] = r
        print(json.dumps({"%s_k%d" % (where, k): r["summary"]}), flush=True)
    out = {"item": "E9 C1 supplement 2: does monitor.py validate_files() (an ordinary open-read-close of the live "
                   "database, -shm and -wal after the read transaction is pinned) release the reader's SQLite locks and "
                   "leave its snapshot unprotected? readonly_shm reader with vs without that open-read-close, while a "
                   "writer checkpoints aggressively",
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "monitor_validate_files": "monitor/monitor.py validate_files(): open(db).read(100), open(db-shm).read(96), "
                                     "open(db-wal).read(12), each closed; called by direct_snapshot() after BEGIN and "
                                     "the first read",
           "writer_load": {"wal_autocheckpoint_pages": 8, "rows_per_txn": 20, "sleep_s": 0.005},
           "reader_limits_docker_limited": LIMITS, "conditions": conds}
    with open(out_path, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", out_path, sha(out_path))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "writer":
        return writer(sys.argv[2], sys.argv[3])
    if cmd == "reader":
        v = tuple(sys.argv[4].split(",")) if len(sys.argv) > 4 else ("readonly_shm", "ro")
        print(json.dumps(reader(sys.argv[2], int(sys.argv[3]), v)), flush=True)
        return
    if cmd == "lockdrop":
        return lockdrop()
    out_path = DST
    if "--out" in sys.argv:
        out_path = os.path.abspath(sys.argv[sys.argv.index("--out") + 1])
    if os.path.exists(out_path):
        raise SystemExit("refusing to overwrite " + out_path)
    # docker_limited: the reader container gets the C1 monitor limits (exp/sp2027/e9_cost_scale.py LIMITS), so a
    # quick_check of the 2.9 GB recorder takes tens of seconds, as in the C1 direct-read runs
    limits = {"cpus": "1", "memory": "1g", "device_read_bps": "100mb", "device_write_bps": "50mb", "device": "/dev/vda"}
    plan = [("host", 1, 20), ("host", 15, 6), ("docker", 1, 20), ("docker", 5, 10), ("docker_limited", 15, 4)]
    conds = {}
    for where, k, n in plan:
        src = os.path.join(C1, "master_k%d.db" % k)
        r = (host(src, n) if where == "host" else docker(src, n, limits if where == "docker_limited" else None))
        r["source"] = {"path": src, "sha256": sha(src), "bytes": os.path.getsize(src)}
        r["summary"] = summarize(r["trials"])
        conds["%s_k%d" % (where, k)] = r
        print(json.dumps({"%s_k%d" % (where, k): r["summary"]}), flush=True)
    out = {"item": "E9 C1 supplement: consistency of a readonly_shm reader (the direct-read mode's connection) vs an "
                   "ordinary read-only reader, each running quick_check in one read transaction while a writer "
                   "checkpoints aggressively; on the Mac and in the C1 deployment pattern (reader container with the "
                   "volume mounted read-only)",
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "writer_load": {"wal_autocheckpoint_pages": 8, "rows_per_txn": 20, "sleep_s": 0.005},
           "conditions": conds,
           "note": "A deliberately aggressive checkpoint rate: the question is whether the reader's snapshot is "
                   "protected, not how often a hub's default checkpointing would hit it."}
    with open(out_path, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", out_path, sha(out_path))


if __name__ == "__main__":
    main()
