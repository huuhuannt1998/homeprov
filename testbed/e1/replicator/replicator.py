"""E1 replicator (round 12, 2026-10-08): two-host placement of the monitor.

Runs on the MONITOR'S host. Every PERIOD seconds it asks the hub's host, over SSH, for a consistent SQLite backup of
the recorder (hub_backup.py, run inside the hub's Core container), and installs it as the monitor's input:

  1. write the copy to a temporary file in the replica directory and fsync it;
  2. os.replace() it onto home-assistant_v2.db (atomic: the monitor never sees a partial file);
  3. then os.replace() the clock file with the time, on THIS host's clock, at which the copy was requested.

The monitor (HOMEPROV_CLOCK_FILE) reads the clock before it copies the replica, and seals only segments that closed
before that time. Step 3 after step 2 makes the replica the monitor copies at least as recent as the clock it read.
The time used is this host's, not the hub's: the hub's host is the adversary's, so its clock is not trusted; the
hub's clock at backup start is logged only to measure the skew.

One JSON line per cycle goes to the log directory: request time, hub time at backup start, receive time, install
time, size, and any error. A failed cycle installs nothing; the monitor keeps the previous replica and clock.
"""
import json
import os
import subprocess
import time

REP = os.environ.get("E1_REPLICA_DIR", "/rep")
LOGDIR = os.environ.get("E1_LOG_DIR", "/replog")
PERIOD = float(os.environ.get("E1_REPL_PERIOD", "2"))
SSH = ["ssh", "-F", os.environ.get("E1_SSH_CONFIG", "/e1/ssh_config"), os.environ.get("E1_HUB_HOST", "e1a")]
REMOTE = os.environ.get("E1_REMOTE", "docker exec homeassistant python3 /config/.e1_hub_backup.py")
MAGIC = b"SQLite format 3\x00"


def install(data: bytes, t_req: float):
    tmp = os.path.join(REP, ".replica.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, os.path.join(REP, "home-assistant_v2.db"))
    ctmp = os.path.join(REP, ".clock.tmp")
    with open(ctmp, "w") as fh:
        fh.write("%.6f\n" % t_req)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(ctmp, os.path.join(REP, "clock"))


def main():
    os.makedirs(REP, exist_ok=True)
    os.makedirs(LOGDIR, exist_ok=True)
    log = open(os.path.join(LOGDIR, "replication.jsonl"), "a", buffering=1)
    n = 0
    while True:
        t_req = time.time()
        rec = {"cycle": n, "t_req": t_req}
        try:
            p = subprocess.run(SSH + [REMOTE], capture_output=True, timeout=60)
            rec["t_got"] = time.time()
            err = p.stderr.decode(errors="replace").strip().splitlines()
            if p.returncode != 0 or not p.stdout.startswith(MAGIC):
                rec.update(ok=False, rc=p.returncode, err=" | ".join(err[-3:])[:300], bytes=len(p.stdout))
            else:
                rec["hub_t_backup"] = float(err[-1])
                install(p.stdout, t_req)
                rec.update(ok=True, bytes=len(p.stdout), t_installed=time.time())
        except Exception as exc:                                          # noqa: BLE001
            rec.update(ok=False, err=repr(exc)[:300])
        log.write(json.dumps(rec) + "\n")
        n += 1
        time.sleep(max(0.0, PERIOD - (time.time() - t_req)))


if __name__ == "__main__":
    main()
