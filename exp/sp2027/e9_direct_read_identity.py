"""E9 item A4 (round 13, 2026-10-09): direct read and copy give the same records, on saved recorders.

monitor/monitor.py HOMEPROV_READ=direct reads the live recorder through one read-only connection (mode=ro,
readonly_shm=1) in one read transaction per poll; the default copies the database and its WAL first. This check takes
a saved recorder (a scratch copy of it), lets a separate "hub" process open it in WAL mode and commit rows that stay in
the WAL (no checkpoint; the process keeps the database open, as the hub does), and then polls it with two monitors that
differ only in HOMEPROV_READ, at the same fixed clock, each with its own scratch, escrow and in-memory anchor:
  * the appended record bytes, the state files and the escrow files must be byte-identical;
  * the hub's database, -wal and -shm must be byte-identical before and after the direct-read polls.
Configurations: the E9 one (stable columns, coverage, keylog, per-row binding, escrow, full-history first poll) and the
E8 closure monitor's (coverage, keylog, escrow). Per-poll wall times of both modes are recorded as measured here (one
laptop, scratch copies; not the cost study, which is C1).

    python3 exp/sp2027/e9_direct_read_identity.py [--recorders A.db B.db] [--out FILE]
Writes exp/out/e9_direct_read_identity.json (never overwritten).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_RECORDERS = ("<research-dir>/HOMEPROV-P13-exp/e8/e8_main/recorder.db",
                     "<research-dir>/HOMEPROV-P13-exp/e7/e7_main/recorder.db")
CONFIGS = {"e9_stable_rowbind_escrow_full_history": {"HOMEPROV_SCHEME": "stable", "HOMEPROV_ROWBIND": "1",
                                                      "HOMEPROV_SINCE": "0"},
           "e8_closure_escrow": {"HOMEPROV_SCHEME": "closure"}}
ENV_CLEAR = ("HOMEPROV_ENCODING", "HOMEPROV_NAMEMAP_DIR", "HOMEPROV_CLOCK_FILE", "HOMEPROV_GRACE_S",
             "HOMEPROV_ANCHOR_KEY", "HOMEPROV_SIGN_KEY", "HOMEPROV_COST_LOG", "HOMEPROV_QUICK_CHECK_EVERY",
             "HOMEPROV_MAX_RECORD_BYTES", "HOMEPROV_MAX_PARTS", "HOMEPROV_REPLY_TAGS", "HOMEPROV_ROWBIND",
             "HOMEPROV_SINCE", "HOMEPROV_KEYLOG", "HOMEPROV_COVERAGE")

HUB = r"""
import os, sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("PRAGMA journal_mode=WAL")
con.execute("PRAGMA wal_autocheckpoint=0")
n = int(sys.argv[2])
cols = [r[1] for r in con.execute("PRAGMA table_info(states)") if r[1] != "state_id"]
ecols = [r[1] for r in con.execute("PRAGMA table_info(events)") if r[1] != "event_id"]
t = max(con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0],
        con.execute("SELECT max(time_fired_ts) FROM events").fetchone()[0])
sel = ", ".join(("last_updated_ts + ?" if c == "last_updated_ts" else c) for c in cols)
con.execute("INSERT INTO states (%s) SELECT %s FROM (SELECT * FROM states ORDER BY state_id DESC LIMIT ?)"
            % (", ".join(cols), sel), (60.0, n))
sel = ", ".join(("time_fired_ts + ?" if c == "time_fired_ts" else c) for c in ecols)
con.execute("INSERT INTO events (%s) SELECT %s FROM (SELECT * FROM events ORDER BY event_id DESC LIMIT ?)"
            % (", ".join(ecols), sel), (60.0, n))
con.commit()
print(repr(t + 60.0), flush=True)
sys.stdin.read()
os._exit(0)
"""


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def files(p):
    return {s or "db": sha(p + s) for s in ("", "-wal", "-shm") if os.path.exists(p + s)}


class Chain:
    def __init__(self):
        self.bodies = []

    def append(self, rec):
        self.bodies.append(json.dumps(rec, sort_keys=True).encode())
        return {"ok": True, "seq": len(self.bodies)}


class Clock:
    def __init__(self):
        self.t = 0.0

    def time(self):
        return self.t

    def sleep(self, _s):
        return None


def monitor(db, scratch, mode, env):
    e = dict(env, HOMEPROV_DB=db, HOMEPROV_SCRATCH=scratch, HOMEPROV_READ=mode, HOMEPROV_COVERAGE="1",
             HOMEPROV_KEYLOG="1", HOMEPROV_ESCROW_DIR=os.path.join(scratch, "escrow"))
    old = {k: os.environ.get(k) for k in set(e) | set(ENV_CLEAR)}
    for k in ENV_CLEAR:
        os.environ.pop(k, None)
    os.environ.update(e)
    try:
        os.makedirs(scratch, exist_ok=True)
        spec = importlib.util.spec_from_file_location("e9a4_%s_%d" % (mode, int(time.time() * 1e6)),
                                                      os.path.join(REPO, "monitor", "monitor.py"))
        M = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(M)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    chain, clock = Chain(), Clock()
    M.append, M.time = chain.append, clock
    return M, chain, clock


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--recorders", nargs="*", default=list(DEFAULT_RECORDERS))
    ap.add_argument("--rows", type=int, default=200, help="rows of each table the hub commits into the WAL")
    ap.add_argument("--polls", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(REPO, "exp", "out", "e9_direct_read_identity.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    out = {"check": "e9_direct_read_identity", "generated_utc": datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "code_sha256": {p: sha(os.path.join(REPO, p)) for p in ("monitor/monitor.py",
                                                                "exp/sp2027/e9_direct_read_identity.py")},
        "hub_rows_in_wal_per_table": a.rows, "polls": a.polls, "recorders": {}}
    ok_all = True
    for src in a.recorders:
        work = tempfile.mkdtemp(prefix="e9a4_")
        db = os.path.join(work, "home-assistant_v2.db")
        shutil.copy2(src, db)
        hub = subprocess.Popen([sys.executable, "-c", HUB, db, str(a.rows)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, text=True)
        t_new = float(hub.stdout.readline())
        ro = {"source": src, "source_sha256": sha(src), "wal_bytes": os.path.getsize(db + "-wal"), "configs": {}}
        try:
            for name, env in CONFIGS.items():
                runs = {}
                for mode in ("copy", "direct"):
                    M, chain, clock = monitor(db, os.path.join(work, name + "_" + mode), mode, env)
                    st, ms, reads = M.load_state(), [], []
                    before = files(db)
                    for i in range(a.polls):
                        clock.t = t_new + 5.0 + 5.0 * i
                        t0 = time.perf_counter()
                        o = M.tick(st)
                        ms.append(round((time.perf_counter() - t0) * 1000, 1))
                        reads.append(o.get("read", "copy"))
                    runs[mode] = {"bodies": chain.bodies, "state": open(M.STATE, "rb").read(),
                                  "escrow": open(os.path.join(M.ESCROW_DIR, "escrow.jsonl"), "rb").read(),
                                  "hub_files_unchanged": files(db) == before, "poll_wall_ms": ms, "reads": reads}
                c, d = runs["copy"], runs["direct"]
                res = {"records": len(c["bodies"]), "record_bytes": sum(len(b) for b in c["bodies"]),
                       "records_identical": c["bodies"] == d["bodies"], "state_identical": c["state"] == d["state"],
                       "escrow_identical": c["escrow"] == d["escrow"], "escrow_bytes": len(c["escrow"]),
                       "records_sha256": hashlib.sha256(b"\n".join(c["bodies"])).hexdigest(),
                       "hub_files_unchanged_by_direct_read": d["hub_files_unchanged"],
                       "direct_reads": d["reads"], "poll_wall_ms": {"copy": c["poll_wall_ms"],
                                                                    "direct": d["poll_wall_ms"]}}
                res["identical"] = all(res[k] for k in ("records_identical", "state_identical", "escrow_identical",
                                                        "hub_files_unchanged_by_direct_read")) and \
                    all(r == "direct" for r in d["reads"])
                ok_all &= res["identical"]
                ro["configs"][name] = res
                print(os.path.basename(os.path.dirname(src)), name, json.dumps({k: v for k, v in res.items()
                                                                                if k != "records_sha256"}), flush=True)
        finally:
            hub.stdin.close()
            hub.wait(timeout=30)
            shutil.rmtree(work, ignore_errors=True)
        out["recorders"][src] = ro
    out["all_identical"] = ok_all
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("all identical:", ok_all, "->", a.out)
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
