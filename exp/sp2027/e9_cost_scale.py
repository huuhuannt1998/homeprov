"""E9 part C1 (2026-10-09): the monitor's per-poll cost at recorder sizes of about 0.2, 1 and 3 GB.

Round-3 reviews R1 W5, R2 W4 and R3 W5: every poll copies the whole recorder and its WAL (monitor.py snapshot()) and runs
quick_check, and the cost was measured only on the lab installation's 186 MB recorder. This script measures, per poll,
the copy, check, keylog, load, commit, escrow and append time and the bytes read and written, on synthetic recorders of
three sizes, in the monitor's own container image, under stated Docker CPU, memory and IO limits, for copy mode (the
default) and, when the code has it, direct-read mode (HOMEPROV_READ=direct, E9 design A4).

SYNTHETIC RECORDERS (`generate`). Derived from a read-only copy of the lab installation's recorder (Home Assistant
2026.7.4, schema 53, about 30 days; default HOMEPROV-P13-exp/e9pre/src/pre_oct9.db, a byte copy of
e2night/pre_oct9.db, opened immutable): the schema (every CREATE statement, in order) is copied, and the lab's entity
population is replicated K times. Replica r gets its own states_meta rows (entity_id + "_<r+1>" for r >= 1), its own
state_attributes and event_data rows (entity ids and friendly names renamed, hash recomputed with FNV-1a 32 as the
recorder does), and every states and events row of the source, with its timestamps shifted cyclically within the
source's span by a per-replica offset (replica 0: no shift; others: seeded uniform), context ids re-derived (the source
id's 48-bit millisecond prefix shifted the same way, the 80 other bits from BLAKE2b(replica, source id), so rows that
shared a context still share one), old_state_id re-linked to the replica's previous row of the same entity (NULL where
the source's was NULL), and every other column (state, origin_idx, user ids, last_reported_ts / last_changed_ts relative
to last_updated_ts, the NULL legacy columns) as in the source. Rows are inserted in global time order with explicit
increasing keys, in batches of consecutive same-table rows, into the source's own indexes (as the recorder builds
them); the small tables (event_types, recorder_runs, schema_changes, statistics_runs, ...) are copied once; ANALYZE
at the end; journal mode WAL. K = 1, 5, 15 give the three sizes (the file sizes are recorded).

WRITE LOAD (`writer`, the hub's stand-in, in its own container with no limits). It replays the synthetic recorder's own
rows of one day earlier, second by second (so the write rate is K times the lab's), inserting them as the recorder does:
new keys, timestamps now, fresh context ids (shared within a replayed context), old_state_id = the entity's previous row,
attributes and event data reused, one transaction per second (commit_interval 1), with the recorder's pragmas
(journal_mode WAL, cache_size -16384, synchronous NORMAL, foreign_keys ON; wal_autocheckpoint left at its default). It
does not emulate the recorder's in-place last_reported_ts updates, purges or statistics.

CLOCK. The synthetic history ends at the source's last row. The writer and the monitor harness both run on the clock
time.time() + OFFSET, one constant chosen at the start of a run so the history ends where the writer starts: the
monitor's open window then holds the history's last hours, as on a hub. The harness rebinds the monitor module's `time`
name to that clock (durations are unchanged); nothing else in the monitor is altered.

HARNESS (`harness`, inside the monitor container). Loads /app/monitor.py from the image exactly as the monitor runs it
(environment as the E9 configuration: stable scheme, coverage, keylog, escrow, Ed25519 signatures, tagged replies, a
linked anchor) and calls tick() WARMUP + POLLS times with HOMEPROV_PERIOD seconds between polls, as main() does. Each
module function a poll calls (snapshot, validate_copy, watermark, keylog_poll, load, commit, escrow_write,
escrow_keylog, append, save_state, and any direct-read function the code adds) is wrapped in a timer that only measures;
per poll it records the wall time of tick(), each phase's time, tick()'s own copy_ms/load_ms/commit_ms/append_ms, and
the deltas of /proc/self/io (rchar, wchar: bytes passed to read/write calls; read_bytes, write_bytes: bytes the process
caused to be fetched from or sent to storage) and of the container's cgroup io.stat (rbytes, wbytes on the VM's data
disk, which includes writeback of the copies). Results are printed as JSON lines and collected from the container log.

RUN (`run`, on the Mac). Per (K, mode): a fresh copy of the K master into a Docker volume (dd, O_DIRECT, so no page of
it is cached), an anchor (hpr-anchord:e8, linked, fresh append key, never recorded), the writer, then the monitor
container with --cpus, --memory and --device-read-bps / --device-write-bps on the VM's data disk (the volumes live on
it), the live recorder mounted read-only at /cfg as deployed. Everything is created under the prefix e9k- on an
internal network and removed at the end. `summarize` writes exp/out/e9_cost_scale.json (never overwriting).

    python3 exp/sp2027/e9_cost_scale.py generate --k 5 --out .../master_k5.db
    python3 exp/sp2027/e9_cost_scale.py run --k 5 --mode copy --image hpr-monitor:e9c1 --tag k5_copy
    python3 exp/sp2027/e9_cost_scale.py summarize --runs DIR [DIR ...]       # -> exp/out/e9_cost_scale.json
"""
from __future__ import annotations

import argparse
import bisect
import collections
import datetime as dt
import hashlib
import heapq
import importlib.util
import json
import os
import random
import sqlite3
import statistics
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EXP = "<research-dir>/HOMEPROV-P13-exp/e9pre"
DEFAULT_SRC = os.path.join(EXP, "src", "pre_oct9.db")
DST = os.path.join(REPO, "exp", "out", "e9_cost_scale.json")
PREFIX = "e9k"
SEED = 20261009

# the stated limits (monitor container only)
LIMITS = {"cpus": "1", "memory": "1g", "device_read_bps": "100mb", "device_write_bps": "50mb", "device": "/dev/vda"}
POLLS, WARMUP, PERIOD = 30, 3, 5.0


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fnv1a_32(b: bytes) -> int:
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x01000193) & 0xFFFFFFFF
    return h


# ============================================================================================== generate (on the Mac)
def generate(a):
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    src = sqlite3.connect("file:%s?mode=ro&immutable=1" % a.src, uri=True)
    K = int(a.k)
    rng = random.Random(SEED)
    t0s = src.execute("SELECT min(last_updated_ts), max(last_updated_ts) FROM states").fetchone()
    t0e = src.execute("SELECT min(time_fired_ts), max(time_fired_ts) FROM events").fetchone()
    T0, T1 = min(t0s[0], t0e[0]), max(t0s[1], t0e[1])
    S = (T1 - T0) + 0.001
    shifts = [0.0] + [rng.uniform(0, S) for _ in range(K - 1)]

    def f(t, r):
        if t is None:
            return None
        return T0 + ((t - T0 + shifts[r]) % S)

    def fctx(c, r):
        if c is None:
            return None
        ms = int.from_bytes(c[:6], "big")
        nms = int(round(f(ms / 1000.0, r) * 1000)) if T0 - S <= ms / 1000.0 <= T1 + S else ms
        tail = hashlib.blake2b(bytes([r & 0xFF, r >> 8]) + bytes(c), digest_size=10).digest()
        return nms.to_bytes(6, "big") + tail

    tmp = a.out + ".partial"
    if os.path.exists(tmp):
        os.remove(tmp)
    dst = sqlite3.connect(tmp)
    dst.execute("PRAGMA journal_mode=OFF")
    dst.execute("PRAGMA synchronous=OFF")
    dst.execute("PRAGMA cache_size=-1000000")
    ddl = src.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
                      "ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, rowid").fetchall()
    for _t, _n, sql_ in ddl:
        dst.execute(sql_)
    # small tables, once
    for t in ("event_types", "recorder_runs", "schema_changes", "migration_changes", "statistics_runs",
              "statistics_meta", "statistics", "statistics_short_term"):
        cols = [r[1] for r in src.execute("PRAGMA table_info(%s)" % t)]
        rows = src.execute("SELECT %s FROM %s" % (",".join('"%s"' % c for c in cols), t)).fetchall()
        if rows:
            dst.executemany("INSERT INTO %s (%s) VALUES (%s)" % (t, ",".join('"%s"' % c for c in cols),
                                                               ",".join("?" * len(cols))), rows)
    # replicated dimension tables
    metas = src.execute("SELECT metadata_id, entity_id FROM states_meta ORDER BY metadata_id").fetchall()
    ents = sorted((e for _m, e in metas), key=len, reverse=True)
    attrs = src.execute("SELECT attributes_id, shared_attrs FROM state_attributes ORDER BY attributes_id").fetchall()
    datas = src.execute("SELECT data_id, shared_data FROM event_data ORDER BY data_id").fetchall()
    meta_map, attr_map, data_map = {}, {}, {}
    nm = na = nd = 0

    def rename(s, r):
        if r == 0 or s is None:
            return s
        for e in ents:                                   # longest first, so no id is a prefix of a later one
            s = s.replace('"%s"' % e, '"%s_%d"' % (e, r + 1))
        return s

    for r in range(K):
        for m, e in metas:
            nm += 1
            meta_map[(r, m)] = nm
            dst.execute("INSERT INTO states_meta (metadata_id, entity_id) VALUES (?,?)",
                        (nm, e if r == 0 else "%s_%d" % (e, r + 1)))
        for i, s in attrs:
            na += 1
            attr_map[(r, i)] = na
            s2 = rename(s, r)
            if r and s2 is not None:
                try:
                    o = json.loads(s2)
                    if isinstance(o, dict) and isinstance(o.get("friendly_name"), str):
                        o["friendly_name"] = "%s %d" % (o["friendly_name"], r + 1)
                        s2 = json.dumps(o, separators=(",", ":"))
                except ValueError:
                    pass
            dst.execute("INSERT INTO state_attributes (attributes_id, hash, shared_attrs) VALUES (?,?,?)",
                        (na, fnv1a_32(s2.encode()) if s2 is not None else None, s2))
        for i, s in datas:
            nd += 1
            data_map[(r, i)] = nd
            s2 = rename(s, r)
            dst.execute("INSERT INTO event_data (data_id, hash, shared_data) VALUES (?,?,?)",
                        (nd, fnv1a_32(s2.encode()) if s2 is not None else None, s2))
    dst.commit()

    scols = [r[1] for r in src.execute("PRAGMA table_info(states)")]
    ecols = [r[1] for r in src.execute("PRAGMA table_info(events)")]
    S_ = {c: i for i, c in enumerate(scols)}
    E_ = {c: i for i, c in enumerate(ecols)}
    srows = src.execute("SELECT %s FROM states" % ",".join('"%s"' % c for c in scols)).fetchall()
    erows = src.execute("SELECT %s FROM events" % ",".join('"%s"' % c for c in ecols)).fetchall()
    src_sorted = sorted([(r[S_["last_updated_ts"]] or 0.0, 0, i) for i, r in enumerate(srows)]
                        + [(r[E_["time_fired_ts"]] or 0.0, 1, i) for i, r in enumerate(erows)])
    n_src = len(src_sorted)

    src_times = [x[0] for x in src_sorted]

    def stream(r):
        # the replica's rows in its shifted time order: a rotation of the source order (rows at or after
        # T0 + S - shift wrap to the start of the span)
        start = bisect.bisect_left(src_times, T0 + S - shifts[r]) if r else 0
        start = start % n_src
        for j in range(n_src):
            t, tb, i = src_sorted[(start + j) % n_src]
            yield (f(t, r), r, tb, i)

    sins = "INSERT INTO states (%s) VALUES (%s)" % (",".join('"%s"' % c for c in scols), ",".join("?" * len(scols)))
    eins = "INSERT INTO events (%s) VALUES (%s)" % (",".join('"%s"' % c for c in ecols), ",".join("?" * len(ecols)))
    last_state = {}
    sid = eid = 0
    batch, btab = [], None
    n_out = 0
    t_start = time.time()

    def flush():
        nonlocal batch
        if batch:
            dst.executemany(sins if btab == 0 else eins, batch)
            batch = []

    for (_t, r, tb, i) in heapq.merge(*[stream(r) for r in range(K)]):
        if tb != btab or len(batch) >= 5000:
            flush()
            btab = tb
        if tb == 0:
            row = list(srows[i])
            sid += 1
            lu = row[S_["last_updated_ts"]]
            nlu = f(lu, r)
            for c in ("last_changed_ts", "last_reported_ts"):
                v = row[S_[c]]
                row[S_[c]] = None if v is None else nlu + (v - lu)
            row[S_["last_updated_ts"]] = nlu
            row[S_["state_id"]] = sid
            mk = (r, row[S_["metadata_id"]])
            row[S_["metadata_id"]] = meta_map.get(mk, row[S_["metadata_id"]])
            prev = last_state.get(mk)
            row[S_["old_state_id"]] = None if row[S_["old_state_id"]] is None else prev
            last_state[mk] = sid
            if row[S_["attributes_id"]] is not None:
                row[S_["attributes_id"]] = attr_map.get((r, row[S_["attributes_id"]]))
            for c in ("context_id_bin", "context_parent_id_bin"):
                row[S_[c]] = fctx(row[S_[c]], r)
            batch.append(row)
        else:
            row = list(erows[i])
            eid += 1
            row[E_["event_id"]] = eid
            row[E_["time_fired_ts"]] = f(row[E_["time_fired_ts"]], r)
            if row[E_["data_id"]] is not None:
                row[E_["data_id"]] = data_map.get((r, row[E_["data_id"]]))
            for c in ("context_id_bin", "context_parent_id_bin"):
                row[E_["%s" % c]] = fctx(row[E_[c]], r)
            batch.append(row)
        n_out += 1
        if n_out % 1000000 == 0:
            flush()
            dst.commit()
            print(json.dumps({"rows": n_out, "elapsed_s": round(time.time() - t_start, 1)}), flush=True)
    flush()
    dst.commit()
    dst.execute("ANALYZE")
    dst.commit()
    dst.execute("PRAGMA journal_mode=WAL")
    dst.close()
    os.replace(tmp, a.out)
    meta = {"k": K, "src": a.src, "src_sha256": sha(a.src), "seed": SEED, "shifts_s": shifts, "span_s": S,
            "T0": T0, "T1": T1, "states": sid, "events": eid, "states_meta": nm, "state_attributes": na,
            "event_data": nd, "bytes": os.path.getsize(a.out), "sha256": sha(a.out),
            "generator_sha256": sha(os.path.abspath(__file__)), "elapsed_s": round(time.time() - t_start, 1),
            "history_end_ts": T1}
    with open(a.out + ".json", "x") as fh:
        json.dump(meta, fh, indent=1)
    print(json.dumps(meta))


# ================================================================================ writer (in the hub stand-in container)
def ulid_bytes(ts: float) -> bytes:
    return int(ts * 1000).to_bytes(6, "big") + os.urandom(10)


def writer(a):
    db = a.db
    offset = float(a.offset)
    clock = lambda: time.time() + offset
    con = sqlite3.connect(db, timeout=60, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA cache_size = -16384")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=ON")
    end_hist = float(a.history_end)
    dur = float(a.duration)
    scols = [r[1] for r in con.execute("PRAGMA table_info(states)")]
    ecols = [r[1] for r in con.execute("PRAGMA table_info(events)")]
    lo, hi = end_hist - 86400.0, end_hist - 86400.0 + dur + 60
    rep = []
    for r in con.execute("SELECT %s FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?"
                         % ",".join('"%s"' % c for c in scols), (lo, hi)):
        rep.append((r[scols.index("last_updated_ts")] + 86400.0, 0, r))
    for r in con.execute("SELECT %s FROM events WHERE time_fired_ts >= ? AND time_fired_ts < ?"
                         % ",".join('"%s"' % c for c in ecols), (lo, hi)):
        rep.append((r[ecols.index("time_fired_ts")] + 86400.0, 1, r))
    rep.sort(key=lambda x: (x[0], x[1]))
    S_ = {c: i for i, c in enumerate(scols)}
    E_ = {c: i for i, c in enumerate(ecols)}
    last = {}
    for (m,) in con.execute("SELECT metadata_id FROM states_meta"):
        v = con.execute("SELECT state_id FROM states WHERE metadata_id=? ORDER BY last_updated_ts DESC LIMIT 1",
                        (m,)).fetchone()
        if v:
            last[m] = v[0]
    scols_ins = [c for c in scols if c != "state_id"]
    ecols_ins = [c for c in ecols if c != "event_id"]
    sins = "INSERT INTO states (%s) VALUES (%s)" % (",".join('"%s"' % c for c in scols_ins), ",".join("?" * len(scols_ins)))
    eins = "INSERT INTO events (%s) VALUES (%s)" % (",".join('"%s"' % c for c in ecols_ins), ",".join("?" * len(ecols_ins)))
    ctxmap = {}

    def nctx(c, ts):
        if c is None:
            return None
        if c not in ctxmap:
            ctxmap[c] = ulid_bytes(ts)
        return ctxmap[c]

    print(json.dumps({"writer": "start", "replay_rows": len(rep), "offset": offset, "clock": clock(),
                      "history_end": end_hist}), flush=True)
    i, n_s, n_e, commits, lat = 0, 0, 0, 0, []
    stop = {"now": False}

    def _term(_sig, _frm):
        stop["now"] = True
    import signal
    signal.signal(signal.SIGTERM, _term)
    t_end_clock = clock() + dur
    # the first rows due are those just after the end of the history
    while i < len(rep) and rep[i][0] <= end_hist:
        i += 1
    while clock() < t_end_clock and i < len(rep) and not stop["now"]:
        now = clock()
        due = []
        while i < len(rep) and rep[i][0] <= now:
            due.append(rep[i])
            i += 1
        if due:
            t0 = time.time()
            con.execute("BEGIN")
            for ts, tb, r in due:
                if tb == 0:
                    row = dict(zip(scols, r))
                    lu = row["last_updated_ts"]
                    nlu = ts
                    for c in ("last_changed_ts", "last_reported_ts"):
                        if row[c] is not None:
                            row[c] = nlu + (row[c] - lu)
                    row["last_updated_ts"] = nlu
                    m = row["metadata_id"]
                    row["old_state_id"] = None if row["old_state_id"] is None else last.get(m)
                    row["context_id_bin"] = nctx(row["context_id_bin"], nlu)
                    row["context_parent_id_bin"] = nctx(row["context_parent_id_bin"], nlu)
                    cur = con.execute(sins, [row[c] for c in scols_ins])
                    last[m] = cur.lastrowid
                    n_s += 1
                else:
                    row = dict(zip(ecols, r))
                    row["time_fired_ts"] = ts
                    row["context_id_bin"] = nctx(row["context_id_bin"], ts)
                    row["context_parent_id_bin"] = nctx(row["context_parent_id_bin"], ts)
                    con.execute(eins, [row[c] for c in ecols_ins])
                    n_e += 1
            con.execute("COMMIT")
            commits += 1
            lat.append(time.time() - t0)
        if len(ctxmap) > 200000:
            ctxmap.clear()
        time.sleep(max(0.0, 1.0 - (clock() % 1.0)))      # one transaction per second (commit_interval 1)
        if commits and commits % 60 == 0:
            print(json.dumps({"writer": "tick", "clock": clock(), "states": n_s, "events": n_e,
                              "commits": commits}), flush=True)
    lat.sort()
    print(json.dumps({"writer": "stop", "clock": clock(), "states": n_s, "events": n_e, "commits": commits,
                      "commit_s_median": statistics.median(lat) if lat else None,
                      "commit_s_max": lat[-1] if lat else None}), flush=True)


# ============================================================================== harness (in the monitor's container)
class OffsetClock:
    def __init__(self, offset):
        self.offset = offset

    def time(self):
        return time.time() + self.offset

    def sleep(self, s):
        time.sleep(s)

    def __getattr__(self, name):
        return getattr(time, name)


def _proc_io():
    out = {}
    try:
        for line in open("/proc/self/io"):
            k, v = line.split(":")
            out[k.strip()] = int(v)
    except OSError:
        pass
    return out


def _cg_io():
    out = {"rbytes": 0, "wbytes": 0}
    try:
        for line in open("/sys/fs/cgroup/io.stat"):
            for kv in line.split()[1:]:
                k, v = kv.split("=")
                if k in out:
                    out[k] += int(v)
    except OSError:
        pass
    return out


def harness(a):
    spec = importlib.util.spec_from_file_location("monitor", a.monitor)
    M = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(M)
    M.time = OffsetClock(float(a.offset))
    phases = {}
    names = ["snapshot", "validate_copy", "watermark", "keylog_poll", "load", "commit", "escrow_write",
             "escrow_keylog", "append", "save_state", "namemap_seal"]
    names += [n for n in dir(M) if n.startswith(("direct", "_direct", "read_direct", "open_direct", "quick_check"))
              and callable(getattr(M, n)) and n not in names]

    def wrap(name, fn):
        def w(*args, **kw):
            t = time.perf_counter()
            try:
                return fn(*args, **kw)
            finally:
                phases[name] = phases.get(name, 0.0) + (time.perf_counter() - t) * 1000
        w.__wrapped__ = fn
        return w

    wrapped = []
    for n in names:
        fn = getattr(M, n, None)
        if callable(fn):
            setattr(M, n, wrap(n, fn))
            wrapped.append(n)
    checks = []
    if callable(getattr(M, "check_connection", None)):
        _cc = M.check_connection

        def check_connection(con, quick=True, *args, **kw):
            t = time.perf_counter()
            r = _cc(con, quick, *args, **kw)
            checks.append({"quick_check_ran": bool(quick), "ok": r is None,
                           "reason": None if r is None else r[1], "ms": round((time.perf_counter() - t) * 1000, 3)})
            return r
        check_connection.__wrapped__ = _cc
        M.check_connection = check_connection
        wrapped.append("check_connection")
    os.makedirs(M.SCRATCH, exist_ok=True)
    st = M.load_state()
    print(json.dumps({"harness": "start", "monitor_sha256": sha(a.monitor), "wrapped": wrapped,
                      "read_mode": os.environ.get("HOMEPROV_READ", "copy"), "scheme": M.SCHEME,
                      "db_bytes": os.path.getsize(M.SRC), "clock": M.time.time()}), flush=True)
    for i in range(int(a.warmup) + int(a.polls)):
        phases.clear()
        checks.clear()
        sizes_before = {}
        for p_ in (M.SRC, M.SRC + "-wal"):
            try:
                sizes_before[os.path.basename(os.path.dirname(p_)) + "/" + os.path.basename(p_)] = os.path.getsize(p_)
            except OSError:
                pass
        io0, cg0 = _proc_io(), _cg_io()
        t = time.perf_counter()
        try:
            r = M.tick(st)
            err = None
        except Exception as exc:                          # noqa: BLE001
            r, err = {}, repr(exc)[:300]
        total = (time.perf_counter() - t) * 1000
        io1, cg1 = _proc_io(), _cg_io()
        sizes = {}
        for p in (M.SRC, M.SRC + "-wal", os.path.join(M.SCRATCH, "recorder.db"),
                  os.path.join(M.SCRATCH, "recorder.db-wal")):
            try:
                sizes[os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p)] = os.path.getsize(p)
            except OSError:
                pass
        rec = {"poll": i + 1, "warmup": i < int(a.warmup), "total_ms": round(total, 3), "err": err,
               "phases_ms": {k: round(v, 3) for k, v in phases.items()},
               "tick": {k: r.get(k) for k in ("copy_ms", "load_ms", "commit_ms", "append_ms", "n_nodes", "parts",
                                               "evidence_unobservable", "reason", "escrowed", "escrowed_keylog",
                                               "pending", "backlog", "read", "read_mode", "check", "quick_check", "detail", "seq_local",
                                               "read_attempts")
                        if k in r},
               "checks": list(checks),
               "anchor_ok": bool((r.get("anchor") or {}).get("ok")),
               "proc_io": {k: io1.get(k, 0) - io0.get(k, 0) for k in ("rchar", "wchar", "read_bytes", "write_bytes")},
               "cgroup_io": {k: cg1[k] - cg0[k] for k in cg1}, "sizes": sizes, "sizes_before": sizes_before,
               "clock": M.time.time()}
        print(json.dumps(rec), flush=True)
        time.sleep(float(a.period))
    print(json.dumps({"harness": "done"}), flush=True)


# ================================================================================================ run (on the Mac)
def sh(*args, check=True, capture=True):
    r = subprocess.run(list(args), capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("%s -> %s %s" % (" ".join(args)[:200], r.returncode, (r.stderr or "")[-400:]))
    return (r.stdout or "").strip()


def run(a):
    K, mode, tag = int(a.k), a.mode, a.tag
    rundir = os.path.join(EXP, "c1", "runs", tag)
    if os.path.exists(rundir):
        raise SystemExit("refusing: %s exists" % rundir)
    os.makedirs(rundir)
    master = os.path.join(EXP, "c1", "master_k%d.db" % K)
    meta = json.load(open(master + ".json"))
    names = {"net": "%s-net" % PREFIX, "anc": "%s-anchord" % PREFIX, "wr": "%s-writer" % PREFIX,
             "mon": "%s-monitor" % PREFIX, "cp": "%s-copy" % PREFIX, "kg": "%s-keygen" % PREFIX}
    vols = {v: "%s-%s" % (PREFIX, v) for v in ("live", "scratch", "escrow", "sign", "chain", "pub")}
    mvol = "%s-master-k%d" % (PREFIX, K)
    for c in names.values():
        if sh("docker", "ps", "-a", "-q", "-f", "name=^%s$" % c):
            raise SystemExit("refusing: container %s exists" % c)
    log = open(os.path.join(rundir, "run.log"), "w")

    def note(**kw):
        kw["at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.write(json.dumps(kw) + "\n")
        log.flush()
        print(json.dumps(kw), flush=True)

    def context():
        return {"uptime": sh("uptime", check=False),
                "containers_cpu": sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}}",
                                     check=False).splitlines()}

    note(step="start", context=context(), k=K, mode=mode, image=a.image, limits=LIMITS, polls=int(a.polls or POLLS),
         warmup=int(a.warmup if a.warmup is not None else WARMUP), period=PERIOD,
         master=master, master_sha256=meta["sha256"], master_bytes=meta["bytes"], load=sh("uptime"))
    try:
        # master volume (once per K): the master file copied in with O_DIRECT
        if not sh("docker", "volume", "ls", "-q", "-f", "name=^%s$" % mvol):
            sh("docker", "volume", "create", mvol)
            sh("docker", "run", "--rm", "--name", names["cp"], "-v", "%s:/src:ro" % os.path.dirname(master),
               "-v", "%s:/m" % mvol, "python:3.12-slim", "dd", "if=/src/%s" % os.path.basename(master),
               "of=/m/master.db", "bs=4M", "oflag=direct")
            note(step="master_volume", volume=mvol)
        for v in vols.values():
            sh("docker", "volume", "create", v)
        sh("docker", "network", "create", "--internal", names["net"])
        t = time.time()
        sh("docker", "run", "--rm", "--name", names["cp"], "-v", "%s:/m:ro" % mvol, "-v", "%s:/cfg" % vols["live"],
           "python:3.12-slim", "sh", "-c", "dd if=/m/master.db of=/cfg/home-assistant_v2.db bs=4M iflag=direct "
           "oflag=direct status=none && chmod 666 /cfg/home-assistant_v2.db && chmod 777 /cfg")
        note(step="live_copy", seconds=round(time.time() - t, 1))
        key = os.urandom(32).hex()
        sh("docker", "run", "-d", "--name", names["anc"], "--network", names["net"], "--network-alias", "anchor",
           "-e", "HOMEPROV_ANCHOR_KEY=" + key, "-e", "HOMEPROV_ANCHOR_LINK=v2",
           "-v", "%s:/anchor" % vols["chain"], "-v", "%s:/published" % vols["pub"], "hpr-anchord:e8")
        sh("docker", "run", "--rm", "--name", names["kg"], "-v", "%s:/sign" % vols["sign"], "--entrypoint", "python",
           a.image, "-c", "import os\nfrom cryptography.hazmat.primitives import serialization as s\n"
           "from cryptography.hazmat.primitives.asymmetric import ed25519\nk=ed25519.Ed25519PrivateKey.generate()\n"
           "os.umask(0o077)\nopen('/sign/monitor.pem','wb').write(k.private_bytes(s.Encoding.PEM,"
           "s.PrivateFormat.PKCS8,s.NoEncryption()))")
        here = os.path.dirname(os.path.abspath(__file__))
        offset = meta["history_end_ts"] - time.time() + 2.0
        polls, warm = int(a.polls or POLLS), int(a.warmup if a.warmup is not None else WARMUP)
        dur = (polls + warm) * 400 + 600
        sh("docker", "run", "-d", "--name", names["wr"], "--network", names["net"], "-v", "%s:/cfg" % vols["live"],
           "-v", "%s:/h:ro" % here, "python:3.12-slim", "python", "-u", "/h/e9_cost_scale.py", "writer",
           "--db", "/cfg/home-assistant_v2.db", "--offset", repr(offset), "--history-end", repr(meta["history_end_ts"]),
           "--duration", str(dur))
        time.sleep(15)
        env = {"HOMEPROV_DB": "/cfg/home-assistant_v2.db", "HOMEPROV_ANCHOR": "http://anchor:9900/append",
               "HOMEPROV_PERIOD": str(PERIOD), "HOMEPROV_SCRATCH": "/scratch", "HOMEPROV_ANCHOR_KEY": key,
               "HOMEPROV_SCHEME": "stable", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "1",
               "HOMEPROV_ESCROW_DIR": "/escrow", "HOMEPROV_SIGN_KEY": "/sign/monitor.pem", "HOMEPROV_REPLY_TAGS": "1"}
        if mode == "direct":
            env["HOMEPROV_READ"] = "direct"
        for kv in (a.env or []):
            k_, v_ = kv.split("=", 1)
            env[k_] = v_
        envargs = [x for k_, v_ in env.items() for x in ("-e", "%s=%s" % (k_, v_))]
        lim = ["--cpus", LIMITS["cpus"], "--memory", LIMITS["memory"],
               "--device-read-bps", "%s:%s" % (LIMITS["device"], LIMITS["device_read_bps"]),
               "--device-write-bps", "%s:%s" % (LIMITS["device"], LIMITS["device_write_bps"])]
        ro = ":ro" if not a.rw_mount else ""
        note(step="monitor_start", env={k_: ("<key>" if k_ == "HOMEPROV_ANCHOR_KEY" else v_)
                                        for k_, v_ in env.items()}, mount_ro=not a.rw_mount, offset=offset)
        sh("docker", "run", "-d", "--name", names["mon"], "--network", names["net"], *lim, *envargs,
           "-v", "%s:/cfg%s" % (vols["live"], ro), "-v", "%s:/scratch" % vols["scratch"],
           "-v", "%s:/escrow" % vols["escrow"], "-v", "%s:/sign:ro" % vols["sign"], "-v", "%s:/h:ro" % here,
           "--entrypoint", "python", a.image, "-u", "/h/e9_cost_scale.py", "harness", "--monitor", "/app/monitor.py",
           "--offset", repr(offset), "--polls", str(polls), "--warmup", str(warm), "--period", str(PERIOD))
        n_ctx = 0
        while sh("docker", "inspect", "-f", "{{.State.Running}}", names["mon"]) == "true":
            time.sleep(10)
            n_ctx += 1
            if n_ctx % 30 == 0:
                note(step="during", context=context())
        mlog = subprocess.run(["docker", "logs", names["mon"]], capture_output=True, text=True)
        open(os.path.join(rundir, "monitor.jsonl"), "w").write(mlog.stdout + mlog.stderr)
        note(step="monitor_done", exit=sh("docker", "inspect", "-f", "{{.State.ExitCode}}", names["mon"]),
             context=context())
        sh("docker", "stop", "-t", "5", names["wr"], check=False)
        wlog = subprocess.run(["docker", "logs", names["wr"]], capture_output=True, text=True)
        open(os.path.join(rundir, "writer.jsonl"), "w").write(wlog.stdout + wlog.stderr)
        sizes = sh("docker", "run", "--rm", "-v", "%s:/cfg:ro" % vols["live"], "-v", "%s:/scratch:ro" % vols["scratch"],
                   "-v", "%s:/escrow:ro" % vols["escrow"], "-v", "%s:/anchor:ro" % vols["chain"], "python:3.12-slim",
                   "sh", "-c", "for f in /cfg/* /scratch/* /escrow/* /anchor/*; do [ -f $f ] && echo $f $(stat -c %s $f); "
                   "done; wc -l < /anchor/chain.jsonl")
        open(os.path.join(rundir, "sizes.txt"), "w").write(sizes + "\n")
        note(step="sizes", sizes=sizes.splitlines(), load=sh("uptime"))
    finally:
        for c in names.values():
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)
        for v in vols.values():
            subprocess.run(["docker", "volume", "rm", "-f", v], capture_output=True)
        subprocess.run(["docker", "network", "rm", names["net"]], capture_output=True)
        note(step="teardown", left=sh("docker", "ps", "-a", "--format", "{{.Names}}", "-f", "name=%s-" % PREFIX,
                                      check=False))
        log.close()


# ============================================================================================ summarize (on the Mac)
def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * (len(xs) - 1)))]


def summ(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"n": len(xs), "median": round(statistics.median(xs), 3), "p90": round(q(xs, 0.9), 3),
            "max": round(max(xs), 3), "min": round(min(xs), 3)}


WAL_KEY = "cfg/home-assistant_v2.db-wal"


def wal_stats(polls):
    """The live recorder's -wal file size over the measured polls, sampled after each poll and (when recorded) before
    it. The WAL file is not truncated by a passive checkpoint, so its size is the furthest the hub's writes have extended
    it since the run started; it grows past the autocheckpoint size when backfill is held off."""
    meas = [p for p in polls if not p["warmup"]]
    after = [p["sizes"].get(WAL_KEY) for p in meas if WAL_KEY in p.get("sizes", {})]
    before = [p["sizes_before"].get(WAL_KEY) for p in meas if WAL_KEY in p.get("sizes_before", {})]
    return {"after_poll": summ(after), "before_poll": summ(before) if before else None,
            "first_after_poll": after[0] if after else None, "last_after_poll": after[-1] if after else None,
            "series_after_poll": after}


def read_polls(d):
    polls, hstart = [], None
    for line in open(os.path.join(d, "monitor.jsonl")):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("harness") == "start":
            hstart = r
        elif "poll" in r:
            polls.append(r)
    return polls, hstart


def summarize(a):
    out_path = a.out or DST
    if os.path.exists(out_path):
        raise SystemExit("refusing to overwrite " + out_path)
    runs = {}
    for d in a.runs:
        tag = os.path.basename(os.path.normpath(d))
        steps = [json.loads(x) for x in open(os.path.join(d, "run.log")) if x.strip()]
        start = steps[0]
        polls, hstart = [], None
        for line in open(os.path.join(d, "monitor.jsonl")):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("harness") == "start":
                hstart = r
            elif "poll" in r:
                polls.append(r)
        meas = [p for p in polls if not p["warmup"]]
        w = [json.loads(x) for x in open(os.path.join(d, "writer.jsonl")) if x.strip().startswith("{")]
        wstop = next((x for x in w if x.get("writer") == "stop"), None)
        wstart = next((x for x in w if x.get("writer") == "start"), None)
        phase_names = sorted({k for p in meas for k in p["phases_ms"]})
        t_first, t_last = (meas[0]["clock"], meas[-1]["clock"]) if meas else (None, None)
        runs[tag] = {
            "k": start["k"], "mode": start["mode"], "image": start["image"], "limits": start["limits"],
            "master_bytes": start["master_bytes"], "master_sha256": start["master_sha256"],
            "monitor_sha256": (hstart or {}).get("monitor_sha256"), "read_mode": (hstart or {}).get("read_mode"),
            "wrapped_functions": (hstart or {}).get("wrapped"),
            "polls_measured": len(meas), "warmup_polls": sum(1 for p in polls if p["warmup"]),
            "poll_errors": [p["err"] for p in meas if p["err"]],
            "unobservable_polls": sum(1 for p in meas if p["tick"].get("evidence_unobservable")),
            "unobservable_reasons": dict(collections.Counter(p["tick"].get("reason") for p in meas
                                                             if p["tick"].get("evidence_unobservable"))),
            "unobservable_detail_examples": [p["tick"].get("detail") for p in polls
                                             if p["tick"].get("evidence_unobservable") and p["tick"].get("detail")][:3],
            "read_path_counts": dict(collections.Counter(p["tick"].get("read", "copy") for p in meas)),
            "read_attempts_counts": dict(sorted(collections.Counter(
                int(p["tick"].get("read_attempts") or 1) for p in meas if p["tick"].get("read") == "direct").items())),
            "read_attempts_note": "direct reads per measured poll (monitor.py logs read_attempts only when a raced read "
                                  "was retried; absent = 1)",
            "quick_check_outcomes": ({"polls_with_quick_check": sum(1 for p in meas if any(
                                          c["quick_check_ran"] for c in p.get("checks", []))),
                                      "passed": sum(1 for p in meas for c in p.get("checks", [])
                                                    if c["quick_check_ran"] and c["ok"]),
                                      "failed": sum(1 for p in meas for c in p.get("checks", [])
                                                    if c["quick_check_ran"] and not c["ok"]),
                                      "check_connection_without_quick_check": sum(
                                          1 for p in meas for c in p.get("checks", []) if not c["quick_check_ran"]),
                                      "check_connection_failed_reasons": dict(collections.Counter(
                                          c["reason"] for p in meas for c in p.get("checks", []) if not c["ok"])),
                                      "warmup_polls": [{"poll": p["poll"], "checks": p.get("checks")}
                                                       for p in polls if p["warmup"]]}
                                     if any("checks" in p for p in polls) else None),
            "env_extra": next((x.get("env") for x in steps if x.get("step") == "monitor_start"), None),
            "failed_appends": sum(1 for p in meas if not p["anchor_ok"]),
            "per_poll_ms": {"total": summ([p["total_ms"] for p in meas]),
                            "tick_copy_ms": summ([p["tick"].get("copy_ms") for p in meas]),
                            "tick_load_ms": summ([p["tick"].get("load_ms") for p in meas]),
                            "tick_commit_ms": summ([p["tick"].get("commit_ms") for p in meas]),
                            "tick_append_ms": summ([p["tick"].get("append_ms") for p in meas]),
                            **{"phase_" + n: summ([p["phases_ms"].get(n, 0.0) for p in meas]) for n in phase_names}},
            "per_poll_bytes": {**{"proc_" + k: summ([p["proc_io"][k] for p in meas])
                                  for k in ("rchar", "wchar", "read_bytes", "write_bytes")},
                               **{"cgroup_" + k: summ([p["cgroup_io"][k] for p in meas]) for k in ("rbytes", "wbytes")}},
            "measured_window": {"clock_first": t_first, "clock_last": t_last,
                                "seconds": round(t_last - t_first, 1) if meas else None,
                                **{"sum_" + k: sum(p["proc_io"][k] for p in meas) for k in
                                   ("read_bytes", "write_bytes", "rchar", "wchar")},
                                **{"sum_cgroup_" + k: sum(p["cgroup_io"][k] for p in meas) for k in
                                   ("rbytes", "wbytes")}},
            "rows_in_open_window": summ([p["tick"].get("n_nodes") for p in meas]),
            "wal_bytes": wal_stats(polls),
            "writer": {"start": wstart, "stop": wstop},
            "steps": steps,
        }
        r = runs[tag]
        mw = r["measured_window"]
        if mw["seconds"]:
            r["measured_window"]["bytes_written_per_hour_proc"] = round(mw["sum_write_bytes"] / mw["seconds"] * 3600)
            r["measured_window"]["bytes_written_per_hour_cgroup"] = round(mw["sum_cgroup_wbytes"] / mw["seconds"]
                                                                          * 3600)
        if wstop and wstart:
            secs = wstop["clock"] - wstart["clock"]
            r["writer"]["rows_per_minute"] = round((wstop["states"] + wstop["events"]) / secs * 60, 2) if secs else None
    out = {"item": a.item or ("E9 C1: monitor per-poll cost on synthetic recorders of about 0.2, 1 and 3 GB, copy "
                              "mode and direct-read mode, under Docker CPU, memory and IO limits (R1 W5, R2 W4, R3 W5)"),
           "monitor_sha256_runs": sorted({r["monitor_sha256"] for r in runs.values() if r.get("monitor_sha256")}),
           "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "limits_monitor_container": LIMITS, "polls_measured_per_run": POLLS, "warmup_polls": WARMUP,
           "period_s": PERIOD, "host": sh("uname", "-a"), "docker": sh("docker", "info", "--format",
                                                                       "{{.ServerVersion}} {{.NCPU}} {{.MemTotal}}"),
           "masters": {}, "runs": runs,
           "caveats": [
               "Copy-mode scaling runs (tags *_m3e479ae0) use the evaluated E8 monitor image hpr-monitor:e8 "
               "(monitor.py 3e479ae0). Runs tagged *_m38370b2a use an image built from the working-tree monitor.py "
               "38370b2a, which carried the parallel code agent's unfinished HOMEPROV_READ=direct mode; its direct-read "
               "rows are preliminary.",
               "Direct-read correctness: exp/out/e9_readonly_shm_lockdrop.json shows that validate_files()'s ordinary "
               "open-read-close of the live database, -shm and -wal after the read transaction is pinned (as "
               "direct_snapshot() does in 38370b2a) leaves the snapshot unprotected against the writer's checkpoints "
               "(torn reads fail quick_check); exp/out/e9_readonly_shm_probe.json shows the readonly_shm reader alone "
               "stays consistent. The quick_check_failed polls of the K=15 direct runs are of that kind (the masters "
               "pass quick_check offline). Direct-read polls that skip quick_check are not checked here for torn reads.",
               "rows_in_open_window differs between runs of one size because the monitor re-reads from the start of the "
               "previous hour: runs whose measured polls fall after the clock crosses an hour boundary fold about one "
               "hour of rows, earlier ones up to two. Load and commit times scale with it; copy and check do not.",
               "Page cache: a poll's storage reads are cache misses only; the 1 GB memory limit of the monitor "
               "container bounds what it can keep cached, and pages the writer touched may be served from the VM's "
               "cache. proc_rchar counts the bytes read through system calls whether cached or not.",
               "The Mac was shared with other agents' work during the runs; load averages and per-container CPU at "
               "the start, every 300 s and at the end of each run are in runs[*].steps."],
           "definitions": {
               "total": "wall time of monitor.tick() for one poll (everything the poll does)",
               "phase_*": "time inside that monitor function during the poll (timers only; nested calls counted in "
                          "both, e.g. watermark inside keylog_poll is not nested, validate_copy holds quick_check)",
               "proc_read_bytes/write_bytes": "from /proc/self/io: bytes the monitor process caused to be fetched "
                                              "from / sent to storage in the poll (page-cache hits are not reads)",
               "proc_rchar/wchar": "bytes passed through read/write-type system calls (includes page-cache hits)",
               "cgroup_rbytes/wbytes": "the container's cgroup io.stat on the VM disk (includes writeback)",
               "bytes_written_per_hour": "sum over the measured polls / the measured window's seconds * 3600: the "
                                         "run's measured rate, expressed per hour"}}
    if a.caveats_file:
        out["caveats"] = json.load(open(a.caveats_file))
    if a.reference_runs:
        ref = {}
        for d in a.reference_runs:
            steps = [json.loads(x) for x in open(os.path.join(d, "run.log")) if x.strip()]
            polls, hstart = read_polls(d)
            ref[os.path.basename(os.path.normpath(d))] = {
                "k": steps[0]["k"], "mode": steps[0]["mode"], "monitor_sha256": (hstart or {}).get("monitor_sha256"),
                "env_extra": next((x.get("env") for x in steps if x.get("step") == "monitor_start"), None),
                "unobservable_polls": sum(1 for p in polls if not p["warmup"] and p["tick"].get("evidence_unobservable")),
                "wal_bytes": wal_stats(polls)}
        out["reference_wal_runs"] = {"what": "the live -wal size in earlier runs of exp/out/e9_cost_scale.json at the "
                                             "same sizes and writer load (copy mode reads a copy, so no read is held on "
                                             "the live recorder): a baseline for the WAL growth without a direct read",
                                     "runs": ref}
    for k in sorted({r["k"] for r in runs.values()}):
        mp = os.path.join(EXP, "c1", "master_k%d.db.json" % k)
        if os.path.exists(mp):
            m = json.load(open(mp))
            out["masters"]["k%d" % k] = {x: m[x] for x in ("k", "bytes", "sha256", "states", "events", "states_meta",
                                                          "src_sha256", "seed", "generator_sha256", "span_s")}
    with open(out_path, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", out_path, sha(out_path))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--k", required=True)
    g.add_argument("--src", default=DEFAULT_SRC)
    g.add_argument("--out", required=True)
    w = sub.add_parser("writer")
    w.add_argument("--db", required=True)
    w.add_argument("--offset", required=True)
    w.add_argument("--history-end", required=True)
    w.add_argument("--duration", required=True)
    h = sub.add_parser("harness")
    h.add_argument("--monitor", required=True)
    h.add_argument("--offset", required=True)
    h.add_argument("--polls", default=POLLS)
    h.add_argument("--warmup", default=WARMUP)
    h.add_argument("--period", default=PERIOD)
    r = sub.add_parser("run")
    r.add_argument("--k", required=True)
    r.add_argument("--mode", choices=("copy", "direct"), required=True)
    r.add_argument("--image", required=True)
    r.add_argument("--tag", required=True)
    r.add_argument("--env", nargs="*", help="extra monitor environment KEY=VALUE")
    r.add_argument("--rw-mount", action="store_true", help="mount the recorder read-write (only if a mode needs it)")
    r.add_argument("--polls", default=None, help="smoke tests only; results use the fixed POLLS")
    r.add_argument("--warmup", default=None, help="smoke tests only; results use the fixed WARMUP")
    s = sub.add_parser("summarize")
    s.add_argument("--runs", nargs="+", required=True)
    s.add_argument("--out", default=None)
    s.add_argument("--item", default=None, help="the result's item text (default: the C1 text)")
    s.add_argument("--caveats-file", default=None, help="a JSON list replacing the default caveats")
    s.add_argument("--reference-runs", nargs="*", default=None, help="earlier run dirs whose WAL sizes are added as a "
                                                                    "baseline")
    a = ap.parse_args()
    {"generate": generate, "writer": writer, "harness": harness, "run": run, "summarize": summarize}[a.cmd](a)


if __name__ == "__main__":
    main()
