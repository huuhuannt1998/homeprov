"""HOMEPROV external monitor.

WHY THIS EXISTS. The previous defender was a Home Assistant integration, so it
executed in the adversary's interpreter. Rebinding one module-level name gave the
adversary a censored view of the recorder, and the anchor then held no record
that the adversary had acted at all (measured: the defender read 475 rows where
the graph held 477). A defender inside the process it defends cannot make the
guarantee this project claims.

WHAT CHANGED. The monitor runs in its own container, on a network the hub is not
attached to, and mounts the hub's configuration directory READ-ONLY. It receives
nothing from the hub process: no Python objects, no callbacks, no RPC. It reads
recorder state itself and computes commitments itself.

WHY IT COPIES BEFORE READING. The recorder runs in WAL mode. A read-only open of
a live WAL database fails outright, because SQLite must create the -shm file;
and `immutable=1`, which does open, silently IGNORES the WAL and therefore
misses exactly the newest rows, which is the window an adversary exploits. The
monitor instead copies the database and its sidecars into its own scratch space
and opens the copy. The hub's directory stays mounted read-only, so a compromised
monitor cannot write back into the hub either.

WHAT THIS STILL DOES NOT SOLVE. The monitor observes at a polling interval, so an
adversary that writes and deletes entirely between two polls is never observed.
That residual pre-observation window is a property of the architecture, not a bug,
and it is what experiment E1 measures.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.request

SRC = os.environ.get("HOMEPROV_DB", "/cfg/home-assistant_v2.db")
SCRATCH = os.environ.get("HOMEPROV_SCRATCH", "/scratch")
ANCHOR = os.environ.get("HOMEPROV_ANCHOR", "http://hp-anchord:9900/append")
PERIOD = float(os.environ.get("HOMEPROV_PERIOD", "5"))
STATE = os.path.join(SCRATCH, "monitor_state.json")

# The monitor's half of the authenticated append path (review 4a). The key is
# provisioned to the monitor and the anchor, and to nothing in the hub process.
# When set, every append carries an HMAC-SHA256 over the exact body the anchor
# verifies; the in-process adversary cannot produce it and its appends are
# refused at the anchor.
ANCHOR_KEY = os.environ.get("HOMEPROV_ANCHOR_KEY", "").encode()

# COMMITMENT SCHEME (2026-10-02). 'closure' commits the renderer dependency
# closure measured in E4/stage31 (the rig's b2c, key homeprov2-era): the row
# fields below PLUS context_user_id_bin on both tables, states.old_state_id and
# states.last_changed_ts, the three renderer-consumed fields the row scheme omits.
# 'row' is the scheme every result published before 2026-10-02 was produced with;
# in row mode load() and node_hash() are byte-identical to that code, so those
# results stay reproducible with HOMEPROV_SCHEME=row.
SCHEME = os.environ.get("HOMEPROV_SCHEME", "closure")
if SCHEME not in ("closure", "row"):
    raise SystemExit("HOMEPROV_SCHEME must be 'closure' or 'row', got %r" % SCHEME)

ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]
H = lambda b: hashlib.sha256(b).digest()

LABELS = {"automation_triggered": "triggers", "call_service": "invokes"}


def _canon(obj) -> bytes:
    """Byte-identical to exp/rig/graph.py::_canon. The determinism gate compares
    the monitor's commitments against the rig's; any drift here breaks it."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def snapshot() -> str:
    """Copy the recorder and its WAL sidecars into scratch, then read the copy."""
    dst = os.path.join(SCRATCH, "recorder.db")
    for suffix in ("", "-wal", "-shm"):
        src = SRC + suffix
        out = dst + suffix
        if os.path.exists(src):
            shutil.copy2(src, out)
        elif os.path.exists(out):
            os.remove(out)          # sidecar vanished upstream; do not read a stale one
    return dst


WAL_MAGIC = (0x377F0682, 0x377F0683)


def validate_copy(db: str):
    """FAIL-CLOSED evidence check (review 4d). The adversary owns the file the
    monitor copies, so a damaged or truncated copy is an adversary-controlled
    view, not a neutral one. E5 showed the monitor reading a consistent prefix of
    a truncated WAL (6409 of 6857 nodes) and sealing over the gap with no error.

    This validates the copy BEFORE it is folded and returns (ok, reason, detail).
    When it returns ok=False the monitor must not seal; it anchors an explicit
    'evidence unobservable' record instead, so the gap is on the chain rather
    than silently absorbed.

    Detection of a truncated/zeroed WAL uses the WAL-index (-shm) header, which
    records the number of committed frames (mxFrame). A -wal too small to hold
    those frames, or carrying an invalid magic, is damaged: SQLite would silently
    ignore it and lose exactly the newest rows. A cleanly checkpointed database
    resets mxFrame, so normal WAL operation is not flagged.
    """
    try:
        with open(db, "rb") as fh:
            hdr = fh.read(100)
    except OSError as exc:
        if not os.path.exists(db):
            return False, "db_missing", {}
        return False, "db_unreadable", {"exc": repr(exc)[:120]}
    if hdr[:16] != b"SQLite format 3\x00":
        return False, "bad_db_header", {"magic": hdr[:16].hex()}
    wal, shm = db + "-wal", db + "-shm"
    if os.path.exists(wal):
        wsz = os.path.getsize(wal)
        mx = spage = None
        if os.path.exists(shm):
            with open(shm, "rb") as fh:
                s = fh.read(96)
            if len(s) >= 96:
                mx = max(struct.unpack_from("<I", s, 16)[0],
                         struct.unpack_from("<I", s, 64)[0])
                spage = struct.unpack_from("<H", s, 14)[0] or 4096
        if 0 < wsz < 32:
            return False, "wal_truncated_header", {"wal_size": wsz}
        if wsz == 0:
            if mx and mx > 0:
                return False, "wal_truncated", {"wal_size": 0, "shm_mxframe": mx}
        else:
            with open(wal, "rb") as fh:
                wh = fh.read(12)
            magic = struct.unpack_from(">I", wh, 0)[0]
            if magic not in WAL_MAGIC:
                return False, "wal_header_corrupt", {"wal_magic": hex(magic),
                                                     "shm_mxframe": mx}
            wpage = struct.unpack_from(">I", wh, 8)[0] or 4096
            if (wsz - 32) % (wpage + 24) != 0:
                return False, "wal_partial_frame", {"wal_size": wsz,
                                                    "stride": wpage + 24}
            if mx is not None and mx > 0:
                need = 32 + mx * ((spage or wpage) + 24)
                if wsz < need:
                    return False, "wal_truncated", {"wal_size": wsz,
                                                    "shm_mxframe": mx, "need": need}
    try:
        con = sqlite3.connect(db, timeout=10)
        con.execute("PRAGMA query_only=ON")
        qc = con.execute("PRAGMA quick_check").fetchone()[0]
        if qc != "ok":
            con.close()
            return False, "quick_check_failed", {"quick_check": str(qc)[:80]}
        con.execute("SELECT s.state, s.last_updated_ts, s.context_id_bin FROM states s "
                    "JOIN states_meta sm ON sm.metadata_id=s.metadata_id LIMIT 1").fetchone()
        con.execute("SELECT e.time_fired_ts, e.context_id_bin FROM events e "
                    "JOIN event_types et ON et.event_type_id=e.event_type_id LIMIT 1").fetchone()
        con.close()
    except Exception as exc:                              # noqa: BLE001
        return False, "schema_unreadable", {"exc": repr(exc)[:120]}
    return True, "ok", {}


def load(db: str, since: float | None = None):
    """Recorder rows as (ts, key, content, ctx, par, label), time-ordered.

    `since` bounds the read to rows at or after a timestamp. It is NOT a
    high-water mark on rows already seen: it is the start of the oldest segment
    that is still open. Filtering on "newer than anything I have processed" would
    let a BACKDATED insert into a still-open segment slip past unfolded, and that
    is forgery class FT-9. Re-reading from the oldest open segment bounds the work
    to one coarse segment-width of rows while leaving no gap.
    """
    con = sqlite3.connect(db, timeout=30)
    con.execute("PRAGMA query_only=ON")
    nodes = []
    closure = SCHEME == "closure"
    # In closure mode the same rows are read with the three extra closure fields
    # appended (exactly as exp/rig/graph.py loads usr/prev/changed for b2c);
    # nodes become 9-tuples. Row mode is unchanged: 6-tuples, same SQL.
    sq = ("""SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                    s.context_id_bin, s.context_parent_id_bin"""
          + (", s.context_user_id_bin, s.old_state_id, s.last_changed_ts" if closure else "")
          + """ FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"""
          + (" WHERE s.last_updated_ts >= ?" if since is not None else ""))
    for r in con.execute(sq, (since,) if since is not None else ()):
        sid, ent, st, ts, ctx, par = r[:6]
        node = (ts or 0.0, "s:%d" % sid,
                _canon({"t": "state", "e": ent, "s": st, "ts": round(ts or 0.0, 6)}),
                ctx, par, "actuates")
        nodes.append(node + (r[6], r[7], r[8]) if closure else node)
    eq = ("""SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin,
                    e.context_parent_id_bin, ed.shared_data"""
          + (", e.context_user_id_bin" if closure else "")
          + """ FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id
               LEFT JOIN event_data ed ON ed.data_id = e.data_id"""
          + (" WHERE e.time_fired_ts >= ?" if since is not None else ""))
    for r in con.execute(eq, (since,) if since is not None else ()):
        eid, ety, ts, ctx, par, data = r[:6]
        node = (ts or 0.0, "e:%d" % eid,
                _canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                ctx, par, LABELS.get(ety, "causes"))
        nodes.append(node + (r[6], None, None) if closure else node)
    con.close()
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def node_hash(key: str, content: bytes, ctx, par, label: str) -> bytes:
    """FULL-ROW commitment: identity, payload, and both causal columns.

    Committing the record rather than a chosen projection of it is the design
    conclusion of this work. Three separate identity omissions were found in the
    bespoke graph-shaped construction this replaces, each only by testing.
    """
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + label.encode())


def node_hash_closure(key: str, content: bytes, ctx, par, label: str,
                      usr, prev, chg) -> bytes:
    """RENDERER-CLOSURE commitment: the row fields plus context_user_id_bin,
    old_state_id and last_changed_ts. Byte-for-byte the rig's b2c
    (exp/rig/commit.py), so the monitor computes what stage31 evaluated."""
    p = b"" if prev is None else str(prev).encode()
    c = b"" if chg is None else repr(round(chg, 6)).encode()
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + (usr or b"") + b"|" + p + b"|" + c
             + b"|" + label.encode())


def commit(nodes):
    """Laminar segment accumulators over the per-node hashes (row or closure)."""
    phi = {}
    for name, width in GRAN:
        segs = {}
        for n in nodes:
            ts, key, content, ctx, par, label = n[:6]
            h = (node_hash_closure(key, content, ctx, par, label, n[6], n[7], n[8])
                 if len(n) == 9 else node_hash(key, content, ctx, par, label))
            s = segs.setdefault(int(ts // width), {"acc": ZERO, "n": 0})
            s["acc"] = H(s["acc"] + h)
            s["n"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]}
                     for k, v in segs.items()}
    return phi


def sealed(phi, now: float):
    """Segments whose window has closed and can therefore never gain a row."""
    out = {}
    for name, width in GRAN:
        cutoff = int(now // width)
        out[name] = {k: v for k, v in phi.get(name, {}).items() if int(k) < cutoff}
    return out


def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {"anchored": {g: [] for g, _ in GRAN}}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(st, fh)
    os.replace(tmp, STATE)


def append(rec) -> dict:
    body = json.dumps(rec, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if ANCHOR_KEY:
        headers["X-HP-Auth"] = hmac.new(ANCHOR_KEY, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(ANCHOR, data=body, method="POST",
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code}
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "err": repr(exc)[:120]}


def tick(st) -> dict:
    """One observation cycle, incremental in history length.

    Only segments that are still OPEN can change, so only rows from the oldest
    open segment onward need folding. Sealed segments are already anchored and an
    append-only chain keeps them; a later change to one is the verifier's business
    to detect, not the monitor's to re-anchor.
    """
    t_start = time.time()
    db = snapshot()
    t_copy = time.time() - t_start
    now = time.time()

    # FAIL CLOSED over hostile input (review 4d). If the copy is damaged or
    # truncated, do not seal a partial view: anchor an explicit record that the
    # evidence was unobservable, so the gap appears on the chain.
    vok, vreason, vdetail = validate_copy(db)
    if not vok:
        rec = {"observer": "external-monitor", "ts": now, "scheme": SCHEME,
               "evidence_unobservable": True, "reason": vreason, "detail": vdetail}
        r = append(rec)
        return {"n_nodes": None, "copy_ms": round(t_copy * 1000, 3),
                "evidence_unobservable": True, "reason": vreason,
                "detail": vdetail, "sealed_new": {}, "anchor": r,
                "fail_closed": True}

    widest = max(w for _, w in GRAN)
    since = (int(now // widest) * widest) - widest    # one coarse window of slack
    nodes = load(db, since=since)
    t_load = time.time() - t_start - t_copy
    phi = commit(nodes)
    t_commit = time.time() - t_start - t_copy - t_load
    closed = sealed(phi, now)
    fresh = {}
    for g, segs in closed.items():
        known = set(st["anchored"].get(g, []))
        new = {k: v for k, v in segs.items() if k not in known}
        if new:
            fresh[g] = new
    out = {"n_nodes": len(nodes), "copy_ms": round(t_copy * 1000, 3),
           "load_ms": round(t_load * 1000, 3), "commit_ms": round(t_commit * 1000, 3),
           "sealed_new": {g: len(v) for g, v in fresh.items()}}
    if fresh:
        r = append({"observer": "external-monitor", "ts": now, "scheme": SCHEME,
                    "sealed": fresh})
        out["anchor"] = r
        if r.get("ok"):
            for g, segs in fresh.items():
                st["anchored"].setdefault(g, []).extend(segs.keys())
            save_state(st)
    return out


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    st = load_state()
    if "--phi" in sys.argv:
        # Determinism gate: emit the commitment so it can be compared against the
        # rig's independent implementation. Divergence between the artifact and
        # the evaluated design is exactly the defect this project keeps finding.
        nodes = load(snapshot())
        print(json.dumps({"n_nodes": len(nodes), "phi": commit(nodes)}, sort_keys=True))
        return
    if "--once" in sys.argv:
        print(json.dumps(tick(st)))
        return
    n = 0
    while True:
        try:
            r = tick(st)
            n += 1
            if n <= 3 or n % 12 == 0:
                print(json.dumps({"tick": n, **r}), flush=True)
        except Exception as exc:                      # noqa: BLE001
            print(json.dumps({"error": repr(exc)[:200]}), flush=True)
        time.sleep(PERIOD)


if __name__ == "__main__":
    main()
