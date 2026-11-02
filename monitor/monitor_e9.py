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

import bisect
import hashlib
import math
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
# 'stable' (round 13, experiment E7) is the BASELINE the closure is compared with
# live: every stored column of the row and of the rows it joins, except the
# columns the recorder rewrites in place for untouched rows (see STABLE_EXCLUDE).
SCHEME = os.environ.get("HOMEPROV_SCHEME", "closure")
if SCHEME not in ("closure", "row", "stable"):
    raise SystemExit("HOMEPROV_SCHEME must be 'closure', 'row' or 'stable', got %r" % SCHEME)

# NODE-HASH ENCODING (2026-10-06, review sp2027-r1 finding T7). Encoding 'v1'
# joined the node's fields with the byte '|' (0x7C) and wrote the context BLOBs
# raw, with no length and no type. It is not injective: a BLOB that contains 0x7C
# can be split across the separator (a parent id 01a112f04c7c11.. rewritten to
# 01a112f04c with 11..7c moved into an empty user column gives the same bytes), a
# NULL column and an empty BLOB both encode as nothing, and last_changed_ts was
# rounded to six decimals. Any such rewrite left every root unchanged.
# Encoding 'v2' (the default) is a canonical typed encoding: a version tag, the
# scheme as a typed field, the field count, then every field as tag + 8-byte
# length + bytes (NULL, BLOB, TEXT, INTEGER) or tag + 8-byte IEEE-754 (REAL).
# The code is prefix-free, so distinct field tuples give distinct byte strings
# (monitor/test_node_hash.py decodes it back). 'v1' stays available, byte-identical
# to the earlier code, because every anchor chain sealed before this change was
# sealed with it and can only be checked with it; anchored records now carry the
# encoding, and a record without the field was sealed with 'v1'.
ENCODING = os.environ.get("HOMEPROV_ENCODING", "v2")
if ENCODING not in ("v2", "v1"):
    raise SystemExit("HOMEPROV_ENCODING must be 'v2' or 'v1', got %r" % ENCODING)
ENCODINGS = ("v1", "v2")
# The stable scheme was written after the v1 defect was found; it has no v1 form to stay compatible with.
if SCHEME == "stable" and ENCODING != "v2":
    raise SystemExit("HOMEPROV_SCHEME=stable exists only with HOMEPROV_ENCODING=v2")

ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]
H = lambda b: hashlib.sha256(b).digest()

NODE_V2_TAG = b"HOMEPROV-node-v2\x00"
_LEN = struct.Struct(">Q")
_F64 = struct.Struct(">d")


def tlv(v) -> bytes:
    """Canonical typed, length-prefixed encoding of one recorder value.

    NULL -> b'N'; BLOB -> b'B' len bytes; TEXT -> b'T' len utf-8; INTEGER ->
    b'I' len decimal; REAL -> b'F' + 8 bytes big-endian IEEE-754. Every codeword
    determines its own end, so a concatenation of codewords parses one way only."""
    if v is None:
        return b"N"
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b"B" + _LEN.pack(len(b)) + b
    if isinstance(v, str):
        b = v.encode("utf-8", "surrogatepass")
        return b"T" + _LEN.pack(len(b)) + b
    if isinstance(v, bool):
        raise TypeError("bool is not a recorder value")
    if isinstance(v, int):
        b = str(v).encode("ascii")
        return b"I" + _LEN.pack(len(b)) + b
    if isinstance(v, float):
        return b"F" + _F64.pack(v)
    raise TypeError("unsupported recorder value type %r" % type(v).__name__)


def encode_node_v2(scheme: str, fields) -> bytes:
    """The exact bytes a v2 node hash covers: tag, scheme, field count, fields."""
    fields = tuple(fields)
    return (NODE_V2_TAG + tlv(scheme) + _LEN.pack(len(fields))
            + b"".join(tlv(f) for f in fields))

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


# TEXT DECODING (E7 re-review R2). Python's sqlite3 raises on a TEXT value that is not valid UTF-8, and the hub can
# write one into any TEXT column; read by the keylog (whose high-water cannot pass a range it cannot read), one such
# value stopped sealing for good. With coverage on, every connection the monitor opens decodes TEXT leniently: valid
# UTF-8 gives exactly the same str as before (so every hash of ordinary data is unchanged), and each byte that is not
# valid UTF-8 becomes a lone surrogate (surrogateescape). tlv() encodes str with surrogatepass, so the committed bytes
# are a deterministic, injective function of the raw bytes: a later change to those bytes changes the commitment.
# HOMEPROV_COVERAGE=0 keeps the strict default, as before.
def _lenient(b: bytes) -> str:
    return b.decode("utf-8", "surrogateescape")


def has_raw_bytes(v) -> bool:
    """True for a str decoded from TEXT that was not valid UTF-8."""
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")                             # no surrogate at all (the common case, without a scan)
        return False
    except UnicodeEncodeError:
        return any("\udc80" <= ch <= "\udcff" for ch in v)


def _connect(db: str, timeout: float = 30):
    con = sqlite3.connect(db, timeout=timeout)
    if COVERAGE:
        con.text_factory = _lenient
    return con


def _open(db):
    """(connection, owned). A path (a copy, or a verifier's file) opens its own read-only connection, which the caller
    closes; a connection (direct read, HOMEPROV_READ=direct) is the poll's one connection inside its one read
    transaction, used as it is and left open, so every read of the poll sees the same snapshot."""
    if not isinstance(db, (str, bytes, os.PathLike)):  # (not sqlite3.Connection: verifiers replace this module's
        return db, False                              # sqlite3 by a read-only shim, reproduce/verify_all.py)
    con = _connect(db)
    con.execute("PRAGMA query_only=ON")
    return con, True


def _close(con, owned: bool):
    if owned:
        con.close()


def validate_copy(db: str, quick: bool = True):
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
    bad = validate_files(db)
    if bad:
        return bad
    try:
        con = _connect(db, timeout=10)
        con.execute("PRAGMA query_only=ON")
        bad = check_connection(con, quick)
        con.close()
        if bad:
            return bad
    except Exception as exc:                              # noqa: BLE001
        return False, "schema_unreadable", {"exc": repr(exc)[:120]}
    return True, "ok", {}


def validate_files(db: str):
    """The file part of validate_copy(): the database header, and the -wal against the -shm's frame count. None when
    they pass, else (False, reason, detail)."""
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
    return None


def check_connection(con, quick: bool = True):
    """quick_check (when due) and the schema probes on an open connection; None when they pass. A failed quick_check
    returns its (False, reason, detail); a probe that raises propagates (the caller reports schema_unreadable)."""
    if quick:
        qc = con.execute("PRAGMA quick_check").fetchone()[0]
        if qc != "ok":
            return False, "quick_check_failed", {"quick_check": str(qc)[:80]}
    con.execute("SELECT s.state, s.last_updated_ts, s.context_id_bin FROM states s "
                "JOIN states_meta sm ON sm.metadata_id=s.metadata_id LIMIT 1").fetchone()
    con.execute("SELECT e.time_fired_ts, e.context_id_bin FROM events e "
                "JOIN event_types et ON et.event_type_id=e.event_type_id LIMIT 1").fetchone()
    return None


# TIMESTAMP GUARD (round 13, E7 review M2). The hub writes the recorder, so a timestamp can be TEXT, a BLOB or infinite.
# SQLite orders TEXT and BLOB after every number, so "ts >= since" loads them, and round()/int(ts // width) then raise:
# one such row stopped every poll and the verifier. With coverage on, only finite numeric timestamps are folded; the
# other rows are committed by the keylog (which reads timestamps raw) and listed in the record as "malformed".
TS_OK = "typeof({c}) IN ('real', 'integer') AND abs({c}) < 1e12"


def ts_ok(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and abs(v) < 1e12


def _where(col: str, since, guard: bool, until=None) -> str:
    conds = ([TS_OK.format(c=col)] if guard else []) + (["%s >= ?" % col] if since is not None else []) \
        + (["%s < ?" % col] if until is not None else [])
    return (" WHERE " + " AND ".join(conds)) if conds else ""


def _wargs(since, until=None) -> tuple:
    return tuple(x for x in (since, until) if x is not None)


def load(db: str, since: float | None = None, until: float | None = None):
    """Recorder rows as (ts, key, content, ctx, par, label), time-ordered.

    `since` bounds the read to rows at or after a timestamp. It is NOT a
    high-water mark on rows already seen: it is the start of the oldest segment
    that is still open. Filtering on "newer than anything I have processed" would
    let a BACKDATED insert into a still-open segment slip past unfolded, and that
    is forgery class FT-9. Re-reading from the oldest open segment bounds the work
    to one coarse segment-width of rows while leaving no gap. `until` (the streamed full-history seal only) bounds
    the read to rows before a timestamp as well.
    """
    if SCHEME == "stable":
        return load_stable(db, since, until)
    con, owned = _open(db)
    nodes = []
    closure = SCHEME == "closure"
    # In closure mode the same rows are read with the three extra closure fields
    # appended (exactly as exp/rig/graph.py loads usr/prev/changed for b2c);
    # nodes become 9-tuples. Row mode is unchanged: 6-tuples, same SQL.
    sq = ("""SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                    s.context_id_bin, s.context_parent_id_bin"""
          + (", s.context_user_id_bin, s.old_state_id, s.last_changed_ts" if closure else "")
          + """ FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"""
          + _where("s.last_updated_ts", since, COVERAGE, until))
    for r in con.execute(sq, _wargs(since, until)):
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
          + _where("e.time_fired_ts", since, COVERAGE, until))
    for r in con.execute(eq, _wargs(since, until)):
        eid, ety, ts, ctx, par, data = r[:6]
        node = (ts or 0.0, "e:%d" % eid,
                _canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                ctx, par, LABELS.get(ety, "causes"))
        nodes.append(node + (r[6], None, None) if closure else node)
    _close(con, owned)
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


# STABLE-COLUMNS SCHEME (round 13, 2026-10-08, experiment E7). The obvious alternative to deriving the commitment from
# what the renderer reads is to commit every column that does not change by itself. The whole-row baseline
# (monitor_wholerow.py) committed EVERY column and failed on most untouched seconds; the pre-image test of its runs
# (exp/out/e_d_whr_floor_preimage_d2.json, and the e_ps_whr / e_psr_whr files of the same name) reproduced the first
# anchored root of 403 of 432, 186 of 203 and 202 of 218 of those untouched failures by restoring states.last_reported_ts
# alone, and no other column was implicated; the remaining ones "cannot be decided from the final snapshot, because the
# anchored roots fold in last_reported_ts values that were overwritten after sealing" (same files). The recorder's own
# code says why: when an entity's next state is recorded, the entity's previous row (already committed, often already
# sealed) gets its last_reported_ts written in place (homeassistant.components.recorder core.py,
# _process_state_changed_event_into_session -> states_manager.update_pending_last_reported -> _commit_event_session,
# "update(States)"; read in release 2026.2.3, the deployment runs 2026.7.4). That column is therefore the one
# exclusion. (The nightly purge also rewrites old_state_id in place, queries.py disconnect_states_rows, but only on
# rows next to the retention cutoff, and the closure commits that column too.) A node is the table name, then every
# stored column of the row as
# (name, value) pairs in schema order (PRAGMA table_info, so no column is chosen by hand and a schema change changes
# the hash instead of being silently ignored), then the joined values: states_meta.entity_id and
# state_attributes.shared_attrs for a state, event_types.event_type and event_data.shared_data for an event. The
# rows read are the closure scheme's rows (same joins), so the two schemes seal the same segments with the same counts.
STABLE_EXCLUDE = {"states": ("last_reported_ts",), "events": ()}


def _q(col: str) -> str:
    return '"%s"' % col.replace('"', '""')


def load_stable(db: str, since: float | None = None, until: float | None = None):
    """Recorder rows as (ts, key, content, ctx, par, label, fields): the closure scheme's first six fields (so tools
    that read n[:6] work unchanged) and the stable field tuple that the stable node hash covers."""
    con, owned = _open(db)
    scols = [r[1] for r in con.execute("PRAGMA table_info(states)") if r[1] not in STABLE_EXCLUDE["states"]]
    ecols = [r[1] for r in con.execute("PRAGMA table_info(events)") if r[1] not in STABLE_EXCLUDE["events"]]
    nodes = []
    sq = ("SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts, s.context_id_bin, s.context_parent_id_bin,"
          " sa.shared_attrs, " + ", ".join("s.%s" % _q(c) for c in scols)
          + " FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"
            " LEFT JOIN state_attributes sa ON sa.attributes_id = s.attributes_id"
          + _where("s.last_updated_ts", since, True, until))
    for r in con.execute(sq, _wargs(since, until)):
        sid, ent, st, ts, ctx, par, attrs = r[:7]
        fields = (("states",) + tuple(x for c, v in zip(scols, r[7:]) for x in (c, v))
                  + ("states_meta.entity_id", ent, "state_attributes.shared_attrs", attrs))
        nodes.append((ts or 0.0, "s:%d" % sid,
                      _canon({"t": "state", "e": ent, "s": st, "ts": round(ts or 0.0, 6)}),
                      ctx, par, "actuates", fields))
    eq = ("SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin, e.context_parent_id_bin,"
          " ed.shared_data, " + ", ".join("e.%s" % _q(c) for c in ecols)
          + " FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id"
            " LEFT JOIN event_data ed ON ed.data_id = e.data_id"
          + _where("e.time_fired_ts", since, True, until))
    for r in con.execute(eq, _wargs(since, until)):
        eid, ety, ts, ctx, par, data = r[:6]
        fields = (("events",) + tuple(x for c, v in zip(ecols, r[6:]) for x in (c, v))
                  + ("event_types.event_type", ety, "event_data.shared_data", data))
        nodes.append((ts or 0.0, "e:%d" % eid,
                      _canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                      ctx, par, LABELS.get(ety, "causes"), fields))
    _close(con, owned)
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def node_hash(key: str, content: bytes, ctx, par, label: str,
              encoding: str | None = None) -> bytes:
    """FULL-ROW commitment: identity, payload, and both causal columns.

    Committing the record rather than a chosen projection of it is the design
    conclusion of this work. Three separate identity omissions were found in the
    bespoke graph-shaped construction this replaces, each only by testing.
    """
    if (encoding or ENCODING) == "v2":
        return H(encode_node_v2("row", (key, content, ctx, par, label)))
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + label.encode())


def node_hash_closure(key: str, content: bytes, ctx, par, label: str,
                      usr, prev, chg, encoding: str | None = None) -> bytes:
    """RENDERER-CLOSURE commitment: the row fields plus context_user_id_bin,
    old_state_id and last_changed_ts. In 'v1' byte-for-byte the rig's b2c
    (exp/rig/commit.py), so the monitor computes what stage31 evaluated; in 'v2'
    the same fields, typed and length-prefixed, last_changed_ts unrounded."""
    if (encoding or ENCODING) == "v2":
        return H(encode_node_v2("closure", (key, content, ctx, par, usr, prev, chg, label)))
    p = b"" if prev is None else str(prev).encode()
    c = b"" if chg is None else repr(round(chg, 6)).encode()
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + (usr or b"") + b"|" + p + b"|" + c
             + b"|" + label.encode())


def node_hash_stable(fields, encoding: str | None = None) -> bytes:
    """STABLE-COLUMNS commitment: the v2 typed encoding of load_stable()'s field tuple, scheme tag 'stable'."""
    if (encoding or ENCODING) != "v2":
        raise ValueError("the stable scheme exists only with node-hash encoding v2")
    return H(encode_node_v2("stable", fields))


def node_digest(n, encoding: str | None = None) -> bytes:
    """The node hash of one loaded node, selected by its shape: 9 fields closure, 7 stable, otherwise row."""
    enc = encoding or ENCODING
    ts, key, content, ctx, par, label = n[:6]
    if len(n) == 9:
        return node_hash_closure(key, content, ctx, par, label, n[6], n[7], n[8], enc)
    if len(n) == 7:
        return node_hash_stable(n[6], enc)
    return node_hash(key, content, ctx, par, label, enc)


def commit(nodes, encoding: str | None = None):
    """Laminar segment accumulators over the per-node hashes (row, closure or stable).

    `encoding` defaults to the module's ENCODING; a verifier passes the encoding
    the anchored record names (records without one were sealed with 'v1')."""
    enc = encoding or ENCODING
    if enc not in ENCODINGS:
        raise ValueError("unknown node-hash encoding %r" % enc)
    hs = [node_digest(n, enc) for n in nodes]         # once per node, not once per granularity (same result)
    phi = {}
    for name, width in GRAN:
        segs = {}
        for n, h in zip(nodes, hs):
            ts = n[0]
            s = segs.setdefault(int(ts // width), {"acc": ZERO, "n": 0})
            s["acc"] = H(s["acc"] + h)
            s["n"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]}
                     for k, v in segs.items()}
    return phi


# Round 12 (2026-10-07), experiment E3: an optional grace period before sealing. A segment is sealed at the first
# poll at least GRACE_S after it closes, so a row the recorder commits up to GRACE_S late still lands before the seal.
# The default, 0, is the evaluated behaviour: seal at the first poll after the segment closes.
GRACE_S = float(os.environ.get("HOMEPROV_GRACE_S", "0"))


def sealed(phi, now: float):
    """Segments whose window has closed (GRACE_S ago) and can therefore never gain a row."""
    out = {}
    for name, width in GRAN:
        cutoff = int((now - GRACE_S) // width)
        out[name] = {k: v for k, v in phi.get(name, {}).items() if int(k) < cutoff}
    return out


# Round 12 (2026-10-08), experiment E1: two-host placement. When the monitor reads a REPLICA of the recorder copied
# from the hub's host, its own clock runs ahead of the replica, and a second could be sealed before the replica holds
# that second's rows. HOMEPROV_CLOCK_FILE names a file the replicator rewrites after each copy with the time, on the
# monitor's side, at which that copy was requested; sealing then uses that time instead of the monitor's clock, so a
# segment is sealed only from a copy requested after it closed. The time is read BEFORE the copy, and the replicator
# replaces the replica before the clock file, so the replica the monitor copies is never older than the time it uses.
# Unset (the default) keeps the evaluated behaviour.
CLOCK_FILE = os.environ.get("HOMEPROV_CLOCK_FILE", "")


def observed_at():
    """Request time of the replica on disk (clock-file mode), or None when unreadable."""
    try:
        with open(CLOCK_FILE) as fh:
            return float(fh.read().strip())
    except (OSError, ValueError):
        return None


# Round 13 (2026-10-08), experiment E6: the NAME MAP. The displayed cause also reads inputs that live outside the
# recorder: the frontend shows a user only when the row's user id is a key of the viewer's name map (person entities,
# and for an admin viewer the account list), and it names an automation or entity from the entity registry (and the
# device registry for an entity named after its device). An integration can rename an account, re-link a person or
# rename an entity without writing any committed row, which re-attributes past rows. HOMEPROV_NAMEMAP_DIR (e.g.
# /cfg/.storage, the hub's storage directory on the read-only mount) turns on a commitment to these inputs: at each
# seal the monitor reads ONLY the display-relevant fields below (no credential, token or password field is kept; the
# auth file is parsed and every other field is dropped at once) and adds "namemap": {"v", "digest", "n", "parts"} to
# the anchored record. Unset (the default), the record is byte-identical to the evaluated one.
NAMEMAP_DIR = os.environ.get("HOMEPROV_NAMEMAP_DIR", "")
NAMEMAP_TAG = b"HOMEPROV-namemap-v1\x00"
# part -> (storage file, list key, display-relevant fields). Booleans are committed as integers 0/1.
NAMEMAP_PARTS = (
    ("auth", "auth", "users", ("id", "name", "is_active", "system_generated")),
    ("person", "person", "items", ("id", "name", "user_id")),
    ("entity", "core.entity_registry", "entities", ("entity_id", "name", "original_name", "device_id")),
    ("device", "core.device_registry", "devices", ("id", "name", "name_by_user")),
)


def namemap_entries(storage_dir: str) -> dict:
    """{part: sorted list of field tuples, or None when the file is absent}; display-relevant fields only."""
    out = {}
    for part, fname, key, fields in NAMEMAP_PARTS:
        try:
            with open(os.path.join(storage_dir, fname), "rb") as fh:
                items = (json.load(fh).get("data") or {}).get(key) or []
        except FileNotFoundError:
            out[part] = None
            continue
        rows = []
        for it in items:
            rows.append(tuple(int(v) if isinstance(v, bool) else v
                              for v in (it.get(f) for f in fields)))
        del items                                  # the auth file's credentials and tokens are not retained
        out[part] = sorted(rows, key=lambda r: tuple("" if v is None else str(v) for v in r))
    return out


def namemap_commitment(entries: dict) -> dict:
    """Canonical typed digest of the name map: per part, the sorted v2 node encodings of its entries."""
    parts, top, n_all = {}, [], 0
    for part, _f, _k, _fields in NAMEMAP_PARTS:
        rows = entries.get(part)
        hs = sorted(H(encode_node_v2("namemap." + part, r)) for r in (rows or []))
        d = H(NAMEMAP_TAG + tlv(part) + tlv(1 if rows is not None else 0) + _LEN.pack(len(hs)) + b"".join(hs))
        parts[part] = {"digest": d.hex(), "n": len(hs)}
        top.append(tlv(part) + d)
        n_all += len(hs)
    digest = H(NAMEMAP_TAG + _LEN.pack(len(top)) + b"".join(top)).hex()
    return {"v": 1, "digest": digest, "n": n_all, "parts": parts}


def namemap_seal(storage_dir: str) -> dict:
    """The record field; on a read error an explicit unobservable marker instead of a digest."""
    try:
        entries = namemap_entries(storage_dir)
    except Exception as exc:                          # noqa: BLE001
        return {"v": 1, "unobservable": True, "reason": repr(exc)[:120]}
    c = namemap_commitment(entries)
    # Keep the display-relevant entries per digest in the monitor's own scratch (outside the hub), so a verifier can
    # say which names changed; the anchor holds only the digest.
    try:
        snap = os.path.join(SCRATCH, "namemap", c["digest"] + ".json")
        if not os.path.exists(snap):
            os.makedirs(os.path.dirname(snap), exist_ok=True)
            with open(snap + ".tmp", "w") as fh:
                json.dump(entries, fh, sort_keys=True)
            os.replace(snap + ".tmp", snap)
    except OSError:
        pass
    return c


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


# RECORD SIGNATURES (E8 design A2). The HMAC on the append path authenticates the monitor to the anchor, but the key is
# shared with the anchor, so it proves nothing to a third party: the anchor host could write any record and tag it. With
# HOMEPROV_SIGN_KEY set (the path of an Ed25519 private key, PKCS#8 PEM, kept on the monitor host and nowhere else),
# every record also carries "sig_alg", "sig_fp" (SHA-256 of the raw 32-byte public key) and "sig", a detached Ed25519
# signature over record_signing_bytes(): a tag followed by the record's canonical JSON (sorted keys, the encoding the
# HMAC already covers) without the "sig" field itself. The HMAC then tags the bytes including the signature. A verifier
# holding the published public key checks each record on its own; the anchor's JSON round trip (parse, re-serialise with
# sorted keys) reproduces those bytes exactly. The `cryptography` package is imported only when the variable is set
# (pinned in requirements-sign.txt); unset, records are byte-identical to the unsigned ones.
SIGN_KEY = os.environ.get("HOMEPROV_SIGN_KEY", "")
SIG_TAG = b"HOMEPROV-record-sig-v1\x00"
SIG_ALG = "ed25519"


def record_signing_bytes(rec: dict) -> bytes:
    """The exact bytes a record signature covers."""
    return SIG_TAG + json.dumps({k: v for k, v in rec.items() if k != "sig"}, sort_keys=True).encode()


def _crypto():
    from cryptography.hazmat.primitives import serialization                     # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ed25519               # noqa: PLC0415
    return serialization, ed25519


def public_key_fingerprint(pub) -> str:
    serialization, _ed = _crypto()
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def load_public_key(path: str):
    """A published Ed25519 public key (PEM SubjectPublicKeyInfo) for verifiers."""
    serialization, ed = _crypto()
    with open(path, "rb") as fh:
        pub = serialization.load_pem_public_key(fh.read())
    if not isinstance(pub, ed.Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key: %s" % path)
    return pub


def verify_record_signature(payload: dict, pub, fp: str | None = None) -> str:
    """'ok', 'unsigned', 'wrong_key' (signed under another key) or 'bad_signature' for one record payload."""
    if "sig" not in payload:
        return "unsigned"
    fp = fp or public_key_fingerprint(pub)
    if payload.get("sig_fp") != fp or payload.get("sig_alg") != SIG_ALG:
        return "wrong_key"
    try:
        pub.verify(bytes.fromhex(payload["sig"]), record_signing_bytes(payload))
        return "ok"
    except Exception:                                 # noqa: BLE001  (InvalidSignature, or a malformed hex value)
        return "bad_signature"


_SIGNER = None
SIGN_FP = None
if SIGN_KEY:
    _ser, _ed = _crypto()
    with open(SIGN_KEY, "rb") as _fh:
        _SIGNER = _ser.load_pem_private_key(_fh.read(), password=None)
    if not isinstance(_SIGNER, _ed.Ed25519PrivateKey):
        raise SystemExit("HOMEPROV_SIGN_KEY must name an Ed25519 private key (PKCS#8 PEM)")
    SIGN_FP = public_key_fingerprint(_SIGNER.public_key())


def sign_record(rec: dict) -> dict:
    """The record with its signature fields, or the record itself (same object) when no signing key is set."""
    if _SIGNER is None:
        return rec
    rec = dict(rec, sig_alg=SIG_ALG, sig_fp=SIGN_FP)
    rec["sig"] = _SIGNER.sign(record_signing_bytes(rec)).hex()
    return rec


# TAGGED REPLIES (E8 design A4). A host on the monitor's network can answer an append with a forged {"ok": true}; the
# monitor would then drop frozen roots the anchor never stored. An anchor that tags its replies sends X-HP-Reply-Auth:
# HMAC-SHA256 under the append key over reply_tag_message() (the domain tag, the request's own X-HP-Auth value, the
# status code, the exact reply body; the same bytes as testbed/anchord/anchord.py reply_tag()), so a reply is bound to
# the request it answers and to its status. HOMEPROV_REPLY_TAGS: "1" requires a valid tag on every reply
# (an untagged or wrongly tagged reply, success or refusal, is a failed append and the roots are re-sent); "0" never
# checks; "auto" (the default) requires tags once a validly tagged reply has been seen from this anchor (remembered in
# the coverage monitor's state), so an anchor that does not tag replies works as before. Needs HOMEPROV_ANCHOR_KEY.
REPLY_TAGS = os.environ.get("HOMEPROV_REPLY_TAGS", "auto")
if REPLY_TAGS not in ("auto", "0", "1"):
    raise SystemExit("HOMEPROV_REPLY_TAGS must be 'auto', '0' or '1', got %r" % REPLY_TAGS)
REPLY_TAG_HEADER = "X-HP-Reply-Auth"
_REPLY = {"seen": False}


def reply_tag_message(req_tag: str, status: int, body: bytes) -> bytes:
    return (b"homeprov-anchor-reply-v1\n" + (req_tag or "").encode("latin-1", "replace") + b"\n"
            + str(int(status)).encode() + b"\n" + body)


def _reply_check(req_tag, status, body: bytes, tag) -> str:
    """'ok', 'missing', 'bad', or 'off' (no key, or checking disabled)."""
    if not ANCHOR_KEY or REPLY_TAGS == "0" or req_tag is None:
        return "off"
    if not tag:
        return "missing"
    want = hmac.new(ANCHOR_KEY, reply_tag_message(req_tag, status, body), hashlib.sha256).hexdigest()
    return "ok" if hmac.compare_digest(str(tag).encode("latin-1", "replace"), want.encode()) else "bad"


def _reply_required() -> bool:
    return bool(ANCHOR_KEY) and (REPLY_TAGS == "1" or (REPLY_TAGS == "auto" and _REPLY["seen"]))


def append(rec) -> dict:
    body = json.dumps(rec, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if ANCHOR_KEY:
        headers["X-HP-Auth"] = hmac.new(ANCHOR_KEY, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(ANCHOR, data=body, method="POST",
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw, tag, status = r.read(), r.headers.get(REPLY_TAG_HEADER), r.status
            out = json.loads(raw)
    except urllib.error.HTTPError as e:
        raw, tag, status = e.read() or b"", e.headers.get(REPLY_TAG_HEADER) if e.headers else None, e.code
        out = {"ok": False, "http": e.code}
        if COVERAGE:
            # The coverage monitor needs the anchor's reason for a refusal: a 409 names the segment whose root the
            # anchor already holds differently, and without it that one segment would block every later append.
            try:
                out["body"] = json.loads(raw or b"{}")
            except Exception:                         # noqa: BLE001
                pass
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "err": repr(exc)[:120]}
    check = _reply_check(headers.get("X-HP-Auth"), status, raw, tag)
    if check == "ok":
        _REPLY["seen"] = True
    elif check in ("missing", "bad") and _reply_required():
        # not the anchor's answer to this request: neither its "ok" nor its refusal is believed
        return {"ok": False, "err": "reply_tag_" + check, "unverified_reply": out}
    if COVERAGE and check != "off":
        out = dict(out, reply_tag=check) if isinstance(out, dict) else out
    return out


# Round 13 (2026-10-08), experiment E7: SEALED COVERAGE, STALL-PROOF SEALING, ESCROW.
#
# WHAT WAS MISSING. A record held (root, row count) per sealed segment and nothing else, and a record was appended only
# when a poll sealed something. Three consequences, each found by the internal review of round 13:
#   1. The verifier could not tell a row that was in a segment when it was sealed from a row that arrived later, so an
#      edit plus enough rows inserted into the edited second was "rows arrived after the seal" and counted undetected.
#   2. A second that held no row when it was sealed left no trace, so a row backdated into it was never examined.
#   3. When appends failed, every poll recomputed the unanchored segments from the CURRENT copy, so a row edited during
#      the outage was sealed in its edited form, segments older than the re-read window were never anchored, and nothing
#      recorded the outage.
#
# WHAT EACH RECORD NOW CARRIES (HOMEPROV_COVERAGE=1, the default), read from the same copy the roots are computed from:
#   wm        {"states": max(state_id), "events": max(event_id)}. The recorder is the only writer and SQLite assigns an
#             INTEGER PRIMARY KEY as max+1 in commit order (VACUUM does not renumber), so the copy holds exactly the rows
#             with key <= wm. A row of a sealed segment whose key exceeds the sealing poll's wm arrived after the seal.
#   through   the sealing cutoff: every second s with since <= s < through is sealed at or before this record (a minute
#             or hour segment is sealed once its end is <= through). A second in that range with no segment held no row.
#   since     the start of the re-read window; seconds before it were not examined by this poll.
#   copy_at   the monitor's clock when the copy began (in clock-file mode, the replica's request time): a row absent
#             from the copy was committed after it, which is the lower bound the verifier's late-row test needs.
#   seq_local the monitor's own poll counter, persisted, so a missing record shows as a jump.
# A record is appended at EVERY poll (the heartbeat), also when nothing is newly sealed; "sealed" is then {}.
#
# STALL-PROOF SEALING. A segment's root and count are FROZEN, with the sealing poll's time, counter and wm, the first
# time a poll's cutoff passes it, and kept in the persistent state ("pending") until an append carrying them succeeds.
# Later polls re-send the frozen roots and never recompute them, and pending entries do not expire with the re-read
# window. A segment sealed by an earlier poll carries "sealed_at", "seal_seq" and "wm" in the record; the heads of polls
# whose own record failed ride in "backlog", so the verifier sees every poll's wm, through and copy time. Every failed
# append is printed with its error (the local alarm).
#
# ESCROW (HOMEPROV_ESCROW_DIR, default off). At sealing, the exact node tuples folded into each sealed second, with that
# second's root, are appended as one JSON line to <dir>/escrow.jsonl outside the hub; with the keylog on, so are the
# exact keylog tuples of every row at its first observation, one line per committed sub-range ("kind": "keylog"). Recomputing the root from them
# reproduces the anchored root, so the escrow is checked against the anchor before it is believed; the verifier then
# lists the original closure fields of every changed row. The escrow is a copy of the history's closure fields outside
# the hub, which is a privacy cost, hence off by default.
#
# HOMEPROV_COVERAGE=0 runs the earlier tick() unchanged: same records, same state file, byte for byte.
_cov = os.environ.get("HOMEPROV_COVERAGE", "1")
if _cov not in ("0", "1"):
    raise SystemExit("HOMEPROV_COVERAGE must be '0' or '1', got %r" % _cov)
COVERAGE = _cov == "1"
COVERAGE_VERSION = 1
ESCROW_DIR = os.environ.get("HOMEPROV_ESCROW_DIR", "")
# RECORD SIZE. The hardened anchor refuses a body over HOMEPROV_ANCHOR_MAX_BODY (16 MiB by default) with 413, unread,
# and cuts a request not read within 10 s. After a long outage the frozen roots and the backlog heads (about 200 bytes
# each) can exceed that in one record, and a monitor that retried the same record would be refused forever. So a poll
# sends its items, backlog heads first and then frozen roots by sealing poll (oldest first), in records of at most
# MAX_RECORD_BYTES; the first record is the poll's own, and the rest follow at once as continuation records of the same
# poll, carrying the same poll fields and "part": 2, 3, ... (each re-sent root still carries its own sealed_at). A 413
# halves the size (kept in the state, never below MIN_RECORD_BYTES) and the same items are split again and sent in the
# same poll; a 409 quarantines the refused root (below) and the rest are sent. At most MAX_PARTS records per poll; any
# remainder waits for the next poll, still frozen. The default is one sixteenth of the anchor's default limit.
MAX_RECORD_BYTES = int(os.environ.get("HOMEPROV_MAX_RECORD_BYTES", str(1024 * 1024)))
MIN_RECORD_BYTES = 1024
# A 413 is REMEMBERED (the next polls start with the smaller record size) only down to this floor; below it the smaller
# size holds for the current poll only. The anchor tags its 413 for whatever request tag was offered, so a host that
# merely saw the monitor's X-HP-Auth can obtain a validly tagged 413 for it (E8 review mE8a); with the floor that can no
# longer shrink the monitor's records for good. The anchor's own limit (16 MiB by default) is far above it.
REMEMBERED_RECORD_BYTES_FLOOR = min(MAX_RECORD_BYTES, 64 * 1024)
MAX_PARTS = int(os.environ.get("HOMEPROV_MAX_PARTS", "64"))
if MAX_RECORD_BYTES < MIN_RECORD_BYTES or MAX_PARTS < 1:
    raise SystemExit("HOMEPROV_MAX_RECORD_BYTES must be >= %d and HOMEPROV_MAX_PARTS >= 1" % MIN_RECORD_BYTES)
# Optional per-poll cost log (copy, load, commit, append milliseconds), one JSON line per poll; off when unset.
COST_LOG = os.environ.get("HOMEPROV_COST_LOG", "")

# DIRECT READ (round 13, E9 item A4; reviews r3 R1 W5, R2 W4). Copying the recorder and its WAL at every poll costs a
# full read and write of the database (186 MB on the lab installation, more on a real one). HOMEPROV_READ=direct reads
# the live recorder instead, through ONE read-only SQLite connection opened with mode=ro&readonly_shm=1 (the monitor
# never writes the hub's files, even on a writable mount; with a read-only -shm SQLite builds the WAL index in its own
# memory) and ONE read transaction per poll: the transaction starts at the poll's first read and every read of the poll
# (watermark, keylog, segment rows) sees that one snapshot, while the hub keeps writing; a checkpoint waits for the
# transaction to end (at most one poll's read time). copy_at is the time taken just before that first read, so a row
# absent from the snapshot was committed after it, as for a copy. The evidence checks stay: validate_files() on the live
# database, -wal and -shm, then quick_check and the schema probes through the same connection; any failure, or an
# exception while opening, makes the poll evidence_unobservable exactly as in copy mode (reasons direct_open_failed,
# the validate_files() reasons, quick_check_failed, schema_unreadable). When the hub's -wal or -shm does not exist (the hub is stopped, or
# closed cleanly), the poll falls back to a copy. The connection is closed (transaction rolled back) right after the
# rows are read, before escrow and the append. Records are byte-identical to copy mode's for the same snapshot (tests,
# exp/sp2027/e9_direct_read_identity.py); the read path is in the cost log ("read"), not in the record.
# HOMEPROV_QUICK_CHECK_EVERY=N runs quick_check at every Nth poll (seq_local % N == 1, so the first poll always), in
# either mode; the default 1 runs it at every poll, as before. The schema probes run at every poll.
# NO FILE IS OPENED AND CLOSED WHILE THE READ IS HELD (2026-10-10, exp/out/e9_readonly_shm_lockdrop.json). SQLite's
# locks are POSIX advisory locks, which belong to the process and the file, not to the descriptor: closing ANY
# descriptor of the database, -wal or -shm drops every lock the process holds on that file, so the read lock that holds
# a checkpoint off the snapshot was lost when validate_files() (open, read, close) ran after the snapshot was pinned,
# and a checkpoint could tear it (quick_check failed in 11 of 18 such reads, 0 of 18 without). Now validate_files()
# runs BEFORE the connection is opened (repeated up to 3 times, 20 ms apart, while the hub's writes leave the live files
# momentarily inconsistent) and again AFTER it is closed (direct_finish(): damage done to the files during the read
# fails the poll closed, its rows unused); while the read is held the files are read only through SQLite and through
# two descriptors opened before the connection and closed after it (_read_stamp()).
# READ RACE CHECK (E9 code review m3). Through those descriptors the monitor reads the WAL header's checkpoint sequence
# and salts and the database header's change counter right after the snapshot is pinned and again after the rows are
# read. While a read lock is held, SQLite cannot reset the WAL, and a checkpoint backfills only frames inside the
# snapshot, so these bytes cannot move; if they did, the locks did not hold and the poll fails closed ("read_raced").
READ = os.environ.get("HOMEPROV_READ", "copy")
if READ not in ("copy", "direct"):
    raise SystemExit("HOMEPROV_READ must be 'copy' or 'direct', got %r" % READ)
try:
    QUICK_CHECK_EVERY = int(os.environ.get("HOMEPROV_QUICK_CHECK_EVERY", "1"))
except ValueError:
    QUICK_CHECK_EVERY = 0
if QUICK_CHECK_EVERY < 1:
    raise SystemExit("HOMEPROV_QUICK_CHECK_EVERY must be an integer >= 1")
if READ == "direct" and (not COVERAGE or CLOCK_FILE):
    raise SystemExit("HOMEPROV_READ=direct needs HOMEPROV_COVERAGE=1 and no HOMEPROV_CLOCK_FILE")


def quick_check_due(seq: int) -> bool:
    return QUICK_CHECK_EVERY == 1 or seq % QUICK_CHECK_EVERY == 1


_DIRECT = {}                                          # the poll's stamp descriptors and the stamp read at pinning


def _read_stamp(fds):
    """The WAL header's checkpoint sequence and salts (bytes 12-23) and the database header's change counter (bytes
    24-27), read with pread() through descriptors opened before the read transaction (never opened or closed during
    it: see NO FILE IS OPENED AND CLOSED WHILE THE READ IS HELD)."""
    out = {}
    for name, off, n in (("wal", 12, 12), ("db", 24, 4)):
        fd = fds.get(name)
        try:
            out[name] = None if fd is None else os.pread(fd, n, off).hex()
        except OSError:
            out[name] = None
    return out


def _validate_files_retry(path):
    bad = None
    for _attempt in range(3):
        bad = validate_files(path)
        if not bad:
            return None
        time.sleep(0.02)
    return bad


def direct_snapshot(quick: bool = True):
    """(connection or None, copy_at, (ok, reason, detail)). The connection holds this poll's read transaction; end it
    with direct_finish() (or direct_close() when its rows are not used)."""
    import urllib.parse                                # noqa: PLC0415
    copy_at = time.time()
    direct_close(None)                                # no descriptor of an earlier poll is left open
    bad = _validate_files_retry(SRC)                  # before the connection: see NO FILE IS OPENED AND CLOSED ...
    if bad:
        return None, copy_at, bad
    fds = {}
    for name, path in (("db", SRC), ("wal", SRC + "-wal")):
        try:
            fds[name] = os.open(path, os.O_RDONLY)
        except OSError:
            fds[name] = None
    _DIRECT["fds"] = fds
    con = None
    try:
        con = sqlite3.connect("file:%s?mode=ro&readonly_shm=1" % urllib.parse.quote(SRC), uri=True, timeout=10,
                              isolation_level=None, check_same_thread=False)
        con.text_factory = _lenient
        con.execute("PRAGMA query_only=ON")
        copy_at = time.time()
        con.execute("BEGIN")
        con.execute("SELECT count(*) FROM sqlite_master").fetchone()     # the first read: the snapshot is pinned
    except Exception as exc:                          # noqa: BLE001
        direct_close(con)
        return None, copy_at, (False, "direct_open_failed", {"exc": repr(exc)[:160]})
    _DIRECT["stamp"] = _read_stamp(fds)
    try:
        bad = check_connection(con, quick)
    except Exception as exc:                          # noqa: BLE001
        bad = (False, "schema_unreadable", {"exc": repr(exc)[:120]})
    if bad:
        direct_close(con)
        return None, copy_at, bad
    return con, copy_at, (True, "ok", {})


DIRECT_READ_ATTEMPTS = 3


def _escrow_size():
    """The escrow file's size (0 when absent), or None without an escrow."""
    if not ESCROW_DIR:
        return None
    try:
        return os.path.getsize(os.path.join(ESCROW_DIR, "escrow.jsonl"))
    except OSError:
        return 0


def _escrow_truncate(size):
    """Cut the escrow file back to `size` bytes (the lines a discarded read wrote)."""
    if size is None:
        return
    path = os.path.join(ESCROW_DIR, "escrow.jsonl")
    try:
        if os.path.getsize(path) > size:
            os.truncate(path, size)
    except OSError:
        pass


def direct_finish(con):
    """End the poll's read transaction after its rows were read: None, or (False, reason, detail) when the poll must
    fail closed: "read_raced" (the stamp moved while the read was held), or a validate_files() reason found after the
    connection was closed (detail "after_read": true)."""
    first = _DIRECT.get("stamp")
    last = _read_stamp(_DIRECT.get("fds") or {})
    direct_close(con)
    if first != last:
        return False, "read_raced", {"pinned": first, "after_rows": last}
    bad = _validate_files_retry(SRC)
    if bad:
        return bad[0], bad[1], dict(bad[2] or {}, after_read=True)
    return None


def direct_close(con):
    """Roll back and close the connection, THEN close the stamp descriptors (closing them first would drop the locks
    of a read still held)."""
    if con is not None:
        try:
            con.execute("ROLLBACK")
        except Exception:                             # noqa: BLE001
            pass
        try:
            con.close()
        except Exception:                             # noqa: BLE001
            pass
    for fd in (_DIRECT.pop("fds", None) or {}).values():
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    _DIRECT.pop("stamp", None)

# KEYLOG (round 13, E7 review B1). The late-row test dates a row by its key: a row whose key exceeds the sealing poll's
# wm "arrived after the seal", and it is benign when that was within LATE_BOUND of its timestamp. But a key is assigned
# when a row is first written, and the row's timestamp, content and visibility can change afterwards. The review showed
# three ways to reserve a key early and fill it later with a row backdated into a sealed second, scored benign: a row
# parked with a far-future timestamp (its segments stay open) and moved back later; a row written at once into the
# sealed second with a metadata_id that does not exist yet (the inner join never loads it) and made visible later; and
# an explicit key far above the maximum, which opens a gap that a later row fills. Nothing committed such a row while it
# sat in an open segment, unjoined or in a gap.
# The keylog binds every row at its FIRST observation, whatever segment it is in. Each poll commits, per table, the key
# range (from, to] = (previous high-water, wm] that its copy holds for the first time: the rows read from the table
# ITSELF with LEFT JOINs (so an unjoinable row, or one with a malformed or far-future timestamp, is still committed), in
# key order, each as the v2 typed encoding of its renderer-closure columns with the timestamp raw (the stable scheme:
# every stable column), folded like a segment, with a 32-bit prefix of each row's hash for localisation (the security
# is the 256-bit fold; a prefix collision only loses the localisation, and the verifier then flags the whole range).
# The high-water only rises, so a falling wm (the newest row deleted) never reopens a range; a gap inside a range is
# committed as empty, so a row inserted into it later changes the range. last_reported_ts is not committed: the recorder
# rewrites it in place on committed rows (see STABLE_EXCLUDE). The range rides in the poll's record and, if that append
# fails, in its backlog head, so it is stall-proof like the frozen roots. The first poll of a monitor (no high-water in
# its state) starts each range above the largest key of a row that is already sealed (timestamp < through), so every
# row not yet sealed is bound from that first observation; older rows are covered, as before, by the segment roots of
# the re-read window. HOMEPROV_KEYLOG=0 turns it off (for comparison).
_kl = os.environ.get("HOMEPROV_KEYLOG", "1")
if _kl not in ("0", "1"):
    raise SystemExit("HOMEPROV_KEYLOG must be '0' or '1', got %r" % _kl)
KEYLOG = _kl == "1"
KEY_COL = {"states": "state_id", "events": "event_id"}
TS_COL = {"states": "last_updated_ts", "events": "time_fired_ts"}
KEYLOG_COLS = {"states": ("state_id", "state", "last_updated_ts", "last_changed_ts", "old_state_id", "context_id_bin",
                          "context_parent_id_bin", "context_user_id_bin"),
               "events": ("event_id", "time_fired_ts", "context_id_bin", "context_parent_id_bin", "context_user_id_bin")}
# (joined table, joined column, foreign key) -- the renderer-closure joins; the stable scheme adds the attributes
KEYLOG_JOINS = {"states": (("states_meta", "entity_id", "metadata_id"),),
                "events": (("event_types", "event_type", "event_type_id"), ("event_data", "shared_data", "data_id"))}
STABLE_JOINS = {"states": (("states_meta", "entity_id", "metadata_id"), ("state_attributes", "shared_attrs",
                                                                          "attributes_id")),
                "events": KEYLOG_JOINS["events"]}
MALFORMED_CAP = 50
# A range is committed as consecutive sub-ranges of at most KEYLOG_CHUNK rows (about 2.5 KB each with the localisation
# prefixes), so no record item outgrows a small anchor body limit, even after a long monitor outage; a backlog head
# larger than HEAD_PIECE_BYTES is stored as several pieces with one sub-range each, merged again by the verifier.
KEYLOG_CHUNK = 128
HEAD_PIECE_BYTES = 4096

# PER-ROW BINDING (round 13, E9 item A2; review r3 R1 W4). The 32-bit prefixes above only rank the suspects of a failed
# range: whoever writes the rows can grind a changed row to the prefix it had (2^32 work, or a birthday search for a row
# it writes itself) and add a decoy, so the verifier has to treat every row of a failed range as a suspect, and in E8
# more than half of the untouched seconds became suspects. With HOMEPROV_ROWBIND=1 each keylog row entry carries the
# FULL 256-bit row hash in place of the 8-hex prefix ([key offset, 64 hex, first-observed second]) and the entry carries
# "bind": "row_sha256". The entry's fold is still over the same row hashes, so the verifier first checks that the listed
# hashes fold to the entry's acc and count, and then localises a failed range exactly: a row is a suspect only if its
# current hash differs, it was added, or it is gone. A second preimage of SHA-256 is needed to hide a changed row, so a
# failed range with no differing row is reported as an inconsistent binding, never cleared. Unset or "0", the entries
# are byte-identical to the earlier ones. Cost: 56 more bytes per first-observed row in the record.
_rb = os.environ.get("HOMEPROV_ROWBIND", "0")
if _rb not in ("0", "1"):
    raise SystemExit("HOMEPROV_ROWBIND must be '0' or '1', got %r" % _rb)
ROWBIND = _rb == "1"
ROWBIND_TAG = "row_sha256"

# KEYLOG REWIND (E9 code review R6). The keylog's high-water only rose: after a restore put an older recorder back, the
# rows the hub wrote with keys reusing the lost ones (up to the old high-water) were bound by their segment roots only,
# so the attacks the keylog closes (a row parked, deleted or re-timed before its second is sealed) were open again for
# them. With HOMEPROV_KEYLOG_REWIND=1, an observable poll that finds a table's watermark BELOW its high-water restarts
# that table's keylog: the new high-water is the largest key of a row timestamped before the copy time of the last
# poll that advanced the keylog (the state keeps it, "keylog_copy_at"; after a restore that is the backup's last key,
# since the backup's rows predate that poll and the rows the hub wrote after the restore follow it), and every row
# above it is committed again from this first observation on. The record and the poll's head say so:
# "keylog_rewind": {table: {"from": old high-water, "to": new high-water, "wm": the watermark}}; keys in (to, from]
# have a new incarnation from this poll on. The earlier key ranges stay on the chain and are checked as before (a
# restore's are excused only under its RESTORE marker). Unset or "0": as before (and the state has no
# "keylog_copy_at").
_kr = os.environ.get("HOMEPROV_KEYLOG_REWIND", "0")
if _kr not in ("0", "1"):
    raise SystemExit("HOMEPROV_KEYLOG_REWIND must be '0' or '1', got %r" % _kr)
KEYLOG_REWIND = _kr == "1"

# FULL-HISTORY INITIAL SEAL (round 13, E9 item A5). A monitor seals what its first poll reads: the re-read window (the
# current and the previous hour) and, through the keylog, the rows first observed after its first poll. Rows written
# before that stayed outside every commitment, so a nightly purge that disconnects one of them (old_state_id = NULL on a
# retained row whose predecessor is deleted, recorder/purge.py _purge_state_ids) could not be checked against anything.
# HOMEPROV_SINCE=<unix time> makes the FIRST observable poll of a monitor (no "since_applied" in its state) read from the
# hour boundary at or before that time: every segment from there to the cutoff is sealed by that poll, and the keylog's
# first range starts above the largest key of a row older than that boundary (HOMEPROV_SINCE=0: every row, whatever its
# timestamp, is bound by key). The roots and keylog sub-ranges go out split as usual (HOMEPROV_MAX_RECORD_BYTES per
# record, HOMEPROV_MAX_PARTS records per poll, the rest at the next polls, frozen). Later polls read the usual window.
# Unset (the default), nothing changes. A monitor that loses its state seals the full history again (identical roots are
# accepted by a first-write-wins anchor; a root that differs is a conflict and is carried as such).
_since = os.environ.get("HOMEPROV_SINCE", "").strip()
try:
    SINCE = float(_since) if _since else None
except ValueError:
    raise SystemExit("HOMEPROV_SINCE must be a unix time in seconds, got %r" % _since)
if SINCE is not None and not (SINCE >= 0 and math.isfinite(SINCE)):
    raise SystemExit("HOMEPROV_SINCE must be a finite time >= 0, got %r" % _since)
# HOMEPROV_SINCE=0 (E9 code review m5) means no lower bound at all: the keylog's first range starts at key 0, and the
# first poll reads from the hour of the smallest finite timestamp of any row when that is below 0 (the recorder's
# timestamp guard, TS_OK, admits negative times), so no row is left out of every commitment. With no such row the
# records are those of before.


def watermark(db: str) -> dict:
    """Largest row key per table in the copy: every row with a key at or below it is in the copy."""
    con, owned = _open(db)
    s = con.execute("SELECT max(state_id) FROM states").fetchone()[0]
    e = con.execute("SELECT max(event_id) FROM events").fetchone()[0]
    _close(con, owned)
    return {"states": s, "events": e}


def keylog_rows(db: str, table: str, lo: int, hi: int, limit: int | None = None):
    """(key, row hash, raw timestamp, holds raw text, fields) of every row with lo < key <= hi, in key order, read with
    LEFT JOINs; the fourth element is True when a TEXT value of the row was not valid UTF-8 (committed by its raw bytes);
    the fifth is the exact field tuple the row hash covers (what the escrow keeps)."""
    con, owned = _open(db)
    if SCHEME == "stable":
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % table) if r[1] not in STABLE_EXCLUDE[table]]
        joins = STABLE_JOINS[table]
    else:
        cols, joins = list(KEYLOG_COLS[table]), KEYLOG_JOINS[table]
    k = KEY_COL[table]
    sql = ("SELECT t.%s, t.%s, " % (_q(k), _q(TS_COL[table]))
           + ", ".join(["t.%s" % _q(c) for c in cols] + ["j%d.%s" % (i, _q(jc)) for i, (_jt, jc, _fk) in enumerate(joins)])
           + " FROM %s t" % table
           + "".join(" LEFT JOIN %s j%d ON j%d.%s = t.%s" % (jt_, i, i, _q(fk), _q(fk))
                     for i, (jt_, _jc, fk) in enumerate(joins))
           + " WHERE t.%s > ? AND t.%s <= ? ORDER BY t.%s" % (_q(k), _q(k), _q(k))
           + (" LIMIT %d" % int(limit) if limit else ""))
    out = []
    for r in con.execute(sql, (lo, hi)):
        vals, jvals = r[2:2 + len(cols)], r[2 + len(cols):]
        fields = ((table,) + tuple(x for c, v in zip(cols, vals) for x in (c, v))
                  + tuple(x for (jt_, jc, _fk), v in zip(joins, jvals) for x in ("%s.%s" % (jt_, jc), v)))
        out.append((r[0], H(encode_node_v2("keylog", fields)), r[1], any(has_raw_bytes(v) for v in fields), fields))
    _close(con, owned)
    return out


def keylog_entry(rows, lo: int, hi: int) -> dict:
    """The committed form of one key range: bounds, row count, fold, and per row (key offset, 32-bit hash prefix, the
    second the row was in when first observed, null if its timestamp was malformed). The second lets the verifier flag
    where a row was even when it is later deleted, re-timed or made malformed before that second is sealed (re-review
    R3); the prefix only ranks the suspects of a failed range (R1)."""
    acc = ZERO
    for r in rows:
        acc = H(acc + r[1])
    e = {"from": lo, "to": hi, "n": len(rows), "acc": acc.hex(),
         "rows": [[r[0] - lo, r[1].hex() if ROWBIND else r[1].hex()[:8], int(r[2] // 1.0) if ts_ok(r[2]) else None]
                  for r in rows]}
    if ROWBIND:
        e["bind"] = ROWBIND_TAG
    return e


def keylog_chunks(rows, lo: int, hi: int) -> list:
    """(lo, hi] as consecutive sub-ranges of at most KEYLOG_CHUNK rows; together they cover every key of the range."""
    if not rows:
        return [keylog_entry([], lo, hi)]
    out, start = [], lo
    for i in range(0, len(rows), KEYLOG_CHUNK):
        part = rows[i:i + KEYLOG_CHUNK]
        end = hi if i + KEYLOG_CHUNK >= len(rows) else part[-1][0]
        out.append(keylog_entry(part, start, end))
        start = end
    return out


def head_pieces(head: dict) -> list:
    """A backlog head as stored: whole, or (when its keylog makes it large) one piece per keylog sub-range. Every piece
    repeats the head's fields; "head_piece" marks a piece of a failed poll's head, "keylog_part" (set below) a sub-range
    left over from a poll whose own record did go out."""
    if "keylog" not in head or len(json.dumps(head, sort_keys=True)) <= HEAD_PIECE_BYTES:
        return [head]
    base = {k: v for k, v in head.items() if k != "keylog"}
    return [dict(base, keylog={t: [e]}, head_piece=True) for t, es in sorted(head["keylog"].items()) for e in es]


def _hw_below(con, t, bound):
    """The largest key of a row of table t timestamped before bound (finite timestamps only), or 0."""
    c = TS_COL[t]
    return int(con.execute("SELECT max(%s) FROM %s WHERE %s AND %s < ?" % (
        KEY_COL[t], t, TS_OK.format(c=c), c), (bound,)).fetchone()[0] or 0)


def keylog_poll(db: str, hw, wm: dict, through: int, start_before=None, rewind=None, rewind_before=None):
    """This poll's keylog, the new high-water, the keys of first-observed rows with a malformed timestamp or text, and
    the first-observed rows themselves (for the escrow).

    The first poll of a monitor (no high-water yet) starts each range just above the largest key of a row whose
    timestamp is already sealed (< through): every row not yet sealed, including one parked in the future or with a
    malformed timestamp, is bound from this first observation on. Rows below that key are sealed by this poll's own
    segment roots (within the re-read window) or predate the window. With a full-history first poll (HOMEPROV_SINCE),
    start_before is the start of that poll's window instead, so every row from there on is bound by key as well.
    rewind: a dict this call fills with the tables whose keylog it restarted (KEYLOG REWIND, HOMEPROV_KEYLOG_REWIND=1;
    the new high-water is the largest key of a row timestamped before rewind_before, else before through); without it
    nothing is rewound."""
    first = hw is None
    if first:
        bound = through if start_before is None else start_before
        con, owned = _open(db)
        hw = {t: _hw_below(con, t, bound) for t in KEY_COL}
        _close(con, owned)
    kl, new, bad, seen = {}, dict(hw), {}, {}
    for t in KEY_COL:
        lo, hi = int(hw.get(t, 0)), int(wm.get(t) or 0)
        if hi < lo and rewind is not None and KEYLOG_REWIND and not first:
            con, owned = _open(db)
            to = min(hi, _hw_below(con, t, through if rewind_before is None else rewind_before))
            _close(con, owned)
            rewind[t] = {"from": lo, "to": to, "wm": hi}
            lo = new[t] = to
        if hi <= lo:
            kl[t] = [{"from": lo, "to": lo, "n": 0}]
        else:
            rows = keylog_rows(db, t, lo, hi)
            seen[t] = rows
            kl[t] = keylog_chunks(rows, lo, hi)
            new[t] = hi
            b = [r[0] for r in rows if not ts_ok(r[2])]
            if b:
                bad.setdefault("malformed", {})[t] = b
            b = [r[0] for r in rows if r[3]]
            if b:
                bad.setdefault("invalid_text", {})[t] = b
        if first:
            kl[t][0]["start"] = True
    return kl, new, bad, seen


# STREAMED FULL-HISTORY SEAL (2026-10-10, after the E9 smoke runs). Reading the whole history at once held every row
# twice (the segment nodes and the keylog rows) and the escrow lines in memory: on the lab installation's recorder
# (199 MB, 1.2 M rows) the first poll peaked at 4.24 GB and was killed in Docker's VM. The full-history first poll now
# goes through the history one span of STREAM_SPAN_S at a time (an hour: every second, minute and hour segment lies
# inside one span, so each span's roots are the roots a single pass computes) and through the keylog in batches of
# STREAM_KEYLOG_BATCH rows (the 128-row sub-ranges are cut exactly where keylog_chunks() cuts them: a sub-range ends at
# its last key unless it is the range's last, which ends at the watermark), and writes the escrow as it goes, segment
# lines first, then keylog lines, as before. Records, state and escrow are byte-identical to the single pass's
# (monitor/test_e9.py, and the E8 recorder in E9_IMPL_NOTES.md); what stays in memory is one span's rows, one batch,
# the frozen roots and the keylog entries (which the records and, after a failed append, the backlog need).
STREAM_SPAN_S = 3600.0
STREAM_KEYLOG_BATCH = 64 * KEYLOG_CHUNK


class _EscrowStream:
    """Escrow writes of one poll: counts, and the first error, after which this poll writes no more lines."""

    def __init__(self):
        self.segments = self.keylog = 0
        self.error = None

    def write(self, lines, kind):
        if not ESCROW_DIR or not lines or self.error is not None:
            return
        try:
            n = _escrow_append(lines)
        except OSError as exc:
            self.error = repr(exc)[:120]
            return
        if kind == "segments":
            self.segments += n
        else:
            self.keylog += n


def _next_row_ts_any(db):
    """The smallest finite timestamp of any row in states or events, or None."""
    con, owned = _open(db)
    try:
        return _next_row_ts(con, -1e12)
    finally:
        _close(con, owned)


def _next_row_ts(con, t):
    """The smallest finite timestamp at or after t in states or events, or None."""
    vals = []
    for table, col in (("states", "last_updated_ts"), ("events", "time_fired_ts")):
        v = con.execute("SELECT min(%s) FROM %s WHERE %s AND %s >= ?" % (col, table, TS_OK.format(c=col), col),
                        (t,)).fetchone()[0]
        if v is not None:
            vals.append(v)
    return min(vals) if vals else None


def seal_stream(db, since, now, seal, known, esc):
    """The segment part of a full-history first poll, span by span: (new frozen roots {g: {seg: entry}}, fresh counts
    {g: n}, rows read, load seconds, commit seconds). Escrow lines of the fresh seconds go out per span."""
    con, owned = _open(db)
    new_pending, fresh_n, n_nodes, t_load, t_commit = {}, {}, 0, 0.0, 0.0
    try:
        t = _next_row_ts(con, since)
        while t is not None:
            h = int(t // STREAM_SPAN_S) * STREAM_SPAN_S
            t0 = time.time()
            nodes = load(con if not owned else db, since=max(h, since), until=h + STREAM_SPAN_S)
            t_load += time.time() - t0
            t0 = time.time()
            closed = sealed(commit(nodes), now)
            t_commit += time.time() - t0
            n_nodes += len(nodes)
            for g, segs in closed.items():
                new = {k: v for k, v in segs.items() if k not in known.get(g, ())}
                if not new:
                    continue
                np = new_pending.setdefault(g, {})
                for k, v in new.items():
                    np[k] = {"acc": v["acc"], "n": v["n"], **seal}
                fresh_n[g] = fresh_n.get(g, 0) + len(new)
                if g == "second" and ESCROW_DIR and esc.error is None:
                    try:
                        esc.segments += escrow_write(nodes, new, seal)
                    except OSError as exc:
                        esc.error = repr(exc)[:120]
            del nodes, closed
            t = _next_row_ts(con, h + STREAM_SPAN_S)
    finally:
        _close(con, owned)
    return new_pending, fresh_n, n_nodes, t_load, t_commit


def keylog_stream(db, wm: dict, start_before, seq: int, now: float, esc):
    """keylog_poll() for a full-history first poll without holding every first-observed row: the same entries,
    high-water and flagged keys; the keylog escrow lines go out per batch, tables in escrow order."""
    con, owned = _open(db)
    hw = {t: (0 if start_before is None else _hw_below(con, t, start_before)) for t in KEY_COL}   # None: every key
    _close(con, owned)
    kl, new, bad = {}, dict(hw), {}
    for t in sorted(KEY_COL):                         # events, states: the order escrow_keylog() writes
        lo, hi = int(hw.get(t, 0)), int(wm.get(t) or 0)
        if hi <= lo:
            kl[t] = [{"from": lo, "to": lo, "n": 0}]
        else:
            entries, mal, inv = [], [], []
            start, cursor, pend = lo, lo, []
            while True:
                batch = keylog_rows(db, t, cursor, hi, limit=STREAM_KEYLOG_BATCH)
                done = len(batch) < STREAM_KEYLOG_BATCH
                if batch:
                    cursor = batch[-1][0]
                mal += [r[0] for r in batch if not ts_ok(r[2])]
                inv += [r[0] for r in batch if r[3]]
                pend.extend(batch)
                lines = []
                while len(pend) > KEYLOG_CHUNK or (done and pend):
                    part, pend = pend[:KEYLOG_CHUNK], pend[KEYLOG_CHUNK:]
                    end = hi if (done and not pend) else part[-1][0]
                    e = keylog_entry(part, start, end)
                    entries.append(e)
                    start = end
                    if ESCROW_DIR:
                        lines.append(json.dumps({"v": 1, "kind": "keylog", "scheme": SCHEME, "seq_local": seq,
                                                 "poll_ts": now, "table": t, "from": e["from"], "to": e["to"],
                                                 "n": e["n"], "acc": e["acc"],
                                                 "rows": [[r[0], jt(r[4])] for r in part]}, sort_keys=True))
                esc.write(lines, "keylog")
                del batch
                if done:
                    break
            kl[t] = entries or [keylog_entry([], lo, hi)]
            new[t] = hi
            if mal:
                bad.setdefault("malformed", {})[t] = mal
            if inv:
                bad.setdefault("invalid_text", {})[t] = inv
        kl[t][0]["start"] = True
    return {t: kl[t] for t in KEY_COL}, new, bad


def _wal_salt():
    """Salt words of the hub's WAL header: they change whenever the WAL is restarted after a checkpoint."""
    try:
        with open(SRC + "-wal", "rb") as fh:
            h = fh.read(24)
        return h[16:24] if len(h) == 24 else None
    except OSError:
        return None


def jt(v):
    """Typed JSON form of a recorder value or node tuple (escrow): no value changes type or loses bits."""
    if v is None:
        return ["N"]
    if isinstance(v, (bytes, bytearray, memoryview)):
        return ["B", bytes(v).hex()]
    if isinstance(v, str):
        return ["T", v]
    if isinstance(v, bool):
        raise TypeError("bool is not a recorder value")
    if isinstance(v, int):
        return ["I", v]
    if isinstance(v, float):
        return ["F", v.hex()]
    if isinstance(v, (tuple, list)):
        return ["L", [jt(x) for x in v]]
    raise TypeError("unsupported value type %r" % type(v).__name__)


def from_jt(j):
    tag = j[0]
    if tag == "N":
        return None
    if tag == "B":
        return bytes.fromhex(j[1])
    if tag == "T":
        return j[1]
    if tag == "I":
        return int(j[1])
    if tag == "F":
        return float.fromhex(j[1])
    if tag == "L":
        return tuple(from_jt(x) for x in j[1])
    raise ValueError("bad escrow tag %r" % tag)


def _escrow_append(lines) -> int:
    os.makedirs(ESCROW_DIR, exist_ok=True)
    with open(os.path.join(ESCROW_DIR, "escrow.jsonl"), "a") as fh:
        fh.write("".join(line + "\n" for line in lines))
        fh.flush()
        os.fsync(fh.fileno())
    return len(lines)


def escrow_keylog(kl: dict, seen: dict, seq: int, now: float) -> int:
    lines = escrow_keylog_lines(kl, seen, seq, now)
    return _escrow_append(lines) if lines else 0


def escrow_keylog_lines(kl: dict, seen: dict, seq: int, now: float) -> list:
    """One line per committed keylog sub-range: the exact field tuple of every row at its FIRST observation, in key
    order, with the sub-range's bounds, count and fold. A row that reached the recorder after its second was sealed is
    in no sealed segment, so without these lines the escrow had no copy of it (E7 main run: recovery missed one late
    unlock out of 120). Recomputing the fold from the tuples must reproduce the anchored keylog commitment."""
    lines = []
    for t, es in sorted(kl.items()):
        rows = seen.get(t) or []
        keys = [r[0] for r in rows]                   # in key order: each sub-range is a slice (a full-history first
        for e in es:                                  # poll has a million rows and thousands of sub-ranges)
            if not e.get("n"):
                continue
            part = rows[bisect.bisect_right(keys, e["from"]):bisect.bisect_right(keys, e["to"])]
            lines.append(json.dumps({"v": 1, "kind": "keylog", "scheme": SCHEME, "seq_local": seq, "poll_ts": now,
                                     "table": t, "from": e["from"], "to": e["to"], "n": e["n"], "acc": e["acc"],
                                     "rows": [[r[0], jt(r[4])] for r in part]}, sort_keys=True))
    return lines


def escrow_write(nodes, segs: dict, seal: dict) -> int:
    """Append one line per newly sealed second: its node tuples in fold order, its root, and the sealing poll."""
    by = {}
    for n in nodes:
        k = str(int(n[0] // 1.0))
        if k in segs:
            by.setdefault(k, []).append(n)
    lines = [json.dumps({"v": 1, "scheme": SCHEME, "encoding": ENCODING, "gran": "second", "seg": k,
                         "acc": segs[k]["acc"], "n": segs[k]["n"], "sealed_at": seal["sealed_at"],
                         "seal_seq": seal["seal_seq"], "wm": seal["wm"],
                         "nodes": [jt(n) for n in by.get(k, [])]}, sort_keys=True)
             for k in sorted(segs, key=int)]
    return _escrow_append(lines)


def _alarm(what: str, **kw):
    print(json.dumps({"alarm": what, **kw}, sort_keys=True, default=str), flush=True)


def tick_coverage(st) -> dict:
    """One observation cycle with coverage fields, the keylog, a heartbeat record, frozen roots and optional escrow."""
    pending = st.setdefault("pending", {})            # {gran: {segment: frozen entry}}
    backlog = st.setdefault("backlog", [])            # heads of polls whose own record was not appended
    anchored = st.setdefault("anchored", {g: [] for g, _ in GRAN})
    if st.get("inflight"):
        # The monitor stopped while appending that poll's record, so its outcome is unknown: the head (with its keylog)
        # is re-sent. A duplicate on the chain is harmless; a lost keylog range would not be.
        backlog.extend(head_pieces(st.pop("inflight")))
    seq = int(st.get("seq_local", 0)) + 1
    st["seq_local"] = seq
    if st.get("reply_tags_seen"):
        _REPLY["seen"] = True                         # this anchor tags its replies: an untagged one is not its answer
    # DIRECT READ RETRY (E9 code review re-check N2). A read that began on a fully checkpointed WAL holds read mark 0 and
    # reads only the database file; the hub's next commit then legitimately restarts the WAL (new salts), which the
    # race check above cannot tell from a torn read. As copy mode repeats a raced copy, a direct poll whose read raced
    # is repeated, up to DIRECT_READ_ATTEMPTS reads in all; escrow lines a raced full-history pass wrote are dropped
    # (the file is cut back to its size before the read), and the attempts are in the poll's summary and cost log
    # ("read_attempts", only when more than one) and, when every read raced, in the record's detail.
    esc_size0 = _escrow_size()
    for read_attempt in range(1, DIRECT_READ_ATTEMPTS + 1):
        t_start = time.time()
        t_obs = observed_at() if CLOCK_FILE else None
        quick = quick_check_due(seq)
        # DIRECT READ (HOMEPROV_READ=direct, see above): one read transaction on the live recorder instead of a copy, unless
        # the hub's -wal or -shm is absent (then this poll copies).
        direct = READ == "direct" and os.path.exists(SRC + "-wal") and os.path.exists(SRC + "-shm")
        con = None
        raced = False
        if direct:
            con, copy_at, (vok, vreason, vdetail) = direct_snapshot(quick)
            db = con
        else:
            # COPY RACE (review m2). The copy is the db file, then the -wal. If the hub checkpoints and restarts its WAL in
            # between, the copy can lack rows committed before it while holding newer keys, and step 1 of the verifier would
            # call that an attributable insertion. A restart changes the WAL header salts, so the copy is repeated while they
            # move, and the poll fails closed ("copy_raced") if they never settle.
            for _attempt in range(3):
                copy_start = time.time()
                salt = _wal_salt()
                db = snapshot()
                raced = _wal_salt() != salt
                if not raced:
                    break
            copy_at = copy_start
        t_copy = time.time() - t_start
        now = time.time()
        out = {"seq_local": seq, "copy_ms": round(t_copy * 1000, 3)}
        if READ == "direct":
            out["read"] = "direct" if direct else "copy_fallback"

        if direct:
            pass                                          # direct_snapshot() validated the snapshot it holds
        elif CLOCK_FILE and t_obs is None:
            vok, vreason, vdetail = False, "clock_unreadable", {}
        elif raced:
            vok, vreason, vdetail = False, "copy_raced", {"attempts": 3}
        else:
            if CLOCK_FILE:
                now = copy_at = t_obs
            vok, vreason, vdetail = validate_copy(db, quick)
        rec = {"observer": "external-monitor", "ts": now, "scheme": SCHEME, "encoding": ENCODING,
               "coverage": COVERAGE_VERSION, "seq_local": seq, "copy_at": copy_at}
        head = {"seq_local": seq, "ts": now, "copy_at": copy_at}
        if CLOCK_FILE:
            rec["monitor_ts"] = time.time()

        if vok:
            # Anything the hub can put in the recorder must not stop polling (review M2): a failure here makes this poll
            # unobservable, on the chain, and the next poll tries again.
            try:
                wm = watermark(db)
                kl = new_hw = bad = seen = None
                through = int((now - GRACE_S) // 1.0)
                widest = max(w for _, w in GRAN)
                since = (int(now // widest) * widest) - widest
                # FULL-HISTORY INITIAL SEAL (HOMEPROV_SINCE, see above): the first observable poll reads from the hour at
                # or before SINCE, and its keylog starts there too
                full = SINCE is not None and not st.get("since_applied")
                if full:
                    since = min(since, int(SINCE // widest) * widest)
                    if SINCE == 0:
                        lowest = _next_row_ts_any(db)
                        if lowest is not None and lowest < since:
                            since = int(lowest // widest) * widest
                rewound = {}
                if full:
                    # STREAMED FULL-HISTORY SEAL (see above): segments span by span, then the keylog in batches, the escrow
                    # written as they go; the frozen roots join `pending` below only if the whole pass succeeds
                    esc = _EscrowStream()
                    seal = {"sealed_at": now, "seal_seq": seq, "wm": wm}
                    known = {g: set(anchored.get(g, [])) | set(pending.get(g, {})) for g, _w in GRAN}
                    new_pending, fresh_n, n_nodes, t_load, t_commit = seal_stream(db, since, now, seal, known, esc)
                    if KEYLOG and st.get("keylog_hw") is None:
                        kl, new_hw, bad = keylog_stream(db, wm, None if SINCE == 0 else since, seq, now, esc)
                    elif KEYLOG:
                        kl, new_hw, bad, seen = keylog_poll(db, st.get("keylog_hw"), wm, through, rewind=rewound,
                                                            rewind_before=st.get("keylog_copy_at"))
                        esc.write(escrow_keylog_lines(kl, seen or {}, seq, now), "keylog")
                else:
                    if KEYLOG:
                        kl, new_hw, bad, seen = keylog_poll(db, st.get("keylog_hw"), wm, through, rewind=rewound,
                                                            rewind_before=st.get("keylog_copy_at"))
                    t0 = time.time()
                    nodes = load(db, since=since)
                    t_load = time.time() - t0
                    phi = commit(nodes)
                    t_commit = time.time() - t0 - t_load
                    closed = sealed(phi, now)
            except Exception as exc:                      # noqa: BLE001
                vok, vreason, vdetail = False, "load_failed", {"exc": repr(exc)[:160]}
        if con is not None:
            # end the read transaction before escrow and the append; the race check and the file check after the read
            # (direct_finish) can still fail the poll closed, and its rows are then not used
            fin = direct_finish(con) if vok else direct_close(con)
            con = None
            if fin:
                vok, vreason, vdetail = fin
        if direct and not vok and vreason == "read_raced":
            _escrow_truncate(esc_size0)
            if read_attempt < DIRECT_READ_ATTEMPTS:
                continue
        break
    if direct and read_attempt > 1:
        out["read_attempts"] = read_attempt
        if not vok and vreason == "read_raced":
            vdetail = dict(vdetail or {}, attempts=read_attempt)

    if not vok:
        # FAIL CLOSED, as before: an unobservable poll seals nothing and says so on the chain. Frozen roots are still
        # re-sent, in continuation records of this poll (review M4), so keeping copies unobservable cannot hold them.
        rec.update(evidence_unobservable=True, reason=vreason, detail=vdetail)
        head["unobservable"] = vreason
        out.update(evidence_unobservable=True, reason=vreason, detail=vdetail, fail_closed=True)
    else:
        seal = {"sealed_at": now, "seal_seq": seq, "wm": wm}
        if full:
            for g, d in new_pending.items():
                pending.setdefault(g, {}).update(d)
            fresh = {g: range(n) for g, n in fresh_n.items()}       # only the counts are read below
            del new_pending
            if esc.segments:
                out["escrowed"] = esc.segments
            if ESCROW_DIR and kl and esc.error is None:
                out["escrowed_keylog"] = esc.keylog
            if esc.error is not None:
                out["escrow_error"] = esc.error
                _alarm("escrow_write_failed", seq_local=seq, err=esc.error)
        else:
            fresh = {}
            for g, segs in closed.items():
                known = set(anchored.get(g, [])) | set(pending.get(g, {}))
                new = {k: v for k, v in segs.items() if k not in known}
                if new:
                    fresh[g] = new
                    for k, v in new.items():
                        pending.setdefault(g, {})[k] = {"acc": v["acc"], "n": v["n"], **seal}
            if ESCROW_DIR and (fresh.get("second") or kl):
                try:
                    if fresh.get("second"):
                        out["escrowed"] = escrow_write(nodes, fresh["second"], seal)
                    if kl:
                        out["escrowed_keylog"] = escrow_keylog(kl, seen or {}, seq, now)
                except OSError as exc:
                    out["escrow_error"] = repr(exc)[:120]
                    _alarm("escrow_write_failed", seq_local=seq, err=repr(exc)[:120])
            n_nodes = len(nodes)
        # n_sealed (review M3): how many segments this poll froze, so a verifier holding fewer of its roots knows a
        # root is missing instead of reading the segment as empty.
        cov = {"since": since, "through": through, "wm": wm,
               "n_sealed": {g: len(fresh.get(g, {})) for g, _w in GRAN}}
        if rewound:
            cov["keylog_rewind"] = rewound            # KEYLOG REWIND (above)
            _alarm("keylog_rewind", seq_local=seq, tables=rewound)
        rec.update(cov)
        head.update(cov)
        if full:
            st["since_applied"] = True
        if kl is not None:
            # the head keeps the whole keylog (it is what the backlog re-sends if this poll's append fails); the
            # record carries it as items, so a large keylog is split across this poll's records like the roots
            head["keylog"] = kl
            st["keylog_hw"] = new_hw
            if KEYLOG_REWIND:
                st["keylog_copy_at"] = copy_at            # KEYLOG REWIND: the bound of the next rewind
        for what, by_t in (bad or {}).items():
            # "malformed": first-observed rows whose timestamp is not a finite number; "invalid_text": rows holding a
            # TEXT value that is not valid UTF-8 (committed by its raw bytes, see TEXT DECODING)
            rec[what] = {t: {"n": len(v), "keys": v[:MALFORMED_CAP]} for t, v in by_t.items()}
            _alarm(what, seq_local=seq, rows=rec[what])
        out.update(n_nodes=n_nodes, load_ms=round(t_load * 1000, 3), commit_ms=round(t_commit * 1000, 3),
                   sealed_new={g: len(v) for g, v in fresh.items()})
        if NAMEMAP_DIR:
            rec["namemap"] = namemap_seal(NAMEMAP_DIR)
        if SCHEME == "stable":
            rec["stable_exclude"] = sorted("%s.%s" % (t, c) for t, cs in STABLE_EXCLUDE.items() for c in cs)
        # Segments older than the re-read window cannot be sealed again (no row before `since` is read), so the
        # anchored list need not remember them; without this it grows by every sealed segment forever.
        for g, w in GRAN:
            anchored[g] = [k for k in anchored.get(g, []) if int(k) * w >= since]

    # Every poll sends one record (the heartbeat). Every poll also re-sends every frozen root; heads of polls whose
    # record failed ride along. Items are split into records below the size limit (RECORD SIZE, above).
    order = {g: i for i, (g, _w) in enumerate(GRAN)}
    items = [("h", h) for h in backlog]
    items += [("c", t, e) for t, es in sorted((head.get("keylog") or {}).items()) for e in es]
    for e_seq, _o, _k, g, k in sorted((e["seal_seq"], order.get(g, 9), int(k), g, k)
                                     for g, d in pending.items() for k, e in d.items()):
        e = pending[g][k]
        entry = {"acc": e["acc"], "n": e["n"]}
        if e_seq != seq:
            entry.update(sealed_at=e["sealed_at"], seal_seq=e_seq, wm=e["wm"])
        items.append(("s", g, k, entry))
    # a continuation of an unobservable poll carries frozen roots only: it is not itself unobservable evidence
    cont_base = rec if vok else {k: v for k, v in rec.items() if k not in ("evidence_unobservable", "reason", "detail")}
    conflicted = list(st.get("conflicted") or [])
    budget = max(MIN_RECORD_BYTES, int(st.get("max_bytes", MAX_RECORD_BYTES)))

    def fill(pos, part, with_conflicted):
        """The record of the given part holding items[pos:...] below the budget (at least one item, if any is left)."""
        seals = vok or part > 1
        r_ = dict(rec if part == 1 else cont_base)
        if seals:
            r_["sealed"] = {}
        if part > 1:
            r_["part"] = part
        if with_conflicted:
            r_["conflicted"] = conflicted
        size = len(json.dumps(r_, sort_keys=True)) + 64
        taken = []
        for it in items[pos:]:
            if it[0] == "s" and not seals:
                break                                 # an unobservable record seals nothing
            c = len(json.dumps(it[-1], sort_keys=True)) + (len(it[2]) + 8 if it[0] == "s" else 16)
            if taken and size + c > budget:
                break
            size += c
            taken.append(it)
        heads = [it[1] for it in taken if it[0] == "h"]
        if heads:
            r_["backlog"] = heads
        for it in taken:
            if it[0] == "s":
                r_["sealed"].setdefault(it[1], {})[it[2]] = it[3]
            elif it[0] == "c":
                r_.setdefault("keylog", {}).setdefault(it[1], []).append(it[2])
        return r_, taken

    st["inflight"] = head                             # until an append of this poll succeeds (see the top)
    save_state(st)                                    # frozen roots survive a monitor restart before the append
    t0 = time.time()
    pos, part, r, refusals = 0, 0, {}, 0
    while part < MAX_PARTS and refusals < 64:
        rec_i, taken = fill(pos, part + 1, bool(conflicted) and part == 0)
        r = append(sign_record(rec_i))
        if r.get("ok"):
            part += 1
            st.pop("inflight", None)
            pos += len(taken)
            n_heads = sum(1 for it in taken if it[0] == "h")
            del backlog[:n_heads]
            for it in taken:
                if it[0] == "s":
                    pending[it[1]].pop(it[2], None)
                    anchored.setdefault(it[1], []).append(it[2])
            if "conflicted" in rec_i:
                st.pop("conflicted", None)
            if pos >= len(items):
                break
            continue
        refusals += 1
        out.setdefault("refused", []).append(r.get("http") or r.get("err"))
        # Too large for this anchor: split smaller and send the same items again now, at half the refused body's size.
        # The hardened anchor refuses an oversized body unread and closes, so a large body can see a reset or a broken
        # pipe instead of the 413 (review m1): a reset on a body above 4 KiB is taken as a 413 for this poll (it is not
        # remembered, since a reset can also be the anchor restarting); a 413 is remembered in the state.
        err = str(r.get("err") or "")
        reset = any(x in err for x in ("BrokenPipe", "Broken pipe", "ConnectionReset", "Connection reset",
                                       "ConnectionAborted"))
        size = len(json.dumps(rec_i, sort_keys=True))
        if (r.get("http") == 413 or (reset and size > 4 * MIN_RECORD_BYTES)) and budget > MIN_RECORD_BYTES:
            budget = max(MIN_RECORD_BYTES, min(budget, size) // 2)
            if r.get("http") == 413:
                st["max_bytes"] = max(budget, REMEMBERED_RECORD_BYTES_FLOOR)
            continue
        conflict = ((r.get("body") or {}).get("conflict") or {}) if r.get("http") == 409 else {}
        g, k = conflict.get("granularity"), str(conflict.get("segment"))
        if g in pending and k in pending[g]:
            # The anchor already holds a different root for this segment (an earlier writer, or a monitor bug).
            # Re-sending it would refuse every later append; it moves to "conflicted", which the next record carries
            # under a key the anchor's first-write-wins check does not read, so the disagreement is on the chain.
            e = pending[g].pop(k)
            entry = {"gran": g, "seg": k, **e, "anchored_acc": conflict.get("anchored_acc")}
            st.setdefault("conflicted", []).append(entry)
            conflicted.append(entry)
            anchored.setdefault(g, []).append(k)
            items = items[:pos] + [it for it in items[pos:] if not (it[0] == "s" and (it[1], it[2]) == (g, k))]
            continue
        break                                         # unreachable, timed out, or refused for another reason
    for g in [g for g, d in pending.items() if not d]:
        del pending[g]
    if _REPLY["seen"]:
        st["reply_tags_seen"] = True
    out["append_ms"] = round((time.time() - t0) * 1000, 3)
    out["anchor"] = r
    out["parts"] = part
    if part == 0:
        backlog.extend(head_pieces(st.pop("inflight")))
    else:
        # this poll's own keylog sub-ranges that did not get out go to the backlog as head pieces
        left = [it for it in items[pos:] if it[0] == "c"]
        if left:
            base = {k: v for k, v in head.items() if k != "keylog"}
            backlog.extend(dict(base, keylog={it[1]: [it[2]]}, keylog_part=True) for it in left)
    if not r.get("ok") or out.get("refused"):
        _alarm("append_failed" if not r.get("ok") else "append_refused_then_resent", seq_local=seq, anchor=r,
               refused=out.get("refused"), parts_appended=part,
               pending=sum(len(d) for d in pending.values()), backlog=len(backlog))
    save_state(st)
    out["pending"] = sum(len(d) for d in pending.values())
    out["backlog"] = len(backlog)
    if COST_LOG:
        try:
            with open(COST_LOG, "a") as fh:
                fh.write(json.dumps({"seq_local": seq, "ts": now, **{k: out.get(k) for k in (
                    "copy_ms", "load_ms", "commit_ms", "append_ms", "n_nodes")}, "ok": bool(r.get("ok")),
                    **({"read": out.get("read")} if READ == "direct" else {})}) + "\n")
        except OSError:
            pass
    return out


def tick(st) -> dict:
    """One observation cycle, incremental in history length.

    Only segments that are still OPEN can change, so only rows from the oldest
    open segment onward need folding. Sealed segments are already anchored and an
    append-only chain keeps them; a later change to one is the verifier's business
    to detect, not the monitor's to re-anchor.

    With HOMEPROV_COVERAGE=1 (the default) the cycle is tick_coverage(); the body
    below is the earlier cycle, unchanged, and runs with HOMEPROV_COVERAGE=0.
    """
    if COVERAGE:
        return tick_coverage(st)
    t_start = time.time()
    t_obs = observed_at() if CLOCK_FILE else None
    db = snapshot()
    t_copy = time.time() - t_start
    now = time.time()
    if CLOCK_FILE:
        if t_obs is None:
            return {"n_nodes": None, "copy_ms": round(t_copy * 1000, 3), "sealed_new": {},
                    "clock_unreadable": True}
        now = t_obs

    # FAIL CLOSED over hostile input (review 4d). If the copy is damaged or
    # truncated, do not seal a partial view: anchor an explicit record that the
    # evidence was unobservable, so the gap appears on the chain.
    vok, vreason, vdetail = validate_copy(db)
    if not vok:
        rec = {"observer": "external-monitor", "ts": now, "scheme": SCHEME,
               "encoding": ENCODING,
               "evidence_unobservable": True, "reason": vreason, "detail": vdetail}
        r = append(sign_record(rec))
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
        rec = {"observer": "external-monitor", "ts": now, "scheme": SCHEME,
               "encoding": ENCODING, "sealed": fresh}
        if CLOCK_FILE:
            rec["monitor_ts"] = time.time()
        if NAMEMAP_DIR:
            rec["namemap"] = namemap_seal(NAMEMAP_DIR)
        r = append(sign_record(rec))
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
        print(json.dumps({"n_nodes": len(nodes), "encoding": ENCODING,
                          "phi": commit(nodes)}, sort_keys=True))
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
