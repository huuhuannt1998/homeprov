"""E9 tests (round 13, drafts/round13/E9_DESIGN.md part A): A1 the purge-disconnect rule, A2 per-row keylog binding,
A3 the name-map check with operator RENAME markers, A4 direct read, A5 the full-history initial seal.

    python3 -m pytest -q monitor/test_e9.py

The rig of test_coverage.py (a synthetic recorder with Home Assistant's schema, the shipped monitor at a fixed clock,
an in-memory anchor with the daemon's record format) is reused; exp/stages/e7_verify.py verifies. Operator markers are
made with exp/rig/marker_issuer.py itself (HMAC tag under the operator key, Ed25519 operator signature). A6 (the issuer
against a linked anchor) is in testbed/anchord/test_anchor_e9.py, A7 in monitor/test_e9_dishonest.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "exp"))

from test_coverage import (GAP, LATE, T0, USER, V, Anchor, Recorder, Rig, _keypair, ctx, history,  # noqa: E402
                           needs_crypto, rec, seg_v, tmp, verify)
from rig import marker_issuer as MI  # noqa: E402

assert rec and tmp                                   # fixtures, imported for pytest
OP = bytes.fromhex(hashlib.sha256(b"operator-e9").hexdigest())
KEEP = 3600.0                                        # the retention policy of these tests (purge_keep_s)
SCHED = T0 + 6000.0                                  # the scheduled purge
CUT = SCHED - KEEP                                   # its cutoff: T0 + 2400


def operator(tmp, name="operator"):
    priv, pub, _k = _keypair(tmp, name)
    return MI.load_signer(priv), pub


def put_marker(anchor, payload, key=OP, signer=None):
    """The operator's marker record on the chain, exactly as rig.marker_issuer.post() sends it."""
    anchor.write(MI.marker_record(key, payload, signer))


def ha_purge(rec, cutoff):
    """Home Assistant 2026.7.4's purge of everything older than cutoff (recorder/purge.py): _purge_state_ids first
    disconnects (queries.py disconnect_states_rows: old_state_id = NULL where it names a purged row), then deletes the
    states; events; then attributes, event data and entity metadata no remaining row uses."""
    ids = [r[0] for r in rec.con.execute("SELECT state_id FROM states WHERE last_updated_ts < ?", (cutoff,))]
    q = ",".join("?" * len(ids))
    rec.sql("UPDATE states SET old_state_id = NULL WHERE old_state_id IN (%s)" % q, ids)
    rec.sql("DELETE FROM states WHERE state_id IN (%s)" % q, ids)
    rec.sql("DELETE FROM events WHERE time_fired_ts < ?", (cutoff,))
    rec.sql("DELETE FROM state_attributes WHERE attributes_id NOT IN (SELECT attributes_id FROM states"
            " WHERE attributes_id IS NOT NULL)")
    rec.sql("DELETE FROM event_data WHERE data_id NOT IN (SELECT data_id FROM events WHERE data_id IS NOT NULL)")
    rec.sql("DELETE FROM states_meta WHERE metadata_id NOT IN (SELECT metadata_id FROM states)")
    return ids


def purge_history(rec):
    """Rows older and younger than CUT. sensor.a and sensor.b have retained rows whose predecessor is older than CUT
    (the purge disconnects them); sensor.c's retained rows follow each other (never disconnected)."""
    k = {}
    k["a1"] = rec.state("sensor.a", "1", T0 + 0.5, ctx=ctx(1))
    k["b1"] = rec.state("sensor.b", "1", T0 + 1.2, ctx=ctx(2))
    rec.event("call_service", T0 + 1.5, ctx=ctx(3), usr=USER, data='{"domain":"light"}')
    k["b2"] = rec.state("sensor.b", "2", T0 + 2.2, ctx=ctx(4))
    k["b3"] = rec.state("sensor.b", "3", T0 + 4990.4, ctx=ctx(5))
    k["c1"] = rec.state("sensor.c", "1", T0 + 4995.1, ctx=ctx(6))
    k["a2"] = rec.state("sensor.a", "2", T0 + 5000.3, ctx=ctx(7), usr=USER)
    k["c2"] = rec.state("sensor.c", "2", T0 + 5001.6, ctx=ctx(8))
    rec.event("call_service", T0 + 5002.0, ctx=ctx(9), data='{"domain":"lock"}')
    return k


SOURCES = {"escrow": {"HOMEPROV_ROWBIND": "0"}, "rowbind": {"HOMEPROV_ROWBIND": "1"}}


def sealed_rig(tmp, rec, source, scheme="stable", name="m"):
    """A monitor that sealed every row (HOMEPROV_SINCE=0) with the committed values held by the escrow or by the
    per-row binding (the escrow then off)."""
    env = dict(SOURCES[source], HOMEPROV_SCHEME=scheme, HOMEPROV_SINCE="0")
    if source == "escrow":
        env["HOMEPROV_ESCROW_DIR"] = os.path.join(tmp, "escrow_" + name)
    r = Rig(tmp, rec, name=name, **env)
    r.polls(T0 + 5010.0, T0 + 5020.0)
    return r


def verify_e9(tmp, r, pub=None, key=OP, keep=KEEP, **kw):
    esc = os.path.join(r.M.ESCROW_DIR, "escrow.jsonl") if r.M.ESCROW_DIR else None
    Mv = V.load_monitor(r.M.SCHEME, os.path.join(tmp, "vs_%d" % len(r.anchor.lines)))
    db = os.path.join(tmp, "verify_e9.db")
    shutil.copy2(r.rec.path, db)
    lines = open(esc).read().splitlines() if esc else None
    return V.verify(Mv, db, r.anchor.lines, LATE, GAP, scheme=r.M.SCHEME, escrow_lines=lines, operator_key=key,
                    operator_pubkey=pub, purge_keep_s=keep, **kw)


def purge_marker(issued=SCHED - 120.0):
    return MI.scoped_marker(SCHED, KEEP, issued_ts=issued)


# ================================================================================================ A1
@needs_crypto
@pytest.mark.parametrize("source,scheme", [("escrow", "stable"), ("rowbind", "stable"), ("escrow", "closure"),
                                           ("rowbind", "closure")])
def test_A1_a_purge_disconnect_is_excused_and_reported(tmp, rec, source, scheme):
    signer, pub = operator(tmp)
    k = purge_history(rec)
    r = sealed_rig(tmp, rec, source, scheme)
    put_marker(r.anchor, purge_marker(), signer=signer)
    purged = ha_purge(rec, CUT)
    assert set(purged) == {k["a1"], k["b1"], k["b2"]}
    assert rec.con.execute("SELECT old_state_id FROM states WHERE state_id IN (?, ?)", (k["a2"], k["b3"])).fetchall() \
        == [(None,), (None,)]
    r.polls(T0 + 6010.0, T0 + 6020.0)
    plain = verify(tmp, r)                                    # the earlier verifier: the disconnects are violations
    s_a2, s_b3 = str(int(T0) + 5000), str(int(T0) + 4990)
    assert {s_a2, s_b3} <= set(plain["flagged_seconds"])
    res = verify_e9(tmp, r, pub)
    assert res["flagged_seconds"] == [] and res["violations"] == [] and res["keylog_violations"] == []
    p = res["purge"]
    assert p["disconnects"]["n_rows"] == 2 and p["disconnects"]["seconds"] == sorted([s_b3, s_a2], key=int)
    got = {d["key"]: d for d in p["disconnected_rows"]}
    assert got["s:%d" % k["a2"]]["restored_old_state_id"] == k["a1"]
    assert got["s:%d" % k["b3"]]["restored_old_state_id"] == k["b2"]
    assert {d["source"] for d in got.values()} <= ({"escrow", "keylog_escrow"} if source == "escrow"
                                                   else {"row_binding"})
    assert p["excused"]["disconnect_segments"].get("second") == 2
    assert p["excused"]["segments_before_cutoff"].get("second") == 3      # T0, T0+1, T0+2: gone
    assert p["excused"]["straddling"].get("hour") == 1


def _purged_and(tmp, rec, source, change):
    signer, pub = operator(tmp)
    k = purge_history(rec)
    r = sealed_rig(tmp, rec, source)
    put_marker(r.anchor, purge_marker(), signer=signer)
    change(rec, k)
    r.polls(T0 + 6010.0, T0 + 6020.0)
    return r, k, verify_e9(tmp, r, pub)


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_A1_not_excused_when_another_field_also_changed(tmp, rec, source):
    def change(rec, k):
        ha_purge(rec, CUT)
        rec.sql("UPDATE states SET context_user_id_bin = NULL WHERE state_id = ?", (k["a2"],))  # the unlock's user
    r, k, res = _purged_and(tmp, rec, source, change)
    s = str(int(T0) + 5000)
    v = seg_v(res, T0 + 5000)
    assert v and v["not_excused_by_purge"] == ("restoring_the_disconnects_does_not_reproduce_the_anchored_root"
                                               if source == "escrow" else
                                               "committed_value_not_found_for_a_row_whose_old_state_id_is_null")
    assert s in res["flagged_seconds"]
    assert str(int(T0) + 4990) not in res["flagged_seconds"]                # the other disconnect alone is excused
    (kv,) = res["keylog_violations"]                                        # the range keeps only the edited row
    assert [x["key"] for x in kv["suspects"]] == ["s:%d" % k["a2"]] and kv["seconds"] == [s]


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_A1_not_excused_when_the_referenced_row_still_exists(tmp, rec, source):
    def change(rec, k):                                       # old_state_id cleared, the predecessor not purged
        rec.sql("UPDATE states SET old_state_id = NULL WHERE state_id = ?", (k["a2"],))
    r, k, res = _purged_and(tmp, rec, source, change)
    v = seg_v(res, T0 + 5000)
    assert v and v["not_excused_by_purge"] == "referenced_row_still_present"
    assert str(int(T0) + 5000) in res["flagged_seconds"]


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_A1_not_excused_when_the_referenced_row_is_newer_than_the_cutoff(tmp, rec, source):
    def change(rec, k):                                       # c1 (after the cutoff) deleted the way a purge would
        ha_purge(rec, CUT)
        rec.sql("UPDATE states SET old_state_id = NULL WHERE old_state_id = ?", (k["c1"],))
        rec.sql("DELETE FROM states WHERE state_id = ?", (k["c1"],))
    r, k, res = _purged_and(tmp, rec, source, change)
    v = seg_v(res, T0 + 5001)
    assert v and v["not_excused_by_purge"] == "referenced_row_not_committed_before_cutoff"
    assert {str(int(T0) + 5001), str(int(T0) + 4995)} <= set(res["flagged_seconds"])
    assert str(int(T0) + 5000) not in res["flagged_seconds"]                # the genuine disconnects stay excused


@needs_crypto
@pytest.mark.parametrize("marker", ["none", "foreign_signature", "wrong_hmac", "issued_after_schedule",
                                    "unscoped_policy"])
def test_A1_not_excused_without_a_valid_marker(tmp, rec, marker):
    signer, pub = operator(tmp)
    other, _pub2 = operator(tmp, "intruder")
    purge_history(rec)
    r = sealed_rig(tmp, rec, "escrow")
    if marker == "foreign_signature":
        put_marker(r.anchor, purge_marker(), signer=other)
    elif marker == "wrong_hmac":
        put_marker(r.anchor, purge_marker(), key=b"not-the-operator-key-0123456789", signer=signer)
    elif marker == "issued_after_schedule":
        put_marker(r.anchor, purge_marker(issued=SCHED + 1.0), signer=signer)
    elif marker == "unscoped_policy":                         # the verifier's own policy is required
        put_marker(r.anchor, purge_marker(), signer=signer)
    ha_purge(rec, CUT)
    r.polls(T0 + 6010.0, T0 + 6020.0)
    res = verify_e9(tmp, r, pub, keep=None if marker == "unscoped_policy" else KEEP)
    assert {str(int(T0) + 5000), str(int(T0) + 4990), str(int(T0))} <= set(res["flagged_seconds"])
    assert not res["excused_violations"]
    if marker in ("foreign_signature", "wrong_hmac"):
        assert res["markers"]["rejected"] and not res["markers"]["accepted"]


@needs_crypto
def test_A1_a_segment_older_than_the_cutoff_must_be_gone(tmp, rec):
    """A purge-shaped deletion of only some old rows (a targeted deletion under a purge marker) is not excused."""
    def change(rec, k):
        rec.sql("UPDATE states SET old_state_id = NULL WHERE old_state_id = ?", (k["b1"],))
        rec.sql("DELETE FROM states WHERE state_id = ?", (k["b1"],))   # b1 alone; a1 in the same old minute stays
    r, k, res = _purged_and(tmp, rec, "escrow", change)
    m = seg_v(res, (T0 + 1) // 60, "minute")
    assert m and m["not_excused_by_purge"] == "rows_left_in_a_segment_older_than_the_cutoff"


# ================================================================================================ A2
def _range_scenario(tmp, rec, rowbind):
    r = Rig(tmp, rec, name="rb%s" % rowbind, HOMEPROV_ROWBIND=rowbind)
    r.poll(T0 - 5.0)                                          # the monitor runs before the rows exist
    sid, eid = history(rec, T0)
    r.poll(T0 + 5.0)                                          # one poll first observes all four rows
    rec.sql("UPDATE states SET context_user_id_bin = NULL WHERE state_id = ?", (sid,))
    r.polls(T0 + 10.0, T0 + 20.0)
    return r, sid


def test_A2_per_row_binding_localizes_exactly_the_edited_rows(tmp, rec):
    r, sid = _range_scenario(tmp, rec, "1")
    e = r.anchor.payloads()[1]["keylog"]["states"][0]
    assert e["bind"] == "row_sha256" and e["n"] == 3 and all(len(x[1]) == 64 for x in e["rows"])
    res = verify(tmp, r)
    (kv,) = res["keylog_violations"]
    assert kv["localization"] == "exact"
    assert [x["key"] for x in kv["suspects"]] == ["s:%d" % sid] == [x["key"] for x in kv["changed"]]
    assert res["keylog_suspect_rows"] == []
    assert res["flagged_seconds"] == [str(int(T0) + 1)]
    # the same chain read by its prefixes (what the verifier did before the binding): every row of the range
    pre = verify(tmp, r, rowbind=False)
    (kp,) = pre["keylog_violations"]
    assert kp["localization"] == "prefix_ranked" and len(kp["suspects"]) == 3
    assert set(pre["flagged_seconds"]) == {str(int(T0) + i) for i in (0, 1, 2)}


def test_A2_without_the_binding_records_are_as_before(tmp, rec):
    r, _sid = _range_scenario(tmp, rec, "0")
    e = r.anchor.payloads()[1]["keylog"]["states"][0]
    assert "bind" not in e and e["n"] == 3 and all(len(x[1]) == 8 for x in e["rows"])
    (kv,) = verify(tmp, r)["keylog_violations"]
    assert "localization" not in kv and len(kv["suspects"]) == 3


def test_A2_an_inconsistent_binding_keeps_every_row_a_suspect(tmp, rec):
    r, _sid = _range_scenario(tmp, rec, "1")
    p = json.loads(r.anchor.lines[1])
    p["payload"]["keylog"]["states"][0]["rows"][0][1] = "00" * 32      # a listed hash that does not fold to acc
    r.anchor.lines[1] = json.dumps(p, sort_keys=True)
    (kv,) = verify(tmp, r)["keylog_violations"]
    assert kv["localization"] == "row_binding_inconsistent" and len(kv["suspects"]) == 3


def test_A2_prefix_collision_plus_decoy_is_localized_exactly(tmp, rec):
    """Re-review A1's attack (a birthday-searched 32-bit prefix collision between a parked and a forged form of one
    key, plus a decoy deleted from the same range) against the per-row binding: the forged row is singled out."""
    from test_coverage import FAR, _keylog_prefix
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_ROWBIND="1")
    r.poll(T0 + 5.0)
    M = r.M
    k = rec.con.execute("SELECT max(state_id) FROM states").fetchone()[0] + 1
    seen = {}
    for i in range(1 << 17):
        c = hashlib.md5(b"P%d" % i).digest()
        seen[_keylog_prefix(M, k, "0", FAR, c, None, "sensor.parked")] = c
    i = 0
    while True:
        y = hashlib.md5(b"F%d" % i).digest()
        h = _keylog_prefix(M, k, "unlocked", T0 + 3.5, y, USER, "lock.front_door")
        if h in seen:
            break
        i += 1
    meta = lambda e: rec._id("states_meta", "metadata_id", "entity_id", e)               # noqa: E731
    rec.sql("INSERT INTO states (state_id, state, last_updated_ts, context_id_bin, metadata_id, origin_idx)"
            " VALUES (?, '0', ?, ?, ?, 0)", (k, FAR, seen[h], meta("sensor.parked")))
    rec.sql("INSERT INTO states (state_id, state, last_updated_ts, context_id_bin, metadata_id, origin_idx)"
            " VALUES (?, '0', ?, ?, ?, 0)", (k + 1, FAR + 1, ctx(90), meta("sensor.parked")))
    r.polls(T0 + 10.0, T0 + 40.0)
    rec.sql("UPDATE states SET state='unlocked', last_updated_ts=?, context_id_bin=?, context_user_id_bin=?,"
            " metadata_id=? WHERE state_id=?", (T0 + 3.5, y, USER, meta("lock.front_door"), k))
    rec.sql("DELETE FROM states WHERE state_id=?", (k + 1,))
    r.polls(T0 + 45.0, T0 + 75.0)
    res = verify(tmp, r)
    (kv,) = res["keylog_violations"]
    assert kv["localization"] == "exact"
    assert [x["key"] for x in kv["changed"]] == ["s:%d" % k] and kv["removed"] == ["s:%d" % (k + 1)]
    assert str(int(T0) + 3) in res["flagged_seconds"]


# ================================================================================================ A3
def storage(d, entities, persons=(("p1", "Alex", "u1"),)):
    os.makedirs(d, exist_ok=True)
    files = {"auth": {"users": [{"id": "u1", "name": "Alex", "is_active": True, "system_generated": False,
                                 "password": "never-kept"}]},
             "person": {"items": [{"id": i, "name": n, "user_id": u} for i, n, u in persons]},
             "core.entity_registry": {"entities": [{"entity_id": e, "name": n, "original_name": None,
                                                   "device_id": None} for e, n in entities]},
             "core.device_registry": {"devices": []}}
    for f, data in files.items():
        with open(os.path.join(d, f), "w") as fh:
            json.dump({"data": data}, fh)


@needs_crypto
@pytest.mark.parametrize("case", ["declared", "undeclared", "wrong_digest", "declared_after"])
def test_A3_namemap_change_is_excused_only_by_a_prior_operator_rename(tmp, rec, case):
    signer, pub = operator(tmp)
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch"), ("lock.front_door", "Front door")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    new = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch lamp")
    if case == "wrong_digest":
        new = {"entity": "ab" * 32}
    if case in ("declared", "wrong_digest"):
        put_marker(r.anchor, MI.rename_marker(new, issued_ts=T0 + 11.0), signer=signer)
    storage(st, [("light.porch", "Porch lamp"), ("lock.front_door", "Front door")])
    r.polls(T0 + 15.0, T0 + 20.0)
    if case == "declared_after":
        put_marker(r.anchor, MI.rename_marker(new, issued_ts=T0 + 21.0), signer=signer)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, namemap_storage=st)
    nm = res["namemap"]
    (t,) = nm["transitions"]
    assert t["parts_changed"] == ["entity"] and nm["pending"] is None
    assert t["excused_by_rename_marker"] is (case == "declared")
    assert nm["verdict"] == ("changed_with_declared_renames" if case == "declared"
                             else "display_input_changed_after_seal")
    assert all("never-kept" not in line for line in r.anchor.lines)


def test_A3_pending_change_against_the_hub_storage(tmp, rec):
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    storage(st, [("light.porch", "Porch")], persons=(("p1", "Alex", "u2"),))      # the person re-linked
    res = verify(tmp, r, namemap_storage=st)
    assert res["namemap"]["transitions"] == [] and res["namemap"]["pending"]["parts_changed"] == ["person"]
    assert res["namemap"]["verdict"] == "display_input_changed_after_seal"


# ================================================================================================ A4
HUB_CHILD = r"""
import os, pickle, sqlite3, struct, sys
con = sqlite3.connect(sys.argv[1])
con.execute("PRAGMA journal_mode=WAL")
con.execute("PRAGMA wal_autocheckpoint=0")
inp, out = sys.stdin.buffer, sys.stdout.buffer
def rd():
    h = inp.read(4)
    return None if len(h) < 4 else pickle.loads(inp.read(struct.unpack(">I", h)[0]))
def wr(o):
    b = pickle.dumps(o)
    out.write(struct.pack(">I", len(b)) + b)
    out.flush()
while True:
    m = rd()
    if m is None:
        break
    op, q, a = m
    try:
        if op == "script":
            con.executescript(q); wr(("ok", None, None))
        elif op == "commit":
            con.commit(); wr(("ok", None, None))
        else:
            cur = con.execute(q, a); wr(("ok", cur.fetchall(), cur.lastrowid))
    except Exception as e:
        wr(("err", repr(e), None))
os._exit(0)                     # like a hub that is still running: the WAL and its index stay as they are
"""


class _Cursor:
    def __init__(self, rows, lastrowid):
        self.rows, self.lastrowid = rows, lastrowid

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


class _HubConnection:
    """The hub's SQLite connection, in another process (a reader in the same process would share its WAL index)."""

    def __init__(self, path):
        import subprocess
        import struct
        self._struct = struct
        self.p = subprocess.Popen([sys.executable, "-c", HUB_CHILD, path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)

    def _call(self, m):
        import pickle
        b = pickle.dumps(m)
        self.p.stdin.write(self._struct.pack(">I", len(b)) + b)
        self.p.stdin.flush()
        n = self._struct.unpack(">I", self.p.stdout.read(4))[0]
        st, rows, lastrowid = pickle.loads(self.p.stdout.read(n))
        if st != "ok":
            raise sqlite3.OperationalError(rows)
        return _Cursor(rows, lastrowid)

    def execute(self, q, a=()):
        return self._call(("exec", q, tuple(a)))

    def executescript(self, q):
        return self._call(("script", q, ()))

    def commit(self):
        return self._call(("commit", None, ()))

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


@pytest.fixture
def hub(tmp):
    """A WAL-mode recorder written by a hub process that stays up, its frames not checkpointed."""
    from test_coverage import SCHEMA
    rec = Recorder.__new__(Recorder)
    rec.path = os.path.join(tmp, "hub_v2.db")
    rec.con = _HubConnection(rec.path)
    rec.con.executescript(SCHEMA)
    rec.last = {}
    yield rec
    rec.con.close()


def verify_wal(tmp, rig, **kw):
    """verify() on a copy of a live WAL recorder: the database with its -wal and -shm."""
    Mv = V.load_monitor(rig.M.SCHEME, os.path.join(tmp, "vw_%s_%d" % (rig.M.SCHEME, len(rig.anchor.lines))))
    d = os.path.join(tmp, "vw_%d" % len(os.listdir(tmp)))
    os.makedirs(d)
    db = os.path.join(d, "rec.db")
    for x in ("", "-wal", "-shm"):
        if os.path.exists(rig.rec.path + x):
            shutil.copy2(rig.rec.path + x, db + x)
    return V.verify(Mv, db, rig.anchor.lines, LATE, GAP, scheme=rig.M.SCHEME, **kw)


def files_digest(path):
    return {s: hashlib.sha256(open(path + s, "rb").read()).hexdigest() for s in ("", "-wal", "-shm")
            if os.path.exists(path + s)}


@pytest.mark.parametrize("env", [{}, {"HOMEPROV_SCHEME": "stable", "HOMEPROV_ROWBIND": "1", "HOMEPROV_SINCE": "0"}])
def test_A4_direct_read_and_copy_give_byte_identical_records(tmp, hub, env):
    rec = hub
    sid, eid = history(rec, T0)
    for i in range(40):
        rec.state("sensor.power", str(i), T0 - 7200.0 + i * 13.7, ctx=ctx(200 + i))
    assert os.path.getsize(rec.path + "-wal") > 0 and os.path.exists(rec.path + "-shm")
    rigs = {m: Rig(tmp, rec, name=m, HOMEPROV_READ=m, HOMEPROV_ESCROW_DIR=os.path.join(tmp, "esc_" + m), **env)
            for m in ("copy", "direct")}
    before = files_digest(rec.path)
    for t in (T0 + 5.0, T0 + 10.0):
        for m in ("copy", "direct"):
            out = rigs[m].poll(t)
            assert out.get("read") == ("direct" if m == "direct" else None)
        assert files_digest(rec.path) == before                # direct read wrote nothing of the hub's
    rec.launder(sid, eid)
    for m in ("copy", "direct"):
        rigs[m].poll(T0 + 15.0)
    c, d = rigs["copy"], rigs["direct"]
    assert c.anchor.bodies == d.anchor.bodies and len(d.anchor.bodies) >= 3
    assert open(c.M.STATE, "rb").read() == open(d.M.STATE, "rb").read()
    assert open(os.path.join(tmp, "esc_copy", "escrow.jsonl"), "rb").read() == \
        open(os.path.join(tmp, "esc_direct", "escrow.jsonl"), "rb").read()
    assert verify_wal(tmp, c)["flagged_seconds"] == verify_wal(tmp, d)["flagged_seconds"] == [str(int(T0) + 1)]


def test_A4_one_snapshot_per_poll_while_the_hub_writes(tmp, hub):
    """Rows the hub commits while a direct-read poll runs are not in that poll (one read transaction): its record
    equals the record of a copy taken before them."""
    rec = hub
    history(rec, T0)
    c = Rig(tmp, rec, name="copy")
    d = Rig(tmp, rec, name="direct", HOMEPROV_READ="direct")
    c.poll(T0 + 5.0)
    real = d.M.watermark

    def watermark_then_hub_writes(db):
        wm = real(db)
        rec.state("sensor.late", "x", T0 + 4.5, ctx=ctx(77))          # into a second this poll seals
        rec.event("call_service", T0 + 3.5, ctx=ctx(78))
        return wm
    d.M.watermark = watermark_then_hub_writes
    d.poll(T0 + 5.0)
    assert c.anchor.bodies == d.anchor.bodies


def test_A4_direct_read_falls_back_to_a_copy_without_the_wal_and_fails_closed(tmp, rec, hub):
    rec = Recorder(os.path.join(tmp, "rollback.db"))
    history(rec, T0)                                          # a rollback-journal recorder: no -wal, no -shm
    d = Rig(tmp, rec, HOMEPROV_READ="direct")
    out = d.poll(T0 + 5.0)
    assert out["read"] == "copy_fallback" and out["anchor"]["ok"]
    rec2 = hub
    history(rec2, T0)
    d2 = Rig(tmp, rec2, name="d2", HOMEPROV_READ="direct")
    d2.M.validate_files = lambda db: (False, "wal_truncated", {"test": True})
    out = d2.poll(T0 + 5.0)
    assert out["read"] == "direct" and out["evidence_unobservable"] and out["reason"] == "wal_truncated"
    assert d2.anchor.payloads()[0]["evidence_unobservable"]


def test_A4_a_direct_read_keeps_its_snapshot_while_the_hub_checkpoints(tmp, hub):
    """The pinned read holds SQLite's WAL read lock until the poll ends: a checkpoint by the hub (another process) can
    backfill only up to the snapshot and cannot reset the WAL under it, so the rows, the roots and quick_check stay
    those of the snapshot. (2026-10-10: direct_snapshot() ran validate_files(), which opens and closes the live files,
    after the snapshot was pinned; closing any descriptor of a file drops the process's POSIX advisory locks on it, so a
    checkpoint could tear the snapshot: exp/out/e9_readonly_shm_lockdrop.json.)"""
    rec = hub
    pad = "x" * 300
    for i in range(400):
        rec.state("sensor.s%d" % (i % 5), str(i), T0 + i * 0.5, ctx=ctx(3000 + i), attrs='{"i": %d, "p": "%s"}' % (i, pad))
    rec.con.execute("PRAGMA busy_timeout=200")
    d = Rig(tmp, rec, name="direct", HOMEPROV_READ="direct", HOMEPROV_SCHEME="stable")
    con, _copy_at, (ok, reason, _detail) = d.M.direct_snapshot(quick=True)
    assert ok, reason
    try:
        wm, before = d.M.watermark(con), d.M.commit(d.M.load(con))
        for i in range(400):                                  # the hub rewrites pages the snapshot reads
            rec.sql("UPDATE states SET state = ? WHERE state_id = ?", ("u%d" % i, i + 1))
        busy = rec.con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        assert busy[0] == 1                                   # the snapshot's read lock is still held
        assert os.path.getsize(rec.path + "-wal") > 0
        assert d.M.watermark(con) == wm and d.M.commit(d.M.load(con)) == before
        assert con.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        d.M.direct_close(con)
    assert rec.con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0   # free once the read has ended


def test_A4_quick_check_cadence_and_configuration(tmp, rec):
    history(rec, T0)
    d = Rig(tmp, rec, HOMEPROV_QUICK_CHECK_EVERY="3")
    calls = []
    real = d.M.check_connection

    def spy(con, quick=True):
        calls.append(quick)
        return real(con, quick)
    d.M.check_connection = spy
    d.polls(T0 + 5.0, T0 + 35.0)
    assert calls == [True, False, False, True, False, False, True]
    from test_coverage import monitor_module
    for bad in ({"HOMEPROV_READ": "mmap"}, {"HOMEPROV_QUICK_CHECK_EVERY": "0"},
                {"HOMEPROV_READ": "direct", "HOMEPROV_COVERAGE": "0"}, {"HOMEPROV_ROWBIND": "2"},
                {"HOMEPROV_SINCE": "yesterday"}):
        with pytest.raises(SystemExit):
            monitor_module(os.path.join(HERE, "monitor.py"), os.path.join(tmp, "bad"), rec.path, **bad)


# ================================================================================================ A5
def big_history(rec, n_seconds, t_start):
    for i in range(n_seconds):
        rec.state("sensor.s%d" % (i % 7), str(i), t_start + i + 0.25, ctx=ctx(1000 + i))
        if i % 3 == 0:
            rec.event("call_service", t_start + i + 0.75, ctx=ctx(50000 + i), data='{"i": %d}' % i)


def test_A5_full_history_seal_splits_under_the_anchor_limit_and_binds_every_row(tmp, rec):
    t_start = T0 - 3 * 86400.0                                # three days before the monitor starts
    big_history(rec, 3000, t_start)
    old_sid = rec.con.execute("SELECT min(state_id) FROM states").fetchone()[0]
    limit = 64 * 1024
    a = Anchor()
    a.too_large = limit
    r = Rig(tmp, rec, anchor=a, HOMEPROV_SINCE="0", HOMEPROV_ROWBIND="1", HOMEPROV_MAX_RECORD_BYTES=str(limit),
            HOMEPROV_MAX_PARTS="8")
    r.polls(T0 + 5.0, T0 + 120.0)
    assert r.st["since_applied"] and r.ticks[-1]["pending"] == 0 and r.ticks[-1]["backlog"] == 0
    assert max(len(b) for b in a.bodies) <= limit and max(t["parts"] for t in r.ticks) == 8
    first = a.payloads()[0]
    st0 = next(p["keylog"]["states"][0] for p in a.payloads() if "states" in p.get("keylog", {}))
    assert first["since"] == 0.0 and st0["start"] and st0["from"] == 0  # every row bound by key, from the first poll
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [] and res["segments"]["second"]["anchored_in_window"] == 3000
    rec.sql("UPDATE states SET state = 'x' WHERE state_id = ?", (old_sid,))     # a row three days older than the monitor
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [str(int(t_start))]
    (kv,) = res["keylog_violations"]
    assert kv["localization"] == "exact" and [x["key"] for x in kv["suspects"]] == ["s:%d" % old_sid]


def test_A5_default_records_stay_far_below_16_MiB(tmp, rec):
    big_history(rec, 6000, T0 - 86400.0)
    r = Rig(tmp, rec, HOMEPROV_SINCE="0", HOMEPROV_ROWBIND="1")
    r.polls(T0 + 5.0, T0 + 10.0)
    assert r.ticks[-1]["pending"] == 0
    assert max(len(b) for b in r.anchor.bodies) <= 1024 * 1024 < 16 * 1024 * 1024
    assert r.ticks[0]["parts"] > 1


def test_A5_without_since_the_first_poll_reads_the_window_as_before(tmp, rec):
    big_history(rec, 100, T0 - 86400.0)
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    p = r.anchor.payloads()[0]
    assert p["since"] == T0 - 3600.0 and "since_applied" not in r.st
    assert min(int(s) for s in p["sealed"]["second"]) >= T0 - 3600.0


# ================================================================================================ defaults
E8_MONITOR = os.path.join(HERE, "monitor_e8.py")
E8_SHA256 = "3e479ae01caf299e697b0274a22ddddbaa6b57b9bf4b730a8774b2d7c5b5282b"


def e8_scenario(tmp, rec, path, name, sign=None):
    """Bodies, state and escrow of the E8 configuration (coverage, keylog, escrow, signatures) over a few polls."""
    sid, eid = history(rec, T0)
    env = {"HOMEPROV_SCHEME": "stable", "HOMEPROV_ESCROW_DIR": os.path.join(tmp, "esc_" + name)}
    if sign:
        env["HOMEPROV_SIGN_KEY"] = sign
    r = Rig(tmp, rec, name=name, path=path, **env)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.launder(sid, eid)
    rec.state("sensor.power", "10", T0 + 12.2, ctx=ctx(20))
    r.polls(T0 + 15.0, T0 + 20.0)
    return (r.anchor.bodies, open(r.M.STATE, "rb").read(),
            open(os.path.join(tmp, "esc_" + name, "escrow.jsonl"), "rb").read())


@needs_crypto
def test_new_settings_unset_records_are_byte_identical_to_the_e8_monitor(tmp):
    assert hashlib.sha256(open(E8_MONITOR, "rb").read()).hexdigest() == E8_SHA256
    priv, _pub, _k = _keypair(tmp, "mon")
    got = {}
    for name, path in (("e8", E8_MONITOR), ("now", os.path.join(HERE, "monitor.py"))):
        rec = Recorder(os.path.join(tmp, "rec_%s.db" % name))
        got[name] = e8_scenario(tmp, rec, path, name, sign=priv)
    assert got["e8"] == got["now"]


# ================================================================================================ RESTORE (A6 markers)
def backup_keys(path):
    """The backup's largest key per table (what the harness signs into the RESTORE marker as backup_wm)."""
    c = sqlite3.connect(path)
    wm = {"states": c.execute("SELECT max(state_id) FROM states").fetchone()[0],
          "events": c.execute("SELECT max(event_id) FROM events").fetchone()[0]}
    c.close()
    return wm


FAR = T0 + 100000.0


def restore_scenario(tmp, rec, source="rowbind", backup_at=59, last=100, issued=105.0, after=(110, 130), hold=None,
                     env=None, backup_wm=True, done=True, dummies=False, done_issued=None, restart_rows=0,
                     done_at_end=False, hub_started=True):
    """Rows every second; a backup of the recorder at R = T0 + backup_at + 1; rows go on to T0+last; the operator
    declares the restore (I = T0 + issued; the marker signs the backup's last keys), the hub runs on until T0+hold (when
    given), the backup is put back, the operator declares the hub back (RESTORE_DONE, issued at T0 + after[0] - 0.5 or
    done_issued, with the hub's start T0 + after[0] - 1 and the restored recorder's keys), and the hub writes new rows
    (their keys reuse the lost ones). dummies: the restored recorder also holds one state and one event with keys above
    the pre-restore maximum and a far-future timestamp (re-check N1: a tampered archive), so no poll sees its watermark
    fall. restart_rows: rows the restored hub writes at once (both tables), before any poll reads it. done_at_end: the
    RESTORE_DONE record reaches the chain only after the last poll; hub_started=False: it names no hub start."""
    signer, pub = operator(tmp)
    r = Rig(tmp, rec, name="rs", HOMEPROV_SCHEME="stable", **SOURCES[source],
            **({"HOMEPROV_ESCROW_DIR": os.path.join(tmp, "esc_rs")} if source == "escrow" else {}), **(env or {}))
    r.poll(T0 - 5.0)
    bak = os.path.join(tmp, "backup.db")
    for i in range(last):
        rec.state("sensor.t%d" % (i % 3), str(i), T0 + i + 0.4, ctx=ctx(400 + i))
        if i % 7 == 0:
            rec.event("call_service", T0 + i + 0.6, ctx=ctx(900 + i), data='{"i": %d}' % i)
        if i % 5 == 4:
            r.poll(T0 + i + 1.0)
        if i == backup_at:
            b = sqlite3.connect(bak)
            rec.con.backup(b)
            b.close()
    r.polls(T0 + last + 1.0, T0 + issued + 1.0)
    bw = backup_keys(bak) if backup_wm is True else (backup_wm or None)
    rm = MI.restore_marker(T0 + backup_at + 1.0, issued_ts=T0 + issued, backup_wm=bw)
    put_marker(r.anchor, rm, signer=signer)
    if hold is not None:
        r.polls(T0 + issued + 6.0, T0 + hold)
    top = backup_keys(rec.path)
    rec.con.close()
    shutil.copy2(bak, rec.path)
    rec.con = sqlite3.connect(rec.path)
    if dummies:
        rec.state("sensor.dummy", "x", FAR, sid=top["states"] + 1)
        rec.event("dummy", FAR, eid=top["events"] + 1)
    dm = MI.restore_done_marker(rm, backup_keys(rec.path), hub_started_ts=T0 + after[0] - 1.0 if hub_started else None,
                                issued_ts=T0 + after[0] - 0.5 if done_issued is None else done_issued)
    if done and not done_at_end:
        put_marker(r.anchor, dm, signer=signer)
    for i in range(restart_rows):
        rec.state("sensor.t%d" % (i % 3), "n%d" % i, T0 + after[0] - 0.9 + i * 0.01, ctx=ctx(2000 + i))
        rec.event("call_service", T0 + after[0] - 0.9 + i * 0.01, ctx=ctx(3000 + i))
    rec.last = {e: rec.con.execute("SELECT max(s.state_id) FROM states s JOIN states_meta m ON"
                                   " m.metadata_id = s.metadata_id WHERE m.entity_id = ?", (e,)).fetchone()[0]
                for e in ("sensor.t0", "sensor.t1", "sensor.t2")}
    for i in range(*after):
        rec.state("sensor.t%d" % (i % 3), str(i), T0 + i + 0.4, ctx=ctx(400 + i))
        if i % 5 == 4:
            r.poll(T0 + i + 1.0)
    r.polls(T0 + after[1] + 5.0, T0 + after[1] + 10.0)
    if done and done_at_end:
        put_marker(r.anchor, dm, signer=signer)
    return r, pub


@needs_crypto
@pytest.mark.parametrize("source", ["rowbind", "escrow"])
def test_restore_of_a_backup_is_excused_under_a_restore_marker(tmp, rec, source):
    r, pub = restore_scenario(tmp, rec, source)
    plain = verify(tmp, r)
    assert plain["flagged_seconds"]                                       # the lost rows: violations without the marker
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    assert res["flagged_seconds"] == [] and res["violations"] == [] and res["keylog_violations"] == []
    assert res["restore"]["excused"]["keylog_ranges"] >= 1 and len(plain["keylog_violations"]) >= 1
    assert res["restore"]["excused"]["segments_after_restore_point"]["second"] >= 40
    assert res["restore"]["restores"][0]["backup_last_key"]["states"] == 60


@needs_crypto
def test_restore_marker_does_not_excuse_a_change_before_the_restore_point(tmp, rec):
    r, pub = restore_scenario(tmp, rec, "rowbind")
    rec.sql("UPDATE states SET state = 'x' WHERE state_id = 10")          # after the restore, a row from the backup
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    sec = str(int(rec.con.execute("SELECT last_updated_ts FROM states WHERE state_id = 10").fetchone()[0]))
    assert sec in res["flagged_seconds"]
    assert any(v["seg"] == sec and v.get("not_excused_by_restore") for v in res["violations"])
    no_marker = verify(tmp, r, operator_key=OP, operator_pubkey=pub)      # without --restore-tol-s: not applied
    assert no_marker["restore"]["note"].startswith("RESTORE markers on the chain are not applied")


# ================================================================================================ after the E9 smoke runs
# (1) the streamed full-history seal: the same records, state and escrow as one pass, span by span and batch by batch
def _seal_run(tmp, rec_path, name, span, batch, env):
    rec = Recorder.__new__(Recorder)
    rec.path, rec.con, rec.last = rec_path, sqlite3.connect(rec_path), {}
    r = Rig(tmp, rec, name=name, HOMEPROV_SCHEME="stable", HOMEPROV_SINCE="0",
            HOMEPROV_ESCROW_DIR=os.path.join(tmp, "esc_" + name), HOMEPROV_MAX_RECORD_BYTES=str(32 * 1024),
            HOMEPROV_MAX_PARTS="6", **env)
    r.M.STREAM_SPAN_S, r.M.STREAM_KEYLOG_BATCH = span, batch
    loads, real = [], r.M.load

    def spy(db, since=None, until=None):
        nodes = real(db, since=since, until=until)
        loads.append((since, until, len(nodes)))
        return nodes
    r.M.load = spy
    r.polls(T0 + 5.0, T0 + 60.0)
    assert r.ticks[-1]["pending"] == 0 and r.ticks[-1]["backlog"] == 0
    return (r.anchor.bodies, open(r.M.STATE, "rb").read(),
            open(os.path.join(tmp, "esc_" + name, "escrow.jsonl"), "rb").read()), loads


@pytest.mark.parametrize("env", [{"HOMEPROV_ROWBIND": "1"}, {"HOMEPROV_ROWBIND": "0"}])
def test_streamed_full_history_seal_equals_one_pass(tmp, rec, env):
    big_history(rec, 5000, T0 - 2 * 86400.0)                # rows over about 1.4 hours, two days back
    for i in range(300):                                     # and over six other hours
        rec.state("sensor.h%d" % (i % 4), str(i), T0 - 86400.0 + i * 61.3, ctx=ctx(70000 + i))
    rec.state("sensor.bad", "x", "not a time", ctx=ctx(99999))           # a malformed timestamp, bound by key only
    one, l1 = _seal_run(tmp, rec.path, "one", 1e12, 10 ** 9, env)
    streamed, l2 = _seal_run(tmp, rec.path, "stream", 3600.0, 256, env)
    assert streamed == one
    first = [x for x in l2 if x[1] is not None]              # the streamed first poll read one hour at a time
    assert len(first) >= 8 and all(u - s <= 3600.0 for s, u, _n in first)
    assert max(n for _s, _u, n in first) < sum(n for _s, _u, n in first)


# (2) the PURGE tolerance band: the hub's purge fired 20 s after the scheduled time
def band_history(rec):
    k = purge_history(rec)
    k["d1"] = rec.state("sensor.d", "1", CUT - 10.0, ctx=ctx(40))         # older than the cutoff: purged
    k["d2"] = rec.state("sensor.d", "2", CUT + 5.0, ctx=ctx(41))          # in the band, before the hub's cutoff: purged
    k["d3"] = rec.state("sensor.d", "3", CUT + 30.0, ctx=ctx(42))         # in the band, retained: disconnected
    k["d4"] = rec.state("sensor.d", "4", CUT + 45.0, ctx=ctx(43))         # in the band, retained
    return k


def _band_run(tmp, rec, source, change=None, tol=60.0):
    signer, pub = operator(tmp)
    k = band_history(rec)
    r = sealed_rig(tmp, rec, source)
    put_marker(r.anchor, purge_marker(), signer=signer)
    ha_purge(rec, CUT + 20.0)                                # the hub's own cutoff: its fire time minus keep
    if change:
        change(rec, k)
    r.polls(T0 + 6010.0, T0 + 6020.0)
    return k, verify_e9(tmp, r, pub, purge_tol_s=tol)


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_purge_band_retained_and_disconnected_rows_are_excused(tmp, rec, source):
    k, res = _band_run(tmp, rec, source)
    assert res["flagged_seconds"] == [] and res["violations"] == [] and res["keylog_violations"] == []
    assert res["purge"]["excused"]["tolerance_band"]
    assert "s:%d" % k["d3"] in {d["key"] for d in res["purge"]["disconnected_rows"]}


@needs_crypto
def test_purge_band_without_tolerance_leaves_the_late_purge_unexcused(tmp, rec):
    _k, res = _band_run(tmp, rec, "escrow", tol=0.0)
    assert res["flagged_seconds"]


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_purge_band_deletion_after_a_retained_row_is_not_excused(tmp, rec, source):
    def change(rec, k):                                      # d4 (CUT+45) deleted while d3 (CUT+30) stays
        rec.sql("DELETE FROM states WHERE state_id = ?", (k["d4"],))
    k, res = _band_run(tmp, rec, source, change)
    assert str(int(CUT) + 45) in res["flagged_seconds"]
    assert any(v.get("not_excused_by_purge") == "band_deletion_not_purge_shaped" for v in res["violations"])


@needs_crypto
@pytest.mark.parametrize("source", ["escrow", "rowbind"])
def test_purge_band_edited_row_is_not_excused(tmp, rec, source):
    def change(rec, k):
        rec.sql("UPDATE states SET state = 'x' WHERE state_id = ?", (k["d4"],))
    k, res = _band_run(tmp, rec, source, change)
    assert str(int(CUT) + 45) in res["flagged_seconds"]
    assert any(v.get("not_excused_by_purge") == "a_row_in_the_band_segment_changed" for v in res["violations"])


# (3) RESTORE: the minute holding the restore point keeps the backup's earlier rows
@needs_crypto
@pytest.mark.parametrize("source", ["rowbind", "escrow"])
def test_restore_point_inside_a_minute_is_excused_at_every_granularity(tmp, rec, source):
    r, pub = restore_scenario(tmp, rec, source, backup_at=69, last=130, issued=135.0, after=(140, 160))
    plain = verify(tmp, r)                                   # R = T0+70: minute [T0+60, T0+120), sealed before
    assert str(int(T0 + 60) // 60) in {v["seg"] for v in plain["violations"] if v["gran"] == "minute"}
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0, escrow=(source == "escrow"))
    assert res["flagged_seconds"] == [] and res["violations"] == [] and res["keylog_violations"] == []
    minutes = [v for v in res["excused_violations"] if v["gran"] == "minute"]
    assert [v["seg"] for v in minutes] == [str(int(T0 + 60) // 60)]
    assert minutes[0]["excused_by"]["rule"] == "rows_from_the_backup"


# (4) a RENAME marker excuses one change
@needs_crypto
def test_a_rename_marker_is_consumed_and_a_repeated_change_is_flagged(tmp, rec):
    signer, pub = operator(tmp)
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    to_lamp = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch lamp")
    put_marker(r.anchor, MI.rename_marker(to_lamp, issued_ts=T0 + 11.0), signer=signer)
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 15.0, T0 + 20.0)                            # the declared rename
    back = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch")
    put_marker(r.anchor, MI.rename_marker(back, issued_ts=T0 + 21.0), signer=signer)
    storage(st, [("light.porch", "Porch")])
    r.polls(T0 + 25.0, T0 + 30.0)                            # the declared rename back
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 35.0, T0 + 40.0)                            # the same change again, undeclared
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub)
    t = res["namemap"]["transitions"]
    assert [x["excused_by_rename_marker"] for x in t] == [True, True, False]
    assert len(res["namemap"]["rename_markers_consumed"]) == 2 and res["namemap"]["unexcused_changes"] == 1


def test_namemap_records_after_the_snapshot_are_left_out(tmp, rec):
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 15.0, T0 + 20.0)
    assert len(verify(tmp, r)["namemap"]["transitions"]) == 1
    assert verify(tmp, r, tsnap=T0 + 12.0)["namemap"]["transitions"] == []


# ================================================================================================ E9 code review
# drafts/round13/E9_CODE_REVIEW.md (2026-10-09). Each reproduction of the review (scratch e9review/test_e9_review.py,
# whose attack tests asserted that the attack SUCCEEDS) is here a regression test asserting that it is DETECTED; each
# fails on the reviewed code (monitor a60cdf59..., verifier 428e229b..., issuer 05bde4e4...) and passes now.
def _restore_then_honest_unlock(tmp, rec, source, **kw):
    """The restore scenario, then the hub runs on: an honest app unlock in second T0+1001 (state row and its service
    call), sealed by later polls, long after the restore."""
    r, pub = restore_scenario(tmp, rec, source, **kw)
    r.polls(T0 + 140.0, T0 + 990.0, period=50.0)
    sid, eid = history(rec, T0 + 1000.0)
    r.polls(T0 + 1005.0, T0 + 1030.0)
    return r, pub, sid, eid


@needs_crypto
def test_R1_control_laundering_after_the_restore_is_flagged_without_restore_tol(tmp, rec):
    r, pub, sid, eid = _restore_then_honest_unlock(tmp, rec, "rowbind")
    rec.launder(sid, eid)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub)
    assert str(int(T0) + 1001) in res["flagged_seconds"]


@needs_crypto
@pytest.mark.parametrize("rewind", ["0", "1"])
def test_R1_a_restore_marker_does_not_excuse_a_laundering_after_the_restore(tmp, rec, rewind):
    r, pub, sid, eid = _restore_then_honest_unlock(tmp, rec, "rowbind", env={"HOMEPROV_KEYLOG_REWIND": rewind})
    rec.launder(sid, eid)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0)
    target = str(int(T0) + 1001)
    assert res["flagged_seconds"] == [target]
    assert not any(v["seg"] == target for v in res["excused_violations"])
    v = seg_v(res, target)
    assert v["not_excused_by_restore"] == "segment_sealed_after_the_restored_recorder_was_read"
    x = res["restore"]["restores"][0]
    assert x["status"] == "applied" and T0 + 105.0 <= x["read_back_at"] <= T0 + 115.0
    assert x["falling_watermark_at"] == x["restore_done_at"] == x["read_back_at"]
    assert res["restore"]["excused"]["segments_after_restore_point"]["second"] >= 40     # the restore: still excused
    if rewind == "1":
        # the keylog committed the post-restore rows again: the laundering fails a range the marker cannot excuse
        kept = [kv for kv in res["keylog_violations"] if kv["poll"][1] > x["read_back_poll"][1]]
        assert kept and all(kv["not_excused_by_restore"] == ["range_committed_after_the_restored_recorder_was_read"]
                            for kv in kept)
    else:
        # the lost keys the hub reused are listed with the excused range; their content is bound by their own segments
        reused = {k for kv in res["excused_keylog_violations"] for k in kv.get("restore_reused_keys", [])}
        assert "s:%d" % sid in reused and "e:%d" % eid not in reused


@needs_crypto
def test_R1_a_restore_marker_does_not_excuse_an_edit_with_escrow(tmp, rec):
    r, pub, sid, eid = _restore_then_honest_unlock(tmp, rec, "escrow")
    rec.sql("UPDATE states SET state = 'locked' WHERE state_id = ?", (sid,))
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0, escrow=True)
    assert res["flagged_seconds"] == [str(int(T0) + 1001)]


@needs_crypto
def test_R1_a_restore_marker_does_not_excuse_deleting_every_row_of_a_later_second(tmp, rec):
    r, pub, sid, eid = _restore_then_honest_unlock(tmp, rec, "rowbind")
    rec.sql("DELETE FROM states WHERE state_id = ?", (sid,))
    rec.sql("DELETE FROM events WHERE event_id = ?", (eid,))
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0)
    assert res["flagged_seconds"] == [str(int(T0) + 1001)]


@needs_crypto
def test_R1_a_low_key_row_in_a_second_sealed_before_the_restore_was_read_is_not_excused(tmp, rec):
    """Rows the old hub wrote after the marker (T0+105..109) are sealed before the restore; after it, a row with a lost
    key is inserted into one of those seconds."""
    r, pub = restore_scenario(tmp, rec, "rowbind", last=110, issued=105.0, after=(120, 140))
    fid = rec.state("lock.front_door", "unlocked", T0 + 106.7, ctx=ctx(98), usr=USER)
    assert fid <= 110                                         # a key the restore freed, below the sealing poll's wm
    r.polls(T0 + 150.0, T0 + 160.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0)
    assert str(int(T0) + 106) in res["flagged_seconds"]
    assert seg_v(res, T0 + 106)["not_excused_by_restore"] == "a_row_that_is_not_an_unchanged_backup_row"
    # the other seconds the old hub sealed after the marker were emptied by the restore: excused
    assert all(not seg_v(res, T0 + s) for s in (105, 107, 108))


@needs_crypto
def test_R1_a_restore_marker_without_a_restore_excuses_nothing(tmp, rec):
    """No poll after the marker read a recorder whose keys fell: restore_not_observed, and a deletion in the restore
    window stays a violation."""
    signer, pub = operator(tmp)
    r = Rig(tmp, rec, name="nr", HOMEPROV_SCHEME="stable", HOMEPROV_ROWBIND="1")
    r.poll(T0 - 5.0)
    for i in range(60):
        rec.state("sensor.t%d" % (i % 3), str(i), T0 + i + 0.4, ctx=ctx(400 + i))
        if i % 5 == 4:
            r.poll(T0 + i + 1.0)
    r.polls(T0 + 65.0, T0 + 70.0)
    put_marker(r.anchor, MI.restore_marker(T0 + 30.0, issued_ts=T0 + 71.0, backup_wm={"states": 60, "events": None}),
               signer=signer)
    rec.sql("DELETE FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?", (T0 + 40.0, T0 + 46.0))
    r.polls(T0 + 75.0, T0 + 90.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0)
    assert [str(int(T0) + s) for s in range(40, 46)] == [x for x in res["flagged_seconds"]
                                                          if T0 + 40 <= int(x) < T0 + 46]
    assert res["excused_violations"] == []
    assert res["restore"]["restores"][0]["status"] == "restore_done_missing"


@needs_crypto
@pytest.mark.parametrize("wm", ["disagrees", "absent"])
def test_R1_K_comes_from_the_signed_backup_wm_and_a_mismatch_fails_closed(tmp, rec, wm):
    r, pub = restore_scenario(tmp, rec, "rowbind",
                              backup_wm={"states": 59, "events": 9} if wm == "disagrees" else None)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    assert res["flagged_seconds"] and res["excused_violations"] == []
    if wm == "disagrees":
        x = res["restore"]["restores"][0]
        assert x["status"] == "backup_wm_disagrees_with_the_recorder"
        assert x["backup_last_key"]["states"] == 59 and x["recorder_last_key_before_marker"]["states"] == 60
    else:
        assert res["restore"]["rejected"][0]["why"] == "no_signed_backup_wm"


@needs_crypto
def test_m2_a_restore_marker_older_than_the_maximum_is_rejected(tmp, rec):
    r, pub = restore_scenario(tmp, rec, "rowbind")                         # I - R = 45 s
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0, restore_max_age_s=40.0)
    assert res["restore"]["rejected"][0]["why"] == "restore_point_older_than_the_maximum"
    assert res["flagged_seconds"] and res["excused_violations"] == []
    ok = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0, restore_max_age_s=45.0)
    assert ok["flagged_seconds"] == []


# R6: after a restore, the keylog commits the rows that reuse lost keys again (HOMEPROV_KEYLOG_REWIND=1)
@needs_crypto
@pytest.mark.parametrize("rewind", ["0", "1"])
def test_R6_a_reused_key_row_deleted_before_its_second_is_sealed(tmp, rec, rewind):
    r, pub = restore_scenario(tmp, rec, "rowbind", env={"HOMEPROV_KEYLOG_REWIND": rewind})
    if rewind == "1":
        rw = [p["keylog_rewind"] for p in r.anchor.payloads() if p.get("keylog_rewind")]
        assert len(rw) == 1 and rw[0]["states"] == {"from": 100, "to": 60, "wm": 65}
        assert rw[0]["events"] == {"from": 15, "to": 9, "wm": 9}
    x = rec.state("lock.front_door", "unlocked", T0 + 150.4, ctx=ctx(97), usr=USER)
    assert 60 < x <= 100                                      # a lost key, reused
    r.poll(T0 + 150.8)                                        # first observed; its second not yet sealed
    rec.sql("DELETE FROM states WHERE state_id = ?", (x,))
    r.polls(T0 + 156.0, T0 + 166.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    if rewind == "1":
        assert res["flagged_seconds"] == [str(int(T0) + 150)]
        assert any("s:%d" % x in kv["removed"] for kv in res["keylog_violations"])
    else:
        assert res["flagged_seconds"] == []                   # the gap the setting closes (review R6)


@needs_crypto
def test_R6_the_evidence_of_a_reused_key_is_its_post_restore_row(tmp, rec):
    r, pub = restore_scenario(tmp, rec, "rowbind", env={"HOMEPROV_KEYLOG_REWIND": "1"})
    Mv = V.load_monitor("stable", os.path.join(tmp, "vs_epoch"))
    db = os.path.join(tmp, "epoch.db")
    shutil.copy2(rec.path, db)
    P = V.parse_chain(r.anchor.lines, "stable")
    ev = V.PurgeEvidence(Mv, db, P)
    nodes = {n[1]: n for n in Mv.load(db)}
    reused = [k for k in range(61, 81) if "s:%d" % k in nodes and ev.rewound("states", k)]
    assert len(reused) == 20
    for k in reused:
        n = nodes["s:%d" % k]
        assert ev.first_sec[("states", k)] == int(n[0])                # the post-restore row, not the lost one
        assert ev.row_verdict(n) is True


# R4: the tolerance band's check in a windowed verification, and for a successor's disconnect
def _band_with_successor(tmp, rec, source, change, t_end=T0 + 7300.0):
    """band_history plus sensor.e: e1 in the band (CUT+50, retained by a hub that purged at CUT+20) and its successor e2
    at T0+7250 (old_state_id = e1). Marker, the hub's purge at CUT+20, then `change`, then polls to t_end."""
    signer, pub = operator(tmp)
    k = band_history(rec)
    k["e1"] = rec.state("sensor.e", "open", CUT + 50.0, ctx=ctx(60))
    r = sealed_rig(tmp, rec, source)
    put_marker(r.anchor, purge_marker(), signer=signer)
    ha_purge(rec, CUT + 20.0)
    r.polls(T0 + 6010.0, T0 + 7240.0, period=60.0)
    k["e2"] = rec.state("sensor.e", "closed", T0 + 7250.4, ctx=ctx(61))
    r.polls(T0 + 7255.0, T0 + 7265.0)
    if change:
        change(rec, k)
    r.polls(T0 + 7270.0, t_end)
    return k, r, pub


def _delete_out_of_order(rec, k):
    rec.sql("DELETE FROM states WHERE state_id = ?", (k["d4"],))   # d4 (CUT+45) deleted while d3 (CUT+30) stays


@needs_crypto
@pytest.mark.parametrize("window", [False, True])
def test_R4_an_out_of_order_band_deletion_is_flagged_in_a_windowed_verification_too(tmp, rec, window):
    k, r, pub = _band_with_successor(tmp, rec, "rowbind", _delete_out_of_order)
    kw = {"t0": T0 + 7200.0, "t1": T0 + 7300.0} if window else {}
    res = verify_e9(tmp, r, pub, purge_tol_s=60.0, **kw)
    assert str(int(CUT) + 45) in res["flagged_seconds"]
    kept = [kv for kv in res["keylog_violations"] if "s:%d" % k["d4"] in kv["removed"]]
    assert kept and "removed_row_not_older_than_the_cutoff" in kept[0]["not_excused_by_purge"]


def _hide_successor(rec, k):
    # e1 (a retained band row) deleted out of purge order, and its successor e2 disconnected: e2's state change
    # disappears from the logbook
    rec.sql("DELETE FROM states WHERE state_id = ?", (k["e1"],))
    rec.sql("UPDATE states SET old_state_id = NULL WHERE state_id = ?", (k["e2"],))


@needs_crypto
@pytest.mark.parametrize("source", ["rowbind", "escrow"])
def test_R4_a_successor_disconnect_needs_a_purge_shaped_predecessor(tmp, rec, source):
    k, r, pub = _band_with_successor(tmp, rec, source, _hide_successor)
    e2_sec = str(int(T0) + 7250)
    res = verify_e9(tmp, r, pub, purge_tol_s=60.0)
    assert e2_sec in res["flagged_seconds"] and str(int(CUT) + 50) in res["flagged_seconds"]
    assert "s:%d" % k["e2"] not in {d["key"] for d in res["purge"]["disconnected_rows"]}
    day = verify_e9(tmp, r, pub, purge_tol_s=60.0, t0=T0 + 7200.0, t1=T0 + 7300.0)
    assert e2_sec in day["flagged_seconds"]


@needs_crypto
def test_R4_control_a_purge_shaped_band_still_excuses_the_successor_disconnect(tmp, rec):
    k, r, pub = _band_with_successor(tmp, rec, "rowbind", None)
    for kw in ({}, {"t0": T0 + 7200.0, "t1": T0 + 7300.0}):
        res = verify_e9(tmp, r, pub, purge_tol_s=60.0, **kw)
        assert res["flagged_seconds"] == [] and res["keylog_violations"] == []


# R7: a row written after the purge, backdated before its cutoff, then deleted
@needs_crypto
def test_R7_a_row_written_after_the_purge_and_deleted_is_not_excused_as_purged(tmp, rec):
    signer, pub = operator(tmp)
    purge_history(rec)
    r = sealed_rig(tmp, rec, "rowbind")
    put_marker(r.anchor, purge_marker(), signer=signer)
    ha_purge(rec, CUT)
    r.polls(T0 + 6010.0, T0 + 6020.0)
    r.polls(T0 + 6150.0, T0 + 6150.0)
    # forged and backdated after the purge (first observed after scheduled + tol + PURGE_SEEN_SLACK_S = T0+6120)
    fid = rec.state("lock.front_door", "unlocked", CUT - 500.3, ctx=ctx(77), usr=USER)
    r.polls(T0 + 6155.0, T0 + 6165.0)
    rec.sql("DELETE FROM states WHERE state_id = ?", (fid,))
    r.polls(T0 + 6170.0, T0 + 6180.0)
    res = verify_e9(tmp, r, pub, purge_tol_s=60.0)
    assert str(int(CUT - 500.3)) in res["flagged_seconds"]
    kv = [x for x in res["keylog_violations"] if "s:%d" % fid in x["removed"]]
    assert kv and kv[0]["not_excused_by_purge"] == ["removed_row_written_after_the_purge"]


# R3: a replayed or duplicated marker counts once
@needs_crypto
def test_R3_a_replayed_rename_marker_counts_once(tmp, rec):
    signer, pub = operator(tmp)
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    to_lamp = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch lamp")
    m1 = MI.marker_record(OP, MI.rename_marker(to_lamp, issued_ts=T0 + 11.0), signer)
    r.anchor.write(m1)
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 15.0, T0 + 20.0)                            # the declared rename
    back = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch")
    put_marker(r.anchor, MI.rename_marker(back, issued_ts=T0 + 21.0), signer=signer)
    storage(st, [("light.porch", "Porch")])
    r.polls(T0 + 25.0, T0 + 30.0)                            # the declared rename back
    r.anchor.write(m1)                                       # a replay of the first marker record (same bytes)
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 35.0, T0 + 40.0)                            # the same change again, undeclared
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub)
    assert [x["excused_by_rename_marker"] for x in res["namemap"]["transitions"]] == [True, True, False]
    assert res["namemap"]["unexcused_changes"] == 1
    assert [d["kind"] for d in res["markers"]["duplicates"]] == ["RENAME"]
    assert len(res["markers"]["accepted"]) == 2


# m4: a RENAME marker naming the digest before the change excuses only a change from it
@needs_crypto
@pytest.mark.parametrize("frm", ["right", "wrong"])
def test_m4_a_rename_marker_with_a_from_digest(tmp, rec, frm):
    signer, pub = operator(tmp)
    st = os.path.join(tmp, "storage")
    storage(st, [("light.porch", "Porch")])
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_NAMEMAP_DIR=st)
    r.polls(T0 + 5.0, T0 + 10.0)
    to_lamp = MI.renamed_part_digests(st, "entity", ("entity_id", "light.porch"), "name", "Porch lamp")
    before = MI.current_part_digests(st, to_lamp) if frm == "right" else {"entity": "00" * 32}
    put_marker(r.anchor, MI.rename_marker(to_lamp, issued_ts=T0 + 11.0, from_parts=before), signer=signer)
    storage(st, [("light.porch", "Porch lamp")])
    r.polls(T0 + 15.0, T0 + 20.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub)
    assert [x["excused_by_rename_marker"] for x in res["namemap"]["transitions"]] == [frm == "right"]


# m1: --no-rowbind uses no per-row binding anywhere, the purge rule included
@needs_crypto
def test_m1_without_rowbind_the_purge_rule_does_not_use_the_binding(tmp, rec):
    signer, pub = operator(tmp)
    k = purge_history(rec)
    r = sealed_rig(tmp, rec, "rowbind")
    put_marker(r.anchor, purge_marker(), signer=signer)
    ha_purge(rec, CUT)
    r.polls(T0 + 6010.0, T0 + 6020.0)
    on = verify_e9(tmp, r, pub)
    assert on["flagged_seconds"] == [] and on["purge"]["disconnects"]["n_rows"] >= 2
    off = verify_e9(tmp, r, pub, rowbind=False)
    assert off["purge"]["disconnects"]["n_rows"] == 0
    assert str(int(T0 + 4990.4)) in off["flagged_seconds"]        # b3's disconnect cannot be checked without it
    assert all(kv.get("localization") == "prefix_ranked" for kv in off["keylog_violations"])


# m5: HOMEPROV_SINCE edge cases
def test_m5_since_must_be_finite_and_zero_has_no_lower_bound(tmp, rec):
    from test_coverage import monitor_module
    for bad in ("inf", "-inf", "nan", "1e400"):
        with pytest.raises(SystemExit):
            monitor_module(os.path.join(HERE, "monitor.py"), os.path.join(tmp, "bad"), rec.path, HOMEPROV_SINCE=bad)
    neg = rec.state("sensor.old", "x", -7200.5, ctx=ctx(5))              # a negative (finite) timestamp
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_SCHEME="stable", HOMEPROV_SINCE="0", HOMEPROV_ROWBIND="1")
    r.poll(T0 + 5.0)
    p = r.anchor.payloads()[0]
    assert p["since"] == -10800 and p["keylog"]["states"][0]["from"] == 0
    assert str(int(-7200.5 // 1)) in {s for d in [x.get("sealed", {}).get("second", {}) for x in r.anchor.payloads()]
                                      for s in d}
    rec.sql("UPDATE states SET state = 'y' WHERE state_id = ?", (neg,))
    r.poll(T0 + 10.0)
    assert str(int(-7200.5 // 1)) in verify(tmp, r)["flagged_seconds"]


# m3 (and the lock defect): direct read fails closed when its snapshot is not what it read
def test_m3_direct_read_fails_closed_when_the_read_raced_or_the_files_changed_during_it(tmp, hub):
    rec = hub
    history(rec, T0)
    d = Rig(tmp, rec, name="d", HOMEPROV_READ="direct")
    real = d.M._read_stamp
    calls = []

    def moving(fds):
        got = real(fds)
        calls.append(got)
        return got if len(calls) % 2 else dict(got, wal="00" * 12)
    d.M._read_stamp = moving
    out = d.poll(T0 + 5.0)
    assert out["evidence_unobservable"] and out["reason"] == "read_raced"
    assert out["read_attempts"] == 3 and out["detail"]["attempts"] == 3 and len(calls) == 6    # re-check N2
    p = d.anchor.payloads()[0]
    assert p["evidence_unobservable"] and "sealed" not in p and "keylog" not in p
    d2 = Rig(tmp, rec, name="d2", HOMEPROV_READ="direct")
    realv, seen = d2.M.validate_files, []

    def v(db):
        assert "stamp" not in d2.M._DIRECT                   # never while the read is held
        seen.append(db)
        return realv(db) if len(seen) == 1 else (False, "wal_truncated", {"test": True})
    d2.M.validate_files = v
    out = d2.poll(T0 + 5.0)
    assert out["evidence_unobservable"] and out["reason"] == "wal_truncated" and out["detail"]["after_read"]
    d3 = Rig(tmp, rec, name="d3", HOMEPROV_READ="direct")
    out = d3.poll(T0 + 5.0)
    assert out["read"] == "direct" and not out.get("evidence_unobservable") and d3.M._DIRECT == {}


# ================================================================================================ re-check (2026-10-10)
# drafts/round13/E9_CODE_REVIEW.md "Re-check": N1 and N2, from the reviewer's scratch e9review/recheck/test_recheck.py
# and m3_probe.py, as regression tests (each fails on monitor 3f277d39... / verifier 59a1b228... and passes now).
def _n1_run(tmp, rec, source, done, early=False):
    """The re-check's N1 scenario: the restore, with a tampered archive (rows above the pre-restore maximum keys,
    far-future timestamps), then an honest unlock in T0+1001 sealed, both its rows deleted (after its second is sealed;
    with early=True before its minute is), and much later the planted rows deleted (only now would the watermark fall)."""
    r, pub = restore_scenario(tmp, rec, source, dummies=True, done=done)
    r.polls(T0 + 135.0, T0 + 990.0, period=50.0)
    sid, eid = history(rec, T0 + 1000.0)
    r.polls(T0 + 1005.0, T0 + (1010.0 if early else 1030.0))
    rec.sql("DELETE FROM states WHERE state_id = ?", (sid,))
    rec.sql("DELETE FROM events WHERE event_id = ?", (eid,))
    r.polls(T0 + (1015.0 if early else 1035.0), T0 + 1060.0)
    rec.sql("DELETE FROM states WHERE metadata_id = (SELECT metadata_id FROM states_meta WHERE entity_id = ?)",
            ("sensor.dummy",))
    rec.sql("DELETE FROM events WHERE time_fired_ts = ?", (FAR,))
    r.polls(T0 + 1065.0, T0 + 1080.0)
    return r, pub


@needs_crypto
@pytest.mark.parametrize("source,early", [("escrow", False), ("escrow", True), ("rowbind", True)])
def test_N1_planted_max_keys_cannot_postpone_the_end_of_the_restore_excuse(tmp, rec, source, early):
    r, pub = _n1_run(tmp, rec, source, done=True, early=early)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0, escrow=(source == "escrow"))
    assert str(int(T0) + 1001) in res["flagged_seconds"]
    assert not any(v["seg"] == str(int(T0) + 1001) for v in res["excused_violations"])
    assert res["restore"]["excused"]["segments_after_restore_point"]["second"] >= 40     # the restore: still excused
    x = res["restore"]["restores"][0]
    assert x["status"] == "applied" and x["read_back_by"] == "restore_done"
    assert x["read_back_at"] <= T0 + 115.0 and x["falling_watermark_at"] > T0 + 1060.0


@needs_crypto
def test_N1_without_a_restore_done_marker_the_restore_excuses_nothing(tmp, rec):
    r, pub = _n1_run(tmp, rec, "escrow", done=False)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=30.0, escrow=True)
    assert res["restore"]["restores"][0]["status"] == "restore_done_missing"
    assert str(int(T0) + 1001) in res["flagged_seconds"] and res["excused_violations"] == []


@needs_crypto
def test_N1_a_restore_done_marker_later_than_the_maximum_is_rejected(tmp, rec):
    r, pub = restore_scenario(tmp, rec, "rowbind", done_issued=T0 + 105.0 + 601.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    assert res["restore"]["restores"][0]["status"] == "restore_done_missing"
    assert [x["why"] for x in res["restore"]["rejected"]] == [
        "restore_done_not_within_the_maximum_after_the_restore_marker"]
    assert res["flagged_seconds"] and res["excused_violations"] == []
    ok = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0, restore_done_max_s=605.0)
    assert ok["flagged_seconds"] == []


@needs_crypto
def test_N1_an_honest_restore_whose_watermark_never_falls_is_excused_under_its_restore_done(tmp, rec):
    """The hub writes more rows after the restart than the restore lost before the monitor's first poll reads the
    restored recorder: no poll sees the watermark fall (the honest restore_not_observed case of the re-check)."""
    r, pub = restore_scenario(tmp, rec, "rowbind", restart_rows=60)     # keys past the old maxima in both tables
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    assert res["flagged_seconds"] == [] and res["violations"] == [] and res["keylog_violations"] == []
    x = res["restore"]["restores"][0]
    assert x["falling_watermark_at"] is None and x["read_back_by"] == "restore_done"


@needs_crypto
@pytest.mark.parametrize("hub_started", [True, False])
def test_N1_the_hub_start_in_restore_done_closes_the_window_before_the_restore_done_poll(tmp, rec, hub_started):
    """No poll sees the watermark fall (the restored hub wrote past the old maxima at once) and the RESTORE_DONE record
    reaches the chain after the last poll, so every second the restored hub wrote was sealed before B. A whole such
    second emptied: with the hub's start in the marker it is not excused. Without it (E10, drafts/round13/
    FORMAL_DRAFT.md D4) the RESTORE_DONE marker is rejected (no_hub_started_ts), the restore excuses nothing and the
    second is flagged; before E10 it was excused (the residual window the harness closed by passing the hub's start)."""
    r, pub = restore_scenario(tmp, rec, "rowbind", restart_rows=60, done_at_end=True, hub_started=hub_started,
                              done_issued=T0 + 141.0)
    rec.sql("DELETE FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?", (T0 + 115.0, T0 + 116.0))
    r.polls(T0 + 145.0, T0 + 150.0)
    res = verify(tmp, r, operator_key=OP, operator_pubkey=pub, restore_tol_s=2.0)
    x = res["restore"]["restores"][0]
    if hub_started:
        assert x["falling_watermark_at"] is None and x["read_back_by"] == "restore_done"
        assert str(int(T0) + 115) in res["flagged_seconds"]
        assert seg_v(res, T0 + 115)["not_excused_by_restore"] == "segment_starts_after_the_hub_restarted"
    else:
        assert any(j["kind"] == "RESTORE_DONE" and j["why"] == "no_hub_started_ts" for j in res["restore"]["rejected"])
        assert x["done"] is None
        assert str(int(T0) + 115) in res["flagged_seconds"]


def test_N2_a_direct_read_that_raced_a_legitimate_wal_restart_is_repeated(tmp, hub):
    """The re-check's m3_probe case B: the read pins on a fully checkpointed WAL (read mark 0) and the hub's next commit,
    during the read, restarts the WAL. The poll's first read raced; the poll reads again and succeeds."""
    rec = hub
    rec.con.execute("PRAGMA journal_size_limit=-1")       # Home Assistant's SQLite (Debian's default; macOS's system
    history(rec, T0)                                      # library cuts the WAL to 32 KiB at a restart, unaligned)
    for i in range(40):
        rec.state("sensor.power", str(i), T0 - 600.0 + i * 13.7, ctx=ctx(300 + i))
    assert rec.con.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()[0] == 0     # every frame backfilled
    d = Rig(tmp, rec, name="d", HOMEPROV_READ="direct", HOMEPROV_SCHEME="stable", HOMEPROV_ROWBIND="1",
            HOMEPROV_ESCROW_DIR=os.path.join(tmp, "esc_d"), HOMEPROV_SINCE="0")
    real, n = d.M.watermark, []

    def watermark_then_hub_commits(db):
        wm = real(db)
        if not n:
            n.append(1)
            rec.state("sensor.late", "x", T0 + 3.5, ctx=ctx(77))          # restarts the WAL during the first read
        return wm
    d.M.watermark = watermark_then_hub_commits
    out = d.poll(T0 + 5.0)
    assert out["read"] == "direct" and not out.get("evidence_unobservable") and out["read_attempts"] == 2
    c = Rig(tmp, rec, name="c", HOMEPROV_SCHEME="stable", HOMEPROV_ROWBIND="1",
            HOMEPROV_ESCROW_DIR=os.path.join(tmp, "esc_c"), HOMEPROV_SINCE="0")
    c.poll(T0 + 5.0)
    assert c.anchor.bodies == d.anchor.bodies                # the repeated read is the poll, nothing of the first
    assert open(os.path.join(tmp, "esc_c", "escrow.jsonl"), "rb").read() == \
        open(os.path.join(tmp, "esc_d", "escrow.jsonl"), "rb").read()


def test_A4_malformed_rows_are_reported_in_direct_mode_as_in_copy_mode(tmp, hub):
    """(Found while fixing N2: from the lock fix on, the direct read's end overwrote the poll's list of first-observed
    malformed rows, so a direct poll's record lacked "malformed" where a copy poll's had it.)"""
    rec = hub
    history(rec, T0)
    rec.state("sensor.bad", "x", "not a time", ctx=ctx(55))
    rigs = {m: Rig(tmp, rec, name=m, HOMEPROV_READ=m) for m in ("copy", "direct")}
    for m in ("copy", "direct"):
        rigs[m].poll(T0 + 5.0)
    assert rigs["copy"].anchor.bodies == rigs["direct"].anchor.bodies
    assert "malformed" in rigs["direct"].anchor.payloads()[0]

