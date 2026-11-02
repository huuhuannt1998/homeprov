"""E7 tests (round 13): sealed coverage, stall-proof sealing, escrow, the stable-columns scheme, and the E7 verifier.

    python3 -m pytest -q monitor/test_coverage.py

Every case runs the shipped monitor (monitor/monitor.py, imported per case with its own environment) against a synthetic
SQLite recorder with Home Assistant's schema, at a fixed clock, appending to an in-memory anchor that keeps the anchor
daemon's record format and first-write-wins rule; exp/stages/e7_verify.py then verifies the chain against the final
recorder. Cases: a plain edit; an edit plus 9 and 20 rows inserted into the edited second; rows backdated into an empty
sealed second, minute and hour; benign late rows (never attributed); an insertion with a forged low key into a key gap;
an anchor that refuses appends for several polls while a row of an already-sealed segment is edited (detected after the
anchor returns, stall reported; the earlier monitor misses it); frozen roots that outlive the re-read window and a
monitor restart; escrow round trip, recovery and restore; a 409 conflict; a frozen backlog larger than the anchor's body
limit, split by 413 into continuation records and anchored completely and in order in one poll, and the per-poll bound
on records; clock-file mode; the stable scheme; the
fallback to the existing rule for records without coverage fields; HOMEPROV_COVERAGE=0 byte-identical to the monitor
before E7 (golden digests); and, when the shipped extracts are present, an evaluated chain verified by both verifiers.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
T0 = 1790280000.0                    # an hour boundary (497300 * 3600)
USER = bytes.fromhex("aa" * 16)      # the household member whose unlock is laundered
LATE, GAP = 5.0, 15.0                # LATE_BOUND and GAP_S for the 5 s poll period used here


def ctx(i: int) -> bytes:
    return hashlib.md5(b"ctx%d" % i).digest()


SCHEMA = """
CREATE TABLE states_meta (metadata_id INTEGER PRIMARY KEY, entity_id VARCHAR(255));
CREATE TABLE state_attributes (attributes_id INTEGER PRIMARY KEY, hash BIGINT, shared_attrs TEXT);
CREATE TABLE states (state_id INTEGER PRIMARY KEY, entity_id CHAR(0), state VARCHAR(255), attributes CHAR(0),
  event_id SMALLINT, last_changed CHAR(0), last_changed_ts FLOAT, last_reported_ts FLOAT, last_updated CHAR(0),
  last_updated_ts FLOAT, old_state_id INTEGER, attributes_id INTEGER, context_id CHAR(0), context_user_id CHAR(0),
  context_parent_id CHAR(0), origin_idx SMALLINT, context_id_bin BLOB, context_user_id_bin BLOB,
  context_parent_id_bin BLOB, metadata_id INTEGER);
CREATE TABLE event_types (event_type_id INTEGER PRIMARY KEY, event_type VARCHAR(64));
CREATE TABLE event_data (data_id INTEGER PRIMARY KEY, hash BIGINT, shared_data TEXT);
CREATE TABLE events (event_id INTEGER PRIMARY KEY, event_type CHAR(0), event_data CHAR(0), origin CHAR(0),
  origin_idx SMALLINT, time_fired CHAR(0), time_fired_ts FLOAT, context_id CHAR(0), context_user_id CHAR(0),
  context_parent_id CHAR(0), data_id INTEGER, context_id_bin BLOB, context_user_id_bin BLOB,
  context_parent_id_bin BLOB, event_type_id INTEGER);
"""


class Recorder:
    """A recorder with Home Assistant's table layout; every call commits, as the recorder's commit task does."""

    def __init__(self, path):
        self.path = path
        self.con = sqlite3.connect(path)
        self.con.executescript(SCHEMA)
        self.last = {}

    def _id(self, table, idcol, col, val):
        r = self.con.execute("SELECT %s FROM %s WHERE %s=?" % (idcol, table, col), (val,)).fetchone()
        return r[0] if r else self.con.execute("INSERT INTO %s (%s) VALUES (?)" % (table, col), (val,)).lastrowid

    def state(self, entity, state, ts, ctx=None, par=None, usr=None, sid=None, attrs="{}"):
        mid = self._id("states_meta", "metadata_id", "entity_id", entity)
        aid = self._id("state_attributes", "attributes_id", "shared_attrs", attrs)
        cur = self.con.execute(
            "INSERT INTO states (state_id, state, last_updated_ts, last_changed_ts, old_state_id, attributes_id,"
            " origin_idx, context_id_bin, context_user_id_bin, context_parent_id_bin, metadata_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sid, state, ts, None, self.last.get(entity), aid, 0, ctx, usr, par, mid))
        self.con.commit()
        self.last[entity] = cur.lastrowid
        return cur.lastrowid

    def event(self, etype, ts, ctx=None, par=None, usr=None, data=None, eid=None):
        tid = self._id("event_types", "event_type_id", "event_type", etype)
        did = None if data is None else self._id("event_data", "data_id", "shared_data", data)
        cur = self.con.execute(
            "INSERT INTO events (event_id, origin_idx, time_fired_ts, data_id, context_id_bin, context_user_id_bin,"
            " context_parent_id_bin, event_type_id) VALUES (?,?,?,?,?,?,?,?)",
            (eid, 0, ts, did, ctx, usr, par, tid))
        self.con.commit()
        return cur.lastrowid

    def sql(self, q, args=()):
        self.con.execute(q, args)
        self.con.commit()

    def launder(self, sid, eid):
        """S1-shaped post-commit laundering: the unlock is re-attributed to an automation, the service call removed."""
        self.sql("UPDATE states SET context_user_id_bin=NULL, context_parent_id_bin=? WHERE state_id=?", (ctx(10), sid))
        self.sql("DELETE FROM events WHERE event_id=?", (eid,))


class Anchor:
    """The anchor daemon's record format ({seq, recv_ts, payload}) and its first-write-wins refusal, in memory."""

    def __init__(self):
        self.lines, self.roots, self.down, self.bodies, self.too_large = [], {}, False, [], None

    def append(self, rec):
        body = json.dumps(rec, sort_keys=True).encode()          # the exact bytes monitor.append() would POST
        self.bodies.append(body)
        if self.down:
            return {"ok": False, "err": "TimeoutError('timed out') (stalled anchor)"}
        if self.too_large is not None and len(body) > self.too_large:
            return {"ok": False, "http": 413}
        p = json.loads(body)
        for g, segs in (p.get("sealed") or {}).items():
            for s, v in segs.items():
                k = (g, str(s))
                if k in self.roots and self.roots[k] != v.get("acc"):
                    return {"ok": False, "http": 409, "body": {"error": "first-write-wins: conflicting root",
                            "conflict": {"granularity": g, "segment": str(s), "anchored_acc": self.roots[k],
                                         "offered_acc": v.get("acc")}}}
        return self.write(p)

    def write(self, p):
        for g, segs in (p.get("sealed") or {}).items():
            for s, v in segs.items():
                self.roots[(g, str(s))] = v.get("acc")
        line = json.dumps({"seq": len(self.lines) + 1, "recv_ts": p.get("ts"), "payload": p}, sort_keys=True)
        self.lines.append(line)
        return {"ok": True, "seq": len(self.lines)}

    def payloads(self):
        return [json.loads(x)["payload"] for x in self.lines]


class _Clock:
    def __init__(self):
        self.t = 0.0

    def time(self):
        return self.t

    def sleep(self, _s):
        return None


ENV_KEYS = ("HOMEPROV_SCHEME", "HOMEPROV_ENCODING", "HOMEPROV_COVERAGE", "HOMEPROV_ESCROW_DIR", "HOMEPROV_GRACE_S",
            "HOMEPROV_CLOCK_FILE", "HOMEPROV_NAMEMAP_DIR", "HOMEPROV_ANCHOR_KEY", "HOMEPROV_MAX_ITEMS",
            "HOMEPROV_COST_LOG", "HOMEPROV_PERIOD", "HOMEPROV_MAX_RECORD_BYTES", "HOMEPROV_MAX_PARTS",
            "HOMEPROV_KEYLOG", "HOMEPROV_ROWBIND", "HOMEPROV_SINCE", "HOMEPROV_READ", "HOMEPROV_QUICK_CHECK_EVERY",
            "HOMEPROV_KEYLOG_REWIND")


def load_module(path, name, env):
    old = {k: os.environ.get(k) for k in env}
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod


_n = [0]


def monitor_module(path, scratch, db, **env):
    e = {k: None for k in ENV_KEYS}
    e.update({"HOMEPROV_SCRATCH": scratch, "HOMEPROV_DB": db})
    e.update(env)
    _n[0] += 1
    os.makedirs(scratch, exist_ok=True)
    return load_module(path, "hp_monitor_t%d" % _n[0], e)


class Rig:
    """One monitor (its own scratch and anchor) on a shared recorder, polled at chosen clock times."""

    def __init__(self, tmp, rec, name="m", anchor=None, path=None, real_append=False, **env):
        self.rec = rec
        self.M = monitor_module(path or os.path.join(HERE, "monitor.py"), os.path.join(tmp, "scratch_" + name),
                                rec.path, **env)
        self.anchor = anchor or Anchor()
        if not real_append:                   # real_append: the monitor's own HTTP append, to a test server
            self.M.append = self.anchor.append
        self.clock = _Clock()
        self.M.time = self.clock
        self.st = self.M.load_state()
        self.ticks = []

    def poll(self, t):
        self.clock.t = t
        out = self.M.tick(self.st)
        self.ticks.append(out)
        return out

    def polls(self, t_from, t_to, period=5.0):
        t = t_from
        while t <= t_to + 1e-9:
            self.poll(t)
            t += period


V = load_module(os.path.join(REPO, "exp", "stages", "e7_verify.py"), "e7_verify_t", {})


def verify(tmp, rig, late=LATE, gap=GAP, escrow=False, restore_out=None, scheme=None, **kw):
    scheme = scheme or rig.M.SCHEME
    Mv = V.load_monitor(scheme, os.path.join(tmp, "vscratch_%s_%d" % (scheme, len(rig.anchor.lines))))
    db = os.path.join(tmp, "verify_copy.db")
    shutil.copy2(rig.rec.path, db)
    esc = None
    if escrow:
        esc = open(os.path.join(rig.M.ESCROW_DIR, "escrow.jsonl")).read().splitlines()
    return V.verify(Mv, db, rig.anchor.lines, late, gap, scheme=scheme, escrow_lines=esc, restore_out=restore_out, **kw)


def seg_v(res, seg, gran="second"):
    return next((v for v in res["violations"] if v["gran"] == gran and v["seg"] == str(int(seg))), None)


def history(rec, t):
    """A household member's app unlock in second t+1 (state row and its service call), with neighbours."""
    rec.state("binary_sensor.motion", "on", t + 0.2, ctx=ctx(10))
    eid = rec.event("call_service", t + 1.30, ctx=ctx(1), usr=USER, data='{"domain":"lock","service":"unlock"}')
    sid = rec.state("lock.front_door", "unlocked", t + 1.31, ctx=ctx(1), usr=USER)
    rec.state("light.porch", "on", t + 2.5, ctx=ctx(11), par=ctx(10))
    return sid, eid


@pytest.fixture
def tmp(tmp_path):
    return str(tmp_path)


@pytest.fixture
def rec(tmp):
    return Recorder(os.path.join(tmp, "home-assistant_v2.db"))


# ---------------------------------------------------------------------------------------------- record format
def test_heartbeat_record_carries_coverage_every_poll(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    r.poll(T0 + 10.0)                         # nothing newly sealed: still a record
    p1, p2 = r.anchor.payloads()
    for p, s in ((p1, 1), (p2, 2)):
        assert p["coverage"] == 1 and p["seq_local"] == s and p["copy_at"] == p["ts"]
        assert p["wm"] == {"states": 3, "events": 1} and p["since"] == T0 - 3600.0
    assert p1["through"] == int(T0) + 5 and p2["through"] == int(T0) + 10
    assert set(p1["sealed"]["second"]) == {str(int(T0) + i) for i in (0, 1, 2)}
    assert p2["sealed"] == {}
    assert all("seal_seq" not in v for v in p1["sealed"]["second"].values())   # sealed by its own poll


# ---------------------------------------------------------------------------------------------- detection cases
def test_plain_edit_detected_and_attributable(tmp, rec):
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    rec.launder(sid, eid)
    r.polls(T0 + 10.0, T0 + 20.0)
    res = verify(tmp, r)
    v = seg_v(res, T0 + 1)
    assert v["rule"] == "coverage" and v["violation"] and v["attributable"]
    assert v["mechanism"] == "sealed_rows_removed"
    assert v["existing_rule"]["attributable"]                 # the old rule also attributes it (delta_n = -1)
    assert res["flagged_seconds"] == [str(int(T0) + 1)]
    assert not res["attributable_rows"] and not res["stalls"]


@pytest.mark.parametrize("k", [9, 20])
def test_edit_plus_rows_inserted_into_the_edited_second(tmp, rec, k):
    """The existing rule calls this ambiguous (the row count rose); under coverage it is attributable."""
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    rec.launder(sid, eid)
    for i in range(k):
        rec.state("sensor.filler_%d" % i, "x", T0 + 1.0 + (i + 1) / (k + 2.0), ctx=ctx(100 + i))
    r.polls(T0 + 10.0, T0 + 20.0)
    res = verify(tmp, r)
    v = seg_v(res, T0 + 1)
    assert v["existing_rule"]["violation"] and v["existing_rule"]["ambiguous"]
    assert v["existing_rule"]["delta_n"] == k - 1
    assert v["violation"] and v["attributable"] and v["n_late"] == k
    assert str(int(T0) + 1) in res["flagged_seconds"]


def test_row_backdated_into_empty_sealed_second(tmp, rec):
    history(rec, T0)                          # second T0+3 holds no row and is sealed empty at T0+5
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 40.0)
    rec.state("lock.front_door", "unlocked", T0 + 3.5, ctx=ctx(50), par=ctx(10))
    r.polls(T0 + 45.0, T0 + 50.0)             # the monitor seals the late segment itself
    res = verify(tmp, r)
    rows = res["attributable_rows"]
    assert [x["second"] for x in rows] == [str(int(T0) + 3)]
    assert rows[0]["committed_after_lower_bound_s"] == pytest.approx(36.5)
    assert any(w["why"] == "backdated_into_empty_sealed_time" for w in rows[0]["why"])
    assert str(int(T0) + 3) in res["flagged_seconds"]
    v = seg_v(res, T0 + 3)
    assert v is None                          # its root (sealed late, with the row) reproduces: step 1 alone misses it


def test_row_backdated_into_empty_sealed_minute(tmp, rec):
    history(rec, T0)                          # minute T0+60..T0+120 holds no row
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 130.0)
    rec.state("lock.front_door", "unlocked", T0 + 75.0, ctx=ctx(51))
    r.poll(T0 + 135.0)
    res = verify(tmp, r)
    rows = res["attributable_rows"]
    assert len(rows) == 1 and rows[0]["second"] == str(int(T0) + 75)
    grans = {w["gran"] for w in rows[0]["why"] if w["verdict"] == "attributable"}
    assert grans == {"second", "minute"}      # the hour is still open at T0+135


def test_row_backdated_into_empty_sealed_hour(tmp, rec):
    history(rec, T0)                          # hour T0+3600..T0+7200 holds no row
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 7230.0, period=30.0)
    rec.state("lock.front_door", "unlocked", T0 + 5400.0, ctx=ctx(52))
    r.polls(T0 + 7260.0, T0 + 7290.0, period=30.0)
    res = verify(tmp, r, gap=90.0)
    rows = res["attributable_rows"]
    assert len(rows) == 1 and rows[0]["second"] == str(int(T0) + 5400)
    assert {w["gran"] for w in rows[0]["why"] if w["verdict"] == "attributable"} == {"second", "minute", "hour"}
    assert not res["stalls"]


def test_benign_late_rows_are_not_attributed(tmp, rec):
    history(rec, T0)
    rec.state("sensor.power", "10", T0 + 4.2, ctx=ctx(20))
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)                          # seals T0+4 with one row, T0+3 empty
    rec.state("sensor.power", "11", T0 + 4.9, ctx=ctx(21))    # committed after the seal, 0.1 s after its second
    rec.state("sensor.temp", "20", T0 + 3.95, ctx=ctx(22))    # into the empty second, 1.05 s late
    r.polls(T0 + 10.0, T0 + 20.0)
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [] and res["attributable_rows"] == []
    late = {x["second"]: x["committed_after_lower_bound_s"] for x in res["benign_late_rows"]}
    assert late == {str(int(T0) + 4): pytest.approx(0.1), str(int(T0) + 3): pytest.approx(1.05)}
    v = seg_v(res, T0 + 4)                    # the existing rule fails this segment as rows_arrived_after_seal
    assert not v["violation"] and v["existing_rule"]["violation"] and v["existing_rule"]["ambiguous"]


def test_insertion_with_forged_low_key_into_a_gap(tmp, rec):
    for i in range(6):                        # keys 100..105, then a gap up to 200
        rec.state("sensor.a", str(i), T0 + 0.1 + i * 0.1, ctx=ctx(30 + i), sid=100 + i)
    sid, eid = history(rec, T0)
    rec.sql("UPDATE states SET state_id=200 WHERE state_id=?", (sid,))
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.state("lock.front_door", "unlocked", T0 + 1.2, ctx=ctx(53), usr=USER, sid=150)   # into a non-empty second
    rec.state("lock.front_door", "unlocked", T0 + 3.2, ctx=ctx(54), usr=USER, sid=151)   # into an empty one
    r.polls(T0 + 15.0, T0 + 20.0)
    res = verify(tmp, r)
    v = seg_v(res, T0 + 1)
    assert v["violation"] and v["attributable"] and v["mechanism"] == "row_inserted_with_low_key_or_moved_in"
    rows = {x["key"]: x for x in res["attributable_rows"]}
    assert rows["s:151"]["why"][0]["why"] == "present_when_sealed_empty"
    assert set(res["flagged_seconds"]) == {str(int(T0) + 1), str(int(T0) + 3)}


# ---------------------------------------------------------------------------------------------- anchor stall
def stall_scenario(tmp, rec, **env):
    history(rec, T0)
    r = Rig(tmp, rec, **env)
    r.poll(T0 + 5.0)                          # anchored
    r.anchor.down = True
    eid = rec.event("call_service", T0 + 6.30, ctx=ctx(2), usr=USER, data='{"domain":"lock","service":"unlock"}')
    sid = rec.state("lock.front_door", "unlocked", T0 + 6.31, ctx=ctx(2), usr=USER)
    r.poll(T0 + 10.0)                         # seals T0+6; the append fails
    rec.launder(sid, eid)                     # the sealed row is laundered during the stall
    r.polls(T0 + 15.0, T0 + 25.0)             # three more failed appends
    r.anchor.down = False
    r.polls(T0 + 30.0, T0 + 35.0)
    return r


def test_anchor_stall_edit_of_sealed_row_detected_after_return(tmp, rec):
    r = stall_scenario(tmp, rec)
    p = r.anchor.payloads()[1]                # the first record after the anchor returned
    e = p["sealed"]["second"][str(int(T0) + 6)]
    assert e["seal_seq"] == 2 and e["sealed_at"] == T0 + 10.0 and e["wm"] == {"states": 4, "events": 2}
    assert [h["seq_local"] for h in p["backlog"]] == [2, 3, 4, 5]
    res = verify(tmp, r)
    v = seg_v(res, T0 + 6)
    assert v["violation"] and v["attributable"] and v["seal_poll"] == [0, 2]
    (s,) = res["stalls"]
    assert s["from_ts"] == T0 + 5.0 and s["to_ts"] == T0 + 30.0 and s["kind"] == "anchor_unreachable"
    assert s["seq_local_jump"] == 5 and s["polls_in_backlog"] == 4 and s["polls_unrecorded"] == 0
    assert str(int(T0) + 6) in s["seconds_sealed_during"] and s["segments_sealed_during_violated"] >= 1


def test_anchor_stall_missed_by_the_earlier_monitor(tmp, rec):
    """The same scenario with HOMEPROV_COVERAGE=0: the edited row is sealed in its edited form and nothing is flagged."""
    r = stall_scenario(tmp, rec, HOMEPROV_COVERAGE="0")
    res = verify(tmp, r)
    assert seg_v(res, T0 + 6) is None and res["flagged_seconds"] == [] and res["stalls"] == []


def test_frozen_roots_outlive_the_reread_window(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.anchor.down = True
    r.poll(T0 + 5.0)                          # seals T0..T0+2, append fails
    r.anchor.down = False
    r.poll(T0 + 7300.0)                       # two hours later: T0..T0+2 are before the re-read window
    p = r.anchor.payloads()[0]
    assert p["since"] == T0 + 3600.0
    assert {str(int(T0) + i) for i in range(3)} <= set(p["sealed"]["second"])
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [] and res["stalls"][0]["kind"] == "anchor_unreachable"


def test_monitor_restart_keeps_frozen_roots(tmp, rec):
    sid, eid = history(rec, T0)
    r1 = Rig(tmp, rec, name="m")
    r1.anchor.down = True
    r1.poll(T0 + 5.0)                         # frozen in the state file, append fails
    rec.launder(sid, eid)
    r2 = Rig(tmp, rec, name="m", anchor=r1.anchor)     # same scratch: the restarted monitor reads its state
    r2.anchor.down = False
    r2.poll(T0 + 10.0)
    p = r2.anchor.payloads()[0]
    assert p["seq_local"] == 2 and p["sealed"]["second"][str(int(T0) + 1)]["seal_seq"] == 1
    res = verify(tmp, r2)
    assert seg_v(res, T0 + 1)["attributable"] and res["stalls"][0]["polls_in_backlog"] == 1


def test_state_loss_is_reported_as_a_restart(tmp, rec):
    history(rec, T0)
    r1 = Rig(tmp, rec, name="m")
    r1.polls(T0 + 5.0, T0 + 10.0)
    r2 = Rig(tmp, rec, name="m_new_scratch", anchor=r1.anchor)
    r2.polls(T0 + 15.0, T0 + 20.0)            # counter restarts at 1; identical roots are accepted again
    res = verify(tmp, r2)
    assert res["P"]["epochs"] == 2 and [s["kind"] for s in res["stalls"]] == ["monitor_restarted"]
    assert res["flagged_seconds"] == []


# ---------------------------------------------------------------------------------------------- escrow
def test_escrow_round_trip_recovery_and_restore(tmp, rec):
    sid, eid = history(rec, T0)
    esc = os.path.join(tmp, "escrow")
    r = Rig(tmp, rec, HOMEPROV_ESCROW_DIR=esc)
    r.poll(T0 + 5.0)
    lines = [json.loads(x) for x in open(os.path.join(esc, "escrow.jsonl"))]
    assert [x["seg"] for x in lines] == [str(int(T0) + i) for i in range(3)]
    anchored = r.anchor.payloads()[0]["sealed"]["second"]
    for x in lines:                           # the root recomputed from the escrow equals the anchored root
        got = r.M.commit([r.M.from_jt(j) for j in x["nodes"]])["second"][x["seg"]]
        assert got == anchored[x["seg"]] == {"acc": x["acc"], "n": x["n"]}
    rec.launder(sid, eid)
    r.polls(T0 + 10.0, T0 + 15.0)
    res = verify(tmp, r, escrow=True, restore_out=os.path.join(tmp, "restored.db"))
    (item,) = res["recovery"]["seconds"]
    assert item["escrow"] == "verified_against_anchor"
    (ch,) = item["changed"]
    assert ch["key"] == "s:%d" % sid and set(ch["fields_changed"]) == {"user_id", "parent_id"}
    assert ch["original"]["user_id"] == USER.hex() and ch["current"]["user_id"] is None
    (rm,) = item["removed"]
    assert rm["key"] == "e:%d" % eid and rm["content"]["ty"] == "call_service" and rm["user_id"] == USER.hex()
    rs = res["recovery"]["restore"]
    assert rs["all_roots_reproduced"] is True
    con = sqlite3.connect(os.path.join(tmp, "restored.db"))
    assert con.execute("SELECT context_user_id_bin FROM states WHERE state_id=?", (sid,)).fetchone()[0] == USER
    assert con.execute("SELECT count(*) FROM events WHERE event_id=?", (eid,)).fetchone()[0] == 1


# ---------------------------------------------------------------------------------------------- anchor refusals
def test_conflicting_root_is_quarantined_not_retried(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    forged = {"observer": "external-monitor", "ts": T0 + 4.0, "scheme": "closure", "encoding": "v2",
              "sealed": {"second": {str(int(T0) + 1): {"acc": "00" * 32, "n": 2}}}}
    r.anchor.write(forged)                    # an earlier writer holds a different root for T0+1
    out = r.poll(T0 + 5.0)
    assert out["refused"] == [409] and out["anchor"]["ok"]       # quarantined and re-sent in the same poll
    r.polls(T0 + 10.0, T0 + 15.0)
    ps = r.anchor.payloads()
    assert len(ps) == 4 and ps[1]["conflicted"][0]["seg"] == str(int(T0) + 1)
    assert set(ps[1]["sealed"]["second"]) == {str(int(T0)), str(int(T0) + 2)}
    assert "conflicted" not in ps[2] and "conflicted" not in ps[3] and r.ticks[-1]["pending"] == 0
    res = verify(tmp, r)
    assert res["P"]["conflicted"][0]["seg"] == str(int(T0) + 1)
    assert seg_v(res, T0 + 1)["rule"] == "existing"      # the earlier monitor-format writer's root is the first write


def test_conflicted_root_is_verified_when_no_monitor_record_holds_one(tmp, rec):
    """If the conflicting root came from another appender, the monitor's own (quarantined) root is the one checked."""
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec)
    r.anchor.write({"observer": "someone-else", "sealed": {"second": {str(int(T0) + 1): {"acc": "00" * 32, "n": 2}}}})
    r.polls(T0 + 5.0, T0 + 10.0)
    res = verify(tmp, r)
    assert res["flagged_seconds"] == []
    rec.launder(sid, eid)
    r.poll(T0 + 15.0)
    res = verify(tmp, r)
    v = seg_v(res, T0 + 1)
    assert v["conflicted"] and v["rule"] == "coverage" and v["attributable"]


def long_outage(tmp, rec, seconds=400, anchor=None, **env):
    """Rows in every second for `seconds`; the anchor refuses every append while the monitor polls through them; a
    household member's unlock in an early second is laundered during the outage."""
    sid, eid = history(rec, T0)
    for i in range(3, seconds):
        rec.state("sensor.power", str(i), T0 + i + 0.5, ctx=ctx(1000 + i))
    r = Rig(tmp, rec, anchor=anchor, **env)
    r.anchor.down = True
    r.polls(T0 + 5.0, T0 + seconds + 5.0)
    rec.launder(sid, eid)
    return r


def test_backlog_larger_than_the_anchor_limit_is_split_and_anchored_in_order(tmp, rec):
    r = long_outage(tmp, rec)
    frozen = {g: dict(d) for g, d in r.st["pending"].items()}
    entries = len(r.st["backlog"])
    heads = len({h["seq_local"] for h in r.st["backlog"]})       # a large head is stored as several pieces
    total = sum(len(json.dumps({k: v}, sort_keys=True)) for d in frozen.values() for k, v in d.items())
    limit = 8000
    assert total > 5 * limit and heads > 50
    r.anchor.down, r.anchor.too_large = False, limit        # back, with a body limit far below the backlog
    out = r.poll(T0 + 410.0)
    assert out["pending"] == 0 and out["backlog"] == 0 and out["parts"] > 5
    assert r.st["max_bytes"] < 1024 * 1024                  # 413 halved the record size until records fit
    ps = r.anchor.payloads()
    assert all(len(json.dumps(p, sort_keys=True)) <= limit for p in ps)    # every anchored record is below the limit
    assert out["refused"][:1] == [413] and set(out["refused"]) == {413}
    assert [p.get("part", 1) for p in ps] == list(range(1, len(ps) + 1))
    assert {p["seq_local"] for p in ps} == {r.st["seq_local"]}
    got = {(g, k): v for p in ps for g, d in p["sealed"].items() for k, v in d.items()}
    assert set(got) == {(g, k) for g, d in frozen.items() for k in d}                 # complete
    assert all(got[(g, k)]["acc"] == e["acc"] for g, d in frozen.items() for k, e in d.items())   # frozen roots
    spans = [[v["seal_seq"] for d in p["sealed"].values() for v in d.values()] for p in ps]
    spans = [(min(x), max(x)) for x in spans if x]
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))    # oldest sealing poll first, across records
    assert all("sealed_at" in v for p in ps for d in p["sealed"].values() for v in d.values())
    assert sum(len(p.get("backlog", [])) for p in ps) == entries
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [str(int(T0) + 1)]          # the laundering during the outage
    (st,) = res["stalls"]                                         # one stall, not one per continuation record
    assert st["kind"] == "anchor_unreachable" and st["polls_in_backlog"] == heads


def test_parts_per_poll_are_bounded_and_the_rest_follows(tmp, rec):
    r = long_outage(tmp, rec, seconds=120, HOMEPROV_MAX_RECORD_BYTES="2048", HOMEPROV_MAX_PARTS="3")
    r.anchor.down = False
    r.polls(T0 + 130.0, T0 + 300.0)
    parts = [t["parts"] for t in r.ticks if t.get("parts")]
    assert max(parts) == 3 and r.ticks[-1]["pending"] == 0 and r.ticks[-1]["backlog"] == 0
    assert all(len(b) <= 2048 + 512 for b in r.anchor.bodies if b"part" in b)
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [str(int(T0) + 1)] and len(res["stalls"]) == 1


def test_clock_file_mode(tmp, rec):
    history(rec, T0)
    cf = os.path.join(tmp, "clock")
    open(cf, "w").write("%r" % (T0 + 4.5))
    r = Rig(tmp, rec, HOMEPROV_CLOCK_FILE=cf)
    r.poll(T0 + 6.0)
    p = r.anchor.payloads()[0]
    assert p["ts"] == p["copy_at"] == T0 + 4.5 and p["through"] == int(T0) + 4 and p["monitor_ts"] == T0 + 6.0
    os.remove(cf)
    r.poll(T0 + 11.0)
    p = r.anchor.payloads()[1]
    assert p["evidence_unobservable"] and p["reason"] == "clock_unreadable" and "sealed" not in p


# ---------------------------------------------------------------------------------------------- stable scheme
def test_stable_scheme_ignores_last_reported_and_sees_every_other_column(tmp, rec):
    sid, _eid = history(rec, T0)
    porch = sid + 1
    stable = Rig(tmp, rec, name="stable", HOMEPROV_SCHEME="stable")
    closure = Rig(tmp, rec, name="closure")
    for m in (stable, closure):
        m.poll(T0 + 5.0)
    assert stable.anchor.payloads()[0]["stable_exclude"] == ["states.last_reported_ts"]
    assert {k: v["n"] for k, v in stable.anchor.payloads()[0]["sealed"]["second"].items()} == \
        {k: v["n"] for k, v in closure.anchor.payloads()[0]["sealed"]["second"].items()}
    rec.sql("UPDATE states SET last_reported_ts=? WHERE state_id=?", (T0 + 9.0, sid))   # benign, in place
    for m in (stable, closure):
        m.poll(T0 + 10.0)
    assert verify(tmp, stable)["flagged_seconds"] == [] and verify(tmp, closure)["flagged_seconds"] == []
    rec.sql("UPDATE states SET origin_idx=1 WHERE state_id=?", (porch,))                # outside the closure
    for m in (stable, closure):
        m.poll(T0 + 15.0)
    assert verify(tmp, stable)["flagged_seconds"] == [str(int(T0) + 2)]
    assert verify(tmp, closure)["flagged_seconds"] == []
    rec.sql("UPDATE states SET context_user_id_bin=NULL WHERE state_id=?", (sid,))      # inside the closure
    for m in (stable, closure):
        m.poll(T0 + 20.0)
    assert str(int(T0) + 1) in verify(tmp, stable)["flagged_seconds"]
    assert verify(tmp, closure)["flagged_seconds"] == [str(int(T0) + 1)]


def test_stable_scheme_requires_v2(tmp, rec):
    with pytest.raises(SystemExit):
        monitor_module(os.path.join(HERE, "monitor.py"), os.path.join(tmp, "s"), rec.path,
                       HOMEPROV_SCHEME="stable", HOMEPROV_ENCODING="v1")


# ---------------------------------------------------------------------------------------------- compatibility
def test_records_without_coverage_use_the_existing_rule(tmp, rec):
    sid, eid = history(rec, T0)
    rec.state("sensor.power", "10", T0 + 4.2, ctx=ctx(20))
    r = Rig(tmp, rec, HOMEPROV_COVERAGE="0")
    r.poll(T0 + 5.0)
    rec.launder(sid, eid)
    rec.state("sensor.power", "11", T0 + 4.9, ctx=ctx(21))     # a benign late row
    r.polls(T0 + 10.0, T0 + 15.0)
    assert all("coverage" not in p for p in r.anchor.payloads())
    res = verify(tmp, r)
    v1, v4 = seg_v(res, T0 + 1), seg_v(res, T0 + 4)
    assert v1["rule"] == "existing" and v1["attributable"] and v1["existing_rule"]["delta_n"] == -1
    assert v4["rule"] == "existing" and v4["ambiguous"] and not v4["attributable"]
    assert res["stalls"] == [] and res["attributable_rows"] == []


def test_late_delays_of_an_earlier_chain(tmp, rec):
    """The LATE_BOUND evidence tool on a chain without coverage fields: one benign late row, bracketed exactly."""
    history(rec, T0)
    rec.state("sensor.power", "10", T0 + 4.2, ctx=ctx(20))
    r = Rig(tmp, rec, HOMEPROV_COVERAGE="0")
    r.poll(T0 + 5.0)
    k = rec.state("sensor.power", "11", T0 + 4.9, ctx=ctx(21))
    rec.state("sensor.power", "12", T0 + 6.5, ctx=ctx(22))
    r.poll(T0 + 10.0)
    Mv = V.load_monitor("closure", os.path.join(tmp, "ld"))
    db = os.path.join(tmp, "ld.db")
    shutil.copy2(rec.path, db)
    d = V.late_delays(Mv, db, r.anchor.lines)
    assert d["n_late_rows"] == 1 and d["late_rows"][0]["key"] == "s:%d" % k
    assert d["max_delay_lower_s"] == pytest.approx(0.1) and d["max_delay_upper_s"] == pytest.approx(0.1)


def golden_scenario(tmp, rec, path):
    """Record bytes and state-file bytes after each poll, for the HOMEPROV_COVERAGE=0 byte-identity check."""
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec, name="golden_%d" % _n[0], path=path, HOMEPROV_COVERAGE="0")
    h = hashlib.sha256()
    steps = [(T0 + 3.5, None), (T0 + 4.0, None), (T0 + 9.0, "down"), (T0 + 10.0, "up"), (T0 + 15.0, "launder"),
             (T0 + 70.0, None), (T0 + 3700.0, None)]
    for t, what in steps:
        if what == "down":
            rec.state("sensor.power", "10", T0 + 7.2, ctx=ctx(20))
            r.anchor.down = True
        elif what == "up":
            r.anchor.down = False
        elif what == "launder":
            rec.launder(sid, eid)
        n0 = len(r.anchor.bodies)
        r.poll(t)
        for b in r.anchor.bodies[n0:]:
            h.update(b)
        h.update(b"|state|" + open(r.M.STATE, "rb").read())
    return h.hexdigest(), len(r.anchor.bodies)


# The pre-E7 file itself (review m4: compare against it by default). Copies of it sit in several trees beside the
# repository; they are found by their sha256, not by path, since a tree can be refreshed with a newer monitor.
PRE_E7_SHA256 = "2eb8f872bb9e40452b353a507229e1502fff1ed81e2d772f5de4fe4bb30fc48b"
PRE_E7_CANDIDATES = [os.path.join(os.path.dirname(REPO), *p) for p in (
    ("HOMEPROV-P13-artifact-prep", "r13_tree", "monitor", "monitor.py"),
    ("HOMEPROV-P13-exp", "e6", "stack", "monitor", "monitor.py"),
    ("HOMEPROV-P13-exp", "dz", "runs", "dz", "hp", "monitor.py"),
    ("HOMEPROV-P13-exp", "dz", "dev", "mon_hp", "monitor.py"))]


def pre_e7_file():
    for p in [os.environ.get("HOMEPROV_PRE_E7_MONITOR")] + PRE_E7_CANDIDATES:
        if p and os.path.exists(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == PRE_E7_SHA256:
            return p
    return None

# Computed with monitor/monitor.py as it stood before E7 (sha256 2eb8f872bb9e40452b353a507229e1502fff1ed81e2d772f5de4fe4bb30fc48b,
# the working copy of 2026-10-08 that carries the v2 encoding and the name map), by golden_scenario() above.
GOLDEN_COVERAGE_OFF = ("ebaae19df1f5eaf3d23a811899bf54a26712873b9a6182a285375cc6f22edbfb", 5)


def test_coverage_off_is_byte_identical_to_the_monitor_before_e7(tmp, rec):
    got = golden_scenario(tmp, rec, None)
    pre = pre_e7_file()
    if pre:                                   # direct comparison when the earlier file is at hand
        rec2 = Recorder(os.path.join(tmp, "rec2.db"))
        assert golden_scenario(tmp, rec2, pre) == got
    assert got == GOLDEN_COVERAGE_OFF


# ---------------------------------------------------------------------------------------------- evaluated chains
EXTRACTS = os.path.join(REPO, "reproduce", "snapshots")


@pytest.mark.skipif(not os.path.exists(os.path.join(EXTRACTS, "e_psr_clo.db")), reason="shipped extracts not present")
def test_evaluated_chain_verifies_as_before(tmp):
    """An evaluated closure run (records without coverage fields): the E7 verifier's existing-rule fallback finds the
    same violated seconds as reproduce/verify_all.py, and its per-trial scoring gives the published 90 of 90."""
    sys.path.insert(0, os.path.join(REPO, "reproduce"))
    import verify_all as VA
    res_p = json.load(open(os.path.join(REPO, "exp", "out", "e_psr_clo_detection.json")))
    t0, t1, tsnap = (res_p["window"][k] for k in ("t_start", "t_end", "recorder_snapshot_at"))
    lines = VA.chain_lines(os.path.join(EXTRACTS, "e_psr_clo.chain.jsonl"))
    db = os.path.join(tmp, "e_psr_clo.db")
    shutil.copy2(os.path.join(EXTRACTS, "e_psr_clo.db"), db)
    M = V.load_monitor("closure", os.path.join(tmp, "vs"))
    res = V.verify(M, db, lines, LATE, GAP, scheme="closure", t0=t0, t1=t1, tsnap=tsnap)
    roots = VA.anchored_roots(lines, t0, tsnap)
    (enc,) = {a["encoding"] for a in roots.values()}          # this evaluated chain predates v2: 'v1'
    phi = M.commit(M.load(db, since=(int(t0 // 3600) - 1) * 3600.0), encoding=enc)
    ref = VA.verify_window(phi, roots, dict(M.GRAN), t0, t1)
    mine = {(v["gran"], v["seg"]) for v in res["violations"] if v["violation"]}
    assert mine == {k for k, v in ref.items() if v["violation"]} and mine
    assert all(v["rule"] == "existing" for v in res["violations"])
    trials = [t for t in res_p["trials"] if not (t.get("err") or t.get("error"))]
    arms = V.score_trials(res, trials)
    assert arms["PSR"]["n"] == 90 and arms["PSR"]["existing_attributable"] == 90



# ================================================================================================ E7 code review round
# Each test below turns a reproduction of E7_CODE_REVIEW.md (or of the E7 dry runs) into a check of the fixed
# behaviour; each one fails on the monitor and verifier as they stood before the review.
FAR = T0 + 5 * 3600.0                        # a far-future timestamp: its segments stay open for hours


def _forge(rec, variant):
    """Reserve a key early, fill it 40 s later with a household member's unlock backdated into T0+3 (sealed empty)."""
    if variant == "parked":
        k = rec.state("sensor.parked", "0", FAR, ctx=ctx(61))
        yield
        rec.sql("UPDATE states SET last_updated_ts=?, state='unlocked', context_user_id_bin=?, metadata_id="
                "(SELECT metadata_id FROM states_meta WHERE entity_id='lock.front_door') WHERE state_id=?",
                (T0 + 3.5, USER, k))
    elif variant == "invisible":
        k = rec.con.execute("INSERT INTO states (state, last_updated_ts, context_id_bin, context_user_id_bin, "
                            "metadata_id, origin_idx) VALUES ('unlocked', ?, ?, ?, 999, 0)",
                            (T0 + 3.5, ctx(62), USER)).lastrowid
        rec.con.commit()
        yield
        rec.sql("INSERT INTO states_meta (metadata_id, entity_id) VALUES (999, 'lock.back_door')")
    else:                                    # key_gap
        top = rec.con.execute("SELECT max(state_id) FROM states").fetchone()[0]
        rec.state("sensor.power", "10", T0 + 5.2, ctx=ctx(70), sid=top + 1000)
        rec.state("sensor.power", "11", T0 + 9.0, ctx=ctx(71))
        k = top + 500
        yield
        rec.state("lock.front_door", "unlocked", T0 + 3.5, ctx=ctx(72), usr=USER, sid=k)
    yield "s:%d" % k


def test_B1_control_fresh_key_backdating_is_attributable(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 40.0)
    rec.state("lock.front_door", "unlocked", T0 + 3.5, ctx=ctx(60), usr=USER)
    r.polls(T0 + 45.0, T0 + 75.0)
    assert str(int(T0) + 3) in verify(tmp, r)["flagged_seconds"]


@pytest.mark.parametrize("variant", ["parked", "invisible", "key_gap"])
def test_B1_reserved_key_backdating_is_attributable(tmp, rec, variant):
    """Review B1: the key is reserved right after T0+3 is sealed empty and filled 40 s later. The keylog bound the row
    (or the empty key) at its first observation, so the change is found and localised to the forged row."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    g = _forge(rec, variant)
    next(g)
    r.polls(T0 + 10.0, T0 + 40.0)
    key = next(g)
    r.polls(T0 + 45.0, T0 + 75.0)
    res = verify(tmp, r)
    assert str(int(T0) + 3) in res["flagged_seconds"]
    (kv,) = res["keylog_violations"]
    assert [x["key"] for x in kv["likely"]] == [key] and key in [x["key"] for x in kv["suspects"]]
    assert [x["second"] for x in kv["likely"]] == [str(int(T0) + 3)] and str(int(T0) + 3) in kv["seconds"]
    row = next(x for x in res["attributable_rows"] if x["key"] == key)
    assert any(w["gran"] == "keylog" for w in row["why"])


@pytest.mark.parametrize("scheme", ["closure", "stable"])
def test_keylog_is_quiet_on_benign_late_rows_and_on_last_reported(tmp, rec, scheme):
    """Rows committed up to 0.95 s late, every second, and the recorder's in-place rewrite of last_reported_ts on the
    previous row of an entity: the keylog checks every range and finds nothing."""
    prev = None
    r = Rig(tmp, rec, HOMEPROV_SCHEME=scheme)
    for i in range(40):
        if i % 5 == 0:
            r.poll(T0 + i + 0.95)
        k = rec.state("sensor.power", str(i % 3), T0 + i + 0.05, ctx=ctx(3000 + i))
        if prev is not None:
            rec.sql("UPDATE states SET last_reported_ts=? WHERE state_id=?", (T0 + i + 0.06, prev))
        prev = k
    r.polls(T0 + 45.0, T0 + 60.0)
    res = verify(tmp, r)
    assert res["keylog"]["ranges_checked"] >= 8 and res["keylog_violations"] == []
    assert res["flagged_seconds"] == [] and res["attributable_rows"] == []


def test_M1_minute_only_violation_reaches_flagged_seconds_scoring_and_floor(tmp, rec):
    """Review M1 (keylog off, so only the minute root sees it): the parked row is moved into T0+3 after its minute was
    sealed. The minute violation is localised to T0+3, which reaches flagged_seconds, the trial score and the floor."""
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_KEYLOG="0")
    r.poll(T0 + 5.0)
    k = rec.state("sensor.parked", "0", FAR, ctx=ctx(63))
    r.polls(T0 + 10.0, T0 + 70.0)
    rec.sql("UPDATE states SET last_updated_ts=?, context_user_id_bin=? WHERE state_id=?", (T0 + 3.5, USER, k))
    r.polls(T0 + 75.0, T0 + 80.0)
    res = verify(tmp, r)
    mv = seg_v(res, T0 // 60, "minute")
    assert mv["attributable"] and mv["localized_seconds"] == [str(int(T0) + 3)]
    assert str(int(T0) + 3) in res["flagged_seconds"]
    assert {"gran": "minute", "seg": str(int(T0 // 60))}.items() <= res["flagged_segments"][0].items()
    arms = V.score_trials(res, [{"arm": "backdate", "forged_row": {"ts": T0 + 3.5}}])
    assert arms["backdate"]["e7_detected"] == 1 and arms["backdate"]["e7_detected_any_granularity"] == 1
    floor = V.benign_floor(res, set())
    assert floor["minute"]["attributable"] == 1 and str(int(T0) + 3) in floor["untouched_flagged_seconds"]["seconds"]


def test_M1_a_flagged_second_explains_its_minute_without_flagging_neighbours(tmp, rec):
    """A minute violated by a laundered second must not also flag a benign late row of the same minute (seen in the
    E7 dry runs before the guard)."""
    sid, eid = history(rec, T0)
    rec.state("sensor.power", "10", T0 + 4.2, ctx=ctx(20))
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    rec.state("sensor.power", "11", T0 + 4.9, ctx=ctx(21))     # benign: late for its second, early for its minute
    r.polls(T0 + 10.0, T0 + 65.0)                              # the minute is sealed with it
    rec.launder(sid, eid)
    r.polls(T0 + 70.0, T0 + 75.0)
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [str(int(T0) + 1)]
    mv = seg_v(res, T0 // 60, "minute")
    assert mv["attributable"] and mv["localized_seconds"] == [] and mv["explained_by_flagged_seconds"]


@pytest.mark.parametrize("bad", ["abc", b"\x00", float("inf"), None])
def test_M2_malformed_timestamp_neither_stops_polling_nor_the_verifier(tmp, rec, bad):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    rec.sql("INSERT INTO states (state, last_updated_ts, metadata_id) VALUES ('x', ?, 1)", (bad,))
    rec.state("sensor.after", "1", T0 + 7.5, ctx=ctx(80))
    r.polls(T0 + 10.0, T0 + 20.0)
    ps = r.anchor.payloads()
    assert len(ps) == 4 and not any(p.get("evidence_unobservable") for p in ps)
    assert str(int(T0) + 7) in ps[1]["sealed"]["second"]                  # sealing went on
    assert ps[1]["malformed"]["states"]["n"] == 1                         # and the row is named on the chain
    res = verify(tmp, r)
    assert res["malformed_rows"]["n"] == 1 and res["flagged_seconds"] == []


def test_M2_a_failing_load_is_an_unobservable_poll_and_polling_goes_on(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    real = r.M.load

    def boom(*a, **k):
        raise TypeError("unsupported recorder value")
    r.M.load = boom
    r.poll(T0 + 5.0)
    r.M.load = real
    r.poll(T0 + 10.0)
    p1, p2 = r.anchor.payloads()
    assert p1["evidence_unobservable"] and p1["reason"] == "load_failed" and "TypeError" in p1["detail"]["exc"]
    assert len(p2["sealed"]["second"]) == 3


class PartAnchor(Anchor):
    """Accepts the first `ok_first` appends, then times out until reopened (budget None)."""

    def __init__(self, ok_first):
        super().__init__()
        self.budget = ok_first

    def append(self, rec):
        if self.budget is not None:
            if self.budget <= 0:
                self.bodies.append(json.dumps(rec, sort_keys=True).encode())
                return {"ok": False, "err": "TimeoutError('timed out')"}
            self.budget -= 1
        return super().append(rec)


def test_M3_a_root_not_yet_on_the_chain_is_never_read_as_empty(tmp, rec):
    for i in range(60):
        rec.state("sensor.power", str(i), T0 + i + 0.5, ctx=ctx(2000 + i))
    r = Rig(tmp, rec, anchor=PartAnchor(1), HOMEPROV_MAX_RECORD_BYTES="2048")
    r.poll(T0 + 65.0)
    assert r.ticks[-1]["parts"] == 1 and r.ticks[-1]["pending"] > 0
    stopped = verify(tmp, r)                                  # the monitor stopped here: those roots never came
    assert stopped["attributable_rows"] == [] and len(stopped["root_unknown_segments"]) >= 10
    r.anchor.budget = None
    r.poll(T0 + 70.0)
    trunc = verify(tmp, r, tsnap=T0 + 67.0)                   # roots sealed before the snapshot, anchored after it
    assert trunc["attributable_rows"] == [] and trunc["root_unknown_segments"] == []
    full = verify(tmp, r)
    assert full["attributable_rows"] == [] and full["root_unknown_segments"] == []


def test_M4_unobservable_interval_is_reported_and_its_laundering_detected(tmp, rec):
    sid, eid = history(rec, T0 + 10)                          # unlock at T0+11.31
    r = Rig(tmp, rec, HOMEPROV_GRACE_S="2")
    r.poll(T0 + 12.0)                                         # observed (and keylogged), not yet sealed
    wal = rec.path + "-wal"
    open(wal, "wb").write(b"\x00" * 64)                       # the hub makes every copy unobservable
    r.polls(T0 + 17.0, T0 + 27.0)
    os.remove(wal)
    rec.launder(sid, eid)
    assert sqlite3.connect(rec.path).execute("SELECT context_user_id_bin FROM states WHERE state_id=?",
                                             (sid,)).fetchone()[0] is None
    r.polls(T0 + 32.0, T0 + 37.0)                             # T0+11 is sealed in its laundered form
    res = verify(tmp, r)
    (s,) = [x for x in res["stalls"] if x["kind"] == "evidence_unobservable"]
    assert s["unobservable_polls"] == 3 and s["reasons"] == ["wal_header_corrupt"]
    assert str(int(T0) + 11) in s["seconds_sealed_after_gap"][0]["nonempty"]
    assert str(int(T0) + 11) in res["flagged_seconds"]        # the keylog bound the unlock at T0+12


def test_M4_frozen_roots_are_sent_while_copies_are_unobservable(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.anchor.down = True
    r.poll(T0 + 5.0)                                          # frozen, not anchored
    r.anchor.down = False
    wal = rec.path + "-wal"
    open(wal, "wb").write(b"\x00" * 64)
    r.poll(T0 + 10.0)                                         # unobservable: the roots still go out
    os.remove(wal)
    p1, p2 = r.anchor.payloads()
    assert p1["evidence_unobservable"] and "sealed" not in p1
    assert p2["part"] == 2 and not p2.get("evidence_unobservable") and len(p2["sealed"]["second"]) == 3
    assert r.ticks[-1]["pending"] == 0
    res = verify(tmp, r)
    assert res["flagged_seconds"] == [] and len([1 for (g, _s) in res["roots"] if g == "second"]) == 3


class ResetAnchor(Anchor):
    """The hardened anchor refuses an oversized body unread and closes: a large body sees a broken pipe."""

    reset_over = None

    def append(self, rec):
        body = json.dumps(rec, sort_keys=True).encode()
        if not self.down and self.reset_over is not None and len(body) > self.reset_over:
            self.bodies.append(body)
            return {"ok": False, "err": "URLError(BrokenPipeError(32, 'Broken pipe'))"}
        return super().append(rec)


def test_m1_a_reset_on_a_large_body_is_taken_as_a_413(tmp, rec):
    r = long_outage(tmp, rec, seconds=120, anchor=ResetAnchor())
    r.anchor.down, r.anchor.reset_over = False, 6000
    out = r.poll(T0 + 130.0)
    assert out["pending"] == 0 and out["backlog"] == 0
    assert any("Broken pipe" in str(x) for x in out["refused"])


def test_m2_a_copy_racing_a_wal_restart_is_repeated_or_fails_closed(tmp, rec):
    import itertools
    history(rec, T0)
    r = Rig(tmp, rec)
    salts = iter([b"a", b"b", b"b", b"b"])                    # the first copy races, the second does not
    r.M._wal_salt = lambda: next(salts)
    r.poll(T0 + 5.0)
    count = itertools.count()
    r.M._wal_salt = lambda: str(next(count)).encode()          # the WAL never settles
    r.poll(T0 + 10.0)
    p1, p2 = r.anchor.payloads()
    assert not p1.get("evidence_unobservable") and len(p1["sealed"]["second"]) == 3
    assert p2["evidence_unobservable"] and p2["reason"] == "copy_raced"


def test_m6_configuration_is_validated(tmp, rec):
    for env in ({"HOMEPROV_MAX_PARTS": "0"}, {"HOMEPROV_MAX_RECORD_BYTES": "10"}, {"HOMEPROV_KEYLOG": "yes"}):
        with pytest.raises(SystemExit):
            monitor_module(os.path.join(HERE, "monitor.py"), os.path.join(tmp, "v"), rec.path, **env)


class LateCommitAnchor(Anchor):
    """While held, an append times out at the monitor but the anchor keeps it, and commits it later (E7 dry runs)."""

    hold = False

    def __init__(self):
        super().__init__()
        self.held = []

    def append(self, rec):
        if self.hold:
            self.bodies.append(json.dumps(rec, sort_keys=True).encode())
            self.held.append(json.loads(json.dumps(rec)))
            return {"ok": False, "err": "TimeoutError('timed out')"}
        return super().append(rec)

    def release(self, order):
        for i in order:
            self.write(self.held[i])
        self.held = []


def test_late_committed_records_are_one_anchor_interval_not_a_restart(tmp, rec):
    """E7 dry runs: three appends time out at the monitor, the anchor commits them late and out of poll order, the
    next poll carries their heads. One anchor_unreachable interval, no restart."""
    history(rec, T0)
    r = Rig(tmp, rec, anchor=LateCommitAnchor())
    r.polls(T0 + 5.0, T0 + 20.0)
    r.anchor.hold = True
    r.polls(T0 + 35.0, T0 + 65.0, period=15.0)                # 10 s client timeout + 5 s period
    r.anchor.hold = False
    r.anchor.release([1, 0, 2])
    r.polls(T0 + 80.0, T0 + 90.0)
    res = verify(tmp, r, gap=30.0)
    assert res["P"]["epochs"] == 1
    (s,) = res["stalls"]
    assert s["kind"] == "anchor_unreachable" and s["polls_in_backlog"] == 3 and s["late_committed_polls"] == 3
    assert s["from_ts"] == T0 + 20.0 and s["to_ts"] == T0 + 80.0 and res["flagged_seconds"] == []


def test_a_benign_gap_is_an_interval_never_a_detection(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.state("sensor.power", "1", T0 + 30.5, ctx=ctx(40))    # written while the monitor is silent
    r.polls(T0 + 60.0, T0 + 65.0)
    res = verify(tmp, r, gap=30.0)
    (s,) = res["stalls"]
    assert s["kind"] == "monitor_silent" and res["flagged_seconds"] == [] and res["attributable_rows"] == []
    assert str(int(T0) + 30) in s["seconds_sealed_after_gap"][0]["nonempty"]


def test_rows_in_time_never_read_are_unsealed_not_attributed(tmp, rec):
    """Review mutant no_since: after a two-hour monitor outage, rows of the unread interval are reported as unsealed,
    never as attributable insertions."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    rec.state("sensor.x", "1", T0 + 100.5, ctx=ctx(90))
    r.poll(T0 + 7300.0)
    res = verify(tmp, r, gap=8000.0)
    assert res["attributable_rows"] == [] and res["rows_in_unsealed_time"].get("second", 0) >= 1


# ================================================================================================ E7 re-review round
# Each test turns an attack of the re-review (scratchpad e7review/test_rereview.py, A1-A5) into a check of the fixed
# behaviour; each one fails on the re-reviewed code (monitor 9b0970d7..., verifier 6764e8e4...).
def _keylog_prefix(M, sid, state, ts, ctx_, usr, ent):
    fields = ("states", "state_id", sid, "state", state, "last_updated_ts", ts, "last_changed_ts", None,
              "old_state_id", None, "context_id_bin", ctx_, "context_parent_id_bin", None,
              "context_user_id_bin", usr, "states_meta.entity_id", ent)
    return M.H(M.encode_node_v2("keylog", fields)).hex()[:8]


def test_R1_prefix_collision_plus_decoy_still_flags_the_forged_second(tmp, rec):
    """Re-review A1: a birthday search gives a parked and a forged form of one key with equal 32-bit prefixes, and a
    decoy in the same range is deleted so the range looks localised elsewhere. Every row of a failed range is a suspect
    now, so the forged row's second is flagged although the prefixes do not single it out."""
    history(rec, T0)
    r = Rig(tmp, rec)
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
            " VALUES (?, '0', ?, ?, ?, 0)", (k + 1, FAR + 1, ctx(90), meta("sensor.parked")))      # the decoy
    r.polls(T0 + 10.0, T0 + 40.0)
    rec.sql("UPDATE states SET state='unlocked', last_updated_ts=?, context_id_bin=?, context_user_id_bin=?,"
            " metadata_id=? WHERE state_id=?", (T0 + 3.5, y, USER, meta("lock.front_door"), k))
    rec.sql("DELETE FROM states WHERE state_id=?", (k + 1,))
    r.polls(T0 + 45.0, T0 + 75.0)
    res = verify(tmp, r)
    (kv,) = res["keylog_violations"]
    assert kv["changed"] == [] and kv["removed"] == ["s:%d" % (k + 1)]       # the prefixes point at the decoy ...
    assert "s:%d" % k in [x["key"] for x in kv["suspects"]]                    # ... but every row is a suspect
    assert str(int(T0) + 3) in kv["seconds"] and str(int(T0) + 3) in res["flagged_seconds"]


def test_R2_invalid_utf8_text_neither_stops_sealing_nor_the_verifier(tmp, rec):
    """Re-review A2: one TEXT value that is not valid UTF-8. Sealing goes on, the row is named in the record and by the
    verifier, and a later change to the raw bytes is still detected (they are committed byte for byte)."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    k = rec.con.execute("INSERT INTO states (state, last_updated_ts, metadata_id) VALUES (CAST(x'ff41' AS TEXT), ?, 1)",
                        (T0 - 7200.0,)).lastrowid
    rec.con.commit()
    rec.state("lock.front_door", "unlocked", T0 + 6.3, ctx=ctx(80), usr=USER)
    r.polls(T0 + 10.0, T0 + 40.0, period=10.0)
    ps = r.anchor.payloads()
    assert not any(p.get("evidence_unobservable") for p in ps)
    assert str(int(T0) + 6) in ps[1]["sealed"]["second"] and ps[1]["invalid_text"]["states"]["keys"] == [k]
    res = verify(tmp, r)
    assert [x["key"] for x in res["invalid_text_rows"]["rows"]] == ["s:%d" % k] and res["flagged_seconds"] == []
    rec.sql("UPDATE states SET state=CAST(x'ff42' AS TEXT) WHERE state_id=?", (k,))
    r.poll(T0 + 50.0)
    res = verify(tmp, r)
    assert any(x["key"] == "s:%d" % k for kv in res["keylog_violations"] for x in kv["changed"])
    assert str(int(T0 - 7200)) in res["flagged_seconds"]


@pytest.mark.parametrize("how", ["malformed", "deleted", "deleted_key_reused", "re_timed"])
def test_R3_a_row_hit_in_its_open_second_flags_that_second(tmp, rec, how):
    """Re-review A3/A3b: a genuine unlock is observed while its second is open, then made malformed, deleted, or moved,
    before the second is sealed. Its first-observed second (now in the keylog) is flagged."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 5.0)
    k = rec.state("lock.front_door", "unlocked", T0 + 5.2, ctx=ctx(81), usr=USER)
    r.poll(T0 + 5.5)                                          # observed; second T0+5 still open
    if how == "malformed":
        rec.sql("UPDATE states SET last_updated_ts='gone' WHERE state_id=?", (k,))
    elif how == "re_timed":
        rec.sql("UPDATE states SET last_updated_ts=? WHERE state_id=?", (FAR, k))
    else:
        rec.sql("DELETE FROM states WHERE state_id=?", (k,))
        if how == "deleted_key_reused":
            rec.state("sensor.power", "1", T0 + 7.0, ctx=ctx(88))
    r.polls(T0 + 10.5, T0 + 20.5)
    res = verify(tmp, r)
    assert str(int(T0) + 5) in res["flagged_seconds"]
    (kv,) = res["keylog_violations"]
    assert any(x["key"] == "s:%d" % k and x["first_observed_second"] == str(int(T0) + 5) for x in kv["suspects"])


def test_R4_key_hole_after_a_restart_without_state_is_reported(tmp, rec):
    """Re-review A5: with the state file lost, the new monitor starts its keylog above the largest sealed key; the keys
    between the old high-water and that start were never committed, and are now listed."""
    history(rec, T0)
    r1 = Rig(tmp, rec, name="m")
    r1.polls(T0 + 5.0, T0 + 20.0)
    k = rec.state("sensor.parked", "0", FAR, ctx=ctx(84))
    rec.state("sensor.power", "1", T0 + 22.0, ctx=ctx(85))
    r2 = Rig(tmp, rec, name="m_new", anchor=r1.anchor)       # state lost
    r2.polls(T0 + 25.0, T0 + 40.0)
    res = verify(tmp, r2)
    holes = [h for h in res["keylog"]["uncommitted_key_ranges"] if h["table"] == "states"]
    assert [h["why"] for h in holes] == ["monitor_restarted_without_its_state"]
    assert holes[0]["range"][0] < k <= holes[0]["range"][1]


def test_floor_a_trials_own_deleted_events_are_touched_not_benign(tmp, rec):
    """E7 smoke run: a laundering trial deletes the author's service call after the keylog first observed it in the
    trial's own second. The removed row has no current second; it is touched through its first-observed second (or
    through the trial's deleted_event_ids) and must not appear among the floor's untouched attributable rows, while it
    stays in the trial's own detection evidence."""
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec)
    r.poll(T0 + 1.5)                                          # the unlock and its service call are first observed
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.launder(sid, eid)
    r.polls(T0 + 15.0, T0 + 20.0)
    res = verify(tmp, r)
    s1, ekey = str(int(T0) + 1), "e:%d" % eid
    row = next(x for x in res["attributable_rows"] if x["key"] == ekey)
    assert row["second"] is None and row["first_observed_second"] == s1
    floor = V.benign_floor(res, {s1})
    assert ekey not in [x["key"] for x in floor["untouched_attributable_rows"]]
    assert floor["keylog_violations_untouched"] == []
    floor = V.benign_floor(res, set(), touched_rows={ekey})   # the trial report names the deleted event
    assert ekey not in [x["key"] for x in floor["untouched_attributable_rows"]]
    assert V.touched_by_deletions([{"deleted_event_ids": [eid], "deleted_event_seconds": [T0 + 1.3]}]) == ({s1}, {ekey})
    trial = {"arm": "INS-L", "row_before": {"state_id": sid, "ts": T0 + 1.31}, "deleted_event_ids": [eid]}
    V.score_trials(res, [trial])
    assert ekey in trial["_e7"]["attributable_rows"] and trial["_e7"]["deleted_event_rows_attributable"] == [ekey]
    assert trial["_e7"]["detected"]


def test_escrow_restores_a_late_row_from_its_first_observation(tmp, rec):
    """E7 main run, recovery 119 of 120: an unlock reached the recorder after its second was sealed, so no sealed-
    segment escrow line held it; the keylog committed it at first sight and caught its laundering. The escrow now keeps
    the keylog's first-observation tuples (checked against the anchored keylog), and the restore writes the row back."""
    history(rec, T0)
    esc = os.path.join(tmp, "escrow")
    r = Rig(tmp, rec, HOMEPROV_ESCROW_DIR=esc)
    r.poll(T0 + 3.0)                                          # seals T0, T0+1, T0+2 with their rows
    k = rec.state("lock.back_door", "unlocked", T0 + 2.6, ctx=ctx(95), usr=USER)     # late for T0+2: 0.4 s
    r.poll(T0 + 5.0)                                          # first observed, in the keylog
    rec.sql("UPDATE states SET context_user_id_bin=NULL, context_parent_id_bin=? WHERE state_id=?", (ctx(10), k))
    r.polls(T0 + 10.0, T0 + 15.0)
    out = os.path.join(tmp, "restored.db")
    res = verify(tmp, r, escrow=True, restore_out=out)
    assert str(int(T0) + 2) in res["flagged_seconds"]
    rv = res["recovery"]
    assert rv["keylog_lines_verified"] >= 1 and rv["keylog_lines_rejected"] == 0
    (item,) = [x for x in rv["keylog"] if x.get("changed")]
    assert item["changed"][0]["key"] == "s:%d" % k
    assert item["changed"][0]["original"]["context_user_id_bin"] == USER.hex()
    rs = rv["restore"]
    assert rs["keylog_rows_restored"] == ["s:%d" % k] and rs["all_keylog_ranges_reproduced"] is True
    assert rs["all_roots_reproduced"] is True
    con = sqlite3.connect(out)
    assert con.execute("SELECT context_user_id_bin, context_parent_id_bin FROM states WHERE state_id=?",
                       (k,)).fetchone() == (USER, None)



# ================================================================================================ E8: A2 and A4
# A2: every record signed with an Ed25519 key that stays on the monitor host; the verifier checks each record against
# the published public key. A4: replies tagged by the anchor; an untagged or wrongly tagged reply is a failed append.
try:
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EdPriv
except ImportError:                          # the signature tests need the `cryptography` package
    _EdPriv = None
needs_crypto = pytest.mark.skipif(_EdPriv is None, reason="cryptography is not installed")


def _keypair(tmp, name):
    k = _EdPriv.generate()
    priv, pub = os.path.join(tmp, name + ".pem"), os.path.join(tmp, name + ".pub.pem")
    open(priv, "wb").write(k.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()))
    open(pub, "wb").write(k.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub, k


def _signed_run(tmp, rec):
    priv, pub, _k = _keypair(tmp, "monitor")
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_SIGN_KEY=priv)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.launder(sid, eid)
    r.poll(T0 + 15.0)
    return r, pub


@needs_crypto
def test_E8_signature_round_trip(tmp, rec):
    r, pub = _signed_run(tmp, rec)
    ps = r.anchor.payloads()
    assert all(p["sig_alg"] == "ed25519" and len(p["sig"]) == 128 and p["sig_fp"] == r.M.SIGN_FP for p in ps)
    # the HMAC'd body is the signed record itself: the signature covers it minus the "sig" field
    assert all(json.loads(b) == p for b, p in zip(r.anchor.bodies, ps))
    res = verify(tmp, r, sign_pubkey=pub)
    sg = res["signatures"]
    assert sg["checked"] and sg["signed_ok"] == len(ps) and sg["unsigned"] == 0
    assert sg["bad_signature"] == [] and sg["wrong_key"] == []
    assert res["flagged_seconds"] == [str(int(T0) + 1)]


@needs_crypto
def test_E8_a_record_altered_after_signing_is_reported_and_excluded(tmp, rec):
    """The anchor host rewrites record 1's root of T0+1 into the laundered state's root, so recomputation would pass:
    the published key exposes it, and the record is not used."""
    r, pub = _signed_run(tmp, rec)
    laundered = r.M.commit(r.M.load(rec.path))["second"][str(int(T0) + 1)]
    line = json.loads(r.anchor.lines[0])
    line["payload"]["sealed"]["second"][str(int(T0) + 1)] = laundered
    r.anchor.lines[0] = json.dumps(line, sort_keys=True)
    blind = verify(tmp, r)                                     # without the key the forgery verifies
    assert str(int(T0) + 1) not in blind["flagged_seconds"]
    res = verify(tmp, r, sign_pubkey=pub)
    assert res["signatures"]["bad_signature"] == [1] and res["signatures"]["excluded_from_verification"] == [1]


@needs_crypto
def test_E8_a_record_signed_by_another_key_is_reported(tmp, rec):
    r, pub = _signed_run(tmp, rec)
    _p, _q, other = _keypair(tmp, "other")
    line = json.loads(r.anchor.lines[1])
    p = line["payload"]
    p["sig_fp"] = hashlib.sha256(other.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)).hexdigest()
    p["sig"] = other.sign(r.M.record_signing_bytes(p)).hex()
    r.anchor.lines[1] = json.dumps(line, sort_keys=True)
    res = verify(tmp, r, sign_pubkey=pub)
    assert res["signatures"]["wrong_key"] == [2] and res["signatures"]["signed_ok"] == len(r.anchor.lines) - 1


@needs_crypto
def test_E8_unsigned_records_verify_as_before(tmp, rec):
    _priv, pub, _k = _keypair(tmp, "monitor")
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec)                                          # no signing key
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.launder(sid, eid)
    r.poll(T0 + 15.0)
    assert not any("sig" in p for p in r.anchor.payloads())
    plain = verify(tmp, r)
    legacy = verify(tmp, r, sign_pubkey=pub, allow_unsigned=True)      # chains written before signatures existed
    assert legacy["signatures"]["unsigned"] == 3 and legacy["flagged_seconds"] == plain["flagged_seconds"]
    assert plain["signatures"] == {"checked": False, "records_with_signature": 0}
    strict = verify(tmp, r, sign_pubkey=pub)                           # E8 review BE8: unsigned is not the monitor's
    assert strict["signatures"]["unsigned_excluded"] == [1, 2, 3] and strict["roots"] == {}


class TagServer:
    """A minimal anchor over HTTP: HMAC-authenticated appends, first-write-wins, and replies tagged (or not) as the
    mode says. "spoof": an untagged {"ok": true} without appending; "spoof_badtag": the same with a wrong tag;
    "spoof409": an untagged 409 naming a pending segment."""

    def __init__(self, key, M):
        import http.server
        import threading
        self.key, self.M, self.mode, self.lines, self.roots = key, M, "tagged", [], {}
        srv = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                return None

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                req_tag = self.headers.get("X-HP-Auth", "")
                assert hmac_ok(srv.key, body, req_tag)
                code, reply = 200, {"ok": True, "seq": 999}
                if srv.mode in ("tagged", "untagged"):
                    p = json.loads(body)
                    conflict = None
                    for g, segs in (p.get("sealed") or {}).items():
                        for k_, v in segs.items():
                            if srv.roots.get((g, k_), v["acc"]) != v["acc"]:
                                conflict = {"granularity": g, "segment": k_}
                    if conflict:
                        code, reply = 409, {"error": "conflict", "conflict": conflict}
                    else:
                        for g, segs in (p.get("sealed") or {}).items():
                            for k_, v in segs.items():
                                srv.roots[(g, k_)] = v["acc"]
                        srv.lines.append(json.dumps({"seq": len(srv.lines) + 1, "recv_ts": p.get("ts"),
                                                     "payload": p}, sort_keys=True))
                        reply = {"ok": True, "seq": len(srv.lines)}
                elif srv.mode == "tagged413":
                    code, reply = 413, {"error": "body too large"}
                elif srv.mode == "spoof409":
                    p = json.loads(body)
                    g, segs = next(iter((p.get("sealed") or {"second": {"0": {}}}).items()))
                    code, reply = 409, {"error": "conflict", "conflict": {"granularity": g, "segment": next(iter(segs))}}
                raw = json.dumps(reply).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if srv.mode in ("tagged", "tagged413"):
                    self.send_header("X-HP-Reply-Auth", hmac.new(srv.key, srv.M.reply_tag_message(req_tag, code, raw),
                                                                 hashlib.sha256).hexdigest())
                elif srv.mode == "spoof_badtag":
                    self.send_header("X-HP-Reply-Auth", "00" * 32)
                self.end_headers()
                self.wfile.write(raw)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def hmac_ok(key, body, tag):
    return hmac.compare_digest(hmac.new(key, body, hashlib.sha256).hexdigest(), tag)


import hmac  # noqa: E402


def _http_rig(tmp, rec, mode_env):
    key = b"e8-test-append-key"
    r = Rig(tmp, rec, real_append=True, HOMEPROV_ANCHOR_KEY=key.decode(), HOMEPROV_REPLY_TAGS=mode_env)
    srv = TagServer(key, r.M)
    r.M.ANCHOR = "http://127.0.0.1:%d/append" % srv.port
    r.anchor.lines = srv.lines                                 # verify() reads the server's chain
    return r, srv


@pytest.mark.parametrize("spoof", ["spoof", "spoof_badtag", "spoof409"])
def test_E8_a_spoofed_reply_is_a_failed_append_and_the_roots_are_resent(tmp, rec, spoof):
    history(rec, T0)
    r, srv = _http_rig(tmp, rec, "1")
    try:
        srv.mode = spoof
        out = r.poll(T0 + 5.0)                                 # the "ok" (or the 409) is not the anchor's answer
        assert not out["anchor"].get("ok") and out["anchor"]["err"].startswith("reply_tag_")
        assert out["pending"] == 3 and out["backlog"] == 1 and srv.lines == []
        assert not r.st.get("conflicted")                      # a forged 409 quarantines nothing
        srv.mode = "tagged"
        out = r.poll(T0 + 10.0)
        assert out["anchor"]["ok"] and out["pending"] == 0 and out["backlog"] == 0
        p = json.loads(srv.lines[0])["payload"]
        assert {v["seal_seq"] for v in p["sealed"]["second"].values()} == {1}
        res = verify(tmp, r)
        assert res["flagged_seconds"] == [] and res["stalls"][0]["kind"] == "anchor_unreachable"
    finally:
        srv.close()


def test_E8_auto_requires_tags_once_the_anchor_has_tagged_a_reply(tmp, rec):
    history(rec, T0)
    r, srv = _http_rig(tmp, rec, "auto")
    try:
        srv.mode = "tagged"
        assert r.poll(T0 + 5.0)["anchor"]["ok"] and r.st["reply_tags_seen"] is True
        srv.mode = "spoof"
        rec.state("sensor.power", "1", T0 + 6.5, ctx=ctx(40))
        out = r.poll(T0 + 10.0)
        assert out["anchor"]["err"] == "reply_tag_missing" and out["pending"] == 1
    finally:
        srv.close()


def test_E8_an_anchor_that_does_not_tag_replies_still_works_in_auto(tmp, rec):
    history(rec, T0)
    r, srv = _http_rig(tmp, rec, "auto")
    try:
        srv.mode = "untagged"
        r.polls(T0 + 5.0, T0 + 10.0)
        assert r.ticks[-1]["pending"] == 0 and len(srv.lines) == 2 and not r.st.get("reply_tags_seen")
    finally:
        srv.close()



def test_E8_reply_tag_bytes_match_the_anchor(tmp, rec):
    """The monitor's reply check uses the same bytes as the anchor's reply_tag() (testbed/anchord/anchord.py)."""
    spec = importlib.util.spec_from_file_location("anchord_e8_t", os.path.join(REPO, "testbed", "anchord", "anchord.py"))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    if not hasattr(A, "reply_tag"):
        pytest.skip("this anchor does not tag replies")
    M = monitor_module(os.path.join(HERE, "monitor.py"), os.path.join(tmp, "s"), rec.path, HOMEPROV_ANCHOR_KEY="k1")
    body, req = b'{"ok": true, "seq": 7}', "ab" * 32
    for status in (200, 409):
        assert A.reply_tag(b"k1", req, status, body) == hmac.new(b"k1", M.reply_tag_message(req, status, body),
                                                                hashlib.sha256).hexdigest()
        assert M._reply_check(req, status, body, A.reply_tag(b"k1", req, status, body)) == "ok"
        assert M._reply_check(req, 200 if status == 409 else 409, body, A.reply_tag(b"k1", req, status, body)) == "bad"



# ================================================================================================ E8 review (BE8, ME8, mE8a)
class SubstitutingAnchor(Anchor):
    """The anchor host (it holds the append key). For one poll it stores, instead of the monitor's signed record, an
    UNSIGNED record with the same fields whose roots and keylog are those of the recorder after a laundering the hub
    does later, and answers the monitor with an ok."""

    def __init__(self, target_seq, holder):
        super().__init__()
        self.target_seq, self.holder, self.launder_sql = target_seq, holder, []

    def append(self, rec_):
        if rec_.get("seq_local") != self.target_seq or "part" in rec_:
            return super().append(rec_)
        M = self.holder[0]
        lau = os.path.join(M.SCRATCH, "forger.db")
        shutil.copy2(os.path.join(M.SCRATCH, "recorder.db"), lau)
        con = sqlite3.connect(lau)
        for q, a in self.launder_sql:
            con.execute(q, a)
        con.commit()
        con.close()
        forged = {k: v for k, v in rec_.items() if k not in ("sig", "sig_alg", "sig_fp")}
        phi = M.commit(M.load(lau, since=rec_["since"]))
        forged["sealed"] = {g: {k: dict(v, **phi[g][k]) for k, v in d.items() if k in phi[g]}
                            for g, d in rec_["sealed"].items()}
        forged["keylog"] = {t: [M.keylog_entry(M.keylog_rows(lau, t, e["from"], e["to"]), e["from"], e["to"])
                                for e in es] for t, es in rec_["keylog"].items()}
        self.bodies.append(json.dumps(rec_, sort_keys=True).encode())
        return self.write(forged)


class DroppingAnchor(Anchor):
    """The anchor host answers ok but never stores one poll's record."""

    def __init__(self, drop_seq):
        super().__init__()
        self.drop_seq = drop_seq

    def append(self, rec_):
        if rec_.get("seq_local") == self.drop_seq:
            self.bodies.append(json.dumps(rec_, sort_keys=True).encode())
            return {"ok": True, "seq": len(self.lines) + 1}
        return super().append(rec_)


def _unlock_at(rec, t):
    rec.state("binary_sensor.motion", "on", t + 0.2, ctx=ctx(10))
    eid = rec.event("call_service", t + 0.30, ctx=ctx(1), usr=USER, data='{"domain":"lock","service":"unlock"}')
    sid = rec.state("lock.front_door", "unlocked", t + 0.31, ctx=ctx(1), usr=USER)
    return sid, eid


@needs_crypto
def test_BE8_an_unsigned_substitute_record_is_excluded_under_the_public_key(tmp, rec):
    """E8 review BE8: the anchor host stores an unsigned record of its own (roots of the laundered recorder) for poll 2.
    Under the published key only verified records are used: the substitute is listed and excluded, its poll is then a
    missing poll, and the seconds it covered are unknown, never read with the forged roots."""
    priv, pub, _k = _keypair(tmp, "monitor")
    history(rec, T0)
    holder = [None]
    a = SubstitutingAnchor(2, holder)
    r = Rig(tmp, rec, anchor=a, HOMEPROV_SIGN_KEY=priv)
    holder[0] = r.M
    r.poll(T0 + 5.0)
    sid, eid = _unlock_at(rec, T0 + 6)
    a.launder_sql = [("UPDATE states SET context_user_id_bin=NULL, context_parent_id_bin=? WHERE state_id=?",
                      (ctx(10), sid)), ("DELETE FROM events WHERE event_id=?", (eid,))]
    r.poll(T0 + 10.0)                                          # the host stores its unsigned substitute
    rec.launder(sid, eid)                                      # the hub launders the sealed unlock afterwards
    r.polls(T0 + 15.0, T0 + 25.0)
    res = verify(tmp, r, sign_pubkey=pub)
    sg = res["signatures"]
    assert sg["unsigned_excluded"] == [2] and 2 in sg["excluded_from_verification"]
    assert all(rt["chain_seq"] != 2 for rt in res["roots"].values())
    s6 = str(int(T0) + 6)
    assert s6 in {x["seg"] for x in res["root_unknown_segments"] if x["gran"] == "second"}
    assert any(st["kind"] == "polls_unrecorded" for st in res["stalls"]) and res["keylog"]["uncommitted_key_ranges"]


@needs_crypto
def test_ME8_a_dropped_record_leaves_its_seconds_unknown_not_attributable(tmp, rec):
    """E8 review ME8: the anchor host answers poll 2 with ok and never stores it. The recorder is untouched. The seconds
    poll 2 sealed are unknown and their benign rows are not attributed; the gap is reported."""
    priv, pub, _k = _keypair(tmp, "monitor")
    history(rec, T0)
    r = Rig(tmp, rec, anchor=DroppingAnchor(2), HOMEPROV_SIGN_KEY=priv)
    r.poll(T0 + 5.0)
    _unlock_at(rec, T0 + 6)
    r.polls(T0 + 10.0, T0 + 25.0)
    res = verify(tmp, r, sign_pubkey=pub)
    s6 = str(int(T0) + 6)
    assert res["flagged_seconds"] == [] and res["attributable_rows"] == []
    unk = [x for x in res["root_unknown_segments"] if x["seg"] == s6]
    assert unk and unk[0]["why"] == "a_poll_before_its_first_cover_is_missing_from_the_chain"
    assert any(st["kind"] == "polls_unrecorded" and st["polls_unrecorded"] == 1 for st in res["stalls"])


def test_mE8a_a_tagged_413_cannot_shrink_the_remembered_record_size_below_the_floor(tmp, rec):
    """E8 review mE8a: a validly tagged 413 for the monitor's own request tag can be obtained by a host without the key.
    It shrinks the record size for the current poll only; what the monitor remembers stays at or above the floor."""
    history(rec, T0)
    r, srv = _http_rig(tmp, rec, "1")
    try:
        srv.mode = "tagged413"
        r.polls(T0 + 5.0, T0 + 20.0)
        assert all(t["anchor"].get("http") == 413 for t in r.ticks)
        assert r.st["max_bytes"] == 64 * 1024                 # the floor (REMEMBERED_RECORD_BYTES_FLOOR)
        srv.mode = "tagged"
        out = r.poll(T0 + 25.0)
        assert out["anchor"]["ok"] and out["pending"] == 0 and out["backlog"] == 0
    finally:
        srv.close()
