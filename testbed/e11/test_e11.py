"""E11 static tests with fake data (no Docker, no openHAB): the openHAB reader plugged into the shipped monitor.py, the
scorer's verification rule, the plan, the interpreter guard.

    <home>/miniconda3/bin/python3 -m pytest -q -p no:cacheprovider testbed/e11/test_e11.py

The synthetic database has the shape the JDBC SQLite DAO of openHAB 5.2.3 creates (index table `items` with ItemId
INTEGER PRIMARY KEY AUTOINCREMENT and ItemName; per-item tables itemNNNN with time TIMESTAMP NOT NULL, value,
PRIMARY KEY(time); times as 'YYYY-MM-DD HH:MM:SS.mmm' text). The registry files have the layout of openHAB's JSON
database as assumed by the reader (checked in the smoke run before registration)."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
T = 1792800000                                    # a whole second (2026-10-24T...Z), the synthetic hour


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def env():
    d = tempfile.mkdtemp(prefix="e11t_")
    os.environ.update({"HOMEPROV_SCHEME": "closure", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "0",
                       "HOMEPROV_READ": "copy", "HOMEPROV_SCRATCH": os.path.join(d, "scratch"),
                       "HOMEPROV_DB": os.path.join(d, "hub", "openhab.db"), "HOMEPROV_MONITOR_DIR": os.path.join(REPO, "monitor"),
                       "HP_OH_JSONDB": os.path.join(d, "hub", "jsondb"), "HOMEPROV_ANCHOR": "http://127.0.0.1:9/append"})
    for k in ("HP_OH_ARCHIVE", "HOMEPROV_SINCE", "HOMEPROV_ESCROW_DIR", "HOMEPROV_NAMEMAP_DIR", "HOMEPROV_SIGN_KEY"):
        os.environ.pop(k, None)
    os.makedirs(os.path.join(d, "scratch"))
    os.makedirs(os.path.join(d, "hub", "jsondb"))
    sys.modules.pop("monitor", None)
    A = _load(os.path.join(HERE, "monitor", "oh_monitor.py"), "oh_monitor_test")
    S = _load(os.path.join(REPO, "exp", "stages", "e11_score.py"), "e11_score_test")
    yield {"dir": d, "A": A, "S": S}
    shutil.rmtree(d, ignore_errors=True)


def ts_text(t):
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(t))) + ".%03d" % int(round((t % 1) * 1000))


def make_db(path, rows):
    """rows: {item_name: (item_id, [(t, value), ...])}; rollback-journal mode, as the DAO leaves it."""
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS items (ItemId INTEGER PRIMARY KEY AUTOINCREMENT, ItemName VARCHAR(500) NOT NULL)")
    for name, (iid, pts) in rows.items():
        con.execute("INSERT INTO items (ItemId, ItemName) VALUES (?, ?)", (iid, name))
        t = "item%04d" % iid
        con.execute('CREATE TABLE IF NOT EXISTS %s (time TIMESTAMP NOT NULL, value VARCHAR(6), PRIMARY KEY(time))' % t)
        for ts, v in pts:
            con.execute("INSERT OR IGNORE INTO %s (TIME, VALUE) VALUES (?, CAST(? AS VARCHAR(6)))" % t, (ts_text(ts), v))
    con.commit()
    con.close()


def make_registry(d, types, units=None, labels=None):
    items = {n: {"class": "org.openhab.core.items.ManagedItemProvider$PersistedItem",
                 "value": {"groupNames": [], "itemType": t, "tags": [], "label": (labels or {}).get(n, n)}}
             for n, t in types.items()}
    meta = {"unit:%s" % n: {"class": "org.openhab.core.items.Metadata",
                            "value": {"key": {"segments": ["unit", n], "namespace": "unit", "itemName": n},
                                      "value": u, "configuration": {}}} for n, u in (units or {}).items()}
    json.dump(items, open(os.path.join(d, "org.openhab.core.items.Item.json"), "w"))
    json.dump(meta, open(os.path.join(d, "org.openhab.core.items.Metadata.json"), "w"))


BASE = {"FrontDoor_Lock": (1, [(T + 0.100, "ON"), (T + 3.250, "OFF"), (T + 7.500, "ON")]),
        "Kitchen_Temp": (2, [(T + 0.500, "21.5"), (T + 3.700, "21.6")])}
TYPES = {"FrontDoor_Lock": "Switch", "Kitchen_Temp": "Number:Temperature", "Label_Probe": "Switch"}


def setup_hub(env, rows=None, types=None, units=None, labels=None, orphan=False):
    d = env["dir"]
    db = os.path.join(d, "hub", "openhab.db")
    make_db(db, rows or BASE)
    if orphan:
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE item0099 (time TIMESTAMP NOT NULL, value VARCHAR(6), PRIMARY KEY(time))")
        con.execute("INSERT INTO item0099 VALUES (?, 'X')", (ts_text(T + 1.5),))
        con.commit()
        con.close()
    make_registry(os.path.join(d, "hub", "jsondb"), types or TYPES, units if units is not None else {"Kitchen_Temp": "°C"},
                  labels)
    return db


def roots(env, scheme, db=None, jsondb=None):
    A = env["A"]
    db = db or os.path.join(env["dir"], "hub", "openhab.db")
    con = sqlite3.connect(db)
    data = A.read_rows(con, jsondb=jsondb or os.path.join(env["dir"], "hub", "jsondb"))
    con.close()
    return A.M.commit(A.nodes_from_rows(scheme, data))["second"]


# ------------------------------------------------------------------------------------------------- the reader
def test_names_and_times(env):
    A = env["A"]
    assert A.table_for(1, "X") == "item0001" and A.table_for(1234, "X") == "item1234"
    assert A.parse_time("2026-10-24 00:00:00.250") == pytest.approx(T + 0.25)
    assert A.parse_time("2026-10-24 00:00:00") == T
    assert A.parse_time("2026-10-24T00:00:00.250") is None and A.parse_time(12345) is None
    assert A.time_text(T) == ts_text(T)[:19]


def test_refusals_default_env(env):
    assert env["A"].refusals() == []


def test_closure_nodes_and_join(env):
    A = env["A"]
    setup_hub(env, orphan=True)
    con = sqlite3.connect(os.path.join(env["dir"], "hub", "openhab.db"))
    data = A.read_rows(con)
    con.close()
    clo = A.nodes_from_rows("closure", data)
    rows = A.nodes_from_rows("rows", data)
    assert len(clo) == 5 and len(rows) == 6           # the orphan table is not rendered, so not in the closure
    assert all(len(n) == 9 for n in clo) and all(len(n) == 6 for n in rows)
    assert clo[0][1] == "o:item0001:%s" % ts_text(T + 0.100)


@pytest.mark.parametrize("write, closure, rows, wholerow", [
    ("value", True, True, True), ("time", True, True, True), ("rowid", False, True, True),
    ("itemname", True, False, True), ("itemid", True, False, True), ("type", True, False, True),
    ("unit", True, False, True), ("label", False, False, True), ("delete_entry", True, False, True)])
def test_single_write_directions(env, write, closure, rows, wholerow):
    """The two failure directions in miniature: `rows` (schema-chosen) misses the index and registry fields the
    renderer reads; `wholerow` also changes on fields the renderer does not read (rowid, label)."""
    base_db = setup_hub(env, labels={"FrontDoor_Lock": "Front door"})
    base = {s: roots(env, s) for s in ("closure", "rows", "wholerow")}
    con = sqlite3.connect(base_db)
    jd = os.path.join(env["dir"], "hub", "jsondb")
    if write == "value":
        con.execute("UPDATE item0001 SET value='ON' WHERE value='OFF'")
    elif write == "time":
        con.execute("UPDATE item0001 SET time=? WHERE value='OFF'", (ts_text(T + 4.250),))
    elif write == "rowid":
        con.execute("UPDATE item0001 SET rowid=100 WHERE value='OFF'")
    elif write == "itemname":
        con.execute("UPDATE items SET ItemName='FrontDoor_Lock_x' WHERE ItemId=1")
    elif write == "itemid":
        con.execute("UPDATE items SET ItemId=7 WHERE ItemId=1")
    else:
        types, units, labels = dict(TYPES), {"Kitchen_Temp": "°C"}, {"FrontDoor_Lock": "Front door"}
        if write == "type":
            types["FrontDoor_Lock"] = "Contact"
        elif write == "unit":
            units["Kitchen_Temp"] = "°F"
        elif write == "label":
            labels["FrontDoor_Lock"] = "Front door x"
        else:
            types.pop("FrontDoor_Lock")
        make_registry(jd, types, units, labels)
    con.commit()
    con.close()
    got = {s: roots(env, s) for s in ("closure", "rows", "wholerow")}
    assert (got["closure"] != base["closure"]) is closure
    assert (got["rows"] != base["rows"]) is rows
    assert (got["wholerow"] != base["wholerow"]) is wholerow


def test_watermark_check_connection_snapshot(env):
    A = env["A"]
    db = setup_hub(env)
    assert A.watermark(db) == {"items": 2, "item0001": 3, "item0002": 2}
    con = sqlite3.connect(db)
    assert A.check_connection(con, True) is None
    con.close()
    copy = A.snapshot()                                 # backup API from a read-only connection on the "hub" file
    assert A.validate_copy(copy, True) == (True, "ok", {})
    assert roots(env, "closure", db=copy) == roots(env, "closure")
    os.rename(db, db + ".gone")
    A.snapshot()
    ok, reason, _d = A.validate_copy(os.path.join(env["dir"], "scratch", "recorder.db"), True)
    assert not ok and reason == "snapshot_failed"
    os.rename(db + ".gone", db)


def test_object_check_view(env):
    A = env["A"]
    db = setup_hub(env)
    con = sqlite3.connect(db)
    con.execute("ALTER TABLE item0002 RENAME TO real2")
    con.execute("CREATE VIEW item0002 AS SELECT * FROM real2")
    con.commit()
    bad = A.check_objects_oh(con)
    con.close()
    assert bad and bad[1] == "schema_object_not_a_table" and "item0002" in bad[2]["objects"]


def test_tick_end_to_end_with_shipped_monitor(env, monkeypatch):
    """The shipped tick_coverage() with the replaced read path: records carry the per-table watermark and seal."""
    A = env["A"]
    M = A.M
    import time as _t
    now = _t.time()
    rows = {"FrontDoor_Lock": (1, [(now - 40.2, "ON"), (now - 20.6, "OFF")]), "Kitchen_Temp": (2, [(now - 30.3, "21.5")])}
    setup_hub(env, rows=rows)
    sent = []
    monkeypatch.setattr(M, "append", lambda rec: (sent.append(rec), {"ok": True, "seq": len(sent)})[1])
    monkeypatch.setattr(M, "save_state", lambda st: None)
    st = {}
    out = M.tick(st)
    assert not out.get("evidence_unobservable"), out
    rec = sent[0]
    assert rec["wm"] == {"items": 2, "item0001": 2, "item0002": 1}
    assert rec["scheme"] == "closure" and rec["sealed"]["second"]
    assert sum(v["n"] for v in rec["sealed"]["second"].values()) == 3


# ----------------------------------------------------------------------------------------- the verification rule
def _pairs(env, db, scheme="closure"):
    A = env["A"]
    con = sqlite3.connect(db)
    data = A.read_rows(con, jsondb=os.path.join(env["dir"], "hub", "jsondb"))
    con.close()
    return A.nodes_from_rows(scheme, data, with_meta=True)


def _sealed(env, db, scheme="closure"):
    """Roots as the poll sealing at T+8.5 (copy at T+8.4) froze them: seconds T..T+7."""
    S = env["S"]
    pairs = _pairs(env, db, scheme)
    phi = env["A"].M.commit([n for n, _m in pairs])["second"]
    wm = env["A"].watermark(db)
    roots = {("second", k): dict(v, seal_seq=1, seal_ts=T + 8.5, wm=wm) for k, v in phi.items() if int(k) < T + 8}
    polls = {1: {"seq": 1, "ts": T + 8.5, "copy_at": T + 8.4, "wm": wm, "since": T - 3600, "through": T + 8,
                 "observable": True, "reason": None},
             2: {"seq": 2, "ts": T + 140.5, "copy_at": T + 140.4, "wm": dict(wm), "since": T - 3600, "through": T + 140,
                 "observable": True, "reason": None}}
    return roots, polls, S.Coverage(polls)


def _verdict(env, roots, cov, db, k, scheme="closure"):
    S = env["S"]
    return S.verify(env["A"].M, cov, roots, S.by_seg(_pairs(env, db, scheme), 1), "second", 1, k)


def test_rule_unchanged_removed_changed(env):
    db = setup_hub(env)
    roots, _polls, cov = _sealed(env, db)
    assert _verdict(env, roots, cov, db, T + 3)["class"] == "ok"
    con = sqlite3.connect(db)
    con.execute("DELETE FROM item0001 WHERE value='OFF'")                     # A-RM shape
    con.commit()
    con.close()
    v = _verdict(env, roots, cov, db, T + 3)
    assert v["class"] == "attributable" and v["why"] == "sealed_row_removed_or_changed"


def test_rule_change_by_remove_and_reinsert(env):
    db = setup_hub(env)
    roots, _p, cov = _sealed(env, db)
    con = sqlite3.connect(db)
    tt = con.execute("SELECT time FROM item0001 WHERE value='OFF'").fetchone()[0]
    con.execute("DELETE FROM item0001 WHERE time=?", (tt,))                   # A-CHG shape (remove, persist)
    con.execute("INSERT INTO item0001 (time, value) VALUES (?, 'ON')", (tt,))
    con.commit()
    con.close()
    assert _verdict(env, roots, cov, db, T + 3)["class"] == "attributable"


def test_rule_backdated_insert_and_benign_late(env):
    db = setup_hub(env)
    roots, polls, cov = _sealed(env, db)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO item0001 (time, value) VALUES (?, 'OFF')", (ts_text(T + 0.800),))   # A-BD shape
    con.commit()
    con.close()
    v = _verdict(env, roots, cov, db, T)
    assert v["class"] == "attributable" and v["why"] == "late_rows_after_seal" and v["late"][0]["lag_s"] > 30
    # the same row, but seen by the poll right after the sealing one: committed within the late bound
    polls2 = dict(polls)
    polls2[2] = dict(polls[2], copy_at=T + 9.9, ts=T + 10.0, through=T + 9,
                     wm=dict(polls[2]["wm"], item0001=polls[2]["wm"]["item0001"] + 1))
    cov2 = env["S"].Coverage(polls2)
    assert _verdict(env, roots, cov2, db, T)["class"] == "benign_late"


def test_rule_insert_into_sealed_empty_second(env):
    db = setup_hub(env)
    roots, _p, cov = _sealed(env, db)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO item0001 (time, value) VALUES (?, 'OFF')", (ts_text(T + 5.400),))  # second T+5 held no row
    con.commit()
    con.close()
    v = _verdict(env, roots, cov, db, T + 5)
    assert v["class"] == "attributable" and v["why"] == "rows_in_a_second_sealed_empty"


def test_rule_replace_same_values(env):
    """B-REPLACE-SAME: a past point removed and stored again with the same time and value (new rowid): no violation
    under the closure (the renderer reads no rowid), a violation under `rows` (which commits the rowid)."""
    db = setup_hub(env)
    r_clo, _p, cov = _sealed(env, db, "closure")
    r_rows, _p2, _c2 = _sealed(env, db, "rows")
    con = sqlite3.connect(db)
    tt, vv = con.execute("SELECT time, value FROM item0002 ORDER BY time LIMIT 1").fetchone()
    con.execute("DELETE FROM item0002 WHERE time=?", (tt,))
    con.execute("INSERT INTO item0002 (time, value) VALUES (?, ?)", (tt, vv))
    con.commit()
    con.close()
    assert _verdict(env, r_clo, cov, db, T)["class"] == "ok"
    assert _verdict(env, r_rows, cov, db, T, "rows")["class"] == "attributable"


def test_parse_chain_and_cover(env):
    S = env["S"]
    lines = [json.dumps({"seq": 1, "payload": {"observer": "external-monitor", "seq_local": 1, "ts": T + 2.1, "copy_at": T + 2.0,
                                               "wm": {"item0001": 3}, "since": T - 3600, "through": T + 2,
                                               "sealed": {"second": {str(T): {"acc": "aa", "n": 1}}}}}),
             json.dumps({"seq": 2, "payload": {"observer": "external-monitor", "seq_local": 2, "ts": T + 7.1,
                                               "evidence_unobservable": True, "reason": "snapshot_failed",
                                               "sealed": {"second": {str(T + 1): {"acc": "bb", "n": 2, "sealed_at": T + 2.1,
                                                                                  "seal_seq": 1, "wm": {"item0001": 3}}}}}})]
    polls, roots = S.parse_chain(lines)
    assert polls[1]["observable"] and not polls[2]["observable"] and polls[2]["reason"] == "snapshot_failed"
    assert roots[("second", str(T + 1))]["seal_seq"] == 1
    cov = S.Coverage(polls)
    assert cov.first_cover(T + 1, 1)["seq"] == 1 and cov.first_cover(T + 2, 1) is None


# ------------------------------------------------------------------------------------------- plan and guard
def test_plan_deterministic():
    ops = _load(os.path.join(HERE, "e11ops.py"), "e11ops_test")
    a, b = ops.make_plan(20261021), ops.make_plan(20261021)
    assert a == b and sorted(x["arm"] for x in a["arms"]) == ["A-BD", "A-CHG", "A-RM"]
    assert all(x["n"] == 30 for x in a["arms"]) and all(x["n"] == 3 for x in ops.make_plan(20261021, smoke=True)["arms"])
    bd = next(x for x in a["arms"] if x["arm"] == "A-BD")
    assert len(bd["mark_ms_offsets"]) == 30 and all(0 <= m < 1000 for m in bd["mark_ms_offsets"])
    assert ops.ms_text(1792800000250) == "2026-10-24 00:00:00.250"


def test_pyguard():
    ops = os.path.join(HERE, "e11ops.py")
    r = subprocess.run([sys.executable, ops, "pyguard", "--expect", sys.executable], capture_output=True, text=True)
    want_ok = sys.version_info >= (3, 12)
    assert json.loads(r.stdout.strip().splitlines()[-1])["ok"] is want_ok
    r = subprocess.run([sys.executable, ops, "pyguard", "--expect", "/usr/bin/python3"], capture_output=True, text=True)
    assert json.loads(r.stdout.strip().splitlines()[-1])["ok"] is False


HARDENED_PROBE = r"""
import json, os, sqlite3, sys, time, importlib.util
tree, reader = sys.argv[1], sys.argv[2]
d = os.path.join(tree, "run")
os.makedirs(os.path.join(d, "scratch")); os.makedirs(os.path.join(d, "jsondb"))
os.environ.update({"HOMEPROV_SCHEME": "closure", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "0", "HOMEPROV_READ": "copy",
                   "HOMEPROV_SCRATCH": os.path.join(d, "scratch"), "HOMEPROV_DB": os.path.join(d, "openhab.db"),
                   "HOMEPROV_MONITOR_DIR": os.path.join(tree, "monitor"), "HP_OH_JSONDB": os.path.join(d, "jsondb")})
db = os.path.join(d, "openhab.db")
con = sqlite3.connect(db)
con.execute("CREATE TABLE items (ItemId INTEGER PRIMARY KEY AUTOINCREMENT, ItemName VARCHAR(500) NOT NULL)")
con.execute("INSERT INTO items VALUES (1, 'FrontDoor_Lock')")
con.execute("CREATE TABLE item0001 (time TIMESTAMP NOT NULL, value VARCHAR(6), PRIMARY KEY(time))")
now = time.time()
for dt, v in ((40.2, "ON"), (20.6, "OFF")):
    con.execute("INSERT INTO item0001 VALUES (?, ?)", (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now - dt)) + ".123", v))
con.commit(); con.close()
json.dump({"FrontDoor_Lock": {"value": {"itemType": "Switch"}}}, open(os.path.join(d, "jsondb", "org.openhab.core.items.Item.json"), "w"))
spec = importlib.util.spec_from_file_location("ohm", reader); A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
M = A.M
sent = []
M.append = lambda rec: (sent.append(rec), {"ok": True, "seq": len(sent)})[1]
M.save_state = lambda st: None
out = M.tick({})
print(json.dumps({"harden": getattr(M, "HARDEN", None), "qc": getattr(M, "_QC", None), "unobservable": out.get("evidence_unobservable"),
                  "reason": out.get("reason"), "wm": sent[0].get("wm"), "n_sealed": sum(v["n"] for v in sent[0]["sealed"]["second"].values()),
                  "refusals": A.refusals()}))
"""


def test_reader_with_e10_hardened_monitor(tmp_path):
    """The reader plugs into the E10-hardened monitor.py as well (monitor/hardening_e10.patch applied to a COPY)."""
    tree = tmp_path / "tree"
    for rel in ("monitor/monitor.py", "exp/stages/e7_verify.py"):
        (tree / os.path.dirname(rel)).mkdir(parents=True, exist_ok=True)
        shutil.copy2(os.path.join(REPO, rel), tree / rel)
    # Since E10 the working tree carries the hardening already. Apply the patch only to an unhardened copy: macOS's patch,
    # without a terminal, silently REVERSES an already-applied patch ("Assume -R? [y]") and exits 0 (found 2026-10-23).
    if "HOMEPROV_HARDEN" not in (tree / "monitor" / "monitor.py").read_text():
        r = subprocess.run(["patch", "-s", "-p1", "-i", os.path.join(REPO, "monitor", "hardening_e10.patch")], cwd=tree,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        assert r.returncode == 0, r.stderr
    assert "HOMEPROV_HARDEN" in (tree / "monitor" / "monitor.py").read_text()
    r = subprocess.run([sys.executable, "-c", HARDENED_PROBE, str(tree), os.path.join(HERE, "monitor", "oh_monitor.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["harden"] is True and out["qc"]["first"] is False and out["qc"]["latched"] is False
    assert not out["unobservable"], out
    assert out["wm"] == {"items": 1, "item0001": 2} and out["n_sealed"] == 2 and out["refusals"] == []


# ----------------------------------------------------------------------------------------- scorer pieces end to end
def test_scorer_single_writes(env, tmp_path):
    S = env["S"]
    rows = {"FrontDoor_Lock": (1, [(T + 0.100, "ON"), (T + 3.250, "OFF")]), "Kitchen_Temp": (2, [(T + 0.500, "21.5")]),
            "Label_Probe": (3, [(T + 5.5, "ON")])}
    db = str(tmp_path / "final.db")
    make_db(db, rows)
    jd = tmp_path / "jsondb_final"
    jd.mkdir()
    make_registry(str(jd), TYPES, {"Kitchen_Temp": "°C"})
    res = {r["write"]: r["segments_changed"] for r in S.single_writes(env["A"], db, str(jd), T, T + 10)}
    assert res["<table>.value"]["closure"] == 1 and res["<table>.value"]["rows"] == 1
    assert res["<table>.rowid"] == {"closure": 0, "rows": 1, "wholerow": 1}
    for w in ("items.ItemName", "items.ItemId", "registry.itemType", "registry (item entry) deleted"):
        assert res[w]["closure"] == 2 and res[w]["rows"] == 0 and res[w]["wholerow"] == 2, w
    assert res["registry.meta.unit"] == {"closure": 1, "rows": 0, "wholerow": 1}
    assert res["registry.label"] == {"closure": 0, "rows": 0, "wholerow": 1}


def test_scorer_arm_floor_and_closure_summary(env, tmp_path):
    S = env["S"]
    rep = {"trials": [{"trial": 0, "row_ts": T + 3.25, "target": {"time_ms": (T + 3) * 1000 + 250},
                       "instrument_effect_rendered_all_roles": True, "same_render_for_every_role": True,
                       "edit_delay_s": 131.0, "edit": {"api_calls": 1},
                       "per_role": {"owner": {"other_points_unchanged": True}, "member": {"other_points_unchanged": True}}},
                      {"trial": 1, "err": "no persisted unlock row within 20 s"}]}
    verd = {s: {"second": {T + 3: {"class": "attributable"}, T + 9: {"class": "ok", "root_n": 1, "rows_now": 1}},
                "minute": {T // 60: {"class": "attributable"}}} for s in S.SCHEMES}
    r = S.score_arm("A-RM", rep, verd)
    assert r["n_valid"] == 1 and r["detection"]["closure"]["second"]["k"] == 1 and r["failures"]
    f = S.floor(verd, {T + 3}, {T // 60})
    assert f["closure"]["second"]["untouched_anchored"]["k"] == 0 and f["closure"]["second"]["untouched_anchored"]["n"] == 1
    clo = {"predicted_closure": ["<table>.value", "items.ItemName"], "fixtures": [{
        "item": "Fx_Switch", "determinism_control_equal": True, "same_render_for_every_role": True,
        "positive_control_value_change_changed_render": True, "dto_top_level_keys": ["data", "datapoints", "name", "unit"],
        "dto_point_keys": ["state", "time"], "mutations": [
            {"field": "<table>.value", "rendered_output_changed": True, "restore_equal_to_baseline": True},
            {"field": "<table>.rowid", "rendered_output_changed": False, "restore_equal_to_baseline": True},
            {"field": "items.ItemName", "rendered_output_changed": True, "restore_equal_to_baseline": True,
             "immediately": {"rendered_output_changed": False}}]}]}
    p = tmp_path / "clo.json"
    p.write_text(json.dumps(clo))
    s = S.closure_summary(str(p))
    assert s["fields_changing_rendered_history"] == ["<table>.value", "items.ItemName"]
    assert s["fields_changing_only_after_index_reload"] == ["items.ItemName"]
    assert s["attribution_field_in_rendered_history"] is False and s["predicted_minus_measured"] == []


SCORER_E2E = r"""
import json, os, shutil, sqlite3, subprocess, sys, time, importlib.util
repo, reader, root = sys.argv[1], sys.argv[2], sys.argv[3]
run, out = os.path.join(root, "run"), os.path.join(root, "out")
for d in ("scratch", "hub/jsondb", "run/code", "run/snapshots/jsondb_final", "run/logs", "out"):
    os.makedirs(os.path.join(root, d), exist_ok=True)
hub = os.path.join(root, "hub", "openhab.db")
os.environ.update({"HOMEPROV_SCHEME": "closure", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "0", "HOMEPROV_READ": "copy",
                   "HOMEPROV_SCRATCH": os.path.join(root, "scratch"), "HOMEPROV_DB": hub,
                   "HOMEPROV_MONITOR_DIR": os.path.join(repo, "monitor"), "HP_OH_JSONDB": os.path.join(root, "hub", "jsondb"),
                   "HP_OH_ARCHIVE": os.path.join(run, "archive.jsonl"), "HOMEPROV_COST_LOG": os.path.join(run, "cost.jsonl")})
now = time.time()
txt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(t))) + ".%03d" % int((t % 1) * 1000)
con = sqlite3.connect(hub)
con.execute("CREATE TABLE items (ItemId INTEGER PRIMARY KEY AUTOINCREMENT, ItemName VARCHAR(500) NOT NULL)")
con.execute("INSERT INTO items VALUES (1, 'FrontDoor_Lock')"); con.execute("INSERT INTO items VALUES (2, 'Kitchen_Temp')")
for t in ("item0001", "item0002"):
    con.execute("CREATE TABLE %s (time TIMESTAMP NOT NULL, value VARCHAR(6), PRIMARY KEY(time))" % t)
target = int(now) - 100 + 0.25
for dt in range(150, 40, -7):
    con.execute("INSERT INTO item0002 VALUES (?, ?)", (txt(int(now) - dt + 0.5), str(20 + dt / 100)))
con.execute("INSERT INTO item0001 VALUES (?, 'ON')", (txt(target - 3),))
con.execute("INSERT INTO item0001 VALUES (?, 'OFF')", (txt(target),))
con.commit(); con.close()
json.dump({"FrontDoor_Lock": {"value": {"itemType": "Switch"}}, "Kitchen_Temp": {"value": {"itemType": "Number:Temperature"}}},
          open(os.path.join(root, "hub", "jsondb", "org.openhab.core.items.Item.json"), "w"))
spec = importlib.util.spec_from_file_location("ohm", reader); A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
recs = []
A.M.append = lambda rec: (recs.append(rec), {"ok": True, "seq": len(recs)})[1]
A.M.save_state = lambda st: None
A.M.tick({})
with open(os.path.join(run, "chain.jsonl"), "w") as fh:
    for i, r in enumerate(recs, 1):
        fh.write(json.dumps({"seq": i, "recv_ts": now, "payload": r}) + "\n")
con = sqlite3.connect(hub); con.execute("DELETE FROM item0001 WHERE value='OFF'"); con.commit(); con.close()   # A-RM shape
shutil.copy2(hub, os.path.join(run, "snapshots", "final.db"))
shutil.copy2(os.path.join(root, "hub", "jsondb", "org.openhab.core.items.Item.json"), os.path.join(run, "snapshots", "jsondb_final"))
open(os.path.join(run, "t_start"), "w").write(repr(now - 160)); open(os.path.join(run, "t_end"), "w").write(repr(now - 30))
for f in ("monitor/monitor.py",):
    shutil.copy2(os.path.join(repo, f), os.path.join(run, "code", "monitor.py"))
shutil.copy2(reader, os.path.join(run, "code", "oh_monitor.py"))
tms = int(round(target * 1000))
rep = {"trials": [{"arm": "A-RM", "trial": 0, "target": {"time_ms": tms}, "row_ts": tms / 1000.0, "edit_delay_s": 130.0,
                   "edit": {"api_calls": 1, "ok": True}, "instrument_effect_rendered_all_roles": True,
                   "same_render_for_every_role": True,
                   "per_role": {"owner": {"other_points_unchanged": True}, "member": {"other_points_unchanged": True}}}]}
json.dump(rep, open(os.path.join(out, "t_report_A-RM.json"), "w"))
for k in [k for k in os.environ if k.startswith(("HOMEPROV_", "HP_OH_"))]:
    os.environ.pop(k)
r = subprocess.run([sys.executable, os.path.join(repo, "exp", "stages", "e11_score.py"), "--run", run, "--tag", "t",
                    "--outdir", out], capture_output=True, text=True)
print(r.stdout[-1500:]); print(r.stderr[-3000:], file=sys.stderr)
sys.exit(r.returncode)
"""


def test_scorer_main_end_to_end(tmp_path):
    """The scorer's main() on a synthetic run: one shipped-monitor poll sealed the rows, one sealed row was then removed
    (A-RM shape); the trial is detected, the offline schemes are reconstructed from the archive, the floor is 0."""
    r = subprocess.run([sys.executable, "-c", SCORER_E2E, REPO, os.path.join(HERE, "monitor", "oh_monitor.py"), str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-3000:]
    res = json.load(open(tmp_path / "out" / "t_score.json"))
    det = res["O3_detection"]["A-RM"]["detection"]
    assert det["closure"]["second"]["k"] == 1 and det["rows"]["second"]["k"] == 1 and det["wholerow"]["second"]["k"] == 1
    assert det["closure"]["minute"]["k"] == 1
    assert res["offline_reconstruction"]["records"].get("records_matched", 0) >= 1
    fl = res["O4_floor"]["closure"]["second"]["untouched_anchored"]
    assert fl["k"] == 0 and fl["n"] >= 10
    assert res["O2_single_writes"] and res["polls"]["observable"] == 1
