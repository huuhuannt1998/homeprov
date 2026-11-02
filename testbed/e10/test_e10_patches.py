"""E10 (round 14): tests for the two patches that land after E9 (2026-10-19 16:01Z), against a tree that has them.

    <home>/miniconda3/bin/python3 -m pytest -q testbed/e10/test_e10_patches.py

The patches (drafts/round13/E10_DESIGN.md section 5):
  monitor/hardening_e10.patch     SQLite hardening of the monitor and the verifier (internal review r4 R1 W4; SQLite's
                                  untrusted-file guidance, drafts/round13/r4_sources.md section 9): trusted_schema=OFF,
                                  cell_size_check=ON, mmap_size=0, views/triggers off and DEFENSIVE on where Python
                                  exposes sqlite3_db_config, quick_check as the first statement that reads the file, the
                                  object-type check of the recorder tables; HOMEPROV_HARDEN=0 / --no-harden for the
                                  earlier behaviour.
  exp/stages/verifier_e10.patch   applied after it: verifier fixes D1-D5 of drafts/round13/FORMAL_DRAFT.md section 6 (D1
                                  observation breaks in the late-row bracket; D2 empty segments first covered by an
                                  incomplete poll are root_unknown; D3 a CLOCK_STEP rule; D4 RESTORE_DONE needs the hub's
                                  start; D5 the straddling segment excuses removed rows and valid disconnects only), and
                                  the one expectation of monitor/test_e9.py that D4 changes.

Which tree is tested: E10_TREE if set; else the repository itself when both patches are already applied (the
markers HOMEPROV_HARDEN in monitor.py and ObservationBreaks in e7_verify.py); else a temporary copy of the repository's
monitor/, exp/stages/ and exp/rig/ with both patches applied by `patch -p1` (exp/out, testbed and reproduce linked).
The unpatched repository files (until the lead applies the patches) serve as the "before" side of the comparisons; once
the patches are applied, monitor/monitor_e9.py (the E9 monitor kept byte for byte, as monitor_e8.py was) does. No
Docker, no network; each test runs in seconds on synthetic recorders.
"""
from __future__ import annotations

import hashlib
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
PATCHES = (os.path.join(REPO, "monitor", "hardening_e10.patch"), os.path.join(REPO, "exp", "stages", "verifier_e10.patch"))
E9_MONITOR_SHA256 = "8ad9e2d77f2d098af1e81ed509445631dc3d3ba2d349fddff75bfd920a7ab8ae"
E9_VERIFIER_SHA256 = "9c42fad983a00e43083359339bc185c11d31ab7cdec7781f0e2cdee94ebea885"


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def _applied(root):
    try:
        return ("HOMEPROV_HARDEN" in open(os.path.join(root, "monitor", "monitor.py")).read()
                and "class ObservationBreaks" in open(os.path.join(root, "exp", "stages", "e7_verify.py")).read())
    except OSError:
        return False


def build_tree():
    if os.environ.get("E10_TREE"):
        return os.environ["E10_TREE"], "E10_TREE"
    if _applied(REPO):
        return REPO, "repository (patches applied)"
    t = tempfile.mkdtemp(prefix="e10tree_")
    for sub in ("monitor", os.path.join("exp", "stages"), os.path.join("exp", "rig")):
        os.makedirs(os.path.join(t, sub), exist_ok=True)
        for f in os.listdir(os.path.join(REPO, sub)):
            if f.endswith((".py", ".txt")):
                shutil.copy2(os.path.join(REPO, sub, f), os.path.join(t, sub, f))
    if os.path.exists(os.path.join(REPO, "exp", "__init__.py")):
        shutil.copy2(os.path.join(REPO, "exp", "__init__.py"), os.path.join(t, "exp", "__init__.py"))
    for link in (os.path.join("exp", "out"), "testbed", "reproduce"):
        os.symlink(os.path.join(REPO, link), os.path.join(t, link))
    for p in PATCHES:
        subprocess.run(["patch", "-p1", "-s", "-d", t, "-i", p], check=True)
    return t, "temporary tree with both patches"


TREE, TREE_KIND = build_tree()
BEFORE_MONITOR = (os.path.join(REPO, "monitor", "monitor.py") if not _applied(REPO)
                  else os.path.join(REPO, "monitor", "monitor_e9.py"))
BEFORE_VERIFIER = (os.path.join(REPO, "exp", "stages", "e7_verify.py") if not _applied(REPO)
                   else os.path.join(REPO, "exp", "stages", "e7_verify_e9.py"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# the tree's own test harness (Recorder, Rig, in-memory anchor, verify) and the E9 helpers (operator markers, purge,
# restore scenario, the hub process fixture); loaded under their module names while test_e9 imports test_coverage, then
# the previous modules (if any) are put back, so another test file's harness is never replaced
_saved = {k: sys.modules.get(k) for k in ("test_coverage", "test_e9")}
_path0 = list(sys.path)
sys.path[:0] = [os.path.join(TREE, "monitor"), os.path.join(TREE, "exp")]
try:
    TC = _load("test_coverage", os.path.join(TREE, "monitor", "test_coverage.py"))
    TE9 = _load("e10_test_e9", os.path.join(TREE, "monitor", "test_e9.py"))
finally:
    for k, v in _saved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v
    sys.path[:] = _path0

T0, LATE, GAP, ctx, history = TC.T0, TC.LATE, TC.GAP, TC.ctx, TC.history
Rig, Recorder, Anchor, V, seg_v, verify = TC.Rig, TC.Recorder, TC.Anchor, TC.V, TC.seg_v, TC.verify
needs_crypto, MI, OP = TC.needs_crypto, TE9.MI, TE9.OP
tmp, rec = TC.tmp, TC.rec                                   # pytest fixtures


@pytest.fixture
def hub(tmp):
    """test_e9's hub fixture (a WAL recorder written by a hub process that stays up), with the tree's schema."""
    r = Recorder.__new__(Recorder)
    r.path = os.path.join(tmp, "hub_v2.db")
    r.con = TE9._HubConnection(r.path)
    r.con.executescript(TC.SCHEMA)
    r.last = {}
    yield r
    r.con.close()


def sub(tmp, name):
    d = os.path.join(tmp, name)
    os.makedirs(d, exist_ok=True)
    return d
PY312 = hasattr(sqlite3.Connection, "setconfig")
E9_ENV = {"HOMEPROV_SCHEME": "stable", "HOMEPROV_ROWBIND": "1", "HOMEPROV_SINCE": "0", "HOMEPROV_KEYLOG_REWIND": "1"}
assert tmp and rec and hub


def test_tree_carries_both_patches():
    m = open(os.path.join(TREE, "monitor", "monitor.py")).read()
    v = open(os.path.join(TREE, "exp", "stages", "e7_verify.py")).read()
    assert "HOMEPROV_HARDEN" in m and "def check_objects" in m and "_QC = " in m
    for s in ("def refuse_untrusted", "class ObservationBreaks", "def clock_steps", "no_hub_started_ts",
              "a_row_in_the_straddling_segment_changed", ":no_row_now"):
        assert s in v, s
    print("tree:", TREE_KIND, TREE, "monitor.py", sha(os.path.join(TREE, "monitor", "monitor.py"))[:16],
          "e7_verify.py", sha(os.path.join(TREE, "exp", "stages", "e7_verify.py"))[:16])


# ================================================================================================ hardening: monitor
def test_H1_every_monitor_connection_is_hardened(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    con = r.M._connect(rec.path)
    assert [con.execute("PRAGMA %s" % p).fetchone()[0] for p in ("trusted_schema", "cell_size_check", "mmap_size")] \
        == [0, 1, 0]
    if PY312:
        for flag, want in (("SQLITE_DBCONFIG_DEFENSIVE", 1), ("SQLITE_DBCONFIG_TRUSTED_SCHEMA", 0),
                           ("SQLITE_DBCONFIG_ENABLE_VIEW", 0), ("SQLITE_DBCONFIG_ENABLE_TRIGGER", 0)):
            assert int(con.getconfig(getattr(sqlite3, flag))) == want, flag
    rep = r.M.hardening_report()
    assert rep["harden"] is True and rep["applied"]["trusted_schema"] == 0
    off = Rig(tmp, rec, name="off", HOMEPROV_HARDEN="0")
    assert off.M.HARDEN is False and off.M.harden(sqlite3.connect(":memory:")) is None
    assert off.M.hardening_report()["applied"] is None
    with pytest.raises(SystemExit):
        TC.monitor_module(os.path.join(TREE, "monitor", "monitor.py"), os.path.join(tmp, "bad"), rec.path,
                          HOMEPROV_HARDEN="yes")


def test_H2_without_setconfig_the_pragmas_still_apply(tmp, rec):
    """An interpreter without sqlite3_db_config (Python 3.9 to 3.11): the pragmas are set, the flags reported None."""
    r = Rig(tmp, rec)

    class NoConfig:
        def __init__(self):
            self.c = sqlite3.connect(os.path.join(tmp, "noconfig.db"))

        def execute(self, *a):
            return self.c.execute(*a)
    got = r.M.harden(NoConfig())
    assert got["trusted_schema"] == 0 and got["cell_size_check"] == 1 and got["mmap_size"] == 0
    assert all(got[f] is None for f, _w in r.M.HARDEN_DBCONFIG)


def _three_monitors(tmp, rec, env, before_path):
    """The hardened monitor, the same with HOMEPROV_HARDEN=0, and the E9 monitor, on one recorder and one clock."""
    rigs = {}
    for name, path, extra in (("hard", None, {}), ("off", None, {"HOMEPROV_HARDEN": "0"}), ("e9", before_path, {})):
        if path is not None and not os.path.exists(path):
            continue
        rigs[name] = Rig(tmp, rec, name=name, path=path,
                         HOMEPROV_ESCROW_DIR=os.path.join(tmp, "esc_" + name), **env, **extra)
    return rigs


@pytest.mark.parametrize("env", [{}, E9_ENV])
def test_H3_records_state_and_escrow_are_byte_identical_with_and_without_hardening(tmp, rec, env):
    sid, eid = history(rec, T0)
    for i in range(30):
        rec.state("sensor.power", str(i), T0 - 5000.0 + i * 17.3, ctx=ctx(200 + i))
    rigs = _three_monitors(tmp, rec, env, BEFORE_MONITOR)
    for t in (T0 + 5.0, T0 + 10.0):
        for r in rigs.values():
            r.poll(t)
    rec.launder(sid, eid)
    for r in rigs.values():
        r.polls(T0 + 15.0, T0 + 25.0)
    ref = rigs["hard"]
    for name, r in rigs.items():
        assert r.anchor.bodies == ref.anchor.bodies, name
        assert open(r.M.STATE, "rb").read() == open(ref.M.STATE, "rb").read(), name
        assert open(os.path.join(tmp, "esc_" + name, "escrow.jsonl"), "rb").read() == \
            open(os.path.join(tmp, "esc_hard", "escrow.jsonl"), "rb").read(), name
    assert verify(tmp, ref)["flagged_seconds"] == [str(int(T0) + 1)]


def test_H4_direct_read_records_are_byte_identical_with_and_without_hardening(tmp, hub):
    rec = hub
    sid, eid = history(rec, T0)
    for i in range(40):
        rec.state("sensor.power", str(i), T0 - 7200.0 + i * 13.7, ctx=ctx(200 + i))
    rigs = _three_monitors(tmp, rec, dict(E9_ENV, HOMEPROV_READ="direct"), BEFORE_MONITOR)
    before = TE9.files_digest(rec.path)
    for t in (T0 + 5.0, T0 + 10.0):
        for r in rigs.values():
            assert r.poll(t).get("read") == "direct"
        assert TE9.files_digest(rec.path) == before            # the hardened direct read wrote nothing of the hub's
    rec.launder(sid, eid)
    for r in rigs.values():
        r.poll(T0 + 15.0)
    ref = rigs["hard"]
    for name, r in rigs.items():
        assert r.anchor.bodies == ref.anchor.bodies, name
        assert open(r.M.STATE, "rb").read() == open(ref.M.STATE, "rb").read(), name


def _view_recorder(path):
    """A recorder whose `states` is a VIEW over the real rows (a hub adversary's crafted schema)."""
    rec = Recorder(path)
    history(rec, T0)
    rec.con.executescript("ALTER TABLE states RENAME TO states_real; CREATE VIEW states AS SELECT * FROM states_real;")
    rec.con.commit()
    return rec


def test_H5_a_view_named_states_fails_closed_in_copy_mode(tmp):
    rec = _view_recorder(os.path.join(tmp, "view.db"))
    out = Rig(tmp, rec).poll(T0 + 5.0)
    assert out["evidence_unobservable"] and out["reason"] == "schema_object_not_a_table"
    assert out["detail"]["objects"] == {"states": "view"}
    before = Rig(tmp, rec, name="e9", path=BEFORE_MONITOR) if os.path.exists(BEFORE_MONITOR) else None
    if before is not None:                                      # the E9 monitor read through the view and sealed
        out0 = before.poll(T0 + 5.0)
        assert not out0.get("evidence_unobservable") and out0["anchor"]["ok"]


def test_H6_a_view_named_states_fails_closed_in_direct_mode(tmp, hub):
    rec = hub
    history(rec, T0)
    rec.con.executescript("ALTER TABLE states RENAME TO states_real; CREATE VIEW states AS SELECT * FROM states_real;")
    for quick in ("1", "720"):                                  # quick_check due (first poll) and not due
        r = Rig(tmp, rec, name="d" + quick, HOMEPROV_READ="direct", HOMEPROV_QUICK_CHECK_EVERY=quick)
        r.poll(T0 + 5.0)
        out = r.poll(T0 + 10.0)
        assert out["read"] == "direct" and out["evidence_unobservable"]
        assert out["reason"] == "schema_object_not_a_table"


def test_H7_virtual_and_shadowing_objects_are_refused(tmp):
    con = sqlite3.connect(os.path.join(tmp, "v.db"))
    con.executescript(TC.SCHEMA)
    M = TC.monitor_module(os.path.join(TREE, "monitor", "monitor.py"), os.path.join(tmp, "s"), os.path.join(tmp, "v.db"))
    assert M.check_objects(con) is None
    try:
        con.executescript("DROP TABLE event_data; CREATE VIRTUAL TABLE event_data USING fts5(shared_data);")
    except sqlite3.OperationalError:
        pytest.skip("this SQLite has no fts5")
    bad = M.check_objects(con)
    assert bad[1] == "schema_object_not_a_table" and bad[2]["objects"] == {"event_data": "virtual table"}


def test_H8_quick_check_is_the_first_read_of_a_direct_poll(tmp, hub):
    rec = hub
    history(rec, T0)
    r = Rig(tmp, rec, HOMEPROV_READ="direct", HOMEPROV_QUICK_CHECK_EVERY="720")
    seen = []
    real = r.M.sqlite3.connect

    def traced(*a, **k):
        c = real(*a, **k)
        if "readonly_shm" in str(a[0]):
            log = []
            seen.append(log)
            c.set_trace_callback(log.append)
        return c
    r.M.sqlite3 = type("S", (), {"connect": staticmethod(traced)})
    r.poll(T0 + 5.0)                                            # the first poll of the process: quick_check due
    r.poll(T0 + 10.0)                                           # not due (720)
    settings = ("PRAGMA query_only", "PRAGMA trusted_schema", "PRAGMA cell_size_check", "PRAGMA mmap_size", "BEGIN")

    def first_read(log):
        return next(s for s in log if not s.startswith(settings))
    assert first_read(seen[0]).startswith("PRAGMA quick_check")
    assert first_read(seen[1]).startswith("SELECT lower(name), type, sql FROM sqlite_master")
    assert not any("quick_check" in s for s in seen[1])


def _corrupt_index(path):
    """Overwrite the page header and cell pointers of an index's root page; returns (offset, original bytes)."""
    con = sqlite3.connect(path)
    root = con.execute("SELECT rootpage FROM sqlite_master WHERE name='ix_e10'").fetchone()[0]
    psz = con.execute("PRAGMA page_size").fetchone()[0]
    con.close()
    off = (root - 1) * psz
    with open(path, "r+b") as fh:
        fh.seek(off)
        orig = fh.read(psz)
        fh.seek(off)
        fh.write(b"\x0a\x00\x00\xff\xff\x00\x00\x00" + b"\xff" * 64)
    return off, orig


def test_H9_a_failed_quick_check_is_latched_until_the_file_passes(tmp, rec):
    history(rec, T0)
    for i in range(300):
        rec.state("sensor.power", str(i), T0 - 3000.0 + i * 7.1, ctx=ctx(500 + i))
    rec.sql("CREATE INDEX ix_e10 ON states (state, last_updated_ts)")
    r = Rig(tmp, rec, HOMEPROV_QUICK_CHECK_EVERY="4")
    calls = []
    real = r.M.check_connection

    def spy(con, quick=True):
        calls.append(quick)
        return real(con, quick)
    r.M.check_connection = spy
    assert not r.poll(T0 + 5.0).get("evidence_unobservable")      # 1: due (first poll and cadence)
    assert not r.poll(T0 + 10.0).get("evidence_unobservable")     # 2: not due
    rec.con.close()
    off, orig = _corrupt_index(rec.path)
    a = r.poll(T0 + 15.0)                                         # 3: not due by cadence (the index is not read)
    b = r.poll(T0 + 20.0)                                         # 4: not due (4 % 4 == 0)
    c = r.poll(T0 + 25.0)                                         # 5: due (5 % 4 == 1): fails
    d = r.poll(T0 + 30.0)                                         # 6: not due by cadence, latched: fails again
    assert c["evidence_unobservable"] and c["reason"] == "quick_check_failed"
    assert d["evidence_unobservable"] and d["reason"] == "quick_check_failed"
    with open(rec.path, "r+b") as fh:
        fh.seek(off)
        fh.write(orig)
    e = r.poll(T0 + 35.0)                                         # 7: latched: passes, latch released
    f = r.poll(T0 + 40.0)                                         # 8: not due
    assert not e.get("evidence_unobservable") and not f.get("evidence_unobservable")
    assert calls == [True, False, False, False, True, True, True, False]
    assert not a.get("fail_closed") or a["reason"] != "quick_check_failed"
    assert not b.get("fail_closed") or b["reason"] != "quick_check_failed"


# ================================================================================================ hardening: verifier
def test_H10_verifier_connections_are_hardened_and_refuse_crafted_recorders(tmp):
    p = os.path.join(tmp, "plain.db")
    Recorder(p)
    con = V.vconnect(p)
    assert [con.execute("PRAGMA %s" % x).fetchone()[0] for x in ("trusted_schema", "cell_size_check", "mmap_size")] \
        == [0, 1, 0]
    assert V.refuse_untrusted(p) is None
    rv = _view_recorder(os.path.join(tmp, "view.db"))
    rv.con.close()
    with pytest.raises(V.RecorderRefused) as e:
        V.refuse_untrusted(rv.path)
    assert e.value.reason == "schema_object_not_a_table" and e.value.detail["objects"] == {"states": "view"}
    rc = Recorder(os.path.join(tmp, "corrupt.db"))
    for i in range(300):
        rc.state("sensor.power", str(i), T0 + i, ctx=ctx(i))
    rc.sql("CREATE INDEX ix_e10 ON states (state, last_updated_ts)")
    rc.con.close()
    _corrupt_index(rc.path)
    with pytest.raises(V.RecorderRefused) as e:
        V.refuse_untrusted(rc.path)
    assert e.value.reason == "quick_check_failed"


def test_H11_the_verifier_cli_refuses_and_exits_3(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 10.0)
    chain = os.path.join(tmp, "chain.jsonl")
    open(chain, "w").write("\n".join(r.anchor.lines) + "\n")
    rec.con.executescript("ALTER TABLE states RENAME TO states_real; CREATE VIEW states AS SELECT * FROM states_real;")
    rec.con.commit()
    cmd = [sys.executable, os.path.join(TREE, "exp", "stages", "e7_verify.py"), "verify", "--chain", chain,
           "--db", rec.path, "--late-bound", "5", "--gap-s", "15", "--monitor-dir", os.path.join(TREE, "monitor")]
    p = subprocess.run(cmd, capture_output=True, text=True)
    assert p.returncode == 3 and json.loads(p.stdout)["refused"]["reason"] == "schema_object_not_a_table"
    p2 = subprocess.run(cmd + ["--no-harden"], capture_output=True, text=True)
    assert p2.returncode == 0 and "refused" not in json.loads(p2.stdout)


def test_H12_honest_verdicts_are_identical_with_and_without_the_verifier_hardening(tmp, rec):
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec, **E9_ENV)
    r.poll(T0 + 5.0)
    rec.launder(sid, eid)
    r.polls(T0 + 10.0, T0 + 20.0)
    on = verify(tmp, r)
    V.VERIFY_HARDEN = False
    try:
        off = verify(tmp, r)
    finally:
        V.VERIFY_HARDEN = True
    keys = ("segments", "violations", "attributable_rows", "benign_late_rows", "unobserved_late_rows", "flagged_seconds",
            "flagged_segments", "stalls", "root_unknown_segments", "keylog", "keylog_violations", "keylog_suspect_rows")
    for k in keys:
        assert json.dumps(on[k], sort_keys=True, default=str) == json.dumps(off[k], sort_keys=True, default=str), k


# ================================================================================================ D1
def _unobservable_stall_then_backdate(tmp, rec, gap_polls=12):
    """FORMAL_DRAFT.md probe P2: polls to T0+100; the hub makes 12 polls unobservable (a corrupt -wal header); then a
    row backdated about 70 s into a second sealed before the stall; polls go on."""
    history(rec, T0 + 80)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 100.0)
    wal = rec.path + "-wal"
    open(wal, "wb").write(b"\x00" * 64)
    r.polls(T0 + 105.0, T0 + 100.0 + 5.0 * gap_polls)
    os.remove(wal)
    rec.state("lock.front_door", "unlocked", T0 + 97.4, ctx=ctx(60), par=ctx(10))   # 2.6 s before the last copy
    r.polls(T0 + 105.0 + 5.0 * gap_polls, T0 + 115.0 + 5.0 * gap_polls)
    return r


def test_D1_probe_P2_a_row_backdated_across_an_unobservable_stall_is_not_benign(tmp, rec):
    r = _unobservable_stall_then_backdate(tmp, rec)
    res = verify(tmp, r)
    (row,) = [x for x in res["unobserved_late_rows"] if x["second"] == str(int(T0) + 97)]
    assert any(w["why"] == "observation_break:unobservable_poll" for w in row["why"])
    assert not [x for x in res["benign_late_rows"] if x["second"] == str(int(T0) + 97)]
    if os.path.exists(BEFORE_VERIFIER):                         # the E9 verifier: benign_late, lower bound 7.6 s
        old = TC.load_module(BEFORE_VERIFIER, "e7_verify_before_d1", {})
        Mv = old.load_monitor("closure", os.path.join(tmp, "vold"))
        db = os.path.join(tmp, "old_copy.db")
        shutil.copy2(rec.path, db)
        o = old.verify(Mv, db, r.anchor.lines, LATE, GAP, scheme="closure")
        (b,) = [x for x in o["benign_late_rows"] if x["second"] == str(int(T0) + 97)]
        assert b["committed_after_lower_bound_s"] == pytest.approx(2.6)


def test_D1_a_gap_above_gap_s_between_polls_breaks_the_bracket(tmp, rec):
    history(rec, T0 + 80)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 100.0)
    rec.state("lock.front_door", "unlocked", T0 + 97.0, ctx=ctx(61))     # lower bound 3 s: benign before E10
    r.polls(T0 + 100.0 + GAP + 10.0, T0 + 100.0 + GAP + 20.0)            # the monitor was silent for GAP + 10 s
    res = verify(tmp, r)
    (row,) = [x for x in res["unobserved_late_rows"] if x["second"] == str(int(T0) + 97)]
    assert any(w["why"] == "observation_break:gap_above_gap_s" for w in row["why"])


def test_D1_a_backlogged_poll_breaks_the_bracket(tmp, rec):
    history(rec, T0 + 80)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 100.0)
    r.anchor.down = True
    r.poll(T0 + 105.0)                                            # its own record fails: its head goes to the backlog
    rec.state("lock.front_door", "unlocked", T0 + 103.0, ctx=ctx(62))
    r.anchor.down = False
    r.polls(T0 + 110.0, T0 + 120.0)
    res = verify(tmp, r)
    (row,) = [x for x in res["unobserved_late_rows"] if x["second"] == str(int(T0) + 103)]
    assert any(w["why"] == "observation_break:backlogged_poll" for w in row["why"])


def test_D1_without_a_break_a_late_row_stays_benign_and_the_boundary_is_unchanged(tmp, rec):
    """FORMAL_DRAFT.md probe P1 with this harness's LATE_BOUND: a lag just under the bound is benign, just over it
    attributable; a short late commit with polls every 5 s stays benign_late."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 95.0)
    rec.state("lock.front_door", "unlocked", T0 + 95.0 - (LATE - 0.1), ctx=ctx(63))
    rec.state("binary_sensor.door", "on", T0 + 95.0 - (LATE + 0.1), ctx=ctx(64))
    r.polls(T0 + 100.0, T0 + 110.0)
    res = verify(tmp, r)
    benign = {x["second"] for x in res["benign_late_rows"]}
    attributable = {x["second"] for x in res["attributable_rows"]}
    assert str(int(T0 + 95.0 - (LATE - 0.1))) in benign
    assert str(int(T0 + 95.0 - (LATE + 0.1))) in attributable
    assert not res["unobserved_late_rows"]


# ================================================================================================ D2
def _withheld_empty_second(tmp, rec, withhold):
    """FORMAL_DRAFT.md probe P3: an unlock in second T0+31, sealed by the poll at T0+35; the hub deletes both of its
    rows; the anchor host withholds the one record that carries that second's root and keylog ranges."""
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 30.0)
    sid, eid = history(rec, T0 + 30)
    r.poll(T0 + 35.0)
    rec.sql("DELETE FROM states WHERE state_id=?", (sid,))
    rec.sql("DELETE FROM events WHERE event_id=?", (eid,))
    r.polls(T0 + 40.0, T0 + 130.0)
    if withhold:
        keep = [l for l in r.anchor.lines
                if str(int(T0) + 31) not in (json.loads(l)["payload"].get("sealed") or {}).get("second", {})]
        assert len(keep) == len(r.anchor.lines) - 1
        r.anchor.lines = keep
    return r


def test_D2_probe_P3_an_emptied_second_whose_record_is_withheld_is_unknown(tmp, rec):
    honest = verify(tmp, _withheld_empty_second(tmp, rec, False))
    assert str(int(T0) + 31) in honest["flagged_seconds"]
    rec2 = Recorder(os.path.join(tmp, "rec2.db"))
    res = verify(sub(tmp, "w"), _withheld_empty_second(sub(tmp, "w"), rec2, True))
    assert str(int(T0) + 31) not in res["flagged_seconds"]
    unknown = {x["seg"]: x for x in res["root_unknown_segments"] if x["gran"] == "second"}
    assert str(int(T0) + 31) in unknown and unknown[str(int(T0) + 31)]["why"].endswith(":no_row_now")
    sys.path.insert(0, os.path.join(REPO, "exp", "stages"))
    try:
        import e10_outcome as EO                                  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    assert EO.outcome(EO.annotate(res), str(int(T0) + 31)) == "unknown"
    assert EO.outcome(EO.annotate(honest), str(int(T0) + 31)) == "violation"


def test_D2_honest_chains_mark_no_empty_second_unknown(tmp, rec):
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 60.0)
    res = verify(tmp, r)
    assert not [x for x in res["root_unknown_segments"] if x["why"].endswith(":no_row_now")]


# ================================================================================================ D3
def _clock_step(tmp, rec, step_s=20.0, marker=None, signer=None, forged=None):
    """The hub's clock steps back by step_s at T0+100: for the next step_s seconds it writes rows timestamped
    step_s earlier, into seconds sealed already."""
    history(rec, T0)
    r = Rig(tmp, rec)
    r.polls(T0 + 5.0, T0 + 95.0)
    if marker is not None:
        TE9.put_marker(r.anchor, marker, signer=signer)
    t = T0 + 100.0
    while t < T0 + 100.0 + step_s:
        rec.state("sensor.clock", str(t), t - step_s + 0.3, ctx=ctx(int(t)))
        r.poll(t)
        t += 5.0
    if forged is not None:
        rec.state("lock.front_door", "unlocked", forged, ctx=ctx(99))
    r.polls(T0 + 100.0 + step_s, T0 + 130.0 + step_s)
    return r


def cs_marker(lo, hi, issued):
    return {"marker": "CLOCK_STEP", "window": [lo, hi], "issued_ts": issued, "issuer": "operator",
            "nonce": MI.new_nonce()}


@needs_crypto
def test_D3_a_backward_clock_step_is_attributable_without_a_marker_and_excused_with_one(tmp, rec):
    plain = verify(tmp, _clock_step(tmp, rec))
    assert len(plain["attributable_rows"]) >= 3 and plain["flagged_seconds"]
    signer, pub = TE9.operator(tmp)
    rec2 = Recorder(os.path.join(tmp, "rec2.db"))
    r = _clock_step(sub(tmp, "m"), rec2, marker=cs_marker(T0 + 80.0, T0 + 100.0, T0 + 96.0), signer=signer)
    res = TE9.verify_e9(sub(tmp, "m"), r, pub=pub)
    assert res["flagged_seconds"] == [] and not res["attributable_rows"]
    cs = res["clock_step"]
    assert len(cs["accepted"]) == 1 and len(cs["excused_rows"]) >= 3


@needs_crypto
def test_D3_the_clock_step_licence_is_bounded(tmp, rec):
    signer, pub = TE9.operator(tmp)
    # a forged row outside the window, and an edit of a sealed row, stay attributable under a valid marker
    sid, eid = history(rec, T0 + 40)
    r = _clock_step(tmp, rec, marker=cs_marker(T0 + 80.0, T0 + 100.0, T0 + 96.0), signer=signer,
                    forged=T0 + 50.5)
    rec.launder(sid, eid)
    r.polls(T0 + 160.0, T0 + 165.0)
    res = TE9.verify_e9(tmp, r, pub=pub)
    assert str(int(T0) + 50) in res["flagged_seconds"] and str(int(T0) + 41) in res["flagged_seconds"]
    # windows too long, far from the marker, unsigned: rejected or not considered
    for m, why in ((cs_marker(T0 - 400.0, T0 + 100.0, T0 + 96.0), "window_longer_than_the_maximum"),
                   (cs_marker(T0 + 80.0, T0 + 100.0, T0 + 900.0), "window_not_at_the_marker")):
        rr = Recorder(os.path.join(tmp, why + ".db"))
        res = TE9.verify_e9(sub(tmp, why), _clock_step(sub(tmp, why), rr, marker=m, signer=signer), pub=pub)
        assert res["clock_step"]["rejected"][0]["why"] == why and res["flagged_seconds"]
    ru = Recorder(os.path.join(tmp, "unsigned.db"))
    res = TE9.verify_e9(sub(tmp, "u"), _clock_step(sub(tmp, "u"), ru, marker=cs_marker(T0 + 80.0, T0 + 100.0,
                                                                                         T0 + 96.0)), pub=pub)
    assert res["flagged_seconds"] and res.get("clock_step") is None


# ================================================================================================ D4
@needs_crypto
def test_D4_a_restore_done_without_the_hub_start_is_rejected(tmp, rec):
    r, pub = TE9.restore_scenario(tmp, rec, "rowbind", hub_started=False)
    res = TE9.verify_e9(tmp, r, pub=pub, restore_tol_s=2.0)
    assert any(j["kind"] == "RESTORE_DONE" and j["why"] == "no_hub_started_ts" for j in res["restore"]["rejected"])
    assert res["restore"]["restores"][0]["done"] is None
    r2, pub2 = TE9.restore_scenario(sub(tmp, "ok"), Recorder(os.path.join(tmp, "ok.db")), "rowbind")
    ok = TE9.verify_e9(sub(tmp, "ok"), r2, pub=pub2, restore_tol_s=2.0)
    assert ok["restore"]["restores"][0]["done"]["hub_started_ts"] is not None


# ================================================================================================ D5
def _straddle(tmp, rec, change, source):
    """tol = 0; the cutoff falls inside second T0+2400 (scheduled T0+6000.5, keep 3600 s): a row before it (purged)
    and one after it (retained) in that second. change: None, or an edit of the retained row after the purge."""
    signer, pub = TE9.operator(tmp)
    a = rec.state("sensor.a", "1", T0 + 2400.2, ctx=ctx(1))
    b = rec.state("sensor.b", "1", T0 + 2400.8, ctx=ctx(2))
    rec.state("sensor.c", "1", T0 + 5000.0, ctx=ctx(3))
    env = dict(TE9.SOURCES[source], HOMEPROV_SCHEME="stable", HOMEPROV_SINCE="0", HOMEPROV_KEYLOG="0")
    if source == "escrow":
        env["HOMEPROV_ESCROW_DIR"] = os.path.join(tmp, "esc")
    r = Rig(tmp, rec, **env)
    r.polls(T0 + 5010.0, T0 + 5020.0)
    TE9.put_marker(r.anchor, MI.scoped_marker(T0 + 6000.5, 3600.0, issued_ts=T0 + 5900.0), signer=signer)
    rec.sql("DELETE FROM states WHERE state_id=?", (a,))
    if change:
        rec.sql("UPDATE states SET state='forged' WHERE state_id=?", (b,))
    r.polls(T0 + 6010.0, T0 + 6020.0)
    return TE9.verify_e9(tmp, r, pub=pub, keep=3600.0, purge_tol_s=0.0)


@needs_crypto
def test_D5_tol0_the_straddling_second_excuses_removed_rows_only(tmp, rec):
    """Keylog off (so no per-row binding): the straddling second's own root and its escrowed tuples are the evidence,
    as for a row below the keylog start of a recorder sealed without HOMEPROV_SINCE."""
    source = "escrow"
    ok = _straddle(tmp, rec, False, source)
    assert str(int(T0) + 2400) not in ok["flagged_seconds"]
    rec2 = Recorder(os.path.join(tmp, "rec2.db"))
    bad = _straddle(sub(tmp, "b"), rec2, True, source)
    assert str(int(T0) + 2400) in bad["flagged_seconds"]
    assert any(x.get("why") == "a_row_in_the_straddling_segment_changed" for x in bad["purge"]["not_excused"])


@needs_crypto
def test_D5_without_per_row_evidence_only_an_emptied_straddling_second_is_excused(tmp, rec):
    signer, pub = TE9.operator(tmp)
    rec.state("sensor.a", "1", T0 + 2400.2, ctx=ctx(1))
    b = rec.state("sensor.b", "1", T0 + 2400.8, ctx=ctx(2))
    r = Rig(tmp, rec, HOMEPROV_SCHEME="stable", HOMEPROV_SINCE="0", HOMEPROV_KEYLOG="0")
    r.polls(T0 + 5010.0, T0 + 5020.0)
    TE9.put_marker(r.anchor, MI.scoped_marker(T0 + 6000.5, 3600.0, issued_ts=T0 + 5900.0), signer=signer)
    TE9.ha_purge(rec, T0 + 2400.5)
    rec.sql("UPDATE states SET state='forged' WHERE state_id=?", (b,))
    r.polls(T0 + 6010.0, T0 + 6020.0)
    res = TE9.verify_e9(tmp, r, pub=pub, keep=3600.0, purge_tol_s=0.0)
    assert str(int(T0) + 2400) in res["flagged_seconds"]
    assert any(x.get("why") == "a_row_in_the_straddling_segment_cannot_be_checked_without_binding_or_escrow"
               for x in res["purge"]["not_excused"])


# ================================================================================================ O-MIG (no patch needed)
@pytest.mark.parametrize("shape,breaks", [("statistics_meta", False), ("index", False), ("states_column", True)])
def test_OMIG_only_a_migration_of_the_states_or_events_columns_changes_the_commitment(tmp, rec, shape, breaks):
    """E10_DESIGN.md section 3: the stable scheme commits PRAGMA table_info's columns of states and events, so the 51 -> 52
    step of Home Assistant's recorder (statistics_meta.unit_class) and a new index leave every root as it was, and a
    migration that adds a states column fails every sealed segment holding a state row."""
    history(rec, T0)
    for i in range(20):
        rec.state("sensor.power", str(i), T0 + 3.0 + i * 2.5, ctx=ctx(700 + i))
    rec.sql("CREATE TABLE statistics_meta (id INTEGER PRIMARY KEY, statistic_id VARCHAR(255), unit_of_measurement VARCHAR(255))")
    r = Rig(tmp, rec, **E9_ENV)
    r.polls(T0 + 5.0, T0 + 70.0)
    rec.sql({"statistics_meta": "ALTER TABLE statistics_meta ADD COLUMN unit_class VARCHAR(255)",
             "index": "CREATE INDEX ix_e10_probe ON states (state, last_updated_ts)",
             "states_column": "ALTER TABLE states ADD COLUMN e10_probe TEXT"}[shape])
    r.polls(T0 + 75.0, T0 + 80.0)
    res = verify(tmp, r)
    state_seconds = {str(int(x[0])) for x in rec.con.execute("SELECT last_updated_ts FROM states")}
    if breaks:
        assert state_seconds <= set(res["flagged_seconds"])
        assert res["keylog_violations"]
    else:
        assert res["flagged_seconds"] == [] and not res["keylog_violations"]
