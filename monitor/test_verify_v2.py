"""Verifier and monitor version 2 (round 17, review r6): the pinned committed column list and the two-signed-roots rule.

    <home>/miniconda3/bin/python3 -m pytest -q monitor/test_verify_v2.py

Every case runs the shipped monitor (monitor/monitor.py, or monitor/monitor_v2.py which executes monitor.py unchanged)
against a synthetic recorder with Home Assistant's layout at a fixed clock, appending to monitor/test_coverage.py's
in-memory anchor, and verifies with the registered verifier (exp/stages/e7_verify.py, imported and called unchanged) and
with exp/stages/verify_v2.py. Signing keys are generated in each test's temporary directory (Ed25519, test keys only).
No Docker, no network.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "exp", "stages"))
import test_coverage as TC                                    # noqa: E402  (the shared harness; not edited)
import pinned_columns as PC                                   # noqa: E402
import verify_v2 as VV                                        # noqa: E402

EV = VV.EV
T0, LATE, GAP, history, Rig = TC.T0, TC.LATE, TC.GAP, TC.history, TC.Rig
tmp, rec = TC.tmp, TC.rec                                     # pytest fixtures
needs_crypto = TC.needs_crypto
V2_PATH = os.path.join(HERE, "monitor_v2.py")
STABLE = {"HOMEPROV_SCHEME": "stable"}
assert tmp and rec


def frozen_verify(tmp, rig, **kw):
    """The registered verifier, as test_coverage.verify() runs it, on a private copy."""
    M = EV.load_monitor("stable", os.path.join(tmp, "fv_%d" % len(rig.anchor.lines)))
    db = os.path.join(tmp, "fv_copy.db")
    shutil.copy2(rig.rec.path, db)
    return VV._ORIG["verify"](M, db, rig.anchor.lines, LATE, GAP, scheme="stable", **kw)


def v2_verify(tmp, rig, lines=None, **kw):
    M = EV.load_monitor("stable", os.path.join(tmp, "v2_%d" % len(rig.anchor.lines)))
    db = os.path.join(tmp, "v2_copy.db")
    shutil.copy2(rig.rec.path, db)
    return VV.verify_v2(M, db, rig.anchor.lines if lines is None else lines, LATE, GAP, scheme="stable", **kw)


def flagged(res):
    return res["flagged_seconds"]


def viol(res, seg, gran="second"):
    return next((v for v in res["violations"] if v["gran"] == gran and v["seg"] == str(int(seg))), None)


def comparable(res):
    """The verdict-bearing parts of a verify() result (what run() prints), as JSON."""
    keys = ("segments", "violations", "attributable_rows", "benign_late_rows", "unobserved_late_rows",
            "rows_in_unsealed_time", "flagged_seconds", "ambiguous_seconds", "flagged_segments", "stalls",
            "observation_gaps", "root_unknown_segments", "keylog", "keylog_violations", "malformed_rows",
            "keylog_suspect_rows", "invalid_text_rows", "signatures", "markers", "purge", "restore",
            "excused_violations", "excused_keylog_violations", "namemap", "clock_step")
    return json.dumps({k: res.get(k) for k in keys}, sort_keys=True, default=str)


def rich_history(rec, t):
    """Rows of both tables with every value type the field tuples carry: NULLs, BLOBs, REAL, INTEGER, TEXT that is not
    valid UTF-8, joined attributes and event data."""
    sid, eid = history(rec, t)
    rec.state("sensor.temp", "21.5", t + 3.1, attrs='{"unit":"C"}')
    rec.event("state_changed", t + 3.2, ctx=TC.ctx(20), data='{"x":1}')
    rec.sql("UPDATE states SET state=CAST(x'ff41' AS TEXT) WHERE state_id=(SELECT max(state_id) FROM states)")
    return sid, eid


# ================================================================================================ pinned_columns
def test_pinned_load_and_keylog_equal_monitor_py_for_the_current_list(tmp, rec):
    rich_history(rec, T0)
    rec.state("sensor.bad", "x", "not-a-number")             # a malformed timestamp: neither function folds it
    M = EV.load_monitor("stable", os.path.join(tmp, "m"))
    cols = PC.current_columns(M, rec.path)
    assert "last_reported_ts" not in cols["states"] and cols["states"][0] == "state_id"
    for since, until in ((None, None), (T0 + 1.0, None), (T0, T0 + 3.0)):
        assert PC.load_stable_cols(M, rec.path, cols, since, until) == M.load_stable(rec.path, since, until)
    for t in ("states", "events"):
        for lo, hi in ((0, 100), (1, 3), (2, 2), (0, 1)):
            assert PC.keylog_rows_cols(M, rec.path, t, lo, hi, cols[t]) == M.keylog_rows(rec.path, t, lo, hi)
        assert PC.keylog_rows_cols(M, rec.path, t, 0, 100, cols[t], limit=2) == M.keylog_rows(rec.path, t, 0, 100, 2)


def test_pinned_list_ignores_an_added_column_and_marks_a_dropped_one(tmp, rec):
    rich_history(rec, T0)
    M = EV.load_monitor("stable", os.path.join(tmp, "m"))
    before = PC.current_columns(M, rec.path)
    nodes0 = M.load_stable(rec.path)
    rec.sql("ALTER TABLE states ADD COLUMN probe TEXT")
    rec.sql("UPDATE states SET probe='backfilled'")
    assert PC.load_stable_cols(M, rec.path, before) == nodes0          # the old list reproduces the sealed tuples
    assert M.load_stable(rec.path) != nodes0                           # monitor.py's current list does not
    now = PC.current_columns(M, rec.path)
    full = PC.load_stable_cols(M, rec.path, now)
    assert [n[:6] + (PC.refields(n[6], before[n[6][0]]),) for n in full] == nodes0
    assert PC.added(before, M, rec.path) == {"states": ["probe"], "events": []}
    rec.sql("ALTER TABLE states DROP COLUMN origin_idx")
    got = PC.load_stable_cols(M, rec.path, before)
    st = [n for n in got if n[1].startswith("s:")]
    assert st and all(PC.DROPPED + "origin_idx" in n[6] for n in st)
    assert all(a[6] != b[6] for a, b in zip(got, nodes0) if a[1].startswith("s:"))
    assert [a for a in got if a[1].startswith("e:")] == [b for b in nodes0 if b[1].startswith("e:")]
    assert PC.dropped(before, M, rec.path) == {"states": ["origin_idx"], "events": []}


def test_digest_and_canonical_reject_malformed_lists():
    good = {"states": ["state_id", "state"], "events": ["event_id"]}
    assert PC.digest(good) == PC.digest(json.loads(json.dumps(good)))
    for bad in ({"states": ["a"]}, {"states": ["a", "a"], "events": []}, {"states": [""], "events": []},
                {"states": [1], "events": []}):
        with pytest.raises(ValueError):
            PC.canonical(bad)


# ================================================================================================ monitor_v2
@needs_crypto
def test_monitor_v2_records_carry_the_signed_column_list_and_verify_as_before(tmp, rec):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    sid, eid = history(rec, T0)
    r = Rig(tmp, rec, path=V2_PATH, HOMEPROV_SIGN_KEY=priv, **STABLE)
    assert r.M.V1_SHA256_FOUND == r.M.V1_SHA256                       # monitor.py is the registered file
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.launder(sid, eid)
    r.polls(T0 + 15.0, T0 + 70.0)
    ps = r.anchor.payloads()
    cc = [p["committed_columns"] for p in ps]
    assert all(c["v"] == 1 and c["instance"] == cc[0]["instance"] and len(c["history"]) == 1 for c in cc)
    (d,) = cc[0]["lists"]
    assert PC.digest(cc[0]["lists"][d]) == d and cc[0]["history"] == [[1, d]]
    M = EV.load_monitor("stable", os.path.join(tmp, "m"))
    assert cc[0]["lists"][d] == PC.current_columns(M, rec.path)
    assert all(p["sig_alg"] == "ed25519" for p in ps)
    old = frozen_verify(tmp, r, sign_pubkey=pub)
    new = v2_verify(tmp, r, sign_pubkey=pub)
    assert old["signatures"]["signed_ok"] == len(ps)                   # the field is under the signature
    assert flagged(old) == flagged(new) == [str(int(T0) + 1)]
    assert comparable(old) == comparable(new)
    cl = new["v2"]["column_list"]
    assert cl["mode"] == "one_list" and cl["roots_checked_by_source"] == {"record": len(new["checked"])}
    assert new["v2"]["conflict_rule"]["segments_with_two_or_more_signed_roots"] == {}


def migration_scenario(tmp, rec, path, keylog_row=True, edit_after=False, **env):
    """Rows sealed before a migration that adds a states column and backfills it, then rows sealed after it."""
    priv, pub, _k = TC._keypair(tmp, "monitor")
    sid, _eid = history(rec, T0)
    r = Rig(tmp, rec, path=path, HOMEPROV_SIGN_KEY=priv, **STABLE, **env)
    r.poll(T0 + 5.0)
    if keylog_row:
        rec.state("sensor.early", "1", T0 + 6.0)                       # first observed (keylog range) before the migration
    r.poll(T0 + 10.0)
    pre = os.path.join(tmp, "start_snapshot.db")                      # a recorder copy from before the migration
    shutil.copy2(rec.path, pre)
    rec.sql("ALTER TABLE states ADD COLUMN probe TEXT")
    rec.sql("UPDATE states SET probe='backfilled'")
    history(rec, T0 + 20.0)
    r.polls(T0 + 25.0, T0 + 70.0)                                     # seconds after it, and minute T0 with the new list
    if edit_after:
        rec.sql("UPDATE states SET state='forged' WHERE state_id=?", (sid,))
        r.poll(T0 + 75.0)
    return r, pub, pre, sid


@needs_crypto
def test_v2_monitor_across_a_migration_verifies_each_segment_over_its_own_list(tmp, rec):
    r, pub, _pre, _sid = migration_scenario(tmp, rec, V2_PATH)
    hist = r.anchor.payloads()[-1]["committed_columns"]["history"]
    assert len(hist) == 2 and hist[0][0] == 1                         # the list changed at the first poll after it
    old = frozen_verify(tmp, r, sign_pubkey=pub)
    new = v2_verify(tmp, r, sign_pubkey=pub)
    early = {str(int(T0) + i) for i in range(3)}                     # seconds sealed before the migration
    assert early <= set(flagged(old))                                 # registered verifier: the current list fails them
    assert old["keylog"]["violations"] >= 1                           # and the range first observed before it
    assert flagged(new) == [] and new["keylog"]["violations"] == 0
    assert new["segments"]["second"]["violated"] == 0 and new["segments"]["minute"]["violated"] == 0
    assert new["segments"]["minute"]["anchored_in_window"] == 1        # minute T0: sealed after it, over the new list
    cl = new["v2"]["column_list"]
    assert cl["mode"] == "per_segment_lists" and len(cl["lists"]) == 2
    assert cl["added_since_sealing_not_read"] == {"states": {"probe": 4}}      # the backfilled rows


@needs_crypto
def test_v2_still_detects_an_edit_of_a_row_sealed_before_the_migration(tmp, rec):
    r, pub, _pre, _sid = migration_scenario(tmp, rec, V2_PATH, edit_after=True)
    new = v2_verify(tmp, r, sign_pubkey=pub)
    assert flagged(new) == [str(int(T0) + 1)]
    v = viol(new, T0 + 1)
    assert v["attributable"] and v["mechanism"] == "sealed_row_changed" and "v2_reason" not in v


@needs_crypto
def test_v1_chain_with_the_start_snapshot_list_supplied(tmp, rec):
    r, pub, pre, _sid = migration_scenario(tmp, rec, os.path.join(HERE, "monitor.py"), keylog_row=False)
    assert "committed_columns" not in r.anchor.payloads()[0]
    old = frozen_verify(tmp, r, sign_pubkey=pub)
    plain = v2_verify(tmp, r, sign_pubkey=pub)                        # no list known: exactly the registered verifier
    assert comparable(plain) == comparable(old) and plain["v2"]["column_list"]["mode"] == "current_schema"
    assert {str(int(T0) + i) for i in range(3)} <= set(flagged(old))
    M = EV.load_monitor("stable", os.path.join(tmp, "m"))
    start = VV.columns_of_file(M, pre)
    pinned = v2_verify(tmp, r, sign_pubkey=pub, pinned=start, pinned_label="start snapshot")
    # seconds sealed before the migration are recomputed over the start list and match; seconds and the minute sealed
    # after it carry the new column, which the one supplied list cannot reproduce: the outside list is right only for
    # records sealed under it, which is why a v1 chain across a schema change needs the list in force per record
    assert not {str(int(T0) + i) for i in range(3)} & set(flagged(pinned))
    cl = pinned["v2"]["column_list"]
    assert cl["default_source"] == "external:start snapshot" and cl["external"]["digest"] == PC.digest(start)


@needs_crypto
def test_a_dropped_committed_column_stays_a_violation_with_its_reason(tmp, rec):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    history(rec, T0)
    rec.event("state_changed", T0 + 3.5, ctx=TC.ctx(30))             # a second with an event row only
    r = Rig(tmp, rec, path=V2_PATH, HOMEPROV_SIGN_KEY=priv, **STABLE)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.sql("ALTER TABLE states DROP COLUMN origin_idx")
    old = frozen_verify(tmp, r, sign_pubkey=pub)
    new = v2_verify(tmp, r, sign_pubkey=pub)
    with_states = [str(int(T0) + i) for i in (0, 1, 2)]
    assert flagged(old) == flagged(new) == with_states                # T0+3 (events only) still matches
    assert all(viol(new, s)["v2_reason"] == "committed_column_dropped" for s in with_states)
    assert viol(new, T0)["v2_dropped_columns"] == {"states": ["origin_idx"]}


@needs_crypto
def test_monitor_v2_fails_the_poll_closed_when_the_list_changes_within_it(tmp, rec, monkeypatch):
    priv, _pub, _k = TC._keypair(tmp, "monitor")
    history(rec, T0)
    r = Rig(tmp, rec, path=V2_PATH, HOMEPROV_SIGN_KEY=priv, **STABLE)
    assert not r.poll(T0 + 5.0).get("evidence_unobservable")
    rec.state("sensor.new", "1", T0 + 6.0)                            # the next poll reads a keylog range, then loads
    real = PC.current_columns
    calls = {"n": 0}

    def flip(M, db):                                                  # the second read of the poll sees another list
        calls["n"] += 1
        cols = real(M, db)
        return dict(cols, states=cols["states"] + ["phantom"]) if calls["n"] >= 2 else cols
    monkeypatch.setattr(r.M.PC, "current_columns", flip)
    out = r.poll(T0 + 10.0)
    assert calls["n"] >= 2
    assert out.get("evidence_unobservable") and out["reason"] == "load_failed"
    assert "changed within one poll" in out["detail"]["exc"]


# ================================================================================================ two signed roots
class AcceptingAnchor(TC.Anchor):
    """A dishonest anchor host: it stores every record, a second root for a sealed segment included."""

    def append(self, rec):
        self.bodies.append(json.dumps(rec, sort_keys=True).encode())
        return self.write(json.loads(self.bodies[-1]))


def state_loss(tmp, rec, priv, anchor=None, edit=True, late_row=False, path=None):
    """Monitor 1 seals; the hub edits (or a benign late row arrives); monitor 1 loses its state and a fresh monitor on a
    new scratch re-seals the re-read window, appending to the same anchor."""
    sid, eid = history(rec, T0)
    rec.state("sensor.t4", "1", T0 + 4.2)
    r1 = Rig(tmp, rec, name="m1", anchor=anchor, path=path, HOMEPROV_SIGN_KEY=priv, **STABLE)
    r1.poll(T0 + 5.0)
    if late_row:
        rec.state("sensor.t4", "2", T0 + 4.6)        # committed late for its second, after the copy of the poll at T0+5
    r1.poll(T0 + 10.0)
    if edit:
        rec.launder(sid, eid)
    n1 = len(r1.anchor.lines)
    r2 = Rig(tmp, rec, name="m2_fresh_scratch", anchor=r1.anchor, path=path, HOMEPROV_SIGN_KEY=priv, **STABLE)
    r2.polls(T0 + 15.0, T0 + 20.0)
    return r1, r2, n1


def orders(r, n1):
    """The chain as appended, and with every record of the restarted monitor served first."""
    lines = r.anchor.lines
    return {"as_appended": list(lines), "later_root_first": list(lines[n1:]) + list(lines[:n1])}


@needs_crypto
@pytest.mark.parametrize("anchor_kind", ["honest_first_write_wins", "accepting"])
def test_X8_two_signed_roots_violation_in_either_order(tmp, rec, anchor_kind):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    anchor = TC.Anchor() if anchor_kind == "honest_first_write_wins" else AcceptingAnchor()
    _r1, r2, n1 = state_loss(tmp, rec, priv, anchor=anchor)
    s = str(int(T0) + 1)
    got = {}
    for name, lines in orders(r2, n1).items():
        M = EV.load_monitor("stable", os.path.join(tmp, "o_" + name))
        db = os.path.join(tmp, "o_%s.db" % name)
        shutil.copy2(rec.path, db)
        old = VV._ORIG["verify"](M, db, lines, LATE, GAP, scheme="stable", sign_pubkey=pub)
        new = v2_verify(tmp, r2, lines=lines, sign_pubkey=pub)
        got[name] = (s in flagged(old), s in flagged(new), viol(new, s))
    assert got["as_appended"][0] is True                             # the first root is the honest one
    assert got["later_root_first"][0] is False                       # X8: the re-sealed root hides the edit
    for name in got:
        assert got[name][1] is True
        v = got[name][2]
        assert v["mechanism"] == v["v2_reason"] == "conflicting_roots" and len(v["conflicting_roots"]) == 2
        rep = {d["acc"]: d["reproduced_by_current_rows"] for d in v["conflicting_roots"]}
        assert sorted(rep.values()) == [False, True]                 # the current rows reproduce the re-seal only


@needs_crypto
def test_state_loss_without_a_change_gives_identical_roots_and_no_conflict(tmp, rec):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    _r1, r2, _n1 = state_loss(tmp, rec, priv, edit=False)
    old = frozen_verify(tmp, r2, sign_pubkey=pub)
    new = v2_verify(tmp, r2, sign_pubkey=pub)
    assert flagged(old) == flagged(new) == [] and comparable(old) == comparable(new)
    assert new["v2"]["conflict_rule"]["segments_with_two_or_more_signed_roots"] == {}


@needs_crypto
def test_state_loss_after_a_benign_late_row_is_a_conflict_under_the_strict_rule(tmp, rec):
    """The cost of the rule: an honest monitor that lost its state re-seals a second that gained a benign late row."""
    priv, pub, _k = TC._keypair(tmp, "monitor")
    _r1, r2, _n1 = state_loss(tmp, rec, priv, edit=False, late_row=True)
    s = str(int(T0) + 4)
    old = frozen_verify(tmp, r2, sign_pubkey=pub)
    new = v2_verify(tmp, r2, sign_pubkey=pub)
    assert s not in flagged(old) and any(x["key"].startswith("s:") for x in old["benign_late_rows"])
    assert flagged(new) == [s]
    v = viol(new, s)
    assert v["v2_reason"] == "conflicting_roots"
    assert all(d["reproduced_by_current_rows"] for d in v["conflicting_roots"])   # explained by the late row


@needs_crypto
def test_without_a_public_key_conflicts_are_listed_only(tmp, rec):
    priv, _pub, _k = TC._keypair(tmp, "monitor")
    _r1, r2, n1 = state_loss(tmp, rec, priv, anchor=AcceptingAnchor())
    lines = orders(r2, n1)["later_root_first"]
    M = EV.load_monitor("stable", os.path.join(tmp, "nk"))
    db = os.path.join(tmp, "nk.db")
    shutil.copy2(rec.path, db)
    old = VV._ORIG["verify"](M, db, lines, LATE, GAP, scheme="stable")
    new = v2_verify(tmp, r2, lines=lines)
    assert comparable(old) == comparable(new)
    cr = new["v2"]["conflict_rule"]
    assert not cr["applied"] and cr["why_not_applied"] and len(cr["unsigned_conflicts_listed_only"]) == 1


@needs_crypto
def test_conflict_rule_off_is_the_registered_verifier(tmp, rec):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    _r1, r2, n1 = state_loss(tmp, rec, priv, anchor=AcceptingAnchor())
    lines = orders(r2, n1)["later_root_first"]
    M = EV.load_monitor("stable", os.path.join(tmp, "off"))
    db = os.path.join(tmp, "off.db")
    shutil.copy2(rec.path, db)
    old = VV._ORIG["verify"](M, db, lines, LATE, GAP, scheme="stable", sign_pubkey=pub)
    new = v2_verify(tmp, r2, lines=lines, sign_pubkey=pub, conflict_rule="off")
    assert comparable(old) == comparable(new)


@needs_crypto
def test_state_loss_with_the_first_instance_withheld_is_the_residual(tmp, rec):
    """What v2 does not close: the host withholds every record of the instance that lost its state, so the only root on
    the chain is the re-seal of the edited second (Theorem 1's state assumption still covers this case)."""
    priv, pub, _k = TC._keypair(tmp, "monitor")
    _r1, r2, n1 = state_loss(tmp, rec, priv, anchor=AcceptingAnchor())
    lines = r2.anchor.lines[n1:]
    new = v2_verify(tmp, r2, lines=lines, sign_pubkey=pub)
    assert str(int(T0) + 1) not in flagged(new)
    assert new["v2"]["conflict_rule"]["segments_with_two_or_more_signed_roots"] == {}


# ================================================================================================ the CLI path
@needs_crypto
def test_run_v2_output_is_the_registered_output_plus_v2(tmp, rec):
    priv, pub, _k = TC._keypair(tmp, "monitor")
    sid, eid = rich_history(rec, T0)
    esc = os.path.join(tmp, "escrow")
    r = Rig(tmp, rec, HOMEPROV_SIGN_KEY=priv, HOMEPROV_ESCROW_DIR=esc, HOMEPROV_ROWBIND="1", **STABLE)
    r.polls(T0 + 5.0, T0 + 10.0)
    rec.state("sensor.late", "x", T0 + 1.9)                          # a late row
    rec.launder(sid, eid)
    r.polls(T0 + 15.0, T0 + 70.0)
    chain = os.path.join(tmp, "chain.jsonl")
    open(chain, "w").write("\n".join(r.anchor.lines) + "\n")
    snap = os.path.join(tmp, "snap.db")
    shutil.copy2(rec.path, snap)

    def args(**kw):
        a = VV.parser().parse_args(["verify", "--chain", chain, "--db", snap, "--late-bound", str(LATE),
                                    "--gap-s", str(GAP), "--scheme", "stable", "--sign-pubkey", pub,
                                    "--escrow", os.path.join(esc, "escrow.jsonl"),
                                    "--window", str(T0 - 10), str(T0 + 80)] + kw.pop("extra", []))
        a.pinned_json = None
        return a
    frozen = VV._ORIG["run"](args())
    for extra in ([], ["--pinned-columns-db", snap]):
        out, _res = VV.run_v2(args(extra=extra))
        v2 = out.pop("v2")
        assert json.dumps(out, sort_keys=True, default=str) == json.dumps(frozen, sort_keys=True, default=str)
        assert v2["code_sha256"]["registered_code_unchanged"]
    assert frozen["flagged_seconds"]


def test_monitor_v2_refuses_a_monitor_py_other_than_the_registered_one(tmp):
    d = os.path.join(tmp, "fake")
    os.makedirs(d)
    shutil.copy2(V2_PATH, os.path.join(d, "monitor_v2.py"))
    shutil.copy2(os.path.join(HERE, "pinned_columns.py"), os.path.join(d, "pinned_columns.py"))
    open(os.path.join(d, "monitor.py"), "w").write(open(os.path.join(HERE, "monitor.py")).read() + "\n# changed\n")
    with pytest.raises(SystemExit):
        TC.monitor_module(os.path.join(d, "monitor_v2.py"), os.path.join(tmp, "s"), os.path.join(tmp, "x.db"))
    assert hashlib.sha256(open(os.path.join(HERE, "monitor.py"), "rb").read()).hexdigest() == \
        "4b9931cb7d1cffae6485fb2b660b68d733da9f73e5c22c22ca7265d49ceaa9b7"
