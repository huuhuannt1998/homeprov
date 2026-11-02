"""E9 item A7: a dishonest anchor host against signed records (exp/stages/e9_dishonest_anchor.py's cases, on a small
signed chain built with the test rig).

    python3 -m pytest -q monitor/test_e9_dishonest.py

A monitor with a signing key seals a recorder; a sealed unlock is then laundered. The host rewrites the chain (relinked,
so its own links verify) by dropping, withholding, truncating, reordering or replaying records, by inserting unsigned
records whose roots and keylog ranges match the laundered recorder, by altering a signed record, or by interleaving
another monitor's signed records. Under the monitor's public key the laundered second is never verified as matching
(violation or unknown) and no untouched second becomes a violation; without the key the forged records hide it, which
is what the signatures prevent. Also: a prefix-ranked range that failed while every prefix still matches is reported as
a prefix collision; a row backdated after the last poll the host kept is not called benign.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from test_coverage import (GAP, LATE, T0, USER, V, Recorder, Rig, _keypair, ctx, needs_crypto, rec,  # noqa: E402
                           tmp, verify)

assert rec and tmp
spec = importlib.util.spec_from_file_location("e9_a7", os.path.join(REPO, "exp", "stages", "e9_dishonest_anchor.py"))
A7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A7)


def scenario(tmp, rec, name="m", priv=None):
    """Background rows every second; an unlock in T0+20 sealed, then laundered at T0+60."""
    r = Rig(tmp, rec, name=name, HOMEPROV_SIGN_KEY=priv, HOMEPROV_ROWBIND="1")
    for i in range(0, 120):
        rec.state("sensor.t", str(i), T0 + i + 0.4, ctx=ctx(300 + i))
        if i == 20:
            eid = rec.event("call_service", T0 + 20.5, ctx=ctx(1), usr=USER, data='{"domain":"lock"}')
            sid = rec.state("lock.front_door", "unlocked", T0 + 20.6, ctx=ctx(1), usr=USER)
        if i % 5 == 4:
            r.poll(T0 + i + 1.0)
        if i == 60:
            rec.launder(sid, eid)
    r.polls(T0 + 125.0, T0 + 140.0)
    return r


def run(tmp, rig, lines, pub):
    Mv = V.load_monitor(rig.M.SCHEME, os.path.join(tmp, "v%d" % len(lines)))
    db = os.path.join(tmp, "vdb_%d.db" % len(lines))
    shutil.copy2(rig.rec.path, db)
    return A7.annotate(V.verify(Mv, db, lines, LATE, GAP, scheme=rig.M.SCHEME, sign_pubkey=pub))


@pytest.fixture
def signed(tmp, rec):
    priv, pub, _k = _keypair(tmp, "mon")
    r = scenario(tmp, rec, priv=priv)
    return r, pub


TARGET = str(int(T0) + 20)


def outcomes(res, secs):
    return {s: A7.outcome(V, res, s) for s in secs}


@needs_crypto
@pytest.mark.parametrize("case", ["drop", "drop_all_evidence", "withhold", "truncate", "reorder", "replay",
                                  "forge_unsigned", "alter_signed"])
def test_a_dishonest_host_can_withhold_but_not_forge(tmp, signed, case):
    r, pub = signed
    recs = [json.loads(x) for x in r.anchor.lines]
    honest = run(tmp, r, r.anchor.lines, pub)
    secs = sorted({s for (g, s) in honest["checked"] if g == "second"}, key=int)
    h = outcomes(honest, secs)
    assert h[TARGET] == "violation"
    assert all(v in ("match", "violation_coarse_only") for s, v in h.items() if s != TARGET)
    groups = honest["groups"]
    Mf = V.load_monitor(r.M.SCHEME, os.path.join(tmp, "forger"))
    db = os.path.join(tmp, "forge.db")
    shutil.copy2(r.rec.path, db)
    t0, t1 = T0 + 15.0, T0 + 70.0
    if case == "withhold":
        t0 = T0 + 15.0 - 600.0                                # its 15-minute span then covers T0+15 .. T0+915
    host = A7.build(case, recs, [], {TARGET}, t0, t1, V, Mf, db, groups, b"host")
    res = run(tmp, r, A7.relink(host), pub)
    got = outcomes(res, secs)
    assert got[TARGET] in ("violation", "unknown")
    assert not any(got[s] == "violation" for s in secs if s != TARGET)     # no untouched second is framed
    if case in ("reorder", "replay", "forge_unsigned"):
        assert got == h                                    # nothing withheld: the same outcome
    if case in ("drop", "drop_all_evidence", "alter_signed"):
        assert got[TARGET] == "unknown"


@needs_crypto
def test_without_the_key_forged_records_hide_the_laundering(tmp, signed):
    r, pub = signed
    recs = [json.loads(x) for x in r.anchor.lines]
    honest = run(tmp, r, r.anchor.lines, pub)
    Mf = V.load_monitor(r.M.SCHEME, os.path.join(tmp, "forger"))
    db = os.path.join(tmp, "forge.db")
    shutil.copy2(r.rec.path, db)
    host = A7.relink(A7.build("forge_unsigned", recs, [], {TARGET}, T0, T0 + 140.0, V, Mf, db, honest["groups"],
                              b"host"))
    Mv = V.load_monitor(r.M.SCHEME, os.path.join(tmp, "nokey"))
    shutil.copy2(r.rec.path, os.path.join(tmp, "nk.db"))
    nokey = A7.annotate(V.verify(Mv, os.path.join(tmp, "nk.db"), host, LATE, GAP, scheme=r.M.SCHEME))
    assert A7.outcome(V, nokey, TARGET) == "match"
    assert A7.outcome(V, run(tmp, r, host, pub), TARGET) == "violation"


@needs_crypto
def test_another_monitors_signed_records_are_excluded(tmp, rec, signed):
    r, pub = signed
    priv2, _pub2, _k = _keypair(tmp, "other")
    rec2 = Recorder(os.path.join(tmp, "other.db"))
    r2 = scenario(tmp, rec2, name="other", priv=priv2)
    recs = [json.loads(x) for x in r.anchor.lines]
    other = [json.loads(x) for x in r2.anchor.lines]
    host = A7.relink(A7.build("cross_monitor", recs, other, {TARGET}, T0, T0 + 140.0, V, None, None, None, b"h"))
    res = run(tmp, r, host, pub)
    assert res["signatures"]["wrong_key"] and A7.outcome(V, res, TARGET) == "violation"


def test_a_prefix_ranked_range_that_fails_with_every_prefix_matching_is_a_collision(tmp, rec):
    r = Rig(tmp, rec)
    r.poll(T0 - 5.0)
    rec.state("sensor.a", "1", T0 + 0.5, ctx=ctx(1))
    rec.state("sensor.b", "1", T0 + 0.6, ctx=ctx(2))
    r.polls(T0 + 5.0, T0 + 10.0)
    p = json.loads(r.anchor.lines[1])
    e = p["payload"]["keylog"]["states"][0]
    assert e["n"] == 2 and "bind" not in e
    e["acc"] = "ab" * 32                                       # the fold no longer matches, no prefix differs
    r.anchor.lines[1] = json.dumps(p, sort_keys=True)
    (kv,) = verify(tmp, r)["keylog_violations"]
    assert kv["prefix_collision"] and not kv["localized"] and len(kv["suspects"]) == 2


def test_a_row_backdated_after_the_last_kept_poll_is_not_benign(tmp, rec):
    """The host cuts the chain right after the poll that sealed a second; a row backdated into that second just after
    it was sealed is then held by no known poll: not benign (its commit time has no upper bound), not attributable."""
    rec.state("sensor.a", "1", T0 + 0.5, ctx=ctx(1))
    r = Rig(tmp, rec)
    r.poll(T0 + 2.0)                                           # seals T0 and T0+1
    rec.state("lock.front_door", "unlocked", T0 + 1.5, ctx=ctx(2), usr=USER)
    r.polls(T0 + 7.0, T0 + 12.0)                               # these polls hold the row (wm >= its key)
    full = verify(tmp, r)
    assert [x["key"] for x in full["benign_late_rows"]] == ["s:2"]
    Mv = V.load_monitor(r.M.SCHEME, os.path.join(tmp, "vc"))
    db = os.path.join(tmp, "vc.db")
    shutil.copy2(r.rec.path, db)
    res = V.verify(Mv, db, r.anchor.lines[:1], LATE, GAP, scheme=r.M.SCHEME)
    assert res["benign_late_rows"] == [] and [x["key"] for x in res["unobserved_late_rows"]] == ["s:2"]
    assert str(int(T0) + 1) not in res["flagged_seconds"]
