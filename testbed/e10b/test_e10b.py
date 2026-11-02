"""Offline unit tests of E10b (no Docker, no network). Run with the pinned interpreter:

    <home>/miniconda3/bin/python3 -m pytest -q -p no:cacheprovider testbed/e10b/test_e10b.py

The add-on tests use the Home Assistant release installed for that interpreter (2026.2.3) and are skipped without it.
E10B_HA_SRC=<dir holding an extracted homeassistant/ package> adds a source check of another release (e.g. 2026.7.4).
"""
from __future__ import annotations

import ast
import asyncio
import collections
import importlib.util
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import e10b_plan as P                 # noqa: E402
import e10b_score as SC               # noqa: E402

RUNNER = os.path.join(HERE, "run_e10b.sh")
E10_RUNNER = os.path.join(REPO, "testbed", "e10", "run_e10.sh")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ================================================================================================ plan and schedule
def test_levels_counts_and_steps_are_e10s():
    e10 = _load(os.path.join(REPO, "testbed", "e10", "e10ops.py"), "e10ops_t")
    assert P.AGES == tuple(float(a) for a in e10.BDT_AGES) and P.N_PER_AGE == e10.BDT_N == 20
    assert P.CS_STEPS == tuple(e10.CS_STEPS) and P.CS_DURATION_S == e10.CS_DURATION_S
    plan = P.make_plan()
    b = plan["blocks"][0]
    assert b["op"] == "bdt" and b["spacing_s"] == 50.0 and b["pre_wait_s"] == 60.0
    assert collections.Counter(b["ages"]) == {a: 20 for a in P.AGES}
    assert [x["block"] for x in plan["blocks"]] == ["A1_BDT", "SNAP_BDT", "A6_CS2", "SNAP_CS_END"]
    assert plan["blocks"][2]["op"] == "clock_step_all" and plan["blocks"][2]["steps"] == list(e10.CS_STEPS)


def test_plan_is_deterministic():
    assert P.make_plan(P.SEED) == P.make_plan(P.SEED)
    assert P.make_plan(P.SEED)["blocks"][0]["ages"] != P.make_plan(P.SEED + 1)["blocks"][0]["ages"]


def test_schedule_bound_holds_for_the_registered_order_and_any_order():
    s = P.make_plan()["schedule"]
    assert s["ok"] and s["min_guaranteed_separation_s"] >= P.MIN_SEPARATION_S
    assert s["worst_case_any_order_s"] == 50.0 - 8.0 - 40.0 == P.MIN_SEPARATION_S


def test_e10s_spacing_could_collide():
    assert not P.schedule(P.make_plan()["blocks"][0]["ages"], spacing=15.0)["ok"]


def test_simulated_op_bdt_timing_never_collides():
    """op_bdt's timing (start_i, nxt = start_i + spacing, insert after delta_i, the slot waited out or overrun)."""
    rnd = random.Random(7)
    ages = P.make_plan()["blocks"][0]["ages"]
    for _ in range(300):
        start, targets = 1.8e9 + rnd.random() * 100, []
        for a in ages:
            delta = rnd.uniform(0.0, P.DELTA_MAX_S)
            t_ins = start + delta
            targets.append(t_ins - a)
            dur = delta + 0.5 + 3.0 + rnd.expovariate(1 / 2.0) + (rnd.random() < 0.02) * rnd.uniform(0, 80)
            start = max(start + P.SPACING_S, start + dur)
        assert P.realised_separation(targets)["collisions"] == []


def test_realised_separation_flags_equal_and_adjacent_seconds():
    assert P.realised_separation([100.2, 101.9, 300.0])["collisions"] == [[0, 1]]
    assert P.realised_separation([100.0, 101.99])["collisions"] == [[0, 1]]
    assert P.realised_separation([100.9, 102.0])["collisions"] == []
    assert P.realised_separation([5.5, 5.6])["collisions"] == [[0, 1]]


def test_smoke_plan():
    p = P.make_plan(smoke=True)
    assert collections.Counter(p["blocks"][0]["ages"]) == {a: 2 for a in P.AGES}
    steps = p["blocks"][2]["steps"]
    assert [s["marker"] for s in steps] == [True, False] and all(s["step_s"] == 60.0 for s in steps)


def test_plan_cli_prints_the_plan():
    r = subprocess.run([sys.executable, os.path.join(HERE, "e10b_plan.py"), "plan"], capture_output=True, text=True)
    assert r.returncode == 0 and json.loads(r.stdout) == json.loads(json.dumps(P.make_plan()))


# ================================================================================================ the prediction rule
def poll(seq, copy_at, ts=None, wm=0, unobs=False, epoch=0, backlog=False):
    return {"key": (epoch, seq), "epoch": epoch, "seq": seq, "copy_at": copy_at,
            "ts": copy_at + 0.001 if ts is None else ts, "wm": None if unobs else {"states": wm, "events": 0},
            "since": None if unobs else 0, "through": None if unobs else int(copy_at), "unobservable": unobs,
            "reason": "x" if unobs else None, "own": True, "in_backlog": backlog}


def regular(t0, n, period=5.0, dur=0.0):
    return [poll(i + 1, t0 + i * period, ts=t0 + i * period + dur) for i in range(n)]


T_INS = 1_800_000_100.0
T_COM = T_INS + 0.004


def test_direct_33s_detected_when_a_poll_copied_in_the_last_3s():
    ps = regular(T_INS - 61.0, 30)          # copies at T_INS - 1.0 (index 12) and every 5 s
    r = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 33.0)
    assert r["predicted"] == "detected" and abs(r["lower_bound_s"] - 32.0) < 1e-9


def test_direct_33s_reported_late_when_the_last_copy_is_4s_before():
    ps = regular(T_INS - 64.0, 30)          # last copy before the insert at T_INS - 4
    r = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 33.0)
    assert r["predicted"] == "reported_late" and abs(r["lower_bound_s"] - 29.0) < 1e-9


def test_direct_45s_detected_and_5s_reported_or_no_evidence():
    ps = regular(T_INS - 64.0, 30)
    assert SC.predict(ps, "direct", T_INS, T_COM, T_INS - 45.0)["predicted"] == "detected"
    assert SC.predict(ps, "direct", T_INS, T_COM, T_INS - 5.0)["predicted"] == "reported_late"   # copy at -4 >= sec+1
    ps2 = regular(T_INS - 60.3, 30)         # copies at -5.3 and -0.3: the second (T_INS - 5) is covered only at -0.3
    r = SC.predict(ps2, "direct", T_INS, T_COM, T_INS - 5.0)
    assert r["predicted"] == "reported_late"
    ps3 = [p for p in regular(T_INS - 60.3, 30) if not (T_INS - 1.0 < p["copy_at"] < T_INS)]
    assert SC.predict(ps3, "direct", T_INS, T_COM, T_INS - 5.0)["predicted"] == "no_evidence"


def test_direct_30s_with_a_copy_inside_the_write_is_ambiguous():
    ps = regular(T_INS - 60.0 + 0.002, 30)  # a copy at T_INS + 0.002, inside [t_insert, t_commit]
    r = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 30.0)
    assert r["predicted"] == "ambiguous" and set(r["alternatives"]) == {"detected", "reported_late"}
    ps2 = regular(T_INS - 62.0, 30)
    assert SC.predict(ps2, "direct", T_INS, T_COM, T_INS - 30.0)["predicted"] == "reported_late"


def test_copy_window_overlapping_the_insert_makes_33s_ambiguous():
    ps = regular(T_INS - 62.0, 30, dur=0.3)   # a copy from T_INS - 2.0 to T_INS - 1.7: ends before the insert
    assert SC.predict(ps, "copy", T_INS, T_COM, T_INS - 33.0)["predicted"] == "detected"
    ps2 = regular(T_INS - 62.0, 30, dur=2.2)  # the same copy now runs past the insert: may hold the row
    r = SC.predict(ps2, "copy", T_INS, T_COM, T_INS - 33.0)
    assert r["predicted"] == "ambiguous" and set(r["alternatives"]) == {"detected", "reported_late"}
    assert SC.predict(ps2, "direct", T_INS, T_COM, T_INS - 33.0)["predicted"] == "detected"   # direct: no window


def test_observation_break_gives_unknown_below_the_bound_only():
    ps = regular(T_INS - 64.0, 30)
    i = next(k for k, p in enumerate(ps) if p["copy_at"] > T_COM)     # the first poll after the commit
    ps[i] = poll(ps[i]["seq"], ps[i]["copy_at"], unobs=True)
    r15 = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 15.0)
    assert r15["predicted"] == "unknown" and "unobservable" in r15["why"]
    assert SC.predict(ps, "direct", T_INS, T_COM, T_INS - 45.0)["predicted"] == "detected"


def test_gap_above_gap_s_and_missing_poll_give_unknown():
    ps = [p for p in regular(T_INS - 64.0, 40) if not (T_INS < p["copy_at"] < T_INS + 35.0)]
    for k, p in enumerate(ps):                      # consecutive counters: only the time gap remains
        p["seq"], p["key"] = k + 1, (0, k + 1)
    r = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 15.0)
    assert r["predicted"] == "unknown" and "gap_above_gap_s" in r["why"]
    ps2 = regular(T_INS - 64.0, 30)
    j = next(k for k, p in enumerate(ps2) if p["copy_at"] > T_COM)
    for p in ps2[j:]:
        p["seq"] += 1
        p["key"] = (0, p["seq"])
    assert "poll_missing" in SC.predict(ps2, "direct", T_INS, T_COM, T_INS - 15.0)["why"]


def test_late_view_resolves_an_overlapping_copy_by_its_end():
    ps = regular(T_INS - 62.0, 30, dur=2.2)  # the copy from T_INS - 2.0 ends at T_INS + 0.2: late view -> holds the row
    assert SC.predict(ps, "copy", T_INS, T_COM, T_INS - 33.0)["predicted"] == "ambiguous"
    assert SC.predict_late_view(ps, "copy", T_INS, T_COM, T_INS - 33.0) == "reported_late"
    ps2 = regular(T_INS - 62.0, 30, dur=1.97)  # ends 30 ms before the insert (inside the 50 ms band): lacks the row
    assert SC.predict(ps2, "copy", T_INS, T_COM, T_INS - 33.0)["predicted"] == "ambiguous"
    assert SC.predict_late_view(ps2, "copy", T_INS, T_COM, T_INS - 33.0) == "detected"
    assert SC.predict_late_view(ps, "direct", T_INS, T_COM, T_INS - 33.0) == "detected"


def test_lower_bound_within_1ms_of_the_bound_is_ambiguous():
    ps = regular(T_INS - 63.0, 30)           # last copy before the insert at T_INS - 3.0
    r = SC.predict(ps, "direct", T_INS, T_COM, T_INS - 33.0 - 0.0004)
    assert r["predicted"] == "ambiguous" and r["why"] == "boundary_within_1ms"


def test_e10_frozen_rule_is_called_unchanged():
    ps = regular(T_INS - 61.0, 30)
    pred, lb = SC.e10_frozen_prediction(ps, T_COM, T_INS - 33.0)
    assert pred == "detected" and abs(lb - 32.0) < 1e-9


# ================================================================================================ own-row scoring
def fake_v(att=(), benign=(), unobs=(), flagged=()):
    def row(key, ts, lb, verdict):
        return {"key": key, "ts": ts, "second": str(int(ts)), "verdict": verdict, "committed_after_lower_bound_s": lb,
                "why": [{"gran": "second", "seg": str(int(ts)), "verdict": verdict, "why": "x"}]}
    return {"attributable_rows": [row(k, ts, lb, "attributable") for k, ts, lb in att],
            "benign_late_rows": [row(k, ts, lb, "benign_late") for k, ts, lb in benign],
            "unobserved_late_rows": [row(k, ts, lb, "unobserved_late") for k, ts, lb in unobs],
            "flagged_seconds": [str(s) for s in flagged], "root_unknown_segments": [], "keylog_violations": []}


def trial(i, age, key, t_ins):
    return {"trial": i, "age_s": age, "forged_state_id": key, "forged_row_ts": t_ins - age, "t_insert": t_ins,
            "t_commit": t_ins + 0.004, "attack_success_admin": True, "listed": True}


def test_own_outcome_mapping():
    v = fake_v(att=[("s:1", 100.5, 31.0)], benign=[("s:2", 200.5, 10.0)], unobs=[("s:3", 300.5, 5.0)], flagged=[100])
    S = SC.S10.sets(v)
    assert SC.own_outcome(S, v, "s:1", 100.5)["outcome"] == "detected"
    assert SC.own_outcome(S, v, "s:1", 100.5)["second_flagged"] is True
    assert SC.own_outcome(S, v, "s:2", 200.5)["outcome"] == "reported_late"
    assert SC.own_outcome(S, v, "s:3", 300.5)["outcome"] == "unknown"
    assert SC.own_outcome(S, v, "s:4", 400.5)["outcome"] == "no_evidence"
    assert SC.own_outcome(None, None, "s:4", 400.5)["outcome"] == "verification_failed"


def test_score_bdt_agreement_consistency_and_collision_exclusion():
    t1 = trial(0, 33.0, 11, T_INS)
    t2 = trial(1, 15.0, 12, T_INS + 50.0)
    t3 = trial(2, 45.0, 13, T_INS + 100.0)
    t4 = trial(3, 15.0, 14, T_INS + 100.0 - 29.5)     # its target lies 0.5 s from t3's: both excluded
    ps = regular(T_INS - 61.0, 60)
    ts1, ts2, ts3 = t1["forged_row_ts"], t2["forged_row_ts"], t3["forged_row_ts"]
    v = fake_v(att=[("s:11", ts1, 32.0), ("s:13", ts3, 44.0)], benign=[("s:12", ts2, 14.0)],
               flagged=[int(ts1), int(ts3)])
    sec = SC.score_bdt([t1, t2, t3, t4], {"direct": ps}, {"direct": v}, modes=("direct",))
    rows = {r["trial"]: r for r in sec["per_trial"]}
    assert rows[0]["direct"]["predicted"] == "detected" and rows[0]["direct"]["agrees"] is True
    assert rows[0]["direct"]["segment_consistent"] is True and rows[0]["direct"]["lower_bound_equal"] is True
    assert rows[1]["direct"]["predicted"] == "reported_late" and rows[1]["direct"]["agrees"] is True
    assert rows[2]["excluded"] and rows[3]["excluded"] and rows[2]["direct"]["agrees"] is None
    v2 = fake_v(att=[("s:11", ts1, 32.0)], benign=[("s:12", ts2, 14.0)], flagged=[int(ts1), int(ts2)])
    sec2 = SC.score_bdt([t1, t2], {"direct": ps}, {"direct": v2}, modes=("direct",))
    assert sec2["per_trial"][1]["direct"]["segment_consistent"] is False
    summ = SC.summarise_bdt(sec2, modes=("direct",))
    assert summ["hypotheses"]["direct"]["H1b_seg_inconsistent_trials"] == [1]
    assert summ["hypotheses"]["direct"]["H1b_all_non_ambiguous_trials_agree"] is True


def test_block_conditions(tmp_path):
    hl = tmp_path / "hostlog.jsonl"
    hl.write_text("\n".join(json.dumps(x) for x in [
        {"kind": "sample", "ts": 150.0},
        {"kind": "wall_gap", "ts": 160.0, "gap_s": 120.0},
        {"kind": "hub_state", "ts": 170.0, "started_at": "B", "previous_started_at": "A"},
        {"kind": "hub_state", "ts": 400.0, "started_at": "C", "previous_started_at": "B"}]) + "\n")
    r = {"direct": 0, "copy": 0, "hub_started_at": "A"}
    ev = [{"type": "block_begin", "block": "A1_BDT", "ts": 100.0, "restarts": r},
          {"type": "block_end", "block": "A1_BDT", "ts": 300.0, "restarts": dict(r, copy=1, hub_started_at="B")},
          {"type": "block_begin", "block": "A6_CS2", "ts": 350.0, "restarts": r},
          {"type": "hub_restart", "ts": 390.0},
          {"type": "block_end", "block": "A6_CS2", "ts": 500.0, "restarts": r}]
    out = SC.block_conditions(ev, str(hl))
    a, c = out["A1_BDT"], out["A6_CS2"]
    assert not a["pooled"] and a["monitor_restarts"] == {"direct": 0, "copy": 1}
    assert len(a["wall_gaps_over_90s"]) == 1 and len(a["hub_starts_without_cause"]) == 1
    assert c["pooled"] and c["hub_starts_without_cause"] == []


def test_scorer_main_end_to_end_with_a_stubbed_verifier(tmp_path, monkeypatch):
    """The scorer's glue on a synthetic run directory (the verifier is stubbed; it runs for real in the smoke)."""
    sp = tmp_path / "run"
    (sp / "e10").mkdir(parents=True)
    (sp / "e10bs" / "snapshots").mkdir(parents=True)
    t0 = 1_800_000_000.0
    db = sp / "e10bs" / "snapshots" / "snap.db"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE states (state_id INTEGER PRIMARY KEY, last_updated_ts REAL)")
    c.execute("CREATE TABLE events (event_id INTEGER PRIMARY KEY, time_fired_ts REAL)")
    c.commit()
    c.close()
    (sp / "e10bs" / "t_start").write_text("%d\n" % t0)
    trials = [trial(0, 33.0, 101, t0 + 101.0), trial(1, 15.0, 102, t0 + 151.0), trial(2, 45.0, 103, t0 + 201.0)]
    (sp / "e10" / "b002aaaaaa_bdt.json").write_text(json.dumps({"op": "bdt", "t_started": t0 + 60, "trials": trials}))
    snaps = [{"type": "snapshot", "ok": True, "stack": "e10bs", "label": lab, "t_snapshot": t0 + 400 + i,
              "file": "e10bs/snapshots/snap.db"} for i, lab in enumerate(("snap_bdt", "final"))]
    (sp / "events.jsonl").write_text("\n".join(json.dumps(e) for e in snaps) + "\n")
    (sp / "plan.json").write_text(json.dumps(P.make_plan(smoke=True)))
    lines = []
    for m in ("direct", "copy"):
        recs = []
        for i in range(90):
            ca = t0 + i * 5.0
            recs.append(json.dumps({"seq": i, "payload": {"observer": "external-monitor", "coverage": 2,
                                    "seq_local": i + 1, "ts": ca + 0.1, "copy_at": ca, "since": 0, "through": int(ca),
                                    "wm": {"states": 100 + sum(1 for t in trials if t["t_commit"] < ca), "events": 0}}}))
        (sp / "e10bs" / ("%s_chain.jsonl" % m)).write_text("\n".join(recs) + "\n")
    ts = {t["forged_state_id"]: t["forged_row_ts"] for t in trials}
    v = fake_v(att=[("s:101", ts[101], 32.0), ("s:103", ts[103], 44.0)], benign=[("s:102", ts[102], 14.0)],
               flagged=[int(ts[101]), int(ts[103])])
    monkeypatch.setattr(SC.S10, "verify_job", lambda sp_, stack, m, label, *a: ((stack, m, label), v))
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(sys, "argv", ["e10b_score.py", "--run-dir", str(sp), "--tag", "e10b_smoke9",
                                      "--out-dir", str(out), "--jobs", "1"])
    assert SC.main() == 0
    res = json.loads((out / "e10b_smoke9_score.json").read_text())
    rows = res["arms"]["H1b_BDT"]["per_trial"]
    assert [r["direct"]["observed"]["outcome"] for r in rows] == ["detected", "reported_late", "detected"]
    assert all(r["direct"]["agrees"] for r in rows), [r["direct"]["predicted"] for r in rows]
    assert res["arms"]["H1b_BDT"]["summary"]["hypotheses"]["copy"]["H1b_seg_all_consistent"] is True
    assert res["arms"]["floor"]["direct"]["unexplained_flagged_seconds"] == 0
    assert res["arms"]["H1b_late_view_copy"]["all_trials"] == {"n": 3, "agree": 3, "disagree": []}
    with pytest.raises(SystemExit):
        SC.main()                                      # never overwrites


# ================================================================================================ the chain reader
def test_chain_polls_streams_epochs_backlog_and_continuations(tmp_path):
    def rec(seq, ts, copy_at, wm, part=None, backlog=None, unobs=False):
        p = {"observer": "external-monitor", "coverage": 2, "seq_local": seq, "ts": ts, "copy_at": copy_at,
             "wm": wm, "since": 0, "through": int(copy_at)}
        if part:
            p["part"] = part
        if backlog:
            p["backlog"] = backlog
        if unobs:
            p.update(evidence_unobservable=True, wm=None, through=None)
        return json.dumps({"seq": seq, "payload": p})
    lines = [json.dumps({"payload": {"marker": "CLOCK_STEP"}}),
             rec(1, 100.2, 100.0, {"states": 5}), rec(1, 100.2, 100.0, {"states": 5}, part=2),
             rec(2, 105.2, 105.0, {"states": 6}, unobs=True),
             rec(4, 115.2, 115.0, {"states": 7}, backlog=[{"seq_local": 3, "ts": 110.2, "copy_at": 110.0,
                                                           "wm": {"states": 6}, "since": 0, "through": 110}]),
             rec(1, 200.2, 200.0, {"states": 9}),            # a lower counter later in time: a new epoch
             rec(2, 900.2, 900.0, {"states": 9})]            # after the snapshot
    path = tmp_path / "chain.jsonl"
    path.write_text("\n".join(lines) + "\n")
    ps = SC.chain_polls(str(path), tsnap=300.0)
    keys = [p["key"] for p in ps]
    assert keys == [(0, 1), (0, 2), (0, 3), (0, 4), (1, 1)]
    by = {p["key"]: p for p in ps}
    assert by[(0, 2)]["unobservable"] and by[(0, 3)]["in_backlog"] and not by[(0, 4)]["in_backlog"]
    assert by[(0, 1)]["own"] and by[(1, 1)]["wm"] == {"states": 9}


# ================================================================================================ H10b scoring
def test_cs2_scoring_on_a_small_recorder(tmp_path):
    db = str(tmp_path / "r.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE states (state_id INTEGER PRIMARY KEY, last_updated_ts REAL)")
    c.execute("CREATE TABLE events (event_id INTEGER PRIMARY KEY, time_fired_ts REAL)")
    t_on = 1000.0
    c.executemany("INSERT INTO states VALUES (?, ?)", [(1, 900.0), (2, t_on - 50), (3, t_on - 20), (4, t_on - 1.0),
                                                        (5, t_on + 61)])
    c.executemany("INSERT INTO events VALUES (?, ?)", [(1, t_on - 40), (2, t_on - 10)])
    c.commit()
    c.close()
    step = {"command": {"step": 0, "marker": True, "step_s": 60.0}, "step_s": 60.0, "t_on": t_on, "t_off": t_on + 60,
            "wm_before": {"states": 1, "events": 0}, "wm_after": {"states": 5, "events": 2}}
    v_ok = {"attributable_rows": [], "benign_late_rows": [], "unobserved_late_rows": [], "flagged_seconds": [],
            "root_unknown_segments": [], "keylog_violations": [],
            "clock_step": {"excused_rows": [{"key": k} for k in ("s:2", "s:3", "e:1", "e:2")]}}
    out = SC.score_cs2([step], db, {"direct": v_ok}, modes=("direct",))[0]
    assert out["manipulation_stepped_state_rows"] == 2 and out["evaluable"]
    assert out["direct"]["states"]["agrees"] is True and out["direct"]["events"]["agrees"] is True
    assert out["rows"]["states"] == {"stepped": 2, "boundary": 1, "after": 1}
    v_bad = dict(v_ok, clock_step={"excused_rows": [{"key": "s:2"}]},
                 attributable_rows=[{"key": "s:3", "second": str(int(t_on - 20)), "why": []}])
    assert SC.score_cs2([step], db, {"direct": v_bad}, modes=("direct",))[0]["direct"]["states"]["agrees"] is False
    step10 = dict(step, command={"step": 4, "marker": False}, step_s=10.0)
    assert SC.score_cs2([step10], db, {"direct": v_ok}, modes=("direct",))[0]["direct"]["states"]["agrees"] is True


# ================================================================================================ homeprov_e10b
# [Withheld from the artifact: the tests of the E10b in-hub add-on (testbed/e10b/homeprov_e10b, not released): they load it and check how it steps the hub's clock and how it registers its operation. See README.md, "What is deliberately not here".]


# ================================================================================================ the runner
def _main_body(path):
    return open(path).read()


def test_runner_parses_with_macos_bash_and_is_one_function():
    assert subprocess.run(["/bin/bash", "-n", RUNNER]).returncode == 0
    lines = [x for x in _main_body(RUNNER).splitlines() if x.strip() and not x.lstrip().startswith("#")]
    assert lines[0] == "main() {" and lines[-1] == 'main "$@"; exit $?' and lines[-2] == "}"
    assert "exec </dev/null" in _main_body(RUNNER)


def _brace_hits(text):
    """Lines with a brace list ({a,b}) inside a double-quoted string inside a command substitution (bash 3.2 expands
    it there: E10 smoke e10_smoke1)."""
    bad = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(r'\$\(', line):
            depth, i, inner, sq = 1, m.end(), [], False
            while i < len(line) and depth:      # parentheses outside single quotes (Python code keeps them balanced)
                ch = line[i]
                if ch == "'":
                    sq = not sq
                elif not sq:
                    depth += ch == "("
                    depth -= ch == ")"
                inner.append(ch)
                i += 1
            seg = re.sub(r"'[^']*'", "''", "".join(inner))      # single-quoted text is never brace-expanded
            for q in re.findall(r'"((?:[^"\\]|\\.)*)"', seg):
                if re.search(r"(?<!\$)\{[^{}]*,[^{}]*\}", q):     # ${name:+, x} is a parameter expansion
                    bad.append((n, line.strip()[:120]))
    return bad


def test_runner_has_no_brace_list_in_a_double_quoted_string_inside_a_command_substitution():
    assert _brace_hits(_main_body(RUNNER)) == []
    # the check itself: the E10 smoke e10_smoke1 shape is caught, the bcmd fix and a parameter expansion are not
    assert _brace_hits('F=$(e10_cmd "$("$PY" -c "import json;print({\'op\':\'bdt\',\'ages\':[1]})")" 7200)')
    assert not _brace_hits('d=$("$PY" -c \'import json,sys;print({"op":sys.argv[1],"x":2})\' bdt)')
    assert not _brace_hits('x=$(printf "%s" "${2:+, $2}")')


def _func(path, name):
    src = open(path).read()
    m = re.search(r"^\s*%s\(\) \{\n.*?^\}\n" % re.escape(name), src, re.S | re.M)
    return m.group(0) if m else None


def test_runner_event_guard_is_e10s_and_keeps_one_object_per_line(tmp_path):
    ev10, ev10b = _func(E10_RUNNER, "ev"), _func(RUNNER, "ev")
    assert ev10 and ev10b and ev10.strip() == ev10b.strip()
    log = tmp_path / "events.jsonl"
    script = ev10b + 'ev good "\\"x\\": 1"\nev bad "\\"x\\": 0\nnull"\nev empty\n'
    env = dict(os.environ, PY=sys.executable, EVLOG=str(log))
    r = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    recs = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(recs) == 3 and recs[0]["x"] == 1 and recs[1]["malformed"] is True and recs[2]["type"] == "empty"


def _run(args, env_extra, tmp_path):
    env = dict(os.environ)
    env.update({"HPR_E10B_OUT": str(tmp_path / "out"), "HPR_E10B_REFUSALS_ONLY": "1"})
    env.update(env_extra)
    return subprocess.run(["/bin/bash", RUNNER] + args, env=env, capture_output=True, text=True, timeout=60)


def test_runner_refuses_bad_tags_and_mode_mixups(tmp_path):
    assert _run([], {}, tmp_path).returncode == 2
    assert _run(["e10_main"], {}, tmp_path).returncode == 2
    assert _run(["e10b_main"], {"HPR_E10B_SMOKE": "1"}, tmp_path).returncode == 2
    assert _run(["e10b_smoke1"], {"HPR_E10B_SMOKE": "0"}, tmp_path).returncode == 2
    assert _run(["e10b_smoke1x"], {"HPR_E10B_SMOKE": "1"}, tmp_path).returncode == 2


def test_runner_refuses_an_existing_run_directory_or_output(tmp_path):
    sp = tmp_path / "sp"
    sp.mkdir()
    r = _run(["e10b_smoke1"], {"HPR_E10B_SMOKE": "1", "HPR_E10B_SP": str(sp)}, tmp_path)
    assert r.returncode == 3 and "exists" in r.stdout
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "e10b_smoke1_score.json").write_text("{}")
    r = _run(["e10b_smoke1"], {"HPR_E10B_SMOKE": "1", "HPR_E10B_SP": str(tmp_path / "sp2")}, tmp_path)
    assert r.returncode == 3 and "outputs" in r.stdout and not (tmp_path / "sp2").exists()
    r = _run(["e10b_smoke1"], {"HPR_E10B_SMOKE": "1", "HPR_E10B_SP": str(tmp_path / "sp3"),
                               "HPR_E10B_OUT": str(tmp_path / "out_empty")}, tmp_path)
    assert r.returncode == 0 and "refusals passed" in r.stdout and not (tmp_path / "sp3").exists()


# ================================================================================================ the registration
def test_draft_registration(tmp_path):
    out = tmp_path / "draft.json"
    r = subprocess.run([sys.executable, os.path.join(HERE, "e10b_prereg.py"), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    d = json.loads(out.read_text())
    assert d["status"] == "DRAFT" and d["registered_at"] is None
    plan_text = json.dumps(P.make_plan(), indent=1, sort_keys=True) + "\n"
    import hashlib
    assert d["plan"]["sha256"] == hashlib.sha256(plan_text.encode()).hexdigest()
    assert all(v is not None for v in d["code_sha256"]["files"].values())
    assert "testbed/e10b/run_e10b.sh" in d["code_sha256"]["files"] and "monitor/monitor.py" in d["code_sha256"]["files"]
    assert subprocess.run([sys.executable, os.path.join(HERE, "e10b_prereg.py"), "--check", str(out)],
                          capture_output=True).returncode == 1
    r2 = subprocess.run([sys.executable, os.path.join(HERE, "e10b_prereg.py"), "--out", str(out)],
                        capture_output=True, text=True)
    assert r2.returncode != 0 and "FileExistsError" in r2.stderr
