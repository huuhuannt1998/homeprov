"""Static tests of E10's review-r5 additions (drafts/round13/E10_ADDENDUM_R5.md): no Docker, no network, nothing run against
the lab. Plans and schedules, the restart timing rule, the scorers' logic on synthetic inputs, the sham's code paths (by
AST: the edit disabled, everything else the attack's), the pairwise plan, classifier, coverage tracer and pair
apply/restore on a synthetic SQLite file, the Pi-4 profiles and docker-argument insertion, the switch-type prediction.

    <home>/miniconda3/bin/python3 -m pytest -q testbed/e10/test_e10_r5.py
"""
from __future__ import annotations

import argparse
import ast
import collections
import importlib.util
import itertools
import json
import os
import sqlite3
import subprocess
import sys

import pytest

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
PAPER = R + "/[READY] (TDSC) HOMEPROV - P13"
for p in ("testbed/e10", "exp/stages", "exp/sp2027", "exp"):
    sys.path.insert(0, os.path.join(R, p))
import e10ops  # noqa: E402
import e10r5_score as S5  # noqa: E402
import e10_pairwise_closure as PW  # noqa: E402
import e10_pi4_cost as PI  # noqa: E402
import e10_dz_switchtype as DZS  # noqa: E402

HE10 = os.path.join(R, "testbed/real/ha-config/custom_components/homeprov_e10/__init__.py")
E8_JSON = os.path.join(R, "exp/out/e8_closure_real.json")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ================================================================================================ the plan (S, R)
def block(plan, name):
    return next(b for b in plan["blocks"] if b["block"] == name)


def test_original_orders_unchanged_by_the_additions():
    """The r5 draws come after the original ones, so the A1/A2/A3 orders are those of the 2026-10-12 make_plan (its
    first three shuffles, recomputed here) and the first ages of the 2026-10-12 draft (45, 15, 15, 5, 30, 33)."""
    import random
    rnd = random.Random(20261020)
    bdt = [a for a in e10ops.BDT_AGES for _ in range(e10ops.BDT_N)]
    rnd.shuffle(bdt)
    ctx = [d for d in e10ops.CTX_DELAYS for _ in range(e10ops.CTX_N)]
    rnd.shuffle(ctx)
    dl = [d for d in e10ops.DEL_DELAYS for _ in range(e10ops.DEL_N)]
    rnd.shuffle(dl)
    new = e10ops.make_plan(20261020)
    assert block(new, "A1_BDT")["ages"] == bdt and block(new, "A2_CTX")["delays"] == ctx
    assert block(new, "A3_DEL")["delays"] == dl
    assert bdt[:6] == [45.0, 15.0, 15.0, 5.0, 30.0, 33.0] and ctx[:3] == [5.0, 5.0, 45.0] and dl[:3] == [2.0, 1.0, 5.0]


def test_sham_block():
    p = e10ops.make_plan(20261020)
    names = [b["block"] for b in p["blocks"]]
    i = names.index("S_SHAM")
    assert names[i - 1] == "SNAP_DEL" and names[i + 1] == "SNAP_SHAM" and names[i + 2] == "A3_LOWKEY"
    tr = block(p, "S_SHAM")["trials"]
    assert len(tr) == 90
    c = collections.Counter((t["variant"], t["level"]) for t in tr)
    assert c == {("S-BDT", 45.0): 30, ("S-CTX", 45.0): 30, ("S-DEL", 10.0): 30}
    assert [t["variant"] for t in tr] != sorted(t["variant"] for t in tr)          # interleaved (seeded)
    b = block(p, "S_SHAM")
    assert (b["spacing_bdt_s"], b["spacing_ctx_s"], b["spacing_del_s"]) == (15.0, 5.0, 8.0)   # A1, A2, A3 spacings
    # the levels are those at which the attack arms are predicted detected
    assert 45.0 in e10ops.BDT_AGES and 45.0 in e10ops.CTX_DELAYS and 10.0 in e10ops.DEL_DELAYS
    assert e10ops.make_plan(20261020) == p                                          # deterministic


def test_restart_block():
    p = e10ops.make_plan(20261020)
    names = [b["block"] for b in p["blocks"]]
    i = names.index("R_RESTART")
    assert names[i - 1] == "SNAP_WIPE" and names[i + 1] == "SNAP_RESTART" and names[i + 2] == "A6_CS"
    tr = block(p, "R_RESTART")["trials"]
    assert collections.Counter((t["kind"], t["target"]) for t in tr) == {("graceful", "direct"): 4,
                                                                        ("kill", "direct"): 3, ("graceful", "copy"): 3}
    s = e10ops.make_plan(20261020, smoke=True)
    assert len(block(s, "R_RESTART")["trials"]) == 2 and len(block(s, "S_SHAM")["trials"]) == 18


def test_new_blocks_cannot_excuse_flagged_seconds_in_the_floor():
    """e10_score.floor() treats blocks starting A4_/A5_/A6_/A7_/B as row-changing windows; S and R must not be."""
    for n in ("S_SHAM", "R_RESTART", "SNAP_SHAM", "SNAP_RESTART"):
        assert not n.startswith(("A4_", "A5_", "A6_", "A7_", "B"))


# ================================================================================================ restart timing
def cost_lines(t0=1000.0, n=12, per=5.1, copy_ms=1.0, load=35.0, commit=45.0):
    return [{"seq_local": i, "ts": t0 + i * per, "copy_ms": copy_ms, "load_ms": load, "commit_ms": commit, "ok": True}
            for i in range(n)]


def test_predict_window_direct_and_copy():
    cl = cost_lines()
    last = cl[-1]["ts"]
    w = e10ops.predict_window(cl, "direct", now_vm=last + 0.2)
    assert w["next_ts"] == pytest.approx(last + 5.1) and w["spacing_s"] == pytest.approx(5.1)
    assert w["start"] == pytest.approx(last + 5.1 - 0.001) and w["end"] == pytest.approx(last + 5.1 + 0.080)
    w2 = e10ops.predict_window(cl, "direct", now_vm=last + 4.5)       # too close: the window after next
    assert w2["next_ts"] == pytest.approx(last + 10.2)
    c = e10ops.predict_window(cost_lines(copy_ms=3900.0, per=9.0), "copy", now_vm=1000 + 11 * 9.0)
    assert c["end"] - c["start"] == pytest.approx(3.9) and c["end"] == pytest.approx(c["next_ts"])
    assert e10ops.predict_window(cl[:3], "direct", 0) is None


def test_fire_time_and_landing():
    w = {"start": 100.0, "end": 100.08}
    assert e10ops.fire_time_vm(w, "kill", 2.0) == pytest.approx(100.04 - e10ops.KILL_LATENCY_S)
    assert e10ops.fire_time_vm(w, "graceful", 2.0) == pytest.approx(98.04)
    wins = e10ops.cost_windows_of(cost_lines(), "direct")
    assert e10ops.landed(1000.0 + 5.1 * 3 + 0.03, wins) is not None
    assert e10ops.landed(1000.0 + 5.1 * 3 + 2.0, wins) is None
    assert e10ops.docker_ts("2026-10-20T05:12:33.250000000Z") == pytest.approx(1792473153.25)
    assert e10ops.docker_ts("0001-01-01T00:00:00Z") is None


# ================================================================================================ arm S scoring
def S(flagged=(), unknown=(), verdict=None, keylog=()):
    return {"flagged": {str(x) for x in flagged}, "unknown": {str(x) for x in unknown}, "verdict": verdict or {},
            "keylog": set(keylog), "keylog_seconds": set()}


def sham_trials():
    out = []
    for i in range(3):
        out.append({"arm": "S-BDT", "trial": i, "age_s": 45.0, "would_be_second": 2000 + i, "db_writes": 0})
        out.append({"arm": "S-CTX", "trial": 10 + i, "delay_s": 45.0, "would_be_second": 3000 + i, "db_writes": 0,
                    "unlock_row": {"state_id": 50 + i, "ts": 3100.5 + i}, "displayed_cause_changed_admin": False})
        out.append({"arm": "S-DEL", "trial": 20 + i, "delay_s": 10.0, "would_be_second": 4000 + i, "rows_deleted": 0,
                    "deleted_row": {"state_id": 70 + i, "ts": 4000.2 + i}, "listed": True})
    return out


def test_score_sham_counts_and_confusion():
    tr = sham_trials()
    clean = {m: S() for m in S5.MONITORS}
    bad = {"direct": S(flagged=[3001]), "copy": S(keylog=["s:70"])}       # one CTX trial, one DEL trial violated
    att = {"bdt": [{"age_s": 45.0, "forged_row_ts": 10.5, "forged_state_id": 1}],
           "ctx": [{"delay_s": 45.0, "inserted_ts": 20.2, "inserted_event_id": 2}],
           "del": [{"delay_s": 10.0, "deleted_row": {"ts": 30.1, "state_id": 3}}]}
    sdel = {m: S(flagged=[10, 20, 30]) for m in S5.MONITORS}
    r = S5.score_sham(tr, att, clean, sdel)
    assert r["overall"]["direct"]["k"] == 0 and r["overall"]["direct"]["n"] == 9
    cm = r["confusion_at_target_seconds"]["direct"]["S-CTX"]
    assert cm["attack_violated"] == 1 and cm["sham_not_violated"] == 3
    r2 = S5.score_sham(tr, att, bad, sdel)
    assert r2["overall"]["direct"]["k"] == 1 and r2["overall"]["copy"]["k"] == 1
    assert r2["per_variant"]["S-CTX"]["direct"]["violations"]["k"] == 1
    assert r2["per_variant"]["S-DEL"]["copy"]["violations"]["k"] == 1
    # the trial's own actuation row attributable counts too
    r3 = S5.score_sham(tr, att, {"direct": S(verdict={"s:51": ("attributable", {})}), "copy": S()}, sdel)
    assert r3["overall"]["direct"]["k"] == 1
    # an err trial is listed, not scored
    r4 = S5.score_sham(tr + [{"arm": "S-DEL", "trial": 99, "err": "lock unavailable"}], att, clean, sdel)
    assert len(r4["errors"]) == 1 and r4["overall"]["direct"]["n"] == 9


def test_sham_zero_of_ninety_bound():
    from rig import stats
    r = stats.clopper_pearson(0, 90)
    assert r["ci_hi"] == pytest.approx(0.0402, abs=2e-4)                      # two-sided 95% (as Table 1)
    assert 1 - 0.05 ** (1 / 90) == pytest.approx(0.0327, abs=1e-4)          # one-sided 95%


# ================================================================================================ arm R scoring
class FakePolls:
    def __init__(self, polls, runs=()):
        self.polls, self._runs = polls, list(runs)

    def unobservable_runs(self):
        return [dict(r) for r in self._runs]


def test_score_restarts():
    cl = {m: cost_lines() for m in S5.MONITORS}
    t_kill_vm = 1000.0 + 5.1 * 4 + 0.03                                     # inside the 5th direct read window
    ev = [{"type": "restart_trial", "trial": 0, "kind": "kill", "target": "direct",
           "result": {"ok": True, "kind": "kill", "t_fire_mac": t_kill_vm - 0.5, "vm_offset_s": 0.5,
                      "started_at_ts": t_kill_vm + 30.0}},
          {"type": "restart_trial", "trial": 1, "kind": "graceful", "target": "copy",
           "result": {"ok": True, "kind": "graceful", "t_fire_mac": 1100.0, "vm_offset_s": 0.0,
                      "finished_at_ts": 1102.0, "started_at_ts": 1110.0}},
          {"type": "restart_trial", "trial": 2, "kind": "graceful", "target": "direct", "result": {"ok": False}}]
    polls = {m: FakePolls([{"copy_at": 1000.0 + 5.1 * i, "unobservable": i == 6, "reason": "read_raced"}
                           for i in range(40)], runs=[{"from": 1030.6, "to": 1030.6, "duration_s": 5.1,
                                                       "reasons": {"read_raced": 1}}]) for m in S5.MONITORS}
    Sp = {"direct": S(verdict={"s:9": ("benign_late", {"second": "1021", "lat": 3.2})}),
          "copy": S(verdict={"s:9": ("unobserved_late", {"second": "1021"})})}
    Se = {m: S(verdict={"s:9": ("benign_late", {"second": "1021"})}) for m in S5.MONITORS}
    r = S5.score_restarts(ev, cl, Sp, Se, polls, hub_starts=[1010.0])
    t0 = r["per_trial"][0]
    assert t0["landed_in_target"] is True and t0["direct"]["rows_patched"]["by_verdict"] == {"benign_late": 1}
    assert t0["copy"]["rows_patched"]["by_verdict"] == {"unobserved_late": 1}
    assert r["per_trial"][2]["unscored"]
    assert r["summary"]["direct"]["attributable_rows_patched"] == 0 and r["summary"]["scored"] == 2
    assert r["summary"]["direct"]["suspicious_intervals"] == 0             # 5.1 s and near a hub start


# ================================================================================================ the sham's code path (AST)
def _fn(tree, name):
    return next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


def _calls(nodes):
    out = set()
    for n in nodes:
        for c in ast.walk(n):
            if isinstance(c, ast.Call):
                f = c.func
                out.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None)
    return out


def _strings(nodes):
    return {c.value for n in nodes for c in ast.walk(n) if isinstance(c, ast.Constant) and isinstance(c.value, str)}


# [Withheld from the artifact: two static tests that read the source of the E10 in-hub adversary (homeprov_e10, not released) and check its internal structure: where the sham flag disables the edit, and how its command loop ignores a stale command after a restart. See README.md, "What is deliberately not here".]


def test_display_rule_still_identical():
    import e10_score
    assert e10_score.display_src_identity() is True


# ================================================================================================ arm D (pairwise)
@pytest.fixture(scope="module")
def e8():
    return json.load(open(E8_JSON))


@pytest.fixture(scope="module")
def plan(e8):
    return PW.make_plan(e8)


def test_pairwise_plan_frame(e8, plan):
    fields = collections.defaultdict(set)
    for m in e8["mutations"]:
        fields[m["target"]].add(m["field"])
    expect_w = sum(len(list(itertools.combinations(sorted(v), 2))) for v in fields.values())
    assert plan["population"]["W"] <= expect_w and plan["population"]["W"] >= expect_w - 40
    assert plan["units_per_stratum"]["W"] == plan["population"]["W"]                      # exhaustive
    assert plan["units_per_stratum"]["V"] == min(PW.N_V, plan["population"]["V"])
    assert plan["units_per_stratum"]["X"] == min(PW.N_X, plan["population"]["X"])
    assert len({u["id"] for u in plan["units"]}) == len(plan["units"])
    assert [u["stratum"] for u in plan["units"]] == sorted((u["stratum"] for u in plan["units"]),
                                                         key=lambda s: "WVX".index(s))
    assert set(plan["closure_27"]) == set(e8["static"]["union"]) and len(plan["closure_27"]) == 27
    assert PW.make_plan(e8) == plan                                                          # deterministic
    for u in plan["units"][:2000]:
        a, b = u["muts"]
        assert (a["table"], a["key"], a["col"]) != (b["table"], b["key"], b["col"])
        if (a["table"], a["key"]) == (b["table"], b["key"]):
            assert a["col"] != a["key_col"]                                                   # a key change goes last
        if u["stratum"] == "X":
            assert u["render_target"] in (a["target"], b["target"]) and a["target"] != b["target"]


def test_pairwise_smoke_plan(plan):
    s = PW.smoke_plan(plan)
    assert s["units_per_stratum"] == {"W": 100, "V": min(20, plan["units_per_stratum"]["V"]),
                                      "X": min(20, plan["units_per_stratum"]["X"])}
    assert s["cap_s"] == 900.0 and s["smoke"]
    assert set(s["targets"]) == {u["render_target"] for u in s["units"]}


def test_classify_unit():
    f = {"id": "f", "field": "states.origin_idx"}
    g = {"id": "g", "field": "states.context_id_bin"}
    base = {"render": {"a": "0"}, "commit": {"stable": ["S0", 1], "closure": ["C0", 1], "row": ["R0", 1]}}
    same = {"render": {"a": "0"}, "commit": {"stable": ["S0", 1], "closure": ["C0", 1], "row": ["R0", 1]}}
    cl = {"states.context_id_bin"}
    # joint-only, and undetected because the stable commitment did not move
    u = {"muts": [f, g], "render": {"a": "1"}, "commit": {"stable": ["S0", 1], "closure": ["C0", 1], "row": ["R1", 1]}}
    c = PW.classify_unit(u, base, {"f": same, "g": same}, cl)
    assert c["joint_only"] and c["undetected_render_change"] and c["conditional_noncl"]
    # g changes the output alone, f outside the closure changes it further given g: conditional_noncl
    gch = {"render": {"a": "2"}, "commit": {"stable": ["S2", 1], "closure": ["C2", 1], "row": ["R2", 1]}}
    u2 = {"muts": [f, g], "render": {"a": "3"}, "commit": {"stable": ["S3", 1], "closure": ["C3", 1], "row": ["R3", 1]}}
    c2 = PW.classify_unit(u2, base, {"f": same, "g": gch}, cl)
    assert c2["conditional_noncl"] and not c2["joint_only"] and not c2["undetected_render_change"]
    # masking: both change it alone, together they do not
    fch = {"render": {"a": "4"}, "commit": base["commit"]}
    u3 = {"muts": [f, g], "render": {"a": "0"}, "commit": {"stable": ["S5", 1], "closure": ["C5", 1], "row": ["R5", 1]}}
    c3 = PW.classify_unit(u3, base, {"f": fch, "g": gch}, cl)
    assert c3["masking"] and not c3["render_changed"]


def test_summarize_records(plan):
    small = PW.smoke_plan(plan, 3, 0, 0)
    raw = []
    for t in small["targets"]:
        raw.append(json.dumps({"kind": "baseline", "target": t, "render": {"activity": "b"},
                               "commit": {"stable": ["s", 1], "closure": ["c", 1], "row": ["r", 1]}}))
    for u in small["units"]:
        for m in u["muts"]:
            raw.append(json.dumps({"kind": "single", "target": u["render_target"], "mut": m["id"],
                                   "render": {"activity": "b"},
                                   "commit": {"stable": ["s", 1], "closure": ["c", 1], "row": ["r", 1]}}))
    for i, u in enumerate(small["units"]):
        changed = i == 0
        raw.append(json.dumps({"kind": "unit", "id": u["id"], "stratum": "W", "target": u["render_target"],
                               "render": {"activity": "x" if changed else "b"},
                               "commit": {"stable": ["s2" if changed else "s", 1], "closure": ["c", 1], "row": ["r", 1]},
                               "restore": {"db_equal": True, "render_equal": True, "commit_equal": True}}))
    r = PW.summarize_records(small, raw)
    w = r["per_stratum"]["W"]
    assert w["done"] == 3 and w.get("joint_only") == 1 and not w.get("undetected_render_change")
    assert r["restore_failures"] == []


def test_branch_tracer_on_a_toy_function():
    def toy(x):
        if x:
            return 1
        return 2
    tr = PW.BranchTracer("e10p_test")
    codes = PW.code_objects([toy])
    assert toy.__code__ in codes
    tr.start(codes)
    try:
        toy(1)
        m1 = tr.mark("one")
        toy(0)
        m2 = tr.mark("two")
    finally:
        tr.stop()
    f = toy.__code__.co_filename
    assert m1["files"][f]["branch_outcomes"] == [1, 2] and m2["files"][f]["branch_outcomes"] == [2, 2]
    assert m2["files"][f]["lines"][0] > m1["files"][f]["lines"][0] or m2["files"][f]["lines"][0] == m2["files"][f]["lines"][1]
    assert tr.never_taken() == []


def test_pair_apply_and_restore_on_a_synthetic_recorder(tmp_path):
    E8 = PW._e8()
    Inner = PW.make_inner(E8)
    db = str(tmp_path / "w.db")
    c = sqlite3.connect(db, isolation_level=None)
    c.execute("CREATE TABLE states (state_id INTEGER PRIMARY KEY, state TEXT, metadata_id INTEGER)")
    c.execute("CREATE TABLE states_meta (metadata_id INTEGER PRIMARY KEY, entity_id TEXT)")
    c.execute("INSERT INTO states VALUES (5, 'on', 1)")
    c.execute("INSERT INTO states_meta VALUES (1, 'light.porch_light')")
    inner = Inner(None)
    inner.con = c
    key = {"id": "k", "table": "states", "key_col": "state_id", "key": 5, "col": "state_id",
           "new": {"t": "int", "v": 99}}
    st = {"id": "s", "table": "states", "key_col": "state_id", "key": 5, "col": "state", "new": {"t": "text", "v": "off"}}
    meta = {"id": "m", "table": "states_meta", "key_col": "metadata_id", "key": 1, "col": "entity_id",
            "new": {"t": "text", "v": "light.x"}}
    for muts in (PW.ordered_pair(key, st), PW.ordered_pair(st, meta)):
        assert muts is not None
        done = inner.apply_pair(muts)
        assert c.execute("SELECT count(*) FROM states").fetchone()[0] == 1
        inner.restore_pair(done)
        assert c.execute("SELECT * FROM states").fetchall() == [(5, "on", 1)]
        assert c.execute("SELECT * FROM states_meta").fetchall() == [(1, "light.porch_light")]
    assert PW.ordered_pair(key, st)[-1] is key and PW.ordered_pair(st, st) is None


# ================================================================================================ arm E (Pi 4 cost)
def test_pi4_profiles_and_matrix():
    assert len(PI.MATRIX) == 10 and len({PI.tag_of(*m) for m in PI.MATRIX}) == 10
    assert PI.PROFILES["ref"] == {"cpus": "1", "memory": "1g", "device_read_bps": "100mb", "device_write_bps": "50mb",
                                  "device": "/dev/vda"}
    CS = PI.cost_scale()
    assert PI.PROFILES["ref"] == CS.LIMITS                                    # ref is exactly the C1 limits
    ea = PI.extra_args(PI.PROFILES["pi4"])
    assert ea == ["--memory-swap", "512m", "--device-read-iops", "/dev/vda:1500", "--device-write-iops", "/dev/vda:500"]
    assert PI.extra_args(PI.PROFILES["ref"]) == []
    assert set(PI.ASSUMED["pi4"]) == {"cpus", "memory", "memory_swap", "device_read_bps", "device_write_bps",
                                      "device_read_iops", "device_write_iops"}


def test_pi4_docker_argument_insertion():
    seen = []
    sh = PI.wrap_sh(lambda *a, **k: seen.append(list(a)) or "", ["--x", "1"], "e10e-monitor")
    sh("docker", "run", "-d", "--name", "e10e-monitor", "--network", "n", "img")
    sh("docker", "run", "-d", "--name", "e10e-writer", "img")
    sh("docker", "volume", "create", "v")
    assert seen[0] == ["docker", "run", "-d", "--name", "e10e-monitor", "--x", "1", "--network", "n", "img"]
    assert seen[1] == ["docker", "run", "-d", "--name", "e10e-writer", "img"] and seen[2][:2] == ["docker", "volume"]
    CS = PI.cost_scale()
    PI.install(CS, "pi4")
    assert CS.LIMITS["cpus"] == "0.25" and CS.PREFIX == "e10e" and "memory_swap" not in CS.LIMITS
    PI.install(CS, "ref")                                                     # re-install does not stack wrappers
    assert CS.sh.__wrapped__.__name__ == "sh" and not hasattr(CS.sh.__wrapped__, "__wrapped__")


def test_pi4_merge():
    def doc(prof, med):
        return {"runs": {PI.tag_of(prof, "direct", 1, "720"): {"mode": "direct", "k": 1, "limits": {},
                                                                "per_poll_ms": {"total": {"median": med}},
                                                                "measured_window": {}, "per_poll_bytes": {}}}}
    m = PI.merge({"ref": doc("ref", 80.0), "pi4": doc("pi4", 400.0)}, {})
    assert m["median_ratio"] == {"direct_k1_pi4_over_ref": 5.0}


# ================================================================================================ arm C (Domoticz)
def test_dz_switchtype_prediction():
    W = {"second": 1, "minute": 60, "hour": 3600}
    lock_secs = [1000, 1030, 1200, 1300]
    first = {("second", "1000"): 1002.0, ("second", "1030"): 1031.0, ("second", "1200"): 1201.0,
             ("second", "1300"): 1302.0, ("minute", "16"): 1021.0, ("minute", "20"): 1201.0, ("minute", "21"): 1302.0,
             ("hour", "0"): 3601.0}
    pred, amb = DZS.predicted_segments(lock_secs, first, t_change=1205.0, W=W)
    assert ("second", "1000") in pred and ("second", "1030") in pred and ("second", "1300") not in pred
    assert ("second", "1200") in amb and ("minute", "20") in amb and ("hour", "0") not in pred
    verd = {("second", "1000"): {"violation": True}, ("second", "1030"): {"violation": True},
            ("second", "1300"): {"violation": False}, ("minute", "16"): {"violation": True},
            ("second", "1100"): {"violation": True}}
    ag = DZS.agreement(verd, pred, amb)
    assert ag["second"]["n_observed_not_predicted"] == 1 and ag["second"]["n_predicted_not_observed"] == 0
    assert ag["minute"]["agree"] is True


def test_dz_setused_request_changes_only_the_switch_type():
    D = _load(os.path.join(R, "testbed/e10/dz_switchtype.py"), "dz_switchtype")
    dev = {"idx": "21", "Name": "Front Door", "Description": "", "Protected": False, "CustomImage": 0,
           "StrParam1": "", "StrParam2": "", "SwitchTypeVal": 19}
    p = D.setused_params(dev, 20)
    assert p == {"idx": 21, "used": "true", "switchtype": 20, "name": "Front Door", "description": "",
                 "protected": "false", "customimage": 0, "strparam1": "", "strparam2": ""}
    assert D.find_lock([dev, dict(dev, idx="22", SwitchTypeVal=0)], 19)["idx"] == "21"
    assert D.find_lock([dev, dict(dev, idx="22")], 19) is None


# ================================================================================================ the registration draft
def test_prereg_document_has_the_r5_arms():
    P = _load(os.path.join(R, "testbed/e10/e10_prereg.py"), "e10_prereg_t")
    d = P.document(False)
    ids = {a["id"] for a in d["arms"]}
    assert {"S-SHAM", "R-RESTART", "C-DZ-SWITCHTYPE", "D-PAIRWISE", "E-PI4-COST"} <= ids
    assert {"H17_sham_specificity", "H18_restart_mid_poll", "H19_dz_switchtype", "H20_pairwise_closure",
            "H21_pi4_cost"} <= set(d["hypotheses"])
    dp = d["review_r5_offline_plans"]["D_pairwise"]
    assert dp["population"] == PW.make_plan(json.load(open(E8_JSON)))["population"]
    for f in ("exp/stages/e10r5_score.py", "testbed/e10/run_e10_r5.sh", "exp/stages/e10_pairwise_closure.py",
              "exp/sp2027/e10_pi4_cost.py", "testbed/e10/run_dz_switchtype.sh"):
        assert d["code_sha256"]["files"][f] is not None, f
    names = [b["block"] for b in d["plan"]["plan"]["blocks"]]
    assert "S_SHAM" in names and "R_RESTART" in names


def test_shell_syntax():
    for f in ("testbed/e10/run_e10.sh", "testbed/e10/run_e10_r5.sh", "testbed/e10/run_dz_switchtype.sh"):
        r = subprocess.run(["bash", "-n", os.path.join(R, f)], capture_output=True, text=True)
        assert r.returncode == 0, (f, r.stderr)


def test_switchtype_launcher_is_the_e_dz_launcher_plus_the_arm():
    """The copy keeps E-DZ's stack, provisioning, anchor, monitor and snapshot lines verbatim."""
    a = open(os.path.join(R, "testbed/domoticz/run_dz.sh")).read().splitlines()
    b = open(os.path.join(R, "testbed/e10/run_dz_switchtype.sh")).read().splitlines()
    for key in ("docker run -d --name dz-monitor", "docker run -d --name dz-anchord", "dz_provision.py run",
                "s.backup(d)", "-e HOMEPROV_SCHEME=closure"):
        la = [x for x in a if key in x]
        assert la and all(x in b for x in la), key
    assert not any("dz_arms.py --tag" in x for x in b)
