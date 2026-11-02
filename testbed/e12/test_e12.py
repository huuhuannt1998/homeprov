"""Static tests of E12 (drafts/round13/E12_DESIGN.md): no Docker, nothing run against the lab.

The schedule (two days, routine operations only), the configuration transform on the lab's own configuration.yaml, the
default-commit-interval parser, the commit-cadence analysis, the summary's block rates and rule-consistency check, the
copy relation to E9's frozen files (every e9ops.py function E12 does not need to change is unchanged in e12ops.py), shell
syntax, and the registration draft.

    <home>/miniconda3/bin/python3 -m pytest -q testbed/e12/test_e12.py
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import subprocess
import sys

import pytest

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
for p in ("testbed/e12", "exp/stages", "exp"):
    sys.path.insert(0, os.path.join(R, p))
import e12ops  # noqa: E402
import e12_summary as SM  # noqa: E402

LAB_CFG = "<research-dir>/HOMEPROV-P13-exp/e9/e9_main2/hub_configuration.yaml.orig"
FALLBACK_CFG = """homeassistant:
  name: HomeProv Real
  time_zone: UTC

recorder:
  db_url: sqlite:////config/home-assistant_v2.db
  commit_interval: 1
  purge_keep_days: 30

logbook:
history:

automation: !include automations.yaml
"""


def ns(**kw):
    d = dict(keep_days=30, restart_day=1, backup_day=2, day_s=1080.0, smoke_keep_days=29)
    d.update(kw)
    return argparse.Namespace(**d)


# ================================================================================================ schedule
def test_e12_schedule_two_days_routine_only():
    start = e12ops.parse_iso("2026-10-21T00:00:00Z")
    ev = e12ops.e12_schedule(start, 2, ns())
    types = collections.Counter(e["type"] for e in ev)
    assert set(types) <= e12ops.E12_BENIGN_TYPES
    assert types["planned_restart"] == 1 and types["backup"] == 1 and types["purge_marker"] == 2
    assert types["day_end"] == 2 and types["sleep_guard"] == 2 and types["snapshot"] == 4
    assert not ({"attack_batch", "namemap_session", "restore", "forced_purge"} & set(types))
    rs = next(e for e in ev if e["type"] == "planned_restart")
    bk = next(e for e in ev if e["type"] == "backup")
    assert e12ops.iso(rs["t"]) == "2026-10-21T20:00:00Z" and rs["day"] == 1
    assert e12ops.iso(bk["t"]) == "2026-10-22T20:00:00Z" and bk["day"] == 2
    for e in ev:
        if e["type"] == "purge_marker":
            assert e12ops.iso(e["scheduled_ts"])[11:] == "04:12:00Z" and e["scheduled_ts"] - e["t"] == 300
    end = next(e for e in ev if e["type"] == "end")
    assert end["t"] == start + 2 * 86400 + 60
    days = [e["window"] for e in ev if e["type"] == "day_end"]
    assert days == [[start, start + 86400], [start + 86400, start + 2 * 86400]]


def test_e12_schedule_refuses_a_start_inside_the_purge_hour():
    with pytest.raises(SystemExit):
        e12ops.e12_schedule(e12ops.parse_iso("2026-10-21T04:00:00Z"), 2, ns())


def test_e12_smoke_schedule():
    ev = e12ops.e12_smoke_schedule(1000.0, ns(day_s=1080.0))
    types = [e["type"] for e in ev]
    assert types.count("forced_purge") == 1 and types.count("backup") == 1 and types.count("day_end") == 2
    assert set(types) <= e12ops.E12_BENIGN_TYPES
    bk = next(e for e in ev if e["type"] == "backup")
    assert 1000.0 + 1080.0 < bk["t"] < 1000.0 + 2 * 1080.0


def test_cmd_schedule_output(capsys):
    a = argparse.Namespace(start="2026-10-21T00:00:00Z", days=2, smoke=False, smoke_only="", day_s=1080.0,
                           keep_days=30, smoke_keep_days=29, restart_day=1, backup_day=2, namemap_day=0, restore_day=0,
                           trials=5, ec_arms=[], e7_arms=[])
    e12ops.cmd_schedule(a)
    d = json.loads(capsys.readouterr().out)
    assert d["mode"] == "real" and d["days"] == 2 and [e["id"] for e in d["events"]] == list(range(len(d["events"])))


# ================================================================================================ configuration
def lab_cfg():
    return open(LAB_CFG).read() if os.path.exists(LAB_CFG) else FALLBACK_CFG


def test_e12_config_on_the_lab_configuration():
    orig = lab_cfg()
    new, diff = e12ops.e12_config(orig)
    assert len(diff["removed"]) == 1 and "commit_interval: 1" in diff["removed"][0]["text"]
    assert "commit_interval" not in new.split("automation e12:")[0]
    for keep in ("purge_keep_days: 30", "db_url: sqlite:////config/home-assistant_v2.db", "automation: !include"):
        assert keep in new
    # every original line but the removed one is kept, in order, before the appended block
    head = new.split("\n# E12 (review r5)")[0].splitlines()
    assert [x for x in orig.splitlines() if "commit_interval" not in x] == head[:len(orig.splitlines()) - 1]
    tail = new.split("automation e12:")[1]
    assert "trigger: mqtt" in tail and 'topic: "hpr/e12/ops/backup"' in tail and "action: backup.create" in tail
    with pytest.raises(ValueError):
        e12ops.e12_config(new)                      # no commit_interval left (and the block exists)


def test_e12_config_refusals():
    with pytest.raises(ValueError):
        e12ops.e12_config(FALLBACK_CFG.replace("  commit_interval: 1\n", ""))
    two = FALLBACK_CFG.replace("  commit_interval: 1\n", "  commit_interval: 1\n  commit_interval: 2\n")
    with pytest.raises(ValueError):
        e12ops.e12_config(two)
    other = FALLBACK_CFG + "\nsomething:\n  commit_interval: 3\n"     # outside the recorder block: kept
    new, diff = e12ops.e12_config(other)
    assert "  commit_interval: 3" in new and len(diff["removed"]) == 1


def test_default_commit_interval_parser():
    assert e12ops.parse_default_commit_interval("DEFAULT_COMMIT_INTERVAL = 5\n") == 5
    assert e12ops.parse_default_commit_interval("x = 1\nDEFAULT_COMMIT_INTERVAL: Final = 5  # s\n") == 5
    assert e12ops.parse_default_commit_interval("COMMIT_INTERVAL = 5\n") is None
    assert e12ops.parse_default_commit_interval("DEFAULT_COMMIT_INTERVAL = 5\nDEFAULT_COMMIT_INTERVAL = 1\n") is None
    r = subprocess.run([sys.executable, os.path.join(R, "testbed/e12/e12ops.py"), "default-commit-interval"],
                       input="DEFAULT_COMMIT_INTERVAL = 5\n", capture_output=True, text=True)
    assert r.stdout.strip() == "5" and r.returncode == 0


def test_commit_cadence_analysis():
    samples, size, mt = [], 0, 0
    t = 0.0
    while t < 60.0:
        if abs((t % 5.0)) < 1e-9 or abs((t % 5.0) - 0.1) < 1e-9:     # a commit burst every 5 s (two writes 0.1 s apart)
            size += 4096
            mt += 1
        samples.append((t, size, mt))
        t = round(t + 0.05, 2)
    c = e12ops.cadence(samples)
    assert c["interval_median_s"] == pytest.approx(5.0, abs=0.06) and c["bursts"] >= 11
    flat = e12ops.cadence([(i * 0.05, 1, 1) for i in range(100)])
    assert flat["bursts"] == 0 and flat["interval_median_s"] is None


# ================================================================================================ summary logic
def test_block_rates_and_bounds():
    v = {"flagged_seconds": ["130", "131"], "violations": [{"violation": True, "attributable": True, "gran": "minute",
                                                             "seg": "5"}],
         "keylog_violations": [{"seconds": ["400"]}]}
    fs = SM.failed_seconds(v)
    assert fs == {130, 131, 400}
    fm = SM.failed_minutes(v)
    assert fm == {2, 5, 6}
    assert SM.minute_blocks(fm, (0, 3600)) == (3, 60)
    copies = [i * 5.1 for i in range(800)]
    k, n = SM.poll_blocks(fs, copies, (0, 3600))
    assert k == 2 and n == len([c for c in copies if c < 3600])           # 130 and 131 share the poll copying at 132.6
    ci = SM.cp(0, 2880)
    assert SM.per_day_bound(ci, 1440) == pytest.approx(1.843, abs=0.01)    # 0 of 2,880 minutes: about 1.8 per day


def test_rule_consistency():
    assert SM.rule_consistency(10.0, 0)["agrees"] is True
    assert SM.rule_consistency(10.0, 3)["agrees"] is False
    assert SM.rule_consistency(50.0, 12) == {"pause_s": 50.0, "predicted": "some_attributable", "attributable": 12,
                                             "agrees": True}
    assert SM.rule_consistency(50.0, 0)["agrees"] is False
    assert SM.rule_consistency(27.0, 0)["predicted"] == "either"
    assert SM.rule_consistency(None, 0)["agrees"] is None


def test_rows_window_and_late_rows():
    v = {"attributable_rows": [{"second": "100", "lat": 40.0}],
         "benign_late_rows": [{"second": "101", "lat": 7.0}, {"second": "500", "lat": 26.0}],
         "unobserved_late_rows": []}
    w = SM.rows_window(v, 90, 110)
    assert w["by_verdict"] == {"attributable": 1, "benign_late": 1} and w["max_delay_s"] == 40.0
    lr = SM.late_rows(v, (0, 1000))
    assert lr["benign_late_rows"] == {"n": 2, "max_s": 26.0, "over_25_s": 1}


# ================================================================================================ the copy relation
def _functions(path):
    src = open(path).read()
    return {n.name: ast.dump(n) for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}


def test_e12ops_is_e9ops_with_only_e12_changes():
    a = _functions(os.path.join(R, "testbed/e9/e9ops.py"))
    b = _functions(os.path.join(R, "testbed/e12/e12ops.py"))
    changed = {k for k in a if a[k] != b.get(k)}
    assert changed == {"cmd_schedule", "main"}, changed                    # the schedule dispatch and the CLI
    assert set(b) - set(a) == {"e12_schedule", "e12_smoke_schedule", "e12_config", "cmd_e12_config",
                               "parse_default_commit_interval", "cmd_default_commit_interval", "cadence",
                               "cmd_commit_cadence"}


def test_run_e12_keeps_e9s_machinery():
    a = open(os.path.join(R, "testbed/e9/run_e9.sh")).read().splitlines()
    b = open(os.path.join(R, "testbed/e12/run_e12.sh")).read().splitlines()
    for key in ("start_anchor()", "wait_sealed()", "snapshot_db()", "-e HOMEPROV_SCHEME=stable -e HOMEPROV_COVERAGE=1",
                "HEAD_WITNESS_MODE=sync", "QC_DIRECT_PREREG=720; QC_COPY_PREREG=1", "sleep-guard --hostlog",
                "exp/stages/e9_score.py\" --run-dir"):
        la = [x for x in a if key in x]
        assert la and all(x in b for x in la), key
    txt = "\n".join(b)
    i_ref = txt.index("attack_batch|namemap_session|restore)")
    i_att = txt.index("  attack_batch)")
    assert i_ref < i_att                                               # the refusal precedes E9's unreachable arm
    assert "e12_summary.py" in txt and "default-commit-interval" in txt and "e12-config" in txt
    assert 'INFO=$(e6_on) || { note "FAIL: homeprov_e6 did not answer' not in txt     # no E6 person setup
    assert "person_create" not in txt.split("THE WEEK")[0]                           # nothing of it before the days


def test_shell_syntax():
    r = subprocess.run(["bash", "-n", os.path.join(R, "testbed/e12/run_e12.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_registration_draft():
    import importlib.util
    spec = importlib.util.spec_from_file_location("e12_prereg_t", os.path.join(R, "testbed/e12/e12_prereg.py"))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    d = P.document(False)
    assert d["parameters"]["start"] == "2026-10-22T00:00:00Z" and d["parameters"]["days"] == 2
    assert [e["type"] for e in d["schedule"]["events"]].count("backup") == 1
    assert set(d["hypotheses"]) == {"H1_floor", "H2_commit_cadence", "H3_late_rows", "H4_nightly_purges",
                                    "H5_planned_restart", "H6_backup", "H7_cost", "H8_distinguishability"}
    missing = [f for f, s in d["code_sha256"]["files"].items() if s is None]
    assert missing == [], missing
    assert P.document(False)["schedule"]["sha256"] == d["schedule"]["sha256"]
