"""E12 pre-registration: writes the draft (default) or the registered file (--final) from the run's parameters, the
schedule testbed/e12/e12ops.py generates for the registered start, and the sha256 of every file the run executes or
scores with; --check verifies a registered file against the working tree (run_e12.sh's preflight).

    <home>/miniconda3/bin/python3 testbed/e12/e12_prereg.py --out "<PAPER>/drafts/round13/E12_PREREG_DRAFT.json"
    <home>/miniconda3/bin/python3 testbed/e12/e12_prereg.py --final --out exp/out/e12_preregistration.json
    <home>/miniconda3/bin/python3 testbed/e12/e12_prereg.py --check exp/out/e12_preregistration.json
After --final: ots stamp exp/out/e12_preregistration.json (OpenTimestamps, as E9 and E10), then ots upgrade.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
PAPER = R + "/[READY] (TDSC) HOMEPROV - P13"
sys.path.insert(0, os.path.join(R, "testbed", "e12"))
import e12ops  # noqa: E402

START = "2026-10-22T00:00:00Z"   # moved from 2026-10-21T00:00Z (E10 ended 2026-10-21 19:57Z; E12 smoke after it)
DAYS = 2
FILES = [
    # the monitor and the verifier as E10 leaves them (both E10 patches applied), images, anchors, witness
    "monitor/monitor.py", "monitor/Dockerfile.sign", "monitor/requirements-sign.txt", "exp/stages/e7_verify.py",
    "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py", "testbed/anchord/headwitness.py",
    "testbed/anchord/chainverify.py", "testbed/e8/anchord-e8.Dockerfile",
    # operator markers
    "exp/rig/marker_issuer.py", "exp/rig/markers.py", "exp/rig/stats.py",
    # the E12 launcher and helper (copies of run_e9.sh / e9ops.py), the generator, the summary, the tests
    "testbed/e12/run_e12.sh", "testbed/e12/e12ops.py", "testbed/e12/e12_prereg.py", "exp/stages/e12_summary.py",
    "testbed/e12/test_e12.py",
    # what E12 uses unchanged: E9's scorer (and what it imports), E10's poll timeline, E10's interpreter guard, the
    # scratch stack of the smoke, and the sources the copies were made from (so the copy relation is checkable)
    "exp/stages/e9_score.py", "exp/stages/e8_score.py", "exp/stages/e10_score.py", "testbed/e10/e10ops.py",
    "testbed/e9/smoke_stack.sh", "testbed/e9/run_e9.sh", "testbed/e9/e9ops.py",
    # tests the preflight runs
    "monitor/test_coverage.py", "monitor/test_node_hash.py", "monitor/test_e9.py", "monitor/test_e9_dishonest.py",
    "testbed/anchord/test_anchor_chain.py", "testbed/anchord/test_anchor_e8.py", "testbed/anchord/test_anchor_e9.py",
    "testbed/anchord/test_anchor_cache.py", "testbed/anchord/test_anchor_stall.py",
]
DESIGN = PAPER + "/drafts/round13/E12_DESIGN.md"


def h(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None


def schedule():
    a = argparse.Namespace(keep_days=30, restart_day=1, backup_day=2)
    ev = e12ops.e12_schedule(e12ops.parse_iso(START), DAYS, a)
    ev.sort(key=lambda e: (e["t"], e["type"] != "day_end"))
    for i, e in enumerate(ev):
        e["id"] = i
        e["utc"] = e12ops.iso(e["t"])
    return ev


HYPOTHESES = {
    "H1_floor": "CONFIRMATORY. Over both days, neither monitor reports an unexcused violation (second, minute, hour or "
                "keylog); every anchored segment is untouched, so the run's false-violation count is 0 per monitor. "
                "Reported with minute-block and poll-block exact intervals and their per-day upper bounds.",
    "H2_commit_cadence": "CONFIRMATORY (manipulation check). The recorder commits at the default interval: the median "
                         "interval between commit bursts seen on the -wal file outside the hub is between 4.0 and 6.5 s at "
                         "setup and at each day's end (E9's 1 s setting would give about 1 s).",
    "H3_late_rows": "EXPLORATORY. Outside the backup window no row is attributable; late rows (benign_late, or "
                    "unobserved_late under D1) have delays below 30 s; their count and largest delay per day are "
                    "reported and compared with E9's week (larger delays expected at 5 s commits; no number predicted).",
    "H4_nightly_purges": "CONFIRMATORY. Each night's 04:12 purge under its operator PURGE marker adds no unexcused "
                         "violation on either monitor; its disconnects are excused (as E9).",
    "H5_planned_restart": "CONFIRMATORY. The planned restart (day 1, 20:00) raises no attributable row and no flagged "
                          "second on either monitor in [restart - 30 s, restart + 120 s]; no unobservable interval is "
                          "flagged by the distinguishability rule.",
    "H6_backup": "CONDITIONAL on the measured commit pause p (the largest interval between commit bursts in the backup "
                 "probe): if p + 5 s < 25 s, no attributable row in the backup window; if p > 35 s, rows written early in "
                 "the pause are attributable (false violations: no marker declares a backup); in between, either. The "
                 "pause itself, the window's row verdicts, flagged seconds and unobservable polls are reported.",
    "H7_cost": "EXPLORATORY. Per-poll cost, bytes read and written, and quick_check timing per monitor at the default "
               "commit interval (e9_score.py's cost and io sections), compared with E9's week; no prediction.",
    "H8_distinguishability": "CONFIRMATORY. No unobservable interval of the two days is flagged by the rule (>= 60 s "
                             "and no hub start within 120 s).",
}

OUTCOMES = {"primary": ["per day and per run, per monitor (M-direct primary): unexcused violations by granularity and "
                        "keylog; minute-block and poll-block k/n with exact 95% intervals and per-day upper bounds",
                        "commit cadence (H2)", "nightly purges (H4)", "planned restart window (H5)",
                        "suspicious unobservable intervals (H8)"],
            "secondary": ["late-row delays (H3)", "backup window and its rule consistency (H6)", "cost (H7)",
                          "every e9_score.py section (days, nights, monitors, host, events)"]}
EXCLUSIONS = ["none of the run's seconds is excluded from the floor (no trial touches any); a day whose verification "
              "fails is reported as failed, not dropped",
              "a host sleep (host log gap above 90 s) or an unexplained hub start is reported with its interval; the "
              "seconds it affects stay in the floor, flagged as such",
              "smoke runs are not results"]
ANALYSIS = ["No hypothesis test beyond exact intervals; per-day and per-run counts are reported as counts",
            "Block intervals (per minute, per poll) are the reviewers' requested reporting unit; blocks are not "
            "independent and the intervals are not a model of the failure process",
            "Both monitors are scored separately; M-direct (the recommended direct read) is primary; nothing is pooled "
            "across monitors",
            "Every deviation from this registration is written to an amendment before it is used, as for E9 and E10"]
LIMITS = ["48 hours, not a week: with no failure the per-day upper bound is about 1.8 (minute blocks, 2,880 minutes); "
          "the week-scale rate comes from E9 (commit interval 1 s) and E12 together, and the paper says so",
          "One lab installation with virtual devices; its write rate is the lab's",
          "The backup is Home Assistant's own (backup.create) through a harness automation, once; its pause depends on "
          "the configuration directory's size at that moment",
          "The configuration is changed for the run (commit_interval line removed, automation e12 added) and restored "
          "byte for byte afterwards; one extra hub restart at setup precedes START"]


def document(final):
    now = dt.datetime.now(dt.timezone.utc)
    ev = schedule()
    pre = {"experiment": ("E12: the recommended configuration (direct read primary, copy secondary; stable columns, "
                          "coverage, keylog, per-row binding, escrow, signatures, name-map digest, linked anchors, head "
                          "witnesses) for 48 h on the lab installation at Home Assistant's DEFAULT recorder commit "
                          "interval (5 s; E9 ran at 1 s), with routine operations (two nightly purges under PURGE markers, "
                          "one planned restart, one Home Assistant backup) and no attacks"),
           "status": "REGISTERED" if final else "DRAFT", "registered_at": now.isoformat() if final else None,
           "registered_before": "START (%s) and any event of the real run (tag e12_main); smoke runs precede it and "
                                "are not results" % START,
           "approval": {"pi": "2026-10-16, verbatim option label: '48-hour run at 5 s (Recommended)' (TDSC_PLAN.md "
                              "decision log, after review r5: a 48 h benign run at Home Assistant's default commit "
                              "interval after E10, called E12)"},
           "design": {"file": "drafts/round13/E12_DESIGN.md", "sha256": h(DESIGN)},
           "parameters": {"start": START, "days": DAYS, "late_bound_s": 30.0, "gap_s": 30.0, "period_s": 5.0,
                          "purge_tol_s": 60.0, "keep_days": 30, "restore_tol_s": 30.0, "quick_check_every":
                          {"direct": 720, "copy": 1}, "default_commit_interval_s_required": 5,
                          "backup_topic": "hpr/e12/ops/backup", "cadence_probe_s": {"setup": 120, "backup": 660,
                                                                                    "day_end": 120},
                          "unobservable_rule": {"min_duration_s": 60.0, "no_hub_start_within_s": 120.0},
                          "witness_ports": [19986, 19987], "prefix": "e12", "images": ["hpr-monitor:e12",
                                                                                         "hpr-anchord:e12"]},
           "schedule": {"generated_by": "testbed/e12/e12ops.py e12_schedule(%s, %d)" % (START, DAYS),
                        "sha256": hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest(), "events": ev},
           "hypotheses": HYPOTHESES, "outcomes": OUTCOMES, "exclusions": EXCLUSIONS, "analysis_plan": ANALYSIS,
           "known_limits_stated_in_advance": LIMITS,
           "code_sha256": {"computed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "files": {f: h(os.path.join(R, f)) for f in FILES}}}
    if not final:
        pre["code_sha256"]["note"] = ("DRAFT: monitor.py and e7_verify.py are the E9-frozen versions until E10 applies "
                                      "its two patches; the hashes to freeze are computed at --final, after E10")
    return pre


def check(path):
    pre = json.load(open(path))
    bad = [] if pre.get("status") == "REGISTERED" else ["status %r" % pre.get("status")]
    for f, s in pre["code_sha256"]["files"].items():
        if h(os.path.join(R, f)) != s:
            bad.append(f)
    print(json.dumps({"ok": not bad, "mismatch": bad}))
    return 0 if not bad else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--check")
    a = ap.parse_args()
    if a.check:
        return check(a.check)
    doc = document(a.final)
    if a.final:
        missing = [f for f, s in doc["code_sha256"]["files"].items() if s is None]
        if missing:
            raise SystemExit("REFUSING --final: missing %s" % missing)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    with open(a.out, "x" if a.final else "w") as fh:
        fh.write(text)
    print("wrote", a.out, hashlib.sha256(text.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
