"""E11 pre-registration: writes the draft (default) or the registered file (--final) from the design's parameters, the
plan testbed/e11/e11ops.py generates from the registered seed, and the sha256 of every file the run executes or scores
with; --check verifies a registered file against the working tree (run_e11.sh's preflight).

    <home>/miniconda3/bin/python3 testbed/e11/e11_prereg.py --out "<PAPER>/drafts/round13/E11_PREREG_DRAFT.json"
    <home>/miniconda3/bin/python3 testbed/e11/e11_prereg.py --final --out exp/out/e11_preregistration.json
    <home>/miniconda3/bin/python3 testbed/e11/e11_prereg.py --check exp/out/e11_preregistration.json
After --final: ots stamp exp/out/e11_preregistration.json (OpenTimestamps, as E9 and E10), ots upgrade hours later.
The instrument's source (testbed/e11/attack) is hashed, never copied into this file or into the artifact.
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
sys.path.insert(0, os.path.join(R, "testbed", "e11"))
import e11ops  # noqa: E402

SEED = e11ops.SEED
HUB_IMAGE = "openhab/openhab:5.2.3@sha256:fa50a6934dfd5bcbf21db18af66f2558f58c6c493ba23bdeb7a894e764507a99"
HUB_IMAGE_ARM64 = "sha256:1423029b751dba9432a0052d009b5ce47ef959ea1576464931020e42e5fc7a93"
FILES = [
    # the monitor as E11 runs it (the E10-hardened version once E10's patches are applied), its image, the anchor
    "monitor/monitor.py", "monitor/Dockerfile.sign", "monitor/requirements-sign.txt",
    "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py", "testbed/anchord/headwitness.py",
    "testbed/anchord/chainverify.py", "testbed/e8/anchord-e8.Dockerfile",
    # the host-side tunnel reused from the Domoticz run (unchanged)
    "testbed/domoticz/harness/tunnel.py", "testbed/domoticz/harness/relay.py",
    # E11: reader, harness, stacks, operations, build, configuration, tests, generator, scorer
    "testbed/e11/monitor/oh_monitor.py", "testbed/e11/run_e11.sh", "testbed/e11/e11_stack.sh", "testbed/e11/e11ops.py",
    "testbed/e11/build_bundles.sh", "testbed/e11/e11_prereg.py", "testbed/e11/test_e11.py",
    "testbed/e11/conf/services/addons.cfg", "testbed/e11/conf/services/jdbc.cfg", "testbed/e11/conf/services/runtime.cfg",
    "testbed/e11/conf/persistence/jdbc.persist",
    "testbed/e11/fixture/src/org/homeprov/e11/fixture/Activator.java", "testbed/e11/fixture/META-INF/MANIFEST.MF",
    # the instrument (never released; hashed only)
    "testbed/e11/attack/src/org/homeprov/e11/lockbridge/Activator.java", "testbed/e11/attack/META-INF/MANIFEST.MF",
    "exp/stages/e11_score.py", "exp/rig/stats.py",
]
DESIGN = PAPER + "/drafts/round13/E11_DESIGN.md"


def h(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None


RESEARCH_QUESTION = {
    "RQ4": "Does HOMEPROV's principle carry across hubs? (SP2027_ACCEPT_PLAN.md section 0)",
    "a": "Can the evidence openHAB shows be measured as a renderer closure?",
    "b": "Do a schema-chosen commitment and a whole-row commitment fail there in the same two directions as on Home "
         "Assistant and Domoticz (missing fields the renderer reads; breaking on fields the renderer does not read)?",
    "c": "Does the out-of-process monitor with a closure-checked commitment, ported by replacing only its read path, detect "
         "post-commit rewrites of the persisted history, at a low benign floor and a feasible cost?",
    "framing": "PI 2026-10-14, verbatim: \"We are doing research and finding a scientific contribution, not a pentester\". "
               "The instrument only creates the post-commit rewrites to detect: the smallest edits of the persisted "
               "history, through openHAB's documented persistence extensions, on one item; no other openHAB weakness "
               "is explored.",
}

HYPOTHESES = {
    "H1_closure_measurable": "(a) Per-field mutation on a closure instance yields a deterministic closure of the rendered "
                             "history (REST /rest/persistence/items/{item}, the request behind Main UI's Analyze view): "
                             "the determinism and positive controls hold, every restore equals the baseline, and the "
                             "measured set is {items.ItemId, items.ItemName (both only after the index reload), "
                             "<table>.time, <table>.value (Number values only to 3 decimals), <table> (name), "
                             "registry.itemType, registry.meta.unit, registry (item entry)}; <table>.rowid, "
                             "registry.label/category/tags/groupNames are outside it.",
    "H2_no_attribution": "(a) The rendered history and the persisted rows carry no field naming a cause, user or source "
                         "(rendered fields: name, datapoints, unit, data[time, state]): on openHAB the closure protects "
                         "the integrity of a history without attribution. (events.log lines carry a sender-set "
                         "'(source: ...)' string outside the persisted history; characterised, not protected.)",
    "H3_schema_chosen_misses": "(b) A commitment chosen from the persistence schema (every stored column of every item "
                               "table, nothing joined: `rows`) changes 0 one-second roots under single writes of "
                               "items.ItemName, items.ItemId, registry.itemType, registry.meta.unit and the deletion of "
                               "a registry entry, each of which changes the rendered history and changes every closure "
                               "root holding a row of that item.",
    "H4_whole_row_over_commits_but_no_in_place_rewrite": "(b) openHAB rewrites no persisted field in place (in-place "
                               "probe: no column of an item table or the index changed for an existing row; registry "
                               "entries unchanged across benign traffic and a restart), so the untouched floor of the "
                               "whole-row scheme is 0, unlike Home Assistant (last_reported_ts) and Domoticz "
                               "(DeviceStatus): that direction is conditional on in-place rewrites. Whole-row still "
                               "over-commits: a rowid or label write changes its roots and not the rendered history, and "
                               "B-LABEL and B-REPLACE-SAME (a past point removed and stored again unchanged) produce "
                               "whole-row (and, for B-REPLACE-SAME, `rows`) violations and no closure violation.",
    "H5_detection": "(c) The closure monitor detects every instrument trial: 30 of 30 per arm (A-BD back-dated state, "
                    "A-RM removal, A-CHG value change), at the one-second and one-minute segment, as attributable "
                    "under the registered rule; the instrument's effect is rendered for both accounts in 30 of 30 "
                    "trials per arm with every other point of the window unchanged.",
    "H6_benign_floor": "(c) No attributable violation on any untouched anchored second (closure scheme) over the "
                       "session, which includes two hub restarts and the index clean; benign late rows are counted "
                       "and expected rare.",
    "H7_operations_needing_a_declaration": "(c) B-BACKFILL (TimeSeries ADD of past states: the documented 'persisting "
                       "historic state' use), B-REPLACE-NEW (a forecast's past points re-sent with new values) and "
                       "B-RETAIN (housekeeping removal of old states) produce attributable violations on exactly the "
                       "seconds they change, and a B-BACKFILL row is indistinguishable from an A-BD row under the "
                       "rule; B-REPLACE-SAME, B-LABEL, B-RESTART and B-CLEAN produce none under the closure.",
    "H8_port_feasible": "(c) monitor.py runs unchanged (0 lines changed); the reader is one module replacing five "
                        "functions (snapshot, validate_copy for a failed snapshot only, check_connection, watermark, "
                        "load); median per-poll time below 1 s and no gap between observable polls above 30 s; no "
                        "hub write failure ('SQLITE_BUSY' or 'database is locked' in openhab.log) during the session.",
}

ARMS = [
    {"id": "A-BD", "n": 30, "what": "instrument: PersistenceExtensions.persist(FrontDoor_Lock, t, OFF, 'jdbc') with t a "
     "moment of phase 1 (no lock row then), at least 130 s later (the second and its minute sealed and anchored)",
     "expected": {"rendered": "a new OFF point at t, both accounts, every other point unchanged: 30/30",
                  "closure": "attributable 30/30 (late row after seal, or rows in a second sealed empty; lag >= 130 s)",
                  "rows": "attributable 30/30", "wholerow": "attributable 30/30"}},
    {"id": "A-RM", "n": 30, "what": "phase 1: the instrument relocks (state ON), the member unlocks through REST "
     "(command OFF); after 130 s: removeAllStatesBetween(lock, floor(t), floor(t)+1 s, 'jdbc') on the unlock's second",
     "expected": {"rendered": "the OFF point at t gone, both accounts: 30/30", "closure": "attributable 30/30 (a sealed "
                  "row removed)", "rows": "attributable 30/30", "wholerow": "attributable 30/30"}},
    {"id": "A-CHG", "n": 30, "what": "phase 1 as A-RM; after 130 s: removeAllStatesBetween over the unlock's second, "
     "then persist(lock, t, ON, 'jdbc') at the unlock's exact time (the extensions have no update)",
     "expected": {"rendered": "the point at t shows ON instead of OFF, both accounts: 30/30",
                  "closure": "attributable 30/30 (a sealed row changed)", "rows": "attributable 30/30",
                  "wholerow": "attributable 30/30"}},
]
BENIGN = [
    {"id": "B-STRAT", "what": "the persistence strategies running all session: everyChange (locks, lights, motion, "
     "Label_Probe), everyUpdate (temperatures, Retention_Probe, Energy_Backfill), the cron everyMinute (Power_Meter), "
     "restoreOnStartup, forecast (Price_Forecast); six motion-light rules", "expected": "no attributable violation (H6)"},
    {"id": "B-REPLACE-SETUP", "what": "a REPLACE TimeSeries of 12 future 5-min points on Price_Forecast at t_start",
     "expected": "no past point affected"},
    {"id": "B-REPLACE-SAME", "what": "REPLACE over the last 30 min and the next hour, past points re-sent unchanged",
     "expected": {"closure": "no violation", "rows": "attributable on each re-sent past point (rowid changed)",
                  "wholerow": "attributable on each re-sent past point"}},
    {"id": "B-REPLACE-NEW", "what": "the same with each past point's value + 1.0",
     "expected": {"closure": "attributable on each changed past point", "rows": "same", "wholerow": "same"}},
    {"id": "B-BACKFILL", "n": 3, "what": "an ADD TimeSeries of up to 10 past states (1 per minute, the last 10 min, at "
     "+30.25 s) on Energy_Backfill", "expected": {"closure": "attributable on every backfilled second", "rows": "same",
                                                 "wholerow": "same"}},
    {"id": "B-LABEL", "what": "the owner renames Label_Probe's label through REST",
     "expected": {"closure": "no violation", "rows": "no violation",
                  "wholerow": "attributable on every sealed second holding a Label_Probe row written before the "
                              "rename"}},
    {"id": "B-RESTART", "n": 2, "what": "docker restart of the hub (the household resumes)", "expected": "no violation"},
    {"id": "B-CLEAN", "what": "Karaf console 'openhab:jdbc tables clean'", "expected": "no violation (no orphan)"},
    {"id": "B-RETAIN", "what": "housekeeping removal of Retention_Probe states older than 20 min "
     "(removeAllStatesBetween, whole-second bound)", "expected": {"closure": "attributable on every second holding a "
                                                                 "removed row", "rows": "same", "wholerow": "same"}},
]
OUTCOMES = {
    "O1_closure": "fields changing the rendered history (default request and the UI's request), immediately and after "
                  "the index reload; controls; rendered-history fields (attribution present or not); in-place probe",
    "O2_schemes": "per scheme (closure live; rows and wholerow from the per-poll archive, validated against the anchored "
                  "closure roots): detection per arm, untouched floor, benign-operation verdicts; single-write checks "
                  "(changed one-second roots per scheme for value, time, rowid, ItemName, ItemId, itemType, unit, label, "
                  "registry-entry deletion)",
    "O3_detection": "per arm: detected (attributable at the one-second segment of the edited row) k/n with exact 95% "
                    "intervals, and at the minute; instrument effect rendered (both accounts); UI agreement (secondary)",
    "O4_floor": "attributable violations over untouched anchored seconds (and minutes), benign-late segments, per "
                "benign operation the verdict classes of the seconds it changed",
    "O5_port": "monitor.py lines changed, reader size and functions replaced, per-poll cost (median, p90, max), gaps "
               "between observable polls, hub write failures",
}
SCORING = {
    "verification_rule": "exp/stages/e11_score.py module docstring (coverage records, per-table rowid watermark, late-row "
                         "test with L = 30 s); detected = attributable",
    "touched": "a second is touched when it holds a row an arm wrote, edited or named (relock, unlock, mark) or a row a "
               "benign operation changed (re-sent, backfilled, removed points; every Label_Probe second for B-LABEL); "
               "the floor is over untouched seconds only, as in the Domoticz run",
    "closure_gate": "after E11-CLO and before E11-DET: every measured closure field must be one the reader commits "
                    "(e11_score.py --closure-gate), else the run stops for a registered amendment",
}
EXCLUSIONS = ["a trial the harness or the instrument reports with err: listed, not scored",
              "polls a hub restart makes unobservable are reported, not excluded",
              "smoke runs (prefixes e11cs/e11ss, outputs under HOMEPROV-P13-exp/e11/smoke) are not results"]
ANALYSIS = ["No hypothesis test beyond exact intervals; every prediction above is per trial or per count and is "
            "confirmed only if every non-excluded trial agrees; an unpredicted outcome is reported with its trial",
            "Schemes are scored separately; nothing is pooled across them",
            "Results are compared side by side with the saved Domoticz files (exp/out/dz_*.json) and the Home Assistant "
            "closure results, never merged",
            "Every deviation from this registration is written to an amendment before it is used"]
LIMITS = ["One release (openHAB 5.2.3), one persistence service (JDBC on SQLite, default settings), one Mac, virtual "
          "devices driven by a fixture bundle, compressed time (about two hours of session)",
          "rrd4j, the persistence the openHAB tutorial suggests, replaces older readings by averages by design; E11 does "
          "not measure it",
          "The reader reads managed items (the JSON database), not items defined in .items files",
          "The keylog is not ported: segments are sealed with coverage records, and attacks the keylog closes on Home "
          "Assistant (a row parked in the future, an unjoinable row) are not exercised",
          "The verification rule is E11's own (unit-tested), not exp/stages/e7_verify.py, which reads Home Assistant "
          "tables",
          "The hub runs in UTC; 'localtime' text in a zone with daylight saving is ambiguous in the fall-back hour"]
ALTERNATIVES = [
    {"if": "the image has no /openhab/dist to initialise the volumes from",
     "then": "the stack lets the image's entrypoint initialise empty volumes at a first start, stops, and installs the E11 "
             "configuration; registered before --final"},
    {"if": "the registry files' layout differs from the reader's assumption (smoke)",
     "then": "the reader's read_registry() is amended and re-tested before --final"},
    {"if": "Main UI's Analyze view requests the history with parameters other than the REST defaults (smoke uicapture)",
     "then": "E11_RENDER_PARAMS is set to them for E11-CLO and the arms, registered before --final"},
    {"if": "the JDBC SQLite add-on cannot be installed from the remote repository during provisioning",
     "then": "the offline add-ons archive of the same release is used; registered before --final"},
    {"if": "the measured closure contains a field the reader does not commit (closure gate)",
     "then": "the run stops after E11-CLO; the reader is amended (HP_OH_CLOSURE_REGISTRY or code), re-tested, the "
             "amendment registered and stamped, then E11-DET runs"},
]


def document(final):
    plan = e11ops.make_plan(SEED)
    plan_text = json.dumps(plan, indent=1, sort_keys=True) + "\n"
    now = dt.datetime.now(dt.timezone.utc)
    pre = {
        "experiment": "E11 (RQ4): does HOMEPROV's principle carry to a third hub family? openHAB 5.2.3 with JDBC "
                      "persistence on SQLite: renderer closure, the two failure directions of schema-chosen and "
                      "whole-row commitments, and the shipped monitor with only its read path replaced",
        "status": "REGISTERED" if final else "DRAFT",
        "registered_at": now.isoformat() if final else None,
        "registered_before": "any event of the real run (tag e11_main; run directory on the external SSD); smoke runs "
                             "precede it and are not results",
        "approval": {"pi": "2026-10-14, verbatim option label: 'Reframe + openHAB (E11)' (SP2027_ACCEPT_PLAN.md, "
                           "decision log)",
                     "framing": RESEARCH_QUESTION["framing"]},
        "research_question": RESEARCH_QUESTION,
        "design": {"file": "drafts/round13/E11_DESIGN.md", "sha256": h(DESIGN)},
        "hub": {"image": HUB_IMAGE, "arm64_manifest": HUB_IMAGE_ARM64, "release": "openHAB 5.2.3 (2026-10-10)",
                "persistence": "JDBC (org.openhab.persistence.jdbc 5.2.3) on SQLite (org.xerial sqlite-jdbc 3.53.1.0, "
                               "feature openhab-persistence-jdbc-sqlite), default settings, database in the userdata "
                               "volume; time zone UTC; implicit user role off; Basic auth on",
                "accounts": "owner (administrator), member (user); per-run passwords, fingerprints only"},
        "monitor": {"code": "monitor/monitor.py unchanged, run with testbed/e11/monitor/oh_monitor.py as entry point",
                    "settings": {"HOMEPROV_SCHEME": "closure", "HOMEPROV_COVERAGE": 1, "HOMEPROV_KEYLOG": 0,
                                 "HOMEPROV_READ": "copy (SQLite backup API)", "HOMEPROV_QUICK_CHECK_EVERY": 1,
                                 "HOMEPROV_PERIOD": 5, "record signatures": "Ed25519", "reply tags": 1,
                                 "anchor": "linked (v2) with a head witness on the host outside Docker's VM",
                                 "archive": "rows of the last 180 s per poll, for the offline schemes"},
                    "mounts": "hub userdata volume read-only; no write path to the hub"},
        "parameters": {"late_bound_s": e11ops.LATE_BOUND_S, "seal_wait_s": e11ops.SEAL_WAIT_S, "arm_n": e11ops.ARM_N,
                       "arm_spacing_s": e11ops.ARM_SPACING_S, "seed": SEED},
        "plan": {"generated_by": "testbed/e11/e11ops.py plan --seed %d" % SEED,
                 "sha256": hashlib.sha256(plan_text.encode()).hexdigest(), "plan": plan},
        "hypotheses": HYPOTHESES, "instrument_arms": ARMS, "benign_operations": BENIGN, "outcomes": OUTCOMES,
        "scoring": SCORING, "exclusions": EXCLUSIONS, "analysis_plan": ANALYSIS,
        "known_limits_stated_in_advance": LIMITS, "registered_alternatives": ALTERNATIVES,
        "render_params": {"used_by_E11_CLO_and_the_arms": e11ops.RENDER_EXTRA,
                          "main_ui_analyze_request": {"starttime": "now - 24 h", "endtime": "now", "boundary": "true",
                                                      "itemState": "true"},
                          "why": "the registered alternative on Main UI's request was triggered (smoke uicapture, "
                                 "2026-10-24): boundary=true is used; itemState=true is left out of E11-CLO and the "
                                 "arms because it appends the hub's live item state stamped with the query time (not "
                                 "a stored row; renders 2.5 s apart differ only in that point); uicapture replays "
                                 "Main UI's own request and compares bodies without that point"},
        "amendments_before_registration": {
            "log": PAPER + "/drafts/round13/E11_DECISIONS.md (entries dated 2026-10-23 and 2026-10-24)",
            "log_sha256_at_registration": h(PAPER + "/drafts/round13/E11_DECISIONS.md"),
            "smoke_runs": "e11_smoke1 to e11_smoke6 (2026-10-24; outputs outside exp/out; not results)",
            "harness_changes": [
                "Karaf console: commands on stdin with a 60 s limit (5.2.3 closes an argument command); outputs of "
                "commands carrying a password are discarded",
                "hub restart: the removed provisioning network is recreated INTERNAL for the restart, then removed; "
                "the hub stays on its internal network only; the in-place probe fails if its restart fails",
                "JDBC persistence at a first start: openHAB 5.2.3 left the bundle Resolved or its feature half "
                "installed in many starts; the harness starts the bundle or reinstalls the feature (at most 3 kicks), "
                "logs each and reports jdbc_bundle_started_by_harness; E11's bundles are deployed after JDBC is up",
                "uicapture signs in through openHAB's own form (Main UI ignores HTTP basic credentials)",
                "the stack guard also refuses while E12 runs; the hardened-monitor unit test no longer re-applies "
                "an applied patch"],
            "hypotheses_arms_benign_operations_outcomes_scoring": "unchanged"},
        "code_sha256": {"computed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "files": {f: h(os.path.join(R, f)) for f in FILES}},
    }
    if not final:
        pre["code_sha256"]["note"] = ("DRAFT: monitor/monitor.py is the E9-frozen version until E9 ends and E10's patches "
                                      "are applied; the hashes to freeze are computed at --final, after E10, the smoke "
                                      "runs and any registered alternative")
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
