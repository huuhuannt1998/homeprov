"""E9 pre-registration: writes the draft (default) or the registered file (--final) from the run's own parameters, the
schedule testbed/e9/e9ops.py generates, and the sha256 of every file the run executes or scores with.

    python3 testbed/e9/e9_prereg.py --out "drafts/round13/E9_PREREG_DRAFT.json"             # draft (any time)
    python3 testbed/e9/e9_prereg.py --final --out exp/out/e9_preregistration.json           # at registration (refuses
                                                                                             # to overwrite)
--start moves the week (default 2026-10-11T12:00:00Z); --trials sets the attack trials per arm per day (default 5).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
E6 = "<research-dir>/HOMEPROV-P13-exp/e6/code/homeprov_e6/__init__.py"
FILES = ["monitor/monitor.py", "monitor/Dockerfile.sign", "monitor/requirements-sign.txt",
         "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py", "testbed/anchord/headwitness.py",
         "testbed/anchord/chainverify.py", "testbed/e8/anchord-e8.Dockerfile", "exp/stages/e7_verify.py",
         "exp/stages/e8_score.py", "exp/stages/e9_score.py", "exp/rig/markers.py", "exp/rig/marker_issuer.py",
         "testbed/e9/run_e9.sh", "testbed/e9/e9ops.py", "testbed/e9/smoke_stack.sh", "testbed/e9/e9_prereg.py",
         "testbed/e9/start_e9_at.sh",
         "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py",
         "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py",
         # tests the run's preflight runs (python3 -m pytest -q monitor; python3 -m pytest -q testbed/anchord)
         "monitor/test_coverage.py", "monitor/test_node_hash.py", "monitor/test_e9.py", "monitor/test_e9_dishonest.py",
         "testbed/anchord/test_anchor_chain.py", "testbed/anchord/test_anchor_e8.py", "testbed/anchord/test_anchor_e9.py",
         "testbed/anchord/test_anchor_cache.py", "testbed/anchord/test_anchor_stall.py",
         # part A's check scripts and the result files behind the per-party table and the read modes
         "exp/stages/e9_dishonest_anchor.py", "exp/stages/e9_dishonest_markers.py",
         "exp/stages/e9_purge_disconnect_offline.py", "exp/out/e9_dishonest_anchor.json",
         "exp/out/e9_dishonest_anchor_markers.json", "exp/out/e9_direct_read_identity.json",
         "exp/out/e9_readonly_shm_lockdrop.json"]


# The time from the RESTORE marker (its issued_ts) to the anchored RESTORE_DONE, measured by the final smoke run on the
# frozen code (e9_score.py restore_done_check, restore_to_done_anchored_s); filled in before registration.
RESTORE_DONE_MEASURED = os.environ.get("E9_RESTORE_DONE_MEASURED", (
    "82.5 s (anchor-direct 82.50 s, anchor-copy 82.53 s, chain receive times; final smoke e9s_final, 2026-10-10 07:18:08 "
    "to 07:19:31 UTC: hub stop, archive placed and its copy checked, start, Home Assistant's restore, the restored "
    "watermark read outside the hub, RESTORE_DONE issued; H 35.2 s and the first poll reading the restored recorder "
    "37.8 s after the RESTORE marker)"))
RESTORE_DONE_BASIS = (
    "review N1 / re-check 2: a RESTORE marker excuses nothing unless its operator-signed RESTORE_DONE is issued and "
    "anchored within this after the RESTORE marker's issued_ts. "
    + ("Measured in the final smoke run on the frozen code: %s from the RESTORE marker to the anchored RESTORE_DONE "
       "(both anchors). " % RESTORE_DONE_MEASURED if RESTORE_DONE_MEASURED else
       "MEASUREMENT PENDING: the final smoke run measures the time from the RESTORE marker to the anchored RESTORE_DONE. ")
    + "The reviewer estimated the worst case at about 300 s; smoke 3 (old sequence, no RESTORE_DONE) took 78 s from the "
    "RESTORE marker to the operator's post-restart observation; the hub stop, the archive check and up to a minute of "
    "Docker latency per container start are inside 600 s")


def h(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--start", default="2026-10-11T12:00:00Z")
    ap.add_argument("--trials", type=int, default=5)
    a = ap.parse_args()
    sched = json.loads(subprocess.run([sys.executable, os.path.join(R, "testbed/e9/e9ops.py"), "schedule", "--start",
                                       a.start, "--days", "7", "--trials", str(a.trials)],
                                      capture_output=True, text=True, check=True).stdout)
    ev = [{k: e[k] for k in ("utc", "type", "day", "room", "label", "ec_arms", "e7_arms", "trials", "keep_days") if k in e}
          | ({"post_utc": dt.datetime.fromtimestamp(e["post_at"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
             if "post_at" in e else {}) for e in sched["events"]]
    start = sched["start_utc"]
    d = lambda n, hm: (dt.datetime.fromisoformat(start.replace("Z", "+00:00")) + dt.timedelta(days=n - 1)).strftime("%Y-%m-%d") + " " + hm
    pre = {
        "experiment": "E9: the deployed configuration for seven days on the lab installation (Home Assistant 2026.7.4, "
                      "virtual devices, purge_keep_days 30, auto_purge on): two monitors (direct read and copy), both "
                      "stable columns with coverage, Ed25519 record signatures, escrow, name-map digest, per-row keylog "
                      "binding and the full-history initial seal; each with its own linked anchor (append key, separate "
                      "operator key, tagged replies) and a head witness outside Docker's VM; the deployment's own nightly "
                      "purges under operator-signed PURGE markers, one planned restart, one restore, one benign rename, "
                      "the person re-link attack and its benign counterpart, and one attack batch a day",
        "status": ("REGISTERED" if a.final else
                   "DRAFT (harness agent, 2026-10-09). Becomes exp/out/e9_preregistration.json with "
                   "`python3 testbed/e9/e9_prereg.py --final --out exp/out/e9_preregistration.json` after the code review "
                   "and the smoke run on the final code; its sha256 is then timestamped externally (OpenTimestamps) if "
                   "that works from this machine, otherwise recorded in the run log only."),
        "registered_at": dt.datetime.now(dt.timezone.utc).isoformat() if a.final else None,
        "registered_before": "any event of the main run (tag e9_main); smoke runs on the scratch stack (prefix e9s-, "
                             "outputs outside exp/out) precede it and are not results",
        "approval": "PI 2026-10-09: '7 days (Recommended)'; code changes and smaller additions 'You decide what is the "
                    "best for s&p' (drafts/round13/E9_DESIGN.md)",
        "design": {"doc": "drafts/round13/E9_DESIGN.md (section B)",
                   "impl_notes": "drafts/round13/E9_IMPL_NOTES.md (part A: A1-A7)",
                   "run_notes": "drafts/round13/E9_RUN_NOTES.md",
                   "purge_timer_diagnosis": "drafts/round13/E2_PURGE_DIAGNOSIS.md"},
        "schedule": {
            "start_utc": start, "end_utc": sched["end_utc"] + " (end event; the freeze and scoring follow)",
            "condition": "starts only if the part-A code is reviewed, both test suites pass, a smoke run on the final code "
                         "exits 0 and scores; otherwise the start moves by whole days (HPR_E9_START) and this file is "
                         "re-issued before any event",
            "day_window": "day d = [START + (d-1) x 24 h, START + d x 24 h), 12:00 UTC to 12:00 UTC",
            "daily_utc": {"14:00": "attack batch (rooms rotate porch, hallway, kitchen)",
                          "03:40": "sleep guard (restart the hub if its 04:12 purge timer is more than 30 s late)",
                          "03:55": "recorder snapshot night<d>_pre",
                          "04:07:00 / 04:10:00": "operator PURGE marker: the issuer container starts / posts to both anchors "
                                                 "(retried until 04:12:00, when the hub purges)",
                          "04:45": "recorder snapshot night<d>_post", "12:00:30": "recorder snapshot day<d>_end"},
            "special": {
                d(2, "20:00"): "planned hub restart",
                d(3, "17:00"): "name-map session, in this order: benign entity rename (light.porch_light -> 'Porch lamp') "
                               "under a RENAME marker; the person re-link as a MOVE (hpr has one household account): the "
                               "household account's user_id moves from its person to the person without an account "
                               "('Jordan Rivera (household)', created at setup), two person_update calls (unlink P1, link "
                               "P2), declared under RENAME markers for every intermediate name-map state, and moved back "
                               "(unlink P2, link P1) the same way; then the ATTACK, the same move with no marker and no "
                               "recorder row written, held 180 s (the verifier consumes a RENAME marker at its first "
                               "matching transition and counts a duplicated marker once, so the earlier declared move "
                               "cannot excuse it); its declared move back. The run log names the mode used (move; a swap of "
                               "two persons' accounts only on a hub without the account-less person)",
                d(4, "20:00") + " / 20:30": "backup of the recorder: a consistent SQLite copy wrapped in Home Assistant's "
                                            "backup format and hashed, HELD OUTSIDE THE HUB (run directory, read-only) / "
                                            "an operator RESTORE marker (backup_wm, archive and database sha256 signed "
                                            "into it); 30 s later the hub is STOPPED, the archive and .HA_RESTORE "
                                            "(restore_database=true, restore_homeassistant=false) are placed, the "
                                            "archive's copy in the hub is read back and must match the signed sha256 "
                                            "(else no restore), the hub is started and Home Assistant's own start-up "
                                            "restore runs; once its log says 'Restore complete' and the operator reads "
                                            "the restored recorder's watermark from outside the hub, an operator "
                                            "RESTORE_DONE marker (rig.marker_issuer.restore_done_marker: restore_nonce, "
                                            "restore_sha256 = the SHA-256 of the RESTORE marker's canonical JSON, "
                                            "post_restart_wm, hub_started_ts H = the restored hub's container start) is "
                                            "issued and anchored within 600 s of the RESTORE marker (review re-check N1, "
                                            "E9_IMPL_NOTES.md 12.1)"},
            "events": ev,
            "generated_by": "python3 testbed/e9/e9ops.py schedule --start %s --days 7 --trials %d" % (a.start, a.trials),
            "notes": ["2026-10-11 is the second Sunday of the month: the 04:12 purge that day also repacks (auto_repack); "
                      "it falls before START. No second Sunday falls inside the run.",
                      "Every wait is on the wall clock; no hub restart in [03:50, 04:45) UTC."]},
        "parameters": {
            "LATE_BOUND_s": 30, "GAP_s": 30, "LATE_BOUND_basis": "unchanged from E7/E8 (exp/out/e7_preregistration.json)",
            "poll_period_s": 5, "seal_wait_s": 130, "K_inserted_rows": 9, "bd_min_age_s": 130, "bd_lookback_s": 1800,
            "restart_wait_s": 45, "purge_keep_days": 30, "verifier_purge_keep_s": 2592000, "verifier_purge_tol_s": 60,
            "verifier_purge_tol_basis": "tol > 0 is required: Home Assistant's own cutoff (its fire time minus keep) "
                                        "lies in [c0, c0 + tol] with c0 = scheduled - keep; with tol = 0 a purge that "
                                        "fires a fraction of a second late leaves unexcused deletions (E9_IMPL_NOTES.md "
                                        "10.2); 60 s as in E2",
            "verifier_purge_seen_slack_s": 60,
            "verifier_purge_seen_slack_basis": "e7_verify.py PURGE_SEEN_SLACK_S (review R7): a removed row counts as "
                                               "purged only if first observed by a poll that copied at or before "
                                               "scheduled + tol + 60 s",
            "verifier_restore_tol_s": 30, "verifier_restore_max_age_s": 86400, "verifier_restore_done_max_s": 600,
            "verifier_restore_done_max_basis": RESTORE_DONE_BASIS,
            "restore_done_validity_rule": "scorer (e9_score.py restore_done_check), review re-check 2: every anchored, "
                                          "operator-signed RESTORE_DONE must carry hub_started_ts H and a post_restart_wm "
                                          "consistent with the restored recorder observed afterwards (the first snapshot "
                                          "after the RESTORE_DONE was anchored): post_restart_wm >= the RESTORE marker's "
                                          "signed backup_wm in each table, the recorder holds the keys up to "
                                          "post_restart_wm, and no row with a key above backup_wm was written before H. "
                                          "A RESTORE_DONE lacking H or failing a check is reported INVALID and the restore "
                                          "it closes counts as not excused (its RESTORE-excused segments are counted as "
                                          "unexcused). Without H the verifier would excuse a deletion between the restart "
                                          "and the first post-restore poll (reproduced by the reviewer); the harness always "
                                          "sends H",
            "verifier_restore_max_age_basis": "a RESTORE marker with issued_ts - restore_point_ts above it is rejected "
                                              "(review m2); E9's restore marker comes about 30 min after its backup",
            "purge_marker_post_s_before_purge": 120, "sleep_guard_threshold_s": 30,
            "restart_guard_utc": ["03:50", "04:45"], "marker_lead_s": 30, "namemap_step_s": 60,
            "namemap_attack_hold_s": 180, "witness_mode": "sync",
            "initial_seal": "M-direct first; M-copy only after M-direct's history is anchored (its poll counter 6 polls "
                            "past its first record); at most 5,400 s each, else the run does not start",
            "monitor_env_both": "HOMEPROV_SCHEME=stable HOMEPROV_COVERAGE=1 HOMEPROV_ESCROW_DIR HOMEPROV_COST_LOG "
                                "HOMEPROV_SIGN_KEY HOMEPROV_REPLY_TAGS=1 HOMEPROV_NAMEMAP_DIR=/cfg/.storage HOMEPROV_SINCE=0 "
                                "HOMEPROV_ROWBIND=1 HOMEPROV_KEYLOG_REWIND=1 HOMEPROV_PERIOD=5",
            "monitor_env_direct": "HOMEPROV_READ=direct HOMEPROV_QUICK_CHECK_EVERY=720",
            "monitor_env_copy": "HOMEPROV_READ=copy HOMEPROV_QUICK_CHECK_EVERY=1",
            "quick_check_every": {"M-direct": 720, "M-copy": 1},
            "quick_check_every_smoke_only": "the smoke runs use M-direct 12 (once a minute) so the hourly path is "
                                            "exercised several times; the real run keeps 720 (its preflight refuses "
                                            "any other value). Final smoke: M-direct quick_check due at 64 of 769 "
                                            "polls, snapshot stage median 242.6 ms when due against 1.3 ms otherwise; "
                                            "M-copy at every poll (705), median 124.3 ms; no quick_check failure and no "
                                            "unobservable poll in either",
            "quick_check_every_basis": "lead decision 2026-10-10. M-direct 720 (once an hour at 5 s polls): in direct mode "
                                       "quick_check reads the whole live database inside the read transaction and holds "
                                       "off a checkpoint's backfill for that long (E9_IMPL_NOTES.md section 9 item 4), "
                                       "while the per-poll consistency check (WAL salts, checkpoint sequence, change "
                                       "counter; read_raced) catches a torn read at every poll. M-copy 1 (every poll, as "
                                       "E8's copy path did). C1 measured direct mode at both cadences (E9_PRE_NOTES.md) and "
                                       "the final direct-mode re-run measures both again. The run's preflight refuses "
                                       "other values and logs each container's own setting",
            "verifier": "exp/stages/e7_verify.py verify --scheme stable --late-bound 30 --gap-s 30 --sign-pubkey <monitor> "
                        "--escrow <monitor escrow> --operator-pubkey <operator> --purge-keep-s 2592000 --purge-tol-s 60 "
                        "--restore-tol-s 30 --restore-max-age-s 86400 --restore-done-max-s 600 [--namemap-storage "
                        "<sanitized storage>, last day] "
                        "[--trials <day reports>]; each day again with --no-rowbind (suspects without the per-row "
                        "binding, which then is used nowhere); each night's post-purge snapshot again with "
                        "--no-purge-disconnect (the round-12 rule, for comparison)",
            "scorer_jobs": 2,
            "scorer_jobs_basis": "E9_VERIFY_JOBS=2 verifications in parallel, on the host after the freeze (not in "
                                 "Docker's VM). Measured with the indexed escrow on the E8 recorder history (E9_IMPL_NOTES.md "
                                 "11.2): a day window 64.8 s, 1.17 GB resident (1.36 GB peak footprint); a whole-history "
                                 "window 140.3 s, 1.81 GB resident (2.99 GB footprint): two jobs need at most about 6 GB "
                                 "of the Mac's 24 GB beside the Docker VM. Final smoke (full seed, 2.66 GB escrow per "
                                 "monitor): 18 verifications with 2 jobs in 877 s (day windows 64-72 s, whole-history "
                                 "windows 151-160 s)",
            "settings_checked": "against drafts/round13/E9_IMPL_NOTES.md section 8 (2026-10-10, part A final pending its "
                                "re-check); --final re-hashes every file"},
        "arms": {
            "per_day": {arm: a.trials for arm in ("PU", "PSR", "INS-L", "BD-S")},
            "per_arm_total": 7 * a.trials,
            "rooms_by_day": {str(i + 1): ("porch", "hallway", "kitchen")[i % 3] for i in range(7)},
            "components": {"homeprov_ec": ["PU", "PSR"], "homeprov_e7": ["INS-L", "BD-S"],
                           "homeprov_e6": "setup (persons) and the name-map session only; outside the repository, never "
                                          "released"},
            "order_per_batch": "homeprov_ec (PU, PSR), then homeprov_e7 (INS-L, BD-S); one hub restart switches each on "
                               "(exactly one listed in configuration.yaml), one more switches both off",
            "scored_by": "both monitors (each trial counts once per monitor)",
            "name_map": {"attack_move": 1, "benign_move_and_back": 1, "benign_entity_rename": 1, "declared_move_back": 1}},
        "benign_events": {"nightly_purges": 7, "operator_purge_markers": 7, "planned_restart": 1, "restore": 1,
                          "benign_rename": 1, "benign_person_swap_and_back": 1,
                          "setup": "before START: `person:` added to configuration.yaml, one person per household "
                                   "account (active, not system-generated) that has none, and one person without an "
                                   "account, 'Jordan Rivera (household)' (user_id null), the person move's target "
                                   "(homeprov_e6 person_create, the call the person/create websocket handler makes); no "
                                   "account and no token is created"},
        "outcomes": {
            "primary": {
                "unexcused_untouched": "per day and monitor: attributable violations on UNTOUCHED segments that the "
                                       "verifier does not excuse under an operator-signed marker, at one-second, minute "
                                       "and hour granularity, with the untouched anchored segments as denominators "
                                       "(paper's counting rule: a segment is touched when it holds a row any trial wrote, "
                                       "edited or named)",
                "purge": "per night and monitor: the verifier's NEW attributable violations between the 03:55 and 04:45 "
                         "snapshots over the historical window (segments sealed by the full-history initial seal), split "
                         "into excused (segment older than c0 gone, tolerance band [c0, c0 + tol], purge disconnect: count, "
                         "seconds, rows; and keylog ranges purged or disconnected) and unexcused, next to the round-12 rule "
                         "alone (--no-purge-disconnect); and the database's own evidence (rows older than the cutoff "
                         "before and after, retained state rows whose old_state_id the purge set to NULL, statistics_runs)",
                "detection": "per arm and monitor, per day and pooled: trials whose target second the verifier flags as "
                             "attributable at one-second granularity, k of n with the exact (Clopper-Pearson) 95% "
                             "interval"},
            "secondary": {
                "suspect_seconds": "untouched seconds of the day flagged by a failed keylog range, with the per-row "
                                   "binding and without it (--no-rowbind)",
                "name_map": "every digest transition: changed parts, excused by an operator RENAME marker anchored before "
                            "it with the new part digests, or unexcused (detected); the verifier's verdict",
                "restore": "segments and keylog ranges the verifier excuses under the RESTORE marker (rule "
                           "rows_from_the_backup: only segments sealed before the first poll that read the restored "
                           "recorder and ending after restore point - tol, every row in them an unchanged backup row "
                           "(key <= the signed backup_wm), every row gone above it; key ranges committed before that "
                           "poll, rows at or below backup_wm unchanged; E9_IMPL_NOTES.md 11.1; nothing without the "
                           "operator's RESTORE_DONE within --restore-done-max-s, and no segment starting at or after the "
                           "hub's start H it carries; a gone row must predate H, a reused-key row must follow it; 12.1), "
                           "the marker's status "
                           "(read_back_at, backup_last_key vs the recorder), the archive check in the hub, and any "
                           "violation outside it",
                "cost": "per day and monitor: per-poll copy or direct read, load, commit, append and total ms (median, "
                        "p90, max), the read path, failed appends, unobservable polls; seal delay",
                "quick_check": "per day and monitor: the polls at which quick_check was due (seq_local % N == 1, every "
                               "poll for N = 1), the per-poll snapshot/copy and total cost of those polls against the "
                               "others, and the polls the monitor's signed records report unobservable, by reason "
                               "(quick_check_failed, read_raced, after_read, direct_open_failed, file checks)",
                "bytes": "per day and monitor: bytes read and written by the monitor process (/proc/1/io rchar, wchar, "
                         "read_bytes, write_bytes; sampled every 60 s)",
                "host": "every wall-clock gap above 90 s, every pmset Sleep entry, every jump of the Docker VM's "
                        "time()-monotonic() offset above 5 s, every hub start with its cause, power source and lid state",
                "signatures_and_witness": "monitor records valid under each monitor's key; markers accepted under the "
                                          "operator's key; chain links, every witnessed head, the final head; anchor "
                                          "refusals by reason",
                "full_history_seal": "seconds holding a row at START without an anchored root (expected 0)"}},
        "exclusions": "only trials whose harness record carries an error are excluded, each counted and listed; a day "
                      "with a host sleep, a late event or an unplanned hub start is reported with it, not excluded; a "
                      "night whose purge did not run (database evidence) is reported as such and its marker as "
                      "unconsumed; if the Mac or Docker restarts, the run stops and the completed days are scored and "
                      "reported as an incomplete run",
        "known_limits_stated_in_advance": [
            "one physical machine: the witnesses run on the Mac outside Docker's VM, a separate trust domain, not a "
            "separate party",
            "the attack integrations are installed for each batch; the hub restarts three times a day for them",
            "Home Assistant arms its 04:12 purge on the VM's monotonic clock: a host sleep delays it (the sleep guard "
            "restarts the hub at 03:40 if so); a purge delayed past the marker's tolerance can delete rows younger than "
            "the scoped cutoff, which then stay unexcused",
            "the restore runs Home Assistant's own restore code at start-up on an archive the operator built from a "
            "consistent SQLite copy (Home Assistant's backup manager needs an access token the lab installation does "
            "not have)",
            "the person re-link attack is one move of the household account between two persons; E6 measured the "
            "effect of a re-link on displayed causes",
            "every recorder snapshot, the restore's backup included, is read OUTSIDE the hub: a throwaway container on "
            "the read-only mount of the configuration volume runs SQLite's online backup API from a read-only "
            "connection with read-only shared memory (one read transaction, as the direct-read monitor) into the run "
            "directory; only if that fails three times does a snapshot go through the hub container's /tmp, recorded "
            "per snapshot (event field 'method': readonly_mount or hub_tmp_fallback); the archive is then held outside "
            "the hub and checked again inside it, with the hub stopped, before the restore",
            "a declared multi-step change carries one RENAME marker per intermediate state; markers for states no seal "
            "caught stay unconsumed on the chain (reported)",
            "a host that withholds or moves markers can turn a benign purge, restore or rename into violations (a false "
            "accusation the every-head witness check detects unless the markers were never appended), never a "
            "violation into a match (exp/out/e9_dishonest_anchor_markers.json)",
            "backdating by less than about LATE_BOUND plus one poll period is scored as a benign late row; write-time "
            "forgery is outside the guarantee"],
        "code_sha256": {"computed_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "files": {f: h(os.path.join(R, f)) for f in FILES},
                        "homeprov_e6 (outside the repository; never released)": h(E6)},
    }
    if not a.final:
        pre["code_sha256"]["note"] = ("part A is still changing monitor.py, e7_verify.py and marker_issuer.py: these are "
                                      "the files as of computed_at; --final recomputes them")
        pre["lead_decisions_open"] = [
            "the three smoke-3 verifier findings are fixed in part A and the final smoke on the frozen code showed "
            "them as intended: the forced purge's band and disconnects excused with nothing left, the restore excused "
            "only between restore point - tol and H, the undeclared attack swap flagged after the consumed benign "
            "markers",
            "household accounts on hpr (lead's read-only check): one, 'Alex Rivera (household)', and no persons yet; "
            "the setup creates Alex's person and the account-less person, and day 3 uses the move",
            "memory (resolved by the final smoke on the frozen code, full 30-day seed, 1.2 M rows): the streamed "
            "full-history seal inside Docker's VM took 145 s (M-direct, 184 records) and 146 s (M-copy, 183 records) "
            "with cgroup memory.peak 946,692,096 B and 1,161,584,640 B (page cache included), no restart; Docker "
            "Desktop's memory need not be raised; the harness still seals one monitor at a time",
            "counts: 5 per arm per day (35 per arm) proposed; 10 per day (70) costs about 10 more minutes a day",
            "the stock hpr-monitor / hpr-anchord are stopped for the week (as E7/E8): a 7-day gap in the default chain",
            "configuration.yaml is restored byte for byte at the end; the persons stay in .storage/person"]
    mode = "x" if a.final else "w"
    with open(a.out, mode) as fh:
        json.dump(pre, fh, indent=1)
    print("wrote", a.out, h(a.out))


if __name__ == "__main__":
    main()
