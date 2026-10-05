"""E-C -- WRITE-TIME forgery on the real deployment: aggregate and verify.

WHAT THIS ANSWERS (review 4b). HOMEPROV commits to rows that already exist, so
its guarantee is about EDITING history, not about WRITING it. The review's
objection is that the in-process adversary of section 3.1 has no reason to edit
anything: it can make the false attribution be the row's content the first time
the recorder ever sees it, and no commitment scheme can detect that because
there is no earlier version to disagree with. Section 3.4 asserted that the
write-time strategies leave the timeline naming the service call. This measures
that assertion on the real deployment.

TWO MEASUREMENTS PER ARM.

  1. Renderer-confirmed misattribution, from the platform's own logbook, using
     byte-identical processor and principal-resolution code to the flagship, so
     an E-C rate and S1's 30/30 are produced by the same oracle over the same
     three configurations.

  2. HOMEPROV detection, from the SHIPPED external monitor and anchor running
     live throughout the run. Every anchored segment root in the run window is
     recomputed from the final recorder and compared against what the anchor
     holds. A trial counts as detected when the anchored segment containing the
     row the renderer judged fails that comparison.

WHY ARM P EXISTS. "HOMEPROV detected 0 of 30" is worth nothing on its own: it is
indistinguishable from a detector that was not running. Arm P performs the S1
post-commit laundering on rows the monitor had already sealed, in the same run,
against the same anchor, scored by the same verifier. P is the positive control
and its rate is the evidence that the zeros are a property of the attack.

WHY THE BENIGN FLOOR IS REPORTED. The hub commits rows about a second after the
event (recorder commit_interval 1), so a row can in principle land on disk after
the second it belongs to has already been sealed. That would produce a violation
no adversary caused. The rate of that is measured over anchored segments in the
window that no arm touched, at both granularities, and reported next to the
detection rates rather than assumed to be zero.
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")
sys.path.insert(0, os.path.join(ROOT, "exp"))

from rig import capability, stats                                  # noqa: E402

HUB = "hpr-hass"
ANCHORD = "hpr-anchord"
MONITOR = "hpr-monitor"
SCRATCH = os.environ.get("EC_SCRATCH", "/tmp/homeprov_ec_verify")

WRITE_TIME_ARMS = ("W1", "W2", "W2b", "W3")
# E-D arms: post-commit, but the target row was authored by a principal the
# adversary did not control, so there is no write-time forgery available for it.
# They are renderer-scored like the W arms, but by their OWN criterion -- see
# the component: for PU the household member is the TRUE principal, so "the
# renderer names the member" means the launder failed, the opposite of W1.
OTHER_PRINCIPAL_ARMS = ("PU", "PI")
RENDER_SCORED = WRITE_TIME_ARMS + OTHER_PRINCIPAL_ARMS
ALL_ARMS = ("W1", "W2", "W2b", "W3", "P") + OTHER_PRINCIPAL_ARMS
ARM_LABEL = {
    "W1": "minted Context(user_id=<household member>)",
    "W2": "minted parent context + fabricated automation_triggered",
    "W2b": "minted context id shared with a fabricated automation_triggered",
    "W3": "recorder write-path hook (module-level symbol rebind)",
    "P": "POST-COMMIT control: S1 laundering of an already-anchored row",
    "PU": "POST-COMMIT: laundering a household member's app unlock",
    "PI": "POST-COMMIT: laundering a second integration's service call",
}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


# ---------------------------------------------------------------- the monitor
def _load_monitor():
    """Import the SHIPPED monitor and use ITS commitment code.

    Re-implementing the fold here would let the verifier and the monitor drift,
    and a verifier that computes something the monitor never computed proves
    nothing. monitor.py's fold is pure; only its paths come from the environment.
    """
    os.makedirs(SCRATCH, exist_ok=True)
    os.environ.setdefault("HOMEPROV_SCRATCH", SCRATCH)
    os.environ.setdefault("HOMEPROV_DB", os.path.join(SCRATCH, "recorder.db"))
    sys.path.insert(0, os.path.join(ROOT, "monitor"))
    import monitor                                                 # noqa: PLC0415
    return monitor


def snapshot_recorder() -> str:
    """A CONSISTENT copy of the live recorder, via SQLite's own backup API.

    Not shutil.copy2: the hub is still writing, and a byte copy of a live WAL
    database can be torn. sqlite3.Connection.backup takes a transactionally
    consistent snapshot including WAL content, which is what a verifier needs and
    what the monitor's own validate_copy() would otherwise have to reject.
    """
    dst = os.path.join(SCRATCH, "recorder.db")
    os.makedirs(SCRATCH, exist_ok=True)
    inner = "/config/ec_verify_copy.db"
    sh(f"docker exec {HUB} rm -f {inner} {inner}-wal {inner}-shm")
    r = subprocess.run(
        ["docker", "exec", HUB, "python3", "-c",
         "import sqlite3;s=sqlite3.connect('/config/home-assistant_v2.db',timeout=120);"
         f"d=sqlite3.connect('{inner}');s.backup(d);d.close();s.close();print('ok')"],
        capture_output=True, text=True)
    if "ok" not in r.stdout:
        raise SystemExit("recorder snapshot failed: %s %s" % (r.stdout, r.stderr))
    subprocess.run(["docker", "cp", f"{HUB}:{inner}", dst], check=True,
                   capture_output=True)
    sh(f"docker exec {HUB} rm -f {inner}")
    for side in ("-wal", "-shm"):                 # the backup is checkpointed
        p = dst + side
        if os.path.exists(p):
            os.remove(p)
    return dst, time.time()


def anchored_roots(t_start: float, t_snapshot: float):
    """First-write-wins roots the anchor holds, per granularity and segment.

    FIRST write, not last: that is what verification selects, and it is the rule
    the daemon enforces (a conflicting root for an anchored segment is refused
    with 409). Taking the newest would silently verify against whatever the last
    writer said.

    THE UPPER BOUND IS THE SNAPSHOT, NOT THE END OF THE RUN. The monitor keeps
    sealing while the verifier works, so a root anchored after the recorder
    snapshot was taken describes rows the snapshot cannot contain, and comparing
    the two manufactures violations out of nothing. A first draft of this
    verifier bounded the chain at t_end + 300s and duly reported eight
    "segment_absent_now" violations that were entirely an artifact of reading a
    chain newer than the database. Only roots the snapshot could already account
    for are admitted.
    """
    raw = subprocess.run(["docker", "exec", ANCHORD, "cat", "/anchor/chain.jsonl"],
                         capture_output=True, text=True).stdout
    roots = {}
    n_records = n_in_window = 0
    unobservable = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        n_records += 1
        payload = rec.get("payload") or {}
        ts = payload.get("ts") or rec.get("recv_ts") or 0.0
        if not (t_start <= ts <= t_snapshot):
            continue
        n_in_window += 1
        if payload.get("evidence_unobservable"):
            unobservable.append({"ts": ts, "reason": payload.get("reason")})
            continue
        for gran, segs in (payload.get("sealed") or {}).items():
            if not isinstance(segs, dict):
                continue
            for seg, v in segs.items():
                key = (gran, str(seg))
                if key not in roots and isinstance(v, dict):
                    roots[key] = {"acc": v.get("acc"), "n": v.get("n"),
                                  "anchored_at": ts, "seq": rec.get("seq")}
    return roots, {"chain_records_total": n_records,
                   "chain_records_in_window": n_in_window,
                   "evidence_unobservable_records": unobservable}


def verify_window(monitor, db, roots, t_start, t_end):
    """Recompute every anchored segment of the RUN from the final recorder.

    The segment range is the run window. The chain was already bounded by the
    snapshot time; bounding the segments by the run as well keeps the benign
    floor a property of the measured period instead of drifting with however long
    the verifier happened to take.
    """
    nodes = monitor.load(db)                       # whole history, no `since`
    phi = monitor.commit(nodes)
    widths = dict(monitor.GRAN)
    results = {}
    for (gran, seg), anchored in roots.items():
        w = widths.get(gran)
        if w is None:
            continue
        seg_start = int(seg) * w
        if not (t_start - w <= seg_start <= t_end + w):
            continue
        got = (phi.get(gran) or {}).get(str(seg))
        if got is None:
            results[(gran, seg)] = {"violation": True, "why": "segment_absent_now",
                                    "anchored": anchored, "recomputed": None,
                                    "delta_n": None, "mechanism": "segment_vanished"}
        elif got["acc"] != anchored["acc"] or got["n"] != anchored["n"]:
            d_n = got["n"] - anchored["n"]
            # The direction of the row-count change separates the two causes
            # cleanly, and it is worth recording rather than inferring: a row that
            # lands on disk after its segment was sealed INCREASES the count and no
            # adversary caused it, while the laundering deletes an event and
            # DECREASES it. An in-place edit leaves the count alone.
            results[(gran, seg)] = {
                "violation": True, "why": "root_mismatch",
                "anchored": anchored, "recomputed": got, "delta_n": d_n,
                "mechanism": ("rows_arrived_after_seal" if d_n > 0 else
                              "rows_removed_after_seal" if d_n < 0 else
                              "content_changed_in_place")}
        else:
            results[(gran, seg)] = {"violation": False, "anchored": anchored,
                                    "recomputed": got}
    return results, {"n_nodes_recomputed": len(nodes)}


# ------------------------------------------------------------------- scoring
def trial_row_ts(t):
    """The timestamp of the row the verdict is about.

    For a write-time arm that is the row the RENDERER judged (judged_row), not
    whatever row happened to be captured at actuation time -- an MQTT device can
    echo a second row a few seconds later and the timeline then judges that one.
    For arm P it is the row that was anchored and then edited.
    """
    for k in ("judged_row", "forged_row", "row_before"):
        r = t.get(k)
        if isinstance(r, dict) and r.get("ts"):
            return float(r["ts"]), r.get("state_id")
    return None, None


def main(rooms, tag="e_c"):
    t_start = float(open(os.path.join(OUT, "%s_t_start" % tag)).read().strip())
    t_end = float(open(os.path.join(OUT, "%s_t_end" % tag)).read().strip())

    per_room, trials = [], []
    for room in rooms:
        f = os.path.join(OUT, "%s_report_%s.json" % (tag, room))
        if not os.path.exists(f):
            print("  %-9s MISSING" % room)
            continue
        d = json.load(open(f))
        for t in d.get("trials", []):
            t["room"] = room
            t["household_member_user_id"] = d.get("household_member_user_id")
            trials.append(t)
        per_room.append({"room": room, "n_trials": len(d.get("trials", [])),
                         "innocent_party": d.get("innocent_party"),
                         "household_member_user_id": d.get("household_member_user_id"),
                         "target": d.get("target")})
    if not trials:
        raise SystemExit("no per-room reports found; nothing to aggregate")

    monitor = _load_monitor()
    db, t_snapshot = snapshot_recorder()
    vok, vreason, vdetail = monitor.validate_copy(db)
    if not vok:
        raise SystemExit("recorder snapshot did not validate (%s); refusing to "
                         "verify against a view that may be inconsistent" % vreason)
    roots, chain_info = anchored_roots(t_start, t_snapshot)
    verdicts, recompute_info = verify_window(monitor, db, roots, t_start, t_end)
    widths = dict(monitor.GRAN)

    # -------- per-trial detection, at both granularities --------------------
    touched = {"second": set(), "minute": set()}
    for t in trials:
        ts, _sid = trial_row_ts(t)
        if ts is None:
            continue
        for g in ("second", "minute"):
            touched[g].add(str(int(ts // widths[g])))

    for t in trials:
        ts, sid = trial_row_ts(t)
        t["_row_ts"] = ts
        t["_row_state_id"] = sid
        det = {}
        for g in ("second", "minute"):
            if ts is None:
                det[g] = {"segment": None, "anchored": False, "violation": None}
                continue
            seg = str(int(ts // widths[g]))
            v = verdicts.get((g, seg))
            det[g] = {"segment": seg,
                      "anchored": (g, seg) in roots,
                      "violation": (None if v is None else bool(v["violation"])),
                      "why": (None if v is None else v.get("why"))}
        t["_detection"] = det

    # -------- benign floor: anchored segments no arm touched ----------------
    benign = {}
    for g in ("second", "minute"):
        segs = [(gg, s) for (gg, s) in verdicts if gg == g and s not in touched[g]]
        k = sum(1 for key in segs if verdicts[key]["violation"])
        benign[g] = {**(stats.clopper_pearson(k, len(segs)) if segs
                        else {"k": 0, "n": 0, "prop": None}),
                     "what": "anchored %s-segments inside the run window that no "
                             "arm touched and that fail recomputation" % g}

    # ---- did the attack leave an operational trace in the hub's own log? ---
    # W3 rebinds a symbol on the recorder's write path. A hook that breaks the
    # recorder is self-announcing, and one variant of this attack does exactly
    # that: rebinding the module-global `core.States` to a proxy class makes
    # SQLAlchemy reject `update(States)` in _commit_event_session, every
    # CommitTask fails, and the hub stops writing rows for as long as the hook is
    # installed. The variant measured here rebinds only `States.from_event`, and
    # whether that is silent is a fact about this run, not an assertion.
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t_start))
    log = subprocess.run(["docker", "logs", "--since", since, HUB],
                         capture_output=True, text=True)
    logtext = (log.stdout or "") + (log.stderr or "")
    n_sqla = sum(1 for ln in logtext.splitlines()
                 if "SQLAlchemyError" in ln or "ArgumentError" in ln)
    n_rec_err = sum(1 for ln in logtext.splitlines()
                    if "ERROR" in ln and "recorder" in ln)
    recorder_health = {
        "sqlalchemy_errors_in_window": n_sqla,
        "recorder_error_lines_in_window": n_rec_err,
        "how": "docker logs --since <t_start> %s, counting SQLAlchemyError / "
               "ArgumentError and recorder ERROR lines" % HUB,
        "why_it_matters": "zero means the write-path hook left no operational "
                          "trace: the recorder kept committing normally while the "
                          "forgery was written. A hook that crashes the recorder "
                          "would announce itself in the hub's own log.",
    }

    # ---- what actually caused each violation, by row-count direction --------
    mechanisms = {}
    for g in ("second", "minute"):
        c = collections.Counter()
        for (gg, seg), v in verdicts.items():
            if gg != g or not v["violation"]:
                continue
            c[v.get("mechanism") or "unknown"] += 1
            c["untouched_" + (v.get("mechanism") or "unknown")] += (
                0 if seg in touched[g] else 1)
        mechanisms[g] = dict(c)

    # ------------------------------------------------------------ per arm ---
    arms = {}
    present = [a for a in ALL_ARMS if any(t.get("arm") == a for t in trials)]
    for arm in present:
        rows = [t for t in trials if t.get("arm") == arm]
        valid = [t for t in rows if not t.get("err") and not t.get("error")]
        out = {"strategy": ARM_LABEL[arm],
               "write_time": arm in WRITE_TIME_ARMS,
               "n_attempted": len(rows), "n_valid": len(valid),
               "failures": [t.get("err") or t.get("error") for t in rows
                            if t.get("err") or t.get("error")],
               "per_room": {}}
        for room in rooms:
            rr = [t for t in valid if t.get("room") == room]
            if arm in RENDER_SCORED:
                out["per_room"][room] = {
                    "n": len(rr),
                    "misattributed": sum(1 for t in rr
                                         if t.get("renderer_confirmed_misattribution"))}
            else:
                out["per_room"][room] = {"n": len(rr)}

        if arm in RENDER_SCORED:
            k = sum(1 for t in valid if t.get("renderer_confirmed_misattribution"))
            out["renderer_confirmed_misattribution"] = stats.clopper_pearson(k, len(valid))
            # A FIELD THE DRIVER NEVER EMITTED IS NOT A MEASUREMENT OF ZERO.
            # The other-principal driver (PU/PI) scores no strict S1 ordering,
            # runs no control arm, and reports the post-attack person check as
            # renderer_still_names_person. Scoring those keys anyway turned three
            # never-evaluated fields into authoritative-looking zeros over the
            # pooled n, which is exactly how a fabricated number reaches a paper.
            # Write-time arms are unaffected: they do emit all three, and W1's
            # strict 0/30 is a real measurement that must stay a real 0.
            def _if_emitted(field, fn):
                if not any(field in t for t in valid):
                    return "not_measured_for_this_arm"
                return fn()
            out["misattribution_strict_s1_ordering"] = _if_emitted(
                "misattribution_strict_s1_ordering",
                lambda: stats.clopper_pearson(
                    sum(1 for t in valid
                        if t.get("misattribution_strict_s1_ordering")), len(valid)))
            out["principals_rendered"] = sorted(
                {str(t.get("principal_rendered")) for t in valid})
            out["control_principals"] = _if_emitted(
                "control_principal",
                lambda: sorted({str(t.get("control_principal")) for t in valid}))
            out["renderer_named_person"] = _if_emitted(
                "renderer_names_person",
                lambda: stats.clopper_pearson(
                    sum(1 for t in valid if t.get("renderer_names_person")), len(valid)))
            out["renderer_named_automation"] = stats.clopper_pearson(
                sum(1 for t in valid if t.get("renderer_names_automation")), len(valid))
            out["db_writes_per_trial"] = sorted({t.get("db_writes", 0) for t in valid})
        if arm in OTHER_PRINCIPAL_ARMS:
            # THE ARM'S OWN PREMISE, CHECKED. PU/PI claim the target row was
            # authored by a principal the adversary did not control. If the clean
            # render never named that principal, the trial did not test what the
            # arm says it tests, and "misattributed 30/30" would be true of
            # trials that had nothing to launder. This is the vacuity check the
            # marker-abuse and stage-18 defects both needed.
            out["clean_principals"] = sorted({str(t.get("clean_principal"))
                                              for t in valid})
            out["clean_named_the_author"] = stats.clopper_pearson(
                sum(1 for t in valid
                    if (t.get("clean_names_person") if arm == "PU"
                        else bool(t.get("clean_principal")))), len(valid))
            out["still_names_person_after"] = sum(
                1 for t in valid if t.get("renderer_still_names_person"))
            out["principal_moved"] = stats.clopper_pearson(
                sum(1 for t in valid if t.get("principal_moved")), len(valid))
        else:
            out["db_writes_per_trial"] = sorted({t.get("db_writes") for t in valid
                                                 if t.get("db_writes") is not None})
            out["operations_used"] = [t.get("operations_used") for t in valid][:3]

        for g in ("second", "minute"):
            anch = [t for t in valid if (t.get("_detection") or {}).get(g, {}).get("anchored")]
            det = sum(1 for t in anch if t["_detection"][g]["violation"])
            out["homeprov_detection_%s" % g] = {
                **(stats.clopper_pearson(det, len(anch)) if anch
                   else {"k": 0, "n": 0, "prop": None}),
                "n_trials_whose_segment_was_anchored": len(anch),
                "n_valid_trials": len(valid)}
        if arm == "W3":
            out["hook"] = {
                "symbols_rebound": sorted({s for t in valid
                                           for s in (t.get("symbols_rebound") or [])}),
                "rows_forged_on_write": sum(1 for t in valid if t.get("row_written_forged")),
                "collateral_rows_seen_untouched": sum(
                    t.get("hook_collateral_rows_seen_untouched", 0) for t in valid),
                "residual_adversary_call_service_events": sum(
                    len(t.get("residual_adversary_call_service") or []) for t in valid),
                "note": "the hook rebinds ONE symbol and forges only the state row; "
                        "the adversary's own call_service event survives under its "
                        "true context and is counted here. S1's post-commit "
                        "adversary removed it with one DELETE."}
        arms[arm] = out

    result = {
        "experiment": "E-C",
        "what": "write-time forgery of actuation attribution on the real "
                "deployment, with a post-commit positive control",
        "substrate": "real (mosquitto + MQTT discovery + shipped motion-light "
                     "blueprint), three home configurations",
        "oracle": "the platform's own logbook EventProcessor, identical form and "
                  "principal resolution to the flagship S1 harness",
        "guarantee_boundary": (
            "HOMEPROV commits to rows that exist. A forgery performed at write "
            "time produces no earlier version of the row, so no commitment over "
            "committed state can detect it. The write-time arms are expected to "
            "show zero detection; arm P is the control proving the detector was "
            "live in the same run."),
        "rooms": rooms, "per_room": per_room,
        "window": {"t_start": t_start, "t_end": t_end,
                   "duration_s": round(t_end - t_start, 1),
                   "recorder_snapshot_at": t_snapshot,
                   "chain_upper_bound": "the recorder snapshot time; roots "
                                        "anchored after it are excluded because "
                                        "the snapshot cannot account for them"},
        "detection_method": {
            "how": "every anchored segment root in the run window recomputed from "
                   "a transactionally consistent snapshot of the final recorder, "
                   "using the SHIPPED monitor's own load()/commit()",
            "first_write_wins": "the FIRST anchored root for a segment is the one "
                                "verified against, matching the daemon's 409 rule",
            "granularities": list(widths.keys()),
            "anchored_segments_in_window": {
                g: sum(1 for (gg, _s) in roots if gg == g) for g in widths},
            "violating_segments_in_window": {
                g: sum(1 for (gg, s), v in verdicts.items() if gg == g and v["violation"])
                for g in widths},
            **recompute_info,
            **chain_info,
            "recorder_copy_valid": vok, "recorder_copy_reason": vreason,
            "recorder_copy_detail": vdetail},
        "benign_violation_floor": benign,
        "detection_metric": {
            "sound_unit": "second",
            "why": "the per-trial unit must be the segment the trial's own row "
                   "occupies. A minute segment aggregates sixty seconds, so ONE "
                   "violation anywhere inside it marks every trial in that minute "
                   "as detected, whoever caused it. That is not a hypothetical: in "
                   "this run the minute figures for W3 are entirely contamination. "
                   "Hallway minute 29815314 violates because of a single untouched "
                   "second (1788918899) in which five rows landed after the seal, "
                   "and hallway 29815315 and kitchen 29815327 violate because arm "
                   "P's deletions fall in the same minute as the last W3 trials. "
                   "Every one of the ten W3 minute-granularity 'detections' is "
                   "one of those two, and none is a violation of a W3 row. The "
                   "minute figures are reported because they were computed, not "
                   "because they measure detection of the arm they sit under.",
            "read_this_one": "homeprov_detection_second",
            "minute_figures_are": "unsound as a per-trial detection metric; kept "
                                  "for completeness and explained above"},
        "violation_mechanisms": mechanisms,
        "recorder_health": recorder_health,
        "arms": arms,
        "trials": trials,
        "versions": {
            "ha_image": sh("docker inspect %s --format '{{.Config.Image}}'" % HUB),
            "ha_image_digest": sh("docker inspect %s --format '{{index .Image}}'" % HUB),
            "monitor_image_digest": sh(
                "docker inspect %s --format '{{index .Image}}'" % MONITOR),
            "anchor_image_digest": sh(
                "docker inspect %s --format '{{index .Image}}'" % ANCHORD),
            "monitor_period_s": sh(
                "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                % MONITOR).split("HOMEPROV_PERIOD=")[-1].split("\n")[0]
            if "HOMEPROV_PERIOD" in sh(
                "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                % MONITOR) else None,
            "anchor_authenticated": bool(sh(
                "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                % ANCHORD).count("HOMEPROV_ANCHOR_KEY=") and not sh(
                "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                % ANCHORD).count("HOMEPROV_ANCHOR_KEY=\n")),
            "host_arch": sh("uname -m"),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }
    result["capability"] = capability.record(
        actor_id="write_time_forger", actor_position="in_process_integration",
        seed=None, budget_writes=0, window_s=None,
        knowledge={"deployment_topology": "full", "automation_configs": "full",
                   "household_member_user_ids": "known (readable from the auth "
                                                "store the hub already holds)",
                   "anchor_schedule_known": False, "anchor_key_known": False},
        constraints={"host_root": False, "cross_uid_write": False,
                     "anchor_key_access": False,
                     "external_anchor_retraction": False, "clock_control": False,
                     "post_commit_row_edits_used": "NONE in arms W1/W2/W2b/W3; "
                                                   "arm P is the post-commit control",
                     "rebind_in_process_symbols": True},
        substrate={"kind": "real Home Assistant deployment in Docker (Container "
                           "install method)",
                   "broker": "eclipse-mosquitto:2 with real MQTT discovery",
                   "monitor": "shipped external monitor, own container, config "
                              "mounted read-only, live throughout the run",
                   "anchor": "shipped append-only anchor daemon, own container "
                             "and own volume, live throughout the run"},
        mission="E-C write-time forgery (review 4b)")
    result["capability"]["capability_record"]["powers"].update({
        "rebind_in_process_symbols": True,
        "mint_service_call_context": True,
        "emit_bus_events": True,
        "db_write": "used only by arm P (the post-commit control)"})

    path = os.path.join(OUT, ("e_c_write_time.json" if tag == "e_c"
                              else "%s_other_principal_real.json" % tag))
    dig = capability.stamp(result, path)

    print("\n== E-C write-time forgery ==")
    print("  window %.0fs, %d anchored second-segments, %d minute-segments"
          % (result["window"]["duration_s"],
             result["detection_method"]["anchored_segments_in_window"].get("second", 0),
             result["detection_method"]["anchored_segments_in_window"].get("minute", 0)))
    print("  recorder copy valid: %s (%s)" % (vok, vreason))
    print("  recorder errors in window: %d SQLAlchemy, %d recorder ERROR lines"
          % (n_sqla, n_rec_err))
    for arm in present:
        a = arms[arm]
        m = a.get("renderer_confirmed_misattribution")
        print("  %-4s n=%-3d %s" % (arm, a["n_valid"], ARM_LABEL[arm]))
        if m:
            print("        misattribution %d/%d = %.3f  CI [%.3f, %.3f]"
                  % (m["k"], m["n"], m["prop"], m["ci_lo"], m["ci_hi"]))
        for g in ("second", "minute"):
            dd = a.get("homeprov_detection_%s" % g, {})
            if dd.get("n"):
                print("        HOMEPROV detection (%-6s) %d/%d = %.3f  CI [%.3f, %.3f]"
                      % (g, dd["k"], dd["n"], dd["prop"], dd["ci_lo"], dd["ci_hi"]))
            else:
                print("        HOMEPROV detection (%s): no trial's segment was "
                      "anchored" % g)
    for g in ("second", "minute"):
        b = benign[g]
        if b.get("n"):
            print("  benign floor (%s): %d/%d = %.3f  CI [%.3f, %.3f]"
                  % (g, b["k"], b["n"], b["prop"], b["ci_lo"], b["ci_hi"]))
    print("  -> %s" % path)
    print("  digest", dig)
    return result


if __name__ == "__main__":
    _args = sys.argv[1:]
    _tag = "e_c"
    if "--tag" in _args:
        _i = _args.index("--tag")
        _tag = _args[_i + 1]
        _args = _args[:_i] + _args[_i + 2:]
    main(_args or ["porch", "hallway", "kitchen"], tag=_tag)
