"""E-DZ summary: every number the paper might print about the Domoticz experiment, each with the file and JSON locator
it is read from and that file's sha256. Reads only result files; computes nothing new except interval rounding labels.

    python3 exp/stages/dz_summary.py [--tag dz] [--outdir exp/out]     -> <outdir>/<tag>_summary.json (never overwrites)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def get(d, path):
    for k in path.split("."):
        d = d[int(k)] if isinstance(d, list) else d[k]
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="dz")
    ap.add_argument("--outdir", default=os.path.join(REPO, "exp", "out"))
    a = ap.parse_args()
    path = os.path.join(a.outdir, "%s_summary.json" % a.tag)
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    files = {k: os.path.join(a.outdir, "%s_%s.json" % (a.tag, k)) for k in
             ("closure", "laundering_detection", "memberswap_detection", "config", "offline_checks")}
    files["closure"] = os.path.join(REPO, "exp", "out", "dz_closure.json")
    data = {k: json.load(open(p)) for k, p in files.items()}
    nums = []

    def add(name, fkey, loc, fmt=None, label=None):
        v = get(data[fkey], loc)
        nums.append({"name": name, "value": v if fmt is None else fmt(v),
                     "file": os.path.relpath(files[fkey], REPO), "locator": label or loc, "sha256": sha(files[fkey])})

    def cp(name, fkey, loc):
        d = get(data[fkey], loc)
        nums.append({"name": name, "value": "%d of %d [%.3f, %.3f]" % (d["k"], d["n"], d["ci_lo"], d["ci_hi"]),
                     "k": d["k"], "n": d["n"], "ci95_clopper_pearson": [round(d["ci_lo"], 3), round(d["ci_hi"], 3)],
                     "file": os.path.relpath(files[fkey], REPO), "locator": loc, "sha256": sha(files[fkey])})

    # platform
    add("Domoticz version", "config", "domoticz.version")
    add("Domoticz build hash", "config", "domoticz.build_hash")
    add("Domoticz build time", "config", "domoticz.build_time")
    add("Domoticz image id", "config", "domoticz.image_id")
    add("Domoticz image repo digest", "config", "domoticz.repo_digests")
    add("Python version of the integration framework", "config", "domoticz.python_version")
    # closure
    add("closure fixtures (one device per rendering path)", "closure", "summary.n_fixtures")
    add("closure mutations performed", "closure", "summary.n_mutations")
    add("stored fields mutated", "closure", "summary.fields_mutated")
    add("fields whose mutation changed the rendered output", "closure", "summary.n_fields_changing_rendered_output")
    add("fields whose mutation changed the rendered output (list)", "closure", "summary.fields_changing_rendered_output")
    add("fields whose mutation changed the displayed User", "closure", "summary.n_fields_changing_displayed_user")
    add("fields whose mutation changed the displayed User (list)", "closure", "summary.fields_changing_displayed_user")
    add("fields the renderer's code reads", "closure", "summary.n_code_read_fields")
    add("code-read fields not flagged by mutation", "closure", "summary.code_read_not_measured")
    add("renderer closure size", "closure", "summary.n_renderer_closure")
    add("positive control (User mutation) changed the displayed User on every fixture", "closure",
        "summary.positive_control_all_fixtures")
    add("determinism control on every fixture", "closure", "summary.determinism_control_all_fixtures")
    add("same render for Admin, User and Viewer on every fixture", "closure",
        "summary.same_render_for_every_role_all_fixtures")
    add("every restore equal to baseline", "closure", "summary.every_restore_equal_to_baseline")
    add("SwitchType mutation: fixtures whose rendered output changed", "closure", "summary.per_field",
        lambda d: len(d["DeviceStatus.SwitchType"]["fixtures_rendered_output_changed"]),
        "summary.per_field['DeviceStatus.SwitchType'].fixtures_rendered_output_changed (count)")
    add("UI (browser) checks on the door-lock fixture", "closure", "ui_controls.checks")
    add("DeviceStatus columns rewritten in place by benign traffic", "closure",
        "in_place_rewrite_probe.diff.DeviceStatus.columns_rewritten_in_place")
    add("LightingLog columns rewritten in place by benign traffic", "closure",
        "in_place_rewrite_probe.diff.LightingLog.columns_rewritten_in_place")
    # arms
    for arm, fk in (("laundering", "laundering_detection"), ("member-account swap", "memberswap_detection")):
        R = "result"
        add("%s: valid trials" % arm, fk, R + ".n_valid")
        cp("%s: misattribution for all three viewer roles" % arm, fk, R + ".renderer_confirmed_misattribution_all_roles")
        for role in ("owner", "member", "guest"):
            cp("%s: misattribution, %s viewer" % (arm, role), fk, R + ".misattribution_per_role.%s" % role)
        cp("%s: clean render named the true author" % arm, fk, R + ".clean_user_was_true_author")
        add("%s: displayed User before the edit" % arm, fk, R + ".clean_users")
        add("%s: displayed User after the edit" % arm, fk, R + ".users_after_edit")
        add("%s: browser renderings agreeing with the API" % arm, fk, R + ".ui_rendering.agree_with_api")
        add("%s: browser renderings" % arm, fk, R + ".ui_rendering.renderings")
        add("%s: minimum edit delay after the row was written (s)" % arm, fk, R + ".edit_delay_s.min")
        add("%s: trials edited at least 130 s after the row" % arm, fk, R + ".edit_delay_s.n_at_least_130")
        add("%s: trials whose segment was anchored before the edit" % arm, fk, R + ".segment_sealed_before_edit.k")
        add("%s: database writes per trial" % arm, fk, R + ".db_writes_per_trial")
        for sch, lab in (("closure", "closure scheme (live, authenticated anchor)"),
                         ("logrows", "log-rows-only scheme (offline, same snapshots)"),
                         ("wholerow", "whole-row scheme (offline, same snapshots)"),
                         ("row", "row-scheme analogue without User (offline, same snapshots)")):
            cp("%s: detected at one-second granularity, %s" % (arm, lab), fk, R + ".detection.%s.second" % sch)
            add("%s: raw one-second violations, %s" % (arm, lab), fk, R + ".detection.%s.second.raw_violation_hits" % sch)
            add("%s: late-row (ambiguous) hits, %s" % (arm, lab), fk,
                R + ".detection.%s.second.hits_explained_by_late_rows" % sch)
    # run level (identical in both arm files)
    fk = "laundering_detection"
    add("run window (s)", fk, "run.window.duration_s")
    add("anchored one-second segments in the window", fk, "run.anchored_segments_in_window.second")
    add("untouched anchored one-second segments", fk, "run.untouched_anchored_segments.second")
    for sch, lab in (("closure", "closure scheme"), ("logrows", "log-rows-only scheme"), ("wholerow", "whole-row scheme"),
                     ("row", "row-scheme analogue")):
        cp("benign floor, %s (one-second)" % lab, fk, "run.benign_floor.%s.second" % sch)
        add("benign floor late-row failures, %s" % lab, fk, "run.benign_floor.%s.second.late_row_failures" % sch)
    add("whole-row failing untouched segments", fk, "run.wholerow_floor_mechanism.failing_untouched_second_segments")
    add("of which reproduced by restoring DeviceStatus nValue/sValue/LastUpdate/LastLevel", fk,
        "run.wholerow_floor_mechanism.reproduced_by_restoring_in_place_devicestatus_columns")
    add("offline reconstruction: chain records matched", fk, "run.offline_reconstruction.chain_records")
    add("offline reconstruction: closure verdicts equal the live verifier's", fk,
        "run.offline_reconstruction.closure_verdicts_equal_live")
    add("anchor chain records", fk, "run.anchor_chain.records")
    add("anchor chain schemes", fk, "run.anchor_chain.schemes")
    # anchor and probes
    add("HMAC key fingerprint (sha256, 16 hex)", "config", "anchor.key_fingerprint_sha256_16")
    add("probe from the Domoticz process: untagged append", "config", "probes.from_hub_process.untagged")
    add("probe from the Domoticz process: forged-tag append", "config", "probes.from_hub_process.forged_tag")
    add("probe from a shell in the hub container: untagged append", "config", "probes.from_hub_container_shell.untagged")
    add("probe from a shell in the hub container: forged-tag append", "config",
        "probes.from_hub_container_shell.forged_tag")
    add("refusals logged by the anchor", "config", "probes.refusals_logged_by_anchor", len)
    add("monitor.py sha256 (run copy and repository)", "config", "monitor.monitor_py_sha256")
    add("wrapper script sha256", "config", "wrapper_script_sha256")
    # offline checks
    for i, w in enumerate(data["offline_checks"]["single_write"]):
        add("single write of %s: one-second segments changed per scheme" % w["write"], "offline_checks",
            "single_write.%d.segments_changed" % i)
    add("lock rows in the run window", "offline_checks", "lock_rows_in_window")
    add("VACUUM alone: rows whose ROWID binding changed", "offline_checks", "vacuum.a.rows_whose_rowid_binding_changed")
    add("VACUUM alone: closure one-second segments changed", "offline_checks",
        "vacuum.a.closure_second_segments_changed_in_window")
    add("retention DELETE + VACUUM: rows whose ROWID binding changed", "offline_checks",
        "vacuum.b.rows_whose_rowid_binding_changed")
    add("retention DELETE + VACUUM: closure one-second segments changed", "offline_checks",
        "vacuum.b.closure_second_segments_changed_in_window")
    add("retention DELETE alone: closure one-second segments changed", "offline_checks",
        "vacuum.c.closure_second_segments_changed_in_window")
    add("retention DELETE + VACUUM vs DELETE alone: closure one-second segments differing", "offline_checks",
        "vacuum.b.closure_second_segments_differing_from_delete_only")
    add("SQLite version used for the VACUUM check (the Domoticz image's)", "offline_checks", "vacuum.sqlite_version")
    add("seal delay: median (s)", "offline_checks", "seal_delay.median_s")
    add("seal delay: max (s)", "offline_checks", "seal_delay.max_s")
    out = {"experiment": "E-DZ summary", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "sources": {k: {"file": os.path.relpath(p, REPO), "sha256": sha(p)} for k, p in files.items()},
           "numbers": nums, "script_sha256": sha(os.path.abspath(__file__))}
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1, default=str)
    for n in nums:
        print("%-95s %s" % (n["name"][:95], json.dumps(n["value"], default=str)[:120]))
    print("->", path, sha(path))


if __name__ == "__main__":
    main()
