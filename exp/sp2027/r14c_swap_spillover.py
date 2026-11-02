#!/usr/bin/env python3
"""R14c (S&P 2027 round 14c, 2026-10-12): the source and mechanism of Section 4's "in 11 of them also into the previous
trial's row", and the same harness race in every saved run.

Answers internal review r4, R3 minor: "'in 11 of them also into the previous trial's row' (Sec. 4) looks like harness
spillover across trials; please explain."

SOURCE. The sentence's evidence use (authoring/writer/03-evidence/P-003@v1.yaml) cites exp/out/e_psr_clo_detection.json,
trials[*].db_writes and swapped_state_ids: the member-account swap run of 2026-10-03 (arm PSR, 90 trials, closure monitor).

MECHANISM (homeprov_ec, read as text; its sha256 equals the component hash e_psr_clo_config.json records):
  phase 1  _unlock_and_capture (lines 309-340) calls lock.unlock, waits until the STATE MACHINE shows the new state
           (lines 322-326), then reads the newest 'unlocked' row of the lock FROM THE RECORDER (lines 329-333, ORDER BY
           last_updated_ts DESC LIMIT 1). The recorder writes on its own thread and commits once per second, so the
           state machine can change before the new row is on disk; the read then returns the PREVIOUS trial's unlocked
           row. That row is stored as row_before. The judged row (the row the logbook shows at the rendered `when`,
           _row_at_ts, lines 157-186) is looked up after the render and is the trial's own row.
  phase 2  _arm_PS (lines 885-899) writes the member account's id into every row of
           sids = {row_before.state_id, judged_row.state_id} | {state rows carrying row_before's context}.
           When row_before is the previous trial's row, the trial writes two rows: its own (judged) row and the previous
           trial's. The value is the same member id in every trial (line 888, user_id_hex), and the previous trial's own
           phase-2 UPDATE ran earlier in the same loop, so the second write rewrites the value already there.
The same capture is shared by every arm that calls _unlock_and_capture (homeprov_ec P, PU, PI, PS, PSR; homeprov_e7 INS-L,
INS-M, STALL, OUTAGE via _anchor_own_actuation). What the race does then depends on the arm, and this file counts it in
every saved run (E9 files are not read).

    python3 exp/sp2027/r14c_swap_spillover.py   -> exp/out/r14c_swap_spillover.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import collections
import datetime
import glob
import hashlib
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
MS = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13")
EC = "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py"
E7 = "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py"
DST = os.path.join(os.environ.get("R14C_DRYRUN_DIR") or OUT, "r14c_swap_spillover.json")
INPUTS = {}

CODE_LINES = {   # (file, line, fragment that must be on that line)
    "capture_waits_on_state_machine": (EC, 325, '[withheld from the artifact: a source line of an attack integration]'),
    "capture_reads_newest_unlocked_row": (EC, 333, '[withheld from the artifact: a source line of an attack integration]'),
    "judged_row_by_rendered_when": (EC, 177, '[withheld from the artifact: a source line of an attack integration]'),
    "psr_value_constant": (EC, 888, '[withheld from the artifact: a source line of an attack integration]'),
    "psr_row_set": (EC, 890, '[withheld from the artifact: a source line of an attack integration]'),
    "psr_row_set_context": (EC, 893, '[withheld from the artifact: a source line of an attack integration]'),
    "psr_update": (EC, 898, '[withheld from the artifact: a source line of an attack integration]'),
    "pupi_row_set": (EC, 771, '[withheld from the artifact: a source line of an attack integration]'),
    "p_row_is_captured_row_only": (EC, 620, '[withheld from the artifact: a source line of an attack integration]'),
    "p_cover_most_recent_run": (EC, 622, '[withheld from the artifact: a source line of an attack integration]'),
    "e7_stall_captured_row_context_events_deleted": (E7, 855, '[withheld from the artifact: a source line of an attack integration]'),
    "recorder_commit_interval_1s_used_by_harness": (EC, 502, '[withheld from the artifact: a source line of an attack integration]'),
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(p):
    INPUTS[os.path.relpath(p, REPO)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def sid(x):
    return (x or {}).get("state_id")


def edited_ids(t):
    return t.get("swapped_state_ids") or t.get("laundered_state_ids")


def classify_file(trials):
    """Per valid trial with a captured row: raced = row_before is the row of the previous valid trial IN FILE ORDER (any
    arm: the arms of a configuration run one after another, so the first trial of an arm can capture the last trial of
    the arm before; the previous trial's row_before, judged row or forged row). Returns per-arm counts and the raced
    trials' details."""
    valid = [t for t in trials if isinstance(t, dict) and not (t.get("err") or t.get("error"))
             and (t.get("row_before") or t.get("judged_row") or t.get("forged_row"))]
    by = collections.defaultdict(list)
    prev_of = {}
    for i, t in enumerate(valid):
        if t.get("row_before"):
            by[t.get("arm")].append(t)
            prev_of[id(t)] = valid[i - 1] if i > 0 else None
    res = {}
    for arm, ts in by.items():
        raced = []
        for t in ts:
            p = prev_of[id(t)]
            if p is None:
                continue
            rb = sid(t.get("row_before"))
            if rb not in {sid(p.get("row_before")), sid(p.get("judged_row")), sid(p.get("forged_row"))} - {None}:
                continue
            ids = edited_ids(t) or []
            jr = sid(t.get("judged_row"))
            ops = t.get("operations_used") or {}
            d = {"trial": t.get("trial"), "row_before": rb, "judged_row": jr,
                 "previous_trial": p.get("trial"), "previous_trial_arm": p.get("arm"),
                 "previous_row_before": sid(p.get("row_before")),
                 "previous_judged_row": sid(p.get("judged_row")), "edited_ids": ids,
                 "db_writes": t.get("db_writes"), "operations_used": ops,
                 "own_row_edited": (jr in ids) if jr else None}
            if arm in ("PS", "PSR"):
                d["same_value_as_previous_trial"] = t.get("swap_user_id_hex") == p.get("swap_user_id_hex")
            if arm == "P":
                # P edits only the captured row: a raced P trial re-edits the previous trial's row and never its own;
                # with the previous trial's cover the UPDATE writes the values already there
                d["same_cover_as_previous_trial"] = (t.get("cover_context") is not None
                                                     and t.get("cover_context") == p.get("cover_context"))
                d["no_change_to_the_recorder"] = d["same_cover_as_previous_trial"] and ops.get("delete") == 0
            if arm in ("STALL", "OUTAGE"):
                # STALL/OUTAGE edit within the trial, after the previous trial's row was laundered: the captured row's
                # context is the previous trial's COVER, so the context query also reaches the genuine run's rows
                d["captured_context_is_previous_cover"] = ((t.get("row_before") or {}).get("context_id_bin") or "") \
                    .startswith(p.get("cover_context") or "-")
                d["events_deleted"] = ops.get("delete")
            raced.append(d)
        res[arm] = {"trials": len(ts), "raced": len(raced),
                    "multi_row_edits": sum(1 for t in ts if len(edited_ids(t) or []) > 1),
                    "raced_trials": raced}
    return res


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    src = {}
    for f in (EC, E7):
        p = os.path.join(REPO, f)
        INPUTS[f] = sha256_file(p)
        src[f] = open(p).read().split("\n")
    code = {}
    for name, (f, ln, frag) in CODE_LINES.items():
        assert frag in src[f][ln - 1], (name, ln, src[f][ln - 1])
        code[name] = {"file": f, "line": ln, "text": src[f][ln - 1].strip()}
    cfg = read_json(os.path.join(OUT, "e_psr_clo_config.json"))
    assert cfg["code"]["component_sha256"] == INPUTS[EC], "homeprov_ec differs from the one e_psr_clo ran"

    # ------------------------------------------------------------------ the printed 11 of 90
    det = read_json(os.path.join(OUT, "e_psr_clo_detection.json"))
    T = det["trials"]
    assert len(T) == 90 and all(t["arm"] == "PSR" for t in T)
    dist = collections.Counter((t["db_writes"], len(t["swapped_state_ids"])) for t in T)
    rows = []
    prev_by_room = {}
    for t in T:
        p = prev_by_room.get(t["room"])
        rb, jr = sid(t["row_before"]), sid(t["judged_row"])
        two = len(t["swapped_state_ids"]) == 2
        if two:
            other = [x for x in t["swapped_state_ids"] if x != jr]
            rows.append({
                "room": t["room"], "trial": t["trial"],
                "swapped_state_ids": t["swapped_state_ids"], "db_writes": t["db_writes"],
                "judged_row_own": jr, "row_before_captured": rb,
                "row_before_is_previous_trials_judged_row": p is not None and rb == sid(p["judged_row"]),
                "extra_row": other, "extra_row_is_previous_trials_row": p is not None and other == [sid(p["judged_row"])],
                "own_row_ts": t["judged_row"]["ts"], "captured_row_ts": t["row_before"]["ts"],
                "captured_row_older_by_s": round(t["judged_row"]["ts"] - t["row_before"]["ts"], 3),
                "same_member_id_as_previous_trial": p is not None and p["swap_user_id_hex"] == t["swap_user_id_hex"],
                "previous_trial_valid_and_written_first": p is not None and not p.get("err")
                and (p.get("operations_used") or {}).get("user_swap", 0) >= 1})
        else:
            assert rb == jr and t["swapped_state_ids"] == [jr], (t["room"], t["trial"])
        prev_by_room[t["room"]] = t
    assert len(rows) == 11 and all(r["row_before_is_previous_trials_judged_row"] and r["extra_row_is_previous_trials_row"]
                                   and r["same_member_id_as_previous_trial"]
                                   and r["previous_trial_valid_and_written_first"] for r in rows), rows
    per_room = collections.Counter(r["room"] for r in rows)
    disp = read_json(os.path.join(OUT, "e_psr_clo_display_check.json"))

    # ------------------------------------------------------------------ census over every saved run
    census = {}
    for f in sorted(glob.glob(os.path.join(OUT, "*report*.json"))):
        b = os.path.basename(f)
        if b.startswith("e9") or b.startswith("r14c"):
            continue
        try:
            d = read_json(f)
        except (ValueError, OSError):
            continue
        tr = d.get("trials") if isinstance(d, dict) else None
        if not isinstance(tr, list):
            continue
        res = classify_file(tr)
        if any(v["trials"] for v in res.values()):
            census[b] = res
    tot = collections.defaultdict(lambda: [0, 0])
    for b, res in census.items():
        for arm, v in res.items():
            tot[arm][0] += v["raced"]
            tot[arm][1] += v["trials"]
    p_noop = [{"file": b, **x} for b, res in census.items() for x in res.get("P", {}).get("raced_trials", [])]
    # how the scored P trials were counted: the detection unit is the one-second segment of the captured row, so a
    # raced P trial is scored on the previous trial's segment
    p_scoring = {}
    for f, scheme in (("e_c_write_time.json", "row scheme, unauthenticated anchor (2026-09-09)"),
                      ("e_c_auth_other_principal_real.json", "row scheme, authenticated anchor"),
                      ("e_c_clo_other_principal_real.json", "closure scheme, authenticated anchor")):
        d = read_json(os.path.join(OUT, f))
        P = [t for t in d["trials"] if t.get("arm") == "P" and not (t.get("err") or t.get("error"))]
        segs = collections.Counter((t["room"], t["_detection"]["second"]["segment"]) for t in P)
        p_scoring[f] = {"run": scheme, "trials": len(P),
                        "detected_second": sum(bool(t["_detection"]["second"]["violation"]) for t in P),
                        "distinct_scored_segments": len(segs),
                        "segments_scored_twice": [{"room": r, "segment": s, "trials": c} for (r, s), c in segs.items()
                                                  if c > 1]}
    for mon in ("stable", "closure"):
        f = "e8_main_%s_verify_main.json" % mon
        v = read_json(os.path.join(OUT, f))
        P = [x for x in v["trials"] if x.get("arm") == "P"]
        segs = collections.Counter(x["segment"] for x in P)
        p_scoring[f] = {"run": "E8 main window, %s monitor" % mon, "trials": len(P),
                        "detected_second": sum(bool(x["detected"]) for x in P),
                        "distinct_scored_segments": len(segs),
                        "segments_scored_twice": [{"segment": s, "trials": c} for s, c in segs.items() if c > 1]}
    stall = [{"file": b, "arm": a, **x} for b, res in census.items() for a in ("STALL", "OUTAGE")
             for x in res.get(a, {}).get("raced_trials", [])]

    tex = os.path.join(MS, "sections", "04_sp_atk.tex")
    INPUTS[os.path.relpath(tex, REPO)] = sha256_file(tex)
    printed = [s.strip().rstrip(".") + "." for line in open(tex) for s in line.split(". ") if "previous trial" in s]
    tex7 = os.path.join(MS, "sections", "07_sp_eval.tex")
    INPUTS[os.path.relpath(tex7, REPO)] = sha256_file(tex7)
    printed_control = [s.strip().rstrip(".") + "." for line in open(tex7) for s in line.split(". ") if "post-commit control" in s]
    src_self = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14c: Section 4's 11-of-90 'previous trial's row' writes traced to their file and to a capture race in "
                "the attack harness, and the same race counted in every saved run",
        "answers": ["R3 minor (r4): 'in 11 of them also into the previous trial's row' ... please explain"],
        "printed": {"file": "sections/04_sp_atk.tex", "text": printed},
        "source": {"file": "exp/out/e_psr_clo_detection.json", "fields": "trials[*].db_writes, swapped_state_ids",
                   "evidence_use": "authoring/writer/03-evidence/P-003@v1.yaml (79 / 11: trials issuing one UPDATE / "
                                   "two UPDATEs)",
                   "distribution_db_writes_and_ids": {"%d writes, %d ids" % k: v for k, v in sorted(dist.items())},
                   "per_room": dict(per_room), "trials": rows},
        "mechanism": {
            "code": code,
            "statement": "the trial's captured row (row_before) was the previous trial's unlocked row in 11 of 90 trials: "
                         "_unlock_and_capture waits for the state machine, then reads the newest unlocked row from the "
                         "recorder, which commits once per second; phase 2 writes the member id into row_before, the "
                         "judged row and every row of row_before's context, so these trials wrote their own (judged) "
                         "row and the previous trial's row, each once",
            "consequence_for_PSR": "the second write puts the same member id into a row that already holds it (the "
                                   "previous trial's phase-2 write ran first in the same loop): no content change, and "
                                   "the row is the previous trial's own touched row; detection and the floor are "
                                   "unaffected (both rows are touched under the counting rule)",
            "not_cross_trial_harness_state": "no state crosses trials except the recorder itself: the captured row is "
                                             "simply the newest unlocked row at capture time",
            "display_check_uses_the_judged_row": "the 90/90 admin display result (exp/out/e_psr_clo_display_check.json) "
                                                 "is computed from each trial's rendered rows at its own `when`, so it "
                                                 "is about the trial's own row",
            "display_check_n": disp.get("n")},
        "census_all_runs": {"per_file": census,
                            "total_by_arm": {a: {"raced": v[0], "trials": v[1]} for a, v in sorted(tot.items())},
                            "rule": "raced = the captured row (row_before) is the previous valid trial's row_before or "
                                    "judged row, same report file and arm"},
        "consequences_in_other_arms": {
            "PS, PSR, INS-M (swap)": "own row and the previous row both written with the swap value; PSR/INS-M write the "
                                     "same member id (a same-value rewrite); PS writes fresh random bytes, so the "
                                     "previous row's value changes",
            "PU, PI, INS-L (laundering, two phases)": "the context query matches no row and the event query no event "
                                                      "(the previous trial already re-pointed its row and deleted its "
                                                      "events), so the raced trial deletes 0 events, leaves its own "
                                                      "author's call_service event in place, and re-points its own row "
                                                      "and the previous row to its cover",
            "P (control, edits the captured row only)": p_noop,
            "P reading": "a raced P trial edits only the captured row, i.e. the previous trial's row, never its own; "
                         "_find_genuine_automation_run() without a bound picks the most recent run, the same cover as "
                         "the previous trial, so the UPDATE writes the values already there and the DELETE finds "
                         "nothing: the trial changed nothing in the recorder, and its detection is the previous "
                         "trial's segment scored again",
            "P scoring (detection files)": p_scoring,
            "STALL, OUTAGE (E7, edit inside the trial)": stall,
            "STALL/OUTAGE reading": "the previous trial's row had already been laundered, so the captured context is "
                                    "the previous trial's COVER: the trial deleted that genuine automation run's events "
                                    "(%s events) and re-pointed every state row carrying that context (%d to %d rows) "
                                    "to a new cover" % (sorted({x["events_deleted"] for x in stall}),
                                                        min(len(x["edited_ids"]) for x in stall),
                                                        max(len(x["edited_ids"]) for x in stall)),
        },
        "printed_post_commit_control": {"file": "sections/07_sp_eval.tex", "text": printed_control},
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14c_swap_spillover.py",
        "script_sha256": hashlib.sha256(src_self).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, sha256_file(DST))
    print(dict(dist), dict(per_room))
    for a, v in sorted(tot.items()):
        print(a, v)
    for x in p_noop:
        print("P raced", x["file"], x["trial"], x["same_cover_as_previous_trial"], x["no_change_to_the_recorder"],
              x["operations_used"])
    for x in stall:
        print(x["arm"], x["file"], x["trial"], x["captured_context_is_previous_cover"], x["events_deleted"],
              len(x["edited_ids"]))


if __name__ == "__main__":
    main()
