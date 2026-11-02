#!/usr/bin/env python3
"""R14c (S&P 2027 round 14c, 2026-10-12): attack success per E8 arm, what each harness field means, and why the score
file shows 26/90 for BD-S and 0/90 "principal moved" for INS-M (and 0/90 for PSR and P).

Answers internal review r4, R3 minor: "E8's score file records a harness-confirmed misattribution in only 26/90 BD-S
trials and 0/90 'principal moved' for INS-M; report attack success per E8 arm."

WHAT IT READS (saved files only; the attack code is read as text, never imported or run):
  * the E8 harness reports exp/out/e8_main_report_{ec,e7}_{porch,hallway,kitchen}.json and
    exp/out/e8_main_stress_report_porch.json (per trial: clean_rendered / rendered = the platform's logbook rows before
    and after the edit, the harness's own success fields, the forged row of BD-S); the E7 reports for BD-S as a second
    run; exp/out/e8_main_score_rescored.json (its `harness` block, to tie the counts to the score file);
  * exp/out/e_psr_clo_config.json: the display rule of home-assistant-frontend 20260624.6 as transcribed for Table 2
    (display_check); the function below must equal that text (asserted), and the account map is the same;
  * the shipped recorder extracts reproduce/snapshots/e7e8/e{7,8}_main.db (read-only, immutable; sha256 checked): for
    BD-S, the forged row, the lock row before it (old_state_id) and any other unlocked lock row within 1 s; for P,
    the captured row's current context;
  * testbed/real/ha-config/custom_components/homeprov_ec/__init__.py, homeprov_e7/__init__.py, exp/stages/e8_score.py
    (text only, line numbers asserted) for the field definitions;
  * the logbook's state filter in the locally installed Home Assistant (site-packages, 2026.2.3; the lab ran 2026.7.4,
    whose source is not on this machine): homeassistant/components/logbook/queries/common.py _missing_state_matcher.

ATTACK SUCCESS used here (one criterion per arm family, from the stored rows the harness rendered):
  laundering (PU, PI, INS-L, stress PU)  displayed cause after the edit is the motion-light automation, for an admin and a
                                         non-admin viewer (display rule), and the harness field (names the automation
                                         and, for a member's unlock, no longer names the person);
  swap (PSR, INS-M)                      displayed cause for an admin viewer becomes the household member account
                                         (Table 2's criterion); a non-admin viewer's name map is empty on this hub;
  backdated insertion (BD-S)             the forged row appears in the logbook with an automation as its displayed cause;
  own-actuation control (P)              the harness renders nothing for P; the stored-row check (captured row now
                                         carries a genuine automation run's context) is reported instead.

    python3 exp/sp2027/r14c_e8_attack_success.py   -> exp/out/r14c_e8_attack_success.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import collections
import datetime
import hashlib
import json
import os
import sqlite3

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
EXTR = os.path.join(REPO, "reproduce", "snapshots", "e7e8")
EC = "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py"
E7 = "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py"
SC = "exp/stages/e8_score.py"
HA_LOGBOOK = "<home>/miniconda3/lib/python3.13/site-packages/homeassistant/components/logbook/queries/common.py"
DST = os.path.join(os.environ.get("R14C_DRYRUN_DIR") or OUT, "r14c_e8_attack_success.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import stats  # noqa: E402

INPUTS = {}

# The display rule exactly as exp/out/e_psr_clo_config.json display_check transcribes it (asserted below).
DISPLAY_SRC = '''def display(row, names):
    u = row.get("context_user_id")
    if u and names.get(u):
        return "user:" + names[u]
    if row.get("context_event_type") in ("automation_triggered", "script_started"):
        n = row.get("context_entity_id") or row.get("context_name")
        if n:
            return "automation:" + n
    if row.get("context_event_type") == "call_service" and row.get("context_domain"):
        return "integration:" + row["context_domain"]
    return "none"
'''
ACCOUNTS_SRC = ('ACCOUNTS = {"177db62efb414fbdb5af6e480c34a0b5": "Home Assistant Content",\n'
                '            "90b6f1f5983443c2b47f563e8f652752": "Alex Rivera (household)"}')
ACCOUNTS = {"177db62efb414fbdb5af6e480c34a0b5": "Home Assistant Content",
            "90b6f1f5983443c2b47f563e8f652752": "Alex Rivera (household)"}
_ns = {}
exec(DISPLAY_SRC, _ns)                                         # noqa: S102  (a constant of this file, asserted equal)
display = _ns["display"]

FIELD_DEFS = {   # (file, line, fragment): where each harness field is set
    "PU/PI renderer_confirmed_misattribution": (EC, 820, '[withheld from the artifact: a source line of an attack integration]'),
    "PU/PI renderer_confirmed_misattribution (criterion)": (EC, 821, '[withheld from the artifact: a source line of an attack integration]'),
    "PU/PI principal_moved": (EC, 822, '[withheld from the artifact: a source line of an attack integration]'),
    "PSR principal_moved": (EC, 924, '[withheld from the artifact: a source line of an attack integration]'),
    "PSR renderer_confirmed_misattribution = principal_moved": (EC, 929,
                                                               '[withheld from the artifact: a source line of an attack integration]'),
    "_principal ranks automation, then service call, then user": (EC, 134, '[withheld from the artifact: a source line of an attack integration]'),
    "_principal: service before user": (EC, 139, '[withheld from the artifact: a source line of an attack integration]'),
    "P records no render (phase 2 ends with the edit)": (EC, 643, '[withheld from the artifact: a source line of an attack integration]'),
    "INS principal_moved": (E7, 358, '[withheld from the artifact: a source line of an attack integration]'),
    "INS renderer_confirmed_misattribution": (E7, 363, '[withheld from the artifact: a source line of an attack integration]'),
    "INS-M criterion: the member account is named and was not before": (
        E7, 365, '[withheld from the artifact: a source line of an attack integration]'),
    "INS inserted rows: second + (i + 1) / (K + 1), cover context": (E7, 150, '[withheld from the artifact: a source line of an attack integration]'),
    "PU/PI: names_auto = any context_entity_id": (EC, 813, '[withheld from the artifact: a source line of an attack integration]'),
    "BD-S render match: an unlocked lock row whose ts is within 1 s of the forged ts": (
        E7, 530, '[withheld from the artifact: a source line of an attack integration]'),
    "BD-S renderer_confirmed_misattribution = names an automation": (
        E7, 537, '[withheld from the artifact: a source line of an attack integration]'),
    "BD-S forged row's old_state_id = the lock's previous row": (E7, 126, '[withheld from the artifact: a source line of an attack integration]'),
    "scorer counts a missing field as 0": (SC, 186, "a[f] += bool(t.get(f))"),
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(p):
    p = os.path.abspath(p)
    return os.path.relpath(p, REPO) if p.startswith(REPO + os.sep) else p


def read_json(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return {"k": k, "n": n, "interval": [r["ci_lo"], r["ci_hi"]]}


def ro(db):
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)


def iso_ts(s):
    return datetime.datetime.fromisoformat(str(s)).timestamp()


def first(rows):
    return rows[0] if rows else {}


def bd_classify(con, lock_mid, t):
    """BD-S: what the logbook could show for the forged row, from the extract."""
    sid = t.get("forged_state_id") or t.get("reserved_state_id") or (t.get("forged_row") or {}).get("state_id")
    ts = float(t.get("forged_row_ts") or (t.get("forged_row") or {}).get("ts"))
    r = con.execute("SELECT state, last_updated_ts, old_state_id, context_id_bin FROM states WHERE state_id=?",
                    (sid,)).fetchone()
    old = con.execute("SELECT state FROM states WHERE state_id=?", (r[2],)).fetchone() if r and r[2] else None
    near = con.execute("SELECT count(*) FROM states WHERE metadata_id=? AND state='unlocked' AND "
                       "abs(last_updated_ts - ?) < 1.0 AND state_id != ?", (lock_mid, ts, sid)).fetchone()[0]
    rend = t.get("rendered") or []
    w = first(rend).get("when")
    matched_forged = w is not None and abs(iso_ts(w) - ts) < 0.002
    if matched_forged:
        cls = "forged row rendered"
    elif w is None:
        cls = "no logbook entry matched"
    else:
        cls = "harness matched another unlocked row within 1 s"
    return {"forged_row_present": r is not None, "forged_state": r[0] if r else None,
            "forged_context_is_cover": bool(r and r[3] and r[3].hex().startswith(t.get("cover_context") or "-")),
            "previous_lock_state": old[0] if old else None, "other_unlocked_rows_within_1s": near,
            "class": cls, "displayed_after_admin": display(first(rend), ACCOUNTS) if matched_forged else None}


def no_cause_diagnosis(con, trials):
    """For laundering trials the display rule shows with no cause: the re-attached context's earliest state row versus
    its automation_triggered event (the logbook resolves a context to its earliest row; a state row that precedes the
    run's trigger in the same context becomes the context's origin, which has no event type)."""
    out = []
    for t in trials:
        sid = (t.get("judged_row") or {}).get("state_id") or (t.get("row_before") or {}).get("state_id")
        r = con.execute("SELECT context_id_bin FROM states WHERE state_id=?", (sid,)).fetchone()
        ctx = r[0] if r else None
        trig = con.execute("SELECT min(e.time_fired_ts) FROM events e JOIN event_types y ON "
                           "y.event_type_id=e.event_type_id WHERE e.context_id_bin=? AND "
                           "y.event_type='automation_triggered'", (ctx,)).fetchone()[0] if ctx else None
        early = con.execute("SELECT s.state_id, m.entity_id, s.last_updated_ts FROM states s JOIN states_meta m ON "
                            "m.metadata_id=s.metadata_id WHERE s.context_id_bin=? ORDER BY s.last_updated_ts LIMIT 1",
                            (ctx,)).fetchone() if ctx else None
        rend = first(t.get("rendered") or [])
        out.append({"room": t.get("room"), "trial": t.get("trial"), "context": ctx.hex()[:16] if ctx else None,
                    "logbook_context_entity_id": rend.get("context_entity_id"),
                    "logbook_context_event_type": rend.get("context_event_type"),
                    "earliest_state_row_in_context": {"state_id": early[0], "entity_id": early[1], "ts": early[2]}
                    if early else None,
                    "automation_triggered_ts": trig,
                    "earliest_state_row_precedes_trigger_by_s": (round(trig - early[2], 4)
                                                                if early and trig is not None else None),
                    "earliest_row_is_the_logbook_context_entity": bool(early and early[1] == rend.get(
                        "context_entity_id")),
                    "laundered_state_ids": t.get("laundered_state_ids"),
                    "inserted_state_ids_count": len(t.get("inserted_state_ids") or [])})
    return {"trials": len(out),
            "all_explained_by_an_earlier_state_row_in_the_context": all(
                x["earliest_row_is_the_logbook_context_entity"] and (x["earliest_state_row_precedes_trigger_by_s"] or 0) > 0
                for x in out),
            "detail": out}


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    # ---------------------------------------------------------------- code text: definitions and the display rule
    text = {}
    for f in (EC, E7, SC):
        INPUTS[f] = sha256_file(os.path.join(REPO, f))
        text[f] = open(os.path.join(REPO, f)).read().split("\n")
    defs = {}
    for name, (f, ln, frag) in FIELD_DEFS.items():
        assert frag in text[f][ln - 1], (name, ln, text[f][ln - 1])
        defs[name] = {"file": f, "line": ln, "text": text[f][ln - 1].strip()}
    cfg = read_json(os.path.join(OUT, "e_psr_clo_config.json"))
    assert DISPLAY_SRC in cfg["code"]["display_check"] and ACCOUNTS_SRC in cfg["code"]["display_check"]
    INPUTS[HA_LOGBOOK] = sha256_file(HA_LOGBOOK)
    lb = open(HA_LOGBOOK).read().split("\n")
    assert "def _missing_state_matcher" in lb[191] and "(States.state != OLD_STATE.state)," in lb[197], lb[191:199]
    logbook_rule = {"file": HA_LOGBOOK, "home_assistant_version": "2026.2.3 (installed locally; the lab ran 2026.7.4)",
                    "lines": "192-200", "text": [x.strip() for x in lb[191:200]],
                    "meaning": "the logbook lists a state row only when it has an old state and its state differs "
                               "from the old state's"}

    # ---------------------------------------------------------------- reports and extracts
    sums = {}
    p_sums = os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS")
    INPUTS[rel(p_sums)] = sha256_file(p_sums)
    for line in open(p_sums):
        h, p = line.split(None, 1)
        sums[p.strip().lstrip("./")] = h
    cons = {}
    for name in ("e8_main.db", "e7_main.db"):
        db = os.path.join(EXTR, name)
        h = sha256_file(db)
        assert h == sums[name]
        INPUTS[rel(db)] = h
        cons[name] = ro(db)
    score = read_json(os.path.join(OUT, "e8_main_score_rescored.json"))
    sets = {
        "E8 main": ("e8_main.db", ["e8_main_report_ec_porch.json", "e8_main_report_ec_hallway.json",
                                   "e8_main_report_ec_kitchen.json", "e8_main_report_e7_porch.json",
                                   "e8_main_report_e7_hallway.json", "e8_main_report_e7_kitchen.json"]),
        "E8 stress": ("e8_main.db", ["e8_main_stress_report_porch.json"]),
        "E7": ("e7_main.db", ["e7_main_report_porch.json", "e7_main_report_hallway.json", "e7_main_report_kitchen.json"]),
        "e_d_clo (Section 1's 180 of 180)": (None, ["e_d_clo_report_porch.json", "e_d_clo_report_hallway.json",
                                                    "e_d_clo_report_kitchen.json"]),
    }
    results = {}
    for setname, (dbname, files) in sets.items():
        con = cons.get(dbname)
        lock_mid = (con.execute("SELECT metadata_id FROM states_meta WHERE entity_id='lock.front_door'").fetchone()[0]
                    if con is not None else None)
        by = collections.defaultdict(list)
        member = None
        for f in files:
            d = read_json(os.path.join(OUT, f))
            member = member or d.get("household_member_user_id")
            for t in d["trials"]:
                if t.get("arm") == "RENDER":
                    continue
                by[t.get("arm")].append(dict(t, room=d.get("room"), innocent=d.get("innocent_party")))
        assert member in ACCOUNTS
        arms = {}
        for arm, ts in by.items():
            valid = [t for t in ts if not (t.get("err") or t.get("error"))]
            n = len(valid)
            a = {"n_records": len(ts), "n_valid": n,
                 "harness_fields": {f: {"true": sum(bool(t.get(f)) for t in valid),
                                        "field_present": sum(f in t for t in valid)}
                                    for f in ("renderer_confirmed_misattribution", "principal_moved")}}
            have_render = [t for t in valid if "rendered" in t]
            if have_render and arm not in ("BD-S", "BD-M", "BD-PARK", "BD-JOIN", "BD-GAP"):
                for viewer, names in (("admin", dict(ACCOUNTS)), ("non_admin", {})):
                    before = collections.Counter(display(first(t.get("clean_rendered") or []), names) for t in have_render)
                    after = collections.Counter(display(first(t.get("rendered") or []), names) for t in have_render)
                    changed = sum(1 for t in have_render if display(first(t.get("clean_rendered") or []), names)
                                  != display(first(t.get("rendered") or []), names))
                    to_auto = sum(1 for t in have_render
                                  if display(first(t.get("rendered") or []), names) == "automation:" + t["innocent"])
                    to_member = sum(1 for t in have_render
                                    if display(first(t.get("rendered") or []), names) == "user:" + ACCOUNTS[member])
                    a["display_rule_" + viewer] = {"before": dict(before), "after": dict(after),
                                                   "displayed_cause_changed": cp(changed, len(have_render)),
                                                   "after_is_the_rooms_motion_light_automation": cp(to_auto, len(have_render)),
                                                   "after_is_the_household_member_account": cp(to_member, len(have_render))}
                if con is not None and arm in ("PU", "PI", "INS-L"):
                    a["why_no_cause_after"] = no_cause_diagnosis(con, [t for t in have_render
                                                                      if display(first(t.get("rendered") or []), {})
                                                                      == "none"])
                a["logbook_principal_by_harness_ranking"] = {
                    "before": dict(collections.Counter(str(t.get("clean_principal")) for t in have_render)),
                    "after": dict(collections.Counter(str(t.get("principal_rendered")) for t in have_render))}
            if arm in ("BD-S", "BD-M", "BD-PARK", "BD-JOIN", "BD-GAP") and dbname:
                cls = [bd_classify(con, lock_mid, t) for t in valid]
                c = collections.Counter((x["class"], x["previous_lock_state"]) for x in cls)
                a["forged_row_classes"] = [{"class": k[0], "previous_lock_state": k[1], "trials": v}
                                           for k, v in sorted(c.items(), key=lambda kv: -kv[1])]
                a["forged_row_present_in_extract"] = sum(x["forged_row_present"] for x in cls)
                a["forged_row_context_is_recorded_cover"] = sum(x["forged_context_is_cover"] for x in cls)
                a["forged_row_rendered_with_automation_cause_admin"] = cp(
                    sum(1 for x in cls if (x["displayed_after_admin"] or "").startswith("automation:")), n)
                a["previous_lock_state"] = dict(collections.Counter(str(x["previous_lock_state"]) for x in cls))
                a["harness_field_equals_rendered_forged_row"] = all(
                    bool(t.get("renderer_confirmed_misattribution")) == (x["class"] == "forged row rendered"
                                                                          and (x["displayed_after_admin"] or "")
                                                                          .startswith("automation:"))
                    for t, x in zip(valid, cls))
            if arm == "P" and con is not None:
                rows = []
                for t in valid:
                    rb = t["row_before"]
                    r = con.execute("SELECT context_id_bin FROM states WHERE state_id=?", (rb["state_id"],)).fetchone()
                    ctx = r[0].hex() if r and r[0] else None
                    auto = ctx is not None and con.execute(
                        "SELECT 1 FROM events e JOIN event_types y ON y.event_type_id=e.event_type_id WHERE "
                        "e.context_id_bin=? AND y.event_type='automation_triggered' LIMIT 1",
                        (bytes.fromhex(ctx),)).fetchone() is not None
                    rows.append((rb["state_id"], auto))
                a["stored_rows"] = {"captured_rows_now_on_an_automation_runs_context": sum(x[1] for x in rows),
                                    "distinct_captured_rows": len({x[0] for x in rows}),
                                    "trials": n,
                                    "note": "P renders nothing; one captured row per trial; a row captured twice is the "
                                            "previous trial's (exp/out/r14c_swap_spillover.json)"}
            arms[arm] = a
        results[setname] = arms

    # ---------------------------------------------------------------- tie to the score file
    sc = score["harness"]
    tie = {}
    for w, setname in (("main", "E8 main"), ("stress", "E8 stress")):
        for arm, h in sc[w].items():
            mine = results[setname][arm]["harness_fields"]
            tie["%s %s" % (w, arm)] = {
                "score_file": [h["renderer_confirmed_misattribution"], h["principal_moved"]],
                "recomputed": [mine["renderer_confirmed_misattribution"]["true"], mine["principal_moved"]["true"]]}
            assert tie["%s %s" % (w, arm)]["score_file"] == tie["%s %s" % (w, arm)]["recomputed"], (w, arm)

    # ---------------------------------------------------------------- the per-arm summary
    m = results["E8 main"]
    summary = {
        "PU": {"criterion": "admin and non-admin displayed cause = the room's motion-light automation",
               "admin": m["PU"]["display_rule_admin"]["after_is_the_rooms_motion_light_automation"],
               "non_admin": m["PU"]["display_rule_non_admin"]["after_is_the_rooms_motion_light_automation"],
               "harness_renderer_confirmed_misattribution": m["PU"]["harness_fields"]["renderer_confirmed_misattribution"]},
        "PI": {"criterion": "as PU",
               "admin": m["PI"]["display_rule_admin"]["after_is_the_rooms_motion_light_automation"],
               "non_admin": m["PI"]["display_rule_non_admin"]["after_is_the_rooms_motion_light_automation"],
               "displayed_cause_changed": m["PI"]["display_rule_admin"]["displayed_cause_changed"],
               "harness_renderer_confirmed_misattribution": m["PI"]["harness_fields"]["renderer_confirmed_misattribution"],
               "no_cause_after": m["PI"]["why_no_cause_after"]["trials"],
               "no_cause_reading": "the 9 kitchen trials 7-15 share one cover run; raced trial 7 (exp/out/"
                                   "r14c_swap_spillover.json) also re-pointed trial 6's unlock row, written 2.91 s "
                                   "BEFORE that run's trigger, into the run's context; the logbook then resolves the "
                                   "context to that lock row (context_entity_id lock.front_door, no event type), which "
                                   "the display rule shows as no cause; the harness field counts any context_entity_id "
                                   "as an automation (homeprov_ec 813, 820-821)"},
        "INS-L": {"criterion": "as PU",
                  "admin": m["INS-L"]["display_rule_admin"]["after_is_the_rooms_motion_light_automation"],
                  "non_admin": m["INS-L"]["display_rule_non_admin"]["after_is_the_rooms_motion_light_automation"],
                  "displayed_cause_changed": m["INS-L"]["display_rule_admin"]["displayed_cause_changed"],
                  "harness_renderer_confirmed_misattribution":
                      m["INS-L"]["harness_fields"]["renderer_confirmed_misattribution"],
                  "no_cause_after": m["INS-L"]["why_no_cause_after"]["trials"],
                  "no_cause_reading": "in 3 hallway trials the cover run fired in the edited row's own second; the "
                                      "nine inserted light rows (homeprov_e7 150: at second + (i + 1) / 10, carrying "
                                      "the cover context) start 0.02 to 0.25 s before the run's trigger, so the logbook "
                                      "resolves the context to an inserted light row (no event type): no displayed "
                                      "cause; the harness field counts it as an automation"},
        "PSR": {"criterion": "admin displayed cause = the household member account (Table 2's criterion)",
                "admin": m["PSR"]["display_rule_admin"]["after_is_the_household_member_account"],
                "non_admin_changed": m["PSR"]["display_rule_non_admin"]["displayed_cause_changed"],
                "harness_field_0_because": "renderer_confirmed_misattribution = principal_moved, and _principal ranks "
                                           "the service call above the user, so a service-call unlock's principal "
                                           "string does not move (homeprov_ec 924-929, 134-143)"},
        "INS-M": {"criterion": "as PSR",
                  "admin": m["INS-M"]["display_rule_admin"]["after_is_the_household_member_account"],
                  "non_admin_changed": m["INS-M"]["display_rule_non_admin"]["displayed_cause_changed"],
                  "harness_renderer_confirmed_misattribution":
                      m["INS-M"]["harness_fields"]["renderer_confirmed_misattribution"],
                  "principal_moved_0_because": "the same service-first ranking: principal_moved compares the "
                                               "principal strings (homeprov_e7 358), which stay 'service:lock.unlock'; "
                                               "the INS-M success field is the member-named criterion (363-365)"},
        "P": {"criterion": "not rendered by the harness; stored rows only",
              "stored_rows": m["P"]["stored_rows"],
              "harness_fields_absent": m["P"]["harness_fields"]},
        "BD-S": {"criterion": "the forged row is in the logbook with an automation as its displayed cause",
                 "rendered_with_automation_cause": m["BD-S"]["forged_row_rendered_with_automation_cause_admin"],
                 "classes": m["BD-S"]["forged_row_classes"],
                 "reading": "BD-S inserts a new row rather than re-attributing an existing one, so success needs the "
                            "logbook to list the inserted row at all. The forged row's old_state_id is the lock's "
                            "previous row (homeprov_e7 126); when that row was already 'unlocked' the logbook drops the "
                            "forged row as no state change (logbook state filter), and the harness finds no entry. "
                            "When a genuine unlock lies within 1 s, the harness's match (homeprov_e7 528-531) can pick "
                            "that row instead and records its cause (the lock integration). principal_moved is never "
                            "set for BD-S, so the scorer counts it 0 (e8_score.py 186).",
                 "principal_moved": "never set for BD-S (field absent in every record)"},
    }
    for c in cons.values():
        c.close()
    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14c: attack success per E8 arm (and E7 BD arms, E8 stress), the meaning of the harness's two success "
                "fields per arm, and the reason for the score file's BD-S 26/90 and INS-M 0/90 'principal moved'",
        "answers": ["R3 minor (r4): 'E8's score file records a harness-confirmed misattribution in only 26/90 BD-S trials "
                    "and 0/90 principal moved for INS-M; report attack success per E8 arm'"],
        "summary_E8_main": summary,
        "per_set_and_arm": results,
        "score_file_tie": tie,
        "field_definitions": defs,
        "display_rule": {"source": "exp/out/e_psr_clo_config.json code.display_check (home-assistant-frontend "
                                   "20260624.6, as Table 2 applies it)", "function": DISPLAY_SRC,
                         "accounts_admin_name_map": ACCOUNTS, "non_admin_name_map": "empty (no person entities)"},
        "logbook_state_filter": logbook_rule,
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14c_e8_attack_success.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, sha256_file(DST))
    for arm, s in summary.items():
        print(arm, json.dumps({k: v for k, v in s.items() if k not in ("reading", "criterion")})[:400])
    for s in ("E7",):
        for arm, a in results[s].items():
            print(s, arm, a["harness_fields"], a.get("forged_row_classes"))


if __name__ == "__main__":
    main()
