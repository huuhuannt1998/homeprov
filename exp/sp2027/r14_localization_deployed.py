#!/usr/bin/env python3
"""R14 (S&P 2027 round 14, 2026-10-12): localization in the deployed configuration (coverage), per edited trial of E7
and E8, from the saved verify files.

Answers internal review r3: R3 W4 "report Figure 6's metrics and the suspect seconds per edit for E7 and E8, from
existing files"; R1 W4 "Report the E8 quarantine sizes".

THE QUARANTINE. Under coverage the verifier (exp/stages/e7_verify.py) flags a set of one-second segments: every
attributable second-level violation, every second holding an attributable row, the localized seconds of attributable
minute and hour violations, and every second that the rows of a failed keylog range sit in now or sat in when the
monitor first read them (flagged_seconds). That set, restricted to the scored window with the verifier's own rule for
second segments (t_start - 1 <= s <= t_end + 1, as exp/stages/e8_score.py scope_suspects), is the quarantine Q of a
window: its rows are the rows whose attribution the anchor no longer vouches for. Rows outside Q keep their committed
attribution.

PER EDITED TRIAL (every E7 and E8 trial edits or inserts after its row's segment was sealed):
  tampered elements T_i, from the harness reports (ground truth):
    edited state rows   laundered_state_ids, swapped_state_ids, or row_before.state_id (arm P); second = the row's
                        clean second (row_before.ts);
    deleted events      deleted_event_ids with deleted_event_seconds where the report lists them (E7-family arms);
                        for the laundering arms whose reports do not list them (E8 PU, PI, P), every event the verifier
                        reports removed after its first observation (attributable_rows, why
                        "removed_after_first_observation") whose first-observed second lies in the trial's own span
                        [ULID time of row_before.context_id_bin, row_before.ts] (the span the counting rule touches for
                        a deleted service-call event); each such event must map to exactly one trial (checked);
    inserted rows       inserted_state_ids (second from the recorder extract), forged_row / forged_state_id and
                        reserved_state_id (second = forged_row_ts, the second the row was moved or backdated into);
  covered_i             every element's second lies in Q (Figure 6's soundness rule: an element is covered when its
                        clean timestamp lies in a quarantined region; an inserted row's position is its only one);
  keys_flagged_i        every element's key is named by the verifier (an attributable row, a keylog suspect, or a row
                        removed from a failed key range);
  Q_i                   Q intersected with: the elements' seconds, the seconds of every failed keylog range whose rows
                        include an element's key (now or when first read), and the localized seconds of attributable
                        minute/hour violations that contain an element's second;
  spill_i               Q_i minus every second any trial of the window touched (the paper's counting rule:
                        reproduce/verify_all.py touched_segments plus the trials' deleted-event seconds, exactly as
                        exp/stages/e8_score.py window_touched): the suspect seconds attributed to this edit
                        (keylog-range spillover);
  rows                  surviving recorder rows (states + events) whose second lies in Q_i, from the shipped recorder
                        window extract (reproduce/snapshots/e7e8/<exp>.db, opened read-only and immutable);
  OQ_i                  Figure 6's over-quarantine |Q_i rows minus T| / |U| (exp/sp2027/r2_localize.py per-trial OQ),
                        T = every tampered key of the window, U = the surviving rows of the window (second in
                        [t_start - 1, t_end + 1]).
Per window the script also reports Q's size, the union of the spill_i, and checks that its recomputed untouched suspect
seconds equal the published counts (E7: exp/out/e7_main_score.json; E8: exp/out/e8_main_score_rescored.json).
The component policy of Figure 6 is not computed: it needs stage24's recomputation over the recorder graph, which the
deployed verifier does not run and no saved file holds.

    python3 exp/sp2027/r14_localization_deployed.py   -> exp/out/r14_localization_deployed.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import collections
import datetime
import hashlib
import json
import os
import statistics

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
EXTR = os.path.join(REPO, "reproduce", "snapshots", "e7e8")
DRY = os.environ.get("R14_DRYRUN_DIR")          # development only: write elsewhere
DST = os.path.join(DRY or OUT, "r14_localization_deployed.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.join(REPO, "reproduce"))
from rig import stats  # noqa: E402
import verify_all as VA  # noqa: E402  (touched_segments, ro_connect: the paper's counting rule, read-only)

INPUTS = {}


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


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return {"k": k, "n": n, "interval": [r["ci_lo"], r["ci_hi"]], "method": r["method"]}


def dist(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"n": len(xs), "median": statistics.median(xs), "mean": statistics.mean(xs), "max": max(xs),
            "min": min(xs)}


def ulid_sec(hexctx):
    return int(int(hexctx[:12], 16) / 1000.0 // 1) if hexctx and len(hexctx) == 32 else None


# ------------------------------------------------------------------------------------------------ inputs
EXPS = {
    "E7": {"db": os.path.join(EXTR, "e7_main.db"), "sums": os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS"),
           "dbname": "e7_main.db",
           "windows": {"main": {"verify": {"closure": "e7_main_closure_verify.json",
                                           "stable": "e7_main_stable_verify.json"},
                                "reports": ["e7_main_report_porch.json", "e7_main_report_hallway.json",
                                            "e7_main_report_kitchen.json"]}}},
    "E8": {"db": os.path.join(EXTR, "e8_main.db"), "sums": os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS"),
           "dbname": "e8_main.db",
           "windows": {"main": {"verify": {"closure": "e8_main_closure_verify_main.json",
                                           "stable": "e8_main_stable_verify_main.json"},
                                "reports": ["e8_main_report_ec_porch.json", "e8_main_report_e7_porch.json",
                                            "e8_main_report_ec_hallway.json", "e8_main_report_e7_hallway.json",
                                            "e8_main_report_ec_kitchen.json", "e8_main_report_e7_kitchen.json"]},
                       "stress": {"verify": {"closure": "e8_main_closure_verify_stress.json",
                                             "stable": "e8_main_stable_verify_stress.json"},
                                  "reports": ["e8_main_stress_report_porch.json"]},
                       "base": {"verify": {"closure": "e8_main_closure_verify_base.json",
                                           "stable": "e8_main_stable_verify_base.json"},
                                "reports": []}}},
}


def load_trials(files):
    out = []
    for f in files:
        d = read_json(os.path.join(OUT, f))
        room = d.get("room")
        for t in d.get("trials", []):
            if t.get("err") or t.get("error"):
                continue
            out.append(dict(t, room=room, _file=f))
    return out


def touched_window(trials, con):
    """exp/stages/e8_score.py window_touched: the counting rule plus the trials' own deleted-event seconds."""
    if not trials:
        return set()
    t = set(VA.touched_segments(trials, con, {"second": 1.0})["second"])
    for x in trials:
        t |= {str(int(float(s) // 1)) for s in (x.get("deleted_event_seconds") or [])}
    return t


def state_second(con, sid):
    r = con.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (sid,)).fetchone()
    return str(int(float(r[0]) // 1)) if r and r[0] is not None else None


def elements_of(t, con, removed_by_trial):
    """Tampered elements of one trial: (key, kind, second, source)."""
    els = []
    rb = t.get("row_before") or {}
    edited = list(t.get("laundered_state_ids") or []) + list(t.get("swapped_state_ids") or [])
    if t.get("arm") == "P" and not edited and rb.get("state_id"):
        edited = [rb["state_id"]]
    for sid in edited:
        if rb.get("state_id") == sid and rb.get("ts"):
            sec, src = str(int(float(rb["ts"]) // 1)), "row_before.ts (clean)"
        else:
            sec, src = state_second(con, sid), "recorder extract (current)"
        els.append({"key": "s:%d" % sid, "kind": "edited", "second": sec, "source": src})
    ids, secs = t.get("deleted_event_ids") or [], t.get("deleted_event_seconds") or []
    if ids:
        for j, eid in enumerate(ids):
            sec = str(int(float(secs[j]) // 1)) if j < len(secs) else None
            els.append({"key": "e:%d" % int(eid), "kind": "deleted", "second": sec,
                        "source": "report deleted_event_ids / deleted_event_seconds"})
    else:
        for key, sec in removed_by_trial.get(id(t), []):
            els.append({"key": key, "kind": "deleted", "second": sec,
                        "source": "verifier: removed after first observation, first-observed second in the "
                                  "trial's span [context ULID time, row_before.ts]"})
    for sid in t.get("inserted_state_ids") or []:
        els.append({"key": "s:%d" % sid, "kind": "inserted", "second": state_second(con, sid),
                    "source": "recorder extract (current)"})
    fr = t.get("forged_row") or {}
    fsid = t.get("reserved_state_id") or t.get("forged_state_id") or fr.get("state_id")
    if fsid:
        ts = t.get("forged_row_ts") or fr.get("ts")
        els.append({"key": "s:%d" % fsid, "kind": "inserted (backdated or moved in)",
                    "second": str(int(float(ts) // 1)) if ts else state_second(con, fsid),
                    "source": "report forged_row_ts" if ts else "recorder extract (current)"})
    return els


def deletes_expected(t):
    return bool((t.get("operations_used") or {}).get("delete")) and not (t.get("deleted_event_ids"))


def map_removed(trials, v):
    """Removed events of the laundering arms whose reports do not list them, mapped to trials by span."""
    removed = [(r["key"], r.get("first_observed_second")) for r in v.get("attributable_rows") or []
               if r["key"].startswith("e:") and any(w.get("why") == "removed_after_first_observation"
                                                      for w in r.get("why") or [])]
    listed = {"e:%d" % int(i) for t in trials for i in (t.get("deleted_event_ids") or [])}
    spans = []
    for t in trials:
        if not deletes_expected(t):
            continue
        rb = t.get("row_before") or {}
        lo, hi = ulid_sec(rb.get("context_id_bin")), (int(float(rb["ts"]) // 1) if rb.get("ts") else None)
        if lo is None or hi is None:
            continue
        spans.append((min(lo, hi), max(lo, hi), t))
    by_trial = collections.defaultdict(list)
    conflicts, unmapped = [], []
    for key, fos in removed:
        if key in listed:
            continue
        if fos is None:
            unmapped.append(key)
            continue
        hit = [t for lo, hi, t in spans if lo <= int(fos) <= hi]
        if len(hit) == 1:
            by_trial[id(hit[0])].append((key, fos))
        elif len(hit) > 1:
            conflicts.append({"key": key, "first_observed_second": fos,
                              "trials": ["%s/%s/%s" % (x.get("arm"), x.get("room"), x.get("trial")) for x in hit]})
        else:
            unmapped.append(key)
    no_event = ["%s/%s/%s" % (t.get("arm"), t.get("room"), t.get("trial")) for lo, hi, t in spans
                if not by_trial.get(id(t))]
    return by_trial, {"removed_events_reported_by_verifier": len(removed),
                      "listed_in_reports": len([k for k, _ in removed if k in listed]),
                      "mapped_by_span": sum(len(x) for x in by_trial.values()),
                      "span_conflicts": conflicts, "not_in_any_trial_span": unmapped,
                      "laundering_trials_without_a_mapped_removed_event": no_event}


def rows_by_second(con, t0, t1):
    by = collections.defaultdict(set)
    for sid, ts in con.execute("SELECT state_id, last_updated_ts FROM states WHERE last_updated_ts >= ? "
                               "AND last_updated_ts < ?", (t0 - 1, t1 + 2)):
        by[str(int(float(ts) // 1))].add("s:%d" % sid)
    for eid, ts in con.execute("SELECT event_id, time_fired_ts FROM events WHERE time_fired_ts >= ? "
                               "AND time_fired_ts < ?", (t0 - 1, t1 + 2)):
        by[str(int(float(ts) // 1))].add("e:%d" % eid)
    return by


def score_window(exp, win, mon, vfile, trials, con, touched, rows, window, published_spill):
    v = read_json(os.path.join(OUT, vfile))
    t0, t1 = window
    inwin = lambda s: s is not None and t0 - 1 <= int(s) <= t1 + 1
    Q = sorted({s for s in v.get("flagged_seconds") or [] if inwin(s)}, key=int)
    Qset = set(Q)
    U = {k for s, ks in rows.items() if inwin(s) for k in ks}
    q_rows = {k for s in Q for k in rows.get(s, ())}
    spill_all = sorted((s for s in Q if s not in touched), key=int)
    # e7_verify's own list is unscoped (every untouched flagged second of the whole chain); E8's published figures are
    # scoped to the window (exp/stages/e8_score.py scope_suspects); E7's published figures are e7_verify's unscoped ones
    spill_chain = sorted((s for s in v.get("flagged_seconds") or [] if s not in touched), key=int)
    unscoped_pub = ((v.get("benign_floor") or {}).get("untouched_flagged_seconds") or {}).get("n")
    kvs = v.get("keylog_violations") or []
    kv_keys = []
    for kv in kvs:
        ks = ({x["key"] for x in kv.get("suspects") or []} | set(kv.get("removed") or [])
              | {x["key"] for x in kv.get("changed") or []} | {x["key"] for x in kv.get("added") or []}
              | {x["key"] for x in kv.get("likely") or []})
        kv_keys.append(ks)
    flagged_keys = ({r["key"] for r in v.get("attributable_rows") or []}
                    | {k for ks in kv_keys for k in ks})
    coarse = [(f["gran"], f["seg"], f.get("localized_seconds") or []) for f in v.get("flagged_segments") or []
              if f["gran"] != "second" and f.get("localized_seconds")]
    W = {"minute": 60, "hour": 3600}
    removed_by_trial, removed_map = map_removed(trials, v)

    per_trial = []
    T_all = set()
    els_by = {}
    for t in trials:
        els = elements_of(t, con, removed_by_trial)
        els_by[id(t)] = els
        T_all |= {e["key"] for e in els}
    attributed_spill = set()
    for t in trials:
        els = els_by[id(t)]
        keys = {e["key"] for e in els}
        esecs = {e["second"] for e in els if e["second"] is not None}
        linked = [i for i, ks in enumerate(kv_keys) if ks & keys]
        rsecs = {s for i in linked for s in kvs[i].get("seconds") or []}
        csecs = {s for g, seg, loc in coarse for s in loc if any(int(e) // W[g] == int(seg) for e in esecs)}
        cand = esecs | rsecs | csecs
        Qi = sorted((s for s in cand if s in Qset), key=int)
        spill = [s for s in Qi if s not in touched]
        attributed_spill |= set(spill)
        qi_rows = {k for s in Qi for k in rows.get(s, ())}
        spill_rows = {k for s in spill for k in rows.get(s, ())}
        missing_second = [e["key"] for e in els if e["second"] is None]
        covered = bool(els) and not missing_second and all(e["second"] in Qset for e in els)
        per_trial.append({
            "arm": t.get("arm"), "room": t.get("room"), "trial": t.get("trial"),
            "n_tampered_elements": len(els),
            "elements": els,
            "covered": covered,
            "elements_not_covered": [e["key"] for e in els if e["second"] is not None and e["second"] not in Qset],
            "elements_without_a_second": missing_second,
            "keys_flagged_by_verifier": bool(els) and all(e["key"] in flagged_keys for e in els),
            "keys_not_flagged": sorted(e["key"] for e in els if e["key"] not in flagged_keys),
            "failed_keylog_ranges_linked": len(linked),
            "linked_flagged_seconds_outside_window": sorted((s for s in rsecs if not inwin(s)), key=int),
            "quarantine_seconds": len(Qi), "quarantine_rows": len(qi_rows),
            "quarantine_rows_untampered": len(qi_rows - T_all),
            "spill_seconds": len(spill), "spill_rows": len(spill_rows),
            "quarantined_seconds_touched_by_other_trials": len([s for s in Qi if s not in esecs and s in touched]),
            "over_quarantine": (len(qi_rows - T_all) / len(U)) if U else None,
            "quarantine_seconds_list": Qi, "spill_seconds_list": spill,
        })

    by_arm = collections.OrderedDict()
    for arm in sorted({p["arm"] for p in per_trial}, key=lambda a: [p["arm"] for p in per_trial].index(a)):
        ps = [p for p in per_trial if p["arm"] == arm]
        by_arm[arm] = arm_summary(ps)
    out = {
        "experiment": exp, "window": win, "monitor": mon, "verify_file": "exp/out/" + vfile,
        "window_bounds": [t0, t1], "window_rule": "second s with t_start - 1 <= s <= t_end + 1",
        "n_edited_trials": len(per_trial),
        "quarantine_window": {
            "seconds": len(Q), "rows": len(q_rows),
            "anchored_one_second_segments_in_window": ((v.get("segments") or {}).get("second") or {})
            .get("anchored_in_window"),
            "untouched_anchored_one_second_segments": (v.get("benign_floor") or {}).get("untouched_anchored_seconds"),
            "surviving_rows_in_window_U": len(U),
            "share_of_window_rows_quarantined": (len(q_rows) / len(U)) if U else None,
            "untouched_suspect_seconds_recomputed": len(spill_all),
            "untouched_suspect_seconds_published_scoped": published_spill,
            "matches_published": published_spill is None or len(spill_all) == published_spill,
            "untouched_flagged_seconds_whole_chain_recomputed": len(spill_chain),
            "untouched_flagged_seconds_whole_chain_e7_verify": unscoped_pub,
            "whole_chain_matches_e7_verify": len(spill_chain) == unscoped_pub,
            "untouched_flagged_seconds_outside_window": sorted(set(spill_chain) - set(spill_all), key=int),
            "untouched_suspect_seconds_attributed_to_an_edit": len(attributed_spill & set(spill_all)),
            "untouched_suspect_seconds_not_linked_to_any_edit": sorted(set(spill_all) - attributed_spill, key=int),
            "untouched_suspect_rows": len({k for s in spill_all for k in rows.get(s, ())}),
        },
        "removed_event_mapping": removed_map,
        "summary_all_trials": arm_summary(per_trial) if per_trial else None,
        "by_arm": by_arm,
        "trials": per_trial,
    }
    return out


def arm_summary(ps):
    k = sum(1 for p in ps if p["covered"])
    kf = sum(1 for p in ps if p["keys_flagged_by_verifier"])
    return {
        "n_trials": len(ps),
        "covered": cp(k, len(ps)),
        "keys_flagged_by_verifier": cp(kf, len(ps)),
        "tampered_elements_per_trial": dist([p["n_tampered_elements"] for p in ps]),
        "quarantine_seconds_per_trial": dist([p["quarantine_seconds"] for p in ps]),
        "quarantine_rows_per_trial": dist([p["quarantine_rows"] for p in ps]),
        "spill_seconds_per_trial": dist([p["spill_seconds"] for p in ps]),
        "spill_rows_per_trial": dist([p["spill_rows"] for p in ps]),
        "spill_seconds_sum_over_trials": sum(p["spill_seconds"] for p in ps),
        "trials_with_zero_spill": sum(1 for p in ps if p["spill_seconds"] == 0),
        "over_quarantine_per_trial": dist([p["over_quarantine"] for p in ps]),
        "quarantine_rows_untampered_per_trial": dist([p["quarantine_rows_untampered"] for p in ps]),
    }


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    e7s = read_json(os.path.join(OUT, "e7_main_score.json"))
    e8s = read_json(os.path.join(OUT, "e8_main_score_rescored.json"))
    sums = {}
    for line in open(os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS")):
        h, p = line.split(None, 1)
        sums[p.strip().lstrip("./")] = h
    INPUTS[os.path.relpath(os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS"), REPO)] = \
        sha256_file(os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS"))
    results = []
    for exp, cfg in EXPS.items():
        dbh = sha256_file(cfg["db"])
        assert dbh == sums[cfg["dbname"]], (exp, "extract does not match EXTRACTS_E7E8_SHA256SUMS")
        INPUTS[os.path.relpath(cfg["db"], REPO)] = dbh
        con = VA.ro_connect(cfg["db"])
        for win, wcfg in cfg["windows"].items():
            if exp == "E7":
                window = (e7s["window"]["t_start"], e7s["window"]["t_end"])
            else:
                window = (e8s["windows"][win]["t_start"], e8s["windows"][win]["t_end"])
            trials = load_trials(wcfg["reports"])
            touched = touched_window(trials, con)
            rows = rows_by_second(con, *window)
            for mon, vfile in wcfg["verify"].items():
                if exp == "E7":
                    pub = None          # E7's published 129/169 are e7_verify's whole-chain lists (checked below)
                    pub_e7 = e7s[mon + "_monitor"]["benign_floor"]["untouched_flagged_seconds"]["n"]
                else:
                    pub = e8s["monitors"][mon]["by_window"][win]["benign_floor"]["untouched_flagged_seconds"]["n"]
                r = score_window(exp, win, mon, vfile, trials, con, touched, rows, window, pub)
                r["touched_seconds_counting_rule"] = len(touched)
                if exp == "E7":
                    r["quarantine_window"]["published_figure_e7_main_score"] = pub_e7
                    r["quarantine_window"]["published_figure_is"] = (
                        "e7_verify's whole-chain list (E7 was not re-scored per window); it equals the whole-chain "
                        "recomputation" if pub_e7 == r["quarantine_window"]["untouched_flagged_seconds_whole_chain_recomputed"]
                        else "NOT equal to the whole-chain recomputation")
                results.append(r)
                qw = r["quarantine_window"]
                s = r["summary_all_trials"]
                print(exp, win, mon, "Q", qw["seconds"], "spill", qw["untouched_suspect_seconds_recomputed"], "pub",
                      qw["untouched_suspect_seconds_published_scoped"], "chain", qw["untouched_flagged_seconds_whole_chain_recomputed"],
                      qw["untouched_flagged_seconds_whole_chain_e7_verify"], "match", qw["matches_published"],
                      "covered", s and (s["covered"]["k"], s["covered"]["n"]),
                      "spill/trial med,max", s and (s["spill_seconds_per_trial"]["median"],
                                                    s["spill_seconds_per_trial"]["max"]))
        con.close()
    for r in results:
        qw = r["quarantine_window"]
        assert qw["matches_published"], (r["experiment"], r["window"], r["monitor"])
        assert qw["whole_chain_matches_e7_verify"], (r["experiment"], r["window"], r["monitor"])
        if r["experiment"] == "E7":
            assert qw["published_figure_e7_main_score"] == qw["untouched_flagged_seconds_whole_chain_recomputed"]

    # pooled coverage per experiment and monitor (edited trials of every window)
    pooled = {}
    for exp in EXPS:
        for mon in ("stable", "closure"):
            ps = [p for r in results if r["experiment"] == exp and r["monitor"] == mon for p in r["trials"]]
            if ps:
                pooled["%s_%s" % (exp, mon)] = arm_summary(ps)

    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14: localization in the deployed configuration (coverage) per edited trial of E7 and E8: quarantine "
                "size in seconds and rows, the untouched suspect seconds attributed to each edit (keylog-range "
                "spillover), whether the quarantine covers every tampered element, Figure 6's per-trial "
                "over-quarantine, and summaries per arm and monitor with exact intervals",
        "answers": ["R3 W4: 'report Figure 6's metrics and the suspect seconds per edit for E7 and E8, from existing "
                    "files'", "R1 W4: 'Report the E8 quarantine sizes'"],
        "definitions": {
            "quarantine_Q": "the verifier's flagged one-second segments in the window (exp/stages/e7_verify.py "
                            "flagged_seconds; window rule t_start - 1 <= s <= t_end + 1)",
            "covered": "every tampered element's second (edited row: clean second; deleted event: its second; inserted "
                       "row: the second it was backdated or moved into) lies in Q",
            "keys_flagged_by_verifier": "every tampered element's key is an attributable row, a keylog suspect or a "
                                        "row removed from a failed key range",
            "Q_i": "Q intersected with the trial's element seconds, the seconds of every failed keylog range holding "
                   "one of its keys, and localized seconds of attributable minute/hour violations containing an "
                   "element second",
            "spill_i": "Q_i minus every second touched by any trial of the window (paper's counting rule + deleted "
                       "events): untouched suspect seconds attributed to this edit",
            "over_quarantine": "|rows of Q_i minus every tampered key of the window| / |surviving rows of the window| "
                               "(Figure 6's per-trial OQ, exp/sp2027/r2_localize.py)",
            "not_computed": "the component policy of Figure 6 (needs the stage24 recomputation over the recorder "
                            "graph, which no saved file holds)",
            "shared_quarantine": "consecutive trials share failed key ranges, so Q_i of neighbouring trials overlap; "
                                 "per-trial sums double count, the window's union is quarantine_window",
        },
        "windows": results,
        "pooled_by_experiment_and_monitor": pooled,
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14_localization_deployed.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, hashlib.sha256(open(DST, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
