#!/usr/bin/env python3
"""R14c (S&P 2027 round 14c, 2026-10-12): localization in absolute terms for E7 and E8 (the deployed configuration with
coverage): untampered rows and untouched seconds inside each edit's quarantine, the window fraction quarantined as a
function of edit density, the single-edit case, and whether suspect seconds are quarantined.

Answers internal review r4: R1 W6 "say whether suspects are quarantined; report the single-edit case (one laundering in
a quiet day)"; R3 W6 "Report absolute untampered rows and seconds quarantined per edit, and the window fraction as a
function of edit rate."

WHAT IT READS (saved files only; nothing re-verifies; no E9 file is read):
  * exp/out/r14_localization_deployed.json: per edited trial the quarantine Q_i (its seconds), its rows, untampered rows,
    untouched (spill) seconds and rows, the tampered elements and their seconds; per window the quarantine totals;
  * the eight verify files (exp/out/e7_main_*_verify.json, exp/out/e8_main_*_verify_*.json): flagged_seconds (the
    quarantine), keylog_violations (failed key ranges, their suspects and "likely" rows), violations, recovery (escrow);
  * the shipped recorder extracts reproduce/snapshots/e7e8/e{7,8}_main.db (read-only, immutable; sha256 checked against
    EXTRACTS_E7E8_SHA256SUMS): rows per second, background write rate around an edit;
  * the harness reports of each window (for the counting rule's touched set, via reproduce/verify_all.py
    touched_segments and the trials' deleted-event seconds, exactly as r14_localization_deployed.py and
    exp/stages/e8_score.py window_touched);
  * exp/stages/e7_verify.py as text (line numbers of the quarantine rule; this is the E9-frozen copy, sha256 recorded;
    the E7/E8 verify files were written by an earlier revision, exp/out/e8_main_score_rescored.json code_sha256).

DEFINITIONS (Q, Q_i, spill_i, untampered rows: as exp/sp2027/r14_localization_deployed.py)
  untampered rows in Q_i   surviving rows whose second lies in Q_i, minus every tampered key of the window;
  untouched seconds in Q_i spill_i: seconds of Q_i that no trial touched (the counting rule);
  percentiles              numpy linear interpolation (p90 = 90th percentile);
  blocks                   consecutive 600 s blocks from each window's t_start (300 s as a sensitivity); per block: edited
                           trials whose first tampered element lies in it, surviving rows, rows in Q, untouched row-bearing
                           seconds, untouched suspect seconds;
  isolated edit            a trial whose Q_i shares no second with any other trial's Q_i, holds no second another trial
                           touched, and whose failed key ranges hold no other trial's tampered key: its quarantine is its
                           own;
  exact-localisation       counterfactual only, NOT a measurement: Q_i with each failed key range's seconds replaced by
  counterfactual           the seconds of its "likely" rows (changed, added, removed by 32-bit prefix). E7/E8 ran without
                           the per-row binding (E9's HOMEPROV_ROWBIND), so every row of a failed range was a suspect; the
                           binding would flag only the changed rows' seconds (e7_verify check_keylog). Prefix ranking
                           equals the binding's exact set unless a 32-bit prefix collides.

    python3 exp/sp2027/r14c_localization_absolute.py   -> exp/out/r14c_localization_absolute.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import collections
import datetime
import hashlib
import json
import os

import numpy as np
from scipy import stats as sps

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
EXTR = os.path.join(REPO, "reproduce", "snapshots", "e7e8")
MS = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13")
DST = os.path.join(os.environ.get("R14C_DRYRUN_DIR") or OUT, "r14c_localization_absolute.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as VA  # noqa: E402  (touched_segments, ro_connect: read-only)

INPUTS = {}
BLOCKS = (600, 300)
EDIT_ARMS = ("PU", "PI", "PSR", "P", "INS-L", "INS-M", "STALL", "OUTAGE")
EV = "exp/stages/e7_verify.py"
EV_LINES = {   # (line, fragment): the quarantine rule in e7_verify.py (current, E9-frozen copy)
    "every row of a failed key range is a suspect": (460, "Every row of a failed range is a suspect"),
    "without the per-row binding every row now or logged is a suspect": (513, "suspects = [row(k) for k in sorted(set(now) | set(logged))]"),
    "with the binding only changed, added, removed rows": (511, "suspects = [row(k) for k in sorted(set(changed) | set(added) | set(removed))]"),
    "a failed range's seconds: where its suspects sit now and sat when first observed": (514, "seconds = sorted({x for r_ in suspects for x in (r_[\"second\"], r_[\"first_observed_second\"]) if x},"),
    "keylog seconds collected": (1889, "keylog_seconds |= set(kv[\"seconds\"])"),
    "flagged_seconds includes the keylog seconds": (1950, "| keylog_seconds, key=int)"),
    "escrow recovery runs over every flagged second": (2211, "for seg in flagged_seconds:"),
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(p):
    return os.path.relpath(os.path.abspath(p), REPO)


def read_json(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def q(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    a = np.array(xs, dtype=float)
    return {"n": len(xs), "median": float(np.percentile(a, 50)), "p90": float(np.percentile(a, 90)),
            "max": float(a.max()), "mean": float(a.mean()), "min": float(a.min()), "sum": float(a.sum())}


METRICS = ("quarantine_seconds", "quarantine_rows", "quarantine_rows_untampered", "spill_seconds", "spill_rows")


def summarize(trials):
    return {m: q([t[m] for t in trials]) for m in METRICS}


def load_trials(files):
    out = []
    for f in files:
        d = read_json(os.path.join(OUT, f))
        for t in d.get("trials", []):
            if t.get("err") or t.get("error"):
                continue
            out.append(dict(t, room=d.get("room")))
    return out


def touched_window(trials, con):
    if not trials:
        return set()
    t = set(VA.touched_segments(trials, con, {"second": 1.0})["second"])
    for x in trials:
        t |= {str(int(float(s) // 1)) for s in (x.get("deleted_event_seconds") or [])}
    return t


def rows_by_second(con, t0, t1):
    by = collections.defaultdict(set)
    for sid, ts in con.execute("SELECT state_id, last_updated_ts FROM states WHERE last_updated_ts >= ? AND "
                               "last_updated_ts < ?", (t0 - 1, t1 + 2)):
        by[str(int(float(ts) // 1))].add("s:%d" % sid)
    for eid, ts in con.execute("SELECT event_id, time_fired_ts FROM events WHERE time_fired_ts >= ? AND "
                               "time_fired_ts < ?", (t0 - 1, t1 + 2)):
        by[str(int(float(ts) // 1))].add("e:%d" % eid)
    return by


def kv_keyset(kv):
    return ({x["key"] for x in kv.get("suspects") or []} | set(kv.get("removed") or [])
            | {x["key"] for x in kv.get("changed") or []} | {x["key"] for x in kv.get("added") or []}
            | {x["key"] for x in kv.get("likely") or []})


def likely_seconds(kv):
    return {x for r_ in (kv.get("likely") or []) for x in (r_.get("second"), r_.get("first_observed_second")) if x}


WINDOWS = {   # (experiment, window) -> extract, reports
    ("E7", "main"): ("e7_main.db", ["e7_main_report_porch.json", "e7_main_report_hallway.json",
                                    "e7_main_report_kitchen.json"]),
    ("E8", "main"): ("e8_main.db", ["e8_main_report_ec_porch.json", "e8_main_report_e7_porch.json",
                                    "e8_main_report_ec_hallway.json", "e8_main_report_e7_hallway.json",
                                    "e8_main_report_ec_kitchen.json", "e8_main_report_e7_kitchen.json"]),
    ("E8", "stress"): ("e8_main.db", ["e8_main_stress_report_porch.json"]),
    ("E8", "base"): ("e8_main.db", []),
}


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    r14 = read_json(os.path.join(OUT, "r14_localization_deployed.json"))
    sums = {}
    p_sums = os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS")
    INPUTS[rel(p_sums)] = sha256_file(p_sums)
    for line in open(p_sums):
        h, p = line.split(None, 1)
        sums[p.strip().lstrip("./")] = h
    cons = {}
    for name in ("e7_main.db", "e8_main.db"):
        db = os.path.join(EXTR, name)
        h = sha256_file(db)
        assert h == sums[name]
        INPUTS[rel(db)] = h
        cons[name] = VA.ro_connect(db)
    INPUTS[EV] = sha256_file(os.path.join(REPO, EV))
    evl = open(os.path.join(REPO, EV)).read().split("\n")
    code = {}
    for name, (ln, frag) in EV_LINES.items():
        assert frag in evl[ln - 1], (name, ln, evl[ln - 1])
        code[name] = {"file": EV, "line": ln, "text": evl[ln - 1].strip()}

    per_window, all_blocks, isolated_all = [], {b: [] for b in BLOCKS}, []
    for w in r14["windows"]:
        exp, win, mon = w["experiment"], w["window"], w["monitor"]
        dbname, reports = WINDOWS[(exp, win)]
        con = cons[dbname]
        t0, t1 = w["window_bounds"]
        inwin = lambda s: s is not None and t0 - 1 <= int(s) <= t1 + 1          # noqa: E731
        v = read_json(os.path.join(REPO, w["verify_file"]))
        Q = {s for s in v.get("flagged_seconds") or [] if inwin(s)}
        rows = rows_by_second(con, t0, t1)
        U = {k for s, ks in rows.items() if inwin(s) for k in ks}
        trials_h = load_trials(reports)
        touched = touched_window(trials_h, con)
        T = w["trials"]
        T_all = {e["key"] for t in T for e in t["elements"]}
        spill_all = {s for s in Q if s not in touched}
        qw = w["quarantine_window"]
        # the recomputation must reproduce r14's window totals exactly
        assert len(Q) == qw["seconds"], (exp, win, mon)
        assert len({k for s in Q for k in rows.get(s, ())}) == qw["rows"]
        assert len(U) == qw["surviving_rows_in_window_U"]
        assert len(spill_all) == qw["untouched_suspect_seconds_recomputed"]
        union_spill = set().union(*[set(t["spill_seconds_list"]) for t in T]) if T else set()
        assert union_spill == spill_all, (exp, win, mon, "spill union differs")

        # ---------------------------------------------------------- (1) absolute per-edit figures
        by_arm = collections.OrderedDict()
        for t in T:
            by_arm.setdefault(t["arm"], []).append(t)
        absolute = {"all_arms": summarize(T) if T else None,
                    "edit_arms_only": summarize([t for t in T if t["arm"] in EDIT_ARMS]) if T else None,
                    "by_arm": {a: summarize(ts) for a, ts in by_arm.items()}}

        # ---------------------------------------------------------- (4) suspects are quarantined
        rec = {it["second"]: it for it in ((v.get("recovery") or {}).get("seconds") or [])}
        second_attr = {x["seg"] for x in v.get("violations") or [] if x["gran"] == "second" and x.get("attributable")}
        second_late = {x["seg"] for x in v.get("violations") or [] if x["gran"] == "second"
                       and not x.get("attributable")}
        st = collections.Counter()
        for s in spill_all:
            it = rec.get(s)
            st["in_quarantine"] += s in Q
            st["second_violation_attributable"] += s in second_attr
            st["second_holds_late_rows_only_earlier_rule_violation"] += s in second_late
            if it is None:
                st["escrow_no_recovery_item"] += 1
            else:
                st["escrow_" + str(it.get("escrow"))] += 1
                if it.get("escrow") == "verified_against_anchor" and not (it.get("changed") or it.get("removed")
                                                                            or it.get("added")):
                    st["escrow_verified_and_rows_unchanged"] += 1
        suspects = {"untouched_suspect_seconds": len(spill_all), **dict(st),
                    "escrow_configured": v.get("recovery") is not None,
                    "recovery_items_cover_every_flagged_second": (set(rec) == set(v.get("flagged_seconds") or []))
                    if rec else None,
                    "untouched_suspect_rows": len({k for s in spill_all for k in rows.get(s, ())})}

        # ---------------------------------------------------------- (2) blocks: fraction vs edit density
        first_sec = {}
        for t in T:
            secs = [int(e["second"]) for e in t["elements"] if e.get("second") is not None]
            first_sec[(t["arm"], t["room"], t["trial"])] = min(secs) if secs else None
        blocks = {}
        for B in BLOCKS:
            bl = []
            nb = int((t1 - t0 + B - 1) // B)
            for i in range(nb):
                lo, hi = t0 + i * B, min(t0 + (i + 1) * B, t1)
                in_b = lambda s: lo <= int(s) < hi                                          # noqa: E731
                secs_rows = [s for s in rows if inwin(s) and in_b(s) and rows[s]]
                n_rows = sum(len(rows[s]) for s in secs_rows)
                q_rows = sum(len(rows[s]) for s in secs_rows if s in Q)
                unt = [s for s in secs_rows if s not in touched]
                edits = sum(1 for x in first_sec.values() if x is not None and lo <= x < hi)
                bl.append({"experiment": exp, "window": win, "monitor": mon, "block_start": lo, "block_s": hi - lo,
                           "edited_trials": edits, "edits_per_hour": edits * 3600.0 / (hi - lo),
                           "rows": n_rows, "rows_quarantined": q_rows,
                           "fraction_rows_quarantined": q_rows / n_rows if n_rows else None,
                           "row_seconds": len(secs_rows), "row_seconds_quarantined": sum(1 for s in secs_rows if s in Q),
                           "untouched_row_seconds": len(unt), "untouched_suspect_seconds": sum(1 for s in unt if s in Q),
                           "fraction_untouched_seconds_suspect": (sum(1 for s in unt if s in Q) / len(unt))
                           if unt else None})
            blocks[str(B)] = bl
            all_blocks[B].extend(bl)

        # ---------------------------------------------------------- (3) isolated edits and the exact counterfactual
        kvs = v.get("keylog_violations") or []
        kv_keys = [kv_keyset(kv) for kv in kvs]
        qi_sets = {(t["arm"], t["room"], t["trial"]): set(t["quarantine_seconds_list"]) for t in T}
        keys_of = {(t["arm"], t["room"], t["trial"]): {e["key"] for e in t["elements"]} for t in T}
        coarse = [(f["gran"], f["seg"], f.get("localized_seconds") or []) for f in v.get("flagged_segments") or []
                  if f["gran"] != "second" and f.get("localized_seconds")]
        WG = {"minute": 60, "hour": 3600}
        iso, exact = [], []
        for t in T:
            me = (t["arm"], t["room"], t["trial"])
            keys = keys_of[me]
            esecs = {e["second"] for e in t["elements"] if e.get("second") is not None}
            linked = [i for i, ks in enumerate(kv_keys) if ks & keys]
            other_keys = set().union(*[k for o, k in keys_of.items() if o != me]) if len(keys_of) > 1 else set()
            others_q = set().union(*[s for o, s in qi_sets.items() if o != me]) if len(qi_sets) > 1 else set()
            isolated = (not (qi_sets[me] & others_q) and t["quarantined_seconds_touched_by_other_trials"] == 0
                        and not any(kv_keys[i] & other_keys for i in linked))
            csecs = {s for g, seg, loc in coarse for s in loc if any(int(e) // WG[g] == int(seg) for e in esecs)}
            lsecs = {s for i in linked for s in likely_seconds(kvs[i])}
            qx = {s for s in (esecs | lsecs | csecs) if s in Q}
            sx = {s for s in qx if s not in touched}
            sx_rows = {k for s in sx for k in rows.get(s, ())}
            qx_rows = {k for s in qx for k in rows.get(s, ())}
            exact.append({"arm": t["arm"], "spill_seconds_exact": len(sx), "spill_rows_exact": len(sx_rows),
                          "quarantine_seconds_exact": len(qx), "quarantine_rows_untampered_exact": len(qx_rows - T_all)})
            if isolated:
                s0 = min(int(x) for x in esecs) if esecs else None
                bg = (sum(len([k for k in rows.get(str(s), ()) if k not in T_all]) for s in range(s0 - 60, s0 + 61))
                      / 121.0) if s0 is not None else None
                iso.append({"experiment": exp, "window": win, "monitor": mon, "arm": t["arm"], "room": t["room"],
                            "trial": t["trial"], "edit_second": s0,
                            "background_rows_per_s_pm60": bg,
                            "quarantine_seconds": t["quarantine_seconds"], "quarantine_rows": t["quarantine_rows"],
                            "quarantine_rows_untampered": t["quarantine_rows_untampered"],
                            "spill_seconds": t["spill_seconds"], "spill_rows": t["spill_rows"],
                            "failed_key_ranges_linked": len(linked)})
        isolated_all.extend(iso)
        ex_by = collections.defaultdict(list)
        for x in exact:
            ex_by[x["arm"]].append(x)
        exact_sum = {"all_arms": {m: q([x[m] for x in exact]) for m in ("spill_seconds_exact", "spill_rows_exact",
                                                                          "quarantine_seconds_exact",
                                                                          "quarantine_rows_untampered_exact")}
                     if exact else None,
                     "by_arm": {a: {m: q([x[m] for x in xs]) for m in ("spill_seconds_exact",
                                                                       "quarantine_rows_untampered_exact")}
                                for a, xs in ex_by.items()}}

        dur = t1 - t0
        per_window.append({
            "experiment": exp, "window": win, "monitor": mon, "verify_file": w["verify_file"],
            "window_bounds": [t0, t1], "duration_s": dur,
            "edited_trials": len(T), "edited_trials_per_hour": len(T) * 3600.0 / dur,
            "window_totals": {"quarantine_seconds": len(Q), "anchored_seconds": qw["anchored_one_second_segments_in_window"],
                              "quarantine_rows": qw["rows"], "surviving_rows": len(U),
                              "fraction_rows_quarantined": qw["rows"] / len(U) if U else None,
                              "fraction_anchored_seconds_quarantined": len(Q) / qw["anchored_one_second_segments_in_window"],
                              "untouched_anchored_seconds": qw["untouched_anchored_one_second_segments"],
                              "untouched_suspect_seconds": len(spill_all),
                              "fraction_untouched_seconds_suspect": len(spill_all) / qw["untouched_anchored_one_second_segments"],
                              "untouched_suspect_rows": qw["untouched_suspect_rows"],
                              "tampered_keys": len(T_all)},
            "per_edit_absolute": absolute,
            "suspects_quarantined": suspects,
            "blocks": blocks,
            "isolated_edits": {"n": len(iso), "of": len(T),
                               "by_arm": dict(collections.Counter(x["arm"] for x in iso)),
                               "edit_arms_summary": {m: q([x[m] for x in iso if x["arm"] in EDIT_ARMS])
                                                     for m in METRICS + ("background_rows_per_s_pm60",)},
                               "detail": iso},
            "exact_localisation_counterfactual": exact_sum,
        })

    # ------------------------------------------------------------------ cross-window: fraction vs density
    def corr(bl, field):
        xs = [b["edits_per_hour"] for b in bl if b[field] is not None]
        ys = [b[field] for b in bl if b[field] is not None]
        r = sps.spearmanr(xs, ys)
        return {"n_blocks": len(xs), "spearman_rho": float(r.statistic), "p_value": float(r.pvalue)}

    density = {}
    for B in BLOCKS:
        for mon in ("stable", "closure"):
            bl = [b for b in all_blocks[B] if b["monitor"] == mon and b["block_s"] >= B / 2]
            bins = collections.OrderedDict()
            for lab, lo, hi in (("0 edits", 0, 0), ("1-5", 1, 5), ("6-15", 6, 15), ("16-30", 16, 30),
                                (">30", 31, 10 ** 9)):
                sel = [b for b in bl if lo <= b["edited_trials"] <= hi]
                rows_ = sum(b["rows"] for b in sel)
                qr = sum(b["rows_quarantined"] for b in sel)
                un = sum(b["untouched_row_seconds"] for b in sel)
                us = sum(b["untouched_suspect_seconds"] for b in sel)
                bins[lab] = {"blocks": len(sel), "edits": sum(b["edited_trials"] for b in sel),
                             "hours": sum(b["block_s"] for b in sel) / 3600.0,
                             "rows": rows_, "rows_quarantined": qr, "fraction_rows_quarantined": qr / rows_ if rows_ else None,
                             "untouched_row_seconds": un, "untouched_suspect_seconds": us,
                             "fraction_untouched_seconds_suspect": us / un if un else None}
            density["%ds_%s" % (B, mon)] = {
                "blocks_used": len(bl), "rule": "blocks of at least half the nominal length",
                "rows_quarantined_vs_edits_per_hour": corr(bl, "fraction_rows_quarantined"),
                "untouched_suspect_share_vs_edits_per_hour": corr(bl, "fraction_untouched_seconds_suspect"),
                "by_edit_count": bins}

    # ------------------------------------------------------------------ paper check (Section 7.8)
    e8m = [w for w in per_window if (w["experiment"], w["window"], w["monitor"]) == ("E8", "main", "stable")][0]
    a = e8m["per_edit_absolute"]["all_arms"]
    tex = os.path.join(MS, "sections", "07_sp_eval.tex")
    INPUTS[rel(tex)] = sha256_file(tex)
    printed = [s.strip().rstrip(".") + "." for line in open(tex) for s in line.split(". ")
               if "spanned a median of" in s or "such a suspect" in s or "become quarantined suspects" in s]
    paper_check = {"printed": printed,
                   "E8_main_stable_all_arms": {"median_quarantine_seconds": a["quarantine_seconds"]["median"],
                                               "median_quarantine_rows": a["quarantine_rows"]["median"],
                                               "max_quarantine_seconds": a["quarantine_seconds"]["max"],
                                               "median_spill_seconds": a["spill_seconds"]["median"],
                                               "max_spill_seconds": a["spill_seconds"]["max"]}}

    iso_edit = [x for x in isolated_all if x["arm"] in EDIT_ARMS and x["monitor"] == "stable"]
    base = [w for w in per_window if (w["experiment"], w["window"], w["monitor"]) == ("E8", "base", "stable")][0]
    quiet_rate = base["window_totals"]["surviving_rows"] / base["duration_s"]
    iso_quiet = [x for x in iso_edit if x["background_rows_per_s_pm60"] is not None
                 and x["background_rows_per_s_pm60"] <= quiet_rate]
    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14c: E7/E8 localization in absolute terms per edit (untampered rows and untouched seconds in each "
                "edit's quarantine), the window fraction quarantined against edit density (blocks of 600 s and 300 s), "
                "isolated single edits, an exact-localisation counterfactual, and whether suspects are quarantined",
        "answers": ["R1 W6 (r4): 'say whether suspects are quarantined; report the single-edit case'",
                    "R3 W6 (r4): 'Report absolute untampered rows and seconds quarantined per edit, and the window "
                    "fraction as a function of edit rate'"],
        "windows": per_window,
        "fraction_vs_edit_density": density,
        "single_edit": {
            "baseline_window": "E8's 600 s baseline holds no edit: its quarantine is empty (0 of 124 anchored "
                               "seconds, both monitors; see windows[E8 base])",
            "no_saved_window_holds_one_edit_in_a_quiet_stretch": True,
            "isolated_edits_stable_monitor_edit_arms": {
                "n": len(iso_edit), "by_window_arm": dict(collections.Counter("%s %s %s" % (x["experiment"], x["window"],
                                                                                            x["arm"]) for x in iso_edit)),
                **{m: q([x[m] for x in iso_edit]) for m in METRICS + ("background_rows_per_s_pm60",)}},
            "isolated_edits_as_quiet_as_the_baseline": {
                "rule": "isolated edit-arm trials (stable monitor) whose background rate (surviving untampered rows per "
                        "second in the 121 s around the edit) is at most the E8 baseline window's rate",
                "baseline_rows_per_s": quiet_rate, "n": len(iso_quiet),
                "by_window_arm": dict(collections.Counter("%s %s %s" % (x["experiment"], x["window"], x["arm"])
                                                          for x in iso_quiet)),
                **{m: q([x[m] for x in iso_quiet]) for m in METRICS + ("background_rows_per_s_pm60",)}},
            "isolated_edits_all": isolated_all},
        "suspects_are_quarantined": {
            "answer": "yes: the verifier's flagged seconds (the quarantine) include every second a failed key range's "
                      "rows sit in or sat in when first read, and without the per-row binding every row of a failed "
                      "range is a suspect; the escrow recovery then examines every flagged second",
            "code": code,
            "per_window": {"%s %s %s" % (w["experiment"], w["window"], w["monitor"]): w["suspects_quarantined"]
                           for w in per_window}},
        "paper_check_section_7_8": paper_check,
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14c_localization_absolute.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0], "numpy": np.__version__,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    for c in cons.values():
        c.close()
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, sha256_file(DST))
    for w in per_window:
        a = w["per_edit_absolute"]["all_arms"]
        wt = w["window_totals"]
        print(w["experiment"], w["window"], w["monitor"], "edits", w["edited_trials"],
              "untampered rows med/p90/max", a and (a["quarantine_rows_untampered"]["median"],
                                                   a["quarantine_rows_untampered"]["p90"],
                                                   a["quarantine_rows_untampered"]["max"]),
              "spill s med/p90/max", a and (a["spill_seconds"]["median"], a["spill_seconds"]["p90"],
                                            a["spill_seconds"]["max"]),
              "frac rows", round(wt["fraction_rows_quarantined"], 4), "iso", w["isolated_edits"]["n"],
              "susp", w["suspects_quarantined"])
    print(json.dumps(density["600s_stable"], indent=0)[:1500])
    print(json.dumps(out["single_edit"]["isolated_edits_stable_monitor_edit_arms"])[:1200])
    print(json.dumps(out["single_edit"]["isolated_edits_as_quiet_as_the_baseline"])[:1500])
    print(json.dumps(paper_check))


if __name__ == "__main__":
    main()
