#!/usr/bin/env python3
"""R14c (S&P 2027 round 14c, 2026-10-12): the deployed configuration's benign bound per sealed segment, the occupancy of
each E7/E8 window, and the per-hour and per-day bound implied at stated occupancies.

Answers internal review r4, R3 W2: "That count is converted into 'at most 0.83 per wall-clock hour or 19.95 per day' by
dividing by E7/E8 wall-clock time, most of whose row-bearing seconds were touched by trials and removed from n ... At
Sec. 7.1's 34.9% occupancy the same bound (9.3x10^-4 per segment) gives about 1.2 per hour, roughly 28 per day; at
stress occupancy about 2.2 per hour." Fix asked: "Report the bound per sealed segment, then scale it at stated deployment
occupancies."

WHAT IT READS (saved files only; nothing runs against a live system; no E9 file is read):
  * exp/out/r14_benign_rates.json: the published pool (k = 0 of n = 3,972 untouched anchored one-second segments, E7 and
    the three E8 windows, either monitor) and its wall-clock duration, to tie this file to the printed figure;
  * the eight verify files (exp/out/e7_main_{stable,closure}_verify.json, exp/out/e8_main_{stable,closure}_verify_
    {main,base,stress}.json): per window and monitor, k and n of the one-second benign floor (benign_floor.violated,
    benign_floor.untouched_anchored_seconds), the anchored one-second and one-minute segments in the window
    (segments.second/minute.anchored_in_window, e7_verify's window rule t_start - 1 <= s <= t_end + 1 for seconds), and
    the minute floor (benign_floor.minute.attributable / untouched_anchored);
  * exp/out/e7_main_score.json and exp/out/e8_main_score_rescored.json: the windows, and E8's recorder write rate per
    window (write_rate.<w>.seconds_with_a_row, rows of monitor.load() on the full recorder);
  * the shipped recorder window extracts reproduce/snapshots/e7e8/e{7,8}_main.db (read-only, immutable; sha256 checked
    against EXTRACTS_E7E8_SHA256SUMS): the seconds and minutes of each window that hold at least one states or events row;
  * exp/out/r13_write_rate.json: the twelve earlier single-host runs' occupancy (Section 7.1's 34.9%);
  * sections/07_sp_eval.tex: the printed sentence, quoted.

DEFINITIONS
  per-segment bound    the exact (Clopper-Pearson, exp/rig/stats.py, alpha = 0.05) upper end of k/n, k = 0, n = 3,972:
                       the 95% upper bound on the probability that an untouched sealed one-second segment fails; the
                       one-sided 95% bound 1 - 0.05^(1/n) is given beside it;
  sealed occupancy     anchored one-second segments in the window / window duration (s): the share of wall-clock seconds
                       that held a row when sealed and were anchored (numerator uses e7_verify's window rule, which
                       admits t_start - 1 and t_end + 1);
  row occupancy        seconds s, t_start <= s < t_end, holding at least one surviving states/events row in the shipped
                       extract / window duration (E8: also the scorer's own figure from the full recorder);
  untouched occupancy  n / window duration: the occupancy the printed per-wall-clock figure implicitly assumes;
  implied bound        per-segment bound x occupancy x 3600 (per hour), x 86400 (per day): in a home without trials every
                       sealed second is untouched, so the expected failures per wall-clock hour are (failure probability
                       per sealed second) x (sealed seconds per hour).
  minute analogue      the same with untouched anchored one-minute segments (benign_floor.minute) and minute occupancy.

    python3 exp/sp2027/r14c_benign_per_segment.py   -> exp/out/r14c_benign_per_segment.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import datetime
import hashlib
import json
import math
import os
import sqlite3

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
EXTR = os.path.join(REPO, "reproduce", "snapshots", "e7e8")
PAPER = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13", "sections")
DST = os.path.join(os.environ.get("R14C_DRYRUN_DIR") or OUT, "r14c_benign_per_segment.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import stats  # noqa: E402

INPUTS = {}
GRID = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 1.00]


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


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return [r["ci_lo"], r["ci_hi"]]


def scale(p, occ):
    return {"occupancy": occ, "per_hour": p * occ * 3600.0, "per_day": p * occ * 86400.0}


def ro(db):
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)


def occupied(con, t0, t1, width):
    """Distinct floor(ts / width) of every states / events row with t0 <= ts < t1 (the extract's surviving rows)."""
    s = set()
    for (ts,) in con.execute("SELECT last_updated_ts FROM states WHERE last_updated_ts >= ? AND last_updated_ts < ?",
                             (t0, t1)):
        s.add(int(float(ts) // width))
    for (ts,) in con.execute("SELECT time_fired_ts FROM events WHERE time_fired_ts >= ? AND time_fired_ts < ?",
                             (t0, t1)):
        s.add(int(float(ts) // width))
    return s


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    r14 = read_json(os.path.join(OUT, "r14_benign_rates.json"))
    e7s = read_json(os.path.join(OUT, "e7_main_score.json"))
    e8s = read_json(os.path.join(OUT, "e8_main_score_rescored.json"))
    r13 = read_json(os.path.join(OUT, "r13_write_rate.json"))
    sums = {}
    p_sums = os.path.join(EXTR, "EXTRACTS_E7E8_SHA256SUMS")
    INPUTS[rel(p_sums)] = sha256_file(p_sums)
    for line in open(p_sums):
        h, p = line.split(None, 1)
        sums[p.strip().lstrip("./")] = h

    windows = [("E7", "main", e7s["window"], "e7_main.db",
                {"stable": "e7_main_stable_verify.json", "closure": "e7_main_closure_verify.json"}, None)]
    for w in ("main", "base", "stress"):
        windows.append(("E8", w, e8s["windows"][w], "e8_main.db",
                        {"stable": "e8_main_stable_verify_%s.json" % w, "closure": "e8_main_closure_verify_%s.json" % w},
                        e8s["write_rate"][w]))

    per_window = []
    cons = {}
    for exp, w, win, dbname, vfiles, wr in windows:
        db = os.path.join(EXTR, dbname)
        if dbname not in cons:
            h = sha256_file(db)
            assert h == sums[dbname], (dbname, "extract does not match EXTRACTS_E7E8_SHA256SUMS")
            INPUTS[rel(db)] = h
            cons[dbname] = ro(db)
        con = cons[dbname]
        t0, t1, dur = float(win["t_start"]), float(win["t_end"]), float(win["duration_s"])
        assert abs((t1 - t0) - dur) < 1e-6
        mons = {}
        for mon, vf in vfiles.items():
            v = read_json(os.path.join(OUT, vf))
            bf, seg = v["benign_floor"], v["segments"]
            mons[mon] = {"verify_file": "exp/out/" + vf,
                         "k_second": bf["violated"], "n_second_untouched": bf["untouched_anchored_seconds"],
                         "anchored_seconds_in_window": seg["second"]["anchored_in_window"],
                         "k_minute": bf["minute"]["attributable"], "n_minute_untouched": bf["minute"]["untouched_anchored"],
                         "anchored_minutes_in_window": seg["minute"]["anchored_in_window"]}
        # both monitors observed the same run: the untouched sets and anchored counts must agree
        a, b = mons["stable"], mons["closure"]
        for f in ("n_second_untouched", "anchored_seconds_in_window", "n_minute_untouched", "anchored_minutes_in_window"):
            assert a[f] == b[f], (exp, w, f, a[f], b[f])
        secs = occupied(con, t0, t1, 1.0)
        mins = occupied(con, t0, t1, 60.0)
        n_min_window = int((t1 - 1) // 60) - int(t0 // 60) + 1          # minutes overlapping [t0, t1)
        row = {"experiment": exp, "window": w, "t_start": t0, "t_end": t1, "duration_s": dur,
               "monitors": mons,
               "n_untouched_seconds": a["n_second_untouched"], "k_untouched_seconds": a["k_second"] + b["k_second"],
               "anchored_seconds_in_window": a["anchored_seconds_in_window"],
               "sealed_occupancy": a["anchored_seconds_in_window"] / dur,
               "row_seconds_in_extract": len(secs),
               "row_occupancy_extract": len(secs) / dur,
               "untouched_occupancy": a["n_second_untouched"] / dur,
               "touched_share_of_anchored_seconds": 1.0 - a["n_second_untouched"] / a["anchored_seconds_in_window"],
               "n_untouched_minutes": a["n_minute_untouched"], "k_untouched_minutes": a["k_minute"] + b["k_minute"],
               "anchored_minutes_in_window": a["anchored_minutes_in_window"],
               "minutes_overlapping_window": n_min_window,
               "row_minutes_in_extract": len(mins),
               "minute_row_occupancy_extract": len(mins) / n_min_window}
        if wr is not None:
            row["row_occupancy_scorer"] = wr["seconds_with_a_row"]["share"]
            row["row_seconds_scorer"] = wr["seconds_with_a_row"]["k"]
            row["row_occupancy_scorer_source"] = ("exp/out/e8_main_score_rescored.json write_rate.%s.seconds_with_a_row "
                                                  "(rows of monitor.load() on the full recorder)" % w)
        per_window.append(row)

    # ------------------------------------------------------------------ the pool and the per-segment bound
    n = sum(r["n_untouched_seconds"] for r in per_window)
    k = sum(r["monitors"]["stable"]["k_second"] for r in per_window)
    k_clo = sum(r["monitors"]["closure"]["k_second"] for r in per_window)
    dur = sum(r["duration_s"] for r in per_window)
    pool = r14["pools"]["stable_columns_with_coverage_E7_E8"]
    assert (k, n) == (pool["k"], pool["n_untouched_anchored_one_second_segments"]) == (0, 3972), (k, n)
    assert k_clo == r14["pools"]["closure_with_coverage_E7_E8"]["k"] == 0
    assert abs(dur - pool["window_duration_s"]) < 1e-6
    lo, hi = cp(k, n)
    one_sided = 1.0 - 0.05 ** (1.0 / n)
    closed_form = 1.0 - 0.025 ** (1.0 / n)                       # CP upper end for k = 0
    assert abs(closed_form - hi) < 1e-12
    printed_hour = hi * n / dur * 3600.0
    assert abs(printed_hour - pool["per_wallclock_hour"]["exact_interval"][1]) < 1e-9

    anchored_all = sum(r["anchored_seconds_in_window"] for r in per_window)
    rows_all = sum(r["row_seconds_in_extract"] for r in per_window)
    lab = r13["pooled_single_host_real_deployment"]["seconds_with_at_least_one_row"]

    occupancies = []

    def add(label, occ, source):
        occupancies.append({"label": label, "source": source, **scale(hi, occ),
                            "one_sided_95": scale(one_sided, occ)})
    add("untouched occupancy of E7 + E8 (what the printed 0.83 per hour assumes)", n / dur,
        "n / total window duration = %d / %g" % (n, dur))
    add("sealed occupancy of E7 + E8 pooled", anchored_all / dur, "anchored seconds / total duration = %d / %g"
        % (anchored_all, dur))
    add("row occupancy of E7 + E8 pooled (extracts)", rows_all / dur, "row seconds / total duration = %d / %g"
        % (rows_all, dur))
    for r in per_window:
        tag = "%s %s" % (r["experiment"], r["window"])
        add(tag + ": sealed occupancy", r["sealed_occupancy"], "anchored seconds in window / duration = %d / %g"
            % (r["anchored_seconds_in_window"], r["duration_s"]))
        add(tag + ": row occupancy (extract)", r["row_occupancy_extract"], "row seconds / duration = %d / %g"
            % (r["row_seconds_in_extract"], r["duration_s"]))
        if "row_occupancy_scorer" in r:
            add(tag + ": row occupancy (scorer, full recorder)", r["row_occupancy_scorer"],
                r["row_occupancy_scorer_source"])
    add("twelve earlier single-host runs (Section 7.1's 34.9%)", lab["share"],
        "exp/out/r13_write_rate.json pooled_single_host_real_deployment.seconds_with_at_least_one_row = %d / %d"
        % (lab["k"], lab["n"]))
    grid = [{**scale(hi, o), "one_sided_95": scale(one_sided, o)} for o in GRID]

    # ------------------------------------------------------------------ R3's arithmetic
    by = {(r["experiment"], r["window"]): r for r in per_window}
    st = by[("E8", "stress")]
    r3 = {
        "claim_per_segment": "9.3x10^-4 per segment",
        "computed_per_segment": hi,
        "per_segment_holds": round(hi, 5) == 0.00093,
        "claim_34.9pct": "about 1.2 per hour, roughly 28 per day",
        "computed_at_34.9pct_printed": scale(hi, 0.349),
        "computed_at_lab_share_r13": scale(hi, lab["share"]),
        "holds_34.9pct": round(hi * 0.349 * 3600, 1) == 1.2 and round(hi * 0.349 * 86400) == 28,
        "claim_stress": "about 2.2 per hour at stress occupancy",
        "computed_at_stress_row_occupancy_scorer": scale(hi, st["row_occupancy_scorer"]),
        "computed_at_stress_row_occupancy_extract": scale(hi, st["row_occupancy_extract"]),
        "computed_at_stress_sealed_occupancy": scale(hi, st["sealed_occupancy"]),
        "stress_reading": ("the stress window's occupancy (%.4f by the scorer, %.4f sealed) gives %.2f and %.2f per hour: "
                           "2.3 to one decimal, so R3's 'about 2.2' is slightly low; the direction of the point holds"
                           % (st["row_occupancy_scorer"], st["sealed_occupancy"],
                              hi * st["row_occupancy_scorer"] * 3600, hi * st["sealed_occupancy"] * 3600)),
        "why_the_printed_figure_is_lower": ("the printed 0.83 per hour equals the per-segment bound x n / wall-clock "
                                            "duration x 3600, i.e. an occupancy of %.4f (untouched seconds per "
                                            "wall-clock second); the windows' sealed occupancy was %.4f, because "
                                            "trials touched %d of %d anchored seconds and the counting rule removed "
                                            "them from n" % (n / dur, anchored_all / dur, anchored_all - n, anchored_all)),
    }

    # ------------------------------------------------------------------ minute analogue
    n_m = sum(r["n_untouched_minutes"] for r in per_window)
    k_m = sum(r["k_untouched_minutes"] for r in per_window)
    lo_m, hi_m = cp(k_m, n_m)
    min_rows_all = sum(r["row_minutes_in_extract"] for r in per_window)
    min_total = sum(r["minutes_overlapping_window"] for r in per_window)
    minute = {"k": k_m, "n_untouched_anchored_minutes": n_m, "per_minute_segment_exact_interval": [lo_m, hi_m],
              "one_sided_95": 1.0 - 0.05 ** (1.0 / n_m),
              "minute_row_occupancy_pooled_extract": min_rows_all / min_total,
              "implied_per_hour_at_pooled_minute_occupancy": hi_m * (min_rows_all / min_total) * 60.0,
              "implied_per_day_at_pooled_minute_occupancy": hi_m * (min_rows_all / min_total) * 1440.0,
              "implied_per_hour_at_full_minute_occupancy": hi_m * 60.0,
              "implied_per_day_at_full_minute_occupancy": hi_m * 1440.0,
              "untouched_minute_occupancy": n_m / (dur / 60.0),
              "per_window": [{"experiment": r["experiment"], "window": r["window"], "k": r["k_untouched_minutes"],
                              "n": r["n_untouched_minutes"], "anchored_minutes": r["anchored_minutes_in_window"],
                              "minutes_overlapping_window": r["minutes_overlapping_window"],
                              "minute_row_occupancy_extract": r["minute_row_occupancy_extract"]}
                             for r in per_window],
              "reading": ("an untouched minute holds no touched second; trial density left %d untouched anchored "
                          "minutes in %.2f h of windows, so the minute bound per hour (%.2f at the windows' minute "
                          "occupancy) is wider than the second bound scaled to the windows' sealed occupancy (%.2f)"
                          % (n_m, dur / 3600.0, hi_m * (min_rows_all / min_total) * 60.0,
                             hi * anchored_all / dur * 3600.0))}

    # ------------------------------------------------------------------ the printed sentence
    tex = os.path.join(PAPER, "07_sp_eval.tex")
    INPUTS[rel(tex)] = sha256_file(tex)
    printed = None
    for line in open(tex):
        if "0.83 per wall-clock hour" in line:
            printed = line.strip().split(". ")[0] + "."
    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14c: the deployed configuration's benign bound per untouched sealed one-second segment (0 of 3,972, E7 "
                "and E8), each E7/E8 window's occupancy, and the per-hour and per-day bound implied at those and at a "
                "stated range of occupancies; R3's arithmetic checked; the minute-granularity analogue",
        "answers": ["R3 W2 (r4): 'Report the bound per sealed segment, then scale it at stated deployment occupancies.'"],
        "paper_sentence": {"file": "sections/07_sp_eval.tex", "text": printed},
        "per_segment_bound": {"k": k, "n_untouched_anchored_one_second_segments": n,
                              "k_closure_monitor": k_clo,
                              "exact_interval_two_sided_95": [lo, hi], "one_sided_95_upper": one_sided,
                              "method": "Clopper-Pearson (exp/rig/stats.py), alpha = 0.05; one-sided 1 - 0.05^(1/n)",
                              "total_window_duration_s": dur,
                              "printed_per_wallclock_hour_reproduced": printed_hour,
                              "printed_per_wallclock_day_reproduced": printed_hour * 24.0,
                              "per_untouched_hour_at_full_occupancy": hi * 3600.0,
                              "per_untouched_day_at_full_occupancy": hi * 86400.0},
        "windows": per_window,
        "implied_bound_at_measured_occupancies": occupancies,
        "implied_bound_on_occupancy_grid": grid,
        "r3_arithmetic": r3,
        "minute_analogue": minute,
        "definitions": {
            "per_segment_bound": "95% exact upper bound on the probability that an untouched sealed one-second segment "
                                 "fails verification",
            "sealed_occupancy": "anchored one-second segments in the window (e7_verify window rule, t_start - 1 to t_end "
                                "+ 1) / window duration",
            "row_occupancy": "seconds of [t_start, t_end) holding >= 1 surviving states/events row / duration",
            "untouched_occupancy": "untouched anchored seconds / duration (the printed figure's implicit occupancy)",
            "implied_bound": "per-segment bound x occupancy x 3600 (hour) or x 86400 (day)",
            "caveat": "the trial windows' occupancy includes rows the trials wrote (insertions, forged rows, the "
                      "harness's lock/unlock churn); the trial-free baseline window is the cleanest estimate of a quiet "
                      "home on this installation, the stress window of a busy one",
        },
        "not_read": "E9 files (E9 runs until 2026-10-19)",
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14c_benign_per_segment.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    for c in cons.values():
        c.close()
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, sha256_file(DST))
    print("per-segment", hi, "one-sided", one_sided, "printed/h", printed_hour)
    for o in occupancies:
        print("  %-70s occ %.4f  %.3f/h  %.2f/day" % (o["label"], o["occupancy"], o["per_hour"], o["per_day"]))
    print("minute", k_m, n_m, hi_m, minute["implied_per_hour_at_pooled_minute_occupancy"])


if __name__ == "__main__":
    main()
