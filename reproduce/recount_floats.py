#!/usr/bin/env python3
"""Recount every number the S&P floats print that verify_all.py does not re-derive from the verifier snapshots.

verify_all.py re-verifies the ten real-deployment runs from their recorder snapshots and anchor chains (SP-TAB3 and the
benign floors). This script covers the other floats. For each printed number it does one of three things, and the report
says which:

  recounted   counted again from per-trial or per-row records in the result file (trials[], rows[], per_detection_log[]),
              and compared with the aggregate the file also stores;
  recomputed  derived again from counts: every exact 95% interval (Clopper-Pearson, with this file's own incomplete-beta
              code, not exp/rig/stats.py), every pooled sum and every mean over rows;
  read        taken from an aggregate field because the file keeps no finer records (listed under "read_only").
              A registered parameter a float prints (SP-TAB-HY) is read from its registration and checked
              against the registration's other fields and, where the run has them, its per-trial records.

Every recount and every recomputed interval is compared with the value stored in the result file; any difference makes
the status "mismatch". Result files are opened read-only. The report is a new file; an existing one is never overwritten.

    python3 reproduce/recount_floats.py [--out reproduce/recount_floats_report.json]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "exp", "out")

FLOATS: dict[str, set] = {}
CHECKS: list[dict] = []
READ_ONLY: list[str] = []
SOURCES: dict[str, str] = {}


def load(name, base=OUT):
    p = os.path.join(base, name)
    SOURCES[os.path.relpath(p, REPO)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(p) as fh:
        return json.load(fh)


# ------------------------------------------------------------------ exact intervals (independent implementation)
def _betacf(a, b, x):
    tiny, eps = 1e-300, 3e-16
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 1000):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d; d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c; c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d; d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c; c = c if abs(c) > tiny else tiny
        de = d * c
        h *= de
        if abs(de - 1.0) < eps:
            break
    return h


def betainc(a, b, x):
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lb = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lb) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lb) * _betacf(b, a, 1.0 - x) / b


def beta_ppf(q, a, b):
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if betainc(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def cp(k, n, alpha=0.05):
    lo = 0.0 if k == 0 else beta_ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta_ppf(1 - alpha / 2, k + 1, n - k)
    return lo, hi


# ------------------------------------------------------------------ recording helpers
def num(fid, *vals):
    FLOATS.setdefault(fid, set()).update(str(v) for v in vals)


def bound_strs(x):
    out = {f"{x:.3f}"}
    if x < 0.01:
        out.add(f"{x:.4f}")
    return out


def interval(fid, k, n, stored=None, what=""):
    """Add k, n and the recomputed interval; compare with a stored interval when the file has one."""
    lo, hi = cp(k, n)
    num(fid, k, n, *bound_strs(lo), *bound_strs(hi), 95)   # 95: the confidence level the float states for the interval
    if stored is not None:
        slo, shi = stored
        check(fid, f"interval {what} {k}/{n}", [round(lo, 6), round(hi, 6)], [round(slo, 6), round(shi, 6)],
              abs(lo - slo) < 1e-6 and abs(hi - shi) < 1e-6)
    return lo, hi


def check(fid, what, recount, stored, ok=None):
    ok = (recount == stored) if ok is None else ok
    CHECKS.append({"float": fid, "what": what, "recount": recount, "stored": stored, "ok": bool(ok)})


def read(fid, what):
    READ_ONLY.append(f"{fid}: {what}")


# ------------------------------------------------------------------ SP-TAB2 (laundering and swaps)
def tab2():
    F = "SP-TAB2"
    s1 = load("s1_real_multiconfig.json")
    k = sum(c["misattributed"] for c in s1["configurations"]); n = sum(c["n"] for c in s1["configurations"])
    check(F, "laundering misattributed, summed over configurations", [k, n], [s1["pooled"]["misattributed"], s1["pooled"]["n"]])
    interval(F, k, n, s1["pooled"]["ci95"], "laundering")
    d = load("e_s1_display_check.json")
    before, moved = {"lock": 0, "none": 0}, 0
    for pair, c in d["pairs_before_after"].items():
        b0, a0 = json.loads(pair)
        before["none" if b0 is None else b0[1]] += c
        moved += c if (a0 and a0[0] == "automation") else 0
    check(F, "laundering displayed cause moved (pairs recounted)", moved, d["displayed_cause_moved_to_innocent_automation"])
    num(F, before["lock"], before["none"])
    interval(F, moved, d["n"])
    e5 = load("e5_real_multiconfig.json")["pooled_per_variant"]["principal_swap"]
    read(F, "e5 principal_swap 88/88 (pooled_per_variant; e5 keeps no per-instance rows)")
    interval(F, e5["misattributed"], e5["n"], e5["ci95"], "e5 principal swap")
    ps = load("e_ps_auth_detection.json")
    k = sum(1 for t in ps["trials"] if t["renderer_names_person"]); n = len(ps["trials"])
    check(F, "random-id swap: logbook entry carries the written id (trials recounted)", [k, n],
          [ps["renderer_names_person"]["k"], ps["renderer_names_person"]["n"]])
    interval(F, k, n, (ps["renderer_names_person"]["ci_lo"], ps["renderer_names_person"]["ci_hi"]), "random-id API entry")
    rec = load("e_ps_render_reconciliation.json")["e_ps_rows"]
    read(F, "random-id swap displayed cause before/after (e_ps_render_reconciliation aggregate)")
    num(F, rec["displayed_cause_before"]["('integration', 'lock')"], rec["displayed_cause_before"]["None"])
    interval(F, rec["displayed_cause_changed"], rec["n"])
    psr = load("e_psr_clo_display_check.json")
    read(F, "member-account swap API entry and displayed cause (e_psr_clo_display_check aggregate)")
    interval(F, psr["api_entry_carries_user_id"], psr["n"])
    for v in ("admin", "non_admin"):
        x = psr[v]["displayed_cause_changed"]
        interval(F, x["k"], x["n"], (x["ci_lo"], x["ci_hi"]), f"member-account {v}")


# ------------------------------------------------------------------ SP-TAB3 (pooled rows on top of verify_all)
def tab3():
    F = "SP-TAB3"
    rep = load("verify_all_report.json", base=HERE)
    for rid, r in rep["runs"].items():
        if set(r["arms"]) == {"PU", "PI"}:
            for key in ("flagged", "attributable"):
                if any(r["arms"][a][key] is None for a in ("PU", "PI")):
                    continue             # round 13c: not computable for this run; the table prints no count
                k = sum(r["arms"][a][key] for a in ("PU", "PI")); n = sum(r["arms"][a]["n"] for a in ("PU", "PI"))
                interval(F, k, n)
                amb = [r["arms"][a]["ambiguous"] for a in ("PU", "PI")]
                if None not in amb:      # round 13c: a run whose late-row test is not computable prints no count
                    num(F, sum(amb))


# ------------------------------------------------------------------ SP-TAB4 and SP-TAB-C (forgery classes)
def classes(F, part, n_expected, with_all_ci):
    r9 = load("r9_e_scheme_detection_n60.json")
    log = r9[part]["per_detection_log"]
    schemes = ("b2", "row", "homeprov2", "b2c")
    cnt = {}
    for e in log:
        c = cnt.setdefault(e["ft"], {s: [0, 0] for s in schemes})
        for s in schemes:
            c[s][0] += bool(e[s]); c[s][1] += 1
    for ft, c in sorted(cnt.items()):
        for s in schemes:
            k, n = c[s]
            check(F, f"{ft} {s}: n per class", n, n_expected)
            if with_all_ci or ft in ("FT-U", "FT-E"):
                interval(F, k, n)
            else:
                num(F, k, n)
    return cnt


def tab4():
    F = "SP-TAB4"
    cnt = classes(F, "extend_new_seeds", 60, with_all_ci=False)
    r9 = load("r9_e_scheme_detection_n60.json")
    for ft, row in r9["table_new_60"].items():
        for s in ("b2", "row", "homeprov2", "b2c"):
            check(F, f"{ft} {s} recount vs table_new_60", cnt[ft][s], [row[s]["k"], row[s]["n"]])


def tab_appc():
    F = "SP-TAB-C"
    cnt = classes(F, "reproduce_original_seeds", 12, with_all_ci=False)
    s31 = load("stage31_hp2.json")
    for ft, row in {**s31["per_ft"], **s31["post_predeclaration"]}.items():
        for s in ("b2", "row", "homeprov2", "b2c"):
            st = row[s]
            stored = [st["k"], st["n"]] if isinstance(st, dict) else st
            check(F, f"{ft} {s} recount (r9 reproduction of the stage31 seeds) vs stage31_hp2", cnt[ft][s], stored)


# Round 13d (E8 part B): Table 9's real-copy column, for each of the fourteen closure fields the mutations of that column
# on a copy of the real deployment's recorder that changed the rendered logbook (any of the three rendered forms),
# recounted from the per-mutation records and checked against the per-field aggregate; with the commitment misses.
TAB_C_FIELDS = ["states.context_id_bin", "states.context_parent_id_bin", "states.context_user_id_bin", "states.state",
                "states.metadata_id", "states.old_state_id", "states.last_updated_ts", "states.last_changed_ts",
                "events.context_id_bin", "events.context_parent_id_bin", "events.context_user_id_bin",
                "events.event_type_id", "events.data_id", "events.time_fired_ts"]


def tab_appc_real():
    F = "SP-TAB-C"
    if not os.path.exists(os.path.join(OUT, "e8_closure_real.json")):
        return
    d = load("e8_closure_real.json")
    cnt, missed = {}, {"closure": 0, "stable": 0, "row": 0}
    for m in d["mutations"]:
        ch = any(v.get("changed") for v in m["render"].values())
        c = cnt.setdefault(m["field"], [0, 0])
        c[0] += ch
        c[1] += 1
        if ch:
            for sch in missed:
                missed[sch] += not m["commit_changed"][sch]
    for f in TAB_C_FIELDS:
        pf = d["per_field"][f]
        check(F, f"{f}: render changed / mutations (records counted) vs per_field", cnt[f], [pf["render_changed"], pf["mutations"]])
        num(F, cnt[f][0], cnt[f][1], f"{cnt[f][0]}/{cnt[f][1]}")
    check(F, "render changes not detected per scheme (records counted) vs summary", missed,
          d["summary"]["comparison"]["render_changes_not_detected"])
    check(F, "mutations that changed the render (records counted) vs summary",
          sum(c[0] for c in cnt.values()), d["summary"]["mutations_render_changed"])


# Round 13d (E8): Figure 5 plots E8 by arm. For each monitor (stable columns, closure) and window (main, stress), the
# trials, detections with coverage and the earlier rule's attributable verdicts per arm, recounted from the verifier's
# per-trial records and checked against the per-arm counts the verify file and e8_main_score.json store.
def fig3_detect_e8():
    F = "SP-FIG3"
    if not os.path.exists(os.path.join(OUT, "e8_main_score.json")):
        return
    sc = load("e8_main_score.json")
    for scheme in ("stable", "closure"):
        for window in ("main", "stress"):
            v = load(f"e8_main_{scheme}_verify_{window}.json")
            c = {}
            for t in v["trials"]:
                x = c.setdefault(t["arm"], [0, 0, 0])
                x[0] += 1
                x[1] += bool(t["detected"])
                x[2] += bool(t["existing_rule"]["attributable"])
            stored = sc["monitors"][scheme]["by_window"][window]["arms"]
            for arm, x in sorted(c.items()):
                check(F, f"E8 {scheme} {window} {arm}: trials, detected, earlier-rule attributable (trials counted) vs verify file",
                      x, [v["arms"][arm]["n"], v["arms"][arm]["e7_detected"], v["arms"][arm]["existing_attributable"]])
                check(F, f"E8 {scheme} {window} {arm}: same vs e8_main_score.json", x,
                      [stored[arm]["n"], stored[arm]["e7_detected"], stored[arm]["existing_attributable"]])
                num(F, *x, f"{x[1]}/{x[0]}", f"{x[2]}/{x[0]}")
    num(F, "0", "0.5", "1")


# Round 17a (the r6 revision): the rows of E8's arms and windows the floats print, in their printed order (make_floats'
# E8_ROWS): the seven arms of the main window, then the stress window's laundering arm.
E8_ROWS = (("main", "PU"), ("main", "PI"), ("main", "PSR"), ("main", "P"), ("main", "INS-L"), ("main", "INS-M"),
           ("main", "BD-S"), ("stress", "PU"))


def _e8_counts(scheme, window):
    """Per arm [trials, detected with coverage, earlier rule attributable, earlier rule ambiguous], counted from the
    verifier's per-trial records of one monitor and window."""
    v = load(f"e8_main_{scheme}_verify_{window}.json")
    c = {}
    for t in v["trials"]:
        x = c.setdefault(t["arm"], [0, 0, 0, 0])
        x[0] += 1
        x[1] += bool(t["detected"])
        x[2] += bool(t["existing_rule"]["attributable"])
        x[3] += bool(t["existing_rule"]["ambiguous"])
    return c


# Round 17a (the r6 revision): Table tab:e8arms (SP-TAB-E8) holds the eight detection rows Table tab:deployed printed
# before: per arm the trials, the detections of both monitors with coverage, and the earlier rule's attributable and
# ambiguous trials on the stable-columns chain. Every cell is counted from the per-trial records (the ambiguous count
# too, which round 14 read from the per-arm aggregate) and checked against the verify file's per-arm counts and
# e8_main_score.json.
def tab_e8arms():
    F = "SP-TAB-E8"
    if not os.path.exists(os.path.join(OUT, "e8_main_score.json")):
        return
    sc = load("e8_main_score.json")
    for window, arm in E8_ROWS:
        s_, c_ = _e8_counts("stable", window)[arm], _e8_counts("closure", window)[arm]
        vs = load(f"e8_main_stable_verify_{window}.json")["arms"][arm]
        vc = load(f"e8_main_closure_verify_{window}.json")["arms"][arm]
        ss = sc["monitors"]["stable"]["by_window"][window]["arms"][arm]
        cs = sc["monitors"]["closure"]["by_window"][window]["arms"][arm]
        check(F, f"E8 stable {window} {arm}: trials, detected, earlier-rule attributable and ambiguous (trials counted) "
                 "vs verify file", s_, [vs["n"], vs["e7_detected"], vs["existing_attributable"], vs["existing_ambiguous"]])
        check(F, f"E8 stable {window} {arm}: same vs e8_main_score.json", s_,
              [ss["n"], ss["e7_detected"], ss["existing_attributable"], ss["existing_ambiguous"]])
        check(F, f"E8 closure {window} {arm}: trials and detected (trials counted) vs verify file and score", c_[:2],
              [vc["n"], vc["e7_detected"]], c_[:2] == [vc["n"], vc["e7_detected"]] == [cs["n"], cs["e7_detected"]])
        check(F, f"E8 {window} {arm}: the same trials under both monitors", s_[0], c_[0])
        num(F, s_[0], s_[1], c_[1], s_[2], s_[3])


# Round 17a (the r6 revision, R3 W1): Table tab:hyp (SP-TAB-HY) lists every registered hypothesis; the two numbers it
# prints are E10's. 30: H1's backdating boundary ("d <= 30 s"), a registered prediction, read from the registration and
# checked against the registered late bound L and the registered age grid. 45: H2's insertion delay at which the
# inserted event is attributable ("detected only at 45 s"), checked against the registered delay grid and recounted
# from E10's per-trial records of arm A2-CTX (both monitors): the only delay with a detected trial, every trial there
# detected.
def tab_hyp():
    F = "SP-TAB-HY"
    if not os.path.exists(os.path.join(OUT, "e10_preregistration.json")):
        return
    reg = load("e10_preregistration.json")
    hy, arms = reg["hypotheses"], {a["id"]: a for a in reg["arms"] if isinstance(a, dict)}
    grid = lambda arm, word: [float(x) for x in re.search(word + r" ([\d, ]+) s", arms[arm]["n"]).group(1).split(",")]
    m1 = re.search(r"d <= (\d+) s into a sealed second is never attributable", hy["H1_backdating_boundary"])
    b = float(m1.group(1))
    ages = grid("A1-BDT", "ages")
    check(F, "E10 H1: the boundary the hypothesis registers = the registered late bound (parameters.late_bound_s) = "
             "the largest registered age at or below it", [b, b], [reg["parameters"]["late_bound_s"],
                                                                   max(x for x in ages if x <= reg["parameters"]["late_bound_s"])])
    read(F, "E10 H1: the boundary 30 s (registration: hypotheses.H1_backdating_boundary, parameters.late_bound_s; a "
            "registered prediction, not a count)")
    num(F, m1.group(1))
    m2 = re.search(r"at (\d+) s it is attributable", hy["H2_insertion_only_reattribution"])
    delays = grid("A2-CTX", "delays")
    ctx = load("e10_main_score.json")["arms"]["CTX"]
    cnt = {}
    for t in ctx["per_trial"]:
        for mon in ("direct", "copy"):
            x = cnt.setdefault((float(t["level"]), mon), [0, 0])
            x[0] += t[mon]["outcome"] == "detected"
            x[1] += 1
    for (lev, mon), x in sorted(cnt.items()):
        d = ctx["per_level"][f"{lev:.1f}"][mon]["detected"]
        check(F, f"E10 A2-CTX {mon} delay {lev:g} s: detected / trials (trials counted) vs per_level", x, [d["k"], d["n"]])
    det = sorted({lev for (lev, _m), x in cnt.items() if x[0]})
    full = sorted({lev for (lev, _m), x in cnt.items() if x[0] == x[1]})
    check(F, "E10 A2-CTX: the delays at which an inserted event was detected, and those at which every trial was "
             "(trials counted, both monitors) = H2's registered delay, one of the registered delays",
          [det, full, sorted({lev for lev, _m in cnt}) == sorted(delays)], [[float(m2.group(1))]] * 2 + [True])
    num(F, m2.group(1))


# Round 14: the deployed-configuration table (SP-TAB8) replaces Figure 5. Detection per arm and monitor as in
# fig3_detect_e8 (recounted from per-trial records); the earlier rule's ambiguous count and the benign floors per window
# read from the verify files and checked against e8_main_score.json; each floor's exact interval recomputed here; the
# stress window's write rate (its row label) recomputed from the scorer's row and minute counts.
def tab_deployed():
    F = "SP-TAB8"
    if not os.path.exists(os.path.join(OUT, "e8_main_score.json")):
        return
    sc = load("e8_main_score.json")
    for scheme in ("stable", "closure"):
        for window in ("main", "stress"):
            v = load(f"e8_main_{scheme}_verify_{window}.json")
            c = {}
            for t in v["trials"]:
                x = c.setdefault(t["arm"], [0, 0, 0])
                x[0] += 1
                x[1] += bool(t["detected"])
                x[2] += bool(t["existing_rule"]["attributable"])
            stored = sc["monitors"][scheme]["by_window"][window]["arms"]
            for arm, x in sorted(c.items()):
                check(F, f"E8 {scheme} {window} {arm}: trials, detected, earlier-rule attributable (trials counted) vs score",
                      x, [stored[arm]["n"], stored[arm]["e7_detected"], stored[arm]["existing_attributable"]])
                num(F, *x)
                if scheme == "stable":
                    check(F, f"E8 stable {window} {arm}: earlier-rule ambiguous, verify file vs score",
                          v["arms"][arm]["existing_ambiguous"], stored[arm]["existing_ambiguous"])
                    read(F, f"E8 stable {window} {arm}: earlier-rule ambiguous (per-arm aggregate)")
                    num(F, stored[arm]["existing_ambiguous"])
    # Round 17a (the r6 revision): the detection part is one line, every trial of the seven arms and of the stress
    # window's arm (per arm: Table tab:e8arms, SP-TAB-E8 below): its trials and both monitors' detections, summed over
    # E8_ROWS from the per-trial records and checked against the per-arm counts e8_main_score.json stores.
    c = {s: {w: _e8_counts(s, w) for w in ("main", "stress")} for s in ("stable", "closure")}
    tot = {s: [sum(c[s][w][a][i] for w, a in E8_ROWS) for i in (0, 1)] for s in c}
    st = {s: [sum(sc["monitors"][s]["by_window"][w]["arms"][a][k] for w, a in E8_ROWS) for k in ("n", "e7_detected")]
          for s in c}
    for s in c:
        check(F, f"E8 one line, {s}: trials and detections summed over the seven arms and stress (trials counted) "
                 "vs the score's per-arm counts summed", tot[s], st[s])
    check(F, "E8 one line: trials = stable-columns detections = closure detections (as printed)",
          [tot["stable"][0], tot["stable"][1], tot["closure"][1]], [tot["closure"][0]] * 3)
    num(F, tot["stable"][0], tot["stable"][1], tot["closure"][1])
    for window in ("main", "base", "stress"):
        for scheme in ("stable", "closure"):
            bf = load(f"e8_main_{scheme}_verify_{window}.json")["benign_floor"]
            st = sc["monitors"][scheme]["by_window"][window]["benign_floor"]
            check(F, f"E8 {scheme} {window}: untouched seconds and violations, verify file vs score",
                  [bf["untouched_anchored_seconds"], bf["violated"]], [st["untouched_anchored_seconds"], st["violated"]])
            read(F, f"E8 {scheme} {window}: benign floor (verifier aggregate)")
            lo, hi = interval(F, st["violated"], st["untouched_anchored_seconds"])
            check(F, f"E8 {scheme} {window} floor: exact interval as printed (3 decimals) vs score",
                  [f"{lo:.3f}", f"{hi:.3f}"], [f"{st['violated_ci'][0]:.3f}", f"{st['violated_ci'][1]:.3f}"])
            num(F, f"{st['untouched_anchored_seconds']:,}")
    # The stress window's write rate in its row label: rows (state + event) over the window's minutes, recomputed.
    wr = sc["write_rate"]["stress"]
    check(F, "E8 stress write rate: state + event rows, rows / minutes (2 decimals) vs score",
          [wr["state_rows"] + wr["event_rows"], round(wr["rows"] / wr["minutes"], 2)], [wr["rows"], wr["rows_per_minute"]])
    read(F, "E8 stress write rate: the window's rows and minutes (scorer aggregate)")
    num(F, f"{wr['rows'] / wr['minutes']:.2f}")


# ------------------------------------------------------------------ SP-TAB5 and SP-TAB-B (benign floors)
def floors():
    rep = load("verify_all_report.json", base=HERE)
    per = {rid: r["benign_floor_second"] for rid, r in rep["runs"].items() if r["scheme"] != "wholerow"}
    per.update(rep["not_rerun_read_from_file"])
    return per, rep["pooled_floor_nine_runs"]


def tab5():
    F = "SP-TAB5"
    s10 = load("stage10_raw.json")
    read(F, "generated-deployment benign trials (stage10_raw aggregates; no per-trial rows)")
    for key in ("raw_false_alarm_without_markers", "b2_false_alarm", "post_marker_false_alarm"):
        x = s10[key]
        interval(F, x["k"], x["n"], (x["ci_lo"], x["ci_hi"]), key)
    for ev in s10["per_benign_event"].values():
        num(F, ev["raw_detected"], ev["n"])
    quiet = [v for v in s10["per_benign_event"].values() if not v["marker_used_by_stage10"]]
    num(F, len(quiet))
    per, pooled = floors()
    check(F, "nine-run pool = sum of per-run floors", pooled, [sum(v[0] for v in per.values()), sum(v[1] for v in per.values())])
    interval(F, *pooled)


RESCORE = {"e_c_write_time": "e_c_write_time", "e_d_other_principal_real": "e_d_other_principal_real",
           "e_d_auth": "e_d_auth", "e_c_auth": "e_c_auth", "e_ps_auth": "e_ps_auth", "e_ps_clo": "e_ps_clo",
           "e_d_clo": "e_d_clo", "e_c_clo": "e_c_clo", "e_psr_clo": "e_psr_clo"}
CONF = {"e_d_auth": "e_d_auth_config.json", "e_c_auth": "e_c_auth_config.json", "e_ps_auth": "e_ps_auth_config.json",
        "e_ps_clo": "e_ps_clo_config.json", "e_d_clo": "e_d_clo_config.json", "e_c_clo": "e_c_clo_config.json",
        "e_psr_clo": "e_psr_clo_config.json"}


def tab_appb():
    F = "SP-TAB-B"
    per, pooled = floors()
    for rid, (k, n) in per.items():
        rs = load(RESCORE[rid] + "_floor_rescore.json")
        check(F, f"{rid}: snapshot floor vs re-score file", [k, n],
              [rs["new_rule_floor"]["second"]["k"], rs["new_rule_floor"]["second"]["n"]])
        interval(F, k, n)
        m = rs["new_rule_floor"]["minute"]
        read(F, f"{rid}: minute floor (floor re-score file)")
        num(F, m["k"], m["n"])
        if rid in CONF:
            read(F, f"{rid}: host load at start/end (configuration log)")
            lines = load(CONF[rid])["configuration_log"]
            for key in ("load_before", "load_after"):
                v = next(re.search(r"load averages: ([\d.]+)", l).group(1) for l in lines if key in l)
                num(F, v)
    interval(F, *pooled)


# ------------------------------------------------------------------ SP-TAB-A (write-time strategies)
def tab_appa():
    F = "SP-TAB-A"
    for f, lr in (("e_c_write_time.json", None), ("e_c_auth_other_principal_real.json", "e_c_auth_late_row_check.json"),
                  ("e_c_clo_other_principal_real.json", "e_c_clo_late_row_check.json")):
        d = load(f)
        late = load(lr)["per_arm"] if lr else None
        for a, v in d["arms"].items():
            n_tr = sum(1 for t in d["trials"] if t["arm"] == a)
            rc = v.get("renderer_confirmed_misattribution")
            if rc:
                check(F, f"{f} {a}: trials in arm", n_tr, rc["n"])
                interval(F, rc["k"], rc["n"], (rc["ci_lo"], rc["ci_hi"]) if "ci_lo" in rc else None, f"{f} {a} misattributed")
            for g in ("homeprov_detection_second", "homeprov_detection_minute"):
                s = v[g]
                interval(F, s["k"], s["n"], (s["ci_lo"], s["ci_hi"]), f"{f} {a} {g}")
            if late:
                interval(F, late[a]["attributable"], late[a]["n_valid"])
                num(F, late[a]["late_row"])
        read(F, f"{f}: per-arm misattribution and detection counts (arms aggregate; detection needs the verifier)")


# ------------------------------------------------------------------ SP-TAB-D (localization)
def tab_appd():
    F = "SP-TAB-D"
    e13 = load("stage25_final.json")["E13_exhaustive"]
    read(F, "stage25 exhaustive enumeration counts")
    num(F, e13["instances"], e13["sound"], len(e13["proper_subset_sound"]))
    for name, base in (("stage24_final.json", OUT), ("stage24_recon_baselines.json", os.path.join(REPO, "exp", "out_recal"))):
        d = load(name, base=base)
        rows = d["rows"]
        for pol in ("R5_homeprov", "R4_component", "R2_segments"):
            oq = sum(r[pol]["OQ"] for r in rows) / len(rows)
            q = sum(r[pol]["Q"] for r in rows) / len(rows)
            check(F, f"{name} {pol}: mean OQ over {len(rows)} rows", round(oq, 12), round(d["summary"][pol]["mean_OQ"], 12))
            check(F, f"{name} {pol}: mean Q over {len(rows)} rows", round(q, 9), round(d["summary"][pol]["mean_Q"], 9))
            num(F, f"{oq:.5f}", f"{q:.1f}", f"{q:.2f}")
        num(F, len(rows))


def tab6_real():
    _localize("SP-TAB6")   # round 4: the real-deployment localization rows moved from Appendix D to Table 6


def fig4_localize():
    _localize("SP-FIG4")   # round 5 (O-002@4): Table 6 becomes Figure 4, the same rows plotted by arm


def _localize(F):
    r2 = load("r2_localization_summary.json")
    rows = [x for x in r2["rows"] if x.get("arm") and x["scheme"] == "closure" and x.get("admitted")]
    k = sum(x["R5_sound"][0] for x in rows); n = sum(x["R5_sound"][1] for x in rows)
    p = r2["pooled_R5_soundness_admitted_runs"]["closure/all_post_commit_arms"]
    check(F, "R2 pooled closure soundness (rows summed)", [k, n], [p["k"], p["n"]])
    interval(F, k, n, (p["ci_lo"], p["ci_hi"]), "R2 pooled")
    k2 = sum(x["R5_sound_anchor_resolved"][0] for x in rows)
    p2 = r2["pooled_R5_soundness_anchor_resolved_admitted_runs"]["closure/all_post_commit_arms"]
    check(F, "R2 pooled anchor-resolved soundness (rows summed)", [k2, n], [p2["k"], p2["n"]])
    interval(F, k2, n, (p2["ci_lo"], p2["ci_hi"]), "R2 anchor-resolved")
    read(F, "R2 per-arm per-trial over-quarantine means (r2_localization_summary rows; per-trial OQ is not stored)")
    for x in rows:
        interval(F, x["R5_sound"][0], x["R5_sound"][1], x["R5_ci95"], f"R2 {x['run_id']} {x['arm']}")
        oq = x["per_trial_OQ_mean"]
        v4 = oq["R4_component"]
        d4 = max(0, 2 - int(math.floor(math.log10(abs(v4))))) if v4 else 0
        num(F, f"{oq['R5_homeprov']:.6f}", f"{v4:.{d4}f}")



# ------------------------------------------------------------------ SP-FIG3 (detection by arm, round 5)
def fig3_detect():
    """Every k/n that Figure 3 plots, recounted from verify_all's re-verification where it covers the arm, and compared
    with the late-row or rescored result file that make_floats.py reads; the write-time arms are read from the late-row
    files (verify_all does not re-run them) and checked for internal consistency."""
    F = "SP-FIG3"
    runs = load("verify_all_report.json", base=HERE)["runs"]

    def va(run, arms):
        return [sum(runs[run]["arms"][a]["attributable"] for a in arms), sum(runs[run]["arms"][a]["n"] for a in arms)]

    dlr = load("e_d_clo_late_row_check.json")["per_arm"]
    clr = load("e_c_clo_late_row_check.json")["per_arm"]
    calr = load("e_c_auth_late_row_check.json")["per_arm"]
    resc = load("e_ps_detection_rescored.json")["runs"]
    psr = load("e_psr_clo_detection.json")["homeprov_detection_second"]
    pairs = [
        ("other-principal laundering, closure", va("e_d_clo", ("PU", "PI")),
         [sum(dlr[a]["attributable"] for a in ("PU", "PI")), sum(dlr[a]["n_valid"] for a in ("PU", "PI"))]),
        ("own-actuation laundering, closure", va("e_c_clo", ("P",)), [clr["P"]["attributable"], clr["P"]["n_valid"]]),
        ("own-actuation laundering, row scheme", va("e_c_auth", ("P",)), [calr["P"]["attributable"], calr["P"]["n_valid"]]),
        ("random-id swap, closure", va("e_ps_clo", ("PS",)), [resc["e_ps_clo_detection.json"]["second"]["attributable_to_swap"], 90]),
        ("random-id swap, row scheme", va("e_ps_auth", ("PS",)), [resc["e_ps_auth_detection.json"]["second"]["attributable_to_swap"], 90]),
        ("member-account swap, closure", va("e_psr_clo", ("PSR",)), [psr["hits_consistent_with_detection"], psr["n"]]),
    ]
    for what, recount, stored in pairs:
        check(F, f"{what}: attributable (verify_all re-verification vs the file the figure reads)", recount, stored)
        interval(F, *recount)
    for scheme, lr in (("closure", clr), ("row scheme", calr)):
        for a in ("W1", "W2b", "W3"):
            x = lr[a]
            check(F, f"write time {a}, {scheme}: attributable = flagged - late rows, late rows listed",
                  [x["flagged"] - x["late_row"], len(x["late_detail"])], [x["attributable"], x["late_row"]])
            read(F, f"write time {a}, {scheme}: per-arm aggregate of the late-row file (verify_all does not re-run it)")
            interval(F, x["attributable"], x["n_valid"])


# ------------------------------------------------------------------ SP-TAB-E (marker abuse)
def tab_appe():
    F = "SP-TAB-E"
    d = load("stage29_final.json")
    rows = d["rows"]
    check(F, "cases (rows counted)", len(rows), d["n_cases"])
    esc = [r for r in rows if r["escaped"]]
    check(F, "escaped (rows counted)", len(esc), d["n_escaped"])
    check(F, "vacuous (rows counted)", sum(1 for r in rows if r["VACUOUS"]), d["n_vacuous"])
    num(F, len(rows), len(esc), d["n_vacuous"])
    cases = {}
    for r in rows:
        c = cases.setdefault(r["case"], [0, 0, 0])
        c[0] += bool(r["detected_after_marker"]); c[1] += bool(r["escaped"]); c[2] += bool(r["VACUOUS"])
    for c in cases.values():
        num(F, *c)
    # "All cases" row, Detected column (Table 11): the per-case Detected cells summed, recounted from the rows and
    # checked against the file's stored aggregates (every case-instance is detected, escaped or vacuous).
    det = sum(1 for r in rows if r["detected_after_marker"])
    check(F, "All cases Detected: sum of the per-case Detected column = rows detected after the marker",
          sum(c[0] for c in cases.values()), det)
    check(F, "All cases Detected = cases - escaped - vacuous (stored n_cases, n_escaped, n_vacuous)",
          det, d["n_cases"] - d["n_escaped"] - d["n_vacuous"])
    check(F, "every case-instance is exactly one of detected, escaped, vacuous",
          sum(1 for r in rows if [bool(r["detected_after_marker"]), bool(r["escaped"]), bool(r["VACUOUS"])].count(True) == 1),
          len(rows))
    num(F, det, f"{det} of {len(rows)}", f"{d['n_vacuous']} of {len(rows)}")
    if esc:
        hs = [r["history_sacrificed"] for r in esc]
        num(F, f"{min(hs):.3f}", f"{max(hs):.3f}")
    # Round 12 (E2): the escaping case scored under a retention-scoped marker (window 0.75 of the history), recounted
    # from the per-case rows of e2_scoped_markers_generated.json and checked against the summary the file stores.
    if os.path.exists(os.path.join(OUT, "e2_scoped_markers_generated.json")):
        e2 = load("e2_scoped_markers_generated.json")
        rs = [r for r in e2["rows"] if r["case"] == "hidden" and r["keep_fraction"] == 0.75 and not r["VACUOUS"]]
        det = sum(1 for r in rs if r["scoped_detected"])
        st = e2["summary"]["hidden@0.75"]["scoped_detected"]
        check(F, "E2 scoped row: detected (rows counted) = stored summary", [det, len(rs)], [st["k"], st["n"]])
        hs = [r["history_sacrificed"] for r in rs]
        num(F, det, len(rs) - det, "0.75", f"{min(hs):.3f}", f"{max(hs):.3f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(HERE, "recount_floats_report.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit(f"refusing to overwrite {a.out}; pass --out for a new file")
    for fn in (tab2, tab3, tab4, tab_appc, tab_appc_real, tab5, tab_appb, tab_appa, tab_appd, tab6_real, fig3_detect,
               fig3_detect_e8, tab_deployed, fig4_localize, tab_appe, tab_e8arms, tab_hyp):
        fn()
    bad = [c for c in CHECKS if not c["ok"]]
    report = {"status": "ok" if not bad else "mismatch",
              "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "script_sha256": hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest(),
              "python": sys.version.split()[0],
              "checks_total": len(CHECKS), "checks_failed": bad,
              "floats": {k: sorted(v) for k, v in sorted(FLOATS.items())},
              "read_only": READ_ONLY, "sources_sha256": SOURCES,
              "checks": CHECKS}
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"status {report['status']}: {len(CHECKS)} checks, {len(bad)} failed; floats {sorted(FLOATS)}; report {a.out}")
    for c in bad[:20]:
        print("  MISMATCH", c)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
