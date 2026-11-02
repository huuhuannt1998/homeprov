#!/usr/bin/env python3
"""R14 (S&P 2027 round 14, 2026-10-12): which printed outcomes follow by construction and which are measured.

Answers internal review r3, R3 W3: "Given (A3) and the field list, any rewrite of a covered field after sealing changes
the root. So '90 of 90 trials [0.960, 1.000]' tests the harness under one workload. It does not bound adaptive evasion.
Section 7.1 says results that follow by construction 'carry no interval', yet these carry one." Fix asked for: "a rule-level
argument (coverage, keylog, late bound, markers) listing exactly when evasion is possible, and present the trials as
regression tests."

WHAT IT READS (read-only): the manuscript's current printed sentences of the abstract and Section 7 through the authoring
graph's source map (sections/wk_sourcemap.yaml -> 10-realizations text, 07-intents evidence uses, 03-evidence numbers
with the result file and the sha256 each number was licensed from), the generated Section 7 file (to check that each
sentence is printed verbatim), the generated float files (captions), the result files those numbers cite (sha256 only,
to say whether the licensed file is still the current one), and a few result files whose counts it re-reads directly
(listed under counts_reread). It writes no manuscript file.

CLASSIFICATION (the script's own table CLASS below, keyed by sentence intent id; one entry per printed outcome):
  by construction (regression test)   the outcome is implied by (A3), the committed field list and a rule of the
                                      design, given the trial's preconditions (the edit happens after the row's segment
                                      is sealed; the segment's record is anchored and verifies); the trials exercise the
                                      implementation and the harness, so a k-of-n interval on them bounds an
                                      implementation failure rate under that harness and workload, not adaptive evasion;
  by construction (negative)          a scheme whose field list omits the rewritten field detects 0 by construction;
  by construction (rule design)       the outcome restates what a rule does (the earlier rule, markers, fail-closed);
  by construction given a measured input  derived from a measured set by field-list arithmetic;
  logical consequence                 follows from the definition of the guarantee;
  exact enumeration                   an exhaustive check of a finite instance set (no sampling);
  measured                            depends on platform behavior, timing, load, workload or the renderer: benign floor,
                                      observation window, cost, localization size, misattribution, renderer behavior;
  demonstration (measured)            an attack's effect shown once;
  context                             setup or definition, no outcome.
A sentence that prints an exact interval on an outcome classified "by construction" is listed under
interval_on_by_construction (the inconsistency R3 W3 names, against the paper's own sentence SI-S112-01).

    python3 exp/sp2027/r14_by_construction.py   -> exp/out/r14_by_construction.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import datetime
import hashlib
import json
import os
import re

import yaml

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
PAPER = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13")
W = os.path.join(PAPER, "authoring", "writer")
DRY = os.environ.get("R14_DRYRUN_DIR")
DST = os.path.join(DRY or OUT, "r14_by_construction.json")
INPUTS = {}
_SHA = {}


def rel(p):
    return os.path.relpath(os.path.abspath(p), REPO)


def sha256_file(p):
    p = os.path.abspath(p)
    if p not in _SHA:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        _SHA[p] = h.hexdigest()
    return _SHA[p]


def read_text(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def read_yaml(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def read_json(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def artifact(kind, ref):
    i, v = ref.split("@")
    return read_yaml(os.path.join(W, kind, "%s@v%s.yaml" % (i, v)))


BC = "by construction (regression test)"
BCN = "by construction (negative)"
BCD = "by construction (rule design)"
MIX = "by construction given a measured input"
LOG = "logical consequence"
EX = "exact enumeration"
M = "measured"
D = "demonstration (measured)"
C = "context"

A3F = "(A3) and the committed field list"
# intent id (without version) -> list of (outcome, category, basis, what is measured / what the trials test)
CLASS = {
    # ---------------------------------------------------------------- abstract
    "SI-S002-01": [("framing", C, "", "")],
    "SI-S002-02": [("threat statement", C, "", "laundering's display effect is measured in Section 7 (current releases)")],
    "SI-S002-08": [("scope", C, "", "")],
    "SI-S002-03": [("renderer closure is measured", M, "", "the closure (fields the renderer reads) is measured by "
                    "mutation on a real recorder copy")],
    "SI-S002-12": [("design summary", C, "", "")],
    "SI-S002-04": [("90 of 90 in each of seven arms", BC, A3F + " + coverage, keylog and late-bound rules",
                    "trials test the implementation and harness under one workload; preconditions: edits >= 130 s after "
                    "the row was written, backdating 129.8-243.0 s > LATE_BOUND 30 s"),
                   ("no untouched one-second segment failed (also at 176.81 rows per minute)", M, "",
                    "benign floor under coverage, three windows of one run")],
    "SI-S002-09": [("arm description", C, "", "")],
    "SI-S002-10": [("Domoticz 30 of 30 per attack", BC, A3F + " (the closure scheme commits LightingLog.User)",
                    "regression test on a second hub; the renderer closure there (11 fields) is measured")],
    "SI-S002-05": [("guarantee statement (locked)", C, "", "")],
    "SI-S002-11": [("write-time forgery outside the guarantee", BCN, "no earlier committed version exists",
                    "Section 7 measures the misattribution such forgeries reach (renderer)")],
    # ---------------------------------------------------------------- 7.1 setup
    "SI-S042-01": [("substrate split", C, "", "")],
    "SI-S043-03": [("counting unit and interval method", C, "", "")],
    "SI-S043-04": [("definition of untouched segment and benign floor", C, "", "")],
    "SI-S043-10": [("lab write rate and commit interval", M, "", "write rate 122.5 rows/min, 34.9% of seconds")],
    "SI-S112-01": [("by-construction results carry no interval (framing)", C, "",
                    "contradicted by sentences listed under interval_on_by_construction")],
    # ---------------------------------------------------------------- what to commit
    "SI-S047-01": [("design of the forgery-class comparison", C, "", "")],
    "SI-S047-02": [("row and graph schemes detect every predeclared class 60/60", BC, A3F,
                    "each predeclared class rewrites a field these schemes commit; regression test on generated "
                    "deployments (the content-only scheme's 57/60 on FT-6 is measured)")],
    "SI-S047-03": [("closure 60/60 on FT-U/FT-E, every other scheme 0/60", BCN, A3F + " (stated: 'as the field lists imply')",
                    "regression test")],
    "SI-S047-04": [("schemes separate by fields committed", BC, A3F, "summary of the two sentences above")],
    "SI-S048-02": [("3 of 3 omitted fields: closure root changes, row root unchanged", BCN, A3F, "one copy, one write per field")],
    "SI-S049-01": [("whole-row scheme flagged every edit", BC, A3F + " (whole-row commits every column)", "regression test")],
    "SI-S049-02": [("whole-row benign failures 203/281, 432/552, 218/300", M, "mechanism by construction: the recorder "
                    "rewrites last_reported_ts in place after sealing", "rate of in-place rewrites on the deployment")],
    "SI-S049-03": [("791 of 853 reproduced by restoring last_reported_ts", M, "", "offline reconstruction")],
    "SI-S049-04": [("stable-columns bound 2 to 62 of 1,133 without coverage", M, "", "derived bound from the reconstruction")],
    "SI-S050-02": [("646 of 1,744 mutations changed the output (27 columns)", M, "", "renderer closure on a real copy")],
    "SI-S050-07": [("all fourteen closure fields among them", M, "", "renderer closure")],
    "SI-S050-06": [("stable 0 missed, row 227, closure 91", MIX, "field-list subtraction over the measured mutation set "
                    "(stable columns omit only last_reported_ts, whose 57 mutations changed no output)", "the mutation set")],
    "SI-S050-03": [("12 fields flagged on 2026.9.4 and 2026.10.0b2", M, "", "per-field mutation on fresh stacks")],
    "SI-S050-04": [("flagged sets differ by release and role", M, "", "")],
    # ---------------------------------------------------------------- where the commitment runs
    "SI-S051-01": [("blinding setup", C, "", "")],
    "SI-S051-02": [("in-process defender saw 133,087 of 133,088 rows", D, "the rebinding filters the adversary's row",
                    "one run")],
    "SI-S051-03": [("external monitor sealed the adversary's second", BC, "placement: a rebinding in the hub process "
                    "cannot reach the monitor's container (A1)", "two runs")],
    "SI-S051-07": [("first anchored root matches the recompute", D, "", "one run")],
    "SI-S051-05": [("earlier demo hub: 475 of 477 rows", D, "", "one run")],
    # ---------------------------------------------------------------- the append path
    "SI-S052-07": [("unauthenticated anchor accepts adversary appends; preemption", BC, "first write wins without a key",
                    "client test")],
    "SI-S052-02": [("authenticated path refuses untagged/forged, accepts monitor", BC, "(A2) and HMAC-SHA256",
                    "client test (regression)")],
    "SI-S052-04": [("overhead 1.00017, storage 1.005x", M, "", "one measurement, earlier encoding")],
    "SI-S052-10": [("copy/load/commit times on the 186 MB recorder", M, "", "cost")],
    # ---------------------------------------------------------------- benign operations
    "SI-S055-01": [("benign-trial design", C, "", "")],
    "SI-S055-02": [("192 of 448 without markers, all purge/restore/clock step", BCD, "these events rewrite sealed segments "
                    "wholesale; the trial design fixes the counts (Table 5 caption)", "regression test")],
    "SI-S055-03": [("0 of 448 with markers", BCD, "markers excuse exactly the declared events", "regression test")],
    "SI-S056-01": [("13 of 4,733 pooled floor", M, "", "benign floor; mixes the row and closure schemes and two "
                    "authentication settings (exp/out/r14_benign_rates.json decomposes it)")],
    "SI-S056-02": [("each failure a late row", M, "", "mechanism of the measured failures")],
    "SI-S056-05": [("minute floor zero in every run", M, "", "")],
    "SI-S056-03": [("late rows from commit delay vs no-grace sealing", M, "explanation", "")],
    "SI-S057-01": [("ten of eleven marker-abuse cases detected", BCD, "marker scoping rules", "regression tests")],
    "SI-S057-02": [("purge-shaped deletion escaped 4 of 4 at 0.498-0.520 of history", BCD,
                    "a deletion confined to rows the marker's cutoff excuses is excused by design (evasion condition)",
                    "the history it costs is measured")],
    "SI-S057-03": [("scoped markers: 0/12 purges flagged, 13/13 deletions past the boundary detected", BCD,
                    "cutoff recomputed from the retention policy and schedule", "regression tests on generated deployments")],
    "SI-S057-04": [("markers declaring the deletion's own cutoff excuse it", BCD, "evasion condition: needs the operator "
                    "key held outside the hub", "")],
    # ---------------------------------------------------------------- observation window and write-time forgery
    "SI-S096-01": [("window data set", C, "", "")],
    "SI-S096-02": [("write-to-anchor 3.8 s median, 17.75 s max", M, "", "observation window")],
    "SI-S096-06": [("segments left out", M, "", "")],
    "SI-S096-03": [("escape probability 0.98 / 0.27 / 0.012", M, "", "observation window")],
    "SI-S096-07": [("window does not limit detection of pre-arrival actuations", LOG, "the segment was sealed before the "
                    "adversary acted", "")],
    "SI-S097-01": [("evidence-unobservable record under five hostile conditions", BCD, "fail-closed rule",
                    "one run each (regression)")],
    "SI-S053-01": [("write-time design", C, "", "")],
    "SI-S053-02": [("three write-time strategies reach misattribution 30/30", M, "", "renderer behavior")],
    "SI-S053-06": [("minted parent context 0/30", M, "", "renderer behavior")],
    "SI-S053-03": [("write-time strategies detected 0/30", BCN, "no earlier committed version", "regression test")],
    "SI-S053-04": [("post-commit control 30/30 [0.884, 1.000]", BC, A3F, "liveness check of the detector")],
    "SI-S054-01": [("forward-integrity definition (citation)", C, "", "")],
    "SI-S054-03": [("write-time result on the boundary of forward integrity", LOG, "definition", "")],
    "SI-S054-02": [("boundary independent of the fields committed", BCN, "no earlier version under any field list", "")],
    # ---------------------------------------------------------------- detection on the real deployment
    "SI-S044-11": [("E8 setup", C, "", "")],
    "SI-S044-13": [("E8 arms", C, "", "")],
    "SI-S044-14": [("adaptive arms; backdated by 129.8 to 243.0 s", C, "", "measured precondition: every backdating exceeds "
                    "LATE_BOUND (30 s), so the late-bound rule attributes it by construction")],
    "SI-S044-15": [("both monitors 90 of 90 in every arm [0.960, 1.000]", BC, A3F + " + coverage (watermark), keylog, "
                    "late bound", "regression test under one workload")],
    "SI-S044-16": [("earlier rule: insertions ambiguous, forged unlocks not flagged", BCD, "stated: 'by its design'", "")],
    "SI-S045-12": [("0 of 1,435 / 0 of 124 / 0 of 1,201", M, "", "benign floor under coverage")],
    "SI-S045-13": [("write rates 93.54 / 38.1 / 176.81 rows per minute", M, "", "workload"),
                   ("30 of 30 launderings under stress [0.884, 1.000]", BC, A3F, "regression test at 176.81 rows/min")],
    "SI-S045-15": [("records verify under own key, fail under the other's; witness checks", BC, "Ed25519 and the link "
                    "check", "regression")],
    "SI-S045-17": [("anchors refused hub probes and wrong-key requests; reply tags", BC, "(A2), operator key",
                    "regression"), ("no witness reachable from the hub", M, "", "network property of the run")],
    "SI-S045-18": [("poll times", M, "", "cost")],
    "SI-S046-01": [("every edit >= 130 s after the row was written", M, "", "measured precondition that makes the "
                    "detection outcomes follow by construction (the row's segment was sealed before the edit)")],
    "SI-S113-01": [("E7 setup", C, "", "")],
    "SI-S113-02": [("E7 30 of 30 in every arm [0.884, 1.000]", BC, A3F + " + coverage, keylog, late bound", "regression")],
    "SI-S113-03": [("earlier rule on E7", BCD, "late-row test's design", "")],
    "SI-S113-05": [("appends kept succeeding under slow connections", M, "", "hardened anchor under a stall"),
                   ("edits during a 90 s pause attributed 30/30", BC, "freeze-and-resend protocol", "regression")],
    "SI-S113-06": [("E7 floor 0 of 1,212; poll 271 ms", M, "", "benign floor, cost")],
    "SI-S113-07": [("escrow recovery 119 of 120", M, "", "escrow coverage; the miss is the escrow's sealed-only design")],
    "SI-S121-01": [("earlier runs; member-account flags are in-place changes", BC, "the swap rewrites the row in place", "")],
    "SI-S121-02": [("ambiguous trials were late rows", M, "", "")],
    "SI-S121-03": [("row scheme: 0 of 90 random-id swaps, 0 of 90 member-account swaps (offline)", BCN,
                    A3F + " (the row scheme omits the user column)", "regression")],
    # ---------------------------------------------------------------- localization
    "SI-S058-02": [("quarantine sound on 480 of 480 enumerated instances", EX, "innermost-first rule given a complete "
                    "record of sealed segments (A4)", "exhaustive")],
    "SI-S058-05": [("257 admit a smaller sound set", EX, "", "")],
    "SI-S058-04": [("389 of 390 covered [0.986, 1.000]", MIX, "covered by construction when every edited second is "
                    "sealed (A4 completeness)", "whether the run sealed every second is measured (one indeterminate)")],
    "SI-S058-06": [("indeterminate trial: a second never sealed", M, "", "")],
    "SI-S101-01": [("89 of 90 in PU, every trial of the other arms", MIX, "as above", "")],
    "SI-S101-02": [("over-quarantine below the component policy's in every arm", M, "", "localization size")],
    "SI-S101-03": [("390 of 390 [0.991, 1.000] with the anchor's record read as complete", BC, "innermost-first rule",
                    "regression")],
    "SI-S101-05": [("keylog-range spillover enlarges the quarantine", BCD, "a failed range flags every row's second "
                    "(32-bit prefixes only rank suspects)", "its size is measured")],
    "SI-S101-06": [("suspect seconds 129/169 of 1,212 (E7); 791/768 of 1,435, 0 of 124, 100/99 of 1,201 (E8)", M, "",
                    "localization size; E7's 129 and 169 are e7_verify's whole-chain lists, one second of each lies "
                    "outside the E7 window (exp/out/r14_localization_deployed.json)")],
    # ---------------------------------------------------------------- current releases
    "SI-S100-02": [("rendering setup", C, "", "")],
    "SI-S100-03": [("laundering moved the displayed cause 30/30 per release", M, "", "renderer behavior")],
    "SI-S100-11": [("rendering agreed with the display rule 120/120 and 116/120", M, "", "renderer vs rule")],
    "SI-S100-05": [("Details chain; automation trace exposed laundering 30/30 (admin)", M, "", "renderer behavior")],
    "SI-S100-06": [("member-account swap moved the cause: admin 30/30, non-admin 0/30", M, "", "renderer behavior")],
    "SI-S100-15": [("swap rendering agreed 120/120", M, "", "renderer vs rule")],
    "SI-S100-07": [("person entity: non-admin cause moved 30/30", M, "", "renderer behavior")],
}

# Floats whose cells or captions print outcomes (generated files, read-only).
FLOATS = [
    ("fig:detect", "figures/fig_detect.tex", BC, "E8 detection by arm with exact intervals: regression tests of the "
     "coverage, keylog and late-bound rules; the earlier rule's 0/90 attributable on insertions and BD-S is by its design"),
    ("tab:classes", "tables/tab4.tex", BCN, "forgery classes x schemes; the caption already says 'by construction' for "
     "FT-U and FT-E"),
    ("tab:benign", "tables/tab5.tex", BCD, "generated-deployment rows fixed by the trial design (caption says so); the "
                                          "real-deployment pooled floor row is measured and mixes schemes"),
    ("tab:detect", "tables/tab3.tex", BC, "flags and detections follow from the field lists (row scheme 0/90 and 1/90 on "
                                          "swaps by omission); misattribution and the per-run floors are measured"),
    ("fig:localize", "figures/fig_localize.tex", MIX, "coverage by construction given a complete record of sealed "
                                                      "seconds; over-quarantine measured"),
    ("tab:floors", "tables/tab_appb.tex", M, "per-run benign floors (measured)"),
]

# Rule-level argument: every way a post-commit change of a displayed cause escapes detection, with the paper sentence
# that states it (intent id) and what bounds it.
EVASION = [
    {"condition": "the rewritten input is not committed", "cases": "a scheme that omits the column (row scheme: user "
     "column, old_state_id, last_changed_ts); the name map and entity registry without the name-map digest; automation "
     "traces", "statement": ["SI-S021-10", "SI-S021-08", "SI-S121-03"], "kind": "by construction (field list)",
     "bound": "the renderer closure measured on the release (stable columns cover every column the output reads)"},
    {"condition": "the row is changed or deleted before any poll reads it", "cases": "observation window",
     "statement": ["SI-S021-02", "SI-S096-03"], "kind": "boundary", "bound": "measured window (median 3.8 s write to "
     "anchor; escape probability 0.98 / 0.27 / 0.012 at 1 / 5 / 10 s); does not apply to rows committed before the "
     "adversary's code arrived (SI-S096-07)"},
    {"condition": "the row is forged when first written by resident code", "cases": "write-time forgery",
     "statement": ["SI-S111-04", "SI-S053-03"], "kind": "outside the guarantee by construction",
     "bound": "none: no earlier committed version exists"},
    {"condition": "a row inserted into sealed time with a timestamp within LATE_BOUND (30 s) of the copies that lacked it",
     "cases": "backdating by less than about 35 s passes as a benign late row", "statement": ["SI-S021-07", "SI-S071-14",
     "SI-S035-11"], "kind": "rule design (late bound)", "bound": "LATE_BOUND = 30 s plus one poll; the keylog catches "
     "rows created earlier and moved in (SI-S032-10)"},
    {"condition": "a deletion that a lifecycle marker excuses", "cases": "a purge-shaped deletion confined to rows older "
     "than the scoped cutoff; a marker declaring the deletion's own cutoff", "statement": ["SI-S021-06", "SI-S057-02",
     "SI-S057-04", "SI-S037-04"], "kind": "rule design (markers)", "bound": "markers need the operator key outside the "
     "hub; the purge-shaped deletion costs about half the history (0.498-0.520 of it on generated deployments)"},
    {"condition": "rows inside an evidence-unobservable interval", "cases": "the monitor could not read a consistent copy",
     "statement": ["SI-S035-05"], "kind": "rule design (fail closed)", "bound": "the interval is anchored and reported"},
    {"condition": "the anchor host rewrites or withholds records", "cases": "(A4)", "statement": ["SI-S019-04",
     "SI-S035-13"], "kind": "assumption", "bound": "linked anchor and witness detect a rewrite up to the latest witnessed "
     "head; the evaluated guarantee assumes (A4)"},
    {"condition": "two rows that differ in a covered field share a node hash", "cases": "(A3); the earlier separator "
     "encoding", "statement": ["SI-S019-03", "SI-S032-08"], "kind": "assumption", "bound": "typed encoding injective; "
     "under the earlier encoding 7.33% of 1,090,765 rows admitted a splice (measured)"},
    {"condition": "the monitor or anchor is within the adversary's reach, or the append key leaks", "cases": "(A1), (A2): "
     "privileged core or host network on the same host", "statement": ["SI-S019-01", "SI-S019-02", "SI-S021-05"],
     "kind": "assumption", "bound": "placement on another host (E1, E5)"},
]
PREMISES = ["SI-S019-01", "SI-S019-02", "SI-S019-03", "SI-S019-04", "SI-S093-01", "SI-S093-02", "SI-S020-01",
            "SI-S020-02", "SI-S036-02", "SI-S032-10", "SI-S035-11", "SI-S037-04"]

INTERVAL_RE = re.compile(r"\[\d\.\d{3}, \d\.\d{3}\]")


def strip_tex(s):
    return re.sub(r"\s+", " ", s).strip()


def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    smap = read_yaml(os.path.join(PAPER, "sections", "wk_sourcemap.yaml"))
    eval_tex = strip_tex(read_text(os.path.join(PAPER, "sections", "07_sp_eval.tex")))
    abs_tex = strip_tex(read_text(os.path.join(PAPER, "sections", "00_abstract.tex")))
    si_text = {}
    for e in smap:
        si_text[e["si"].split("@")[0]] = (e, artifact("10-realizations", e["r"])["content"]["text"])

    sentences, missing_class, licensed_files = [], [], {}
    for e in smap:
        if e["section"] not in ("SP-ABS", "SP-EVAL"):
            continue
        sid = e["si"].split("@")[0]
        text = si_text[sid][1]
        si = artifact("07-intents", e["si"])
        pids = si["content"].get("evidence_uses") or []
        ev = []
        for pref in pids:
            pref = pref.get("ref") if isinstance(pref, dict) else pref
            p = artifact("03-evidence", pref)
            nums = []
            for n in (p.get("content") or {}).get("numbers") or []:
                f = n.get("file")
                rec = {"value": n.get("value"), "meaning": n.get("meaning"), "locator": n.get("locator")}
                if f and (f.startswith("http") or "*" in f or ";" in f):
                    rec["reference"] = f          # a URL, a glob or a list: not one file, not hashed here
                elif f and not os.path.isabs(f) and not f.startswith("exp/") and os.path.exists(os.path.join(PAPER, f)):
                    rec["file"] = "[paper]/" + f
                    rec["sha256_licensed"] = n.get("sha256")
                    cur = sha256_file(os.path.join(PAPER, f))
                    rec["sha256_current"] = cur
                    rec["licensed_file_unchanged"] = (n.get("sha256") == cur) if n.get("sha256") else None
                elif f:
                    f_abs = f if os.path.isabs(f) else os.path.join(REPO, f)
                    f_rel = rel(f_abs)
                    rec["file"] = f_rel
                    rec["sha256_licensed"] = n.get("sha256")
                    if os.path.exists(f_abs):
                        cur = sha256_file(f_abs)
                        rec["sha256_current"] = cur
                        rec["licensed_file_unchanged"] = (n.get("sha256") == cur) if n.get("sha256") else None
                        licensed_files[f_rel] = cur
                    else:
                        rec["sha256_current"] = None
                        rec["licensed_file_unchanged"] = None
                nums.append(rec)
            ev.append({"evidence": pref, "numbers": nums})
        cls = CLASS.get(sid)
        if cls is None:
            missing_class.append(sid)
            cls = [("unclassified", "unclassified", "", "")]
        tex = abs_tex if e["section"] == "SP-ABS" else eval_tex
        printed = strip_tex(text) in tex
        sentences.append({
            "section": e["section"], "slot": e["slot"], "intent": e["si"], "realization": e["r"],
            "text": text, "printed_verbatim_in_current_tex": printed,
            "outcomes": [{"outcome": o, "category": c, "basis": b, "measured_or_tested": m} for o, c, b, m in cls],
            "prints_exact_interval": bool(INTERVAL_RE.search(text)),
            "evidence": ev,
        })
    assert not missing_class, missing_class
    by_construction_cats = {BC, BCN, BCD}
    files_not_current = sorted({(n["file"], e["evidence"]) for s in sentences for e in s["evidence"]
                                for n in e["numbers"] if n.get("licensed_file_unchanged") is False})
    inconsistent = [{"slot": s["slot"], "intent": s["intent"], "text": s["text"],
                     "outcomes": [o["outcome"] for o in s["outcomes"] if o["category"] in by_construction_cats]}
                    for s in sentences if s["prints_exact_interval"]
                    and any(o["category"] in by_construction_cats for o in s["outcomes"])]

    floats = []
    # floats whose exact intervals sit on by-construction cells (read from the generated files by hand, 2026-10-12)
    ON_BC = {"fig:detect": "every detection interval (E8 arms and the stress row)",
             "tab:detect": "the flagged and detected columns (k of n with exact intervals)",
             "fig:localize": "the pooled 390/390 [0.991, 1.000] with the anchor's record read as complete"}
    for label, path, cat, basis in FLOATS:
        t = read_text(os.path.join(PAPER, path))
        m = re.search(r"\\caption\{(.*?)\}\\label\{" + re.escape(label) + r"\}", t, re.S)
        cap = m.group(1) if m else ""
        floats.append({"label": label, "file": "[paper]/" + path, "caption": cap or None,
                       "category": cat, "basis": basis,
                       "prints_exact_interval": bool(INTERVAL_RE.search(t)) or ("exact" in cap and "interval" in cap),
                       "interval_on_by_construction_cells": ON_BC.get(label)})

    def stmt(ids):
        return [{"intent": i, "slot": si_text[i][0]["slot"], "text": si_text[i][1]} for i in ids if i in si_text]

    evasion = [dict(x, statement=stmt(x["statement"])) for x in EVASION]
    premises = stmt(PREMISES)

    # ---------------------------------------------------------------- counts re-read from result files
    e8 = read_json(os.path.join(OUT, "e8_main_score_rescored.json"))
    e7 = read_json(os.path.join(OUT, "e7_main_score.json"))
    r9 = read_json(os.path.join(OUT, "r9_e_scheme_detection_n60.json"))
    s10 = read_json(os.path.join(OUT, "stage10_raw.json"))
    s25 = read_json(os.path.join(OUT, "stage25_final.json"))
    loc = read_json(os.path.join(DRY or OUT, "r14_localization_deployed.json"))
    ben = read_json(os.path.join(DRY or OUT, "r14_benign_rates.json"))
    wt = {}
    for f, lr in (("e_c_write_time.json", None), ("e_c_auth_other_principal_real.json", "e_c_auth_late_row_check.json"),
                  ("e_c_clo_other_principal_real.json", "e_c_clo_late_row_check.json")):
        d = read_json(os.path.join(OUT, f))
        late = read_json(os.path.join(OUT, lr))["per_arm"] if lr else {}
        wt[f] = {a: {"n_valid": v.get("n_valid"),
                     "flagged_second_raw": (v.get("homeprov_detection_second") or {}).get("k"),
                     "attributable_after_late_row_test": (late.get(a) or {}).get("attributable"),
                     "late_row": (late.get(a) or {}).get("late_row"),
                     "late_row_check_file": ("exp/out/" + lr) if lr else None}
                 for a, v in (d.get("arms") or {}).items()}
    counts = {
        "E8_detection_by_arm": {m: {a: [v["e7_detected"], v["n"]] for a, v in
                                    e8["monitors"][m]["by_window"]["main"]["arms"].items()} for m in ("stable", "closure")},
        "E8_stress_detection": {m: {a: [v["e7_detected"], v["n"]] for a, v in
                                    e8["monitors"][m]["by_window"]["stress"]["arms"].items()} for m in ("stable", "closure")},
        "E8_earlier_rule_ambiguous_and_flagged": {a: {"ambiguous": v["existing_ambiguous"], "flagged": v["existing_flagged"],
                                                      "attributable": v["existing_attributable"]}
                                                  for a, v in e8["monitors"]["stable"]["by_window"]["main"]["arms"].items()},
        "E7_detection_by_arm": {m: {a: [v["e7_detected"], v["n"]] for a, v in e7[m + "_monitor"]["arms"].items()}
                                for m in ("stable", "closure")},
        "FT-U_FT-E_by_scheme_n60": {ft: {s: r9["table_new_60"][ft][s]["k"] for s in ("row", "homeprov2", "b2", "b2c")}
                                    for ft in ("FT-U", "FT-E")},
        "FT-U_FT-E_scheme_keys": {k: r9["scheme_keys"][k] for k in ("row", "homeprov2", "b2", "b2c")},
        "benign_trials_without_and_with_markers": [s10["raw_false_alarm_without_markers"]["k"],
                                                   s10["post_marker_false_alarm"]["k"], s10["n_trials"]],
        "enumerated_localization": [s25["E13_exhaustive"]["sound"], s25["E13_exhaustive"]["instances"],
                                    len(s25["E13_exhaustive"]["proper_subset_sound"])],
        "write_time_runs_arms": wt,
        "deployed_localization_coverage": {k: [v["covered"]["k"], v["covered"]["n"]]
                                           for k, v in loc["pooled_by_experiment_and_monitor"].items()},
        "deployed_localization_E7_suspects_window_vs_whole_chain": {
            r["monitor"]: [r["quarantine_window"]["untouched_suspect_seconds_recomputed"],
                           r["quarantine_window"]["untouched_flagged_seconds_whole_chain_recomputed"]]
            for r in loc["windows"] if r["experiment"] == "E7"},
        "nine_run_pool_by_scheme": ben["nine_run_pool_decomposition"]["by_scheme"],
    }
    assert all(v == [90, 90] for m in counts["E8_detection_by_arm"].values() for v in m.values())
    assert all(v == [30, 30] for m in counts["E7_detection_by_arm"].values() for v in m.values())
    assert counts["benign_trials_without_and_with_markers"] == [192, 0, 448]
    assert counts["enumerated_localization"][:2] == [480, 480]

    # ---------------------------------------------------------------- summary table (one row per printed outcome)
    table = []
    for s in sentences:
        for o in s["outcomes"]:
            if o["category"] == C:
                continue
            files = sorted({n["file"] for e in s["evidence"] for n in e["numbers"] if n.get("file")})
            table.append({"slot": s["slot"], "intent": s["intent"], "outcome": o["outcome"], "category": o["category"],
                          "interval_printed": s["prints_exact_interval"], "files": files})
    cat_counts = {}
    for r in table:
        cat_counts[r["category"]] = cat_counts.get(r["category"], 0) + 1

    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14: which printed outcomes of the abstract and Section 7 follow by construction from (A3), the committed "
                "field list and a rule's design (the trials are regression tests), and which are measured; with each "
                "sentence's current text, the result files its numbers are licensed from, the rule-level conditions "
                "under which evasion is possible, and the sentences that print an exact interval on a by-construction "
                "outcome",
        "answers": ["R3 W3: 'Give a rule-level argument (coverage, keylog, late bound, markers) listing exactly when "
                    "evasion is possible, and present the trials as regression tests'",
                    "R3 W3: 'Section 7.1 says results that follow by construction carry no interval, yet these carry one'"],
        "categories": {BC: "implied by (A3) + field list + a rule, given the trial's preconditions; trials test the "
                           "implementation and harness; an interval bounds an implementation failure rate under one "
                           "harness and workload, not adaptive evasion",
                       BCN: "a scheme that omits the rewritten field detects 0 (or write-time: no earlier version)",
                       BCD: "restates what a rule does (earlier rule, markers, fail-closed)",
                       MIX: "follows by construction once a measured input or precondition is given",
                       LOG: "follows from the guarantee's definition",
                       EX: "exhaustive check of a finite instance set",
                       M: "depends on platform behavior, timing, load, workload or the renderer",
                       D: "an attack's effect shown in a run", C: "setup or definition"},
        "premises": premises,
        "sentences": sentences,
        "floats": floats,
        "interval_on_by_construction": inconsistent,
        "evasion_conditions": evasion,
        "counts_reread": counts,
        "summary_table": table,
        "category_counts": cat_counts,
        "licensed_files_current_sha256": licensed_files,
        "licensed_files_changed_since_licensing": [{"file": f, "evidence": p} for f, p in files_not_current],
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14_by_construction.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", DST, hashlib.sha256(open(DST, "rb").read()).hexdigest())
    print("sentences", len(sentences), "not printed verbatim", [s["slot"] + " " + s["intent"] for s in sentences
                                                               if not s["printed_verbatim_in_current_tex"]])
    print("interval on by-construction:", [x["intent"] for x in inconsistent])
    print("categories", cat_counts)


if __name__ == "__main__":
    main()
