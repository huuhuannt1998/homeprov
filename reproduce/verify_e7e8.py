#!/usr/bin/env python3
"""Re-verify E7 and E8 from the shipped recorder window extracts and compare with the published verify files.

    python3 reproduce/verify_e7e8.py [--extracts DIR] [--only e7_main,e8_main] [--escrow] [--jobs N] [--out FILE]
                                     [--verifier FILE] [--monitor FILE]

The code it runs, by default: the verifier and the monitor the published E7/E8 verify files were made with, kept byte
for byte as exp/stages/e7_verify_e8.py (sha256 7e036386...) and monitor/monitor_e8.py (sha256 3e479ae0...). The
repository's exp/stages/e7_verify.py and monitor/monitor.py are the later E9 versions. The default files must have
exactly those digests (otherwise the script stops); --verifier and --monitor run other files instead, and the report
says which code ran ("code": "e8" or "other"). The monitor is staged as monitor.py in a temporary directory, which is
the verifier's --monitor-dir; the verifier is also the e7_verify module that exp/stages/e8_score.py uses here.

For each experiment (E7: one window; E8: the arms, the baseline and the stress window), each monitor (stable columns,
closure) and each window, this script
  1. checks the extract (<exp>.db) and the monitor's anchor chain (<exp>_<monitor>.chain.jsonl.gz) against
     EXTRACTS_E7E8_SHA256SUMS (reproduce/make_e7e8_extracts.py made both from the run's saved recorder copy and the
     chain published in exp/out);
  2. runs the verifier the runs were scored with, unchanged (it recomputes every root with the monitor's own load() and
     commit()), with the parameters recorded in the published verify file (window,
     recorder snapshot time, scheme, LATE_BOUND, GAP_S), the run's harness reports for the counting rule, and for E8 the
     monitor's published Ed25519 key (exp/out/e8_main_{stb,clo}_sign_pub.pem: only records whose signature verifies
     under it are used, as in the run);
  3. compares the output with the published file exp/out/e7_main_<monitor>_verify.json or
     exp/out/e8_main_<monitor>_verify_<window>.json: field by field (every field except params, which names the run's
     own paths, and recovery unless --escrow is given; E7's file predates the verifier's signatures field), and, as
     separate named checks, the numbers the paper prints: per arm the trials, detections and the earlier rule's
     flagged, attributable and ambiguous counts; the benign floor at one second, one minute and one hour; the suspect
     seconds (for E8 restricted to the window, as exp/out/e8_main_score_rescored.json reports them, with
     exp/stages/e8_score.py's scope_suspects); for E8 the signature counts, the cross-check under the other monitor's
     key, and the chain against every head its witness accepted (exp/out/e8_main_<monitor>_witness_heads.jsonl.gz).
With --escrow, each monitor's escrow is passed as in the run and the recovery section is compared too (the rendering
of the restored copy in a throwaway hub is not redone here): exp/out/e8_main_<monitor>_escrow.jsonl.gz for E8, and for
E7's closure monitor exp/out/e7_main_escrow_scored.jsonl.gz, the first 2,680 lines of the run's escrow file, which are
the lines the run's verifier read (exp/out/e7_main_escrow_scored.json; exp/out/e7_main_escrow.jsonl.gz holds the first
2,674). E7's run also wrote a restored copy (--restore-out); it is written here to a temporary directory and its checks
are compared, not its path. E7's recovery section was written by the verifier version of the run, before the keylog's
first-read rows were escrowed: every field it holds is compared, and the fields only the E8 verifier adds (the
keylog's recovery, keylog_* in restore) are listed under recovery_fields_added, not compared.

Writes a report (default reproduce/verify_e7e8_report.json, never overwritten) and prints MATCH or MISMATCH per
monitor and window. Exit status 0 only if every comparison matches.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime
import gzip
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "exp", "out")
DEFAULT_EXTRACTS = os.path.join(REPO, "reproduce", "snapshots", "e7e8")
# The default code: the E8 versions of the verifier and the monitor, with the digests they must have (see the docstring).
E8_CODE = {"verifier": ("exp/stages/e7_verify_e8.py", "7e036386baacea9d05808a50a709489bd554d5a4b0a3d568583d07afbb0ae1f8"),
           "monitor": ("monitor/monitor_e8.py", "3e479ae01caf299e697b0274a22ddddbaa6b57b9bf4b730a8774b2d7c5b5282b")}
sys.path.insert(0, os.path.join(REPO, "exp", "stages"))
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import chainverify as CV  # noqa: E402

# Set by use_code() before any verification: the verifier file and module (EV), exp/stages/e8_score.py importing that
# module (ES: scope_suspects, window_touched, the scorer's own window rule), the monitor file and its --monitor-dir.
E7_VERIFY = MONITOR_PY = MONITOR_DIR = None
EV = ES = None


def use_code(verifier, monitor, scratch_root):
    global E7_VERIFY, MONITOR_PY, MONITOR_DIR, EV, ES
    E7_VERIFY, MONITOR_PY = os.path.abspath(verifier), os.path.abspath(monitor)
    spec = importlib.util.spec_from_file_location("e7_verify", E7_VERIFY)
    EV = importlib.util.module_from_spec(spec)
    sys.modules["e7_verify"] = EV          # e8_score.py's "import e7_verify" gets this module, not exp/stages/e7_verify.py
    spec.loader.exec_module(EV)
    ES = importlib.import_module("e8_score")
    MONITOR_DIR = os.path.join(scratch_root, "monitor")
    os.makedirs(MONITOR_DIR)
    shutil.copyfile(MONITOR_PY, os.path.join(MONITOR_DIR, "monitor.py"))

# (experiment, monitor) -> published files; the window list is the published one.
RUNS = {
    # E7's escrow: the first 2,680 lines of the run's escrow file, the lines its verifier read (recovery.escrow_lines);
    # its recovery section predates the keylog escrow, so fields only the E8 verifier adds are listed, not compared.
    ("e7_main", "closure"): {"verify": {"main": "e7_main_closure_verify.json"}, "escrow": "e7_main_escrow_scored.jsonl.gz",
                             "recovery_published_fields_only": True},
    ("e7_main", "stable"): {"verify": {"main": "e7_main_stable_verify.json"}, "escrow": None},
    ("e8_main", "stable"): {"verify": {w: "e8_main_stable_verify_%s.json" % w for w in ("main", "base", "stress")},
                            "escrow": "e8_main_stable_escrow.jsonl.gz", "key": "stb", "other_key": "clo"},
    ("e8_main", "closure"): {"verify": {w: "e8_main_closure_verify_%s.json" % w for w in ("main", "base", "stress")},
                             "escrow": "e8_main_closure_escrow.jsonl.gz", "key": "clo", "other_key": "stb"},
}
SCORE = {"e7_main": "e7_main_score.json", "e8_main": "e8_main_score.json"}
RESCORED = "e8_main_score_rescored.json"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(name):
    return json.load(open(os.path.join(OUT, name)))


def checked_inputs(base, exp, monitor):
    sums = {}
    for line in open(os.path.join(base, "EXTRACTS_E7E8_SHA256SUMS")):
        h, p = line.split(None, 1)
        p = p.strip()
        sums[p[2:] if p.startswith("./") else p] = h
    db = os.path.join(base, exp + ".db")
    chain = os.path.join(base, "%s_%s.chain.jsonl.gz" % (exp, monitor))
    info = {}
    for label, p in (("db", db), ("chain", chain)):
        got = sha256_file(p)
        if sums.get(os.path.basename(p)) != got:
            raise SystemExit("%s %s: %s is not vouched for by EXTRACTS_E7E8_SHA256SUMS" % (exp, monitor, p))
        info[label] = {"path": os.path.relpath(p, REPO), "sha256": got}
    published_chain = os.path.join(OUT, "%s_%s_chain.jsonl.gz" % (exp, monitor))
    info["chain"]["same_bytes_as_exp_out"] = (os.path.exists(published_chain)
                                              and sha256_file(published_chain) == info["chain"]["sha256"])
    return db, chain, info


def report_files(exp, window):
    rf = load(SCORE[exp])["report_files"]
    files = rf if isinstance(rf, list) else rf.get(window, [])
    return [os.path.join(REPO, f) for f in files]


def run_verify(exp, monitor, window, db, chain, scratch, escrow):
    """exp/stages/e7_verify.py verify, with the published file's own parameters."""
    pub = load(RUNS[(exp, monitor)]["verify"][window])
    prm = pub["params"]
    out = os.path.join(scratch, "%s_%s_%s.json" % (exp, monitor, window))
    cmd = [sys.executable, E7_VERIFY, "verify", "--chain", chain, "--db", db,
           "--late-bound", str(prm["late_bound_s"]), "--gap-s", str(prm["gap_s"]),
           "--snapshot-at", str(prm["snapshot_at"]), "--window", str(prm["window"][0]), str(prm["window"][1]),
           "--scheme", prm["scheme"], "--out", out, "--monitor-dir", MONITOR_DIR]
    key = RUNS[(exp, monitor)].get("key")
    if key:
        cmd += ["--sign-pubkey", os.path.join(OUT, "%s_%s_sign_pub.pem" % (exp, key))]
    esc = RUNS[(exp, monitor)].get("escrow")
    if escrow and esc and prm.get("escrow"):
        cmd += ["--escrow", os.path.join(OUT, esc)]
        if isinstance((pub.get("recovery") or {}).get("restore"), dict):     # the run wrote a restored copy too
            cmd += ["--restore-out", os.path.join(scratch, "restored.db")]
    trials = report_files(exp, window)
    if trials:
        cmd += ["--trials", *trials]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0 or not os.path.exists(out):
        raise SystemExit("%s %s %s: e7_verify failed (rc %s): %s" % (exp, monitor, window, r.returncode, r.stderr[-1500:]))
    return pub, json.load(open(out)), trials


def diff(a, b, path="", out=None, cap=50):
    if out is None:
        out = []
    if len(out) >= cap:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append("%s/%s: only in the %s output" % (path, k, "published" if k in a else "recomputed"))
            else:
                diff(a[k], b[k], "%s/%s" % (path, k), out, cap)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("%s: %d vs %d items" % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, "%s[%d]" % (path, i), out, cap)
    elif a != b:
        out.append("%s: published %r, recomputed %r" % (path, str(a)[:80], str(b)[:80]))
    return out


def strip_path(rec):
    if isinstance(rec, dict) and isinstance(rec.get("restore"), dict):
        rec = dict(rec, restore={k: v for k, v in rec["restore"].items() if k != "path"})
    return rec


def published_fields(pub, new, path):
    """new restricted to the dict keys pub holds (recursively); the keys dropped are returned."""
    if not (isinstance(pub, dict) and isinstance(new, dict)):
        return new, []
    out, dropped = {}, []
    for k, v in new.items():
        if k in pub:
            out[k], sub = published_fields(pub[k], v, "%s/%s" % (path, k))
            dropped += sub
        else:
            dropped.append("%s/%s" % (path, k))
    return out, dropped


def printed_checks(exp, monitor, window, pub, new, db, trials):
    """The numbers the paper prints, each as a named check (recomputed vs published)."""
    checks = {}

    def chk(name, got, want):
        checks[name] = {"recomputed": got, "published": want, "match": got == want}

    for arm in sorted(pub.get("arms") or {}):
        p, n = pub["arms"][arm], (new.get("arms") or {}).get(arm) or {}
        for k in ("n", "e7_detected", "existing_flagged", "existing_attributable", "existing_ambiguous"):
            chk("arm %s %s" % (arm, k), n.get(k), p.get(k))
    pb, nb = pub["benign_floor"], new["benign_floor"]
    chk("floor second violated/untouched", [nb["violated"], nb["untouched_anchored_seconds"]],
        [pb["violated"], pb["untouched_anchored_seconds"]])
    for g in ("minute", "hour"):
        chk("floor %s attributable/untouched" % g, [nb[g]["attributable"], nb[g]["untouched_anchored"]],
            [pb[g]["attributable"], pb[g]["untouched_anchored"]])
    if exp == "e7_main":
        chk("suspect seconds (untouched flagged)", [nb["untouched_flagged_seconds"]["n"],
                                                    nb["untouched_flagged_seconds"]["of_untouched_anchored_seconds"]],
            [pb["untouched_flagged_seconds"]["n"], pb["untouched_flagged_seconds"]["of_untouched_anchored_seconds"]])
    else:
        prm = pub["params"]
        w = (float(prm["window"][0]), float(prm["window"][1]))
        tmp = tempfile.mkdtemp(prefix="e7e8_touch_")
        try:
            dbc = os.path.join(tmp, "rec.db")
            shutil.copyfile(db, dbc)
            touched = ES.window_touched(trials, dbc)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        sc = ES.scope_suspects(new, w, touched)
        rs = load(RESCORED)["monitors"][monitor]["by_window"][window]["benign_floor"]["untouched_flagged_seconds"]
        chk("suspect seconds in the window (as e8_main_score_rescored.json)",
            [sc["n"], sc["of_untouched_anchored_seconds"], sc["keylog_suspect_rows"], sc["keylog_likely_rows"]],
            [rs["n"], rs["of_untouched_anchored_seconds"], rs["keylog_suspect_rows"], rs["keylog_likely_rows"]])
        ps, ns = pub["signatures"], new["signatures"]
        chk("signatures: monitor records, verified under its own key, excluded",
            [ns.get("monitor_records"), ns.get("signed_ok"), len(ns.get("excluded_from_verification") or [])],
            [ps.get("monitor_records"), ps.get("signed_ok"), len(ps.get("excluded_from_verification") or [])])
    return checks


def chain_checks(exp, monitor, chain, scratch):
    """E8: every record under the other monitor's key (wrong_key), and the chain against every witnessed head."""
    cfg = RUNS[(exp, monitor)]
    if not cfg.get("other_key"):
        return {}
    checks = {}
    M = EV.load_monitor("closure", scratch, MONITOR_DIR)
    other = os.path.join(OUT, "%s_%s_sign_pub.pem" % (exp, cfg["other_key"]))
    lines = EV.read_lines(chain)
    _keep, sig = EV.check_signatures(M, lines, other)
    sc = load(SCORE[exp])
    want = next(x for x in sc["signature_cross_check"] if x["chain"] == cfg["key"])
    got = {"wrong_key": len(sig["wrong_key"]), "fingerprint": sig["pubkey_fp"]}
    checks["records under the other monitor's key (wrong_key)"] = {
        "recomputed": got, "published": {"wrong_key": want.get("wrong_key"), "fingerprint": want.get("fingerprint")},
        "match": got == {"wrong_key": want.get("wrong_key"), "fingerprint": want.get("fingerprint")}}
    heads_p = os.path.join(OUT, "%s_%s_witness_heads.jsonl.gz" % (exp, monitor))
    data = gzip.open(chain).read()
    res = CV.verify_chain(data, witnessed_heads=CV.read_heads(gzip.open(heads_p).read()))
    pw = sc["monitors"][monitor]["witness"]
    got = {"records": res["records"], "link": res["link"], "ok": res["ok"],
           "witnessed_heads_matched": res["witnessed_heads"]["matched"],
           "witnessed_heads": res["witnessed_heads"]["heads"]}
    want = {"records": pw["records"], "link": pw["link"], "ok": pw["ok"],
            "witnessed_heads_matched": pw["witnessed_heads"]["matched"], "witnessed_heads": pw["witnessed_heads"]["heads"]}
    checks["chain links and every witnessed head"] = {"recomputed": got, "published": want, "match": got == want}
    return checks


def one(exp, monitor, window, base, escrow):
    scratch = tempfile.mkdtemp(prefix="e7e8_")
    try:
        db, chain, inputs = checked_inputs(base, exp, monitor)
        pub, new, trials = run_verify(exp, monitor, window, db, chain, scratch, escrow)
        esc_cmp = bool(escrow and RUNS[(exp, monitor)].get("escrow"))
        ignore = {"params"} | (set() if esc_cmp else {"recovery"})
        if "signatures" not in pub:
            ignore.add("signatures")          # E7's file predates the verifier's signatures field
        a = {k: v for k, v in pub.items() if k not in ignore}
        b = {k: v for k, v in new.items() if k not in ignore}
        added = []
        if esc_cmp:
            # the restored copy's path is this run's temporary file
            a["recovery"] = strip_path(a.get("recovery"))
            b["recovery"] = strip_path(b.get("recovery"))
            if RUNS[(exp, monitor)].get("recovery_published_fields_only"):
                b["recovery"], added = published_fields(a["recovery"], b["recovery"], "/recovery")
        d = diff(a, b)
        checks = printed_checks(exp, monitor, window, pub, new, db, trials)
        if window == "main":
            checks.update(chain_checks(exp, monitor, chain, scratch))
        if esc_cmp:
            def rsum(r):
                r = r or {}
                rs = r.get("restore") if isinstance(r.get("restore"), dict) else {}
                return [r.get("escrow_lines"), len(r.get("seconds") or []), rs.get("restored"), rs.get("all_roots_reproduced")]
            got, want = rsum(new.get("recovery")), rsum(pub.get("recovery"))
            checks["recovery: escrow lines, flagged seconds recovered, restored copy written, its roots reproduced"] = {
                "recomputed": got, "published": want, "match": got == want}
        return {"experiment": exp, "monitor": monitor, "window": window, "inputs": inputs,
                "published": "exp/out/" + RUNS[(exp, monitor)]["verify"][window],
                "params": {k: pub["params"].get(k) for k in ("window", "snapshot_at", "scheme", "late_bound_s", "gap_s")},
                "trials_from": [os.path.relpath(f, REPO) for f in trials],
                "fields_compared": sorted(a), "fields_ignored": sorted(ignore & (set(pub) | set(new))),
                "recovery_compared": esc_cmp, "recovery_fields_added": added,
                "recovery_escrow": ("exp/out/" + RUNS[(exp, monitor)]["escrow"]) if esc_cmp else None,
                "identical_except_ignored": not d, "differences": d, "checks": checks,
                "match": not d and all(c["match"] for c in checks.values())}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--extracts", default=DEFAULT_EXTRACTS)
    ap.add_argument("--only", default="e7_main,e8_main")
    ap.add_argument("--escrow", action="store_true", help="pass the published escrow and compare the recovery section")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--out", default=os.path.join(REPO, "reproduce", "verify_e7e8_report.json"))
    ap.add_argument("--verifier", default=os.path.join(REPO, E8_CODE["verifier"][0]),
                    help="the verifier to run (default: the E8 copy, exp/stages/e7_verify_e8.py)")
    ap.add_argument("--monitor", default=os.path.join(REPO, E8_CODE["monitor"][0]),
                    help="the monitor the verifier loads (default: the E8 copy, monitor/monitor_e8.py)")
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s; pass --out for a new file" % a.out)
    code = {}
    for k, path in (("verifier", a.verifier), ("monitor", a.monitor)):
        default, want_sha = E8_CODE[k]
        got = sha256_file(path)
        is_default = os.path.abspath(path) == os.path.join(REPO, default)
        if is_default and got != want_sha:
            raise SystemExit("%s is not the E8 %s (sha256 %s, expected %s)" % (default, k, got, want_sha))
        code[k] = {"path": os.path.relpath(os.path.abspath(path), REPO), "sha256": got, "e8_version": got == want_sha}
    code_kind = "e8" if all(c["e8_version"] for c in code.values()) else "other"
    want = set(a.only.split(","))
    todo = [(exp, m, w) for (exp, m), cfg in RUNS.items() if exp in want for w in cfg["verify"]]
    print("code (%s): verifier %s (%s), monitor %s (%s)" % (
        "the E8 versions the published files were made with" if code_kind == "e8" else "NOT the E8 versions",
        code["verifier"]["path"], code["verifier"]["sha256"][:12], code["monitor"]["path"], code["monitor"]["sha256"][:12]),
        flush=True)
    print("inputs: extracts in %s; %d verifier runs" % (a.extracts, len(todo)), flush=True)
    rows = []
    scratch_root = tempfile.mkdtemp(prefix="e7e8_code_")
    try:
        use_code(a.verifier, a.monitor, scratch_root)
        with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
            for r in ex.map(lambda t: one(*t, a.extracts, a.escrow), todo):
                rows.append(r)
                nm = sum(c["match"] for c in r["checks"].values())
                print("  %s %-7s %-6s %s: %s; %d of %d printed-number checks match%s"
                      % (r["experiment"], r["monitor"], r["window"], "MATCH" if r["match"] else "MISMATCH",
                         "every compared field identical" if r["identical_except_ignored"]
                         else "%d field differences" % len(r["differences"]), nm, len(r["checks"]),
                         "" if r["identical_except_ignored"] else " (first: %s)" % r["differences"][0]), flush=True)
    finally:
        shutil.rmtree(scratch_root, ignore_errors=True)
    n_checks = sum(len(r["checks"]) for r in rows)
    n_ok = sum(c["match"] for r in rows for c in r["checks"].values())
    report = {"status": "ok" if rows and all(r["match"] for r in rows) else "mismatch",
              "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "script_sha256": sha256_file(os.path.abspath(__file__)),
              "code": code_kind, "verifier": code["verifier"]["path"], "monitor": code["monitor"]["path"],
              "e7_verify_sha256": code["verifier"]["sha256"],
              "monitor_sha256": code["monitor"]["sha256"],
              "python": sys.version.split()[0], "escrow": bool(a.escrow),
              "verifier_runs": len(rows), "verifier_runs_matching": sum(r["match"] for r in rows),
              "printed_number_checks": n_checks, "printed_number_checks_matching": n_ok,
              "runs": rows,
              "not_regenerated": ["the rendering of the escrow-restored copy (E7: true author shown again in 119 of 120 "
                                  "trials) needs a throwaway Home Assistant container; exp/out/e7_main_recovery_render.json "
                                  "holds it",
                                  "per-poll cost and seal delay (monitor cost logs of the run, not recorder rows)",
                                  "the hub and operator probes (configuration log of the run)"]}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "x") as fh:
        json.dump(report, fh, indent=1)
    print("status %s; %d of %d verifier runs MATCH; %d of %d printed-number checks MATCH; report %s"
          % (report["status"], report["verifier_runs_matching"], len(rows), n_ok, n_checks, a.out))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
