"""E10 (round 14): re-verify the saved E7, E8 and E9 results with the PATCHED code, offline, after both patches are applied
(monitor/hardening_e10.patch, then exp/stages/verifier_e10.patch; not before 2026-10-19 16:01Z, E9's end). No Docker.
drafts/round13/E10_DESIGN.md section 6 lists the verdict changes each patch can cause and predicts which occur.

    <home>/miniconda3/bin/python3 testbed/e10/reverify_patched.py --out-dir <dir> \
        [--parts e7e8,verify_all,e9] [--e9-run-dir ../HOMEPROV-P13-exp/e9/e9_main2] [--e9-keep-days 30] [--jobs 2]

Three parts, each comparing the E9 code with the patched code on the same inputs (so every difference is a patch's):
  e7e8        reproduce/verify_e7e8.py's eight verifier runs (E7: closure and stable, one window; E8: stable and closure,
              windows main, base, stress), with --escrow, once with the E9 code (exp/stages/e7_verify_e9.py,
              monitor/monitor_e9.py) and once with the patched code (exp/stages/e7_verify.py, monitor/monitor.py). Each
              pass also reports its own MATCH / MISMATCH against the published files (the E9 code's pass reproduces
              E9_IMPL_NOTES.md section 6: 8 of 8 runs; E7's recovery and signatures fields predate E8).
  verify_all  reproduce/verify_all.py with the patched (hardened) monitor: the ten real-deployment runs (published numbers).
  e9          every verification e9_score.py runs on E9's run directory (each day against its end-of-day snapshot, each
              night's pre and post snapshot over the historical window, the no-rowbind and no-disconnect comparison
              jobs), with e9_score.py's own arguments: the E9 output is read from E9's verification cache when present
              (its key is e9_score.py's, computed with the E9 verifier's digest), else recomputed with the E9 code.
For every pair: every field except params (and the scorer's timing) is compared; the changed verdicts are listed one by
one (flagged seconds, attributable violations, excused violations, the late-row verdicts, root-unknown segments,
RESTORE / RESTORE_DONE acceptances, the arms' detections, the benign floor), each with the patch it comes from (D1 to
D5, hardening) and its evidence, or 'unattributed' (to be explained by hand before any number is used). Writes
<out-dir>/reverify_patched.json (never overwritten).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

R = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
PINNED = "<home>/miniconda3/bin/python3"
E9_CODE = {"verifier": ("exp/stages/e7_verify_e9.py", "9c42fad983a00e43083359339bc185c11d31ab7cdec7781f0e2cdee94ebea885"),
           "monitor": ("monitor/monitor_e9.py", "8ad9e2d77f2d098af1e81ed509445631dc3d3ba2d349fddff75bfd920a7ab8ae")}
PATCHED = {"verifier": "exp/stages/e7_verify.py", "monitor": "monitor/monitor.py"}
PATCH_MARK = {"monitor/monitor.py": "HOMEPROV_HARDEN", "exp/stages/e7_verify.py": "class ObservationBreaks"}
DEFAULT_E9 = os.path.join(os.path.dirname(R), "HOMEPROV-P13-exp", "e9", "e9_main2")
IGNORE = {"params", "_e9"}
D5_WHY = {"a_row_in_the_straddling_segment_changed",
          "a_row_in_the_straddling_segment_cannot_be_checked_without_binding_or_escrow"}


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def preconditions():
    bad = []
    if os.path.realpath(sys.executable) != os.path.realpath(PINNED) or sys.version_info < (3, 12):
        bad.append("interpreter %s %s (run with %s)" % (sys.executable, sys.version.split()[0], PINNED))
    for k, (p, want) in E9_CODE.items():
        q = os.path.join(R, p)
        if not os.path.exists(q) or sha(q) != want:
            bad.append("%s is not the E9 %s byte for byte" % (p, k))
    for p, mark in PATCH_MARK.items():
        if mark not in open(os.path.join(R, p)).read():
            bad.append("%s is not patched (no %r)" % (p, mark))
    if bad:
        raise SystemExit("REFUSING: " + "; ".join(bad))


# ------------------------------------------------------------------------------------------------ comparison
def full_diff(a, b, path="", out=None):
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if not path and k in IGNORE:
                continue
            if k not in a or k not in b:
                out.append({"path": "%s/%s" % (path, k), "only_in": "e9" if k in a else "patched"})
            else:
                full_diff(a[k], b[k], "%s/%s" % (path, k), out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            full_diff(x, y, "%s[%d]" % (path, i), out)
    elif a != b:
        out.append({"path": path, "e9": str(a)[:160], "patched": str(b)[:160]})
    return out


def _rows(x):
    out = {}
    for key, verdict in (("attributable_rows", "attributable"), ("benign_late_rows", "benign_late"),
                         ("unobserved_late_rows", "unobserved_late")):
        for r in x.get(key) or []:
            out[tuple(r.get("key") or ())] = dict(r, verdict=r.get("verdict", verdict))
    return out


def _viol(x, key):
    return {(v.get("gran"), str(v.get("seg")), v.get("rule")): v for v in x.get(key) or []}


def _strings(x):
    if isinstance(x, dict):
        for v in x.values():
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)
    elif isinstance(x, str):
        yield x


def summarize(e9, new):
    """The changed verdicts between the E9 code's output and the patched code's, each with its attribution."""
    if not isinstance(e9, dict) or not isinstance(new, dict) or "error" in e9 or "error" in new:
        return {"error": "missing or failed output", "e9": (e9 or {}).get("error"), "patched": (new or {}).get("error")}
    if "refused" in new:
        return {"refused_by_hardening": new["refused"], "attributed_to": "hardening"}
    ch = []
    ru_new = {(r.get("gran"), str(r.get("seg"))): r for r in new.get("root_unknown_segments") or []}
    ru_old = {(r.get("gran"), str(r.get("seg"))): r for r in e9.get("root_unknown_segments") or []}
    for k in sorted(set(ru_new) - set(ru_old), key=str):
        ch.append({"kind": "root_unknown_added", "gran": k[0], "seg": k[1], "why": ru_new[k].get("why"),
                   "attributed_to": "D2" if str(ru_new[k].get("why", "")).endswith(":no_row_now") else "unattributed"})
    for k in sorted(set(ru_old) - set(ru_new), key=str):
        ch.append({"kind": "root_unknown_removed", "gran": k[0], "seg": k[1], "attributed_to": "unattributed"})
    rn, ro = _rows(new), _rows(e9)
    for k in sorted(set(rn) | set(ro), key=str):
        a, b = ro.get(k), rn.get(k)
        va, vb = (a or {}).get("verdict"), (b or {}).get("verdict")
        if va == vb:
            continue
        why = (b or {}).get("why") or ""
        # a row's "why" is the verifier's list of per-segment verdicts ({gran, seg, verdict, why}); a bare string is
        # accepted too (fixed 2026-10-19: the synthetic tests used strings, the real outputs carry lists)
        whys = [w if isinstance(w, str) else ((w or {}).get("why") or "")
                for w in (why if isinstance(why, list) else [why])]
        att = ("D1" if any(w.startswith("observation_break:") for w in whys) else "D3" if vb == "excused_clock_step"
               else "unattributed")
        ch.append({"kind": "late_row_verdict", "key": list(k), "second": (b or a or {}).get("second"),
                   "e9": va, "patched": vb, "why": why or None, "attributed_to": att})
    vo, vn = _viol(e9, "violations"), _viol(new, "violations")
    eo, en = _viol(e9, "excused_violations"), _viol(new, "excused_violations")
    for k in sorted(set(vo) | set(vn), key=str):
        a, b = vo.get(k), vn.get(k)
        sa = None if a is None else bool(a.get("violation") and a.get("attributable"))
        sb = None if b is None else bool(b.get("violation") and b.get("attributable"))
        la, lb = (a or {}).get("localized_seconds"), (b or {}).get("localized_seconds")
        if sa == sb and la == lb:
            continue
        nx = (b or {}).get("not_excused_by_purge")
        if nx in D5_WHY:
            att = "D5"
        elif b is not None and (b.get("unlocalized_root_unknown_seconds") and not (a or {}).get("unlocalized_root_unknown_seconds")):
            att = "D2 (localisation: a second inside it is now root-unknown)"
        else:
            att = "unattributed"
        ch.append({"kind": "violation", "gran": k[0], "seg": k[1], "rule": k[2], "e9_attributable": sa,
                   "patched_attributable": sb, "e9_localized": la, "patched_localized": lb,
                   "e9_excused_by": (eo.get(k) or {}).get("excused_by"), "patched_not_excused_by_purge": nx,
                   "attributed_to": att})
    for k in sorted(set(eo) ^ set(en), key=str):
        b = vn.get(k) or {}
        ch.append({"kind": "excused_violation_" + ("removed" if k in eo else "added"), "gran": k[0], "seg": k[1],
                   "rule": k[2], "e9_excused_by": (eo.get(k) or {}).get("excused_by"),
                   "patched_excused_by": (en.get(k) or {}).get("excused_by"),
                   "patched_not_excused_by_purge": b.get("not_excused_by_purge"),
                   "attributed_to": "D5" if b.get("not_excused_by_purge") in D5_WHY else "unattributed"})
    d4 = sum(1 for s in _strings(new.get("restore")) if s == "no_hub_started_ts")
    if d4:
        ch.append({"kind": "restore_done_rejected", "n": d4, "attributed_to": "D4"})
    fo, fn = set(map(str, e9.get("flagged_seconds") or [])), set(map(str, new.get("flagged_seconds") or []))
    attr_by_sec = collections.defaultdict(set)
    for c in ch:
        for s in ([c.get("second")] if c.get("second") is not None else []) + \
                 [x for x in (c.get("e9_localized") or []) + (c.get("patched_localized") or [])] + \
                 ([c["seg"]] if c.get("gran") == "second" and c.get("seg") is not None else []):
            attr_by_sec[str(s)].add(c["attributed_to"])
    flagged = [{"second": s, "change": "added" if s in fn else "removed",
                "attributed_to": sorted(attr_by_sec.get(s) or {"unattributed"})} for s in sorted(fo ^ fn, key=int)]
    arms = None
    if e9.get("arms") != new.get("arms"):
        arms = {"e9": e9.get("arms"), "patched": new.get("arms")}
    floor = None
    if e9.get("benign_floor") != new.get("benign_floor"):
        floor = {"e9": e9.get("benign_floor"), "patched": new.get("benign_floor")}
    handled = {"flagged_seconds", "violations", "excused_violations", "attributable_rows", "benign_late_rows",
               "unobserved_late_rows", "root_unknown_segments", "arms", "benign_floor", "clock_step"}
    other = [d for d in full_diff(e9, new) if d["path"].split("/")[1].split("[")[0] not in handled]
    cs = new.get("clock_step")
    return {"flagged_seconds": {"e9": len(fo), "patched": len(fn), "changed": flagged},
            "verdict_changes": ch,
            "verdict_changes_by_patch": dict(collections.Counter(c["attributed_to"] for c in ch)),
            "arms_changed": arms, "benign_floor_changed": floor,
            "clock_step_field": None if cs is None else {"accepted": len(cs.get("accepted") or []),
                                                          "rejected": len(cs.get("rejected") or []),
                                                          "excused_rows": len(cs.get("excused_rows") or [])},
            "other_differences": other[:400], "other_differences_n": len(other),
            "unattributed": sum(1 for c in ch if c["attributed_to"] == "unattributed")
                            + sum(1 for f in flagged if f["attributed_to"] == ["unattributed"])}


# ------------------------------------------------------------------------------------------------ E7 / E8
def e7e8_pass(code, dump, extracts, jobs):
    """One pass of reproduce/verify_e7e8.py's eight runs with `code`'s verifier and monitor; raw outputs to `dump`."""
    VE = load(os.path.join(R, "reproduce", "verify_e7e8.py"), "verify_e7e8_" + code)
    v, m = ((E9_CODE["verifier"][0], E9_CODE["monitor"][0]) if code == "e9" else (PATCHED["verifier"], PATCHED["monitor"]))
    scratch = tempfile.mkdtemp(prefix="e10rv_%s_" % code)
    os.makedirs(dump, exist_ok=True)
    try:
        VE.use_code(os.path.join(R, v), os.path.join(R, m), scratch)
        orig = VE.run_verify

        def rv(exp, monitor, window, db, chain, scr, escrow):
            pub, new, trials = orig(exp, monitor, window, db, chain, scr, escrow)
            new = dict(new, recovery=VE.strip_path(new.get("recovery")))
            with open(os.path.join(dump, "%s_%s_%s.json" % (exp, monitor, window)), "w") as fh:
                json.dump(new, fh, sort_keys=True, default=str)
            return pub, new, trials
        VE.run_verify = rv
        todo = [(exp, mon, w) for (exp, mon), cfg in VE.RUNS.items() for w in cfg["verify"]]
        rows = []
        with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            for r in ex.map(lambda t: VE.one(*t, extracts, True), todo):
                rows.append({k: r[k] for k in ("experiment", "monitor", "window", "match", "identical_except_ignored")}
                            | {"differences_from_published": r["differences"],
                               "checks_failed": [n for n, c in r["checks"].items() if not c["match"]]})
        with open(os.path.join(dump, "rows.json"), "w") as fh:
            json.dump({"code": code, "verifier": v, "monitor": m, "rows": rows}, fh, indent=1, sort_keys=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def part_e7e8(out_dir, extracts, jobs):
    res = {}
    for code in ("e9", "patched"):
        dump = os.path.join(out_dir, "e7e8_" + code)
        r = subprocess.run([PINNED, os.path.abspath(__file__), "_e7e8_pass", "--code", code, "--dump", dump,
                            "--extracts", extracts, "--jobs", str(jobs)], capture_output=True, text=True, cwd=R)
        if r.returncode != 0:
            return {"error": "%s pass failed (rc %s)" % (code, r.returncode), "stderr": r.stderr[-3000:]}
        res[code] = json.load(open(os.path.join(dump, "rows.json")))
    cmp_ = {}
    for row in res["patched"]["rows"]:
        k = "%s_%s_%s" % (row["experiment"], row["monitor"], row["window"])
        a = json.load(open(os.path.join(out_dir, "e7e8_e9", k + ".json")))
        b = json.load(open(os.path.join(out_dir, "e7e8_patched", k + ".json")))
        cmp_[k] = summarize(a, b)
    return {"passes": {c: {"verifier": res[c]["verifier"], "monitor": res[c]["monitor"],
                           "runs_matching_published": sum(r["match"] for r in res[c]["rows"]),
                           "runs": len(res[c]["rows"]), "rows": res[c]["rows"]} for c in res},
            "e9_vs_patched": cmp_}


def part_verify_all(out_dir):
    dst = os.path.join(out_dir, "verify_all_patched.json")
    r = subprocess.run([PINNED, os.path.join(R, "reproduce", "verify_all.py"), "--out", dst],
                       capture_output=True, text=True, cwd=R)
    rep = json.load(open(dst)) if os.path.exists(dst) else None
    return {"rc": r.returncode, "report": os.path.relpath(dst, R) if rep else None,
            "status": (rep or {}).get("status"), "stdout_tail": r.stdout[-2000:], "stderr_tail": r.stderr[-1500:]}


# ------------------------------------------------------------------------------------------------ E9
def e9_jobs(ES, run_dir, keep_days, tag, reports_dir):
    """e9_score.py main()'s job list, unchanged in substance (its own Run, e9_args and verify_options); the harness
    reports are E9's own (<reports_dir>/<tag>_d<n>_report_*.json, as e9_score.py reads them)."""
    run = ES.Run(run_dir, tag, reports_dir)
    opts = ES.verify_options()
    extra, used, nm_args = ES.e9_args(run_dir, opts, keep_days, os.path.join(run_dir, "namemap_storage"))
    norb = ["--no-rowbind"] if "--no-rowbind" in opts else None
    jobs = []
    t_start = run.snap("start")
    hist_lo = None
    if t_start[0]:
        import sqlite3
        c = sqlite3.connect("file:%s?mode=ro" % t_start[0], uri=True)
        hist_lo = min(x for x in (c.execute("select min(last_updated_ts) from states").fetchone()[0],
                                  c.execute("select min(time_fired_ts) from events").fetchone()[0]) if x is not None)
        c.close()
    for d in run.days:
        n = d["day"]
        db, ts = run.snap("day%d_end" % n)
        last = n == run.days[-1]["day"]
        if db:
            for m in ES.MONITORS:
                jobs.append((m, "day%d" % n, db, ts, d["window"], run.day_reports(n), extra + (nm_args if last else [])))
                if norb:
                    jobs.append((m, "day%d_norowbind" % n, db, ts, d["window"], run.day_reports(n), extra + norb))
        for lab in ("night%d_pre" % n, "night%d_post" % n):
            db, ts = run.snap(lab)
            if db and hist_lo is not None:
                for m in ES.MONITORS:
                    jobs.append((m, lab, db, ts, [int(hist_lo) - 3600, run.start], [], extra))
                    if lab.endswith("_post") and "--no-purge-disconnect" in opts:
                        jobs.append((m, lab + "_nodisconnect", db, ts, [int(hist_lo) - 3600, run.start], [],
                                     extra + ["--no-purge-disconnect"]))
    return jobs, used


def e9_cache_key(ES, extra, window, tsnap, db, trials, verifier_sha):
    return hashlib.sha256(json.dumps([extra, window, tsnap, ES.sha(db), verifier_sha,
                                      sorted(os.path.basename(t) for t in trials or [])]).encode()).hexdigest()[:12]


def run_verifier(verifier, monitor_dir, sp, m, db, tsnap, window, trials, extra, dst, ES):
    cmd = [PINNED, os.path.join(R, verifier), "verify", "--chain", os.path.join(sp, "%s_chain.jsonl" % m), "--db", db,
           "--late-bound", str(ES.LATE_BOUND), "--gap-s", str(ES.GAP_S), "--snapshot-at", str(tsnap),
           "--scheme", "stable", "--window", str(window[0]), str(window[1]), "--out", dst,
           "--sign-pubkey", os.path.join(sp, "keys", "%s_sign_pub.pem" % m), "--monitor-dir", monitor_dir]
    esc = os.path.join(sp, "escrow_%s" % m, "escrow.jsonl")
    if os.path.exists(esc) and os.path.getsize(esc) > 0:
        cmd += ["--escrow", esc]
    if trials:
        cmd += ["--trials", *trials]
    cmd += extra
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=R)
    if r.returncode != 0 or not os.path.exists(dst):
        return {"error": "verifier failed", "rc": r.returncode, "stderr": r.stderr[-2000:], "cmd": " ".join(cmd)}
    return json.load(open(dst))


def part_e9(out_dir, run_dir, keep_days, jobs_n, tag, reports_dir):
    ES = load(os.path.join(R, "exp", "stages", "e9_score.py"), "e9_score_for_reverify")
    jobs, used = e9_jobs(ES, run_dir, keep_days, tag, reports_dir)
    e9_sha = E9_CODE["verifier"][1]
    scratch = tempfile.mkdtemp(prefix="e10rv_mon_")
    mon_e9 = os.path.join(scratch, "e9")
    os.makedirs(mon_e9)
    shutil.copyfile(os.path.join(R, E9_CODE["monitor"][0]), os.path.join(mon_e9, "monitor.py"))
    dump = os.path.join(out_dir, "e9")
    os.makedirs(dump, exist_ok=True)

    def one(j):
        m, label, db, tsnap, window, trials, extra = j
        key = e9_cache_key(ES, extra, window, tsnap, db, trials, e9_sha)
        cached = os.path.join(run_dir, "verify", "%s_%s_%s.json" % (m, label, key))
        if os.path.exists(cached):
            old, src = json.load(open(cached)), os.path.relpath(cached, os.path.dirname(R))
        else:
            old = run_verifier(E9_CODE["verifier"][0], mon_e9, run_dir, m, db, tsnap, window, trials, extra,
                               os.path.join(dump, "%s_%s_e9.json" % (m, label)), ES)
            src = "recomputed with the E9 code"
        new = run_verifier(PATCHED["verifier"], os.path.join(R, "monitor"), run_dir, m, db, tsnap, window, trials, extra,
                           os.path.join(dump, "%s_%s_patched.json" % (m, label)), ES)
        return "%s_%s" % (m, label), {"e9_source": src, **summarize(old, new)}

    try:
        with cf.ThreadPoolExecutor(max_workers=max(1, jobs_n)) as ex:
            res = dict(ex.map(one, jobs))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return {"run_dir": run_dir, "tag": tag, "jobs": len(jobs), "e9_options_used": used, "keep_days": keep_days, "comparisons": res}


def totals(parts):
    out = collections.Counter()
    flagged, errors, refused, unattributed = 0, [], [], 0
    for name, p in parts.items():
        for k_, c in ((p or {}).get("e9_vs_patched") or (p or {}).get("comparisons") or {}).items():
            for k, n in (c.get("verdict_changes_by_patch") or {}).items():
                out[k] += n
            flagged += len((c.get("flagged_seconds") or {}).get("changed") or [])
            unattributed += c.get("unattributed") or 0
            if "error" in c:
                errors.append("%s/%s" % (name, k_))
            if "refused_by_hardening" in c:
                refused.append("%s/%s" % (name, k_))
    return {"verdict_changes_by_patch": dict(out), "flagged_seconds_changed": flagged, "unattributed": unattributed,
            "comparisons_failed": errors, "refused_by_hardening": refused,
            "verify_all_status": ((parts.get("verify_all") or {}).get("status"))}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "_e7e8_pass":
        ap = argparse.ArgumentParser()
        ap.add_argument("_mode")
        ap.add_argument("--code", choices=("e9", "patched"), required=True)
        ap.add_argument("--dump", required=True)
        ap.add_argument("--extracts", required=True)
        ap.add_argument("--jobs", type=int, default=2)
        a = ap.parse_args()
        e7e8_pass(a.code, a.dump, a.extracts, a.jobs)
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--parts", default="e7e8,verify_all,e9")
    ap.add_argument("--e9-run-dir", default=DEFAULT_E9)
    ap.add_argument("--e9-keep-days", type=int, default=30, help="as e9_score.py was run (its --keep-days)")
    ap.add_argument("--e9-tag", default="e9_main2", help="E9's tag (run_e9.sh TAG): its harness reports' prefix")
    ap.add_argument("--e9-reports-dir", default=os.path.join(R, "exp", "out"), help="where E9's harness reports are")
    ap.add_argument("--extracts", default=os.path.join(R, "reproduce", "snapshots", "e7e8"))
    ap.add_argument("--jobs", type=int, default=2)
    a = ap.parse_args()
    preconditions()
    dst = os.path.join(a.out_dir, "reverify_patched.json")
    if os.path.exists(dst):
        raise SystemExit("REFUSING: %s exists" % dst)
    os.makedirs(a.out_dir, exist_ok=True)
    parts = {}
    want = a.parts.split(",")
    if "e7e8" in want:
        parts["e7e8"] = part_e7e8(a.out_dir, a.extracts, a.jobs)
    if "verify_all" in want:
        parts["verify_all"] = part_verify_all(a.out_dir)
    if "e9" in want:
        parts["e9"] = part_e9(a.out_dir, a.e9_run_dir, a.e9_keep_days, a.jobs, a.e9_tag, a.e9_reports_dir)
    code = {k: {"path": p, "sha256": sha(os.path.join(R, p))} for k, p in PATCHED.items()}
    code.update({"e9_" + k: {"path": p, "sha256": s} for k, (p, s) in E9_CODE.items()})
    for p in ("monitor/hardening_e10.patch", "exp/stages/verifier_e10.patch"):
        code[os.path.basename(p)] = {"path": p, "sha256": sha(os.path.join(R, p))}
    out = {"check": "E10: E7, E8, E9 re-verified with the patched code", "generated_at": dt.datetime.now(
           dt.timezone.utc).isoformat(), "python": sys.version.split()[0], "code": code, "parts": parts,
           "totals": totals(parts)}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print(json.dumps(out["totals"]))
    print("wrote", dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
