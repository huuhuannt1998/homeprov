"""Round 17 (review r6), exploratory: regression of verifier version 2 against the registered verifier's saved outputs.

For every saved verification of a registered run (the JSON files the scorers cached under <run dir>/verify/, written by
exp/stages/e7_verify.py, sha256 ae9d9c42..., the file E10, E10b and E12 registered), this script re-runs the same
verification with exp/stages/verify_v2.py: the arguments are read back from the saved output itself (its "params";
the monitor's public key by the scorers' file convention, checked against the saved key fingerprint; E12's trial
reports and name-map storage by e9_score.py's convention), and the committed column list is supplied from the start
snapshot of the run's stack, so the pinned-column code path runs (and the two-roots rule, always on). It then compares:
  - bytes: e7_verify's output part of the v2 output (everything but "v2"), serialised exactly as e7_verify writes it,
    against the saved file (SHA-256 and size);
  - seconds: the per-second output (exp/stages/e10_outcome.py outcome(): match, violation, violation_coarse_only,
    unknown) of every second of the verification window, from the v2 result and, when the bytes differ, from the saved
    file's flagged, root-unknown, unobserved and coarse sets over the same chain timeline.
The saved files and the run directories are only read. Results go to --scratch (one JSON line per verification, so an
interrupted run resumes) and, with --final, to --out (never overwritten).

    python3 exp/stages/r17_v2_regress.py --exp e10 --run-dir <run dir> --scratch <dir> [--only LABEL ...]
            [--skip LABEL ...] [--deadline 2026-10-27T03:20:00Z] [--final --out exp/out/r17_v2_regress_e10.json]
"""
from __future__ import annotations

import argparse
import calendar
import collections
import glob
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import verify_v2 as VV                          # noqa: E402
import e10_outcome as OC                        # noqa: E402

EV = VV.EV
TOP = re.compile(rb'^ "([^"]+)": ')


def top_level(path, wanted):
    """Top-level values of a JSON file written by json.dumps(indent=1, sort_keys=True), read line by line."""
    got, cur, buf = {}, None, []

    def finish():
        if cur in wanted:
            t = b"".join(buf).rstrip()
            if t.endswith(b","):
                t = t[:-1]
            got[cur] = json.loads(t)
    with open(path, "rb") as fh:
        for line in fh:
            m = TOP.match(line)
            if m:
                finish()
                cur, buf = m.group(1).decode(), []
                if cur in wanted:
                    buf.append(line[m.end():])
            elif line.startswith(b"}") and not line.startswith(b"} "):
                finish()
                cur, buf = None, []
            elif cur in wanted:
                buf.append(line)
    return got


def fp_of(M, path):
    return M.public_key_fingerprint(M.load_public_key(path))


def start_snapshot(run_dir, stack_dir):
    for c in (os.path.join(stack_dir, "snapshots", "start.db"), os.path.join(run_dir, "snapshots", "start.db")):
        if os.path.exists(c):
            return c
    return None


class Args:
    pass


def build_args(exp, run_dir, saved, label, last_day=None):
    want = {"params", "signatures", "trials", "namemap"}
    t = top_level(saved, want)
    p = t["params"]
    a = Args()
    a.cmd, a.chain, a.db = "verify", p["chain"], p["db"]
    a.late_bound, a.gap_s, a.scheme = float(p["late_bound_s"]), float(p["gap_s"]), p["scheme"]
    a.window, a.snapshot_at = p["window"], p["snapshot_at"]
    a.escrow = p.get("escrow")
    a.restore_out = None
    a.allow_unsigned = False
    a.operator_key = None
    if p.get("operator_key_given"):
        raise SystemExit("%s: an operator HMAC key was given; not reproducible here" % saved)
    a.operator_pubkey = p.get("operator_pubkey")
    a.purge_keep_s = p.get("purge_keep_s")
    a.purge_tol_s = p.get("purge_tol_s", 0.0)
    a.restore_tol_s = p.get("restore_tol_s")
    a.restore_max_age_s = p.get("restore_max_age_s", EV.RESTORE_MAX_AGE_S)
    a.restore_done_max_s = p.get("restore_done_max_s", EV.RESTORE_DONE_MAX_S)
    a.no_purge_disconnect = p.get("purge_disconnect") is False
    a.no_rowbind = p.get("rowbind") is False
    a.no_harden = p.get("harden") is False
    a.monitor_dir = EV.DEFAULT_MONITOR_DIR
    a.out = None
    a.namemap_storage = None
    a.trials = None
    m = os.path.basename(a.chain).split("_")[0]
    keys = [os.path.join(os.path.dirname(a.chain), "%s_sign_pub.pem" % m),
            os.path.join(run_dir, "keys", "%s_sign_pub.pem" % m)]
    a.sign_pubkey = next((k for k in keys if os.path.exists(k)), None)
    if "trials" in t:
        if exp not in ("e12", "e9"):
            raise SystemExit("%s: trials given; only E9-style runs are reconstructed" % saved)
        import e9_score as S9                          # noqa: E402,PLC0415  (frozen; imported, not edited)
        tag = os.path.basename(run_dir.rstrip("/"))
        n = int(re.match(r"day(\d+)", label).group(1))
        a.trials = sorted(glob.glob(os.path.join(REPO, "exp", "out", "%s_d%d_report_*.json" % (tag, n))))
        _ = S9
    if exp in ("e12", "e9") and last_day is not None and label == "day%d" % last_day:
        # e9_score.py: the name-map storage goes to the last day's verification only (not its --no-rowbind twin)
        stor = os.path.join(run_dir, "namemap_storage")
        a.namemap_storage = stor if os.path.isdir(stor) else None
    a.pinned_columns_db = None
    a.pinned_columns_json = None
    a.pinned_json = None
    a.pinned_columns_label = None
    a.conflict_rule = "strict"
    return a, t


def second_outcomes(res, lo, hi):
    OC.annotate(res)
    c = collections.Counter()
    per = {}
    for s in range(lo, hi + 1):
        o = OC.outcome(res, s)
        c[o] += 1
        per[s] = o
    return c, per


def frozen_outcomes(saved, res_v2, lo, hi):
    """Per-second outputs of the saved (registered) result over the same chain timeline (P, TL of the v2 run, which
    the chain alone determines)."""
    t = top_level(saved, {"flagged_seconds", "root_unknown_segments", "unobserved_late_rows", "flagged_segments"})
    fake = {"flagged_seconds": t.get("flagged_seconds"), "root_unknown_segments": t.get("root_unknown_segments"),
            "unobserved_late_rows": t.get("unobserved_late_rows"), "flagged_segments": t.get("flagged_segments"),
            "P": res_v2["P"], "TL": res_v2["TL"], "roots": res_v2["roots"]}
    return second_outcomes(fake, lo, hi)


def one(exp, run_dir, saved, label, scratch, keep_outputs, last_day=None):
    a, t = build_args(exp, run_dir, saved, label, last_day)
    M = EV.load_monitor("stable", os.path.join(scratch, "keycheck"))
    sig = t.get("signatures") or {}
    if a.sign_pubkey is None or fp_of(M, a.sign_pubkey) != sig.get("pubkey_fp"):
        raise SystemExit("%s: no public key file matches the saved fingerprint %s" % (saved, sig.get("pubkey_fp")))
    stack_dir = os.path.dirname(a.chain)
    start = start_snapshot(run_dir, stack_dir)
    a.pinned_columns_db = start
    t0 = time.time()
    out, res = VV.run_v2(a)
    wall = round(time.time() - t0, 1)
    v2 = out.pop("v2")
    dst = os.path.join(scratch, "v2_" + os.path.basename(saved))
    h = hashlib.sha256()
    with open(dst, "w") as fh:
        for chunk in json.JSONEncoder(indent=1, sort_keys=True, default=str).iterencode(out):
            fh.write(chunk)
            h.update(chunk.encode())
    v2_sha, v2_size = h.hexdigest(), os.path.getsize(dst)
    saved_sha, saved_size = VV.sha256_file(saved), os.path.getsize(saved)
    identical = v2_sha == saved_sha and v2_size == saved_size
    lo, hi = int(float(a.window[0])), int(float(a.window[1]))
    hi = min(hi, int(float(a.snapshot_at))) if a.snapshot_at is not None else hi
    cnt, per = second_outcomes(res, lo, hi)
    row = {"label": label, "monitor": os.path.basename(a.chain).split("_")[0], "saved": saved,
           "saved_sha256": saved_sha, "saved_bytes": saved_size, "v2_sha256": v2_sha, "v2_bytes": v2_size,
           "bytes_identical": identical, "window": [lo, hi], "seconds_compared": hi - lo + 1,
           "v2_second_outputs": dict(cnt), "wall_s": wall,
           "pinned_columns_db": start, "pinned_source_check": v2["column_list"].get("roots_checked_by_source"),
           "column_mode": v2["column_list"].get("mode"),
           "added_since_sealing": v2["column_list"].get("added_since_sealing_not_read"),
           "dropped": {d: x["dropped_now"] for d, x in (v2["column_list"].get("lists") or {}).items()},
           "conflicts": v2["conflict_rule"]["segments_with_two_or_more_signed_roots"],
           "conflict_violations": v2["conflict_rule"]["in_window_reported_as_violation"],
           "flagged_seconds": len(res["flagged_seconds"]),
           "trials": [os.path.basename(x) for x in a.trials or []], "namemap_storage": a.namemap_storage,
           "v2_code_sha256": v2["code_sha256"]}
    if identical:
        row.update(seconds_identical=hi - lo + 1, seconds_differing=0, differing=[])
        if not keep_outputs:
            os.remove(dst)
    else:
        fc, fper = frozen_outcomes(saved, res, lo, hi)
        diff = [{"second": s, "registered": fper[s], "v2": per[s]} for s in range(lo, hi + 1) if fper[s] != per[s]]
        row.update(registered_second_outputs=dict(fc), seconds_identical=hi - lo + 1 - len(diff),
                   seconds_differing=len(diff), differing=diff[:500], v2_output_kept=dst)
    return row


def labels_of(exp, verify_dir):
    out = []
    for f in sorted(glob.glob(os.path.join(verify_dir, "*.json"))):
        b = os.path.basename(f)[:-5]
        if exp in ("e10", "e10b"):
            m = re.fullmatch(r"(e10s|e10u|e10bs)_(direct|copy)_(.+)_([0-9a-f]{12})", b)
            if not m:
                continue
            stack, mon, lab = m.group(1), m.group(2), m.group(3)
            if lab.endswith("_e9"):
                continue                               # verified with the E9 verifier (a different, earlier file)
            out.append(("%s/%s/%s" % (stack, mon, lab), lab, f))
        else:
            m = re.fullmatch(r"(direct|copy)_(.+)_([0-9a-f]{12})", b) or re.fullmatch(r"(direct|copy)_(.+)_patched", b)
            if not m:
                continue
            out.append(("%s/%s" % (m.group(1), m.group(2)), m.group(2), f))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--exp", required=True, choices=("e10", "e10b", "e12", "e9"))
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--verify-dir", default=None)
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--skip", nargs="*", default=[])
    ap.add_argument("--deadline", default=None, help="UTC; no verification starts after it")
    ap.add_argument("--keep-outputs", action="store_true")
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--order", choices=("name", "size", "size_desc"), default="name")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    vd = a.verify_dir or os.path.join(a.run_dir, "verify")
    os.makedirs(a.scratch, exist_ok=True)
    # several processes may share one scratch directory: each writes its own log, claims a verification by creating
    # claims/<key> exclusively before running it, and reads every log as done
    log = os.path.join(a.scratch, "r17_v2_regress_%s_%d.jsonl" % (a.exp, os.getpid()))
    claims = os.path.join(a.scratch, "claims")
    os.makedirs(claims, exist_ok=True)

    def read_done():
        d = {}
        for f in sorted(glob.glob(os.path.join(a.scratch, "r17_v2_regress_%s*.jsonl" % a.exp))):
            for l in open(f):
                if l.strip():
                    r = json.loads(l)
                    if not r.get("error") or r["key"] not in d:
                        d[r["key"]] = r
        return d
    done = read_done()
    jobs = labels_of(a.exp, vd)
    if a.order != "name":
        jobs.sort(key=lambda j: os.path.getsize(j[2]), reverse=a.order == "size_desc")
    days = [int(m.group(1)) for _k, lab, _f in jobs for m in [re.fullmatch(r"day(\d+)", lab)] if m]
    last_day = max(days) if days else None
    deadline = calendar.timegm(time.strptime(a.deadline, "%Y-%m-%dT%H:%M:%SZ")) if a.deadline else None
    for key, label, f in jobs:
        if (a.only and key not in a.only) or key in a.skip or key in done:
            continue
        try:
            os.close(os.open(os.path.join(claims, key.replace("/", "__")), os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError:
            continue
        if deadline and time.time() > deadline:
            print("deadline reached; stopping before %s" % key, flush=True)
            break
        print("%s %s ..." % (time.strftime("%H:%M:%SZ", time.gmtime()), key), flush=True)
        try:
            row = one(a.exp, a.run_dir, f, label, a.scratch, a.keep_outputs, last_day)
        except SystemExit as exc:
            row = {"label": label, "saved": f, "error": str(exc)}
        except Exception as exc:                                          # noqa: BLE001
            row = {"label": label, "saved": f, "error": repr(exc)[:500]}
        row["key"] = key
        with open(log, "a") as fh:
            fh.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        done[key] = row
        print("  %s identical=%s seconds=%s differing=%s wall=%ss %s" % (
            key, row.get("bytes_identical"), row.get("seconds_compared"), row.get("seconds_differing"),
            row.get("wall_s"), row.get("error", "")), flush=True)
    if a.final:
        done = read_done()
        if not a.out or os.path.exists(a.out):
            raise SystemExit("REFUSING: --out missing or exists")
        rows = [done[k] for k, _l, _f in jobs if k in done]
        summ = {"checks": len(rows), "bytes_identical": sum(1 for r in rows if r.get("bytes_identical")),
                "errors": sum(1 for r in rows if r.get("error")),
                "seconds_compared": sum(r.get("seconds_compared") or 0 for r in rows),
                "seconds_identical": sum(r.get("seconds_identical") or 0 for r in rows),
                "seconds_differing": sum(r.get("seconds_differing") or 0 for r in rows),
                "not_run": [k for k, _l, _f in jobs if k not in done]}
        res = {"check": "r17 v2 regression against the registered verifier's saved outputs (%s), exploratory" % a.exp,
               "run_dir": a.run_dir, "verify_dir": vd, "code_sha256": VV.code_hashes(), "summary": summ,
               "checks": rows, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        with open(a.out, "x") as fh:
            json.dump(res, fh, indent=1, sort_keys=True, default=str)
        print("wrote", a.out)


if __name__ == "__main__":
    main()
