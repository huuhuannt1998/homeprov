"""R6 (T8/T10): observation-window latencies measured on the REAL deployment, from the saved snapshots and chains.

Section 7.6's latencies (55 segments on the demo-platform hub, 2026-08-24) have no raw data left (exp/out/r9_bd_unavailable.json).
The real-deployment runs kept everything needed to measure the same quantities on the main substrate, at its 5 s
observation interval, without re-running anything:

  - each anchor-chain record carries recv_ts, the time the anchor accepted it, and the one-second segments it sealed;
  - each recorder snapshot carries the rows of those segments with their recorded timestamps.

Only anchored one-second segments whose recomputed v1 root equals the anchored root are used (verify_all.py's rule), so
the snapshot rows are exactly the rows that were sealed; segments a trial touched or that gained late rows are excluded.
For each segment: close-to-anchor = recv_ts - (segment end); for each of its rows: write-to-anchor = recv_ts - row
timestamp (last_updated_ts / time_fired_ts, the instant the platform stamps). A row deleted d seconds after its write
escapes the commitment iff its write-to-anchor latency exceeds d; the escape probability at d is the fraction of rows
whose latency exceeds d (empirical survival function; exact 95% intervals are per row, and rows within a segment are
not independent, so the per-segment fraction at the segment's earliest row is reported beside it).

    python3 exp/sp2027/r6_window_latency_real.py     # writes exp/out/r6_window_latency_real.json (never overwrites)
"""
from __future__ import annotations

import collections
import datetime
import json
import os
import statistics
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import verify_all as VA  # noqa: E402
from rig import stats  # noqa: E402

DELAYS = (0.5, 1.0, 2.0, 5.0, 10.0, 15.0)


def first_anchoring(lines, t0, tsnap):
    """(gran, seg) -> (recv_ts, payload ts, acc, n) of the first chain record that sealed it."""
    out = {}
    for line in lines:
        rec = json.loads(line)
        p = rec.get("payload") or {}
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap) or p.get("evidence_unobservable"):
            continue
        for g, segs in (p.get("sealed") or {}).items():
            for s, v in (segs or {}).items():
                out.setdefault((g, str(s)), (rec.get("recv_ts"), p.get("ts"), v.get("acc"), v.get("n")))
    return out


def q(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summary(xs):
    return {"n": len(xs), "median": round(statistics.median(xs), 3), "p90": round(q(xs, 0.9), 3),
            "p99": round(q(xs, 0.99), 3), "max": round(max(xs), 3), "min": round(min(xs), 3)}


def main():
    dst = os.path.join(OUT, "r6_window_latency_real.json")
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", default=None)
    ap.add_argument("--extracts", default=None)
    ap.add_argument("--out", default=dst)
    a = ap.parse_args()
    dst = a.out
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    src = VA.default_inputs(a.snapshots, a.extracts)
    per_run, all_close, all_write, seg_min_write = {}, [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        for rid, cfg in VA.RUNS.items():
            db, chain, _info = src.checked(rid)
            res = json.load(open(os.path.join(OUT, cfg["result"])))
            w = res["window"]
            t0, t1, tsnap = w["t_start"], w["t_end"], w["recorder_snapshot_at"]
            M = VA.load_monitor(cfg["scheme"], tmp)
            fa = first_anchoring(VA.chain_lines(chain), t0, tsnap)
            nodes = M.load(db, since=(int(t0 // 3600) - 1) * 3600.0)
            by = collections.defaultdict(list)
            for n in nodes:
                by[str(int(n[0] // 1))].append(n)
            phi = M.commit(nodes, encoding="v1")["second"]
            close, write, used, skipped = [], [], 0, collections.Counter()
            for (g, s), (recv, pts, acc, n) in fa.items():
                if g != "second" or not (t0 - 1 <= int(s) <= t1 + 1):
                    continue
                got = phi.get(s)
                if not got or got["acc"] != acc or got["n"] != n:
                    skipped["root_differs_now"] += 1
                    continue
                if recv is None:
                    skipped["no_recv_ts"] += 1
                    continue
                used += 1
                close.append(recv - (int(s) + 1))
                lat = [recv - x[0] for x in by[s]]
                write.extend(lat)
                seg_min_write.append(min(lat))
            per_run[rid] = {"scheme": cfg["scheme"], "segments_used": used, "segments_skipped": dict(skipped),
                            "close_to_anchor_s": summary(close), "write_to_anchor_s": summary(write)}
            all_close += close
            all_write += write
    esc = {}
    for d in DELAYS:
        k = sum(1 for x in all_write if x > d)
        ci = stats.clopper_pearson(k, len(all_write))
        ks = sum(1 for x in seg_min_write if x > d)
        esc[str(d)] = {"rows_escaping": k, "rows": len(all_write), "rate": round(k / len(all_write), 4),
                       "ci95_rows": [round(ci["ci_lo"], 4), round(ci["ci_hi"], 4)],
                       "segments_whose_earliest_row_escapes": ks, "segments": len(seg_min_write)}
    out = {"item": "R6: observation-window latencies on the real deployment (5 s interval), from saved chains and snapshots",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "script_sha256": VA.sha256_file(os.path.abspath(__file__)),
           "inputs_mode": src.mode,
           "substrate": "real deployment, Home Assistant 2026.7.4, recorder commit_interval 1 s, monitor period 5 s",
           "pooled": {"close_to_anchor_s": summary(all_close), "write_to_anchor_s": summary(all_write)},
           "escape_if_deleted_d_seconds_after_write": esc, "per_run": per_run,
           "caveats": ["The ten runs share one deployment and overlapping hours (e_ps_clo, e_d_clo, e_c_clo windows are "
                       "distinct; rows are not double-counted because each run's segments are its own window).",
                       "Latency is measured from the platform's row timestamp, not from the commit to disk "
                       "(commit_interval 1 s).", "Rows within a segment share one anchoring time."]}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({k: out[k] for k in ("pooled", "escape_if_deleted_d_seconds_after_write")}, indent=1))


if __name__ == "__main__":
    main()
