#!/usr/bin/env python3
"""Build per-run window extracts of the HOMEPROV verifier snapshots, small enough to publish.

    python3 reproduce/make_window_extracts.py [--snapshots DIR] [--out DIR] [--margin 2.0]

verify_all.py and the shipped monitor read only recorder rows at or after `since = (floor(t0/3600) - 1) * 3600`, and the
verifier checks only segments whose start lies within the run window plus or minus one segment width. Rows older than
`since` are therefore never folded into an in-window segment. For each run this script copies the recorder's schema and,
from the tables the monitor and verifier read, keeps:
  - states with since - margin <= last_updated_ts <= tsnap + 7200, and any states referenced by state_id in the run's
    trial records (row_before, laundered_state_ids, swapped_state_ids) in case one lies outside that range;
  - events with time_fired_ts >= since - margin, plus a safety margin to tsnap + 7200;
  - the states_meta, event_types, event_data and state_attributes rows those rows reference;
  - recorder_runs rows overlapping [since, tsnap].
Everything else (statistics*, schema_changes, migration_changes, and all older history) is dropped. The result is a valid
recorder database on which verify_all.py reproduces the same flagged, attributable, ambiguous and benign-floor numbers,
because every in-window segment's rows are present in full.

Each extract carries no absolute path and no identifying text (recorder rows are entity ids, states and timestamps). The
script writes a new directory of extracts plus an EXTRACTS_SHA256SUMS and a manifest; it never writes to the snapshots.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "exp", "out")
DEFAULT_SNAP = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-snapshots", "verifier-recorder-snapshots-2026-10")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as VA  # reuse its RUNS table and window logic  # noqa: E402

DROP_TABLES = {"statistics", "statistics_meta", "statistics_runs", "statistics_short_term", "schema_changes",
               "migration_changes", "sqlite_stat1"}


def ro(db):
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db)), uri=True)


def referenced_state_ids(res):
    ids = set()
    for t in res.get("trials", []):
        for k in ("row_before", "judged_row", "forged_row"):
            r = t.get(k)
            if isinstance(r, dict) and r.get("state_id"):
                ids.add(r["state_id"])
        ids.update(t.get("laundered_state_ids") or [])
        ids.update(t.get("swapped_state_ids") or [])
    return {i for i in ids if isinstance(i, int)}


def build(run_id, snap, out_dir, margin):
    cfg = VA.RUNS[run_id]
    src = os.path.join(snap, cfg["db"])
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    win = res["window"]
    t0, tsnap = win["t_start"], win["recorder_snapshot_at"]
    since = (int(t0 // 3600) - 1) * 3600.0
    lo = since - margin
    hi = tsnap + 7200.0
    ref_sids = referenced_state_ids(res)
    dst = os.path.join(out_dir, run_id + ".db")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    con = ro(src)
    schema = [r[0] for r in con.execute(
        "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type DESC")]
    out = sqlite3.connect(dst)
    out.execute("PRAGMA journal_mode=OFF")
    kept = {}
    try:
        for s in schema:
            out.execute(s)
        # states: in-window, plus referenced older rows
        placeholders = ",".join("?" * len(ref_sids)) if ref_sids else ""
        where = "(last_updated_ts >= ? AND last_updated_ts <= ?)" + (f" OR state_id IN ({placeholders})" if ref_sids else "")
        rows = list(con.execute(f"SELECT * FROM states WHERE {where}", (lo, hi, *sorted(ref_sids))))
        cols = [c[1] for c in con.execute("PRAGMA table_info(states)")]
        out.executemany(f"INSERT INTO states VALUES ({','.join('?' * len(cols))})", rows)
        kept["states"] = len(rows)
        meta_ids = {r[cols.index("metadata_id")] for r in rows if r[cols.index("metadata_id")] is not None}
        attr_ids = {r[cols.index("attributes_id")] for r in rows if r[cols.index("attributes_id")] is not None}
        # events: in-window
        erows = list(con.execute("SELECT * FROM events WHERE time_fired_ts >= ? AND time_fired_ts <= ?", (lo, hi)))
        ecols = [c[1] for c in con.execute("PRAGMA table_info(events)")]
        out.executemany(f"INSERT INTO events VALUES ({','.join('?' * len(ecols))})", erows)
        kept["events"] = len(erows)
        etype_ids = {r[ecols.index("event_type_id")] for r in erows if r[ecols.index("event_type_id")] is not None}
        data_ids = {r[ecols.index("data_id")] for r in erows if r[ecols.index("data_id")] is not None}
        # referenced metadata / lookups (keep ALL of these tiny tables; they carry no window rows)
        for tab, key, keep in (("states_meta", "metadata_id", None), ("event_types", "event_type_id", None),
                               ("state_attributes", "attributes_id", attr_ids), ("event_data", "data_id", data_ids)):
            trows = list(con.execute(f"SELECT * FROM {tab}"))
            tcols = [c[1] for c in con.execute(f"PRAGMA table_info({tab})")]
            if keep is not None:
                ki = tcols.index(key)
                trows = [r for r in trows if r[ki] in keep]
            out.executemany(f"INSERT INTO {tab} VALUES ({','.join('?' * len(tcols))})", trows)
            kept[tab] = len(trows)
        rr = list(con.execute("SELECT * FROM recorder_runs WHERE start IS NULL OR 1=1"))
        rcols = [c[1] for c in con.execute("PRAGMA table_info(recorder_runs)")]
        out.executemany(f"INSERT INTO recorder_runs VALUES ({','.join('?' * len(rcols))})", rr)
        kept["recorder_runs"] = len(rr)
        out.commit()
        out.execute("VACUUM")
        out.commit()
    finally:
        out.close()
        con.close()
    size = os.path.getsize(dst)
    chain_src = (os.path.join(OUT, cfg["chain"][5:]) if cfg["chain"].startswith("@out/")
                 else os.path.join(snap, cfg["chain"]))
    chain_dst = os.path.join(out_dir, run_id + ".chain.jsonl" + (".gz" if chain_src.endswith(".gz") else ""))
    if os.path.exists(chain_dst):
        raise SystemExit("refusing to overwrite " + chain_dst)
    shutil.copyfile(chain_src, chain_dst)
    return {"run": run_id, "db": run_id + ".db", "chain": os.path.basename(chain_dst),
            "chain_sha256": VA.sha256_file(chain_dst), "since": since, "window": [t0, win["t_end"], tsnap],
            "kept_rows": kept, "referenced_older_states": len(ref_sids), "bytes": size,
            "under_100MB": size < 100 * 1024 * 1024, "sha256": VA.sha256_file(dst),
            "source_sha256": VA.sha256_file(src)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=os.environ.get("HOMEPROV_SNAPSHOTS", DEFAULT_SNAP))
    ap.add_argument("--out", default=os.path.join(REPO, "reproduce", "window_extracts"))
    ap.add_argument("--margin", type=float, default=2.0)
    ap.add_argument("--runs", default=",".join(VA.RUNS))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    manifest = {"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "script_sha256": VA.sha256_file(os.path.abspath(__file__)), "margin_s": a.margin, "runs": {}}
    for rid in [r for r in a.runs.split(",") if r]:
        cfg = VA.RUNS[rid]
        if cfg["db"].startswith("hp_d2"):
            # e_d_auth uses the shared live recorder copy, not a per-run verifier snapshot; extract it too
            pass
        print(f"extracting {rid} ...", flush=True)
        m = build(rid, a.snapshots, a.out, a.margin)
        manifest["runs"][rid] = m
        print(f"  {rid}: {m['bytes']/1e6:.1f} MB ({'OK' if m['under_100MB'] else 'OVER 100MB'}) kept {m['kept_rows']}", flush=True)
    # also copy the chains the verifier needs (text, already small) and SHA256SUMS lines
    sums = {}
    for rid, m in manifest["runs"].items():
        sums[m["db"]] = m["sha256"]
        sums[m["chain"]] = m["chain_sha256"]
    with open(os.path.join(a.out, "EXTRACTS_SHA256SUMS"), "w") as fh:
        for name in sorted(sums):
            fh.write(f"{sums[name]}  ./{name}\n")
    with open(os.path.join(a.out, "extract_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)
    over = [r for r, m in manifest["runs"].items() if not m["under_100MB"]]
    print(f"wrote {len(manifest['runs'])} extracts to {a.out}" + (f"; OVER 100MB: {over}" if over else "; all under 100MB"))
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
