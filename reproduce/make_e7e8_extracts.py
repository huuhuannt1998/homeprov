#!/usr/bin/env python3
"""Build the E7 and E8 recorder window extracts: every recorder row the E7/E8 verifier reads, small enough to publish.

    python3 reproduce/make_e7e8_extracts.py [--e7-db RECORDER.db] [--e8-db RECORDER.db] [--out DIR] [--margin 2.0]

E7 and E8 were scored by the E8 version of the verifier (kept as exp/stages/e7_verify_e8.py; exp/stages/e7_verify.py
is now the E9 version) on the recorder copy each run saved at its end (one copy per run, read by both of its
monitors). The verifier reads, from that copy,
  - every row the E8 monitor's load() (monitor/monitor_e8.py) returns for the window: states and events with a
    timestamp at or after since = (floor(t_start/3600) - 1) * 3600 (the earliest such since over the run's windows,
    and the earliest re-read start any poll of either chain records, are used);
  - every row of every key range a poll's keylog committed (monitor.keylog_rows: by key, whatever its timestamp, with
    LEFT JOINs, so a row parked in the future, unjoinable or re-keyed is read too): every state and event whose key is
    above the lowest keylog bound either chain records;
  - the rows the paper's counting rule looks up for the trials (reproduce/verify_all.py touched_segments): the states a
    trial names by key and the events that carry a context id a trial names;
  - every row whose timestamp is not a finite number and every row holding a TEXT value that is not valid UTF-8
    (e7_verify lists them from the whole table);
  - the states_meta, event_types, state_attributes and event_data rows those rows join, and recorder_runs.
This script keeps exactly those rows (a superset where a rule is broader than the verifier's own read) and drops the
rest (older history, statistics*, schema_changes, migration_changes). Rows are copied by SQLite itself (INSERT ...
SELECT from the attached copy, which is opened read-only), so every value keeps its storage class and bytes, every key
is unchanged and the schema (column order included, which the stable-columns node hash depends on) is the original's.
reproduce/verify_e7e8.py re-runs that verifier on the extracts and compares its output with the published verify
files.

Each experiment's extract (<exp>.db) is written next to a byte-for-byte copy of each monitor's anchor chain
(<exp>_<monitor>.chain.jsonl.gz, the same bytes as exp/out/<exp>_<monitor>_chain.jsonl.gz), with
EXTRACTS_E7E8_SHA256SUMS and extract_manifest_e7e8.json. The earlier runs' extracts and their EXTRACTS_SHA256SUMS
(reproduce/make_window_extracts.py) are left as they are. Recorder rows are entity ids, states, attributes, event data,
timestamps and random context ids; the script writes no absolute path. It never writes to the source copies and refuses
to overwrite an output.
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
RUNS_DIR = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-exp")

# Per experiment: the saved recorder copy (in the run directory, not shipped), the monitors with their chains, and the
# published verify file of every scored window (its params give the window, snapshot time and scheme).
EXPERIMENTS = {
    "e7_main": {"db": os.path.join(RUNS_DIR, "e7", "e7_main", "recorder.db"), "score": "e7_main_score.json",
                "monitors": {"closure": {"chain": "e7_main_closure_chain.jsonl.gz",
                                         "verify": {"main": "e7_main_closure_verify.json"}},
                             "stable": {"chain": "e7_main_stable_chain.jsonl.gz",
                                        "verify": {"main": "e7_main_stable_verify.json"}}}},
    "e8_main": {"db": os.path.join(RUNS_DIR, "e8", "e8_main", "recorder.db"), "score": "e8_main_score.json",
                "monitors": {"stable": {"chain": "e8_main_stable_chain.jsonl.gz", "pubkey": "e8_main_stb_sign_pub.pem",
                                        "verify": {w: "e8_main_stable_verify_%s.json" % w
                                                   for w in ("main", "base", "stress")}},
                             "closure": {"chain": "e8_main_closure_chain.jsonl.gz", "pubkey": "e8_main_clo_sign_pub.pem",
                                         "verify": {w: "e8_main_closure_verify_%s.json" % w
                                                    for w in ("main", "base", "stress")}}}},
}
TS_OK = "typeof({c}) IN ('real', 'integer') AND abs({c}) < 1e12"      # monitor.TS_OK
TEXT_TABLES = ("states", "events", "states_meta", "event_types", "event_data", "state_attributes")   # e7_verify.RAW_TABLES


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ro_uri(db):
    return "file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db))


def report_files(exp):
    """The harness reports the published verify files were scored with (from the run's score file)."""
    rf = json.load(open(os.path.join(OUT, EXPERIMENTS[exp]["score"])))["report_files"]
    files = rf if isinstance(rf, list) else sorted({f for v in rf.values() for f in v})
    return [os.path.join(REPO, f) for f in files]


def walk(x, key=""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from walk(v, k)
    elif isinstance(x, list):
        for v in x:
            yield from walk(v, key)
    else:
        yield key, x


B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ctx_bytes(v):
    """A context id as the recorder stores it (16 bytes), from its hex or ULID form; None if it is neither."""
    if not isinstance(v, str):
        return None
    if len(v) == 32:
        try:
            return bytes.fromhex(v)
        except ValueError:
            return None
    if len(v) == 26 and all(ch in B32 for ch in v.upper()):
        n = 0
        for ch in v.upper():
            n = n * 32 + B32.index(ch)
        return n.to_bytes(16, "big") if n < (1 << 128) else None
    return None


def referenced(files):
    """State keys, event keys and context ids the trials name (any field that holds one)."""
    sids, eids, ctxs = set(), set(), set()
    for f in files:
        for t in json.load(open(f)).get("trials", []):
            for k, v in walk(t):
                if isinstance(v, bool):
                    continue
                if k.endswith("state_id") or k.endswith("state_ids"):
                    if isinstance(v, int):
                        sids.add(v)
                elif k.endswith("event_id") or k.endswith("event_ids"):
                    if isinstance(v, int):
                        eids.add(v)
                elif "context" in k:
                    b = ctx_bytes(v)
                    if b is not None:
                        ctxs.add(b)
    return sids, eids, ctxs


def chain_bounds(exp):
    """The earliest re-read start (since) of any poll and the lowest keylog bound per table, over both chains."""
    import gzip
    since, lo = None, {"states": None, "events": None}
    for m in EXPERIMENTS[exp]["monitors"].values():
        for line in gzip.open(os.path.join(OUT, m["chain"]), "rt"):
            try:
                p = (json.loads(line).get("payload") or {})
            except ValueError:
                continue
            if p.get("observer") != "external-monitor":
                continue
            for h in (p.get("backlog") or []) + [p]:
                if isinstance(h.get("since"), (int, float)):
                    since = h["since"] if since is None else min(since, h["since"])
                for t, es in (h.get("keylog") or {}).items():
                    for e in (es if isinstance(es, list) else [es]):
                        if isinstance(e, dict) and t in lo:
                            a = int(e.get("from", 0))
                            lo[t] = a if lo[t] is None else min(lo[t], a)
    return since, lo


def window_since(exp):
    out = []
    for m in EXPERIMENTS[exp]["monitors"].values():
        for vf in m["verify"].values():
            prm = json.load(open(os.path.join(OUT, vf)))["params"]
            out.append((int(float(prm["window"][0]) // 3600) - 1) * 3600.0)
    return min(out)


def invalid_text_keys(con, table):
    """rowids of rows holding a TEXT value that is not valid UTF-8 (as e7_verify.invalid_text_rows finds them)."""
    cols = [r[1] for r in con.execute("PRAGMA src.table_info(%s)" % table)]
    if not cols:
        return []
    sel = ", ".join("CASE WHEN typeof(\"%s\") = 'text' THEN CAST(\"%s\" AS BLOB) END" % (c, c) for c in cols)
    bad = []
    for r in con.execute("SELECT rowid, %s FROM src.%s" % (sel, table)):
        for v in r[1:]:
            if v is not None:
                try:
                    bytes(v).decode("utf-8")
                except UnicodeDecodeError:
                    bad.append(r[0])
                    break
    return bad


def build(exp, src, out_dir, margin):
    cfg = EXPERIMENTS[exp]
    files = report_files(exp)
    sids, eids, ctxs = referenced(files)
    c_since, kl_lo = chain_bounds(exp)
    w_since = window_since(exp)
    lo_ts = min(x for x in (c_since, w_since) if x is not None) - margin
    if None in kl_lo.values():
        raise SystemExit("%s: a chain records no keylog bound for %r" % (exp, kl_lo))
    dst = os.path.join(out_dir, exp + ".db")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    con = sqlite3.connect(dst, uri=True)        # uri=True: ATTACH opens the source read-only by URI
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("ATTACH DATABASE ? AS src", (ro_uri(src),))
    kept, sel = {}, {}
    try:
        schema = [r[0] for r in con.execute(
            "SELECT sql FROM src.sqlite_master WHERE sql IS NOT NULL AND type IN ('table','index') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY type DESC, rowid")]
        for s in schema:
            con.execute(s)
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        bad_text = {t: invalid_text_keys(con, t) for t in TEXT_TABLES if t in tables}
        con.execute("CREATE TEMP TABLE ref_ctx (b BLOB PRIMARY KEY)")
        con.executemany("INSERT OR IGNORE INTO ref_ctx VALUES (?)", [(b,) for b in sorted(ctxs)])
        con.execute("CREATE TEMP TABLE ref_key (t TEXT, k INTEGER, PRIMARY KEY (t, k))")
        con.executemany("INSERT OR IGNORE INTO ref_key VALUES (?, ?)",
                        [("states", k) for k in sids] + [("events", k) for k in eids]
                        + [(t, k) for t, ks in bad_text.items() for k in ks])
        for t, key, ts in (("states", "state_id", "last_updated_ts"), ("events", "event_id", "time_fired_ts")):
            where = ("(%s AND %s >= :lo_ts) OR NOT (%s) OR %s > :kl_lo OR context_id_bin IN (SELECT b FROM ref_ctx)"
                     " OR %s IN (SELECT k FROM ref_key WHERE t = '%s')"
                     % (TS_OK.format(c=ts), ts, TS_OK.format(c=ts), key, key, t))
            con.execute("INSERT INTO main.%s SELECT * FROM src.%s WHERE %s" % (t, t, where),
                        {"lo_ts": lo_ts, "kl_lo": kl_lo[t]})
            kept[t] = con.execute("SELECT count(*) FROM main.%s" % t).fetchone()[0]
            sel[t] = {"malformed_ts": con.execute("SELECT count(*) FROM main.%s WHERE NOT (%s)"
                                                  % (t, TS_OK.format(c=ts))).fetchone()[0],
                      "keylog_lowest_bound": kl_lo[t]}
        for t, cond in (("states_meta", "1"), ("event_types", "1"), ("recorder_runs", "1"),
                        ("state_attributes", "attributes_id IN (SELECT attributes_id FROM main.states)"),
                        ("event_data", "data_id IN (SELECT data_id FROM main.events)")):
            if t not in tables:
                continue
            extra = (" OR rowid IN (SELECT k FROM ref_key WHERE t = '%s')" % t) if bad_text.get(t) else ""
            con.execute("INSERT OR IGNORE INTO main.%s SELECT * FROM src.%s WHERE %s%s" % (t, t, cond, extra))
            kept[t] = con.execute("SELECT count(*) FROM main.%s" % t).fetchone()[0]
        con.commit()
        con.execute("DETACH DATABASE src")
        con.execute("VACUUM")
        con.commit()
    finally:
        con.close()
    chains = {}
    for name, m in cfg["monitors"].items():
        c_src = os.path.join(OUT, m["chain"])
        c_dst = os.path.join(out_dir, "%s_%s.chain.jsonl.gz" % (exp, name))
        if os.path.exists(c_dst):
            raise SystemExit("refusing to overwrite " + c_dst)
        shutil.copyfile(c_src, c_dst)
        chains[name] = {"chain": os.path.basename(c_dst), "chain_sha256": sha256_file(c_dst),
                        "copied_from": "exp/out/" + m["chain"], "pubkey": ("exp/out/" + m["pubkey"]) if m.get("pubkey")
                        else None, "verify_files": {w: "exp/out/" + f for w, f in m["verify"].items()}}
    size = os.path.getsize(dst)
    return {"experiment": exp, "db": os.path.basename(dst), "bytes": size, "sha256": sha256_file(dst),
            "source": os.path.relpath(src, os.path.dirname(REPO)), "source_bytes": os.path.getsize(src),
            "source_sha256": sha256_file(src),
            "selection": {"lowest_since_s": lo_ts + margin, "margin_s": margin, "since_from_windows": w_since,
                          "since_from_chains": c_since, "keylog_lowest_bound": kl_lo,
                          "trial_state_keys": len(sids), "trial_event_keys": len(eids), "trial_context_ids": len(ctxs),
                          "invalid_text_rows": {t: len(v) for t, v in bad_text.items()}, "per_table": sel,
                          "report_files": [os.path.relpath(f, REPO) for f in files]},
            "kept_rows": kept, "monitors": chains, "under_100MB": size < 100 * 1024 * 1024}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--e7-db", default=EXPERIMENTS["e7_main"]["db"])
    ap.add_argument("--e8-db", default=EXPERIMENTS["e8_main"]["db"])
    ap.add_argument("--out", default=os.path.join(REPO, "reproduce", "snapshots", "e7e8"))   # a subdirectory: test_anchor_chain.py globs snapshots/*.chain.jsonl* for the earlier unlinked chains
    ap.add_argument("--margin", type=float, default=2.0)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for f in ("EXTRACTS_E7E8_SHA256SUMS", "extract_manifest_e7e8.json"):
        if os.path.exists(os.path.join(a.out, f)):
            raise SystemExit("refusing to overwrite " + os.path.join(a.out, f))
    manifest = {"generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "script_sha256": sha256_file(os.path.abspath(__file__)), "margin_s": a.margin, "experiments": {}}
    for exp, src in (("e7_main", a.e7_db), ("e8_main", a.e8_db)):
        print("extracting %s ..." % exp, flush=True)
        m = build(exp, src, a.out, a.margin)
        manifest["experiments"][exp] = m
        print("  %s: %.1f MB (source %.1f MB) kept %s" % (exp, m["bytes"] / 1e6, m["source_bytes"] / 1e6, m["kept_rows"]),
              flush=True)
    sums = {}
    for m in manifest["experiments"].values():
        sums[m["db"]] = m["sha256"]
        for c in m["monitors"].values():
            sums[c["chain"]] = c["chain_sha256"]
    with open(os.path.join(a.out, "EXTRACTS_E7E8_SHA256SUMS"), "x") as fh:
        for name in sorted(sums):
            fh.write("%s  ./%s\n" % (sums[name], name))
    with open(os.path.join(a.out, "extract_manifest_e7e8.json"), "x") as fh:
        json.dump(manifest, fh, indent=1)
    over = [e for e, m in manifest["experiments"].items() if not m["under_100MB"]]
    print("wrote %d extracts to %s%s" % (len(manifest["experiments"]), a.out,
                                         "; OVER 100MB: %s" % over if over else "; all under 100MB"))
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
