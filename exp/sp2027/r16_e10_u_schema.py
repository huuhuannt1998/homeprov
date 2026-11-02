#!/usr/bin/env python3
"""E10 exploratory: the recorder schema before and after arm U (2025.11.1 -> 2026.7.4) and arm B4 (2026.7.4 -> 2026.10.1).
The upgrade record of U has no "before" (testbed/e10 upgrade.json: before null), so H14's "states and events columns
unchanged; statistics_meta gains unit_class" is checked here on the snapshots the run took (pre_upgrade / final of
e10u, b4_pre / b4_post of e10s), opened mode=ro&immutable=1. Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_u_schema.py [--run-dir DIR] [--out exp/out/r16_e10_u_schema.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
TABLES = ("states", "events", "statistics_meta", "states_meta", "event_types", "state_attributes", "event_data")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def schema(db):
    p = db + "-wal"
    assert not os.path.exists(p) or os.path.getsize(p) == 0, p
    c = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
    out = {t: [r[1] for r in c.execute("PRAGMA table_info(%s)" % t)] for t in TABLES}
    out["schema_changes"] = [list(r) for r in c.execute("SELECT schema_version, changed FROM schema_changes ORDER BY change_id")]
    c.close()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_u_schema.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    snaps = {}
    for line in open(os.path.join(a.run_dir, "events.jsonl")):
        e = json.loads(line)
        if e.get("type") == "snapshot" and e.get("ok"):
            snaps[(e["stack"], e["label"])] = (os.path.join(a.run_dir, e["file"]), e["t_snapshot"])
    out = {"what": "recorder schema before/after U and B4 (EXPLORATORY)", "inputs": {}, "pairs": {}}
    for name, before, after in (("U", ("e10u", "pre_upgrade"), ("e10u", "final")), ("B4", ("e10s", "b4_pre"), ("e10s", "b4_post"))):
        (pb, tb), (pa, ta) = snaps[before], snaps[after]
        out["inputs"]["%s_before" % name] = {"path": pb, "sha256": sha(pb), "t_snapshot": tb}
        out["inputs"]["%s_after" % name] = {"path": pa, "sha256": sha(pa), "t_snapshot": ta}
        sb, sa = schema(pb), schema(pa)
        out["pairs"][name] = {"before": sb, "after": sa,
                              "columns_changed": {t: {"added": [c for c in sa[t] if c not in sb[t]],
                                                      "removed": [c for c in sb[t] if c not in sa[t]]}
                                                  for t in TABLES if sa[t] != sb[t]}}
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
