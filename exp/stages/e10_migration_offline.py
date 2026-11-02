"""E10 (round 14), offline: what a recorder schema migration does to the stable-columns commitment, on a COPY of a recorder
the E10 monitor sealed (drafts/round13/E10_DESIGN.md section 3, O-MIG). No Docker; no Home Assistant.

The stable scheme commits every column of a states and events row that PRAGMA table_info lists (except
states.last_reported_ts) plus four joined values (monitor.py STABLE-COLUMNS SCHEME), so the commitment changes with the
schema of those tables and with nothing else. The live arms U and B4 cross real releases (2025.11.1 -> 2026.7.4,
schema 51 -> 53, whose SQLite steps touch statistics_meta only; 2026.7.4 -> 2026.10.1, no schema change). This check
applies three migration shapes to copies and verifies each against the same chain:
  m52     the 51 -> 52 step on SQLite as Home Assistant 2026.7.4 runs it (migration.py _SchemaVersion52Migrator,
          _apply_update_postgresql_sqlite): ALTER TABLE statistics_meta ADD COLUMN unit_class VARCHAR(255) (the UPDATE
          that fills it touches statistics_meta only)                        prediction: no violation
  index   CREATE INDEX on states (a new index, as several earlier migrations did)              prediction: no violation
  column  ALTER TABLE states ADD COLUMN e10_probe TEXT (a hypothetical migration that adds a states column)
          prediction: every anchored segment holding a state row, and every keylog range of the states table, fails
          (no rule excuses it; a MIGRATE rule does not exist in the coverage verifier: open question for the lead)

    python3 exp/stages/e10_migration_offline.py --run-dir <E10 run dir> --stack e10s --snapshot final [--monitor direct]
            --out exp/out/<tag>_migration_offline.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import e7_verify as EV                       # noqa: E402

SHAPES = {"none": [],
          "m52": ["ALTER TABLE statistics_meta ADD COLUMN unit_class VARCHAR(255)"],
          "index": ["CREATE INDEX ix_e10_probe ON states (state, last_updated_ts)"],
          "column": ["ALTER TABLE states ADD COLUMN e10_probe TEXT"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--stack", default="e10s")
    ap.add_argument("--snapshot", default="final")
    ap.add_argument("--monitor", default="direct", choices=("direct", "copy"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    ev = [json.loads(l) for l in open(os.path.join(a.run_dir, "events.jsonl")) if l.strip()]
    snap = next(e for e in ev if e.get("type") == "snapshot" and e.get("stack") == a.stack and e.get("label") == a.snapshot)
    src, tsnap = os.path.join(a.run_dir, snap["file"]), snap["t_snapshot"]
    lines = open(os.path.join(a.run_dir, a.stack, "%s_chain.jsonl" % a.monitor)).read().splitlines()
    out = {"check": "E10 O-MIG", "snapshot": snap["file"], "monitor": a.monitor, "shapes": {}}
    for name, stmts in SHAPES.items():
        scratch = tempfile.mkdtemp(prefix="e10mig_")
        try:
            db = os.path.join(scratch, "rec.db")
            shutil.copy2(src, db)
            con = sqlite3.connect(db)
            applied, skipped = [], []
            for q in stmts:
                # An ADD COLUMN whose column already exists is skipped and recorded (fix of 2026-10-19, smoke
                # e10_smoke3: the main phase's recorder is the lab's schema-53 copy, which already has
                # statistics_meta.unit_class, so m52 cannot be re-applied; the live upgrade arm U crosses 51 -> 52).
                w = q.split()
                if len(w) >= 6 and [x.upper() for x in w[:2]] == ["ALTER", "TABLE"] and \
                        [x.upper() for x in w[3:5]] == ["ADD", "COLUMN"] and \
                        w[5] in {r[1] for r in con.execute("PRAGMA table_info(%s)" % w[2])}:
                    skipped.append({"statement": q, "why": "column already present"})
                    continue
                con.execute(q)
                applied.append(q)
            con.commit()
            con.close()
            M = EV.load_monitor("stable", scratch)
            res = EV.verify(M, db, lines, 30.0, 30.0, scheme="stable", tsnap=tsnap,
                            sign_pubkey=os.path.join(a.run_dir, a.stack, "%s_sign_pub.pem" % a.monitor), recovery=False)
            c = collections.Counter(v["gran"] for v in res["violations"] if v["violation"] and v["attributable"])
            out["shapes"][name] = {"statements": stmts, "applied": applied, "skipped": skipped, "violations": dict(c),
                                   "segments_checked": {g: d["anchored_in_window"] for g, d in res["segments"].items()},
                                   "keylog_violations": len(res["keylog_violations"]),
                                   "keylog_ranges_checked": res["keylog"]["ranges_checked"],
                                   "flagged_seconds": len(res["flagged_seconds"])}
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
