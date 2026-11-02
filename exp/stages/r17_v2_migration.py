"""Round 17 (review r6), exploratory: E10's offline migration case re-verified with verifier version 2.

The registered check (exp/stages/e10_migration_offline.py, result exp/out/e10_main_migration_offline.json) copied the
final recorder snapshot of E10's main stack (e10s), applied a migration shape to the copy and verified the direct
monitor's chain against it with the E10 verifier, over the whole chain (no window), signatures checked, recovery off.
This script repeats the shapes "none" and "column" (ALTER TABLE states ADD COLUMN e10_probe TEXT), and optionally
"drop" (ALTER TABLE states DROP COLUMN origin_idx, a committed column), with exp/stages/verify_v2.py and the same
parameters, the committed column list supplied from the start snapshot of the same stack (E10's chains were written
by monitor.py, which records no list; v2 never guesses one). The start snapshot's list is checked equal to the final
snapshot's own list before any shape is applied (no schema change of states or events during the run; the upgrade
block crossed no schema step), so it is the list in force for every record of the chain. Nothing under the run
directory is written: each shape runs on a private copy in --scratch.

    python3 exp/stages/r17_v2_migration.py --run-dir <E10 run dir> --scratch <dir> --out exp/out/r17_v2_migration.json
            [--shapes none column drop]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import verify_v2 as VV                          # noqa: E402

EV = VV.EV
SHAPES = {"none": [],
          "column": ["ALTER TABLE states ADD COLUMN e10_probe TEXT"],
          "drop": ["ALTER TABLE states DROP COLUMN origin_idx"]}
V1_RESULT = os.path.join(REPO, "exp", "out", "e10_main_migration_offline.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--stack", default="e10s")
    ap.add_argument("--monitor", default="direct", choices=("direct", "copy"))
    ap.add_argument("--scratch", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--shapes", nargs="+", default=["none", "column"])
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    ev = [json.loads(l) for l in open(os.path.join(a.run_dir, "events.jsonl")) if l.strip()]
    snap = {e["label"]: e for e in ev if e.get("type") == "snapshot" and e.get("stack") == a.stack}
    final, start = snap["final"], snap["start"]
    src, tsnap = os.path.join(a.run_dir, final["file"]), final["t_snapshot"]
    start_db = os.path.join(a.run_dir, start["file"])
    chain = os.path.join(a.run_dir, a.stack, "%s_chain.jsonl" % a.monitor)
    pub = os.path.join(a.run_dir, a.stack, "%s_sign_pub.pem" % a.monitor)
    lines = open(chain).read().splitlines()
    M0 = EV.load_monitor("stable", tempfile.mkdtemp(prefix="r17m_", dir=a.scratch))
    pinned = VV.columns_of_file(M0, start_db)
    final_cols = VV.columns_of_file(M0, src)
    if pinned != final_cols:
        raise SystemExit("the start and final snapshots commit different column lists; this check needs one list")
    v1 = json.load(open(V1_RESULT))
    out = {"check": "r17 v2 migration (E10 O-MIG re-verified with verifier version 2), exploratory",
           "run_dir": a.run_dir, "stack": a.stack, "monitor": a.monitor,
           "snapshot": {"file": final["file"], "sha256": final["sha256"], "t_snapshot": tsnap},
           "pinned_columns": {"source": "start snapshot of the same stack", "file": start["file"],
                              "sha256": start["sha256"], "digest": VV.PC.digest(pinned), "columns": pinned,
                              "equals_final_snapshot_list": True},
           "chain": {"file": os.path.relpath(chain, a.run_dir), "sha256": VV.sha256_file(chain), "lines": len(lines)},
           "parameters": {"late_bound_s": 30.0, "gap_s": 30.0, "scheme": "stable", "window": None,
                          "sign_pubkey": os.path.relpath(pub, a.run_dir), "recovery": False,
                          "as": "exp/stages/e10_migration_offline.py (registered with E10)"},
           "v1_result": {"file": "exp/out/e10_main_migration_offline.json",
                         "sha256": VV.sha256_file(V1_RESULT)},
           "code_sha256": VV.code_hashes(), "shapes": {}}
    for name in a.shapes:
        stmts = SHAPES[name]
        scratch = tempfile.mkdtemp(prefix="r17mig_%s_" % name, dir=a.scratch)
        t0 = time.time()
        try:
            db = os.path.join(scratch, "rec.db")
            shutil.copy2(src, db)
            con = EV.sqlite3.connect(db)
            for q in stmts:
                con.execute(q)
            con.commit()
            con.close()
            M = EV.load_monitor("stable", scratch)
            res = VV.verify_v2(M, db, lines, 30.0, 30.0, scheme="stable", tsnap=tsnap, sign_pubkey=pub,
                               recovery=False, pinned=pinned,
                               pinned_label="%s start snapshot %s (sha256 %s)" % (a.stack, start["file"],
                                                                                  start["sha256"][:12]))
            c = collections.Counter(v["gran"] for v in res["violations"] if v["violation"] and v["attributable"])
            reasons = collections.Counter(v.get("v2_reason") or "none" for v in res["violations"]
                                          if v["violation"] and v["attributable"] and v["gran"] == "second")
            r = {"statements": stmts, "violations": dict(c),
                 "segments_checked": {g: d["anchored_in_window"] for g, d in res["segments"].items()},
                 "keylog_violations": len(res["keylog_violations"]),
                 "keylog_ranges_checked": res["keylog"]["ranges_checked"],
                 "flagged_seconds": len(res["flagged_seconds"]),
                 "second_violations_by_v2_reason": dict(reasons),
                 "v2": res["v2"], "wall_s": round(time.time() - t0, 1)}
            vs = (v1["shapes"].get(name) or {})
            if vs:
                r["v1_same_shape"] = {k: vs.get(k) for k in ("violations", "segments_checked", "keylog_violations",
                                                             "keylog_ranges_checked", "flagged_seconds")}
            out["shapes"][name] = r
            with open(os.path.join(a.scratch, "r17_v2_migration_%s.partial.json" % name), "w") as fh:
                json.dump(r, fh, indent=1, sort_keys=True, default=str)
            print("%s: %s seconds violated of %s checked (%.0f s)" % (name, c.get("second"),
                                                                      r["segments_checked"].get("second"), r["wall_s"]),
                  flush=True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    if "none" in out["shapes"] and "column" in out["shapes"]:
        n, col = out["shapes"]["none"], out["shapes"]["column"]
        chk = col["segments_checked"]["second"]
        base = n["violations"].get("second", 0)
        out["comparison"] = {
            "v1": {"column_violated_seconds": v1["shapes"]["column"]["violations"]["second"],
                   "none_violated_seconds": v1["shapes"]["none"]["violations"]["second"],
                   "checked_seconds": v1["shapes"]["column"]["segments_checked"]["second"],
                   "increment": v1["shapes"]["column"]["violations"]["second"]
                   - v1["shapes"]["none"]["violations"]["second"],
                   "increment_of": v1["shapes"]["column"]["segments_checked"]["second"]
                   - v1["shapes"]["none"]["violations"]["second"]},
            "v2": {"column_violated_seconds": col["violations"].get("second", 0), "none_violated_seconds": base,
                   "checked_seconds": chk, "increment": col["violations"].get("second", 0) - base,
                   "increment_of": chk - base},
            "v2_none_equals_v1_none": {k: n.get(k) == (v1["shapes"]["none"] or {}).get(k)
                                       for k in ("violations", "segments_checked", "keylog_violations",
                                                 "keylog_ranges_checked", "flagged_seconds")}}
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
