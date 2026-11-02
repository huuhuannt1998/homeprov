"""E-DZ offline checks on copies of the run's final consistent snapshot (never on the live hub).

1. Single-write check (the Home Assistant paper's "one post-commit write to one row" check, on Domoticz): on a copy of
   the snapshot, one write to one field (a LightingLog field of one committed lock row, or a DeviceStatus field of the
   lock device), then, for each scheme (closure, log rows only, row-scheme analogue, whole row), the number of
   one-second segments of the run window whose root differs from the unmodified copy. The displayed effect of each
   field is measured in exp/out/dz_closure.json (API and UI); this check measures what each scheme commits.
2. VACUUM check: LightingLog has no INTEGER PRIMARY KEY, so its rows are keyed by the implicit ROWID, which SQLite's
   VACUUM may renumber ("The VACUUM command may change the ROWIDs of entries in any tables that do not have an explicit
   INTEGER PRIMARY KEY", sqlite.org/lang_vacuum.html). Domoticz runs VACUUM in ClearShortLog(), after a database
   restore and on the admin command vacuumdatabase. On copies, inside the Domoticz image (its own libsqlite3), run
   (a) VACUUM alone and (b) a retention-style DELETE of the oldest LightingLog rows followed by VACUUM, and count rows
   whose ROWID-to-content binding changed and closure one-second segments of the run window whose root changed.

    python3 exp/stages/dz_offline_checks.py --tag dz --run DIR [--outdir exp/out]   -> <outdir>/<tag>_offline_checks.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import dz_detection as D  # noqa: E402

SCHEMES = ("closure", "logrows", "row", "wholerow")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def roots(A, db, t0, t1):
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
    rows = A.read_rows(con)
    con.close()
    out = {}
    for s in SCHEMES:
        phi = A.M.commit(A.nodes_from_rows(s, *rows))["second"]
        out[s] = {k: v for k, v in phi.items() if t0 - 1 <= int(k) <= t1 + 1}
    return out


def ndiff(a, b):
    keys = set(a) | set(b)
    return sum(1 for k in keys if a.get(k) != b.get(k))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--outdir", default=os.path.join(REPO, "exp", "out"))
    a = ap.parse_args()
    path = os.path.join(a.outdir, "%s_offline_checks.json" % a.tag)
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    t0 = float(open(os.path.join(a.outdir, "%s_t_start" % a.tag)).read())
    t1 = float(open(os.path.join(a.outdir, "%s_t_end" % a.tag)).read())
    snap = os.path.join(a.run, "verify", "domoticz.db")
    rep = json.load(open(os.path.join(a.outdir, "%s_report_porch.json" % a.tag)))
    lock = int(rep["lock_device_idx"])
    with tempfile.TemporaryDirectory() as tmp:
        A = D.load_adapter(os.path.join(a.run, "hp"), tmp)
        base_db = os.path.join(tmp, "base.db")
        shutil.copy2(snap, base_db)
        base = roots(A, base_db, t0, t1)
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % base_db, uri=True)
        lock_rows = con.execute("SELECT ROWID, Date FROM LightingLog WHERE DeviceRowID=? AND Date>=? AND Date<=? "
                                "ORDER BY ROWID", (lock, A.ts_date(t0), A.ts_date(t1))).fetchall()
        lock_secs = {str(int(A.date_ts(d))) for _r, d in lock_rows}
        ds = con.execute("SELECT Type, SubType, SwitchType, Options, nValue, LastUpdate FROM DeviceStatus WHERE ID=?",
                         (lock,)).fetchone()
        con.close()
        row = lock_rows[0][0]
        writes = [("LightingLog", "ROWID", row, "User", "EventSystem/porch_motion_light"),
                  ("LightingLog", "ROWID", row, "nValue", None),
                  ("LightingLog", "ROWID", row, "sValue", "Off-mut"),
                  ("DeviceStatus", "ID", lock, "SwitchType", 20),
                  ("DeviceStatus", "ID", lock, "Type", 82),
                  ("DeviceStatus", "ID", lock, "SubType", ds[1] + 1),
                  ("DeviceStatus", "ID", lock, "Options", "LevelNames:VW5vfERvc3xUcmVz"),
                  ("DeviceStatus", "ID", lock, "nValue", 1 - ds[4] if ds[4] in (0, 1) else 0),
                  ("DeviceStatus", "ID", lock, "LastUpdate", "2026-10-07 00:00:00")]
        single = []
        for table, keycol, key, col, val in writes:
            db = os.path.join(tmp, "w.db")
            shutil.copy2(base_db, db)
            c = sqlite3.connect(db)
            if col == "nValue" and table == "LightingLog":
                val = 1 - c.execute("SELECT nValue FROM LightingLog WHERE ROWID=?", (key,)).fetchone()[0]
            orig = c.execute("SELECT [%s] FROM %s WHERE %s=?" % (col, table, keycol), (key,)).fetchone()[0]
            c.execute("UPDATE %s SET [%s]=? WHERE %s=?" % (table, col, keycol), (val, key))
            c.commit()
            c.close()
            got = roots(A, db, t0, t1)
            single.append({"write": "%s.%s" % (table, col), "target": "%s=%s" % (keycol, key), "from": orig, "to": val,
                           "segments_changed": {s: ndiff(base[s], got[s]) for s in SCHEMES},
                           "segments_in_window": {s: len(base[s]) for s in SCHEMES}})
            os.remove(db)
        # ---- VACUUM check inside the Domoticz image (its libsqlite3)
        vdir = os.path.join(tmp, "vac")
        os.makedirs(vdir)
        for n in ("a.db", "b.db", "c.db"):
            shutil.copy2(base_db, os.path.join(vdir, n))
        inner = r'''
import json, sqlite3
def binding(db):
    c = sqlite3.connect(db)
    r = {x[0]: list(x[1:]) for x in c.execute("SELECT ROWID, DeviceRowID, nValue, sValue, User, Date FROM LightingLog")}
    c.close(); return r
out = {"sqlite_version": sqlite3.sqlite_version}
for name, delete, vacuum in (("a", 0.0, True), ("b", 0.10, True), ("c", 0.10, False)):
    db = "/v/%s.db" % name
    before = binding(db)
    c = sqlite3.connect(db)
    deleted = []
    if delete:
        ids = sorted(before)[: int(len(before) * delete)]
        cut = before[ids[-1]][4]
        deleted = [k for k in before if before[k][4] <= cut]
        c.execute("DELETE FROM LightingLog WHERE Date<=?", (cut,)); c.commit()
    if vacuum:
        c.execute("VACUUM")
    c.close()
    after = binding(db)
    kept = {k: v for k, v in before.items() if k not in set(deleted)}
    content_to_old = {}
    for k, v in kept.items():
        content_to_old.setdefault(json.dumps(v), []).append(k)
    renumbered = sum(1 for k, v in after.items() if before.get(k) != v)
    out[name] = {"rows_before": len(before), "rows_deleted": len(deleted), "rows_after": len(after),
                 "rows_whose_rowid_binding_changed": renumbered,
                 "max_rowid_before": max(before) if before else None, "max_rowid_after": max(after) if after else None}
print(json.dumps(out))
'''
        r = subprocess.run(["docker", "run", "--rm", "--name", "dz-vacuum", "--network", "none", "--entrypoint",
                            "python3", "-v", "%s:/v" % vdir, "domoticz/domoticz:stable", "-c", inner],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("vacuum check failed: %s" % r.stderr[-1500:])
        vac = json.loads(r.stdout)
        got = {}
        for n in ("a", "b", "c"):
            got[n] = roots(A, os.path.join(vdir, n + ".db"), t0, t1)
            vac[n]["closure_second_segments_changed_in_window"] = ndiff(base["closure"], got[n]["closure"])
            vac[n]["closure_second_segments_in_window"] = len(base["closure"])
        vac["b"]["closure_second_segments_differing_from_delete_only"] = ndiff(got["c"]["closure"], got["b"]["closure"])
        vac["c"]["what"] = "the same DELETE without VACUUM (control: separates the deletion from the VACUUM)"
        vac["a"]["what"] = "VACUUM alone"
        vac["b"]["what"] = "DELETE of the oldest 10% of LightingLog rows (by Date, as CleanupLightSceneLog deletes " \
                           "by date) followed by VACUUM"
    # ---- observation window: from a row's second to the anchoring of that second's root
    import statistics                                                    # noqa: PLC0415
    first = {}
    for line in open(os.path.join(a.run, "chain.jsonl")):
        rec = json.loads(line)
        for s_, _v in ((rec.get("payload") or {}).get("sealed") or {}).get("second", {}).items():
            first.setdefault(s_, rec["recv_ts"])
    win = [first[k] - int(k) for k in base["closure"] if k in first and t0 <= int(k) <= t1]
    seal_delay = {"n_segments": len(win), "median_s": statistics.median(win), "max_s": max(win), "min_s": min(win),
                  "what": "anchor receive time of a one-second segment's first root minus the segment's start; a row "
                          "written in that second was anchored at most this long after its write (Date has one-second "
                          "resolution, so the write lies in [start, start+1))"}
    out = {"experiment": "E-DZ offline checks", "what": __doc__.split("\n\n")[1].replace("\n", " "),
           "snapshot": {"path": os.path.relpath(snap, os.path.dirname(REPO)), "sha256": sha(snap)},
           "window": [t0, t1], "lock_device_id": lock, "lock_rows_in_window": len(lock_rows),
           "lock_seconds_in_window": len(lock_secs), "single_write_row": row,
           "single_write": single, "vacuum": vac, "seal_delay": seal_delay,
           "script_sha256": sha(os.path.abspath(__file__)),
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1, default=str)
    for s in single:
        print("%-24s %s" % (s["write"], s["segments_changed"]))
    print("lock rows in window %d in %d seconds" % (len(lock_rows), len(lock_secs)))
    print("vacuum", json.dumps(vac))
    print("->", path, sha(path))


if __name__ == "__main__":
    main()
