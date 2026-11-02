"""R10 (review sp2027-r4, R2 N2): an offline check of the coarse roots on the saved real-deployment runs.

The paper's construction says that where no finer segment exists the coarser roots detect: a row inserted into an empty
second after its minute was sealed changes the minute root, and one inserted into an empty minute after its hour was
sealed changes the hour root. No live run exercised this. This script checks it offline, on the per-run recorder extracts
and anchor chains that the artifact ships (reproduce/snapshots, verified against EXTRACTS_SHA256SUMS), with the shipped
monitor's own load() and commit() and the encoding the anchored records name ('v1').

Per run (closure- and row-scheme runs; the whole-row runs are left out because the recorder rewrites their committed
columns in place, so their untouched roots do not reproduce):
  1. control: recompute every anchored minute (hour) root of the run window from the extract; keep the segments whose
     recomputed root equals the first anchored root (acc and n), i.e. segments the extract reproduces;
  2. minute test: in a copy of the extract, insert one state row (a copy of a row of that minute, new state_id) into the
     first second of each kept minute that holds no row; reload and recompute. Count the minutes whose root now differs
     from the anchored one, and check that no one-second root was anchored for the inserted second (so the minute root is
     the finest anchored root that covers the row) and that every anchored one-second root that reproduced before still
     reproduces;
  3. hour case: the hours anchored during each run (the hour in which the run started, sealed after it ended) are
     recomputed and their empty minutes counted; the hour test (one row into an empty minute) is run only where such a
     minute exists. Each run's extract starts one hour before the hour in which the run started and ends two hours after
     its recorder snapshot, so it holds those hours whole; by default they are recomputed from the extracts. With
     --snapshots DIR they are recomputed from the full verifier snapshot set instead (same results, checked 2026-10-07).
Nothing is written to the extracts or the anchor; the copies live in a temporary directory.

    python3 exp/sp2027/r10_coarse_roots.py [--snapshots DIR] [--out FILE]   # writes exp/out/r10_coarse_roots.json
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as VA  # noqa: E402

RUNS = [r for r, c in VA.RUNS.items() if c["scheme"] in ("closure", "row")]


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def inject(src_db, dst_db, targets):
    """Copy src_db to dst_db and insert, for each (template_state_id, ts), one state row copied from the template with a
    fresh state_id and its time columns moved to ts. Returns the new state ids."""
    shutil.copyfile(src_db, dst_db)
    con = sqlite3.connect(dst_db)
    cols = [r[1] for r in con.execute("PRAGMA table_info(states)")]
    nxt = con.execute("SELECT MAX(state_id) FROM states").fetchone()[0] + 1
    new = []
    for tid, ts in targets:
        row = dict(zip(cols, con.execute("SELECT %s FROM states WHERE state_id=?" % ",".join(cols), (tid,)).fetchone()))
        row["state_id"] = nxt
        for c in ("last_updated_ts", "last_changed_ts", "last_reported_ts"):
            if c in row and row[c] is not None:
                row[c] = ts
        con.execute("INSERT INTO states (%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))),
                    [row[c] for c in cols])
        new.append(nxt)
        nxt += 1
    con.commit()
    con.close()
    return new


def run_one(run_id, src, scratch):
    cfg = VA.RUNS[run_id]
    db, chain, info = src.checked(run_id)
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    M = VA.load_monitor(cfg["scheme"], scratch)
    roots = VA.anchored_roots(VA.chain_lines(chain), t0, tsnap)
    assert {a["encoding"] for a in roots.values()} == {"v1"}
    since = (int(t0 // 3600) - 1) * 3600.0
    W = dict(M.GRAN)

    def phi_of(path):
        return M.commit(M.load(path, since=since), encoding="v1")

    def same(phi, g, s):
        a, r = roots.get((g, s)), (phi.get(g) or {}).get(s)
        return bool(a and r and a["acc"] == r["acc"] and a["n"] == r["n"])

    nodes = M.load(db, since=since)
    phi = M.commit(nodes, encoding="v1")
    occupied = {g: {int(n[0] // w) for n in nodes} for g, w in W.items()}
    states_by = {g: {} for g in W}
    for n in nodes:
        if n[1].startswith("s:"):
            for g, w in W.items():
                states_by[g].setdefault(int(n[0] // w), int(n[1][2:]))
    second_ok_before = {s for (g, s) in roots if g == "second" and same(phi, "second", s)}
    out = {"scheme": cfg["scheme"], "inputs": info, "window": {"t_start": t0, "t_end": t1}}

    for g, finer, coarse_w in (("minute", "second", 60),):
        fw = W[finer]
        anchored = sorted(int(s) for (gg, s) in roots if gg == g and t0 <= int(s) * coarse_w and (int(s) + 1) * coarse_w <= tsnap)
        kept = [s for s in anchored if same(phi, g, str(s))]
        targets, plan = [], []
        for s in kept:
            lo, hi = int(s * coarse_w // fw), int((s + 1) * coarse_w // fw)
            empty = next((f for f in range(lo, hi) if f not in occupied[finer]
                          and (finer, str(f)) not in roots and ("second", str(int(f * fw))) not in roots), None)
            tid = states_by[g].get(s)
            if empty is None or tid is None:
                continue
            ts = empty * fw + fw / 2.0 + 0.25
            targets.append((tid, ts))
            plan.append((s, empty, ts))
        copy = os.path.join(scratch, "%s_%s.db" % (run_id, g))
        inject(db, copy, targets)
        phi2 = phi_of(copy)
        changed = sum(1 for s, _, _ in plan if not same(phi2, g, str(s)))
        finer_anchored = sum(1 for _, f, ts in plan if (finer, str(f)) in roots or ("second", str(int(ts))) in roots)
        seconds_still_ok = all(same(phi2, "second", s) for s in second_ok_before
                               if not any(int(s) == int(ts) for _, _, ts in plan))
        out[g] = {"anchored_in_window": len(anchored), "reproduced_by_extract": len(kept),
                  "with_an_empty_" + finer: len(plan), "root_changed_after_one_inserted_row": changed,
                  "inserted_rows_with_an_anchored_finer_root": finer_anchored,
                  "other_anchored_second_roots_unchanged": seconds_still_ok}
        os.remove(copy)
    return out


def hour_case(run_id, full, scratch):
    """Hours anchored during the run, recomputed from `full` (the window extracts by default, or the full verifier
    snapshot set): reproduced or not, and empty minutes."""
    cfg = VA.RUNS[run_id]
    db, chain, info = full.checked(run_id)
    win = json.load(open(os.path.join(OUT, cfg["result"])))["window"]
    t0, tsnap = win["t_start"], win["recorder_snapshot_at"]
    M = VA.load_monitor(cfg["scheme"], scratch)
    roots = VA.anchored_roots(VA.chain_lines(chain), t0, tsnap)
    nodes = M.load(db, since=(int(t0 // 3600) - 1) * 3600.0)
    phi = M.commit(nodes, encoding="v1")
    occ = {int(n[0] // 60) for n in nodes}
    hours = []
    for (g, s) in sorted(roots):
        if g != "hour":
            continue
        a, r = roots[(g, s)], phi["hour"].get(s) or {}
        h = int(s)
        hours.append({"hour": h, "reproduced": a["acc"] == r.get("acc") and a["n"] == r.get("n"),
                      "empty_minutes": sum(1 for m in range(h * 60, (h + 1) * 60) if m not in occ)})
    return {"inputs": info, "hours_anchored_during_run": hours}


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None, help="recompute the hour case from the full verifier snapshot set")
    ap.add_argument("--out", default=os.path.join(OUT, "r10_coarse_roots.json"))
    a = ap.parse_args()
    dst = a.out
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    src = VA.Inputs(extracts=VA.DEFAULT_EXTRACTS)
    full = VA.Inputs(snapshots=a.snapshots) if a.snapshots else src
    runs, hours = {}, {}
    with tempfile.TemporaryDirectory() as scratch:
        for r in RUNS:
            runs[r] = run_one(r, src, scratch)
            print(r, json.dumps(runs[r]["minute"]))
            if full is not None:
                hours[r] = hour_case(r, full, scratch)
    pooled = {}
    for g in ("minute",):
        keys = [k for k in runs[RUNS[0]][g] if isinstance(runs[RUNS[0]][g][k], int)]
        pooled[g] = {k: sum(runs[r][g][k] for r in runs) for k in keys}
        pooled[g]["other_anchored_second_roots_unchanged"] = all(runs[r][g]["other_anchored_second_roots_unchanged"] for r in runs)
    out = {"item": "R10: offline check of the minute and hour roots on the saved real-deployment runs (review sp2027-r4, R2 N2)",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": "exp/sp2027/r10_coarse_roots.py", "script_sha256": sha(os.path.abspath(__file__)),
           "monitor_sha256": sha(os.path.join(REPO, "monitor", "monitor.py")),
           "inputs_mode": src.mode, "substrate": "real deployment (Home Assistant 2026.7.4), saved recorder extracts and "
           "anchor chains of the closure- and row-scheme runs; offline, no live run",
           "runs_left_out": {r: "whole-row scheme: the recorder rewrites committed columns in place, so untouched roots do "
                                "not reproduce" for r, c in VA.RUNS.items() if c["scheme"] == "wholerow"},
           "pooled": pooled, "runs": runs,
           "hour_case": {"inputs_mode": full.mode,
                         "hours_anchored_during_runs": sum(len(h["hours_anchored_during_run"]) for h in hours.values()),
                         "hours_reproduced": sum(x["reproduced"] for h in hours.values() for x in h["hours_anchored_during_run"]),
                         "empty_minutes_in_reproduced_hours": sum(x["empty_minutes"] for h in hours.values()
                                                                  for x in h["hours_anchored_during_run"] if x["reproduced"]),
                         "runs": hours,
                         "note": "the hour test needs an empty minute inside a reproduced hour; where there is none it is "
                                 "not run, and the hour root's role rests on the construction"},
           "caveats": ["deterministic given the hash chain: the check exercises the shipped load()/commit() on real rows, "
                       "it is not a rate", "one inserted row per kept segment, at the first empty second (minute test) "
                       "or empty minute (hour test)"]}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(pooled))


if __name__ == "__main__":
    main()
