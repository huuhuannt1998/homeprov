"""E10 arm C (review r5 Z4): score the benign switch-type change on Domoticz (testbed/e10/run_dz_switchtype.sh).

Live verification exactly as exp/stages/dz_detection.py scores E-DZ: every anchored segment root of the run window is
recomputed from the final consistent snapshot with the shipped monitor's commit() through the Domoticz adapter's
closure nodes, and compared with its first anchored root (reproduce/verify_all.py anchored_roots / verify_window).

Prediction (drafts/round13/E10_ADDENDUM_R5.md section C, stated before the run):
  * every anchored second, minute and hour segment that holds a LightingLog row of the lock and was first anchored
    before the change is a violation (the closure commits DeviceStatus.SwitchType with each of the device's log rows);
    no other segment is (floor 0); segments within BAND_S of the change are ambiguous and left out of agreement;
  * the offline comparison (closure roots of the pre-change snapshot against the final one, dz_offline_checks.roots)
    changes exactly the predicted seconds;
  * the platform's renderer shows the lock's earlier rows differently after the change (render_before/after);
  * no marker can excuse it: the Domoticz adapter has none, and the five marker kinds of the Home Assistant verifier
    (PURGE, RESTORE, RESTORE_DONE, RENAME, CLOCK_STEP) declare a purge, a restore, a name-map change or a clock step,
    not a committed configuration field.

    python3 exp/stages/e10_dz_switchtype.py --tag e10dz_st --run DIR [--outdir exp/out]
Writes <outdir>/<tag>_switchtype_score.json; never overwrites.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BAND_S = 10.0          # seconds around the change left out of agreement (a poll may seal either value)


def predicted_segments(lock_secs, first_recv, t_change, W, band=BAND_S):
    """(predicted violated, ambiguous): the anchored segments (gran, seg) holding a lock row whose first anchoring
    (first_recv, VM clock) precedes the change; those first anchored within `band` of the change are ambiguous."""
    pred, amb = set(), set()
    for s in lock_secs:
        for g, w in W.items():
            key = (g, str(int(s) // int(w)))
            fr = first_recv.get(key)
            if fr is None:
                continue
            if abs(fr - t_change) <= band:
                amb.add(key)
            elif fr < t_change:
                pred.add(key)
    return pred - amb, amb


def agreement(verd_live, pred, amb):
    """Per granularity: predicted and observed violations, both directions of disagreement, and the floor (violations
    of segments holding no lock row sealed before the change)."""
    out = {}
    grans = sorted({g for g, _s in verd_live} | {g for g, _s in pred})
    for g in grans:
        obs = {k for k, v in verd_live.items() if k[0] == g and v.get("violation") and k not in amb}
        p = {k for k in pred if k[0] == g}
        out[g] = {"predicted": len(p), "observed": len(obs), "predicted_not_observed": sorted(s for _g, s in p - obs)[:50],
                  "observed_not_predicted": sorted(s for _g, s in obs - p)[:50], "n_predicted_not_observed": len(p - obs),
                  "n_observed_not_predicted": len(obs - p), "agree": p == obs,
                  "ambiguous": sum(1 for k in amb if k[0] == g)}
    return out


def main():
    sys.path.insert(0, HERE)
    sys.path.insert(0, os.path.join(REPO, "reproduce"))
    sys.path.insert(0, os.path.join(REPO, "exp"))
    import dz_detection as D               # noqa: PLC0415
    import dz_offline_checks as O          # noqa: PLC0415
    import verify_all as VA                # noqa: PLC0415
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--outdir", default=os.path.join(REPO, "exp", "out"))
    a = ap.parse_args()
    dst = os.path.join(a.outdir, "%s_switchtype_score.json" % a.tag)
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite %s" % dst)
    t0 = float(open(os.path.join(a.outdir, "%s_t_start" % a.tag)).read())
    t1 = float(open(os.path.join(a.outdir, "%s_t_end" % a.tag)).read())
    rep = json.load(open(os.path.join(a.outdir, "%s_switchtype_report.json" % a.tag)))
    t_change = float(rep["t_change_request_vm"])
    lock = int(rep["lock_device_idx"])
    db = os.path.join(a.run, "verify", "domoticz.db")
    pre = os.path.join(a.run, "verify", "domoticz_pre_change.db")
    t_snap = float(open(os.path.join(a.run, "verify", "t_snapshot")).read())
    lines = open(os.path.join(a.run, "chain.jsonl")).read().splitlines()
    with tempfile.TemporaryDirectory() as scratch:
        A = D.load_adapter(os.path.join(a.run, "hp"), scratch)
        M = A.M
        W = dict(M.GRAN)
        roots = VA.anchored_roots(lines, t0, t_snap)
        phi = M.commit(A.nodes_from_rows("closure", *D.read_final(A, db)))
        verd = VA.verify_window(phi, roots, W, t0, t1)
        first_recv = {}
        for line in lines:
            rec = json.loads(line)
            for g, segs in ((rec.get("payload") or {}).get("sealed") or {}).items():
                for s in segs:
                    first_recv.setdefault((g, str(s)), rec.get("recv_ts"))
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % pre, uri=True)
        lock_rows = con.execute("SELECT ROWID, Date FROM LightingLog WHERE DeviceRowID=? AND Date>=? AND Date<=?",
                                (lock, A.ts_date(t0), A.ts_date(t1))).fetchall()
        ds_pre = con.execute("SELECT * FROM DeviceStatus WHERE ID=?", (lock,)).fetchone()
        cols = [r[1] for r in con.execute("PRAGMA table_info(DeviceStatus)")]
        con.close()
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
        ds_post = con.execute("SELECT * FROM DeviceStatus WHERE ID=?", (lock,)).fetchone()
        con.close()
        lock_secs = {int(A.date_ts(d)) for _r, d in lock_rows}
        pred, amb = predicted_segments(lock_secs, first_recv, t_change, W)
        # offline: closure roots of the pre-change snapshot against the final one, over [t0, t_change - BAND_S]
        b1, b2 = os.path.join(scratch, "pre.db"), os.path.join(scratch, "post.db")
        shutil.copy2(pre, b1)
        shutil.copy2(db, b2)
        r1 = O.roots(A, b1, t0, t_change - BAND_S)["closure"]
        r2 = O.roots(A, b2, t0, t_change - BAND_S)["closure"]
        off_changed = sorted(k for k in set(r1) | set(r2) if r1.get(k) != r2.get(k) and int(k) <= t_change - BAND_S)
    res = {"experiment": "E10 arm C: a benign switch-type change on Domoticz, closure monitor live", "tag": a.tag,
           "window": [t0, t1], "t_change_vm": t_change, "lock_device_idx": lock,
           "change": {"applied": rep.get("change_applied"), "request": rep.get("change_request"),
                      "reply": rep.get("change_reply")},
           "devicestatus_columns_changed": sorted(c for c, x, y in zip(cols, ds_pre or [], ds_post or []) if x != y),
           "rendered_rows_changed": rep.get("rendered_rows_changed"),
           "lock_rows_in_window_before_change": len(lock_rows),
           "anchored_segments": {g: sum(1 for k in verd if k[0] == g) for g in W},
           "violations": {g: sum(1 for k, v in verd.items() if k[0] == g and v.get("violation")) for g in W},
           "agreement_with_prediction": agreement(verd, pred, amb),
           "offline_pre_vs_final": {"seconds_changed": len(off_changed),
                                    "equal_to_predicted_seconds": set(off_changed) == {s for g, s in pred if g == "second"},
                                    "first": off_changed[:20]},
           "markers": "none: the Domoticz adapter has no marker, and no marker kind of the verifier declares a "
                      "configuration field",
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(dst, "x") as fh:
        json.dump(res, fh, indent=1, default=str)
    print("wrote", dst, json.dumps(res["agreement_with_prediction"])[:600])


if __name__ == "__main__":
    main()
