"""E10 (round 14): the offline collusion checks on E10's own signed chains (drafts/round13/FORMAL_DRAFT.md section 6, D1 and
D2; drafts/round13/E10_DESIGN.md section 4, offline checks). No Docker; the hub's half of each case happened live in E10, the anchor
host's half is emulated here by withholding signed records from a copy of the chain (it cannot forge one: the records
are signed by the monitor). Each case is verified with the E9 verifier (exp/stages/e7_verify_e9.py, its outcome rule:
exp/stages/e9_dishonest_anchor.py outcome()) and with the patched verifier (exp/stages/e7_verify.py with
exp/stages/verifier_e10.patch; outcome rule exp/stages/e10_outcome.py).

  D2  WIPE: the hub emptied a sealed second (A7 WIPE, live); the host withholds every record that carries that second's
      root or a keylog entry listing one of the deleted rows. Prediction: honest chain -> violation; withheld, E9
      verifier -> match (the defect); withheld, patched verifier -> unknown.
  D1h BDT at 45 s (detected live): the host withholds the records of the polls strictly between the one that sealed the
      forged row's second and the insertion, so the last known poll lacking the row precedes it by seconds. Prediction:
      honest -> violation; withheld, E9 verifier -> match (benign_late); withheld, patched -> unknown (poll missing from
      the chain inside the bracket).

    python3 exp/stages/e10_collusion.py --run-dir <E10 run dir> --tag e10_main [--out-dir exp/out] [--monitor direct]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "exp"))
import e10_outcome as EO                     # noqa: E402


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


EV_NEW = _load(os.path.join(HERE, "e7_verify.py"), "e7_verify_e10")
EV_OLD = _load(os.path.join(HERE, "e7_verify_e9.py"), "e7_verify_e9_frozen") \
    if os.path.exists(os.path.join(HERE, "e7_verify_e9.py")) else None
DA = _load(os.path.join(HERE, "e9_dishonest_anchor.py"), "e9_dishonest_anchor_rule")


def payload_carries(line, second=None, keys=()):
    p = (json.loads(line).get("payload") or {})
    if p.get("observer") != "external-monitor":
        return False
    if second is not None and str(second) in ((p.get("sealed") or {}).get("second") or {}):
        return True
    heads = [p] + list(p.get("backlog") or [])
    for h in heads:
        for t, es in (h.get("keylog") or {}).items():
            for e in es if isinstance(es, list) else [es]:
                lo = int((e or {}).get("from", 0))
                for x in (e or {}).get("rows") or []:
                    if (t, lo + int(x[0])) in keys:
                        return True
    return False


def verify(EVm, run, m, lines, db, tsnap, window):
    scratch = tempfile.mkdtemp(prefix="e10col_")
    try:
        M = EVm.load_monitor("stable", scratch)
        dbc = EVm._private_copy(db, scratch)
        esc_p = os.path.join(run, "e10s", "escrow_%s" % m, "escrow.jsonl")
        esc = EVm.Escrow(path=esc_p) if os.path.exists(esc_p) else None
        kw = dict(scheme="stable", t0=window[0], t1=window[1], tsnap=tsnap, escrow_lines=esc,
                  sign_pubkey=os.path.join(run, "e10s", "%s_sign_pub.pem" % m),
                  operator_pubkey=os.path.join(run, "e10s", "operator_sign_pub.pem"),
                  purge_keep_s=29 * 86400.0, purge_tol_s=60.0, recovery=False)
        return EVm.verify(M, dbc, lines, 30.0, 30.0, **kw)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def outcome_old(res, s):
    return DA.outcome(None, DA.annotate(res), str(int(s)))


def outcome_new(res, s):
    return EO.outcome(EO.annotate(res), s)


def snap(run, label):
    for line in open(os.path.join(run, "events.jsonl")):
        e = json.loads(line)
        if e.get("type") == "snapshot" and e.get("ok") and e.get("stack") == "e10s" and e.get("label") == label:
            return os.path.join(run, e["file"]), e["t_snapshot"]
    return None, None


def results(run, op):
    out = []
    for f in sorted(os.listdir(os.path.join(run, "e10"))):
        if f.endswith("_%s.json" % op):
            out += [t for t in json.load(open(os.path.join(run, "e10", f))).get("trials", []) if not t.get("err")]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "exp", "out"))
    ap.add_argument("--monitor", default="direct", choices=("direct", "copy"))
    ap.add_argument("--max-cases", type=int, default=5, help="per check (pre-registered: 5)")
    a = ap.parse_args()
    dst = os.path.join(a.out_dir, "%s_collusion_%s.json" % (a.tag, a.monitor))
    if os.path.exists(dst):
        raise SystemExit("REFUSING: %s exists" % dst)
    run, m = a.run_dir, a.monitor
    lines = open(os.path.join(run, "e10s", "%s_chain.jsonl" % m)).read().splitlines()
    t0 = float(open(os.path.join(run, "e10s", "t_start")).read())
    out = {"check": "E10 offline collusion (D2, D1 host variant)", "monitor": m, "cases": {"D2": [], "D1h": []},
           "verifiers": {"e9": EV_OLD.__file__ if EV_OLD else None, "patched": EV_NEW.__file__}}

    db, ts = snap(run, "snap_wipe")
    wipes = results(run, "wipe")
    if db and wipes:
        for t in wipes[:a.max_cases]:
            s = int(t["second"])
            w = (max(t0, s - 3600), ts)
            honest_new = verify(EV_NEW, run, m, lines, db, ts, w)
            honest_old = verify(EV_OLD, run, m, lines, db, ts, w) if EV_OLD else None
            keys = {("states", k) for k in t.get("states_deleted") or []} | {("events", k) for k in t.get("events_deleted") or []}
            kept = [l for l in lines if not payload_carries(l, s, keys)]
            row = {"second": s, "records_withheld": len(lines) - len(kept),
                   "honest": {"patched": outcome_new(honest_new, s), "e9": outcome_old(honest_old, s) if honest_old else None}}
            wn = verify(EV_NEW, run, m, kept, db, ts, w)
            wo = verify(EV_OLD, run, m, kept, db, ts, w) if EV_OLD else None
            row["withheld"] = {"patched": outcome_new(wn, s), "e9": outcome_old(wo, s) if wo else None}
            row["predicted"] = {"honest": "violation", "withheld_e9": "match", "withheld_patched": "unknown"}
            out["cases"]["D2"].append(row)

    db, ts = snap(run, "snap_del")
    bdt = [t for t in results(run, "bdt") if float(t.get("age_s", 0)) >= 45.0]
    if db and bdt:
        P = EV_NEW.parse_chain(lines)
        polls = sorted((p for p in P["polls"].values() if p.get("copy_at") is not None), key=lambda p: p["copy_at"])
        for t in bdt[:a.max_cases]:
            sec, tc = int(t["forged_row_ts"]), t["t_commit"]
            w = (max(t0, sec - 3600), ts)
            sealing = next((p for p in polls if not p.get("unobservable") and p.get("through") is not None
                            and int(p["through"]) >= sec + 1), None)
            if sealing is None:
                continue
            drop = {p["key"][1] for p in polls if sealing["copy_at"] < p["copy_at"] < tc}
            kept = [l for l in lines if (json.loads(l).get("payload") or {}).get("seq_local") not in drop
                    or (json.loads(l).get("payload") or {}).get("observer") != "external-monitor"]
            row = {"second": sec, "age_s": t["age_s"], "polls_withheld": len(drop)}
            for name, ls in (("honest", lines), ("withheld", kept)):
                rn = verify(EV_NEW, run, m, ls, db, ts, w)
                ro = verify(EV_OLD, run, m, ls, db, ts, w) if EV_OLD else None
                row[name] = {"patched": outcome_new(rn, sec), "e9": outcome_old(ro, sec) if ro else None}
            row["predicted"] = {"honest": "violation", "withheld_e9": "match", "withheld_patched": "unknown"}
            out["cases"]["D1h"].append(row)
    os.makedirs(a.out_dir, exist_ok=True)
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote", dst)


if __name__ == "__main__":
    main()
