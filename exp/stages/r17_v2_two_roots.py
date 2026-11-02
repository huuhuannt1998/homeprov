"""Round 17 (review r6), exploratory: Theorem 1's exception X8 on a synthetic chain, registered verifier versus v2.

X8 (drafts/round13/d16f_REPORT.md, Appendix I): "A monitor that loses its state can sign two roots for one segment, and
an anchor host that reorders records could then serve the later one first." The scenario, at a fixed clock on a
synthetic recorder with Home Assistant's layout (monitor/test_coverage.py's harness, imported unchanged): monitor 1
(monitor.py, stable scheme, records signed with an Ed25519 key generated here for this run and deleted with its
temporary directory; only its fingerprint is recorded) seals seconds T0..T0+4; the hub launders the unlock of second
T0+1 (the state row's user and parent context rewritten, the service call deleted); monitor 1 loses its state; a fresh
monitor (new scratch, same key, same anchor) re-seals its re-read window, so second T0+1 gets a second signed root over
the laundered rows. Two anchors: the honest first-write-wins anchor (it refuses the second root, which the monitor
then carries signed as "conflicted") and an accepting dishonest host (it stores it as a sealed root). Two record orders:
as appended, and every record of the fresh monitor served first. Controls: the same state loss without an edit, and
with a benign late row in second T0+4 instead (the cost of the strict rule); the fresh monitor's records alone (the
residual v2 does not close); and the chain without a public key (the rule does not apply; conflicts are listed).
Outputs per second are exp/stages/e10_outcome.py's outcome() over the in-process results.

    python3 exp/stages/r17_v2_two_roots.py --out exp/out/r17_v2_two_roots.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "monitor"))
import verify_v2 as VV                          # noqa: E402
import e10_outcome as OC                        # noqa: E402
import test_coverage as TC                      # noqa: E402  (the shared harness; not edited)

EV = VV.EV
T0, LATE, GAP = TC.T0, TC.LATE, TC.GAP
STABLE = {"HOMEPROV_SCHEME": "stable"}


class AcceptingAnchor(TC.Anchor):
    """A dishonest anchor host that stores every record, a second root for a sealed segment included."""

    def append(self, rec):
        self.bodies.append(json.dumps(rec, sort_keys=True).encode())
        return self.write(json.loads(self.bodies[-1]))


def scenario(tmp, kind, edit=True, late_row=False):
    priv, pub, k = TC._keypair(tmp, "monitor")
    rec = TC.Recorder(os.path.join(tmp, "home-assistant_v2.db"))
    sid, eid = TC.history(rec, T0)
    rec.state("sensor.t4", "1", T0 + 4.2)
    anchor = TC.Anchor() if kind == "honest_first_write_wins" else AcceptingAnchor()
    r1 = TC.Rig(tmp, rec, name="m1", anchor=anchor, HOMEPROV_SIGN_KEY=priv, **STABLE)
    r1.poll(T0 + 5.0)
    if late_row:
        rec.state("sensor.t4", "2", T0 + 4.6)
    r1.poll(T0 + 10.0)
    if edit:
        rec.launder(sid, eid)
    n1 = len(anchor.lines)
    r2 = TC.Rig(tmp, rec, name="m2_fresh_scratch", anchor=anchor, HOMEPROV_SIGN_KEY=priv, **STABLE)
    r2.polls(T0 + 15.0, T0 + 20.0)
    fp = r1.M.SIGN_FP
    return rec, anchor, n1, pub, fp, r2


def outcomes(res, lo, hi):
    OC.annotate(res)
    return {str(s): OC.outcome(res, s) for s in range(lo, hi + 1)}


def run_case(tmp, rec, lines, pub, tag):
    M = EV.load_monitor("stable", os.path.join(tmp, "v1_" + tag))
    db = os.path.join(tmp, "v1_%s.db" % tag)
    shutil.copy2(rec.path, db)
    old = VV._ORIG["verify"](M, db, lines, LATE, GAP, scheme="stable", sign_pubkey=pub)
    M2 = EV.load_monitor("stable", os.path.join(tmp, "v2_" + tag))
    db2 = os.path.join(tmp, "v2_%s.db" % tag)
    shutil.copy2(rec.path, db2)
    new = VV.verify_v2(M2, db2, lines, LATE, GAP, scheme="stable", sign_pubkey=pub)
    lo, hi = int(T0), int(T0) + 4
    s = str(int(T0) + 1)

    def brief(res):
        v = next((x for x in res["violations"] if x["gran"] == "second" and x["seg"] == s), None)
        return {"flagged_seconds": res["flagged_seconds"], "per_second": outcomes(res, lo, hi),
                "second_T0_plus_1": None if v is None else {k: v.get(k) for k in ("violation", "attributable",
                                                                                   "mechanism", "v2_reason")},
                "epochs": res["P"]["epochs"], "chain_conflicted_entries": len(res["P"]["conflicted"])}
    out = {"v1_registered_verifier": brief(old), "v2": brief(new),
           "v2_conflicts": new["v2"]["conflict_rule"]["violations"]}
    if pub is None:
        out["v2_unsigned_listed"] = new["v2"]["conflict_rule"]["unsigned_conflicts_listed_only"]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    res = {"check": "r17 v2 two signed roots (Theorem 1, X8), synthetic, exploratory", "T0": T0,
           "late_bound_s": LATE, "gap_s": GAP, "edited_second": str(int(T0) + 1),
           "code_sha256": VV.code_hashes(), "harness": {"monitor/test_coverage.py": VV.sha256_file(
               os.path.join(REPO, "monitor", "test_coverage.py"))}, "cases": {}}
    fps = []
    for kind in ("honest_first_write_wins", "accepting"):
        tmp = tempfile.mkdtemp(prefix="r17x8_")
        try:
            rec, anchor, n1, pub, fp, _r2 = scenario(tmp, kind)
            fps.append(fp)
            L = anchor.lines
            orders = {"as_appended": list(L), "later_root_first": list(L[n1:]) + list(L[:n1])}
            for oname, lines in orders.items():
                res["cases"]["edit_then_state_loss/%s/%s" % (kind, oname)] = run_case(tmp, rec, lines, pub, oname)
            res["cases"]["edit_then_state_loss/%s/first_instance_withheld" % kind] = run_case(
                tmp, rec, list(L[n1:]), pub, "withheld")
            res["cases"]["edit_then_state_loss/%s/later_root_first/no_public_key" % kind] = run_case(
                tmp, rec, orders["later_root_first"], None, "nokey")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    for name, kw in (("no_change", {"edit": False}), ("benign_late_row", {"edit": False, "late_row": True})):
        tmp = tempfile.mkdtemp(prefix="r17x8c_")
        try:
            rec, anchor, n1, pub, fp, _r2 = scenario(tmp, "honest_first_write_wins", **kw)
            fps.append(fp)
            L = anchor.lines
            for oname, lines in (("as_appended", list(L)), ("later_root_first", list(L[n1:]) + list(L[:n1]))):
                res["cases"]["state_loss_%s/honest_first_write_wins/%s" % (name, oname)] = run_case(
                    tmp, rec, lines, pub, name + oname)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    res["test_key_fingerprints"] = fps
    res["summary"] = {k: {"v1": v["v1_registered_verifier"]["per_second"].get(str(int(T0) + 1)),
                          "v2": v["v2"]["per_second"].get(str(int(T0) + 1)),
                          "v1_T0+4": v["v1_registered_verifier"]["per_second"].get(str(int(T0) + 4)),
                          "v2_T0+4": v["v2"]["per_second"].get(str(int(T0) + 4))}
                      for k, v in res["cases"].items()}
    res["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(a.out, "x") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
    print(json.dumps(res["summary"], indent=1))


if __name__ == "__main__":
    main()
