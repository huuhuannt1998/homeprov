"""E9 code review R5 (2026-10-10): what a dishonest anchor host can do with the OPERATOR'S MARKERS, on a real chain.

A7 (exp/stages/e9_dishonest_anchor.py, exp/out/e9_dishonest_anchor.json) measured the host on the E8 chains, which hold
no operator-signed marker. Markers change the picture: the verifier reads them from the chain only (e7_verify.py
chain_markers), so a host that withholds or moves them can turn a benign purge, restore or rename into violations (a
false accusation); it cannot make a marker excuse more than it says, and a replayed marker counts once (review R3). This
script measures that on the E9 smoke run 3 (HOMEPROV-P13-exp/e9/smoke/e9s_smoke3: two monitors, copy and direct read,
with a real Home Assistant purge under a signed PURGE marker, declared renames and person swaps under signed RENAME
markers, and a real restore under a signed RESTORE marker), verified as e9_score.py verified it (LATE_BOUND = GAP_S =
30 s, the day's window and snapshot, the monitor's and the operator's public keys, the escrow, purge keep 2 days, purge
tolerance 60 s, restore tolerance 30 s):
  night1_post (the purge)    honest | withhold_purge (the PURGE marker record removed) | replay_markers
  day2 (the renames)         honest | withhold_rename (every RENAME record removed) | reorder_rename (each RENAME record
                             moved to just after the first monitor record that already carries its new digest) |
                             replay_markers
  day3 (the restore)         honest | withhold_restore (the RESTORE record removed) | replay_markers
(replay_markers: every marker record appended again at the end of the chain.) Every case's chain is RELINKED (its own
links verify) and checked with chainverify against every head the run's witness accepted. Every one-second segment the
honest verification checked gets an outcome (violation / unknown / violation_coarse_only / match, as A7 classifies
them); the property measured: no second goes from violation to match in any case (a host cannot hide tampering with
markers), and how many go from match to violation (what withholding costs the household: false accusations).
Writes exp/out/e9_dishonest_anchor_markers.json (never overwritten). Reads copies only.

    python3 exp/stages/e9_dishonest_markers.py [--run-dir DIR] [--out FILE]
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import chainverify as CV  # noqa: E402

RUN_DIR = "<research-dir>/HOMEPROV-P13-exp/e9/smoke/e9s_smoke3"
LATE_BOUND = GAP_S = 30.0
KEEP_S, PURGE_TOL_S, RESTORE_TOL_S = 2 * 86400.0, 60.0, 30.0       # e9_score.py's values for the smoke run
CONTEXTS = {   # label: (snapshot file, window, snapshot time, cases) -- the windows e9_score.py used
    "night1_post": ("snapshots/night1_post.db", (1791271212.0, 1791589032.0), 1791590067.1410701,
                    ("honest", "withhold_purge", "replay_markers")),
    "day2": ("snapshots/day2_end.db", (1791590112.0, 1791591192.0), 1791591222.455816,
             ("honest", "withhold_rename", "reorder_rename", "replay_markers")),
    "day3": ("snapshots/day3_end.db", (1791591192.0, 1791592272.0), 1791592302.457152,
             ("honest", "withhold_restore", "replay_markers")),
}
CASE_DOC = {
    "honest": "the saved chain as it is",
    "withhold_purge": "the PURGE marker record removed",
    "withhold_rename": "every RENAME marker record removed",
    "reorder_rename": "each RENAME marker record moved to just after the first monitor record that already carries its "
                      "new part digest(s)",
    "withhold_restore": "the RESTORE marker record removed",
    "replay_markers": "every marker record appended again at the end of the chain",
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def kind(r):
    m = (r.get("payload") or {}).get("marker")
    return m.get("marker") if isinstance(m, dict) else None


def build(case, recs):
    if case == "honest":
        return list(recs)
    if case.startswith("withhold_"):
        drop = case.split("_", 1)[1].upper()
        return [r for r in recs if kind(r) != drop]
    if case == "replay_markers":
        return list(recs) + [dict(r) for r in recs if kind(r)]
    if case == "reorder_rename":
        out = [r for r in recs if kind(r) != "RENAME"]
        for r in recs:
            if kind(r) != "RENAME":
                continue
            parts = r["payload"]["marker"].get("parts") or {}
            i0 = next(i for i, x in enumerate(out) if x["seq"] > r["seq"]) if any(x["seq"] > r["seq"] for x in out) \
                else len(out)
            hit = None
            for i in range(i0, len(out)):
                nm = (out[i].get("payload") or {}).get("namemap") or {}
                if parts and all(((nm.get("parts") or {}).get(p) or {}).get("digest") == d for p, d in parts.items()):
                    hit = i
                    break
            out.insert(len(out) if hit is None else hit + 1, r)
        return out
    raise ValueError(case)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN_DIR)
    ap.add_argument("--out", default=os.path.join(OUT, "e9_dishonest_anchor_markers.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    V = load(os.path.join(HERE, "e7_verify.py"), "e9r5_e7_verify")
    A7 = load(os.path.join(HERE, "e9_dishonest_anchor.py"), "e9r5_a7")
    scratch = tempfile.mkdtemp(prefix="e9r5_")
    op_pub = os.path.join(a.run_dir, "keys", "operator_sign_pub.pem")
    out = {"check": "e9_dishonest_anchor_markers (E9 code review R5)",
           "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "purge_keep_s": KEEP_S,
                          "purge_tol_s": PURGE_TOL_S, "restore_tol_s": RESTORE_TOL_S},
           "code_sha256": {p: sha(os.path.join(REPO, p)) for p in (
               "exp/stages/e9_dishonest_markers.py", "exp/stages/e9_dishonest_anchor.py", "exp/stages/e7_verify.py",
               "monitor/monitor.py", "testbed/anchord/chainverify.py", "exp/rig/marker_issuer.py")},
           "inputs": {"run_dir": a.run_dir, "operator_pubkey": {"path": op_pub, "sha256": sha(op_pub)}},
           "cases": CASE_DOC, "monitors": {}}
    for m in ("copy", "direct"):
        p = os.path.join(a.run_dir, "%s_chain.jsonl" % m)
        recs = [json.loads(line) for line in open(p) if line.strip()]
        pub = os.path.join(a.run_dir, "keys", "%s_sign_pub.pem" % m)
        esc_p = os.path.join(a.run_dir, "escrow_%s" % m, "escrow.jsonl")
        heads_p = os.path.join(a.run_dir, "witness_%s" % m, "heads.jsonl")
        heads = [json.loads(line) for line in open(heads_p) if line.strip()]
        out["inputs"][m] = {"chain": {"path": p, "sha256": sha(p), "records": len(recs)},
                            "pubkey": {"path": pub, "sha256": sha(pub)},
                            "escrow": {"path": esc_p, "bytes": os.path.getsize(esc_p)},
                            "witness_heads": {"path": heads_p, "sha256": sha(heads_p), "heads": len(heads)},
                            "markers": [{"seq": r["seq"], "kind": kind(r)} for r in recs if kind(r)]}
        M = V.load_monitor("stable", os.path.join(scratch, "mon_" + m))
        esc = V.Escrow(path=esc_p)
        mo = {}
        for label, (snap, window, tsnap, cases) in CONTEXTS.items():
            src = os.path.join(a.run_dir, snap)
            out["inputs"].setdefault("snapshots", {})[label] = {"path": src, "sha256": sha(src)}
            db = V._private_copy(src, tempfile.mkdtemp(dir=scratch))
            co, honest = {}, None
            for case in cases:
                rr = build(case, recs)
                lines = A7.relink(rr) if case != "honest" else [json.dumps(r, sort_keys=True) for r in rr]
                if case == "honest":
                    lines = [line for line in open(p).read().splitlines() if line.strip()]
                res = A7.annotate(V.verify(M, db, lines, LATE_BOUND, GAP_S, scheme="stable", t0=window[0],
                                           t1=window[1], tsnap=tsnap, escrow_lines=esc, sign_pubkey=pub,
                                           operator_pubkey=op_pub, purge_keep_s=KEEP_S, purge_tol_s=PURGE_TOL_S,
                                           restore_tol_s=RESTORE_TOL_S, recovery=False))
                if honest is None:
                    honest = res
                    pop = sorted({s for (g, s) in res["checked"] if g == "second"} | set(res["flagged_seconds"]),
                                 key=int)
                oc = {s: A7.outcome(V, res, s) for s in pop}
                res["_oc"] = oc
                cv = CV.verify_chain(("\n".join(lines) + "\n").encode(), witnessed_heads=heads)
                nm = res.get("namemap") or {}
                s_ = {"records": len(lines), "flagged_seconds": len(res["flagged_seconds"]),
                      "outcomes": dict(collections.Counter(oc.values())),
                      "markers": {"accepted": len(res["markers"]["accepted"]),
                                  "rejected": res["markers"]["rejected"],
                                  "duplicates": len(res["markers"]["duplicates"])},
                      "excused_violations": len(res["excused_violations"]),
                      "excused_keylog_violations": len(res["excused_keylog_violations"]),
                      "purge_disconnects": ((res.get("purge") or {}).get("disconnects") or {}).get("n_rows"),
                      "restore_excused": (res.get("restore") or {}).get("excused"),
                      "namemap": {"verdict": nm.get("verdict"), "unexcused_changes": nm.get("unexcused_changes"),
                                  "transitions": len(nm.get("transitions") or [])},
                      "chainverify_every_witnessed_head": {
                          "ok": cv["ok"], "records_after_the_last_witnessed_head":
                              max(0, len(lines) - max(int(h["seq"]) for h in heads)),
                          **{k: (len(v) if isinstance(v, list) else v) for k, v in cv["witnessed_heads"].items()}}}
                if case != "honest":
                    tr = collections.Counter("%s->%s" % (honest["_oc"][s], oc[s]) for s in pop)
                    s_["transitions_from_honest"] = dict(tr)
                    s_["violation_to_match"] = tr.get("violation->match", 0)
                    s_["violation_to_not_violation"] = sum(v for k, v in tr.items()
                                                           if k.startswith("violation->") and k != "violation->violation")
                    s_["newly_violation"] = sum(v for k, v in tr.items()
                                                if k.endswith("->violation") and not k.startswith("violation->"))
                    s_["newly_flagged_seconds"] = sorted(set(res["flagged_seconds"]) - set(honest["flagged_seconds"]),
                                                         key=int)[:50]
                co[case] = s_
                print("%-6s %-11s %-16s flagged %4d  outcomes %s  namemap %s  chainverify ok=%s" % (
                    m, label, case, s_["flagged_seconds"], s_["outcomes"], s_["namemap"]["verdict"], cv["ok"]),
                    flush=True)
            mo[label] = {"window": list(window), "snapshot_at": tsnap, "seconds_classified": len(pop), "cases": co}
        esc.close()
        mo["property"] = {
            "violation_to_match": {"%s/%s" % (lab, c): v.get("violation_to_match", 0) for lab, x in mo.items()
                                   for c, v in x["cases"].items() if c != "honest"},
            "violation_to_not_violation": {"%s/%s" % (lab, c): v.get("violation_to_not_violation", 0)
                                           for lab, x in mo.items() for c, v in x["cases"].items() if c != "honest"},
            "newly_violation": {"%s/%s" % (lab, c): v.get("newly_violation", 0) for lab, x in mo.items()
                                for c, v in x["cases"].items() if c != "honest"}}
        out["monitors"][m] = mo
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    shutil.rmtree(scratch, ignore_errors=True)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
