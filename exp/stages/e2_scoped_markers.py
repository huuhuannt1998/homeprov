"""E2 (round 12, 2026-10-07): retention-scoped PURGE markers on generated deployments.

Question. Stage 29's "deletion hidden in a genuine purge" escaped in 4 of 4 deployments: the marker declared a
cutoff (the midpoint of the history) and the adversary's purge-shaped deletion matched it. If markers are issued by
an operator-side tool from the retention policy (rig.marker_issuer) and the verifier recomputes the cutoff from that
policy (rig.markers.filter_violations_scoped), does the same deletion become a detection, and does a benign
scheduled purge stay excused?

Setup. The four stage-29 deployments (seeds 501-504; same generator parameters, so the same databases). The purge is
scheduled at the anchor time T. Because a generated deployment spans 30 minutes, the retention window is scaled to
the history: keep_s = f * (T - lo) for f in {0.75, 0.5, 0.25}; the scoped cutoff is T - keep_s. Cases per (seed, f):
  benign   the scheduled purge alone: delete every row older than the scoped cutoff;
  hidden   stage 29's case: the scheduled purge plus the adversary's purge-shaped deletion of every row older than
           the history's midpoint;
  victim   the scheduled purge plus a purge-shaped deletion up to and including the stage-29 victim row (75th
           percentile of committed rows).
Each case is scored three ways: no marker; the declared-cutoff marker of stage 29 (cutoff = the deletion's own
upper edge, i.e. what a declaration matching the deletion would say); and the scoped marker from the policy.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.dirname(HERE)
sys.path.insert(0, EXP)
from rig import forge, graph, markers, marker_issuer, truth, verify  # noqa: E402
from rig.commit import GRAN, commit_full  # noqa: E402
from stages import stage29_marker_abuse as s29  # noqa: E402

FRACTIONS = (0.75, 0.5, 0.25)
SCHEME = "row"           # stage 29's scheme; markers act on violations, not on which fields were committed


def _score(db, base, phi, anchor_ts, declared, scoped, keep_s):
    after = graph.load(db)
    r = verify.verify(after, phi, anchor_ts, SCHEME)
    out = {"raw_detected": bool(r["detected"]), "raw_violations": r["n_violations"]}
    if declared is not None:
        hon = markers.is_honoured(declared, after)
        f = markers.filter_violations(r["violations"], [declared], GRAN, nodes=after) if hon else r
        out.update({"declared_honoured": bool(hon), "declared_detected": bool(f["detected"]),
                    "declared_violations": f["n_violations"]})
    f2 = markers.filter_violations_scoped(r["violations"], [scoped], GRAN, keep_s)
    out.update({"scoped_detected": bool(f2["detected"]), "scoped_violations": f2["n_violations"],
                "scoped_excused": f2["n_excused"],
                "history_sacrificed": round(1.0 - len(after) / len(base), 4) if base else 0.0})
    return out


def run() -> dict:
    os.makedirs(s29.WORK, exist_ok=True)
    rows = []
    for seed in s29.SEEDS:
        clean = s29._base(seed)
        base = graph.load(clean)
        if not base:
            continue
        head, lo = max(n.ts for n in base), min(n.ts for n in base)
        anchor_ts = math.floor(head) + 1.0
        phi = commit_full(base, SCHEME)
        mid = lo + (head - lo) / 2.0
        committed = [n for n in base if n.ts < anchor_ts - 5.0 and n.ctx]
        victim = committed[int(len(committed) * 0.75)] if committed else base[0]
        for f in FRACTIONS:
            keep_s = f * (anchor_ts - lo)
            scoped = marker_issuer.scoped_marker(anchor_ts, keep_s, issued_ts=anchor_ts - 120.0)
            cut = scoped["cutoff_ts"]
            cases = {"benign": (cut, None),
                     "hidden": (max(mid, cut), markers.marker(markers.PURGE, cutoff_ts=max(mid, cut))),
                     "victim": (max(victim.ts + 1e-6, cut), markers.marker(markers.PURGE, cutoff_ts=max(victim.ts + 1e-6, cut)))}
            for case, (upper, declared) in cases.items():
                db = f"{clean}.e2_{case}_{f}"
                shutil.copy(clean, db)
                fg = forge.Forger(db)
                fg.ft3_delete_segment(0, upper)
                T = truth.truth_set(clean, db)
                res = _score(db, base, phi, anchor_ts, declared, scoped, keep_s)
                rows.append({"seed": seed, "keep_fraction": f, "case": case, "deleted_upto": upper,
                             "scoped_cutoff": cut, "midpoint": mid, "victim_ts": victim.ts,
                             "deletion_beyond_cutoff_s": round(upper - cut, 3), "writes": fg.writes,
                             "tampered_nodes": len(T), "VACUOUS": fg.writes == 0, **res})
                os.remove(db)

    def tally(case, f, key):
        rs = [r for r in rows if r["case"] == case and r["keep_fraction"] == f and not r["VACUOUS"]]
        return {"k": sum(bool(r[key]) for r in rs), "n": len(rs)}
    summary = {f"{case}@{f}": {k: tally(case, f, k) for k in ("raw_detected", "declared_detected", "scoped_detected")
                               if any(k in r for r in rows if r["case"] == case)}
               for case in ("benign", "hidden", "victim") for f in FRACTIONS}
    return {"experiment": "E2 retention-scoped PURGE markers (generated deployments)", "seeds": s29.SEEDS,
            "generator_params": "stage29_marker_abuse._base", "scheme": SCHEME, "keep_fractions": FRACTIONS,
            "rows": rows, "summary": summary,
            "versions": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "markers_py_sha256": hashlib.sha256(open(os.path.join(EXP, "rig", "markers.py"), "rb").read()).hexdigest(),
                         "marker_issuer_py_sha256": hashlib.sha256(open(os.path.join(EXP, "rig", "marker_issuer.py"), "rb").read()).hexdigest()},
            "capability": {"adversary": "recorder write (DELETE) at the scheduled purge time; cannot append to the anchor "
                                        "(no append key); cannot choose the scoped cutoff",
                           "markers": "declared: harness-supplied with the deletion's own cutoff (stage 29); scoped: "
                                      "rig.marker_issuer.scoped_marker from the scaled retention policy"}}


if __name__ == "__main__":
    out = os.path.join(EXP, "out", "e2_scoped_markers_generated.json")
    res = run()
    json.dump(res, open(out, "w"), indent=1)
    print(json.dumps(res["summary"], indent=1))
    print(out, hashlib.sha256(open(out, "rb").read()).hexdigest()[:12])
