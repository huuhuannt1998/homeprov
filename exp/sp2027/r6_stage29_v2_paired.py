"""R6 (T7): does the marker-abuse table (stage 29, SP-TAB-E, Row scheme) depend on the '|' node encoding?

Runs exp/stages/stage29_marker_abuse.run() unmodified, with two thin wrappers: commit_full() also computes the 'row_v2'
commitment of the same base graph, and verify() also verifies every forged database against it. For each case the log
records the v1 and v2 violation sets; if they are identical, every column of SP-TAB-E (raw detection, the marker filter
applied to the violations, escape) is identical too, because the filter is a function of the violations, the marker and
the nodes only. Generated deployments are rebuilt with the stage's own seeds.

    python3 exp/sp2027/r6_stage29_v2_paired.py      # writes exp/out/r6_stage29_v2_paired.json (never overwrites)
"""
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import r9_common as C  # noqa: E402
C.forbid_docker()
from rig import verify as V  # noqa: E402
import stages.stage29_marker_abuse as s29  # noqa: E402

DST = os.path.join(C.OUT, "r6_stage29_v2_paired.json")
if os.path.exists(DST):
    raise SystemExit("refusing to overwrite " + DST)
s29.WORK = os.path.join(C.SCRATCH, "r6_stage29_work")
_cf, _verify = s29.commit_full, V.verify
PHI = {}
LOG = []


def commit_full(base, scheme="homeprov", grans=None):
    phi = _cf(base, scheme, grans) if grans else _cf(base, scheme)
    PHI["v2"] = _cf(base, scheme + "_v2")
    return phi


class _V:
    @staticmethod
    def verify(after, phi, anchor_ts, scheme="homeprov", **kw):
        r1 = _verify(after, phi, anchor_ts, scheme, **kw)
        r2 = _verify(after, PHI["v2"], anchor_ts, scheme + "_v2", **kw)
        key = lambda r: sorted(json.dumps(v, sort_keys=True, default=str) for v in r["violations"])  # noqa: E731
        LOG.append({"v1_detected": bool(r1["detected"]), "v2_detected": bool(r2["detected"]),
                    "violation_sets_identical": key(r1) == key(r2), "n_violations_v1": len(r1["violations"]),
                    "n_violations_v2": len(r2["violations"])})
        return r1


s29.commit_full, s29.verify = commit_full, _V
started = C.now_iso()
res = s29.run({})
pub = json.load(open(os.path.join(C.OUT, "stage29_final.json")))
for row, lg in zip(res["rows"], LOG):
    lg.update({"seed": row["seed"], "case": row["case"]})
same_as_pub = [(r["seed"], r["case"], r["raw_detected"], r["detected_after_marker"], r["escaped"], r["VACUOUS"])
               for r in res["rows"]] == [(r["seed"], r["case"], r["raw_detected"], r["detected_after_marker"], r["escaped"],
                                          r["VACUOUS"]) for r in pub["rows"]]
out = {"item": "R6/T7: stage 29 marker abuse, Row scheme, '|' vs typed encoding, paired",
       "cases": len(LOG), "violation_sets_identical": sum(1 for x in LOG if x["violation_sets_identical"]),
       "detected_v1": sum(x["v1_detected"] for x in LOG), "detected_v2": sum(x["v2_detected"] for x in LOG),
       "this_run_matches_stage29_final_rows": same_as_pub,
       "this_run_counts": {k: res[k] for k in ("n_cases", "n_escaped", "n_vacuous")},
       "published_counts": {k: pub[k] for k in ("n_cases", "n_escaped", "n_vacuous")},
       "log": LOG,
       "provenance": C.provenance(__file__, inputs=[os.path.join(C.EXP, "stages", "stage29_marker_abuse.py"),
                                                    os.path.join(C.EXP, "rig", "commit.py")],
                                  seeds={"stage29": s29.SEEDS}, extra={"started": started, "finished": C.now_iso()})}
with open(DST, "x") as fh:
    json.dump(out, fh, indent=1, default=str)
print({k: v for k, v in out.items() if k not in ("log", "provenance")})
