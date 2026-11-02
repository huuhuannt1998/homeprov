"""R6 (T7): do the forgery-class detections of Table 4 / App. C depend on the non-injective '|' node encoding?

Paired re-run of the r9_e_scheme_detection driver (stage31_b2c.run, original seeds 81-86 and the 30 predeclared seeds
7001-7030, both arms), with two more schemes computed on the SAME generated deployments and the SAME forged databases:
'b2c_v2' and 'row_v2' commit exactly the fields of 'b2c' (Closure) and 'row' (Row) with the canonical typed encoding of
monitor/monitor.py (encoding 'v2'). For every (deployment, forgery) the log records the four verdicts, so a v1-vs-v2
difference would show as a discordant pair. Nothing else in the stage or the rig changes.

Also checks the rig/monitor determinism gate for both encodings on one generated deployment: rig commit_full(b2c|b2c_v2)
against monitor.commit(load(db), encoding v1|v2) on the same database.

    python3 exp/sp2027/r6_rig_v2_paired.py        # writes exp/out/r6_rig_v2_paired.json (never overwrites)
"""
from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import r9_common as C  # noqa: E402
C.forbid_docker()

from rig import gen as _gen, graph as _graph, verify, stats  # noqa: E402
from rig.commit import commit_full  # noqa: E402
import stages.stage31_b2c as s31  # noqa: E402

SCHEMES = ("homeprov", "homeprov2", "b2", "b2b", "b2c", "row", "b2c_v2", "row_v2")
ORIG_SEEDS = [81, 82, 83, 84, 85, 86]
EXT_SEEDS = list(range(7001, 7031))
R9 = os.path.join(C.OUT, "r9_e_scheme_detection_n60.json")
WORK = os.path.join(C.SCRATCH, "r6_rig_v2_work")
_ORIG_DETECT = s31._detect
STATE = {"seed": None, "span": None, "last_path": None, "gate": None}
LOG: list = []


def _gate(path):
    """Rig vs shipped monitor on one clean generated database, both encodings."""
    os.environ.setdefault("HOMEPROV_SCRATCH", WORK)
    sys.path.insert(0, os.path.join(C.REPO, "monitor"))
    import monitor as M  # noqa: PLC0415
    nodes_m = M.load(path)
    base = _graph.load(path)
    out = {}
    for enc, rig_scheme in (("v1", "b2c"), ("v2", "b2c_v2")):
        pm = M.commit(nodes_m, encoding=enc)
        pr = commit_full(base, rig_scheme)
        same = all(pm[g] == pr[g] for g, _w in M.GRAN)
        diff = {g: sum(1 for k in set(pm[g]) | set(pr[g]) if pm[g].get(k) != pr[g].get(k)) for g, _w in M.GRAN}
        out[enc] = {"identical": same, "segments_differing": diff,
                    "segments": {g: len(pm[g]) for g, _w in M.GRAN}}
    return out


class _GenProxy:
    @staticmethod
    def generate(path, params, seed=0, **kw):
        STATE["seed"], STATE["span"] = seed, params.get("span_s")
        r = _gen.generate(path, params, seed=seed, **kw)
        if STATE["gate"] is None:
            STATE["gate"] = _gate(path)
        return r


class _GraphProxy:
    @staticmethod
    def load(path, *a, **kw):
        STATE["last_path"] = path
        return _graph.load(path, *a, **kw)


def _detect(after, phi, anchor_ts):
    d = _ORIG_DETECT(after, phi, anchor_ts)
    for s in ("homeprov2", "b2c_v2", "row_v2"):
        d[s] = verify.verify(after, phi[s], anchor_ts, s)["detected"]
    out = {s: d[s] for s in SCHEMES}
    ft = os.path.basename(STATE["last_path"] or "").split(".", 2)[-1]
    LOG.append({"seed": STATE["seed"], "span_s": STATE["span"], "ft": ft, **{s: bool(v) for s, v in out.items()}})
    return out


def _run(label, seeds):
    s31.SEEDS, s31.WORK, s31.SCHEMES, s31._detect = list(seeds), WORK, SCHEMES, _detect
    s31.gen, s31.graph = _GenProxy, _GraphProxy
    LOG.clear()
    os.makedirs(WORK, exist_ok=True)
    l0 = C.load_snapshot(label + " start")
    t0 = time.time()
    s31.run({})
    return {"seeds": list(seeds), "wallclock_s": round(time.time() - t0, 1), "load": [l0, C.load_snapshot(label + " end")],
            "per_detection_log": list(LOG)}


def _table(rows, schemes):
    t = {}
    for ft in ["FT-%d" % i for i in range(1, 13)] + ["FT-U", "FT-E"]:
        rs = [r for r in rows if r["ft"] == ft]
        t[ft] = {"n": len(rs), **({s: stats.clopper_pearson(sum(1 for r in rs if r[s]), len(rs)) for s in schemes}
                                  if rs else {})}
    return t


def _pairs(rows):
    out = {}
    for v1, v2 in (("b2c", "b2c_v2"), ("row", "row_v2")):
        disc = [r for r in rows if r[v1] != r[v2]]
        out[v1 + "_vs_" + v2] = {"pairs": len(rows), "both_detect": sum(1 for r in rows if r[v1] and r[v2]),
                                 "neither": sum(1 for r in rows if not r[v1] and not r[v2]),
                                 "v1_only": sum(1 for r in rows if r[v1] and not r[v2]),
                                 "v2_only": sum(1 for r in rows if r[v2] and not r[v1]),
                                 "discordant_examples": disc[:20]}
    return out


def main():
    started = C.now_iso()
    passes = {"reproduce_original_seeds": _run("orig", ORIG_SEEDS), "extend_new_seeds": _run("ext", EXT_SEEDS)}
    r9 = json.load(open(R9))
    summary = {}
    for name, ps in passes.items():
        rows = ps["per_detection_log"]
        tab = _table(rows, SCHEMES)
        ref = r9["table_new_60"] if name == "extend_new_seeds" else None
        cmp_pub = None
        if ref:
            cmp_pub = {ft: {s: [tab[ft][s]["k"], ref[ft][s]["k"]] for s in ("b2", "row", "homeprov2", "b2c")
                            if s in tab[ft] and s in ref[ft]} for ft in tab}
        summary[name] = {"paired": _pairs(rows), "table": tab,
                         "v1_counts_this_run_vs_published_r9_new60": cmp_pub}
    res = {
        "item": "R6/T7: Table 4 forgery-class detection with the typed node encoding, paired against the '|' encoding",
        "schemes": {"b2c": "Closure, '|' encoding (published)", "b2c_v2": "Closure, typed encoding v2",
                    "row": "Row, '|' encoding (published)", "row_v2": "Row, typed encoding v2",
                    "homeprov2": "Graph", "b2": "Content-only"},
        "rig_monitor_determinism_gate": STATE["gate"],
        "summary": summary,
        "passes": passes,
        "provenance": C.provenance(__file__, inputs=[R9, os.path.join(C.EXP, "stages", "stage31_b2c.py"),
                                                     os.path.join(C.EXP, "rig", "commit.py"),
                                                     os.path.join(C.REPO, "monitor", "monitor.py")],
                                   seeds={"original": ORIG_SEEDS, "new_predeclared": EXT_SEEDS, "arms": s31.ARMS},
                                   extra={"started": started, "finished": C.now_iso(), "work_dir": "scratchpad"}),
        "notes": ["Generator context ids and some forgery bytes come from os.urandom, so these deployments are not "
                  "byte-identical to r9_e's; the v1 counts of this run are listed beside r9_e's for reference only. "
                  "The v1-vs-v2 comparison is paired on identical databases."],
    }
    p = os.path.join(C.OUT, "r6_rig_v2_paired.json")
    with open(p, "x") as fh:          # never overwrite an existing result
        fh.write(json.dumps(res, indent=2, default=str) + "\n")
    try:
        os.rmdir(WORK)
    except OSError:
        pass
    print(p)
    print("gate:", json.dumps(STATE["gate"]))
    for name, s in summary.items():
        print(name, json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "discordant_examples"}
                                for k, v in s["paired"].items()}))


if __name__ == "__main__":
    main()
