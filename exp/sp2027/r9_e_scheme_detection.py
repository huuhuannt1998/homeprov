"""R9 item (e): forgery-class detection with 60 generated deployments per class.

Re-runs the stage-31 scheme comparison exactly as exp/out/stage31_hp2.json records
it -- stage31_b2c.run() with SCHEMES extended by homeprov2 and _detect extended to
verify it (Graph keyed as homeprov2), recalibrated generator (bg_ratio 4.4 is
hard-coded in stage31_b2c.run at this HEAD), arms (1800 s, 5000 nodes) and
(7200 s, 7000 nodes) -- in two passes:

  pass 1 "reproduce": the original seeds 81-86, compared count-for-count against
          stage31_hp2.json (every scheme, every class, and strict_separations);
  pass 2 "extend":    30 NEW predeclared seeds (7001-7030) x the same 2 arms
          = 60 deployments per class, same parameters, nothing else changed.

The stage module is used unmodified; only module globals are rebound from this
driver (SEEDS, WORK, SCHEMES, _detect), plus thin wrappers around gen.generate
and graph.load that RECORD which deployment/class each detection belongs to.
Predeclared: a class with n < 60 is reported as is (no seed replacement).
Temporary deployments live in the scratchpad and are deleted by run() itself.
"""
from __future__ import annotations
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import r9_common as C  # noqa: E402
C.forbid_docker()

from rig import gen as _gen, graph as _graph, verify, stats  # noqa: E402
import stages.stage31_b2c as s31  # noqa: E402

SCHEMES_HP2 = ("homeprov", "homeprov2", "b2", "b2b", "b2c", "row")
ORIG_SEEDS = [81, 82, 83, 84, 85, 86]
EXT_SEEDS = list(range(7001, 7031))
REF = os.path.join(C.EXP, "out", "stage31_hp2.json")
WORK = os.path.join(C.SCRATCH, "b2c_work")
HP2_COMMIT = "8952cc10546abe50eee53ce48488dd78e90b0cc3"

_ORIG_DETECT = s31._detect
STATE = {"seed": None, "span": None, "last_path": None}
LOG: list = []


class _GenProxy:
    @staticmethod
    def generate(path, params, seed=0, **kw):
        STATE["seed"], STATE["span"] = seed, params.get("span_s")
        return _gen.generate(path, params, seed=seed, **kw)


class _GraphProxy:
    @staticmethod
    def load(path, *a, **kw):
        STATE["last_path"] = path
        return _graph.load(path, *a, **kw)


def _detect_hp2(after, phi, anchor_ts):
    d = _ORIG_DETECT(after, phi, anchor_ts)
    d["homeprov2"] = verify.verify(after, phi["homeprov2"], anchor_ts,
                                   "homeprov2")["detected"]
    out = {s: d[s] for s in s31.SCHEMES}
    ft = os.path.basename(STATE["last_path"] or "").split(".", 2)[-1]
    LOG.append({"seed": STATE["seed"], "span_s": STATE["span"], "ft": ft,
                **{s: bool(v) for s, v in out.items()}})
    return out


def _configure(seeds):
    s31.SEEDS = list(seeds)
    s31.WORK = WORK
    s31.SCHEMES = SCHEMES_HP2
    s31._detect = _detect_hp2
    s31.gen = _GenProxy
    s31.graph = _GraphProxy


def _counts(res):
    out = {}
    for tab in ("per_ft", "post_predeclaration"):
        for ft, v in res[tab].items():
            out[ft] = {"n": v.get("n", 0),
                       **{s: v[s]["k"] for s in res["schemes"] if s in v}}
    return out


def _run_pass(label, seeds):
    _configure(seeds)
    LOG.clear()
    os.makedirs(WORK, exist_ok=True)
    l0 = C.load_snapshot("%s start" % label)
    t0 = time.time()
    res = s31.run({})
    wall = time.time() - t0
    l1 = C.load_snapshot("%s end" % label)
    left = os.listdir(WORK)
    return {"seeds": list(seeds), "arms": s31.ARMS, "wallclock_s": round(wall, 1),
            "load": [l0, l1], "work_dir_leftovers": left,
            "result": res, "per_detection_log": list(LOG)}


def main():
    started = C.now_iso()
    ref = json.load(open(REF))
    code_unchanged = subprocess.run(
        ["git", "-C", C.REPO, "diff", "--quiet", HP2_COMMIT, "HEAD", "--",
         "exp/rig", "exp/stages/stage31_b2c.py", "exp/stages/stage20_fairbaseline.py"]
    ).returncode == 0

    rep = _run_pass("reproduce", ORIG_SEEDS)
    got, want = _counts(rep["result"]), _counts(ref)
    mism = {ft: {"ref": want.get(ft), "got": got.get(ft)}
            for ft in sorted(set(got) | set(want)) if got.get(ft) != want.get(ft)}
    sep_match = rep["result"]["strict_separations"] == ref["strict_separations"]
    rep["matches_stage31_hp2"] = {"all_counts_equal": not mism, "mismatches": mism,
                                  "strict_separations_equal": sep_match}

    ext = _run_pass("extend", EXT_SEEDS)

    # Tabulate k/n with exact Clopper-Pearson intervals (rig.stats), new seeds only,
    # and the pooled 72 (original 12 + new 60) as a secondary view.
    def table(rows):
        t = {}
        for ft in ["FT-%d" % i for i in range(1, 13)] + ["FT-U", "FT-E"]:
            rs = [r for r in rows if r["ft"] == ft]
            t[ft] = {"n": len(rs)}
            for s in SCHEMES_HP2:
                if rs:
                    t[ft][s] = stats.clopper_pearson(sum(1 for r in rs if r[s]), len(rs))
        return t

    # consistency: the log must reproduce run()'s own aggregate counts
    def agg_from_log(rows):
        return {ft: {"n": v["n"], **{s: v[s]["k"] for s in SCHEMES_HP2 if s in v}}
                for ft, v in table(rows).items()}
    ext["log_matches_run_aggregate"] = agg_from_log(ext["per_detection_log"]) == _counts(ext["result"])
    rep["log_matches_run_aggregate"] = agg_from_log(rep["per_detection_log"]) == _counts(rep["result"])

    new60 = table(ext["per_detection_log"])
    pooled = table(rep["per_detection_log"] + ext["per_detection_log"])

    res = {
        "item": "R9(e) forgery-class detection, 60 generated deployments per class",
        "scheme_keys": {"homeprov2": "Graph (as stage31_hp2.json records it)",
                        "row": "Row", "b2": "Cnt (content-only)", "b2c": "Cls (closure)",
                        "homeprov": "Gr- (pre node-key fix)",
                        "b2b": "full row without node key"},
        "reference": os.path.relpath(REF, C.REPO),
        "code_unchanged_since_stage31_hp2_commit": {"commit": HP2_COMMIT,
                                                    "paths_identical": code_unchanged},
        "reproduce_original_seeds": rep,
        "extend_new_seeds": ext,
        "table_new_60": new60,
        "table_pooled_72_secondary": pooled,
        "provenance": C.provenance(
            __file__, inputs=[REF, os.path.join(C.EXP, "stages", "stage31_b2c.py"),
                              os.path.join(C.EXP, "stages", "stage20_fairbaseline.py")],
            seeds={"original": ORIG_SEEDS, "new_predeclared": EXT_SEEDS,
                   "arms": s31.ARMS},
            extra={"started": started, "finished": C.now_iso(),
                   "work_dir": WORK}),
        "deviations": [
            "Driver re-creates the stage31_hp2 configuration (SCHEMES + homeprov2 in "
            "_detect) from the note in stage31_hp2.json; the original driver is not "
            "in the repository.",
            "WORK directory moved from /tmp/homeprov_b2c to the session scratchpad.",
            "New seeds 7001-7030 replace 81-86 for the 60-per-class arm; generator "
            "parameters, arms and forgery code unchanged.",
            "Generator context ids and some forgery bytes come from os.urandom, so "
            "databases are not byte-identical across runs; detection counts are what "
            "is compared.",
        ],
    }
    p = C.write_result("r9_e_scheme_detection_n60.json", res)
    try:
        os.rmdir(WORK)
    except OSError:
        pass
    print(p)
    print("reproduce matches:", rep["matches_stage31_hp2"])
    print("log==aggregate:", rep["log_matches_run_aggregate"], ext["log_matches_run_aggregate"])
    for ft, v in new60.items():
        print(ft, v["n"], {s: "%d/%d [%.3f,%.3f]" % (v[s]["k"], v[s]["n"], v[s]["ci_lo"], v[s]["ci_hi"])
                           for s in SCHEMES_HP2 if s in v})


if __name__ == "__main__":
    main()
