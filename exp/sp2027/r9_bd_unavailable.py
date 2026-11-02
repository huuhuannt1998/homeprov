"""R9 items (b) and (d): record WHY no interval was produced.

Both items need inputs that this script searches for and does not find. Nothing
is estimated here; the file documents the search so the gap is auditable.

(b) E1 observation-window escape probabilities (0.975 / 0.183 / 0 at 0.5 / 5 /
    10 s dwell) and latency/exposure quantiles, from 55 anchored one-second
    segments over a 264 s window (RKA jrn_01M0TT14JJRFV02N6GVN2SS9CS, 2026-08-24).
    Needed: the 55 per-segment observation latencies (and positions).
(d) closure-commitment hashing cost (exp/out/stage31_cost.json: 1.478x input,
    1.868x time, 712,964 nodes/s on 27,132 nodes).
    Needed: the producing script and the 27,132-node input set.
"""
from __future__ import annotations
import glob, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import r9_common as C  # noqa: E402
C.forbid_docker()

SKIP = ("[READY]", os.sep + "archive" + os.sep, os.sep + ".git" + os.sep,
        "__pycache__", os.sep + "sp2027" + os.sep)
TEXT_EXT = (".py", ".json", ".jsonl", ".md", ".txt", ".log", ".csv", ".sh", ".yaml", ".yml")


def scan(patterns):
    hits = {}
    for root, dirs, files in os.walk(C.REPO):
        if any(s in root + os.sep for s in SKIP):
            continue
        for f in files:
            p = os.path.join(root, f)
            if not f.endswith(TEXT_EXT) or f.startswith("r9_"):
                continue
            try:
                txt = open(p, errors="replace").read()
            except Exception:
                continue
            for pat in patterns:
                if pat in txt:
                    hits.setdefault(pat, []).append(os.path.relpath(p, C.REPO))
    return hits


def git_history_files():
    r = subprocess.run(["git", "-C", C.REPO, "log", "--all", "--name-only",
                        "--pretty=format:"], capture_output=True, text=True)
    return sorted({l for l in r.stdout.splitlines() if l.strip()})


def git_grep_all_commits(pattern, exclude_json=True):
    revs = subprocess.run(["git", "-C", C.REPO, "rev-list", "--all"],
                          capture_output=True, text=True).stdout.split()
    found = set()
    for rev in revs:
        args = ["git", "-C", C.REPO, "grep", "-l", pattern, rev, "--"]
        if exclude_json:
            args.append(":!*.json")
        out = subprocess.run(args, capture_output=True, text=True).stdout
        found |= {l for l in out.splitlines() if l.strip()}
    return sorted(found), len(revs)


def item_b():
    first = subprocess.run(["git", "-C", C.REPO, "log", "--reverse", "--format=%H %aI", "--all"],
                           capture_output=True, text=True).stdout.splitlines()[0]
    hist = git_history_files()
    cand = [f for f in hist if any(k in f.lower() for k in
                                   ("e1_", "window", "latenc", "observ", "exposure", "dwell"))]
    hits = scan(["never observed", "never_observed", "obs_latency", "observation latency",
                 "dwell", "P(never observed)", "exposure"])
    # 0.975 is not k/55 for any k, so it is not a plain per-segment proportion
    k_over_55 = {k: k / 55 for k in range(50, 56)}
    return {
        "status": "NOT DONE -- raw per-segment latencies are not in the repository",
        "needed": "55 per-segment observation latencies (+ position within segment) "
                  "from the 2026-08-24 E1 run of the external monitor",
        "searched": {
            "working_tree_text_hits_excluding_READY_and_archive": hits,
            "git_history_paths_matching_e1_window_latency": cand,
            "first_commit": first,
            "note_on_dates": "RKA jrn_01M0TT14JJRFV02N6GVN2SS9CS (the E1 entry) was written "
                             "2026-08-24T21:15Z; the repository's first commit is the one "
                             "above, so the E1 run predates version control.",
            "stage27_window_py": "E23 exposure curve on a generated substrate with "
                                 "uniformly drawn write instants; not the monitor's observed "
                                 "latencies, so it cannot stand in for E1.",
        },
        "why_not_from_summary_stats": {
            "k_over_55": k_over_55,
            "comment": "0.975 equals no k/55, so the escape estimator is not a plain "
                       "fraction of the 55 segments; it cannot be rebuilt from the "
                       "published quantiles without the raw values.",
        },
    }


def _probe_node_counts():
    """Node counts of the deployments stage 31 used, under both generator
    calibrations, to test whether any of them is the 27,132-node cost input."""
    import importlib, shutil
    out = {}
    work = os.path.join(C.SCRATCH, "d_probe")
    os.makedirs(work, exist_ok=True)
    variants = {"HEAD_rig_bg4.4": (C.EXP, 4.4),
                "f644936_rig_bg24.0": (os.path.join(C.SCRATCH, "f644936", "exp"), 24.0)}
    for name, (root, bg) in variants.items():
        for m in [k for k in list(sys.modules) if k == "rig" or k.startswith("rig.")]:
            del sys.modules[m]
        sys.path.insert(0, root)
        gen = importlib.import_module("rig.gen"); graph = importlib.import_module("rig.graph")
        counts = {}
        for span, target in [(1800.0, 5000), (7200.0, 7000)]:
            for seed in [81, 82, 83, 84, 85, 86]:
                p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                     "rate_hr": 100, "history": "1d", "bg_ratio": bg,
                     "target_nodes": target, "span_s": span, "max_nodes": 10**9}
                db = os.path.join(work, "c.db")
                gen.generate(db, p, seed=seed)
                counts["%d_%d_seed%d" % (span, target, seed)] = len(graph.load(db))
                os.remove(db)
        sys.path.remove(root)
        vals = list(counts.values())
        arm1, arm2 = vals[:6], vals[6:]
        out[name] = {"per_deployment": counts, "sum_arm_1800s": sum(arm1),
                     "sum_arm_7200s": sum(arm2), "sum_all_12": sum(vals),
                     "any_single_equals_27132": 27132 in vals,
                     "any_subset_sum_equals_27132": _subset_sum(vals, 27132)}
    shutil.rmtree(work)
    return out


def _subset_sum(vals, target):
    reach = {0}
    for v in vals:
        reach |= {r + v for r in reach if r + v <= target}
    return target in reach


def item_d():
    producers, nrev = git_grep_all_commits("mean_hash_input_bytes\\|hash_p50_s\\|bytes_vs_b2")
    hits = scan(["mean_hash_input_bytes", "hash_p50_s", "bytes_vs_b2", "stage31_cost"])
    return {
        "status": "NOT DONE -- producing script and the 27,132-node input set are absent",
        "needed": "the script that wrote exp/out/stage31_cost.json and its node set",
        "searched": {
            "non_json_files_in_any_commit_writing_cost_keys": producers,
            "commits_searched": nrev,
            "working_tree_text_hits_excluding_READY_and_archive": hits,
            "node_count_probe_of_stage31_deployments": _probe_node_counts(),
        },
        "why_input_ratio_not_confirmed": "mean hash-input bytes per node depend on the "
            "node set; without it the 1.478x ratio cannot be recomputed exactly.",
    }


def main():
    started = C.now_iso()
    ref = os.path.join(C.EXP, "out", "stage31_cost.json")
    res = {"item": "R9(b) and R9(d): not produced; search record",
           "b_window_escape": item_b(), "d_hashing_cost": item_d(),
           "provenance": C.provenance(
               __file__, inputs=[ref, os.path.join(C.EXP, "stages", "stage27_window.py")],
               extra={"started": started, "finished": C.now_iso(),
                      "f644936_rig_extracted_to": os.path.join(C.SCRATCH, "f644936")})}
    p = C.write_result("r9_bd_unavailable.json", res)
    print(p)
    print(json.dumps({"b": res["b_window_escape"]["status"],
                      "d": res["d_hashing_cost"]["status"],
                      "d_probe": {k: {kk: vv for kk, vv in v.items() if kk != "per_deployment"}
                                  for k, v in res["d_hashing_cost"]["searched"]
                                  ["node_count_probe_of_stage31_deployments"].items()},
                      "d_producers": res["d_hashing_cost"]["searched"]
                      ["non_json_files_in_any_commit_writing_cost_keys"],
                      "b_hits": res["b_window_escape"]["searched"]
                      ["working_tree_text_hits_excluding_READY_and_archive"],
                      "b_hist": res["b_window_escape"]["searched"]
                      ["git_history_paths_matching_e1_window_latency"]}, indent=1))


if __name__ == "__main__":
    main()
