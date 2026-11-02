"""R6 (T8): re-measure App. C's hashing cost ("the closure scheme hashed about 1.5 times the input of the content-only
scheme and took about 1.9 times its hashing time") on a node set that ships with the artifact.

The script and the 27,132-node input behind exp/out/stage31_cost.json are lost (exp/out/r9_bd_unavailable.json). This
script measures the same quantities (mean hash-input bytes per node, total input, per-node hashing time as the median of
repeated passes, ratios to the content-only scheme) with the rig's own node_hashes(), on every row of one published
window extract (default reproduce/snapshots/e_c_clo.db, the largest closure-run window). Hash-input sizes are counted by
wrapping the rig's hash function for one pass; timings use the unwrapped function. The '|' schemes and the typed
encoding (row_v2, b2c_v2) are both measured.

    python3 exp/sp2027/r6_hashing_cost.py [--db PATH] [--reps 15]     # writes exp/out/r6_hashing_cost.json
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import statistics
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import commit as C, graph  # noqa: E402

SCHEMES = ("b2", "homeprov", "b2b", "row", "b2c", "row_v2", "b2c_v2")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", default=os.path.join(REPO, "reproduce", "snapshots", "e_c_clo.db"))
    ap.add_argument("--reps", type=int, default=15)
    ap.add_argument("--out", default=os.path.join(OUT, "r6_hashing_cost.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    nodes = graph.load(a.db)
    nodes.sort(key=lambda n: (n.ts, n.key))
    real_H = C.H
    res = {}
    for s in SCHEMES:
        sizes = []
        C.H = lambda b: (sizes.append(len(b)), hashlib.sha256(b).digest())[1]   # noqa: E731
        C.node_hashes(nodes, s)
        C.H = real_H
        times = []
        for _ in range(a.reps):
            t = time.perf_counter()
            C.node_hashes(nodes, s)
            times.append(time.perf_counter() - t)
        p50 = statistics.median(times)
        res[s] = {"mean_hash_input_bytes": round(sum(sizes) / len(sizes), 1),
                  "total_hash_input_MB": round(sum(sizes) / 1e6, 3), "hash_p50_s": round(p50, 4),
                  "hash_min_s": round(min(times), 4), "nodes_per_s": int(len(nodes) / p50)}
    for s in SCHEMES:
        res[s]["bytes_vs_b2"] = round(res[s]["mean_hash_input_bytes"] / res["b2"]["mean_hash_input_bytes"], 3)
        res[s]["time_vs_b2"] = round(res[s]["hash_p50_s"] / res["b2"]["hash_p50_s"], 3)
    out = {"item": "R6: App. C hashing cost re-measured on a published node set",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "script_sha256": hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest(),
           "node_set": {"db": os.path.relpath(os.path.abspath(a.db), REPO),
                        "db_sha256": hashlib.sha256(open(a.db, "rb").read()).hexdigest(),
                        "n_nodes": len(nodes), "loader": "exp/rig/graph.py load(), every row"},
           "reps": a.reps, "machine": {"platform": platform.platform(), "python": sys.version.split()[0],
                                       "load_avg_start": os.getloadavg()},
           "schemes": res,
           "replaces": "exp/out/stage31_cost.json (n_nodes 27132; script and node set lost, see r9_bd_unavailable.json)",
           "note": "one run on a shared machine; timings are relative (ratios to b2) and carry no interval"}
    out["machine"]["load_avg_end"] = os.getloadavg()
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out["schemes"], indent=1), out["node_set"])


if __name__ == "__main__":
    main()
