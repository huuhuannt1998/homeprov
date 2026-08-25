"""STAGE 22 (E16) -- root-cause the FT-6 miss.

FT-6 detects 11/12 under HOMEPROV, B2 and B4, and 12/12 under B2b. The review
requires the missed instance be explained rather than reported as noise.

Procedure follows the review: capture clean and forged rows for the missed
instance, identify which serialized values changed, identify segment membership
and committed state, recompute the intermediate hashes, and compare the inputs
each scheme actually sees.
"""
import json, math, os, shutil, sqlite3
from rig import gen, graph, forge, verify
from rig.commit import commit_full, node_hashes

WORK = "/tmp/homeprov_ft6"
ARMS = [(1800.0, 5000), (7200.0, 7000)]
SEEDS = [81, 82, 83, 84, 85, 86]
SCHEMES = ["homeprov", "b2", "b2b", "b4"]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    cases = []
    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "c.db")
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            head = max(n.ts for n in base)
            anchor_ts = math.floor(head) + 1.0
            phi = {s: commit_full(base, s) for s in SCHEMES}
            db = clean + ".ft6"; shutil.copy(clean, db)
            con = sqlite3.connect(db)
            ids = [x[0] for x in con.execute(
                "SELECT state_id FROM states ORDER BY last_updated_ts DESC LIMIT 2")]
            rows_before = {i: con.execute(
                "SELECT state_id, metadata_id, state, last_updated_ts, "
                "context_id_bin, context_parent_id_bin FROM states WHERE state_id=?",
                (i,)).fetchone() for i in ids}
            con.close()
            f = forge.Forger(db)
            ok = True
            try:
                if len(ids) == 2:
                    f.ft6_swap_siblings(ids[0], ids[1])
                else:
                    ok = False
            except Exception:
                ok = False
            writes = f.writes

            if not ok or writes == 0:
                os.remove(db); os.remove(clean); continue
            con = sqlite3.connect(db)
            rows_after = {i: con.execute(
                "SELECT state_id, metadata_id, state, last_updated_ts, "
                "context_id_bin, context_parent_id_bin FROM states WHERE state_id=?",
                (i,)).fetchone() for i in ids}
            con.close()
            after = graph.load(db)
            det = {s: verify.verify(after, phi[s], anchor_ts, s)["detected"] for s in SCHEMES}

            # what actually changed on the two rows
            changed = {}
            for i in ids:
                b, a = rows_before.get(i), rows_after.get(i)
                if not b or not a:
                    changed[i] = "row missing"; continue
                cols = ["state_id","metadata_id","state","last_updated_ts",
                        "context_id_bin","context_parent_id_bin"]
                changed[i] = [c for c, x, y in zip(cols, b, a) if x != y]

            # node-level: are the touched nodes committed, and do their hashes move?
            keys = {"s:%d" % i for i in ids}
            hb = {k: h for _, k, h in node_hashes(base, "homeprov") if k in keys}
            ha = {k: h for _, k, h in node_hashes(after, "homeprov") if k in keys}
            bb = {k: h for _, k, h in node_hashes(base, "b2b") if k in keys}
            ba = {k: h for _, k, h in node_hashes(after, "b2b") if k in keys}
            ts_of = {n.key: n.ts for n in base if n.key in keys}
            committed = {k: (ts_of.get(k, 0.0) < anchor_ts) for k in keys}

            cases.append({
                "seed": seed, "span": span, "writes": writes,
                "detected": det,
                "MISS_homeprov": not det["homeprov"],
                "changed_columns": {str(k): v for k, v in changed.items()},
                "node_ts": {k: ts_of.get(k) for k in keys},
                "committed_before_anchor": committed,
                "hash_moved_homeprov": {k: (hb.get(k) != ha.get(k)) for k in keys},
                "hash_moved_b2b": {k: (bb.get(k) != ba.get(k)) for k in keys},
                "anchor_ts": anchor_ts, "head": head,
            })
            os.remove(db); os.remove(clean)
    misses = [c for c in cases if c["MISS_homeprov"]]
    return {"stage": 22, "n_cases": len(cases), "n_misses": len(misses),
            "misses": misses, "cases": cases}
