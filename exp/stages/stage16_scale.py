"""STAGE 16 — scale to 10^6 nodes. The design target was 10^6-10^7; stage 6
capped at 50k, so the asymptotic claim was never tested."""
import gc, math, os, shutil, sqlite3, time
from rig import gen, graph, verify, localize, forge, truth, capability
from rig.commit import commit_full, Incremental, GRAN

WORK = "/tmp/homeprov_scale"
SIZES = [50_000, 200_000, 1_000_000]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for target in SIZES:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 4.4,
             "target_nodes": target, "span_s": target / 20.0, "max_nodes": 10**9}
        db = os.path.join(WORK, "s.db")
        t0 = time.perf_counter(); info = gen.generate(db, p, seed=91)
        gen_s = time.perf_counter() - t0
        t0 = time.perf_counter(); nodes = graph.load(db)
        load_s = time.perf_counter() - t0

        t0 = time.perf_counter(); phi = commit_full(nodes, "homeprov")
        full_s = time.perf_counter() - t0

        # incremental: replay in 5s anchor batches, disjoint
        t0min = min(n.ts for n in nodes)
        buckets = {}
        for n in nodes:
            buckets.setdefault(int((n.ts - t0min) // 5.0), []).append(n)
        inc = Incremental("homeprov"); per = []
        for i in sorted(buckets):
            s = time.perf_counter()
            inc.ingest(buckets[i]); inc.seal(t0min + (i + 1) * 5.0)
            per.append((time.perf_counter() - s) * 1000)
        per.sort()

        # detection + localization at this scale
        head = max(n.ts for n in nodes); anchor = math.floor(head) + 1.0
        con = sqlite3.connect(db)
        r = con.execute("""SELECT s.context_id_bin, sm.entity_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
             WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
               AND s.last_updated_ts < ? ORDER BY s.last_updated_ts DESC LIMIT 1""",
                       (anchor - 2.0,)).fetchone()
        con.close()
        det = loc_s = None; Qn = None
        if r:
            fdb = db + ".f"; shutil.copy(db, fdb)
            f = forge.Forger(fdb); f.ft4_reparent(r[0], os.urandom(16), r[1])
            after = graph.load(fdb)
            t0 = time.perf_counter()
            v = verify.verify(after, phi, anchor, "homeprov")
            ver_s = time.perf_counter() - t0
            t0 = time.perf_counter()
            Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
            loc_s = time.perf_counter() - t0
            det = v["detected"]; Qn = len(Q)
            os.remove(fdb)
            del after
        rows.append({"target": target, "nodes": len(nodes),
                     "gen_s": gen_s, "load_s": load_s,
                     "full_commit_s": full_s,
                     "inc_p50_ms": per[len(per)//2], "inc_p95_ms": per[int(len(per)*0.95)],
                     "inc_max_ms": per[-1], "anchors": len(per),
                     "verify_s": ver_s if r else None,
                     "localize_s": loc_s, "detected": det, "Q": Qn,
                     "phi_bytes": len(str(phi))})
        os.remove(db)
        del nodes, phi, inc, buckets; gc.collect()
    return {"stage": 16, "rows": rows,
            "claim": "incremental per-anchor cost is O(new nodes), flat in history length",
            "capability": capability.record("none", "in_process_integration", 0, 2, 5)}
