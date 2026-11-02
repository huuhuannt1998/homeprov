"""STAGE 6 — scale + AB-1. GATE: Proposition 2 holds empirically.
A single divergence FALSIFIES it and is reported as a falsification."""
import os, shutil, sqlite3, time
from rig import graph, localize, verify, capability
from rig.commit import commit_full, Incremental

SIZES = [1000, 10000, 50000]   # capped: 200k copies exhausted swap on a 24GB host


def _grow(src, dst, target):
    shutil.copy(src, dst)
    con = sqlite3.connect(dst); cur = con.cursor()
    n = cur.execute("SELECT COUNT(*) FROM states").fetchone()[0]
    while n < target:
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                        last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                       SELECT metadata_id,state,last_updated_ts+?,last_changed_ts+?,
                              last_reported_ts+?,context_id_bin,context_parent_id_bin,0
                         FROM states LIMIT ?""",
                    (n * 0.01, n * 0.01, n * 0.01, min(n, target - n)))
        if cur.rowcount == 0: break
        n += cur.rowcount
    con.commit(); con.close(); return n


def run(cfg):
    snap = cfg["snapshot"]
    if not os.path.exists(snap):
        return {"stage": 6, "error": "no snapshot; run stage0 first"}
    os.makedirs(cfg["work"], exist_ok=True)
    rows = []
    for target in SIZES:
        db = os.path.join(cfg["work"], "s6_%d.db" % target)
        n = _grow(snap, db, target)
        nodes = graph.load(db)
        t0 = time.perf_counter(); phi = commit_full(nodes, "homeprov")
        full_ms = (time.perf_counter() - t0) * 1000
        inc = Incremental("homeprov")
        t1 = time.perf_counter(); inc.ingest(nodes); inc.seal(1e12)
        inc_ms = (time.perf_counter() - t1) * 1000
        # AB-1 needs a REAL forgery so that T exists and soundness is testable.
        import math
        from rig import forge as _forge, truth as _truth, verify as _verify
        anchor_ts = math.floor(max(n.ts for n in nodes)) + 1.0
        db2 = db + ".forged"
        shutil.copy(db, db2)
        con2 = sqlite3.connect(db2); cur2 = con2.cursor()
        rows2 = cur2.execute("SELECT state_id,last_updated_ts FROM states "
                             "ORDER BY last_updated_ts").fetchall()
        bkt = {}
        for sid, ts in rows2:
            bkt.setdefault(int(ts), []).append(sid)
        cand = [k for k, v in bkt.items() if len(v) >= 3 and (k + 1) <= anchor_ts]
        for sid in bkt[cand[len(cand) // 2]][:3]:
            cur2.execute("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                         (b"Z" * 16, sid))
        con2.commit(); con2.close()
        after = graph.load(db2)
        T = _truth.truth_set(db, db2)
        hv = _verify.verify(after, phi, anchor_ts, "homeprov")
        ab1 = localize.check_sound_minimal(after, hv["violations"], T)
        ab1["detected"] = hv["detected"]
        os.remove(db2)
        os.remove(db)                      # free disk immediately; do not accumulate copies
        rows.append({"target": target, "nodes": len(nodes),
                     "full_recompute_ms": full_ms, "incremental_ms": inc_ms,
                     "speedup": full_ms / inc_ms if inc_ms else None,
                     "AB1_prop2": ab1})
    t = [r for r in rows if r["AB1_prop2"].get("greedy_sound") is not None]
    sound = all(r["AB1_prop2"]["greedy_sound"] for r in t) if t else None
    return {"stage": 6, "rows": rows, "AB1_greedy_sound": sound,
            "GATE_PASS": sound,
            "falsifier_note": "AB-1 CORRECTED: tests soundness + minimality-among-sound. "
                              "The original greedy==ILP test was falsified because the ILP "
                              "optimised consistency, not trust.",
            "capability": capability.record("none", "in_process_integration",
                                            cfg.get("seed", 0), 0, cfg.get("window_s", 5))}
