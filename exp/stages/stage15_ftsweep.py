"""STAGE 15 — the full FT-1..FT-12 catalog swept across deployments.

Stage 1 demonstrated every atomic class on ONE deployment; only FT-1 and FT-4
were later swept. This runs the whole catalog across the grid so the taxonomy
table in the paper carries per-class detection rates with intervals, and so the
B2/B4 comparison is per-class rather than per-example.
"""
import math, os, shutil, sqlite3
from rig import (gen, graph, forge, verify, localize, metrics, truth,
                 baselines, stats, capability)
from rig.commit import commit_full

WORK = "/tmp/homeprov_ft"
ARMS = [(1800.0, 5000), (7200.0, 7000)]
SEEDS = [81, 82, 83, 84, 85, 86]


def _chain(db, before):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin, sm.entity_id, MIN(s.last_updated_ts)
                         FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
                          AND s.last_updated_ts < ?
                        GROUP BY s.context_id_bin ORDER BY 3 DESC LIMIT 1""",
                    (before,)).fetchone()
    con.close(); return r


def _apply(ft, f, adv, ent, bts, db, anchor_ts):
    auto, trig = "automation.auto_00", "input_boolean.trigger_00"
    if ft == "FT-1":  f.ft1_delete_own_action(adv)
    elif ft == "FT-2": f.ft2_delete_intermediate()
    elif ft == "FT-3": f.ft3_delete_segment(bts - 1.0, bts + 1.0)
    elif ft == "FT-4": f.ft4_reparent(adv, os.urandom(16), ent)
    elif ft == "FT-5": f.ft5_reparent_branch(adv, os.urandom(16))
    elif ft == "FT-6":
        con = sqlite3.connect(db)
        ids = [x[0] for x in con.execute(
            "SELECT state_id FROM states ORDER BY last_updated_ts DESC LIMIT 2")]
        con.close()
        if len(ids) == 2: f.ft6_swap_siblings(*ids)
    elif ft == "FT-7": f.inject_state(trig, "on", os.urandom(16), None, bts - 2.0, ft)
    elif ft == "FT-8": f.inject_event("call_service", {"domain": "person", "service": "see"},
                                      os.urandom(16), None, bts - 2.0, ft)
    elif ft == "FT-9":
        A = os.urandom(16)
        f.inject_event("automation_triggered", {"entity_id": auto, "name": auto},
                       A, None, bts - 2.0, ft)
        f.inject_state(ent, "unlocked", A, None, bts - 1.5, ft)
    elif ft == "FT-10": f.ft10_causal_laundering(adv, ent, auto, trig, bts)
    elif ft == "FT-11": f.ft11_branch_laundering(adv, os.urandom(16))
    elif ft == "FT-12": f.ft12_segment_substitution(bts - 2.0, bts + 2.0, ent, auto, trig)


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    fts = ["FT-%d" % i for i in range(1, 13)]
    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": 4.4,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "c.db")
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            head = max(n.ts for n in base)
            anchor_ts = math.floor(head) + 1.0
            phi = {s: commit_full(base, s) for s in ("homeprov", "b2", "b4")}
            ch = _chain(clean, head - 2.0)
            if not ch:
                os.remove(clean); continue
            adv, ent, bts = ch
            for ft in fts:
                db = clean + "." + ft
                shutil.copy(clean, db)
                f = forge.Forger(db)
                try:
                    _apply(ft, f, adv, ent, bts, db, anchor_ts)
                except Exception:
                    os.remove(db); continue
                if f.writes == 0:
                    os.remove(db); continue
                after = graph.load(db)
                T = truth.truth_set(clean, db)
                if not T:
                    os.remove(db); continue
                hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
                b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
                b4 = baselines.b4_no_edge_binding(after, phi["b4"], anchor_ts)
                Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
                R = localize.greedy_regions(after, hp["violations"]) if hp["detected"] else []
                Tt = [n.ts for n in base if n.key in T]
                rows.append({"ft": ft, "seed": seed, "span_s": span,
                             "writes_b": f.writes, "T": len(T),
                             "hp": 1.0 if hp["detected"] else 0.0,
                             "b2": 1.0 if b2["detected"] else 0.0,
                             "b4": 1.0 if b4["detected"] else 0.0,
                             "LR": metrics.lr_regions(R, Tt) if hp["detected"] else 0.0,
                             "OQ": metrics.oq(Q, T, len(after))})
                os.remove(db)
            os.remove(clean)

    per = {}
    for ft in fts:
        rs = [r for r in rows if r["ft"] == ft]
        if not rs:
            per[ft] = {"n": 0}
            continue
        per[ft] = {"n": len(rs),
                   "hp": stats.clopper_pearson(int(sum(r["hp"] for r in rs)), len(rs)),
                   "b2": stats.clopper_pearson(int(sum(r["b2"] for r in rs)), len(rs)),
                   "b4": stats.clopper_pearson(int(sum(r["b4"] for r in rs)), len(rs)),
                   "mean_b": sum(r["writes_b"] for r in rs) / len(rs),
                   "min_LR": min(r["LR"] for r in rs),
                   "mean_OQ": sum(r["OQ"] for r in rs) / len(rs)}
    hard = all(r["LR"] >= 1.0 for r in rows if r["hp"] == 1.0)
    return {"stage": 15, "n_rows": len(rows), "per_ft": per,
            "HARD_GATE_LR": hard, "GATE_PASS": hard,
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 7, 5)}
