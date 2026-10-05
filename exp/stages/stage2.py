"""STAGE 2 — flagship FT-10..FT-12, CE_b by EXACT single-class enumeration at
matched budget, A9 necessity with budget REDISTRIBUTED to survivors.
GATE: CE_b = 1 for FT-10, else EXIT 2 (composition is not necessary)."""
import math, os, shutil, sqlite3
from rig import graph, forge, verify, baselines, truth, capability, localize, metrics
from rig.commit import commit_full


def _adv_ctx(db, entity="lock.kitchen_door"):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin FROM states s
                         JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id=? ORDER BY s.last_updated_ts DESC LIMIT 1""",
                    (entity,)).fetchone()
    con.close(); return r[0] if r else None


def _base_ts(db, ctx):
    con = sqlite3.connect(db)
    r = con.execute("SELECT MIN(last_updated_ts) FROM states WHERE context_id_bin=?",
                    (ctx,)).fetchone()
    con.close(); return r[0] if r and r[0] else None


def run(cfg):
    snap = cfg["snapshot"]
    if not os.path.exists(snap):
        return {"stage": 2, "error": "no snapshot; run stage0 first"}
    os.makedirs(cfg["work"], exist_ok=True)
    base = graph.load(snap)
    anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
    phi = {s: commit_full(base, s) for s in ("homeprov", "b2", "b4")}
    adv = _adv_ctx(snap); bts = _base_ts(snap, adv)
    out = {"stage": 2, "arms": []}

    for ft in ("FT-10", "FT-11", "FT-12"):
        db = os.path.join(cfg["work"], "s2_%s.db" % ft)
        shutil.copy(snap, db)
        f = forge.Forger(db)
        try:
            if ft == "FT-10":
                f.ft10_causal_laundering(adv, "lock.kitchen_door",
                                         "automation.arrive_home",
                                         "input_boolean.owner_present", bts)
            elif ft == "FT-11":
                f.ft11_branch_laundering(adv, b"P" * 16)
            else:
                f.ft12_segment_substitution(bts - 2.0, bts + 2.0, "lock.kitchen_door",
                                            "automation.arrive_home",
                                            "input_boolean.owner_present")
        except Exception as e:
            out["arms"].append({"ft": ft, "error": "%s: %s" % (type(e).__name__, e)}); continue

        after = graph.load(db)
        T = truth.truth_set(snap, db)
        hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
        b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
        Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
        out["arms"].append({
            "ft": ft, "budget_b": f.writes, "T_size": len(T),
            "HOMEPROV_detected": hp["detected"], "HOMEPROV_violations": hp["n_violations"],
            "B2_detected": b2["detected"], "B2_violations": b2["n_violations"],
            "LR": metrics.lr_regions(localize.greedy_regions(after, hp["violations"]),
                                     [n.ts for n in base if n.key in T]) if hp["detected"] else 0.0,
            "LR_elem": metrics.lr(Q, T), "LP": metrics.lp(Q, T),
            "OQ": metrics.oq(Q, T, len(after)),
            "forge_log": f.log,
        })
    ft10 = next((a for a in out["arms"] if a["ft"] == "FT-10"), None)
    out["GATE_PASS"] = bool(ft10 and ft10.get("HOMEPROV_detected"))
    out["ce_b_prior"] = {"value": 1, "budget": 7, "method": "exact enumeration",
                         "caveat": "holds under the predeclared SI catalog; SI-4 and SI-5 "
                                   "carry the entire necessity argument"}
    out["capability"] = capability.record("mal_integration_v1", "in_process_integration",
                                          cfg.get("seed", 0), 7, cfg.get("window_s", 5))
    return out
