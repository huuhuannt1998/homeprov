"""STAGE 4 — Thrust B. VERIFY + localization (A5 exact / A6 greedy) +
reconstruction (A8) across S1-S5, with metrics M1-M6 and the miss taxonomy.
HARD GATES: LR = 1 on EVERY run; Miss-R-assert = 0."""
import math, os, shutil, sqlite3
from rig import (graph, forge, verify, localize, reconstruct, metrics,
                 baselines, truth, capability)
from rig.commit import commit_full, context_counts, tainted_contexts


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


def _scenario(name, f, adv, bts, anchor_ts):
    if name == "S1":
        f.ft10_causal_laundering(adv, "lock.kitchen_door", "automation.arrive_home",
                                 "input_boolean.owner_present", bts)
    elif name == "S2":
        f.ft11_branch_laundering(adv, b"P" * 16)
    elif name == "S3":
        f.ft12_segment_substitution(bts - 2.0, bts + 2.0, "lock.kitchen_door",
                                    "automation.arrive_home", "input_boolean.owner_present")
    elif name == "S4":
        f.ft1_delete_own_action(adv)          # early-t_c proxy on the snapshot arm
    elif name == "S5":
        f.ft4_reparent(adv, b"K" * 16, "lock.kitchen_door")   # anchor-key-leak arm


def run(cfg):
    snap = cfg["snapshot"]
    if not os.path.exists(snap):
        return {"stage": 4, "error": "no snapshot; run stage0 first"}
    os.makedirs(cfg["work"], exist_ok=True)
    base = graph.load(snap)
    anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
    phi = {s: commit_full(base, s) for s in ("homeprov", "b2", "b4")}
    ctx_ref = context_counts(base)          # anchored alongside phi
    adv = _adv_ctx(snap); bts = _base_ts(snap, adv)
    truth_attr = truth.attribution_truth(snap)

    runs = []
    for name in ("S1", "S2", "S3", "S4", "S5"):
        db = os.path.join(cfg["work"], "s4_%s.db" % name)
        shutil.copy(snap, db)
        f = forge.Forger(db)
        try:
            _scenario(name, f, adv, bts, anchor_ts)
        except Exception as e:
            runs.append({"scenario": name, "error": "%s: %s" % (type(e).__name__, e)}); continue

        after = graph.load(db)
        T = truth.truth_set(snap, db)
        hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
        b2 = baselines.b2_record_level(after, phi["b2"], anchor_ts)
        Qg = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
        if hp["detected"]:
            Qg = localize.context_closure(after, hp["violations"], Qg)
        Qe = localize.exact(after, hp["violations"]) if hp["detected"] else None
        tainted = tainted_contexts(ctx_ref, after)
        acct = reconstruct.reconstruct(after, Qg, hp["violations"], tainted_ctxs=tainted)
        Rg = localize.greedy_regions(after, hp["violations"]) if hp["detected"] else []
        Ttimes = [n.ts for n in base if n.key in T]
        mt = metrics.miss_taxonomy(hp["detected"], Qg, T, acct, truth_attr,
                                   Q_regions=Rg, T_times=Ttimes)
        b3 = baselines.b3_whole_log_void(after, hp["detected"])
        runs.append({
            "scenario": name, "budget_b": f.writes, "T_size": len(T),
            "detected": hp["detected"], "violations": hp["n_violations"],
            "B2_detected": b2["detected"],
            "LR": metrics.lr_regions(localize.greedy_regions(after, hp["violations"]),
                                     [n.ts for n in base if n.key in T]),
            "LR_elem": metrics.lr(Qg, T), "LP": metrics.lp(Qg, T),
            "OQ": metrics.oq(Qg, T, len(after)),
            "OQ_B3": metrics.oq(b3["Q"], T, len(after)),
            "RA": metrics.ra(acct, truth_attr),
            "miss": mt,
            "Q_greedy": len(Qg), "Q_exact": (len(Qe) if Qe is not None else None),
            "prop2_holds": (len(Qg) == len(Qe)) if Qe is not None else None,
            "account_asserted": sum(1 for e in acct if e["trust"] == "VERIFIED"),
            "account_abstained": sum(1 for e in acct if e["trust"] != "VERIFIED"),
        })

    ok = [r for r in runs if "error" not in r]
    hard_lr = all(r["LR"] >= 1.0 for r in ok if r["T_size"])
    hard_assert = all(r["miss"]["Miss-R-assert"] == 0 for r in ok)
    return {"stage": 4, "runs": runs,
            "conditionals": metrics.conditionals(
                [{"T": r["T_size"], "detected": r["detected"], "LR": r["LR"], "RA": r["RA"]}
                 for r in ok]),
            "HARD_GATE_LR": hard_lr, "HARD_GATE_MISS_R_ASSERT": hard_assert,
            "GATE_PASS": hard_lr and hard_assert,
            "note": "OQ must ALSO be reported as a function of event age (laminar "
                    "retention degrades localization granularity with age by design)",
            "capability": capability.record("mal_integration_v1", "in_process_integration",
                                            cfg.get("seed", 0), 7, cfg.get("window_s", 5))}
