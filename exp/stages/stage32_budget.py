"""STAGE 32 (E8) — attack-budget robustness under three budget models.

The review's objection is exact: the capability record said ``db_writes_max``
and ``a database write'' is ambiguous, because one SQL statement can modify many
rows and neither number says how much was written. A composition-essentiality
result stated against an ambiguous budget establishes little, since the composed
attack could be winning on the axis nobody bounded.

Three models are measured per forgery rather than reconstructed afterwards:

  B_rows   rows inserted, updated or deleted
  B_sql    SQL statements issued
  B_bytes  bytes appended to the write-ahead log

The third needed care to measure at all. SQLite grows the WAL at commit and
truncates it when the writing connection closes, so a reading taken afterwards
reports zero for every forgery; ``rig/forge.py`` samples at commit and pins a
connection open so the log survives to be read.

Two arms, and the second is the one that carries the argument:

  NATURAL         each class applied once, costing what it costs.
  BUDGET-MATCHED  each ATOMIC class repeated until it has spent at least the
                  flagship composition's row budget. Without this arm the stage
                  answers a weaker question than the review asked -- the
                  composition costs more, so "it merely spent more" would not be
                  excluded. An atomic class that becomes a no-op under repetition
                  has exhausted what it can do at any budget, which is the answer
                  for that class.
"""
import math, os, shutil
from rig import gen, graph, forge, verify, truth, capability, stats
from rig.commit import commit_full
from stages.stage20_fairbaseline import _chain, _apply

WORK = "/tmp/homeprov_budget"
ARMS = [(1800.0, 5000), (7200.0, 7000)]
SEEDS = [81, 82, 83, 84, 85, 86]
ATOMIC = ["FT-1", "FT-4", "FT-7"]          # delete / re-parent / inject
COMPOSED = ["FT-10", "FT-11", "FT-12"]     # the laundering compositions
MATCH_TARGET = "FT-10"                     # flagship, whose budget is matched


def _severe(clean_db, forged_db, adv_ctx, entity) -> bool:
    """Did the forgery reach SEV-2 for the adversary's own actuation?

    SEV-2 is "attribution moves to a named innocent". Two subtleties, and each
    one reverses the result if got wrong.

    It must be scoped to the actuation performed under the adversary's context,
    identified in the CLEAN graph so a forgery that rewrites the context cannot
    hide the target. Accepting any named verdict on any row of the same entity
    reports severity for forgeries that never touched the actuation; measured
    here that alone took atomic severity from zero to a majority.

    And on these generated deployments the selected chain is itself
    automation-caused, so the clean verdict is ALREADY a named automation. The
    severe outcome is therefore a change of named party, not a first naming.
    Requiring "was not named before" scores every laundering as harmless.
    """
    before = graph.load(clean_db)
    after = graph.load(forged_db)
    bidx, aidx = graph.build_indexes(before), graph.build_indexes(after)
    targets = [n.key for n in before
               if n.kind == "state" and n.entity == entity and n.ctx == adv_ctx]
    if not targets:
        return False
    for key in targets:
        b = graph.attribution(before, key, bidx)
        a = graph.attribution(after, key, aidx)
        if a.get("verdict") != "NAMED_INNOCENT":
            continue
        if b.get("verdict") != "NAMED_INNOCENT" or b.get("principal") != a.get("principal"):
            return True
    return False


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
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
            phi = commit_full(base, "b2c")
            ch = _chain(clean, head - 2.0)
            if not ch:
                os.remove(clean); continue
            adv, ent, bts = ch

            budgets = {}
            for ft in COMPOSED + ATOMIC:          # composition first, to set the cap
                db = clean + "." + ft
                shutil.copy(clean, db)
                f = forge.Forger(db)
                try:
                    _apply(ft, f, adv, ent, bts, db, anchor_ts)
                except Exception:
                    f.close(); os.remove(db); continue
                b = f.budget(); f.close()
                if b["rows"] == 0 and b["sql_statements"] <= 1:
                    os.remove(db); continue
                budgets[ft] = b
                after = graph.load(db)
                det = verify.verify(after, phi, anchor_ts, "b2c")["detected"]
                rows.append({"ft": ft, "seed": seed, "span_s": span,
                             "arm": "natural", "composed": ft in COMPOSED, "reps": 1,
                             "severe": _severe(clean, db, adv, ent),
                             "detected": 1.0 if det else 0.0,
                             "T": len(truth.truth_set(clean, db)), **b})
                os.remove(db)

            cap = budgets.get(MATCH_TARGET)
            if not cap:
                os.remove(clean); continue
            for ft in ATOMIC:
                db = clean + "." + ft + ".m"
                shutil.copy(clean, db)
                f = forge.Forger(db)
                reps = 0
                while f.budget()["rows"] < cap["rows"] and reps < 40:
                    prev = f.budget()["rows"]
                    try:
                        _apply(ft, f, adv, ent, bts, db, anchor_ts)
                    except Exception:
                        break
                    reps += 1
                    if f.budget()["rows"] == prev:
                        break                      # class exhausted; more budget buys nothing
                b = f.budget(); f.close()
                if b["rows"] == 0:
                    os.remove(db); continue
                after = graph.load(db)
                det = verify.verify(after, phi, anchor_ts, "b2c")["detected"]
                rows.append({"ft": ft, "seed": seed, "span_s": span,
                             "arm": "budget-matched", "composed": False, "reps": reps,
                             "severe": _severe(clean, db, adv, ent),
                             "detected": 1.0 if det else 0.0, "T": 0, **b})
                os.remove(db)
            os.remove(clean)

    def _summ(sel):
        out = {}
        for ft in ATOMIC + COMPOSED:
            rs = [r for r in rows if r["ft"] == ft and sel(r)]
            if not rs:
                out[ft] = {"n": 0}; continue
            out[ft] = {"n": len(rs), "composed": ft in COMPOSED,
                       "reps_mean": sum(r["reps"] for r in rs) / len(rs),
                       "rows_mean": sum(r["rows"] for r in rs) / len(rs),
                       "sql_mean": sum(r["sql_statements"] for r in rs) / len(rs),
                       "bytes_mean": sum(r["bytes"] for r in rs) / len(rs),
                       "severe": stats.clopper_pearson(
                           sum(1 for r in rs if r["severe"]), len(rs)),
                       "detected": stats.clopper_pearson(
                           int(sum(r["detected"] for r in rs)), len(rs))}
        return out

    def _curve(unit):
        pts = []
        for B in sorted({r[unit] for r in rows}):
            fits = [r for r in rows if r[unit] <= B]
            atom = [r for r in fits if not r["composed"]]
            comp = [r for r in fits if r["composed"]]
            pts.append({"budget": B, "n_fitting": len(fits),
                        "atomic_severe": sum(1 for r in atom if r["severe"]),
                        "atomic_n": len(atom),
                        "composed_severe": sum(1 for r in comp if r["severe"]),
                        "composed_n": len(comp),
                        "composition_essential": bool(
                            any(r["severe"] for r in comp) and
                            not any(r["severe"] for r in atom))})
        return pts

    def _min_sev(unit, composed):
        c = [r[unit] for r in rows if r["severe"] and r["composed"] == composed]
        return min(c) if c else None

    return {"stage": 32, "n": len(rows),
            "natural": _summ(lambda r: r["arm"] == "natural"),
            "budget_matched_atomic": _summ(lambda r: r["arm"] == "budget-matched"),
            "curves": {u: _curve(u) for u in ("rows", "sql_statements", "bytes")},
            "headline": {u: {"min_budget_severe_atomic": _min_sev(u, False),
                             "min_budget_severe_composed": _min_sev(u, True)}
                         for u in ("rows", "sql_statements", "bytes")},
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 7, 5)}
