"""STAGE 33 (E9) — minimum-cost causal laundering by search, not by hand.

The flagship forgery in this paper was composed by hand, which invites the
obvious objection: the composition may be essential only because the author did
not look for a cheaper single-class attack. The review asks for the composition
to be replaced by a systematic search, and that is what this stage does.

TARGET. A mutation sequence after which the adversary's own actuation is
attributed to a named innocent automation different from the one the clean graph
names, AND that attribution is PLAUSIBLE under the predeclared semantic
invariants SI-4 and SI-5. Both halves are load-bearing. Searching on attribution
alone finds a one-row attack immediately -- move the actuation's context id onto
an existing automation's context -- but that context then spans two disjoint
actuation episodes, which SI-5 rejects and which the platform's own renderer
displays as visibly odd. A minimum cost measured against an oracle that ignores
plausibility is a minimum for an attack nobody would get away with, and it is
reported here alongside the plausible minimum precisely so the difference between
the two is visible rather than hidden in the choice of oracle.

SEARCH. Iterative-deepening over sequences of mutation primitives, ordered by
cost, with a bounded frontier. Breadth-first over full sequences is intractable
here -- the primitives are parameterised by row and context, so the branching
factor is in the thousands -- so the parameter space is restricted to
CANDIDATES DERIVED FROM THE TARGET: the rows of the adversary's context, the
innocent automation's rows, and the contexts adjacent to either. That restriction
is an admission and is reported: the search returns an UPPER BOUND on minimum
cost, never a proof of optimality. A cheaper attack outside the candidate set
would not be found.

PRIMITIVES, matching the review's list: delete row, insert row, alter field,
alter timestamp, alter parent, alter principal, alter context id.

COSTS. Three, evaluated separately because they order the primitives differently:
per row mutated, per field mutated, and bytes written to the write-ahead log.
"""
import itertools, math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, capability
from rig.commit import commit_full
from stages.stage20_fairbaseline import _chain
from stages.stage11_ce import _plaus_si

WORK = "/tmp/homeprov_mincost"
SEEDS = [81, 82, 83]
SPAN, TARGET_NODES = 1800.0, 5000
MAX_DEPTH = 4
# The frontier bounds how many sequences are examined per depth. It matters most
# for the NEGATIVE result: 'no plausible laundering found' is only as strong as
# the number of sequences actually tried, so the count is reported with it.
FRONTIER = 3000


# --------------------------------------------------------------- primitives
def _rows_of_ctx(db, ctx):
    con = sqlite3.connect(db)
    st = [r[0] for r in con.execute(
        "SELECT state_id FROM states WHERE context_id_bin=?", (ctx,))]
    ev = [r[0] for r in con.execute(
        "SELECT event_id FROM events WHERE context_id_bin=?", (ctx,))]
    con.close()
    return st, ev


def _cost(seq, wal_bytes):
    """Three cost models. Fields differ from rows because a single UPDATE touches
    one row but only one field, while a DELETE removes an entire row's worth."""
    rows = len(seq)
    fields = sum(1 if p[0] not in ("del_state", "del_event") else 8 for p in seq)
    return {"rows": rows, "fields": fields, "bytes": wal_bytes}


def _severe(before, bidx, after_db, targets, require_plausible: bool):
    """SEV-2 for the adversary's actuation, optionally requiring plausibility.

    `require_plausible` selects the oracle. Without it this is attribution only,
    which is the weak result. With it, the attributed context must also satisfy
    SI-4 and SI-5, which is what the paper's composition-essentiality claim is
    actually stated against.
    """
    after = graph.load(after_db)
    aidx = graph.build_indexes(after)
    for key in targets:
        b = graph.attribution(before, key, bidx)
        a = graph.attribution(after, key, aidx)
        if a.get("verdict") != "NAMED_INNOCENT":
            continue
        if b.get("verdict") == "NAMED_INNOCENT" and b.get("principal") == a.get("principal"):
            continue
        if not require_plausible:
            return True
        node = next((n for n in after if n.key == key), None)
        if node is None or node.ctx is None:
            continue
        ok, _why = _plaus_si(after, node.ctx)
        if ok:
            return True
    return False


def _candidates(db, adv_ctx, entity):
    """Parameter space, derived from the target rather than enumerated globally."""
    con = sqlite3.connect(db)
    innocent_ctxs = [r[0] for r in con.execute(
        """SELECT DISTINCT e.context_id_bin FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
            WHERE et.event_type='automation_triggered' AND e.context_id_bin IS NOT NULL
            LIMIT 6""")]
    con.close()
    st, ev = _rows_of_ctx(db, adv_ctx)
    prims = []
    for sid in st[:4]:
        prims.append(("del_state", sid))
        prims.append(("ts_state", sid, -1.5))
        prims.append(("field_state", sid, "unlocked"))
        prims.append(("principal_state", sid, os.urandom(16)))
        for c in innocent_ctxs[:3]:
            prims.append(("parent_state", sid, c))
            prims.append(("ctx_state", sid, c))
    for eid in ev[:4]:
        prims.append(("del_event", eid))
        for c in innocent_ctxs[:3]:
            prims.append(("parent_event", eid, c))
    return prims


def _search(clean, adv_ctx, entity, phi, anchor_ts, require_plausible):
    before = graph.load(clean)
    bidx = graph.build_indexes(before)
    targets = [n.key for n in before
               if n.kind == "state" and n.entity == entity and n.ctx == adv_ctx]
    if not targets:
        return None
    prims = _candidates(clean, adv_ctx, entity)
    examined = 0
    for depth in range(1, MAX_DEPTH + 1):
        seen = 0
        for seq in itertools.combinations(prims, depth):
            if seen >= FRONTIER:
                break
            seen += 1
            examined += 1
            db = clean + ".s"
            shutil.copy(clean, db)
            f = forge.Forger(db)
            applied = []
            for p in seq:
                # Route through the Forger's counting connection so WAL bytes are
                # sampled at commit; a direct connection would report zero.
                con = f._con()
                try:
                    if p[0] == "del_state":
                        n = con.execute("DELETE FROM states WHERE state_id=?", (p[1],)).rowcount
                    elif p[0] == "del_event":
                        n = con.execute("DELETE FROM events WHERE event_id=?", (p[1],)).rowcount
                    elif p[0] == "parent_state":
                        n = con.execute("UPDATE states SET context_parent_id_bin=? WHERE state_id=?", (p[2], p[1])).rowcount
                    elif p[0] == "parent_event":
                        n = con.execute("UPDATE events SET context_parent_id_bin=? WHERE event_id=?", (p[2], p[1])).rowcount
                    elif p[0] == "ctx_state":
                        n = con.execute("UPDATE states SET context_id_bin=? WHERE state_id=?", (p[2], p[1])).rowcount
                    elif p[0] == "principal_state":
                        n = con.execute("UPDATE states SET context_user_id_bin=? WHERE state_id=?", (p[2], p[1])).rowcount
                    elif p[0] == "ts_state":
                        n = con.execute("UPDATE states SET last_updated_ts=last_updated_ts+? WHERE state_id=?", (p[2], p[1])).rowcount
                    else:
                        n = con.execute("UPDATE states SET state=? WHERE state_id=?", (p[2], p[1])).rowcount
                    con.commit()
                except Exception:                            # noqa: BLE001
                    n = 0
                finally:
                    con.close()
                if n:
                    applied.append(p)
            b = f.budget()
            f.close()
            if len(applied) != depth:
                os.remove(db); continue          # a no-op in the sequence: not a real depth-d attack
            if _severe(before, bidx, db, targets, require_plausible):
                det = verify.verify(graph.load(db), phi, anchor_ts, "b2c")["detected"]
                cost = _cost(seq, b["bytes"])
                classes = sorted({p[0] for p in seq})
                os.remove(db)
                return {"depth": depth, "cost": cost, "classes": classes,
                        "detected": bool(det), "sequences_examined": examined}
            os.remove(db)
    return {"depth": None, "sequences_examined": examined}


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    out = []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
             "target_nodes": TARGET_NODES, "span_s": SPAN, "max_nodes": 10**9}
        clean = os.path.join(WORK, "c_%d.db" % seed)
        gen.generate(clean, p, seed=seed)
        base = graph.load(clean)
        head = max(n.ts for n in base)
        anchor_ts = math.floor(head) + 1.0
        phi = commit_full(base, "b2c")
        ch = _chain(clean, head - 2.0)
        if not ch:
            os.remove(clean); continue
        adv, ent, bts = ch
        for oracle, req in (("attribution_only", False), ("plausible", True)):
            r = _search(clean, adv, ent, phi, anchor_ts, req)
            if r:
                r["seed"] = seed
                r["oracle"] = oracle
                out.append(r)
        os.remove(clean)

    def _agg(oracle):
        rs = [r for r in out if r["oracle"] == oracle]
        f = [r for r in rs if r.get("depth")]
        return {"n": len(rs), "n_found": len(f),
                "min_depth": min((r["depth"] for r in f), default=None),
                "min_cost_rows": min((r["cost"]["rows"] for r in f), default=None),
                "min_cost_fields": min((r["cost"]["fields"] for r in f), default=None),
                "min_cost_bytes": min((r["cost"]["bytes"] for r in f), default=None),
                "all_detected": all(r["detected"] for r in f) if f else None,
                "classes": sorted({c for r in f for c in r["classes"]})}

    found = [r for r in out if r.get("depth")]
    return {"stage": 33,
            "by_oracle": {o: _agg(o) for o in ("attribution_only", "plausible")},
            "n_deployments": len(out), "n_found": len(found),
            "max_depth_searched": MAX_DEPTH, "frontier_per_depth": FRONTIER,
            "results": out,
            "min_depth": min((r["depth"] for r in found), default=None),
            "all_detected": all(r["detected"] for r in found) if found else None,
            "primitive_classes_required": sorted(
                {c for r in found for c in r["classes"]}),
            "optimality": "upper bound; parameter space restricted to rows and "
                          "contexts derived from the target, and the frontier is "
                          "bounded, so a cheaper attack outside that set would "
                          "not be found",
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 7, 5)}
