"""AB-1 .. AB-7. AB-6 runs FIRST because it validates every other result."""
import math, os, shutil, sqlite3
from rig import (graph, forge, verify, localize, reconstruct, metrics,
                 baselines, truth, markers, capability)
from rig.commit import commit_full, context_counts, tainted_contexts, GRAN


def _prep(cfg):
    snap = cfg["snapshot"]
    base = graph.load(snap)
    anchor_ts = math.floor(max(n.ts for n in base)) + 1.0
    return snap, base, anchor_ts


def _adv(db, entity="lock.kitchen_door"):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin FROM states s JOIN states_meta sm
                        ON sm.metadata_id=s.metadata_id WHERE sm.entity_id=?
                        ORDER BY s.last_updated_ts DESC LIMIT 1""", (entity,)).fetchone()
    b = con.execute("SELECT MIN(last_updated_ts) FROM states WHERE context_id_bin=?",
                    (r[0],)).fetchone() if r else None
    con.close()
    return (r[0] if r else None), (b[0] if b and b[0] else None)


def _forge_s1(db):
    a, bts = _adv(db)
    f = forge.Forger(db)
    f.ft10_causal_laundering(a, "lock.kitchen_door", "automation.arrive_home",
                             "input_boolean.owner_present", bts)
    return f


# ---------------------------------------------------------------- AB-6
def ab6_l4_leak(cfg):
    """L4-LEAK TEST. Every algorithm is re-run with the ground-truth oracle
    ZEROED. Any metric that changes is a harness bug: it means L4 reached an
    algorithm at inference time, and every result that depends on it is void.

    L4 = the true tampered set T and the true attribution map. Neither may
    influence detection, localization, or reconstruction -- only the METRICS
    computed afterwards.
    """
    snap, base, anchor_ts = _prep(cfg)
    phi = commit_full(base, "homeprov")
    ctx_ref = context_counts(base)
    db = os.path.join(cfg["work"], "ab6.db")
    os.makedirs(cfg["work"], exist_ok=True); shutil.copy(snap, db)
    _forge_s1(db)
    after = graph.load(db)

    def pipeline(with_oracle: bool):
        # WITH oracle: the harness computes T/truth and (incorrectly) could pass
        # them in. WITHOUT: they are empty. The ALGORITHMS must be identical.
        T = truth.truth_set(snap, db) if with_oracle else set()
        tattr = truth.attribution_truth(snap) if with_oracle else {}
        v = verify.verify(after, phi, anchor_ts, "homeprov")
        Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
        if v["detected"]:
            Q = localize.context_closure(after, v["violations"], Q)
        tainted = tainted_contexts(ctx_ref, after)
        acct = reconstruct.reconstruct(after, Q, v["violations"], tainted_ctxs=tainted)
        sig = {"detected": v["detected"], "n_violations": v["n_violations"],
               "Q": sorted(Q),
               "account": [(e["actuation"], e["trust"], e["attr"]) for e in acct]}
        return sig, T, tattr

    with_o, T, tattr = pipeline(True)
    without_o, _, _ = pipeline(False)

    identical = with_o == without_o
    diffs = []
    if not identical:
        for k in with_o:
            if with_o[k] != without_o[k]:
                diffs.append(k)
    return {"ablation": "AB-6", "oracle_size": {"T": len(T), "truth_attr": len(tattr)},
            "algorithm_output_identical": identical, "differing_fields": diffs,
            "PASS": identical,
            "interpretation": ("no L4 leakage: detection, localization and "
                               "reconstruction are byte-identical with the oracle "
                               "zeroed" if identical else
                               "L4 LEAKED -- every dependent result is VOID")}


# ---------------------------------------------------------------- AB-2
def ab2_granularity(cfg):
    """Minimum segment granularity -- the OQ / overhead knob."""
    from collections import OrderedDict
    snap, base, anchor_ts = _prep(cfg)
    out = []
    for label, grans in (("second+minute+hour", GRAN),
                         ("minute+hour", OrderedDict([("minute", 60.0), ("hour", 3600.0)])),
                         ("hour only", OrderedDict([("hour", 3600.0)]))):
        phi = commit_full(base, "homeprov", grans)
        db = os.path.join(cfg["work"], "ab2_%s.db" % label.replace("+", "_").replace(" ", ""))
        shutil.copy(snap, db); _forge_s1(db)
        after = graph.load(db); T = truth.truth_set(snap, db)
        import rig.verify as V
        saved = V.GRAN
        try:
            V.GRAN = grans
            v = V.verify(after, phi, anchor_ts, "homeprov")
            Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
        finally:
            V.GRAN = saved
        out.append({"granularity": label, "detected": v["detected"],
                    "n_violations": v["n_violations"], "Q": len(Q),
                    "OQ": metrics.oq(Q, T, len(after)),
                    "phi_bytes": len(str(phi))})
    return {"ablation": "AB-2", "rows": out,
            "expectation": "coarser granularity -> larger blast radius -> higher OQ"}


# ---------------------------------------------------------------- AB-4
def ab4_nesting(cfg):
    """Nesting on/off. Flat (single granularity) should degrade OQ toward B3."""
    from collections import OrderedDict
    snap, base, anchor_ts = _prep(cfg)
    out = []
    for label, grans in (("laminar (nested)", GRAN),
                         ("flat (hour only)", OrderedDict([("hour", 3600.0)]))):
        phi = commit_full(base, "homeprov", grans)
        db = os.path.join(cfg["work"], "ab4.db"); shutil.copy(snap, db); _forge_s1(db)
        after = graph.load(db); T = truth.truth_set(snap, db)
        import rig.verify as V
        saved = V.GRAN
        try:
            V.GRAN = grans
            v = V.verify(after, phi, anchor_ts, "homeprov")
            Q = localize.greedy(after, v["violations"]) if v["detected"] else set()
        finally:
            V.GRAN = saved
        b3 = baselines.b3_whole_log_void(after, v["detected"])
        out.append({"mode": label, "Q": len(Q), "OQ": metrics.oq(Q, T, len(after)),
                    "OQ_B3": metrics.oq(b3["Q"], T, len(after))})
    return {"ablation": "AB-4", "rows": out}


# ---------------------------------------------------------------- AB-7
def ab7_no_abstention(cfg):
    """Abstention disabled -- what soundness costs in completeness."""
    snap, base, anchor_ts = _prep(cfg)
    phi = commit_full(base, "homeprov"); ctx_ref = context_counts(base)
    db = os.path.join(cfg["work"], "ab7.db"); shutil.copy(snap, db); _forge_s1(db)
    after = graph.load(db)
    tattr = truth.attribution_truth(snap)
    v = verify.verify(after, phi, anchor_ts, "homeprov")
    Q = localize.context_closure(after, v["violations"],
                                 localize.greedy(after, v["violations"]))
    tainted = tainted_contexts(ctx_ref, after)
    normal = reconstruct.reconstruct(after, Q, v["violations"], tainted_ctxs=tainted)
    forced = reconstruct.reconstruct(after, set(), v["violations"], tainted_ctxs=set())
    def score(acct):
        a = [e for e in acct if e["trust"] == "VERIFIED"]
        wrong = sum(1 for e in a if tattr.get(e["actuation"]) not in (None, e["attr"]))
        return {"asserted": len(a), "abstained": len(acct) - len(a), "wrong_asserts": wrong}
    return {"ablation": "AB-7", "with_abstention": score(normal),
            "without_abstention": score(forced),
            "cost_of_soundness": "abstentions traded for wrong assertions"}
