"""STAGE 25 -- mock-review batch: E13, E11, E15, E10.

E13 exhaustive small-graph validation of soundness and minimality
E11 adversarial/malformed graph fuzzing against verifier invariants
E15 generator sensitivity across structural parameters
E10 lifecycle-marker abuse

All run against the FIXED scheme (homeprov2, node identity bound, per E16).
"""
import itertools, math, os, random, shutil, time
from rig import gen, graph, forge, verify, localize, metrics, truth, markers, stats
from rig.commit import commit_full, GRAN

WORK = "/tmp/homeprov_batch"


# ---------------------------------------------------------------- E13
def e13_exhaustive(max_n=7, max_tamper=2):
    """Enumerate small graphs, tamper every subset, check soundness and whether
    any proper subset of the quarantine could also be sound on the same evidence."""
    N = graph.Node
    results = {"instances": 0, "sound": 0, "unsound": [],
               "minimal_checked": 0, "proper_subset_sound": []}
    rnd = random.Random(7)
    for n in range(3, max_n + 1):
        for shape in range(6):          # a few parent-linkage shapes per size
            nodes = []
            ctxs = [bytes([i + 1]) * 16 for i in range(n)]
            for i in range(n):
                par = None
                if i and shape:
                    par = ctxs[max(0, i - (shape % max(1, i)) - 1)]
                nodes.append(N(key="e:%d" % i, kind="event", ty="kappa",
                               ts=1000.0 + i, entity=None,
                               content=b'{"i":%d}' % i,
                               ctx=ctxs[i], par=par, label="causes"))
            phi = commit_full(nodes, "homeprov2")
            anchor_ts = 1000.0 + n + 1
            for k in range(1, max_tamper + 1):
                for idx in itertools.combinations(range(n), k):
                    after = []
                    for i, nd in enumerate(nodes):
                        if i in idx:
                            after.append(N(key=nd.key, kind=nd.kind, ty=nd.ty, ts=nd.ts,
                                           entity=None, content=b'{"i":%d,"X":1}' % i,
                                           ctx=nd.ctx, par=nd.par, label=nd.label))
                        else:
                            after.append(nd)
                    r = verify.verify(after, phi, anchor_ts, "homeprov2")
                    results["instances"] += 1
                    T = {nodes[i].key for i in idx}
                    if not r["detected"]:
                        results["unsound"].append({"n": n, "shape": shape,
                                                   "tampered": sorted(T),
                                                   "why": "not detected"})
                        continue
                    Q = localize.greedy(after, r["violations"])
                    if T <= Q:
                        results["sound"] += 1
                    else:
                        results["unsound"].append({"n": n, "shape": shape,
                                                   "tampered": sorted(T),
                                                   "Q": sorted(Q)})
                    # minimality: can any proper subset of Q still cover T?
                    results["minimal_checked"] += 1
                    for drop in Q:
                        sub = Q - {drop}
                        if T <= sub:
                            results["proper_subset_sound"].append(
                                {"n": n, "tampered": sorted(T), "dropped": drop})
                            break
    return results


# ---------------------------------------------------------------- E11
def e11_fuzz(trials=400):
    """Malformed / adversarial graph structures. The verifier must never crash,
    hang, or label a malformed COMMITTED region clean."""
    N = graph.Node
    rnd = random.Random(11)
    cases = ["self_parent", "cycle2", "cycle_n", "dup_context", "ctx_swap",
             "future_parent", "cross_parent", "deep_chain", "fan_out",
             "orphan_storm", "repeat_reparent", "dangling", "ts_inversion",
             "parent_after_child", "dup_identity"]
    out = {c: {"n": 0, "crash": 0, "timeout": 0, "undetected_committed": 0}
           for c in cases}
    for t in range(trials):
        c = cases[t % len(cases)]
        n = rnd.randint(4, 12)
        ctxs = [bytes([i + 1]) * 16 for i in range(n)]
        nodes = [N(key="e:%d" % i, kind="event", ty="kappa", ts=1000.0 + i,
                   entity=None, content=b'{"i":%d}' % i, ctx=ctxs[i],
                   par=(ctxs[i - 1] if i else None), label="causes")
                 for i in range(n)]
        phi = commit_full(nodes, "homeprov2")
        anchor_ts = 1000.0 + n + 1
        a = [N(**{**nd.__dict__}) for nd in nodes]
        try:
            if c == "self_parent":       a[2] = a[2].__class__(**{**a[2].__dict__, "par": a[2].ctx})
            elif c == "cycle2":
                a[1] = a[1].__class__(**{**a[1].__dict__, "par": a[2].ctx})
                a[2] = a[2].__class__(**{**a[2].__dict__, "par": a[1].ctx})
            elif c == "cycle_n":
                for i in range(n): a[i] = a[i].__class__(**{**a[i].__dict__, "par": ctxs[(i + 1) % n]})
            elif c == "dup_context":     a[3] = a[3].__class__(**{**a[3].__dict__, "ctx": a[1].ctx})
            elif c == "ctx_swap":
                a[1], a[2] = (a[1].__class__(**{**a[1].__dict__, "ctx": a[2].ctx}),
                              a[2].__class__(**{**a[2].__dict__, "ctx": a[1].ctx}))
            elif c == "future_parent":   a[1] = a[1].__class__(**{**a[1].__dict__, "par": ctxs[n - 1]})
            elif c == "cross_parent":    a[2] = a[2].__class__(**{**a[2].__dict__, "par": os.urandom(16)})
            elif c == "deep_chain":      pass
            elif c == "fan_out":
                for i in range(1, n): a[i] = a[i].__class__(**{**a[i].__dict__, "par": ctxs[0]})
            elif c == "orphan_storm":
                for i in range(1, n): a[i] = a[i].__class__(**{**a[i].__dict__, "par": os.urandom(16)})
            elif c == "repeat_reparent":
                for _ in range(5): a[2] = a[2].__class__(**{**a[2].__dict__, "par": os.urandom(16)})
            elif c == "dangling":        a[1] = a[1].__class__(**{**a[1].__dict__, "par": os.urandom(16)})
            elif c == "ts_inversion":
                a[1] = a[1].__class__(**{**a[1].__dict__, "ts": a[3].ts})
                a[3] = a[3].__class__(**{**a[3].__dict__, "ts": 1000.0 + 1})
            elif c == "parent_after_child":
                a[1] = a[1].__class__(**{**a[1].__dict__, "ts": a[0].ts - 10})
            elif c == "dup_identity":    a[3] = a[3].__class__(**{**a[3].__dict__, "key": a[1].key})
        except Exception:
            out[c]["crash"] += 1; continue
        out[c]["n"] += 1
        t0 = time.time()
        try:
            r = verify.verify(a, phi, anchor_ts, "homeprov2")
        except Exception:
            out[c]["crash"] += 1; continue
        if time.time() - t0 > 10:
            out[c]["timeout"] += 1
        # every mutation above alters committed state, so a clean verdict is a miss
        if c != "deep_chain" and not r["detected"]:
            out[c]["undetected_committed"] += 1
    return out


# ---------------------------------------------------------------- E15
def e15_sensitivity():
    """Vary structural parameters one at a time; the measured testbed point for
    parent-context fraction (~0.012) is marked."""
    os.makedirs(WORK, exist_ok=True)
    base = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
            "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
            "target_nodes": 3000, "span_s": 1800.0, "max_nodes": 10**9}
    sweeps = {
        "bg_ratio": [4.0, 12.0, 24.0, 48.0, 96.0],     # drives parent-context fraction
        "n_aut": [3, 8, 15, 30],
        "n_dev": [5, 25, 60],
        "rate_hr": [20, 100, 400],
        "interlock": [0.0, 0.3, 0.7],
    }
    rows = []
    for pname, vals in sweeps.items():
        for v in vals:
            p = dict(base); p[pname] = v
            db = os.path.join(WORK, "s.db")
            gen.generate(db, p, seed=301)
            nodes = graph.load(db)
            if not nodes:
                os.remove(db); continue
            with_parent = sum(1 for n in nodes if n.par) / len(nodes)
            head = max(n.ts for n in nodes); anchor_ts = math.floor(head) + 1.0
            t0 = time.time(); phi = commit_full(nodes, "homeprov2")
            t_commit = time.time() - t0
            phi_bytes = sum(len(str(v)) for g in phi.values() for v in g.values())
            # tamper one committed node and measure
            import sqlite3
            f = forge.Forger(db)
            try:
                f.ft2_delete_intermediate()
            except Exception:
                pass
            after = graph.load(db)
            t0 = time.time(); r = verify.verify(after, phi, anchor_ts, "homeprov2")
            t_verify = time.time() - t0
            T = truth.truth_set_from_nodes(nodes, after) if hasattr(truth, "truth_set_from_nodes") else set()
            Q = localize.greedy(after, r["violations"]) if r["detected"] else set()
            rows.append({"param": pname, "value": v, "n_nodes": len(nodes),
                         "parent_ctx_fraction": round(with_parent, 4),
                         "detected": r["detected"], "Q": len(Q),
                         "OQ": len(Q) / max(1, len(after)),
                         "commit_s": round(t_commit, 4),
                         "verify_s": round(t_verify, 4),
                         "phi_bytes": phi_bytes})
            os.remove(db)
    return {"rows": rows, "measured_testbed_parent_ctx_fraction": 0.012}


def run(cfg):
    return {"stage": 25,
            "E13_exhaustive": e13_exhaustive(),
            "E11_fuzz": e11_fuzz(),
            "E15_sensitivity": e15_sensitivity()}
