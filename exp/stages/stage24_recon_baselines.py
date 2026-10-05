"""STAGE 24 (E12) -- strong reconstruction baselines.

The review's objection: whole-log invalidation (R0) is too easy a competitor, so
beating it by 0.986 says little. Five alternative quarantine policies are added,
all given the SAME violation set HOMEPROV computes, so the only thing that varies
is the policy that turns violations into a quarantine.

  R0 whole-log void            everything
  R1 fixed time window         +/- w around each violating segment (1s/1min/1h)
  R2 segment-only hierarchy    innermost violated segments, NO causal-run expansion
  R3 per-record commitment     maximum-precision bound: exactly the violating nodes
  R4 connected causal component the whole causal component touched
  R5 HOMEPROV                  sound quarantine (segments + causal-run closure)

R3 is not achievable by any scheme with aggregate segment commitments; it is the
precision ceiling, included so the reader can see how far each policy is from it.

COVERAGE IS MEASURED OVER TIME INTERVALS, NOT NODE SETS. A deleted node is absent
from the post-forgery graph, so a node-set recall cannot see it and reports a
policy that quarantines EVERYTHING as recall 0.5. Each policy is therefore
expressed as a set of covered time intervals, and a tampered node counts as
covered when its CLEAN-graph timestamp falls inside one. This is the same
correction the project already made once, when lr_regions was added.
"""
import math, os, shutil
from rig import gen, graph, forge, verify, localize, metrics, truth, stats, capability
from rig.commit import commit_full, GRAN

WORK = "/tmp/homeprov_recon"
SEEDS = [201, 202, 203, 204, 205, 206, 207, 208]
FTS = ["FT-1", "FT-4", "FT-7", "FT-10", "FT-12"]


def _apply(ft, f, adv, ent, bts):
    if ft == "FT-1":  f.ft1_delete_own_action(adv)
    elif ft == "FT-4": f.ft4_reparent(adv, os.urandom(16), ent)
    elif ft == "FT-7": f.ft7_inject_trigger("automation.auto_00", bts - 2.0)
    elif ft == "FT-10":
        f.ft1_delete_own_action(adv); f.ft4_reparent(adv, os.urandom(16), ent)
        f.ft7_inject_trigger("automation.auto_00", bts - 2.0)
    elif ft == "FT-12":
        f.ft3_delete_segment(bts - 1.0, bts + 1.0); f.ft9_backdate(adv, bts - 60.0)


def _viol_segments(viol):
    out = []
    for v in viol:
        g = v.get("gran") or v.get("granularity")
        k = v.get("seg") if "seg" in v else v.get("segment")
        if g is None or k is None:
            continue
        w = dict(GRAN).get(g)
        if w is None:
            continue
        lo = int(k) * w
        out.append((lo, lo + w))
    return out


def _r1_window(nodes, viol, width):
    segs = _viol_segments(viol)
    if not segs:
        return set()
    Q = set()
    for lo, hi in segs:
        a, b = lo - width, hi + width
        Q |= {n.key for n in nodes if a <= n.ts <= b}
    return Q


def _r2_segments_only(nodes, viol):
    """Innermost violated segments, without causal-run expansion."""
    segs = _viol_segments(viol)
    if not segs:
        return set()
    # innermost = narrowest width covering each violation
    best = {}
    for lo, hi in segs:
        w = hi - lo
        key = round(lo / w)
        if (key, w) not in best or w < best[(key, w)][1] - best[(key, w)][0]:
            best[(key, w)] = (lo, hi)
    Q = set()
    for lo, hi in best.values():
        Q |= {n.key for n in nodes if lo <= n.ts < hi}
    return Q


def _r4_component(nodes, Q_seed):
    """Whole connected causal component touched by the seed set."""
    by_key = {n.key: n for n in nodes}
    ctx_of = {n.key: n.ctx for n in nodes}
    members = {}
    for n in nodes:
        if n.ctx is not None:
            members.setdefault(n.ctx, set()).add(n.key)
    parent = {n.ctx: n.par for n in nodes if n.ctx is not None}
    seeds = {ctx_of.get(k) for k in Q_seed if ctx_of.get(k) is not None}
    seen, stack = set(), list(seeds)
    while stack:
        c = stack.pop()
        if c in seen or c is None:
            continue
        seen.add(c)
        p = parent.get(c)
        if p is not None and p not in seen:
            stack.append(p)
        for cc, pp in parent.items():
            if pp == c and cc not in seen:
                stack.append(cc)
    Q = set(Q_seed)
    for c in seen:
        Q |= members.get(c, set())
    return Q


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 4.4,
             "target_nodes": 4000, "span_s": 1800.0, "max_nodes": 10**9}
        clean = os.path.join(WORK, "c.db")
        gen.generate(clean, p, seed=seed)
        base = graph.load(clean)
        head = max(n.ts for n in base)
        anchor_ts = math.floor(head) + 1.0
        phi = commit_full(base, "homeprov2")
        import sqlite3
        con = sqlite3.connect(clean)
        ch = con.execute("""SELECT s.context_id_bin, sm.entity_id, MIN(s.last_updated_ts)
                              FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                             WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
                               AND s.last_updated_ts < ?
                             GROUP BY s.context_id_bin ORDER BY 3 DESC LIMIT 1""",
                         (head - 2.0,)).fetchone()
        con.close()
        if not ch:
            os.remove(clean); continue
        adv, ent, bts = ch
        for ft in FTS:
            db = clean + "." + ft; shutil.copy(clean, db)
            f = forge.Forger(db)
            try:
                _apply(ft, f, adv, ent, bts)
            except Exception:
                os.remove(db); continue
            if f.writes == 0:
                os.remove(db); continue
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            if not T:
                os.remove(db); continue
            r = verify.verify(after, phi, anchor_ts, "homeprov2")
            if not r["detected"]:
                os.remove(db)
                rows.append({"seed": seed, "ft": ft, "detected": False})
                continue
            viol = r["violations"]
            U = len(after)
            span_lo = min(n.ts for n in after); span_hi = max(n.ts for n in after)
            R5nodes = localize.greedy(after, viol)
            R5regions = localize.greedy_regions(after, viol)
            ts_clean = {n.key: n.ts for n in base}
            T_times = [ts_clean[k] for k in T if k in ts_clean]

            def iv_of_nodes(keys):
                t = sorted(ts_clean.get(k, after_ts.get(k)) for k in keys
                           if k in ts_clean or k in after_ts)
                return [(min(t), max(t))] if t else []
            after_ts = {n.key: n.ts for n in after}

            segs = _viol_segments(viol)
            def win(w):
                return [(lo - w, hi + w) for lo, hi in segs]
            def innermost():
                if not segs: return []
                mw = min(hi - lo for lo, hi in segs)
                return [(lo, hi) for lo, hi in segs if (hi - lo) == mw]

            pol_iv = {
                "R0_void": [(span_lo, span_hi)],
                "R1_1s": win(1.0),
                "R1_1min": win(60.0),
                "R1_1h": win(3600.0),
                "R2_segments": innermost(),
                "R3_ceiling": [(t, t) for t in T_times],
                "R4_component": iv_of_nodes(_r4_component(after, R5nodes)),
                "R5_homeprov": [tuple(r[:2]) for r in R5regions] if R5regions
                                else iv_of_nodes(R5nodes),
            }
            pol_nodes = {
                "R0_void": {n.key for n in after},
                "R1_1s": _r1_window(after, viol, 1.0),
                "R1_1min": _r1_window(after, viol, 60.0),
                "R1_1h": _r1_window(after, viol, 3600.0),
                "R2_segments": _r2_segments_only(after, viol),
                "R3_ceiling": set(T),
                "R4_component": _r4_component(after, R5nodes),
                "R5_homeprov": R5nodes,
            }

            def covered(ivs, t):
                return any(lo <= t <= hi for lo, hi in ivs)

            row = {"seed": seed, "ft": ft, "detected": True, "U": U, "T": len(T)}
            for name in pol_iv:
                ivs = pol_iv[name]
                rec = (sum(1 for t in T_times if covered(ivs, t)) / len(T_times)
                       if T_times else None)
                row[name] = {"Q": len(pol_nodes[name]),
                             "recall": rec,
                             "OQ": metrics.oq(pol_nodes[name], T, U)}
            # SET-level, not size-level: is the segment policy's quarantine the
            # SAME node set this work returns, or merely the same size?
            row["R2_equals_R5_setwise"] = (
                pol_nodes["R2_segments"] == pol_nodes["R5_homeprov"])
            row["R4_equals_R5_setwise"] = (
                pol_nodes["R4_component"] == pol_nodes["R5_homeprov"])
            rows.append(row)
            os.remove(db)
        os.remove(clean)

    names = ["R0_void","R1_1s","R1_1min","R1_1h","R2_segments","R3_ceiling",
             "R4_component","R5_homeprov"]
    det = [r for r in rows if r.get("detected")]
    summary = {}
    for nm in names:
        rec = [r[nm]["recall"] for r in det]
        oq = [r[nm]["OQ"] for r in det]
        q = [r[nm]["Q"] for r in det]
        summary[nm] = {
            "n": len(det),
            "mean_recall": sum(rec)/len(rec) if rec else None,
            "min_recall": min(rec) if rec else None,
            "sound_always": all(x >= 1.0 for x in rec) if rec else None,
            "mean_OQ": sum(oq)/len(oq) if oq else None,
            "mean_Q": sum(q)/len(q) if q else None,
        }
    return {"stage": 24, "n_rows": len(rows), "n_detected": len(det),
            "summary": summary, "rows": rows,
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 0, 5)}
