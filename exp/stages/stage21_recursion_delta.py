"""STAGE 21 (E3b) -- does the parent-hash RECURSION buy anything B2b cannot have?

Stage 20 showed a fair full-row baseline (B2b) matches HOMEPROV on every
catalogue class and beats it on FT-6, so on that evidence edge binding buys
nothing. One structural difference survives and is tested here.

B2b's hash of a child covers the parent's IDENTITY (the parent context id is a
column of the child's row) but NOT the parent's CONTENT. HOMEPROV folds the
parent's HASH into the child. So where a parent's own commitment is unavailable
but a child's commitment survives, HOMEPROV can in principle detect tampering in
the parent through the child, and B2b cannot.

Under laminar commitment every node is committed at EVERY granularity, so a
parent is unprotected only when second, minute AND hour segments covering it
have all been pruned. With the measured retention policy that means the parent
is older than 90 days while the child is recent, i.e. a causal edge spanning the
retention horizon. This measures whether the delta exists and, separately,
whether the deployment conditions it needs are realistic.
"""
import time
from rig import graph, verify
from rig.commit import commit_full, prune, GRAN, RETENTION

DAY = 86400.0


def _node(key, ts, content, ctx, par, label="causes"):
    return graph.Node(key=key, kind="event", ty="kappa", ts=ts, entity=None,
                      content=content, ctx=ctx, par=par, label=label)


def _case(gap_s, tamper):
    """One parent/child pair separated by gap_s, then `tamper` applied to parent."""
    p_ctx, c_ctx = b"P" * 16, b"C" * 16
    t_parent = 1_000_000.0
    t_child = t_parent + gap_s
    parent = _node("e:1", t_parent, b'{"v":"original"}', p_ctx, None)
    child = _node("e:2", t_child, b'{"v":"child"}', c_ctx, p_ctx)
    # filler so the child's segments are populated and the graph is non-trivial
    nodes = [parent, child]
    now = t_child + 1.0
    out = {}
    for scheme in ("homeprov", "b2b"):
        phi = commit_full(nodes, scheme)
        phi_pruned = prune(phi, now)
        after = list(nodes)
        if tamper == "content":
            after[0] = _node("e:1", t_parent, b'{"v":"FORGED"}', p_ctx, None)
        elif tamper == "delete":
            after = [child]
        r = verify.verify(after, phi_pruned, now, scheme, retention=RETENTION)
        out[scheme] = bool(r["detected"])
        out[scheme + "_levels"] = sorted(phi_pruned.keys())
    return out


def run(cfg):
    rows = []
    for label, gap in (("same-minute (1s)", 1.0),
                       ("same-hour (10min)", 600.0),
                       ("1 day", DAY),
                       ("30 days", 30 * DAY),
                       ("100 days (beyond hour retention)", 100 * DAY)):
        for tamper in ("content", "delete"):
            r = _case(gap, tamper)
            rows.append({"gap": label, "gap_s": gap, "tamper": tamper,
                         "homeprov": r["homeprov"], "b2b": r["b2b"],
                         "levels_surviving": r["homeprov_levels"],
                         "delta": bool(r["homeprov"]) and not bool(r["b2b"])})
    any_delta = any(r["delta"] for r in rows)
    return {"stage": 21, "rows": rows, "recursion_delta_exists": any_delta,
            "retention_policy": RETENTION,
            "note": ("A delta requires the parent to have NO surviving commitment at any "
                     "granularity while the child does, i.e. a causal edge spanning the "
                     "90-day hour horizon.")}
