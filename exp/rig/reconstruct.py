"""A8 RECONSTRUCT — the forensic product. Consumes L2/L3, never L4.

ABSTENTION IS A FIRST-CLASS OUTPUT (insight I-4), and it is what makes soundness
provable by construction: RECONSTRUCT never asserts an attribution for an
actuation whose causal ancestry intersects Q, so Miss-R-assert = 0 follows from
the algorithm rather than from an empirical result.

  soundness    = never assert what cannot be supported   [CLAIMED, by construction]
  completeness = rarely abstain                          [MEASURED, not claimed]
"""
from __future__ import annotations
from .graph import attribution

VERIFIED, UNVERIFIABLE, CONTRADICTED = "VERIFIED", "UNVERIFIABLE", "CONTRADICTED"


def build_index(nodes) -> dict:
    """Context index, built ONCE. Rebuilding it per actuation made reconstruct
    O(n^2) and stalled the deployment sweep at 30k-node fixtures."""
    at_ctx: dict = {}
    for m in nodes:
        if m.ctx is not None:
            at_ctx.setdefault(m.ctx, []).append(m)
    return at_ctx


def ancestry(nodes, node, at_ctx=None) -> set[str]:
    """Causal ancestry via context/parent-context chaining."""
    if at_ctx is None:
        at_ctx = build_index(nodes)
    seen, frontier = set(), [node]
    while frontier:
        cur = frontier.pop()
        if cur.key in seen:
            continue
        seen.add(cur.key)
        for peer in at_ctx.get(cur.ctx, []):
            if peer.key not in seen:
                frontier.append(peer)
        if cur.par:
            for p in at_ctx.get(cur.par, []):
                if p.key not in seen:
                    frontier.append(p)
    return seen


def reconstruct(nodes, Q: set[str], viol: list[dict], tainted_ctxs=None) -> list[dict]:
    """Trust-annotated account, dependence-preserving. One entry per actuation.

    RULE ADDED 2026-08-20, after Stage 4 measured a Miss-R-assert in S3:
    BOTTOM IS NOT A SAFE ANSWER UNDER A DELETION-CAPABLE ADVERSARY.

    If a COUNT-decrease violation exists anywhere in the anchored history, then
    nodes were removed and we cannot bound WHICH contexts lost members -- the
    deleted node is absent from the post-forgery graph, so its context can never
    be recovered from what survives. An actuation that now resolves to UNKNOWN
    is therefore indistinguishable from one whose naming evidence was deleted,
    and asserting UNKNOWN with trust=VERIFIED is unsound.

    Measured failure without this rule: an actuation whose naming call_service
    was deleted reported Attr=UNKNOWN, trust=VERIFIED, while the truth was
    'service-call'. Its own ancestry never intersected Q, precisely because the
    evidence was gone.

    This is the M1 observation ("deletion yields bottom, which is suspicious")
    turned into a defence rule.
    """
    tainted_ctxs = tainted_ctxs or set()
    at_ctx = build_index(nodes)          # ONCE, not per actuation
    from .graph import build_indexes
    idx = build_indexes(nodes)           # ONCE, shared with attribution()
    out = []
    for n in nodes:
        if n.ty != "delta":
            continue
        anc = ancestry(nodes, n, at_ctx)
        if anc & Q:
            inner = min((v for v in viol), key=lambda v: v["gran"], default=None)
            out.append({"actuation": n.key, "entity": n.entity, "ts": n.ts,
                        "attr": None, "trust": UNVERIFIABLE,
                        "reason": "ancestry intersects the quarantined set",
                        "innermost_violation": inner})
            continue
        a = attribution(nodes, n.key, idx)
        if a["verdict"] == "UNKNOWN" and n.ctx is not None and n.ctx in tainted_ctxs:
            # Scoped, not blanket: abstain only where THIS actuation's context is
            # known to have lost a member. Blanket abstention on bottom-under-any-
            # deletion was measured at 136 abstentions -- trivially sound, useless.
            out.append({"actuation": n.key, "entity": n.entity, "ts": n.ts,
                        "attr": None, "trust": UNVERIFIABLE,
                        "reason": "this context lost a member (per-context count "
                                  "violation); bottom is indistinguishable from "
                                  "deleted evidence"})
            continue
        if a["verdict"] == "ABSENT":
            out.append({"actuation": n.key, "entity": n.entity, "ts": n.ts,
                        "attr": None, "trust": CONTRADICTED})
        else:
            out.append({"actuation": n.key, "entity": n.entity, "ts": n.ts,
                        "attr": a.get("principal") or a["verdict"],
                        "trust": VERIFIED,
                        "evidence": sorted(anc)[:8]})
    return _compact(out)


def _compact(acct: list[dict]) -> list[dict]:
    """Dependence-preserving compaction: merge consecutive entries that share an
    attribution and trust level, so the output is an EXPLANATION not an event dump."""
    merged = []
    for e in acct:
        if merged and merged[-1]["attr"] == e["attr"] and merged[-1]["trust"] == e["trust"] \
           and merged[-1]["entity"] == e["entity"]:
            merged[-1]["merged"] = merged[-1].get("merged", 1) + 1
            merged[-1]["ts_end"] = e["ts"]
        else:
            merged.append(dict(e))
    return merged
