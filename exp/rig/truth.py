"""L4 ORACLE — ground truth T, for METRIC COMPUTATION ONLY.

L4 is an upper bound, not a capability. No algorithm in rig/ may read this
module; it exists so the harness can compute LP/LR/OQ. Ablation AB-6 verifies
the separation by re-running every algorithm with L4 zeroed and asserting no
metric moves.
"""
from __future__ import annotations
from .graph import load


def truth_set(db_before: str, db_after: str) -> set[str]:
    """T = elements added, removed, or whose content/structure changed."""
    a = {n.key: n for n in load(db_before)}
    b = {n.key: n for n in load(db_after)}
    T = set()
    T |= set(a) ^ set(b)                                   # added or removed
    for k in set(a) & set(b):
        if (a[k].content != b[k].content or a[k].ctx != b[k].ctx
                or a[k].par != b[k].par or a[k].label != b[k].label):
            T.add(k)                                        # content OR structure
    return T


def attribution_truth(db_before: str) -> dict:
    """True Attr for every actuation, from the pre-forgery graph."""
    from .graph import attribution, build_indexes
    nodes = load(db_before)
    idx = build_indexes(nodes)
    out = {}
    for n in nodes:
        if n.ty == "delta":
            a = attribution(nodes, n.key, idx)
            out[n.key] = a.get("principal") or a["verdict"]
    return out
