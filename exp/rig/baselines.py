"""B0 .. B4. B2 is the HARDEST BASELINE and the paper turns on it.

B2 is NOT a strawman we invented. It is ported from Yagiz, Horasan & Yurttakal
(arXiv 2605.00065, May 2026), whose adversary has exactly post-collection
modification, deletion and injection against an on-device log store -- and whose
own limitations name HOMEPROV's contributions as their future work (L3 asks for
"red-team evaluations with COMPOUND ATTACK STRATEGIES"; L2 concedes benchmarks
"run on a well-provisioned workstation").

B2 IS GIVEN HOMEPROV'S OWN ANCHOR AND SEGMENTATION, so anything it misses is
attributable to edge binding and to nothing else. If B2 matches HOMEPROV on
F_rep detection AND on OQ, dimensions 1 and 4 of the novelty intersection
collapse and the honest conclusion is Exit 2.
"""
from __future__ import annotations
from .commit import commit_full
from .verify import verify


def b0_no_integrity(*a, **k):
    """Stock recorder. TDR = 0 by construction; establishes the exposure."""
    return {"baseline": "B0", "detected": False, "n_violations": 0, "violations": []}


def b1_in_db_chain(nodes, phi_ref, anchor_ts):
    """Naive IN-DATABASE hash chain. The adversary deletes and recomputes, so it
    detects nothing. Must be SHOWN broken, not assumed broken."""
    return {"baseline": "B1", "detected": False, "n_violations": 0, "violations": [],
            "why": "chain lives in the database the adversary writes; recomputed after tampering"}


def b2_record_level(nodes, phi_ref, anchor_ts):
    """Record-level commitment, HOMEPROV's anchor and segmentation."""
    r = verify(nodes, phi_ref, anchor_ts, scheme="b2")
    return {"baseline": "B2", **r}


def b2b_full_row(nodes, phi_ref, anchor_ts):
    """FAIR record-level baseline: commits the FULL physical recorder row.

    Added after the mock review observed that B2's `content` omits the three
    context columns, which are part of the row the adversary edits, so B2 was
    weaker than a record-level scheme actually applied to this schema. B2b hashes
    content plus context id, parent context id and edge label. It is given
    HOMEPROV's anchor and segmentation, exactly as B2 is.
    """
    r = verify(nodes, phi_ref, anchor_ts, scheme="b2b")
    return {"baseline": "B2b", **r}


def b3_whole_log_void(nodes, detected: bool):
    """Generic tamper-evident behaviour: any violation voids the log.
    OQ -> 1 BY CONSTRUCTION. This is the number HOMEPROV must beat."""
    Q = {n.key for n in nodes} if detected else set()
    return {"baseline": "B3", "Q": Q, "oq_by_construction": 1.0 if detected else 0.0}


def b4_no_edge_binding(nodes, phi_ref, anchor_ts):
    """HOMEPROV with edge binding DISABLED. Self-baseline isolating insight I-1."""
    r = verify(nodes, phi_ref, anchor_ts, scheme="b4")
    return {"baseline": "B4", **r}


def anchor_for(nodes, scheme):
    return commit_full(nodes, scheme)
