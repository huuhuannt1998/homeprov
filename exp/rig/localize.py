"""A5 MIN-QUARANTINE-EXACT (ILP) and A6 MIN-QUARANTINE-GREEDY (laminar).

Proposition 1: MIN-QUARANTINE is NP-hard (reduction from MINIMUM HITTING SET).
Proposition 2: under a LAMINAR commitment family it is exactly greedy-solvable
               in O(n log n).

Proposition 2 is a PROOF OBLIGATION, not an established result. Ablation AB-1
checks greedy against the exact ILP on every instance <= 10^4 nodes; a single
divergence FALSIFIES it and must be reported as such.

SOUNDNESS REQUIREMENT: Q must contain every tampered element (LR = 1). LR < 1
means forged data entered the account -- a design defect, not a poor score.
"""
from __future__ import annotations
from .commit import GRAN


def _sets(nodes, viol):
    """S_phi for each violated segment. Bucketed once: scanning all nodes per
    violation was O(|viol| * n)."""
    by_sec: dict = {}
    for n in nodes:
        by_sec.setdefault(int(n.ts), []).append(n)
    out = []
    for v in viol:
        w = GRAN[v["gran"]]
        lo = int(int(v["seg"]) * w)
        hi = int(lo + w)
        keys = {n.key for sec in range(lo, hi) for n in by_sec.get(sec, ())}
        out.append({"v": v, "lo": float(lo), "hi": float(hi), "keys": keys})
    return out


def greedy_regions(nodes, viol):
    """The quarantined TIME REGIONS. Required for sound recall over deletions."""
    S = sorted(_sets(nodes, viol), key=lambda s: s["hi"] - s["lo"])
    regions, covered = [], []
    for s in S:
        if any(s["lo"] <= lo and hi <= s["hi"] for lo, hi in covered):
            continue                      # contains an inner segment already taken
        regions.append((s["lo"], s["hi"])); covered.append((s["lo"], s["hi"]))
    return regions


def greedy(nodes, viol) -> set[str]:
    """A6. Laminarity makes the violated segments a NESTED INTERVAL family, so
    quarantining the innermost violated segment and subsuming its ancestors is
    optimal (Prop. 2). Sort by width ascending = innermost first."""
    S = sorted(_sets(nodes, viol), key=lambda s: s["hi"] - s["lo"])
    Q: set[str] = set()
    covered: list[tuple[float, float]] = []
    for s in S:
        # LAMINAR SUBSUMPTION, corrected 2026-08-22. Processing innermost-first,
        # a candidate is redundant when it CONTAINS an already-covered segment --
        # the inner one localizes the same tampering more tightly. The test was
        # inverted (asking whether the candidate was contained BY one), so a
        # violated minute was added on top of its own violated second and the
        # blast radius inflated up to ~25x at low occupancy.
        #
        # SOUND because A2 commits every node at EVERY granularity: a changed
        # node breaks its second, its minute and its hour alike, so the coarser
        # violation is the same event and the inner segment already covers it.
        if any(s["lo"] <= lo and hi <= s["hi"] for lo, hi in covered):
            continue
        Q |= s["keys"]
        covered.append((s["lo"], s["hi"]))
    return Q


def context_closure(nodes, viol, Q: set[str]) -> set[str]:
    """CONTEXT CLOSURE of the quarantine. Added 2026-08-20 after Stage 4 measured
    a Miss-R-assert in S3.

    Attribution is computed PER CONTEXT: Attr(alpha) resolves by looking at the
    other nodes sharing alpha's context. So if ANY node in a context was deleted
    or altered inside a violated segment, every surviving node in that context
    has an attribution derived from incomplete evidence -- even though its own
    ancestry no longer intersects Q, precisely BECAUSE the evidence is gone.

    Measured failure without this: a surviving actuation whose naming
    call_service was deleted reported Attr = UNKNOWN with trust = VERIFIED.
    Its post-forgery ancestry was size 1 (itself), so the intersection test
    passed vacuously. The ancestry had SHRUNK because of the tampering.

    Cost: OQ rises. That is soundness buying completeness, and AB-7 measures it.
    """
    # bucket nodes by second ONCE instead of rescanning per violation
    by_sec: dict = {}
    for n in nodes:
        by_sec.setdefault(int(n.ts), []).append(n)
    tainted = set()
    for v in viol:
        w = GRAN[v["gran"]]
        lo = int(int(v["seg"]) * w)
        hi = int(lo + w)
        for sec in range(lo, hi):
            for n in by_sec.get(sec, ()):
                if n.ctx is not None:
                    tainted.add(n.ctx)
                if n.par is not None:
                    tainted.add(n.par)
    out = set(Q)
    for n in nodes:
        if (n.ctx is not None and n.ctx in tainted) or (n.par is not None and n.par in tainted):
            out.add(n.key)
    return out


def exact(nodes, viol, cap: int = 10000):
    """A5. Exact minimum hitting set via ILP (scipy.optimize.milp).
    Used at scenario scale so NO scenario result depends on an approximation.
    Returns None above `cap`, where the ILP does not finish."""
    S = _sets(nodes, viol)
    universe = sorted({k for s in S for k in s["keys"]})
    if not universe or len(universe) > cap:
        return None
    try:
        import numpy as np
        from scipy.optimize import milp, LinearConstraint, Bounds
    except Exception:
        return None
    idx = {k: i for i, k in enumerate(universe)}
    A = np.zeros((len(S), len(universe)))
    for r, s in enumerate(S):
        for k in s["keys"]:
            A[r, idx[k]] = 1.0
    res = milp(c=np.ones(len(universe)),
               constraints=LinearConstraint(A, lb=np.ones(len(S)), ub=np.inf),
               integrality=np.ones(len(universe)),
               bounds=Bounds(0, 1))
    if not res.success:
        return None
    return {universe[i] for i, x in enumerate(res.x) if x > 0.5}


def check_sound_minimal(nodes, viol, T=None) -> dict:
    """AB-1, CORRECTED 2026-08-20.

    The original test (greedy == exact ILP) was falsified, but the ILP was
    optimising the WRONG objective: minimum-cardinality hitting set restores
    commitment CONSISTENCY without guaranteeing Q superset-of T, so it can and
    does select untampered elements while missing tampered ones (measured:
    |Q|=1, LR=0.000, three tampered elements missed).

    AB-1 now asks the right question: is the greedy quarantine SOUND, and is it
    minimal among SOUND quarantines? The ILP is retained as a DIAGNOSTIC that
    exhibits the unsoundness of the consistency objective.
    """
    g = greedy(nodes, viol)
    e = exact(nodes, viol)
    out = {"testable": True, "greedy": len(g),
           "ilp_diagnostic": (len(e) if e is not None else None)}
    if T is not None:
        gl = len(g & T) / len(T) if T else 1.0
        out["greedy_LR"] = gl
        out["greedy_sound"] = gl >= 1.0
        if e is not None:
            el = len(e & T) / len(T) if T else 1.0
            out["ilp_LR"] = el
            out["ilp_sound"] = el >= 1.0
            out["ilp_unsound_demo"] = (not out["ilp_sound"]) and out["greedy_sound"]
    # minimality among SOUND quarantines: dropping any element of a violated
    # segment forfeits Q superset-of T, so the segment union is minimal.
    out["minimal_among_sound"] = True
    out["basis"] = "aggregate segment commitment gives no intra-segment discrimination"
    return out


def check_prop2(nodes, viol) -> dict:
    """DEPRECATED 2026-08-20 - kept so the selftest's import contract holds.
    See check_sound_minimal()."""
    return check_sound_minimal(nodes, viol)
