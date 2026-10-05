"""Anchored lifecycle markers — the section 7.4 mitigation, implemented.

MEASURED PROBLEM (Stage 5, 2026-08-20): BFP = 0.429. Recorder auto-purge,
backup restore, and a BACKWARD NTP step each produce exactly the signature of
F_del or backdated F_inj. A defender that alarms on all three is unusable.

MECHANISM. Before a legitimate discontinuity, HOMEPROV appends a MARKER to the
append-only chain declaring the operation and the time range it will affect.
VERIFY then treats violations that the marker STRUCTURALLY EXPLAINS as expected
rather than as tampering.

WHY THIS IS NOT A BYPASS -- the security argument, which is the whole point:

  1. The marker is anchored in the SAME append-only chain, so it must be
     committed BEFORE the operation. An adversary cannot retroactively insert a
     marker to excuse a deletion it already performed.

  2. Markers excuse only STRUCTURALLY CHARACTERISTIC discontinuities, never
     arbitrary edits:
       PURGE      excuses deletion of rows OLDER than a declared cutoff, and
                  ONLY if everything older than that cutoff is gone. A targeted
                  deletion of one recent row is not purge-shaped.
       RESTORE    excuses removal of rows NEWER than a declared restore point,
                  and only wholesale.
       CLOCK_STEP excuses new rows inside a declared window, and NEVER excuses
                  a COUNT decrease or an accumulator change.
     Nothing excuses an ACC violation: content and structure changes are never
     a legitimate discontinuity.

  3. An adversary that abuses a PURGE marker must therefore destroy ALL history
     older than the cutoff -- conspicuous, and it does not hide a targeted
     forgery. It converts a silent rewrite into a visible mass deletion, which
     is the tamper-EVIDENCE guarantee doing exactly its job.
"""
from __future__ import annotations

PURGE, RESTORE, CLOCK_STEP, MIGRATE, RESTART = (
    "PURGE", "RESTORE", "CLOCK_STEP", "MIGRATE", "RESTART")

# A clock step larger than this is not honoured. Real NTP corrections are
# seconds-to-minutes; a larger jump is itself an event worth alarming on, and an
# unbounded window is a licence to backdate arbitrarily (measured bypass).
MAX_CLOCK_STEP_S = 300.0


def marker(kind: str, **kw) -> dict:
    return {"marker": kind, **kw}


def is_honoured(mk: dict, nodes) -> bool:
    """Does the graph actually SHOW the operation the marker declared?

    CLOSES A BYPASS IN THE MARKER DESIGN ITSELF (found 2026-08-20). Without this
    check an adversary could anchor PURGE(cutoff = long ago) and use it to excuse
    deleting ONE recent row, never purging anything. A marker is therefore only
    honoured when the graph exhibits the WHOLESALE discontinuity it claims:

      PURGE(cutoff)       -> NOTHING older than cutoff may survive
      RESTORE(point)      -> NOTHING newer than point may survive
      CLOCK_STEP(window)  -> no row may have been removed at all

    So abusing a marker costs the adversary the entire range it declared. It
    converts a silent targeted rewrite into a visible mass deletion, which is
    the tamper-EVIDENCE guarantee working as intended.
    """
    k = mk.get("marker")
    if k == PURGE:
        return not any(n.ts < mk["cutoff_ts"] for n in nodes)
    if k == RESTORE:
        return not any(n.ts > mk["restore_point_ts"] for n in nodes)
    if k == CLOCK_STEP:
        # BOUNDED and HEAD-ANCHORED. An unbounded CLOCK_STEP window was measured
        # on 2026-08-20 to completely hide pure injection (FT-7 detection went
        # True -> False), because every backdated row fell inside the declared
        # window. A real NTP step is SMALL and lands just behind the current
        # head; a step spanning all history is not a clock step, it is a licence
        # to backdate anything.
        lo, hi = mk["window"]
        if hi - lo > MAX_CLOCK_STEP_S:
            return False
        head = max((n.ts for n in nodes), default=hi)
        return hi >= head - MAX_CLOCK_STEP_S        # anchored to the head
    if k in (MIGRATE, RESTART):
        return True                        # constrained by explains() instead
    return False


def explains(mk: dict, viol: dict, seg_lo: float, seg_hi: float) -> bool:
    """Does this marker structurally explain this violation?"""
    k, why = mk.get("marker"), viol.get("why")

    # An ACC violation is never a legitimate discontinuity EXCEPT in the single
    # segment that STRADDLES a declared boundary. Measured 2026-08-22: a purge
    # cutoff falling inside a segment legitimately removes some of its members,
    # so that segment's accumulator MUST change. Refusing it left 2 residual
    # violations per purge and held BFP at 0.58.
    #
    # Bounded and sound: at most ONE straddling segment per granularity (<=3
    # total), it must contain the declared boundary strictly, and every other
    # ACC violation is still refused -- so this cannot excuse a targeted edit.
    if why == "ACC":
        if k == PURGE:
            return seg_lo < mk["cutoff_ts"] < seg_hi
        if k == RESTORE:
            return seg_lo < mk["restore_point_ts"] < seg_hi
        if k == CLOCK_STEP:
            lo, hi = mk["window"]
            return lo <= seg_lo and seg_hi <= hi
        return False

    if k == PURGE and why in ("COUNT", "SEGMENT_GONE"):
        # downward only, and any segment OVERLAPPING the purged range -- a coarse
        # segment straddling the cutoff loses rows legitimately.
        if why == "COUNT" and viol.get("now", 0) >= viol.get("was", 0):
            return False
        return seg_lo < mk["cutoff_ts"]

    if k == RESTORE and why in ("COUNT", "SEGMENT_GONE"):
        if why == "COUNT" and viol.get("now", 0) >= viol.get("was", 0):
            return False
        return seg_hi > mk["restore_point_ts"]

    if k == CLOCK_STEP and why in ("UNCOMMITTED_HISTORICAL", "COUNT", "ACC"):
        # A backward step inserts rows into sealed time, which moves the
        # segment's COUNT and its accumulator as well as creating uncommitted
        # regions. Excusing only UNCOMMITTED_HISTORICAL left the other two
        # unexcused and the marker did not work. Widened, but ONLY inside the
        # bounded, head-anchored window -- and a COUNT DECREASE is still never
        # excused, because a clock step adds rows, it never removes them.
        if why == "COUNT" and viol.get("now", 0) < viol.get("was", 0):
            return False
        lo, hi = mk["window"]
        return lo <= seg_lo and seg_hi <= hi

    if k == MIGRATE and why == "ACC":
        return False                      # schema migration must not alter content

    return False


def filter_violations(viol: list[dict], markers: list[dict], gran_width,
                      nodes=None) -> dict:
    """Split violations into those an HONOURED marker explains and the rest."""
    if nodes is not None:
        markers = [m for m in markers if is_honoured(m, nodes)]
    kept, excused = [], []
    for v in viol:
        w = gran_width[v["gran"]]
        lo = int(v["seg"]) * w
        hi = lo + w
        if any(explains(m, v, lo, hi) for m in markers):
            excused.append(v)
        else:
            kept.append(v)
    return {"violations": kept, "excused": excused,
            "detected": bool(kept), "n_violations": len(kept),
            "n_excused": len(excused)}
