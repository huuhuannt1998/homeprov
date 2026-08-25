"""A4 VERIFY — consumes L2/L3 only, NEVER L4 (enforced by ablation AB-6).

Two checks that M2 measurement proved necessary and that a naive implementation
omits. Both were real defects found by testing, not by reasoning:

  CLOSED-SEGMENT COMPARISON. A segment still accumulating when the anchor was
  taken legitimately grows afterwards. Comparing it produces false positives on
  a live hub -- the first M2 run reported 3 violations of which 2 were spurious.

  UNCOMMITTED HISTORICAL SEGMENTS. A segment absent from the anchor is legitimate
  ONLY if it lies in the anchor's FUTURE. A brand-new segment wholly in the
  anchor's PAST cannot be honest: nothing can be appended to time already
  committed. Omitting this made the ENTIRE F_inj class invisible, because the
  injections were backdated into a second that had no prior activity.
"""
from __future__ import annotations
from .commit import GRAN, commit_full


def verify(nodes, phi_ref: dict, anchor_ts: float, scheme="homeprov",
           retention=None) -> dict:
    """`retention` maps granularity -> how long that granularity is KEPT.

    REQUIRED whenever the commitment has been pruned by the laminar retention
    policy. Measured 2026-08-22: pruning and the UNCOMMITTED-REGIONS check are
    INCOMPATIBLE if combined naively -- every legitimately pruned segment reads
    as a backdated injection, and OQ went to 0.988 (near-total quarantine) at
    every event age. A segment absent from the anchor is legitimate when it is
    in the FUTURE, or when it is older than its granularity's retention horizon
    AND a coarser granularity still covers that time. The second clause is
    exactly what nesting provides, so retention is only safe BECAUSE the family
    is laminar."""
    now = commit_full(nodes, scheme)
    viol, skipped_open, skipped_future, skipped_pruned = [], 0, 0, 0

    for g, w in GRAN.items():
        old, new = phi_ref.get(g, {}), now.get(g, {})
        for k in set(old) | set(new):
            o, n = old.get(k), new.get(k)
            seg_end = (int(k) + 1) * w

            if o is None:
                # legitimately pruned? (older than this granularity's horizon,
                # with a coarser granularity still covering the time)
                if retention and g in retention:
                    horizon = anchor_ts - retention[g]
                    coarser_covers = any(
                        gg != g and GRAN[gg] > w and
                        (retention.get(gg, float("inf")) >= anchor_ts - seg_end)
                        for gg in GRAN)
                    if seg_end < horizon and coarser_covers:
                        skipped_pruned += 1
                        continue
                # UNCOMMITTED-REGIONS: only a FUTURE segment may be absent.
                if seg_end <= anchor_ts:
                    viol.append({"gran": g, "seg": k,
                                 "why": "UNCOMMITTED_HISTORICAL",
                                 "detail": "backdated write into committed time"})
                else:
                    skipped_future += 1
                continue

            if seg_end > anchor_ts:          # segment was still OPEN when anchored
                skipped_open += 1
                continue

            if n is None:
                viol.append({"gran": g, "seg": k, "why": "SEGMENT_GONE"})
                continue
            # report BOTH: a count change must not mask an accumulator change,
            # or re-parenting hides behind deletion in the same segment.
            if o["n"] != n["n"]:
                viol.append({"gran": g, "seg": k, "why": "COUNT",
                             "was": o["n"], "now": n["n"]})
            if o["acc"] != n["acc"]:
                viol.append({"gran": g, "seg": k, "why": "ACC",
                             "detail": "structure or content changed"})

    return {"detected": bool(viol), "n_violations": len(viol), "violations": viol,
            "skipped_open": skipped_open, "skipped_future": skipped_future,
            "skipped_pruned": skipped_pruned}


def violated_elements(nodes, viol: list[dict]) -> set[str]:
    """S_phi -- the node keys covered by each violated segment. Input to A5/A6."""
    cov: set[str] = set()
    for v in viol:
        w = GRAN[v["gran"]]
        lo = int(v["seg"]) * w
        hi = lo + w
        for n in nodes:
            if lo <= n.ts < hi:
                cov.add(n.key)
    return cov
