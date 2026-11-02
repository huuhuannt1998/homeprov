"""E10 (round 14): the per-second outcome of a verification, match / violation / violation_coarse_only / unknown, with
the collusion case of drafts/round13/FORMAL_DRAFT.md section 6, D2, closed.

exp/stages/e9_dishonest_anchor.py (frozen with E9) classifies a second by outcome(): flagged -> violation; a second
the verifier lists as root-unknown or holding an unobserved late row -> unknown; a second with an anchored root or a
first cover -> match (violation_coarse_only when a minute or hour around it is flagged). Probe P3 of the draft: the hub
empties a sealed second and the anchor host withholds the one record that carried its root; the verifier of E9 listed
root-unknown segments only among segments that still hold rows, so that second had a first cover and no root and read
"match". The patched verifier (exp/stages/verifier_e10.patch, D2) lists such seconds as root_unknown (why ending in
":no_row_now"). This module is the outcome rule used by E10's scorer and by the offline collusion check
(exp/stages/e10_collusion.py); on top of the verifier's list it treats as unknown, when the verification result still
carries the poll timeline (verify() in-process: res["P"], res["TL"]), every second first covered by a poll whose roots
are not all on the chain or that follows a poll missing from the chain, and that has no anchored root, so it does not
depend on the verifier patch being applied (defence in depth). The rules are otherwise e9_dishonest_anchor.outcome()'s,
re-implemented here (that file stays as it was registered).
"""
from __future__ import annotations


class _CoarseSet:
    def __init__(self, segs):
        self.segs = segs

    def __contains__(self, s):
        s = int(s)
        return ("minute", s - s % 60) in self.segs or ("hour", s - s % 3600) in self.segs


def _incomplete_cover_seconds(res):
    """Seconds first covered by a poll with incomplete roots or after a missing poll, with no anchored root (needs the
    in-process result: res["P"] and res["TL"])."""
    P, TL = res.get("P"), res.get("TL")
    if P is None or TL is None:
        return set()
    seen, polls = P["seen_by_poll"], P["polls"]
    gap_before, prev = {}, None
    for k in sorted(polls):
        gap_before[k] = (k[1] > 1) if (prev is None or prev[0] != k[0]) else (k[1] - prev[1] > 1)
        prev = k
    out = set()
    for lo, hi, p in TL.pieces:
        ns = (p.get("n_sealed") or {}).get("second")
        incomplete = ns is not None and len(seen.get(p["key"], {}).get("second", ())) < ns
        if not incomplete and not gap_before.get(p["key"]):
            continue
        for s in range(int(lo), int(hi)):
            a = P["all_roots"].get(("second", str(s)))
            if a is None or (a.get("poll") is not None and a["poll"] > p["key"]):
                out.add(str(s))
    return out


def annotate(res):
    res["_flagged"] = set(res.get("flagged_seconds") or [])
    res["_unknown"] = {x["seg"] for x in res.get("root_unknown_segments") or [] if x["gran"] == "second"}
    res["_unobserved"] = {x["second"] for x in res.get("unobserved_late_rows") or [] if x.get("second")}
    res["_incomplete"] = _incomplete_cover_seconds(res)
    coarse = set()
    for f in res.get("flagged_segments") or []:
        if f["gran"] in ("minute", "hour"):
            w = 60 if f["gran"] == "minute" else 3600
            coarse.add((f["gran"], int(f["seg"]) * w))
    res["_coarse"] = _CoarseSet(coarse)
    return res


def outcome(res, s):
    """res: an annotate()d verification result; s: a second (str or int)."""
    s = str(int(s))
    if s in res["_flagged"]:
        return "violation"
    if s in res["_unknown"] or s in res["_unobserved"] or s in res["_incomplete"]:
        return "unknown"
    roots = res.get("roots")
    TL = res.get("TL")
    has_root = roots is not None and ("second", s) in roots
    if has_root or (TL is not None and TL.first_cover(int(s), int(s) + 1) is not None):
        return "violation_coarse_only" if s in res["_coarse"] else "match"
    if roots is None and TL is None:
        # a CLI result (JSON): no timeline; a second the verifier neither flags nor lists as unknown is read as match
        # only if a segment it lies in was checked
        return "violation_coarse_only" if s in res["_coarse"] else "match_or_unsealed"
    return "unknown"
