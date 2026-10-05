"""M1-M6 and the miss taxonomy. Every metric is DEFINED HERE, before use.

  M1 TDR  detection rate            P[VERIFY reports | T != {}]      up
  M2 LP   localization precision    |Q ^ T| / |Q|                    up
  M3 LR   localization recall       |Q ^ T| / |T|   MUST BE 1        up
  M4 OQ   over-quarantine ratio     |Q \\ T| / |V u A|   HEADLINE     down
  M5 RA   reconstruction accuracy   correct Attr on V\\Q             up
  M6 BFP  benign false positives    P[VERIFY reports | T == {}]      down

CONDITIONALS that localize failure (so a drop is attributable, never ambiguous):
  RA_e2e = P[detect] x P[LR=1 | detect] x P[correct | LR=1]
           anchor        localizer          reconstructor

MISS TAXONOMY -- not all failures are equal, and collapsing them hides the only
one that matters:
  Miss-D          undetected                          high
  Miss-L          detected but LR<1                   CRITICAL (unsound)
  Miss-R-assert   asserts a WRONG attribution         CRITICAL (confidently wrong)
  Miss-R-abstain  declines to attribute               NOT a soundness failure
"""
from __future__ import annotations
from .conf_import import THRESHOLDS   # noqa: F401  (re-export for callers)


def tdr(detected: bool) -> float:
    return 1.0 if detected else 0.0


def lp(Q: set, T: set) -> float:
    return len(Q & T) / len(Q) if Q else 1.0


def lr(Q: set, T: set) -> float:
    """Element-wise recall. VALID ONLY when no element of T was DELETED --
    a deleted element cannot appear in Q because Q is drawn from the surviving
    graph. Use lr_regions() for any forgery involving F_del."""
    return len(Q & T) / len(T) if T else 1.0


def lr_regions(Q_regions, T_times) -> float:
    """Region-wise recall: the sound formulation.

    Q is really a set of quarantined TIME REGIONS (violated segments). A
    tampered element is covered when its timestamp falls inside one -- which
    handles DELETIONS, whose elements are absent from the post-forgery graph
    and so can never be quarantined element-wise.
    Found necessary on 2026-08-20: element-wise LR reported 0.000 for a pure
    deletion that was in fact correctly localized."""
    if not T_times:
        return 1.0
    cov = sum(1 for t in T_times if any(lo <= t < hi for lo, hi in Q_regions))
    return cov / len(T_times)


def oq(Q: set, T: set, universe_size: int) -> float:
    return len(Q - T) / universe_size if universe_size else 0.0


def ra(account, truth: dict) -> float:
    """Accuracy on entries the account actually ASSERTS (trust == VERIFIED)."""
    asserted = [e for e in account if e["trust"] == "VERIFIED"]
    if not asserted:
        return 1.0                      # vacuously sound; completeness is separate
    ok = sum(1 for e in asserted if truth.get(e["actuation"]) == e["attr"])
    return ok / len(asserted)


def miss_taxonomy(detected: bool, Q: set, T: set, account, truth: dict,
                  Q_regions=None, T_times=None) -> dict:
    """Miss-L uses the REGION formulation when regions are supplied, because
    element-wise recall is uncomputable for deletions (a deleted element cannot
    appear in Q). Passing only Q and T reports element-wise, which over-counts
    Miss-L on any deletion-bearing forgery."""
    out = {"Miss-D": 0, "Miss-L": 0, "Miss-R-assert": 0, "Miss-R-abstain": 0}
    if T and not detected:
        out["Miss-D"] = 1
        return out
    recall = (lr_regions(Q_regions, T_times)
              if Q_regions is not None and T_times is not None else lr(Q, T))
    if T and recall < 1.0:
        out["Miss-L"] = 1
    for e in account:
        if e["trust"] == "VERIFIED":
            if truth.get(e["actuation"]) not in (None, e["attr"]):
                out["Miss-R-assert"] += 1
        else:
            out["Miss-R-abstain"] += 1
    return out


def conditionals(runs: list[dict]) -> dict:
    """Decompose end-to-end accuracy into anchor / localizer / reconstructor."""
    tam = [r for r in runs if r["T"]]
    if not tam:
        return {}
    p_det = sum(1 for r in tam if r["detected"]) / len(tam)
    det = [r for r in tam if r["detected"]]
    p_lr = (sum(1 for r in det if r["LR"] >= 1.0) / len(det)) if det else 0.0
    good = [r for r in det if r["LR"] >= 1.0]
    p_ra = (sum(r["RA"] for r in good) / len(good)) if good else 0.0
    return {"P_detect": p_det, "P_LR1_given_detect": p_lr,
            "P_correct_given_LR1": p_ra, "RA_e2e": p_det * p_lr * p_ra}


def gate(name: str, value: float) -> dict:
    from .conf_import import THRESHOLDS as T
    spec = T.get(name)
    if not spec:
        return {"metric": name, "value": value, "threshold": None}
    ok = {">=": value >= spec["value"], "<=": value <= spec["value"],
          "==": value == spec["value"]}[spec["op"]]
    return {"metric": name, "value": value, "op": spec["op"],
            "threshold": spec["value"], "pass": ok, "hard": spec.get("hard", False)}
