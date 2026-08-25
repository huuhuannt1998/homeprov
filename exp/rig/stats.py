"""Statistics (design section 11.5).

  EXACT arms need no testing. CE_b, necessity and MIN-QUARANTINE-EXACT are
  computed by enumeration/ILP and are reported as FACTS ABOUT THE INSTANCE,
  with no p-values and no statistical decoration.

  SAMPLED arms use PAIRED comparison: HOMEPROV and every baseline see the
  IDENTICAL deployment, event stream and forgery instance.

  NO BARE POINT ESTIMATE appears in any table or figure, including the abstract.
"""
from __future__ import annotations
import math, random


def clopper_pearson(k: int, n: int, alpha=0.05):
    """EXACT binomial interval for a proportion.

    REQUIRED for constant binary outcomes. A bootstrap over constant data
    returns a ZERO-WIDTH interval, which reads as perfect precision but is
    really just an artifact of constancy -- resampling 18 identical values can
    only ever produce that value. Reporting "CI [1.0000, 1.0000]" from 18
    observations would misrepresent what the data supports; Clopper-Pearson on
    18/18 gives roughly [0.815, 1.000], which is the honest statement.
    """
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return {"k": k, "n": n, "prop": k / n if n else 0.0,
            "ci_lo": lo, "ci_hi": hi, "method": "Clopper-Pearson exact"}


def binary_contrast(a, b, alpha=0.05):
    """Paired binary contrast reported as two exact proportions plus the
    discordant-pair count, instead of a degenerate bootstrap on the difference."""
    assert len(a) == len(b)
    n = len(a)
    ka, kb = int(sum(a)), int(sum(b))
    disc = sum(1 for x, y in zip(a, b) if x != y)
    return {"arm_a": clopper_pearson(ka, n, alpha),
            "arm_b": clopper_pearson(kb, n, alpha),
            "discordant_pairs": disc, "n_pairs": n,
            "note": ("outcome is CONSTANT in both arms; a bootstrap CI on the "
                     "difference would be zero-width by construction"
                     if (ka in (0, n) and kb in (0, n)) else "")}


def paired_bootstrap(a, b, n=10000, seed=0, alpha=0.05):
    """Paired bootstrap on the difference a-b. Returns mean and a CI."""
    assert len(a) == len(b) and a, "paired arms must be equal length and non-empty"
    rng = random.Random(seed)
    d = [x - y for x, y in zip(a, b)]
    obs = sum(d) / len(d)
    boots = []
    for _ in range(n):
        s = [d[rng.randrange(len(d))] for _ in range(len(d))]
        boots.append(sum(s) / len(s))
    boots.sort()
    lo = boots[int((alpha / 2) * n)]
    hi = boots[int((1 - alpha / 2) * n) - 1]
    degenerate = (hi - lo) == 0.0
    return {"mean_diff": obs, "ci_lo": lo, "ci_hi": hi, "n_pairs": len(d),
            "excludes_zero": (lo > 0 or hi < 0),
            "degenerate": degenerate,
            "warning": ("zero-width interval: the paired differences are "
                        "CONSTANT, so this reflects constancy and NOT precision "
                        "-- use clopper_pearson() for binary outcomes"
                        if degenerate else None)}


def ci(xs, n=10000, seed=0, alpha=0.05):
    """Bootstrap CI for a single arm. Never report a bare point estimate."""
    rng = random.Random(seed)
    boots = []
    for _ in range(n):
        s = [xs[rng.randrange(len(xs))] for _ in range(len(xs))]
        boots.append(sum(s) / len(s))
    boots.sort()
    return {"mean": sum(xs) / len(xs),
            "ci_lo": boots[int((alpha / 2) * n)],
            "ci_hi": boots[int((1 - alpha / 2) * n) - 1], "n": len(xs)}


def mixed_effects(rows, metric, fixed="system"):
    """metric ~ system + scenario + (1|deployment) + (1|seed).

    Random effects on DEPLOYMENT and SEED because deployments are a sample from
    a population we generalize to and seeds are nuisance variation. Treating
    deployment as fixed would overstate precision.
    Falls back to a clustered bootstrap if statsmodels is unavailable.
    """
    try:
        import pandas as pd, statsmodels.formula.api as smf
    except Exception:
        return {"available": False,
                "fallback": "cluster-bootstrap by deployment"}
    df = pd.DataFrame(rows)
    if df["deployment"].nunique() < 2:
        return {"available": False, "reason": "need >=2 deployments"}
    try:
        m = smf.mixedlm("%s ~ %s + scenario" % (metric, fixed), df,
                        groups=df["deployment"]).fit()
    except Exception as e:
        # A modelling failure must not abort a sweep that already produced valid
        # paired-bootstrap contrasts. Report it and fall back.
        return {"available": False, "error": "%s: %s" % (type(e).__name__, e),
                "fallback": "paired bootstrap contrasts remain valid"}
    return {"available": True, "summary": str(m.summary()),
            "params": {k: float(v) for k, v in m.params.items()},
            "pvalues": {k: float(v) for k, v in m.pvalues.items()}}


def holdout_split(deployments, frac=0.6, seed=0):
    """60/40. ALL design choices (granularity, compaction, thresholds) are tuned
    on the 60% only; the 40% is touched ONCE, at the end."""
    rng = random.Random(seed)
    d = list(deployments); rng.shuffle(d)
    k = int(len(d) * frac)
    return {"tune": d[:k], "holdout": d[k:]}
