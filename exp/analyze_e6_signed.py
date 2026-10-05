#!/usr/bin/env python3
"""E6: does cover have to be NEAR the target, or merely BEFORE it?

The paper says adjacency. Two absolute-distance sweeps said distance does not
matter at all out to six hours. This scores the signed sweep, where the sign of
(cover_ts - target_ts) separates cover that ran before the target from cover
that ran after it -- which the renderer's own "a cause precedes its effect"
invariant predicts should be the operative condition.
"""
import json, sys, collections
from math import comb


def clopper_pearson(k, n, alpha=0.05):
    """Exact interval by bisection on the binomial CDF; no SciPy in this env."""
    if n == 0:
        return (0.0, 1.0)
    def cdf(p, m):                      # P[X <= m]
        return sum(comb(n, i) * p**i * (1 - p)**(n - i) for i in range(m + 1))
    lo = 0.0
    if k > 0:
        a, b = 0.0, 1.0
        for _ in range(60):
            m = (a + b) / 2
            if cdf(m, k - 1) > 1 - alpha / 2: a = m
            else: b = m
        lo = (a + b) / 2
    hi = 1.0
    if k < n:
        a, b = 0.0, 1.0
        for _ in range(60):
            m = (a + b) / 2
            if cdf(m, k) < alpha / 2: b = m
            else: a = m
        hi = (a + b) / 2
    return (lo, hi)


rooms = sys.argv[1:] or ["kitchen", "porch", "hallway"]
pooled = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
sign_pool = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))

for room in rooms:
    try:
        d = json.load(open(f"exp/out/e6_signed_{room}.json"))
    except FileNotFoundError:
        print(f"  {room}: MISSING"); continue
    for r in d["per_instance"]:
        if not r.get("reachable") or "misattributed" not in r:
            continue
        v, dt = r["variant"], r["dt_requested"]
        b = pooled[v][dt]; b[1] += 1; b[0] += bool(r["misattributed"])
        # sign of the ACTUAL achieved offset, not the requested bin
        act = r.get("dt_actual")
        if act is not None:
            key = "cover BEFORE target" if act < 0 else ("simultaneous" if act == 0 else "cover AFTER target")
            s = sign_pool[v][key]; s[1] += 1; s[0] += bool(r["misattributed"])

print("=" * 68)
print("Misattribution vs SIGNED offset (cover_ts - target_ts), pooled over", ", ".join(rooms))
print("negative = cover ran BEFORE the target\n")
for v in sorted(pooled):
    print(v)
    for dt in sorted(pooled[v]):
        k, n = pooled[v][dt]
        lo, hi = clopper_pearson(k, n)
        print(f"   {dt:+7d}s   {k:3d}/{n:<3d}  {k/n if n else 0:.3f}  [{lo:.3f}, {hi:.3f}]")
    print()

print("=" * 68)
print("Collapsed by SIGN\n")
for v in sorted(sign_pool):
    print(v)
    for key in ("cover BEFORE target", "simultaneous", "cover AFTER target"):
        if key not in sign_pool[v]: continue
        k, n = sign_pool[v][key]
        lo, hi = clopper_pearson(k, n)
        print(f"   {key:22s} {k:3d}/{n:<3d}  {k/n if n else 0:.3f}  [{lo:.3f}, {hi:.3f}]")
    print()
