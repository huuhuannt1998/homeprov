"""E10b plan: E10's A1-BDT arm (hypothesis H1) re-run with the trials spaced so that no two forged rows share a
one-second segment or lie in neighbouring ones, plus H10's clock-step arm with the hub's state rows stepped as well
(drafts/round13/E10B_DESIGN.md; pre-registration exp/out/e10b_preregistration.json).

Standard library only. The backdate levels, the trial count per level and the clock steps are E10's own constants,
imported from testbed/e10/e10ops.py (frozen with E10; read, never changed). Only the spacing, the seed and the block
list are E10b's.

SCHEDULE ARITHMETIC (why 50 s). homeprov_e10's op_bdt (frozen) starts trial i at start_i and computes
nxt = start_i + spacing before the trial, then waits for nxt at its end, so start_j >= start_i + (j - i) * spacing for
j > i (a trial that overruns its slot only pushes later trials further away). Trial i inserts at
t_ins_i = start_i + delta_i (delta_i >= 0: the genuine-automation lookup and the connection before BEGIN IMMEDIATE) and
timestamps its row target_i = t_ins_i - age_i. Hence, for j > i,

    target_j - target_i  >=  (j - i) * spacing - delta_i - (age_j - age_i)  >=  (j - i) * spacing - DELTA_MAX - 40

(the ages span 5..45 s). With spacing 50 s and DELTA_MAX 8 s the right side is at least 2 s for every pair, and
target_j - target_i >= 2 implies floor(target_j) >= floor(target_i) + 2: different one-second segments, never
adjacent ones. The realised separations are checked again by the scorer from the trials' own timestamps (a pair
closer than that is a registered exclusion); `schedule` below computes the guaranteed bound for the realised order.

    python3 testbed/e10b/e10b_plan.py plan [--seed N] [--smoke]       one JSON document (the registration embeds its sha256)
    python3 testbed/e10b/e10b_plan.py schedule [--seed N] [--smoke]   the separation bound for that plan
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
E10OPS_PATH = os.path.join(REPO, "testbed", "e10", "e10ops.py")


def _e10ops():
    spec = importlib.util.spec_from_file_location("e10ops_for_e10b", E10OPS_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_E10 = _e10ops()
AGES = tuple(float(a) for a in _E10.BDT_AGES)      # 5, 15, 30, 33, 45 s (E10's levels)
N_PER_AGE = int(_E10.BDT_N)                         # 20 per level (E10's count)
CS_STEPS = tuple(dict(s) for s in _E10.CS_STEPS)    # 3 x (60 s, marker), (60 s, none), (10 s, none) (E10's steps)
CS_DURATION_S = float(_E10.CS_DURATION_S)           # 60 s (E10)
CS_SPACING_S = 120.0                                # as E10's A6 block
SEED = 20261024                                     # E10b's registered seed (E10 used 20261020)
SPACING_S = 50.0                                    # E10 used 15 s
PRE_WAIT_S = 60.0                                   # as E10's A1 block (every target lies after the session start)
DELTA_MAX_S = 8.0                                   # assumed bound of delta_i (measured in E10: r16_e10_e10b_basis)
MIN_SEPARATION_S = 2.0                              # target_j - target_i >= 2 s: no shared and no adjacent second
SMOKE_N_PER_AGE = 2
SMOKE_CS_STEPS = (CS_STEPS[0], CS_STEPS[3])         # one 60 s step with a marker, one without


def schedule(ages, spacing=SPACING_S, delta_max=DELTA_MAX_S):
    """The guaranteed lower bound of target_j - target_i over every pair i < j of this order, and the worst case of
    any order of these levels (consecutive trials, youngest then oldest)."""
    best, pair = None, None
    n = len(ages)
    for i in range(n):
        for j in range(i + 1, n):
            b = (j - i) * spacing - delta_max - (ages[j] - ages[i])
            if best is None or b < best:
                best, pair = b, (i, j)
    span = (max(ages) - min(ages)) if ages else 0.0
    worst_any = spacing - delta_max - span
    return {"spacing_s": spacing, "delta_max_s": delta_max, "age_span_s": span,
            "min_guaranteed_separation_s": best, "attained_by_trials": list(pair) if pair else None,
            "worst_case_any_order_s": worst_any, "required_s": MIN_SEPARATION_S,
            "ok": best is not None and best >= MIN_SEPARATION_S and worst_any >= MIN_SEPARATION_S,
            "max_delta_tolerated_s": spacing - span - MIN_SEPARATION_S}


def realised_separation(targets):
    """Realised check from the trials' own row timestamps: pairs whose one-second segments are equal or adjacent."""
    secs = sorted((int(t // 1.0), i) for i, t in enumerate(targets) if t is not None)
    close = []
    for a in range(len(secs)):
        for b in range(a + 1, len(secs)):
            if secs[b][0] - secs[a][0] > 1:
                break
            close.append(sorted((secs[a][1], secs[b][1])))
    srt = sorted(t for t in targets if t is not None)
    gaps = [b - a for a, b in zip(srt, srt[1:])]
    return {"collisions": close, "min_gap_s": min(gaps) if gaps else None}


def make_plan(seed=SEED, smoke=False):
    """Deterministic from the seed (the registration fixes the order)."""
    rnd = random.Random(seed)
    n = SMOKE_N_PER_AGE if smoke else N_PER_AGE
    ages = [a for a in AGES for _ in range(n)]
    rnd.shuffle(ages)
    steps = [dict(s) for s in (SMOKE_CS_STEPS if smoke else CS_STEPS)]
    blocks = [
        {"block": "A1_BDT", "op": "bdt", "ages": ages, "spacing_s": SPACING_S, "pre_wait_s": PRE_WAIT_S},
        {"block": "SNAP_BDT"},                    # H1b is scored against this snapshot (nothing else written before it)
        {"block": "A6_CS2", "op": "clock_step_all", "steps": steps, "duration_s": CS_DURATION_S,
         "spacing_s": CS_SPACING_S},              # H10b, after SNAP_BDT so it cannot touch H1b's verification
        {"block": "SNAP_CS_END"},
    ]
    return {"experiment": "E10b", "seed": seed, "smoke": bool(smoke), "blocks": blocks,
            "schedule": schedule(ages)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "schedule"):
        s = sub.add_parser(name)
        s.add_argument("--seed", type=int, default=SEED)
        s.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    p = make_plan(a.seed, a.smoke)
    if a.cmd == "plan":
        sys.stdout.write(json.dumps(p, indent=1, sort_keys=True) + "\n")
        return 0 if p["schedule"]["ok"] else 1
    sys.stdout.write(json.dumps(p["schedule"], indent=1, sort_keys=True) + "\n")
    return 0 if p["schedule"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
