"""FRESH SEALED HOLDOUT for the recalibrated generator (E1).

The stage-19 holdout was sealed against the bg_ratio 24.0 arm and has now been
inspected, so it is spent. This is a NEW sealed set: a different grid seed, a
different split seed, and deployment seeds disjoint from every set used to fit
bg_ratio (51-56) or to run stage 19 (1000+i).

The seeds below were written down and committed BEFORE the stage was run once.
It is evaluated exactly once. Do not re-run it after inspecting its output.
"""
import os
from . import stage19_holdout as _base

SEAL = {"grid_seed": 7, "split_seed": 7, "deployment_seed_base": 3000,
        "declared": "2026-09-03", "runs_permitted": 1}

WORK = "/tmp/homeprov_holdout2"


def run(cfg):
    import types
    from rig import deployment, stats
    # monkeypatch the sealed constants for this run only
    _o_work, _o_grid, _o_split = _base.WORK, deployment.grid, stats.holdout_split
    _base.WORK = WORK
    deployment.grid = lambda limit, seed: _o_grid(limit=limit, seed=SEAL["grid_seed"])
    stats.holdout_split = lambda ids, frac, seed: _o_split(
        ids, frac=frac, seed=SEAL["split_seed"])
    src = _base.run.__globals__
    _o_gen = src["gen"].generate
    src["gen"].generate = lambda db, p, seed: _o_gen(
        db, p, seed=SEAL["deployment_seed_base"] + (seed - 1000))
    try:
        out = _base.run(cfg)
    finally:
        _base.WORK = _o_work
        deployment.grid, stats.holdout_split = _o_grid, _o_split
        src["gen"].generate = _o_gen
    out["stage"] = "19b"
    out["seal"] = SEAL
    return out
