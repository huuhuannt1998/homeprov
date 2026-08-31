"""STAGE 34 (E25) -- characterising the REAL deployment against the generator.

Every statistical result in this paper rests on deployments from one calibrated
generator, and the limitations section has had to say that the generator was
never validated against anything real, because nothing real was available. That
is no longer true. The realistic substrate is a genuine deployment: a real MQTT
broker, devices announcing themselves over real discovery, and automations
instantiated from the blueprint Home Assistant ships. It is not a household, and
this stage does not pretend otherwise -- but it IS a real deployment produced by
the platform's own code paths rather than by our generator, which makes it a
calibration target the paper has never had.

What is compared is the STRUCTURE the paper's results are sensitive to, not
surface statistics:

  parent-context fraction   the share of state rows carrying a causal edge.
                            E15 measured this as the ONLY swept parameter that
                            moves the quarantine, so it is the number that
                            matters most.
  causal run length         nodes per context; the floor on blast radius.
  contexts per actuation    how many distinct chains touch one actuator.
  inter-arrival             timing structure, which decides how separable
                            causal runs are in time.
  actuation share           how much of the history is actuation rather than
                            background chatter.

The comparison is reported as a per-dimension ratio with the generated value
alongside, and NOT collapsed into a single fidelity score: a scalar would hide
which dimension is wrong, and knowing which one is wrong is the whole use of
this measurement.
"""
from __future__ import annotations

import json, math, os, sqlite3, statistics, subprocess, tempfile

from rig import gen, graph

CONTAINER = os.environ.get("HPR_CONTAINER", "hpr-hass")
GEN_SEEDS = [81, 82, 83, 84, 85, 86]


def pull_real_db() -> str:
    """Copy the live recorder out of the container.

    Copied rather than read in place: the hub holds it open in WAL mode, and a
    read-only open against a live WAL is exactly the failure this project has
    already been bitten by twice.
    """
    dst = os.path.join(tempfile.mkdtemp(), "real.db")
    for suf in ("", "-wal", "-shm"):
        subprocess.run(["docker", "cp",
                        f"{CONTAINER}:/config/home-assistant_v2.db{suf}", dst + suf],
                       capture_output=True)
    con = sqlite3.connect(dst)
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    n = con.execute("SELECT COUNT(*) FROM states").fetchone()[0]
    con.close()
    if integrity != "ok" or n == 0:
        raise RuntimeError(f"copied recorder unusable: integrity={integrity} rows={n}")
    return dst


def structure(nodes) -> dict:
    """The five structural dimensions, computed identically for both arms."""
    states = [n for n in nodes if n.kind == "state"]
    if not states:
        return {}
    with_parent = sum(1 for n in states if n.par is not None)
    ctxs: dict = {}
    for n in nodes:
        if n.ctx is not None:
            ctxs.setdefault(n.ctx, []).append(n)
    runs = [len(v) for v in ctxs.values()]
    ts = sorted(n.ts for n in nodes)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    actuation = sum(1 for n in nodes if n.ty == "alpha")
    return {
        "n_nodes": len(nodes),
        "n_states": len(states),
        "parent_context_fraction": with_parent / len(states),
        "mean_causal_run": statistics.mean(runs) if runs else 0.0,
        "median_causal_run": statistics.median(runs) if runs else 0.0,
        "max_causal_run": max(runs) if runs else 0,
        "n_contexts": len(ctxs),
        "median_inter_arrival_s": statistics.median(gaps) if gaps else 0.0,
        "actuation_share": actuation / len(nodes),
    }


def run(cfg):
    real_db = pull_real_db()
    real = structure(graph.load(real_db))
    if not real:
        return {"stage": 34, "error": "real deployment produced no state rows"}

    # Generated arm at the deployment size the real substrate actually reached,
    # so the comparison is not confounded by history length.
    work = "/tmp/homeprov_realchar"
    os.makedirs(work, exist_ok=True)
    gens = []
    for seed in GEN_SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
             "target_nodes": max(2000, real["n_nodes"]), "span_s": 1800.0,
             "max_nodes": 10**9}
        db = os.path.join(work, f"g_{seed}.db")
        gen.generate(db, p, seed=seed)
        gens.append(structure(graph.load(db)))
        os.remove(db)

    def agg(k):
        vals = [g[k] for g in gens if k in g]
        return {"mean": statistics.mean(vals),
                "sd": statistics.pstdev(vals) if len(vals) > 1 else 0.0}

    DIMS = ["parent_context_fraction", "mean_causal_run", "median_causal_run",
            "median_inter_arrival_s", "actuation_share"]
    comparison = {}
    for k in DIMS:
        g, r = agg(k), real.get(k, 0.0)
        ratio = (r / g["mean"]) if g["mean"] else float("inf")
        comparison[k] = {"real": r, "generated_mean": g["mean"],
                         "generated_sd": g["sd"], "ratio_real_over_generated": ratio,
                         "log_ratio": math.log10(ratio) if ratio > 0 else None}

    worst = max(comparison.items(),
                key=lambda kv: abs(kv[1]["log_ratio"] or 0))

    return {
        "stage": 34,
        "real": real,
        "generated_arm": {"seeds": GEN_SEEDS, "per_seed": gens},
        "comparison": comparison,
        "largest_divergence": {"dimension": worst[0], **worst[1]},
        "interpretation": (
            "Reported per dimension and deliberately NOT collapsed into a single "
            "fidelity score. A scalar would hide which dimension diverges, and "
            "which one diverges is the entire use of the measurement: E15 "
            "established that the parent-context fraction is the only swept "
            "parameter that moves the quarantine, so a divergence there bounds "
            "the transferability of the reconstruction results, while a "
            "divergence in inter-arrival timing bounds the localisation results "
            "instead."),
        "scope": (
            "The real arm is a real DEPLOYMENT -- real broker, real MQTT "
            "discovery, real shipped blueprint -- not a real HOUSEHOLD. It "
            "calibrates the generator against something the platform produced "
            "rather than something we produced, which the paper has never had, "
            "but it does not establish transfer to homes."),
    }
