"""R9 item (a): intervals for the localization over-quarantine comparison.

Paper policy (localize.greedy, artifact key R5_homeprov) vs connected causal
component (R4_component), stage 24 (E12). Reads the per-row values already saved
by stage 24; nothing is regenerated.

  published arm : exp/out/stage24_final.json          (bg_ratio 24.0, git f644936)
  refit arm     : exp/out_recal/stage24_recon_baselines.json (bg_ratio 4.4)

Rows are (seed, forgery type) pairs: 8 generated deployments (seeds 201-208) x
2 forgery types that survived (FT-1, FT-4). The paper's unit "16 deployments" is
these 16 rows. The PRIMARY bootstrap therefore resamples the 16 rows (paired:
both policies see the same resampled rows). A SENSITIVITY bootstrap resamples the
8 seeds as clusters (both rows of a seed travel together), because the two rows
of one seed share the same clean deployment.

Percentile intervals, 10,000 resamples, numpy default_rng(SEED). One resample
index set drives every statistic, so the per-policy, difference and ratio
intervals are computed jointly.
"""
from __future__ import annotations
import json, os, sys
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import r9_common as C  # noqa: E402

B = 10_000
SEED = 20261006
ALPHA = 0.05
P5, P4 = "R5_homeprov", "R4_component"
ARMS = {
    "published_bg24": os.path.join(C.EXP, "out", "stage24_final.json"),
    "refit_bg4.4": os.path.join(C.EXP, "out_recal", "stage24_recon_baselines.json"),
}
PUBLISHED = {"published_bg24": {"R5": 0.00179, "R4": 0.00193, "rel_margin_pct": 7.3},
             "refit_bg4.4": {"R5": 0.00157, "R4": 0.00159}}


def pct(x):
    lo, hi = np.quantile(x, [ALPHA / 2, 1 - ALPHA / 2])
    return [float(lo), float(hi)]


def stats_from_idx(r5, r4, idx):
    m5 = r5[idx].mean(axis=1)
    m4 = r4[idx].mean(axis=1)
    diff = m4 - m5
    with np.errstate(divide="ignore", invalid="ignore"):
        ratio = m4 / m5
        margin = 1.0 - m5 / m4
    return {
        "mean_R5_homeprov": pct(m5),
        "mean_R4_component": pct(m4),
        "diff_R4_minus_R5": pct(diff),
        "ratio_R4_over_R5": pct(ratio),
        "rel_margin_1_minus_R5_over_R4": pct(margin),
        "frac_resamples_diff_le_0": float(np.mean(diff <= 0)),
        "frac_resamples_diff_eq_0": float(np.mean(diff == 0)),
    }


def analyse(path, rng):
    d = json.load(open(path))
    rows = [r for r in d["rows"] if r.get("detected")]
    r5 = np.array([r[P5]["OQ"] for r in rows], dtype=float)
    r4 = np.array([r[P4]["OQ"] for r in rows], dtype=float)
    n = len(rows)
    seeds = [r["seed"] for r in rows]
    useeds = sorted(set(seeds))
    # point estimates, recomputed from rows and compared with the file's summary
    point = {
        "n_rows": n,
        "row_keys": [[r["seed"], r["ft"]] for r in rows],
        "per_row_OQ_R5": r5.tolist(), "per_row_OQ_R4": r4.tolist(),
        "per_row_Q_R5": [r[P5]["Q"] for r in rows],
        "per_row_Q_R4": [r[P4]["Q"] for r in rows],
        "per_row_U": [r["U"] for r in rows], "per_row_T": [r["T"] for r in rows],
        "mean_R5": float(r5.mean()), "mean_R4": float(r4.mean()),
        "summary_mean_OQ_R5_in_file": d["summary"][P5]["mean_OQ"],
        "summary_mean_OQ_R4_in_file": d["summary"][P4]["mean_OQ"],
        "means_equal_file_summary": (float(r5.mean()) == d["summary"][P5]["mean_OQ"]
                                     and float(r4.mean()) == d["summary"][P4]["mean_OQ"]),
        "diff_R4_minus_R5": float(r4.mean() - r5.mean()),
        "ratio_R4_over_R5": float(r4.mean() / r5.mean()),
        "rel_margin_1_minus_R5_over_R4": float(1 - r5.mean() / r4.mean()),
        "rows_R4_gt_R5": int(np.sum(r4 > r5)), "rows_R4_eq_R5": int(np.sum(r4 == r5)),
        "rows_R4_lt_R5": int(np.sum(r4 < r5)),
        "rows_R4_equals_R5_setwise": ([r.get("R4_equals_R5_setwise") for r in rows]
                                      if "R4_equals_R5_setwise" in rows[0] else None),
        "n_seeds": len(useeds), "seeds": useeds,
    }
    # PRIMARY: resample the n rows
    idx = rng.integers(0, n, size=(B, n))
    primary = stats_from_idx(r5, r4, idx)
    # SENSITIVITY: resample seeds as clusters
    groups = [np.array([i for i, s in enumerate(seeds) if s == u]) for u in useeds]
    gidx = rng.integers(0, len(useeds), size=(B, len(useeds)))
    sizes = {len(g) for g in groups}
    assert len(sizes) == 1, "unequal cluster sizes; cluster mean would need weights"
    cidx = np.stack([np.concatenate([groups[j] for j in row]) for row in gidx])
    cluster = stats_from_idx(r5, r4, cidx)
    return point, primary, cluster


def main():
    rng = np.random.default_rng(SEED)
    started = C.now_iso()
    res = {"item": "R9(a) localization over-quarantine intervals",
           "method": {"bootstrap": "paired, percentile", "B": B, "rng": "numpy.default_rng",
                      "seed": SEED, "alpha": ALPHA,
                      "primary_unit": "row = (seed, forgery type); 16 rows as in the paper",
                      "sensitivity_unit": "seed cluster (8 clusters x 2 rows)",
                      "metric": "OQ = |Q \\ T| / U  (rig.metrics.oq), per row",
                      "policies": {"R5_homeprov": "paper policy, localize.greedy",
                                   "R4_component": "connected causal component"}},
           "arms": {}}
    for arm, path in ARMS.items():
        point, primary, cluster = analyse(path, rng)
        pub = PUBLISHED[arm]
        point["reproduces_published_3dp"] = {
            "R5": round(point["mean_R5"], 5) == pub["R5"],
            "R4": round(point["mean_R4"], 5) == pub["R4"]}
        if "rel_margin_pct" in pub:
            point["reproduces_published_3dp"]["rel_margin_pct"] = (
                round(100 * point["rel_margin_1_minus_R5_over_R4"], 1) == pub["rel_margin_pct"])
        res["arms"][arm] = {"input": os.path.relpath(path, C.REPO),
                            "published_numbers": pub, "point": point,
                            "ci95_primary_rows": primary,
                            "ci95_sensitivity_seed_clusters": cluster}
    res["provenance"] = C.provenance(__file__, inputs=list(ARMS.values()),
                                     seeds={"bootstrap_rng": SEED,
                                            "deployment_seeds_in_inputs": "201-208"},
                                     extra={"started": started, "finished": C.now_iso()})
    res["deviations"] = [
        "No recomputation: per-row values are taken from the saved stage-24 artifacts.",
        "The paper's '16 generated deployments' are 8 generated deployments (seeds "
        "201-208) x 2 forgery types (FT-1, FT-4); FT-7/10/12 produced no row. The "
        "seed-cluster bootstrap is reported as a sensitivity analysis for that.",
    ]
    p = C.write_result("r9_a_localization_ci.json", res)
    print(p)
    print(json.dumps({a: {"point": {k: v for k, v in r["point"].items()
                                    if not k.startswith("per_row") and k != "row_keys"},
                          "primary": r["ci95_primary_rows"],
                          "cluster": r["ci95_sensitivity_seed_clusters"]}
                      for a, r in res["arms"].items()}, indent=1))


if __name__ == "__main__":
    main()
