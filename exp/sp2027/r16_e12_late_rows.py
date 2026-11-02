"""E12 H3 (exploratory), recomputed: late rows per day and monitor, and in the restart and backup windows.

exp/stages/e12_summary.py reads a row's delay from "lat", "lower_bound_s" or "late_s"; the verifier's rows carry it as
"committed_after_lower_bound_s", so the summary reported n = 0 and no maximum (found 2026-10-24). This script reads the
per-day verifier outputs in the run directory (verify/<monitor>_day<n>_<hash>.json, not the norowbind variants) and the
day windows exp/out/e12_main_d<n>_window.json, and writes exp/out/r16_e12_late_rows.json (never overwritten).
"""
import glob, hashlib, json, os, sys

RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e12/e12_main"
OUT = "<artifact-root>/exp/out"
DELAY = "committed_after_lower_bound_s"
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
summ = json.load(open(os.path.join(OUT, "e12_main_e12_summary.json")))
wins = {"restart": summ["planned_restart"]["window"], "backup": summ["backup"]["window"]}
res = {"source_note": __doc__.strip().split("\n")[0], "delay_field": DELAY, "inputs": {}, "days": {}, "windows": {}}


def stats(rows, lo, hi):
    ds = [r[DELAY] for r in rows if r.get("second") is not None and lo <= int(r["second"]) < hi and isinstance(r.get(DELAY), (int, float))]
    nodelay = sum(1 for r in rows if r.get("second") is not None and lo <= int(r["second"]) < hi and not isinstance(r.get(DELAY), (int, float)))
    ds.sort()
    q = lambda p: ds[min(len(ds) - 1, int(p * len(ds)))] if ds else None
    return {"n": len(ds), "n_without_delay": nodelay, "median_s": q(0.5), "p99_s": q(0.99), "max_s": ds[-1] if ds else None,
            "over_25_s": sum(1 for d in ds if d > 25.0), "over_30_s": sum(1 for d in ds if d > 30.0)}


for n in ("1", "2"):
    w = json.load(open(os.path.join(OUT, "e12_main_d%s_window.json" % n)))
    res["inputs"]["window_d" + n] = {"value": w, "sha256": h(os.path.join(OUT, "e12_main_d%s_window.json" % n))}
    for m in ("direct", "copy"):
        f = [p for p in glob.glob(os.path.join(RUN, "verify", "%s_day%s_*.json" % (m, n))) if "norowbind" not in p][0]
        v = json.load(open(f))
        res["inputs"]["%s_day%s" % (m, n)] = {"file": os.path.relpath(f, RUN), "sha256": h(f)}
        day = res["days"].setdefault(n, {}).setdefault(m, {})
        for kind in ("benign_late_rows", "unobserved_late_rows", "attributable_rows"):
            day[kind] = stats(v.get(kind) or [], w[0], w[1])
        day["verifier_benign_late_max_lower_bound_s_whole_file"] = v.get("benign_late_max_lower_bound_s")
        if n == "1":
            lo, hi = wins["restart"]; res["windows"].setdefault("restart", {})[m] = {k: stats(v.get(k) or [], lo, hi + 1) for k in ("benign_late_rows", "unobserved_late_rows", "attributable_rows")}
        else:
            lo, hi = wins["backup"]; res["windows"].setdefault("backup", {})[m] = {k: stats(v.get(k) or [], lo, hi + 1) for k in ("benign_late_rows", "unobserved_late_rows", "attributable_rows")}
res["windows_def"] = wins
with open(os.path.join(OUT, "r16_e12_late_rows.json"), "x") as fh:
    json.dump(res, fh, indent=1)
print(json.dumps({"days": {n: {m: {k: (v[k]["n"], v[k]["max_s"], v[k]["over_25_s"]) for k in ("benign_late_rows", "unobserved_late_rows", "attributable_rows")} for m, v in d.items()} for n, d in res["days"].items()},
                  "windows": {w: {m: {k: (v[k]["n"], v[k]["max_s"]) for k in v} for m, v in d.items()} for w, d in res["windows"].items()}}, indent=1))
