#!/usr/bin/env python3
"""R14 (S&P 2027 round 14, 2026-10-12): benign failure rates per hour and per day, per real-deployment run, with a
block bootstrap over consecutive untouched one-second segments, and the pooled floor decomposed by scheme.

Answers internal review r3 (R3 W3): "Report benign rates per hour or day, with per-run counts and a block bootstrap";
"The 13/4,733 pool mixes schemes and authentication settings across nine runs".

WHAT IT READS (saved files only; no recorder is re-committed, no monitor code runs, nothing touches a live system):
  * each run's published floor file (exp/out/<tag>_floor_rescore.json: the paper's counting rule, k, n, the failing
    one-second segments, the seconds the new rule added to the touched set) and its result file (trials, window);
  * each run's saved anchor chain (the exact file whose sha256 the floor file records), to list the anchored one-second
    segments in the window with the floor file's own rule (first record per segment among records whose payload ts lies
    in [t_start, recorder_snapshot_at], evidence-unobservable records skipped, segment start in [t_start - 1, t_end + 1]
    unless the floor file says the segment-window filter was off);
  * E3, E1 and E5: their derived files (k, n and window; these files do not list the failing segment ids);
  * E7 and E8: each monitor's verify file (k = benign_floor.violated, n = benign_floor.untouched_anchored_seconds) and
    the score files' windows.
The untouched set of a run is rebuilt as (anchored seconds) minus (old touched set: the second of each trial's judged /
forged / captured row, from the result file) minus (newly_touched_second_segments, from the floor file), which is the
floor file's own construction; the script asserts that its size equals the floor file's n and that every failing
segment lies in it, so the ordering used by the bootstrap is the published set, not an estimate.

RATES. Two denominators, both stated per run:
  * per untouched hour / day: k / n x 3600 (x 86400), where n counts untouched anchored one-second segments, i.e. the
    failure rate per hour of untouched seconds that held rows and were sealed (each such segment is one second);
  * per wall-clock hour / day of the run window: k / duration_s x 3600 (x 86400).
Each rate carries the exact (Clopper-Pearson, exp/rig/stats.py) interval of k/n scaled the same way, and, where the
failing segment ids are saved, a block-bootstrap percentile interval.

BLOCK BOOTSTRAP. Circular block bootstrap (Politis and Romano) over a run's untouched one-second segments in time order
(the series x_i = 1 if the i-th untouched segment failed): b = ceil(n / L) blocks of L consecutive untouched segments,
start positions uniform on the circle, the last block truncated so every replicate has exactly n segments; statistic:
the replicate's failure proportion. Primary block length L = 60 untouched segments (60 distinct seconds, at least a
minute of wall-clock time, so a block spans at least twelve 5 s monitor polls); sensitivity L = 1 (iid), 10, 30, 120.
B = 10,000 replicates; numpy PCG64 seeded with SeedSequence([20261012, run index, L]); percentile interval
[sorted[int(0.025 B)], sorted[int(0.975 B) - 1]] (exp/rig/stats.py's convention). A pool is a stratified bootstrap: each
run is resampled within itself with its own replicates and the pool's replicate rate is (sum of run failures) / (sum of
run n), so dependence is kept inside runs and no block crosses runs. With k = 0 every replicate is 0 (degenerate): the
exact interval is the informative one, and the file says so.

    python3 exp/sp2027/r14_benign_rates.py      -> exp/out/r14_benign_rates.json (never overwrites)
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import datetime
import gzip
import hashlib
import json
import math
import os
import re

import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
EXTRACTS = os.path.join(REPO, "reproduce", "snapshots")
SNAPSET = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-snapshots", "verifier-recorder-snapshots-2026-10")
# R14_DRYRUN_DIR (development only) writes the output elsewhere with fewer replicates; the published file uses neither.
DRY = os.environ.get("R14_DRYRUN_DIR")
DST = os.path.join(DRY or OUT, "r14_benign_rates.json")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import stats  # noqa: E402

SEED = 20261012
B = 200 if DRY else 10000
L_PRIMARY = 60
L_SENS = (1, 10, 30, 60, 120)

INPUTS = {}          # relative path -> sha256 (every file this script reads)


def rel(p):
    p = os.path.abspath(p)
    if p.startswith(REPO + os.sep):
        return os.path.relpath(p, REPO)
    return "<snapshot-set>/" + os.path.relpath(p, SNAPSET) if p.startswith(SNAPSET + os.sep) else p


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(p):
    INPUTS[rel(p)] = sha256_file(p)
    with open(p) as fh:
        return json.load(fh)


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return [r["ci_lo"], r["ci_hi"]]


# ------------------------------------------------------------------------------------------------ runs
# The nine-run pool (paper Table 11 / tab:floors) and the three whole-row runs: floor file, result file, saved chain.
# "chain" is the file whose sha256 equals the floor file's chain_sha256 (asserted).
FLOOR_RUNS = [
    dict(tag="e_c_write_time", label="Write-time strategies", date="2026-09-09", pool9=True,
         result="e_c_write_time.json", chain=os.path.join(SNAPSET, "hp_d2", "live", "default_chain.jsonl")),
    dict(tag="e_d_other_principal_real", label="Other principal", date="2026-09-18", pool9=True,
         result="e_d_other_principal_real.json",
         chain=os.path.join(SNAPSET, "hp_d2", "live", "default_chain.jsonl")),
    dict(tag="e_d_auth", label="Other principal", date="2026-09-26", pool9=True,
         result="e_d_auth_other_principal_real.json", chain=os.path.join(OUT, "e_d_auth_anchor_chain.jsonl.gz")),
    dict(tag="e_c_auth", label="Write-time strategies", date="2026-10-02", pool9=True,
         result="e_c_auth_other_principal_real.json", chain=os.path.join(OUT, "e_c_auth_anchor_chain.jsonl.gz")),
    dict(tag="e_ps_auth", label="Random-id swap", date="2026-10-02", pool9=True,
         result="e_ps_auth_detection.json", chain=os.path.join(OUT, "e_ps_auth_anchor_chain.jsonl.gz")),
    dict(tag="e_ps_clo", label="Random-id swap", date="2026-10-02", pool9=True,
         result="e_ps_clo_detection.json", chain=os.path.join(EXTRACTS, "e_ps_clo.chain.jsonl")),
    dict(tag="e_d_clo", label="Other principal", date="2026-10-02", pool9=True,
         result="e_d_clo_other_principal_real.json", chain=os.path.join(EXTRACTS, "e_d_clo.chain.jsonl")),
    dict(tag="e_c_clo", label="Write-time strategies", date="2026-10-02", pool9=True,
         result="e_c_clo_other_principal_real.json", chain=os.path.join(EXTRACTS, "e_c_clo.chain.jsonl")),
    dict(tag="e_psr_clo", label="Member-account swap", date="2026-10-03", pool9=True,
         result="e_psr_clo_detection.json", chain=os.path.join(EXTRACTS, "e_psr_clo.chain.jsonl")),
    dict(tag="e_ps_whr", label="Random-id swap", date="2026-10-04", pool9=False,
         result="e_ps_whr_detection.json", chain=os.path.join(EXTRACTS, "e_ps_whr.chain.jsonl")),
    dict(tag="e_d_whr", label="Other principal", date="2026-10-04", pool9=False,
         result="e_d_whr_other_principal_real.json", chain=os.path.join(EXTRACTS, "e_d_whr.chain.jsonl")),
    dict(tag="e_psr_whr", label="Member-account swap", date="2026-10-04", pool9=False,
         result="e_psr_whr_detection.json", chain=os.path.join(EXTRACTS, "e_psr_whr.chain.jsonl")),
]
TS_RE = re.compile(r'"ts":\s*([0-9.eE+-]+)\s*\}\s*,\s*"recv_ts"')


def chain_lines(p):
    INPUTS[rel(p)] = sha256_file(p)
    if p.endswith(".gz"):
        with gzip.open(p, "rt") as fh:
            return fh.read().splitlines()
    with open(p) as fh:
        return fh.read().splitlines()


def anchored_seconds(lines, t0, t1, tsnap, segwin):
    """The floor file's rule: first record per segment among records with payload ts in [t0, tsnap], evidence-
    unobservable records skipped; second segments whose start lies in [t0 - 1, t1 + 1] when segwin. Also returns the
    node encodings named by the records used (absent = the earlier encoding)."""
    secs, encs = set(), set()
    for line in lines:
        if not line.strip():
            continue
        m = TS_RE.search(line)                      # cheap pre-filter on the payload ts (the full parse decides)
        if m is not None:
            try:
                ts_hint = float(m.group(1))
            except ValueError:
                ts_hint = None
            if ts_hint is not None and not (t0 - 1 <= ts_hint <= tsnap + 1):
                continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        p = rec.get("payload") or {}
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap) or p.get("evidence_unobservable"):
            continue
        sec = (p.get("sealed") or {}).get("second")
        if isinstance(sec, dict) and sec:
            encs.add(p.get("encoding") or "absent (earlier encoding)")
            for s in sec:
                if (not segwin) or (t0 - 1 <= int(s) <= t1 + 1):
                    secs.add(str(s))
    return secs, sorted(encs)


def row_ts(t):
    for k in ("judged_row", "forged_row", "row_before"):
        r = t.get(k)
        if isinstance(r, dict) and r.get("ts"):
            return float(r["ts"])
    return None


def untouched_series(run):
    fl = read_json(os.path.join(OUT, run["tag"] + "_floor_rescore.json"))
    res = read_json(os.path.join(OUT, run["result"]))
    assert fl["result_sha256"] == INPUTS[rel(os.path.join(OUT, run["result"]))], run["tag"]
    lines = chain_lines(run["chain"])
    assert fl["chain_sha256"] == INPUTS[rel(run["chain"])], (run["tag"], "chain is not the floor file's chain")
    win = fl["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    secs, encs = anchored_seconds(lines, t0, t1, tsnap, fl["segment_window_filter"])
    trials = ([t for t in res["trials"] if t.get("arm") in ("PS", "PSR")] if "homeprov_detection_second" in res
              else res["trials"])
    old = {str(int(row_ts(t) // 1)) for t in trials if row_ts(t) is not None}
    touched = old | set(fl["newly_touched_second_segments"])
    unt = sorted((s for s in secs if s not in touched), key=int)
    f = fl["new_rule_floor"]["second"]
    failing = [x["segment"] for x in f["failing"]]
    assert len(unt) == f["n"], (run["tag"], len(unt), f["n"])
    assert set(failing) <= set(unt) and len(failing) == f["k"], run["tag"]
    x = np.array([1 if s in set(failing) else 0 for s in unt], dtype=np.int64)
    auth = (res.get("versions") or {}).get("anchor_authenticated")
    return {"floor": fl, "res": res, "series": x, "untouched": unt, "failing": failing, "encodings": encs,
            "window": win, "auth": auth, "scheme": fl["scheme"],
            "mechanisms": f["mechanisms"], "anchored_seconds": len(secs)}


# ------------------------------------------------------------------------------------------------ bootstrap
def cbb_counts(x, L, idx):
    """B replicate failure counts of a circular block bootstrap of series x with block length L."""
    n = len(x)
    L = min(L, n)
    b = math.ceil(n / L)
    r = n - (b - 1) * L                                   # length of the truncated last block
    rng = np.random.Generator(np.random.PCG64(np.random.SeedSequence([SEED, idx, L])))
    c = np.concatenate([[0], np.cumsum(np.concatenate([x, x]))])
    starts = rng.integers(0, n, size=(B, b))
    full = (c[starts[:, :b - 1] + L] - c[starts[:, :b - 1]]).sum(axis=1) if b > 1 else np.zeros(B, dtype=np.int64)
    last = c[starts[:, b - 1] + r] - c[starts[:, b - 1]]
    return full + last


def pct(v):
    s = np.sort(v)
    return float(s[int(0.025 * len(s))]), float(s[int(0.975 * len(s)) - 1])


def rates(k, n, duration_s, boot=None):
    """Rates per untouched hour/day and per wall-clock hour/day, with exact and (if given) bootstrap intervals."""
    lo, hi = cp(k, n)
    out = {"k": k, "n_untouched_anchored_one_second_segments": n, "window_duration_s": duration_s,
           "proportion": k / n, "exact_interval": [lo, hi],
           "per_untouched_hour": {"rate": 3600.0 * k / n, "exact_interval": [3600.0 * lo, 3600.0 * hi]},
           "per_untouched_day": {"rate": 86400.0 * k / n, "exact_interval": [86400.0 * lo, 86400.0 * hi]}}
    if duration_s:
        sc = n / duration_s
        out["per_wallclock_hour"] = {"rate": 3600.0 * k / duration_s,
                                     "exact_interval": [3600.0 * lo * sc, 3600.0 * hi * sc]}
        out["per_wallclock_day"] = {"rate": 86400.0 * k / duration_s,
                                    "exact_interval": [86400.0 * lo * sc, 86400.0 * hi * sc]}
    if boot is not None:
        bb = {}
        for L, counts in boot.items():
            p = counts / n
            plo, phi = pct(p)
            e = {"block_length": L, "replicates": B, "proportion_interval": [plo, phi],
                 "per_untouched_hour_interval": [3600.0 * plo, 3600.0 * phi],
                 "per_untouched_day_interval": [86400.0 * plo, 86400.0 * phi],
                 "replicate_mean_proportion": float(p.mean()),
                 "share_of_replicates_with_zero_failures": float((counts == 0).mean())}
            if duration_s:
                sc = n / duration_s
                e["per_wallclock_hour_interval"] = [3600.0 * plo * sc, 3600.0 * phi * sc]
                e["per_wallclock_day_interval"] = [86400.0 * plo * sc, 86400.0 * phi * sc]
            bb[str(L)] = e
        out["block_bootstrap"] = {"primary_block_length": L_PRIMARY, "by_block_length": bb}
    return out


def degenerate_note(k):
    if k == 0:
        return ("degenerate: k = 0, so every block resample of the all-zero series is 0; no bootstrap interval is "
                "reported and the exact interval is the informative one")
    return None


# ------------------------------------------------------------------------------------------------ main
def main():
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    runs = {}
    boots = {}                                             # run id -> {L: replicate counts}
    for i, run in enumerate(FLOOR_RUNS):
        u = untouched_series(run)
        dur = u["window"]["duration_s"]
        k, n = int(u["series"].sum()), len(u["series"])
        boots[run["tag"]] = {L: cbb_counts(u["series"], L, i) for L in L_SENS} if k > 0 else None
        pos = [int(j) for j in np.flatnonzero(u["series"])]
        runs[run["tag"]] = {
            "label": run["label"], "date": run["date"], "group": "nine-run pool" if run["pool9"] else "whole-row runs",
            "scheme": u["scheme"], "authenticated_append_path": u["auth"], "coverage": False, "markers": False,
            "record_signatures": False, "linked_anchor": False, "placement": "lab installation (single host, unprivileged container)",
            "node_encoding_named_by_chain_records": u["encodings"], "sealing_grace_s": 0,
            "window": u["window"], "anchored_one_second_segments_in_window": u["anchored_seconds"],
            "failing_segments": u["failing"], "failure_mechanisms": u["mechanisms"],
            "failing_positions_in_untouched_series": pos,
            "untouched_set_check": "rebuilt from the saved chain, the result file and the floor file; size equals the "
                                   "floor file's n and every failing segment lies in it (asserted)",
            "floor_file": "exp/out/%s_floor_rescore.json" % run["tag"], "result_file": "exp/out/" + run["result"],
            "chain_file": rel(run["chain"]),
            **rates(k, n, dur, boots[run["tag"]]),
        }
        if k == 0:
            runs[run["tag"]]["block_bootstrap"] = degenerate_note(0)

    # E3 (paired grace runs), E1 and E5 (two-host placement): k, n, window from their derived files; no failing ids.
    e3 = read_json(os.path.join(OUT, "e3_grace_sealing.json"))
    for r in e3["runs"]:
        bf = r["benign_floor"]["second"]
        t0, t1, _ts = r["window"]
        k, n = bf["k"], bf["n"]
        runs[r["tag"]] = {
            "label": "Other principal, grace %g s" % r["grace_s"], "date": "2026-10-07", "group": "E3 paired grace runs",
            "scheme": "closure", "authenticated_append_path": True, "coverage": False, "markers": False,
            "record_signatures": False, "linked_anchor": False,
            "placement": "lab installation (single host, unprivileged container)",
            "node_encoding_named_by_chain_records": [r.get("node_hash_encoding")], "sealing_grace_s": r["grace_s"],
            "window": {"t_start": t0, "t_end": t1, "duration_s": t1 - t0}, "source_file": "exp/out/e3_grace_sealing.json",
            **rates(k, n, t1 - t0),
            "block_bootstrap": degenerate_note(k) or ("not computed: exp/out/e3_grace_sealing.json saves k and n but not "
                                                       "the failing segment ids, so their positions are not in a saved file"),
        }
    auth_e3 = {}
    for tag in ("e3_g0_clo", "e3_g2_clo"):
        cfg = read_json(os.path.join(OUT, tag + "_config.json"))
        auth_e3[tag] = [l for l in cfg["configuration_log"] if "probe_from_hub" in l]
        runs[tag]["authenticated_append_path_evidence"] = auth_e3[tag]
    for tag, det, rule_file, rule_path in (("e1_psr_clo", "e1_psr_clo_detection.json", "e1_psr_clo_two_host.json",
                                            ("paper_counting_rule", "benign_floor")),
                                           ("e5_psr_lnk", "e5_psr_lnk_detection.json", "e5_psr_lnk_paper_rule.json",
                                            ("benign_floor",))):
        d = read_json(os.path.join(OUT, det))
        rf = read_json(os.path.join(OUT, rule_file))
        bf = rf
        for kk in rule_path:
            bf = bf[kk]
        bf = bf["second"]
        k, n = bf["k"], bf["n"]
        runs[tag] = {
            "label": "Member-account swap, " + ("two hosts" if tag.startswith("e1") else "linked anchor, two hosts"),
            "date": "2026-10-08", "group": "two-host placement (HA OS VM, privileged core)",
            "scheme": "closure", "authenticated_append_path": (d.get("versions") or {}).get("anchor_authenticated"),
            "coverage": False, "markers": False, "record_signatures": False, "linked_anchor": tag.startswith("e5"),
            "placement": "two hosts: Home Assistant OS VM with a privileged core; monitor and anchor on another VM",
            "node_encoding_named_by_chain_records": rf.get("encoding") or rf["paper_counting_rule"].get("encoding"),
            "sealing_grace_s": 0, "window": d["window"], "source_file": "exp/out/" + rule_file,
            "failure_mechanisms": bf.get("mechanisms"),
            **rates(k, n, d["window"]["duration_s"]),
            "block_bootstrap": degenerate_note(k) or ("not computed: exp/out/%s saves k, n and the mechanisms but not "
                                                       "the failing segment ids" % rule_file),
        }

    # E7 and E8: each monitor's verify file; windows from the score files.
    e7s = read_json(os.path.join(OUT, "e7_main_score.json"))
    e8s = read_json(os.path.join(OUT, "e8_main_score_rescored.json"))
    e7c = read_json(os.path.join(OUT, "e7_main_config.json"))
    e8c = read_json(os.path.join(OUT, "e8_main_config.json"))
    e7_probe = [l for l in e7c["configuration_log"] if "probe_from_hub" in l]
    e8_probe = [l for l in e8c["configuration_log"] if "probe_from_hub" in l]
    cov = []

    def chain_encodings(path):
        encs = set()
        for line in chain_lines(path):
            if line.strip():
                p = (json.loads(line).get("payload") or {})
                if p.get("sealed") is not None or p.get("coverage") is not None:
                    encs.add(p.get("encoding") or "absent (earlier encoding)")
        return sorted(encs)
    for mon, scheme in (("closure", "closure"), ("stable", "stable columns")):
        v = read_json(os.path.join(OUT, "e7_main_%s_verify.json" % mon))
        bf = v["benign_floor"]
        w = e7s["window"]
        tag = "e7_main_" + mon
        runs[tag] = {"label": "E7, nine arms (%s monitor)" % mon, "date": "2026-10-08",
                     "group": "deployed configuration (coverage)", "scheme": scheme,
                     "authenticated_append_path": True, "authenticated_append_path_evidence": e7_probe,
                     "coverage": True, "markers": False, "record_signatures": False, "linked_anchor": False,
                     "placement": "lab installation (single host, unprivileged container)", "sealing_grace_s": 0,
                     "node_encoding_named_by_chain_records":
                         chain_encodings(os.path.join(OUT, "e7_main_%s_chain.jsonl.gz" % mon)),
                     "window": w, "source_file": "exp/out/e7_main_%s_verify.json" % mon,
                     "counting_rule": bf.get("counting_rule"),
                     **rates(bf["violated"], bf["untouched_anchored_seconds"], w["duration_s"]),
                     "block_bootstrap": degenerate_note(bf["violated"]),
                     "note": "both E7 monitors observed the same run and the same untouched seconds"}
        cov.append(tag)
        e8enc = {mon: chain_encodings(os.path.join(OUT, "e8_main_%s_chain.jsonl.gz" % mon))}
        for win in ("main", "base", "stress"):
            v = read_json(os.path.join(OUT, "e8_main_%s_verify_%s.json" % (mon, win)))
            bf = v["benign_floor"]
            w = e8s["windows"][win]
            tag = "e8_main_%s_%s" % (mon, win)
            runs[tag] = {"label": "E8 %s window (%s monitor)" % (win, mon), "date": "2026-10-09",
                         "group": "deployed configuration (coverage)", "scheme": scheme,
                         "authenticated_append_path": True, "authenticated_append_path_evidence": e8_probe,
                         "coverage": True, "markers": False, "record_signatures": True, "linked_anchor": True,
                         "placement": "lab installation (single host, unprivileged container)", "sealing_grace_s": 0,
                         "node_encoding_named_by_chain_records": e8enc[mon],
                         "window": w, "source_file": "exp/out/e8_main_%s_verify_%s.json" % (mon, win),
                         "counting_rule": bf.get("counting_rule"),
                         **rates(bf["violated"], bf["untouched_anchored_seconds"], w["duration_s"]),
                         "block_bootstrap": degenerate_note(bf["violated"]),
                         "note": "both E8 monitors observed the same run and the same untouched seconds"}
            cov.append(tag)

    # ---------------------------------------------------------------- pools (each pool holds one scheme, except the
    # reference row that reproduces the published nine-run pool)
    def pool(members, what):
        k = sum(runs[m]["k"] for m in members)
        n = sum(runs[m]["n_untouched_anchored_one_second_segments"] for m in members)
        dur = sum(runs[m]["window_duration_s"] for m in members)
        schemes = sorted({runs[m]["scheme"] for m in members})
        auths = sorted({str(runs[m]["authenticated_append_path"]) for m in members})
        out = {"what": what, "runs": members, "n_runs": len(members), "schemes": schemes,
               "authenticated_append_path": auths, "mixes_schemes": len(schemes) > 1,
               "mixes_authentication_settings": len(auths) > 1}
        # a member with k = 0 adds 0 to every replicate (any resample of an all-zero series is 0); a member with k > 0
        # needs its own replicates, which exist only where its failing segment ids are saved
        if k > 0 and all(boots.get(m) is not None for m in members if runs[m]["k"] > 0):
            bb = {}
            for L in L_SENS:
                tot = np.zeros(B, dtype=np.int64)
                for m in members:
                    if boots.get(m) is not None:
                        tot = tot + boots[m][L]
                bb[L] = tot
            out.update(rates(k, n, dur, bb))
            out["block_bootstrap"]["how"] = ("stratified: each run resampled within itself (its own replicates, "
                                             "the per-run seeds above); pool replicate = sum of run failures / sum of n")
        else:
            out.update(rates(k, n, dur))
            out["block_bootstrap"] = degenerate_note(k) or (
                "not computed: at least one member run's failing segment ids are not saved")
        return out

    nine = [r["tag"] for r in FLOOR_RUNS if r["pool9"]]
    pools = {
        "nine_run_pool_as_published": pool(nine, "the published pool (Table 5 last row, Appendix B): mixes the row "
                                                 "and closure schemes and two authentication settings; reference only"),
        "nine_run_pool_row_scheme": pool([t for t in nine if runs[t]["scheme"] == "row"],
                                         "row scheme, both authentication settings"),
        "nine_run_pool_row_scheme_unauthenticated": pool([t for t in nine if runs[t]["scheme"] == "row"
                                                          and runs[t]["authenticated_append_path"] is False],
                                                         "row scheme, unauthenticated anchor"),
        "nine_run_pool_row_scheme_authenticated": pool([t for t in nine if runs[t]["scheme"] == "row"
                                                        and runs[t]["authenticated_append_path"] is True],
                                                       "row scheme, authenticated append path"),
        "nine_run_pool_closure_scheme": pool([t for t in nine if runs[t]["scheme"] == "closure"],
                                             "closure scheme without coverage, authenticated append path"),
        "whole_row_scheme": pool([r["tag"] for r in FLOOR_RUNS if not r["pool9"]],
                                 "whole-row scheme without coverage, authenticated append path (in-place rewrites "
                                 "of last_reported_ts fail sealed segments)"),
        "closure_with_coverage_E7_E8": pool([t for t in cov if "closure" in t],
                                            "closure scheme with coverage (E7 and the three E8 windows)"),
        "stable_columns_with_coverage_E7_E8": pool([t for t in cov if "stable" in t],
                                                   "stable-columns scheme with coverage, the deployed scheme (E7 and "
                                                   "the three E8 windows)"),
        "stable_columns_with_coverage_E8_only": pool([t for t in cov if "stable" in t and t.startswith("e8")],
                                                     "the deployed configuration as evaluated in E8 (signed records, "
                                                     "linked anchors): main, baseline and stress windows"),
        "closure_without_coverage_E3": pool(["e3_g0_clo", "e3_g2_clo"],
                                            "closure scheme, authenticated, E3 grace 0 s and 2 s (encoding v2)"),
        "closure_two_host_E1_E5": pool(["e1_psr_clo", "e5_psr_lnk"],
                                       "closure scheme, authenticated, two-host placement (E1, E5)"),
    }
    pub = pools["nine_run_pool_as_published"]
    assert (pub["k"], pub["n_untouched_anchored_one_second_segments"]) == (13, 4733), pub
    decomp = {s: {"k": pools[p]["k"], "n": pools[p]["n_untouched_anchored_one_second_segments"]}
              for s, p in (("row", "nine_run_pool_row_scheme"), ("closure", "nine_run_pool_closure_scheme"))}

    src = open(os.path.abspath(__file__), "rb").read()
    out = {
        "what": "R14: benign failure rates per hour and per day for every real-deployment run with a benign floor, "
                "per-run counts and settings, a block bootstrap over consecutive untouched one-second segments, and "
                "the pooled floor decomposed so that no pool mixes schemes",
        "answers": ["R3 W3: 'Report benign rates per hour or day, with per-run counts and a block bootstrap'",
                    "R3 W3: 'The 13/4,733 pool mixes schemes and authentication settings across nine runs'"],
        "definitions": {
            "untouched_segment": "an anchored one-second segment that holds no row any trial wrote, edited or named "
                                 "(the paper's counting rule; reproduce/verify_all.py touched_segments and, for E7/E8, "
                                 "e7_verify's benign floor with the trials' deleted events)",
            "k": "untouched one-second segments that fail verification (the benign floor's numerator)",
            "per_untouched_hour": "k / n x 3600: failures per hour of untouched anchored seconds (seconds that held "
                                  "rows, were sealed and were not touched by a trial)",
            "per_wallclock_hour": "k / window duration x 3600: failures per hour of the run window",
            "exact_interval": "Clopper-Pearson 95% interval of k/n (exp/rig/stats.py), scaled like the rate",
            "block_bootstrap": {"method": "circular block bootstrap over the run's untouched one-second segments in "
                                          "time order; replicate statistic = failure proportion; percentile interval",
                                "primary_block_length": L_PRIMARY,
                                "block_lengths_reported": list(L_SENS),
                                "block_length_unit": "consecutive untouched one-second segments (each a distinct "
                                                     "second; L = 60 spans at least 60 s of wall-clock time, i.e. "
                                                     "at least twelve 5 s monitor polls)",
                                "replicates": B, "seed": SEED,
                                "rng": "numpy PCG64, SeedSequence([seed, run index in FLOOR_RUNS, L])",
                                "pools": "stratified by run (blocks never cross runs)",
                                "k_zero": "degenerate (every replicate is 0); exact interval reported instead"},
        },
        "runs": runs,
        "pools": pools,
        "nine_run_pool_decomposition": {
            "published": "13/4,733 [Table 5, Appendix B]",
            "by_scheme": decomp,
            "by_scheme_and_authentication": {
                "row, unauthenticated": [pools["nine_run_pool_row_scheme_unauthenticated"]["k"],
                                         pools["nine_run_pool_row_scheme_unauthenticated"]
                                         ["n_untouched_anchored_one_second_segments"]],
                "row, authenticated": [pools["nine_run_pool_row_scheme_authenticated"]["k"],
                                       pools["nine_run_pool_row_scheme_authenticated"]
                                       ["n_untouched_anchored_one_second_segments"]],
                "closure, authenticated": [pools["nine_run_pool_closure_scheme"]["k"],
                                           pools["nine_run_pool_closure_scheme"]
                                           ["n_untouched_anchored_one_second_segments"]]},
            "every_failure_mechanism": sorted({m for t in nine for m in runs[t]["failure_mechanisms"]}),
        },
        "not_included": {
            "Domoticz run": "a different hub (exp/out/dz_summary.json), not a Home Assistant real-deployment run",
            "E2 real purge (night 3)": "a purge evaluation, not an untouched-segment floor (exp/out/"
                                       "e2_scoped_markers_real_night_2026-10-10.json)",
            "E9": "running until 2026-10-19; its files are not read",
        },
        "inputs_sha256": INPUTS,
        "script": "exp/sp2027/r14_benign_rates.py",
        "script_sha256": hashlib.sha256(src).hexdigest(),
        "python": sys.version.split()[0], "numpy": np.__version__,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=False)
    print("wrote", DST, hashlib.sha256(open(DST, "rb").read()).hexdigest())
    for p in ("nine_run_pool_as_published", "nine_run_pool_row_scheme", "nine_run_pool_closure_scheme",
              "whole_row_scheme", "stable_columns_with_coverage_E7_E8", "closure_with_coverage_E7_E8"):
        x = pools[p]
        bb = x.get("block_bootstrap")
        bbi = bb["by_block_length"][str(L_PRIMARY)]["per_untouched_hour_interval"] if isinstance(bb, dict) else bb
        print(p, x["k"], x["n_untouched_anchored_one_second_segments"], round(x["per_untouched_hour"]["rate"], 3),
              [round(v, 3) for v in x["per_untouched_hour"]["exact_interval"]], bbi)


if __name__ == "__main__":
    main()
