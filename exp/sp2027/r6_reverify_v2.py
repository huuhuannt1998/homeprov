"""R6 (T7, T5): re-verify every saved real-deployment run with the typed node encoding (v2), and derive the Row scheme's
verdict on the member-account swap offline.

Every anchor chain in the snapshot set was sealed with the '|' encoding (v1), so a v2 root for a sealed segment does not
exist anywhere. This script recomputes it from the snapshot itself, segment by segment, and only where the snapshot
allows it:

  1. post rows: the segment's rows in the saved recorder copy (what the verifier reads);
  2. candidate sealed rows: the post rows with every recorded trial edit reverted (the trial records keep the edited
     rows' original context columns: row_before / judged_row), and, when the segment holds more rows than were sealed,
     the k late rows removed (the highest state and event ids, every split of k between the two tables tried); the
     unreverted post rows are tried as well;
  3. a candidate is ACCEPTED only if its v1 fold reproduces the anchored v1 root exactly (acc and n). The accepted rows
     are then the rows the monitor sealed, so their v2 fold is the root a v2 monitor would have sealed, and the v2 fold
     of the post rows is what a v2 verifier computes. Both come from the same snapshot data.
  4. A segment with fewer post rows than were sealed lost rows the snapshot no longer holds (deleted events): it cannot be
     reconstructed; its verdict is a row-count mismatch, which no node encoding affects (the count is outside the hash).

Per trial the script reports the v1 and v2 verdicts of the trial's one-second (and one-minute) segment, classified as
verify_all.py does (flagged; attributable if delta_n <= 0; ambiguous if delta_n > 0), and whether the trial's edit was in
the v1 collision class (an edited row whose v1 node hash is the same before and after the edit). The benign floor is
recounted under v2 with the paper's counting rule. The v1 numbers are checked against verify_all.py's.

T5: for the member-account swap (e_psr_clo, Closure monitor) the accepted sealed rows also determine what a Row-scheme
monitor would have sealed for the same segments (the Row scheme's fields are a subset of the Closure's), so the Row
scheme's verdict per trial is derived offline, with exact intervals. The same derivation on e_ps_clo, e_d_clo and e_c_clo
is reported as a check against the Row-scheme runs actually made (e_ps_auth, e_d_auth, e_c_auth).

    python3 exp/sp2027/r6_reverify_v2.py [--snapshots DIR]     # writes exp/out/r6_reverify_v2.json (never overwrites)
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import verify_all as VA  # noqa: E402
from rig import stats  # noqa: E402

GRANS = ("second", "minute")          # the granularities the paper reports; hours are listed but not reconstructed
ROW_OFFLINE = ("e_psr_clo", "e_ps_clo", "e_d_clo", "e_c_clo")


def hx(v):
    return bytes.fromhex(v) if v else None


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return [round(r["ci_lo"], 3), round(r["ci_hi"], 3)]


def reverts_for(trials):
    """state key -> original values of the fields the trial's edit rewrote (from the harness's own records)."""
    rev, edited_by = {}, {}
    for t in trials:
        arm, rb, jr = t.get("arm"), t.get("row_before") or {}, t.get("judged_row") or {}
        if arm in ("PS", "PSR"):
            sids, fields = t.get("swapped_state_ids") or [], ("usr",)
        elif arm in ("PU", "PI"):
            sids, fields = t.get("laundered_state_ids") or [], (("ctx", "par", "usr") if arm == "PU" else ("ctx", "par"))
        elif arm == "P":
            sids, fields = [rb["state_id"]], ("ctx", "par")
        else:
            continue                                    # write-time arms: no post-commit edit
        for sid in sids:
            src = jr if jr.get("state_id") == sid else rb
            orig = {"ctx": hx(src.get("context_id_bin")), "par": hx(src.get("context_parent_id_bin")),
                    "usr": hx(src.get("context_user_id_bin"))}
            rev["s:%d" % sid] = {f: orig[f] for f in fields}
            edited_by["s:%d" % sid] = (arm, t.get("trial"), t.get("room"))
    return rev, edited_by


class Hasher:
    def __init__(self, M, WR):
        self.M, self.WR, self.cache = M, WR, {}

    def node(self, n, enc):
        k = (id(n), enc)
        h = self.cache.get(k)
        if h is None:
            M = self.M
            if len(n) == 6:
                h = M.node_hash(n[1], n[2], n[3], n[4], n[5], encoding=enc)
            elif len(n) == 9:
                h = M.node_hash_closure(n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], encoding=enc)
            else:
                h = self.WR.node_hash_wholerow(n, enc)
            self.cache[k] = (h, n)              # keep n alive so id() is not reused
            return h
        return h[0]

    def fold(self, nodes, enc):
        acc = self.M.ZERO
        for n in nodes:
            acc = self.M.H(acc + self.node(n, enc))
        return acc.hex()


def revert(M, n, r):
    n = list(n)
    if "ctx" in r:
        n[3] = r["ctx"]
    if "par" in r:
        n[4] = r["par"]
    if "usr" in r and len(n) >= 9:
        n[6] = r["usr"]
    if len(n) == 10:                                  # whole-row node: the serialized row carries the same columns
        w = json.loads(n[9])
        for col, f in (("context_id_bin", "ctx"), ("context_parent_id_bin", "par"), ("context_user_id_bin", "usr")):
            if f in r:
                w["row"][col] = None if r[f] is None else {"hex": r[f].hex()}
        n[9] = M._canon(w)
    return tuple(n)


def without_late(nodes, k):
    """Every way to drop k rows as late arrivals: the ks highest state ids and the k-ks highest event ids."""
    st = sorted((n for n in nodes if n[1].startswith("s:")), key=lambda n: int(n[1][2:]))
    ev = sorted((n for n in nodes if n[1].startswith("e:")), key=lambda n: int(n[1][2:]))
    for ks in range(k + 1):
        ke = k - ks
        if ks > len(st) or ke > len(ev):
            continue
        drop = {id(n) for n in st[len(st) - ks:]} | {id(n) for n in ev[len(ev) - ke:]}
        yield ks, [n for n in nodes if id(n) not in drop]


def reconstruct(hs, M, post, root, rev):
    """Return (accepted_rows | None, how). Reverted candidates first, then the rows as they stand."""
    touched = any(n[1] in rev for n in post)
    bases = []
    if touched:
        bases.append(("reverted", [revert(M, n, rev[n[1]]) if n[1] in rev else n for n in post]))
    bases.append(("as_is", post))
    missing = False
    for label, base in bases:
        k = len(base) - root["n"]
        if k < 0:
            missing = True
            continue
        for ks, cand in without_late(base, k):
            if hs.fold(cand, "v1") == root["acc"]:
                return cand, {"base": label, "late_rows_removed": k, "late_states": ks, "late_events": k - ks}
    return None, {"base": None, "rows_missing": missing}


def verdict(acc_ok, n_post, n_root):
    v = (not acc_ok) or n_post != n_root
    return {"violation": v, "delta_n": n_post - n_root} if v else {"violation": False}


def classify(v):
    if not v or not v["violation"]:
        return "not_flagged"
    return "ambiguous" if (v["delta_n"] is not None and v["delta_n"] > 0) else "attributable"


def run_one(run_id, src, scratch, row_offline):
    cfg = VA.RUNS[run_id]
    db, chain, _info = src.checked(run_id)
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    M = VA.load_monitor(cfg["scheme"], scratch)
    WR = sys.modules.get("monitor_wholerow") if cfg["scheme"] == "wholerow" else None
    hs = Hasher(M, WR)
    W = dict(M.GRAN)
    roots = VA.anchored_roots(VA.chain_lines(chain), t0, tsnap)
    encs = {a["encoding"] for a in roots.values()}
    assert encs == {"v1"}, encs
    nodes = M.load(db, since=(int(t0 // 3600) - 1) * 3600.0)
    by_seg = {g: collections.defaultdict(list) for g in W}
    for n in nodes:
        for g, w in W.items():
            by_seg[g][str(int(n[0] // w))].append(n)
    trials = [t for t in res["trials"] if not (t.get("err") or t.get("error"))]
    rev, edited_by = reverts_for(trials)

    seg = {}
    status = collections.Counter()
    for (g, s), root in roots.items():
        w = W[g]
        if not (t0 - w <= int(s) * w <= t1 + w):
            continue
        post = by_seg[g].get(s, [])
        v1 = verdict(hs.fold(post, "v1") == root["acc"], len(post), root["n"])
        rec = {"v1": v1, "n_post": len(post), "n_sealed": root["n"]}
        if g in GRANS:
            cand, how = reconstruct(hs, M, post, root, rev)
            rec["reconstruction"] = how
            if cand is not None:
                v2_sealed, v2_post = hs.fold(cand, "v2"), hs.fold(post, "v2")
                rec["v2"] = verdict(v2_sealed == v2_post, len(post), root["n"])
                rec["v2_basis"] = "recomputed"
                if run_id in row_offline and g == "second":
                    proj = lambda xs: [x[:6] for x in xs]          # noqa: E731
                    for enc in ("v1", "v2"):
                        a = hs.fold(proj(cand), enc) if enc == "v2" else hs.fold(proj(cand), "v1")
                        b = hs.fold(proj(post), enc)
                        rec["row_offline_" + enc] = verdict(a == b, len(post), root["n"])
                status["%s:%s" % (g, how["base"])] += 1
            else:
                # Not reconstructable (rows the snapshot no longer holds). The count is outside the node hash, and a v1
                # mismatch implies distinct field tuples, hence a v2 mismatch: the verdict carries over unchanged.
                rec["v2"] = dict(v1)
                rec["v2_basis"] = "carried_over_count_or_refinement" if v1["violation"] else "unresolved"
                if run_id in row_offline and g == "second":
                    rec["row_offline_v1"] = rec["row_offline_v2"] = (dict(v1) if v1.get("delta_n") else None)
                status["%s:not_reconstructed%s" % (g, "_rows_missing" if how.get("rows_missing") else "")] += 1
        seg[(g, s)] = rec

    # ---- per trial
    per_arm, discord, collisions, exposed = {}, [], [], []
    for t in trials:
        a = t.get("arm")
        d = per_arm.setdefault(a, {"n": 0, **{f"{e}_{c}": 0 for e in ("v1", "v2") for c in ("flagged", "attributable", "ambiguous")},
                                   "minute_v1_flagged": 0, "minute_v2_flagged": 0, "v2_basis": collections.Counter()})
        d["n"] += 1
        sg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
        r = seg.get(("second", str(sg))) if sg is not None else None
        for e in ("v1", "v2"):
            c = classify(r[e] if r else None)
            if c != "not_flagged":
                d[f"{e}_flagged"] += 1
                d[f"{e}_{c}"] += 1
        d["v2_basis"][r["v2_basis"] if r else "no_anchored_segment"] += 1
        if r and classify(r["v1"]) != classify(r["v2"]):
            discord.append({"arm": a, "trial": t.get("trial"), "segment": sg, "v1": r["v1"], "v2": r["v2"]})
        mg = ((t.get("_detection") or {}).get("minute") or {}).get("segment")
        rm = seg.get(("minute", str(mg))) if mg is not None else None
        for e in ("v1", "v2"):
            d[f"minute_{e}_flagged"] += bool(rm and rm[e]["violation"])
    for n in nodes:                                   # collision class: edited rows whose v1 hash did not change
        r = rev.get(n[1])
        if r is None:
            continue
        pre = revert(M, n, r)
        if pre != n and hs.node(pre, "v1") == hs.node(n, "v1"):
            collisions.append({"row": n[1], "edited_by": edited_by[n[1]]})
        fields = [pre[3], pre[4], n[3], n[4]] + ([pre[6], n[6]] if len(n) >= 9 else [])
        if any(f is not None and 0x7C in f for f in fields):
            exposed.append({"row": n[1], "edited_by": edited_by[n[1]]})
    for d in per_arm.values():
        d["v2_basis"] = dict(d["v2_basis"])
        for e in ("v1", "v2"):
            d[f"{e}_attributable_ci"] = cp(d[f"{e}_attributable"], d["n"])

    # ---- benign floor (paper's rule: untouched one-second segments)
    floor_trials = [t for t in trials if t.get("arm") in ("PS", "PSR")] if "homeprov_detection_second" in res else trials
    touched = VA.touched_segments(floor_trials, VA.ro_connect(db), W)["second"]
    untouched = [s for (g, s) in seg if g == "second" and s not in touched]
    floor = {e: [sum(1 for s in untouched if seg[("second", s)][e]["violation"]), len(untouched)] for e in ("v1", "v2")}
    floor_basis = dict(collections.Counter(seg[("second", s)]["v2_basis"] for s in untouched))

    # ---- T5: Row scheme offline
    row_off = None
    if run_id in row_offline:
        row_off = {}
        for a in sorted({t.get("arm") for t in trials}):
            if a in ("W1", "W2", "W2b", "W3"):
                continue
            ts_ = [t for t in trials if t.get("arm") == a]
            out = {"n": len(ts_)}
            for e in ("v1", "v2"):
                cnt = collections.Counter()
                for t in ts_:
                    sg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
                    r = seg.get(("second", str(sg))) if sg is not None else None
                    v = r.get("row_offline_" + e) if r else None
                    cnt["underivable" if (r is not None and ("row_offline_" + e) in r and v is None and r["v1"]["violation"]) else classify(v)] += 1
                fl = cnt["attributable"] + cnt["ambiguous"]
                out[e] = {"flagged": fl, "attributable": cnt["attributable"], "ambiguous": cnt["ambiguous"],
                          "underivable": cnt["underivable"], "flagged_ci": cp(fl, len(ts_)),
                          "attributable_ci": cp(cnt["attributable"], len(ts_))}
            row_off[a] = out
        fl = {e: [sum(1 for s in untouched if (seg[("second", s)].get("row_offline_" + e) or {}).get("violation")),
                  sum(1 for s in untouched if seg[("second", s)].get("row_offline_" + e) is not None or not seg[("second", s)]["v1"]["violation"])]
              for e in ("v1", "v2")}
        row_off["benign_floor_second"] = fl

    hours = [(g, s) for (g, s) in seg if g == "hour"]
    return {"run": run_id, "scheme": cfg["scheme"], "chain_encoding": sorted(encs), "window": [t0, t1, tsnap],
            "segments_in_window": dict(collections.Counter(g for (g, _s) in seg)),
            "reconstruction_status": dict(status),
            "hour_segments_not_reconstructed": len(hours),
            "per_arm": per_arm, "trial_verdict_changes_v1_to_v2": discord,
            "edited_rows": len(rev), "edited_rows_in_v1_collision_class": collisions,
            "edited_rows_with_0x7C_in_a_context_field": exposed,
            "benign_floor_second": floor, "floor_segments_v2_basis": floor_basis,
            "row_scheme_offline": row_off}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None, help="full verifier snapshot set")
    ap.add_argument("--extracts", default=None, help="per-run window extracts (default: reproduce/snapshots if present)")
    ap.add_argument("--out", default=os.path.join(OUT, "r6_reverify_v2.json"))
    ap.add_argument("--runs", default=",".join(VA.RUNS))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    src = VA.default_inputs(a.snapshots, a.extracts)
    print(f"inputs: {src.mode} in {src.base}", flush=True)
    rows, t_start = {}, time.time()
    with tempfile.TemporaryDirectory() as scratch:
        for rid in [r for r in a.runs.split(",") if r]:
            print("re-verifying", rid, flush=True)
            rows[rid] = run_one(rid, src, scratch, ROW_OFFLINE)
            r = rows[rid]
            print("  ", json.dumps({k: {kk: vv for kk, vv in v.items() if kk in ("n", "v1_flagged", "v1_attributable", "v2_flagged", "v2_attributable", "v2_basis")} for k, v in r["per_arm"].items()}),
                  "floor", r["benign_floor_second"], "changes", len(r["trial_verdict_changes_v1_to_v2"]),
                  "collisions", len(r["edited_rows_in_v1_collision_class"]), r["reconstruction_status"], flush=True)
    ref = json.load(open(os.path.join(REPO, "reproduce", "verify_all_report.json")))["runs"]
    v1_matches_verify_all = {}
    for rid, r in rows.items():
        q = ref.get(rid)
        if not q:
            continue
        ok = r["benign_floor_second"]["v1"] == q["benign_floor_second"]
        for arm, x in q["arms"].items():
            y = r["per_arm"][arm]
            ok &= (y["n"], y["v1_flagged"], y["v1_attributable"], y["v1_ambiguous"]) == (x["n"], x["flagged"], x["attributable"], x["ambiguous"])
        v1_matches_verify_all[rid] = ok
    res = {"item": "R6/T7+T5: real-deployment runs re-verified with the typed node encoding; Row scheme offline on the swaps",
           "inputs_mode": src.mode,
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": VA.sha256_file(os.path.abspath(__file__)),
           "monitor_sha256": VA.sha256_file(os.path.join(REPO, "monitor", "monitor.py")),
           "v1_recount_matches_verify_all_report": v1_matches_verify_all,
           "not_covered": {"e_c_write_time": "unauthenticated run; verifier snapshot not in the snapshot set",
                           "e_d_other_principal_real": "unauthenticated run; verifier snapshot not in the snapshot set"},
           "runs": rows, "seconds": round(time.time() - t_start, 1)}
    with open(a.out, "x") as fh:
        json.dump(res, fh, indent=1, default=str)
    print("v1 recount matches verify_all:", v1_matches_verify_all)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
