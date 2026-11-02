"""R13 (round 13): the subset test for violated segments that gained rows after sealing.

Today a violated one-second segment whose row count rose after its seal (delta_n > 0) is "ambiguous" and counted as not
detected (verify_all.py run_one), so an adversary who inserts rows into the edited second makes its edit ambiguous. The
subset test asks whether the sealed rows are still there, unchanged: a segment root is a hash chain over the node hashes of
the segment's rows in time order, ties broken by row key, plus the row count (monitor.py commit()). Removing rows keeps
the order of the rest, so when a segment now holds N + k rows and N were anchored, the sealed rows are intact iff some
N-row subsequence of the current rows reproduces the anchored chain. If one does, only rows were added (late rows or an
insertion), and the complement names them; if none does, a sealed row was edited or deleted, which is attributable even
though rows were added.

The search is exact: a depth-first enumeration over the time-ordered rows of every N-row subsequence (C(N+k, k)
candidates), capped at k <= 8 and at a per-segment candidate budget; a segment beyond either is reported as such. Before
it, a polynomial "late-row hypothesis" check tries the k + 1 candidates that drop the j newest state rows and the k - j
newest event rows by primary key (a row committed after the seal carries a larger id than every row the seal saw); a match
there is also an exact witness that the sealed rows are intact, and it is the only check run when the exhaustive search is
beyond budget.

Part A re-scores, with the shipped monitor's load() and node hashing and verify_all's loaders, every trial that the late-row
test leaves ambiguous and every benign-floor failure of the runs verify_all.py covers, plus the round-12 runs E3 (e3_g0_clo,
e3_g2_clo) and E1 (e1_psr_clo) from their saved recorder copies and chains (vouched for by the sha256 recorded in
exp/out/e3_grace_sealing.json and exp/out/e1_psr_clo_two_host.json).

Part B is an offline insertion experiment on the closure-scheme runs. In a copy of each saved recorder, synthetic state
rows (copies of a neighbouring state row with a fresh state_id and a timestamp drawn inside the target second) are inserted
  B1  into the one-second segment of every trial the existing rule attributes: one row; then the number of rows that makes
      the segment's count exceed the anchored count (1 - delta_n, the adversary's cheapest insertion); then enough rows to
      reach k = 8;
  B2  into every untouched anchored one-second segment whose root reproduces (no edit): one row; then k = 2..8 rows.
For each, the existing rule's verdict (attributable iff delta_n <= 0) and the subset test's verdict are recorded.

    python3 exp/sp2027/r13_subset_test.py [--snapshots DIR | --extracts DIR] [--exp DIR] [--scratch DIR] [--out FILE]

Writes exp/out/r13_subset_test.json and never overwrites. Nothing is written to a snapshot; the copies live in a temporary
directory.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import itertools
import json
import math
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import verify_all as VA  # noqa: E402
from rig import stats  # noqa: E402
import chainverify  # noqa: E402  (imported by verify_all from testbed/anchord)

CAP_K = 8
BUDGET = 2_000_000          # exhaustive candidates C(N+k, k) per segment
SEED = 20261013
DEFAULT_EXP = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-exp")

# Round-12 runs that verify_all.py does not cover. Their inputs are vouched for by the sha256 the round-12 result files
# recorded when those runs were scored.
def extra_runs(exp_root):
    g = json.load(open(os.path.join(OUT, "e3_grace_sealing.json")))
    e3 = {r["tag"]: r["inputs"] for r in g["runs"]}
    e1 = json.load(open(os.path.join(OUT, "e1_psr_clo_two_host.json")))["inputs"]
    out = {}
    for tag in ("e3_g0_clo", "e3_g2_clo"):
        out[tag] = dict(scheme="closure", db=os.path.join(exp_root, "e3", tag, "ec_verify", "recorder.db"),
                        chain=os.path.join(exp_root, "e3", tag, "chain.jsonl"),
                        result=tag + "_other_principal_real.json", arms=("PU", "PI"),
                        vouch={"db": e3[tag]["recorder_db_sha256"], "chain": e3[tag]["chain_sha256"],
                               "by": "exp/out/e3_grace_sealing.json runs[].inputs"})
    out["e1_psr_clo"] = dict(scheme="closure", db=os.path.join(exp_root, "e1", "e1_psr_clo", "ps_verify", "recorder.db"),
                             chain=os.path.join(exp_root, "e1", "e1_psr_clo", "chain.jsonl"),
                             result="e1_psr_clo_detection.json", arms=("PSR",),
                             vouch={"db": e1["recorder_snapshot_sha256"], "chain": e1["chain"]["sha256_uncompressed"],
                                    "by": "exp/out/e1_psr_clo_two_host.json inputs"})
    return out


def rel(p):
    return os.path.relpath(p, os.path.dirname(REPO))


def cp(k, n):
    if n == 0:
        return None
    r = stats.clopper_pearson(k, n)
    return [round(r["ci_lo"], 3), round(r["ci_hi"], 3)]


# ----------------------------------------------------------------------------------------------------------------------
# Node hashing, reused from the shipped monitor (monitor.py commit(); monitor_wholerow.py for the whole-row baseline).

def node_hasher(M, scheme, enc):
    if scheme == "wholerow":
        WR = sys.modules["monitor_wholerow"]
        return lambda n: WR.node_hash_wholerow(n, enc)

    def h(n):
        ts, key, content, ctx, par, label = n[:6]
        return (M.node_hash_closure(key, content, ctx, par, label, n[6], n[7], n[8], enc) if len(n) == 9
                else M.node_hash(key, content, ctx, par, label, enc))
    return h


def chain_acc(M, hs):
    acc = M.ZERO
    for h in hs:
        acc = M.H(acc + h)
    return acc


# ----------------------------------------------------------------------------------------------------------------------
# The subset test.

def exhaustive(H, ZERO, hs, n_anch, target):
    """Every n_anch-row subsequence of hs whose chain equals target. Returns (matches, leaves, hashes)."""
    m = len(hs)
    k = m - n_anch
    matches, skipped = [], []
    cnt = [0, 0]  # leaves, hashes

    def rec(i, acc, s):
        if s == k:                                   # every remaining row is kept
            a = acc
            for j in range(i, m):
                a = H(a + hs[j])
            cnt[0] += 1
            cnt[1] += m - i
            if a == target:
                matches.append(tuple(skipped))
            return
        if i - s == n_anch:                          # every remaining row is dropped
            cnt[0] += 1
            if acc == target:
                matches.append(tuple(skipped) + tuple(range(i, m)))
            return
        skipped.append(i)
        rec(i + 1, acc, s + 1)
        skipped.pop()
        cnt[1] += 1
        rec(i + 1, H(acc + hs[i]), s)

    rec(0, ZERO, 0)
    return matches, cnt[0], cnt[1]


def late_row_hypothesis(H, ZERO, hs, keys, n_anch, target):
    """The k + 1 candidates that drop the j newest state rows and the k - j newest event rows (largest primary keys).
    Returns the dropped indices of the first candidate that reproduces target, or None, and the candidates tried."""
    k = len(hs) - n_anch
    by_t = {"s": [], "e": []}
    for i, key in enumerate(keys):
        t, _, num = key.partition(":")
        by_t[t].append((int(num), i))
    for t in by_t:
        by_t[t].sort(reverse=True)
    tried = 0
    for j in range(k + 1):
        if j > len(by_t["s"]) or k - j > len(by_t["e"]):
            continue
        drop = {i for _, i in by_t["s"][:j]} | {i for _, i in by_t["e"][:k - j]}
        tried += 1
        if chain_acc_fn(H, ZERO, [h for i, h in enumerate(hs) if i not in drop]) == target:
            return sorted(drop), tried
    return None, tried


def chain_acc_fn(H, ZERO, hs):
    acc = ZERO
    for h in hs:
        acc = H(acc + h)
    return acc


def subset_test(M, rows, hasher, anchored, budget=BUDGET, cap=CAP_K):
    """rows: the segment's current nodes in monitor order; anchored: {'acc', 'n'}."""
    tick = time.perf_counter()
    hs = [hasher(n) for n in rows]
    keys = [n[1] for n in rows]
    n_anch, m = anchored["n"], len(rows)
    k = m - n_anch
    res = {"rows_now": m, "rows_anchored": n_anch, "k": k}
    if k <= 0:
        res["verdict"] = "not_applicable"
        return res
    res["candidates"] = math.comb(m, k)
    if k > cap:
        res["verdict"] = "beyond_cap"
        return res
    target = bytes.fromhex(anchored["acc"])
    drop, tried = late_row_hypothesis(M.H, M.ZERO, hs, keys, n_anch, target)
    res["late_row_hypothesis"] = {"candidates_tried": tried, "reproduces": drop is not None}
    if res["candidates"] <= budget:
        matches, leaves, hashes = exhaustive(M.H, M.ZERO, hs, n_anch, target)
        assert leaves == res["candidates"], (leaves, res["candidates"])
        res.update(exhaustive=True, leaves=leaves, hashes=hashes, matching_subsets=len(matches))
        if drop is not None:
            assert matches and sorted(matches[0]) == drop, "late-row witness not found by the exhaustive search"
        res["verdict"] = "sealed_rows_intact" if matches else "sealed_row_changed"
        added = sorted(matches[0]) if matches else None
    else:
        res["exhaustive"] = False
        if drop is not None:
            res["verdict"] = "sealed_rows_intact"
            added = drop
        else:
            res["verdict"] = "beyond_budget"
            added = None
    if added is not None:
        kept_ids = collections.defaultdict(list)
        for i, key in enumerate(keys):
            if i not in added:
                t, _, num = key.partition(":")
                kept_ids[t].append(int(num))
        res["added_rows"] = []
        for i in added:
            t, _, num = keys[i].partition(":")
            res["added_rows"].append({"key": keys[i], "ts": round(rows[i][0], 6),
                                      "id_above_every_sealed_row_of_its_table": all(int(num) > x for x in kept_ids[t])})
    res["seconds"] = round(time.perf_counter() - tick, 4)
    return res


def self_test():
    """Synthetic check of the search: random node hashes, a random anchored subsequence, then one edit."""
    import hashlib as _h
    H = lambda b: _h.sha256(b).digest()  # noqa: E731
    ZERO = b"\x00" * 32
    rng = random.Random(7)
    ok = True
    for m, k in ((5, 1), (9, 3), (16, 8), (12, 0 + 4)):
        hs = [rng.randbytes(32) for _ in range(m)]
        drop = set(rng.sample(range(m), k))
        target = chain_acc_fn(H, ZERO, [h for i, h in enumerate(hs) if i not in drop])
        matches, leaves, _ = exhaustive(H, ZERO, hs, m - k, target)
        ok &= matches == [tuple(sorted(drop))] and leaves == math.comb(m, k)
        kept = [i for i in range(m) if i not in drop]
        hs2 = list(hs)
        hs2[kept[0]] = rng.randbytes(32)               # edit a sealed row
        ok &= exhaustive(H, ZERO, hs2, m - k, target)[0] == []
    return ok


# ----------------------------------------------------------------------------------------------------------------------
# Inputs.

def resolve(rid, src, extras):
    """(cfg, db, chain, inputs-info) for a verify_all run or a round-12 run."""
    if rid in VA.RUNS:
        cfg = VA.RUNS[rid]
        db, chain, info = src.checked(rid)
        info["vouched_by"] = src.mode + " checksum list" if all(v["listed"] for v in info.values()) else \
            "snapshot-set SHA256SUMS where listed (verify_all.Inputs.checked)"
        return cfg, db, chain, info
    cfg = extras[rid]
    info = {}
    for label, p, want in (("snapshot_db", cfg["db"], cfg["vouch"]["db"]), ("chain", cfg["chain"], cfg["vouch"]["chain"])):
        got = VA.sha256_file(p)
        if got != want:
            raise SystemExit(f"{rid}: {p} sha256 {got} differs from {want} ({cfg['vouch']['by']})")
        info[label] = {"path": rel(p), "sha256": got, "matches_recorded": True}
    info["vouched_by"] = cfg["vouch"]["by"]
    return cfg, cfg["db"], cfg["chain"], info


def segment_rows(nodes, width=1.0):
    by = collections.defaultdict(list)
    for n in nodes:
        by[str(int(n[0] // width))].append(n)
    return by


# ----------------------------------------------------------------------------------------------------------------------
# Part A.

def wholerow_last_reported_check(M, rows, enc, anchored, max_rows=16):
    """Whole-row baseline only. The recorder rewrites last_reported_ts in place after sealing (NULL -> a time; see
    exp/out/e_ps_whr_floor_preimage.json), and the whole-row scheme commits that column, so a "sealed row changed"
    verdict there need not come from the edit. This tries, for each late-row-hypothesis drop (the j newest state rows
    and k - j newest event rows), every subset of the kept state rows that now carry a last_reported_ts, with that column
    restored to NULL; a match shows the sealed rows intact up to that in-place update, and names the added rows."""
    WR = sys.modules["monitor_wholerow"]
    target = bytes.fromhex(anchored["acc"])
    k = len(rows) - anchored["n"]
    by_t = {"s": [], "e": []}
    for i, n in enumerate(rows):
        by_t[n[1][0]].append((int(n[1][2:]), i))
    for t in by_t:
        by_t[t].sort(reverse=True)
    tried, skipped = 0, 0
    for j in range(max(k, 0) + 1):
        if j > len(by_t["s"]) or k - j > len(by_t["e"]):
            continue
        drop = {i for _, i in by_t["s"][:j]} | {i for _, i in by_t["e"][:k - j]}
        kept = [n for i, n in enumerate(rows) if i not in drop]
        orig = [WR.node_hash_wholerow(n, enc) for n in kept]
        alt, idx = {}, []
        for pos, n in enumerate(kept):
            if n[1].startswith("s:"):
                w = json.loads(n[9])
                if w["row"].get("last_reported_ts") is not None:
                    w["row"]["last_reported_ts"] = None
                    alt[pos] = WR.node_hash_wholerow(n[:9] + (M._canon(w),), enc)
                    idx.append(pos)
        if len(idx) > max_rows:
            skipped += 1
            continue
        for mask in range(1 << len(idx)):
            hs = list(orig)
            for b, pos in enumerate(idx):
                if mask >> b & 1:
                    hs[pos] = alt[pos]
            tried += 1
            if chain_acc_fn(M.H, M.ZERO, hs) == target:
                return {"reproduced": True, "added_rows": sorted(rows[i][1] for i in drop),
                        "last_reported_ts_restored_to_null": sorted(kept[idx[b]][1] for b in range(len(idx)) if mask >> b & 1),
                        "candidates_tried": tried}
    return {"reproduced": False, "candidates_tried": tried, "drops_skipped_too_many_rows": skipped}


def part_a(rid, cfg, db, chain, info, scratch):
    tick = time.time()
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    M = VA.load_monitor(cfg["scheme"], scratch)
    W = dict(M.GRAN)
    cc = chainverify.verify_chain(chainverify.read(chain))
    if not cc["ok"]:
        raise SystemExit(f"{rid}: anchor chain fails its link check")
    roots = VA.anchored_roots(VA.chain_lines(chain), t0, tsnap)
    encs = sorted({a["encoding"] for a in roots.values()})
    assert len(encs) == 1, encs
    enc = encs[0]
    since = (int(t0 // 3600) - 1) * 3600.0
    nodes = M.load(db, since=since)
    phi = M.commit(nodes, encoding=enc)
    verd = VA.verify_window(phi, roots, W, t0, t1)
    by = segment_rows(nodes)
    by_min = segment_rows(nodes, 60.0)
    hasher = node_hasher(M, cfg["scheme"], enc)

    def test(seg, g="second"):
        rows = (by if g == "second" else by_min).get(seg, [])
        got = phi[g].get(seg)
        assert got is not None and chain_acc(M, [hasher(n) for n in rows]).hex() == got["acc"] and len(rows) == got["n"], \
            f"{rid} {g} {seg}: re-chained rows do not give commit()'s root"
        st = subset_test(M, rows, hasher, roots[(g, seg)])
        if cfg["scheme"] == "wholerow" and st["verdict"] in ("sealed_row_changed", "beyond_budget"):
            st["wholerow_last_reported_check"] = wholerow_last_reported_check(M, rows, enc, roots[(g, seg)])
        return st

    def minute_view(t):
        """The trial's one-minute segment: existing rule, and the subset test when it gained rows."""
        mseg = ((t.get("_detection") or {}).get("minute") or {}).get("segment")
        vm = verd.get(("minute", str(mseg))) if mseg is not None else None
        if vm is None:
            return {"segment": mseg, "anchored": False}
        o = {"segment": str(mseg), "violation": vm["violation"], "delta_n": vm.get("delta_n")}
        if vm["violation"]:
            o["existing_rule"] = "ambiguous" if (vm["delta_n"] is not None and vm["delta_n"] > 0) else "attributable"
            if o["existing_rule"] == "ambiguous":
                st = test(str(mseg), "minute")
                o["subset_test"] = {k: st.get(k) for k in ("rows_now", "rows_anchored", "k", "candidates", "exhaustive",
                                                         "verdict", "late_row_hypothesis")}
        return o

    trials = [t for t in res["trials"] if not (t.get("err") or t.get("error"))]
    arms, ambiguous = {}, []
    for t in trials:
        a = arms.setdefault(t.get("arm"), collections.Counter(n=0))
        a["n"] += 1
        seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
        v = verd.get(("second", str(seg))) if seg is not None else None
        if not (v and v["violation"]):
            continue
        a["flagged"] += 1
        if v["delta_n"] is not None and v["delta_n"] > 0:
            a["ambiguous_existing"] += 1
            st = test(str(seg))
            a["subset_" + st["verdict"]] += 1
            edited = {str(x) for x in (t.get("swapped_state_ids") or []) + (t.get("laundered_state_ids") or [])}
            for kk in ("row_before", "judged_row", "forged_row"):
                if isinstance(t.get(kk), dict) and t[kk].get("state_id") is not None:
                    edited.add(str(t[kk]["state_id"]))
            ambiguous.append({"arm": t.get("arm"), "room": t.get("room"), "trial": t.get("trial"), "segment": str(seg),
                              "delta_n": v["delta_n"], "subset_test": st,
                              "trial_rows_among_added_rows": sorted(x["key"] for x in st.get("added_rows") or []
                                                                    if x["key"][2:] in edited and x["key"].startswith("s:")),
                              "trial_rows_among_added_rows_wholerow_check":
                                  sorted(x for x in (st.get("wholerow_last_reported_check") or {}).get("added_rows") or []
                                         if x[2:] in edited and x.startswith("s:")),
                              "minute_segment": minute_view(t)})
        else:
            a["attributable_existing"] += 1
    for a in arms.values():
        a["attributable_with_subset_test"] = a["attributable_existing"] + a["subset_sealed_row_changed"]
    floor_trials = [t for t in trials if t.get("arm") in ("PS", "PSR")] if "homeprov_detection_second" in res else trials
    touched = VA.touched_segments(floor_trials, VA.ro_connect(db), W)["second"]
    untouched = sorted(s for (g, s) in verd if g == "second" and s not in touched)
    failures = []
    for s in untouched:
        v = verd[("second", s)]
        if not v["violation"]:
            continue
        d = v["delta_n"]
        f = {"segment": s, "delta_n": d}
        if d is None:
            f["kind"] = "segment_vanished"
        elif d < 0:
            f["kind"] = "rows_removed"
        elif d == 0:
            f["kind"] = "same_count_root_differs"
        else:
            f["kind"] = "rows_added"
            f["subset_test"] = test(s)
        failures.append(f)
    late = [f for f in failures if f["kind"] == "rows_added"]
    floor = {"untouched": len(untouched), "failing": len(failures),
             "failing_by_kind": dict(collections.Counter(f["kind"] for f in failures)),
             "late_row_failures": len(late),
             "late_row_failures_by_subset_verdict": dict(collections.Counter(f["subset_test"]["verdict"] for f in late)),
             "attributable_failures_existing_rule": sum(1 for f in failures if f["kind"] != "rows_added"),
             "attributable_failures_with_subset_test": sum(1 for f in failures if f["kind"] != "rows_added"
                                                           or f["subset_test"]["verdict"] == "sealed_row_changed"),
             "late_row_failure_detail": late,
             "other_failures": [f for f in failures if f["kind"] != "rows_added"] if len(failures) - len(late) <= 20
             else "%d failures, not listed" % (len(failures) - len(late))}
    return {"scheme": cfg["scheme"], "node_hash_encoding": enc, "inputs": info, "window": [t0, t1, tsnap],
            "anchor_chain": {k: cc[k] for k in ("records", "link")},
            "anchored_second_segments_verified": sum(1 for (g, _s) in verd if g == "second"),
            "arms": {k: dict(v) for k, v in arms.items()}, "ambiguous_trials": ambiguous, "benign_floor_second": floor,
            "seconds": round(time.time() - tick, 2)}, (M, nodes, phi, verd, roots, trials, touched, enc, since, by, t0, t1)


# ----------------------------------------------------------------------------------------------------------------------
# Part B.

def inject(src_db, dst_db, plan, old_keys=False):
    """Copy src_db to dst_db and insert, for each (template_state_id, ts), one state row copied from the template with a
    fresh state_id and its time columns moved to ts (as r10_coarse_roots.py does). The fresh state_id is the next one
    above the table's largest (what a late commit gets), or, with old_keys, the next one below the table's smallest
    (older than every row in the table, which no late commit gets). Returns the new state ids."""
    shutil.copyfile(src_db, dst_db)
    con = sqlite3.connect(dst_db)
    con.execute("PRAGMA journal_mode=DELETE")
    cols = [r[1] for r in con.execute("PRAGMA table_info(states)")]
    if old_keys:
        low = con.execute("SELECT MIN(state_id) FROM states").fetchone()[0]
        free = itertools.count(low - 1, -1)
    else:
        top = con.execute("SELECT MAX(state_id) FROM states").fetchone()[0]
        free = itertools.count(top + 1)
    new = []
    for tid, ts in plan:
        row = dict(zip(cols, con.execute("SELECT %s FROM states WHERE state_id=?" % ",".join(cols), (tid,)).fetchone()))
        nxt = next(free)
        row["state_id"] = nxt
        for c in ("last_updated_ts", "last_changed_ts", "last_reported_ts"):
            if c in row and row[c] is not None:
                row[c] = ts
        con.execute("INSERT INTO states (%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))),
                    [row[c] for c in cols])
        new.append(nxt)
    con.commit()
    con.close()
    return new


def plan_rows(seg, r, by, state_nodes, rng):
    """r synthetic rows for second `seg`: a timestamp drawn inside the second and the nearest state row as template."""
    s = int(seg)
    local = [n for n in by.get(seg, []) if n[1].startswith("s:")]
    out = []
    for _ in range(r):
        ts = s + rng.uniform(0.001, 0.999)
        assert int(ts // 1) == s
        pool = local or state_nodes
        tpl = min(pool, key=lambda n: (abs(n[0] - ts), n[1]))
        out.append((int(tpl[1][2:]), ts))
    return out


def part_b(rid, cfg, db, ctx, scratch):
    M, nodes, phi, verd, roots, trials, touched, enc, since, by, t0, t1 = ctx
    tick = time.time()
    hasher = node_hasher(M, cfg["scheme"], enc)
    rng = random.Random(int(hashlib.sha256(("%s:%d" % (rid, SEED)).encode()).hexdigest()[:12], 16))
    state_nodes = [n for n in nodes if n[1].startswith("s:")]
    # B1 targets: trials the existing rule attributes, grouped by their one-second segment.
    tseg = collections.defaultdict(list)
    for t in trials:
        seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
        v = verd.get(("second", str(seg))) if seg is not None else None
        if v and v["violation"] and (v["delta_n"] is None or v["delta_n"] <= 0):
            tseg[str(seg)].append("%s/%s/%s" % (t.get("arm"), t.get("room"), t.get("trial")))
    delta0 = {s: (verd[("second", s)]["delta_n"] if verd[("second", s)]["delta_n"] is not None
                  else -roots[("second", s)]["n"]) for s in tseg}
    # B2 targets: untouched anchored one-second segments whose root reproduces.
    ok_untouched = sorted(s for (g, s) in verd if g == "second" and s not in touched and not verd[("second", s)]["violation"])
    variants = {
        "one_row": ({s: 1 for s in tseg}, {s: 1 for s in ok_untouched}),
        "count_above_anchored": ({s: max(1, 1 - delta0[s]) for s in tseg},
                                 {s: 2 + i % 7 for i, s in enumerate(ok_untouched)}),
        "k_8": ({s: CAP_K - delta0[s] for s in tseg}, {}),
        "count_above_anchored_old_keys": ({s: max(1, 1 - delta0[s]) for s in tseg}, {s: 1 for s in ok_untouched}),
    }
    out = {"b1_trials": sum(len(v) for v in tseg.values()), "b1_segments": len(tseg),
           "b1_delta_n_before": dict(collections.Counter(delta0.values())), "b2_segments": len(ok_untouched)}
    for vname, (r1, r2) in variants.items():
        vt = time.time()
        plan, owner = [], []
        for s, r in list(r1.items()) + list(r2.items()):
            for p in plan_rows(s, r, by, state_nodes, rng):
                plan.append(p)
                owner.append(s)
        copy = os.path.join(scratch, "%s_%s.db" % (rid, vname))
        new_ids = inject(db, copy, plan, old_keys=vname.endswith("_old_keys"))
        nodes2 = M.load(copy, since=since)
        phi2 = M.commit(nodes2, encoding=enc)
        by2 = segment_rows(nodes2)
        verd2 = VA.verify_window(phi2, roots, dict(M.GRAN), t0, t1)
        # every inserted row landed in its target second, and no other anchored second changed its verdict
        new_key = {"s:%d" % i: s for i, s in zip(new_ids, owner)}
        placed = all(any(n[1] == key for n in by2.get(s, [])) for key, s in new_key.items())
        targets = set(r1) | set(r2)
        others_same = all(verd2.get(key) == v for key, v in verd.items() if key[0] == "second" and key[1] not in targets
                          and key in verd2)
        res_v = {"rows_inserted": len(plan), "inserted_state_id_range": [min(new_ids), max(new_ids)] if new_ids else None,
                 "inserted_rows_in_target_seconds": placed,
                 "other_anchored_seconds_unchanged": others_same}
        for label, rmap, trial_map in (("b1", r1, tseg), ("b2", r2, None)):
            if not rmap:
                continue
            seg_out = []
            for s in sorted(rmap):
                v2 = verd2[("second", s)]
                existing = ("not_flagged" if not v2["violation"] else
                            "ambiguous" if (v2["delta_n"] is not None and v2["delta_n"] > 0) else "attributable")
                st = subset_test(M, by2.get(s, []), hasher, roots[("second", s)])
                if existing == "attributable":
                    combined = "attributable"
                elif existing == "ambiguous":
                    combined = {"sealed_row_changed": "attributable", "sealed_rows_intact": "rows_added_only"}.get(
                        st["verdict"], "ambiguous")
                else:
                    combined = "not_flagged"
                seg_out.append({"segment": s, "rows_inserted": rmap[s], "delta_n_after": v2.get("delta_n"),
                                "existing_rule": existing, "subset_verdict": st["verdict"], "combined_rule": combined,
                                "candidates": st.get("candidates"), "exhaustive": st.get("exhaustive"),
                                "late_row_hypothesis_reproduces": (st.get("late_row_hypothesis") or {}).get("reproduces"),
                                "trials": trial_map[s] if trial_map else None, "seconds": st.get("seconds")})
            w = (lambda e: len(e["trials"])) if label == "b1" else (lambda e: 1)
            agg = collections.Counter()
            for e in seg_out:
                agg["n"] += w(e)
                agg["existing_" + e["existing_rule"]] += w(e)
                agg["subset_" + e["subset_verdict"]] += w(e)
                agg["combined_" + e["combined_rule"]] += w(e)
                if e["exhaustive"] is not None:
                    agg["exhaustive_search_" + ("run" if e["exhaustive"] else "beyond_budget")] += w(e)
                if e["late_row_hypothesis_reproduces"] is not None:
                    agg["late_row_hypothesis_" + ("reproduces" if e["late_row_hypothesis_reproduces"] else "fails")] += w(e)
            res_v[label] = {"unit": "trials" if label == "b1" else "segments", **dict(agg),
                            "rows_inserted_histogram": dict(collections.Counter(rmap.values())),
                            "max_candidates": max((e["candidates"] or 0) for e in seg_out),
                            "max_test_seconds": max((e["seconds"] or 0.0) for e in seg_out),
                            "detail": seg_out if label == "b1" else [e for e in seg_out if e["subset_verdict"] != "sealed_rows_intact"]}
        res_v["seconds"] = round(time.time() - vt, 2)
        os.remove(copy)
        out[vname] = res_v
    out["seconds"] = round(time.time() - tick, 2)
    return out


# ----------------------------------------------------------------------------------------------------------------------

def published_checks(rid, a):
    """The existing rule's counts recomputed here against the numbers already on file."""
    if rid in VA.RUNS:
        rep = json.load(open(os.path.join(REPO, "reproduce", "verify_all_report.json")))["runs"][rid]
        ok = rep["benign_floor_second"] == [a["benign_floor_second"]["failing"], a["benign_floor_second"]["untouched"]]
        for arm, r in rep["arms"].items():
            mine = a["arms"].get(arm, {})
            ok &= (mine.get("n") == r["n"] and mine.get("flagged", 0) == r["flagged"]
                   and mine.get("attributable_existing", 0) == r["attributable"]
                   and mine.get("ambiguous_existing", 0) == r["ambiguous"])
        return {"against": "reproduce/verify_all_report.json", "match": bool(ok)}
    if rid.startswith("e3_"):
        r = [x for x in json.load(open(os.path.join(OUT, "e3_grace_sealing.json")))["runs"] if x["tag"] == rid][0]
        ok = [r["benign_floor"]["second"]["k"], r["benign_floor"]["second"]["n"]] == \
             [a["benign_floor_second"]["failing"], a["benign_floor_second"]["untouched"]]
        for arm, x in r["arms"].items():
            mine = a["arms"].get(arm, {})
            ok &= (mine.get("n") == x["n"] and mine.get("flagged", 0) == x["flagged"]
                   and mine.get("attributable_existing", 0) == x["attributable"]
                   and mine.get("ambiguous_existing", 0) == x["ambiguous"])
        return {"against": "exp/out/e3_grace_sealing.json", "match": bool(ok)}
    r = json.load(open(os.path.join(OUT, "e1_psr_clo_two_host.json")))["paper_counting_rule"]
    mine = a["arms"]["PSR"]
    ok = (r["n_trials"] == mine["n"] and r["flagged"] == mine.get("flagged", 0)
          and r["attributable"] == mine.get("attributable_existing", 0) and r["ambiguous"] == mine.get("ambiguous_existing", 0)
          and [r["benign_floor"]["second"]["k"], r["benign_floor"]["second"]["n"]] ==
          [a["benign_floor_second"]["failing"], a["benign_floor_second"]["untouched"]])
    return {"against": "exp/out/e1_psr_clo_two_host.json paper_counting_rule", "match": bool(ok)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None)
    ap.add_argument("--extracts", default=None)
    ap.add_argument("--exp", default=DEFAULT_EXP, help="directory holding the round-12 E3/E1 run folders")
    ap.add_argument("--scratch", default=None)
    ap.add_argument("--runs", default=None)
    ap.add_argument("--out", default=os.path.join(OUT, "r13_subset_test.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    t_all = time.time()
    st_ok = self_test()
    if not st_ok:
        raise SystemExit("self-test of the subset search failed")
    src = VA.Inputs(snapshots=a.snapshots) if a.snapshots else (
        VA.Inputs(extracts=a.extracts) if a.extracts else VA.Inputs(snapshots=VA.DEFAULT_SNAP))
    extras = extra_runs(a.exp)
    run_ids = a.runs.split(",") if a.runs else list(VA.RUNS) + list(extras)
    A, B = {}, {}
    with tempfile.TemporaryDirectory(dir=a.scratch) as scratch:
        for rid in run_ids:
            cfg, db, chain, info = resolve(rid, src, extras)
            A[rid], ctx = part_a(rid, cfg, db, chain, info, scratch)
            A[rid]["consistency"] = published_checks(rid, A[rid])
            print(rid, "A", json.dumps({k: v for k, v in A[rid]["arms"].items()}),
                  json.dumps({k: A[rid]["benign_floor_second"][k] for k in
                              ("untouched", "failing", "late_row_failures", "late_row_failures_by_subset_verdict")}),
                  A[rid]["consistency"], A[rid]["seconds"], "s", flush=True)
            if cfg["scheme"] == "closure":
                B[rid] = part_b(rid, cfg, db, ctx, scratch)
                summ = {v: {lab: {kk: vv for kk, vv in B[rid][v][lab].items() if kk not in ("detail", "unit")}
                                 for lab in ("b1", "b2") if lab in B[rid][v]} for v in ("one_row", "count_above_anchored", "k_8",
                                                                             "count_above_anchored_old_keys")}
                print(rid, "B", json.dumps(summ), B[rid]["seconds"], "s", flush=True)
            del ctx

    # ---- pooled summaries
    amb = [dict(run=r, **t) for r in A for t in A[r]["ambiguous_trials"]]
    late = [dict(run=r, **f) for r in A for f in A[r]["benign_floor_second"]["late_row_failure_detail"]]
    pa = {"ambiguous_trials": len(amb),
          "ambiguous_trials_by_subset_verdict": dict(collections.Counter(t["subset_test"]["verdict"] for t in amb)),
          "ambiguous_trials_now_attributable": sum(1 for t in amb if t["subset_test"]["verdict"] == "sealed_row_changed"),
          "ambiguous_trials_table": [{"run": t["run"], "arm": t["arm"], "room": t["room"], "trial": t["trial"],
                                      "segment": t["segment"], "delta_n": t["delta_n"],
                                      "verdict": t["subset_test"]["verdict"],
                                      "late_row_hypothesis_reproduces": (t["subset_test"].get("late_row_hypothesis") or {}).get("reproduces"),
                                      "candidates": t["subset_test"].get("candidates"),
                                      "trial_rows_among_added_rows": t["trial_rows_among_added_rows"],
                                      "wholerow_last_reported_check_reproduces":
                                          (t["subset_test"].get("wholerow_last_reported_check") or {}).get("reproduced"),
                                      "trial_rows_among_added_rows_wholerow_check": t["trial_rows_among_added_rows_wholerow_check"],
                                      "minute_segment": t["minute_segment"]} for t in amb],
          "late_row_floor_failures": len(late),
          "late_row_floor_failures_by_subset_verdict": dict(collections.Counter(f["subset_test"]["verdict"] for f in late)),
          "late_row_floor_failures_table": [{"run": f["run"], "segment": f["segment"], "delta_n": f["delta_n"],
                                             "verdict": f["subset_test"]["verdict"],
                                             "late_row_hypothesis_reproduces": (f["subset_test"].get("late_row_hypothesis") or {}).get("reproduces"),
                                             "candidates": f["subset_test"].get("candidates"),
                                             "wholerow_last_reported_check_reproduces":
                                                 (f["subset_test"].get("wholerow_last_reported_check") or {}).get("reproduced"),
                                             "added_rows_all_newer_than_sealed_rows":
                                                 (all(x["id_above_every_sealed_row_of_its_table"] for x in f["subset_test"]["added_rows"])
                                                  if f["subset_test"].get("added_rows") else None)} for f in late],
          "closure_and_row_runs": {
              "late_row_floor_failures": sum(1 for f in late if A[f["run"]]["scheme"] != "wholerow"),
              "of_which_sealed_rows_intact": sum(1 for f in late if A[f["run"]]["scheme"] != "wholerow"
                                                 and f["subset_test"]["verdict"] == "sealed_rows_intact")},
          "not_rescored_no_snapshot": {k: json.load(open(os.path.join(OUT, v)))["new_rule_floor"]["second"]["failing"]
                                       for k, v in VA.NOT_RERUN.items()}}
    pb = {}
    for vname in ("one_row", "count_above_anchored", "k_8", "count_above_anchored_old_keys"):
        for label in ("b1", "b2"):
            rs = [B[r][vname][label] for r in B if label in B[r].get(vname, {})]
            if not rs:
                continue
            agg = collections.Counter()
            for x in rs:
                for k2, v2 in x.items():
                    if isinstance(v2, int) and not k2.startswith("max_"):
                        agg[k2] += v2
            n = agg["n"]
            d = dict(agg)
            if label == "b1":
                d["existing_rule_attributable_ci"] = cp(agg["existing_attributable"], n)
                d["subset_test_attributable"] = agg["combined_attributable"]
                d["subset_test_attributable_ci"] = cp(agg["combined_attributable"], n)
            else:
                d["false_attribution_subset_test"] = agg["subset_sealed_row_changed"]
                d["false_attribution_ci"] = cp(agg["subset_sealed_row_changed"], n)
                d["sealed_rows_intact_ci"] = cp(agg["subset_sealed_rows_intact"], n)
            d["max_candidates"] = max(x["max_candidates"] for x in rs)
            d["max_test_seconds"] = max(x["max_test_seconds"] for x in rs)
            pb["%s.%s" % (vname, label)] = d
    sha = VA.sha256_file
    out = {"item": "R13: subset test for violated segments that gained rows after sealing; offline insertion experiment",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "script_sha256": sha(os.path.abspath(__file__)),
           "code_sha256": {"monitor/monitor.py": sha(os.path.join(REPO, "monitor", "monitor.py")),
                           "monitor/monitor_wholerow.py": sha(os.path.join(REPO, "monitor", "monitor_wholerow.py")),
                           "reproduce/verify_all.py": sha(os.path.join(REPO, "reproduce", "verify_all.py")),
                           "exp/rig/stats.py": sha(os.path.join(REPO, "exp", "rig", "stats.py"))},
           "result_files_sha256": {"exp/out/" + f: sha(os.path.join(OUT, f)) for f in
                                   sorted({(VA.RUNS.get(r) or extras[r])["result"] for r in A}
                                          | {"e3_grace_sealing.json", "e1_psr_clo_two_host.json"})},
           "inputs_mode": src.mode, "python": sys.version.split()[0],
           "parameters": {"cap_k": CAP_K, "exhaustive_budget_candidates": BUDGET, "seed": SEED,
                          "granularity": "second (the counting granularity)"},
           "self_test_passed": st_ok,
           "rule": {"existing": "violation with delta_n <= 0 (or segment vanished): attributable; delta_n > 0: ambiguous",
                    "subset_test": "delta_n = k > 0: search every anchored-size subsequence of the segment's current rows "
                                   "(time order, ties by key) for one whose hash chain equals the anchored root; none: a "
                                   "sealed row was edited or deleted (attributable); one: the sealed rows are intact and "
                                   "the complement is the added rows; k > 8 or C(N+k,k) above the budget without a "
                                   "late-row witness: ambiguous",
                    "late_row_hypothesis": "the k+1 candidates dropping the j newest state rows and k-j newest event rows "
                                           "(largest primary keys); a match is an exact witness of intact sealed rows"},
           "part_a": {"pooled": pa, "runs": A},
           "part_b": {"what": "closure-scheme runs; synthetic state rows (copy of the nearest state row, fresh state_id, "
                              "time columns moved to a timestamp drawn uniformly inside the target second) inserted into a "
                              "copy of the saved recorder; B1: one-second segments of trials the existing rule attributes; "
                              "B2: untouched anchored one-second segments whose root reproduces",
                      "variants": {"one_row": "B1 one row; B2 one row",
                                   "count_above_anchored": "B1 1 - delta_n rows (the fewest that make the count exceed "
                                                           "the anchored count); B2 k = 2..8 rows, cycling",
                                   "k_8": "B1 8 - delta_n rows, so the segment holds 8 rows more than anchored",
                                   "count_above_anchored_old_keys": "as count_above_anchored for B1 and one row for B2, "
                                                                    "but each inserted row takes a state_id below the "
                                                                    "table's smallest, older than every sealed row: the "
                                                                    "exact search must find it, the late-row hypothesis "
                                                                    "cannot"},
                      "pooled": pb, "runs": B},
           "runtime_s": round(time.time() - t_all, 1),
           "caveats": [
               "e_d_auth: the verifier's own snapshot is not in the set; the later recorder copy hp_d2/live is used, as "
               "verify_all.py does, so its late-row breakdown is not the run-time one.",
               "e_c_write_time and e_d_other_principal_real have no saved verifier snapshot; their late-row floor "
               "failures are listed from file and not re-scored.",
               "The subset test rests on SHA-256 collision resistance: a reproduced chain is taken to mean the same node "
               "hashes in the same order.",
               "The late-row hypothesis assumes the recorder assigns primary keys in commit order (SQLite rowid max+1); "
               "it is reported beside the exhaustive verdict, which does not assume it.",
               "Part B inserts rows offline into copies; no live adversary inserted rows."]}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({"part_a": {k: v for k, v in pa.items() if not k.endswith("_table")}, "part_b": pb,
                      "runtime_s": out["runtime_s"]}, indent=1))


if __name__ == "__main__":
    main()
