"""E11 scorer (drafts/round13/E11_DESIGN.md, sections 6-7): does the principle carry to openHAB (RQ4)?

Inputs, all written by testbed/e11/run_e11.sh: the run directory (anchor chain, witness heads, the monitor's record-
signing public key, cost log and per-poll row archive, the final consistent snapshot of the persistence database and
the registry files taken outside the hub, the benign-operation log, the copies of monitor.py and the openHAB reader the
run executed) and the per-arm reports in the output directory; optionally the closure result of E11-CLO.

What it computes, per pre-registered outcome:
  O1 closure       the closure measured by E11-CLO, against the predicted field set; the controls; the rendered
                   history's fields (is there any cause / attribution field?); the in-place probe.
  O2 schemes       detection and benign floor under the live closure scheme and, from the per-poll row archive
                   (validated by reproducing the anchored closure roots exactly), under the schema-chosen `rows` scheme
                   and the `wholerow` scheme; single-write checks on copies of the final snapshot (one write to one
                   stored or registry field, changed one-second roots per scheme).
  O3 detection     per instrument trial: the verdict of the second (and minute) holding the edited row.
  O4 floor         attributable violations over untouched sealed seconds; benign late rows; per benign operation the
                   verdicts of the seconds it changed (what needs an operator declaration).
  O5 port          monitor.py lines changed (0), reader size, functions replaced; per-poll cost; hub write failures.

THE VERIFICATION RULE (coverage records, no keylog; the late-row test of the Home Assistant verifier with the per-table
rowid watermark in place of the recorder keys). For a segment k of width w in the window, let c be the first observable
poll whose record covers it (since <= k*w and (k+1)*w <= through), R its first anchored root (if any) with the
watermark W_R of the poll that froze it, and F the rows the final snapshot holds in it. A row's lag is the copy time of
the latest observable poll whose watermark for the row's table is below the row's rowid, minus the row's timestamp (a
row absent from a copy taken more than L after its timestamp was committed more than L late).
  - R exists, commit(F) == R: no violation; if R was frozen after c (k held no row at c), the rows of F with rowid above
    c's watermark arrived after k was first covered and are classified by lag.
  - R exists, commit(F) != R: if removing the rows of F with rowid above W_R reproduces R, those rows are late arrivals
    and are classified by lag; otherwise the segment is ATTRIBUTABLE (a sealed row was removed or changed).
  - no R, F not empty: every row of F arrived after the last poll covering k saw none: classified by lag.
  Classified by lag: ATTRIBUTABLE if any lag exceeds L (30 s), else BENIGN_LATE.
Rowids are reused by SQLite only after the newest row of a table is deleted; the rule then still reports the edit (as a
removal or change instead of a late insertion), so detection is unaffected; the label is reported as computed.

    <home>/miniconda3/bin/python3 exp/stages/e11_score.py --run RUN --tag TAG --outdir exp/out \
        [--closure exp/out/<ctag>_closure.json]
Writes <outdir>/<tag>_score.json; never overwrites.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
LATE_BOUND_S = 30.0
GRANS = (("second", 1), ("minute", 60))
SCHEMES = ("closure", "rows", "wholerow")
ARMS = ("A-BD", "A-RM", "A-CHG")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cp(k, n):
    """Exact (Clopper-Pearson) 95% interval; rig.stats when scipy is present, else bisection on the binomial."""
    if not n:
        return {"k": 0, "n": 0, "prop": None}
    try:
        from rig import stats                                  # noqa: PLC0415
        return stats.clopper_pearson(k, n)
    except Exception:                                          # noqa: BLE001
        import math                                            # noqa: PLC0415

        def cdf(x, p):
            return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(x + 1))

        def solve(f, lo=0.0, hi=1.0):
            for _ in range(80):
                mid = (lo + hi) / 2
                lo, hi = (mid, hi) if f(mid) else (lo, mid)
            return (lo + hi) / 2
        lo = 0.0 if k == 0 else solve(lambda p: 1 - cdf(k - 1, p) < 0.025)
        hi = 1.0 if k == n else solve(lambda p: cdf(k, p) > 0.025)
        return {"k": k, "n": n, "prop": k / n, "ci_lo": lo, "ci_hi": hi, "method": "Clopper-Pearson exact (bisection)"}


# --------------------------------------------------------------------------------------------- the reader module
def load_reader(monitor_dir, reader_path, scratch):
    """The run's own copies of monitor.py and the openHAB reader, configured as the live monitor was."""
    env = {"HOMEPROV_SCHEME": "closure", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "0", "HOMEPROV_READ": "copy",
           "HOMEPROV_SCRATCH": scratch, "HOMEPROV_DB": os.path.join(scratch, "unused.db"),
           "HOMEPROV_MONITOR_DIR": monitor_dir, "HP_OH_JSONDB": os.path.join(scratch, "jsondb")}
    for k, v in env.items():
        os.environ[k] = v
    for k in ("HP_OH_ARCHIVE", "HOMEPROV_SINCE", "HOMEPROV_ESCROW_DIR", "HOMEPROV_NAMEMAP_DIR"):
        os.environ.pop(k, None)
    sys.modules.pop("monitor", None)
    spec = importlib.util.spec_from_file_location("oh_monitor_e11", reader_path)
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    assert A.M.SCHEME == "closure" and A.M.ENCODING == "v2" and not A.M.KEYLOG
    return A


def read_db(A, db, jsondb):
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
    try:
        return A.read_rows(con, jsondb=jsondb)
    finally:
        con.close()


# ------------------------------------------------------------------------------------------- chain -> polls, roots
def parse_chain(lines):
    """polls {seq: {ts, copy_at, wm, since, through, observable}} (records and backlog heads), and first anchored
    roots {(gran, seg): {acc, n, seal_seq, seal_ts, wm}}."""
    polls, roots = {}, {}
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        p = rec.get("payload") or {}
        if p.get("observer") != "external-monitor":
            continue
        for hd in [p] + list(p.get("backlog") or []):
            s = hd.get("seq_local")
            if s is None:
                continue
            obs = ("wm" in hd and "through" in hd and not hd.get("evidence_unobservable") and not hd.get("unobservable"))
            if s not in polls or (obs and not polls[s]["observable"]):
                polls[s] = {"seq": s, "ts": hd.get("ts"), "copy_at": hd.get("copy_at"), "wm": hd.get("wm") or {},
                            "since": hd.get("since"), "through": hd.get("through"), "observable": obs,
                            "reason": hd.get("reason") or hd.get("unobservable")}
        for g, segs in (p.get("sealed") or {}).items():
            if not isinstance(segs, dict):
                continue
            for k, e in segs.items():
                key = (g, str(k))
                if key in roots or not isinstance(e, dict):
                    continue
                roots[key] = {"acc": e.get("acc"), "n": e.get("n"), "seal_seq": e.get("seal_seq", p.get("seq_local")),
                              "seal_ts": e.get("sealed_at", p.get("ts")), "wm": e.get("wm", p.get("wm")) or {}}
    return polls, roots


class Coverage:
    """First covering observable poll of a segment, and the latest poll lacking a row (by rowid)."""

    def __init__(self, polls):
        self.obs = sorted((p for p in polls.values() if p["observable"]), key=lambda p: p["seq"])
        self.by_through = sorted(self.obs, key=lambda p: (p["through"], p["seq"]))
        self.thr = [p["through"] for p in self.by_through]

    def first_cover(self, k, w):
        need = (int(k) + 1) * w
        i = bisect.bisect_left(self.thr, need)
        best = None
        for p in self.by_through[i:]:
            if p["since"] is not None and p["since"] <= int(k) * w and (best is None or p["seq"] < best["seq"]):
                best = p
            if best is not None and p["through"] > need + 3600:
                break
        return best

    def lag(self, table, rowid, ts):
        last = None
        for p in self.obs:
            w = p["wm"].get(table)
            if w is None or int(w) < int(rowid):
                last = p
        return (last["copy_at"] - ts) if last is not None and last.get("copy_at") is not None else None


def seg_root(M, nodes, g, w, k):
    phi = M.commit(nodes)
    v = (phi.get(g) or {}).get(str(k))
    return {"acc": v["acc"], "n": v["n"]} if v else None


def classify_late(cov, rows, L):
    lags = []
    for m in rows:
        lg = cov.lag(m["table"], m["rowid"], m["ts"])
        lags.append({"table": m["table"], "rowid": m["rowid"], "time": m["time"], "item": m.get("item"),
                     "lag_s": None if lg is None else round(lg, 3)})
    att = any(x["lag_s"] is not None and x["lag_s"] > L for x in lags)
    undecided = any(x["lag_s"] is None for x in lags)
    return ("attributable" if att else ("benign_late" if not undecided else "late_undecided")), lags


def verify(M, cov, roots, rows_by_seg, g, w, k, L=LATE_BOUND_S):
    """Verdict of one segment under the E11 rule (module docstring). rows_by_seg: {k: [(node, meta), ...]}."""
    F = rows_by_seg.get(int(k), [])
    nodes = [n for n, _m in F]
    R = roots.get((g, str(k)))
    c = cov.first_cover(k, w)
    out = {"segment": int(k), "rows_now": len(F), "covered": c is not None, "root_n": R["n"] if R else None}
    if c is None and R is None:
        out["class"] = "not_covered"
        return out
    if R is not None:
        now = seg_root(M, nodes, g, w, k) if nodes else None
        if now == {"acc": R["acc"], "n": R["n"]}:
            if c is not None and R["seal_seq"] != c["seq"]:
                late = [m for _n, m in F if int(m["rowid"]) > int(c["wm"].get(m["table"]) or -1)]
                if late:
                    out["class"], out["late"] = classify_late(cov, late, L)
                    out["why"] = "rows_arrived_after_first_coverage"
                    return out
            out["class"] = "ok"
            return out
        WR = R.get("wm") or {}
        late = [(n, m) for n, m in F if int(m["rowid"]) > int(WR.get(m["table"]) if WR.get(m["table"]) is not None else -1)]
        rest = [n for n, m in F if (n, m) not in late]
        if late and (seg_root(M, rest, g, w, k) if rest else None) == {"acc": R["acc"], "n": R["n"]}:
            out["class"], out["late"] = classify_late(cov, [m for _n, m in late], L)
            out["why"] = "late_rows_after_seal"
            return out
        out["class"] = "attributable"
        out["why"] = "sealed_row_removed_or_changed"
        out["delta_n"] = len(F) - R["n"]
        return out
    if not F:
        out["class"] = "ok"
        return out
    out["class"], out["late"] = classify_late(cov, [m for _n, m in F], L)
    out["why"] = "rows_in_a_second_sealed_empty"
    return out


def by_seg(pairs, w):
    d = collections.defaultdict(list)
    for n, m in pairs:
        d[int(n[0] // w)].append((n, m))
    return d


# ------------------------------------------------------------------------------- offline schemes from the archive
def reconstruct(A, archive_path, lines, polls):
    """First sealed root per (scheme, gran, seg) from the rows each poll read; validated against the anchored closure
    roots of that poll's own sealed segments."""
    arch = []
    for line in open(archive_path):
        try:
            arch.append(json.loads(line))
        except ValueError:
            pass
    arch.sort(key=lambda r: r["t_load"])
    loads = [r["t_load"] for r in arch]
    sealed = {s: {} for s in SCHEMES}
    status = collections.Counter()
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        p = rec.get("payload") or {}
        if p.get("observer") != "external-monitor" or p.get("evidence_unobservable") or not p.get("sealed"):
            continue
        own = {(g, str(k)): v for g, segs in p["sealed"].items() if g in dict(GRANS) for k, v in segs.items()
               if isinstance(v, dict) and "sealed_at" not in v}
        if not own:
            continue
        i = bisect.bisect_left(loads, (p.get("ts") or 0) - 0.01)
        match = None
        for cand in arch[i:i + 3]:
            if cand["t_load"] > (p.get("ts") or 0) + 10:
                break
            data = {k: cand[k] for k in ("items_cols", "items", "mapped", "tables", "registry")}
            phi = A.M.commit(A.nodes_from_rows("closure", data))
            if all((phi.get(g) or {}).get(s) == {"acc": v["acc"], "n": v["n"]} for (g, s), v in own.items()):
                match = data
                break
        if match is None:
            status["records_not_matched"] += 1
            continue
        status["records_matched"] += 1
        for sch in SCHEMES:
            phi = A.M.commit(A.nodes_from_rows(sch, match)) if sch != "closure" else None
            for (g, s), v in own.items():
                if (g, s) in sealed[sch]:
                    continue
                if sch == "closure":
                    root = {"acc": v["acc"], "n": v["n"]}
                else:
                    r = (phi.get(g) or {}).get(s)
                    if r is None:
                        continue
                    root = {"acc": r["acc"], "n": r["n"]}
                sealed[sch][(g, s)] = dict(root, seal_seq=p.get("seq_local"), seal_ts=p.get("ts"), wm=p.get("wm") or {})
    return sealed, dict(status)


# ---------------------------------------------------------------------------------------------- scoring helpers
def window_segments(t0, t1, w):
    return range(int(t0 // w), int(t1 // w) + 1)


def verdicts(A, cov, roots, final_pairs, t0, t1):
    out = {}
    for g, w in GRANS:
        bs = by_seg(final_pairs, w)
        segs = set(window_segments(t0, t1, w))
        cand = {int(s) for (gg, s) in roots if gg == g and int(s) in segs} | {k for k in bs if k in segs}
        out[g] = {k: verify(A.M, cov, roots, bs, g, w, k) for k in sorted(cand)}
    return out


def trial_seconds(t):
    secs = set()
    for k in ("mark", "target"):
        if t.get(k):
            secs.add(int(t[k]["time_ms"]) // 1000)
    rl = (t.get("relock") or {}).get("row")
    if rl:
        secs.add(int(rl[0]) // 1000)
    return secs


def score_arm(arm, rep, verd):
    trials = rep["trials"]
    valid = [t for t in trials if not t.get("err")]
    out = {"n_trials": len(trials), "n_valid": len(valid), "failures": [t.get("err") for t in trials if t.get("err")],
           "instrument_effect_rendered_all_roles": cp(sum(1 for t in valid if t.get("instrument_effect_rendered_all_roles")),
                                                      len(valid)),
           "other_points_unchanged_all_roles": cp(sum(1 for t in valid if all(t["per_role"][r]["other_points_unchanged"]
                                                                              for r in t["per_role"])), len(valid)),
           "same_render_for_every_role": cp(sum(1 for t in valid if t.get("same_render_for_every_role")), len(valid)),
           "edit_delay_s": ({"min": min(x["edit_delay_s"] for x in valid), "median": statistics.median(
               x["edit_delay_s"] for x in valid), "max": max(x["edit_delay_s"] for x in valid)} if valid else None),
           "api_calls_per_edit": sorted({(t.get("edit") or {}).get("api_calls") for t in valid})}
    det = {}
    for sch, v in verd.items():
        d = {}
        for g, w in GRANS:
            hits, classes = 0, collections.Counter()
            detail = []
            for t in valid:
                k = int(t["row_ts"] // w)
                r = v[g].get(k) or {"class": "absent"}
                classes[r["class"]] += 1
                hits += r["class"] == "attributable"
                if g == "second":
                    detail.append({"trial": t["trial"], "segment": k, "class": r["class"], "why": r.get("why")})
            d[g] = {**cp(hits, len(valid)), "classes": dict(classes)}
            if g == "second":
                d[g]["trials"] = detail
        det[sch] = d
    out["detection"] = det
    return out


def floor(verd, touched_secs, touched_mins):
    out = {}
    for sch, v in verd.items():
        f = {}
        for g, w in GRANS:
            touched = touched_secs if g == "second" else touched_mins
            un = {k: r for k, r in v[g].items() if k not in touched and r["class"] != "not_covered"}
            anchored = {k: r for k, r in un.items() if r.get("root_n") is not None}
            f[g] = {"untouched_anchored": cp(sum(1 for r in anchored.values() if r["class"] == "attributable"),
                                             len(anchored)),
                    "untouched_covered_empty_now_holding_rows": sum(1 for r in un.values() if r.get("root_n") is None
                                                                    and r["rows_now"] > 0),
                    "attributable_in_any_untouched_segment": sum(1 for r in un.values() if r["class"] == "attributable"),
                    "benign_late_segments": sum(1 for r in un.values() if r["class"] == "benign_late"),
                    "late_undecided_segments": sum(1 for r in un.values() if r["class"] == "late_undecided"),
                    "unexplained": [r for r in un.values() if r["class"] == "attributable"][:50]}
        out[sch] = f
    return out


def benign_outcomes(ops, verd, label_secs):
    out = []
    for op in ops:
        secs = sorted({int(ms) // 1000 for ms, *_ in (op.get("affected_past") or [])})
        if op["op"] == "B-LABEL":
            secs = sorted(label_secs)
        rec = {"op": op["op"], "variant": op.get("variant"), "item": op.get("item"), "t_start": op.get("t_start"),
               "t_end": op.get("t_end"), "seconds_affected": len(secs), "per_scheme": {}}
        for sch, v in verd.items():
            cls = collections.Counter((v["second"].get(k) or {"class": "absent"})["class"] for k in secs)
            rec["per_scheme"][sch] = dict(cls)
        out.append(rec)
    return out


def touched_sets(reports, ops, label_secs):
    secs = set()
    for rep in reports.values():
        for t in rep["trials"]:
            secs |= trial_seconds(t)
    for op in ops:
        for x in op.get("affected_past") or []:
            secs.add(int(x[0]) // 1000)
        for x in ((op.get("result") or {}).get("rows_before") or []):
            secs.add(int(x[0]) // 1000)
    secs |= set(label_secs)
    return secs, {s // 60 for s in secs}


# ------------------------------------------------------------------------------------------ single-write checks
def single_writes(A, db, jsondb, t0, t1):
    """One write to one field on copies of the final snapshot (database or registry); changed one-second roots per
    scheme in the window."""
    def roots(dbp, jd):
        data = read_db(A, dbp, jd)
        out = {}
        for sch in SCHEMES:
            phi = A.M.commit(A.nodes_from_rows(sch, data))["second"]
            out[sch] = {k: v for k, v in phi.items() if t0 - 1 <= int(k) <= t1 + 1}
        return out

    def ndiff(a, b):
        return sum(1 for k in set(a) | set(b) if a.get(k) != b.get(k))
    res = []
    with tempfile.TemporaryDirectory() as tmp:
        base_db, base_jd = os.path.join(tmp, "base.db"), os.path.join(tmp, "jd")
        shutil.copy2(db, base_db)
        shutil.copytree(jsondb, base_jd)
        base = roots(base_db, base_jd)
        con = sqlite3.connect(base_db)
        iid = con.execute("SELECT ItemId FROM items WHERE ItemName='FrontDoor_Lock'").fetchone()[0]
        tab = A.table_for(iid, "FrontDoor_Lock")
        row = con.execute('SELECT rowid, time, value FROM "%s" WHERE time >= ? ORDER BY time LIMIT 1' % tab,
                          (A.time_text(t0),)).fetchone()
        con.close()
        db_writes = [("<table>.value", 'UPDATE "%s" SET value=? WHERE rowid=?' % tab, ("ON" if row[2] == "OFF" else "OFF", row[0])),
                     ("<table>.time", 'UPDATE "%s" SET time=? WHERE rowid=?' % tab,
                      (A.time_text(A.parse_time(row[1]) + 1) + row[1][19:], row[0])),
                     ("<table>.rowid", 'UPDATE "%s" SET rowid=(SELECT max(rowid)+100 FROM "%s") WHERE rowid=?' % (tab, tab),
                      (row[0],)),
                     ("items.ItemName", "UPDATE items SET ItemName=? WHERE ItemId=?", ("FrontDoor_Lock_x", iid)),
                     ("items.ItemId", "UPDATE items SET ItemId=(SELECT max(ItemId)+100 FROM items) WHERE ItemId=?", (iid,))]
        for name, sql, args in db_writes:
            p = os.path.join(tmp, "w.db")
            shutil.copy2(base_db, p)
            c = sqlite3.connect(p)
            c.execute(sql, args)
            c.commit()
            c.close()
            got = roots(p, base_jd)
            res.append({"write": name, "target": "%s rowid %s" % (tab, row[0]) if name.startswith("<") else "items",
                        "segments_changed": {s: ndiff(base[s], got[s]) for s in SCHEMES},
                        "segments_in_window": {s: len(base[s]) for s in SCHEMES}})
            os.remove(p)

        def reg_write(name, fn):
            jd = os.path.join(tmp, "jd_w")
            if os.path.exists(jd):
                shutil.rmtree(jd)
            shutil.copytree(base_jd, jd)
            try:
                fn(jd)
            except Exception as exc:                           # noqa: BLE001  (registry layout not as expected)
                res.append({"write": name, "target": "registry", "error": repr(exc)[:200]})
                return
            got = roots(base_db, jd)
            res.append({"write": name, "target": "registry", "segments_changed": {s: ndiff(base[s], got[s]) for s in SCHEMES},
                        "segments_in_window": {s: len(base[s]) for s in SCHEMES}})

        def edit(jd, fname, f):
            p = os.path.join(jd, fname)
            d = json.load(open(p))
            f(d)
            json.dump(d, open(p, "w"))

        def set_type(d):
            d["FrontDoor_Lock"]["value"]["itemType"] = "Contact"

        def set_unit(d):
            for k, e in d.items():
                if k == "unit:Kitchen_Temp":
                    e["value"]["value"] = "°F"

        def set_label(d):
            d["Label_Probe"]["value"]["label"] = (d["Label_Probe"]["value"].get("label") or "") + " x"

        reg_write("registry.itemType", lambda jd: edit(jd, A.ITEM_FILE, set_type))
        reg_write("registry.meta.unit", lambda jd: edit(jd, A.META_FILE, set_unit))
        reg_write("registry.label", lambda jd: edit(jd, A.ITEM_FILE, set_label))
        reg_write("registry (item entry) deleted", lambda jd: edit(jd, A.ITEM_FILE, lambda d: d.pop("FrontDoor_Lock")))
    return res


# -------------------------------------------------------------------------------------------------- closure (O1)
def closure_summary(path):
    d = json.load(open(path))
    by = {}
    for f in d["fixtures"]:
        for m in f["mutations"]:
            e = by.setdefault(m["field"], {"rendered_changed": set(), "immediately_changed": set(), "n": 0})
            e["n"] += 1
            imm = m["immediately"]["rendered_output_changed"] if "immediately" in m else m["rendered_output_changed"]
            if m["rendered_output_changed"] or imm:
                e["rendered_changed"].add(f["item"])
            if imm:
                e["immediately_changed"].add(f["item"])
    measured = sorted(k for k, v in by.items() if v["rendered_changed"])
    keys_top = sorted({k for f in d["fixtures"] for k in (f.get("dto_top_level_keys") or [])})
    keys_pt = sorted({k for f in d["fixtures"] for k in (f.get("dto_point_keys") or [])})
    return {"file": os.path.relpath(path, REPO), "sha256": sha(path), "n_fixtures": len(d["fixtures"]),
            "n_mutations": sum(len(f["mutations"]) for f in d["fixtures"]),
            "fields_mutated": sorted(by), "fields_changing_rendered_history": measured,
            "fields_changing_only_after_index_reload": sorted(k for k, v in by.items()
                                                              if v["rendered_changed"] and not v["immediately_changed"]),
            "predicted": d.get("predicted_closure"), "predicted_minus_measured": sorted(set(d.get("predicted_closure") or [])
                                                                                       - set(measured)),
            "measured_minus_predicted": sorted(set(measured) - set(d.get("predicted_closure") or [])),
            "per_field": {k: {"fixtures_rendered_changed": sorted(v["rendered_changed"]), "mutations": v["n"]}
                          for k, v in sorted(by.items())},
            "positive_control_all_fixtures": all(f.get("positive_control_value_change_changed_render") for f in d["fixtures"]),
            "determinism_control_all_fixtures": all(f.get("determinism_control_equal") for f in d["fixtures"]),
            "same_render_for_every_role_all_fixtures": all(f.get("same_render_for_every_role") for f in d["fixtures"]),
            "every_restore_equal_to_baseline": all(m["restore_equal_to_baseline"] for f in d["fixtures"]
                                                   for m in f["mutations"]),
            "rendered_history_fields": {"top_level": keys_top, "per_point": keys_pt},
            "attribution_field_in_rendered_history": any(k for k in keys_top + keys_pt
                                                         if k.lower() in ("source", "user", "cause", "context", "actor")),
            "in_place_probe": d.get("in_place_probe", {}).get("tables_with_in_place_rewrites")}


# What the live reader commits (testbed/e11/monitor/oh_monitor.py, closure scheme): the fields E11-CLO measures are
# checked against this list before the detection run (--closure-gate); a measured field outside it stops the run for a
# registered amendment of the reader.
READER_COMMITS = ["<table>.time", "<table>.value", "<table> (name)", "items.ItemId", "items.ItemName",
                  "registry.itemType", "registry.meta.unit", "registry (item entry)"]


def closure_gate(path):
    s = closure_summary(path)
    measured = set(s["fields_changing_rendered_history"])
    missing = sorted(measured - set(READER_COMMITS))
    controls = s["positive_control_all_fixtures"] and s["determinism_control_all_fixtures"] and s["every_restore_equal_to_baseline"]
    return {"ok": not missing and controls, "missing_from_reader": missing, "controls_hold": controls,
            "committed_but_not_measured": sorted(set(READER_COMMITS) - measured)}


# ------------------------------------------------------------------------------------------------------- cost (O5)
def cost_summary(path, hub_log, reader_path, monitor_py):
    rows = [json.loads(l) for l in open(path) if l.strip()] if os.path.exists(path) else []

    def st(k):
        v = sorted(r[k] for r in rows if isinstance(r.get(k), (int, float)))
        if not v:
            return None
        return {"n": len(v), "median_ms": statistics.median(v), "p90_ms": v[int(0.9 * (len(v) - 1))], "max_ms": v[-1]}
    tot = sorted(sum(r.get(k) or 0 for k in ("copy_ms", "load_ms", "commit_ms", "append_ms")) for r in rows)
    busy = 0
    if hub_log and os.path.exists(hub_log):
        busy = sum(1 for l in open(hub_log, errors="replace") if "SQLITE_BUSY" in l or "database is locked" in l)
    code = [l for l in open(reader_path) if l.strip() and not l.strip().startswith("#")]
    return {"polls": len(rows), "copy_backup": st("copy_ms"), "load": st("load_ms"), "commit": st("commit_ms"),
            "append": st("append_ms"), "total": {"median_ms": statistics.median(tot), "p90_ms": tot[int(0.9 * (len(tot) - 1))],
                                                 "max_ms": tot[-1]} if tot else None,
            "hub_log_lines_busy_or_locked": busy,
            "port": {"monitor_py_sha256": sha(monitor_py), "monitor_py_lines_changed": 0,
                     "reader_file": os.path.relpath(reader_path, REPO), "reader_sha256": sha(reader_path),
                     "reader_non_blank_non_comment_lines": len(code),
                     "functions_replaced": ["snapshot", "validate_copy (reports a failed snapshot only)",
                                            "check_connection", "watermark", "load"]}}


# ------------------------------------------------------------------------------- event log (characterisation only)
def events_log_sources(path):
    """Where openHAB keeps a sender: events.log lines end in "(source: ...)" when the sender set one (ItemCommandEvent and
    ItemStateChangedEvent toString(), openhab-core 5.2.3). Counted by sender kind; account names are reduced to their
    role. Characterisation for the hub model only: E11 does not edit or protect events.log."""
    if not os.path.exists(path):
        return None
    kinds = collections.Counter()
    lines = with_src = 0
    for line in open(path, errors="replace"):
        lines += 1
        if "(source: " not in line:
            continue
        with_src += 1
        src = line.rsplit("(source: ", 1)[1].rstrip().rstrip(")")
        if "org.openhab.core.io.rest$" in src:
            kinds["rest$<account>"] += 1
        elif src.startswith("org.openhab.core.automation"):
            kinds["automation rule"] += 1
        elif "org.homeprov.e11" in src:
            kinds["E11 bundle"] += 1
        else:
            kinds["other"] += 1
    return {"lines": lines, "lines_with_source": with_src, "source_kinds": dict(kinds),
            "note": "sender-set and informational per the openHAB event-bus documentation; not in the persisted history"}


# --------------------------------------------------------------------------------------------------------- main
def main():
    if sys.argv[1:2] == ["--closure-gate"]:
        g = closure_gate(sys.argv[2])
        print(json.dumps(g))
        sys.exit(0 if g["ok"] else 9)
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--outdir", default=OUT)
    ap.add_argument("--closure")
    ap.add_argument("--late-bound", type=float, default=LATE_BOUND_S)
    a = ap.parse_args()
    path = os.path.join(a.outdir, "%s_score.json" % a.tag)
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    tick = time.time()
    run = a.run
    t0 = float(open(os.path.join(run, "t_start")).read())
    t1 = float(open(os.path.join(run, "t_end")).read())
    db = os.path.join(run, "snapshots", "final.db")
    jd = os.path.join(run, "snapshots", "jsondb_final")
    lines = open(os.path.join(run, "chain.jsonl")).read().splitlines()
    reports = {}
    for arm in ARMS:
        p = os.path.join(a.outdir, "%s_report_%s.json" % (a.tag, arm))
        if os.path.exists(p):
            reports[arm] = json.load(open(p))
    ops = [json.loads(l) for l in open(os.path.join(run, "benign.jsonl")) if l.strip()] \
        if os.path.exists(os.path.join(run, "benign.jsonl")) else []
    import chainverify                                         # noqa: PLC0415
    heads_path = os.path.join(run, "witness_heads.jsonl")
    heads = chainverify.read_heads(open(heads_path, "rb").read()) if os.path.exists(heads_path) else None
    link = chainverify.verify_chain(open(os.path.join(run, "chain.jsonl"), "rb").read(), witnessed_heads=heads)
    with tempfile.TemporaryDirectory() as scratch:
        A = load_reader(os.path.join(run, "code"), os.path.join(run, "code", "oh_monitor.py"), scratch)
        M = A.M
        sig = collections.Counter()
        pub_path = os.path.join(run, "sign_pub.pem")
        if os.path.exists(pub_path):
            pub = M.load_public_key(pub_path)
            for line in lines:
                sig[M.verify_record_signature(json.loads(line).get("payload") or {}, pub)] += 1
        polls, roots = parse_chain(lines)
        cov = Coverage(polls)
        data = read_db(A, db, jd)
        finals = {sch: A.nodes_from_rows(sch, data, with_meta=True) for sch in SCHEMES}
        recon, rstat = reconstruct(A, os.path.join(run, "archive.jsonl"), lines, polls) \
            if os.path.exists(os.path.join(run, "archive.jsonl")) else ({s: {} for s in SCHEMES}, {})
        roots_by = {"closure": roots, "rows": recon["rows"], "wholerow": recon["wholerow"]}
        verd = {sch: verdicts(A, cov, roots_by[sch], finals[sch], t0, t1) for sch in SCHEMES}
        label_item = next((op.get("item") for op in ops if op["op"] == "B-LABEL"), "Label_Probe")
        label_secs = {int(m["ts"]) for _n, m in finals["closure"] if m.get("item") == label_item}
        ts_, tm_ = touched_sets(reports, ops, label_secs)
        oc = sorted(p["copy_at"] for p in polls.values() if p["observable"] and p.get("copy_at") is not None
                    and t0 <= p["copy_at"] <= t1)
        gaps = [(b - a, a, b) for a, b in zip(oc, oc[1:])]
        poll_gaps = {"observable_polls_in_window": len(oc), "max_gap_s": round(max(g[0] for g in gaps), 3) if gaps else None,
                     "median_interval_s": round(statistics.median(g[0] for g in gaps), 3) if gaps else None,
                     "gaps_over_30s": [[round(g, 3), a, b] for g, a, b in gaps if g > 30.0]}
        res = {
            "experiment": "E11 (RQ4): HOMEPROV's principle on a third hub family, openHAB",
            "tag": a.tag, "window": [t0, t1], "late_bound_s": a.late_bound,
            "verification_rule": __doc__.split("THE VERIFICATION RULE")[1].split("    /Users")[0].strip(),
            "inputs": {"final_snapshot": {"path": os.path.relpath(db, os.path.dirname(REPO)), "sha256": sha(db)},
                       "chain": {"records": len(lines), "sha256": sha(os.path.join(run, "chain.jsonl"))},
                       "monitor_py_sha256": sha(os.path.join(run, "code", "monitor.py")),
                       "reader_sha256": sha(os.path.join(run, "code", "oh_monitor.py")),
                       "reports": {k: sha(os.path.join(a.outdir, "%s_report_%s.json" % (a.tag, k))) for k in reports}},
            "chain_link_check": {k: link.get(k) for k in ("ok", "link", "linked_records", "integrity", "witnessed_heads")},
            "record_signatures": dict(sig),
            "polls": {"total": len(polls), "observable": sum(1 for p in polls.values() if p["observable"]),
                      "unobservable_reasons": dict(collections.Counter(p["reason"] for p in polls.values()
                                                                       if not p["observable"]))},
            "offline_reconstruction": {"records": rstat, "segments": {s: len(v) for s, v in recon.items()}},
            "O3_detection": {arm: score_arm(arm, rep, verd) for arm, rep in reports.items()},
            "O4_floor": floor(verd, ts_, tm_),
            "O4_benign_operations": benign_outcomes(ops, verd, label_secs),
            "touched_seconds": len(ts_),
            "O2_single_writes": single_writes(A, db, jd, t0, t1),
            "O5_observable_poll_gaps": poll_gaps,
            "O5_cost_and_port": cost_summary(os.path.join(run, "cost.jsonl"), os.path.join(run, "logs", "openhab.log"),
                                             os.path.join(run, "code", "oh_monitor.py"), os.path.join(run, "code", "monitor.py")),
            "final_snapshot_rows": sum(len(t["rows"]) for t in data["tables"].values()),
            "events_log_sources": events_log_sources(os.path.join(run, "logs", "events.log")),
            "script_sha256": sha(os.path.abspath(__file__)),
        }
        if a.closure:
            res["O1_closure"] = closure_summary(a.closure)
    res["seconds"] = round(time.time() - tick, 1)
    res["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(path, "x") as fh:
        json.dump(res, fh, indent=1, default=str)
    for arm, r in res["O3_detection"].items():
        print("%-6s valid %d/%d rendered-as-intended %s | detected closure %s rows %s wholerow %s" % (
            arm, r["n_valid"], r["n_trials"], r["instrument_effect_rendered_all_roles"]["k"],
            r["detection"]["closure"]["second"]["k"], r["detection"]["rows"]["second"]["k"],
            r["detection"]["wholerow"]["second"]["k"]))
    print("floor (second, untouched anchored):", {s: (f["second"]["untouched_anchored"]["k"], f["second"]["untouched_anchored"]["n"])
                                                  for s, f in res["O4_floor"].items()})
    print("->", path, sha(path))


if __name__ == "__main__":
    main()
