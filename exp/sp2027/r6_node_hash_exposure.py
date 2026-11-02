"""R6 (T7): how many recorder rows admit a rewrite that leaves the v1 ('|'-joined) node hash unchanged.

For every recorder snapshot in the verifier snapshot set (16 distinct copies of the real deployment's recorder) and for
every row of `states` and `events`, this script reads the three context BLOBs the node hashes cover (context_id_bin,
context_parent_id_bin, context_user_id_bin) and classifies the row:

  row_splice        the Row scheme hashes ctx|par: some other (ctx', par') gives the same bytes. True iff ctx or par
                    contains 0x7C (each extra 0x7C is a place the separator can move to).
  closure_splice    the Closure scheme hashes ctx|par|usr|prev|chg: some other (ctx', par', usr') gives the same bytes.
                    True iff ctx, par or usr contains 0x7C (prev, chg and the label contain no 0x7C, so their separators
                    cannot move).
  par_usr_splice    the triage's case: the parent/user boundary can move. True iff par or usr contains 0x7C.
  ctx_par_splice    the context/parent boundary can move (changes the context id the logbook resolves). True iff ctx or
                    par contains 0x7C.
  user_erasable     the row carries a user id and the parent/user boundary can move, so a rewrite can replace the user
                    id with a value the platform does not resolve (any length other than 16 bytes) at no cost to any
                    root. True iff usr is not NULL and par_usr_splice.
  null_alias_*      a NULL column could be rewritten to an empty BLOB (or back) at no cost to any v1 root.
  natural_alt_*     forensic: the row's bytes also parse as a DIFFERENT field tuple whose fields are all NULL/empty or
                    16 bytes, i.e. the row could be the v1-invisible rewrite of a natural recorder row.
  unnatural         some context BLOB is empty or not 16 bytes long (the recorder writes NULL or 16 bytes).
  prev_text/chg_text  old_state_id / last_changed_ts stored as TEXT (v1 encodes 5 and '5' alike).

Rates are given per snapshot, per run window (the rows verify_all.py folds), and over the union of distinct rows
(keyed by table and row id, latest snapshot wins). Snapshots are opened read-only and immutable.

    python3 exp/sp2027/r6_node_hash_exposure.py [--snapshots DIR]     # writes exp/out/r6_node_hash_exposure.json
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import itertools
import json
import os
import sqlite3
import sys
import urllib.parse

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
DEFAULT_SNAP = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-snapshots", "verifier-recorder-snapshots-2026-10")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import verify_all as VA  # noqa: E402  (RUNS table: which snapshot and window each run verifies)
from rig import stats  # noqa: E402

PIPE = 0x7C
FLAGS = ("row_splice", "closure_splice", "par_usr_splice", "ctx_par_splice", "user_erasable",
         "null_alias_row", "null_alias_closure", "natural_alt_row", "natural_alt_closure", "unnatural",
         "ctx_has_7c", "par_has_7c", "usr_has_7c", "usr_present", "par_present", "prev_text", "chg_text")


def ro(db):
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db)), uri=True)


def natural_alt(fields) -> bool:
    """Does b'|'.join(fields) also split, at different 0x7C positions, into parts that are all 0 or 16 bytes long?"""
    region = b"|".join(f or b"" for f in fields)
    k = len(fields) - 1
    orig, pos = [], -1
    for f in fields[:-1]:
        pos += len(f or b"") + 1
        orig.append(pos)
    pipes = [i for i, ch in enumerate(region) if ch == PIPE]
    if len(pipes) <= k:
        return False
    for cut in itertools.combinations(pipes, k):
        if list(cut) == orig:
            continue
        bounds = (-1,) + cut + (len(region),)
        if all(bounds[i + 1] - bounds[i] - 1 in (0, 16) for i in range(len(bounds) - 1)):
            return True
    return False


def classify(ctx, par, usr, prev_type=None, chg_type=None) -> dict:
    h = lambda b: b is not None and PIPE in b          # noqa: E731
    c7, p7, u7 = h(ctx), h(par), h(usr)
    f = {"ctx_has_7c": c7, "par_has_7c": p7, "usr_has_7c": u7,
         "usr_present": usr is not None, "par_present": par is not None,
         "row_splice": c7 or p7, "closure_splice": c7 or p7 or u7,
         "par_usr_splice": p7 or u7, "ctx_par_splice": c7 or p7,
         "user_erasable": usr is not None and (p7 or u7),
         "null_alias_row": ctx is None or par is None,
         "null_alias_closure": ctx is None or par is None or usr is None,
         "unnatural": any(b is not None and len(b) != 16 for b in (ctx, par, usr)),
         "prev_text": prev_type == "text", "chg_text": chg_type == "text"}
    f["natural_alt_row"] = f["row_splice"] and natural_alt((ctx, par))
    f["natural_alt_closure"] = f["closure_splice"] and natural_alt((ctx, par, usr))
    return f


def scan(db, since=None, until=None, union=None, tag=""):
    con = ro(db)
    out = {}
    for table, idc, tsc, extra in (("states", "state_id", "last_updated_ts", ", typeof(old_state_id), typeof(last_changed_ts)"),
                                   ("events", "event_id", "time_fired_ts", ", NULL, NULL")):
        q = (f"SELECT {idc}, {tsc}, context_id_bin, context_parent_id_bin, context_user_id_bin{extra} FROM {table}"
             + (f" WHERE {tsc} >= ? AND {tsc} <= ?" if since is not None else ""))
        cnt = dict.fromkeys(FLAGS, 0)
        n = 0
        examples = {"user_erasable": [], "natural_alt_closure": [], "unnatural": []}
        for rid, ts, ctx, par, usr, pt, ct in con.execute(q, (since, until) if since is not None else ()):
            n += 1
            f = classify(ctx, par, usr, pt, ct)
            for k, v in f.items():
                if v:
                    cnt[k] += 1
            for k in examples:
                if f[k] and len(examples[k]) < 5:
                    examples[k].append({"id": rid, "ts": ts, "ctx": ctx.hex() if ctx else None,
                                        "par": par.hex() if par else None, "usr": usr.hex() if usr else None})
            if union is not None:
                union[(table, rid)] = tuple(f[k] for k in FLAGS)
        out[table] = {"rows": n, "counts": cnt, "examples": examples}
    con.close()
    tot = {"rows": out["states"]["rows"] + out["events"]["rows"],
           "counts": {k: out["states"]["counts"][k] + out["events"]["counts"][k] for k in FLAGS}}
    out["both"] = tot
    return out


def rates(block):
    n = block["rows"]
    r = {}
    for k in ("row_splice", "closure_splice", "par_usr_splice", "ctx_par_splice", "natural_alt_closure", "unnatural"):
        k_ = block["counts"][k]
        ci = stats.clopper_pearson(k_, n) if n else None
        r[k] = {"k": k_, "n": n, "rate": round(k_ / n, 5) if n else None,
                "ci95": [round(ci["ci_lo"], 5), round(ci["ci_hi"], 5)] if ci else None}
    up = block["counts"]["usr_present"]
    r["user_erasable_among_user_rows"] = {"k": block["counts"]["user_erasable"], "n": up,
                                          "rate": round(block["counts"]["user_erasable"] / up, 5) if up else None}
    return r


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None, help="full verifier snapshot set: every row of the 16 recorder copies")
    ap.add_argument("--extracts", default=None, help="per-run window extracts (default reproduce/snapshots if present): "
                                                    "every row of the ten extracts")
    ap.add_argument("--out", default=os.path.join(OUT, "r6_node_hash_exposure.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    src = VA.default_inputs(a.snapshots, a.extracts)
    if src.mode == "snapshots":
        dbs = sorted((p for p in src.sums if p.endswith("recorder.db")),
                     key=lambda p: os.path.getmtime(os.path.join(src.base, p)))       # oldest first: latest row wins
    else:
        dbs = [os.path.relpath(src.paths(rid)[0], src.base) for rid in VA.RUNS]
    union, per_db = {}, {}
    for rel in dbs:
        p = os.path.join(src.base, rel)
        got = sha256_file(p)
        if got != src.sums.get(rel):
            raise SystemExit(rel + " is not vouched for by the checksum list")
        print("scanning", rel, flush=True)
        s = scan(p, union=union)
        per_db[rel] = {"sha256": got, "states": s["states"], "events": s["events"], "rates_both_tables": rates(s["both"])}
    per_run = {}
    for rid, cfg in VA.RUNS.items():
        res = json.load(open(os.path.join(OUT, cfg["result"])))
        w = res["window"]
        since = (int(w["t_start"] // 3600) - 1) * 3600.0
        s = scan(src.paths(rid)[0], since=since, until=w["recorder_snapshot_at"])
        per_run[rid] = {"db": os.path.relpath(src.paths(rid)[0], src.base), "rows_folded_by_verifier": [since, w["recorder_snapshot_at"]],
                        "states": s["states"], "events": s["events"], "rates_both_tables": rates(s["both"])}
    ucnt = {"rows": len(union), "counts": {k: sum(1 for v in union.values() if v[i]) for i, k in enumerate(FLAGS)}}
    ust = {"rows": sum(1 for (t, _r) in union if t == "states"),
           "counts": {k: sum(1 for (t, _r), v in union.items() if t == "states" and v[i]) for i, k in enumerate(FLAGS)}}
    uev = {"rows": ucnt["rows"] - ust["rows"], "counts": {k: ucnt["counts"][k] - ust["counts"][k] for k in FLAGS}}
    res = {
        "item": "R6/T7: rows whose v1 node hash admits a rewrite that changes stored fields but no root",
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha256_file(os.path.abspath(__file__)),
        "inputs_mode": src.mode,
        "snapshot_set": ("verifier-recorder-snapshots-2026-10, 16 recorder copies (SHA256SUMS checked)"
                         if src.mode == "snapshots" else
                         "the ten per-run window extracts in reproduce/snapshots (EXTRACTS_SHA256SUMS checked)"),
        "reference_rate_random_16_bytes_contains_0x7C": round(1 - (255 / 256) ** 16, 5),
        "definitions": {
            "row_splice": "ctx or par contains 0x7C: another (ctx', par') has the same v1 Row-scheme bytes",
            "closure_splice": "ctx, par or usr contains 0x7C: another (ctx', par', usr') has the same v1 Closure bytes",
            "par_usr_splice": "par or usr contains 0x7C: the parent/user boundary can move (the triage's case)",
            "ctx_par_splice": "ctx or par contains 0x7C: the context/parent boundary can move",
            "user_erasable": "usr not NULL and par_usr_splice: the user id can be replaced by an unresolvable value",
            "null_alias_closure": "some of ctx/par/usr is NULL: NULL <-> empty BLOB is invisible to v1",
            "natural_alt_closure": "the row's v1 bytes also parse as a different tuple whose BLOBs are all 0 or 16 bytes",
            "unnatural": "some context BLOB is non-NULL and not 16 bytes long",
            "rates": "k/n with exact Clopper-Pearson 95% intervals (exp/rig/stats.py)"},
        "union_distinct_rows": {"states": {**ust, "rates": rates(ust)}, "events": {**uev, "rates": rates(uev)},
                                "both": {**ucnt, "rates": rates(ucnt)}},
        "per_run_window": per_run,
        "per_snapshot": per_db,
    }
    with open(a.out, "x") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps(res["union_distinct_rows"]["both"]["rates"], indent=1))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
