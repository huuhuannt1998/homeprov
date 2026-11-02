#!/usr/bin/env python3
"""E10 follow-up (PI-approved, 2026-10-24): the DEL 69 copy-mode anomaly, from saved data only. EXPLORATORY.

Copy poll seq_local 790 (copy began 1792570953.124911) had states watermark 1268167 and so lacked state 1268168, the
DEL trial 69 actuation's row, which the direct monitor had read at 1792570948.396 (seq_local 916). This file collects:

  row       the row and its companion event (trial record; snap_del / snap_timing snapshots, opened immutable)
  polls     both monitors' polls around 1792570930-1792570976 from the chains (copy_at, wm, through, sealed seconds with
            their acc and n, keylog entries), the cost-log lines, and whether poll 790 was a single copy attempt
            (copy_at equal to the poll's start = cost ts - copy_ms)
  escrow    the node keys each monitor folded into its sealed root of second 1792570948 (escrow.jsonl, streamed)
  adversary DEL 69's transaction times and the duration of every DEL / DEL-PH delete transaction (t_delete_commit -
            t_delete_start), the BDT inserts (t_commit - t_insert)
  verifier  second 1792570948 and key s:1268168 in the scorer's cached 'del' verifications of both monitors
  later     every copy poll whose keylog lists key 1268168, with the row's second (original 948 or a reuse)
  scan      the whole-session staleness scan: every observable copy poll (e10s and e10u) whose states or events
            watermark is below one the direct monitor had read before the copy began, not explained by a deletion
            committed before the copy ended (trial deletions, WIPE, PW, UL-SHM blind deletions, B3 purge range), with an
            exact 95% interval for the per-poll rate (exp/rig/stats.py clopper_pearson)

Inputs read only; chains and escrows streamed. Output: one new JSON file (mode 'x').

    python3 exp/sp2027/r16_e10_del69.py [--run-dir DIR] [--out exp/out/r16_e10_del69.json]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "exp"))
from rig import stats                                      # noqa: E402

RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
KEY, EVENT, SECOND = 1268168, 702801, "1792570948"
T_LO, T_HI = 1792570930.0, 1792570976.0


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def ro(db):
    p = db + "-wal"
    assert not os.path.exists(p) or os.path.getsize(p) == 0, p
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)


def stream_polls(chain, detail_window=None):
    """seq_local -> poll (copy_at, wm, through, since, unobservable, reason); plus full detail for polls in the window."""
    polls, detail, kl_key = {}, {}, []
    with open(chain) as fh:
        for line in fh:
            if not line.strip():
                continue
            cr = json.loads(line)
            p = cr.get("payload") or {}
            if p.get("observer") != "external-monitor" or "coverage" not in p or "seq_local" not in p:
                continue
            for h, own in [(h, False) for h in (p.get("backlog") or [])] + [(p, True)]:
                s = int(h["seq_local"])
                cur = polls.get(s)
                if cur is None or (cur.get("through") is None and h.get("through") is not None):
                    polls[s] = {"seq_local": s, "copy_at": h.get("copy_at"), "wm": h.get("wm"), "through": h.get("through"),
                                "since": h.get("since"),
                                "unobservable": bool(h.get("evidence_unobservable") or h.get("unobservable"))}
                for t, es in (h.get("keylog") or {}).items():
                    for e in es if isinstance(es, list) else [es]:
                        lo = int((e or {}).get("from", 0))
                        for x in (e or {}).get("rows") or []:
                            if t == "states" and lo + int(x[0]) == KEY:
                                kl_key.append({"seq_local": s, "row_second": x[2] if len(x) > 2 else None})
            ca = p.get("copy_at")
            if detail_window and ca is not None and detail_window[0] <= ca <= detail_window[1]:
                sec = (p.get("sealed") or {}).get("second") or {}
                detail[int(p["seq_local"])] = {
                    "chain_seq": cr.get("seq"), "recv_ts": cr.get("recv_ts"), "copy_at": ca, "ts": p.get("ts"),
                    "wm": p.get("wm"), "since": p.get("since"), "through": p.get("through"), "part": p.get("part"),
                    "unobservable": bool(p.get("evidence_unobservable")), "n_sealed": p.get("n_sealed"),
                    "sealed_seconds": {k: {"n": v.get("n"), "acc": (v.get("acc") or "")[:16]} for k, v in sec.items()},
                    "keylog": {t: [{"from": e.get("from"), "n": e.get("n"),
                                    "rows": [[int(e.get("from", 0)) + int(x[0]), x[2] if len(x) > 2 else None]
                                             for x in e.get("rows") or []]}
                                   for e in (es if isinstance(es, list) else [es])]
                               for t, es in (p.get("keylog") or {}).items()}}
    return polls, detail, kl_key


def cost(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            if line.strip().startswith("{"):
                d = json.loads(line)
                if "seq_local" in d:
                    out[int(d["seq_local"])] = d
    return out


def escrow_second(path, second):
    """Node keys folded into the sealed one-second root of `second` (escrow lines with gran 'second')."""
    out = []
    tag = '"%s"' % second
    with open(path, errors="replace") as fh:
        for line in fh:
            if tag not in line or '"gran": "second"' not in line:
                continue
            d = json.loads(line)
            if str(d.get("seg") or d.get("second") or "") != second and tag not in json.dumps({k: v for k, v in d.items() if k != "nodes"}):
                continue
            keys = re.findall(r'\["T", "([se]:\d+)"\]', line)
            out.append({"n": d.get("n"), "acc": (d.get("acc") or "")[:16], "node_keys": keys,
                        "fields": {k: v for k, v in d.items() if k not in ("nodes",)}})
    return out


def scan(polls_d, polls_c, cost_c, cost_d, dels, t_max=None):
    dobs = sorted(((p["copy_at"] + ((cost_d.get(s) or {}).get("copy_ms") or 0) / 1000.0, p)
                   for s, p in polls_d.items() if not p["unobservable"] and p.get("copy_at") is not None
                   and isinstance(p.get("wm"), dict)), key=lambda x: x[0])
    cobs = sorted((p for p in polls_c.values() if not p["unobservable"] and p.get("copy_at") is not None
                   and isinstance(p.get("wm"), dict)), key=lambda p: p["copy_at"])
    hits, n, j, last = [], 0, 0, None
    for c in cobs:
        if t_max is not None and c["copy_at"] > t_max:
            break
        while j < len(dobs) and dobs[j][0] <= c["copy_at"]:
            last = dobs[j][1]
            j += 1
        if last is None:
            continue
        n += 1
        c_end = c["copy_at"] + ((cost_c.get(c["seq_local"]) or {}).get("copy_ms") or 0) / 1000.0
        for table in ("states", "events"):
            cw, dw = c["wm"].get(table), last["wm"].get(table)
            if cw is None or dw is None or cw >= dw:
                continue
            if not [x for x in dels if x[0] == table and x[1] <= dw and x[2] >= cw + 1 and x[3] <= c_end]:
                hits.append({"table": table, "copy_seq_local": c["seq_local"], "copy_at": c["copy_at"], "copy_wm": cw,
                             "direct_seq_local": last["seq_local"], "direct_copy_at": last["copy_at"], "direct_wm": dw})
    return n, hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_del69.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    t_begin = time.time()
    run = a.run_dir
    inputs = {}
    out = {"what": "E10 DEL 69 copy-mode anomaly (EXPLORATORY, saved data only)", "inputs": inputs}
    ev = [json.loads(l) for l in open(os.path.join(run, "events.jsonl")) if l.strip()]
    inputs["events"] = {"path": os.path.join(run, "events.jsonl"), "sha256": sha(os.path.join(run, "events.jsonl"))}
    snaps = {(e["stack"], e["label"]): (os.path.join(run, e["file"]), e["t_snapshot"]) for e in ev
             if e.get("type") == "snapshot" and e.get("ok")}

    # ---------------------------------------------------------------- trial records
    tr = {}
    for op in ("del", "delph", "bdt", "wipe", "pw", "lock_shm"):
        tr[op] = []
        for f in sorted(glob.glob(os.path.join(run, "e10", "*_%s.json" % op))):
            inputs.setdefault("e10_" + op, []).append({"path": f, "sha256": sha(f)})
            tr[op].append(json.load(open(f)))
    t69 = next(t for t in tr["del"][0]["trials"] if t["trial"] == 69)
    out["trial_69"] = {k: t69.get(k) for k in ("trial", "delay_s", "context", "deleted_row", "t_call", "t_visible",
                                                "t_delete_start", "t_delete_commit", "rows_deleted", "recorder_cache",
                                                "visible_for_s", "context_events_left", "dangling_successors")}
    dd = sorted(((t["t_delete_commit"] - t["t_delete_start"], "DEL", t["trial"]) for t in tr["del"][0]["trials"]), reverse=True)
    dp = sorted(((t["t_delete_commit"] - t["t_delete_start"], "DEL-PH", t["trial"]) for t in tr["delph"][0]["trials"]), reverse=True)
    allx = sorted(dd + dp, reverse=True)
    out["delete_transaction_durations"] = {
        "n": len(allx), "trial_69_s": round(t69["t_delete_commit"] - t69["t_delete_start"], 6),
        "rank_of_trial_69": 1 + [x[1:] for x in allx].index(("DEL", 69)),
        "over_0.05_s": sum(1 for x in allx if x[0] > 0.05), "median_s": round(sorted(x[0] for x in allx)[len(allx) // 2], 6),
        "slowest": [{"s": round(x[0], 4), "arm": x[1], "trial": x[2]} for x in allx[:8]]}

    # ---------------------------------------------------------------- row and event in the snapshots
    rows = {}
    for lab in ("snap_del", "snap_timing", "start"):
        db, ts = snaps[("e10s", lab)]
        inputs[lab] = {"path": db, "sha256": sha(db)}
        c = ro(db)
        r = c.execute("SELECT s.state_id, m.entity_id, s.state, s.last_updated_ts, s.old_state_id, hex(s.context_id_bin) "
                      "FROM states s LEFT JOIN states_meta m ON m.metadata_id = s.metadata_id WHERE s.state_id=?", (KEY,)).fetchone()
        e = c.execute("SELECT e.event_id, t.event_type, e.time_fired_ts, hex(e.context_id_bin) FROM events e LEFT JOIN event_types t "
                      "ON t.event_type_id = e.event_type_id WHERE e.event_id=?", (EVENT,)).fetchone()
        same_ctx = c.execute("SELECT s.state_id, s.last_updated_ts FROM states s WHERE s.context_id_bin = x'%s'" % t69["context"]).fetchall()
        rows[lab] = {"t_snapshot": ts, "state_%d" % KEY: list(r) if r else None, "event_%d" % EVENT: list(e) if e else None,
                     "states_with_trial_context": [list(x) for x in same_ctx]}
        c.close()
    out["row_in_snapshots"] = rows

    # ---------------------------------------------------------------- polls, cost, escrow, verifier
    P, C, K = {}, {}, {}
    out["polls_window"] = {}
    for st in ("e10s", "e10u"):
        for m in ("direct", "copy"):
            ch = os.path.join(run, st, "%s_chain.jsonl" % m)
            co = os.path.join(run, st, "%s_cost.jsonl" % m)
            inputs["%s_%s_chain" % (st, m)] = {"path": ch, "sha256": sha(ch)}
            inputs["%s_%s_cost" % (st, m)] = {"path": co, "sha256": sha(co)}
            polls, detail, kl = stream_polls(ch, (T_LO, T_HI) if st == "e10s" else None)
            P[(st, m)], C[(st, m)] = polls, cost(co)
            if st == "e10s":
                K[m] = kl
                for s, d in detail.items():
                    cc = C[(st, m)].get(s) or {}
                    d["cost"] = {k: cc.get(k) for k in ("ts", "copy_ms", "load_ms", "commit_ms", "append_ms", "n_nodes", "read", "ok",
                                                        "read_attempts")}
                    if cc.get("ts") is not None and cc.get("copy_ms") is not None:
                        d["poll_start_from_cost"] = round(cc["ts"] - cc["copy_ms"] / 1000.0, 6)
                        d["copy_at_minus_poll_start_s"] = round(d["copy_at"] - d["poll_start_from_cost"], 6)
                out["polls_window"][m] = {str(s): detail[s] for s in sorted(detail)}
    out["keylog_listings_of_key_%d" % KEY] = K
    esc = {}
    for m in ("direct", "copy"):
        p = os.path.join(run, "e10s", "escrow_%s" % m, "escrow.jsonl")
        inputs["escrow_" + m] = {"path": p, "bytes": os.path.getsize(p)}       # 3.4 GB each: not hashed, streamed
        esc[m] = escrow_second(p, SECOND)
    out["escrow_second_%s" % SECOND] = esc
    ver = {}
    for m in ("direct", "copy"):
        pat = re.compile(r"^e10s_%s_del_[0-9a-f]{12}\.json$" % m)
        f = [x for x in glob.glob(os.path.join(run, "verify", "e10s_%s_del_*.json" % m)) if pat.match(os.path.basename(x))][0]
        inputs["verify_del_" + m] = {"path": f, "sha256": sha(f)}
        v = json.load(open(f))
        kv = [x for x in v.get("keylog_violations") or [] if any(
            (y if isinstance(y, str) else (y or {}).get("key")) == "s:%d" % KEY
            for fld in ("removed", "suspects", "added", "changed", "likely") for y in x.get(fld) or [])]
        ver[m] = {"second_flagged": SECOND in set(v.get("flagged_seconds") or []),
                  "keylog_violations_naming_key": [{k: x.get(k) for k in ("removed", "changed", "added", "seconds", "localization")} for x in kv][:3],
                  "late_row_verdict_of_key": next(({"verdict": n_, "lb": r.get("committed_after_lower_bound_s")}
                                                   for n_, rr in (("attributable", v.get("attributable_rows")),
                                                                  ("benign_late", v.get("benign_late_rows")),
                                                                  ("unobserved_late", v.get("unobserved_late_rows")))
                                                   for r in rr or [] if r["key"] == "s:%d" % KEY), None)}
    out["verifier_del"] = ver

    # ---------------------------------------------------------------- whole-session staleness scan
    dels = []                                             # (table, key_lo, key_hi, t_commit)
    for op in ("del", "delph"):
        for t in tr[op][0]["trials"]:
            if not t.get("err"):
                k = int(t["deleted_row"]["state_id"])
                dels.append(("states", k, k, t["t_delete_commit"]))
    for d in tr["wipe"]:
        for t in d.get("trials") or []:
            for k in t.get("states_deleted") or []:
                dels.append(("states", int(k), int(k), t["t_commit"]))
            for k in t.get("events_deleted") or []:
                dels.append(("events", int(k), int(k), t["t_commit"]))
    for d in tr["pw"]:
        for var, act in (d.get("actions") or {}).items():
            if var == "PW-R":
                dels.append(("states", int(act["state_id"]), int(act["state_id"]), act["t_commit"]))
            elif var.startswith("PW-F"):
                k = int(act["insert"]["forged_state_id"])
                dels.append(("states", k, k, act["delete"]["t_commit"]))
    for d in tr["lock_shm"]:
        b = d.get("blind_delete") or {}
        if b.get("deleted_row"):
            k = int(b["deleted_row"]["state_id"])
            dels.append(("states", k, k, b["t_delete_commit"]))
    infw = json.load(open(glob.glob(os.path.join(run, "e10", "*_inflate_window.json"))[0]))
    b3 = json.load(open(glob.glob(os.path.join(run, "e10", "*_purge_entities.json"))[0]))
    dels.append(("states", int(infw["first_key"]), int(infw["last_key"]), b3["t"]))
    res = {}
    for st in ("e10s", "e10u"):
        n, hits = scan(P[(st, "direct")], P[(st, "copy")], C[(st, "copy")], C[(st, "direct")], dels if st == "e10s" else [])
        ci = stats.clopper_pearson(len({h["copy_seq_local"] for h in hits}), n) if n else None
        res[st] = {"copy_polls_checked": n, "hits": hits, "polls_with_a_hit": len({h["copy_seq_local"] for h in hits}),
                   "rate_exact_95": [ci["ci_lo"], ci["ci_hi"]] if ci else None}
    tot_n = res["e10s"]["copy_polls_checked"] + res["e10u"]["copy_polls_checked"]
    tot_k = res["e10s"]["polls_with_a_hit"] + res["e10u"]["polls_with_a_hit"]
    ci = stats.clopper_pearson(tot_k, tot_n)
    res["both_stacks"] = {"copy_polls_checked": tot_n, "polls_with_a_hit": tot_k, "rate_exact_95": [ci["ci_lo"], ci["ci_hi"]]}
    res["deletions_considered"] = len(dels)
    out["staleness_scan_whole_session"] = res
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["wall_s"] = round(time.time() - t_begin, 1)
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
