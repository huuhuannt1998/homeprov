#!/usr/bin/env python3
"""E10 exploratory: the benign floor (H16) re-scoped, the routine operations B1-B4 (H11-H14) as segment sets, the INF-W
seconds, and an O-MIG consistency count. Labelled EXPLORATORY; the confirmatory numbers are the frozen scorer's
(exp/out/e10_main_score.json arms.floor, arms.ROUTINE; exp/out/e10_main_migration_offline.json).

Floor  The scorer's floor (arms.floor) subtracts from the floor verification's flagged seconds the trial seconds and the
       seconds inside block windows [begin - 60 s, end + 120 s]. The verifier lists flagged seconds over the WHOLE chain,
       and B1 (entity-id rename) and B3 (entity history purge) change rows far outside their block windows. Here the
       scorer's own rule is recomputed (its 'unexplained' count must reproduce), then the unexplained seconds are split
       into (a) seconds holding a row of the renamed entity (b1_end snapshot), (b) seconds holding a row of the purged
       junk entity (b2_end snapshot), (c) the rest, each by location (before the session start t0 / inside the session).
B1-B4  Segment sets: B1's predicted seconds/minutes/hours (the scorer's entity_segments rule: rows of the renamed entity
       timestamped >= 10 s before the rename, b1_end) against the seconds newly flagged and the minute/hour attributable
       violations new in the b1 verification relative to a_end; B2 = b1 -> b2 differences; B3 likewise against b2 with
       the junk entity (b2_end); B4 = b3 -> b4 differences; excused violations by marker and rule.
INF-W  The junk rows' seconds already flagged or holding an attributable row at a_end (before B3), and why.
O-MIG  Distinct seconds holding a state row, an event row, or any row in the final snapshot, next to the O-MIG counts.

Large verifier outputs are read by slicing single top-level fields (indented, key-sorted JSON), never loaded whole.
Snapshots are opened mode=ro&immutable=1 (their -wal files are empty). Output: one new JSON file.

    python3 exp/sp2027/r16_e10_routine_floor.py [--run-dir DIR] [--out exp/out/r16_e10_routine_floor.json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import mmap
import os
import re
import sqlite3
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
MONITORS = ("direct", "copy")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def top_slice(path, key):
    with open(path, "rb") as fh:
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        tag = b'\n "%s": ' % key.encode()
        i = m.find(tag)
        if i < 0:
            return None
        j = m.find(b'\n "', i + len(tag))
        if j < 0:
            j = m.rfind(b"\n}")
        return json.loads(m[i + len(tag):j].decode().rstrip().rstrip(","))


def ro(db):
    p = db + "-wal"
    assert not os.path.exists(p) or os.path.getsize(p) == 0, p
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)


def jl(path):
    return [json.loads(l) for l in open(path) if l.strip().startswith("{")]


def vfile(run, m, lab):
    pat = re.compile(r"^e10s_%s_%s_[0-9a-f]{12}\.json$" % (m, lab))
    fs = [x for x in glob.glob(os.path.join(run, "verify", "e10s_%s_%s_*.json" % (m, lab))) if pat.match(os.path.basename(x))]
    assert len(fs) == 1, (m, lab, fs)
    return fs[0]


def vsets(path):
    """flagged seconds and (gran, seg) sets of attributable violations, and excused violations by marker/rule."""
    fl = set(top_slice(path, "flagged_seconds") or [])
    viol = top_slice(path, "violations") or []
    segs = {"second": set(), "minute": set(), "hour": set()}
    for x in viol:
        if x.get("violation") and x.get("attributable") and x.get("gran") in segs:
            segs[x["gran"]].add(int(x["seg"]))
    del viol
    exc = top_slice(path, "excused_violations") or []
    ex = collections.Counter((x.get("gran"), (x.get("excused_by") or {}).get("marker"), (x.get("excused_by") or {}).get("rule"))
                             for x in exc)
    exc_segs = {(x.get("gran"), int(x["seg"])) for x in exc if x.get("gran") in ("second", "minute", "hour")}
    del exc
    return {"flagged": fl, "segs": segs, "excused": ex, "excused_segs": exc_segs}


def segsets(ts_list):
    return {"second": {int(t) for t in ts_list}, "minute": {int(t // 60) for t in ts_list}, "hour": {int(t // 3600) for t in ts_list}}


def cmp(pred, obs, sample=20):
    return {"predicted": len(pred), "observed": len(obs), "both": len(pred & obs),
            "predicted_not_observed": len(pred - obs), "observed_not_predicted": len(obs - pred),
            "predicted_not_observed_sample": sorted(pred - obs)[:sample], "observed_not_predicted_sample": sorted(obs - pred)[:sample]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_routine_floor.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    t_begin = time.time()
    run = a.run_dir
    inputs = {}
    out = {"what": "E10 floor re-scoped, B1-B4 segment sets, INF-W seconds, O-MIG consistency (EXPLORATORY)", "inputs": inputs}
    evp = os.path.join(run, "events.jsonl")
    inputs["events"] = {"path": evp, "sha256": sha(evp)}
    ev = jl(evp)

    def snap(label):
        for e in ev:
            if e.get("type") == "snapshot" and e.get("ok") and e.get("stack") == "e10s" and e.get("label") == label:
                return os.path.join(run, e["file"]), e["t_snapshot"]
        return None, None

    t0 = float(open(os.path.join(run, "e10s", "t_start")).read().strip())
    res = {}
    for op in ("bdt", "lowkey", "ctx", "del", "delph", "wipe", "pw", "rename_entity", "purge_entities", "inflate_window"):
        res[op] = []
        for f in sorted(glob.glob(os.path.join(run, "e10", "*_%s.json" % op))):
            inputs.setdefault("e10_" + op, []).append({"path": f, "sha256": sha(f)})
            res[op].append(json.load(open(f)))
    trials = lambda op: [t for d in res[op] for t in d.get("trials", []) if not t.get("err")]   # noqa: E731

    # ---------------------------------------------------------------- entity seconds from the snapshots
    b1 = res["rename_entity"][0]
    b3 = res["purge_entities"][0]
    db1, ts1 = snap("b1_end")
    db2, ts2 = snap("b2_end")
    dbf, tsf = snap("final")
    for lab, p in (("b1_end", db1), ("b2_end", db2), ("final", dbf)):
        inputs[lab] = {"path": p, "sha256": sha(p)}
    q = "SELECT s.last_updated_ts FROM states s JOIN states_meta m ON m.metadata_id = s.metadata_id WHERE m.entity_id=?"
    c = ro(db1)
    porch_all = [r[0] for r in c.execute(q, (b1["new_entity_id"],)) if isinstance(r[0], (int, float))]
    c.close()
    c = ro(db2)
    junk_all = [r[0] for e in b3["entity_ids"] for r in c.execute(q, (e,)) if isinstance(r[0], (int, float))]
    c.close()
    porch_pred = segsets([t for t in porch_all if t < b1["t"] - 10.0])     # the scorer's entity_segments rule
    junk_pred = segsets([t for t in junk_all if t < b3["t"] - 10.0])
    porch_any_sec = {int(t) for t in porch_all if t < b1["t"]}
    junk_any_sec = {int(t) for t in junk_all}
    out["entities"] = {"renamed": {"entity_id": b1["entity_id"], "new_entity_id": b1["new_entity_id"], "t_rename": b1["t"],
                                   "rows": len(porch_all), "predicted": {g: len(v) for g, v in porch_pred.items()},
                                   "rows_in_session": sum(1 for t in porch_all if t >= t0)},
                       "purged": {"entity_ids": b3["entity_ids"], "t_purge": b3["t"], "rows": len(junk_all),
                                  "predicted": {g: len(v) for g, v in junk_pred.items()},
                                  "first_ts": min(junk_all) if junk_all else None, "last_ts": max(junk_all) if junk_all else None}}

    # ---------------------------------------------------------------- verification sets
    VS = {}
    for m in MONITORS:
        for lab in ("a_end", "b1", "b2", "b3", "b4", "floor"):
            p = vfile(run, m, lab)
            inputs["verify_%s_%s" % (m, lab)] = {"path": p, "sha256": sha(p)}
            VS[(m, lab)] = vsets(p)

    # ---------------------------------------------------------------- routine operations
    rt = {}
    for m in MONITORS:
        A, B1, B2, B3, B4 = (VS[(m, x)] for x in ("a_end", "b1", "b2", "b3", "b4"))
        new_b1_sec = {int(s) for s in B1["flagged"] - A["flagged"]}
        r = {"B1": {"second_flagged_new_vs_a_end": cmp(porch_pred["second"], new_b1_sec),
                    "minute_violations_new_vs_a_end": cmp(porch_pred["minute"], B1["segs"]["minute"] - A["segs"]["minute"]),
                    "hour_violations_new_vs_a_end": cmp(porch_pred["hour"], B1["segs"]["hour"] - A["segs"]["hour"]),
                    "second_violations_new_vs_a_end": cmp(porch_pred["second"], B1["segs"]["second"] - A["segs"]["second"]),
                    "second_flagged_total_in_b1": cmp(porch_pred["second"], {int(s) for s in B1["flagged"]} & porch_pred["second"]),
                    "minute_violated_total_in_b1": cmp(porch_pred["minute"], B1["segs"]["minute"] & porch_pred["minute"]),
                    "hour_violated_total_in_b1": cmp(porch_pred["hour"], B1["segs"]["hour"] & porch_pred["hour"]),
                    "excused_in_b1": {"|".join(map(str, k)): v for k, v in B1["excused"].items()},
                    "predicted_segments_excused": sum(1 for g in ("second", "minute", "hour") for s in porch_pred[g]
                                                      if (g, s) in B1["excused_segs"])},
             "B2": {"flagged_equal_b1": B2["flagged"] == B1["flagged"],
                    "segs_equal_b1": all(B2["segs"][g] == B1["segs"][g] for g in B1["segs"]),
                    "flagged_added": len(B2["flagged"] - B1["flagged"]), "flagged_removed": len(B1["flagged"] - B2["flagged"])},
             "B3": {"second_flagged_new_vs_b2": cmp(junk_pred["second"], {int(s) for s in B3["flagged"] - B2["flagged"]}),
                    "minute_violations_new_vs_b2": cmp(junk_pred["minute"], B3["segs"]["minute"] - B2["segs"]["minute"]),
                    "hour_violations_new_vs_b2": cmp(junk_pred["hour"], B3["segs"]["hour"] - B2["segs"]["hour"]),
                    "junk_seconds_flagged_before_b3_in_b2": len({str(s) for s in junk_pred["second"]} & B2["flagged"]),
                    "junk_minutes_violated_before_b3_in_b2": len(junk_pred["minute"] & B2["segs"]["minute"]),
                    "junk_hours_violated_before_b3_in_b2": len(junk_pred["hour"] & B2["segs"]["hour"]),
                    "junk_seconds_flagged_at_a_end": len({str(s) for s in junk_pred["second"]} & A["flagged"]),
                    "junk_minutes_violated_at_a_end": len(junk_pred["minute"] & A["segs"]["minute"]),
                    "junk_hours_violated_at_a_end": len(junk_pred["hour"] & A["segs"]["hour"]),
                    "junk_seconds_flagged_in_b3": len({str(s) for s in junk_pred["second"]} & B3["flagged"]),
                    "junk_minutes_violated_in_b3": len(junk_pred["minute"] & B3["segs"]["minute"]),
                    "junk_hours_violated_in_b3": len(junk_pred["hour"] & B3["segs"]["hour"]),
                    "excused_in_b3": {"|".join(map(str, k)): v for k, v in B3["excused"].items()}},
             "B4": {"flagged_equal_b3": B4["flagged"] == B3["flagged"],
                    "segs_equal_b3": all(B4["segs"][g] == B3["segs"][g] for g in B3["segs"]),
                    "flagged_added": len(B4["flagged"] - B3["flagged"]), "flagged_removed": len(B3["flagged"] - B4["flagged"])}}
        rt[m] = r
    out["routine"] = rt

    # ---------------------------------------------------------------- INF-W at a_end
    infw = res["inflate_window"][0]
    w0, w1 = infw["t_start"], infw["t_end"]
    iw = {"t_start": w0, "t_end": w1, "junk_rows": len(junk_all)}
    for m in MONITORS:
        p = vfile(run, m, "a_end")
        ar = top_slice(p, "attributable_rows") or []
        sel = [x for x in ar if x.get("ts") is not None and w0 - 60 <= x["ts"] <= w1 + 120]
        why = collections.Counter(w.get("why") for x in sel for w in (x.get("why") or [])[:1])
        fl = VS[(m, "a_end")]["flagged"]
        iw[m] = {"flagged_seconds_in_window": sum(1 for s in fl if w0 - 60 <= int(s) <= w1 + 120),
                 "flagged_junk_seconds": len({str(s) for s in junk_any_sec} & fl),
                 "attributable_rows_in_window": len(sel), "first_why": dict(why),
                 "attributable_rows_sample": [{k: x.get(k) for k in ("key", "ts", "committed_after_lower_bound_s")} for x in sel[:5]]}
    out["inf_w_at_a_end"] = iw

    # ---------------------------------------------------------------- floor
    touched = set()
    for op in ("bdt", "lowkey"):
        touched |= {str(int(t["forged_row_ts"])) for t in trials(op)}
    touched |= {str(int(t["inserted_ts"])) for t in trials("ctx")}
    touched |= {str(int(t["unlock_row"]["ts"])) for t in trials("ctx")}
    touched |= {str(int((t.get("deleted_row") or {}).get("ts", 0))) for t in trials("del") + trials("delph")}
    touched |= {str(t["second"]) for t in trials("wipe")}
    for d in res["pw"]:
        for act in (d.get("actions") or {}).values():
            if isinstance(act.get("insert"), dict):
                touched.add(str(int(act["insert"]["forged_row_ts"])))
    windows, open_ = [], {}
    for e in ev:
        if e.get("type") == "block_begin":
            open_[e["block"]] = e["ts"]
        elif e.get("type") == "block_end" and e.get("block") in open_:
            b = e["block"]
            if b.startswith(("A4_", "A5_", "A6_", "A7_", "B")):
                windows.append((b, open_[b] - 60, e["ts"] + 120))
    fl_out = {"t0": t0, "t_final_snapshot": tsf, "touched_trial_seconds": len(touched), "block_windows": windows}
    # every key a trial wrote, deleted or changed (A arms), to test keylog co-flagging of the remaining seconds
    tkeys = set()
    for t in trials("bdt") + trials("lowkey"):
        tkeys.add("s:%s" % t["forged_state_id"])
    for t in trials("ctx"):
        tkeys |= {"e:%s" % t["inserted_event_id"], "s:%s" % t["unlock_row"]["state_id"]}
    for t in trials("del") + trials("delph"):
        tkeys.add("s:%s" % t["deleted_row"]["state_id"])
    for t in trials("wipe"):
        tkeys |= {"s:%s" % k for k in t.get("states_deleted") or []} | {"e:%s" % k for k in t.get("events_deleted") or []}
    kl_by_sec = {}
    for m in MONITORS:
        kv = top_slice(vfile(run, m, "a_end"), "keylog_violations") or []
        d = collections.defaultdict(list)
        for x in kv:
            keys = set()
            for f in ("removed", "suspects", "added", "changed", "likely"):
                for y in x.get(f) or []:
                    keys.add(y if isinstance(y, str) else y.get("key"))
            for s in x.get("seconds") or []:
                d[str(s)].append(keys)
        kl_by_sec[m] = d
    for m in MONITORS:
        F = VS[(m, "floor")]["flagged"]
        U = sorted((s for s in F - touched if not any(lo <= int(s) <= hi for _n, lo, hi in windows)), key=int)
        Uset = set(U)
        in_sess = lambda s: t0 <= int(s) <= tsf   # noqa: E731
        porch_s = {str(s) for s in porch_any_sec}
        junk_s = {str(s) for s in junk_any_sec}
        a_ = [s for s in U if s in porch_s]
        b_ = [s for s in U if s not in porch_s and s in junk_s]
        rest = [s for s in U if s not in porch_s and s not in junk_s]
        fl_out[m] = {"flagged_seconds": len(F), "scorer_rule_unexplained": len(U),
                     "flagged_in_session": sum(1 for s in F if in_sess(s)),
                     "flagged_before_t0": sum(1 for s in F if int(s) < t0),
                     "unexplained_holding_renamed_entity_row": {"n": len(a_), "in_session": sum(1 for s in a_ if in_sess(s)),
                                                                "before_t0": sum(1 for s in a_ if int(s) < t0)},
                     "unexplained_holding_purged_entity_row": {"n": len(b_), "in_session": sum(1 for s in b_ if in_sess(s)),
                                                               "before_t0": sum(1 for s in b_ if int(s) < t0)},
                     "unexplained_rest": {"n": len(rest), "in_session": sum(1 for s in rest if in_sess(s)),
                                          "before_t0": sum(1 for s in rest if int(s) < t0), "seconds": rest[:200],
                                          "flagged_already_at_a_end": sum(1 for s in rest if s in VS[(m, "a_end")]["flagged"]),
                                          "in_an_a_end_keylog_violation_naming_a_trial_key": sum(
                                              1 for s in rest if any(ks & tkeys for ks in kl_by_sec[m].get(s, []))),
                                          "in_an_a_end_keylog_violation": sum(1 for s in rest if kl_by_sec[m].get(s)),
                                          "not_explained_by_trial_keylog_ranges": [s for s in rest if not any(
                                              ks & tkeys for ks in kl_by_sec[m].get(s, []))]}}
    # keys named by the a_end keylog violations of the seconds not explained by a trial key, with the rows' entity and
    # old_state_id in snap_a_end (a NULL old_state_id on a lock row after a wiped actuation is WIPE's disconnect)
    dba, _tsa = snap("snap_a_end")
    inputs["snap_a_end"] = {"path": dba, "sha256": sha(dba)}
    ca = ro(dba)
    for m in MONITORS:
        detail = []
        for s in fl_out[m]["unexplained_rest"]["not_explained_by_trial_keylog_ranges"]:
            keys = sorted({k for ks in kl_by_sec[m].get(s, []) for k in ks if k})
            rows = []
            for k in keys[:12]:
                t_, n_ = k.split(":")
                if t_ == "s":
                    r = ca.execute("SELECT s.state_id, m.entity_id, s.state, s.old_state_id, s.last_updated_ts FROM states s "
                                   "LEFT JOIN states_meta m ON m.metadata_id = s.metadata_id WHERE s.state_id=?", (int(n_),)).fetchone()
                    rows.append({"key": k, "row": list(r) if r else None})
                else:
                    r = ca.execute("SELECT e.event_id, t.event_type, e.time_fired_ts FROM events e LEFT JOIN event_types t "
                                   "ON t.event_type_id = e.event_type_id WHERE e.event_id=?", (int(n_),)).fetchone()
                    rows.append({"key": k, "row": list(r) if r else None})
            detail.append({"second": s, "keys": keys[:12], "rows": rows})
        fl_out[m]["unexplained_rest"]["not_explained_detail"] = detail
    ca.close()
    wipe_secs = sorted(int(t["second"]) for t in trials("wipe"))
    fl_out["wipe_seconds"] = wipe_secs
    # the same state rows before WIPE (snap_timing): was their old_state_id a state row WIPE deleted?
    dbt, _tst = snap("snap_timing")
    inputs["snap_timing"] = {"path": dbt, "sha256": sha(dbt)}
    ct = ro(dbt)
    wiped_states = {int(k) for t in trials("wipe") for k in t.get("states_deleted") or []}
    for m in MONITORS:
        n_succ, n_state_rows = 0, 0
        for dd in fl_out[m]["unexplained_rest"]["not_explained_detail"]:
            for rr in dd["rows"]:
                if not rr["key"].startswith("s:"):
                    continue
                n_state_rows += 1
                r = ct.execute("SELECT old_state_id FROM states WHERE state_id=?", (int(rr["key"][2:]),)).fetchone()
                rr["old_state_id_before_wipe"] = r[0] if r else None
                rr["old_state_id_was_wiped"] = bool(r and r[0] in wiped_states)
                n_succ += rr["old_state_id_was_wiped"]
        fl_out[m]["unexplained_rest"]["not_explained_state_rows"] = n_state_rows
        fl_out[m]["unexplained_rest"]["not_explained_state_rows_successor_of_a_wiped_row"] = n_succ
        fl_out[m]["unexplained_rest"]["not_explained_seconds_with_a_successor_of_a_wiped_row"] = sum(
            1 for dd in fl_out[m]["unexplained_rest"]["not_explained_detail"] if any(rr.get("old_state_id_was_wiped") for rr in dd["rows"]))
    ct.close()
    # B1 predicted minutes/hours not violated in b1: their entries in the b1 verification's violations list
    for m in MONITORS:
        miss = {("minute", s) for s in rt[m]["B1"]["minute_violated_total_in_b1"]["predicted_not_observed_sample"]} | \
               {("hour", s) for s in rt[m]["B1"]["hour_violated_total_in_b1"]["predicted_not_observed_sample"]}
        viol = top_slice(vfile(run, m, "b1"), "violations") or []
        ent = [{k: x.get(k) for k in ("gran", "seg", "violation", "attributable", "ambiguous", "mechanism", "rule", "n_late",
                                      "anchored_n", "n_sealed_now", "sealed_at", "conflicted")}
               for x in viol if (x.get("gran"), int(x["seg"])) in miss]
        del viol
        rt[m]["B1"]["predicted_not_violated_entries_in_b1_violations"] = ent
        rt[m]["B1"]["predicted_not_violated_segments"] = sorted([list(x) for x in miss])
    out["floor"] = fl_out

    # ---------------------------------------------------------------- O-MIG consistency
    c = ro(dbf)
    one = lambda sql, *p: c.execute(sql, p).fetchone()[0]   # noqa: E731
    out["o_mig_final_snapshot"] = {
        "t_snapshot": tsf,
        "distinct_seconds_with_state_row": one("SELECT COUNT(DISTINCT CAST(last_updated_ts AS INTEGER)) FROM states WHERE last_updated_ts <= ?", tsf),
        "distinct_seconds_with_event_row": one("SELECT COUNT(DISTINCT CAST(time_fired_ts AS INTEGER)) FROM events WHERE time_fired_ts <= ?", tsf),
        "distinct_seconds_with_any_row": one("SELECT COUNT(*) FROM (SELECT CAST(last_updated_ts AS INTEGER) s FROM states WHERE last_updated_ts <= ? "
                                             "UNION SELECT CAST(time_fired_ts AS INTEGER) FROM events WHERE time_fired_ts <= ?)", tsf, tsf),
        "states_rows": one("SELECT COUNT(*) FROM states"), "events_rows": one("SELECT COUNT(*) FROM events")}
    c.close()
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["wall_s"] = round(time.time() - t_begin, 1)
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
