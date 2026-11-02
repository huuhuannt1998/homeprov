#!/usr/bin/env python3
"""E10 exploratory: every per-trial deviation of the insertion and deletion arms (A1-BDT, A2-CTX, A3-DEL, A3-DEL-PH),
with the saved data that can explain it. Labelled EXPLORATORY: the confirmatory outcome of each trial is the frozen
scorer's (exp/out/e10_main_score.json, arms.<ARM>.per_trial); nothing here changes it.

For every trial and monitor this file lists, next to the scorer's outcome, prediction and agreement:
  insertion (BDT, CTX)
    - the verifier's own verdict of the inserted row (attributable / benign_late / unobserved_late / none) and its
      committed_after_lower_bound_s, from the scorer's cached 'del' verification (<run>/verify/e10s_<m>_del_*.json);
    - whether the row's second is flagged, and every other trial row (BDT, CTX, DEL, DEL-PH) timestamped in the same
      second with that row's verifier verdict;
    - the poll the scorer's prediction used (last observable copy_at before the insertion committed), its copy duration
      (cost log copy_ms) and whether its watermark already held the row's key (wm >= key: the copy contained the row);
    - the design's own rule (drafts/round13/E10_DESIGN.md section 4: 'the latest observable copy before c, among the
      polls whose watermark is below its key'), i.e. the wm-aware lower bound, and the prediction it gives;
    - the actual lag at commit (t_commit - ts, from the trial record).
  deletion (DEL, DEL-PH)
    - the polls whose copy began in [visible, deleted] (copy_at, copy_ms, approximate copy end copy_at + copy_ms);
    - which poll's keylog first listed the deleted row's key WITH the row's own second (the original row) and which
      listed the key with another second (the key reused by a later row: SQLite reassigns a freed largest key);
    - detected vs observed-original (H3's 'iff an observable poll read the row', free of the key-reuse confound).

Inputs are read only (the run folder is never written; chains and logs are streamed). Output: one new JSON file,
opened with mode 'x'.

    python3 exp/sp2027/r16_e10_trial_deviations.py [--run-dir DIR] [--out exp/out/r16_e10_trial_deviations.json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RUN = "/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10/e10_main"
SCORE = os.path.join(ROOT, "exp", "out", "e10_main_score.json")
MONITORS = ("direct", "copy")
LATE_BOUND, AMBIGUOUS_S = 30.0, 0.05


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def kparse(key):
    t, k = key.split(":")
    return ("states" if t == "s" else "events"), int(k)


def load_polls(chain, targets):
    """Stream a chain: every poll (own record or backlog head) by seq_local, and keylog observations of target keys."""
    polls, obs = {}, collections.defaultdict(list)
    epochs_seen, max_seq, max_ts, records = 0, 0, None, 0
    with open(chain) as fh:
        for line in fh:
            if not line.strip():
                continue
            cr = json.loads(line)
            p = cr.get("payload") or {}
            if p.get("observer") != "external-monitor" or "coverage" not in p or "seq_local" not in p:
                continue
            records += 1
            s_ = int(p["seq_local"])
            cont = isinstance(p.get("part"), int) and p["part"] >= 2
            same = s_ in polls and polls[s_].get("ts") == p.get("ts")
            if s_ <= max_seq and not cont and not same and (max_ts is None or (p.get("ts") or 0) > max_ts):
                epochs_seen += 1                     # a counter restart (expected 0: no monitor restart)
            max_seq = max(max_seq, s_)
            heads = [(h, False) for h in (p.get("backlog") or [])] + [(p, True)]
            for h, own in heads:
                if h.get("ts") is not None:
                    max_ts = h["ts"] if max_ts is None else max(max_ts, h["ts"])
                s = int(h["seq_local"])
                cur = polls.get(s)
                if cur is None or (cur.get("through") is None and h.get("through") is not None) \
                        or (own and not cur.get("own") and h.get("through") is not None):
                    polls[s] = {"seq_local": s, "ts": h.get("ts"), "copy_at": h.get("copy_at"), "wm": h.get("wm"),
                                "since": h.get("since"), "through": h.get("through"),
                                "unobservable": bool(h.get("evidence_unobservable") or h.get("unobservable")),
                                "reason": h.get("reason") or (h.get("unobservable") if isinstance(h.get("unobservable"), str) else None),
                                "own": own or bool(cur and cur.get("own")),
                                "in_backlog": bool(cur and cur.get("in_backlog"))}
                    cur = polls[s]
                if not own and not h.get("keylog_part"):
                    cur["in_backlog"] = True
                for t, es in (h.get("keylog") or {}).items():
                    for e in es if isinstance(es, list) else [es]:
                        lo = int((e or {}).get("from", 0))
                        for x in (e or {}).get("rows") or []:
                            k = lo + int(x[0])
                            if (t, k) in targets:
                                obs[(t, k)].append({"seq_local": s, "row_second": x[2] if len(x) > 2 else None})
    return polls, obs, {"records": records, "polls": len(polls), "counter_restarts": epochs_seen}


def load_cost(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("{"):
                d = json.loads(line)
                if "seq_local" in d:
                    out[int(d["seq_local"])] = {"copy_ms": d.get("copy_ms"), "ts": d.get("ts"), "read": d.get("read")}
    return out


class Timeline:
    def __init__(self, polls, cost):
        self.polls, self.cost = polls, cost
        self.obs = sorted((p for p in polls.values() if not p["unobservable"] and p.get("copy_at") is not None
                           and isinstance(p.get("wm"), dict)), key=lambda p: p["copy_at"])

    def info(self, p, table=None, key=None):
        if p is None:
            return None
        c = self.cost.get(p["seq_local"]) or {}
        cm = c.get("copy_ms")
        d = {"seq_local": p["seq_local"], "copy_at": p["copy_at"], "copy_ms": cm,
             "copy_end_approx": (p["copy_at"] + cm / 1000.0) if cm is not None else None, "read": c.get("read")}
        if table is not None:
            w = (p.get("wm") or {}).get(table)
            d["wm"] = w
            d["held_key"] = (w is not None and w >= key)
        return d

    def last_before(self, t, pred=None):
        best = None
        for p in self.obs:
            if p["copy_at"] >= t:
                break
            if pred is None or pred(p):
                best = p
        return best

    def last_where(self, pred):
        best = None
        for p in self.obs:
            if pred(p):
                best = p
        return best

    def first_sealing(self, sec):
        for p in self.obs:
            th, si = p.get("through"), p.get("since")
            if th is not None and int(th) >= sec + 1 and (si is None or int(si) <= sec):
                return p
        return None

    def copies_in(self, a, b):
        return [p for p in self.obs if a <= p["copy_at"] <= b]


def verdict_index(v):
    idx = {}
    for name, rows in (("attributable", v.get("attributable_rows")), ("benign_late", v.get("benign_late_rows")),
                       ("unobserved_late", v.get("unobserved_late_rows"))):
        for r in rows or []:
            idx.setdefault(r["key"], {"verdict": name, "committed_after_lower_bound_s": r.get("committed_after_lower_bound_s"),
                                      "why": [w.get("why") for w in r.get("why") or []][:4]})
    return idx


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN)
    ap.add_argument("--out", default=os.path.join(ROOT, "exp", "out", "r16_e10_trial_deviations.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("REFUSING: %s exists" % a.out)
    t_begin = time.time()
    score = json.load(open(SCORE))
    inputs = {"score": {"path": os.path.relpath(SCORE, ROOT), "sha256": sha(SCORE)}}

    # trial records (for co-located rows and deletion times)
    trials = {}
    for op in ("bdt", "ctx", "del", "delph"):
        fs = sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_%s.json" % op)))
        assert len(fs) == 1, (op, fs)
        inputs["trials_" + op] = {"path": fs[0], "sha256": sha(fs[0])}
        trials[op] = {t["trial"]: t for t in json.load(open(fs[0]))["trials"] if not t.get("err")}

    rows_by_second = collections.defaultdict(list)   # second -> [(arm, trial, level, key)]
    for t in trials["bdt"].values():
        rows_by_second[int(t["forged_row_ts"])].append(("BDT", t["trial"], t["age_s"], "s:%s" % t["forged_state_id"]))
    for t in trials["ctx"].values():
        rows_by_second[int(t["inserted_ts"])].append(("CTX", t["trial"], t["delay_s"], "e:%s" % t["inserted_event_id"]))
        rows_by_second[int(t["unlock_row"]["ts"])].append(("CTX-actuation", t["trial"], t["delay_s"], "s:%s" % t["unlock_row"]["state_id"]))
    for op, arm in (("del", "DEL"), ("delph", "DEL-PH")):
        for t in trials[op].values():
            r0 = t["deleted_row"]
            rows_by_second[int(r0["ts"])].append((arm, t["trial"], t.get("delay_s"), "s:%s" % r0["state_id"]))

    targets = set()
    for op, keyf in (("bdt", lambda t: ("states", t["forged_state_id"])), ("ctx", lambda t: ("events", t["inserted_event_id"])),
                     ("del", lambda t: ("states", t["deleted_row"]["state_id"])), ("delph", lambda t: ("states", t["deleted_row"]["state_id"]))):
        for t in trials[op].values():
            targets.add(keyf(t))

    TL, V, VS = {}, {}, {}
    chain_info = {}
    for m in MONITORS:
        chain = os.path.join(a.run_dir, "e10s", "%s_chain.jsonl" % m)
        cost = os.path.join(a.run_dir, "e10s", "%s_cost.jsonl" % m)
        vf = sorted(glob.glob(os.path.join(a.run_dir, "verify", "e10s_%s_del_*.json" % m)))
        assert len(vf) == 1, vf
        inputs["chain_" + m] = {"path": chain, "sha256": sha(chain)}
        inputs["cost_" + m] = {"path": cost, "sha256": sha(cost)}
        inputs["verify_del_" + m] = {"path": vf[0], "sha256": sha(vf[0])}
        polls, kobs, ci = load_polls(chain, targets)
        chain_info[m] = ci
        TL[m] = (Timeline(polls, load_cost(cost)), kobs)
        v = json.load(open(vf[0]))
        V[m] = verdict_index(v)
        VS[m] = set(v.get("flagged_seconds") or [])

    out = {"what": "E10 per-trial deviations of A1-BDT, A2-CTX, A3-DEL, A3-DEL-PH with candidate explanations "
                   "(EXPLORATORY; the confirmatory outcome is the frozen scorer's)",
           "inputs": inputs, "chain_info": chain_info, "insertion": {}, "deletion": {}}

    # ---------------------------------------------------------------- insertions
    for arm, op, lev_field in (("BDT", "bdt", "age_s"), ("CTX", "ctx", "delay_s")):
        rows = []
        for r in score["arms"][arm]["per_trial"]:
            tr = trials[op][r["trial"]]
            table, k = kparse(r["key"])
            sec = int(r["ts"])
            row = {"trial": r["trial"], "level": r["level"], "key": r["key"], "ts": r["ts"], "t_commit": r["t_commit"],
                   "lag_at_commit_s": round(r["t_commit"] - r["ts"], 6), "second": str(sec),
                   "commit_duration_s": (round(tr["t_commit"] - tr["t_insert"], 6) if tr.get("t_insert") else None)}
            others = [x for x in rows_by_second[sec] if x[3] != r["key"]]
            for m in MONITORS:
                tl, _kobs = TL[m]
                sc = r[m]
                q_s = tl.last_before(r["t_commit"])
                q_d = tl.last_where(lambda p, table=table, k=k: (p["wm"].get(table) if p["wm"].get(table) is not None else -1) < k)
                seal = tl.first_sealing(sec)
                lat_d = (q_d["copy_at"] - r["ts"]) if q_d else None
                if seal is None or ((seal["wm"].get(table) or -1) >= k):
                    dpred = "no_evidence"
                else:
                    dpred = "detected" if (lat_d is not None and lat_d > LATE_BOUND) else "reported_late"
                amb50 = any(abs(p["copy_at"] - r["t_commit"]) < AMBIGUOUS_S for p in tl.copies_in(r["t_commit"] - 1, r["t_commit"] + 1))
                vr = V[m].get(r["key"]) or {}
                own = vr.get("verdict")
                row_level = {"attributable": "detected", "benign_late": "reported_late",
                             "unobserved_late": "unknown"}.get(own, "no_evidence")
                co = [{"arm": x[0], "trial": x[1], "level": x[2], "key": x[3],
                       "verdict": (V[m].get(x[3]) or {}).get("verdict")} for x in others]
                d = {"scorer": {"outcome": sc["outcome"], "predicted": sc["predicted"], "lower_bound_s": sc["lower_bound_s"],
                                "agrees": sc["agrees"]},
                     "verifier_row": {"verdict": own, "committed_after_lower_bound_s": vr.get("committed_after_lower_bound_s"),
                                      "why": vr.get("why")},
                     "second_flagged": str(sec) in VS[m],
                     "colocated_trial_rows": co,
                     "scorer_poll": tl.info(q_s, table, k),
                     "design_rule": {"poll": tl.info(q_d, table, k), "lower_bound_s": lat_d, "sealing_poll": tl.info(seal, table, k),
                                     "predicted": dpred, "ambiguous_50ms": amb50},
                     "row_level_outcome": row_level}
                cls = None
                if sc["agrees"] is False:
                    if own != "attributable" and str(sec) in VS[m] and any(c["verdict"] == "attributable" for c in co):
                        cls = "shared_second_with_another_trials_attributable_row"
                    elif m == "copy" and q_s is not None and d["scorer_poll"]["held_key"]:
                        cls = "copy_began_before_commit_and_held_the_row"
                    elif m == "copy" and seal is not None and d["design_rule"]["sealing_poll"]["held_key"] and sc["outcome"] == "no_evidence":
                        cls = "sealing_copy_held_the_row"
                    else:
                        cls = "other"
                d["deviation_class"] = cls
                row[m] = d
            rows.append(row)
        out["insertion"][arm] = rows

    # ---------------------------------------------------------------- deletions
    for arm, op in (("DEL", "del"), ("DEL-PH", "delph")):
        rows = []
        for r in score["arms"][arm]["per_trial"]:
            tr = trials[op][r["trial"]]
            r0 = tr["deleted_row"]
            k, sec = int(r0["state_id"]), int(r0["ts"])
            row = {"trial": r["trial"], "delay_s": r["delay_s"], "key": r["key"], "ts": r0["ts"], "t_visible": tr["t_visible"],
                   "t_delete_commit": tr["t_delete_commit"], "visible_for_s": r["visible_for_s"]}
            for m in MONITORS:
                tl, kobs = TL[m]
                sc = r[m]
                ins = [tl.info(p, "states", k) for p in tl.copies_in(tr["t_visible"] - 1.0, tr["t_delete_commit"] + 0.05)]
                prev = tl.last_before(tr["t_visible"])
                ob = kobs.get(("states", k)) or []
                orig = [o for o in ob if o["row_second"] is not None and int(o["row_second"]) == sec]
                reuse = [o for o in ob if o["row_second"] is not None and int(o["row_second"]) != sec]
                first_orig = None
                if orig:
                    s0 = min(orig, key=lambda o: o["seq_local"])["seq_local"]
                    first_orig = tl.info(tl.polls[s0], "states", k)
                d = {"scorer": {"outcome": sc["outcome"], "predicted": sc["predicted"], "agrees": sc["agrees"],
                                "observed_by_keylog": sc["observed_by_keylog"]},
                     "copies_from_visible_minus_1s_to_delete": ins,
                     "last_copy_before_visible": tl.info(prev, "states", k),
                     "keylog_original_row_observed": bool(orig), "keylog_first_original_poll": first_orig,
                     "keylog_key_reused_by_later_row": bool(reuse),
                     "keylog_reuse_seconds": sorted({o["row_second"] for o in reuse})[:5],
                     "detected": sc["outcome"] == "detected"}
                d["detected_iff_observed_original"] = d["detected"] == d["keylog_original_row_observed"]
                cls = None
                if sc["agrees"] is False:
                    if sc["predicted"] == "detected" and not orig:
                        cls = "copy_began_inside_window_but_did_not_hold_the_row"
                    elif sc["predicted"] == "no_evidence" and orig and first_orig and first_orig["copy_at"] < tr["t_visible"]:
                        cls = "copy_began_before_visible_and_held_the_row"
                    else:
                        cls = "other"
                d["deviation_class"] = cls
                row[m] = d
            rows.append(row)
        out["deletion"][arm] = rows

    # ---------------------------------------------------------------- summaries
    summ = {"deviations": [], "insertion_by_level": {}, "deletion": {}}
    for arm, rows in out["insertion"].items():
        for row in rows:
            for m in MONITORS:
                d = row[m]
                if d["scorer"]["agrees"] is False:
                    summ["deviations"].append({
                        "arm": arm, "trial": row["trial"], "level": row["level"], "monitor": m,
                        "predicted": d["scorer"]["predicted"], "observed": d["scorer"]["outcome"],
                        "lag_at_commit_s": row["lag_at_commit_s"], "scorer_lower_bound_s": d["scorer"]["lower_bound_s"],
                        "verifier_row_verdict": d["verifier_row"]["verdict"],
                        "verifier_lower_bound_s": d["verifier_row"]["committed_after_lower_bound_s"],
                        "colocated_attributable": [(c["arm"], c["trial"], c["level"]) for c in d["colocated_trial_rows"]
                                                   if c["verdict"] == "attributable"],
                        "scorer_poll_copy_ms": (d["scorer_poll"] or {}).get("copy_ms"),
                        "scorer_poll_held_key": (d["scorer_poll"] or {}).get("held_key"),
                        "class": d["deviation_class"]})
        for lev in sorted({r["level"] for r in rows}):
            rs = [r for r in rows if r["level"] == lev]
            e = {"n": len(rs)}
            for m in MONITORS:
                c = collections.Counter(r[m]["row_level_outcome"] for r in rs)
                ag = [r[m]["row_level_outcome"] == r[m]["design_rule"]["predicted"] for r in rs]
                e[m] = {"row_level_outcomes": dict(c),
                        "row_level_attributable": c.get("detected", 0),
                        "design_rule_predictions": dict(collections.Counter(r[m]["design_rule"]["predicted"] for r in rs)),
                        "row_level_agrees_with_design_rule": sum(ag),
                        "scorer_outcomes": dict(collections.Counter(r[m]["scorer"]["outcome"] for r in rs)),
                        "max_abs_diff_design_lb_vs_verifier_lb": max(
                            [abs(r[m]["design_rule"]["lower_bound_s"] - r[m]["verifier_row"]["committed_after_lower_bound_s"])
                             for r in rs if r[m]["design_rule"]["lower_bound_s"] is not None
                             and r[m]["verifier_row"]["committed_after_lower_bound_s"] is not None] or [None])}
            summ["insertion_by_level"]["%s_%s" % (arm, lev)] = e
    for arm, rows in out["deletion"].items():
        for row in rows:
            for m in MONITORS:
                d = row[m]
                if d["scorer"]["agrees"] is False:
                    summ["deviations"].append({
                        "arm": arm, "trial": row["trial"], "level": row["delay_s"], "monitor": m,
                        "predicted": d["scorer"]["predicted"], "observed": d["scorer"]["outcome"],
                        "t_visible": row["t_visible"], "t_delete_commit": row["t_delete_commit"],
                        "visible_for_s": row["visible_for_s"],
                        "copies_in_window": d["copies_from_visible_minus_1s_to_delete"],
                        "keylog_first_original_poll": d["keylog_first_original_poll"],
                        "class": d["deviation_class"]})
        e = {}
        for m in MONITORS:
            e[m] = {"n": len(rows),
                    "scorer_observed_by_keylog_true": sum(1 for r in rows if r[m]["scorer"]["observed_by_keylog"]),
                    "keylog_original_row_observed": sum(1 for r in rows if r[m]["keylog_original_row_observed"]),
                    "keylog_key_reused_by_later_row": sum(1 for r in rows if r[m]["keylog_key_reused_by_later_row"]),
                    "scorer_observed_but_only_by_reused_key": sum(1 for r in rows if r[m]["scorer"]["observed_by_keylog"]
                                                                  and not r[m]["keylog_original_row_observed"]),
                    "detected": sum(1 for r in rows if r[m]["detected"]),
                    "detected_iff_observed_original": sum(1 for r in rows if r[m]["detected_iff_observed_original"]),
                    "detected_not_observed_original": [r["trial"] for r in rows if r[m]["detected"] and not r[m]["keylog_original_row_observed"]],
                    "observed_original_not_detected": [r["trial"] for r in rows if not r[m]["detected"] and r[m]["keylog_original_row_observed"]]}
        summ["deletion"][arm] = e
    summ["deviation_count"] = len(summ["deviations"])
    summ["deviation_classes"] = dict(collections.Counter(d["class"] for d in summ["deviations"]))
    # the scorer's prediction poll (last copy_at before t_commit) already held the inserted key, per arm and monitor
    summ["scorer_poll_held_key"] = {
        "%s_%s" % (arm, m): {"n": len(rows),
                             "held": [r["trial"] for r in rows if (r[m]["scorer_poll"] or {}).get("held_key")],
                             "held_and_scorer_disagrees": [r["trial"] for r in rows if (r[m]["scorer_poll"] or {}).get("held_key")
                                                           and r[m]["scorer"]["agrees"] is False],
                             "held_and_ambiguous": [r["trial"] for r in rows if (r[m]["scorer_poll"] or {}).get("held_key")
                                                    and r[m]["scorer"]["agrees"] is None]}
        for arm, rows in out["insertion"].items() for m in MONITORS}
    bd = [r["commit_duration_s"] for r in out["insertion"]["BDT"] if r["commit_duration_s"] is not None]
    bd_s = sorted(bd)
    summ["bdt_commit_duration_s"] = {"n": len(bd_s), "median": bd_s[len(bd_s) // 2] if bd_s else None,
                                     "max": bd_s[-1] if bd_s else None, "over_0.05": sum(1 for x in bd_s if x > 0.05),
                                     "trials_over_0.05": [r["trial"] for r in out["insertion"]["BDT"]
                                                          if (r["commit_duration_s"] or 0) > 0.05]}

    # whole A-phase scan: copy-mode polls whose watermark is below a watermark the direct monitor had already read
    # (its read finished before the copy began), with no trial deletion of a key in between that committed before the
    # copy ended. A hit is a copy that lacked a row another process had already read.
    dels = []                                             # (table, key, t_delete_commit)
    for op in ("del", "delph"):
        for t in trials[op].values():
            dels.append(("states", int(t["deleted_row"]["state_id"]), t["t_delete_commit"]))
    extra_ops = {}
    for op in ("wipe", "pw", "lock_shm"):
        for f in sorted(glob.glob(os.path.join(a.run_dir, "e10", "*_%s.json" % op))):
            inputs.setdefault("deletions_" + op, []).append({"path": f, "sha256": sha(f)})
            d = json.load(open(f))
            for t in d.get("trials") or []:
                if t.get("err"):
                    continue
                for k in t.get("states_deleted") or []:
                    dels.append(("states", int(k), t.get("t_commit") or t.get("t_delete_commit") or 0))
                for k in t.get("events_deleted") or []:
                    dels.append(("events", int(k), t.get("t_commit") or t.get("t_delete_commit") or 0))
            for var, act in (d.get("actions") or {}).items():
                if var == "PW-R":
                    dels.append(("states", int(act["state_id"]), act["t_commit"]))
                elif var.startswith("PW-F"):
                    dels.append(("states", int(act["insert"]["forged_state_id"]), act["delete"]["t_commit"]))
            bdl = d.get("blind_delete") or {}
            if bdl.get("deleted_row"):
                dels.append(("states", int(bdl["deleted_row"]["state_id"]), bdl["t_delete_commit"]))
            extra_ops[op] = extra_ops.get(op, 0) + 1
    t_a_end = None
    for line in open(os.path.join(a.run_dir, "events.jsonl")):
        e = json.loads(line)
        if e.get("type") == "snapshot" and e.get("stack") == "e10s" and e.get("label") == "snap_a_end":
            t_a_end = e["t_snapshot"]
    inputs["events"] = {"path": os.path.join(a.run_dir, "events.jsonl"), "sha256": sha(os.path.join(a.run_dir, "events.jsonl"))}
    tld, tlc = TL["direct"][0], TL["copy"][0]
    stale = []
    n_checked = 0
    dobs = [(p["copy_at"] + ((tld.cost.get(p["seq_local"]) or {}).get("copy_ms") or 0) / 1000.0, p) for p in tld.obs]
    dobs.sort(key=lambda x: x[0])
    j, last_d = 0, None
    for c in tlc.obs:
        if t_a_end is not None and c["copy_at"] > t_a_end:
            break
        while j < len(dobs) and dobs[j][0] <= c["copy_at"]:
            last_d = dobs[j][1]
            j += 1
        if last_d is None:
            continue
        n_checked += 1
        cms = (tlc.cost.get(c["seq_local"]) or {}).get("copy_ms") or 0
        c_end = c["copy_at"] + cms / 1000.0
        for table in ("states", "events"):
            cw, dw = c["wm"].get(table), last_d["wm"].get(table)
            if cw is None or dw is None or cw >= dw:
                continue
            explained = [x for x in dels if x[0] == table and cw < x[1] <= dw and x[2] <= c_end]
            if not explained:
                stale.append({"table": table, "copy_seq_local": c["seq_local"], "copy_at": c["copy_at"], "copy_ms": cms,
                              "copy_wm": cw, "direct_seq_local": last_d["seq_local"], "direct_copy_at": last_d["copy_at"],
                              "direct_wm": dw, "keys_missing": dw - cw})
    summ["copy_staleness_scan"] = {
        "what": "copy-mode polls (A phase, up to snap_a_end) whose watermark is below one the direct monitor had read "
                "before the copy began, not explained by a trial deletion committed before the copy ended",
        "copy_polls_checked": n_checked, "t_a_end": t_a_end, "deletions_considered": len(dels),
        "hits": stale[:100], "n_hits": len(stale)}
    out["summary"] = summ
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out["wall_s"] = round(time.time() - t_begin, 1)
    out["script"] = {"path": os.path.relpath(os.path.abspath(__file__), ROOT), "sha256": sha(os.path.abspath(__file__))}
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True, default=str)
    print("wrote %s sha256 %s" % (a.out, sha(a.out)))


if __name__ == "__main__":
    main()
