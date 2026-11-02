"""E-DZ detection and misattribution scoring on Domoticz (one authenticated run, both arms).

Inputs: the run directory written by testbed/domoticz/run_dz.sh (the final consistent snapshot of domoticz.db taken with
SQLite's backup API inside the hub container, the anchor chain, the monitor's per-poll row archive) and the per-room
trial reports written by testbed/domoticz/harness/dz_arms.py.

Detection (live closure scheme), exactly as the Home Assistant runs are scored: every anchored segment root in the run
window is recomputed from the final snapshot with the SHIPPED monitor's commit() (monitor/monitor.py, through the
Domoticz adapter's load()) and compared with the first anchored root of its segment (reproduce/verify_all.py's
anchored_roots() and verify_window(), imported unchanged). A trial is detected when the one-second segment of the row it
edited is a violation and the late-row test finds it attributable (row count not above the anchored count); a violation
whose segment holds more rows than were anchored is ambiguous and counted as not detected. Benign floor: anchored
one-second segments in the window that no trial touched (a trial touches every second holding a row it wrote or named:
its relock row(s), its target row, the genuine row whose label it copied, and the member's own actions of the arm) and
that fail, over all such segments.

Offline schemes (log rows only, whole row, and the row-scheme analogue), from the same snapshots: for every anchored
record, the rows the monitor's poll read for it (archived by the adapter's load()) are located and validated by
reproducing the record's anchored closure roots exactly; the same rows then give the root each offline scheme would have
sealed for those segments, and the final snapshot gives the root a verifier recomputes. Granularities: second and minute.

Misattribution: the platform's own renderer (getlightlog, the API behind the device Log page) read by the harness for
each viewer role before and after each edit, and the web UI's Text log table rendered in a browser for each role.

    python3 exp/stages/dz_detection.py --tag dz --run DIR [--outdir exp/out]
Writes <outdir>/<tag>_laundering_detection.json and <outdir>/<tag>_memberswap_detection.json. Never overwrites.
"""
from __future__ import annotations

import argparse
import collections
import gzip
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
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import verify_all as VA  # noqa: E402  (anchored_roots, verify_window, the shipped verifier rule)
import chainverify  # noqa: E402
from rig import stats  # noqa: E402

ARMS = ("laundering", "memberswap")
ROLES = ("owner", "member", "guest")
ROLE_RIGHTS = {"owner": "Admin", "member": "User", "guest": "Viewer"}
GRANS = ("second", "minute")
INPLACE_DS = ("nValue", "sValue", "LastUpdate", "LastLevel")   # measured in dz_closure.json in_place_rewrite_probe


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cp(k, n):
    return stats.clopper_pearson(k, n) if n else {"k": 0, "n": 0, "prop": None}


def load_adapter(monitor_dir, scratch):
    os.environ["HOMEPROV_SCHEME"] = "closure"
    os.environ["HOMEPROV_SCRATCH"] = scratch
    os.environ["HOMEPROV_DB"] = os.path.join(scratch, "unused.db")
    os.environ["HOMEPROV_MONITOR_DIR"] = monitor_dir
    os.environ.pop("HP_DZ_ARCHIVE", None)
    spec = importlib.util.spec_from_file_location(
        "dz_monitor", os.path.join(REPO, "testbed", "domoticz", "monitor", "dz_monitor.py"))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    assert A.M.SCHEME == "closure" and A.M.ENCODING == "v2"
    return A


def read_final(A, db):
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % db, uri=True)
    try:
        return A.read_rows(con)
    finally:
        con.close()


def seg_of(ts, g, W):
    return str(int(ts // W[g]))


def verdict(sealed, got):
    if got is None:
        return {"violation": True, "delta_n": None}
    if got["acc"] != sealed["acc"] or got["n"] != sealed["n"]:
        return {"violation": True, "delta_n": got["n"] - sealed["n"]}
    return {"violation": False}


def classify(v):
    if not v or not v["violation"]:
        return "not_flagged"
    return "ambiguous" if (v.get("delta_n") is not None and v["delta_n"] > 0) else "attributable"


# ------------------------------------------------------------------------------------------- trials and the counting rule
def load_trials(outdir, tag, rooms):
    trials, per_room, arm_runs = [], [], []
    for room in rooms:
        d = json.load(open(os.path.join(outdir, "%s_report_%s.json" % (tag, room))))
        for t in d["trials"]:
            trials.append(t)
        for r in d["arm_runs"]:
            r = dict(r)
            r["room"] = room
            arm_runs.append(r)
        per_room.append({"room": room, "lock_device_idx": d["lock_device_idx"], "light_device_idx": d["light_device_idx"],
                         "n_trials": len(d["trials"]), "host_minus_vm_s": d.get("host_minus_vm_s")})
    return trials, per_room, arm_runs


def rows_written_or_named(t):
    """Rows a trial wrote (relock rows, the target unlock row) or named (the genuine row whose label it copied)."""
    out = []
    lk = t.get("relock") or {}
    for r in [lk.get("row")] + list(lk.get("extra_rows") or []):
        if r:
            out.append(("wrote", r))
    un = (t.get("unlock") or {}).get("row")
    if un:
        out.append(("wrote", un))
    for r in t.get("named_rows") or []:
        if r:
            out.append(("named", r))
    return out


def touched_seconds(trials, arm_runs, A):
    secs = set()
    for t in trials:
        for _kind, r in rows_written_or_named(t):
            if r.get("Date"):
                secs.add(int(A.date_ts(r["Date"])))
    for r in arm_runs:                                   # the member's own actions in the memberswap arm
        w = (r.get("member_warmup") or {}).get("row")
        if w and w.get("Date"):
            secs.add(int(A.date_ts(w["Date"])))
    return secs


# --------------------------------------------------------------------------------------- offline schemes from the archive
def reconstruct_offline(A, archive_path, chain_lines, t0, tsnap, final_rows, W, schemes=("logrows", "wholerow", "row")):
    """First sealed root per (scheme, granularity, segment) from the rows each poll read, validated against the anchored
    closure roots; and each scheme's recomputation from the final snapshot."""
    arch = []
    with open(archive_path) as fh:
        for line in fh:
            try:
                arch.append(json.loads(line))
            except ValueError:
                pass
    arch.sort(key=lambda r: r["t_load"])
    loads = [r["t_load"] for r in arch]
    import bisect
    sealed = {s: {} for s in ("closure",) + tuple(schemes)}
    status = collections.Counter()
    restore_info = {}
    for line in chain_lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        p = rec.get("payload") or {}
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap) or p.get("evidence_unobservable") or not p.get("sealed"):
            continue
        want = {(g, s): v for g, segs in p["sealed"].items() if g in GRANS for s, v in segs.items()}
        i = bisect.bisect_left(loads, ts - 0.01)
        match = None
        for cand in arch[i:i + 3]:
            if cand["t_load"] > ts + 10:
                break
            phi = A.M.commit(A.nodes_from_rows("closure", cand["ll_cols"], cand["ll"], cand["ds_cols"], cand["ds"]))
            if all((phi.get(g) or {}).get(s) == {"acc": v["acc"], "n": v["n"]} for (g, s), v in want.items()):
                match = (cand, phi)
                break
        if match is None:
            status["records_not_matched"] += 1
            continue
        status["records_matched"] += 1
        cand, phi_c = match
        for (g, s), v in want.items():
            sealed["closure"].setdefault((g, s), {"acc": v["acc"], "n": v["n"]})
        for sch in schemes:
            phi = A.M.commit(A.nodes_from_rows(sch, cand["ll_cols"], cand["ll"], cand["ds_cols"], cand["ds"]))
            for (g, s) in want:
                if (g, s) not in sealed[sch] and s in (phi.get(g) or {}):
                    sealed[sch][(g, s)] = phi[g][s]
                    if sch == "wholerow" and g == "second":
                        restore_info[s] = {c: [r[cand["ds_cols"].index(c)] for r in cand["ds"]] for c in
                                           ("ID",) + INPLACE_DS}
    ll_cols, ll, ds_cols, ds = final_rows
    post = {sch: A.M.commit(A.nodes_from_rows(sch, ll_cols, ll, ds_cols, ds)) for sch in sealed}
    verd = {sch: {} for sch in sealed}
    for sch in sealed:
        for (g, s), root in sealed[sch].items():
            verd[sch][(g, s)] = verdict(root, (post[sch].get(g) or {}).get(s))
    return sealed, verd, dict(status), post, restore_info


def wholerow_restore_check(A, s, restore, final_rows, sealed_root):
    """Does putting back the seal-time values of the DeviceStatus columns Domoticz rewrites in place (nValue, sValue,
    LastUpdate, LastLevel) reproduce the whole-row root sealed for this second?"""
    ll_cols, ll, ds_cols, ds = final_rows
    idx = {c: ds_cols.index(c) for c in ("ID",) + INPLACE_DS}
    at_seal = {restore["ID"][k]: {c: restore[c][k] for c in INPLACE_DS} for k in range(len(restore["ID"]))}
    ds2 = []
    for r in ds:
        r = list(r)
        v = at_seal.get(r[idx["ID"]])
        if v:
            for c in INPLACE_DS:
                r[idx[c]] = v[c]
        ds2.append(r)
    li = ll_cols.index("Date")
    seg_rows = [r for r in ll if int(A.date_ts(r[li])) == int(s)]
    phi = A.M.commit(A.nodes_from_rows("wholerow", ll_cols, seg_rows, ds_cols, ds2))
    return (phi.get("second") or {}).get(str(s)) == {"acc": sealed_root["acc"], "n": sealed_root["n"]}


# ----------------------------------------------------------------------------------------------------------- scoring
def score_arm(arm, trials, verd_by_scheme, roots, W, untouched_by_g, chain_first_recv):
    ts_ = [t for t in trials if t["arm"] == arm]
    valid = [t for t in ts_ if not t.get("err")]
    out = {"n_trials": len(ts_), "n_valid": len(valid),
           "failures": [t.get("err") for t in ts_ if t.get("err")]}
    # misattribution, per viewer role and for all roles together
    out["renderer_confirmed_misattribution_all_roles"] = cp(sum(1 for t in valid if t["renderer_confirmed_misattribution"]),
                                                            len(valid))
    out["misattribution_per_role"] = {
        r: {"rights": ROLE_RIGHTS[r], **cp(sum(1 for t in valid if t["per_role"][r]["misattributed"]), len(valid))}
        for r in ROLES}
    out["principal_moved_per_role"] = {r: cp(sum(1 for t in valid if t["per_role"][r]["principal_moved"]), len(valid))
                                       for r in ROLES}
    out["clean_user_was_true_author"] = cp(sum(1 for t in valid if t.get("clean_is_true_author")), len(valid))
    out["clean_users"] = sorted({t["clean_user"] for t in valid})
    out["users_after_edit"] = sorted({t["per_role"]["owner"]["after_user"] for t in valid})
    out["date_and_data_unchanged_all_roles"] = cp(sum(1 for t in valid if all(t["per_role"][r]["date_and_data_unchanged"]
                                                                              for r in ROLES)), len(valid))
    same = sum(1 for t in valid for ph in ("before", "after")
               if len({json.dumps(t[ph][r], sort_keys=True) for r in ROLES}) == 1)
    out["same_render_for_every_role"] = {"k": same, "n": 2 * len(valid),
                                         "what": "trial renderings (before and after each edit) identical for all roles"}
    ui = [v for t in valid for v in (t.get("ui_agreement") or {}).values()]
    out["ui_rendering"] = {"renderings": len(ui), "agree_with_api": sum(1 for v in ui if v["agrees"]),
                           "ui_after_shows_written_label": sum(
                               1 for t in valid for r in ROLES
                               if (t.get("ui_agreement") or {}).get("after_%s" % r, {}).get("ui_users")
                               and all(u == t["per_role"][r]["after_user"]
                                       for u in t["ui_agreement"]["after_%s" % r]["ui_users"])),
                           "what": "per trial, phase (before/after) and viewer role: the browser-rendered Text log cell "
                                   "User of the trial's row equals the API's User"}
    dl = [t["edit_delay_s"] for t in valid]
    out["edit_delay_s"] = {"min": min(dl), "median": statistics.median(dl), "max": max(dl),
                           "n_at_least_130": sum(1 for x in dl if x >= 130), "n": len(dl)}
    sb = []
    for t in valid:
        s = seg_of(t["row_ts"], "second", W)
        fr = chain_first_recv.get(("second", s))
        sb.append(fr is not None and fr < t["edit"]["t_edit"])
    out["segment_sealed_before_edit"] = {"k": sum(sb), "n": len(sb)}
    out["db_writes_per_trial"] = sorted({t["edit"].get("db_writes") for t in valid})
    out["per_room"] = {room: {"n": sum(1 for t in valid if t["room"] == room),
                              "misattributed_all_roles": sum(1 for t in valid if t["room"] == room
                                                             and t["renderer_confirmed_misattribution"])}
                       for room in ("porch", "hallway", "kitchen")}
    # detection per scheme
    det = {}
    for sch, verd in verd_by_scheme.items():
        d = {}
        for g in GRANS:
            hits, att, amb, anch, absent = [], 0, 0, 0, 0
            for t in valid:
                s = seg_of(t["row_ts"], g, W)
                v = verd.get((g, s))
                if v is None:
                    absent += 1
                    continue
                anch += 1
                c = classify(v)
                if c != "not_flagged":
                    hits.append({"room": t["room"], "trial": t["trial"], "segment": s, **v})
                    att += c == "attributable"
                    amb += c == "ambiguous"
            d[g] = {**cp(att, len(valid)), "detected_attributable": att, "raw_violation_hits": len(hits),
                    "hits_explained_by_late_rows": amb, "n_trials_whose_segment_was_sealed": anch,
                    "n_trials_segment_not_available": absent, "flagged_ci": cp(len(hits), len(valid)),
                    "hit_detail": hits if g == "second" else len(hits)}
        det[sch] = d
    out["detection"] = det
    return out


def floor_counts(verd, untouched):
    fl = {}
    for g in GRANS:
        segs = [s for (gg, s) in verd if gg == g and s in untouched[g]]
        k = sum(1 for s in segs if verd[(g, s)]["violation"])
        mech = collections.Counter(classify(verd[(g, s)]) for s in segs if verd[(g, s)]["violation"])
        fl[g] = {**cp(k, len(segs)), "late_row_failures": mech.get("ambiguous", 0),
                 "in_place_or_removal_failures": mech.get("attributable", 0)}
    return fl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--outdir", default=OUT)
    ap.add_argument("--rooms", nargs="+", default=["porch", "hallway", "kitchen"])
    a = ap.parse_args()
    paths = {arm: os.path.join(a.outdir, "%s_%s_detection.json" % (a.tag, arm)) for arm in ARMS}
    for p in paths.values():
        if os.path.exists(p):
            raise SystemExit("refusing to overwrite %s" % p)
    t_start = float(open(os.path.join(a.outdir, "%s_t_start" % a.tag)).read())
    t_end = float(open(os.path.join(a.outdir, "%s_t_end" % a.tag)).read())
    db = os.path.join(a.run, "verify", "domoticz.db")
    t_snap = float(open(os.path.join(a.run, "verify", "t_snapshot")).read())
    chain_path = os.path.join(a.run, "chain.jsonl")
    archive = os.path.join(a.run, "archive", "archive.jsonl")
    monitor_copy = os.path.join(a.run, "hp", "monitor.py")
    tick = time.time()
    with tempfile.TemporaryDirectory() as scratch:
        A = load_adapter(os.path.join(a.run, "hp"), scratch)
        M = A.M
        W = dict(M.GRAN)
        vcopy = os.path.join(scratch, "validate.db")       # validate a copy: opening it may create sidecars
        shutil.copy2(db, vcopy)
        vok, vreason, vdetail = A.validate_copy(vcopy)
        lines = open(chain_path).read().splitlines()
        cc = chainverify.verify_chain(chainverify.read(chain_path))
        roots = VA.anchored_roots(lines, t_start, t_snap)
        encs = sorted({r["encoding"] for r in roots.values()})
        final_rows = read_final(A, db)
        nodes = A.nodes_from_rows("closure", *final_rows)
        phi = M.commit(nodes)
        verd_live = VA.verify_window(phi, roots, W, t_start, t_end)
        first_recv = {}
        schemes_in_chain = collections.Counter()
        refused = 0
        for line in lines:
            rec = json.loads(line)
            p = rec.get("payload") or {}
            schemes_in_chain[p.get("scheme", "unrecorded")] += 1
            for g, segs in (p.get("sealed") or {}).items():
                for s in segs:
                    first_recv.setdefault((g, str(s)), rec.get("recv_ts"))
        trials, per_room, arm_runs = load_trials(a.outdir, a.tag, a.rooms)
        touched = touched_seconds(trials, arm_runs, A)
        untouched = {"second": {s for (g, s) in verd_live if g == "second" and int(s) not in touched},
                     "minute": {s for (g, s) in verd_live if g == "minute"
                                and not any(int(x) // 60 == int(s) for x in touched)}}
        # offline schemes
        sealed_off, verd_off, rec_status, post_off, restore_info = reconstruct_offline(
            A, archive, lines, t_start, t_snap, final_rows, W)
        for sch in verd_off:                       # same run window as the live verifier
            verd_off[sch] = {k: v for k, v in verd_off[sch].items()
                             if t_start - W[k[0]] <= int(k[1]) * W[k[0]] <= t_end + W[k[0]]}
        # cross-check: the archive-reconstructed closure roots equal the anchored ones for every live segment
        live_keys = {k for k in verd_live if k[0] in GRANS}
        recon_cover = {g: [sum(1 for k in live_keys if k[0] == g and k in sealed_off["closure"]),
                           sum(1 for k in live_keys if k[0] == g)] for g in GRANS}
        closure_agree = all(verd_off["closure"].get(k) == {"violation": verd_live[k]["violation"],
                                                           **({"delta_n": verd_live[k]["delta_n"]}
                                                              if verd_live[k]["violation"] else {})}
                            for k in verd_off["closure"] if k in verd_live)
        verd_by_scheme = {"closure": verd_live, "logrows": verd_off["logrows"], "wholerow": verd_off["wholerow"],
                          "row": verd_off["row"]}
        floors = {sch: floor_counts(v, untouched) for sch, v in verd_by_scheme.items()}
        # whole-row floor mechanism: restoring the in-place DeviceStatus columns
        wr_fail = [s for (g, s), v in verd_off["wholerow"].items() if g == "second" and s in untouched["second"]
                   and v["violation"]]
        wr_restored = sum(1 for s in wr_fail if s in restore_info and wholerow_restore_check(
            A, s, restore_info[s], final_rows, sealed_off["wholerow"][("second", s)]))
        for sch in floors:
            floors[sch]["untouched_second_segments_available"] = len([k for k in verd_by_scheme[sch]
                                                                      if k[0] == "second" and k[1] in untouched["second"]])
        run_level = {
            "window": {"t_start": t_start, "t_end": t_end, "duration_s": round(t_end - t_start, 1),
                       "recorder_snapshot_at": t_snap},
            "recorder_snapshot": {"path": os.path.relpath(db, os.path.dirname(REPO)), "sha256": sha(db),
                                  "valid": vok, "reason": vreason, "lighting_log_rows": len(final_rows[1])},
            "anchor_chain": {"records": len(lines), "sha256": sha(chain_path), "schemes": dict(schemes_in_chain),
                             "encodings_in_window": encs, "link_check": {k: cc.get(k) for k in
                                                                         ("ok", "link", "linked_records", "integrity")}},
            "anchored_segments_in_window": {g: sum(1 for k in verd_live if k[0] == g) for g in W},
            "violating_segments_in_window": {g: sum(1 for k, v in verd_live.items() if k[0] == g and v["violation"])
                                             for g in W},
            "touched_seconds": len(touched),
            "untouched_anchored_segments": {g: len(untouched[g]) for g in GRANS},
            "benign_floor": floors,
            "wholerow_floor_mechanism": {
                "failing_untouched_second_segments": len(wr_fail),
                "reproduced_by_restoring_in_place_devicestatus_columns": wr_restored,
                "columns": list(INPLACE_DS),
                "what": "a failing untouched whole-row segment is reproduced exactly when the seal-time values of the "
                        "DeviceStatus columns Domoticz rewrites in place are put back into the final snapshot"},
            "offline_reconstruction": {"chain_records": rec_status, "live_segments_reconstructed": recon_cover,
                                       "closure_verdicts_equal_live": closure_agree,
                                       "method": "rows each poll read (adapter archive), validated by reproducing the "
                                                 "anchored closure roots exactly"},
            "monitor_py_sha256": sha(monitor_copy),
            "monitor_py_repo_sha256": sha(os.path.join(REPO, "monitor", "monitor.py")),
            "adapter_sha256": sha(os.path.join(REPO, "testbed", "domoticz", "monitor", "dz_monitor.py")),
            "verifier": "reproduce/verify_all.py anchored_roots()/verify_window() (sha256 %s)"
                        % sha(os.path.join(REPO, "reproduce", "verify_all.py")),
            "script_sha256": sha(os.path.abspath(__file__)),
        }
        cfg_path = os.path.join(a.outdir, "%s_config.json" % a.tag)
        cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {}
        for arm in ARMS:
            res = score_arm(arm, trials, verd_by_scheme, roots, W, untouched, first_recv)
            label = {"laundering": "laundering analogue: a household member's app unlock rewritten post-commit so its "
                                   "displayed User is the configuration's motion-light automation "
                                   "(EventSystem/<configuration>_motion_light)",
                     "memberswap": "member-account swap analogue: the lock integration's own unlock rewritten "
                                   "post-commit so its displayed User is the household member account"}[arm]
            out = {
                "experiment": "E-DZ", "arm": arm, "what": label,
                "substrate": "Domoticz %s (build %s) in container dz-domoticz on an internal network, TZ=UTC, "
                             "three motion-light configurations (porch, hallway, kitchen)" % (
                                 cfg.get("domoticz", {}).get("version"), cfg.get("domoticz", {}).get("build_hash")),
                "oracle": "the platform's own renderer, json.htm?type=command&param=getlightlog (the API behind the "
                          "device Log page's Text log table), read per viewer role (owner/Admin, member/User, "
                          "guest/Viewer); plus the web UI's Text log table rendered in a browser per role",
                "monitor_scheme_live": M.SCHEME, "node_encoding": M.ENCODING,
                "counting_rule": "a trial is detected when the one-second segment of the row it edited is a violation "
                                 "and the late-row test finds it attributable (delta_n <= 0); ambiguous (delta_n > 0) "
                                 "counts as not detected; a trial touches every second holding a row it wrote or "
                                 "named; benign floor = failing untouched anchored one-second segments over all "
                                 "untouched anchored one-second segments",
                "rooms": a.rooms, "per_room_reports": per_room,
                "result": res,
                "run": run_level,
                "trials": [t for t in trials if t["arm"] == arm],
                "versions": {k: cfg.get(k) for k in ("domoticz", "images", "anchor", "monitor")},
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seconds": round(time.time() - tick, 1),
            }
            with open(paths[arm], "w") as fh:
                json.dump(out, fh, indent=1, default=str)
            r = res
            print("== %s ==" % arm)
            print("  valid %d/%d; misattribution all roles %d/%d; per role %s" % (
                r["n_valid"], r["n_trials"], r["renderer_confirmed_misattribution_all_roles"]["k"],
                r["renderer_confirmed_misattribution_all_roles"]["n"],
                {k: v["k"] for k, v in r["misattribution_per_role"].items()}))
            print("  UI renderings agreeing %d/%d; edit delay min %.1f s; sealed before edit %d/%d" % (
                r["ui_rendering"]["agree_with_api"], r["ui_rendering"]["renderings"], r["edit_delay_s"]["min"],
                r["segment_sealed_before_edit"]["k"], r["segment_sealed_before_edit"]["n"]))
            for sch, d in r["detection"].items():
                s = d["second"]
                print("  %-8s second: detected %d/%d (raw %d, late-row %d, sealed %d)" % (
                    sch, s["k"], s["n"], s["raw_violation_hits"], s["hits_explained_by_late_rows"],
                    s["n_trials_whose_segment_was_sealed"]))
            print("  ->", paths[arm], sha(paths[arm]))
        print("floors:", json.dumps({s: [f["second"]["k"], f["second"]["n"]] for s, f in floors.items()}))
        print("offline reconstruction:", rec_status, recon_cover, "closure agree:", closure_agree)
        print("whole-row floor failures %d, reproduced by restoring in-place columns %d" % (len(wr_fail), wr_restored))


if __name__ == "__main__":
    main()
