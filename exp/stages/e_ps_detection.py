"""E-PS -- POST-COMMIT PRINCIPAL SWAP on the real deployment: detection + renderer.

New (2026-10-02). Scores the homeprov_ec `PS` arm (write random bytes into
states.context_user_id_bin of an already-anchored row) two ways:

  1. Renderer-confirmed misattribution, from the per-room ec_report trials the
     component already wrote (its own logbook render), identical oracle to E-C/E-D.
  2. HOMEPROV detection, by reusing the SHIPPED verifier from e_c_write_time.py
     unchanged (snapshot_recorder / anchored_roots / verify_window), so this file
     adds no commitment or verification logic of its own.

The shipped monitor commits a full-row projection that does NOT include
context_user_id_bin, so whether the swap is detected is a measurement. Any
detected PS trial is subjected to the same late-row test as E-C: a violation
whose segment GAINED rows after sealing (delta_n > 0) is late-arriving benign
traffic in the trial's own second, not a detection of the swap.

Writes exp/out/e_ps_<tag>_detection.json. Never overwrites a published file.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")
sys.path.insert(0, os.path.join(ROOT, "exp"))

# Reuse the shipped verifier and the stats/capability helpers unchanged.
from stages.e_c_write_time import (  # noqa: E402
    _load_monitor, snapshot_recorder, anchored_roots, verify_window, trial_row_ts,
    HUB, ANCHORD, MONITOR, sh)
from rig import capability, stats                                   # noqa: E402


def main(rooms, tag="e_ps_auth"):
    t_start = float(open(os.path.join(OUT, "%s_t_start" % tag)).read().strip())
    t_end = float(open(os.path.join(OUT, "%s_t_end" % tag)).read().strip())

    per_room, trials = [], []
    for room in rooms:
        f = os.path.join(OUT, "%s_report_%s.json" % (tag, room))
        if not os.path.exists(f):
            print("  %-9s MISSING" % room)
            continue
        d = json.load(open(f))
        for t in d.get("trials", []):
            if t.get("arm") not in ("PS", "PSR"):
                continue
            t["room"] = room
            trials.append(t)
        per_room.append({"room": room,
                         "n_trials": sum(1 for t in d.get("trials", [])
                                         if t.get("arm") in ("PS", "PSR")),
                         "innocent_party": d.get("innocent_party"),
                         "target": d.get("target")})
    if not trials:
        raise SystemExit("no PS trials found in the per-room reports")

    monitor = _load_monitor()
    db, t_snapshot = snapshot_recorder()
    vok, vreason, vdetail = monitor.validate_copy(db)
    if not vok:
        raise SystemExit("recorder snapshot did not validate (%s)" % vreason)
    roots, chain_info = anchored_roots(t_start, t_snapshot)
    import collections as _c
    _raw = sh("docker exec %s cat /anchor/chain.jsonl" % ANCHORD)
    chain_schemes = dict(_c.Counter(
        (json.loads(l).get("payload") or {}).get("scheme", "unrecorded")
        for l in _raw.splitlines() if l.strip()))
    verdicts, recompute_info = verify_window(monitor, db, roots, t_start, t_end)
    widths = dict(monitor.GRAN)

    # Per-trial detection, at both granularities, and the segments trials touched.
    touched = {"second": set(), "minute": set()}
    for t in trials:
        ts, _sid = trial_row_ts(t)
        if ts is None:
            continue
        for g in ("second", "minute"):
            touched[g].add(str(int(ts // widths[g])))
    for t in trials:
        ts, sid = trial_row_ts(t)
        det = {}
        for g in ("second", "minute"):
            if ts is None:
                det[g] = {"segment": None, "anchored": False, "violation": None}
                continue
            seg = str(int(ts // widths[g]))
            v = verdicts.get((g, seg))
            det[g] = {"segment": seg, "anchored": (g, seg) in roots,
                      "violation": (None if v is None else bool(v["violation"])),
                      "why": (None if v is None else v.get("why")),
                      "mechanism": (None if v is None else v.get("mechanism")),
                      "delta_n": (None if v is None else v.get("delta_n"))}
        t["_detection"] = det

    valid = [t for t in trials if not t.get("err") and not t.get("error")]

    def cp(k, n):
        return stats.clopper_pearson(k, n) if n else {"k": 0, "n": 0, "prop": None}

    mis = cp(sum(1 for t in valid if t.get("renderer_confirmed_misattribution")), len(valid))
    moved = cp(sum(1 for t in valid if t.get("principal_moved")), len(valid))
    person = cp(sum(1 for t in valid if t.get("renderer_names_person")), len(valid))
    det_detail = {}
    for g in ("second", "minute"):
        anch = [t for t in valid if (t.get("_detection") or {}).get(g, {}).get("anchored")]
        hits = [t for t in anch if t["_detection"][g]["violation"]]
        # Late-row test: a hit whose segment GAINED rows (delta_n > 0) cannot be
        # attributed to the arm; an in-place change (delta_n == 0), a removal
        # (delta_n < 0) or a vanished segment can. (Fixed 2026-10-02: the first
        # version required delta_n < 0 and so mislabelled in-place changes, the
        # signature of this arm, as late rows.)
        genuine = [t for t in hits
                   if t["_detection"][g].get("why") == "segment_absent_now"
                   or (t["_detection"][g].get("delta_n") is not None
                       and t["_detection"][g]["delta_n"] <= 0)]
        det_detail[g] = {
            **cp(len(hits), len(anch)),
            "n_trials_whose_segment_was_anchored": len(anch),
            "raw_violation_hits": len(hits),
            "hits_explained_by_late_rows": len(hits) - len(genuine),
            "hits_consistent_with_detection": len(genuine),
            "hit_detail": [{"room": t["room"], "trial": t["trial"],
                            **t["_detection"][g]} for t in hits]}

    # Benign floor: anchored segments no PS trial touched that fail recomputation.
    benign = {}
    for g in ("second", "minute"):
        segs = [(gg, s) for (gg, s) in verdicts if gg == g and s not in touched[g]]
        k = sum(1 for key in segs if verdicts[key]["violation"])
        benign[g] = {**(cp(k, len(segs))),
                     "what": "anchored %s-segments inside the run window that no PS "
                             "trial touched and that fail recomputation" % g}

    mechanisms = {}
    for g in ("second", "minute"):
        import collections
        c = collections.Counter()
        for (gg, seg), v in verdicts.items():
            if gg != g or not v["violation"]:
                continue
            c[v.get("mechanism") or "unknown"] += 1
        mechanisms[g] = dict(c)

    result = {
        "experiment": "E-PS",
        "what": "post-commit principal swap (write random bytes into "
                "context_user_id_bin of an anchored row) on the real deployment, "
                "under the authenticated anchor, scored for renderer "
                "misattribution and for HOMEPROV detection",
        "substrate": "real (mosquitto + MQTT discovery + shipped motion-light "
                     "blueprint), three home configurations",
        "oracle": "the platform's own logbook EventProcessor (per-room ec_report), "
                  "identical to E-C/E-D; detection by the shipped monitor/verifier",
        "monitor_scheme": getattr(monitor, "SCHEME", "row"),
        "chain_schemes": chain_schemes,
        "commitment_note": ("closure: the monitor commits the renderer closure, "
                            "including context_user_id_bin, the only column this "
                            "arm writes" if getattr(monitor, "SCHEME", "row") == "closure"
                            else "row: the monitor commits entity, state, ts, "
                            "context_id_bin, context_parent_id_bin and label; it "
                            "does NOT commit context_user_id_bin, the only column "
                            "this arm writes"),
        "rooms": rooms, "per_room": per_room,
        "window": {"t_start": t_start, "t_end": t_end,
                   "duration_s": round(t_end - t_start, 1),
                   "recorder_snapshot_at": t_snapshot},
        "n_trials": len(trials), "n_valid": len(valid),
        "renderer_confirmed_misattribution": mis,
        "principal_moved": moved,
        "renderer_names_person": person,
        "principals_rendered": sorted({str(t.get("principal_rendered")) for t in valid}),
        "clean_principals": sorted({str(t.get("clean_principal")) for t in valid}),
        "homeprov_detection_second": det_detail["second"],
        "homeprov_detection_minute": det_detail["minute"],
        "benign_violation_floor": benign,
        "violation_mechanisms": mechanisms,
        "detection_method": {
            "how": "every anchored segment root in the run window recomputed from a "
                   "consistent snapshot of the final recorder, using the SHIPPED "
                   "monitor's load()/commit()",
            "late_row_test": "a violating segment whose row count rose after sealing "
                             "(delta_n > 0) is late-arriving benign traffic, not a "
                             "detection of the swap",
            "anchored_segments_in_window": {
                g: sum(1 for (gg, _s) in roots if gg == g) for g in widths},
            **recompute_info, **chain_info,
            "recorder_copy_valid": vok, "recorder_copy_reason": vreason},
        "trials": trials,
        "versions": {
            "ha_image_digest": sh("docker inspect %s --format '{{index .Image}}'" % HUB),
            "monitor_image_digest": sh("docker inspect %s --format '{{index .Image}}'" % MONITOR),
            "anchor_image_digest": sh("docker inspect %s --format '{{index .Image}}'" % ANCHORD),
            "anchor_authenticated": bool(
                "HOMEPROV_ANCHOR_KEY=" in sh(
                    "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                    % ANCHORD)
                and "HOMEPROV_ANCHOR_KEY=\n" not in sh(
                    "docker inspect %s --format '{{range .Config.Env}}{{println .}}{{end}}'"
                    % ANCHORD)),
            "host_arch": sh("uname -m")},
    }
    result["capability"] = capability.record(
        actor_id="principal_swapper", actor_position="in_process_integration",
        seed=None, budget_writes=1, window_s=None,
        knowledge={"anchor_key_known": False},
        constraints={"host_root": False, "anchor_key_access": False,
                     "post_commit_row_edits_used": "one UPDATE of context_user_id_bin"},
        substrate={"kind": "real Home Assistant deployment (Container install)",
                   "monitor": "shipped external monitor, live, authenticated anchor",
                   "anchor": "shipped append-only anchor daemon, authenticated"},
        mission="E-PS post-commit principal swap detection")
    path = os.path.join(OUT, "e_ps_auth_detection.json" if tag == "e_ps_auth"
                        else "%s_detection.json" % tag)
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    dig = capability.stamp(result, path)

    print("\n== E-PS post-commit principal swap ==")
    print("  n_valid %d" % len(valid))
    print("  renderer misattribution %d/%d (%.3f)" % (mis["k"], mis["n"], mis.get("prop") or 0))
    print("  principal moved        %d/%d" % (moved["k"], moved["n"]))
    print("  renderer names person  %d/%d" % (person["k"], person["n"]))
    for g in ("second", "minute"):
        d = det_detail[g]
        print("  detection (%-6s) %d/%d anchored=%d raw_hits=%d late_row=%d genuine=%d"
              % (g, d["k"], d["n"], d["n_trials_whose_segment_was_anchored"],
                 d["raw_violation_hits"], d["hits_explained_by_late_rows"],
                 d["hits_consistent_with_detection"]))
    for g in ("second", "minute"):
        b = benign[g]
        if b.get("n"):
            print("  benign floor (%s) %d/%d" % (g, b["k"], b["n"]))
    print("  -> %s" % path)
    print("  digest", dig)
    return result


if __name__ == "__main__":
    args = sys.argv[1:]
    tag = "e_ps_auth"
    if "--tag" in args:
        i = args.index("--tag")
        tag = args[i + 1]
        args = args[:i] + args[i + 2:]
    main(args or ["porch", "hallway", "kitchen"], tag=tag)
