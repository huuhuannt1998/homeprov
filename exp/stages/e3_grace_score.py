"""E3 (round 12, 2026-10-07): score the paired grace-period runs e3_g0_clo (no grace) and e3_g2_clo (2 s grace).

Both runs used the same monitor image (hpr-monitor:closure-grace: monitor.py with the typed encoding, the closure
scheme and HOMEPROV_GRACE_S), the authenticated anchor, the E-D arms PU and PI (30 trials per configuration) and the
same evening, back to back. The counting rule is reproduce/verify_all.py's (the paper's): a trial is flagged when its
one-second segment is a violation, attributable when the segment did not gain rows after its seal, ambiguous when it
did; the benign floor is over untouched anchored one-second segments. The observation window's sealing delay is the
time from a one-second segment's end to the anchor's receipt of its root.

    python3 stages/e3_grace_score.py      # writes exp/out/e3_grace_sealing.json
"""
from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.dirname(HERE)
REPO = os.path.dirname(EXP)
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as V  # noqa: E402

RUNS = {"e3_g0_clo": 0.0, "e3_g2_clo": 2.0}
SP = "<research-dir>/HOMEPROV-P13-exp/e3"


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def score(tag, grace):
    db, chain = os.path.join(SP, tag, "ec_verify", "recorder.db"), os.path.join(SP, tag, "chain.jsonl")
    res_p = os.path.join(V.OUT, f"{tag}_other_principal_real.json")
    res = json.load(open(res_p))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    M = V.load_monitor("closure", os.path.join(SP, tag, "score_scratch"))
    W = dict(M.GRAN)
    lines = V.chain_lines(chain)
    roots = V.anchored_roots(lines, t0, tsnap)
    encs = sorted({a["encoding"] for a in roots.values()})
    assert len(encs) == 1, encs
    phi = M.commit(M.load(db, since=(int(t0 // 3600) - 1) * 3600.0), encoding=encs[0])
    verd = V.verify_window(phi, roots, W, t0, t1)
    trials = [t for t in res["trials"] if not (t.get("err") or t.get("error"))]
    arms = {}
    for a in ("PU", "PI"):
        ts = [t for t in trials if t.get("arm") == a]
        fl = at = am = 0
        for t in ts:
            seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
            v = verd.get(("second", str(seg))) if seg is not None else None
            if not (v and v["violation"]):
                continue
            fl += 1
            if v["delta_n"] is not None and v["delta_n"] > 0:
                am += 1
            else:
                at += 1
        arms[a] = {"n": len(ts), "flagged": fl, "attributable": at, "ambiguous": am}
    touched = V.touched_segments(trials, V.ro_connect(db), W)
    floor = {}
    for g in ("second", "minute"):
        segs = [s for (gg, s) in verd if gg == g and s not in touched[g]]
        floor[g] = [sum(1 for s in segs if verd[(g, s)]["violation"]), len(segs)]
    # Sealing delay: anchor receipt minus the end of each one-second segment, for segments in the run window.
    delays = []
    seen = set()
    for line in lines:
        r = json.loads(line)
        p = r.get("payload") or {}
        for k in ((p.get("sealed") or {}).get("second") or {}):
            if k not in seen and t0 <= int(k) <= t1:
                seen.add(k)
                delays.append(r["recv_ts"] - (int(k) + 1))
    n_all = sum(x["n"] for x in arms.values())
    amb = sum(x["ambiguous"] for x in arms.values())
    att = sum(x["attributable"] for x in arms.values())
    return {"tag": tag, "grace_s": grace, "window": [t0, t1, tsnap], "arms": arms,
            "pooled": {"n": n_all, "attributable": att, "ambiguous": amb,
                       "attributable_ci": V.cp(att, n_all), "ambiguous_ci": V.cp(amb, n_all)},
            "benign_floor": {g: {"k": k, "n": n, "ci": V.cp(k, n)} for g, (k, n) in floor.items()},
            "sealing_delay_s": {"n": len(delays), "median": round(statistics.median(delays), 3),
                                "p90": round(sorted(delays)[int(0.9 * (len(delays) - 1))], 3), "max": round(max(delays), 3)},
            "inputs": {"recorder_db_sha256": sha(db), "chain_sha256": sha(chain), "result_sha256": sha(res_p),
                       "config_sha256": sha(os.path.join(V.OUT, f"{tag}_config.json"))},
            "node_hash_encoding": encs[0]}


if __name__ == "__main__":
    out = {"experiment": "E3 grace-period sealing, paired real-deployment runs (other-principal arms PU and PI)",
           "runs": [score(t, g) for t, g in RUNS.items()],
           "counting_rule": "reproduce/verify_all.py run_one (flagged; attributable delta_n<=0; ambiguous delta_n>0); "
                            "benign floor over untouched anchored segments (touched_segments)",
           "versions": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "verify_all_py_sha256": sha(os.path.join(REPO, "reproduce", "verify_all.py")),
                        "monitor_py_sha256": sha(os.path.join(REPO, "monitor", "monitor.py"))}}
    p = os.path.join(V.OUT, "e3_grace_sealing.json")
    json.dump(out, open(p, "w"), indent=1)
    for r in out["runs"]:
        print(r["tag"], r["grace_s"], r["arms"], r["pooled"], r["benign_floor"], r["sealing_delay_s"])
    print(p, sha(p)[:12])
