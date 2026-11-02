"""R13 (2026-10-08): score a two-host run (E1, E5) with the paper's counting rule from its saved snapshot and chain.

The shipped aggregator (exp/stages/e_ps_detection.py) counts a trial's touched segment from the judged row only; the
paper's counting rule (reproduce/verify_all.py, touched_segments) counts every one-second segment holding a row the
trial wrote. This script applies verify_all.py's anchored_roots, verify_window, touched_segments and cp to the run's
saved verifier snapshot and anchor chain, exactly as exp/stages/e3_grace_score.py does for E3.

    python3 exp/sp2027/r13_paper_rule_floor.py e5_psr_lnk <research-dir>/HOMEPROV-P13-exp/e5/e5_psr_lnk
writes exp/out/<tag>_paper_rule.json (never overwrites)
"""
import collections, hashlib, json, os, sys
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as V  # noqa: E402

tag, rundir = sys.argv[1], sys.argv[2]
dst = os.path.join(V.OUT, f"{tag}_paper_rule.json")
if os.path.exists(dst):
    raise SystemExit("refusing to overwrite " + dst)
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
db, chain = os.path.join(rundir, "ps_verify", "recorder.db"), os.path.join(rundir, "chain.jsonl")
res_p = os.path.join(V.OUT, f"{tag}_detection.json")
res = json.load(open(res_p))
t0, t1, tsnap = res["window"]["t_start"], res["window"]["t_end"], res["window"]["recorder_snapshot_at"]
M = V.load_monitor("closure", os.path.join(rundir, "paper_rule_scratch"))
W = dict(M.GRAN)
roots = V.anchored_roots(V.chain_lines(chain), t0, tsnap)
encs = sorted({a["encoding"] for a in roots.values()})
assert len(encs) == 1, encs
phi = M.commit(M.load(db, since=(int(t0 // 3600) - 1) * 3600.0), encoding=encs[0])
verd = V.verify_window(phi, roots, W, t0, t1)
trials = [t for t in res["trials"] if not (t.get("err") or t.get("error"))]
fl = at = am = 0
for t in trials:
    seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
    v = verd.get(("second", str(seg))) if seg is not None else None
    if not (v and v["violation"]):
        continue
    fl += 1
    if v["delta_n"] is not None and v["delta_n"] > 0:
        am += 1
    else:
        at += 1
touched = V.touched_segments(trials, V.ro_connect(db), W)
mech = lambda v: ("segment_vanished" if v.get("delta_n") is None else "rows_arrived_after_seal" if v["delta_n"] > 0
                  else "rows_removed_after_seal" if v["delta_n"] < 0 else "content_changed_in_place")
floor = {}
for g in ("second", "minute"):
    segs = [s for (gg, s) in verd if gg == g and s not in touched[g]]
    k = sum(1 for s in segs if verd[(g, s)]["violation"])
    floor[g] = {"k": k, "n": len(segs), "ci": V.cp(k, len(segs)),
                "mechanisms": dict(collections.Counter(mech(verd[(g, s)]) for s in segs if verd[(g, s)]["violation"]))}
out = {"tag": tag, "rule": "reproduce/verify_all.py anchored_roots, verify_window, touched_segments, cp (as E3)",
       "encoding": encs, "n_trials": len(trials), "flagged": fl, "attributable": at, "ambiguous": am,
       "attributable_ci": V.cp(at, len(trials)), "benign_floor": floor,
       "inputs": {"recorder_db_sha256": sha(db), "chain_sha256": sha(chain), "result_sha256": sha(res_p)},
       "code": {"script_sha256": sha(os.path.abspath(__file__)),
                "verify_all_py_sha256": sha(os.path.join(REPO, "reproduce", "verify_all.py")),
                "monitor_py_sha256": sha(os.path.join(REPO, "monitor", "monitor.py"))}}
with open(dst, "x") as fh:
    json.dump(out, fh, indent=1)
print(json.dumps({k: out[k] for k in ("flagged", "attributable", "ambiguous", "attributable_ci", "benign_floor")}))
