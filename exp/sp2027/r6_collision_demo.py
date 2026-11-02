"""R6 (T7): end-to-end demonstration of the v1 node-hash collision on a real recorder snapshot, and that v2 closes it.

On a scratch COPY of the e_psr_clo verifier snapshot (Closure scheme, authenticated chain), two rewrites are applied to
rows in anchored, untouched one-second segments:

  A  parent/user splice (the triage's case): a row whose context_parent_id_bin contains 0x7C at byte k and whose
     context_user_id_bin is NULL gets parent := parent[:k], user := parent[k+1:] + b'|';
  B  context/parent splice: a row whose context_id_bin contains 0x7C at byte k and whose parent is NULL gets
     context := context[:k], parent := context[k+1:] + b'|'.

Each rewritten segment is then verified the way verify_all.py does: the shipped monitor's load() and commit() with the
chain's encoding (v1) against the first anchored root. With v2, the sealed root is recomputed from the unmodified
snapshot rows (which reproduce the anchored v1 root exactly) and compared with the v2 fold of the rewritten rows.
Optionally (--ha-container NAME, read-only `docker exec`), the Home Assistant release's own decoders are asked what they
make of the rewritten values.

    python3 exp/sp2027/r6_collision_demo.py [--ha-container hpr-hass]     # writes exp/out/r6_collision_demo.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import verify_all as VA  # noqa: E402

RUN = "e_psr_clo"


def fold(M, nodes, enc):
    acc = M.ZERO
    for n in nodes:
        acc = M.H(acc + M.node_hash_closure(n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], encoding=enc))
    return acc.hex()


def pick(con, roots, touched, t0, t1, which):
    """First state row in an anchored, untouched second of the run window that the rewrite applies to."""
    col = "context_parent_id_bin" if which == "A" else "context_id_bin"
    other = "context_user_id_bin" if which == "A" else "context_parent_id_bin"
    q = (f"SELECT state_id, last_updated_ts, context_id_bin, context_parent_id_bin, context_user_id_bin FROM states "
         f"WHERE last_updated_ts BETWEEN ? AND ? AND instr({col}, x'7c') > 1 AND {other} IS NULL ORDER BY state_id")
    for sid, ts, ctx, par, usr in con.execute(q, (t0, t1)):
        s = str(int(ts // 1))
        if ("second", s) in roots and s not in touched:
            return sid, ts, ctx, par, usr
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None, help="full verifier snapshot set")
    ap.add_argument("--extracts", default=None, help="per-run window extracts (default reproduce/snapshots if present)")
    ap.add_argument("--ha-container", default=None)
    ap.add_argument("--out", default=os.path.join(OUT, "r6_collision_demo.json"))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite " + a.out)
    cfg = VA.RUNS[RUN]
    inputs = VA.default_inputs(a.snapshots, a.extracts)
    src, chain, _info = inputs.checked(RUN)
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    w = res["window"]
    t0, t1, tsnap = w["t_start"], w["t_end"], w["recorder_snapshot_at"]
    roots = VA.anchored_roots(VA.chain_lines(chain), t0, tsnap)
    out = {"item": "R6/T7: v1 collision demonstrated on a real snapshot copy; v2 detects it",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "inputs_mode": inputs.mode, "snapshot": os.path.relpath(src, inputs.base),
           "chain": os.path.relpath(chain, inputs.base), "snapshot_sha256": VA.sha256_file(src), "cases": {}}
    with tempfile.TemporaryDirectory() as tmp:
        M = VA.load_monitor("closure", tmp)
        trials = [t for t in res["trials"] if not t.get("err")]
        ro = VA.ro_connect(src)
        touched = VA.touched_segments(trials, ro, dict(M.GRAN))["second"]
        picks = {k: pick(ro, roots, touched, t0, t1, k) for k in ("A", "B")}
        ro.close()
        copy = os.path.join(tmp, "copy.db")
        shutil.copy2(src, copy)
        since = (int(t0 // 3600) - 1) * 3600.0
        before = M.load(copy, since=since)
        con = sqlite3.connect(copy)
        for case, p in picks.items():
            if p is None:
                out["cases"][case] = {"applied": False, "reason": "no qualifying row in an anchored untouched second"}
                continue
            sid, ts, ctx, par, usr = p
            if case == "A":
                k = par.index(b"|")
                new = {"context_parent_id_bin": par[:k], "context_user_id_bin": par[k + 1:] + b"|"}
            else:
                k = ctx.index(b"|")
                new = {"context_id_bin": ctx[:k], "context_parent_id_bin": ctx[k + 1:] + b"|"}
            con.execute("UPDATE states SET %s WHERE state_id=?" % ", ".join(f"{c}=?" for c in new),
                        (*new.values(), sid))
            out["cases"][case] = {"applied": True, "state_id": sid, "segment": str(int(ts // 1)),
                                  "before": {"context_id_bin": ctx.hex(), "context_parent_id_bin": par.hex() if par else None,
                                             "context_user_id_bin": usr.hex() if usr else None},
                                  "after": {c: v.hex() for c, v in new.items()}}
        con.commit()
        con.close()
        after = M.load(copy, since=since)
        for case, c in out["cases"].items():
            if not c.get("applied"):
                continue
            s = c["segment"]
            pre = [n for n in before if str(int(n[0] // 1)) == s]
            post = [n for n in after if str(int(n[0] // 1)) == s]
            root = roots[("second", s)]
            c["anchored_v1_root"] = root
            c["v1_unmodified_rows_reproduce_anchored_root"] = fold(M, pre, "v1") == root["acc"] and len(pre) == root["n"]
            c["v1_verifier_on_rewritten_rows"] = {"acc": fold(M, post, "v1"), "n": len(post)}
            c["v1_detects"] = not (c["v1_verifier_on_rewritten_rows"]["acc"] == root["acc"] and len(post) == root["n"])
            v2s, v2v = fold(M, pre, "v2"), fold(M, post, "v2")
            c["v2_sealed_from_unmodified_rows"], c["v2_verifier_on_rewritten_rows"] = v2s, v2v
            c["v2_detects"] = v2s != v2v
            # the minute and hour roots, too
            for g, wd in (("minute", 60.0), ("hour", 3600.0)):
                sg = str(int(float(s) // wd))
                r = roots.get((g, sg))
                if r:
                    p2 = [n for n in after if str(int(n[0] // wd)) == sg]
                    c[f"v1_{g}_root_unchanged"] = fold(M, p2, "v1") == r["acc"] and len(p2) == r["n"]
        # sanity: whole-window v1 verification of the rewritten copy flags no segment the snapshot itself did not flag
        phi_b = M.commit(before, encoding="v1")
        phi_a = M.commit(after, encoding="v1")
        vb = VA.verify_window(phi_b, roots, dict(M.GRAN), t0, t1)
        va = VA.verify_window(phi_a, roots, dict(M.GRAN), t0, t1)
        out["v1_window_verdicts_identical_before_and_after_rewrites"] = vb == va
        out["v1_violations_in_window"] = sum(1 for v in va.values() if v["violation"])
    if a.ha_container:
        vals = {case: c["after"] for case, c in out["cases"].items() if c.get("applied")}
        code = ("import json,sys\nfrom homeassistant.util.ulid import bytes_to_ulid_or_none as U\n"
                "from homeassistant.components.recorder.models.context import bytes_to_uuid_hex_or_none as V\n"
                "from homeassistant.const import __version__\n"
                "d=json.loads(sys.argv[1]); o={'ha_version': __version__}\n"
                "for k,c in d.items():\n o[k]={col:(V if col=='context_user_id_bin' else U)(bytes.fromhex(h)) for col,h in c.items()}\n"
                "print(json.dumps(o))")
        r = subprocess.run(["docker", "exec", a.ha_container, "python3", "-c", code, json.dumps(vals)],
                           capture_output=True, text=True, timeout=60)
        out["ha_decoders_on_rewritten_values"] = (json.loads(r.stdout) if r.returncode == 0
                                                  else {"error": r.stderr[-300:]})
        out["ha_container"] = a.ha_container
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out, indent=1)[:4000])


if __name__ == "__main__":
    main()
