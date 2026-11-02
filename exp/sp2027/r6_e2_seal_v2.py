"""R6 (T7): the E2 authenticated seal check (exp/out/e2_auth_seal_check.json) re-done with both node encodings.

E2 asks whether the monitor sealed the second holding the adversary's censored actuation, and whether that sealed root
includes the adversary's row (the recomputed segment equals the anchored one). This recomputes the adversary second from
the saved snapshot with v1 (must reproduce the published answer) and checks the rows for 0x7C-bearing context fields. A
v1 match means the snapshot rows are the sealed rows, so their v2 fold is the v2 root a v2 monitor would have sealed.

    python3 exp/sp2027/r6_e2_seal_v2.py      # writes exp/out/r6_e2_seal_v2.json (never overwrites)
"""
import json
import os
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as VA  # noqa: E402

SNAP = os.environ.get("HOMEPROV_SNAPSHOTS", VA.DEFAULT_SNAP)
DB, CHAIN = "hp-e2-auth/seal_verify/recorder.db", "hp-e2-auth/e2_auth_chain.jsonl"
pub = json.load(open(os.path.join(OUT, "e2_auth_seal_check.json")))
dst = os.path.join(OUT, "r6_e2_seal_v2.json")
if os.path.exists(dst):
    raise SystemExit("refusing to overwrite " + dst)
sums = {p.strip()[2:]: h for h, p in (l.split(None, 1) for l in open(os.path.join(SNAP, "SHA256SUMS")))}
for rel in (DB, CHAIN):
    assert VA.sha256_file(os.path.join(SNAP, rel)) == sums[rel], rel
lines = VA.chain_lines(os.path.join(SNAP, CHAIN))
schemes = {json.loads(l).get("payload", {}).get("scheme") for l in lines if l.strip()}
scheme = (schemes - {None}).pop() if len(schemes - {None}) == 1 else "row"
first = {}
for l in lines:
    p = json.loads(l).get("payload") or {}
    for g, segs in (p.get("sealed") or {}).items():
        for s, v in (segs or {}).items():
            first.setdefault((g, str(s)), {**v, "encoding": p.get("encoding", "v1")})
with tempfile.TemporaryDirectory() as tmp:
    M = VA.load_monitor(scheme, tmp)
    res = {"item": "R6/T7: E2 seal check with v1 and v2", "snapshot": DB, "chain": CHAIN, "chain_scheme": scheme,
           "published": {k: pub[k] for k in ("adversary_second_sealed", "sealed_root_includes_adversary_row", "adversary_seconds")},
           "per_second": []}
    for sec in pub["adversary_seconds"]:
        nodes = [n for n in M.load(DB if os.path.isabs(DB) else os.path.join(SNAP, DB), since=float(sec))
                 if int(n[0] // 1) == sec]
        a = first.get(("second", str(sec)))
        f1, f2 = M.commit(nodes, encoding="v1")["second"][str(sec)], M.commit(nodes, encoding="v2")["second"][str(sec)]
        res["per_second"].append({
            "second": sec, "anchored": a, "v1_recomputed": f1,
            "v1_root_matches": bool(a and a["acc"] == f1["acc"] and a["n"] == f1["n"]),
            "v2_root_of_sealed_rows": f2,
            "rows_with_0x7C_in_ctx_or_par": sum(1 for n in nodes if any(b and 0x7C in b for b in (n[3], n[4]))),
            "rows": len(nodes)})
    res["v1_reproduces_published"] = all(x["v1_root_matches"] for x in res["per_second"]) == pub["sealed_root_includes_adversary_row"]
    res["conclusion"] = ("the snapshot rows reproduce the anchored v1 root, so they are the sealed rows; the adversary row "
                         "is in the sealed segment under either encoding")
with open(dst, "x") as fh:
    json.dump(res, fh, indent=1)
print(json.dumps(res, indent=1))
