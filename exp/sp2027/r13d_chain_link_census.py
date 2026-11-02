#!/usr/bin/env python3
"""Round 13d (2026-10-09): which authenticated runs' saved anchor chains hold linked (hash-chained) records.

Round 13d recount with E8 (one run, two monitors, linked anchors) in the run-provenance table.
The paper states how many of the authenticated runs used the anchor daemon with unlinked records. The authenticated runs
are the rows of the run-provenance table that have a run configuration (floats/make_floats.py RUNS_G and RUNS_G12; E7
is one run with two monitors and two chains). For each run this counts the records of its saved chain(s) and the records
that carry a link to the previous record (`prev_digest`), and writes exp/out/r13d_chain_link_census.json.
"""
from __future__ import annotations

import ast
import datetime
import gzip
import hashlib
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(REPO, "exp", "out")
FLOATS = os.path.join(REPO, "[READY] (S&P 2027) HOMEPROV - P13", "floats", "make_floats.py")


def runs():
    s = open(FLOATS).read()
    rows = []
    for name in ("RUNS_G", "RUNS_G12"):
        i = s.index(name + " = [")
        rows += ast.literal_eval(s[i + len(name) + 3:s.index("]\n", i) + 1])
    # Round 13d: E8's rows are appended under the R13D_TABG gate ("RUNS_G12 = RUNS_G12 + [...]").
    j = s.find("RUNS_G12 = RUNS_G12 + [")
    if j >= 0:
        k = j + len("RUNS_G12 = RUNS_G12 + ")
        depth = 0
        for e in range(k, len(s)):
            depth += {"[": 1, "]": -1}.get(s[e], 0)
            if depth == 0:
                break
        rows += ast.literal_eval(s[k:e + 1])
    out = {}
    for r in rows:
        if len(r) > 2 and r[2]:                              # authenticated: the row has a run configuration
            tag = r[2][:-len("_config.json")]
            out.setdefault(tag, []).append(r[1])
    return out


def chains(tag):
    cands = sorted(f for f in os.listdir(OUT) if f.startswith(tag + "_") and "chain" in f and f.endswith(".jsonl.gz"))
    assert cands, tag
    return cands


def census(path):
    n = linked = 0
    for line in gzip.open(os.path.join(OUT, path), "rt"):
        if not line.strip():
            continue
        d = json.loads(line)
        n += 1
        rec = d.get("record") if isinstance(d.get("record"), dict) else d
        if "prev_digest" in d or "prev_digest" in rec or "prev_digest" in (rec.get("payload") or {}):
            linked += 1
    return {"file": "exp/out/" + path, "sha256": hashlib.sha256(open(os.path.join(OUT, path), "rb").read()).hexdigest(),
            "records": n, "linked_records": linked}


def main():
    per = {}
    for tag in runs():
        per[tag] = [census(c) for c in chains(tag)]
    with_links = sorted(t for t, cs in per.items() if any(c["linked_records"] for c in cs))
    out = {"what": __doc__.strip().splitlines()[0], "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
           "authenticated_runs": len(per), "chains": sum(len(c) for c in per.values()),
           "runs_with_linked_records": with_links, "runs_without_linked_records": len(per) - len(with_links),
           "per_run": per}
    dst = os.path.join(OUT, "r13d_chain_link_census.json")
    assert not os.path.exists(dst), dst
    json.dump(out, open(dst, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("authenticated_runs", "chains", "runs_with_linked_records",
                                          "runs_without_linked_records")}))


if __name__ == "__main__":
    main()
