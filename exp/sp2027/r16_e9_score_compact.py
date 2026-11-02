#!/usr/bin/env python3
"""A compact, loadable copy of E9's frozen score file (exp/out/e9_main2_score.json, 2.6 GB), for the round-16 analyses.

The score file is written by exp/stages/e9_score.py with json.dump(indent=1). About 2.6 GB of it are the
"verifier" subtrees of days/<n>/by_monitor/<m> and nights/<n>/by_monitor/<m> (verifier_marker_fields: the
verifier's own marker, purge and restore detail, lists of excused segments). Every registered outcome the scorer
computes is in the other fields. This script streams the file line by line and copies every line except those
subtrees, each replaced by {"_compacted": true, "scalars": <its one-line scalar fields>, "subtree_bytes": <bytes of each
of its top-level keys>}. Nothing else is changed; the output parses as JSON and names the source file's sha256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re

KEY = re.compile(r'^( *)"([^"]*)": (.*)$')


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    src_sha = sha(a.score)
    path, out, n_compacted = [], [], 0
    with open(a.score) as f:
        it = iter(f)
        for line in it:
            m = KEY.match(line)
            if m:
                d, k, rest = len(m.group(1)), m.group(2), m.group(3)
                path = path[:d - 1] + [k]
                if (k == "verifier" and d == 5 and len(path) == 5 and path[0] in ("days", "nights")
                        and path[2] == "by_monitor" and rest.rstrip() == "{"):
                    scalars, sizes, cur = {}, {}, None
                    closing = None
                    for sub in it:
                        if sub.rstrip("\n") in (" " * d + "}", " " * d + "},"):
                            closing = sub
                            break
                        sm = KEY.match(sub)
                        if sm and len(sm.group(1)) == d + 1:
                            cur = sm.group(2)
                            v = sm.group(3).rstrip().rstrip(",")
                            if v not in ("{", "[") and len(v) < 2000:
                                try:
                                    scalars[cur] = json.loads(v)
                                except ValueError:
                                    pass
                        if cur is not None:
                            sizes[cur] = sizes.get(cur, 0) + len(sub)
                    assert closing is not None, path
                    comma = "," if closing.rstrip("\n").endswith(",") else ""
                    out.append(" " * d + '"verifier": ' + json.dumps({"_compacted": True, "scalars": scalars,
                                                                      "subtree_bytes": sizes}) + comma + "\n")
                    n_compacted += 1
                    continue
            out.append(line)
    doc = json.loads("".join(out))
    doc["_compact"] = {"source": os.path.relpath(a.score, os.path.dirname(os.path.dirname(os.path.abspath(a.score)))),
                       "source_sha256": src_sha, "verifier_subtrees_compacted": n_compacted,
                       "script": "exp/sp2027/r16_e9_score_compact.py"}
    with open(a.out, "x") as f:
        json.dump(doc, f, indent=1)
    print("wrote %s (%d verifier subtrees compacted) sha256 %s; source sha256 %s" % (a.out, n_compacted, sha(a.out), src_sha))


if __name__ == "__main__":
    main()
