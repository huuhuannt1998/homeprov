#!/usr/bin/env python3
"""E1 old-vs-new: every scalar in a recalibrated stage against its published
counterpart. Prints only what MOVED, plus the unchanged count, so a stage that
is invariant to the calibration says so in one line."""
import os, sys, json, re, glob
HERE = os.path.dirname(os.path.abspath(__file__))
OLD, NEW = os.path.join(HERE, "out"), os.path.join(HERE, "out_recal")

SKIP = re.compile(r"(capability|_ms$|elapsed|duration|wall|timestamp|generated_at|path|dir)", re.I)

def flat(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from flat(v, "%s.%s" % (p, k) if p else k)
    elif isinstance(o, list):
        for i, v in enumerate(o): yield from flat(v, "%s[%d]" % (p, i))
    elif isinstance(o, (int, float, bool)) and not isinstance(o, bool) or isinstance(o, bool):
        yield p, o

def pub(stage):
    n = stage.split("_")[0]
    for c in ("%s_final.json" % n, "%s.json" % stage, "%s.json" % n):
        f = os.path.join(OLD, c)
        if os.path.exists(f): return f
    return None

rows = []
for f in sorted(glob.glob(os.path.join(NEW, "stage*.json"))):
    stage = os.path.basename(f)[:-5]
    o = pub(stage)
    if not o:
        rows.append((stage, None, None, ["no published counterpart"])); continue
    A = dict(x for x in flat(json.load(open(o))) if not SKIP.search(x[0]))
    B = dict(x for x in flat(json.load(open(f))) if not SKIP.search(x[0]))
    keys = sorted(set(A) & set(B))
    moved = []
    for k in keys:
        a, b = A[k], B[k]
        if a == b: continue
        if isinstance(a, float) and isinstance(b, float) and abs(a-b) < 1e-9: continue
        moved.append("%s: %s -> %s" % (k, a, b))
    rows.append((stage, len(keys), len(moved), moved))

for stage, n, nm, moved in rows:
    if n is None: print("?? %-22s %s" % (stage, moved[0])); continue
    tag = "== " if nm == 0 else "!! "
    print("%s%-22s %d scalars compared, %d moved" % (tag, stage, n, nm))
    for m in moved[:int(sys.argv[1]) if len(sys.argv)>1 else 12]:
        print("      %s" % m)
    if nm > 12 and len(sys.argv) <= 1: print("      ... %d more" % (nm-12))
