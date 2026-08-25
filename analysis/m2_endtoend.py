"""M2 end-to-end: does the P1-anchored commitment catch the M1 forgery?

Reads the append-only chain, takes the last anchor recorded BEFORE the
forgery, recomputes the commitment over the (now forged) live database, and
compares. No in-memory anchor: the reference comes off the append-only file
the adversary could not rewrite.
"""
import json, subprocess, sys

def sh(c):
    return subprocess.run(["docker","exec","homeprov-ha","sh","-c",c],
                          capture_output=True, text=True).stdout

chain = [json.loads(l) for l in sh("cat /anchor/chain").splitlines() if l.strip()]
report = json.loads(sh("cat /config/homeprov_out/s1_report.json"))
# forgery time = timestamp of the injected automation event's context window
forge_ts = report["B_graph"]["states"][-1]["ts"]

pre = [c for c in chain if c["r"]["ts"] <= forge_ts]
post = [c for c in chain if c["r"]["ts"] > forge_ts]
print("chain records: %d total, %d before the forgery, %d after" % (len(chain), len(pre), len(post)))
if not pre:
    print("NO PRE-FORGERY ANCHOR — cannot verify"); sys.exit(1)

ref = pre[-1]
print("reference anchor: seq=%s digest=%s..." % (ref["r"]["seq"], ref["d"][:16]))

# recompute over the CURRENT (forged) database using the defender's own code
cur = json.loads(sh(
  "cd /config/custom_components && python -c \""
  "import json,sys; sys.path.insert(0,'.');"
  "from homeprov import commitment; print(json.dumps(commitment()))\""))

# A2 commits a segment only when it CLOSES. A segment still open at anchor
# time legitimately grows afterwards, so comparing it produces false positives.
WIDTH = {"second": 1.0, "minute": 60.0, "hour": 3600.0}
anchor_ts = ref["r"]["ts"]
viol, skipped_open = [], 0
for gran in ("second","minute","hour"):
    w = WIDTH[gran]
    old, new = ref["r"]["phi"][gran], cur[gran]
    for k in set(old) | set(new):
        o, n = old.get(k), new.get(k)
        if o is None:
            # A4 UNCOMMITTED-REGIONS. A segment absent from the anchor is only
            # legitimate if it lies in the FUTURE relative to the anchor.
            # A brand-new segment wholly in the anchor's PAST cannot be honest:
            # nothing can be appended to a time that has already been committed.
            # Omitting this check makes backdated injection invisible.
            if (int(k) + 1) * w <= anchor_ts:
                viol.append((gran, k, "UNCOMMITTED HISTORICAL SEGMENT (backdated injection)"))
            continue
        if (int(k) + 1) * w > anchor_ts:               # segment was still OPEN when anchored
            skipped_open += 1
            continue
        if n is None:
            viol.append((gran,k,"SEGMENT_GONE")); continue
        # report BOTH: a count change must not mask an accumulator change in the
        # same segment, or re-parenting hides behind deletion.
        if o["n"] != n["n"]:
            viol.append((gran,k,"COUNT %d->%d"%(o["n"],n["n"])))
        if o["acc"] != n["acc"]:
            viol.append((gran,k,"ACC (structure or content changed)"))
print("closed-segment comparison; %d open segments correctly skipped" % skipped_open)

print()
print("="*70)
print("VERDICT: %s" % ("TAMPERING DETECTED — %d violated segments" % len(viol) if viol
                       else "no violation (FORGERY MISSED)"))
print("="*70)
for g,k,w in sorted(viol)[:20]:
    print("   %-7s seg=%-12s %s" % (g,k,w))
json.dump({"chain_records":len(chain),"pre":len(pre),"violations":len(viol),
           "detail":[{"gran":g,"seg":k,"why":w} for g,k,w in viol]},
          open("analysis/m2_endtoend_result.json","w"), indent=2)
