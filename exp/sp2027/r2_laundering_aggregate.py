#!/usr/bin/env python3
"""Aggregate r2_laundering_render output (item 3). Adds per-trial trace-exposure
rate (borrowed run's saved trace present, reachable via admin 'View trace', and
containing no lock action -> contradicts the laundered chain) with exact CP, and
embeds integrity pre/post paths + validity.
usage: r2_laundering_aggregate.py <ha_version> <container> <pre_path> <post_path>"""
import json, os, subprocess, sys
sys.path.insert(0,"<artifact-root>/exp/sp2027")
import r1_common as RC
VER=sys.argv[1]; C=sys.argv[2]; PRE=sys.argv[3]; POST=sys.argv[4]
d=json.load(open("/tmp/r2_laundering_render_%s.json"%VER)); TR=d["trials"]; n=len(TR)
def gate_pass(p):
    try: return len(json.load(open(p)).get("fail",[]))==0
    except Exception: return False
pre_pass=gate_pass(PRE); post_pass=gate_pass(POST); valid=pre_pass and post_pass
def norm(s):
    if s is None or s=="": return "none"
    if s.startswith("By automation") or s.startswith("By state change"): return "automation"
    if s.startswith("By "): return "user:"+s[3:]
    if s.startswith("Via "): return "integration:"+s[4:].lower()
    return s
def normr(r):
    if r is None: return "none"
    if r.startswith("automation:"): return "automation"
    return r
moved={"admin":0,"non_admin":0}; agree=0; tot=0
details_lock_after={"admin":0,"non_admin":0}; vt_admin=0; vt_nonadmin=0
trace_present=0; trace_nolock=0; trace_exposes=0
rows=[]
for t in TR:
    r={"room":t["room"],"trial":t["trial"],"ops":t["ops"],"trace":t.get("trace"),
       "reachable_admin":t.get("reachable_admin"),"reachable_nonadmin":t.get("reachable_nonadmin"),"rendered":{}}
    for v in ("admin","non_admin"):
        b=t["before"][v]; a=t["after"][v]
        r["rendered"][v]={"before_top":b["top_cause"],"after_top":a["top_cause"],"after_wh":a["wh"]}
        if (b["top_cause"] or"")!=(a["top_cause"] or""): moved[v]+=1
        for rend,rul in ((b["top_cause"],t["rule_before"][v]),(a["top_cause"],t["rule_after"][v])):
            tot+=1
            if norm(rend)==normr(rul): agree+=1
        wh=a["wh"] or []
        if any("Unlock lock" in x or x=="Lock" for x in wh): details_lock_after[v]+=1
    if r["reachable_admin"]: vt_admin+=1
    if r["reachable_nonadmin"]: vt_nonadmin+=1
    tr=t.get("trace") or {}
    present=bool(tr.get("present")); nolock=not tr.get("mentions_lock",True)
    if present: trace_present+=1
    if present and nolock: trace_nolock+=1
    if present and nolock and r["reachable_admin"]: trace_exposes+=1
    rows.append(r)
payload={
 "experiment":"R2-item3-laundering-render","ha_version":VER,
 "what":("s1 laundering re-attached to the TRIGGERED room's own motion-light run (deviation fixed), "
         "rendered admin+non-admin, 3 configurations x %d trials; Activity top line + 2026.9/10 Details "
         "chain; per-trial automation-trace measurement; compared to display()."%d["n_per_room"]),
 "configurations":d["rooms"],"n_per_room":d["n_per_room"],"n_total":n,
 "laundering_moved_displayed_top_line":{"admin":RC.cp(moved["admin"],n),"non_admin":RC.cp(moved["non_admin"],n)},
 "rendered_vs_rule_agreement":{"agree":agree,"total":tot,"prop":agree/tot if tot else None},
 "activity_details_chain":{"after_chain_names_lock_action":details_lock_after,
    "exposes_laundering":not (details_lock_after["admin"]==0 and details_lock_after["non_admin"]==0),
    "example_before_admin_wh":rows[0]["rendered"]["admin"]["after_wh"] if rows else None,
    "view_trace_admin_after":RC.cp(vt_admin,n),"view_trace_nonadmin_after":RC.cp(vt_nonadmin,n)},
 "automation_trace":{
    "borrowed_trace_present":RC.cp(trace_present,n),
    "trace_contains_no_lock":RC.cp(trace_nolock,n),
    "trace_exposure_rate":RC.cp(trace_exposes,n),
    "definition":"trace exposes laundering = borrowed run's saved trace present AND reachable via admin 'View trace' AND contains no lock action"},
 "integrity":{"pre_path":PRE,"pre_pass":pre_pass,"post_path":POST,"post_pass":post_pass,"valid":valid},
 "trials":rows,
 "provenance":RC.provenance(VER,[
    "<artifact-root>/exp/sp2027/r2_laundering_render.py",
    "<artifact-root>/exp/sp2027/r2_laundering_aggregate.py",
    "<artifact-root>/exp/sp2027/r1_common.py",
    "<artifact-root>/exp/sp2027/r1_render.py"]),
}
RC.write_result("r2_%s_laundering_render.json"%VER,payload)
if not valid:
    side="<artifact-root>/exp/out/r2_%s_laundering_render_INVALID.json"%VER
    json.dump({"invalid":True,"reason":"integrity gate FAILED","integrity":payload["integrity"]},open(side,"w"),indent=1)
    print("INVALID integrity gate -> sidecar",side)
print("moved admin %d/%d non_admin %d/%d | agree %d/%d | details_lock_after %s | VT admin %d nonad %d | trace present %d nolock %d exposes %d | valid %s"%(
 moved["admin"],n,moved["non_admin"],n,agree,tot,details_lock_after,vt_admin,vt_nonadmin,trace_present,trace_nolock,trace_exposes,valid))
