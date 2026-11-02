#!/usr/bin/env python3
"""Aggregate r1_laundering_render output into an exp/out result file (item 2).
Per-trial rows, Clopper-Pearson proportions, rendered-vs-rule agreement, the
Activity Details context-chain finding, the automation-trace finding, provenance.
usage: r1_laundering_aggregate.py <ha_version> <container>"""
import json, os, subprocess, sys
sys.path.insert(0,"<artifact-root>/exp/sp2027")
import r1_common as RC
VER=sys.argv[1]; C=sys.argv[2]
SRC="/tmp/r1_laundering_render_%s.json"%VER
d=json.load(open(SRC))
TR=d["trials"]; n=len(TR)
TRACE_KEY={"porch":"automation.motion_light_porch","hallway":"automation.motion_light_hall","kitchen":"automation.motion_light_kitchen"}

def norm(s):
    if s is None or s=="": return "none"
    if s.startswith("By automation"): return "automation"
    if s.startswith("By state change"): return "automation"
    if s.startswith("By "): return "user:"+s[3:]
    if s.startswith("Via "): return "integration:"+s[4:].lower()
    return s
def norm_rule(r):
    if r is None: return "none"
    if r.startswith("automation:"): return "automation"
    return r

# trace finding (independent of run): does each room automation's saved trace
# contain the unlock? (expect no)
def trace_probe():
    code=r"""
import json
d=json.load(open('/config/.storage/trace.saved_traces')); data=d.get('data',{})
out={}
for k,v in data.items():
    blob=json.dumps(v)
    out[k]={'n':len(v) if isinstance(v,list) else None,
            'mentions_lock_front_door':'lock.front_door' in blob,'mentions_unlock':'unlock' in blob,
            'mentions_light':'light.' in blob}
print(json.dumps(out))"""
    r=subprocess.run(["docker","exec",C,"python3","-c",code],capture_output=True,text=True)
    try: return json.loads(r.stdout.strip())
    except Exception: return {"err":r.stderr[:200]}
traces=trace_probe()

moved={("admin"):0,("non_admin"):0}
agree=0; agree_total=0
details_names_lock_after={"admin":0,"non_admin":0}  # after-laundering chain still names the lock action -> exposes
view_trace_admin_after=0
rows=[]
for t in TR:
    r={"room":t["room"],"trial":t["trial"],"ops":t["ops"],"rendered":{},"rule":{"before":t["rule_before"],"after":t["rule_after"]}}
    for viewer in ("admin","non_admin"):
        b=t["before"][viewer]; a=t["after"][viewer]
        r["rendered"][viewer]={"before_top":b["top_cause"],"after_top":a["top_cause"],
                               "before_wh":b["wh"],"after_wh":a["wh"]}
        if (b["top_cause"] or "")!=(a["top_cause"] or ""): moved[viewer]+=1
        # rendered-vs-rule agreement, both phases
        for ph,rend,rul in (("before",b["top_cause"],t["rule_before"][viewer]),
                            ("after",a["top_cause"],t["rule_after"][viewer])):
            agree_total+=1
            if norm(rend)==norm_rule(rul): agree+=1
        wh=a["wh"] or []
        if any("Unlock lock" in x or x=="Lock" for x in wh): details_names_lock_after[viewer]+=1
        if viewer=="admin" and any(x=="View trace" for x in wh): view_trace_admin_after+=1
    rows.append(r)

payload={
 "experiment":"R1-item2-laundering-render",
 "what":("s1 laundering recipe (delete the adversary context's events; reattach the unlock "
         "state row to a genuine motion-light automation run), rendered in a real browser as "
         "an admin and a non-admin viewer, 3 configurations (porch/hallway/kitchen) x %d trials. "
         "Captures the Activity top line and the 2026.9 Activity Details context chain "
         "(dialog-logbook-detail 'What happened', frontend PR #53362) before/after, and compares "
         "to the transcribed display() rule."%d["n_per_room"]),
 "ha_version":VER,"configurations":d["rooms"],"n_per_room":d["n_per_room"],"n_total":n,
 "laundering_moved_displayed_top_line":{
    "admin":RC.cp(moved["admin"],n),"non_admin":RC.cp(moved["non_admin"],n)},
 "rendered_vs_rule_agreement":{"agree":agree,"total":agree_total,"prop":agree/agree_total if agree_total else None},
 "activity_details_chain":{
    "finding":("after laundering the Details 'What happened' chain shows Motion Detected -> "
               "<room> motion light Triggered -> Front Door Unlocked, i.e. it is built from the "
               "rewritten logbook context and corroborates the laundered cause; it does NOT name "
               "the lock integration"),
    "after_chain_still_names_lock_action":details_names_lock_after,
    "exposes_laundering": (details_names_lock_after["admin"]==0 and details_names_lock_after["non_admin"]==0)==False,
    "example_before_admin_wh": (rows[0]["rendered"]["admin"]["before_wh"] if rows else None),
    "example_after_admin_wh": (rows[0]["rendered"]["admin"]["after_wh"] if rows else None),
    "view_trace_link_admin_after_count":view_trace_admin_after,
    "view_trace_link_nonadmin":"absent (trace access is admin-gated; non-admin chain has no 'View trace')"},
 "automation_trace_finding":{
    "trace_keys":TRACE_KEY,"saved_traces":traces,
    "trace_exposes_laundering": all((not traces.get(k,{}).get("mentions_unlock",False)) for k in TRACE_KEY.values() if k in traces),
    "note":("the motion-light automation's saved execution traces contain only the motion->light "
            "actions and never a lock/unlock; following the admin 'View trace' link therefore "
            "contradicts the laundered chain -> the trace link EXPOSES the laundering")},
 "trials":rows,
 "provenance":RC.provenance(VER,[
    "<artifact-root>/exp/sp2027/r1_laundering_render.py",
    "<artifact-root>/exp/sp2027/r1_laundering_aggregate.py",
    "<artifact-root>/exp/sp2027/r1_common.py",
    "<artifact-root>/exp/sp2027/r1_render.py"]),
}
RC.write_result("r1_%s_laundering_render_v2.json"%VER, payload)
print("moved admin %d/%d non_admin %d/%d | agree %d/%d | details_names_lock_after %s | view_trace_admin %d"%(
    moved["admin"],n,moved["non_admin"],n,agree,agree_total,details_names_lock_after,view_trace_admin_after))
