#!/usr/bin/env python3
"""Aggregate r1_memberswap_render output -> exp/out result (item 3).
usage: r1_memberswap_aggregate.py <ha_version>"""
import json,sys
sys.path.insert(0,"<artifact-root>/exp/sp2027")
import r1_common as RC
VER=sys.argv[1]; d=json.load(open("/tmp/r1_memberswap_render_%s.json"%VER)); TR=d["trials"]; n=len(TR)
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
c={("admin","member"):0,("non_admin","member"):0,("admin","random"):0,("non_admin","random"):0}
agree=0; tot=0; rows=[]
for t in TR:
    r={"room":t["room"],"trial":t["trial"],"rendered":{},"rule_member":t["rule_member"]}
    for v in ("admin","non_admin"):
        base=t["baseline"][v]["top_cause"]; mem=t["member"][v]["top_cause"]; rnd=t["random"][v]["top_cause"]
        r["rendered"][v]={"baseline":base,"member":mem,"random":rnd,
                          "member_wh":t["member"][v]["wh"]}
        if (mem or"")!=(base or""): c[(v,"member")]+=1
        if (rnd or"")!=(base or""): c[(v,"random")]+=1
        # agreement on baseline + member arms
        tot+=1
        if norm(base)==normr(t["rule_baseline"][v]): agree+=1
        tot+=1
        if norm(mem)==normr(t["rule_member"][v]): agree+=1
    rows.append(r)
payload={"experiment":"R1-item3-memberswap-render","ha_version":VER,
 "what":("member-account swap (context_user_id_bin<-provisioned household member) and random-id "
         "control, rendered as admin and non-admin viewer, 3 configurations x %d trials; Activity "
         "top line + 2026.9 Details chain; compared to display(). Extends the N=10 porch result."%d["n_per_room"]),
 "configurations":d["rooms"],"n_per_room":d["n_per_room"],"n_total":n,
 "member_account":{"user_id_hex":d["member_hex"],"name":"Alex Rivera (household)","in_admin_name_map":d["names_admin_has_member"]},
 "member_swap_changed_displayed_cause":{"admin":RC.cp(c[("admin","member")],n),"non_admin":RC.cp(c[("non_admin","member")],n)},
 "random_id_changed_displayed_cause":{"admin":RC.cp(c[("admin","random")],n),"non_admin":RC.cp(c[("non_admin","random")],n)},
 "rendered_vs_rule_agreement":{"agree":agree,"total":tot,"prop":agree/tot if tot else None},
 "details_chain_example":{"member_admin_wh":rows[0]["rendered"]["admin"]["member_wh"] if rows else None,
                          "member_nonadmin_wh":rows[0]["rendered"]["non_admin"]["member_wh"] if rows else None},
 "extends":"exp/out/r1_2026.9.4_member_swap_render.json (N=10 porch): combined admin %d/%d, non-admin 0/%d"%(c[("admin","member")]+10,n+10,n+10),
 "trials":rows,
 "provenance":RC.provenance(VER,["<artifact-root>/exp/sp2027/r1_memberswap_render.py",
    "<artifact-root>/exp/sp2027/r1_memberswap_aggregate.py",
    "<artifact-root>/exp/sp2027/r1_common.py","<artifact-root>/exp/sp2027/r1_render.py"])}
RC.write_result("r1_%s_memberswap_render_v2.json"%VER,payload)
print("member admin %d/%d non_admin %d/%d | random admin %d/%d non_admin %d/%d | agree %d/%d"%(
 c[("admin","member")],n,c[("non_admin","member")],n,c[("admin","random")],n,c[("non_admin","random")],n,agree,tot))
