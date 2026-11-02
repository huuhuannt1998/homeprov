#!/usr/bin/env python3
"""Aggregate r2 member-swap render output (items 4 and 5). Embeds integrity paths
+ validity; writes exp/out/<out_name>. INVALID sidecar if the gate failed.
usage: r2_memberswap_aggregate.py <ha_version> <tmp_path> <pre> <post> <out_name>"""
import json,sys
sys.path.insert(0,"<artifact-root>/exp/sp2027")
import r1_common as RC
VER=sys.argv[1]; TMP=sys.argv[2]; PRE=sys.argv[3]; POST=sys.argv[4]; OUT=sys.argv[5]
d=json.load(open(TMP)); TR=d["trials"]; n=len(TR)
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
c={("admin","member"):0,("non_admin","member"):0,("admin","random"):0,("non_admin","random"):0}
agree=0; tot=0; rows=[]
for t in TR:
    r={"room":t["room"],"trial":t["trial"],"rendered":{},"rule_member":t["rule_member"]}
    for v in ("admin","non_admin"):
        base=t["baseline"][v]["top_cause"]; mem=t["member"][v]["top_cause"]; rnd=t["random"][v]["top_cause"]
        r["rendered"][v]={"baseline":base,"member":mem,"random":rnd,"member_wh":t["member"][v]["wh"]}
        if (mem or"")!=(base or""): c[(v,"member")]+=1
        if (rnd or"")!=(base or""): c[(v,"random")]+=1
        tot+=1
        if norm(base)==normr(t["rule_baseline"][v]): agree+=1
        tot+=1
        if norm(mem)==normr(t["rule_member"][v]): agree+=1
    rows.append(r)
payload={"experiment":"R2-memberswap-render","ha_version":VER,"output":OUT,
 "what":("member-account swap (context_user_id_bin<-member) + random-id control, rendered "
         "admin+non-admin, 3 configs x %d trials; non-admin name map = person entities."%d["n_per_room"]),
 "configurations":d["rooms"],"n_per_room":d["n_per_room"],"n_total":n,
 "member_account":{"user_id_hex":d["member_hex"],"name":"Alex Rivera (household)",
    "in_admin_name_map":d["names_admin_has_member"],"in_nonadmin_person_map":d.get("names_nonadmin_has_member"),
    "person_name_map_size":d.get("person_name_map_size")},
 "member_swap_changed_displayed_cause":{"admin":RC.cp(c[("admin","member")],n),"non_admin":RC.cp(c[("non_admin","member")],n)},
 "random_id_changed_displayed_cause":{"admin":RC.cp(c[("admin","random")],n),"non_admin":RC.cp(c[("non_admin","random")],n)},
 "rendered_vs_rule_agreement":{"agree":agree,"total":tot,"prop":agree/tot if tot else None},
 "details_chain_example":{"member_admin_wh":rows[0]["rendered"]["admin"]["member_wh"] if rows else None,
                          "member_nonadmin_wh":rows[0]["rendered"]["non_admin"]["member_wh"] if rows else None},
 "integrity":{"pre_path":PRE,"pre_pass":pre_pass,"post_path":POST,"post_pass":post_pass,"valid":valid},
 "trials":rows,
 "provenance":RC.provenance(VER,["<artifact-root>/exp/sp2027/r2_memberswap_render.py",
    "<artifact-root>/exp/sp2027/r2_memberswap_aggregate.py",
    "<artifact-root>/exp/sp2027/r1_common.py","<artifact-root>/exp/sp2027/r1_render.py"])}
RC.write_result(OUT,payload)
if not valid:
    side="<artifact-root>/exp/out/"+OUT.replace(".json","_INVALID.json")
    json.dump({"invalid":True,"reason":"integrity gate FAILED","integrity":payload["integrity"]},open(side,"w"),indent=1)
    print("INVALID gate -> sidecar",side)
print("%s: member admin %d/%d non_admin %d/%d | random admin %d/%d non_admin %d/%d | agree %d/%d | valid %s"%(
 OUT,c[("admin","member")],n,c[("non_admin","member")],n,c[("admin","random")],n,c[("non_admin","random")],n,agree,tot,valid))
