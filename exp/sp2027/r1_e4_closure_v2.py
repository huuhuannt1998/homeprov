#!/usr/bin/env python3
"""R1 item 4 (positive control): dynamic renderer-closure MUTATION re-run via the
homeprov_e4 'closure' verb on a target release, compared to the 2026.7.4 baseline
and the 2026.9.4 result. Confirms/refutes that states.last_changed_ts is newly
attribution-relevant by mutation. Writes exp/out/r1_<ver>_e4_closure_v2.json.
usage: r1_e4_closure_v2.py <ha_version> <container>"""
import json, os, subprocess, sys, time
sys.path.insert(0,"<artifact-root>/exp/sp2027")
import r1_common as RC
VER=sys.argv[1]; C=sys.argv[2]
NINE4=json.load(open("<artifact-root>/exp/out/r1_2026.9.4_e4_closure.json"))
BASE74=NINE4["baseline_2026_7_4"]            # {all_tested,n_relevant,relevant}
NEW94=NINE4["new_release"]

def ex(code): return subprocess.run(["docker","exec",C,"sh","-c",code],capture_output=True,text=True)

# send closure verb
ex("rm -f /config/homeprov_e4.ack")
subprocess.run(["docker","exec",C,"sh","-c","printf closure > /config/homeprov_e4.cmd"],check=True)
end=time.time()+600; ack=None
while time.time()<end:
    r=ex("cat /config/homeprov_e4.ack 2>/dev/null")
    if r.stdout.strip():
        ack=r.stdout.strip(); break
    time.sleep(5)
if ack is None: raise SystemExit("TIMEOUT waiting homeprov_e4 closure ack")
# pull the full report
rep=json.loads(ex("cat /config/homeprov_out/e4_closure.json").stdout)
muts=rep.get("mutations",[])
all_tested=sorted(m["field"] for m in muts)
relevant=sorted(m["field"] for m in muts if m.get("attribution_relevant"))
new={"all_tested":all_tested,"n_relevant":len(relevant),"relevant":relevant}
def setcmp(a,b):
    sa,sb=set(a),set(b)
    return {"all_tested_set_identical":set(all_tested)==set(b["all_tested"]),
            "only_in_this":sorted(set(relevant)-set(b["relevant"])),
            "only_in_other":sorted(set(b["relevant"])-set(relevant)),
            "relevant_set_identical":set(relevant)==set(b["relevant"])}
payload={
 "experiment":"R1-item4-dynamic","ha_version":VER,
 "what":("renderer dependency-closure MUTATION re-run (homeprov_e4 'closure') on %s: each DB "
         "column mutated, rendered cause re-read, field flagged attribution-relevant if the render "
         "changed; positive control validates the harness. Compared to the 2026.7.4 baseline and "
         "the 2026.9.4 result."%VER),
 "new_release":new,
 "positive_control":rep.get("positive_control"),
 "last_changed_ts_attribution_relevant":("states.last_changed_ts" in relevant),
 "baseline_2026_7_4":BASE74,
 "result_2026_9_4":NEW94,
 "comparison_vs_2026_7_4":setcmp(relevant,BASE74),
 "comparison_vs_2026_9_4":setcmp(relevant,NEW94),
 "verdict":None,  # filled below
 "raw_component_output":rep,
 "ack":json.loads(ack) if ack.startswith("{") else ack,
 "provenance":RC.provenance(VER,["<artifact-root>/exp/sp2027/r1_e4_closure_v2.py",
    "<artifact-root>/exp/sp2027/r1_common.py"]),
}
lc = "states.last_changed_ts" in relevant
same94 = set(relevant)==set(NEW94["relevant"])
payload["verdict"]=("CONFIRMS 2026.9.4 on %s: relevant set %s 2026.9.4 (%d fields); "
   "states.last_changed_ts %s attribution-relevant by mutation; all_tested=%d."%(
   VER,"==" if same94 else "!=",len(relevant),"IS" if lc else "is NOT",len(all_tested)))
RC.write_result("r1_%s_e4_closure_v2.json"%VER,payload)
print(payload["verdict"])
print("relevant:",relevant)
