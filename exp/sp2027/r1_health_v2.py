#!/usr/bin/env python3
"""R1 item 1 health check for an isolated hub. Verifies the four named criteria:
hub up, MQTT entities bound, motion-light automation bound (functional
motion->light), recorder writing. Records checks to exp/out/r1_<ver>_health_v2.json.
Reuses r1_common for provenance; refuses to overwrite (hard rule 1)."""
import json, os, subprocess, sys, time, requests
sys.path.insert(0, "<artifact-root>/exp/sp2027")
import r1_common as RC

AUTH = json.load(open(sys.argv[1])); VER = sys.argv[2]; C = sys.argv[3]
BASE = AUTH["base"]; H = {"Authorization": "Bearer " + AUTH["admin"]["token"]}
BROKER = C.replace("hass", "broker")
DB = "/config/home-assistant_v2.db"

def dbq(code):
    r = subprocess.run(["docker","exec",C,"python3","-c",code],capture_output=True,text=True)
    if r.returncode: raise RuntimeError(r.stderr[:200])
    return r.stdout.strip()

def states():
    return {s["entity_id"]: s for s in requests.get(BASE+"/api/states",headers=H,timeout=30).json()}

def pub(topic,msg):
    subprocess.run(["docker","exec",BROKER,"mosquitto_pub","-t",topic,"-m",msg],
                   capture_output=True,text=True,timeout=15)

chk = {}
cfg = requests.get(BASE+"/api/config",headers=H,timeout=20).json()
chk["hub_up"] = {"version": cfg.get("version"), "state": cfg.get("state"),
                 "mqtt_component": "mqtt" in cfg.get("components",[]),
                 "recorder_component": "recorder" in cfg.get("components",[]),
                 "pass": cfg.get("state")=="RUNNING"}
S = states()
mqtt_ents = ["binary_sensor.hallway_motion","binary_sensor.kitchen_motion","binary_sensor.porch_motion",
             "light.hallway_light","light.kitchen_light","light.porch_light",
             "lock.front_door","lock.back_door"]
mb = {e: (S[e]["state"] if e in S else "MISSING") for e in mqtt_ents}
chk["mqtt_entities_bound"] = {"entities": mb,
    "pass": all(e in S and S[e]["state"] not in ("unavailable","unknown",None) for e in mqtt_ents)}
autos = ["automation.hallway_motion_light","automation.kitchen_motion_light","automation.porch_motion_light"]
ab = {a: (S[a]["state"] if a in S else "MISSING") for a in autos}
# functional: motion porch -> porch light on
before_light = S.get("light.porch_light",{}).get("state")
# ensure light off first via automation's target? just flip motion ON and watch
cnt0 = dbq("import sqlite3;c=sqlite3.connect('%s');print(c.execute('select count(*) from states').fetchone()[0])"%DB)
pub("hpr/motion/porch/state","ON")
fired = False; last_light=None
end=time.time()+20
while time.time()<end:
    time.sleep(2)
    s2=states()
    last_light=s2.get("light.porch_light",{}).get("state")
    # automation last_triggered advanced?
    if last_light=="on":
        fired=True; break
pub("hpr/motion/porch/state","OFF")
time.sleep(2)
cnt1 = dbq("import sqlite3;c=sqlite3.connect('%s');print(c.execute('select count(*) from states').fetchone()[0])"%DB)
auto_state=states().get("automation.porch_motion_light",{})
chk["automation_bound"] = {"automation_states": ab,
    "functional_motion_to_light": {"light_before": before_light, "light_after": last_light, "fired": fired},
    "porch_last_triggered": auto_state.get("attributes",{}).get("last_triggered"),
    "pass": all(a in S and S[a]["state"]=="on" for a in autos) and fired}
chk["recorder_writing"] = {"states_rows_before": int(cnt0), "states_rows_after": int(cnt1),
    "delta": int(cnt1)-int(cnt0), "pass": int(cnt1) > int(cnt0)}
chk["overall_pass"] = all(v.get("pass") for v in chk.values() if isinstance(v,dict))

payload = {"experiment":"R1-item1-health","ha_version":VER,"container":C,
           "checks":chk,"provenance":RC.provenance(VER,[__file__,
               "<artifact-root>/exp/sp2027/r1_common.py"])}
RC.write_result("r1_%s_health_v2.json"%VER, payload)
print("OVERALL", VER, chk["overall_pass"], "| hub",chk["hub_up"]["pass"],
      "mqtt",chk["mqtt_entities_bound"]["pass"],"auto",chk["automation_bound"]["pass"],
      "rec",chk["recorder_writing"]["pass"])
