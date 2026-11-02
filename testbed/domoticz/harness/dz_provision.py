"""Provision a fresh Domoticz hub for E-DZ through its own JSON API, as the owner would in the web UI.

  dz_provision.py run      Dummy hardware with the three lights (porch, hallway, kitchen), the lock integration
                           (hardware "LockBridge", key HPLock), the sensor integration (hardware "SensorHub", key
                           HPSensors), and the household accounts member (User rights) and guest (Viewer rights).
  dz_provision.py closure  the same accounts and Dummy hardware plus the closure fixture integration (key HPFixture).

The owner account (Admin rights) is created by Domoticz from DOMOTICZ_ADMIN_USERNAME/PASSWORD at first start. Prints a
JSON record of what was created. The hub must be restarted afterwards so that dzVents learns the new hardware names."""
import json
import sys
import time

from dz_api import ACCOUNTS, Api, md5

LIGHTS = ("Porch Light", "Hallway Light", "Kitchen Light")


def hw_by_name(a):
    return {h["Name"]: h for h in (a.cmd("gethardware").get("result") or [])}


def main(kind):
    a = Api("owner")
    rec = {"kind": kind, "t": time.time(), "steps": []}
    hw = hw_by_name(a)
    if "Virtual" not in hw:
        rec["steps"].append(a.cmd("addhardware", htype=15, name="Virtual", enabled="true", datatimeout=0))
        hw = hw_by_name(a)
    vid = hw["Virtual"]["idx"]
    devs = {d["Name"]: d for d in (a.get("/json.htm?type=command&param=getdevices&filter=all&used=true")
                                   .get("result") or [])}
    for n in LIGHTS:
        if n not in devs:
            rec["steps"].append(a.cmd("createdevice", idx=vid, sensorname=n, devicetype=244, devicesubtype=73))
    want = ([("LockBridge", "HPLock", {}), ("SensorHub", "HPSensors", {"Mode1": "7"})] if kind == "run"
            else [("ClosureFixture", "HPFixture", {})])
    # One Python hardware entry at a time, waiting until its integration has started: adding two back to back
    # crashed Domoticz 2026.3 once (fatal signal 6 in Plugins::CPlugin::StartHardware) while provisioning a hub.
    for name, key, extra in want:
        if name not in hw:
            rec["steps"].append(a.cmd("addhardware", htype=94, name=name, enabled="true", datatimeout=0,
                                      extra=key, **extra))
            time.sleep(8)
            hw = hw_by_name(a)
    users = {u.get("Username") for u in (a.cmd("getusers").get("result") or [])}
    for acc in ("member", "guest"):
        if acc not in users:
            p = ACCOUNTS[acc]
            rec["steps"].append(a.cmd("adduser", enabled="true", username=acc, password=md5(p["password"]),
                                      rights=p["rights"], RemoteSharing="false", TabsEnabled=0))
    time.sleep(5)
    rec["hardware"] = [(h["idx"], h["Name"], h["Type"], h.get("Extra")) for h in
                       (a.cmd("gethardware").get("result") or [])]
    rec["devices"] = [(d["idx"], d["Name"], d.get("SwitchType"), d.get("HardwareName")) for d in
                      (a.get("/json.htm?type=command&param=getdevices&filter=all&used=true").get("result") or [])]
    rec["users"] = [(u.get("idx"), u.get("Username"), u.get("Rights")) for u in
                    (a.cmd("getusers").get("result") or [])]
    rec["version"] = a.cmd("getversion")
    names = {h[1] for h in rec["hardware"]}
    need = {"Virtual"} | {n for n, _k, _e in want}
    rec["complete"] = (need <= names and {u[1] for u in rec["users"]} >= {"owner", "member", "guest"}
                       and len(rec["devices"]) >= len(LIGHTS) + (4 if kind == "run" else 7))
    print(json.dumps(rec, default=str))
    if not rec["complete"]:
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "run")
