# HOMEPROV E-DZ renderer-closure fixture: a Python integration that owns one switch device per rendering path of the
# device Log view (CWebServer::Cmd_GetLightLog): plain on/off, contact, motion, dimmer, selector (level names in
# Options), media player (sValue shown verbatim, "0" skipped) and door lock. On a harness command it writes an
# update, which the hub records as a LightingLog row. Used only on the closure instance, never on the run hub.
"""
<plugin key="HPFixture" name="HP Closure Fixture (HOMEPROV E-DZ)" author="homeprov" version="1.0">
    <params>
    </params>
</plugin>
"""
import Domoticz
import glob
import json
import os
import sqlite3
import time

CTL = "/hpctl"
DB = "/opt/domoticz/userdata/domoticz.db"
FIXTURES = {
    1: dict(Name="OnOff", Type=244, Subtype=73, Switchtype=0),
    2: dict(Name="Contact", Type=244, Subtype=73, Switchtype=2),
    3: dict(Name="Motion", Type=244, Subtype=73, Switchtype=8),
    4: dict(Name="Dimmer", Type=244, Subtype=73, Switchtype=7),
    5: dict(Name="Selector", Type=244, Subtype=62, Switchtype=18,
            Options={"LevelNames": "Off|Low|Medium|High", "LevelOffHidden": "false", "SelectorStyle": "0"}),
    6: dict(Name="Media", Type=244, Subtype=73, Switchtype=17),
    7: dict(Name="DoorLock", Type=244, Subtype=73, Switchtype=19),
}


def onStart():
    os.makedirs(CTL, exist_ok=True)
    for unit, kw in FIXTURES.items():
        if unit not in Devices:
            Domoticz.Device(Unit=unit, Used=1, **kw).Create()
    Domoticz.Heartbeat(1)


def onHeartbeat():
    for path in sorted(glob.glob(os.path.join(CTL, "cmd_*.json"))):
        cid = os.path.basename(path)[4:-5]
        try:
            with open(path) as fh:
                cmd = json.load(fh)
        except (OSError, ValueError):
            continue
        os.remove(path)
        res = {"op": cmd.get("op")}
        try:
            if cmd.get("op") == "set":
                u = int(cmd["unit"])
                Devices[u].Update(nValue=int(cmd["nValue"]), sValue=str(cmd["sValue"]))
                con = sqlite3.connect(DB, timeout=30)
                r = con.execute("SELECT ROWID, DeviceRowID, nValue, sValue, User, Date FROM LightingLog "
                                "WHERE DeviceRowID=? ORDER BY ROWID DESC LIMIT 1", (Devices[u].ID,)).fetchone()
                con.close()
                res.update(ok=True, device_row_id=Devices[u].ID, row=r)
            elif cmd.get("op") == "devices":
                res.update(ok=True, devices={u: Devices[u].ID for u in Devices})
            else:
                res.update(ok=False, err="unknown op")
        except Exception as exc:                                  # noqa: BLE001
            res.update(ok=False, err=repr(exc)[:300])
        res["t_ack"] = time.time()
        tmp = os.path.join(CTL, ".ack_%s.tmp" % cid)
        with open(tmp, "w") as fh:
            json.dump(res, fh)
        os.replace(tmp, os.path.join(CTL, "ack_%s.json" % cid))
