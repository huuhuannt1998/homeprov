# HOMEPROV E-DZ: benign household traffic. A Python integration standing in for a sensor bridge (as a Z-Wave or Zigbee
# integration would): it owns the three motion sensors (porch, hallway, kitchen) and reports motion on a seeded
# random schedule, so each configuration's motion-light automation runs genuinely and the lighting log carries
# ordinary traffic throughout the run. It never touches the database directly.
#
# Control: the file /hpctl/sensors_pause pauses new motion events (motions in progress still end).
"""
<plugin key="HPSensors" name="HP Motion Sensor Bridge (HOMEPROV E-DZ benign traffic)" author="homeprov" version="1.0">
    <params>
        <param field="Mode1" label="Seed" width="100px" default="7"/>
    </params>
</plugin>
"""
import Domoticz
import json
import os
import random
import time

CTL = "/hpctl"
LOG = os.path.join(CTL, "sensors_log.jsonl")
ROOMS = {1: "Porch", 2: "Hallway", 3: "Kitchen"}
ON_S = (3.0, 8.0)          # motion stays on for this long
GAP_S = (15.0, 45.0)       # quiet period per configuration between motions

_rng = None
_state = {}


def _log(rec):
    rec = dict(rec)
    rec["t"] = time.time()
    try:
        with open(LOG, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def onStart():
    global _rng
    os.makedirs(CTL, exist_ok=True)
    for unit, room in ROOMS.items():
        if unit not in Devices:
            Domoticz.Device(Name="%s Motion" % room, Unit=unit, Type=244, Subtype=73, Switchtype=8, Used=1).Create()
    seed = int(Parameters.get("Mode1") or 7)
    _rng = random.Random(seed)
    now = time.time()
    for unit in ROOMS:
        _state[unit] = {"on": False, "next_on": now + _rng.uniform(5.0, 20.0), "off_at": None}
    Domoticz.Heartbeat(1)
    _log({"ev": "start", "seed": seed, "devices": {u: Devices[u].ID for u in Devices}, "pid": os.getpid()})


def onHeartbeat():
    now = time.time()
    paused = os.path.exists(os.path.join(CTL, "sensors_pause"))
    for unit, st in _state.items():
        if st["on"] and now >= st["off_at"]:
            Devices[unit].Update(nValue=0, sValue="Off")
            st["on"] = False
            st["next_on"] = now + _rng.uniform(*GAP_S)
            _log({"ev": "off", "unit": unit})
        elif not st["on"] and now >= st["next_on"]:
            if paused:
                st["next_on"] = now + 1.0
                continue
            Devices[unit].Update(nValue=1, sValue="On")
            st["on"] = True
            st["off_at"] = now + _rng.uniform(*ON_S)
            _log({"ev": "on", "unit": unit})
