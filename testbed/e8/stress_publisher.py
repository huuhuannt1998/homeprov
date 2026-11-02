"""E8 write-rate stress: a second motion publisher on the deployment's own MQTT topics.

The lab device simulator (testbed/real/devices/devices.py, image hpr-devices:1) has no rate setting: its loop picks a
motion sensor, publishes ON, sleeps U(1.5, 4.0) s, publishes OFF and sleeps U(4.0, 20.0) s, with no environment knob
other than the broker and the seed. Rather than restart the deployment's simulator with modified code, this process
runs NEXT to it, from the same image (python + paho-mqtt), and drives the same three motion sensors with the same loop,
every sleep divided by HPR_STRESS_FACTOR. With factor F it adds about F times the simulator's motion cycles, so the
combined motion rate is about (1 + F) times the lab rate; the motion-light automations then add their runs, service
calls and light changes. The resulting recorder write rate is MEASURED from the recorder (exp/stages/e8_score.py),
not assumed from F.

What it does NOT do: it does not announce devices (no discovery payloads), does not subscribe to command topics (the
lab simulator stays the only device that echoes light and lock commands), and never publishes to a lock or light topic.
On SIGTERM it publishes OFF to every motion sensor (the state the lab simulator leaves between cycles) and exits.

    HPR_BROKER=broker HPR_STRESS_FACTOR=4 python3 stress_publisher.py
"""
from __future__ import annotations

import json
import os
import random
import signal
import sys
import time

import paho.mqtt.client as mqtt

BROKER = os.environ.get("HPR_BROKER", "broker")
FACTOR = float(os.environ.get("HPR_STRESS_FACTOR", "4"))
SEED = int(os.environ.get("HPR_STRESS_SEED", "20261009"))
MOTION = ("hall", "kitchen", "porch")          # the lab simulator's three motion sensors (devices.py MOTION)
if FACTOR <= 0:
    raise SystemExit("HPR_STRESS_FACTOR must be positive")

_stop = {"flag": False}
_count = {"on": 0, "off": 0}


def _term(*_a):
    _stop["flag"] = True


def main() -> int:
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    rng = random.Random(SEED)
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="hpr-e8-stress-%d" % os.getpid())
    c.connect(BROKER, 1883, 60)
    c.loop_start()
    time.sleep(1)
    t0 = time.time()
    last_report = t0
    print(json.dumps({"stress": "start", "factor": FACTOR, "seed": SEED, "broker": BROKER, "ts": t0}), flush=True)

    def nap(s):
        end = time.time() + s
        while not _stop["flag"] and time.time() < end:
            time.sleep(min(0.2, max(0.0, end - time.time())))

    while not _stop["flag"]:
        uid = rng.choice(MOTION)
        c.publish("hpr/motion/%s/state" % uid, "ON", retain=True)
        _count["on"] += 1
        nap(rng.uniform(1.5, 4.0) / FACTOR)
        c.publish("hpr/motion/%s/state" % uid, "OFF", retain=True)
        _count["off"] += 1
        nap(rng.uniform(4.0, 20.0) / FACTOR)
        if time.time() - last_report >= 60:
            last_report = time.time()
            print(json.dumps({"stress": "tick", "ts": last_report, "elapsed_s": round(last_report - t0, 1),
                              **_count}), flush=True)
    for uid in MOTION:
        c.publish("hpr/motion/%s/state" % uid, "OFF", retain=True)
    time.sleep(1)
    c.loop_stop()
    c.disconnect()
    t1 = time.time()
    print(json.dumps({"stress": "stop", "ts": t1, "elapsed_s": round(t1 - t0, 1), **_count,
                      "motion_on_per_min": round(_count["on"] / max(1e-9, (t1 - t0) / 60.0), 2)}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
