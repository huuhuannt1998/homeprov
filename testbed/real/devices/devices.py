"""Simulated smart-home devices speaking real MQTT.

These publish Home Assistant's real MQTT DISCOVERY payloads and then real state
on real topics, which is the same mechanism commodity hardware uses: a Zigbee
bulb behind zigbee2mqtt, an ESPHome sensor, a Tasmota switch, and a Zwave-JS
lock all reach Home Assistant this way. The broker cannot distinguish these from
physical devices, and neither can Home Assistant -- the integration, the entity
registry entries, the state machine transitions and the recorder rows are all
produced by the platform's own code paths rather than by a test harness reaching
inside it.

What is simulated is the firmware, not the protocol. That distinction is the
whole point: the paper's claims are about what the platform records and renders,
and those are driven by real MQTT traffic here.

Device set is chosen for CAUSAL structure, not for variety:

  motion sensors  trigger the shipped motion-light blueprint
  lights          are actuated BY that automation (a real causal chain)
  locks           are the forensically interesting actuator -- the thing an
                  investigator asks "what caused this" about

Timing is deliberately irregular. A generator that fires on a clean period
produces causal chains that are trivially separable in time, which would flatter
every localisation result in the paper.
"""
from __future__ import annotations

import json, os, random, time
import paho.mqtt.client as mqtt

BROKER = os.environ.get("HPR_BROKER", "broker")
SEED = int(os.environ.get("HPR_SEED", "20260831"))
DISCOVERY = "homeassistant"

MOTION = [("hall", "Hallway Motion"), ("kitchen", "Kitchen Motion"),
          ("porch", "Porch Motion")]
LIGHTS = [("hall", "Hallway Light"), ("kitchen", "Kitchen Light"),
          ("porch", "Porch Light")]
LOCKS = [("front", "Front Door"), ("back", "Back Door")]


def device_block(uid: str, name: str, model: str) -> dict:
    """The `device` block is what makes these appear as real devices in the
    registry rather than as loose entities, which matters because the logbook
    renders device-scoped context.

    Entity payloads below pair this with `name: None`. Without it Home Assistant
    concatenates the device name and the entity name and produces ids like
    binary_sensor.hallway_motion_hallway_motion, which then do not match the
    automation's inputs, so the automation silently never fires and the
    deployment produces no causal chains at all -- a failure that looks exactly
    like "the attack did not work".

    `object_id` is also sent but does NOT pin the entity id here: Home Assistant
    derives it from the device name regardless, giving binary_sensor.hallway_motion.
    The automations therefore reference the device-derived ids.
    """
    return {"identifiers": [f"hpr_{uid}"], "name": name,
            "manufacturer": "HomeProv Testbed", "model": model,
            "sw_version": "1.0.0"}


def announce(c: mqtt.Client) -> None:
    for uid, name in MOTION:
        c.publish(f"{DISCOVERY}/binary_sensor/hpr_motion_{uid}/config", json.dumps({
            "name": None, "object_id": f"motion_{uid}", "unique_id": f"hpr_motion_{uid}",
            "state_topic": f"hpr/motion/{uid}/state",
            "device_class": "motion", "payload_on": "ON", "payload_off": "OFF",
            "device": device_block(f"motion_{uid}", name, "PIR-1"),
        }), retain=True)
    for uid, name in LIGHTS:
        c.publish(f"{DISCOVERY}/light/hpr_light_{uid}/config", json.dumps({
            "name": None, "object_id": f"light_{uid}", "unique_id": f"hpr_light_{uid}",
            "state_topic": f"hpr/light/{uid}/state",
            "command_topic": f"hpr/light/{uid}/set",
            "payload_on": "ON", "payload_off": "OFF",
            "device": device_block(f"light_{uid}", name, "BULB-1"),
        }), retain=True)
    for uid, name in LOCKS:
        c.publish(f"{DISCOVERY}/lock/hpr_lock_{uid}/config", json.dumps({
            "name": None, "object_id": f"lock_{uid}", "unique_id": f"hpr_lock_{uid}",
            "state_topic": f"hpr/lock/{uid}/state",
            "command_topic": f"hpr/lock/{uid}/set",
            "payload_lock": "LOCK", "payload_unlock": "UNLOCK",
            "state_locked": "LOCKED", "state_unlocked": "UNLOCKED",
            "device": device_block(f"lock_{uid}", name, "DEADBOLT-1"),
        }), retain=True)


def main() -> None:
    rng = random.Random(SEED)
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    def on_connect(cl, _u, _f, rc, _p=None):
        print(f"[devices] connected rc={rc}", flush=True)
        announce(cl)
        # Devices echo their commanded state, which is what real firmware does
        # and what makes the actuation appear in the recorder as a state change
        # caused by the command rather than as an unexplained transition.
        for uid, _ in LIGHTS:
            cl.subscribe(f"hpr/light/{uid}/set")
        for uid, _ in LOCKS:
            cl.subscribe(f"hpr/lock/{uid}/set")

    def on_message(cl, _u, msg):
        parts = msg.topic.split("/")
        kind, uid = parts[1], parts[2]
        payload = msg.payload.decode()
        if kind == "light":
            cl.publish(f"hpr/light/{uid}/state", payload, retain=True)
        elif kind == "lock":
            state = "LOCKED" if payload == "LOCK" else "UNLOCKED"
            cl.publish(f"hpr/lock/{uid}/state", state, retain=True)
        print(f"[devices] {msg.topic} -> {payload}", flush=True)

    c.on_connect, c.on_message = on_connect, on_message
    c.connect(BROKER, 1883, 60)
    c.loop_start()
    time.sleep(3)

    for uid, _ in LIGHTS:
        c.publish(f"hpr/light/{uid}/state", "OFF", retain=True)
    for uid, _ in LOCKS:
        c.publish(f"hpr/lock/{uid}/state", "LOCKED", retain=True)
    for uid, _ in MOTION:
        c.publish(f"hpr/motion/{uid}/state", "OFF", retain=True)

    print("[devices] announced; entering motion loop", flush=True)
    while True:
        uid, _ = rng.choice(MOTION)
        c.publish(f"hpr/motion/{uid}/state", "ON", retain=True)
        time.sleep(rng.uniform(1.5, 4.0))
        c.publish(f"hpr/motion/{uid}/state", "OFF", retain=True)
        # Irregular gaps on purpose: a clean period would make causal runs
        # trivially separable and flatter every localisation number.
        time.sleep(rng.uniform(4.0, 20.0))


if __name__ == "__main__":
    main()
