"""Scenario binding: which real entities the experiments act on.

The harnesses used to hardcode entity ids from the synthetic `demo` deployment
(lock.kitchen_door, automation.arrive_home, input_boolean.owner_present). On the
real substrate those do not exist, and a hardcoded id that does not resolve does
not raise -- the service call succeeds against nothing, the automation never
fires, and the experiment reports a clean run having measured nothing. That
failure mode has already cost this project several wasted runs, so the binding is
declared in one place and validated at setup.

The entities below are produced by real MQTT discovery from the device simulator
and by the motion-light blueprint Home Assistant ships. Nothing here is invented:
the automation the flagship forgery frames is the platform's own canonical
motion-activated-light automation, and the trigger it fabricates is a real
motion sensor on a real topic.
"""
from __future__ import annotations

import logging
import os

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov_scenario"

# The forensically interesting actuator: what an investigator asks about.
TARGET_LOCK = "lock.front_door"
SECOND_LOCK = "lock.back_door"

# The INNOCENT PARTY the flagship forgery frames. A real automation, instantiated
# from the blueprint Home Assistant ships, not one written for this experiment.
#
# Selectable, because the flagship's scope was previously one home configuration
# and a reviewer is right to ask whether the result is a property of the attack
# or of the particular triple it was demonstrated on. Each of the three triples
# below is an independent instantiation of the SAME shipped blueprint against a
# different sensor, light and room, so switching between them changes the
# configuration under test without changing anything about the attack.
def _room() -> str:
    """Which triple the flagship frames, from a file the runner writes.

    An environment variable would be the obvious mechanism and does not work
    here: this module is imported inside a long-lived hub container whose
    environment is fixed by compose at create time, so `docker exec -e` reaches
    the exec'd process and never the hub's. The runner therefore writes a file
    into the config directory the hub already mounts, and a restart picks it up.
    """
    try:
        with open("/config/.hpr_room") as fh:
            v = fh.read().strip()
        if v:
            return v
    except OSError:
        pass
    return os.environ.get("HPR_INNOCENT_ROOM", "porch")


_ROOM = _room()
if _ROOM not in ("porch", "hallway", "kitchen"):
    raise ValueError(
        "HPR_INNOCENT_ROOM must be one of porch|hallway|kitchen, got %r" % _ROOM)
INNOCENT_AUTOMATION = "automation.%s_motion_light" % _ROOM
INNOCENT_TRIGGER = "binary_sensor.%s_motion" % _ROOM
INNOCENT_LIGHT = "light.%s_light" % _ROOM

# Additional real chains, used for benign workload and for target selection.
MOTION_SENSORS = ["binary_sensor.hallway_motion", "binary_sensor.kitchen_motion",
                  "binary_sensor.porch_motion"]
LIGHTS = ["light.hallway_light", "light.kitchen_light", "light.porch_light"]
AUTOMATIONS = ["automation.hallway_motion_light", "automation.kitchen_motion_light",
               "automation.porch_motion_light"]
LOCKS = [TARGET_LOCK, SECOND_LOCK]

ALL_REQUIRED = [TARGET_LOCK, SECOND_LOCK, INNOCENT_AUTOMATION, INNOCENT_TRIGGER,
                INNOCENT_LIGHT, *MOTION_SENSORS, *LIGHTS, *AUTOMATIONS]


def validate(hass) -> dict:
    """Fail loudly at setup if the scenario does not bind.

    A missing entity here means every downstream experiment silently measures
    nothing, so this is checked once and reported rather than discovered later
    as an inexplicably clean result.
    """
    missing = [e for e in dict.fromkeys(ALL_REQUIRED) if hass.states.get(e) is None]
    ok = not missing
    if ok:
        _LOGGER.warning("HOMEPROV scenario bound: %d entities present",
                        len(set(ALL_REQUIRED)))
    else:
        _LOGGER.error("HOMEPROV scenario NOT BOUND, missing: %s", missing)
    return {"bound": ok, "missing": missing,
            "present": len(set(ALL_REQUIRED)) - len(missing)}


async def async_setup(hass, config) -> bool:
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
    import json, os

    async def _check(_event=None):
        res = validate(hass)
        os.makedirs("/config/homeprov_out", exist_ok=True)
        with open("/config/homeprov_out/scenario_binding.json", "w") as fh:
            json.dump(res, fh, indent=2)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _check)
    return True


async def plant_actuations(hass, n_wanted: int = 6, db: str = "/config/home-assistant_v2.db"):
    """Create actuations the ADVERSARY owns, and return their contexts.

    Lives here because two experiments need it and they must not drift apart.

    THE PROBLEM IT SOLVES. Experiments that pick their target from whatever the
    deployment happens to have rendered measure nothing on this substrate. The
    only actuator rows a settled real deployment renders are the motion-light
    automations turning their own lights on and off, which are ALREADY attributed
    to the automation a forgery would try to move them onto. E5 reported
    full_laundering 0/40 that way, and E4's constructive parent test simply found
    no eligible row at all on a freshly restarted hub.

    A planted actuation satisfies every condition those experiments need at once:
    the hub calls the service, so the row's clean attribution is a bare service
    call; the device echoes the new state back over the broker, so the row opens
    its own fresh context and is the minimum state_id within it; and because the
    state genuinely changed, it has an old_state_id whose value differs and
    last_updated_ts equal to last_changed_ts, which is what the logbook's
    eligibility filter requires.

    Both waits below are load-bearing. After a restart the MQTT lock is
    `unavailable` until the broker replays its retained state, and a service call
    in that window silently does nothing -- no actuation, no event, and the
    experiment then measures a restart artifact. The echo wait is needed because
    the resulting row arrives from the device, not from the call.
    """
    import asyncio
    import sqlite3

    planted = []
    for i in range(n_wanted):
        lock = TARGET_LOCK if i % 2 == 0 else SECOND_LOCK
        st = hass.states.get(lock)
        waited = 0.0
        while (st is None or st.state in ("unavailable", "unknown")) and waited < 120:
            await asyncio.sleep(5)
            waited += 5
            st = hass.states.get(lock)
        if st is None or st.state in ("unavailable", "unknown"):
            _LOGGER.warning("HOMEPROV plant: %s unavailable, skipping", lock)
            continue
        before = st.state
        verb = "unlock" if before != "unlocked" else "lock"
        await hass.services.async_call("lock", verb, {"entity_id": lock}, blocking=True)
        for _ in range(24):
            await asyncio.sleep(1)
            now = hass.states.get(lock)
            if now is not None and now.state != before:
                break
        con = sqlite3.connect(db, timeout=30)
        mid = con.execute(
            "SELECT metadata_id FROM states_meta WHERE entity_id=?", (lock,)).fetchone()
        row = None
        if mid:
            row = con.execute(
                """SELECT state_id, context_id_bin, state, last_updated_ts
                     FROM states
                    WHERE metadata_id=? AND context_id_bin IS NOT NULL
                 ORDER BY last_updated_ts DESC LIMIT 1""", (mid[0],)).fetchone()
        con.close()
        if row and row[1] is not None:
            planted.append({"state_id": row[0], "ctx": row[1],
                            "entity": lock, "state": row[2], "ts": float(row[3])})
        await asyncio.sleep(1)
    _LOGGER.warning("HOMEPROV planted %d adversary actuations", len(planted))
    return planted
