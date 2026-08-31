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

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov_scenario"

# The forensically interesting actuator: what an investigator asks about.
TARGET_LOCK = "lock.front_door"
SECOND_LOCK = "lock.back_door"

# The INNOCENT PARTY the flagship forgery frames. A real automation, instantiated
# from the blueprint Home Assistant ships, not one written for this experiment.
INNOCENT_AUTOMATION = "automation.porch_motion_light"
INNOCENT_TRIGGER = "binary_sensor.porch_motion"
INNOCENT_LIGHT = "light.porch_light"

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
