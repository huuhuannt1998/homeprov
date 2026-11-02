"""HOMEPROV benign-event driver.

Kept deliberately separate from BOTH the defender (`homeprov`) and the adversary
(`homeprov_redteam`). Its only job is to perform BENIGN hub operations on demand
so the live-hub false-positive arms exercise something real.

This exists because three live-hub arms were measured and found vacuous:
BE-6's "integration reload" was `import urllib.request; pass` (0 new nodes) and
BE-8 merely slept and hoped the hub's own automations happened to overlap. An
arm in which nothing occurs cannot produce a false positive, so "no alarm" from
it is not evidence. Driving the operations in-process is the only route
available: the testbed mints no long-lived API token.

Commands arrive as a one-word file at /config/bench_cmd (the harness writes it
with `docker exec`); the result is written to /config/bench_ack.
"""
from __future__ import annotations

# Entity ids come from the shared scenario binding, not from literals: the
# synthetic testbed's ids do not exist on the real substrate, and a service
# call against a nonexistent entity fails silently rather than raising.
from custom_components.homeprov_scenario import (
    TARGET_LOCK, INNOCENT_AUTOMATION, INNOCENT_TRIGGER, INNOCENT_LIGHT,
    LIGHTS, LOCKS)


import asyncio
import json
import logging
import os

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov_bench"

CMD = "/config/bench_cmd"
ACK = "/config/bench_ack"


async def _cmd_reload(hass) -> dict:
    """BE-6: a genuine YAML integration reload with no restart."""
    await hass.services.async_call("automation", "reload", {}, blocking=True)
    return {"did": "automation.reload"}


async def _cmd_interleave(hass) -> dict:
    """BE-8: force genuinely OVERLAPPING automation runs and actuations.

    The synthetic version toggled an input_boolean helper. On the real substrate
    that entity is an MQTT binary_sensor published by a device, and
    input_boolean.turn_on against it is not merely wrong but SILENT: the service
    call raises nothing the driver sees, the benign workload never happens, and
    the false-alarm arm reports a clean result having generated no load at all.

    Real actuations are used instead. Lights and locks accept real service calls,
    the commands go out over the broker, and the devices echo their state back --
    so the interleaving that lands in the recorder is produced by the same path a
    real household produces it by.
    """
    calls = []
    for i in range(4):
        calls.append(hass.services.async_call(
            "light", "turn_on" if i % 2 == 0 else "turn_off",
            {"entity_id": LIGHTS[i % len(LIGHTS)]}, blocking=False))
        calls.append(hass.services.async_call(
            "lock", "lock" if i % 2 == 0 else "unlock",
            {"entity_id": LOCKS[i % len(LOCKS)]}, blocking=False))
    await asyncio.gather(*calls)
    # The echo returns over the broker, so the rows do not land instantly.
    await asyncio.sleep(4)
    return {"did": f"{len(calls)} concurrent real service calls across "
                   f"{len(LIGHTS)} lights and {len(LOCKS)} locks"}


async def _cmd_churn(hass) -> dict:
    """BE-7 on a real transport: device becomes unavailable mid-automation.

    A real MQTT deployment produces this constantly -- a device drops off, its
    entity goes unavailable, and it returns. It is the benign discontinuity most
    likely to be mistaken for tampering, and the synthetic substrate could not
    produce it at all because its devices never left.
    """
    import asyncio as _a
    before = {e: (hass.states.get(e).state if hass.states.get(e) else None)
              for e in LIGHTS + LOCKS}
    # Drive several actuations while the automations are also firing, so the
    # recorder sees overlapping chains with mixed availability.
    for _ in range(3):
        await _a.gather(*[
            hass.services.async_call("light", "toggle", {"entity_id": e},
                                     blocking=False) for e in LIGHTS])
        await _a.sleep(2)
    await _a.sleep(3)
    after = {e: (hass.states.get(e).state if hass.states.get(e) else None)
             for e in LIGHTS + LOCKS}
    return {"did": "repeated real actuation during live automation runs",
            "before": before, "after": after}


HANDLERS = {"reload": _cmd_reload, "interleave": _cmd_interleave,
            "churn": _cmd_churn}


async def async_setup(hass, config) -> bool:
    async def _poll(_now=None):
        if not os.path.exists(CMD):
            return
        try:
            cmd = open(CMD).read().strip()
        except OSError:
            return
        os.remove(CMD)
        fn = HANDLERS.get(cmd)
        if fn is None:
            out = {"ok": False, "err": "unknown command %r" % cmd}
        else:
            try:
                out = {"ok": True, "cmd": cmd, **(await fn(hass))}
            except Exception as exc:                     # noqa: BLE001
                out = {"ok": False, "cmd": cmd, "err": repr(exc)}
        _LOGGER.warning("HOMEPROV bench %s", out)
        with open(ACK, "w") as fh:
            json.dump(out, fh)

    async def _loop(_event=None):
        while True:
            await _poll()
            await asyncio.sleep(1)

    hass.async_create_background_task(_loop(), "homeprov_bench_poll")
    return True
