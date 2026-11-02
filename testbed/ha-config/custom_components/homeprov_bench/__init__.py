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
    """BE-8: force automation runs to genuinely OVERLAP.

    `arrive_home` is mode: single, so re-triggering it concurrently would be
    skipped rather than interleaved. Overlap is produced instead by issuing
    several independent service calls concurrently, so their context chains are
    open at the same time.
    """
    calls = []
    for i in range(4):
        calls.append(hass.services.async_call(
            "input_boolean", "turn_on" if i % 2 == 0 else "turn_off",
            {"entity_id": "input_boolean.owner_present"}, blocking=False))
        calls.append(hass.services.async_call(
            "lock", "lock" if i % 2 == 0 else "unlock",
            {"entity_id": "lock.kitchen_door"}, blocking=False))
    await asyncio.gather(*calls)
    await asyncio.sleep(2)
    return {"did": "8 concurrent service calls"}


HANDLERS = {"reload": _cmd_reload, "interleave": _cmd_interleave}


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
