"""HOMEPROV defender — A1/A2 emission + laminar commitment, anchored to P1.

Runs INSIDE the same process as the adversary, deliberately: the emitter has no
privilege the attacker lacks. The only asymmetry is the anchor, an append-only
file the HA container can extend but (lacking CAP_LINUX_IMMUTABLE) cannot
rewrite.
"""
from __future__ import annotations
import asyncio, hashlib, json, logging, os, sqlite3, time

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov"
DB = "/config/home-assistant_v2.db"
CHAIN = "/anchor/chain"
H = lambda b: hashlib.sha256(b).digest()
ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]


def _graph():
    con = sqlite3.connect(DB, timeout=30)
    nodes = []
    for sid, ent, st, ts, ctx, par in con.execute(
        """SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                  s.context_id_bin, s.context_parent_id_bin
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id"""):
        c = json.dumps({"t": "state", "e": ent, "s": st, "ts": round(ts or 0, 6)},
                       sort_keys=True).encode()
        nodes.append((ts or 0.0, "s:%d" % sid, c, ctx, par, "actuates"))
    for eid, ety, ts, ctx, par, data in con.execute(
        """SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin,
                  e.context_parent_id_bin, ed.shared_data
             FROM events e JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id"""):
        c = json.dumps({"t": "event", "ty": ety, "ts": round(ts or 0, 6), "d": data},
                       sort_keys=True).encode()
        lbl = {"automation_triggered": "triggers", "call_service": "invokes"}.get(ety, "causes")
        nodes.append((ts or 0.0, "e:%d" % eid, c, ctx, par, lbl))
    con.close()
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


_STATE = {"cursor": -1.0, "rep": None, "open": None, "sealed": None}


def _incremental(now: float) -> dict:
    """A2, incremental. Per-anchor cost is O(new nodes), NOT O(history).

    Segments are time-indexed and normal operation only appends, so once a
    segment's window has passed it is CLOSED and its accumulator is final. An
    anchor therefore folds only newly-arrived nodes and emits only segments
    that closed since the last anchor. This removes the O(n) rebuild that
    Yagiz et al. 2026 name as their own limitation L4.
    """
    from collections import OrderedDict
    if _STATE["rep"] is None:
        _STATE["rep"] = OrderedDict()
        _STATE["open"] = {g: {} for g, _ in GRAN}
        _STATE["sealed"] = {g: {} for g, _ in GRAN}
    rep, op, sealed = _STATE["rep"], _STATE["open"], _STATE["sealed"]

    fresh = [n for n in _graph() if n[0] > _STATE["cursor"]]
    for ts, key, content, ctx, par, lbl in fresh:
        ph = rep.get(par, ZERO) if par else ZERO
        h = H(content + b"|" + ph + b"|" + lbl.encode())
        if ctx is not None and ctx not in rep:
            rep[ctx] = h
            if len(rep) > 20000:
                rep.popitem(last=False)          # bounded: parents are seconds old
        for g, w in GRAN:
            k = int(ts // w)
            sg = op[g].setdefault(k, {"acc": ZERO, "n": 0})
            sg["acc"] = H(sg["acc"] + h); sg["n"] += 1
        if ts > _STATE["cursor"]:
            _STATE["cursor"] = ts

    newly = {}
    for g, w in GRAN:
        for k in [k for k in op[g] if (k + 1) * w <= now]:
            sealed[g][k] = op[g].pop(k)
            newly.setdefault(g, {})[str(k)] = {"acc": sealed[g][k]["acc"].hex(),
                                               "n": sealed[g][k]["n"]}
    return {"newly_sealed": newly, "n_fresh": len(fresh)}


def commitment() -> dict:
    """A1 + A2. h(v) binds content AND the parent's hash AND the edge label."""
    rep, hashed = {}, []
    for ts, key, content, ctx, par, lbl in _graph():
        ph = rep.get(par, ZERO) if par else ZERO
        h = H(content + b"|" + ph + b"|" + lbl.encode())
        if ctx is not None and ctx not in rep:
            rep[ctx] = h
        hashed.append((ts, h))
    phi = {}
    for name, width in GRAN:
        segs = {}
        for ts, h in hashed:
            s = segs.setdefault(int(ts // width), {"acc": ZERO, "n": 0})
            s["acc"] = H(s["acc"] + h); s["n"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]} for k, v in segs.items()}
    return phi


def anchor_append() -> dict:
    """A3 P1 — extend the append-only chain. The hub can add; it cannot rewrite."""
    now = time.time()
    inc = _incremental(now)
    # The anchor records only the digest and the NEWLY SEALED segments, which is
    # what the design specifies. It previously carried `"phi": commitment()`, the
    # complete segment map at all granularities recomputed over the whole
    # history, on every five-second append. That was instrumentation for the M2
    # A/B and was never reverted: measured 2026-08-24, it had grown the chain to
    # 66.9 GB in 3.2 days against a 4.4 MB recorder, roughly 1.3 MB per anchor,
    # while the paper claims anchor storage of 1.005x the recorder. Appending
    # only sealed segments is O(newly sealed) and matches the measured design.
    rec = {"seq": int(now * 1000), "ts": now,
           "sealed": inc["newly_sealed"], "n_fresh": inc["n_fresh"]}
    line = json.dumps(rec, sort_keys=True)
    digest = hashlib.sha256(line.encode()).hexdigest()
    try:
        with open(CHAIN, "a") as fh:          # append ONLY — O_APPEND
            fh.write(json.dumps({"d": digest, "r": rec}) + "\n")
        return {"ok": True, "digest": digest, "fresh": inc["n_fresh"],
                "sealed": {g: len(v) for g, v in inc["newly_sealed"].items()}}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


async def _loop(hass):
    await asyncio.sleep(6)
    n = 0
    while True:
        r = await hass.async_add_executor_job(anchor_append)
        n += 1
        if n <= 3 or n % 10 == 0:
            _LOGGER.warning("HOMEPROV anchor #%d: %s", n, r)
        await asyncio.sleep(5)


async def async_setup(hass, config):
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED

    async def _go(_event):
        hass.async_create_task(_loop(hass))

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _go)
    return True
