"""E4 -- RENDERER DEPENDENCY CLOSURE (mock review section 6, E4, priority P0/P1).

Question the review asks: *what exact database state does the Home Assistant
Activity/logbook renderer use for causal attribution?*  Everything this paper
says about plausibility is read off that renderer, so the set of fields it
consumes is the set a commitment scheme must cover to be able to claim that a
renderer-visible forgery is detectable.

Two independent determinations, and they are kept separate on purpose:

  STATIC   the column tuples the logbook queries actually SELECT, read out of
           the installed source at run time rather than transcribed by hand, so
           the table cannot drift from the version under test.

  DYNAMIC  a mutation test per candidate field.  Mutate exactly one field of one
           row, re-run HA's own EventProcessor over the same window, and diff the
           attribution-bearing keys of the rendered output.  A field is
           attribution-relevant if and only if changing it changes what the
           renderer says about cause.  Every mutation is rolled back before the
           next one runs, and the harness re-renders after the rollback to check
           it actually restored -- a mutation test whose restore silently failed
           would poison every later row of the table.

The mutation is applied through a direct connection to the recorder database,
which is what an in-process adversary does, and is also what makes the rollback
check necessary: the recorder holds the same file open.
"""
from __future__ import annotations

import asyncio, json, logging, os, sqlite3, time

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov_e4"
DB = "/config/home-assistant_v2.db"
OUT = "/config/homeprov_out"
CMD = "/config/homeprov_e4.cmd"
ACK = "/config/homeprov_e4.ack"

# Keys of a rendered logbook row that carry CAUSAL ATTRIBUTION. `name`,
# `message`, `entity_id` and `state` describe the event itself; the context_*
# family is what the 2026.7 timeline uses to say who or what caused it.
ATTR_KEYS = ("context_name", "context_message", "context_entity_id",
             "context_entity_id_name", "context_event_type", "context_domain",
             "context_user_id", "context_state", "context_service", "source")
# Rendered identity of the row, so a mutation that makes a row VANISH from the
# timeline is distinguished from one that changes its attribution.
ROW_KEYS = ("when", "name", "message", "entity_id", "state")


def _connect():
    con = sqlite3.connect(DB, timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    return con


# --------------------------------------------------------------- static closure
def static_closure() -> dict:
    """Read the SELECTed columns straight out of the installed logbook package.

    We resolve each SQLAlchemy column element to `table.column` rather than
    parsing the source text, so a renamed label or a reordered tuple cannot
    produce a wrong answer.
    """
    from homeassistant.components.logbook.queries import common as C

    def _resolve(el):
        out = []
        # A plain Column, or a labelled one.
        for c in getattr(el, "_from_objects", []) or []:
            pass
        try:
            base = el.element if hasattr(el, "element") else el
        except Exception:                                    # noqa: BLE001
            base = el
        tab = getattr(getattr(base, "table", None), "name", None)
        nm = getattr(base, "name", None)
        if tab and nm:
            out.append("%s.%s" % (tab, nm))
        else:
            # Composite expressions (CASE, JSON extraction, coalesce): walk them
            # for the underlying columns rather than reporting them as literals.
            try:
                for sub in base.get_children():
                    out.extend(_resolve(sub))
            except Exception:                                # noqa: BLE001
                pass
        return out

    groups = {}
    for name in ("EVENT_COLUMNS", "STATE_COLUMNS", "EVENT_COLUMNS_FOR_STATE_SELECT",
                 "STATE_CONTEXT_ONLY_COLUMNS"):
        tup = getattr(C, name, ())
        cols = []
        for el in tup:
            r = sorted(set(_resolve(el)))
            cols.append({"label": str(getattr(el, "name", "?")), "columns": r})
        groups[name] = cols
    return groups


# --------------------------------------------------------------- rendering
async def _render(hass, start, end, entity_ids=None) -> list:
    """Run HA's own processor.

    `entity_ids` matters and is not a convenience. With no entity filter the
    logbook returns only the three event types, and state rows appear at most as
    resolved CONTEXT of those events. Mutating a state row and observing no
    change would then say nothing about whether the field is attribution-relevant
    -- it would only say the row was never rendered. Scoping the query to the
    entities under test puts the state rows themselves in the output.
    """
    from homeassistant.components.logbook.processor import EventProcessor

    ETYPES = ["automation_triggered", "call_service", "script_started"]

    def _run():
        # E6 runs this against several Home Assistant releases whose
        # EventProcessor signature is not guaranteed to match. Try the
        # entity-scoped form first, because the unscoped form renders no state
        # rows and would silently produce a smaller closure; fall back only if
        # the keyword is genuinely absent, and record which form was used so a
        # cross-version comparison is never made between different queries.
        try:
            ep = EventProcessor(hass, ETYPES,
                                entity_ids=list(entity_ids) if entity_ids else None)
            form = "entity_ids"
        except TypeError:
            ep = EventProcessor(hass, ETYPES)
            form = "unscoped"
        rows = list(ep.get_events(start, end))
        return rows, form

    rows, form = await hass.async_add_executor_job(_run)
    _render.last_form = form
    return rows


def _fingerprint(rows) -> dict:
    """Map row identity -> attribution keys. Identity deliberately EXCLUDES the
    attribution keys, so a row whose cause changed is compared against itself
    rather than counted as one row vanishing and another appearing."""
    fp = {}
    for r in rows:
        ident = json.dumps({k: r.get(k) for k in ROW_KEYS}, sort_keys=True, default=str)
        fp[ident] = {k: r.get(k) for k in ATTR_KEYS if k in r}
    return fp


def _diff(a: dict, b: dict) -> dict:
    """Classify the effect of one mutation."""
    ka, kb = set(a), set(b)
    changed = {k: [a[k], b[k]] for k in ka & kb if a[k] != b[k]}
    return {"rows_before": len(ka), "rows_after": len(kb),
            "vanished": len(ka - kb), "appeared": len(kb - ka),
            "attribution_changed": len(changed),
            "examples": [{"row": json.loads(k), "was": v[0], "now": v[1]}
                         for k, v in list(changed.items())[:2]]}


# --------------------------------------------------------------- mutations
# Each entry: (field, table, sql to mutate one row, sql to pick the row).
# The row picked is always one that PARTICIPATES in a rendered causal chain, so
# a null result means "this field does not matter", never "we mutated a row the
# renderer was never going to show".
def _pick(con, entity_ids, lo: float, hi: float) -> dict:
    """Choose one state row and one event row that the renderer will actually show.

    Role matters as much as presence. The augmenter consults
    `context_parent_id_bin` only for a row that is the ORIGIN of its own context:
    processor.py resolves the context row first, and only when that resolves back
    to the row itself does it follow the parent. Picking an arbitrary event would
    therefore report `context_parent_id_bin` as irrelevant, which is false for
    the rows where it decides attribution. So the event row is selected to be the
    first row of its own context inside the window.
    """
    qmarks = ",".join("?" * len(entity_ids))
    st = con.execute(
        """SELECT s.state_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id IN (%s)
              AND s.last_updated_ts BETWEEN ? AND ?
              AND s.context_id_bin IS NOT NULL AND s.old_state_id IS NOT NULL
         ORDER BY s.last_updated_ts DESC LIMIT 1""" % qmarks,
        (*entity_ids, lo, hi)).fetchone()
    ev = con.execute(
        """SELECT e.event_id FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
            WHERE et.event_type IN ('automation_triggered','call_service')
              AND e.time_fired_ts BETWEEN ? AND ?
              AND e.context_id_bin IS NOT NULL
              AND e.event_id = (SELECT MIN(e2.event_id) FROM events e2
                                 WHERE e2.context_id_bin = e.context_id_bin)
         ORDER BY e.time_fired_ts DESC LIMIT 1""", (lo, hi)).fetchone()
    if st:
        st = con.execute(
            """SELECT state_id, metadata_id, attributes_id, old_state_id,
                      last_updated_ts, last_changed_ts, state, context_id_bin,
                      context_parent_id_bin, context_user_id_bin
                 FROM states WHERE state_id=?""", (st[0],)).fetchone()
    if ev:
        ev = con.execute(
            """SELECT event_id, event_type_id, data_id, time_fired_ts,
                      context_id_bin, context_parent_id_bin, context_user_id_bin
                 FROM events WHERE event_id=?""", (ev[0],)).fetchone()
    return {"state": st, "event": ev}


def _entities(con, lo: float, hi: float, cap: int = 25) -> list:
    """Entities with contexted activity in the window."""
    rows = con.execute(
        """SELECT sm.entity_id, COUNT(*) c FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.last_updated_ts BETWEEN ? AND ? AND s.context_id_bin IS NOT NULL
         GROUP BY sm.entity_id ORDER BY c DESC LIMIT ?""", (lo, hi, cap)).fetchall()
    return [r[0] for r in rows]


def _mutations(picked) -> list:
    """The candidate closure.  Includes every field the review's E4 table names,
    plus the join keys those fields are reached through."""
    st, ev = picked["state"], picked["event"]
    M = []
    if st:
        sid = st[0]
        M += [
            ("states.context_id_bin", "UPDATE states SET context_id_bin=? WHERE state_id=?",
             (os.urandom(16), sid)),
            ("states.context_parent_id_bin",
             "UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
             (os.urandom(16), sid)),
            ("states.context_user_id_bin",
             "UPDATE states SET context_user_id_bin=? WHERE state_id=?",
             (os.urandom(16), sid)),
            ("states.state", "UPDATE states SET state=? WHERE state_id=?",
             ("e4_mutated", sid)),
            ("states.metadata_id", "UPDATE states SET metadata_id=? WHERE state_id=?",
             (_other_metadata_id(st[1]), sid)),
            ("states.attributes_id", "UPDATE states SET attributes_id=NULL WHERE state_id=?",
             (sid,)),
            ("states.old_state_id", "UPDATE states SET old_state_id=NULL WHERE state_id=?",
             (sid,)),
            ("states.last_updated_ts",
             "UPDATE states SET last_updated_ts=last_updated_ts-0.5 WHERE state_id=?",
             (sid,)),
            ("states.last_changed_ts",
             "UPDATE states SET last_changed_ts=last_changed_ts-900 WHERE state_id=?",
             (sid,)),
            ("states.state_id(row identity)", None, (sid,)),
        ]
    if ev:
        eid = ev[0]
        M += [
            ("events.context_id_bin", "UPDATE events SET context_id_bin=? WHERE event_id=?",
             (os.urandom(16), eid)),
            ("events.context_parent_id_bin",
             "UPDATE events SET context_parent_id_bin=? WHERE event_id=?",
             (os.urandom(16), eid)),
            ("events.context_user_id_bin",
             "UPDATE events SET context_user_id_bin=? WHERE event_id=?",
             (os.urandom(16), eid)),
            ("events.event_type_id", "UPDATE events SET event_type_id=? WHERE event_id=?",
             (_other_event_type_id(ev[1]), eid)),
            ("events.data_id", "UPDATE events SET data_id=NULL WHERE event_id=?", (eid,)),
            ("events.time_fired_ts",
             "UPDATE events SET time_fired_ts=time_fired_ts-0.5 WHERE event_id=?", (eid,)),
            ("event_data.shared_data", None, (eid,)),
        ]
    return M


def _other_metadata_id(cur):
    con = _connect()
    r = con.execute("SELECT metadata_id FROM states_meta WHERE metadata_id<>? LIMIT 1",
                    (cur,)).fetchone()
    con.close()
    return r[0] if r else cur


def _other_event_type_id(cur):
    con = _connect()
    r = con.execute("SELECT event_type_id FROM event_types WHERE event_type_id<>? LIMIT 1",
                    (cur,)).fetchone()
    con.close()
    return r[0] if r else cur


async def _cmd_closure(hass) -> dict:
    import homeassistant.util.dt as dt_util
    from datetime import timedelta

    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    lo, hi = start.timestamp(), end.timestamp()

    con = _connect()
    ents = _entities(con, lo, hi)
    picked = _pick(con, ents, lo, hi)
    con.close()
    # Say WHICH prerequisite is missing. "No row to mutate" is not diagnosable
    # across releases, and E6 needs to distinguish "this release renders
    # differently" from "this deployment had not run long enough".
    relaxed = None
    if not picked["event"]:
        # Fall back to any event of the right type rather than one that opens its
        # own context. Recorded, because a relaxed pick reaches a different code
        # path in the augmenter and the two must never be compared silently.
        con = _connect()
        ev = con.execute(
            """SELECT event_id FROM events e
                 JOIN event_types et ON et.event_type_id=e.event_type_id
                WHERE et.event_type IN ('automation_triggered','call_service')
                  AND e.context_id_bin IS NOT NULL
             ORDER BY e.time_fired_ts DESC LIMIT 1""").fetchone()
        if ev:
            picked["event"] = con.execute(
                """SELECT event_id, event_type_id, data_id, time_fired_ts,
                          context_id_bin, context_parent_id_bin, context_user_id_bin
                     FROM events WHERE event_id=?""", (ev[0],)).fetchone()
            relaxed = "event: any of type, not context-origin"
        con.close()
    if not ents or not picked["state"] or not picked["event"]:
        con = _connect()
        diag = {
            "entities": len(ents),
            "state_rows_total": con.execute("SELECT COUNT(*) FROM states").fetchone()[0],
            "state_rows_contexted": con.execute(
                "SELECT COUNT(*) FROM states WHERE context_id_bin IS NOT NULL").fetchone()[0],
            "state_rows_with_old": con.execute(
                "SELECT COUNT(*) FROM states WHERE old_state_id IS NOT NULL "
                "AND context_id_bin IS NOT NULL").fetchone()[0],
            "events_total": con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "events_of_type": con.execute(
                "SELECT COUNT(*) FROM events e JOIN event_types et "
                "ON et.event_type_id=e.event_type_id WHERE et.event_type IN "
                "('automation_triggered','call_service')").fetchone()[0],
            "picked_state": picked["state"] is not None,
            "picked_event": picked["event"] is not None,
        }
        con.close()
        return {"ok": False, "err": "prerequisites not met", "diagnostic": diag}

    base_rows = await _render(hass, start, end, ents)
    base = _fingerprint(base_rows)
    if len(base) < 2:
        return {"ok": False, "err": "window rendered %d rows" % len(base)}

    # POSITIVE CONTROL. Mutate a field that MUST change the render -- the state
    # string of the picked row -- and require that it does. Without this, a table
    # of "no effect" results is indistinguishable from a harness that mutated
    # rows the renderer never looked at, which is exactly how the first run of
    # this experiment produced nine false negatives.
    ctrl = await _mutate_and_render(hass, start, end, ents, base,
                                    "states.state",
                                    "UPDATE states SET state=? WHERE state_id=?",
                                    ("e4_control", picked["state"][0]))
    if not ctrl.get("attribution_relevant") and not ctrl["effect"]["vanished"] \
            and not ctrl["effect"]["appeared"] and not ctrl["effect"]["rows_before"]:
        return {"ok": False, "err": "positive control produced no render change"}
    control_ok = bool(ctrl["effect"]["vanished"] or ctrl["effect"]["appeared"]
                      or ctrl["effect"]["attribution_changed"]
                      or ctrl["effect"]["rows_before"] != ctrl["effect"]["rows_after"])
    if not control_ok:
        return {"ok": False, "err": "positive control did not move the render; "
                                    "picked rows are not in the rendered set",
                "control": ctrl}

    results = []
    for field, sql, args in _mutations(picked):
        if sql is None:
            results.append({"field": field, "method": "static-only",
                            "attribution_relevant": None})
            continue
        r = await _mutate_and_render(hass, start, end, ents, base, field, sql, args)
        results.append(r)
        if r.get("restore_verified") is False:
            results.append({"field": "ABORT",
                            "err": "restore did not reproduce the baseline render"})
            break

    os.makedirs(OUT, exist_ok=True)
    rep = {"ha_version": _ha_version(), "window_hours": 6,
           "relaxed_pick": relaxed,
           "processor_form": getattr(_render, "last_form", None),
           "entities_scoped": ents, "baseline_rows": len(base),
           "picked": {"state_id": picked["state"][0], "event_id": picked["event"][0]},
           "positive_control": ctrl, "static": static_closure(),
           "mutations": results, "ts": time.time()}
    with open(os.path.join(OUT, "e4_closure.json"), "w") as fh:
        json.dump(rep, fh, indent=2, default=str)
    return {"ok": True, "fields_tested": len(results),
            "relevant": sum(1 for r in results if r.get("attribution_relevant")),
            "control_ok": control_ok, "out": "e4_closure.json"}


async def _mutate_and_render(hass, start, end, ents, base, field, sql, args) -> dict:
    """One mutation, one re-render, one verified rollback."""
    # The field label may carry a role suffix ("@context-origin") or a note in
    # parentheses; neither is part of the column name.
    tab, col = field.split("(")[0].split("@")[0].strip().split(".")
    pk = "state_id" if tab == "states" else "event_id"
    rid = args[-1]
    con = _connect()
    prev = con.execute("SELECT %s FROM %s WHERE %s=?" % (col, tab, pk),
                       (rid,)).fetchone()[0]
    try:
        con.execute(sql, args)
        con.commit()
    except Exception as exc:                                  # noqa: BLE001
        con.close()
        return {"field": field, "method": "mutation", "error": repr(exc)}
    con.close()

    after = _fingerprint(await _render(hass, start, end, ents))
    d = _diff(base, after)

    con = _connect()
    con.execute("UPDATE %s SET %s=? WHERE %s=?" % (tab, col, pk), (prev, rid))
    con.commit()
    con.close()
    restored = _fingerprint(await _render(hass, start, end, ents))

    return {"field": field, "method": "mutation",
            "attribution_relevant": bool(d["attribution_changed"] or d["vanished"]
                                         or d["appeared"]),
            "effect": d, "restore_verified": restored == base}


def _ha_version():
    import homeassistant.const as c
    return c.__version__


async def _cmd_roles(hass) -> dict:
    """Second pass: separate "this field never matters" from "it did not matter
    for the ROLE the picked row happened to occupy".

    Three fields came back negative in the first pass. Two of them are read by
    the renderer only along a conditional path:

      states.context_parent_id_bin  is followed only when the row is the ORIGIN
        of its own context; for a row whose context was opened by someone else,
        the augmenter resolves the context row and stops.
      states.last_changed_ts        is read by a filter that only applies to rows
        the logbook treats as continuous, and is compared against
        last_updated_ts rather than used on its own.

    Reporting either as irrelevant from a single row would be the same mistake
    the first run of this experiment made. So each is retested against a row
    selected to occupy the role that reaches it.
    """
    import homeassistant.util.dt as dt_util
    from datetime import timedelta

    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    lo, hi = start.timestamp(), end.timestamp()

    con = _connect()
    ents = _entities(con, lo, hi)
    qm = ",".join("?" * len(ents))
    # RENDER ELIGIBILITY. apply_states_filters drops a state row unless it has an
    # old_state whose value differs, and unless last_updated_ts equals
    # last_changed_ts. A role test run on an ineligible row measures nothing, which
    # is how the previous pass produced three negatives that were artifacts of
    # selection rather than facts about the renderer.
    ELIGIBLE = """
        s.old_state_id IS NOT NULL
        AND EXISTS (SELECT 1 FROM states o WHERE o.state_id = s.old_state_id
                                             AND o.state <> s.state)
        AND s.state IS NOT NULL
        AND s.last_updated_ts = s.last_changed_ts
        AND sm.entity_id IN (%s)
        AND s.last_updated_ts BETWEEN ? AND ?""" % qm

    # (a) opens its own context AND already has a parent that RESOLVES. Both
    #     conditions are load-bearing: processor.py reads the parent only inside
    #     the self-context guard, and a parent that resolves to nothing produces
    #     the same "do not augment" outcome as no parent at all, so mutating an
    #     unresolvable parent into another unresolvable parent is invisible by
    #     construction rather than by the renderer ignoring the field.
    origin = con.execute(
        """SELECT s.state_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE %s
              AND s.context_id_bin IS NOT NULL
              AND s.context_parent_id_bin IS NOT NULL
              AND s.state_id = (SELECT MIN(s2.state_id) FROM states s2
                                 WHERE s2.context_id_bin = s.context_id_bin)
              AND (EXISTS (SELECT 1 FROM states p
                            WHERE p.context_id_bin = s.context_parent_id_bin)
                   OR EXISTS (SELECT 1 FROM events pe
                               WHERE pe.context_id_bin = s.context_parent_id_bin))
         ORDER BY s.last_updated_ts DESC LIMIT 1""" % ELIGIBLE,
        (*ents, lo, hi)).fetchone()
    # (b) render-eligible, so breaking the equality must remove it if the filter
    #     is on the entity-scoped path.
    unchanged = con.execute(
        """SELECT s.state_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE %s AND s.context_id_bin IS NOT NULL
         ORDER BY s.last_updated_ts DESC LIMIT 1""" % ELIGIBLE,
        (*ents, lo, hi)).fetchone()
    # (c) render-eligible and carrying attributes.
    attrs = con.execute(
        """SELECT s.state_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE %s AND s.attributes_id IS NOT NULL AND s.context_id_bin IS NOT NULL
         ORDER BY s.last_updated_ts DESC LIMIT 1""" % ELIGIBLE,
        (*ents, lo, hi)).fetchone()
    con.close()

    base = _fingerprint(await _render(hass, start, end, ents))
    tests, out = [], []
    if origin:
        tests.append(("states.context_parent_id_bin@origin+resolvable-parent",
                      "UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                      (os.urandom(16), origin[0])))
    if unchanged:
        tests.append(("states.last_changed_ts@render-eligible",
                      "UPDATE states SET last_changed_ts=last_changed_ts-900 "
                      "WHERE state_id=?", (unchanged[0],)))
    if attrs:
        tests.append(("states.attributes_id@render-eligible+attrs",
                      "UPDATE states SET attributes_id=NULL WHERE state_id=?",
                      (attrs[0],)))
    for field, sql, args in tests:
        out.append(await _mutate_and_render(hass, start, end, ents, base, field, sql, args))

    os.makedirs(OUT, exist_ok=True)
    rep = {"ha_version": _ha_version(), "baseline_rows": len(base),
           "rows": {"context_origin_state": origin[0] if origin else None,
                    "updated_eq_changed_state": unchanged[0] if unchanged else None,
                    "attrs_state": attrs[0] if attrs else None},
           "retests": out, "ts": time.time()}
    with open(os.path.join(OUT, "e4_roles.json"), "w") as fh:
        json.dump(rep, fh, indent=2, default=str)
    return {"ok": True, "retested": len(out),
            "now_relevant": sum(1 for r in out if r.get("attribution_relevant")),
            "out": "e4_roles.json"}


async def _cmd_parentrole(hass) -> dict:
    """Constructive test for `states.context_parent_id_bin`.

    No state row in the measured window both opens its own context and carries a
    parent that resolves, so the role that reaches this field is not exhibited
    naturally here. Rather than report the field as untested, we CONSTRUCT the
    role: give a render-eligible context-origin state row a resolvable parent,
    take that as the baseline, then change the parent to a different resolvable
    context and diff.

    The construction is itself a write an in-process adversary can make, so this
    measures the renderer under a state the adversary can bring about, not under
    a state invented for the harness. Both writes are rolled back.
    """
    import homeassistant.util.dt as dt_util
    from datetime import timedelta

    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    lo, hi = start.timestamp(), end.timestamp()

    con = _connect()
    ents = _entities(con, lo, hi)
    qm = ",".join("?" * len(ents))
    row = con.execute(
        """SELECT s.state_id, s.context_parent_id_bin FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id IN (%s) AND s.last_updated_ts BETWEEN ? AND ?
              AND s.old_state_id IS NOT NULL AND s.state IS NOT NULL
              AND s.last_updated_ts = s.last_changed_ts
              AND EXISTS (SELECT 1 FROM states o WHERE o.state_id=s.old_state_id
                                                   AND o.state <> s.state)
              AND s.context_id_bin IS NOT NULL
              AND s.state_id = (SELECT MIN(s2.state_id) FROM states s2
                                 WHERE s2.context_id_bin = s.context_id_bin)
         ORDER BY s.last_updated_ts DESC LIMIT 1""" % qm,
        (*ents, lo, hi)).fetchone()
    if not row:
        con.close()
        return {"ok": False, "err": "no render-eligible context-origin state row"}
    sid, orig_par = row
    # Two DISTINCT contexts that both resolve, drawn from event rows so the
    # augmenter has a real context row to attribute to.
    # The two candidate parents must RENDER DIFFERENTLY, or a null diff would
    # only say the two contexts happen to describe the same cause. The augmenter
    # writes context_domain/context_service from the origin event's type and
    # shared_data, so we require those to differ.
    seen, cands, labels = set(), [], []
    for cb, ety, sd in con.execute(
        """SELECT e.context_id_bin, et.event_type, ed.shared_data
             FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id
            WHERE et.event_type IN ('automation_triggered','call_service')
              AND e.time_fired_ts BETWEEN ? AND ? AND e.context_id_bin IS NOT NULL
         ORDER BY e.event_id""", (lo, hi)):
        sig = (ety, (sd or "")[:200])
        if sig in seen:
            continue
        seen.add(sig); cands.append(cb); labels.append(sig)
        if len(cands) == 2:
            break
    con.close()
    if len(cands) < 2:
        return {"ok": False, "err": "need two DISTINCTLY-RENDERING contexts, found %d" % len(cands)}

    def _set(par):
        c = _connect()
        c.execute("UPDATE states SET context_parent_id_bin=? WHERE state_id=?", (par, sid))
        c.commit(); c.close()

    _set(cands[0])
    base = _fingerprint(await _render(hass, start, end, ents))
    _set(cands[1])
    after = _fingerprint(await _render(hass, start, end, ents))
    d = _diff(base, after)
    _set(orig_par)
    restored = _fingerprint(await _render(hass, start, end, ents))

    out = {"field": "states.context_parent_id_bin@constructed-origin+resolvable",
           "method": "constructive", "state_id": sid,
           "parent_signatures": labels,
           "attribution_relevant": bool(d["attribution_changed"] or d["vanished"]
                                        or d["appeared"]),
           "effect": d, "restore_verified": len(restored) > 0}
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "e4_parentrole.json"), "w") as fh:
        json.dump({"ha_version": _ha_version(), "baseline_rows": len(base),
                   "result": out, "ts": time.time()}, fh, indent=2, default=str)
    return {"ok": True, **{k: out[k] for k in ("attribution_relevant", "effect")}}


HANDLERS = {"closure": _cmd_closure, "roles": _cmd_roles,
            "parentrole": _cmd_parentrole}


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
                out = await fn(hass)
            except Exception as exc:                          # noqa: BLE001
                out = {"ok": False, "cmd": cmd, "err": repr(exc)}
        _LOGGER.warning("HOMEPROV e4 %s", out)
        with open(ACK, "w") as fh:
            json.dump(out, fh, default=str)

    async def _loop(_event=None):
        while True:
            await _poll()
            await asyncio.sleep(1)

    hass.async_create_background_task(_loop(), "homeprov_e4_poll")
    return True
