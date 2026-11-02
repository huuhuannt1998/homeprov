"""E8 part B: the renderer closure of Home Assistant 2026.7.4, re-measured on a copy of the real deployment's recorder.

Why (review R3, W2). The closure the paper prints (fourteen fields) was measured by mutating one state row and one event
row of a 43-row demo window (exp/out/e4_closure.json). The real-deployment attempt (exp/out/e4_real_closure.json) ran
inside the live hub and aborted after the first event field with "restore did not reproduce the baseline render",
after flagging states.last_changed_ts directly.

Method. A copy of the default deployment's recorder (SQLite backup API, read-only, taken from hpr-hass) is served to a
throwaway hub (container e8b-hass, image homeassistant/home-assistant:2026.7.4, the image hpr-hass runs) whose recorder
is disabled once the hub has started, so nothing but this stage writes to the copy. For each target row (several
roles: front-door lock, lights, motion sensors, automation runs, service calls, user-bearing rows, rows with and
without old_state_id) every stored column of the row and of the states_meta / state_attributes / event_types /
event_data row it references is mutated in turn, in one or more variants, through a separate SQLite connection (as
code in the hub process can). After each mutation the release's own logbook processor (EventProcessor) renders the
target's window (+-300 s) in three request forms: the Activity panel's (no entity filter, websocket form), the
entity's own logbook (entity filter, websocket form) and the REST form with names (entity filter). The rendered
output is compared byte for byte with the baseline; the rows are aligned to classify the change (row vanished or
appeared, displayed cause of a row changed, decoration only, order only); the frontend's display rule (the transcription
of home-assistant-frontend 20260624.6 used in exp/out/e_ps_render_reconciliation.json) is applied for an admin and a
non-admin viewer; and the commitments of the monitor's closure, stable-columns and row schemes over the window are
recomputed with the monitor's own loaders. The mutation is then restored and checked three ways: the stored row equals
its original (value and type), every render equals the baseline byte for byte, every commitment equals the baseline.
A mutation of the user column is the positive control on every rendered target; rendering the baseline twice is the
determinism control. A replay of the earlier harness (homeprov_e4, unchanged) on the frozen copy reproduces the
earlier abort when, and only when, a row is written into the window during the measurement.

    python3 exp/stages/e8_closure_real.py acquire     # backup of hpr-hass's recorder (read-only), docker cp out
    python3 exp/stages/e8_closure_real.py plan        # targets and mutations, from the pristine copy
    python3 exp/stages/e8_closure_real.py up          # e8b-hass on a working copy
    python3 exp/stages/e8_closure_real.py run         # main measurement, then the replay of the earlier harness
    python3 exp/stages/e8_closure_real.py summarize   # exp/out/e8_closure_real.json
    python3 exp/stages/e8_closure_real.py down        # remove e8b-hass and its volume
Inside e8b-hass this file is the custom component e8b_closure (async_setup below).
"""
from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
import time

# ------------------------------------------------------------------------------------------------ shared constants
HOUSEHOLD_USER = "90b6f1f5983443c2b47f563e8f652752"
# The hub's auth accounts and person entities as recorded in exp/out/e_ps_render_reconciliation.json (accounts_on_hub;
# person_entities: none). The frontend's name map: admin = persons + auth users, non-admin = persons only.
ACCOUNTS = {"177db62efb414fbdb5af6e480c34a0b5": "Home Assistant Content",
            HOUSEHOLD_USER: "Alex Rivera (household)"}
PERSONS: dict = {}
CAUSE_KEYS = ("context_user_id", "context_entity_id", "context_entity_id_name", "context_state", "context_event_type",
              "context_domain", "context_service", "context_name", "context_message", "context_source")
DECOR_KEYS = ("icon", "attributes", "context_id")
FORMS = ("activity", "entity", "rest_entity")
HALF = 300.0          # window half-width, seconds
COMMIT_MARGIN = 1000.0
TABLES = ("states", "events", "states_meta", "state_attributes", "event_types", "event_data")
KEYCOL = {"states": "state_id", "events": "event_id", "states_meta": "metadata_id",
          "state_attributes": "attributes_id", "event_types": "event_type_id", "event_data": "data_id"}


def display_rule(row, names):
    """The frontend's context resolution (home-assistant-frontend 20260624.6), transcribed in
    exp/out/e_ps_render_reconciliation.json and used by exp/sp2027/r2_*_render.py; applied to one logbook entry."""
    u = row.get("context_user_id")
    if u and names.get(u):
        return "user:" + names[u]
    if row.get("context_event_type") in ("automation_triggered", "script_started"):
        n = row.get("context_entity_id") or row.get("context_name")
        if n:
            return "automation:" + n
    if row.get("context_event_type") == "call_service" and row.get("context_domain"):
        return "integration:" + row["context_domain"]
    return "none"


def enc(v):
    if v is None:
        return {"t": "null"}
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"t": "blob", "v": bytes(v).hex()}
    if isinstance(v, bool):
        raise TypeError("bool")
    if isinstance(v, int):
        return {"t": "int", "v": v}
    if isinstance(v, float):
        return {"t": "real", "v": repr(v)}
    if isinstance(v, str):
        return {"t": "text", "v": v}
    raise TypeError(type(v))


def dec(e):
    t = e["t"]
    return {"null": lambda: None, "blob": lambda: bytes.fromhex(e["v"]), "int": lambda: int(e["v"]),
            "real": lambda: float(e["v"]), "text": lambda: e["v"]}[t]()


def table_digest(db: str, watermarks: dict) -> dict:
    """SHA-256 over every row of the six measured tables, in key order, with typed values; states and events limited to
    keys at or below the copy's watermark (the hub's own later rows, if any, are reported separately)."""
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=60) if db.startswith("/Users") else \
        sqlite3.connect(db, timeout=60)
    con.execute("PRAGMA query_only=ON")
    out = {}
    for t in TABLES:
        k = KEYCOL[t]
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % t)]
        h = hashlib.sha256()
        n = 0
        q = "SELECT * FROM %s%s ORDER BY %s" % (t, " WHERE %s <= ?" % k if t in watermarks else "", k)
        for r in con.execute(q, (watermarks[t],) if t in watermarks else ()):
            h.update(json.dumps([enc(x) for x in r], sort_keys=True).encode())
            n += 1
        extra = con.execute("SELECT COUNT(*) FROM %s WHERE %s > ?" % (t, k), (watermarks[t],)).fetchone()[0] \
            if t in watermarks else None
        out[t] = {"columns": cols, "rows": n, "sha256": h.hexdigest(), "rows_above_watermark": extra}
    con.close()
    return out


# ================================================================================================ inner (in e8b-hass)
DOMAIN = "e8b_closure"
WORK_DB = "/e8bdb/work.db"
IO = "/config/e8b"


def _ident(r):
    return json.dumps({k: v for k, v in r.items() if k not in CAUSE_KEYS and k not in DECOR_KEYS},
                      sort_keys=True, default=str)


def _cause(r):
    return {k: r[k] for k in CAUSE_KEYS if k in r}


def _decor(r):
    return {k: r[k] for k in DECOR_KEYS if k in r}


def _find_target(rows, exp):
    if rows is None or exp is None:
        return None
    for i, r in enumerate(rows):
        if all(r.get(k) == v for k, v in exp.items()):
            return i
    return None


def compare(base_rows, rows, base_bytes, new_bytes, exp):
    """Classify the effect of one mutation on one rendered form."""
    res = {"changed": new_bytes != base_bytes}
    if not res["changed"]:
        return res
    if rows is None or base_rows is None:
        res["error"] = True
        return res
    a = [_ident(r) for r in base_rows]
    b = [_ident(r) for r in rows]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    van = app = cause = decor = da = dn = 0
    ex = None
    ti = _find_target(base_rows, exp)
    tj = None
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for i, j in zip(range(i1, i2), range(j1, j2)):
                ra, rb = base_rows[i], rows[j]
                if i == ti:
                    tj = j
                if _cause(ra) != _cause(rb):
                    cause += 1
                    if ex is None:
                        ex = {"row": json.loads(a[i]), "cause_before": _cause(ra), "cause_after": _cause(rb)}
                if _decor(ra) != _decor(rb):
                    decor += 1
                if display_rule(ra, {**PERSONS, **ACCOUNTS}) != display_rule(rb, {**PERSONS, **ACCOUNTS}):
                    da += 1
                if display_rule(ra, PERSONS) != display_rule(rb, PERSONS):
                    dn += 1
        else:
            van += i2 - i1
            app += j2 - j1
    full = lambda rr: sorted(json.dumps(r, sort_keys=True, default=str) for r in rr)
    res.update({"rows_before": len(base_rows), "rows_after": len(rows), "vanished": van, "appeared": app,
                "cause_changed": cause, "decoration_changed": decor, "display_changed_admin": da,
                "display_changed_nonadmin": dn,
                "order_only": van == 0 and app == 0 and cause == 0 and decor == 0 and full(base_rows) == full(rows),
                "example": ex})
    if ti is not None:
        tb = base_rows[ti]
        res["target"] = {"rendered_before": True, "vanished": tj is None,
                         "cause_before": _cause(tb), "cause_after": _cause(rows[tj]) if tj is not None else None,
                         "display_admin_before": display_rule(tb, {**PERSONS, **ACCOUNTS}),
                         "display_admin_after": display_rule(rows[tj], {**PERSONS, **ACCOUNTS}) if tj is not None
                         else None}
    else:
        tnew = _find_target(rows, exp)
        res["target"] = {"rendered_before": False, "appeared": tnew is not None}
    if not (van or app or cause or decor) and not res["order_only"]:
        # same rows, same causes and decorations, different bytes: report the first differing key
        for ra, rb in zip(base_rows, rows):
            if ra != rb:
                res["other_diff"] = {"before": ra, "after": rb}
                break
    return res


class Inner:
    def __init__(self, hass):
        self.hass = hass
        self.M = None
        self.con = None

    # -- monitor commitments
    def _monitor(self):
        if self.M is None:
            import importlib.util
            os.environ.setdefault("HOMEPROV_ENCODING", "v2")
            os.environ.setdefault("HOMEPROV_COVERAGE", "1")
            spec = importlib.util.spec_from_file_location("e8b_monitor_snapshot", os.path.join(IO, "monitor_snapshot.py"))
            M = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(M)
            orig = M._where
            M._HI = None

            def _where(col, since, guard, until=None):
                # the E10 monitor added an optional upper bound ("until"); forward it only when given, so the E8-era
                # monitor (three arguments) still works (fix of 2026-10-20, E10 review-r5 smoke, arm D)
                base = orig(col, since, guard) if until is None else orig(col, since, guard, until)
                return base + " AND %s <= %r" % (col, M._HI)
            M._where = _where
            self.M = M
        return self.M

    def commit(self, lo, hi):
        M = self._monitor()
        M._HI = hi
        out = {}
        for scheme in ("closure", "stable", "row"):
            M.SCHEME = scheme
            nodes = M.load(WORK_DB, lo)
            h = hashlib.sha256()
            for n in nodes:
                h.update(n[1].encode() + b"\x00" + M.node_digest(n))
            out[scheme] = [h.hexdigest(), len(nodes)]
        return out

    # -- rendering
    def make_ep(self, form, ent):
        from homeassistant.components.logbook.helpers import async_determine_event_types, async_filter_entities
        from homeassistant.components.logbook.processor import EventProcessor
        if form == "activity":
            return EventProcessor(self.hass, async_determine_event_types(self.hass, None, None), None, None, None,
                                  timestamp=True, include_entity_name=False)
        if not ent:
            return None
        ents = async_filter_entities(self.hass, [ent])
        if not ents:
            return None
        et = async_determine_event_types(self.hass, ents, None)
        if form == "entity":
            return EventProcessor(self.hass, et, ents, None, None, timestamp=True, include_entity_name=False)
        return EventProcessor(self.hass, et, ents, None, None, timestamp=False, include_entity_name=True)

    async def render(self, form, ent, start, end):
        from homeassistant.components.recorder import get_instance
        from homeassistant.helpers.json import json_bytes
        ep = self.make_ep(form, ent)
        if ep is None:
            return None

        def run():
            try:
                rows = ep.get_events(start, end)
                return json_bytes(rows), rows
            except Exception as exc:                                      # noqa: BLE001
                return ("ERROR %s: %s" % (type(exc).__name__, exc)).encode(), None
        return await get_instance(self.hass).async_add_executor_job(run)

    async def render_all(self, tgt, start, end):
        out = {}
        for f in FORMS:
            r = await self.render(f, tgt.get("entity"), start, end)
            if r is not None:
                out[f] = r
        return out

    async def job(self, fn, *a):
        from homeassistant.components.recorder import get_instance
        return await get_instance(self.hass).async_add_executor_job(fn, *a)

    # -- mutation
    def _conn(self):
        if self.con is None:
            self.con = sqlite3.connect(WORK_DB, timeout=60, isolation_level=None, check_same_thread=False)
            self.con.execute("PRAGMA busy_timeout=60000")
        return self.con

    def row(self, table, kc, key):
        c = self._conn()
        r = c.execute('SELECT * FROM %s WHERE "%s"=?' % (table, kc), (key,)).fetchone()
        return None if r is None else [enc(x) for x in r]

    def apply(self, m):
        """One mutation: the primary column, plus (compound variants only) further columns of the same row, applied
        in order. Returns the original values and the row's key afterwards."""
        c = self._conn()
        t, kc, k = m["table"], m["key_col"], m["key"]
        cols = [(m["col"], m["new"])] + [(a["col"], a["new"]) for a in m.get("also", [])]
        origs = []
        cur = k
        for col, new in cols:
            orig = c.execute('SELECT "%s" FROM %s WHERE "%s"=?' % (col, t, kc), (cur,)).fetchone()
            if orig is None:
                raise RuntimeError("row %s %s=%s missing" % (t, kc, cur))
            nv = dec(new)
            n = c.execute('UPDATE %s SET "%s"=? WHERE "%s"=?' % (t, col, kc), (nv, cur)).rowcount
            if n != 1:
                raise RuntimeError("update touched %d rows" % n)
            origs.append((col, orig[0], cur))
            if col == kc:
                cur = nv
        return origs, cur

    def restore(self, m, origs, curkey):
        c = self._conn()
        cur = curkey
        for col, orig, key_before in reversed(origs):
            c.execute('UPDATE %s SET "%s"=? WHERE "%s"=?' % (m["table"], col, m["key_col"]), (orig, cur))
            if col == m["key_col"]:
                cur = key_before
        return cur

    # -- one target
    async def run_target(self, tgt, out_fh):
        from datetime import datetime, timezone
        from homeassistant.components.recorder.models import process_timestamp_to_utc_isoformat
        start = datetime.fromtimestamp(tgt["window"][0], timezone.utc)
        end = datetime.fromtimestamp(tgt["window"][1], timezone.utc)
        lo, hi = tgt["window"][0] - COMMIT_MARGIN, tgt["window"][1] + COMMIT_MARGIN
        exp = {}
        for f in FORMS:
            e = dict(tgt["expect"]) if tgt.get("expect") else None
            if e is not None and f == "rest_entity":
                e["when"] = process_timestamp_to_utc_isoformat(datetime.fromtimestamp(e["when"], timezone.utc))
            exp[f] = e
        t0 = time.time()
        await self.render_all(tgt, start, end)                    # warm-up (manager caches, lambda caches)
        base = await self.render_all(tgt, start, end)
        again = await self.render_all(tgt, start, end)
        base_commit = await self.job(self.commit, lo, hi)
        res = {"target": tgt["id"], "role": tgt["role"], "forms": sorted(base),
               "baseline": {f: {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b),
                                "rows": None if r is None else len(r),
                                "error": None if r is not None else b.decode(errors="replace"),
                                "target_rendered": _find_target(r, exp[f]) is not None,
                                "target_entry": (r[_find_target(r, exp[f])] if r is not None and
                                                 _find_target(r, exp[f]) is not None else None)}
                             for f, (b, r) in base.items()},
               "determinism_equal": {f: again[f][0] == base[f][0] for f in base},
               "baseline_commit": base_commit, "mutations": []}
        for m in tgt["mutations"]:
            rec = {"field": m["field"], "variant": m["variant"], "table": m["table"], "key": m["key"],
                   "new": m["new"], **({"also": m["also"]} if m.get("also") else {})}
            before_row = await self.job(self.row, m["table"], m["key_col"], m["key"])
            try:
                orig, curkey = await self.job(self.apply, m)
            except Exception as exc:                              # noqa: BLE001
                rec["apply_error"] = repr(exc)
                rec["restore"] = {"db_equal": (await self.job(self.row, m["table"], m["key_col"], m["key"]))
                                  == before_row}
                res["mutations"].append(rec)
                continue
            rec["orig"] = enc(orig[0][1])
            if len(orig) > 1:
                rec["also_orig"] = [[c_, enc(v_)] for c_, v_, _k in orig[1:]]
            try:
                after = await self.render_all(tgt, start, end)
                cm = await self.job(self.commit, lo, hi)
            finally:
                await self.job(self.restore, m, orig, curkey)
            rec["render"] = {f: compare(base[f][1], after[f][1], base[f][0], after[f][0], exp[f]) for f in base}
            rec["commit_changed"] = {s: cm[s] != base_commit[s] for s in cm}
            rec["commit_nodes"] = {s: [base_commit[s][1], cm[s][1]] for s in cm}
            after_row = await self.job(self.row, m["table"], m["key_col"], m["key"])
            rest = await self.render_all(tgt, start, end)
            rc = await self.job(self.commit, lo, hi)
            rec["restore"] = {"db_equal": after_row == before_row,
                              "render_equal": {f: rest[f][0] == base[f][0] for f in base},
                              "commit_equal": rc == base_commit}
            if not all(rec["restore"]["render_equal"].values()) or not rec["restore"]["commit_equal"] \
                    or not rec["restore"]["db_equal"]:
                # Diagnose rather than abort: render again, and keep what differs.
                rest2 = await self.render_all(tgt, start, end)
                rec["restore"]["render_equal_second_try"] = {f: rest2[f][0] == base[f][0] for f in base}
                rec["restore"]["diff"] = {f: compare(base[f][1], rest[f][1], base[f][0], rest[f][0], exp[f])
                                          for f in base if rest[f][0] != base[f][0]}
            res["mutations"].append(rec)
        res["seconds"] = round(time.time() - t0, 2)
        out_fh.write(json.dumps(res, default=str) + "\n")
        out_fh.flush()
        return res

    # -- static read-set
    def static_read_set(self, tgt):
        """Every table.column the logbook's compiled SQL references (SELECT, JOIN, WHERE, ORDER BY), for the
        unscoped and the entity-scoped statement, plus the parent-user lookup statement."""
        import re
        from datetime import datetime, timezone
        from sqlalchemy.dialects import sqlite as sqld
        from homeassistant.components.logbook.queries import statement_for_request
        from homeassistant.components.logbook.queries.common import select_context_user_ids_for_context_ids
        from homeassistant.components.logbook.helpers import async_determine_event_types
        from homeassistant.components.recorder import get_instance
        from homeassistant.components.recorder.models import extract_event_type_ids, extract_metadata_ids
        from homeassistant.components.recorder.util import session_scope
        start = datetime.fromtimestamp(tgt["window"][0], timezone.utc)
        end = datetime.fromtimestamp(tgt["window"][1], timezone.utc)
        inst = get_instance(self.hass)
        out = {}

        def run():
            with session_scope(hass=self.hass, read_only=True) as session:
                for label, ents in (("activity", None), ("entity", [tgt["entity"]])):
                    ets = async_determine_event_types(self.hass, ents, None)
                    eids = tuple(extract_event_type_ids(inst.event_type_manager.get_many(ets, session)))
                    mids = extract_metadata_ids(inst.states_meta_manager.get_many(ents, session, False)) \
                        if ents else None
                    stmt = statement_for_request(start, end, eids, ents, mids, None, None, None)
                    sql = str(stmt._resolved.compile(dialect=sqld.dialect()))
                    out[label] = sql
                st = select_context_user_ids_for_context_ids([b"x" * 16])
                out["parent_user_lookup"] = str(st._resolved.compile(dialect=sqld.dialect()))
        run()
        cols = {}
        for label, sql in out.items():
            found = set()
            for tab, col in re.findall(r"\b(states|events|states_meta|event_types|event_data|state_attributes|"
                                       r"old_state)\.(\w+)", sql):
                found.add("%s.%s" % ("states" if tab == "old_state" else tab, col))
            cols[label] = sorted(found)
        return {"sql": out, "columns": cols, "union": sorted({c for v in cols.values() for c in v})}

    # -- replay of the earlier harness (homeprov_e4, unchanged) on the frozen copy
    async def replay_e4(self, end_ts, live_write):
        """Run the earlier harness's closure procedure (its own _entities, _pick, _render, _fingerprint, _mutations and
        _mutate_and_render) on the frozen copy, with its 6-hour window ending one minute after the copy was taken.
        With live_write, one state row is inserted into the window after the baseline, as the live recorder did
        while the earlier harness ran; the row is deleted afterwards."""
        import importlib
        from datetime import datetime, timezone, timedelta
        mod = importlib.import_module("custom_components.homeprov_e4")
        mod.DB = WORK_DB
        end = datetime.fromtimestamp(end_ts, timezone.utc) + timedelta(minutes=1)
        start = end - timedelta(hours=6)
        lo, hi = start.timestamp(), end.timestamp()

        def prep():
            con = mod._connect()
            ents = mod._entities(con, lo, hi)
            picked = mod._pick(con, ents, lo, hi)
            con.close()
            return ents, picked
        ents, picked = await self.job(prep)
        base = mod._fingerprint(await mod._render(self.hass, start, end, ents))
        inserted = []

        def ins():
            c = self._conn()
            # the write the live recorder makes next: the porch light's newest row, followed one second later by
            # the opposite state, chained to it as a recorded state change (inside the harness's window, which
            # ends one minute after "now")
            r = c.execute("""SELECT s.state_id, s.metadata_id, s.state, s.last_updated_ts, s.attributes_id
                               FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                              WHERE sm.entity_id='light.porch_light' AND s.last_updated_ts < ?
                           ORDER BY s.last_updated_ts DESC LIMIT 1""", (hi - 60,)).fetchone()
            sid = c.execute("SELECT max(state_id)+1 FROM states").fetchone()[0]
            c.execute("""INSERT INTO states (state_id, state, last_updated_ts, old_state_id, attributes_id,
                                             origin_idx, context_id_bin, metadata_id)
                         VALUES (?,?,?,?,?,0,?,?)""",
                      (sid, "off" if r[2] == "on" else "on", hi - 59, r[0], r[4], os.urandom(16), r[1]))
            inserted.append(sid)

        orig_render = mod._render
        armed = {"n": None}

        async def render_hook(*a, **kw):
            # With live_write: the earlier harness's _mutate_and_render renders twice (mutated, then restored); the
            # row is written between those two renders of the first event field, as a live recorder can.
            if armed["n"] is not None:
                armed["n"] -= 1
                if armed["n"] == 0:
                    await self.job(ins)
                    armed["n"] = None
            return await orig_render(*a, **kw)
        mod._render = render_hook
        results = []
        t0 = time.time()
        try:
            for field, sql, args in mod._mutations(picked):
                if sql is None:
                    results.append({"field": field, "method": "static-only"})
                    continue
                if live_write and field == "events.context_id_bin":
                    armed["n"] = 2
                r = await mod._mutate_and_render(self.hass, start, end, ents, base, field, sql, args)
                results.append(r)
                if r.get("restore_verified") is False:
                    results.append({"field": "ABORT", "err": "restore did not reproduce the baseline render"})
                    break
        finally:
            mod._render = orig_render
            if inserted:
                def rm():
                    self._conn().execute("DELETE FROM states WHERE state_id=?", (inserted[0],))
                await self.job(rm)
        return {"live_write": live_write, "inserted_state_id": inserted[0] if inserted else None,
                "seconds": round(time.time() - t0, 2), "window": [lo, hi],
                "entities_scoped": ents, "baseline_rows": len(base),
                "picked": {"state_id": picked["state"][0] if picked["state"] else None,
                           "event_id": picked["event"][0] if picked["event"] else None},
                "mutations": results,
                "aborted": any(r.get("field") == "ABORT" for r in results)}

    # -- commands
    async def cmd(self, c):
        from homeassistant.components.recorder import get_instance
        op = c["op"]
        if op == "info":
            import homeassistant.const as HC
            import importlib.metadata as md
            lb = self.hass.data.get("logbook")
            return {"ha_version": HC.__version__, "frontend": md.version("home-assistant-frontend"),
                    "sqlalchemy": md.version("SQLAlchemy"), "sqlite": sqlite3.sqlite_version,
                    "recorder_enabled": get_instance(self.hass).enabled,
                    "recorder_db": str(get_instance(self.hass).db_url),
                    "external_events": sorted(map(str, lb.external_events)) if lb else None,
                    "components": sorted(self.hass.config.components)}
        if op == "digest":
            return await self.job(table_digest, WORK_DB, c["watermarks"])
        if op == "static":
            plan = json.load(open(os.path.join(IO, "plan.json")))
            tgt = next(t for t in plan["targets"] if t["id"] == c["target"])
            return await self.job(self.static_read_set, tgt)
        if op == "run":
            plan = json.load(open(os.path.join(IO, "plan.json")))
            os.makedirs(os.path.join(IO, "out"), exist_ok=True)
            done = set()
            path = os.path.join(IO, "out", "raw.jsonl")
            if os.path.exists(path):
                for line in open(path):
                    done.add(json.loads(line)["target"])
            n = 0
            with open(path, "a") as fh:
                for tgt in plan["targets"]:
                    if tgt["id"] in done or (c.get("only") and tgt["id"] not in c["only"]):
                        continue
                    await self.run_target(tgt, fh)
                    n += 1
            return {"targets_run": n}
        if op == "replay":
            return await self.replay_e4(c["end_ts"], c["live_write"])
        if op == "apply":            # browser oracle: hold one mutation until "restore"
            before = await self.job(self.row, c["m"]["table"], c["m"]["key_col"], c["m"]["key"])
            origs, cur = await self.job(self.apply, c["m"])
            self.pending = (c["m"], origs, cur, before)
            return {"applied": True}
        if op == "restore":
            m, origs, cur, before = self.pending
            await self.job(self.restore, m, origs, cur)
            self.pending = None
            return {"db_equal": (await self.job(self.row, m["table"], m["key_col"], m["key"])) == before}
        if op == "render_rows":
            from datetime import datetime, timezone
            start = datetime.fromtimestamp(c["window"][0], timezone.utc)
            end = datetime.fromtimestamp(c["window"][1], timezone.utc)
            b, rows = await self.render(c["form"], c.get("entity"), start, end)
            return {"sha256": hashlib.sha256(b).hexdigest(), "rows": rows}
        return {"err": "unknown op %r" % op}


async def async_setup(hass, config):
    """Custom-component entry point inside e8b-hass."""
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
    from homeassistant.components.recorder import get_instance
    inner = Inner(hass)
    os.makedirs(IO, exist_ok=True)

    async def _started(_ev=None):
        # Nothing but this stage may write to the copy: stop the recorder from recording anything further.
        await hass.services.async_call("recorder", "disable", {}, blocking=True)
        await get_instance(hass).async_block_till_done()
        with open(os.path.join(IO, "ready.json"), "w") as fh:
            json.dump({"ready_at": time.time(), "recorder_enabled": get_instance(hass).enabled}, fh)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _started)

    async def _loop():
        while True:
            p = os.path.join(IO, "cmd.json")
            if os.path.exists(p):
                try:
                    c = json.load(open(p))
                except ValueError:
                    await asyncio.sleep(1)
                    continue
                os.remove(p)
                try:
                    out = await inner.cmd(c)
                except Exception as exc:                          # noqa: BLE001
                    import traceback
                    out = {"err": repr(exc), "tb": traceback.format_exc()}
                tmp = os.path.join(IO, "ack.tmp")
                with open(tmp, "w") as fh:
                    json.dump({"op": c.get("op"), "tag": c.get("tag"), "result": out}, fh, default=str)
                os.replace(tmp, os.path.join(IO, "ack_%s.json" % c.get("tag", c.get("op"))))
            await asyncio.sleep(1)

    hass.async_create_background_task(_loop(), "e8b_closure_loop")
    return True


# ================================================================================================ host side
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
DATA = "<research-dir>/HOMEPROV-P13-exp/e8b_closure"
PRISTINE = os.path.join(DATA, "pristine.db")
CFG = os.path.join(DATA, "config")
IMAGE = "homeassistant/home-assistant:2026.7.4"
CONTAINER = "e8b-hass"
VOLUME = "e8b-db"
SEED = 20261009


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def acquire():
    """One read-only SQLite backup of hpr-hass's recorder, copied out and removed from the container. Must not run
    between 03:50 and 05:00 UTC (E2 night snapshots and the recorder's purge)."""
    path = os.path.join(DATA, "acquire.json")
    if os.path.exists(PRISTINE):
        raise SystemExit("pristine copy exists; refusing to overwrite")
    hm = time.gmtime()
    if (hm.tm_hour, hm.tm_min) >= (3, 50) and hm.tm_hour < 5:
        raise SystemExit("03:50-05:00 UTC: nothing may touch hpr-* now")
    os.makedirs(DATA, exist_ok=True)
    code = ("import sqlite3,time,os\n"
            "t0=time.time()\n"
            "s=sqlite3.connect('file:/config/home-assistant_v2.db?mode=ro',uri=True,timeout=30)\n"
            "d=sqlite3.connect('/tmp/e8b_copy.db')\n"
            "s.backup(d)\n"
            "r=d.execute('select max(state_id),max(event_id),(select max(last_updated_ts) from states),"
            "(select max(time_fired_ts) from events) from states').fetchone()\n"
            "d.close(); s.close()\n"
            "print(r, round(time.time()-t0,2), os.path.getsize('/tmp/e8b_copy.db'), time.time())\n")
    t0 = time.time()
    r = sh(["docker", "exec", "hpr-hass", "python3", "-c", code])
    if r.returncode:
        raise SystemExit(r.stderr)
    sh(["docker", "cp", "hpr-hass:/tmp/e8b_copy.db", PRISTINE])
    sh(["docker", "exec", "hpr-hass", "rm", "-f", "/tmp/e8b_copy.db"])
    os.chmod(PRISTINE, 0o444)
    json.dump({"source": "hpr-hass:/config/home-assistant_v2.db", "method": "sqlite3 backup API, mode=ro, in hpr-hass",
               "started": utc(t0), "inner_stdout": r.stdout.strip(), "sha256": sha(PRISTINE)},
              open(path, "w"), indent=1)


def watermarks(con):
    w = {}
    for t, k in (("states", "state_id"), ("events", "event_id")):
        w[t] = con.execute("SELECT max(%s) FROM %s" % (k, t)).fetchone()[0]
    return w


# ---------------------------------------------------------------------------------------------- plan
ELIG = ("o.state_id IS NOT NULL AND s.state IS NOT NULL AND s.state<>o.state "
        "AND (s.last_changed_ts IS NULL OR s.last_changed_ts=s.last_updated_ts)")
AUTO_CTX = ("EXISTS (SELECT 1 FROM events ae WHERE ae.context_id_bin=s.context_id_bin AND ae.event_type_id="
            "(SELECT event_type_id FROM event_types WHERE event_type='automation_triggered'))")
SVC_CTX = ("EXISTS (SELECT 1 FROM events ce JOIN event_data cd ON cd.data_id=ce.data_id WHERE "
           "ce.context_id_bin=s.context_id_bin AND ce.event_type_id=(SELECT event_type_id FROM event_types WHERE "
           "event_type='call_service') AND cd.shared_data LIKE '%%\"service\":\"%s\"%%')")
STATE_ROLES = [
    # role, condition, count, one per entity. On this deployment the front-door lock changes only when an experiment
    # harness actuates it: through a lock service call (the row then shares the call's context), and in earlier trials
    # some of those rows were rewritten into an automation run's context (laundering) or given a user id (swap).
    ("lock_unlock_in_service_call_context", "sm.entity_id='lock.front_door' AND s.state='unlocked' "
                                            "AND s.context_user_id_bin IS NULL AND " + ELIG + " AND "
                                            + SVC_CTX % "unlock" + " AND NOT " + AUTO_CTX, 2, False),
    ("lock_unlock_in_automation_context", "sm.entity_id='lock.front_door' AND s.state='unlocked' "
                                          "AND s.context_user_id_bin IS NULL AND " + ELIG + " AND " + AUTO_CTX, 2,
     False),
    ("lock_locked_in_service_call_context", "sm.entity_id='lock.front_door' AND s.state='locked' "
                                            "AND s.context_user_id_bin IS NULL AND " + ELIG + " AND "
                                            + SVC_CTX % "lock", 1, False),
    ("lock_front_user_column", "sm.entity_id='lock.front_door' AND s.context_user_id_bin IS NOT NULL AND " + ELIG,
     2, False),
    ("lock_no_old_state", "sm.entity_id LIKE 'lock.%' AND s.old_state_id IS NULL", 2, True),
    ("lock_back_door", "sm.entity_id='lock.back_door' AND " + ELIG, 1, False),
    ("light_on_automation", "sm.entity_id LIKE 'light.%' AND s.state='on' AND " + ELIG + " AND " + AUTO_CTX, 3, True),
    ("light_off_automation", "sm.entity_id LIKE 'light.%' AND s.state='off' AND " + ELIG + " AND " + AUTO_CTX, 3,
     True),
    ("light_no_old_state", "sm.entity_id LIKE 'light.%' AND s.old_state_id IS NULL", 1, False),
    ("light_last_changed_differs", "sm.entity_id LIKE 'light.%' AND s.last_changed_ts IS NOT NULL "
                                   "AND s.last_changed_ts<>s.last_updated_ts", 1, False),
    ("motion_on", "sm.entity_id LIKE 'binary_sensor.%' AND s.state='on' AND " + ELIG, 3, True),
    ("motion_off", "sm.entity_id LIKE 'binary_sensor.%' AND s.state='off' AND " + ELIG, 2, True),
    ("motion_no_old_state", "sm.entity_id LIKE 'binary_sensor.%' AND s.old_state_id IS NULL", 1, False),
    ("automation_entity_state", "sm.entity_id LIKE 'automation.%'", 2, True),
    ("sun", "sm.entity_id='sun.sun'", 1, False),
    ("backup_sensor", "sm.entity_id='sensor.backup_backup_manager_state'", 1, False),
]
EVENT_ROLES = [
    ("automation_triggered", "et.event_type='automation_triggered'", 4, True),
    ("call_service_by_automation", "et.event_type='call_service' AND e.context_parent_id_bin IS NOT NULL "
                                   "AND e.context_user_id_bin IS NULL", 3, True),
    ("call_service_with_user", "et.event_type='call_service' AND e.context_user_id_bin IS NOT NULL", 3, False),
    ("call_service_no_parent_no_user", "et.event_type='call_service' AND e.context_parent_id_bin IS NULL "
                                       "AND e.context_user_id_bin IS NULL", 1, False),
    ("homeassistant_start", "et.event_type='homeassistant_start'", 1, False),
]
# A render-eligible state row without an attributes row: on this deployment only rows an earlier experiment's
# insertion arm wrote (E7, 2026-10-08) have one; it is the role on which the legacy states.attributes column is read.
EXTRA_STATE_ROLES = [
    ("inserted_row_without_attributes_row", "s.attributes_id IS NULL AND " + ELIG, 1, False),
]


def _ent_of_event(etype, data):
    try:
        d = json.loads(data or "{}")
    except ValueError:
        return None
    if etype == "automation_triggered":
        return d.get("entity_id")
    if etype == "call_service":
        e = (d.get("service_data") or {}).get("entity_id")
        return e[0] if isinstance(e, list) and e else e
    return None


def plan():
    con = sqlite3.connect("file:%s?mode=ro" % PRISTINE, uri=True)
    rng = random.Random(SEED)
    tmax = max(con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0],
               con.execute("SELECT max(time_fired_ts) FROM events").fetchone()[0])
    p_hi = tmax - 2 * HALF
    p_lo = tmax - 30 * 3600
    clean_lo = 1791491140 + 300          # five minutes after E7's run ended (exp/out/e7_main_t_end)
    wm = watermarks(con)
    scols = [r[1] for r in con.execute("PRAGMA table_info(states)")]
    ecols = [r[1] for r in con.execute("PRAGMA table_info(events)")]
    etype_id = dict((t, i) for i, t in con.execute("SELECT event_type_id, event_type FROM event_types"))
    used = set()
    targets = []

    def pick(rows, n, per_entity, clean_first):
        rows = sorted(rows)
        clean = [r for r in rows if r[1] >= clean_lo]
        rest = [r for r in rows if r[1] < clean_lo]
        rng.shuffle(clean)
        rng.shuffle(rest)
        out, ents = [], set()
        for r in (clean + rest) if clean_first else (rest + clean):
            if r[0] in used or (per_entity and r[2] in ents):
                continue
            out.append(r)
            ents.add(r[2])
            used.add(r[0])
            if len(out) == n:
                break
        return out

    for role, cond, n, per_ent in STATE_ROLES:
        rows = con.execute("""SELECT s.state_id, s.last_updated_ts, sm.entity_id FROM states s
                                JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                                LEFT JOIN states o ON o.state_id=s.old_state_id
                               WHERE s.last_updated_ts BETWEEN ? AND ? AND %s""" % cond, (p_lo, p_hi)).fetchall()
        for sid, ts, ent in pick(rows, n, per_ent, True):
            targets.append({"kind": "state", "role": role, "key": sid, "ts": ts, "entity": ent})
    def state_role(role, cond, n, per_ent):
        rows = con.execute("""SELECT s.state_id, s.last_updated_ts, sm.entity_id FROM states s
                                JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                                LEFT JOIN states o ON o.state_id=s.old_state_id
                               WHERE s.last_updated_ts BETWEEN ? AND ? AND %s""" % cond, (p_lo, p_hi)).fetchall()
        for sid, ts, ent in pick(rows, n, per_ent, True):
            targets.append({"kind": "state", "role": role, "key": sid, "ts": ts, "entity": ent})

    for role, cond, n, per_ent in EVENT_ROLES:
        rows = con.execute("""SELECT e.event_id, e.time_fired_ts, et.event_type, ed.shared_data FROM events e
                                JOIN event_types et ON et.event_type_id=e.event_type_id
                                LEFT JOIN event_data ed ON ed.data_id=e.data_id
                               WHERE e.time_fired_ts BETWEEN ? AND ? AND %s""" % cond, (p_lo, p_hi)).fetchall()
        rows = [(r[0], r[1], _ent_of_event(r[2], r[3]) or "") for r in rows]
        for eid, ts, ent in pick(rows, n, per_ent, role != "call_service_with_user"):
            targets.append({"kind": "event", "role": role, "key": eid, "ts": ts, "entity": ent or None})
    for role, cond, n, per_ent in EXTRA_STATE_ROLES:
        state_role(role, cond, n, per_ent)

    user_ctx = con.execute("""SELECT context_id_bin FROM events WHERE context_user_id_bin=? ORDER BY time_fired_ts DESC
                              LIMIT 1""", (bytes.fromhex(HOUSEHOLD_USER),)).fetchone()[0]
    max_state = con.execute("SELECT max(state_id) FROM states").fetchone()[0]
    max_event = con.execute("SELECT max(event_id) FROM events").fetchone()[0]
    max_attr = con.execute("SELECT max(attributes_id) FROM state_attributes").fetchone()[0]
    max_data = con.execute("SELECT max(data_id) FROM event_data").fetchone()[0]
    max_meta = con.execute("SELECT max(metadata_id) FROM states_meta").fetchone()[0]
    max_et = con.execute("SELECT max(event_type_id) FROM event_types").fetchone()[0]
    icon_attr = con.execute("SELECT attributes_id FROM state_attributes WHERE shared_attrs LIKE '%\"icon\"%' "
                            "ORDER BY attributes_id LIMIT 1").fetchone()

    def M(field, variant, table, kc, key, col, new, also=None):
        d = {"field": field, "variant": variant, "table": table, "key_col": kc, "key": key, "col": col,
             "new": enc(new)}
        if also:
            d["also"] = [{"col": c, "new": enc(v)} for c, v in also]
        return d

    def other_ctx(lo, hi, ctx):
        r = con.execute("""SELECT e.context_id_bin FROM events e WHERE e.event_type_id=? AND e.time_fired_ts
                           BETWEEN ? AND ? AND e.context_id_bin<>? ORDER BY abs(e.time_fired_ts-?) LIMIT 1""",
                        (etype_id["automation_triggered"], lo, hi, ctx or b"", (lo + hi) / 2)).fetchone()
        if r is None:
            r = con.execute("""SELECT context_id_bin FROM events WHERE time_fired_ts BETWEEN ? AND ?
                               AND context_id_bin<>? LIMIT 1""", (lo, hi, ctx or b"")).fetchone()
        return r[0] if r else os.urandom(16)

    def common_ctx_variants(table, kc, key, row, lo, hi):
        out = []
        f = "%s." % table
        cid, cuser, cpar = row["context_id_bin"], row["context_user_id_bin"], row["context_parent_id_bin"]
        rnd = lambda: bytes(rng.getrandbits(8) for _ in range(16))
        out.append(M(f + "context_id_bin", "random", table, kc, key, "context_id_bin", rnd()))
        out.append(M(f + "context_id_bin", "other_automation_run", table, kc, key, "context_id_bin",
                     other_ctx(lo, hi, cid)))
        out.append(M(f + "context_id_bin", "null", table, kc, key, "context_id_bin", None))
        out.append(M(f + "context_user_id_bin", "random", table, kc, key, "context_user_id_bin", rnd()))
        if cuser != bytes.fromhex(HOUSEHOLD_USER):
            out.append(M(f + "context_user_id_bin", "household_user", table, kc, key, "context_user_id_bin",
                         bytes.fromhex(HOUSEHOLD_USER)))
        if cuser is not None:
            out.append(M(f + "context_user_id_bin", "null", table, kc, key, "context_user_id_bin", None))
        out.append(M(f + "context_parent_id_bin", "random", table, kc, key, "context_parent_id_bin", rnd()))
        if cpar != user_ctx:
            out.append(M(f + "context_parent_id_bin", "user_context", table, kc, key, "context_parent_id_bin",
                         user_ctx))
        out.append(M(f + "context_parent_id_bin", "other_automation_run", table, kc, key, "context_parent_id_bin",
                     other_ctx(lo, hi, cpar or cid)))
        if cpar is not None:
            out.append(M(f + "context_parent_id_bin", "null", table, kc, key, "context_parent_id_bin", None))
        out.append(M(f + "context_id", "legacy_text", table, kc, key, "context_id", "01E8B0000000000000000000AA"))
        out.append(M(f + "context_user_id", "legacy_text", table, kc, key, "context_user_id", HOUSEHOLD_USER))
        out.append(M(f + "context_parent_id", "legacy_text", table, kc, key, "context_parent_id",
                     "01E8B0000000000000000000BB"))
        out.append(M(f + "origin_idx", "plus_1", table, kc, key, "origin_idx", (row["origin_idx"] or 0) + 1))
        return out

    for i, t in enumerate(sorted(targets, key=lambda x: (x["kind"], x["role"], x["ts"]))):
        t["id"] = "T%02d" % i
        lo, hi = t["ts"] - HALF, t["ts"] + HALF
        t["window"] = [lo, hi]
        muts = []
        if t["kind"] == "state":
            row = dict(zip(scols, con.execute("SELECT * FROM states WHERE state_id=?", (t["key"],)).fetchone()))
            t["stored"] = {k: enc(v) for k, v in row.items()}
            key, ent = t["key"], t["entity"]
            t["expect"] = {"entity_id": ent, "when": row["last_updated_ts"], "state": row["state"]}
            S = lambda col, var, new: M("states." + col, var, "states", "state_id", key, col, new)
            muts.append(S("state_id", "fresh_key", max_state + 10_000_000 + key))
            other_ent = con.execute("SELECT entity_id FROM states_meta WHERE entity_id<>? AND entity_id LIKE ? "
                                    "ORDER BY metadata_id LIMIT 1", (ent, ent.split(".")[0] + ".%")).fetchone() or \
                con.execute("SELECT entity_id FROM states_meta WHERE entity_id<>? ORDER BY metadata_id DESC LIMIT 1",
                            (ent,)).fetchone()
            muts.append(S("entity_id", "legacy_other_entity", other_ent[0]))
            muts.append(S("state", "suffix", (row["state"] or "") + "_e8b"))
            old = con.execute("SELECT state FROM states WHERE state_id=?", (row["old_state_id"],)).fetchone() \
                if row["old_state_id"] else None
            if old and old[0] != row["state"]:
                muts.append(S("state", "equal_to_old_state", old[0]))
            muts.append(S("state", "null", None))
            muts.append(S("attributes", "legacy_icon", '{"icon":"mdi:e8b"}'))
            muts.append(S("attributes", "legacy_unit", '{"unit_of_measurement":"e8b"}'))
            muts.append(S("attributes", "legacy_event_type", '{"event_type":"e8b"}'))
            if row["attributes_id"] is not None:
                # compound: the legacy column is read only when the row has no attributes row
                for var, js in (("legacy_icon_with_attributes_id_null", '{"icon":"mdi:e8b"}'),
                                ("legacy_unit_with_attributes_id_null", '{"unit_of_measurement":"e8b"}'),
                                ("legacy_event_type_with_attributes_id_null", '{"event_type":"e8b"}')):
                    muts.append(M("states.attributes", var, "states", "state_id", key, "attributes", js,
                                  also=[("attributes_id", None)]))
            muts.append(S("event_id", "legacy_int", 1))
            muts.append(S("last_changed", "legacy_text", "2026-10-01 00:00:00.000000"))
            lu = row["last_updated_ts"]
            if row["last_changed_ts"] is None:
                muts.append(S("last_changed_ts", "minus_900", lu - 900))
                muts.append(S("last_changed_ts", "equal_last_updated", lu))
            else:
                muts.append(S("last_changed_ts", "null", None))
                muts.append(S("last_changed_ts", "equal_last_updated", lu))
            if row["last_reported_ts"] is None:
                muts.append(S("last_reported_ts", "plus_5", lu + 5))
            else:
                muts.append(S("last_reported_ts", "null", None))
                muts.append(S("last_reported_ts", "plus_900", row["last_reported_ts"] + 900))
            muts.append(S("last_updated", "legacy_text", "2026-10-01 00:00:00.000000"))
            muts.append(S("last_updated_ts", "minus_0.25", lu - 0.25))
            muts.append(S("last_updated_ts", "plus_120", lu + 120))
            mid = row["metadata_id"]
            if row["old_state_id"] is not None:
                muts.append(S("old_state_id", "null", None))
                muts.append(S("old_state_id", "nonexistent", max_state + 20_000_000))
                same = con.execute("SELECT state_id FROM states WHERE metadata_id=? AND state=? AND state_id<? "
                                   "AND state_id<>? ORDER BY state_id DESC LIMIT 1",
                                   (mid, row["state"], key, row["old_state_id"])).fetchone()
                if same:
                    muts.append(S("old_state_id", "same_state_predecessor", same[0]))
            else:
                prev = con.execute("SELECT state_id FROM states WHERE metadata_id=? AND last_updated_ts<? "
                                   "ORDER BY last_updated_ts DESC LIMIT 1", (mid, lu)).fetchone()
                if prev:
                    muts.append(S("old_state_id", "previous_row_of_entity", prev[0]))
                muts.append(S("old_state_id", "nonexistent", max_state + 20_000_000))
            aid = row["attributes_id"]
            if aid is not None:
                muts.append(S("attributes_id", "null", None))
            alt = icon_attr[0] if icon_attr and icon_attr[0] != aid else con.execute(
                "SELECT attributes_id FROM state_attributes WHERE attributes_id<>? ORDER BY attributes_id DESC "
                "LIMIT 1", (aid or -1,)).fetchone()[0]
            muts.append(S("attributes_id", "other_attributes_row", alt))
            muts.append(S("attributes_id", "nonexistent", max_attr + 10_000_000))
            muts += common_ctx_variants("states", "state_id", key, row, lo, hi)
            om = con.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?", (other_ent[0],)).fetchone()[0]
            muts.append(S("metadata_id", "other_entity", om))
            muts.append(S("metadata_id", "nonexistent", max_meta + 100_000))
            # the referenced states_meta row
            muts.append(M("states_meta.metadata_id", "fresh_key", "states_meta", "metadata_id", mid, "metadata_id",
                          max_meta + 200_000 + mid))
            muts.append(M("states_meta.entity_id", "suffix", "states_meta", "metadata_id", mid, "entity_id",
                          ent + "_e8b"))
            # the referenced state_attributes row
            if aid is not None:
                sa = con.execute("SELECT hash, shared_attrs FROM state_attributes WHERE attributes_id=?",
                                 (aid,)).fetchone()
                A = lambda col, var, new: M("state_attributes." + col, var, "state_attributes", "attributes_id",
                                            aid, col, new)
                muts.append(A("attributes_id", "fresh_key", max_attr + 20_000_000 + aid))
                muts.append(A("hash", "plus_1", (sa[0] or 0) + 1))
                try:
                    d = json.loads(sa[1])
                except ValueError:
                    d = {}
                for var, upd in (("add_icon", {"icon": "mdi:e8b"}), ("add_unit", {"unit_of_measurement": "e8b"}),
                                 ("add_event_type", {"event_type": "e8b"}),
                                 ("friendly_name", {"friendly_name": "E8B renamed"})):
                    muts.append(A("shared_attrs", var, json.dumps({**d, **upd}, separators=(",", ":"))))
                muts.append(A("shared_attrs", "empty_object", "{}"))
        else:
            row = dict(zip(ecols, con.execute("SELECT * FROM events WHERE event_id=?", (t["key"],)).fetchone()))
            t["stored"] = {k: enc(v) for k, v in row.items()}
            key = t["key"]
            et = con.execute("SELECT event_type FROM event_types WHERE event_type_id=?",
                             (row["event_type_id"],)).fetchone()[0]
            t["event_type"] = et
            dom = {"automation_triggered": "automation", "homeassistant_start": "homeassistant"}.get(et)
            t["expect"] = {"domain": dom, "when": row["time_fired_ts"]} if dom else None
            E = lambda col, var, new: M("events." + col, var, "events", "event_id", key, col, new)
            muts.append(E("event_id", "fresh_key", max_event + 10_000_000 + key))
            # the processor treats two rows with equal row ids as one row (_rows_ids_match): give the event the id of
            # a state row of its own context, where that id is free in the events table
            same = con.execute("""SELECT state_id FROM states WHERE context_id_bin=? AND state_id NOT IN
                                  (SELECT event_id FROM events) ORDER BY last_updated_ts LIMIT 1""",
                               (row["context_id_bin"],)).fetchone()
            if same:
                muts.append(E("event_id", "equal_to_state_row_id_in_context", same[0]))
            muts.append(E("event_type", "legacy_text", et))
            ent = t["entity"] or "lock.front_door"
            muts.append(E("event_data", "legacy_json", json.dumps({"name": "E8B legacy", "entity_id": ent,
                                                                    "domain": "e8b", "service": "e8b"})))
            if row["data_id"] is not None:
                # compound: the legacy column is read only when the row has no event_data row
                muts.append(M("events.event_data", "legacy_json_with_data_id_null", "events", "event_id", key,
                              "event_data", json.dumps({"name": "E8B legacy", "entity_id": ent, "domain": "e8b",
                                                        "service": "e8b", "source": "e8b"}),
                              also=[("data_id", None)]))
            muts.append(E("origin", "legacy_text", "REMOTE"))
            muts.append(E("time_fired", "legacy_text", "2026-10-01 00:00:00.000000"))
            tf = row["time_fired_ts"]
            muts.append(E("time_fired_ts", "minus_0.25", tf - 0.25))
            muts.append(E("time_fired_ts", "plus_120", tf + 120))
            did = row["data_id"]
            if did is not None:
                muts.append(E("data_id", "null", None))
                alt = con.execute("""SELECT e.data_id FROM events e JOIN event_data d ON d.data_id=e.data_id
                                     WHERE e.event_type_id=? AND e.data_id<>? ORDER BY e.time_fired_ts DESC LIMIT 1""",
                                  (row["event_type_id"], did)).fetchone()
                if alt:
                    muts.append(E("data_id", "other_data_row_same_type", alt[0]))
                muts.append(E("data_id", "nonexistent", max_data + 10_000_000))
            muts += common_ctx_variants("events", "event_id", key, row, lo, hi)
            swap = {"automation_triggered": "call_service", "call_service": "automation_triggered",
                    "homeassistant_start": "homeassistant_stop"}[et]
            muts.append(E("event_type_id", "other_type", etype_id[swap]))
            muts.append(E("event_type_id", "nonexistent", max_et + 100_000))
            tid = row["event_type_id"]
            muts.append(M("event_types.event_type_id", "fresh_key", "event_types", "event_type_id", tid,
                          "event_type_id", max_et + 200_000 + tid))
            muts.append(M("event_types.event_type", "suffix", "event_types", "event_type_id", tid, "event_type",
                          et + "_e8b"))
            if did is not None:
                ed = con.execute("SELECT hash, shared_data FROM event_data WHERE data_id=?", (did,)).fetchone()
                D = lambda col, var, new: M("event_data." + col, var, "event_data", "data_id", did, col, new)
                muts.append(D("data_id", "fresh_key", max_data + 20_000_000 + did))
                muts.append(D("hash", "plus_1", (ed[0] or 0) + 1))
                try:
                    d = json.loads(ed[1])
                except ValueError:
                    d = {}
                if et == "automation_triggered":
                    variants = (("name", {"name": "E8B renamed"}), ("entity_id", {"entity_id": "automation.e8b"}),
                                ("source", {"source": "E8B source"}))
                else:
                    sd = dict(d.get("service_data") or {})
                    sd["entity_id"] = ["lock.back_door"]
                    variants = (("domain", {"domain": "e8b"}), ("service", {"service": "e8b"}),
                                ("service_data_entity", {"service_data": sd}))
                for var, upd in variants:
                    muts.append(D("shared_data", var, json.dumps({**d, **upd}, separators=(",", ":"))))
                muts.append(D("shared_data", "empty_object", "{}"))
        # drop no-op variants
        stored = t["stored"] if t["kind"] in ("state", "event") else {}
        t["mutations"] = [m for m in muts if not (m["table"] in ("states", "events") and m["col"] in stored
                                                  and stored[m["col"]] == m["new"])]
        t["n_mutations"] = len(t["mutations"])
    p = {"seed": SEED, "pristine_sha256": sha(PRISTINE), "copy_max_ts": tmax, "candidate_period": [p_lo, p_hi],
         "clean_period_start": clean_lo, "watermarks": wm, "half_window": HALF, "commit_margin": COMMIT_MARGIN,
         "user_context": user_ctx.hex(), "household_user": HOUSEHOLD_USER,
         "targets": sorted(targets, key=lambda x: x["id"])}
    con.close()
    os.makedirs(os.path.join(CFG, "e8b"), exist_ok=True)
    json.dump(p, open(os.path.join(CFG, "e8b", "plan.json"), "w"), indent=1)
    print(json.dumps({"targets": len(p["targets"]), "mutations": sum(t["n_mutations"] for t in p["targets"]),
                      "roles": sorted({t["role"] for t in p["targets"]})}, indent=1))


# ---------------------------------------------------------------------------------------------- container
CONFIG_YAML = """# Throwaway hub for E8 part B (renderer closure on a copy of the real deployment's recorder).
# Same core configuration as testbed/real/ha-config/configuration.yaml, without the experiment integrations and without
# MQTT; the recorder serves the copy, never purges or repacks it, and is disabled once the hub has started.
homeassistant:
  name: HomeProv Real
  latitude: 0
  longitude: 0
  elevation: 0
  unit_system: metric
  time_zone: UTC

http:
  server_port: 8123

recorder:
  db_url: sqlite:////e8bdb/work.db
  commit_interval: 1
  purge_keep_days: 30
  auto_purge: false
  auto_repack: false

logbook:
history:

automation: !include automations.yaml

logger:
  default: warning

e8b_closure:
"""


def up():
    import shutil
    if sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split().count(CONTAINER):
        raise SystemExit("%s exists" % CONTAINER)
    cc = os.path.join(CFG, "custom_components")
    os.makedirs(os.path.join(cc, "e8b_closure"), exist_ok=True)
    os.makedirs(os.path.join(cc, "homeprov_e4"), exist_ok=True)
    shutil.copy(os.path.abspath(__file__), os.path.join(cc, "e8b_closure", "__init__.py"))
    json.dump({"domain": "e8b_closure", "name": "E8B closure", "version": "1.0.0", "documentation": "",
               "codeowners": [], "dependencies": ["recorder", "logbook"], "iot_class": "local_polling",
               "requirements": []}, open(os.path.join(cc, "e8b_closure", "manifest.json"), "w"))
    e4 = os.path.join(REPO, "testbed", "real", "ha-config", "custom_components", "homeprov_e4")
    for f in ("__init__.py", "manifest.json"):
        shutil.copy(os.path.join(e4, f), os.path.join(cc, "homeprov_e4", f))
    shutil.copy(os.path.join(REPO, "testbed", "real", "ha-config", "automations.yaml"),
                os.path.join(CFG, "automations.yaml"))
    # the blueprint the automations use, as the release ships it (a hub populates it into its config on first run)
    bp = os.path.join(CFG, "blueprints", "automation", "homeassistant")
    os.makedirs(bp, exist_ok=True)
    r = sh(["docker", "run", "--rm", "--name", "e8b-prep", "--network", "none", "--entrypoint", "cat", IMAGE,
            "/usr/src/homeassistant/homeassistant/components/automation/blueprints/motion_light.yaml"])
    open(os.path.join(bp, "motion_light.yaml"), "w").write(r.stdout)
    shutil.copy(os.path.join(REPO, "monitor", "monitor.py"), os.path.join(CFG, "e8b", "monitor_snapshot.py"))
    open(os.path.join(CFG, "configuration.yaml"), "w").write(CONFIG_YAML)
    for f in ("ready.json", "cmd.json"):
        if os.path.exists(os.path.join(CFG, "e8b", f)):
            os.remove(os.path.join(CFG, "e8b", f))
    sh(["docker", "volume", "create", VOLUME])
    r = sh(["docker", "run", "--rm", "--name", "e8b-prep", "--network", "none", "--entrypoint", "sh",
            "-v", "%s:/e8bdb" % VOLUME, "-v", "%s:/src:ro" % DATA, IMAGE, "-c",
            "cp /src/pristine.db /e8bdb/work.db && sha256sum /e8bdb/work.db"])
    if r.returncode or sha(PRISTINE) not in r.stdout:
        raise SystemExit("copy into volume failed: %s %s" % (r.stdout, r.stderr))
    r = sh(["docker", "run", "-d", "--name", CONTAINER, "--network", "none", "-e", "TZ=UTC",
            "-v", "%s:/config" % CFG, "-v", "%s:/e8bdb" % VOLUME, IMAGE])
    if r.returncode:
        raise SystemExit(r.stderr)
    t0 = time.time()
    while not os.path.exists(os.path.join(CFG, "e8b", "ready.json")):
        if time.time() - t0 > 600:
            raise SystemExit("hub not ready after 600 s; docker logs %s" % CONTAINER)
        time.sleep(3)
    print("ready", json.load(open(os.path.join(CFG, "e8b", "ready.json"))), round(time.time() - t0, 1), "s")


def send(op, tag, timeout=7200, **kw):
    ack = os.path.join(CFG, "e8b", "ack_%s.json" % tag)
    if os.path.exists(ack):
        os.remove(ack)
    tmp = os.path.join(CFG, "e8b", "cmd.tmp")
    json.dump({"op": op, "tag": tag, **kw}, open(tmp, "w"))
    os.replace(tmp, os.path.join(CFG, "e8b", "cmd.json"))
    t0 = time.time()
    while not os.path.exists(ack):
        if time.time() - t0 > timeout:
            raise SystemExit("timeout waiting for %s" % tag)
        time.sleep(2)
    return json.load(open(ack))["result"]


def run():
    p = json.load(open(os.path.join(CFG, "e8b", "plan.json")))
    info = send("info", "info")
    json.dump(info, open(os.path.join(CFG, "e8b", "out_info.json"), "w"), indent=1)
    print("info", {k: info[k] for k in ("ha_version", "frontend", "recorder_enabled", "external_events")})
    if info.get("recorder_enabled"):
        raise SystemExit("recorder still enabled")
    wm = p["watermarks"]
    pre = send("digest", "digest_pre", watermarks=wm)
    pristine = table_digest(PRISTINE, wm)
    same = {t: pre[t]["sha256"] == pristine[t]["sha256"] for t in TABLES}
    json.dump({"pristine": pristine, "work_before": pre, "equal": same},
              open(os.path.join(CFG, "e8b", "out_digest_pre.json"), "w"), indent=1)
    print("pre-run digest equal to pristine:", same)
    if not all(same.values()):
        raise SystemExit("the hub changed the copy before the run")
    st = send("static", "static", target=next(t["id"] for t in p["targets"] if t["entity"]))
    json.dump(st, open(os.path.join(CFG, "e8b", "out_static.json"), "w"), indent=1)
    t0 = time.time()
    r = send("run", "run", timeout=6 * 3600)
    print("run", r, round(time.time() - t0, 1), "s")
    post = send("digest", "digest_post", watermarks=wm)
    json.dump({"work_after": post, "equal": {t: post[t]["sha256"] == pristine[t]["sha256"] for t in TABLES}},
              open(os.path.join(CFG, "e8b", "out_digest_post.json"), "w"), indent=1)
    print("post-run digest equal:", {t: post[t]["sha256"] == pristine[t]["sha256"] for t in TABLES})
    replay()


def replay():
    p = json.load(open(os.path.join(CFG, "e8b", "plan.json")))
    out = {}
    for live in (False, True):
        out["live_write" if live else "frozen"] = send("replay", "replay_%d" % live, end_ts=p["copy_max_ts"],
                                                      live_write=live)
        print("replay live_write=%s aborted=%s" % (live, out["live_write" if live else "frozen"].get("aborted")))
    post = send("digest", "digest_post_replay", watermarks=p["watermarks"])
    pristine = table_digest(PRISTINE, p["watermarks"])
    out["digest_after_replay_equal"] = {t: post[t]["sha256"] == pristine[t]["sha256"] for t in TABLES}
    json.dump(out, open(os.path.join(CFG, "e8b", "out_replay.json"), "w"), indent=1, default=str)


def down():
    sh(["docker", "rm", "-f", CONTAINER])
    sh(["docker", "rm", "-f", "e8b-prep"])
    sh(["docker", "volume", "rm", VOLUME])
    for c in (UI_CONTAINER, UI_PROXY):
        sh(["docker", "rm", "-f", c])
    sh(["docker", "volume", "rm", UI_VOLUME])
    sh(["docker", "network", "rm", UI_NET])


# ---------------------------------------------------------------------------------------------- browser oracle
# The earlier stages' browser oracle (exp/sp2027/r1_render.py: Playwright + Chromium, a logged-in viewer, the Activity
# view's entries read from the DOM) reused on a second throwaway hub that serves another working copy. The hub sits on
# an internal Docker network with no route out; a forwarder on the same image publishes its port on 127.0.0.1 only.
# The deployment's own accounts are not in this hub, so the user-column steps use this hub's owner account; the
# display rule is evaluated with that name map for the comparison.
UI_CONTAINER, UI_PROXY, UI_VOLUME, UI_NET = "e8b-hass-ui", "e8b-ui-proxy", "e8b-db-ui", "e8b-ui-net"
UI_PORT = 18493
CFG_UI = os.path.join(DATA, "config_ui")
PROXY_PY = """
import asyncio
async def pipe(r, w):
    try:
        while True:
            b = await r.read(65536)
            if not b:
                break
            w.write(b)
            await w.drain()
    finally:
        w.close()
async def handle(cr, cw):
    ur, uw = await asyncio.open_connection('e8b-hass-ui', 8123)
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
async def main():
    srv = await asyncio.start_server(handle, '0.0.0.0', 8123)
    async with srv:
        await srv.serve_forever()
asyncio.run(main())
"""


def ui_send(op, tag, timeout=600, **kw):
    ack = os.path.join(CFG_UI, "e8b", "ack_%s.json" % tag)
    if os.path.exists(ack):
        os.remove(ack)
    tmp = os.path.join(CFG_UI, "e8b", "cmd.tmp")
    json.dump({"op": op, "tag": tag, **kw}, open(tmp, "w"))
    os.replace(tmp, os.path.join(CFG_UI, "e8b", "cmd.json"))
    t0 = time.time()
    while not os.path.exists(ack):
        if time.time() - t0 > timeout:
            raise SystemExit("timeout waiting for %s" % tag)
        time.sleep(0.5)
    return json.load(open(ack))["result"]


def ui_up():
    import shutil
    if os.path.exists(CFG_UI):
        shutil.rmtree(CFG_UI)
    os.makedirs(os.path.join(CFG_UI, "e8b"))
    for f in ("configuration.yaml", "automations.yaml"):
        shutil.copy(os.path.join(CFG, f), os.path.join(CFG_UI, f))
    shutil.copytree(os.path.join(CFG, "blueprints"), os.path.join(CFG_UI, "blueprints"))
    shutil.copytree(os.path.join(CFG, "custom_components"), os.path.join(CFG_UI, "custom_components"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(os.path.abspath(__file__), os.path.join(CFG_UI, "custom_components", "e8b_closure", "__init__.py"))
    shutil.copy(os.path.join(CFG, "e8b", "plan.json"), os.path.join(CFG_UI, "e8b", "plan.json"))
    shutil.copy(os.path.join(CFG, "e8b", "monitor_snapshot.py"), os.path.join(CFG_UI, "e8b", "monitor_snapshot.py"))
    sh(["docker", "volume", "create", UI_VOLUME])
    r = sh(["docker", "run", "--rm", "--name", "e8b-prep", "--network", "none", "--entrypoint", "sh",
            "-v", "%s:/e8bdb" % UI_VOLUME, "-v", "%s:/src:ro" % DATA, IMAGE, "-c",
            "cp /src/pristine.db /e8bdb/work.db && sha256sum /e8bdb/work.db"])
    if r.returncode or sha(PRISTINE) not in r.stdout:
        raise SystemExit("copy failed %s %s" % (r.stdout, r.stderr))
    sh(["docker", "network", "create", "--internal", UI_NET])
    r = sh(["docker", "run", "-d", "--name", UI_CONTAINER, "--network", UI_NET, "-e", "TZ=UTC",
            "-v", "%s:/config" % CFG_UI, "-v", "%s:/e8bdb" % UI_VOLUME, IMAGE])
    if r.returncode:
        raise SystemExit(r.stderr)
    r = sh(["docker", "run", "-d", "--name", UI_PROXY, "-p", "127.0.0.1:%d:8123" % UI_PORT, "--entrypoint",
            "python3", IMAGE, "-c", PROXY_PY])
    if r.returncode:
        raise SystemExit(r.stderr)
    sh(["docker", "network", "connect", UI_NET, UI_PROXY])
    t0 = time.time()
    while not os.path.exists(os.path.join(CFG_UI, "e8b", "ready.json")):
        if time.time() - t0 > 600:
            raise SystemExit("ui hub not ready")
        time.sleep(2)


def ui_onboard(base, password):
    import requests
    client = base + "/"
    for _ in range(60):
        try:
            if requests.get(base + "/api/onboarding", timeout=5).ok:
                break
        except Exception:                                         # noqa: BLE001
            time.sleep(2)
    r = requests.post(base + "/api/onboarding/users", json={"client_id": client, "name": "E8B Owner",
                                                            "username": "e8bowner", "password": password,
                                                            "language": "en"}, timeout=30)
    r.raise_for_status()
    code = r.json()["auth_code"]
    tok = requests.post(base + "/auth/token", data={"grant_type": "authorization_code", "code": code,
                                                    "client_id": client}, timeout=30).json()
    H = {"Authorization": "Bearer " + tok["access_token"]}
    requests.post(base + "/api/onboarding/core_config", headers=H, json={}, timeout=30)
    requests.post(base + "/api/onboarding/analytics", headers=H, json={}, timeout=30)
    requests.post(base + "/api/onboarding/integration", headers=H, json={"client_id": client,
                                                                         "redirect_uri": client}, timeout=30)
    for _ in range(30):
        try:
            a = json.load(open(os.path.join(CFG_UI, ".storage", "auth")))
            u = [x for x in a["data"]["users"] if x.get("name") == "E8B Owner"]
            if u:
                return u[0]["id"]
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    raise SystemExit("owner id not found")


def ui():
    """Browser oracle on a subset of mutations: Activity view (filtered to the target's entity) for the target's
    window, as the owner (an admin), before each mutation, with it applied, and after the restore."""
    sys.path.insert(0, os.path.join(REPO, "exp", "sp2027"))
    import r1_render as R                                       # noqa: PLC0415
    from playwright.sync_api import sync_playwright             # noqa: PLC0415
    from datetime import datetime, timezone                     # noqa: PLC0415
    from urllib.parse import quote                              # noqa: PLC0415
    p = json.load(open(os.path.join(CFG, "e8b", "plan.json")))
    tg = {t["id"]: t for t in p["targets"]}
    base = "http://127.0.0.1:%d" % UI_PORT
    pw_ = "e8b-" + os.urandom(6).hex()
    ui_up()
    owner = ui_onboard(base, pw_)
    shots = os.path.join(DATA, "ui_screens")
    os.makedirs(shots, exist_ok=True)
    rnd = os.urandom(16).hex()

    def find(t, field, variant):
        return next(m for m in t["mutations"] if m["field"] == field and m["variant"] == variant)

    def own(t, field):
        return {"field": field, "variant": "this_hub_owner", "table": "states", "key_col": "state_id",
                "key": t["key"], "col": field.split(".")[1], "new": {"t": "blob", "v": owner}}

    def rndm(t, field):
        return {"field": field, "variant": "random", "table": "states", "key_col": "state_id", "key": t["key"],
                "col": field.split(".")[1], "new": {"t": "blob", "v": rnd}}
    lock = next(t for t in p["targets"] if t["role"] == "lock_unlock_in_service_call_context")
    light = next(t for t in p["targets"] if t["role"] == "light_on_automation")
    steps = [(lock, own(lock, "states.context_user_id_bin")), (lock, rndm(lock, "states.context_user_id_bin")),
             (lock, find(lock, "states.context_id_bin", "random")),
             (lock, find(lock, "state_attributes.shared_attrs", "add_icon")),
             (light, own(light, "states.context_user_id_bin")),
             (light, find(light, "states.context_id_bin", "random")),
             (light, find(light, "states.context_parent_id_bin", "random")),
             (light, find(light, "states.last_changed_ts", "minus_900"))]
    names = {**PERSONS, owner: "E8B Owner"}
    out = {"owner_user_id": owner, "viewer": "owner (admin)", "steps": []}

    # a narrow window (+-15 s) so the target's entry is among the entries the Activity view's virtualized list puts
    # in the DOM; the processor-side display rule is evaluated on the same window
    nw = lambda t: [t["ts"] - 15.0, t["ts"] + 15.0]

    def rule(t):
        r = ui_send("render_rows", "rr", window=nw(t), form="entity", entity=t["entity"])
        rows = r["rows"] or []
        i = _find_target(rows, t["expect"])
        return (display_rule(rows[i], names) if i is not None else "NOT RENDERED"), r["sha256"]

    with sync_playwright() as pwp:
        br, ctx = R.login_context(pwp, base, "e8bowner", pw_)

        def view(t, label):
            s0 = datetime.fromtimestamp(nw(t)[0], timezone.utc).isoformat()
            s1 = datetime.fromtimestamp(nw(t)[1], timezone.utc).isoformat()
            page = ctx.new_page()
            page.goto(base + "/logbook?entity_id=%s&start_date=%s&end_date=%s" % (t["entity"], quote(s0), quote(s1)),
                      wait_until="load", timeout=60000)
            ents = []
            for _ in range(15):
                page.wait_for_timeout(1500)
                ents = R.extract_entries(page)
                if ents:
                    break
            page.wait_for_timeout(2000)
            ents = R.extract_entries(page)
            shot = os.path.join(shots, "%s_%s.png" % (t["id"], label))
            page.screenshot(path=shot, full_page=True)
            page.close()
            return {"entries": ents, "screenshot": os.path.relpath(shot, DATA), "screenshot_sha256": sha(shot)}
        for t, m in steps:
            b = view(t, "base_%s_%s" % (m["field"].split(".")[1], m["variant"]))
            rb = rule(t)
            ui_send("apply", "apply", m=m)
            try:
                a = view(t, "mut_%s_%s" % (m["field"].split(".")[1], m["variant"]))
                ra = rule(t)
            finally:
                rs = ui_send("restore", "restore")
            r_ = view(t, "rest_%s_%s" % (m["field"].split(".")[1], m["variant"]))
            out["steps"].append({"target": t["id"], "role": t["role"], "field": m["field"], "variant": m["variant"],
                                 "browser_before": b, "browser_mutated": a, "browser_restored": r_,
                                 "rule_before": rb[0], "rule_mutated": ra[0],
                                 "browser_changed": a["entries"] != b["entries"],
                                 "browser_restored_equal": r_["entries"] == b["entries"],
                                 "rule_changed": ra[0] != rb[0], "db_restored": rs["db_equal"]})
            print(t["id"], m["field"], m["variant"], "browser_changed", a["entries"] != b["entries"],
                  "rule", rb[0], "->", ra[0], "restored", r_["entries"] == b["entries"], rs)
        br.close()
    json.dump(out, open(os.path.join(CFG, "e8b", "out_ui.json"), "w"), indent=1)


# ---------------------------------------------------------------------------------------------- summary
PAPER14 = {   # Table 9 (tables/tab_appc.tex): the fourteen renderer-closure fields; key columns stand for the value
    # they reference ("For the key columns metadata_id, event_type_id and data_id the monitor commits the referenced
    # entity id, event type and shared event data").
    "states.context_id_bin": ["states.context_id_bin"],
    "states.context_parent_id_bin": ["states.context_parent_id_bin"],
    "states.context_user_id_bin": ["states.context_user_id_bin"],
    "states.state": ["states.state"],
    "states.metadata_id": ["states.metadata_id", "states_meta.entity_id"],
    "states.old_state_id": ["states.old_state_id"],
    "states.last_updated_ts": ["states.last_updated_ts"],
    "states.last_changed_ts": ["states.last_changed_ts"],
    "events.context_id_bin": ["events.context_id_bin"],
    "events.context_parent_id_bin": ["events.context_parent_id_bin"],
    "events.context_user_id_bin": ["events.context_user_id_bin"],
    "events.event_type_id": ["events.event_type_id", "event_types.event_type"],
    "events.data_id": ["events.data_id", "event_data.shared_data"],
    "events.time_fired_ts": ["events.time_fired_ts"],
}
ROW_KEYS = {"states.state_id", "events.event_id", "states_meta.metadata_id", "event_types.event_type_id",
            "event_data.data_id", "state_attributes.attributes_id"}


def stable_columns(pristine_cols):
    """Columns the stable-columns scheme commits (monitor.load_stable: every stored column of states except
    last_reported_ts, every stored column of events, and the joined entity_id, shared_attrs, event_type and
    shared_data)."""
    s = {"states.%s" % c for c in pristine_cols["states"] if c != "last_reported_ts"}
    s |= {"events.%s" % c for c in pristine_cols["events"]}
    s |= {"states_meta.entity_id", "state_attributes.shared_attrs", "event_types.event_type",
          "event_data.shared_data"}
    return s


def summarize():
    import collections
    base = os.path.join(CFG, "e8b")
    p = json.load(open(os.path.join(base, "plan.json")))
    raw = [json.loads(l) for l in open(os.path.join(base, "out", "raw.jsonl"))]
    tmeta = {t["id"]: t for t in p["targets"]}
    acq = json.load(open(os.path.join(DATA, "acquire.json")))
    info = json.load(open(os.path.join(base, "out_info.json")))
    dpre = json.load(open(os.path.join(base, "out_digest_pre.json")))
    dpost = json.load(open(os.path.join(base, "out_digest_post.json")))
    static = json.load(open(os.path.join(base, "out_static.json")))
    rep = json.load(open(os.path.join(base, "out_replay.json")))
    cols = {t: dpre["pristine"][t]["columns"] for t in TABLES}
    all_fields = sorted({"%s.%s" % (t, c) for t in TABLES for c in cols[t]})

    per = collections.OrderedDict((f, {"rows": set(), "mutations": 0, "applied": 0, "render_changed": 0,
                                       "by_form": collections.Counter(), "cause_changed": 0,
                                       "target_cause_changed": 0, "rows_vanished_or_appeared": 0,
                                       "decoration_only": 0, "order_only": 0, "error": 0,
                                       "display_changed_admin": 0, "display_changed_nonadmin": 0,
                                       "closure_commit_changed_when_render_changed": 0,
                                       "stable_commit_changed_when_render_changed": 0,
                                       "row_commit_changed_when_render_changed": 0,
                                       "roles_render_changed": set(), "variants_render_changed": set(),
                                       "restore_ok": 0, "examples": []}) for f in all_fields)
    controls = {"determinism_equal": 0, "determinism_total": 0, "pos_ctrl_rendered_targets": 0,
                "pos_ctrl_render_changed": 0, "pos_ctrl_failures": [], "pos_ctrl_household_rendered": 0,
                "pos_ctrl_household_display_admin_changed": 0}
    restores = {"mutations": 0, "db_equal": 0, "render_equal": 0, "commit_equal": 0, "failures": []}
    roles = collections.Counter()
    for t in raw:
        tm = tmeta[t["target"]]
        roles[t["role"]] += 1
        for f, ok in t["determinism_equal"].items():
            controls["determinism_total"] += 1
            controls["determinism_equal"] += bool(ok)
        rendered = any(v["target_rendered"] for v in t["baseline"].values())
        for m in t["mutations"]:
            d = per[m["field"]]
            d["rows"].add((m["table"], m["key"]))
            d["mutations"] += 1
            if "apply_error" in m:
                continue
            d["applied"] += 1
            rr = m["render"]
            ch = [f for f, v in rr.items() if v["changed"]]
            restores["mutations"] += 1
            rs = m["restore"]
            ok = rs["db_equal"] and all(rs["render_equal"].values()) and rs["commit_equal"]
            restores["db_equal"] += rs["db_equal"]
            restores["render_equal"] += all(rs["render_equal"].values())
            restores["commit_equal"] += rs["commit_equal"]
            d["restore_ok"] += ok
            if not ok:
                restores["failures"].append({"target": t["target"], "field": m["field"], "variant": m["variant"],
                                             "restore": rs})
            if m["field"].endswith("context_user_id_bin") and m["variant"] == "random" and rendered:
                controls["pos_ctrl_rendered_targets"] += 1
                if ch:
                    controls["pos_ctrl_render_changed"] += 1
                else:
                    controls["pos_ctrl_failures"].append(t["target"])
            if m["field"].endswith("context_user_id_bin") and m["variant"] == "household_user" and rendered:
                controls["pos_ctrl_household_rendered"] += 1
                controls["pos_ctrl_household_display_admin_changed"] += any(
                    v.get("display_changed_admin") for v in rr.values() if v["changed"])
            if not ch:
                continue
            d["render_changed"] += 1
            for f in ch:
                d["by_form"][f] += 1
            d["roles_render_changed"].add(t["role"])
            d["variants_render_changed"].add(m["variant"])
            vals = [rr[f] for f in ch]
            if any(v.get("error") for v in vals):
                d["error"] += 1
            if any(v.get("cause_changed") for v in vals):
                d["cause_changed"] += 1
            tc = [v.get("target") or {} for v in vals]
            if any(x.get("rendered_before") and (x.get("vanished") or x.get("cause_before") != x.get("cause_after"))
                   for x in tc) or any(x.get("appeared") for x in tc):
                d["target_cause_changed"] += 1
            if any(v.get("vanished") or v.get("appeared") for v in vals):
                d["rows_vanished_or_appeared"] += 1
            if all(not v.get("error") and not v.get("vanished") and not v.get("appeared") and not v.get("cause_changed")
                   and v.get("decoration_changed") for v in vals):
                d["decoration_only"] += 1
            if all(v.get("order_only") for v in vals):
                d["order_only"] += 1
            if any(v.get("display_changed_admin") for v in vals):
                d["display_changed_admin"] += 1
            if any(v.get("display_changed_nonadmin") for v in vals):
                d["display_changed_nonadmin"] += 1
            for s in ("closure", "stable", "row"):
                d["%s_commit_changed_when_render_changed" % s] += m["commit_changed"][s]
            if len(d["examples"]) < 2:
                f0 = ch[0]
                d["examples"].append({"target": t["target"], "role": t["role"], "variant": m["variant"], "form": f0,
                                      "effect": {k: v for k, v in rr[f0].items() if k != "other_diff"},
                                      "other_diff": rr[f0].get("other_diff")})
    # role-stratified hit frequency: per field and row role, targets on which some variant changed the render (and the
    # displayed cause of some row), out of the targets of that role on which the field was mutated
    by_role = collections.defaultdict(lambda: collections.defaultdict(lambda: [set(), set(), set()]))
    for t in raw:
        for m in t["mutations"]:
            if "apply_error" in m:
                continue
            e = by_role[m["field"]][t["role"]]
            e[2].add(t["target"])
            if any(v["changed"] for v in m["render"].values()):
                e[0].add(t["target"])
            if any(v.get("cause_changed") for v in m["render"].values() if v["changed"]):
                e[1].add(t["target"])
    per_field_by_role = {f: {r: {"targets_render_changed": len(e[0]), "targets_cause_changed": len(e[1]),
                                 "targets_mutated": len(e[2])} for r, e in sorted(rs.items())}
                         for f, rs in sorted(by_role.items())}
    per_field = {}
    for f, d in per.items():
        if not d["mutations"]:
            continue
        per_field[f] = {**{k: v for k, v in d.items() if k not in ("rows", "by_form", "roles_render_changed",
                                                                    "variants_render_changed")},
                        "rows_mutated": len(d["rows"]), "by_form": dict(d["by_form"]),
                        "roles_render_changed": sorted(d["roles_render_changed"]),
                        "variants_render_changed": sorted(d["variants_render_changed"])}
    # provenance of each target row: the event types in its context, and the experiment run (exp/out/*_t_start and
    # *_t_end) whose period contains it
    import glob
    runs = []
    for f in glob.glob(os.path.join(OUT, "*_t_start")):
        e = f[:-len("_t_start")] + "_t_end"
        if os.path.exists(e):
            runs.append((float(open(f).read().split()[0]), float(open(e).read().split()[0]),
                         os.path.basename(f)[:-len("_t_start")]))
    pc = sqlite3.connect("file:%s?mode=ro" % PRISTINE, uri=True)
    provenance = {}
    for tid, t in tmeta.items():
        cb = t["stored"]["context_id_bin"]
        ctx = bytes.fromhex(cb["v"]) if cb["t"] == "blob" else None
        evs = [r[0] for r in pc.execute("SELECT et.event_type FROM events e JOIN event_types et ON "
                                        "et.event_type_id=e.event_type_id WHERE e.context_id_bin=? "
                                        "ORDER BY e.time_fired_ts", (ctx,))] if ctx else []
        provenance[tid] = {"context_event_types": evs,
                           "during_run": [n for a, b, n in runs if a <= t["ts"] <= b]}
    pc.close()
    measured = sorted(f for f, v in per_field.items() if v["render_changed"])
    cause = sorted(f for f, v in per_field.items() if v["cause_changed"])
    target_cause = sorted(f for f, v in per_field.items() if v["target_cause_changed"])
    visible = sorted(f for f, v in per_field.items() if v["rows_vanished_or_appeared"])
    deco_only = sorted(f for f, v in per_field.items() if v["render_changed"] and v["render_changed"] ==
                       v["decoration_only"])
    disp_a = sorted(f for f, v in per_field.items() if v["display_changed_admin"])
    disp_n = sorted(f for f, v in per_field.items() if v["display_changed_nonadmin"])
    unread = sorted(f for f, v in per_field.items() if v["applied"] and not v["render_changed"])
    paper_phys = {x for v in PAPER14.values() for x in v}
    stable = stable_columns(cols)
    cause_or_visible = sorted(set(cause) | set(visible) | set(target_cause))
    comparison = {
        "paper14_logical_fields_hit": {k: sorted(set(v) & set(measured)) for k, v in PAPER14.items()},
        "paper14_fields_with_no_render_change": sorted(k for k, v in PAPER14.items() if not set(v) & set(measured)),
        "measured_outside_paper14_and_row_keys": sorted(set(measured) - paper_phys - ROW_KEYS),
        "measured_row_keys": sorted(set(measured) & ROW_KEYS),
        "cause_or_row_set_outside_paper14_and_row_keys": sorted(set(cause_or_visible) - paper_phys - ROW_KEYS),
        "stable_columns": sorted(stable),
        "measured_not_committed_by_stable_by_column": sorted(set(measured) - stable - ROW_KEYS),
        "render_changes_not_detected": {s: sum(v["render_changed"] - v["%s_commit_changed_when_render_changed" % s]
                                               for v in per_field.values()) for s in ("closure", "stable", "row")},
        "render_changes_not_detected_by_field": {s: {f: v["render_changed"] - v["%s_commit_changed_when_render_changed"
                                                                                % s]
                                                     for f, v in per_field.items()
                                                     if v["render_changed"] - v["%s_commit_changed_when_render_changed"
                                                                                % s]}
                                                 for s in ("closure", "stable", "row")},
        "static_read_set": static["union"],
        "static_not_measured": sorted(set(static["union"]) - set(measured)),
        "measured_not_static": sorted(set(measured) - set(static["union"])),
    }
    summary = {
        "targets": len(raw), "roles": dict(roles),
        "target_rows": {"states": sum(1 for t in raw if tmeta[t["target"]]["kind"] == "state"),
                        "events": sum(1 for t in raw if tmeta[t["target"]]["kind"] == "event")},
        "targets_rendered_in_baseline": sum(1 for t in raw if any(v["target_rendered"] for v in t["baseline"].values())),
        "fields_mutated": len(per_field), "mutations": sum(v["mutations"] for v in per_field.values()),
        "mutations_applied": sum(v["applied"] for v in per_field.values()),
        "mutations_render_changed": sum(v["render_changed"] for v in per_field.values()),
        "closure_render": measured, "n_closure_render": len(measured),
        "closure_cause": cause, "closure_target_cause": target_cause, "closure_row_set": visible,
        "closure_decoration_only": deco_only, "display_rule_admin": disp_a, "display_rule_nonadmin": disp_n,
        "fields_never_changed_render": unread, "controls": controls, "restores": restores,
        "comparison": comparison,
    }
    result = {
        "experiment": "E8 part B: renderer closure of Home Assistant 2026.7.4 on a copy of the real deployment's "
                      "recorder",
        "what": __doc__.split("\n\n")[1].replace("\n", " ") + " " + __doc__.split("\n\n")[2].replace("\n", " "),
        "inputs": {"recorder_copy": {**acq, "path": PRISTINE, "bytes": os.path.getsize(PRISTINE)},
                   "plan_sha256": sha(os.path.join(base, "plan.json")),
                   "monitor_snapshot_sha256": sha(os.path.join(base, "monitor_snapshot.py")),
                   "homeprov_e4_sha256": sha(os.path.join(CFG, "custom_components", "homeprov_e4", "__init__.py")),
                   "automations_sha256": sha(os.path.join(CFG, "automations.yaml")),
                   "configuration_yaml": CONFIG_YAML, "display_rule_source": "exp/out/e_ps_render_reconciliation.json "
                   "(frontend_display; accounts_on_hub; person_entities: none)",
                   "accounts": ACCOUNTS, "persons": PERSONS},
        "hub": {"container": CONTAINER, "image": IMAGE,
                "image_id": sh(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"]).stdout.strip(),
                "repo_digests": sh(["docker", "image", "inspect", IMAGE, "--format",
                                    "{{json .RepoDigests}}"]).stdout.strip(),
                "hpr_hass_image_id": sh(["docker", "inspect", "hpr-hass", "--format", "{{.Image}}"]).stdout.strip(),
                **{k: info[k] for k in ("ha_version", "frontend", "sqlalchemy", "sqlite", "recorder_enabled",
                                        "external_events")}},
        "copy_integrity": {"pre_run_equal_to_pristine": dpre["equal"], "post_run_equal_to_pristine": dpost["equal"],
                           "post_replay_equal_to_pristine": rep["digest_after_replay_equal"],
                           "pristine_digest": dpre["pristine"], "hub_rows_above_watermark": {
                               t: dpost["work_after"][t]["rows_above_watermark"] for t in ("states", "events")}},
        "forms": {"activity": "EventProcessor(event types for no filter, entity_ids=None, timestamp=True, "
                              "include_entity_name=False): the Activity panel's websocket request",
                  "entity": "EventProcessor(event types for the entity, entity_ids=[entity], timestamp=True, "
                            "include_entity_name=False): the entity's own logbook (websocket)",
                  "rest_entity": "EventProcessor(..., entity_ids=[entity], timestamp=False, include_entity_name=True):"
                                 " the REST form, as the earlier E4 harness rendered"},
        "summary": summary,
        "per_field": per_field,
        "per_field_by_role": per_field_by_role,
        "static": static,
        "replay_of_earlier_harness": rep,
        "browser_oracle": json.load(open(os.path.join(base, "out_ui.json"))) if os.path.exists(
            os.path.join(base, "out_ui.json")) else None,
        "plan": {k: v for k, v in p.items() if k != "targets"},
        "targets": [{**{k: v for k, v in tmeta[t["target"]].items() if k not in ("mutations",)},
                     "provenance": provenance[t["target"]],
                     "baseline": t["baseline"], "determinism_equal": t["determinism_equal"],
                     "baseline_commit": t["baseline_commit"], "seconds": t["seconds"]} for t in raw],
        "mutations": [{"target": t["target"], **m} for t in raw for m in t["mutations"]],
        "script_sha256": sha(os.path.abspath(__file__)),
        "generated_at": utc(time.time()),
    }
    path = os.path.join(OUT, "e8_closure_real.json")
    with open(path, "w") as fh:
        json.dump(result, fh, indent=1, default=str)
    print(json.dumps({k: summary[k] for k in ("targets", "mutations", "mutations_render_changed", "n_closure_render",
                                              "closure_render", "closure_cause", "controls", "restores")},
                     indent=1, default=str)[:6000])
    print(json.dumps(comparison, indent=1)[:4000])
    print("->", path, sha(path))


if __name__ == "__main__":
    a = sys.argv[1:] or ["help"]
    {"acquire": acquire, "plan": plan, "up": up, "run": run, "replay": replay, "summarize": summarize,
     "down": down, "ui": ui}.get(a[0], lambda: print(__doc__))()
