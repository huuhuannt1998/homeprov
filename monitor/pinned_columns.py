"""Verifier and monitor version 2 (round 17, review r6): the COMMITTED COLUMN LIST of the stable-columns scheme.

WHY. The stable-columns scheme (monitor.py, STABLE-COLUMNS SCHEME) commits every stored column of a states or events row
that PRAGMA table_info lists, except STABLE_EXCLUDE, plus the joined values. monitor.py and the E10 verifier
(exp/stages/e7_verify.py) both read that list from the recorder at hand, so a verifier that recomputes a root sealed
before a migration added a column recomputes it over the CURRENT list, gets a different field tuple for every row, and
reports almost every sealed second as a violation (E10 offline, exp/out/e10_main_migration_offline.json: 413,161 of
419,143 checked seconds with an added states column; 115,108 without it). Version 2 fixes the list a segment is
recomputed over to the list in force when the segment was sealed.

WHAT THIS MODULE IS. The one implementation, shared by monitor_v2.py (which seals with it) and exp/stages/verify_v2.py
(which recomputes with it), of monitor.py's load_stable() and of the stable branch of monitor.py's keylog_rows() with
the column list passed in instead of read from PRAGMA table_info. With the current list they return exactly what
monitor.py's functions return (monitor/test_verify_v2.py asserts it on synthetic recorders). Every function takes the
monitor module M (monitor.py loaded as a module, or monitor_v2's namespace) for its helpers, so no hashing, encoding or
SQL guard of monitor.py is re-implemented here; monitor.py itself is registered code (E9-E12) and is not edited.

A COLUMN OF THE PINNED LIST THAT THE TABLE NO LONGER HAS (a dropped column). Its value cannot be read, so the field tuple
names it DROPPED + name with the value NULL: such a tuple never equals the sealed one (the name is a different typed
TEXT field, the encoding is a prefix code), so every root over a row of that table fails, exactly as it fails today
when the current list lacks a sealed column. Version 2 does not excuse a dropped column (no declaration is implemented;
whether a declaration may excuse one changes what the guarantee means and is the PI's decision).

A COLUMN THE TABLE HAS THAT THE PINNED LIST LACKS (an added column) is not read for that segment: its values were never
committed for rows sealed before it existed, as for any input outside the field tuple (Theorem 1, X6).
"""
from __future__ import annotations

import hashlib
import json

COLUMNS_VERSION = 1
TABLES = ("states", "events")
DROPPED = "\x00dropped-column\x00"            # prefix of the field name that stands for a pinned column now absent


def current_columns(M, db) -> dict:
    """{"states": [...], "events": [...]}: the columns monitor.py's load_stable() and keylog_rows() commit for this
    recorder view (PRAGMA table_info in schema order, without M.STABLE_EXCLUDE), read on M's own connection (a path or a
    poll's direct-read connection), so a monitor's list comes from the same snapshot as its rows."""
    con, owned = M._open(db)
    try:
        return {t: [r[1] for r in con.execute("PRAGMA table_info(%s)" % t) if r[1] not in M.STABLE_EXCLUDE[t]]
                for t in TABLES}
    finally:
        M._close(con, owned)


def canonical(cols) -> dict:
    """A column list in its canonical form: exactly the two tables, each a list of column-name strings."""
    if not isinstance(cols, dict) or set(cols) != set(TABLES):
        raise ValueError("a committed column list names exactly the tables %r" % (TABLES,))
    out = {}
    for t in TABLES:
        v = cols[t]
        if not isinstance(v, (list, tuple)) or not all(isinstance(c, str) and c for c in v) or len(set(v)) != len(v):
            raise ValueError("committed columns of %s must be distinct non-empty names" % t)
        out[t] = list(v)
    return out


def digest(cols) -> str:
    """SHA-256 (hex) of the canonical JSON of a column list: how records name a list."""
    return hashlib.sha256(json.dumps(canonical(cols), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _present(con, table) -> set:
    return {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}


def _pairs(cols, have, vals):
    """(name, value) pairs of the pinned list, in its order; an absent column as (DROPPED + name, None)."""
    out = []
    for c in cols:
        if c in have:
            out += [c, vals[c]]
        else:
            out += [DROPPED + c, None]
    return tuple(out)


def dropped(cols, M, db) -> dict:
    """{table: [pinned columns the recorder's table no longer has]} (empty lists when none)."""
    con, owned = M._open(db)
    try:
        return {t: [c for c in canonical(cols)[t] if c not in _present(con, t)] for t in TABLES}
    finally:
        M._close(con, owned)


def added(cols, M, db) -> dict:
    """{table: [committed-kind columns the recorder's table has that the pinned list lacks]}."""
    cur = current_columns(M, db)
    pin = canonical(cols)
    return {t: [c for c in cur[t] if c not in pin[t]] for t in TABLES}


def load_stable_cols(M, db, cols, since=None, until=None):
    """monitor.py load_stable() with the committed column list `cols` instead of PRAGMA table_info: the same rows (same
    joins, the same timestamp guard and bounds, the same order) and the same node shape (ts, key, content, ctx, par,
    label, fields); the field tuple lists the pinned columns in the pinned order."""
    cols = canonical(cols)
    con, owned = M._open(db)
    try:
        have_s, have_e = _present(con, "states"), _present(con, "events")
        sel_s = [c for c in cols["states"] if c in have_s]
        sel_e = [c for c in cols["events"] if c in have_e]
        nodes = []
        sq = ("SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts, s.context_id_bin, s.context_parent_id_bin,"
              " sa.shared_attrs" + "".join(", s.%s" % M._q(c) for c in sel_s)
              + " FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"
                " LEFT JOIN state_attributes sa ON sa.attributes_id = s.attributes_id"
              + M._where("s.last_updated_ts", since, True, until))
        for r in con.execute(sq, M._wargs(since, until)):
            sid, ent, st, ts, ctx, par, attrs = r[:7]
            vals = dict(zip(sel_s, r[7:]))
            fields = (("states",) + _pairs(cols["states"], have_s, vals)
                      + ("states_meta.entity_id", ent, "state_attributes.shared_attrs", attrs))
            nodes.append((ts or 0.0, "s:%d" % sid,
                          M._canon({"t": "state", "e": ent, "s": st, "ts": round(ts or 0.0, 6)}),
                          ctx, par, "actuates", fields))
        eq = ("SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin, e.context_parent_id_bin,"
              " ed.shared_data" + "".join(", e.%s" % M._q(c) for c in sel_e)
              + " FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id"
                " LEFT JOIN event_data ed ON ed.data_id = e.data_id"
              + M._where("e.time_fired_ts", since, True, until))
        for r in con.execute(eq, M._wargs(since, until)):
            eid, ety, ts, ctx, par, data = r[:6]
            vals = dict(zip(sel_e, r[6:]))
            fields = (("events",) + _pairs(cols["events"], have_e, vals)
                      + ("event_types.event_type", ety, "event_data.shared_data", data))
            nodes.append((ts or 0.0, "e:%d" % eid,
                          M._canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                          ctx, par, M.LABELS.get(ety, "causes"), fields))
    finally:
        M._close(con, owned)
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def keylog_rows_cols(M, db, table, lo, hi, tcols, limit=None):
    """The stable-scheme branch of monitor.py keylog_rows() with the committed columns `tcols` of `table`: (key, row
    hash, raw timestamp, holds raw text, fields) of every row with lo < key <= hi, in key order, LEFT JOINs as there."""
    tcols = list(tcols)
    joins = M.STABLE_JOINS[table]
    k = M.KEY_COL[table]
    con, owned = M._open(db)
    try:
        have = _present(con, table)
        sel = [c for c in tcols if c in have]
        sql = ("SELECT t.%s, t.%s" % (M._q(k), M._q(M.TS_COL[table]))
               + "".join(", t.%s" % M._q(c) for c in sel)
               + "".join(", j%d.%s" % (i, M._q(jc)) for i, (_jt, jc, _fk) in enumerate(joins))
               + " FROM %s t" % table
               + "".join(" LEFT JOIN %s j%d ON j%d.%s = t.%s" % (jt_, i, i, M._q(fk), M._q(fk))
                         for i, (jt_, _jc, fk) in enumerate(joins))
               + " WHERE t.%s > ? AND t.%s <= ? ORDER BY t.%s" % (M._q(k), M._q(k), M._q(k))
               + (" LIMIT %d" % int(limit) if limit else ""))
        out = []
        for r in con.execute(sql, (lo, hi)):
            vals, jvals = dict(zip(sel, r[2:2 + len(sel)])), r[2 + len(sel):]
            fields = ((table,) + _pairs(tcols, have, vals)
                      + tuple(x for (jt_, jc, _fk), v in zip(joins, jvals) for x in ("%s.%s" % (jt_, jc), v)))
            out.append((r[0], M.H(M.encode_node_v2("keylog", fields)), r[1], any(M.has_raw_bytes(v) for v in fields),
                        fields))
    finally:
        M._close(con, owned)
    return out


def refields(fields, tcols, n_joins=2):
    """The field tuple of the same row under another committed list `tcols` of its table, from a tuple that holds every
    column the row has now (load_stable_cols over the current list): (table, c1, v1, ..., the join pairs). A column of
    `tcols` the tuple lacks becomes (DROPPED + name, None), as load_stable_cols makes it."""
    table, body = fields[0], fields[1:]
    jn = 2 * n_joins
    cols_part, join_part = body[:len(body) - jn], body[len(body) - jn:]
    vals = {cols_part[i]: cols_part[i + 1] for i in range(0, len(cols_part), 2)}
    return (table,) + _pairs(tcols, set(vals), vals) + tuple(join_part)
