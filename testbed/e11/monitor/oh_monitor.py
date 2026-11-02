"""E11 openHAB row reader for the SHIPPED HOMEPROV monitor (monitor/monitor.py, imported unchanged).

Research use (drafts/round13/E11_DESIGN.md, RQ4): the same monitor, with only its read path replaced, on a third hub
family. This module imports monitor.py from HOMEPROV_MONITOR_DIR (the monitor image's /app, or a read-only copy) and
replaces five module-level functions (validate_copy only to report a failed snapshot). Everything else (sealing, the
laminar one-second / one-minute / one-hour segments, node encoding v2, coverage records, the authenticated append,
record signatures, reply tags, the state file, the fail-closed evidence path) is monitor.py's code, whichever version
is installed (the E9 monitor 8ad9e2d7 or the E10-hardened one; with the hardened one this module keeps its quick_check
latch and runs an openHAB object-type check):

  snapshot()          a CONSISTENT copy of the hub's persistence database through SQLite's online backup API from a
                      read-only connection. The SQLite DAO of openHAB 5.2.3 sets no journal mode, so SQLite's default
                      rollback journal applies unless the driver is configured otherwise (the run records the mode);
                      there, copying the file while the hub commits can tear pages, and monitor.py's file copy is
                      built for Home Assistant's WAL recorder. The backup works in either mode. A failed backup is reported by
                      validate_copy() as "snapshot_failed": the poll is unobservable and says so on the chain.
  check_connection()  quick_check when due (as monitor.py), the object-type check when monitor.py is the hardened one
                      (the index table and every mapped item table must be ordinary tables), and an openHAB schema
                      probe in place of the Home Assistant one.
  watermark()         {"items": max(ItemId), "<item table>": max(rowid) per mapped table}: the per-table arrival order
                      the late-row test needs (item tables have no INTEGER PRIMARY KEY; SQLite assigns rowid max+1).
  load()              persisted rows as monitor nodes under the closure scheme (below).

What openHAB stores (JDBC persistence, openhab-addons 5.2.3, JdbcBaseDAO / JdbcSqliteDAO / NamingStrategy): an index
table `items` (ItemId INTEGER PRIMARY KEY AUTOINCREMENT, ItemName) and one table per item, named prefix + zero-padded
ItemId (default `item0001`), with columns `time` (declared TIMESTAMP; SQLite text 'YYYY-MM-DD HH:MM:SS.SSS' in the
hub's local time, written by strftime(..., 'localtime')) and `value`, PRIMARY KEY(time), INSERT OR IGNORE. The rendered
history (REST GET /rest/persistence/items/{item}, behind Main UI's Analyze view) is built from the item -> table index
(cached in the persistence service; reloaded by `jdbc reload` or a restart), the rows' time and value, and the item's
type and unit from the item registry. No column records who or what caused a state.

Schemes (node = (ts, key, content, ctx, par, label[, usr, prev, chg])):
  closure   (live, HOMEPROV_SCHEME=closure) key 'o:<table>:<time>'; content = the v2 typed encoding of
            (table, ItemId, ItemName, time, value, registry itemType, registry 'unit' metadata). The field set is the
            renderer closure PREDICTED in E11_DESIGN.md section 3; E11-CLO measures it before the detection run, and a
            different measured set is registered as an amendment (CLOSURE_REGISTRY below) before the run starts.
  rows      every stored column of every item table found in sqlite_master (rowid included), nothing joined: the
            commitment a reader of the persistence schema would choose (offline only).
  wholerow  `rows` plus every stored column of the item's index row and its full registry entry and metadata (as
            stored JSON), no field chosen by hand (offline only).
The offline schemes are computed by exp/stages/e11_score.py from the rows each live poll read, archived by load()
(HP_OH_ARCHIVE, on the monitor's own scratch volume, never on the hub): every column of the rows of every item table
dated in the last ARCHIVE_WINDOW_S seconds, the whole index table and the registry entries.

Time: the hub runs with TZ=UTC and openHAB's regional time zone UTC (E11 harness), so 'localtime' text is UTC.
HP_OH_TZ must be "UTC"; any other value is refused (DST makes local text ambiguous).

Run (E11 harness): python -u /ohm/oh_monitor.py, with HOMEPROV_MONITOR_DIR=/app, HOMEPROV_SCHEME=closure,
HOMEPROV_COVERAGE=1, HOMEPROV_KEYLOG=0, HOMEPROV_READ=copy, HOMEPROV_DB=/hub/persistence/jdbc/openhab.db,
HP_OH_JSONDB=/hub/jsondb (the hub's userdata volume mounted read-only at /hub).
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse

sys.path.insert(0, os.environ.get("HOMEPROV_MONITOR_DIR", "/hp"))
import monitor as M  # noqa: E402

READER_VERSION = "e11-oh-1"
ITEMS_TABLE = os.environ.get("HP_OH_ITEMS_TABLE", "items")
PREFIX = os.environ.get("HP_OH_TABLE_PREFIX", "item")
DIGITS = int(os.environ.get("HP_OH_TABLE_DIGITS", "4"))
REAL_NAMES = os.environ.get("HP_OH_REAL_NAMES", "0") == "1"      # tableUseRealItemNames=true (lower-case + suffix)
JSONDB = os.environ.get("HP_OH_JSONDB", "")
HUB_TZ = os.environ.get("HP_OH_TZ", "UTC")
ARCHIVE = os.environ.get("HP_OH_ARCHIVE", "")
ARCHIVE_WINDOW_S = float(os.environ.get("HP_OH_ARCHIVE_WINDOW_S", "180"))
ITEM_FILE = "org.openhab.core.items.Item.json"
META_FILE = "org.openhab.core.items.Metadata.json"
# Registry fields in the closure (predicted; E11-CLO amends by setting HP_OH_CLOSURE_REGISTRY before the run):
# "type" = the item's itemType, "meta:<namespace>" = the value of that metadata namespace.
CLOSURE_REGISTRY = tuple(x for x in os.environ.get("HP_OH_CLOSURE_REGISTRY", "type,meta:unit").split(",") if x)
SCHEMES = ("closure", "rows", "wholerow")
LABEL = "persists"
TIME_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\.\d{1,9})?$")
_SNAP = {"error": None}


# ------------------------------------------------------------------------------------------------- names and time
def table_for(item_id, item_name) -> str:
    """The item table the persistence service maps an index row to (NamingStrategy.getTableName, 5.2.3)."""
    suffix = ("%0" + str(DIGITS) + "d") % int(item_id) if DIGITS > 0 else str(int(item_id))
    if REAL_NAMES:
        return str(item_name).lower() + "_" + suffix
    return PREFIX + suffix


def parse_time(v):
    """Seconds since the epoch of a stored time text (UTC), or None when it is not the text the DAO writes."""
    if not isinstance(v, str):
        return None
    m = TIME_RE.match(v)
    if not m:
        return None
    try:
        base = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return None
    return float(base) + (float(m.group(2)) if m.group(2) else 0.0)


def time_text(t: float) -> str:
    """The second-resolution text bound the DAO's own range queries use (JDBC_DATE_FORMAT, UTC here)."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


def _qi(name: str) -> str:
    return '"%s"' % str(name).replace('"', '""')


# ----------------------------------------------------------------------------------------------------- registry
def read_registry(jsondb: str | None = None) -> dict:
    """{"items": {name: stored value dict}, "metadata": {name: {namespace: stored value dict}}, "error": str|None,
    "sha256": {file: digest}} from openHAB's JSON database (managed items and metadata)."""
    d = JSONDB if jsondb is None else jsondb
    out = {"items": {}, "metadata": {}, "error": None, "sha256": {}}
    if not d:
        out["error"] = "no_jsondb"
        return out
    for fname, kind in ((ITEM_FILE, "items"), (META_FILE, "metadata")):
        p = os.path.join(d, fname)
        if not os.path.exists(p):
            continue
        raw = open(p, "rb").read()
        out["sha256"][fname] = hashlib.sha256(raw).hexdigest()
        doc = json.loads(raw.decode("utf-8"))          # a torn read raises: load() fails, the poll is unobservable
        for k, entry in sorted(doc.items()):
            val = entry.get("value") if isinstance(entry, dict) and "value" in entry else entry
            if kind == "items":
                out["items"][k] = val
            else:
                key = (val or {}).get("key") if isinstance(val, dict) else None
                ns = (key or {}).get("namespace") if isinstance(key, dict) else None
                item = (key or {}).get("itemName") if isinstance(key, dict) else None
                if ns is None or item is None:
                    ns, _, item = k.partition(":")
                out["metadata"].setdefault(item, {})[ns] = val
    return out


def registry_fields(reg: dict, item_name) -> tuple:
    """(name, value) pairs of the registry fields in the closure for one item, in CLOSURE_REGISTRY order."""
    ent = reg["items"].get(item_name) if item_name is not None else None
    meta = reg["metadata"].get(item_name, {}) if item_name is not None else {}
    out = []
    for f in CLOSURE_REGISTRY:
        if f == "type":
            out += ["registry.itemType", (ent or {}).get("itemType") if isinstance(ent, dict) else None]
        elif f.startswith("meta:"):
            m = meta.get(f[5:])
            out += ["registry.meta." + f[5:], (m or {}).get("value") if isinstance(m, dict) else None]
        else:
            raise ValueError("unknown closure registry field %r" % f)
    return tuple(out)


# ------------------------------------------------------------------------------------------------------- reading
def read_rows(con, since=None, until=None, jsondb: str | None = None, all_tables: bool = True) -> dict:
    """Every stored column of the index table, of the rows of the item tables with since <= time < until (text
    comparison with the DAO's own second-resolution bounds, so a row the hub's range queries skip is skipped here
    too), and the registry. all_tables=False reads only the tables the index maps (the closure's read)."""
    master = {r[0]: r[1] for r in con.execute("SELECT name, type FROM sqlite_master")}
    icols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % _qi(ITEMS_TABLE))]
    items = [list(r) for r in con.execute("SELECT * FROM %s" % _qi(ITEMS_TABLE))] if icols else []
    ii = {c.lower(): i for i, c in enumerate(icols)}
    mapped = {}
    for r in items:
        iid, name = r[ii.get("itemid", 0)], r[ii.get("itemname", 1)] if len(r) > 1 else None
        try:
            mapped.setdefault(table_for(iid, name), []).append((iid, name))
        except (TypeError, ValueError):
            continue
    names = sorted(n for n, t in master.items() if t == "table" and n.lower() not in (ITEMS_TABLE.lower(), "sqlite_sequence")
                   and not n.startswith("sqlite_")) if all_tables else sorted(t for t in mapped if master.get(t) == "table")
    cond, args = [], []
    if since is not None:
        cond.append('"time" >= ?')
        args.append(time_text(since))
    if until is not None:
        cond.append('"time" < ?')
        args.append(time_text(until))
    where = (" WHERE " + " AND ".join(cond)) if cond else ""
    tables = {}
    for t in names:
        cols = ["rowid"] + [r[1] for r in con.execute("PRAGMA table_info(%s)" % _qi(t))]
        if "time" not in [c.lower() for c in cols]:
            continue                                   # not an item table
        rows = [list(r) for r in con.execute("SELECT rowid, * FROM %s%s" % (_qi(t), where), args)]
        tables[t] = {"cols": cols, "rows": rows}
    return {"items_cols": icols, "items": items, "mapped": {t: [list(x) for x in v] for t, v in mapped.items()},
            "tables": tables, "registry": read_registry(jsondb)}


def _enc(tag: str, fields) -> bytes:
    return M.encode_node_v2(tag, tuple(fields))


def nodes_from_rows(scheme: str, data: dict, with_meta: bool = False):
    """Monitor nodes under one scheme, time-ordered; with_meta also returns, per node, {table, rowid, time, ts}."""
    if scheme not in SCHEMES:
        raise ValueError(scheme)
    reg = data["registry"]
    icols = data["items_cols"]
    ii = {c.lower(): i for i, c in enumerate(icols)}
    by_table_items = data["mapped"]
    out = []
    for t, tab in sorted(data["tables"].items()):
        cols = tab["cols"]
        ci = {c.lower(): i for i, c in enumerate(cols)}
        maps = by_table_items.get(t) or []
        if scheme == "closure" and not maps:
            continue                                   # no index row maps to it: the renderer never shows it
        for r in tab["rows"]:
            tr, vr, rid = r[ci["time"]], r[ci["value"]] if "value" in ci else None, r[ci["rowid"]]
            ts = parse_time(tr)
            if ts is None:
                continue                               # not the DAO's text: neither renderer nor reader folds it
            key = "o:%s:%s" % (t, tr)
            if scheme == "closure":
                for iid, name in maps:
                    content = _enc("oh-closure", ("table", t, "item_id", iid, "item_name", name, "time", tr,
                                                  "value", vr) + registry_fields(reg, name))
                    node = (ts, key if len(maps) == 1 else "%s#%s" % (key, iid), content, None, None, LABEL,
                            None, None, None)
                    out.append((node, {"table": t, "rowid": rid, "time": tr, "ts": ts, "item": name}))
            else:
                fields = ["table", t] + [x for c, v in zip(cols, r) for x in (c, v)]
                if scheme == "wholerow":
                    for iid, name in (maps or [(None, None)]):
                        irow = next((x for x in data["items"] if x[ii.get("itemid", 0)] == iid), None)
                        fields += ["items_row", M._canon(dict(zip(icols, irow))).decode() if irow else None,
                                   "registry_item", M._canon(reg["items"].get(name)).decode()
                                   if reg["items"].get(name) is not None else None,
                                   "registry_metadata", M._canon(reg["metadata"].get(name, {})).decode()]
                node = (ts, key, _enc("oh-" + scheme, fields), None, None, LABEL)
                out.append((node, {"table": t, "rowid": rid, "time": tr, "ts": ts,
                                   "item": maps[0][1] if maps else None}))
    out.sort(key=lambda x: (x[0][0], x[0][1]))
    return out if with_meta else [n for n, _ in out]


# ------------------------------------------------------------------------------- the four replaced functions
def snapshot() -> str:
    """Consistent copy of the live database into scratch through SQLite's backup API (read-only source)."""
    dst = os.path.join(M.SCRATCH, "recorder.db")
    for suf in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(dst + suf):
            os.remove(dst + suf)
    _SNAP["error"] = None
    src = d = None
    try:
        uri = "file:%s?mode=ro" % urllib.parse.quote(M.SRC)
        if os.path.exists(M.SRC + "-wal"):
            uri += "&readonly_shm=1"
        src = sqlite3.connect(uri, uri=True, timeout=10)
        if hasattr(M, "harden"):
            M.harden(src)
        d = sqlite3.connect(dst)
        src.backup(d)
    except Exception as exc:                          # noqa: BLE001  (busy, hot journal on a read-only mount, missing)
        _SNAP["error"] = repr(exc)[:160]
    finally:
        for c in (d, src):
            if c is not None:
                try:
                    c.close()
                except Exception:                     # noqa: BLE001
                    pass
    return dst


_shipped_validate = M.validate_copy


def validate_copy(db: str, quick: bool = True):
    if _SNAP["error"] is not None:
        return False, "snapshot_failed", {"exc": _SNAP["error"]}
    return _shipped_validate(db, quick)


def check_objects_oh(con):
    """Hardened monitors only: the index table and every mapped item table must each be exactly one ordinary table."""
    kinds = {}
    for name, typ, sql in con.execute("SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"):
        virtual = typ == "table" and " ".join(str(sql or "").split()).upper().startswith("CREATE VIRTUAL TABLE")
        kinds.setdefault(name.lower(), []).append("virtual table" if virtual else typ)
    want = {ITEMS_TABLE.lower()}
    if ITEMS_TABLE.lower() in kinds and kinds[ITEMS_TABLE.lower()] == ["table"]:
        for iid, name in con.execute("SELECT ItemId, ItemName FROM %s" % _qi(ITEMS_TABLE)):
            try:
                want.add(table_for(iid, name).lower())
            except (TypeError, ValueError):
                pass
    bad = {n: "/".join(sorted(k)) for n, k in kinds.items() if n in want and (k.count("table") != 1 or len(k) != 1)}
    return (False, "schema_object_not_a_table", {"objects": bad}) if bad else None


def check_connection(con, quick: bool = True):
    hard = bool(getattr(M, "HARDEN", False))
    if quick:
        try:
            qc = con.execute("PRAGMA quick_check").fetchone()[0]
        except Exception:                             # noqa: BLE001
            if hard:
                M._QC.update(first=False, latched=True)
            raise
        if hard:
            M._QC.update(first=False, latched=qc != "ok")
        if qc != "ok":
            return False, "quick_check_failed", {"quick_check": str(qc)[:80]}
    if hard:
        bad = check_objects_oh(con)
        if bad:
            return bad
    con.execute("SELECT ItemId, ItemName FROM %s LIMIT 1" % _qi(ITEMS_TABLE)).fetchone()
    return None


def watermark(db) -> dict:
    con, owned = M._open(db)
    try:
        out = {"items": con.execute("SELECT max(ItemId) FROM %s" % _qi(ITEMS_TABLE)).fetchone()[0]}
        master = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for iid, name in con.execute("SELECT ItemId, ItemName FROM %s" % _qi(ITEMS_TABLE)).fetchall():
            try:
                t = table_for(iid, name)
            except (TypeError, ValueError):
                continue
            if t in master:
                out[t] = con.execute("SELECT max(rowid) FROM %s" % _qi(t)).fetchone()[0]
        return out
    finally:
        M._close(con, owned)


def _archive(con, n_nodes, since):
    t = time.time()
    data = read_rows(con, since=t - ARCHIVE_WINDOW_S)
    rec = {"v": READER_VERSION, "t_load": t, "since": since, "n_nodes": n_nodes, "window_s": ARCHIVE_WINDOW_S,
           "items_cols": data["items_cols"], "items": data["items"], "mapped": data["mapped"],
           "tables": data["tables"], "registry": data["registry"]}
    with open(ARCHIVE, "a") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")


def load(db, since: float | None = None, until: float | None = None):
    """Replacement for monitor.load(): persisted rows as monitor nodes under monitor.SCHEME (closure)."""
    con, owned = M._open(db)
    try:
        nodes = nodes_from_rows(M.SCHEME, read_rows(con, since=since, until=until, all_tables=False))
        if ARCHIVE:
            try:
                _archive(con, len(nodes), since)
            except Exception as exc:                  # noqa: BLE001  (never affects sealing)
                print(json.dumps({"archive_error": repr(exc)[:200]}), flush=True)
    finally:
        M._close(con, owned)
    return nodes


def refusals() -> list:
    """Configurations this reader does not support (each would use a Home Assistant code path of monitor.py)."""
    bad = []
    if M.SCHEME != "closure":
        bad.append("HOMEPROV_SCHEME must be closure (the offline schemes are computed by the scorer)")
    if M.ENCODING != "v2":
        bad.append("HOMEPROV_ENCODING must be v2")
    if not M.COVERAGE:
        bad.append("HOMEPROV_COVERAGE must be 1 (records carry wm, since, through, copy_at, seq_local)")
    if M.KEYLOG:
        bad.append("HOMEPROV_KEYLOG must be 0 (the keylog reads Home Assistant tables; not ported in E11)")
    if M.READ != "copy":
        bad.append("HOMEPROV_READ must be copy (the backup-API snapshot replaces the copy)")
    if M.SINCE is not None:
        bad.append("HOMEPROV_SINCE is not supported (its streamed seal reads Home Assistant tables)")
    if M.ESCROW_DIR or M.NAMEMAP_DIR or M.CLOCK_FILE:
        bad.append("HOMEPROV_ESCROW_DIR, HOMEPROV_NAMEMAP_DIR and HOMEPROV_CLOCK_FILE must be unset")
    if HUB_TZ != "UTC":
        bad.append("HP_OH_TZ must be UTC")
    if not JSONDB:
        bad.append("HP_OH_JSONDB must name the hub's jsondb directory (read-only)")
    return bad


def install():
    M.snapshot = snapshot
    M.validate_copy = validate_copy
    M.check_connection = check_connection
    M.watermark = watermark
    M.load = load


install()

if __name__ == "__main__":
    bad = refusals()
    mp = os.path.join(os.environ.get("HOMEPROV_MONITOR_DIR", "/hp"), "monitor.py")
    print(json.dumps({"oh_reader": {"version": READER_VERSION, "refusals": bad, "db": M.SRC, "jsondb": JSONDB,
                                    "closure_registry": list(CLOSURE_REGISTRY), "table_prefix": PREFIX,
                                    "digits": DIGITS, "real_names": REAL_NAMES, "hardened_monitor": hasattr(M, "harden"),
                                    "monitor_py_sha256": hashlib.sha256(open(mp, "rb").read()).hexdigest()
                                    if os.path.exists(mp) else None,
                                    "replaced": ["snapshot", "validate_copy (snapshot_failed only)",
                                                 "check_connection", "watermark", "load"]}}), flush=True)
    if bad:
        raise SystemExit(2)
    M.main()
