"""E-DZ adapter: the SHIPPED HOMEPROV monitor (monitor/monitor.py, mounted read-only and imported unchanged) run against a
Domoticz hub.

It replaces exactly two things in the imported module:
  * monitor.load(): rows of Domoticz's LightingLog joined with the device's DeviceStatus row, as monitor nodes;
  * the Home Assistant schema probe at the end of monitor.validate_copy() (the WAL, header and quick_check checks before
    it are monitor.py's and run unchanged; only a 'schema_unreadable' verdict is re-decided with a Domoticz probe).
Snapshot (copy of domoticz.db and its WAL sidecars from the read-only mount), node encoding v2, laminar one-second /
one-minute / one-hour segments, sealing, the HMAC-authenticated append and the monitor state are monitor.py's code.

What a node commits under each scheme. The renderer closure was measured by exp/stages/dz_closure.py (exp/out/
dz_closure.json): the device Log view (CWebServer::Cmd_GetLightLog) output depends on LightingLog.{ROWID, DeviceRowID,
nValue, sValue, User, Date} and DeviceStatus.{ID, Type, SubType, SwitchType, Options}.
  closure   (live, HOMEPROV_SCHEME=closure) key 'l:<ROWID>'; content = DeviceRowID, nValue, sValue, Date and the
            device's Type, SubType, SwitchType, Options; User in the node's user slot (monitor.node_hash_closure).
            DeviceStatus.ID is bound through the join: a row whose device row moves leaves the read.
  row       (HOMEPROV_SCHEME=row) the same minus User: the Home Assistant row scheme's analogue (offline only here).
  logrows   every stored column of the LightingLog row, nothing from DeviceStatus (offline only).
  wholerow  the closure fields plus every stored column of the LightingLog row and of its DeviceStatus row, read with
            PRAGMA table_info so no column is chosen by hand (offline only).
The offline schemes are computed by exp/stages/dz_detection.py from the rows each live poll read, which load() archives
(HP_DZ_ARCHIVE, on the monitor's own scratch volume, never on the hub): every column of the LightingLog rows dated in
the last ARCHIVE_WINDOW_S seconds and every column of every DeviceStatus row. The archive does not change what is
committed or anchored.

Timestamps: LightingLog.Date is written by SQLite as datetime('now','localtime') at one-second resolution; the hub runs
with TZ=UTC, so Date is read as UTC.
"""
from __future__ import annotations

import calendar
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.environ.get("HOMEPROV_MONITOR_DIR", "/hp"))
import monitor as M  # noqa: E402

LL_CLOSURE = ("DeviceRowID", "nValue", "sValue", "User", "Date")          # plus ROWID, the node key
DS_CLOSURE = ("Type", "SubType", "SwitchType", "Options")                 # plus ID, bound by the join
SCHEMES = ("closure", "row", "logrows", "wholerow")
ARCHIVE = os.environ.get("HP_DZ_ARCHIVE", "")
ARCHIVE_WINDOW_S = float(os.environ.get("HP_DZ_ARCHIVE_WINDOW_S", "180"))


def date_ts(s: str) -> float:
    return float(calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S")))


def ts_date(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


def read_rows(con, since=None, ll_since=None):
    """(ll_cols, ll_rows, ds_cols, ds_rows): every stored column of the LightingLog rows (ROWID first) dated at or after
    `since`, and every stored column of every DeviceStatus row."""
    ll_cols = ["ROWID"] + [r[1] for r in con.execute("PRAGMA table_info(LightingLog)")]
    ds_cols = [r[1] for r in con.execute("PRAGMA table_info(DeviceStatus)")]
    q = "SELECT ROWID, * FROM LightingLog" + (" WHERE Date >= ?" if since is not None else "")
    ll = con.execute(q, (ts_date(since),) if since is not None else ()).fetchall()
    ds = con.execute("SELECT * FROM DeviceStatus").fetchall()
    return ll_cols, [list(r) for r in ll], ds_cols, [list(r) for r in ds]


def nodes_from_rows(scheme, ll_cols, ll_rows, ds_cols, ds_rows):
    """Monitor nodes (ts, key, content, ctx, par, label[, usr, prev, chg]) under one scheme, time-ordered."""
    if scheme not in SCHEMES:
        raise ValueError(scheme)
    li = {c: i for i, c in enumerate(ll_cols)}
    di = {c: i for i, c in enumerate(ds_cols)}
    devs = {r[di["ID"]]: r for r in ds_rows}
    nodes = []
    for r in ll_rows:
        d = devs.get(r[li["DeviceRowID"]])
        if d is None:                      # no device row: the renderer shows nothing for it, and the join drops it
            continue
        ts = date_ts(r[li["Date"]])
        key = "l:%d" % r[li["ROWID"]]
        if scheme in ("closure", "row"):
            content = M._canon({"t": "lightlog", "dev": r[li["DeviceRowID"]], "n": r[li["nValue"]],
                                "s": r[li["sValue"]], "date": r[li["Date"]], "type": d[di["Type"]],
                                "sub": d[di["SubType"]], "sw": d[di["SwitchType"]], "opt": d[di["Options"]]})
            node = (ts, key, content, None, None, "actuates")
            nodes.append(node + (r[li["User"]], None, None) if scheme == "closure" else node)
        elif scheme == "logrows":
            content = M._canon({"t": "lightlog-row", "row": dict(zip(ll_cols, r))})
            nodes.append((ts, key, content, None, None, "actuates"))
        else:
            content = M._canon({"t": "lightlog-wholerow", "row": dict(zip(ll_cols, r)),
                                "device": dict(zip(ds_cols, d))})
            nodes.append((ts, key, content, None, None, "actuates"))
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def _archive(con, n_nodes, since):
    t = time.time()
    ll_cols, ll, ds_cols, ds = read_rows(con, since=t - ARCHIVE_WINDOW_S)
    rec = {"t_load": t, "since": since, "n_nodes": n_nodes, "window_s": ARCHIVE_WINDOW_S,
           "ll_cols": ll_cols, "ll": ll, "ds_cols": ds_cols, "ds": ds}
    with open(ARCHIVE, "a") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")


def load(db: str, since: float | None = None):
    """Replacement for monitor.load(): Domoticz lighting-log rows as monitor nodes under monitor.SCHEME."""
    con = sqlite3.connect(db, timeout=30)
    con.execute("PRAGMA query_only=ON")
    try:
        ll_cols, ll, ds_cols, ds = read_rows(con, since=since)
        nodes = nodes_from_rows(M.SCHEME, ll_cols, ll, ds_cols, ds)
        if ARCHIVE:
            try:
                _archive(con, len(nodes), since)
            except Exception as exc:                                 # noqa: BLE001  (never affects sealing)
                print(json.dumps({"archive_error": repr(exc)[:200]}), flush=True)
    finally:
        con.close()
    return nodes


_shipped_validate = M.validate_copy


def validate_copy(db: str, quick: bool = True):
    """monitor.validate_copy() unchanged, except that its Home Assistant schema probe is replaced by a Domoticz one.
    `quick` is passed through: the E10 monitor calls validate_copy(db, quick) (fix of 2026-10-20, E10 review-r5 smoke,
    arm C: every poll failed with "validate_copy() takes 1 positional argument but 2 were given")."""
    ok, reason, detail = _shipped_validate(db, quick)
    if ok or reason != "schema_unreadable":
        return ok, reason, detail
    try:
        con = sqlite3.connect(db, timeout=10)
        con.execute("PRAGMA query_only=ON")
        con.execute("SELECT ROWID, DeviceRowID, nValue, sValue, User, Date FROM LightingLog LIMIT 1").fetchone()
        con.execute("SELECT ID, Type, SubType, SwitchType, Options FROM DeviceStatus LIMIT 1").fetchone()
        con.close()
    except Exception as exc:                                         # noqa: BLE001
        return False, "schema_unreadable", {"exc": repr(exc)[:120]}
    return True, "ok", {}


def watermark(db: str) -> dict:
    """Replacement for monitor.watermark(), which reads Home Assistant's states/events keys at every poll (added with the
    coverage scheme, after the first Domoticz run): the largest LightingLog ROWID, with states and events None (no keylog
    runs on Domoticz). Fix of 2026-10-20 (E10 review-r5 smoke, arm C: every poll load_failed, "no such table: states")."""
    con, owned = M._open(db)
    try:
        return {"states": None, "events": None,
                "lightinglog": con.execute("SELECT max(ROWID) FROM LightingLog").fetchone()[0]}
    finally:
        M._close(con, owned)


M.load = load
M.validate_copy = validate_copy
M.watermark = watermark
# The keylog reads Home Assistant's states/events keys and is on by default since round 13 (HOMEPROV_KEYLOG=1); it has
# no Domoticz counterpart, so the adapter turns it off whatever the environment says (fix of 2026-10-20, as above).
M.KEYLOG = False

if __name__ == "__main__":
    M.main()
