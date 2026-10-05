"""HOMEPROV WHOLE-ROW baseline monitor (review D1, finding F-09; added 2026-10-04).

WHY THIS EXISTS. The paper's closure scheme commits the recorder fields the
logbook processor is measured to read. The obvious baseline from tamper-evident
logging is to commit the WHOLE record: every column of every states and events
row. This module runs that baseline with the shipped monitor's own code, so the
two schemes differ only in the bytes each node hash covers.

WHAT IT COMMITS. Per node, the closure scheme's hash input (row key, resolved
content, context, parent, user context, old_state_id, last_changed_ts, edge
label) PLUS a canonical serialization of every column of the stored row, read
with `PRAGMA table_info` so no column is chosen by hand (BLOBs as hex). It is
therefore a strict superset of the closure: any rewrite the closure detects
changes this hash too. Segments, sealing, anchoring and verification are the
shipped monitor's, unchanged.

HOW IT IS USED. As a container entry point it patches the shipped monitor
module in memory and runs its main loop; the appended payloads record scheme
"wholerow". Imported (HOMEPROV_WHOLEROW=1 via a sitecustomize shim), it patches
`monitor` for the host-side verifier, which imports the shipped module by name.
monitor.py itself is not modified.
"""
from __future__ import annotations

import os
import sqlite3
import sys

# monitor.py accepts only 'closure' or 'row' at import; whole-row extends the
# closure node, so import it in closure mode and patch below.
os.environ["HOMEPROV_SCHEME"] = "closure"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monitor as M  # noqa: E402

H = M.H


def _cell(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"hex": bytes(v).hex()}
    return v


def load(db: str, since: float | None = None):
    """Same rows, same order and same segment timestamps as monitor.load in
    closure mode; each node carries a tenth element, the whole stored row."""
    con = sqlite3.connect(db, timeout=30)
    con.execute("PRAGMA query_only=ON")
    scols = [r[1] for r in con.execute("PRAGMA table_info(states)")]
    ecols = [r[1] for r in con.execute("PRAGMA table_info(events)")]
    nodes = []
    sq = ("SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts, s.context_id_bin, "
          "s.context_parent_id_bin, s.context_user_id_bin, s.old_state_id, s.last_changed_ts, "
          + ", ".join("s.%s" % c for c in scols)
          + " FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"
          + (" WHERE s.last_updated_ts >= ?" if since is not None else ""))
    for r in con.execute(sq, (since,) if since is not None else ()):
        sid, ent, st, ts, ctx, par, usr, prev, chg = r[:9]
        whole = M._canon({"table": "states", "row": {c: _cell(v) for c, v in zip(scols, r[9:])}})
        nodes.append((ts or 0.0, "s:%d" % sid,
                      M._canon({"t": "state", "e": ent, "s": st, "ts": round(ts or 0.0, 6)}),
                      ctx, par, "actuates", usr, prev, chg, whole))
    eq = ("SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin, "
          "e.context_parent_id_bin, ed.shared_data, e.context_user_id_bin, "
          + ", ".join("e.%s" % c for c in ecols)
          + " FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id"
          " LEFT JOIN event_data ed ON ed.data_id = e.data_id"
          + (" WHERE e.time_fired_ts >= ?" if since is not None else ""))
    for r in con.execute(eq, (since,) if since is not None else ()):
        eid, ety, ts, ctx, par, data, usr = r[:7]
        whole = M._canon({"table": "events", "row": {c: _cell(v) for c, v in zip(ecols, r[7:])}})
        nodes.append((ts or 0.0, "e:%d" % eid,
                      M._canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                      ctx, par, M.LABELS.get(ety, "causes"), usr, None, None, whole))
    con.close()
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def node_hash_wholerow(n) -> bytes:
    ts, key, content, ctx, par, label, usr, prev, chg, whole = n
    return H(M.node_hash_closure(key, content, ctx, par, label, usr, prev, chg) + b"|" + whole)


def commit(nodes):
    """monitor.commit with the whole-row node hash; same laminar accumulators."""
    phi = {}
    for name, width in M.GRAN:
        segs = {}
        for n in nodes:
            s = segs.setdefault(int(n[0] // width), {"acc": M.ZERO, "n": 0})
            s["acc"] = H(s["acc"] + node_hash_wholerow(n))
            s["n"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]} for k, v in segs.items()}
    return phi


M.load = load
M.commit = commit
M.SCHEME = "wholerow"

if __name__ == "__main__":
    M.main()
