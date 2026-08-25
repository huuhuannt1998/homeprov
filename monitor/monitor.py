"""HOMEPROV external monitor.

WHY THIS EXISTS. The previous defender was a Home Assistant integration, so it
executed in the adversary's interpreter. Rebinding one module-level name gave the
adversary a censored view of the recorder, and the anchor then held no record
that the adversary had acted at all (measured: the defender read 475 rows where
the graph held 477). A defender inside the process it defends cannot make the
guarantee this project claims.

WHAT CHANGED. The monitor runs in its own container, on a network the hub is not
attached to, and mounts the hub's configuration directory READ-ONLY. It receives
nothing from the hub process: no Python objects, no callbacks, no RPC. It reads
recorder state itself and computes commitments itself.

WHY IT COPIES BEFORE READING. The recorder runs in WAL mode. A read-only open of
a live WAL database fails outright, because SQLite must create the -shm file;
and `immutable=1`, which does open, silently IGNORES the WAL and therefore
misses exactly the newest rows, which is the window an adversary exploits. The
monitor instead copies the database and its sidecars into its own scratch space
and opens the copy. The hub's directory stays mounted read-only, so a compromised
monitor cannot write back into the hub either.

WHAT THIS STILL DOES NOT SOLVE. The monitor observes at a polling interval, so an
adversary that writes and deletes entirely between two polls is never observed.
That residual pre-observation window is a property of the architecture, not a bug,
and it is what experiment E1 measures.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
import urllib.error
import urllib.request

SRC = os.environ.get("HOMEPROV_DB", "/cfg/home-assistant_v2.db")
SCRATCH = os.environ.get("HOMEPROV_SCRATCH", "/scratch")
ANCHOR = os.environ.get("HOMEPROV_ANCHOR", "http://hp-anchord:9900/append")
PERIOD = float(os.environ.get("HOMEPROV_PERIOD", "5"))
STATE = os.path.join(SCRATCH, "monitor_state.json")

ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]
H = lambda b: hashlib.sha256(b).digest()

LABELS = {"automation_triggered": "triggers", "call_service": "invokes"}


def _canon(obj) -> bytes:
    """Byte-identical to exp/rig/graph.py::_canon. The determinism gate compares
    the monitor's commitments against the rig's; any drift here breaks it."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def snapshot() -> str:
    """Copy the recorder and its WAL sidecars into scratch, then read the copy."""
    dst = os.path.join(SCRATCH, "recorder.db")
    for suffix in ("", "-wal", "-shm"):
        src = SRC + suffix
        out = dst + suffix
        if os.path.exists(src):
            shutil.copy2(src, out)
        elif os.path.exists(out):
            os.remove(out)          # sidecar vanished upstream; do not read a stale one
    return dst


def load(db: str, since: float | None = None):
    """Recorder rows as (ts, key, content, ctx, par, label), time-ordered.

    `since` bounds the read to rows at or after a timestamp. It is NOT a
    high-water mark on rows already seen: it is the start of the oldest segment
    that is still open. Filtering on "newer than anything I have processed" would
    let a BACKDATED insert into a still-open segment slip past unfolded, and that
    is forgery class FT-9. Re-reading from the oldest open segment bounds the work
    to one coarse segment-width of rows while leaving no gap.
    """
    con = sqlite3.connect(db, timeout=30)
    con.execute("PRAGMA query_only=ON")
    nodes = []
    sq = ("""SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                    s.context_id_bin, s.context_parent_id_bin
               FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"""
          + (" WHERE s.last_updated_ts >= ?" if since is not None else ""))
    for sid, ent, st, ts, ctx, par in con.execute(
        sq, (since,) if since is not None else ()):
        nodes.append((ts or 0.0, "s:%d" % sid,
                      _canon({"t": "state", "e": ent, "s": st,
                              "ts": round(ts or 0.0, 6)}),
                      ctx, par, "actuates"))
    eq = ("""SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin,
                    e.context_parent_id_bin, ed.shared_data
               FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id
               LEFT JOIN event_data ed ON ed.data_id = e.data_id"""
          + (" WHERE e.time_fired_ts >= ?" if since is not None else ""))
    for eid, ety, ts, ctx, par, data in con.execute(
        eq, (since,) if since is not None else ()):
        nodes.append((ts or 0.0, "e:%d" % eid,
                      _canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6),
                              "d": data}),
                      ctx, par, LABELS.get(ety, "causes")))
    con.close()
    nodes.sort(key=lambda n: (n[0], n[1]))
    return nodes


def node_hash(key: str, content: bytes, ctx, par, label: str) -> bytes:
    """FULL-ROW commitment: identity, payload, and both causal columns.

    Committing the record rather than a chosen projection of it is the design
    conclusion of this work. Three separate identity omissions were found in the
    bespoke graph-shaped construction this replaces, each only by testing.
    """
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + label.encode())


def commit(nodes):
    """Laminar segment accumulators over the full-row node hashes."""
    phi = {}
    for name, width in GRAN:
        segs = {}
        for ts, key, content, ctx, par, label in nodes:
            h = node_hash(key, content, ctx, par, label)
            s = segs.setdefault(int(ts // width), {"acc": ZERO, "n": 0})
            s["acc"] = H(s["acc"] + h)
            s["n"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]}
                     for k, v in segs.items()}
    return phi


def sealed(phi, now: float):
    """Segments whose window has closed and can therefore never gain a row."""
    out = {}
    for name, width in GRAN:
        cutoff = int(now // width)
        out[name] = {k: v for k, v in phi.get(name, {}).items() if int(k) < cutoff}
    return out


def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {"anchored": {g: [] for g, _ in GRAN}}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(st, fh)
    os.replace(tmp, STATE)


def append(rec) -> dict:
    body = json.dumps(rec, sort_keys=True).encode()
    req = urllib.request.Request(ANCHOR, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code}
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "err": repr(exc)[:120]}


def tick(st) -> dict:
    """One observation cycle, incremental in history length.

    Only segments that are still OPEN can change, so only rows from the oldest
    open segment onward need folding. Sealed segments are already anchored and an
    append-only chain keeps them; a later change to one is the verifier's business
    to detect, not the monitor's to re-anchor.
    """
    t_start = time.time()
    db = snapshot()
    t_copy = time.time() - t_start
    now = time.time()
    widest = max(w for _, w in GRAN)
    since = (int(now // widest) * widest) - widest    # one coarse window of slack
    nodes = load(db, since=since)
    t_load = time.time() - t_start - t_copy
    phi = commit(nodes)
    t_commit = time.time() - t_start - t_copy - t_load
    closed = sealed(phi, now)
    fresh = {}
    for g, segs in closed.items():
        known = set(st["anchored"].get(g, []))
        new = {k: v for k, v in segs.items() if k not in known}
        if new:
            fresh[g] = new
    out = {"n_nodes": len(nodes), "copy_ms": round(t_copy * 1000, 3),
           "load_ms": round(t_load * 1000, 3), "commit_ms": round(t_commit * 1000, 3),
           "sealed_new": {g: len(v) for g, v in fresh.items()}}
    if fresh:
        r = append({"observer": "external-monitor", "ts": now, "sealed": fresh})
        out["anchor"] = r
        if r.get("ok"):
            for g, segs in fresh.items():
                st["anchored"].setdefault(g, []).extend(segs.keys())
            save_state(st)
    return out


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    st = load_state()
    if "--phi" in sys.argv:
        # Determinism gate: emit the commitment so it can be compared against the
        # rig's independent implementation. Divergence between the artifact and
        # the evaluated design is exactly the defect this project keeps finding.
        nodes = load(snapshot())
        print(json.dumps({"n_nodes": len(nodes), "phi": commit(nodes)}, sort_keys=True))
        return
    if "--once" in sys.argv:
        print(json.dumps(tick(st)))
        return
    n = 0
    while True:
        try:
            r = tick(st)
            n += 1
            if n <= 3 or n % 12 == 0:
                print(json.dumps({"tick": n, **r}), flush=True)
        except Exception as exc:                      # noqa: BLE001
            print(json.dumps({"error": repr(exc)[:200]}), flush=True)
        time.sleep(PERIOD)


if __name__ == "__main__":
    main()
