"""HOMEPROV M2 core — A1 emission, A2 laminar commitment, A4 verification.

Two commitment schemes over the SAME provenance graph, so the comparison
isolates one variable:

  HOMEPROV : h(v) = H( content(v) || [ (h(parent_i), label_i) ] )   <- insight I-1
  B2       : h(v) = H( content(v) )                                  <- record-level only
             (Yagiz et al. 2026 / Crosby-Wallach lineage: a Merkle
              commitment over a FLAT sequence of record contents)

B2 is given HOMEPROV's own anchor and its own laminar segmentation, so the
only difference is whether causal structure is bound. Anything B2 misses that
HOMEPROV catches is attributable to edge binding and to nothing else.
"""
from __future__ import annotations
import hashlib, json, sqlite3
from dataclasses import dataclass, field

H = lambda b: hashlib.sha256(b).digest()
ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]   # laminar: nested


@dataclass
class Node:
    key: str            # stable identity: "s:<state_id>" | "e:<event_id>"
    kind: str           # 'state' | 'event'
    ts: float
    content: bytes      # what B2 commits
    ctx: bytes | None
    par: bytes | None
    label: str
    h_hp: bytes = b""   # HOMEPROV hash (content + structure)
    h_b2: bytes = b""   # B2 hash (content only)


def load_graph(db: str) -> list[Node]:
    """A1 EMIT-PROV, applied retrospectively to a recorder database."""
    con = sqlite3.connect(db)
    nodes: list[Node] = []
    for r in con.execute(
        """SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                  s.context_id_bin, s.context_parent_id_bin
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id"""):
        sid, ent, st, ts, ctx, par = r
        content = json.dumps({"t": "state", "entity": ent, "state": st,
                              "ts": round(ts or 0, 6)}, sort_keys=True).encode()
        nodes.append(Node("s:%d" % sid, "state", ts or 0.0, content, ctx, par, "actuates"))
    for r in con.execute(
        """SELECT e.event_id, et.event_type, e.time_fired_ts,
                  e.context_id_bin, e.context_parent_id_bin, ed.shared_data
             FROM events e JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id"""):
        eid, ety, ts, ctx, par, data = r
        content = json.dumps({"t": "event", "type": ety, "ts": round(ts or 0, 6),
                              "data": data}, sort_keys=True).encode()
        lbl = {"automation_triggered": "triggers", "call_service": "invokes"}.get(ety, "causes")
        nodes.append(Node("e:%d" % eid, "event", ts or 0.0, content, ctx, par, lbl))
    con.close()
    nodes.sort(key=lambda n: (n.ts, n.key))
    return nodes


def hash_graph(nodes: list[Node]) -> None:
    """Compute both hash families in topological (time) order.

    HOMEPROV binds the PARENT'S HASH and the EDGE LABEL into the child.
    Re-parenting therefore changes the child's hash even though its content is
    untouched -- which is exactly the case M1 measured as
    content_byte_identical = true.
    """
    rep: dict[bytes, bytes] = {}          # context -> hash of its earliest node
    for n in nodes:
        n.h_b2 = H(n.content)             # B2: content only
        ph = rep.get(n.par, ZERO) if n.par else ZERO
        n.h_hp = H(n.content + b"|" + ph + b"|" + n.label.encode())
        if n.ctx is not None and n.ctx not in rep:
            rep[n.ctx] = n.h_hp


def commit(nodes: list[Node], which: str) -> dict:
    """A2 COMMIT-LAMINAR. Nested segments; each carries an ordered accumulator
    and a count, so deletion and injection are caught by count and reordering
    or re-parenting by the accumulator."""
    phi: dict[str, dict] = {}
    for name, width in GRAN:
        segs: dict[int, dict] = {}
        for n in nodes:
            k = int(n.ts // width)
            s = segs.setdefault(k, {"acc": ZERO, "count": 0})
            hv = n.h_hp if which == "homeprov" else n.h_b2
            s["acc"] = H(s["acc"] + hv)
            s["count"] += 1
        phi[name] = {str(k): {"acc": v["acc"].hex(), "count": v["count"]}
                     for k, v in segs.items()}
    return phi


def anchor(db: str, which: str) -> dict:
    nodes = load_graph(db)
    hash_graph(nodes)
    return commit(nodes, which)


def verify(db: str, phi: dict, which: str) -> dict:
    """A4 VERIFY. Returns the violated segments, per granularity."""
    nodes = load_graph(db)
    hash_graph(nodes)
    now = commit(nodes, which)
    violations = []
    for name, _ in GRAN:
        old, new = phi[name], now[name]
        for k in set(old) | set(new):
            o, n2 = old.get(k), new.get(k)
            if o is None:
                violations.append({"gran": name, "seg": k, "why": "UNCOMMITTED"})
            elif n2 is None:
                violations.append({"gran": name, "seg": k, "why": "SEGMENT_GONE"})
            elif o["count"] != n2["count"]:
                violations.append({"gran": name, "seg": k, "why": "COUNT",
                                   "was": o["count"], "now": n2["count"]})
            elif o["acc"] != n2["acc"]:
                violations.append({"gran": name, "seg": k, "why": "ACC"})
    return {"detected": bool(violations), "n_violations": len(violations),
            "violations": violations}
