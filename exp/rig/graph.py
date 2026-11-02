"""A1 EMIT-PROV — the actuation-provenance graph G = (V, A), recovered from a
Home Assistant recorder database.

Node types map to the formal model (design section 1.2):
  pi principal | tau trigger | kappa condition | alpha action | delta device-state

MEASURED FACT this module rests on (M1): HA 2026.7 stores causal structure in
three MUTABLE columns -- context_id_bin, context_parent_id_bin,
context_user_id_bin -- with nothing binding them to the record they belong to.
context_parent_id_bin IS the causal edge.
"""
from __future__ import annotations
import json, sqlite3
from dataclasses import dataclass

LABELS = {"automation_triggered": "triggers",
          "call_service": "invokes",
          "script_started": "invokes"}


@dataclass
class Node:
    key: str            # "s:<state_id>" | "e:<event_id>"  -- stable identity
    kind: str           # 'state' | 'event'
    ty: str             # pi | tau | kappa | alpha | delta
    ts: float
    entity: str | None
    content: bytes      # canonical serialization -- what a record-level scheme commits
    ctx: bytes | None
    par: bytes | None
    label: str
    payload: dict | None = None
    # RENDERER-CLOSURE FIELDS (E4, 2026-08-25). These are consumed by HA's
    # logbook when it computes attribution, and are carried separately from
    # `content` because `content` is the record-level abstraction a B2-style
    # scheme commits, and the whole point of B2c is to be able to commit the
    # closure WITHOUT committing the whole physical row. Keeping them here makes
    # the difference between the two schemes explicit rather than implicit.
    usr: bytes | None = None      # context_user_id_bin  -- person attribution
    prev: int | None = None       # old_state_id         -- render eligibility
    changed: float | None = None  # last_changed_ts      -- render eligibility


def _canon(obj) -> bytes:
    """Canonical serialization. Determinism here is a Stage-0 gate: two runs at
    the same seed must produce byte-identical hashes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def classify_event(ety: str) -> str:
    if ety == "automation_triggered":
        return "tau"
    if ety in ("call_service", "script_started"):
        return "alpha"
    return "kappa"


def load(db: str, entities: list[str] | None = None) -> list[Node]:
    con = sqlite3.connect(db)
    nodes: list[Node] = []
    q = """SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                  s.context_id_bin, s.context_parent_id_bin, s.context_user_id_bin,
                  s.old_state_id, s.last_changed_ts
             FROM states s JOIN states_meta sm ON sm.metadata_id = s.metadata_id"""
    if entities:
        q += " WHERE sm.entity_id IN (%s)" % ",".join("?" * len(entities))
    for r in con.execute(q, entities or ()):
        sid, ent, st, ts, ctx, par, usr, prev, chg = r
        ty = "pi" if usr else "delta"
        nodes.append(Node("s:%d" % sid, "state", ty, ts or 0.0, ent,
                          _canon({"t": "state", "e": ent, "s": st,
                                  "ts": round(ts or 0.0, 6)}),
                          ctx, par, "actuates",
                          usr=usr, prev=prev, changed=chg))
    for r in con.execute(
        """SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin,
                  e.context_parent_id_bin, ed.shared_data, e.context_user_id_bin
             FROM events e JOIN event_types et ON et.event_type_id = e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id = e.data_id"""):
        eid, ety, ts, ctx, par, data, usr = r
        try:
            payload = json.loads(data) if data else None
        except Exception:
            payload = None
        nodes.append(Node("e:%d" % eid, "event", classify_event(ety), ts or 0.0,
                          (payload or {}).get("entity_id"),
                          _canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6),
                                  "d": data}),
                          ctx, par, LABELS.get(ety, "causes"), payload, usr=usr))
    con.close()
    nodes.sort(key=lambda n: (n.ts, n.key))
    return nodes


def build_indexes(nodes: list[Node]):
    """Build the key and context indexes ONCE.

    attribution() previously rebuilt both on EVERY call. Called once per
    actuation that is O(n^2) overall -- measured at 17 s for a 20k-node fixture
    with 6k actuations, which stalled the deployment sweep.
    """
    by_key = {n.key: n for n in nodes}
    at_ctx: dict = {}
    for m in nodes:
        if m.ctx is not None:
            at_ctx.setdefault(m.ctx, []).append(m)
    return by_key, at_ctx


def attribution(nodes: list[Node], target_key: str, idx=None) -> dict:
    """Attr_G(alpha) -- the principal at the root of the causal ancestry, as the
    2026.7 timeline resolves it. Returns bottom (UNKNOWN) when none exists."""
    by_key, at_ctx = idx if idx is not None else build_indexes(nodes)
    n = by_key.get(target_key)
    if n is None:
        return {"verdict": "ABSENT"}
    peers = at_ctx.get(n.ctx, [])
    for m in peers:
        if m.kind == "event" and m.ty == "tau":
            name = (m.payload or {}).get("name")
            return {"verdict": "NAMED_INNOCENT", "principal": "automation:%s" % name}
    for m in peers:
        if m.kind == "event" and m.ty == "alpha":
            return {"verdict": "INTEGRATION", "principal": "service-call"}
    return {"verdict": "UNKNOWN"}
