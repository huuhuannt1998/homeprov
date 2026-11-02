"""Calibrated synthetic deployment generator (design section 11.2).

WHY SYNTHETIC. Booting Home Assistant per deployment costs ~2 minutes, so the
full parameter grid is not reachable by booting. Detection, localization and OQ
are properties of the PROVENANCE GRAPH's shape, not of HA's implementation, so a
generator that reproduces that shape is a sound substrate for the sweep.

WHY CALIBRATED, AND WHAT THAT DOES NOT BUY. The generator emits a real recorder
schema and reproduces the causal pattern MEASURED from HA 2026.7.4 in M1:
    trigger_state (ctx=T, par=NULL)
    automation_triggered (ctx=A, par=T)
    call_service (ctx=A, par=T)
    actuation states (ctx=A, par=T)
calibrate() reports the structural distance to the real deployment so the gap is
stated rather than assumed. It does NOT reproduce HA's exact entity mix,
attribute payloads, or timing jitter, and results on generated deployments are
therefore reported as such -- never merged with the measured single-deployment
results without saying which is which.

WE DO NOT BUILD OR RELEASE A LABELLED DATASET (VESPER boundary, decision D2).
These are ephemeral fixtures written to a temp dir and deleted after the run.
"""
from __future__ import annotations
import os, random, sqlite3

SCHEMA = """
CREATE TABLE states_meta (metadata_id INTEGER PRIMARY KEY, entity_id TEXT);
CREATE TABLE event_types (event_type_id INTEGER PRIMARY KEY, event_type TEXT);
CREATE TABLE event_data (data_id INTEGER PRIMARY KEY, hash INTEGER, shared_data TEXT);
CREATE TABLE states (
  state_id INTEGER PRIMARY KEY, metadata_id INTEGER, state TEXT,
  last_updated_ts FLOAT, last_changed_ts FLOAT, last_reported_ts FLOAT,
  context_id_bin BLOB, context_user_id_bin BLOB, context_parent_id_bin BLOB,
  origin_idx INTEGER, old_state_id INTEGER, attributes_id INTEGER);
CREATE TABLE events (
  event_id INTEGER PRIMARY KEY, event_type_id INTEGER, data_id INTEGER,
  time_fired_ts FLOAT, context_id_bin BLOB, context_user_id_bin BLOB,
  context_parent_id_bin BLOB, origin_idx INTEGER);
"""


# CALIBRATED AGAINST THE REAL DEPLOYMENT AS THE PAPER CHARACTERIZES IT, 2026-09-03.
#
# WHICH REAL DEPLOYMENT. The target is the published characterization -- 3,229
# nodes, 784 state rows, parent-context fraction 0.3227 -- NOT the live recorder
# as it stands now. The live recorder has since absorbed the evaluation suite's
# own traffic and measures 0.478 over 57,354 state rows; calibrating to that
# would be calibrating the generator to the experiments' footprint. The original
# database is gone, so the published stage34 artifact is the pinned baseline.
#
# The generated arm ran at bg_ratio 24.0, which gives a parent-context fraction
# of 0.091 against the real deployment's 0.323 -- three and a half times too
# sparse on the ONE swept structural parameter that moves the quarantine.
# Every generated-arm result rested on it, so the value is now FITTED: sweeping
# bg_ratio and measuring the fraction the way stage34 defines it (parents per
# STATE row, not per node) gives 4.4 -> 0.3221 against a target of 0.3227, and
# the fraction stays within 0.3204-0.3257 across the six deployment seeds.
#
# WHAT THIS DOES NOT FIX. Mean causal run is 1.204 at bg_ratio 4.4 against the
# real deployment's 1.151: the generator still builds slightly longer causal
# runs than the real hub. bg_ratio cannot close that -- lowering it raises both
# quantities together -- so the residual is reported rather than tuned away.
BG_RATIO = 4.4

def generate(path: str, params: dict, seed: int = 0, t0: float = 1_787_000_000.0) -> dict:
    """Emit a recorder-shaped database for one deployment point."""
    rng = random.Random(seed)
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path); cur = con.cursor()
    cur.executescript(SCHEMA)

    n_dev, n_aut = params["n_dev"], params["n_aut"]
    interlock, rate = params["interlock"], params["rate_hr"]
    hours = {"1d": 24, "7d": 24 * 7, "90d": 24 * 90}.get(params["history"], 24)
    span = float(params.get("span_s", hours * 3600.0))   # explicit span for the
    hours = span / 3600.0                                # OCCUPANCY sweep (G-3)
    # Bound the fixture. A 90-day history at 1000 events/hr is millions of rows,
    # which is a scale question (stage 6) not a sweep question -- the sweep varies
    # graph SHAPE. Cap total nodes and record the scaling so it is not silent.
    max_nodes = params.get("max_nodes", 30000)
    # target_nodes pins TOTAL graph size so that varying span varies OCCUPANCY
    # (nodes per second) without varying size -- the only way to test guarantee
    # G-3 without the confound that the max_nodes cap introduced.
    if params.get("target_nodes"):
        tgt = float(params["target_nodes"])
        n_runs = max(1, int(tgt / (6 * (1 + params.get("bg_ratio", BG_RATIO)))))
    else:
        n_runs = max(1, int(rate * hours / 4))      # each run emits ~6 nodes
    bg_ratio_pre = params.get("bg_ratio", BG_RATIO)
    est = n_runs * 6 * (1 + bg_ratio_pre)
    scaled = False
    if est > max_nodes:
        n_runs = max(1, int(n_runs * max_nodes / est)); scaled = True
    # BACKGROUND. Calibration against the real deployment showed the measured
    # graph is dominated by parentless background activity -- entity
    # registrations, component loads, standalone service calls -- with
    # with_parent = 0.012 and nodes_per_context = 1.03. A generator emitting
    # only causal chains produced with_parent = 0.833, which would have made the
    # whole sweep unrepresentative, because OQ depends on SEGMENT OCCUPANCY and
    # occupancy is dominated by that background.
    bg_ratio = params.get("bg_ratio", BG_RATIO)     # background nodes per causal node

    ents = (["input_boolean.trigger_%02d" % i for i in range(max(1, n_dev // 3))] +
            ["lock.dev_%02d" % i for i in range(max(1, n_dev // 3))] +
            ["automation.auto_%02d" % i for i in range(n_aut)])
    for i, e in enumerate(ents, 1):
        cur.execute("INSERT INTO states_meta (metadata_id, entity_id) VALUES (?,?)", (i, e))
    mid = {e: i for i, e in enumerate(ents, 1)}
    for i, t in enumerate(("automation_triggered", "call_service"), 1):
        cur.execute("INSERT INTO event_types (event_type_id, event_type) VALUES (?,?)", (i, t))

    trig = [e for e in ents if e.startswith("input_boolean")]
    lock = [e for e in ents if e.startswith("lock.")]
    auto = [e for e in ents if e.startswith("automation.")]
    sid = eid = did = 0
    prev: dict[int, int] = {}

    for r in range(n_runs):
        ts = t0 + (r / max(1, n_runs)) * span + rng.random() * 0.5
        A, T = os.urandom(16), os.urandom(16)
        a_ent = auto[rng.randrange(len(auto))]
        l_ent = lock[rng.randrange(len(lock))]
        # interlocked runs are triggered by ANOTHER automation's effect
        t_ent = (l_ent if rng.random() < interlock else trig[rng.randrange(len(trig))])

        def st(entity, val, tstamp, ctx, par):
            nonlocal sid
            sid += 1
            m = mid[entity]
            cur.execute("""INSERT INTO states (state_id,metadata_id,state,last_updated_ts,
                            last_changed_ts,last_reported_ts,context_id_bin,
                            context_parent_id_bin,origin_idx,old_state_id)
                           VALUES (?,?,?,?,?,?,?,?,0,?)""",
                        (sid, m, val, tstamp, tstamp, tstamp, ctx, par, prev.get(m)))
            prev[m] = sid

        def ev(etype, ts2, ctx, par, data):
            nonlocal eid, did
            did += 1; eid += 1
            cur.execute("INSERT INTO event_data (data_id,hash,shared_data) VALUES (?,?,?)",
                        (did, did, data))
            cur.execute("""INSERT INTO events (event_id,event_type_id,data_id,time_fired_ts,
                            context_id_bin,context_parent_id_bin,origin_idx)
                           VALUES (?,?,?,?,?,?,0)""",
                        (eid, 1 if etype == "automation_triggered" else 2, did, ts2, ctx, par))

        # the MEASURED HA 2026.7 attribution pattern
        st(t_ent, "on", ts, T, None)
        ev("automation_triggered", ts + 0.05, A, T,
           '{"entity_id":"%s","name":"%s"}' % (a_ent, a_ent))
        ev("call_service", ts + 0.06, A, T, '{"domain":"lock","service":"unlock"}')
        st(a_ent, "on", ts + 0.07, A, T)
        st(l_ent, "unlocking", ts + 0.10, A, T)
        st(l_ent, "unlocked", ts + 0.20, A, T)

    # background: single-node contexts, no parent, spread across the span
    n_bg = int(sid * bg_ratio)
    for b in range(n_bg):
        ts = t0 + rng.random() * span
        if rng.random() < 0.70:                     # measured: ~70% events
            did += 1; eid += 1
            cur.execute("INSERT INTO event_data (data_id,hash,shared_data) VALUES (?,?,?)",
                        (did, did, '{"domain":"sys","service":"bg"}'))
            cur.execute("""INSERT INTO events (event_id,event_type_id,data_id,time_fired_ts,
                            context_id_bin,context_parent_id_bin,origin_idx)
                           VALUES (?,2,?,?,?,NULL,0)""", (eid, did, ts, os.urandom(16)))
        else:
            sid += 1
            m = mid[ents[rng.randrange(len(ents))]]
            cur.execute("""INSERT INTO states (state_id,metadata_id,state,last_updated_ts,
                            last_changed_ts,last_reported_ts,context_id_bin,
                            context_parent_id_bin,origin_idx,old_state_id)
                           VALUES (?,?,?,?,?,?,?,NULL,0,?)""",
                        (sid, m, "bg", ts, ts, ts, os.urandom(16), prev.get(m)))
            prev[m] = sid

    con.commit(); con.close()
    return {"path": path, "params": params, "seed": seed, "runs": n_runs,
            "states": sid, "events": eid, "background": n_bg, "span_s": span,
            "downscaled": scaled, "max_nodes": max_nodes}


def calibrate(gen_db: str, real_db: str) -> dict:
    """Structural distance between a generated deployment and the REAL one.
    Reported so the fidelity gap is stated, never assumed away."""
    from .graph import load

    def stats(db):
        ns = load(db)
        if not ns:
            return {}
        span = max(n.ts for n in ns) - min(n.ts for n in ns) or 1.0
        ctxs = {n.ctx for n in ns if n.ctx}
        return {"nodes": len(ns),
                "with_parent": sum(1 for n in ns if n.par) / len(ns),
                "events_frac": sum(1 for n in ns if n.kind == "event") / len(ns),
                "contexts": len(ctxs),
                "nodes_per_context": len(ns) / max(1, len(ctxs)),
                "nodes_per_s": len(ns) / span}
    g, r = stats(gen_db), stats(real_db)
    return {"generated": g, "real": r,
            "delta": {k: (round(g[k] - r[k], 4) if isinstance(g.get(k), float) else None)
                      for k in ("with_parent", "events_frac", "nodes_per_context")}}
