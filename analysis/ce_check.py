"""HOMEPROV A10 CE-CHECK — exact single-class enumeration at matched budget.

Decides CE_b(G, G', alpha): is the achieved plausible re-attribution reachable
by ANY single forgery class at the SAME write budget? If yes, composition is
merely convenient and the paper narrows (Exit 2). If no, composition is
NECESSARY and claim CL stands.

Operates on snapshot_B.db - the recorder state immediately after the adversary
acted and before any forgery. Each arm gets its own copy.
"""
from __future__ import annotations
import json, os, shutil, sqlite3, sys

SNAP = sys.argv[1] if len(sys.argv) > 1 else "testbed/ha-config/homeprov_out/snapshot_B.db"
META = json.load(open(os.path.join(os.path.dirname(SNAP), "s1_report.json")))
ADV = bytes.fromhex(META["adversary_context"])
A_REAL = bytes.fromhex(META["A_innocent_automation_context"])
T_REAL = bytes.fromhex(META["A_innocent_trigger_context"])
ENTITY = "lock.kitchen_door"
WORK = "/tmp/homeprov_ce"

# Matched budget: rows written by the composed attack.
#   4 injected rows + 2 relabelled actuation rows + 1 deleted event = 7
BUDGET = 7


def fresh(tag):
    os.makedirs(WORK, exist_ok=True)
    dst = os.path.join(WORK, "ce_%s.db" % tag)
    shutil.copy(SNAP, dst)
    return sqlite3.connect(dst)


def mid(con, entity):
    r = con.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?", (entity,)).fetchone()
    return r[0] if r else None


def actuation_rows(con, ctx):
    """The adversary's actuation states (the object alpha)."""
    return con.execute(
        """SELECT s.state_id, s.state, s.context_id_bin, s.context_parent_id_bin
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id=? AND s.context_id_bin=? ORDER BY s.last_updated_ts""",
        (ENTITY, ctx)).fetchall()


# ------------------------------------------------------------------ oracles
def attr(con, state_ids):
    """Attr(alpha): resolve the causal root the 2026.7 timeline would display."""
    if not state_ids:
        return {"verdict": "ABSENT", "detail": "actuation no longer present"}
    row = con.execute(
        "SELECT context_id_bin, context_parent_id_bin FROM states WHERE state_id=?",
        (state_ids[-1],)).fetchone()
    if not row:
        return {"verdict": "ABSENT", "detail": "row gone"}
    ctx, par = row
    ev = con.execute(
        """SELECT et.event_type, ed.shared_data FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id
            WHERE e.context_id_bin=?""", (ctx,)).fetchall()
    types = {t for t, _ in ev}
    if "automation_triggered" in types:
        for t, d in ev:
            if t == "automation_triggered":
                name = json.loads(d).get("name") if d else None
                return {"verdict": "NAMED_INNOCENT", "principal": "automation:%s" % name}
    if "call_service" in types:
        # a bare service call with no automation above it: the caller is the cause
        return {"verdict": "INTEGRATION", "principal": "service-call (integration)"}
    if par is None:
        return {"verdict": "UNKNOWN", "detail": "no parent, no naming event"}
    return {"verdict": "UNKNOWN", "detail": "parent present but unresolvable"}


def plaus(con, ctx_used):
    """Plaus(G''): structural match to the genuine pattern + semantic invariants."""
    fails = []
    st = con.execute(
        """SELECT s.state_id, s.state, s.last_updated_ts, s.context_parent_id_bin
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id=? AND s.context_id_bin=? ORDER BY s.last_updated_ts""",
        (ENTITY, ctx_used)).fetchall()
    if not st:
        fails.append("no actuation states at the attributed context")
        return {"plausible": False, "failures": fails}

    ev = con.execute(
        """SELECT et.event_type FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
            WHERE e.context_id_bin=?""", (ctx_used,)).fetchall()
    types = {t for (t,) in ev}
    if "automation_triggered" not in types:
        fails.append("SI-4: actuation attributed to an automation with no automation_triggered event")
    if "call_service" not in types:
        fails.append("SI-4: automation-attributed actuation with no service call")

    # SI-5 / mode:single -- one automation run must not produce two disjoint
    # actuation episodes. Detect a temporal gap inside one context.
    ts = [r[2] for r in st]
    if len(ts) >= 2 and (max(ts) - min(ts)) > 5.0:
        fails.append("SI-5: one automation context spans %.1fs of actuations "
                     "(duplicate run under mode:single)" % (max(ts) - min(ts)))
    episodes = 1
    for a, b in zip(ts, ts[1:]):
        if b - a > 5.0:
            episodes += 1
    if episodes > 1:
        fails.append("SI-4: %d disjoint actuation episodes under a single automation run" % episodes)

    # residual naming: does any surviving event still name the adversary?
    adv = con.execute(
        """SELECT COUNT(*) FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
            WHERE e.context_id_bin=?""", (ADV,)).fetchone()[0]
    if adv:
        fails.append("residual: %d event(s) still bear the adversary's context" % adv)

    # competing causes: two independent chains claiming the same physical unlock
    unl = con.execute(
        """SELECT COUNT(DISTINCT s.context_id_bin) FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE sm.entity_id=? AND s.state='unlocked'
              AND s.last_updated_ts > (SELECT MIN(last_updated_ts) FROM states
                                        WHERE context_id_bin=?)""",
        (ENTITY, ADV)).fetchone()[0]
    if unl > 1:
        fails.append("competing causes: %d distinct contexts claim an unlock in the window" % unl)
    return {"plausible": not fails, "failures": fails}


# ------------------------------------------------------------- single-class arms
def arm_del_a():
    """F_del, variant a: delete the adversary's naming call_service only."""
    con = fresh("del_a"); cur = con.cursor()
    cur.execute("DELETE FROM events WHERE context_id_bin=?", (ADV,))
    w = cur.rowcount; con.commit()
    ids = [r[0] for r in actuation_rows(con, ADV)]
    res = {"arm": "F_del (a): erase naming event", "writes": w,
           "attr": attr(con, ids), "plaus": plaus(con, ADV)}
    con.close(); return res


def arm_del_b():
    """F_del, variant b: erase the actuation entirely (naming event + states)."""
    con = fresh("del_b"); cur = con.cursor()
    cur.execute("DELETE FROM events WHERE context_id_bin=?", (ADV,)); w = cur.rowcount
    cur.execute("""DELETE FROM states WHERE context_id_bin=? AND metadata_id=
                   (SELECT metadata_id FROM states_meta WHERE entity_id=?)""", (ADV, ENTITY))
    w += cur.rowcount; con.commit()
    res = {"arm": "F_del (b): erase the actuation entirely", "writes": w,
           "attr": attr(con, []), "plaus": plaus(con, ADV)}
    con.close(); return res


def arm_rep():
    """F_rep, strongest variant: re-point the adversary's actuation onto the REAL
    innocent automation context from phase A. This is the arm that could break
    claim CL, so it is given every advantage within budget."""
    con = fresh("rep"); cur = con.cursor()
    cur.execute("""UPDATE states SET context_id_bin=?, context_parent_id_bin=?
                    WHERE context_id_bin=? AND metadata_id=
                    (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
                (A_REAL, T_REAL, ADV, ENTITY))
    w = cur.rowcount
    # spend remaining budget re-pointing the naming event too
    if w < BUDGET:
        cur.execute("""UPDATE events SET context_id_bin=?, context_parent_id_bin=?
                        WHERE context_id_bin=?""", (A_REAL, T_REAL, ADV))
        w += cur.rowcount
    con.commit()
    ids = [r[0] for r in actuation_rows(con, A_REAL)]
    res = {"arm": "F_rep: re-point onto the real innocent automation", "writes": w,
           "attr": attr(con, ids), "plaus": plaus(con, A_REAL)}
    con.close(); return res


def arm_inj():
    """F_inj, strongest variant: fabricate a complete innocent chain including
    its own actuation states, spending the full budget."""
    con = fresh("inj"); cur = con.cursor()
    A_F, T_F = os.urandom(16), os.urandom(16)
    base = con.execute(
        """SELECT MIN(last_updated_ts) FROM states WHERE context_id_bin=?""", (ADV,)).fetchone()[0]
    m_ob = mid(con, "input_boolean.owner_present"); m_lk = mid(con, ENTITY)
    w = 0
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                     last_reported_ts,context_id_bin,origin_idx) VALUES (?,?,?,?,?,?,0)""",
                (m_ob, "on", base - 2, base - 2, base - 2, T_F)); w += 1
    et = cur.execute("SELECT event_type_id FROM event_types WHERE event_type=?",
                     ("automation_triggered",)).fetchone()[0]
    d = json.dumps({"entity_id": "automation.arrive_home", "name": "Arrive Home"})
    cur.execute("INSERT INTO event_data (hash,shared_data) VALUES (?,?)", (1, d))
    cur.execute("""INSERT INTO events (event_type_id,data_id,origin_idx,time_fired_ts,
                     context_id_bin,context_parent_id_bin) VALUES (?,?,0,?,?,?)""",
                (et, cur.lastrowid, base - 1.5, A_F, T_F)); w += 1
    et2 = cur.execute("SELECT event_type_id FROM event_types WHERE event_type=?",
                      ("call_service",)).fetchone()[0]
    d2 = json.dumps({"domain": "lock", "service": "unlock"})
    cur.execute("INSERT INTO event_data (hash,shared_data) VALUES (?,?)", (2, d2))
    cur.execute("""INSERT INTO events (event_type_id,data_id,origin_idx,time_fired_ts,
                     context_id_bin,context_parent_id_bin) VALUES (?,?,0,?,?,?)""",
                (et2, cur.lastrowid, base - 1.4, A_F, T_F)); w += 1
    for stv, off in (("unlocking", -0.2), ("unlocked", 0.0)):
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                         last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                       VALUES (?,?,?,?,?,?,?,0)""",
                    (m_lk, stv, base + off, base + off, base + off, A_F, T_F)); w += 1
    con.commit()
    ids = [r[0] for r in actuation_rows(con, ADV)]   # the REAL actuation is untouched
    res = {"arm": "F_inj: fabricate a complete decoy chain", "writes": w,
           "attr_of_real_actuation": attr(con, ids),
           "attr_of_decoy": attr(con, [r[0] for r in actuation_rows(con, A_F)]),
           "plaus": plaus(con, A_F)}
    con.close(); return res


if __name__ == "__main__":
    arms = [arm_del_a(), arm_del_b(), arm_rep(), arm_inj()]
    print("=" * 78)
    print("A10 CE-CHECK  |  matched budget b = %d row-writes" % BUDGET)
    print("target: Attr(alpha) = NAMED_INNOCENT  AND  Plaus = True")
    print("=" * 78)
    reached = []
    for a in arms:
        av = a.get("attr") or a.get("attr_of_real_actuation")
        ok = av["verdict"] == "NAMED_INNOCENT" and a["plaus"]["plausible"]
        reached.append(ok)
        print("\n%-52s writes=%d" % (a["arm"], a["writes"]))
        print("   Attr      : %-16s %s" % (av["verdict"], av.get("principal") or av.get("detail","")))
        if "attr_of_decoy" in a:
            print("   Attr(decoy): %-16s %s" % (a["attr_of_decoy"]["verdict"],
                                                a["attr_of_decoy"].get("principal","")))
        print("   Plaus     : %s" % a["plaus"]["plausible"])
        for f in a["plaus"]["failures"]:
            print("       FAIL  %s" % f)
        print("   -> reaches the composed outcome: %s" % ok)
    print("\n" + "=" * 78)
    print("CE_b = %d   (%s)" % (0 if any(reached) else 1,
          "some single class reaches it -> composition NOT necessary -> EXIT 2"
          if any(reached) else
          "no single class reaches it -> COMPOSITION IS NECESSARY -> claim CL holds"))
    print("=" * 78)
    json.dump([{k: v for k, v in a.items()} for a in arms],
              open("analysis/ce_check_result.json", "w"), indent=2, default=str)
