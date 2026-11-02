"""M2 preregistered contrast 1 & 3: does edge binding buy F_rep detection?

Anchors a clean recorder DB under both schemes, applies each forgery class
from the M1 taxonomy to independent copies, and verifies.

HYPOTHESIS (mechanical, from M1's measurement that re-parenting leaves record
content byte-identical): B2 detects F_del and F_inj but MISSES F_rep.
HOMEPROV detects all of them.
"""
from __future__ import annotations
import json, os, shutil, sqlite3, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from homeprov_core import anchor, verify

SNAP = "testbed/ha-config/homeprov_out/snapshot_B.db"
META = json.load(open("testbed/ha-config/homeprov_out/s1_report.json"))
ADV = bytes.fromhex(META["adversary_context"])
A_REAL = bytes.fromhex(META["A_innocent_automation_context"])
T_REAL = bytes.fromhex(META["A_innocent_trigger_context"])
ENT = "lock.kitchen_door"
WORK = "/tmp/homeprov_m2"


def copy(tag):
    os.makedirs(WORK, exist_ok=True)
    d = os.path.join(WORK, "%s.db" % tag)
    shutil.copy(SNAP, d)
    return d


def _mid(con, ent):
    r = con.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?", (ent,)).fetchone()
    return r[0] if r else None


def _actuation_ts(con):
    return con.execute("SELECT MIN(last_updated_ts) FROM states WHERE context_id_bin=?",
                       (ADV,)).fetchone()[0]


# ---------------------------------------------------------------- forgeries
def ft1_delete(db):
    """F_del — erase the adversary's naming event."""
    con = sqlite3.connect(db)
    con.execute("DELETE FROM events WHERE context_id_bin=?", (ADV,))
    con.commit(); con.close()


def ft4_reparent(db):
    """F_rep — PURE edge re-parent. Touches ONLY context_parent_id_bin.
    No content changes, no rows added or removed."""
    con = sqlite3.connect(db)
    con.execute("""UPDATE states SET context_parent_id_bin=? WHERE context_id_bin=?
                     AND metadata_id=(SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
                (A_REAL, ADV, ENT))
    con.commit(); con.close()


def ft7_inject(db):
    """F_inj — fabricate a trigger state."""
    con = sqlite3.connect(db); cur = con.cursor()
    ts = _actuation_ts(con) - 2.0
    m = _mid(con, "input_boolean.owner_present")
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                     last_reported_ts,context_id_bin,origin_idx) VALUES (?,?,?,?,?,?,0)""",
                (m, "on", ts, ts, ts, os.urandom(16)))
    con.commit(); con.close()


def ft10_composed(db):
    """FT-10 — the full causal laundering exactly as demonstrated in M1."""
    con = sqlite3.connect(db); cur = con.cursor()
    base = _actuation_ts(con)
    A_F, T_F = os.urandom(16), os.urandom(16)
    m_ob, m_au = _mid(con, "input_boolean.owner_present"), _mid(con, "automation.arrive_home")
    for m, val, off, ctx, par in ((m_ob, "on", -2.0, T_F, None),
                                  (m_au, "on", -1.3, A_F, T_F)):
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                         last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                       VALUES (?,?,?,?,?,?,?,0)""",
                    (m, val, base+off, base+off, base+off, ctx, par))
    for ety, data, off in (("automation_triggered",
                            {"entity_id": "automation.arrive_home", "name": "Arrive Home"}, -1.5),
                           ("call_service", {"domain": "lock", "service": "unlock"}, -1.4)):
        et = cur.execute("SELECT event_type_id FROM event_types WHERE event_type=?", (ety,)).fetchone()[0]
        cur.execute("INSERT INTO event_data (hash,shared_data) VALUES (?,?)",
                    (1, json.dumps(data, sort_keys=True)))
        cur.execute("""INSERT INTO events (event_type_id,data_id,origin_idx,time_fired_ts,
                         context_id_bin,context_parent_id_bin) VALUES (?,?,0,?,?,?)""",
                    (et, cur.lastrowid, base+off, A_F, T_F))
    cur.execute("""UPDATE states SET context_id_bin=?, context_parent_id_bin=?
                    WHERE context_id_bin=? AND metadata_id=
                    (SELECT metadata_id FROM states_meta WHERE entity_id=?)""",
                (A_F, T_F, ADV, ENT))
    cur.execute("DELETE FROM events WHERE context_id_bin=?", (ADV,))
    con.commit(); con.close()


ARMS = [("FT-1  F_del  delete naming event", ft1_delete),
        ("FT-4  F_rep  PURE edge re-parent", ft4_reparent),
        ("FT-7  F_inj  inject fabricated trigger", ft7_inject),
        ("FT-10 composed causal laundering", ft10_composed)]

if __name__ == "__main__":
    phi = {s: anchor(SNAP, s) for s in ("homeprov", "b2")}
    # control: no tampering at all
    rows = [("(control) untampered", verify(SNAP, phi["homeprov"], "homeprov"),
             verify(SNAP, phi["b2"], "b2"))]
    for name, fn in ARMS:
        d = copy(name.split()[0].replace("-", ""))
        fn(d)
        rows.append((name, verify(d, phi["homeprov"], "homeprov"),
                     verify(d, phi["b2"], "b2")))

    print("=" * 78)
    print("M2 DETECTION MATRIX — same graph, same anchor, same segmentation.")
    print("Only difference: whether causal structure is bound into the hash.")
    print("=" * 78)
    print("%-40s %-16s %-16s" % ("forgery", "HOMEPROV", "B2 (record-level)"))
    print("-" * 78)
    out = []
    for name, hp, b2 in rows:
        f = lambda r: ("DETECTED (%d)" % r["n_violations"]) if r["detected"] else "MISSED"
        print("%-40s %-16s %-16s" % (name, f(hp), f(b2)))
        out.append({"arm": name, "homeprov": hp["detected"], "b2": b2["detected"],
                    "hp_violations": hp["n_violations"], "b2_violations": b2["n_violations"]})
    print("-" * 78)
    rep = [o for o in out if "F_rep" in o["arm"]][0]
    ctl = out[0]
    print("CONTRAST 1  HOMEPROV detects F_rep, B2 does not : %s"
          % ("CONFIRMED" if rep["homeprov"] and not rep["b2"] else "NOT CONFIRMED"))
    print("CONTROL     no false positive on untampered DB  : %s"
          % ("PASS" if not ctl["homeprov"] and not ctl["b2"] else "FAIL"))
    json.dump(out, open("analysis/m2_detection_result.json", "w"), indent=2)
