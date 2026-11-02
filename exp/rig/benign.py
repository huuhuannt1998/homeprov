"""BE-1 .. BE-11 — the predeclared benign catalog. NONE may trigger an alarm.

BFP is a first-class gate (<= 0.01). A system with high BFP is unusable
regardless of its security properties, and generic tamper-evident schemes fail
here precisely because they cannot tell a legitimate discontinuity from an
attack. HOMEPROV commits explicit LIFECYCLE MARKERS so a legitimate
discontinuity is itself anchored.

BE-11 was ADDED FROM MEASUREMENT in M1, not designed in: a template lock's
derived state row carries context_parent_id=NULL even for a genuine
automation-driven actuation. Any defender treating a missing parent as
suspicious false-positives on every template entity.
"""
from __future__ import annotations
import os, shutil, sqlite3, subprocess, time

MARKERS = ("RESTART", "PURGE", "MIGRATE", "RESTORE", "CLOCK_STEP", "RELOAD", "SHUTDOWN")


def _head(con) -> float:
    """The graph head: max over states AND events. A states-only head silently
    places appended rows BEHIND the true head, where they look backdated."""
    a = con.execute("SELECT MAX(last_updated_ts) FROM states").fetchone()[0] or 0.0
    b = con.execute("SELECT MAX(time_fired_ts) FROM events").fetchone()[0] or 0.0
    return max(a, b)


def _run(a): return subprocess.run(a, capture_output=True, text=True)


def be1_restart(container="homeprov-ha"):
    _run(["docker", "restart", container]); return {"be": "BE-1", "applied": True}


def be2_purge(db, keep_s=60.0):
    """Recorder auto-purge at the retention boundary.

    CORRECTED 2026-08-20: HA's recorder purges BOTH states and events. Purging
    only states left old events behind, so the PURGE lifecycle marker was
    correctly REFUSED (its wholesale claim was false) and BFP stayed high for a
    modelling reason rather than a real one.
    """
    con = sqlite3.connect(db)
    # HEAD = max over states AND events. Using states alone made the purge cutoff
    # disagree with the marker's declared cutoff, so rows survived below it, the
    # PURGE marker was refused wholesale, and 6,835 SEGMENT_GONE violations fired.
    head = _head(con)
    cut = head - keep_s
    n = con.execute("DELETE FROM states WHERE last_updated_ts < ?", (cut,)).rowcount
    n += con.execute("DELETE FROM events WHERE time_fired_ts < ?", (cut,)).rowcount
    con.commit(); con.close()
    # RETURN the cutoff actually used, so the marker can declare exactly it.
    return {"be": "BE-2", "purged_rows": n, "cutoff": cut}


def be3_migrate(db):
    con = sqlite3.connect(db)
    try:
        con.execute("ALTER TABLE states ADD COLUMN homeprov_migration_probe INTEGER")
        con.commit(); ok = True
    except sqlite3.OperationalError:
        ok = False
    con.close(); return {"be": "BE-3", "applied": ok}


def be4_restore(db, snapshot):
    shutil.copy(snapshot, db); return {"be": "BE-4", "restored_from": snapshot}


def be5_clock_step(db, delta_s=-120.0):
    """NTP step. Stresses T-5, the clock assumption.

    CORRECTED 2026-08-20. The first model shifted EVERY row's timestamp, which
    is not what a clock step does and is not what DST does either: Home
    Assistant stores UTC, so a DST transition changes no stored value at all.
    That model produced a 100% false-alarm rate and a meaningless BFP.

    The realistic and genuinely hard case is a BACKWARD NTP step: new events are
    written with timestamps that fall into ALREADY-SEALED segments, which is
    exactly the signature of backdated injection. This is the honest test.
    """
    con = sqlite3.connect(db); cur = con.cursor()
    mx = _head(con)
    m = cur.execute("SELECT metadata_id FROM states_meta LIMIT 1").fetchone()[0]
    ts = mx + delta_s                       # backward step -> lands in sealed time
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                    last_reported_ts,context_id_bin,origin_idx)
                   VALUES (?,?,?,?,?,?,0)""",
                (m, "on", ts, ts, ts, os.urandom(16)))
    con.commit(); con.close()
    return {"be": "BE-5", "model": "backward NTP step; new row lands in sealed time",
            "delta_s": delta_s,
            "expected": "WILL alarm without an anchored CLOCK_STEP lifecycle marker"}


def be6_reload(container="homeprov-ha"):
    return {"be": "BE-6", "note": "integration reload; exercised via HA service call"}


def be7_unavailable(db, entity):
    con = sqlite3.connect(db); cur = con.cursor()
    m = cur.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?",
                    (entity,)).fetchone()
    if not m:
        con.close(); return {"be": "BE-7", "applied": False}
    ts = _head(con) + 0.5
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                    last_reported_ts,origin_idx) VALUES (?,?,?,?,?,0)""",
                (m[0], "unavailable", ts, ts, ts))
    con.commit(); con.close(); return {"be": "BE-7", "applied": True}


def be8_interleave(db):
    return {"be": "BE-8", "note": "concurrent automation runs; produced by the workload driver"}


def be9_clean_shutdown(container="homeprov-ha"):
    _run(["docker", "stop", container]); _run(["docker", "start", container])
    return {"be": "BE-9", "applied": True}


def be10_disk_full(db):
    return {"be": "BE-10", "note": "write failure; simulated by a read-only remount arm"}


def be11_template_context_loss(db, entity):
    """MEASURED benign attribution loss. A template entity's derived state row
    carries context_parent_id = NULL even under a genuine automation-driven
    actuation. Adversary-independent."""
    con = sqlite3.connect(db); cur = con.cursor()
    m = cur.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?",
                    (entity,)).fetchone()
    if not m:
        con.close(); return {"be": "BE-11", "applied": False}
    ts = _head(con) + 0.5
    cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                    last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                   VALUES (?,?,?,?,?,?,NULL,0)""",
                (m[0], "unlocked", ts, ts, ts, os.urandom(16)))
    con.commit(); con.close()
    return {"be": "BE-11", "applied": True,
            "note": "derived row with NULL parent, as measured in M1"}


CATALOG = {"BE-1": be1_restart, "BE-2": be2_purge, "BE-3": be3_migrate,
           "BE-4": be4_restore, "BE-5": be5_clock_step, "BE-6": be6_reload,
           "BE-7": be7_unavailable, "BE-8": be8_interleave, "BE-9": be9_clean_shutdown,
           "BE-10": be10_disk_full, "BE-11": be11_template_context_loss}
