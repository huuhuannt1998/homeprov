"""STAGE 18 — the live-hub benign arms: BE-1, BE-6, BE-8, BE-9, BE-10.

These five could never run on the snapshot arm because they are properties of a
RUNNING Home Assistant, not of a database file: a real restart, a real
integration reload, genuinely interleaved automation runs, a clean shutdown, and
a write failure. BFP so far rests on 7 of 11 catalog entries; this closes it.
"""
import json, math, os, shutil, sqlite3, subprocess, time
from rig import graph, verify, markers, baselines, stats, capability
from rig.commit import commit_full, GRAN

CONTAINER = "homeprov-ha"
# Stages are executed with cwd=exp/, so the host side of the /config bind mount
# must be resolved from this file, not from a path relative to the cwd.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HA_CONFIG = os.path.join(PROJECT_ROOT, "testbed", "ha-config")
CFG_DB = os.path.join(HA_CONFIG, "home-assistant_v2.db")


def _sh(args, t=180):
    return subprocess.run(args, capture_output=True, text=True, timeout=t)


def _snapshot(tag, retries=4):
    """WAL-safe copy of the live recorder, VALIDATED, with the reason reported.

    Two failure modes have been observed and both are guarded here. The first
    live-hub run lost 3 of 5 arms to a bare "snapshot failed" with no diagnosis.
    The second produced a file that passed a size check and then read back as
    "database disk image is malformed" — a size test can pass without the copy
    being a database, which is the same defect in a different place. The copy is
    therefore opened and queried before it is accepted.

    /config is a bind mount of the host testbed directory, so the in-container
    backup lands on the host directly; the previous `docker cp` was a second
    copy and a second chance to race.
    """
    host_side = os.path.join(HA_CONFIG, "live_%s.db" % tag)
    dst = "/tmp/homeprov_live_%s.db" % tag
    last = ""
    for _attempt in range(retries):
        for f in (dst, host_side):
            if os.path.exists(f):
                os.remove(f)
        r1 = _sh(["docker", "exec", CONTAINER, "python", "-c",
                  "import sqlite3;s=sqlite3.connect('/config/home-assistant_v2.db');"
                  "d=sqlite3.connect('/config/live_%s.db');s.backup(d);"
                  "d.close();s.close();print('ok')" % tag])
        if os.path.exists(host_side):
            shutil.move(host_side, dst)
        if os.path.exists(dst):
            try:
                con = sqlite3.connect("file:%s?mode=ro" % dst, uri=True)
                n_ev = con.execute("select count(*) from events").fetchone()[0]
                n_st = con.execute("select count(*) from states").fetchone()[0]
                ok = con.execute("PRAGMA integrity_check").fetchone()[0]
                con.close()
                if ok == "ok" and n_ev > 0 and n_st > 0:
                    return dst
                last = "integrity=%s events=%s states=%s" % (ok, n_ev, n_st)
            except sqlite3.Error as exc:
                last = "unreadable copy: %s" % exc
        else:
            last = "backup_rc=%s %s" % (r1.returncode,
                                        (r1.stderr or r1.stdout).strip()[:140])
        time.sleep(4)
    _snapshot.last_error = last
    return None


def _bench(cmd, wait=40):
    """Drive a benign hub operation IN-PROCESS and confirm it actually ran.

    Returns the parsed ack dict, or None. The confirmation is the point: the
    first version of BE-6 executed `import urllib.request; pass`, which cannot
    fail and cannot do anything, and its "no false alarm" was therefore vacuous.
    An arm that reports success without evidence of having acted is not an arm.
    """
    _sh(["docker", "exec", CONTAINER, "rm", "-f", "/config/bench_ack"])
    _sh(["docker", "exec", CONTAINER, "sh", "-c",
         "printf %s " + cmd + " > /config/bench_cmd"])
    for _ in range(wait):
        r = _sh(["docker", "exec", CONTAINER, "sh", "-c",
                 "cat /config/bench_ack 2>/dev/null"])
        if r.stdout.strip():
            try:
                return json.loads(r.stdout.strip())
            except json.JSONDecodeError:
                return None
        time.sleep(1)
    return None


def run(cfg):
    rows = []
    before = _snapshot("before")
    if not before:
        return {"stage": 18, "error": "could not snapshot the live hub"}
    base = graph.load(before)
    head = max(n.ts for n in base)
    phi = {s: commit_full(base, s) for s in ("homeprov", "b2")}

    def measure(be, mk=None, note="", ack=None):
        after_db = _snapshot("after_%s" % be.replace("-", ""))
        if not after_db:
            rows.append({"be": be,
                         "error": "snapshot failed: %s"
                                  % getattr(_snapshot, "last_error", "?")}); return
        if ack is not None and not ack.get("ok"):
            rows.append({"be": be, "note": note,
                         "error": "benign operation did not execute: %r" % (ack,)})
            os.remove(after_db); return
        after = graph.load(after_db)
        raw = verify.verify(after, phi["homeprov"], head, "homeprov")
        filt = (markers.filter_violations(raw["violations"], [mk], GRAN, nodes=after)
                if mk else raw)
        b2 = baselines.b2_record_level(after, phi["b2"], head)
        rows.append({"be": be, "note": note,
                     "hp_alarm": 1.0 if filt["detected"] else 0.0,
                     "b2_alarm": 1.0 if b2["detected"] else 0.0,
                     "raw": raw["n_violations"],
                     "new_nodes": len(after) - len(base),
                     "ack": ack})
        os.remove(after_db)

    # BE-6 integration reload with NO restart, driven in-process and confirmed.
    ack6 = _bench("reload")
    time.sleep(4); measure("BE-6", note="automation/YAML integration reload", ack=ack6)

    # BE-8 genuinely INTERLEAVED runs: eight concurrent service calls, so several
    # context chains are open at once. Previously this was a bare sleep(12) that
    # hoped the hub's own automations would overlap; they did not (2 new nodes).
    ack8 = _bench("interleave")
    time.sleep(6); measure("BE-8", note="8 concurrent service calls, live hub", ack=ack8)

    # BE-10 transient write failure. The earlier `chmod a-w /config` ran as root,
    # and root bypasses the DAC write bits, so the recorder never saw a failure.
    # An EXCLUSIVE sqlite transaction held from a second process does produce a
    # real one: recorder writes get SQLITE_BUSY for the duration.
    lock = subprocess.Popen(
        ["docker", "exec", CONTAINER, "python", "-c",
         "import sqlite3,time;c=sqlite3.connect('/config/home-assistant_v2.db',timeout=1);"
         "c.execute('BEGIN EXCLUSIVE');print('locked',flush=True);time.sleep(6);"
         "c.rollback();c.close()"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)
    busy = _sh(["docker", "exec", CONTAINER, "python", "-c",
                "import sqlite3;c=sqlite3.connect('/config/home-assistant_v2.db',timeout=0.5);"
                "\ntry:\n c.execute('BEGIN IMMEDIATE');print('NOT_BUSY')\n"
                "except Exception as e:print('BUSY',type(e).__name__)"])
    lock.wait(timeout=60)
    time.sleep(4)
    measure("BE-10", note="transient write failure (exclusive lock)",
            ack={"ok": "BUSY" in busy.stdout, "probe": busy.stdout.strip()})

    # BE-1 restart
    _sh(["docker", "restart", CONTAINER], t=180)
    for _ in range(40):
        lg = _sh(["docker", "logs", "--tail", "40", CONTAINER]).stdout
        if "Initialized trigger" in lg or "HOMEPROV" in lg:
            break
        time.sleep(5)
    time.sleep(8)
    measure("BE-1", mk=markers.marker(markers.RESTART), note="full HA restart")

    # BE-9 clean shutdown then start
    _sh(["docker", "stop", CONTAINER], t=180)
    _sh(["docker", "start", CONTAINER], t=180)
    for _ in range(40):
        lg = _sh(["docker", "logs", "--tail", "40", CONTAINER]).stdout
        if "Initialized trigger" in lg or "HOMEPROV" in lg:
            break
        time.sleep(5)
    time.sleep(8)
    measure("BE-9", mk=markers.marker(markers.RESTART), note="clean shutdown then start")

    os.remove(before)
    ok = [r for r in rows if "error" not in r]
    failed = [r for r in rows if "error" in r]
    n = len(ok)
    k_hp = int(sum(r["hp_alarm"] for r in ok))
    k_b2 = int(sum(r["b2_alarm"] for r in ok))
    # AN ARM THAT DID NOT RUN IS NOT AN ARM THAT RAISED NO ALARM.
    # A prior artifact recorded n=2 with three arms erroring "snapshot failed"
    # and still reported GATE_PASS true, because the gate counted only the arms
    # that succeeded. Absence of a measurement was being credited as absence of
    # a false alarm. The gate now requires every declared arm to have run.
    return {"stage": 18, "rows": rows, "n": n,
            "n_failed": len(failed),
            "failed_arms": [r.get("be") for r in failed],
            "BFP_homeprov_livehub": stats.clopper_pearson(k_hp, n) if n else None,
            "BFP_b2_livehub": stats.clopper_pearson(k_b2, n) if n else None,
            "GATE_PASS": (bool(n) and not failed and k_hp == 0),
            "capability": capability.record("none", "in_process_integration", 0, 0, 5)}
