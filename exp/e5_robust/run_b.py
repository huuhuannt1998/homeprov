"""E-B / E5b -- monitor robustness over hostile input, WITH THE ANCHOR RUNNING.

The prior e5_robust run reported ConnectionRefused throughout (anchor not up),
so anchoring behaviour was not evidenced, and the monitor sealed silently over a
truncated WAL. This re-runs every condition against a live signed anchor with the
FAIL-CLOSED monitor (monitor.validate_copy), and checks the anchor chain for the
explicit 'evidence unobservable' record.

Substrate: a COPY of a live Home Assistant recorder (the deployment's own DB was
reset, so a live recorder from another local HA container is copied; only a copy
is ever touched). Each condition applies the exact e5_robust corruption recipe to
a fresh restore of that copy.
"""
import json, os, shutil, sqlite3, subprocess, sys, time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "exp"))
from rig import capability  # noqa: E402

SRC = os.environ.get("E5B_SRC", "/private/tmp/claude-501/-Users-huanbui-Research/"
                     "fcdf91f1-466b-418b-ab46-c45ec6cd7ad9/scratchpad/e5copy")
WORK = "/tmp/hpr_e5b"
NET = "hpr-e5b-net"
ANCHOR = "hpr-anchord-e5b"
MON_IMG = "hpr-monitor:sig"
ANC_IMG = "hpr-anchord:sig"
PORT = 9973
KEY = "hpr-monitor-key-2026-09-08"
CONDS = ["baseline", "db_missing", "db_empty_schema", "wal_truncated",
         "shm_deleted", "db_unreadable", "page_header_corrupt", "wal_header_corrupt"]


def sh(*a, t=120):
    return subprocess.run(list(a), capture_output=True, text=True, timeout=t)


def restore():
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK + "/db"); os.makedirs(WORK + "/scratch")
    for f in os.listdir(SRC):
        shutil.copy2(os.path.join(SRC, f),
                     os.path.join(WORK + "/db", f.replace("rec.db", "recorder.db")))
    return WORK + "/db/recorder.db"


def corrupt(cond, db):
    if cond == "db_missing":
        os.rename(db, db + ".moved")
    elif cond == "db_empty_schema":
        for s in ("", "-wal", "-shm"):
            if os.path.exists(db + s):
                os.remove(db + s)
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE states (state_id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE states_meta (metadata_id INTEGER PRIMARY KEY, entity_id TEXT)")
        c.execute("CREATE TABLE events (event_id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE event_types (event_type_id INTEGER PRIMARY KEY, event_type TEXT)")
        c.commit(); c.close()
    elif cond == "wal_truncated":
        if os.path.exists(db + "-wal"):
            open(db + "-wal", "w").close()
    elif cond == "shm_deleted":
        if os.path.exists(db + "-shm"):
            os.remove(db + "-shm")
    elif cond == "db_unreadable":
        os.chmod(db, 0)
    elif cond == "page_header_corrupt":
        f = open(db, "r+b"); f.seek(24); f.write(b"\xde\xad\xbe\xef" * 4); f.close()
    elif cond == "wal_header_corrupt":
        if os.path.exists(db + "-wal"):
            f = open(db + "-wal", "r+b"); f.seek(0); f.write(b"\x00" * 32); f.close()


def anchor_lines():
    r = sh("docker", "exec", ANCHOR, "sh", "-c",
           "wc -l < /anchor/chain.jsonl 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0


def anchor_tail(n):
    r = sh("docker", "exec", ANCHOR, "sh", "-c",
           "tail -n %d /anchor/chain.jsonl 2>/dev/null" % n)
    recs = []
    for ln in r.stdout.splitlines():
        try:
            recs.append(json.loads(ln))
        except Exception:
            pass
    return recs


def run_monitor(db):
    # fresh scratch each run so the monitor re-folds from scratch
    shutil.rmtree(WORK + "/scratch", ignore_errors=True); os.makedirs(WORK + "/scratch")
    r = sh("docker", "run", "--rm", "--network", NET,
           "-v", WORK + "/db:/cfg:ro", "-v", WORK + "/scratch:/scratch",
           "-e", "HOMEPROV_DB=/cfg/recorder.db",
           "-e", "HOMEPROV_ANCHOR=http://%s:9900/append" % ANCHOR,
           "-e", "HOMEPROV_ANCHOR_KEY=" + KEY,
           "-e", "HOMEPROV_SCRATCH=/scratch",
           MON_IMG, "python3", "/app/monitor.py", "--once")
    return r.stdout.strip(), r.stderr.strip()


def main():
    sh("docker", "network", "create", NET)
    sh("docker", "rm", "-f", ANCHOR)
    sh("docker", "run", "-d", "--name", ANCHOR, "--network", NET,
       "-e", "HOMEPROV_ANCHOR_KEY=" + KEY, "-e", "PUBLISH_PERIOD=3600", ANC_IMG)
    time.sleep(1.5)

    # baseline node count first
    db = restore()
    base_out, _ = run_monitor(db)
    try:
        base_nodes = json.loads(base_out.splitlines()[-1]).get("n_nodes")
    except Exception:
        base_nodes = None

    results = {}
    for cond in CONDS:
        db = restore()
        corrupt(cond, db)
        before = anchor_lines()
        out, err = run_monitor(db)
        if cond == "db_unreadable":
            os.chmod(db, 0o644)
        after = anchor_lines()
        new_recs = anchor_tail(max(after - before, 1)) if after > before else []
        try:
            tick = json.loads(out.splitlines()[-1]) if out else {}
        except Exception:
            tick = {"raw": (out or err)[:200]}
        unobs = any(r.get("payload", {}).get("evidence_unobservable")
                    for r in new_recs)
        sealed_rec = any(r.get("payload", {}).get("sealed") for r in new_recs)
        n_nodes = tick.get("n_nodes")
        results[cond] = {
            "monitor_out": tick,
            "n_nodes": n_nodes,
            "nodes_lost_vs_baseline": (base_nodes - n_nodes)
                if (base_nodes and isinstance(n_nodes, int)) else None,
            "fail_closed": bool(tick.get("fail_closed")),
            "evidence_unobservable_record_in_chain": unobs,
            "sealed_record_in_chain": sealed_rec,
            "anchor_records_added": after - before,
            "detected": bool(unobs) if cond != "baseline" else None,
        }

    sh("docker", "rm", "-f", ANCHOR)
    sh("docker", "network", "rm", NET)

    out = {"experiment": "E-B / E5b",
           "what": "monitor robustness over hostile input WITH the anchor "
                   "running and the fail-closed monitor",
           "substrate": "copy of a live HA recorder (%s); only a copy touched" % SRC,
           "baseline_nodes": base_nodes,
           "conditions": results,
           "silent_loss_conditions_now_detected": [
               c for c in ("wal_truncated", "wal_header_corrupt")
               if results.get(c, {}).get("evidence_unobservable_record_in_chain")],
           "prior_run_note": "e5_robust.json reported ConnectionRefused throughout "
                             "and silent_loss on wal_truncated/wal_header_corrupt "
                             "(6409 of 6857 nodes sealed with no record)",
           "capability": capability.record(
               actor_id="wal_corruptor", actor_position="in_process_integration",
               seed=0, budget_writes=None, window_s=None,
               knowledge={"can_corrupt_wal_shm": True},
               constraints={"anchor_key_access": False},
               substrate={"kind": "docker_monitor + docker_signed_anchor",
                          "monitor_image": MON_IMG, "anchor_image": ANC_IMG},
               mission="E-B fail-closed monitor")}
    dig = capability.stamp(out, os.path.join(ROOT, "exp", "out", "e5b_robust_anchored.json"))
    for c, v in results.items():
        print("%-20s nodes=%-6s lost=%-5s fail_closed=%-5s unobs_record=%-5s detected=%s"
              % (c, v["n_nodes"], v["nodes_lost_vs_baseline"], v["fail_closed"],
                 v["evidence_unobservable_record_in_chain"], v["detected"]))
    print("digest", dig)


if __name__ == "__main__":
    main()
