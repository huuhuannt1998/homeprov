"""R6 (T7): end-to-end check of the fixed monitor through the real append path, without Docker.

For each node-hash encoding (v1, v2): start the unmodified anchor daemon (testbed/anchord/anchord.py, via
exp/sp2027/r9_c_anchord_local.py) on 127.0.0.1 with a fresh HMAC key; make a working recorder from a published window
extract (reproduce/snapshots/e_c_clo.db) with every timestamp shifted so the rows end a few seconds ago; run ONE
monitor tick (monitor/monitor.py --once, its own process, HOMEPROV_ENCODING set) so it seals and appends over the
authenticated path; then verify the chain against the recorder (verify_all.py's rule, encoding read from the records),
apply the triage's parent/user splice to one row in a sealed second, and verify again.

Expected: both encodings verify the untouched recorder clean; after the splice v1 still verifies clean (the defect) and
v2 flags exactly the spliced second (and its minute and hour). Every anchored record names its encoding.

    python3 exp/sp2027/r6_e2e_local.py     # writes exp/out/r6_e2e_local.json (never overwrites)
"""
import datetime
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
import verify_all as VA  # noqa: E402

SRC_DB = os.path.join(REPO, "reproduce", "snapshots", "e_c_clo.db")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def shifted_copy(dst):
    shutil.copyfile(SRC_DB, dst)
    con = sqlite3.connect(dst)
    hi = max(con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0],
             con.execute("SELECT max(time_fired_ts) FROM events").fetchone()[0])
    off = (time.time() - 3.0) - hi
    con.execute("UPDATE states SET last_updated_ts = last_updated_ts + ?, "
                "last_changed_ts = CASE WHEN last_changed_ts IS NULL THEN NULL ELSE last_changed_ts + ? END, "
                "last_reported_ts = CASE WHEN last_reported_ts IS NULL THEN NULL ELSE last_reported_ts + ? END",
                (off, off, off))
    con.execute("UPDATE events SET time_fired_ts = time_fired_ts + ?", (off,))
    con.commit()
    con.close()
    return off


def run_encoding(enc, tmp):
    key = secrets.token_hex(32)
    port = free_port()
    data = os.path.join(tmp, "anchor_" + enc)
    ad = subprocess.Popen([sys.executable, os.path.join(REPO, "exp", "sp2027", "r9_c_anchord_local.py"),
                           str(port), data, key], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        assert ad.stdout.readline().startswith("READY")
        live = os.path.join(tmp, "live_%s.db" % enc)
        off = shifted_copy(live)
        time.sleep(1.5)                                    # let the last second close
        scratch = os.path.join(tmp, "mon_" + enc)
        os.makedirs(scratch)
        env = dict(os.environ, HOMEPROV_DB=live, HOMEPROV_SCRATCH=scratch, HOMEPROV_SCHEME="closure",
                   HOMEPROV_ENCODING=enc, HOMEPROV_ANCHOR="http://127.0.0.1:%d/append" % port,
                   HOMEPROV_ANCHOR_KEY=key)
        t_tick = time.time()
        r = subprocess.run([sys.executable, os.path.join(REPO, "monitor", "monitor.py"), "--once"],
                           env=env, capture_output=True, text=True, timeout=300)
        tick = json.loads(r.stdout.strip().splitlines()[-1])
        chain = open(os.path.join(data, "anchor", "chain.jsonl")).read().splitlines()
        encs = sorted({json.loads(l)["payload"].get("encoding", "<none>") for l in chain if l.strip()})
        os.environ["HOMEPROV_ENCODING"] = enc
        M = VA.load_monitor("closure", scratch)
        roots = VA.anchored_roots(chain, 0, time.time() + 60)
        W = dict(M.GRAN)
        t0, t1 = min(int(s) * W[g] for g, s in roots), max(int(s) * W[g] for g, s in roots)

        def verify():
            renc = sorted({a["encoding"] for a in roots.values()})
            assert len(renc) == 1
            phi = M.commit(M.load(live, since=t0 - 3600), encoding=renc[0])
            v = VA.verify_window(phi, roots, W, t0, t1)
            return sorted([g, s] for (g, s), x in v.items() if x["violation"]), len(v)

        clean, n_checked = verify()
        con = sqlite3.connect(live)
        sealed_secs = {s for (g, s) in roots if g == "second"}
        row = None
        for sid, ts, par in con.execute("SELECT state_id, last_updated_ts, context_parent_id_bin FROM states WHERE "
                                        "instr(context_parent_id_bin, x'7c') > 1 AND context_user_id_bin IS NULL "
                                        "ORDER BY state_id"):
            if str(int(ts // 1)) in sealed_secs:
                row = (sid, ts, par)
                break
        k = row[2].index(b"|")
        con.execute("UPDATE states SET context_parent_id_bin=?, context_user_id_bin=? WHERE state_id=?",
                    (row[2][:k], row[2][k + 1:] + b"|", row[0]))
        con.commit()
        con.close()
        after, _ = verify()
        return {"encoding": enc, "anchor_port": "127.0.0.1:<ephemeral>", "time_shift_s": round(off, 3),
                "tick": {k_: tick.get(k_) for k_ in ("n_nodes", "sealed_new", "anchor")},
                "tick_seconds": round(time.time() - t_tick, 2),
                "chain_records": len(chain), "record_encodings": encs, "segments_verified": n_checked,
                "violations_before_splice": clean,
                "splice": {"state_id": row[0], "second": str(int(row[1] // 1)),
                           "parent_before": row[2].hex(), "parent_after": row[2][:k].hex(),
                           "user_after": (row[2][k + 1:] + b"|").hex()},
                "violations_after_splice": after}
    finally:
        ad.terminate()
        ad.wait(timeout=10)


def main():
    dst = os.path.join(OUT, "r6_e2e_local.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    with tempfile.TemporaryDirectory() as tmp:
        res = {e: run_encoding(e, tmp) for e in ("v1", "v2")}
    out = {"item": "R6/T7: v1 vs v2 monitor through the authenticated append path (local anchord, no Docker)",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "script_sha256": VA.sha256_file(os.path.abspath(__file__)),
           "monitor_sha256": VA.sha256_file(os.path.join(REPO, "monitor", "monitor.py")),
           "anchord_sha256": VA.sha256_file(os.path.join(REPO, "testbed", "anchord", "anchord.py")),
           "recorder": "reproduce/snapshots/e_c_clo.db, timestamps shifted to end 3 s before the run",
           "runs": res,
           "verdict": {"v1_detects_splice": bool(res["v1"]["violations_after_splice"]),
                       "v2_detects_splice": bool(res["v2"]["violations_after_splice"]),
                       "clean_before_splice": not res["v1"]["violations_before_splice"]
                       and not res["v2"]["violations_before_splice"]}}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
