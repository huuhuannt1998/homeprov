"""R7 (round-2 triage N2): end-to-end check of the hash-linked anchor through the real daemon, without Docker.

1. A head witness (testbed/anchord/headwitness.py, own process, own directory, HMAC key) and the linked anchor daemon
   (testbed/anchord/anchord_linked.py over the unmodified anchord.py, via exp/sp2027/r7_anchord_local.py,
   HEAD_WITNESS_MODE=sync) on 127.0.0.1.
2. A working recorder made from reproduce/snapshots/e_c_clo.db with its timestamps shifted to end 3 s ago; the shipped
   monitor (monitor/monitor.py --once, encoding v2, authenticated append) ticks once, then five more times, each after a
   fresh state row is written, so the chain holds several records.
3. Checks: the chain verifies as fully linked against the witness's head; the monitor's roots verify against the
   recorder (verify_all's rule); copies of the chain with two records swapped, one deleted, one root rewritten, or the
   tail truncated each fail the check against the witness head; the daemon's published head and GET /head match.
4. Upgrade path: the daemon is restarted on a copy of an unlinked chain saved by an evaluated run
   (reproduce/snapshots/e_c_clo.chain.jsonl) and the monitor appends; the chain verifies as 'mixed', and an edit inside
   the unlinked prefix is then detected.

    python3 exp/sp2027/r7_anchor_link_e2e.py     # writes exp/out/r7_anchor_link_e2e.json (never overwrites)
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
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "reproduce"))
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import verify_all as VA  # noqa: E402
import chainverify as CV  # noqa: E402

SRC_DB = os.path.join(REPO, "reproduce", "snapshots", "e_c_clo.db")
LEGACY_CHAIN = os.path.join(REPO, "reproduce", "snapshots", "e_c_clo.chain.jsonl")


def port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def start(args, env):
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = p.stdout.readline()
    assert line.startswith("READY"), line
    return p


def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def shifted_copy(dst):
    shutil.copyfile(SRC_DB, dst)
    con = sqlite3.connect(dst)
    hi = max(con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0],
             con.execute("SELECT max(time_fired_ts) FROM events").fetchone()[0])
    off = (time.time() - 3.0) - hi
    con.execute("UPDATE states SET last_updated_ts = last_updated_ts + ?, last_changed_ts = CASE WHEN last_changed_ts "
                "IS NULL THEN NULL ELSE last_changed_ts + ? END, last_reported_ts = CASE WHEN last_reported_ts IS NULL "
                "THEN NULL ELSE last_reported_ts + ? END", (off, off, off))
    con.execute("UPDATE events SET time_fired_ts = time_fired_ts + ?", (off,))
    con.commit(); con.close()


def fresh_row(db):
    con = sqlite3.connect(db)
    cols = [c[1] for c in con.execute("PRAGMA table_info(states)")]
    r = list(con.execute("SELECT * FROM states ORDER BY state_id DESC LIMIT 1").fetchone())
    r[cols.index("state_id")] = None
    r[cols.index("last_updated_ts")] = time.time()
    r[cols.index("context_id_bin")] = os.urandom(16)
    con.execute("INSERT INTO states VALUES (%s)" % ",".join("?" * len(cols)), r)
    con.commit(); con.close()


def tick(env):
    r = subprocess.run([sys.executable, os.path.join(REPO, "monitor", "monitor.py"), "--once"], env=env,
                       capture_output=True, text=True, timeout=300)
    return json.loads(r.stdout.strip().splitlines()[-1])


def tampered(data, how):
    ls = [l for l in data.split(b"\n") if l.strip()]
    if how == "swap":
        ls[1], ls[2] = ls[2], ls[1]
    elif how == "delete":
        del ls[2]
    elif how == "rewrite_root":
        r = json.loads(ls[1]); g = next(iter(r["payload"]["sealed"])); s = next(iter(r["payload"]["sealed"][g]))
        r["payload"]["sealed"][g][s]["acc"] = "ff" * 32
        ls[1] = json.dumps(r, sort_keys=True).encode()
    elif how == "truncate":
        ls = ls[:-2]
    return b"\n".join(ls) + b"\n"


def main():
    dst = os.path.join(OUT, "r7_anchor_link_e2e.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    akey, wkey = secrets.token_hex(32), secrets.token_hex(32)
    out = {"item": "R7/N2: hash-linked anchor, end to end through the real daemon, the shipped monitor and a head witness",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "anchord_sha256": VA.sha256_file(os.path.join(REPO, "testbed", "anchord", "anchord.py")),
           "anchord_linked_sha256": VA.sha256_file(os.path.join(REPO, "testbed", "anchord", "anchord_linked.py")),
           "headwitness_sha256": VA.sha256_file(os.path.join(REPO, "testbed", "anchord", "headwitness.py")),
           "chainverify_sha256": VA.sha256_file(os.path.join(REPO, "testbed", "anchord", "chainverify.py")),
           "monitor_sha256": VA.sha256_file(os.path.join(REPO, "monitor", "monitor.py"))}
    procs = []
    with tempfile.TemporaryDirectory() as tmp:
        try:
            wp, ap = port(), port()
            wenv = dict(os.environ, HOMEPROV_WITNESS_KEY=wkey, WITNESS_PORT=str(wp),
                        WITNESS_LOG=os.path.join(tmp, "w", "heads.jsonl"), WITNESS_FORKS=os.path.join(tmp, "w", "forks.jsonl"))
            procs.append(start([sys.executable, os.path.join(REPO, "testbed", "anchord", "headwitness.py")], wenv))
            aenv = dict(os.environ, HOMEPROV_ANCHOR_KEY=akey, HOMEPROV_ANCHOR_LINK="v2", HOMEPROV_WITNESS_KEY=wkey,
                        HEAD_WITNESS_URL="http://127.0.0.1:%d/head" % wp, HEAD_WITNESS_MODE="sync", PUBLISH_PERIOD="1")
            procs.append(start([sys.executable, os.path.join(REPO, "exp", "sp2027", "r7_anchord_local.py"),
                                str(ap), os.path.join(tmp, "a")], aenv))
            live = os.path.join(tmp, "live.db")
            shifted_copy(live)
            time.sleep(1.5)
            os.makedirs(os.path.join(tmp, "m"))
            menv = dict(os.environ, HOMEPROV_DB=live, HOMEPROV_SCRATCH=os.path.join(tmp, "m"), HOMEPROV_SCHEME="closure",
                        HOMEPROV_ENCODING="v2", HOMEPROV_ANCHOR="http://127.0.0.1:%d/append" % ap, HOMEPROV_ANCHOR_KEY=akey)
            ticks = [tick(menv)]
            for _ in range(5):
                fresh_row(live)
                time.sleep(1.3)
                ticks.append(tick(menv))
            chain_path = os.path.join(tmp, "a", "anchor", "chain.jsonl")
            data = open(chain_path, "rb").read()
            whead = get("http://127.0.0.1:%d/head" % wp)
            ahead = get("http://127.0.0.1:%d/head" % ap)
            time.sleep(1.5)
            pub = json.load(open(os.path.join(tmp, "a", "published", "head.json")))
            res = CV.verify_chain(data, whead)
            os.environ["HOMEPROV_ENCODING"] = "v2"
            M = VA.load_monitor("closure", os.path.join(tmp, "m2"))
            roots = VA.anchored_roots(data.decode().splitlines(), 0, time.time() + 60)
            W = dict(M.GRAN)
            t0, t1 = min(int(s) * W[g] for g, s in roots), max(int(s) * W[g] for g, s in roots)
            phi = M.commit(M.load(live, since=t0 - 3600), encoding="v2")
            verd = VA.verify_window(phi, roots, W, t0, t1)
            out["linked_run"] = {
                "ticks": [{"sealed_new": t.get("sealed_new"), "anchor": {k: v for k, v in (t.get("anchor") or {}).items()
                                                                         if k in ("ok", "seq", "witness_push")}}
                          for t in ticks],
                "chain_records": res["records"], "chain_check_against_witness": {k: res[k] for k in
                                                                                ("ok", "link", "linked_records",
                                                                                 "problems", "integrity")},
                "witness_head": whead, "anchor_get_head_digest": ahead["head_digest"],
                "published_head_digest": pub.get("head_digest"),
                "heads_agree": whead["head_digest"] == ahead["head_digest"] == pub.get("head_digest")
                and whead["seq"] == res["records"],
                "monitor_roots_verified": len(verd), "root_violations": sum(1 for v in verd.values() if v["violation"]),
                "record_encodings": sorted({json.loads(l)["payload"].get("encoding") for l in data.decode().splitlines()
                                            if l.strip()})}
            out["tamper_checks"] = {}
            for how in ("swap", "delete", "rewrite_root", "truncate"):
                t = CV.verify_chain(tampered(data, how), whead)
                alone = CV.verify_chain(tampered(data, how))
                out["tamper_checks"][how] = {"detected_with_witness_head": not t["ok"],
                                             "detected_by_chain_alone": not alone["ok"],
                                             "problems": [p["problem"] for p in t["problems"]][:3]}
            for p in procs[1:]:
                p.terminate(); p.wait(10)
            procs = procs[:1]
            # upgrade path: restart on an unlinked chain saved by an evaluated run
            os.makedirs(os.path.join(tmp, "b", "anchor"))
            shutil.copyfile(LEGACY_CHAIN, os.path.join(tmp, "b", "anchor", "chain.jsonl"))
            legacy = open(LEGACY_CHAIN, "rb").read()
            ap2 = port()
            aenv2 = dict(aenv, HEAD_WITNESS_URL="")
            procs.append(start([sys.executable, os.path.join(REPO, "exp", "sp2027", "r7_anchord_local.py"),
                                str(ap2), os.path.join(tmp, "b")], aenv2))
            fresh_row(live)
            time.sleep(1.3)
            os.makedirs(os.path.join(tmp, "m3"))
            t = tick(dict(menv, HOMEPROV_ANCHOR="http://127.0.0.1:%d/append" % ap2, HOMEPROV_SCRATCH=os.path.join(tmp, "m3")))
            d2 = open(os.path.join(tmp, "b", "anchor", "chain.jsonl"), "rb").read()
            r2 = CV.verify_chain(d2, get("http://127.0.0.1:%d/head" % ap2))
            ls = [l for l in d2.split(b"\n") if l.strip()]
            x = json.loads(ls[10]); x["recv_ts"] += 1.0
            ls[10] = json.dumps(x, sort_keys=True).encode()
            r3 = CV.verify_chain(b"\n".join(ls) + b"\n")
            out["upgrade_from_unlinked_chain"] = {
                "legacy_chain": "reproduce/snapshots/e_c_clo.chain.jsonl", "legacy_records": len(legacy.splitlines()),
                "legacy_chain_alone": {k: v for k, v in CV.verify_chain(legacy).items() if k in ("ok", "link", "records")},
                "tick_anchor": {k: v for k, v in (t.get("anchor") or {}).items() if k in ("ok", "seq")},
                "after_append": {k: r2[k] for k in ("ok", "link", "records", "linked_records", "problems")},
                "edit_inside_unlinked_prefix_detected": not r3["ok"]}
        finally:
            for p in procs:
                p.terminate()
                try:
                    p.wait(10)
                except Exception:
                    p.kill()
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
