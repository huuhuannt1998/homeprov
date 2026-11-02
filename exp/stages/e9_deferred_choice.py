"""E9 C2 (2026-10-09): the deferred-choice attack on an in-process committer vs an external monitor (R1 W2).

Round-3 review R1 W2: against update-delivered code, an in-process committer feeding a first-write-wins anchor would
already have frozen the roots of rows written before the code arrived, so external placement is needed only against a
RESIDENT adversary that chooses its target LATER. This harness demonstrates exactly that residual case, with the
PLACEMENT as the only difference between the two commitment paths.

Both paths run monitor/monitor.py unchanged (its sha256 is recorded), with the evaluated configuration: stable-columns
scheme, coverage, keylog, Ed25519 record signatures, tagged replies, each with its own first-write-wins anchor
(testbed/anchord/anchord.py) and append key:
  M-ext     the EXTERNAL monitor: reads the recorder itself; its read path is NOT reachable from the hub process.
  C-inproc  the IN-PROCESS committer: it runs in the resident's interpreter, so the resident controls when it reads
            each row -- the "module-level rebinding of its read path" R1 W2 names. The resident holds the target
            second back from C-inproc until after it has rewritten it, so C-inproc never commits the honest row and
            commits the rewritten one instead.

This is a CONTROLLED HARNESS, not a live Home Assistant stack: the recorder is real 2026.7.4 bytes (a scratch copy of a
synthetic master built from the lab recorder's schema and value distributions; the source is read-only), the honest
actuation is inserted as the recorder stores it, and the rewrite is the member-account swap of the paper's PSR arm --
the public primitive in exp/rig/forge.py / testbed's homeprov_ec arm PSR -- a single UPDATE of context_user_id_bin on
the target context's rows (both tables). No deployable attack integration is created; the blinding is realized by the
resident choosing, per poll, which recorder state the in-process committer's read path reveals, on the same monitor.py
the external monitor runs. Placement is therefore the only variable.

Per trial (fixed count, default 30), on a shared scratch recorder, driven on a virtual clock:
  1. an honest household-member unlock (member A) is written at second t (state row + call_service event, one context);
  2. the external monitor polls at t+1 and seals second t with the HONEST root, anchored first-write-wins;
  3. the resident picks that actuation as its target and rewrites context_user_id_bin A -> B on its rows (member-account
     swap), so the recorder now attributes it to member B;
  4. STOLEN-KEY PROBE: the resident, holding the external monitor's append key, posts the rewritten root for second t to
     the external anchor -- which already holds the honest root -- and the anchor's reply is recorded (expected 409);
  5. the in-process committer, whose read path the resident released only now (post-rewrite), polls and seals second t
     with the REWRITTEN root, anchored first-write-wins on its own anchor (accepted: it never held the honest root).
At the end both chains are scored by exp/stages/e7_verify.py against the FINAL recorder (post-rewrite): the external
monitor detects an attributable second-level violation at each target second; the in-process committer's chain verifies
clean there, because it certified the rewrite. Exact 95% Clopper-Pearson intervals (exp/rig/stats.py) over the trials.

    python3 exp/stages/e9_deferred_choice.py --trials 30 --out exp/out/e9_deferred_choice.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
MONITOR_PY = os.path.join(REPO, "monitor", "monitor.py")
VERIFY_PY = os.path.join(HERE, "e7_verify.py")
DEFAULT_SRC = "<research-dir>/HOMEPROV-P13-exp/e9pre/c1/master_k1.db"
DEFAULT_OUT = os.path.join(REPO, "exp", "out", "e9_deferred_choice.json")
PREFIX = "e9dc"
ANC_IMG = "hpr-anchord:e8"
MEMBER_A = bytes.fromhex("90b6f1f5983443c2b47f563e8f652752")   # the real household member (E8's member id)
MEMBER_B = bytes.fromhex("a1c2e3f4051627384950617283940516")   # a second household account
TARGET = "lock.front_door"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sh(*a, check=True):
    r = subprocess.run(list(a), capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("%s -> %s %s" % (" ".join(a)[:160], r.returncode, (r.stderr or "")[-300:]))
    return (r.stdout or "").strip()


class Clock:
    def __init__(self):
        self.t = 0.0

    def time(self):
        return self.t

    def sleep(self, s):
        return None

    def __getattr__(self, name):
        return getattr(time, name)


def load_monitor(name, env):
    old = {k: os.environ.get(k) for k in env}
    try:
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        spec = importlib.util.spec_from_file_location(name, MONITOR_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod


def verifier_module(scratch):
    spec = importlib.util.spec_from_file_location("e9dc_e7_verify", VERIFY_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def start_anchor(name, port, key):
    sh("docker", "run", "-d", "--name", name, "-p", "127.0.0.1:%d:9900" % port,
       "-e", "HOMEPROV_ANCHOR_KEY=" + key, "--entrypoint", "python", ANC_IMG, "-u", "/app/anchord.py")
    url = "http://127.0.0.1:%d" % port
    for _ in range(40):
        try:
            with urllib.request.urlopen(url + "/head", timeout=2) as r:
                if r.status == 200:
                    return url
        except Exception:                                 # noqa: BLE001
            time.sleep(0.5)
    raise RuntimeError("anchor %s did not come up on %s" % (name, url))


def post(url, body: bytes, key: str):
    tag = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url + "/append", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-HP-Auth": tag})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:                    # noqa: F821
        try:
            b = json.loads(e.read() or b"{}")
        except Exception:                                 # noqa: BLE001
            b = {}
        return e.code, b
    except Exception as exc:                               # noqa: BLE001
        return None, {"err": repr(exc)[:120]}


# --------------------------------------------------------------------------- recorder edits (the hub, then the resident)
def _mid(con, entity):
    r = con.execute("SELECT metadata_id FROM states_meta WHERE entity_id=?", (entity,)).fetchone()
    return r[0] if r else None


def _etype_id(con, et):
    r = con.execute("SELECT event_type_id FROM event_types WHERE event_type=?", (et,)).fetchone()
    if r:
        return r[0]
    nid = (con.execute("SELECT max(event_type_id) FROM event_types").fetchone()[0] or 0) + 1
    con.execute("INSERT INTO event_types (event_type_id, event_type) VALUES (?,?)", (nid, et))
    return nid


def honest_unlock(db, ts, ctx):
    """One honest member-A unlock as the recorder stores it: the unlocked state row and its call_service event, sharing
    one context, context_user_id_bin = member A. Returns (state_id, event_id)."""
    con = sqlite3.connect(db, timeout=30)
    con.execute("PRAGMA foreign_keys=ON")
    mid = _mid(con, TARGET)
    prev = con.execute("SELECT state_id FROM states WHERE metadata_id=? ORDER BY last_updated_ts DESC LIMIT 1",
                       (mid,)).fetchone()
    con.execute("INSERT INTO states (metadata_id, state, last_updated_ts, last_changed_ts, last_reported_ts, "
                "old_state_id, origin_idx, context_id_bin, context_user_id_bin, context_parent_id_bin) "
                "VALUES (?,?,?,?,?,?,0,?,?,NULL)", (mid, "unlocked", ts, ts, ts, prev[0] if prev else None,
                                                    ctx, MEMBER_A))
    sid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    etid = _etype_id(con, "call_service")
    con.execute("INSERT INTO events (event_type_id, time_fired_ts, origin_idx, context_id_bin, context_user_id_bin, "
                "context_parent_id_bin) VALUES (?,?,0,?,?,NULL)", (etid, ts - 0.002, ctx, MEMBER_A))
    eid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.commit()
    con.close()
    return sid, eid


def member_account_swap(db, ctx):
    """The paper's PSR primitive: rewrite context_user_id_bin A -> B on every state and event row of the context."""
    con = sqlite3.connect(db, timeout=30)
    ns = con.execute("UPDATE states SET context_user_id_bin=? WHERE context_id_bin=?", (MEMBER_B, ctx)).rowcount
    ne = con.execute("UPDATE events SET context_user_id_bin=? WHERE context_id_bin=?", (MEMBER_B, ctx)).rowcount
    con.commit()
    con.close()
    return ns, ne


def tick_until_sealed(mod, st, clock, second, t_now, max_ticks=4):
    """Poll mod on the virtual clock from t_now until it anchors second `second` (or max_ticks)."""
    got = None
    for i in range(max_ticks):
        clock.t = t_now + i
        r = mod.tick(st)
        anc = st.get("anchored", {}).get("second", [])
        pend = st.get("pending", {}).get("second", {})
        if str(second) in anc:
            got = {"tick": i, "anchor_ok": bool((r.get("anchor") or {}).get("ok")),
                   "sealed_new": r.get("sealed_new"), "parts": r.get("parts")}
            break
    return got, st.get("anchored", {}).get("second", []), st.get("pending", {}).get("second", {})


def run(a):
    out_path = a.out or DEFAULT_OUT
    if os.path.exists(out_path):
        raise SystemExit("refusing to overwrite " + out_path)
    trials = int(a.trials)
    work = tempfile.mkdtemp(prefix="e9dc_")
    rec = os.path.join(work, "home-assistant_v2.db")
    # scratch copy of the real-schema recorder; the source stays read-only
    for suf in ("", "-wal", "-shm"):
        if os.path.exists(a.src + suf):
            shutil.copy2(a.src + suf, rec + suf)
    os.chmod(rec, 0o644)
    con = sqlite3.connect(rec)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("PRAGMA journal_mode=WAL")
    base = con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0]
    con.close()
    src_sha = sha(a.src)

    names = {"ext": "%s-anc-ext" % PREFIX, "ip": "%s-anc-ip" % PREFIX}
    for n in names.values():
        if sh("docker", "ps", "-aq", "-f", "name=^%s$" % n, check=False):
            raise SystemExit("refusing: container %s exists" % n)
    key_ext, key_ip = os.urandom(32).hex(), os.urandom(32).hex()
    scratch_ext, scratch_ip = os.path.join(work, "ext"), os.path.join(work, "ip")
    os.makedirs(scratch_ext)
    os.makedirs(scratch_ip)
    # signing keys (one per path), generated here with cryptography
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pubs = {}
    for who, scr in (("ext", scratch_ext), ("ip", scratch_ip)):
        k = ed25519.Ed25519PrivateKey.generate()
        with open(os.path.join(scr, "sign.pem"), "wb") as fh:
            fh.write(k.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()))
        p = os.path.join(scr, "sign_pub.pem")
        with open(p, "wb") as fh:
            fh.write(k.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo))
        pubs[who] = p

    log = []

    def note(**kw):
        kw["at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.append(kw)
        print(json.dumps(kw)[:300], flush=True)

    clock = Clock()
    results = []
    try:
        url_ext = start_anchor(names["ext"], a.port_ext, key_ext)
        url_ip = start_anchor(names["ip"], a.port_ip, key_ip)
        common = {"HOMEPROV_DB": rec, "HOMEPROV_SCHEME": "stable", "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "1",
                  "HOMEPROV_REPLY_TAGS": "auto", "HOMEPROV_ENCODING": None, "HOMEPROV_ESCROW_DIR": None,
                  "HOMEPROV_NAMEMAP_DIR": None, "HOMEPROV_CLOCK_FILE": None, "HOMEPROV_GRACE_S": "0",
                  "HOMEPROV_PERIOD": "5"}
        ext = load_monitor("e9dc_mon_ext", {**common, "HOMEPROV_SCRATCH": scratch_ext, "HOMEPROV_ANCHOR": url_ext +
                           "/append", "HOMEPROV_ANCHOR_KEY": key_ext, "HOMEPROV_SIGN_KEY": os.path.join(scratch_ext,
                           "sign.pem")})
        ip = load_monitor("e9dc_mon_ip", {**common, "HOMEPROV_SCRATCH": scratch_ip, "HOMEPROV_ANCHOR": url_ip +
                          "/append", "HOMEPROV_ANCHOR_KEY": key_ip, "HOMEPROV_SIGN_KEY": os.path.join(scratch_ip,
                          "sign.pem")})
        ext.time = clock
        ip.time = clock
        monitor_sha = sha(MONITOR_PY)
        assert ext.SCHEME == ip.SCHEME == "stable"
        st_ext, st_ip = ext.load_state(), ip.load_state()
        note(step="ready", monitor_sha256=monitor_sha, scheme="stable", trials=trials, src=a.src, src_sha256=src_sha,
             recorder_base_ts=base, members={"A": MEMBER_A.hex(), "B": MEMBER_B.hex()},
             anchor_image=ANC_IMG, anchor_image_id=sh("docker", "image", "inspect", ANC_IMG, "--format", "{{.Id}}"))
        # bring the external monitor's state up to the recorder's history edge once, so the per-trial seals are cheap
        clock.t = base + 0.5
        ext.tick(st_ext)
        ip.tick(st_ip)

        base = int(base) + 10
        step = 6
        for i in range(trials):
            t = base + i * step
            ctx = (int(t * 1000).to_bytes(6, "big") + os.urandom(10))
            honest_unlock(rec, t + 0.4, ctx)
            # external monitor seals the honest second first
            ext_seal, ext_anc, ext_pend = tick_until_sealed(ext, st_ext, clock, t, t + 1)
            # the resident picks the target now and rewrites it (member-account swap)
            ns, ne = member_account_swap(rec, ctx)
            # stolen-key probe: re-anchor a DIFFERENT (rewritten) root for this second on the external anchor
            body = json.dumps({"observer": "external-monitor", "ts": clock.t, "scheme": "stable",
                               "sealed": {"second": {str(t): {"acc": "00" * 32, "n": 99}}}},
                              sort_keys=True).encode()
            code, reply = post(url_ext, body, key_ext)
            # the in-process committer's read path is released only now; it seals the rewritten second
            ip_seal, ip_anc, ip_pend = tick_until_sealed(ip, st_ip, clock, t, t + 1)
            results.append({"trial": i, "second": t, "context": ctx.hex(),
                            "ext_sealed": ext_seal, "ext_anchored_second": str(t) in ext_anc,
                            "swap_states": ns, "swap_events": ne,
                            "stolen_key_reanchor_status": code,
                            "stolen_key_reanchor_reason": (reply or {}).get("error") or (reply or {}).get("reason"),
                            "ip_sealed": ip_seal, "ip_anchored_second": str(t) in ip_anc})
            if i < 2 or (i + 1) % 10 == 0:
                note(step="trial", i=i, second=t, ext_anchored=str(t) in ext_anc, swap=(ns, ne),
                     stolen_key_status=code, ip_anchored=str(t) in ip_anc)
        # a few trailing polls so every pending root is flushed
        for j in range(3):
            clock.t = base + trials * step + 10 + j
            ext.tick(st_ext)
            ip.tick(st_ip)
        # pull the two chains out of the anchors
        chains = {}
        for who, nm in names.items():
            raw = sh("docker", "exec", nm, "sh", "-c", "cat /anchor/chain.jsonl")
            p = os.path.join(work, "%s_chain.jsonl" % who)
            open(p, "w").write(raw + ("\n" if raw and not raw.endswith("\n") else ""))
            chains[who] = p
        note(step="runs_done", ext_chain_lines=len(open(chains["ext"]).read().splitlines()),
             ip_chain_lines=len(open(chains["ip"]).read().splitlines()))

        # score both chains against the FINAL (rewritten) recorder
        V = verifier_module(work)
        scored = {}
        trial_rows = [{"arm": "deferred_choice", "forged_row": {"ts": r["second"] + 0.4}} for r in results]
        for who in ("ext", "ip"):
            vscr = os.path.join(work, "vscratch_" + who); os.makedirs(vscr, exist_ok=True)
            vdb = os.path.join(work, "vdb_" + who); os.makedirs(vdb, exist_ok=True)
            Vm = V.load_monitor("stable", vscr)
            dbcopy = V._private_copy(rec, vdb)
            lines = V.read_lines(chains[who])
            res = V.verify(Vm, dbcopy, lines, 30.0, 30.0, scheme="stable", sign_pubkey=pubs[who])
            flagged = set(res["flagged_seconds"])
            viol = {(v["gran"], v["seg"]): v for v in res["violations"]}
            per = []
            for r in results:
                seg = str(r["second"])
                v = viol.get(("second", seg))
                per.append({"second": r["second"], "anchored": ("second", seg) in res["roots"],
                            "flagged": seg in flagged,
                            "second_violation": bool(v and v.get("violation")),
                            "attributable": bool(v and v.get("attributable"))})
            scored[who] = {"sign_pubkey": os.path.relpath(pubs[who], work),
                           "signatures": {k: res["signatures"].get(k) for k in
                                          ("checked", "monitor_records", "signed_ok", "bad_signature", "wrong_key")},
                           "monitor_records": res.get("segments"),
                           "n_detected": sum(1 for x in per if x["flagged"]),
                           "n_anchored": sum(1 for x in per if x["anchored"]),
                           "per_trial": per}
        note(step="scored", ext_detected=scored["ext"]["n_detected"], ip_detected=scored["ip"]["n_detected"])

        sys.path.insert(0, os.path.join(REPO, "exp"))
        from rig import stats                                  # noqa: PLC0415

        def ci(k, n):
            if not n:
                return None
            r = stats.clopper_pearson(k, n)
            return [round(r["ci_lo"], 3), round(r["ci_hi"], 3)]
        n = len(results)
        ext_det = scored["ext"]["n_detected"]
        ip_det = scored["ip"]["n_detected"]
        ext_anc = sum(1 for r in results if r["ext_anchored_second"])
        ip_anc = sum(1 for r in results if r["ip_anchored_second"])
        s409 = sum(1 for r in results if r["stolen_key_reanchor_status"] == 409)
        out = {
            "item": "E9 C2: deferred-choice attack on an in-process committer vs the external monitor (R1 W2). The "
                    "resident blinds the in-process committer (controls its read path) from installation so it never "
                    "commits the honest row, picks its target later, and the committer anchors the rewritten root to a "
                    "first-write-wins anchor; the external monitor on the same hub had sealed the honest row and "
                    "detects the rewrite. Controlled harness on a real-schema scratch recorder; monitor.py and the "
                    "anchor unchanged; placement is the only variable.",
            "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
            "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
            "monitor_py": "monitor/monitor.py", "monitor_sha256": monitor_sha,
            "verifier": {"file": os.path.relpath(VERIFY_PY, REPO), "sha256": sha(VERIFY_PY)},
            "anchor": {"image": ANC_IMG, "entry": "anchord.py (first-write-wins, HMAC append key, tagged replies)",
                       "image_id": sh("docker", "image", "inspect", ANC_IMG, "--format", "{{.Id}}")},
            "forge_primitive": {"what": "member-account swap (PSR): UPDATE context_user_id_bin A->B on the target "
                                        "context's state and event rows", "also_in": ["exp/rig/forge.py",
                                "testbed/real/ha-config/custom_components/homeprov_ec arm PSR"]},
            "source_recorder": {"path": a.src, "sha256": src_sha, "read_only": True,
                                "note": "a synthetic master built from the lab recorder's 2026.7.4 schema and value "
                                        "distributions (exp/sp2027/e9_cost_scale.py generate); copied, never written"},
            "method": {"placement_is_the_only_variable": True,
                       "M_ext": "external monitor: monitor.py, real virtual clock, reads the recorder itself (read path "
                                "not reachable from the hub process)",
                       "C_inproc": "in-process committer: the SAME monitor.py, run in the resident's interpreter; the "
                                   "resident releases the target second to its read path only after rewriting it, which "
                                   "is the module-level read-path rebinding R1 W2 names",
                       "trials": n, "second_spacing_s": step, "clock": "virtual; no wall-clock waits"},
            "results_summary": {
                "n_trials": n,
                "external_monitor_sealed_honest_second": {"k": ext_anc, "n": n, "ci": ci(ext_anc, n)},
                "external_monitor_detected_rewrite": {"k": ext_det, "n": n, "ci": ci(ext_det, n)},
                "stolen_key_reanchor_on_external_anchor_409": {"k": s409, "n": n, "ci": ci(s409, n),
                    "meaning": "the external anchor refuses a different root for a second it already holds: a holder of "
                               "the append key can withhold, not forge"},
                "in_process_committer_anchored_rewritten_second": {"k": ip_anc, "n": n, "ci": ci(ip_anc, n)},
                "in_process_committer_detected_rewrite": {"k": ip_det, "n": n, "ci": ci(ip_det, n),
                    "meaning": "0 expected: the in-process committer certified the rewrite, so its own chain does not "
                               "contradict the rewritten recorder"},
            },
            "scored": scored,
            "trials": results,
            "run_log": log,
            "conclusion": "Against a resident that chooses its target later, an in-process committer feeding a "
                          "first-write-wins anchor can be blinded from installation and made to certify the rewritten "
                          "history; only the external monitor, whose read path the hub process cannot reach, sealed the "
                          "honest row and detects the rewrite. A stolen append key lets the resident withhold or stall "
                          "the external anchor, not forge a sealed root (409).",
        }
        with open(out_path, "x") as fh:
            json.dump(out, fh, indent=1)
        print(json.dumps(out["results_summary"], indent=1))
        print("wrote", out_path, sha(out_path))
    finally:
        for n_ in names.values():
            subprocess.run(["docker", "logs", n_], capture_output=True)
            subprocess.run(["docker", "rm", "-f", n_], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out", default=None)
    ap.add_argument("--port-ext", type=int, default=19980)
    ap.add_argument("--port-ip", type=int, default=19981)
    run(ap.parse_args())


if __name__ == "__main__":
    main()
