"""E10 (round 14) run helpers, called by testbed/e10/run_e10.sh. Standard library only (runs on the Mac's pinned python3
and in the python:3.12-slim monitor image). Reuses testbed/e9/e9ops.py (frozen with E9) and exp/rig/marker_issuer.py by
import; nothing of either is changed or copied.

    plan        the E10 session plan from the registered seed: block order, trial orders (ages, delays), purge events,
                hold parameters; one JSON document (the pre-registration embeds its sha256)
    issue       append ONE operator marker to every named anchor: CLOCK_STEP here (window, issued_ts, nonce; signed with
                rig.marker_issuer), every other kind through e9ops.cmd_issue (PURGE, RESTORE, RESTORE_DONE, RENAME)
    namemap     the hub's name map and the predicted part digests after a planned routine change: e9ops' entity display
                rename and person update, plus an entity_id rename and a device removal (the monitor's own namemap code)
    hostlog / sleep-guard / pmset / namemap-sanitize / ha-backup   delegated to e9ops unchanged
    pyguard     refuse unless this interpreter is the pinned one and opens a WAL-mode SQLite copy read-only (amendment 3
                of E9: the system Python 3.9.6 could not)
    restart-trial  review r5 arm R: one hub restart (graceful or kill) timed from a monitor's cost log to land inside
                its next read (direct) or copy (copy) window; prints every time it used (Mac and VM clocks)
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
E9OPS_PATH = os.environ.get("E10_E9OPS", os.path.join(REPO, "testbed", "e9", "e9ops.py"))
PINNED_PY = "<home>/miniconda3/bin/python3"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def e9ops():
    return _load(E9OPS_PATH, "e9ops_for_e10")


# ------------------------------------------------------------------------------------------------ the session plan
BDT_AGES = (5.0, 15.0, 30.0, 33.0, 45.0)       # insertion backdated by (s); 45 s is outside the stated window (control)
BDT_N = 20                                      # per age
CTX_DELAYS = (5.0, 15.0, 25.0, 45.0)            # insertion delay after the actuation (backdate = delay + ~1-2 s)
CTX_N = 10
DEL_DELAYS = (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0)   # deletion delay after the row was committed
DEL_N = 10
DELPH_N = 20
LOWKEY_MAX = 10
PW_EVENTS = ({"variants": ["PW-B", "PW-R", "PW-F-in"]}, {"variants": ["PW-U", "PW-X", "PW-F-out"]},
             {"variants": ["PW-B", "PW-R", "PW-F-in"]}, {"variants": ["PW-U", "PW-X", "PW-F-out"]},
             {"variants": ["PW-B", "PW-R", "PW-F-in"]}, {"variants": ["PW-U", "PW-X", "PW-F-out"]})
PW_KEEP_DAYS = 29                               # the scratch hub's forced purge (recorder.purge keep_days)
PW_SPACING_S = 900
CS_STEPS = ({"step_s": 60.0, "marker": True}, {"step_s": 60.0, "marker": True}, {"step_s": 60.0, "marker": True},
            {"step_s": 60.0, "marker": False}, {"step_s": 10.0, "marker": False})
CS_DURATION_S = 60.0
ULSHM_HOLDS = 5
ULSHM_HOLD_S = 60.0
WIPE_N = 10
# ---- review r5 additions (drafts/round13/E10_ADDENDUM_R5.md). Their random draws come AFTER the original ones, so every
# order of the original arms is unchanged by the additions (test_e10_r5.py checks it).
# Arm S (sham, Z5): each attack code path at the level at which the real attack is predicted DETECTED, edit disabled.
SHAM_LEVELS = {"S-BDT": 45.0, "S-CTX": 45.0, "S-DEL": 10.0}   # A1-BDT 45 s, A2-CTX 45 s, A3-DEL 10 s
SHAM_N = 30                                                   # per variant (90 in all)
SHAM_SPACING = {"spacing_bdt_s": 15.0, "spacing_ctx_s": 5.0, "spacing_del_s": 8.0}   # as A1, A2, A3
# Arm R (hub restart mid-poll, Z4): 10 restarts, each fired at the predicted middle of a monitor's next read (direct)
# or copy (copy) window, from that monitor's own cost log.
RESTART_TRIALS = (("graceful", "direct"),) * 4 + (("kill", "direct"),) * 3 + (("graceful", "copy"),) * 3
RESTART_SETTLE_S = 150.0          # after the hub writes again and homeprov_e10 is ready, before the next restart
RESTART_LAG0_S = 2.0              # first estimate of docker restart -> container exit (graceful); then the running median
RESTART_STOP_TIMEOUT_S = 30       # docker restart -t (SIGTERM, then SIGKILL after this)
KILL_LATENCY_S = 0.05             # docker kill -> SIGKILL delivered (assumption; the measured return time is recorded)
RESTART_FRAC = 0.5                # aim at this fraction of the predicted window


def make_plan(seed, smoke=False):
    """Deterministic from the seed: every randomised order, so the pre-registration fixes it."""
    rnd = random.Random(seed)
    k = 0.2 if smoke else 1.0
    n = lambda x: max(1, int(round(x * k)))          # noqa: E731
    bdt = [a for a in BDT_AGES for _ in range(n(BDT_N))]
    rnd.shuffle(bdt)
    ctx = [d for d in CTX_DELAYS for _ in range(n(CTX_N))]
    rnd.shuffle(ctx)
    dl = [d for d in DEL_DELAYS for _ in range(n(DEL_N))]
    rnd.shuffle(dl)
    # review r5: drawn after the original orders (which are therefore unchanged)
    sham = [{"variant": v, "level": SHAM_LEVELS[v]} for v in sorted(SHAM_LEVELS) for _ in range(n(SHAM_N))]
    rnd.shuffle(sham)
    rst = list(RESTART_TRIALS) if not smoke else [("graceful", "direct"), ("kill", "direct")]
    rnd.shuffle(rst)
    pw = [dict(e, i=i) for i, e in enumerate(PW_EVENTS[:2] if smoke else PW_EVENTS)]
    blocks = [
        {"block": "A1_BDT", "op": "bdt", "ages": bdt, "spacing_s": 15.0},
        {"block": "A2_CTX", "op": "ctx", "delays": ctx, "spacing_s": 5.0},
        {"block": "A3_DEL", "op": "del", "delays": dl, "spacing_s": 8.0},
        {"block": "A3_DELPH", "op": "delph", "trials": n(DELPH_N), "margin_s": 0.3, "warmup_s": 40.0, "spacing_s": 8.0},
        {"block": "SNAP_DEL"},                    # BDT, CTX, DEL and DEL-PH are scored against this snapshot
        {"block": "S_SHAM", "op": "sham", "trials": sham, **SHAM_SPACING},
        {"block": "SNAP_SHAM"},                   # S (sham) is scored against this snapshot (before LOWKEY's insertions)
        {"block": "A3_LOWKEY", "op": "lowkey", "max": LOWKEY_MAX, "age_s": 90.0},
        {"block": "SNAP_TIMING"},                 # LOWKEY
        {"block": "A7_WIPE", "op": "wipe", "n": n(WIPE_N), "min_age_s": 60.0},
        {"block": "SNAP_WIPE"},                   # WIPE (and, offline, the D2 collusion check)
        {"block": "R_RESTART", "trials": [{"kind": a, "target": b} for a, b in rst], "settle_s": RESTART_SETTLE_S,
         "lag0_s": RESTART_LAG0_S, "stop_timeout_s": RESTART_STOP_TIMEOUT_S, "frac": RESTART_FRAC},
        {"block": "SNAP_RESTART"},                # R is scored against this snapshot
        {"block": "A6_CS", "steps": list(CS_STEPS[:2] if smoke else CS_STEPS), "duration_s": CS_DURATION_S,
         "spacing_s": 120.0},
        {"block": "A5_PW", "events": pw, "keep_days": PW_KEEP_DAYS, "spacing_s": 300 if smoke else PW_SPACING_S},
        {"block": "A4_ULW", "op": "lock_write", "holds": [60.0, 60.0]},
        {"block": "A4_ULSHM", "op": "lock_shm", "holds": n(ULSHM_HOLDS), "hold_s": ULSHM_HOLD_S, "mode": "posix",
         "ranges": [[128, 1]], "backdate_before_end_s": 2.0, "backdate_target_before_hold_s": 12.0,
         "blind_delete_delay_s": 8.0},
        {"block": "A4_ULSHM_OFD", "op": "lock_shm", "holds": 1, "hold_s": 60.0, "mode": "ofd", "ranges": [[123, 5]]},
        {"block": "A4_ULJM", "op": "journal_mode", "mode": "DELETE"},
        {"block": "A4_INFT", "op": "inflate_table", "target_bytes_large": 3 << 30, "target_bytes_small": 1 << 30,
         "free_gb_for_large": 20, "hold_s": 120.0 if smoke else 300.0, "repack_wait_s": 600.0 if smoke else 1200.0},
        {"block": "A4_INFW", "op": "inflate_window", "rows": 30000 if smoke else 300000, "rate": 500.0,
         "observe_s": 300.0 if smoke else 1200.0},
        {"block": "SNAP_A_END"},
        {"block": "B1_ENTITY_ID_RENAME", "entity_id": "light.porch_light", "new_entity_id": "light.porch_lamp_e10"},
        {"block": "B2_DEVICE_REMOVE", "entity_id": "binary_sensor.kitchen_motion"},
        {"block": "B3_PURGE_ENTITIES", "entity_ids": ["sensor.homeprov_e10_junk"], "optional": True},
        {"block": "B4_UPGRADE", "from_image": "homeassistant/home-assistant:2026.7.4",
         "to_image": "homeassistant/home-assistant:2026.10.1", "observe_s": 900 if smoke else 1800},
    ]
    upgrade_stack = {"from_image": "homeassistant/home-assistant:2025.11.1", "from_schema": 51,
                     "to_image": "homeassistant/home-assistant:2026.7.4", "to_schema": 53,
                     "before_s": 900 if smoke else 3600, "after_s": 900 if smoke else 3600}
    return {"seed": seed, "smoke": smoke, "blocks": blocks, "upgrade_stack": upgrade_stack}


def cmd_plan(a):
    p = make_plan(a.seed, a.smoke)
    text = json.dumps(p, indent=1, sort_keys=True)
    sys.stdout.write(text + "\n")


# ------------------------------------------------------------------------------------------------ markers
def cmd_issue(a):
    """CLOCK_STEP: built here, signed and appended with rig.marker_issuer.issue() to every anchor (reply tags checked).
    Every other kind: e9ops.cmd_issue unchanged."""
    E9 = e9ops()
    if a.kind != "CLOCK_STEP":
        return E9.cmd_issue(a)
    MI = E9._load_issuer(a.issuer)
    signer = MI.load_signer(a.sign_key) if a.sign_key else None
    extra = json.loads(a.extra) if a.extra else {}
    if a.not_before:
        while time.time() < a.not_before:
            time.sleep(min(5.0, max(0.05, a.not_before - time.time())))
    m = {"marker": "CLOCK_STEP", "window": [float(a.window[0]), float(a.window[1])], "issued_ts": time.time(),
         "issuer": "operator", "nonce": MI.new_nonce()}
    if a.note:
        m["note"] = a.note
    m.update(extra)
    out = {"markers": [], "issuer_sha256": hashlib.sha256(open(a.issuer, "rb").read()).hexdigest(),
           "operator_sig_fp": MI._fp(signer.public_key()) if signer is not None else None}
    one = {"marker": m, "anchors": {}, "marker_sha256": hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()}
    for spec in a.anchors:
        alias, kf = spec.split("=", 1)
        raw = open(kf).read().strip()
        r = MI.issue("http://%s:%d/append" % (alias, a.port), bytes.fromhex(raw), m, signer, "1", attempts=a.attempts,
                     retry_s=5.0, deadline=a.deadline or None, timeout=a.timeout)
        r["operator_key_fp"] = hashlib.sha256(raw.encode()).hexdigest()[:16]
        r.pop("marker", None)
        one["anchors"][alias] = r
    out["markers"].append(one)
    out["marker"], out["anchors"], out["marker_sha256"] = m, one["anchors"], one["marker_sha256"]
    out["all_ok"] = all(v.get("ok") for v in one["anchors"].values())
    print(json.dumps(out, sort_keys=True, default=str))
    return 0 if out["all_ok"] else 1


# ------------------------------------------------------------------------------------------------ name map
def cmd_namemap(a):
    """e9ops' name map, extended with two planned changes of B1/B2: {"op": "entity_id_rename", "entity_id", "new"} and
    {"op": "device_remove", "device_id"} (the device's row and its entities' rows leave the registries)."""
    E9 = e9ops()
    planned = json.loads(a.change) if a.change else []
    planned = planned if isinstance(planned, list) else [planned]
    if not any(ch.get("op") in ("entity_id_rename", "device_remove") for ch in planned):
        return E9.cmd_namemap(a)
    M = E9._monitor(a.monitor)
    e = M.namemap_entries(a.storage)
    cur = M.namemap_commitment(e)
    chs = json.loads(a.change)
    chs = chs if isinstance(chs, list) else [chs]
    e2 = {k: (list(v) if v is not None else None) for k, v in e.items()}
    srt = lambda rows: sorted(rows, key=lambda r: tuple("" if v is None else str(v) for v in r))   # noqa: E731
    states = []
    for ch in chs:
        if ch["op"] == "entity_id_rename":
            e2["entity"] = srt([tuple([ch["new"]] + list(r[1:])) if r[0] == ch["entity_id"] else tuple(r)
                                for r in e2["entity"] or []])
        elif ch["op"] == "device_remove":
            e2["entity"] = srt([tuple(r) for r in e2["entity"] or [] if r[3] != ch["device_id"]])
            e2["device"] = srt([tuple(r) for r in e2["device"] or [] if r[0] != ch["device_id"]])
        else:
            raise SystemExit("unknown change op %r" % ch["op"])
        new = M.namemap_commitment({k: ([tuple(x) for x in v] if v is not None else None) for k, v in e2.items()})
        states.append({"digest": new["digest"], "parts": {p: v["digest"] for p, v in new["parts"].items()},
                       "changed_parts": sorted(p for p in new["parts"]
                                               if new["parts"][p]["digest"] != cur["parts"][p]["digest"])})
    devs = {}
    for r in e.get("entity") or []:
        # an entity without a device has device_id None; json.dumps(sort_keys=True) cannot order None among strings
        # (fix of 2026-10-19, smoke e10_smoke3: B1/B2's predictions were empty, so their RENAME markers were not issued)
        devs.setdefault("" if r[3] is None else r[3], []).append(r[0])
    print(json.dumps({"current": {"digest": cur["digest"], "parts": {p: v["digest"] for p, v in cur["parts"].items()}},
                      "states": states, "predicted": states[-1], "devices_of_entities": devs}, sort_keys=True))
    return 0


# ------------------------------------------------------------------------------------------------ interpreter guard
def cmd_pyguard(a):
    """E9 amendment 3: the host interpreter must be the pinned one and open a WAL-mode SQLite copy read-only."""
    exe = os.path.realpath(sys.executable)
    want = os.path.realpath(a.expect)
    d = tempfile.mkdtemp(prefix="e10py_")
    s = sqlite3.connect(os.path.join(d, "src.db"))
    s.execute("PRAGMA journal_mode=WAL")
    s.execute("CREATE TABLE t (x)")
    s.execute("INSERT INTO t VALUES (1)")
    s.commit()
    c = sqlite3.connect(os.path.join(d, "copy.db"))
    s.backup(c)
    c.close()
    s.close()
    wal_header = open(os.path.join(d, "copy.db"), "rb").read()[18:20] == b"\x02\x02"
    try:
        n = sqlite3.connect("file:%s?mode=ro" % os.path.join(d, "copy.db"), uri=True).execute(
            "SELECT count(*) FROM t").fetchone()[0]
    except sqlite3.Error as exc:
        n = repr(exc)
    ok = exe == want and wal_header and n == 1 and sys.version_info >= (3, 12)
    print(json.dumps({"ok": ok, "python": exe, "expected": want, "version": sys.version.split()[0],
                      "sqlite": sqlite3.sqlite_version, "wal_copy_readable_ro": n == 1,
                      "setconfig": hasattr(sqlite3.Connection, "setconfig")}))
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------------ arm R: restart timing
def _median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def predict_window(cost_lines, mode, now_vm, min_lead_s=1.5):
    """The next read (direct: from the read's open to the end of load and commit) or copy (copy: the file copy) window
    of a monitor, on the monitor's clock (the Docker VM's), predicted from the last lines of its cost log. Each line's
    ts is the poll's snapshot time (monitor.py tick_coverage: `now` right after direct_snapshot()/the copy), copy_ms the
    time to that point, load_ms and commit_ms what follows inside a direct read. The next ts is the last plus the median
    spacing of the recent polls (poll time + HOMEPROV_PERIOD), advanced by whole spacings until it is min_lead_s ahead.
    Returns None when fewer than 4 recent observable polls are logged."""
    rows = [r for r in cost_lines if r.get("ts") is not None and r.get("ok", True)][-12:]
    if len(rows) < 4:
        return None
    ts = [float(r["ts"]) for r in rows]
    per = _median([b - a for a, b in zip(ts, ts[1:])])
    if not per or per <= 0:
        return None
    copy_s = (_median([float(r.get("copy_ms") or 0.0) for r in rows]) or 0.0) / 1000.0
    after_s = (_median([float(r.get("load_ms") or 0.0) + float(r.get("commit_ms") or 0.0) for r in rows]) or 0.0) / 1000.0
    nxt = ts[-1] + per
    while nxt - copy_s < now_vm + min_lead_s:
        nxt += per
    if mode == "direct":
        return {"start": nxt - copy_s, "end": nxt + after_s, "next_ts": nxt, "spacing_s": per}
    return {"start": nxt - copy_s, "end": nxt, "next_ts": nxt, "spacing_s": per}


def fire_time_vm(window, kind, lag_s, frac=RESTART_FRAC, kill_latency_s=KILL_LATENCY_S):
    """When to send the command (VM clock) so that its effect lands at `frac` of the window: a graceful restart's
    container exit (the recorder's last commit and close precede it) lags the command by lag_s; a kill by about
    kill_latency_s."""
    target = window["start"] + frac * (window["end"] - window["start"])
    return target - (lag_s if kind == "graceful" else kill_latency_s)


def docker_ts(s):
    """Docker's RFC 3339 nanosecond timestamp (State.StartedAt / FinishedAt) as epoch seconds."""
    if not s or s.startswith("0001-"):
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$", s.strip())
    if not m:
        return None
    import datetime as _dt
    base = _dt.datetime.fromisoformat(m.group(1) + (m.group(3).replace("Z", "+00:00")))
    return base.timestamp() + (float("0" + m.group(2)) if m.group(2) else 0.0)


def landed(effect_vm, windows):
    """The window (start, end on the VM clock) that contains the restart's effect, or None."""
    for w in windows:
        if effect_vm is not None and w[0] <= effect_vm <= w[1]:
            return w
    return None


def cost_windows_of(cost_lines, mode):
    """Every logged poll's read (direct) or copy (copy) window, as predict_window defines them, from a full cost log."""
    out = []
    for r in cost_lines:
        if r.get("ts") is None:
            continue
        t, c = float(r["ts"]), float(r.get("copy_ms") or 0.0) / 1000.0
        a = (float(r.get("load_ms") or 0.0) + float(r.get("commit_ms") or 0.0)) / 1000.0
        out.append((t - c, t + a) if mode == "direct" else (t - c, t))
    return out


def _sh(*cmd, timeout=60):
    r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def vm_offset(probe, n=5):
    """VM clock minus Mac clock, from the sample with the shortest round trip (docker exec of time.time())."""
    best = None
    for _ in range(n):
        t0 = time.time()
        rc, out, _e = _sh("docker", "exec", probe, "python", "-c", "import time;print(repr(time.time()))", timeout=20)
        t1 = time.time()
        if rc == 0:
            try:
                v = float(out.splitlines()[-1])
            except (ValueError, IndexError):
                continue
            if best is None or (t1 - t0) < best[1]:
                best = (v - (t0 + t1) / 2.0, t1 - t0)
    return best


def cmd_restart_trial(a):
    """One arm-R restart: predict the target monitor's next read/copy window from its cost log, fire `docker restart`
    (graceful) or `docker kill -s KILL` (+ `docker start`) so the effect lands at frac of it, record every time."""
    off = vm_offset(a.probe)
    if off is None:
        print(json.dumps({"ok": False, "err": "no VM clock offset"}))
        return 1
    rc, tail, err = _sh("docker", "exec", a.monitor, "tail", "-n", "16", "/scratch/cost.jsonl")
    lines = []
    for x in tail.splitlines():
        try:
            lines.append(json.loads(x))
        except ValueError:
            pass
    w = predict_window(lines, a.mode, time.time() + off[0])
    if w is None:
        print(json.dumps({"ok": False, "err": "too few cost lines", "rc": rc, "stderr": err[-200:]}))
        return 1
    fire_vm = fire_time_vm(w, a.kind, float(a.lag), float(a.frac))
    fire_mac = fire_vm - off[0]
    before = _sh("docker", "inspect", a.hub, "--format", "{{.State.StartedAt}} {{.State.FinishedAt}}")[1]
    while True:
        r = fire_mac - time.time()
        if r <= 0:
            break
        time.sleep(r - 0.004 if r > 0.006 else 0.0005)
    t_fire = time.time()
    if a.kind == "graceful":
        res = _sh("docker", "restart", "-t", str(int(a.stop_timeout)), a.hub, timeout=600)
    else:
        res = _sh("docker", "kill", "-s", "KILL", a.hub, timeout=60)
    t_ret = time.time()
    started_by_harness = False
    if a.kind == "kill":
        time.sleep(1.0)
        if _sh("docker", "inspect", a.hub, "--format", "{{.State.Running}}")[1] != "true":
            _sh("docker", "start", a.hub, timeout=120)
            started_by_harness = True
    after = _sh("docker", "inspect", a.hub, "--format", "{{.State.StartedAt}} {{.State.FinishedAt}}")[1]
    st, fin = (after.split() + [None, None])[:2]
    print(json.dumps({"ok": res[0] == 0, "kind": a.kind, "target": a.mode, "monitor": a.monitor, "frac": float(a.frac),
                      "lag_s_used": float(a.lag), "vm_offset_s": off[0], "vm_offset_rtt_s": off[1], "window_vm": w,
                      "fire_vm": fire_vm, "t_fire_mac": t_fire, "t_return_mac": t_ret,
                      "fire_error_s": t_fire - fire_mac, "docker_rc": res[0], "docker_stderr": res[2][-200:],
                      "inspect_before": before, "started_at": st, "finished_at": fin,
                      "finished_at_ts": docker_ts(fin), "started_at_ts": docker_ts(st),
                      "started_by_harness": started_by_harness}, sort_keys=True))
    return 0 if res[0] == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("restart-trial")
    s.add_argument("--hub", required=True)
    s.add_argument("--monitor", required=True)
    s.add_argument("--probe", required=True, help="a container on the same VM whose clock is read (an anchor)")
    s.add_argument("--mode", choices=("direct", "copy"), required=True)
    s.add_argument("--kind", choices=("graceful", "kill"), required=True)
    s.add_argument("--lag", type=float, default=RESTART_LAG0_S)
    s.add_argument("--frac", type=float, default=RESTART_FRAC)
    s.add_argument("--stop-timeout", type=float, default=RESTART_STOP_TIMEOUT_S)
    s = sub.add_parser("plan")
    s.add_argument("--seed", type=int, required=True)
    s.add_argument("--smoke", action="store_true")
    s = sub.add_parser("issue")
    s.add_argument("--kind", choices=("PURGE", "RESTORE", "RESTORE_DONE", "RENAME", "CLOCK_STEP"), required=True)
    s.add_argument("--window", nargs=2, type=float, help="CLOCK_STEP: [lo, hi] of the declared step")
    s.add_argument("--scheduled-ts", type=float)
    s.add_argument("--keep-days", type=float)
    s.add_argument("--restore-point-ts", type=float)
    s.add_argument("--parts", default="{}")
    s.add_argument("--extra", default="")
    s.add_argument("--note", default=None)
    s.add_argument("--anchors", nargs="+", required=True)
    s.add_argument("--sign-key", default="")
    s.add_argument("--issuer", default="/rig/marker_issuer.py")
    s.add_argument("--port", type=int, default=9900)
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--attempts", type=int, default=5)
    s.add_argument("--deadline", type=float, default=0.0)
    s.add_argument("--not-before", type=float, default=0.0)
    s = sub.add_parser("namemap")
    s.add_argument("--storage", required=True)
    s.add_argument("--monitor", default="/app/monitor.py")
    s.add_argument("--change", default="")
    s = sub.add_parser("pyguard")
    s.add_argument("--expect", default=PINNED_PY)
    a, rest = ap.parse_known_args()
    if a.cmd in ("plan", "issue", "namemap", "pyguard", "restart-trial"):
        return {"plan": cmd_plan, "issue": cmd_issue, "namemap": cmd_namemap, "pyguard": cmd_pyguard,
                "restart-trial": cmd_restart_trial}[a.cmd](a) or 0
    return 2


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("hostlog", "sleep-guard", "pmset", "namemap-sanitize", "ha-backup"):
        sys.argv[0] = E9OPS_PATH
        sys.exit(e9ops().main())
    sys.exit(main())
