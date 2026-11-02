"""E11 (round 15) host-side operations: the instrument and benign operations on a scratch openHAB, the renderer-closure
measurement, the plan, the interpreter guard. drafts/round13/E11_DESIGN.md is the design; this file implements it.

    pyguard      refuse unless this interpreter is the pinned one, 3.12 or later, and opens a WAL-mode SQLite copy
                 read-only (E9 amendment 3: the system Python 3.9.6 could not)
    plan         the session plan from the registered seed (arm order, A-BD mark offsets, device schedule, benign ops)
    provision    items, metadata and the motion-light rules through the hub's REST API (as the owner account)
    closure      E11-CLO: per-field mutation of the stored history and the item registry on the closure instance,
                 re-reading the rendered history after each (REST, both accounts); the in-place probe
    arm          one instrument arm (A-BD, A-RM, A-CHG): phase 1 genuine actions, seal wait, phase 2 the minimal edits,
                 the rendered history before and after each edit, for both accounts
    benign       one benign operation (B-REPLACE setup/same/new, B-BACKFILL, B-LABEL, B-CLEAN, B-RETAIN); B-RESTART is
                 done by e11_stack.sh and logged here with `benign --op B-RESTART --t0 .. --t1 ..`
    dbinner      (inside the closure instance's helper container only) dump / set / rename on the persistence database
    vmnow        the Docker VM's clock (through the harness container)

Every result is JSON on stdout or in the named output file. No key is ever printed: account passwords are read from the
run's credentials file (0600) and only their sha256 fingerprints appear in outputs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PINNED_PY = "<home>/miniconda3/bin/python3"
SEED = 20261021
SERVICE = "jdbc"
LOCK = "FrontDoor_Lock"
ROLES = ("owner", "member")                      # openHAB roles: administrator, user (no viewer role exists)
LATE_BOUND_S = 30.0
# The rendered history is read with the request Main UI's Analyze view issues. Captured by `uicapture` on a provisioned
# debug stack on 2026-10-24 (both accounts signed in; one request each: starttime, endtime, boundary=true,
# itemState=true): both differ from the REST defaults (false). boundary=true adds the stored points at the window's
# edges and is deterministic, so it is the default here, per the registered alternative, before --final. itemState=true
# appends the hub's LIVE item state stamped with the time of each query (two renders 2.5 s apart differed only in that
# point; tested 2026-10-24): it is not a stored row, no recorder edit can change it, and it would fail every
# before/after comparison of E11-CLO and the arms by construction. It is left out of those renders; uicapture replays
# Main UI's own request (with itemState) and compares bodies without that live point.
RENDER_EXTRA = json.loads(os.environ.get("E11_RENDER_PARAMS", '{"boundary": "true"}'))

# -------------------------------------------------------------------------------------------- items and devices
# (name, type, label, unit metadata or None). One fixture item per rendering path of the JDBC DAO (objectAsState:
# Switch/Contact via TypeParser, Number as DOUBLE, Number with a unit, Dimmer as TINYINT, String, DateTime).
ITEMS = [
    ("FrontDoor_Lock", "Switch", "Front door lock", None),
    ("Porch_Light", "Switch", "Porch light", None), ("Hallway_Light", "Switch", "Hallway light", None),
    ("Kitchen_Light", "Switch", "Kitchen light", None),
    ("Porch_Motion", "Contact", "Porch motion", None), ("Hallway_Motion", "Contact", "Hallway motion", None),
    ("Kitchen_Motion", "Contact", "Kitchen motion", None),
    ("Kitchen_Temp", "Number:Temperature", "Kitchen temperature", "°C"),
    ("Hallway_Temp", "Number:Temperature", "Hallway temperature", "°C"),
    ("Power_Meter", "Number:Power", "Power", "W"),
    ("Energy_Backfill", "Number:Energy", "Energy (backfilled)", "kWh"),
    ("Price_Forecast", "Number", "Price forecast", None),
    ("Retention_Probe", "Number", "Retention probe", None),
    ("Label_Probe", "Switch", "Label probe", None),
]
FIXTURES = [
    ("Fx_Switch", "Switch", "Fixture switch", None, ["ON", "OFF"]),
    ("Fx_Switch2", "Switch", "Fixture switch 2", None, ["OFF", "ON"]),
    ("Fx_Contact", "Contact", "Fixture contact", None, ["OPEN", "CLOSED"]),
    ("Fx_Number", "Number", "Fixture number", None, ["12.25", "13.5"]),
    ("Fx_Temperature", "Number:Temperature", "Fixture temperature", "°C", ["21.5 °C", "22.25 °C"]),
    ("Fx_Dimmer", "Dimmer", "Fixture dimmer", None, ["40", "55"]),
    ("Fx_String", "String", "Fixture string", None, ["alpha", "bravo"]),
    ("Fx_DateTime", "DateTime", "Fixture datetime", None, ["2026-10-20T10:00:00.000Z", "2026-10-20T11:30:00.000Z"]),
]
CLO_SCHEDULE = {   # closure instance, in-place probe only: one minute of every fixture updating
    "Fx_Switch": {"period_s": 7, "kind": "toggle", "values": ["ON", "OFF"]},
    "Fx_Contact": {"period_s": 6, "kind": "toggle", "values": ["OPEN", "CLOSED"]},
    "Fx_Number": {"period_s": 5, "kind": "walk", "lo": 10.0, "hi": 20.0},
    "Fx_Temperature": {"period_s": 5, "kind": "walk", "lo": 19.0, "hi": 24.0, "unit": "°C"},
    "Fx_Dimmer": {"period_s": 8, "kind": "choice", "values": ["10", "40", "70"]},
    "Fx_String": {"period_s": 9, "kind": "choice", "values": ["alpha", "bravo", "charlie"]},
}
RULES = [("%s_motion_light_%s" % (room, cmd.lower()), "%s_Motion" % room.capitalize(), st, "%s_Light" % room.capitalize(), cmd)
         for room in ("porch", "hallway", "kitchen") for st, cmd in (("OPEN", "ON"), ("CLOSED", "OFF"))]
SCHEDULE = {   # fixture device schedule (main stack): period per item, as a binding would update them
    "Kitchen_Temp": {"period_s": 10, "kind": "walk", "lo": 19.0, "hi": 24.0, "unit": "°C"},
    "Hallway_Temp": {"period_s": 10, "kind": "walk", "lo": 18.0, "hi": 22.0, "unit": "°C"},
    "Power_Meter": {"period_s": 3, "kind": "walk", "lo": 80.0, "hi": 900.0, "unit": "W"},
    "Porch_Motion": {"period_s": 75, "kind": "choice", "values": ["OPEN", "CLOSED", "CLOSED"]},
    "Hallway_Motion": {"period_s": 60, "kind": "choice", "values": ["OPEN", "CLOSED", "CLOSED"]},
    "Kitchen_Motion": {"period_s": 90, "kind": "choice", "values": ["OPEN", "CLOSED", "CLOSED"]},
    "Retention_Probe": {"period_s": 30, "kind": "counter", "lo": 0.0, "step": 1.0},
    "Energy_Backfill": {"period_s": 60, "kind": "counter", "lo": 1000.0, "step": 0.05, "unit": "kWh"},
    "Label_Probe": {"period_s": 420, "kind": "toggle", "values": ["ON", "OFF"]},
}


def fp16(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def ms_text(ms: int) -> str:
    """The DAO's stored text for an instant (UTC hub): 'YYYY-MM-DD HH:MM:SS.mmm'."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ms // 1000)) + ".%03d" % (ms % 1000)


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int(round((t % 1) * 1000) % 1000)


# ------------------------------------------------------------------------------------------------------- plan
ARMS = ("A-BD", "A-RM", "A-CHG")
ARM_N = 30
ARM_SPACING_S = 3.0
SEAL_WAIT_S = 130.0


def make_plan(seed: int, smoke: bool = False) -> dict:
    rng = random.Random(seed)
    order = list(ARMS)
    rng.shuffle(order)
    n = 3 if smoke else ARM_N
    k = 0.2 if smoke else 1.0                      # smoke: compressed windows
    plan = {
        "seed": seed, "smoke": smoke, "late_bound_s": LATE_BOUND_S,
        "warmup_s": round(600 * k), "window1_s": round(1500 * k), "window2_s": round(1800 * k), "settle_s": 90,
        "arms": [{"arm": a, "n": n, "spacing_s": ARM_SPACING_S, "seal_wait_s": SEAL_WAIT_S,
                  "mark_ms_offsets": [rng.randrange(0, 1000) for _ in range(n)] if a == "A-BD" else None}
                 for a in order],
        "replace": {"item": "Price_Forecast", "step_s": 300, "future_points": 12, "past_window_s": 1800,
                    "new_delta": 1.0},
        "backfill": {"item": "Energy_Backfill", "points": 10, "span_s": 600, "offset_s": 30.25},
        "retain": {"item": "Retention_Probe", "older_than_s": 1200},
        "label": {"item": "Label_Probe", "new_label": "Label probe (renamed by the owner)"},
        # benign blocks after the arms, in this order (B-REPLACE-1 runs at the start of window 1, so its future points
        # are past and sealed by the time B-REPLACE-2 and -3 run)
        "benign": ["B-REPLACE-SAME", "B-BACKFILL", "B-LABEL", "B-RESTART", "B-REPLACE-NEW", "B-BACKFILL", "B-CLEAN",
                   "B-RESTART", "B-BACKFILL", "B-RETAIN"],
        "benign_gap_s": round(120 * k),
        "schedule": SCHEDULE, "schedule_seed": seed,
    }
    return plan


# -------------------------------------------------------------------------------------------- REST and channel
class Rest:
    """openHAB REST API through the host-side tunnel, HTTP Basic as one account (runtime.cfg allows Basic auth)."""

    def __init__(self, base: str, account: str, password: str):
        self.base = base.rstrip("/")
        self.account = account
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (account, password)).encode()).decode()

    def req(self, method, path, body=None, ctype="application/json", query=None, timeout=30):
        url = self.base + path + (("?" + urllib.parse.urlencode(query)) if query else "")
        data = None
        if body is not None:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        r = urllib.request.Request(url, data=data, method=method, headers={"Authorization": self.auth,
                                                                          "Content-Type": ctype,
                                                                          "Accept": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=timeout) as x:
                raw = x.read()
                return x.status, (json.loads(raw) if raw and raw[:1] in (b"{", b"[") else raw.decode(errors="replace"))
        except urllib.error.HTTPError as e:
            raw = e.read() or b""
            return e.code, raw.decode(errors="replace")[:500]

    def history(self, item, t0, t1, extra=None):
        """(status, body) of the rendered history of item over [t0, t1] (unix seconds)."""
        q = {"serviceId": SERVICE, "starttime": iso(t0), "endtime": iso(t1)}
        q.update(RENDER_EXTRA)
        q.update(extra or {})
        return self.req("GET", "/rest/persistence/items/%s" % item, query=q)


def points(body) -> list:
    """[(time ms, state)] of a history body."""
    if not isinstance(body, dict):
        return []
    return [(int(d["time"]), str(d["state"])) for d in body.get("data") or []]


def read_creds(path):
    d = json.load(open(path))
    return {r: d[r] for r in ROLES}


def rests(base, creds):
    return {r: Rest(base, r, creds[r]) for r in ROLES}


class Ctl:
    """Host side of a bundle's command channel: write <dir>/cmd_<id>.json, wait for <dir>/ack_<id>.json (the run's
    hpctl directory is bind-mounted into the hub at /hpctl)."""

    _n = 0

    def __init__(self, d):
        self.dir = d
        os.makedirs(d, exist_ok=True)

    def call(self, op, timeout=40, **kw):
        Ctl._n += 1
        cid = "%d_%06d" % (int(time.time() * 1000), Ctl._n)
        tmp = os.path.join(self.dir, ".cmd_%s.tmp" % cid)
        with open(tmp, "w") as fh:
            json.dump(dict(op=op, **kw), fh)
        os.chmod(tmp, 0o666)
        os.replace(tmp, os.path.join(self.dir, "cmd_%s.json" % cid))
        ack = os.path.join(self.dir, "ack_%s.json" % cid)
        end = time.time() + timeout
        while time.time() < end:
            if os.path.exists(ack):
                try:
                    d = json.load(open(ack))
                except ValueError:
                    time.sleep(0.1)
                    continue
                os.remove(ack)
                return d
            time.sleep(0.1)
        return {"ok": False, "err": "timeout waiting for ack of %s" % op}


def vm_now(container):
    r = subprocess.run(["docker", "exec", container, "python3", "-c", "import time;print(repr(time.time()))"],
                       capture_output=True, text=True)
    return float(r.stdout.strip())


# ---------------------------------------------------------------------------------------------------- provision
def provision(base, creds, closure_fixtures=False):
    """Main stack: the household's items, units and six motion-light rules. Closure instance: the fixture items only."""
    owner = Rest(base, "owner", creds["owner"])
    out = {"items": {}, "metadata": {}, "rules": {}}
    spec = [(n, t, l, u) for n, t, l, u, _v in FIXTURES] if closure_fixtures else [(n, t, l, u) for n, t, l, u in ITEMS]
    for name, typ, label, unit in spec:
        body = {"type": typ, "name": name, "label": label, "category": None, "tags": [], "groupNames": []}
        out["items"][name] = owner.req("PUT", "/rest/items/%s" % name, body)[0]
        if unit:
            out["metadata"][name] = owner.req("PUT", "/rest/items/%s/metadata/unit" % name,
                                              {"value": unit, "config": {}})[0]
    if not closure_fixtures:
        for uid, motion, state, light, command in RULES:
            rule = {"uid": uid, "name": uid.replace("_", " "), "triggers": [
                {"id": "1", "type": "core.ItemStateChangeTrigger", "configuration": {"itemName": motion, "state": state}}],
                "conditions": [], "actions": [{"id": "2", "type": "core.ItemCommandAction",
                                               "configuration": {"itemName": light, "command": command}}]}
            out["rules"][uid] = owner.req("POST", "/rest/rules", rule)[0]
    st, persist = owner.req("GET", "/rest/persistence")
    out["persistence_services"] = persist if st == 200 else {"status": st}
    out["ok"] = all(v in (200, 201) for v in out["items"].values()) and \
        all(v in (200, 201) for v in out["metadata"].values()) and \
        all(v in (200, 201) for v in out["rules"].values())
    return out


# --------------------------------------------------------------------------------------------- instrument arms
def window_points(rest, t0, t1):
    st, body = rest.history(LOCK, t0, t1)
    return st, points(body), body


def newest(pts, after_ms=None, state=None):
    c = [p for p in pts if (after_ms is None or p[0] > after_ms) and (state is None or p[1] == state)]
    return max(c) if c else None


def wait_point(rest, t0, after_ms, state, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        _st, pts, _b = window_points(rest, t0, time.time() + 60)
        p = newest(pts, after_ms, state)
        if p:
            return p
        time.sleep(0.4)
    return None


def run_arm(a, plan_arm, base, creds, hpctl, harness, out_path):
    R = rests(base, creds)
    lock = Ctl(os.path.join(hpctl, "lock"))
    info = lock.call("info")
    if not info.get("ok"):
        raise SystemExit("instrument bundle not answering: %r" % info)
    arm, n = plan_arm["arm"], plan_arm["n"]
    host_minus_vm = time.time() - vm_now(harness)
    rep = {"experiment": "E11", "arm": arm, "item": LOCK, "n_requested": n, "seal_wait_s": plan_arm["seal_wait_s"],
           "instrument": info, "host_minus_vm_s": host_minus_vm, "trials": [], "t_arm_start": time.time()}
    w0 = time.time() - 300
    for i in range(n):
        rec = {"arm": arm, "trial": i}
        if arm == "A-BD":
            # a moment at which nothing happens to the lock: its second is sealed by the time the row is inserted
            now_vm = time.time() - host_minus_vm
            ms = int(now_vm) * 1000 + int(plan_arm["mark_ms_offsets"][i])
            if ms > now_vm * 1000:
                ms -= 1000
            rec["mark"] = {"time_ms": ms, "time_text": ms_text(ms)}
        else:
            _st, pts, _b = window_points(R["owner"], w0, time.time() + 60)
            prev = newest(pts)
            rl = lock.call("relock")
            relock_pt = wait_point(R["owner"], w0, prev[0] if prev else None, "ON", timeout=6)
            rec["relock"] = {"ack": rl, "row": list(relock_pt) if relock_pt else None,
                             "already_locked": relock_pt is None and bool(prev and prev[1] == "ON")}
            time.sleep(1.5)
            after = relock_pt[0] if relock_pt else (prev[0] if prev else None)
            st = R["member"].req("POST", "/rest/items/%s" % LOCK, "OFF", ctype="text/plain")[0]
            tgt = wait_point(R["owner"], w0, after, "OFF", timeout=20)
            rec["unlock"] = {"rest_status": st, "account": "member"}
            if not tgt:
                rec["err"] = "no persisted unlock row within 20 s"
                rep["trials"].append(rec)
                continue
            rec["target"] = {"time_ms": tgt[0], "time_text": ms_text(tgt[0]), "state": tgt[1]}
        rep["trials"].append(rec)
        time.sleep(plan_arm["spacing_s"])
    rep["t_phase1_end"] = time.time()
    rest_s = plan_arm["seal_wait_s"] - (time.time() - rep["t_phase1_end"])
    if rest_s > 0:
        time.sleep(rest_s)
    for rec in rep["trials"]:
        if rec.get("err"):
            continue
        before = {r: window_points(R[r], w0, time.time() + 60) for r in ROLES}
        if arm == "A-BD":
            ed = lock.call("persist_at", time_ms=rec["mark"]["time_ms"], state="OFF")
            tms, want_before, want_after = rec["mark"]["time_ms"], None, "OFF"
        elif arm == "A-RM":
            ed = lock.call("remove_second", second=rec["target"]["time_ms"] // 1000)
            tms, want_before, want_after = rec["target"]["time_ms"], "OFF", None
        else:
            ed = lock.call("change_value", time_ms=rec["target"]["time_ms"], state="ON")
            tms, want_before, want_after = rec["target"]["time_ms"], "OFF", "ON"
        rec["edit"] = ed
        if not ed.get("ok"):
            rec["err"] = "edit failed: %r" % ed
            continue
        after = {r: window_points(R[r], w0, time.time() + 60) for r in ROLES}
        per = {}
        for r in ROLES:
            b = dict(before[r][1])
            a_ = dict(after[r][1])
            others_b = {k: v for k, v in b.items() if k != tms}
            others_a = {k: v for k, v in a_.items() if k != tms}
            per[r] = {"status_before": before[r][0], "status_after": after[r][0],
                      "state_at_target_before": b.get(tms), "state_at_target_after": a_.get(tms),
                      "rendered_as_intended": b.get(tms) == want_before and a_.get(tms) == want_after,
                      "other_points_unchanged": others_b == others_a}
        rec["per_role"] = per
        rec["instrument_effect_rendered_all_roles"] = all(per[r]["rendered_as_intended"] for r in ROLES)
        rec["same_render_for_every_role"] = len({json.dumps(after[r][2], sort_keys=True) for r in ROLES}) == 1
        rec["row_ts"] = tms / 1000.0
        rec["edit_delay_s"] = ed["t_edit"] - rec["row_ts"]
    rep["t_arm_end"] = time.time()
    with open(out_path, "x") as fh:
        json.dump(rep, fh, indent=1)
    ok = [t for t in rep["trials"] if not t.get("err")]
    print(json.dumps({"arm": arm, "valid": len(ok), "n": n,
                      "rendered_as_intended": sum(1 for t in ok if t.get("instrument_effect_rendered_all_roles"))}))


# ------------------------------------------------------------------------------------------------ benign ops
def grid(t, step):
    return int(t // step) * step


def benign(op, plan, base, creds, hpctl, log_path, extra=None):
    fx = Ctl(os.path.join(hpctl, "fixture"))
    owner = Rest(base, "owner", creds["owner"])
    t0 = time.time()
    res = {"op": op, "t_start": t0}
    if op.startswith("B-REPLACE"):
        p = plan["replace"]
        step, now = p["step_s"], time.time()
        variant = op.split("-", 2)[2]                 # B-REPLACE-SETUP, B-REPLACE-SAME, B-REPLACE-NEW
        if variant == "SETUP":
            pts = [[int((grid(now, step) + step * (i + 1)) * 1000), "%.2f" % (20 + i * 0.5)]
                   for i in range(p["future_points"])]
        else:
            begin = grid(now - p["past_window_s"], step) + step
            cur = fx.call("rows", item=p["item"], from_ms=int(begin * 1000), to_ms=int((now + 4 * 3600) * 1000))
            have = {int(t): s for t, s in (cur.get("rows") or [])}
            pts = []
            tt = begin
            while tt <= now + step * p["future_points"]:
                ms = int(tt * 1000)
                v = have.get(ms)
                if tt < now:
                    if v is None:                     # no earlier point here: re-sending none keeps the op benign
                        tt += step
                        continue
                    v = ("%.2f" % (float(v) + p["new_delta"])) if variant == "NEW" else v
                elif v is None:
                    v = "%.2f" % (30 + (tt % 3600) / 600)
                pts.append([ms, v])
                tt += step
        r = fx.call("timeseries", timeout=60, item=p["item"], policy="REPLACE", points=pts)
        res.update(variant=variant, item=p["item"], points=pts, result=r,
                   affected_past=[[ms, v] for ms, v in pts if ms < t0 * 1000])
    elif op == "B-BACKFILL":
        p = plan["backfill"]
        now = time.time()
        pts = [[int((grid(now - p["span_s"], 60) + 60 * i + p["offset_s"]) * 1000), "%.3f kWh" % (900 + i * 0.01)]
               for i in range(p["points"])]
        pts = [x for x in pts if x[0] < (now - 5) * 1000]
        r = fx.call("timeseries", timeout=60, item=p["item"], policy="ADD", points=pts)
        res.update(item=p["item"], points=pts, result=r, affected_past=pts)
    elif op == "B-LABEL":
        p = plan["label"]
        st, cur = owner.req("GET", "/rest/items/%s" % p["item"])
        body = {"type": cur["type"], "name": cur["name"], "label": p["new_label"], "category": cur.get("category"),
                "tags": cur.get("tags") or [], "groupNames": cur.get("groupNames") or []}
        res.update(item=p["item"], label_before=cur.get("label"), label_after=p["new_label"],
                   status=owner.req("PUT", "/rest/items/%s" % p["item"], body)[0])
    elif op == "B-RETAIN":
        p = plan["retain"]
        until = int(time.time() - p["older_than_s"]) * 1000
        r = fx.call("remove_until", timeout=60, item=p["item"], until_ms=until)
        res.update(item=p["item"], until_ms=until, result=r, affected_past=r.get("removed") or [])
    elif op in ("B-RESTART", "B-CLEAN"):
        res.update(extra or {})
    else:
        raise SystemExit("unknown benign op %s" % op)
    res["t_end"] = time.time()
    with open(log_path, "a") as fh:
        fh.write(json.dumps(res) + "\n")
    print(json.dumps({"op": op, "ok": (res.get("result") or {}).get("ok", True),
                      "affected_past": len(res.get("affected_past") or [])}))


# ---------------------------------------------------------------------------------------------- dbinner (helper)
DBPATH = "/hub/persistence/jdbc/openhab.db"


def dbinner(a):
    con = sqlite3.connect(DBPATH, timeout=30, isolation_level=None)
    if a.key is not None and a.key.lstrip("-").isdigit():
        a.key = int(a.key)
    if a.op == "dump":
        out = {}
        for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            cols = ["rowid"] + [r[1] for r in con.execute('PRAGMA table_info("%s")' % t)]
            out[t] = {"cols": cols, "rows": {str(r[0]): list(r) for r in con.execute('SELECT rowid, * FROM "%s"' % t)}}
        jd = "/hub/jsondb"
        for f in ("org.openhab.core.items.Item.json", "org.openhab.core.items.Metadata.json"):
            p = os.path.join(jd, f)
            out["jsondb:" + f] = json.load(open(p)) if os.path.exists(p) else None
        print(json.dumps(out, default=str))
    else:   # [Withheld from the artifact: the helper's write operations (set, rename, delete_row, cleanup, insert_row), which edit the closure instance's persistence database in place for E11-CLO's mutations. See README.md, "What is deliberately not here".]
        raise SystemExit("withheld from the artifact: dbinner %s" % a.op)
    con.close()


class Db:
    """Host side of dbinner: docker exec into the closure instance's helper container."""

    def __init__(self, container):
        self.c = container

    def __call__(self, *args):
        r = subprocess.run(["docker", "exec", self.c, "python3", "/e11/e11ops.py", "dbinner"] + [str(x) for x in args],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("dbinner %s failed: %s" % (args[:2], r.stderr[-800:]))
        return json.loads(r.stdout)


# ------------------------------------------------------------------------------------------------- E11-CLO
PREDICTED_CLOSURE = ["items.ItemId", "items.ItemName", "<table>.time", "<table>.value", "<table> (name)",
                     "registry.itemType", "registry.meta.unit"]
PREDICTED_NOT = ["<table>.rowid", "registry.label", "registry.category", "registry.tags", "registry.groupNames",
                 "registry.meta.stateDescription (unless the history is requested with displayState=true)"]


def time_mutations(v):
    if not isinstance(v, str) or len(v) < 19:
        return [("to_text_now", "2026-01-01 00:00:00.000")]
    import calendar                                   # noqa: PLC0415
    sec = calendar.timegm(time.strptime(v[:19], "%Y-%m-%d %H:%M:%S"))
    frac = v[19:]
    return [("plus_1s", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec + 1)) + frac),
            ("minus_3d", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec - 3 * 86400)) + frac),
            ("drop_ms", v[:19]), ("iso_T", v[:10] + "T" + v[11:]),
            ("integer_ms", int(sec * 1000 + round(float(frac or "0") * 1000)))]


def value_mutations(typ, v, alt):
    out = [("suffix", "%s-mut" % v), ("empty", ""), ("null", None)]
    if alt is not None and alt != v:
        out.append(("other_valid", alt))
    if typ.startswith("Number") and isinstance(v, (int, float)):
        out += [("plus_1", v + 1), ("below_render_precision", v + 0.0004)]
    if typ == "Dimmer" and isinstance(v, int):
        out.append(("plus_1", v + 1))
    return out


def compare(base, got, tms):
    bs, bb = base
    gs, gb = got
    bp, gp = dict(points(bb)), dict(points(gb))
    return {"status": [bs, gs], "rendered_output_changed": (bs, bb) != (gs, gb),
            "target_point_changed": bp.get(tms) != gp.get(tms), "target_point_vanished": tms in bp and tms not in gp,
            "other_points_changed": {k: v for k, v in bp.items() if k != tms} != {k: v for k, v in gp.items() if k != tms},
            "unit_changed": (bb or {}).get("unit") != (gb or {}).get("unit") if isinstance(bb, dict) and isinstance(gb, dict)
            else None, "target_after": gp.get(tms)}


def closure(a):
    creds = read_creds(a.creds)
    R = rests(a.base, creds)
    owner = R["owner"]
    db = Db(a.dbhelper)
    fx = Ctl(os.path.join(a.hpctl, "fixture"))
    console = lambda cmd: subprocess.run([os.path.join(HERE, "e11_stack.sh"), "console", a.prefix, cmd],  # noqa: E731
                                         capture_output=True, text=True).stdout[-400:]
    fx.call("pause")
    only = [x for x in os.environ.get("E11_CLO_FIXTURES", "").split(",") if x]   # smoke: a subset of the fixtures
    fixtures = [f for f in FIXTURES if not only or f[0] in only]
    created = {}
    for name, typ, _l, _u, vals in fixtures:           # a predecessor row, then the target row, 1.5 s apart
        for v in vals:
            fx.call("set_state", item=name, state=v)
            time.sleep(1.5)
        created[name] = time.time()
    time.sleep(3)
    dump0 = db("dump")
    items_rows = {r[2]: r for r in dump0["items"]["rows"].values()} if "items" in dump0 else {}
    out = {"fixtures": [], "items_columns": dump0.get("items", {}).get("cols"), "predicted_closure": PREDICTED_CLOSURE,
           "predicted_not_in_closure": PREDICTED_NOT, "render_extra": RENDER_EXTRA}
    try:
        _closure_fixtures(out, fixtures, dump0, created, R, owner, db, console)
    except BaseException as exc:                        # a failed restore: keep what was measured, for diagnosis
        out["aborted"] = repr(exc)[:400]
        with open(a.out + ".partial.json", "w") as fh:
            json.dump(out, fh, indent=1, default=str)
        raise
    _closure_in_place(a, out, fixtures, R, db, fx)


def _closure_fixtures(out, fixtures, dump0, created, R, owner, db, console):
    items_rows = {r[2]: r for r in dump0["items"]["rows"].values()} if "items" in dump0 else {}
    for name, typ, _label, unit, vals in fixtures:
        irow = items_rows.get(name)
        iid = irow[1]
        table = "item%04d" % iid
        trows = sorted(dump0[table]["rows"].values(), key=lambda r: r[0])
        cols = dump0[table]["cols"]
        tgt = trows[-1]
        tms = None
        t_lo, t_hi = created[name] - 86400, created[name] + 86400
        render = lambda r="owner": R[r].history(name, t_lo, t_hi)  # noqa: E731
        base = render()
        tms = max(points(base[1]))[0] if points(base[1]) else None
        fx_rec = {"item": name, "type": typ, "unit": unit, "item_id": iid, "table": table, "target_rowid": tgt[0],
                  "target_row": dict(zip(cols, tgt)), "baseline": base, "baseline_target_ms": tms,
                  "determinism_control_equal": render() == base,
                  "same_render_for_every_role": all(render(r) == base for r in ROLES),
                  "dto_top_level_keys": sorted(base[1].keys()) if isinstance(base[1], dict) else None,
                  "dto_point_keys": sorted((base[1].get("data") or [{}])[0].keys()) if isinstance(base[1], dict) else None,
                  "mutations": []}

        def record(field, label, mutated_to, got, extra=None):
            restored = render()
            m = {"field": field, "mutation": label, "mutated_to": mutated_to, **compare(base, got, tms),
                 "restore_equal_to_baseline": restored == base}
            m.update(extra or {})
            fx_rec["mutations"].append(m)
            if not m["restore_equal_to_baseline"]:
                raise SystemExit("restore failed after %s %s" % (field, label))

        # --- the stored row
        ci = {c: i for i, c in enumerate(cols)}
        for label, new in time_mutations(tgt[ci["time"]]):
            o = db("set", table, "rowid", tgt[0], "time", json.dumps(new))["orig"]
            got = render()
            db("set", table, "rowid", tgt[0], "time", json.dumps(o))
            record("<table>.time", label, new, got)
        alt = None
        prev = trows[-2] if len(trows) > 1 else None
        if prev is not None:
            alt = prev[ci["value"]]
        for label, new in value_mutations(typ, tgt[ci["value"]], alt):
            o = db("set", table, "rowid", tgt[0], "value", json.dumps(new))["orig"]
            got = render()
            db("set", table, "rowid", tgt[0], "value", json.dumps(o))
            record("<table>.value", label, new, got)
        fresh = max(int(k) for k in dump0[table]["rows"]) + 100
        db("set", table, "rowid", tgt[0], "rowid", json.dumps(fresh))
        got = render()
        db("set", table, "rowid", fresh, "rowid", json.dumps(tgt[0]))
        record("<table>.rowid", "fresh_key", fresh, got)
        db("rename", table, "x", 0, "x", table + "_mut")
        got = render()
        db("rename", table + "_mut", "x", 0, "x", table)
        record("<table> (name)", "renamed", table + "_mut", got)
        # --- the index row: immediately, and after `jdbc reload` (the service caches the index)
        other = items_rows["Fx_Switch2" if name != "Fx_Switch2" else "Fx_Switch"]
        max_id = max(r[1] for r in items_rows.values())
        tables0 = sorted(t for t in dump0 if not t.startswith("jsondb:"))
        for col, label, new in (("ItemName", "suffix", name + "_mut"), ("ItemName", "swap_with_other_item", other[2]),
                                ("ItemId", "fresh_id", max(r[1] for r in items_rows.values()) + 100)):
            if label == "swap_with_other_item":
                db("set", "items", "ItemId", other[1], "ItemName", json.dumps(name + "_tmp"))
            o = db("set", "items", "ItemId", iid, col, json.dumps(new))["orig"]
            if label == "swap_with_other_item":
                db("set", "items", "ItemId", other[1], "ItemName", json.dumps(name))
            got_now = render()
            console("openhab:jdbc reload")
            got_reload = render()
            key_now = new if col == "ItemId" else iid
            if label == "swap_with_other_item":
                db("set", "items", "ItemId", other[1], "ItemName", json.dumps(name + "_tmp"))
            db("set", "items", "ItemId", key_now, col, json.dumps(o))
            if label == "swap_with_other_item":
                db("set", "items", "ItemId", other[1], "ItemName", json.dumps(other[2]))
            cl = db("cleanup", "items", "ItemId", max_id, "x", json.dumps(tables0))
            console("openhab:jdbc reload")
            imm = compare(base, got_now, tms)
            record("items.%s" % col, label, new, got_reload, {"immediately": imm, "cleanup": cl})
        # --- the item registry (through the registry's own REST API, as in-runtime code would use the registry)
        st, cur = owner.req("GET", "/rest/items/%s" % name)
        body0 = {"type": cur["type"], "name": name, "label": cur.get("label"), "category": cur.get("category"),
                 "tags": cur.get("tags") or [], "groupNames": cur.get("groupNames") or []}
        other_type = {"Switch": "Contact", "Contact": "Switch", "Number": "String", "Number:Temperature": "Number:Length",
                      "Dimmer": "Number", "String": "Number", "DateTime": "String"}[typ]
        for field, label, patch in (("registry.itemType", "to_" + other_type, {"type": other_type}),
                                    ("registry.label", "suffix", {"label": (cur.get("label") or "") + " mut"}),
                                    ("registry.category", "set", {"category": "lock"}),
                                    ("registry.tags", "add", {"tags": ["E11Tag"]}),
                                    ("registry.groupNames", "add", {"groupNames": ["gE11"]})):
            put_st = owner.req("PUT", "/rest/items/%s" % name, dict(body0, **patch))[0]
            got = render()
            owner.req("PUT", "/rest/items/%s" % name, body0)
            if unit:
                owner.req("PUT", "/rest/items/%s/metadata/unit" % name, {"value": unit, "config": {}})
            record(field, label, patch, got, {"put_status": put_st})
        meta = [("registry.meta.stateDescription", "pattern", "stateDescription", {"value": " ", "config": {"pattern": "%.4f"}})]
        meta += [("registry.meta.unit", "to_degF", "unit", {"value": "°F", "config": {}})] if unit else \
            [("registry.meta.unit", "add", "unit", {"value": "kW" if typ == "Number" else "%", "config": {}})]
        for field, label, ns, val in meta:
            owner.req("PUT", "/rest/items/%s/metadata/%s" % (name, ns), val)
            got = render()
            got_ds = R["owner"].history(name, t_lo, t_hi, {"displayState": "true"})
            if ns == "unit" and unit:
                owner.req("PUT", "/rest/items/%s/metadata/unit" % name, {"value": unit, "config": {}})
            else:
                owner.req("DELETE", "/rest/items/%s/metadata/%s" % (name, ns))
            record(field, label, val, got, {"with_displayState": compare(base, got_ds, tms)})
        owner.req("DELETE", "/rest/items/%s" % name)
        got = render()
        owner.req("PUT", "/rest/items/%s" % name, body0)
        if unit:
            owner.req("PUT", "/rest/items/%s/metadata/unit" % name, {"value": unit, "config": {}})
        record("registry (item entry)", "deleted", None, got)
        ctrl = [m for m in fx_rec["mutations"] if m["field"] == "<table>.value" and m["mutation"] == "other_valid"]
        fx_rec["positive_control_value_change_changed_render"] = bool(ctrl) and all(m["target_point_changed"] for m in ctrl)
        out["fixtures"].append(fx_rec)


def _closure_in_place(a, out, fixtures, R, db, fx):
    # --- in-place probe: which stored fields does openHAB rewrite in place during benign operation?
    before = db("dump")
    ops = []
    fx.call("schedule", items={k: v for k, v in CLO_SCHEDULE.items() if k in {f[0] for f in fixtures}}, seed=SEED)
    fx.call("resume")
    for r in ROLES:
        for v in ("ON", "OFF"):
            ops.append({"op": "%s command Fx_Switch %s" % (r, v),
                        "status": R[r].req("POST", "/rest/items/Fx_Switch", v, ctype="text/plain")[0]})
            time.sleep(1.2)
    for name, _t, _l, _u, vals in fixtures:
        fx.call("set_state", item=name, state=vals[0])
        time.sleep(1.1)
    time.sleep(60)
    fx.call("pause")
    restart_rc = subprocess.run([os.path.join(HERE, "e11_stack.sh"), "restart", a.prefix], capture_output=True, text=True).returncode
    ops.append({"op": "hub restart", "res": restart_rc})
    time.sleep(30)
    after = db("dump")
    diff = {}
    for t in sorted(set(before) | set(after)):
        b, af = before.get(t), after.get(t)
        if t.startswith("jsondb:"):
            diff[t] = {"entries_before": len(b or {}), "entries_after": len(af or {}),
                       "entries_changed_in_place": sorted(k for k in (b or {}) if k in (af or {}) and b[k] != af[k])}
            continue
        if b is None or af is None:
            diff[t] = {"table_added" if b is None else "table_removed": True}
            continue
        changed = {}
        for k, rb in b["rows"].items():
            ra = af["rows"].get(k)
            if ra is None:
                continue
            for i, c in enumerate(b["cols"]):
                if rb[i] != ra[i]:
                    changed.setdefault(c, []).append(k)
        diff[t] = {"rows_before": len(b["rows"]), "rows_after": len(af["rows"]),
                   "rows_deleted": sorted(set(b["rows"]) - set(af["rows"]), key=int),
                   "rows_added": len(set(af["rows"]) - set(b["rows"])),
                   "columns_rewritten_in_place": {c: len(v) for c, v in changed.items()}}
    # valid only if the hub really restarted (smoke 2, 2026-10-24: the restart failed, so its empty result meant nothing)
    out["in_place_probe"] = {"operations": ops, "diff": diff, "restart_ok": restart_rc == 0,
                             "tables_with_in_place_rewrites": sorted(t for t, d in diff.items()
                                                                     if d.get("columns_rewritten_in_place")
                                                                     or d.get("entries_changed_in_place"))}
    out["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, default=str)
    print(json.dumps({"fixtures": len(out["fixtures"]), "mutations": sum(len(f["mutations"]) for f in out["fixtures"]),
                      "in_place": out["in_place_probe"]["tables_with_in_place_rewrites"]}))
    if restart_rc != 0:
        raise SystemExit("in-place probe invalid: the hub restart failed (e11_stack.sh restart exit %d)" % restart_rc)


# ------------------------------------------------------------------------------------------------- UI capture
def uicapture(a):
    """Main UI's Analyze view for one item in a headless browser, as one account: every /rest/persistence request the
    page makes (URL with its query, status, body sha256, whether the body equals the harness's own REST read with the
    same query) and a screenshot. Used in the smoke to fix the render request (E11_RENDER_PARAMS) and, in the run,
    as the UI-agreement check of the instrument arms (secondary outcome)."""
    from playwright.sync_api import sync_playwright        # noqa: PLC0415
    creds = read_creds(a.creds)
    seen = []
    out = {"item": a.item, "account": a.account, "url": None, "requests": seen, "error": None}
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        try:
            ctx = b.new_context(viewport={"width": 1400, "height": 1000},
                                http_credentials={"username": a.account, "password": creds[a.account]})
            page = ctx.new_page()

            def on_resp(r):
                if "/rest/persistence/items/" in r.url:
                    try:
                        body = r.body()
                    except Exception:                     # noqa: BLE001
                        body = b""
                    seen.append({"url": r.url, "status": r.status, "body_sha256": hashlib.sha256(body).hexdigest(),
                                 "body": body.decode(errors="replace")[:200000]})
            page.on("response", on_resp)
            out["url"] = a.base.rstrip("/") + "/analyzer/?items=%s" % a.item
            page.goto(out["url"], wait_until="networkidle", timeout=60000)
            # Main UI ignores HTTP basic credentials: an admin page redirects to openHAB's own sign-in form (smoke 2,
            # 2026-10-24: every capture stopped there with 0 requests). Sign in as the account, then reopen the view.
            out["signed_in"] = False
            try:      # Main UI loads first and redirects to the form a moment later (smoke 4: count 0 at first look)
                page.wait_for_selector("input[name=username]", timeout=20000)
            except Exception:                             # noqa: BLE001
                pass
            if page.locator("input[name=username]").count():
                page.fill("input[name=username]", a.account)
                page.fill("input[name=password]", creds[a.account])
                page.click("input[type=Submit], input.submit, button[type=submit]")
                # signed in, Main UI holds an event stream open, so the network never goes idle: wait for load instead
                page.wait_for_load_state("load", timeout=60000)
                page.wait_for_timeout(3000)
                out["signed_in"] = page.locator("input[name=username]").count() == 0
                if out["signed_in"] and "/analyzer" not in page.url:
                    page.goto(out["url"], wait_until="load", timeout=60000)
                out["after_sign_in_url_path"] = urllib.parse.urlparse(page.url).path
                if not seen:
                    try:
                        page.wait_for_response(lambda r: "/rest/persistence/items/" in r.url, timeout=30000)
                    except Exception:                     # noqa: BLE001
                        pass
            page.wait_for_timeout(3000)
            page.screenshot(path=a.screenshot, full_page=True)
            out["screenshot"] = a.screenshot
            out["screenshot_sha256"] = hashlib.sha256(open(a.screenshot, "rb").read()).hexdigest()
        except Exception as exc:                          # noqa: BLE001
            out["error"] = repr(exc)[:400]
        finally:
            b.close()
    rest = Rest(a.base, a.account, creds[a.account])
    for r in seen:
        q = urllib.parse.urlparse(r["url"])
        st, body = rest.req("GET", q.path, query=dict(urllib.parse.parse_qsl(q.query)))
        r["query"] = dict(urllib.parse.parse_qsl(q.query))
        ui_body = json.loads(r["body"]) if r["body"][:1] == "{" else None
        live = r["query"].get("itemState") == "true"     # the last point is the live state at query time: drop it
        strip = (lambda b: {**b, "data": (b.get("data") or [])[:-1]} if live and isinstance(b, dict) else b)  # noqa: E731
        r["compared_without_live_item_state_point"] = live
        r["harness_read_equal"] = (st == r["status"] and isinstance(body, dict)
                                   and strip(ui_body) == strip(body)) if ui_body is not None else None
        r.pop("body", None)
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({"requests": len(seen), "error": out["error"],
                      "queries": [r["query"] for r in seen], "agree": [r["harness_read_equal"] for r in seen]}))


# ------------------------------------------------------------------------------------------------------ guard
def cmd_pyguard(a):
    exe = os.path.realpath(sys.executable)
    want = os.path.realpath(a.expect)
    d = tempfile.mkdtemp(prefix="e11py_")
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
                      "sqlite": sqlite3.sqlite_version, "wal_copy_readable_ro": n == 1}))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("pyguard")
    s.add_argument("--expect", default=PINNED_PY)
    s = sub.add_parser("plan")
    s.add_argument("--seed", type=int, default=SEED)
    s.add_argument("--smoke", action="store_true")
    s = sub.add_parser("provision")
    s.add_argument("--base", required=True)
    s.add_argument("--creds", required=True)
    s.add_argument("--closure-fixtures", action="store_true")
    s = sub.add_parser("closure")
    for k in ("--base", "--creds", "--hpctl", "--dbhelper", "--prefix", "--out"):
        s.add_argument(k, required=True)
    s = sub.add_parser("arm")
    for k in ("--base", "--creds", "--hpctl", "--harness", "--plan", "--out"):
        s.add_argument(k, required=True)
    s.add_argument("--arm", required=True, choices=ARMS)
    s = sub.add_parser("benign")
    for k in ("--base", "--creds", "--hpctl", "--plan", "--log"):
        s.add_argument(k, required=True)
    s.add_argument("--op", required=True)
    s.add_argument("--extra", default="{}")
    s = sub.add_parser("schedule")
    for k in ("--hpctl", "--plan"):
        s.add_argument(k, required=True)
    s.add_argument("--action", choices=("set", "pause", "resume", "info"), default="set")
    s = sub.add_parser("instrument-info")
    s.add_argument("--hpctl", required=True)
    s = sub.add_parser("dbinner")
    s.add_argument("op", choices=("dump", "set", "rename", "delete_row", "insert_row", "cleanup"))
    s.add_argument("table", nargs="?")
    s.add_argument("keycol", nargs="?")
    s.add_argument("key", nargs="?")
    s.add_argument("col", nargs="?")
    s.add_argument("value", nargs="?")
    s = sub.add_parser("uicapture")
    for k in ("--base", "--creds", "--item", "--account", "--out", "--screenshot"):
        s.add_argument(k, required=True)
    s = sub.add_parser("vmnow")
    s.add_argument("--harness", required=True)
    a = ap.parse_args()
    if a.cmd == "pyguard":
        return cmd_pyguard(a)
    if a.cmd == "plan":
        print(json.dumps(make_plan(a.seed, a.smoke), indent=1, sort_keys=True))
        return 0
    if a.cmd == "provision":
        r = provision(a.base, read_creds(a.creds), a.closure_fixtures)
        print(json.dumps(r))
        return 0 if r["ok"] else 1
    if a.cmd == "closure":
        closure(a)
        return 0
    if a.cmd == "arm":
        plan = json.load(open(a.plan))
        pa = next(x for x in plan["arms"] if x["arm"] == a.arm)
        run_arm(a, pa, a.base, read_creds(a.creds), a.hpctl, a.harness, a.out)
        return 0
    if a.cmd == "benign":
        benign(a.op, json.load(open(a.plan)), a.base, read_creds(a.creds), a.hpctl, a.log, json.loads(a.extra))
        return 0
    if a.cmd == "schedule":
        fx = Ctl(os.path.join(a.hpctl, "fixture"))
        plan = json.load(open(a.plan))
        if a.action == "set":
            r = fx.call("schedule", items=plan["schedule"], seed=plan["schedule_seed"])
        else:
            r = fx.call(a.action)
        print(json.dumps(r))
        return 0 if r.get("ok") else 1
    if a.cmd == "instrument-info":
        r = Ctl(os.path.join(a.hpctl, "lock")).call("info")
        print(json.dumps(r))
        return 0 if r.get("ok") else 1
    if a.cmd == "dbinner":
        dbinner(a)
        return 0
    if a.cmd == "uicapture":
        uicapture(a)
        return 0
    if a.cmd == "vmnow":
        print(repr(vm_now(a.harness)))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
