"""E10 arm C (review r5 Z4; drafts/round13/E10_ADDENDUM_R5.md section C), host side: a BENIGN switch-type change of the
Domoticz front-door lock with the closure monitor live. Called by testbed/e10/run_dz_switchtype.sh.

  pre     PRE_S seconds of ordinary lock traffic: every 30 s the household member's account switches the lock through
          the API, alternating Off / On (the E-DZ member actuation, dz_arms.member_unlock), so the lock has committed
          LightingLog rows in many sealed seconds; the HPSensors plugin's motion traffic and the dzVents motion-light
          scripts run as in E-DZ
  snap    the launcher takes a consistent snapshot of domoticz.db (the "before" of the offline root comparison)
  render  the platform's renderer (getlightlog, the device Log page's Text log) for owner, member and guest
  change  the OWNER changes the lock's switch type from 19 (Door Lock) to 20 (Door Lock Inverted) with the request the web
          UI's Edit Device dialog sends (param=setused with every other field the device has, unchanged)
  render  the renderer again, for every role
  post    POST_S more seconds of the same traffic
Writes <out>/<tag>_switchtype_report.json, <out>/<tag>_t_start and <out>/<tag>_t_end (the Docker VM's clock, as E-DZ).
Not an attack: the owner's own configuration change through the hub's own API; nothing is written to the database
except by Domoticz.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HARNESS = os.environ.get("DZ_HARNESS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "domoticz",
                                                     "harness"))
sys.path.insert(0, HARNESS)
TRAFFIC_EVERY_S = 30.0
ROLES = ("owner", "member", "guest")
# The fields the web UI's Edit Device dialog sends back with param=setused (Domoticz's own names); each is copied from
# the device's current state so that only the switch type changes. Recorded in the report as sent.
SETUSED_FIELDS = (("name", "Name"), ("description", "Description"), ("protected", "Protected"),
                  ("customimage", "CustomImage"), ("strparam1", "StrParam1"), ("strparam2", "StrParam2"))


def vm_now(container="dz-harness"):
    r = subprocess.run(["docker", "exec", container, "python3", "-c", "import time;print(repr(time.time()))"],
                       capture_output=True, text=True)
    return float(r.stdout.strip())


def setused_params(dev, to_type):
    """The setused request for a device JSON (getdevices entry): every UI field copied, only switchtype changed."""
    p = {"idx": int(dev["idx"]), "used": "true", "switchtype": int(to_type)}
    for q, k in SETUSED_FIELDS:
        v = dev.get(k)
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        p[q] = v
    return p


def find_lock(devs, from_type):
    """The one device whose switch type is the Door Lock (SwitchTypeVal 19); None unless exactly one."""
    c = [d for d in devs if str(d.get("SwitchTypeVal")) == str(from_type)]
    return c[0] if len(c) == 1 else None


def main():
    from dz_api import Api, lightlog_by_row      # noqa: PLC0415
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default=os.environ.get("DZ_BASE", "http://127.0.0.1:18480"))
    ap.add_argument("--pre-s", type=float, default=600.0)
    ap.add_argument("--post-s", type=float, default=600.0)
    ap.add_argument("--from-type", type=int, default=19)
    ap.add_argument("--to-type", type=int, default=20)
    ap.add_argument("--pre-snapshot-cmd", default="")
    ap.add_argument("--pre-snapshot-flag", default="")
    a = ap.parse_args()
    names = ["%s_t_start" % a.tag, "%s_t_end" % a.tag, "%s_switchtype_report.json" % a.tag]
    for f in names:
        if os.path.exists(os.path.join(a.out, f)):
            raise SystemExit("refusing to overwrite %s" % f)
    api = {r: Api(r, base=a.base) for r in ROLES}
    devs = api["owner"].cmd("getdevices", filter="all", used="true").get("result") or []
    lock = find_lock(devs, a.from_type)
    if lock is None:
        raise SystemExit("no unique device of switch type %d: %r" % (a.from_type, [(d.get("Name"), d.get("SwitchTypeVal"))
                                                                                  for d in devs]))
    idx = int(lock["idx"])
    rep = {"experiment": "E10 arm C: benign switch-type change on Domoticz", "tag": a.tag, "lock_device_idx": idx,
           "from_type": a.from_type, "to_type": a.to_type, "device_before": lock, "traffic": [],
           "host_minus_vm_s": time.time() - vm_now()}
    t0 = vm_now()
    open(os.path.join(a.out, "%s_t_start" % a.tag), "w").write("%r\n" % t0)
    cmdv = ["Off", "On"]

    def traffic(until_vm, phase):
        k = 0
        while vm_now() < until_vm:
            sw = cmdv[k % 2]
            t = vm_now()
            r = api["member"].cmd("switchlight", idx=idx, switchcmd=sw)
            rep["traffic"].append({"phase": phase, "vm_t": t, "switchcmd": sw, "reply": r.get("status")})
            k += 1
            time.sleep(TRAFFIC_EVERY_S)
    try:
        traffic(t0 + a.pre_s, "pre")
        if a.pre_snapshot_cmd:
            subprocess.run(a.pre_snapshot_cmd, shell=True, check=False)
            end = time.time() + 180
            while a.pre_snapshot_flag and not os.path.exists(a.pre_snapshot_flag) and time.time() < end:
                time.sleep(1)
            rep["pre_snapshot_taken"] = bool(a.pre_snapshot_flag and os.path.exists(a.pre_snapshot_flag))
        rep["render_before"] = {r: lightlog_by_row(api[r], idx)[0] for r in ROLES}
        params = setused_params(lock, a.to_type)
        rep["change_request"] = {"param": "setused", **params}
        rep["t_change_request_vm"] = vm_now()
        rep["change_reply"] = api["owner"].cmd("setused", **params)
        rep["t_change_reply_vm"] = vm_now()
        time.sleep(3.0)
        after = [d for d in (api["owner"].cmd("getdevices", filter="all", used="true").get("result") or [])
                 if int(d["idx"]) == idx]
        rep["device_after"] = after[0] if after else None
        rep["change_applied"] = bool(after) and str(after[0].get("SwitchTypeVal")) == str(a.to_type)
        rep["render_after"] = {r: lightlog_by_row(api[r], idx)[0] for r in ROLES}
        rep["rendered_rows_changed"] = {r: sum(1 for k, v in rep["render_before"][r].items()
                                               if rep["render_after"][r].get(k) != v) for r in ROLES}
        traffic(rep["t_change_reply_vm"] + a.post_s, "post")
    finally:
        open(os.path.join(a.out, "%s_t_end" % a.tag), "w").write("%r\n" % vm_now())
        with open(os.path.join(a.out, "%s_switchtype_report.json" % a.tag), "x") as fh:
            json.dump(rep, fh, indent=1, default=str)
    print("change applied:", rep.get("change_applied"), "rendered rows changed:", rep.get("rendered_rows_changed"))
    return 0 if rep.get("change_applied") else 3


if __name__ == "__main__":
    sys.exit(main())
