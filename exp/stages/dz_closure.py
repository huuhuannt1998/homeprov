"""E-DZ, renderer closure on Domoticz: which stored fields does the displayed User of a device Log row depend on?

Method (the Home Assistant derivation, repeated on Domoticz). The device Log page's "Text log" table (columns Date,
Data, User) is filled by one API call, json.htm?type=command&param=getlightlog (CWebServer::Cmd_GetLightLog), which
reads LightingLog joined with the device's DeviceStatus row. On a closure instance that is never the run hub, for one
committed target row of each fixture device (one device per rendering path: on/off with a household member's own
rows, contact, motion, dimmer, selector, media player, door lock), every column of the target LightingLog row and
every column of the device's DeviceStatus row is mutated in turn, directly in domoticz.db as code in the hub process
can; the platform's own renderer is re-run; the rendered output is compared with the baseline; the field is restored
and the restore is checked against the baseline. A mutation of LightingLog.User is the positive control (it must change
the displayed User on every fixture); re-rendering without a mutation is the determinism control.

Two further measurements: the same row rendered for each viewer role (owner/Admin, member/User, guest/Viewer), and the
web UI's own rendering of the Text log table in a browser for an Admin and a Viewer, before and after a User and a
SwitchType mutation. And an in-place probe: every stored LightingLog and DeviceStatus row before and after benign
traffic (one update of every fixture, a member's switch actions, a hub restart), diffed column by column, to record
which fields Domoticz rewrites in place.

    python3 exp/stages/dz_closure.py            # host: runs the inner part in dz-closure, writes exp/out/dz_closure.json
    (inner, inside dz-closure)  python3 /stages/dz_closure.py --inner | --dump | --set ... | --restore ...
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time

DB = "/opt/domoticz/userdata/domoticz.db"
FRESH = "FRESH_KEY"
CONTAINER = "dz-closure"

# Fields the renderer's code reads (CWebServer::Cmd_GetLightLog, build f734fde31, WebServerCmds.cpp L6930-L7046):
#   SELECT Type, SubType, SwitchType, Options FROM DeviceStatus WHERE (ID == idx)
#   SELECT ROWID, nValue, sValue, User, Date FROM LightingLog WHERE (DeviceRowID==idx) ORDER BY Date DESC
CODE_READ = ["LightingLog.ROWID", "LightingLog.DeviceRowID", "LightingLog.nValue", "LightingLog.sValue",
             "LightingLog.User", "LightingLog.Date", "DeviceStatus.ID", "DeviceStatus.Type", "DeviceStatus.SubType",
             "DeviceStatus.SwitchType", "DeviceStatus.Options"]


# ------------------------------------------------------------------------------------------------ inner (in the hub)
def _con():
    return sqlite3.connect(DB, timeout=30, isolation_level=None)


def _api(account):
    sys.path.insert(0, "/dzsrc/harness")
    from dz_api import Api                                     # noqa: PLC0415
    return Api(account, base="http://127.0.0.1:8080")


def render(api, idx):
    d = api.cmd("getlightlog", idx=idx)
    d.pop("title", None)
    return d


def entry(r, idx):
    for e in r.get("result") or []:
        if e.get("idx") == str(idx):
            return e
    return None


def b64(s):
    return base64.b64encode(s.encode()).decode()


def mutations(table, col, v, decl, dev):
    if table == "LightingLog":
        if col == "ROWID":
            return [("fresh_key", FRESH)]
        if col == "DeviceRowID":
            return [("other_device", dev["other_id"]), ("missing_device", 999999)]
        if col == "User":
            return [("suffix", (v or "") + "-mut")]
        if col == "Date":
            import calendar                                    # noqa: PLC0415
            plus = time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.gmtime(calendar.timegm(time.strptime(v, "%Y-%m-%d %H:%M:%S")) + 1))
            return [("earlier", "2026-10-08 00:00:01"), ("plus_1s", plus)]
        if col == "sValue":
            out = [("suffix", (v or "") + "-mut"), ("empty", "")]
            if v != "0":
                out.append(("zero", "0"))
            if dev["switchtype"] == 18:
                out.append(("other_level", "10"))
            return out
        if col == "nValue":
            return [("plus_1", v + 1)] + ([("flip", 1 - v)] if v in (0, 1) else [("zero", 0)])
    if table == "DeviceStatus":
        if col == "ID":
            return [("fresh_key", FRESH)]
        if col == "Type":
            return [("non_light_type_82", 82), ("other_light_type_16", 16)]
        if col == "SubType":
            return [("plus_1", v + 1), ("selector_62", 62) if v != 62 else ("switch_73", 73)]
        if col == "SwitchType":
            return [("st_%d" % x, x) for x in (0, 7, 17, 18, 19, 20) if x != v]
        if col == "Options":
            other = "LevelNames:%s;LevelOffHidden:%s;SelectorStyle:%s" % (b64("Off|Uno|Dos|Tres"), b64("false"), b64("0"))
            return [("other_level_names", other)] + ([("null", None)] if v is not None else [])
        if col == "LastUpdate":
            return [("shift", "2026-10-07 00:00:00")]
    # generic
    if v is None:
        return [("from_null", 1 if "INT" in (decl or "").upper() else "mut")]
    if isinstance(v, int):
        return [("plus_1", v + 1)]
    if isinstance(v, float):
        return [("plus_1", v + 1.0)]
    return [("suffix", v + "-mut")]


def apply(con, table, keycol, keyval, col, new):
    """Write one mutation; return a function that restores the original value."""
    if new == FRESH:
        fresh = con.execute("SELECT max(%s)+100 FROM %s" % (keycol, table)).fetchone()[0]
        con.execute("UPDATE %s SET %s=? WHERE %s=?" % (table, keycol, keycol), (fresh, keyval))
        return fresh, lambda: con.execute("UPDATE %s SET %s=? WHERE %s=?" % (table, keycol, keycol), (keyval, fresh))
    orig = con.execute("SELECT [%s] FROM %s WHERE %s=?" % (col, table, keycol), (keyval,)).fetchone()[0]
    con.execute("UPDATE %s SET [%s]=? WHERE %s=?" % (table, col, keycol), (new, keyval))
    return None, lambda: con.execute("UPDATE %s SET [%s]=? WHERE %s=?" % (table, col, keycol), (orig, keyval))


def compare(base, after, t_idx_before, t_idx_after):
    tb, ta = entry(base, t_idx_before), entry(after, t_idx_after)
    flags = ("HaveDimmer", "HaveSelector", "HaveGroupCmd", "status")
    others_b = [e for e in (base.get("result") or []) if e.get("idx") != str(t_idx_before)]
    others_a = [e for e in (after.get("result") or []) if e.get("idx") != str(t_idx_after)]
    return {
        "rendered_output_changed": after != base,
        "target_entry_changed": ta != tb,
        "target_entry_vanished": ta is None,
        "displayed_user_changed": (ta or {}).get("User") != tb.get("User"),
        "changed_attributes": sorted(k for k in set(tb) | set(ta or {}) if (ta or {}).get(k) != tb.get(k)),
        "other_rows_changed": others_a != others_b,
        "header_changed": {k: [base.get(k), after.get(k)] for k in flags if base.get(k) != after.get(k)},
        "target_after": ta,
    }


def inner():
    owner, member, guest = _api("owner"), _api("member"), _api("guest")
    # A household member's own actions on the Porch Light (Dummy hardware), so one fixture's target row carries an
    # account label "member (IP: ...)".
    member.cmd("switchlight", idx=1, switchcmd="On")
    time.sleep(1.2)
    member.cmd("switchlight", idx=1, switchcmd="Off")
    time.sleep(1.5)
    con = _con()
    ll_cols = [("ROWID", "INTEGER")] + [(r[1], r[2]) for r in con.execute("PRAGMA table_info(LightingLog)")]
    ds_cols = [(r[1], r[2]) for r in con.execute("PRAGMA table_info(DeviceStatus)")]
    fixtures = []
    for did, name, st in con.execute("SELECT ID, Name, SwitchType FROM DeviceStatus WHERE ID=1 OR HardwareID="
                                     "(SELECT ID FROM Hardware WHERE Name='ClosureFixture') ORDER BY ID").fetchall():
        tgt = con.execute("SELECT ROWID FROM LightingLog WHERE DeviceRowID=? ORDER BY ROWID DESC LIMIT 1",
                          (did,)).fetchone()
        if tgt:
            fixtures.append({"id": did, "name": name, "switchtype": st, "target_rowid": tgt[0]})
    for f in fixtures:
        f["other_id"] = next(x["id"] for x in fixtures if x["id"] != f["id"])

    out = {"fixtures": [], "ll_columns": [c for c, _ in ll_cols], "ds_columns": [c for c, _ in ds_cols]}
    for f in fixtures:
        dev, row = f["id"], f["target_rowid"]
        base = render(owner, dev)
        again = render(owner, dev)
        roles = {"owner": base, "member": render(member, dev), "guest": render(guest, dev)}
        tb = entry(base, row)
        fx = {"device": f["name"], "device_id": dev, "switchtype": f["switchtype"], "target_rowid": row,
              "target_row_stored": dict(zip([c for c, _ in ll_cols],
                                            con.execute("SELECT ROWID, * FROM LightingLog WHERE ROWID=?",
                                                        (row,)).fetchone())),
              "baseline_entry": tb, "baseline_rows_rendered": len(base.get("result") or []),
              "determinism_control_equal": again == base,
              "same_render_for_every_role": all(v == base for v in roles.values()),
              "mutations": []}
        assert tb is not None, "target row %s not rendered" % row
        for table, keycol, keyval, cols in (("LightingLog", "ROWID", row, ll_cols), ("DeviceStatus", "ID", dev, ds_cols)):
            for col, decl in cols:
                orig = con.execute("SELECT [%s] FROM %s WHERE %s=?" % (col if col != "ROWID" else "ROWID", table, keycol),
                                   (keyval,)).fetchone()[0]
                for label, new in mutations(table, col, orig, decl, f):
                    fresh, restore = apply(con, table, keycol, keyval, col, new)
                    try:
                        after = render(owner, dev)
                        other = render(owner, f["other_id"]) if (table, col) == ("LightingLog", "DeviceRowID") else None
                        moved = render(owner, fresh) if fresh is not None and table == "DeviceStatus" else None
                    finally:
                        restore()
                    t_after_idx = fresh if (table == "LightingLog" and col == "ROWID") else row
                    res = {"field": "%s.%s" % (table, col), "mutation": label,
                           "orig": orig, "mutated_to": "fresh key %s" % fresh if fresh is not None else new,
                           **compare(base, after, row, t_after_idx)}
                    if other is not None:
                        res["row_appears_in_other_device_log"] = entry(other, row) is not None
                    if moved is not None:
                        res["render_under_fresh_device_id"] = moved
                    restored = render(owner, dev)
                    res["restore_equal_to_baseline"] = restored == base
                    if not res["restore_equal_to_baseline"]:
                        raise SystemExit("restore failed after %s %s" % (res["field"], label))
                    fx["mutations"].append(res)
        ctrl = [m for m in fx["mutations"] if m["field"] == "LightingLog.User"]
        fx["positive_control_user_suffix_changed_displayed_user"] = all(m["displayed_user_changed"] for m in ctrl)
        out["fixtures"].append(fx)
    con.close()
    print(json.dumps(out, default=str))


def dump():
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=30)
    res = {}
    for table, key in (("LightingLog", "ROWID"), ("DeviceStatus", "ID")):
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % table)]
        rows = con.execute("SELECT %s AS _k, * FROM %s" % (key, table)).fetchall()
        res[table] = {"columns": cols, "rows": {str(r[0]): list(r[1:]) for r in rows}}
    print(json.dumps(res, default=str))


def set_field(table, keycol, keyval, col, new_json):
    con = _con()
    orig = con.execute("SELECT [%s] FROM %s WHERE %s=?" % (col, table, keycol), (keyval,)).fetchone()[0]
    con.execute("UPDATE %s SET [%s]=? WHERE %s=?" % (table, col, keycol), (json.loads(new_json), keyval))
    print(json.dumps({"orig": orig}))


# --------------------------------------------------------------------------------------------------------- host side
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
DATA = "<research-dir>/HOMEPROV-P13-exp/dz/closure"
TUNNEL = "http://127.0.0.1:18482"


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def dexec(*args):
    r = sh(["docker", "exec", CONTAINER, "python3", "/stages/dz_closure.py"] + list(args))
    if r.returncode != 0:
        raise SystemExit("inner %s failed: %s" % (args[:1], r.stderr[-2000:]))
    return json.loads(r.stdout)


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def summarize(inner_res):
    fx = inner_res["fixtures"]
    allf = sorted({m["field"] for f in fx for m in f["mutations"]})
    by = {}
    for f in fx:
        for m in f["mutations"]:
            d = by.setdefault(m["field"], {"rendered": set(), "user": set(), "vanish": set(), "other_rows": set()})
            if m["rendered_output_changed"]:
                d["rendered"].add(f["device"])
            if m["displayed_user_changed"]:
                d["user"].add(f["device"])
            if m["target_entry_vanished"]:
                d["vanish"].add(f["device"])
            if m["other_rows_changed"]:
                d["other_rows"].add(f["device"])
    rendered = sorted(k for k, v in by.items() if v["rendered"])
    user = sorted(k for k, v in by.items() if v["user"])
    per_field = {k: {"fixtures_rendered_output_changed": sorted(v["rendered"]),
                     "fixtures_displayed_user_changed": sorted(v["user"]),
                     "fixtures_target_row_vanished": sorted(v["vanish"]),
                     "fixtures_other_rows_changed": sorted(v["other_rows"])} for k, v in sorted(by.items())}
    return {
        "fields_mutated": len(allf),
        "fields_mutated_list": allf,
        "fixtures": [f["device"] for f in fx],
        "n_fixtures": len(fx),
        "n_mutations": sum(len(f["mutations"]) for f in fx),
        "fields_changing_rendered_output": rendered,
        "n_fields_changing_rendered_output": len(rendered),
        "fields_changing_displayed_user": user,
        "n_fields_changing_displayed_user": len(user),
        "code_read_fields": CODE_READ,
        "n_code_read_fields": len(CODE_READ),
        "measured_not_in_code_read": sorted(set(rendered) - set(CODE_READ)),
        "code_read_not_measured": sorted(set(CODE_READ) - set(rendered)),
        "renderer_closure": sorted(set(rendered) | set(CODE_READ)),
        "n_renderer_closure": len(set(rendered) | set(CODE_READ)),
        "positive_control_all_fixtures": all(f["positive_control_user_suffix_changed_displayed_user"] for f in fx),
        "determinism_control_all_fixtures": all(f["determinism_control_equal"] for f in fx),
        "same_render_for_every_role_all_fixtures": all(f["same_render_for_every_role"] for f in fx),
        "every_restore_equal_to_baseline": all(m["restore_equal_to_baseline"] for f in fx for m in f["mutations"]),
        "per_field": per_field,
    }


def ui_controls(lock_id, lock_row):
    """The web UI's own rendering of the Text log table, in a browser, before and after a User and a SwitchType
    mutation of the door-lock fixture, for an Admin and a Viewer viewer."""
    from playwright.sync_api import sync_playwright        # noqa: PLC0415
    sys.path.insert(0, os.path.join(REPO, "testbed", "domoticz", "harness"))
    from dz_ui import UiSession                             # noqa: PLC0415
    shots = os.path.join(OUT, "dz_screens")
    os.makedirs(shots, exist_ok=True)
    res = {"device_id": lock_id, "target_rowid": lock_row, "renders": []}
    steps = [("baseline", None),
             ("user_suffix", ("LightingLog", "ROWID", lock_row, "User", None)),
             ("switchtype_20_door_lock_inverted", ("DeviceStatus", "ID", lock_id, "SwitchType", 20)),
             ("restored", None)]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        sess = {acc: UiSession(browser, TUNNEL, acc) for acc in ("owner", "guest")}
        for label, mut in steps:
            orig = None
            if mut is not None:
                table, keycol, keyval, col, new = mut
                if col == "User":
                    cur = dexec("--dump")["LightingLog"]
                    i = cur["columns"].index("User")
                    new = cur["rows"][str(lock_row)][i] + "-mut"
                orig = dexec("--set", table, keycol, str(keyval), col, json.dumps(new))["orig"]
            try:
                for acc, s in sess.items():
                    shot = os.path.join(shots, "dz_closure_%s_%s.png" % (label, acc))
                    rows = s.text_log(lock_id, shot)
                    res["renders"].append({"step": label, "viewer": acc, "rows": rows,
                                           "screenshot": os.path.relpath(shot, REPO), "screenshot_sha256": sha(shot)})
            finally:
                if mut is not None:
                    table, keycol, keyval, col, _new = mut
                    dexec("--set", table, keycol, str(keyval), col, json.dumps(orig))
        browser.close()
    by = {(r["step"], r["viewer"]): r["rows"] for r in res["renders"]}
    base = by[("baseline", "owner")]
    res["checks"] = {
        "viewers_agree_every_step": all(by[(s, "owner")] == by[(s, "guest")] for s, _ in steps),
        "user_mutation_changed_ui_rows": by[("user_suffix", "owner")] != base,
        "switchtype_mutation_changed_ui_rows": by[("switchtype_20_door_lock_inverted", "owner")] != base,
        "restored_equal_baseline": by[("restored", "owner")] == base,
    }
    return res


def inplace_probe():
    """Which stored fields does Domoticz rewrite in place during benign operation?"""
    sys.path.insert(0, os.path.join(REPO, "testbed", "domoticz", "harness"))
    from dz_api import Api                                  # noqa: PLC0415
    from dz_ctl import Ctl                                  # noqa: PLC0415
    before = dexec("--dump")
    ops = []
    c = Ctl(os.path.join(DATA, "hpctl"))
    vals = {1: (1, "On"), 2: (1, "On"), 3: (1, "On"), 4: (2, "55"), 5: (2, "10"), 6: (1, "Playing: Track B"), 7: (1, "On")}
    for u, (n, s) in vals.items():
        ops.append({"op": "integration update", "unit": u, "res": c.call("set", unit=u, nValue=n, sValue=s).get("ok")})
        time.sleep(1.1)
    m = Api("member", base=TUNNEL)
    for cmd in ("On", "Off"):
        ops.append({"op": "member switchlight Porch Light %s" % cmd,
                    "res": m.cmd("switchlight", idx=1, switchcmd=cmd).get("status")})
        time.sleep(1.2)
    ops.append({"op": "owner renders every fixture's log", "res": [Api("owner", base=TUNNEL).cmd(
        "getlightlog", idx=i).get("status") for i in range(1, 11)]})
    ops.append({"op": "docker restart", "res": sh(["docker", "restart", CONTAINER]).returncode})
    time.sleep(75)
    after = dexec("--dump")
    diff = {}
    for table in ("LightingLog", "DeviceStatus"):
        cols = before[table]["columns"]
        b, a = before[table]["rows"], after[table]["rows"]
        changed = {}
        for k, rb in b.items():
            ra = a.get(k)
            if ra is None:
                continue
            for i, cn in enumerate(cols):
                if rb[i] != ra[i]:
                    changed.setdefault(cn, []).append(k)
        diff[table] = {"rows_before": len(b), "rows_after": len(a), "rows_deleted": sorted(set(b) - set(a)),
                       "rows_added": len(set(a) - set(b)),
                       "columns_rewritten_in_place": {cn: len(ks) for cn, ks in sorted(changed.items())},
                       "rows_with_in_place_change": len({k for ks in changed.values() for k in ks})}
    return {"operations": ops, "diff": diff}


def host():
    path = os.path.join(OUT, "dz_closure.json")
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    t0 = time.time()
    raw = dexec("--inner")
    summ = summarize(raw)
    lock = next(f for f in raw["fixtures"] if f["switchtype"] == 19)
    ui = ui_controls(lock["device_id"], lock["target_rowid"])
    inplace = inplace_probe()
    sys.path.insert(0, os.path.join(REPO, "testbed", "domoticz", "harness"))
    from dz_api import Api                                  # noqa: PLC0415
    ver = Api("owner", base=TUNNEL).cmd("getversion")
    img = sh(["docker", "inspect", CONTAINER, "--format", "{{.Config.Image}} {{.Image}}"]).stdout.strip()
    result = {
        "experiment": "E-DZ renderer closure on Domoticz",
        "what": __doc__.split("\n\n")[1].replace("\n", " "),
        "substrate": "closure instance (container dz-closure, its own volume), never the run hub",
        "domoticz": {"version": ver.get("version"), "build_hash": ver.get("hash"), "build_time": ver.get("build_time"),
                     "dzvents_version": ver.get("dzvents_version"), "python_version": ver.get("python_version"),
                     "image": img.split()[0], "image_id": img.split()[-1],
                     "repo_digest": sh(["docker", "image", "inspect", img.split()[0], "--format",
                                        "{{json .RepoDigests}}"]).stdout.strip()},
        "renderer": "CWebServer::Cmd_GetLightLog (json.htm?type=command&param=getlightlog), which fills the device Log "
                    "page's Text log table (www/app/log/components/DeviceTextLogTable.js: columns Date, Data, User)",
        "summary": summ,
        "ui_controls": ui,
        "in_place_rewrite_probe": inplace,
        "fixtures": raw["fixtures"],
        "columns": {"LightingLog": raw["ll_columns"], "DeviceStatus": raw["ds_columns"]},
        "script_sha256": sha(os.path.abspath(__file__)),
        "fixture_integration_sha256": sha(os.path.join(REPO, "testbed/domoticz/integration/HPFixture/plugin.py")),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t0, 1),
    }
    with open(path, "w") as fh:
        json.dump(result, fh, indent=1, default=str)
    print(json.dumps({k: summ[k] for k in ("n_fixtures", "n_mutations", "fields_changing_rendered_output",
                                          "fields_changing_displayed_user", "code_read_not_measured",
                                          "positive_control_all_fixtures", "determinism_control_all_fixtures",
                                          "same_render_for_every_role_all_fixtures")}, indent=1))
    print("ui checks", ui["checks"])
    print("in place", json.dumps(inplace["diff"], indent=1))
    print("->", path, sha(path))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--inner"]:
        inner()
    elif a[:1] == ["--dump"]:
        dump()
    elif a[:1] == ["--set"]:
        set_field(a[1], a[2], int(a[3]), a[4], a[5])
    else:
        host()
