"""E6 (round 13, 2026-10-08): verifier check for the NAME-MAP commitment, and its self-test.

The displayed cause reads inputs outside the recorder: the viewer's name map (person entities and, for an admin
viewer, the account list) and the entity and device registries the frontend names an automation or entity from. With
HOMEPROV_NAMEMAP_DIR set, monitor/monitor.py adds "namemap": {"v", "digest", "n", "parts"} to every anchored seal
record. This check recomputes that digest from the hub's CURRENT storage with the monitor's own code (no second
implementation) and compares it with the anchored records:

  * transitions: the anchored records at which the digest changed, with the parts that changed;
  * first_record_differing_from_current: the first anchored record whose digest differs from the current name map,
    i.e. the earliest seal whose rows the current name map may display under a different cause;
  * pending: the current name map differs from the LAST anchored digest (a change no seal has captured yet);
  * markers: a NAMEMAP_CHANGE lifecycle marker ({"marker": "NAMEMAP_CHANGE", "part": P, "to_part_digest": D}, or
    {"marker": "NAMEMAP_CHANGE", "parts": {P: D, ...}}),
    appended by a holder of the append key BEFORE the change, excuses a transition whose changed parts all carry such
    a marker with the new part digest; anything else is reported as a display-input change after a seal;
  * with --snapshots (the monitor's scratch/namemap), the entries that changed; with --recorder (a recorder copy),
    the committed rows whose displayed cause reads a changed entry, sealed before the change;
  * with --segments T0 T1, the closure-scheme segment roots of [T0, T1] recomputed from --recorder, so the result
    shows whether the row commitment alone saw anything.

usage:
  e6_namemap.py verify --chain CHAIN.jsonl --storage DIR [--snapshots DIR] [--recorder DB] [--segments T0 T1]
                       [--monitor-dir DIR]
  e6_namemap.py selftest --pre PRE_E6_MONITOR.py --db RECORDER_COPY.db [--monitor-dir DIR]
Prints one JSON document. Writes nothing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MONITOR_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "monitor"))


def load_module(path, name, env=None):
    old = {}
    for k, v in (env or {}).items():
        old[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod


def monitor_module(mdir, scratch):
    return load_module(os.path.join(mdir, "monitor.py"), "e6_monitor",
                       {"HOMEPROV_SCRATCH": scratch, "HOMEPROV_NAMEMAP_DIR": None})


# ------------------------------------------------------------------------------------------------ verify
def read_chain(path):
    recs = []
    with open(path) as fh:
        for line in fh:
            if line.strip():
                recs.append(json.loads(line))
    return recs


def _diff_entries(old, new):
    """Per part, entries keyed by their first field (user id, person id, entity id, device id)."""
    out = {}
    for part in sorted(set(old or {}) | set(new or {})):
        o = {r[0]: r for r in ((old or {}).get(part) or [])}
        n = {r[0]: r for r in ((new or {}).get(part) or [])}
        ch = [{"key": k, "old": o[k], "new": n[k]} for k in sorted(o) if k in n and list(o[k]) != list(n[k])]
        add = [n[k] for k in sorted(n) if k not in o]
        rem = [o[k] for k in sorted(o) if k not in n]
        if ch or add or rem:
            out[part] = {"changed": ch, "added": add, "removed": rem}
    return out


def _viewer_maps(entries):
    """The frontend's name maps from committed entries: persons first (the person entity's display name: its entity
    registry name, else the person's name; the entity is taken as person.<id>), then, for an admin viewer only,
    accounts not already present."""
    ents = {r[0]: r for r in ((entries or {}).get("entity") or [])}
    non_admin = {}
    for pid, name, uid in ((entries or {}).get("person") or []):
        if uid:
            e = ents.get("person." + str(pid))
            non_admin[uid] = (e[1] if e is not None and e[1] is not None else name)
    admin = dict(non_admin)
    for uid, name, _act, _sg in ((entries or {}).get("auth") or []):
        admin.setdefault(uid, name)
    return {"admin": admin, "non_admin": non_admin}


def _affected(db, diff, before_ts, old_entries=None, new_entries=None):
    """Committed rows whose displayed cause reads a changed entry, written before `before_ts`. With both snapshots,
    also the user ids whose resolved name changed for each viewer type, and their rows."""
    users, ents = set(), set()
    for part, d in diff.items():
        for c in d["changed"]:
            if part == "auth":
                users.add(c["key"])
            elif part == "person":
                users.update(x for x in (c["old"][2], c["new"][2]) if x)
            elif part == "entity":
                ents.add(c["key"])
        for r in d["added"] + d["removed"]:
            if part == "auth":
                users.add(r[0])
            elif part == "person" and r[2]:
                users.add(r[2])
            elif part == "entity":
                ents.add(r[0])
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    res = {"user_ids": sorted(users), "entity_ids": sorted(ents), "states_rows_by_user": {}, "events_rows_by_user": {},
           "states_rows_caused_by_entity": {}}
    for u in sorted(users):
        b = bytes.fromhex(u)
        res["states_rows_by_user"][u] = con.execute(
            "select count(*) from states where context_user_id_bin=? and last_updated_ts<?", (b, before_ts)).fetchone()[0]
        res["events_rows_by_user"][u] = con.execute(
            "select count(*) from events where context_user_id_bin=? and time_fired_ts<?", (b, before_ts)).fetchone()[0]
    for e in sorted(ents):
        ctxs = [r[0] for r in con.execute(
            "select e.context_id_bin from events e join event_types t on e.event_type_id=t.event_type_id "
            "join event_data d on e.data_id=d.data_id where t.event_type in ('automation_triggered','script_started') "
            "and d.shared_data like ? and e.time_fired_ts<?", ('%%"entity_id":"%s"%%' % e, before_ts))]
        n = 0
        for c in ctxs:
            n += con.execute("select count(*) from states s join states_meta m on s.metadata_id=m.metadata_id "
                             "where s.context_id_bin=? and m.entity_id<>? and s.last_updated_ts<?",
                             (c, e, before_ts)).fetchone()[0]
        res["states_rows_caused_by_entity"][e] = {"runs": len(ctxs), "rows_in_those_contexts": n}
    if old_entries is not None and new_entries is not None:
        mo, mn = _viewer_maps(old_entries), _viewer_maps(new_entries)
        res["displayed_name_changed"] = {}
        for v in ("admin", "non_admin"):
            ids = sorted(k for k in set(mo[v]) | set(mn[v]) if mo[v].get(k) != mn[v].get(k))
            rows = 0
            for u in ids:
                b = bytes.fromhex(u)
                rows += con.execute("select count(*) from states where context_user_id_bin=? and last_updated_ts<?",
                                    (b, before_ts)).fetchone()[0]
            res["displayed_name_changed"][v] = {"user_ids": ids, "states_rows": rows}
    con.close()
    return res


def _segments(M, db, recs, t0, t1):
    roots = {}
    for r in recs:
        p = r.get("payload") or {}
        for g, segs in (p.get("sealed") or {}).items():
            for k, v in (segs or {}).items():
                roots.setdefault((g, str(k)), {"acc": v.get("acc"), "n": v.get("n"), "seq": r.get("seq"),
                                               "encoding": p.get("encoding", "v1")})
    nodes = M.load(db)
    phis = {e: M.commit(nodes, encoding=e) for e in {a["encoding"] for a in roots.values()}}
    widths = dict(M.GRAN)
    viol, checked = [], 0
    for (g, k), a in sorted(roots.items()):
        w = widths[g]
        if not (t0 <= int(k) * w and int(k) * w + w <= t1):
            continue
        checked += 1
        got = (phis[a["encoding"]].get(g) or {}).get(k)
        if got is None or got["acc"] != a["acc"] or got["n"] != a["n"]:
            viol.append({"granularity": g, "segment": k, "anchored_seq": a["seq"], "anchored_n": a["n"],
                         "recomputed_n": None if got is None else got["n"]})
    return {"window": [t0, t1], "segments_checked": checked, "violations": len(viol),
            "violated_seconds": sorted(int(v["segment"]) for v in viol if v["granularity"] == "second"),
            "violations_detail": viol[:100]}


def verify(a):
    scratch = tempfile.mkdtemp(prefix="e6v_")
    M = monitor_module(a.monitor_dir, scratch)
    recs = read_chain(a.chain)
    nm = [(r["seq"], (r.get("payload") or {}).get("ts"), r["payload"]["namemap"]) for r in recs
          if isinstance((r.get("payload") or {}).get("namemap"), dict) and "digest" in r["payload"]["namemap"]]
    unobs = [r["seq"] for r in recs if ((r.get("payload") or {}).get("namemap") or {}).get("unobservable")]
    markers = [(r["seq"], r["payload"]) for r in recs if (r.get("payload") or {}).get("marker") == "NAMEMAP_CHANGE"]
    entries_now = M.namemap_entries(a.storage)
    cur = M.namemap_commitment(entries_now)

    def excused(parts_changed, new_parts, before_seq):
        why = {}
        for p in parts_changed:
            m = [s for s, mk in markers
                 if ((mk.get("part") == p and mk.get("to_part_digest") == new_parts[p]["digest"])
                     or (mk.get("parts") or {}).get(p) == new_parts[p]["digest"])
                 and (before_seq is None or s < before_seq)]
            why[p] = m[0] if m else None
        return all(v is not None for v in why.values()), why

    def snap(d):
        if not a.snapshots:
            return None
        p = os.path.join(a.snapshots, d + ".json")
        if not os.path.exists(p):
            return None
        e = json.load(open(p))
        # the snapshot must hash to the anchored digest, or it is not evidence
        return e if M.namemap_commitment(e)["digest"] == d else {"_bad_snapshot": True}

    transitions = []
    prev = None
    for seq, ts, c in nm:
        if prev is not None and c["digest"] != prev[2]["digest"]:
            pc = [p for p in c["parts"] if c["parts"][p]["digest"] != prev[2]["parts"].get(p, {}).get("digest")]
            ok, why = excused(pc, c["parts"], seq)
            t = {"seq": seq, "ts": ts, "prev_seq": prev[0], "prev_ts": prev[1], "from": prev[2]["digest"],
                 "to": c["digest"], "parts_changed": pc, "excused_by_marker": ok, "marker_seq": why}
            o, n = snap(prev[2]["digest"]), snap(c["digest"])
            if o is not None and n is not None and "_bad_snapshot" not in o and "_bad_snapshot" not in n:
                t["entries"] = _diff_entries(o, n)
                t["_snap"] = (o, n)
            transitions.append(t)
        prev = (seq, ts, c)
    last = nm[-1] if nm else None
    pending = None
    if last is not None and last[2]["digest"] != cur["digest"]:
        pc = [p for p in cur["parts"] if cur["parts"][p]["digest"] != last[2]["parts"].get(p, {}).get("digest")]
        ok, why = excused(pc, cur["parts"], None)
        pending = {"last_seq": last[0], "last_ts": last[1], "from": last[2]["digest"], "to": cur["digest"],
                   "parts_changed": pc, "excused_by_marker": ok, "marker_seq": why}
        o = snap(last[2]["digest"])
        if o is not None and "_bad_snapshot" not in o:
            pending["entries"] = _diff_entries(o, entries_now)
            pending["_snap"] = (o, entries_now)
    first_diff = next(({"seq": s, "ts": t, "digest": c["digest"],
                        "parts_differing": [p for p in cur["parts"]
                                            if cur["parts"][p]["digest"] != c["parts"].get(p, {}).get("digest")]}
                       for s, t, c in nm if c["digest"] != cur["digest"]), None)
    unexcused = [t for t in transitions if not t["excused_by_marker"]]
    flags = len(unexcused) + (1 if pending and not pending["excused_by_marker"] else 0)
    out = {"check": "e6_namemap verify", "chain_records": len(recs), "records_with_namemap": len(nm),
           "records_namemap_unobservable": len(unobs), "namemap_markers": [s for s, _ in markers],
           "current": cur, "last_anchored": None if last is None else {"seq": last[0], "ts": last[1],
                                                                       "digest": last[2]["digest"]},
           "transitions": transitions, "pending": pending, "first_record_differing_from_current": first_diff,
           "unexcused_changes": flags,
           "verdict": ("consistent" if flags == 0 and first_diff is None else
                       "consistent_with_declared_changes" if flags == 0 else
                       "display_input_changed_after_seal")}
    if a.recorder:
        db = os.path.join(scratch, "rec.db")
        for s in ("", "-wal", "-shm"):
            if os.path.exists(a.recorder + s):
                shutil.copy2(a.recorder + s, db + s)
        con = sqlite3.connect(db)
        con.execute("pragma wal_checkpoint(TRUNCATE)")
        con.close()
        for t in transitions + ([pending] if pending else []):
            if "entries" in t:
                o, n = t.get("_snap") or (None, None)
                t["affected_committed_rows"] = _affected(db, t["entries"], t.get("prev_ts") or t.get("last_ts"), o, n)
        if a.segments:
            out["segment_check"] = _segments(M, db, recs, float(a.segments[0]), float(a.segments[1]))
    for t in transitions + ([pending] if pending else []):
        t.pop("_snap", None)
    shutil.rmtree(scratch, ignore_errors=True)
    return out


# ------------------------------------------------------------------------------------------------ selftest
class _Clock:
    def __init__(self, t):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, _s):
        return None


def _tick_bytes(M, db, scratch, now, storage=None):
    """One monitor tick against `db` at a fixed clock; returns the exact bytes the monitor would POST."""
    sent = []
    os.makedirs(scratch, exist_ok=True)
    M.SRC, M.SCRATCH, M.STATE = db, scratch, os.path.join(scratch, "monitor_state.json")
    M.time = _Clock(now)
    if hasattr(M, "NAMEMAP_DIR"):
        M.NAMEMAP_DIR = storage or ""
    M.append = lambda rec: (sent.append(json.dumps(rec, sort_keys=True).encode()), {"ok": True})[1]
    st = {"anchored": {g: [] for g, _ in M.GRAN}}
    M.tick(st)
    return sent


def _fixture_storage(d, users, persons, entities, devices, secret="s3cr3t"):
    os.makedirs(d, exist_ok=True)
    auth = {"version": 1, "minor_version": 1, "key": "auth", "data": {
        "users": [{"id": i, "group_ids": ["system-users"], "is_owner": False, "is_active": act, "name": n,
                   "system_generated": sg, "local_only": False} for i, n, act, sg in users],
        "groups": [], "credentials": [{"id": "c1", "user_id": users[0][0], "auth_provider_type": "homeassistant",
                                       "auth_provider_id": None, "data": {"username": "u"}}],
        "refresh_tokens": [{"id": "r1", "user_id": users[0][0], "token": secret, "jwt_key": secret + "j"}]}}
    json.dump(auth, open(os.path.join(d, "auth"), "w"))
    json.dump({"version": 2, "key": "person", "data": {"items": [
        {"id": i, "name": n, "user_id": u, "device_trackers": []} for i, n, u in persons]}},
        open(os.path.join(d, "person"), "w"))
    json.dump({"version": 1, "key": "core.entity_registry", "data": {"entities": [
        {"entity_id": e, "name": n, "original_name": o, "device_id": dv, "unique_id": e} for e, n, o, dv in entities],
        "deleted_entities": []}}, open(os.path.join(d, "core.entity_registry"), "w"))
    json.dump({"version": 1, "key": "core.device_registry", "data": {"devices": [
        {"id": i, "name": n, "name_by_user": nu} for i, n, nu in devices], "deleted_devices": []}},
        open(os.path.join(d, "core.device_registry"), "w"))


def selftest(a):
    res = {"check": "e6_namemap selftest", "tests": {}}
    T = res["tests"]
    tmp = tempfile.mkdtemp(prefix="e6s_")
    env_off = {"HOMEPROV_NAMEMAP_DIR": None, "HOMEPROV_SCRATCH": tmp, "HOMEPROV_CLOCK_FILE": None,
               "HOMEPROV_GRACE_S": None, "HOMEPROV_SCHEME": None, "HOMEPROV_ENCODING": None}
    M0 = load_module(a.pre, "e6_monitor_pre", env_off)
    M1 = load_module(os.path.join(a.monitor_dir, "monitor.py"), "e6_monitor_post", env_off)
    # 1. default record byte-identical to the pre-E6 monitor, at several clock times over a real recorder copy
    times = [float(x) for x in a.times] if a.times else []
    if not times:
        con = sqlite3.connect("file:%s?mode=ro" % a.db, uri=True)
        hi = con.execute("select max(last_updated_ts) from states").fetchone()[0]
        con.close()
        times = [hi + 2.0, hi - 30.0, hi - 300.5, hi + 3600.0]
    ident = []
    for i, now in enumerate(times):
        b0 = _tick_bytes(M0, a.db, os.path.join(tmp, "s0_%d" % i), now)
        b1 = _tick_bytes(M1, a.db, os.path.join(tmp, "s1_%d" % i), now)
        ident.append({"now": now, "records_pre": len(b0), "records_post": len(b1), "bytes": [len(x) for x in b0],
                      "identical": b0 == b1 and len(b0) > 0})
    T["default_record_byte_identical"] = {"pass": all(x["identical"] for x in ident), "cases": ident}
    # 2. feature on: the record is the default record plus exactly the key "namemap"
    sd = os.path.join(tmp, "storage")
    U = [("u1", "Alex", True, False), ("u2", "Owner", True, False), ("u3", "Content", True, True)]
    P = [("p1", "Owner", "u2")]
    E = [("automation.porch", None, "Porch light", None), ("lock.door", None, None, "d1")]
    D = [("d1", "Front Door", None)]
    _fixture_storage(sd, U, P, E, D)
    on = _tick_bytes(M1, a.db, os.path.join(tmp, "s2"), times[0], storage=sd)
    off = _tick_bytes(M1, a.db, os.path.join(tmp, "s3"), times[0])
    ro, rf = json.loads(on[0]), json.loads(off[0])
    extra = sorted(set(ro) - set(rf))
    ro2 = dict(ro)
    ro2.pop("namemap", None)
    T["feature_on_adds_only_namemap"] = {"pass": extra == ["namemap"] and json.dumps(ro2, sort_keys=True).encode()
                                         == off[0], "extra_keys": extra}
    # 3. digest properties on fixtures
    def dig(users=U, persons=P, ents=E, devs=D, secret="s3cr3t", drop=None):
        d = tempfile.mkdtemp(dir=tmp)
        _fixture_storage(d, users, persons, ents, devs, secret)
        if drop:
            os.remove(os.path.join(d, drop))
        return M1.namemap_commitment(M1.namemap_entries(d))
    base = dig()
    cases = {
        "account_rename": dig(users=[("u1", "Owner", True, False)] + U[1:]),
        "account_swap": dig(users=[("u1", "Owner", True, False), ("u2", "Alex", True, False), U[2]]),
        "person_relink": dig(persons=[("p1", "Owner", "u1")]),
        "person_rename": dig(persons=[("p1", "Alex", "u2")]),
        "entity_rename": dig(ents=[("automation.porch", "Door auto-unlock", "Porch light", None), E[1]]),
        "device_rename": dig(devs=[("d1", "Front Door", "Garage")]),
        "deactivate": dig(users=[("u1", "Alex", False, False)] + U[1:]),
        "person_file_absent": dig(drop="person"),
        "person_list_empty": dig(persons=[]),
    }
    exp_parts = {"account_rename": ["auth"], "account_swap": ["auth"], "person_relink": ["person"],
                 "person_rename": ["person"], "entity_rename": ["entity"], "device_rename": ["device"],
                 "deactivate": ["auth"], "person_file_absent": ["person"], "person_list_empty": ["person"]}
    pr = {}
    for k, c in cases.items():
        parts = sorted(p for p in c["parts"] if c["parts"][p]["digest"] != base["parts"][p]["digest"])
        pr[k] = {"digest_changed": c["digest"] != base["digest"], "parts": parts,
                 "pass": c["digest"] != base["digest"] and parts == exp_parts[k]}
    pr["absent_vs_empty_distinct"] = {"pass": cases["person_file_absent"]["digest"] !=
                                      cases["person_list_empty"]["digest"]}
    same = {
        "credential_and_token_change": dig(secret="other-secret"),
        "entry_order": dig(users=list(reversed(U)), ents=list(reversed(E))),
        "revert_after_rename": dig(users=[("u1", "Alex", True, False)] + U[1:]),
    }
    for k, c in same.items():
        pr[k] = {"digest_unchanged": c["digest"] == base["digest"], "pass": c["digest"] == base["digest"]}
    T["digest_properties"] = {"pass": all(v["pass"] for v in pr.values()), "cases": pr}
    # 4. no credential field reaches the entries
    ent = M1.namemap_entries(sd)
    blob = json.dumps(ent)
    T["no_credential_retained"] = {"pass": "s3cr3t" not in blob and "jwt" not in blob and "credentials" not in blob,
                                   "entry_fields": {p: len(v[0]) if v else 0 for p, v in ent.items()}}
    shutil.rmtree(tmp, ignore_errors=True)
    res["pass"] = all(t["pass"] for t in T.values())
    return res


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--chain", required=True)
    v.add_argument("--storage", required=True)
    v.add_argument("--snapshots")
    v.add_argument("--recorder")
    v.add_argument("--segments", nargs=2)
    v.add_argument("--monitor-dir", default=DEFAULT_MONITOR_DIR)
    s = sub.add_parser("selftest")
    s.add_argument("--pre", required=True)
    s.add_argument("--db", required=True)
    s.add_argument("--times", nargs="*")
    s.add_argument("--monitor-dir", default=DEFAULT_MONITOR_DIR)
    a = ap.parse_args()
    out = verify(a) if a.cmd == "verify" else selftest(a)
    print(json.dumps(out, indent=1, sort_keys=True, default=str))
    return 0 if a.cmd == "verify" or out.get("pass") else 1


if __name__ == "__main__":
    sys.exit(main())
