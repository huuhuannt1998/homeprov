"""E9 item A1 (round 13, 2026-10-09): the purge-disconnect rule against a REAL nightly purge, offline.

Home Assistant 2026.7.4's nightly purge (recorder/purge.py _purge_state_ids -> queries.py disconnect_states_rows) sets
states.old_state_id = NULL on every retained state row whose predecessor it deletes. Both deployed schemes commit that
column, so a monitor that had sealed those rows would see violations on retained rows, after the purge's cutoff, that
the retention-scoped PURGE marker of round 12 does not excuse.

OFFLINE EMULATION (not a run of a deployed monitor). The E2 night driver took two read-only snapshots of the lab
installation's recorder around the 04:12 UTC purge (HOMEPROV-P13-exp/e2night/pre_<tag>.db at about 03:55 and
post_<tag>.db at about 04:45). This script works on copies of them only:
  1. a stable-columns monitor (monitor/monitor.py as it is: HOMEPROV_SCHEME=stable, coverage, keylog,
     HOMEPROV_SINCE=0 so its first poll seals every row and binds every key) polls the pre copy, at a clock fixed at the
     pre snapshot's time, and appends to an in-memory anchor with the anchor daemon's record format; twice: with the
     escrow on (the committed values come from the escrow) and with the per-row binding instead (HOMEPROV_ROWBIND=1,
     escrow off);
  2. the operator's PURGE marker for that night (rig.marker_issuer.scoped_marker: scheduled 04:12:00 UTC, keep 30 days,
     issued 04:10:00), tagged and signed with a throwaway operator key made here, is appended after the monitor's
     records;
  3. exp/stages/e7_verify.py verifies the post copy against that chain (whole history, recorder snapshot time = the post
     snapshot's) three ways: without markers; with the marker and the round-12 retention-scoped rule alone
     (purge_disconnect=False); with the marker and the purge-disconnect rule;
  4. the ground truth is read from the two copies directly: retained state rows whose old_state_id went from a value to
     NULL (with the referenced row: present after the purge or not, and its timestamp before the purge), retained rows
     changed in any other committed column, and the rows the purge removed.
Writes exp/out/e9_purge_disconnect_offline.json (never overwritten), or --out.

    python3 exp/stages/e9_purge_disconnect_offline.py --tag oct10 [--night 2026-10-10] [--out FILE]
"""
from __future__ import annotations

import argparse
import calendar
import collections
import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "exp"))
from rig import marker_issuer as MI  # noqa: E402

E2 = "<research-dir>/HOMEPROV-P13-exp/e2night"
KEEP_DAYS = 30
LATE_BOUND = GAP_S = 30.0
ENV_CLEAR = ("HOMEPROV_ENCODING", "HOMEPROV_NAMEMAP_DIR", "HOMEPROV_CLOCK_FILE", "HOMEPROV_GRACE_S",
             "HOMEPROV_ANCHOR_KEY", "HOMEPROV_SIGN_KEY", "HOMEPROV_COST_LOG", "HOMEPROV_READ",
             "HOMEPROV_QUICK_CHECK_EVERY", "HOMEPROV_MAX_RECORD_BYTES", "HOMEPROV_MAX_PARTS", "HOMEPROV_REPLY_TAGS")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load(path, name, env):
    old = {k: os.environ.get(k) for k in set(env) | set(ENV_CLEAR)}
    for k in ENV_CLEAR:
        os.environ.pop(k, None)
    for k, v in env.items():
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


def private_copy(src, dst):
    for s in ("", "-wal", "-shm"):
        if os.path.exists(src + s) and os.path.getsize(src + s) > 0:
            shutil.copy2(src + s, dst + s)
    con = sqlite3.connect(dst)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    return dst


def snapshot_time(tag, db):
    """The time the night driver logged for the snapshot (night_log.jsonl), else the newest row's timestamp."""
    try:
        for line in open(os.path.join(E2, "night_log.jsonl")):
            d = json.loads(line)
            if d.get("step") == "snapshot" and d.get("tag") == tag:
                return float(calendar.timegm(time.strptime(d["at"], "%Y-%m-%dT%H:%M:%SZ"))), "night_log.jsonl"
    except OSError:
        pass
    con = sqlite3.connect(db)
    t = max(con.execute("SELECT max(last_updated_ts) FROM states").fetchone()[0],
            con.execute("SELECT max(time_fired_ts) FROM events").fetchone()[0])
    con.close()
    return float(int(t) + 1), "newest row + 1 s"


class Chain:
    """The anchor daemon's record format ({seq, recv_ts, payload}), in memory; every append is accepted."""

    def __init__(self):
        self.lines = []

    def append(self, rec):
        p = json.loads(json.dumps(rec, sort_keys=True))
        self.lines.append(json.dumps({"seq": len(self.lines) + 1, "recv_ts": p.get("ts"), "payload": p},
                                     sort_keys=True))
        return {"ok": True, "seq": len(self.lines)}


class Clock:
    def __init__(self, t):
        self.t = t

    def time(self):
        return self.t

    def sleep(self, _s):
        return None


def emulate(pre, scratch, source, t_pre):
    """Poll the pre copy with a stable-columns monitor that seals every row; returns (chain, escrow path, polls)."""
    env = {"HOMEPROV_DB": pre, "HOMEPROV_SCRATCH": os.path.join(scratch, "mon_" + source), "HOMEPROV_SCHEME": "stable",
           "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "1", "HOMEPROV_SINCE": "0",
           "HOMEPROV_ROWBIND": "1" if source == "rowbind" else "0",
           "HOMEPROV_ESCROW_DIR": os.path.join(scratch, "escrow_" + source) if source == "escrow" else None,
           "HOMEPROV_MAX_RECORD_BYTES": str(8 * 1024 * 1024), "HOMEPROV_MAX_PARTS": "64"}
    os.makedirs(env["HOMEPROV_SCRATCH"], exist_ok=True)
    M = load(os.path.join(REPO, "monitor", "monitor.py"), "e9a1_monitor_" + source, env)
    chain = Chain()
    M.append = chain.append
    M.time = Clock(t_pre)
    st = M.load_state()
    ticks, t_start = [], time.time()
    while True:
        out = M.tick(st)
        ticks.append({k: out.get(k) for k in ("seq_local", "n_nodes", "parts", "pending", "backlog", "copy_ms",
                                               "load_ms", "commit_ms", "evidence_unobservable", "reason")})
        if out.get("evidence_unobservable") or (out.get("pending") == 0 and out.get("backlog") == 0) \
                or len(ticks) >= 40:
            break
    esc = os.path.join(env["HOMEPROV_ESCROW_DIR"], "escrow.jsonl") if env["HOMEPROV_ESCROW_DIR"] else None
    return chain, esc, {"polls": ticks, "wall_s": round(time.time() - t_start, 1), "records": len(chain.lines),
                        "chain_bytes": sum(len(x) + 1 for x in chain.lines),
                        "escrow_bytes": os.path.getsize(esc) if esc and os.path.exists(esc) else None}


def ground_truth(pre, post, cutoff):
    con = sqlite3.connect(post)
    con.execute("ATTACH DATABASE ? AS pre", (pre,))
    q = con.execute
    gt = {"cutoff": cutoff}
    rows = q("""SELECT a.state_id, a.last_updated_ts, a.old_state_id, p.last_updated_ts,
                       (SELECT 1 FROM main.states x WHERE x.state_id = a.old_state_id)
                FROM pre.states a JOIN main.states b ON b.state_id = a.state_id
                LEFT JOIN pre.states p ON p.state_id = a.old_state_id
                WHERE a.old_state_id IS NOT NULL AND b.old_state_id IS NULL""").fetchall()
    gt["disconnected_rows"] = [{"key": "s:%d" % r[0], "ts": r[1], "second": str(int(r[1] // 1)),
                                "old_state_id_before": r[2], "referenced_row_ts": r[3],
                                "referenced_row_present_after": bool(r[4]),
                                "referenced_row_before_cutoff": r[3] is not None and r[3] < cutoff,
                                "seconds_after_cutoff": round(r[1] - cutoff, 3)} for r in rows]
    gt["n_disconnected_rows"] = len(rows)
    gt["disconnected_seconds"] = sorted({d["second"] for d in gt["disconnected_rows"]}, key=int)
    gt["n_disconnected_seconds"] = len(gt["disconnected_seconds"])
    gt["n_disconnected_more_than_an_hour_after_cutoff"] = sum(1 for d in gt["disconnected_rows"]
                                                              if d["seconds_after_cutoff"] > 3600)
    cols = [r[1] for r in q("PRAGMA main.table_info(states)") if r[1] not in ("last_reported_ts", "old_state_id")]
    diff = " OR ".join("a.%s IS NOT b.%s" % (c, c) for c in cols)
    gt["retained_states_changed_in_other_columns"] = q(
        "SELECT count(*) FROM pre.states a JOIN main.states b ON b.state_id = a.state_id WHERE " + diff).fetchone()[0]
    gt["retained_states_old_state_id_changed_otherwise"] = q(
        "SELECT count(*) FROM pre.states a JOIN main.states b ON b.state_id = a.state_id"
        " WHERE a.old_state_id IS NOT b.old_state_id AND NOT (a.old_state_id IS NOT NULL AND b.old_state_id IS NULL)"
    ).fetchone()[0]
    ecols = [r[1] for r in q("PRAGMA main.table_info(events)")]
    gt["retained_events_changed"] = q(
        "SELECT count(*) FROM pre.events a JOIN main.events b ON b.event_id = a.event_id WHERE "
        + " OR ".join("a.%s IS NOT b.%s" % (c, c) for c in ecols)).fetchone()[0]
    for t, k, ts in (("states", "state_id", "last_updated_ts"), ("events", "event_id", "time_fired_ts")):
        gone = q("SELECT a.%s FROM pre.%s a WHERE NOT EXISTS (SELECT 1 FROM main.%s b WHERE b.%s = a.%s)"
                 % (ts, t, t, k, k)).fetchall()
        gt["%s_removed" % t] = {"n": len(gone), "older_than_cutoff": sum(1 for (x,) in gone if x < cutoff),
                                "not_older_than_cutoff": sum(1 for (x,) in gone if not x < cutoff)}
        gt["%s_older_than_cutoff_left" % t] = q("SELECT count(*) FROM main.%s WHERE %s < ?" % (t, ts),
                                               (cutoff,)).fetchone()[0]
    con.close()
    return gt


def summary(res):
    viol = collections.Counter(v["gran"] for v in res["violations"])
    out = {"violations": dict(viol), "keylog_violations": len(res["keylog_violations"]),
           "flagged_seconds": len(res["flagged_seconds"]),
           "flagged_seconds_list": res["flagged_seconds"][:200],
           "attributable_rows": len(res["attributable_rows"]),
           "unobserved_late_rows": len(res.get("unobserved_late_rows") or []),
           "benign_late_rows": len(res["benign_late_rows"]),
           "root_unknown_segments": len(res["root_unknown_segments"]),
           "excused_violations": dict(collections.Counter(v["gran"] for v in res.get("excused_violations") or [])),
           "excused_keylog_violations": len(res.get("excused_keylog_violations") or []),
           "signatures": res["signatures"], "markers": res.get("markers")}
    p = res.get("purge")
    if p:
        out["purge"] = {"cutoffs": p.get("cutoffs"), "disconnect_rule": p.get("disconnect_rule"),
                        "excused": p.get("excused"), "disconnects": p.get("disconnects"),
                        "disconnected_rows": p.get("disconnected_rows"),
                        "not_excused": collections.Counter(
                            (x.get("gran") or "keylog") + ":" + (x["why"] if isinstance(x["why"], str)
                                                                  else ",".join(x["why"]))
                            for x in p.get("not_excused") or [])}
    left = [v for v in res["violations"]]
    out["left"] = {"violations": [{"gran": v["gran"], "seg": v["seg"], "mechanism": v.get("mechanism"),
                                   "not_excused_by_purge": v.get("not_excused_by_purge")} for v in left[:100]],
                   "keylog_violations": [{"range": kv["range"], "table": kv["table"],
                                          "why": kv.get("not_excused_by_purge"),
                                          "suspects": [x["key"] for x in kv["suspects"]][:20]}
                                         for kv in res["keylog_violations"][:100]]}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tag", default="oct10", help="snapshot pair pre_<tag>.db / post_<tag>.db in the E2 directory")
    ap.add_argument("--night", default=None, help="the purge's date (default from the tag: 2026-10-<day>)")
    ap.add_argument("--e2-dir", default=E2)
    ap.add_argument("--out", default=os.path.join(OUT, "e9_purge_disconnect_offline.json"))
    ap.add_argument("--sources", default="escrow,rowbind")
    ap.add_argument("--purge-tol-s", type=float, default=60.0, help="the verifier's tolerance after the scheduled "
                    "purge (the hub's cutoff is its fire time minus keep); 60 as in the E9 smoke runs")
    ap.add_argument("--pre-at", type=float, default=None, help="the pre snapshot's time (default: the night log's, "
                    "else the newest row + 1 s)")
    ap.add_argument("--post-at", type=float, default=None, help="the post snapshot's time (same default); a dry run "
                    "on an emulated purge must give one after the scheduled purge, or the marker counts as after it")
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    night = a.night or "2026-10-%02d" % int(a.tag[3:])
    sched = float(calendar.timegm(time.strptime(night + "T04:12:00", "%Y-%m-%dT%H:%M:%S")))
    keep = KEEP_DAYS * 86400.0
    cutoff = sched - keep
    src_pre, src_post = (os.path.join(a.e2_dir, "%s_%s.db" % (w, a.tag)) for w in ("pre", "post"))
    for p in (src_pre, src_post):
        if not os.path.exists(p):
            raise SystemExit("missing %s (the night driver writes it after the purge)" % p)
    scratch = tempfile.mkdtemp(prefix="e9a1_")
    out = {"check": "e9_purge_disconnect_offline", "label": "offline emulation: a stable-columns monitor that sealed "
           "every row of the pre-purge snapshot, verified against the post-purge snapshot; not a run of a deployed "
           "monitor", "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "night": night, "scheduled_purge_ts": sched, "keep_s": keep, "cutoff_ts": cutoff,
           "cutoff_utc": datetime.datetime.fromtimestamp(cutoff, datetime.timezone.utc).isoformat(),
           "parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "purge_tol_s": a.purge_tol_s},
           "inputs": {"pre": {"path": src_pre, "sha256": sha(src_pre)}, "post": {"path": src_post,
                                                                                 "sha256": sha(src_post)}},
           "code_sha256": {p: sha(os.path.join(REPO, p)) for p in (
               "exp/stages/e9_purge_disconnect_offline.py", "exp/stages/e7_verify.py", "monitor/monitor.py",
               "exp/rig/marker_issuer.py")}}
    pre = private_copy(src_pre, os.path.join(scratch, "pre.db"))
    post = private_copy(src_post, os.path.join(scratch, "post.db"))
    t_pre, how_pre = (a.pre_at, "--pre-at") if a.pre_at is not None else snapshot_time("pre_" + a.tag, pre)
    t_post, how_post = (a.post_at, "--post-at") if a.post_at is not None else snapshot_time("post_" + a.tag, post)
    out["snapshot_times"] = {"pre": t_pre, "pre_from": how_pre, "post": t_post, "post_from": how_post}
    out["ground_truth"] = ground_truth(pre, post, cutoff)
    print(json.dumps({k: v for k, v in out["ground_truth"].items() if k != "disconnected_rows"}), flush=True)
    # the operator: a throwaway key pair and HMAC key made here, used for this emulation only and not kept
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    signer = Ed25519PrivateKey.generate()
    pub = os.path.join(scratch, "operator_pub.pem")
    with open(pub, "wb") as fh:
        fh.write(signer.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    opkey = os.urandom(32)
    marker = MI.scoped_marker(sched, keep, issued_ts=sched - 120.0)
    out["marker"] = marker
    V = load(os.path.join(HERE, "e7_verify.py"), "e9a1_e7_verify", {})
    out["sources"] = {}
    for source in a.sources.split(","):
        chain, esc, emu = emulate(pre, scratch, source, t_pre)
        chain.lines.append(json.dumps({"seq": len(chain.lines) + 1, "recv_ts": sched - 120.0,
                                       "payload": MI.marker_record(opkey, marker, signer)}, sort_keys=True))
        so = {"emulation": emu, "chain_sha256": hashlib.sha256(("\n".join(chain.lines) + "\n").encode()).hexdigest()}
        Mv = V.load_monitor("stable", os.path.join(scratch, "v_" + source))
        esc_lines = V.Escrow(path=esc) if esc else None     # read lazily (E9 code review R2)
        for variant, kw in (("no_marker", {}),
                            ("marker_retention_rule_only", {"operator_key": opkey, "operator_pubkey": pub,
                                                            "purge_keep_s": keep, "purge_tol_s": a.purge_tol_s,
                                                            "purge_disconnect": False}),
                            ("marker_with_purge_disconnect_rule", {"operator_key": opkey, "operator_pubkey": pub,
                                                                   "purge_keep_s": keep,
                                                                   "purge_tol_s": a.purge_tol_s})):
            t = time.time()
            res = V.verify(Mv, post, chain.lines, LATE_BOUND, GAP_S, scheme="stable", tsnap=t_post,
                           escrow_lines=esc_lines, recovery=False, **kw)
            so[variant] = dict(summary(res), verify_wall_s=round(time.time() - t, 1))
            print(source, variant, json.dumps({k: so[variant][k] for k in (
                "violations", "keylog_violations", "flagged_seconds", "excused_violations",
                "excused_keylog_violations")}), flush=True)
        if esc_lines is not None:
            esc_lines.close()
        del esc_lines
        out["sources"][source] = so
        shutil.rmtree(os.path.join(scratch, "escrow_" + source), ignore_errors=True)
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    shutil.rmtree(scratch, ignore_errors=True)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
