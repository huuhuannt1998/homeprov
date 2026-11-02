"""E2 (round 12): retention-scoped PURGE markers through a real nightly purge on the real deployment.

The real deployment keeps 30 days (purge_keep_days: 30; time_zone UTC, so the purge runs at 04:12 UTC). Its oldest
state row is from 2026-09-09 01:17 UTC, so the purge of 2026-10-09 04:12 UTC is the first that deletes rows
(cutoff 2026-09-09 04:12 UTC). The deployment's long-running default monitor (published row scheme, encoding v1) has
anchored every second since 2026-08-31 to the default anchor, which does not check tags; it is the only chain that
covers rows old enough to be purged. The operator-side issuer (rig.marker_issuer) appends a scoped PURGE marker
before each scheduled purge, carrying an HMAC tag under the operator key in the record, and the verifier honours a
marker only if that tag verifies. Nothing on the deployment is reconfigured: the purge is the deployment's own.

    python3 stages/e2_night.py snapshot <tag>      # read-only consistent copy of the recorder, and of the chain
    python3 stages/e2_night.py issue  --until TS   # run the issuer in a throwaway container on the hub network
    python3 stages/e2_night.py analyze             # writes exp/out/e2_scoped_markers_real_night.json

Analysis. Every anchored segment of the default chain in the window [first row - 60 s, cutoff + 3600 s) is recomputed
from the pre-purge and the post-purge snapshot with the published monitor's commitment (row scheme, encoding v1).
Violations present after the purge but not before it are the purge's; each is scored without a marker, with the
scoped marker found on the chain, and against the declared cutoff an unscoped marker would carry. An offline copy of
the post-purge snapshot then deletes the rows of the hour after the cutoff (a purge-shaped deletion that reaches past
the retention boundary) to check that the scoped marker does not excuse it.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.dirname(HERE)
REPO = os.path.dirname(EXP)
sys.path.insert(0, EXP)
sys.path.insert(0, os.path.join(REPO, "monitor"))

WORK = os.environ.get("E2_WORK", "<research-dir>/HOMEPROV-P13-exp/e2night")   # outside the repo: DB copies, key
KEY_FILE = os.path.join(WORK, "operator.key")
HUB, ANCHOR, NET = "hpr-hass", "hpr-anchord", "homeprov-real_hp-real"
KEEP_DAYS, TOL_S = 30, 60.0
FIRST_ROW = 1788916675.0                     # min(states.last_updated_ts) on 2026-10-07
# The night analysed (E2_NIGHT, default the first scheduled night 2026-10-09). The 2026-10-09 purge never ran (Mac sleep
# delayed Home Assistant's timer and a hub restart cancelled it; drafts/round13/E2_PURGE_DIAGNOSIS.md), so the rerun
# analyses 2026-10-10 into its own file; the snapshot tags are pre_oct<day> and post_oct<day>.
import calendar as _cal
NIGHT = os.environ.get("E2_NIGHT", "2026-10-09")
PURGE_TS = float(_cal.timegm(time.strptime(NIGHT + "T04:12:00", "%Y-%m-%dT%H:%M:%S")))
CUTOFF = PURGE_TS - KEEP_DAYS * 86400.0      # 2026-10-09: 1788927120.0
TAG = "oct%d" % int(NIGHT[8:10])
OUT_NAME = "e2_scoped_markers_real_night.json" if NIGHT == "2026-10-09" else "e2_scoped_markers_real_night_%s.json" % NIGHT
assert NIGHT != "2026-10-09" or CUTOFF == 1788927120.0


def sh(*a, **k):
    return subprocess.run(list(a), check=True, capture_output=True, text=True, **k).stdout


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def log(**kw):
    kw["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join(WORK, "night_log.jsonl"), "a") as fh:
        fh.write(json.dumps(kw) + "\n")
    print(json.dumps(kw), flush=True)


def snapshot(tag):
    os.makedirs(WORK, exist_ok=True)
    tmp = f"/tmp/e2_{tag}.db"
    # sqlite3 online backup from a read-only connection: the live recorder is not written.
    sh("docker", "exec", HUB, "python3", "-c",
       "import sqlite3,sys; s=sqlite3.connect('file:/config/home-assistant_v2.db?mode=ro',uri=True); "
       "d=sqlite3.connect(sys.argv[1]); s.backup(d); d.close(); s.close()", tmp)
    db = os.path.join(WORK, f"{tag}.db")
    sh("docker", "cp", f"{HUB}:{tmp}", db)
    sh("docker", "exec", HUB, "rm", "-f", tmp)
    chain = os.path.join(WORK, f"{tag}.chain.jsonl")
    sh("docker", "cp", f"{ANCHOR}:/anchor/chain.jsonl", chain)
    con = sqlite3.connect(db)
    st = con.execute("select count(*), min(last_updated_ts), max(last_updated_ts) from states").fetchone()
    ev = con.execute("select count(*), min(time_fired_ts) from events").fetchone()
    con.close()
    log(step="snapshot", tag=tag, db_sha256=sha(db), chain_sha256=sha(chain), states=st, events=ev)


def issue(until):
    os.makedirs(WORK, exist_ok=True)
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as fh:
            fh.write(os.urandom(32).hex())
        os.chmod(KEY_FILE, 0o600)
    key = bytes.fromhex(open(KEY_FILE).read().strip())
    shutil.copy(os.path.join(EXP, "rig", "marker_issuer.py"), os.path.join(WORK, "marker_issuer.py"))
    log(step="issuer_start", key_fingerprint_sha256_16=hashlib.sha256(key).hexdigest()[:16], until=until,
        image=sh("docker", "inspect", "--format", "{{.Config.Image}}", "hpr-monitor").strip())
    # A throwaway container from the monitor's image on the deployment network, outside the hub's container; the
    # default anchor does not check X-HP-Auth, so the tag the verifier checks is the record's marker_tag.
    out = sh("docker", "run", "--rm", "--network", NET, "-v", f"{WORK}:/w:ro",
             sh("docker", "inspect", "--format", "{{.Config.Image}}", "hpr-monitor").strip(),
             "python3", "/w/marker_issuer.py", "--keep-days", str(KEEP_DAYS), "--tz", "UTC",
             "--anchor", f"http://{ANCHOR}:9900/append", "--key-file", "/w/operator.key",
             "--lead-s", "120", "--until", str(until))
    for line in out.splitlines():
        if line.strip():
            log(step="issued", **json.loads(line))


def _published_monitor():
    import importlib
    os.environ["HOMEPROV_SCHEME"] = "row"           # the default monitor's commitment (published, encoding v1)
    import monitor
    return importlib.reload(monitor)


def _roots(chain_path, lo, hi):
    roots = {}
    for line in open(chain_path):
        r = json.loads(line)
        p = r.get("payload") or {}
        sealed = p.get("sealed") if isinstance(p, dict) else None
        for g, segs in (sealed or {}).items():
            if not isinstance(segs, dict):
                continue
            for k, v in segs.items():
                # the chain also holds earlier anchor-test records (flood, a forged preemption root); only
                # well-formed roots count, and the first anchored one wins
                if isinstance(v, dict) and "acc" in v and "n" in v and (g, k) not in roots:                       # first anchored root of each segment
                    roots[(g, k)] = {"acc": v["acc"], "n": v["n"], "encoding": p.get("encoding", "v1"), "seq": r["seq"]}
    from rig.commit import GRAN
    return {gk: v for gk, v in roots.items() if lo - GRAN[gk[0]] <= int(gk[1]) * GRAN[gk[0]] < hi}


def _verify(mon, db, roots):
    nodes = mon.load(db)
    phis = {e: mon.commit(nodes, encoding=e) for e in {a["encoding"] for a in roots.values()}}
    out = {}
    for (g, k), a in roots.items():
        got = (phis[a["encoding"]].get(g) or {}).get(str(k))
        if got is None:
            out[(g, k)] = {"why": "SEGMENT_GONE", "was": a["n"], "now": 0}
        elif got["n"] != a["n"]:
            out[(g, k)] = {"why": "COUNT", "was": a["n"], "now": got["n"]}
        elif got["acc"] != a["acc"]:
            out[(g, k)] = {"why": "ACC"}
    return out


def analyze():
    from rig import marker_issuer, markers
    from rig.commit import GRAN
    mon = _published_monitor()
    key = bytes.fromhex(open(KEY_FILE).read().strip())
    pre, post = os.path.join(WORK, "pre_%s.db" % TAG), os.path.join(WORK, "post_%s.db" % TAG)
    chain = os.path.join(WORK, "post_%s.chain.jsonl" % TAG)
    out = os.path.join(EXP, "out", OUT_NAME)
    assert NIGHT == "2026-10-09" or not os.path.exists(out), "refusing to overwrite " + out
    lo, hi = FIRST_ROW - 60.0, CUTOFF + 3600.0
    roots = _roots(chain, lo, hi)
    recs = [json.loads(l) for l in open(chain)]
    mk_ok = marker_issuer.markers_from_chain(recs, key)
    mk_any = marker_issuer.markers_from_chain(recs, None)
    scoped = [m for m in mk_ok if abs(m["scheduled_ts"] - PURGE_TS) < 1.0]
    v_pre, v_post = _verify(mon, pre, roots), _verify(mon, post, roots)
    new = {gk: v for gk, v in v_post.items() if gk not in v_pre}
    as_list = [{"gran": g, "seg": k, **v} for (g, k), v in new.items()]
    f_scoped = markers.filter_violations_scoped(as_list, scoped, GRAN, KEEP_DAYS * 86400.0, TOL_S)
    # The unscoped rule at a declared cutoff one hour past the boundary (what a purge-shaped deletion would declare).
    declared = markers.marker(markers.PURGE, cutoff_ts=CUTOFF + 3600.0)
    f_decl = markers.filter_violations(as_list, [declared], GRAN)
    # Offline attack on a COPY of the post-purge snapshot: delete the hour after the scoped cutoff.
    atk = os.path.join(WORK, "post_%s_attack_copy.db" % TAG)
    shutil.copy(post, atk)
    con = sqlite3.connect(atk)
    n_del = con.execute("DELETE FROM states WHERE last_updated_ts>=? AND last_updated_ts<?", (CUTOFF + TOL_S, CUTOFF + 3600.0)).rowcount
    n_del += con.execute("DELETE FROM events WHERE time_fired_ts>=? AND time_fired_ts<?", (CUTOFF + TOL_S, CUTOFF + 3600.0)).rowcount
    con.commit(); con.close()
    v_atk = _verify(mon, atk, roots)
    new_atk = [{"gran": g, "seg": k, **v} for (g, k), v in v_atk.items() if (g, k) not in v_pre]
    a_scoped = markers.filter_violations_scoped(new_atk, scoped, GRAN, KEEP_DAYS * 86400.0, TOL_S)
    a_decl = markers.filter_violations(new_atk, [declared], GRAN)
    os.remove(atk)
    con = sqlite3.connect(post)
    oldest_after = con.execute("select min(last_updated_ts) from states").fetchone()[0]
    con.close()
    con = sqlite3.connect(pre)
    purged_rows = [con.execute("select count(*) from states where last_updated_ts<?", (CUTOFF,)).fetchone()[0],
                   con.execute("select count(*) from events where time_fired_ts<?", (CUTOFF,)).fetchone()[0]]
    con.close()
    # Did the purge run? A purge also deletes recorder_runs and statistics_runs older than its cutoff (the 2026-10-09
    # night left both unchanged; E2_PURGE_DIAGNOSIS.md 2.1).
    def _runs(db):
        c = sqlite3.connect(db)
        r = {t: c.execute("select count(*), min(start) from %s" % t).fetchone() for t in ("recorder_runs", "statistics_runs")}
        c.close()
        return r
    purge_evidence = {"pre": _runs(pre), "post": _runs(post)}
    # statistics_runs gains a row every few minutes, so compare the oldest start, not the count.
    purge_evidence["ran"] = (any(purge_evidence["post"][t][1] != purge_evidence["pre"][t][1]
                                 for t in ("recorder_runs", "statistics_runs"))
                             and oldest_after is not None and oldest_after >= CUTOFF)
    by = lambda vs: {g: sum(1 for v in vs if v["gran"] == g) for g in GRAN}
    res = {"experiment": "E2 real night: retention-scoped PURGE markers through the deployment's own nightly purge",
           "purge_scheduled_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(PURGE_TS)),
           "policy": {"purge_keep_days": KEEP_DAYS, "time_zone": "UTC", "tol_s": TOL_S},
           "scoped_cutoff_ts": CUTOFF + TOL_S, "oldest_state_after_purge": oldest_after,
           "purge_evidence": purge_evidence, "night": NIGHT,
           "rows_older_than_cutoff_before_purge": {"states": purged_rows[0], "events": purged_rows[1]},
           "window": [lo, hi], "anchored_segments_in_window": by([{"gran": g} for g, _ in roots]),
           "markers_on_chain": {"tag_valid": len(mk_ok), "any": len(mk_any), "scoped_for_this_purge": len(scoped),
                                "scoped": scoped},
           "violations_before_purge": len(v_pre), "new_violations_after_purge": len(new),
           "new_by_granularity": by(as_list),
           "scoped": {"excused": f_scoped["n_excused"], "remaining": f_scoped["n_violations"],
                      "remaining_detail": f_scoped["violations"][:20]},
           "unscoped_declared_cutoff_plus_1h": {"excused": len(f_decl["excused"]), "remaining": f_decl["n_violations"]},
           "offline_attack_copy": {"deleted_rows": n_del, "deleted_window": [CUTOFF + TOL_S, CUTOFF + 3600.0],
                                   "new_violations": len(new_atk), "by_granularity": by(new_atk),
                                   "scoped_remaining": a_scoped["n_violations"], "scoped_excused": a_scoped["n_excused"],
                                   "declared_remaining": a_decl["n_violations"], "declared_excused": len(a_decl["excused"])},
           "inputs": {os.path.basename(p): sha(p) for p in (pre, post, chain)},
           "versions": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "monitor_py_sha256": sha(os.path.join(REPO, "monitor", "monitor.py")),
                        "markers_py_sha256": sha(os.path.join(EXP, "rig", "markers.py")),
                        "marker_issuer_py_sha256": sha(os.path.join(EXP, "rig", "marker_issuer.py")),
                        "operator_key_fingerprint_sha256_16": hashlib.sha256(key).hexdigest()[:16]},
           "night_log": [json.loads(l) for l in open(os.path.join(WORK, "night_log.jsonl"))],
           "capability": {"issuer": "operator-side, outside the hub's container, holds the operator key",
                          "anchor": "the deployment's default anchor (no tag check); the verifier checks marker_tag",
                          "purge": "Home Assistant's own scheduled purge; the deployment was not reconfigured"}}
    json.dump(res, open(out, "w"), indent=1, default=str)
    print(json.dumps({k: res[k] for k in ("purge_evidence", "new_violations_after_purge", "scoped", "offline_attack_copy")}, indent=1, default=str))
    print(out, sha(out)[:12])


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "snapshot":
        snapshot(sys.argv[2])
    elif cmd == "issue":
        issue(float(sys.argv[sys.argv.index("--until") + 1]))
    elif cmd == "analyze":
        analyze()
