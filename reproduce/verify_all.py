#!/usr/bin/env python3
"""Re-run the HOMEPROV verifier on the saved real-deployment snapshots and regenerate the detection table.

    python3 reproduce/verify_all.py [--snapshots DIR] [--runs e_d_clo,e_ps_clo,...] [--out FILE]

For each real-deployment run whose verifier snapshot is in the snapshot set, this script
  1. checks every input file against the snapshot set's SHA256SUMS,
  2. recomputes the commitment of the saved recorder copy with the shipped monitor (monitor/monitor.py, or
     monitor/monitor_wholerow.py for the whole-row baseline), opened read-only,
  3. verifies it against the first anchored root of each segment in the saved anchor chain (the same rule as
     exp/stages/e_c_write_time.py verify_window),
  4. counts, per arm, the trials whose one-second segment raised a violation (flagged) and, of those, the ones the
     late-row test attributes to the edit (delta_n <= 0) or leaves ambiguous (delta_n > 0, rows arrived after sealing),
  5. counts the benign floor: untouched anchored one-second segments that fail, under the paper's counting rule (a
     trial touches every one-second segment holding a row it wrote; hp_d2/floor_rescore.py),
  6. compares every regenerated number with the published result files in exp/out and writes a report.

What it does not regenerate: the misattribution column (the logbook processor's verdict at run time, recorded by the
harness) and the two unauthenticated runs (e_c_write_time, e_d_other_principal_real), whose verifier snapshots are not in
the snapshot set; their published numbers are listed as read from file. Paths are relative to the repository; the
snapshot directory defaults to ../HOMEPROV-P13-snapshots/verifier-recorder-snapshots-2026-10 beside it.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import types
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "exp", "out")
DEFAULT_SNAP = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-snapshots", "verifier-recorder-snapshots-2026-10")
# The released artifact ships per-run window extracts (reproduce/make_window_extracts.py) with their anchor chains
# here; every in-window segment's rows are present in full, so the regenerated numbers are the same.
DEFAULT_EXTRACTS = os.path.join(REPO, "reproduce", "snapshots")


class Inputs:
    """Where a run's recorder copy and anchor chain come from, and the checksum list that vouches for them.

    mode 'snapshots': the full verifier snapshot set (SHA256SUMS); mode 'extracts': the per-run window extracts
    (EXTRACTS_SHA256SUMS), named <run>.db and <run>.chain.jsonl[.gz]."""

    def __init__(self, snapshots=None, extracts=None):
        if snapshots:
            self.mode, self.base, sums_name = "snapshots", snapshots, "SHA256SUMS"
        else:
            self.mode, self.base, sums_name = "extracts", extracts, "EXTRACTS_SHA256SUMS"
        self.sums = {}
        for line in open(os.path.join(self.base, sums_name)):
            h, p = line.split(None, 1)
            p = p.strip()
            self.sums[p[2:] if p.startswith("./") else p] = h

    def paths(self, run_id):
        cfg = RUNS[run_id]
        if self.mode == "extracts":
            db = os.path.join(self.base, run_id + ".db")
            chain = os.path.join(self.base, run_id + ".chain.jsonl" + (".gz" if cfg["chain"].endswith(".gz") else ""))
        else:
            db = os.path.join(self.base, cfg["db"])
            chain = (os.path.join(OUT, cfg["chain"][5:]) if cfg["chain"].startswith("@out/")
                     else os.path.join(self.base, cfg["chain"]))
        return db, chain

    def checked(self, run_id):
        """Paths after their checksums are verified; an extract must be listed, a snapshot file must match if listed."""
        db, chain = self.paths(run_id)
        info = {}
        for label, p in (("snapshot_db", db), ("chain", chain)):
            rel = os.path.relpath(p, self.base)
            listed, got = self.sums.get(rel), sha256_file(p)
            if (listed is None and self.mode == "extracts") or (listed is not None and listed != got):
                raise SystemExit(f"{run_id}: {rel} is not vouched for by the {self.mode} checksum list")
            info[label] = {"path": os.path.relpath(p, REPO if self.mode == "extracts" else os.path.dirname(REPO)),
                           "sha256": got, "listed": listed is not None}
        return db, chain, info


def default_inputs(snapshots=None, extracts=None):
    """--snapshots wins, then --extracts, then $HOMEPROV_SNAPSHOTS, then the extracts shipped in the artifact, then the
    full snapshot set beside the repository."""
    if snapshots:
        return Inputs(snapshots=snapshots)
    if extracts:
        return Inputs(extracts=extracts)
    if os.environ.get("HOMEPROV_SNAPSHOTS"):
        return Inputs(snapshots=os.environ["HOMEPROV_SNAPSHOTS"])
    if os.path.exists(os.path.join(DEFAULT_EXTRACTS, "EXTRACTS_SHA256SUMS")):
        return Inputs(extracts=DEFAULT_EXTRACTS)
    return Inputs(snapshots=DEFAULT_SNAP)
sys.path.insert(0, os.path.join(REPO, "exp"))
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
from rig import stats  # noqa: E402
import chainverify  # noqa: E402  (anchor-chain link check, review sp2027-r2 N2)

RUNS = {
    "e_d_clo": dict(scheme="closure", db="hp-clo/e_d_clo/ec_verify/recorder.db", chain="hp-clo/e_d_clo/chain.jsonl",
                    result="e_d_clo_other_principal_real.json", floor="e_d_clo_floor_rescore.json", arms=("PU", "PI")),
    "e_c_clo": dict(scheme="closure", db="hp-clo/e_c_clo/ec_verify/recorder.db", chain="hp-clo/e_c_clo/chain.jsonl",
                    result="e_c_clo_other_principal_real.json", floor="e_c_clo_floor_rescore.json", arms=("P",)),
    "e_ps_clo": dict(scheme="closure", db="hp-clo/e_ps_clo/ps_verify/recorder.db", chain="hp-clo/e_ps_clo/chain.jsonl",
                     result="e_ps_clo_detection.json", floor="e_ps_clo_floor_rescore.json", arms=("PS",)),
    "e_psr_clo": dict(scheme="closure", db="hp-clo/e_psr_clo/ps_verify/recorder.db", chain="hp-clo/e_psr_clo/chain.jsonl",
                      result="e_psr_clo_detection.json", floor="e_psr_clo_floor_rescore.json", arms=("PSR",)),
    "e_d_auth": dict(scheme="row", db="hp_d2/live/recorder.db", chain="@out/e_d_auth_anchor_chain.jsonl.gz",
                     result="e_d_auth_other_principal_real.json", floor="e_d_auth_floor_rescore.json", arms=("PU", "PI"),
                     note="the verifier's own e_d_auth snapshot is not in the set; the later consistent recorder copy "
                          "hp_d2/live (2026-10-04) is used, as e_d_auth_floor_rescore.json did; rows that reached the "
                          "recorder after the run make the late-row breakdown not computable, as the paper states",
                     late_row_not_computable=True),
    "e_c_auth": dict(scheme="row", db="hp-ec-auth/ec_verify/recorder.db", chain="hp-ec-auth/e_c_auth_chain.jsonl",
                     result="e_c_auth_other_principal_real.json", floor="e_c_auth_floor_rescore.json", arms=("P",)),
    "e_ps_auth": dict(scheme="row", db="hp-ps-auth/ps_verify/recorder.db", chain="hp-ps-auth/e_ps_auth_chain.jsonl",
                      result="e_ps_auth_detection.json", floor="e_ps_auth_floor_rescore.json", arms=("PS",)),
    "e_d_whr": dict(scheme="wholerow", db="hp-whr/e_d_whr/ec_verify/recorder.db", chain="hp-whr/e_d_whr/chain.jsonl",
                    result="e_d_whr_other_principal_real.json", floor="e_d_whr_floor_rescore.json", arms=("PU", "PI")),
    "e_ps_whr": dict(scheme="wholerow", db="hp-whr/e_ps_whr/ps_verify/recorder.db", chain="hp-whr/e_ps_whr/chain.jsonl",
                     result="e_ps_whr_detection.json", floor="e_ps_whr_floor_rescore.json", arms=("PS",)),
    "e_psr_whr": dict(scheme="wholerow", db="hp-whr/e_psr_whr/ps_verify/recorder.db", chain="hp-whr/e_psr_whr/chain.jsonl",
                      result="e_psr_whr_detection.json", floor="e_psr_whr_floor_rescore.json", arms=("PSR",)),
}
NOT_RERUN = {"e_c_write_time": "e_c_write_time_floor_rescore.json",
             "e_d_other_principal_real": "e_d_other_principal_real_floor_rescore.json"}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ro_connect(db, timeout=30, **_kw):
    """Read-only, immutable: no -wal/-shm/-journal file is ever created next to a snapshot."""
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(os.path.abspath(db)), uri=True, timeout=timeout)


SHIM = types.SimpleNamespace(connect=ro_connect)


def load_monitor(scheme, scratch):
    os.environ["HOMEPROV_SCRATCH"] = scratch
    os.environ["HOMEPROV_DB"] = os.path.join(scratch, "unused.db")
    if scheme == "wholerow":
        sys.path.insert(0, os.path.join(REPO, "monitor"))
        import monitor_wholerow as WR  # noqa: PLC0415
        WR.sqlite3 = SHIM
        WR.M.sqlite3 = SHIM
        assert WR.M.SCHEME == "wholerow"
        return WR.M
    os.environ["HOMEPROV_SCHEME"] = scheme
    spec = importlib.util.spec_from_file_location("hp_monitor_" + scheme, os.path.join(REPO, "monitor", "monitor.py"))
    M = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(M)
    M.sqlite3 = SHIM
    assert M.SCHEME == scheme
    return M


def chain_lines(path):
    return (gzip.open(path, "rt") if path.endswith(".gz") else open(path)).read().splitlines()


def anchored_roots(lines, t0, tsnap):
    """First anchored root per (granularity, segment) among chain records stamped in [t0, tsnap]."""
    roots = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        p = rec.get("payload") or {}
        ts = p.get("ts") or rec.get("recv_ts") or 0.0
        if not (t0 <= ts <= tsnap) or p.get("evidence_unobservable"):
            continue
        for g, segs in (p.get("sealed") or {}).items():
            if isinstance(segs, dict):
                for s, v in segs.items():
                    if (g, str(s)) not in roots and isinstance(v, dict):
                        # records without "encoding" were sealed before the 2026-10-06 node-hash fix ('v1')
                        roots[(g, str(s))] = {"acc": v.get("acc"), "n": v.get("n"),
                                              "encoding": p.get("encoding", "v1")}
    return roots


def verify_window(phi, roots, widths, t0, t1):
    out = {}
    for (g, seg), a in roots.items():
        w = widths.get(g)
        if w is None or not (t0 - w <= int(seg) * w <= t1 + w):
            continue
        got = (phi.get(g) or {}).get(str(seg))
        if got is None:
            out[(g, seg)] = {"violation": True, "delta_n": None}
        elif got["acc"] != a["acc"] or got["n"] != a["n"]:
            out[(g, seg)] = {"violation": True, "delta_n": got["n"] - a["n"]}
        else:
            out[(g, seg)] = {"violation": False}
    return out


B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid_s(v):
    if not v:
        return None
    if len(v) == 32:
        return int(v[:12], 16) / 1000.0
    if len(v) == 26:
        n = 0
        for ch in v[:10].upper():
            n = n * 32 + B32.index(ch)
        return n / 1000.0
    return None


def ulid_bytes(v):
    n = 0
    for ch in v.upper():
        n = n * 32 + B32.index(ch)
    return n.to_bytes(16, "big")


def row_ts(t):
    for k in ("judged_row", "forged_row", "row_before"):
        r = t.get(k)
        if isinstance(r, dict) and r.get("ts"):
            return float(r["ts"])
    return None


def touched_segments(trials, con, W):
    """The paper's counting rule (hp_d2/floor_rescore.py): every one-second segment holding a row the trial wrote."""
    def state_ts(sid):
        return (con.execute("SELECT last_updated_ts FROM states WHERE state_id=?", (sid,)).fetchone() or [None])[0]
    new = {g: set() for g in W}
    for t in trials:
        ts = row_ts(t)
        if ts is None:
            continue
        secs = {int(ts // 1)}
        for k in ("row_before", "judged_row", "forged_row"):
            r = t.get(k)
            if isinstance(r, dict) and r.get("state_id"):
                x = state_ts(r["state_id"]) or r.get("ts")
                if x:
                    secs.add(int(float(x) // 1))
        for sid in (t.get("laundered_state_ids") or []) + (t.get("swapped_state_ids") or []):
            x = state_ts(sid)
            if x:
                secs.add(int(x // 1))
        if t.get("arm") == "W3":
            for e in t.get("residual_adversary_call_service") or []:
                if e.get("ts"):
                    secs.add(int(float(e["ts"]) // 1))
        else:
            r = t.get("row_before") or t.get("forged_row") or t.get("judged_row") or {}
            for cid in (r.get("context_id_bin"), t.get("fabricated_event_context")):
                if not cid:
                    continue
                b = bytes.fromhex(cid) if len(cid) == 32 else ulid_bytes(cid)
                evs = [x[0] for x in con.execute("SELECT time_fired_ts FROM events WHERE context_id_bin=?", (b,))]
                if evs:
                    secs |= {int(x // 1) for x in evs if x}
                else:
                    c = ulid_s(cid)
                    if c is not None:
                        lo, hi = sorted((c, ts))
                        secs |= set(range(int(lo // 1), int(hi // 1) + 1))
        for s in secs:
            for g, w in W.items():
                new[g].add(str(int(s * 1.0 // w)))
    return new


def cp(k, n):
    r = stats.clopper_pearson(k, n)
    return [round(r["ci_lo"], 3), round(r["ci_hi"], 3)]


def published(run_id, cfg):
    """The numbers the paper's tables print, read from the same files the float generator reads."""
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    fl = json.load(open(os.path.join(OUT, cfg["floor"])))["new_rule_floor"]["second"]
    pub = {"floor": [fl["k"], fl["n"]], "arms": {}}
    if "arms" in res:
        for a in cfg["arms"]:
            pub["arms"][a] = {"flagged": res["arms"][a]["homeprov_detection_second"]["k"],
                              "n": res["arms"][a]["homeprov_detection_second"]["n"]}
    else:
        d = res["homeprov_detection_second"]
        pub["arms"][cfg["arms"][0]] = {"flagged": d["raw_violation_hits"], "n": d["n"]}
    late = {"e_d_clo": "e_d_clo_late_row_check.json", "e_c_clo": "e_c_clo_late_row_check.json",
            "e_c_auth": "e_c_auth_late_row_check.json"}.get(run_id)
    if late:
        pa = json.load(open(os.path.join(OUT, late)))["per_arm"]
        for a in cfg["arms"]:
            pub["arms"][a].update(attributable=pa[a]["attributable"], ambiguous=pa[a]["late_row"])
    if run_id in ("e_ps_clo", "e_ps_auth"):
        s = json.load(open(os.path.join(OUT, "e_ps_detection_rescored.json")))["runs"][cfg["result"]]["second"]
        pub["arms"]["PS"].update(flagged=s["raw_hits"], attributable=s["attributable_to_swap"],
                                 ambiguous=s.get("late_row_ambiguous", 0))
    if run_id == "e_psr_clo":
        d = res["homeprov_detection_second"]
        pub["arms"]["PSR"].update(attributable=d["hits_consistent_with_detection"],
                                  ambiguous=d["raw_violation_hits"] - d["hits_consistent_with_detection"])
    return pub


def signed_lines(M, lines, pubkey_path, allow_unsigned=False):
    """E8 (A2, review BE8): with a published Ed25519 key, only monitor records whose signature verifies under it are
    used; a record that is unsigned, signed under another key or badly signed is left out and counted. allow_unsigned
    keeps unsigned records (every chain an evaluated run wrote is unsigned)."""
    pub = M.load_public_key(pubkey_path)
    fp = M.public_key_fingerprint(pub)
    keep, count = [], collections.Counter()
    for line in lines:
        try:
            p = (json.loads(line).get("payload") or {})
        except ValueError:
            keep.append(line)
            continue
        if p.get("observer") != "external-monitor":
            keep.append(line)
            continue
        st = M.verify_record_signature(p, pub, fp)
        count[st] += 1
        if st == "ok" or (st == "unsigned" and allow_unsigned):
            keep.append(line)
    return keep, {"pubkey_fp": fp, "allow_unsigned": bool(allow_unsigned),
                  **{k: count[k] for k in ("ok", "unsigned", "bad_signature", "wrong_key")}}


def run_one(run_id, src, scratch, sign_pubkey=None, allow_unsigned=False):
    cfg = RUNS[run_id]
    db, chain, inputs = src.checked(run_id)
    res = json.load(open(os.path.join(OUT, cfg["result"])))
    win = res["window"]
    t0, t1, tsnap = win["t_start"], win["t_end"], win["recorder_snapshot_at"]
    M = load_monitor(cfg["scheme"], scratch)
    W = dict(M.GRAN)
    # The chain itself: hash links (records written since 2026-10-07) or, for every chain an evaluated run wrote, the
    # unlinked v1 format, whose order and content rest on the anchor host (assumption A4).
    cc = chainverify.verify_chain(chainverify.read(chain))
    if not cc["ok"]:
        raise SystemExit(f"{run_id}: anchor chain fails its link check: {cc['problems'][:3]}")
    anchor_chain = {k: cc[k] for k in ("records", "link", "linked_records", "head", "integrity")}
    lines, sigs = chain_lines(chain), None
    if sign_pubkey:
        lines, sigs = signed_lines(M, lines, sign_pubkey, allow_unsigned)
    roots = anchored_roots(lines, t0, tsnap)
    tick = time.time()
    encs = sorted({a["encoding"] for a in roots.values()})
    if len(encs) != 1:
        raise SystemExit(f"{run_id}: chain holds node-hash encodings {encs}; expected exactly one")
    phi = M.commit(M.load(db, since=(int(t0 // 3600) - 1) * 3600.0), encoding=encs[0])
    verd = verify_window(phi, roots, W, t0, t1)
    del phi
    trials = [t for t in res["trials"] if not (t.get("err") or t.get("error"))]
    arms = {}
    for a in cfg["arms"]:
        ts = [t for t in trials if t.get("arm") == a]
        flagged = attributable = ambiguous = 0
        for t in ts:
            seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
            v = verd.get(("second", str(seg))) if seg is not None else None
            if not (v and v["violation"]):
                continue
            flagged += 1
            if v["delta_n"] is not None and v["delta_n"] > 0:
                ambiguous += 1
            else:
                attributable += 1
        arms[a] = {"n": len(ts), "flagged": flagged, "attributable": attributable, "ambiguous": ambiguous,
                   "flagged_ci": cp(flagged, len(ts)), "attributable_ci": cp(attributable, len(ts))}
        if cfg.get("late_row_not_computable"):
            # round 13c (internal review r1): print no late-row breakdown where the paper says it is not computable,
            # so the report cannot be read as a result; the flags and the benign floor are still recomputed.
            arms[a].update(attributable=None, ambiguous=None, attributable_ci=None,
                           late_row_breakdown="not computable on the later recorder copy (see note)")
    floor_trials = [t for t in trials if t.get("arm") in ("PS", "PSR")] if "homeprov_detection_second" in res else trials
    touched = touched_segments(floor_trials, ro_connect(db), W)["second"]
    segs = [s for (g, s) in verd if g == "second" and s not in touched]
    floor = [sum(1 for s in segs if verd[("second", s)]["violation"]), len(segs)]
    pub = published(run_id, cfg)
    checks = {"floor": floor == pub["floor"]}
    for a, r in arms.items():
        p = pub["arms"][a]
        checks[f"{a}.n"] = r["n"] == p["n"]
        checks[f"{a}.flagged"] = r["flagged"] == p["flagged"]
        if "attributable" in p and run_id != "e_d_auth":
            checks[f"{a}.attributable"] = r["attributable"] == p["attributable"]
            checks[f"{a}.ambiguous"] = r["ambiguous"] == p["ambiguous"]
    out_sig = {"signatures": sigs} if sigs is not None else {}
    return {**out_sig, "run": run_id, "scheme": cfg["scheme"], "node_hash_encoding": encs[0], "anchor_chain": anchor_chain,
            "inputs": inputs,
            "window": [t0, t1, tsnap],
            "anchored_second_segments_verified": sum(1 for (g, _s) in verd if g == "second"),
            "arms": arms, "benign_floor_second": floor, "published": pub, "checks": checks,
            "match": all(checks.values()), "seconds": round(time.time() - tick, 1), "note": cfg.get("note")}


def table_numbers(rows):
    """The numbers SP-TAB3 / SP-TAB-B print, as strings, for gate.py B9."""
    nums = set()
    for r in rows.values():
        nums |= {str(r["benign_floor_second"][0]), str(r["benign_floor_second"][1])}
        for a in r["arms"].values():
            for k in ("n", "flagged", "attributable", "ambiguous"):
                if a[k] is not None:
                    nums.add(str(a[k]))
            nums |= {f"{x:.3f}" for x in a["flagged_ci"] + (a["attributable_ci"] or [])}
    return sorted(nums)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--snapshots", default=None, help="the full verifier snapshot set (SHA256SUMS)")
    ap.add_argument("--extracts", default=None, help="per-run window extracts (EXTRACTS_SHA256SUMS); default: "
                                                    "reproduce/snapshots if present")
    ap.add_argument("--runs", default=",".join(RUNS))
    ap.add_argument("--out", default=os.path.join(REPO, "reproduce", "verify_all_report.json"))
    ap.add_argument("--sign-pubkey", default=None, help="the monitor's published Ed25519 public key (PEM): check every "
                    "signed record against it (E8); only records it verifies are used")
    ap.add_argument("--allow-unsigned", action="store_true", help="with --sign-pubkey, keep unsigned records (every "
                    "evaluated run's chain is unsigned)")
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit(f"refusing to overwrite {a.out}; pass --out for a new file")
    src = default_inputs(a.snapshots, a.extracts)
    print(f"inputs: {src.mode} in {src.base}", flush=True)
    rows = {}
    with tempfile.TemporaryDirectory() as scratch:
        for rid in [r for r in a.runs.split(",") if r]:
            print(f"verifying {rid} ...", flush=True)
            rows[rid] = run_one(rid, src, scratch, a.sign_pubkey, a.allow_unsigned)
            print(f"  {rid}: {'MATCH' if rows[rid]['match'] else 'MISMATCH'} "
                  + json.dumps({k: v for k, v in rows[rid]['arms'].items()}) + f" floor {rows[rid]['benign_floor_second']}", flush=True)
    not_rerun = {k: json.load(open(os.path.join(OUT, v)))["new_rule_floor"]["second"] for k, v in NOT_RERUN.items()}
    pooled_rerun = [sum(r["benign_floor_second"][0] for r in rows.values() if r["scheme"] != "wholerow"),
                    sum(r["benign_floor_second"][1] for r in rows.values() if r["scheme"] != "wholerow")]
    report = {"status": "ok" if rows and all(r["match"] for r in rows.values()) else "mismatch",
              "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "script_sha256": sha256_file(os.path.abspath(__file__)),
              "inputs_mode": src.mode,
              "monitor_sha256": sha256_file(os.path.join(REPO, "monitor", "monitor.py")),
              "python": sys.version.split()[0], "runs": rows,
              "pooled_floor_rerun_runs": pooled_rerun,
              "not_rerun_read_from_file": {k: [v["k"], v["n"]] for k, v in not_rerun.items()},
              "pooled_floor_nine_runs": [pooled_rerun[0] + sum(v["k"] for v in not_rerun.values()),
                                         pooled_rerun[1] + sum(v["n"] for v in not_rerun.values())],
              "floats": {"SP-TAB3": table_numbers(rows)},
              "not_regenerated": ["misattribution column: the logbook processor's verdict at run time, recorded by the harness",
                                  "e_c_write_time and e_d_other_principal_real: their verifier snapshots are not in the set"]}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=1, sort_keys=False)
    print(f"status {report['status']}; pooled floor (re-run runs) {pooled_rerun}; nine-run pool "
          f"{report['pooled_floor_nine_runs']}; report {a.out}")
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
