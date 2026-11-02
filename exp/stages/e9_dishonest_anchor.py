"""E9 item A7 (round 13, 2026-10-09): what a dishonest anchor host can make the verifier say, on the saved E8 chains.

The anchor host stores the chain, so it can drop, reorder, withhold, truncate or replay records, and write records of
its own. In E8 every monitor record is signed with an Ed25519 key that never left the monitor's volume, every record
carries the monitor's persisted poll counter, and the anchor is hash-linked with a head witness outside Docker's VM.
This script builds, for each E8 monitor (stable columns, closure) and each case below, the host's version of the saved
chain, RELINKED so that its own hash links verify (the strongest host: it rewrites at rest and recomputes every
prev_digest), and verifies it twice:
  * exp/stages/e7_verify.py, as E8 was scored (the monitor's published key, LATE_BOUND = GAP_S = 30 s, the arms window,
    the recorder snapshot time, the run's recorder copy and harness reports). Every trial second and every untouched
    second of the honest run's floor population gets an outcome: violation (flagged), unknown (a root it could be
    checked against is missing: root_unknown, or no known poll covers the second), or match (its anchored root
    reproduces, or it was sealed empty, and nothing flags it). A second that is not flagged while the minute or hour
    over it is an attributable violation is counted as violation_coarse_only.
  * testbed/anchord/chainverify.py against every head the run's witness accepted.
Cases:
  honest                   the saved chain as it is
  drop                     every record that carries the one-second root of a trial second
  drop_all_evidence        also every record carrying a minute or hour root over a trial second, or a keylog range
                           with a row first observed in a trial second
  withhold                 every record of a 15-minute span of the arms (t_start + 600 s to t_start + 1,500 s)
  truncate                 the tail from the middle of the arms
  reorder                  the arms' records in reverse order
  replay                   50 records of the arms appended again
  forge_unsigned           before every monitor record of the arms, an unsigned copy whose roots and keylog ranges are
                           recomputed from the CURRENT recorder (after the attacks): first write wins
  forge_unsigned_no_key    the same chain verified WITHOUT the monitor's key (what the signatures prevent)
  cross_monitor            the other E8 monitor's signed records interleaved
  alter_signed             in every record that carries a trial second's root, that root replaced after signing
  forged_marker            a PURGE marker the host tags with the operator's HMAC key (it holds it to check markers),
                           no operator signature, its cutoff after the arms; verified with an operator public key
  forged_marker_hmac_only  the same chain verified with the HMAC key alone (what the operator signature prevents)
Writes exp/out/e9_dishonest_anchor.json (never overwritten).

    python3 exp/stages/e9_dishonest_anchor.py [--run-dir DIR] [--out FILE]
"""
from __future__ import annotations

import argparse
import collections
import copy
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
sys.path.insert(0, os.path.join(REPO, "exp"))
import chainverify as CV  # noqa: E402
from rig import marker_issuer as MI  # noqa: E402

RUN_DIR = "<research-dir>/HOMEPROV-P13-exp/e8/e8_main"
MONITORS = (("stb", "stable", "clo"), ("clo", "closure", "stb"))
LATE_BOUND = GAP_S = 30.0                                  # E8's pre-registered parameters
ROOMS = ("porch", "hallway", "kitchen")
KEEP_S = 30 * 86400.0
CASE_DOC = {
    "honest": "the saved chain as it is",
    "drop": "every record that carries the one-second root of a trial second, removed",
    "drop_all_evidence": "also every record carrying a minute or hour root over a trial second, or a keylog range with "
                         "a row first observed in a trial second, removed",
    "withhold": "every record of a 15-minute span of the arms (t_start + 600 s to t_start + 1,500 s) held back",
    "truncate": "the tail from the middle of the arms cut",
    "reorder": "the arms' records in reverse order",
    "replay": "50 records of the arms appended again",
    "forge_unsigned": "before every monitor record of the arms, an unsigned copy whose roots and keylog ranges are "
                      "recomputed from the current recorder (after the attacks)",
    "forge_unsigned_no_key": "the forge_unsigned chain verified without the monitor's public key",
    "cross_monitor": "the other E8 monitor's signed records interleaved",
    "alter_signed": "in every record carrying a trial second's root, that root replaced after signing",
    "forged_marker": "a PURGE marker tagged with the operator's HMAC key (which the anchor host holds to check "
                     "markers), without the operator's signature, cutoff one hour after the arms; verified with an "
                     "operator public key",
    "forged_marker_hmac_only": "the forged_marker chain verified with the operator's HMAC key alone"}
CASES = tuple(CASE_DOC)


def load_verifier():
    spec = importlib.util.spec_from_file_location("e9a7_e7_verify", os.path.join(HERE, "e7_verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    return V


def sha(p):
    h = hashlib.sha256()
    with (gzip.open(p, "rb") if p.endswith(".gz") else open(p, "rb")) as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def relink(recs):
    """The host's chain: records renumbered and every prev_digest recomputed, so its own links verify."""
    out, prev = [], None
    for i, r in enumerate(recs, 1):
        r = dict(r, seq=i)
        if r.get("link") == "v2":
            r["prev_digest"] = CV.record_digest(prev.encode()) if prev is not None else CV.GENESIS
        line = json.dumps(r, sort_keys=True)
        out.append(line)
        prev = line
    return out


def is_monitor(r):
    return (r.get("payload") or {}).get("observer") == "external-monitor"


def first_seconds(p):
    """Seconds named as first-observed seconds by the record's keylog rows."""
    out = set()
    for es in (p.get("keylog") or {}).values():
        for e in es if isinstance(es, list) else [es]:
            for x in (e or {}).get("rows") or []:
                if len(x) > 2 and x[2] is not None:
                    out.add(str(x[2]))
    return out


def outcome(V, res, s):
    if s in res["_flagged"]:
        return "violation"
    if s in res["_unknown"] or s in res["_unobserved"]:
        return "unknown"
    if ("second", s) in res["roots"] or res["TL"].first_cover(int(s), int(s) + 1) is not None:
        return "violation_coarse_only" if s in res["_coarse"] else "match"
    return "unknown"


def annotate(res):
    res["_flagged"] = set(res["flagged_seconds"])
    res["_unknown"] = {x["seg"] for x in res["root_unknown_segments"] if x["gran"] == "second"}
    res["_unobserved"] = {x["second"] for x in res.get("unobserved_late_rows") or [] if x.get("second")}
    coarse = set()
    for f in res["flagged_segments"]:
        if f["gran"] in ("minute", "hour"):
            w = 60 if f["gran"] == "minute" else 3600
            coarse.add((f["gran"], int(f["seg"]) * w))
    res["_coarse_segs"] = coarse
    res["_coarse"] = _CoarseSet(coarse)
    return res


class _CoarseSet:
    def __init__(self, segs):
        self.segs = segs

    def __contains__(self, s):
        s = int(s)
        return ("minute", s - s % 60) in self.segs or ("hour", s - s % 3600) in self.segs


def forged_copy(V, M, db, groups, r):
    """An unsigned copy of monitor record r whose roots and keylog ranges are recomputed over the current recorder."""
    p = {k: v for k, v in r["payload"].items() if k not in ("sig", "sig_alg", "sig_fp")}
    p = copy.deepcopy(p)
    for g, segs in (p.get("sealed") or {}).items():
        for seg, e in segs.items():
            wm = e.get("wm") or p.get("wm")
            rows = [n for n in groups.get(g, {}).get(str(seg), []) if V.under(n, wm)]
            got = V.fold(M, rows, g, str(seg), p.get("encoding", "v2")) or {"acc": V.ZERO.hex(), "n": 0}
            e["acc"], e["n"] = got["acc"], got["n"]
    for t, es in (p.get("keylog") or {}).items():
        for i, e in enumerate(es):
            if not isinstance(e, dict) or int(e.get("to", 0)) <= int(e.get("from", 0)):
                continue
            new = M.keylog_entry(M.keylog_rows(db, t, int(e["from"]), int(e["to"])), int(e["from"]), int(e["to"]))
            if e.get("start"):
                new["start"] = True
            es[i] = new
    return {"seq": None, "recv_ts": r.get("recv_ts"), "link": r.get("link"), "payload": p}


def build(case, recs, other, trial_secs, t0, t1, V, M, db, groups, host_key):
    """The host's chain for one case (records, before relinking)."""
    in_arms = [r for r in recs if is_monitor(r) and t0 <= (r["payload"].get("ts") or 0) <= t1]
    arms_ids = {id(r) for r in in_arms}

    def carries_second(r):
        return bool(set((r["payload"].get("sealed") or {}).get("second", {})) & trial_secs)

    if case == "drop":
        return [r for r in recs if not (is_monitor(r) and carries_second(r))]
    if case == "drop_all_evidence":
        def evidence(r):
            p = r["payload"]
            if carries_second(r) or (first_seconds(p) & trial_secs):
                return True
            for g, w in (("minute", 60), ("hour", 3600)):
                for seg in (p.get("sealed") or {}).get(g, {}):
                    if any(int(seg) * w <= int(s) < (int(seg) + 1) * w for s in trial_secs):
                        return True
            return False
        return [r for r in recs if not (is_monitor(r) and evidence(r))]
    if case == "withhold":
        lo, hi = t0 + 600.0, t0 + 1500.0
        return [r for r in recs if not (is_monitor(r) and lo <= (r["payload"].get("ts") or 0) <= hi)]
    if case == "truncate":
        mid = t0 + (t1 - t0) / 2.0
        cut = next(i for i, r in enumerate(recs) if is_monitor(r) and (r["payload"].get("ts") or 0) >= mid)
        return recs[:cut]
    if case == "reorder":
        idx = [i for i, r in enumerate(recs) if id(r) in arms_ids]
        out = list(recs)
        for i, r in zip(idx, reversed([recs[i] for i in idx])):
            out[i] = r
        return out
    if case == "replay":
        return recs + in_arms[100:150]
    if case in ("forge_unsigned", "forge_unsigned_no_key"):
        out = []
        for r in recs:
            if id(r) in arms_ids and ((r["payload"].get("sealed") or {}) or r["payload"].get("keylog")):
                out.append(forged_copy(V, M, db, groups, r))
            out.append(r)
        return out
    if case == "cross_monitor":
        merged = sorted([(r.get("recv_ts") or 0, 0, i, r) for i, r in enumerate(recs)]
                        + [(r.get("recv_ts") or 0, 1, i, r) for i, r in enumerate(other) if is_monitor(r)])
        return [x[3] for x in merged]
    if case == "alter_signed":
        out = []
        for r in recs:
            if is_monitor(r) and carries_second(r):
                r = copy.deepcopy(r)
                for s, e in r["payload"]["sealed"]["second"].items():
                    if s in trial_secs:
                        e["acc"] = hashlib.sha256(b"host" + e["acc"].encode()).hexdigest()
            out.append(r)
        return out
    if case in ("forged_marker", "forged_marker_hmac_only"):
        sched = t1 + KEEP_S + 3600.0                         # cutoff an hour after the arms end
        m = MI.scoped_marker(sched, KEEP_S, issued_ts=sched - 120.0)
        mk = {"seq": None, "recv_ts": t1, "link": recs[0].get("link"), "payload": MI.marker_record(host_key, m)}
        cut = next(i for i, r in enumerate(recs) if is_monitor(r) and (r["payload"].get("ts") or 0) >= t1)
        return recs[:cut] + [mk] + recs[cut:]
    return recs


def summarize(V, res, trial_secs, untouched, honest=None):
    out = {"flagged_seconds": len(res["flagged_seconds"]), "root_unknown_second_segments": len(res["_unknown"]),
           "seconds_with_unobserved_late_rows": len(res["_unobserved"]),
           "signatures": {k: (len(v) if isinstance(v, list) else v) for k, v in res["signatures"].items()
                          if k in ("signed_ok", "unsigned", "bad_signature", "wrong_key", "excluded_from_verification",
                                   "checked")},
           "stall_kinds": dict(collections.Counter(s["kind"] for s in res["stalls"]))}
    for name, pop in (("trial_seconds", trial_secs), ("untouched_seconds", untouched)):
        oc = {s: outcome(V, res, s) for s in pop}
        out[name] = {"n": len(pop), "outcomes": dict(collections.Counter(oc.values()))}
        if honest is not None:
            tr = collections.Counter("%s->%s" % (honest["_oc"][name][s], oc[s]) for s in pop)
            out[name]["transitions_from_honest"] = dict(tr)
        res.setdefault("_oc", {})[name] = oc
    if res.get("purge"):
        out["purge"] = {k: res["purge"].get(k) for k in ("cutoffs", "excused") if k in res["purge"]}
        out["excused_violations"] = len(res.get("excused_violations") or [])
    if res.get("markers"):
        out["markers"] = res["markers"]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", default=RUN_DIR)
    ap.add_argument("--out", default=os.path.join(OUT, "e9_dishonest_anchor.json"))
    ap.add_argument("--cases", default=",".join(CASES))
    a = ap.parse_args()
    if os.path.exists(a.out):
        raise SystemExit("refusing to overwrite %s" % a.out)
    V = load_verifier()
    cases = a.cases.split(",")
    t0 = float(open(os.path.join(OUT, "e8_main_t_start")).read().strip())
    t1 = float(open(os.path.join(OUT, "e8_main_t_end")).read().strip())
    tsnap = float(open(os.path.join(a.run_dir, "snapshot_at")).read().strip())
    reports = [os.path.join(OUT, "e8_main_report_%s_%s.json" % (k, room)) for room in ROOMS for k in ("ec", "e7")]
    scratch = tempfile.mkdtemp(prefix="e9a7_")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    op_pub = os.path.join(scratch, "operator_pub.pem")          # an operator key the host does not hold
    with open(op_pub, "wb") as fh:
        fh.write(Ed25519PrivateKey.generate().public_key().public_bytes(ser.Encoding.PEM,
                                                                        ser.PublicFormat.SubjectPublicKeyInfo))
    host_key = hashlib.sha256(b"the operator HMAC key, as the anchor host holds it").digest()
    db0 = os.path.join(a.run_dir, "recorder.db")
    inputs = {"recorder": {"path": db0, "sha256": sha(db0)}, "reports": {os.path.basename(r): sha(r) for r in reports},
              "window": [t0, t1], "snapshot_at": tsnap}
    out = {"check": "e9_dishonest_anchor", "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"), "parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S, "keep_s_for_markers": KEEP_S},
        "code_sha256": {p: sha(os.path.join(REPO, p)) for p in (
            "exp/stages/e9_dishonest_anchor.py", "exp/stages/e7_verify.py", "monitor/monitor.py",
            "testbed/anchord/chainverify.py", "exp/rig/marker_issuer.py")},
        "inputs": inputs, "cases": {c: CASE_DOC[c] for c in cases}, "monitors": {}}
    chains, raw = {}, {}
    for m, scheme, _o in MONITORS:
        p = os.path.join(a.run_dir, "%s_chain.jsonl" % m)
        raw[m] = [line for line in open(p).read().splitlines() if line.strip()]
        chains[m] = [json.loads(line) for line in raw[m]]
        inputs["%s_chain" % m] = {"path": p, "sha256": sha(p), "records": len(chains[m])}
    for m, scheme, other in MONITORS:
        M = V.load_monitor(scheme, os.path.join(scratch, "mon_" + m))
        db = V._private_copy(db0, os.path.join(scratch))
        pub = os.path.join(a.run_dir, "keys", "%s_sign_pub.pem" % m)
        heads_p = os.path.join(a.run_dir, "witness_%s" % m, "heads.jsonl")
        heads = [json.loads(line) for line in open(heads_p) if line.strip()]
        inputs["%s_pubkey" % m] = {"path": pub, "sha256": sha(pub)}
        inputs["%s_witness_heads" % m] = {"path": heads_p, "sha256": sha(heads_p), "heads": len(heads)}
        trials = []
        for f in reports:
            trials += [t for t in json.load(open(f)).get("trials", []) if not (t.get("err") or t.get("error"))]
        touched, rule = V.touched_seconds(trials, db)
        del_secs, _del_rows = V.touched_by_deletions(trials)
        touched = set(touched) | del_secs
        trial_secs = {s for s in (V.trial_second(t) for t in trials) if s is not None}
        mo = {"trials": len(trials), "trial_seconds": len(trial_secs), "counting_rule": rule, "cases": {}}
        honest = None
        for case in cases:
            recs = build(case, chains[m], chains[other], trial_secs, t0, t1, V, M, db,
                         honest["groups"] if honest else None, host_key) if case != "honest" else chains[m]
            lines = relink(recs) if case != "honest" else raw[m]
            kw = {"sign_pubkey": None if case == "forge_unsigned_no_key" else pub}
            if case == "forged_marker":
                kw.update(operator_key=host_key, operator_pubkey=op_pub, purge_keep_s=KEEP_S)
            elif case == "forged_marker_hmac_only":
                kw.update(operator_key=host_key, purge_keep_s=KEEP_S)
            res = annotate(V.verify(M, db, lines, LATE_BOUND, GAP_S, scheme=scheme, t0=t0, t1=t1, tsnap=tsnap, **kw))
            if case == "honest":
                untouched = sorted({s for (g, s) in res["checked"] if g == "second" and s not in touched}, key=int)
                mo["untouched_anchored_seconds"] = len(untouched)
                honest = res
            data = ("\n".join(lines) + "\n").encode()
            cv = CV.verify_chain(data, witnessed_heads=heads)
            s_ = summarize(V, res, sorted(trial_secs, key=int), untouched, None if case == "honest" else honest)
            s_["records"] = len(lines)
            s_["chainverify_every_witnessed_head"] = {
                "ok": cv["ok"], "link": cv["link"],
                "records_after_the_last_witnessed_head": max(0, len(lines) - max(int(h["seq"]) for h in heads)),
                **{k: (len(v) if isinstance(v, list) else v) for k, v in cv["witnessed_heads"].items()}}
            mo["cases"][case] = s_
            print("%-3s %-24s trial %s  untouched %s  chainverify ok=%s" % (
                m, case, s_["trial_seconds"]["outcomes"], s_["untouched_seconds"]["outcomes"], cv["ok"]), flush=True)
        mo["property"] = {
            "trial_second_violation_to_match": {c: v["trial_seconds"].get("transitions_from_honest", {}).get(
                "violation->match", 0) for c, v in mo["cases"].items() if c != "honest"},
            "untouched_second_match_to_violation": {c: v["untouched_seconds"].get("transitions_from_honest", {}).get(
                "match->violation", 0) for c, v in mo["cases"].items() if c != "honest"}}
        out["monitors"][scheme] = mo
    with open(a.out, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    shutil.rmtree(scratch, ignore_errors=True)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
