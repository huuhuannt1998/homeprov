"""E8 (round 13), part C -- score one run of testbed/e8/run_e8.sh.

The authoritative per-record verification is exp/stages/e7_verify.py (watermark, sealed-through, keylog, LATE_BOUND,
GAP_S, escrow recovery, the earlier rule's verdict per segment, the benign floor with the paper's counting rule, and,
with --sign-pubkey, every monitor record's Ed25519 signature). This file runs it, unchanged, once per MONITOR and
WINDOW, with the pre-registered LATE_BOUND = 30 s and GAP_S = 30 s, and adds what e7_verify does not cover:

  monitors  stable columns (the evaluated scheme; chain stb_chain.jsonl) and the closure (alongside; clo_chain.jsonl);
  windows   main   [<tag>_t_start, <tag>_t_end]: arms PU, PI, PSR, P (homeprov_ec) and INS-L, INS-M, BD-S (homeprov_e7);
            base   [<tag>_base_t_start, <tag>_base_t_end]: lab rate, no trials (benign floor and cost only);
            stress [<tag>_stress_t_start, <tag>_stress_t_end]: the second motion publisher on, a PU arm;
  per arm   e7_detected k of n with the exact (Clopper-Pearson) 95% interval, the earlier rule's flagged / attributable /
            ambiguous counts (both from e7_verify), and from the harness reports: trials requested, valid, with an
            error (each listed), renderer-confirmed misattribution, principal moved;
  floors    e7_verify's benign floor per monitor and window (one-second, minute, hour); its list of untouched flagged
            (suspect) seconds covers the whole chain, so the scorer restricts it to the window (scope_suspects) and adds
            the keylog suspect and "likely" row counts;
  cost      each monitor's per-poll copy, load, commit, append and total milliseconds (median, p90, max) per window,
            from its HOMEPROV_COST_LOG, and the seal delay (end of a one-second segment to the anchor's receipt of its
            root) per window, from its chain;
  signatures e7_verify's check of every record against that monitor's published key (always --sign-pubkey, never
            --allow-unsigned: only records whose signature verifies are used; unsigned_excluded, bad and wrong-key counts,
            and the root_unknown segments a missing signed poll leaves), a cross-check that the other monitor's key
            rejects every record (wrong_key), and the key fingerprints against the run's configuration log;
  witness   testbed/anchord/chainverify.py on each chain: links, the witness's final head, EVERY witnessed head; forks;
            controls on copies (a truncated tail; a rewritten, relinked record, alone and with the old latest-head-only
            check given the doctored head; an unrelinked rewrite);
  probes    the hub's probes (records and markers untagged / forged, the witness port) and the operator-key probe
            (marker under the append key refused, record under the operator key refused, operator marker accepted,
            reply tags verified), read from the configuration log; reply-tag failures and failed appends from the
            monitors' own logs; anchor refusals by reason;
  rates     recorder write rate per window (rows of monitor.load(), as exp/sp2027/r13_write_rate.py counts them) and
            its ratio to the baseline window and to the lab rate in exp/out/r13_write_rate.json.

    E8_SP=<run dir> python3 exp/stages/e8_score.py --tag e8_main --rooms porch hallway kitchen --stress-rooms porch
    ... --verify-only [--restore-out DB]   only run e7_verify (the run script renders the restored copy in between)

e7_verify outputs are cached in the run directory (<m>_verify_<window>.json) and reused. Writes exp/out/<tag>_score.json
and copies the verify outputs to exp/out/<tag>_<monitor>_verify_<window>.json. Never overwrites (unless --overwrite).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import glob
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.environ.get("E8_OUT") or os.path.join(ROOT, "exp", "out")     # E8_OUT: a dry run keeps its files out of exp/out
E7_VERIFY = os.path.join(HERE, "e7_verify.py")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "exp"))
sys.path.insert(0, os.path.join(ROOT, "testbed", "anchord"))
import e7_verify as EV                       # noqa: E402  (load_monitor, cp: the verifier's own helpers)
import chainverify as CV                     # noqa: E402

LATE_BOUND = float(os.environ.get("E8_LATE_BOUND", "30"))
GAP_S = float(os.environ.get("E8_GAP_S", "30"))
MONITORS = (("stable", "stb", "stable"), ("closure", "clo", "closure"))     # (name, run-dir prefix, scheme)
WINDOWS = ("main", "base", "stress")
WFILES = {"main": ("t_start", "t_end"), "base": ("base_t_start", "base_t_end"),
          "stress": ("stress_t_start", "stress_t_end")}
CTX_FIELDS = ("renderer_confirmed_misattribution", "principal_moved")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if p and os.path.exists(p) else None


def q(xs, p):
    """Linear interpolation between order statistics (as e7_score and r13_write_rate)."""
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)


def dist(xs):
    return {"n": len(xs), "median": q(xs, 0.5), "p90": q(xs, 0.9), "max": round(max(xs), 3) if xs else None}


# ------------------------------------------------------------------------------------------------ inputs
def windows(tag):
    w = {}
    for name, (a, b) in WFILES.items():
        fa, fb = os.path.join(OUT, "%s_%s" % (tag, a)), os.path.join(OUT, "%s_%s" % (tag, b))
        if os.path.exists(fa) and os.path.exists(fb):
            w[name] = (float(open(fa).read().strip()), float(open(fb).read().strip()))
    return w


def report_files(tag, rooms, stress_rooms):
    main = [f for room in rooms for f in (os.path.join(OUT, "%s_report_ec_%s.json" % (tag, room)),
                                          os.path.join(OUT, "%s_report_e7_%s.json" % (tag, room))) if os.path.exists(f)]
    stress = [f for room in stress_rooms
              for f in (os.path.join(OUT, "%s_stress_report_%s.json" % (tag, room)),) if os.path.exists(f)]
    return {"main": main, "base": [], "stress": stress}


def load_trials(files):
    out = []
    for f in files:
        d = json.load(open(f))
        room = d.get("room") or os.path.basename(f).rsplit("_", 1)[-1].split(".")[0]
        for t in d.get("trials", []):
            out.append(dict(t, room=room, _file=os.path.basename(f)))
    return out


# ------------------------------------------------------------------------------------------------ e7_verify
def verify_job(sp, m, scheme, window, w, trials, tsnap, restore_out=None):
    dst = os.path.join(sp, "%s_verify_%s.json" % (m, window))
    if os.path.exists(dst):
        try:
            return window, m, json.load(open(dst)), True
        except ValueError:
            os.rename(dst, dst + ".bad.%d" % int(time.time()))
    cmd = [sys.executable, E7_VERIFY, "verify", "--chain", os.path.join(sp, "%s_chain.jsonl" % m),
           "--db", os.path.join(sp, "recorder.db"), "--late-bound", str(LATE_BOUND), "--gap-s", str(GAP_S),
           "--snapshot-at", str(tsnap), "--window", str(w[0]), str(w[1]), "--scheme", scheme, "--out", dst]
    pub = os.path.join(sp, "keys", "%s_sign_pub.pem" % m)
    if os.path.exists(pub):
        cmd += ["--sign-pubkey", pub]
    elif os.environ.get("E8_OFFLINE_UNSIGNED") != "1":      # only for offline tests on chains written before signatures
        return window, m, {"error": "no published public key %s: an E8 chain is verified only with --sign-pubkey" % pub,
                           "rc": None, "stderr": ""}, False
    esc = os.path.join(sp, "escrow_%s" % m, "escrow.jsonl")
    if os.path.exists(esc) and os.path.getsize(esc) > 0:
        cmd += ["--escrow", esc]
    if restore_out:
        cmd += ["--restore-out", restore_out]
    if trials:
        cmd += ["--trials", *trials]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(dst):
        return window, m, {"error": "e7_verify failed", "rc": r.returncode, "stderr": r.stderr[-3000:],
                           "cmd": " ".join(cmd)}, False
    return window, m, json.load(open(dst)), False


def run_verifies(sp, w, files, tsnap, restore_out=None, jobs=3):
    res = collections.defaultdict(dict)
    todo = []
    for name, m, scheme in MONITORS:
        for window in WINDOWS:
            if window not in w:
                continue
            ro = restore_out if (restore_out and scheme == "closure" and window == "main") else None
            todo.append((sp, m, scheme, window, w[window], files[window], tsnap, ro))
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        for window, m, out, cached in ex.map(lambda a: verify_job(*a), todo):
            res[m][window] = out
            print("  e7_verify %-3s %-6s %s" % (m, window, "cached" if cached else
                                                 ("ERROR " + out.get("stderr", "")[-300:] if "error" in out else "ok")),
                  flush=True)
    return res


# ------------------------------------------------------------------------------------------------ additions
def report_context(trials):
    """Per arm, from the harness reports: requested, valid, errors, attack-success fields."""
    by = collections.defaultdict(lambda: {"n_records": 0, "n_valid": 0, "errors": [],
                                          **{f: 0 for f in CTX_FIELDS}})
    for t in trials:
        a = by[t.get("arm")]
        a["n_records"] += 1
        err = t.get("err") or t.get("error")
        if err:
            a["errors"].append({"room": t.get("room"), "trial": t.get("trial"), "err": str(err)[:200]})
            continue
        a["n_valid"] += 1
        for f in CTX_FIELDS:
            a[f] += bool(t.get(f))
        if t.get("arm") in ("INS-L", "INS-M"):
            a.setdefault("K_inserted", []).append(t.get("K_inserted"))
        if t.get("arm") == "BD-S" and t.get("row_age_s") is not None:
            a.setdefault("row_age_s", []).append(t.get("row_age_s"))
    for a in by.values():
        if "K_inserted" in a:
            ks = [k for k in a["K_inserted"] if k is not None]
            a["K_inserted"] = {"min": min(ks) if ks else None, "max": max(ks) if ks else None}
        if "row_age_s" in a:
            a["row_age_s"] = {"min": min(a["row_age_s"]), "max": max(a["row_age_s"])}
        a["note"] = ("renderer_confirmed_misattribution and principal_moved are the harness's own attack-success "
                     "fields (homeprov_ec / homeprov_e7); for PSR the former equals principal_moved, which a "
                     "service-call unlock does not move (E7_RUN_NOTES.md item 8)")
    return dict(by)


def cost_by_window(path, w):
    if not os.path.exists(path):
        return {"available": False}
    rows = []
    for line in open(path, errors="replace"):
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    out = {"available": True, "n_polls_total": len(rows)}
    for name, (a, b) in w.items():
        sel = [r for r in rows if r.get("ts") is not None and a <= float(r["ts"]) <= b]
        cols = collections.defaultdict(list)
        for r in sel:
            c, l, m, ap = (r.get("copy_ms") or 0), (r.get("load_ms") or 0), (r.get("commit_ms") or 0), r.get("append_ms")
            cols["copy_ms"].append(c); cols["load_ms"].append(l); cols["commit_ms"].append(m)
            if ap is not None:
                cols["append_ms"].append(ap)
            cols["total_ms"].append(c + l + m + (ap or 0))
            if r.get("n_nodes") is not None:
                cols["n_nodes"].append(r["n_nodes"])
        out[name] = {"n_polls": len(sel), "failed_appends": sum(1 for r in sel if r.get("ok") is False),
                     "per_poll_ms": {k: dist(v) for k, v in cols.items() if k != "n_nodes"},
                     "rows_loaded_per_poll": dist(cols["n_nodes"]) if cols["n_nodes"] else None}
    return out


def read_chain(path):
    recs = []
    for line in open(path):
        if line.strip():
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    return recs


def seal_delay(recs, w):
    """End of each one-second segment to the anchor's receipt of the first record carrying its root."""
    first = {}
    for r in recs:
        p = r.get("payload") or {}
        if p.get("observer") != "external-monitor":
            continue
        secs = ((p.get("sealed") or {}).get("second") or {})
        for seg in secs:
            if seg not in first:
                first[seg] = r.get("recv_ts")
    out = {}
    for name, (a, b) in w.items():
        d = [float(t) - (int(s) + 1) for s, t in first.items() if t is not None and a <= int(s) < b]
        out[name] = dist(d)
    return out


def marker_records(recs):
    return [{"seq": r.get("seq"), "marker": (r.get("payload") or {}).get("marker"),
             "probe": (r.get("payload") or {}).get("probe")} for r in recs if (r.get("payload") or {}).get("marker")]


def cross_key(sp, m_chain, m_key):
    """Every monitor record of one chain checked against the OTHER monitor's key: all must be wrong_key."""
    pub = os.path.join(sp, "keys", "%s_sign_pub.pem" % m_key)
    if not os.path.exists(pub):
        return None
    scratch = tempfile.mkdtemp(prefix="e8s_")
    try:
        M = EV.load_monitor("closure", scratch)
        k = M.load_public_key(pub)
        fp = M.public_key_fingerprint(k)
        c = collections.Counter()
        for r in read_chain(os.path.join(sp, "%s_chain.jsonl" % m_chain)):
            p = r.get("payload") or {}
            if p.get("observer") == "external-monitor":
                c[M.verify_record_signature(p, k, fp)] += 1
        return {"chain": m_chain, "key_of": m_key, "fingerprint": fp, **dict(c)}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def key_fingerprints(sp, meta):
    out = {}
    scratch = tempfile.mkdtemp(prefix="e8s_")
    try:
        M = EV.load_monitor("closure", scratch)
        for _n, m, _s in MONITORS:
            pub = os.path.join(sp, "keys", "%s_sign_pub.pem" % m)
            if os.path.exists(pub):
                fp = M.public_key_fingerprint(M.load_public_key(pub))
                logged = next((l.split("fingerprint (sha256 of the raw 32-byte Ed25519 key) ", 1)[1].split(";")[0]
                               for l in meta if l.split(" ", 1)[-1].startswith("%s: signing public key" % m)), None)
                out[m] = {"fingerprint": fp, "matches_configuration_log": fp == logged,
                          "public_key_pem": open(pub).read()}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return out


def witness_checks(sp, m):
    chain_p = os.path.join(sp, "%s_chain.jsonl" % m)
    wdir = os.path.join(sp, "witness_%s" % m)
    heads_p = os.path.join(wdir, "heads.jsonl")
    if not (os.path.exists(chain_p) and os.path.exists(heads_p)):
        return {"available": False}
    data = open(chain_p, "rb").read()
    heads = CV.read_heads(open(heads_p, "rb").read())
    final = None
    fp = os.path.join(wdir, "head_final.json")
    if os.path.exists(fp) and os.path.getsize(fp):
        try:
            final = json.load(open(fp))
        except ValueError:
            final = None
    res = CV.verify_chain(data, external_head=final, witnessed_heads=heads)
    forks = [json.loads(l) for l in open(os.path.join(wdir, "forks.jsonl"))] \
        if os.path.exists(os.path.join(wdir, "forks.jsonl")) else []
    lines = [l for l in data.split(b"\n") if l.strip()]
    seqs = {int(h["seq"]) for h in heads}
    out = {"available": True, "records": len(lines), "link": res.get("link"), "ok": res.get("ok"),
           "problems": res.get("problems")[:20], "witnessed_heads": res.get("witnessed_heads"),
           "final_witness_head": final, "chain_head": res.get("head"),
           "final_head_equals_chain_head": bool(final and final.get("seq") == res["head"]["seq"]
                                                and final.get("head_digest") == res["head"]["head_digest"]),
           "records_never_witnessed": len([i for i in range(1, len(lines) + 1) if i not in seqs]),
           "forks_logged": len(forks), "integrity": res.get("integrity"),
           "other_witness_files": sorted(os.path.basename(x) for x in glob.glob(os.path.join(wdir, "*"))
                                         if os.path.basename(x) not in ("heads.jsonl", "forks.jsonl"))}
    out["controls"] = witness_controls(lines, heads, final)
    return out


def _digest(line):
    return CV.record_digest(line)


def witness_controls(lines, heads, final):
    """Copies of the saved chain, doctored the ways the anchor host could, checked by chainverify."""
    if len(lines) < 10 or not heads:
        return {"skipped": "chain too short"}
    n = len(lines)
    latest = final or {"seq": max(int(h["seq"]) for h in heads),
                       "head_digest": {int(h["seq"]): h["head_digest"] for h in heads}[max(int(h["seq"]) for h in heads)]}
    out = {}
    # 1. truncated tail (5 records)
    trunc = b"\n".join(lines[:-5]) + b"\n"
    r1 = CV.verify_chain(trunc, external_head=latest)
    r1b = CV.verify_chain(trunc, witnessed_heads=heads)
    out["truncated_tail"] = {"alone_ok": CV.verify_chain(trunc)["ok"], "vs_latest_head_ok": r1["ok"],
                             "vs_every_witnessed_head_ok": r1b["ok"]}
    # 2. rewrite record i (middle), relink i+1..n: the reviewer's attack, with the doctored head handed to a check that
    #    reads the latest head only (what a witness that accepted any non-regressing head would hold)
    i = n // 2
    recs = [json.loads(l) for l in lines]
    recs[i - 1] = dict(recs[i - 1], payload=dict(recs[i - 1].get("payload") or {}, e8_control_rewrite=True))
    new = list(lines[:i - 1])                     # the untouched prefix, byte for byte
    prev = _digest(new[-1]) if new else CV.GENESIS
    for r in recs[i - 1:]:
        if r.get("link") == "v2":
            r = dict(r, prev_digest=prev)
        b = json.dumps(r, sort_keys=True).encode()
        new.append(b)
        prev = _digest(b)
    doctored = b"\n".join(new) + b"\n"
    doctored_head = {"seq": n, "head_digest": _digest(new[-1])}
    heads_doctored = [h for h in heads if int(h["seq"]) != n] + [doctored_head]
    out["relinked_rewrite"] = {
        "rewritten_record": i,
        "alone_ok": CV.verify_chain(doctored)["ok"],
        "vs_true_latest_head_ok": CV.verify_chain(doctored, external_head=latest)["ok"],
        "vs_doctored_latest_head_only_ok": CV.verify_chain(doctored, external_head=doctored_head)["ok"],
        "vs_every_witnessed_head_with_doctored_latest_ok": CV.verify_chain(doctored, witnessed_heads=heads_doctored)["ok"],
        "expected": "alone and against a doctored latest head: passes (the gap); against every witnessed head: fails"}
    # 3. rewrite without relinking
    unl = list(lines)
    unl[i - 1] = json.dumps(recs[i - 1], sort_keys=True).encode()
    out["unrelinked_rewrite"] = {"alone_ok": CV.verify_chain(b"\n".join(unl) + b"\n")["ok"]}
    return out


def probes(meta):
    def grab(prefix):
        for l in meta:
            body = l.split(" ", 1)[-1]
            if body.startswith(prefix):
                try:
                    return json.loads(body[len(prefix):].strip())
                except ValueError:
                    return {"unparsed": body[len(prefix):][:500]}
        return None
    hub = grab("probe_from_hub:")
    op = grab("operator_probe:")
    exp = {"hub": None, "operator": None}
    if isinstance(hub, dict):
        exp["hub"] = all(hub.get(a, {}).get(k) == 401 for a in ("anchor-stb", "anchor-clo")
                         for k in ("record_untagged", "record_forged", "marker_untagged", "marker_forged")) \
            and all(not isinstance(v, int) for v in (hub.get("witness_from_hub") or {}).values())
    if isinstance(op, dict):
        def chk(a):
            x = op.get(a) or {}
            return ((x.get("marker_with_append_key") or {}).get("status") == 403
                    and (x.get("record_with_operator_key") or {}).get("status") == 403
                    and (x.get("marker_with_operator_key") or {}).get("status") == 200
                    and all((x.get(k) or {}).get("reply_tag_ok") for k in
                            ("marker_with_append_key", "record_with_operator_key", "marker_with_operator_key")))
        exp["operator"] = all(chk(a) for a in ("anchor-stb", "anchor-clo"))
    return {"from_hub": hub, "operator": op, "as_expected": exp,
            "expected": {"from_hub": "401 for untagged and forged records and markers on both anchors; no route to "
                                     "either witness (an error, not an HTTP status)",
                         "operator": "403 for a marker under the append key and for a record under the operator key, "
                                     "200 for the operator-key marker, every reply tag valid"}}


def monitor_log_counts(path):
    if not os.path.exists(path):
        return None
    c = collections.Counter()
    for line in open(path, errors="replace"):
        if '"alarm"' in line:
            try:
                d = json.loads(line)
                c["alarm:" + str(d.get("alarm"))] += 1
                if "reply_tag" in json.dumps(d.get("anchor")):
                    c["reply_tag_failures"] += 1
            except ValueError:
                c["alarm:unparsed"] += 1
        elif "reply_tag_" in line:
            c["reply_tag_mentions"] += 1
    return dict(c)


def refusals(path):
    if not os.path.exists(path):
        return None
    c = collections.Counter()
    for line in open(path):
        if line.strip():
            try:
                c[json.loads(line).get("reason")] += 1
            except ValueError:
                c["unparsed"] += 1
    return dict(c)


def write_rates(sp, w):
    """Rows of monitor.load() (closure loader: states joined to states_meta, events joined to event_types) per window."""
    db = os.path.join(sp, "recorder.db")
    if not os.path.exists(db) or not w:
        return {"available": False}
    scratch = tempfile.mkdtemp(prefix="e8r_")
    try:
        M = EV.load_monitor("closure", scratch)
        cpy = EV._private_copy(db, scratch)
        lo = min(a for a, _ in w.values())
        nodes = M.load(cpy, since=(int(lo // 3600) - 1) * 3600.0)
        out = {}
        for name, (a, b) in w.items():
            sel = [n for n in nodes if a <= n[0] < b]
            minutes = (b - a) / 60.0
            st = sum(1 for n in sel if str(n[1]).startswith("s:"))
            ev = len(sel) - st
            per_sec = collections.Counter(int(n[0]) for n in sel)
            secs = int(b) - int(a)
            out[name] = {"minutes": round(minutes, 3), "rows": len(sel), "state_rows": st, "event_rows": ev,
                         "rows_per_minute": round(len(sel) / minutes, 2) if minutes else None,
                         "state_rows_per_minute": round(st / minutes, 2) if minutes else None,
                         "event_rows_per_minute": round(ev / minutes, 2) if minutes else None,
                         "seconds_with_a_row": {"k": len(per_sec), "n": secs,
                                                "share": round(len(per_sec) / secs, 4) if secs else None},
                         "rows_per_nonempty_second": dist(list(per_sec.values()))}
        lab = None
        try:
            lab = json.load(open(os.path.join(ROOT, "exp", "out", "r13_write_rate.json")))["pooled_single_host_real_deployment"][
                "rows_per_minute"]
        except Exception:                                      # noqa: BLE001
            pass
        ratios = {"lab_rows_per_minute_r13_write_rate_json": lab}
        if "stress" in out and "base" in out and out["base"]["rows_per_minute"]:
            ratios["stress_over_base"] = round(out["stress"]["rows_per_minute"] / out["base"]["rows_per_minute"], 3)
        if "stress" in out and lab:
            ratios["stress_over_lab"] = round(out["stress"]["rows_per_minute"] / lab, 3)
        if "base" in out and lab:
            ratios["base_over_lab"] = round(out["base"]["rows_per_minute"] / lab, 3)
        out["ratios"] = ratios
        return out
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def stress_publisher(sp):
    for f in [os.path.join(sp, "stress_publisher.log")] + glob.glob(os.path.join(sp, "log_*-stress.txt")):
        if not os.path.exists(f):
            continue
        last = None
        for line in open(f, errors="replace"):
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                    if d.get("stress") in ("start", "stop"):
                        last = dict(last or {}, **{d["stress"]: d})
                except ValueError:
                    pass
        return last
    return None


def recovery_render(sp):
    raw = os.path.join(sp, "recovery_render_raw.json")
    if not os.path.exists(raw):
        return {"available": False}
    tr = [t for t in json.load(open(raw)).get("trials", []) if t.get("arm") == "RENDER"]
    by = collections.defaultdict(lambda: {"n": 0, "true_author_shown": 0})
    for t in tr:
        by[t.get("arm_of_trial")]["n"] += 1
        by[t.get("arm_of_trial")]["true_author_shown"] += bool(t.get("true_author_shown"))
    return {"available": True, "n_trials": len(tr), "true_author_recovered": sum(bool(t.get("true_author_shown"))
                                                                                  for t in tr), "per_arm": dict(by)}


def window_touched(files, db):
    """The touched seconds e7_verify used for a window: its counting rule over the window's trials plus the trials' own
    deleted events (e7_verify.run(), same functions, same order)."""
    trials = []
    for f in files:
        trials += [t for t in json.load(open(f)).get("trials", []) if not (t.get("err") or t.get("error"))]
    if not trials:
        return set()
    touched, _rule = EV.touched_seconds(trials, db)
    del_secs, _rows = EV.touched_by_deletions(trials)
    return set(touched) | del_secs


def scope_suspects(v, w, touched):
    """benign_floor.untouched_flagged_seconds restricted to the scored window (scorer fix, 2026-10-09).

    e7_verify.benign_floor() takes every flagged second of the WHOLE chain (res["flagged_seconds"], keylog seconds
    included), not only the window's, so a window's list held the other windows' suspects (base: 1,598 listed against
    124 untouched anchored seconds, none inside the base window). Here the list is recomputed from the same verify
    output with the window rule e7_verify uses for second segments (t0 - 1 <= s <= t1 + 1) and the same touched set and
    near-attack rule; the counts of keylog suspect rows and of "likely" rows (ranked by the hash prefixes: changed,
    added, removed) whose current or first-observed second is among the window's suspect seconds are added."""
    bf = v.get("benign_floor") or {}
    orig = bf.get("untouched_flagged_seconds") or {}
    t0, t1 = w
    inwin = lambda s: s is not None and t0 - 1 <= int(s) <= t1 + 1
    allf = [s for s in v.get("flagged_seconds") or [] if s not in touched]
    scoped = [s for s in allf if inwin(s)]
    by_range = [set(kv["seconds"]) for kv in v.get("keylog_violations") or []]
    other = ({x["seg"] for x in v.get("violations") or [] if x["gran"] == "second" and x["attributable"]}
             | {r["second"] for r in v.get("attributable_rows") or [] if r.get("second") is not None}
             | {s_ for x in v.get("violations") or [] for s_ in x.get("localized_seconds", [])})
    near = [s for s in scoped if s not in other and any(s in r_ and r_ & touched for r_ in by_range)]
    sset = set(scoped)
    hit = lambda r: r.get("second") in sset or r.get("first_observed_second") in sset
    sus = {x["key"] for kv in v.get("keylog_violations") or [] for x in kv.get("suspects") or [] if hit(x)}
    lik = {x["key"] for kv in v.get("keylog_violations") or [] for x in kv.get("likely") or [] if hit(x)}
    n_unt = bf.get("untouched_anchored_seconds")
    return {"n": len(scoped), "seconds": scoped[:500], "of_untouched_anchored_seconds": n_unt,
            "share_of_untouched_anchored_seconds": round(len(scoped) / n_unt, 4) if n_unt else None,
            "via_a_key_range_that_holds_a_touched_second": {"n": len(near), "seconds": near[:500]},
            "keylog_suspect_rows": len(sus), "keylog_likely_rows": len(lik),
            "scope": "second s with t_start - 1 <= s <= t_end + 1 (e7_verify's window rule for second segments)",
            "e7_verify_unscoped": {"n": orig.get("n"), "n_recomputed_here": len(allf),
                                   "via_a_key_range_that_holds_a_touched_second_listed":
                                       len(orig.get("via_a_key_range_that_holds_a_touched_second") or [])}}


def summarize_verify(v, scoped=None):
    if not isinstance(v, dict) or "error" in v:
        return {"verify_error": v.get("error") if isinstance(v, dict) else "missing",
                "stderr_tail": (v or {}).get("stderr", "")[-800:]}
    stalls = v.get("stalls") or []
    sg = v.get("signatures") or {}
    ru = v.get("root_unknown_segments") or []
    bf = v.get("benign_floor")
    if scoped is not None and isinstance(bf, dict):
        bf = dict(bf, untouched_flagged_seconds=scoped)
    return {"arms": v.get("arms"), "benign_floor": bf,
            "signature_counts": {"checked": sg.get("checked"), "pubkey_fp": sg.get("pubkey_fp"),
                                 "signed_ok": sg.get("signed_ok"),
                                 "unsigned_excluded": len(sg.get("unsigned_excluded") or []),
                                 "bad_signature": len(sg.get("bad_signature") or []),
                                 "wrong_key": len(sg.get("wrong_key") or []),
                                 "allow_unsigned": sg.get("allow_unsigned")},
            "root_unknown_segments": {"n": len(ru), "by_granularity": dict(collections.Counter(x.get("gran") for x in ru)),
                                      "first": ru[:20]},
            "benign_late_rows": len(v.get("benign_late_rows") or []),
            "benign_late_max_lower_bound_s": v.get("benign_late_max_lower_bound_s"),
            "intervals_by_kind": dict(collections.Counter(s.get("kind") for s in stalls)),
            "intervals": stalls[:50], "chain": v.get("chain"),
            "recovery": v.get("recovery"), "keylog_violations": len(v.get("keylog_violations") or []),
            "malformed_rows": len(v.get("malformed_rows") or []), "params": v.get("params")}


def rescore_check(orig_path, result):
    """Assert that a re-score changes nothing but benign_floor.untouched_flagged_seconds, and say so in the output."""
    orig = json.load(open(orig_path))
    for name in result["monitors"]:
        for win, s in result["monitors"][name]["by_window"].items():
            o = orig["monitors"][name]["by_window"][win]
            assert s.get("arms") == o.get("arms"), (name, win, "arms differ")
            nb = {k: v for k, v in (s.get("benign_floor") or {}).items() if k != "untouched_flagged_seconds"}
            ob = {k: v for k, v in (o.get("benign_floor") or {}).items() if k != "untouched_flagged_seconds"}
            assert nb == ob, (name, win, "benign floor fields differ")
            for k in s:
                if k != "benign_floor":
                    assert s[k] == o.get(k), (name, win, k, "differs")
    same = {k: result[k] == orig.get(k) for k in result if k not in ("monitors", "generated_at", "code_sha256")}
    same["monitors_outside_by_window"] = all(
        {k: v for k, v in result["monitors"][n].items() if k != "by_window"}
        == {k: v for k, v in orig["monitors"][n].items() if k != "by_window"} for n in result["monitors"])
    return {"of": os.path.relpath(orig_path, ROOT), "of_sha256": sha(orig_path),
            "what_changed_in_the_scorer": (
                "exp/stages/e8_score.py now restricts benign_floor.untouched_flagged_seconds to the scored window: "
                "e7_verify.benign_floor() lists every untouched flagged second of the whole chain, so each window "
                "reported the other windows' suspect seconds. The scorer recomputes the list from the same verify output "
                "(flagged_seconds, keylog_violations, violations, attributable_rows) with e7_verify's window rule for "
                "second segments and the same touched set; it reports n, the subset via a key range that holds a touched "
                "second, the share of the window's untouched anchored seconds, the keylog suspect rows and the 'likely' "
                "(prefix-ranked) rows in those seconds, and keeps e7_verify's unscoped n under e7_verify_unscoped. "
                "The e7_verify outputs are the cached ones of the run (unchanged); nothing was re-run on the deployment."),
            "detection_and_floor_fields_unchanged": True,
            "asserted": "per monitor and window: arms, every benign_floor field except untouched_flagged_seconds, and "
                        "every other by_window field are identical to the original file",
            "other_top_level_fields_identical": same,
            "scorer_sha256": sha(os.path.abspath(__file__))}


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--run-dir", default=os.environ.get("E8_SP", ""))
    ap.add_argument("--rooms", nargs="*", default=["porch", "hallway", "kitchen"])
    ap.add_argument("--stress-rooms", nargs="*", default=["porch"])
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--restore-out", default=None)
    ap.add_argument("--jobs", type=int, default=int(os.environ.get("E8_VERIFY_JOBS", "3")))
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--out-name", default="%s_score.json",
                    help="output file name under exp/out (%%s = tag); e.g. %%s_score_rescored.json")
    ap.add_argument("--rescore-of", default=None,
                    help="an earlier score of the same run: assert that detection and floor fields are unchanged and "
                         "record what changed")
    a = ap.parse_args()
    sp, tag = a.run_dir, a.tag
    if not sp or not os.path.isdir(sp):
        raise SystemExit("run directory missing (E8_SP or --run-dir)")
    dst = os.path.join(OUT, a.out_name % tag)
    if os.path.exists(dst) and not a.overwrite and not a.verify_only:
        raise SystemExit("REFUSING: %s exists" % dst)
    w = windows(tag)
    if not w:
        raise SystemExit("no window files exp/out/%s_*t_start / *t_end" % tag)
    snap_f = os.path.join(sp, "snapshot_at")
    tsnap = float(open(snap_f).read().strip()) if os.path.exists(snap_f) else os.path.getmtime(
        os.path.join(sp, "recorder.db"))
    files = report_files(tag, a.rooms, a.stress_rooms)
    print("== E8 score %s (LATE_BOUND=%.0fs GAP_S=%.0fs) windows=%s ==" % (tag, LATE_BOUND, GAP_S, sorted(w)), flush=True)
    t0 = time.time()
    V = run_verifies(sp, w, files, tsnap, a.restore_out, a.jobs)
    print("  verify wall time %.0f s" % (time.time() - t0), flush=True)
    if a.verify_only:
        return 0
    meta = [l.rstrip("\n") for l in open(os.path.join(sp, "auth_meta.log"))] \
        if os.path.exists(os.path.join(sp, "auth_meta.log")) else []
    trials = {k: load_trials(v) for k, v in files.items()}
    result = {
        "experiment": "E8 part C",
        "tag": tag,
        "what": "arms PU, PI, PSR, P (homeprov_ec) and INS-L, INS-M, BD-S (homeprov_e7) on the default deployment, "
                "then a lab-rate baseline and a write-rate stress window with a PU arm; scored by e7_verify under the "
                "stable-columns monitor (the evaluated scheme) and the closure monitor (alongside), each with coverage, "
                "escrow, Ed25519 record signatures, tagged anchor replies, a linked anchor with an operator key, and a "
                "head witness outside Docker's VM",
        "pre_registered_parameters": {"late_bound_s": LATE_BOUND, "gap_s": GAP_S},
        "windows": {k: {"t_start": v[0], "t_end": v[1], "duration_s": round(v[1] - v[0], 1)} for k, v in w.items()},
        "recorder_snapshot_at": tsnap,
        "report_files": {k: [os.path.relpath(f, ROOT) for f in v] for k, v in files.items()},
        "harness": {k: report_context(v) for k, v in trials.items() if v},
        "monitors": {},
        "signature_keys": key_fingerprints(sp, meta),
        "signature_cross_check": [x for x in (cross_key(sp, "stb", "clo"), cross_key(sp, "clo", "stb")) if x],
        "probes": probes(meta),
        "write_rate": write_rates(sp, w),
        "stress_publisher": stress_publisher(sp),
        "recovery_render": recovery_render(sp),
        "code_sha256": {p: sha(os.path.join(ROOT, p)) for p in (
            "exp/stages/e7_verify.py", "exp/stages/e8_score.py", "testbed/anchord/chainverify.py",
            "monitor/monitor.py")},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    scratch = tempfile.mkdtemp(prefix="e8t_")
    try:
        dbc = EV._private_copy(os.path.join(sp, "recorder.db"), scratch)
        touched = {win: window_touched(files[win], dbc) for win in WINDOWS if win in w}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    for name, m, scheme in MONITORS:
        recs = read_chain(os.path.join(sp, "%s_chain.jsonl" % m)) if os.path.exists(
            os.path.join(sp, "%s_chain.jsonl" % m)) else []
        result["monitors"][name] = {
            "scheme": scheme, "evaluated": name == "stable",
            "by_window": {win: summarize_verify(V[m].get(win), scope_suspects(V[m][win], w[win], touched[win])
                                                if isinstance(V[m].get(win), dict) and "error" not in V[m][win] else None)
                          for win in WINDOWS if win in w},
            "per_poll_cost": cost_by_window(os.path.join(sp, "%s_cost.jsonl" % m), w),
            "seal_delay_s": seal_delay(recs, w),
            "chain_markers": marker_records(recs),
            "witness": witness_checks(sp, m),
            "monitor_log": monitor_log_counts(os.path.join(sp, "%s_monitor.log" % m)),
            "anchor_refusals_by_reason": refusals(os.path.join(sp, "%s_refusals.jsonl" % m))}
    if a.rescore_of:
        result["rescore"] = rescore_check(a.rescore_of, result)
    with open(dst, "w" if a.overwrite else "x") as fh:
        json.dump(result, fh, indent=1, default=str)
    for name, m, _s in MONITORS:
        for win in WINDOWS:
            src = os.path.join(sp, "%s_verify_%s.json" % (m, win))
            to = os.path.join(OUT, "%s_%s_verify_%s.json" % (tag, name, win))
            if os.path.exists(src) and (a.overwrite or not os.path.exists(to)):
                shutil.copyfile(src, to)

    # ---- printed summary
    for name, _m, _s in MONITORS:
        mon = result["monitors"][name]
        print("\n-- %s monitor%s --" % (name, " (evaluated)" if name == "stable" else ""))
        for win, s in mon["by_window"].items():
            if s.get("verify_error"):
                print("  %-6s verify ERROR: %s" % (win, s.get("stderr_tail", "")[-300:]))
                continue
            for arm, x in sorted((s.get("arms") or {}).items()):
                print("  %-6s %-6s n=%-3d e7_detected=%-3d %s  earlier rule: flagged=%d attributable=%d ambiguous=%d"
                      % (win, arm, x["n"], x["e7_detected"], x.get("e7_detected_ci"), x["existing_flagged"],
                         x["existing_attributable"], x["existing_ambiguous"]))
            bf = s.get("benign_floor") or {}
            uf = bf.get("untouched_flagged_seconds") or {}
            if "keylog_likely_rows" in uf:
                print("  %-6s suspect seconds (window-scoped): %s of %s untouched anchored (share %s); via a touched key "
                      "range %s; keylog suspect rows %s, likely rows %s; e7_verify unscoped n %s"
                      % (win, uf["n"], uf["of_untouched_anchored_seconds"], uf["share_of_untouched_anchored_seconds"],
                         uf["via_a_key_range_that_holds_a_touched_second"]["n"], uf["keylog_suspect_rows"],
                         uf["keylog_likely_rows"], uf["e7_verify_unscoped"]["n"]))
            sg = s.get("signature_counts") or {}
            print("  %-6s floor: %s of %s untouched seconds %s; minute %s/%s; signatures ok=%s unsigned_excluded=%s "
                  "bad=%s wrong=%s; root_unknown=%s"
                  % (win, bf.get("violated"), bf.get("untouched_anchored_seconds"), bf.get("violated_ci"),
                     (bf.get("minute") or {}).get("attributable"), (bf.get("minute") or {}).get("untouched_anchored"),
                     sg.get("signed_ok"), sg.get("unsigned_excluded"), sg.get("bad_signature"), sg.get("wrong_key"),
                     (s.get("root_unknown_segments") or {}).get("n")))
        for win, c in (mon["per_poll_cost"] or {}).items():
            if isinstance(c, dict) and "per_poll_ms" in c:
                t = c["per_poll_ms"].get("total_ms") or {}
                print("  %-6s cost total ms median %s p90 %s max %s (%d polls, %d failed appends); seal delay %s"
                      % (win, t.get("median"), t.get("p90"), t.get("max"), c["n_polls"], c["failed_appends"],
                         mon["seal_delay_s"].get(win)))
        wt = mon["witness"]
        if wt.get("available"):
            print("  witness: chain %s records link=%s ok=%s; final head = chain head: %s; never witnessed %s; forks %s; "
                  "controls %s" % (wt["records"], wt["link"], wt["ok"], wt["final_head_equals_chain_head"],
                                   wt["records_never_witnessed"], wt["forks_logged"],
                                   json.dumps(wt["controls"])[:400]))
    print("\n  probes as expected: %s" % result["probes"]["as_expected"])
    wr = result["write_rate"]
    if wr.get("available", True):
        print("  write rate rows/min: %s; ratios %s" % ({k: v.get("rows_per_minute") for k, v in wr.items()
                                                         if isinstance(v, dict) and "rows_per_minute" in v},
                                                        wr.get("ratios")))
    print("  -> %s" % dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
