"""E9 part C3 (2026-10-09): the off-hub replica baseline (round-3 review R2 W3), computed from the E8 files only.

R2 asks what commitment adds over shipping the record off the hub. E8's monitors already ran both: the anchor chain
(the commitment: roots, counts, coverage fields, keylog prefixes, signatures) and the escrow (HOMEPROV_ESCROW_DIR: the
exact committed field tuples of every sealed second and of every row at its first observation, i.e. a full off-hub
replica of the committed fields). This script reads, for both E8 monitors (stable columns, evaluated; closure,
alongside):

  exp/out/e8_main_{stable,closure}_chain.jsonl.gz    the anchor's chain file (one JSON line per stored record)
  exp/out/e8_main_{stable,closure}_escrow.jsonl.gz   the monitor's escrow file (one JSON line per sealed second or keylog
                                                     sub-range)
  exp/out/e8_main_score.json                         the run's windows and the recorder rows written in each
  exp/out/e8_main_{stb,clo}_sign_pub.pem             the monitors' published Ed25519 public keys
  exp/out/e8_main_config.json                        the run's configuration (code hashes)

and computes, per window of the run (main: arms; base: lab write rate, no trials; stress: about 4.6 times the base
rate):
  1. STORAGE: bytes of chain records (by the anchor's recv_ts) and of escrow lines (by sealed_at / poll_ts) whose time
     falls in the window, as stored (uncompressed JSON lines) and gzip-compressed (level 6, one stream per window); the
     window's rate in bytes per second, the same rate times 86400 (bytes per day AT THAT WINDOW'S WRITE RATE: a unit
     conversion of a rate measured over the window, not a day-long measurement), and bytes per recorder row written in
     the window (rows from e8_main_score.json write_rate).
  2. WHAT A THIRD PARTY CAN CHECK: (a) each chain record's Ed25519 signature under the published key (the monitor's own
     verify_record_signature); (b) each escrow line against the chain: the fold of its tuples (the monitor's own
     node_digest / keylog encoding) must reproduce its own acc AND the root or keylog sub-range the chain anchored for
     it (exp/stages/e7_verify.py read_escrow / read_escrow_keylog); (c) a control: one escrow line is doctored (one
     committed value changed) and its acc recomputed, so the line is self-consistent; it must still fail against the
     chain. A replica without a commitment has only check (c)'s first half: self-consistency.
  3. WHAT THE ANCHOR HOST LEARNS: the union of the payload fields of every chain record (by name, with counts); whether
     any committed value appears in the chain (every distinct TEXT value of 8 or more characters and every BLOB of 8 or
     more bytes, as hex, from the escrowed tuples, searched for in the chain file's text); and the activity timeline it
     does receive: the seconds with a non-empty anchored root per window, next to the run's own count of seconds with a
     recorder row (e8_main_score.json write_rate seconds_with_a_row).

    python3 exp/sp2027/e9_replica_baseline.py        # writes exp/out/e9_replica_baseline.json (never overwrites)
    python3 exp/sp2027/e9_replica_baseline.py --out /tmp/x.json      # a trial run elsewhere
"""
import collections
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
DST = os.path.join(OUT, "e9_replica_baseline.json")
MONS = {"stable": "stb", "closure": "clo"}
MIN_TEXT, MIN_BLOB = 8, 8


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def sha_gz(path):
    return hashlib.sha256(gzip.open(path, "rb").read()).hexdigest()


def load_verifier():
    path = os.path.join(REPO, "exp", "stages", "e7_verify.py")
    spec = importlib.util.spec_from_file_location("e9c3_e7_verify", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, path


def gz_size(lines):
    return len(gzip.compress("".join(x + "\n" for x in lines).encode(), compresslevel=6))


def in_window(t, w):
    return t is not None and w["t_start"] <= t < w["t_end"]


def walk_values(v, texts, blobs):
    """Every TEXT and BLOB leaf of a decoded escrow value (tuples nest)."""
    if isinstance(v, (tuple, list)):
        for x in v:
            walk_values(x, texts, blobs)
    elif isinstance(v, str):
        if len(v) >= MIN_TEXT:
            texts.add(v)
    elif isinstance(v, (bytes, bytearray)):
        if len(v) >= MIN_BLOB:
            blobs.add(bytes(v).hex())


def main():
    global DST
    if "--out" in sys.argv:                 # a trial run writes elsewhere; the result file is written without it
        DST = os.path.abspath(sys.argv[sys.argv.index("--out") + 1])
    if os.path.exists(DST):
        raise SystemExit("refusing to overwrite " + DST)
    V, vpath = load_verifier()
    score = json.load(open(os.path.join(OUT, "e8_main_score.json")))
    cfg = json.load(open(os.path.join(OUT, "e8_main_config.json")))
    windows = score["windows"]
    rates = score["write_rate"]
    inputs = {}
    out = {
        "item": "E9 C3: off-hub replica baseline (R2 W3) from the E8 files: storage of the anchor chain vs the escrow "
                "(a full off-hub replica of the committed fields), what each lets a third party verify, and what the "
                "anchor host receives",
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
        "script": os.path.relpath(os.path.abspath(__file__), REPO),
        "script_sha256": sha(os.path.abspath(__file__)),
        "verifier": {"file": os.path.relpath(vpath, REPO), "sha256": sha(vpath),
                     "e8_run_used": cfg["code_sha256"].get("exp/stages/e7_verify.py")},
        "monitor_code": {"file": "monitor/monitor.py", "sha256": sha(os.path.join(REPO, "monitor", "monitor.py")),
                         "e8_run_used": cfg["code_sha256"].get("monitor/monitor.py")},
        "windows": windows,
        "recorder_rows_written": {w: {k: rates[w][k] for k in ("rows", "rows_per_minute", "seconds_with_a_row")}
                                  for w in windows},
        "definitions": {
            "chain_bytes": "bytes of the anchor's chain lines (JSON plus newline, as anchord stores them) whose recv_ts "
                           "is in the window",
            "escrow_bytes": "bytes of the monitor's escrow lines (JSON plus newline, as written) whose sealed_at "
                            "(sealed-second lines) or poll_ts (keylog lines) is in the window",
            "per_day_at_window_rate": "bytes in the window / window seconds * 86400: the window's measured rate "
                                      "expressed per day, NOT a measurement over a day",
            "gzip": "one gzip stream (level 6) of the window's lines; an archival option, not what the run stored",
        },
        "monitors": {},
    }
    scratch = tempfile.mkdtemp(prefix="e9c3_")
    try:
        for scheme, short in MONS.items():
            cpath = os.path.join(OUT, "e8_main_%s_chain.jsonl.gz" % scheme)
            epath = os.path.join(OUT, "e8_main_%s_escrow.jsonl.gz" % scheme)
            kpath = os.path.join(OUT, "e8_main_%s_sign_pub.pem" % short)
            inputs[os.path.relpath(cpath, REPO)] = {"sha256_gz": sha(cpath), "sha256_uncompressed": sha_gz(cpath)}
            inputs[os.path.relpath(epath, REPO)] = {"sha256_gz": sha(epath), "sha256_uncompressed": sha_gz(epath)}
            inputs[os.path.relpath(kpath, REPO)] = {"sha256": sha(kpath)}
            M = V.load_monitor(scheme, scratch)
            chain = V.read_lines(cpath)
            esc = V.read_lines(epath)
            recs = [json.loads(x) for x in chain if x.strip()]
            escs = [json.loads(x) for x in esc if x.strip()]

            # ---------------------------------------------------------------- 1. storage per window
            storage = {}
            for w, win in windows.items():
                c_lines = [x for x, r in zip([y for y in chain if y.strip()], recs) if in_window(r.get("recv_ts"), win)]
                e_sec = [x for x, e in zip([y for y in esc if y.strip()], escs)
                         if e.get("kind") != "keylog" and in_window(e.get("sealed_at"), win)]
                e_kl = [x for x, e in zip([y for y in esc if y.strip()], escs)
                        if e.get("kind") == "keylog" and in_window(e.get("poll_ts"), win)]
                dur = float(win["duration_s"])
                rows = rates[w]["rows"]

                def block(lines):
                    b = sum(len(x.encode()) + 1 for x in lines)
                    g = gz_size(lines) if lines else 0
                    return {"lines": len(lines), "bytes": b, "bytes_gzip": g,
                            "bytes_per_s": round(b / dur, 3), "bytes_per_day_at_window_rate": round(b / dur * 86400),
                            "bytes_gzip_per_day_at_window_rate": round(g / dur * 86400),
                            "bytes_per_recorder_row": round(b / rows, 2) if rows else None}
                ch = block(c_lines)
                es = block(e_sec + e_kl)
                es["sealed_second_lines"] = len(e_sec)
                es["keylog_lines"] = len(e_kl)
                es["sealed_second_bytes"] = sum(len(x.encode()) + 1 for x in e_sec)
                es["keylog_bytes"] = sum(len(x.encode()) + 1 for x in e_kl)
                storage[w] = {"chain": ch, "escrow": es,
                              "escrow_over_chain_bytes": round(es["bytes"] / ch["bytes"], 3) if ch["bytes"] else None,
                              "escrow_over_chain_gzip": (round(es["bytes_gzip"] / ch["bytes_gzip"], 3)
                                                         if ch["bytes_gzip"] else None)}
            whole = {"chain_lines": len(recs), "chain_bytes": sum(len(x.encode()) + 1 for x in chain if x.strip()),
                     "escrow_lines": len(escs), "escrow_bytes": sum(len(x.encode()) + 1 for x in esc if x.strip()),
                     "first_recv_ts": recs[0].get("recv_ts"), "last_recv_ts": recs[-1].get("recv_ts"),
                     "note": "whole files, including the first poll's seal of the re-read window (history before the "
                             "monitor started) and the set-up and teardown minutes outside the three windows"}

            # ---------------------------------------------------------------- 2. third-party checks
            kept, sig = V.check_signatures(M, chain, kpath)
            P = V.parse_chain(kept, scheme=scheme)
            roots = P["all_roots"]
            by_sec = V.read_escrow(esc, M)
            n_lines = n_self = n_anch = n_no_root = 0
            mismatch = []
            for seg, lines in by_sec.items():
                for e in lines:
                    n_lines += 1
                    acc = M.ZERO
                    for nd in e["_nodes"]:
                        acc = M.H(acc + M.node_digest(nd, e.get("encoding", "v2")))
                    self_ok = acc.hex() == e.get("acc") and len(e["_nodes"]) == e.get("n")
                    n_self += self_ok
                    a = roots.get(("second", str(seg)))
                    if a is None:
                        n_no_root += 1
                    elif self_ok and a.get("acc") == e.get("acc") and a.get("n") == e.get("n"):
                        n_anch += 1
                    elif len(mismatch) < 20:
                        mismatch.append({"seg": seg, "self_consistent": self_ok})
            good_kl, kl_sum = V.read_escrow_keylog(esc, M, P["polls"])
            n_kl_lines = sum(1 for e in escs if e.get("kind") == "keylog")

            # control: doctor one sealed-second line (first node whose stable/closure tuple holds a 'state' TEXT value
            # or, failing that, the first node's key), recompute its acc, and check it against the chain
            control = None
            for seg, lines in sorted(by_sec.items(), key=lambda kv: int(kv[0])):
                e = lines[0]
                a = roots.get(("second", str(seg)))
                if not e["_nodes"] or a is None or a.get("acc") != e.get("acc"):
                    continue
                nodes = [list(n) for n in e["_nodes"]]
                n0 = nodes[0]
                before = n0[2]
                n0[2] = (before + b" ") if isinstance(before, (bytes, bytearray)) else (str(before) + " ")
                changed = "content (node column 3)"
                if len(n0) == 7:                      # stable: the hash covers the field tuple; change one value in it
                    f = list(n0[6])
                    changed = None
                    for i in range(1, len(f) - 1, 2):
                        if f[i] in ("state", "event_data.shared_data", "state_attributes.shared_attrs",
                                    "context_id_bin") and isinstance(f[i + 1], (str, bytes)):
                            f[i + 1] = f[i + 1] + (" " if isinstance(f[i + 1], str) else b" ")
                            changed = f[i]
                            break
                    n0[6] = tuple(f)
                if changed is None:
                    continue
                nodes[0] = tuple(n0)
                acc = M.ZERO
                for nd in nodes:
                    acc = M.H(acc + M.node_digest(nd, e.get("encoding", "v2")))
                control = {"seg": seg, "field_changed": changed, "doctored_line_self_consistent": True,
                           "recomputed_acc_equals_doctored_line_acc": True,
                           "doctored_acc_equals_anchored_root": acc.hex() == a.get("acc"),
                           "original_acc_equals_anchored_root": e.get("acc") == a.get("acc"),
                           "what": "one committed value of the line's first node extended by one byte (field_changed), the line's acc "
                                   "recomputed from the doctored tuples (as a replica host could)"}
                break

            # ---------------------------------------------------------------- 3. what the anchor host receives
            fields = collections.Counter()
            sub = collections.Counter()
            for r in recs:
                p = r.get("payload") or {}
                for k in p:
                    fields[k] += 1
                for g, segs in (p.get("sealed") or {}).items():
                    for v in (segs or {}).values():
                        for k in (v or {}):
                            sub["sealed.<gran>.<seg>." + k] += 1
                for t, es_ in (p.get("keylog") or {}).items():
                    for e in es_:
                        for k in e:
                            sub["keylog.<table>[]." + k] += 1
            texts, blobs = set(), set()
            for e in escs:
                if e.get("kind") == "keylog":
                    for _k, j in e.get("rows", []):
                        walk_values(M.from_jt(j), texts, blobs)
                else:
                    for j in e.get("nodes", []):
                        walk_values(M.from_jt(j), texts, blobs)
            # the node's canonical 'content' (column 3) is JSON bytes, which holds the entity id and state as text:
            # its strings are covered by the TEXT leaves of the stable tuple; for closure, decode it as well
            chain_text = "\n".join(chain)
            # field names, record keys and fixed labels are not committed values: drop them from the search set
            labels = set(fields) | {k.split(".")[-1] for k in sub} | {"external-monitor", "operator-marker-issuer"}
            for e in escs:
                if e.get("kind") != "keylog":
                    for j in e.get("nodes", []):
                        n = M.from_jt(j)
                        if len(n) == 7:
                            labels |= {n[6][i] for i in range(1, len(n[6]) - 1, 2) if isinstance(n[6][i], str)}
                            labels.add(n[6][0])
                        labels.add(n[5])
                    break
            for e in escs:
                if e.get("kind") == "keylog":
                    for _k, j in e.get("rows", [])[:1]:
                        f = M.from_jt(j)
                        labels |= {f[i] for i in range(1, len(f) - 1, 2) if isinstance(f[i], str)}
                        labels.add(f[0])
                    break
            # node keys ("s:123", "e:45") and node labels are the monitor's, not the recorder's
            texts = {t for t in texts if t not in labels and not (t[:2] in ("s:", "e:") and t[2:].isdigit())}
            found_t = sorted(t for t in texts if t in chain_text)
            found_b = sorted(b for b in blobs if b in chain_text)
            act = {}
            for w, win in windows.items():
                secs = {int(s) for (g, s), a in roots.items() if g == "second" and (a.get("n") or 0) > 0
                        and win["t_start"] <= int(s) < win["t_end"]}
                act[w] = {"seconds_with_a_nonempty_anchored_root": len(secs),
                          "recorder_seconds_with_a_row_e8_score": rates[w]["seconds_with_a_row"]["k"],
                          "window_seconds": int(win["duration_s"])}
            out["monitors"][scheme] = {
                "evaluated": scheme == "stable",
                "files": {"chain": os.path.relpath(cpath, REPO), "escrow": os.path.relpath(epath, REPO),
                          "sign_pubkey": os.path.relpath(kpath, REPO)},
                "storage_by_window": storage,
                "whole_files": whole,
                "third_party_checks": {
                    "signatures": {k: sig[k] for k in ("monitor_records", "signed_ok", "unsigned", "bad_signature",
                                                       "wrong_key", "pubkey_fp")},
                    "escrow_sealed_second_lines": {"lines": n_lines, "self_consistent": n_self,
                                                   "reproduce_the_anchored_root": n_anch,
                                                   "no_anchored_root_for_the_second": n_no_root,
                                                   "mismatches_first_20": mismatch},
                    "escrow_keylog_lines": {"lines": n_kl_lines, **kl_sum},
                    "doctored_escrow_line_control": control,
                },
                "anchor_host_receives": {
                    "payload_fields_by_record_count": dict(sorted(fields.items())),
                    "sealed_and_keylog_subfields": dict(sorted(sub.items())),
                    "committed_values_searched": {"text_values_min_chars": MIN_TEXT, "n_text": len(texts),
                                                  "blob_values_min_bytes": MIN_BLOB, "n_blob": len(blobs),
                                                  "text_found_in_chain": len(found_t),
                                                  "text_found_first_20": found_t[:20],
                                                  "blob_found_in_chain": len(found_b),
                                                  "blob_found_first_20": found_b[:20]},
                    "activity_timeline": act,
                },
            }
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    out["inputs"] = inputs
    out["what_each_lets_a_third_party_verify"] = {
        "anchor_chain_alone": "the monitor's records are authentic (Ed25519 under the published key) and linked; it "
                              "holds no row content, so alone it shows neither what a row said nor whether a recorder "
                              "is unchanged",
        "anchor_chain_plus_recorder_or_extract": "whether each sealed segment of the presented rows reproduces the "
                                                 "anchored root (match, violation, or unknown); a changed row is "
                                                 "detected, its original content is not recovered",
        "anchor_chain_plus_escrow": "each escrow line is authenticated by reproducing an anchored root or keylog "
                                    "sub-range (counts above), after which the original committed fields of every "
                                    "sealed second are recoverable",
        "escrow_or_replica_alone": "self-consistency only: the replica's host (or anyone who can write it) can change "
                                  "a line and recompute its fold, as the doctored-line control shows; a third party "
                                  "must trust that host for integrity",
    }
    out["what_the_anchor_host_learns"] = (
        "Roots (32-byte hashes), row counts per segment, the poll's times and watermarks (row keys), and per "
        "first-observed row its key offset, a 32-bit prefix of its row hash and the second it was in (field lists "
        "above); so it learns WHEN rows were written and how many (the activity timeline, counted above), and no "
        "committed value (search above). The escrow's host holds every committed value of every sealed row.")
    with open(DST, "x") as fh:
        json.dump(out, fh, indent=1, sort_keys=False)
    summ = {s: {w: {"chain_B_per_day": m["storage_by_window"][w]["chain"]["bytes_per_day_at_window_rate"],
                    "escrow_B_per_day": m["storage_by_window"][w]["escrow"]["bytes_per_day_at_window_rate"],
                    "ratio": m["storage_by_window"][w]["escrow_over_chain_bytes"]} for w in windows}
            for s, m in out["monitors"].items()}
    print(json.dumps(summ, indent=1))
    print(json.dumps({s: m["third_party_checks"]["escrow_sealed_second_lines"] for s, m in out["monitors"].items()},
                     indent=1)[:2000])
    print("wrote", DST, sha(DST))


if __name__ == "__main__":
    sys.exit(main())
