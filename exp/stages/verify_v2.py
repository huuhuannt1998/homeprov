"""Verifier version 2 (round 17, review r6; PI 2026-10-26: "Also fix the verifier"): the E10 verifier, unchanged, with
two additions. Exploratory: registered verdicts stay as their registered verifier scored them.

exp/stages/e7_verify.py (registered by E10, E10b and E12, sha256 ae9d9c42...) is imported and called, never edited.
verify_v2() runs its verify() with two of its module functions wrapped for the duration of the call (check_signatures:
the result of the one signature check is reused; parse_chain: see 2.) and with three functions of its own monitor module
instance replaced (see 1.); run_v2() runs its run(), so the output is e7_verify's output plus a "v2" section.

1. PINNED COLUMN LIST (stable scheme). Each root is recomputed over the committed column list in force when its segment
   was sealed, and each keylog range over the list of the poll that committed it:
   - a record written by monitor/monitor_v2.py carries "committed_columns" (instance, history [[from_seq, digest]],
     lists); a root sealed by poll s (the record's seq_local, or the seal_seq of a frozen or conflicted root) uses the
     last history entry of the CARRYING record with from_seq <= s (the carrying record's history covers every poll up
     to its own); a keylog range uses the list of the poll that committed it (the record's own, or a backlog head's
     seq_local);
   - a record without the field (monitor.py, every registered run) uses the list given from outside
     (--pinned-columns-db: the column list of a recorder file, e.g. the run's start snapshot; or --pinned-columns-json),
     recorded with its source; with neither, the CURRENT list of the recorder being verified, which is exactly what the
     E10 verifier does, and the output says so ("current_schema"). Nothing is guessed silently.
   The rows are loaded once; when every root and range uses one list, the field tuples are built over that list
   (pinned_columns.load_stable_cols / keylog_rows_cols, byte-identical to monitor.py's functions for that list) and
   e7_verify's fold is unchanged; when lists differ (a v2 chain across a migration), each segment's root is folded over
   its own list (commit_v2 below, the fold of monitor.py commit() with the field tuple chosen per segment).
   A column added after a segment was sealed is not read for it (reported under v2.column_list.added, with the number of
   rows holding a non-NULL value in it). A pinned column the recorder no longer has makes every root over a row of that
   table fail, as today (pinned_columns.DROPPED); such violations carry v2_reason "committed_column_dropped". No
   declaration excuses a dropped column (the PI's decision, VERIFY_V2_NOTES.md).
2. TWO SIGNED ROOTS. Every root of every validly signed monitor record is collected per segment, whatever the record
   order: the roots it seals, the frozen roots it re-sends and the monitor's own root of a "conflicted" entry (the anchor
   refused it); with the same filters parse_chain applies (scheme, observable records, sealing time not after the
   snapshot). When two of them differ (acc or n), the segment's first anchored root is replaced, for verify(), by a value
   no recomputation equals, so step 1 reports the segment as an attributable violation through e7_verify's own path
   (flagged seconds, coarse localisation, counts); the violation carries mechanism and v2_reason "conflicting_roots",
   every distinct root, and whether the current rows with keys at or below that root's watermark reproduce it (for the
   investigator; the verdict does not depend on it). "Validly signed": records kept by check_signatures with a public
   key; with --allow-unsigned only those whose signature verifies; without a key the rule does not apply and conflicts
   are listed only. --conflict-rule off turns the rule off (for comparison).

usage (every e7_verify verify option, plus):
  verify_v2.py verify ... [--pinned-columns-db RECORDER.db | --pinned-columns-json LIST.json]
                          [--pinned-columns-label TEXT] [--conflict-rule strict|off]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "monitor"))
import e7_verify as EV                          # noqa: E402  (registered; imported, never edited)
import pinned_columns as PC                     # noqa: E402

VERSION = 2
SENTINEL = "conflicting-roots"                  # stands in for a first anchored root when two signed roots differ
REGISTERED = {"exp/stages/e7_verify.py": "ae9d9c42bf484cbfda50f2e32f1de26ea19f3a956b659f8ad4abf245e5f03ef7",
              "monitor/monitor.py": "4b9931cb7d1cffae6485fb2b660b68d733da9f73e5c22c22ca7265d49ceaa9b7"}
_ORIG = {"verify": EV.verify, "parse_chain": EV.parse_chain, "check_signatures": EV.check_signatures,
         "run": EV.run}
LIST_CAP = 500


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def code_hashes():
    files = {"exp/stages/verify_v2.py": os.path.join(HERE, "verify_v2.py"),
             "exp/stages/e7_verify.py": os.path.join(HERE, "e7_verify.py"),
             "monitor/monitor.py": os.path.join(REPO, "monitor", "monitor.py"),
             "monitor/pinned_columns.py": os.path.join(REPO, "monitor", "pinned_columns.py")}
    out = {k: sha256_file(p) for k, p in files.items()}
    out["registered_code_unchanged"] = all(out[k] == v for k, v in REGISTERED.items())
    return out


# ------------------------------------------------------------------------------------------------ the column lists
def columns_of_file(M, path):
    """The committed column list of a recorder file (e.g. a run's start snapshot), read without writing anything: an
    immutable read-only open when its -wal is absent or empty, else a private copy."""
    wal = path + "-wal"
    if os.path.exists(wal) and os.path.getsize(wal) > 0:
        raise SystemExit("--pinned-columns-db %s has a non-empty -wal; pass a checkpointed copy" % path)
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % path, uri=True)
    try:
        EV.vharden(con)
        cols = {t: [r[1] for r in con.execute("PRAGMA table_info(%s)" % t) if r[1] not in M.STABLE_EXCLUDE[t]]
                for t in PC.TABLES}
    finally:
        con.close()
    return PC.canonical(cols)


def _history_lookup(cc, seq):
    """The list of poll `seq` from one record's committed_columns field, or (None, why)."""
    try:
        hist = sorted((int(a), str(d)) for a, d in cc.get("history") or [])
        lists = cc.get("lists") or {}
    except (TypeError, ValueError):
        return None, "malformed"
    best = None
    for a, d in hist:
        if a <= seq:
            best = d
    if best is None:
        return None, "poll_before_history"
    cols = lists.get(best)
    try:
        if cols is None or PC.digest(cols) != best:
            return None, "list_digest_mismatch"
        return PC.canonical(cols), None
    except ValueError:
        return None, "malformed"


class Chain:
    """One pass over the kept chain lines: every root with the record list that sealed it, every keylog range with the
    list of the poll that committed it, every signed root per segment (for the conflict rule)."""

    def __init__(self, lines, scheme, tsnap, signed_ok):
        self.root_list = {}                          # (chain_seq, g, seg, acc) -> list or None
        self.keylog_list = collections.defaultdict(set)   # (table, lo, hi) -> {digest or None}
        self.lists = {}                              # digest -> list
        self.roots = collections.defaultdict(list)   # (g, seg) -> [root info], signed records only
        self.unsigned_roots = collections.defaultdict(list)
        self.lookup_failures = collections.Counter()
        self.records_with_lists = 0
        self.instances = set()
        self.after_snapshot_ignored = 0

        def after_snap(t):
            return tsnap is not None and t is not None and t > tsnap

        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                cr = json.loads(line)
            except ValueError:
                continue
            p = cr.get("payload") or {}
            if p.get("observer") != "external-monitor":
                continue
            if scheme is not None and p.get("scheme", "row") != scheme:
                continue
            ts = p.get("ts") or cr.get("recv_ts") or 0.0
            cov = "coverage" in p and "seq_local" in p
            if not cov and after_snap(ts):
                continue
            unobs = bool(p.get("evidence_unobservable"))
            cc = p.get("committed_columns") if isinstance(p.get("committed_columns"), dict) else None
            if cc is not None:
                self.records_with_lists += 1
                self.instances.add(cc.get("instance"))
            own = int(p["seq_local"]) if cov else None
            signed = signed_ok(i, p)
            dest = self.roots if signed else self.unsigned_roots

            def list_of(seq):
                if cc is None or seq is None:
                    return None
                cols, why = _history_lookup(cc, seq)
                if why:
                    self.lookup_failures[why] += 1
                    return None
                self.lists[PC.digest(cols)] = cols
                return cols

            def add(g, seg, v, seal_seq, eff_ts, conflicted):
                acc = v.get("acc")
                cols = list_of(seal_seq)
                self.root_list[(cr.get("seq"), g, str(seg), acc)] = cols
                if after_snap(eff_ts):
                    self.after_snapshot_ignored += 1
                    return
                dest[(g, str(seg))].append({"acc": acc, "n": v.get("n"), "chain_seq": cr.get("seq"), "line": i,
                                            "seal_seq": seal_seq, "sealed_at": eff_ts, "record_ts": ts,
                                            "encoding": p.get("encoding", "v1"), "conflicted": conflicted,
                                            "wm": v.get("wm") if "seal_seq" in v else (p.get("wm") if cov else None),
                                            "instance": (cc or {}).get("instance"),
                                            "column_list": None if cols is None else PC.digest(cols)[:16]})

            # keylog ranges: the record's own poll, and backlog heads (polls of the same instance)
            heads = [(own, p.get("keylog"))] + [(h.get("seq_local"), h.get("keylog")) for h in (p.get("backlog") or [])
                                                if isinstance(h, dict)]
            for seq, kl in heads:
                for t, es in (kl or {}).items():
                    for e in (es if isinstance(es, list) else [es]):
                        if isinstance(e, dict):
                            cols = list_of(None if seq is None else int(seq))
                            self.keylog_list[(t, int(e.get("from", 0)), int(e.get("to", 0)))].add(
                                None if cols is None else PC.digest(cols))
            if cov:
                for c in p.get("conflicted") or []:
                    if not unobs and isinstance(c, dict) and "seal_seq" in c:
                        add(c.get("gran"), c.get("seg"), c, int(c["seal_seq"]), c.get("sealed_at") or ts, True)
            if unobs:
                continue
            for g, segs in (p.get("sealed") or {}).items():
                if not isinstance(segs, dict):
                    continue
                for seg, v in segs.items():
                    if not isinstance(v, dict):
                        continue
                    if cov and "seal_seq" in v:
                        add(g, seg, v, int(v["seal_seq"]), v.get("sealed_at"), False)
                    elif cov:
                        add(g, seg, v, own, ts, False)
                    else:
                        add(g, seg, v, None, ts, False)

    def conflicts(self, roots=None):
        """{(g, seg): [distinct roots, each with every record that carries it]} for segments holding two or more
        different (acc, n) among the given roots (default: the validly signed ones)."""
        out = {}
        for k, rs in (self.roots if roots is None else roots).items():
            by = collections.OrderedDict()
            for r in rs:
                by.setdefault((r["acc"], r["n"]), []).append(r)
            if len(by) > 1:
                out[k] = [{"acc": a, "n": n, "carried_by": [{x: r[x] for x in ("chain_seq", "seal_seq", "sealed_at",
                                                                                  "record_ts", "conflicted", "encoding",
                                                                                  "instance", "wm", "column_list")}
                                                             for r in v]}
                          for (a, n), v in by.items()]
        return out


# ------------------------------------------------------------------------------------------------ the column regimes
class Regimes:
    """Which committed column list each segment root and keylog range is recomputed over."""

    def __init__(self, chain, current, external, external_label):
        self.chain, self.current, self.external, self.external_label = chain, current, external, external_label
        self.default = external if external is not None else current
        self.default_source = ("external:%s" % external_label) if external is not None else "current_schema"
        self.P = None
        # the outside (or current) list is a regime only if some root or keylog range has no list of its own
        self.default_needed = (not chain.root_list or any(v is None for v in chain.root_list.values())
                               or any(None in s for s in chain.keylog_list.values()))
        lists = {PC.digest(self.default): self.default} if self.default_needed else {}
        lists.update(chain.lists)
        self.lists = lists
        self.single = len(lists) == 1
        self.sources = collections.Counter()
        self.keylog_ambiguous = 0

    def for_segment(self, g, seg):
        P = self.P or {}
        a = (P.get("roots") or {}).get((g, seg)) or (P.get("all_roots") or {}).get((g, seg))
        if a is None:
            return self.default
        cols = self.chain.root_list.get((a.get("chain_seq"), g, seg, a.get("v2_acc", a.get("acc"))))
        return self.default if cols is None else cols

    def for_keylog(self, table, lo, hi):
        ds = self.chain.keylog_list.get((table, lo, hi))
        if not ds:
            ds = set()
            for (t, a, b), d in self.chain.keylog_list.items():
                if t == table and a < hi <= b:
                    ds |= d
        if not ds:
            return self.default
        ds = {self.default_digest() if d is None else d for d in ds}
        if len(ds) > 1:
            self.keylog_ambiguous += 1
            return self.default
        return self.lists[next(iter(ds))]

    def default_digest(self):
        return PC.digest(self.default)

    def only(self):
        """The one list of a single-list verification."""
        return next(iter(self.lists.values()))


def pin_monitor(M, R):
    """Replace load_stable, keylog_rows and (several lists only) commit on this verification's own monitor module
    instance (EV.load_monitor gives every run a fresh one). Returns a function that puts them back."""
    saved = {k: getattr(M, k) for k in ("load_stable", "keylog_rows", "commit")}
    master = {}

    def load_stable(db, since=None, until=None):
        if R.single:
            return PC.load_stable_cols(M, db, R.only(), since, until)
        nodes = PC.load_stable_cols(M, db, R.current, since, until)
        out = []
        for n in nodes:
            master[n[1]] = n[6]
            cols = R.for_segment("second", str(int(n[0] // 1.0)))
            out.append(n if cols == R.current else n[:6] + (PC.refields(n[6], cols[n[6][0]]),))
        return out

    def keylog_rows(db, table, lo, hi, limit=None):
        cols = R.only() if R.single else R.for_keylog(table, lo, hi)
        return PC.keylog_rows_cols(M, db, table, lo, hi, cols[table], limit)

    def commit(nodes, encoding=None):
        enc = encoding or M.ENCODING
        if enc not in M.ENCODINGS:
            raise ValueError("unknown node-hash encoding %r" % enc)
        cache, phi = {}, {}
        for name, width in M.GRAN:
            segs = {}
            for n in nodes:
                s = int(n[0] // width)
                if len(n) != 7:
                    h = M.node_digest(n, enc)
                else:
                    cols = R.for_segment(name, str(s))
                    ck = (n[1], PC.digest(cols))
                    h = cache.get(ck)
                    if h is None:
                        f = master.get(n[1])
                        f = n[6] if f is None else PC.refields(f, cols[n[6][0]])
                        h = cache[ck] = M.node_hash_stable(f, enc)
                e = segs.setdefault(s, {"acc": M.ZERO, "n": 0})
                e["acc"] = M.H(e["acc"] + h)
                e["n"] += 1
            phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]} for k, v in segs.items()}
        return phi

    M.load_stable, M.keylog_rows = load_stable, keylog_rows
    if not R.single:
        M.commit = commit

    def restore():
        for k, v in saved.items():
            setattr(M, k, v)
    return restore


# ------------------------------------------------------------------------------------------------ verify
def verify_v2(M, db, lines, late_bound, gap_s, scheme=None, t0=None, t1=None, tsnap=None, pinned=None,
              pinned_label=None, conflict_rule="strict", **kw):
    """e7_verify.verify() with the two version-2 rules (module docstring). Returns its result plus res["v2"]."""
    if conflict_rule not in ("strict", "off"):
        raise ValueError("conflict_rule must be 'strict' or 'off'")
    sign_pubkey, allow_unsigned = kw.get("sign_pubkey"), kw.get("allow_unsigned", False)
    kept, sigs = _ORIG["check_signatures"](M, lines, sign_pubkey, allow_unsigned)

    status = None
    if sigs.get("checked") and allow_unsigned:
        pub = M.load_public_key(sign_pubkey)
        fp = M.public_key_fingerprint(pub)
        status = {}
        for i, line in enumerate(kept):
            try:
                p = json.loads(line).get("payload") or {}
            except ValueError:
                continue
            if p.get("observer") == "external-monitor":
                status[i] = M.verify_record_signature(p, pub, fp) == "ok"

    def signed_ok(i, _p):
        if not sigs.get("checked"):
            return False
        return True if status is None else status.get(i, False)

    stable = (scheme or "") == "stable"
    chain = Chain(kept, scheme, tsnap, signed_ok)
    conflicts = chain.conflicts() if conflict_rule == "strict" and sigs.get("checked") else {}
    listed_only = chain.conflicts(chain.unsigned_roots) if not sigs.get("checked") else {}
    R = None
    restore = None
    if stable:
        current = PC.canonical(PC.current_columns(M, db))
        if pinned is None and not chain.lists:
            R = None                                     # no list known: e7_verify's own functions (current schema)
        else:
            R = Regimes(chain, current, None if pinned is None else PC.canonical(pinned), pinned_label)
            restore = pin_monitor(M, R)

    cap = {}

    def check_signatures(M_, lines_, pubkey_path=None, allow_unsigned_=False):
        if lines_ is lines and pubkey_path == sign_pubkey and allow_unsigned_ == allow_unsigned:
            return list(kept), sigs
        return _ORIG["check_signatures"](M_, lines_, pubkey_path, allow_unsigned_)

    def parse_chain(lines_, scheme_=None, t0_=None, tsnap_=None):
        P = _ORIG["parse_chain"](lines_, scheme_, t0_, tsnap_)
        if "P" not in cap and scheme_ == scheme and t0_ == t0 and tsnap_ == tsnap:
            cap["P"] = P
            if R is not None:
                R.P = P
            for k in conflicts:
                a = P["roots"].get(k)
                if a is not None:
                    P["roots"][k] = dict(a, acc=SENTINEL, v2_acc=a["acc"], v2_conflict=True)
        return P

    EV.check_signatures, EV.parse_chain = check_signatures, parse_chain
    try:
        res = _ORIG["verify"](M, db, lines, late_bound, gap_s, scheme=scheme, t0=t0, t1=t1, tsnap=tsnap, **kw)
    finally:
        EV.check_signatures, EV.parse_chain = _ORIG["check_signatures"], _ORIG["parse_chain"]

    P = res["P"]
    W = dict(M.GRAN)
    # --- conflicting roots: annotate the violations e7_verify's step 1 reported for them
    in_window = 0
    conf_out = []
    for v in res["violations"]:
        k = (v["gran"], v["seg"])
        if k in conflicts and (P["roots"].get(k) or {}).get("v2_conflict"):
            in_window += 1
            rows = res["groups"].get(v["gran"], {}).get(v["seg"], [])
            distinct = []
            for d in conflicts[k]:
                wm = next((c["wm"] for c in d["carried_by"] if c.get("wm") is not None), None)
                sel = rows if wm is None else [n for n in rows if EV.under(n, wm)]
                enc = d["carried_by"][0]["encoding"]
                got = EV.fold(M, sel, v["gran"], v["seg"], enc)
                distinct.append(dict(d, reproduced_by_current_rows=bool(got and got["acc"] == d["acc"]
                                                                         and got["n"] == d["n"])))
            v.update(mechanism="conflicting_roots", v2_reason="conflicting_roots", conflicting_roots=distinct)
            conf_out.append({"gran": v["gran"], "seg": v["seg"], "roots": distinct})
    conf_keys = {(c["gran"], c["seg"]) for c in conf_out}
    for f in res["flagged_segments"]:
        if (f["gran"], f["seg"]) in conf_keys:
            f["mechanism"] = "conflicting_roots"

    # --- dropped columns: annotate violations and keylog violations whose list holds a column the recorder lacks
    col_report = None
    if stable:
        cur = PC.canonical(PC.current_columns(M, db))
        if R is None:
            col_report = {"mode": "current_schema", "why": "no committed list on the chain and none given: every root "
                          "is recomputed over the recorder's current columns, as e7_verify does",
                          "current": cur, "current_digest": PC.digest(cur)}
        else:
            src = collections.Counter()
            for (g, seg) in res["checked"]:
                a = P["roots"].get((g, seg))
                key = (a.get("chain_seq"), g, seg, a.get("v2_acc", a.get("acc"))) if a else None
                src["record" if key is not None and chain.root_list.get(key) is not None else R.default_source] += 1
            lists = dict(R.lists)
            drop = {d: {t: [c for c in L[t] if c not in cur[t]] for t in PC.TABLES} for d, L in lists.items()}
            for v in res["violations"]:
                if v.get("v2_reason"):
                    continue
                L = R.only() if R.single else R.for_segment(v["gran"], v["seg"])
                dd = drop[PC.digest(L)]
                tabs = {EV.kparse(n[1])[0] for n in res["groups"].get(v["gran"], {}).get(v["seg"], [])}
                hit = {t: dd[t] for t in tabs if dd[t]}
                if hit:
                    v.update(v2_reason="committed_column_dropped", v2_dropped_columns=hit)
            for kv in res["keylog_violations"]:
                L = R.only() if R.single else R.for_keylog(kv["table"], kv["range"][0], kv["range"][1])
                if drop[PC.digest(L)][kv["table"]]:
                    kv.update(v2_reason="committed_column_dropped",
                              v2_dropped_columns={kv["table"]: drop[PC.digest(L)][kv["table"]]})
            added = {}
            con = EV.vconnect(db)
            try:
                for d, L in lists.items():
                    for t in PC.TABLES:
                        for c in cur[t]:
                            if c not in L[t]:
                                n_ = con.execute("SELECT count(*) FROM %s WHERE %s IS NOT NULL" % (t, M._q(c))).fetchone()[0]
                                added.setdefault(t, {})[c] = n_
            finally:
                con.close()
            col_report = {"mode": "one_list" if R.single else "per_segment_lists",
                          "default_source": R.default_source, "roots_checked_by_source": dict(src),
                          "records_with_committed_columns": chain.records_with_lists,
                          "monitor_instances": sorted(x for x in chain.instances if x),
                          "lookup_failures": dict(chain.lookup_failures),
                          "lists": {d: {"columns": L, "dropped_now": drop[d]} for d, L in lists.items()},
                          "external": None if R.external is None else {"label": R.external_label,
                                                                        "digest": PC.digest(R.external)},
                          "current": cur, "current_digest": PC.digest(cur),
                          "added_since_sealing_not_read": added, "keylog_list_ambiguous": R.keylog_ambiguous}
    if restore is not None:
        restore()

    by_gran = collections.Counter(g for g, _s in conflicts)
    res["v2"] = {"verifier_version": VERSION, "code_sha256": code_hashes(),
                 "column_list": col_report if stable else {"mode": "not_applicable", "scheme": scheme},
                 "conflict_rule": {
                     "rule": conflict_rule, "applied": bool(conflict_rule == "strict" and sigs.get("checked")),
                     "why_not_applied": (None if sigs.get("checked") or conflict_rule == "off"
                                         else "no public key: no record is validly signed; conflicts listed only"),
                     "segments_with_two_or_more_signed_roots": dict(by_gran),
                     "in_window_reported_as_violation": in_window,
                     "outside_the_window_or_not_first_anchored": len(conflicts) - in_window,
                     "roots_after_the_snapshot_ignored": chain.after_snapshot_ignored,
                     "violations": conf_out[:LIST_CAP],
                     "unsigned_conflicts_listed_only": [{"gran": g, "seg": s, "roots": r}
                                                        for (g, s), r in list(listed_only.items())[:LIST_CAP]]}}
    return res


# ------------------------------------------------------------------------------------------------ CLI (e7_verify's run)
def run_v2(a):
    """e7_verify.run(a) with verify() replaced by verify_v2(); returns (output with "v2", the in-process result)."""
    cap = {}
    pinned = getattr(a, "pinned_json", None)
    label = getattr(a, "pinned_columns_label", None)

    def verify(M, db, lines, late_bound, gap_s, **kw):
        pin = pinned
        lab = label
        if getattr(a, "pinned_columns_db", None):
            pin = columns_of_file(M, a.pinned_columns_db)
            lab = lab or "columns of %s (sha256 %s)" % (a.pinned_columns_db, sha256_file(a.pinned_columns_db)[:16])
        elif pin is not None:
            lab = lab or "columns of %s" % a.pinned_columns_json
        res = verify_v2(M, db, lines, late_bound, gap_s, pinned=pin, pinned_label=lab,
                        conflict_rule=getattr(a, "conflict_rule", "strict"), **kw)
        cap["res"] = res
        return res

    EV.verify = verify
    try:
        out = _ORIG["run"](a)
    finally:
        EV.verify = _ORIG["verify"]
    if "res" in cap:
        out["v2"] = cap["res"]["v2"]
    return out, cap.get("res")


def parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--late-bound", type=float, required=True)
    v.add_argument("--gap-s", type=float, required=True)
    v.add_argument("--escrow", default=None)
    v.add_argument("--trials", nargs="*")
    v.add_argument("--restore-out", default=None)
    v.add_argument("--sign-pubkey", default=None)
    v.add_argument("--allow-unsigned", action="store_true")
    v.add_argument("--operator-key", default=None)
    v.add_argument("--operator-pubkey", default=None)
    v.add_argument("--purge-keep-s", type=float, default=None)
    v.add_argument("--purge-tol-s", type=float, default=0.0)
    v.add_argument("--restore-tol-s", type=float, default=None)
    v.add_argument("--restore-max-age-s", type=float, default=EV.RESTORE_MAX_AGE_S)
    v.add_argument("--restore-done-max-s", type=float, default=EV.RESTORE_DONE_MAX_S)
    v.add_argument("--no-purge-disconnect", action="store_true")
    v.add_argument("--no-rowbind", action="store_true")
    v.add_argument("--namemap-storage", default=None)
    v.add_argument("--no-harden", action="store_true")
    v.add_argument("--chain", required=True)
    v.add_argument("--db", required=True)
    v.add_argument("--snapshot-at", type=float, default=None)
    v.add_argument("--window", nargs=2, default=None)
    v.add_argument("--scheme", choices=("closure", "row", "stable", "wholerow"), default=None)
    v.add_argument("--out", default=None)
    v.add_argument("--monitor-dir", default=EV.DEFAULT_MONITOR_DIR)
    g = v.add_mutually_exclusive_group()
    g.add_argument("--pinned-columns-db", default=None, help="a recorder file whose committed column list stands for "
                   "records without one (e.g. the run's start snapshot)")
    g.add_argument("--pinned-columns-json", default=None, help='{"states": [...], "events": [...]}')
    v.add_argument("--pinned-columns-label", default=None)
    v.add_argument("--conflict-rule", choices=("strict", "off"), default="strict")
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    a.pinned_json = json.load(open(a.pinned_columns_json)) if a.pinned_columns_json else None
    out, _res = run_v2(a)
    text = json.dumps(out, indent=1, sort_keys=True, default=str)
    if a.out:
        with open(a.out, "x") as fh:
            fh.write(text)
    else:
        print(text)
    return 3 if "refused" in out else 0


if __name__ == "__main__":
    sys.exit(main())
