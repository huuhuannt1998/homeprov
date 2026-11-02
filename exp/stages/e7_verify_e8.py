"""E7 (round 13, 2026-10-08): verifier for sealed coverage, stall-proof sealing and escrow.

monitor/monitor.py (HOMEPROV_COVERAGE=1) now appends a record at every poll carrying, from the copy the roots were
computed from, the row watermark wm (largest state_id and event_id), the sealing cutoff through, the start of the
re-read window since, the copy time copy_at and the poll counter seq_local; a segment sealed by an earlier poll carries
that poll's sealed_at, seal_seq and wm, and heads of polls whose record failed ride in backlog. This verifier uses them.
It recomputes with the monitor's own load() and commit() (no second implementation), loaded as e6_namemap.py does.

For each record R in chain order (a record without coverage fields is checked by the existing rule: the root over every
current row of the segment, attributable iff the row count did not rise, as exp/stages/e_c_write_time.py and
reproduce/verify_all.py do):
  1. sealed segments: the root over the CURRENT rows of the segment whose key is <= the sealing poll's wm (per table)
     must reproduce the anchored root. A mismatch is a violation and is ATTRIBUTABLE: a sealed row was edited, deleted
     or re-keyed, or a row was inserted with a forged low key. Rows with a larger key are LATE rows; they never enter the
     recomputation, so added rows cannot make an edit ambiguous.
  2. empty sealed time and late rows: a segment's first cover is the first known poll P with since(P) <= start and
     end <= through(P). If no segment was sealed at P, the segment held no row then. A current row in it with key <=
     wm(P) existed when it was sealed empty: ATTRIBUTABLE (moved in, or a forged key). Any other late row was committed
     after copy_at(Q) for every poll Q with wm(Q) < key; if the latest such copy_at minus the row's timestamp exceeds
     LATE_BOUND the row is an ATTRIBUTABLE backdated insertion, else a benign late row (reported, outside the guarantee).
  2b. keylog (E7 code review B1): every key range a poll observed for the first time is recomputed over the current
     rows; a mismatch (a row changed, re-timed, made visible, deleted, or inserted into the range after that poll) is
     attributable, and every second the range's rows sit in or sat in when first observed is flagged (the per-row hash
     prefixes only rank the suspects: the writer of the rows can steer them). This closes key reservation (a row parked in the future,
     an unjoinable row, an explicit key gap) that made a backdated row look like a benign late row. A segment whose
     first-cover poll's roots are not all known (n_sealed) is root_unknown, never "sealed empty" (review M3). An
     attributable minute or hour violation is localised to the seconds of its late rows, unless a flagged second inside
     it already explains it (review M1). Rows with a malformed timestamp are listed (review M2).
  3. intervals: on the poll timeline (not the chain order, since an anchor can commit records late and out of order),
     every run of polls whose append the monitor saw fail (their heads are in a backlog: anchor_unreachable, with how
     many were committed late anyway), of unobservable polls (evidence_unobservable), of unrecorded polls, every gap
     between polls longer than GAP_S (monitor_silent) and every counter restart (monitor_restarted) is reported with its
     bounds, the segments sealed inside it, and the seconds sealed from a copy taken after it. These are reports, never
     detections.
  4. recovery (with --escrow): for every flagged second, the escrow line whose recomputed root equals the anchored root,
     and the original closure fields of each changed, removed or added row next to the current ones; --restore-out writes
     a copy of the recorder with the escrowed closure fields restored (closure scheme), so the release's own logbook
     processor can render the original displayed cause outside the hub; its recomputed roots are checked.
  5. benign floor: untouched anchored one-second segments that violate, and untouched seconds holding an attributable
     row, each case listed.
LATE_BOUND and GAP_S are explicit parameters, fixed before a run, and recorded in the output. With --trials, every trial
is scored on its one-second segment (the paper's unit) next to the existing rule's verdict, and the benign floor uses the
paper's counting rule (reproduce/verify_all.py touched_segments).

usage:
  e7_verify.py verify --chain CHAIN.jsonl[.gz] --db RECORDER.db --late-bound S --gap-s S [--snapshot-at T]
               [--window T0 T1] [--scheme closure|row|stable|wholerow] [--escrow ESCROW.jsonl]
               [--trials RESULT_OR_REPORT.json ...] [--restore-out DB] [--sign-pubkey PUBKEY.pem] [--out FILE]
               [--monitor-dir DIR]
  e7_verify.py late-delays --chain CHAIN --db RECORDER.db [--snapshot-at T] [--window T0 T1] [--scheme S] [--out FILE]
               (the benign late-row delays of an earlier chain: the evidence LATE_BOUND is fixed from)
Prints one JSON document (or writes --out, never overwriting). The recorder is read from a private copy.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import gzip
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_MONITOR_DIR = os.path.join(REPO, "monitor")


# ------------------------------------------------------------------------------------------------ the monitor's code
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


def load_monitor(scheme, scratch, monitor_dir=DEFAULT_MONITOR_DIR):
    """The shipped monitor module for `scheme` ('wholerow' via monitor_wholerow.py, which patches monitor.py)."""
    env = {"HOMEPROV_SCRATCH": scratch, "HOMEPROV_DB": os.path.join(scratch, "unused.db"),
           "HOMEPROV_SCHEME": "closure" if scheme == "wholerow" else scheme, "HOMEPROV_ENCODING": None,
           "HOMEPROV_NAMEMAP_DIR": None, "HOMEPROV_ESCROW_DIR": None, "HOMEPROV_CLOCK_FILE": None,
           "HOMEPROV_COVERAGE": "1", "HOMEPROV_KEYLOG": "1", "HOMEPROV_MAX_RECORD_BYTES": None,
           "HOMEPROV_MAX_PARTS": None}
    if scheme == "wholerow":
        sys.path.insert(0, monitor_dir)
        WR = load_module(os.path.join(monitor_dir, "monitor_wholerow.py"), "e7_monitor_wholerow", env)
        return WR.M
    M = load_module(os.path.join(monitor_dir, "monitor.py"), "e7_monitor_" + scheme, env)
    assert M.SCHEME == scheme
    return M


# ------------------------------------------------------------------------------------------------ chain
def read_lines(path):
    return (gzip.open(path, "rt") if path.endswith(".gz") else open(path)).read().splitlines()


def vconnect(db):
    """A connection that decodes TEXT leniently, as the coverage monitor does (re-review R2): a value that is not valid
    UTF-8 must not stop the verifier."""
    con = sqlite3.connect(db)
    con.text_factory = lambda b: b.decode("utf-8", "surrogateescape")
    return con


def kparse(key):
    t, _, num = key.partition(":")
    return ("states" if t == "s" else "events"), int(num)


def under(n, wm):
    """Was the node's row in a copy whose watermark is wm? (keys are assigned max+1 in commit order)."""
    table, k = kparse(n[1])
    w = (wm or {}).get(table)
    return w is not None and k <= w


def parse_chain(lines, scheme=None, t0=None, tsnap=None):
    """Monitor records, the poll timeline and the first-written root of every segment.

    Polls are keyed (epoch, seq_local); the epoch advances when a record's own seq_local does not exceed an earlier
    one (the monitor lost its state and restarted its counter); a continuation record ("part" >= 2) is the same poll.
    Records without coverage fields follow the existing rule: first write wins among records stamped in [t0, tsnap].
    A coverage root is dated by its SEALING poll, not by the record that carried it: a root frozen before the recorder
    snapshot is valid even when it reached the chain after it (review M3). The timeline holds every poll up to tsnap,
    because the first cover of an early segment may precede t0."""
    recs, polls, roots, all_roots, conflicted = [], {}, {}, {}, []
    seen_by_poll = collections.defaultdict(lambda: collections.defaultdict(set))
    other = collections.Counter()
    epoch, max_seq, max_ts = 0, 0, None
    schemes = collections.Counter()

    def after_snap(t):
        return tsnap is not None and t is not None and t > tsnap

    def add_root(k, a, eff_ts):
        if after_snap(eff_ts):
            return
        all_roots.setdefault(k, a)
        if (t0 is None or eff_ts >= t0) and k not in roots:
            roots[k] = a

    for line in lines:
        if not line.strip():
            continue
        try:
            cr = json.loads(line)
        except ValueError:
            other["unparsable"] += 1
            continue
        p = cr.get("payload") or {}
        if p.get("observer") != "external-monitor":
            other["marker" if p.get("marker") else "other"] += 1
            continue
        # records written before the scheme field existed (2026-10-02) were sealed with the row scheme
        rs = p.get("scheme", "row")
        schemes[rs] += 1
        if scheme is not None and rs != scheme:
            other["other_scheme"] += 1
            continue
        ts = p.get("ts") or cr.get("recv_ts") or 0.0
        cov = "coverage" in p and "seq_local" in p
        if not cov and after_snap(ts):
            continue
        # a continuation record ("part" >= 2) carries more of the same poll's items; it is not another poll
        cont = cov and isinstance(p.get("part"), int) and p["part"] >= 2
        r = {"chain_seq": cr.get("seq"), "ts": ts, "coverage": cov, "continuation": cont,
             "unobservable": bool(p.get("evidence_unobservable")),
             "encoding": p.get("encoding", "v1"), "n_sealed": sum(len(v) for v in (p.get("sealed") or {}).values()
                                                                   if isinstance(v, dict))}
        if cov:
            s_ = int(p["seq_local"])
            # A lower counter starts a new epoch only when time has moved on: an anchor can commit a record late, after
            # the record of a later poll (seen in the E7 dry runs as seq_local 73 before 72), and that is the same
            # monitor, not a restart.
            same_poll = (epoch, s_) in polls and polls[(epoch, s_)]["ts"] == ts
            if s_ <= max_seq and not cont and not same_poll and (max_ts is None or ts > max_ts):
                epoch, max_seq, max_ts = epoch + 1, 0, None
            max_seq = max(s_, max_seq)
            r["poll"] = (epoch, s_)
            heads = [dict(h, _own=False) for h in (p.get("backlog") or [])] + [dict(p, _own=True)]
            for h in heads:
                if after_snap(h.get("ts")):
                    continue
                if h.get("ts") is not None:
                    max_ts = h["ts"] if max_ts is None else max(max_ts, h["ts"])
                key = (epoch, int(h["seq_local"]))
                cur = polls.get(key)
                if cur is None or (h["_own"] and not cur["own"] and h.get("through") is not None) \
                        or (cur.get("through") is None and h.get("through") is not None):
                    keep = {k_: cur[k_] for k_ in ("keylog_chunks", "_own_seen") if cur and k_ in cur}
                    polls[key] = {**keep, "key": key, "ts": h.get("ts"), "copy_at": h.get("copy_at"), "wm": h.get("wm"),
                                  "since": h.get("since"), "through": h.get("through"),
                                  "own": h["_own"] or bool(cur and cur["own"]),
                                  "unobservable": bool(h.get("evidence_unobservable") or h.get("unobservable")),
                                  "reason": h.get("reason") or h.get("unobservable"),
                                  "n_sealed": h.get("n_sealed"), "keylog": h.get("keylog"),
                                  "chain_seq": cr.get("seq") if h["_own"] else (cur or {}).get("chain_seq"),
                                  "recv_ts": cr.get("recv_ts") if h["_own"] else (cur or {}).get("recv_ts"),
                                  "in_backlog": bool(cur and cur.get("in_backlog"))}
                    cur = polls[key]
                if h["_own"] and not cont:
                    cur["own"] = True
                    if cur.get("chain_seq") is None or not cur.get("_own_seen"):
                        cur["chain_seq"], cur["recv_ts"], cur["_own_seen"] = cr.get("seq"), cr.get("recv_ts"), True
                if not h["_own"] and not h.get("keylog_part"):
                    # the monitor carries a head in its backlog only after it saw that poll's append fail (a keylog
                    # piece of a poll whose own record went out is not such a head)
                    cur["in_backlog"] = True
                # keylog sub-ranges of a poll can arrive in its own record, its continuation records and backlog
                # pieces: they are merged per poll
                chunks = cur.setdefault("keylog_chunks", {})
                for t, es in (h.get("keylog") or {}).items():
                    for e in (es if isinstance(es, list) else [es]):
                        if isinstance(e, dict):
                            chunks.setdefault((t, int(e.get("from", 0)), int(e.get("to", 0))), e)
            for c in p.get("conflicted") or []:
                if not after_snap(ts):
                    conflicted.append(dict(c, chain_seq=cr.get("seq")))
                # The anchor refused this frozen root because it already held another for the segment. The monitor's
                # own root, carried here, is what the monitor sealed: it is checked like any frozen root (unless a
                # monitor record anchored one first), and the disagreement is reported as such.
                if not r["unobservable"] and "seal_seq" in c:
                    k = (c.get("gran"), str(c.get("seg")))
                    pk = (epoch, int(c["seal_seq"]))
                    seen_by_poll[pk][k[0]].add(k[1])
                    add_root(k, {"acc": c.get("acc"), "n": c.get("n"), "encoding": p.get("encoding", "v1"),
                                 "chain_seq": cr.get("seq"), "record_ts": ts, "wm": c.get("wm"), "poll": pk,
                                 "sealed_at": c.get("sealed_at"), "conflicted": True,
                                 "anchor_holds": c.get("anchored_acc")}, c.get("sealed_at") or ts)
        if not after_snap(ts):
            recs.append(r)
        if r["unobservable"]:
            continue
        for g, segs in (p.get("sealed") or {}).items():
            if not isinstance(segs, dict):
                continue
            for seg, v in segs.items():
                if not isinstance(v, dict):
                    continue
                k = (g, str(seg))
                a = {"acc": v.get("acc"), "n": v.get("n"), "encoding": p.get("encoding", "v1"),
                     "chain_seq": cr.get("seq"), "record_ts": ts, "wm": None, "poll": None, "sealed_at": None}
                if cov and "seal_seq" in v:
                    a.update(wm=v.get("wm"), poll=(epoch, int(v["seal_seq"])), sealed_at=v.get("sealed_at"))
                elif cov:
                    a.update(wm=p.get("wm"), poll=(epoch, int(p["seq_local"])), sealed_at=ts)
                if a["poll"] is not None:
                    seen_by_poll[a["poll"]][g].add(str(seg))
                # step 1 checks the first root sealed (coverage) or anchored (earlier records) inside the window, as
                # the existing verifiers do; whether a segment was sealed with rows at all (step 2) is read from every
                # record, so a seal just before t0 counts
                add_root(k, a, a["sealed_at"] if cov else ts)
    return {"records": recs, "polls": polls, "roots": roots, "all_roots": all_roots, "conflicted": conflicted,
            "seen_by_poll": seen_by_poll, "other": dict(other), "schemes": dict(schemes), "epochs": epoch + 1}


class Timeline:
    """First cover of a segment, and the late-row bracket, from the known polls."""

    def __init__(self, polls):
        self.valid = sorted((p for p in polls.values() if p["through"] is not None and p["wm"] is not None),
                            key=lambda p: p["key"])
        # covered seconds assigned to the first poll that covers them: disjoint [lo, hi) pieces
        self.pieces = []                 # (lo, hi, poll)
        union = []                       # sorted disjoint [lo, hi)
        for p in self.valid:
            lo, hi = int(p["since"]), int(p["through"])
            for a, b in self._minus(lo, hi, union):
                self.pieces.append((a, b, p))
            union = self._merge(union + [(lo, hi)])
        self.pieces.sort(key=lambda x: x[0])
        self._starts = [x[0] for x in self.pieces]
        self.bracket = {}
        for table in ("states", "events"):
            pts = sorted(((-1 if p["wm"].get(table) is None else p["wm"][table]), p["copy_at"]) for p in self.valid
                         if p.get("copy_at") is not None)
            best, out = None, []
            for w, c in pts:
                best = c if best is None else max(best, c)
                out.append((w, best))
            self.bracket[table] = out

    @staticmethod
    def _merge(iv):
        out = []
        for a, b in sorted(i for i in iv if i[0] < i[1]):
            if out and a <= out[-1][1]:
                out[-1] = (out[-1][0], max(out[-1][1], b))
            else:
                out.append((a, b))
        return out

    @staticmethod
    def _minus(lo, hi, union):
        out, cur = [], lo
        for a, b in union:
            if b <= cur or a >= hi:
                continue
            if a > cur:
                out.append((cur, min(a, hi)))
            cur = max(cur, b)
        if cur < hi:
            out.append((cur, hi))
        return out

    def first_cover(self, start, end):
        """The first poll whose [since, through) holds every second of [start, end), or None."""
        i = bisect.bisect_right(self._starts, end - 1) - 1
        if i < 0:
            return None
        lo, hi, p = self.pieces[i]
        if not (lo <= end - 1 < hi):
            return None
        # the last second of the segment is covered first by p; the segment is covered by p only if p read its start
        return p if int(p["since"]) <= start and end <= int(p["through"]) else None

    def committed_after(self, table, key):
        """Latest copy time of a poll whose copy could not hold this key (wm < key): the row was committed after it."""
        pts = self.bracket.get(table) or []
        i = bisect.bisect_left(pts, (key, -float("inf"))) - 1
        return pts[i][1] if i >= 0 else None


# ------------------------------------------------------------------------------------------------ verification
def fold(M, rows, g, seg, enc):
    return ((M.commit(rows, encoding=enc).get(g) or {}).get(seg)) if rows else None


def hx(v):
    return v.hex() if isinstance(v, (bytes, bytearray, memoryview)) else v


def describe(n):
    """Readable fields of one node (what the closure scheme hashes, with the BLOBs in hex)."""
    d = {"key": n[1], "ts": n[0], "label": n[5], "context_id": hx(n[3]), "parent_id": hx(n[4])}
    try:
        d["content"] = json.loads(n[2])
    except (TypeError, ValueError):
        d["content_hex"] = hx(n[2])
    if len(n) == 9:
        d.update(user_id=hx(n[6]), old_state_id=n[7], last_changed_ts=n[8])
    elif len(n) == 7:
        f = n[6]
        d["columns"] = {f[i]: hx(f[i + 1]) for i in range(1, len(f) - 1, 2)}
    return d


MALFORMED_LIST_CAP = 200


def malformed_rows(M, db):
    """Rows whose timestamp is not a finite number (TEXT, BLOB, NULL, infinite): the monitor's guarded load never folds
    them (review M2). Listed with their key, the timestamp's type and its quoted value."""
    con = vconnect(db)
    out = []
    for t in ("states", "events"):
        k, c = M.KEY_COL[t], M.TS_COL[t]
        for key, typ, val in con.execute("SELECT %s, typeof(%s), quote(%s) FROM %s WHERE NOT (%s) ORDER BY %s"
                                         % (k, c, c, t, M.TS_OK.format(c=c), k)):
            out.append({"key": "%s:%d" % (t[0], key), "type": typ, "value": str(val)[:80]})
    con.close()
    return out


RAW_TABLES = ("states", "events", "states_meta", "event_types", "event_data", "state_attributes")


def invalid_text_rows(M, db):
    """Rows holding a TEXT value that is not valid UTF-8 (re-review R2), with the columns concerned. The monitor and
    this verifier commit such a value by its raw bytes; the rows are listed because a recorder never writes them."""
    con = vconnect(db)
    out = []
    for t in RAW_TABLES:
        try:
            cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % t)]
            for r in con.execute("SELECT rowid, * FROM %s" % t):
                bad = [c for c, v in zip(cols, r[1:]) if M.has_raw_bytes(v)]
                if bad:
                    out.append({"table": t, "key": ("%s:%d" % (t[0], r[0])) if t in ("states", "events")
                                else "%s:%d" % (t, r[0]), "columns": bad})
        except sqlite3.Error:
            continue
    con.close()
    return out


def loadable_copy(M, db, bad):
    """The recorder copy the monitor's load() reads: the private copy itself, or, when it holds malformed rows, a copy
    without them, so a load that is not guarded (the whole-row entry point) cannot fail on them either."""
    if not bad:
        return db
    dst = db + ".loadable.db"
    shutil.copy2(db, dst)
    con = vconnect(dst)
    for t in ("states", "events"):
        con.execute("DELETE FROM %s WHERE NOT (%s)" % (t, M.TS_OK.format(c=M.TS_COL[t])))
    con.commit()
    con.close()
    return dst


def check_keylog(M, db, polls):
    """Recompute every committed key range over the current rows (review B1). A mismatch means a row first observed by
    that poll was changed, re-timed, made visible, deleted, or a row was inserted into the range later: attributable.

    Every row of a failed range is a suspect (re-review R1): the 32-bit hash prefixes are chosen by whoever writes the
    rows (a birthday search plus a decoy row hides a forged row from them), so they only RANK the suspects ("likely":
    changed, added, removed) and never clear one. The seconds of a failed range are every second its rows sit in now
    and every second they sat in when first observed (the record names it, re-review R3), so a row deleted, re-timed
    or made malformed before its second was sealed still flags that second."""
    out, checked, starts = [], 0, []
    covered = collections.defaultdict(list)
    for key in sorted(polls):
        p = polls[key]
        for (t, lo, hi), e in sorted((p.get("keylog_chunks") or {}).items()):
            if e.get("start"):
                starts.append({"poll": list(key), "table": t, "from_key": lo})
            covered[t].append((lo, hi, key))
            if hi <= lo:
                continue
            checked += 1
            rows = M.keylog_rows(db, t, lo, hi)
            acc = M.ZERO
            for r in rows:
                acc = M.H(acc + r[1])
            if len(rows) == e.get("n") and acc.hex() == e.get("acc"):
                continue
            logged = {lo + int(x[0]): x for x in (e.get("rows") or [])}
            now = {r[0]: (r[1].hex()[:8], r[2]) for r in rows}
            changed = sorted(k for k in now if k in logged and now[k][0] != logged[k][1])
            added = sorted(k for k in now if k not in logged)
            removed = sorted(k for k in logged if k not in now)
            pre = t[0] + ":"

            def sat(k):
                x = logged.get(k)
                return str(x[2]) if x is not None and len(x) > 2 and x[2] is not None else None

            def row(k):
                ts = now[k][1] if k in now else None
                return {"key": pre + str(k), "ts": ts if M.ts_ok(ts) else (None if ts is None else str(ts)[:80]),
                        "second": str(int(ts // 1.0)) if M.ts_ok(ts) else None, "first_observed_second": sat(k)}
            suspects = [row(k) for k in sorted(set(now) | set(logged))]
            seconds = sorted({x for r_ in suspects for x in (r_["second"], r_["first_observed_second"]) if x},
                             key=int)
            out.append({"poll": list(key), "seq_local": key[1], "poll_ts": p.get("ts"), "table": t, "range": [lo, hi],
                        "n_logged": e.get("n"), "n_now": len(rows), "localized": bool(changed or added or removed),
                        "changed": [row(k) for k in changed], "added": [row(k) for k in added],
                        "removed": [pre + str(k) for k in removed],
                        "likely": [row(k) for k in changed + added + removed],
                        "suspects": suspects, "seconds": seconds})
    # key ranges never committed: a poll whose keylog never reached the chain, or the keys between the last range of a
    # monitor and the first range of the same monitor restarted without its state (re-review R4); rows there are bound
    # only by the segment roots
    start_keys = {(x["table"], x["from_key"]) for x in starts}
    holes = []
    for t, rs in covered.items():
        rs = sorted(set(rs))
        for (a_lo, a_hi, a_poll), (b_lo, b_hi, b_poll) in zip(rs, rs[1:]):
            if b_lo > a_hi:
                restart = (t, b_lo) in start_keys
                if restart and a_poll[0] == b_poll[0]:
                    continue                          # an epoch's own first range is not a hole
                holes.append({"table": t, "range": [a_hi, b_lo],
                              "why": "monitor_restarted_without_its_state" if restart else "keylog_not_on_chain"})
    return out, checked, starts, holes


def check_signatures(M, lines, pubkey_path=None, allow_unsigned=False):
    """Monitor records against the published Ed25519 key (E8 design A2), with the monitor's own record_signing_bytes().
    With a key, ONLY records whose signature verifies under it are used (E8 review BE8): a record signed under another
    key, with a bad signature, or with no signature at all was not shown to be the monitor's (the anchor host holds the
    append key and can store an unsigned record of its own making), so it is listed and left out of everything below
    (roots, keylog, coverage); the gap it leaves is then reported as a missing poll. allow_unsigned keeps unsigned
    records, for chains written before signatures existed. Without a key, only counts."""
    if not pubkey_path:
        n = sum(1 for x in lines if x.strip() and '"sig"' in x)
        return list(lines), {"checked": False, "records_with_signature": n}
    pub = M.load_public_key(pubkey_path)
    fp = M.public_key_fingerprint(pub)
    keep, by = [], collections.defaultdict(list)
    for line in lines:
        if not line.strip():
            continue
        try:
            cr = json.loads(line)
        except ValueError:
            keep.append(line)
            continue
        p = cr.get("payload") or {}
        if p.get("observer") != "external-monitor":
            keep.append(line)
            continue
        st = M.verify_record_signature(p, pub, fp)
        by[st].append(cr.get("seq"))
        if st == "ok" or (st == "unsigned" and allow_unsigned):
            keep.append(line)
    excluded = by["bad_signature"] + by["wrong_key"] + ([] if allow_unsigned else by["unsigned"])
    return keep, {"checked": True, "pubkey_fp": fp, "allow_unsigned": bool(allow_unsigned),
                  "monitor_records": sum(len(v) for v in by.values()),
                  "signed_ok": len(by["ok"]), "unsigned": len(by["unsigned"]), "unsigned_chain_seq": by["unsigned"][:200],
                  "unsigned_excluded": [] if allow_unsigned else by["unsigned"],
                  "bad_signature": by["bad_signature"], "wrong_key": by["wrong_key"],
                  "excluded_from_verification": sorted(x for x in excluded if x is not None)}


def verify(M, db, lines, late_bound, gap_s, scheme=None, t0=None, t1=None, tsnap=None, escrow_lines=None,
           restore_out=None, sign_pubkey=None, allow_unsigned=False):
    if late_bound is None or gap_s is None:
        raise ValueError("late_bound and gap_s are explicit parameters fixed before the run")
    lines, sigs = check_signatures(M, lines, sign_pubkey, allow_unsigned)
    P = parse_chain(lines, scheme, t0, tsnap)
    roots, polls = P["roots"], P["polls"]
    TL = Timeline(polls)
    W = dict(M.GRAN)
    bad = malformed_rows(M, db)
    raw_text = invalid_text_rows(M, db)
    load_since = (int(t0 // 3600) - 1) * 3600.0 if t0 is not None else None
    nodes = M.load(loadable_copy(M, db, bad), since=load_since)
    groups = {g: {} for g in W}
    for n in nodes:
        for g, w in W.items():
            groups[g].setdefault(str(int(n[0] // w)), []).append(n)

    def in_window(g, seg):
        w = W[g]
        return (t0 is None or t0 - w <= int(seg) * w) and (t1 is None or int(seg) * w <= t1 + w)

    row_verdicts = {}                     # row key -> {"ts", "verdict", "why", per granularity}

    def verdict_of(key, ts):
        return row_verdicts.setdefault(key, {"key": key, "ts": ts, "second": str(int(ts // 1.0)) if M.ts_ok(ts)
                                             else None, "verdict": "benign_late", "why": [],
                                             "committed_after_lower_bound_s": None, "first_observed_second": None})

    def judge_late(n, g, seg, why_base, wm_ref):
        table, k = kparse(n[1])
        if under(n, wm_ref):
            v, why, lat = "attributable", "present_when_sealed_empty", None
        else:
            after = TL.committed_after(table, k)
            lat = None if after is None else round(after - n[0], 6)
            if lat is not None and lat > late_bound:
                v, why = "attributable", why_base
            else:
                v, why = "benign_late", "late_within_bound"
        cur = verdict_of(n[1], n[0])
        if lat is not None:
            cur["committed_after_lower_bound_s"] = lat
        cur["why"].append({"gran": g, "seg": seg, "verdict": v, "why": why})
        if v == "attributable":
            cur["verdict"] = "attributable"
        return v

    segs_out, viol, checked = {g: {"anchored_in_window": 0, "violated": 0, "violated_existing_rule": 0} for g in W}, [], []
    for (g, seg), a in sorted(roots.items(), key=lambda x: (x[0][0], int(x[0][1]))):
        if g not in W or not in_window(g, seg):
            continue
        segs_out[g]["anchored_in_window"] += 1
        checked.append((g, seg))
        rows = groups[g].get(seg, [])
        enc = a["encoding"]
        got_all = fold(M, rows, g, seg, enc)
        old_v = got_all is None or got_all["acc"] != a["acc"] or got_all["n"] != a["n"]
        d_n = None if got_all is None else got_all["n"] - a["n"]
        old = {"violation": old_v, "delta_n": d_n,
               "attributable": old_v and (d_n is None or d_n <= 0), "ambiguous": old_v and d_n is not None and d_n > 0}
        v = {"gran": g, "seg": seg, "anchored_n": a["n"], "chain_seq": a["chain_seq"], "existing_rule": old,
             "conflicted": bool(a.get("conflicted"))}
        if a["wm"] is None:
            v.update(rule="existing", violation=old_v, attributable=old["attributable"], ambiguous=old["ambiguous"])
        else:
            sealed_rows = [n for n in rows if under(n, a["wm"])]
            late = [n for n in rows if not under(n, a["wm"])]
            got = fold(M, sealed_rows, g, seg, enc)
            cv = got is None or got["acc"] != a["acc"] or got["n"] != a["n"]
            dn = (0 if got is None else got["n"]) - a["n"]
            v.update(rule="coverage", violation=cv, attributable=cv, ambiguous=False, sealed_at=a["sealed_at"],
                     seal_poll=list(a["poll"]), wm=a["wm"], n_sealed_now=len(sealed_rows), n_late=len(late),
                     mechanism=(None if not cv else "sealed_rows_removed" if dn < 0 else
                                "row_inserted_with_low_key_or_moved_in" if dn > 0 else "sealed_row_changed"))
            for n in late:
                judge_late(n, g, seg, "backdated_insertion", a["wm"])
        segs_out[g]["violated"] += bool(v["violation"])
        segs_out[g]["violated_existing_rule"] += bool(old_v)
        if v["violation"] or old_v:
            viol.append(v)

    # step 2: segments that were empty at their first cover. That inference needs every root the first-cover poll
    # sealed: a head says how many (n_sealed); with fewer known, the segment is root_unknown, never attributed (M3).
    seen = P["seen_by_poll"]

    def roots_complete(p, g):
        ns = (p.get("n_sealed") or {}).get(g)
        return ns is None or len(seen.get(p["key"], {}).get(g, ())) >= ns

    # a poll missing from the chain (a seq_local the monitor's own sequence skips, with no backlog head for it: the
    # record was dropped by the anchor host, or excluded as not the monitor's) may have been the first cover of the
    # seconds the next known poll covers, and may have sealed rows in them: those seconds are root_unknown, not empty
    # (E8 review ME8)
    gap_before, prev_k = {}, None
    for k in sorted(polls):
        gap_before[k] = (k[1] > 1) if (prev_k is None or prev_k[0] != k[0]) else (k[1] - prev_k[1] > 1)
        prev_k = k

    unsealed = collections.Counter()
    root_unknown = []
    for g, w in W.items():
        for seg, rows in groups[g].items():
            if not in_window(g, seg):
                continue
            start, end = int(seg) * int(w), (int(seg) + 1) * int(w)
            p = TL.first_cover(start, end)
            if p is None:
                if TL.valid:
                    unsealed[g] += len(rows)
                continue
            a = P["all_roots"].get((g, seg))
            if a is not None and (a["wm"] is None or a["poll"] <= p["key"]):
                continue                  # sealed with rows at its first cover (step 1), or an existing-rule record
            if not roots_complete(p, g) or gap_before.get(p["key"]):
                root_unknown.append({"gran": g, "seg": seg, "first_cover_poll": list(p["key"]), "rows": len(rows),
                                     "roots_known": len(seen.get(p["key"], {}).get(g, ())),
                                     "n_sealed": (p.get("n_sealed") or {}).get(g),
                                     "why": ("a_poll_before_its_first_cover_is_missing_from_the_chain"
                                             if gap_before.get(p["key"]) else "first_cover_roots_incomplete")})
                continue
            for n in rows:
                judge_late(n, g, seg, "backdated_into_empty_sealed_time", p["wm"])

    # step 2b: the keylog (review B1). Rows changed, re-timed, made visible or inserted into a committed key range after
    # their first observation are attributable; their current seconds are flagged.
    keylog_viol, keylog_checked, keylog_starts, keylog_holes = check_keylog(M, db, polls)
    keylog_seconds = set()
    for kv in keylog_viol:
        keylog_seconds |= set(kv["seconds"])
        likely = {x["key"] for x in kv["likely"]}
        for x in kv["suspects"]:
            if x["ts"] is None and x["key"] not in likely:
                continue                          # removed rows have no current row; their seconds are in kv["seconds"]
            cur = verdict_of(x["key"], x["ts"])
            if cur.get("first_observed_second") is None:
                cur["first_observed_second"] = x.get("first_observed_second")
            if x["key"] in likely:
                cur["why"].append({"gran": "keylog", "seg": None, "verdict": "attributable",
                                   "why": ("inserted_into_observed_key_range" if any(x["key"] == a["key"]
                                                                                      for a in kv["added"])
                                           else "removed_after_first_observation" if x["ts"] is None
                                           else "changed_after_first_observation"), "poll": kv["poll"]})
                cur["verdict"] = "attributable"
            else:
                cur["why"].append({"gran": "keylog", "seg": None, "verdict": "suspect",
                                   "why": "in_a_failed_key_range", "poll": kv["poll"]})
                if cur["verdict"] != "attributable":
                    cur["verdict"] = "keylog_suspect"

    # coarse violations (review M1): a minute or hour violation whose seconds are all intact comes from rows that were
    # late for their second but under the coarse segment's wm; those rows' seconds are the localisation. When a second
    # inside it is already flagged, that second explains the coarse violation and nothing else is localised (in the E7
    # dry runs a laundered second's minute otherwise flagged a benign late row of the same minute).
    fine = ({v["seg"] for v in viol if v["gran"] == "second" and v["attributable"]}
            | {r["second"] for r in row_verdicts.values() if r["verdict"] == "attributable" and r["second"]})
    for v in viol:
        if v["gran"] == "second" or not v["attributable"] or v["rule"] != "coverage":
            continue
        w = int(W[v["gran"]])
        if any(int(x) // w == int(v["seg"]) for x in fine):
            v["localized_seconds"] = []
            v["explained_by_flagged_seconds"] = sorted((x for x in fine if int(x) // w == int(v["seg"])), key=int)
            continue
        cand = [n for n in groups[v["gran"]].get(v["seg"], []) if under(n, v["wm"]) and n[1] in row_verdicts]
        v["localized_seconds"] = sorted({str(int(n[0] // 1.0)) for n in cand}, key=int)

    attributable_rows = sorted((r for r in row_verdicts.values() if r["verdict"] == "attributable"),
                               key=lambda r: ((r["ts"] if M.ts_ok(r["ts"]) else float("inf")), r["key"]))
    benign_rows = sorted((r for r in row_verdicts.values() if r["verdict"] == "benign_late"),
                         key=lambda r: (r["ts"], r["key"]))
    suspect_rows = sorted((r for r in row_verdicts.values() if r["verdict"] == "keylog_suspect"),
                          key=lambda r: (r["ts"] if M.ts_ok(r["ts"]) else float("inf"), r["key"]))
    # detected = attributable: every coverage violation, an existing-rule violation whose row count did not rise, every
    # second holding an attributable row, and the localised seconds of attributable minute and hour violations. An
    # existing-rule violation whose count rose stays ambiguous, as before.
    flagged_seconds = sorted({v["seg"] for v in viol if v["gran"] == "second" and v["attributable"]}
                             | {r["second"] for r in attributable_rows if r["second"] is not None}
                             | {s_ for v in viol for s_ in v.get("localized_seconds", [])}
                             | keylog_seconds, key=int)
    ambiguous_seconds = sorted({v["seg"] for v in viol if v["gran"] == "second" and v["ambiguous"]}
                               - set(flagged_seconds), key=int)
    flagged_segments = [{"gran": v["gran"], "seg": v["seg"], "rule": v["rule"], "mechanism": v.get("mechanism"),
                         "localized_seconds": v.get("localized_seconds")} for v in viol if v["attributable"]]

    # step 3: intervals in which the monitor was not appending or not observing. They are reported with their cause
    # (they are never detections; a frozen root sealed inside one is verified by steps 1-2 like any other). They are
    # built on the POLL timeline, not on the order of records in the chain: an anchor can commit a record late, after a
    # later poll's record, and a poll whose append the monitor saw fail (its head is in a later backlog) may still have
    # its own record on the chain, committed late (both seen in the E7 dry runs).
    by_poll = collections.defaultdict(list)            # segments by sealing poll (review m5)
    for (g, s_), r in roots.items():
        if r["poll"] is not None:
            by_poll[r["poll"]].append((g, s_))
    viol_keys = {(v["gran"], v["seg"]) for v in viol if v["violation"]}
    poll_keys = sorted(polls)

    # observation gaps (review M4): consecutive observable polls further apart than GAP_S, or with unobservable or
    # unrecorded polls between them. Every second in [through(before), through(after)) was sealed from a copy taken
    # after the gap, so a change made during the gap is not detectable there; those seconds are listed.
    obs_gaps, prev, mid = [], None, []
    for k in poll_keys:
        p = polls[k]
        if p["through"] is None:
            mid.append(p)
            continue
        if prev is not None:
            same = prev["key"][0] == k[0]
            jump = (k[1] - prev["key"][1]) if same else None
            unobs = [q for q in mid if q["unobservable"]]
            if not same or jump > 1 or (p["ts"] - prev["ts"] > gap_s):
                lo, hi = int(prev["through"]), int(p["through"])
                nonempty = sorted((x for x in groups["second"] if lo <= int(x) < hi), key=int)
                obs_gaps.append({"from_ts": prev["ts"], "to_ts": p["ts"], "from_poll": list(prev["key"]),
                                 "to_poll": list(k),
                                 "kind": ("monitor_restarted" if not same else "evidence_unobservable" if unobs else
                                          "polls_unrecorded" if jump > 1 else "monitor_silent"),
                                 "unobservable_polls": len(unobs),
                                 "reasons": sorted({str(q.get("reason")) for q in unobs}),
                                 "seconds_sealed_after_gap": {"from": lo, "to": hi, "n": max(0, hi - lo),
                                                              "nonempty_n": len(nonempty),
                                                              "nonempty": nonempty[:200]}})
        prev, mid = p, []
    if prev is not None and any(q["unobservable"] for q in mid):
        obs_gaps.append({"from_ts": prev["ts"], "to_ts": None, "from_poll": list(prev["key"]), "to_poll": None,
                         "kind": "evidence_unobservable", "unobservable_polls": sum(1 for q in mid if q["unobservable"]),
                         "reasons": sorted({str(q.get("reason")) for q in mid if q["unobservable"]}),
                         "seconds_sealed_after_gap": None})

    def affected(p):
        return p["in_backlog"] or p["unobservable"]

    def interval(before, inside, after, kind_hint=None):
        """One reported interval: bounded by the last unaffected poll before it and the first one after it."""
        # with nothing before it (the chain's first polls unrecorded, or excluded), the interval starts at the epoch
        lo_key = before["key"] if before else ((inside[0] if inside else after)["key"][0], 0)
        hi_key = after["key"] if after else None
        seqs = [q["key"][1] for q in inside]
        span_lo = lo_key[1]
        span_hi = hi_key[1] if hi_key else (max(seqs) + 1 if seqs else span_lo + 1)
        unrecorded = max(0, (span_hi - span_lo - 1) - len(inside)) if not kind_hint else None
        causes = sorted({"anchor_unreachable" for q in inside if q["in_backlog"]}
                        | {"evidence_unobservable" for q in inside if q["unobservable"]}
                        | ({"polls_unrecorded"} if unrecorded else set()) | ({kind_hint} if kind_hint else set()))
        kind = next((c for c in ("monitor_restarted", "anchor_unreachable", "evidence_unobservable", "polls_unrecorded",
                                 "monitor_silent") if c in causes), "monitor_silent")
        late = [q for q in inside if q["in_backlog"] and q["own"] and q.get("recv_ts") is not None]
        during = sorted((gs for q in inside for gs in by_poll.get(q["key"], [])), key=lambda x: (x[0], int(x[1])))
        f_ts = before["ts"] if before else (inside[0]["ts"] if inside else None)
        t_ts = after["ts"] if after else None
        return {"from_ts": f_ts, "to_ts": t_ts,
                "duration_s": None if f_ts is None or t_ts is None else round(t_ts - f_ts, 3),
                "from_chain_seq": before.get("chain_seq") if before else None,
                "to_chain_seq": after.get("chain_seq") if after else None,
                "seq_local_jump": (span_hi - span_lo) if hi_key and hi_key[0] == lo_key[0] else None,
                "polls_in_backlog": sum(1 for q in inside if q["in_backlog"]), "polls_unrecorded": unrecorded,
                "kind": kind, "causes": causes,
                "unobservable_polls": sum(1 for q in inside if q["unobservable"]),
                "reasons": sorted({str(q.get("reason")) for q in inside if q["unobservable"]}),
                "late_committed_polls": len(late),
                "max_commit_delay_s": max((round(q["recv_ts"] - q["ts"], 3) for q in late), default=None),
                "segments_sealed_during": len(during),
                "segments_sealed_during_violated": sum(1 for gs in during if gs in viol_keys),
                "seconds_sealed_during": [x for g, x in during if g == "second"][:200],
                "seconds_sealed_after_gap": [o["seconds_sealed_after_gap"] for o in obs_gaps
                                             if o["seconds_sealed_after_gap"] and f_ts is not None
                                             and o["from_ts"] >= f_ts and (t_ts is None or o["to_ts"] <= t_ts)]}

    stalls = []
    by_epoch = collections.defaultdict(list)
    for k in poll_keys:
        by_epoch[k[0]].append(polls[k])
    last_of_prev_epoch = None
    for ep in sorted(by_epoch):
        seq_ = by_epoch[ep]
        if last_of_prev_epoch is not None:
            first_ok = next((q for q in seq_ if not affected(q)), None)
            stalls.append(interval(last_of_prev_epoch, [], first_ok, "monitor_restarted"))
        good, run = None, []
        for q in seq_:
            jump = (q["key"][1] - (run[-1]["key"][1] if run else good["key"][1] if good else 0))
            if affected(q):
                run.append(q)
                continue
            if run or jump > 1:
                stalls.append(interval(good, run, q))
            elif good is not None and q["ts"] - good["ts"] > gap_s:
                stalls.append(interval(good, [], q, "monitor_silent"))
            good, run = q, []
        if run:
            stalls.append(interval(good, run, None))
        last_of_prev_epoch = good or (seq_[-1] if seq_ else None)
    if t0 is not None:
        stalls = [x for x in stalls if x["to_ts"] is None or x["to_ts"] >= t0]

    # step 4: escrow recovery
    recovery = None
    if escrow_lines is not None:
        recovery = recover(M, escrow_lines, roots, groups, flagged_seconds, restore_out, db, keylog_viol, polls)

    return {"P": P, "TL": TL, "segments": segs_out, "violations": viol, "attributable_rows": attributable_rows,
            "benign_late_rows": benign_rows, "rows_in_unsealed_time": dict(unsealed), "flagged_seconds": flagged_seconds,
            "ambiguous_seconds": ambiguous_seconds, "flagged_segments": flagged_segments, "stalls": stalls,
            "observation_gaps": obs_gaps, "root_unknown_segments": root_unknown,
            "keylog": {"ranges_checked": keylog_checked, "violations": len(keylog_viol), "starts": keylog_starts,
                       "uncommitted_key_ranges": keylog_holes},
            "keylog_violations": keylog_viol, "malformed_rows": {"n": len(bad), "rows": bad[:MALFORMED_LIST_CAP]},
            "keylog_suspect_rows": suspect_rows,
            "invalid_text_rows": {"n": len(raw_text), "rows": raw_text[:MALFORMED_LIST_CAP]},
            "recovery": recovery, "groups": groups, "roots": roots, "checked": checked, "signatures": sigs}


# ------------------------------------------------------------------------------------------------ escrow
def read_escrow(lines, M):
    """Sealed-second lines by second; keylog lines (first-observation tuples) are returned by read_escrow_keylog."""
    by = collections.defaultdict(list)
    for line in lines:
        if line.strip():
            e = json.loads(line)
            if e.get("kind") == "keylog":
                continue
            e["_nodes"] = [M.from_jt(j) for j in e.get("nodes", [])]
            by[str(e["seg"])].append(e)
    return by


def read_escrow_keylog(lines, M, polls):
    """Keylog escrow lines, each checked twice: the fold of its tuples reproduces its own acc and count, and some poll
    on the chain committed exactly that sub-range (table, bounds, count, acc). Returns the verified lines in key order
    and a summary."""
    anchored = set()
    for p in polls.values():
        for (t, lo, hi), e in (p.get("keylog_chunks") or {}).items():
            anchored.add((t, lo, hi, e.get("n"), e.get("acc")))
    good, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("kind") != "keylog":
            continue
        rows = [(int(k), M.from_jt(j)) for k, j in e.get("rows", [])]
        acc = M.ZERO
        for _k, f in rows:
            acc = M.H(acc + M.H(M.encode_node_v2("keylog", f)))
        if acc.hex() == e.get("acc") and len(rows) == e.get("n") and \
                (e.get("table"), int(e.get("from")), int(e.get("to")), e.get("n"), e.get("acc")) in anchored:
            e["_rows"] = rows
            good.append(e)
        else:
            bad += 1
    good.sort(key=lambda e: (e["table"], int(e["from"]), int(e.get("seq_local", 0))))
    return good, {"keylog_lines_verified": len(good), "keylog_lines_rejected": bad}


def _fields_dict(f):
    return {f[i]: f[i + 1] for i in range(1, len(f) - 1, 2)}


def _describe_fields(f):
    return {k: hx(v) for k, v in _fields_dict(f).items()}


def recover_keylog(M, db, keylog_viol, kesc, skip_keys):
    """For every failed keylog range, the first-observation tuples of its rows (re-review R3 and the E7 main run's late
    unlock): changed and removed rows are restored from them, rows added to the range afterwards are removed. A row a
    verified sealed-segment tuple already restores (skip_keys) keeps that tuple."""
    by_range = {}
    for e in kesc:
        by_range.setdefault((e["table"], int(e["from"]), int(e["to"])), e)       # the earliest committed line
    items, plan = [], []
    for kv in keylog_viol:
        t, lo, hi = kv["table"], kv["range"][0], kv["range"][1]
        e = by_range.get((t, lo, hi))
        item = {"table": t, "range": [lo, hi], "poll": kv["poll"]}
        if e is None:
            item["escrow"] = "absent"
            items.append(item)
            continue
        item["escrow"] = "verified_against_anchor"
        orig = dict(e["_rows"])
        now = {r[0]: r for r in M.keylog_rows(db, t, lo, hi)}
        pre = t[0] + ":"
        changed = [k for k in sorted(orig) if k in now and M.H(M.encode_node_v2("keylog", orig[k])) != now[k][1]]
        removed = [k for k in sorted(orig) if k not in now]
        added = [k for k in sorted(now) if k not in orig]
        item["changed"] = [{"key": pre + str(k), "original": _describe_fields(orig[k]),
                            "current": _describe_fields(now[k][4])} for k in changed]
        item["removed"] = [{"key": pre + str(k), "original": _describe_fields(orig[k])} for k in removed]
        item["added"] = [{"key": pre + str(k), "current": _describe_fields(now[k][4])} for k in added]
        for k in changed + removed:
            if pre + str(k) not in skip_keys:
                plan.append((t, k, orig[k]))
        for k in added:
            if pre + str(k) not in skip_keys:
                plan.append((t, k, None))
        item["restore_rows"] = [pre + str(k) for k in changed + removed + added if pre + str(k) not in skip_keys]
        items.append(item)
    return items, plan, by_range


def recover(M, escrow_lines, roots, groups, flagged_seconds, restore_out=None, db=None, keylog_viol=None, polls=None):
    esc = read_escrow(escrow_lines, M)
    out, restore_plan = [], []
    for seg in flagged_seconds:
        a = roots.get(("second", seg))
        item = {"second": seg}
        lines = esc.get(seg, [])
        good = None
        for e in lines:
            got = fold(M, e["_nodes"], "second", seg, e.get("encoding", "v2")) or {"acc": M.ZERO.hex(), "n": 0}
            ok_self = got["acc"] == e["acc"] and got["n"] == e["n"]
            ok_anchor = a is not None and e["acc"] == a["acc"] and e["n"] == a["n"]
            if ok_self and ok_anchor:
                good = e
                break
        if good is None:
            item["escrow"] = "absent" if not lines else ("no_anchored_root" if a is None else "does_not_match_anchor")
            # a second sealed empty has no escrow line and no anchored root; its sealed state was "no row"
            if a is None and not lines:
                item["original"] = "no row when sealed (empty sealed time)"
                item["added"] = [describe(n) for n in groups["second"].get(seg, [])]
            out.append(item)
            continue
        item["escrow"] = "verified_against_anchor"
        orig = {n[1]: n for n in good["_nodes"]}
        wm = good.get("wm")
        cur_all = groups["second"].get(seg, [])
        cur = {n[1]: n for n in cur_all if under(n, wm)}
        late = [n for n in cur_all if not under(n, wm)]
        item["changed"] = [{"key": k, "original": describe(orig[k]), "current": describe(cur[k]),
                            "fields_changed": sorted(f for f in set(describe(orig[k])) | set(describe(cur[k]))
                                                     if describe(orig[k]).get(f) != describe(cur[k]).get(f))}
                           for k in sorted(orig) if k in cur and tuple(orig[k]) != tuple(cur[k])]
        item["removed"] = [describe(orig[k]) for k in sorted(orig) if k not in cur]
        item["added"] = [describe(cur[k]) for k in sorted(cur) if k not in orig]
        item["late_rows"] = [describe(n) for n in late]
        out.append(item)
        restore_plan.append((seg, good, [n for n in cur_all if under(n, wm)]))
    res = {"seconds": out, "escrow_lines": sum(len(v) for v in esc.values())}
    kplan, kranges = [], {}
    if keylog_viol and db:
        kesc, ksum = read_escrow_keylog(escrow_lines, M, polls or {})
        res.update(ksum)
        skip = {n[1] for _s, e, _c in restore_plan for n in e["_nodes"]}
        res["keylog"], kplan, kranges = recover_keylog(M, db, keylog_viol, kesc, skip)
    if restore_out and db:
        res["restore"] = restore(M, db, restore_out, restore_plan, kplan,
                                 [kranges[(x["table"], x["range"][0], x["range"][1])] for x in res.get("keylog", [])
                                  if x.get("escrow") == "verified_against_anchor"])
    return res


def _id(con, table, idcol, col, val):
    r = con.execute("SELECT %s FROM %s WHERE %s IS ?" % (idcol, table, col), (val,)).fetchone()
    if r:
        return r[0]
    return con.execute("INSERT INTO %s (%s) VALUES (?)" % (table, col), (val,)).lastrowid


def _restore_keylog_row(con, t, k, f):
    """Write one row back from its first-observation keylog tuple (every committed column and joined value)."""
    d = _fields_dict(f)
    kc = "state_id" if t == "states" else "event_id"
    cols = {c: v for c, v in d.items() if "." not in c and c != kc}
    for jname, v in d.items():
        if "." not in jname:
            continue
        jt_, jc = jname.split(".", 1)
        fk = {"states_meta": "metadata_id", "state_attributes": "attributes_id", "event_types": "event_type_id",
              "event_data": "data_id"}[jt_]
        cols[fk] = None if v is None and jt_ in ("event_data", "state_attributes") else _id(con, jt_, fk, jc, v)
    if con.execute("SELECT 1 FROM %s WHERE %s=?" % (t, kc), (k,)).fetchone():
        con.execute("UPDATE %s SET %s WHERE %s=?" % (t, ", ".join("%s=?" % c for c in cols), kc),
                    tuple(cols.values()) + (k,))
    else:
        con.execute("INSERT INTO %s (%s, %s) VALUES (%s)" % (t, ", ".join(cols), kc, ",".join("?" * (len(cols) + 1))),
                    tuple(cols.values()) + (k,))


def restore(M, db, dst, plan, keylog_plan=(), keylog_lines=()):
    """A copy of the recorder with the escrowed closure fields of every flagged second written back (closure scheme).

    Only the closure fields are restored (what the renderer is measured to read); rows inserted into a sealed second with
    a key at or below its watermark are removed, rows that arrived after the seal are kept. The restored copy's roots are
    recomputed and must equal the anchored ones."""
    if M.SCHEME != "closure":
        return {"restored": False, "why": "restore is implemented for the closure scheme (the escrowed configuration)"}
    for s in ("", "-wal", "-shm"):
        if os.path.exists(db + s):
            shutil.copy2(db + s, dst + s)
    con = vconnect(dst)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # every deletion first: a row moved from one flagged second into another is removed from the second it was moved
    # into and then written back, with its escrowed timestamp, by the second it came from
    keep = {n[1] for _s, e, _c in plan for n in e["_nodes"]} | {"%s:%d" % (t[0], k) for t, k, f in keylog_plan
                                                                 if f is not None}
    for _seg, e, cur_sealed in plan:
        for n in cur_sealed:
            if n[1] not in keep:
                t, k = kparse(n[1])
                con.execute("DELETE FROM %s WHERE %s=?" % (t, "state_id" if t == "states" else "event_id"), (k,))
    for t, k, f in keylog_plan:                       # rows added to a key range after its first observation
        if f is None:
            con.execute("DELETE FROM %s WHERE %s=?" % (t, "state_id" if t == "states" else "event_id"), (k,))
    for _seg, e, _c in plan:
        for n in e["_nodes"]:
            t, k = kparse(n[1])
            c = json.loads(n[2])
            if t == "states":
                mid = _id(con, "states_meta", "metadata_id", "entity_id", c["e"])
                vals = (c["s"], n[0], n[3], n[4], n[6], n[7], n[8], mid)
                if con.execute("SELECT 1 FROM states WHERE state_id=?", (k,)).fetchone():
                    con.execute("UPDATE states SET state=?, last_updated_ts=?, context_id_bin=?, context_parent_id_bin=?,"
                                " context_user_id_bin=?, old_state_id=?, last_changed_ts=?, metadata_id=?"
                                " WHERE state_id=?", vals + (k,))
                else:
                    con.execute("INSERT INTO states (state, last_updated_ts, context_id_bin, context_parent_id_bin,"
                                " context_user_id_bin, old_state_id, last_changed_ts, metadata_id, state_id)"
                                " VALUES (?,?,?,?,?,?,?,?,?)", vals + (k,))
            else:
                tid = _id(con, "event_types", "event_type_id", "event_type", c["ty"])
                did = None if c.get("d") is None else _id(con, "event_data", "data_id", "shared_data", c["d"])
                vals = (n[0], n[3], n[4], n[6], tid, did)
                if con.execute("SELECT 1 FROM events WHERE event_id=?", (k,)).fetchone():
                    con.execute("UPDATE events SET time_fired_ts=?, context_id_bin=?, context_parent_id_bin=?,"
                                " context_user_id_bin=?, event_type_id=?, data_id=? WHERE event_id=?", vals + (k,))
                else:
                    con.execute("INSERT INTO events (time_fired_ts, context_id_bin, context_parent_id_bin,"
                                " context_user_id_bin, event_type_id, data_id, event_id) VALUES (?,?,?,?,?,?,?)",
                                vals + (k,))
    # rows no verified sealed-segment tuple holds (a row that reached the recorder after its second was sealed, or one
    # hit before its second was sealed) come back from their first-observation keylog tuple
    for t, k, f in keylog_plan:
        if f is not None:
            _restore_keylog_row(con, t, k, f)
    con.commit()
    con.close()
    nodes = M.load(dst)
    by = collections.defaultdict(list)
    for n in nodes:
        by[str(int(n[0] // 1.0))].append(n)
    checks = {}
    for seg, e, _c in plan:
        got = fold(M, [n for n in by.get(seg, []) if under(n, e.get("wm"))], "second", seg, e.get("encoding", "v2"))
        checks[seg] = bool(got and got["acc"] == e["acc"] and got["n"] == e["n"])
    kchecks = {}
    for e in keylog_lines:                            # every restored key range must reproduce its keylog commitment
        acc = M.ZERO
        for r in M.keylog_rows(dst, e["table"], int(e["from"]), int(e["to"])):
            acc = M.H(acc + r[1])
        kchecks["%s:(%s,%s]" % (e["table"], e["from"], e["to"])] = acc.hex() == e["acc"]
    return {"restored": True, "path": dst, "seconds": len(plan), "root_reproduced": checks,
            "all_roots_reproduced": all(checks.values()) if checks else None,
            "keylog_rows_restored": ["%s:%d" % (t[0], k) for t, k, f in keylog_plan if f is not None],
            "keylog_rows_removed": ["%s:%d" % (t[0], k) for t, k, f in keylog_plan if f is None],
            "keylog_range_reproduced": kchecks,
            "all_keylog_ranges_reproduced": all(kchecks.values()) if kchecks else None}


# ------------------------------------------------------------------------------------------------ scoring
def trial_second(t):
    """The one-second segment of the trial's row, as exp/stages/e_c_write_time.py scores it."""
    seg = ((t.get("_detection") or {}).get("second") or {}).get("segment")
    if seg is not None:
        return str(seg)
    for k in ("judged_row", "forged_row", "row_before"):
        r = t.get(k)
        if isinstance(r, dict) and r.get("ts"):
            return str(int(float(r["ts"]) // 1))
    return None


def cp(k, n):
    sys.path.insert(0, os.path.join(REPO, "exp"))
    from rig import stats  # noqa: PLC0415
    if n == 0:
        return None
    r = stats.clopper_pearson(k, n)
    return [round(r["ci_lo"], 3), round(r["ci_hi"], 3)]


def score_trials(res, trials):
    """Per trial, the E7 verdict on its one-second segment next to the existing rule's; per arm, the counts.

    detected: the trial's second is flagged (a second-level violation, an attributable row in it, or the localised
    second of an attributable minute or hour violation). detected_second_unit: the same without the coarse
    localisation. detected_any_granularity: detected, or a minute or hour segment containing the second is attributable
    (sound only when one trial occupies the segment: a coarse violation marks every trial inside it)."""
    viol = {(v["gran"], v["seg"]): v for v in res["violations"]}
    flagged = set(res["flagged_seconds"])
    rows_by_sec = collections.defaultdict(list)
    for r in res["attributable_rows"]:
        # a row is evidence for the second it is in now and for the second it was in when first observed (a deleted
        # row has only the latter)
        for sec in {r["second"], r.get("first_observed_second")} - {None}:
            rows_by_sec[sec].append(r["key"])
    attributable_keys = {r["key"] for r in res["attributable_rows"]}
    coarse = {(f["gran"], f["seg"]) for f in res.get("flagged_segments", []) if f["gran"] != "second"}
    arms = collections.defaultdict(lambda: {"n": 0, "e7_detected": 0, "existing_flagged": 0,
                                            "existing_attributable": 0, "existing_ambiguous": 0,
                                            "e7_detected_second_unit": 0, "e7_detected_any_granularity": 0})
    for t in trials:
        seg = trial_second(t)
        v = viol.get(("second", seg)) if seg is not None else None
        old = (v or {}).get("existing_rule") or {}
        c = ([("minute", str(int(seg) // 60)), ("hour", str(int(seg) // 3600))] if seg is not None else [])
        c = [list(x) for x in c if x in coarse]
        second_unit = bool(v and v["attributable"]) or bool(rows_by_sec.get(seg))
        e7 = {"segment": seg, "anchored": ("second", seg) in res["roots"],
              "detected": seg in flagged, "segment_violation": bool(v and v["violation"]),
              "attributable_rows": rows_by_sec.get(seg, []),
              "existing_rule": {"violation": bool(old.get("violation")), "attributable": bool(old.get("attributable")),
                                "ambiguous": bool(old.get("ambiguous"))},
              "detected_second_unit": second_unit, "coarse_segments_attributable": c,
              "detected_any_granularity": seg in flagged or bool(c),
              "deleted_event_rows_attributable": sorted(k for k in ("e:%d" % int(i) for i in
                                                                    (t.get("deleted_event_ids") or []))
                                                        if k in attributable_keys)}
        t["_e7"] = e7
        a = arms[t.get("arm")]
        a["n"] += 1
        a["e7_detected"] += e7["detected"]
        a["e7_detected_second_unit"] += second_unit
        a["e7_detected_any_granularity"] += e7["detected_any_granularity"]
        a["existing_flagged"] += e7["existing_rule"]["violation"]
        a["existing_attributable"] += e7["existing_rule"]["attributable"]
        a["existing_ambiguous"] += e7["existing_rule"]["ambiguous"]
    for a in arms.values():
        a["e7_detected_ci"] = cp(a["e7_detected"], a["n"])
        a["e7_detected_any_granularity_ci"] = cp(a["e7_detected_any_granularity"], a["n"])
        a["existing_attributable_ci"] = cp(a["existing_attributable"], a["n"])
    return dict(arms)


def touched_seconds(trials, db):
    """The paper's counting rule (reproduce/verify_all.py touched_segments), else the trials' own seconds."""
    try:
        sys.path.insert(0, os.path.join(REPO, "reproduce"))
        import verify_all as VA  # noqa: PLC0415
        return VA.touched_segments(trials, vconnect(db), {"second": 1.0})["second"], "verify_all.touched_segments"
    except Exception as exc:                          # noqa: BLE001
        return {s for s in (trial_second(t) for t in trials) if s is not None}, "trial_second (%s)" % repr(exc)[:80]


def touched_by_deletions(trials):
    """Seconds and rows a trial reports itself as deleting ("deleted_event_seconds", "deleted_event_ids"): touched under
    the counting rule, since the trial wrote (removed) them."""
    secs, rows = set(), set()
    for t in trials:
        secs |= {str(int(float(x) // 1)) for x in (t.get("deleted_event_seconds") or [])}
        rows |= {"e:%d" % int(i) for i in (t.get("deleted_event_ids") or [])}
    return secs, rows


def benign_floor(res, touched, touched_rows=()):
    touched_rows = set(touched_rows)

    def row_touched(r):
        # a keylog row that was removed or changed counts as touched when the second it is in now, or the second it was
        # in when first observed, is touched (a trial deleting its own events leaves no current second)
        return (r.get("key") in touched_rows or r.get("second") in touched
                or r.get("first_observed_second") in touched)
    cases = [{"seg": v["seg"], "rule": v["rule"], "mechanism": v.get("mechanism"),
              "existing_rule": v["existing_rule"]} for v in res["violations"]
             if v["gran"] == "second" and v["violation"] and v["seg"] not in touched]
    rows = [r for r in res["attributable_rows"] if not row_touched(r)]
    n = sum(1 for (g, s) in res["checked"] if g == "second" and s not in touched)
    old = [v["seg"] for v in res["violations"] if v["gran"] == "second" and v["existing_rule"]["violation"]
           and v["seg"] not in touched]
    out = {"untouched_anchored_seconds": n, "violated": len(cases), "violated_ci": cp(len(cases), n),
           "cases": cases, "untouched_attributable_rows": rows,
           "existing_rule_violated": len(old), "existing_rule_cases": old}
    # every flag source, and the minute and hour segments (review M1): a coarse segment is untouched when no touched
    # second lies inside it
    untouched_flagged = [s for s in res["flagged_seconds"] if s not in touched]
    # a failed key range flags every second its rows sit or sat in; when one of them is a touched second, the others
    # are neighbours of the attack, first observed in the same poll, not benign failures
    by_range = [set(kv["seconds"]) for kv in res.get("keylog_violations", [])]
    other = ({v["seg"] for v in res["violations"] if v["gran"] == "second" and v["attributable"]}
             | {r["second"] for r in res["attributable_rows"] if r["second"] is not None}
             | {s_ for v in res["violations"] for s_ in v.get("localized_seconds", [])})
    near_attack = [s for s in untouched_flagged if s not in other and any(s in r_ and r_ & set(touched)
                                                                          for r_ in by_range)]
    out["untouched_flagged_seconds"] = {"n": len(untouched_flagged), "seconds": untouched_flagged[:500],
                                        "of_untouched_anchored_seconds": n,
                                        "via_a_key_range_that_holds_a_touched_second": near_attack[:500]}
    for g, w in (("minute", 60), ("hour", 3600)):
        t_g = {str(int(s) // w) for s in touched}
        segs = [s for (gg, s) in res["checked"] if gg == g and s not in t_g]
        cg = [{"seg": v["seg"], "rule": v["rule"], "mechanism": v.get("mechanism"),
               "localized_seconds": v.get("localized_seconds"), "existing_rule": v["existing_rule"]}
              for v in res["violations"] if v["gran"] == g and v["attributable"] and v["seg"] not in t_g]
        out[g] = {"untouched_anchored": len(segs), "attributable": len(cg), "attributable_ci": cp(len(cg), len(segs)),
                  "cases": cg}
    out["keylog_violations_untouched"] = [kv for kv in res.get("keylog_violations", [])
                                          if not (set(kv["seconds"]) & set(touched))
                                          and not any(x["key"] in touched_rows for x in kv["suspects"])]
    return out


# ------------------------------------------------------------------------------------------------ LATE_BOUND evidence
def late_delays(M, db, lines, t0=None, t1=None, tsnap=None, scheme=None):
    """Benign late-row delays of an EARLIER chain (records without coverage fields), the evidence LATE_BOUND is fixed
    from. In every one-second segment whose root fails with more rows now than anchored (delta_n = k > 0), the late-row
    hypothesis of exp/sp2027/r13_subset_test.py (drop the j newest state rows and k - j newest event rows by key) is
    tried; when a candidate reproduces the anchored root, the dropped rows arrived after the seal.

    The E7 verifier's quantity for such a row is copy_at(Q) - ts for the latest poll Q whose copy lacked it. An earlier
    chain has no watermark, so it is bracketed: LOWER = the sealing record's time minus the row's timestamp (that copy
    lacked the row; the record time is taken just after the copy); UPPER = the time of the last record before the first
    record that provably held the row (one that sealed an intact segment containing a row of the same table with a key
    at or above it), minus the row's timestamp. LATE_BOUND must exceed every UPPER value of the benign rows."""
    P = parse_chain(lines, scheme, None, tsnap)
    load_since = (int(t0 // 3600) - 1) * 3600.0 if t0 is not None else None
    by = collections.defaultdict(list)
    for n in M.load(db, since=load_since):
        by[str(int(n[0] // 1.0))].append(n)
    rec_ts, wm_lb = {}, collections.defaultdict(lambda: {"states": -1, "events": -1})
    late, unexplained = [], []
    for (g, seg), a in sorted(P["roots"].items(), key=lambda x: (x[0][0], int(x[0][1]))):
        if g != "second":
            continue
        rec_ts[a["chain_seq"]] = a["record_ts"]
        rows = by.get(seg, [])
        got = fold(M, rows, g, seg, a["encoding"])
        kept = None
        if got is not None and got["acc"] == a["acc"] and got["n"] == a["n"]:
            kept = rows
        elif got is not None and got["n"] > a["n"]:
            k = got["n"] - a["n"]
            ranked = {t: sorted((kparse(n[1])[1], i) for i, n in enumerate(rows) if kparse(n[1])[0] == t)[::-1]
                      for t in ("states", "events")}
            for j in range(k + 1):
                if j > len(ranked["states"]) or k - j > len(ranked["events"]):
                    continue
                drop = {i for _, i in ranked["states"][:j]} | {i for _, i in ranked["events"][:k - j]}
                g2 = fold(M, [n for i, n in enumerate(rows) if i not in drop], g, seg, a["encoding"])
                if g2 is not None and g2["acc"] == a["acc"] and g2["n"] == a["n"]:
                    kept = [n for i, n in enumerate(rows) if i not in drop]
                    in_window = (t0 is None or int(seg) >= t0 - 1) and (t1 is None or int(seg) <= t1 + 1)
                    if in_window:
                        late += [(seg, rows[i], a) for i in sorted(drop)]
                    break
            if kept is None and (t0 is None or int(seg) >= t0 - 1) and (t1 is None or int(seg) <= t1 + 1):
                unexplained.append({"seg": seg, "delta_n": k})
        for n in kept or []:
            t, key = kparse(n[1])
            wm_lb[a["chain_seq"]][t] = max(wm_lb[a["chain_seq"]][t], key)
    seqs = sorted(rec_ts)
    out = []
    for seg, n, a in late:
        t, key = kparse(n[1])
        upper = None
        after = [q for q in seqs if q > a["chain_seq"]]
        for i, q in enumerate(after):
            if wm_lb[q][t] >= key:
                upper = rec_ts[after[i - 1]] if i > 0 else a["record_ts"]
                break
        out.append({"seg": seg, "key": n[1], "ts": n[0], "sealing_record_ts": a["record_ts"],
                    "delay_lower_s": round(a["record_ts"] - n[0], 6),
                    "delay_upper_s": None if upper is None else round(upper - n[0], 6)})
    lo = sorted(x["delay_lower_s"] for x in out)
    up = sorted(x["delay_upper_s"] for x in out if x["delay_upper_s"] is not None)
    return {"late_rows": out, "n_late_rows": len(out), "segments_not_explained_by_late_rows": unexplained,
            "max_delay_lower_s": lo[-1] if lo else None, "max_delay_upper_s": up[-1] if up else None,
            "rows_without_upper": sum(1 for x in out if x["delay_upper_s"] is None)}


# ------------------------------------------------------------------------------------------------ CLI
def _private_copy(src, scratch):
    db = os.path.join(scratch, "rec.db")
    for s in ("", "-wal", "-shm"):
        if os.path.exists(src + s):
            shutil.copy2(src + s, db + s)
    con = vconnect(db)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()
    return db


def _scheme_of(lines, given):
    if given:
        return given
    sch = parse_chain(lines)["schemes"]
    if len(sch) != 1:
        raise SystemExit("the chain holds monitor records of schemes %r; pass --scheme" % sch)
    return next(iter(sch))


def run(a):
    scratch = tempfile.mkdtemp(prefix="e7v_")
    lines = read_lines(a.chain)
    scheme = _scheme_of(lines, a.scheme)
    M = load_monitor(scheme, scratch, a.monitor_dir)
    db = _private_copy(a.db, scratch)
    t0, t1 = (float(a.window[0]), float(a.window[1])) if a.window else (None, None)
    if a.cmd == "late-delays":
        out = {"check": "e7_verify late-delays", "params": {"scheme": scheme, "window": a.window,
                                                          "snapshot_at": a.snapshot_at,
                                                          "chain": os.path.abspath(a.chain), "db": os.path.abspath(a.db)},
               **late_delays(M, db, lines, t0, t1, a.snapshot_at, scheme)}
        shutil.rmtree(scratch, ignore_errors=True)
        return out
    esc = read_lines(a.escrow) if a.escrow else None
    res = verify(M, db, lines, a.late_bound, a.gap_s, scheme=scheme, t0=t0, t1=t1, tsnap=a.snapshot_at,
                 escrow_lines=esc, restore_out=a.restore_out, sign_pubkey=a.sign_pubkey,
                 allow_unsigned=a.allow_unsigned)
    trials = []
    for f in a.trials or []:
        d = json.load(open(f))
        trials += [t for t in d.get("trials", []) if not (t.get("err") or t.get("error"))]
    touched, rule = (touched_seconds(trials, db) if trials else (set(), "no trials given: every segment untouched"))
    del_secs, del_rows = touched_by_deletions(trials)
    if del_secs or del_rows:
        touched = set(touched) | del_secs
        rule += " + the trials' deleted_event_seconds and deleted_event_ids"
    P = res["P"]
    out = {"check": "e7_verify",
           "params": {"late_bound_s": a.late_bound, "gap_s": a.gap_s, "scheme": scheme, "window": a.window,
                      "snapshot_at": a.snapshot_at, "chain": os.path.abspath(a.chain), "db": os.path.abspath(a.db),
                      "escrow": a.escrow, "stable_exclude": ({t: list(c) for t, c in M.STABLE_EXCLUDE.items()}
                                                             if scheme == "stable" else None)},
           "chain": {"monitor_records": len(P["records"]),
                     "coverage_records": sum(1 for r in P["records"] if r["coverage"]),
                     "continuation_records": sum(1 for r in P["records"] if r["continuation"]),
                     "existing_format_records": sum(1 for r in P["records"] if not r["coverage"]),
                     "unobservable_records": sum(1 for r in P["records"] if r["unobservable"]),
                     "polls_known": len(P["polls"]), "polls_from_backlog": sum(1 for p in P["polls"].values()
                                                                                if not p["own"]),
                     "epochs": P["epochs"], "other_records": P["other"], "schemes": P["schemes"],
                     "conflicted_segments": P["conflicted"]},
           "segments": res["segments"], "violations": res["violations"],
           "attributable_rows": res["attributable_rows"], "benign_late_rows": res["benign_late_rows"],
           "benign_late_max_lower_bound_s": max((r["committed_after_lower_bound_s"] for r in res["benign_late_rows"]
                                                 if r["committed_after_lower_bound_s"] is not None), default=None),
           "rows_in_unsealed_time": res["rows_in_unsealed_time"], "flagged_seconds": res["flagged_seconds"],
           "ambiguous_seconds": res["ambiguous_seconds"],
           "stalls": res["stalls"], "recovery": res["recovery"],
           "benign_floor": dict(benign_floor(res, touched, del_rows), counting_rule=rule),
           "flagged_segments": res["flagged_segments"], "observation_gaps": res["observation_gaps"],
           "root_unknown_segments": res["root_unknown_segments"], "keylog": res["keylog"],
           "keylog_violations": res["keylog_violations"], "malformed_rows": res["malformed_rows"],
           "keylog_suspect_rows": res["keylog_suspect_rows"], "invalid_text_rows": res["invalid_text_rows"],
           "signatures": res["signatures"]}
    if trials:
        out["arms"] = score_trials(res, trials)
        out["trials"] = [{"arm": t.get("arm"), "room": t.get("room"), **t["_e7"]} for t in trials]
    shutil.rmtree(scratch, ignore_errors=True)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--late-bound", type=float, required=True, help="seconds; fixed before the run")
    v.add_argument("--gap-s", type=float, required=True, help="seconds; fixed before the run (e.g. 3 x poll period)")
    v.add_argument("--escrow", default=None)
    v.add_argument("--trials", nargs="*")
    v.add_argument("--restore-out", default=None)
    v.add_argument("--sign-pubkey", default=None, help="the monitor's published Ed25519 public key (PEM); every signed "
                   "record is checked against it; only records it verifies are used, the others are listed")
    v.add_argument("--allow-unsigned", action="store_true", help="with --sign-pubkey, keep unsigned records (chains "
                   "written before signatures existed)")
    d = sub.add_parser("late-delays")
    for p in (v, d):
        p.add_argument("--chain", required=True)
        p.add_argument("--db", required=True)
        p.add_argument("--snapshot-at", type=float, default=None, help="time the recorder copy was taken")
        p.add_argument("--window", nargs=2, default=None)
        p.add_argument("--scheme", choices=("closure", "row", "stable", "wholerow"), default=None)
        p.add_argument("--out", default=None)
        p.add_argument("--monitor-dir", default=DEFAULT_MONITOR_DIR)
    a = ap.parse_args()
    out = run(a)
    text = json.dumps(out, indent=1, sort_keys=True, default=str)
    if a.out:
        with open(a.out, "x") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
