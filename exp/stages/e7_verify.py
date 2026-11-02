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
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_MONITOR_DIR = os.path.join(REPO, "monitor")
ZERO = b"\x00" * 32


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


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
           "HOMEPROV_MAX_PARTS": None, "HOMEPROV_SIGN_KEY": None, "HOMEPROV_ROWBIND": None, "HOMEPROV_SINCE": None,
           "HOMEPROV_READ": None, "HOMEPROV_QUICK_CHECK_EVERY": None,
           "HOMEPROV_HARDEN": None if VERIFY_HARDEN else "0"}    # E10: --no-harden turns the monitor's off too
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


# HARDENING (round 14, E10; internal review r4 R1 W4). The verifier reads a recorder the hub's adversary may have
# crafted, so it applies SQLite's untrusted-file settings (https://www.sqlite.org/security.html Section 1.2, items 9-13)
# on every connection it opens, as the hardened monitor does (monitor.py HARDENING; repeated here because this verifier
# also loads earlier monitors, monitor_e8.py, that lack it): trusted_schema=OFF, cell_size_check=ON, mmap_size=0, and
# where Python exposes sqlite3_db_config, views and triggers disabled and DEFENSIVE on. Before it reads anything else it
# runs quick_check on the recorder copy as the first statement and refuses a copy that fails it, or whose recorder
# tables are not ordinary tables (refuse_untrusted(); run() prints {"refused": ...} and exits 3). On a recorder that
# passes, every verdict is unchanged. --no-harden (or HOMEPROV_VERIFY_HARDEN=0) restores the earlier behaviour.
VERIFY_HARDEN = os.environ.get("HOMEPROV_VERIFY_HARDEN", "1") != "0"
HARDEN_TABLES = ("states", "events", "states_meta", "event_types", "event_data", "state_attributes")
_DBCONFIG = (("SQLITE_DBCONFIG_DEFENSIVE", True), ("SQLITE_DBCONFIG_TRUSTED_SCHEMA", False),
             ("SQLITE_DBCONFIG_ENABLE_VIEW", False), ("SQLITE_DBCONFIG_ENABLE_TRIGGER", False))


class RecorderRefused(Exception):
    """The recorder copy fails the untrusted-file checks: no verdict is given."""

    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason, self.detail = reason, detail or {}


def vharden(con):
    """trusted_schema=OFF, cell_size_check=ON, mmap_size=0 and, where available, the db_config flags; returns what is in
    force (a flag None when it cannot be set)."""
    applied = {}
    setconfig, getconfig = getattr(con, "setconfig", None), getattr(con, "getconfig", None)
    for name, want in _DBCONFIG:
        op = getattr(sqlite3, name, None)
        if setconfig is None or op is None:
            applied[name] = None
            continue
        try:
            setconfig(op, want)
            applied[name] = bool(getconfig(op)) if getconfig is not None else want
        except sqlite3.Error:
            applied[name] = None
    for name, val in (("trusted_schema", 0), ("cell_size_check", 1), ("mmap_size", 0)):
        con.execute("PRAGMA %s=%d" % (name, val))
        row = con.execute("PRAGMA %s" % name).fetchone()       # (an in-memory database reports no mmap_size)
        applied[name] = row[0] if row else None
    return applied


def vconnect(db):
    """A connection that decodes TEXT leniently, as the coverage monitor does (re-review R2): a value that is not valid
    UTF-8 must not stop the verifier. Hardened (E10) unless VERIFY_HARDEN is off."""
    con = sqlite3.connect(db)
    con.text_factory = lambda b: b.decode("utf-8", "surrogateescape")
    if VERIFY_HARDEN:
        vharden(con)
    return con


def object_kinds(con):
    """{table name: kinds} for the recorder tables the verifier reads that are not exactly one ordinary table."""
    kinds = {}
    for name, typ, sql in con.execute(
            "SELECT lower(name), type, sql FROM sqlite_master WHERE lower(name) IN (%s)"
            % ",".join("?" * len(HARDEN_TABLES)), HARDEN_TABLES):
        virtual = typ == "table" and " ".join(str(sql or "").split()).upper().startswith("CREATE VIRTUAL TABLE")
        kinds.setdefault(name, []).append("virtual table" if virtual else typ)
    return {n: "/".join(sorted(k)) for n, k in kinds.items() if k.count("table") != 1 or "view" in k}


def refuse_untrusted(db):
    """SQLite item 11 for the verifier: quick_check as the first statement on the recorder copy, then the object-type
    check. Raises RecorderRefused; returns None when the copy may be read. A no-op when VERIFY_HARDEN is off."""
    if not VERIFY_HARDEN:
        return None
    try:
        con = vconnect(db)
    except sqlite3.Error as exc:
        raise RecorderRefused("unreadable", {"exc": repr(exc)[:160]})
    try:
        try:
            qc = [r[0] for r in con.execute("PRAGMA quick_check")]
        except sqlite3.DatabaseError as exc:
            raise RecorderRefused("quick_check_failed", {"exc": repr(exc)[:160]})
        if qc != ["ok"]:
            raise RecorderRefused("quick_check_failed", {"quick_check": [str(x)[:120] for x in qc[:10]]})
        bad = object_kinds(con)
        if bad:
            raise RecorderRefused("schema_object_not_a_table", {"objects": bad})
    finally:
        con.close()
    return None


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
                                  "keylog_rewind": h.get("keylog_rewind") or (cur or {}).get("keylog_rewind"),
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

    def observed(self, table, key):
        """Did any known poll's copy hold this key (wm >= key)? (E9 A7: a chain cut after a row was written holds no
        poll that saw it, so how late the row was committed is not bounded from above.)"""
        pts = self.bracket.get(table) or []
        return bool(pts) and pts[-1][0] >= key


# OBSERVATION BREAKS (E10; drafts/round13/FORMAL_DRAFT.md section 6, D1). A late row's commit time lies between the copy
# of Q, the last known poll whose copy lacked its key, and the read of P, the first known poll whose copy held it. The
# late-row test reads only the lower end (committed_after), which bounds the commit delay only if the monitor watched
# the recorder in between. An unobservable poll, a poll missing from the chain (a skipped seq_local, or a known poll
# without its watermark), a poll whose own record failed (backlogged), a monitor restart (a new epoch), or more than
# GAP_S between the copies of two consecutive polls leaves the commit time unbounded inside [Q, P]: such a row is
# judged unobserved_late (neither benign nor attributable) unless the lower end alone already exceeds LATE_BOUND, which
# stays attributable. Probe P2 of the draft: 12 unobservable polls, then a row backdated about 70 s into a second
# sealed before them, read benign_late (lower bound 7.6 s) and its second "match".
# A backlogged poll (its own record failed; its head, signed, came later in a backlog) carries its watermark and copy
# time, so it could bound the commit time like any poll; with LATE_BREAK_BACKLOG (the lead's specification, 2026-10-12)
# it is not used as either end of the bracket, so a late row whose bracket spans an anchor outage is unobserved_late.
LATE_BREAK_BACKLOG = True


class ObservationBreaks:
    """For a key: the first known poll whose copy held it, the known poll before it, and the first break between them."""

    def __init__(self, polls, gap_s):
        self.polls = polls
        self.keys = sorted(polls)
        self.index = {k: i for i, k in enumerate(self.keys)}
        self.trans, self.state = {}, {}
        prev = None
        for i, k in enumerate(self.keys):
            p = polls[k]
            if prev is not None:
                pp = polls[prev]
                if k[0] != prev[0]:
                    self.trans[i] = "monitor_restarted"
                elif k[1] - prev[1] > 1:
                    self.trans[i] = "poll_missing_from_the_chain"
                elif p.get("copy_at") is not None and pp.get("copy_at") is not None \
                        and p["copy_at"] - pp["copy_at"] > gap_s:
                    self.trans[i] = "gap_above_gap_s"
            if p.get("unobservable"):
                self.state[i] = "unobservable_poll"
            elif p.get("through") is None or not isinstance(p.get("wm"), dict) or p.get("copy_at") is None:
                self.state[i] = "poll_without_its_watermark"
            elif LATE_BREAK_BACKLOG and p.get("in_backlog"):
                self.state[i] = "backlogged_poll"
            prev = k
        self.valid = [k for k in self.keys if polls[k].get("through") is not None
                      and isinstance(polls[k].get("wm"), dict) and polls[k].get("copy_at") is not None
                      and not polls[k].get("unobservable")
                      and not (LATE_BREAK_BACKLOG and polls[k].get("in_backlog"))]
        self.pmax = {}
        for t in ("states", "events"):
            m, out = -1, []
            for k in self.valid:
                w = polls[k]["wm"].get(t)
                m = max(m, -1 if w is None else w)
                out.append(m)
            self.pmax[t] = out

    def bracket(self, table, key):
        """(Q key, P key) or None: P the first valid poll in poll order whose copy held the key, Q the valid poll
        before it."""
        pm = self.pmax.get(table) or []
        i = bisect.bisect_left(pm, key)
        if i >= len(pm) or i == 0:
            return None
        return self.valid[i - 1], self.valid[i]

    def first_holding_copy_at(self, table, key):
        b = self.bracket(table, key)
        return None if b is None else self.polls[b[1]].get("copy_at")

    def between(self, table, key):
        """The first break between Q and P (a reason string), or None."""
        b = self.bracket(table, key)
        if b is None:
            return None
        a, z = self.index[b[0]], self.index[b[1]]
        for j in range(a + 1, z + 1):
            if j in self.trans:
                return self.trans[j]
            if j < z and j in self.state:
                return self.state[j]
        return None


# CLOCK_STEP (E10; FORMAL_DRAFT.md D3). The coverage verifier had no rule for a backward clock step, which the paper's
# G3 lists among the operations markers declare: after the hub's clock steps back by s seconds, the rows it writes for
# the next s seconds carry timestamps in seconds sealed already, so each is a late row whose commit delay exceeds
# LATE_BOUND when s does, an attributable backdated insertion. An operator CLOCK_STEP marker {"marker": "CLOCK_STEP",
# "window": [lo, hi], "issued_ts": I, ...}, signed like every marker, excuses exactly such rows: a late row (its key
# above the sealing poll's watermark, so it was not in the sealed copy) with lo <= t(r) < hi, first held by a poll that
# copied after I and at most CLOCK_STEP_SEEN_S after it. The window is BOUNDED and AT THE MARKER, as in exp/rig/
# markers.py (an unbounded window was measured to hide injection): 0 < hi - lo <= MAX_CLOCK_STEP_S and
# |hi - I| <= MAX_CLOCK_STEP_S. It never excuses a changed or deleted sealed row, a row inserted with a low key, or a
# keylog violation: a clock step adds rows, it never removes or edits them. Its cost: a row the hub adversary inserts
# with a timestamp in the declared window during those CLOCK_STEP_SEEN_S seconds is excused too.
MAX_CLOCK_STEP_S = 300.0
CLOCK_STEP_SEEN_S = 2 * MAX_CLOCK_STEP_S


def clock_steps(markers):
    acc, rej = [], []
    for m in markers or []:
        if m.get("marker") != "CLOCK_STEP":
            continue
        why = None
        try:
            lo, hi = (float(x) for x in m["window"])
            i = float(m["issued_ts"])
        except (KeyError, TypeError, ValueError):
            lo = hi = i = None
            why = "malformed"
        if why is None and not lo < hi:
            why = "empty_window"
        elif why is None and hi - lo > MAX_CLOCK_STEP_S:
            why = "window_longer_than_the_maximum"
        elif why is None and abs(hi - i) > MAX_CLOCK_STEP_S:
            why = "window_not_at_the_marker"
        if why:
            rej.append({"chain_seq": m.get("chain_seq"), "kind": "CLOCK_STEP", "why": why})
            continue
        acc.append({"chain_seq": m.get("chain_seq"), "lo": lo, "hi": hi, "issued_ts": i,
                    "seen_by": i + CLOCK_STEP_SEEN_S})
    return acc, rej


def clock_step_excuse(steps, ts, first_held_at):
    """The accepted CLOCK_STEP window that excuses a late row timestamped ts, first held by a poll that copied at
    first_held_at, or None."""
    if first_held_at is None:
        return None
    for c in steps:
        if c["lo"] <= ts < c["hi"] and c["issued_ts"] < first_held_at <= c["seen_by"]:
            return c
    return None


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


def bound_rows(e, lo):
    """The full per-row hashes of a keylog entry written with HOMEPROV_ROWBIND=1 (E9 A2), {key: hex}, if the listed
    hashes fold to the entry's own acc and count with keys strictly inside (lo, to] in ascending order; else None."""
    rows = e.get("rows") or []
    keys = [lo + int(x[0]) for x in rows]
    if len(rows) != e.get("n") or keys != sorted(set(keys)) or any(not (lo < k <= int(e.get("to", lo))) for k in keys):
        return None
    acc = ZERO
    try:
        for x in rows:
            h = bytes.fromhex(x[1])
            if len(h) != 32:
                return None
            acc = H(acc + h)
    except (TypeError, ValueError):
        return None
    return {k: x[1] for k, x in zip(keys, rows)} if acc.hex() == e.get("acc") else None


def check_keylog(M, db, polls, rowbind=True):
    """Recompute every committed key range over the current rows (review B1). A mismatch means a row first observed by
    that poll was changed, re-timed, made visible, deleted, or a row was inserted into the range later: attributable.

    Every row of a failed range is a suspect (re-review R1): the 32-bit hash prefixes are chosen by whoever writes the
    rows (a birthday search plus a decoy row hides a forged row from them), so they only RANK the suspects ("likely":
    changed, added, removed) and never clear one. The seconds of a failed range are every second its rows sit in now
    and every second they sat in when first observed (the record names it, re-review R3), so a row deleted, re-timed
    or made malformed before its second was sealed still flags that second.

    PER-ROW BINDING (E9 A2). An entry written with HOMEPROV_ROWBIND=1 ("bind": "row_sha256") lists every row's full
    256-bit hash. When those fold to the entry's acc and count, the failed range is localised exactly: the suspects are
    the rows whose current hash differs, the rows added and the rows gone ("localization": "exact"), and only their
    seconds are flagged; a failed range whose listed hashes do not fold to its acc keeps every row as a suspect
    ("row_binding_inconsistent"). rowbind=False (--no-rowbind) reads such entries by their 32-bit prefixes, as before,
    for comparison. A prefix-ranked range that failed with no row whose prefix differs carries "prefix_collision"."""
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
            bind = e.get("bind") == "row_sha256"
            full = bound_rows(e, lo) if bind and rowbind else None
            if full is not None:
                now = {r[0]: (r[1].hex(), r[2]) for r in rows}
            else:
                now = {r[0]: (r[1].hex()[:8], r[2]) for r in rows}
                logged = {k: [x[0], str(x[1])[:8]] + list(x[2:]) for k, x in logged.items()}
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
            if full is not None:
                suspects = [row(k) for k in sorted(set(changed) | set(added) | set(removed))]
            else:
                suspects = [row(k) for k in sorted(set(now) | set(logged))]
            seconds = sorted({x for r_ in suspects for x in (r_["second"], r_["first_observed_second"]) if x},
                             key=int)
            kv = {"poll": list(key), "seq_local": key[1], "poll_ts": p.get("ts"), "table": t, "range": [lo, hi],
                  "n_logged": e.get("n"), "n_now": len(rows), "localized": bool(changed or added or removed),
                  "changed": [row(k) for k in changed], "added": [row(k) for k in added],
                  "removed": [pre + str(k) for k in removed],
                  "likely": [row(k) for k in changed + added + removed],
                  "suspects": suspects, "seconds": seconds}
            if bind:
                kv["localization"] = ("exact" if full is not None else
                                      "prefix_ranked" if not rowbind else "row_binding_inconsistent")
            if full is None and not kv["localized"]:
                kv["prefix_collision"] = True                 # failed, yet every 32-bit prefix still matches
            out.append(kv)
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


# ------------------------------------------------------------------------------------------------ markers (E9)
def _marker_issuer():
    sys.path.insert(0, os.path.join(REPO, "exp"))
    from rig import marker_issuer as MI  # noqa: PLC0415
    return MI


def chain_markers(lines, operator_key=None, operator_pubkey=None, tsnap=None, monitor_fp=None):
    """Lifecycle markers the operator issued (E9 A1, A3, A6). A marker record counts only when its marker_tag verifies
    under the operator's HMAC key (when given) AND its operator signature verifies under the operator's Ed25519 public
    key (when given). With neither, no marker counts: an excuse is never taken on the anchor host's word, and the anchor
    host holds the HMAC key (it checks markers with it), so only the signature shows a third party that the operator
    issued the marker. A marker appended after the recorder snapshot is not considered.

    ONE ISSUANCE, ONE MARKER (E9 code review R3). The same signed marker can reach a chain twice: the issuer resends a
    request whose reply it could not verify (the first may have been appended), and the anchor host, or anyone who saw
    the request, can replay it. A marker is identified by the SHA-256 of its canonical JSON (sort_keys; RESTORE and
    RENAME markers carry a random nonce): only its first copy on the chain counts, every later copy is listed in
    "duplicates". Two different markers with the same nonce are not one issuance: the later is rejected
    (nonce_reused). A marker that names the monitors it is for ("monitors": [fingerprints of their record-signing
    keys]) is rejected on another monitor's chain (marker_for_another_monitor) when that monitor's key is given."""
    MI = _marker_issuer()
    if operator_key is None and operator_pubkey is None:
        n = 0
        for line in lines:
            if line.strip() and '"marker"' in line:
                n += 1
        return [], {"checked": False, "marker_records": n,
                    "note": "no operator key given: markers are not considered"}
    pub = MI.load_pubkey(operator_pubkey) if operator_pubkey else None
    acc, rej, dup, seen, nonces = [], [], [], {}, {}
    for line in lines:
        if not line.strip():
            continue
        try:
            cr = json.loads(line)
        except ValueError:
            continue
        p = cr.get("payload") or {}
        m = p.get("marker")
        if not isinstance(m, dict):
            continue
        why = None
        if operator_key is not None and not hmac.compare_digest(
                str(p.get("marker_tag") or ""), MI.tag(json.dumps(m, sort_keys=True).encode(), operator_key)):
            why = "bad_marker_tag"
        elif pub is not None and not MI.signature_ok(p, pub):
            why = "unsigned" if "marker_sig" not in p else "bad_or_foreign_signature"
        elif tsnap is not None and (cr.get("recv_ts") or 0) > tsnap and (m.get("issued_ts") or 0) > tsnap:
            why = "after_snapshot"
        elif monitor_fp is not None and isinstance(m.get("monitors"), list) and monitor_fp not in m["monitors"]:
            why = "marker_for_another_monitor"
        digest = hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()
        if not why and digest in seen:
            dup.append({"chain_seq": cr.get("seq"), "kind": m.get("marker"), "duplicate_of": seen[digest]})
            continue
        if not why and m.get("nonce") is not None and nonces.get(str(m["nonce"]), digest) != digest:
            why = "nonce_reused"
        if why:
            rej.append({"chain_seq": cr.get("seq"), "kind": m.get("marker"), "why": why})
            continue
        seen[digest] = cr.get("seq")
        if m.get("nonce") is not None:
            nonces[str(m["nonce"])] = digest
        acc.append(dict(m, chain_seq=cr.get("seq"), recv_ts=cr.get("recv_ts"), _sha256=digest))
    return acc, {"checked": True, "hmac": operator_key is not None, "signature": pub is not None,
                 "pubkey_fp": MI._fp(pub) if pub is not None else None,
                 "accepted": [{"chain_seq": m["chain_seq"], "kind": m.get("marker")} for m in acc], "rejected": rej,
                 "duplicates": dup}


# A row the purge deleted existed when it ran (E9 code review R7): the hub fires at the scheduled time, up to tol_s late
# (the tolerance band), and the purge then runs for a while. A removed row counts as purged only if the poll that
# first observed it copied the recorder at or before scheduled_ts + tol_s + PURGE_SEEN_SLACK_S ("first_seen_by").
PURGE_SEEN_SLACK_S = 60.0


def purge_cutoffs(markers, keep_s, tol_s=0.0):
    """Retention-scoped cutoffs (exp/rig/markers.py scoped_cutoff): scheduled_ts - keep_s + tol_s, with keep_s the
    verifier's own retention policy, never the record's. A PURGE marker counts only if it declares the retention scope
    and was issued before its scheduled time."""
    out = []
    for m in markers:
        if m.get("marker") != "PURGE" or m.get("scope") != "retention_policy":
            continue
        try:
            sched, issued = float(m["scheduled_ts"]), float(m["issued_ts"])
        except (KeyError, TypeError, ValueError):
            continue
        if issued > sched:
            continue
        out.append({"chain_seq": m.get("chain_seq"), "scheduled_ts": sched, "issued_ts": issued,
                    "cutoff": sched - float(keep_s) + float(tol_s), "c0": sched - float(keep_s),
                    "c1": sched - float(keep_s) + float(tol_s),
                    "first_seen_by": sched + float(tol_s) + PURGE_SEEN_SLACK_S})
    return sorted(out, key=lambda x: x["cutoff"])


def _fidx(fields, name):
    """Index of the value of column `name` in a (table, name, value, name, value, ...) field tuple."""
    for i in range(1, len(fields) - 1, 2):
        if fields[i] == name:
            return i + 1
    return None


def node_osid(n):
    """(committed?, old_state_id) of a loaded node: closure n[7]; stable: its old_state_id column; row: not committed."""
    if len(n) == 9:
        return True, n[7]
    if len(n) == 7:
        i = _fidx(n[6], "old_state_id")
        return (i is not None), (n[6][i] if i is not None else None)
    return False, None


def node_with_osid(n, v):
    if len(n) == 9:
        return n[:7] + (v,) + n[8:]
    i = _fidx(n[6], "old_state_id")
    return n[:6] + (n[6][:i] + (v,) + n[6][i + 1:],)


def fields_with(fields, name, v):
    i = _fidx(fields, name)
    return None if i is None else fields[:i] + (v,) + fields[i + 1:]


_SEG_RE = re.compile(rb'"seg": "?(-?\d+)"?')
_KL_RES = (re.compile(rb'"table": "(\w+)"'), re.compile(rb'"from": (-?\d+)'), re.compile(rb'"to": (-?\d+)'))
_KL_MARK = b'"kind": "keylog"'


class Escrow:
    """The escrow, indexed and read lazily (E9 code review R2). A full-history escrow is 2.6 GB; reading it into memory
    and parsing every line held about 7 bytes of heap per byte. One pass over the file records, per sealed second and
    per keylog sub-range (table, from, to), the byte offsets of its lines (found with the regular expressions below on
    the raw line: the monitor writes them with sort_keys, and node and row values are JSON lists, so these keys occur
    only at the top level); a line is read and parsed only when a second or a range is needed. An in-memory list of
    lines (tests, scripts) or a .gz file is indexed the same way, by position."""

    def __init__(self, path=None, lines=None):
        self.path, self._fh, self._lines = path, None, None
        self.seg, self.kl, self.kl_order = {}, {}, []
        self.n_seg = self.n_kl = 0
        if path is not None and not str(path).endswith(".gz"):
            self._fh = open(path, "rb")
            off = 0
            for raw in self._fh:
                self._index(raw, off)
                off += len(raw)
        else:
            if path is not None:
                lines = read_lines(path)
            self._lines = [x.encode("utf-8", "surrogateescape") if isinstance(x, str) else bytes(x) for x in lines]
            for n, raw in enumerate(self._lines):
                self._index(raw, n)

    @staticmethod
    def _add(d, k, ref):
        cur = d.get(k)
        if cur is None:
            d[k] = ref
        elif isinstance(cur, list):
            cur.append(ref)
        else:
            d[k] = [cur, ref]

    def _index(self, raw, ref):
        if not raw.strip():
            return
        if _KL_MARK in raw:
            self.n_kl += 1
            t_, f_, o_ = (r.search(raw) for r in _KL_RES)
            if t_ and f_ and o_:
                k = (t_.group(1).decode(), int(f_.group(1)), int(o_.group(1)))
                self._add(self.kl, k, ref)
            self.kl_order.append(ref)
        else:
            self.n_seg += 1
            m = _SEG_RE.search(raw)
            if m:
                self._add(self.seg, int(m.group(1)), ref)

    def _read(self, ref):
        if self._lines is not None:
            return self._lines[ref].decode("utf-8", "surrogateescape")
        self._fh.seek(ref)
        return self._fh.readline().decode("utf-8", "surrogateescape")

    def _get(self, d, k):
        refs = d.get(k)
        if refs is None:
            return []
        return [self._read(r) for r in (refs if isinstance(refs, list) else [refs])]

    def seg_lines(self, seg):
        """The lines of one sealed second, in file order."""
        try:
            return self._get(self.seg, int(seg))
        except (TypeError, ValueError):
            return []

    def kl_lines(self, key):
        """The lines of one keylog sub-range (table, from, to), in file order."""
        return self._get(self.kl, (key[0], int(key[1]), int(key[2])))

    def keylog_lines(self):
        """Every keylog line, in file order, one at a time."""
        for r in self.kl_order:
            yield self._read(r)

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def as_escrow(escrow):
    """An Escrow from an Escrow, a list of lines, or None."""
    if escrow is None or isinstance(escrow, Escrow):
        return escrow
    return Escrow(lines=escrow)


class PurgeEvidence:
    """What the verifier may use to undo a purge disconnect (E9 A1), all of it checked against the anchor before use:
    escrowed node tuples of sealed seconds (a line counts only when its tuples fold to its own root and that root is the
    anchored one), escrowed first-observation keylog tuples (read_escrow_keylog's checks), and the keylog itself: per
    committed key, the second it was first observed in (every keylog entry) and, for entries written with
    HOMEPROV_ROWBIND=1 whose listed hashes fold to their acc, its full row hash (not with rowbind=False, --no-rowbind:
    E9 code review m1). Escrow lines are read and checked only for the seconds and key ranges a disconnect needs.

    KEY EPOCHS (E9 code review R6). A monitor with HOMEPROV_KEYLOG_REWIND=1 commits keys again after a restore made the
    recorder's keys fall ("keylog_rewind" on the poll); a key in a rewound interval then has an earlier incarnation (a
    lost row) and a later one (the row the hub wrote after the restore). The evidence of a key is that of its LATEST
    incarnation: the entry committed in the latest epoch (first within it), its escrowed tuple taken from that exact
    second and its keylog tuple from that exact range. Without rewinds every key has one incarnation, as before."""

    def __init__(self, M, db, P, escrow_lines=None, rowbind=True):
        self.M, self.db, self.P, self.rowbind = M, db, P, rowbind
        self.escrow = as_escrow(escrow_lines)
        self.rewinds = collections.defaultdict(list)
        for pk, p in P["polls"].items():
            for t, rw in (p.get("keylog_rewind") or {}).items():
                try:
                    self.rewinds[t].append((tuple(pk), int(rw["to"]), int(rw["from"])))
                except (KeyError, TypeError, ValueError):
                    continue
        self.first_sec, self.row_hash, ranges = {}, {}, collections.defaultdict(set)
        self.epoch, self.kl_range = {}, {}
        for pk, p in P["polls"].items():
            for (t, lo, hi), e in (p.get("keylog_chunks") or {}).items():
                if hi > lo:
                    ranges[t].add((lo, hi))
                full = bound_rows(e, lo) if (e.get("bind") == "row_sha256" and rowbind) else None
                for x in e.get("rows") or []:
                    k = (t, lo + int(x[0]))
                    sec = int(x[2]) if len(x) > 2 and x[2] is not None else None
                    h = full[k[1]] if full is not None else None
                    if self.rewinds.get(t) and self.rewound(t, k[1]):
                        ep = self._epoch(t, k[1], tuple(pk))
                        if k in self.epoch and ep <= self.epoch[k]:
                            if ep == self.epoch[k]:
                                if sec is not None:
                                    self.first_sec.setdefault(k, sec)
                                if h is not None:
                                    self.row_hash.setdefault(k, h)
                            continue
                        self.epoch[k] = ep
                        self.first_sec.pop(k, None)
                        self.row_hash.pop(k, None)
                        if ep > 0:
                            self.kl_range[k] = (lo, hi)
                    if sec is not None:
                        self.first_sec.setdefault(k, sec)
                    if h is not None:
                        self.row_hash.setdefault(k, h)
        self.ranges = {t: sorted(v) for t, v in ranges.items()}
        self.seg_tuple, self.seg_at, self.seg_keys, self._klr, self._segs = {}, {}, {}, {}, set()
        con = vconnect(db)
        self.present = {r[0] for r in con.execute("SELECT state_id FROM states")}
        self.present_events = {r[0] for r in con.execute("SELECT event_id FROM events")}
        con.close()
        self._absent = None

    def rewound(self, t, key):
        return any(lo < key <= hi for _pk, lo, hi in self.rewinds.get(t, ()))

    def _epoch(self, t, key, pk):
        return sum(1 for rpk, lo, hi in self.rewinds.get(t, ()) if rpk <= pk and lo < key <= hi)

    def is_present(self, table, key):
        return key in (self.present if table == "states" else self.present_events)

    def row_verdict(self, n, pred_check=None):
        """Is the current row n exactly as committed (True), changed (False), or not checkable (None)? With
        pred_check(v, row_ts) given, a state row whose only change is old_state_id -> NULL counts as unchanged when the
        committed value v passes it (absent now, committed before the cutoff, purge-shaped in the tolerance band: a
        purge disconnect)."""
        table, key = kparse(n[1])
        sec = int(n[0] // 1.0) if self.M.ts_ok(n[0]) else None
        t = self.seg_node(key, sec) if table == "states" else self._seg_event(key, sec)
        if t is not None:
            if tuple(t) == tuple(n):
                return True
            if pred_check and table == "states" and node_osid(n)[1] is None and node_osid(t)[1] is not None:
                v = node_osid(t)[1]
                return tuple(node_with_osid(n, v)) == tuple(t) and bool(pred_check(v, n[0]))
            return False
        h = self.row_hash.get((table, key))
        if h is None:
            return None
        cur = self.M.keylog_rows(self.db, table, key - 1, key)
        if not cur:
            return None
        if cur[0][1].hex() == h:
            return True
        if pred_check and table == "states":
            fields = cur[0][4]
            i = _fidx(fields, "old_state_id")
            if i is not None and fields[i] is None:
                src, v = self.committed_osid(key, None, "keylog", sec)
                if src == "row_binding" and v is not None and pred_check(v, n[0]):
                    return True
        return False

    def _seg_event(self, key, sec):
        return self._seg_lookup("e:%d" % key, "events", key, sec)

    def _seg_lookup(self, nkey, table, key, sec):
        if sec is not None:
            self._seg(sec)
        if self.epoch.get((table, key), 0) > 0:
            return self.seg_at.get((nkey, str(sec))) if sec is not None else None
        return self.seg_tuple.get(nkey)

    def _seg(self, seg):
        """Index the escrowed tuples of one sealed second, from lines that reproduce the anchored root."""
        seg = str(seg)
        if seg in self._segs:
            return
        self._segs.add(seg)
        a = self.P["all_roots"].get(("second", seg))
        for line in (self.escrow.seg_lines(seg) if self.escrow is not None else ()):
            e = json.loads(line)
            if a is None or a.get("acc") != e.get("acc") or a.get("n") != e.get("n"):
                continue
            nodes = [self.M.from_jt(j) for j in e.get("nodes", [])]
            got = fold(self.M, nodes, "second", seg, e.get("encoding", "v2")) or {"acc": None, "n": 0}
            if got["acc"] == e["acc"] and got["n"] == e["n"]:
                for n in nodes:
                    self.seg_tuple.setdefault(n[1], n)
                    self.seg_at[(n[1], seg)] = n
                self.seg_keys[seg] = [n[1] for n in nodes]
                return

    def sealed_keys_gone(self, seg):
        """(key, sealed timestamp) of the rows a second was sealed with (its verified escrow line) that are absent now,
        or None when no verified escrow line holds that second."""
        self._seg(seg)
        keys = self.seg_keys.get(str(seg))
        if keys is None:
            return None
        return [(k, self.seg_at[(k, str(seg))][0]) for k in keys if not self.is_present(*kparse(k))]

    def _range_tuples(self, t, lo, hi):
        """The escrowed first-observation tuples of one committed key range, from lines read_escrow_keylog accepts."""
        key = (t, lo, hi)
        if key not in self._klr:
            good, _sum = read_escrow_keylog(self.escrow.kl_lines(key) if self.escrow is not None else (), self.M,
                                            self.P["polls"])
            d = {}
            for e in good:
                for k, f in e["_rows"]:
                    d.setdefault(k, f)
            self._klr[key] = d
        return self._klr[key]

    def seg_node(self, key, second):
        return self._seg_lookup("s:%d" % key, "states", key, second)

    def kl_fields(self, t, key, rng=None):
        """The escrowed first-observation tuple of row `key`: from the range rng = (lo, hi) when given, else from the
        range of its latest incarnation."""
        if rng is not None:
            return self._range_tuples(t, int(rng[0]), int(rng[1])).get(key)
        r = self.kl_range.get((t, key))
        if r is not None:
            return self._range_tuples(t, *r).get(key)
        rs = self.ranges.get(t) or []
        i = bisect.bisect_left(rs, (key, key)) - 1
        for lo, hi in rs[max(0, i):i + 2]:
            if lo < key <= hi:
                f = self._range_tuples(t, lo, hi).get(key)
                if f is not None:
                    return f
        return None

    def committed_before(self, key, cutoff):
        """Was state row `key` committed with a timestamp before `cutoff`? (evidence, or None)"""
        sec = self.first_sec.get(("states", key))
        n = self.seg_node(key, sec)
        if n is not None and self.M.ts_ok(n[0]):
            return {"by": "escrow", "ts": n[0]} if n[0] < cutoff else None
        f = self.kl_fields("states", key)
        if f is not None:
            i = _fidx(f, "last_updated_ts")
            ts = f[i] if i is not None else None
            if self.M.ts_ok(ts):
                return {"by": "keylog_escrow", "ts": ts} if ts < cutoff else None
        if sec is not None:
            return {"by": "keylog_first_observed_second", "second": sec} if sec + 1 <= cutoff else None
        return None

    def committed_osid(self, key, cutoff, prefer="segment", second=None):
        """(source, committed old_state_id) of state row `key`, whose old_state_id is now NULL, or (None, None) when
        nothing committed shows it. prefer="segment": the escrowed sealed tuple first (what the segment root folded);
        "keylog": the first-observation tuple or the per-row binding first (what the key range folded). With only the
        per-row binding, the committed value is the row v below `key` for which the row's current keylog fields with
        old_state_id = v hash to the bound row hash; tried are the entity's previous row if it is still there, then
        every absent key the keylog bound (the caller checks that v is absent and was committed before the cutoff)."""
        order = ("seg", "kl", "bind") if prefer == "segment" else ("kl", "bind", "seg")
        for src in order:
            if src == "seg":
                t = self.seg_node(key, second)
                if t is not None:
                    return "escrow", node_osid(t)[1]
            elif src == "kl":
                f = self.kl_fields("states", key)
                if f is not None:
                    i = _fidx(f, "old_state_id")
                    if i is not None:
                        return "keylog_escrow", f[i]
            else:
                h = self.row_hash.get(("states", key))
                if h is None:
                    continue
                cur = self.M.keylog_rows(self.db, "states", key - 1, key)
                if not cur:
                    continue
                fields = cur[0][4]
                i = _fidx(fields, "old_state_id")
                if i is None:
                    continue
                if self.M.H(self.M.encode_node_v2("keylog", fields)).hex() == h:
                    return "row_binding", fields[i]               # unchanged since its first observation
                # the entity's previous row, if it is still there (what the recorder writes as old_state_id): found,
                # it is reported as present and nothing is excused
                con = vconnect(self.db)
                prev = con.execute("SELECT max(state_id) FROM states WHERE state_id < ? AND metadata_id ="
                                   " (SELECT metadata_id FROM states WHERE state_id = ?)", (key, key)).fetchone()[0]
                con.close()
                if prev is not None and self.M.H(self.M.encode_node_v2(
                        "keylog", fields[:i] + (prev,) + fields[i + 1:])).hex() == h:
                    return "row_binding", prev
                if self._absent is None:
                    self._absent = sorted(k for (t_, k) in self.first_sec if t_ == "states" and k not in self.present)
                j = bisect.bisect_left(self._absent, key)
                for v in reversed(self._absent[:j]):        # every absent bound key below this one; whether the
                    g = fields[:i] + (v,) + fields[i + 1:]    # one found is older than the cutoff is checked by the caller
                    if self.M.H(self.M.encode_node_v2("keylog", g)).hex() == h:
                        return "row_binding", v
        return None, None


def apply_purge(M, db, P, viol, keylog_viol, groups, W, cuts, evidence, disconnect=True):
    """E9 A1: split violations and keylog violations into those a valid, retention-scoped PURGE marker explains and the
    rest. With cutoffs C (one per accepted marker):
      * a segment wholly before some C is excused only if it holds no row now (a purge deletes everything older than
        its cutoff);
      * the one segment per granularity that straddles some C is excused for removed rows and valid purge
        disconnects only (E10, D5: every row still in it exactly as committed, checked per row), never for inserted
        or changed ones;
      * a segment wholly at or after the latest C at or before its start (the purge-disconnect rule): excused only if
        restoring, for every current state row whose old_state_id is now NULL, the value committed at first read
        (escrow; else the per-row binding) reproduces the anchored root, and every restored value names a state row
        that is absent now and was committed with a timestamp before C. Any other change keeps the violation;
      * a failed keylog range: excused only if every logged row that is gone was first observed before some C, no row
        was added, and every present row is unchanged or differs only by such a disconnect (exactly: per-row binding,
        or the escrowed first-observation tuples; without either, only a range none of whose rows is left).
    disconnect=False leaves out the purge-disconnect rule (segments at or after a cutoff, and changed rows of a key
    range, are then never excused), which is the retention-scoped rule of round 12 (exp/rig/markers.py).
    Returns (kept, excused, kept_keylog, excused_keylog, report)."""
    report = {"cutoffs": cuts, "disconnect_rule": bool(disconnect), "excused": {"segments_before_cutoff": collections.Counter(),
                                           "straddling": collections.Counter(), "tolerance_band": collections.Counter(),
                                           "disconnect_segments": collections.Counter(),
                                           "keylog_ranges_purged": 0, "keylog_ranges_with_disconnects": 0},
              "disconnected_rows": {}, "not_excused": []}
    if not cuts:
        return viol, [], keylog_viol, [], report
    cvals = [c["c1"] for c in cuts]

    # THE TOLERANCE BAND (2026-10-10, E9 smoke 3). With --purge-tol-s, the hub's own cutoff (its fire time minus keep)
    # lies anywhere in [c0, c1] = [scheduled - keep, scheduled - keep + tol]: a row in the band is either purged or
    # retained (and then maybe disconnected), and the purge deletes everything below its cutoff, so in the band the
    # deleted rows all precede the retained ones. band_ok() checks that ordering: the latest deleted row of the band
    # (its escrowed timestamp, else the second the keylog first observed it in) is not after the earliest row still in
    # the band (ties inside one second are allowed when only the keylog's second is known).
    # THE EARLIEST ROW STILL IN THE BAND is read from the whole recorder (E9 code review R4): a daily verification
    # loads only the rows of its window, and the band lies 30 days before it, so taking it from the loaded rows made
    # band_ok() vacuous there.
    band_memo, rmin_memo = {}, {}

    def r_min_of(cut):
        key = (cut["c0"], cut["c1"])
        if key not in rmin_memo:
            con = vconnect(db)
            vals = []
            for t in ("states", "events"):
                c = M.TS_COL[t]
                x = con.execute("SELECT min(%s) FROM %s WHERE %s AND %s >= ? AND %s < ?" % (
                    c, t, M.TS_OK.format(c=c), c, c), key).fetchone()[0]
                if x is not None:
                    vals.append(x)
            con.close()
            rmin_memo[key] = min(vals) if vals else None
        return rmin_memo[key]

    def band_ok(cut):
        key = (cut["c0"], cut["c1"])
        if key in band_memo:
            return band_memo[key]
        c0, c1 = key
        ok = True
        if c1 > c0:
            r_min = r_min_of(cut)
            d_max, exact = None, True
            for (t, k), sec in evidence.first_sec.items():
                if not (int(c0 // 1.0) <= sec < c1) or evidence.is_present(t, k):
                    continue
                node = evidence.seg_node(k, sec) if t == "states" else evidence._seg_event(k, sec)
                ts = node[0] if node is not None and evidence.M.ts_ok(node[0]) else None
                if ts is None:
                    exact, ts = False, float(sec)
                d_max = ts if d_max is None else max(d_max, ts)
            if d_max is not None and r_min is not None:
                ok = (d_max < r_min) if exact else (int(d_max // 1.0) <= int(r_min // 1.0))
        band_memo[key] = ok
        return ok

    def pred_in_band_ok(ev, cut):
        """A deleted predecessor committed at or after c0 lies in the tolerance band: the purge deleted it only if the
        band's deletions are purge-shaped and it precedes every row still in the band (E9 code review R4)."""
        if ev is None:
            return False
        exact = "ts" in ev
        ts = float(ev["ts"]) if exact else float(ev["second"])
        if cut["c1"] <= cut["c0"] or (ts if exact else ts + 1.0) <= cut["c0"]:
            return True
        if not band_ok(cut):
            return False
        r = r_min_of(cut)
        return r is None or (ts < r if exact else int(ts) <= int(r // 1.0))

    def pred_check_for(cut):
        def ok(v, row_ts):
            if v in evidence.present:
                return False
            return pred_in_band_ok(evidence.committed_before(v, min(cut["c1"], row_ts)), cut)
        return ok

    def restore_rows(rows, cut, where):
        """(restored rows, disconnect entries, rows whose committed value was not found) or (None, why, None)."""
        cutoff = cut["c1"]
        out, dis, unknown = [], [], []
        for n in rows:
            committed, cur = node_osid(n)
            if not (committed and n[1].startswith("s:") and cur is None):
                out.append(n)
                continue
            src, v = evidence.committed_osid(int(n[1][2:]), cutoff, "segment", int(n[0] // 1.0))
            if src is None or v is None:
                out.append(n)                          # nothing committed shows another value: kept as it is
                if src is None:
                    unknown.append(n[1])
                continue
            if v in evidence.present:
                return None, "referenced_row_still_present", None
            ev = evidence.committed_before(v, cutoff)
            if ev is None:
                return None, "referenced_row_not_committed_before_cutoff", None
            if not pred_in_band_ok(ev, cut):
                return None, "referenced_row_in_the_band_not_purge_shaped", None
            out.append(node_with_osid(n, v))
            dis.append({"key": n[1], "second": str(int(n[0] // 1.0)), "restored_old_state_id": v, "source": src,
                        "referenced_row": ev, "cutoff": cutoff, "where": where})
        return out, dis, unknown

    kept, excused = [], []
    for v in viol:
        w = W[v["gran"]]
        lo, hi = int(v["seg"]) * w, (int(v["seg"]) + 1) * w
        why = None
        rows = groups[v["gran"]].get(v["seg"], [])
        band = next((c for c in cuts if lo < c["c1"] and hi > c["c0"] and c["c1"] > c["c0"]), None)
        if any(hi <= c["c0"] for c in cuts):
            if rows:
                why = "rows_left_in_a_segment_older_than_the_cutoff"
            else:
                v["excused_by"] = {"marker": "PURGE", "rule": "segment_older_than_cutoff_gone"}
                report["excused"]["segments_before_cutoff"][v["gran"]] += 1
        elif band is not None:
            # a segment reaching into the tolerance band: nothing older than c0 left, nothing inserted, and every row
            # still in it exactly as committed or a valid purge disconnect (checked per row: escrow tuple, else the
            # per-row binding); the rows it lost are checked by their key ranges (removed rows must be purge-shaped)
            inserted = (v.get("mechanism") == "row_inserted_with_low_key_or_moved_in" if v["rule"] == "coverage"
                        else (v["existing_rule"].get("delta_n") or 0) > 0)
            a = P["roots"].get((v["gran"], v["seg"])) or {}
            sealed = [n for n in rows if under(n, a.get("wm"))] if a.get("wm") is not None else rows
            verdicts = [evidence.row_verdict(n, pred_check_for(band)) if disconnect else evidence.row_verdict(n)
                        for n in sealed]
            if not band_ok(band):
                why = "band_deletion_not_purge_shaped"
            elif any(n[0] < band["c0"] for n in rows):
                why = "rows_left_in_a_segment_older_than_the_cutoff"
            elif inserted:
                why = "rows_inserted_into_the_band_segment"
            elif any(x is False for x in verdicts):
                why = "a_row_in_the_band_segment_changed"
            elif any(x is None for x in verdicts):
                why = "a_row_in_the_band_segment_cannot_be_checked_without_binding_or_escrow"
            else:
                v["excused_by"] = {"marker": "PURGE", "rule": "tolerance_band", "c0": band["c0"], "c1": band["c1"]}
                report["excused"]["tolerance_band"][v["gran"]] += 1
        elif any(lo < c < hi for c in cvals):
            # E10, FORMAL_DRAFT.md D5: a removed row, or a valid purge disconnect, only. Every row still in the segment
            # must be exactly as committed (or such a disconnect), checked per row (escrowed tuple, else the per-row
            # binding); without either, only a segment that lost every sealed row is excused.
            inserted = (v.get("mechanism") == "row_inserted_with_low_key_or_moved_in" if v["rule"] == "coverage"
                        else (v["existing_rule"].get("delta_n") or 0) > 0)
            scut = next(c for c in cuts if lo < c["c1"] < hi)
            a = P["roots"].get((v["gran"], v["seg"])) or {}
            sealed = [n for n in rows if under(n, a.get("wm"))] if a.get("wm") is not None else rows
            # (the comparison mode without the purge-disconnect rule keeps the round-12 rule, exp/rig/markers.py
            # explains_scoped: removed or changed rows)
            verdicts = [evidence.row_verdict(n, pred_check_for(scut)) for n in sealed] if disconnect else []
            if inserted:
                why = "rows_inserted_into_the_straddling_segment"
            elif any(x is False for x in verdicts):
                why = "a_row_in_the_straddling_segment_changed"
            elif any(x is None for x in verdicts):
                why = "a_row_in_the_straddling_segment_cannot_be_checked_without_binding_or_escrow"
            else:
                v["excused_by"] = {"marker": "PURGE", "rule": "straddling_segment"}
                report["excused"]["straddling"][v["gran"]] += 1
        else:
            cut = max((x for x in cuts if x["c1"] <= lo), key=lambda x: x["c1"], default=None)
            c = None if cut is None else cut["c1"]
            if not disconnect:
                why = "purge_disconnect_rule_off"
            elif c is None:
                why = "no_purge_cutoff_before_this_segment"
            else:
                a = P["roots"].get((v["gran"], v["seg"])) or {}
                sealed = [n for n in rows if under(n, a.get("wm"))] if a.get("wm") is not None else rows
                new, dis, unknown = restore_rows(sealed, cut, "%s:%s" % (v["gran"], v["seg"]))
                if new is None:
                    why = dis
                elif not dis:
                    # with only the per-row binding, a row that differs in more than old_state_id matches no candidate
                    why = ("committed_value_not_found_for_a_row_whose_old_state_id_is_null" if unknown
                           else "no_disconnected_row")
                else:
                    got = fold(M, new, v["gran"], v["seg"], a.get("encoding", "v2"))
                    if got is not None and got["acc"] == a.get("acc") and got["n"] == a.get("n"):
                        v["excused_by"] = {"marker": "PURGE", "rule": "purge_disconnect", "cutoff": c,
                                           "restored": [d["key"] for d in dis]}
                        report["excused"]["disconnect_segments"][v["gran"]] += 1
                        for d in dis:
                            report["disconnected_rows"].setdefault(d["key"], d)
                    else:
                        why = "restoring_the_disconnects_does_not_reproduce_the_anchored_root"
        if why:
            v["not_excused_by_purge"] = why
            report["not_excused"].append({"gran": v["gran"], "seg": v["seg"], "why": why})
            kept.append(v)
        else:
            excused.append(v)

    kept_k, excused_k = [], []
    chunks = {}
    for pk, p in P["polls"].items():
        for (t, lo, hi), e in (p.get("keylog_chunks") or {}).items():
            chunks.setdefault((tuple(pk), t, lo, hi), e)
    for kv in keylog_viol:
        t, (lo, hi) = kv["table"], kv["range"]
        e = chunks.get((tuple(kv["poll"]), t, lo, hi)) or {}
        logged = {lo + int(x[0]): x for x in e.get("rows") or []}
        full = bound_rows(e, lo) if (e.get("bind") == "row_sha256" and evidence.rowbind) else None
        now = {r[0]: r for r in M.keylog_rows(db, t, lo, hi)}
        present = sorted(set(now) & set(logged))
        esc = {k: evidence.kl_fields(t, k, (lo, hi)) for k in present} if full is None else {}
        exact = full is not None or all(f is not None for f in esc.values())
        unexplained, dis, purged = {}, [], []
        pc = (P["polls"].get(tuple(kv["poll"])) or {}).get("copy_at")
        for k in sorted(set(now) - set(logged)):
            unexplained[k] = "row_added_to_the_range"
        for k in sorted(set(logged) - set(now)):
            x = logged[k]
            sec = x[2] if len(x) > 2 else None
            older = [c for c in cuts if sec is not None and sec + 1 <= c["c1"] and (sec + 1 <= c["c0"] or band_ok(c))]
            if any(pc is not None and pc <= c["first_seen_by"] for c in older):
                purged.append(k)
            elif older:
                unexplained[k] = "removed_row_written_after_the_purge"     # first observed after the purge ran (R7)
            else:
                unexplained[k] = "removed_row_not_older_than_the_cutoff"
        for k in present if exact else []:
            r = now[k]
            same = (r[1].hex() == full[k]) if full is not None else (tuple(r[4]) == tuple(esc[k]))
            if same:
                continue
            cur = dict(zip(r[4][1::2], r[4][2::2])).get("old_state_id") if t == "states" else "n/a"
            row_ts = r[2] if M.ts_ok(r[2]) else -1
            cut = max((x for x in cuts if row_ts >= x["c0"]), key=lambda x: x["c0"], default=None)
            c = None if cut is None else min(cut["c1"], row_ts)     # its predecessor: deleted, so older than this
            if t != "states" or cur is not None:
                unexplained[k] = "row_changed"
                continue
            if not disconnect:
                unexplained[k] = "purge_disconnect_rule_off"
                continue
            if c is None:
                unexplained[k] = "changed_row_older_than_every_cutoff"
                continue
            src, v_ = evidence.committed_osid(k, c, "keylog", int(r[2] // 1.0) if M.ts_ok(r[2]) else None)
            ev = None if (src is None or v_ is None or v_ in evidence.present) else evidence.committed_before(v_, c)
            if ev is not None and not pred_in_band_ok(ev, cut):
                unexplained[k] = "predecessor_in_the_band_not_purge_shaped"
                continue
            g = fields_with(r[4], "old_state_id", v_) if ev is not None else None
            ok = g is not None and ((M.H(M.encode_node_v2("keylog", g)).hex() == full[k]) if full is not None
                                    else (tuple(g) == tuple(esc[k])))
            if not ok:
                unexplained[k] = "changed_row_is_not_a_purge_disconnect"
                continue
            dis.append({"key": "s:%d" % k, "second": str(int(r[2] // 1.0)) if M.ts_ok(r[2]) else None,
                        "restored_old_state_id": v_, "source": src, "referenced_row": ev, "cutoff": c,
                        "where": "keylog:%s(%d,%d]" % (t, lo, hi)})
        if not exact and present:
            # without the per-row binding or the escrowed tuples, rows left in the range cannot be checked: only a range
            # none of whose rows is left can be excused, and its suspects stay as they are
            unexplained.update({k: "rows_left_and_no_per_row_binding_or_escrow_to_check_them" for k in present})
        if not unexplained:
            kv["excused_by"] = {"marker": "PURGE", "rule": "purge_disconnect" if dis else "rows_purged"}
            report["excused"]["keylog_ranges_with_disconnects" if dis else "keylog_ranges_purged"] += 1
            for d in dis:
                report["disconnected_rows"].setdefault(d["key"], d)
            excused_k.append(kv)
            continue
        kv["not_excused_by_purge"] = sorted(set(unexplained.values()))
        report["not_excused"].append({"keylog": [t, lo, hi], "poll": kv["poll"],
                                      "why": kv["not_excused_by_purge"]})
        if exact:
            # the rows the purge explains are not suspects of this range; the rest are, with their seconds
            pre = t[0] + ":"
            keep = {pre + str(k) for k in unexplained}
            kv["explained_by_purge"] = sorted([pre + str(k) for k in purged] + [d["key"] for d in dis],
                                              key=lambda x: int(x[2:]))
            for f in ("changed", "added", "likely", "suspects"):
                kv[f] = [x for x in kv[f] if x["key"] in keep]
            kv["removed"] = [x for x in kv["removed"] if x in keep]
            kv["seconds"] = sorted({x for r_ in kv["suspects"] for x in (r_["second"], r_["first_observed_second"])
                                    if x}, key=int)
            for d in dis:
                report["disconnected_rows"].setdefault(d["key"], d)
        kept_k.append(kv)
    rows = sorted(report["disconnected_rows"].values(), key=lambda d: (int(d["key"][2:])))
    secs = sorted({d["second"] for d in rows if d["second"] is not None}, key=int)
    report["disconnected_rows"] = rows
    report["disconnects"] = {"n_rows": len(rows), "n_seconds": len(secs), "seconds": secs}
    report["excused"] = {k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in report["excused"].items()}
    return kept, excused, kept_k, excused_k, report


def check_namemap(M, lines, markers, storage=None, tsnap=None):
    """E9 A3: the name-map digest the monitor seals with HOMEPROV_NAMEMAP_DIR (exp/stages/e6_namemap.py computes the
    same with the monitor's own code). Over the records used (signature-checked), in record time order: every change of
    the anchored digest is a transition; it is excused only by a RENAME marker the operator issued (accepted by
    chain_markers) before the first record carrying the new digest, naming every part that changed with exactly its new
    part digest. With storage (the hub's .storage, read only) the current name map is compared with the last anchored
    digest (pending). Returns None when no record carries a name map.

    ONE MARKER, ONE CHANGE (2026-10-10, E9 smoke 3): a RENAME marker is consumed by the first transition it excuses, so
    a declared change, reverted and applied again later, is flagged the second time. Records after the recorder
    snapshot (tsnap) are left out, as the markers after it are (E9 smoke item 12)."""
    nm, unobs = [], []
    for line in lines:
        if not line.strip() or '"namemap"' not in line:
            continue
        cr = json.loads(line)
        p = cr.get("payload") or {}
        if p.get("observer") != "external-monitor" or not isinstance(p.get("namemap"), dict):
            continue
        if tsnap is not None and (p.get("ts") or 0.0) > tsnap:
            continue
        if p["namemap"].get("unobservable"):
            unobs.append({"chain_seq": cr.get("seq"), "ts": p.get("ts"), "reason": p["namemap"].get("reason")})
        elif "digest" in p["namemap"]:
            nm.append((p.get("ts") or 0.0, cr.get("seq") or 0, p["namemap"]))
    if not nm and not unobs:
        return None
    nm.sort(key=lambda x: (x[0], x[1]))
    renames = [m for m in markers if m.get("marker") == "RENAME" and isinstance(m.get("parts"), dict)]
    used = set()

    def excused(parts_changed, new_parts, seq, old_parts):
        why = {}
        for part in parts_changed:
            # a marker that also names the digest the part had before (its "from", E9 code review m4) excuses only a
            # change from exactly that digest
            hit = [m["chain_seq"] for m in renames if m["chain_seq"] not in used
                   and m["parts"].get(part) == new_parts[part]["digest"]
                   and (not isinstance(m.get("from"), dict) or part not in m["from"]
                        or m["from"][part] == (old_parts.get(part) or {}).get("digest"))
                   and (seq is None or (m.get("chain_seq") or 0) < seq)]
            why[part] = hit[0] if hit else None
        ok = all(v is not None for v in why.values())
        if ok:
            used.update(why.values())                 # consumed: each marker excuses one change
        return ok, why

    transitions, prev = [], None
    for ts, seq, c in nm:
        if prev is not None and c["digest"] != prev[2]["digest"]:
            pc = [k for k in c["parts"] if c["parts"][k]["digest"] != prev[2]["parts"].get(k, {}).get("digest")]
            ok, why = excused(pc, c["parts"], seq, prev[2]["parts"])
            transitions.append({"chain_seq": seq, "ts": ts, "prev_chain_seq": prev[1], "prev_ts": prev[0],
                                "from": prev[2]["digest"], "to": c["digest"], "parts_changed": pc,
                                "excused_by_rename_marker": ok, "marker_chain_seq": why})
        prev = (ts, seq, c)
    pending = None
    if storage and nm:
        cur = M.namemap_commitment(M.namemap_entries(storage))
        last = nm[-1]
        if cur["digest"] != last[2]["digest"]:
            pc = [k for k in cur["parts"] if cur["parts"][k]["digest"] != last[2]["parts"].get(k, {}).get("digest")]
            ok, why = excused(pc, cur["parts"], None, last[2]["parts"])
            pending = {"last_chain_seq": last[1], "last_ts": last[0], "from": last[2]["digest"], "to": cur["digest"],
                       "parts_changed": pc, "excused_by_rename_marker": ok, "marker_chain_seq": why}
    unexcused = sum(1 for t in transitions if not t["excused_by_rename_marker"]) + \
        (1 if pending and not pending["excused_by_rename_marker"] else 0)
    return {"records_with_namemap": len(nm), "records_namemap_unobservable": unobs[:200],
            "n_unobservable": len(unobs), "first": nm[0][2]["digest"] if nm else None,
            "last": nm[-1][2]["digest"] if nm else None, "transitions": transitions, "pending": pending,
            "rename_markers": [m["chain_seq"] for m in renames], "rename_markers_consumed": sorted(used),
            "unexcused_changes": unexcused,
            "verdict": ("unchanged" if not transitions and not pending else
                        "changed_with_declared_renames" if unexcused == 0 else "display_input_changed_after_seal")}


# The largest I - R a RESTORE marker may declare (E9 code review m2): a marker naming an old backup would excuse a long
# range. Pre-registered; --restore-max-age-s overrides it.
RESTORE_MAX_AGE_S = 86400.0
# The latest a RESTORE_DONE marker may come after its RESTORE marker (re-check N1): its issued_ts and the time the anchor
# received it, minus the RESTORE marker's issued_ts. Pre-registered; --restore-done-max-s overrides it.
RESTORE_DONE_MAX_S = 600.0


def _wm_ok(bw):
    return isinstance(bw, dict) and all(
        bw.get(t) is None or (isinstance(bw.get(t), int) and not isinstance(bw.get(t), bool))
        for t in ("states", "events")) and any(bw.get(t) is not None for t in ("states", "events"))


def restore_points(markers, tol_s, max_age_s=RESTORE_MAX_AGE_S, done_max_s=RESTORE_DONE_MAX_S):
    """Accepted RESTORE markers, each with the RESTORE_DONE marker that closes it (or None), and the rejected ones. A
    RESTORE marker counts only with the backup's time R (restore_point_ts) <= the time the operator declared it, I
    (issued_ts), I - R <= max_age_s, and the backup's last keys signed into it (backup_wm {"states", "events"}: K, the
    largest key of each table in the backup; E9 code review R1 item 4); tol_s is the verifier's allowance for rows
    committed just after R that carry a timestamp just before it (commit lag).

    RESTORE_DONE (re-check N1): the operator's signed statement that the restored hub is up. It names the RESTORE marker
    it closes (restore_nonce and/or restore_sha256, each of which must match when present, at least one present) and
    carries post_restart_wm (the restored recorder's largest keys the operator read after the restart) and
    hub_started_ts (the restored hub's start, between I and the DONE's own issued_ts; required since E10, D4). It counts only when issued at or
    after I and, like its arrival on the chain (recv_ts), at most done_max_s after I. The first one on the chain that
    passes is used; the others are listed as rejected."""
    out, rej = [], []
    for m in markers:
        if m.get("marker") != "RESTORE":
            continue
        why, bw = None, m.get("backup_wm")
        try:
            r, i = float(m["restore_point_ts"]), float(m["issued_ts"])
        except (KeyError, TypeError, ValueError):
            r = i = None
            why = "malformed"
        if why is None and not r <= i:
            why = "restore_point_after_the_marker"
        elif why is None and max_age_s is not None and i - r > float(max_age_s):
            why = "restore_point_older_than_the_maximum"
        elif why is None and not _wm_ok(bw):
            why = "no_signed_backup_wm"
        if why:
            rej.append({"chain_seq": m.get("chain_seq"), "kind": "RESTORE", "why": why})
            continue
        x = {"chain_seq": m.get("chain_seq"), "restore_point_ts": r, "issued_ts": i, "tol_s": float(tol_s),
             "backup_wm": {t: int(bw.get(t) or 0) for t in ("states", "events")}, "done": None}
        for d in sorted((d for d in markers if d.get("marker") == "RESTORE_DONE"),
                        key=lambda d: d.get("chain_seq") or 0):
            names = [(d.get("restore_nonce"), m.get("nonce")), (d.get("restore_sha256"), m.get("_sha256"))]
            given = [(a, b) for a, b in names if a is not None]
            if not given or any(a != b for a, b in given):
                continue                                  # another restore's
            dwhy = None
            try:
                di = float(d["issued_ts"])
                h = None if d.get("hub_started_ts") is None else float(d["hub_started_ts"])
            except (KeyError, TypeError, ValueError):
                di = h = None
                dwhy = "malformed"
            if dwhy is None and not (i <= di <= i + float(done_max_s)):
                dwhy = "restore_done_not_within_the_maximum_after_the_restore_marker"
            elif dwhy is None and d.get("recv_ts") is not None and float(d["recv_ts"]) > i + float(done_max_s):
                dwhy = "restore_done_anchored_after_the_maximum"
            elif dwhy is None and not _wm_ok(d.get("post_restart_wm")):
                dwhy = "no_post_restart_wm"
            elif dwhy is None and h is None:
                dwhy = "no_hub_started_ts"             # E10, FORMAL_DRAFT.md D4: required (E9's harness always sent it)
            elif dwhy is None and h is not None and not (i <= h <= di):
                dwhy = "hub_started_ts_outside_the_restore"
            if dwhy or x["done"] is not None:
                rej.append({"chain_seq": d.get("chain_seq"), "kind": "RESTORE_DONE",
                            "why": dwhy or "a_restore_done_for_this_restore_came_earlier"})
                continue
            x["done"] = {"chain_seq": d.get("chain_seq"), "issued_ts": di, "recv_ts": d.get("recv_ts"),
                         "post_restart_wm": {t: d["post_restart_wm"].get(t) for t in ("states", "events")},
                         "hub_started_ts": h}
        out.append(x)
    return sorted(out, key=lambda x: x["restore_point_ts"]), rej


def restore_read_back(P, I):
    """(copy_at, poll) of the first observable poll after I whose watermark, in either table, is below the largest
    watermark of the polls before I: the first poll that read the restored recorder. None when no such poll is on the
    chain (E9 code review R1 item 1)."""
    obs = [p for p in P["polls"].values() if p.get("through") is not None and isinstance(p.get("wm"), dict)
           and p.get("copy_at") is not None and not p.get("unobservable")]
    before = [p for p in obs if p["copy_at"] < I]
    if not before:
        return None, None
    top = {t: max((p["wm"].get(t) or 0) for p in before) for t in ("states", "events")}
    for p in sorted((p for p in obs if p["copy_at"] >= I), key=lambda p: (p["copy_at"], p["key"])):
        if any((p["wm"].get(t) or 0) < top[t] for t in top):
            return p["copy_at"], p
    return None, None


def restore_done_poll(P, done):
    """(copy_at, poll) of the first observable poll whose own record comes after the RESTORE_DONE record on the chain,
    or (the DONE's issued_ts, None) when no poll follows it."""
    obs = [p for p in P["polls"].values() if p.get("through") is not None and isinstance(p.get("wm"), dict)
           and p.get("copy_at") is not None and not p.get("unobservable") and p.get("chain_seq") is not None
           and p["chain_seq"] > (done.get("chain_seq") or 0)]
    if not obs:
        return done["issued_ts"], None
    p = min(obs, key=lambda p: (p["chain_seq"], p["key"]))
    return p["copy_at"], p


def apply_restore(M, db, P, viol, keylog_viol, groups, W, restores, evidence):
    """E9 (A6's RESTORE markers): split the remaining violations into those an accepted RESTORE marker explains and
    the rest. Restoring a backup taken at R removes every row committed after R and nothing else; the hub then writes
    new rows whose keys can reuse the lost ones. K = the backup's last key per table, signed into the marker
    (backup_wm); the recorder's own largest key among rows timestamped before I must equal it, else the marker excuses
    nothing (backup_wm_disagrees_with_the_recorder).

    THE RULE ENDS WHEN THE RESTORED RECORDER IS READ (E9 code review R1, re-check N1). A RESTORE marker excuses nothing
    without its RESTORE_DONE marker (restore_done_missing; restore_points). B = the copy time of the first poll anchored
    after the RESTORE_DONE marker (restore_done_poll), or, if earlier, of the first poll after I whose watermark fell
    below the pre-restore maximum (restore_read_back): a falling watermark alone could be postponed by rows planted in
    the restored recorder with keys above that maximum (N1). With hub_started_ts H in the RESTORE_DONE marker, a segment
    starting at or after H is never excused, a gone row must have been committed before H, and a reused key must hold a
    row timestamped at or after H. Only what was committed before B can have been changed by the restore:
      * a segment whose sealing poll copied before B and which ends after R - tol is excused only if every row it holds
        now is a backup row (key <= K) exactly as committed (escrowed tuple, else the per-row binding), and, for a second
        with a verified escrow line, every sealed row that is gone had a key above K (rule rows_from_the_backup). An
        emptied segment passes. A segment sealed from B on was sealed from the restored recorder and is never excused;
      * a failed keylog range committed by a poll that copied before B is excused only if every row of it with a key at
        or below K is present and unchanged (checked exactly: per-row binding or the escrowed first-observation tuples),
        every logged row above K was first observed no earlier than R - tol, and every row above K present now (a lost
        key the hub reused) is timestamped at or after I; those reused keys are listed (restore_reused_keys): their
        content is bound by their own post-restore segment roots (and, with HOMEPROV_KEYLOG_REWIND, by the keylog
        ranges committed from B on), which no RESTORE rule excuses. Rows the purge already explained stay explained.
    Returns (kept, excused, kept_keylog, excused_keylog, report)."""
    report = {"restores": restores, "excused": {"segments_after_restore_point": collections.Counter(),
                                                "keylog_ranges": 0},
              "not_excused": []}
    if not restores:
        return viol, [], keylog_viol, [], report
    con = vconnect(db)
    for x in restores:
        x["backup_last_key"] = dict(x["backup_wm"])
        x["recorder_last_key_before_marker"] = {}
        for t in ("states", "events"):
            c = M.TS_COL[t]
            x["recorder_last_key_before_marker"][t] = con.execute("SELECT max(%s) FROM %s WHERE %s AND %s < ?" % (
                M.KEY_COL[t], t, M.TS_OK.format(c=c), c), (x["issued_ts"],)).fetchone()[0] or 0
        b, bp = restore_read_back(P, x["issued_ts"])
        x["falling_watermark_at"], x["falling_watermark_poll"] = b, (list(bp["key"]) if bp else None)
        x["read_back_at"] = x["read_back_poll"] = x["read_back_by"] = None
        if x["recorder_last_key_before_marker"] != x["backup_last_key"]:
            x["status"] = "backup_wm_disagrees_with_the_recorder"
        elif x["done"] is None:
            x["status"] = "restore_done_missing"
        else:
            bd, bdp = restore_done_poll(P, x["done"])
            x["restore_done_at"], x["restore_done_poll"] = bd, (list(bdp["key"]) if bdp else None)
            if b is not None and b <= bd:
                x["read_back_at"], x["read_back_poll"], x["read_back_by"] = b, x["falling_watermark_poll"], \
                    "falling_watermark"
            else:
                x["read_back_at"], x["read_back_poll"], x["read_back_by"] = bd, x["restore_done_poll"], "restore_done"
            x["status"] = "applied"
    con.close()
    live = [x for x in restores if x["status"] == "applied"]

    def copy_at_of(pk):
        p = P["polls"].get(tuple(pk)) if pk is not None else None
        return None if p is None else p.get("copy_at")

    kept, excused = [], []
    for v in viol:
        w = W[v["gran"]]
        lo, hi = int(v["seg"]) * w, (int(v["seg"]) + 1) * w
        rows = groups[v["gran"]].get(v["seg"], [])
        a = P["all_roots"].get((v["gran"], v["seg"])) or {}
        sc = copy_at_of(a.get("poll"))
        rule, why = None, "no_applied_restore_marker" if not live else None
        for x in live:
            K, r0 = x["backup_last_key"], x["restore_point_ts"] - x["tol_s"]
            H = x["done"].get("hub_started_ts")
            if hi <= r0:
                why = "segment_wholly_before_the_restore_point"
                continue                              # the restore left it as it was
            if sc is None or sc >= x["read_back_at"]:
                why = "segment_sealed_after_the_restored_recorder_was_read"
                continue
            if H is not None and lo >= H:
                why = "segment_starts_after_the_hub_restarted"
                continue
            verdicts = [evidence.row_verdict(n) if kparse(n[1])[1] <= K[kparse(n[1])[0]] else False for n in rows]
            if any(x_ is False for x_ in verdicts):
                why = "a_row_that_is_not_an_unchanged_backup_row"
                continue
            if any(x_ is None for x_ in verdicts):
                why = "a_backup_row_cannot_be_checked_without_binding_or_escrow"
                continue
            gone = evidence.sealed_keys_gone(v["seg"]) if v["gran"] == "second" else None
            if gone and any(kparse(k_)[1] <= K[kparse(k_)[0]] for k_, _ts in gone):
                why = "a_backup_row_is_gone"
                continue
            if gone and H is not None and any(not (M.ts_ok(ts_) and ts_ < H) for _k, ts_ in gone):
                why = "a_gone_row_was_committed_after_the_hub_restarted"
                continue
            rule = "rows_from_the_backup"
            v["excused_by"] = {"marker": "RESTORE", "rule": rule, "chain_seq": x["chain_seq"]}
            report["excused"]["segments_after_restore_point"][v["gran"]] += 1
            break
        if rule:
            excused.append(v)
        else:
            v["not_excused_by_restore"] = why or "not_restore_shaped"
            report["not_excused"].append({"gran": v["gran"], "seg": v["seg"], "why": v["not_excused_by_restore"]})
            kept.append(v)

    chunks = {}
    for pk, p in P["polls"].items():
        for (t, lo, hi), e in (p.get("keylog_chunks") or {}).items():
            chunks.setdefault((tuple(pk), t, lo, hi), e)
    kept_k, excused_k = [], []
    for kv in keylog_viol:
        t, (lo, hi) = kv["table"], kv["range"]
        e = chunks.get((tuple(kv["poll"]), t, lo, hi)) or {}
        logged = {lo + int(x[0]): x for x in e.get("rows") or []}
        full = bound_rows(e, lo) if (e.get("bind") == "row_sha256" and evidence.rowbind) else None
        now = {r[0]: r for r in M.keylog_rows(db, t, lo, hi)}
        purged = {int(k[2:]) for k in kv.get("explained_by_purge") or []}
        pc = copy_at_of(kv["poll"])
        best, why, reused = None, ["no_applied_restore_marker"] if not live else [], []
        for x in live:
            K, r0, I = x["backup_last_key"][t], x["restore_point_ts"] - x["tol_s"], x["issued_ts"]
            H = x["done"].get("hub_started_ts")
            why, reused = [], []
            if pc is None or pc >= x["read_back_at"]:
                why.append("range_committed_after_the_restored_recorder_was_read")
                continue
            for k in sorted(set(logged) | set(now)):
                if k in purged:
                    continue
                lx, r = logged.get(k), now.get(k)
                sec = lx[2] if lx is not None and len(lx) > 2 else None
                if k <= K:
                    if lx is None or r is None:
                        why.append("row_in_the_backup_changed")
                        continue
                    if full is not None:
                        same = r[1].hex() == full[k]
                    else:
                        f = evidence.kl_fields(t, k, (lo, hi))
                        if f is None:
                            why.append("row_below_the_backup_key_unverifiable_without_binding_or_escrow")
                            continue
                        same = tuple(f) == tuple(r[4])
                    if not same:
                        why.append("row_in_the_backup_changed")
                    continue
                if lx is not None and (sec is None or sec + 1 <= r0):
                    why.append("lost_row_older_than_the_restore_point")
                elif lx is not None and r is None and H is not None and not sec + 1 <= H:
                    why.append("lost_row_first_observed_after_the_hub_restarted")
                elif r is not None and not (M.ts_ok(r[2]) and r[2] >= (I if H is None else H)):
                    why.append("row_above_the_backup_key_not_written_after_the_marker" if H is None
                               else "row_above_the_backup_key_not_written_after_the_hub_restarted")
                elif r is not None:
                    reused.append("%s:%d" % (t[0], k))
            if not why:
                best = x
                break
        if best is not None:
            kv["excused_by"] = {"marker": "RESTORE", "rule": "rows_after_the_restore_point",
                                "chain_seq": best["chain_seq"]}
            if reused:
                kv["restore_reused_keys"] = reused
            report["excused"]["keylog_ranges"] += 1
            excused_k.append(kv)
        else:
            kv["not_excused_by_restore"] = sorted(set(why))
            report["not_excused"].append({"keylog": [t, lo, hi], "poll": kv["poll"], "why": kv["not_excused_by_restore"]})
            kept_k.append(kv)
    report["excused"] = {k: (dict(v) if isinstance(v, collections.Counter) else v) for k, v in report["excused"].items()}
    return kept, excused, kept_k, excused_k, report


def verify(M, db, lines, late_bound, gap_s, scheme=None, t0=None, t1=None, tsnap=None, escrow_lines=None,
           restore_out=None, sign_pubkey=None, allow_unsigned=False, operator_key=None, operator_pubkey=None,
           purge_keep_s=None, purge_tol_s=0.0, rowbind=True, namemap_storage=None, purge_disconnect=True,
           recovery=True, restore_tol_s=None, restore_max_age_s=RESTORE_MAX_AGE_S,
           restore_done_max_s=RESTORE_DONE_MAX_S, refuse=True):
    """refuse (E10 hardening): run refuse_untrusted() on db first (run() does it on the private copy already).
    operator_key / operator_pubkey (E9): consider lifecycle markers the operator issued (PURGE with purge_keep_s,
    the verifier's own retention policy; RENAME for the name map); without them no marker is considered and the result
    is the earlier one. rowbind=False reads per-row-bound keylog entries by their prefixes (for comparison).
    purge_disconnect=False applies the retention-scoped PURGE rule without the purge-disconnect rule (for comparison).
    recovery=False skips the escrow recovery section (the purge rule still reads the escrow it needs).
    restore_tol_s: apply accepted RESTORE markers (apply_restore), with this commit-lag allowance before the restore
    point; without it RESTORE markers are listed and not applied. restore_max_age_s: the largest I - R accepted.
    escrow_lines: a list of escrow lines or an Escrow (read lazily, E9 code review R2)."""
    if late_bound is None or gap_s is None:
        raise ValueError("late_bound and gap_s are explicit parameters fixed before the run")
    if refuse:
        refuse_untrusted(db)
    recovery_on = recovery
    escrow_lines = as_escrow(escrow_lines)
    lines, sigs = check_signatures(M, lines, sign_pubkey, allow_unsigned)
    mon_fp = None
    if sign_pubkey and (operator_key is not None or operator_pubkey):
        try:
            mon_fp = _marker_issuer()._fp(_marker_issuer().load_pubkey(sign_pubkey))
        except (OSError, ValueError):
            mon_fp = None
    markers, marker_report = chain_markers(lines, operator_key, operator_pubkey, tsnap, mon_fp)
    P = parse_chain(lines, scheme, t0, tsnap)
    roots, polls = P["roots"], P["polls"]
    TL = Timeline(polls)
    BR = ObservationBreaks(polls, gap_s)                       # E10, D1
    csteps, csteps_rej = clock_steps(markers)                  # E10, D3 (operator-signed markers only)
    clock_excused = []
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
            brk = None
            if lat is not None and lat > late_bound:
                cs = clock_step_excuse(csteps, n[0], BR.first_holding_copy_at(table, k))
                if cs is not None:
                    # E10, D3: a row written by the hub's stepped-back clock inside a declared, bounded window
                    v, why = "excused_clock_step", "clock_step_marker"
                    clock_excused.append({"key": n[1], "ts": n[0], "gran": g, "seg": seg,
                                          "committed_after_lower_bound_s": lat, "marker_chain_seq": cs["chain_seq"]})
                else:
                    v, why = "attributable", why_base
            elif not TL.observed(table, k):
                # no known poll holds the row, so nothing bounds how late it was committed: neither benign nor
                # attributable (E9 A7: a chain cut, or withheld, right after a row was backdated into sealed time)
                v, why = "unobserved_late", "no_known_poll_holds_the_row"
            else:
                brk = BR.between(table, k)
                if brk:
                    # E10, D1: the monitor did not watch the recorder between the poll that lacked the row and the
                    # first that held it, so its commit delay is not bounded by LATE_BOUND
                    v, why = "unobserved_late", "observation_break:" + brk
                else:
                    v, why = "benign_late", "late_within_bound"
        cur = verdict_of(n[1], n[0])
        if lat is not None:
            cur["committed_after_lower_bound_s"] = lat
        cur["why"].append({"gran": g, "seg": seg, "verdict": v, "why": why})
        if v == "attributable":
            cur["verdict"] = "attributable"
        elif v == "unobserved_late" and cur["verdict"] in ("benign_late", "excused_clock_step"):
            cur["verdict"] = "unobserved_late"
        elif v == "excused_clock_step" and cur["verdict"] == "benign_late":
            cur["verdict"] = "excused_clock_step"
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

    # E10, D2 (FORMAL_DRAFT.md section 6, probe P3): the loop above sees only segments that still hold rows. A segment
    # first covered by a poll whose roots are not all on the chain, or that follows a poll missing from the chain, is
    # root_unknown whether or not it holds rows now: a second the hub emptied, sealed by the one record the anchor host
    # withheld, read "sealed empty" and so "match".
    for lo_, hi_, p in TL.pieces:
        gapped = bool(gap_before.get(p["key"]))
        incomplete = {g for g in W if not roots_complete(p, g)}
        if not gapped and not incomplete:
            continue
        for g, w in W.items():
            if not gapped and g not in incomplete:
                continue
            w = int(w)
            for s_ in range(int(lo_) // w, (int(hi_) - 1) // w + 1):
                start, end = s_ * w, (s_ + 1) * w
                seg = str(s_)
                if not (lo_ <= end - 1 < hi_) or seg in groups[g] or not in_window(g, seg):
                    continue
                if TL.first_cover(start, end) is not p:
                    continue
                a = P["all_roots"].get((g, seg))
                if a is not None and (a["wm"] is None or a["poll"] <= p["key"]):
                    continue                  # its root is on the chain: step 1 checks it
                root_unknown.append({"gran": g, "seg": seg, "first_cover_poll": list(p["key"]), "rows": 0,
                                     "roots_known": len(seen.get(p["key"], {}).get(g, ())),
                                     "n_sealed": (p.get("n_sealed") or {}).get(g),
                                     "why": ("a_poll_before_its_first_cover_is_missing_from_the_chain"
                                             if gapped else "first_cover_roots_incomplete") + ":no_row_now"})

    # step 2b: the keylog (review B1). Rows changed, re-timed, made visible or inserted into a committed key range after
    # their first observation are attributable; their current seconds are flagged.
    keylog_viol, keylog_checked, keylog_starts, keylog_holes = check_keylog(M, db, polls, rowbind)

    # E9 A1: violations a valid, retention-scoped PURGE marker explains (with the purge-disconnect rule) are set aside
    # before anything is attributed or flagged; without markers nothing changes
    purge, excused_viol, excused_kl = None, [], []
    cuts = purge_cutoffs(markers, purge_keep_s, purge_tol_s) if (markers and purge_keep_s is not None) else []
    if cuts:
        ev = PurgeEvidence(M, db, P, escrow_lines, rowbind)
        viol, excused_viol, keylog_viol, excused_kl, purge = apply_purge(M, db, P, viol, keylog_viol, groups, W, cuts,
                                                                          ev, purge_disconnect)
        for v in excused_viol:
            segs_out[v["gran"]]["violated"] -= bool(v["violation"])
            segs_out[v["gran"]]["excused_by_marker"] = segs_out[v["gran"]].get("excused_by_marker", 0) + 1
    elif markers and any(m.get("marker") == "PURGE" for m in markers):
        purge = {"note": "PURGE markers on the chain are not applied without --purge-keep-s (the verifier's own "
                         "retention policy)"}
    restore = None
    rps, rps_rej = (restore_points(markers, restore_tol_s, restore_max_age_s, restore_done_max_s)
                    if (markers and restore_tol_s is not None) else ([], []))
    if rps:
        ev = ev if cuts else PurgeEvidence(M, db, P, escrow_lines, rowbind)
        viol, ex_v, keylog_viol, ex_k, restore = apply_restore(M, db, P, viol, keylog_viol, groups, W, rps, ev)
        restore.update(rejected=rps_rej, max_age_s=restore_max_age_s, done_max_s=restore_done_max_s)
        for v in ex_v:
            segs_out[v["gran"]]["violated"] -= bool(v["violation"])
            segs_out[v["gran"]]["excused_by_marker"] = segs_out[v["gran"]].get("excused_by_marker", 0) + 1
        excused_viol, excused_kl = excused_viol + ex_v, excused_kl + ex_k
    elif rps_rej:
        restore = {"restores": [], "rejected": rps_rej, "max_age_s": restore_max_age_s,
                   "done_max_s": restore_done_max_s, "note": "no RESTORE marker accepted"}
    elif markers and any(m.get("marker") == "RESTORE" for m in markers):
        restore = {"note": "RESTORE markers on the chain are not applied without --restore-tol-s"}
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
    unknown_secs = {x["seg"] for x in root_unknown if x["gran"] == "second"}
    for v in viol:
        if v["gran"] == "second" or not v["attributable"] or v["rule"] != "coverage":
            continue
        w = int(W[v["gran"]])
        if any(int(x) // w == int(v["seg"]) for x in fine):
            v["localized_seconds"] = []
            v["explained_by_flagged_seconds"] = sorted((x for x in fine if int(x) // w == int(v["seg"])), key=int)
            continue
        if any(int(x) // w == int(v["seg"]) for x in unknown_secs):
            # a second inside it has no root to check (its record is missing from the chain): the change may sit
            # there, so the coarse violation is not pinned on the late rows of other seconds (E9 A7: a host that
            # withholds a tampered second's record would otherwise move the localisation onto an untouched neighbour)
            v["localized_seconds"] = []
            v["unlocalized_root_unknown_seconds"] = sorted((x for x in unknown_secs if int(x) // w == int(v["seg"])),
                                                           key=int)
            continue
        cand = [n for n in groups[v["gran"]].get(v["seg"], []) if under(n, v["wm"]) and n[1] in row_verdicts]
        v["localized_seconds"] = sorted({str(int(n[0] // 1.0)) for n in cand}, key=int)

    attributable_rows = sorted((r for r in row_verdicts.values() if r["verdict"] == "attributable"),
                               key=lambda r: ((r["ts"] if M.ts_ok(r["ts"]) else float("inf")), r["key"]))
    unobserved_rows = sorted((r for r in row_verdicts.values() if r["verdict"] == "unobserved_late"),
                             key=lambda r: (r["ts"], r["key"]))
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
    if escrow_lines is not None and recovery_on:
        recovery = recover(M, escrow_lines, roots, groups, flagged_seconds, restore_out, db, keylog_viol, polls)

    return {"P": P, "TL": TL, "segments": segs_out, "violations": viol, "attributable_rows": attributable_rows,
            "benign_late_rows": benign_rows, "unobserved_late_rows": unobserved_rows,
            "rows_in_unsealed_time": dict(unsealed), "flagged_seconds": flagged_seconds,
            "ambiguous_seconds": ambiguous_seconds, "flagged_segments": flagged_segments, "stalls": stalls,
            "observation_gaps": obs_gaps, "root_unknown_segments": root_unknown,
            "keylog": {"ranges_checked": keylog_checked, "violations": len(keylog_viol), "starts": keylog_starts,
                       "uncommitted_key_ranges": keylog_holes},
            "keylog_violations": keylog_viol, "malformed_rows": {"n": len(bad), "rows": bad[:MALFORMED_LIST_CAP]},
            "keylog_suspect_rows": suspect_rows,
            "invalid_text_rows": {"n": len(raw_text), "rows": raw_text[:MALFORMED_LIST_CAP]},
            "recovery": recovery, "groups": groups, "roots": roots, "checked": checked, "signatures": sigs,
            "markers": marker_report, "purge": purge, "restore": restore, "excused_violations": excused_viol,
            "excused_keylog_violations": excused_kl,
            "namemap": check_namemap(M, lines, markers, namemap_storage, tsnap),
            "clock_step": ({"accepted": csteps, "rejected": csteps_rej, "excused_rows": clock_excused,
                            "max_window_s": MAX_CLOCK_STEP_S, "seen_s": CLOCK_STEP_SEEN_S}
                           if (csteps or csteps_rej) else None)}


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


def escrow_keylog_ranges(escrow, M, polls, want):
    """read_escrow_keylog() over every keylog line of the escrow, one line at a time (E9 code review R2): the counts of
    verified and rejected lines, and for each wanted (table, from, to) the verified line read_escrow_keylog's order
    puts first (the smallest seq_local, then the first in the file)."""
    anchored = set()
    for p in polls.values():
        for (t, lo, hi), e in (p.get("keylog_chunks") or {}).items():
            anchored.add((t, lo, hi, e.get("n"), e.get("acc")))
    best, good, bad = {}, 0, 0
    for line in escrow.keylog_lines():
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
            good += 1
            k = (e["table"], int(e["from"]), int(e["to"]))
            if k in want and (k not in best or int(e.get("seq_local", 0)) < int(best[k].get("seq_local", 0))):
                e["_rows"] = rows
                best[k] = e
        else:
            bad += 1
    return best, {"keylog_lines_verified": good, "keylog_lines_rejected": bad}


def recover_keylog(M, db, keylog_viol, by_range, skip_keys):
    """For every failed keylog range, the first-observation tuples of its rows (re-review R3 and the E7 main run's late
    unlock): changed and removed rows are restored from them, rows added to the range afterwards are removed. A row a
    verified sealed-segment tuple already restores (skip_keys) keeps that tuple. by_range: the verified escrow line of
    each range (escrow_keylog_ranges)."""
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
    """Escrow recovery of the flagged seconds and failed key ranges. Only their lines are read and parsed (E9 code
    review R2); the output is that of the earlier full parse (escrow_lines: the number of sealed-second lines;
    keylog_lines_verified/rejected: over every keylog line)."""
    esc = as_escrow(escrow_lines)
    out, restore_plan = [], []
    for seg in flagged_seconds:
        a = roots.get(("second", seg))
        item = {"second": seg}
        lines = []
        for line in esc.seg_lines(seg):
            e = json.loads(line)
            if e.get("kind") == "keylog" or str(e.get("seg")) != str(seg):
                continue
            e["_nodes"] = [M.from_jt(j) for j in e.get("nodes", [])]
            lines.append(e)
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
    res = {"seconds": out, "escrow_lines": esc.n_seg}
    kplan, kranges = [], {}
    if keylog_viol and db:
        want = {(kv["table"], kv["range"][0], kv["range"][1]) for kv in keylog_viol}
        by_range, ksum = escrow_keylog_ranges(esc, M, polls or {}, want)
        res.update(ksum)
        skip = {n[1] for _s, e, _c in restore_plan for n in e["_nodes"]}
        res["keylog"], kplan, kranges = recover_keylog(M, db, keylog_viol, by_range, skip)
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
    refuse_untrusted(db)              # E10: quick_check first, before the checkpoint replays the copied WAL
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
    global VERIFY_HARDEN
    if getattr(a, "no_harden", False):
        VERIFY_HARDEN = False
    scratch = tempfile.mkdtemp(prefix="e7v_")
    lines = read_lines(a.chain)
    scheme = _scheme_of(lines, a.scheme)
    M = load_monitor(scheme, scratch, a.monitor_dir)
    try:
        db = _private_copy(a.db, scratch)
    except RecorderRefused as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        return {"check": "e7_verify", "refused": {"reason": exc.reason, "detail": exc.detail,
                                                  "db": os.path.abspath(a.db)}}
    t0, t1 = (float(a.window[0]), float(a.window[1])) if a.window else (None, None)
    if a.cmd == "late-delays":
        out = {"check": "e7_verify late-delays", "params": {"scheme": scheme, "window": a.window,
                                                          "snapshot_at": a.snapshot_at,
                                                          "chain": os.path.abspath(a.chain), "db": os.path.abspath(a.db)},
               **late_delays(M, db, lines, t0, t1, a.snapshot_at, scheme)}
        shutil.rmtree(scratch, ignore_errors=True)
        return out
    esc = Escrow(path=a.escrow) if a.escrow else None
    opkey = bytes.fromhex(open(a.operator_key).read().strip()) if a.operator_key else None
    res = verify(M, db, lines, a.late_bound, a.gap_s, scheme=scheme, t0=t0, t1=t1, tsnap=a.snapshot_at,
                 escrow_lines=esc, restore_out=a.restore_out, sign_pubkey=a.sign_pubkey,
                 allow_unsigned=a.allow_unsigned, operator_key=opkey, operator_pubkey=a.operator_pubkey,
                 purge_keep_s=a.purge_keep_s, purge_tol_s=a.purge_tol_s, rowbind=not a.no_rowbind,
                 namemap_storage=a.namemap_storage, purge_disconnect=not a.no_purge_disconnect,
                 restore_tol_s=a.restore_tol_s, restore_max_age_s=a.restore_max_age_s,
                 restore_done_max_s=a.restore_done_max_s, refuse=False)
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
    # E9 keys, present only when used (an E7 or E8 verification without them prints exactly what it printed before)
    if opkey is not None or a.operator_pubkey:
        out["params"].update(operator_key_given=opkey is not None, operator_pubkey=a.operator_pubkey,
                             purge_keep_s=a.purge_keep_s, purge_tol_s=a.purge_tol_s,
                             purge_disconnect=not a.no_purge_disconnect)
        out["params"].update(restore_tol_s=a.restore_tol_s, restore_max_age_s=a.restore_max_age_s,
                             restore_done_max_s=a.restore_done_max_s,
                             purge_seen_slack_s=PURGE_SEEN_SLACK_S)
        out.update(markers=res["markers"], purge=res["purge"], restore=res["restore"],
                   excused_violations=res["excused_violations"],
                   excused_keylog_violations=res["excused_keylog_violations"])
    if a.no_rowbind:
        out["params"]["rowbind"] = False
    if getattr(a, "no_harden", False):
        out["params"]["harden"] = False
    if res["namemap"] is not None:
        out["namemap"] = res["namemap"]
    if res["unobserved_late_rows"]:
        out["unobserved_late_rows"] = res["unobserved_late_rows"]
    if res.get("clock_step"):
        out["clock_step"] = res["clock_step"]
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
    v.add_argument("--operator-key", default=None, help="E9: the operator's HMAC key file (hex, as rig.marker_issuer "
                   "reads it); a marker counts only if its marker_tag verifies under it")
    v.add_argument("--operator-pubkey", default=None, help="E9: the operator's Ed25519 public key (PEM); a marker "
                   "counts only if its operator signature verifies under it")
    v.add_argument("--purge-keep-s", type=float, default=None, help="E9: the retention policy in seconds "
                   "(purge_keep_days * 86400); PURGE markers are applied only with it")
    v.add_argument("--purge-tol-s", type=float, default=0.0, help="E9: slack added to every PURGE cutoff")
    v.add_argument("--restore-tol-s", type=float, default=None, help="E9: apply RESTORE markers, allowing rows "
                   "timestamped this many seconds before the restore point to be lost (commit lag)")
    v.add_argument("--restore-max-age-s", type=float, default=RESTORE_MAX_AGE_S, help="E9: the largest issued_ts - "
                   "restore_point_ts a RESTORE marker may declare (default %(default)s)")
    v.add_argument("--restore-done-max-s", type=float, default=RESTORE_DONE_MAX_S, help="E9: the latest a RESTORE_DONE "
                   "marker may be issued and anchored after its RESTORE marker (default %(default)s); without one in "
                   "time the RESTORE marker excuses nothing")
    v.add_argument("--no-purge-disconnect", action="store_true", help="E9: apply PURGE markers without the "
                   "purge-disconnect rule (the round-12 retention-scoped rule alone), for comparison")
    v.add_argument("--no-rowbind", action="store_true", help="E9: read per-row-bound keylog entries by their 32-bit "
                   "prefixes (to report suspects without the per-row binding)")
    v.add_argument("--namemap-storage", default=None, help="E9: the hub's .storage directory (read only), to compare "
                   "the current name map with the last anchored digest")
    d = sub.add_parser("late-delays")
    for p in (v, d):
        p.add_argument("--no-harden", action="store_true", help="E10: without the untrusted-file settings and the "
                       "refusal checks (the earlier behaviour), for comparison")
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
    return 3 if "refused" in out else 0


if __name__ == "__main__":
    sys.exit(main())
