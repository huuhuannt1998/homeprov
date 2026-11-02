"""HOMEPROV monitor, version 2 (round 17, review r6): monitor.py unchanged, plus the committed column list in every
signed coverage record.

WHY. Under the stable-columns scheme a segment's root covers every column PRAGMA table_info lists when the segment is
sealed. A verifier that does not know that list recomputes over the columns of the recorder it is given, so a release
whose migration adds a column to states or events turns almost every sealed second into a violation (review r6: R1 W5,
R2 W1, R4 W4; E10 offline, exp/out/e10_main_migration_offline.json). Version 2 makes the list part of the evidence.

HOW. This module runs monitor.py's own code: it reads monitor/monitor.py, checks its SHA-256 against the version E10,
E10b, E11 and E12 registered (V1_SHA256; HOMEPROV_V2_ALLOW_OTHER_V1=1 accepts another), and executes it in this module's
namespace, so every function, constant and environment option is monitor.py's and a test or a container that sets
module attributes (append, time) reaches the code that uses them. It then replaces four names of that namespace:
  load_stable, keylog_rows  read the poll's committed column list once from the poll's own view (a read transaction or a
                            copy; pinned_columns.current_columns) and load with exactly that list
                            (pinned_columns.load_stable_cols / keylog_rows_cols, byte-identical to monitor.py's functions
                            for that list). If two reads of one poll see different lists, the poll fails closed
                            (load_failed, unobservable), as any load failure does.
  load_state                gives the state an instance id (8 random bytes, hex) on first use and keeps the list history
                            {"history": [[from_seq, digest], ...], "lists": {digest: list}}; a list the poll reads that
                            differs from the last entry is appended at the poll's seq_local before anything is sealed or
                            saved, so the saved state and every record of that poll agree.
  sign_record               adds to every coverage record, before it is signed, "committed_columns": {"v": 1,
                            "instance": id, "history": [[from_seq, digest], ...], "lists": {digest: {"states": [...],
                            "events": [...]}}}. A root sealed by poll s of this instance (its own record's seq_local, or
                            the seal_seq of a frozen or conflicted root) was computed over the list of the last history
                            entry with from_seq <= s. Every record carries the whole history of its instance, so a
                            withheld record never hides a list; a monitor that loses its state starts a new instance.
Nothing else changes: the rows, roots, keylog ranges, escrow lines and records are monitor.py's, except for the added
field (about 0.5-1 KB per record) and the fail-closed poll above. Other schemes (closure, row) commit a fixed field set;
for them no list is recorded and nothing changes.

    HOMEPROV_SCHEME=stable ... python3 monitor/monitor_v2.py          (in place of monitor.py)
"""
import hashlib as _hashlib
import os as _os
import sys as _sys

_HERE = _os.path.dirname(_os.path.abspath(__file__))
V1_PATH = _os.path.join(_HERE, "monitor.py")
# monitor.py as E10, E10b, E11 and E12 registered it (exp/out/e1*_preregistration.json code_sha256)
V1_SHA256 = "4b9931cb7d1cffae6485fb2b660b68d733da9f73e5c22c22ca7265d49ceaa9b7"
_V2_DOC = __doc__
_src = open(V1_PATH, "rb").read()
V1_SHA256_FOUND = _hashlib.sha256(_src).hexdigest()
if V1_SHA256_FOUND != V1_SHA256 and _os.environ.get("HOMEPROV_V2_ALLOW_OTHER_V1") != "1":
    raise SystemExit("monitor_v2: %s has sha256 %s, not the registered %s (HOMEPROV_V2_ALLOW_OTHER_V1=1 to accept)"
                     % (V1_PATH, V1_SHA256_FOUND, V1_SHA256))
_v2_name = __name__
globals()["__name__"] = "homeprov_monitor_v1_body"      # monitor.py's own `if __name__ == "__main__"` must not run here
try:
    exec(compile(_src, V1_PATH, "exec"), globals())
finally:
    globals()["__name__"] = _v2_name
__doc__ = _V2_DOC

if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
import pinned_columns as PC                             # noqa: E402

V2_COLUMNS_VERSION = PC.COLUMNS_VERSION
_V1 = {"load_stable": load_stable, "keylog_rows": keylog_rows,       # noqa: F821  (defined by monitor.py above)
       "sign_record": sign_record, "load_state": load_state}         # noqa: F821
_ST = {"st": None}
_POLL = {"seq": None, "cols": None}


class _Namespace:
    """This module's globals as attributes (what pinned_columns' functions call M.<name> on), looked up at call time."""

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name) from None


_SELF = _Namespace()


def _history(st):
    return st.setdefault("v2_columns", {"history": [], "lists": {}})


def poll_columns(db) -> dict:
    """The committed column list of this poll's view; recorded in the state's history at the poll's seq_local."""
    cols = PC.current_columns(_SELF, db)
    st = _ST["st"]
    seq = st.get("seq_local") if st is not None else None
    if seq is not None and _POLL["seq"] == seq and _POLL["cols"] is not None and _POLL["cols"] != cols:
        raise RuntimeError("the committed column list changed within one poll (seq_local %s)" % seq)
    _POLL["seq"], _POLL["cols"] = seq, cols
    if st is not None and seq is not None:
        h = _history(st)
        d = PC.digest(cols)
        h["lists"].setdefault(d, cols)
        if not h["history"] or h["history"][-1][1] != d:
            if h["history"] and h["history"][-1][0] == seq:
                h["history"][-1] = [seq, d]            # a repeated read of the same poll (direct-read retry)
            else:
                h["history"].append([seq, d])
    return cols


def load_stable(db, since=None, until=None):                          # noqa: F811
    """monitor.py load_stable() over this poll's committed column list (recorded, see poll_columns)."""
    return PC.load_stable_cols(_SELF, db, poll_columns(db), since, until)


def keylog_rows(db, table, lo, hi, limit=None):                        # noqa: F811
    """monitor.py keylog_rows(); under the stable scheme over this poll's committed column list."""
    if SCHEME != "stable":                                             # noqa: F821
        return _V1["keylog_rows"](db, table, lo, hi, limit)
    return PC.keylog_rows_cols(_SELF, db, table, lo, hi, poll_columns(db)[table], limit)


def load_state():                                                      # noqa: F811
    st = _V1["load_state"]()
    if SCHEME == "stable":                                             # noqa: F821
        st.setdefault("v2_instance", _os.urandom(8).hex())
        _history(st)
    _ST["st"] = st
    return st


def committed_columns_field(st) -> dict | None:
    h = (st or {}).get("v2_columns") or {}
    if not h.get("history"):
        return None
    return {"v": V2_COLUMNS_VERSION, "instance": st.get("v2_instance"),
            "history": [list(x) for x in h["history"]],
            "lists": {d: h["lists"][d] for d in sorted({x[1] for x in h["history"]})}}


def sign_record(rec: dict) -> dict:                                    # noqa: F811
    """monitor.py sign_record() over the record with "committed_columns" added (coverage records, stable scheme)."""
    if SCHEME == "stable" and "seq_local" in rec and _ST["st"] is not None:                 # noqa: F821
        f = committed_columns_field(_ST["st"])
        if f is not None:
            rec = dict(rec, committed_columns=f)
    return _V1["sign_record"](rec)


if __name__ == "__main__":
    main()                                                             # noqa: F821
