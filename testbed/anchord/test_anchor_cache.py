"""The anchor's chain state in memory (2026-10-09, before E9): same answers as the E8 daemon, also across a restart.

    python3 -m pytest -q testbed/anchord/test_anchor_cache.py

anchord.py now scans the chain file once and keeps its line offsets, size, line count and last line in memory, checked
against the file before each use. The E8 daemon is kept byte for byte as anchord_e8.py and anchord_linked_e8.py. Each
test drives both with the same appends at the same (fixed) clock and compares chain bytes, replies, heads and witness
pushes: linked and unlinked; with a restart in the middle (a new process scanning the file); after the host rewrites the
last record at rest or appends to the file behind the daemon's back; after a failed write. The per-append work is
checked too: one scan in total, and a witness push reads only the record it pushes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import sys
import time
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import chainverify as CV  # noqa: E402
from test_anchor_e8 import WKEY, Witness  # noqa: E402

_n = itertools.count()
E8_SHA = {"anchord_e8.py": "53d1ac92ebbca11e7d3aeda742c1bd790ccb98edb913ad0f4eda8b664af96dfd",
          "anchord_linked_e8.py": "966d2b351cec120538e059eb293293892cf5bb312fc7b310ffb8888f0fad9b5c"}


class Clock:
    """A fixed, shared clock: recv_ts enters the next record's prev_digest, so both daemons must see the same one."""

    def __init__(self):
        self.t = 1790000000.0

    def time(self):
        self.t += 0.25
        return self.t


def load(which, tmp, clock, link="v2", witness_url=""):
    """The E8 pair ("e8") or the current pair ("now") with its files in tmp; returns (linked module, anchord module)."""
    os.environ.update(HOMEPROV_ANCHOR_KEY="", HOMEPROV_ANCHOR_LINK=link)
    os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    a_name, l_name = ("anchord_e8.py", "anchord_linked_e8.py") if which == "e8" else ("anchord.py", "anchord_linked.py")
    for f in (a_name, l_name):
        if which == "e8":
            assert hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest() == E8_SHA[f]
    spec = importlib.util.spec_from_file_location("ac_%s_a_%d" % (which, next(_n)), os.path.join(HERE, a_name))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    saved = sys.modules.get("anchord")
    sys.modules["anchord"] = A                       # the linked entry point imports "anchord"
    try:
        spec = importlib.util.spec_from_file_location("ac_%s_l_%d" % (which, next(_n)), os.path.join(HERE, l_name))
        L = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(L)
    finally:
        if saved is None:
            sys.modules.pop("anchord", None)
        else:
            sys.modules["anchord"] = saved
    fake = types.SimpleNamespace(time=clock.time, monotonic=time.monotonic, sleep=time.sleep)
    A.time = L.time = fake
    A.CHAIN, A.REFUSALS, A.PUBLISH = (os.path.join(tmp, "chain.jsonl"), os.path.join(tmp, "refusals.jsonl"),
                                      os.path.join(tmp, "head.json"))
    L.WITNESS_URL, L.WITNESS_MODE, L.WITNESS_KEY = (witness_url + "/head") if witness_url else "", "sync", WKEY.encode()
    return L, A


def payload(i, big=0):
    return {"observer": "external-monitor", "ts": 1790000000.0 + i, "scheme": "stable", "encoding": "v2",
            "sealed": {"second": {str(1790000000 + i): {"acc": hashlib.sha256(b"%d" % i).hexdigest(), "n": i}}},
            **({"pad": "x" * big} if big else {})}


def strip(reply):
    """A reply without the push's wall time."""
    r = json.loads(json.dumps(reply))
    if isinstance(r.get("witness_push"), dict):
        r["witness_push"].pop("ms", None)
        (r["witness_push"].get("witness") or {}).pop("recv_ts", None)
    return r


def run_both(tmp_path, steps, link="v2", witness=False):
    """Run the same steps on the E8 pair and the current pair; each step is ("append", i), ("restart",), or a
    callable(L, A) acting on the files. Returns per pair: replies, heads, chain bytes, witness log."""
    out = {}
    for which in ("e8", "now"):
        d = str(tmp_path / which)
        os.makedirs(d)
        clock = Clock()
        w = Witness(os.path.join(d, "w")) if witness else None
        try:
            L, A = load(which, d, clock, link, w.url if w else "")
            replies, heads = [], []
            for st in steps:
                if st[0] == "append":
                    f = L._append
                    replies.append(strip(f(payload(st[1], *(st[2:] or ())))))
                    heads.append(L._head())
                elif st[0] == "restart":
                    L, A = load(which, d, clock, link, w.url if w else "")
                elif st[0] == "unlinked_append":
                    replies.append(strip(L.EVALUATED_APPEND(payload(st[1]))))
                else:
                    st[0](L, A)
            log = [json.loads(x) for x in open(w.log)] if w else []
            for h in log:
                h.pop("witness_recv_ts", None)
            out[which] = {"replies": replies, "heads": heads, "chain": open(A.CHAIN, "rb").read(), "log": log,
                          "A": A}
        finally:
            if w:
                w.close()
    return out["e8"], out["now"]


def same(e8, now):
    assert now["chain"] == e8["chain"]
    assert now["replies"] == e8["replies"]
    assert now["heads"] == e8["heads"]
    assert now["log"] == e8["log"]


def test_linked_with_a_witness_answers_as_the_e8_daemon(tmp_path):
    e8, now = run_both(tmp_path, [("append", i) for i in range(1, 30)], witness=True)
    same(e8, now)
    assert CV.verify_chain(now["chain"], witnessed_heads=now["log"])["ok"]
    assert now["A"]._chain["scans"] == 1                                 # scanned once, not once per append


def test_unlinked_daemon_answers_as_the_e8_daemon(tmp_path):
    e8, now = run_both(tmp_path, [("append", i) for i in range(1, 12)], link="v1")
    same(e8, now)


def test_a_restarted_anchor_gives_identical_answers(tmp_path):
    """Appends, a restart (a new daemon scanning the file it finds), more appends, another restart: the chain, every
    reply, every head and every witnessed head equal those of the E8 daemon doing the same, and equal those of a daemon
    that never restarted."""
    steps = [("append", i) for i in range(1, 8)] + [("restart",)] + [("append", i) for i in range(8, 15)] + \
        [("restart",), ("append", 15, 300000)] + [("append", i) for i in range(16, 20)]
    e8, now = run_both(tmp_path, steps, witness=True)
    same(e8, now)
    os.makedirs(tmp_path / "x")
    _e8x, nox = run_both(tmp_path / "x", [s for s in steps if s[0] != "restart"], witness=True)
    assert nox["chain"] == now["chain"] and nox["heads"] == now["heads"] and nox["log"] == now["log"]


def test_a_legacy_prefix_then_linked_records(tmp_path):
    steps = [("unlinked_append", i) for i in range(1, 6)] + [("append", i) for i in range(6, 9)] + [("restart",)] + \
        [("append", i) for i in range(9, 11)]
    e8, now = run_both(tmp_path, steps)
    same(e8, now)
    assert json.loads(now["chain"].split(b"\n")[5])["legacy_records"] == 5


def _rewrite_last_at_rest(L, A):
    lines = open(A.CHAIN, "rb").read().split(b"\n")
    r = json.loads(lines[-2])
    seg = r["payload"]["sealed"]["second"]
    k = next(iter(seg))
    seg[k]["acc"] = hashlib.sha256(b"host" + seg[k]["acc"].encode()).hexdigest()   # same length: same file size
    lines[-2] = json.dumps(r, sort_keys=True).encode()
    open(A.CHAIN, "wb").write(b"\n".join(lines))


def _append_behind_the_daemon(L, A):
    with open(A.CHAIN, "ab") as fh:
        fh.write(json.dumps({"seq": 99, "recv_ts": 1.0, "payload": {"note": "written by the host"}},
                            sort_keys=True).encode() + b"\n")


@pytest.mark.parametrize("change", [_rewrite_last_at_rest, _append_behind_the_daemon])
def test_a_file_changed_behind_the_daemon_is_read_as_it_is(tmp_path, change):
    steps = [("append", i) for i in range(1, 6)] + [(change,)] + [("append", i) for i in range(6, 9)]
    e8, now = run_both(tmp_path, steps)
    same(e8, now)
    assert now["A"]._chain["scans"] == 2


def test_a_failed_write_is_not_remembered(tmp_path):
    os.makedirs(tmp_path / "d")
    L, A = load("now", str(tmp_path / "d"), Clock())
    for i in range(1, 4):
        L._append(payload(i))
    real = A.os.fsync
    A.os.fsync = lambda fd: (_ for _ in ()).throw(OSError("disk full"))
    try:
        with pytest.raises(OSError):
            L._append(payload(4))
    finally:
        A.os.fsync = real
    assert A._chain["state"] is None                                      # dropped: the file is scanned next time
    o = L._append(payload(5))
    data = open(A.CHAIN, "rb").read()
    assert o["seq"] == 5 == len([x for x in data.split(b"\n") if x.strip()])  # the line written before fsync failed counts
    assert CV.verify_chain(data)["ok"]


def test_a_push_reads_only_what_it_pushes(tmp_path):
    os.makedirs(tmp_path / "d")
    L, A = load("now", str(tmp_path / "d"), Clock())
    for i in range(1, 40):
        L._append(payload(i, 20000))
    reads = []
    real = A._chain_read
    A._chain_read = lambda p, a, b: (reads.append(b - a), real(p, a, b))[1]
    L._append(payload(40, 20000))
    lines = L._chain_lines(40, 40)
    size = os.path.getsize(A.CHAIN)
    assert len(lines) == 1 and json.loads(lines[0])["seq"] == 40
    assert max(reads) < 30000 < size / 20                                 # one record at a time, never the file
    assert L._chain_lines(3, 5) == [x.decode() for x in open(A.CHAIN, "rb").read().split(b"\n")[2:5]]


def test_the_anchord_entry_point_answers_as_the_e8_daemon_across_a_restart(tmp_path):
    steps = [("unlinked_append", i) for i in range(1, 6)] + [("restart",)] + [("unlinked_append", i) for i in range(6, 9)]
    e8, now = run_both(tmp_path, steps, link="v1")
    same(e8, now)
    assert CV.verify_chain(now["chain"])["link"] == "v1"
