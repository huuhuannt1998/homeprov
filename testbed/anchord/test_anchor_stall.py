"""Anchor stall and serving-limit tests (round 13, E7 "anchor hardening").

    python3 -m pytest -q testbed/anchord/test_anchor_stall.py                        # the tests (about one minute)
    python3 testbed/anchord/test_anchor_stall.py record --out exp/out/e7_anchor_stall_unit.json   # the saved result

The earlier daemon (anchord_r12.py, byte-identical to the anchord.py every run up to E5 used) served on one thread and
read a request body with no timeout, so one slow client blocked every append. The stall test runs the same workload
against it and against the hardened daemon (anchord.py, alone and through anchord_linked.py), each in its own process on
127.0.0.1 with a fresh HMAC key and default serving limits:

  STALL  for stall_s seconds, slow clients hold connections open and reopen them whenever the daemon closes one. Four
         kinds, n_per_kind of each: 'silent' (connects, sends nothing), 'slow_headers' (a request line and a header that
         grows by one byte every 0.5 s and never ends), 'partial_body' (complete headers, Content-Length 4096, 11 body
         bytes, then nothing), 'trickle_body' (complete headers, Content-Length 4096, one body byte every 0.5 s).
  APPEND meanwhile an authenticated client (the monitor's role) attempts one append per period, each on a new
         connection with a client timeout of CLIENT_TIMEOUT_S, scheduled so every attempt ends inside the stall. An
         attempt counts as accepted when it gets HTTP 200, and as accepted within the bound when that took at most
         APPEND_BOUND_S.
  AFTER  the slow clients stop; after settle_s seconds three more appends are attempted, then the chain is read: which
         attempts it holds (an attempt the client saw fail but the chain holds is a late commit), whether the sequence
         numbers are consecutive, and chainverify's verdict.

The saved result (record) runs two scenarios: 'flood' (the four kinds above) and 'one_silent_client' (a single silent
client). Against the earlier daemon they fail differently: in the flood the slow clients also fill its listen backlog, so
the authenticated connection is never accepted; with one silent client the request is queued, the client times out, and
the daemon appends it after the stall (a late commit the client never learns of).

The original daemon is served exactly as its __main__ block does (its handler class H on socketserver.TCPServer), with its
three file paths redirected to a temporary directory and the address 127.0.0.1 instead of 0.0.0.0:9900.

The other tests run the daemons in-process: oversized, malformed and short bodies are refused; untagged and forged
appends are refused with 401 exactly as before; the replies, chain records and refusal records of the hardened daemon
equal the earlier daemon's for the same requests (recv_ts aside); concurrent appends get consecutive sequence numbers,
the chain file only grows, first-write-wins holds under a race, and the linked chain still verifies; slow connections are
cut at the read timeout and the request deadline; the head witness has the same limits.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import hmac
import http.client
import importlib.util
import itertools
import json
import os
import platform
import secrets
import shutil
import socket
import socketserver
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ORIGINAL = os.path.join(HERE, "anchord_r12.py")
ORIGINAL_SHA256 = "7b1ef9f1e11a36584eb0fde218fc6a0bb234ff33071e80990d0d354883a0c17f"
sys.path.insert(0, HERE)
import chainverify as CV  # noqa: E402

APPEND_BOUND_S = 2.0          # every authenticated append to the hardened daemon must be answered 200 within this
CLIENT_TIMEOUT_S = 5.0        # the authenticated client's socket timeout (the monitor uses 10 s)
TRICKLE_S = 0.5               # one byte every TRICKLE_S for the trickling slow clients
SLOW_KINDS = ("silent", "slow_headers", "partial_body", "trickle_body")
DAEMONS = ("original", "hardened", "hardened_linked")
_n = itertools.count()


# ----------------------------------------------------------------------------------------------------------- helpers

def tag(key: str, body: bytes) -> str:
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def rec(i: int, root: str | None = None, seg: str | None = None) -> dict:
    seg = str(1790000000 + i) if seg is None else seg
    return {"observer": "e7-stall-unit", "attempt": i, "scheme": "closure", "encoding": "v2", "ts": 1790000000.0 + i,
            "sealed": {"second": {seg: {"acc": root or hashlib.sha256(b"%d" % i).hexdigest(), "n": 1}}}}


def enc(obj) -> bytes:
    return json.dumps(obj, sort_keys=True).encode()


def req(port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None,
        timeout: float = 5.0) -> tuple:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, (json.loads(data) if data else None)
    finally:
        c.close()


def post(port: int, obj_or_body, key: str = "", timeout: float = 5.0, auth: str | None = None) -> tuple:
    body = obj_or_body if isinstance(obj_or_body, bytes) else enc(obj_or_body)
    hdr = {"Content-Type": "application/json"}
    if auth is not None:
        hdr["X-HP-Auth"] = auth
    elif key:
        hdr["X-HP-Auth"] = tag(key, body)
    return req(port, "POST", "/append", body, hdr, timeout)


def raw(port: int, data: bytes, timeout: float = 5.0, shut: bool = False) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(data)
        if shut:
            s.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            try:
                b = s.recv(65536)
            except ConnectionResetError:
                break
            if not b:
                break
            buf += b
        return buf
    finally:
        s.close()


def status_of(buf: bytes):
    return int(buf.split(b" ", 2)[1]) if buf.startswith(b"HTTP/") else None


def json_of(buf: bytes):
    return json.loads(buf.split(b"\r\n\r\n", 1)[1])


def read_jsonl(path: str) -> list:
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, "rb").read().split(b"\n") if l.strip()]


def sha256_file(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def load(tmp: str, which: str = "hardened", key: str = "", link: str = "v2"):
    """A fresh daemon module with its files in tmp. which: hardened | original | linked. Returns the anchord module
    (for 'linked', the anchord the linked daemon imported, with its _append and _head replaced)."""
    os.environ["HOMEPROV_ANCHOR_KEY"] = key
    os.environ["HOMEPROV_ANCHOR_LINK"] = link
    if which == "linked":
        sys.modules.pop("anchord", None)
        spec = importlib.util.spec_from_file_location("anchord_linked_s%d" % next(_n),
                                                      os.path.join(HERE, "anchord_linked.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        A = m.A
    else:
        path = ORIGINAL if which == "original" else os.path.join(HERE, "anchord.py")
        spec = importlib.util.spec_from_file_location("anchord_%s_s%d" % (which, next(_n)), path)
        A = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(A)
    A.CHAIN = os.path.join(tmp, "chain.jsonl")
    A.REFUSALS = os.path.join(tmp, "refusals.jsonl")
    A.PUBLISH = os.path.join(tmp, "published", "head.json")
    return A


class InProcess:
    """Serve a loaded daemon module on 127.0.0.1 in this process: the original on TCPServer, as its __main__ does."""

    def __init__(self, A, original: bool = False):
        cls = socketserver.TCPServer if original else A.AnchorServer
        self.srv = cls(("127.0.0.1", 0), A.H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------------------------------------- the daemon as a process

def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve_cli(kind: str, tmp: str, port: str) -> None:
    """Child process: serve one daemon on 127.0.0.1:port with its files in tmp."""
    port = int(port)
    if kind == "original":
        assert sha256_file(ORIGINAL) == ORIGINAL_SHA256
        spec = importlib.util.spec_from_file_location("anchord_r12", ORIGINAL)
        A = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(A)
    elif kind == "hardened":
        import anchord as A
    elif kind == "hardened_linked":
        import anchord_linked as L
        A = L.A
    else:
        raise SystemExit("unknown daemon kind %r" % kind)
    A.CHAIN = os.path.join(tmp, "chain.jsonl")
    A.REFUSALS = os.path.join(tmp, "refusals.jsonl")
    A.PUBLISH = os.path.join(tmp, "published", "head.json")
    if kind == "original":
        # anchord_r12.py's __main__ block, verbatim except for the paths above and the loopback address.
        A._rebuild_roots()
        threading.Thread(target=A._publisher, daemon=True).start()
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("127.0.0.1", port), A.H) as s:
            s.serve_forever()
    elif kind == "hardened":
        A.serve("127.0.0.1", port)
    else:
        L.serve("127.0.0.1", port)


def launch(kind: str, tmp: str, key: str):
    port = free_port()
    env = dict(os.environ, HOMEPROV_ANCHOR_KEY=key, HOMEPROV_ANCHOR_LINK="v2", PYTHONDONTWRITEBYTECODE="1")
    for v in ("HOMEPROV_ANCHOR_IO_TIMEOUT_S", "HOMEPROV_ANCHOR_REQUEST_DEADLINE_S", "HOMEPROV_ANCHOR_MAX_BODY",
              "HEAD_WITNESS_URL"):
        env.pop(v, None)                                   # default serving limits, no witness
    log = open(os.path.join(tmp, "daemon.log"), "wb")
    proc = subprocess.Popen([sys.executable, "-u", os.path.abspath(__file__), "serve", kind, tmp, str(port)],
                            env=env, stdout=log, stderr=subprocess.STDOUT, cwd=HERE)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("daemon %s exited: %s" % (kind, open(os.path.join(tmp, "daemon.log")).read()))
        try:
            if req(port, "GET", "/head", timeout=1.0)[0] == 200:
                return proc, port
        except OSError:
            pass
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError("daemon %s did not come up" % kind)


# ------------------------------------------------------------------------------------------------------- the stall

_BODY_HEADERS = (b"POST /append HTTP/1.1\r\nHost: anchor\r\nContent-Type: application/json\r\n"
                 b"Content-Length: 4096\r\nX-HP-Auth: " + b"0" * 64 + b"\r\n\r\n")
_INITIAL = {"silent": b"",
            "slow_headers": b"POST /append HTTP/1.1\r\nHost: anchor\r\nContent-Type: application/json\r\nX-Pad: ",
            "partial_body": _BODY_HEADERS + b'{"sealed": ',
            "trickle_body": _BODY_HEADERS}
_TRICKLES = ("slow_headers", "trickle_body")


def _slow_client(kind: str, port: int, stop_at: float, log: list) -> None:
    """Hold connections of one kind open until stop_at, reopening each one the daemon closes."""
    while time.monotonic() < stop_at:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        except OSError as e:
            log.append({"kind": kind, "connect_failed": type(e).__name__})
            time.sleep(0.2)
            continue
        opened, ended, status = time.monotonic(), None, None
        try:
            s.settimeout(0.1)
            if _INITIAL[kind]:
                s.sendall(_INITIAL[kind])
            next_byte = opened + TRICKLE_S
            while time.monotonic() < stop_at:
                try:
                    b = s.recv(4096)
                    if not b:
                        ended = "daemon_closed"
                        break
                    status = status or status_of(b)
                except socket.timeout:
                    pass
                if kind in _TRICKLES and time.monotonic() >= next_byte:
                    s.sendall(b"a")
                    next_byte += TRICKLE_S
        except OSError:
            ended = "daemon_reset"
        log.append({"kind": kind, "held_s": time.monotonic() - opened, "ended": ended or "held_to_stall_end",
                    "status": status})
        s.close()


def _attempt(i: int, port: int, key: str, out: dict) -> None:
    """One authenticated append on a new connection. phase says where a failure happened: 'connect' (the connection
    was never accepted) or 'response' (the request was sent and no reply came within the client timeout)."""
    body = enc(rec(i))
    t = time.monotonic()
    st, reply, err, phase = None, None, None, "connect"
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=CLIENT_TIMEOUT_S)
    try:
        c.connect()
        phase = "response"
        c.request("POST", "/append", body=body, headers={"Content-Type": "application/json",
                                                          "X-HP-Auth": tag(key, body)})
        r = c.getresponse()
        data = r.read()
        st, reply, phase = r.status, (json.loads(data) if data else None), None
    except Exception as e:                                  # noqa: BLE001
        err = type(e).__name__
    finally:
        c.close()
    out[i] = {"status": st, "latency_s": time.monotonic() - t, "error": err, "failed_at": phase,
              "seq": reply.get("seq") if isinstance(reply, dict) else None}


def run_stall(kind: str, stall_s: float = 12.0, n_per_kind: int = 2, period_s: float = 1.0,
              settle_s: float = 3.0, post_attempts: int = 3, kinds: tuple = SLOW_KINDS) -> dict:
    """The stall workload against one daemon in its own process; returns what was measured."""
    tmp = tempfile.mkdtemp(prefix="e7stall_")
    key = secrets.token_hex(32)
    proc, port = launch(kind, tmp, key)
    try:
        times, t = [], 1.0
        while t + CLIENT_TIMEOUT_S <= stall_s - 0.5:      # every attempt has ended (or timed out) before the stall ends
            times.append(t)
            t += period_s
        slow_log, attempts = [], {}
        t0, t0_wall = time.monotonic(), time.time()
        stop_at = t0 + stall_s
        slow = [threading.Thread(target=_slow_client, args=(k, port, stop_at, slow_log), daemon=True)
                for k in kinds for _ in range(n_per_kind)]
        for th in slow:
            th.start()
        workers = []
        for i, at in enumerate(times, 1):
            time.sleep(max(0.0, t0 + at - time.monotonic()))
            th = threading.Thread(target=_attempt, args=(i, port, key, attempts), daemon=True)
            th.start()
            workers.append(th)
        for th in workers:
            th.join(CLIENT_TIMEOUT_S + 5)
        for th in slow:
            th.join(stall_s + 5)
        time.sleep(settle_s)
        after = {}
        for i in range(len(times) + 1, len(times) + 1 + post_attempts):
            _attempt(i, port, key, after)
        chain_bytes = open(os.path.join(tmp, "chain.jsonl"), "rb").read() if \
            os.path.exists(os.path.join(tmp, "chain.jsonl")) else b""
        refusals = read_jsonl(os.path.join(tmp, "refusals.jsonl"))
    finally:
        proc.kill()
        proc.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)

    chain = [json.loads(l) for l in chain_bytes.split(b"\n") if l.strip()]
    in_chain = {r["payload"].get("attempt"): r for r in chain}
    ok = [a for a in attempts.values() if a["status"] == 200]
    within = [a for a in ok if a["latency_s"] <= APPEND_BOUND_S]
    late = sorted(i for i, a in attempts.items() if a["status"] != 200 and i in in_chain)
    by_kind = {}
    for k in kinds:
        rows = [r for r in slow_log if r.get("kind") == k and "held_s" in r]
        ended = [r for r in rows if r["ended"] != "held_to_stall_end"]
        by_kind[k] = {"connections": len(rows),
                      "connect_failures": sum(1 for r in slow_log if r.get("kind") == k and "connect_failed" in r),
                      "ended_by_daemon": len(ended),
                      "held_to_stall_end": len(rows) - len(ended),
                      "max_hold_when_ended_by_daemon_s": round(max((r["held_s"] for r in ended), default=0.0), 3),
                      "statuses_seen": dict(collections.Counter(str(r["status"]) for r in ended if r["status"]))}
    vr = CV.verify_chain(chain_bytes)
    lat = sorted(a["latency_s"] for a in attempts.values())
    return {
        "daemon": kind,
        "stall_s": stall_s, "slow_client_kinds": list(kinds), "slow_clients_per_kind": n_per_kind,
        "attempt_period_s": period_s,
        "attempts_during_stall": len(attempts),
        "accepted_during_stall": len(ok),
        "accepted_within_bound_during_stall": len(within),
        "failed_during_stall": dict(collections.Counter("%s at %s" % (a["error"] or a["status"], a["failed_at"])
                                                        for a in attempts.values() if a["status"] != 200)),
        "max_latency_accepted_s": round(max((a["latency_s"] for a in ok), default=0.0), 4) if ok else None,
        "median_latency_accepted_s": round(statistics.median(a["latency_s"] for a in ok), 4) if ok else None,
        "max_latency_all_attempts_s": round(lat[-1], 4) if lat else None,
        "late_commits": {"count": len(late), "attempts": late,
                         "committed_at_s_after_stall_start": [round(in_chain[i]["recv_ts"] - t0_wall, 3)
                                                              for i in late]},
        "after_stall": {"attempts": post_attempts, "accepted": sum(1 for a in after.values() if a["status"] == 200),
                        "max_latency_s": round(max(a["latency_s"] for a in after.values()), 4)},
        "slow_connections": by_kind,
        "chain": {"records": len(chain), "seq_consecutive": [r["seq"] for r in chain] == list(range(1, len(chain) + 1)),
                  "attempt_order": [r["payload"].get("attempt") for r in chain],
                  "chainverify_ok": vr["ok"], "link": vr["link"]},
        "refusals_by_reason": dict(collections.Counter(r["reason"] for r in refusals)),
        "attempt_detail": [{"attempt": i, "scheduled_s": times[i - 1], "status": a["status"], "error": a["error"],
                            "failed_at": a["failed_at"], "latency_s": round(a["latency_s"], 4),
                            "in_chain": i in in_chain}
                           for i, a in sorted(attempts.items())],
    }


# ---------------------------------------------------------------------------------------------------------- tests

def _assert_not_blocked(r: dict) -> None:
    assert r["attempts_during_stall"] >= 6
    assert r["accepted_within_bound_during_stall"] == r["attempts_during_stall"], r
    assert r["after_stall"]["accepted"] == r["after_stall"]["attempts"]
    assert r["late_commits"]["count"] == 0
    assert r["chain"]["seq_consecutive"] and r["chain"]["chainverify_ok"]
    assert r["chain"]["attempt_order"] == list(range(1, r["attempts_during_stall"] + r["after_stall"]["attempts"] + 1))
    for k, v in r["slow_connections"].items():         # every slow connection was cut by the daemon, none held it
        assert v["ended_by_daemon"] >= 1 and v["held_to_stall_end"] <= r["slow_clients_per_kind"], (k, v)
        assert v["max_hold_when_ended_by_daemon_s"] <= 10.0 + 1.5, (k, v)   # the default request deadline + slack


def test_stall_hardened_does_not_block():
    r = run_stall("hardened")
    _assert_not_blocked(r)
    assert r["chain"]["link"] == "v1"


def test_stall_hardened_linked_does_not_block():
    r = run_stall("hardened_linked")
    _assert_not_blocked(r)
    assert r["chain"]["link"] == "v2"


def test_stall_original_blocks():
    """The same workload against the earlier daemon: no append is answered while the slow clients hold it."""
    r = run_stall("original")
    assert r["attempts_during_stall"] >= 6
    assert r["accepted_during_stall"] == 0, r
    assert r["after_stall"]["accepted"] == r["after_stall"]["attempts"]      # it recovers once they let go


def test_oversized_and_malformed_bodies_refused(tmp_path):
    key = "k" * 32
    A = load(str(tmp_path), "hardened", key)
    assert A.MAX_BODY == 16 * 1024 * 1024                  # the default
    A.MAX_BODY = 1024
    s = InProcess(A)
    try:
        hdr = b"POST /append HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n"
        # declared too large: refused 413 without reading the body
        buf = raw(s.port, b"POST /append HTTP/1.1\r\nHost: a\r\nContent-Length: 1025\r\n\r\n")
        assert status_of(buf) == 413 and json_of(buf)["reason"] == "body_too_large"
        # a valid tagged record under the limit is still accepted
        assert post(s.port, rec(1), key) == (200, {"ok": True, "seq": 1})
        # a tagged record over the limit, sent in full: refused (or the connection reset before the reply), not appended
        big = rec(2)
        big["pad"] = "x" * 4096
        try:
            st, _ = post(s.port, big, key)
        except OSError:
            st = None
        assert st in (413, None)
        # malformed lengths are refused at once instead of raising or reading until the client closes
        t = time.monotonic()
        assert status_of(raw(s.port, hdr + b"Content-Length: -1\r\n\r\n{}")) == 400
        assert status_of(raw(s.port, hdr + b"Content-Length: abc\r\n\r\n{}")) == 400
        assert time.monotonic() - t < 1.0
        # a body that ends before its Content-Length is refused
        buf = raw(s.port, hdr + b"Content-Length: 100\r\n\r\n" + b"{" * 10, shut=True)
        assert status_of(buf) == 400 and json_of(buf)["reason"] == "short_body"
        # JSON that is not an object is refused as bad json (the earlier daemon raised)
        assert post(s.port, b"[1, 2]", key) == (400, {"error": "bad json"})
    finally:
        s.close()
    chain = read_jsonl(A.CHAIN)
    assert [r["payload"]["attempt"] for r in chain] == [1]
    reasons = [r["reason"] for r in read_jsonl(A.REFUSALS)]
    assert reasons[0] == "body_too_large" and reasons.count("bad_content_length") == 2 and "short_body" in reasons
    tl = next(r for r in read_jsonl(A.REFUSALS) if r["reason"] == "body_too_large")
    assert tl["declared_length"] == 1025 and tl["http"] == 413 and tl["body_len"] == 0


def test_untagged_and_forged_appends_refused(tmp_path):
    key = "k" * 32
    A = load(str(tmp_path), "hardened", key)
    s = InProcess(A)
    try:
        body = enc(rec(1))
        assert post(s.port, body) == (401, {"error": "unauthenticated append refused", "reason": "missing_signature"})
        assert post(s.port, body, auth="ab" * 32) == (401, {"error": "unauthenticated append refused",
                                                            "reason": "bad_signature"})
        assert post(s.port, body, auth=tag("x" * 32, body)) == (401, {"error": "unauthenticated append refused",
                                                                      "reason": "bad_signature"})
        # a tag with non-ASCII bytes: 401 (the earlier daemon raised in compare_digest and sent no reply)
        buf = raw(s.port, b"POST /append HTTP/1.0\r\nContent-Length: %d\r\nX-HP-Auth: \xe9\xe9\r\n\r\n" % len(body)
                  + body)
        assert status_of(buf) == 401 and json_of(buf)["reason"] == "bad_signature"
        assert post(s.port, body, key)[0] == 200
    finally:
        s.close()
    assert len(read_jsonl(A.CHAIN)) == 1
    assert [r["reason"] for r in read_jsonl(A.REFUSALS)] == ["missing_signature", "bad_signature", "bad_signature",
                                                             "bad_signature"]


def _script(port: int, key: str) -> list:
    """One fixed sequence of requests; returns (status, reply) for each, recv_ts removed from replies."""
    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k != "recv_ts"}
        return x
    a, b = rec(1, seg="S1"), rec(2, seg="S2")
    clash = rec(3, seg="S1", root="ff" * 32)
    same = rec(4, seg="S1", root=a["sealed"]["second"]["S1"]["acc"])
    out = [post(port, a, key), post(port, b, key),
           post(port, rec(5)),                                   # untagged
           post(port, rec(5), auth="cd" * 32),                   # forged
           post(port, b"not json", key),
           post(port, clash, key),                               # first-write-wins conflict
           post(port, same, key),                                # the same root again is fine
           post(port, b"", key),                                 # empty body, tagged
           req(port, "GET", "/head"), req(port, "GET", "/nope"),
           req(port, "PUT", "/append", b"{}"), req(port, "DELETE", "/append"), req(port, "PATCH", "/append", b"{}"),
           req(port, "POST", "/other", b"{}")]
    return [(st, strip(r)) for st, r in out]


def test_protocol_and_records_equal_the_earlier_daemon(tmp_path):
    """Same requests to the earlier and the hardened daemon: same statuses, replies, chain records and refusal records
    (recv_ts aside), with a key and without one."""
    for key in ("k" * 32, ""):
        res = {}
        for which in ("original", "hardened"):
            d = str(tmp_path / ("%s_%d" % (which, len(key))))
            os.makedirs(d)
            A = load(d, which, key)
            s = InProcess(A, original=(which == "original"))
            try:
                replies = _script(s.port, key)
            finally:
                s.close()
            drop = lambda rows: [{k: v for k, v in r.items() if k != "recv_ts"} for r in rows]  # noqa: E731
            res[which] = (replies, drop(read_jsonl(A.CHAIN)), drop(read_jsonl(A.REFUSALS)))
        assert res["hardened"] == res["original"]
        statuses = [st for st, _ in res["hardened"][0]]
        assert statuses == ([200, 200, 401, 401, 400, 409, 200, 200, 200, 404, 405, 405, 405, 405] if key else
                            [200, 200, 200, 200, 400, 409, 200, 200, 200, 404, 405, 405, 405, 405])


def test_record_format_equals_the_earlier_daemon(tmp_path):
    """The chain writer is unchanged: the hardened daemon's records equal anchord_r12.py's, byte for byte bar recv_ts."""
    os.makedirs(tmp_path / "o"); os.makedirs(tmp_path / "h")
    O, Hd = load(str(tmp_path / "o"), "original"), load(str(tmp_path / "h"), "hardened")
    for i in range(1, 6):
        assert O._append(rec(i))["seq"] == Hd._append(rec(i))["seq"] == i
    def norm(p):
        return [l.replace(b'"recv_ts": %s' % json.dumps(json.loads(l)["recv_ts"]).encode(), b'"recv_ts": 0')
                for l in open(p, "rb").read().split(b"\n") if l.strip()]
    assert norm(O.CHAIN) == norm(Hd.CHAIN)


def _concurrent(A, key: str, threads: int = 16, per_thread: int = 25) -> tuple:
    s = InProcess(A)
    snaps, stop, replies = [], threading.Event(), {}

    def sampler():                                          # the chain file must only ever grow by appending
        prev = b""
        while not stop.is_set():
            cur = open(A.CHAIN, "rb").read() if os.path.exists(A.CHAIN) else b""
            snaps.append(cur.startswith(prev))
            prev = cur
            time.sleep(0.002)

    def worker(t):
        for j in range(per_thread):
            i = t * 1000 + j
            st, r = post(s.port, rec(i), key)
            replies[i] = (st, r["seq"] if st == 200 else None)

    smp = threading.Thread(target=sampler)
    smp.start()
    ws = [threading.Thread(target=worker, args=(t,)) for t in range(threads)]
    for w in ws:
        w.start()
    for w in ws:
        w.join(60)
    stop.set(); smp.join(10)
    s.close()
    return replies, snaps


def _check_concurrent(A, replies: dict, snaps: list, threads: int = 16, per_thread: int = 25) -> list:
    n = threads * per_thread
    assert len(replies) == n and all(st == 200 for st, _ in replies.values())
    chain = read_jsonl(A.CHAIN)
    assert [r["seq"] for r in chain] == list(range(1, n + 1))              # consecutive, no gaps, no duplicates
    assert {r["payload"]["attempt"]: r["seq"] for r in chain} == {i: q for i, (_, q) in replies.items()}
    for t in range(threads):                                              # each client's appends stay in its order
        seqs = [replies[t * 1000 + j][1] for j in range(per_thread)]
        assert seqs == sorted(seqs)
    assert len(snaps) > 10 and all(snaps)                                   # append-only while it was written
    return chain


def test_concurrent_appends_ordered_and_append_only(tmp_path):
    key = "k" * 32
    A = load(str(tmp_path), "hardened", key)
    replies, snaps = _concurrent(A, key)
    _check_concurrent(A, replies, snaps)
    r = CV.verify_chain(open(A.CHAIN, "rb").read())
    assert r["ok"] and r["link"] == "v1"


def test_concurrent_appends_linked_chain_verifies(tmp_path):
    key = "k" * 32
    A = load(str(tmp_path), "linked", key)
    replies, snaps = _concurrent(A, key)
    _check_concurrent(A, replies, snaps)
    data = open(A.CHAIN, "rb").read()
    r = CV.verify_chain(data, {"seq": 400, "head_digest": CV.record_digest(data.split(b"\n")[-2])})
    assert r["ok"] and r["link"] == "v2" and r["linked_records"] == 400


def test_first_write_wins_under_a_race(tmp_path):
    """32 clients offer 32 different roots for one segment at the same instant: exactly one is anchored."""
    key = "k" * 32
    A = load(str(tmp_path), "hardened", key)
    s = InProcess(A)
    gate, out = threading.Barrier(32), []

    def go(i):
        body = enc(rec(i, seg="RACE", root=hashlib.sha256(b"r%d" % i).hexdigest()))
        gate.wait()
        out.append(post(s.port, body, key)[0])

    ts = [threading.Thread(target=go, args=(i,)) for i in range(32)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    s.close()
    assert sorted(out) == [200] + [409] * 31
    assert len(read_jsonl(A.CHAIN)) == 1
    assert [r["reason"] for r in read_jsonl(A.REFUSALS)] == ["conflicting_root"] * 31


def test_slow_connections_cut_at_timeout_and_deadline(tmp_path):
    key = "k" * 32
    A = load(str(tmp_path), "hardened", key)
    A.IO_TIMEOUT_S, A.REQUEST_DEADLINE_S = 1.0, 2.0
    s = InProcess(A)
    log = []
    try:
        th = [threading.Thread(target=_slow_client, args=(k, s.port, time.monotonic() + 4.5, log)) for k in SLOW_KINDS]
        for t in th:
            t.start()
        time.sleep(0.3)
        st, _ = post(s.port, rec(1), key, timeout=APPEND_BOUND_S)            # not blocked meanwhile
        assert st == 200
        for t in th:
            t.join(10)
    finally:
        s.close()
    first = {k: next(r for r in log if r.get("kind") == k and "held_s" in r) for k in SLOW_KINDS}
    assert all(r["ended"] in ("daemon_closed", "daemon_reset") for r in first.values()), first
    assert 0.8 <= first["silent"]["held_s"] <= 1.6                         # the read timeout
    assert 0.8 <= first["partial_body"]["held_s"] <= 1.6 and first["partial_body"]["status"] == 408
    assert 1.8 <= first["slow_headers"]["held_s"] <= 2.6                   # the deadline, despite steady bytes
    assert 1.8 <= first["trickle_body"]["held_s"] <= 2.6 and first["trickle_body"]["status"] == 408
    assert "body_timeout" in [r["reason"] for r in read_jsonl(A.REFUSALS)]


def test_head_witness_has_the_same_limits(tmp_path):
    key = "w" * 32
    os.environ.update(HOMEPROV_WITNESS_KEY=key, WITNESS_LOG=str(tmp_path / "heads.jsonl"),
                      WITNESS_FORKS=str(tmp_path / "forks.jsonl"))
    spec = importlib.util.spec_from_file_location("hw_s%d" % next(_n), os.path.join(HERE, "headwitness.py"))
    hw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hw)
    assert hw.MAX_BODY == 64 * 1024 * 1024               # the default since E8 (a push carries record lines)
    hw.IO_TIMEOUT_S, hw.REQUEST_DEADLINE_S, hw.MAX_BODY = 1.0, 2.0, 512
    srv = hw.WitnessServer(("127.0.0.1", 0), hw.H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        held = socket.create_connection(("127.0.0.1", port))            # a client that stops mid-body
        held.sendall(b"POST /head HTTP/1.1\r\nContent-Length: 100\r\n\r\n{")
        t_open = time.monotonic()
        line = json.dumps({"seq": 1, "recv_ts": 1.0, "payload": {}, "link": "v2", "prev_digest": "0" * 64},
                          sort_keys=True)                         # a valid first record (E8: pushes carry it)
        body = enc({"seq": 1, "head_digest": hashlib.sha256(line.encode()).hexdigest(), "recv_ts": 1.0,
                    "records": [line]})
        assert len(body) < 512
        t = time.monotonic()
        assert req(port, "POST", "/head", body, {"X-HP-Auth": tag(key, body)}, timeout=APPEND_BOUND_S)[0] == 200
        assert time.monotonic() - t < APPEND_BOUND_S
        assert status_of(raw(port, b"POST /head HTTP/1.0\r\nContent-Length: 513\r\n\r\n")) == 413
        assert status_of(raw(port, b"POST /head HTTP/1.0\r\nContent-Length: -5\r\n\r\n{}")) == 400
        assert status_of(raw(port, b"POST /head HTTP/1.0\r\nContent-Length: %d\r\nX-HP-Auth: \xe9\r\n\r\n" % len(body)
                             + body)) == 401
        held.settimeout(3.0)
        resp = held.recv(4096)                                          # the witness answers 408 at the read timeout
        assert status_of(resp) == 408 and 0.8 <= time.monotonic() - t_open <= 1.6
        held.close()
    finally:
        srv.shutdown(); srv.server_close()


def test_bad_limits_in_the_environment_are_rejected():
    for var, val in (("HOMEPROV_ANCHOR_MAX_BODY", "0"), ("HOMEPROV_ANCHOR_IO_TIMEOUT_S", "-1"),
                     ("HOMEPROV_ANCHOR_REQUEST_DEADLINE_S", "soon")):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", **{var: val})
        p = subprocess.run([sys.executable, "-c", "import anchord"], cwd=HERE, env=env, capture_output=True, text=True)
        assert p.returncode != 0 and var in p.stderr


# ------------------------------------------------------------------------------------------------- saved result

def _record_cli(out: str, reps: int, stall_s: float, n_per_kind: int, period_s: float) -> None:
    files = {"original": "testbed/anchord/anchord_r12.py", "hardened": "testbed/anchord/anchord.py",
             "hardened_linked": "testbed/anchord/anchord_linked.py"}
    sums = {k: sha256_file(os.path.join(REPO, v)) for k, v in files.items()}
    try:
        git_head = subprocess.run(["git", "-C", REPO, "show", "HEAD:testbed/anchord/anchord.py"], capture_output=True,
                                  check=True).stdout
        original_is_git_head = hashlib.sha256(git_head).hexdigest() == sums["original"]
    except Exception:                                       # noqa: BLE001
        original_is_git_head = None
    started = datetime.datetime.now(datetime.timezone.utc)
    scenarios = {"flood": (SLOW_KINDS, n_per_kind), "one_silent_client": (("silent",), 1)}
    runs = []
    for scen, (kinds, per) in scenarios.items():
        for rep in range(1, reps + 1):
            for kind in DAEMONS:
                r = run_stall(kind, stall_s=stall_s, n_per_kind=per, period_s=period_s, kinds=kinds)
                r["scenario"], r["repetition"] = scen, rep
                runs.append(r)
                print("%s %s rep %d: accepted %d/%d within bound %d, late commits %d, failed %s" % (
                    scen, kind, rep, r["accepted_during_stall"], r["attempts_during_stall"],
                    r["accepted_within_bound_during_stall"], r["late_commits"]["count"], r["failed_during_stall"]),
                    flush=True)
    summary = {}
    for scen in scenarios:
        summary[scen] = {}
        for kind in DAEMONS:
            rs = [r for r in runs if r["daemon"] == kind and r["scenario"] == scen]
            acc = [r["max_latency_accepted_s"] for r in rs if r["max_latency_accepted_s"] is not None]
            failed = collections.Counter()
            for r in rs:
                failed.update(r["failed_during_stall"])
            summary[scen][kind] = {
                "repetitions": len(rs),
                "appends_attempted_during_stall": sum(r["attempts_during_stall"] for r in rs),
                "appends_accepted_during_stall": sum(r["accepted_during_stall"] for r in rs),
                "appends_accepted_within_bound_during_stall": sum(r["accepted_within_bound_during_stall"] for r in rs),
                "appends_failed_during_stall": dict(failed),
                "max_latency_accepted_s": max(acc) if acc else None,
                "max_latency_all_attempts_s": max(r["max_latency_all_attempts_s"] for r in rs),
                "late_commits": sum(r["late_commits"]["count"] for r in rs),
                "appends_accepted_after_stall": sum(r["after_stall"]["accepted"] for r in rs),
                "appends_attempted_after_stall": sum(r["after_stall"]["attempts"] for r in rs),
                "chains_verify": all(r["chain"]["chainverify_ok"] and r["chain"]["seq_consecutive"] for r in rs),
            }
    res = {
        "experiment": "E7 anchor hardening: stall unit test (two slow-client scenarios against the earlier and the "
                      "hardened anchor daemon)",
        "date_utc": started.isoformat(timespec="seconds"),
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "command": "python3 testbed/anchord/test_anchor_stall.py record --out exp/out/e7_anchor_stall_unit.json "
                   "--reps %d --stall %g --per-kind %d --period %g" % (reps, stall_s, n_per_kind, period_s),
        "environment": {"python": platform.python_version(), "platform": platform.platform(terse=True),
                        "address": "127.0.0.1, one daemon process per run, fresh random HMAC key per run",
                        "serving_limits": "defaults (HOMEPROV_ANCHOR_IO_TIMEOUT_S, HOMEPROV_ANCHOR_REQUEST_DEADLINE_S "
                                          "and HOMEPROV_ANCHOR_MAX_BODY unset: 5 s, 10 s, 16 MiB)"},
        "daemons": {
            "original": {"file": files["original"], "sha256": sums["original"],
                         "identical_to_git_HEAD_anchord_py": original_is_git_head,
                         "served_by": "its __main__ block: socketserver.TCPServer (one thread) with its handler H; "
                                      "paths redirected to a temporary directory, bound to 127.0.0.1"},
            "hardened": {"file": files["hardened"], "sha256": sums["hardened"],
                         "served_by": "anchord.serve(): AnchorServer (thread per connection) with H"},
            "hardened_linked": {"file": files["hardened_linked"], "sha256": sums["hardened_linked"],
                                "uses": files["hardened"], "uses_sha256": sums["hardened"],
                                "served_by": "anchord_linked.serve(): AnchorServer with H, HOMEPROV_ANCHOR_LINK=v2"}},
        "harness": {"file": "testbed/anchord/test_anchor_stall.py",
                    "sha256": sha256_file(os.path.abspath(__file__))},
        "workload": {"stall_s": stall_s,
                     "scenarios": {"flood": "%d slow clients, %d of each kind %s" % (
                                       n_per_kind * len(SLOW_KINDS), n_per_kind, ", ".join(SLOW_KINDS)),
                                   "one_silent_client": "one silent client (connects, sends nothing)"},
                     "trickle_period_s": TRICKLE_S,
                     "reopen": "each slow client reopens its connection whenever the daemon closes it",
                     "authenticated_append_period_s": period_s, "client_timeout_s": CLIENT_TIMEOUT_S,
                     "attempt_window": "first attempt 1 s after the slow clients start; every attempt ends before "
                                       "the stall ends",
                     "failed_at": "connect: the connection was never accepted within the client timeout; response: "
                                  "the request was sent and no reply came within the client timeout",
                     "late_commit": "an attempt whose client saw no HTTP 200 but whose record is in the chain at the "
                                    "end (the daemon read and appended it after the client had given up)",
                     "after_stall": "3 appends, 3 s after the slow clients stop",
                     "bound_s": APPEND_BOUND_S,
                     "bound_meaning": "an authenticated append counts as accepted within the bound when it is "
                                      "answered HTTP 200 within bound_s of the request"},
        "summary": summary,
        "runs": runs,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "serve":
        _serve_cli(*a[1:4])
    elif a and a[0] == "record":
        def opt(name, default, kind):
            return kind(a[a.index(name) + 1]) if name in a else default
        _record_cli(opt("--out", os.path.join(REPO, "exp", "out", "e7_anchor_stall_unit.json"), str),
                    opt("--reps", 3, int), opt("--stall", 30.0, float), opt("--per-kind", 4, int),
                    opt("--period", 1.0, float))
    else:
        raise SystemExit(__doc__)
