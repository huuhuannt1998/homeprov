"""E8 anchor tests (round 13, items A1, A3, A4; review r2 R1 W1).

    python3 -m pytest -q testbed/anchord/test_anchor_e8.py

A1  the reviewer's attack: the anchor host rewrites record 3, relinks records 4..10 and lets one honest append through.
    The witness must refuse the honest head (it does not extend the witnessed head 10), and the chain must fail against
    every witnessed head. On the code before E8 the witness accepted head 11 and the chain verified against the latest
    witnessed head, so test_reviewer_attack_* fails there. Also: a forged extension push that links but is not the
    chain's record; witness outages and restarts (gap, resend, batching, legacy prefix); the verifier's every-head mode.
A3  lifecycle markers only under the operator key, issued with the operator tool itself (rig.marker_issuer.append).
A4  every anchor reply is tagged; a spoofed, altered or replayed reply does not verify.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import itertools
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "exp"))
import chainverify as CV  # noqa: E402

_n = itertools.count()
WKEY = "w" * 32
AKEY = "k" * 32                                   # the monitor's append key (raw string, as monitor.py reads it)
OP_HEX = hashlib.sha256(b"operator").hexdigest()  # the operator's key file content (hex, as rig.marker_issuer reads it)
OP = bytes.fromhex(OP_HEX)


# ----------------------------------------------------------------------------------------------------------- helpers

def payload(i):
    return {"observer": "external-monitor", "ts": 1790000000.0 + i, "scheme": "closure", "encoding": "v2",
            "sealed": {"second": {str(1790000000 + i): {"acc": hashlib.sha256(b"%d" % i).hexdigest(), "n": i}}}}


def lines_of(data):
    return [l for l in data.split(b"\n") if l.strip()]


def join(lines):
    return b"\n".join(lines) + b"\n"


def linked(tmp, url="", key="", wkey=WKEY, push_max=None):
    """A fresh anchord_linked (and anchord) with its files in tmp, pushing to the witness at url (sync)."""
    os.environ["HOMEPROV_ANCHOR_KEY"] = key
    os.environ["HOMEPROV_ANCHOR_LINK"] = "v2"
    os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    sys.modules.pop("anchord", None)
    spec = importlib.util.spec_from_file_location("al_e8_%d" % next(_n), os.path.join(HERE, "anchord_linked.py"))
    ad = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ad)
    ad.A.CHAIN = os.path.join(tmp, "chain.jsonl")
    ad.A.REFUSALS = os.path.join(tmp, "refusals.jsonl")
    ad.A.PUBLISH = os.path.join(tmp, "head.json")
    ad.WITNESS_URL, ad.WITNESS_MODE, ad.WITNESS_KEY = (url + "/head") if url else "", "sync", wkey.encode()
    if push_max:
        ad.PUSH_MAX_BYTES = push_max
    return ad


class Witness:
    """headwitness.py served in-process; seed: witness log lines to start from (e.g. E5's saved heads)."""

    def __init__(self, tmp, key=WKEY, seed=None, path=None):
        os.makedirs(tmp, exist_ok=True)
        os.environ["HOMEPROV_WITNESS_KEY"] = key
        os.environ["WITNESS_LOG"] = self.log = os.path.join(tmp, "heads.jsonl")
        os.environ["WITNESS_FORKS"] = self.forks = os.path.join(tmp, "forks.jsonl")
        if seed:
            with open(self.log, "wb") as fh:
                fh.write(seed)
        spec = importlib.util.spec_from_file_location("hw_e8_%d" % next(_n), path or os.path.join(HERE, "headwitness.py"))
        self.hw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hw)
        self.hw._load()
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), self.hw.H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def get(self, path):
        with urllib.request.urlopen(self.url + path, timeout=5) as r:
            return json.loads(r.read())

    def post(self, obj, key=WKEY):
        body = json.dumps(obj, sort_keys=True).encode()
        hdr = {"Content-Type": "application/json", "X-HP-Auth": hmac.new(key.encode(), body, hashlib.sha256).hexdigest()}
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url + "/head", data=body, headers=hdr,
                                                               method="POST"), timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def forks_logged(self):
        return [json.loads(l) for l in open(self.forks)] if os.path.exists(self.forks) else []

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


def rewrite_and_relink(data: bytes, i: int) -> bytes:
    """The reviewer's host-side attack: rewrite record i's first root at rest and relink records i+1..n."""
    recs = [json.loads(l) for l in lines_of(data)]
    seg = recs[i - 1]["payload"]["sealed"]
    g = next(iter(seg))
    s = next(iter(seg[g]))
    seg[g][s]["acc"] = hashlib.sha256(b"rewritten" + seg[g][s]["acc"].encode()).hexdigest()
    out = [json.dumps(r, sort_keys=True).encode() for r in recs]
    for k in range(i, len(recs)):
        recs[k]["prev_digest"] = CV.record_digest(out[k - 1])
        out[k] = json.dumps(recs[k], sort_keys=True).encode()
    return join(out)


def build_witnessed(tmp_path, n=10):
    w = Witness(str(tmp_path / "w"))
    os.makedirs(tmp_path / "a")
    ad = linked(str(tmp_path / "a"), w.url)
    outs = [ad._append(payload(i)) for i in range(1, n + 1)]
    assert all(o["witness_push"]["ok"] for o in outs)
    return w, ad


# ------------------------------------------------------------------------------------------------- A1: the attack

def test_reviewer_attack_rewrite_relink_then_honest_append(tmp_path):
    w, ad = build_witnessed(tmp_path)
    try:
        head10 = w.get("/head")
        attacked = rewrite_and_relink(open(ad.A.CHAIN, "rb").read(), 3)
        open(ad.A.CHAIN, "wb").write(attacked)
        assert CV.verify_chain(attacked)["ok"]                                  # self-consistent on its own
        o = ad._append(payload(11))                                             # one honest append goes through
        assert o["ok"] and o["seq"] == 11                                       # the anchor still appends ...
        assert not o["witness_push"]["ok"]                                      # ... but the witness refuses head 11
        assert o["witness_push"]["witness"]["reason"] == "not_extension"
        assert w.get("/head") == head10                                         # it still holds the honest head 10
        assert [f["seq"] for f in w.forks_logged()] == [11]                     # and logged the refused head
        final = open(ad.A.CHAIN, "rb").read()
        assert not CV.verify_chain(final, w.get("/head"))["ok"]                 # latest witnessed head: fails
        r = CV.verify_chain(final, witnessed_heads=w.get("/log")["heads"])       # every witnessed head: fails
        assert not r["ok"] and r["witnessed_heads"]["mismatched_seqs"] == list(range(3, 11))
    finally:
        w.close()


def test_forged_extension_push_is_caught_by_every_head_check(tmp_path):
    """The host pushes a fabricated record 11 that does link to the witnessed head 10 (so the witness accepts it), while
    the chain it keeps is the rewritten one: the chain then fails at every rewritten seq and at 11."""
    w, ad = build_witnessed(tmp_path)
    try:
        honest = open(ad.A.CHAIN, "rb").read()
        fake11 = json.dumps({"seq": 11, "recv_ts": 1.0, "payload": payload(11), "link": "v2",
                             "prev_digest": CV.record_digest(lines_of(honest)[-1])}, sort_keys=True)
        assert w.post({"seq": 11, "head_digest": CV.record_digest(fake11.encode()), "recv_ts": 1.0,
                       "records": [fake11]})[0] == 200
        open(ad.A.CHAIN, "wb").write(rewrite_and_relink(honest, 3))
        ad._wit["seq"] = 11
        ad._append(payload(12))                                                 # now chain seq 11 is the real record
        final = open(ad.A.CHAIN, "rb").read()
        r = CV.verify_chain(final, witnessed_heads=w.get("/log")["heads"])
        assert not r["ok"] and r["witnessed_heads"]["mismatched_seqs"] == list(range(3, 12))
    finally:
        w.close()


def test_honest_chain_verifies_against_every_head(tmp_path):
    w, ad = build_witnessed(tmp_path, n=12)
    try:
        data = open(ad.A.CHAIN, "rb").read()
        r = CV.verify_chain(data, witnessed_heads=w.get("/log")["heads"])
        assert r["ok"] and r["witnessed_heads"]["matched"] == 12 and "every witnessed head" in r["integrity"]
        r = CV.verify_chain(join(lines_of(data)[:9]), witnessed_heads=w.get("/log")["heads"])     # truncated
        assert not r["ok"] and r["witnessed_heads"]["beyond_chain_seqs"] == [10, 11, 12]
        conflicting = w.get("/log")["heads"] + [{"seq": 4, "head_digest": "ab" * 32}]
        r = CV.verify_chain(data, witnessed_heads=conflicting)
        assert not r["ok"] and r["witnessed_heads"]["conflicting_seqs"] == [4]
    finally:
        w.close()


def test_chainverify_cli_with_witness_log(tmp_path):
    w, ad = build_witnessed(tmp_path)
    try:
        with gzip.open(tmp_path / "heads.jsonl.gz", "wb") as fh:
            fh.write(open(w.log, "rb").read())
        open(tmp_path / "bad.jsonl", "wb").write(rewrite_and_relink(open(ad.A.CHAIN, "rb").read(), 5))
        run = lambda c, *a: subprocess.run([sys.executable, os.path.join(HERE, "chainverify.py"), c, *a],  # noqa: E731
                                           capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        ok = run(ad.A.CHAIN, "--heads", str(tmp_path / "heads.jsonl.gz"))
        assert ok.returncode == 0 and json.loads(ok.stdout)["witnessed_heads"]["matched"] == 10
        bad = run(str(tmp_path / "bad.jsonl"), "--heads", str(tmp_path / "heads.jsonl.gz"))
        assert bad.returncode == 1 and json.loads(bad.stdout)["witnessed_heads"]["mismatched_seqs"] == list(range(5, 11))
        url = run(ad.A.CHAIN, "--heads-url", w.url + "/log")
        assert url.returncode == 0
    finally:
        w.close()


# ------------------------------------------------------------------------------------------ A1: witness mechanics

def test_witness_outage_is_caught_up_with_linked_records(tmp_path):
    w = Witness(str(tmp_path / "w"))
    os.makedirs(tmp_path / "a")
    ad = linked(str(tmp_path / "a"), w.url)
    try:
        for i in range(1, 4):
            assert ad._append(payload(i))["witness_push"]["ok"]
        ad.WITNESS_URL = "http://127.0.0.1:9/head"                              # witness unreachable for 3 appends
        assert not any(ad._append(payload(i))["witness_push"]["ok"] for i in range(4, 7))
        ad.WITNESS_URL = w.url + "/head"
        o = ad._append(payload(7))
        assert o["witness_push"]["ok"] and o["witness_push"]["records_pushed"] == 4      # records 4..7 in one push
        log = w.get("/log")["heads"]
        assert [h["seq"] for h in log] == [1, 2, 3, 7]
        assert CV.verify_chain(open(ad.A.CHAIN, "rb").read(), witnessed_heads=log)["ok"]
    finally:
        w.close()


def test_restarts_gap_resend_and_batches(tmp_path):
    os.makedirs(tmp_path / "a")
    ad = linked(str(tmp_path / "a"))                                            # 7 records with no witness at all
    for i in range(1, 8):
        ad._append(payload(i))
    w = Witness(str(tmp_path / "w"))
    try:
        ad2 = linked(str(tmp_path / "a"), w.url, push_max=1)                   # restarted daemon, fresh witness
        o = ad2._append(payload(8))
        assert o["witness_push"]["ok"] and o["witness_push"]["records_pushed"] == 8     # gap -> resent from record 1
        assert [h["seq"] for h in w.get("/log")["heads"]] == list(range(1, 9))          # batches of one record
        ad3 = linked(str(tmp_path / "a"), w.url)                               # restarted again, witness at 8
        o = ad3._append(payload(9))
        assert o["witness_push"]["ok"] and o["witness_push"]["records_pushed"] == 1
        assert CV.verify_chain(open(ad3.A.CHAIN, "rb").read(), witnessed_heads=w.get("/log")["heads"])["ok"]
    finally:
        w.close()


def test_fresh_witness_checks_an_unlinked_legacy_prefix(tmp_path):
    os.makedirs(tmp_path / "a")
    ad = linked(str(tmp_path / "a"))
    for i in range(1, 6):
        ad.EVALUATED_APPEND(payload(i))                                         # unlinked records, as before 2026-10-07
    w = Witness(str(tmp_path / "w"))
    try:
        ad2 = linked(str(tmp_path / "a"), w.url)
        o = ad2._append(payload(6))
        assert o["witness_push"]["ok"] and o["witness_push"]["records_pushed"] == 6
        ls = [l.decode() for l in lines_of(open(ad2.A.CHAIN, "rb").read())]
        w2 = Witness(str(tmp_path / "w2"))
        try:
            tampered = list(ls)
            r1 = json.loads(tampered[1]); r1["recv_ts"] += 1
            tampered[1] = json.dumps(r1, sort_keys=True)
            st, rep = w2.post({"seq": 6, "head_digest": CV.record_digest(ls[5].encode()), "records": tampered})
            assert st == 409 and rep["reason"] == "not_extension" and "legacy" in rep["detail"]
        finally:
            w2.close()
    finally:
        w.close()


def test_witness_refusals(tmp_path):
    w, ad = build_witnessed(tmp_path, n=3)
    try:
        ls = [l.decode() for l in lines_of(open(ad.A.CHAIN, "rb").read())]
        d3 = CV.record_digest(ls[2].encode())
        assert w.post({"seq": 3, "head_digest": d3}) == (200, {"ok": True, "seq": 3})     # a head it holds: fine
        r4 = json.dumps({"seq": 4, "recv_ts": 1.0, "payload": payload(4), "link": "v2", "prev_digest": d3},
                        sort_keys=True)
        d4 = CV.record_digest(r4.encode())
        st, rep = w.post({"seq": 4, "head_digest": d4})                                       # no records
        assert st == 409 and rep["reason"] == "not_extension"
        bad = json.dumps({**json.loads(r4), "prev_digest": "cd" * 32}, sort_keys=True)          # does not link
        st, rep = w.post({"seq": 4, "head_digest": CV.record_digest(bad.encode()), "records": [bad]})
        assert st == 409 and rep["reason"] == "not_extension"
        r5 = json.dumps({"seq": 5, "recv_ts": 1.0, "payload": payload(5), "link": "v2", "prev_digest": d4},
                        sort_keys=True)
        st, rep = w.post({"seq": 5, "head_digest": CV.record_digest(r5.encode()), "records": [r5]})   # skips 4
        assert st == 409 and rep["reason"] == "gap" and rep["latest"] == 3
        st, rep = w.post({"seq": 5, "head_digest": "ef" * 32, "records": [r4, r5]})          # last is not the head
        assert st == 409 and rep["reason"] == "not_extension"
        unl = json.dumps({"seq": 4, "recv_ts": 1.0, "payload": payload(4)}, sort_keys=True)  # unlinked after a head
        st, rep = w.post({"seq": 4, "head_digest": CV.record_digest(unl.encode()), "records": [unl]})
        assert st == 409 and rep["reason"] == "not_extension"
        assert w.post({"seq": 3, "head_digest": "ab" * 32})[1]["reason"] == "fork"
        assert w.post({"seq": 2, "head_digest": "ab" * 32})[0] == 409
        assert w.post({"seq": 5, "head_digest": CV.record_digest(r5.encode()), "records": [r4, r5]})[0] == 200
        assert w.get("/head") == {"seq": 5, "head_digest": CV.record_digest(r5.encode())}
        assert len(w.forks_logged()) == 6                                     # 4 non-extensions and 2 forks
    finally:
        w.close()


E5_CHAIN = os.path.join(REPO, "exp", "out", "e5_psr_lnk_linked_chain.jsonl.gz")
E5_HEADS = os.path.join(REPO, "exp", "out", "e5_psr_lnk_witness_heads.jsonl.gz")


@pytest.mark.skipif(not (os.path.exists(E5_CHAIN) and os.path.exists(E5_HEADS)), reason="E5 outputs absent")
def test_e5_chain_verifies_against_every_witnessed_head_and_resists_the_attack(tmp_path):
    data, heads_raw = CV.read(E5_CHAIN), CV.read(E5_HEADS)
    heads = CV.read_heads(heads_raw)
    r = CV.verify_chain(data, witnessed_heads=heads)
    assert r["ok"] and r["witnessed_heads"]["matched"] == len(heads) == 225
    w = Witness(str(tmp_path / "w"), seed=heads_raw)                          # the witness as E5 left it
    try:
        os.makedirs(tmp_path / "a")
        ad = linked(str(tmp_path / "a"), w.url)
        open(ad.A.CHAIN, "wb").write(rewrite_and_relink(data, 100))
        o = ad._append(payload(226))
        assert not o["witness_push"]["ok"] and o["witness_push"]["witness"]["reason"] == "not_extension"
        r = CV.verify_chain(open(ad.A.CHAIN, "rb").read(), witnessed_heads=heads)
        assert not r["ok"] and r["witnessed_heads"]["mismatched_seqs"] == list(range(100, 226))
    finally:
        w.close()


# ------------------------------------------------------------------------------------------------- A3 and A4

def load_anchord(tmp, key=AKEY, op=OP_HEX):
    os.environ["HOMEPROV_ANCHOR_KEY"] = key
    if op is None:
        os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    else:
        os.environ["HOMEPROV_OPERATOR_KEY"] = op
    spec = importlib.util.spec_from_file_location("ad_e8_%d" % next(_n), os.path.join(HERE, "anchord.py"))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    A.CHAIN, A.REFUSALS, A.PUBLISH = (os.path.join(tmp, "chain.jsonl"), os.path.join(tmp, "refusals.jsonl"),
                                      os.path.join(tmp, "head.json"))
    return A


class Served:
    def __init__(self, A):
        self.A = A
        self.srv = A.AnchorServer(("127.0.0.1", 0), A.H)
        self.port = self.srv.server_address[1]
        self.url = "http://127.0.0.1:%d/append" % self.port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def post(self, body: bytes, tag=None, method="POST", path="/append"):
        """(status, reply body bytes, X-HP-Reply-Auth, request tag)."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdr = {"Content-Type": "application/json"}
        if tag is not None:
            hdr["X-HP-Auth"] = tag
        try:
            c.request(method, path, body=body, headers=hdr)
            r = c.getresponse()
            return r.status, r.read(), r.getheader("X-HP-Reply-Auth"), tag or ""
        finally:
            c.close()

    def raw_413(self, tag):
        """A request declaring a body over the limit and sending none (no unread bytes, so no reset)."""
        import socket
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(b"POST /append HTTP/1.0\r\nContent-Length: 5000\r\nX-HP-Auth: %s\r\n\r\n" % tag.encode())
            buf = b""
            while True:
                b = s.recv(65536)
                if not b:
                    break
                buf += b
        finally:
            s.close()
        head, body = buf.split(b"\r\n\r\n", 1)
        hdr = dict(l.split(": ", 1) for l in head.decode("latin-1").split("\r\n")[1:])
        return int(head.split(b" ", 2)[1]), body, hdr.get("X-HP-Reply-Auth"), tag

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


def hm(key: bytes, body: bytes) -> str:
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def marker_body(key: bytes):
    from rig import marker_issuer as MI
    m = MI.scoped_marker(1790000000.0, 30 * 86400.0, issued_ts=1789999880.0)
    return json.dumps({"observer": "operator-marker-issuer", "marker": m,
                       "marker_tag": MI.tag(json.dumps(m, sort_keys=True).encode(), key)}, sort_keys=True).encode()


def test_markers_need_the_operator_key(tmp_path):
    from rig import marker_issuer as MI
    A = load_anchord(str(tmp_path))
    s = Served(A)
    try:
        assert MI.append(s.url, OP, MI.scoped_marker(1790000000.0, 30 * 86400.0))["ok"]   # the operator tool itself
        with pytest.raises(urllib.error.HTTPError) as e:                                   # same tool, append key
            MI.append(s.url, AKEY.encode(), MI.scoped_marker(1790086400.0, 30 * 86400.0))
        assert e.value.code == 403 and json.loads(e.value.read())["reason"] == "marker_needs_operator_key"
        rec = json.dumps({"observer": "external-monitor", "sealed": {}}, sort_keys=True).encode()
        st, b, _, _ = s.post(rec, hm(OP, rec))                                             # operator key, no marker
        assert st == 403 and json.loads(b)["reason"] == "operator_key_for_markers_only"
        mb = marker_body(AKEY.encode())                                                    # marker_tag under append key
        st, b, _, _ = s.post(mb, hm(OP, mb))
        assert st == 403 and json.loads(b)["reason"] == "bad_marker_tag"
        mb = marker_body(OP)
        assert s.post(mb)[0] == 401 and json.loads(s.post(mb)[1])["reason"] == "missing_signature"
        assert json.loads(s.post(mb, "ab" * 32)[1])["reason"] == "bad_signature"
        st, b, _, _ = s.post(rec, hm(AKEY.encode(), rec))                                  # monitor records unchanged
        assert st == 200
    finally:
        s.close()
    recs = [json.loads(l) for l in open(A.CHAIN)]
    assert len(recs) == 2 and "marker" in recs[0]["payload"]
    assert len(MI.markers_from_chain(recs, OP)) == 1 and MI.markers_from_chain(recs, AKEY.encode()) == []
    reasons = [json.loads(l)["reason"] for l in open(A.REFUSALS)]
    assert reasons == ["marker_needs_operator_key", "operator_key_for_markers_only", "bad_marker_tag",
                       "missing_signature", "missing_signature", "bad_signature"]


def test_without_an_operator_key_markers_behave_as_before(tmp_path):
    A = load_anchord(str(tmp_path), op=None)
    s = Served(A)
    try:
        mb = marker_body(AKEY.encode())
        assert s.post(mb, hm(AKEY.encode(), mb))[0] == 200
    finally:
        s.close()
    os.makedirs(tmp_path / "u")
    U = load_anchord(str(tmp_path / "u"), key="")                       # unauthenticated anchor with an operator key
    s = Served(U)
    try:
        rec = json.dumps({"observer": "external-monitor", "sealed": {}}, sort_keys=True).encode()
        assert s.post(rec)[0] == 200
        mb = marker_body(OP)
        assert s.post(mb)[0] == 403 and s.post(mb, hm(OP, mb))[0] == 200
    finally:
        s.close()


def test_operator_key_must_be_hex_and_differ_from_the_append_key():
    for op, key in ((AKEY, AKEY), ("zz" * 16, AKEY), ("ab" * 4, AKEY), (OP_HEX, OP_HEX)):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HOMEPROV_ANCHOR_KEY=key, HOMEPROV_OPERATOR_KEY=op)
        p = subprocess.run([sys.executable, "-c", "import anchord"], cwd=HERE, env=env, capture_output=True, text=True)
        assert p.returncode != 0 and "HOMEPROV_OPERATOR_KEY" in p.stderr, (op, key)


def test_every_reply_is_tagged(tmp_path):
    A = load_anchord(str(tmp_path))
    A.MAX_BODY = 4096
    s = Served(A)
    ak = AKEY.encode()
    try:
        rec = json.dumps(payload(1), sort_keys=True).encode()
        clash = json.dumps({**payload(1), "sealed": {"second": {"1790000001": {"acc": "ff" * 32, "n": 1}}}},
                           sort_keys=True).encode()
        mb = marker_body(OP)
        cases = [s.post(rec, hm(ak, rec)), s.post(rec), s.post(rec, "ab" * 32), s.post(clash, hm(ak, clash)),
                 s.post(b"[]", hm(ak, b"[]")), s.raw_413(hm(ak, b"x")), s.post(b"", None, "GET", "/head"),
                 s.post(b"", None, "GET", "/nope"), s.post(b"", None, "PUT")]
        assert [c[0] for c in cases] == [200, 401, 401, 409, 400, 413, 200, 404, 405]
        for st, body, rt, qt in cases:
            assert A.reply_ok(ak, qt, st, body, rt), (st, body)
            assert not A.reply_ok(OP, qt, st, body, rt)
        st, body, rt, qt = s.post(mb, hm(OP, mb))                                   # operator reply: operator key
        assert st == 200 and A.reply_ok(OP, qt, st, body, rt) and not A.reply_ok(ak, qt, st, body, rt)
        st, body, rt, qt = cases[0]                                                 # tampering is detected
        assert not A.reply_ok(ak, qt, 409, body, rt)
        assert not A.reply_ok(ak, qt, st, body.replace(b'"seq": 1', b'"seq": 9'), rt)
        other = json.dumps(payload(2), sort_keys=True).encode()
        assert not A.reply_ok(ak, hm(ak, other), st, body, rt)                     # replayed to another request
        assert not A.reply_ok(ak, qt, st, body, None)
    finally:
        s.close()
    os.makedirs(tmp_path / "n")
    N = load_anchord(str(tmp_path / "n"), key="", op=None)                         # no key: no reply tag
    s = Served(N)
    try:
        assert s.post(b"{}")[2] is None
    finally:
        s.close()


def test_a_spoofed_ok_is_detected(tmp_path):
    """A host on the anchor's network answers the monitor's append with a fabricated ok. Without the key it can only
    send no tag, a tag under a guessed key, or a tag copied from an earlier genuine reply; none verifies."""
    A = load_anchord(str(tmp_path))
    s = Served(A)
    ak = AKEY.encode()
    try:
        first = json.dumps(payload(1), sort_keys=True).encode()
        st, gbody, gtag, _ = s.post(first, hm(ak, first))
        assert st == 200
    finally:
        s.close()
    spoofs = [(None, b'{"ok": true, "seq": 2}'), (hm(b"guess", b"x"), b'{"ok": true, "seq": 2}'),
              (gtag, gbody)]

    class Fake(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            tag, body = spoofs[self.server.k]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            if tag:
                self.send_header("X-HP-Reply-Auth", tag)
            self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass

    fake = socketserver.TCPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    try:
        second = json.dumps(payload(2), sort_keys=True).encode()
        for k in range(len(spoofs)):
            fake.k = k
            c = http.client.HTTPConnection("127.0.0.1", fake.server_address[1], timeout=5)
            c.request("POST", "/append", body=second, headers={"X-HP-Auth": hm(ak, second)})
            r = c.getresponse(); body = r.read()
            assert json.loads(body)["ok"] is True                                  # it looks like success ...
            assert not A.reply_ok(ak, hm(ak, second), r.status, body, r.getheader("X-HP-Reply-Auth"))   # ... it is not
            c.close()
    finally:
        fake.shutdown(); fake.server_close()
