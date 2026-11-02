"""E9 item A6: the operator's marker issuer (exp/rig/marker_issuer.py) against a LINKED anchor (anchord_linked.py over
anchord.py) with an append key, a separate operator key, tagged replies and a head witness, as E8 and E9 run it.

    python3 -m pytest -q testbed/anchord/test_anchor_e9.py

Cases: a signed PURGE marker issued with reply tags required is accepted, linked, witnessed, and read back by
markers_from_chain and by the verifier (exp/stages/e7_verify.py chain_markers) only under the operator's keys; RESTORE
and RENAME issued from the command line, the RENAME digest computed with the monitor's own name-map code; a spoofed
reply (untagged, wrongly tagged, or a genuine tag replayed from another request) is not believed and the marker is
reported as not issued; the anchor's own authenticated refusal stops the retries without an exception; the wait before a
purge follows the wall clock.
"""
from __future__ import annotations

import hashlib
import http.server
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "exp"))
import chainverify as CV  # noqa: E402
from rig import marker_issuer as MI  # noqa: E402
from test_anchor_e8 import AKEY, OP, OP_HEX, WKEY, Served, Witness  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EdPriv
except ImportError:
    _EdPriv = None
needs_crypto = pytest.mark.skipif(_EdPriv is None, reason="cryptography is not installed")
_n = itertools.count()


def keypair(tmp, name):
    k = _EdPriv.generate()
    priv, pub = os.path.join(tmp, name + ".pem"), os.path.join(tmp, name + ".pub.pem")
    open(priv, "wb").write(k.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()))
    open(pub, "wb").write(k.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def linked_operator_anchor(tmp, witness_url):
    """anchord_linked with an append key, an operator key (hex) and sync pushes to a witness, served on loopback."""
    os.environ.update(HOMEPROV_ANCHOR_KEY=AKEY, HOMEPROV_OPERATOR_KEY=OP_HEX, HOMEPROV_ANCHOR_LINK="v2")
    sys.modules.pop("anchord", None)
    spec = importlib.util.spec_from_file_location("al_e9_%d" % next(_n), os.path.join(HERE, "anchord_linked.py"))
    ad = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ad)
    os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    ad.A.CHAIN = os.path.join(tmp, "chain.jsonl")
    ad.A.REFUSALS = os.path.join(tmp, "refusals.jsonl")
    ad.A.PUBLISH = os.path.join(tmp, "head.json")
    ad.WITNESS_URL, ad.WITNESS_MODE, ad.WITNESS_KEY = witness_url + "/head", "sync", WKEY.encode()
    return ad, Served(ad.A)


@pytest.fixture
def stack(tmp_path):
    saved = {k: os.environ.get(k) for k in ("HOMEPROV_ANCHOR_KEY", "HOMEPROV_ANCHOR_LINK", "HOMEPROV_WITNESS_KEY",
                                            "WITNESS_LOG", "WITNESS_FORKS", "HOMEPROV_SCRATCH")}
    w = Witness(str(tmp_path / "w"))
    os.makedirs(tmp_path / "a")
    ad, s = linked_operator_anchor(str(tmp_path / "a"), w.url)
    yield ad, s, w
    s.close()
    w.close()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def chain(ad):
    return [json.loads(line) for line in open(ad.A.CHAIN)]


@needs_crypto
def test_signed_purge_marker_through_a_linked_anchor_with_tagged_replies(tmp_path, stack):
    ad, s, w = stack
    priv, pub = keypair(str(tmp_path), "operator")
    _p2, pub2 = keypair(str(tmp_path), "other")
    signer = MI.load_signer(priv)
    rec = json.dumps({"observer": "external-monitor", "sealed": {}, "ts": 1.0}, sort_keys=True).encode()
    assert s.post(rec, MI.tag(rec, AKEY.encode()))[0] == 200                     # a monitor record first
    m = MI.scoped_marker(1790000000.0, 30 * 86400.0, issued_ts=1789999880.0)
    r = MI.issue(s.url, OP, m, signer=signer, reply_tags="1", attempts=1)
    assert r["ok"] and r["signed"] and len(r["attempts"]) == 1
    a = r["attempts"][0]
    assert a["reply_tag"] == "ok" and a["reply"]["witness_push"]["ok"] and a["reply"]["seq"] == 2
    recs = chain(ad)
    assert recs[1]["link"] == "v2" and recs[1]["payload"]["marker"] == m
    assert recs[1]["payload"]["marker_sig_fp"] == r["sig_fp"]
    data = open(ad.A.CHAIN, "rb").read()
    heads = [json.loads(line) for line in open(w.log)]
    v = CV.verify_chain(data, witnessed_heads=heads)
    assert v["ok"] and v["witnessed_heads"]["matched"] == 2
    got = MI.markers_from_chain(recs, OP, kinds=None, pubkey=MI.load_pubkey(pub))
    assert [g["marker"] for g in got] == ["PURGE"] and got[0]["seq"] == 2
    assert MI.markers_from_chain(recs, OP, kinds=None, pubkey=MI.load_pubkey(pub2)) == []
    assert MI.markers_from_chain(recs, AKEY.encode(), kinds=None) == []
    spec = importlib.util.spec_from_file_location("e7v_a6", os.path.join(REPO, "exp", "stages", "e7_verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    lines = open(ad.A.CHAIN).read().splitlines()
    acc, rep = V.chain_markers(lines, OP, pub)
    assert [x["chain_seq"] for x in acc] == [2] and rep["signature"] and rep["hmac"]
    acc2, rep2 = V.chain_markers(lines, OP, pub2)                    # signed by someone else: not the operator's
    assert acc2 == [] and rep2["rejected"][0]["why"] == "bad_or_foreign_signature"
    assert V.purge_cutoffs(acc, 30 * 86400.0)[0]["cutoff"] == 1790000000.0 - 30 * 86400.0


@needs_crypto
def test_restore_and_rename_from_the_command_line(tmp_path, stack):
    ad, s, w = stack
    priv, pub = keypair(str(tmp_path), "operator")
    key_file = tmp_path / "operator.key"
    key_file.write_text(OP_HEX + "\n")
    st = tmp_path / "storage"
    st.mkdir()
    (st / "core.entity_registry").write_text(json.dumps({"data": {"entities": [
        {"entity_id": "light.porch", "name": "Porch", "original_name": None, "device_id": None}]}}))
    env = dict(os.environ, PYTHONPATH=os.path.join(REPO, "exp"))
    base = [sys.executable, "-m", "rig.marker_issuer", "--anchor", s.url, "--key-file", str(key_file),
            "--sign-key", priv, "--reply-tags", "1", "--attempts", "1", "--log", str(tmp_path / "log.jsonl")]
    p = subprocess.run(base + ["--kind", "RESTORE", "--restore-point-ts", "1790000000"], env=env,
                       capture_output=True, text=True, cwd=REPO)
    assert p.returncode == 0, p.stderr
    p = subprocess.run(base + ["--kind", "RENAME", "--storage", str(st), "--rename-part", "entity", "--rename-match",
                               "entity_id=light.porch", "--rename-field", "name", "--rename-to", "Porch lamp"],
                       env=env, capture_output=True, text=True, cwd=REPO)
    assert p.returncode == 0, p.stderr
    log = [json.loads(line) for line in open(tmp_path / "log.jsonl")]
    assert [x["outcome"]["ok"] for x in log] == [True, True]
    got = MI.markers_from_chain(chain(ad), OP, kinds=None, pubkey=MI.load_pubkey(pub))
    assert [g["marker"] for g in got] == ["RESTORE", "RENAME"]
    assert got[0]["restore_point_ts"] == 1790000000.0
    # the declared digest is the one the monitor will seal once the rename is made
    spec = importlib.util.spec_from_file_location("mon_a6", os.path.join(REPO, "monitor", "monitor.py"))
    M = importlib.util.module_from_spec(spec)
    os.environ["HOMEPROV_SCRATCH"] = str(tmp_path / "scratch")
    spec.loader.exec_module(M)
    (st / "core.entity_registry").write_text(json.dumps({"data": {"entities": [
        {"entity_id": "light.porch", "name": "Porch lamp", "original_name": None, "device_id": None}]}}))
    assert got[1]["parts"] == {"entity": M.namemap_commitment(M.namemap_entries(str(st)))["parts"]["entity"]["digest"]}


class Spoof:
    """A host on the operator's network answering every append itself: untagged, with a wrong tag, or with a genuine
    tag it recorded for another request."""

    def __init__(self, mode, recorded=None):
        srv = self
        self.mode, self.recorded = mode, recorded

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                return None

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                raw = json.dumps({"ok": True, "seq": 7}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                if srv.mode == "badtag":
                    self.send_header("X-HP-Reply-Auth", "00" * 32)
                elif srv.mode == "replayed":
                    self.send_header("X-HP-Reply-Auth", srv.recorded)
                self.end_headers()
                self.wfile.write(raw)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/append" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.mark.parametrize("mode", ["untagged", "badtag", "replayed"])
def test_a_spoofed_reply_is_not_believed(mode):
    m = MI.scoped_marker(1790000000.0, 30 * 86400.0, issued_ts=1789999880.0)
    other = MI.marker_record(OP, MI.scoped_marker(1790086400.0, 30 * 86400.0, issued_ts=1790086280.0))
    body = json.dumps(other, sort_keys=True).encode()
    raw = json.dumps({"ok": True, "seq": 7}).encode()
    genuine_for_other = MI.hmac.new(OP, MI.REPLY_DOMAIN + MI.tag(body, OP).encode() + b"\n200\n" + raw,
                                    hashlib.sha256).hexdigest()
    sp = Spoof(mode, genuine_for_other)
    try:
        r = MI.issue(sp.url, OP, m, reply_tags="1", attempts=2, retry_s=0.0)
    finally:
        sp.close()
    assert not r["ok"] and len(r["attempts"]) == 2
    assert {a["reply_tag"] for a in r["attempts"]} == {"missing" if mode == "untagged" else "bad"}
    assert all(a["reply"] == {"ok": True, "seq": 7} for a in r["attempts"])  # it said ok; it was not believed


def test_the_anchors_authenticated_refusal_stops_the_retries(stack):
    _ad, s, _w = stack
    m = MI.scoped_marker(1790000000.0, 30 * 86400.0, issued_ts=1789999880.0)
    r = MI.issue(s.url, AKEY.encode(), m, reply_tags="1", attempts=5, retry_s=0.0)   # the append key, not the operator's
    (a,) = r["attempts"]
    assert not r["ok"] and a["http"] == 403 and a["reply_tag"] == "ok"
    assert a["reply"]["reason"] == "marker_needs_operator_key"


def test_waiting_follows_the_wall_clock(monkeypatch):
    """A host sleep stops the monotonic clock; time.sleep(s) then returns late. wait_until re-reads the wall clock
    after every step of at most 30 s, so it wakes at most one step after the host resumes."""
    clock = {"t": 1000.0, "slept": []}

    def sleep(sec):
        clock["slept"].append(sec)
        clock["t"] += sec + (5000.0 if len(clock["slept"]) == 2 else 0.0)   # the host sleeps during the 2nd step

    monkeypatch.setattr(MI.time, "time", lambda: clock["t"])
    monkeypatch.setattr(MI.time, "sleep", sleep)
    MI.wait_until(1100.0)
    assert clock["slept"] == [30.0, 30.0] and clock["t"] >= 1100.0


@needs_crypto
def test_R3_a_byte_identical_operator_request_appended_twice_counts_as_one_marker(tmp_path, stack):
    """E9 code review R3: the real anchord_linked.py (append key, operator key, sync witness) appends a captured operator
    request resent verbatim a second time (the issuer itself resends after a reply it could not verify, and the first
    may have been appended). The anchor keeps both records; the verifier counts the marker once and lists the copy."""
    import urllib.request
    ad, s, w = stack
    priv, pub = keypair(str(tmp_path), "op")
    rec = MI.marker_record(OP, MI.rename_marker({"entity": "ab" * 32}, issued_ts=1.0), MI.load_signer(priv))
    assert rec["marker"]["nonce"] and len(rec["marker"]["nonce"]) == 32
    body = json.dumps(rec, sort_keys=True).encode()
    seqs = []
    for _ in range(2):                                        # the original request, then the captured copy
        req = urllib.request.Request(s.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-HP-Auth": MI.tag(body, OP)})
        with urllib.request.urlopen(req, timeout=10) as resp:
            seqs.append(json.loads(resp.read())["seq"])
    assert seqs == [1, 2]
    spec = importlib.util.spec_from_file_location("e7v_r3", os.path.join(REPO, "exp", "stages", "e7_verify.py"))
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    acc, rep = V.chain_markers(open(ad.A.CHAIN).read().splitlines(), OP, pub)
    assert [x["chain_seq"] for x in acc] == [1]
    assert rep["duplicates"] == [{"chain_seq": 2, "kind": "RENAME", "duplicate_of": 1}]
