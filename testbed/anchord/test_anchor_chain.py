"""Anchor hash-linking tests (review sp2027-r2 N2).

    python3 -m pytest -q testbed/anchord/test_anchor_chain.py

The linked daemon (anchord_linked.py, which wraps the unmodified evaluated daemon anchord.py) is imported with its paths
pointed at a temporary directory and driven through its own _append() and, for the witness, through HTTP. chainverify.py is the verifier. Checks: a linked chain verifies; reordering,
deleting or rewriting a record is detected; a truncated tail or a replaced chain is detected against the externally held
head (and is not detectable without it, which the report states); a daemon restarted on an unlinked chain links forward
and fixes the unlinked prefix; every unlinked chain saved by the evaluated runs still verifies as v1; v1 mode writes
records byte-identical to the earlier daemon; the head witness refuses forks, regressions and untagged pushes.
"""
from __future__ import annotations

import glob
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import chainverify as CV  # noqa: E402


def load_anchord(tmp, link="v2", key=""):
    """A fresh anchord + anchord_linked pair with its files in tmp; ad.CHAIN aliases the evaluated module's path."""
    os.environ["HOMEPROV_ANCHOR_KEY"] = key
    os.environ["HOMEPROV_ANCHOR_LINK"] = link
    sys.modules.pop("anchord", None)
    spec = importlib.util.spec_from_file_location("anchord_linked_t_%s_%d" % (link, id(tmp)),
                                                  os.path.join(HERE, "anchord_linked.py"))
    ad = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ad)
    ad.A.CHAIN = ad.CHAIN = os.path.join(tmp, "chain.jsonl")
    ad.A.REFUSALS = os.path.join(tmp, "refusals.jsonl")
    ad.A.PUBLISH = os.path.join(tmp, "head.json")
    return ad


def payload(i):
    return {"observer": "external-monitor", "ts": 1790000000.0 + i, "scheme": "closure", "encoding": "v2",
            "sealed": {"second": {str(1790000000 + i): {"acc": hashlib.sha256(b"%d" % i).hexdigest(), "n": i}}}}


def build(tmp, n=12, link="v2"):
    ad = load_anchord(tmp, link)
    for i in range(1, n + 1):
        assert ad._append(payload(i))["ok"]
    return ad, open(ad.CHAIN, "rb").read()


def lines_of(data):
    return [l for l in data.split(b"\n") if l.strip()]


def join(lines):
    return b"\n".join(lines) + b"\n"


def test_linked_chain_verifies(tmp_path):
    ad, data = build(str(tmp_path))
    r = CV.verify_chain(data, ad._head())
    assert r["ok"] and r["link"] == "v2" and r["records"] == 12 and r["linked_records"] == 12
    assert r["head"]["head_digest"] == ad._head()["head_digest"]
    assert json.loads(lines_of(data)[0])["prev_digest"] == CV.GENESIS


def test_reordering_detected(tmp_path):
    _ad, data = build(str(tmp_path))
    ls = lines_of(data)
    ls[4], ls[5] = ls[5], ls[4]
    r = CV.verify_chain(join(ls))
    assert not r["ok"] and any("prev_digest" in p["problem"] for p in r["problems"])


def test_reordering_with_renumbering_detected(tmp_path):
    """Swap two records and rewrite their seq fields so the numbering looks intact: the links still break."""
    _ad, data = build(str(tmp_path))
    ls = [json.loads(l) for l in lines_of(data)]
    ls[4], ls[5] = ls[5], ls[4]
    ls[4]["seq"], ls[5]["seq"] = 5, 6
    r = CV.verify_chain(join([json.dumps(x, sort_keys=True).encode() for x in ls]))
    assert not r["ok"] and all("sequence" not in p["problem"] for p in r["problems"])


def test_deletion_detected(tmp_path):
    _ad, data = build(str(tmp_path))
    ls = lines_of(data)
    del ls[6]
    assert not CV.verify_chain(join(ls))["ok"]


def test_deletion_with_renumbering_detected(tmp_path):
    _ad, data = build(str(tmp_path))
    ls = [json.loads(l) for l in lines_of(data)]
    del ls[6]
    for i, x in enumerate(ls, 1):
        x["seq"] = i
    r = CV.verify_chain(join([json.dumps(x, sort_keys=True).encode() for x in ls]))
    assert not r["ok"] and any("prev_digest" in p["problem"] for p in r["problems"])


def test_rewritten_root_detected(tmp_path):
    _ad, data = build(str(tmp_path))
    ls = [json.loads(l) for l in lines_of(data)]
    seg = next(iter(ls[3]["payload"]["sealed"]["second"]))
    ls[3]["payload"]["sealed"]["second"][seg]["acc"] = "ff" * 32
    assert not CV.verify_chain(join([json.dumps(x, sort_keys=True).encode() for x in ls]))["ok"]


def test_truncation_detected_only_with_external_head(tmp_path):
    ad, data = build(str(tmp_path))
    head = ad._head()
    cut = join(lines_of(data)[:9])
    alone = CV.verify_chain(cut)
    assert alone["ok"] and "truncated tail" in alone["integrity"]          # the chain alone cannot show it
    r = CV.verify_chain(cut, {"seq": head["seq"], "head_digest": head["head_digest"]})
    assert not r["ok"] and any("truncated" in p["problem"] for p in r["problems"])


def test_replaced_chain_detected_by_external_head(tmp_path):
    os.makedirs(tmp_path / "a")
    ad, _data = build(str(tmp_path / "a"), n=12)
    head = ad._head()
    os.makedirs(tmp_path / "b")
    _ad2, other = build(str(tmp_path / "b"), n=12)                          # a different, self-consistent chain
    assert CV.verify_chain(other)["ok"]
    r = CV.verify_chain(other, {"seq": head["seq"], "head_digest": head["head_digest"]})
    assert not r["ok"]


def test_restart_on_unlinked_chain_links_forward(tmp_path):
    """The unlinked prefix is written by the EVALUATED daemon's own append (anchord.py, unmodified)."""
    tmp = str(tmp_path)
    ad1 = load_anchord(tmp, "v2")
    for i in range(1, 6):
        ad1.EVALUATED_APPEND(payload(i))
    v1 = open(ad1.CHAIN, "rb").read()
    assert CV.verify_chain(v1)["link"] == "v1"
    ad2 = load_anchord(tmp, "v2")
    for i in range(6, 10):
        ad2._append(payload(i))
    data = open(ad2.CHAIN, "rb").read()
    r = CV.verify_chain(data, ad2._head())
    assert r["ok"] and r["link"] == "mixed" and r["linked_records"] == 4
    first = json.loads(lines_of(data)[5])
    assert first["legacy_records"] == 5 and first["legacy_prefix_digest"] == hashlib.sha256(v1).hexdigest()
    ls = [json.loads(l) for l in lines_of(data)]                           # the unlinked prefix is now fixed
    ls[1]["recv_ts"] += 1
    assert not CV.verify_chain(join([json.dumps(x, sort_keys=True).encode() for x in ls]))["ok"]


def test_v1_mode_writes_the_earlier_record_format(tmp_path):
    """v1 mode writes what the evaluated daemon writes: same keys, same serialization."""
    os.makedirs(tmp_path / "v1"); os.makedirs(tmp_path / "orig")
    _ad, data = build(str(tmp_path / "v1"), n=3, link="v1")
    o = load_anchord(str(tmp_path / "orig"), "v2")
    for i in range(1, 4):
        o.EVALUATED_APPEND(payload(i))
    orig = open(o.CHAIN, "rb").read()
    strip = lambda d: [{k: v for k, v in json.loads(l).items() if k != "recv_ts"} for l in lines_of(d)]  # noqa: E731
    assert strip(data) == strip(orig)
    for l in lines_of(data):
        assert set(json.loads(l)) == {"seq", "recv_ts", "payload"}
        assert l == json.dumps(json.loads(l), sort_keys=True).encode()


def test_evaluated_daemon_is_unmodified():
    """The daemon every evaluated run up to E5 used (git blob of artifact-review/HEAD's anchord.py) is kept byte-identical
    as anchord_r12.py. anchord.py itself was hardened for E7 on 2026-10-08 (serving only; protocol, record format and
    refusals unchanged), which test_anchor_stall.py checks against this copy."""
    assert hashlib.sha256(open(os.path.join(HERE, "anchord_r12.py"), "rb").read()).hexdigest() == \
        "7b1ef9f1e11a36584eb0fde218fc6a0bb234ff33071e80990d0d354883a0c17f"


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(REPO, "reproduce", "snapshots", "*.chain.jsonl*")))
                         + sorted(glob.glob(os.path.join(REPO, "exp", "out", "*anchor_chain.jsonl*"))))
def test_saved_evaluation_chains_verify_as_v1(path):
    r = CV.verify_chain(CV.read(path))
    assert r["ok"] and r["link"] == "v1" and r["linked_records"] == 0


def _serve_witness(tmp, key):
    os.environ["HOMEPROV_WITNESS_KEY"] = key
    os.environ["WITNESS_LOG"] = os.path.join(tmp, "heads.jsonl")
    os.environ["WITNESS_FORKS"] = os.path.join(tmp, "forks.jsonl")
    spec = importlib.util.spec_from_file_location("hw_%d" % id(tmp), os.path.join(HERE, "headwitness.py"))
    hw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hw)
    import socketserver
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), hw.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return hw, srv, "http://127.0.0.1:%d" % srv.server_address[1]


def _post(url, obj, key):
    body = json.dumps(obj, sort_keys=True).encode()
    hdr = {"Content-Type": "application/json"}
    if key:
        hdr["X-HP-Auth"] = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    try:
        with urllib.request.urlopen(urllib.request.Request(url + "/head", data=body, headers=hdr, method="POST")) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_witness_flow_and_refusals(tmp_path):
    key = "k" * 32
    os.makedirs(tmp_path / "w")
    hw, srv, url = _serve_witness(str(tmp_path / "w"), key)
    try:
        os.makedirs(tmp_path / "a")
        ad = load_anchord(str(tmp_path / "a"), "v2", key="")
        ad.WITNESS_URL, ad.WITNESS_MODE, ad.WITNESS_KEY = url + "/head", "sync", key.encode()
        outs = [ad._append(payload(i)) for i in range(1, 8)]
        assert all(o["witness_push"]["ok"] for o in outs)
        with urllib.request.urlopen(url + "/head") as r:
            wh = json.loads(r.read())
        data = open(ad.CHAIN, "rb").read()
        assert wh == {"seq": 7, "head_digest": CV.record_digest(lines_of(data)[-1])}
        assert CV.verify_chain(data, wh)["ok"]
        assert not CV.verify_chain(join(lines_of(data)[:6]), wh)["ok"]       # truncation caught by the witness
        assert _post(url, {"seq": 7, "head_digest": "ab" * 32}, key) == 409   # fork
        assert _post(url, {"seq": 3, "head_digest": "cd" * 32}, key) == 409   # regression with a new digest
        assert _post(url, {"seq": 8, "head_digest": "ef" * 32}, "") == 401    # untagged
        assert _post(url, {"seq": 8, "head_digest": "ef" * 32}, "x" * 32) == 401  # forged tag
    finally:
        srv.shutdown()
