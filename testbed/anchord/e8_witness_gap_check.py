"""E8 item A1, offline: the reviewer's witness-gap attack replayed on E5's saved chain and witnessed heads.

    python3 testbed/anchord/e8_witness_gap_check.py [--e5-witness PATH] [--out exp/out/e8_witness_gap_check.json]

Inputs (read only): exp/out/e5_psr_lnk_linked_chain.jsonl.gz (225 linked records) and exp/out/e5_psr_lnk_witness_heads.jsonl.gz
(the 225 heads E5's witness accepted). For every i in 1..225, on a COPY of the chain: rewrite record i's first sealed
root, relink records i+1..225 (the links are unkeyed SHA-256, so the copy is self-consistent), then let one honest
append (record 226) through with the current linked daemon (anchord_linked._append, sync push). That push goes to two
witnesses, each started from E5's 225 heads: E5's own witness code (headwitness.py as E5 ran it, sha256 recorded in
e5_psr_lnk_config.json) and the current one. Then the attacked chain is verified by the old rule (against the latest
witnessed head only) and by the new rule (against every witnessed head). The witness key is a fresh one (E5's was never
recorded); the rules do not depend on it.
"""
from __future__ import annotations

import datetime
import gzip
import hashlib
import hmac
import importlib.util
import itertools
import json
import os
import platform
import shutil
import socketserver
import sys
import tempfile
import threading
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import chainverify as CV  # noqa: E402

CHAIN = "exp/out/e5_psr_lnk_linked_chain.jsonl.gz"
HEADS = "exp/out/e5_psr_lnk_witness_heads.jsonl.gz"
CONFIG = "exp/out/e5_psr_lnk_config.json"
DEFAULT_E5_WITNESS = os.path.join(os.path.dirname(REPO), "HOMEPROV-P13-artifact-prep", "r12_tree", "testbed",
                                  "anchord", "headwitness.py")
WKEY = hashlib.sha256(b"e8-witness-gap-check").hexdigest()
_n = itertools.count()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def lines_of(data):
    return [l for l in data.split(b"\n") if l.strip()]


def rewrite_and_relink(data: bytes, i: int) -> bytes:
    """Rewrite record i's first sealed root at rest and relink records i+1..n."""
    recs = [json.loads(l) for l in lines_of(data)]
    seg = recs[i - 1]["payload"]["sealed"]
    g = next(g for g in seg if seg[g])
    s = next(iter(seg[g]))
    seg[g][s]["acc"] = sha(b"rewritten" + seg[g][s]["acc"].encode())
    out = [json.dumps(r, sort_keys=True).encode() for r in recs]
    for k in range(i, len(recs)):
        recs[k]["prev_digest"] = CV.record_digest(out[k - 1])
        out[k] = json.dumps(recs[k], sort_keys=True).encode()
    return b"\n".join(out) + b"\n"


class Witness:
    def __init__(self, path: str, tmp: str, seed: bytes):
        os.makedirs(tmp)
        os.environ.update(HOMEPROV_WITNESS_KEY=WKEY, WITNESS_LOG=os.path.join(tmp, "heads.jsonl"),
                          WITNESS_FORKS=os.path.join(tmp, "forks.jsonl"))
        self.forks = os.path.join(tmp, "forks.jsonl")
        open(os.path.join(tmp, "heads.jsonl"), "wb").write(seed)
        spec = importlib.util.spec_from_file_location("hw_gap_%d" % next(_n), path)
        self.hw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hw)
        self.hw._load()
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), self.hw.H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def get(self, p):
        with urllib.request.urlopen(self.url + p, timeout=5) as r:
            return json.loads(r.read())

    def n_forks(self):
        return sum(1 for _ in open(self.forks)) if os.path.exists(self.forks) else 0

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


def linked_daemon(tmp: str):
    os.environ.update(HOMEPROV_ANCHOR_KEY="", HOMEPROV_ANCHOR_LINK="v2")
    os.environ.pop("HOMEPROV_OPERATOR_KEY", None)
    sys.modules.pop("anchord", None)
    spec = importlib.util.spec_from_file_location("al_gap_%d" % next(_n), os.path.join(HERE, "anchord_linked.py"))
    ad = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ad)
    ad.A.CHAIN, ad.A.REFUSALS, ad.A.PUBLISH = (os.path.join(tmp, "chain.jsonl"), os.path.join(tmp, "refusals.jsonl"),
                                               os.path.join(tmp, "head.json"))
    ad.WITNESS_MODE, ad.WITNESS_KEY = "sync", WKEY.encode()
    return ad


def main(argv):
    out_path = argv[argv.index("--out") + 1] if "--out" in argv else os.path.join(REPO, "exp", "out",
                                                                                 "e8_witness_gap_check.json")
    e5_witness = argv[argv.index("--e5-witness") + 1] if "--e5-witness" in argv else DEFAULT_E5_WITNESS
    chain_gz, heads_gz = open(os.path.join(REPO, CHAIN), "rb").read(), open(os.path.join(REPO, HEADS), "rb").read()
    data, heads_raw = gzip.decompress(chain_gz), gzip.decompress(heads_gz)
    heads = CV.read_heads(heads_raw)
    cfg = json.load(open(os.path.join(REPO, CONFIG)))
    have_old = os.path.exists(e5_witness)
    old_sha = sha(open(e5_witness, "rb").read()) if have_old else None
    started = datetime.datetime.now(datetime.timezone.utc)

    base = {"chain_alone": CV.verify_chain(data), "latest_head": CV.verify_chain(data, heads[-1]),
            "every_head": CV.verify_chain(data, witnessed_heads=heads)}
    baseline = {"chain_alone_ok": base["chain_alone"]["ok"], "link": base["chain_alone"]["link"],
                "records": base["chain_alone"]["records"], "latest_head_ok": base["latest_head"]["ok"],
                "every_head_ok": base["every_head"]["ok"],
                "every_head_matched": base["every_head"]["witnessed_heads"]["matched"]}

    n = len(lines_of(data))
    last = json.loads(lines_of(data)[-1])["payload"]
    seconds = [int(s) for s in ((last.get("sealed") or {}).get("second") or {})]
    seg = (max(seconds) if seconds else int(float(last.get("ts", 0)))) + 6
    honest = {"observer": "external-monitor", "ts": float(last.get("ts", 0)) + 6.0, "scheme": last.get("scheme"),
              "encoding": last.get("encoding"),
              "sealed": {"second": {str(seg): {"acc": sha(b"honest append after the rewrite"), "n": 1}}}}
    work = tempfile.mkdtemp(prefix="e8gap_")
    per_i = []
    try:
        for i in range(1, n + 1):
            d = os.path.join(work, str(i))
            new_w = Witness(os.path.join(HERE, "headwitness.py"), os.path.join(d, "new"), heads_raw)
            old_w = Witness(e5_witness, os.path.join(d, "old"), heads_raw) if have_old else None
            try:
                os.makedirs(os.path.join(d, "a"))
                ad = linked_daemon(os.path.join(d, "a"))
                attacked = rewrite_and_relink(data, i)
                assert CV.verify_chain(attacked)["ok"]
                open(ad.A.CHAIN, "wb").write(attacked)
                ad.WITNESS_URL = new_w.url + "/head"
                o = ad._append(honest)                                    # the honest append, pushed to the new witness
                final = open(ad.A.CHAIN, "rb").read()
                l226 = lines_of(final)[-1].decode()
                push = {"seq": o["seq"], "head_digest": o["head_digest"], "recv_ts": json.loads(l226)["recv_ts"],
                        "records": [l226]}
                row = {"i": i, "honest_append_seq": o["seq"],
                       "new_witness_accepted": o["witness_push"]["ok"],
                       "new_witness_reason": o["witness_push"]["witness"].get("reason"),
                       "new_witness_forks_logged": new_w.n_forks()}
                new_log = new_w.get("/log")["heads"]
                r_new_every = CV.verify_chain(final, witnessed_heads=new_log)
                r_new_latest = CV.verify_chain(final, new_w.get("/head"))
                row.update(new_rule_every_head_ok=r_new_every["ok"],
                           new_rule_mismatched=len(r_new_every["witnessed_heads"]["mismatched_seqs"]),
                           new_rule_first_mismatch=(r_new_every["witnessed_heads"]["mismatched_seqs"] or [None])[0],
                           latest_head_of_new_witness_ok=r_new_latest["ok"])
                if old_w:
                    ad.WITNESS_URL = old_w.url + "/head"
                    ok, rep = ad._post_witness(push)                       # the same push to E5's witness code
                    old_log = old_w.get("/log")["heads"]
                    row.update(e5_witness_accepted=ok,
                               old_rule_latest_head_ok=CV.verify_chain(final, old_w.get("/head"))["ok"],
                               new_rule_on_e5_witness_log_ok=CV.verify_chain(final, witnessed_heads=old_log)["ok"])
                per_i.append(row)
            finally:
                new_w.close()
                if old_w:
                    old_w.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    def count(key, val=True):
        return sum(1 for r in per_i if r.get(key) == val)
    summary = {
        "attacks": len(per_i),
        "new_witness_refused_honest_head": count("new_witness_accepted", False),
        "new_witness_refusal_reasons": sorted({str(r["new_witness_reason"]) for r in per_i}),
        "new_witness_forks_logged": sum(r["new_witness_forks_logged"] for r in per_i),
        "new_rule_every_witnessed_head_failed": count("new_rule_every_head_ok", False),
        "new_rule_mismatches_equal_rewritten_and_relinked_records": all(
            r["new_rule_mismatched"] == n - r["i"] + 1 and r["new_rule_first_mismatch"] == r["i"] for r in per_i),
        "latest_head_of_new_witness_failed": count("latest_head_of_new_witness_ok", False),
    }
    if have_old:
        summary.update(e5_witness_accepted_honest_head=count("e5_witness_accepted"),
                       old_rule_latest_head_passed=count("old_rule_latest_head_ok"),
                       new_rule_on_e5_witness_log_failed=count("new_rule_on_e5_witness_log_ok", False))
    files = {"chainverify.py": "testbed/anchord/chainverify.py", "headwitness.py": "testbed/anchord/headwitness.py",
             "anchord_linked.py": "testbed/anchord/anchord_linked.py", "anchord.py": "testbed/anchord/anchord.py",
             "e8_witness_gap_check.py": "testbed/anchord/e8_witness_gap_check.py"}
    res = {
        "check": "E8 A1 offline: the reviewer's witness-gap attack (rewrite record i, relink i+1..n, let one honest "
                 "append through) on E5's saved chain and witnessed heads, for every i",
        "date_utc": started.isoformat(timespec="seconds"),
        "command": "python3 testbed/anchord/e8_witness_gap_check.py",
        "python": platform.python_version(),
        "inputs": {
            "chain": {"file": CHAIN, "sha256_gz": sha(chain_gz), "sha256_uncompressed": sha(data),
                      "matches_e5_config": sha(data) == cfg.get("linked_chain", {}).get("sha256_uncompressed"),
                      "records": n},
            "witness_heads": {"file": HEADS, "sha256_gz": sha(heads_gz), "sha256_uncompressed": sha(heads_raw),
                              "matches_e5_config": sha(heads_raw) == cfg.get("witness_heads", {}).get(
                                  "sha256_uncompressed"), "heads": len(heads)},
            "e5_witness_code": {"source": "headwitness.py as E5 ran it (copy in the r12 artifact tree, outside the "
                                          "repository)" if have_old else "absent: E5-witness verdicts not computed",
                                "sha256": old_sha,
                                "matches_e5_config": old_sha == cfg.get("witness", {}).get("headwitness_py_sha256")
                                if have_old else None}},
        "code": {k: sha(open(os.path.join(REPO, v), "rb").read()) for k, v in files.items()},
        "procedure": {
            "attack": "on a copy: record i's first sealed root replaced by sha256('rewritten' + old root); records "
                      "i+1..225 relinked (prev_digest recomputed); then one honest append (record 226) by the current "
                      "anchord_linked._append with a sync push",
            "witnesses": "each attack gets two fresh witnesses started from E5's 225 heads: the current headwitness.py "
                         "(receives the daemon's own push) and E5's headwitness.py (receives the identical push body)",
            "old_rule": "chainverify against the latest witnessed head only (verify_chain(chain, latest_head))",
            "new_rule": "chainverify against every witnessed head (verify_chain(chain, witnessed_heads=log))",
            "witness_key": "fresh, fixed in the script (E5's key was not recorded; the rules do not use it)"},
        "baseline_unmodified_chain": baseline,
        "summary": summary,
        "per_attack": per_i,
    }
    with open(out_path, "w") as fh:
        json.dump(res, fh, indent=1)
        fh.write("\n")
    print(json.dumps({"baseline": baseline, "summary": summary}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
