"""Verify an anchor chain written by testbed/anchord/anchord.py (review sp2027-r2 N2).

    python3 chainverify.py CHAIN.jsonl[.gz] [--head HEAD.json | --head-url http://witness:9910/head]
                           [--heads HEADS.jsonl[.gz] | --heads-url http://witness:9910/log]

A chain is a sequence of JSON lines. Records written before 2026-10-07 (link 'v1') carry only seq, recv_ts and payload:
their order, presence and content rest on the anchor host's word, and the verifier can check only that they parse and
are numbered 1, 2, 3, ... Records with "link": "v2" carry prev_digest, the SHA-256 of the previous record's exact line
(64 zeros for the first record); the first linked record after unlinked ones also carries legacy_prefix_digest, the
SHA-256 of every byte before it, which fixes the unlinked prefix from then on. A record's digest is SHA-256 over its line
as written, without the newline.

verify_chain() reports link ('v1' unlinked, 'v2' fully linked, 'mixed' unlinked prefix then linked suffix), the head
(seq and digest of the last record), and problems. Against an externally held head {seq, head_digest} (the head witness,
testbed/anchord/headwitness.py, or any copy kept off the anchor host) it also detects a truncated or replaced chain: the
chain must hold at least seq records and its record seq must have that digest. Without an external head a truncated
tail is undetectable even for a linked chain, and the report says so.

EVERY WITNESSED HEAD (2026-10-08, round 13, E8 item A1; review r2 R1 W1). Checking the latest witnessed head alone has a
gap: a host that rewrites record i, relinks records i+1..n and lets one honest append through presents a chain whose
record n+1 matches the latest head. verify_chain(..., witnessed_heads=[...]) checks EVERY head the witness accepted (its
log: heads.jsonl, or GET /log): the chain must hold record seq and that record must have the witnessed digest, for each
head; two different digests for one seq in the witness log are a problem too. --heads / --heads-url select this mode.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
import urllib.request

GENESIS = "0" * 64


def record_digest(line: bytes) -> str:
    return hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def verify_chain(data: bytes, external_head: dict | None = None, witnessed_heads: list | None = None) -> dict:
    problems, offsets, lines = [], [], []
    pos = 0
    for raw in data.split(b"\n"):
        if raw.strip():
            offsets.append(pos)
            lines.append(raw)
        elif pos + len(raw) < len(data):          # a blank line that is not the trailing newline
            problems.append({"at_byte": pos, "problem": "blank line inside the chain"})
        pos += len(raw) + 1
    recs, kinds, linked_seen = [], [], False
    for i, raw in enumerate(lines, 1):
        try:
            r = json.loads(raw)
        except ValueError:
            problems.append({"record": i, "problem": "not JSON"})
            recs.append(None); kinds.append("bad")
            continue
        recs.append(r)
        if r.get("seq") != i:
            problems.append({"record": i, "problem": "sequence number %r where %d was expected" % (r.get("seq"), i)})
        if r.get("link") == "v2":
            kinds.append("v2")
            want = record_digest(lines[i - 2]) if i > 1 else GENESIS
            if r.get("prev_digest") != want:
                problems.append({"record": i, "problem": "prev_digest does not match the previous record"})
            if i > 1 and kinds[i - 2] != "v2":
                if r.get("legacy_prefix_digest") != hashlib.sha256(data[:offsets[i - 1]]).hexdigest():
                    problems.append({"record": i, "problem": "legacy_prefix_digest does not match the unlinked prefix"})
                if r.get("legacy_records") != i - 1:
                    problems.append({"record": i, "problem": "legacy_records does not match the unlinked prefix"})
            linked_seen = True
        else:
            kinds.append("v1")
            if linked_seen:
                problems.append({"record": i, "problem": "unlinked record after a linked one"})
    n_v2 = kinds.count("v2")
    link = "v1" if n_v2 == 0 else ("v2" if n_v2 == len(kinds) else "mixed")
    head = {"seq": len(lines), "head_digest": record_digest(lines[-1]) if lines else None}
    out = {"records": len(lines), "link": link, "linked_records": n_v2, "head": head}
    if external_head:
        s, d = int(external_head.get("seq") or 0), external_head.get("head_digest")
        out["external_head"] = {"seq": s, "head_digest": d}
        if s > len(lines):
            problems.append({"problem": "chain holds %d records but the external head is at %d: truncated or replaced"
                                        % (len(lines), s)})
        elif s >= 1 and record_digest(lines[s - 1]) != d:
            problems.append({"record": s, "problem": "record does not have the externally held head digest: rewritten "
                                                     "or replaced"})
        out["records_after_external_head"] = max(0, len(lines) - s)
    if witnessed_heads is not None:
        digests, conflicting, mismatched, beyond = {}, [], [], []
        for h in witnessed_heads:
            s, d = int(h.get("seq") or 0), h.get("head_digest")
            if s in digests and digests[s] != d:
                conflicting.append(s)
            digests.setdefault(s, d)
        for s in sorted(digests):
            d = digests[s]
            if s > len(lines):
                beyond.append(s)
                problems.append({"problem": "the witness holds a head at seq %d but the chain holds %d records: "
                                            "truncated or replaced" % (s, len(lines))})
            elif s >= 1 and record_digest(lines[s - 1]) != d:
                mismatched.append(s)
                problems.append({"record": s, "problem": "record does not have the witnessed head digest: rewritten, "
                                                         "relinked or replaced"})
        for s in sorted(set(conflicting)):
            problems.append({"record": s, "problem": "the witness log holds two different digests for this seq"})
        out["witnessed_heads"] = {"heads": len(witnessed_heads), "distinct_seqs": len(digests),
                                  "matched": len(digests) - len(mismatched) - len(beyond),
                                  "mismatched_seqs": mismatched, "beyond_chain_seqs": beyond,
                                  "conflicting_seqs": sorted(set(conflicting)),
                                  "latest_seq": max(digests) if digests else 0,
                                  "records_after_latest_witnessed_head": max(0, len(lines) - max(digests, default=0))}
    out["problems"] = problems
    out["ok"] = not problems
    if link == "v1":
        out["integrity"] = ("unlinked (v1): records parse and are numbered consecutively; their order, presence and "
                            "content rest on the anchor host")
    elif witnessed_heads is not None:
        out["integrity"] = "linked and checked against every witnessed head (%d)" % len(witnessed_heads)
    elif not external_head:
        out["integrity"] = ("linked: reordering, deletion and rewriting of records are detectable; a truncated tail or a "
                            "replaced chain is not, without an externally held head")
    else:
        out["integrity"] = ("linked and checked against the externally held head only; check every witnessed head "
                            "(--heads) to rule out a rewrite followed by honest appends")
    return out


def read(path: str) -> bytes:
    return gzip.open(path).read() if path.endswith(".gz") else open(path, "rb").read()


def read_heads(raw: bytes) -> list:
    """Witnessed heads from a witness log (JSON lines) or a GET /log reply ({"heads": [...]})."""
    raw = raw.strip()
    if raw.startswith(b"{") and b"\n" not in raw:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "heads" in obj:
            return list(obj["heads"])
        return [obj]
    return [json.loads(l) for l in raw.split(b"\n") if l.strip()]


def main():
    a = sys.argv[1:]
    if not a:
        raise SystemExit(__doc__)
    head = None
    if "--head" in a:
        head = json.load(open(a[a.index("--head") + 1]))
    if "--head-url" in a:
        with urllib.request.urlopen(a[a.index("--head-url") + 1], timeout=10) as r:
            head = json.loads(r.read())
    heads = None
    if "--heads" in a:
        heads = read_heads(read(a[a.index("--heads") + 1]))
    if "--heads-url" in a:
        with urllib.request.urlopen(a[a.index("--heads-url") + 1], timeout=10) as r:
            heads = read_heads(r.read())
    res = verify_chain(read(a[0]), head, heads)
    print(json.dumps(res, indent=1))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
