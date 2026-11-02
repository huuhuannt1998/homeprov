"""Hash-linked anchor daemon (2026-10-07, review sp2027-r2 N2): anchord.py with linked records and a head export.

anchord.py writes records that carry only a sequence number, so the anchor host could reorder, delete or rewrite them
unseen. This entry point imports it and replaces the two functions that write and read the chain, so the protocol (one
verb, POST /append; HMAC authentication; first-write-wins refusals; the published head) and the way requests are served
are anchord.py's, and only the record format and the head grow. (The anchord.py every evaluated run up to E5 used is kept
byte-identical as anchord_r12.py; anchord.py itself was hardened on 2026-10-08 for E7: a thread per connection, read
timeouts and a request deadline, a body-size limit, and the conflict check and the append in one critical section. See its
docstring. The append below runs inside that critical section, so concurrent appends are linked one after another.)

  LINKED RECORDS. With HOMEPROV_ANCHOR_LINK=v2 (the default) every record also carries "link": "v2" and "prev_digest",
  the SHA-256 of the previous record's exact line (64 zeros for the first record), so each record commits to the whole
  chain before it. The first linked record appended after unlinked ones also carries "legacy_prefix_digest" (SHA-256 of
  every earlier byte) and "legacy_records", so an existing unlinked chain is fixed from that point on. A record's digest
  is SHA-256 over its line as written (sort_keys JSON, no trailing newline). HOMEPROV_ANCHOR_LINK=v1 writes the earlier
  unlinked records, byte-identical to anchord.py.

  HEAD EXPORT. A hash chain does not stop the host from truncating its tail or replacing the whole chain; that needs the
  head held by someone else. GET /head and the published head carry head_digest. With HEAD_WITNESS_URL set, every
  accepted append also pushes {seq, head_digest, recv_ts} (HMAC-tagged with HOMEPROV_WITNESS_KEY, or the anchor key) to a
  head witness on another host (headwitness.py): HEAD_WITNESS_MODE=sync pushes before the append is acknowledged (the
  reply carries the push outcome and its time), async pushes from a background thread. A failed push never refuses an
  append.

  EXTENSION PUSHES (2026-10-08, E8 item A1). The witness now accepts a head only if the push shows that it extends the
  last head the witness holds, so every push also carries "records": the exact chain lines from the record after the
  witness's last head through the new head (normally just the new record). This daemon remembers the last head the
  witness acknowledged; when it does not know it (after a start) it sends the new record alone, and when the witness
  answers 409 "gap" with its latest seq it resends from the record after that one. A catch-up larger than
  HEAD_WITNESS_PUSH_MAX_BYTES (default 8 MiB of record lines) is split into several pushes, each ending at an
  intermediate head. The reply's witness_push gains records_pushed.

chainverify.py verifies a chain, alone, against an externally held head, or against every witnessed head. Run: python3 anchord_linked.py (same port,
paths and environment as anchord.py).
"""
import hashlib, hmac, json, os, queue, sys, threading, time, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anchord as A  # noqa: E402  (the daemon: protocol, serving, refusals)

LINK = os.environ.get("HOMEPROV_ANCHOR_LINK", "v2")
if LINK not in ("v1", "v2"):
    raise SystemExit("HOMEPROV_ANCHOR_LINK must be 'v1' or 'v2', got %r" % LINK)
GENESIS = "0" * 64
WITNESS_URL = os.environ.get("HEAD_WITNESS_URL", "")
WITNESS_MODE = os.environ.get("HEAD_WITNESS_MODE", "sync")
WITNESS_KEY = (os.environ.get("HOMEPROV_WITNESS_KEY", "") or os.environ.get("HOMEPROV_ANCHOR_KEY", "")).encode()
_witness_q: "queue.Queue" = queue.Queue()
PUSH_MAX_BYTES = A._positive("HEAD_WITNESS_PUSH_MAX_BYTES", 8 * 1024 * 1024, int)
_wit = {"seq": None}      # the last head the witness acknowledged, as far as this daemon knows (None: unknown)


def record_digest(line: bytes) -> str:
    """Digest of one chain record: SHA-256 of its line as written, newline excluded."""
    return hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def _post_witness(push: dict) -> tuple:
    """(ok, reply). A refusal's JSON body is returned as the reply; a transport failure as {"err": ...}."""
    body = json.dumps(push, sort_keys=True).encode()
    hdr = {"Content-Type": "application/json"}
    if WITNESS_KEY:
        hdr["X-HP-Auth"] = hmac.new(WITNESS_KEY, body, hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(WITNESS_URL, data=body, method="POST", headers=hdr)
        with urllib.request.urlopen(req, timeout=5) as r:
            out = json.loads(r.read())
        return bool(out.get("ok")), out
    except urllib.error.HTTPError as exc:
        try:
            out = json.loads(exc.read())
        except Exception:                             # noqa: BLE001
            out = {}
        return False, {"http": exc.code, **(out if isinstance(out, dict) else {})}
    except Exception as exc:                          # noqa: BLE001
        return False, {"err": repr(exc)[:120]}


def _chain_lines(lo: int, hi: int) -> list:
    """Records lo..hi (1-based, inclusive) as written, without the newline."""
    with open(A.CHAIN, "rb") as fh:
        lines = [l for l in fh.read().split(b"\n") if l.strip()]
    return [l.decode() for l in lines[lo - 1:hi]]


def _push_range(lo: int, head: dict) -> tuple:
    """Push records lo..head["seq"], in batches of at most PUSH_MAX_BYTES, each batch ending at its own head.
    Returns (ok, last reply, records pushed)."""
    lines, pushed, out = _chain_lines(lo, head["seq"]), 0, {}
    i = 0
    while i < len(lines):
        j, size = i, 0
        while j < len(lines) and (j == i or size + len(lines[j]) <= PUSH_MAX_BYTES):
            size += len(lines[j]); j += 1
        last = lines[j - 1]
        if j == len(lines):
            h = head
        else:
            h = {"seq": lo + j - 1, "head_digest": record_digest(last.encode()), "recv_ts": json.loads(last).get("recv_ts")}
        ok, out = _post_witness({**h, "records": lines[i:j]})
        if not ok:
            return False, out, pushed
        pushed += j - i
        _wit["seq"] = h["seq"]
        i = j
    return True, out, pushed


def _push_head(head: dict) -> dict:
    """Push a new head with the records that show it extends the witness's last head; after a "gap" reply, resend
    once from the record after the witness's head. Never raises; never refuses the append."""
    t = time.time()
    n = head["seq"]
    lo = n if _wit["seq"] is None or _wit["seq"] >= n else _wit["seq"] + 1
    ok, out, pushed = _push_range(lo, head)
    latest = out.get("latest")
    if not ok and out.get("reason") == "gap" and isinstance(latest, int) and 0 <= latest < n and latest + 1 != lo:
        ok, out, more = _push_range(latest + 1, head)
        pushed += more
    if ok:
        _wit["seq"] = n
    return {"ok": ok, "ms": round((time.time() - t) * 1000, 3), "witness": out, "records_pushed": pushed}


def _witness_worker():
    while True:
        _push_head(_witness_q.get())


def _append(rec: dict) -> dict:
    with A._lock:
        seq, last, prefix = 0, None, b""
        if os.path.exists(A.CHAIN):
            with open(A.CHAIN, "rb") as fh:
                prefix = fh.read()
            lines = [l for l in prefix.split(b"\n") if l.strip()]
            seq = len(lines)
            last = lines[-1] if lines else None
        A._record_roots(rec)
        rec = {"seq": seq + 1, "recv_ts": time.time(), "payload": rec}
        if LINK == "v2":
            rec["link"] = "v2"
            rec["prev_digest"] = record_digest(last) if last is not None else GENESIS
            if last is not None and json.loads(last).get("link") != "v2":
                rec["legacy_prefix_digest"] = hashlib.sha256(prefix).hexdigest()
                rec["legacy_records"] = seq
        line = json.dumps(rec, sort_keys=True)
        with open(A.CHAIN, "a") as fh:         # O_APPEND, the only write path
            fh.write(line + "\n")
            fh.flush(); os.fsync(fh.fileno())
        head = {"seq": rec["seq"], "head_digest": record_digest(line.encode()), "recv_ts": rec["recv_ts"]}
    out = {"ok": True, "seq": rec["seq"], "head_digest": head["head_digest"]}
    # Served appends reach this point inside anchord._admit's critical section, so heads are pushed (sync) or queued
    # (async, one worker) in sequence order and the witness never sees a sequence number go backwards.
    if WITNESS_URL:
        if WITNESS_MODE == "sync":
            out["witness_push"] = _push_head(head)
        else:
            _witness_q.put(head)
    return out


def _head() -> dict:
    if not os.path.exists(A.CHAIN):
        return {"seq": 0, "head": None, "head_digest": None, "link": LINK}
    last, n = None, 0
    with open(A.CHAIN, "rb") as fh:
        for line in fh:
            if line.strip():
                last = line; n += 1
    return {"seq": n, "head": json.loads(last) if last else None,
            "head_digest": record_digest(last) if last else None, "link": LINK}


# The handler class and the publisher look these names up in anchord's namespace at call time.
EVALUATED_APPEND, EVALUATED_HEAD = A._append, A._head     # the unlinked writer and reader, kept for tests and comparison
A._append = _append
A._head = _head


def start_background():
    threading.Thread(target=A._publisher, daemon=True).start()
    if WITNESS_URL and WITNESS_MODE != "sync":
        threading.Thread(target=_witness_worker, daemon=True).start()


def serve(host: str = "0.0.0.0", port: int = 9900) -> None:
    os.makedirs(os.path.dirname(A.CHAIN), exist_ok=True)
    A._rebuild_roots()
    start_background()
    with A.AnchorServer((host, port), A.H) as s:          # threaded, with anchord.py's read limits
        s.serve_forever()


if __name__ == "__main__":
    serve()
