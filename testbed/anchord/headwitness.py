"""Head witness: holds the anchor chain's head on another host (review sp2027-r2 N2).

A hash-linked chain lets a verifier detect a reordered, deleted or rewritten record, but not a chain that was truncated
or replaced wholesale by the host that stores it. The witness closes that gap: the anchor daemon pushes
{seq, head_digest, recv_ts} after every accepted append (HEAD_WITNESS_URL), and the witness, which runs on another host
and shares nothing with the anchor, keeps the history of heads it was given. The verifier compares the chain against the
witness's latest head: the chain must have at least that many records and its record at that sequence number must have
that digest.

Rules it enforces: pushes must carry a valid HMAC-SHA256 tag (HOMEPROV_WITNESS_KEY) when a key is set; the sequence
number may not go backwards; a second, different digest for a sequence number already witnessed is refused and logged as
a fork (409). One verb mutates state: POST /head. GET /head returns the latest head, GET /log every accepted head.

EXTENSION (2026-10-08, round 13, E8 item A1; review r2 R1 W1). Refusing regressions and second digests was not enough:
a host that rewrote record i, relinked records i+1..n (the links are unkeyed SHA-256) and let one honest append through
had head n+1 accepted, because n+1 did not regress, and a verifier that compared the chain with the latest head only
passed. The witness now accepts a new head only when the push shows that it extends the last witnessed head: a push is
{seq, head_digest, recv_ts, records}, where records are the exact chain lines (as written, without the newline) from the
record after the last witnessed head through the new head. The witness checks that their seq fields run on from its last
head, that every record is linked ("link": "v2") and its prev_digest is the digest of the record before it (the first
one: the last witnessed head digest), and that the last line's digest is head_digest. A push that starts later than the
record after the last head is refused as a gap (409, reason "gap", with "latest"), so the pusher resends from there; a
push that does not link is refused (409, reason "not_extension") and logged to the forks file. A witness with no head
yet requires the history from record 1 (the first record's prev_digest is 64 zeros; unlinked legacy records before the
first linked one are accepted, and a legacy_prefix_digest is checked against them). A head the witness already holds is
accepted again (200) when the digest matches. HOMEPROV_WITNESS_MAX_BODY now defaults to 64 MiB so a push can carry an
anchor record of the anchor's own maximum size (16 MiB) after JSON escaping; the anchor batches catch-up pushes.

Serving limits (2026-10-08, the same hardening as anchord.py): the server was already threaded, but it read a body with
no timeout and no size limit, so a stalled client held its thread forever and a negative Content-Length read until the
client closed. Every read and write now times out after HOMEPROV_WITNESS_IO_TIMEOUT_S (default 5 s), the request must
arrive within HOMEPROV_WITNESS_REQUEST_DEADLINE_S (default 10 s) of the accept, a declared body over
HOMEPROV_WITNESS_MAX_BODY bytes (default 65536 then; 64 MiB since E8, see above) is refused (413) unread, a bad Content-Length
or a short body is refused (400), a late body is refused (408), and a non-ASCII tag is refused (401) instead of raising.

    HOMEPROV_WITNESS_KEY=... WITNESS_LOG=/witness/heads.jsonl python3 headwitness.py      # listens on 0.0.0.0:9910
"""
import hashlib, hmac, http.server, io, json, os, socket, socketserver, threading, time

LOG = os.environ.get("WITNESS_LOG", "/witness/heads.jsonl")
FORKS = os.environ.get("WITNESS_FORKS", "/witness/forks.jsonl")
KEY = os.environ.get("HOMEPROV_WITNESS_KEY", "").encode()
PORT = int(os.environ.get("WITNESS_PORT", "9910"))
_lock = threading.Lock()


def _positive(name: str, default, kind=float):
    raw = os.environ.get(name, "").strip()
    try:
        value = kind(raw) if raw else kind(default)
    except ValueError:
        raise SystemExit("%s must be a positive %s, got %r" % (name, kind.__name__, raw))
    if value <= 0:
        raise SystemExit("%s must be positive, got %r" % (name, raw))
    return value


IO_TIMEOUT_S = _positive("HOMEPROV_WITNESS_IO_TIMEOUT_S", 5.0)
REQUEST_DEADLINE_S = _positive("HOMEPROV_WITNESS_REQUEST_DEADLINE_S", 10.0)
MAX_BODY = _positive("HOMEPROV_WITNESS_MAX_BODY", 64 * 1024 * 1024, int)
GENESIS = "0" * 64


def record_digest(line: bytes) -> str:
    """Digest of one chain record: SHA-256 of its line as written, newline excluded (as chainverify.py)."""
    return hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def _extension(records, seq: int, digest: str, last_seq: int, last_digest):
    """None if the records show that head (seq, digest) extends the last witnessed head (last_seq, last_digest), else
    (reason, detail). reason is "gap" when the records start after the record that follows the last head."""
    if not isinstance(records, list) or not records or not all(isinstance(x, str) for x in records):
        return "not_extension", "the push carries no records (the chain lines from the last witnessed head on)"
    parsed = []
    for k, line in enumerate(records):
        try:
            r = json.loads(line)
        except ValueError:
            return "not_extension", "record %d of the push is not JSON" % k
        if not isinstance(r, dict) or not isinstance(r.get("seq"), int):
            return "not_extension", "record %d of the push has no integer seq" % k
        parsed.append((r, record_digest(line.encode())))
    first = parsed[0][0]["seq"]
    if first != last_seq + 1:
        return ("gap", "the push starts at seq %d; the record after the witnessed head is %d" % (first, last_seq + 1))
    for k, (r, _d) in enumerate(parsed):
        if r["seq"] != first + k:
            return "not_extension", "seq %r where %d was expected" % (r["seq"], first + k)
    if parsed[-1][0]["seq"] != seq or parsed[-1][1] != digest:
        return "not_extension", "the last record of the push is not the offered head"
    prev, linked = (last_digest if last_seq else GENESIS), False
    for k, (r, d) in enumerate(parsed):
        if r.get("link") == "v2":
            if r.get("prev_digest") != prev:
                return "not_extension", "record %d does not link to %s" % (r["seq"], "the witnessed head" if (
                    k == 0 and last_seq) else "the record before it")
            if "legacy_prefix_digest" in r and last_seq == 0:
                legacy = b"".join(x.encode() + b"\n" for x in records[:k])
                if r.get("legacy_prefix_digest") != hashlib.sha256(legacy).hexdigest():
                    return "not_extension", "legacy_prefix_digest of record %d does not match" % r["seq"]
            linked = True
        elif last_seq or linked:
            return "not_extension", "record %d is not linked" % r["seq"]
        prev = d
    return None


class _DeadlineReader(io.RawIOBase):
    """Per-read timeout plus an overall request deadline (same as anchord.py; this file runs on its own host)."""

    def __init__(self, sock, io_timeout: float, deadline: float):
        super().__init__()
        self._sock, self._io_timeout, self._deadline = sock, io_timeout, deadline

    def readable(self):
        return True

    def readinto(self, buf):
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("request deadline passed")
        self._sock.settimeout(min(self._io_timeout, left))
        return self._sock.recv_into(buf)
_seen: dict = {}          # seq -> digest
_latest = {"seq": 0, "head_digest": None}


def _load():
    if not os.path.exists(LOG):
        return
    with open(LOG) as fh:
        for line in fh:
            if line.strip():
                h = json.loads(line)
                _seen[h["seq"]] = h["head_digest"]
                if h["seq"] >= _latest["seq"]:
                    _latest.update(seq=h["seq"], head_digest=h["head_digest"])


def _log(path, rec):
    with open(path, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush(); os.fsync(fh.fileno())


class H(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(IO_TIMEOUT_S)
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(
            self.connection, IO_TIMEOUT_S, time.monotonic() + REQUEST_DEADLINE_S))

    def _send(self, code, obj):
        self.connection.settimeout(IO_TIMEOUT_S)
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _read_body(self):
        """(body, None) or (None, (http, message))."""
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            n = -1
        if n < 0:
            return None, (400, "bad content-length")
        if n > MAX_BODY:
            return None, (413, "body too large")
        chunks, got = [], 0
        try:
            while got < n:
                b = self.rfile.read1(min(65536, n - got))
                if not b:
                    break
                chunks.append(b); got += len(b)
        except socket.timeout:
            return None, (408, "request body timed out")
        if got < n:
            return None, (400, "body shorter than content-length")
        return b"".join(chunks), None

    def do_POST(self):
        if self.path != "/head":
            return self._send(405, {"error": "only POST /head exists"})
        raw, err = self._read_body()
        if err:
            self.close_connection = True
            return self._send(err[0], {"error": err[1]})
        if KEY:
            want = hmac.new(KEY, raw, hashlib.sha256).hexdigest()
            sig = self.headers.get("X-HP-Auth", "")
            if not hmac.compare_digest(sig.encode("latin-1", "replace"), want.encode()):
                return self._send(401, {"error": "unauthenticated head refused"})
        try:
            h = json.loads(raw)
            seq, dg = int(h["seq"]), str(h["head_digest"])
        except Exception:
            return self._send(400, {"error": "bad head"})
        with _lock:
            if seq in _seen and _seen[seq] != dg:
                _log(FORKS, {"recv_ts": time.time(), "seq": seq, "witnessed": _seen[seq], "offered": dg})
                return self._send(409, {"error": "fork: a different digest was witnessed for this seq",
                                        "reason": "fork"})
            if seq in _seen:
                return self._send(200, {"ok": True, "seq": seq})
            last, last_dg = _latest["seq"], _latest["head_digest"]
            if seq < last:
                return self._send(409, {"error": "sequence went backwards", "reason": "regression", "latest": last})
            bad = _extension(h.get("records"), seq, dg, last, last_dg)
            if bad and bad[0] == "gap":
                return self._send(409, {"error": "gap: push the records after the witnessed head", "reason": "gap",
                                        "detail": bad[1], "latest": last})
            if bad:
                _log(FORKS, {"recv_ts": time.time(), "seq": seq, "offered": dg, "witnessed_seq": last,
                             "witnessed": last_dg, "problem": bad[1]})
                return self._send(409, {"error": "the head does not extend the witnessed head",
                                        "reason": "not_extension", "detail": bad[1], "latest": last})
            _seen[seq] = dg
            _log(LOG, {"seq": seq, "head_digest": dg, "anchor_recv_ts": h.get("recv_ts"),
                       "witness_recv_ts": time.time(), "extends_seq": last, "records_checked": len(h["records"])})
            _latest.update(seq=seq, head_digest=dg)
        return self._send(200, {"ok": True, "seq": seq})

    def do_GET(self):
        if self.path == "/head":
            with _lock:
                latest = dict(_latest)
            return self._send(200, latest)
        if self.path == "/log":
            with _lock:
                heads = [{"seq": s, "head_digest": d} for s, d in sorted(_seen.items())]
            return self._send(200, {"heads": heads})
        return self._send(404, {"error": "not found"})

    def do_PUT(self):    self._send(405, {"error": "append-only"})
    def do_DELETE(self): self._send(405, {"error": "append-only"})
    def log_message(self, *a): pass


class WitnessServer(socketserver.ThreadingTCPServer):
    daemon_threads = True              # a stalled connection never delays shutdown
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128


def serve(host="0.0.0.0", port=PORT):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    _load()
    with WitnessServer((host, port), H) as s:
        print("READY", port, flush=True)
        s.serve_forever()


if __name__ == "__main__":
    serve()
