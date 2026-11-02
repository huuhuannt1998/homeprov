"""P2/P3 anchor daemon — append-only commitment store in its OWN container.

THE ISOLATION ARGUMENT, and why it differs from P1:
  P1 (chattr +a) shares a VOLUME with the hub and relies on the hub lacking
  CAP_LINUX_IMMUTABLE. It is defeated the moment a deployment grants that
  capability or runs --privileged, both measured.
  P2 shares NO filesystem at all. The chain lives on a volume the hub never
  mounts, in a container the hub cannot enter. The hub's only reach is this
  socket, and the socket implements EXACTLY ONE verb: append.
  There is no truncate, no delete, no rewrite, no read-modify-write. Capability
  is bounded by the PROTOCOL, not by a filesystem flag -- so granting the hub
  CAP_LINUX_IMMUTABLE or --privileged changes nothing.

P3 is P2 plus periodic publication of the chain head to a second local volume,
buying a detection window bounded by the publication period. Per
dec_01M0EE5RQP5E2HETFZWPZQT7H7 the off-box variant is NOT built and NOT
evaluated -- named as a deployment option only.

SERVING HARDENED (2026-10-08, round 13, E7 "anchor stall"). The daemon every
run up to E5 used (kept byte-identical as anchord_r12.py, sha256 7b1ef9f1...)
served on a single-threaded socketserver.TCPServer and read each request body
with rfile.read(Content-Length), with no timeout, before checking the tag. One
client that opened a connection and sent a partial request, or nothing, held
the only serving thread and blocked every append from the monitor for as long
as it kept the connection open; the hub process can reach this socket, so code
in the hub could stall the anchor. This version changes how requests are served
and nothing else: the verb, the paths, the status codes and replies, the record
format and the refusal records are those of the earlier daemon, so earlier
chains and the verifiers are unaffected.
  - One thread per connection (AnchorServer: socketserver.ThreadingMixIn over
    TCPServer). A slow client holds only its own thread.
  - Every socket read and write times out after HOMEPROV_ANCHOR_IO_TIMEOUT_S
    (default 5 s), and the request line, the headers and the body must all
    arrive within HOMEPROV_ANCHOR_REQUEST_DEADLINE_S (default 10 s) of the
    accept, so a client that trickles bytes is cut off as well. A body that
    does not arrive in time is refused (408) and recorded.
  - A declared body longer than HOMEPROV_ANCHOR_MAX_BODY bytes (default 16 MiB)
    is refused (413) and recorded without being read. A Content-Length that is
    not a non-negative integer is refused (400), where the earlier daemon raised
    (not an integer) or read until the client closed (negative); a body that
    ends before its Content-Length is refused (400).
  - The HMAC tag is checked over the exact body before the body is parsed, as
    before. A tag with non-ASCII characters is refused as bad_signature (401),
    where the earlier daemon raised; a body that is JSON but not an object is
    refused as bad_json (400), where the earlier daemon raised.
  - The first-write-wins check and the append run as one critical section under
    the chain lock, so concurrent appends are written one at a time with
    consecutive sequence numbers and two concurrent appends can never both pass
    the conflict check. GET /head and the publisher read the chain under the
    same lock. Refusal records use their own lock, so a flood of refused
    requests never delays an append.

OPERATOR KEY AND TAGGED REPLIES (2026-10-08, round 13, E8 items A3 and A4).
  - A3. With HOMEPROV_OPERATOR_KEY set (hex, as the operator's key file holds
    it; it must differ from the append key), a lifecycle-marker record (a
    payload with a top-level "marker" field, as rig.marker_issuer writes it) is
    accepted only when its X-HP-Auth tag verifies under the operator key AND
    its marker_tag (HMAC-SHA256 over the marker's sort_keys JSON) verifies under
    the operator key. A marker tagged with the append key is refused (403,
    marker_needs_operator_key), and so is a non-marker record tagged with the
    operator key (403, operator_key_for_markers_only) and an operator marker
    whose marker_tag does not verify (403, bad_marker_tag); each is recorded.
    Untagged and forged requests are still 401. Unset (the default), markers
    are accepted under the append key exactly as before.
  - A4. Every reply carries X-HP-Reply-Auth = hex HMAC-SHA256 under the key
    that authenticated the request (the operator key for an operator request,
    otherwise the append key; no header when neither is configured) over
        b"homeprov-anchor-reply-v1\n" + request's X-HP-Auth value (latin-1
        bytes, empty if absent) + b"\n" + decimal status code + b"\n" +
        the exact reply body,
    so a client holding the key detects a spoofed or altered reply (reply_tag()
    and reply_ok() below; E8_ANCHOR_NOTES.md has the client rule).
The record format, the 401/409/413 replies and their refusal records are
unchanged; the reply gains one header.

CHAIN STATE IN MEMORY (2026-10-09, round 13, before E9). Every append used to
read the whole chain file (to count its lines, and in anchord_linked.py to find
the last line, and again for each head-witness push), and so did every GET /head
and every publication. A full-history first poll of an E9 monitor starts the
chain at about 185 MB (exp/out/e9_direct_read_identity.json), so at one append
per poll this read would dominate the run. The daemon now scans the file once,
at the first use, and keeps in memory the offsets of its lines, its size, the
line count and the last line; an accepted append writes and fsyncs its line
first, exactly as before, and only then updates that state. Before each use the
state is checked against the file (its size, and the bytes of the last line read
from their offset): a file changed by anything else (a rewrite at rest, a
restore) is scanned again, so the daemon appends to the file as it is on disk,
as before; an append whose write fails drops the state, and the next call scans
the file. A restarted daemon scans it once. The first-root index (_roots) was
already in memory. Answers, records and publications are those of the earlier
daemon (kept byte for byte as anchord_e8.py; anchord_linked_e8.py for the linked
entry point); test_anchor_cache.py compares them, also across a restart.
"""
import hashlib, hmac, http.server, io, json, os, socket, socketserver, sys, threading, time

CHAIN = "/anchor/chain.jsonl"
REFUSALS = "/anchor/refusals.jsonl"
PUBLISH = "/published/head.json"
PUBLISH_PERIOD = float(os.environ.get("PUBLISH_PERIOD", "5"))
# The chain lock guards the chain file and the first-write-wins state. It is
# re-entrant because anchord_linked.py's _append takes it again inside the
# critical section the handler holds.
_lock = threading.RLock()
_refusal_lock = threading.Lock()


def _positive(name: str, default, kind=float):
    raw = os.environ.get(name, "").strip()
    try:
        value = kind(raw) if raw else kind(default)
    except ValueError:
        raise SystemExit("%s must be a positive %s, got %r" % (name, kind.__name__, raw))
    if value <= 0:
        raise SystemExit("%s must be positive, got %r" % (name, raw))
    return value


# SERVING LIMITS (see the module docstring). A slow client can hold one
# connection for at most REQUEST_DEADLINE_S before its request is complete.
IO_TIMEOUT_S = _positive("HOMEPROV_ANCHOR_IO_TIMEOUT_S", 5.0)
REQUEST_DEADLINE_S = _positive("HOMEPROV_ANCHOR_REQUEST_DEADLINE_S", 10.0)
MAX_BODY = _positive("HOMEPROV_ANCHOR_MAX_BODY", 16 * 1024 * 1024, int)

# AUTHENTICATED APPEND PATH (review 4a).
#
# The pre-emption result (e7_anchor_egress.json: first_write_wins_selects =
# "adversary") holds ONLY because any party reaching the socket can append. The
# monitor is trusted and lives OUTSIDE the hub, so it can hold a secret the hub
# process never sees. HOMEPROV_ANCHOR_KEY is provisioned to the monitor and the
# anchor containers and to nothing else. When it is set the anchor accepts a
# POST /append only if it carries a valid HMAC-SHA256 over the exact request
# body; unsigned or forged appends are refused (401) and RECORDED. When the key
# is empty the daemon is unauthenticated exactly as before, so e7 can be
# reproduced. HMAC rather than Ed25519 because PyNaCl is absent on this host and
# the key is symmetric between two trusted endpoints; the guarantee is identical
# for the single-monitor deployment the paper evaluates.
KEY = os.environ.get("HOMEPROV_ANCHOR_KEY", "").encode()


def _operator_key() -> bytes:
    raw = os.environ.get("HOMEPROV_OPERATOR_KEY", "").strip()
    if not raw:
        return b""
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise SystemExit("HOMEPROV_OPERATOR_KEY must be hex (the content of the operator's key file)")
    if len(key) < 16:
        raise SystemExit("HOMEPROV_OPERATOR_KEY must hold at least 16 bytes")
    if key == KEY or raw.encode() == KEY:
        raise SystemExit("HOMEPROV_OPERATOR_KEY must differ from HOMEPROV_ANCHOR_KEY")
    return key


# OPERATOR KEY (E8 A3): lifecycle markers excuse violations, so only the
# operator, not the holder of the monitor's append key, may anchor them.
OPERATOR_KEY = _operator_key()

# TAGGED REPLIES (E8 A4).
REPLY_HEADER = "X-HP-Reply-Auth"
REPLY_TAG_DOMAIN = b"homeprov-anchor-reply-v1\n"


def reply_tag(key: bytes, request_tag: str, status: int, body: bytes) -> str:
    """The X-HP-Reply-Auth value for a reply with this status and exact body to a
    request that carried request_tag in X-HP-Auth ("" if it carried none)."""
    msg = (REPLY_TAG_DOMAIN + (request_tag or "").encode("latin-1", "replace") + b"\n"
           + str(int(status)).encode() + b"\n" + body)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def reply_ok(key: bytes, request_tag: str, status: int, body: bytes, header_value) -> bool:
    """Client side: does a reply's X-HP-Reply-Auth verify? Missing counts as no."""
    if not header_value:
        return False
    want = reply_tag(key, request_tag, status, body)
    return hmac.compare_digest(str(header_value).encode("latin-1", "replace"), want.encode())

# FIRST-WRITE-WINS, made real. Once a (granularity, segment) has an anchored
# root, a DIFFERENT root for that same segment is a conflict and is refused even
# if signed (defence in depth: a monitor bug cannot silently fork history).
_roots: dict = {}
_refusal_seq = [0]


def _refuse(reason: str, http_code: int, body: bytes, extra=None) -> None:
    with _refusal_lock:
        _refusal_seq[0] += 1
        rec = {"refusal_seq": _refusal_seq[0], "recv_ts": time.time(),
               "reason": reason, "http": http_code,
               "body_sha256": hashlib.sha256(body or b"").hexdigest(),
               "body_len": len(body or b"")}
        if extra:
            rec.update(extra)
        try:
            with open(REFUSALS, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush(); os.fsync(fh.fileno())
        except Exception:
            pass


def _authenticate(body: bytes, headers) -> tuple:
    """(ok, reason). No key configured -> unauthenticated pass-through."""
    if not KEY:
        return True, "unauthenticated"
    sig = headers.get("X-HP-Auth", "")
    if not sig:
        return False, "missing_signature"
    want = hmac.new(KEY, body, hashlib.sha256).hexdigest()
    # Compared as bytes: a str comparison raises on non-ASCII input.
    if not hmac.compare_digest(sig.encode("latin-1", "replace"), want.encode()):
        return False, "bad_signature"
    return True, "ok"


def _is_operator(body: bytes, headers) -> bool:
    """Does the request's tag verify under the operator key?"""
    if not OPERATOR_KEY:
        return False
    sig = headers.get("X-HP-Auth", "")
    if not sig:
        return False
    want = hmac.new(OPERATOR_KEY, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig.encode("latin-1", "replace"), want.encode())


def _authorize(rec: dict, operator: bool):
    """None, or the reason an authenticated record is refused (403). Only with an
    operator key configured: markers need it, and it serves markers only."""
    if not OPERATOR_KEY:
        return None
    marker = "marker" in rec
    if operator and not marker:
        return "operator_key_for_markers_only"
    if marker and not operator:
        return "marker_needs_operator_key"
    if marker:
        want = hmac.new(OPERATOR_KEY, json.dumps(rec["marker"], sort_keys=True).encode(),
                        hashlib.sha256).hexdigest()
        got = str(rec.get("marker_tag") or "").encode("latin-1", "replace")
        if not hmac.compare_digest(got, want.encode()):
            return "bad_marker_tag"
    return None


def _conflicts(rec: dict) -> tuple:
    """(is_conflict, detail). A signed append whose sealed roots disagree with an
    already-anchored segment is refused. New or identical roots are fine.
    The caller holds _lock."""
    sealed = rec.get("sealed") or {}
    if not isinstance(sealed, dict):
        return False, None
    for gran, segs in sealed.items():
        if not isinstance(segs, dict):
            continue
        for seg, v in segs.items():
            acc = (v or {}).get("acc") if isinstance(v, dict) else None
            key = (gran, str(seg))
            if key in _roots and _roots[key] != acc:
                return True, {"granularity": gran, "segment": str(seg),
                              "anchored_acc": _roots[key], "offered_acc": acc}
    return False, None


def _record_roots(rec: dict) -> None:
    for gran, segs in (rec.get("sealed") or {}).items():
        if not isinstance(segs, dict):
            continue
        for seg, v in segs.items():
            acc = (v or {}).get("acc") if isinstance(v, dict) else None
            _roots[(gran, str(seg))] = acc


# CHAIN STATE IN MEMORY (see the module docstring). _chain["state"] is None or
# {"path", "size", "n_all", "offs", "last", "last_v2"}: the chain file's size in
# bytes, its line count as `for line in fh` counts it (what this module's append
# numbers from), the (start, end) byte offsets of its non-empty lines (newline
# excluded), the last non-empty line's bytes, and whether that line is linked.
# Read and changed only under _lock.
_chain = {"state": None, "scans": 0}


def _chain_scan(path: str) -> dict:
    offs, n_all, pos, last = [], 0, 0, None
    if os.path.exists(path):
        with open(path, "rb") as fh:
            for line in fh:
                n_all += 1
                if line.strip():
                    body = line.rstrip(b"\n")
                    offs.append((pos, pos + len(body)))
                    last = body
                pos += len(line)
    _chain["scans"] += 1
    return {"path": path, "size": pos, "n_all": n_all, "offs": offs, "last": last,
            "last_v2": last is not None and json.loads(last).get("link") == "v2"}


def _chain_read(path: str, start: int, end: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(start)
        return fh.read(end - start)


def _chain_state() -> dict:
    """The chain's state, checked against the file (path, size, last line); scanned again when it differs."""
    c = _chain["state"]
    if c is not None:
        try:
            size = os.path.getsize(CHAIN) if os.path.exists(CHAIN) else 0
            same = c["path"] == CHAIN and size == c["size"] and (
                not c["offs"] or _chain_read(CHAIN, *c["offs"][-1]) == c["last"])
        except OSError:
            same = False
        if same:
            return c
    c = _chain["state"] = _chain_scan(CHAIN)
    return c


def _chain_append_line(line: str, link_v2=None) -> None:
    """Write one record line (O_APPEND, flushed and fsynced before anyone is answered), then update the state."""
    c = _chain_state()
    try:
        with open(CHAIN, "a") as fh:           # O_APPEND, the only write path
            fh.write(line + "\n")
            fh.flush(); os.fsync(fh.fileno())
    except BaseException:
        _chain["state"] = None                 # whatever reached the file is scanned at the next call
        raise
    b = line.encode()
    c["offs"].append((c["size"], c["size"] + len(b)))
    c["size"] += len(b) + 1
    c["n_all"] += 1
    c["last"] = b
    c["last_v2"] = json.loads(line).get("link") == "v2" if link_v2 is None else bool(link_v2)


def _chain_lines(lo: int, hi: int) -> list:
    """Non-empty records lo..hi (1-based, inclusive) as written, without the newline (str)."""
    with _lock:
        c = _chain_state()
        sel = c["offs"][max(lo, 1) - 1:hi]
        if not sel:
            return []
        blob = _chain_read(CHAIN, sel[0][0], sel[-1][1])
        base = sel[0][0]
        return [blob[a - base:b - base].decode() for a, b in sel]


def _append(rec: dict) -> dict:
    with _lock:
        seq = _chain_state()["n_all"]
        _record_roots(rec)
        rec = {"seq": seq + 1, "recv_ts": time.time(), "payload": rec}
        _chain_append_line(json.dumps(rec, sort_keys=True), link_v2=False)
    return {"ok": True, "seq": rec["seq"]}


def _admit(rec: dict) -> tuple:
    """(reply, conflict_detail). The first-write-wins check and the append form
    one critical section. _append is looked up at call time, so the linked
    daemon's replacement applies."""
    with _lock:
        conflict, detail = _conflicts(rec)
        if conflict:
            return None, detail
        return _append(rec), None


def _head() -> dict:
    if not os.path.exists(CHAIN):
        return {"seq": 0, "head": None}
    with _lock:
        c = _chain_state()
        return {"seq": len(c["offs"]), "head": json.loads(c["last"]) if c["last"] else None}


class _DeadlineReader(io.RawIOBase):
    """Reads the connection with a per-read timeout and an overall deadline.

    Each read waits at most min(IO_TIMEOUT_S, time left before the deadline), so
    a client that sends nothing is cut off after IO_TIMEOUT_S and one that
    trickles bytes is cut off at the deadline. Expiry raises socket.timeout,
    which BaseHTTPRequestHandler turns into a closed connection while it reads
    the request line and headers, and which do_POST refuses while it reads the
    body."""

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


class H(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self._reply_key = None             # set to the operator key for an operator request
        self.connection.settimeout(IO_TIMEOUT_S)
        self.rfile.close()                 # release the plain reader's reference to the socket
        self.rfile = io.BufferedReader(_DeadlineReader(
            self.connection, IO_TIMEOUT_S, time.monotonic() + REQUEST_DEADLINE_S))

    def _send(self, code, obj):
        self.connection.settimeout(IO_TIMEOUT_S)   # the reader may have shortened it
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        key = getattr(self, "_reply_key", None) or KEY
        if key:
            hdrs = getattr(self, "headers", None)
            self.send_header(REPLY_HEADER, reply_tag(key, hdrs.get("X-HP-Auth", "") if hdrs else "", code, b))
        self.end_headers(); self.wfile.write(b)

    def _read_body(self) -> tuple:
        """(body, refusal). refusal is None or (reason, http, message, extra)."""
        declared = self.headers.get("Content-Length", 0)
        try:
            n = int(declared)
        except (TypeError, ValueError):
            n = -1
        if n < 0:
            return b"", ("bad_content_length", 400, "bad content-length",
                         {"content_length": str(declared)[:64]})
        if n > MAX_BODY:
            return b"", ("body_too_large", 413, "body too large",
                         {"declared_length": n, "max_body": MAX_BODY})
        chunks, got = [], 0
        try:
            while got < n:
                b = self.rfile.read1(min(65536, n - got))
                if not b:
                    break
                chunks.append(b); got += len(b)
        except socket.timeout:
            return b"".join(chunks), ("body_timeout", 408, "request body timed out",
                                      {"declared_length": n})
        body = b"".join(chunks)
        if got < n:
            return body, ("short_body", 400, "body shorter than content-length",
                          {"declared_length": n})
        return body, None

    def do_POST(self):
        # THE ONLY MUTATING VERB. No path parameter selects a different action.
        if self.path != "/append":
            return self._send(405, {"error": "only POST /append exists"})
        raw, refusal = self._read_body()
        if refusal:
            reason, code, message, extra = refusal
            _refuse(reason, code, raw, extra)
            self.close_connection = True
            return self._send(code, {"error": message, "reason": reason})
        ok, why = _authenticate(raw, self.headers)
        operator = _is_operator(raw, self.headers)
        if operator:
            self._reply_key = OPERATOR_KEY
        if not ok and not operator:
            _refuse(why, 401, raw)
            return self._send(401, {"error": "unauthenticated append refused",
                                    "reason": why})
        try:
            rec = json.loads(raw or b"{}")
        except Exception:
            _refuse("bad_json", 400, raw)
            return self._send(400, {"error": "bad json"})
        if not isinstance(rec, dict):
            _refuse("bad_json", 400, raw)
            return self._send(400, {"error": "bad json"})
        denied = _authorize(rec, operator)
        if denied:
            _refuse(denied, 403, raw)
            return self._send(403, {"error": "append refused for this key", "reason": denied})
        reply, detail = _admit(rec)
        if reply is None:
            _refuse("conflicting_root", 409, raw, {"conflict": detail})
            return self._send(409, {"error": "first-write-wins: conflicting root",
                                    "conflict": detail})
        self._send(200, reply)

    def do_GET(self):
        if self.path == "/head":
            with _lock:
                head = _head()
            return self._send(200, head)
        return self._send(404, {"error": "not found"})

    # every other verb is refused outright
    def do_PUT(self):    self._send(405, {"error": "append-only store"})
    def do_DELETE(self): self._send(405, {"error": "append-only store"})
    def do_PATCH(self):  self._send(405, {"error": "append-only store"})
    def log_message(self, *a): pass


class AnchorServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """One thread per connection; a stalled connection never delays another or shutdown."""
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, request, client_address):
        # A client that resets or abandons its connection is not an error of the
        # daemon; anything else keeps the standard traceback on stderr.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


def _publisher():
    """P3: periodically publish the head to a SECOND local volume."""
    while True:
        try:
            with _lock:
                h = _head()
            if h["seq"]:
                os.makedirs(os.path.dirname(PUBLISH), exist_ok=True)
                with open(PUBLISH, "w") as fh:
                    json.dump({"published_ts": time.time(), **h}, fh)
        except Exception:
            pass
        time.sleep(PUBLISH_PERIOD)


def _rebuild_roots() -> None:
    """Repopulate first-write-wins state from the existing chain on restart."""
    if not os.path.exists(CHAIN):
        return
    with open(CHAIN) as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                _record_roots(json.loads(line).get("payload", {}))
            except Exception:
                pass


def serve(host: str = "0.0.0.0", port: int = 9900) -> None:
    os.makedirs(os.path.dirname(CHAIN), exist_ok=True)
    _rebuild_roots()
    threading.Thread(target=_publisher, daemon=True).start()
    with AnchorServer((host, port), H) as s:
        s.serve_forever()


if __name__ == "__main__":
    serve()
