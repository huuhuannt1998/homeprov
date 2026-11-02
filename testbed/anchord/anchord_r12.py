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
"""
import hashlib, hmac, http.server, json, os, socketserver, threading, time

CHAIN = "/anchor/chain.jsonl"
REFUSALS = "/anchor/refusals.jsonl"
PUBLISH = "/published/head.json"
PUBLISH_PERIOD = float(os.environ.get("PUBLISH_PERIOD", "5"))
_lock = threading.Lock()

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

# FIRST-WRITE-WINS, made real. Once a (granularity, segment) has an anchored
# root, a DIFFERENT root for that same segment is a conflict and is refused even
# if signed (defence in depth: a monitor bug cannot silently fork history).
_roots: dict = {}
_refusal_seq = [0]


def _refuse(reason: str, http_code: int, body: bytes, extra=None) -> None:
    with _lock:
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
    if not hmac.compare_digest(sig, want):
        return False, "bad_signature"
    return True, "ok"


def _conflicts(rec: dict) -> tuple:
    """(is_conflict, detail). A signed append whose sealed roots disagree with an
    already-anchored segment is refused. New or identical roots are fine."""
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


def _append(rec: dict) -> dict:
    with _lock:
        seq = 0
        if os.path.exists(CHAIN):
            with open(CHAIN, "rb") as fh:
                seq = sum(1 for _ in fh)
        _record_roots(rec)
        rec = {"seq": seq + 1, "recv_ts": time.time(), "payload": rec}
        with open(CHAIN, "a") as fh:           # O_APPEND, the only write path
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush(); os.fsync(fh.fileno())
    return {"ok": True, "seq": rec["seq"]}


def _head() -> dict:
    if not os.path.exists(CHAIN):
        return {"seq": 0, "head": None}
    last, n = None, 0
    with open(CHAIN) as fh:
        for line in fh:
            if line.strip():
                last = line; n += 1
    return {"seq": n, "head": json.loads(last) if last else None}


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        # THE ONLY MUTATING VERB. No path parameter selects a different action.
        if self.path != "/append":
            return self._send(405, {"error": "only POST /append exists"})
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        ok, why = _authenticate(raw, self.headers)
        if not ok:
            _refuse(why, 401, raw)
            return self._send(401, {"error": "unauthenticated append refused",
                                    "reason": why})
        try:
            rec = json.loads(raw or b"{}")
        except Exception:
            _refuse("bad_json", 400, raw)
            return self._send(400, {"error": "bad json"})
        conflict, detail = _conflicts(rec)
        if conflict:
            _refuse("conflicting_root", 409, raw, {"conflict": detail})
            return self._send(409, {"error": "first-write-wins: conflicting root",
                                    "conflict": detail})
        self._send(200, _append(rec))

    def do_GET(self):
        if self.path == "/head":
            return self._send(200, _head())
        return self._send(404, {"error": "not found"})

    # every other verb is refused outright
    def do_PUT(self):    self._send(405, {"error": "append-only store"})
    def do_DELETE(self): self._send(405, {"error": "append-only store"})
    def do_PATCH(self):  self._send(405, {"error": "append-only store"})
    def log_message(self, *a): pass


def _publisher():
    """P3: periodically publish the head to a SECOND local volume."""
    while True:
        try:
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


if __name__ == "__main__":
    os.makedirs("/anchor", exist_ok=True)
    _rebuild_roots()
    threading.Thread(target=_publisher, daemon=True).start()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", 9900), H) as s:
        s.serve_forever()
