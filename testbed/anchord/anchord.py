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
import http.server, json, os, socketserver, threading, time

CHAIN = "/anchor/chain.jsonl"
PUBLISH = "/published/head.json"
PUBLISH_PERIOD = float(os.environ.get("PUBLISH_PERIOD", "5"))
_lock = threading.Lock()


def _append(rec: dict) -> dict:
    with _lock:
        seq = 0
        if os.path.exists(CHAIN):
            with open(CHAIN, "rb") as fh:
                seq = sum(1 for _ in fh)
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
        try:
            rec = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad json"})
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


if __name__ == "__main__":
    os.makedirs("/anchor", exist_ok=True)
    threading.Thread(target=_publisher, daemon=True).start()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", 9900), H) as s:
        s.serve_forever()
