"""R7 client (runs inside a container on the anchor's network): replay a saved monitor chain into anchor daemons and
time every authenticated append.

Reads the payloads of records 2..N of a saved anchor chain (steady-state monitor ticks; record 1 is the start-up record
that seals the whole preceding hour), and for each payload, in an order rotated per record so no daemon is always first,
POSTs it to every target anchor (HMAC-tagged as the monitor does) and records the round-trip time. Prints one JSON line
per append and a final summary line.

usage: r7_head_witness_client.py CHAIN KEY name=url [name=url ...]
"""
import hashlib, hmac, json, sys, time, urllib.request

chain, key = sys.argv[1], sys.argv[2].encode()
targets = [a.split("=", 1) for a in sys.argv[3:]]
payloads = [json.loads(l)["payload"] for l in open(chain) if l.strip()][1:]
for i, p in enumerate(payloads):
    p = dict(p, ts=time.time())
    body = json.dumps(p, sort_keys=True).encode()
    hdr = {"Content-Type": "application/json", "X-HP-Auth": hmac.new(key, body, hashlib.sha256).hexdigest()}
    order = targets[i % len(targets):] + targets[:i % len(targets)]
    for name, url in order:
        t = time.perf_counter()
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=hdr, method="POST"), timeout=30) as r:
            out = json.loads(r.read())
        ms = (time.perf_counter() - t) * 1000.0
        print(json.dumps({"i": i, "target": name, "ms": round(ms, 3), "ok": out.get("ok"), "seq": out.get("seq"),
                          "body_bytes": len(body),
                          "witness_ms": (out.get("witness_push") or {}).get("ms"),
                          "witness_ok": (out.get("witness_push") or {}).get("ok")}), flush=True)
    time.sleep(0.05)
print(json.dumps({"done": True, "records": len(payloads)}), flush=True)
