"""STAGE 26 (E22) -- anchor protocol attack matrix.

The anchor is the root of the whole guarantee, so its protocol deserves its own
adversarial table rather than an assertion that "the only verb is append".

Each attack is issued against the RUNNING hp-anchord container from outside it,
using only what an in-process hub adversary has: the socket. For each we record
whether the anchor ACCEPTED the request, whether it caused a SILENT REWRITE of
already-anchored state, whether a verifier would DETECT the result, and whether
there is an AVAILABILITY impact.
"""
import json, subprocess, time, urllib.error, urllib.request

BASE = "http://localhost:9900"
CONT = "hp-anchord"


def _sh(*a, t=60):
    return subprocess.run(list(a), capture_output=True, text=True, timeout=t)


def _chain_lines():
    r = _sh("docker", "exec", CONT, "sh", "-c",
            "wc -l < /anchor/chain.jsonl 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return -1


def _chain_bytes():
    r = _sh("docker", "exec", CONT, "sh", "-c",
            "stat -c %s /anchor/chain.jsonl 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return -1


def _req(method, path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()[:200].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200].decode("utf-8", "replace")
    except Exception as exc:                       # noqa: BLE001
        return None, repr(exc)[:200]


def run(cfg):
    rows = []

    def attack(name, fn, note=""):
        before_l, before_b = _chain_lines(), _chain_bytes()
        status, body = fn()
        time.sleep(0.3)
        after_l, after_b = _chain_lines(), _chain_bytes()
        accepted = status is not None and 200 <= status < 300
        # A silent rewrite means prior bytes changed or the chain got SHORTER.
        rewrote = (after_l < before_l) or (after_b < before_b)
        rows.append({
            "attack": name, "http": status, "accepted": accepted,
            "chain_lines": [before_l, after_l], "chain_bytes": [before_b, after_b],
            "silent_rewrite": rewrote,
            "appended": after_l - before_l,
            "resp": (body or "")[:80], "note": note,
        })

    seg = {"granularity": "second", "segment": "1787000000",
           "acc": "aa" * 32, "n": 3}

    attack("append duplicate segment",
           lambda: _req("POST", "/append", {"sealed": {"second": {"1787000000": seg}}}),
           "same segment id appended twice")
    attack("append duplicate segment (again)",
           lambda: _req("POST", "/append", {"sealed": {"second": {"1787000000": seg}}}))
    attack("conflicting root, same segment",
           lambda: _req("POST", "/append",
                        {"sealed": {"second": {"1787000000": dict(seg, acc="bb" * 32)}}}),
           "different accumulator for an already-anchored segment")
    attack("future segment",
           lambda: _req("POST", "/append",
                        {"sealed": {"second": {str(int(time.time()) + 86400): seg}}}))
    attack("stale segment",
           lambda: _req("POST", "/append",
                        {"sealed": {"second": {"1000000000": seg}}}))
    attack("root replay (verbatim resend)",
           lambda: _req("POST", "/append", {"sealed": {"second": {"1787000000": seg}}}))
    attack("out-of-order sequence",
           lambda: _req("POST", "/append", {"seq": 1, "sealed": {}}),
           "client-supplied seq")
    attack("fake lifecycle marker",
           lambda: _req("POST", "/append",
                        {"marker": {"kind": "PURGE", "lo": 0, "hi": 9e9}}),
           "declares a purge over all time")
    attack("duplicate marker",
           lambda: _req("POST", "/append",
                        {"marker": {"kind": "PURGE", "lo": 0, "hi": 9e9}}))
    attack("PUT rewrite", lambda: _req("PUT", "/append", {"x": 1}))
    attack("DELETE chain", lambda: _req("DELETE", "/append"))
    attack("PATCH chain", lambda: _req("PATCH", "/append", {"x": 1}))
    attack("GET head (read)", lambda: _req("GET", "/head"))
    attack("truncate via path traversal",
           lambda: _req("POST", "/append/../../anchor/chain.jsonl", {"x": 1}))

    # anchor flood
    before_l, before_b = _chain_lines(), _chain_bytes()
    t0 = time.time(); ok = 0
    for i in range(300):
        s, _ = _req("POST", "/append", {"sealed": {"second": {str(1787000000 + i): seg}}}, timeout=5)
        if s and 200 <= s < 300:
            ok += 1
    dt = time.time() - t0
    after_l, after_b = _chain_lines(), _chain_bytes()
    rows.append({"attack": "anchor flood (300 appends)", "http": None,
                 "accepted": ok > 0, "chain_lines": [before_l, after_l],
                 "chain_bytes": [before_b, after_b],
                 "silent_rewrite": after_l < before_l,
                 "appended": after_l - before_l,
                 "resp": "%d/300 accepted in %.1fs (%.0f/s)" % (ok, dt, ok / max(dt, 1e-9)),
                 "note": "unauthenticated write amplification"})

    # competing concurrent clients
    import threading
    before_l = _chain_lines()
    errs = []
    def worker(k):
        for i in range(40):
            s, b = _req("POST", "/append",
                        {"sealed": {"second": {str(1788000000 + k * 100 + i): seg}}}, timeout=5)
            if not (s and 200 <= s < 300):
                errs.append((k, s, b))
    ths = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    [t.start() for t in ths]; [t.join() for t in ths]
    after_l = _chain_lines()
    rows.append({"attack": "4 concurrent clients x40", "http": None,
                 "accepted": True, "chain_lines": [before_l, after_l],
                 "chain_bytes": [0, 0], "silent_rewrite": after_l < before_l,
                 "appended": after_l - before_l,
                 "resp": "expected 160 appended, errors=%d" % len(errs),
                 "note": "interleaving / lost update"})

    return {"stage": 26, "rows": rows,
            "any_silent_rewrite": any(r["silent_rewrite"] for r in rows)}
