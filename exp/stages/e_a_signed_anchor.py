"""E-A -- authenticated append path + anchor pre-emption, signed vs unsigned.

Reproduces e7_anchor_egress.json (the unauthenticated anchor the review faults:
first_write_wins_selects="adversary") and then measures the fixed system: an
anchor that accepts only monitor-signed appends (HMAC-SHA256 over the body, key
provisioned to the monitor and anchor and to nothing in the hub).

Vantage model: the ANCHOR runs in its own container with its port published to
the host. The ADVERSARY is a host process WITHOUT the key -- it stands for an
in-hub integration that reaches the anchor over the deployment network but never
sees the monitor's secret. The MONITOR is a host process WITH the key.

Everything is loopback + a Docker container; no Home Assistant is needed.
"""
import hashlib, hmac, json, os, subprocess, sys, time
import urllib.error, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rig import capability, stats  # noqa: E402

IMG = "hpr-anchord:sig"
PORT = int(os.environ.get("EA_PORT", "9971"))
BASE = "http://127.0.0.1:%d" % PORT
KEY = os.environ.get("HOMEPROV_ANCHOR_KEY", "hpr-monitor-key-2026-09-08")
SEG = {"granularity": "second", "segment": "1787000000", "acc": "aa" * 32, "n": 3}


def _sh(*a, t=60):
    return subprocess.run(list(a), capture_output=True, text=True, timeout=t)


def _post(path, body, sign_key=None, timeout=5):
    raw = json.dumps(body, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if sign_key is not None:
        headers["X-HP-Auth"] = hmac.new(sign_key.encode(), raw, hashlib.sha256).hexdigest()
    req = urllib.request.Request(BASE + path, data=raw, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()[:200].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200].decode("utf-8", "replace")
    except Exception as exc:                              # noqa: BLE001
        return None, repr(exc)[:120]


def _head():
    try:
        with urllib.request.urlopen(BASE + "/head", timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return {"seq": 0, "head": None}


def _chain_lines(cont):
    r = _sh("docker", "exec", cont, "sh", "-c", "wc -l < /anchor/chain.jsonl 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return -1


def _refusals(cont):
    r = _sh("docker", "exec", cont, "sh", "-c", "wc -l < /anchor/refusals.jsonl 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0


def _start(name, authed):
    _sh("docker", "rm", "-f", name)
    env = ["-e", "PUBLISH_PERIOD=3600"]
    if authed:
        env += ["-e", "HOMEPROV_ANCHOR_KEY=%s" % KEY]
    _sh("docker", "run", "-d", "--name", name, "-p", "%d:9900" % PORT, *env, IMG)
    for _ in range(50):
        if _head().get("seq") is not None and _post("/ping-nope", {}, None)[0] in (200, 404, 405, 401, 400):
            break
        time.sleep(0.2)
    time.sleep(0.5)


def _flood(n, sign_key):
    t0 = time.time(); ok = 0
    for i in range(n):
        s, _ = _post("/append", {"sealed": {"second": {str(1787000000 + i): SEG}}},
                     sign_key=sign_key)
        if s and 200 <= s < 300:
            ok += 1
    return ok, time.time() - t0


def _preempt(adv_key, mon_key):
    """Adversary appends a root for a fresh segment first, then the monitor
    appends its (different) root for the SAME segment. Which one does chain
    verification select under first-write-wins?"""
    seg_id = str(int(time.time()))
    adv = _post("/append", {"sealed": {"second": {seg_id: dict(SEG, acc="ad" * 32)}}},
                sign_key=adv_key)
    mon = _post("/append", {"sealed": {"second": {seg_id: dict(SEG, acc="c0" * 32)}}},
                sign_key=mon_key)
    # Read the chain: which acc is anchored for seg_id (first accepted wins).
    lines = _sh("docker", "exec", CONT, "cat", "/anchor/chain.jsonl").stdout.splitlines()
    anchored = None
    for ln in lines:
        try:
            p = json.loads(ln).get("payload", {})
            v = (p.get("sealed", {}).get("second", {}) or {}).get(seg_id)
            if v and anchored is None:
                anchored = v.get("acc")
        except Exception:
            pass
    selects = ("adversary" if anchored == "ad" * 32 else
               "monitor" if anchored == "c0" * 32 else "neither")
    return {"segment": seg_id, "adversary_http": adv[0], "monitor_http": mon[0],
            "adversary_accepted": bool(adv[0] and 200 <= adv[0] < 300),
            "monitor_accepted": bool(mon[0] and 200 <= mon[0] < 300),
            "anchored_root": anchored, "first_write_wins_selects": selects}


CONT = "hpr-anchord-ea"


def run(cfg=None):
    N = int((cfg or {}).get("n", 300))
    out = {"experiment": "E-A", "what": "authenticated append + pre-emption; "
           "unauthenticated (reproduces e7) vs monitor-signed",
           "n_append_trials": N, "key_scheme": "HMAC-SHA256 (PyNaCl absent; "
           "symmetric key to monitor+anchor only, never the hub)"}

    # ---- PHASE 1: unauthenticated anchor (reproduce e7_anchor_egress) --------
    global CONT
    CONT = "hpr-anchord-ea"
    _start(CONT, authed=False)
    ok_u, dt_u = _flood(N, sign_key=None)
    pre_u = _preempt(adv_key=None, mon_key=None)
    out["unauthenticated"] = {
        "append_rate": {"n": N, "accepted": ok_u, "seconds": round(dt_u, 4),
                        "appends_per_s": round(ok_u / max(dt_u, 1e-9), 1),
                        "authenticated": False},
        "preemption": pre_u,
        "refusals_recorded": _refusals(CONT)}
    _sh("docker", "rm", "-f", CONT)

    # ---- PHASE 2: authenticated anchor (the fix) ----------------------------
    _start(CONT, authed=True)
    # adversary, no key: unsigned and forged-signature appends
    unsigned_ok, unsigned_ref = 0, 0
    for i in range(N):
        s, _ = _post("/append", {"sealed": {"second": {str(1790000000 + i): SEG}}}, sign_key=None)
        if s and 200 <= s < 300:
            unsigned_ok += 1
        elif s == 401:
            unsigned_ref += 1
    forged_ok = forged_ref = 0
    for i in range(N):
        s, _ = _post("/append", {"sealed": {"second": {str(1791000000 + i): SEG}}},
                     sign_key="wrong-key-guess")
        if s and 200 <= s < 300:
            forged_ok += 1
        elif s == 401:
            forged_ref += 1
    # monitor, with key: signed appends accepted; measure signed throughput
    mon_ok, dt_s = _flood(N, sign_key=KEY)
    pre_s = _preempt(adv_key=None, mon_key=KEY)
    refusals = _refusals(CONT)
    out["authenticated"] = {
        "adversary_unsigned": {"n": N, "accepted": unsigned_ok, "refused_401": unsigned_ref},
        "adversary_forged_signature": {"n": N, "accepted": forged_ok, "refused_401": forged_ref},
        "monitor_signed": {"n": N, "accepted": mon_ok, "seconds": round(dt_s, 4),
                           "appends_per_s": round(mon_ok / max(dt_s, 1e-9), 1),
                           "authenticated": True},
        "preemption": pre_s,
        "refusals_recorded": refusals}

    # throughput cost of signing
    r_u = ok_u / max(dt_u, 1e-9)
    r_s = mon_ok / max(dt_s, 1e-9)
    out["throughput_cost_of_signing"] = {
        "unsigned_appends_per_s": round(r_u, 1),
        "signed_appends_per_s": round(r_s, 1),
        "ratio_signed_over_unsigned": round(r_s / r_u, 3),
        "overhead_pct": round((1 - r_s / r_u) * 100, 1)}

    # exact interval on adversary acceptance under the fix (0 of 2N)
    tot_adv = 2 * N
    out["adversary_accept_rate_authenticated"] = stats.clopper_pearson(
        unsigned_ok + forged_ok, tot_adv)

    _sh("docker", "rm", "-f", CONT)

    out["capability"] = capability.record(
        actor_id="in_process_integration", actor_position="in_process_integration",
        seed=0, budget_writes=None, window_s=None,
        knowledge={"anchor_key_known": False, "anchor_reachable_on_network": True},
        constraints={"anchor_key_access": False},
        substrate={"kind": "docker_container_anchor + host_loopback_clients",
                   "anchor_image": IMG,
                   "note": "adversary has network reach to the anchor but not the "
                           "monitor's signing key"},
        mission="E-A signed anchor")
    return out


if __name__ == "__main__":
    r = run()
    dig = capability.stamp(r, os.path.join(os.path.dirname(__file__), "..", "out",
                                           "e7b_anchor_signed.json"))
    print(json.dumps(r, indent=2, default=str))
    print("digest", dig)
