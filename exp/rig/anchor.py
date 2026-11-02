"""A3 ANCHOR — placements P1-P4, compared rather than assumed.

MEASURED IN M2, overturning the design's own prediction. The project record
expected P1 to be "defeated by root". That conflated root with root holding
CAP_LINUX_IMMUTABLE. Home Assistant's container is uid 0 but CapEff=0xa80425fb
(Docker's default set), which DROPS CAP_LINUX_IMMUTABLE. Attacked from a
container with HA's exact capabilities:
    APPEND allowed | TRUNCATE refused | DELETE refused
    CLEAR +a refused | IN-PLACE EDIT refused        -> ANCHOR HOLDS
"""
from __future__ import annotations
import json, os, subprocess, time

ANCHOR_VOLUME = "hp-anchor"
CHAIN = "/anchor/chain"

# HA's measured capability set -- an attacker container is configured with
# exactly these, so the adversarial test is faithful rather than generous.
HA_CAPS = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID",
           "SETUID", "SETPCAP", "NET_BIND_SERVICE", "NET_RAW", "SYS_CHROOT"]


def _run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def p1_install(volume: str = ANCHOR_VOLUME) -> dict:
    """One-time PRIVILEGED install step: create the chain and set it append-only.
    This is a deployment requirement (HA add-ons may request capability), not an
    impossibility -- but it IS real adoption friction, and M4 must address it."""
    _run(["docker", "volume", "rm", volume])
    _run(["docker", "volume", "create", volume])
    r = _run(["docker", "run", "--rm", "--privileged", "-v", "%s:/anchor" % volume,
              "alpine:3", "sh", "-c",
              "apk add -q e2fsprogs-extra; : > /anchor/chain; "
              "chattr +a /anchor/chain && lsattr /anchor/chain"])
    return {"placement": "P1", "ok": "-a-" in r.stdout, "detail": r.stdout.strip()}


def p1_attack(volume: str = ANCHOR_VOLUME) -> dict:
    """Adversarial test with HA's EXACT capability set. Append must succeed;
    every rewrite path must fail."""
    caps = sum([["--cap-add", c] for c in HA_CAPS], [])
    script = (
        "apk add -q e2fsprogs-extra;"
        'echo legit >> /anchor/chain && echo APPEND=ok || echo APPEND=fail;'
        'echo x > /anchor/chain 2>/dev/null && echo TRUNCATE=DEFEATED || echo TRUNCATE=refused;'
        'rm -f /anchor/chain 2>/dev/null && echo DELETE=DEFEATED || echo DELETE=refused;'
        'chattr -a /anchor/chain 2>/dev/null && echo CLEARA=DEFEATED || echo CLEARA=refused;'
        'sed -i "1s/.*/t/" /anchor/chain 2>/dev/null && echo EDIT=DEFEATED || echo EDIT=refused')
    r = _run(["docker", "run", "--rm", "-v", "%s:/anchor" % volume,
              "--cap-drop=ALL"] + caps + ["alpine:3", "sh", "-c", script])
    res = dict(kv.split("=") for kv in r.stdout.split() if "=" in kv)
    res["holds"] = (res.get("APPEND") == "ok" and
                    all(res.get(k) == "refused" for k in
                        ("TRUNCATE", "DELETE", "CLEARA", "EDIT")))
    return {"placement": "P1", **res}


def p1_sensitivity(volume: str = ANCHOR_VOLUME) -> dict:
    """The honest boundary: the defense is CONTINGENT on the capability set.
    Some real HA deployments run privileged for USB/Bluetooth passthrough."""
    out = {}
    for label, extra in (("cap_linux_immutable", ["--cap-add", "LINUX_IMMUTABLE"]),
                         ("privileged", ["--privileged"])):
        r = _run(["docker", "run", "--rm", "-v", "%s:/anchor" % volume] + extra +
                 ["alpine:3", "sh", "-c",
                  "apk add -q e2fsprogs-extra; chattr -a /anchor/chain 2>/dev/null "
                  "&& echo DEFEATED || echo refused"])
        out[label] = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "?"
    return {"placement": "P1", "sensitivity": out}


def p2_install(volume: str = "hp-anchor-p2") -> dict:
    """Separate container holding the chain head. NOTE: uid separation INSIDE
    the HA container is meaningless -- HA runs as root. The real boundary is the
    container, which is also how HA OS already runs add-ons."""
    _run(["docker", "volume", "rm", volume]); _run(["docker", "volume", "create", volume])
    return {"placement": "P2", "ok": True, "volume": volume,
            "note": "isolation is the container namespace, not uid"}


def p3_install(volume: str = "hp-anchor-p3") -> dict:
    """Periodic anchoring to a SEPARATE LOCAL container + volume.
    RE-SCOPED by dec_01M0EE5RQP5E2HETFZWPZQT7H7: off-box publication to a phone,
    second device or external service is NOT built and NOT evaluated."""
    _run(["docker", "volume", "rm", volume]); _run(["docker", "volume", "create", volume])
    return {"placement": "P3", "ok": True, "volume": volume, "scope": "local-only"}


def p4_probe(container: str = "homeprov-ha") -> dict:
    """P4 eBPF/kernel-resident state (from Nitro, CCS 2025). DEMOTED to a note:
    CAP_BPF is NOT held by the HA container, so it needs a privileged add-on --
    and P1 achieves the same isolation far more cheaply. The same measurement
    means the ADVERSARY cannot use eBPF either."""
    r = _run(["docker", "exec", container, "sh", "-c", "grep CapEff /proc/self/status"])
    try:
        v = int(r.stdout.split()[1], 16)
    except Exception:
        return {"placement": "P4", "available": None, "error": r.stderr.strip()}
    return {"placement": "P4", "cap_bpf": bool(v & (1 << 38)),
            "cap_sys_admin": bool(v & (1 << 21)),
            "available": bool(v & (1 << 38)),
            "note": "adversary equally lacks CAP_BPF"}


def read_chain(container: str = "homeprov-ha") -> list[dict]:
    r = _run(["docker", "exec", container, "cat", CHAIN])
    return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]


def detection_window(chain: list[dict], event_ts: float) -> float | None:
    """W(alpha) = t_anchor(alpha) - t(alpha). Forgery inside W is undetectable at
    this placement's granularity. E[W] = 1/(2f) for periodic anchoring.
    W IS A RESULT, NOT A LIMITATION TO BURY -- it tells a deployer what they buy."""
    after = [c["r"]["ts"] for c in chain if c["r"]["ts"] >= event_ts]
    return (min(after) - event_ts) if after else None
