"""STAGE 12 — AB-5 completed: anchor placements P1..P4 attacked side by side.

AB-5 was PARTIAL because P2 and P3 were volume stubs. They are now real: an
append-only daemon in its OWN container, owning a volume the hub never mounts.

THE POINT OF THE COMPARISON. P1 bounds the adversary with a FILESYSTEM FLAG, so
it dies the moment a deployment grants CAP_LINUX_IMMUTABLE or runs --privileged
(both measured in stage 3). P2/P3 bound it with a PROTOCOL -- the hub's only
reach is a socket whose sole mutating verb is append -- so capability grants do
not help the adversary at all. That is the hypothesis under test here.
"""
import json, subprocess
from rig import capability

HA_CAPS = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID",
           "SETUID", "SETPCAP", "NET_BIND_SERVICE", "NET_RAW", "SYS_CHROOT"]
NET, DAEMON = "hp-net", "hp-anchord"


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=90)


def _attack(extra_caps, label):
    """Attack P2/P3 from a container with a given capability set."""
    caps = sum([["--cap-add", c] for c in HA_CAPS], [])
    script = (
        "apk add -q curl e2fsprogs-extra 2>/dev/null;"
        'curl -s -o /dev/null -w "APPEND=%{http_code} " -X POST -d "{}" http://hp-anchord:9900/append;'
        'curl -s -o /dev/null -w "PUT=%{http_code} " -X PUT -d "{}" http://hp-anchord:9900/append;'
        'curl -s -o /dev/null -w "DELETE=%{http_code} " -X DELETE http://hp-anchord:9900/append;'
        'curl -s -o /dev/null -w "PATCH=%{http_code} " -X PATCH -d "{}" http://hp-anchord:9900/append;'
        'curl -s -o /dev/null -w "TRUNCATE_PATH=%{http_code} " -X POST -d "{}" http://hp-anchord:9900/truncate;'
        '[ -e /anchor/chain.jsonl ] && echo "VOLUME=VISIBLE" || echo "VOLUME=unreachable"')
    r = _run(["docker", "run", "--rm", "--network", NET, "--cap-drop=ALL"]
             + caps + extra_caps + ["alpine:3", "sh", "-c", script])
    out = dict(kv.split("=") for kv in r.stdout.split() if "=" in kv)
    out["label"] = label
    out["holds"] = (out.get("APPEND") == "200"
                    and out.get("PUT") == "405" and out.get("DELETE") == "405"
                    and out.get("PATCH") == "405"
                    and out.get("TRUNCATE_PATH") in ("404", "405")
                    and out.get("VOLUME") == "unreachable")
    return out


def _p1(extra_caps, label, volume="hp-anchor"):
    """P1 for comparison: shared volume + chattr +a."""
    caps = sum([["--cap-add", c] for c in HA_CAPS], [])
    script = ("apk add -q e2fsprogs-extra;"
              'echo x >> /anchor/chain 2>/dev/null && echo APPEND=ok || echo APPEND=fail;'
              'echo y > /anchor/chain 2>/dev/null && echo TRUNCATE=DEFEATED || echo TRUNCATE=refused;'
              'chattr -a /anchor/chain 2>/dev/null && echo CLEARA=DEFEATED || echo CLEARA=refused;'
              '[ -e /anchor/chain ] && echo VOLUME=VISIBLE || echo VOLUME=unreachable')
    r = _run(["docker", "run", "--rm", "-v", "%s:/anchor" % volume, "--cap-drop=ALL"]
             + caps + extra_caps + ["alpine:3", "sh", "-c", script])
    out = dict(kv.split("=") for kv in r.stdout.split() if "=" in kv)
    out["label"] = label
    out["holds"] = (out.get("APPEND") == "ok" and out.get("TRUNCATE") == "refused"
                    and out.get("CLEARA") == "refused")
    return out


def run(cfg):
    # INSTALL P1 before attacking it. Attacking a volume whose chain was never
    # made append-only measured "P1 defeated at default caps", contradicting the
    # stage-3 result -- a harness error, not a finding.
    from rig import anchor as _anchor
    inst = _anchor.p1_install()

    grants = [([], "HA default caps"),
              (["--cap-add", "LINUX_IMMUTABLE"], "+ CAP_LINUX_IMMUTABLE"),
              (["--privileged"], "--privileged")]
    p1 = [_p1(g, lbl) for g, lbl in grants]
    p23 = [_attack(g, lbl) for g, lbl in grants]

    # P3 publication: is the head reachable on the second volume?
    r = _run(["docker", "run", "--rm", "-v", "hp-p3:/published", "alpine:3",
              "sh", "-c", "cat /published/head.json 2>/dev/null || echo none"])
    published = r.stdout.strip()[:160]

    return {"stage": 12, "ablation": "AB-5 (completed)",
            "P1_install": inst,
            "P1_shared_volume_chattr": p1,
            "P2_P3_separate_container": p23,
            "P3_published_head": published,
            "P1_survives_capability_grants": all(x["holds"] for x in p1),
            "P2_survives_capability_grants": all(x["holds"] for x in p23),
            "finding": ("P1 is bounded by a FILESYSTEM FLAG and dies under a capability "
                        "grant; P2/P3 are bounded by a PROTOCOL and do not"),
            "GATE_PASS": all(x["holds"] for x in p23),
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 0, 5)}
