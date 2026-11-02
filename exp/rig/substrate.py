"""Container lifecycle and CLEAN-STATE ENFORCEMENT.

STANDING REQUIREMENT, learned the hard way in M2: every end-to-end run must
recreate BOTH the recorder database AND the anchor volume. The anchor is
append-only and therefore DELIBERATELY survives container restarts -- exactly the
property that makes it useful in production and treacherous in a harness. A run
that skips this silently mixes two runs' chains and produces a meaningless
verdict (M2 initially reported FORGERY MISSED for precisely this reason).

Second standing requirement: HA does not attach automation triggers until
EVENT_HOMEASSISTANT_STARTED, measured at ~96s. A harness that acts before that
silently produces a home in which no automation ever fires.
"""
from __future__ import annotations
import json, os, shutil, subprocess, time

IMAGE = "homeassistant/home-assistant:2026.7.4"     # PINNED
NAME = "homeprov-ha"
PORT = 8199

# Pi-shaped cgroup envelope (dec_01M0EAA37PJJFGXHV4V2CPJRAV).
# Absolute latency is NOT claimed as Pi latency; crypto parity on the commit hot
# path (both sides run ARMv8 sha2 on real silicon) is what makes rho transfer.
ENVELOPES = {
    "pi5_4g":  ["--cpus=4", "--memory=4g"],
    "pi5_8g":  ["--cpus=4", "--memory=8g"],
    "pi4_2g":  ["--cpus=4", "--memory=2g"],
    "pi_1core": ["--cpus=1", "--memory=2g"],
}


def _run(a, **k): return subprocess.run(a, capture_output=True, text=True, **k)


def teardown(name=NAME):
    _run(["docker", "rm", "-f", name])


def reset_state(config_dir: str, anchor_volume: str = "hp-anchor",
                name: str = NAME) -> dict:
    """Wipe recorder DB and outputs; recreate the append-only anchor.

    ORDERING IS LOAD-BEARING: the container MUST be torn down before the volume
    is removed. Removing a volume still mounted by a running container wedged
    the Docker daemon on 2026-08-20 and cost a full engine restart.
    """
    teardown(name)
    for suffix in ("", "-wal", "-shm"):
        p = os.path.join(config_dir, "home-assistant_v2.db" + suffix)
        if os.path.exists(p):
            os.remove(p)
    out = os.path.join(config_dir, "homeprov_out")
    if os.path.isdir(out):
        shutil.rmtree(out)
    _run(["docker", "volume", "rm", anchor_volume])
    _run(["docker", "volume", "create", anchor_volume])
    r = _run(["docker", "run", "--rm", "--privileged", "-v", "%s:/anchor" % anchor_volume,
              "alpine:3", "sh", "-c",
              "apk add -q e2fsprogs-extra; : > /anchor/chain; "
              "chattr +a /anchor/chain && lsattr /anchor/chain"])
    return {"db_wiped": True, "anchor_append_only": "-a-" in r.stdout}


def boot(config_dir: str, envelope="pi5_4g", anchor_volume="hp-anchor",
         name=NAME, port=PORT) -> dict:
    teardown(name)
    args = (["docker", "run", "-d", "--name", name] + ENVELOPES[envelope] +
            ["-v", "%s:/config" % os.path.abspath(config_dir),
             "-v", "%s:/anchor" % anchor_volume,
             "-e", "TZ=UTC", "-p", "%d:8123" % port, IMAGE])
    r = _run(args)
    return {"started": r.returncode == 0, "envelope": envelope,
            "image": IMAGE, "error": r.stderr.strip() or None}


def wait_started(name=NAME, timeout=240) -> dict:
    """Block until EVENT_HOMEASSISTANT_STARTED. Do NOT act before this."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        logs = _run(["docker", "logs", name]).stdout
        if "Initialized trigger" in logs or "HOMEPROV S1: begin" in logs:
            return {"started": True, "seconds": round(time.time() - t0, 1)}
        time.sleep(3)
    return {"started": False, "seconds": timeout, "error": "timeout"}


def determinism_check(config_dir: str) -> dict:
    """STAGE-0 GATE. A1's canonical serialization must produce byte-identical
    hashes across two runs at the same seed. If this fails, canonicalization is
    non-deterministic and EVERY commitment result is suspect."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from rig.graph import load
    from rig.commit import commit_full
    db = os.path.join(config_dir, "home-assistant_v2.db")
    if not os.path.exists(db):
        return {"testable": False, "reason": "no recorder database yet"}
    a = commit_full(load(db), "homeprov")
    b = commit_full(load(db), "homeprov")
    return {"testable": True, "byte_identical": a == b}
