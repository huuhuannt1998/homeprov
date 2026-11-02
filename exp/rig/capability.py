"""The machine-readable capability record, shipped with EVERY result.

ANYTHING NOT IN THE RECORD WAS NOT ASSUMED. A reviewer should be able to
reconstruct the exact adversary from this object without reading prose.
Schema v1, frozen 2026-08-19 (design section 2.3).
"""
from __future__ import annotations
import json, os, subprocess, hashlib

SCHEMA_VERSION = 1


def host_facts() -> dict:
    def sh(c):
        return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
    caps = sh("docker exec homeprov-ha sh -c 'grep CapEff /proc/self/status' 2>/dev/null")
    v = 0
    try:
        v = int(caps.split()[1], 16)
    except Exception:
        pass
    return {
        "arch": sh("uname -m"),
        "container_arch": sh("docker exec homeprov-ha uname -m 2>/dev/null"),
        "ha_version": sh("docker inspect homeprov-ha --format '{{index .Config.Image}}' 2>/dev/null"),
        "cap_eff_hex": hex(v) if v else None,
        "cap_linux_immutable": bool(v & (1 << 9)),
        "cap_bpf": bool(v & (1 << 38)),
        "cap_sys_admin": bool(v & (1 << 21)),
        "binfmt_misc_empty": sh("docker exec homeprov-ha sh -c 'ls /proc/sys/fs/binfmt_misc 2>/dev/null | wc -l'") in ("", "0"),
    }


def record(actor_id, actor_position, seed, budget_writes, window_s,
           knowledge=None, constraints=None, substrate=None, mission=None) -> dict:
    return {
        "capability_record": {
            "schema_version": SCHEMA_VERSION,
            "actor_id": actor_id,
            "actor_position": actor_position,       # in_process_integration | llm_agent | ...
            "powers": {
                "db_read": True, "db_write": True,
                "fs_read_as_ha_uid": True, "fs_write_as_ha_uid": True,
                "python_exec_in_core": True,
                "event_bus_listen": True, "event_bus_emit": True,
                "service_call": True, "network_egress": False,
            },
            "knowledge": knowledge or {
                "deployment_topology": "full", "automation_configs": "full",
                "anchor_schedule_known": False, "anchor_key_known": False,
                "victim_routine_model": "coarse",
            },
            "budget": {"db_writes_max": budget_writes,
                       "wallclock_window_s": window_s, "cpu_seconds_max": None},
            "constraints": constraints or {
                "host_root": False,            # root IN CONTAINER, but see caps below
                "cross_uid_write": False,
                "anchor_key_access": False,
                "external_anchor_retraction": False,
                "clock_control": False,        # lifted only in the sensitivity arm
                "cap_linux_immutable": False,  # MEASURED: not held -> P1 holds
                "cap_bpf": False,              # MEASURED: not held -> P4 unavailable to both sides
            },
            "substrate": substrate or {
                "kind": "native_aarch64_container",
                "envelope": "Pi-shaped cgroup (cpus/memory/blkio)",
                "note": "NOT a Raspberry Pi; absolute latency is not claimed as Pi latency",
            },
            "provenance": {"rka_mission": mission, "seed": seed},
        }
    }


def stamp(obj: dict, path: str) -> str:
    """Write a result with its capability record and a content digest."""
    blob = json.dumps(obj, sort_keys=True, default=str).encode()
    obj["_digest"] = hashlib.sha256(blob).hexdigest()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, default=str)
    return obj["_digest"]
