#!/usr/bin/env python3
"""Shared helpers for the R1 (dynamic confirmation on current releases) suite.

Every R1 result file carries per-trial rows, Clopper-Pearson aggregates from
exp/rig/stats.py, and a provenance block (script sha256, image digests,
frontend version, git HEAD, timestamps). Result writers REFUSE to overwrite an
existing file (hard rule 1).
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
OUT = os.path.join(ROOT, "exp", "out")
sys.path.insert(0, os.path.join(ROOT, "exp"))
from rig import stats  # noqa: E402

# Image digests recorded at pull time (homeassistant/home-assistant).
IMAGE_DIGESTS = {
    "2026.7.4": "sha256:5a531753cea96444200158fc2b0ac7ccd739291ec50414877b396de6e0bb29b3",
    "2026.9.4": "sha256:3e6710a7ab2a61311d9d899b719f6c3657791c63e8f4942cec4ebc42401d6b76",
    "2026.10.0b2": "sha256:2c21ccd2682c7f27b674196303e3fa680ad1710c6d1f0ff3a1c2416f4950669d",
}
FRONTEND = {
    "2026.7.4": "20260624.6",
    "2026.9.4": "20260826.7",
    "2026.10.0b2": "20260930.1",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head():
    try:
        return subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return None


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def provenance(ha_version, scripts):
    """scripts: list of absolute paths whose sha256 to record."""
    return {
        "ha_version": ha_version,
        "image_digest": IMAGE_DIGESTS.get(ha_version),
        "frontend_version": FRONTEND.get(ha_version),
        "git_head": git_head(),
        "script_sha256": {os.path.basename(p): sha256_file(p)
                          for p in scripts if os.path.exists(p)},
        "timestamp_utc": now(),
    }


def cp(k, n):
    return stats.clopper_pearson(k, n)


def write_result(name, payload):
    """Write exp/out/<name>; refuse to overwrite (hard rule 1)."""
    dst = os.path.join(OUT, name)
    if os.path.exists(dst):
        raise SystemExit("REFUSE overwrite: " + dst)
    tmp = dst + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    os.rename(tmp, dst)
    print("  -> exp/out/%s  sha256=%s" % (name, sha256_file(dst)))
    return dst
