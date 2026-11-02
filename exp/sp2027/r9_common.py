"""R9 (S&P 2027 plan item R9 / B6) -- shared provenance and safety helpers.

Every r9_* result file records: script path + sha256, python version, git HEAD
and dirty state of exp/rig, input files + sha256, seeds, timestamps, host load,
and any deviation from the original protocol. Results are written only under
exp/out/ with an r9_ prefix, and an existing file is never overwritten.
"""
from __future__ import annotations
import datetime, hashlib, json, os, platform, subprocess, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EXP = os.path.join(REPO, "exp")
OUT = os.path.join(EXP, "out")
SCRATCH = os.environ.get("HOMEPROV_SCRATCH_DIR", os.path.join(__import__("tempfile").gettempdir(), "homeprov-scratch"))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args) -> str:
    r = subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True)
    return r.stdout.strip()


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_snapshot(label: str) -> dict:
    """`uptime` plus os.getloadavg(); other projects share this CPU."""
    up = subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()
    return {"label": label, "ts": now_iso(), "uptime": up,
            "loadavg_1_5_15": list(os.getloadavg())}


def provenance(script_path: str, inputs=(), seeds=None, extra=None) -> dict:
    rig_status = _git("status", "--porcelain", "--", "exp/rig")
    return {
        "script": os.path.abspath(script_path),
        "script_sha256": sha256_file(script_path),
        "helper": os.path.abspath(__file__),
        "helper_sha256": sha256_file(__file__),
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "git_head": _git("rev-parse", "HEAD"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "exp_rig_dirty": bool(rig_status),
        "exp_rig_status_porcelain": rig_status,
        "inputs": {os.path.relpath(p, REPO): sha256_file(p) for p in inputs},
        "seeds": seeds,
        **(extra or {}),
    }


def out_path(name: str) -> str:
    assert name.startswith("r9_"), name
    p = os.path.join(OUT, name)
    if os.path.exists(p):
        raise SystemExit("refusing to overwrite existing result: %s" % p)
    return p


def write_result(name: str, obj: dict) -> str:
    p = out_path(name)
    blob = json.dumps(obj, indent=2, sort_keys=False, default=str)
    with open(p, "x") as fh:          # 'x' -> fail if it appeared meanwhile
        fh.write(blob + "\n")
    return p


def forbid_docker() -> None:
    """Hard guard: any subprocess call mentioning docker raises."""
    import subprocess as sp
    _run, _popen = sp.run, sp.Popen

    def _chk(a):
        s = " ".join(a) if isinstance(a, (list, tuple)) else str(a)
        if "docker" in s:
            raise RuntimeError("R9 guard: refusing docker command: %s" % s[:120])

    def run(*a, **k):
        _chk(a[0] if a else k.get("args")); return _run(*a, **k)

    class Popen(_popen):  # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            _chk(a[0] if a else k.get("args")); super().__init__(*a, **k)

    sp.run, sp.Popen = run, Popen
    _sys = os.system
    def system(c):
        _chk(c); return _sys(c)
    os.system = system
