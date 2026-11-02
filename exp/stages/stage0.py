"""STAGE 0 — substrate stands up; determinism reproduces byte-identical hashes.
GATE: byte-identical hashes, else canonicalization is non-deterministic and
every downstream commitment result is suspect."""
from rig import substrate, capability, anchor

def run(cfg):
    out = {"stage": 0, "host": capability.host_facts()}
    out["reset"] = substrate.reset_state(cfg["config_dir"])
    out["p1_install"] = anchor.p1_install()
    out["boot"] = substrate.boot(cfg["config_dir"], cfg.get("envelope", "pi5_4g"))
    out["wait"] = substrate.wait_started()
    out["determinism"] = substrate.determinism_check(cfg["config_dir"])
    d = out["determinism"]
    out["GATE_PASS"] = bool(d.get("byte_identical")) if d.get("testable") else None
    return out
