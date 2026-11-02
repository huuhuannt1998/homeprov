"""Deployment generator (design section 11.2). Parameters are SWEPT, not fixed,
because forgeability and OQ both depend on graph shape -- specifically on how
densely automations interlock.

Automation logic is seeded from publicly documented HA blueprint patterns rather
than invented, and the fidelity gap is declared.

WE DO NOT BUILD OR RELEASE A LABELLED DATASET. That collides with the PI's
VESPER platform (mission M3 T5, decision D2).
"""
from __future__ import annotations
import itertools, json, os, random

SWEEP = {
    "n_dev":     [10, 25, 50, 100],
    "n_aut":     [5, 15, 40],
    "n_int":     [5, 10, 20],
    "interlock": [0.1, 0.3, 0.6],      # fraction of automations fired by another's effect
    "rate_hr":   [10, 100, 1000],
    "history":   ["1d", "7d", "90d"],
}


def grid(limit=None, seed=0):
    keys = list(SWEEP)
    combos = [dict(zip(keys, v)) for v in itertools.product(*(SWEEP[k] for k in keys))]
    rng = random.Random(seed); rng.shuffle(combos)
    return combos[:limit] if limit else combos


def deployment_id(p: dict) -> str:
    return "dep_%02d_%02d_%02d_%s_%d_%s" % (
        p["n_dev"], p["n_aut"], p["n_int"], str(p["interlock"]).replace(".", ""),
        p["rate_hr"], p["history"])


def render(p: dict, out_dir: str, seed: int = 0) -> str:
    """Emit an HA config directory for one deployment point."""
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)
    n_aut = p["n_aut"]

    cfg = ["# HOMEPROV generated deployment %s" % deployment_id(p),
           "# virtual devices only. NEVER a real home.",
           "default_config:", "",
           "logger:", "  default: warning", "  logs:",
           "    custom_components.homeprov: warning",
           "    custom_components.homeprov_redteam: warning", "",
           "demo:", "",
           "input_boolean:",
           "  owner_present:", "    name: Owner Present", "    initial: off"]
    for i in range(min(p["n_dev"], 20)):
        cfg += ["  sensor_%02d:" % i, "    name: Sensor %02d" % i, "    initial: off"]
    cfg += ["", "recorder:",
            "  db_url: sqlite:////config/home-assistant_v2.db",
            "  commit_interval: 1", "  purge_keep_days: 30", "",
            "automation: !include automations.yaml", "",
            "homeprov:", "", "homeprov_redteam:", ""]
    open(os.path.join(out_dir, "configuration.yaml"), "w").write("\n".join(cfg))

    autos = ["# blueprint-derived patterns; fidelity gap declared in section 7.8"]
    # the INNOCENT automation the flagship forgery frames -- always present
    autos += ["- id: arrive_home", "  alias: Arrive Home", "  triggers:",
              "    - trigger: state", "      entity_id: input_boolean.owner_present",
              '      to: "on"', "  actions:", "    - action: lock.unlock",
              "      target:", "        entity_id: lock.kitchen_door", "  mode: single"]
    for i in range(1, n_aut):
        # interlocked automations fire off ANOTHER automation's effect
        interlocked = rng.random() < p["interlock"]
        src = "lock.kitchen_door" if interlocked else "input_boolean.sensor_%02d" % (i % 20)
        to = '"unlocked"' if interlocked else '"on"'
        autos += ["- id: auto_%02d" % i, "  alias: Auto %02d" % i, "  triggers:",
                  "    - trigger: state", "      entity_id: %s" % src,
                  "      to: %s" % to, "  actions:",
                  "    - action: light.turn_on", "      target:",
                  "        entity_id: light.bed_light", "  mode: single"]
    open(os.path.join(out_dir, "automations.yaml"), "w").write("\n".join(autos))

    open(os.path.join(out_dir, "deployment.json"), "w").write(
        json.dumps({"params": p, "id": deployment_id(p), "seed": seed}, indent=2))
    return out_dir
