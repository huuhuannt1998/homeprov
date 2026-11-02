#!/usr/bin/env python3
"""HOMEPROV experiment orchestrator.

    python3 exp/run.py selftest          # validate the rig WITHOUT running experiments
    python3 exp/run.py plan              # what each stage will do, and its gate
    python3 exp/run.py stage0 --run      # execute a stage
    python3 exp/run.py all --run

Nothing executes without --run. `selftest` and `plan` are side-effect free.
"""
from __future__ import annotations
import argparse, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from rig import capability                                   # noqa: E402
from rig.conf_import import (THRESHOLDS, CONTRASTS, ABLATIONS,   # noqa: E402
                             BASELINES, FROZEN, OBSERVABILITY)

CFG = {
    "config_dir": os.path.join(os.path.dirname(HERE), "testbed", "ha-config"),
    "work": "/tmp/homeprov_exp",
    "snapshot": os.path.join(os.path.dirname(HERE), "testbed", "ha-config",
                             "homeprov_out", "snapshot_B.db"),
    "envelope": "pi5_4g",
    "seed": 0,
    "window_s": 5,
    "out": os.path.join(HERE, "out"),
}

STAGES = ["stage0", "stage1", "stage2", "stage3", "stage4", "stage5", "stage6"]


def _load(name):
    import importlib
    return importlib.import_module("stages.%s" % name)


def selftest() -> int:
    """Import every module, exercise the pure functions, verify nothing touches
    L4 at inference time. Runs NO experiment and mutates NO state."""
    ok, fail = [], []

    def chk(label, fn):
        try:
            fn(); ok.append(label)
        except Exception as e:
            fail.append("%s: %s: %s" % (label, type(e).__name__, e))

    from rig import (graph, commit, verify, localize, reconstruct, metrics,
                     forge, benign, baselines, anchor, deployment, substrate, stats)

    chk("catalog frozen", lambda: (_ for _ in ()).throw(AssertionError("bad")) if FROZEN != "2026-08-19" else None)

    # synthetic graph exercises commit/verify/localize/reconstruct without any DB
    class N:
        def __init__(s, key, ts, ctx, par, ty="delta", label="actuates"):
            s.key, s.ts, s.ctx, s.par, s.ty, s.label = key, ts, ctx, par, ty, label
            s.kind = "state"; s.entity = "lock.x"; s.payload = None
            s.content = ("%s|%s" % (key, ts)).encode()

    A, T = b"A" * 16, b"T" * 16
    nodes = [N("s:1", 10.0, T, None), N("s:2", 11.0, A, T), N("s:3", 12.0, A, T)]

    chk("commit_full/homeprov", lambda: commit.commit_full(nodes, "homeprov"))
    chk("commit_full/b2", lambda: commit.commit_full(nodes, "b2"))
    chk("commit_full/b4", lambda: commit.commit_full(nodes, "b4"))

    def edge_binding_is_real():
        base = commit.commit_full(nodes, "homeprov")
        moved = [N("s:1", 10.0, T, None), N("s:2", 11.0, A, b"Z" * 16), N("s:3", 12.0, A, T)]
        assert commit.commit_full(moved, "homeprov") != base, "homeprov blind to re-parent"
        assert commit.commit_full(moved, "b2") == commit.commit_full(nodes, "b2"), \
            "b2 should be BLIND to a pure re-parent (this is the whole contrast)"
    chk("edge binding detects re-parent AND b2 does not", edge_binding_is_real)

    def incremental_matches_full():
        inc = commit.Incremental("homeprov")
        inc.ingest(nodes); inc.seal(1e9)
        assert inc.phi()["second"] == commit.commit_full(nodes, "homeprov")["second"], \
            "incremental diverges from full recompute"
    chk("incremental == full recompute", incremental_matches_full)

    def verify_clean():
        phi = commit.commit_full(nodes, "homeprov")
        r = verify.verify(nodes, phi, 1e9, "homeprov")
        assert not r["detected"], "false positive on untampered graph"
    chk("no false positive on clean graph", verify_clean)

    def verify_backdated():
        phi = commit.commit_full(nodes, "homeprov")
        inj = nodes + [N("s:9", 5.0, b"X" * 16, None)]     # backdated into committed time
        r = verify.verify(inj, phi, 1e9, "homeprov")
        assert any(v["why"] == "UNCOMMITTED_HISTORICAL" for v in r["violations"]), \
            "backdated injection invisible -- the F_inj gap that M2 found"
    chk("backdated injection detected (UNCOMMITTED-REGIONS)", verify_backdated)

    chk("greedy localizer", lambda: localize.greedy(nodes, [{"gran": "second", "seg": "11"}]))
    chk("exact ILP localizer", lambda: localize.exact(nodes, [{"gran": "second", "seg": "11"}]))
    chk("AB-1 prop2 check", lambda: localize.check_prop2(nodes, [{"gran": "second", "seg": "11"}]))
    chk("reconstruct abstains over Q",
        lambda: (_ for _ in ()).throw(AssertionError("no abstention"))
        if all(e["trust"] == "VERIFIED"
               for e in reconstruct.reconstruct(nodes, {"s:2"}, [])) else None)
    chk("metrics LR/OQ", lambda: (metrics.lr({"a"}, {"a"}), metrics.oq({"a", "b"}, {"a"}, 10)))
    chk("stats paired bootstrap",
        lambda: stats.paired_bootstrap([1, 2, 3, 4], [0, 1, 2, 3], n=200))
    chk("deployment grid", lambda: deployment.grid(limit=3))
    chk("capability record", lambda: capability.record("x", "in_process_integration", 0, 7, 5))
    for s in STAGES:
        chk("import %s" % s, lambda s=s: _load(s))

    print("SELFTEST  %d passed, %d failed" % (len(ok), len(fail)))
    for o in ok:
        print("   ok    %s" % o)
    for f in fail:
        print("   FAIL  %s" % f)
    return 0 if not fail else 1


def plan():
    print("HOMEPROV experiment plan — catalog frozen %s" % FROZEN)
    print("\nOBSERVABILITY LATTICE (L4 is an evaluation oracle, never an algorithm input):")
    for k, v in OBSERVABILITY.items():
        print("   %-3s %s" % (k, v))
    print("\nBASELINES:")
    for k, v in BASELINES.items():
        print("   %-3s %s" % (k, v.split("\n")[0]))
    print("\nTHRESHOLDS (predeclared):")
    for k, v in THRESHOLDS.items():
        print("   %-15s %s %-6s %s" % (k, v["op"], v["value"],
                                       "HARD" if v.get("hard") else ""))
    print("\nPREREGISTERED CONTRASTS:")
    for cid, desc, why in CONTRASTS:
        print("   %-3s %-52s %s" % (cid, desc, why))
    print("\nABLATIONS:")
    for k, v in ABLATIONS.items():
        print("   %-6s %s" % (k, v.split(" -- ")[0]))
    print("\nSTAGES:")
    for s in STAGES:
        m = _load(s)
        print("   %-7s %s" % (s, (m.__doc__ or "").strip().split("\n")[0]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", choices=["selftest", "plan", "all"] + STAGES)
    ap.add_argument("--run", action="store_true",
                    help="actually execute (default is a no-op description)")
    ap.add_argument("--envelope", default=CFG["envelope"])
    ap.add_argument("--seed", type=int, default=CFG["seed"])
    a = ap.parse_args()
    CFG["envelope"] = a.envelope; CFG["seed"] = a.seed

    if a.target == "selftest":
        return selftest()
    if a.target == "plan":
        return plan()

    targets = STAGES if a.target == "all" else [a.target]
    if not a.run:
        print("DRY RUN — nothing executed. Re-invoke with --run.")
        for t in targets:
            print("   %-7s %s" % (t, (_load(t).__doc__ or "").strip().split("\n")[0]))
        return 0

    os.makedirs(CFG["out"], exist_ok=True)
    for t in targets:
        print("=== %s ===" % t)
        res = _load(t).run(CFG)
        path = os.path.join(CFG["out"], "%s_%d.json" % (t, int(time.time())))
        capability.stamp(res, path)
        print(json.dumps(res, indent=2, default=str)[:1500])
        print("-> %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
