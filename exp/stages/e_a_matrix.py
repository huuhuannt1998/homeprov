"""E-A matrix -- App. A.13 anchor attack matrix, unauthenticated vs signed.

Runs stage26 (the anchor protocol attack matrix) against a fresh unauthenticated
anchor and against a fresh monitor-signed anchor, so the two matrices sit side by
side. stage26 issues UNAUTHENTICATED requests -- exactly the in-hub adversary's
reach -- so against the signed anchor every append must be refused.
"""
import importlib, json, os, subprocess, sys, time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rig import capability  # noqa: E402

IMG = "hpr-anchord:sig"
PORT = int(os.environ.get("EAM_PORT", "9972"))
KEY = os.environ.get("HOMEPROV_ANCHOR_KEY", "hpr-monitor-key-2026-09-08")
CONT = "hpr-anchord-eam"


def _sh(*a, t=60):
    return subprocess.run(list(a), capture_output=True, text=True, timeout=t)


def _start(authed):
    _sh("docker", "rm", "-f", CONT)
    env = ["-e", "PUBLISH_PERIOD=3600"]
    if authed:
        env += ["-e", "HOMEPROV_ANCHOR_KEY=%s" % KEY]
    _sh("docker", "run", "-d", "--name", CONT, "-p", "%d:9900" % PORT, *env, IMG)
    for _ in range(50):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/head" % PORT, timeout=2) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.2)
    time.sleep(0.5)


def _matrix():
    os.environ["HOMEPROV_ANCHOR"] = "http://127.0.0.1:%d" % PORT
    os.environ["HOMEPROV_ANCHOR_CONTAINER"] = CONT
    import stages.stage26_anchor_attacks as s26
    importlib.reload(s26)
    return s26.run({})


def run(cfg=None):
    _start(authed=False)
    unauth = _matrix()
    _sh("docker", "rm", "-f", CONT)
    _start(authed=True)
    signed = _matrix()
    refr = _sh("docker", "exec", CONT, "sh", "-c",
               "wc -l < /anchor/refusals.jsonl 2>/dev/null || echo 0").stdout.strip()
    _sh("docker", "rm", "-f", CONT)

    def summ(m):
        rows = m["rows"]
        appends = [r for r in rows if "append" in r["attack"].lower() or "flood" in r["attack"].lower() or "concurrent" in r["attack"].lower() or "marker" in r["attack"].lower() or "root" in r["attack"].lower() or "segment" in r["attack"].lower()]
        return {"n_rows": len(rows),
                "n_accepted": sum(1 for r in rows if r["accepted"]),
                "any_silent_rewrite": m["any_silent_rewrite"]}

    return {"experiment": "E-A-matrix", "what": "App A.13 anchor attack matrix, "
            "unauthenticated vs monitor-signed",
            "unauthenticated": {"summary": summ(unauth), "rows": unauth["rows"]},
            "signed": {"summary": summ(signed), "rows": signed["rows"],
                       "refusals_recorded": int(refr or 0)},
            "capability": capability.record(
                actor_id="in_process_integration",
                actor_position="in_process_integration", seed=0,
                budget_writes=None, window_s=None,
                knowledge={"anchor_key_known": False},
                constraints={"anchor_key_access": False},
                substrate={"kind": "docker_container_anchor", "anchor_image": IMG},
                mission="E-A A.13 matrix")}


if __name__ == "__main__":
    r = run()
    dig = capability.stamp(r, os.path.join(os.path.dirname(__file__), "..", "out",
                                           "e7b_anchor_matrix.json"))
    us, ss = r["unauthenticated"]["summary"], r["signed"]["summary"]
    print("UNAUTH: %d/%d attacks accepted, silent_rewrite=%s"
          % (us["n_accepted"], us["n_rows"], us["any_silent_rewrite"]))
    print("SIGNED: %d/%d attacks accepted, silent_rewrite=%s, refusals=%d"
          % (ss["n_accepted"], ss["n_rows"], ss["any_silent_rewrite"],
             r["signed"]["refusals_recorded"]))
    print("digest", dig)
