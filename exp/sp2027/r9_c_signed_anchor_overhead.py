"""R9 item (c): repeat the anchor append-throughput cost of HMAC signing 5 times.

Original (kept untouched): exp/out/e7b_anchor_signed.json, one measurement,
795.7 -> 779.7 appends/s, overhead 2.0 %, produced by exp/stages/e_a_signed_anchor.py
against the anchor daemon in a Docker container.

PROTOCOL DEVIATION: no container. The unmodified testbed/anchord/anchord.py runs
as a local Python process on 127.0.0.1 (exp/sp2027/r9_c_anchord_local.py) with a
fresh temporary data directory in the session scratchpad for every phase. The
client side is the ORIGINAL code: _post and _flood are imported from
exp/stages/e_a_signed_anchor.py and called unchanged, with N = 300 as there.

Per repetition, mirroring e_a_signed_anchor.run():
  phase 1  fresh unauthenticated daemon; timed flood of N unsigned appends
  phase 2  fresh authenticated daemon; N unsigned + N forged-signature appends
           (refused, untimed, as in the original); timed flood of N signed appends
Not replicated: the pre-emption probes (run after the timed floods in the
original, read the chain through `docker exec`, and do not affect timing).

overhead_pct = (1 - signed_rate / unsigned_rate) * 100, as in the original.
Mean and 95 % t-interval (df = reps - 1) over the repetitions.
"""
from __future__ import annotations
import json, math, os, shutil, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import r9_common as C  # noqa: E402
C.forbid_docker()

PORT = 9971
os.environ["EA_PORT"] = str(PORT)          # e_a_signed_anchor reads it at import
import stages.e_a_signed_anchor as ea  # noqa: E402
assert ea.BASE == "http://127.0.0.1:%d" % PORT

REPS = 5
N = 300
LAUNCHER = os.path.join(HERE, "r9_c_anchord_local.py")
ANCHORD = os.path.join(C.REPO, "testbed", "anchord", "anchord.py")
EA_SRC = os.path.join(C.EXP, "stages", "e_a_signed_anchor.py")
ORIG = os.path.join(C.EXP, "out", "e7b_anchor_signed.json")


def _lines(p):
    if not os.path.exists(p):
        return 0
    with open(p, "rb") as fh:
        return sum(1 for _ in fh)


def _start(data, key):
    if os.path.exists(data):
        shutil.rmtree(data)
    p = subprocess.Popen([sys.executable, LAUNCHER, str(PORT), data, key],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline().strip()
    if not line.startswith("READY"):
        p.kill()
        raise RuntimeError("daemon did not start: %r %r" % (line, p.stderr.read()[:500]))
    # readiness as in e_a_signed_anchor._start: head answers and a probe POST
    # gets an HTTP status, then a fixed 0.5 s settle
    for _ in range(50):
        if ea._head().get("seq") is not None and \
                ea._post("/ping-nope", {}, None)[0] in (200, 404, 405, 401, 400):
            break
        time.sleep(0.2)
    time.sleep(0.5)
    return p


def _stop(p):
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()


def one_rep(i):
    rep = {"rep": i, "load_start": C.load_snapshot("rep %d start" % i)}
    d1 = os.path.join(C.SCRATCH, "anchord_rep%d_unauth" % i)
    p = _start(d1, "")
    ok_u, dt_u = ea._flood(N, sign_key=None)
    _stop(p)
    chain_u = _lines(os.path.join(d1, "anchor", "chain.jsonl"))
    shutil.rmtree(d1)

    d2 = os.path.join(C.SCRATCH, "anchord_rep%d_auth" % i)
    p = _start(d2, ea.KEY)
    unsigned_ok = unsigned_ref = forged_ok = forged_ref = 0
    for j in range(N):
        s, _ = ea._post("/append", {"sealed": {"second": {str(1790000000 + j): ea.SEG}}},
                        sign_key=None)
        unsigned_ok += bool(s and 200 <= s < 300); unsigned_ref += (s == 401)
    for j in range(N):
        s, _ = ea._post("/append", {"sealed": {"second": {str(1791000000 + j): ea.SEG}}},
                        sign_key="wrong-key-guess")
        forged_ok += bool(s and 200 <= s < 300); forged_ref += (s == 401)
    mon_ok, dt_s = ea._flood(N, sign_key=ea.KEY)
    _stop(p)
    chain_s = _lines(os.path.join(d2, "anchor", "chain.jsonl"))
    refusals = _lines(os.path.join(d2, "anchor", "refusals.jsonl"))
    shutil.rmtree(d2)

    r_u = ok_u / max(dt_u, 1e-9)
    r_s = mon_ok / max(dt_s, 1e-9)
    rep.update({
        "unsigned": {"n": N, "accepted": ok_u, "seconds": dt_u, "appends_per_s": r_u,
                     "chain_lines": chain_u},
        "signed": {"n": N, "accepted": mon_ok, "seconds": dt_s, "appends_per_s": r_s,
                   "chain_lines": chain_s},
        "adversary_unsigned": {"n": N, "accepted": unsigned_ok, "refused_401": unsigned_ref},
        "adversary_forged": {"n": N, "accepted": forged_ok, "refused_401": forged_ref},
        "refusals_recorded": refusals,
        "ratio_signed_over_unsigned": r_s / r_u,
        "overhead_pct": (1 - r_s / r_u) * 100,
        "load_end": C.load_snapshot("rep %d end" % i)})
    return rep


def t_interval(xs, alpha=0.05):
    from scipy.stats import t
    n = len(xs); m = statistics.fmean(xs); sd = statistics.stdev(xs)
    h = t.ppf(1 - alpha / 2, n - 1) * sd / math.sqrt(n)
    return {"n": n, "mean": m, "sd": sd, "t_crit": float(t.ppf(1 - alpha / 2, n - 1)),
            "ci_lo": m - h, "ci_hi": m + h, "method": "Student t, df=n-1"}


def main():
    started = C.now_iso()
    os.makedirs(C.SCRATCH, exist_ok=True)
    l0 = C.load_snapshot("overall start")
    reps = [one_rep(i) for i in range(1, REPS + 1)]
    l1 = C.load_snapshot("overall end")
    orig = json.load(open(ORIG))["throughput_cost_of_signing"]
    res = {
        "item": "R9(c) anchor append throughput cost of HMAC signing, 5 repetitions",
        "PROTOCOL_DEVIATION": (
            "LOCAL PROCESS, NOT CONTAINERIZED. The original e7b measurement ran "
            "anchord in a Docker container (python:3.12-slim, Docker volume, port "
            "published to the host). Here the unmodified anchord.py runs as a host "
            "Python %s process on 127.0.0.1:%d with chain files on the host disk "
            "(APFS, fsync per append) in a fresh scratch directory per phase. "
            "Absolute rates are therefore not comparable with the original; the "
            "signed/unsigned ratio is the quantity of interest. The original "
            "number in e7b_anchor_signed.json is left untouched."
            % (sys.version.split()[0], PORT)),
        "original_single_measurement": {"file": os.path.relpath(ORIG, C.REPO), **orig},
        "n_append_trials_per_phase": N, "repetitions": REPS,
        "reps": reps,
        "summary": {
            "overhead_pct": t_interval([r["overhead_pct"] for r in reps]),
            "ratio_signed_over_unsigned": t_interval([r["ratio_signed_over_unsigned"] for r in reps]),
            "unsigned_appends_per_s": t_interval([r["unsigned"]["appends_per_s"] for r in reps]),
            "signed_appends_per_s": t_interval([r["signed"]["appends_per_s"] for r in reps]),
            "all_appends_accepted": all(r["unsigned"]["accepted"] == N and
                                        r["signed"]["accepted"] == N for r in reps),
            "all_adversary_refused": all(r["adversary_unsigned"]["refused_401"] == N and
                                         r["adversary_forged"]["refused_401"] == N for r in reps),
        },
        "load": [l0, l1],
        "provenance": C.provenance(
            __file__, inputs=[LAUNCHER, ANCHORD, EA_SRC, ORIG],
            seeds=None,
            extra={"started": started, "finished": C.now_iso(), "port": PORT,
                   "daemon_python": sys.executable,
                   "client_functions": "stages.e_a_signed_anchor._post/_flood/_head (unmodified)"}),
        "deviations": [
            "anchord run as a local process (no Docker), see PROTOCOL_DEVIATION.",
            "Pre-emption probes of the original run() not replicated (post-timing, "
            "require docker exec); they do not enter the throughput numbers.",
            "Each phase uses a fresh temporary data directory, deleted after the phase.",
        ],
    }
    p = C.write_result("r9_c_signed_anchor_overhead_local.json", res)
    print(p)
    print(json.dumps(res["summary"], indent=1))
    for r in reps:
        print(r["rep"], round(r["unsigned"]["appends_per_s"], 1),
              round(r["signed"]["appends_per_s"], 1), round(r["overhead_pct"], 2),
              r["load_start"]["loadavg_1_5_15"][0], r["load_end"]["loadavg_1_5_15"][0])


if __name__ == "__main__":
    main()
