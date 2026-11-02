"""R9 item (c), diagnostic variant: warm-up-matched phases.

WHY THIS EXISTS. In e_a_signed_anchor.run() (and in its faithful local replay,
r9_c_signed_anchor_overhead.py) the two timed floods are NOT run under equal
conditions: the unsigned flood starts right after a fresh daemon comes up, while
the signed flood starts after the same daemon has already served 600 refused
(401) requests. The ordering therefore confounds the signing cost with warm-up.
The local replay measured the signed flood FASTER than the unsigned one, which
cannot be a signing effect.

FURTHER DEVIATION (beyond running anchord as a local process): phase 1 now also
receives 600 refused requests before its timed flood -- 600 POST /append bodies
that are not valid JSON, refused with HTTP 400 and recorded in refusals.jsonl
with an fsync, exactly as phase 2's 600 refused appends are (401, recorded,
fsync). Neither kind of refusal appends to the chain, so both timed floods start
on an empty chain, as in the original. Everything else is identical to
r9_c_signed_anchor_overhead.py: unmodified anchord.py on 127.0.0.1, the original
client functions, N = 300, 5 repetitions, fresh data directory per phase.
"""
from __future__ import annotations
import json, os, shutil, sys, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import r9_c_signed_anchor_overhead as base  # noqa: E402  (sets EA_PORT, guards docker)
C, ea, N, REPS = base.C, base.ea, base.N, base.REPS


def _bad_json_post():
    req = urllib.request.Request(ea.BASE + "/append", data=b"{not json", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def one_rep(i):
    rep = {"rep": i, "load_start": C.load_snapshot("warm rep %d start" % i)}
    d1 = os.path.join(C.SCRATCH, "anchord_warm_rep%d_unauth" % i)
    p = base._start(d1, "")
    warm_400 = sum(1 for _ in range(2 * N) if _bad_json_post() == 400)
    ok_u, dt_u = ea._flood(N, sign_key=None)
    base._stop(p)
    chain_u = base._lines(os.path.join(d1, "anchor", "chain.jsonl"))
    ref_u = base._lines(os.path.join(d1, "anchor", "refusals.jsonl"))
    shutil.rmtree(d1)

    d2 = os.path.join(C.SCRATCH, "anchord_warm_rep%d_auth" % i)
    p = base._start(d2, ea.KEY)
    unsigned_ref = forged_ref = 0
    for j in range(N):
        s, _ = ea._post("/append", {"sealed": {"second": {str(1790000000 + j): ea.SEG}}},
                        sign_key=None)
        unsigned_ref += (s == 401)
    for j in range(N):
        s, _ = ea._post("/append", {"sealed": {"second": {str(1791000000 + j): ea.SEG}}},
                        sign_key="wrong-key-guess")
        forged_ref += (s == 401)
    mon_ok, dt_s = ea._flood(N, sign_key=ea.KEY)
    base._stop(p)
    chain_s = base._lines(os.path.join(d2, "anchor", "chain.jsonl"))
    ref_s = base._lines(os.path.join(d2, "anchor", "refusals.jsonl"))
    shutil.rmtree(d2)

    r_u, r_s = ok_u / max(dt_u, 1e-9), mon_ok / max(dt_s, 1e-9)
    rep.update({
        "unsigned": {"n": N, "accepted": ok_u, "seconds": dt_u, "appends_per_s": r_u,
                     "chain_lines": chain_u, "warmup_refused_400": warm_400,
                     "refusals_recorded": ref_u},
        "signed": {"n": N, "accepted": mon_ok, "seconds": dt_s, "appends_per_s": r_s,
                   "chain_lines": chain_s, "warmup_refused_401": unsigned_ref + forged_ref,
                   "refusals_recorded": ref_s},
        "ratio_signed_over_unsigned": r_s / r_u,
        "overhead_pct": (1 - r_s / r_u) * 100,
        "load_end": C.load_snapshot("warm rep %d end" % i)})
    return rep


def main():
    started = C.now_iso()
    l0 = C.load_snapshot("overall start")
    reps = [one_rep(i) for i in range(1, REPS + 1)]
    l1 = C.load_snapshot("overall end")
    res = {
        "item": "R9(c) diagnostic: signing overhead with warm-up-matched phases",
        "PROTOCOL_DEVIATION": (
            "LOCAL PROCESS, NOT CONTAINERIZED (as r9_c_signed_anchor_overhead_local.json), "
            "AND phase 1 receives 600 refused malformed-JSON requests before its timed "
            "flood so both timed floods follow 600 refused requests. This is NOT the "
            "original protocol; it isolates the ordering confound."),
        "n_append_trials_per_phase": N, "repetitions": REPS, "reps": reps,
        "summary": {
            "overhead_pct": base.t_interval([r["overhead_pct"] for r in reps]),
            "ratio_signed_over_unsigned": base.t_interval(
                [r["ratio_signed_over_unsigned"] for r in reps]),
            "unsigned_appends_per_s": base.t_interval([r["unsigned"]["appends_per_s"] for r in reps]),
            "signed_appends_per_s": base.t_interval([r["signed"]["appends_per_s"] for r in reps]),
            "all_appends_accepted": all(r["unsigned"]["accepted"] == N and
                                        r["signed"]["accepted"] == N for r in reps),
            "all_warmups_refused": all(r["unsigned"]["warmup_refused_400"] == 2 * N and
                                       r["signed"]["warmup_refused_401"] == 2 * N for r in reps),
        },
        "load": [l0, l1],
        "provenance": C.provenance(
            __file__, inputs=[base.LAUNCHER, base.ANCHORD, base.EA_SRC, base.ORIG,
                              os.path.join(HERE, "r9_c_signed_anchor_overhead.py")],
            extra={"started": started, "finished": C.now_iso(), "port": base.PORT}),
    }
    p = C.write_result("r9_c_signed_anchor_overhead_local_warmmatched.json", res)
    print(p)
    print(json.dumps(res["summary"], indent=1))
    for r in reps:
        print(r["rep"], round(r["unsigned"]["appends_per_s"], 1),
              round(r["signed"]["appends_per_s"], 1), round(r["overhead_pct"], 2),
              r["load_start"]["loadavg_1_5_15"][0], r["load_end"]["loadavg_1_5_15"][0])


if __name__ == "__main__":
    main()
