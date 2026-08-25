"""STAGE 17 — S4 and S5 as REAL scenarios, not proxies.

S4 was a bare deletion standing in for a t_c sweep; S5 was a re-parent standing
in for anchor compromise. Both are now the thing itself.

S4 makes NON-GUARANTEE 2 MEASURABLE: 'an adversary that compromises the hub
before the first anchor can fabricate a fully consistent history from origin.'
Sweep t_c against the first anchor and report the fraction of history that
remains verifiable.

S5 tests the TRUST ASSUMPTION directly: what does an adversary who controls the
ANCHOR obtain? Expected: total failure of G-1. Measured so the failure mode is
characterised rather than assumed away.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, localize, metrics, truth, stats, capability
from rig.commit import commit_full

WORK = "/tmp/homeprov_s4s5"
SEEDS = [101, 102, 103]
# t_c as a FRACTION of history: <0 means before the first anchor
TC_FRACTIONS = [-0.2, 0.0, 0.25, 0.5, 0.75, 0.95]


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    s4, s5 = [], []
    for seed in SEEDS:
        p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
             "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
             "target_nodes": 8000, "span_s": 3600.0, "max_nodes": 10**9}
        clean = os.path.join(WORK, "c.db")
        gen.generate(clean, p, seed=seed)
        base = graph.load(clean)
        lo, hi = min(n.ts for n in base), max(n.ts for n in base)
        span = hi - lo

        # ---------------- S4: t_c sweep against the first anchor -------------
        for frac in TC_FRACTIONS:
            tc = lo + frac * span
            # the anchor only covers history from the FIRST anchor onward.
            # model: commitment built ONLY over nodes at or after first_anchor.
            first_anchor = lo + 0.25 * span          # hub installed 25% in
            anchored = [n for n in base if n.ts >= first_anchor]
            if not anchored:
                continue
            phi = commit_full(anchored, "homeprov")

            db = clean + ".s4"
            shutil.copy(clean, db)
            f = forge.Forger(db)
            # adversary present from t_c rewrites everything it can reach
            con = sqlite3.connect(db)
            n = con.execute("""UPDATE states SET context_parent_id_bin=?
                                WHERE last_updated_ts >= ?""",
                            (os.urandom(16), tc)).rowcount
            con.commit(); con.close()
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            v = verify.verify(after, phi, math.floor(hi) + 1.0, "homeprov")
            # what fraction of the TAMPERED history is covered by the anchor?
            tampered_after_anchor = sum(1 for n2 in base
                                        if n2.key in T and n2.ts >= first_anchor)
            s4.append({"seed": seed, "tc_fraction": frac,
                       "tc_before_first_anchor": tc < first_anchor,
                       "rows_rewritten": n, "T": len(T),
                       "tampered_within_anchored_window": tampered_after_anchor,
                       "detected": v["detected"],
                       "verifiable_fraction": (
                           sum(1 for n2 in base if n2.ts >= first_anchor) / len(base))})
            os.remove(db)

        # ---------------- S5: the adversary controls the ANCHOR --------------
        phi = commit_full(base, "homeprov")
        db = clean + ".s5"
        shutil.copy(clean, db)
        con = sqlite3.connect(db)
        r = con.execute("""SELECT s.context_id_bin, sm.entity_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
             WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
             ORDER BY s.last_updated_ts DESC LIMIT 1""").fetchone()
        con.close()
        f = forge.Forger(db)
        f.ft4_reparent(r[0], os.urandom(16), r[1])
        after = graph.load(db)
        anchor_ts = math.floor(hi) + 1.0
        honest = verify.verify(after, phi, anchor_ts, "homeprov")
        # ANCHOR COMPROMISED: the adversary recomputes the commitment over its
        # own forged graph and substitutes it. This is what controlling the
        # anchor actually buys.
        forged_phi = commit_full(after, "homeprov")
        compromised = verify.verify(after, forged_phi, anchor_ts, "homeprov")
        s5.append({"seed": seed,
                   "detected_with_honest_anchor": honest["detected"],
                   "detected_with_compromised_anchor": compromised["detected"],
                   "violations_honest": honest["n_violations"],
                   "violations_compromised": compromised["n_violations"]})
        os.remove(db)
        os.remove(clean)

    by_frac = {}
    for fr in TC_FRACTIONS:
        rs = [r for r in s4 if r["tc_fraction"] == fr]
        if rs:
            by_frac["tc_%+.2f" % fr] = {
                "n": len(rs),
                "before_first_anchor": rs[0]["tc_before_first_anchor"],
                "detected": sum(1 for r in rs if r["detected"]),
                "mean_rows_rewritten": sum(r["rows_rewritten"] for r in rs) / len(rs),
                "mean_tampered_in_window": sum(
                    r["tampered_within_anchored_window"] for r in rs) / len(rs)}
    return {"stage": 17, "S4_tc_sweep": by_frac, "S4_rows": s4, "S5": s5,
            "S5_verdict": ("G-1 fails TOTALLY under anchor compromise, as the design "
                           "states: the adversary recomputes the commitment over its "
                           "own forged graph"),
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 0, 5),
            "GATE_PASS": all(not x["detected_with_compromised_anchor"] for x in s5)}
