"""STAGE 11 — contrast C4 swept: is COMPOSITION NECESSARY across deployments?

C4 was the last result still at n=1. M1 established CE_b = 1 on the ONE measured
Home Assistant deployment by exact single-class enumeration at matched budget.
This sweeps it.

FIDELITY LIMIT, STATED NOT BURIED. On the real deployment, Plaus was defined as
AGREEMENT WITH HA'S OWN LOGBOOK RENDERER -- M1 measured that a hand-built
structural verifier PASSED a forgery the renderer still showed as unattributed.
Generated deployments have no renderer, so this stage falls back to the SI
catalog (SI-4 automation-run coherence, SI-5 temporal span within one context),
which M1 measured to be the two invariants carrying the entire necessity
argument. Therefore:
  * the RENDERER-BACKED CE_b result remains n=1 (the measured HA deployment);
  * this sweep tests CE_b under the SI PROXY across many graph shapes.
Both must be reported, and neither substitutes for the other.
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, truth, stats, capability

WORK = "/tmp/homeprov_ce"
BG = 4.4
ARMS = [(1800.0, 5000), (7200.0, 7000), (21600.0, 9000)]
SEEDS = [51, 52, 53, 54, 55, 56]


def _chain(db, before_ts):
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin, sm.entity_id, MIN(s.last_updated_ts)
                         FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%'
                          AND s.context_parent_id_bin IS NOT NULL
                          AND s.last_updated_ts < ?
                        GROUP BY s.context_id_bin ORDER BY 3 DESC LIMIT 1""",
                    (before_ts,)).fetchone()
    con.close()
    return r


def _attr(nodes, key):
    """Which principal does the timeline resolve for this actuation?"""
    from rig.graph import attribution, build_indexes
    return attribution(nodes, key, build_indexes(nodes))


def _plaus_si(nodes, ctx):
    """SI-4 and SI-5, the two invariants M1 measured as load-bearing.

    SI-4: one automation run produces ONE actuation episode.
    SI-5: one automation context does not span disjoint episodes.
    """
    ts = sorted(n.ts for n in nodes if n.ctx == ctx)
    if not ts:
        return False, "no nodes at the attributed context"
    if max(ts) - min(ts) > 5.0:
        return False, "SI-5: context spans %.1fs" % (max(ts) - min(ts))
    episodes = 1 + sum(1 for a, b in zip(ts, ts[1:]) if b - a > 5.0)
    if episodes > 1:
        return False, "SI-4: %d disjoint episodes in one run" % episodes
    return True, ""


def _victim_key(nodes, ctx, entity):
    cand = [n for n in nodes if n.ctx == ctx and n.entity == entity and n.kind == "state"]
    return cand[-1].key if cand else None


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": BG,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "c.db")
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            head = max(n.ts for n in base)
            ch = _chain(clean, head - 5.0)
            if not ch:
                os.remove(clean); continue
            _, ent, _ = ch
            auto, trig = "automation.auto_00", "input_boolean.trigger_00"

            # THE GENERATOR EMITS ONLY AUTOMATION-CAUSED CHAINS -- there is no
            # malicious integration in it. Selecting an existing chain as the
            # "victim" made its TRUE attribution already NAMED_INNOCENT, so every
            # arm trivially "reached" the target and CE_b read 0 in 18/18. That
            # was a setup error, not a result.
            # Plant a genuine adversary actuation first: a lock state whose
            # context carries ONLY a call_service (no automation_triggered), so
            # it attributes to the INTEGRATION exactly as the real adversary does.
            fplant = forge.Forger(clean)
            adv = os.urandom(16)
            bts = head - 3.0
            fplant.inject_event("call_service",
                                {"domain": "lock", "service": "unlock"},
                                adv, None, bts - 0.1, "PLANT")
            fplant.inject_state(ent, "unlocked", adv, None, bts, "PLANT")
            fplant.close()                      # see the note below on pinning
            base = graph.load(clean)
            # sanity: the planted actuation must attribute to the integration
            _c = [n for n in base if n.entity == ent and n.kind == "state"]
            if not _c or _attr(base, _c[-1].key)["verdict"] != "INTEGRATION":
                os.remove(clean); continue

            # ---- the COMPOSED attack, and its budget --------------------
            dbc = clean + ".c"; shutil.copy(clean, dbc)
            fc = forge.Forger(dbc)
            try:
                fc.ft10_causal_laundering(adv, ent, auto, trig, bts)
            except Exception:
                fc.close(); os.remove(dbc); os.remove(clean); continue
            b = fc.writes
            fc.close()
            nc = graph.load(dbc)
            vk = _victim_key(nc, bytes.fromhex(
                [x for x in fc.log if x["ft"] == "FT-10"] and
                next(l for l in fc.log if "rows" in str(l) or True) and
                "00"), ent) if False else None
            # resolve the laundered actuation by entity + latest timestamp
            cand = [n for n in nc if n.entity == ent and n.kind == "state"]
            vk = cand[-1].key if cand else None
            comp_attr = _attr(nc, vk) if vk else {"verdict": "ABSENT"}
            comp_ctx = next((n.ctx for n in nc if n.key == vk), None)
            comp_plaus, _ = _plaus_si(nc, comp_ctx) if comp_ctx else (False, "")
            composed_ok = (comp_attr["verdict"] == "NAMED_INNOCENT" and comp_plaus)
            os.remove(dbc)

            # ---- every SINGLE class at the SAME budget ------------------
            singles = {}
            for cls in ("del", "rep", "inj"):
                dbs = clean + "." + cls; shutil.copy(clean, dbs)
                fs = forge.Forger(dbs)
                try:
                    if cls == "del":
                        fs.ft1_delete_own_action(adv)
                        if fs.writes < b:
                            fs.ft2_delete_intermediate()
                    elif cls == "rep":
                        # strongest: re-point onto a REAL innocent automation ctx
                        con = sqlite3.connect(dbs)
                        alt = con.execute(
                            """SELECT context_id_bin FROM states
                                WHERE context_parent_id_bin IS NOT NULL
                                  AND context_id_bin != ?
                                ORDER BY last_updated_ts DESC LIMIT 1""", (adv,)).fetchone()
                        con.close()
                        if alt:
                            fs.ft4_reparent(adv, alt[0], ent, new_ctx=alt[0])
                    else:
                        A, T = os.urandom(16), os.urandom(16)
                        fs.inject_state(trig, "on", T, None, bts - 2.0, "FT-7")
                        fs.inject_event("automation_triggered",
                                        {"entity_id": auto, "name": auto}, A, T,
                                        bts - 1.5, "FT-7")
                        fs.inject_state(auto, "on", A, T, bts - 1.3, "FT-7")
                        fs.inject_event("call_service",
                                        {"domain": "lock", "service": "unlock"},
                                        A, T, bts - 1.4, "FT-7")
                except Exception:
                    fs.close(); os.remove(dbs); continue
                # CLOSE BEFORE READING AND BEFORE REMOVING. Forger pins a WAL
                # connection; leaving it open while the file is unlinked and the
                # same path is re-copied for the next class corrupts the new
                # database, which is what "disk image is malformed" was.
                fs.close()
                ns = graph.load(dbs)
                cand = [n for n in ns if n.entity == ent and n.kind == "state"]
                k = cand[-1].key if cand else None
                a = _attr(ns, k) if k else {"verdict": "ABSENT"}
                cx = next((n.ctx for n in ns if n.key == k), None)
                pl, why = _plaus_si(ns, cx) if cx else (False, "no ctx")
                singles[cls] = {"writes": fs.writes, "within_budget": fs.writes <= b,
                                "verdict": a["verdict"], "plaus": pl, "why": why,
                                "reaches": (a["verdict"] == "NAMED_INNOCENT" and pl
                                            and fs.writes <= b)}
                os.remove(dbs)

            ce = 1 if (composed_ok and not any(v["reaches"] for v in singles.values())) else 0
            rows.append({"deployment": "gen_%d_%d" % (int(span), seed),
                         "span_s": span, "seed": seed, "budget_b": b,
                         "composed_reaches": composed_ok,
                         "composed_verdict": comp_attr["verdict"],
                         "singles": singles, "CE_b": ce})
            os.remove(clean)

    n = len(rows)
    k = sum(r["CE_b"] for r in rows)
    usable = [r for r in rows if r["composed_reaches"]]
    return {"stage": 11, "n_deployments": n,
            "composed_succeeded": len(usable),
            "CE_b_exact": stats.clopper_pearson(k, n) if n else None,
            "CE_b_given_composed_succeeded": (
                stats.clopper_pearson(sum(r["CE_b"] for r in usable), len(usable))
                if usable else None),
            "rows": rows,
            "plaus_oracle": "SI-4 + SI-5 PROXY (no renderer on generated deployments); "
                            "the renderer-backed CE_b result remains n=1 on the measured "
                            "HA deployment",
            "GATE_PASS": (k == n and n > 0),
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 7, 5)}
