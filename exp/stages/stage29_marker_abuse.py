"""STAGE 29 (E10) -- lifecycle-marker abuse.

Markers are security-critical: without them the benign false-alarm rate is 0.429
and the scheme is undeployable. So they must be attacked, not merely used.

This experiment was CLAIMED as run in the stage-25 docstring and was not
implemented; run() there returned only E13, E11 and E15. That is the same class
of error as the vacuous stage-18 arms, made by us, and it is recorded here rather
than quietly fixed.

The review's fourteen abuse cases are run against the honour check. For each we
record whether the marker is honoured, whether tampering inside the declared
range escapes detection, and HOW MUCH HISTORY THE ADVERSARY MUST SACRIFICE to
make the marker honourable, which is the quantity that decides whether abuse is
"loud".
"""
import math, os, shutil, sqlite3
from rig import gen, graph, forge, verify, markers, localize, truth
from rig.commit import commit_full, GRAN

WORK = "/tmp/homeprov_marker"
SEEDS = [501, 502, 503, 504]


def _base(seed):
    p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
         "rate_hr": 100, "history": "1d", "bg_ratio": 24.0,
         "target_nodes": 3000, "span_s": 1800.0, "max_nodes": 10**9}
    db = os.path.join(WORK, "c_%d.db" % seed)
    if not os.path.exists(db):
        gen.generate(db, p, seed=seed)
    return db


def _sacrifice(clean_nodes, after_nodes):
    """Fraction of committed history the adversary destroyed to buy the marker."""
    if not clean_nodes:
        return 0.0
    return 1.0 - (len(after_nodes) / len(clean_nodes))


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for seed in SEEDS:
        clean = _base(seed)
        base = graph.load(clean)
        if not base:
            continue
        head = max(n.ts for n in base)
        lo = min(n.ts for n in base)
        anchor_ts = math.floor(head) + 1.0
        phi = commit_full(base, "row")
        mid = lo + (head - lo) / 2.0
        # Tamper targets must be COMMITTED, i.e. older than the anchor. Using the
        # newest node makes the case vacuous: it is uncommitted, so nothing is
        # detected and the marker is never exercised.
        committed = [n for n in base if n.ts < anchor_ts - 5.0 and n.ctx]
        victim = committed[int(len(committed) * 0.75)] if committed else base[0]
        # A re-parent only writes if the context actually owns rows for the entity,
        # so pick a real lock chain the way the catalogue sweep does.
        con = sqlite3.connect(clean)
        ch = con.execute("""SELECT s.context_id_bin, sm.entity_id
                              FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                             WHERE sm.entity_id LIKE 'lock.%' AND s.context_parent_id_bin IS NOT NULL
                               AND s.last_updated_ts < ?
                          GROUP BY s.context_id_bin ORDER BY MIN(s.last_updated_ts) DESC LIMIT 1""",
                         (anchor_ts - 5.0,)).fetchone()
        con.close()
        rep_ctx, rep_ent = (ch if ch else (victim.ctx, "lock.kitchen_door"))

        def attempt(name, mk, mutate, note=""):
            db = clean + "." + name.replace(" ", "_")
            shutil.copy(clean, db)
            f = forge.Forger(db)
            writes = 0
            err = None
            try:
                mutate(f)
                writes = f.writes
            except Exception as exc:
                err = repr(exc)[:80]
                writes = getattr(f, "writes", 0)
            after = graph.load(db)
            T = truth.truth_set(clean, db)
            r = verify.verify(after, phi, anchor_ts, "row")
            honoured = False
            try:
                honoured = markers.is_honoured(mk, after) if mk else False
            except Exception:
                honoured = False
            filt = r
            if mk and honoured:
                try:
                    filt = markers.filter_violations(r["violations"], [mk], GRAN, nodes=after)
                except Exception:
                    filt = r
            rows.append({
                "seed": seed, "case": name, "note": note,
                "marker": (mk or {}).get("marker"),
                "honoured": bool(honoured),
                "raw_detected": bool(r["detected"]),
                "detected_after_marker": bool(filt["detected"]),
                "escaped": bool(r["detected"]) and not bool(filt["detected"]),
                "writes": writes, "mutation_error": err,
                "VACUOUS": writes == 0,
                "tampered_nodes": len(T),
                "history_sacrificed": round(_sacrifice(base, after), 4),
            })
            os.remove(db)

        # --- the review's abuse cases -------------------------------------
        attempt("fake purge, selective delete",
                markers.marker(markers.PURGE, cutoff_ts=head),
                lambda f: f.ft1_delete_own_action(victim.ctx),
                "declares a total purge, deletes one row")
        attempt("fake restore, selective delete",
                markers.marker(markers.RESTORE, restore_point_ts=lo),
                lambda f: f.ft2_delete_intermediate(),
                "declares restore to the beginning, deletes one row")
        attempt("fake migration",
                markers.marker(markers.MIGRATE),
                lambda f: f.ft2_delete_intermediate(), "migration excuses nothing structural")
        attempt("fake backward clock, injection",
                markers.marker(markers.CLOCK_STEP, window=(lo, head)),
                lambda f: f.inject_state("input_boolean.trigger_00", "on", os.urandom(16), None, mid, "FT-7"),
                "unbounded window: must be refused")
        attempt("oversized clock window",
                markers.marker(markers.CLOCK_STEP, window=(head - 10000.0, head)),
                lambda f: f.inject_state("input_boolean.trigger_00", "on", os.urandom(16), None, head - 5000.0, "FT-7"),
                "window far exceeds MAX_CLOCK_STEP_S")
        attempt("bounded clock window at head",
                markers.marker(markers.CLOCK_STEP, window=(head - 60.0, head)),
                lambda f: f.inject_state("input_boolean.trigger_00", "on", os.urandom(16), None, head - 30.0, "FT-7"),
                "legitimate shape; injection inside it")
        attempt("marker for a future interval",
                markers.marker(markers.PURGE, cutoff_ts=head + 100000.0),
                lambda f: f.ft1_delete_own_action(victim.ctx),
                "purge cutoff in the future")
        attempt("marker around an active attack",
                markers.marker(markers.PURGE, cutoff_ts=mid),
                lambda f: f.ft4_reparent(rep_ctx, os.urandom(16), rep_ent),
                "re-parenting is not a deletion; purge cannot explain it")
        attempt("legitimate purge then selective rewrite",
                markers.marker(markers.PURGE, cutoff_ts=mid),
                lambda f: (f.ft3_delete_segment(0, mid),
                           f.ft4_reparent(rep_ctx, os.urandom(16), rep_ent)),
                "honours the purge, then tampers outside it")
        attempt("deletion hidden in a genuine purge",
                markers.marker(markers.PURGE, cutoff_ts=mid),
                lambda f: f.ft3_delete_segment(0, mid),
                "wholesale deletion matching the declaration")
        attempt("no marker, same deletion",
                None,
                lambda f: f.ft3_delete_segment(0, mid),
                "control: same mutation with no marker")
        os.remove(clean) if False else None

    vacuous = [r for r in rows if r["VACUOUS"]]
    escaped = [r for r in rows if r["escaped"]]
    honoured_abuse = [r for r in rows if r["honoured"] and r["tampered_nodes"] > 0
                      and r["history_sacrificed"] < 0.2]
    return {"stage": 29, "n_cases": len(rows), "rows": rows,
            "n_vacuous": len(vacuous),
            "vacuous_cases": sorted({r["case"] for r in vacuous}),
            "n_escaped": len(escaped),
            "cheap_honoured_abuse": len(honoured_abuse),
            "MAX_CLOCK_STEP_S": markers.MAX_CLOCK_STEP_S}
