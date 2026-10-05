"""STAGE 31 (E3-B2c) — the renderer-closure baseline, and what it exposes.

The mock review asked for THREE record-level baselines, not two: B2a commits the
chosen content subset, B2b commits the whole physical row, and B2c commits
"every row/field needed to reconstruct attribution". Stage 20 delivered the first
two. The third could not be built honestly until the closure was measured rather
than guessed, which is what E4 did against HA 2026.7.4's own logbook processor.

E4 returned fourteen attribution-relevant fields. Three are bound by NO scheme in
this rig:

    context_user_id_bin (states and events)   who the timeline names as a PERSON
    old_state_id                              render eligibility
    last_changed_ts                           render eligibility

The first is a genuine attribution channel and the fourth identity omission this
line of construction has produced, after parent identity (2026-08-20), node key
(E16), and node context (E11). The other two are not attribution values at all:
they decide whether a row is DISPLAYED. Rewriting either removes an actuation
from the timeline while leaving the row in the database, so a verifier reading
the database sees nothing missing and the investigator reading the timeline sees
nothing at all. That is deletion with none of deletion's evidence.

This stage therefore runs two things:

  (1) the twelve PREDECLARED classes against five schemes, so B2c takes its place
      beside the published columns on identical deployments and seeds; and

  (2) two classes E4 exposed, run separately and labelled as POST-PREDECLARATION
      so they are never pooled with the catalogue: FT-U reassigns an action to a
      household member by rewriting context_user_id_bin, and FT-E hides an
      actuation from the renderer by breaking its eligibility.

Reported whatever it shows, including if B2c wins.
"""
import math, os, shutil, sqlite3
from rig import (gen, graph, forge, verify, localize, metrics, truth,
                 baselines, stats, capability)
from rig.commit import commit_full
from stages.stage20_fairbaseline import _chain, _apply

WORK = "/tmp/homeprov_b2c"
ARMS = [(1800.0, 5000), (7200.0, 7000)]
SEEDS = [81, 82, 83, 84, 85, 86]
SCHEMES = ("homeprov", "b2", "b2b", "b2c", "row")


def _ft_user(db) -> int:
    """FT-U — reattribute an action to a user account.

    The adversary does not touch the causal edge and does not delete anything.
    It writes a user id onto the rows of the actuation's context, and the 2026.7
    timeline then credits that account rather than the true cause. Measured in E4
    as attribution-relevant on both tables.

    THE ID IS RANDOM (os.urandom below), so it matches no real account. This
    docstring previously said the attack "reassigns an action to a household
    member" and that the timeline "names a person" -- neither of which the code
    does, and both of which reached the manuscript, including its abstract,
    before being caught. A separate probe also showed the renderer emits no
    context_name for a user context at all: the identifier renders opaque. Say
    what the code writes, not what the attack is meant to evoke.
    """
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.context_id_bin FROM states s
                         JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%' AND s.context_id_bin IS NOT NULL
                     ORDER BY s.last_updated_ts DESC LIMIT 1""").fetchone()
    if not r:
        con.close(); return 0
    ctx, uid = r[0], os.urandom(16)
    n = con.execute("UPDATE states SET context_user_id_bin=? WHERE context_id_bin=?",
                    (uid, ctx)).rowcount
    n += con.execute("UPDATE events SET context_user_id_bin=? WHERE context_id_bin=?",
                     (uid, ctx)).rowcount
    con.commit(); con.close()
    return n


def _ft_elig(db) -> int:
    """FT-E — hide an actuation without deleting it.

    apply_states_filters drops a state row from the logbook unless it has an
    old_state whose value differs and unless last_updated_ts equals
    last_changed_ts. Breaking either predicate removes the row from every
    rendered timeline while the row itself stays in the table.
    """
    con = sqlite3.connect(db)
    r = con.execute("""SELECT s.state_id FROM states s
                         JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        WHERE sm.entity_id LIKE 'lock.%' AND s.old_state_id IS NOT NULL
                     ORDER BY s.last_updated_ts DESC LIMIT 1""").fetchone()
    if not r:
        con.close(); return 0
    n = con.execute("UPDATE states SET last_changed_ts=last_changed_ts-900, "
                    "old_state_id=NULL WHERE state_id=?", (r[0],)).rowcount
    con.commit(); con.close()
    return n


def _detect(after, phi, anchor_ts) -> dict:
    """Detection under each scheme. b2/b2b use their dedicated baseline callers
    so the published columns keep their exact semantics; b2c and row go through
    the generic verifier, which differs only in which hash it recomputes."""
    return {
        "homeprov": verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")["detected"],
        "b2":  baselines.b2_record_level(after, phi["b2"], anchor_ts)["detected"],
        "b2b": baselines.b2b_full_row(after, phi["b2b"], anchor_ts)["detected"],
        "b2c": verify.verify(after, phi["b2c"], anchor_ts, "b2c")["detected"],
        "row": verify.verify(after, phi["row"], anchor_ts, "row")["detected"],
    }


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows, extra = [], []
    fts = ["FT-%d" % i for i in range(1, 13)]

    for span, target in ARMS:
        for seed in SEEDS:
            p = {"n_dev": 25, "n_aut": 15, "n_int": 10, "interlock": 0.3,
                 "rate_hr": 100, "history": "1d", "bg_ratio": 4.4,
                 "target_nodes": target, "span_s": span, "max_nodes": 10**9}
            clean = os.path.join(WORK, "c.db")
            gen.generate(clean, p, seed=seed)
            base = graph.load(clean)
            head = max(n.ts for n in base)
            anchor_ts = math.floor(head) + 1.0
            phi = {s: commit_full(base, s) for s in SCHEMES}
            ch = _chain(clean, head - 2.0)
            if not ch:
                os.remove(clean); continue
            adv, ent, bts = ch

            for ft in fts:
                db = clean + "." + ft
                shutil.copy(clean, db)
                f = forge.Forger(db)
                try:
                    _apply(ft, f, adv, ent, bts, db, anchor_ts)
                except Exception:
                    os.remove(db); continue
                if f.writes == 0:
                    os.remove(db); continue
                after = graph.load(db)
                T = truth.truth_set(clean, db)
                if not T:
                    os.remove(db); continue
                d = _detect(after, phi, anchor_ts)
                hp = verify.verify(after, phi["homeprov"], anchor_ts, "homeprov")
                Q = localize.greedy(after, hp["violations"]) if hp["detected"] else set()
                rows.append({"ft": ft, "seed": seed, "span_s": span,
                             "writes_b": f.writes, "T": len(T),
                             **{k: 1.0 if v else 0.0 for k, v in d.items()},
                             "OQ": metrics.oq(Q, T, len(after))})
                os.remove(db)

            # The two post-predeclaration classes, kept in a separate table.
            for name, fn in (("FT-U", _ft_user), ("FT-E", _ft_elig)):
                db = clean + "." + name
                shutil.copy(clean, db)
                w = fn(db)
                if not w:
                    os.remove(db); continue
                after = graph.load(db)
                d = _detect(after, phi, anchor_ts)
                extra.append({"ft": name, "seed": seed, "span_s": span, "writes": w,
                              **{k: 1.0 if v else 0.0 for k, v in d.items()}})
                os.remove(db)
            os.remove(clean)

    def _tab(src, keys):
        out = {}
        for ft in keys:
            rs = [r for r in src if r["ft"] == ft]
            if not rs:
                out[ft] = {"n": 0}; continue
            out[ft] = {"n": len(rs),
                       **{s: stats.clopper_pearson(int(sum(r[s] for r in rs)), len(rs))
                          for s in SCHEMES}}
        return out

    per = _tab(rows, fts)
    post = _tab(extra, ["FT-U", "FT-E"])

    # The question E3 exists to answer, stated as a comparison rather than a
    # narrative: does any scheme detect something B2c misses, and vice versa.
    sep = {}
    for a in SCHEMES:
        for b in SCHEMES:
            if a >= b:
                continue
            allr = rows + extra
            sep["%s>%s" % (a, b)] = sum(1 for r in allr if r[a] > r[b])
    return {"stage": 31, "n_predeclared": len(rows), "n_post": len(extra),
            "schemes": list(SCHEMES), "per_ft": per, "post_predeclaration": post,
            "strict_separations": sep,
            "capability": capability.record("mal_integration_v1",
                                            "in_process_integration", 0, 7, 5)}
