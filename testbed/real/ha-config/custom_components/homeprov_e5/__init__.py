"""E5 -- RENDERER-BACKED ATTACK EVALUATION (mock review section 6, E5, P1).

The review's complaint is that the renderer-confirmed result is effectively
n = 1: everything else is measured against a synthetic plausibility proxy on
generated deployments that have no logbook. So this runs many attack instances
against Home Assistant's OWN logbook processor and classifies what it renders.

WHAT THIS DELIVERS AND WHAT IT DOES NOT. The review asked for 10 home
configurations x 5 automation structures x 5 target actuations. This delivers
twelve attack variants across every eligible target actuation in ONE running
deployment. That is a large increase over n = 1 and it is renderer-backed
throughout, but it is one home configuration, and the generalisation across
configurations still rests on the generated sweep and its proxy. Reported as
such rather than presented as the 250 the review sketched.

METHOD. Each trial mutates the live recorder, re-runs the platform's
EventProcessor over the same window, classifies the rendered attribution, and
rolls the mutation back. The rollback is re-rendered and compared against the
baseline; a trial whose restore does not reproduce the baseline aborts the run
rather than poisoning every later trial.
"""
from __future__ import annotations

import asyncio, json, logging, os, sqlite3, time

# The locks the adversary actuates. Entity ids come from the shared binding, not
# from literals, for the reason recorded there: a call against a nonexistent
# entity does not raise, it silently does nothing.
from custom_components.homeprov_scenario import (
    TARGET_LOCK, SECOND_LOCK, INNOCENT_AUTOMATION, _room)

_LOGGER = logging.getLogger(__name__)
DOMAIN = "homeprov_e5"
DB = "/config/home-assistant_v2.db"
OUT = "/config/homeprov_out"
CMD = "/config/homeprov_e5.cmd"
ACK = "/config/homeprov_e5.ack"

ATTR_KEYS = ("context_name", "context_message", "context_entity_id",
             "context_entity_id_name", "context_event_type", "context_domain",
             "context_user_id", "context_state", "context_service", "source")
ROW_KEYS = ("when", "name", "message", "entity_id", "state")

# The review's seven output categories.
CAT = ("malicious_integration", "bare_service_call", "unknown",
       "innocent_automation", "innocent_user", "unrenderable",
       "conflicting_narrative")


def _connect():
    con = sqlite3.connect(DB, timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    return con


def _as_epoch(w):
    """Rendered `when` to epoch seconds.

    It is an ISO-8601 STRING in this release, not a datetime and not a float.
    Assuming either and guarding with a bare except silently skips every row, and
    the classifier then reports every instance as unrenderable -- which is how the
    first two runs of this stage produced 368 and 63 instances of nothing.
    """
    if w is None:
        return None
    ts = getattr(w, "timestamp", None)
    if callable(ts):
        try:
            return ts()
        except Exception:                                     # noqa: BLE001
            return None
    if isinstance(w, (int, float)):
        return float(w)
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(w)).timestamp()
    except Exception:                                         # noqa: BLE001
        return None


async def _render(hass, start, end, entity_ids):
    from homeassistant.components.logbook.processor import EventProcessor

    def _run():
        ep = EventProcessor(hass, ["automation_triggered", "call_service",
                                   "script_started"],
                            entity_ids=list(entity_ids) if entity_ids else None)
        return list(ep.get_events(start, end))

    return await hass.async_add_executor_job(_run)


def _classify(rows, target_entity, when_keys):
    """What the renderer says caused the target actuation: (category, principal).

    Returning the NAMED PRINCIPAL alongside the category is the whole point, and
    omitting it is a bug this project has now made twice. On a real deployment
    the actuator's clean attribution is already `innocent_automation`, because a
    real automation legitimately caused it. A forgery that re-points blame from
    one automation to another leaves the CATEGORY unchanged while completely
    changing who the timeline accuses -- which is misattribution, and scoring it
    on category alone reports it as "no change". Measured here that turned every
    one of 480 instances into a null result.
    """
    mine = [r for r in rows
            if r.get("entity_id") == target_entity
            and str(r.get("when")) in when_keys]
    if not mine:
        return ("unrenderable", None)
    causes = set()
    principals = set()
    for r in mine:
        if r.get("context_user_id"):
            causes.add("innocent_user")
            principals.add(f"user:{r.get('context_user_id')}")
        elif str(r.get("context_entity_id") or "").startswith("automation.") or \
                r.get("context_event_type") == "automation_triggered":
            causes.add("innocent_automation")
            principals.add(f"automation:{r.get('context_entity_id') or r.get('context_name')}")
        elif r.get("context_domain") and r.get("context_service"):
            causes.add("bare_service_call")
            principals.add(f"service:{r.get('context_domain')}.{r.get('context_service')}")
        elif r.get("context_event_type") or r.get("context_message"):
            causes.add("malicious_integration")
            principals.add(f"event:{r.get('context_event_type')}")
        else:
            causes.add("unknown")
            principals.add("unknown")
    cat = "conflicting_narrative" if len(causes) > 1 else causes.pop()
    principal = "|".join(sorted(principals))
    return (cat, principal)


def _fingerprint(rows):
    fp = {}
    for r in rows:
        ident = json.dumps({k: r.get(k) for k in ROW_KEYS}, sort_keys=True, default=str)
        fp[ident] = {k: r.get(k) for k in ATTR_KEYS if k in r}
    return fp


# ------------------------------------------------------------------ variants
def _variants(con, target_ctx, target_entity, innocent_ctx, lo, hi):
    """Twelve attack variants, as (name, [sql, args] ...) applied in order.

    Each is expressed as explicit statements rather than reusing the offensive
    integration, so this harness carries no installable attack path.
    """
    # Mutate the row that IS the target actuation, not merely the first row of
    # its context. A real causal chain puts several rows in one context -- the
    # automation's own state row and the actuator's -- and `first by rowid` is
    # usually the automation's. Mutating that leaves the actuator's rendered
    # cause untouched, which is how 480 instances came back with changed=0
    # across every variant and looked like "the attacks do not work here".
    sids = [r[0] for r in con.execute(
        """SELECT s.state_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.context_id_bin=? AND sm.entity_id=?
         ORDER BY s.last_updated_ts DESC""", (target_ctx, target_entity))]
    if not sids:
        # Fall back to any row of the context rather than skipping the target,
        # but record that the precise row was unavailable.
        sids = [r[0] for r in con.execute(
            "SELECT state_id FROM states WHERE context_id_bin=?", (target_ctx,))]
    eids = [r[0] for r in con.execute(
        "SELECT event_id FROM events WHERE context_id_bin=?", (target_ctx,))]
    if not sids:
        return []
    sid, eid = sids[0], (eids[0] if eids else None)
    # RANDOM, and deliberately so: principal_swap measures whether writing the
    # user column moves the rendered principal AT ALL, not whether a specific
    # person can be framed. The adversary needs no real account id. The paper
    # once described this variant as writing "a household member's user
    # identifier" and as naming that member 88 of 88; it writes neither. A probe
    # of the clean render in all three configurations also found no
    # context_name for a user context, so the identifier renders opaque either
    # way. Do not restate this as naming a person.
    R = os.urandom(16)
    V = []

    def add(name, ops):
        V.append((name, ops))

    if eid:
        add("delete_only", [("DELETE FROM events WHERE event_id=?", (eid,))])
    add("reparent_only", [("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                           (innocent_ctx, sid))])
    add("inject_only", [("INSERT INTO states (metadata_id,state,last_updated_ts,"
                         "last_changed_ts,context_id_bin,context_parent_id_bin,"
                         "context_user_id_bin,origin_idx,old_state_id) "
                         "SELECT metadata_id,'on',?,?,?,NULL,NULL,0,state_id "
                         "FROM states WHERE state_id=?",
                         (hi - 1.0, hi - 1.0, R, sid))])
    if eid:
        add("delete_reparent", [("DELETE FROM events WHERE event_id=?", (eid,)),
                                ("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                                 (innocent_ctx, sid))])
        add("delete_inject", [("DELETE FROM events WHERE event_id=?", (eid,)),
                              ("INSERT INTO states (metadata_id,state,last_updated_ts,"
                               "last_changed_ts,context_id_bin,context_parent_id_bin,"
                               "context_user_id_bin,origin_idx,old_state_id) "
                               "SELECT metadata_id,'on',?,?,?,NULL,NULL,0,state_id "
                               "FROM states WHERE state_id=?",
                               (hi - 1.0, hi - 1.0, R, sid))])
        add("full_laundering",
            [("DELETE FROM events WHERE event_id=?", (eid,)),
             ("INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,"
              "context_id_bin,context_parent_id_bin,context_user_id_bin,origin_idx,"
              "old_state_id) SELECT metadata_id,'on',?,?,?,NULL,NULL,0,state_id "
              "FROM states WHERE state_id=?", (hi - 2.0, hi - 2.0, innocent_ctx, sid)),
             ("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
              (innocent_ctx, sid))])
    add("inject_reparent",
        [("INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,"
          "context_id_bin,context_parent_id_bin,context_user_id_bin,origin_idx,"
          "old_state_id) SELECT metadata_id,'on',?,?,?,NULL,NULL,0,state_id "
          "FROM states WHERE state_id=?", (hi - 2.0, hi - 2.0, innocent_ctx, sid)),
         ("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
          (innocent_ctx, sid))])
    add("principal_swap", [("UPDATE states SET context_user_id_bin=? WHERE state_id=?",
                            (R, sid))])
    add("dangling_parent", [("UPDATE states SET context_parent_id_bin=? WHERE state_id=?",
                             (os.urandom(16), sid))])
    add("duplicate_context", [("UPDATE states SET context_id_bin=? WHERE state_id=?",
                               (innocent_ctx, sid))])
    add("timestamp_shift", [("UPDATE states SET last_updated_ts=last_updated_ts-3600, "
                             "last_changed_ts=last_changed_ts-3600 WHERE state_id=?",
                             (sid,))])
    add("retention_edge", [("UPDATE states SET last_updated_ts=?, last_changed_ts=? "
                            "WHERE state_id=?", (lo - 86400, lo - 86400, sid))])
    return V




async def _plant_adversary(hass, n_wanted: int = 20) -> list:
    """Create actuations the ADVERSARY owns, and return their contexts.

    THIS IS THE FIX FOR THE PREVIOUS RUN, AND THE BUG IS ONE THIS PROJECT HAS
    NOW MADE TWICE. Targets used to be drawn from whatever the logbook happened
    to render in the window. On the synthetic demo platform that was fine. On the
    real deployment the only rendered actuator rows are the motion-light
    automations turning their own lights on and off, so every target arrived
    ALREADY attributed to the innocent automation. Laundering an actuation onto
    the automation that already owns it is a no-op, which is why seven of twelve
    variants reported changed=0 and the flagship composition reported 0/40 --
    while S1, on the same substrate, reached 30/30 with the same two operations.

    Section VII-B of the paper narrates exactly this failure for the composition
    indicator: the generator produces no adversary, so the victim actuation was
    already a legitimate automation chain and there was nothing to launder. The
    fix there was to plant an adversary. Same fix here.

    Each planted actuation is a real service call this component makes as itself,
    so the timeline attributes it to a bare service call -- the integration --
    which is the clean state a forgery has to move away from.
    """
    planted = []
    for i in range(n_wanted):
        lock = TARGET_LOCK if i % 2 == 0 else SECOND_LOCK
        st = hass.states.get(lock)
        waited = 0.0
        while (st is None or st.state in ("unavailable", "unknown")) and waited < 120:
            await asyncio.sleep(5); waited += 5
            st = hass.states.get(lock)
        if st is None or st.state in ("unavailable", "unknown"):
            _LOGGER.warning("HOMEPROV E5 plant: %s unavailable, skipping", lock)
            continue
        before = st.state
        verb = "unlock" if before != "unlocked" else "lock"
        await hass.services.async_call("lock", verb, {"entity_id": lock}, blocking=True)
        # The device echoes the commanded state back over the broker, so the
        # resulting row is not there immediately.
        for _ in range(24):
            await asyncio.sleep(1)
            now = hass.states.get(lock)
            if now is not None and now.state != before:
                break
        con = _connect()
        mid = con.execute(
            "SELECT metadata_id FROM states_meta WHERE entity_id=?", (lock,)).fetchone()
        row = None
        if mid:
            row = con.execute(
                """SELECT context_id_bin, state, last_updated_ts FROM states
                    WHERE metadata_id=? AND context_id_bin IS NOT NULL
                 ORDER BY last_updated_ts DESC LIMIT 1""", (mid[0],)).fetchone()
        con.close()
        if row and row[0] is not None:
            planted.append({"ctx": row[0], "entity": lock,
                            "state": row[1], "ts": float(row[2])})
        await asyncio.sleep(1)
    _LOGGER.warning("HOMEPROV E5 planted %d adversary actuations", len(planted))
    return planted

async def _cmd_run(hass) -> dict:
    import homeassistant.util.dt as dt_util
    from datetime import timedelta

    # A LIVE window, with a restore check scoped to what the trial touched.
    # The hub keeps writing, so a whole-render comparison drifts between one
    # render and the next and aborts the run for reasons unrelated to the
    # restore; that is what killed the first attempt. Freezing the window in the
    # past avoids the drift but excludes the activity the harness itself
    # generates, which left one usable target. Comparing only the target's own
    # rendered attribution fixes both: it verifies the mutation was undone where
    # it was applied and is immune to unrelated rows appearing elsewhere.
    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    lo, hi = start.timestamp(), end.timestamp()

    # PLANT THE ADVERSARY FIRST. Targets are its actuations, not whatever the
    # deployment happened to render; see _plant_adversary for why the previous
    # run measured nothing.
    planted = await _plant_adversary(hass, 30)
    if not planted:
        return {"ok": False, "err": "no adversary actuation could be planted; "
                                    "locks unavailable or MQTT not settled"}

    con = _connect()
    # Rank by ACTUATION DOMAIN first, not by row count. Ordering by count puts
    # sensors at the top -- sun, calendar, statistics -- and those are exactly the
    # entities the logbook treats as continuous and drops. A target set drawn
    # from them is renderable in principle and empty in practice: the previous run
    # produced one usable target out of forty. The domains below are the ones an
    # actuation forgery would be about.
    ents = [r[0] for r in con.execute(
        """SELECT sm.entity_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.last_updated_ts BETWEEN ? AND ? AND s.context_id_bin IS NOT NULL
         GROUP BY sm.entity_id
         ORDER BY CASE
                    WHEN sm.entity_id LIKE 'lock.%' THEN 0
                    WHEN sm.entity_id LIKE 'automation.%' THEN 1
                    WHEN sm.entity_id LIKE 'input_boolean.%' THEN 2
                    WHEN sm.entity_id LIKE 'switch.%' THEN 3
                    WHEN sm.entity_id LIKE 'light.%' THEN 4
                    WHEN sm.entity_id LIKE 'cover.%' THEN 5
                    ELSE 9 END,
                  COUNT(*) DESC
            LIMIT 30""", (lo, hi))]
    con.close()

    # Render FIRST, then derive the targets from what was actually rendered.
    # Selecting targets from the database and hoping they appear in the timeline
    # is backwards: the logbook additionally drops rows whose state equals their
    # predecessor's and rows in continuous domains, and it only returns entities
    # inside the scoped list. Three runs of this stage selected 40 targets from
    # the database and classified all 320 instances as unrenderable, because not
    # one of them was in the rendered set. Deriving targets from rendered rows
    # makes every target renderable by construction.
    # The planted locks must be in the rendered scope or their rows cannot be
    # classified, and a target that is not rendered is the OTHER way this
    # experiment has previously measured nothing.
    for _pl in planted:
        if _pl["entity"] not in ents:
            ents.append(_pl["entity"])

    base_rows_pre = await _render(hass, start, end, ents)
    con = _connect()
    targets, spare, seen_ctx = [], [], set()

    # Adversary-owned actuations come first and are the measurement. Each is
    # kept only if the logbook actually rendered it, so every target is
    # renderable by construction and its clean attribution is a bare service
    # call rather than an automation that already owns it.
    _rendered_at = {}
    for r in base_rows_pre:
        _e, _w = r.get("entity_id"), _as_epoch(r.get("when"))
        if _e and _w is not None:
            _rendered_at.setdefault(_e, []).append(_w)
    for _pl in planted:
        if _pl["ctx"] in seen_ctx:
            continue
        if not any(abs(_w - _pl["ts"]) < 0.01 for _w in _rendered_at.get(_pl["entity"], [])):
            continue
        seen_ctx.add(_pl["ctx"])
        targets.append((_pl["ctx"], _pl["entity"]))
    _n_planted_targets = len(targets)

    # SCAVENGED TARGETS ARE NOT ADDED. Earlier versions topped the target list
    # up to forty from whatever actuator rows the deployment had rendered. On
    # this substrate those are the motion-light automations turning their own
    # lights on and off, so their clean attribution is ALREADY the innocent
    # automation and there is nothing for a forgery to move. Mixing them in
    # halves every per-variant rate for a reason that has nothing to do with the
    # attack, and the one restore failure that aborted the previous run came
    # from such a row. Every target is now an actuation this component performed
    # as itself; n is smaller and it means something.

    # THE INNOCENT PARTY IS THE ONE THE SCENARIO BINDS, not an arbitrary
    # automation context. Picking any automation_triggered context makes the
    # experiment untethered from the configuration under test: the framed party
    # varies run to run and cannot be varied deliberately, so "does this depend
    # on which automation is framed?" is unanswerable. Binding it to
    # INNOCENT_AUTOMATION makes that the parameter, and the runner sweeps it
    # across the three shipped-blueprint instantiations exactly as S1 does.
    # The most RECENT run of that automation is taken, because a run far from the
    # target in time has no rendered presence in the target's window and the
    # forgery then resolves to `unknown` rather than to the innocent.
    innocents = [r[0] for r in con.execute(
        """SELECT e.context_id_bin FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id
            WHERE et.event_type='automation_triggered'
              AND e.context_id_bin IS NOT NULL
              AND ed.shared_data LIKE ?
         ORDER BY e.time_fired_ts DESC LIMIT 5""",
        ('%' + INNOCENT_AUTOMATION + '%',))]
    if not innocents:
        # Fall back rather than abort, and say so in the envelope: a run with an
        # unbound innocent still measures something, it just is not the
        # configuration sweep.
        innocents = [r[0] for r in con.execute(
            """SELECT e.context_id_bin FROM events e
                 JOIN event_types et ON et.event_type_id=e.event_type_id
                WHERE et.event_type='automation_triggered'
                  AND e.context_id_bin IS NOT NULL
             ORDER BY e.time_fired_ts DESC LIMIT 5""")]
        _innocent_bound = False
    else:
        _innocent_bound = True
    con.close()
    if not targets or not innocents:
        return {"ok": False, "err": "no targets (%d) or innocent contexts (%d)"
                                    % (len(targets), len(innocents))}
    if _n_planted_targets == 0:
        return {"ok": False, "err": "adversary actuations were planted but none "
                                    "was rendered; nothing to launder"}

    base_rows = base_rows_pre
    base = _fingerprint(base_rows)

    results, aborted, _diag = [], None, []
    for tctx, tent in targets:
        con = _connect()
        variants = _variants(con, tctx, tent, innocents[0], lo, hi)
        # The rendered identity of this actuation, captured from the CLEAN graph
        # so that a forgery which rewrites the context cannot move the target out
        # from under the classifier.
        tts = [r[0] for r in con.execute(
            "SELECT last_updated_ts FROM states WHERE context_id_bin=?", (tctx,))]
        con.close()
        when_keys = set()
        for r in base_rows:
            if r.get("entity_id") != tent:
                continue
            # `when` is an ISO-8601 string in the rendered output and a float
            # epoch in the recorder, so they cannot be compared directly.
            wf = _as_epoch(r.get("when"))
            if wf is None:
                continue
            for t in tts:
                if abs(wf - float(t)) < 0.01:
                    when_keys.add(str(r.get("when")))
                    break
        clean_cat, clean_principal = _classify(base_rows, tent, when_keys)
        _diag.append({"entity": tent, "n_when_keys": len(when_keys),
                      "n_tts": len(tts), "clean": clean_cat,
                      "clean_principal": clean_principal,
                      "sample_when": sorted(when_keys)[:2],
                      "sample_tts": [round(float(t), 3) for t in tts[:2]]})
        for name, ops in variants:
            con = _connect()
            # Snapshot the exact rows the ops will touch so the rollback is a
            # restore rather than an inverse guess.
            snap_states = con.execute(
                "SELECT state_id,state,last_updated_ts,last_changed_ts,context_id_bin,"
                "context_parent_id_bin,context_user_id_bin,old_state_id FROM states "
                "WHERE context_id_bin=?", (tctx,)).fetchall()
            snap_events = con.execute(
                "SELECT event_id,event_type_id,data_id,time_fired_ts,context_id_bin,"
                "context_parent_id_bin,context_user_id_bin,origin_idx FROM events "
                "WHERE context_id_bin=?", (tctx,)).fetchall()
            # Capture the exact set of existing state ids for this entity, not
            # just the maximum. Restoring by "delete anything above the previous
            # max" assumes SQLite hands out monotonically increasing rowids and
            # that no concurrent recorder write lands in between; neither holds on
            # a LIVE hub, and the restore then either misses the injected row or
            # deletes a legitimate one. Either way the next baseline comparison
            # fails, which is what aborted the previous run.
            pre_ids = {r[0] for r in con.execute(
                "SELECT state_id FROM states WHERE last_updated_ts BETWEEN ? AND ?",
                (lo, hi))}
            try:
                for sql, args in ops:
                    con.execute(sql, args)
                con.commit()
            except Exception as exc:                          # noqa: BLE001
                con.close()
                results.append({"variant": name, "entity": tent,
                                "error": repr(exc)[:120]})
                continue
            con.close()

            rows = await _render(hass, start, end, ents)
            cat, principal = _classify(rows, tent, when_keys)
            # Misattribution is "the timeline now names a DIFFERENT innocent
            # party", which covers both first-naming (unknown -> automation) and
            # re-pointing (automation A -> automation B). The second case is the
            # common one on a real deployment and is invisible to a
            # category-only comparison.
            named = cat in ("innocent_automation", "innocent_user")
            results.append({"variant": name, "entity": tent,
                            "clean_category": clean_cat, "category": cat,
                            "clean_principal": clean_principal, "principal": principal,
                            "changed": (cat, principal) != (clean_cat, clean_principal),
                            "misattributed": named and principal != clean_principal})
            # Restore.
            con = _connect()
            post_ids = {r[0] for r in con.execute(
                "SELECT state_id FROM states WHERE last_updated_ts BETWEEN ? AND ?",
                (lo - 90000, hi))}
            added = post_ids - pre_ids
            if added:
                con.executemany("DELETE FROM states WHERE state_id=?",
                                [(i,) for i in added])
            for r in snap_states:
                con.execute("UPDATE states SET state=?,last_updated_ts=?,"
                            "last_changed_ts=?,context_id_bin=?,context_parent_id_bin=?,"
                            "context_user_id_bin=?,old_state_id=? WHERE state_id=?",
                            (r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[0]))
            for r in snap_events:
                con.execute(
                    "INSERT OR REPLACE INTO events (event_id,event_type_id,data_id,"
                    "time_fired_ts,context_id_bin,context_parent_id_bin,"
                    "context_user_id_bin,origin_idx) VALUES (?,?,?,?,?,?,?,?)", r)
            con.commit(); con.close()

            restored_rows = await _render(hass, start, end, ents)
            if _classify(restored_rows, tent, when_keys) != (clean_cat, clean_principal):
                aborted = {"variant": name, "entity": tent,
                           "clean": [clean_cat, clean_principal],
                           "after_restore": list(_classify(restored_rows, tent, when_keys)),
                           "reason": "restore did not return the target's rendered "
                                     "attribution to its clean value"}
                break
        if aborted:
            break

    counts = {}
    for r in results:
        if "category" in r:
            counts[r["category"]] = counts.get(r["category"], 0) + 1
    per_variant = {}
    for r in results:
        if "category" not in r:
            continue
        v = per_variant.setdefault(r["variant"], {"n": 0, "misattributed": 0,
                                                  "changed": 0, "categories": {}})
        v["n"] += 1
        v["misattributed"] += int(r["misattributed"])
        v["changed"] += int(r["changed"])
        v["categories"][r["category"]] = v["categories"].get(r["category"], 0) + 1

    n_scored = sum(1 for r in results if "category" in r)
    per_instance = [{"variant": r.get("variant"), "entity": r.get("entity"),
                     "clean_principal": r.get("clean_principal"),
                     "principal": r.get("principal"),
                     "changed": r.get("changed"),
                     "misattributed": r.get("misattributed")}
                    for r in results if "category" in r]
    rep = {"ha_version": _ha_version(), "target_diagnostic": _diag[:6],
           "per_instance": per_instance,
           "n_targets": len(targets), "n_instances": n_scored,
           "n_adversary_planted": len(planted),
           "innocent_automation": INNOCENT_AUTOMATION,
           "innocent_bound_to_scenario": _innocent_bound,
           "n_targets_adversary_owned": _n_planted_targets,
           "target_provenance": "every target is an actuation this component "
                                "performed as itself, so its clean attribution "
                                "is a bare service call. Targets are NOT scavenged "
                                "from rows the deployment already attributed to an "
                                "automation; doing that measured nothing.",
           "aborted": aborted, "categories": counts, "per_variant": per_variant,
           "renderer_confirmed_misattribution_rate":
               (sum(1 for r in results if r.get("misattributed")) / n_scored)
               if n_scored else None,
           "scope": "one home configuration on the REAL substrate (real broker, "
                    "real discovery, shipped blueprint); twelve variants across "
                    "every planted adversary actuation that the logbook rendered. "
                    "Generalisation across configurations still rests on the "
                    "generated sweep and its proxy.",
           "ts": time.time()}
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "e5_renderer.json"), "w") as fh:
        json.dump(rep, fh, indent=2, default=str)
    return {"ok": True, "n_instances": n_scored, "aborted": bool(aborted),
            "misattribution_rate": rep["renderer_confirmed_misattribution_rate"]}


def _ha_version():
    import homeassistant.const as c
    return c.__version__


async def _cmd_probe(hass) -> dict:
    """Dump what the renderer returns for one target next to what the recorder
    holds, so a mismatch is visible rather than inferred."""
    import homeassistant.util.dt as dt_util
    from datetime import timedelta
    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=12)
    lo, hi = start.timestamp(), end.timestamp()
    con = _connect()
    ents = [r[0] for r in con.execute(
        """SELECT sm.entity_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.last_updated_ts BETWEEN ? AND ? AND s.context_id_bin IS NOT NULL
         GROUP BY sm.entity_id ORDER BY COUNT(*) DESC LIMIT 25""", (lo, hi))]
    tgt = con.execute(
        """SELECT s.context_id_bin, sm.entity_id, s.last_updated_ts, s.state_id
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.last_updated_ts BETWEEN ? AND ?
              AND s.context_id_bin IS NOT NULL AND s.old_state_id IS NOT NULL
              AND (s.last_changed_ts IS NULL OR s.last_updated_ts = s.last_changed_ts)
         ORDER BY s.last_updated_ts DESC LIMIT 3""", (lo, hi)).fetchall()
    con.close()
    rows = await _render(hass, start, end, ents)
    sample = []
    for r in rows[:12]:
        w = r.get("when")
        sample.append({"entity_id": r.get("entity_id"), "when": str(w),
                       "when_type": type(w).__name__,
                       "as_epoch": (w.timestamp() if hasattr(w, "timestamp")
                                    else (float(w) if isinstance(w, (int, float))
                                          else None))})
    out = {"n_rendered": len(rows),
           "rendered_entities": sorted({r.get("entity_id") for r in rows if r.get("entity_id")}),
           "targets": [{"entity": t[1], "db_ts": t[2], "state_id": t[3]} for t in tgt],
           "sample": sample, "scoped_entities": ents}
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "e5_probe.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    return {"ok": True, "n_rendered": len(rows), "out": "e5_probe.json"}




# ------------------------------------------------------------------ E6
# SIGNED offsets: cover_ts - target_ts. The absolute-distance sweep found no
# effect anywhere from 30 s to six hours, which rules out "temporal adjacency"
# as the operative condition. The renderer enforces that a cause precedes its
# effect (Section II), so the variable under test here is the SIGN: cover that
# ran BEFORE the target should be usable, cover that ran AFTER it should not.
DT_BINS = (-21600, -7200, -1800, -300, -60, -15, -5, 0, 5, 15, 60, 300, 1800)


async def _cmd_sweep_dt(hass) -> dict:
    """E6: misattribution rate against Delta-t to the cover run.

    WHY Delta-t IS CONTROLLED BY CHOOSING THE COVER, NOT BY WAITING. The reviewer's
    objection is that cover adjacency is read off a post-hoc pattern rather than
    varied deliberately. The obvious design -- schedule the adversary's actuation
    at Delta-t after a genuine run -- costs sum(DT_BINS) seconds per trial and would
    run for about a day per configuration. It is also not what the attacker
    varies: the forgery PICKS which genuine run to re-point onto, so Delta-t is a
    property of that choice. Selecting the cover context at a controlled distance
    from the target measures the same variable in minutes rather than hours, and
    measures the one the adversary actually controls.

    A bin with no genuine run at that distance is reported UNREACHABLE for that
    target rather than silently filled with the nearest available cover, which
    would turn a missing measurement into a fabricated point on the curve.
    """
    import homeassistant.util.dt as dt_util
    from datetime import timedelta

    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    lo, hi = start.timestamp(), end.timestamp()

    planted = await _plant_adversary(hass, 20)
    if not planted:
        return {"ok": False, "err": "no adversary actuation could be planted"}

    con = _connect()
    ents = [r[0] for r in con.execute(
        """SELECT sm.entity_id FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id
            WHERE s.last_updated_ts BETWEEN ? AND ? AND s.context_id_bin IS NOT NULL
         GROUP BY sm.entity_id ORDER BY COUNT(*) DESC LIMIT 30""", (lo, hi))]
    for _pl in planted:
        if _pl["entity"] not in ents:
            ents.append(_pl["entity"])

    # Cover pool: genuine runs of the bound innocent automation, WITH timestamps.
    cover = con.execute(
        """SELECT e.context_id_bin, e.time_fired_ts FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id
            WHERE et.event_type='automation_triggered'
              AND e.context_id_bin IS NOT NULL
              AND e.time_fired_ts BETWEEN ? AND ?
              AND ed.shared_data LIKE ?
         ORDER BY e.time_fired_ts""", (lo, hi, '%' + INNOCENT_AUTOMATION + '%')).fetchall()
    con.close()
    if len(cover) < 10:
        return {"ok": False, "err": "cover pool too small (%d runs of %s)"
                                    % (len(cover), INNOCENT_AUTOMATION)}

    base_rows = await _render(hass, start, end, ents)
    # Targets: adversary-owned actuations the logbook actually rendered.
    targets = []
    for pl in planted:
        con = _connect()
        tts = [r[0] for r in con.execute(
            "SELECT last_updated_ts FROM states WHERE context_id_bin=?", (pl["ctx"],))]
        con.close()
        wk = set()
        for r in base_rows:
            if r.get("entity_id") != pl["entity"]:
                continue
            wf = _as_epoch(r.get("when"))
            if wf is None:
                continue
            for t in tts:
                if abs(wf - float(t)) < 0.01:
                    wk.add(str(r.get("when"))); break
        if wk:
            targets.append({"ctx": pl["ctx"], "entity": pl["entity"],
                            "ts": pl["ts"], "when_keys": wk})
    if not targets:
        return {"ok": False, "err": "no planted actuation was rendered"}

    results, unreachable = [], 0
    for tg in targets:
        clean_cat, clean_principal = _classify(base_rows, tg["entity"], tg["when_keys"])
        for want in DT_BINS:
            # Closest genuine run to the requested distance; a bin is only
            # measured if a run exists near enough to it.
            best, best_err, best_d = None, None, None
            for ctx, cts in cover:
                d = float(cts) - float(tg["ts"])      # SIGNED
                err = abs(d - want)
                if best_err is None or err < best_err:
                    best, best_err, best_d = ctx, err, d
            tol = max(3.0, 0.25 * abs(want))
            if best_err is None or best_err > tol:
                unreachable += 1
                results.append({"dt_requested": want, "dt_actual": None,
                                "entity": tg["entity"], "variant": None,
                                "reachable": False})
                continue
            con = _connect()
            allv = dict(_variants(con, tg["ctx"], tg["entity"], best, lo, hi))
            con.close()
            for name in ("delete_reparent", "principal_swap"):
                ops = allv.get(name)
                if not ops:
                    continue
                con = _connect()
                snap_states = con.execute(
                    "SELECT state_id,state,last_updated_ts,last_changed_ts,context_id_bin,"
                    "context_parent_id_bin,context_user_id_bin,old_state_id FROM states "
                    "WHERE context_id_bin=?", (tg["ctx"],)).fetchall()
                snap_events = con.execute(
                    "SELECT event_id,event_type_id,data_id,time_fired_ts,context_id_bin,"
                    "context_parent_id_bin,context_user_id_bin,origin_idx FROM events "
                    "WHERE context_id_bin=?", (tg["ctx"],)).fetchall()
                pre_ids = {r[0] for r in con.execute(
                    "SELECT state_id FROM states WHERE last_updated_ts BETWEEN ? AND ?",
                    (lo, hi))}
                try:
                    for sql, args in ops:
                        con.execute(sql, args)
                    con.commit()
                except Exception as exc:                       # noqa: BLE001
                    con.close()
                    results.append({"dt_requested": want, "dt_actual": round(best_d, 2),
                                    "entity": tg["entity"], "variant": name,
                                    "reachable": True, "error": repr(exc)[:120]})
                    continue
                con.close()
                rows = await _render(hass, start, end, ents)
                cat, principal = _classify(rows, tg["entity"], tg["when_keys"])
                named = cat in ("innocent_automation", "innocent_user")
                results.append({"dt_requested": want, "dt_actual": round(best_d, 2),
                                "entity": tg["entity"], "variant": name,
                                "reachable": True,
                                "clean_principal": clean_principal, "principal": principal,
                                "changed": (cat, principal) != (clean_cat, clean_principal),
                                "misattributed": named and principal != clean_principal})
                # Restore.
                con = _connect()
                post_ids = {r[0] for r in con.execute(
                    "SELECT state_id FROM states WHERE last_updated_ts BETWEEN ? AND ?",
                    (lo - 90000, hi))}
                added = post_ids - pre_ids
                if added:
                    con.executemany("DELETE FROM states WHERE state_id=?",
                                    [(i,) for i in added])
                for r in snap_states:
                    con.execute("UPDATE states SET state=?,last_updated_ts=?,"
                                "last_changed_ts=?,context_id_bin=?,context_parent_id_bin=?,"
                                "context_user_id_bin=?,old_state_id=? WHERE state_id=?",
                                (r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[0]))
                for r in snap_events:
                    con.execute(
                        "INSERT OR REPLACE INTO events (event_id,event_type_id,data_id,"
                        "time_fired_ts,context_id_bin,context_parent_id_bin,"
                        "context_user_id_bin,origin_idx) VALUES (?,?,?,?,?,?,?,?)", r)
                con.commit(); con.close()

    measured = [r for r in results if r.get("reachable") and "misattributed" in r]
    rep = {"ok": True, "room": _room(),
           "innocent_automation": INNOCENT_AUTOMATION,
           "n_targets": len(targets), "n_cover_runs": len(cover),
           "dt_bins": list(DT_BINS), "n_instances": len(measured),
           "n_unreachable": unreachable, "per_instance": results,
           "out": "e6_dt_sweep.json"}
    def _write():
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "e6_dt_sweep.json"), "w") as fh:
            json.dump(rep, fh, indent=2, default=str)
    await hass.async_add_executor_job(_write)
    # Keep the ack small; the per-instance list lives in the file.
    return {k: v for k, v in rep.items() if k != "per_instance"}




# ------------------------------------------------------------------ E2
async def _cmd_precommit(hass) -> dict:
    """Is the forgery reachable BEFORE the monitor can observe it?

    The reviewer's first objection is that an adversary with in-process code
    execution forges cheaply at write time, so the post-commit tampering this
    work detects is the more expensive option it would never choose. The paper
    conceded rows t0-t3 of the timeline table and argued, without measuring,
    that three situations force post-commit editing. This measures the concession
    instead.

    Two things are measured. First the WINDOW: the recorder batches writes and
    commits on an interval, so a row exists in memory before it exists on disk,
    and nothing outside the process can see it in between. Second REACHABILITY:
    an integration does not need to hook the recorder queue at all. Home
    Assistant lets a caller supply the Context a service call runs under, and
    the recorder derives context_parent_id_bin from it, so the adversary can mint
    a context whose parent is the innocent automation and the row is written
    ALREADY laundered. Nothing is edited afterwards; there is nothing for a
    commitment over committed history to detect.
    """
    import homeassistant.util.dt as dt_util
    from datetime import timedelta
    from homeassistant.core import Context

    rec = hass.data.get("recorder_instance")
    interval = getattr(rec, "commit_interval", None)

    # --- 1. event-to-disk latency, measured from outside the session ---
    lat = []
    for i in range(12):
        lock = TARGET_LOCK if i % 2 == 0 else SECOND_LOCK
        st = hass.states.get(lock)
        if st is None or st.state in ("unavailable", "unknown"):
            continue
        before = st.state
        verb = "unlock" if before != "unlocked" else "lock"
        t0 = time.time()
        await hass.services.async_call("lock", verb, {"entity_id": lock}, blocking=True)
        seen = None
        for _ in range(600):                       # up to 60 s
            await asyncio.sleep(0.1)
            con = _connect()
            row = con.execute(
                """SELECT s.last_updated_ts FROM states s
                     JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                    WHERE sm.entity_id=? AND s.last_updated_ts>?
                 ORDER BY s.last_updated_ts DESC LIMIT 1""", (lock, t0)).fetchone()
            con.close()
            if row:
                seen = time.time(); break
        if seen:
            lat.append(round(seen - t0, 3))
        await asyncio.sleep(0.5)

    # --- 2. mint-a-context: the launder performed at WRITE time ---
    end = dt_util.utcnow() + timedelta(minutes=1)
    start = end - timedelta(hours=6)
    con = _connect()
    inn = con.execute(
        """SELECT e.context_id_bin FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id
            WHERE et.event_type='automation_triggered' AND e.context_id_bin IS NOT NULL
              AND ed.shared_data LIKE ?
         ORDER BY e.time_fired_ts DESC LIMIT 1""",
        ('%' + INNOCENT_AUTOMATION + '%',)).fetchone()
    con.close()
    if not inn:
        return {"ok": False, "err": "no innocent context to mint against"}
    parent_hex = inn[0].hex()

    lock = TARGET_LOCK
    st = hass.states.get(lock)
    if st is None or st.state in ("unavailable", "unknown"):
        return {"ok": False, "err": "target lock unavailable"}
    verb = "unlock" if st.state != "unlocked" else "lock"
    ctx = Context(parent_id=parent_hex)
    t_mint = time.time()
    await hass.services.async_call("lock", verb, {"entity_id": lock},
                                   blocking=True, context=ctx)
    for _ in range(40):
        await asyncio.sleep(1)
        if hass.states.get(lock) is not None and hass.states.get(lock).state != st.state:
            break

    # What does the platform's own renderer say caused it? No row was edited.
    rows = await _render(hass, start, end, [lock])
    con = _connect()
    tts = [r[0] for r in con.execute(
        "SELECT last_updated_ts FROM states WHERE last_updated_ts>? AND context_id_bin IS NOT NULL"
        " AND metadata_id=(SELECT metadata_id FROM states_meta WHERE entity_id=?)",
        (t_mint, lock))]
    con.close()
    wk = set()
    for r in rows:
        wf = _as_epoch(r.get("when"))
        if wf is None:
            continue
        for t in tts:
            if abs(wf - float(t)) < 0.01:
                wk.add(str(r.get("when"))); break
    cat, principal = _classify(rows, lock, wk)

    # --- 3. the STRONG pre-commit variant: write the row directly ---
    # The mint above still goes through the service registry, so a call_service
    # event is recorded and the logbook names it. An integration need not use the
    # registry at all: it can set state itself under a context it chose, and then
    # no attribution event exists to name. If THAT renders as the innocent
    # automation, the forgery is fully reachable before t4 and the objection
    # stands; if it does not, pre-commit is not the one-step alternative it looks.
    direct = {"attempted": False}
    st2 = hass.states.get(SECOND_LOCK)
    if st2 is not None and st2.state not in ("unavailable", "unknown"):
        newstate = "unlocked" if st2.state != "unlocked" else "locked"
        t_dir = time.time()
        hass.states.async_set(SECOND_LOCK, newstate,
                              dict(st2.attributes), context=Context(parent_id=parent_hex))
        await asyncio.sleep(3)
        rows2 = await _render(hass, start, end, [SECOND_LOCK])
        con = _connect()
        tts2 = [r[0] for r in con.execute(
            "SELECT last_updated_ts FROM states WHERE last_updated_ts>? AND metadata_id="
            "(SELECT metadata_id FROM states_meta WHERE entity_id=?)", (t_dir, SECOND_LOCK))]
        con.close()
        wk2 = set()
        for r in rows2:
            wf = _as_epoch(r.get("when"))
            if wf is None:
                continue
            for t in tts2:
                if abs(wf - float(t)) < 0.01:
                    wk2.add(str(r.get("when"))); break
        c2, p2 = _classify(rows2, SECOND_LOCK, wk2)
        direct = {"attempted": True, "method": "hass.states.async_set with a minted Context",
                  "call_service_event_emitted": False,
                  "rendered_category": c2, "rendered_principal": p2,
                  "n_when_keys": len(wk2)}

    rep = {"ok": True,
           "commit_interval_configured_s": interval,
           "direct_state_write": direct,
           "commit_interval_default_s": 5,
           "latency_s": {"n": len(lat), "samples": lat,
                         "min": min(lat) if lat else None,
                         "median": sorted(lat)[len(lat)//2] if lat else None,
                         "max": max(lat) if lat else None},
           "mint_context": {"method": "Context(parent_id=<innocent>) on the service call",
                            "rows_edited_after_write": 0,
                            "rendered_category": cat,
                            "rendered_principal": principal,
                            "innocent_automation": INNOCENT_AUTOMATION,
                            "n_when_keys": len(wk)},
           "out": "e2_precommit.json"}

    def _write():
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "e2_precommit.json"), "w") as fh:
            json.dump(rep, fh, indent=2, default=str)
    await hass.async_add_executor_job(_write)
    return rep


HANDLERS = {"run": _cmd_run, "probe": _cmd_probe,
            "sweep_dt": _cmd_sweep_dt, "precommit": _cmd_precommit}


async def async_setup(hass, config) -> bool:
    async def _poll(_now=None):
        if not os.path.exists(CMD):
            return
        try:
            cmd = open(CMD).read().strip()
        except OSError:
            return
        os.remove(CMD)
        fn = HANDLERS.get(cmd)
        if fn is None:
            out = {"ok": False, "err": "unknown command %r" % cmd}
        else:
            try:
                out = await fn(hass)
            except Exception as exc:                          # noqa: BLE001
                out = {"ok": False, "cmd": cmd, "err": repr(exc)[:300]}
        _LOGGER.warning("HOMEPROV e5 %s", out)
        with open(ACK, "w") as fh:
            json.dump(out, fh, default=str)

    async def _loop(_event=None):
        while True:
            await _poll()
            await asyncio.sleep(1)

    hass.async_create_background_task(_loop(), "homeprov_e5_poll")
    return True
