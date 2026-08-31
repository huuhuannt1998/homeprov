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
    base_rows_pre = await _render(hass, start, end, ents)
    con = _connect()
    targets, spare, seen_ctx = [], [], set()
    # Targets are ACTUATORS ONLY. "What caused this?" is a question an
    # investigator asks about a lock or a light, not about an automation's own
    # state row -- the automation was caused by its trigger, and its clean
    # attribution is legitimately `unknown`, so including automation entities
    # measures the wrong thing. It also crowds out the actuators entirely once
    # event-bearing contexts are preferred, because automation contexts always
    # own an automation_triggered event: the first attempt at that preference
    # made all forty targets automations and inverted every per-variant result.
    ACTUATOR_DOMAINS = ("lock.", "light.", "switch.", "cover.")
    for r in base_rows_pre:
        ent = r.get("entity_id")
        wf = _as_epoch(r.get("when"))
        if not ent or wf is None:
            continue
        if not ent.startswith(ACTUATOR_DOMAINS):
            continue
        row = con.execute(
            """SELECT s.context_id_bin FROM states s
                 JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                WHERE sm.entity_id=? AND ABS(s.last_updated_ts-?) < 0.01
                  AND s.context_id_bin IS NOT NULL LIMIT 1""", (ent, wf)).fetchone()
        if not row or row[0] in seen_ctx:
            continue
        # Does this context own an EVENT row? Four of the twelve variants --
        # every deletion-based one, including the flagship composition -- can
        # only be built when it does. On the synthetic substrate almost every
        # context did; on the real one most do not, and the first real run
        # produced n=2 for those four cells while the other eight got n=40.
        # An n=2 cell is not a measurement, and reporting 0/2 beside 0/40 would
        # read as "the composition fails on real deployments" when it simply did
        # not run. Contexts owning an event are therefore taken FIRST, and the
        # remainder fill in behind them.
        has_ev = con.execute(
            "SELECT 1 FROM events WHERE context_id_bin=? LIMIT 1", (row[0],)).fetchone()
        seen_ctx.add(row[0])
        (targets if has_ev else spare).append((row[0], ent))
        if len(targets) >= 40:
            break
    if len(targets) < 40:
        targets.extend(spare[:40 - len(targets)])
    innocents = [r[0] for r in con.execute(
        """SELECT DISTINCT e.context_id_bin FROM events e
             JOIN event_types et ON et.event_type_id=e.event_type_id
            WHERE et.event_type='automation_triggered' AND e.context_id_bin IS NOT NULL
            LIMIT 5""")]
    con.close()
    if not targets or not innocents:
        return {"ok": False, "err": "no targets (%d) or innocent contexts (%d)"
                                    % (len(targets), len(innocents))}

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
    rep = {"ha_version": _ha_version(), "target_diagnostic": _diag[:6],
           "n_targets": len(targets), "n_instances": n_scored,
           "aborted": aborted, "categories": counts, "per_variant": per_variant,
           "renderer_confirmed_misattribution_rate":
               (sum(1 for r in results if r.get("misattributed")) / n_scored)
               if n_scored else None,
           "scope": "one home configuration; twelve variants across every eligible "
                    "target actuation. The review asked for ten configurations; "
                    "generalisation across configurations still rests on the "
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


HANDLERS = {"run": _cmd_run, "probe": _cmd_probe}


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
