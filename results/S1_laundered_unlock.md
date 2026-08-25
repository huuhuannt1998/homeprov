# S1 — The Laundered Unlock: measured CLEAN vs ATTACK trace

**Measured** 2026-08-19 on **Home Assistant 2026.7.4**, native aarch64
container (`--cpus=4 --memory=4g`), virtual devices only. Adversary = custom integration
"Weather Plus" (`homeprov_redteam`) installed by dropping a directory into
`/config/custom_components` — the HACS install path. No root, no core modification, no
credential theft, no network egress.

These are renderings produced by **Home Assistant's own logbook processor**
(`homeassistant.components.logbook.processor.EventProcessor`), not our reconstruction of it.

---

## CLEAN — what actually happened

```
  01:35:35  locking    lock.kitchen_door            call_service
  01:35:37  locked     lock.kitchen_door            call_service
  01:35:40  on         input_boolean.owner_present  call_service
  01:35:40  -          automation.arrive_home       triggered by state of input_boolean.owner_present
  01:35:40  unlocking  lock.kitchen_door            Arrive Home
  01:35:42  unlocked   lock.kitchen_door            Arrive Home
  01:35:44  off        input_boolean.owner_present  call_service
  01:35:44  locking    lock.kitchen_door            call_service
  01:35:46  locked     lock.kitchen_door            call_service
  01:35:51  unlocking  lock.kitchen_door            call_service
  01:35:53  unlocked   lock.kitchen_door            call_service
```

The last two rows are the adversary's unlock. HA attributes them to a bare `call_service`,
i.e. to the integration.

## ATTACK — what the homeowner sees after the forgery

```
  01:35:35  locking    lock.kitchen_door            call_service
  01:35:37  locked     lock.kitchen_door            call_service
  01:35:40  on         input_boolean.owner_present  call_service
  01:35:40  -          automation.arrive_home       triggered by state of input_boolean.owner_present
  01:35:40  unlocking  lock.kitchen_door            Arrive Home
  01:35:42  unlocked   lock.kitchen_door            Arrive Home
  01:35:44  off        input_boolean.owner_present  call_service
  01:35:44  locking    lock.kitchen_door            call_service
  01:35:46  locked     lock.kitchen_door            call_service
  01:35:49  on         input_boolean.owner_present  (none)
  01:35:49  -          automation.arrive_home       triggered by state of input_boolean.owner_present
  01:35:51  unlocking  lock.kitchen_door            Arrive Home
  01:35:53  unlocked   lock.kitchen_door            Arrive Home
```

The same physical unlock is now rendered as **"Kitchen Door unlocked — Arrive Home,
triggered by state of input_boolean.owner_present."** Blame has moved to a *named innocent*
automation. This is severity class **SEV-2 (misattribution)**, not the weaker SEV-1
(obscuring): the adversary is not merely hidden, an innocent principal is accused.

---

## The forgery, step by step

| # | Class | Operation | Rows |
|---|---|---|---|
| 1 | `F_inj` | INSERT trigger state `input_boolean.owner_present='on'` @ `ctx=T_fake`, `old_state_id` chained | 1 |
| 2 | `F_inj` | INSERT event `automation_triggered` "Arrive Home" @ `ctx=A_fake, par=T_fake` | 1 |
| 3 | `F_inj` | INSERT state `automation.arrive_home='on'` @ `ctx=A_fake, par=T_fake` | 1 |
| 4 | `F_inj` | INSERT event `call_service` `lock.unlock` @ `ctx=A_fake, par=T_fake` | 1 |
| 5 | `F_rep` | `UPDATE states SET context_id_bin=A_fake, context_parent_id_bin=T_fake WHERE context_id_bin=X` | 2 |
| 6 | `F_del` | `DELETE FROM events WHERE context_id_bin=X` | 1 |
| | | **matched budget b** | **7** |

**Step 5 is the load-bearing one.** It writes *only* context columns.
`content_byte_identical = True` — the
`state_id`, the state value, and `last_updated_ts` of every re-parented row are unchanged.
A commitment over record *content* observes nothing. That is design insight **I-1**, measured.

---

## CE_b — is composition necessary?

Exact enumeration, every single class given its strongest variant at the same budget b=7:

| Arm | Writes | `Attr(α)` | `Plaus` | Reaches it? |
|---|---|---|---|---|
| `F_del` (a) erase naming event | 1 | UNKNOWN (⊥) | ✗ | **No** — SEV-1 only; an unexplained unlock is itself the alarm |
| `F_del` (b) erase the actuation | 3 | ABSENT | ✗ | **No** — the unlock vanishes; no innocent is blamed |
| `F_rep` onto the *real* innocent automation | 3 | **NAMED_INNOCENT** | ✗ | **No** — one automation run would actuate twice, 13.4 s apart, under `mode: single` |
| `F_inj` fabricate a full decoy chain | 5 | INTEGRATION *(decoy: named innocent)* | ✗ | **No** — the true chain survives; competing causes |

**CE_b = 1.** No single class reaches the composed outcome.

The three classes fail in three *different* ways, and each failure is the complement of what
another supplies: deletion removes the cause but offers no replacement; injection offers a
replacement but does not remove the cause; re-parenting redirects blame but inherits the
innocent automation's existing history, producing a temporal impossibility. Only the
composition — delete the true cause, fabricate a *fresh* automation context rather than
borrowing a used one, and relabel the actuation into it — satisfies every constraint at once.

**Caveat, stated plainly.** `CE_b = 1` holds *under the predeclared semantic-invariant
catalog*. `F_rep` alone came closest: it reached the correct attribution and failed only on
two temporal invariants (SI-4 automation-run coherence, SI-5 span within one context).
Against a checker that does not test for duplicate actuation episodes under one automation
run, `F_rep` alone suffices at 3 writes and `CE_b` drops to 0. Those two invariants carry the
entire necessity argument, and they are the first thing an upstream proposal should ask the
platform to enforce.

---

## Four findings the platform's renderer forced on us

Each was discovered because a check failed, not because the code looked right.

1. **The causal edge is a plain mutable column.** `states.context_parent_id_bin` and
   `events.context_parent_id_bin` carry the causal structure and nothing binds them to the
   record they belong to. Content and structure are separate mutable fields.
2. **A cause must precede its effect in wall-clock order.** HA's logbook builds its context
   lookup from rows streaming in time order (`processor.py`), so an injected cause timestamped
   after its effect never resolves. The first forgery attempt failed for exactly this reason.
3. **`old_state_id` must be chained.** The logbook renders a state row only if it can see it as
   a *change*. An injected row with a NULL `old_state_id` is invisible.
4. **The automation's own entity state row is required.** Omitting
   `automation.arrive_home='on'` at `ctx=A_fake` leaves the actuation *unattributed* rather
   than *misattributed* — SEV-1 instead of SEV-2.

Findings 2–4 are what separate a forgery that survives inspection from one that does not, and
none is visible from the schema alone.

## Benign finding, for the false-positive catalog

A **template** lock loses causal context on its own: even a genuine automation-driven unlock
produced a derived state row with `context_parent_id = NULL`. Attribution loss here is benign
and adversary-independent. A defender who treats a missing parent as suspicious will
false-positive on every template entity. Added to the §9.3 benign catalog.

## Reproduction

```
docker run -d --name homeprov-ha --cpus=4 --memory=4g \
  -v $PWD/testbed/ha-config:/config -e TZ=UTC -p 8199:8123 \
  homeassistant/home-assistant:2026.7.4
# scenario runs unattended on EVENT_HOMEASSISTANT_STARTED
python3 analysis/ce_check.py          # exact single-class enumeration
```
Artifacts: `testbed/ha-config/homeprov_out/` (graphs, timelines, `snapshot_B.db`,
`s1_report.json`), `analysis/ce_check_result.json`.
