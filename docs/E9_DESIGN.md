# E9 design (2026-10-09 evening): the deployed configuration for seven days on the lab installation

PI decisions 2026-10-09 (after internal review round 3, TRIAGE.md Z1-Z14): "7 days (Recommended)" for E9; the code
changes and the smaller additions "You decide what is the best for s&p"; the per-party property table and the (A4)
rewording "Approve (Recommended)". AGENT_BRIEF.md section 2 binds every agent (no estimates, every number from a saved
result file, never record keys, the attack integrations are never released, commit/push only when asked).

## Why
All three round-3 reviewers (reviews/r3/) ask for the final configuration over days with real nightly purges, a restart
and a restore; R2 found, and the lead confirmed in Home Assistant 2026.7.4 (recorder/purge.py `_purge_state_ids` ->
queries.py `disconnect_states_rows`), that the nightly purge sets `old_state_id = NULL` on retained state rows whose
predecessor it deletes. Both deployed schemes commit that column and a PURGE marker excuses only rows older than its
cutoff, so every real purge would raise false alarms (the 10-10 purge disconnects 16 retained rows in 11 seconds, 6 of
them more than an hour after the cutoff; computed from e2night/pre_oct9.db).

## A. Code (one agent, monitor + verifier; E9_IMPL_NOTES.md; tests; E7/E8 chains must still verify as before)
A1 Purge-disconnect rule (verifier). Under a valid PURGE marker with cutoff C, a violated segment whose rows are all
   at or after C is excused only if restoring, for each retained state row whose `old_state_id` is now NULL, the value
   committed at first read (escrow, or the per-row binding of A2 when the escrow is off) reproduces the anchored root,
   and every restored value names a state row that is absent now and was committed with a timestamp before C. Any other
   change in the segment keeps the violation. Report excused disconnects separately (count, seconds, rows). Validate
   offline on the 2026-10-10 real purge (HOMEPROV-P13-exp/e2night/pre_oct10.db and post_oct10.db, available after
   04:45 UTC 10-10) by emulating a stable-columns monitor that sealed every row of pre_oct10 (label it an offline
   emulation), then live in E9.
A2 Per-row keylog binding. Each signed record carries, for every row first observed in that poll, its key and the
   32-bit prefix of its node hash (or a compact encoding of the same), so the verifier localizes a failed keylog range
   to the rows whose current prefix differs, instead of listing every row of the range as a suspect. Prefix collisions
   (2^-32) are reported as such. Re-score nothing old: the earlier chains have no per-row binding.
A3 Name-map digest in the recommended configuration: on whenever HOMEPROV_NAMEMAP_DIR is set (the E9 monitors mount the
   hub's .storage read-only); the verifier checks it; RENAME markers under the operator key.
A4 Direct-read mode (HOMEPROV_READ=direct): read the live recorder through one read-only SQLite connection in one read
   transaction per poll (WAL readers see a consistent snapshot without blocking the writer), instead of copying the
   database and WAL; keep the evidence-unobservable path (quick_check cadence and failure handling documented); prove
   on saved recorders and in tests that both modes produce identical node hashes, roots and records for the same
   snapshot. Copy mode stays the default of the code; E9 runs one monitor in each mode.
A5 Full-history initial seal: HOMEPROV_SINCE (or equivalent) lets a monitor seal every existing row at its first poll,
   records split under the anchor's body limit (16 MiB), so E9's monitors have sealed the rows each nightly purge
   disconnects.
A6 Operator marker issuer for linked anchors with the operator key and tagged replies (exp/rig/marker_issuer.py works
   with the earlier untagged default anchor only): PURGE before each scheduled purge, RESTORE/RENAME on demand.
A7 Dishonest-anchor tests (offline, saved E8 chains): drop, reorder, withhold, truncate, replay, forge-unsigned; the
   verifier's outcome per case (match / violation / unknown) into exp/out/e9_dishonest_anchor.json; this backs the
   per-party property table (Section 5) and the (A4) clause "with signed records a dishonest anchor host can withhold,
   not forge".
Monitor version for E9 = the code at the end of A1-A6, hashed in the pre-registration; E8's monitor.py (3e479ae0) stays
reproducible (keep it as monitor_e8.py if monitor.py changes, as anchord_r12.py was kept).

## B. E9 run (harness agent; testbed/e9/run_e9.sh, exp/stages/e9_score.py; pre-registration exp/out/e9_preregistration.json)
- Lab installation hpr (Home Assistant 2026.7.4, virtual devices, purge_keep_days 30, auto_purge on, commit_interval as
  configured; nothing else reconfigured except what E9 needs: read-only mounts of the recorder and .storage, and person
  entities for the household accounts so the person re-link can be measured).
- Two monitors, both stable columns + coverage + Ed25519 signatures + escrow + name-map digest + per-row binding + the
  purge-disconnect rule in the verifier: M-direct (A4 direct-read) and M-copy (copy mode as in E8). Each has its own
  linked anchor (append key, separate operator key, tagged replies) and head witness outside Docker's VM.
- Full-history initial seal at start (A5).
- Seven days, starting after the code review, the smoke run and the pre-registration (target 2026-10-11 12:00 UTC).
- Benign events: the deployment's own nightly purge at 04:12 UTC each night (the Mac stays awake: caffeinate, lid open,
  on power; the run logs every host sleep and every hub start) with operator PURGE markers at 04:10; one planned hub
  restart; one restore if Home Assistant documents a restore path for a Container install, else a declared operator
  restore of the recorder from a backup it made, under a RESTORE marker; one benign entity rename under a RENAME marker.
- Attack batches (homeprov_ec / homeprov_e7, never released): one batch per day at a fixed time, arms PU, PSR, INS-L,
  BD-S (counts fixed in the pre-registration, e.g. 5 each per day); on one day the person re-link attack (no row edit)
  and its benign counterpart.
- Score per day and overall: unexcused violations on untouched seconds (one-second, minute, hour), excused disconnects,
  suspect seconds (with and without per-row binding), detection per arm, name-map digest outcomes, per-poll cost
  (median, p90, max) and bytes read/written per day per monitor, host-sleep log, every hub start.
- Pre-registration before the start; its sha256 timestamped externally if a free anonymous service (OpenTimestamps)
  works from this machine, otherwise its hash is recorded in the run log only.

## C. Before E9 starts (they load the Mac; not during the measured week)
C1 Cost at scale: synthetic recorders of about 0.2, 1 and 3 GB built from the real schema and value distributions;
   per-poll copy/load/commit and bytes read/written, copy mode vs direct-read, under Docker CPU and IO limits.
C2 Deferred-choice attack (R1 W2): a resident adversary blinds an in-process committer from installation (module-level
   rebinding of its read path) so it never commits the honest rows, then picks its target later and lets the committer
   commit the rewritten history to a first-write-wins anchor; the external monitor, on the same hub, had sealed the
   honest rows. Scratch stack only; result file exp/out/e9_deferred_choice.json.
C3 Off-hub replica baseline (R2 W3): from E8 files, storage per day of escrow vs anchor chain, what a replica proves to
   a third party, privacy at the anchor; text plus a small result file.

## D. Artifact (any time; no Docker load)
E7/E8 recorder window extracts so reviewers recompute E7/E8 roots (as reproduce/snapshots does for the earlier runs);
sanitized design documents cited by the pre-registrations; SANITIZED_*.json records the final hash of every file the
extra masking pass rewrites; later E9 the same.

## Constraints
- Until 2026-10-10 05:00 UTC the E2 night runs on hpr (driver_oct10.sh restarts hpr-hass at 03:20 UTC and starts
  e2-issuer-oct10): nobody touches hpr-*, e2-* or the default anchor before then. Scratch stacks use their own prefix.
- During E9 nobody restarts, rebuilds or execs into hpr-* or the E9 containers except the run script, and no other
  Docker-heavy work runs on this Mac.
