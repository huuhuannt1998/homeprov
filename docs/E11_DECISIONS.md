# E11 (openHAB, RQ4): the lead's decisions on the design agent's open questions (2026-10-14)

Context: E11_DESIGN.md and E11_PREREG_DRAFT.json. PI 2026-10-14: "Reframe + openHAB (E11)" and "We are doing research
and finding a scientific contribution, not a pentester". E11 answers RQ4 (does the principle carry to a third hub
family); it adds no marker kinds and no new guarantee for openHAB beyond what it measures. Nothing here changes the
paper's threat model or guarantee statement for Home Assistant.

| # | Question | Decision |
|---|---|---|
| 1 | Back-filled historic states are a documented benign use but flagged like the attack | State it as a measured LIMIT, not a new marker: on openHAB the persistence API itself offers back-dated writes, so a post-commit insertion is indistinguishable from legitimate back-fill without hub cooperation. This is an RQ4 finding (where the principle needs the hub to separate benign back-fill from rewriting). Pre-register the benign back-fill arm with the expected outcome "flagged" and report it. |
| 2 | Housekeeping removal needs a purge-like declaration | Same: measure and report it as flagged (expected), state the limit; note that HOMEPROV's PURGE marker (retention-scoped) is the design answer and porting it is future work. No new marker in E11. |
| 3 | Separate "history with no cause" from "event log with a sender-set source" in the hub model | Yes. The hub model (round 15/16) gets the distinction: openHAB's rendered history carries no attribution; its events.log carries a sender-set, informational source. E11 neither protects nor edits events.log. |
| 4 | Scope to JDBC persistence or extend to rrd4j | Scope to JDBC (SQLite). rrd4j consolidates old readings by design and mapdb keeps only the last state, so neither is a history of individual states; say so in one sentence. |
| 5 | Only UI/REST-managed items, not `.items` files | Accept as a stated scope. |
| 6 | Keylog not ported: wording | "The port replaces the row reader, snapshot, schema check and watermark (five functions); the segment commitment, anchor, signatures and witness are unchanged; the keylog was not ported, so E11's late-row judgement rests on segment roots alone." |
| 7 | Item-index edit flagged at the next poll but shown only after reload/restart | Count it as detected (the record changed and the verifier flags it); report the display lag separately. |
| 8 | E11 scored with its own verifier (same late-row rule, tested) | Acceptable; the paper says E11 used a separate scorer implementing the same rule, and the artifact ships it with its tests. |
| 9 | If whole-row floor is 0 on openHAB, qualify the two-failure-directions lesson | Yes, and it sharpens it: a commitment narrower than the closure misses changes the renderer shows; a commitment broader than the closure flags changes it never shows (on HA/Domoticz through in-place columns on every poll; on openHAB through label/row-id/re-sent points). Both directions are relative to the measured closure, which is the paper's point. Final wording waits for the measured result. |

Build note: the two Java bundles are compiled after E10 inside a pinned Maven/JDK container (no JDK installed on the host),
image digest recorded in the pre-registration.

Order after E10 is scored: finalize E11's pre-registration with the code hashes, stamp it, build, smoke (~1.5 h), closure
(~1 h), detection run (~2.3 h), score. About 6 h of machine time on one calendar day (target 10-21).

## 2026-10-23 (before registration): PI order and a stale test
- PI 2026-10-23 ~15:55Z: "E11" (E11 takes the Mac first after E12; another project's run follows E11's actual end).
  BUSY_WINDOWS.json window 2026-10-24T02:30Z to 16:00Z (planning bound). E11 needs the pinned openHAB 5.2.3 image (not
  yet pulled; 5.2.1 and 4.3.2 are local) and the Maven bundle build, so no Docker work before E12 freezes.
- Offline unit tests (testbed/e11/test_e11.py, pinned interpreter, taskpolicy -b): 26 of 27 passed; the failure was the
  TEST, not the reader. test_reader_with_e10_hardened_monitor re-applied monitor/hardening_e10.patch to a copy of a
  working tree that has carried the hardening since E10; macOS patch (2.0-12u11-Apple) without a terminal silently
  REVERSES an already-applied patch ("Assume -R? [y]", exit 0), so the probe saw HARDEN=None. Fix: apply the patch only
  when HOMEPROV_HARDEN is absent, stdin from /dev/null, and assert the copy is hardened. Re-run: passed (the openHAB
  reader works with the hardened monitor). testbed/e10/test_e10_patches.py has the same pattern; harmless for the
  finished E10, but fix it before the artifact rebuild (gate B9).
- PI 2026-10-23 ~17:30Z, to "Do you want me to prepare a single launcher, like E10's auto-start, that runs the download,
  build and smoke on its own after E12's scoring?": "yes do it". HOMEPROV-P13-exp/e11/launch_e11_smoke.sh, started
  17:47:37Z with nohup (pid 62271, log launch_e11_smoke.out): waits for testbed/e12/run_e12.sh e12_main to exit and for
  2026-10-24T00:05Z; refuses unless E12's log has "score exit: 0" and "done; results under", the SSD is mounted, Docker
  answers and e11_stack.sh guard passes; waits for memory pressure 1 for 5 minutes; pulls openHAB 5.2.3 BY DIGEST and
  tags it (a digest pull can leave the image untagged, and run_e11.sh inspects the tag first); then
  HPR_E11_SMOKE=1 HPR_E11_SP=<SSD>/e11/e11_smoke1 taskpolicy -b run_e11.sh e11_smoke1 all. No registration, no real run.
- e11_stack.sh guard now also refuses while testbed/e12/run_e12.sh runs (it checked E9/E10 only; added before
  registration).
- 2026-10-24 smoke 1 (e11_smoke1, started by the launcher 00:36:52Z after E12 ended normally, score exit 0): tests 27/27,
  openHAB 5.2.3 pulled by digest and verified, bundles and images built and hash-checked, then the closure stack hung in
  `e11_stack.sh up` for 25 min: openHAB 5.2.3 (Karaf 4.4.11) closes a console command given as a client ARGUMENT
  ("Closed", nothing run) and console() had no time limit, so the first jdbc_ready check never returned. REST (200) and
  JDBC persistence were up (00:40:11Z). Smoke 1 stopped (TERM 01:15Z; stack down, nothing left in Docker).
  Fix (before registration): console() sends the command on stdin between echo markers, `timeout 60`, `-u openhab`,
  strips ANSI codes, prompts and the echoed input; the output of `users add` (which carries a password) is discarded
  and `openhab:users list` is recorded instead; "openhab:info" (absent in 5.2.3) replaced by the public REST root
  (runtimeInfo.version). Tested on a throwaway 5.2.3 container: bundle list 166 lines, users list parsed, 0 lines with
  the test password, unknown commands return at once. Smoke 2 follows.
- 2026-10-24 smoke 2 (e11_smoke2, 01:35Z, all phases): tests 27/27, build ok, closure stack up in 44 s with the new
  console (users recorded by name and role, no password in any file of the run folder), closure 3 fixtures 68 mutations,
  closure gate ok (nothing missing from the reader, controls hold). Main stack: "JDBC persistence not installed" after
  the 5-min wait (01:54-02:00Z); the stack was torn down without the hub's log. A debug stack of the same kind (prefix
  e11ts, same bundles incl. the instrument) was ready in 42.7 s, so the failure was intermittent; the likely cause, not
  confirmed, is the JDBC add-on's download from openHAB's repository at first start. Changes (before registration):
  wait_jdbc 60 -> 180 tries (~15 min); on a failed wait, diag() writes the hub's add-ons, addons.cfg, openhab.log tail,
  the console's jdbc and feature checks and docker logs to stderr (config.log) before exit. If it recurs, use the
  registered alternative (the offline add-ons archive of the same release). Smoke 2's main phase re-run 02:11Z
  (run_e11.sh e11_smoke2 main, same run folder).
- 2026-10-24 smoke 2 main phase (re-run 02:11-03:21Z): arms A-BD, A-RM, A-CHG valid 3/3, rendered as intended 3/3,
  detected 3/3 (closure, row and whole-row schemes); score exit 0; chain 782 records, 0 refusals, 0 monitor errors.
  Three harness defects found in it (all fixed before registration):
  (1) HUB RESTART FAILED. The hub is created on the provisioning network (internet, for the JDBC add-on), which `up`
      removes; Docker keeps it as the container's network mode, so `docker restart` failed ("could not find a network
      matching network mode e11ss-prov") and the hub stayed STOPPED. Effects in smoke 2: both B-RESTART left the hub down,
      so every later benign operation timed out ("timeout waiting for ack"), the household schedule did not resume, and
      window 2 ran against a stopped hub; in the closure phase the in-place probe's restart failed too (res 1), so its
      empty in-place result was not evidence. Fix: e11_stack.sh restart recreates the provisioning network as INTERNAL,
      restarts, then disconnects and removes it (hub on its internal network only; no route outside, checked); it reports
      running, networks and ready, and writes diagnostics on failure; run_e11.sh warns if the hub is not ready after a
      restart; e11ops.py records in_place_probe.restart_ok and the closure phase now FAILS if that restart fails.
      Verified on a debug stack (e11ts): restart in 7 s, openHAB 5.2.3 up, fixture bundle restarted (second start event),
      JDBC and both E11 bundles active, only the internal network attached, no outside route.
  (2) UI CAPTURE stuck at openHAB's sign-in page (Main UI ignores HTTP basic credentials), so 0 requests at every
      checkpoint. Fix: uicapture fills openHAB's sign-in form (username, password, Sign In), waits for load (not network
      idle: the signed-in UI holds an event stream open), reopens the Analyze view and waits up to 30 s for its
      persistence request; records signed_in. Verified: owner and member both signed in and reached /analyzer/.
  (3) (from smoke 2's first main attempt) the JDBC wait and diagnostics, above.
  Tests 27/27 after the changes. Next: smoke 3, all phases (e11_smoke3), before registration.
- 2026-10-24 smoke 3 (e11_smoke3, 04:00Z, all phases): closure stack failed after the 15-min JDBC wait. The new
  diagnostics: feature openhab-persistence-jdbc-sqlite installed and "Started", but no openhab:jdbc console command and
  persistence/jdbc empty. Reproduced with repeated debug stacks (prefix e11tr): the 2nd of 2 starts failed; live, the
  bundle org.openhab.persistence.jdbc was RESOLVED, not Active (installed, never started; the only such bundle besides
  the xtend libraries, which are always Resolved); `bundle:start org.openhab.persistence.jdbc` brought persistence up
  within 2 s (openhab.db created, JdbcMapper openConnection, console command present). Seen in 3 of 9 stack starts
  that night. A plausible cause, not established: the add-on installation racing the addons-folder deployment of the
  fixture bundle at first start. Fix (before registration; harness only, HOMEPROV's monitor and the measured fields are
  untouched): wait_jdbc starts a Resolved JDBC bundle once a minute from the first minute (at most 3 times), logs each
  start to config.log and reports the count as jdbc_bundle_started_by_harness in the up and restart records; diag()
  now greps openhab.log for jdbc/persistence/errors (console warnings dropped) and lists bundle and DS component state.
  To report: openHAB 5.2.3 in our containers sometimes left JDBC persistence unstarted at first start; the harness
  started it and the run records each time.
- 2026-10-24 ~05:00Z, a second stuck state (repro2 r1): feature openhab-persistence-jdbc-sqlite recorded as installed
  and Started while neither org.openhab.persistence.jdbc nor org.xerial.sqlite-jdbc existed; `feature:uninstall` +
  `feature:install` brought persistence up in 4 s. Changes (before registration): (a) E11's bundles are copied into the
  addons folder only after JDBC is up, then e11_stack.sh waits for them to be Active (wait_bundles); (b) wait_jdbc's
  recovery from the 2nd minute, once a minute, at most 3 kicks: Resolved -> bundle:start; bundle missing under an
  installed feature -> feature reinstall; every kick logged and counted (jdbc_bundle_started_by_harness).
  Test (repro3, 6 starts of a main-kind stack): 6/6 up, each with exactly 1 kick (2 reinstalls, 4 bundle:start), so
  (a) did not remove the problem: openHAB 5.2.3's first-start JDBC add-on activation failed in every start that hour,
  plausibly in the add-on's online install; up took 184-197 s; users and fixture start present each time. Restart test
  on a kicked stack: 2 harness restarts, both running, internal network only, ready, 0 kicks, fixture restarted each
  time, no outside route.
- 2026-10-24 smoke 4 (e11_smoke4, 05:29-06:25Z, all phases): clean. Closure 3 fixtures 68 mutations, gate ok; arms
  A-BD/A-RM/A-CHG valid 3/3, rendered as intended 3/3, detected 3/3 under closure, row and whole-row; all 11 benign
  operations ok, both B-RESTART included; no WARN; 0 JDBC kicks; score exit 0. Only the UI capture failed: the sign-in
  form appears a moment AFTER Main UI loads, so the first look found none. Fix: wait up to 20 s for the form.
- UI capture verified on a provisioned debug stack (e11tu): owner and member signed in and reached /analyzer/; Main UI's
  Analyze view issued ONE history request per account: starttime, endtime (last 24 h), boundary=true, itemState=true;
  harness read with the same query equal. Registered alternative triggered ("Analyze view requests the history with
  parameters other than the REST defaults"): RENDER_EXTRA was set to {boundary: true, itemState: true}.
- Smoke 5 (e11_smoke5, 06:54Z): closure FAILED at once ("restore failed after <table>.time plus_1s"). Tested directly:
  itemState=true appends the hub's LIVE item state stamped with the query time (two renders 2.5 s apart differ only in
  that last point); boundary=true is deterministic. Decision (before registration): E11-CLO and the arms render with
  boundary=true and WITHOUT itemState: the live point is not a stored row, no recorder edit can change it, and it fails
  every before/after comparison by construction. uicapture still replays Main UI's own request (with itemState) and
  compares the UI and harness bodies without the live point (compared_without_live_item_state_point); verified on a
  stateful item: agree true. Report both parameters and this choice in the supplement.
- 2026-10-24 smoke 6 (e11_smoke6, 07:09-08:08Z, all phases, the code as registered): CLEAN. Closure 3 fixtures 68
  mutations, gate ok, in-place probe restart_ok true with no in-place rewrites, render_extra {boundary: true}; arms
  A-BD/A-RM/A-CHG valid 3/3, rendered as intended 3/3, detected 3/3 under closure, row and whole-row; UI capture 1
  request per checkpoint (starttime, endtime, boundary, itemState), agree true (live point excluded); all 11 benign
  operations ok (two restarts included); untouched anchored seconds flagged: closure 0/549, row 0/547, whole-row 0/547
  (a smoke, not a result); 1 JDBC kick on each stack (logged); no WARN or FAIL; score exit 0.
- Real-run tag e11_main (not e11): run_e11.sh refuses when $OUT/${TAG}_* exists, and with TAG=e11 that matches
  exp/out/e11_preregistration.json; e10_main and e12_main were named the same way. Run directory on the external SSD.
  Next: e11_prereg.py --final, OpenTimestamps, --check, then run_e11.sh e11_main all.

## 2026-10-24 E11 registered run (e11_main), first read; analysis notes to follow in E11_RESULTS_NOTES.md
- Registered 11:53:41Z (exp/out/e11_preregistration.json sha256 d7d114a8c9fe, .ots); run 11:54-14:07Z, score exit 0, no
  WARN/FAIL, 0 JDBC kicks, Docker clean; Mac released 14:59:12Z (BUSY_WINDOWS, ledger; another project's job started 15:00Z).
- exp/out/e11_main_score.json sha256 d6f58975a10a; e11_main_clo_closure.json 24b981a76558. Chain 1407 records, all
  signed, linked and witnessed; 1407/1407 polls observable; median poll 33.1 ms; max observable gap 5.6 s.
- First read against the hypotheses (to be checked field by field before any text): H1 measured closure = the 8
  registered fields (ItemId and ItemName only after the index reload), controls hold (the scorer's internal "predicted"
  list omits "registry (item entry)", which H1's text includes: a bookkeeping inconsistency in the scorer, not a miss);
  H2 no attribution field; H3 the rows scheme changes 0 roots under ItemName, ItemId, itemType, meta.unit and a
  registry deletion (closure 120 to 613); H4 no in-place rewrite, whole-row floor 0/1446; H5 30/30 per arm, effect
  rendered for both accounts 30/30; H6 closure floor 0/1454 s, 0/26 min; H8 monitor.py 0 lines changed.
  H7 PARTLY NOT MET: B-REPLACE-SAME was registered as "no violation" under the closure, but 5 of its 6 seconds are
  attributable under all three schemes (cause to be examined; candidate: the re-sent values or times are not byte-equal
  to the originals). B-BACKFILL 10/10 x3 and B-REPLACE-NEW 6/6 attributable as registered; B-RETAIN 106 attributable,
  22 seconds outside the anchored window ("absent"); B-LABEL closure none (12 ok, 1 absent), whole-row 8 attributable.
