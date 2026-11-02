# E8 design (2026-10-08 evening): third-party verifiable anchoring, coverage at headline scale, write-rate stress,
# real-deployment closure re-measurement

PI approval 2026-10-08: "Reframe (Recommended)" (stable columns become the deployed commitment; the renderer closure is
the measured set any commitment must contain), "Approve E8 in full (Recommended)", "Add Ed25519 signatures
(Recommended)". AGENT_BRIEF.md section 2 binds every agent. Reviews behind it: drafts/round13/reviews/r2/R1-R3.md.

TIME CONSTRAINT: the E2 night runs on the default deployment (hpr-*) until 2026-10-09 05:00 UTC (snapshots 03:55 and
04:45 UTC, the recorder's own purge at 04:12 UTC). Nobody restarts, pauses, rebuilds or execs into hpr-* or e2-issuer
before 05:00 UTC; scratch stacks (prefix given in each task) are fine.

## A. Anchoring a third party can check (code)
A1 Witness gap (R1, reproduced offline): a head is accepted if its sequence does not regress, and verification compares
   the chain against the latest witnessed head only, so a host that rewrites record i, relinks i+1..n and then lets one
   honest append through passes. Fix: the witness accepts head n+1 only if the pushed record links to its last head
   (prev_digest of record n+1 equals the last witnessed digest; for a gap the pusher sends the intermediate records and
   the witness checks the links); the verifier checks the chain against EVERY witnessed head (each (seq, digest) must
   match the chain at seq). Demonstrate on E5's saved chain and 225 witnessed heads: the reviewer's attack must fail.
A2 Ed25519 signatures: the monitor signs each record (detached signature over the exact record bytes it tags with the
   HMAC) with a key that stays on the monitor host; the record carries the signature and the public-key fingerprint;
   the verifier checks every record's signature against the published public key. The HMAC append path stays (it
   authenticates the sender to the anchor). Library: the `cryptography` package in the monitor image (pinned version),
   imported only when HOMEPROV_SIGN_KEY is set (default on in the E8 image); the verifier needs it only to check
   signatures. Records without a signature verify as before.
A3 Operator key: lifecycle markers are accepted only under a separate operator key (the anchor holds both; a marker
   tagged with the monitor's append key is refused); the verifier excuses a violation only with an operator-key marker.
A4 Anchor replies: the anchor tags each reply (HMAC over the reply body and the request's tag) so the monitor detects a
   spoofed "ok" from a host on the same network; the monitor treats an untagged or wrong reply as a failed append.
Tests for each, including the reviewer's attack; all earlier suites stay green; earlier chains still verify.

## B. Renderer closure re-measured on the real deployment (R3)
Per-field mutation of a copy of the default deployment's recorder (no live hub touched), rendered by the release's own
logbook processor in a throwaway hub, with a positive control and a restore check, over several entity types and rows:
the lock, lights, motion sensors, automation runs, service calls, user and person attribution, state rows with and
without old_state_id, events with and without context user. Fix the earlier abort ("restore did not reproduce the
baseline render"). Report per field: rows mutated, render changes, the closure; compare with the 14-field closure and
with the stable-columns set (every stable column must contain the closure).

## C. E8 run (default deployment, after 05:00 UTC on 2026-10-09)
Monitors as in E7 but stable columns is now the evaluated (deployed) scheme; the closure monitor runs alongside; both
with coverage, signatures and the operator key; witness outside the hub's VM-less host process as in E5 (headwitness on
the Mac). Arms at 90 trials each (30 per configuration): PU and PI (other-principal laundering), PSR (member-account
swap), P (own-actuation laundering, the post-commit control), INS-L and INS-M (with K >= 9 inserted rows), BD-S
(backdated forged unlock). Pre-registered like E7 (parameters, arms, counts, outcomes, exclusions) before any trial.
Then a write-rate stress run: the device simulator at about five times the lab rate for a fixed window with a short
laundering arm (30 trials), benign floor and per-poll cost under both monitors. Report median, p90 and max costs.
