# E8 anchor side: notes (2026-10-08/09; items A1, A3, A4)

Scope: E8_DESIGN.md section A, items A1, A3, A4; review r2 R1 W1. Code under testbed/anchord/ only. Nothing committed; no
Docker container, image or VM touched; monitor/, exp/stages/ and exp/rig/ not edited. `anchord_r12.py` is untouched
(sha256 `7b1ef9f1e11a36584eb0fde218fc6a0bb234ff33071e80990d0d354883a0c17f`). Paths are relative to the repository.

## 1. A1: the witness gap, closed twice

The reviewer's finding holds on the code before E8. I replayed it on the pre-E8 files (scratch copy):
1. 10 honest appends, each witnessed.
2. Record 3 rewritten and records 4..10 relinked at rest.
3. One honest append.

The witness accepted head 11, and `verify_chain` against the latest witnessed head returned ok.

**Witness (`headwitness.py`).** A push is now `{seq, head_digest, recv_ts, records}`. `records` holds the exact chain lines (as written, no newline) from the record after the witness's last head through the new head. The witness accepts the head only when:
- the records' seq fields run on from its last head;
- every record is linked (`"link": "v2"`);
- each `prev_digest` is the digest of the record before it, the first one matching the last witnessed head digest;
- the last line's digest is `head_digest`.

Other cases:
- A push that starts after the record following the last head gets 409 `{"reason": "gap", "latest": L}`.
- A push that does not link gets 409 `{"reason": "not_extension", "detail": ...}` and is written to the forks file.
- Re-pushing a head the witness already holds is 200 if the digest matches, and a fork (409) if it does not.
- Regressions are still 409.
- A witness with no head requires the history from record 1:
  - record 1's `prev_digest` must be 64 zeros;
  - unlinked legacy records before the first linked one are accepted;
  - the first linked record's `legacy_prefix_digest` is checked against them.
- heads.jsonl lines gain `extends_seq` and `records_checked`. GET /head and GET /log are unchanged.

**Pusher (`anchord_linked.py`).** Each push carries the records from the witness's last head on; normally that is just the new record.
- The daemon remembers the last head the witness acknowledged.
- After a restart (unknown), it sends the new record alone. On a "gap" reply it resends once from `latest + 1`.
- Catch-ups are split into batches of at most `HEAD_WITNESS_PUSH_MAX_BYTES`, each ending at an intermediate head.
- A failed push still never refuses an append, and `witness_push` gains `records_pushed`.
- In sync mode the push runs inside the append's critical section, so heads arrive in order. A first push to an empty witness sends the whole history once, delaying that one append.

**Verifier (`chainverify.py`).**
- `verify_chain(data, external_head=None, witnessed_heads=None)`: with `witnessed_heads` (the witness log), it checks EVERY head. For each one, the chain must hold record seq, and that record must carry the witnessed digest.
- It also reports two more problems: a head beyond the chain's end (truncated) and two digests for one seq in the log.
- The report gains `witnessed_heads` with `matched`, `mismatched_seqs`, `beyond_chain_seqs` and `conflicting_seqs`.
- CLI: `--heads HEADS.jsonl[.gz]` or `--heads-url http://witness:9910/log`.
- Without `witnessed_heads` the output is as before. The latest-head-only report now says to use `--heads`.

**E5 demonstration** (`python3 testbed/anchord/e8_witness_gap_check.py` → `exp/out/e8_witness_gap_check.json`, sha256 `5f1cfe0b764f5fb00648c3baa4cd81db526f681b33c4cfa3f80232fc6280a777`):
- **Inputs:** E5's chain (225 linked records) and its 225 witnessed heads. Both uncompressed hashes and E5's witness code (sha256 `cde68965...`) match `e5_psr_lnk_config.json`.
- **Baseline:** the unmodified chain verifies alone, against the latest head, and against all 225 heads.
- **Attack:** for every i in 1..225, on a copy:
  1. rewrite record i's first root;
  2. relink i+1..225;
  3. append record 226 with the current linked daemon, sending the same push to two fresh witnesses started from E5's 225 heads (E5's witness code and the current one).
- **Results (all 225 attacks):**

| Check | Result |
|---|---|
| E5's witness accepted head 226 | 225/225 |
| Old rule (latest head only) passed, i.e. the reviewer's gap reproduces on E5's data | 225/225 |
| New witness refused head 226 (`not_extension`) | 225/225, 225 forks logged |
| New rule (every witnessed head) failed | 225/225 |
| New rule failed even on the log of E5's witness, which had accepted head 226 | 225/225 |

In every attack the mismatches were exactly records i..225.

## 2. A3: operator key for lifecycle markers (`anchord.py`)

`HOMEPROV_OPERATOR_KEY` holds the hex content of the operator's key file; `rig.marker_issuer` reads its key the same way. It must hold at least 16 bytes and differ from the append key, or the daemon stops at start. When it is set:
- A record is a marker if its payload has a top-level `"marker"` field (as `rig.marker_issuer.append` writes it).
- A marker is accepted only if both `X-HP-Auth` and its `marker_tag` (HMAC over the marker's sort_keys JSON) verify under the operator key.
- 403 refusals, each recorded in refusals.jsonl:
  - `marker_needs_operator_key`: a marker tagged with the append key, or untagged on an anchor that has no append key;
  - `operator_key_for_markers_only`: a non-marker record tagged with the operator key;
  - `bad_marker_tag`: an operator-tagged marker whose marker_tag does not verify.
- Untagged and forged requests stay 401 as before.

When it is unset, the old rules apply (markers under the append key, as E2 issued them).

No change is needed in `exp/rig/marker_issuer.py`: give it the operator key file (`--key-file operator.key`), and it tags both the request and the marker under that key. The tests use it unchanged.

**For the monitor agent (verifier, `exp/stages/e7_verify.py` or its E8 successor):**
- Excuse a violation only with a marker returned by `rig.marker_issuer.markers_from_chain(records, operator_key)`, which keeps only markers whose `marker_tag` verifies under the operator key.
- Do not rely on the anchor having refused the others: a third party must not take the anchor host's word.
- Today `e7_verify.py` only counts records with a `marker` field as "marker".
- Caveat: the tag is a symmetric HMAC, so whoever verifies markers holds a key that can also make them. An operator signature (the A2 Ed25519 scheme applied to markers) would remove that; not built here.

## 3. A4: tagged anchor replies; spec for the monitor (`anchord.py`)

Every reply of the anchor (any path and status, including 401/409/413) carries `X-HP-Reply-Auth`, a lowercase hex HMAC-SHA256:

    key  = the operator key if the request's X-HP-Auth verified under it, else the append key
           (no header at all when neither key is configured)
    msg  = b"homeprov-anchor-reply-v1\n"
           + the request's X-HP-Auth header value exactly as sent (latin-1 bytes; b"" if none was sent)
           + b"\n" + the HTTP status code in decimal ASCII (e.g. b"200")
           + b"\n" + the exact reply body bytes (as read from the response; JSON)
    X-HP-Reply-Auth = hmac.new(key, msg, hashlib.sha256).hexdigest()

`anchord.reply_tag()` and `anchord.reply_ok()` implement it.

**Monitor rule.** After a POST /append, check the tag for every status, using its append key and the tag it sent. If the header is missing or wrong:
- treat the append as failed, with outcome unknown;
- do not mark the segments anchored;
- log it;
- re-send at the next poll.

Re-sending is safe because the anchor accepts an identical root for an anchored segment (one duplicate record) and refuses a different one (409).

Binding to the request tag means a reply copied from an earlier exchange does not verify for a new body. Binding the status and body means an altered status or seq does not verify. A host without the key cannot make a valid tag.

Gate the check on a setting (for example `HOMEPROV_ANCHOR_REPLY_AUTH=1`, on in the E8 image). An anchor built before E8 sends no tag, so with the check on every append to it would count as failed.

Reference client code (standard library):

    REPLY_DOMAIN = b"homeprov-anchor-reply-v1\n"

    def reply_ok(key, request_tag, status, body, header):
        if not header:
            return False
        msg = REPLY_DOMAIN + request_tag.encode("latin-1") + b"\n" + str(status).encode() + b"\n" + body
        return hmac.compare_digest(header.encode("latin-1", "replace"),
                                   hmac.new(key, msg, hashlib.sha256).hexdigest().encode())

    tag = hmac.new(ANCHOR_KEY, body, hashlib.sha256).hexdigest()       # the X-HP-Auth the monitor sends
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, raw, hdr = r.status, r.read(), r.headers.get("X-HP-Reply-Auth")
    except urllib.error.HTTPError as e:
        status, raw, hdr = e.code, e.read(), e.headers.get("X-HP-Reply-Auth")
    if not reply_ok(ANCHOR_KEY, tag, status, raw, hdr):
        return {"ok": False, "reply_auth": "missing" if not hdr else "bad", "http": status}

`rig.marker_issuer.append` does not check reply tags (it only reads the body). The operator tool could adopt the same check with the operator key; I did not edit it.

## 4. Unchanged

- **Record format:** no new field in any chain record.
- **Protocol:** one verb (POST /append), the 401/409/413 behaviour and its refusal records. `test_protocol_and_records_equal_the_earlier_daemon` compares replies, chain records and refusal records with `anchord_r12.py` and still passes; the reply only gains a header.
- **Earlier chains:** all saved evaluation chains still verify as v1, and E5's chain verifies against every one of its witnessed heads.
- **Serving hardening from E7:** unchanged; its stall tests pass on the E8 code.

The E7 stall result (`exp/out/e7_anchor_stall_unit.json`) was measured on anchord.py `fa662e94...`; E8 changes only the request authorization and the reply header. One test changed in `test_anchor_stall.py`, the witness-limits test: the 64 MiB default, and a push that carries its record. The stall harness itself is unchanged.

## 5. Environment variables

| Variable | Default | Where | Meaning |
|---|---|---|---|
| `HOMEPROV_OPERATOR_KEY` | unset (old marker rules) | anchord.py, anchord_linked.py | hex operator key; markers only under it (A3); its requests get replies tagged under it (A4) |
| `HEAD_WITNESS_PUSH_MAX_BYTES` | 8388608 (8 MiB) | anchord_linked.py | largest batch of record lines per witness push (catch-up) |
| `HOMEPROV_WITNESS_MAX_BODY` | 67108864 (64 MiB; was 65536 in E7) | headwitness.py | a push carries record lines; the anchor's largest record is 16 MiB before JSON escaping |

Unchanged from before: `HOMEPROV_ANCHOR_KEY` (append key, raw string), `HOMEPROV_ANCHOR_IO_TIMEOUT_S`, `HOMEPROV_ANCHOR_REQUEST_DEADLINE_S`, `HOMEPROV_ANCHOR_MAX_BODY`, `HOMEPROV_ANCHOR_LINK`, `HEAD_WITNESS_URL`, `HEAD_WITNESS_MODE`, `HOMEPROV_WITNESS_KEY`, `HOMEPROV_WITNESS_*` timeouts, `WITNESS_LOG`, `WITNESS_FORKS`, `WITNESS_PORT`, `PUBLISH_PERIOD`. A4 adds no variable.

## 6. Tests

`python3 -m pytest -q testbed/anchord/` (Python 3.13.11): **64 passed**:
- 37 in test_anchor_chain.py, unchanged;
- 13 in test_anchor_stall.py;
- 14 in the new test_anchor_e8.py:
  - **A1:**
    - the reviewer's attack;
    - a forged extension push that links (accepted by the witness, caught by the every-head check);
    - the honest chain against every head, with truncation and a conflicting log;
    - the CLI with `--heads` (gz) and `--heads-url`;
    - a witness outage caught up in one push;
    - a restart on a fresh witness (gap, resend from record 1, batches of one record);
    - a fresh witness checking an unlinked legacy prefix (a tampered prefix is refused);
    - the witness's refusals;
    - E5's chain against all its heads, plus the attack at i=100 against E5's head state.
  - **A3:**
    - markers with the operator tool itself under the operator key (accepted) and the append key (403);
    - an operator key on a non-marker record (403) and a bad marker_tag (403);
    - untagged (401) and forged (401) markers;
    - `markers_from_chain` with each key;
    - the old behaviour without an operator key, and an unauthenticated anchor with an operator key;
    - key validation.
  - **A4:**
    - every status's reply verifies under the right key and not the other;
    - tampered status or body, a reply replayed to another request, and a missing header all fail;
    - no key means no header;
    - a fake server's "ok" (no tag, a guessed-key tag, a replayed genuine tag) is detected.

The same test file run against the pre-E8 files fails 14 of 14. The attack test fails at the substantive assertion: the old witness accepted head 11.

Six of the E8 tests, covering A1, A4 and E5, also pass under Python 3.10.20 and 3.9.6; the image runs 3.12.13.

## 7. sha256

| File | Before E8 (= E7 state) | After |
|---|---|---|
| anchord.py | `fa662e94374c46ebf4e63a8092d0a48a84ac94a32baf049076cd279f94341171` | `53d1ac92ebbca11e7d3aeda742c1bd790ccb98edb913ad0f4eda8b664af96dfd` |
| anchord_linked.py | `84e8663c78fb378564fac2ff9877b6ea4e50fb3a397fecd7096b4dbb9ec8cacb` | `966d2b351cec120538e059eb293293892cf5bb312fc7b310ffb8888f0fad9b5c` |
| headwitness.py | `43f43dc3cac0aef19be15124c956ba2ac20499764cb90cbf8bea9b9544f68dbe` | `0d8a83c8e0c4cb09e4a5097045e3d1ae91ae7ed264d4b491712256f0602781f5` |
| chainverify.py | `0f05a5a4bad337b5a9187bb95b701c000c77d5078839b2b4b21747db292761a7` | `38cfa5e9d99e8ece7ee53d4401e6a97d6e16b7dac02e19088b11d13b547f9d0e` |
| anchord_r12.py | `7b1ef9f1...c17f` | unchanged |
| test_anchor_chain.py | `9c0477d3fdb81c3824054d819a637bb62a49311f6f2d69aac748123498f47967` | unchanged |
| test_anchor_stall.py | `236793dc3b577261cef493407de5c5597ef619df1438268e2d2b813818e4c9f3` | `b2844dd38949791eba0a20e22792b7356add062c9a00c10a44901b8e23d0902e` |
| test_anchor_e8.py | (new) | `614d2e994a994d080ce683351a160c664861982417af6cf16da80d3855f3093a` |
| e8_witness_gap_check.py | (new) | `b310e1d7717e8efe62301fa9858aa3b7a1951be0523aed57ea10ba4b00a3e034` |
| exp/out/e8_witness_gap_check.json | (new) | `5f1cfe0b764f5fb00648c3baa4cd81db526f681b33c4cfa3f80232fc6280a777` |

## 8. For the E8 run

- **Anchor images:** build new tags from this tree after 05:00 UTC, as in E7_ANCHOR_NOTES.md section 6 (for example `hpr-anchord:e8`, and the linked one via testbed/e5/anchord-linked.Dockerfile). Check `/app/anchord.py` = `53d1ac92...` and `/app/anchord_linked.py` = `966d2b35...`.
- **Anchor environment:** `HOMEPROV_ANCHOR_KEY` (fresh), `HOMEPROV_OPERATOR_KEY` (hex of the operator key file), and the witness URL and key.
- **Witness:** run `headwitness.py` `0d8a83c8...` as a fresh process on the Mac with an empty log. A witness that already holds heads from another chain refuses this one (gap or not_extension), by design.
- **Verification:** `python3 testbed/anchord/chainverify.py CHAIN --heads WITNESS_LOG` (every head), not `--head`.

## 9. Residual limits

- **What the witness checks:** links and digests only, not content or signatures. Content authenticity is A2 (monitor signatures), which is not part of this task.
- **What the every-head check pins:** the chain from the witness's first head on. A witness that misses pushes (outage) holds fewer heads, but the next accepted head links through the records it checked, so the history stays pinned.
- **Delays in sync mode:** catching up an empty or lagging witness happens inside the append's critical section, so that one append waits for the catch-up. Pushes also time out at 5 s per batch.
