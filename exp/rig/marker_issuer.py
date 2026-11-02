"""Operator-side issuance of lifecycle markers: PURGE (round 12, experiment E2), RESTORE and RENAME (round 13, E9 A6).

Round 13 (E9 item A6) adds linked anchors, the operator key, tagged replies, operator signatures and RESTORE and
RENAME on demand; see the E9 section below.

Runs OUTSIDE the hub's trust domain and holds the append key. It reads the recorder's purge policy from the
operator's copy of the Home Assistant configuration (auto_purge, purge_keep_days) and, shortly before each
scheduled nightly purge, appends one PURGE marker to the anchor over the authenticated append path.

The marker is SCOPED: its cutoff is not chosen by whoever asks for a purge, it is derived from the schedule,

    cutoff_ts = scheduled_ts - keep_days * 86400,

so it can excuse only the deletion of rows older than the retention policy at the scheduled time. The verifier
(rig.markers.filter_violations_scoped) recomputes the cutoff from the same policy and ignores any cutoff a record
declares. Without scoping, a PURGE marker excuses whatever cutoff it declares, and a purge-shaped deletion that
matches a declared cutoff escapes (stage 29, case "deletion hidden in a genuine purge").

Home Assistant schedules the nightly purge at 04:12 local time (recorder/core.py: async_track_time_change(...,
hour=4, minute=12, second=0)) and purges states and events older than now - purge_keep_days.

    python3 -m rig.marker_issuer --config configuration.yaml --anchor http://host:9900/append \
        --key-file key.hex --tz America/New_York --once          # issue the next scheduled marker and exit

E9 (round 13, item A6). The code above was written for the default anchor, which neither tags its replies nor has an
operator key: append() believes any reply and raises on a refusal, the wait before a purge is one time.sleep() on the
monotonic clock (which stops while the host sleeps, drafts/round13/E2_PURGE_DIAGNOSIS.md item 4), and only PURGE
exists. Added, without changing what the old calls do:
  * post(): one append that never raises; with reply_tags="1" the reply must carry a valid X-HP-Reply-Auth under the
    key the request was tagged with (the operator key: the anchor tags an operator request's reply with it,
    testbed/anchord/anchord.py reply_tag()), else it is not the anchor's answer and counts as failed; "auto" (default)
    checks a tag when one is sent; "0" never checks.
  * issue(): post() with retries until an ok or a deadline; the outcome of every attempt is returned (and logged).
  * operator signatures (--sign-key, an Ed25519 private key, PKCS#8 PEM): the record also carries "marker_sig_alg",
    "marker_sig_fp" (SHA-256 of the raw public key) and "marker_sig" over MARKER_SIG_TAG + the marker's sort_keys JSON.
    The HMAC marker_tag is checked by the anchor and by a verifier holding the operator key, which the anchor host
    holds too (to check markers), so it cannot show a third party that the operator issued a marker; the signature
    can, and the anchor host cannot make one. markers_from_chain(..., pubkey=) keeps only markers whose signature
    verifies.
  * waiting on the wall clock (wait_until(): sleeps of at most 30 s, each re-reading time.time()).
  * RESTORE and RENAME markers on demand (--kind): RESTORE {"restore_point_ts": the time of the backup restored};
    RENAME {"parts": {name-map part: its digest after the change}} (with --storage and --rename-*, the digest is
    computed with the monitor's own namemap_commitment() from the hub's storage with the declared change applied), and
    optionally {"entity_id": {"from": old, "to": new}} for an entity_id change, which rewrites recorder rows.
  * markers_from_chain(..., kinds=) for kinds other than PURGE (the default stays PURGE only).
    python3 -m rig.marker_issuer --kind PURGE --keep-days 30 --tz UTC --anchor URL --key-file operator.key \
        --sign-key operator.pem --reply-tags 1 --lead-s 120 --until T --log issuer.jsonl
    python3 -m rig.marker_issuer --kind RENAME --storage /cfg/.storage --rename-part entity \
        --rename-match entity_id=light.porch --rename-field name --rename-to "Porch lamp" --anchor URL \
        --key-file operator.key --sign-key operator.pem --reply-tags 1
    python3 -m rig.marker_issuer --kind RESTORE --restore-point-ts T --anchor URL --key-file operator.key \
        --sign-key operator.pem --reply-tags 1
  * RESTORE_DONE (E9 code review re-check N1), once the restored hub is up: {"restore_nonce", "restore_sha256" (the
    RESTORE marker it closes), "post_restart_wm" (the restored recorder's largest keys the operator read after the
    restart), "hub_started_ts"?}; the verifier ends the RESTORE excuse at it and excuses nothing without it.
    python3 -m rig.marker_issuer --kind RESTORE_DONE --restore-marker '<the RESTORE marker JSON as issued>' \
        --post-restart-wm '{"states": N, "events": N}' --hub-started-ts T --anchor URL --key-file operator.key \
        --sign-key operator.pem --reply-tags 1
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import time
import urllib.error
import urllib.request

PURGE_HOUR, PURGE_MINUTE = 4, 12          # Home Assistant recorder default schedule
DAY = 86400.0
MARKER_SIG_TAG = b"HOMEPROV-marker-sig-v1\x00"
REPLY_DOMAIN = b"homeprov-anchor-reply-v1\n"
REPLY_HEADER = "X-HP-Reply-Auth"
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def purge_policy(config_path: str) -> dict:
    """auto_purge and purge_keep_days from a configuration.yaml (defaults: True, 10)."""
    import yaml

    class _L(yaml.SafeLoader):
        pass
    # Home Assistant tags (!secret, !include, ...) are irrelevant to the recorder block; read them as plain strings.
    _L.add_multi_constructor("!", lambda loader, suffix, node: None)
    conf = yaml.load(open(config_path), Loader=_L) or {}
    rec = conf.get("recorder") or {}
    return {"auto_purge": bool(rec.get("auto_purge", True)),
            "purge_keep_days": int(rec.get("purge_keep_days", 10))}


def scheduled_purges(start_ts: float, end_ts: float, tz: str) -> list[float]:
    """Every 04:12 local time in [start_ts, end_ts)."""
    if tz.upper() == "UTC":                  # no tz database needed (slim images ship none)
        z = dt.timezone.utc
    else:
        from zoneinfo import ZoneInfo
        z = ZoneInfo(tz)
    d = dt.datetime.fromtimestamp(start_ts, z).date() - dt.timedelta(days=1)
    out = []
    while True:
        t = dt.datetime(d.year, d.month, d.day, PURGE_HOUR, PURGE_MINUTE, tzinfo=z).timestamp()
        if t >= end_ts:
            return out
        if t >= start_ts:
            out.append(t)
        d += dt.timedelta(days=1)


def scoped_marker(scheduled_ts: float, keep_s: float, issued_ts: float | None = None) -> dict:
    """A PURGE marker whose cutoff follows from the schedule and the retention policy alone."""
    return {"marker": "PURGE", "scope": "retention_policy", "scheduled_ts": float(scheduled_ts),
            "keep_s": float(keep_s), "cutoff_ts": float(scheduled_ts) - float(keep_s),
            "issued_ts": float(issued_ts if issued_ts is not None else time.time()), "issuer": "operator"}


def new_nonce() -> str:
    """A random marker nonce (E9 code review R3): two issuances never carry the same marker, so a verifier counts a
    marker that reached a chain twice (a resent request, a replay) once."""
    return os.urandom(16).hex()


def restore_marker(restore_point_ts: float, issued_ts: float | None = None, note: str | None = None,
                   backup_wm: dict | None = None, nonce: str | None = None, monitors=None) -> dict:
    """A RESTORE marker: the recorder is about to be replaced by a backup taken at restore_point_ts. backup_wm: the
    backup's largest key per table ({"states": .., "events": ..}), which the verifier needs (E9 code review R1: it
    takes K from the signed marker); monitors: the record-signing key fingerprints of the monitors it is for."""
    m = {"marker": "RESTORE", "restore_point_ts": float(restore_point_ts),
         "issued_ts": float(issued_ts if issued_ts is not None else time.time()), "issuer": "operator",
         "nonce": nonce or new_nonce()}
    if backup_wm is not None:
        m["backup_wm"] = {t: (None if backup_wm.get(t) is None else int(backup_wm[t])) for t in ("states", "events")}
    if monitors:
        m["monitors"] = [str(x) for x in monitors]
    if note:
        m["note"] = str(note)
    return m


def marker_sha256(m: dict) -> str:
    """The identity a verifier gives a marker: SHA-256 of its canonical (sort_keys) JSON."""
    return hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()


def restore_done_marker(restore: dict, post_restart_wm: dict, hub_started_ts: float | None = None,
                        issued_ts: float | None = None, note: str | None = None, nonce: str | None = None,
                        monitors=None) -> dict:
    """A RESTORE_DONE marker (E9 code review re-check N1): the operator saw the hub come back from the restore that the
    RESTORE marker `restore` (the dict as issued) declared. It names that marker by its nonce and by its SHA-256, and
    carries the watermark the operator read from the restored recorder after the restart ({"states", "events"}) and,
    when known, the time the restored hub started. A verifier ends the RESTORE excuse at the first poll anchored after
    this marker (or earlier), and excuses nothing without it."""
    m = {"marker": "RESTORE_DONE", "restore_nonce": restore.get("nonce"), "restore_sha256": marker_sha256(restore),
         "post_restart_wm": {t: (None if post_restart_wm.get(t) is None else int(post_restart_wm[t]))
                             for t in ("states", "events")},
         "issued_ts": float(issued_ts if issued_ts is not None else time.time()), "issuer": "operator",
         "nonce": nonce or new_nonce()}
    if hub_started_ts is not None:
        m["hub_started_ts"] = float(hub_started_ts)
    if monitors:
        m["monitors"] = [str(x) for x in monitors]
    if note:
        m["note"] = str(note)
    return m


def rename_marker(parts: dict, issued_ts: float | None = None, entity_id: tuple | None = None,
                  note: str | None = None, from_parts: dict | None = None, nonce: str | None = None,
                  monitors=None) -> dict:
    """A RENAME marker: the name-map parts named will hold exactly these digests after the change (and, with
    entity_id=(old, new), the recorder's states_meta.entity_id changes from old to new). from_parts: the digests the
    parts hold before the change; a verifier then excuses only a change from exactly those (E9 code review m4)."""
    m = {"marker": "RENAME", "parts": {str(k): str(v) for k, v in (parts or {}).items()},
         "issued_ts": float(issued_ts if issued_ts is not None else time.time()), "issuer": "operator",
         "nonce": nonce or new_nonce()}
    if from_parts:
        m["from"] = {str(k): str(v) for k, v in from_parts.items()}
    if entity_id:
        m["entity_id"] = {"from": str(entity_id[0]), "to": str(entity_id[1])}
    if monitors:
        m["monitors"] = [str(x) for x in monitors]
    if note:
        m["note"] = str(note)
    return m


def tag(body: bytes, key: bytes) -> str:
    return hmac.new(key, body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------------------------------- signatures
def marker_signing_bytes(m: dict) -> bytes:
    return MARKER_SIG_TAG + json.dumps(m, sort_keys=True).encode()


def _crypto():
    from cryptography.hazmat.primitives import serialization                     # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ed25519               # noqa: PLC0415
    return serialization, ed25519


def _fp(pub) -> str:
    ser, _ed = _crypto()
    return hashlib.sha256(pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).hexdigest()


def load_signer(path: str):
    """The operator's Ed25519 private key (PKCS#8 PEM)."""
    ser, ed = _crypto()
    with open(path, "rb") as fh:
        k = ser.load_pem_private_key(fh.read(), password=None)
    if not isinstance(k, ed.Ed25519PrivateKey):
        raise SystemExit("--sign-key must name an Ed25519 private key (PKCS#8 PEM)")
    return k


def load_pubkey(path: str):
    """The operator's published Ed25519 public key (PEM SubjectPublicKeyInfo)."""
    ser, ed = _crypto()
    with open(path, "rb") as fh:
        k = ser.load_pem_public_key(fh.read())
    if not isinstance(k, ed.Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key: %s" % path)
    return k


def sign_fields(m: dict, signer) -> dict:
    return {"marker_sig_alg": "ed25519", "marker_sig_fp": _fp(signer.public_key()),
            "marker_sig": signer.sign(marker_signing_bytes(m)).hex()}


def signature_ok(p: dict, pub) -> bool:
    """Does the marker record's operator signature verify under pub?"""
    m = p.get("marker")
    if not isinstance(m, dict) or p.get("marker_sig_alg") != "ed25519" or p.get("marker_sig_fp") != _fp(pub):
        return False
    try:
        pub.verify(bytes.fromhex(str(p.get("marker_sig") or "")), marker_signing_bytes(m))
        return True
    except Exception:                                 # noqa: BLE001
        return False


def marker_record(key: bytes | None, payload: dict, signer=None) -> dict:
    """The record body the operator appends: the marker, its HMAC tag under the operator key, and (with a signer) the
    operator's signature. Without a signer it is exactly what append() sends."""
    rec = {"observer": "operator-marker-issuer", "marker": payload,
           "marker_tag": tag(json.dumps(payload, sort_keys=True).encode(), key) if key else None}
    if signer is not None:
        rec.update(sign_fields(payload, signer))
    return rec


def append(anchor_url: str, key: bytes | None, payload: dict, timeout: float = 10.0) -> dict:
    """POST one record to the anchor; with a key, over the authenticated append path (X-HP-Auth header, as monitor.py sends it)."""
    body = json.dumps({"observer": "operator-marker-issuer", "marker": payload,
                       "marker_tag": tag(json.dumps(payload, sort_keys=True).encode(), key) if key else None},
                      sort_keys=True).encode()
    req = urllib.request.Request(anchor_url, data=body, method="POST", headers={"Content-Type": "application/json"})
    if key:
        req.add_header("X-HP-Auth", tag(body, key))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def markers_from_chain(records, key: bytes | None = None, kinds=("PURGE",), pubkey=None) -> list[dict]:
    """Lifecycle markers of the given kinds on an anchor chain (default: PURGE only, as before). With a key, only
    markers whose marker_tag verifies under it count, which is how a verifier reading an anchor that does not itself
    check tags rejects a marker from anyone but the issuer; with pubkey (the operator's Ed25519 public key), only
    markers whose operator signature verifies count, which the anchor host cannot produce (E9 A6)."""
    out = []
    for rec in records:
        p = rec.get("payload", rec)
        m = p.get("marker") if isinstance(p, dict) else None
        if not isinstance(m, dict) or (kinds is not None and m.get("marker") not in kinds):
            continue
        if key is not None:
            want = tag(json.dumps(m, sort_keys=True).encode(), key)
            if not hmac.compare_digest(str(p.get("marker_tag") or ""), want):
                continue
        if pubkey is not None and not signature_ok(p, pubkey):
            continue
        out.append({**m, "seq": rec.get("seq"), "recv_ts": rec.get("recv_ts")})
    return out


# ---------------------------------------------------------------------------------------------------- E9 A6: posting
def reply_ok(key: bytes, request_tag: str, status: int, body: bytes, header) -> bool:
    """Does an anchor reply's X-HP-Reply-Auth verify (testbed/anchord/anchord.py reply_tag())? Missing is no."""
    if not header or not key:
        return False
    want = hmac.new(key, REPLY_DOMAIN + (request_tag or "").encode("latin-1", "replace") + b"\n"
                    + str(int(status)).encode() + b"\n" + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(header).encode("latin-1", "replace"), want.encode())


def post(anchor_url: str, key: bytes | None, rec: dict, timeout: float = 10.0, reply_tags: str = "auto") -> dict:
    """One append of a marker record; never raises. {"ok", "http", "reply", "reply_tag"}: reply_tag is "ok", "missing",
    "bad" or "off"; with reply_tags="1" (or "auto" and a tag sent) a reply whose tag does not verify is not the anchor's
    answer, so ok is False whatever it says."""
    body = json.dumps(rec, sort_keys=True).encode()
    req = urllib.request.Request(anchor_url, data=body, method="POST", headers={"Content-Type": "application/json"})
    rtag = tag(body, key) if key else ""
    if key:
        req.add_header("X-HP-Auth", rtag)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw, hdr = r.status, r.read(), r.headers.get(REPLY_HEADER)
    except urllib.error.HTTPError as e:
        status, raw, hdr = e.code, e.read() or b"", e.headers.get(REPLY_HEADER) if e.headers else None
    except Exception as exc:                          # noqa: BLE001
        return {"ok": False, "err": repr(exc)[:160], "reply_tag": "off"}
    try:
        reply = json.loads(raw or b"{}")
    except ValueError:
        reply = {"raw": raw[:200].decode("latin-1")}
    if not key or reply_tags == "0":
        check = "off"
    elif not hdr:
        check = "missing"
    else:
        check = "ok" if reply_ok(key, rtag, status, raw, hdr) else "bad"
    believed = check == "ok" or (check == "off") or (reply_tags == "auto" and check == "missing")
    ok = bool(believed and status == 200 and isinstance(reply, dict) and reply.get("ok"))
    return {"ok": ok, "http": status, "reply": reply, "reply_tag": check}


def issue(anchor_url: str, key: bytes | None, payload: dict, signer=None, reply_tags: str = "auto",
          attempts: int = 5, retry_s: float = 5.0, deadline: float | None = None, timeout: float = 10.0) -> dict:
    """Append one marker, retrying a failed or unverified attempt (not a refusal the anchor tagged validly: a 403 or
    409 it really sent will not change) until ok, `attempts` attempts, or the wall-clock deadline."""
    rec = marker_record(key, payload, signer)
    tries = []
    for i in range(max(1, int(attempts))):
        r = post(anchor_url, key, rec, timeout=timeout, reply_tags=reply_tags)
        r["at"] = time.time()
        tries.append(r)
        if r["ok"]:
            break
        if r.get("http") in (400, 401, 403, 409, 413) and r.get("reply_tag") == "ok":
            break                                         # the anchor's own, authenticated refusal
        if deadline is not None and time.time() + retry_s >= deadline:
            break
        wait_until(time.time() + retry_s)
    return {"ok": tries[-1]["ok"], "marker": payload, "attempts": tries,
            "signed": signer is not None, "sig_fp": _fp(signer.public_key()) if signer is not None else None}


def wait_until(t: float, step: float = 30.0) -> None:
    """Sleep until the wall clock reaches t, in steps of at most `step` seconds, re-reading time.time() after each, so a
    host sleep that stops the monotonic clock delays the wake-up by at most one step after the host resumes."""
    while True:
        left = t - time.time()
        if left <= 0:
            return
        time.sleep(min(step, left))


# ---------------------------------------------------------------------------------------------------- E9 A6: RENAME
def _monitor(monitor_dir: str | None = None):
    path = os.path.join(monitor_dir or os.path.join(REPO, "monitor"), "monitor.py")
    old = {k: os.environ.get(k) for k in ("HOMEPROV_NAMEMAP_DIR", "HOMEPROV_SIGN_KEY", "HOMEPROV_SCRATCH")}
    os.environ.pop("HOMEPROV_NAMEMAP_DIR", None)
    os.environ.pop("HOMEPROV_SIGN_KEY", None)
    os.environ["HOMEPROV_SCRATCH"] = os.environ.get("TMPDIR", "/tmp")
    try:
        spec = importlib.util.spec_from_file_location("mi_monitor", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod


def renamed_part_digests(storage_dir: str, part: str, match: tuple, field: str, new_value,
                         monitor_dir: str | None = None) -> dict:
    """The name-map part digest after one declared change, computed with the monitor's own code from the hub's storage
    as it is now: in `part`, the entry whose `match[0]` field equals `match[1]` gets `field` = new_value. Raises if no
    entry, or more than one, matches."""
    M = _monitor(monitor_dir)
    fields = next(f for p_, _f, _k, f in M.NAMEMAP_PARTS if p_ == part)
    entries = M.namemap_entries(storage_dir)
    rows = entries.get(part)
    if rows is None:
        raise SystemExit("name-map part %r is absent from %s" % (part, storage_dir))
    i_m, i_f = fields.index(match[0]), fields.index(field)
    hit = [i for i, r in enumerate(rows) if r[i_m] == match[1]]
    if len(hit) != 1:
        raise SystemExit("%d entries of part %r have %s=%r" % (len(hit), part, match[0], match[1]))
    r = list(rows[hit[0]])
    r[i_f] = new_value
    rows = list(rows)
    rows[hit[0]] = tuple(r)
    entries = dict(entries, **{part: sorted(rows, key=lambda x: tuple("" if v is None else str(v) for v in x))})
    return {part: M.namemap_commitment(entries)["parts"][part]["digest"]}


def current_part_digests(storage_dir: str, parts, monitor_dir: str | None = None) -> dict:
    """The name-map part digests as the hub's storage holds them now (a RENAME marker's "from", E9 code review m4)."""
    M = _monitor(monitor_dir)
    cur = M.namemap_commitment(M.namemap_entries(storage_dir))["parts"]
    return {p: cur[p]["digest"] for p in parts if p in cur}


def _log(path: str, line: dict) -> None:
    print(json.dumps(line, sort_keys=True), flush=True)
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kind", choices=("PURGE", "RESTORE", "RESTORE_DONE", "RENAME"), default="PURGE",
                    help="PURGE (default): the scheduled loop below; RESTORE, RENAME: one marker now (E9 A6)")
    ap.add_argument("--config", help="operator's copy of configuration.yaml")
    ap.add_argument("--keep-days", type=int, help="retention policy, when no configuration file is at hand")
    ap.add_argument("--until", type=float, default=0.0, help="stop after the last scheduled purge before this time")
    ap.add_argument("--anchor", required=True, help="anchor append URL")
    ap.add_argument("--key-file", help="hex append key; omit only for an anchor that does not check tags")
    ap.add_argument("--tz", help="the hub's time zone, e.g. America/New_York (PURGE)")
    ap.add_argument("--lead-s", type=float, default=120.0, help="append this long before the scheduled purge")
    ap.add_argument("--once", action="store_true", help="issue the next scheduled marker and exit")
    ap.add_argument("--log", default="", help="append a JSON line per issued marker to this file")
    # E9 A6
    ap.add_argument("--reply-tags", choices=("auto", "0", "1"), default=None,
                    help="check the anchor's X-HP-Reply-Auth under the key: 1 always (linked E8/E9 anchors), auto when "
                         "one is sent, 0 never; unset: the earlier append() (no check, raises on a refusal)")
    ap.add_argument("--sign-key", default="", help="operator Ed25519 private key (PKCS#8 PEM): sign every marker")
    ap.add_argument("--attempts", type=int, default=5, help="attempts per marker (with --reply-tags)")
    ap.add_argument("--retry-s", type=float, default=5.0)
    ap.add_argument("--restore-point-ts", type=float, help="RESTORE: time of the backup that is restored")
    ap.add_argument("--backup-wm", default=None, help='RESTORE: the backup\'s largest keys, JSON {"states": N, '
                    '"events": N} (the verifier needs them)')
    ap.add_argument("--restore-marker", default=None, help="RESTORE_DONE: the RESTORE marker it closes, as issued (JSON "
                    "object, e.g. the 'marker' field of the issuer's log line)")
    ap.add_argument("--post-restart-wm", default=None, help='RESTORE_DONE: the restored recorder\'s largest keys after the '
                    'restart, JSON {"states": N, "events": N}')
    ap.add_argument("--hub-started-ts", type=float, default=None, help="RESTORE_DONE: the restored hub's start time")
    ap.add_argument("--monitors", default="", help="RESTORE, RENAME: comma-separated record-signing key fingerprints of "
                    "the monitors the marker is for (a verifier rejects it on another monitor's chain)")
    ap.add_argument("--rename-part", action="append", default=[], help="RENAME: name-map part (auth, person, entity, "
                    "device); with --rename-digest, or with --storage and --rename-match/-field/-to")
    ap.add_argument("--rename-digest", action="append", default=[], help="RENAME: the part's digest after the change")
    ap.add_argument("--storage", help="RENAME: the hub's .storage directory (read only)")
    ap.add_argument("--rename-match", help="RENAME: FIELD=VALUE selecting the one entry that changes")
    ap.add_argument("--rename-field", help="RENAME: the field that changes")
    ap.add_argument("--rename-to", help="RENAME: its new value")
    ap.add_argument("--entity-id-from", help="RENAME: entity_id before (recorder rows change too)")
    ap.add_argument("--entity-id-to", help="RENAME: entity_id after")
    ap.add_argument("--note", default=None)
    ap.add_argument("--monitor-dir", default=None)
    a = ap.parse_args()
    key = bytes.fromhex(open(a.key_file).read().strip()) if a.key_file else None
    signer = load_signer(a.sign_key) if a.sign_key else None
    tags = a.reply_tags or "auto"
    if a.kind != "PURGE":
        if a.kind == "RESTORE_DONE":
            if not (a.restore_marker and a.post_restart_wm):
                raise SystemExit("RESTORE_DONE needs --restore-marker and --post-restart-wm")
            m = restore_done_marker(json.loads(a.restore_marker), json.loads(a.post_restart_wm), a.hub_started_ts,
                                    note=a.note, monitors=[x for x in a.monitors.split(",") if x])
        elif a.kind == "RESTORE":
            if a.restore_point_ts is None:
                raise SystemExit("RESTORE needs --restore-point-ts")
            bw = json.loads(a.backup_wm) if a.backup_wm else None
            m = restore_marker(a.restore_point_ts, note=a.note, backup_wm=bw,
                               monitors=[x for x in a.monitors.split(",") if x])
        else:
            parts = dict(zip(a.rename_part, a.rename_digest))
            before = None
            if a.storage:
                if len(a.rename_part) != 1 or not (a.rename_match and a.rename_field and a.rename_to is not None):
                    raise SystemExit("--storage needs one --rename-part and --rename-match, --rename-field, --rename-to")
                f, v = a.rename_match.split("=", 1)
                parts = renamed_part_digests(a.storage, a.rename_part[0], (f, v), a.rename_field, a.rename_to,
                                             a.monitor_dir)
                before = current_part_digests(a.storage, parts, a.monitor_dir)
            if not parts and not a.entity_id_from:
                raise SystemExit("RENAME needs part digests or an entity_id change")
            eid = (a.entity_id_from, a.entity_id_to) if a.entity_id_from else None
            m = rename_marker(parts, entity_id=eid, note=a.note, from_parts=before,
                              monitors=[x for x in a.monitors.split(",") if x])
        r = issue(a.anchor, key, m, signer, tags, a.attempts, a.retry_s)
        _log(a.log, {"issued": m, "outcome": r})
        return 0 if r["ok"] else 1
    if not a.tz:
        raise SystemExit("PURGE needs --tz")
    while True:
        pol = purge_policy(a.config) if a.config else {"auto_purge": True, "purge_keep_days": int(a.keep_days)}
        if not pol["auto_purge"]:
            print(json.dumps({"auto_purge": False, "note": "no scheduled purge; nothing to declare"}))
            return 0
        now = time.time()
        nxt = scheduled_purges(now + a.lead_s, now + 2 * DAY, a.tz)[0]
        if a.until and nxt > a.until:
            return 0
        if a.reply_tags is None and signer is None:
            # the earlier behaviour, unchanged (E2's issuer)
            time.sleep(max(0.0, nxt - a.lead_s - time.time()))
            m = scoped_marker(nxt, pol["purge_keep_days"] * DAY)
            resp = append(a.anchor, key, m)
            line = {"issued": m, "anchor_response": resp, "policy": pol}
            print(json.dumps(line), flush=True)
            if a.log:
                with open(a.log, "a") as fh:
                    fh.write(json.dumps(line) + "\n")
            if a.once:
                return 0
            time.sleep(a.lead_s + 60)
            continue
        # E9 A6: wait on the wall clock, issue (signed, reply-checked, retried until the scheduled time), log, go on
        wait_until(nxt - a.lead_s)
        m = scoped_marker(nxt, pol["purge_keep_days"] * DAY)
        r = issue(a.anchor, key, m, signer, tags, a.attempts, a.retry_s, deadline=nxt)
        _log(a.log, {"issued": m, "outcome": r, "policy": pol})
        if a.once:
            return 0 if r["ok"] else 1
        wait_until(nxt + 60)


if __name__ == "__main__":
    raise SystemExit(main())
