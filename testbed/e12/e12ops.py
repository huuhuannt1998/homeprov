"""E12 (review r5) run helpers, called by testbed/e12/run_e12.sh. COPIED from testbed/e9/e9ops.py (E9-frozen) and changed
only where E12 needs it: the schedule (two days, no attack batch, no name-map session, no restore: a planned restart on
day 1 and Home Assistant's own backup on day 2; the smoke compressed likewise), and three new commands -- e12-config,
commit-cadence and default-commit-interval. Every other command is E9's, byte for byte in behaviour. Standard library
only (runs on the Mac's pinned python3 and in the python:3.12-slim images of the monitor and the anchor).

    e12-config    the E12 hub configuration from the original: the recorder block's commit_interval line removed (so
                  Home Assistant's default applies), the harness's backup automation appended; refuses on anything else
    commit-cadence  sample the recorder's -wal file (size, mtime) from OUTSIDE the hub on a read-only mount and report
                  the intervals between commit bursts (the hub's commit interval, observed)
    default-commit-interval  the integer DEFAULT_COMMIT_INTERVAL from recorder source lines on stdin (preflight)
    schedule      the event list of a run (real: E12_DAYS days from --start; smoke: compressed), one JSON document
    issue         append ONE operator marker (PURGE, RESTORE, RESTORE_DONE or RENAME, built and signed with rig.marker_issuer, part A
                  item A6) to each named anchor under that anchor's operator key, every reply tag checked (runs in a
                  throwaway container on the deployment network; keys are read from files in the operator's volume,
                  never from arguments, and are never printed)
    namemap       the hub's display-relevant name map (users, persons, entities, devices) and, for a planned change,
                  the predicted part digests after it (runs in the monitor image, with the hub's configuration volume
                  mounted read-only; uses the monitor's own namemap code; prints display fields only, no credential)
    namemap-sanitize  a copy of the hub's storage holding only the name map's display fields (same digest)
    ha-backup     wrap a consistent SQLite copy of the recorder in Home Assistant's backup format (outer tar with
                  backup.json and homeassistant.tar.gz holding data/home-assistant_v2.db and an empty
                  data/home-assistant_v2.db-wal), the archive Home Assistant's own restore code reads at start-up
    hostlog       background logger on the Mac: wall-clock ticks and gaps (host sleep), the Docker VM's
                  time()-monotonic() offset (it moves when the VM was suspended), the hub's StartedAt and status, power
                  source and lid state, and /proc/1/io of each monitor container (bytes read and written)
    sleep-guard   decide from the host log whether the hub's 04:12 purge timer is late (the VM slept since the hub's
                  last start): prints {"restart": true|false, ...}
    pmset         Sleep / Wake / DarkWake entries of `pmset -g log` between two UTC times, as JSON lines

Every wait here and in run_e9.sh is on the wall clock: the Mac's sleep stops Docker's monotonic clock
(drafts/round13/E2_PURGE_DIAGNOSIS.md), so nothing is scheduled with a monotonic sleep of more than a few seconds.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time

DAY = 86400.0
UTC = dt.timezone.utc


def iso(t):
    return dt.datetime.fromtimestamp(float(t), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    s = s.strip().replace("Z", "+00:00")
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.timestamp()


# ------------------------------------------------------------------------------------------------ schedule
ROOMS = ("porch", "hallway", "kitchen")


PURGE_TOD = 4 * 3600 + 12 * 60     # the hub's own nightly purge: 04:12:00 UTC (Home Assistant's recorder)
RESTART_TOD = 20 * 3600            # pre-registered UTC times of day of the special events
NAMEMAP_TOD = 17 * 3600
BACKUP_TOD = 20 * 3600
RESTORE_TOD = 20.5 * 3600


def at_tod(d0, tod):
    """The first time at or after d0 whose UTC time of day is `tod` seconds: always inside the day [d0, d0 + DAY)."""
    return d0 + (tod - d0) % DAY


def real_schedule(start, days, a):
    """Seven days from `start` (registered: 12:00 UTC; amendment 1: any time of day outside (03:40, 04:45] UTC), day d =
    [start + (d-1) x 24 h, + 24 h). Daily: attack batch at +2 h, end-of-day snapshot at the day's end + 30 s, and each
    night at the first 04:12:00 UTC (the hub's own purge) inside the day: sleep guard 03:40, pre-purge snapshot 03:55,
    PURGE marker 04:10:00 (issuer started 04:07), post-purge snapshot 04:45. Special events at their registered day and
    UTC time of day: day 2 planned hub restart 20:00; day 3 name-map session 17:00 (benign rename, benign re-link and
    revert, the re-link attack, declared clean-up); day 4 backup 20:00, restore 20:30. For start = 12:00 UTC this is
    the registered schedule, byte for byte."""
    ev = [{"t": start, "type": "start"}]
    for d in range(1, days + 1):
        d0 = start + (d - 1) * DAY
        ev.append({"t": d0 + 2 * 3600, "type": "attack_batch", "day": d, "room": ROOMS[(d - 1) % 3],
                   "ec_arms": a.ec_arms, "e7_arms": a.e7_arms, "trials": a.trials})
        if d == a.restart_day:
            ev.append({"t": at_tod(d0, RESTART_TOD), "type": "planned_restart", "day": d})
        if d == a.namemap_day:
            ev.append({"t": at_tod(d0, NAMEMAP_TOD), "type": "namemap_session", "day": d})
        if d == a.restore_day:
            ev.append({"t": at_tod(d0, BACKUP_TOD), "type": "backup", "day": d})
            ev.append({"t": at_tod(d0, RESTORE_TOD), "type": "restore", "day": d})
        night = at_tod(d0, PURGE_TOD)                           # the first 04:12:00 UTC inside the day
        if not (d0 <= night - 32 * 60 and night + 33 * 60 < d0 + DAY):
            raise SystemExit("start %s: night %d (%s) does not fit inside its day with its sleep guard and snapshots; "
                             "start at a UTC time of day outside (03:40, 04:45]" % (iso(start), d, iso(night)))
        ev.append({"t": night - 32 * 60, "type": "sleep_guard", "day": d, "purge_ts": night})
        ev.append({"t": night - 17 * 60, "type": "snapshot", "label": "night%d_pre" % d, "day": d})
        ev.append({"t": night - 300, "type": "purge_marker", "day": d, "scheduled_ts": night, "post_at": night - 120,
                   "keep_days": a.keep_days})
        ev.append({"t": night + 33 * 60, "type": "snapshot", "label": "night%d_post" % d, "day": d})
        ev.append({"t": d0 + DAY + 30, "type": "day_end", "day": d, "label": "day%d_end" % d,
                   "window": [d0, d0 + DAY]})
    ev.append({"t": start + days * DAY + 60, "type": "end"})
    return ev


def smoke_schedule(start, a):
    """Compressed: three 'days' of a.day_s seconds (default 1080). Day 1: attack batch, then a FORCED purge
    (recorder.purge with keep_days=a.smoke_keep_days, through an MQTT-triggered automation that exists only in the
    scratch hub) behind an operator PURGE marker, with pre/post snapshots. Day 2: planned restart, name-map session (no
    batch). Day 3: backup, restore (RESTORE and RESTORE_DONE markers), then an attack batch after the restore."""
    L = float(a.day_s)
    ev = [{"t": start, "type": "start"}]
    for d in range(1, 4):
        d0 = start + (d - 1) * L
        if d == 1:
            ev.append({"t": d0 + 60, "type": "attack_batch", "day": d, "room": ROOMS[(d - 1) % 3],
                       "ec_arms": a.ec_arms, "e7_arms": a.e7_arms, "trials": a.trials})
        if d == 1:
            p = d0 + L - 120
            ev.append({"t": p - 300, "type": "sleep_guard", "day": d, "purge_ts": p})
            ev.append({"t": p - 240, "type": "snapshot", "label": "night1_pre", "day": d})
            ev.append({"t": p - 150, "type": "purge_marker", "day": d, "scheduled_ts": p, "post_at": p - 120,
                       "keep_days": a.smoke_keep_days})
            ev.append({"t": p, "type": "forced_purge", "day": d, "keep_days": a.smoke_keep_days})
            ev.append({"t": p + 75, "type": "snapshot", "label": "night1_post", "day": d})
        if d == 2:
            ev.append({"t": d0 + 60, "type": "planned_restart", "day": d})
            ev.append({"t": d0 + 180, "type": "namemap_session", "day": d})
        if d == 3:
            # backup, restore (with RESTORE_DONE), THEN an attack batch: the attacks after the restore must be detected
            ev.append({"t": d0 + 60, "type": "backup", "day": d})
            ev.append({"t": d0 + 180, "type": "restore", "day": d})
            ev.append({"t": d0 + 480, "type": "attack_batch", "day": d, "room": ROOMS[(d - 1) % 3],
                       "ec_arms": a.ec_arms, "e7_arms": a.e7_arms, "trials": a.trials})
        ev.append({"t": d0 + L + 30, "type": "day_end", "day": d, "label": "day%d_end" % d, "window": [d0, d0 + L]})
    ev.append({"t": start + 3 * L + 60, "type": "end"})
    return ev


def namemap_only_schedule(start, a):
    """Targeted smoke of the setup and the name-map session only: one day of a.day_s seconds."""
    L = float(a.day_s)
    return [{"t": start, "type": "start"}, {"t": start + 60, "type": "namemap_session", "day": 1},
            {"t": start + L + 30, "type": "day_end", "day": 1, "label": "day1_end", "window": [start, start + L]},
            {"t": start + L + 60, "type": "end"}]


# ------------------------------------------------------------------------------------------------ E12 (review r5)
E12_RESTART_TOD = 20 * 3600        # day a.restart_day, 20:00 UTC: one planned hub restart (as E9's)
E12_BACKUP_TOD = 20 * 3600         # day a.backup_day, 20:00 UTC: Home Assistant's own backup
E12_BENIGN_TYPES = {"start", "planned_restart", "backup", "sleep_guard", "snapshot", "purge_marker", "forced_purge",
                    "day_end", "end"}


def e12_schedule(start, days, a):
    """E12's days from `start` (registered 2026-10-22T00:00:00Z; any UTC time of day outside (03:40, 04:45]): day d =
    [start + (d-1) x 24 h, + 24 h). Each night at the first 04:12:00 UTC inside the day (the hub's own purge): sleep guard
    03:40, pre-purge snapshot 03:55, PURGE marker 04:10:00 (issuer started 04:07), post-purge snapshot 04:45; the day's
    end-of-day snapshot at its end + 30 s. Day a.restart_day: planned hub restart 20:00; day a.backup_day: Home
    Assistant's backup 20:00. No attack batch, no name-map session, no restore."""
    ev = [{"t": start, "type": "start"}]
    for d in range(1, days + 1):
        d0 = start + (d - 1) * DAY
        if d == a.restart_day:
            ev.append({"t": at_tod(d0, E12_RESTART_TOD), "type": "planned_restart", "day": d})
        if d == a.backup_day:
            ev.append({"t": at_tod(d0, E12_BACKUP_TOD), "type": "backup", "day": d})
        night = at_tod(d0, PURGE_TOD)
        if not (d0 <= night - 32 * 60 and night + 33 * 60 < d0 + DAY):
            raise SystemExit("start %s: night %d (%s) does not fit inside its day with its sleep guard and snapshots; "
                             "start at a UTC time of day outside (03:40, 04:45]" % (iso(start), d, iso(night)))
        ev.append({"t": night - 32 * 60, "type": "sleep_guard", "day": d, "purge_ts": night})
        ev.append({"t": night - 17 * 60, "type": "snapshot", "label": "night%d_pre" % d, "day": d})
        ev.append({"t": night - 300, "type": "purge_marker", "day": d, "scheduled_ts": night, "post_at": night - 120,
                   "keep_days": a.keep_days})
        ev.append({"t": night + 33 * 60, "type": "snapshot", "label": "night%d_post" % d, "day": d})
        ev.append({"t": d0 + DAY + 30, "type": "day_end", "day": d, "label": "day%d_end" % d, "window": [d0, d0 + DAY]})
    ev.append({"t": start + days * DAY + 60, "type": "end"})
    return ev


def e12_smoke_schedule(start, a):
    """Compressed: two 'days' of a.day_s seconds. Day 1: planned restart, then a FORCED purge (the scratch hub's
    MQTT-triggered recorder.purge) behind an operator PURGE marker with pre/post snapshots. Day 2: the backup."""
    L = float(a.day_s)
    ev = [{"t": start, "type": "start"}, {"t": start + 60, "type": "planned_restart", "day": 1}]
    p = start + L - 120
    ev += [{"t": p - 300, "type": "sleep_guard", "day": 1, "purge_ts": p},
           {"t": p - 240, "type": "snapshot", "label": "night1_pre", "day": 1},
           {"t": p - 150, "type": "purge_marker", "day": 1, "scheduled_ts": p, "post_at": p - 120,
            "keep_days": a.smoke_keep_days},
           {"t": p, "type": "forced_purge", "day": 1, "keep_days": a.smoke_keep_days},
           {"t": p + 75, "type": "snapshot", "label": "night1_post", "day": 1},
           {"t": start + L + 30, "type": "day_end", "day": 1, "label": "day1_end", "window": [start, start + L]},
           {"t": start + L + 60, "type": "backup", "day": 2},
           {"t": start + 2 * L + 30, "type": "day_end", "day": 2, "label": "day2_end", "window": [start + L, start + 2 * L]},
           {"t": start + 2 * L + 60, "type": "end"}]
    return ev


def e12_config(text, topic="hpr/e12/ops/backup"):
    """(new text, diff): the recorder block's `commit_interval:` line removed, the harness's backup automation appended.
    Refuses (ValueError) unless exactly one such line is removed, inside the top-level `recorder:` block."""
    lines = text.splitlines(keepends=True)
    out, removed, block = [], [], None
    for i, ln in enumerate(lines):
        m = re.match(r"^([A-Za-z_][\w ]*):", ln)
        if m and not ln.startswith((" ", "\t")):
            block = m.group(1).strip()
        if block == "recorder" and re.match(r"^\s+commit_interval\s*:\s*\S+\s*$", ln):
            removed.append({"line": i + 1, "text": ln.rstrip("\n")})
            continue
        out.append(ln)
    if len(removed) != 1:
        raise ValueError("expected exactly one recorder commit_interval line, found %d" % len(removed))
    if re.search(r"^automation e12\s*:", text, re.M):
        raise ValueError("an `automation e12:` block is already present")
    body = "".join(out)
    if not body.endswith("\n"):
        body += "\n"
    add = ("\n# E12 (review r5): Home Assistant's own backup, triggered by the harness over MQTT; removed at teardown\n"
           "automation e12:\n"
           "  - id: e12_backup_harness\n"
           "    alias: \"E12 backup (harness)\"\n"
           "    triggers:\n"
           "      - trigger: mqtt\n"
           "        topic: \"%s\"\n"
           "    actions:\n"
           "      - action: backup.create\n" % topic)
    return body + add, {"removed": removed, "appended_lines": add.count("\n"), "topic": topic}


def cmd_e12_config(a):
    try:
        new, diff = e12_config(open(a.input).read(), a.topic)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    with open(a.out, "x") as fh:
        fh.write(new)
    print(json.dumps(dict(diff, ok=True, sha256=hashlib.sha256(new.encode()).hexdigest())))
    return 0


def parse_default_commit_interval(text):
    """The integer assigned to DEFAULT_COMMIT_INTERVAL in recorder source lines; None if absent or ambiguous."""
    vals = {int(m.group(1)) for m in re.finditer(r"^\s*DEFAULT_COMMIT_INTERVAL\s*(?::\s*\w+\s*)?=\s*(\d+)\s*(?:#.*)?$",
                                                    text, re.M)}
    return vals.pop() if len(vals) == 1 else None


def cmd_default_commit_interval(_a):
    v = parse_default_commit_interval(sys.stdin.read())
    print("" if v is None else v)
    return 0 if v is not None else 1


def cadence(samples, merge_s=0.5):
    """Commit bursts of the recorder from (t, size, mtime_ns) samples of its -wal file: a burst starts at a sample whose
    (size, mtime_ns) differs from the previous one, after at least merge_s without a change; returns the bursts' start
    times and the interval statistics."""
    starts, last_change, prev = [], None, None
    for t, size, mt in samples:
        key = (size, mt)
        if prev is not None and key != prev:
            if last_change is None or t - last_change >= merge_s:
                starts.append(t)
            last_change = t
        prev = key
    iv = sorted(b - a for a, b in zip(starts, starts[1:]))
    q = lambda f: iv[min(len(iv) - 1, int(f * (len(iv) - 1) + 0.5))] if iv else None   # noqa: E731
    return {"bursts": len(starts), "intervals": len(iv), "interval_median_s": q(0.5), "interval_p10_s": q(0.1),
            "interval_p90_s": q(0.9), "interval_max_s": iv[-1] if iv else None, "burst_starts": starts[:2000]}


def cmd_commit_cadence(a):
    samples, t_end = [], time.time() + float(a.seconds)
    while time.time() < t_end:
        try:
            st = os.stat(a.wal)
            samples.append((time.time(), st.st_size, st.st_mtime_ns))
        except OSError:
            samples.append((time.time(), None, None))
        time.sleep(float(a.step))
    out = cadence(samples, float(a.merge))
    out.update({"wal": a.wal, "seconds": float(a.seconds), "step_s": float(a.step), "samples": len(samples),
                "t_first": samples[0][0] if samples else None, "t_last": samples[-1][0] if samples else None})
    print(json.dumps(out))
    return 0


def cmd_schedule(a):
    start = parse_iso(a.start) if a.start else time.time()
    if a.smoke and a.smoke_only == "namemap":
        ev = namemap_only_schedule(start, a)
    else:
        ev = e12_smoke_schedule(start, a) if a.smoke else e12_schedule(start, a.days, a)
    bad = [e["type"] for e in ev if e["type"] not in E12_BENIGN_TYPES]
    if bad:
        raise SystemExit("E12 schedules carry no attack, name-map or restore event: %s" % bad)
    ev.sort(key=lambda e: (e["t"], e["type"] != "day_end"))
    for i, e in enumerate(ev):
        e["id"] = i
        e["utc"] = iso(e["t"])
    out = {"mode": ("smoke-" + a.smoke_only if a.smoke and a.smoke_only else "smoke") if a.smoke else "real",
           "start": start, "start_utc": iso(start), "end": ev[-1]["t"], "end_utc": iso(ev[-1]["t"]),
           "days": (1 if a.smoke_only else 2) if a.smoke else a.days,
           "day_s": float(a.day_s) if a.smoke else DAY, "events": ev}
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


# ------------------------------------------------------------------------------------------------ operator markers
def _load_issuer(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("e9_marker_issuer", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def cmd_issue(a):
    """ONE marker, built with rig.marker_issuer's helpers (scoped_marker / restore_marker / rename_marker), signed with
    the operator's Ed25519 key and appended to every anchor named in --anchors alias=KEYFILE (that anchor's operator
    HMAC key, hex) with rig.marker_issuer.issue() (reply tags required, retried, wall-clock deadline). The same marker
    (same issued_ts) goes to every anchor. Keys are read from files and never printed; only fingerprints are."""
    MI = _load_issuer(a.issuer)
    extra = json.loads(a.extra) if a.extra else {}
    signer = MI.load_signer(a.sign_key) if a.sign_key else None
    if a.not_before:
        # the container starts early (Docker took up to 41 s to start one in the smoke run); the marker is posted at the
        # declared wall-clock time, not before
        while time.time() < a.not_before:
            time.sleep(min(5.0, max(0.05, a.not_before - time.time())))
    if a.kind == "PURGE":
        ms = [MI.scoped_marker(a.scheduled_ts, a.keep_days * DAY)]
    elif a.kind == "RESTORE":
        # the backup's largest keys must be SIGNED INTO the marker: the verifier takes K from it and rejects a RESTORE
        # marker without it (E9_IMPL_NOTES.md 11.1); restore_marker() normalises it and adds a random nonce (11.3)
        bw = extra.pop("backup_wm", None)
        if not (isinstance(bw, dict) and all(isinstance(bw.get(t), int) for t in ("states", "events"))):
            raise SystemExit("RESTORE needs backup_wm {\"states\": int, \"events\": int} in --extra")
        ms = [MI.restore_marker(a.restore_point_ts, note=a.note, backup_wm=bw)]
        if ms[0].get("backup_wm") != {t: int(bw[t]) for t in ("states", "events")}:
            raise SystemExit("rig.marker_issuer.restore_marker() did not carry backup_wm")
    elif a.kind == "RESTORE_DONE":
        # the operator saw the hub come back from the restore (review re-check N1, E9_IMPL_NOTES.md 12.1): built by
        # rig.marker_issuer.restore_done_marker() from the RESTORE marker AS ISSUED (it names it by its nonce and the
        # SHA-256 of its canonical JSON), the restored recorder's largest keys read after the restart, and the time the
        # restored hub started (H: the verifier then never excuses a segment starting at or after H)
        restore = extra.pop("restore", None)
        wm = extra.pop("post_restart_wm", None)
        h = extra.pop("hub_started_ts", None)
        want = extra.pop("restore_sha256_expected", None)
        if not isinstance(restore, dict) or restore.get("marker") != "RESTORE" or not restore.get("nonce"):
            raise SystemExit("RESTORE_DONE needs the issued RESTORE marker as 'restore' in --extra")
        if not (isinstance(wm, dict) and all(isinstance(wm.get(t), int) for t in ("states", "events"))):
            raise SystemExit("RESTORE_DONE needs post_restart_wm {\"states\": int, \"events\": int} in --extra")
        if h is None:
            raise SystemExit("RESTORE_DONE needs hub_started_ts in --extra (the harness always passes it)")
        ms = [MI.restore_done_marker(restore, wm, hub_started_ts=float(h), note=a.note)]
        if want and ms[0].get("restore_sha256") != want:
            raise SystemExit("restore_sha256 %s differs from the RESTORE marker's recorded identity %s"
                             % (ms[0].get("restore_sha256"), want))
    else:
        # RENAME: one marker per name-map state the change passes through (a JSON list of {part: digest}), so a seal
        # that catches an intermediate state of a multi-step change is declared too
        pl = json.loads(a.parts)
        ms = [MI.rename_marker(p, note=a.note) for p in (pl if isinstance(pl, list) else [pl])]
    keys = []
    for spec in a.anchors:
        alias, kf = spec.split("=", 1)
        raw = open(kf).read().strip()
        keys.append((alias, bytes.fromhex(raw), hashlib.sha256(raw.encode()).hexdigest()[:16]))
    out = {"markers": [], "issuer_sha256": hashlib.sha256(open(a.issuer, "rb").read()).hexdigest(),
           "operator_sig_fp": MI._fp(signer.public_key()) if signer is not None else None}
    for i, m in enumerate(ms):
        m.update(extra)
        if len(ms) > 1:
            m["state"] = i + 1
            m["states"] = len(ms)
        one = {"marker": m, "anchors": {},
               # the verifier identifies a marker by the SHA-256 of its canonical JSON (e7_verify chain_markers)
               "marker_sha256": hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()}
        for alias, key, fp in keys:
            r = MI.issue("http://%s:%d/append" % (alias, a.port), key, m, signer, "1", attempts=a.attempts,
                         retry_s=5.0, deadline=a.deadline or None, timeout=a.timeout)
            r["operator_key_fp"] = fp
            r.pop("marker", None)
            one["anchors"][alias] = r
        out["markers"].append(one)
    out["marker"], out["anchors"] = out["markers"][0]["marker"], out["markers"][0]["anchors"]
    out["marker_sha256"] = out["markers"][0]["marker_sha256"]
    out["all_ok"] = all(v.get("ok") for one in out["markers"] for v in one["anchors"].values())
    print(json.dumps(out, sort_keys=True, default=str))
    return 0 if out["all_ok"] else 1


# ------------------------------------------------------------------------------------------------ name map
def _monitor(mon_path):
    import importlib.util
    os.environ.setdefault("HOMEPROV_SCRATCH", "/tmp/e9nm")
    os.environ.pop("HOMEPROV_NAMEMAP_DIR", None)
    os.makedirs(os.environ["HOMEPROV_SCRATCH"], exist_ok=True)
    spec = importlib.util.spec_from_file_location("e9_monitor", mon_path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def cmd_namemap(a):
    """Display fields only (the monitor's namemap_entries drops every other field of the auth file at once)."""
    M = _monitor(a.monitor)
    e = M.namemap_entries(a.storage)
    cur = M.namemap_commitment(e)
    out = {"current": {"digest": cur["digest"], "parts": {p: v["digest"] for p, v in cur["parts"].items()}},
           "users": [{"id": r[0], "name": r[1], "is_active": r[2], "system_generated": r[3]} for r in e.get("auth") or []],
           "persons": [{"id": r[0], "name": r[1], "user_id": r[2]} for r in e.get("person") or []],
           "entities_named": len(e.get("entity") or [])}
    if a.change:
        # one change ({"op": ...}) or a sequence of changes applied in order; "states" lists the name map after each
        chs = json.loads(a.change)
        chs = chs if isinstance(chs, list) else [chs]
        e2 = {k: (list(v) if v is not None else None) for k, v in e.items()}
        states = []
        srt = lambda rows: sorted(rows, key=lambda r: tuple("" if v is None else str(v) for v in r))
        for ch in chs:
            if ch["op"] == "person_update":
                rows = []
                for r in e2["person"] or []:
                    r = list(r)
                    if r[0] == ch["person_id"]:
                        for f, v in ch["changes"].items():
                            r[{"name": 1, "user_id": 2}[f]] = v
                    rows.append(tuple(r))
                e2["person"] = srt(rows)
            elif ch["op"] == "entity_rename":
                rows = []
                for r in e2["entity"] or []:
                    r = list(r)
                    if r[0] == ch["entity_id"]:
                        r[1] = ch["name"]
                    rows.append(tuple(r))
                e2["entity"] = srt(rows)
            else:
                raise SystemExit("unknown change op %r" % ch["op"])
            new = M.namemap_commitment({k: ([tuple(x) for x in v] if v is not None else None) for k, v in e2.items()})
            states.append({"digest": new["digest"], "parts": {p: v["digest"] for p, v in new["parts"].items()},
                           "changed_parts": sorted(p for p in new["parts"]
                                                   if new["parts"][p]["digest"] != cur["parts"][p]["digest"])})
        out["states"] = states
        out["predicted"] = states[-1]
    print(json.dumps(out, sort_keys=True))


def cmd_namemap_sanitize(a):
    """A copy of the hub's storage that holds ONLY the name map's display fields (the monitor's NAMEMAP_PARTS), in the
    storage files' own layout, so namemap_entries() on it gives the same entries and digest as on the hub's storage. The
    scorer hands it to the verifier (--namemap-storage) instead of the real .storage, whose auth file holds credentials."""
    M = _monitor(a.monitor)
    e = M.namemap_entries(a.storage)
    os.makedirs(a.out, exist_ok=True)
    for part, fname, key, fields in M.NAMEMAP_PARTS:
        rows = e.get(part)
        if rows is None:
            continue
        items = [dict(zip(fields, r)) for r in rows]
        with open(os.path.join(a.out, fname), "w") as fh:
            json.dump({"version": 1, "key": fname, "data": {key: items}, "e9_note": "display fields only"}, fh)
    again = M.namemap_commitment(M.namemap_entries(a.out))
    orig = M.namemap_commitment(e)
    print(json.dumps({"digest": orig["digest"], "sanitized_digest": again["digest"], "same": orig["digest"] == again["digest"],
                      "parts": {p: v["n"] for p, v in orig["parts"].items()}}))
    return 0 if orig["digest"] == again["digest"] else 1


# ------------------------------------------------------------------------------------------------ HA backup archive
def cmd_ha_backup(a):
    """Home Assistant's backup layout as homeassistant/backup_restore.py (2026.7.4) reads it: an outer tar holding
    backup.json ({"homeassistant": {"version"}, "compressed": true, ...}) and homeassistant.tar.gz, whose data/ holds
    home-assistant_v2.db and home-assistant_v2.db-wal (the restore copies both). The database is the consistent copy
    made with SQLite's online backup API, so its WAL is empty."""
    db = open(a.db, "rb").read()
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as tf:
        for name, data in (("data/home-assistant_v2.db", db), ("data/home-assistant_v2.db-wal", b"")):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(a.created), 0o644
            tf.addfile(ti, io.BytesIO(data))
    meta = {"slug": a.slug, "name": "E9 operator backup (recorder only)", "date": iso(a.created),
            "type": "partial", "compressed": True, "protected": False,
            "homeassistant": {"version": a.ha_version, "exclude_database": False},
            "folders": [], "addons": [], "extra": {"e9": "declared operator restore, RESTORE marker"}}
    with tarfile.open(a.out, mode="w") as tf:
        for name, data in (("backup.json", json.dumps(meta).encode()), ("homeassistant.tar.gz", inner.getvalue())):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(a.created), 0o644
            tf.addfile(ti, io.BytesIO(data))
    h = hashlib.sha256(open(a.out, "rb").read()).hexdigest()
    print(json.dumps({"archive": a.out, "archive_sha256": h, "db_sha256": hashlib.sha256(db).hexdigest(),
                      "db_bytes": len(db), "backup_json": meta}))


# ------------------------------------------------------------------------------------------------ host log
def _run(*cmd, timeout=20):
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:                                             # noqa: BLE001
        return None


def _vm_offset(container):
    s = _run("docker", "exec", container, "python", "-c", "import time;print(repr(time.time()-time.monotonic()))")
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _proc_io(container):
    s = _run("docker", "exec", container, "cat", "/proc/1/io")
    if not s:
        return None
    out = {}
    for line in s.splitlines():
        k, _, v = line.partition(":")
        try:
            out[k.strip()] = int(v.strip())
        except ValueError:
            pass
    return out


def _power():
    b = _run("pmset", "-g", "batt") or ""
    src = re.search(r"Now drawing from '([^']+)'", b)
    pct = re.search(r"(\d+)%", b)
    lid = _run("sh", "-c", "ioreg -r -k AppleClamshellState -d 4 | grep AppleClamshellState | head -1") or ""
    return {"source": src.group(1) if src else None, "percent": int(pct.group(1)) if pct else None,
            "lid_closed": ("Yes" in lid) if lid else None}


def cmd_hostlog(a):
    """Runs until --until (wall clock) or until --stop-file exists. One JSON line per event; never prints a key."""
    last = time.time()
    last_started = None
    n = 0
    with open(a.out, "a", buffering=1) as fh:
        def w(**kw):
            kw["ts"] = time.time()
            kw["utc"] = iso(kw["ts"])
            fh.write(json.dumps(kw, sort_keys=True) + "\n")
        w(kind="hostlog_start", pid=os.getpid(), hub=a.hub, monitors=a.monitors, vm_probe=a.vm_probe)
        while True:
            now = time.time()
            if (a.until and now >= a.until) or (a.stop_file and os.path.exists(a.stop_file)):
                w(kind="hostlog_stop")
                return 0
            gap = now - last
            if gap > a.gap_s:
                w(kind="wall_gap", gap_s=round(gap, 3), since_utc=iso(last))
            last = now
            st = _run("docker", "inspect", a.hub, "--format", "{{.State.StartedAt}} {{.State.Status}}")
            started = st.split()[0] if st else None
            if started != last_started:
                w(kind="hub_state", started_at=started, status=(st.split()[1] if st and len(st.split()) > 1 else None),
                  previous_started_at=last_started, vm_offset=_vm_offset(a.vm_probe) if a.vm_probe else None)
                last_started = started
            if n % max(1, int(a.slow_every)) == 0:
                rec = {"power": _power()}
                if a.vm_probe:
                    rec["vm_offset"] = _vm_offset(a.vm_probe)
                for m in a.monitors:
                    rec["io_" + m] = _proc_io(m)
                st = _run("docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}", *a.monitors)
                rec["stats"] = dict((l.split("|", 1)[0], l.split("|", 1)[1]) for l in (st or "").splitlines() if "|" in l)
                w(kind="sample", **rec)
            n += 1
            # wall-clock pacing: short sleeps only, so a host sleep shows as one long gap, not as a stalled timer
            nxt = now + a.tick_s
            while time.time() < nxt:
                time.sleep(min(2.0, max(0.05, nxt - time.time())))


def cmd_sleep_guard(a):
    """The hub arms its 04:12 purge on the VM's monotonic clock when it starts; every second the VM is suspended after
    that delays the purge by one second. The VM offset time()-monotonic() grows by exactly the suspended time. Compare
    the offset measured now with the one measured at (or first after) the hub's current start."""
    rows = [json.loads(l) for l in open(a.hostlog) if l.strip()]
    started = None
    base = None
    for r in rows:
        if r.get("kind") == "hub_state" and r.get("started_at"):
            started, base = r["started_at"], r.get("vm_offset")
        elif base is None and started and r.get("kind") == "sample" and r.get("vm_offset") is not None:
            base = r["vm_offset"]
    lag = (a.now_offset - base) if (base is not None and a.now_offset is not None) else None
    out = {"hub_started_at": started, "vm_offset_at_hub_start": base, "vm_offset_now": a.now_offset,
           "purge_timer_lag_s": round(lag, 3) if lag is not None else None, "threshold_s": a.threshold_s}
    out["restart"] = bool(lag is not None and lag > a.threshold_s)
    if lag is None:
        out["note"] = "no baseline offset for the hub's current start: no restart (the lag cannot be measured)"
    print(json.dumps(out, sort_keys=True))


def cmd_pmset(a):
    lo, hi = parse_iso(a.since), parse_iso(a.until)
    txt = _run("pmset", "-g", "log", timeout=120) or ""
    n = 0
    for l in txt.splitlines():
        m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [-+]\d{4}) (Sleep|Wake|DarkWake|Assertions)\s+(.*)$", l)
        if not m or m.group(2) == "Assertions":
            continue
        t = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S %z").timestamp()
        if lo <= t <= hi:
            print(json.dumps({"ts": t, "utc": iso(t), "event": m.group(2), "detail": m.group(3)[:200]}))
            n += 1
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("e12-config")
    s.add_argument("--in", dest="input", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--topic", default="hpr/e12/ops/backup")
    s = sub.add_parser("commit-cadence")
    s.add_argument("--wal", required=True)
    s.add_argument("--seconds", type=float, default=120.0)
    s.add_argument("--step", type=float, default=0.05)
    s.add_argument("--merge", type=float, default=0.5)
    sub.add_parser("default-commit-interval")
    s = sub.add_parser("schedule")
    s.add_argument("--start", default="")
    s.add_argument("--days", type=int, default=2)
    s.add_argument("--backup-day", type=int, default=2)
    s.add_argument("--smoke", action="store_true")
    s.add_argument("--smoke-only", default="", choices=("", "namemap"), help="targeted smoke: setup + name-map session")
    s.add_argument("--day-s", type=float, default=1080.0)
    s.add_argument("--trials", type=int, default=5)
    s.add_argument("--ec-arms", nargs="*", default=["PU", "PSR"])
    s.add_argument("--e7-arms", nargs="*", default=["INS-L", "BD-S"])
    s.add_argument("--keep-days", type=int, default=30)
    s.add_argument("--smoke-keep-days", type=int, default=29)
    s.add_argument("--restart-day", type=int, default=1)
    s.add_argument("--namemap-day", type=int, default=0)      # E12: none
    s.add_argument("--restore-day", type=int, default=0)      # E12: none
    s = sub.add_parser("issue")
    s.add_argument("--kind", choices=("PURGE", "RESTORE", "RESTORE_DONE", "RENAME"), required=True)
    s.add_argument("--scheduled-ts", type=float)
    s.add_argument("--keep-days", type=float)
    s.add_argument("--restore-point-ts", type=float)
    s.add_argument("--parts", default="{}", help="RENAME: {part: digest after the change}, or a list of them (one marker each)")
    s.add_argument("--extra", default="", help="further marker fields (JSON object), signed with the marker")
    s.add_argument("--note", default=None)
    s.add_argument("--anchors", nargs="+", required=True, help="alias=KEYFILE (that anchor's operator key, hex)")
    s.add_argument("--sign-key", default="", help="operator Ed25519 private key (PKCS#8 PEM)")
    s.add_argument("--issuer", default="/rig/marker_issuer.py")
    s.add_argument("--port", type=int, default=9900)
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--attempts", type=int, default=5)
    s.add_argument("--deadline", type=float, default=0.0, help="wall-clock time after which no attempt starts")
    s.add_argument("--not-before", type=float, default=0.0, help="post no earlier than this wall-clock time")
    s = sub.add_parser("namemap")
    s.add_argument("--storage", required=True)
    s.add_argument("--monitor", default="/app/monitor.py")
    s.add_argument("--change", default="")
    s = sub.add_parser("namemap-sanitize")
    s.add_argument("--storage", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--monitor", default="/app/monitor.py")
    s = sub.add_parser("ha-backup")
    s.add_argument("--db", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--created", type=float, required=True)
    s.add_argument("--slug", required=True)
    s.add_argument("--ha-version", required=True)
    s = sub.add_parser("hostlog")
    s.add_argument("--out", required=True)
    s.add_argument("--hub", required=True)
    s.add_argument("--monitors", nargs="*", default=[])
    s.add_argument("--vm-probe", default="", help="a container of this run (python inside) for the VM clock offset")
    s.add_argument("--tick-s", type=float, default=30.0)
    s.add_argument("--slow-every", type=int, default=2, help="a power/VM/io sample every N ticks")
    s.add_argument("--gap-s", type=float, default=90.0)
    s.add_argument("--until", type=float, default=0.0)
    s.add_argument("--stop-file", default="")
    s = sub.add_parser("sleep-guard")
    s.add_argument("--hostlog", required=True)
    s.add_argument("--now-offset", type=float, default=None)
    s.add_argument("--threshold-s", type=float, default=30.0)
    s = sub.add_parser("pmset")
    s.add_argument("--since", required=True)
    s.add_argument("--until", required=True)
    a = ap.parse_args()
    return {"schedule": cmd_schedule, "issue": cmd_issue, "namemap": cmd_namemap, "ha-backup": cmd_ha_backup,
            "namemap-sanitize": cmd_namemap_sanitize,
            "hostlog": cmd_hostlog, "sleep-guard": cmd_sleep_guard, "pmset": cmd_pmset,
            "e12-config": cmd_e12_config, "commit-cadence": cmd_commit_cadence,
            "default-commit-interval": cmd_default_commit_interval}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
