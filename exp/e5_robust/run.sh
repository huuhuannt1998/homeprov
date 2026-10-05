#!/bin/bash
# E5 -- monitor robustness against a hostile evidence store (mock review W-A2, W-A3).
#
# The monitor parses a SQLite file the adversary can write. The review asks what
# it does when that file is replaced, truncated, or malformed: does it fail
# closed with an explicit record, seal a WRONG root, or go silent?
#
# EVERY TEST RUNS AGAINST A COPY. The live recorder carries the deployment state
# the other experiments depend on; corrupting it to answer this question would
# destroy the substrate. The monitor's behaviour does not depend on which file
# it is pointed at, so a copy answers the question exactly.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/exp/out/e5_robust.json"
WORK=/tmp/hpr_e5_robust
IMG=hpr-monitor:1
rm -rf "$WORK"; mkdir -p "$WORK/db" "$WORK/scratch" "$WORK/state"

echo "-- pulling a copy of the live recorder --"
for suffix in "" "-wal" "-shm"; do
  docker cp "hpr-hass:/config/home-assistant_v2.db${suffix}" "$WORK/db/recorder.db${suffix}" 2>/dev/null
done
ls -la "$WORK/db" | tail -4
cp -a "$WORK/db" "$WORK/db.pristine"

run_monitor () {   # $1 = condition label
  rm -rf "$WORK/scratch"/* "$WORK/state"/* 2>/dev/null
  # macOS has no coreutils `timeout`; --once exits on its own, and docker's
  # own lifetime bounds a hang.
  docker run --rm \
    -v "$WORK/db":/cfg \
    -v "$WORK/scratch":/scratch \
    -e HOMEPROV_DB=/cfg/recorder.db \
    -e HOMEPROV_ANCHOR=http://127.0.0.1:9/append \
    -e HOMEPROV_SCRATCH=/scratch \
    "$IMG" python3 /app/monitor.py --once 2>&1 | tail -3
}

restore () { rm -rf "$WORK/db"; cp -a "$WORK/db.pristine" "$WORK/db"; }

python3 - "$OUT" <<'PYEOF' &
import sys, json, os
open(sys.argv[1] + ".tmp", "w").write("")
PYEOF
wait

echo "$(date -u +%FT%TZ) conditions" > "$WORK/log"

for cond in baseline db_missing db_empty_schema wal_truncated shm_deleted db_unreadable page_header_corrupt wal_header_corrupt; do
  restore
  case "$cond" in
    baseline)            : ;;
    db_missing)          mv "$WORK/db/recorder.db" "$WORK/db/recorder.db.moved" ;;
    db_empty_schema)     rm -f "$WORK/db/recorder.db"*; python3 -c "
import sqlite3,sys; c=sqlite3.connect('$WORK/db/recorder.db')
c.execute('CREATE TABLE states (state_id INTEGER PRIMARY KEY)')
c.execute('CREATE TABLE states_meta (metadata_id INTEGER PRIMARY KEY, entity_id TEXT)')
c.execute('CREATE TABLE events (event_id INTEGER PRIMARY KEY)')
c.execute('CREATE TABLE event_types (event_type_id INTEGER PRIMARY KEY, event_type TEXT)')
c.commit()" ;;
    wal_truncated)       [ -f "$WORK/db/recorder.db-wal" ] && : > "$WORK/db/recorder.db-wal" ;;
    shm_deleted)         rm -f "$WORK/db/recorder.db-shm" ;;
    db_unreadable)       chmod 000 "$WORK/db/recorder.db" ;;
    page_header_corrupt) python3 -c "
f=open('$WORK/db/recorder.db','r+b'); f.seek(24); f.write(b'\xde\xad\xbe\xef'*4); f.close()" ;;
    wal_header_corrupt)  [ -f "$WORK/db/recorder.db-wal" ] && python3 -c "
f=open('$WORK/db/recorder.db-wal','r+b'); f.seek(0); f.write(b'\x00'*32); f.close()" ;;
  esac
  echo "=== $cond ===" | tee -a "$WORK/log"
  run_monitor "$cond" | tee -a "$WORK/log"
  chmod 644 "$WORK/db/recorder.db" 2>/dev/null
done
restore
echo
echo "log: $WORK/log"
