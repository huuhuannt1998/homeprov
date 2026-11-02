#!/bin/bash
# Scratch stack for the E9 smoke run (prefix e9s-; never touches hpr-*, e2-* or the default anchor):
#   e9s-broker (eclipse-mosquitto:2, the deployment's mosquitto.conf), e9s-devices (hpr-devices:1, the lab simulator),
#   e9s-hass (homeassistant/home-assistant:2026.7.4, the release the lab installation runs) on an INTERNAL network.
# Configuration: cloned READ-ONLY from the E6 stack's volume e6-config (users, a person, MQTT config entry, entity and
# device registries; recorder, logs and attack integrations dropped), NOT from the default deployment's volume.
# Recorder: a copy of a saved real recorder snapshot (default: the E8 run's, of the lab installation), trimmed to its last
# E9S_SEED_DAYS days (default 3), so a forced purge with a small keep_days deletes real old rows and disconnects real
# retained rows. Storage files that 2026.7.4 cannot read (E6 ran 2026.10.0b2: http, core.device_registry) are dropped.
# Scratch only: one automation, triggered over MQTT (topic e9s/ops/purge, payload keep_days), calls recorder.purge, so
# the smoke run can force a real purge at a wall-clock time without an access token.
# usage: smoke_stack.sh up | down
set -u
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
SEED_CFG=${E9S_SEED_CFG:-e6-config}
SEED_DB=${E9S_SEED_DB:-<research-dir>/HOMEPROV-P13-exp/e8/e8_main/recorder.db}
SEED_DAYS=${E9S_SEED_DAYS:-3}      # keep the last N days of the seed's history (0: all of it)
WORK=${E9S_WORK:-<research-dir>/HOMEPROV-P13-exp/e9/smoke}
HA_IMG=${E9S_HA_IMAGE:-homeassistant/home-assistant:2026.7.4}
case "${1:-}" in
up)
  for c in e9s-broker e9s-devices e9s-hass; do docker ps -a --format '{{.Names}}' | grep -qx $c && { echo "exists: $c"; exit 3; }; done
  for v in e9s-config e9s-mosq; do docker volume inspect $v >/dev/null 2>&1 && { echo "exists: volume $v"; exit 3; }; done
  [ -f "$SEED_DB" ] || { echo "no seed recorder $SEED_DB"; exit 3; }
  # The full 30-day recorder makes each monitor's full-history first poll exceed the Docker VM's free memory (smoke 1,
  # 2026-10-09: OOM kill and restart loop). The smoke keeps the last SEED_DAYS days: rows older than that are deleted
  # from a private copy exactly as a purge would (states, events, and old_state_id set to NULL where its target is gone),
  # then VACUUMed. The source file is opened read-only.
  if [ "$SEED_DAYS" != "0" ]; then
    mkdir -p "$WORK"; TRIM="$WORK/seed_last${SEED_DAYS}d.db"; rm -f "$TRIM"
    python3 - "$SEED_DB" "$TRIM" "$SEED_DAYS" <<'PY' || { echo "seed trim failed"; exit 3; }
import sqlite3, sys
src, dst, days = sys.argv[1], sys.argv[2], float(sys.argv[3])
s = sqlite3.connect("file:%s?mode=ro" % src, uri=True); d = sqlite3.connect(dst); s.backup(d); s.close()
newest = d.execute("select max(last_updated_ts) from states").fetchone()[0]
cut = newest - days * 86400
d.execute("PRAGMA foreign_keys=OFF")
ns = d.execute("delete from states where last_updated_ts < ?", (cut,)).rowcount
ne = d.execute("delete from events where time_fired_ts < ?", (cut,)).rowcount
nd = d.execute("update states set old_state_id = NULL where old_state_id is not null and old_state_id not in (select state_id from states)").rowcount
d.commit(); d.execute("VACUUM"); d.close()
print("seed: kept rows from %.0f (newest %.0f); deleted %d states, %d events; %d old_state_id set NULL" % (cut, newest, ns, ne, nd))
PY
    SEED_DB=$TRIM
  fi
  docker network create --internal e9s-net >/dev/null
  docker volume create e9s-config >/dev/null; docker volume create e9s-mosq >/dev/null
  docker run --rm --name e9s-seed -v "$SEED_CFG":/src:ro -v e9s-config:/dst -v "$SEED_DB":/seed.db:ro alpine:3 sh -c '
    cd /src && tar --exclude="./home-assistant_v2.db*" --exclude=./homeprov_out --exclude=./.ha_run.lock \
      --exclude="./home-assistant.log*" --exclude="./homeprov_e6.*" --exclude="./.hpr_*" --exclude=./backups -cf - . | tar -C /dst -xf - \
    && rm -rf /dst/custom_components/homeprov_e7 /dst/custom_components/homeprov_ec /dst/custom_components/homeprov_e6 \
    && mkdir -p /dst/e9s_dropped && mv /dst/.storage/http /dst/.storage/core.device_registry /dst/e9s_dropped/ \
    && mkdir -p /dst/homeprov_out && sed -i "/^homeprov_ec:/d;/^homeprov_e7:/d;/^homeprov_e6:/d" /dst/configuration.yaml \
    && cp /seed.db /dst/home-assistant_v2.db && chown -R 0:0 /dst \
    && printf "%s\n" "" "# E9 SMOKE ONLY (scratch hub): a forced purge requested over MQTT, so the smoke run can make a real purge" \
       "- id: e9s_forced_purge" "  alias: E9 smoke forced purge (scratch only)" "  mode: queued" "  triggers:" \
       "    - trigger: mqtt" "      topic: e9s/ops/purge" "  actions:" "    - action: recorder.purge" "      data:" \
       "        keep_days: \"{{ trigger.payload | int(0) }}\"" "        repack: false" >> /dst/automations.yaml \
    && ls -la /dst && du -sh /dst'
  docker run -d --name e9s-broker --network e9s-net --network-alias broker \
    -v $REPO/testbed/real/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro -v e9s-mosq:/mosquitto/data \
    eclipse-mosquitto:2 >/dev/null
  docker run -d --name e9s-devices --network e9s-net hpr-devices:1 >/dev/null
  docker run -d --name e9s-hass --network e9s-net -e TZ=UTC -v e9s-config:/config "$HA_IMG" >/dev/null
  docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep e9s ;;
down)
  docker rm -f e9s-hass e9s-devices e9s-broker >/dev/null 2>&1
  for c in $(docker ps -a --format '{{.Names}}' | grep '^e9s'); do docker rm -f "$c" >/dev/null 2>&1; done
  for v in $(docker volume ls --format '{{.Name}}' | grep '^e9s'); do docker volume rm "$v" >/dev/null 2>&1; done
  for n in $(docker network ls --format '{{.Name}}' | grep '^e9s'); do docker network rm "$n" >/dev/null 2>&1; done
  docker ps -a --format '{{.Names}}' | grep '^e9s' ; docker volume ls --format '{{.Name}}' | grep '^e9s' ; docker network ls --format '{{.Name}}' | grep '^e9s'; echo "down done" ;;
*) echo "usage: $0 up|down"; exit 2 ;;
esac
