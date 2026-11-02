#!/bin/bash
# E10 scratch stacks (round 14; drafts/round13/E10_DESIGN.md section 2). Never touches hpr-*, e2-*, e9-*, rka-*, ds-*,
# delaysteer-* or the lab installation's volumes except to READ the lab configuration once, read-only, after E9 ended.
#
#   e10_stack.sh up-lab   PREFIX   a scratch copy of the lab stack: PREFIX-broker (eclipse-mosquitto:2, the deployment's
#                                  mosquitto.conf), PREFIX-devices (hpr-devices:1, the lab simulator), PREFIX-hass
#                                  (homeassistant/home-assistant:$E10_HA_IMAGE, default 2026.7.4, the lab's release) on an
#                                  INTERNAL network PREFIX-net. Configuration cloned READ-ONLY from $E10_SEED_CFG (default
#                                  the lab volume homeprov-real_hpr-config; fallback e6-config, as the E9 smoke did),
#                                  without the recorder, logs, backups, run files and attack integrations. Recorder =
#                                  $E10_SEED_DB (default: E9's final snapshot, a consistent online-backup copy). Two
#                                  scratch-only automations, triggered over MQTT: PREFIX/ops/purge (recorder.purge with
#                                  keep_days = payload) and PREFIX/ops/repack (recorder.purge keep_days 3650, repack true:
#                                  Home Assistant's own VACUUM). /config/.hpr_room = porch.
#   e10_stack.sh up-fresh PREFIX   a FRESH install on $E10_HA_IMAGE (default 2025.11.1, recorder schema 51) for the
#                                  schema-upgrade arm: PREFIX-hass alone, a YAML-only configuration (input booleans, a
#                                  counter, a template temperature sensor with long-term statistics, time-pattern
#                                  automations), so no config entry and no storage file of a later release is needed.
#   e10_stack.sh upgrade  PREFIX IMAGE   stop PREFIX-hass (60 s), keep its volume, start IMAGE on it; prints one JSON line
#                                  with both images, their ids and the recorder's schema_changes before and after.
#   e10_stack.sh down     PREFIX
set -u
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
X="<research-dir>/HOMEPROV-P13-exp/e10"
ACT=${1:-}; P=${2:-}
case "$P" in e10*) ;; *) echo "REFUSING: prefix must start with e10 ($P)"; exit 2 ;; esac
case "$P" in *hpr*|*e2-*|*e9*) echo "REFUSING: prefix $P"; exit 2 ;; esac
NOT_BEFORE=1792425660          # 2026-10-19T16:01:00Z: E9 owns this Mac's Docker until then (no build, no container)
[ "$(date -u +%s)" -lt "$NOT_BEFORE" ] && { echo "REFUSING: before 2026-10-19T16:01:00Z (E9 runs)"; exit 2; }
pgrep -f "testbed/e9/run_e9.sh" >/dev/null && { echo "REFUSING: run_e9.sh is still running (E9 freeze or scoring)"; exit 2; }
NET=$P-net; HUB=$P-hass; CFG=$P-config
up_common_net() { docker network inspect "$NET" >/dev/null 2>&1 || docker network create --internal "$NET" >/dev/null; }
schema() {   # the recorder's schema_changes, read from OUTSIDE the hub (read-only mount, read-only shared memory)
  docker run --rm -v "$CFG":/cfg:ro --entrypoint python "${E10_PROBE_IMAGE:-hpr-monitor:e10}" -c '
import json, sqlite3
c = sqlite3.connect("file:/cfg/home-assistant_v2.db?mode=ro&readonly_shm=1", uri=True, timeout=30)
print(json.dumps({"schema_changes": c.execute("select schema_version, changed from schema_changes order by change_id").fetchall(),
                  "statistics_meta_columns": [r[1] for r in c.execute("pragma table_info(statistics_meta)")],
                  "states_columns": [r[1] for r in c.execute("pragma table_info(states)")],
                  "events_columns": [r[1] for r in c.execute("pragma table_info(events)")]}))' 2>/dev/null | tail -1
}
case "$ACT" in
up-lab)
  for c in $P-broker $P-devices $HUB; do docker ps -a --format '{{.Names}}' | grep -qx "$c" && { echo "exists: $c"; exit 3; }; done
  docker volume inspect "$CFG" >/dev/null 2>&1 && { echo "exists: volume $CFG"; exit 3; }
  SEED_CFG=${E10_SEED_CFG:-homeprov-real_hpr-config}
  SEED_DB=${E10_SEED_DB:-<research-dir>/HOMEPROV-P13-exp/e9/e9_main2/snapshots/final.db}
  HA_IMG=${E10_HA_IMAGE:-homeassistant/home-assistant:2026.7.4}
  [ -f "$SEED_DB" ] || { echo "no seed recorder $SEED_DB"; exit 3; }
  docker volume inspect "$SEED_CFG" >/dev/null 2>&1 || { echo "no seed configuration volume $SEED_CFG"; exit 3; }
  mkdir -p "$X"; cp "$SEED_DB" "$X/$P-seed.db"; chmod 444 "$X/$P-seed.db"
  up_common_net; docker volume create "$CFG" >/dev/null; docker volume create $P-mosq >/dev/null
  # the lab configuration, read-only, into the scratch volume; .storage/auth (credentials) stays inside that volume
  docker run --rm --name $P-seed -v "$SEED_CFG":/src:ro -v "$CFG":/dst -v "$X/$P-seed.db":/seed.db:ro alpine:3 sh -c '
    cd /src && tar --exclude="./home-assistant_v2.db*" --exclude=./homeprov_out --exclude=./.ha_run.lock \
      --exclude="./home-assistant.log*" --exclude="./homeprov_e6.*" --exclude="./homeprov_e10.*" --exclude="./.hpr_*" \
      --exclude=./backups --exclude=./.HA_RESTORE --exclude=./.HA_RESTORE_RESULT -cf - . | tar -C /dst -xf - \
    && rm -rf /dst/custom_components/homeprov_e7 /dst/custom_components/homeprov_ec /dst/custom_components/homeprov_e6 \
              /dst/custom_components/homeprov_e10 \
    && sed -i "/^homeprov_ec:/d;/^homeprov_e7:/d;/^homeprov_e6:/d;/^homeprov_e10:/d" /dst/configuration.yaml \
    && mkdir -p /dst/homeprov_out && cp /seed.db /dst/home-assistant_v2.db && printf porch > /dst/.hpr_room \
    && printf "%s\n" "" "# E10 SCRATCH ONLY: Home Assistant'"'"'s own purge and repack, requested over MQTT at a wall-clock time" \
       "- id: e10s_forced_purge" "  alias: E10 forced purge (scratch only)" "  mode: queued" "  triggers:" \
       "    - trigger: mqtt" "      topic: '"$P"'/ops/purge" "  actions:" "    - action: recorder.purge" "      data:" \
       "        keep_days: \"{{ trigger.payload | int(0) }}\"" "        repack: false" \
       "- id: e10s_repack" "  alias: E10 repack (scratch only)" "  mode: queued" "  triggers:" \
       "    - trigger: mqtt" "      topic: '"$P"'/ops/repack" "  actions:" "    - action: recorder.purge" "      data:" \
       "        keep_days: 3650" "        repack: true" >> /dst/automations.yaml && chown -R 0:0 /dst && du -sh /dst >&2'
  docker run -d --name $P-broker --network "$NET" --network-alias broker \
    -v $REPO/testbed/real/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro -v $P-mosq:/mosquitto/data \
    eclipse-mosquitto:2 >/dev/null
  docker run -d --name $P-devices --network "$NET" hpr-devices:1 >/dev/null
  docker run -d --name "$HUB" --network "$NET" -e TZ=UTC -v "$CFG":/config "$HA_IMG" >/dev/null
  echo "{\"stack\": \"$P\", \"kind\": \"lab-copy\", \"seed_cfg\": \"$SEED_CFG\", \"seed_db\": \"$SEED_DB\", \"seed_db_sha256\": \"$(shasum -a 256 "$X/$P-seed.db" | cut -d' ' -f1)\", \"hub_image\": \"$HA_IMG\", \"hub_image_id\": \"$(docker image inspect "$HA_IMG" --format '{{.Id}}')\"}"
  ;;
up-fresh)
  docker ps -a --format '{{.Names}}' | grep -qx "$HUB" && { echo "exists: $HUB"; exit 3; }
  docker volume inspect "$CFG" >/dev/null 2>&1 && { echo "exists: volume $CFG"; exit 3; }
  HA_IMG=${E10_HA_IMAGE:-homeassistant/home-assistant:2025.11.1}
  up_common_net; docker volume create "$CFG" >/dev/null
  docker run --rm --name $P-seed -v "$CFG":/dst -v "$REPO/testbed/e10/fresh_configuration.yaml":/cfg.yaml:ro alpine:3 sh -c \
    'cp /cfg.yaml /dst/configuration.yaml && mkdir -p /dst/homeprov_out && chown -R 0:0 /dst'
  docker run -d --name "$HUB" --network "$NET" -e TZ=UTC -v "$CFG":/config "$HA_IMG" >/dev/null
  echo "{\"stack\": \"$P\", \"kind\": \"fresh\", \"hub_image\": \"$HA_IMG\", \"hub_image_id\": \"$(docker image inspect "$HA_IMG" --format '{{.Id}}')\", \"configuration_sha256\": \"$(shasum -a 256 $REPO/testbed/e10/fresh_configuration.yaml | cut -d' ' -f1)\"}"
  ;;
upgrade)
  IMG=${3:?usage: e10_stack.sh upgrade PREFIX IMAGE}
  docker image inspect "$IMG" >/dev/null 2>&1 || { echo "image $IMG is not on this machine (pull it before the run)"; exit 3; }
  B_IMG=$(docker inspect "$HUB" --format '{{.Config.Image}}'); B_ID=$(docker inspect "$HUB" --format '{{.Image}}')
  T0=$(date -u +%s)
  docker stop -t 60 "$HUB" >/dev/null; T1=$(date -u +%s)
  BEFORE=$(schema)
  docker rm "$HUB" >/dev/null
  docker run -d --name "$HUB" --network "$NET" -e TZ=UTC -v "$CFG":/config "$IMG" >/dev/null; T2=$(date -u +%s)
  # Home Assistant migrates the recorder at start-up (live migration from schema 48 on): wait until a new state row
  # is committed, or 900 s
  for i in $(seq 1 180); do
    sleep 5
    lag=$(docker run --rm -v "$CFG":/cfg:ro --entrypoint python "${E10_PROBE_IMAGE:-hpr-monitor:e10}" -c "import sqlite3,time;c=sqlite3.connect('file:/cfg/home-assistant_v2.db?mode=ro&readonly_shm=1',uri=True,timeout=30);print(int(time.time()-c.execute('select max(last_updated_ts) from states').fetchone()[0]))" 2>/dev/null | tail -1)
    [ -n "$lag" ] && [ "$lag" -lt 20 ] 2>/dev/null && [ "$(date -u +%s)" -gt $((T2 + 30)) ] && break
  done
  T3=$(date -u +%s)
  AFTER=$(schema)
  echo "{\"stack\": \"$P\", \"from_image\": \"$B_IMG\", \"from_image_id\": \"$B_ID\", \"to_image\": \"$IMG\", \"to_image_id\": \"$(docker image inspect "$IMG" --format '{{.Id}}')\", \"t_stop_requested\": $T0, \"t_stopped\": $T1, \"t_started\": $T2, \"t_writing_again\": $T3, \"hub_started_at\": \"$(docker inspect "$HUB" --format '{{.State.StartedAt}}')\", \"before\": ${BEFORE:-null}, \"after\": ${AFTER:-null}}"
  ;;
down)
  for c in $(docker ps -a --format '{{.Names}}' | grep "^$P-"); do docker rm -f "$c" >/dev/null 2>&1; done
  for v in $(docker volume ls --format '{{.Name}}' | grep "^$P-"); do docker volume rm "$v" >/dev/null 2>&1; done
  for n in $(docker network ls --format '{{.Name}}' | grep "^$P-"); do docker network rm "$n" >/dev/null 2>&1; done
  rm -f "$X/$P-seed.db"
  docker ps -a --format '{{.Names}}' | grep "^$P-"; docker volume ls --format '{{.Name}}' | grep "^$P-"; echo "down $P done" ;;
*) echo "usage: $0 up-lab|up-fresh|upgrade|down PREFIX [IMAGE]"; exit 2 ;;
esac
