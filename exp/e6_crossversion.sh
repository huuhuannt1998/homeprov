#!/bin/bash
# E6 -- CROSS-VERSION HOME ASSISTANT (mock review section 6, E6).
#
# E4 measured the renderer dependency closure for one release and the paper now
# rests on it. The obvious question is whether that closure is a property of the
# platform or of the patch release, and it cannot be answered by reading the
# schema: three of the invariants E4 relies on were found by experiment.
#
# One implementation note that is load-bearing rather than incidental: /config
# lives in a Docker NAMED VOLUME, not a bind mount from the host. The harness
# writes to the recorder database while Home Assistant holds it open, and SQLite
# doing that across a macOS bind mount returns SQLITE_IOERR rather than blocking
# -- the first run of this experiment lost a whole version that way. A named
# volume keeps the database on the Linux filesystem inside the VM, where SQLite's
# locking works as designed. Config goes in and reports come out via docker cp.
#
# So: run the SAME harness against several releases, each with its OWN fresh
# recorder database, and compare the resulting closures field by field. A fresh
# database per version is not a convenience. The recorder schema migrates
# forward only, so pointing an older release at a newer database either fails or
# silently migrates, and either would make the comparison meaningless.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/exp/out/e6"
VERSIONS="${E6_VERSIONS:-2026.6.4 2026.7.4 2026.8.3 2024.12}"
WARM="${E6_WARM_S:-120}"      # seconds of activity before measuring
mkdir -p "$OUT"
docker network create --internal hp-e6-net >/dev/null 2>&1 || true

for V in $VERSIONS; do
  NAME="hp-e6-${V//./-}"
  VOL="hp-e6-vol-${V//./-}"
  CFG="/tmp/homeprov_e6/$V"          # staging only; the container does not mount it
  echo "=== $V ==="
  docker rm -f "$NAME" >/dev/null 2>&1
  docker volume rm "$VOL" >/dev/null 2>&1
  rm -rf "$CFG"; mkdir -p "$CFG"
  # Fresh config: automations, helpers and the two harness components only.
  cp "$ROOT/testbed/ha-config/automations.yaml" "$CFG/" 2>/dev/null
  cp -r "$ROOT/testbed/ha-config/custom_components" "$CFG/"
  # Drop components that are not needed to measure the renderer and that carry
  # their own side effects (the redteam scenario writes to the recorder on
  # start, which would make one version's window unlike another's).
  rm -rf "$CFG/custom_components/homeprov" "$CFG/custom_components/homeprov_redteam" \
         "$CFG/custom_components/homeprov_e2" 2>/dev/null
  # NOT default_config. It pulls in zeroconf, ssdp and cloud, every one of which
  # fails with ENODEV under --network=none and leaves Home Assistant stuck before
  # it sets up custom components -- the harness then sits waiting for an ack that
  # can never come. Declaring the components the measurement actually needs also
  # keeps the deployment identical across releases, which is the point of E6.
  cat > "$CFG/configuration.yaml" <<'YAML'
homeassistant:
  name: E6
  latitude: 0
  longitude: 0
  elevation: 0
  unit_system: metric
  time_zone: UTC
recorder:
  db_url: sqlite:////config/home-assistant_v2.db
  commit_interval: 5
logbook:
history:
demo:
input_boolean:
  owner_present:
    name: Owner Present
  trigger_00:
    name: Trigger 00
automation: !include automations.yaml
homeprov_bench:
homeprov_e4:
YAML
  docker volume create "$VOL" >/dev/null
  # An INTERNAL docker network, not --network=none. Several components reached
  # transitively from demo/logbook set up zeroconf, whose multicast socket calls
  # fail with ENODEV when there is no interface at all, and Home Assistant then
  # never finishes starting -- the harness waits for an ack that cannot come. An
  # internal network has no route off the host, so the containers still cannot
  # reach the internet or any real device, which is the constraint that matters.
  docker create --name "$NAME" -v "$VOL:/config" --network=hp-e6-net \
     -e TZ=UTC "homeassistant/home-assistant:$V" >/dev/null 2>&1
  docker cp "$CFG/." "$NAME:/config/" >/dev/null 2>&1
  docker start "$NAME" >/dev/null 2>&1
  # Readiness is proven by the harness ANSWERING, not by a log line. Home
  # Assistant logs "Home Assistant initialized" at INFO, which does not reach the
  # container log under the default level, so grepping for it waits out the full
  # timeout on a perfectly healthy container. Sending a command and waiting for
  # its ack proves the recorder is up, the component loaded, and its poll loop is
  # running -- which is what the measurement actually needs.
  send() { printf '%s' "$1" > /tmp/hp_e6_cmd; docker cp /tmp/hp_e6_cmd "$NAME:$2" >/dev/null 2>&1; }
  ok=0
  for i in $(seq 1 72); do
    docker exec "$NAME" test -f /config/homeprov_bench.ack >/dev/null 2>&1 && { ok=1; break; }
    send reload /config/homeprov_bench.cmd
    sleep 5
  done
  if [ "$ok" = 0 ]; then
    echo "  DID NOT START"; docker logs "$NAME" 2>&1 | tail -5 > "$OUT/${V}_startup_fail.log"
    docker rm -f "$NAME" >/dev/null 2>&1; continue
  fi
  # Generate contexted activity: automation reloads plus concurrent service calls.
  # Enough cycles that entities have a state HISTORY, not just a first row. The
  # picker needs a row with a predecessor (old_state_id) and a context, and a
  # fresh deployment's first row for an entity has neither.
  for r in $(seq 1 8); do
    send interleave /config/homeprov_bench.cmd; sleep 12
  done
  send reload /config/homeprov_bench.cmd; sleep 15
  sleep "$WARM"

  docker exec "$NAME" rm -f /config/homeprov_e4.ack >/dev/null 2>&1
  send closure /config/homeprov_e4.cmd
  got=0
  for i in $(seq 1 90); do
    if docker exec "$NAME" test -f /config/homeprov_e4.ack >/dev/null 2>&1; then got=1; break; fi
    sleep 5
  done
  if [ "$got" = 1 ]; then
    docker exec "$NAME" cat /config/homeprov_e4.ack; echo
    docker cp "$NAME:/config/homeprov_out/e4_closure.json" "$OUT/${V}_closure.json" >/dev/null 2>&1 \
      || echo "  no closure report"
  else
    echo "  NO ACK"; docker logs "$NAME" 2>&1 | tail -20 > "$OUT/${V}_noack.log"
  fi
  docker rm -f "$NAME" >/dev/null 2>&1
  docker volume rm "$VOL" >/dev/null 2>&1
done
echo "E6 DONE"
