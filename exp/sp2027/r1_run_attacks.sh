#!/bin/bash
# R1 attack runner for an ISOLATED hub (hpr1-hass-<ver>). Enables an offensive
# component (already bind-mounted in the r1 config copy), triggers it by restart,
# waits on its own ack, pulls the report to /tmp, and disables it again. Writes
# nothing to exp/out (a python aggregator does, under r1_* names).
#
# usage:
#   r1_run_attacks.sh <container> s1 <room>                 -> laundering, 1 room
#   r1_run_attacks.sh <container> ec <room> <trials> <arms> -> e-c arms, 1 room
#     arms is a JSON fragment, e.g. '"PSR"' or '"PSR","PS"'
set -u
C="$1"; kind="$2"; room="$3"
OUTDIR=/config/homeprov_out

enable() {  # add config line (code already present via bind mount) + restart
  docker exec "$C" test -f "/config/custom_components/$1/__init__.py" || {
    echo "FAIL: $1 not present in container"; exit 1; }
  docker exec "$C" sh -c "grep -q '^$1:' /config/configuration.yaml || printf '\n$1:\n' >> /config/configuration.yaml"
  docker restart "$C" >/dev/null; sleep 45
}
disable() {
  docker exec "$C" sh -c "sed -i '/^$1:/d' /config/configuration.yaml"
  docker restart "$C" >/dev/null; sleep 40
}
wait_ack() {  # component ackfile timeout
  local af="$1" end=$((SECONDS+${2:-3600}))
  while [ $SECONDS -lt $end ]; do
    docker exec "$C" test -f "$af" 2>/dev/null && { docker exec "$C" cat "$af"; echo; return 0; }
    sleep 10
  done; echo "TIMEOUT $af"; return 1
}

docker exec "$C" sh -c "printf '%s' '$room' > /config/.hpr_room"

case "$kind" in
  s1)
    docker exec "$C" rm -f $OUTDIR/s1real_ack.json $OUTDIR/s1real_report.json 2>/dev/null
    enable homeprov_s1real
    wait_ack $OUTDIR/s1real_ack.json 2400
    docker cp "$C:$OUTDIR/s1real_report.json" "/tmp/r1_s1_${room}.json" >/dev/null 2>&1 \
      && echo "pulled /tmp/r1_s1_${room}.json" || echo "(no s1 report)"
    disable homeprov_s1real ;;
  ec)
    trials="$4"; arms="$5"
    printf '{"trials": %s, "arms": [%s], "seal_wait_s": 130, "room": "%s"}' \
      "$trials" "$arms" "$room" > /tmp/r1_ec_conf
    docker cp /tmp/r1_ec_conf "$C:/config/.hpr_ec_conf" >/dev/null
    docker exec "$C" rm -f $OUTDIR/ec_ack.json $OUTDIR/ec_report.json 2>/dev/null
    enable homeprov_ec
    wait_ack $OUTDIR/ec_ack.json 3600
    docker cp "$C:$OUTDIR/ec_report.json" "/tmp/r1_ec_${room}.json" >/dev/null 2>&1 \
      && echo "pulled /tmp/r1_ec_${room}.json" || echo "(no ec report)"
    disable homeprov_ec ;;
  *) echo "usage: r1_run_attacks.sh <container> {s1|ec} ..."; exit 2 ;;
esac
