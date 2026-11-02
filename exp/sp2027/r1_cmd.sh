#!/bin/bash
# R1 command helper: send a verb to a homeprov_* component inside an R1 hub and
# wait for its ack. Mirrors testbed/real/run_experiments.sh cmd(), but targets a
# parameterised container and never writes to exp/out itself (callers pull).
# usage: r1_cmd.sh <container> <component> <verb> [timeout_s]
set -u
C="$1"; comp="$2"; verb="$3"; timeout="${4:-900}"
case "$comp" in
  homeprov_bench) cf=/config/bench_cmd; af=/config/bench_ack ;;
  *)              cf="/config/${comp}.cmd"; af="/config/${comp}.ack" ;;
esac
docker exec "$C" rm -f "$af" 2>/dev/null
printf '%s' "$verb" > /tmp/r1_cmd && docker cp /tmp/r1_cmd "$C:$cf" >/dev/null
end=$((SECONDS+timeout))
while [ $SECONDS -lt $end ]; do
  if docker exec "$C" test -f "$af" 2>/dev/null; then
    docker exec "$C" cat "$af"; echo; exit 0
  fi
  sleep 5
done
echo "TIMEOUT ${comp}.${verb}"; exit 1
