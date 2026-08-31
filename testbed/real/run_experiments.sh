#!/bin/bash
# HomeProv realistic-substrate experiment runner.
#
# Every experiment here runs against the REAL deployment: eclipse-mosquitto as
# the broker, devices announcing over real MQTT discovery, and automations
# instantiated from the motion-light blueprint Home Assistant ships. The
# synthetic `demo` platform is gone.
#
# Usage:  ./run_experiments.sh <experiment>
#         ./run_experiments.sh all
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/exp/out"
C=hpr-hass
mkdir -p "$OUT"

cmd() {  # send a command to a harness component and wait for its ack
  # Components do NOT share a file-naming convention: homeprov_e4 and
  # homeprov_e5 use /config/<domain>.cmd, homeprov_bench uses /config/bench_cmd.
  # Assuming one convention meant the bench never saw a single command and the
  # benign arm timed out looking for an ack that was never going to appear.
  local comp="$1" verb="$2" timeout="${3:-600}" cf af
  case "$comp" in
    homeprov_bench) cf=/config/bench_cmd; af=/config/bench_ack ;;
    *)              cf="/config/${comp}.cmd"; af="/config/${comp}.ack" ;;
  esac
  docker exec $C rm -f "$af" 2>/dev/null
  printf '%s' "$verb" > /tmp/hpr_cmd && docker cp /tmp/hpr_cmd "$C:$cf" >/dev/null
  local end=$((SECONDS+timeout))
  while [ $SECONDS -lt $end ]; do
    if docker exec $C test -f "$af" 2>/dev/null; then
      docker exec $C cat "$af"; echo; return 0
    fi
    sleep 5
  done
  echo "  TIMEOUT waiting for ${comp}.${verb}"; return 1
}

pull() { docker cp "$C:/config/homeprov_out/$1" "$OUT/$2" >/dev/null 2>&1 \
         && echo "  -> exp/out/$2" || echo "  (no $1 produced)"; }

enable_offensive() {  # install AND switch on an offensive component for one run
  # Clear any ack from a PREVIOUS run first. Without this the waiter below finds
  # a stale ack immediately and reports the old result as a fresh one -- which
  # it did, silently, returning a single-trial result from a harness that had
  # since been rewritten for ten trials.
  docker exec $C rm -f /config/homeprov_out/s1real_ack.json \
                       /config/homeprov_out/s1real_report.json 2>/dev/null
  # The files must be copied too. Only the defensive components are installed at
  # setup; adding the config line without the code loads nothing and the run
  # reports "no output produced" rather than an error.
  docker exec $C mkdir -p "/config/custom_components/$1"
  docker cp "$HERE/ha-config/custom_components/$1/." "$C:/config/custom_components/$1/" >/dev/null
  docker exec $C sh -c "grep -q '^$1:' /config/configuration.yaml || printf '\n$1:\n' >> /config/configuration.yaml"
  docker restart $C >/dev/null; sleep 45
}
disable_offensive() {
  docker exec $C sh -c "sed -i '/^$1:/d' /config/configuration.yaml"
  docker exec $C rm -rf "/config/custom_components/$1"
  docker restart $C >/dev/null; sleep 45
}

check_binding() {
  echo "== scenario binding =="
  docker exec $C cat /config/homeprov_out/scenario_binding.json 2>/dev/null \
    || echo "  NOT YET WRITTEN (hub may still be starting)"
}

case "${1:-}" in
  binding)  check_binding ;;

  E25)  # real-deployment characterisation vs the generator
        echo "== E25 real-deployment characterisation =="
        cd "$ROOT/exp" && python3 -c "
import json,sys,os; sys.path.insert(0,os.getcwd())
from stages import stage34_realchar as S
r=S.run({}); json.dump(r,open('out/stage34_realchar.json','w'),indent=2)
c=r.get('comparison',{})
for k,v in c.items(): print(f\"  {k:28s} real={v['real']:.4f} gen={v['generated_mean']:.4f} ratio={v['ratio_real_over_generated']:.2f}\")
d=r.get('largest_divergence',{}); print('  largest divergence:',d.get('dimension'))" ;;

  E4)   echo "== E4 renderer dependency closure, on the real substrate =="
        cmd homeprov_e4 closure 900;    pull e4_closure.json    e4_real_closure.json
        cmd homeprov_e4 roles 900;      pull e4_roles.json      e4_real_roles.json
        cmd homeprov_e4 parentrole 900; pull e4_parentrole.json e4_real_parentrole.json ;;

  E5)   echo "== E5 renderer-backed attack evaluation, on the real substrate =="
        cmd homeprov_e5 run 1800;       pull e5_renderer.json   e5_real_renderer.json ;;

  E2)   echo "== E2 in-process defender subversion, on the real substrate =="
        echo "   the monitor now runs in its OWN CONTAINER with /config read-only,"
        echo "   which is stricter than the original testbed's separate process."
        enable_offensive homeprov_e2
        e2() {  # the component speaks a JSON op protocol on /config/e2_cmd
          docker exec $C rm -f /config/e2_ack 2>/dev/null
          printf '%s' "$1" > /tmp/e2c && docker cp /tmp/e2c "$C:/config/e2_cmd" >/dev/null
          local end=$((SECONDS+180))
          while [ $SECONDS -lt $end ]; do
            if docker exec $C test -f /config/e2_ack 2>/dev/null; then
              docker exec $C cat /config/e2_ack; echo; return 0; fi
            sleep 3
          done; echo "  TIMEOUT"; return 1
        }
        echo "-- 1. install the censoring hook (rebinds one module-level name)"
        e2 '{"op":"install"}'
        echo "-- 2. adversary actuates WHILE censoring its own context"
        ACT=$(e2 '{"op":"act"}'); echo "$ACT"
        echo "-- 3. what the IN-PROCESS defender can see"
        e2 '{"op":"diag"}'
        echo "-- 4. what the EXTERNAL monitor saw (own container, /config read-only)"
        CTX=$(printf '%s' "$ACT" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('ctx',''))
except Exception: print('')")
        echo "   adversary context: ${CTX:-<none>}"
        docker exec hpr-anchord sh -c 'wc -l < /anchor/chain.jsonl' | sed 's/^/   anchor records: /'
        python3 - "$CTX" <<'PYEOF'
import json, subprocess, sys
ctx = (sys.argv[1] or "").strip()
raw = subprocess.run(["docker","exec","hpr-anchord","cat","/anchor/chain.jsonl"],
                     capture_output=True, text=True).stdout
recs = [json.loads(l) for l in raw.splitlines() if l.strip()]
print(f"   anchor holds {len(recs)} sealed records")
out = {"adversary_context": ctx, "anchor_records": len(recs),
       "note": "the in-process defender's view is censored by construction; "
               "the anchor is written by the external monitor, which the "
               "in-process hook cannot reach"}
json.dump(out, open("../../exp/out/e2_real_external.json","w"), indent=2)
PYEOF
        pull e2_result.json e2_real_result.json
        disable_offensive homeprov_e2 ;;

  BENIGN) echo "== benign catalogue, false alarms on real device churn =="
        echo "   real service calls over the broker, not helper toggles"
        for v in reload interleave churn; do cmd homeprov_bench "$v" 300; done
        echo "-- verify the arm actually generated load --"
        docker cp "$ROOT/exp/delivery/check_load.py" "$C:/tmp/check_load.py" >/dev/null 2>&1
        docker exec $C python3 /tmp/check_load.py ;;

  all)  for e in binding E25 E4 E5 E2 S1 BENIGN; do "$0" "$e"; echo; done ;;

  *)    echo "usage: $0 {binding|E25|E4|E5|E2|S1|BENIGN|all}"; exit 2 ;;
esac
