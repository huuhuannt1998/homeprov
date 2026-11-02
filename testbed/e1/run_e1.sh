#!/bin/bash
# E1 (round 12, 2026-10-08): TWO-HOST PLACEMENT. The member-account swap arm (PSR, 30 trials per configuration, the
# three motion-light configurations) against a hub whose Core container runs PRIVILEGED, with the monitor and the
# anchor on another host.
#
#   host A  Home Assistant OS 18.3 (generic-aarch64) in a QEMU/HVF virtual machine on the evaluation Mac. The
#           Supervisor runs Core privileged with host networking (recorded below from `docker inspect`).
#   host B  Docker Desktop's Linux virtual machine on the same Mac, standing in for another host: the anchor
#           (hpr-anchord:sig, fresh key), the monitor (closure scheme, encoding v2, replica clock) and the
#           replicator, which copies the recorder from host A over SSH every 2 s (testbed/e1/replicator).
#   devices The MQTT broker and the device simulator of the real deployment (same images, same seed) also run on
#           host B; host A's Core reaches the broker through the QEMU gateway.
#
# Usage: run_e1.sh TAG [TRIALS]    e.g. run_e1.sh e1_psr_clo 30
# The harness is the real deployment's (homeprov_ec arm PSR, homeprov_scenario), installed in host A's /config for
# each configuration and removed after it, exactly as run_experiments.sh EC does on the Container install. The running
# hpr-* deployment is not touched. Never overwrites an existing output.
set -u
TAG=$1; TRIALS=${2:-30}; ARMS='"PSR"'
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
OUT=$REPO/exp/out
SP="<research-dir>/HOMEPROV-P13-exp/e1/$TAG"
VMDIR="<artifact-root>-e1vm"
CC=$REPO/testbed/real/ha-config/custom_components
CFG=/mnt/data/supervisor/homeassistant            # host A's path of Core's /config
A() { ssh -F "$VMDIR/ssh_config" e1a "$@"; }
mkdir -p "$SP/replog"
VCHAIN=e1-$TAG-chain; VPUB=e1-$TAG-pub; VREP=e1-$TAG-rep; VSCR=e1-$TAG-scratch
META=$SP/auth_meta.log
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }

for f in "${TAG}_t_start" "${TAG}_t_end" "${TAG}_report_porch.json" "${TAG}_report_hallway.json" \
         "${TAG}_report_kitchen.json" "${TAG}_detection.json" "${TAG}_config.json"; do
  [ -e "$OUT/$f" ] && { echo "REFUSING: $OUT/$f exists"; exit 3; }
done
for c in e1-anchord e1-monitor e1-replicator; do
  docker ps -a --format '{{.Names}}' | grep -qx $c && { echo "REFUSING: container $c exists"; exit 3; }
done

core_restart() {   # the Supervisor's own restart path, through its CLI container (outside Core), verified
  # Fixed after the run of 2026-10-08 (as-run sha256 ad13b5af..., kept beside the run): that version sent the request
  # from inside Core, so a request issued while the Supervisor was still finishing the previous restart was dropped,
  # and the hallway restart was issued by hand (recorded in exp/out/e1_psr_clo_config.json).
  local before after k=0
  before=$(A 'docker inspect homeassistant --format "{{.State.StartedAt}}"')
  while [ $k -lt 5 ]; do
    A 'docker exec hassio_cli ha core restart' >/dev/null 2>&1
    after=$(A 'docker inspect homeassistant --format "{{.State.StartedAt}}"')
    [ "$after" != "$before" ] && break
    k=$((k+1)); sleep 20
  done
  [ "$after" != "$before" ] || { note "FAIL: Core did not restart"; exit 6; }
  sleep 45
}
enable_offensive() {
  [ -f "$CC/$1/__init__.py" ] || { echo "  FAIL: no $1 under $CC"; exit 1; }
  COPYFILE_DISABLE=1 tar -C "$CC" --exclude __pycache__ -cf - "$1" \
    | A "mkdir -p $CFG/custom_components && tar -C $CFG/custom_components -xf - && rm -f $CFG/custom_components/$1/._*"
  A "test -f $CFG/custom_components/$1/__init__.py" || { echo "  FAIL: $1 did not land"; exit 1; }
  A "grep -q '^$1:' $CFG/configuration.yaml || printf '\n$1:\n' >> $CFG/configuration.yaml"
  core_restart
}
disable_offensive() {
  A "sed -i '/^$1:/d' $CFG/configuration.yaml; rm -rf $CFG/custom_components/$1"
  core_restart
}
teardown() {
  note "teardown: stopping the E1 monitor, anchor and replicator (volumes kept)"
  docker logs e1-monitor > "$SP/monitor.log" 2>&1
  docker stop e1-monitor e1-replicator e1-anchord >/dev/null 2>&1
  A "sed -i '/^homeprov_ec:/d' $CFG/configuration.yaml; test -d $CFG/custom_components/homeprov_ec && rm -rf $CFG/custom_components/homeprov_ec && echo removed-leftover-harness" 2>/dev/null
}

note "tag=$TAG arms=$ARMS trials=$TRIALS scheme=closure placement=two-host"
note "load_before: $(uptime)"
note "git_head: $(git -C $REPO rev-parse HEAD) (monitor.py modified in the working tree: encoding v2, closure, GRACE_S, CLOCK_FILE)"
note "monitor_py_sha256: $(shasum -a 256 $REPO/monitor/monitor.py | cut -c1-16)"
note "replicator_py_sha256: $(shasum -a 256 $REPO/testbed/e1/replicator/replicator.py | cut -c1-16) hub_backup_py_sha256: $(shasum -a 256 $REPO/testbed/e1/replicator/hub_backup.py | cut -c1-16)"
note "hostA_os: $(A 'grep -E "^(NAME|VERSION)=" /etc/os-release | tr "\n" " "')"
note "hostA_core: $(A 'docker inspect homeassistant --format "image={{.Config.Image}} digest={{.Image}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}"')"
note "hostA_vm: $(ps -o command= -p $(cat $VMDIR/qemu-a.pid) | cut -c1-400)"
note "hostA_harness: homeprov_scenario sha256 $(shasum -a 256 $CC/homeprov_scenario/__init__.py | cut -c1-16), homeprov_ec sha256 $(shasum -a 256 $CC/homeprov_ec/__init__.py | cut -c1-16)"
note "clock_skew: mac=$(python3 -c 'import time;print("%.3f"%time.time())') hostA=$(A 'docker exec homeassistant python3 -c "import time;print(\"%.3f\"%time.time())"') mac_after=$(python3 -c 'import time;print("%.3f"%time.time())')"
KEY=$(openssl rand -hex 32)
note "key_fingerprint_sha256_16: $(printf '%s' "$KEY" | shasum -a 256 | cut -c1-16) (key itself not recorded; held only by the anchor and monitor containers on host B)"

trap teardown EXIT
trap 'exit 130' INT TERM HUP
A "ls $CFG/.e1_hub_backup.py" >/dev/null || { echo "hub_backup.py missing on host A"; exit 4; }
for v in $VCHAIN $VPUB $VREP $VSCR; do docker volume create $v >/dev/null; done
docker run -d --name e1-anchord --network e1-net -p 127.0.0.1:19900:9900 \
  -e HOMEPROV_ANCHOR_KEY="$KEY" -v $VCHAIN:/anchor -v $VPUB:/published hpr-anchord:sig >/dev/null || exit 5
docker run -d --name e1-replicator --network e1-net -e E1_REPL_PERIOD=2 \
  -v $VMDIR/ssh-ctr:/e1:ro -v $VREP:/rep -v $SP/replog:/replog hpr-e1-replicator:1 >/dev/null || exit 5
n=0; until docker exec e1-replicator test -f /rep/clock 2>/dev/null || [ $n -ge 30 ]; do sleep 2; n=$((n+1)); done
note "first_replica_after_polls: $n ($(docker exec e1-replicator sh -c 'ls -la /rep | tr "\n" " "'))"
docker run -d --name e1-monitor --network e1-net \
  -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR=http://e1-anchord:9900/append \
  -e HOMEPROV_PERIOD=5 -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$KEY" \
  -e HOMEPROV_SCHEME=closure -e HOMEPROV_CLOCK_FILE=/cfg/clock \
  -v $VREP:/cfg:ro -v $VSCR:/scratch hpr-monitor:e1 >/dev/null || exit 5
note "anchor image: $(docker inspect e1-anchord --format '{{.Config.Image}} {{.Image}}')"
note "monitor image: $(docker inspect e1-monitor --format '{{.Config.Image}} {{.Image}}')"
note "replicator image: $(docker inspect e1-replicator --format '{{.Config.Image}} {{.Image}}')"
sleep 20
# The privileged Core on host A tries the anchor's one verb without the key and with a forged tag.
PROBE='import urllib.request,json
def post(h):
    r=urllib.request.Request("http://10.0.2.2:19900/append",data=b"{\"sealed\": {}}",method="POST",headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:80]
print(json.dumps({"untagged":post({"Content-Type":"application/json"}),"forged_tag":post({"Content-Type":"application/json","X-HP-Auth":"0"*64})}))'
printf '%s' "$PROBE" | A "cat > $CFG/.e1_probe.py"
note "probe_from_hub: $(A 'docker exec homeassistant python3 /config/.e1_probe.py')"
# What a privileged Core holds on host A: every capability, and host A's raw disk devices. Host A holds no HOMEPROV
# key or chain in this placement.
note "core_privilege_on_hostA: $(A 'docker exec homeassistant sh -c "grep CapEff /proc/self/status | tr -s \"\t \" \" \"; ls /dev/vda8 2>&1"' | tr '\n' ' ')"
sleep 40
note "monitor_log_head: $(docker logs e1-monitor 2>&1 | head -3 | cut -c1-400 | tr '\n' ' ')"
note "chain_lines_before_run: $(docker exec e1-anchord sh -c 'wc -l < /anchor/chain.jsonl')"

note "starting E1 runner arms=$ARMS x$TRIALS"
date -u +%s > "$OUT/${TAG}_t_start"
for room in porch hallway kitchen; do
  note "-- configuration: $room --"
  A "mkdir -p $CFG/homeprov_out; printf '%s' '$room' > $CFG/.hpr_room"
  printf '{"trials": %s, "arms": [%s], "seal_wait_s": 130, "room": "%s"}' "$TRIALS" "$ARMS" "$room" \
    | A "cat > $CFG/.hpr_ec_conf"
  A "rm -f $CFG/homeprov_out/ec_ack.json $CFG/homeprov_out/ec_report.json"
  enable_offensive homeprov_ec
  end=$((SECONDS+3600))
  while [ $SECONDS -lt $end ]; do
    if A "test -f $CFG/homeprov_out/ec_ack.json" 2>/dev/null; then
      note "ack $room: $(A "cat $CFG/homeprov_out/ec_ack.json")"; break
    fi
    sleep 10
  done
  [ $SECONDS -ge $end ] && note "TIMEOUT on $room"
  A "cat $CFG/homeprov_out/ec_report.json" > "$OUT/${TAG}_report_${room}.json" \
    && note "  -> exp/out/${TAG}_report_${room}.json" || note "  (no report for $room)"
  disable_offensive homeprov_ec
done
date -u +%s > "$OUT/${TAG}_t_end"
note "settling 90s so the final segments seal and anchor"
sleep 90
note "chain_lines after run: $(docker exec e1-anchord sh -c 'wc -l < /anchor/chain.jsonl')"
note "load_after: $(uptime)"
docker exec e1-anchord cat /anchor/chain.jsonl > "$SP/chain.jsonl"
docker exec e1-anchord sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/refusals.jsonl"
note "running the E1 aggregator (shipped e_ps_detection scoring, host-A transport)"
E1_SP="$SP" EC_SCRATCH="$SP/ps_verify" python3 "$REPO/exp/stages/e1_two_host.py" --tag "$TAG" porch hallway kitchen \
  > "$SP/aggregate.log" 2>&1
note "aggregator exit: $? ($(tail -3 "$SP/aggregate.log" | tr '\n' ' '))"
gzip -c "$SP/chain.jsonl" > "$OUT/${TAG}_anchor_chain.jsonl.gz"
note "done"
python3 - "$SP" "$OUT" "$TAG" "$0" <<'PY'
import hashlib, json, sys
sp, out, tag, script = sys.argv[1:]
R = __import__("os").environ["ARTIFACT_ROOT"]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
cfg = {"experiment": f"{tag}: E1 two-host placement, member-account swap (arm PSR) against a privileged Core on Home "
                     "Assistant OS, monitor and authenticated anchor on another host (a second VM on the same Mac)",
       "monitor": {"image": "hpr-monitor:e1", "scheme": "closure", "encoding": "v2", "clock_file": "/cfg/clock",
                   "period_s": 5, "monitor_py_sha256": h(f"{R}/monitor/monitor.py")},
       "replicator": {"image": "hpr-e1-replicator:1", "period_s": 2,
                      "replicator_py_sha256": h(f"{R}/testbed/e1/replicator/replicator.py"),
                      "hub_backup_py_sha256": h(f"{R}/testbed/e1/replicator/hub_backup.py")},
       "configuration_log": [l.rstrip("\n") for l in open(f"{sp}/auth_meta.log")],
       "anchor_chain": {"file": f"exp/out/{tag}_anchor_chain.jsonl.gz",
                        "records": sum(1 for l in open(f"{sp}/chain.jsonl") if l.strip()),
                        "sha256_uncompressed": h(f"{sp}/chain.jsonl")},
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "x"), indent=1)
PY
