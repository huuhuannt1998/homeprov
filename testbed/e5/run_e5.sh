#!/bin/bash
# E5 (round 13): LINKED ANCHOR WITH A HEAD WITNESS. The E1 placement (testbed/e1/run_e1.sh: the member-account swap
# arm PSR, 30 trials per configuration, the three motion-light configurations, against a PRIVILEGED Core on Home
# Assistant OS, with the monitor and the anchor on another host) with one change: the anchor is the LINKED daemon and
# its head is held by a witness in a third machine context.
#
#   host A   Home Assistant OS 18.3 (generic-aarch64) in a QEMU/HVF virtual machine on the evaluation Mac; the
#            Supervisor runs Core privileged with host networking. Unchanged from E1.
#   host B   Docker Desktop's Linux virtual machine on the same Mac: the monitor (hpr-monitor:e1, closure scheme,
#            encoding v2, replica clock) and the replicator (hpr-e1-replicator:1, every 2 s), both exactly as in E1,
#            and the anchor, now hpr-anchord:linked (testbed/e5/anchord-linked.Dockerfile: the evaluated anchord.py,
#            unmodified, run through testbed/anchord/anchord_linked.py with HOMEPROV_ANCHOR_LINK=v2), so every record
#            carries the SHA-256 digest of the previous record's line. Fresh append key, as in E1.
#   witness  testbed/anchord/headwitness.py as a python3 process on the Mac itself, outside Docker's VM and outside
#            host A's VM, bound to 127.0.0.1:WPORT. The anchor pushes {seq, head_digest, recv_ts} after every accepted
#            append (HEAD_WITNESS_MODE sync, the daemon's default: before the append is acknowledged) to
#            http://host.docker.internal:WPORT/head, tagged with HMAC-SHA256 under a SEPARATE witness key that only the
#            anchor container and the witness process hold (not the monitor, not host A). The witness refuses untagged
#            and forged pushes, forks and regressions, and logs every head it accepts under $SP/witness/.
#   devices  The MQTT broker and device simulator of E1 (e1-broker, e1-devices) are used as they run; not touched.
#
# Usage: run_e5.sh TAG [TRIALS]    e.g. run_e5.sh e5_psr_lnk 30
# Run it detached, as E1 was:  nohup testbed/e5/run_e5.sh e5_psr_lnk 30 > ~/Research/HOMEPROV-P13-exp/e5/e5_psr_lnk.out 2>&1 &
# The harness is the real deployment's (homeprov_ec arm PSR, homeprov_scenario), installed in host A's /config for
# each configuration and removed after it, as in E1. Never overwrites an existing output; refuses to start if the run
# directory, an output, an E5 container, the chain volume or a port already exists.
set -u
TAG=${1:?usage: run_e5.sh TAG [TRIALS]}; TRIALS=${2:-30}; ARMS='"PSR"'
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
OUT=$REPO/exp/out
SP="<research-dir>/HOMEPROV-P13-exp/e5/$TAG"
VMDIR="<artifact-root>-e1vm"
CC=$REPO/testbed/real/ha-config/custom_components
CFG=/mnt/data/supervisor/homeassistant            # host A's path of Core's /config
APORT=19950                                       # anchor, published on the Mac's loopback (E1 used 19900)
WPORT=19960                                       # head witness, on the Mac's loopback
TPORT=19961                                       # throwaway time server for the clock-offset probe (Mac loopback)
WMODE=sync
PY=$(command -v python3); [ -n "$PY" ] || { echo "python3 not found"; exit 4; }
A() { ssh -F "$VMDIR/ssh_config" e1a "$@"; }
VCHAIN=e5-$TAG-chain; VPUB=e5-$TAG-pub; VREP=e5-$TAG-rep; VSCR=e5-$TAG-scratch
WDIR=$SP/witness
META=$SP/auth_meta.log
WPID=""

# ---------------------------------------------------------------- refusals (nothing is created before these pass)
[ -e "$SP" ] && { echo "REFUSING: $SP exists"; exit 3; }
for f in "${TAG}_t_start" "${TAG}_t_end" "${TAG}_report_porch.json" "${TAG}_report_hallway.json" \
         "${TAG}_report_kitchen.json" "${TAG}_detection.json" "${TAG}_config.json" "${TAG}_linked.json" \
         "${TAG}_linked_chain.jsonl.gz" "${TAG}_witness_heads.jsonl.gz"; do
  [ -e "$OUT/$f" ] && { echo "REFUSING: $OUT/$f exists"; exit 3; }
done
for c in e5-anchord e5-monitor e5-replicator; do
  docker ps -a --format '{{.Names}}' | grep -qx $c && { echo "REFUSING: container $c exists"; exit 3; }
done
docker volume inspect $VCHAIN >/dev/null 2>&1 && { echo "REFUSING: volume $VCHAIN exists (the chain must be fresh)"; exit 3; }
for p in $APORT $WPORT $TPORT; do
  lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 && { echo "REFUSING: port $p is in use"; exit 3; }
done
for c in e1-broker e1-devices; do
  docker ps --format '{{.Names}}' | grep -qx $c || { echo "REFUSING: $c is not running (host A's devices need it)"; exit 3; }
done
A true || { echo "REFUSING: host A unreachable over SSH"; exit 4; }
A "grep -q '^homeprov_ec:' $CFG/configuration.yaml || test -e $CFG/custom_components/homeprov_ec" \
  && { echo "REFUSING: host A still has homeprov_ec installed (leftover of an earlier run)"; exit 3; }
A "ls $CFG/.e1_hub_backup.py" >/dev/null || { echo "hub_backup.py missing on host A"; exit 4; }

mkdir -p "$SP/replog" "$WDIR"
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }
s16() { shasum -a 256 "$1" | cut -c1-16; }

core_restart() {   # the Supervisor's own restart path, through its CLI container (outside Core), verified (as E1)
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
witness_get() {    # GET a witness path from the Mac
  "$PY" -c 'import sys,urllib.request;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())' \
    "http://127.0.0.1:$WPORT$1"
}
clock_hostB() {
  echo "mac=$("$PY" -c 'import time;print("%.6f"%time.time())') hostB=$(docker exec e5-anchord python -c 'import time;print("%.6f"%time.time())') mac_after=$("$PY" -c 'import time;print("%.6f"%time.time())')"
}
clock_probe() {    # offset of the Mac's clock from host B's, NTP-style: 25 exchanges from the anchor container to a
                   # throwaway time server on the Mac's loopback, the one with the shortest round trip kept
  "$PY" -c 'import http.server,sys,time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("%.6f" % time.time()).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H); s.timeout = 10
for _ in range(25): s.handle_request()' $TPORT > /dev/null 2>&1 &
  local tp=$! r
  sleep 0.5
  r=$(docker exec e5-anchord python -c 'import json,sys,time,urllib.request
best = None
for _ in range(25):
    t0 = time.time(); m = float(urllib.request.urlopen(sys.argv[1], timeout=5).read()); t1 = time.time()
    if best is None or t1 - t0 < best[0]: best = (t1 - t0, m - (t0 + t1) / 2)
print(json.dumps({"mac_minus_hostB_ms": round(best[1] * 1000, 3), "min_rtt_ms": round(best[0] * 1000, 3), "n": 25}))' \
    "http://host.docker.internal:$TPORT/" 2>&1 | tail -1)
  kill $tp 2>/dev/null; wait $tp 2>/dev/null
  echo "$r"
}
stop_witness() {
  if [ -n "$WPID" ] && kill -0 "$WPID" 2>/dev/null; then
    [ -s "$WDIR/head_final.json" ] || witness_get /head > "$WDIR/head_at_teardown.json" 2>/dev/null
    kill "$WPID"; sleep 1
    kill -0 "$WPID" 2>/dev/null && kill -9 "$WPID"
    note "witness process $WPID stopped"
  fi
  WPID=""
}
teardown() {
  note "teardown: stopping the E5 monitor, anchor and replicator (volumes kept) and the witness process"
  docker ps -a --format '{{.Names}}' | grep -qx e5-monitor && docker logs e5-monitor > "$SP/monitor.log" 2>&1
  docker ps -a --format '{{.Names}}' | grep -qx e5-anchord && docker logs e5-anchord > "$SP/anchord.log" 2>&1
  docker stop e5-monitor e5-replicator e5-anchord >/dev/null 2>&1
  stop_witness
  A "sed -i '/^homeprov_ec:/d' $CFG/configuration.yaml; test -d $CFG/custom_components/homeprov_ec && rm -rf $CFG/custom_components/homeprov_ec && echo removed-leftover-harness" 2>/dev/null
}

note "tag=$TAG arms=$ARMS trials=$TRIALS scheme=closure placement=two-host anchor=linked(v2) witness=mac-loopback mode=$WMODE"
note "load_before: $(uptime)"
note "git_head: $(git -C $REPO rev-parse HEAD) (working tree: monitor.py modified; testbed/anchord linked files, testbed/e1, testbed/e5 untracked)"
note "monitor_py_sha256: $(s16 $REPO/monitor/monitor.py)"
# The monitor container runs the monitor.py baked into hpr-monitor:e1 (E1's); the verifier imports the repository's.
note "monitor_in_image_sha256: $(docker run --rm --name e5-imgcheck-mon --entrypoint sha256sum hpr-monitor:e1 /app/monitor.py | cut -c1-16) (hpr-monitor:e1 /app/monitor.py; the repository file above is what the verifier imports)"
note "replicator_py_sha256: $(s16 $REPO/testbed/e1/replicator/replicator.py) hub_backup_py_sha256: $(s16 $REPO/testbed/e1/replicator/hub_backup.py) hostA_hub_backup_sha256: $(A "sha256sum $CFG/.e1_hub_backup.py" | cut -c1-16)"
note "anchord_py_sha256: $(s16 $REPO/testbed/anchord/anchord.py) anchord_linked_py_sha256: $(s16 $REPO/testbed/anchord/anchord_linked.py) headwitness_py_sha256: $(s16 $REPO/testbed/anchord/headwitness.py) chainverify_py_sha256: $(s16 $REPO/testbed/anchord/chainverify.py) dockerfile_sha256: $(s16 $REPO/testbed/e5/anchord-linked.Dockerfile)"
note "hostA_os: $(A 'grep -E "^(NAME|VERSION)=" /etc/os-release | tr "\n" " "')"
note "hostA_core: $(A 'docker inspect homeassistant --format "image={{.Config.Image}} digest={{.Image}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}}"')"
note "hostA_vm: $(ps -o command= -p $(cat $VMDIR/qemu-a.pid) | cut -c1-400)"
note "hostA_harness: homeprov_scenario sha256 $(s16 $CC/homeprov_scenario/__init__.py), homeprov_ec sha256 $(s16 $CC/homeprov_ec/__init__.py)"
note "clock_skew: mac=$("$PY" -c 'import time;print("%.3f"%time.time())') hostA=$(A 'docker exec homeassistant python3 -c "import time;print(\"%.3f\"%time.time())"') mac_after=$("$PY" -c 'import time;print("%.3f"%time.time())')"
KEY=$(openssl rand -hex 32); WKEY=$(openssl rand -hex 32)
[ ${#KEY} -eq 64 ] && [ ${#WKEY} -eq 64 ] && [ "$KEY" != "$WKEY" ] || { note "FAIL: key generation"; exit 5; }
note "key_fingerprint_sha256_16: $(printf '%s' "$KEY" | shasum -a 256 | cut -c1-16) (append key; not recorded; held only by the anchor and monitor containers on host B)"
note "witness_key_fingerprint_sha256_16: $(printf '%s' "$WKEY" | shasum -a 256 | cut -c1-16) (witness key; not recorded; held only by the anchor container and the witness process on the Mac)"

trap teardown EXIT
trap 'exit 130' INT TERM HUP

# The linked anchor image, built from the repository's files on top of the evaluated image (no pull).
docker build -q -f "$REPO/testbed/e5/anchord-linked.Dockerfile" -t hpr-anchord:linked "$REPO/testbed/anchord" \
  > "$SP/anchord_build.log" 2>&1 || { note "FAIL: anchor image build ($(tail -2 $SP/anchord_build.log))"; exit 5; }
IMG_SUMS=$(docker run --rm --name e5-imgcheck --entrypoint sh hpr-anchord:linked -c 'sha256sum /app/anchord.py /app/anchord_linked.py' | cut -c1-64 | tr '\n' ' ')
REPO_SUMS="$(shasum -a 256 $REPO/testbed/anchord/anchord.py | cut -c1-64) $(shasum -a 256 $REPO/testbed/anchord/anchord_linked.py | cut -c1-64) "
[ "$IMG_SUMS" = "$REPO_SUMS" ] || { note "FAIL: image files differ from the repository ($IMG_SUMS vs $REPO_SUMS)"; exit 5; }
note "anchor image built: hpr-anchord:linked $(docker image inspect hpr-anchord:linked --format '{{.Id}}') (in-image anchord.py, anchord_linked.py = repository files)"

# The head witness: on the Mac, outside both virtual machines, loopback only.
WITNESS_LOG="$WDIR/heads.jsonl" WITNESS_FORKS="$WDIR/forks.jsonl" HOMEPROV_WITNESS_KEY="$WKEY" \
  nohup "$PY" -u -c 'import sys; sys.path.insert(0, sys.argv[1]); import headwitness as W; W.serve(host="127.0.0.1", port=int(sys.argv[2]))' \
  "$REPO/testbed/anchord" "$WPORT" > "$WDIR/witness.log" 2>&1 &
WPID=$!
n=0; until grep -q READY "$WDIR/witness.log" 2>/dev/null || [ $n -ge 20 ]; do sleep 0.5; n=$((n+1)); done
grep -q READY "$WDIR/witness.log" || { note "FAIL: witness did not start ($(cat $WDIR/witness.log))"; exit 5; }
note "witness: pid=$WPID bind=127.0.0.1:$WPORT python=$PY ($("$PY" --version 2>&1)) log=$WDIR/heads.jsonl listen=$(lsof -nP -a -p $WPID -iTCP -sTCP:LISTEN | awk 'NR>1{print $9}')"
note "witness_head_at_start: $(witness_get /head)"

docker network inspect e5-net >/dev/null 2>&1 || docker network create e5-net >/dev/null
for v in $VCHAIN $VPUB $VREP $VSCR; do docker volume create $v >/dev/null; done
docker run -d --name e5-anchord --network e5-net -p 127.0.0.1:$APORT:9900 \
  -e HOMEPROV_ANCHOR_KEY="$KEY" -e HOMEPROV_ANCHOR_LINK=v2 -e HOMEPROV_WITNESS_KEY="$WKEY" \
  -e HEAD_WITNESS_URL=http://host.docker.internal:$WPORT/head -e HEAD_WITNESS_MODE=$WMODE \
  -v $VCHAIN:/anchor -v $VPUB:/published hpr-anchord:linked >/dev/null || exit 5
sleep 2
WREACH=$(docker exec e5-anchord python -c "import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:$WPORT/head',timeout=5).status)" 2>&1 | tail -1)
note "witness_reachable_from_anchor_container: $WREACH"
[ "$WREACH" = "200" ] || { note "FAIL: the anchor cannot reach the witness"; exit 7; }
note "clock_hostB_vs_mac: $(clock_hostB)"
note "clock_probe_before: $(clock_probe)"
docker run -d --name e5-replicator --network e5-net -e E1_REPL_PERIOD=2 \
  -v $VMDIR/ssh-ctr:/e1:ro -v $VREP:/rep -v $SP/replog:/replog hpr-e1-replicator:1 >/dev/null || exit 5
n=0; until docker exec e5-replicator test -f /rep/clock 2>/dev/null || [ $n -ge 30 ]; do sleep 2; n=$((n+1)); done
note "first_replica_after_polls: $n ($(docker exec e5-replicator sh -c 'ls -la /rep | tr "\n" " "'))"
docker run -d --name e5-monitor --network e5-net \
  -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR=http://e5-anchord:9900/append \
  -e HOMEPROV_PERIOD=5 -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$KEY" \
  -e HOMEPROV_SCHEME=closure -e HOMEPROV_CLOCK_FILE=/cfg/clock \
  -v $VREP:/cfg:ro -v $VSCR:/scratch hpr-monitor:e1 >/dev/null || exit 5
note "anchor image: $(docker inspect e5-anchord --format '{{.Config.Image}} {{.Image}}') cmd=$(docker inspect e5-anchord --format '{{json .Config.Cmd}}')"
note "monitor image: $(docker inspect e5-monitor --format '{{.Config.Image}} {{.Image}}')"
note "replicator image: $(docker inspect e5-replicator --format '{{.Config.Image}} {{.Image}}')"
sleep 20
# The privileged Core on host A tries the anchor's one verb without the key and with a forged tag (as E1), then the
# witness: whether it can reach it at all (GET /head), and a head push without a tag and with a forged tag.
cat > "$SP/hub_probe.py" <<PROBE
import urllib.request, urllib.error, json
def req(url, body=None, h=None, method="POST"):
    r = urllib.request.Request(url, data=body, method=method, headers=h or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:80]
A = "http://10.0.2.2:$APORT/append"
W = "http://10.0.2.2:$WPORT/head"
J = {"Content-Type": "application/json"}
fake = json.dumps({"seq": 1000000, "head_digest": "0" * 64, "recv_ts": 0}, sort_keys=True).encode()
print(json.dumps({"untagged": req(A, b'{"sealed": {}}', J),
                  "forged_tag": req(A, b'{"sealed": {}}', {**J, "X-HP-Auth": "0" * 64}),
                  "witness_get_head": req(W, None, None, "GET"),
                  "witness_push_untagged": req(W, fake, J),
                  "witness_push_forged_tag": req(W, fake, {**J, "X-HP-Auth": "0" * 64})}))
PROBE
A "cat > $CFG/.e5_probe.py" < "$SP/hub_probe.py"
note "probe_from_hub: $(A 'docker exec homeassistant python3 /config/.e5_probe.py')"
note "witness_head_after_probe: $(witness_get /head)"
# What a privileged Core holds on host A: every capability, and host A's raw disk devices. Host A holds no HOMEPROV
# key, chain or witness state in this placement.
note "core_privilege_on_hostA: $(A 'docker exec homeassistant sh -c "grep CapEff /proc/self/status | tr -s \"\t \" \" \"; ls /dev/vda8 2>&1"' | tr '\n' ' ')"
sleep 40
note "monitor_log_head: $(docker logs e5-monitor 2>&1 | head -3 | cut -c1-500 | tr '\n' ' ')"
note "chain_lines_before_run: $(docker exec e5-anchord sh -c 'wc -l < /anchor/chain.jsonl')"
note "witness_heads_before_run: $(wc -l < "$WDIR/heads.jsonl" | tr -d ' ') latest=$(witness_get /head)"

note "starting E5 runner arms=$ARMS x$TRIALS"
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
note "chain_lines after run: $(docker exec e5-anchord sh -c 'wc -l < /anchor/chain.jsonl')"
note "load_after: $(uptime)"
note "clock_hostB_vs_mac_after: $(clock_hostB)"
note "clock_probe_after: $(clock_probe)"
# Freeze the chain before it is compared with the witness: stop the monitor (the only appender) and the replicator,
# then wait past the anchor's 5 s push timeout so the last head has reached the witness or failed.
docker logs e5-monitor > "$SP/monitor.log" 2>&1
docker stop e5-monitor e5-replicator >/dev/null 2>&1
sleep 8
note "monitor and replicator stopped; chain frozen at $(docker exec e5-anchord sh -c 'wc -l < /anchor/chain.jsonl') records"
witness_get /head > "$WDIR/head_final.json"
witness_get /log > "$WDIR/log_final.json"
docker exec e5-anchord cat /anchor/chain.jsonl > "$SP/chain.jsonl"
docker exec e5-anchord sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/refusals.jsonl"
docker exec e5-anchord sh -c 'cat /published/head.json 2>/dev/null' > "$SP/anchor_published_head.json"
note "witness head at freeze: $(cat "$WDIR/head_final.json") heads_logged=$(wc -l < "$WDIR/heads.jsonl" | tr -d ' ') forks=$(cat "$WDIR/forks.jsonl" 2>/dev/null | wc -l | tr -d ' ')"
note "anchor head at freeze: $(curl -s http://127.0.0.1:$APORT/head | "$PY" -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps({k:d.get(k) for k in ("seq","head_digest","link")}))')"
gzip -c "$SP/chain.jsonl" > "$OUT/${TAG}_linked_chain.jsonl.gz"
gzip -c "$WDIR/heads.jsonl" > "$OUT/${TAG}_witness_heads.jsonl.gz"
note "running the E5 aggregator (shipped e_ps_detection scoring, host-A transport; chain links; witness head)"
E5_SP="$SP" EC_SCRATCH="$SP/ps_verify" "$PY" "$REPO/exp/stages/e5_linked.py" --tag "$TAG" porch hallway kitchen \
  > "$SP/aggregate.log" 2>&1
note "aggregator exit: $? ($(tail -4 "$SP/aggregate.log" | tr '\n' ' '))"
stop_witness
note "done"
"$PY" - "$SP" "$OUT" "$TAG" "$0" <<'PY'
import hashlib, json, sys
sp, out, tag, script = sys.argv[1:]
R = __import__("os").environ["ARTIFACT_ROOT"]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
cfg = {"experiment": f"{tag}: E5 linked anchor with a head witness, member-account swap (arm PSR) against a privileged "
                     "Core on Home Assistant OS (host A), monitor, replicator and linked authenticated anchor on Docker "
                     "Desktop's VM (host B), head witness as a process on the Mac outside both VMs",
       "monitor": {"image": "hpr-monitor:e1", "scheme": "closure", "encoding": "v2", "clock_file": "/cfg/clock",
                   "period_s": 5, "monitor_py_sha256": h(f"{R}/monitor/monitor.py"),
                   "monitor_py_in_image_sha256_16": next((l.split("monitor_in_image_sha256: ", 1)[1][:16]
                                                          for l in open(f"{sp}/auth_meta.log")
                                                          if "monitor_in_image_sha256: " in l), None)},
       "replicator": {"image": "hpr-e1-replicator:1", "period_s": 2,
                      "replicator_py_sha256": h(f"{R}/testbed/e1/replicator/replicator.py"),
                      "hub_backup_py_sha256": h(f"{R}/testbed/e1/replicator/hub_backup.py")},
       "anchor": {"image": "hpr-anchord:linked", "entry": "anchord_linked.py", "link": "v2", "authenticated": True,
                  "head_witness_mode": "sync", "head_witness_url": "http://host.docker.internal:19960/head",
                  "anchord_py_sha256": h(f"{R}/testbed/anchord/anchord.py"),
                  "anchord_linked_py_sha256": h(f"{R}/testbed/anchord/anchord_linked.py"),
                  "dockerfile_sha256": h(f"{R}/testbed/e5/anchord-linked.Dockerfile")},
       "witness": {"where": "python3 process on the evaluation Mac, outside Docker's VM and host A's VM",
                   "bind": "127.0.0.1:19960", "key": "separate from the append key (fingerprints in the log)",
                   "headwitness_py_sha256": h(f"{R}/testbed/anchord/headwitness.py")},
       "configuration_log": [l.rstrip("\n") for l in open(f"{sp}/auth_meta.log")],
       "linked_chain": {"file": f"exp/out/{tag}_linked_chain.jsonl.gz",
                        "records": sum(1 for l in open(f"{sp}/chain.jsonl") if l.strip()),
                        "sha256_uncompressed": h(f"{sp}/chain.jsonl")},
       "witness_heads": {"file": f"exp/out/{tag}_witness_heads.jsonl.gz",
                         "heads": sum(1 for l in open(f"{sp}/witness/heads.jsonl") if l.strip()),
                         "sha256_uncompressed": h(f"{sp}/witness/heads.jsonl")},
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "x"), indent=1)
PY
