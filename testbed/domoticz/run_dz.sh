#!/bin/bash
# E-DZ: one authenticated real-hub run of HOMEPROV on Domoticz, both post-commit arms (laundering analogue and
# member-account swap analogue), the Domoticz counterpart of testbed/real/run_clo_grace.sh + run_experiments.sh EC:
#   fresh hub (volume dz-<TAG>-userdata, provisioned through its own API, then restarted), the shipped anchor daemon
#   (image hpr-anchord:sig) with a FRESH HMAC key (fingerprint recorded, key never), the shipped monitor.py through the
#   Domoticz adapter (closure scheme, 5 s period), probes of the anchor from inside the Domoticz process (untagged,
#   forged tag), a configuration log, the arms (dz_arms.py), a 90 s settle, a consistent snapshot of domoticz.db taken
#   with SQLite's backup API inside the hub container, collection, and scoring (exp/stages/dz_detection.py).
# Usage: run_dz.sh TAG OUTDIR [TRIALS]
# Every container, network and volume it creates is named dz-*; it touches nothing else. Never overwrites an output.
# Not done during a run, by design: "Clear Short Log" / vacuumdatabase (SQLite VACUUM may renumber LightingLog's
# implicit ROWIDs, the node key) and any change of a device's switch type (a configuration edit the closure commits).
set -u
TAG=$1; OUTDIR=$2; TRIALS=${3:-10}
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
SRC=$REPO/testbed/domoticz
DZ="<research-dir>/HOMEPROV-P13-exp/dz"
RUN=$DZ/runs/$TAG
IMG=domoticz/domoticz:stable
ANCHOR_IMG=hpr-anchord:sig
PYIMG=python:3.13-slim
PORT=18480
NET=dz-net
VUSER=dz-$TAG-userdata; VCHAIN=dz-$TAG-chain; VPUB=dz-$TAG-pub; VSCR=dz-$TAG-scratch

[ -e "$RUN" ] && { echo "REFUSING: $RUN exists"; exit 3; }
mkdir -p "$OUTDIR"
for f in ${TAG}_t_start ${TAG}_t_end ${TAG}_config.json ${TAG}_anchor_chain.jsonl.gz ${TAG}_report_porch.json \
         ${TAG}_report_hallway.json ${TAG}_report_kitchen.json ${TAG}_laundering_detection.json \
         ${TAG}_memberswap_detection.json; do
  [ -e "$OUTDIR/$f" ] && { echo "REFUSING: $OUTDIR/$f exists"; exit 3; }
done
for c in dz-domoticz dz-anchord dz-monitor dz-harness; do
  docker ps -a --format '{{.Names}}' | grep -qx "$c" && { echo "REFUSING: container $c exists"; exit 3; }
done
for v in $VUSER $VCHAIN $VPUB $VSCR; do
  docker volume inspect "$v" >/dev/null 2>&1 && { echo "REFUSING: volume $v exists"; exit 3; }
done
mkdir -p "$RUN"/{hpctl,hp,dzm,archive,verify,screens,logs}
META=$RUN/config.log
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }
TUN_PID=
cleanup() { [ -n "$TUN_PID" ] && kill "$TUN_PID" 2>/dev/null; }
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
s256() { shasum -a 256 "$1" | cut -d' ' -f1; }
vmnow() { docker exec dz-harness python3 -c 'import time;print(repr(time.time()))'; }
ctl() {
  local op=$1 kw=${2:-'{}'}
  (cd "$SRC/harness" && python3 -c "import json,sys;from dz_ctl import Ctl;print(json.dumps(Ctl(sys.argv[3]).call(sys.argv[1], **json.loads(sys.argv[2]))))" "$op" "$kw" "$RUN/hpctl")
}

note "tag=$TAG trials=$TRIALS outdir=$OUTDIR run=$RUN"
note "load_before: $(uptime)"
note "git_head: $(git -C $REPO rev-parse HEAD) (working tree: monitor/monitor.py modified; testbed/domoticz and exp/stages/dz_*.py untracked)"
cp "$REPO/monitor/monitor.py" "$RUN/hp/monitor.py"
cp "$SRC/monitor/dz_monitor.py" "$RUN/dzm/dz_monitor.py"
note "monitor_py_sha256: repo $(s256 $REPO/monitor/monitor.py) run_copy $(s256 $RUN/hp/monitor.py)"
note "adapter_sha256: $(s256 $RUN/dzm/dz_monitor.py)"
note "anchord_py_sha256: repo $(s256 $REPO/testbed/anchord/anchord.py) image $(docker run --rm --name dz-peek --network none --entrypoint sha256sum $ANCHOR_IMG /app/anchord.py | cut -d' ' -f1)"
for f in integration/HPLock/plugin.py integration/HPSensors/plugin.py dzvents/porch_motion_light.lua \
         dzvents/hallway_motion_light.lua dzvents/kitchen_motion_light.lua harness/dz_arms.py harness/dz_api.py \
         harness/dz_ctl.py harness/dz_ui.py harness/dz_provision.py harness/tunnel.py harness/relay.py; do
  note "sha256 testbed/domoticz/$f: $(s256 $SRC/$f)"
done
note "wrapper_sha256: $(s256 $0)"
note "image domoticz: $(docker image inspect $IMG --format '{{.Id}} {{json .RepoDigests}} created={{.Created}} arch={{.Architecture}}')"
note "image anchor: $(docker image inspect $ANCHOR_IMG --format '{{.Id}} created={{.Created}}')"
note "image python: $(docker image inspect $PYIMG --format '{{.Id}} {{json .RepoDigests}}')"

docker network inspect $NET >/dev/null 2>&1 || docker network create --internal $NET >/dev/null
note "network: $(docker network inspect $NET --format '{{.Name}} internal={{.Internal}} {{range .IPAM.Config}}{{.Subnet}}{{end}}')"

# ---------------------------------------------------------------- hub
docker volume create $VUSER >/dev/null
docker run --rm --name dz-init --network none -v $VUSER:/u -v $SRC:/dzsrc:ro alpine:3 sh -c \
  'mkdir -p /u/plugins /u/scripts/dzVents/scripts && cp -r /dzsrc/integration/HPLock /dzsrc/integration/HPSensors /u/plugins/ && cp /dzsrc/dzvents/*.lua /u/scripts/dzVents/scripts/' || exit 5
docker run -d --name dz-domoticz --network $NET -e TZ=UTC -e DOMOTICZ_ADMIN_USERNAME=owner \
  -e DOMOTICZ_ADMIN_PASSWORD=dz-owner-pw -v $VUSER:/opt/domoticz/userdata -v $RUN/hpctl:/hpctl $IMG >/dev/null || exit 5
docker run -d --name dz-harness --network $NET -v $SRC:/dzsrc:ro $PYIMG sleep infinity >/dev/null || exit 5
python3 "$SRC/harness/tunnel.py" $PORT dz-harness dz-domoticz 8080 > "$RUN/logs/tunnel.log" 2>&1 &
TUN_PID=$!
for i in $(seq 1 30); do
  (cd "$SRC/harness" && DZ_BASE=http://127.0.0.1:$PORT python3 -c "from dz_api import Api;Api('owner')" >/dev/null 2>&1) && break
  sleep 2
done
api_up() {
  for i in $(seq 1 40); do
    [ "$(docker inspect -f '{{.State.Running}}' dz-domoticz)" = "true" ] || { note "hub not running (exit $(docker inspect -f '{{.State.ExitCode}}' dz-domoticz)); starting it"; docker start dz-domoticz >/dev/null; }
    (cd "$SRC/harness" && DZ_BASE=http://127.0.0.1:$PORT python3 -c "from dz_api import Api;Api('owner')" >/dev/null 2>&1) && return 0
    sleep 3
  done
  return 1
}
PROV_OK=
for attempt in 1 2 3; do
  api_up || { note "hub API not reachable"; exit 6; }
  if (cd "$SRC/harness" && DZ_BASE=http://127.0.0.1:$PORT python3 dz_provision.py run) > "$RUN/provision.json"; then
    PROV_OK=1; break
  fi
  note "provisioning attempt $attempt incomplete: $(tail -c 300 $RUN/provision.json); hub log: $(docker logs --tail 3 dz-domoticz 2>&1 | tr '\n' ' ' | cut -c1-300)"
  sleep 5
done
[ -n "$PROV_OK" ] || { note "provisioning failed; aborting before any output"; exit 6; }
note "provisioning attempts: $attempt"
PSUM=$(python3 - "$RUN/provision.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(json.dumps({k: d[k] for k in ("hardware", "devices", "users")}))
PY
)
note "provision: $PSUM"
docker restart dz-domoticz >/dev/null
for i in $(seq 1 30); do
  (cd "$SRC/harness" && DZ_BASE=http://127.0.0.1:$PORT python3 -c "from dz_api import Api;Api('owner')" >/dev/null 2>&1) && break
  sleep 2
done
sleep 15
(cd "$SRC/harness" && DZ_BASE=http://127.0.0.1:$PORT python3 -c "from dz_api import Api;import json;print(json.dumps(Api('owner').cmd('getversion')))") > "$RUN/version.json"
note "domoticz_version: $(cat $RUN/version.json)"
note "hub_tz: $(docker exec dz-domoticz date '+%Z %z') hub_process: $(docker exec dz-domoticz sh -c 'cat /proc/1/cmdline | tr "\0" " "; echo " uid=$(id -u)"')"
note "integration_info: $(ctl info)"
note "hub_log_head: $(docker logs dz-domoticz 2>&1 | grep -E 'Status: Domoticz|Build Hash|PluginSystem: Started' | tail -3 | tr '\n' ' ')"

# ---------------------------------------------------------------- anchor + monitor, fresh key
KEY=$(openssl rand -hex 32)
note "key_fingerprint_sha256_16: $(printf '%s' "$KEY" | shasum -a 256 | cut -c1-16) (key itself not recorded)"
for v in $VCHAIN $VPUB $VSCR; do docker volume create $v >/dev/null; done
docker run -d --name dz-anchord --network $NET -e HOMEPROV_ANCHOR_KEY="$KEY" -v $VCHAIN:/anchor -v $VPUB:/published \
  $ANCHOR_IMG >/dev/null || exit 5
docker run -d --name dz-monitor --network $NET -e HOMEPROV_DB=/hub/domoticz.db \
  -e HOMEPROV_ANCHOR=http://dz-anchord:9900/append -e HOMEPROV_PERIOD=5 -e HOMEPROV_SCRATCH=/scratch \
  -e HOMEPROV_ANCHOR_KEY="$KEY" -e HOMEPROV_SCHEME=closure -e HP_DZ_ARCHIVE=/archive/archive.jsonl \
  -v $RUN/hp:/hp:ro -v $RUN/dzm:/dzm:ro -v $VUSER:/hub:ro -v $VSCR:/scratch -v $RUN/archive:/archive \
  $PYIMG python -u /dzm/dz_monitor.py >/dev/null || exit 5
KEY=
note "anchor container: $(docker inspect dz-anchord --format '{{.Config.Image}} {{.Image}}')"
note "monitor container: $(docker inspect dz-monitor --format '{{.Config.Image}} {{.Image}}') mounts: $(docker inspect dz-monitor --format '{{range .Mounts}}{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}} {{end}}')"
note "hub container mounts: $(docker inspect dz-domoticz --format '{{range .Mounts}}{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}} {{end}}') networks: $(docker inspect dz-domoticz --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}')"
sleep 20
ctl probe_anchor '{"url": "http://dz-anchord:9900/append"}' > "$RUN/probe_hub_process.json"
note "probe_from_hub_process: $(cat $RUN/probe_hub_process.json)"
PROBE='import urllib.request,json
def post(h):
    r=urllib.request.Request("http://dz-anchord:9900/append",data=b"{\"sealed\": {}}",method="POST",headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:80]
print(json.dumps({"untagged":post({"Content-Type":"application/json"}),"forged_tag":post({"Content-Type":"application/json","X-HP-Auth":"0"*64})}))'
docker exec dz-domoticz python3 -c "$PROBE" > "$RUN/probe_hub_container.json"
note "probe_from_hub_container_shell: $(cat $RUN/probe_hub_container.json)"
sleep 40
note "monitor_log_head: $(docker logs dz-monitor 2>&1 | head -3 | cut -c1-300 | tr '\n' ' ')"
note "chain_lines_before_run: $(docker exec dz-anchord sh -c 'wc -l < /anchor/chain.jsonl')"

# ---------------------------------------------------------------- arms
note "starting arms: laundering, memberswap; rooms porch hallway kitchen; $TRIALS trials each; seal wait 130 s"
python3 "$SRC/harness/dz_arms.py" --tag $TAG --out "$OUTDIR" --hpctl "$RUN/hpctl" --base http://127.0.0.1:$PORT \
  --trials $TRIALS --ui --screens "$RUN/screens" > "$RUN/logs/arms.log" 2>&1
ARMS_RC=$?
note "arms exit: $ARMS_RC ($(tail -6 $RUN/logs/arms.log | tr '\n' ' '))"
if [ "$ARMS_RC" != "0" ]; then
  note "arms failed; aborting before any write to $OUTDIR beyond the driver's own files; containers left for inspection"
  exit 8
fi
note "settling 90 s so the final segments seal and anchor"
sleep 90
note "chain_lines_after_run: $(docker exec dz-anchord sh -c 'wc -l < /anchor/chain.jsonl')"

# ---------------------------------------------------------------- consistent snapshot + collection
TS=$(vmnow)
docker exec dz-domoticz sh -c 'rm -f /tmp/dzverify.db'
docker exec dz-domoticz python3 -c "import sqlite3;s=sqlite3.connect('/opt/domoticz/userdata/domoticz.db',timeout=120);d=sqlite3.connect('/tmp/dzverify.db');s.backup(d);d.close();s.close();print('ok')" || exit 7
docker cp dz-domoticz:/tmp/dzverify.db "$RUN/verify/domoticz.db" >/dev/null
docker exec dz-domoticz rm -f /tmp/dzverify.db
echo "$TS" > "$RUN/verify/t_snapshot"
note "recorder_snapshot: at $TS sha256 $(s256 $RUN/verify/domoticz.db)"
docker exec dz-anchord cat /anchor/chain.jsonl > "$RUN/chain.jsonl"
docker exec dz-anchord sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$RUN/refusals.jsonl"
docker logs dz-monitor > "$RUN/logs/monitor.log" 2>&1
docker logs dz-domoticz > "$RUN/logs/domoticz.log" 2>&1
note "chain_lines final: $(wc -l < $RUN/chain.jsonl); refusals: $(wc -l < $RUN/refusals.jsonl)"
note "chain_schemes: $(python3 -c "import json,collections,sys;print(dict(collections.Counter((json.loads(l).get('payload') or {}).get('scheme','unrecorded') for l in open(sys.argv[1]) if l.strip())))" $RUN/chain.jsonl)"
note "monitor_errors: $(grep -c '"error"' $RUN/logs/monitor.log) archive_lines: $(wc -l < $RUN/archive/archive.jsonl)"
note "hub_errors_excluding_dzvents_location: $(grep -i 'error' $RUN/logs/domoticz.log | grep -vc 'longitude')"
note "load_after: $(uptime)"
note "done"
gzip -c "$RUN/chain.jsonl" > "$OUTDIR/${TAG}_anchor_chain.jsonl.gz"
python3 - "$RUN" "$OUTDIR" "$TAG" "$0" <<'PY'
import hashlib, json, sys
run, out, tag, script = sys.argv[1:]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
lines = [l.rstrip("\n") for l in open(f"{run}/config.log")]
def grab(prefix):
    for l in lines:
        if (" " + prefix + ":") in l:
            return l.split(prefix + ":", 1)[1].strip()
ver = json.load(open(f"{run}/version.json"))
img = grab("image domoticz").split()
cfg = {"experiment": f"{tag}: E-DZ, HOMEPROV on Domoticz, both post-commit arms, authenticated anchor, closure monitor",
       "domoticz": {"version": ver.get("version"), "build_hash": ver.get("hash"), "build_time": ver.get("build_time"),
                    "dzvents_version": ver.get("dzvents_version"), "python_version": ver.get("python_version"),
                    "image": "domoticz/domoticz:stable", "image_id": img[0], "repo_digests": img[1]},
       "images": {"domoticz": grab("image domoticz"), "anchor": grab("image anchor"), "python": grab("image python")},
       "anchor": {"image": "hpr-anchord:sig", "anchord_py_sha256": grab("anchord_py_sha256"), "authenticated": True,
                  "key_fingerprint_sha256_16": grab("key_fingerprint_sha256_16").split()[0],
                  "key_recorded": False},
       "monitor": {"monitor_py_sha256": grab("monitor_py_sha256"), "adapter_sha256": grab("adapter_sha256"),
                   "scheme": "closure", "period_s": 5, "encoding": "v2",
                   "replaced_in_monitor_py": ["load()", "the Home Assistant schema probe of validate_copy()"]},
       "probes": {"from_hub_process": json.load(open(f"{run}/probe_hub_process.json")),
                  "from_hub_container_shell": json.load(open(f"{run}/probe_hub_container.json")),
                  "refusals_logged_by_anchor": [json.loads(l) for l in open(f"{run}/refusals.jsonl") if l.strip()]},
       "provision": json.load(open(f"{run}/provision.json")),
       "configuration_log": lines,
       "anchor_chain": {"file": f"exp/out/{tag}_anchor_chain.jsonl.gz",
                        "records": sum(1 for l in open(f"{run}/chain.jsonl") if l.strip()),
                        "sha256_uncompressed": h(f"{run}/chain.jsonl")},
       "recorder_snapshot_sha256": h(f"{run}/verify/domoticz.db"),
       "not_done_during_the_run": ["Clear Short Log / vacuumdatabase (VACUUM may renumber LightingLog ROWIDs)",
                                   "switch-type or other device configuration edits"],
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "w"), indent=1)
print("config ->", f"{out}/{tag}_config.json")
PY
python3 "$REPO/exp/stages/dz_detection.py" --tag $TAG --run "$RUN" --outdir "$OUTDIR" 2>&1 | tee "$RUN/logs/detection.log"
