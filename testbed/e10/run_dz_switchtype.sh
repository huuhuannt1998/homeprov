#!/bin/bash
# E10 arm C (review r5 Z4; drafts/round13/E10_ADDENDUM_R5.md section C): a BENIGN device-configuration change on the
# Domoticz test stack with the closure monitor live -- the owner changes the front-door lock's switch type from "Door
# Lock" (19) to "Door Lock Inverted" (20) through the hub's own API, as the web UI's Edit Device dialog does. The
# closure the monitor commits includes DeviceStatus.SwitchType (exp/out/dz_closure.json), and one write of it changed
# 120 one-second closure roots offline (exp/out/dz_offline_checks.json single_write[3]); this arm measures it live.
#
# COPIED from testbed/domoticz/run_dz.sh (E-DZ) and changed only where the arm needs it: the usage line, the output
# names, the driver (testbed/e10/dz_switchtype.py: benign lock traffic before and after the change, the change itself,
# the renders before and after) in place of dz_arms.py, a snapshot just before the change, and the scorer
# (exp/stages/e10_dz_switchtype.py) in place of dz_detection.py. Stack, provisioning, anchor, monitor, settle and the
# consistent snapshot are E-DZ's, unchanged.
#   fresh hub (volume dz-<TAG>-userdata, provisioned through its own API, then restarted), the shipped anchor daemon
#   (image hpr-anchord:sig) with a FRESH HMAC key (fingerprint recorded, key never), the shipped monitor.py through the
#   Domoticz adapter (closure scheme, 5 s period), probes of the anchor from inside the Domoticz process (untagged,
#   forged tag), a configuration log, the switch-type driver, a 90 s settle, a consistent snapshot of domoticz.db taken
#   with SQLite's backup API inside the hub container, collection, and scoring.
# Usage: run_dz_switchtype.sh TAG OUTDIR [PRE_S] [POST_S]      (registered: TAG e10dz_st, PRE_S 600, POST_S 600)
# Every container, network and volume it creates is named dz-*; it touches nothing else. Never overwrites an output.
# Refuses before 2026-10-19T16:01Z (E9 owns Docker) and while E10's or E12's runs are active.
# Not done during the run, by design: "Clear Short Log" / vacuumdatabase (SQLite VACUUM may renumber LightingLog's
# implicit ROWIDs, the node key). The switch-type change is the arm.
set -u
TAG=$1; OUTDIR=$2; PRE_S=${3:-600}; POST_S=${4:-600}
[ "$(date -u +%s)" -lt 1792425660 ] && { echo "REFUSING: before 2026-10-19T16:01:00Z (E9 owns Docker on this Mac)"; exit 2; }
pgrep -f "testbed/e9/run_e9.sh|testbed/e10/run_e10.sh|testbed/e12/run_e12.sh" >/dev/null && { echo "REFUSING: E9, E10 or E12 is running"; exit 2; }
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
for f in ${TAG}_t_start ${TAG}_t_end ${TAG}_config.json ${TAG}_anchor_chain.jsonl.gz ${TAG}_switchtype_report.json \
         ${TAG}_switchtype_score.json; do
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

note "tag=$TAG pre_s=$PRE_S post_s=$POST_S outdir=$OUTDIR run=$RUN (E10 arm C: benign switch-type change)"
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
note "sha256 testbed/e10/dz_switchtype.py: $(s256 $REPO/testbed/e10/dz_switchtype.py)"
note "sha256 exp/stages/e10_dz_switchtype.py: $(s256 $REPO/exp/stages/e10_dz_switchtype.py)"
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

# ---------------------------------------------------------------- arm C: benign traffic, the switch-type change, traffic
snap_pre() {   # a consistent snapshot just before the change (the offline root comparison's "before")
  local ts; ts=$(vmnow)
  docker exec dz-domoticz sh -c 'rm -f /tmp/dzpre.db'
  docker exec dz-domoticz python3 -c "import sqlite3;s=sqlite3.connect('/opt/domoticz/userdata/domoticz.db',timeout=120);d=sqlite3.connect('/tmp/dzpre.db');s.backup(d);d.close();s.close();print('ok')" >/dev/null || return 1
  docker cp dz-domoticz:/tmp/dzpre.db "$RUN/verify/domoticz_pre_change.db" >/dev/null
  docker exec dz-domoticz rm -f /tmp/dzpre.db
  echo "$ts" > "$RUN/verify/t_pre_change_snapshot"
  note "pre-change snapshot at $ts sha256 $(s256 $RUN/verify/domoticz_pre_change.db)"
}
note "starting the switch-type arm: ${PRE_S}s of benign lock traffic, the change (19 -> 20), ${POST_S}s more"
(cd "$REPO/testbed/e10" && DZ_BASE=http://127.0.0.1:$PORT DZ_HARNESS=$SRC/harness python3 dz_switchtype.py \
   --tag $TAG --out "$OUTDIR" --pre-s "$PRE_S" --post-s "$POST_S" --from-type 19 --to-type 20 \
   --pre-snapshot-cmd "touch $RUN/.snap_pre_now" --pre-snapshot-flag "$RUN/.snap_pre_done") > "$RUN/logs/switchtype.log" 2>&1 &
DRV=$!
while kill -0 $DRV 2>/dev/null; do                    # the driver asks for the pre-change snapshot, then waits for it
  if [ -e "$RUN/.snap_pre_now" ]; then rm -f "$RUN/.snap_pre_now"; snap_pre && : > "$RUN/.snap_pre_done"; fi
  sleep 1
done
wait $DRV; ARMS_RC=$?
note "switch-type driver exit: $ARMS_RC ($(tail -6 $RUN/logs/switchtype.log | tr '\n' ' '))"
if [ "$ARMS_RC" != "0" ]; then
  note "driver failed; aborting before any write to $OUTDIR beyond the driver's own files; containers left for inspection"
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
cfg = {"experiment": f"{tag}: E10 arm C, a benign switch-type change on Domoticz with the closure monitor live "
                     "(launcher copied from testbed/domoticz/run_dz.sh)",
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
       "not_done_during_the_run": ["Clear Short Log / vacuumdatabase (VACUUM may renumber LightingLog ROWIDs)"],
       "the_arm": "the owner's switch-type change of the front-door lock, 19 (Door Lock) -> 20 (Door Lock Inverted)",
       "pre_change_snapshot_sha256": h(f"{run}/verify/domoticz_pre_change.db"),
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "x"), indent=1)
print("config ->", f"{out}/{tag}_config.json")
PY
python3 "$REPO/exp/stages/e10_dz_switchtype.py" --tag $TAG --run "$RUN" --outdir "$OUTDIR" 2>&1 | tee "$RUN/logs/switchtype_score.log"
