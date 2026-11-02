#!/bin/bash
# E3 (round 12, 2026-10-07): one real-deployment run under the AUTHENTICATED anchor with the CLOSURE monitor and a
# grace period before sealing (HOMEPROV_GRACE_S). Usage: run_clo_grace.sh TAG ARMS TRIALS GRACE_S
# Recipe of the e_d_clo wrapper (sha256 de2ee5fd..., recorded in exp/out/e_d_clo_config.json) except: the monitor image
# is hpr-monitor:closure-grace (monitor/monitor.py at this commit: typed encoding v2, closure scheme, GRACE_S), and the
# run's configuration file is written by this script. Originals stopped+renamed, never removed, restored by the EXIT
# trap. Never overwrites an existing output.
set -u
TAG=$1; ARMS=$2; TRIALS=$3; GRACE=$4
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
OUT=$REPO/exp/out
SP="<research-dir>/HOMEPROV-P13-exp/e3/$TAG"
mkdir -p "$SP"
NET=homeprov-real_hp-real
VCHAIN=hpr-e3-$TAG-chain; VPUB=hpr-e3-$TAG-pub; VSCR=hpr-e3-$TAG-scratch
export HOMEPROV_SCHEME=closure
META=$SP/auth_meta.log
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }

for f in "${TAG}_t_start" "${TAG}_t_end" "${TAG}_report_porch.json" "${TAG}_report_hallway.json" \
         "${TAG}_report_kitchen.json" "${TAG}_other_principal_real.json" "${TAG}_config.json"; do
  [ -e "$OUT/$f" ] && { echo "REFUSING: $OUT/$f exists"; exit 3; }
done

restore() {
  note "teardown: removing auth containers, restoring originals"
  docker rm -f hpr-anchord hpr-monitor >/dev/null 2>&1
  docker rename hpr-anchord-orig-e3 hpr-anchord >/dev/null 2>&1
  docker rename hpr-monitor-orig-e3 hpr-monitor >/dev/null 2>&1
  docker start hpr-anchord hpr-monitor >/dev/null 2>&1
  note "restored: $(docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E '^hpr-(anchord|monitor) ' | tr '\n' ';')"
}

note "tag=$TAG arms=$ARMS trials=$TRIALS grace_s=$GRACE scheme=$HOMEPROV_SCHEME"
note "load_before: $(uptime)"
note "git_head: $(git -C $REPO rev-parse HEAD) (monitor.py modified in the working tree: encoding v2, closure, GRACE_S)"
note "monitor_py_sha256: $(shasum -a 256 $REPO/monitor/monitor.py | cut -c1-16)"
KEY=$(openssl rand -hex 32)
note "key_fingerprint_sha256_16: $(printf '%s' "$KEY" | shasum -a 256 | cut -c1-16) (key itself not recorded)"

docker stop hpr-monitor hpr-anchord >/dev/null || { echo "stop failed"; exit 4; }
docker rename hpr-anchord hpr-anchord-orig-e3 || exit 4
docker rename hpr-monitor hpr-monitor-orig-e3 || { docker rename hpr-anchord-orig-e3 hpr-anchord; exit 4; }
trap restore EXIT
trap 'exit 130' INT TERM HUP

for v in $VCHAIN $VPUB $VSCR; do docker volume create $v >/dev/null; done
docker run -d --name hpr-anchord --network $NET --network-alias anchor \
  -e HOMEPROV_ANCHOR_KEY="$KEY" -v $VCHAIN:/anchor -v $VPUB:/published \
  hpr-anchord:sig >/dev/null || exit 5
docker run -d --name hpr-monitor --network $NET --network-alias monitor \
  -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR=http://hpr-anchord:9900/append \
  -e HOMEPROV_PERIOD=5 -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$KEY" \
  -e HOMEPROV_SCHEME=closure -e HOMEPROV_GRACE_S="$GRACE" \
  -v homeprov-real_hpr-config:/cfg:ro -v $VSCR:/scratch hpr-monitor:closure-grace >/dev/null || exit 5
note "anchor image: $(docker inspect hpr-anchord --format '{{.Config.Image}} {{.Image}}')"
note "monitor image: $(docker inspect hpr-monitor --format '{{.Config.Image}} {{.Image}}')"
sleep 20
PROBE='import urllib.request,json
def post(h):
    r=urllib.request.Request("http://hpr-anchord:9900/append",data=b"{\"sealed\": {}}",method="POST",headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:80]
print(json.dumps({"untagged":post({"Content-Type":"application/json"}),"forged_tag":post({"Content-Type":"application/json","X-HP-Auth":"0"*64})}))'
note "probe_from_hub: $(docker exec hpr-hass python3 -c "$PROBE")"
sleep 40
note "monitor_log_head: $(docker logs hpr-monitor 2>&1 | head -3 | cut -c1-400 | tr '\n' ' ')"
note "chain_lines_before_run: $(docker exec hpr-anchord sh -c 'wc -l < /anchor/chain.jsonl')"

note "starting runner EC arms=$ARMS x$TRIALS tag=$TAG"
cd $REPO/testbed/real && HPR_EC_ARMS="$ARMS" HPR_EC_TRIALS=$TRIALS HPR_EC_TAG=$TAG \
  EC_SCRATCH=$SP/ec_verify ./run_experiments.sh EC > $SP/run.log 2>&1
note "runner exit: $?"
note "load_after: $(uptime)"
docker exec hpr-anchord cat /anchor/chain.jsonl > $SP/chain.jsonl 2>/dev/null
docker exec hpr-anchord sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > $SP/refusals.jsonl
docker logs hpr-monitor > $SP/monitor.log 2>&1
note "chain_lines final: $(wc -l < $SP/chain.jsonl)"
note "chain_schemes: $(python3 -c "import json,collections,sys;print(dict(collections.Counter((json.loads(l).get('payload') or {}).get('scheme','unrecorded') for l in open(sys.argv[1]) if l.strip())))" $SP/chain.jsonl)"
note "done"
gzip -c $SP/chain.jsonl > $OUT/${TAG}_anchor_chain.jsonl.gz
python3 - "$SP" "$OUT" "$TAG" "$GRACE" "$0" <<'PY'
import hashlib, json, sys
sp, out, tag, grace, script = sys.argv[1:]
lines = [l.rstrip("\n") for l in open(f"{sp}/auth_meta.log")]
cfg = {"experiment": f"{tag}: E3 grace-period sealing ({grace} s) under the AUTHENTICATED anchor with the CLOSURE monitor",
       "monitor": {"image": "hpr-monitor:closure-grace", "grace_s": float(grace),
                   "monitor_py_sha256": hashlib.sha256(open("<artifact-root>/monitor/monitor.py", "rb").read()).hexdigest()},
       "configuration_log": lines,
       "anchor_chain": {"file": f"exp/out/{tag}_anchor_chain.jsonl.gz",
                        "records": sum(1 for l in open(f"{sp}/chain.jsonl") if l.strip()),
                        "sha256_uncompressed": hashlib.sha256(open(f"{sp}/chain.jsonl", "rb").read()).hexdigest()},
       "wrapper_script_sha256": hashlib.sha256(open(script, "rb").read()).hexdigest()}
json.dump(cfg, open(f"{out}/{tag}_config.json", "w"), indent=1)
PY
