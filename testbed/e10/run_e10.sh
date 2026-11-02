#!/bin/bash
# E10 (round 14): adaptive arms on the stated boundaries of the deployed configuration, and routine operations with the
# monitor live, on SCRATCH stacks (drafts/round13/E10_DESIGN.md; pre-registration exp/out/e10_preregistration.json).
#
#   phase "upgrade" (stack e10u): a fresh Home Assistant 2025.11.1 (recorder schema 51), the two E10 monitors with their
#            linked anchors and head witnesses, one hour of rows, then Home Assistant 2026.7.4 (schema 53) on the same
#            volume with the monitors live, one more hour.
#   phase "main" (stack e10s): a scratch copy of the lab stack (2026.7.4, the lab's configuration read once read-only,
#            E9's final recorder snapshot), the same monitors, the in-hub harness homeprov_e10 (never released) driven
#            block by block from the registered plan (testbed/e10/e10ops.py plan): A1 BDT, A2 CTX, A3 DEL / DEL-PH /
#            LOWKEY, A7 WIPE, A6 CS (D3), A5 PW, A4 UL-W / UL-SHM (with the D1 stall-then-backdate) / UL-SHM-OFD / UL-JM /
#            INF-T / INF-W, then B1 entity-id rename, B2 device removal, B3 purge_entities, B4 upgrade 2026.7.4 ->
#            2026.10.1. Review r5 (drafts/round13/E10_ADDENDUM_R5.md): arm S (90 sham trials, after SNAP_DEL) and arm R
#            (10 hub restarts timed into a monitor poll, after SNAP_WIPE), scored by exp/stages/e10r5_score.py; arms C, D
#            and E run separately (testbed/e10/run_e10_r5.sh).
# Monitors (both, hardened code: monitor/hardening_e10.patch applied; verifier with exp/stages/verifier_e10.patch): stable
# columns, coverage, keylog, per-row binding, escrow, Ed25519 record signatures, name-map digest, full-history initial
# seal, keylog rewind; M-direct HOMEPROV_READ=direct (quick_check every 720 polls), M-copy copy mode (every poll), as E9.
#
#   Real run (after 2026-10-19 16:01Z, E9 scored, both patches applied, the pre-registration registered and stamped):
#       nohup testbed/e10/run_e10.sh e10_main all > <research-dir>/HOMEPROV-P13-exp/e10/e10_main.out 2>&1 &
#   Smoke (compressed plan, outputs outside exp/out):
#       HPR_E10_SMOKE=1 nohup testbed/e10/run_e10.sh e10_smoke1 all > .../e10/smoke/e10_smoke1.out 2>&1 &
# The host interpreter is PINNED (E9 amendment 3): PATH starts with <home>/miniconda3/bin and the preflight
# refuses unless `e10ops.py pyguard` passes (Python 3.12 or later at that path, opens a WAL-mode copy read-only).
# Never touches hpr-*, e2-*, e9-* (E9 must have finished); never overwrites an output.
set -u
export PATH="<home>/miniconda3/bin:$PATH"
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
X="<research-dir>/HOMEPROV-P13-exp/e10"
TAG=${1:?usage: run_e10.sh TAG [all|upgrade|main]}
PHASE=${2:-all}
SMOKE=${HPR_E10_SMOKE:-0}
PY=${HPR_E10_PY:-<home>/miniconda3/bin/python3}
OPS="$REPO/testbed/e10/e10ops.py"
STACK="$REPO/testbed/e10/e10_stack.sh"
CC=$REPO/testbed/real/ha-config/custom_components
if [ "$SMOKE" = "1" ]; then OUT=${HPR_E10_OUT:-$X/smoke/out}; else OUT=${HPR_E10_OUT:-$REPO/exp/out}; fi
SP=${HPR_E10_SP:-$X/$TAG}
SEED=${HPR_E10_SEED:-20261020}                       # pre-registered: every randomised order in the plan
MON_IMG=${HPR_E10_MONITOR_IMAGE:-hpr-monitor:e10}
ANC_IMG=${HPR_E10_ANCHOR_IMAGE:-hpr-anchord:e10}
PERIOD=5; LATE_BOUND_S=30; GAP_S=30; PURGE_TOL_S=60  # as E9 (pre-registered)
QC_DIRECT=720; QC_COPY=1
RESTART_WAIT=${HPR_E10_RESTART_WAIT:-45}
SEAL_WAIT_MAX_S=${HPR_E10_SEAL_WAIT_MAX_S:-5400}; SEAL_SETTLE_POLLS=6
NOT_BEFORE=1792425660                                # 2026-10-19T16:01:00Z
HA_LAB=homeassistant/home-assistant:2026.7.4
HA_NEXT=homeassistant/home-assistant:2026.10.1
HA_PREV=homeassistant/home-assistant:2025.11.1
MON_ENV_COMMON="HOMEPROV_SCHEME=stable HOMEPROV_COVERAGE=1 HOMEPROV_KEYLOG=1 HOMEPROV_ROWBIND=1 HOMEPROV_SINCE=0 HOMEPROV_KEYLOG_REWIND=1"

# ---- refusals ----------------------------------------------------------------------------------------------------
case "$PHASE" in all|upgrade|main) ;; *) echo "usage: run_e10.sh TAG [all|upgrade|main]"; exit 2 ;; esac
[ -e "$SP" ] && { echo "REFUSING: $SP exists"; exit 3; }
ls "$OUT/${TAG}_"* >/dev/null 2>&1 && { echo "REFUSING: outputs $OUT/${TAG}_* exist"; exit 3; }
[ "$(date -u +%s)" -lt "$NOT_BEFORE" ] && { echo "REFUSING: before 2026-10-19T16:01:00Z (E9 owns Docker on this Mac)"; exit 2; }
pgrep -f "testbed/e9/run_e9.sh" >/dev/null && { echo "REFUSING: run_e9.sh is still running"; exit 2; }
docker ps -a --format '{{.Names}}' | grep -qE '^e9-|^e9s-' && { echo "REFUSING: E9 containers still exist"; exit 2; }
for p in e10s e10u; do docker ps -a --format '{{.Names}}' | grep -q "^$p-" && { echo "REFUSING: $p-* containers exist"; exit 3; }; done
if [ "$SMOKE" != "1" ] && [ "$PHASE" != "upgrade" ]; then   # the main session (~7 h) must end before 03:40 UTC
  HM=$((10#$(date -u +%H%M))); { [ "$HM" -ge 450 ] && [ "$HM" -le 1500 ]; } || { echo "REFUSING: start the main phase between 04:50 and 15:00 UTC"; exit 2; }
fi
G=$("$PY" "$OPS" pyguard 2>&1 | tail -1)
case "$G" in *'"ok": true'*) ;; *) echo "REFUSING: interpreter guard failed: $G"; exit 4 ;; esac

mkdir -p "$SP/keys" "$SP/code" "$SP/snapshots" "$SP/e10" "$SP/namemap" "$OUT"
META=$SP/auth_meta.log; EVLOG=$SP/events.jsonl
: > "$META"; : > "$EVLOG"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META" >&2; }
# ev TYPE FIELDS: one JSON object per line in events.jsonl. Guard of 2026-10-19 (smoke e10_smoke3: pretty-printed acks,
# a stray du line and "0\nnull" made multi-line or invalid records, and every offline check that reads the log failed):
# a payload that parses is compacted to one line; one that does not is kept as a string under "raw", "malformed": true.
ev() {
  local t; t=$(date -u +%s)
  "$PY" -c 'import json,sys
s, t, k = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    print(json.dumps(json.loads(s)))
except ValueError:
    print(json.dumps({"ts": t, "type": k, "malformed": True, "raw": s}))' \
    "$(printf '{"ts": %s, "utc": "%s", "type": "%s"%s}' "$t" "$(date -u +%FT%TZ)" "$1" "${2:+, $2}")" "$t" "$1" >> "$EVLOG"
}
s16() { shasum -a 256 "$1" | cut -c1-16; }
fp16() { printf '%s' "$1" | shasum -a 256 | cut -c1-16; }
wsleep() { local end=$(( $(date -u +%s) + ${1%.*} )); while [ "$(date -u +%s)" -lt "$end" ]; do sleep 1; done; }
wait_until() { local t=${1%.*}; while [ "$(date -u +%s)" -lt "$t" ]; do sleep 1; done; }
jq_() { "$PY" -c "import json,sys;d=json.loads(sys.argv[1]);v=d.get(sys.argv[2]);print(json.dumps(v) if isinstance(v,(dict,list)) else ('' if v is None else v))" "$1" "$2"; }
# bcmd OP KEY...: the harness command {"op": OP, KEY: block[KEY], ...} from the block JSON in $B. Fix of 2026-10-19
# (smoke e10_smoke1): macOS /bin/bash 3.2 brace-expands a "{a,b}" inside a double-quoted string nested in a quoted
# command substitution ("$(... "...{'op':'bdt','ages':...}..." ...)"), splitting the Python code into three scripts;
# A1_BDT, A2_CTX and A3_DEL sent empty commands and timed out. Single quotes, one level deep, are not expanded.
bcmd() { "$PY" -c 'import json,sys;b=json.loads(sys.argv[1]);d={"op":sys.argv[2]};d.update({k:b[k] for k in sys.argv[3:]});print(json.dumps(d))' "$B" "$@"; }
note "tag=$TAG phase=$PHASE smoke=$SMOKE seed=$SEED python=$G"
caffeinate -i -s -m -w $$ & CAFF_PID=$!

# ---- preflight ---------------------------------------------------------------------------------------------------
preflight() {
  grep -q HOMEPROV_HARDEN "$REPO/monitor/monitor.py" || { note "FAIL monitor/hardening_e10.patch is not applied"; exit 2; }
  grep -q "class ObservationBreaks" "$REPO/exp/stages/e7_verify.py" || { note "FAIL exp/stages/verifier_e10.patch is not applied"; exit 2; }
  [ -f "$REPO/monitor/monitor_e9.py" ] && [ "$(shasum -a 256 "$REPO/monitor/monitor_e9.py" | cut -d' ' -f1)" = 8ad9e2d77f2d098af1e81ed509445631dc3d3ba2d349fddff75bfd920a7ab8ae ] \
    || { note "FAIL monitor/monitor_e9.py (the E9 monitor, byte for byte) is missing"; exit 2; }
  [ -f "$REPO/exp/stages/e7_verify_e9.py" ] && [ "$(shasum -a 256 "$REPO/exp/stages/e7_verify_e9.py" | cut -d' ' -f1)" = 9c42fad983a00e43083359339bc185c11d31ab7cdec7781f0e2cdee94ebea885 ] \
    || { note "FAIL exp/stages/e7_verify_e9.py (the E9 verifier, byte for byte) is missing"; exit 2; }
  if [ "$SMOKE" != "1" ]; then
    "$PY" "$REPO/testbed/e10/e10_prereg.py" --check "$REPO/exp/out/e10_preregistration.json" >> "$META" 2>&1 \
      || { note "FAIL the pre-registration is missing, not registered, or a frozen file changed"; exit 2; }
    note "ok    pre-registration registered and every frozen file at its registered sha256"
  fi
  if [ "${HPR_E10_RUN_TESTS:-1}" = "1" ]; then
    for t in monitor testbed/anchord testbed/e10/test_e10_patches.py; do
      ( cd "$REPO" && "$PY" -m pytest -q -p no:cacheprovider "$t" ) > "$SP/pytest_$(basename $t).log" 2>&1 \
        || { note "FAIL tests $t ($(tail -2 "$SP/pytest_$(basename $t).log" | tr '\n' ' '))"; exit 2; }
      note "ok    tests $t: $(tail -1 "$SP/pytest_$(basename $t).log")"
    done
  fi
  docker build -q -f "$REPO/monitor/Dockerfile.sign" -t "$MON_IMG" "$REPO/monitor" >/dev/null || { note "FAIL build $MON_IMG"; exit 2; }
  docker build -q -f "$REPO/testbed/e8/anchord-e8.Dockerfile" -t "$ANC_IMG" "$REPO/testbed/anchord" >/dev/null || { note "FAIL build $ANC_IMG"; exit 2; }
  local f rp img ip repo_h img_h
  for f in "monitor/monitor.py|$MON_IMG|/app/monitor.py" "testbed/anchord/anchord.py|$ANC_IMG|/app/anchord.py" \
           "testbed/anchord/anchord_linked.py|$ANC_IMG|/app/anchord_linked.py"; do
    rp=${f%%|*}; img=$(echo "$f" | cut -d'|' -f2); ip=${f##*|}
    repo_h=$(shasum -a 256 "$REPO/$rp" | cut -d' ' -f1)
    img_h=$(docker run --rm --entrypoint sha256sum "$img" "$ip" | cut -d' ' -f1)
    [ "$repo_h" = "$img_h" ] || { note "FAIL $img:$ip $img_h != $rp $repo_h"; exit 2; }
    note "ok    $img:$ip = $rp (${repo_h:0:16})"
  done
  note "monitor image hardening: $(docker run --rm --entrypoint python "$MON_IMG" -c 'import os;os.environ["HOMEPROV_SCRATCH"]="/tmp/h";os.makedirs("/tmp/h",exist_ok=True);import importlib.util as u;s=u.spec_from_file_location("m","/app/monitor.py");m=u.module_from_spec(s);s.loader.exec_module(m);import json;print(json.dumps(m.hardening_report()))' 2>&1 | tail -1)"
  for img in "$HA_LAB" "$HA_NEXT" "$HA_PREV" eclipse-mosquitto:2 hpr-devices:1 alpine:3; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null || { note "FAIL image $img"; exit 2; }
    note "image $img $(docker image inspect "$img" --format '{{.Id}} {{index .RepoDigests 0}}' 2>/dev/null)"
  done
  VM_FREE_KB=$(docker run --rm alpine:3 df -k / | awk 'NR==2{print $4}')
  note "Docker VM free disk: ${VM_FREE_KB} KiB; hpr-* running: $(docker ps --format '{{.Names}}' | grep -c '^hpr-')"
  ev preflight "\"vm_free_kib\": ${VM_FREE_KB:-null}, \"hpr_running\": $(docker ps --format '{{.Names}}' | grep -c '^hpr-')"
}
preflight
"$PY" "$OPS" plan --seed "$SEED" $([ "$SMOKE" = "1" ] && echo --smoke) > "$SP/plan.json"
cp "$OPS" "$STACK" "$REPO/testbed/anchord/headwitness.py" "$REPO/testbed/anchord/chainverify.py" "$SP/code/"
note "plan: $(s16 "$SP/plan.json") seed=$SEED; repo sha256_16: monitor.py=$(s16 $REPO/monitor/monitor.py) e7_verify.py=$(s16 $REPO/exp/stages/e7_verify.py) homeprov_e10=$(s16 $CC/homeprov_e10/__init__.py) homeprov_ec=$(s16 $CC/homeprov_ec/__init__.py) homeprov_e7=$(s16 $CC/homeprov_e7/__init__.py) e10ops.py=$(s16 $OPS) run_e10.sh=$(s16 $0)"

# ---- per-stack state (set by use_stack) and helpers ---------------------------------------------------------------
PFX=""; HUB=""; NET=""; CFGVOL=""; BROKER=""; WPORT_D=""; WPORT_C=""; V=""
AD=""; MD=""; AC=""; MC=""; WNET=""; WPID_D=""; WPID_C=""; HOSTLOG_PID=""
use_stack() {   # $1 prefix, $2 witness port (direct), $3 witness port (copy)
  PFX=$1; HUB=$1-hass; NET=$1-net; CFGVOL=$1-config; BROKER=$1-broker; WPORT_D=$2; WPORT_C=$3
  V=$1-$TAG; AD=$1-anchord-direct; MD=$1-monitor-direct; AC=$1-anchord-copy; MC=$1-monitor-copy; WNET=$1-$TAG-wnet
  mkdir -p "$SP/$1/escrow_direct" "$SP/$1/escrow_copy" "$SP/$1/witness_direct" "$SP/$1/witness_copy" "$SP/$1/snapshots"
}
witness_get() { "$PY" -c 'import sys,urllib.request;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())' "http://127.0.0.1:$1$2" 2>/dev/null; }

keys_and_operator() {   # fresh keys per stack; only fingerprints recorded
  KEY_D=$(openssl rand -hex 32); KEY_C=$(openssl rand -hex 32); OKEY_D=$(openssl rand -hex 32); OKEY_C=$(openssl rand -hex 32)
  WKEY_D=$(openssl rand -hex 32); WKEY_C=$(openssl rand -hex 32)
  note "$PFX: append_key_fp direct=$(fp16 "$KEY_D") copy=$(fp16 "$KEY_C"); operator_key_fp direct=$(fp16 "$OKEY_D") copy=$(fp16 "$OKEY_C"); witness_key_fp direct=$(fp16 "$WKEY_D") copy=$(fp16 "$WKEY_C") (keys not recorded)"
  docker volume create "$V-operator" >/dev/null
  printf '%s' "$OKEY_D" | docker run -i --rm -v "$V-operator":/op alpine:3 sh -c 'umask 077; cat > /op/direct.key'
  printf '%s' "$OKEY_C" | docker run -i --rm -v "$V-operator":/op alpine:3 sh -c 'umask 077; cat > /op/copy.key'
  local fp
  fp=$(docker run --rm -v "$V-operator":/op --entrypoint python "$MON_IMG" -c '
import hashlib, os
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519
k = ed25519.Ed25519PrivateKey.generate(); os.umask(0o077)
open("/op/operator.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
p = k.public_key(); open("/op/operator.pub.pem", "wb").write(p.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
print(hashlib.sha256(p.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).hexdigest())' 2>&1 | tail -1)
  [ ${#fp} -eq 64 ] || { note "FAIL operator key ($fp)"; exit 5; }
  docker run --rm -v "$V-operator":/op:ro alpine:3 cat /op/operator.pub.pem > "$SP/$PFX/operator_sign_pub.pem"
  note "$PFX: operator signing key fingerprint $fp"
  local m
  for m in direct copy; do
    docker volume create "$V-$m-sign" >/dev/null
    fp=$(docker run --rm -v "$V-$m-sign":/sign --entrypoint python "$MON_IMG" -c '
import hashlib, os
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519
k = ed25519.Ed25519PrivateKey.generate(); os.umask(0o077)
open("/sign/monitor.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
p = k.public_key(); open("/sign/monitor.pub.pem", "wb").write(p.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
print(hashlib.sha256(p.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).hexdigest())' 2>&1 | tail -1)
    [ ${#fp} -eq 64 ] || { note "FAIL signing key $m ($fp)"; exit 5; }
    docker run --rm -v "$V-$m-sign":/sign:ro alpine:3 cat /sign/monitor.pub.pem > "$SP/$PFX/${m}_sign_pub.pem"
    note "$PFX $m: record-signing key fingerprint $fp"
  done
}

start_witnesses() {
  local m p k d pid n
  for m in direct copy; do
    if [ $m = direct ]; then p=$WPORT_D; k=$WKEY_D; else p=$WPORT_C; k=$WKEY_C; fi
    lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 && { note "FAIL port $p in use"; exit 5; }
    d="$SP/$PFX/witness_$m"
    WITNESS_LOG="$d/heads.jsonl" WITNESS_FORKS="$d/forks.jsonl" HOMEPROV_WITNESS_KEY="$k" WITNESS_DIR="$d" \
      nohup "$PY" -u -c 'import sys; sys.path.insert(0, sys.argv[1]); import headwitness as W; W.serve(host="127.0.0.1", port=int(sys.argv[2]))' \
      "$SP/code" "$p" > "$d/witness.log" 2>&1 &
    pid=$!; n=0
    until grep -q READY "$d/witness.log" 2>/dev/null || [ $n -ge 20 ]; do sleep 0.5; n=$((n+1)); done
    grep -q READY "$d/witness.log" || { note "FAIL witness $m"; exit 5; }
    if [ $m = direct ]; then WPID_D=$pid; else WPID_C=$pid; fi
    note "$PFX witness $m pid $pid port $p"
  done
}

start_anchors() {
  local m a alias k o w p r
  docker network create "$WNET" >/dev/null
  for m in direct copy; do
    if [ $m = direct ]; then a=$AD; alias=anchor-direct; k=$KEY_D; o=$OKEY_D; w=$WKEY_D; p=$WPORT_D
    else a=$AC; alias=anchor-copy; k=$KEY_C; o=$OKEY_C; w=$WKEY_C; p=$WPORT_C; fi
    docker volume create "$V-$m-chain" >/dev/null; docker volume create "$V-$m-pub" >/dev/null
    docker run -d --name "$a" --network "$NET" --network-alias "$alias" --restart unless-stopped \
      -e HOMEPROV_ANCHOR_KEY="$k" -e HOMEPROV_OPERATOR_KEY="$o" -e HOMEPROV_ANCHOR_LINK=v2 \
      -e HOMEPROV_WITNESS_KEY="$w" -e HEAD_WITNESS_URL="http://host.docker.internal:$p/head" -e HEAD_WITNESS_MODE=sync \
      -v "$V-$m-chain":/anchor -v "$V-$m-pub":/published "$ANC_IMG" >/dev/null || { note "FAIL anchor $a"; exit 5; }
    docker network connect "$WNET" "$a"
    sleep 2
    r=$(docker exec "$a" python -c "import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:$p/head',timeout=5).status)" 2>&1 | tail -1)
    [ "$r" = "200" ] || { note "FAIL $a cannot reach its witness ($r)"; exit 7; }
  done
}

start_monitor() {   # $1 direct|copy
  local m=$1 name alias anchor key envs=() kv mode
  if [ $m = direct ]; then name=$MD; alias=monitor-direct; anchor=anchor-direct; key=$KEY_D; mode="HOMEPROV_READ=direct HOMEPROV_QUICK_CHECK_EVERY=$QC_DIRECT"
  else name=$MC; alias=monitor-copy; anchor=anchor-copy; key=$KEY_C; mode="HOMEPROV_READ=copy HOMEPROV_QUICK_CHECK_EVERY=$QC_COPY"; fi
  for kv in $MON_ENV_COMMON $mode; do envs+=(-e "$kv"); done
  docker volume create "$V-$m-scratch" >/dev/null
  docker run -d --name "$name" --network "$NET" --network-alias "$alias" --restart unless-stopped \
    -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR="http://$anchor:9900/append" -e HOMEPROV_PERIOD=$PERIOD \
    -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$key" -e HOMEPROV_ESCROW_DIR=/escrow \
    -e HOMEPROV_COST_LOG=/scratch/cost.jsonl -e HOMEPROV_SIGN_KEY=/sign/monitor.pem -e HOMEPROV_REPLY_TAGS=1 \
    -e HOMEPROV_NAMEMAP_DIR=/cfg/.storage "${envs[@]}" \
    -v "$CFGVOL":/cfg:ro -v "$V-$m-scratch":/scratch -v "$SP/$PFX/escrow_$m":/escrow -v "$V-$m-sign":/sign:ro \
    "$MON_IMG" >/dev/null || { note "FAIL monitor $name"; exit 5; }
  note "$name started ($mode); hardening: $(sleep 8; docker logs "$name" 2>&1 | grep -m1 hardening | cut -c1-300)"
}

wait_sealed() {   # $1 monitor, $2 anchor (as run_e9.sh): the full-history seal anchored and SEAL_SETTLE_POLLS polls past it
  local end=$(( $(date -u +%s) + SEAL_WAIT_MAX_S )) t0 st rc
  t0=$(date -u +%s)
  while [ "$(date -u +%s)" -lt "$end" ]; do
    st=$(docker exec "$2" python -c '
import json
n=mx=mn=0
for l in open("/anchor/chain.jsonl"):
    p=json.loads(l).get("payload") or {}
    if p.get("observer")!="external-monitor": continue
    n+=1; s=int(p.get("seq_local",0)); mx=max(mx,s); mn=s if mn==0 else min(mn,s)
print(n, mn, mx)' 2>/dev/null)
    set -- "$1" "$2" $st
    if [ "${3:-0}" -gt 0 ] && [ $(( ${5:-0} - ${4:-0} )) -ge "$SEAL_SETTLE_POLLS" ]; then
      ev initial_seal "\"monitor\": \"$1\", \"wait_s\": $(( $(date -u +%s) - t0 )), \"records\": $3, \"restarts\": $(docker inspect "$1" --format '{{.RestartCount}}'), \"memory_peak_bytes\": $(docker exec "$1" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo null)"
      return 0
    fi
    sleep 10
  done
  note "FAIL $1 did not seal its history within ${SEAL_WAIT_MAX_S}s"; return 1
}

hub_writing() {   # 0 when the hub's newest state row is younger than 60 s (read outside the hub)
  local lag
  lag=$(docker run --rm -v "$CFGVOL":/cfg:ro --entrypoint python "$MON_IMG" -c "import sqlite3,time;c=sqlite3.connect('file:/cfg/home-assistant_v2.db?mode=ro&readonly_shm=1',uri=True,timeout=30);print(int(time.time()-c.execute('select max(last_updated_ts) from states').fetchone()[0]))" 2>/dev/null | tail -1)
  [ -n "$lag" ] && [ "$lag" -lt 60 ] 2>/dev/null
}
wait_writing() { local i; for i in $(seq 1 60); do hub_writing && return 0; sleep 10; done; return 1; }

snapshot_db() {   # $1 label: SQLite's online backup API from a read-only connection OUTSIDE the hub (as E9)
  local lab=$1 dst="$SP/$PFX/snapshots/$1.db" res try
  for try in 1 2 3; do
    res=$(docker run --rm -v "$CFGVOL":/cfg:ro -v "$SP/$PFX/snapshots":/out --entrypoint python "$MON_IMG" -c '
import json, sqlite3, sys, time
dst = "/out/%s.db.part" % sys.argv[1]; t0 = time.time()
s = sqlite3.connect("file:/cfg/home-assistant_v2.db?mode=ro&readonly_shm=1", uri=True, timeout=120)
d = sqlite3.connect(dst); s.backup(d); d.close(); s.close(); t1 = time.time()
q = sqlite3.connect("file:%s?mode=ro" % dst, uri=True).execute("PRAGMA quick_check").fetchone()[0]
print(json.dumps({"t_snapshot": t0, "t_done": t1, "quick_check": q}))' "$lab" 2>&1 | tail -1)
    case "$res" in "{"*'"quick_check": "ok"'*) mv "$dst.part" "$dst"; break ;; esac
    rm -f "$dst.part"; res=""; sleep 5
  done
  [ -n "$res" ] || { note "  snapshot $lab FAILED"; ev snapshot "\"stack\": \"$PFX\", \"label\": \"$lab\", \"ok\": false"; return 1; }
  ev snapshot "\"stack\": \"$PFX\", \"label\": \"$lab\", \"ok\": true, \"t_snapshot\": $(jq_ "$res" t_snapshot), \"t_done\": $(jq_ "$res" t_done), \"file\": \"$PFX/snapshots/$lab.db\", \"sha256\": \"$(shasum -a 256 "$dst" | cut -d' ' -f1)\", \"bytes\": $(stat -f %z "$dst")"
  note "  snapshot $PFX/$lab $(stat -f %z "$dst") bytes"
}

issue_marker() {   # e10ops issue (CLOCK_STEP here; PURGE/RESTORE/RENAME through e9ops) to both anchors of this stack
  local res
  res=$(docker run --rm --network "$NET" -v "$V-operator":/op:ro -v "$REPO/exp/rig":/rig:ro -v "$REPO/testbed/e9":/e9:ro \
          -v "$REPO/testbed/e10":/e10:ro -e E10_E9OPS=/e9/e9ops.py --entrypoint python "$MON_IMG" /e10/e10ops.py issue \
          --issuer /rig/marker_issuer.py --sign-key /op/operator.pem --anchors anchor-direct=/op/direct.key \
          anchor-copy=/op/copy.key "$@" 2>&1 | tail -1)
  case "$res" in "{"*) ev marker "\"stack\": \"$PFX\", \"result\": $res" ;; *) ev marker "\"stack\": \"$PFX\", \"error\": $(printf '%s' "$res" | "$PY" -c 'import json,sys;print(json.dumps(sys.stdin.read()[-400:]))')" ;; esac
  note "  marker [$*]: $(printf '%s' "$res" | cut -c1-200)"
  printf '%s' "$res" | grep -q '"all_ok": true'
}

namemap_now() {   # $1 change JSON or "": the name map and predicted digests (display fields only)
  docker run --rm -v "$CFGVOL":/cfg:ro -v "$REPO/testbed/e9":/e9:ro -v "$REPO/testbed/e10":/e10:ro -e E10_E9OPS=/e9/e9ops.py \
    --entrypoint python "$MON_IMG" /e10/e10ops.py namemap --storage /cfg/.storage ${1:+--change "$1"} 2>/dev/null | tail -1
}

E10N=0
e10_cmd() {   # $1 JSON body (op and parameters), $2 timeout s -> prints the result's file name; the result is copied to $SP/e10/
  E10N=$((E10N+1)); local id="c$(printf %03d $E10N)$(openssl rand -hex 3)" a end
  "$PY" -c "import json,sys;d=json.loads(sys.argv[1]);d['id']=sys.argv[2];print(json.dumps(d))" "$1" "$id" > "$SP/.e10cmd"
  docker exec "$HUB" rm -f /config/homeprov_e10.ack
  docker cp "$SP/.e10cmd" "$HUB:/config/homeprov_e10.cmd" >/dev/null
  ev e10_cmd "\"id\": \"$id\", \"command\": $(cat "$SP/.e10cmd")"
  end=$(( $(date -u +%s) + ${2:-3600} ))
  while [ "$(date -u +%s)" -lt "$end" ]; do
    a=$(docker exec "$HUB" cat /config/homeprov_e10.ack 2>/dev/null)
    case "$a" in *"\"id\": \"$id\""*)
      local f; f=$(jq_ "$a" file)
      docker cp "$HUB:/config/homeprov_out/e10/$f" "$SP/e10/$f" >/dev/null 2>&1
      ev e10_result "\"id\": \"$id\", \"ack\": $a, \"sha256\": \"$(shasum -a 256 "$SP/e10/$f" 2>/dev/null | cut -d' ' -f1)\""
      note "  e10 $id: $(printf '%s' "$a" | cut -c1-160)"; printf '%s' "$f"; return 0 ;;
    esac
    sleep 2
  done
  ev e10_result "\"id\": \"$id\", \"timeout\": true"; note "  e10 $id TIMEOUT"; return 1
}

hub_restart() { local b; b=$(docker inspect "$HUB" --format '{{.State.StartedAt}}'); docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"; ev hub_restart "\"stack\": \"$PFX\", \"cause\": \"$1\", \"started_before\": \"$b\", \"started_at\": \"$(docker inspect "$HUB" --format '{{.State.StartedAt}}')\""; }

collect() {   # chains, refusals, cost logs of this stack's monitors (copies; the run goes on)
  local m a c
  for m in direct copy; do
    if [ $m = direct ]; then a=$AD; c=$MD; else a=$AC; c=$MC; fi
    docker exec "$a" cat /anchor/chain.jsonl > "$SP/$PFX/${m}_chain.jsonl" 2>/dev/null
    docker exec "$a" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/$PFX/${m}_refusals.jsonl"
    docker cp "$c:/scratch/cost.jsonl" "$SP/$PFX/${m}_cost.jsonl" >/dev/null 2>&1
  done
}

start_stack_monitoring() {   # keys, witnesses, anchors, host log, monitors (staggered full-history seals)
  keys_and_operator; start_witnesses; start_anchors
  nohup "$PY" -u "$OPS" hostlog --out "$SP/$PFX/hostlog.jsonl" --hub "$HUB" --monitors "$MD" "$MC" --vm-probe "$AC" \
    --stop-file "$SP/$PFX/.hostlog_stop" > "$SP/$PFX/hostlog.out" 2>&1 &
  HOSTLOG_PID=$!
  start_monitor direct; wait_sealed "$MD" "$AD" || exit 8
  start_monitor copy; wait_sealed "$MC" "$AC" || exit 8
}

freeze_stack() {   # settle, final snapshot, stop monitors, collect everything of this stack
  local m a c p
  note "$PFX: settling 90 s"; wsleep 90
  for c in $MD $MC; do ev monitor_memory_peak "\"monitor\": \"$c\", \"bytes\": $(docker exec "$c" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo null), \"restarts\": $(docker inspect "$c" --format '{{.RestartCount}}')"; done
  snapshot_db final; wsleep 30
  docker stop "$MD" "$MC" >/dev/null 2>&1; wsleep 8
  : > "$SP/$PFX/.hostlog_stop"
  for m in direct copy; do
    if [ $m = direct ]; then a=$AD; c=$MD; p=$WPORT_D; else a=$AC; c=$MC; p=$WPORT_C; fi
    witness_get $p /head > "$SP/$PFX/witness_$m/head_final.json"
    docker exec "$a" cat /anchor/chain.jsonl > "$SP/$PFX/${m}_chain.jsonl"
    docker exec "$a" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/$PFX/${m}_refusals.jsonl"
    docker cp "$c:/scratch/cost.jsonl" "$SP/$PFX/${m}_cost.jsonl" >/dev/null 2>&1
    docker cp "$c:/scratch/namemap" "$SP/$PFX/namemap_$m" >/dev/null 2>&1
    docker logs "$c" > "$SP/$PFX/${m}_monitor.log" 2>&1; docker logs "$a" > "$SP/$PFX/${m}_anchord.log" 2>&1
    gzip -c "$SP/$PFX/${m}_chain.jsonl" > "$OUT/${TAG}_${PFX}_${m}_chain.jsonl.gz"
    gzip -c "$SP/$PFX/witness_$m/heads.jsonl" > "$OUT/${TAG}_${PFX}_${m}_witness_heads.jsonl.gz"
  done
  mkdir -p "$SP/$PFX/namemap_storage"
  docker run --rm -v "$CFGVOL":/cfg:ro -v "$SP/$PFX/namemap_storage":/out -v "$REPO/testbed/e9":/e9:ro --entrypoint python \
    "$MON_IMG" /e9/e9ops.py namemap-sanitize --storage /cfg/.storage --out /out >> "$META" 2>&1
  kill "$WPID_D" "$WPID_C" 2>/dev/null; WPID_D=""; WPID_C=""
  docker logs "$HUB" > "$SP/$PFX/hub.log" 2>&1
}

teardown_stack() {
  [ -n "$PFX" ] || return 0
  [ -n "$HOSTLOG_PID" ] && { : > "$SP/$PFX/.hostlog_stop"; sleep 2; kill "$HOSTLOG_PID" 2>/dev/null; HOSTLOG_PID=""; }
  [ -n "$WPID_D" ] && kill "$WPID_D" 2>/dev/null; [ -n "$WPID_C" ] && kill "$WPID_C" 2>/dev/null
  docker rm -f "$MD" "$MC" "$AD" "$AC" >/dev/null 2>&1
  docker volume rm "$V-direct-sign" "$V-copy-sign" "$V-operator" >/dev/null 2>&1 && note "$PFX: signing-key and operator volumes destroyed"
  for v in "$V-direct-chain" "$V-direct-pub" "$V-direct-scratch" "$V-copy-chain" "$V-copy-pub" "$V-copy-scratch"; do docker volume rm "$v" >/dev/null 2>&1; done
  docker network rm "$WNET" >/dev/null 2>&1
  "$STACK" down "$PFX" >> "$META" 2>&1
  PFX=""
}
on_exit() { note "exit: tearing down"; teardown_stack; note "hpr-* running at exit: $(docker ps --format '{{.Names}}' | grep -c '^hpr-')"; kill "$CAFF_PID" 2>/dev/null; }
trap on_exit EXIT
trap 'exit 130' INT TERM HUP
PLAN() { "$PY" -c "import json,sys;p=json.load(open(sys.argv[1]));print(json.dumps(next((b for b in p['blocks'] if b['block']==sys.argv[2]),None) if sys.argv[2]!='upgrade_stack' else p['upgrade_stack']))" "$SP/plan.json" "$1"; }
R() { "$PY" -c "import json,sys;d=json.load(open(sys.argv[1]));exec(sys.argv[2])" "$SP/e10/$1" "$2"; }   # read a result file

# =================================================================================================================
# PHASE upgrade (stack e10u): schema 51 -> 53 with the monitors live
# =================================================================================================================
phase_upgrade() {
  local U; U=$(PLAN upgrade_stack)
  use_stack e10u 19984 19985
  ev phase_begin "\"phase\": \"upgrade\", \"plan\": $U"
  E10_HA_IMAGE=$(jq_ "$U" from_image) "$STACK" up-fresh e10u > "$SP/e10u/stack.json" 2>> "$META" || exit 6
  ev stack_up "\"stack\": \"e10u\", \"info\": $(cat "$SP/e10u/stack.json")"
  wait_writing || { note "FAIL e10u hub not writing"; exit 6; }
  start_stack_monitoring
  ev namemap "\"stack\": \"e10u\", \"label\": \"before\", \"namemap\": $(namemap_now "" || echo null)"
  snapshot_db start; T_U0=$(date -u +%s); echo "$T_U0" > "$SP/e10u/t_start"
  wsleep "$(jq_ "$U" before_s)"
  snapshot_db pre_upgrade; collect
  "$STACK" upgrade e10u "$(jq_ "$U" to_image)" > "$SP/e10u/upgrade.json" 2>> "$META"
  ev upgrade "\"stack\": \"e10u\", \"result\": $(cat "$SP/e10u/upgrade.json" 2>/dev/null || echo null)"
  wsleep "$(jq_ "$U" after_s)"
  ev namemap "\"stack\": \"e10u\", \"label\": \"after\", \"namemap\": $(namemap_now "" || echo null)"
  snapshot_db post_upgrade; date -u +%s > "$SP/e10u/t_end"
  freeze_stack; teardown_stack
  ev phase_end "\"phase\": \"upgrade\""
}

# =================================================================================================================
# PHASE main (stack e10s)
# =================================================================================================================
install_e10() {   # homeprov_ec and homeprov_e7 as import dependencies only (never listed), homeprov_e10 listed
  local src comp
  for src in "$CC/homeprov_ec" "$CC/homeprov_e7" "$CC/homeprov_e10"; do
    comp=$(basename "$src")
    docker exec "$HUB" mkdir -p "/config/custom_components/$comp"
    docker cp "$src/." "$HUB:/config/custom_components/$comp/" >/dev/null
    docker exec "$HUB" rm -rf "/config/custom_components/$comp/__pycache__"
  done
  docker exec "$HUB" sh -c 'grep -q "^homeprov_e10:" /config/configuration.yaml || printf "\nhomeprov_e10:\n" >> /config/configuration.yaml'
  docker exec "$HUB" rm -f /config/homeprov_out/e10/ready.json
  hub_restart "activate homeprov_e10"
  local i; for i in $(seq 1 60); do docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json && break; sleep 5; done
  docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json || { note "FAIL homeprov_e10 not ready"; exit 6; }
  ev e10_installed "\"homeprov_e10_sha256\": \"$(shasum -a 256 "$CC/homeprov_e10/__init__.py" | cut -d' ' -f1)\""
}
uninstall_e10() {
  docker exec "$HUB" rm -rf /config/custom_components/homeprov_ec /config/custom_components/homeprov_e7 /config/custom_components/homeprov_e10
  docker exec "$HUB" sh -c "sed -i '/^homeprov_e10:/d' /config/configuration.yaml; rm -f /config/homeprov_e10.cmd /config/homeprov_e10.ack"
  hub_restart "deactivate homeprov_e10"
}

block() {   # $1 block name -> runs it
  local B; B=$(PLAN "$1")
  [ "$B" = "null" ] && return 0
  ev block_begin "\"block\": \"$1\", \"plan\": $B"; note "== block $1"
  case "$1" in
  A1_BDT)   # wait so that every backdated target (ages up to 45 s) lies after the session start t0, the start of every
            # e10s verification window (fix of 2026-10-20, smoke e10_smoke6: trial 1's target, 45 s before its insert at
            # t0 + 16 s, fell before t0 and was scored no_evidence although both monitors had sealed it)
            wsleep 60
            F_BDT=$(e10_cmd "$(bcmd bdt ages spacing_s)" 7200) ;;
  A2_CTX)   F_CTX=$(e10_cmd "$(bcmd ctx delays spacing_s)" 7200) ;;
  A3_DEL)   F_DEL=$(e10_cmd "$(bcmd del delays spacing_s)" 7200) ;;
  A3_DELPH) e10_cmd "$("$PY" -c "import json,sys;b=json.loads(sys.argv[1]);b['op']='delph';b.pop('block');print(json.dumps(b))" "$B")" 3600 >/dev/null ;;
  S_SHAM)   # review r5 arm S: the BDT / CTX / DEL code paths with the write transaction rolled back (homeprov_e10 op sham)
    F_SHAM=$(e10_cmd "$("$PY" -c "import json,sys;b=json.loads(sys.argv[1]);b.pop('block');print(json.dumps(b))" "$B")" 10800) ;;
  R_RESTART)   # review r5 arm R: hub restarts timed from a monitor's cost log to land inside its next read / copy window
    local nr i kind tgt mon lag res lags="" rfrac rto settle
    nr=$("$PY" -c "import json,sys;print(len(json.loads(sys.argv[1])['trials']))" "$B")
    lag=$(jq_ "$B" lag0_s); rfrac=$(jq_ "$B" frac); rto=$(jq_ "$B" stop_timeout_s); settle=$(jq_ "$B" settle_s)
    for i in $(seq 0 $((nr-1))); do
      kind=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['trials'][int(sys.argv[2])]['kind'])" "$B" "$i")
      tgt=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['trials'][int(sys.argv[2])]['target'])" "$B" "$i")
      if [ "$tgt" = direct ]; then mon=$MD; else mon=$MC; fi
      # no command may be pending across the restart (homeprov_e10 also ignores a stale one); readiness is re-awaited
      docker exec "$HUB" rm -f /config/homeprov_e10.cmd /config/homeprov_out/e10/ready.json
      res=$("$PY" "$OPS" restart-trial --hub "$HUB" --monitor "$mon" --probe "$AC" --mode "$tgt" --kind "$kind" \
              --lag "$lag" --frac "$rfrac" --stop-timeout "$rto" 2>&1 | tail -1)
      case "$res" in "{"*) ;; *) res=$("$PY" -c 'import json,sys;print(json.dumps({"ok": False, "raw": sys.argv[1][-400:]}))' "$res") ;; esac
      ev restart_trial "\"stack\": \"$PFX\", \"trial\": $i, \"kind\": \"$kind\", \"target\": \"$tgt\", \"result\": $res"
      ev hub_restart "\"stack\": \"$PFX\", \"cause\": \"arm R trial $i ($kind, aimed at M-$tgt)\", \"started_at\": \"$(docker inspect "$HUB" --format '{{.State.StartedAt}}')\""
      note "  R trial $i $kind -> M-$tgt: $(printf '%s' "$res" | cut -c1-240)"
      wait_writing || note "  WARN R trial $i: the hub is not writing after the restart"
      local w; for w in $(seq 1 60); do docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json && break; sleep 5; done
      docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json || note "  WARN R trial $i: homeprov_e10 not ready again"
      # did the hub move its recorder away (corrupt / unclean) or say anything about the database at start-up?
      ev restart_after "\"stack\": \"$PFX\", \"trial\": $i, \"corrupt_files\": $(docker exec "$HUB" sh -c 'ls /config | grep -c corrupt; true' 2>/dev/null || echo null), \"db_log\": $(docker logs --since 10m "$HUB" 2>&1 | grep -iE 'shut ?down cleanly|unclean|corrupt|integrity|database is locked|malformed' | tail -5 | "$PY" -c 'import json,sys;print(json.dumps(sys.stdin.read().splitlines()))'), \"monitor_restarts\": {\"direct\": $(docker inspect "$MD" --format '{{.RestartCount}}'), \"copy\": $(docker inspect "$MC" --format '{{.RestartCount}}')}"
      if [ "$kind" = graceful ]; then   # running median of the measured command -> container-exit lag (VM clock)
        lags="$lags $("$PY" -c 'import json,sys;d=json.loads(sys.argv[1]);f=d.get("finished_at_ts");print("" if f is None else round(f-(d["t_fire_mac"]+d["vm_offset_s"]),3))' "$res" 2>/dev/null)"
        lag=$("$PY" -c 'import sys;x=sorted(float(v) for v in sys.argv[2:] if v);print(x[len(x)//2] if x else sys.argv[1])' "$lag" $lags)
      fi
      wsleep "$settle"
    done ;;
  A3_LOWKEY)
    KEYS=$(R "$F_DEL" "print(json.dumps([t['deleted_row']['state_id'] for t in d['trials'] if t.get('deleted_row')][:$(jq_ "$B" max)]))")
    e10_cmd "{\"op\": \"lowkey\", \"keys\": $KEYS, \"age_s\": $(jq_ "$B" age_s)}" 1800 >/dev/null ;;
  A7_WIPE)
    SECS=$(R "$F_CTX" "print(json.dumps([int(t['unlock_row']['ts']) for t in d['trials'] if t.get('unlock_row')][:$(jq_ "$B" n)]))")
    e10_cmd "{\"op\": \"wipe\", \"seconds\": $SECS, \"min_age_s\": $(jq_ "$B" min_age_s)}" 1800 >/dev/null ;;
  SNAP_*) snapshot_db "$(echo "$1" | tr 'A-Z' 'a-z')"; collect ;;
  A6_CS)
    local n i st mk t
    n=$("$PY" -c "import json,sys;print(len(json.loads(sys.argv[1])['steps']))" "$B")
    for i in $(seq 0 $((n-1))); do
      st=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['steps'][int(sys.argv[2])]['step_s'])" "$B" "$i")
      mk=$("$PY" -c "import json,sys;print(int(json.loads(sys.argv[1])['steps'][int(sys.argv[2])]['marker']))" "$B" "$i")
      t=$(( $(date -u +%s) + 150 ))
      [ "$mk" = "1" ] && issue_marker --kind CLOCK_STEP --window "$((t - ${st%.*}))" "$t" --not-before "$((t - 120))" \
        --deadline "$t" --note "E10 declared backward clock step $i ($st s)" --extra "{\"step\": $i}"
      e10_cmd "{\"op\": \"clock_step\", \"at\": $t, \"step_s\": $st, \"duration_s\": $(jq_ "$B" duration_s), \"step\": $i, \"marker\": $mk}" 900 >/dev/null
      wsleep "$(jq_ "$B" spacing_s)"
    done
    snapshot_db cs_end; collect ;;
  A5_PW)
    local ne S kd recent bg
    ne=$("$PY" -c "import json,sys;print(len(json.loads(sys.argv[1])['events']))" "$B"); kd=$(jq_ "$B" keep_days)
    for i in $(seq 0 $((ne-1))); do
      S=$(( $(date -u +%s) + 240 ))
      recent=$(R "$F_CTX" "ts=[t['unlock_row']['state_id'] for t in d['trials'] if t.get('unlock_row')];print(ts[-1-$i] if len(ts)>$i else '')")
      issue_marker --kind PURGE --scheduled-ts "$S" --keep-days "$kd" --deadline "$S" --not-before "$((S - 120))" --extra "{\"keep_days\": $kd, \"e10_event\": $i}" \
        || note "  PURGE marker for event $i not accepted by both anchors"
      snapshot_db "pw${i}_pre"
      VAR=$("$PY" -c "import json,sys;print(json.dumps(json.loads(sys.argv[1])['events'][int(sys.argv[2])]['variants']))" "$B" "$i")
      ( e10_cmd "{\"op\": \"pw\", \"scheduled_ts\": $S, \"keep_s\": $((kd * 86400)), \"tol_s\": $PURGE_TOL_S, \"variants\": $VAR, \"recent_state_id\": ${recent:-null}, \"event\": $i}" 1200 > "$SP/.pw_$i" ) &
      bg=$!
      wait_until "$S"
      docker exec "$BROKER" mosquitto_pub -h localhost -t "$PFX/ops/purge" -m "$kd" && ev forced_purge "\"stack\": \"$PFX\", \"event\": $i, \"scheduled_ts\": $S, \"published_ts\": $(date -u +%s), \"keep_days\": $kd"
      wait "$bg"
      wait_until "$((S + 240))"; snapshot_db "pw${i}_post"; collect
      wait_until "$((S + $(jq_ "$B" spacing_s) - 240))"
    done ;;
  A4_ULW) for h in $("$PY" -c "import json,sys;print(' '.join(str(x) for x in json.loads(sys.argv[1])['holds']))" "$B"); do
            e10_cmd "{\"op\": \"lock_write\", \"hold_s\": $h}" 900 >/dev/null; wsleep 60; done ;;
  A4_ULSHM|A4_ULSHM_OFD)
    local nh lst
    nh=$(jq_ "$B" holds)
    for i in $(seq 0 $((nh-1))); do
      lst=$(R "$F_CTX" "ts=[t['unlock_row']['state_id'] for t in d['trials'] if t.get('unlock_row')];print(ts[10+$i] if len(ts)>10+$i else '')")
      e10_cmd "$("$PY" -c "import json,sys;b=json.loads(sys.argv[1]);b['op']='lock_shm';b.pop('block');b.pop('holds');b['launder_state_id']=int(sys.argv[2]) if sys.argv[2] and sys.argv[3]=='A4_ULSHM' else None;b['blind_delete']=sys.argv[3]=='A4_ULSHM';b['hold_index']=int(sys.argv[4]);print(json.dumps(b))" "$B" "$lst" "$1" "$i")" 1200 >/dev/null
      wsleep 90
    done ;;
  A4_ULJM)
    F=$(e10_cmd '{"op": "journal_mode", "mode": "DELETE"}' 300)
    case "$(R "$F" "print(d.get('result'))")" in wal|None) ;; *) note "  the journal mode changed: restarting the hub (it sets WAL at start-up)"; hub_restart "journal mode restored" ;; esac ;;
  A4_INFT)
    local tb; if [ "${VM_FREE_KB:-0}" -ge $(( $(jq_ "$B" free_gb_for_large) * 1024 * 1024 )) ]; then tb=$(jq_ "$B" target_bytes_large); else tb=$(jq_ "$B" target_bytes_small); fi
    ev inft_size "\"target_bytes\": $tb, \"vm_free_kib\": ${VM_FREE_KB:-null}"
    e10_cmd "{\"op\": \"inflate_table\", \"target_bytes\": $tb}" 3600 >/dev/null
    wsleep "$(jq_ "$B" hold_s)"
    e10_cmd '{"op": "deflate_table"}' 600 >/dev/null
    docker exec "$BROKER" mosquitto_pub -h localhost -t "$PFX/ops/repack" -m 1 && ev repack "\"stack\": \"$PFX\", \"published_ts\": $(date -u +%s)"
    wsleep "$(jq_ "$B" repack_wait_s)" ;;
  A4_INFW)
    e10_cmd "{\"op\": \"inflate_window\", \"rows\": $(jq_ "$B" rows), \"rate\": $(jq_ "$B" rate)}" 7200 >/dev/null
    wsleep "$(jq_ "$B" observe_s)" ;;
  B1_ENTITY_ID_RENAME)
    local e n2 pred parts
    e=$(jq_ "$B" entity_id); n2=$(jq_ "$B" new_entity_id)
    pred=$(namemap_now "{\"op\": \"entity_id_rename\", \"entity_id\": \"$e\", \"new\": \"$n2\"}")
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B1_predicted\", \"namemap\": ${pred:-null}"
    parts=$("$PY" -c "import json,sys;p=json.loads(sys.argv[1]);print(json.dumps([{k:p['predicted']['parts'][k] for k in p['predicted']['changed_parts']}]))" "$pred")
    issue_marker --kind RENAME --parts "$parts" --note "E10 B1: entity id $e -> $n2" --extra "{\"entity_id\": [\"$e\", \"$n2\"]}"
    wsleep 30
    e10_cmd "{\"op\": \"rename_entity\", \"entity_id\": \"$e\", \"new_entity_id\": \"$n2\"}" 600 >/dev/null
    wsleep 120; snapshot_db b1_end; collect
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B1_after\", \"namemap\": $(namemap_now "" || echo null)" ;;
  B2_DEVICE_REMOVE)
    local e dev pred parts
    e=$(jq_ "$B" entity_id)
    local nm0                                  # one level of quoting (bash 3.2 brace bug: see bcmd)
    nm0=$(namemap_now '{"op": "device_remove", "device_id": "none"}')
    dev=$("$PY" -c "import json,sys;p=json.loads(sys.argv[1]);print(next((d for d,es in p['devices_of_entities'].items() if sys.argv[2] in es),''))" "$nm0" "$e")
    pred=$(namemap_now "{\"op\": \"device_remove\", \"device_id\": \"$dev\"}")
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B2_predicted\", \"device_id\": \"$dev\", \"namemap\": ${pred:-null}"
    parts=$("$PY" -c "import json,sys;p=json.loads(sys.argv[1]);print(json.dumps([{k:p['predicted']['parts'][k] for k in p['predicted']['changed_parts']}]))" "$pred")
    issue_marker --kind RENAME --parts "$parts" --note "E10 B2: device $dev removed (with $e)"
    wsleep 30
    e10_cmd "{\"op\": \"remove_device\", \"entity_id\": \"$e\", \"settle_s\": 60}" 900 >/dev/null
    wsleep 120; snapshot_db b2_end; collect
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B2_after\", \"namemap\": $(namemap_now "" || echo null)" ;;
  B3_PURGE_ENTITIES)
    [ "${HPR_E10_B3:-1}" = "1" ] || { note "  B3 skipped (HPR_E10_B3=0)"; return 0; }
    e10_cmd "{\"op\": \"purge_entities\", \"entity_ids\": $(jq_ "$B" entity_ids)}" 900 >/dev/null
    wsleep 60; snapshot_db b3_end; collect ;;
  B4_UPGRADE)
    uninstall_e10; wsleep 60
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B4_before\", \"namemap\": $(namemap_now "" || echo null)"
    snapshot_db b4_pre; collect
    "$STACK" upgrade "$PFX" "$(jq_ "$B" to_image)" > "$SP/$PFX/upgrade.json" 2>> "$META"
    ev upgrade "\"stack\": \"$PFX\", \"result\": $(cat "$SP/$PFX/upgrade.json" 2>/dev/null || echo null)"
    wsleep "$(jq_ "$B" observe_s)"
    ev namemap "\"stack\": \"$PFX\", \"label\": \"B4_after\", \"namemap\": $(namemap_now "" || echo null)"
    snapshot_db b4_post; collect ;;
  esac
  ev block_end "\"block\": \"$1\""
}

phase_main() {
  use_stack e10s 19982 19983
  ev phase_begin "\"phase\": \"main\""
  "$STACK" up-lab e10s > "$SP/e10s/stack.json" 2>> "$META" || exit 6
  ev stack_up "\"stack\": \"e10s\", \"info\": $(cat "$SP/e10s/stack.json")"
  wait_writing || { note "FAIL e10s hub not writing"; exit 6; }
  start_stack_monitoring
  install_e10
  F_INFO=$(e10_cmd '{"op": "info"}' 300); note "  info: $(cut -c1-400 "$SP/e10/$F_INFO")"
  snapshot_db start; T_S0=$(date -u +%s); echo "$T_S0" > "$SP/e10s/t_start"
  local b
  for b in $("$PY" -c "import json,sys;print(' '.join(x['block'] for x in json.load(open(sys.argv[1]))['blocks']))" "$SP/plan.json"); do
    block "$b"
  done
  date -u +%s > "$SP/e10s/t_end"
  freeze_stack; teardown_stack
  ev phase_end "\"phase\": \"main\""
}

[ "$PHASE" = "all" ] || [ "$PHASE" = "upgrade" ] && phase_upgrade
[ "$PHASE" = "all" ] || [ "$PHASE" = "main" ] && phase_main
cp "$EVLOG" "$OUT/${TAG}_events.jsonl"; cp "$SP/plan.json" "$OUT/${TAG}_plan.json"
note "scoring with exp/stages/e10_score.py"
"$PY" "$REPO/exp/stages/e10_score.py" --run-dir "$SP" --tag "$TAG" --out-dir "$OUT" > "$SP/score.log" 2>&1
note "score exit: $? ($(tail -20 "$SP/score.log" | tr '\n' ' ' | cut -c1-1200))"
if [ "$PHASE" = "all" ] || [ "$PHASE" = "main" ]; then   # review r5 arms S (sham) and R (restarts), same verifications
  "$PY" "$REPO/exp/stages/e10r5_score.py" --run-dir "$SP" --tag "$TAG" --out-dir "$OUT" >> "$SP/score.log" 2>&1 \
    || note "  WARN e10r5_score.py failed: see score.log"
fi
if [ "$PHASE" = "all" ] || [ "$PHASE" = "main" ]; then   # the pre-registered offline checks on E10's own chains (no Docker)
  for m in direct copy; do
    "$PY" "$REPO/exp/stages/e10_collusion.py" --run-dir "$SP" --tag "$TAG" --out-dir "$OUT" --monitor "$m" >> "$SP/score.log" 2>&1 \
      || note "  WARN e10_collusion.py ($m) failed: see score.log"
  done
  "$PY" "$REPO/exp/stages/e10_migration_offline.py" --run-dir "$SP" --stack e10s --snapshot final --monitor direct \
    --out "$OUT/${TAG}_migration_offline.json" >> "$SP/score.log" 2>&1 || note "  WARN e10_migration_offline.py failed: see score.log"
fi
note "done; results under $OUT/${TAG}_* and $SP"
