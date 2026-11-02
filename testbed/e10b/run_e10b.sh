#!/bin/bash
# E10b: E10's A1-BDT arm (H1) re-run with the trials 50 s apart (no two forged rows share a one-second segment or lie
# in neighbouring ones) and scored from each trial's own row, plus H10's clock-step arm with the hub's state rows stepped
# too (homeprov_e10b op clock_step_all). drafts/round13/E10B_DESIGN.md; pre-registration exp/out/e10b_preregistration.json.
#
# One scratch stack e10bs, built exactly as E10's main stack (testbed/e10/e10_stack.sh up-lab, unchanged: a copy of the
# lab configuration read once read-only, E9's final recorder snapshot, Home Assistant 2026.7.4), the same two monitors
# (direct read, copy mode), linked anchors, head witnesses outside Docker's VM and E10's monitor settings, the in-hub
# harness homeprov_e10 (frozen with E10) plus the add-on homeprov_e10b. Blocks (testbed/e10b/e10b_plan.py): A1_BDT,
# SNAP_BDT, A6_CS2, SNAP_CS_END; then the final snapshot, the freeze and testbed/e10b/e10b_score.py.
#
#   Real run (the registration registered and stamped; after the other project's run has ended):
#       nohup testbed/e10b/run_e10b.sh e10b_main > /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_main.out 2>&1 &
#   Smoke (compressed plan: 2 trials per level, 2 clock steps; outputs outside exp/out; not results):
#       HPR_E10B_SMOKE=1 nohup testbed/e10b/run_e10b.sh e10b_smoke1 > /Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e10b/e10b_smoke1.out 2>&1 &
#
# Lessons of the E10 and E11 smokes encoded here: the whole script is one function read before it runs (editing this
# file while it runs cannot change the running copy); stdin is /dev/null for every command (no tool can stop at a
# prompt, e.g. macOS patch asking whether to reverse an applied patch); the host interpreter is pinned and must pass
# e10ops.py pyguard; one JSON object per event line (ev guard); harness commands are built with single-quoted Python
# (bash 3.2 brace-expands "{a,b}" inside a double-quoted string nested in a quoted command substitution); a tag must be
# e10b_main or e10b_smokeN, and no file of exp/out or of the output directory may start with it; no output and no run
# directory is ever overwritten.
main() {
set -u
exec </dev/null
export PATH="<home>/miniconda3/bin:$PATH"
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
BASE=/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex
X=$BASE/e10b
TAG=${1:-}
SMOKE=${HPR_E10B_SMOKE:-0}
PY=${HPR_E10B_PY:-<home>/miniconda3/bin/python3}
OPS="$REPO/testbed/e10/e10ops.py"
STACK="$REPO/testbed/e10/e10_stack.sh"
PLANPY="$REPO/testbed/e10b/e10b_plan.py"
SCORE="$REPO/testbed/e10b/e10b_score.py"
PREREG="$REPO/testbed/e10b/e10b_prereg.py"
REG="$REPO/exp/out/e10b_preregistration.json"
CC=$REPO/testbed/real/ha-config/custom_components
ADDON=$REPO/testbed/e10b/homeprov_e10b
SEED=${HPR_E10B_SEED:-20261024}                       # pre-registered
MON_IMG=${HPR_E10B_MONITOR_IMAGE:-hpr-monitor:e10b}
ANC_IMG=${HPR_E10B_ANCHOR_IMAGE:-hpr-anchord:e10b}
PERIOD=5; QC_DIRECT=720; QC_COPY=1                    # as E10 (pre-registered)
RESTART_WAIT=45
SEAL_WAIT_MAX_S=5400; SEAL_SETTLE_POLLS=6
HA_LAB=homeassistant/home-assistant:2026.7.4
PFX_STACK=e10bs; WPORT_DIRECT=19986; WPORT_COPY=19987
MON_ENV_COMMON="HOMEPROV_SCHEME=stable HOMEPROV_COVERAGE=1 HOMEPROV_KEYLOG=1 HOMEPROV_ROWBIND=1 HOMEPROV_SINCE=0 HOMEPROV_KEYLOG_REWIND=1"

# ---- refusals (cheap ones first: nothing is created and Docker is not touched until all pass) --------------------
case "$TAG" in
  e10b_main) [ "$SMOKE" = "0" ] || { echo "REFUSING: e10b_main is the real run (HPR_E10B_SMOKE must be 0)"; exit 2; } ;;
  e10b_smoke[0-9]|e10b_smoke[0-9][0-9]) [ "$SMOKE" = "1" ] || { echo "REFUSING: a smoke tag needs HPR_E10B_SMOKE=1"; exit 2; } ;;
  *) echo "usage: [HPR_E10B_SMOKE=1] run_e10b.sh e10b_main|e10b_smokeN"; exit 2 ;;
esac
if [ "$SMOKE" = "1" ]; then OUT=${HPR_E10B_OUT:-$X/smoke_out}; else OUT=$REPO/exp/out; fi
SP=${HPR_E10B_SP:-$X/$TAG}
[ -e "$SP" ] && { echo "REFUSING: $SP exists"; exit 3; }
for f in "$OUT/${TAG}_"* "$OUT/${TAG}."*; do [ -e "$f" ] && { echo "REFUSING: outputs $OUT/${TAG}_* exist ($f)"; exit 3; }; done
for f in "$REPO/exp/out/${TAG}_"* "$REPO/exp/out/${TAG}."*; do [ -e "$f" ] && { echo "REFUSING: $f exists (tag collision in exp/out)"; exit 3; }; done
# the unit tests stop here (HPR_E10B_REFUSALS_ONLY=1): nothing above creates a file or calls Docker
[ "${HPR_E10B_REFUSALS_ONLY:-0}" = "1" ] && { echo "refusals passed (HPR_E10B_REFUSALS_ONLY)"; exit 0; }
[ -d "$BASE" ] || { echo "REFUSING: the external SSD ($BASE) is not mounted"; exit 2; }
[ "$(date -u +%s)" -lt "${HPR_E10B_NOT_BEFORE:-0}" ] && { echo "REFUSING: before HPR_E10B_NOT_BEFORE=${HPR_E10B_NOT_BEFORE}"; exit 2; }
HM=$((10#$(date -u +%H%M)))                           # the scratch hub's own recorder purge runs at 04:12 UTC
{ [ "$HM" -ge 450 ] && [ "$HM" -le 2330 ]; } || { echo "REFUSING: start between 04:50 and 23:30 UTC (the hub's 04:12 purge must not fall in the session)"; exit 2; }
BUSY="testbed/e9/run_e9.sh|testbed/e10/run_e10.sh|testbed/e10/run_e10_r5.sh|testbed/e11/run_e11.sh|run_e12"
[ -n "${HPR_E10B_BUSY_PATTERN:-}" ] && BUSY="$BUSY|$HPR_E10B_BUSY_PATTERN"
pgrep -fl -- "$BUSY" >/dev/null 2>&1 && { echo "REFUSING: another experiment runs: $(pgrep -fl -- "$BUSY" | head -3 | tr '\n' ';')"; exit 2; }
# another run_e10b.sh: a process whose command line names this script, other than this shell and its descendants
# (forked subshells carry the same command line until they exec)
OTHERS=$(ps -axo pid=,ppid=,command= | awk -v me=$$ '{pid[NR]=$1; pp[NR]=$2; m[NR]=($0 ~ /run_e10b[.]sh/)} END {d[me]=1; ch=1; while (ch) {ch=0; for (i=1;i<=NR;i++) if ((pp[i] in d) && !(pid[i] in d)) {d[pid[i]]=1; ch=1}} for (i=1;i<=NR;i++) if (m[i] && !(pid[i] in d)) print pid[i]}')
[ -n "$OTHERS" ] && { echo "REFUSING: another run_e10b.sh runs (pid $OTHERS)"; exit 2; }
G=$("$PY" "$OPS" pyguard 2>&1 | tail -1)
case "$G" in *'"ok": true'*) ;; *) echo "REFUSING: interpreter guard failed (pinned $PY required, never /usr/bin/python3): $G"; exit 4 ;; esac
for p in e10bs e10s e10u; do docker ps -a --format '{{.Names}}' | grep -q "^$p-" && { echo "REFUSING: $p-* containers exist"; exit 3; }; done
docker volume ls --format '{{.Name}}' | grep -q "^e10bs-" && { echo "REFUSING: e10bs-* volumes exist"; exit 3; }

mkdir -p "$SP/keys" "$SP/code" "$SP/snapshots" "$SP/e10" "$OUT"
META=$SP/auth_meta.log; EVLOG=$SP/events.jsonl
: > "$META"; : > "$EVLOG"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META" >&2; }
# ev TYPE FIELDS: one JSON object per line (E10 guard of 2026-10-19: a payload that does not parse is kept as a string)
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
jq_() { "$PY" -c "import json,sys;d=json.loads(sys.argv[1]);v=d.get(sys.argv[2]);print(json.dumps(v) if isinstance(v,(dict,list)) else ('' if v is None else v))" "$1" "$2"; }
# bcmd OP KEY...: {"op": OP, KEY: block[KEY], ...} from the block JSON in $B (single-quoted Python: see the header)
bcmd() { "$PY" -c 'import json,sys;b=json.loads(sys.argv[1]);d={"op":sys.argv[2]};d.update({k:b[k] for k in sys.argv[3:]});print(json.dumps(d))' "$B" "$@"; }
out_new() { [ -e "$1" ] && { note "REFUSING to overwrite $1"; return 1; }; return 0; }
note "tag=$TAG smoke=$SMOKE seed=$SEED python=$G sp=$SP out=$OUT"
caffeinate -i -s -m -w $$ & CAFF_PID=$!

# ---- preflight ---------------------------------------------------------------------------------------------------
"$PY" "$REPO/testbed/e10/e10_prereg.py" --check "$REPO/exp/out/e10_preregistration.json" >> "$META" 2>&1 \
  || { note "FAIL a file frozen by E10's registration changed (monitor, verifier, stack, harness)"; exit 2; }
note "ok    every file frozen by E10's registration at its registered sha256"
if [ "$SMOKE" != "1" ]; then
  "$PY" "$PREREG" --check "$REG" >> "$META" 2>&1 \
    || { note "FAIL the E10b registration is missing, not registered, or a file it froze changed"; exit 2; }
  note "ok    E10b registration registered and every frozen file at its registered sha256"
fi
if [ "${HPR_E10B_RUN_TESTS:-1}" = "1" ]; then
  for t in monitor testbed/anchord testbed/e10/test_e10_patches.py testbed/e10b/test_e10b.py; do
    ( cd "$REPO" && "$PY" -m pytest -q -p no:cacheprovider "$t" ) > "$SP/pytest_$(basename $t).log" 2>&1 \
      || { note "FAIL tests $t ($(tail -2 "$SP/pytest_$(basename $t).log" | tr '\n' ' '))"; exit 2; }
    note "ok    tests $t: $(tail -1 "$SP/pytest_$(basename $t).log")"
  done
fi
docker build -q -f "$REPO/monitor/Dockerfile.sign" -t "$MON_IMG" "$REPO/monitor" >/dev/null || { note "FAIL build $MON_IMG"; exit 2; }
docker build -q -f "$REPO/testbed/e8/anchord-e8.Dockerfile" -t "$ANC_IMG" "$REPO/testbed/anchord" >/dev/null || { note "FAIL build $ANC_IMG"; exit 2; }
for f in "monitor/monitor.py|$MON_IMG|/app/monitor.py" "testbed/anchord/anchord.py|$ANC_IMG|/app/anchord.py" \
         "testbed/anchord/anchord_linked.py|$ANC_IMG|/app/anchord_linked.py"; do
  rp=${f%%|*}; img=$(echo "$f" | cut -d'|' -f2); ip=${f##*|}
  repo_h=$(shasum -a 256 "$REPO/$rp" | cut -d' ' -f1)
  img_h=$(docker run --rm --entrypoint sha256sum "$img" "$ip" | cut -d' ' -f1)
  [ "$repo_h" = "$img_h" ] || { note "FAIL $img:$ip $img_h != $rp $repo_h"; exit 2; }
  note "ok    $img:$ip = $rp (${repo_h:0:16})"
done
for img in "$HA_LAB" eclipse-mosquitto:2 hpr-devices:1 alpine:3; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null || { note "FAIL image $img"; exit 2; }
  note "image $img $(docker image inspect "$img" --format '{{.Id}} {{index .RepoDigests 0}}' 2>/dev/null)"
done
VM_FREE_KB=$(docker run --rm alpine:3 df -k / | awk 'NR==2{print $4}')
ev preflight "\"vm_free_kib\": ${VM_FREE_KB:-null}, \"hpr_running\": $(docker ps --format '{{.Names}}' | grep -c '^hpr-'), \"load\": \"$(sysctl -n vm.loadavg | tr -d '{}')\""

if [ "$SMOKE" = "1" ]; then "$PY" "$PLANPY" plan --seed "$SEED" --smoke > "$SP/plan.json" || { note "FAIL plan"; exit 2; }
else "$PY" "$PLANPY" plan --seed "$SEED" > "$SP/plan.json" || { note "FAIL plan"; exit 2; }
  want=$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["plan"]["sha256"])' "$REG")
  [ "$(shasum -a 256 "$SP/plan.json" | cut -d' ' -f1)" = "$want" ] || { note "FAIL the plan is not the registered plan"; exit 2; }
fi
cp "$OPS" "$STACK" "$PLANPY" "$SCORE" "$REPO/testbed/anchord/headwitness.py" "$REPO/testbed/anchord/chainverify.py" "$SP/code/"
cp "$REPO/testbed/e10b/run_e10b.sh" "$SP/code/"; cp -R "$ADDON" "$SP/code/homeprov_e10b"
note "plan: $(s16 "$SP/plan.json") seed=$SEED; sha256_16: monitor.py=$(s16 $REPO/monitor/monitor.py) e7_verify.py=$(s16 $REPO/exp/stages/e7_verify.py) homeprov_e10=$(s16 $CC/homeprov_e10/__init__.py) homeprov_e10b=$(s16 $ADDON/__init__.py) run_e10b.sh=$(s16 $REPO/testbed/e10b/run_e10b.sh)"

# ---- the stack (as run_e10.sh) -----------------------------------------------------------------------------------
PFX=$PFX_STACK; HUB=$PFX-hass; NET=$PFX-net; CFGVOL=$PFX-config; BROKER=$PFX-broker
V=$PFX-$TAG; AD=$PFX-anchord-direct; MD=$PFX-monitor-direct; AC=$PFX-anchord-copy; MC=$PFX-monitor-copy; WNET=$PFX-$TAG-wnet
WPID_D=""; WPID_C=""; HOSTLOG_PID=""; STACK_UP=0
mkdir -p "$SP/$PFX/escrow_direct" "$SP/$PFX/escrow_copy" "$SP/$PFX/witness_direct" "$SP/$PFX/witness_copy" "$SP/$PFX/snapshots"
witness_get() { "$PY" -c 'import sys,urllib.request;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())' "http://127.0.0.1:$1$2" 2>/dev/null; }

keys_and_operator() {   # fresh keys; only fingerprints recorded
  KEY_D=$(openssl rand -hex 32); KEY_C=$(openssl rand -hex 32); OKEY_D=$(openssl rand -hex 32); OKEY_C=$(openssl rand -hex 32)
  WKEY_D=$(openssl rand -hex 32); WKEY_C=$(openssl rand -hex 32)
  note "$PFX: append_key_fp direct=$(fp16 "$KEY_D") copy=$(fp16 "$KEY_C"); operator_key_fp direct=$(fp16 "$OKEY_D") copy=$(fp16 "$OKEY_C"); witness_key_fp direct=$(fp16 "$WKEY_D") copy=$(fp16 "$WKEY_C") (keys not recorded)"
  docker volume create "$V-operator" >/dev/null
  printf '%s' "$OKEY_D" | docker run -i --rm -v "$V-operator":/op alpine:3 sh -c 'umask 077; cat > /op/direct.key'
  printf '%s' "$OKEY_C" | docker run -i --rm -v "$V-operator":/op alpine:3 sh -c 'umask 077; cat > /op/copy.key'
  local fp m
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
    if [ $m = direct ]; then p=$WPORT_DIRECT; k=$WKEY_D; else p=$WPORT_COPY; k=$WKEY_C; fi
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
    if [ $m = direct ]; then a=$AD; alias=anchor-direct; k=$KEY_D; o=$OKEY_D; w=$WKEY_D; p=$WPORT_DIRECT
    else a=$AC; alias=anchor-copy; k=$KEY_C; o=$OKEY_C; w=$WKEY_C; p=$WPORT_COPY; fi
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

start_monitor() {   # $1 direct|copy (E10's settings)
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

wait_sealed() {   # $1 monitor, $2 anchor: the full-history seal anchored and SEAL_SETTLE_POLLS polls past it
  local end=$(( $(date -u +%s) + SEAL_WAIT_MAX_S )) t0 st
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

hub_writing() {
  local lag
  lag=$(docker run --rm -v "$CFGVOL":/cfg:ro --entrypoint python "$MON_IMG" -c "import sqlite3,time;c=sqlite3.connect('file:/cfg/home-assistant_v2.db?mode=ro&readonly_shm=1',uri=True,timeout=30);print(int(time.time()-c.execute('select max(last_updated_ts) from states').fetchone()[0]))" 2>/dev/null | tail -1)
  [ -n "$lag" ] && [ "$lag" -lt 60 ] 2>/dev/null
}
wait_writing() { local i; for i in $(seq 1 60); do hub_writing && return 0; sleep 10; done; return 1; }

snapshot_db() {   # $1 label: SQLite's online backup API from a read-only connection OUTSIDE the hub (as E9, E10)
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

issue_marker() {   # e10ops issue CLOCK_STEP to both anchors of this stack (as run_e10.sh)
  local res
  res=$(docker run --rm --network "$NET" -v "$V-operator":/op:ro -v "$REPO/exp/rig":/rig:ro -v "$REPO/testbed/e9":/e9:ro \
          -v "$REPO/testbed/e10":/e10:ro -e E10_E9OPS=/e9/e9ops.py --entrypoint python "$MON_IMG" /e10/e10ops.py issue \
          --issuer /rig/marker_issuer.py --sign-key /op/operator.pem --anchors anchor-direct=/op/direct.key \
          anchor-copy=/op/copy.key "$@" 2>&1 | tail -1)
  case "$res" in "{"*) ev marker "\"stack\": \"$PFX\", \"result\": $res" ;; *) ev marker "\"stack\": \"$PFX\", \"error\": $(printf '%s' "$res" | "$PY" -c 'import json,sys;print(json.dumps(sys.stdin.read()[-400:]))')" ;; esac
  note "  marker [$*]: $(printf '%s' "$res" | cut -c1-200)"
  printf '%s' "$res" | grep -q '"all_ok": true'
}

E10N=0
e10_cmd() {   # $1 JSON body, $2 timeout s -> prints the result's file name; the result is copied to $SP/e10/
  E10N=$((E10N+1)); local id="b$(printf %03d $E10N)$(openssl rand -hex 3)" a end f
  "$PY" -c "import json,sys;d=json.loads(sys.argv[1]);d['id']=sys.argv[2];print(json.dumps(d))" "$1" "$id" > "$SP/.e10cmd"
  docker exec "$HUB" rm -f /config/homeprov_e10.ack
  docker cp "$SP/.e10cmd" "$HUB:/config/homeprov_e10.cmd" >/dev/null
  ev e10_cmd "\"id\": \"$id\", \"command\": $(cat "$SP/.e10cmd")"
  end=$(( $(date -u +%s) + ${2:-3600} ))
  while [ "$(date -u +%s)" -lt "$end" ]; do
    a=$(docker exec "$HUB" cat /config/homeprov_e10.ack 2>/dev/null)
    case "$a" in *"\"id\": \"$id\""*)
      f=$(jq_ "$a" file)
      docker cp "$HUB:/config/homeprov_out/e10/$f" "$SP/e10/$f" >/dev/null 2>&1
      ev e10_result "\"id\": \"$id\", \"ack\": $a, \"sha256\": \"$(shasum -a 256 "$SP/e10/$f" 2>/dev/null | cut -d' ' -f1)\""
      note "  e10 $id: $(printf '%s' "$a" | cut -c1-160)"; printf '%s' "$f"; return 0 ;;
    esac
    sleep 2
  done
  ev e10_result "\"id\": \"$id\", \"timeout\": true"; note "  e10 $id TIMEOUT"; return 1
}

hub_restart() { local b; b=$(docker inspect "$HUB" --format '{{.State.StartedAt}}'); docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"; ev hub_restart "\"stack\": \"$PFX\", \"cause\": \"$1\", \"started_before\": \"$b\", \"started_at\": \"$(docker inspect "$HUB" --format '{{.State.StartedAt}}')\""; }

collect() {
  local m a c
  for m in direct copy; do
    if [ $m = direct ]; then a=$AD; c=$MD; else a=$AC; c=$MC; fi
    docker exec "$a" cat /anchor/chain.jsonl > "$SP/$PFX/${m}_chain.jsonl" 2>/dev/null
    docker exec "$a" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/$PFX/${m}_refusals.jsonl"
    docker cp "$c:/scratch/cost.jsonl" "$SP/$PFX/${m}_cost.jsonl" >/dev/null 2>&1
  done
}

restarts_json() { printf '{"direct": %s, "copy": %s, "hub_started_at": "%s"}' "$(docker inspect "$MD" --format '{{.RestartCount}}' 2>/dev/null || echo null)" "$(docker inspect "$MC" --format '{{.RestartCount}}' 2>/dev/null || echo null)" "$(docker inspect "$HUB" --format '{{.State.StartedAt}}' 2>/dev/null)"; }

freeze_stack() {
  local m a c p
  note "$PFX: settling 90 s"; wsleep 90
  for c in $MD $MC; do ev monitor_memory_peak "\"monitor\": \"$c\", \"bytes\": $(docker exec "$c" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo null), \"restarts\": $(docker inspect "$c" --format '{{.RestartCount}}')"; done
  snapshot_db final; wsleep 30
  docker stop "$MD" "$MC" >/dev/null 2>&1; wsleep 8
  : > "$SP/$PFX/.hostlog_stop"
  for m in direct copy; do
    if [ $m = direct ]; then a=$AD; c=$MD; p=$WPORT_DIRECT; else a=$AC; c=$MC; p=$WPORT_COPY; fi
    witness_get $p /head > "$SP/$PFX/witness_$m/head_final.json"
    docker exec "$a" cat /anchor/chain.jsonl > "$SP/$PFX/${m}_chain.jsonl"
    docker exec "$a" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/$PFX/${m}_refusals.jsonl"
    docker cp "$c:/scratch/cost.jsonl" "$SP/$PFX/${m}_cost.jsonl" >/dev/null 2>&1
    docker logs "$c" > "$SP/$PFX/${m}_monitor.log" 2>&1; docker logs "$a" > "$SP/$PFX/${m}_anchord.log" 2>&1
    out_new "$OUT/${TAG}_${PFX}_${m}_chain.jsonl.gz" && gzip -c "$SP/$PFX/${m}_chain.jsonl" > "$OUT/${TAG}_${PFX}_${m}_chain.jsonl.gz"
    out_new "$OUT/${TAG}_${PFX}_${m}_witness_heads.jsonl.gz" && gzip -c "$SP/$PFX/witness_$m/heads.jsonl" > "$OUT/${TAG}_${PFX}_${m}_witness_heads.jsonl.gz"
  done
  kill "$WPID_D" "$WPID_C" 2>/dev/null; WPID_D=""; WPID_C=""
  docker logs "$HUB" > "$SP/$PFX/hub.log" 2>&1
}

teardown_stack() {
  [ "$STACK_UP" = "1" ] || return 0
  [ -n "$HOSTLOG_PID" ] && { : > "$SP/$PFX/.hostlog_stop"; sleep 2; kill "$HOSTLOG_PID" 2>/dev/null; HOSTLOG_PID=""; }
  [ -n "$WPID_D" ] && kill "$WPID_D" 2>/dev/null; [ -n "$WPID_C" ] && kill "$WPID_C" 2>/dev/null
  docker rm -f "$MD" "$MC" "$AD" "$AC" >/dev/null 2>&1
  docker volume rm "$V-direct-sign" "$V-copy-sign" "$V-operator" >/dev/null 2>&1 && note "$PFX: signing-key and operator volumes destroyed"
  for v in "$V-direct-chain" "$V-direct-pub" "$V-direct-scratch" "$V-copy-chain" "$V-copy-pub" "$V-copy-scratch"; do docker volume rm "$v" >/dev/null 2>&1; done
  docker network rm "$WNET" >/dev/null 2>&1
  "$STACK" down "$PFX" >> "$META" 2>&1
  STACK_UP=0
}
on_exit() { note "exit: tearing down"; teardown_stack; note "hpr-* running at exit: $(docker ps --format '{{.Names}}' | grep -c '^hpr-')"; kill "$CAFF_PID" 2>/dev/null; }
trap on_exit EXIT
trap 'exit 130' INT TERM HUP
PLAN() { "$PY" -c "import json,sys;p=json.load(open(sys.argv[1]));print(json.dumps(next((b for b in p['blocks'] if b['block']==sys.argv[2]),None)))" "$SP/plan.json" "$1"; }

install_e10b() {   # homeprov_ec and homeprov_e7 as import dependencies only; homeprov_e10 and homeprov_e10b listed
  local src comp i hc
  for src in "$CC/homeprov_ec" "$CC/homeprov_e7" "$CC/homeprov_e10" "$ADDON"; do
    comp=$(basename "$src")
    docker exec "$HUB" mkdir -p "/config/custom_components/$comp"
    docker cp "$src/." "$HUB:/config/custom_components/$comp/" >/dev/null
    docker exec "$HUB" rm -rf "/config/custom_components/$comp/__pycache__"
  done
  docker exec "$HUB" sh -c 'grep -q "^homeprov_e10:" /config/configuration.yaml || printf "\nhomeprov_e10:\n" >> /config/configuration.yaml'
  docker exec "$HUB" sh -c 'grep -q "^homeprov_e10b:" /config/configuration.yaml || printf "\nhomeprov_e10b:\n" >> /config/configuration.yaml'
  docker exec "$HUB" rm -f /config/homeprov_out/e10/ready.json /config/homeprov_out/e10/e10b_ready.json
  hub_restart "activate homeprov_e10 and homeprov_e10b"
  for i in $(seq 1 60); do docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json && break; sleep 5; done
  docker exec "$HUB" test -f /config/homeprov_out/e10/ready.json || { note "FAIL homeprov_e10 not ready"; exit 6; }
  E10B_READY=$(docker exec "$HUB" cat /config/homeprov_out/e10/e10b_ready.json 2>/dev/null)
  case "$E10B_READY" in *'"clock_step_all"'*) ;; *) note "FAIL homeprov_e10b did not register clock_step_all ($E10B_READY)"; exit 6 ;; esac
  # hc is assigned on its own line (no command substitution nested in a quoted string)
  hc=$(docker exec "$HUB" sh -c 'sha256sum /config/custom_components/homeprov_e10/__init__.py /config/custom_components/homeprov_e10b/__init__.py /config/custom_components/homeprov_ec/__init__.py /config/custom_components/homeprov_scenario/__init__.py' 2>/dev/null | awk '{printf "%s=%s ", $2, substr($1,1,16)}')
  ev e10_installed "\"homeprov_e10_sha256\": \"$(shasum -a 256 "$CC/homeprov_e10/__init__.py" | cut -d' ' -f1)\", \"homeprov_e10b_sha256\": \"$(shasum -a 256 "$ADDON/__init__.py" | cut -d' ' -f1)\", \"hub_copies\": \"$hc\", \"e10b_ready\": $E10B_READY"
}

block() {   # $1 block name
  local B; B=$(PLAN "$1")
  [ "$B" = "null" ] && return 0
  ev block_begin "\"block\": \"$1\", \"plan\": $B, \"restarts\": $(restarts_json)"; note "== block $1"
  case "$1" in
  A1_BDT)   # every backdated target (ages up to 45 s) after the session start t0 (E10 fix of 2026-10-20)
    local to
    wsleep "$(jq_ "$B" pre_wait_s)"
    to=$("$PY" -c "import json,sys;b=json.loads(sys.argv[1]);print(int(len(b['ages'])*float(b['spacing_s'])+1800))" "$B")
    F_BDT=$(e10_cmd "$(bcmd bdt ages spacing_s)" "$to") || note "  A1_BDT did not complete: the run is incomplete" ;;
  SNAP_*) snapshot_db "$(echo "$1" | tr 'A-Z' 'a-z')"; collect ;;
  A6_CS2)
    [ "${HPR_E10B_CS2:-1}" = "1" ] || { note "  A6_CS2 skipped (HPR_E10B_CS2=0)"; ev block_end "\"block\": \"$1\", \"skipped\": true"; return 0; }
    local n i st mk t
    n=$("$PY" -c "import json,sys;print(len(json.loads(sys.argv[1])['steps']))" "$B")
    for i in $(seq 0 $((n-1))); do
      st=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['steps'][int(sys.argv[2])]['step_s'])" "$B" "$i")
      mk=$("$PY" -c "import json,sys;print(int(json.loads(sys.argv[1])['steps'][int(sys.argv[2])]['marker']))" "$B" "$i")
      t=$(( $(date -u +%s) + 150 ))
      [ "$mk" = "1" ] && issue_marker --kind CLOCK_STEP --window "$((t - ${st%.*}))" "$t" --not-before "$((t - 120))" \
        --deadline "$t" --note "E10b declared backward clock step $i ($st s)" --extra "{\"step\": $i}"
      e10_cmd "{\"op\": \"clock_step_all\", \"at\": $t, \"step_s\": $st, \"duration_s\": $(jq_ "$B" duration_s), \"step\": $i, \"marker\": $mk}" 900 >/dev/null
      wsleep "$(jq_ "$B" spacing_s)"
    done ;;
  esac
  ev block_end "\"block\": \"$1\", \"restarts\": $(restarts_json)"
}

# ---- the session --------------------------------------------------------------------------------------------------
ev phase_begin "\"phase\": \"main\""
STACK_UP=1                                     # from here on, the exit trap tears the stack down (also a partial one)
"$STACK" up-lab "$PFX" > "$SP/$PFX/stack.json" 2>> "$META" || exit 6
ev stack_up "\"stack\": \"$PFX\", \"info\": $(cat "$SP/$PFX/stack.json")"
wait_writing || { note "FAIL $PFX hub not writing"; exit 6; }
keys_and_operator; start_witnesses; start_anchors
nohup "$PY" -u "$OPS" hostlog --out "$SP/$PFX/hostlog.jsonl" --hub "$HUB" --monitors "$MD" "$MC" --vm-probe "$AC" \
  --stop-file "$SP/$PFX/.hostlog_stop" > "$SP/$PFX/hostlog.out" 2>&1 &
HOSTLOG_PID=$!
start_monitor direct; wait_sealed "$MD" "$AD" || exit 8
start_monitor copy; wait_sealed "$MC" "$AC" || exit 8
install_e10b
F_INFO=$(e10_cmd '{"op": "info"}' 300); note "  info: $(cut -c1-400 "$SP/e10/$F_INFO")"
snapshot_db start; date -u +%s > "$SP/$PFX/t_start"
for b in $("$PY" -c "import json,sys;print(' '.join(x['block'] for x in json.load(open(sys.argv[1]))['blocks']))" "$SP/plan.json"); do
  block "$b"
done
date -u +%s > "$SP/$PFX/t_end"
freeze_stack; teardown_stack
ev phase_end "\"phase\": \"main\""
out_new "$OUT/${TAG}_events.jsonl" && cp "$EVLOG" "$OUT/${TAG}_events.jsonl"
out_new "$OUT/${TAG}_plan.json" && cp "$SP/plan.json" "$OUT/${TAG}_plan.json"
note "scoring with testbed/e10b/e10b_score.py"
"$PY" "$SCORE" --run-dir "$SP" --tag "$TAG" --out-dir "$OUT" > "$SP/score.log" 2>&1
note "score exit: $? ($(tail -12 "$SP/score.log" | tr '\n' ' ' | cut -c1-1000))"
note "done; results under $OUT/${TAG}_* and $SP"
}
main "$@"; exit $?
