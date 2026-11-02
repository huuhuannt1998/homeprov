#!/bin/bash
# E11 (round 15, RQ4): does HOMEPROV's principle carry to a third hub family? openHAB 5.2.3 in Docker
# (drafts/round13/E11_DESIGN.md; pre-registration exp/out/e11_preregistration.json).
#
#   phase build    the two OSGi bundles (testbed/e11/build_bundles.sh) and the monitor and anchor images (hpr-monitor:e11
#                  from monitor/Dockerfile.sign, hpr-anchord:e11 from testbed/e8/anchord-e8.Dockerfile), in-image hashes
#   phase closure  E11-CLO on a closure instance (stack e11c): per-field mutation of the stored history and the item
#                  registry, the rendered history re-read after each (REST, both accounts); the in-place probe
#   phase main     E11-DET on the run stack (stack e11s): the shipped monitor.py with the openHAB reader
#                  (testbed/e11/monitor/oh_monitor.py), a linked anchor and a head witness outside Docker's VM, the
#                  benign household, the instrument arms A-BD / A-RM / A-CHG, the benign operations, two untouched
#                  windows, the final consistent snapshot, scoring (exp/stages/e11_score.py)
#
#   Real run (after E10 is scored, the pre-registration registered and stamped):
#       HPR_E11_SP=/Volumes/ResearchSSD/HOMEPROV-P13-exp.noindex/e11/e11_main \
#         taskpolicy -b nohup testbed/e11/run_e11.sh e11_main all > <research-dir>/HOMEPROV-P13-exp/e11/e11_main.out 2>&1 &
#       (tag e11_main, not e11: the refusal on existing $OUT/${TAG}_* outputs would match e11_preregistration.json)
#   Smoke (compressed plan, prefixes e11cs/e11ss, outputs outside exp/out):
#       HPR_E11_SMOKE=1 taskpolicy -b nohup testbed/e11/run_e11.sh e11_smoke1 all > .../e11/smoke/e11_smoke1.out 2>&1 &
# The host interpreter is PINNED (E9 amendment 3, as E10): PATH starts with <home>/miniconda3/bin and the
# preflight refuses unless `e11ops.py pyguard` passes (that exact interpreter, Python 3.12 or later, a WAL-mode copy
# opened read-only); /usr/bin/python3 is refused. Never touches hpr-*, e2-*, e9*, e10*, dz-*; never overwrites an output.
set -u
export PATH="<home>/miniconda3/bin:$PATH"
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
E11=$REPO/testbed/e11
X="<research-dir>/HOMEPROV-P13-exp/e11"
TAG=${1:?usage: run_e11.sh TAG [all|build|closure|main]}
PHASE=${2:-all}
SMOKE=${HPR_E11_SMOKE:-0}
PY=${HPR_E11_PY:-<home>/miniconda3/bin/python3}
OPS="$E11/e11ops.py"; STACK="$E11/e11_stack.sh"
SEED=${HPR_E11_SEED:-20261021}
if [ "$SMOKE" = "1" ]; then OUT=${HPR_E11_OUT:-$X/smoke/out}; PC=e11cs; PS=e11ss; else OUT=${HPR_E11_OUT:-$REPO/exp/out}; PC=e11c; PS=e11s; fi
SP=${HPR_E11_SP:-$X/$TAG}
MON_IMG=${HPR_E11_MONITOR_IMAGE:-hpr-monitor:e11}
ANC_IMG=${HPR_E11_ANCHOR_IMAGE:-hpr-anchord:e11}
export E11_PROBE_IMAGE=$MON_IMG
OH_IMG=${E11_OH_IMAGE:-openhab/openhab:5.2.3@sha256:fa50a6934dfd5bcbf21db18af66f2558f58c6c493ba23bdeb7a894e764507a99}
WPORT=19986; TPORT_C=18580; TPORT_S=18581; PERIOD=5

# ---- refusals ----------------------------------------------------------------------------------------------------
case "$PHASE" in all|build|closure|main) ;; *) echo "usage: run_e11.sh TAG [all|build|closure|main]"; exit 2 ;; esac
G=$("$PY" "$OPS" pyguard 2>&1 | tail -1)
case "$G" in *'"ok": true'*) ;; *) echo "REFUSING: interpreter guard failed (pinned $PY required, never /usr/bin/python3): $G"; exit 4 ;; esac
"$STACK" guard || exit 2
[ -e "$SP" ] && [ "$PHASE" = "all" -o "$PHASE" = "build" ] && { echo "REFUSING: $SP exists"; exit 3; }
ls "$OUT/${TAG}_"* >/dev/null 2>&1 && [ "$PHASE" != "main" ] && [ "$PHASE" != "closure" ] && { echo "REFUSING: outputs $OUT/${TAG}_* exist"; exit 3; }
for p in $PC $PS; do docker ps -a --format '{{.Names}}' | grep -q "^$p-" && { echo "REFUSING: $p-* containers exist"; exit 3; }; done
mkdir -p "$SP/code" "$SP/logs" "$SP/snapshots" "$SP/witness" "$OUT"
META=$SP/config.log; EVLOG=$SP/events.jsonl
touch "$META" "$EVLOG"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META" >&2; }
ev() {  # one JSON object per line: guard of 2026-10-19 (E10 smoke 3 wrote multi-line/invalid records; see run_e10.sh)
  local t; t=$(date -u +%s)
  "$PY" -c 'import json,sys
s, t, k = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    print(json.dumps(json.loads(s)))
except ValueError:
    print(json.dumps({"ts": t, "type": k, "malformed": True, "raw": s}))' \
    "$(printf '{"ts": %s, "utc": "%s", "type": "%s"%s}' "$t" "$(date -u +%FT%TZ)" "$1" "${2:+, $2}")" "$t" "$1" >> "$EVLOG"
}
s256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fp16() { printf '%s' "$1" | shasum -a 256 | cut -c1-16; }
wsleep() { local end=$(( $(date -u +%s) + ${1%.*} )); while [ "$(date -u +%s)" -lt "$end" ]; do sleep 1; done; }
note "tag=$TAG phase=$PHASE smoke=$SMOKE seed=$SEED python=$G load=$(uptime | sed 's/.*load/load/')"
caffeinate -i -s -m -w $$ & CAFF_PID=$!
TUN_PID=""; WPID=""; CUR=""
cleanup() {
  [ -n "$TUN_PID" ] && kill "$TUN_PID" 2>/dev/null
  [ -n "$WPID" ] && kill "$WPID" 2>/dev/null
  if [ -n "$CUR" ]; then
    docker rm -f "$CUR-anchord" "$CUR-monitor" >/dev/null 2>&1
    for v in "$CUR-sign" "$CUR-chain" "$CUR-pub" "$CUR-scratch"; do docker volume rm "$v" >/dev/null 2>&1; done
    docker network rm "$CUR-wnet" >/dev/null 2>&1
    "$STACK" down "$CUR" >> "$META" 2>&1; note "stack $CUR down (signing-key volume destroyed)"
  fi
  kill "$CAFF_PID" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# ---- code copies and hashes (the scorer reads the run's own copies) -----------------------------------------------
if [ ! -f "$SP/code/monitor.py" ]; then
  cp "$REPO/monitor/monitor.py" "$E11/monitor/oh_monitor.py" "$OPS" "$STACK" "$E11/build_bundles.sh" \
     "$REPO/testbed/anchord/headwitness.py" "$REPO/testbed/anchord/chainverify.py" "$SP/code/"
  "$PY" "$OPS" plan --seed "$SEED" $([ "$SMOKE" = "1" ] && echo --smoke) > "$SP/plan.json"
  note "code sha256: monitor.py=$(s256 $REPO/monitor/monitor.py) oh_monitor.py=$(s256 $E11/monitor/oh_monitor.py) e11ops.py=$(s256 $OPS) e11_stack.sh=$(s256 $STACK) run_e11.sh=$(s256 $0) e11_score.py=$(s256 $REPO/exp/stages/e11_score.py) plan=$(s256 $SP/plan.json)"
  note "hardened monitor (E10 patch applied): $(grep -q HOMEPROV_HARDEN $REPO/monitor/monitor.py && echo yes || echo no)"
fi
if [ "$SMOKE" != "1" ] && [ "$PHASE" != "build" ]; then
  "$PY" "$E11/e11_prereg.py" --check "$REPO/exp/out/e11_preregistration.json" >> "$META" 2>&1 \
    || { note "FAIL the pre-registration is missing, not registered, or a frozen file changed"; exit 2; }
  note "ok    pre-registration registered and every frozen file at its registered sha256"
fi
if [ "${HPR_E11_RUN_TESTS:-1}" = "1" ]; then
  ( cd "$REPO" && "$PY" -m pytest -q -p no:cacheprovider testbed/e11/test_e11.py ) > "$SP/logs/pytest_e11.log" 2>&1 \
    || { note "FAIL tests ($(tail -2 "$SP/logs/pytest_e11.log" | tr '\n' ' '))"; exit 2; }
  note "ok    tests: $(tail -1 "$SP/logs/pytest_e11.log")"
fi

# =================================================================================================================
phase_build() {
  ev phase_begin '"phase": "build"'
  docker image inspect "${OH_IMG%@*}" >/dev/null 2>&1 || docker pull -q "$OH_IMG" >/dev/null || { note "FAIL pull $OH_IMG"; exit 4; }
  local dig; dig=$(docker image inspect "${OH_IMG%@*}" --format '{{json .RepoDigests}}')
  case "$dig" in *"${OH_IMG##*@}"*) ;; *) note "FAIL ${OH_IMG%@*} is not ${OH_IMG##*@} ($dig)"; exit 4 ;; esac
  note "hub image ${OH_IMG}: $(docker image inspect "${OH_IMG%@*}" --format '{{.Id}} {{.Architecture}} created={{.Created}}')"
  "$E11/build_bundles.sh" "$SP/bundles" > "$SP/logs/build_bundles.log" 2>&1 || { note "FAIL bundles ($(tail -3 "$SP/logs/build_bundles.log" | tr '\n' ' '))"; exit 4; }
  note "bundles: $(tail -1 "$SP/logs/build_bundles.log")"
  docker build -q -f "$REPO/monitor/Dockerfile.sign" -t "$MON_IMG" "$REPO/monitor" >/dev/null || { note "FAIL build $MON_IMG"; exit 4; }
  docker build -q -f "$REPO/testbed/e8/anchord-e8.Dockerfile" -t "$ANC_IMG" "$REPO/testbed/anchord" >/dev/null || { note "FAIL build $ANC_IMG"; exit 4; }
  local f rp img ip repo_h img_h
  for f in "monitor/monitor.py|$MON_IMG|/app/monitor.py" "testbed/anchord/anchord.py|$ANC_IMG|/app/anchord.py" \
           "testbed/anchord/anchord_linked.py|$ANC_IMG|/app/anchord_linked.py"; do
    rp=${f%%|*}; img=$(echo "$f" | cut -d'|' -f2); ip=${f##*|}
    repo_h=$(s256 "$REPO/$rp"); img_h=$(docker run --rm --entrypoint sha256sum "$img" "$ip" | cut -d' ' -f1)
    [ "$repo_h" = "$img_h" ] || { note "FAIL $img:$ip $img_h != $rp $repo_h"; exit 4; }
    note "ok    $img:$ip = $rp (${repo_h:0:16})"
  done
  for img in python:3.13-slim alpine:3; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null || { note "FAIL image $img"; exit 4; }
    note "image $img $(docker image inspect "$img" --format '{{.Id}} {{json .RepoDigests}}')"
  done
  ev phase_end '"phase": "build"'
}

new_creds() {   # per-run household passwords (0600); only fingerprints are logged
  local o m; o=$(openssl rand -hex 16); m=$(openssl rand -hex 16)
  ( umask 077; printf '{"owner": "%s", "member": "%s"}\n' "$o" "$m" > "$1/creds.json" )
  note "account password fingerprints: owner $(fp16 "$o") member $(fp16 "$m") (passwords not recorded)"
}
tunnel() {   # $1 port, $2 prefix: host 127.0.0.1:port -> PREFIX-hub:8080 through PREFIX-harness
  "$PY" "$REPO/testbed/domoticz/harness/tunnel.py" "$1" "$2-harness" "$2-hub" 8080 > "$SP/logs/tunnel_$2.log" 2>&1 &
  TUN_PID=$!; sleep 2
}

# =================================================================================================================
phase_closure() {
  local D="$SP/closure"; mkdir -p "$D/bundles"
  cp "$SP/bundles/org.homeprov.e11.fixture-1.0.0.jar" "$D/bundles/" || { note "FAIL no fixture bundle (run the build phase)"; exit 6; }
  ev phase_begin '"phase": "closure"'
  new_creds "$D"; CUR=$PC
  "$STACK" up "$PC" "$D" closure > "$D/stack.json" 2>> "$META" || { note "FAIL closure stack ($(tail -c 400 "$D/stack.json"))"; exit 6; }
  note "closure stack: $(cut -c1-600 "$D/stack.json")"
  tunnel $TPORT_C "$PC"
  "$PY" "$OPS" provision --base "http://127.0.0.1:$TPORT_C" --creds "$D/creds.json" --closure-fixtures > "$D/provision.json" \
    || { note "FAIL provision ($(tail -c 300 "$D/provision.json"))"; exit 6; }
  local fixtures=""; [ "$SMOKE" = "1" ] && fixtures="Fx_Switch,Fx_Switch2,Fx_Temperature"
  E11_CLO_FIXTURES=$fixtures "$PY" "$OPS" closure --base "http://127.0.0.1:$TPORT_C" --creds "$D/creds.json" --hpctl "$D/hpctl" \
    --dbhelper "$PC-dbh" --prefix "$PC" --out "$OUT/${TAG}_clo_closure.json" > "$D/closure.out" 2> "$D/closure.err" \
    || { note "FAIL closure ($(tail -c 600 "$D/closure.err"))"; exit 7; }
  note "closure: $(tail -1 "$D/closure.out") -> $OUT/${TAG}_clo_closure.json $(s256 "$OUT/${TAG}_clo_closure.json")"
  docker cp "$PC-hub:/openhab/userdata/logs/openhab.log" "$D/openhab.log" >/dev/null 2>&1
  kill "$TUN_PID" 2>/dev/null; TUN_PID=""
  "$STACK" down "$PC" >> "$META" 2>&1; CUR=""
  ev phase_end '"phase": "closure"'
}

# =================================================================================================================
start_monitoring() {   # keys, witness, linked anchor, signing key, monitor
  local KEY OKEY WKEY fp n
  KEY=$(openssl rand -hex 32); OKEY=$(openssl rand -hex 32); WKEY=$(openssl rand -hex 32)
  note "append_key_fp $(fp16 "$KEY") operator_key_fp $(fp16 "$OKEY") witness_key_fp $(fp16 "$WKEY") (keys not recorded)"
  lsof -nP -iTCP:$WPORT -sTCP:LISTEN >/dev/null 2>&1 && { note "FAIL port $WPORT in use"; exit 5; }
  WITNESS_LOG="$SP/witness/heads.jsonl" WITNESS_FORKS="$SP/witness/forks.jsonl" HOMEPROV_WITNESS_KEY="$WKEY" WITNESS_DIR="$SP/witness" \
    nohup "$PY" -u -c 'import sys; sys.path.insert(0, sys.argv[1]); import headwitness as W; W.serve(host="127.0.0.1", port=int(sys.argv[2]))' \
    "$SP/code" "$WPORT" > "$SP/witness/witness.log" 2>&1 &
  WPID=$!; n=0
  until grep -q READY "$SP/witness/witness.log" 2>/dev/null || [ $n -ge 20 ]; do sleep 0.5; n=$((n+1)); done
  grep -q READY "$SP/witness/witness.log" || { note "FAIL witness"; exit 5; }
  docker network create "$PS-wnet" >/dev/null
  for v in "$PS-sign" "$PS-chain" "$PS-pub" "$PS-scratch"; do docker volume create "$v" >/dev/null; done
  docker run -d --name "$PS-anchord" --network "$PS-net" --network-alias anchor --restart unless-stopped \
    -e HOMEPROV_ANCHOR_KEY="$KEY" -e HOMEPROV_OPERATOR_KEY="$OKEY" -e HOMEPROV_ANCHOR_LINK=v2 \
    -e HOMEPROV_WITNESS_KEY="$WKEY" -e HEAD_WITNESS_URL="http://host.docker.internal:$WPORT/head" -e HEAD_WITNESS_MODE=sync \
    -v "$PS-chain":/anchor -v "$PS-pub":/published "$ANC_IMG" >/dev/null || { note "FAIL anchor"; exit 5; }
  docker network connect "$PS-wnet" "$PS-anchord"
  fp=$(docker run --rm -v "$PS-sign":/sign --entrypoint python "$MON_IMG" -c '
import hashlib, os
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519
k = ed25519.Ed25519PrivateKey.generate(); os.umask(0o077)
open("/sign/monitor.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
p = k.public_key(); open("/sign/monitor.pub.pem", "wb").write(p.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
print(hashlib.sha256(p.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).hexdigest())' 2>&1 | tail -1)
  [ ${#fp} -eq 64 ] || { note "FAIL signing key ($fp)"; exit 5; }
  docker run --rm -v "$PS-sign":/sign:ro alpine:3 cat /sign/monitor.pub.pem > "$SP/sign_pub.pem"
  note "record-signing key fingerprint $fp"
  docker run -d --name "$PS-monitor" --network "$PS-net" --restart unless-stopped --entrypoint python \
    -e HOMEPROV_MONITOR_DIR=/app -e HOMEPROV_DB=/hub/persistence/jdbc/openhab.db -e HP_OH_JSONDB=/hub/jsondb -e HP_OH_TZ=UTC \
    -e HOMEPROV_ANCHOR=http://anchor:9900/append -e HOMEPROV_ANCHOR_KEY="$KEY" -e HOMEPROV_PERIOD=$PERIOD \
    -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_SCHEME=closure -e HOMEPROV_COVERAGE=1 -e HOMEPROV_KEYLOG=0 \
    -e HOMEPROV_READ=copy -e HOMEPROV_QUICK_CHECK_EVERY=1 -e HOMEPROV_COST_LOG=/scratch/cost.jsonl \
    -e HP_OH_ARCHIVE=/scratch/archive.jsonl -e HOMEPROV_SIGN_KEY=/sign/monitor.pem -e HOMEPROV_REPLY_TAGS=1 \
    -v "$PS-userdata":/hub:ro -v "$SP/code":/ohm:ro -v "$PS-scratch":/scratch -v "$PS-sign":/sign:ro \
    "$MON_IMG" -u /ohm/oh_monitor.py >/dev/null || { note "FAIL monitor"; exit 5; }
  KEY=; OKEY=; WKEY=
  sleep 10
  note "monitor start: $(docker logs "$PS-monitor" 2>&1 | grep -m1 oh_reader | cut -c1-500)"
  note "monitor mounts: $(docker inspect "$PS-monitor" --format '{{range .Mounts}}{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}} {{end}}')"
  local nrec
  for n in $(seq 1 60); do
    nrec=$(docker exec "$PS-anchord" sh -c 'grep -c external-monitor /anchor/chain.jsonl 2>/dev/null' | head -1)
    [ "${nrec:-0}" -ge 6 ] 2>/dev/null && break; sleep 5
  done
  note "chain records after start: $(docker exec "$PS-anchord" sh -c 'wc -l < /anchor/chain.jsonl')"
}

ui_cap() {   # $1 label: Main UI's Analyze view of the lock, both accounts (secondary; failures do not stop the run)
  local r; mkdir -p "$SP/screens"
  for r in owner member; do
    "$PY" "$OPS" uicapture --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" --item FrontDoor_Lock --account "$r" \
      --out "$OUT/${TAG}_ui_$1_$r.json" --screenshot "$SP/screens/$1_$r.png" >> "$SP/logs/ui.out" 2>> "$SP/logs/ui.err" \
      || note "  WARN ui capture $1 $r failed"
  done
  note "  ui $1: $(tail -1 "$SP/logs/ui.out" | cut -c1-300)"
}

benign_op() {   # $1 op
  local r
  case "$1" in
  B-RESTART) r=$("$STACK" restart "$PS" 2>>"$META" | tail -1); sleep 20
             case "$r" in *'"ready": true'*) ;; *) note "  WARN hub not ready after restart: $r" ;; esac
             # the fixture bundle restarts with the hub, paused and without its schedule: the household resumes
             "$PY" "$OPS" schedule --hpctl "$SP/hpctl" --plan "$SP/plan.json" --action set >/dev/null && \
               "$PY" "$OPS" schedule --hpctl "$SP/hpctl" --plan "$SP/plan.json" --action resume >/dev/null || note "  WARN schedule not resumed after restart"
             "$PY" "$OPS" benign --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" --hpctl "$SP/hpctl" --plan "$SP/plan.json" \
               --log "$SP/benign.jsonl" --op B-RESTART --extra "{\"restart\": ${r:-null}}" >> "$SP/logs/benign.out" ;;
  B-CLEAN)   r=$("$STACK" console "$PS" "openhab:jdbc tables clean" 2>&1 | tail -5 | "$PY" -c 'import json,sys;print(json.dumps(sys.stdin.read()[-600:]))')
             "$PY" "$OPS" benign --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" --hpctl "$SP/hpctl" --plan "$SP/plan.json" \
               --log "$SP/benign.jsonl" --op B-CLEAN --extra "{\"console\": $r}" >> "$SP/logs/benign.out" ;;
  *)         "$PY" "$OPS" benign --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" --hpctl "$SP/hpctl" --plan "$SP/plan.json" \
               --log "$SP/benign.jsonl" --op "$1" >> "$SP/logs/benign.out" 2>> "$SP/logs/benign.err" ;;
  esac
  ev benign "\"op\": \"$1\", \"rc\": $?"; note "  benign $1: $(tail -1 "$SP/logs/benign.out" | cut -c1-200)"
}

phase_main() {
  ls "$OUT/${TAG}_report_"* "$OUT/${TAG}_chain.jsonl.gz" "$OUT/${TAG}_score.json" >/dev/null 2>&1 && { note "REFUSING: main outputs of $TAG exist"; exit 3; }
  local mi; mi=$(docker run --rm --entrypoint sha256sum "$MON_IMG" /app/monitor.py | cut -d' ' -f1)
  [ "$mi" = "$(s256 "$REPO/monitor/monitor.py")" ] && [ "$mi" = "$(s256 "$SP/code/monitor.py")" ] \
    || { note "FAIL $MON_IMG:/app/monitor.py, monitor/monitor.py and the run's copy differ"; exit 4; }
  ev phase_begin '"phase": "main"'
  new_creds "$SP"; CUR=$PS
  "$STACK" up "$PS" "$SP" main > "$SP/stack.json" 2>> "$META" || { note "FAIL main stack ($(tail -c 400 "$SP/stack.json"))"; exit 6; }
  note "main stack: $(cut -c1-600 "$SP/stack.json")"
  tunnel $TPORT_S "$PS"
  "$PY" "$OPS" provision --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" > "$SP/provision.json" \
    || { note "FAIL provision ($(tail -c 300 "$SP/provision.json"))"; exit 6; }
  "$PY" "$OPS" instrument-info --hpctl "$SP/hpctl" > "$SP/instrument_info.json" || { note "FAIL instrument bundle not answering"; exit 6; }
  note "instrument: $(cat "$SP/instrument_info.json")"
  "$PY" "$OPS" schedule --hpctl "$SP/hpctl" --plan "$SP/plan.json" --action set >/dev/null && \
    "$PY" "$OPS" schedule --hpctl "$SP/hpctl" --plan "$SP/plan.json" --action resume >/dev/null || { note "FAIL fixture schedule"; exit 6; }
  start_monitoring
  jp() { "$PY" -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SP/plan.json" "$1"; }
  note "warm-up $(jp warmup_s) s"; wsleep "$(jp warmup_s)"
  "$PY" "$OPS" vmnow --harness "$PS-harness" > "$SP/t_start"; ev t_start "\"t\": $(cat "$SP/t_start")"
  benign_op B-REPLACE-SETUP
  note "window 1: $(jp window1_s) s untouched (benign household only)"; wsleep "$(jp window1_s)"
  local a
  ui_cap before_arms
  for a in $("$PY" -c "import json,sys;print(' '.join(x['arm'] for x in json.load(open(sys.argv[1]))['arms']))" "$SP/plan.json"); do
    ev arm_begin "\"arm\": \"$a\""
    "$PY" "$OPS" arm --arm "$a" --base "http://127.0.0.1:$TPORT_S" --creds "$SP/creds.json" --hpctl "$SP/hpctl" \
      --harness "$PS-harness" --plan "$SP/plan.json" --out "$OUT/${TAG}_report_$a.json" > "$SP/logs/arm_$a.out" 2> "$SP/logs/arm_$a.err" \
      || { note "FAIL arm $a ($(tail -c 400 "$SP/logs/arm_$a.err"))"; exit 8; }
    ev arm_end "\"arm\": \"$a\", \"result\": $(tail -1 "$SP/logs/arm_$a.out")"; note "  arm $a: $(tail -1 "$SP/logs/arm_$a.out")"
    ui_cap "after_$a"
  done
  local b gap; gap=$(jp benign_gap_s)
  for b in $("$PY" -c "import json,sys;print(' '.join(json.load(open(sys.argv[1]))['benign']))" "$SP/plan.json"); do
    benign_op "$b"; wsleep "$gap"
  done
  note "window 2: $(jp window2_s) s untouched"; wsleep "$(jp window2_s)"
  "$PY" "$OPS" vmnow --harness "$PS-harness" > "$SP/t_end"; ev t_end "\"t\": $(cat "$SP/t_end")"
  note "settling $(jp settle_s) s"; wsleep "$(jp settle_s)"
  local snap; snap=$("$STACK" snapshot "$PS" final "$SP/snapshots"); ev snapshot "\"result\": $snap"; note "final snapshot: $snap"
  wsleep 30
  docker stop "$PS-monitor" >/dev/null 2>&1; wsleep 8
  "$PY" -c 'import sys,urllib.request;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())' "http://127.0.0.1:$WPORT/head" > "$SP/witness/head_final.json" 2>/dev/null
  docker exec "$PS-anchord" cat /anchor/chain.jsonl > "$SP/chain.jsonl"
  docker exec "$PS-anchord" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/refusals.jsonl"
  cp "$SP/witness/heads.jsonl" "$SP/witness_heads.jsonl"
  docker cp "$PS-monitor:/scratch/cost.jsonl" "$SP/cost.jsonl" >/dev/null 2>&1
  docker cp "$PS-monitor:/scratch/archive.jsonl" "$SP/archive.jsonl" >/dev/null 2>&1
  docker logs "$PS-monitor" > "$SP/logs/monitor.log" 2>&1; docker logs "$PS-anchord" > "$SP/logs/anchord.log" 2>&1
  docker cp "$PS-hub:/openhab/userdata/logs/openhab.log" "$SP/logs/openhab.log" >/dev/null 2>&1
  docker cp "$PS-hub:/openhab/userdata/logs/events.log" "$SP/logs/events.log" >/dev/null 2>&1
  docker logs "$PS-hub" > "$SP/logs/hub_stdout.log" 2>&1
  gzip -c "$SP/chain.jsonl" > "$OUT/${TAG}_chain.jsonl.gz"; gzip -c "$SP/witness_heads.jsonl" > "$OUT/${TAG}_witness_heads.jsonl.gz"
  cp "$SP/benign.jsonl" "$OUT/${TAG}_benign.jsonl"; cp "$SP/plan.json" "$OUT/${TAG}_plan.json"; cp "$EVLOG" "$OUT/${TAG}_events.jsonl"
  note "chain records $(wc -l < "$SP/chain.jsonl"), refusals $(wc -l < "$SP/refusals.jsonl"), monitor errors $(grep -c '"error"' "$SP/logs/monitor.log"), archive lines $(wc -l < "$SP/archive.jsonl" 2>/dev/null)"
  kill "$TUN_PID" 2>/dev/null; TUN_PID=""; kill "$WPID" 2>/dev/null; WPID=""
  docker rm -f "$PS-anchord" "$PS-monitor" >/dev/null 2>&1
  for v in "$PS-sign" "$PS-chain" "$PS-pub" "$PS-scratch"; do docker volume rm "$v" >/dev/null 2>&1; done
  docker network rm "$PS-wnet" >/dev/null 2>&1
  "$STACK" down "$PS" >> "$META" 2>&1; CUR=""; note "main stack down (signing-key volume destroyed)"
  ev phase_end '"phase": "main"'
  "$PY" - "$SP" "$OUT/${TAG}_config.json" <<'PYC'
import json, os, sys
sp, out = sys.argv[1:]
rd = lambda p: json.load(open(p)) if os.path.exists(p) else None
doc = {"experiment": "E11 (RQ4): HOMEPROV on openHAB", "configuration_log": [l.rstrip("\n") for l in open(os.path.join(sp, "config.log"))],
       "stack": rd(os.path.join(sp, "stack.json")), "build": rd(os.path.join(sp, "bundles", "build.json")),
       "provision": rd(os.path.join(sp, "provision.json")), "instrument_info": rd(os.path.join(sp, "instrument_info.json")),
       "plan": rd(os.path.join(sp, "plan.json")), "keys_recorded": False}
json.dump(doc, open(out, "x"), indent=1)
PYC
  local clo=""; [ -f "$OUT/${TAG}_clo_closure.json" ] && clo="--closure $OUT/${TAG}_clo_closure.json"
  "$PY" "$REPO/exp/stages/e11_score.py" --run "$SP" --tag "$TAG" --outdir "$OUT" $clo > "$SP/logs/score.log" 2>&1
  note "score exit: $? ($(tail -8 "$SP/logs/score.log" | tr '\n' ' ' | cut -c1-900))"
}

[ "$PHASE" = "all" ] || [ "$PHASE" = "build" ] && phase_build
[ "$PHASE" = "all" ] || [ "$PHASE" = "closure" ] && phase_closure
if [ "$PHASE" = "all" ]; then   # the measured closure must lie within what the reader commits, else amend first
  GATE=$("$PY" "$REPO/exp/stages/e11_score.py" --closure-gate "$OUT/${TAG}_clo_closure.json"); GRC=$?
  note "closure gate: $GATE"
  [ $GRC = 0 ] || { note "STOP: the measured closure is not within the reader's committed fields (or a control failed); amend the reader and register the amendment before the main phase"; exit 9; }
fi
[ "$PHASE" = "all" ] || [ "$PHASE" = "main" ] && phase_main
note "done; results under $OUT/${TAG}_* and $SP; load $(uptime | sed 's/.*load/load/')"
