#!/bin/bash
# E8 (round 13), part C: one real-deployment run on the DEFAULT deployment (hpr-hass, hpr-devices, hpr-broker) under
# TWO monitors in parallel, each with its own anchor, keys and head witness:
#   - the STABLE-COLUMNS monitor (HOMEPROV_SCHEME=stable): the evaluated (deployed) commitment;
#   - the CLOSURE monitor (HOMEPROV_SCHEME=closure): the renderer closure, run alongside.
# Both: coverage (watermark, sealed-through, keylog), escrow, per-poll cost log, Ed25519 record signatures
# (HOMEPROV_SIGN_KEY; the private key is generated inside a Docker volume that only that monitor mounts, and destroyed at
# teardown; only the public key and its fingerprint leave it), tagged anchor replies required (HOMEPROV_REPLY_TAGS=1).
# Anchors: the linked daemon (testbed/anchord/anchord_linked.py over the hardened anchord.py; image built from
# testbed/e8/anchord-e8.Dockerfile) with an append key, a SEPARATE operator key for lifecycle markers
# (HOMEPROV_OPERATOR_KEY), and its head pushed synchronously to a head witness (testbed/anchord/headwitness.py) that runs
# as a python3 process on the Mac, outside Docker's VM, bound to 127.0.0.1, as in E5. Fresh keys for everything; only
# fingerprints are recorded.
#
# Phase 1 (arms, 30 trials per configuration and arm, the three motion-light configurations):
#   homeprov_ec:  PU, PI (other-principal laundering), PSR (member-account swap), P (own-actuation laundering, the
#                 post-commit control) -- the component and arms of the earlier runs, unchanged;
#   homeprov_e7:  INS-L, INS-M (edit + K>=9 rows inserted into the edited second), BD-S (forged unlock backdated into an
#                 empty sealed second).
# Phase 2 (write-rate stress): a BASELINE window at the lab rate (no trials, no restarts), then a fixed STRESS window in
#   which a second motion publisher (testbed/e8/stress_publisher.py, hpr-devices:1 image, same topics, sleeps divided by
#   HPR_E8_STRESS_FACTOR) raises the write rate to about five times the lab rate, with a 30-trial PU laundering arm. The
#   lab simulator hpr-devices has no rate knob (testbed/real/devices/devices.py), so it is NOT restarted or modified.
# Scoring: exp/stages/e8_score.py (e7_verify per monitor and window with the pre-registered LATE_BOUND = 30 s and
#   GAP_S = 30 s, the earlier rule's counts, floors, costs, signatures, witness checks, write rates).
#
#   Usage (the LEAD runs this after the E2 night, i.e. after 2026-10-09 05:00 UTC, with e2-issuer stopped):
#       mkdir -p <research-dir>/HOMEPROV-P13-exp/e8
#       nohup caffeinate -i -s testbed/e8/run_e8.sh e8_main > <research-dir>/HOMEPROV-P13-exp/e8/e8_main.out 2>&1 &
#
# It stops+renames the stock monitor and anchor (restored by the EXIT trap), installs and removes the attack
# integrations in the hub's /config per configuration (restoring configuration.yaml byte for byte at the end), restarts
# the hub three times per configuration and twice in the stress phase, starts and removes one extra publisher container.
# Never overwrites an output. Scratch testing: every target is overridable by env (HPR_E8_*); HPR_E8_SCRATCH=1 skips the
# E2-night and clock guards, which protect only the shared real deployment.
set -u

# ---- targets (real-deployment defaults; overridden for the scratch stack) ---------------------------------------
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
OUT=${HPR_E8_OUT:-$REPO/exp/out}                         # a dry run sets this to its own directory
CC=$REPO/testbed/real/ha-config/custom_components
HUB=${HPR_E8_HUB:-hpr-hass}
NET=${HPR_E8_NET:-homeprov-real_hp-real}
CFGVOL=${HPR_E8_CFGVOL:-homeprov-real_hpr-config}
DEVICES=${HPR_E8_DEVICES:-hpr-devices}
BROKER=${HPR_E8_BROKER:-hpr-broker}                     # container; its network alias on NET is "broker"
STOCK_MON=${HPR_E8_STOCK_MONITOR:-hpr-monitor}
STOCK_ANC=${HPR_E8_STOCK_ANCHOR:-hpr-anchord}
PREFIX=${HPR_E8_PREFIX:-e8}
MON_IMG=${HPR_E8_MONITOR_IMAGE:-hpr-monitor:e8}
ANC_IMG=${HPR_E8_ANCHOR_IMAGE:-hpr-anchord:e8}
DEV_IMG=${HPR_E8_DEVICES_IMAGE:-hpr-devices:1}          # the stress publisher runs from the lab simulator's image
SCRATCH_MODE=${HPR_E8_SCRATCH:-0}
RESTART_WAIT=${HPR_E8_RESTART_WAIT:-45}
NOT_BEFORE=${HPR_E8_NOT_BEFORE:-1791522000}             # 2026-10-09T05:00:00Z: the E2 night owns hpr-* until then

# ---- run parameters ---------------------------------------------------------------------------------------------
TAG=${1:?usage: run_e8.sh TAG}
TRIALS=${HPR_E8_TRIALS:-30}                             # per configuration and arm; 3 configurations -> 90 per arm
ROOMS=${HPR_E8_ROOMS:-porch hallway kitchen}
EC_ARMS=${HPR_E8_EC_ARMS:-"\"PU\",\"PI\",\"PSR\",\"P\""}
E7_ARMS=${HPR_E8_E7_ARMS:-"\"INS-L\",\"INS-M\",\"BD-S\""}
K=${HPR_E8_K:-9}
SEAL_WAIT_S=${HPR_E8_SEAL_WAIT_S:-130}
BD_LOOKBACK_S=${HPR_E8_BD_LOOKBACK_S:-1800}
BD_MIN_AGE_S=${HPR_E8_BD_MIN_AGE_S:-130}
PERIOD=${HPR_E8_PERIOD:-5}
LATE_BOUND_S=${HPR_E8_LATE_BOUND_S:-30}                 # pre-registered verifier parameter (as E7)
GAP_S=${HPR_E8_GAP_S:-30}                               # pre-registered verifier parameter (as E7)
SKIP_MAIN=${HPR_E8_SKIP_MAIN:-0}
SKIP_STRESS=${HPR_E8_SKIP_STRESS:-0}
BASELINE_S=${HPR_E8_BASELINE_S:-600}                    # lab-rate window before the stress (no trials, no restarts)
STRESS_S=${HPR_E8_STRESS_S:-1800}                       # fixed stress window (extended only if the arm overruns it)
STRESS_RAMP_S=${HPR_E8_STRESS_RAMP_S:-300}              # stress runs this long before the PU arm is installed
STRESS_FACTOR=${HPR_E8_STRESS_FACTOR:-6}                # extra publisher sleeps divided by this; scratch: F=4/6/7/25 gave 3.9x/4.7x/5.7x(with arm)/15x the baseline write rate
STRESS_ROOMS=${HPR_E8_STRESS_ROOMS:-porch}
STRESS_TRIALS=${HPR_E8_STRESS_TRIALS:-30}               # per stress configuration
STRESS_ARMS=${HPR_E8_STRESS_ARMS:-"\"PU\""}
OPERATOR_PROBE=${HPR_E8_OPERATOR_PROBE:-1}              # one inert operator-key MIGRATE marker per anchor, before the arms
RECOVERY_RENDER=${HPR_E8_RECOVERY_RENDER:-0}            # E7's escrow render of the closure monitor's restored copy (off)
WPORT_STB=${HPR_E8_WITNESS_PORT_STB:-19970}
WPORT_CLO=${HPR_E8_WITNESS_PORT_CLO:-19971}
PY=$(command -v python3); [ -n "$PY" ] || { echo "python3 not found"; exit 4; }

SP=${HPR_E8_SP:-<research-dir>/HOMEPROV-P13-exp/e8/$TAG}
ASTB=${PREFIX}-anchord-stb; MSTB=${PREFIX}-monitor-stb
ACLO=${PREFIX}-anchord-clo; MCLO=${PREFIX}-monitor-clo
STRESS_C=${PREFIX}-$TAG-stress
WNET=${PREFIX}-$TAG-wnet                                # non-internal bridge: anchors -> witnesses on the Mac only
V=${PREFIX}-$TAG
VOLS="$V-stb-chain $V-stb-pub $V-stb-scratch $V-stb-sign $V-clo-chain $V-clo-pub $V-clo-scratch $V-clo-sign"
META=$SP/auth_meta.log
MK=/config/homeprov_out

# ---- refusals (nothing is created before these pass) ------------------------------------------------------------
[ -e "$SP" ] && { echo "REFUSING: $SP exists"; exit 3; }
ls "$OUT/${TAG}_"* >/dev/null 2>&1 && { echo "REFUSING: outputs $OUT/${TAG}_* exist"; exit 3; }
for c in $ASTB $MSTB $ACLO $MCLO $STRESS_C ${PREFIX}r-$TAG-hass; do
  docker ps -a --format '{{.Names}}' | grep -qx "$c" && { echo "REFUSING: container $c exists"; exit 3; }
done
for v in $VOLS; do docker volume inspect "$v" >/dev/null 2>&1 && { echo "REFUSING: volume $v exists"; exit 3; }; done
docker network inspect "$WNET" >/dev/null 2>&1 && { echo "REFUSING: network $WNET exists"; exit 3; }
for p in $WPORT_STB $WPORT_CLO; do
  lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 && { echo "REFUSING: port $p is in use"; exit 3; }
done

e2_night_running() {   # 0 (true) while the E2 night runs: e2-issuer RUNNING, or its driver process alive
  docker ps --format '{{.Names}}' | grep -qx e2-issuer && { echo "the e2-issuer container is running"; return 0; }
  local pid cwd
  for pid in $(pgrep -f 'driver_oct9\.sh|e2night/driver\.sh|e2_night\.py' 2>/dev/null); do
    echo "E2-night process $pid ($(ps -o command= -p "$pid" 2>/dev/null | cut -c1-80)) is running"; return 0
  done
  for pid in $(pgrep -f 'driver.*\.sh' 2>/dev/null); do        # a driver started from inside e2night/ with a relative path
    cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')
    case "$cwd" in *e2night*) echo "process $pid runs in $cwd"; return 0 ;; esac
  done
  return 1
}

preflight() {
  echo "== E8 preflight =="
  case "$MON_IMG $ANC_IMG" in *hpr-monitor:1*|*hpr-anchord:1*|*:sig*|*:linked*|*:e7*)
    echo "  FAIL refusing to build or use the image tags of earlier runs ($MON_IMG, $ANC_IMG); use new tags"; exit 2 ;; esac
  docker info >/dev/null 2>&1 || { echo "  FAIL docker daemon down"; exit 1; }
  if [ "$SCRATCH_MODE" != "1" ]; then
    local now; now=$(date -u +%s)
    if [ "$now" -lt "$NOT_BEFORE" ]; then
      echo "  FAIL it is $(date -u +%FT%TZ); the E2 night owns the default deployment until $(date -u -r "$NOT_BEFORE" +%FT%TZ)"; exit 2
    fi
    local why
    if why=$(e2_night_running); then
      echo "  FAIL the E2 night is running ($why). Wait for it to end (2026-10-09 05:00 UTC) and stop e2-issuer."; exit 2
    fi
    echo "  ok    E2 night not running; clock past $(date -u -r "$NOT_BEFORE" +%FT%TZ)"
  else
    # a scratch run must not touch the default deployment: no target may be one of its containers, volumes or networks
    case " $HUB $DEVICES $BROKER $STOCK_MON $STOCK_ANC $PREFIX " in *" hpr-"*|*" e2-"*|*" e8 "*)
      echo "  FAIL scratch mode with a default-deployment target ($HUB $DEVICES $BROKER $STOCK_MON $STOCK_ANC, prefix $PREFIX)"; exit 2 ;; esac
    case "$CFGVOL $NET" in *homeprov-real*)
      echo "  FAIL scratch mode with the default deployment's volume or network ($CFGVOL, $NET)"; exit 2 ;; esac
    echo "  skip  E2-night and clock guards (scratch mode; no default-deployment target)"
  fi
  for c in "$HUB" "$DEVICES" "$BROKER"; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "  FAIL $c is not running"; exit 2; }
  done
  echo "  ok    hub ($HUB), devices ($DEVICES) and broker ($BROKER) up"
  for comp in homeprov_ec homeprov_e7; do
    [ -f "$CC/$comp/__init__.py" ] || { echo "  FAIL no $comp under $CC"; exit 2; }
  done
  docker exec "$HUB" sh -c "grep -qE '^homeprov_(ec|e7):' /config/configuration.yaml || test -e /config/custom_components/homeprov_ec || test -e /config/custom_components/homeprov_e7" \
    && { echo "  FAIL the hub still has homeprov_ec/homeprov_e7 installed (leftover of an earlier run)"; exit 2; }
  # TESTS: the monitor's and the anchor's suites must pass before anything is built.
  if [ "${HPR_E8_RUN_TESTS:-1}" = "1" ]; then
    if ! ( cd "$REPO" && "$PY" -m pytest -q monitor ) > "/tmp/hpr_e8_${TAG}_pytest_mon.log" 2>&1; then
      echo "  FAIL monitor tests fail ($(tail -2 /tmp/hpr_e8_${TAG}_pytest_mon.log | tr '\n' ' '))"; exit 2
    fi
    echo "  ok    monitor tests pass ($(tail -1 /tmp/hpr_e8_${TAG}_pytest_mon.log))"
    if ! ( cd "$REPO" && "$PY" -m pytest -q testbed/anchord ) > "/tmp/hpr_e8_${TAG}_pytest_anc.log" 2>&1; then
      echo "  FAIL anchor tests fail ($(tail -2 /tmp/hpr_e8_${TAG}_pytest_anc.log | tr '\n' ' '))"; exit 2
    fi
    echo "  ok    anchor tests pass ($(tail -1 /tmp/hpr_e8_${TAG}_pytest_anc.log))"
  fi
  # BUILD both images from the repository's CURRENT files, under the E8 tags only. NEVER `docker compose build` in
  # testbed/real: that would re-tag the default deployment's hpr-monitor:1 / hpr-anchord:1.
  if [ "${HPR_E8_BUILD_IMAGES:-1}" = "1" ]; then
    docker build -q -f "$REPO/monitor/Dockerfile.sign" -t "$MON_IMG" "$REPO/monitor" >/dev/null \
      || { echo "  FAIL docker build $MON_IMG (monitor/Dockerfile.sign)"; exit 2; }
    docker build -q -f "$REPO/testbed/e8/anchord-e8.Dockerfile" -t "$ANC_IMG" "$REPO/testbed/anchord" >/dev/null \
      || { echo "  FAIL docker build $ANC_IMG"; exit 2; }
    echo "  ok    built $MON_IMG from monitor/Dockerfile.sign (pinned cryptography) and $ANC_IMG from testbed/anchord/ (testbed/e8/anchord-e8.Dockerfile)"
  fi
  for img in "$MON_IMG" "$ANC_IMG" "$DEV_IMG"; do
    docker image inspect "$img" >/dev/null 2>&1 || { echo "  FAIL image $img missing"; exit 2; }
  done
  # EXACT CODE: the files inside the images must be byte-identical to the repository's.
  local f repo_h img_h bad=0
  for f in "monitor/monitor.py|$MON_IMG|/app/monitor.py" "testbed/anchord/anchord.py|$ANC_IMG|/app/anchord.py" \
           "testbed/anchord/anchord_linked.py|$ANC_IMG|/app/anchord_linked.py"; do
    local rp=${f%%|*} rest=${f#*|}; local img=${rest%%|*} ip=${rest#*|}     # "|": image tags contain ":"
    repo_h=$(shasum -a 256 "$REPO/$rp" | cut -d' ' -f1)
    img_h=$(docker run --rm --entrypoint sha256sum "$img" "$ip" 2>/dev/null | cut -d' ' -f1)
    if [ "$repo_h" != "$img_h" ]; then
      echo "  FAIL $img:$ip sha $img_h != repository $rp $repo_h"; bad=1
    else
      echo "  ok    $img:$ip = repository $rp (${repo_h:0:16})"
    fi
  done
  [ $bad -eq 0 ] || { [ "$SCRATCH_MODE" = "1" ] && echo "  WARN image/repository mismatch [scratch]" || exit 2; }
  # CAPABILITIES the run relies on, read from the files the images execute.
  local need
  need=$(docker run --rm --entrypoint sh "$MON_IMG" -c "for k in HOMEPROV_COVERAGE seq_local HOMEPROV_SIGN_KEY HOMEPROV_REPLY_TAGS HOMEPROV_ESCROW_DIR HOMEPROV_COST_LOG; do grep -q \$k /app/monitor.py || echo \$k; done")
  [ -z "$need" ] && echo "  ok    $MON_IMG has coverage, signatures, reply tags, escrow, cost log" \
    || { echo "  FAIL $MON_IMG lacks: $need"; [ "$SCRATCH_MODE" = "1" ] || exit 2; }
  MON_CRYPTO=$(docker run --rm --entrypoint python "$MON_IMG" -c "import cryptography;print(cryptography.__version__)" 2>&1 | tail -1)
  case "$MON_CRYPTO" in [0-9]*) echo "  ok    $MON_IMG has cryptography $MON_CRYPTO" ;;
    *) echo "  FAIL $MON_IMG cannot import cryptography ($MON_CRYPTO): signatures impossible"; exit 2 ;; esac
  need=$(docker run --rm --entrypoint sh "$ANC_IMG" -c "for k in HOMEPROV_OPERATOR_KEY X-HP-Reply-Auth; do grep -q \$k /app/anchord.py || echo \$k; done; grep -q records_pushed /app/anchord_linked.py || echo extension-pushes")
  [ -z "$need" ] && echo "  ok    $ANC_IMG has the operator key, tagged replies and extension pushes" \
    || { echo "  FAIL $ANC_IMG lacks: $need"; [ "$SCRATCH_MODE" = "1" ] || exit 2; }
  grep -q not_extension "$REPO/testbed/anchord/headwitness.py" && echo "  ok    headwitness.py checks extension records" \
    || { echo "  FAIL headwitness.py does not check that a head extends the last one"; [ "$SCRATCH_MODE" = "1" ] || exit 2; }
}
preflight

mkdir -p "$SP/keys" "$SP/escrow_stb" "$SP/escrow_clo" "$SP/witness_stb" "$SP/witness_clo" "$SP/code"
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }
s16() { shasum -a 256 "$1" | cut -c1-16; }
fp16() { printf '%s' "$1" | shasum -a 256 | cut -c1-16; }
# The witness runs from a COPY of the repository's headwitness.py taken now (its hash is recorded), so a later edit of
# the repository cannot change the running witness's code unseen.
cp "$REPO/testbed/anchord/headwitness.py" "$REPO/testbed/anchord/chainverify.py" "$SP/code/"
docker exec "$HUB" cat /config/configuration.yaml > "$SP/hub_configuration.yaml.orig" \
  || { echo "cannot read the hub's configuration.yaml"; exit 4; }
HUB_CFG_SHA=$(shasum -a 256 "$SP/hub_configuration.yaml.orig" | cut -d' ' -f1)

note "tag=$TAG hub=$HUB net=$NET cfgvol=$CFGVOL devices=$DEVICES broker=$BROKER prefix=$PREFIX scratch=$SCRATCH_MODE"
note "arms (skip_main=$SKIP_MAIN): homeprov_ec [$EC_ARMS] + homeprov_e7 [$E7_ARMS]; trials/config=$TRIALS rooms='$ROOMS' K=$K seal_wait_s=$SEAL_WAIT_S bd_min_age_s=$BD_MIN_AGE_S bd_lookback_s=$BD_LOOKBACK_S period=$PERIOD"
note "stress: skip=$SKIP_STRESS baseline_s=$BASELINE_S stress_s=$STRESS_S ramp_s=$STRESS_RAMP_S factor=$STRESS_FACTOR rooms='$STRESS_ROOMS' trials=$STRESS_TRIALS arms=[$STRESS_ARMS]"
note "verifier parameters (pre-registered, as E7): LATE_BOUND=${LATE_BOUND_S}s GAP_S=${GAP_S}s; recovery_render=$RECOVERY_RENDER operator_probe=$OPERATOR_PROBE"
note "evaluated scheme: stable columns ($MSTB / $ASTB); alongside: closure ($MCLO / $ACLO)"
note "load_before: $(uptime)"
note "git_head: $(git -C $REPO rev-parse HEAD 2>/dev/null) (working tree carries the round-13 monitor/anchor/verifier changes; hashes below)"
note "hub_image: $(docker inspect "$HUB" --format '{{.Config.Image}} {{.Image}}')"
note "devices_image: $(docker inspect "$DEVICES" --format '{{.Config.Image}} {{.Image}}') (not restarted or modified by this run)"
note "monitor_image: $MON_IMG ($(docker image inspect "$MON_IMG" --format '{{.Id}}')) cryptography=$MON_CRYPTO"
note "anchor_image:  $ANC_IMG ($(docker image inspect "$ANC_IMG" --format '{{.Id}}'))"
BUILT_MON_SHA=$(docker run --rm --entrypoint sha256sum "$MON_IMG" /app/monitor.py | cut -d' ' -f1)
BUILT_ANC_SHA=$(docker run --rm --entrypoint sha256sum "$ANC_IMG" /app/anchord.py | cut -d' ' -f1)
BUILT_LNK_SHA=$(docker run --rm --entrypoint sha256sum "$ANC_IMG" /app/anchord_linked.py | cut -d' ' -f1)
note "in_image_sha256: monitor.py=$BUILT_MON_SHA anchord.py=$BUILT_ANC_SHA anchord_linked.py=$BUILT_LNK_SHA"
note "repo_sha256_16: monitor.py=$(s16 $REPO/monitor/monitor.py) anchord.py=$(s16 $REPO/testbed/anchord/anchord.py) anchord_linked.py=$(s16 $REPO/testbed/anchord/anchord_linked.py) headwitness.py(run copy)=$(s16 $SP/code/headwitness.py) chainverify.py=$(s16 $REPO/testbed/anchord/chainverify.py)"
note "repo_sha256_16: e7_verify.py=$(s16 $REPO/exp/stages/e7_verify.py) e8_score.py=$(s16 $REPO/exp/stages/e8_score.py) homeprov_ec=$(s16 $CC/homeprov_ec/__init__.py) homeprov_e7=$(s16 $CC/homeprov_e7/__init__.py) stress_publisher.py=$(s16 $REPO/testbed/e8/stress_publisher.py) run_e8.sh=$(s16 $0)"
note "hub_configuration_yaml_sha256: $HUB_CFG_SHA (restored byte for byte at teardown)"

# ---- keys: fresh, distinct; only fingerprints are recorded ------------------------------------------------------
KEY_STB=$(openssl rand -hex 32); KEY_CLO=$(openssl rand -hex 32)       # append keys (monitor <-> its anchor)
OKEY_STB=$(openssl rand -hex 32); OKEY_CLO=$(openssl rand -hex 32)     # operator keys (markers only)
WKEY_STB=$(openssl rand -hex 32); WKEY_CLO=$(openssl rand -hex 32)     # witness keys (anchor <-> its witness)
n_distinct=$(printf '%s\n' "$KEY_STB" "$KEY_CLO" "$OKEY_STB" "$OKEY_CLO" "$WKEY_STB" "$WKEY_CLO" | awk 'length($0)==64' | sort -u | wc -l | tr -d ' ')
[ "$n_distinct" = "6" ] || { note "FAIL: key generation ($n_distinct distinct 64-hex keys)"; exit 5; }
note "stable:  append_key_fp=$(fp16 "$KEY_STB") operator_key_fp=$(fp16 "$OKEY_STB") witness_key_fp=$(fp16 "$WKEY_STB") (sha256(hex)[:16]; keys not recorded)"
note "closure: append_key_fp=$(fp16 "$KEY_CLO") operator_key_fp=$(fp16 "$OKEY_CLO") witness_key_fp=$(fp16 "$WKEY_CLO") (sha256(hex)[:16]; keys not recorded)"

WPID_STB=""; WPID_CLO=""
witness_get() { "$PY" -c 'import sys,urllib.request;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())' "http://127.0.0.1:$1$2" 2>/dev/null; }
stop_witness() {   # $1 = pid var name, $2 = port, $3 = dir
  local pid=${!1}
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    [ -s "$3/head_final.json" ] || witness_get "$2" /head > "$3/head_at_teardown.json"
    kill "$pid"; sleep 1; kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
    note "witness $pid (port $2) stopped"
  fi
  eval "$1=''"
}

restore() {
  note "teardown: saving logs, removing the E8 containers, restoring the hub configuration and the stock monitor/anchor"
  for c in $MSTB $MCLO $ASTB $ACLO $STRESS_C; do
    docker ps -a --format '{{.Names}}' | grep -qx "$c" && docker logs "$c" > "$SP/log_$c.txt" 2>&1
  done
  docker rm -f "$STRESS_C" >/dev/null 2>&1
  docker rm -f "$MSTB" "$MCLO" "$ASTB" "$ACLO" >/dev/null 2>&1
  stop_witness WPID_STB "$WPORT_STB" "$SP/witness_stb"
  stop_witness WPID_CLO "$WPORT_CLO" "$SP/witness_clo"
  # the private signing keys never leave their volumes; destroyed here (only the public keys are kept, in $SP/keys)
  docker volume rm "$V-stb-sign" "$V-clo-sign" >/dev/null 2>&1 && note "signing-key volumes destroyed"
  docker network rm "$WNET" >/dev/null 2>&1
  docker rm -f "${PREFIX}r-$TAG-hass" >/dev/null 2>&1; docker volume rm "${PREFIX}r-$TAG-config" >/dev/null 2>&1
  docker network rm "${PREFIX}r-$TAG-net" >/dev/null 2>&1
  # the hub: no attack integration left, configuration.yaml exactly as it was
  if docker ps --format '{{.Names}}' | grep -qx "$HUB"; then
    local changed=0
    docker exec "$HUB" sh -c "test -e /config/custom_components/homeprov_ec || test -e /config/custom_components/homeprov_e7" && changed=1
    docker exec "$HUB" rm -rf /config/custom_components/homeprov_ec /config/custom_components/homeprov_e7 2>/dev/null
    if [ "$(docker exec "$HUB" cat /config/configuration.yaml | shasum -a 256 | cut -d' ' -f1)" != "$HUB_CFG_SHA" ]; then
      docker cp "$SP/hub_configuration.yaml.orig" "$HUB:/config/configuration.yaml" >/dev/null && changed=1
    fi
    note "hub configuration.yaml sha256 now $(docker exec "$HUB" cat /config/configuration.yaml | shasum -a 256 | cut -c1-16) (orig ${HUB_CFG_SHA:0:16})"
    if [ $changed -eq 1 ]; then docker restart "$HUB" >/dev/null; note "hub restarted after removing a leftover integration"; fi
  fi
  if docker ps -a --format '{{.Names}}' | grep -qx "${STOCK_MON}-orig-e8"; then
    docker rename "${STOCK_MON}-orig-e8" "$STOCK_MON" >/dev/null 2>&1
    docker rename "${STOCK_ANC}-orig-e8" "$STOCK_ANC" >/dev/null 2>&1
    docker start "$STOCK_ANC" "$STOCK_MON" >/dev/null 2>&1
    note "restored: $(docker ps --format '{{.Names}}' | grep -E "^($STOCK_MON|$STOCK_ANC)$" | tr '\n' ' ')"
  fi
  note "load_at_teardown: $(uptime)"
}
trap restore EXIT
trap 'exit 130' INT TERM HUP

# ---- signing keys: generated INSIDE the monitor's own volume; only the public key leaves it -----------------------
for m in stb clo; do
  docker volume create "$V-$m-sign" >/dev/null
  fp=$(docker run --rm --name "${PREFIX}-$TAG-keygen-$m" -v "$V-$m-sign":/sign --entrypoint python "$MON_IMG" -c '
import hashlib, os
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519
k = ed25519.Ed25519PrivateKey.generate()
os.umask(0o077)
with open("/sign/monitor.pem", "wb") as fh:
    fh.write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
p = k.public_key()
with open("/sign/monitor.pub.pem", "wb") as fh:
    fh.write(p.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
print(hashlib.sha256(p.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).hexdigest())' 2>&1 | tail -1)
  [ ${#fp} -eq 64 ] || { note "FAIL: signing key generation for $m ($fp)"; exit 5; }
  docker run --rm -v "$V-$m-sign":/sign:ro alpine:3 cat /sign/monitor.pub.pem > "$SP/keys/${m}_sign_pub.pem"
  eval "SIGFP_${m}=$fp"
  note "$m: signing public key fingerprint (sha256 of the raw 32-byte Ed25519 key) $fp; public key at $SP/keys/${m}_sign_pub.pem; private key only in volume $V-$m-sign"
done

# ---- the two head witnesses: python3 processes on the Mac, outside Docker's VM, loopback only ---------------------
start_witness() {   # $1 m, $2 port, $3 key
  local d="$SP/witness_$1"
  WITNESS_LOG="$d/heads.jsonl" WITNESS_FORKS="$d/forks.jsonl" HOMEPROV_WITNESS_KEY="$3" WITNESS_DIR="$d" \
    nohup "$PY" -u -c 'import sys; sys.path.insert(0, sys.argv[1]); import headwitness as W; W.serve(host="127.0.0.1", port=int(sys.argv[2]))' \
    "$SP/code" "$2" > "$d/witness.log" 2>&1 &
  local pid=$! n=0
  until grep -q READY "$d/witness.log" 2>/dev/null || [ $n -ge 20 ]; do sleep 0.5; n=$((n+1)); done
  grep -q READY "$d/witness.log" || { note "FAIL: witness $1 did not start ($(tail -3 "$d/witness.log" | tr '\n' ' '))"; exit 5; }
  eval "WPID_$(echo "$1" | tr a-z A-Z)=$pid"
  note "witness $1: pid=$pid bind=127.0.0.1:$2 code=$SP/code/headwitness.py ($(s16 "$SP/code/headwitness.py")) python=$("$PY" --version 2>&1) head=$(witness_get "$2" /head)"
}
start_witness stb "$WPORT_STB" "$WKEY_STB"
start_witness clo "$WPORT_CLO" "$WKEY_CLO"

# ---- anchors (linked, operator key, tagged replies, sync witness pushes) and monitors ---------------------------
note "stopping+renaming the stock monitor and anchor (restored on exit)"
docker stop "$STOCK_MON" "$STOCK_ANC" >/dev/null 2>&1 || true
docker rename "$STOCK_ANC" "${STOCK_ANC}-orig-e8" >/dev/null 2>&1 || true
docker rename "$STOCK_MON" "${STOCK_MON}-orig-e8" >/dev/null 2>&1 || true
for v in $VOLS; do docker volume create "$v" >/dev/null; done
docker network create "$WNET" >/dev/null || { note "FAIL: network $WNET"; exit 5; }
start_anchor() {   # $1 name, $2 alias, $3 m, $4 append key, $5 operator key, $6 witness key, $7 witness port
  docker run -d --name "$1" --network "$NET" --network-alias "$2" \
    -e HOMEPROV_ANCHOR_KEY="$4" -e HOMEPROV_OPERATOR_KEY="$5" -e HOMEPROV_ANCHOR_LINK=v2 \
    -e HOMEPROV_WITNESS_KEY="$6" -e HEAD_WITNESS_URL="http://host.docker.internal:$7/head" -e HEAD_WITNESS_MODE=sync \
    -v "$V-$3-chain":/anchor -v "$V-$3-pub":/published "$ANC_IMG" >/dev/null || { note "FAIL: anchor $1"; exit 5; }
  docker network connect "$WNET" "$1" || { note "FAIL: connecting $1 to $WNET"; exit 5; }
  sleep 2
  local r; r=$(docker exec "$1" python -c "import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:$7/head',timeout=5).status)" 2>&1 | tail -1)
  note "$1: witness reachable from the anchor container: $r"
  [ "$r" = "200" ] || { note "FAIL: $1 cannot reach its witness"; exit 7; }
}
start_anchor "$ASTB" anchor-stb stb "$KEY_STB" "$OKEY_STB" "$WKEY_STB" "$WPORT_STB"
start_anchor "$ACLO" anchor-clo clo "$KEY_CLO" "$OKEY_CLO" "$WKEY_CLO" "$WPORT_CLO"
start_monitor() {   # $1 name, $2 alias, $3 m, $4 scheme, $5 anchor alias, $6 append key
  docker run -d --name "$1" --network "$NET" --network-alias "$2" \
    -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR="http://$5:9900/append" \
    -e HOMEPROV_PERIOD="$PERIOD" -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$6" \
    -e HOMEPROV_SCHEME="$4" -e HOMEPROV_COVERAGE=1 -e HOMEPROV_ESCROW_DIR=/escrow -e HOMEPROV_COST_LOG=/scratch/cost.jsonl \
    -e HOMEPROV_SIGN_KEY=/sign/monitor.pem -e HOMEPROV_REPLY_TAGS=1 \
    -v "$CFGVOL":/cfg:ro -v "$V-$3-scratch":/scratch -v "$SP/escrow_$3":/escrow -v "$V-$3-sign":/sign:ro \
    "$MON_IMG" >/dev/null || { note "FAIL: monitor $1"; exit 5; }
}
start_monitor "$MSTB" monitor-stb stb stable anchor-stb "$KEY_STB"
start_monitor "$MCLO" monitor-clo clo closure anchor-clo "$KEY_CLO"
note "anchors: $(docker inspect "$ASTB" --format '{{.Config.Image}} {{json .Config.Cmd}}'); monitors: stb=$(docker inspect "$MSTB" --format '{{.State.Status}}') clo=$(docker inspect "$MCLO" --format '{{.State.Status}}')"
sleep 20

# The hub (the adversary's position) tries each anchor without the key and with a forged tag, for a record and for a
# marker, and tries to reach the witness (it should have no route: the hub's network is internal).
PROBE='import urllib.request,urllib.error,json,sys
def post(u,b,h):
    r=urllib.request.Request(u,data=b,method="POST",headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:60]
def get(u):
    try:
        with urllib.request.urlopen(u,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:60]
J={"Content-Type":"application/json"}; F=dict(J,**{"X-HP-Auth":"0"*64})
rec=b"{\"sealed\": {}}"; mk=json.dumps({"observer":"operator-marker-issuer","marker":{"marker":"MIGRATE"},"marker_tag":"0"*64},sort_keys=True).encode()
out={a:{"record_untagged":post("http://%s:9900/append"%a,rec,J),"record_forged":post("http://%s:9900/append"%a,rec,F),
        "marker_untagged":post("http://%s:9900/append"%a,mk,J),"marker_forged":post("http://%s:9900/append"%a,mk,F)}
     for a in ("anchor-stb","anchor-clo")}
out["witness_from_hub"]={p:get("http://host.docker.internal:%s/head"%p) for p in sys.argv[1:]}
print(json.dumps(out))'
note "probe_from_hub: $(docker exec "$HUB" python3 -c "$PROBE" "$WPORT_STB" "$WPORT_CLO" 2>&1 | tail -1)"

# OPERATOR-KEY PROBE (E8 A3/A4), from a throwaway container on the deployment network holding the keys in its
# environment only: a marker tagged with the APPEND key must be refused, a record tagged with the OPERATOR key must be
# refused, and an operator-tagged MIGRATE marker in rig.marker_issuer's record format (inert: rig.markers.explains()
# excuses nothing for MIGRATE, and rig.marker_issuer.markers_from_chain() keeps PURGE markers only) accepted;
# every reply's X-HP-Reply-Auth is checked under the key that tagged the request.
if [ "$OPERATOR_PROBE" = "1" ]; then
  OPROBE='import hashlib,hmac,json,os,sys,time,urllib.request,urllib.error
D=b"homeprov-anchor-reply-v1\n"
def tag(k,b): return hmac.new(k,b,hashlib.sha256).hexdigest()
def post(u,body,key):
    t=tag(key,body); r=urllib.request.Request(u,data=body,method="POST",headers={"Content-Type":"application/json","X-HP-Auth":t})
    try:
        with urllib.request.urlopen(r,timeout=10) as x: st,raw,h=x.status,x.read(),x.headers.get("X-HP-Reply-Auth")
    except urllib.error.HTTPError as e: st,raw,h=e.code,e.read() or b"",e.headers.get("X-HP-Reply-Auth") if e.headers else None
    want=hmac.new(key,D+t.encode()+b"\n"+str(st).encode()+b"\n"+raw,hashlib.sha256).hexdigest()
    try: reason=json.loads(raw).get("reason") or json.loads(raw).get("error")
    except Exception: reason=None
    return {"status":st,"reason":reason,"reply_tag_ok":bool(h) and hmac.compare_digest(h,want)}
out={}
for a,ak,ok in (("anchor-stb",os.environ["AK_STB"],os.environ["OK_STB"]),("anchor-clo",os.environ["AK_CLO"],os.environ["OK_CLO"])):
    ak,ok=ak.encode(),bytes.fromhex(ok)        # append key: the raw string (as the monitor holds it); operator key: hex-decoded (as rig.marker_issuer reads its key file)
    u="http://%s:9900/append"%a
    m={"marker":"MIGRATE","probe":"E8 operator-key probe; MIGRATE excuses no violation","ts":time.time()}
    def mk(key): return json.dumps({"observer":"operator-marker-issuer","marker":m,"marker_tag":tag(key,json.dumps(m,sort_keys=True).encode())},sort_keys=True).encode()
    out[a]={"marker_with_append_key":post(u,mk(ak),ak),
            "record_with_operator_key":post(u,json.dumps({"sealed":{}},sort_keys=True).encode(),ok),
            "marker_with_operator_key":post(u,mk(ok),ok)}
print(json.dumps(out,sort_keys=True))'
  note "operator_probe: $(docker run --rm --name "${PREFIX}-$TAG-oprobe" --network "$NET" -e AK_STB="$KEY_STB" -e OK_STB="$OKEY_STB" -e AK_CLO="$KEY_CLO" -e OK_CLO="$OKEY_CLO" --entrypoint python "$ANC_IMG" -c "$OPROBE" 2>&1 | tail -1)"
fi
sleep 40
for m in stb clo; do
  a=$ASTB; [ $m = clo ] && a=$ACLO
  note "$m chain before run: $(docker exec "$a" sh -c 'wc -l < /anchor/chain.jsonl' 2>/dev/null) records; witness head $(witness_get $([ $m = stb ] && echo $WPORT_STB || echo $WPORT_CLO) /head)"
done
note "monitor_log_head stb: $(docker logs "$MSTB" 2>&1 | head -2 | cut -c1-300 | tr '\n' ' ')"

# ---- the attack integrations ------------------------------------------------------------------------------------
install_components() {   # copy both packages (homeprov_e7 imports homeprov_ec's helpers); enable neither yet
  for comp in homeprov_ec homeprov_e7; do
    docker exec "$HUB" mkdir -p "/config/custom_components/$comp"
    docker cp "$CC/$comp/." "$HUB:/config/custom_components/$comp/" >/dev/null
    docker exec "$HUB" rm -rf "/config/custom_components/$comp/__pycache__"
    docker exec "$HUB" test -f "/config/custom_components/$comp/__init__.py" || { note "FAIL: $comp did not land"; exit 1; }
  done
}
activate() {   # $1 = homeprov_ec | homeprov_e7 | none: exactly one listed in configuration.yaml, then restart
  docker exec "$HUB" sh -c "sed -i '/^homeprov_ec:/d;/^homeprov_e7:/d' /config/configuration.yaml"
  [ "$1" != "none" ] && docker exec "$HUB" sh -c "printf '\n$1:\n' >> /config/configuration.yaml"
  docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"
}
uninstall_components() {
  docker exec "$HUB" rm -rf /config/custom_components/homeprov_ec /config/custom_components/homeprov_e7
  docker cp "$SP/hub_configuration.yaml.orig" "$HUB:/config/configuration.yaml" >/dev/null
  docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"
}
run_component() {   # $1 comp, $2 room, $3 arms json, $4 trials, $5 out file name, $6 timeout s
  local comp=$1 room=$2 conf ack rep
  if [ "$comp" = homeprov_ec ]; then conf=/config/.hpr_ec_conf; ack=ec_ack.json; rep=ec_report.json
    printf '{"trials": %s, "arms": [%s], "seal_wait_s": %s, "room": "%s"}' "$4" "$3" "$SEAL_WAIT_S" "$room" > "$SP/.conf"
  else conf=/config/.hpr_e7_conf; ack=e7_ack.json; rep=e7_report.json
    printf '{"trials": %s, "arms": [%s], "seal_wait_s": %s, "room": "%s", "K": %s, "bd_lookback_s": %s, "bd_min_age_s": %s, "anchor_host": "anchor-stb", "anchor_port": 9900}' \
      "$4" "$3" "$SEAL_WAIT_S" "$room" "$K" "$BD_LOOKBACK_S" "$BD_MIN_AGE_S" > "$SP/.conf"
  fi
  docker exec "$HUB" sh -c "printf '%s' '$room' > /config/.hpr_room"
  docker cp "$SP/.conf" "$HUB:$conf" >/dev/null
  docker exec "$HUB" rm -f "$MK/$ack" "$MK/$rep" 2>/dev/null
  note "  $comp [$3] x$4 in $room: starting"
  activate "$comp"
  local end=$((SECONDS + $6))
  while [ $SECONDS -lt $end ]; do
    if docker exec "$HUB" test -f "$MK/$ack" 2>/dev/null; then
      note "  ack $comp $room: $(docker exec "$HUB" cat "$MK/$ack")"; break
    fi
    sleep 5
  done
  [ $SECONDS -ge $end ] && note "  TIMEOUT: $comp in $room"
  docker cp "$HUB:$MK/$rep" "$OUT/$5" >/dev/null 2>&1 && note "  -> $OUT/$5" || note "  (no report for $comp in $room)"
}

# ---- phase 1: the arms ------------------------------------------------------------------------------------------
if [ "$SKIP_MAIN" != "1" ]; then
  date -u +%s > "$OUT/${TAG}_t_start"
  install_components
  for room in $ROOMS; do
    note "-- configuration: $room --"
    run_component homeprov_ec "$room" "$EC_ARMS" "$TRIALS" "${TAG}_report_ec_${room}.json" 5400
    run_component homeprov_e7 "$room" "$E7_ARMS" "$TRIALS" "${TAG}_report_e7_${room}.json" 3600
  done
  activate none
  date -u +%s > "$OUT/${TAG}_t_end"
  note "phase 1 done; load: $(uptime)"
fi

# ---- phase 2: baseline at the lab rate, then the write-rate stress with a PU arm --------------------------------
if [ "$SKIP_STRESS" != "1" ]; then
  note "settling 90s"; sleep 90
  date -u +%s > "$OUT/${TAG}_base_t_start"; note "baseline window (lab rate, no trials): ${BASELINE_S}s"
  sleep "$BASELINE_S"
  date -u +%s > "$OUT/${TAG}_base_t_end"
  note "baseline done; load: $(uptime)"
  docker run -d --name "$STRESS_C" --network "$NET" -e HPR_BROKER=broker -e HPR_STRESS_FACTOR="$STRESS_FACTOR" \
    -v "$REPO/testbed/e8/stress_publisher.py":/stress.py:ro --entrypoint python "$DEV_IMG" -u /stress.py >/dev/null \
    || { note "FAIL: stress publisher"; exit 5; }
  S0=$(date -u +%s); echo "$S0" > "$OUT/${TAG}_stress_t_start"
  note "stress publisher $STRESS_C started (factor $STRESS_FACTOR, image $DEV_IMG); ramp ${STRESS_RAMP_S}s"
  sleep "$STRESS_RAMP_S"
  docker exec "$HUB" test -f /config/custom_components/homeprov_ec/__init__.py || install_components
  for room in $STRESS_ROOMS; do
    run_component homeprov_ec "$room" "$STRESS_ARMS" "$STRESS_TRIALS" "${TAG}_stress_report_${room}.json" 3600
  done
  # no restart inside the window: the component has finished and only runs again on a restart; it is switched off by
  # uninstall_components after the window
  left=$((S0 + STRESS_S - $(date -u +%s)))
  [ $left -gt 0 ] && { note "stress continues ${left}s to the end of the fixed window"; sleep $left; } \
    || note "the arm overran the fixed window by $((-left))s; the window ends now"
  note "stress publisher: $(docker logs "$STRESS_C" 2>&1 | tail -1)"
  docker stop -t 10 "$STRESS_C" >/dev/null
  date -u +%s > "$OUT/${TAG}_stress_t_end"
  docker logs "$STRESS_C" > "$SP/stress_publisher.log" 2>&1
  note "stress done: $(docker logs "$STRESS_C" 2>&1 | tail -1); load: $(uptime)"
fi
uninstall_components

# ---- freeze: recorder snapshot, then stop the only appenders, then chains, witness logs, costs, escrow ----------
note "settling 90s so the final segments seal and anchor on both monitors"; sleep 90
note "taking a consistent recorder snapshot (SQLite backup API, inside the hub)"
docker exec "$HUB" rm -f /config/.e8_snap.db 2>/dev/null
docker exec "$HUB" python3 -c "import sqlite3;s=sqlite3.connect('/config/home-assistant_v2.db',timeout=120);d=sqlite3.connect('/config/.e8_snap.db');s.backup(d);d.close();s.close();print('ok')" >/dev/null
date -u +%s > "$SP/snapshot_at"
docker cp "$HUB:/config/.e8_snap.db" "$SP/recorder.db" >/dev/null
docker exec "$HUB" rm -f /config/.e8_snap.db 2>/dev/null
sleep 30          # one more seal of the seconds up to the snapshot
docker stop "$MSTB" "$MCLO" >/dev/null 2>&1
sleep 8           # past the anchor's witness-push timeout: the last head has reached its witness or failed
for m in stb clo; do
  a=$ASTB; p=$WPORT_STB; [ $m = clo ] && { a=$ACLO; p=$WPORT_CLO; }
  witness_get $p /head > "$SP/witness_$m/head_final.json"
  witness_get $p /log > "$SP/witness_$m/log_final.json"
  docker exec "$a" cat /anchor/chain.jsonl > "$SP/${m}_chain.jsonl"
  docker exec "$a" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/${m}_refusals.jsonl"
  docker exec "$a" sh -c 'cat /published/head.json 2>/dev/null' > "$SP/${m}_anchor_published_head.json"
  docker cp "$( [ $m = stb ] && echo $MSTB || echo $MCLO ):/scratch/cost.jsonl" "$SP/${m}_cost.jsonl" >/dev/null 2>&1 || note "no $m cost log"
  docker logs "$( [ $m = stb ] && echo $MSTB || echo $MCLO )" > "$SP/${m}_monitor.log" 2>&1
  docker logs "$a" > "$SP/${m}_anchord.log" 2>&1
  note "$m: chain $(wc -l < "$SP/${m}_chain.jsonl" | tr -d ' ') records, witness head $(cat "$SP/witness_$m/head_final.json"), heads logged $(wc -l < "$SP/witness_$m/heads.jsonl" | tr -d ' '), forks $(cat "$SP/witness_$m/forks.jsonl" 2>/dev/null | wc -l | tr -d ' '), refusals $(wc -l < "$SP/${m}_refusals.jsonl" | tr -d ' '), escrow lines $(cat "$SP/escrow_$m/"* 2>/dev/null | wc -l | tr -d ' ')"
done
stop_witness WPID_STB "$WPORT_STB" "$SP/witness_stb"
stop_witness WPID_CLO "$WPORT_CLO" "$SP/witness_clo"
gzip -c "$SP/stb_chain.jsonl" > "$OUT/${TAG}_stable_chain.jsonl.gz"
gzip -c "$SP/clo_chain.jsonl" > "$OUT/${TAG}_closure_chain.jsonl.gz"
gzip -c "$SP/witness_stb/heads.jsonl" > "$OUT/${TAG}_stable_witness_heads.jsonl.gz"
gzip -c "$SP/witness_clo/heads.jsonl" > "$OUT/${TAG}_closure_witness_heads.jsonl.gz"
[ -s "$SP/escrow_stb/escrow.jsonl" ] && gzip -c "$SP/escrow_stb/escrow.jsonl" > "$OUT/${TAG}_stable_escrow.jsonl.gz"
[ -s "$SP/escrow_clo/escrow.jsonl" ] && gzip -c "$SP/escrow_clo/escrow.jsonl" > "$OUT/${TAG}_closure_escrow.jsonl.gz"
note "recorder snapshot sha256 $(s16 $SP/recorder.db) at $(cat $SP/snapshot_at)"

# ---- score ------------------------------------------------------------------------------------------------------
score() {
  E8_SP="$SP" E8_OUT="$OUT" E8_LATE_BOUND="$LATE_BOUND_S" E8_GAP_S="$GAP_S" "$PY" "$REPO/exp/stages/e8_score.py" --tag "$TAG" \
    --rooms $ROOMS --stress-rooms $STRESS_ROOMS "$@"
}
if [ "$RECOVERY_RENDER" = "1" ]; then
  note "scoring (verify only, with the closure monitor's restored copy)"
  score --verify-only --restore-out "$SP/restored_closure.db" > "$SP/score_pass1.log" 2>&1
  note "verify exit: $?"
  # E7's recovery render: the restored copy rendered by the release's logbook processor in a throwaway hub
  # (${PREFIX}r-, the hub's own image, isolated internal network), through homeprov_e7's RENDER mode.
  if [ -s "$SP/restored_closure.db" ]; then
    "$PY" - "$OUT" "$TAG" "$SP/render_targets.json" $ROOMS <<'PY'
import json, os, sys
out, tag, dst, rooms = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
tg = []
for room in rooms:
    for kind in ("ec", "e7"):
        f = os.path.join(out, "%s_report_%s_%s.json" % (tag, kind, room))
        if not os.path.exists(f):
            continue
        for t in json.load(open(f)).get("trials", []):
            if t.get("err") or t.get("error") or not t.get("judged_when") or "clean_principal" not in t:
                continue
            tg.append({"key": "%s/%s/%s" % (room, t["arm"], t["trial"]), "arm_of_trial": t["arm"], "room": room,
                       "trial": t["trial"], "when": t["judged_when"], "clean_principal": t["clean_principal"],
                       "clean_named_user_id": t.get("clean_named_user_id")})
json.dump(tg, open(dst, "w"), indent=1)
PY
    RR_HUB=${PREFIX}r-$TAG-hass; RR_VOL=${PREFIX}r-$TAG-config; RR_NET=${PREFIX}r-$TAG-net
    docker network create --internal "$RR_NET" >/dev/null 2>&1; docker volume create "$RR_VOL" >/dev/null
    docker run --rm -v "$CFGVOL":/src:ro -v "$RR_VOL":/dst -v "$SP":/run:ro -v "$CC":/cc:ro alpine:3 sh -c \
      'cd /src && tar --exclude="./home-assistant_v2.db*" -cf - . | tar -C /dst -xf - && cp /run/restored_closure.db /dst/home-assistant_v2.db \
       && rm -rf /dst/custom_components/homeprov_e7 /dst/custom_components/homeprov_ec /dst/homeprov_out \
       && mkdir -p /dst/homeprov_out && cp -r /cc/homeprov_e7 /cc/homeprov_ec /dst/custom_components/ \
       && rm -rf /dst/custom_components/*/__pycache__ && cp /run/hub_configuration.yaml.orig /dst/configuration.yaml \
       && printf "\nhomeprov_e7:\n" >> /dst/configuration.yaml' || note "recovery render: seeding failed"
    "$PY" -c "import json,sys;print(json.dumps({'arms':['RENDER'],'trials':0,'render_targets':json.load(open(sys.argv[1]))}))" \
      "$SP/render_targets.json" > "$SP/.rr_conf"
    docker run --rm -v "$RR_VOL":/dst -v "$SP/.rr_conf":/c.json:ro alpine:3 cp /c.json /dst/.hpr_e7_conf
    docker run -d --name "$RR_HUB" --network "$RR_NET" -e TZ=UTC -v "$RR_VOL":/config "$(docker inspect "$HUB" --format '{{.Config.Image}}')" >/dev/null
    end=$((SECONDS+900))
    while [ $SECONDS -lt $end ]; do docker exec "$RR_HUB" test -f /config/homeprov_out/e7_ack.json 2>/dev/null && break; sleep 5; done
    docker cp "$RR_HUB:/config/homeprov_out/e7_report.json" "$SP/recovery_render_raw.json" >/dev/null 2>&1 || note "recovery render: no report"
    docker rm -f "$RR_HUB" >/dev/null 2>&1; docker volume rm "$RR_VOL" >/dev/null 2>&1; docker network rm "$RR_NET" >/dev/null 2>&1
  fi
fi
note "scoring with exp/stages/e8_score.py (LATE_BOUND=${LATE_BOUND_S}s GAP_S=${GAP_S}s)"
score > "$SP/score.log" 2>&1
note "score exit: $? ($(tail -25 "$SP/score.log" | tr '\n' ' ' | cut -c1-1500))"

"$PY" - "$SP" "$OUT" "$TAG" "$0" "$MON_IMG" "$ANC_IMG" "$BUILT_MON_SHA" "$BUILT_ANC_SHA" "$BUILT_LNK_SHA" "$LATE_BOUND_S" "$GAP_S" <<'PY'
import glob, hashlib, json, os, sys
sp, out, tag, script, mon_img, anc_img, b_mon, b_anc, b_lnk, lb, gap = sys.argv[1:]
R = __import__("os").environ["ARTIFACT_ROOT"]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
nlines = lambda p: sum(1 for l in open(p) if l.strip()) if os.path.exists(p) else None
cfg = {"experiment": f"{tag}: E8 part C on the default deployment: arms PU, PI, PSR, P (homeprov_ec) and INS-L, INS-M, "
                     "BD-S (homeprov_e7), then a lab-rate baseline and a write-rate stress window with a PU arm, under "
                     "the stable-columns monitor (evaluated) and the closure monitor (alongside), each with coverage, "
                     "escrow, Ed25519 record signatures and tagged anchor replies, its own linked anchor (append key + "
                     "separate operator key) and a head witness on the Mac outside Docker's VM",
       "verifier_parameters": {"late_bound_s": float(lb), "gap_s": float(gap), "verifier": "exp/stages/e7_verify.py",
                               "e7_verify_py_sha256": h(f"{R}/exp/stages/e7_verify.py")},
       "monitors": {"stable": {"image": mon_img, "scheme": "stable", "evaluated": True},
                    "closure": {"image": mon_img, "scheme": "closure", "evaluated": False},
                    "both": "HOMEPROV_COVERAGE=1, HOMEPROV_ESCROW_DIR, HOMEPROV_COST_LOG, HOMEPROV_SIGN_KEY, HOMEPROV_REPLY_TAGS=1"},
       "anchor": {"image": anc_img, "dockerfile": "testbed/e8/anchord-e8.Dockerfile", "entry": "anchord_linked.py",
                  "link": "v2", "operator_key": True, "head_witness_mode": "sync"},
       "in_image_sha256": {"monitor.py": b_mon, "anchord.py": b_anc, "anchord_linked.py": b_lnk},
       "code_sha256": {p: h(f"{R}/{p}") for p in (
           "monitor/monitor.py", "testbed/anchord/anchord.py", "testbed/anchord/anchord_linked.py",
           "testbed/anchord/headwitness.py", "testbed/anchord/chainverify.py", "exp/stages/e7_verify.py",
           "exp/stages/e8_score.py", "testbed/e8/stress_publisher.py", "testbed/e8/anchord-e8.Dockerfile",
           "testbed/real/ha-config/custom_components/homeprov_ec/__init__.py",
           "testbed/real/ha-config/custom_components/homeprov_e7/__init__.py")},
       "witness_code_sha256_as_run": h(f"{sp}/code/headwitness.py"),
       "signing_public_keys": {m: {"pem_sha256": h(f"{sp}/keys/{m}_sign_pub.pem"), "path_in_run_dir": f"keys/{m}_sign_pub.pem"}
                               for m in ("stb", "clo")},
       "configuration_log": [l.rstrip("\n") for l in open(f"{sp}/auth_meta.log")],
       "chains": {m: {"file": f"exp/out/{tag}_{name}_chain.jsonl.gz", "records": nlines(f"{sp}/{m}_chain.jsonl"),
                      "sha256_uncompressed": h(f"{sp}/{m}_chain.jsonl")} for m, name in (("stb", "stable"), ("clo", "closure"))},
       "witness_heads": {m: {"file": f"exp/out/{tag}_{name}_witness_heads.jsonl.gz",
                             "heads": nlines(f"{sp}/witness_{m}/heads.jsonl"),
                             "sha256_uncompressed": h(f"{sp}/witness_{m}/heads.jsonl")}
                         for m, name in (("stb", "stable"), ("clo", "closure"))},
       "recorder_snapshot_sha256": h(f"{sp}/recorder.db"),
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "x"), indent=1)
print("wrote", f"{out}/{tag}_config.json")
PY
note "done; results under $OUT/${TAG}_* and the run directory $SP"
