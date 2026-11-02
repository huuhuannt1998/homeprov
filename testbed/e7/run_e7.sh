#!/bin/bash
# E7 (round 13): one real-deployment run of the coverage-gap, backdating and anchor-stall arms, against the DEFAULT
# deployment (hpr-hass, hpr-devices, hpr-broker), under TWO monitors in parallel -- the E7 closure monitor (row
# watermark + sealed-through + escrow, the evaluated configuration) and a stable-columns monitor -- each with its OWN
# hardened anchor and a FRESH append key (only key fingerprints are recorded). Arms: INS-L, INS-M, BD-S, BD-M, STALL
# (homeprov_e7), 30 trials each where feasible (10 per configuration, the three motion-light rooms).
#
# Arms: INS-L (laundering of a household member's unlock + K>=9 rows inserted into the edited second after its seal),
# INS-M (member-account swap + K rows), BD-S / BD-M (forged unlock backdated >=120 s into an empty sealed second /
# minute), STALL (live: the hub holds reconnecting slow connections to the anchor across the seal, then edits), and
# OUTAGE (SIMULATED: this script pauses this run's e7 closure anchor for 90 s while the edited second seals).
# Verifier: exp/stages/e7_verify.py with the pre-registered LATE_BOUND = 30 s and GAP_S = 30 s (via e7_score.py).
#
#   Usage (the LEAD runs this; the E2 night has been stopped, the preflight still checks for it):
#       nohup testbed/e7/run_e7.sh e7_main > ~/Research/HOMEPROV-P13-exp/e7/e7_main.out 2>&1 &
#
# It stops+renames the stock monitor and anchor (restored by the EXIT trap, as run_clo_grace.sh does), starts the two
# E7 monitor/anchor pairs reading the shared config volume, runs the arms per configuration, snapshots the recorder,
# saves both chains, both monitor logs and the escrow, then scores with exp/stages/e7_score.py. Never overwrites an
# existing output. The stock deployment's hub/devices/broker are not removed.
#
# Scratch testing: every target is overridable by env (see the block below), so the SAME script drives a throwaway
# e7d- stack. HPR_E7_SCRATCH=1 skips the E2-night guard (which only protects the shared real deployment).
set -u

# ---- targets (real-deployment defaults; overridden for the scratch stack) ---------------------------------------
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
OUT=$REPO/exp/out
CC=$REPO/testbed/real/ha-config/custom_components
HUB=${HPR_E7_HUB:-hpr-hass}
NET=${HPR_E7_NET:-homeprov-real_hp-real}
CFGVOL=${HPR_E7_CFGVOL:-homeprov-real_hpr-config}
DEVICES=${HPR_E7_DEVICES:-hpr-devices}
STOCK_MON=${HPR_E7_STOCK_MONITOR:-hpr-monitor}
STOCK_ANC=${HPR_E7_STOCK_ANCHOR:-hpr-anchord}
PREFIX=${HPR_E7_PREFIX:-e7}
MON_IMG=${HPR_E7_MONITOR_IMAGE:-hpr-monitor:e7}
ANC_IMG=${HPR_E7_ANCHOR_IMAGE:-hpr-anchord:e7}
SCRATCH_MODE=${HPR_E7_SCRATCH:-0}
RESTART_WAIT=${HPR_E7_RESTART_WAIT:-45}

# ---- run parameters ---------------------------------------------------------------------------------------------
TAG=${1:?usage: run_e7.sh TAG}
TRIALS=${HPR_E7_TRIALS:-10}                              # per configuration; 3 rooms -> 30/arm
ROOMS=${HPR_E7_ROOMS:-porch hallway kitchen}
ARMS_JSON=${HPR_E7_ARMS:-"\"INS-L\",\"INS-M\",\"BD-S\",\"BD-M\",\"BD-PARK\",\"BD-JOIN\",\"BD-GAP\",\"STALL\""}   # OUTAGE is a separate phase (below)
OUTAGE_TRIALS=${HPR_E7_OUTAGE_TRIALS:-10}               # simulated anchor-outage trials (per configuration)
OUTAGE_SEAL_WAIT_S=${HPR_E7_OUTAGE_SEAL_WAIT_S:-25}     # hold the outage this long so the edited second seals while the e7 anchor is paused
K=${HPR_E7_K:-9}                                         # K>=9 rows inserted into the edited second
STALL_CONNS=${HPR_E7_STALL_CONNS:-8}
STALL_S=${HPR_E7_STALL_S:-40}                           # total stall interval (reconnecting; hardened anchor cuts each conn ~10s)
STALL_SEAL_WAIT_S=${HPR_E7_STALL_SEAL_WAIT_S:-25}       # hold the stall at least this long so the edited row's second seals DURING it
BD_LOOKBACK_S=${HPR_E7_BD_LOOKBACK_S:-1800}             # how far back BD scans for an empty SEALED window
BD_MIN_AGE_S=${HPR_E7_BD_MIN_AGE_S:-130}                # forged backdated row at least this old (> LATE_BOUND 30s + one poll)
BD_MOVE_DELAY_S=${HPR_E7_BD_MOVE_DELAY_S:-130}          # reserved-key variants: move the forged row this long after the target second
PAUSE_DEVICES_S=${HPR_E7_PAUSE_DEVICES_S:-200}          # pause the device simulator: >=2 full empty MINUTES per configuration for BD-M
SEAL_WAIT_S=${HPR_E7_SEAL_WAIT_S:-130}
PERIOD=${HPR_E7_PERIOD:-5}
LATE_BOUND_S=${HPR_E7_LATE_BOUND_S:-30}                 # pre-registered verifier parameter (lead, 2026-10-08)
GAP_S=${HPR_E7_GAP_S:-30}                               # pre-registered verifier parameter (lead, 2026-10-08)
RECOVERY_RENDER=${HPR_E7_RECOVERY_RENDER:-1}            # render e7_verify's --restore-out copy in a throwaway e7r- HA container
WANT_OUTAGE=${HPR_E7_WANT_OUTAGE:-1}                    # run the simulated anchor-outage phase

SP=${HPR_E7_SP:-<research-dir>/HOMEPROV-P13-exp/e7/$TAG}
ACLO=${PREFIX}-anchord-clo; MCLO=${PREFIX}-monitor-clo
ASTB=${PREFIX}-anchord-stb; MSTB=${PREFIX}-monitor-stb
VCLO_C=${PREFIX}-$TAG-clo-chain; VCLO_P=${PREFIX}-$TAG-clo-pub; VCLO_S=${PREFIX}-$TAG-clo-scratch
VSTB_C=${PREFIX}-$TAG-stb-chain; VSTB_P=${PREFIX}-$TAG-stb-pub; VSTB_S=${PREFIX}-$TAG-stb-scratch
ESCROW=$SP/escrow
META=$SP/auth_meta.log

# ---- refusals (nothing is created before these pass) ------------------------------------------------------------
[ -e "$SP" ] && { echo "REFUSING: $SP exists"; exit 3; }
for f in "${TAG}_t_start" "${TAG}_t_end" "${TAG}_score.json" "${TAG}_config.json" \
         "${TAG}_closure_chain.jsonl.gz" "${TAG}_stable_chain.jsonl.gz" \
         "${TAG}_report_porch.json" "${TAG}_report_hallway.json" "${TAG}_report_kitchen.json" \
         "${TAG}_recovery_render.json" "${TAG}_closure_verify.json" "${TAG}_stable_verify.json" "${TAG}_escrow.jsonl.gz"; do
  [ -e "$OUT/$f" ] && { echo "REFUSING: $OUT/$f exists"; exit 3; }
done
for c in $ACLO $MCLO $ASTB $MSTB; do
  docker ps -a --format '{{.Names}}' | grep -qx "$c" && { echo "REFUSING: container $c exists"; exit 3; }
done

preflight() {
  echo "== E7 preflight =="
  docker info >/dev/null 2>&1 || { echo "  FAIL docker daemon down"; exit 1; }
  # E2-NIGHT GUARD: refuse to start while the E2 night is still running (it owns the shared deployment until
  # 2026-10-09 05:00 UTC). Only meaningful for the real deployment.
  if [ "$SCRATCH_MODE" != "1" ]; then
    if docker ps -a --format '{{.Names}}' | grep -qx e2-issuer; then
      echo "  FAIL the e2-issuer container exists: the E2 night is running. Wait until it ends (2026-10-09 05:00 UTC)."
      exit 2
    fi
    if pgrep -fl 'HOMEPROV-P13-exp/e2night/driver.sh' >/dev/null 2>&1; then
      echo "  FAIL <research-dir>/HOMEPROV-P13-exp/e2night/driver.sh is running (the E2 night). Wait for it."
      exit 2
    fi
    echo "  ok    E2 night not running"
  else
    echo "  skip  E2-night guard (scratch mode)"
  fi
  # The hub, devices and broker of the target deployment must be up.
  for c in "$HUB" "$DEVICES"; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "  FAIL $c is not running"; exit 2; }
  done
  echo "  ok    hub ($HUB) and devices ($DEVICES) up"
  # MONITOR TESTS, then BUILD both images from the repository's CURRENT files, at run time, under the E7 tags only
  # (HPR_E7_BUILD_IMAGES=0 skips the build and uses the existing images; the hash checks below still apply).
  if [ "${HPR_E7_BUILD_IMAGES:-1}" = "1" ]; then
    if ! ( cd "$REPO" && python3 -m pytest -q monitor/test_coverage.py monitor/test_node_hash.py ) > /tmp/hpr_e7_pytest.log 2>&1; then
      echo "  FAIL monitor tests fail; refusing to start ($(tail -2 /tmp/hpr_e7_pytest.log | tr '\n' ' '))"; exit 2
    fi
    echo "  ok    monitor tests pass ($(tail -1 /tmp/hpr_e7_pytest.log))"
    docker build -q -t "$MON_IMG" "$REPO/monitor" >/dev/null || { echo "  FAIL docker build $MON_IMG"; exit 2; }
    docker build -q -t "$ANC_IMG" "$REPO/testbed/anchord" >/dev/null || { echo "  FAIL docker build $ANC_IMG"; exit 2; }
    echo "  ok    built $MON_IMG from monitor/ and $ANC_IMG from testbed/anchord/"
  fi
  # The monitor and anchor images must be the E7 versions. NOTE: build them ONLY under new tags (hpr-monitor:e7,
  # hpr-anchord:e7); NEVER run `docker compose build` in testbed/real -- that would re-tag the default deployment's
  # hpr-anchord:1 / hpr-monitor:1 with the E7 daemons (anchor agent, E7_ANCHOR_NOTES.md).
  for img in "$MON_IMG" "$ANC_IMG"; do
    docker image inspect "$img" >/dev/null 2>&1 || { echo "  FAIL image $img missing (build the E7 monitor/anchor first)"; exit 2; }
  done
  echo "  ok    images present: $MON_IMG, $ANC_IMG"
  # EXACT ANCHOR VERSION: the /app/anchord.py inside the anchor image must be byte-identical to the repository's
  # current hardened daemon (threaded, per-connection timeout, request deadline, 16 MiB body cap). Compared by sha256.
  local repo_anc img_anc
  repo_anc=$(shasum -a 256 "$REPO/testbed/anchord/anchord.py" | cut -d' ' -f1)
  img_anc=$(docker run --rm --entrypoint sh "$ANC_IMG" -c 'sha256sum /app/anchord.py 2>/dev/null' | cut -d' ' -f1)
  if [ "$repo_anc" != "$img_anc" ]; then
    if [ "$SCRATCH_MODE" = "1" ]; then
      echo "  WARN anchor image anchord.py sha ($img_anc) != repo ($repo_anc) [scratch]"
    else
      echo "  FAIL anchor image is not the current hardened daemon: in-image anchord.py sha $img_anc != repo $repo_anc"
      echo "       rebuild: docker build -t $ANC_IMG $REPO/testbed/anchord   (NOT docker compose build in testbed/real)"
      exit 2
    fi
  else
    echo "  ok    anchor image anchord.py matches the repository hardened daemon (${repo_anc%${repo_anc#????????}}...)"
  fi
  # EXACT MONITOR VERSION: /app/monitor.py in the monitor image must equal the repository's (the E7 coverage monitor).
  local repo_mon img_mon
  repo_mon=$(shasum -a 256 "$REPO/monitor/monitor.py" | cut -d' ' -f1)
  img_mon=$(docker run --rm --entrypoint sh "$MON_IMG" -c 'sha256sum /app/monitor.py 2>/dev/null' | cut -d' ' -f1)
  if [ "$repo_mon" != "$img_mon" ]; then
    if [ "$SCRATCH_MODE" = "1" ]; then
      echo "  WARN monitor image monitor.py sha ($img_mon) != repo ($repo_mon) [scratch]"
    else
      echo "  FAIL monitor image is not the current E7 monitor: in-image monitor.py sha $img_mon != repo $repo_mon"
      echo "       rebuild: docker build -t $MON_IMG $REPO/monitor   (NOT docker compose build in testbed/real)"
      exit 2
    fi
  else
    echo "  ok    monitor image monitor.py matches the repository (${repo_mon%${repo_mon#????????}}...)"
  fi
  # MONITOR COVERAGE: the closure monitor must advertise the E7 coverage fields (wm/through/seq_local, escrow).
  local mon_cov
  mon_cov=$(docker run --rm --entrypoint sh "$MON_IMG" -c "grep -lE 'HOMEPROV_COVERAGE|seq_local' /app/monitor.py 2>/dev/null" 2>/dev/null)
  if [ -z "$mon_cov" ]; then
    [ "$SCRATCH_MODE" = "1" ] && echo "  WARN $MON_IMG does not advertise E7 coverage (seq_local); coverage metrics will be empty [scratch]" \
      || { echo "  FAIL $MON_IMG is not the E7 coverage monitor (no HOMEPROV_COVERAGE/seq_local in /app/monitor.py)"; exit 2; }
  else
    echo "  ok    $MON_IMG advertises E7 coverage"
  fi
}
preflight
BUILT_MON_SHA=$(docker run --rm --entrypoint sha256sum "$MON_IMG" /app/monitor.py | cut -d' ' -f1)
BUILT_ANC_SHA=$(docker run --rm --entrypoint sha256sum "$ANC_IMG" /app/anchord.py | cut -d' ' -f1)

mkdir -p "$SP" "$ESCROW"
: > "$META"
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$META"; }
s16() { shasum -a 256 "$1" | cut -c1-16; }

# ---- offensive install (homeprov_e7 + homeprov_ec as an import-only dependency) ---------------------------------
enable_offensive() {   # install AND switch on homeprov_e7; homeprov_ec is copied as a dependency but NOT enabled
  for comp in homeprov_ec homeprov_e7; do
    [ -f "$CC/$comp/__init__.py" ] || { echo "  FAIL: no $comp under $CC"; exit 1; }
    docker exec "$HUB" mkdir -p "/config/custom_components/$comp"
    docker cp "$CC/$comp/." "$HUB:/config/custom_components/$comp/" >/dev/null
    docker exec "$HUB" test -f "/config/custom_components/$comp/__init__.py" \
      || { echo "  FAIL: $comp did not land"; exit 1; }
  done
  docker exec "$HUB" sh -c "grep -q '^homeprov_e7:' /config/configuration.yaml || printf '\nhomeprov_e7:\n' >> /config/configuration.yaml"
  docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"
}
disable_offensive() {
  docker exec "$HUB" sh -c "sed -i '/^homeprov_e7:/d' /config/configuration.yaml"
  docker exec "$HUB" rm -rf /config/custom_components/homeprov_e7 /config/custom_components/homeprov_ec
  docker restart "$HUB" >/dev/null; sleep "$RESTART_WAIT"
}
pause_devices()   { docker pause "$DEVICES" >/dev/null 2>&1 && note "paused $DEVICES to punch an empty minute (${1}s)"; }
unpause_devices() { docker unpause "$DEVICES" >/dev/null 2>&1 && note "unpaused $DEVICES"; }

restore() {
  note "teardown: saving logs, removing E7 pairs, restoring the stock monitor and anchor"
  docker logs "$MCLO" > "$SP/closure_monitor.log" 2>&1 || true
  docker logs "$MSTB" > "$SP/stable_monitor.log" 2>&1 || true
  docker logs "$ACLO" > "$SP/closure_anchord.log" 2>&1 || true
  docker logs "$ASTB" > "$SP/stable_anchord.log" 2>&1 || true
  docker unpause "$ACLO" >/dev/null 2>&1
  docker rm -f "$ACLO" "$MCLO" "$ASTB" "$MSTB" >/dev/null 2>&1
  docker rm -f "e7r-$TAG-hass" >/dev/null 2>&1; docker volume rm "e7r-$TAG-config" >/dev/null 2>&1
  docker network rm "e7r-$TAG-net" >/dev/null 2>&1
  unpause_devices
  # restore any leftover offensive install
  docker exec "$HUB" sh -c "sed -i '/^homeprov_e7:/d' /config/configuration.yaml; rm -rf /config/custom_components/homeprov_e7 /config/custom_components/homeprov_ec" 2>/dev/null
  if docker ps -a --format '{{.Names}}' | grep -qx "${STOCK_MON}-orig-e7"; then
    docker rename "${STOCK_MON}-orig-e7" "$STOCK_MON" >/dev/null 2>&1
    docker rename "${STOCK_ANC}-orig-e7" "$STOCK_ANC" >/dev/null 2>&1
    docker start "$STOCK_ANC" "$STOCK_MON" >/dev/null 2>&1
    note "restored: $(docker ps --format '{{.Names}}' | grep -E "^($STOCK_MON|$STOCK_ANC)$" | tr '\n' ' ')"
  fi
}

note "tag=$TAG hub=$HUB net=$NET cfgvol=$CFGVOL prefix=$PREFIX scratch=$SCRATCH_MODE"
note "trials/config=$TRIALS rooms='$ROOMS' arms=[$ARMS_JSON] outage=$WANT_OUTAGE(x$OUTAGE_TRIALS, seal_wait ${OUTAGE_SEAL_WAIT_S}s) K=$K stall_conns=$STALL_CONNS stall_s=$STALL_S stall_seal_wait_s=$STALL_SEAL_WAIT_S bd_min_age_s=$BD_MIN_AGE_S pause_devices_s=$PAUSE_DEVICES_S seal_wait_s=$SEAL_WAIT_S"
note "verifier parameters (pre-registered): LATE_BOUND=${LATE_BOUND_S}s GAP_S=${GAP_S}s; recovery_render=$RECOVERY_RENDER"
note "git_head: $(git -C $REPO rev-parse HEAD 2>/dev/null) (working tree: homeprov_e7 added; monitor.py/anchord may be the agents' E7 versions)"
note "hub_image: $(docker inspect "$HUB" --format '{{.Config.Image}}')"
note "monitor_image: $MON_IMG ($(docker image inspect "$MON_IMG" --format '{{.Id}}' 2>/dev/null))"
note "anchor_image:  $ANC_IMG ($(docker image inspect "$ANC_IMG" --format '{{.Id}}' 2>/dev/null))"
note "monitor_py_sha256(working tree): $(s16 $REPO/monitor/monitor.py) in_image: $(docker run --rm --entrypoint sha256sum "$MON_IMG" /app/monitor.py | cut -c1-16)"
note "anchord_py_sha256(working tree): $(s16 $REPO/testbed/anchord/anchord.py) in_image: $(docker run --rm --entrypoint sha256sum "$ANC_IMG" /app/anchord.py | cut -c1-16)"
note "e7_verify_py_sha256: $(s16 $REPO/exp/stages/e7_verify.py) e7_score_py_sha256: $(s16 $REPO/exp/stages/e7_score.py)"
note "homeprov_e7_sha256: $(s16 $CC/homeprov_e7/__init__.py) homeprov_ec_sha256: $(s16 $CC/homeprov_ec/__init__.py)"
KEY_CLO=$(openssl rand -hex 32); KEY_STB=$(openssl rand -hex 32)
[ ${#KEY_CLO} -eq 64 ] && [ ${#KEY_STB} -eq 64 ] && [ "$KEY_CLO" != "$KEY_STB" ] || { note "FAIL: key generation"; exit 5; }
note "closure_key_fingerprint_sha256_16: $(printf '%s' "$KEY_CLO" | shasum -a 256 | cut -c1-16) (append key; not recorded)"
note "stable_key_fingerprint_sha256_16:  $(printf '%s' "$KEY_STB" | shasum -a 256 | cut -c1-16) (append key; not recorded)"

trap restore EXIT
trap 'exit 130' INT TERM HUP

# ---- stand up the two E7 monitor/anchor pairs -------------------------------------------------------------------
note "stopping+renaming the stock monitor and anchor (restored on exit)"
docker stop "$STOCK_MON" "$STOCK_ANC" >/dev/null 2>&1 || true
docker rename "$STOCK_ANC" "${STOCK_ANC}-orig-e7" >/dev/null 2>&1 || true
docker rename "$STOCK_MON" "${STOCK_MON}-orig-e7" >/dev/null 2>&1 || true
for v in $VCLO_C $VCLO_P $VCLO_S $VSTB_C $VSTB_P $VSTB_S; do docker volume create "$v" >/dev/null; done

docker run -d --name "$ACLO" --network "$NET" --network-alias anchor-clo \
  -e HOMEPROV_ANCHOR_KEY="$KEY_CLO" -v $VCLO_C:/anchor -v $VCLO_P:/published "$ANC_IMG" >/dev/null || exit 5
docker run -d --name "$ASTB" --network "$NET" --network-alias anchor-stb \
  -e HOMEPROV_ANCHOR_KEY="$KEY_STB" -v $VSTB_C:/anchor -v $VSTB_P:/published "$ANC_IMG" >/dev/null || exit 5
# The E7 CLOSURE monitor: coverage (watermark + sealed-through) on, escrow on, escrow dir bind-mounted off the hub.
docker run -d --name "$MCLO" --network "$NET" --network-alias monitor-clo \
  -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR=http://anchor-clo:9900/append \
  -e HOMEPROV_PERIOD="$PERIOD" -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$KEY_CLO" \
  -e HOMEPROV_SCHEME=closure -e HOMEPROV_COVERAGE=1 -e HOMEPROV_ESCROW_DIR=/escrow \
  -e HOMEPROV_COST_LOG=/scratch/cost.jsonl \
  -v $CFGVOL:/cfg:ro -v $VCLO_S:/scratch -v "$ESCROW":/escrow "$MON_IMG" >/dev/null || exit 5
# The STABLE-COLUMNS monitor, its own hardened anchor and key, same coverage fields.
docker run -d --name "$MSTB" --network "$NET" --network-alias monitor-stb \
  -e HOMEPROV_DB=/cfg/home-assistant_v2.db -e HOMEPROV_ANCHOR=http://anchor-stb:9900/append \
  -e HOMEPROV_PERIOD="$PERIOD" -e HOMEPROV_SCRATCH=/scratch -e HOMEPROV_ANCHOR_KEY="$KEY_STB" \
  -e HOMEPROV_SCHEME=stable -e HOMEPROV_COVERAGE=1 \
  -v $CFGVOL:/cfg:ro -v $VSTB_S:/scratch "$MON_IMG" >/dev/null || {
    note "stable monitor failed to start (HOMEPROV_SCHEME=stable may be unsupported in $MON_IMG); continuing with the closure monitor only"; }
note "anchors: $(docker inspect "$ACLO" --format '{{.Config.Image}}') ; monitors: clo=$(docker inspect "$MCLO" --format '{{.State.Status}}') stb=$(docker inspect "$MSTB" --format '{{.State.Status}}' 2>/dev/null || echo absent)"
sleep 20
# The hub tries each anchor's one verb without the key and with a forged tag.
PROBE='import urllib.request,json
def post(u,h):
    r=urllib.request.Request(u,data=b"{\"sealed\": {}}",method="POST",headers=h)
    try:
        with urllib.request.urlopen(r,timeout=5) as x: return x.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return repr(e)[:60]
J={"Content-Type":"application/json"}
print(json.dumps({a:{"untagged":post("http://%s:9900/append"%a,J),"forged":post("http://%s:9900/append"%a,{**J,"X-HP-Auth":"0"*64})} for a in ("anchor-clo","anchor-stb")}))'
note "probe_from_hub: $(docker exec "$HUB" python3 -c "$PROBE" 2>&1 | tail -1)"
sleep 40
note "closure chain before run: $(docker exec "$ACLO" sh -c 'wc -l < /anchor/chain.jsonl' 2>/dev/null)"

# ---- run the arms, one component invocation per configuration ---------------------------------------------------
# The OUTAGE arm (a SIMULATED anchor outage) runs last in the same invocation: the component signals through marker
# files in /config/homeprov_out, and this loop pauses THIS run's closure anchor ($ACLO, never the stock anchor) for
# OUTAGE_PAUSE_S while the monitor seals the edited row's second, then unpauses.
OUTAGE_PAUSE_S=${HPR_E7_OUTAGE_PAUSE_S:-90}
RUN_ARMS="$ARMS_JSON"
[ "$WANT_OUTAGE" = "1" ] && RUN_ARMS="$RUN_ARMS,\"OUTAGE\""
MK=/config/homeprov_out
date -u +%s > "$OUT/${TAG}_t_start"
for room in $ROOMS; do
  note "-- configuration: $room --"
  docker exec "$HUB" sh -c "printf '%s' '$room' > /config/.hpr_room"
  # BD-M needs a sealed EMPTY minute. Empty minutes are rare on this substrate, so punch one by pausing the device
  # simulator for PAUSE_DEVICES_S, then let the monitor seal it before the arm runs.
  if printf '%s' "$RUN_ARMS" | grep -q 'BD-M' && [ "$PAUSE_DEVICES_S" -gt 0 ]; then
    pause_devices "$PAUSE_DEVICES_S"; sleep "$PAUSE_DEVICES_S"; unpause_devices
    note "settling $((PERIOD*4))s so the empty minute seals"; sleep $((PERIOD*4))
  fi
  printf '{"trials": %s, "arms": [%s], "seal_wait_s": %s, "room": "%s", "K": %s, "stall_connections": %s, "stall_s": %s, "stall_seal_wait_s": %s, "bd_lookback_s": %s, "bd_min_age_s": %s, "bd_move_delay_s": %s, "outage_trials": %s, "outage_seal_wait_s": %s, "anchor_host": "anchor-clo", "anchor_port": 9900}' \
    "$TRIALS" "$RUN_ARMS" "$SEAL_WAIT_S" "$room" "$K" "$STALL_CONNS" "$STALL_S" "$STALL_SEAL_WAIT_S" "$BD_LOOKBACK_S" \
    "$BD_MIN_AGE_S" "$BD_MOVE_DELAY_S" "$OUTAGE_TRIALS" "$OUTAGE_SEAL_WAIT_S" > /tmp/hpr_e7_conf
  docker cp /tmp/hpr_e7_conf "$HUB:/config/.hpr_e7_conf" >/dev/null
  docker exec "$HUB" rm -f $MK/e7_ack.json $MK/e7_report.json $MK/e7_outage_ready $MK/e7_outage_paused $MK/e7_outage_edited 2>/dev/null
  enable_offensive
  end=$((SECONDS+7200)); paused=0; t_pause=0
  while [ $SECONDS -lt $end ]; do
    if [ $paused -eq 0 ] && docker exec "$HUB" test -f $MK/e7_outage_ready 2>/dev/null; then
      docker pause "$ACLO" >/dev/null && t_pause=$SECONDS && paused=1
      docker exec "$HUB" touch $MK/e7_outage_paused
      note "outage: paused $ACLO (trial $(docker exec "$HUB" cat $MK/e7_outage_ready 2>/dev/null))"
    fi
    if [ $paused -eq 1 ]; then
      el=$((SECONDS - t_pause))
      if { docker exec "$HUB" test -f $MK/e7_outage_edited 2>/dev/null && [ $el -ge "$OUTAGE_PAUSE_S" ]; } \
         || [ $el -ge $((OUTAGE_PAUSE_S + 60)) ]; then
        docker unpause "$ACLO" >/dev/null; paused=0
        docker exec "$HUB" rm -f $MK/e7_outage_paused
        note "outage: unpaused $ACLO after ${el}s"
      fi
    fi
    if [ $paused -eq 0 ] && docker exec "$HUB" test -f $MK/e7_ack.json 2>/dev/null; then
      note "ack $room: $(docker exec "$HUB" cat $MK/e7_ack.json)"; break
    fi
    sleep 2
  done
  [ $paused -eq 1 ] && { docker unpause "$ACLO" >/dev/null 2>&1; note "outage: unpaused $ACLO at loop exit"; }
  [ $SECONDS -ge $end ] && note "TIMEOUT on $room"
  docker cp "$HUB:$MK/e7_report.json" "$OUT/${TAG}_report_${room}.json" >/dev/null 2>&1 \
    && note "  -> exp/out/${TAG}_report_${room}.json" || note "  (no report for $room)"
  disable_offensive
done
date -u +%s > "$OUT/${TAG}_t_end"

note "settling 90s so the final segments seal and anchor on both monitors"
sleep 90
note "closure chain after run: $(docker exec "$ACLO" sh -c 'wc -l < /anchor/chain.jsonl')"
note "stable chain after run:  $(docker exec "$ASTB" sh -c 'wc -l < /anchor/chain.jsonl' 2>/dev/null || echo n/a)"

# ---- freeze: consistent recorder snapshot + both chains + logs + cost log + escrow -----------------------------
note "taking a consistent recorder snapshot (SQLite backup API, inside the hub)"
docker exec "$HUB" rm -f /config/.e7_snap.db 2>/dev/null
docker exec "$HUB" python3 -c "import sqlite3;s=sqlite3.connect('/config/home-assistant_v2.db',timeout=120);d=sqlite3.connect('/config/.e7_snap.db');s.backup(d);d.close();s.close();print('ok')" >/dev/null
docker cp "$HUB:/config/.e7_snap.db" "$SP/recorder.db" >/dev/null
docker exec "$HUB" rm -f /config/.e7_snap.db 2>/dev/null
docker exec "$ACLO" cat /anchor/chain.jsonl > "$SP/closure_chain.jsonl"
docker exec "$ASTB" cat /anchor/chain.jsonl > "$SP/stable_chain.jsonl" 2>/dev/null || : > "$SP/stable_chain.jsonl"
docker exec "$ACLO" sh -c 'cat /anchor/refusals.jsonl 2>/dev/null' > "$SP/closure_refusals.jsonl"
docker cp "$MCLO:/scratch/cost.jsonl" "$SP/closure_cost.jsonl" >/dev/null 2>&1 || note "no closure cost log"
docker logs "$MCLO" > "$SP/closure_monitor.log" 2>&1
docker logs "$MSTB" > "$SP/stable_monitor.log" 2>&1 || true
gzip -c "$SP/closure_chain.jsonl" > "$OUT/${TAG}_closure_chain.jsonl.gz"
gzip -c "$SP/stable_chain.jsonl"  > "$OUT/${TAG}_stable_chain.jsonl.gz"
[ -s "$ESCROW/escrow.jsonl" ] && gzip -c "$ESCROW/escrow.jsonl" > "$OUT/${TAG}_escrow.jsonl.gz"
note "recorder snapshot sha256: $(s16 $SP/recorder.db); closure chain records: $(wc -l < $SP/closure_chain.jsonl | tr -d ' '); stable: $(wc -l < $SP/stable_chain.jsonl | tr -d ' '); escrow lines: $(cat $ESCROW/* 2>/dev/null | wc -l | tr -d ' '); cost lines: $(wc -l < $SP/closure_cost.jsonl 2>/dev/null | tr -d ' ')"

# ---- score (pass 1: e7_verify with --escrow and --restore-out writes the restored copy) --------------------------
note "scoring (pass 1) with exp/stages/e7_score.py -> e7_verify (LATE_BOUND=${LATE_BOUND_S}s GAP_S=${GAP_S}s)"
E7_LATE_BOUND=$LATE_BOUND_S E7_GAP_S=$GAP_S E7_SP="$SP" python3 "$REPO/exp/stages/e7_score.py" --tag "$TAG" $ROOMS > "$SP/score_pass1.log" 2>&1
note "score pass 1 exit: $?"

# ---- recovery render: e7_verify's restored copy, rendered by the release's own logbook processor ------------------
# A throwaway Home Assistant container (e7r-, the hub's own image) on an isolated internal network, started on the
# restored copy, renders every laundered/swapped trial's `when` through homeprov_e7's RENDER mode (homeprov_ec's
# processor form and principal resolution), and the displayed principal is compared with the clean principal the
# trial recorded before its edit. Removed afterwards.
RR_HUB=e7r-$TAG-hass; RR_VOL=e7r-$TAG-config; RR_NET=e7r-$TAG-net
if [ "$RECOVERY_RENDER" = "1" ] && [ -s "$SP/restored_closure.db" ]; then
  note "recovery render: building targets from the reports"
  python3 - "$OUT" "$TAG" "$SP/render_targets.json" $ROOMS <<'PY'
import json, os, sys
out, tag, dst, rooms = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
tg = []
for room in rooms:
    f = os.path.join(out, "%s_report_%s.json" % (tag, room))
    if not os.path.exists(f):
        continue
    for t in json.load(open(f)).get("trials", []):
        if t.get("err") or t.get("error") or t.get("arm") not in ("INS-L", "INS-M", "STALL", "OUTAGE"):
            continue
        if not t.get("judged_when") or "clean_principal" not in t:
            continue
        tg.append({"key": "%s/%s/%s" % (room, t["arm"], t["trial"]), "arm_of_trial": t["arm"], "room": room,
                   "trial": t["trial"], "when": t["judged_when"], "clean_principal": t["clean_principal"],
                   "clean_named_user_id": t.get("clean_named_user_id")})
json.dump(tg, open(dst, "w"), indent=1)
print(len(tg))
PY
  HUB_IMG=$(docker inspect "$HUB" --format '{{.Config.Image}}')
  docker network create --internal "$RR_NET" >/dev/null 2>&1
  docker volume create "$RR_VOL" >/dev/null
  # seed: the hub's configuration (read-only copy), minus its recorder; the restored copy as the recorder; the
  # render-only harness (homeprov_e7 + its homeprov_ec dependency), enabled for RENDER and nothing else.
  docker run --rm --name e7r-$TAG-seed -v "$CFGVOL":/src:ro -v "$RR_VOL":/dst -v "$SP":/run:ro -v "$CC":/cc:ro \
    alpine sh -c 'cp -a /src/. /dst/ && rm -f /dst/home-assistant_v2.db* && cp /run/restored_closure.db /dst/home-assistant_v2.db \
      && rm -rf /dst/custom_components/homeprov_e7 /dst/custom_components/homeprov_ec /dst/homeprov_out \
      && mkdir -p /dst/custom_components /dst/homeprov_out && cp -r /cc/homeprov_e7 /cc/homeprov_ec /dst/custom_components/ \
      && rm -rf /dst/custom_components/*/__pycache__ \
      && sed -i "/^homeprov_e7:/d;/^homeprov_ec:/d" /dst/configuration.yaml && printf "\nhomeprov_e7:\n" >> /dst/configuration.yaml' \
    || note "recovery render: seeding failed"
  python3 -c "import json,sys;print(json.dumps({'arms':['RENDER'],'trials':0,'render_targets':json.load(open(sys.argv[1]))}))" \
    "$SP/render_targets.json" > /tmp/hpr_e7r_conf
  docker run --rm -v "$RR_VOL":/dst -v /tmp/hpr_e7r_conf:/c.json:ro alpine cp /c.json /dst/.hpr_e7_conf
  docker run -d --name "$RR_HUB" --network "$RR_NET" -e TZ=UTC -v "$RR_VOL":/config "$HUB_IMG" >/dev/null \
    && note "recovery render: started $RR_HUB ($HUB_IMG) on $RR_NET"
  end=$((SECONDS+900))
  while [ $SECONDS -lt $end ]; do
    docker exec "$RR_HUB" test -f /config/homeprov_out/e7_ack.json 2>/dev/null && break
    sleep 5
  done
  docker cp "$RR_HUB:/config/homeprov_out/e7_report.json" "$SP/recovery_render_raw.json" >/dev/null 2>&1 \
    || note "recovery render: no report (timeout or failure)"
  docker rm -f "$RR_HUB" >/dev/null 2>&1; docker volume rm "$RR_VOL" >/dev/null 2>&1; docker network rm "$RR_NET" >/dev/null 2>&1
  python3 - "$SP" <<'PY'
import collections, json, os, sys
sp = sys.argv[1]
raw = os.path.join(sp, "recovery_render_raw.json")
if not os.path.exists(raw):
    json.dump({"available": False, "why": "no render report"}, open(os.path.join(sp, "e7_recovery_render.json"), "w"))
    raise SystemExit
tr = [t for t in json.load(open(raw)).get("trials", []) if t.get("arm") == "RENDER"]
by = collections.defaultdict(lambda: {"n": 0, "true_author_shown": 0})
for t in tr:
    a = by[t.get("arm_of_trial")]
    a["n"] += 1
    a["true_author_shown"] += bool(t.get("true_author_shown"))
out = {"available": True, "n_trials": len(tr),
       "true_author_recovered": sum(1 for t in tr if t.get("true_author_shown")),
       "per_arm": dict(by),
       "how": "e7_verify --restore-out copy rendered by the release's logbook EventProcessor in a throwaway "
              "e7r- container (same image as the hub); true author = the trial's clean principal before the edit",
       "trials": tr}
json.dump(out, open(os.path.join(sp, "e7_recovery_render.json"), "w"), indent=1, default=str)
print(out["true_author_recovered"], "/", out["n_trials"])
PY
  note "recovery render: true author shown $(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('true_author_recovered'),'/',d.get('n_trials'))" "$SP/e7_recovery_render.json" 2>/dev/null)"
  cp "$SP/e7_recovery_render.json" "$OUT/${TAG}_recovery_render.json" 2>/dev/null
else
  note "recovery render: skipped (RECOVERY_RENDER=$RECOVERY_RENDER, restored copy present: $([ -s "$SP/restored_closure.db" ] && echo yes || echo no))"
fi

# ---- score (pass 2: includes the recovery render) ----------------------------------------------------------------
rm -f "$SP/closure_verify.json" "$SP/stable_verify.json" "$SP/restored_closure.db"*
note "scoring (pass 2) with exp/stages/e7_score.py"
E7_LATE_BOUND=$LATE_BOUND_S E7_GAP_S=$GAP_S E7_SP="$SP" python3 "$REPO/exp/stages/e7_score.py" --tag "$TAG" $ROOMS > "$SP/score.log" 2>&1
note "score exit: $? ($(tail -12 "$SP/score.log" | tr '\n' ' '))"
cp "$SP/closure_verify.json" "$OUT/${TAG}_closure_verify.json" 2>/dev/null
cp "$SP/stable_verify.json" "$OUT/${TAG}_stable_verify.json" 2>/dev/null

python3 - "$SP" "$OUT" "$TAG" "$0" "$MON_IMG" "$ANC_IMG" "$LATE_BOUND_S" "$GAP_S" "$BUILT_MON_SHA" "$BUILT_ANC_SHA" <<'PY'
import hashlib, json, sys
sp, out, tag, script, mon_img, anc_img, lb, gap, built_mon, built_anc = sys.argv[1:]
R = __import__("os").environ["ARTIFACT_ROOT"]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
cfg = {"experiment": f"{tag}: E7 coverage-gap (INS-L, INS-M), backdating (BD-S, BD-M), live anchor stall (STALL) and "
                     "simulated anchor outage (OUTAGE) arms on the default deployment, under the E7 closure monitor "
                     "(watermark + sealed-through + escrow) and a stable-columns monitor, each with its own hardened "
                     "anchor and a fresh append key",
       "verifier_parameters": {"late_bound_s": float(lb), "gap_s": float(gap),
                               "fixed_before_run_by": "the lead, 2026-10-08",
                               "verifier": "exp/stages/e7_verify.py",
                               "e7_verify_py_sha256": h(f"{R}/exp/stages/e7_verify.py")},
       "monitors": {"closure": {"image": mon_img, "scheme": "closure", "coverage": True, "escrow": True,
                                "cost_log": True},
                    "stable": {"image": mon_img, "scheme": "stable"}},
       "anchor_image": anc_img,
       "monitor_py_in_image_sha256": built_mon,     # the file the run's monitors executed
       "anchord_py_in_image_sha256": built_anc,     # the file the run's anchors executed
       "anchord_py_sha256_working_tree_at_end": h(f"{R}/testbed/anchord/anchord.py"),
       "monitor_py_sha256_working_tree_at_end": h(f"{R}/monitor/monitor.py"),
       "homeprov_e7_sha256": h(f"{R}/testbed/real/ha-config/custom_components/homeprov_e7/__init__.py"),
       "homeprov_ec_sha256": h(f"{R}/testbed/real/ha-config/custom_components/homeprov_ec/__init__.py"),
       "e7_score_py_sha256": h(f"{R}/exp/stages/e7_score.py"),
       "configuration_log": [l.rstrip("\n") for l in open(f"{sp}/auth_meta.log")],
       "closure_chain": {"file": f"exp/out/{tag}_closure_chain.jsonl.gz",
                         "records": sum(1 for l in open(f"{sp}/closure_chain.jsonl") if l.strip()),
                         "sha256_uncompressed": h(f"{sp}/closure_chain.jsonl")},
       "stable_chain": {"file": f"exp/out/{tag}_stable_chain.jsonl.gz",
                        "records": sum(1 for l in open(f"{sp}/stable_chain.jsonl") if l.strip()),
                        "sha256_uncompressed": h(f"{sp}/stable_chain.jsonl")},
       "recorder_snapshot_sha256": h(f"{sp}/recorder.db"),
       "wrapper_script_sha256": h(script)}
json.dump(cfg, open(f"{out}/{tag}_config.json", "x"), indent=1)
print("wrote", f"{out}/{tag}_config.json")
PY
note "done; results under exp/out/${TAG}_* and the run directory $SP"
