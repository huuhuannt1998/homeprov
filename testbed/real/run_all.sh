#!/bin/bash
# HomeProv: the complete real-substrate experiment suite, in one command.
#
#   ./run_all.sh --check     preflight only, touches nothing
#   ./run_all.sh             run everything still missing, in order
#   ./run_all.sh --force     re-run everything, including completed stages
#   ./run_all.sh --only E5   run one stage
#   ./run_all.sh --list      show stages, their outputs, and what is already done
#
# WHY THIS EXISTS. The suite was previously a set of separately-invoked stages
# with no shared preflight, no resume, and no resource discipline. A machine
# running five projects at once died partway through the E5 sweep and left one
# stage half-finished with no record of how far it got. Everything below is
# sequential by construction, checks the machine can actually take the load
# before starting, records what completed, and skips completed work on restart.
#
# NOTHING HERE RUNS IN PARALLEL. The hub is a single container with a single
# SQLite recorder; two stages mutating it at once produce interleaved writes and
# a restore that cannot be verified. That is not a performance choice.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/exp/out"
LOGS="$OUT/run_all_logs"
C=hpr-hass
MANIFEST="$OUT/run_all_manifest.json"
mkdir -p "$OUT" "$LOGS"

MODE=run; ONLY=""; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --list)  MODE=list ;;
    --force) FORCE=1 ;;
    --only)  shift; ONLY="${ONLY:+$ONLY }${1:-}" ;;   # repeatable
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done

c_red()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yel()  { printf '\033[33m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- stage table
# stage | output proving it ran | ~min | what it establishes | validity predicate
#
# THE VALIDITY PREDICATE IS THE POINT. A stage that measures nothing still
# writes a file and still exits zero -- that is how e4_real_roles.json came to
# hold three nulls and read as "done", and how the first real E5 run reported
# 0/40 on a sweep whose targets could not be laundered. `d` is the parsed JSON.
STAGES="
binding|scenario_binding.json|1|entity binding validates, or every later stage silently measures nothing|d.get('bound') is True
E25|stage34_realchar.json|1|real-vs-generated deployment characterisation|d['real']['parent_context_fraction']>0
E4|e4_real_closure.json|3|renderer dependency closure on the real substrate|d['positive_control']['attribution_relevant'] is True and d['positive_control']['restore_verified'] is True and len(d['mutations'])>0
E4ROLES|e4_real_roles.json|2|conditional-role retests, and which roles this substrate exhibits|len(d.get('retests',[]))>0
E4PARENT|e4_real_parentrole.json|2|constructive test for states.context_parent_id_bin|len(d)>2
E5|e5_real_multiconfig.json|7|twelve-variant renderer-backed sweep, three configurations|len(d.get('configurations',[]))>=1 and all(c.get('n_targets') for c in d['configurations'])
E2|e2_real_external.json|3|in-process defender subversion vs the external monitor|d.get('anchor_records',0)>0
S1|s1_real_multiconfig.json|12|the flagship, three configurations|d['pooled']['n']>0
BENIGN|benign_load_check.json|1|false alarms under real device churn|d.get('actuations',0)>0
"

stage_field() { echo "$STAGES" | awk -F'|' -v s="$1" -v f="$2" '$1==s{print $f}'; }
stage_list()  { echo "$STAGES" | awk -F'|' 'NF>1{print $1}'; }

done_marker() {  # stage -> 0 only if its output exists AND passes its predicate
  local f pred
  f="$OUT/$(stage_field "$1" 2)"
  pred="$(stage_field "$1" 5)"
  [ -s "$f" ] || return 1
  python3 "$HERE/_check_stage.py" "$f" "$pred" >/dev/null 2>&1
}

why_invalid() {  # human-readable reason a stage is not considered done
  local f; f="$OUT/$(stage_field "$1" 2)"
  [ -e "$f" ] || { echo "no $(stage_field "$1" 2) yet"; return; }
  [ -s "$f" ] || { echo "$(stage_field "$1" 2) is empty"; return; }
  echo "exists but fails: $(stage_field "$1" 5)"
}

# ------------------------------------------------------------------- preflight
preflight() {
  local fail=0 warn=0
  echo "== preflight =="

  if ! docker info >/dev/null 2>&1; then
    c_red "  FAIL  Docker daemon is not running. Start Docker Desktop first."
    return 1
  fi
  c_grn "  ok    docker daemon"

  # The crash that prompted this script came from running several compose
  # projects at once. Say so before starting rather than after.
  local others
  others=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -v '^hpr-' | grep -v '^rka-' | wc -l | tr -d ' ')
  if [ "$others" -gt 0 ]; then
    c_yel "  WARN  $others non-HomeProv containers are running:"
    docker ps --format '          {{.Names}}' | grep -v '^          hpr-' | grep -v '^          rka-' | head -8
    c_yel "        This suite drives a hub, a broker, a device simulator, a monitor"
    c_yel "        and an anchor for roughly two hours. Stop other projects first."
    warn=$((warn+1))
  else
    c_grn "  ok    no competing container workloads"
  fi

  local freegb
  freegb=$(df -g "$ROOT" 2>/dev/null | awk 'NR==2{print $4}')
  if [ -n "${freegb:-}" ] && [ "$freegb" -lt 15 ]; then
    c_red "  FAIL  only ${freegb}GB free. The recorder, the per-trial reports and the"
    c_red "        anchor need headroom; 15GB is the floor."
    fail=$((fail+1))
  else
    c_grn "  ok    disk headroom (${freegb:-?}GB free)"
  fi

  if ! docker compose -f "$HERE/docker-compose.yml" config >/dev/null 2>&1; then
    c_red "  FAIL  docker-compose.yml does not parse"
    fail=$((fail+1))
  else
    c_grn "  ok    compose file parses"
  fi

  for f in run_experiments.sh ha-config/custom_components/homeprov_scenario/__init__.py; do
    [ -f "$HERE/$f" ] || { c_red "  FAIL  missing $f"; fail=$((fail+1)); }
  done
  [ $fail -eq 0 ] && c_grn "  ok    harness files present"

  [ $fail -eq 0 ] || return 1
  [ $warn -eq 0 ] || echo "  (warnings above are advisory, not blocking)"
  return 0
}

bring_up() {
  echo "== bringing the substrate up =="
  docker compose -f "$HERE/docker-compose.yml" up -d >/dev/null 2>&1 || {
    c_red "  compose up failed"; return 1; }
  # The hub needs to reach EVENT_HOMEASSISTANT_STARTED before any automation
  # fires. A stage that starts earlier measures a home in which nothing happens.
  echo -n "  waiting for the hub to bind its entities"
  local n=0
  until docker exec $C test -f /config/homeprov_out/scenario_binding.json 2>/dev/null; do
    n=$((n+1)); [ $n -gt 60 ] && { echo; c_red "  hub never wrote scenario_binding.json"; return 1; }
    echo -n "."; sleep 5
  done
  echo
  local bound
  bound=$(docker exec $C sh -c 'python3 -c "import json;print(json.load(open(\"/config/homeprov_out/scenario_binding.json\"))[\"bound\"])"' 2>/dev/null)
  if [ "$bound" != "True" ]; then
    c_red "  scenario is NOT bound; every downstream stage would measure nothing"
    docker exec $C cat /config/homeprov_out/scenario_binding.json
    return 1
  fi
  c_grn "  ok    scenario bound"
  # Let the deployment produce genuine automation runs before anything reads
  # them. S1 and E5 both need real cover to exist.
  echo "  settling for 90s so the blueprint fires and MQTT retains settle"
  sleep 90
  return 0
}

record() {  # stage status seconds
  python3 - "$MANIFEST" "$1" "$2" "$3" <<'PY'
import json,os,sys,time
path,stage,status,secs = sys.argv[1],sys.argv[2],sys.argv[3],float(sys.argv[4])
m = {}
if os.path.exists(path):
    try: m = json.load(open(path))
    except Exception: m = {}
m.setdefault("runs", {})[stage] = {"status": status, "seconds": round(secs,1),
                                   "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
json.dump(m, open(path,"w"), indent=2)
PY
}

run_stage() {
  local s="$1" t0 rc
  if [ $FORCE -eq 0 ] && done_marker "$s"; then
    c_yel "-- $s: already done ($(stage_field "$s" 2)), skipping. --force to redo."
    return 0
  fi
  echo
  echo "=============================================================="
  echo "== $s  (~$(stage_field "$s" 3) min)  $(stage_field "$s" 4)"
  echo "=============================================================="
  t0=$(date +%s)
  "$HERE/run_experiments.sh" "$s" 2>&1 | tee "$LOGS/$s.log"
  rc=${PIPESTATUS[0]}
  local secs=$(( $(date +%s) - t0 ))
  if [ $rc -ne 0 ]; then
    record "$s" "failed" "$secs"
    c_red "-- $s FAILED after ${secs}s. Log: $LOGS/$s.log"
    return 1
  fi
  if done_marker "$s"; then
    record "$s" "ok" "$secs"; c_grn "-- $s ok in ${secs}s"
  else
    record "$s" "no_output" "$secs"
    c_red "-- $s exited 0 but its output is missing or invalid:"
    c_red "   $(why_invalid "$s")"
    c_red "   Treat that as a failure: a stage that measures nothing exits cleanly."
    return 1
  fi
  return 0
}

# ------------------------------------------------------------------- dispatch
case "$MODE" in
  list)
    printf "%-9s %-28s %4s  %s\n" STAGE OUTPUT MIN STATUS
    for s in $(stage_list); do
      if done_marker "$s"; then st="done"; else st="PENDING - $(why_invalid "$s")"; fi
      printf "%-9s %-28s %4s  %s\n" "$s" "$(stage_field "$s" 2)" "$(stage_field "$s" 3)" "$st"
    done
    echo
    echo "total if all pending: ~$(echo "$STAGES" | awk -F'|' 'NF>1{t+=$3}END{print t}') minutes, sequential"
    exit 0 ;;
  check)
    preflight; exit $? ;;
esac

preflight || { c_red "preflight failed; nothing was run"; exit 1; }
bring_up  || { c_red "substrate did not come up; nothing was run"; exit 1; }

FAILED=""
if [ -n "$ONLY" ]; then
  # One bring_up for the whole list. Invoking this script once per stage costs a
  # 90-second settle each time, which is how a four-stage re-run spent six
  # minutes settling.
  for s in $ONLY; do
    run_stage "$s" || { FAILED="$FAILED $s"; c_yel "   continuing to the next stage"; }
  done
else
  for s in $(stage_list); do
    run_stage "$s" || { FAILED="$FAILED $s"; c_yel "   continuing to the next stage"; }
  done
fi

echo
echo "=============================================================="
if [ -n "$FAILED" ]; then
  c_red "FAILED:$FAILED"
  echo "Re-run just those with: $0 --only <stage>"
  echo "Manifest: $MANIFEST"
  exit 1
fi
c_grn "all stages completed"
echo "Manifest: $MANIFEST"
echo "Logs:     $LOGS/"
