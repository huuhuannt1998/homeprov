#!/bin/bash
# E11 scratch openHAB stacks (drafts/round13/E11_DESIGN.md, section 2). Every container, network and volume it creates is
# named PREFIX-* with PREFIX starting with e11; it touches nothing else (never hpr-*, e2-*, e9*, e10*, dz-*).
#
#   e11_stack.sh guard                    exit 0 only when E9 and E10 are over (see guard()); prints why not
#   e11_stack.sh up PREFIX RUNDIR [closure|main]
#                                         networks PREFIX-net (internal) and PREFIX-prov (provisioning only), volumes
#                                         PREFIX-conf/-userdata/-addons initialised from the image's own distribution,
#                                         the E11 configuration (testbed/e11/conf), the bundles from RUNDIR/bundles
#                                         (fixture always; the instrument only for "main"), the hub PREFIX-hub
#                                         ($E11_OH_IMAGE, pinned by digest, TZ=UTC) with RUNDIR/hpctl at /hpctl, the
#                                         household accounts from RUNDIR/creds.json (0600; fingerprints only in the log),
#                                         the JDBC SQLite add-on installed from openHAB's repository while on
#                                         PREFIX-prov, then the hub moved to PREFIX-net alone; the client container
#                                         PREFIX-harness (python, for the host-side tunnel); for "closure" also the
#                                         database helper PREFIX-dbh (uid 9001, userdata read-write, testbed/e11 read-only).
#                                         Prints one JSON line (image, versions, add-on bundles, timings).
#   e11_stack.sh console PREFIX "CMD"     one Karaf console command in the hub (openhab:jdbc reload, ...)
#   e11_stack.sh restart PREFIX           docker restart of the hub; waits for its REST API and the JDBC service
#   e11_stack.sh snapshot PREFIX LABEL OUTDIR
#                                         a consistent copy of the persistence database (SQLite backup API, read-only
#                                         connection from a container OUTSIDE the hub) and of the registry files;
#                                         prints one JSON line with times and sha256
#   e11_stack.sh down PREFIX              remove PREFIX-* containers, networks and volumes
set -u
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
E11=$REPO/testbed/e11
ACT=${1:-}; P=${2:-}
OH_IMG=${E11_OH_IMAGE:-openhab/openhab:5.2.3@sha256:fa50a6934dfd5bcbf21db18af66f2558f58c6c493ba23bdeb7a894e764507a99}
PY_IMG=${E11_PY_IMAGE:-python:3.13-slim}
PROBE_IMG=${E11_PROBE_IMAGE:-hpr-monitor:e11}
NOT_BEFORE=1792425660                          # 2026-10-19T16:01:00Z: E9 owns this Mac's Docker until then
E10_DONE=${HPR_E11_E10_DONE_FILE:-$REPO/exp/out/e10_main_score.json}
DB_IN_HUB=/openhab/userdata/persistence/jdbc/openhab.db

guard() {
  local why=""
  [ "$(date -u +%s)" -lt "$NOT_BEFORE" ] && why="$why before-2026-10-19T16:01Z;"
  pgrep -f "testbed/e9/run_e9.sh" >/dev/null && why="$why run_e9.sh-running;"
  pgrep -f "testbed/e10/run_e10.sh" >/dev/null && why="$why run_e10.sh-running;"
  pgrep -f "testbed/e12/run_e12.sh" >/dev/null && why="$why run_e12.sh-running;"   # added 2026-10-23, before registration
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qE '^(e9-|e9s-|e10s-|e10u-)' && why="$why e9/e10-containers-exist;"
  [ -f "$E10_DONE" ] || why="$why E10-not-scored($E10_DONE missing);"
  if [ -n "$why" ]; then echo "REFUSING:$why"; return 1; fi
  return 0
}
[ "$ACT" = "guard" ] && { guard; exit $?; }
case "$P" in e11*) ;; *) echo "REFUSING: prefix must start with e11 ($P)"; exit 2 ;; esac
case "$P" in *hpr*|*e2-*|*e9*|*e10*|*dz-*) echo "REFUSING: prefix $P"; exit 2 ;; esac
guard >/dev/null || { guard; exit 2; }
HUB=$P-hub; NET=$P-net; PROV=$P-prov; HAR=$P-harness; DBH=$P-dbh
VCONF=$P-conf; VUSER=$P-userdata; VADD=$P-addons
# One Karaf console command. openHAB 5.2.3 (Karaf 4.4.11) closes a command given as an argument ("Closed", nothing
# run), and the old call had no time limit, so E11 smoke 1 hung for 25 min (2026-10-24, before registration). The
# command now goes in on stdin between two echo markers, with a 60 s limit; ANSI codes, prompts and the echoed input
# (the command line itself and "echo HPR_END") are dropped, and only the command's own output is printed.
console() {
  printf 'echo HPR_BEGIN\n%s\necho HPR_END\nlogout\n' "$1" \
    | docker exec -i "$HUB" timeout 60 /openhab/runtime/bin/client -u openhab -p habopen 2>&1 \
    | tr -d '\r' | sed -e $'s/\x1b\\[[0-9;?]*[a-zA-Z]//g' -e $'s/\x1b[()][A-Z0-9]//g' \
    | awk -v cmd="$1" '{ l=$0; while (sub(/^[[:space:]]*openhab>[[:space:]]*/, "", l)); sub(/[[:space:]]+$/, "", l) }
        l=="HPR_BEGIN" {on=1; next} l=="HPR_END" {exit} !on || l=="" || l=="echo HPR_END" {next}
        l==cmd && !seen {seen=1; next} {print l}'
}
rest_up() {   # 0 when the hub's REST answers (401 without credentials is an answer)
  local c
  c=$(docker exec "$HAR" python3 -c "import urllib.request,urllib.error
try:
    print(urllib.request.urlopen('http://$HUB:8080/rest/',timeout=5).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(0)" 2>/dev/null)
  case "$c" in 200|401) return 0 ;; esac; return 1
}
wait_rest() { local i; for i in $(seq 1 120); do rest_up && return 0; sleep 5; done; return 1; }
jdbc_ready() { console "openhab:jdbc tables list all" | grep -qiE 'item|table|no '; }
# 180 tries (~15 min; was 60): the JDBC add-on is downloaded from openHAB's repository at first start, and smoke 2's main
# stack gave up after 5 min while a debug stack of the same kind was ready in 43 s (2026-10-24, before registration)
# openHAB 5.2.3 sometimes leaves the JDBC persistence bundle Resolved (installed, never started) after a first start:
# 3 of 9 stack starts on 2026-10-24 (smoke 2 main, smoke 3 closure, debug repro r2; the feature reported Started, the
# console had no openhab:jdbc, persistence/jdbc stayed empty). `bundle:start` brought it up within 2 s. From the first
# minute on, once a minute, a Resolved JDBC bundle is started (at most 3 times); each start is logged to stderr and
# counted in JDBC_KICKS, which the up and restart records report.
JDBC_KICKS=0
jdbc_state() { console "bundle:list -s" | grep -E 'org\.openhab\.persistence\.jdbc$' | awk -F'│' '{gsub(/ /, "", $2); print $2}' | head -1; }
# A second state (debug repro, same night): the feature recorded as installed and Started while neither the JDBC nor the
# SQLite bundle existed; `feature:uninstall` + `feature:install` brought persistence up within 4 s. From the second
# minute on, once a minute, at most 3 kicks in all: a Resolved bundle is started; a missing bundle under an installed
# feature is reinstalled.
wait_jdbc() { local i st
  for i in $(seq 1 180); do
    jdbc_ready && return 0
    if [ $i -ge 24 ] && [ $((i % 12)) -eq 0 ] && [ $JDBC_KICKS -lt 3 ]; then
      st=$(jdbc_state)
      if [ "$st" = "Resolved" ]; then
        JDBC_KICKS=$((JDBC_KICKS + 1))
        echo "$(date -u +%FT%TZ) $HUB: JDBC persistence bundle left Resolved; bundle:start (kick $JDBC_KICKS)" >&2
        console "bundle:start org.openhab.persistence.jdbc" >/dev/null
      elif [ -z "$st" ] && console "feature:list -i" | grep -q 'openhab-persistence-jdbc-sqlite'; then
        JDBC_KICKS=$((JDBC_KICKS + 1))
        echo "$(date -u +%FT%TZ) $HUB: JDBC feature installed but its bundle missing; feature reinstall (kick $JDBC_KICKS)" >&2
        console "feature:uninstall openhab-persistence-jdbc-sqlite" >/dev/null
        console "feature:install openhab-persistence-jdbc-sqlite" >/dev/null
      fi
    fi
    sleep 5
  done; return 1; }
bundles_active() { local out n; out=$(console "bundle:list -s"); for n in "$@"; do echo "$out" | grep -E "│ Active .*│ ${n}\$" >/dev/null || return 1; done; }
wait_bundles() { local i; for i in $(seq 1 36); do bundles_active "$@" && return 0; sleep 5; done; return 1; }
diag() {   # what the hub shows when a wait fails, to stderr (run_e11.sh appends it to config.log) before the teardown
  { echo "--- diagnostics for $HUB ($1), $(date -u +%FT%TZ)"
    docker exec "$HUB" sh -c 'ls /openhab/addons /openhab/userdata/persistence/jdbc 2>&1; grep -v "^#" /openhab/conf/services/addons.cfg | grep .;
      echo "--- openhab.log (jdbc, persistence, errors; console warnings dropped)";
      grep -vE "jline|NonBlocking|^[[:space:]]+at |^java.lang.Throwable" /openhab/userdata/logs/openhab.log 2>&1 \
        | grep -iE "jdbc|persist|sqlite|error|exception|refused|fail" | tail -40' 2>&1 | cut -c1-300
    echo "--- console: bundle and component state (jdbc, sqlite)"
    console "bundle:list -s" | grep -iE 'jdbc|sqlite|persistence'; console "scr:list" | grep -iE 'jdbc' | head -10
    echo "--- console: openhab:jdbc tables list all"; console "openhab:jdbc tables list all" | head -5
    echo "--- console: feature:list -i (jdbc|persistence)"; console "feature:list -i" | grep -iE 'jdbc|persistence' | head -10
    echo "--- docker logs (tail)"; docker logs --tail 15 "$HUB" 2>&1 | cut -c1-300; } >&2
}

case "$ACT" in
up)
  RUN=${3:?RUNDIR}; KIND=${4:-main}
  for c in $HUB $HAR $DBH; do docker ps -a --format '{{.Names}}' | grep -qx "$c" && { echo "exists: $c"; exit 3; }; done
  for v in $VCONF $VUSER $VADD; do docker volume inspect "$v" >/dev/null 2>&1 && { echo "exists: volume $v"; exit 3; }; done
  [ -f "$RUN/creds.json" ] || { echo "no $RUN/creds.json"; exit 3; }
  [ -f "$RUN/bundles/org.homeprov.e11.fixture-1.0.0.jar" ] || { echo "no fixture bundle in $RUN/bundles"; exit 3; }
  if [ "$KIND" = "main" ]; then
    [ -f "$RUN/bundles/org.homeprov.e11.lockbridge-1.0.0.jar" ] || { echo "no instrument bundle in $RUN/bundles"; exit 3; }
  fi
  T0=$(date -u +%s)
  docker network create --internal "$NET" >/dev/null
  docker network create "$PROV" >/dev/null
  for v in $VCONF $VUSER $VADD; do docker volume create "$v" >/dev/null; done
  # the image's own distribution files, then the E11 configuration (addons.cfg replaced, runtime.cfg appended)
  docker run --rm --name "$P-init" --network none --entrypoint sh -v "$VCONF":/openhab/conf -v "$VUSER":/openhab/userdata \
    -v "$VADD":/openhab/addons -v "$E11/conf":/e11conf:ro -v "$RUN/bundles":/bundles:ro "$OH_IMG" -c '
      set -e
      [ -d /openhab/dist/conf ] && [ -d /openhab/dist/userdata ] || { echo "no /openhab/dist in the image" >&2; exit 4; }
      cp -a /openhab/dist/conf/. /openhab/conf/ && cp -a /openhab/dist/userdata/. /openhab/userdata/
      mkdir -p /openhab/conf/services /openhab/conf/persistence /openhab/userdata/persistence/jdbc
      cp /e11conf/services/addons.cfg /openhab/conf/services/addons.cfg
      cp /e11conf/services/jdbc.cfg /openhab/conf/services/jdbc.cfg
      cp /e11conf/persistence/jdbc.persist /openhab/conf/persistence/jdbc.persist
      printf "\n# --- HOMEPROV E11 ---\n" >> /openhab/conf/services/runtime.cfg
      grep -v "^#" /e11conf/services/runtime.cfg | grep . >> /openhab/conf/services/runtime.cfg
      chown -R 9001:9001 /openhab/conf /openhab/userdata /openhab/addons' || exit 4
  mkdir -p "$RUN/hpctl/lock" "$RUN/hpctl/fixture"; chmod -R 0777 "$RUN/hpctl"
  docker run -d --name "$HUB" --network "$PROV" -e TZ=UTC -e EXTRA_JAVA_OPTS="-Duser.timezone=UTC" \
    -v "$VCONF":/openhab/conf -v "$VUSER":/openhab/userdata -v "$VADD":/openhab/addons -v "$RUN/hpctl":/hpctl \
    "$OH_IMG" >/dev/null || exit 5
  docker run -d --name "$HAR" --network "$NET" -v "$REPO/testbed/domoticz":/dzsrc:ro "$PY_IMG" sleep infinity >/dev/null || exit 5
  docker network connect "$NET" "$HUB"
  wait_rest || { diag "REST not up"; echo "hub REST not up"; exit 6; }
  wait_jdbc || { diag "JDBC not ready"; echo "JDBC persistence not installed"; exit 6; }
  # E11's own bundles enter the addons folder only now, with JDBC persistence up: at a first start the add-on
  # installation and the addons-folder deployment had run together, and 3 of 10 starts on 2026-10-24 left JDBC
  # unstarted or half-installed (see wait_jdbc). The jars stay in the volume, so restarts restore them as before.
  JARS="org.homeprov.e11.fixture"; [ "$KIND" = "main" ] && JARS="$JARS org.homeprov.e11.lockbridge"
  for j in $JARS; do docker cp "$RUN/bundles/$j-1.0.0.jar" "$HUB:/openhab/addons/$j-1.0.0.jar" >/dev/null || exit 5; done
  docker exec -u 0 "$HUB" sh -c 'chown 9001:9001 /openhab/addons/*.jar' || exit 5
  wait_bundles $JARS || { diag "E11 bundles not active"; echo "E11 bundles not active"; exit 6; }
  docker network disconnect "$PROV" "$HUB"; docker network rm "$PROV" >/dev/null
  OWNER_PW=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["owner"])' "$RUN/creds.json")
  MEMBER_PW=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["member"])' "$RUN/creds.json")
  # the console echoes typed input, so the output of a command carrying a password is discarded, never recorded
  console "openhab:users add owner $OWNER_PW administrator" >/dev/null; console "openhab:users add member $MEMBER_PW user" >/dev/null
  OWNER_PW=; MEMBER_PW=
  U1=$(console "openhab:users list" | grep -E 'owner|member' | tr -s ' ' | tr '\n' ';' | cut -c1-300); U2=""
  OUTSIDE=$(docker exec "$HUB" sh -c 'command -v curl >/dev/null && curl -s -m 5 -o /dev/null -w "%{http_code}" https://www.openhab.org/ || echo none' 2>/dev/null)
  if [ "$KIND" = "closure" ]; then
    docker run -d --name "$DBH" --network none --user 9001:9001 -v "$VUSER":/hub -v "$E11":/e11:ro "$PY_IMG" sleep infinity >/dev/null || exit 5
  fi
  # "openhab:info" does not exist in 5.2.3; the public REST root reports the runtime version
  VER=$(docker exec "$HAR" python3 -c "import urllib.request;print(urllib.request.urlopen('http://$HUB:8080/rest/',timeout=10).read().decode()[:600])" 2>/dev/null)
  BUNDLES=$(console "bundle:list -s" | grep -iE 'jdbc|sqlite|homeprov|persistence' | tr -s ' ' | tr '\n' ';' | cut -c1-1200)
  python3 - "$OH_IMG" "$T0" "$VER" "$BUNDLES" "$U1" "$U2" "$OUTSIDE" "$KIND" "$JDBC_KICKS" <<'PY'
import json, subprocess, sys, time
img, t0, ver, bundles, u1, u2, outside, kind, kicks = sys.argv[1:]
insp = subprocess.run(["docker", "image", "inspect", img.split("@")[0], "--format", "{{.Id}} {{json .RepoDigests}} {{.Architecture}}"],
                      capture_output=True, text=True).stdout.strip()
print(json.dumps({"image": img, "image_inspect": insp, "kind": kind, "openhab_info": ver, "bundles": bundles,
                  "users": u1, "hub_reaches_outside_after_provisioning": outside,
                  "jdbc_bundle_started_by_harness": int(kicks), "up_seconds": round(time.time() - float(t0), 1)}))
PY
  ;;
console)
  console "${3:?CMD}" ;;
restart)
  B=$(docker inspect "$HUB" --format '{{.State.StartedAt}}')
  # The hub is created on $PROV (provisioning, with internet), which `up` removes after provisioning; Docker keeps it as
  # the container's network mode, so a plain restart failed ("could not find a network matching network mode ...") and
  # left the hub stopped (found 2026-10-24 in smoke 2, before registration). $PROV is recreated INTERNAL (no outside
  # route) for the restart only, then disconnected and removed again: the hub stays on $NET alone, isolated.
  docker network inspect "$PROV" >/dev/null 2>&1 || docker network create --internal "$PROV" >/dev/null
  docker restart "$HUB" >/dev/null
  RUNNING=$(docker inspect "$HUB" --format '{{.State.Running}}')
  docker network disconnect "$PROV" "$HUB" >/dev/null 2>&1; docker network rm "$PROV" >/dev/null 2>&1
  if [ "$RUNNING" = "true" ]; then wait_rest && wait_jdbc; RC=$?; else RC=1; fi
  [ $RC = 0 ] || diag "restart: running=$RUNNING"
  echo "{\"started_before\": \"$B\", \"started_at\": \"$(docker inspect "$HUB" --format '{{.State.StartedAt}}')\", \"running\": $RUNNING, \"networks\": \"$(docker inspect "$HUB" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' | sed 's/ $//')\", \"jdbc_bundle_started_by_harness\": $JDBC_KICKS, \"ready\": $([ $RC = 0 ] && echo true || echo false)}"
  exit $RC ;;
snapshot)
  LAB=${3:?LABEL}; OUT=${4:?OUTDIR}
  mkdir -p "$OUT/jsondb_$LAB"
  for try in 1 2 3; do
    R=$(docker run --rm --network none --user 9001:9001 -v "$VUSER":/hub:ro -v "$OUT":/out --entrypoint python "$PROBE_IMG" -c '
import json, os, shutil, sqlite3, sys, time
lab = sys.argv[1]; dst = "/out/%s.db.part" % lab; t0 = time.time()
s = sqlite3.connect("file:/hub/persistence/jdbc/openhab.db?mode=ro", uri=True, timeout=60)
jm = s.execute("PRAGMA journal_mode").fetchone()[0]
d = sqlite3.connect(dst); s.backup(d); d.close(); s.close(); t1 = time.time()
for f in ("org.openhab.core.items.Item.json", "org.openhab.core.items.Metadata.json"):
    p = os.path.join("/hub/jsondb", f)
    if os.path.exists(p):
        shutil.copy2(p, os.path.join("/out/jsondb_%s" % lab, f))
q = sqlite3.connect("file:%s?mode=ro" % dst, uri=True).execute("PRAGMA quick_check").fetchone()[0]
print(json.dumps({"t_snapshot": t0, "t_done": t1, "quick_check": q, "hub_journal_mode": jm}))' "$LAB" 2>&1 | tail -1)
    case "$R" in "{"*'"quick_check": "ok"'*) mv "$OUT/$LAB.db.part" "$OUT/$LAB.db"; break ;; esac
    rm -f "$OUT/$LAB.db.part"; R=""; sleep 5
  done
  [ -n "$R" ] || { echo '{"ok": false}'; exit 7; }
  echo "${R%\}}, \"ok\": true, \"file\": \"$LAB.db\", \"sha256\": \"$(shasum -a 256 "$OUT/$LAB.db" | cut -d' ' -f1)\", \"bytes\": $(stat -f %z "$OUT/$LAB.db")}" ;;
down)
  docker rm -f "$HUB" "$HAR" "$DBH" >/dev/null 2>&1
  for n in "$NET" "$PROV"; do docker network rm "$n" >/dev/null 2>&1; done
  for v in "$VCONF" "$VUSER" "$VADD"; do docker volume rm "$v" >/dev/null 2>&1; done
  echo "{\"down\": \"$P\"}" ;;
*)
  echo "usage: e11_stack.sh guard | up PREFIX RUNDIR [closure|main] | console PREFIX CMD | restart PREFIX | snapshot PREFIX LABEL OUTDIR | down PREFIX"; exit 2 ;;
esac
