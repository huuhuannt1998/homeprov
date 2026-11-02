#!/bin/bash
# E9: start the seven-day run at a fixed wall-clock time (default 2026-10-11T09:15:00Z, 2 h 45 min before the week's
# START at 12:00 UTC), exactly as drafts/round13/E9_RUN_NOTES.md 4.2 says:
#     nohup caffeinate -i -s -m testbed/e9/run_e9.sh e9_main > <research-dir>/HOMEPROV-P13-exp/e9/e9_main.out 2>&1 &
# It holds caffeinate while it waits (so the Mac stays awake and the start is on time; the lid must stay open and the
# Mac on power), waits on the WALL clock (short sleeps, re-reading the time: a host sleep cannot stretch the wait), and
# exits WITHOUT starting if the pre-registration is missing, is not the registered one, or any file it freezes no longer
# has its registered sha256. Every step goes to its log.
#   Start detached:  nohup testbed/e9/start_e9_at.sh > <research-dir>/HOMEPROV-P13-exp/e9/start_e9_at.log 2>&1 &
set -u
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
AT=${E9_START_AT:-2026-10-11T09:15:00Z}
TAG=${E9_TAG:-e9_main}
PREREG=${E9_PREREG:-$REPO/exp/out/e9_preregistration.json}
EXPDIR="<research-dir>/HOMEPROV-P13-exp/e9"
OUTF=$EXPDIR/$TAG.out
log() { echo "$(date -u +%FT%TZ) $*"; }
cd "$REPO" || exit 2
caffeinate -i -s -m -w $$ &
AT_TS=$(python3 -c "import datetime as d,sys;print(int(d.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()))" "$AT")
log "start_e9_at: pid $$, will start $TAG at $AT ($AT_TS); pre-registration $PREREG"

check() {   # 0 iff the pre-registration exists, is registered, and every frozen file has its registered sha256
  [ -s "$PREREG" ] || { log "REFUSING: no pre-registration at $PREREG"; return 1; }
  python3 - "$PREREG" "$REPO" <<'PY'
import hashlib, json, os, sys
p, repo = sys.argv[1], sys.argv[2]
d = json.load(open(p))
if d.get("status") != "REGISTERED" or not d.get("registered_at"):
    print("REFUSING: the pre-registration is not a registered one (status %r)" % d.get("status")); sys.exit(1)
files = dict(d["code_sha256"]["files"])
bad = []
for f, want in files.items():
    path = os.path.join(repo, f)
    got = hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.exists(path) else None
    if got != want:
        bad.append((f, (want or "")[:16], (got or "missing")[:16]))
e6 = [k for k in d["code_sha256"] if k.startswith("homeprov_e6")]
for k in e6:
    path = "<research-dir>/HOMEPROV-P13-exp/e6/code/homeprov_e6/__init__.py"
    got = hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.exists(path) else None
    if got != d["code_sha256"][k]:
        bad.append((path, d["code_sha256"][k][:16], (got or "missing")[:16]))
if bad:
    print("REFUSING: %d frozen file(s) changed: %s" % (len(bad), bad)); sys.exit(1)
print("ok: %d frozen files match the registered pre-registration (sha256 %s)" % (
    len(files) + len(e6), hashlib.sha256(open(p, "rb").read()).hexdigest()))
PY
}

check || exit 3
while :; do
  now=$(date -u +%s)
  [ "$now" -ge "$AT_TS" ] && break
  left=$(( AT_TS - now ))
  [ $(( now % 3600 )) -lt 30 ] && log "waiting: ${left}s to go"
  sleep $(( left > 30 ? 30 : (left > 0 ? left : 1) ))
done
log "it is $(date -u +%FT%TZ): final checks"
check || exit 3
[ -e "$EXPDIR/$TAG" ] && { log "REFUSING: the run directory $EXPDIR/$TAG already exists"; exit 3; }
[ -e "$OUTF" ] && { log "REFUSING: $OUTF already exists"; exit 3; }
pgrep -f "run_e9.sh $TAG" >/dev/null && { log "REFUSING: run_e9.sh $TAG is already running"; exit 3; }
mkdir -p "$EXPDIR"
nohup caffeinate -i -s -m testbed/e9/run_e9.sh "$TAG" > "$OUTF" 2>&1 &
RPID=$!
log "started: nohup caffeinate -i -s -m testbed/e9/run_e9.sh $TAG > $OUTF (pid $RPID)"
sleep 20
if kill -0 "$RPID" 2>/dev/null; then log "run_e9.sh is running; first lines:"; head -5 "$OUTF"
else log "run_e9.sh exited at once:"; tail -20 "$OUTF"; fi
