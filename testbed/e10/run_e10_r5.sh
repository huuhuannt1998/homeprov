#!/bin/bash
# E10 review-r5 arms that do not use the e10s stack (drafts/round13/E10_ADDENDUM_R5.md sections C, D, E), in sequence:
#   dz        arm C: a benign switch-type change on the Domoticz test stack with the closure monitor live
#             (testbed/e10/run_dz_switchtype.sh, copied from testbed/domoticz/run_dz.sh; ~45 min)
#   pairwise  arm D: pairwise closure mutation with logbook branch coverage on a copy of the lab recorder
#             (exp/stages/e10_pairwise_closure.py plan / up / run / summarize / down; ~1.5 h, capped at 3 h of units)
#   pi4       arm E: per-poll cost under a Raspberry Pi 4-class CPU, memory and block-I/O cap
#             (exp/sp2027/e10_pi4_cost.py run / summarize; 10 runs, ~1.5-2 h)
# Arms S and R run inside run_e10.sh's main phase (they need the e10s stack and its monitors).
#
#   Real:   nohup testbed/e10/run_e10_r5.sh e10_main all > <research-dir>/HOMEPROV-P13-exp/e10/e10_main_r5.out 2>&1 &
#   Smoke:  HPR_E10R5_SMOKE=1 testbed/e10/run_e10_r5.sh e10r5_smoke1 all      (outputs outside exp/out; not results)
# Refuses before 2026-10-19T16:01Z, while E9, E10's main phase or E12 runs, when the interpreter guard fails, and (real
# run) unless exp/out/e10_preregistration.json is registered and every frozen file matches it. Never overwrites.
set -u
export PATH="<home>/miniconda3/bin:$PATH"
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
X="<research-dir>/HOMEPROV-P13-exp/e10"
TAG=${1:?usage: run_e10_r5.sh TAG [all|dz|pairwise|pi4]}
WHAT=${2:-all}
SMOKE=${HPR_E10R5_SMOKE:-0}
PY=${HPR_E10_PY:-<home>/miniconda3/bin/python3}
NOT_BEFORE=1792425660
case "$WHAT" in all|dz|pairwise|pi4) ;; *) echo "usage: run_e10_r5.sh TAG [all|dz|pairwise|pi4]"; exit 2 ;; esac
[ "$(date -u +%s)" -lt "$NOT_BEFORE" ] && { echo "REFUSING: before 2026-10-19T16:01:00Z (E9 owns Docker on this Mac)"; exit 2; }
pgrep -f "testbed/e9/run_e9.sh|testbed/e10/run_e10.sh|testbed/e12/run_e12.sh" >/dev/null && { echo "REFUSING: E9, E10 or E12 is running"; exit 2; }
docker ps -a --format '{{.Names}}' | grep -qE '^(e9|e9s|e10s|e10u|e12|e10p|e10e|dz)-' && { echo "REFUSING: containers of another run exist"; exit 3; }
G=$("$PY" "$REPO/testbed/e10/e10ops.py" pyguard 2>&1 | tail -1)
case "$G" in *'"ok": true'*) ;; *) echo "REFUSING: interpreter guard failed: $G"; exit 4 ;; esac
if [ "$SMOKE" != "1" ]; then
  "$PY" "$REPO/testbed/e10/e10_prereg.py" --check "$REPO/exp/out/e10_preregistration.json" || { echo "REFUSING: E10 pre-registration not registered or a frozen file changed"; exit 2; }
  OUTDIR=$REPO/exp/out
else
  OUTDIR=$X/smoke/out
fi
mkdir -p "$X" "$OUTDIR"
LOG=$X/${TAG}_r5.log
[ -e "$LOG" ] && { echo "REFUSING: $LOG exists"; exit 3; }
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }
caffeinate -i -s -m -w $$ & CAFF=$!
trap 'kill $CAFF 2>/dev/null' EXIT
note "tag=$TAG what=$WHAT smoke=$SMOKE python=$G load=$(uptime)"

if [ "$WHAT" = all ] || [ "$WHAT" = dz ]; then
  if [ "$SMOKE" = "1" ]; then PRE=120; POST=120; else PRE=600; POST=600; fi
  note "== arm C (Domoticz switch type): tag ${TAG}_dzst pre ${PRE}s post ${POST}s"
  "$REPO/testbed/e10/run_dz_switchtype.sh" "${TAG}_dzst" "$OUTDIR" "$PRE" "$POST" >> "$LOG" 2>&1; note "arm C exit $?"
  for c in dz-domoticz dz-anchord dz-monitor dz-harness; do docker rm -f "$c" >/dev/null 2>&1; done
  note "arm C containers removed (volumes dz-${TAG}_dzst-* kept for inspection)"
fi
if [ "$WHAT" = all ] || [ "$WHAT" = pairwise ]; then
  note "== arm D (pairwise closure mutation)"
  P=$REPO/exp/stages/e10_pairwise_closure.py
  if [ "$SMOKE" = "1" ]; then "$PY" "$P" plan --smoke >> "$LOG" 2>&1; else "$PY" "$P" plan >> "$LOG" 2>&1; fi
  "$PY" "$P" up >> "$LOG" 2>&1 && "$PY" "$P" run >> "$LOG" 2>&1 && "$PY" "$P" summarize >> "$LOG" 2>&1
  note "arm D exit $?"
  "$PY" "$P" down >> "$LOG" 2>&1
fi
if [ "$WHAT" = all ] || [ "$WHAT" = pi4 ]; then
  note "== arm E (Pi 4-class cost)"
  C=$REPO/exp/sp2027/e10_pi4_cost.py
  if [ "$SMOKE" = "1" ]; then
    "$PY" "$C" run --smoke --only e10pi4_pi4_k1_direct_qc720 e10pi4_pi4_k1_copy_qc1 >> "$LOG" 2>&1; note "arm E smoke exit $?"
  else
    "$PY" "$C" run >> "$LOG" 2>&1 && "$PY" "$C" summarize >> "$LOG" 2>&1; note "arm E exit $?"
  fi
fi
note "done; load=$(uptime)"
