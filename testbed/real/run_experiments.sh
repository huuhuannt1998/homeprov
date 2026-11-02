#!/bin/bash
# HomeProv realistic-substrate experiment runner.
#
# Every experiment here runs against the REAL deployment: eclipse-mosquitto as
# the broker, devices announcing over real MQTT discovery, and automations
# instantiated from the motion-light blueprint Home Assistant ships. The
# synthetic `demo` platform is gone.
#
# Usage:  ./run_experiments.sh <experiment>
#         ./run_experiments.sh all
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/exp/out"
C=hpr-hass
mkdir -p "$OUT"

cmd() {  # send a command to a harness component and wait for its ack
  # Components do NOT share a file-naming convention: homeprov_e4 and
  # homeprov_e5 use /config/<domain>.cmd, homeprov_bench uses /config/bench_cmd.
  # Assuming one convention meant the bench never saw a single command and the
  # benign arm timed out looking for an ack that was never going to appear.
  local comp="$1" verb="$2" timeout="${3:-600}" cf af
  case "$comp" in
    homeprov_bench) cf=/config/bench_cmd; af=/config/bench_ack ;;
    *)              cf="/config/${comp}.cmd"; af="/config/${comp}.ack" ;;
  esac
  docker exec $C rm -f "$af" 2>/dev/null
  printf '%s' "$verb" > /tmp/hpr_cmd && docker cp /tmp/hpr_cmd "$C:$cf" >/dev/null
  local end=$((SECONDS+timeout))
  while [ $SECONDS -lt $end ]; do
    if docker exec $C test -f "$af" 2>/dev/null; then
      docker exec $C cat "$af"; echo; return 0
    fi
    sleep 5
  done
  echo "  TIMEOUT waiting for ${comp}.${verb}"; return 1
}

pull() { docker cp "$C:/config/homeprov_out/$1" "$OUT/$2" >/dev/null 2>&1 \
         && echo "  -> exp/out/$2" || echo "  (no $1 produced)"; }

enable_offensive() {  # install AND switch on an offensive component for one run
  # Clear any ack from a PREVIOUS run first. Without this the waiter below finds
  # a stale ack immediately and reports the old result as a fresh one -- which
  # it did, silently, returning a single-trial result from a harness that had
  # since been rewritten for ten trials.
  docker exec $C rm -f /config/homeprov_out/s1real_ack.json \
                       /config/homeprov_out/s1real_report.json 2>/dev/null
  # The files must be copied too. Only the defensive components are installed at
  # setup; adding the config line without the code loads nothing and the run
  # reports "no output produced" rather than an error.
  # REFUSE TO INSTALL A COMPONENT THAT IS NOT THERE. The comment above says
  # adding the config line without the code loads nothing and reports "no output
  # produced" rather than an error. That is exactly what happened on 2026-09-18:
  # the source lived in the experiment worktree, $HERE points at this one, the
  # copy moved nothing, HA restarted with an empty component directory and logged
  # NOTHING, and the driver sat in its 3600s ack wait per room for a result that
  # could never arrive. A missing harness must stop the run, not slow it down.
  [ -f "$HERE/ha-config/custom_components/$1/__init__.py" ] || {
    echo "  FAIL: no $1/__init__.py under $HERE/ha-config/custom_components/"
    echo "        refusing to restart the hub for a component that does not exist"
    exit 1; }
  docker exec $C mkdir -p "/config/custom_components/$1"
  docker cp "$HERE/ha-config/custom_components/$1/." "$C:/config/custom_components/$1/" >/dev/null
  docker exec $C test -f "/config/custom_components/$1/__init__.py" || {
    echo "  FAIL: $1 did not land in the container after docker cp"; exit 1; }
  docker exec $C sh -c "grep -q '^$1:' /config/configuration.yaml || printf '\n$1:\n' >> /config/configuration.yaml"
  docker restart $C >/dev/null; sleep 45
}
disable_offensive() {
  docker exec $C sh -c "sed -i '/^$1:/d' /config/configuration.yaml"
  docker exec $C rm -rf "/config/custom_components/$1"
  docker restart $C >/dev/null; sleep 45
}

check_binding() {
  echo "== scenario binding =="
  docker exec $C cat /config/homeprov_out/scenario_binding.json 2>/dev/null \
    || { echo "  NOT YET WRITTEN (hub may still be starting)"; return 1; }
  # Pulled into exp/out because a binding that only ever existed on stdout
  # cannot be checked later, and everything downstream depends on it.
  pull scenario_binding.json scenario_binding.json
}

case "${1:-}" in
  binding)  check_binding ;;

  E25)  # real-deployment characterisation vs the generator
        echo "== E25 real-deployment characterisation =="
        cd "$ROOT/exp" && python3 -c "
import json,sys,os; sys.path.insert(0,os.getcwd())
from stages import stage34_realchar as S
r=S.run({}); json.dump(r,open('out/stage34_realchar.json','w'),indent=2)
c=r.get('comparison',{})
for k,v in c.items(): print(f\"  {k:28s} real={v['real']:.4f} gen={v['generated_mean']:.4f} ratio={v['ratio_real_over_generated']:.2f}\")
d=r.get('largest_divergence',{}); print('  largest divergence:',d.get('dimension'))" ;;

  E4)   echo "== E4 renderer dependency closure, on the real substrate =="
        cmd homeprov_e4 closure 900;    pull e4_closure.json    e4_real_closure.json ;;

  E4ROLES)
        # Separate stage because it answers a different question and fails
        # differently: the closure asks which fields the renderer reads, this
        # asks whether this substrate even exhibits the roles that reach the
        # conditional ones. On a real MQTT deployment it largely does not, and
        # saying so is the result -- E4PARENT then constructs what is missing.
        echo "== E4 conditional-role retests, on the real substrate =="
        cmd homeprov_e4 roles 900;      pull e4_roles.json      e4_real_roles.json ;;

  E4PARENT)
        echo "== E4 constructive test for states.context_parent_id_bin =="
        echo "   No natural row here both opens its own context and carries a"
        echo "   resolvable parent, so the role is constructed and rolled back."
        cmd homeprov_e4 parentrole 900; pull e4_parentrole.json e4_real_parentrole.json ;;

  E5)   # Swept across the same three configurations as the flagship. The
        # innocent party is now bound to the scenario, so changing the room
        # changes WHICH shipped-blueprint instantiation the forgery frames --
        # the only thing that varies. Targets are adversary-planted lock
        # actuations either way.
        ROOMS="${HPR_ROOMS:-porch hallway kitchen}"
        echo "== E5 renderer-backed attack evaluation, rooms: $ROOMS =="
        for room in $ROOMS; do
          echo "-- configuration: $room --"
          docker exec $C sh -c "printf '%s' '$room' > /config/.hpr_room"
          docker restart $C >/dev/null; sleep 50
          cmd homeprov_e5 run 2400
          pull e5_renderer.json "e5_real_renderer_${room}.json"
        done
        echo "-- pooled across configurations --"
        python3 - "$OUT" $ROOMS <<'PYEOF'
import json, os, sys
from collections import defaultdict
out = sys.argv[1]; rooms = sys.argv[2:]
agg = {"configurations": [], "pooled_per_variant": {}}
pv = defaultdict(lambda: {"n": 0, "changed": 0, "misattributed": 0})
for r in rooms:
    f = os.path.join(out, "e5_real_renderer_%s.json" % r)
    if not os.path.exists(f):
        print("  %-9s MISSING" % r); continue
    d = json.load(open(f))
    bound = d.get("innocent_bound_to_scenario")
    agg["configurations"].append(
        {"room": r, "innocent": d.get("innocent_automation"),
         "innocent_bound": bound, "n_targets": d.get("n_targets"),
         "n_instances": d.get("n_instances"), "aborted": d.get("aborted"),
         "rate": d.get("renderer_confirmed_misattribution_rate")})
    print("  %-9s innocent=%s bound=%s targets=%s rate=%.3f"
          % (r, d.get("innocent_automation"), bound, d.get("n_targets"),
             d.get("renderer_confirmed_misattribution_rate") or 0.0))
    for k, v in (d.get("per_variant") or {}).items():
        pv[k]["n"] += v.get("n", 0)
        pv[k]["changed"] += v.get("changed", 0)
        pv[k]["misattributed"] += v.get("misattributed", 0)
try:
    from scipy.stats import beta
    def ci(k, n):
        lo = 0.0 if k == 0 else beta.ppf(0.025, k, n - k + 1)
        hi = 1.0 if k == n else beta.ppf(0.975, k + 1, n - k)
        return [lo, hi]
except Exception:
    def ci(k, n): return [None, None]
print()
print("  %-20s %4s %5s %5s %7s   95%% CI" % ("variant", "n", "chg", "mis", "rate"))
for k, v in sorted(pv.items(), key=lambda x: -x[1]["misattributed"]):
    n, m = v["n"], v["misattributed"]
    lo, hi = ci(m, n)
    v["rate"] = m / n if n else None
    v["ci95"] = [lo, hi]
    print("  %-20s %4d %5d %5d %7.3f   [%.3f, %.3f]"
          % (k, n, v["changed"], m, v["rate"], lo, hi))
agg["pooled_per_variant"] = dict(pv)
json.dump(agg, open(os.path.join(out, "e5_real_multiconfig.json"), "w"), indent=2)
print("  -> exp/out/e5_real_multiconfig.json")
PYEOF
        ;;

  E2)   echo "== E2 in-process defender subversion, on the real substrate =="
        echo "   the monitor now runs in its OWN CONTAINER with /config read-only,"
        echo "   which is stricter than the original testbed's separate process."
        enable_offensive homeprov_e2
        e2() {  # the component speaks a JSON op protocol on /config/e2_cmd
          docker exec $C rm -f /config/e2_ack 2>/dev/null
          printf '%s' "$1" > /tmp/e2c && docker cp /tmp/e2c "$C:/config/e2_cmd" >/dev/null
          local end=$((SECONDS+180))
          while [ $SECONDS -lt $end ]; do
            if docker exec $C test -f /config/e2_ack 2>/dev/null; then
              docker exec $C cat /config/e2_ack; echo; return 0; fi
            sleep 3
          done; echo "  TIMEOUT"; return 1
        }
        echo "-- 1. install the censoring hook (rebinds one module-level name)"
        e2 '{"op":"install"}'
        echo "-- 2. adversary actuates WHILE censoring its own context"
        ACT=$(e2 '{"op":"act"}'); echo "$ACT"
        echo "-- 3. what the IN-PROCESS defender can see"
        e2 '{"op":"diag"}'
        echo "-- 4. what the EXTERNAL monitor saw (own container, /config read-only)"
        CTX=$(printf '%s' "$ACT" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('ctx',''))
except Exception: print('')")
        echo "   adversary context: ${CTX:-<none>}"
        docker exec hpr-anchord sh -c 'wc -l < /anchor/chain.jsonl' | sed 's/^/   anchor records: /'
        # Output paths are parameterised so a re-run (e.g. under the authenticated
        # anchor) can write NEW files and never overwrite the published results.
        # Both default to the published names, so existing behaviour is unchanged.
        E2_EXTERNAL="${HPR_E2_EXTERNAL:-../../exp/out/e2_real_external.json}"
        python3 - "$CTX" "$E2_EXTERNAL" <<'PYEOF'
import json, subprocess, sys
ctx = (sys.argv[1] or "").strip()
dst = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else "../../exp/out/e2_real_external.json"
raw = subprocess.run(["docker","exec","hpr-anchord","cat","/anchor/chain.jsonl"],
                     capture_output=True, text=True).stdout
recs = [json.loads(l) for l in raw.splitlines() if l.strip()]
print(f"   anchor holds {len(recs)} sealed records")
out = {"adversary_context": ctx, "anchor_records": len(recs),
       "note": "the in-process defender's view is censored by construction; "
               "the anchor is written by the external monitor, which the "
               "in-process hook cannot reach"}
json.dump(out, open(dst, "w"), indent=2)
print("   -> %s" % dst)
PYEOF
        pull e2_result.json "${HPR_E2_RESULT:-e2_real_result.json}"
        disable_offensive homeprov_e2 ;;

  S1)   # The flagship, across THREE home configurations rather than one.
        #
        # The previous run measured 10/10 on a single configuration, and the
        # honest reading of that is n=1 in CONFIGURATION: the interval bounds
        # trial-to-trial variation, not whether the result is a property of the
        # attack or of the particular sensor/light/automation triple it was
        # demonstrated on. Each room below is an independent instantiation of
        # the SAME shipped blueprint, so switching rooms changes the
        # configuration under test and nothing about the attack.
        ROOMS="${HPR_ROOMS:-porch hallway kitchen}"
        echo "== S1 flagship laundering, rooms: $ROOMS =="
        for room in $ROOMS; do
          echo "-- configuration: $room --"
          # The room is read at import time by homeprov_scenario from a file in
          # the config directory. It cannot come from the environment: the hub
          # container's env is fixed by compose at create time, so `docker exec -e`
          # would set it for the exec'd shell and never for the hub process.
          docker exec $C sh -c "printf '%s' '$room' > /config/.hpr_room"
          # homeprov_s1real has NO command protocol: it self-triggers on
          # EVENT_HOMEASSISTANT_STARTED and writes its ack when done. So the
          # trigger is the restart inside enable_offensive, and the wait is on
          # the ack file, not on the /config/<domain>.ack the cmd() helper
          # expects. Using cmd() here waits forever on a path nothing writes.
          enable_offensive homeprov_s1real
          end=$((SECONDS+2400))
          while [ $SECONDS -lt $end ]; do
            if docker exec $C test -f /config/homeprov_out/s1real_ack.json 2>/dev/null; then
              docker exec $C cat /config/homeprov_out/s1real_ack.json; echo; break
            fi
            sleep 10
          done
          [ $SECONDS -ge $end ] && echo "  TIMEOUT on $room"
          pull s1real_report.json "s1_real_report_${room}.json"
          disable_offensive homeprov_s1real
        done
        echo "-- pooled across configurations --"
        python3 - "$OUT" $ROOMS <<'PYEOF'
import json, os, sys
out = sys.argv[1]; rooms = sys.argv[2:]
agg = {"configurations": [], "pooled": {}}
tot_n = tot_m = 0
for r in rooms:
    f = os.path.join(out, "s1_real_report_%s.json" % r)
    if not os.path.exists(f):
        print("  %-9s MISSING" % r); continue
    d = json.load(open(f))
    trials = d.get("trials", [])
    # The per-trial field is renderer_confirmed_misattribution. An earlier
    # version of this aggregator keyed on "misattributed", which no trial
    # carries, so every configuration scored 0/10 while the component's own
    # ack said 10/10. Cross-check against the report's own counters so a
    # future key rename fails loudly instead of reporting zeros.
    n = len(trials)
    m = sum(1 for t in trials if t.get("renderer_confirmed_misattribution"))
    if d.get("n_valid") != n or d.get("n_misattributed") != m:
        print("  %-9s SCHEMA MISMATCH: report says %s/%s, trials say %d/%d"
              % (r, d.get("n_misattributed"), d.get("n_valid"), m, n))
    from collections import Counter
    before = Counter(t.get("principal_before") for t in trials)
    ops = Counter()
    for t in trials:
        for k, v in (t.get("operations_used") or {}).items():
            ops[k] += v
    tot_n += n; tot_m += m
    agg["configurations"].append(
        {"room": r, "n": n, "misattributed": m,
         "innocent_party": d.get("innocent_party"),
         "principal_before": dict(before), "operations_total": dict(ops)})
    print("  %-9s %d/%d   before=%s  ops=%s"
          % (r, m, n, dict(before), dict(ops)))
if tot_n:
    try:
        from scipy.stats import beta
        lo = 0.0 if tot_m == 0 else beta.ppf(0.025, tot_m, tot_n - tot_m + 1)
        hi = 1.0 if tot_m == tot_n else beta.ppf(0.975, tot_m + 1, tot_n - tot_m)
    except Exception:
        lo = hi = float("nan")
    agg["pooled"] = {"n": tot_n, "misattributed": tot_m,
                     "rate": tot_m / tot_n, "ci95": [lo, hi],
                     "n_configurations": len(agg["configurations"])}
    print("  POOLED   %d/%d = %.3f  CI [%.3f, %.3f]  across %d configurations"
          % (tot_m, tot_n, tot_m / tot_n, lo, hi, len(agg["configurations"])))
json.dump(agg, open(os.path.join(out, "s1_real_multiconfig.json"), "w"), indent=2)
print("  -> exp/out/s1_real_multiconfig.json")
PYEOF
        ;;

  BENIGN) echo "== benign catalogue, false alarms on real device churn =="
        echo "   real service calls over the broker, not helper toggles"
        for v in reload interleave churn; do cmd homeprov_bench "$v" 300; done
        echo "-- verify the arm actually generated load --"
        # A benign arm that generated NO load reports zero false alarms just as
        # convincingly as one that generated plenty. The count is the control,
        # so it is written out and checked rather than eyeballed.
        docker cp "$ROOT/exp/delivery/check_load.py" "$C:/tmp/check_load.py" >/dev/null 2>&1
        docker exec $C python3 /tmp/check_load.py | tee /tmp/hpr_benign.txt
        python3 - "$OUT/benign_load_check.json" /tmp/hpr_benign.txt <<'PYEOF'
import json, re, sys
raw = open(sys.argv[2]).read()
nums = [int(n) for n in re.findall(r'(\d+)', raw)]
json.dump({"actuations": max(nums) if nums else 0,
           "raw": raw.strip()[:2000],
           "note": "actuations is the max integer the load check printed; it is "
                   "the control for the zero-false-alarm claim. Zero here means "
                   "the benign arm generated nothing and the claim is vacuous."},
          open(sys.argv[1], "w"), indent=2)
print("  -> exp/out/benign_load_check.json")
PYEOF
        ;;

  EC)   # E-C WRITE-TIME forgery, across the SAME three configurations as S1.
        #
        # Review 4b: the paper's guarantee covers post-commit editing, and the
        # adversary section 3.1 grants can forge attribution at WRITE time, where
        # no commitment can help. Section 3.4 asserted that the write-time
        # strategies leave the timeline naming the service call. This measures it
        # on the real deployment with the platform's own renderer, alongside a
        # post-commit positive control (arm P) run against the same live monitor
        # and anchor, so a zero detection rate for the write-time arms can be
        # distinguished from a detector that was not running.
        #
        # The rooms are the same three the flagship used, so an E-C rate and the
        # S1 30/30 are produced by the same oracle over the same configurations.
        ROOMS="${HPR_ROOMS:-porch hallway kitchen}"
        TRIALS="${HPR_EC_TRIALS:-10}"
        ARMS="${HPR_EC_ARMS:-\"W1\",\"W2\",\"W2b\",\"W3\",\"P\"}"
        # The E-D arms (PU, PI) reuse this whole block -- same component, same
        # monitor, same anchor, same verifier -- and differ only in which arms
        # run. Without a tag they would overwrite E-C's raw per-room reports and
        # its window marks, destroying the run that corrected section 3.4.
        TAG="${HPR_EC_TAG:-e_c}"
        echo "== E-C write-time forgery, rooms: $ROOMS, trials/arm: $TRIALS =="
        # The monitor and the anchor MUST be up: arm P is only a control if the
        # rows it edits were sealed first.
        for c in hpr-monitor hpr-anchord; do
          docker ps --format '{{.Names}}' | grep -qx "$c" || {
            echo "  FAIL $c is not running; arm P would not be a control"; exit 1; }
        done
        docker exec hpr-anchord sh -c 'wc -l < /anchor/chain.jsonl' \
          | sed 's/^/  anchor records before: /'
        date -u +%s > "$OUT/${TAG}_t_start"
        for room in $ROOMS; do
          echo "-- configuration: $room --"
          docker exec $C sh -c "printf '%s' '$room' > /config/.hpr_room"
          printf '{"trials": %s, "arms": [%s], "seal_wait_s": 130, "room": "%s"}' \
            "$TRIALS" "$ARMS" "$room" > /tmp/hpr_ec_conf
          docker cp /tmp/hpr_ec_conf "$C:/config/.hpr_ec_conf" >/dev/null
          docker exec $C rm -f /config/homeprov_out/ec_ack.json \
                               /config/homeprov_out/ec_report.json 2>/dev/null
          # homeprov_ec self-triggers on EVENT_HOMEASSISTANT_STARTED, exactly as
          # homeprov_s1real does, so the restart inside enable_offensive is the
          # trigger and the wait is on its own ack file.
          enable_offensive homeprov_ec
          end=$((SECONDS+3600))
          while [ $SECONDS -lt $end ]; do
            if docker exec $C test -f /config/homeprov_out/ec_ack.json 2>/dev/null; then
              docker exec $C cat /config/homeprov_out/ec_ack.json; echo; break
            fi
            sleep 10
          done
          [ $SECONDS -ge $end ] && echo "  TIMEOUT on $room"
          pull ec_report.json "${TAG}_report_${room}.json"
          disable_offensive homeprov_ec
        done
        date -u +%s > "$OUT/${TAG}_t_end"
        # Give the monitor time to seal and anchor the last segments of the run
        # before the verifier reads the chain.
        echo "  settling 90s so the final segments seal and anchor"
        sleep 90
        docker exec hpr-anchord sh -c 'wc -l < /anchor/chain.jsonl' \
          | sed 's/^/  anchor records after: /'
        echo "-- aggregate + verify --"
        python3 "$ROOT/exp/stages/e_c_write_time.py" --tag "$TAG" $ROOMS
        ;;

  all)  echo "Use ./run_all.sh instead: it preflights, resumes, and verifies"
        echo "that each stage produced a real result rather than just a file."
        for e in binding E25 E4 E4ROLES E4PARENT E5 E2 S1 BENIGN; do "$0" "$e"; echo; done ;;

  *)    echo "usage: $0 {binding|E25|E4|E4ROLES|E4PARENT|E5|E2|S1|BENIGN|all}"; exit 2 ;;
esac
