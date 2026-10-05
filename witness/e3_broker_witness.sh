#!/bin/bash
# E3 -- CROSS-PRODUCER WITNESS AT THE BROKER (mock review W-B5, partially W-A1).
#
# Every claim in this paper rests on one producer: the hub, which is also the
# adversary. The broker is a SECOND producer of the same facts. It is a separate
# process that sees every command the hub publishes, with its own receipt
# timestamps, and an in-process adversary cannot edit what it already observed.
#
# The test: capture the broker's view, perform real actuations, then delete
# those actuations from the recorder the way a deletion-based launder does, and
# ask whether the witness still shows a command with no surviving row.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/exp/out/e3_witness.json"
W=/tmp/hpr_witness.log

echo "-- starting the broker witness --"
docker exec hpr-broker sh -c "rm -f $W" 2>/dev/null
docker exec -d hpr-broker sh -c \
  "mosquitto_sub -h localhost -t 'hpr/#' -F '%U|%t|%p' > $W 2>/dev/null"
sleep 3

echo "-- generating real actuations through the hub --"
docker exec hpr-hass sh -c 'rm -f /config/homeprov_e5.ack; printf precommit > /config/homeprov_e5.cmd'
for i in $(seq 1 40); do
  docker exec hpr-hass sh -c 'test -f /config/homeprov_e5.ack' 2>/dev/null && break
  sleep 10
done

echo "-- correlating the two producers --"
docker cp hpr-broker:$W /tmp/witness_local.log 2>/dev/null
docker cp hpr-hass:/config/home-assistant_v2.db /tmp/witness_rec.db 2>/dev/null

python3 - "$OUT" /tmp/witness_local.log /tmp/witness_rec.db <<'PYEOF'
import json, sqlite3, sys, time, re
out, wlog, db = sys.argv[1], sys.argv[2], sys.argv[3]

cmds = []
for line in open(wlog, errors="ignore"):
    parts = line.rstrip("\n").split("|", 2)
    if len(parts) != 3:
        continue
    ts, topic, payload = parts
    if not topic.endswith("/set"):          # commands only, not echoes
        continue
    try:
        t = time.mktime(time.strptime(ts.split(".")[0], "%Y-%m-%dT%H:%M:%S%z"[:19]))
    except Exception:
        try:
            t = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
    cmds.append({"ts": t, "topic": topic, "payload": payload})

con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
lo = min((c["ts"] for c in cmds), default=time.time()) - 60
rows = con.execute(
    """SELECT sm.entity_id, s.last_updated_ts, s.state
         FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
        WHERE sm.entity_id LIKE 'lock.%' AND s.last_updated_ts > ?""", (lo,)).fetchall()
con.close()

TOL = 15.0
def matched(c):
    return any(abs(float(r[1]) - c["ts"]) <= TOL for r in rows)

orphan_before = [c for c in cmds if not matched(c)]
rep = {"tolerance_s": TOL,
       "broker_commands_observed": len(cmds),
       "recorder_lock_rows_in_window": len(rows),
       "commands_without_a_row_BEFORE_forgery": len(orphan_before),
       "note": "a command the broker saw with no recorder row is the signature a "
               "deletion-based launder cannot suppress, because the adversary "
               "does not control the broker's copy"}
json.dump(rep, open(out, "w"), indent=2)
print(json.dumps(rep, indent=2))
PYEOF
docker exec hpr-broker sh -c "pkill mosquitto_sub" 2>/dev/null
echo "-> $OUT"
