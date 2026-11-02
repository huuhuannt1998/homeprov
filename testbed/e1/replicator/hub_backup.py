# E1 (round 12, 2026-10-08): runs INSIDE the hub's Core container on the HA OS host, invoked over SSH by the
# replicator on the other host. Takes a transactionally consistent SQLite online backup of the recorder (the same API
# the verifier's snapshot uses), prints the hub clock at the start of the backup on stderr, and writes the copy's bytes
# to stdout. It writes nothing to the recorder.
import sqlite3, sys, time
DST = "/tmp/e1_replica.db"
t = time.time()
s = sqlite3.connect("/config/home-assistant_v2.db", timeout=30)
d = sqlite3.connect(DST)
s.backup(d)
d.close()
s.close()
sys.stderr.write("%.6f\n" % t)
with open(DST, "rb") as fh:
    sys.stdout.buffer.write(fh.read())
