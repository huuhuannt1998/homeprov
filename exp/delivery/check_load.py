"""Did the benign arm actually generate load?

A benign false-alarm arm that silently generated nothing would report zero false
alarms having done nothing at all, which is indistinguishable from success. This
is checked rather than assumed.
"""
import sqlite3, time
c = sqlite3.connect("/config/home-assistant_v2.db")
lo = time.time() - 300
n = c.execute("SELECT COUNT(*) FROM states WHERE last_updated_ts>?", (lo,)).fetchone()[0]
e = c.execute("""SELECT COUNT(*) FROM events e
                   JOIN event_types et ON et.event_type_id=e.event_type_id
                  WHERE et.event_type='call_service' AND e.time_fired_ts>?""",
              (lo,)).fetchone()[0]
p = c.execute("""SELECT COUNT(*) FROM states
                  WHERE last_updated_ts>? AND context_parent_id_bin IS NOT NULL""",
              (lo,)).fetchone()[0]
print(f"   last 5 min: {n} state rows, {e} call_service events, {p} with causal parents")
print("   VERDICT:", "load generated" if e > 0 else "NO LOAD -- arm is meaningless")
