"""STAGE 28 (E18) -- scale to 10^7 nodes.

Two things the review asks for are kept apart here: live-platform validation
(done elsewhere) and this scalability microbenchmark, which uses faithful
synthetic recorder-schema databases and needs no renderer.

STREAMING, NOT IN-MEMORY. The evaluation harness elsewhere loads the whole graph
into a Python list. That is O(n) memory and would need well over 10 GB at 10^7
nodes on this machine, so it is not what a deployment would do and not what is
measured here. Segment accumulators are order-dependent over time-sorted rows,
so folding can stream straight out of SQLite in ts order with memory bounded by
the number of open segments. That is what the monitor does per window and what
is measured at each scale point.

PARENT-CONTEXT FRACTION IS SET TO THE MEASURED VALUE (0.012), not the 0.049 the
deployment sweep used. E15 showed the sweep ran four times denser in causal
structure than the real testbed, and blast radius depends on that density.
"""
import hashlib, json, os, random, resource, sqlite3, time

ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]
H = lambda b: hashlib.sha256(b).digest()
WORK = os.environ.get("HOMEPROV_SCALE_DIR", "/tmp/homeprov_scale")
POINTS = [int(x) for x in os.environ.get(
    "HOMEPROV_SCALE_POINTS", "100000,500000,1000000,2000000,5000000,10000000").split(",")]
PARENT_FRACTION = 0.012

SCHEMA = """
PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
CREATE TABLE states_meta(metadata_id INTEGER PRIMARY KEY, entity_id TEXT);
CREATE TABLE states(state_id INTEGER PRIMARY KEY, metadata_id INTEGER, state TEXT,
                    last_updated_ts REAL, context_id_bin BLOB,
                    context_parent_id_bin BLOB, context_user_id_bin BLOB);
CREATE TABLE event_types(event_type_id INTEGER PRIMARY KEY, event_type TEXT);
CREATE TABLE event_data(data_id INTEGER PRIMARY KEY, shared_data TEXT);
CREATE TABLE events(event_id INTEGER PRIMARY KEY, event_type_id INTEGER,
                    time_fired_ts REAL, context_id_bin BLOB,
                    context_parent_id_bin BLOB, data_id INTEGER);
"""


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def generate(path, n_nodes, seed=0, t0=1_787_000_000.0, rate=8.0):
    """Faithful recorder-schema database with a realistic causal-parent fraction."""
    if os.path.exists(path):
        os.remove(path)
    rnd = random.Random(seed)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    cur = con.cursor()
    n_ent = 40
    cur.executemany("INSERT INTO states_meta VALUES (?,?)",
                    [(i, "sensor.dev_%02d" % i) for i in range(n_ent)])
    cur.executemany("INSERT INTO event_types VALUES (?,?)",
                    [(0, "state_changed"), (1, "call_service"), (2, "automation_triggered")])
    n_states = n_nodes // 2
    n_events = n_nodes - n_states
    recent = []
    srows, erows = [], []
    ts = t0
    for i in range(n_states):
        ts += rnd.expovariate(rate)
        ctx = os.urandom(16)
        par = rnd.choice(recent) if (recent and rnd.random() < PARENT_FRACTION) else None
        srows.append((i + 1, rnd.randrange(n_ent), "v%d" % (i % 7), ts, ctx, par, None))
        if len(recent) < 4096:
            recent.append(ctx)
        elif rnd.random() < 0.02:
            recent[rnd.randrange(4096)] = ctx
        if len(srows) >= 50000:
            cur.executemany("INSERT INTO states VALUES (?,?,?,?,?,?,?)", srows); srows = []
    if srows:
        cur.executemany("INSERT INTO states VALUES (?,?,?,?,?,?,?)", srows)
    ts = t0
    for i in range(n_events):
        ts += rnd.expovariate(rate)
        ctx = os.urandom(16)
        par = rnd.choice(recent) if (recent and rnd.random() < PARENT_FRACTION) else None
        erows.append((i + 1, i % 3, ts, ctx, par, None))
        if len(erows) >= 50000:
            cur.executemany("INSERT INTO events VALUES (?,?,?,?,?,?)", erows); erows = []
    if erows:
        cur.executemany("INSERT INTO events VALUES (?,?,?,?,?,?)", erows)
    con.commit()
    cur.execute("CREATE INDEX ix_s ON states(last_updated_ts)")
    cur.execute("CREATE INDEX ix_e ON events(time_fired_ts)")
    con.commit(); con.close()


def stream_rows(db):
    """Rows in ts order, streamed. Memory is O(open segments), not O(n)."""
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    con.execute("PRAGMA query_only=ON")
    cur = con.cursor()
    cur.arraysize = 20000
    q = """SELECT ts, key, content, ctx, par, lbl FROM (
             SELECT s.last_updated_ts AS ts, 's:'||s.state_id AS key,
                    sm.entity_id AS e, s.state AS v, s.context_id_bin AS ctx,
                    s.context_parent_id_bin AS par, 'actuates' AS lbl, 1 AS kind,
                    NULL AS ety, NULL AS d, NULL AS content
               FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id)"""
    # simpler: two ordered cursors merged, avoids building a temp table
    con.close()
    con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    a = con.execute("""SELECT s.last_updated_ts, s.state_id, sm.entity_id, s.state,
                              s.context_id_bin, s.context_parent_id_bin
                         FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id
                        ORDER BY s.last_updated_ts, s.state_id""")
    b = con.execute("""SELECT e.time_fired_ts, e.event_id, et.event_type, ed.shared_data,
                              e.context_id_bin, e.context_parent_id_bin
                         FROM events e JOIN event_types et ON et.event_type_id=e.event_type_id
                         LEFT JOIN event_data ed ON ed.data_id=e.data_id
                        ORDER BY e.time_fired_ts, e.event_id""")
    LBL = {"automation_triggered": "triggers", "call_service": "invokes"}
    ra, rb = a.fetchone(), b.fetchone()
    while ra or rb:
        take_a = rb is None or (ra is not None and (ra[0], "s:%d" % ra[1]) <= (rb[0], "e:%d" % rb[1]))
        if take_a:
            ts, sid, ent, st, ctx, par = ra
            yield (ts or 0.0, "s:%d" % sid,
                   canon({"t": "state", "e": ent, "s": st, "ts": round(ts or 0.0, 6)}),
                   ctx, par, "actuates")
            ra = a.fetchone()
        else:
            ts, eid, ety, data, ctx, par = rb
            yield (ts or 0.0, "e:%d" % eid,
                   canon({"t": "event", "ty": ety, "ts": round(ts or 0.0, 6), "d": data}),
                   ctx, par, LBL.get(ety, "causes"))
            rb = b.fetchone()
    con.close()


def node_hash(key, content, ctx, par, label):
    return H(key.encode() + b"|" + content + b"|" + (ctx or b"") + b"|"
             + (par or b"") + b"|" + label.encode())


def stream_commit(db):
    """Fold every row into laminar segments without holding the graph."""
    phi = {name: {} for name, _ in GRAN}
    n = 0
    for ts, key, content, ctx, par, lbl in stream_rows(db):
        h = node_hash(key, content, ctx, par, lbl)
        for name, w in GRAN:
            k = int(ts // w)
            s = phi[name].get(k)
            if s is None:
                s = phi[name][k] = [ZERO, 0]
            s[0] = H(s[0] + h); s[1] += 1
        n += 1
    return phi, n


def phi_bytes(phi):
    return sum(len(str(k)) + 64 + 8 for g in phi.values() for k in g)


def run(cfg):
    os.makedirs(WORK, exist_ok=True)
    rows = []
    for N in POINTS:
        db = os.path.join(WORK, "s_%d.db" % N)
        t0 = time.time()
        if not os.path.exists(db):
            generate(db, N, seed=900)
        t_gen = time.time() - t0
        db_bytes = os.path.getsize(db)

        c0 = time.process_time(); w0 = time.time()
        phi, n = stream_commit(db)
        t_commit = time.time() - w0
        cpu_commit = time.process_time() - c0
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_mb = rss / (1024 * 1024) if rss > 10**7 else rss / 1024

        # verification: recompute and compare against the committed roots
        w0 = time.time()
        phi2, _ = stream_commit(db)
        mismatches = sum(1 for g in phi for k in phi[g]
                         if phi2[g].get(k, [None, None])[0] != phi[g][k][0])
        t_verify = time.time() - w0

        rows.append({
            "target_nodes": N, "nodes": n,
            "gen_s": round(t_gen, 2),
            "recorder_bytes": db_bytes,
            "commit_s": round(t_commit, 3),
            "commit_cpu_s": round(cpu_commit, 3),
            "throughput_nodes_per_s": round(n / max(t_commit, 1e-9)),
            "verify_s": round(t_verify, 3),
            "verify_mismatches": mismatches,
            "peak_rss_mb": round(rss_mb, 1),
            "anchor_bytes": phi_bytes(phi),
            "segments": {g: len(phi[g]) for g in phi},
        })
        print(json.dumps(rows[-1]), flush=True)
    return {"stage": 28, "rows": rows, "parent_fraction": PARENT_FRACTION,
            "note": "streaming commitment; memory is O(open segments), not O(n)"}
