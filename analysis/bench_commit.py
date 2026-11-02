"""M2 overhead: cost of the commitment path as a function of graph size.

Runs INSIDE the HA container so the measurement is on the real substrate
(native aarch64, real ARMv8 sha2 crypto, Pi-shaped cgroup envelope).

Measures HOMEPROV (content + parent hash + edge label) against B2 (content
only) so the price of edge binding is isolated.
"""
import hashlib, json, os, shutil, sqlite3, sys, time

H = lambda b: hashlib.sha256(b).digest()
ZERO = b"\x00" * 32
GRAN = [("second", 1.0), ("minute", 60.0), ("hour", 3600.0)]
SRC = "/config/home-assistant_v2.db"


def grow(dst, target):
    """Replicate real rows until the graph reaches `target` nodes."""
    shutil.copy(SRC, dst)
    con = sqlite3.connect(dst); cur = con.cursor()
    n = cur.execute("SELECT COUNT(*) FROM states").fetchone()[0] + \
        cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    while n < target:
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                         last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                       SELECT metadata_id,state,last_updated_ts+? ,last_changed_ts+?,
                              last_reported_ts+?,context_id_bin,context_parent_id_bin,0
                         FROM states LIMIT ?""", (n*0.001, n*0.001, n*0.001, min(n, target-n)))
        n += cur.rowcount
        if cur.rowcount == 0:
            break
    con.commit(); con.close()
    return n


def load(db):
    con = sqlite3.connect(db); nodes = []
    for sid, ent, st, ts, ctx, par in con.execute(
        """SELECT s.state_id, sm.entity_id, s.state, s.last_updated_ts,
                  s.context_id_bin, s.context_parent_id_bin
             FROM states s JOIN states_meta sm ON sm.metadata_id=s.metadata_id"""):
        c = json.dumps({"t":"s","e":ent,"s":st,"ts":round(ts or 0,6)},sort_keys=True).encode()
        nodes.append((ts or 0.0, "s:%d"%sid, c, ctx, par, "actuates"))
    for eid, ety, ts, ctx, par, data in con.execute(
        """SELECT e.event_id, et.event_type, e.time_fired_ts, e.context_id_bin,
                  e.context_parent_id_bin, ed.shared_data
             FROM events e JOIN event_types et ON et.event_type_id=e.event_type_id
             LEFT JOIN event_data ed ON ed.data_id=e.data_id"""):
        c = json.dumps({"t":"e","ty":ety,"ts":round(ts or 0,6),"d":data},sort_keys=True).encode()
        nodes.append((ts or 0.0, "e:%d"%eid, c, ctx, par, "invokes"))
    con.close()
    nodes.sort(key=lambda n:(n[0],n[1]))
    return nodes


def commit(nodes, scheme):
    rep, hashed = {}, []
    for ts, key, content, ctx, par, lbl in nodes:
        if scheme == "homeprov":
            ph = rep.get(par, ZERO) if par else ZERO
            h = H(content + b"|" + ph + b"|" + lbl.encode())
            if ctx is not None and ctx not in rep:
                rep[ctx] = h
        else:
            h = H(content)
        hashed.append((ts, h))
    phi = {}
    for name, w in GRAN:
        segs = {}
        for ts, h in hashed:
            s = segs.setdefault(int(ts//w), {"acc":ZERO,"n":0})
            s["acc"] = H(s["acc"]+h); s["n"] += 1
        phi[name] = {str(k):{"acc":v["acc"].hex(),"n":v["n"]} for k,v in segs.items()}
    return phi


if __name__ == "__main__":
    print("%-9s %-8s %-11s %-11s %-11s %-9s" %
          ("nodes","load_ms","HP_ms","B2_ms","HP/B2","phi_KB"))
    out = []
    for target in (500, 2000, 10000, 50000, 200000):
        db = "/tmp/bench_%d.db" % target
        n = grow(db, target)
        t0 = time.perf_counter(); nodes = load(db); t1 = time.perf_counter()
        # median of 3
        hp = min(( (lambda s=time.perf_counter(): (commit(nodes,"homeprov"), time.perf_counter()-s)[1])() ) for _ in range(3))
        b2 = min(( (lambda s=time.perf_counter(): (commit(nodes,"b2"), time.perf_counter()-s)[1])() ) for _ in range(3))
        phi = commit(nodes, "homeprov")
        kb = len(json.dumps(phi))/1024
        print("%-9d %-8.1f %-11.1f %-11.1f %-11.3f %-9.1f" %
              (n,(t1-t0)*1000, hp*1000, b2*1000, hp/b2, kb))
        out.append({"nodes":n,"load_ms":(t1-t0)*1000,"hp_ms":hp*1000,"b2_ms":b2*1000,
                    "ratio":hp/b2,"phi_kb":kb})
        os.remove(db)
    json.dump(out, open("/config/homeprov_out/bench_commit.json","w"), indent=2)
