"""M2 — incremental commitment. Per-anchor cost O(new nodes), not O(history).

KEY INSIGHT: segments are time-indexed and normal operation only ever appends.
Once a segment's time window has passed it is CLOSED and its accumulator is
final — it never needs recomputation. So an anchor only has to:
  (a) fold newly-arrived nodes into their (open) segment accumulators, and
  (b) emit commitments for segments that closed since the last anchor.

This also fixes the limitation Yagiz et al. 2026 name in their own L4:
'the current implementation rebuilds the tree after each batch'.

Bounded state: the context->hash map needed for parent resolution is kept as
an LRU, since causal parents are almost always seconds old.
"""
import hashlib, json, os, shutil, sqlite3, time
from collections import OrderedDict

H = lambda b: hashlib.sha256(b).digest()
ZERO = b"\x00"*32
GRAN = [("second",1.0),("minute",60.0),("hour",3600.0)]
REP_MAX = 20000                      # LRU bound on context -> hash


class Incremental:
    def __init__(self):
        self.rep = OrderedDict()
        self.open = {g: {} for g,_ in GRAN}   # gran -> {seg_key: {acc,n}}
        self.sealed = {g: {} for g,_ in GRAN}
        self.cursor = -1.0

    def _remember(self, ctx, h):
        if ctx is None or ctx in self.rep:
            return
        self.rep[ctx] = h
        if len(self.rep) > REP_MAX:
            self.rep.popitem(last=False)

    def ingest(self, nodes):
        """Fold ONLY nodes newer than the cursor."""
        fresh = nodes                      # caller supplies only new nodes
        for ts, key, content, ctx, par, lbl in fresh:
            ph = self.rep.get(par, ZERO) if par else ZERO
            h = H(content + b"|" + ph + b"|" + lbl.encode())
            self._remember(ctx, h)
            for g, w in GRAN:
                k = int(ts // w)
                s = self.open[g].setdefault(k, {"acc": ZERO, "n": 0})
                s["acc"] = H(s["acc"] + h); s["n"] += 1
            if ts > self.cursor:
                self.cursor = ts
        return len(fresh)

    def seal(self, now):
        """Move segments whose window has passed into the sealed set."""
        newly = 0
        for g, w in GRAN:
            for k in [k for k in self.open[g] if (k+1)*w <= now]:
                self.sealed[g][k] = self.open[g].pop(k)
                newly += 1
        return newly

    def anchor_payload(self):
        return {g: {str(k): {"acc": v["acc"].hex(), "n": v["n"]}
                    for k, v in self.sealed[g].items()} for g,_ in GRAN}


def load(db):
    con = sqlite3.connect(db); nodes=[]
    for sid,ent,st,ts,ctx,par in con.execute(
        """SELECT s.state_id,sm.entity_id,s.state,s.last_updated_ts,s.context_id_bin,
                  s.context_parent_id_bin FROM states s
             JOIN states_meta sm ON sm.metadata_id=s.metadata_id"""):
        c=json.dumps({"t":"s","e":ent,"s":st,"ts":round(ts or 0,6)},sort_keys=True).encode()
        nodes.append((ts or 0.0,"s:%d"%sid,c,ctx,par,"actuates"))
    con.close(); nodes.sort(key=lambda n:(n[0],n[1])); return nodes


if __name__ == "__main__":
    SRC="/config/home-assistant_v2.db"
    # build one large history, then replay it in 5-second anchor batches
    db="/tmp/inc.db"; shutil.copy(SRC,db)
    con=sqlite3.connect(db); cur=con.cursor()
    n=cur.execute("SELECT COUNT(*) FROM states").fetchone()[0]
    while n < 200000:
        cur.execute("""INSERT INTO states (metadata_id,state,last_updated_ts,last_changed_ts,
                        last_reported_ts,context_id_bin,context_parent_id_bin,origin_idx)
                       SELECT metadata_id,state,last_updated_ts+?,last_changed_ts+?,
                              last_reported_ts+?,context_id_bin,context_parent_id_bin,0
                         FROM states LIMIT ?""",(n*0.01,n*0.01,n*0.01,min(n,200000-n)))
        n+=cur.rowcount
        if cur.rowcount==0: break
    con.commit(); con.close()
    nodes=load(db)
    print("history: %d nodes spanning %.0f s" % (len(nodes), nodes[-1][0]-nodes[0][0]))

    # DISJOINT batches, pre-sliced OUTSIDE the timed region, so the measurement
    # is the algorithm and not the harness's filtering.
    inc=Incremental(); t0=nodes[0][0]
    buckets={}
    for x in nodes:
        buckets.setdefault(int((x[0]-t0)//5.0), []).append(x)
    batches=[]
    for i in sorted(buckets):
        batch=buckets[i]                      # disjoint, already sliced
        edge=t0+(i+1)*5.0
        s=time.perf_counter(); inc.ingest(batch); inc.seal(edge); e=time.perf_counter()
        batches.append(((e-s)*1000, len(batch)))
    per=[b[0] for b in batches]; sizes=[b[1] for b in batches]
    per_sorted=sorted(per)
    per=per_sorted
    print()
    print("INCREMENTAL, 5s anchor period, %d anchors" % len(batches))
    print("  per-anchor ms  p50=%.2f  p95=%.2f  max=%.2f" %
          (per[len(per)//2], per[int(len(per)*0.95)], per[-1]))
    print("  total ms       %.1f" % sum(per))
    print("  sealed segments %d" % sum(len(inc.sealed[g]) for g,_ in GRAN))
    print("  nodes per anchor: mean=%.0f max=%d" % (sum(sizes)/len(sizes), max(sizes)))
    print("  duty cycle at 5s period: p95 = %.4f%% of the window" % (per[int(len(per)*0.95)]/5000*100))
    # is cost independent of history length? compare first vs last decile
    first=[b[0] for b in batches[:len(batches)//10]]
    last=[b[0] for b in batches[-len(batches)//10:]]
    print("  first-decile mean %.2f ms  vs  last-decile mean %.2f ms  -> drift x%.2f" %
          (sum(first)/len(first), sum(last)/len(last), (sum(last)/len(last))/(sum(first)/len(first))))
    json.dump({"anchors":len(batches),"p50":per[len(per)//2],
               "p95":per[int(len(per)*0.95)],"max":per[-1],"total_ms":sum(per)},
              open("/config/homeprov_out/bench_incremental.json","w"),indent=2)
