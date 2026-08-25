"""B1 — naive IN-DATABASE hash chain, DEMONSTRATED broken rather than assumed.

The design requires B1 be SHOWN broken. Asserting "the adversary recomputes it"
is exactly the kind of claim this project has been catching itself making.

Construction: a chain table inside the SAME recorder database, each row linking
to the previous. This is what a well-meaning implementer writes first, and it is
the strawman the RKA record identified on day one:
    "A hash chain stored in the same SQLite database the adversary can write is
     worthless: the adversary deletes an entry and recomputes the chain."
"""
from __future__ import annotations
import hashlib, sqlite3

H = lambda b: hashlib.sha256(b).hexdigest()


def install(db: str) -> dict:
    """Build an in-database hash chain over the provenance rows."""
    con = sqlite3.connect(db); cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS homeprov_chain")
    cur.execute("""CREATE TABLE homeprov_chain (
                     seq INTEGER PRIMARY KEY, node_key TEXT, digest TEXT)""")
    prev = "0" * 64
    rows = cur.execute("""SELECT 's:'||state_id, state, last_updated_ts,
                                 context_id_bin, context_parent_id_bin
                            FROM states ORDER BY last_updated_ts, state_id""").fetchall()
    for i, r in enumerate(rows, 1):
        d = H((prev + "|" + "|".join(str(x) for x in r)).encode())
        cur.execute("INSERT INTO homeprov_chain (seq,node_key,digest) VALUES (?,?,?)",
                    (i, r[0], d))
        prev = d
    con.commit(); con.close()
    return {"baseline": "B1", "chain_rows": len(rows), "head": prev}


def verify(db: str) -> dict:
    con = sqlite3.connect(db); cur = con.cursor()
    prev = "0" * 64
    rows = cur.execute("""SELECT 's:'||state_id, state, last_updated_ts,
                                 context_id_bin, context_parent_id_bin
                            FROM states ORDER BY last_updated_ts, state_id""").fetchall()
    stored = {r[0]: r[1] for r in cur.execute(
        "SELECT node_key, digest FROM homeprov_chain")}
    broken = []
    for r in rows:
        d = H((prev + "|" + "|".join(str(x) for x in r)).encode())
        if stored.get(r[0]) != d:
            broken.append(r[0])
        prev = d
    con.close()
    return {"baseline": "B1", "detected": bool(broken), "n_broken": len(broken)}


def adversary_repair(db: str) -> dict:
    """THE POINT. The adversary holds the same database, so after tampering it
    simply rebuilds the chain. One call. No key, no privilege beyond db_write."""
    r = install(db)
    return {"repaired": True, "new_head": r["head"],
            "cost": "one table rebuild; requires only db_write, which the "
                    "in-process adversary already has"}
