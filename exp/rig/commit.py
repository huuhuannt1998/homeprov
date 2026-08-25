"""A2 COMMIT-LAMINAR — nested, time-indexed commitments over the graph.

Three schemes over the SAME graph so comparisons isolate one variable:

  homeprov : h(v) = H( content(v) || h(parent) || edge_label )   <- insight I-1
  b2       : h(v) = H( content(v) )                              <- record-level (Yagiz/Crosby-Wallach)
  b4       : identical to homeprov but with edge binding DISABLED (self-baseline AB-3)
  b2b      : full physical row  (fair record-level baseline, mock review R2)
  b2c      : renderer closure   (the fields E4 measured the logbook to consume)
  row      : the recommended design -- key, content, context, parent, label

The laminar family (second in minute in hour) is chosen for FORENSIC properties,
and MEASURED in M2 to pay off three ways:
  (1) tractability  -- MIN-QUARANTINE becomes greedy-exact (Prop. 2)
  (2) localization  -- a violation quarantines a second, not the epoch
  (3) storage       -- a closed hour subsumes its minutes/seconds (1080x reduction)
"""
from __future__ import annotations
import hashlib
from collections import OrderedDict

H = lambda b: hashlib.sha256(b).digest()
ZERO = b"\x00" * 32
GRAN = OrderedDict([("second", 1.0), ("minute", 60.0), ("hour", 3600.0)])
REP_MAX = 20000          # bounded LRU: causal parents are almost always seconds old


def node_hashes(nodes, scheme="homeprov"):
    """Topological (time-ordered) hashing. Re-parenting changes the CHILD's hash
    under 'homeprov' even though its content is untouched -- which is exactly the
    case M1 measured as content_byte_identical = true."""
    rep: OrderedDict = OrderedDict()
    out = []
    for n in nodes:
        if scheme == "b2c":
            # RENDERER-CLOSURE COMMITMENT (E3-B2c, added 2026-08-25 after E4).
            # The mock review asked for a third record-level baseline committing
            # "every row/field needed to reconstruct attribution". E4 determined
            # that set by mutation against HA 2026.7.4's own logbook processor
            # rather than by reading the schema: fourteen fields across states and
            # events, of which THREE are covered by no other scheme in this rig --
            # context_user_id_bin on both tables, old_state_id, and last_changed_ts.
            #
            # The first is the interesting one. context_user_id_bin is what the
            # timeline uses to name a PERSON, so a scheme that omits it cannot
            # detect an adversary that reassigns an action to a household member;
            # that is the fourth identity omission this construction has produced,
            # after parent identity, node key, and node context. old_state_id and
            # last_changed_ts are not attribution values at all -- they are render
            # ELIGIBILITY, and rewriting either removes a row from the timeline
            # without deleting it, which is deletion with none of its evidence.
            #
            # B2c is therefore not a weaker `row`; on this platform it is a
            # STRICTLY LARGER commitment than the scheme the paper recommends,
            # while still smaller than the whole physical row.
            pid = n.par or b""
            cid = n.ctx or b""
            usr = n.usr or b""
            prev = b"" if n.prev is None else str(n.prev).encode()
            chg = b"" if n.changed is None else repr(round(n.changed, 6)).encode()
            h = H(n.key.encode() + b"|" + n.content + b"|" + cid + b"|" + pid
                  + b"|" + usr + b"|" + prev + b"|" + chg + b"|" + n.label.encode())
        elif scheme == "row":
            # FULL-ROW COMMITMENT (2026-08-24). This is the scheme the external
            # monitor implements and the one the re-centred paper recommends.
            # It commits the record exactly as stored: primary key, payload, and
            # both causal columns. The point of the E3/E16/E11 sequence is that
            # a construction which CHOOSES which fields matter kept omitting one
            # (parent identity, then node key, then node context); committing the
            # record omits nothing by construction.
            pid = n.par or b""
            cid = n.ctx or b""
            h = H(n.key.encode() + b"|" + n.content + b"|" + cid + b"|" + pid
                  + b"|" + n.label.encode())
        elif scheme == "homeprov2":
            # HOMEPROV with the node's OWN IDENTITY bound (E16 fix, 2026-08-24).
            # Root cause of the FT-6 miss: h() covered content, parent id, parent
            # hash and label, but NOT the node's own key. Two rows of the same
            # entity and state with no parent therefore hash to values that differ
            # only through the timestamp inside content, so exchanging their
            # timestamps EXCHANGES their hashes. The multiset of hashes in each
            # segment is unchanged, every accumulator matches, and the swap is
            # invisible. Measured on seed 83: hashes swapped exactly, multiset
            # unchanged, homeprov/b2/b4 missed it and the full-row b2b caught it
            # only because it happens to bind context_id, which does not swap.
            #
            # This is the same class of flaw as the parent-identity hole closed on
            # 2026-08-20: a commitment that omits an identity cannot distinguish
            # two things that differ only by that identity.
            pid = n.par or b""
            ph = rep.get(n.par, ZERO) if n.par else ZERO
            h = H(n.key.encode() + b"|" + n.content + b"|" + pid + b"|" + ph
                  + b"|" + n.label.encode())
        elif scheme == "homeprov":
            # Bind the parent's IDENTITY as well as its hash. Binding only the
            # hash is unsound: an unresolvable parent resolves to ZERO, which is
            # byte-identical to HAVING NO PARENT -- so re-parenting onto a
            # dangling context would be invisible. Found by AB-1 on 2026-08-20;
            # it is the same class of flaw this work accuses B2 of.
            pid = n.par or b""
            ph = rep.get(n.par, ZERO) if n.par else ZERO
            h = H(n.content + b"|" + pid + b"|" + ph + b"|" + n.label.encode())
        elif scheme == "b2b":
            # FAIR RECORD-LEVEL BASELINE (added 2026-08-24 after mock review R2).
            # B2 commits `content` only, and `content` deliberately excludes the
            # three context columns -- which are physically part of the recorder
            # row the attack edits. A real record-level scheme applied to these
            # rows would hash the WHOLE row, context columns included, and would
            # therefore see a re-parent as a changed row. B2b is that scheme.
            #
            # What separates it from HOMEPROV is then exactly one thing: B2b
            # commits the edge AS DATA on the child row, whereas HOMEPROV commits
            # it TRANSITIVELY by folding in the parent's own hash. Any residual
            # detection difference must come from that recursion and nothing else.
            pid = n.par or b""
            cid = n.ctx or b""
            h = H(n.content + b"|" + cid + b"|" + pid + b"|" + n.label.encode())
        elif scheme == "b4":                      # edge binding disabled
            h = H(n.content + b"|" + ZERO + b"|" + n.label.encode())
        else:                                     # b2: content only
            h = H(n.content)
        if n.ctx is not None and n.ctx not in rep:
            rep[n.ctx] = h
            if len(rep) > REP_MAX:
                rep.popitem(last=False)
        out.append((n.ts, n.key, h))
    return out


def context_counts(nodes, grans=None) -> dict:
    """Per-segment, per-context membership counts.

    ADDED 2026-08-20 after Stage 4 measured an unfixable Miss-R-assert.
    A deleted node is ABSENT from the post-forgery graph, so the segment
    accumulator tells you SOMETHING was removed but never WHICH CONTEXT lost a
    member -- and attribution is computed per context. Committing per-context
    counts makes deletion ATTRIBUTABLE, so exactly the affected actuations
    abstain instead of either (a) asserting a degraded attribution or
    (b) abstaining across the whole graph.

    Cost is small: contexts per second are few.
    """
    grans = grans or GRAN
    out = {}
    for name, w in grans.items():
        segs = {}
        for n in nodes:
            if n.ctx is None:
                continue
            k = str(int(n.ts // w))
            segs.setdefault(k, {}).setdefault(n.ctx.hex(), 0)
            segs[k][n.ctx.hex()] += 1
        out[name] = segs
    return out


def tainted_contexts(before_counts: dict, nodes, grans=None) -> set:
    """Contexts that LOST members relative to the commitment. Returns raw bytes."""
    grans = grans or GRAN
    now = context_counts(nodes, grans)
    lost = set()
    for name in grans:
        old, new = before_counts.get(name, {}), now.get(name, {})
        for seg, ctxmap in old.items():
            cur = new.get(seg, {})
            for ctx_hex, n_before in ctxmap.items():
                if cur.get(ctx_hex, 0) < n_before:
                    lost.add(bytes.fromhex(ctx_hex))
    return lost


def commit_full(nodes, scheme="homeprov", grans=None) -> dict:
    """O(n). Correct but NOT deployable -- measured at ~1.1s per anchor at 200k
    nodes. Retained for A/B against the incremental form."""
    grans = grans or GRAN
    hashed = node_hashes(nodes, scheme)
    phi = {}
    for name, w in grans.items():
        segs = {}
        for ts, key, h in hashed:
            s = segs.setdefault(int(ts // w), {"acc": ZERO, "n": 0, "keys": []})
            s["acc"] = H(s["acc"] + h); s["n"] += 1; s["keys"].append(key)
        phi[name] = {str(k): {"acc": v["acc"].hex(), "n": v["n"]} for k, v in segs.items()}
    return phi


class Incremental:
    """Per-anchor cost O(new nodes), independent of history length.

    Once a segment's time window has passed it is CLOSED and its accumulator is
    FINAL. Measured M2: p50 0.90ms, p95 1.14ms, drift x0.85 across a 200k-node
    history. Removes the O(n) rebuild Yagiz et al. name as their own limitation L4.
    """

    def __init__(self, scheme="homeprov", grans=None):
        self.scheme = scheme
        self.grans = grans or GRAN
        self.rep: OrderedDict = OrderedDict()
        self.open = {g: {} for g in self.grans}
        self.sealed = {g: {} for g in self.grans}
        self.cursor = -1.0

    def ingest(self, nodes) -> int:
        """Caller supplies ONLY new nodes."""
        for n in nodes:
            if self.scheme == "homeprov":
                pid = n.par or b""
                ph = self.rep.get(n.par, ZERO) if n.par else ZERO
                h = H(n.content + b"|" + pid + b"|" + ph + b"|" + n.label.encode())
            elif self.scheme == "b4":
                h = H(n.content + b"|" + ZERO + b"|" + n.label.encode())
            else:
                h = H(n.content)
            if n.ctx is not None and n.ctx not in self.rep:
                self.rep[n.ctx] = h
                if len(self.rep) > REP_MAX:
                    self.rep.popitem(last=False)
            for g, w in self.grans.items():
                k = int(n.ts // w)
                s = self.open[g].setdefault(k, {"acc": ZERO, "n": 0})
                s["acc"] = H(s["acc"] + h); s["n"] += 1
            self.cursor = max(self.cursor, n.ts)
        return len(nodes)

    def seal(self, now: float) -> dict:
        """Move segments whose window has passed into the sealed (final) set."""
        newly = {}
        for g, w in self.grans.items():
            for k in [k for k in self.open[g] if (k + 1) * w <= now]:
                self.sealed[g][k] = self.open[g].pop(k)
                newly.setdefault(g, {})[str(k)] = {
                    "acc": self.sealed[g][k]["acc"].hex(), "n": self.sealed[g][k]["n"]}
        return newly

    def phi(self) -> dict:
        return {g: {str(k): {"acc": v["acc"].hex(), "n": v["n"]}
                    for k, v in self.sealed[g].items()} for g in self.grans}


# ------------------------------------------------------------ 9.5 / M2 retention
RETENTION = {"second": 3600.0, "minute": 86400.0, "hour": 86400.0 * 90}


def prune(phi: dict, now: float) -> dict:
    """Laminar retention: fine granularity recent, coarse granularity long.
    MEASURED: 667 MB -> 0.62 MB over 90 days (1080x).
    COST, stated not buried: localization granularity DEGRADES WITH AGE --
    1s blast radius under an hour, 1min under a day, 1h out to 90 days.
    M3 must therefore report OQ AS A FUNCTION OF EVENT AGE."""
    out = {}
    for g, keep in RETENTION.items():
        if g not in phi:
            continue
        w = GRAN[g]
        out[g] = {k: v for k, v in phi[g].items() if (int(k) + 1) * w >= now - keep}
    return out
