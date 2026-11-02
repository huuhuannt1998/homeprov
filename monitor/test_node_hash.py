"""Node-hash encoding tests (review sp2027-r1, finding T7).

    python3 -m pytest -q monitor/test_node_hash.py

1. Regression: the triage's collision case, and the other v1 aliasing classes (NULL vs empty BLOB, a context/parent
   splice, last_changed_ts rounding), hash equal under 'v1' (the defect, kept for re-checking old chains) and differ
   under 'v2'.
2. Property: two distinct field tuples never give the same v2 encoding. Shown constructively: a decoder recovers every
   tuple from its encoding (so the encoding is injective), over random adversarial tuples and over an exhaustive small
   domain; the v2 node hashes of the exhaustive domain are pairwise distinct. If `hypothesis` is installed, the same
   property also runs under it.
3. Compatibility: 'v1' is byte-identical to the monitor before the fix (golden vectors computed from git HEAD b761199).
"""
from __future__ import annotations

import itertools
import os
import random
import struct
import sys

os.environ.setdefault("HOMEPROV_SCRATCH", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_scratch"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monitor as M  # noqa: E402

KEY = "s:702103"
CONTENT = b'{"e":"lock.front_door","s":"unlocked","t":"state","ts":1790987128.343684}'
CTX = bytes.fromhex("01a0ff26ce171afd0f6138a0d1cb87f1")
PAR = bytes.fromhex("01a112f04c7c11223344556677889900")      # 0x7C at byte 5 (the triage's parent id)
PAR_SPLIT = bytes.fromhex("01a112f04c")
USR_SPLIT = bytes.fromhex("112233445566778899007c")


# ------------------------------------------------------------------ decoder (proves injectivity constructively)
def _decode_value(buf: bytes, i: int):
    tag = buf[i:i + 1]
    i += 1
    if tag == b"N":
        return None, i
    if tag == b"F":
        return struct.unpack(">d", buf[i:i + 8])[0], i + 8
    (n,) = struct.unpack(">Q", buf[i:i + 8])
    i += 8
    raw = buf[i:i + n]
    if len(raw) != n:
        raise ValueError("truncated")
    i += n
    if tag == b"B":
        return raw, i
    if tag == b"T":
        return raw.decode("utf-8", "surrogatepass"), i
    if tag == b"I":
        return int(raw.decode("ascii")), i
    raise ValueError("bad tag %r" % tag)


def decode_node_v2(buf: bytes):
    assert buf.startswith(M.NODE_V2_TAG)
    i = len(M.NODE_V2_TAG)
    scheme, i = _decode_value(buf, i)
    (n,) = struct.unpack(">Q", buf[i:i + 8])
    i += 8
    out = []
    for _ in range(n):
        v, i = _decode_value(buf, i)
        out.append(v)
    if i != len(buf):
        raise ValueError("trailing bytes")
    return scheme, tuple(out)


def typed(v):
    """Identity of a recorder value as the encoding sees it: type plus value (floats by bit pattern)."""
    if v is None:
        return ("N",)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return ("B", bytes(v))
    if isinstance(v, str):
        return ("T", v)
    if isinstance(v, int):
        return ("I", v)
    if isinstance(v, float):
        return ("F", struct.pack(">d", v))
    raise TypeError(type(v))


def typed_tuple(t):
    return tuple(typed(v) for v in t)


# ------------------------------------------------------------------ 1. regression
def test_triage_collision_case_v1_equal_v2_distinct():
    """sp2027-r1 T7: parent 01a112f04c7c11.. rewritten to 01a112f04c, 11..7c written into the NULL user column."""
    a = (KEY, CONTENT, CTX, PAR, "actuates", None, 702100, 1790987128.343684)
    b = (KEY, CONTENT, CTX, PAR_SPLIT, "actuates", USR_SPLIT, 702100, 1790987128.343684)
    assert M.node_hash_closure(*a, encoding="v1") == M.node_hash_closure(*b, encoding="v1")   # the defect
    assert M.node_hash_closure(*a, encoding="v2") != M.node_hash_closure(*b, encoding="v2")   # the fix


def test_triage_collision_case_full_commit():
    """The same splice leaves every v1 segment root unchanged and changes the v2 one."""
    n1 = [(1790987128.343684, KEY, CONTENT, CTX, PAR, "actuates", None, 702100, 1790987128.343684)]
    n2 = [(1790987128.343684, KEY, CONTENT, CTX, PAR_SPLIT, "actuates", USR_SPLIT, 702100, 1790987128.343684)]
    assert M.commit(n1, encoding="v1") == M.commit(n2, encoding="v1")
    p1, p2 = M.commit(n1, encoding="v2"), M.commit(n2, encoding="v2")
    for g, _w in M.GRAN:
        assert p1[g] != p2[g]


def test_row_scheme_context_parent_splice():
    """Row scheme: a context id containing 0x7C split across the context/parent separator."""
    ctx = bytes.fromhex("01a0fe7c1f518acaf65f2282f5719093")
    a = (KEY, CONTENT, ctx, None, "actuates")
    b = (KEY, CONTENT, ctx[:3], ctx[4:] + b"|", "actuates")
    assert M.node_hash(*a, encoding="v1") == M.node_hash(*b, encoding="v1")
    assert M.node_hash(*a, encoding="v2") != M.node_hash(*b, encoding="v2")


def test_null_versus_empty_blob():
    a = (KEY, CONTENT, CTX, None, "actuates", None, None, None)
    b = (KEY, CONTENT, CTX, b"", "actuates", b"", None, None)
    assert M.node_hash_closure(*a, encoding="v1") == M.node_hash_closure(*b, encoding="v1")
    assert M.node_hash_closure(*a, encoding="v2") != M.node_hash_closure(*b, encoding="v2")


def test_last_changed_rounding_and_integer_text_confusion():
    a = (KEY, CONTENT, CTX, None, "actuates", None, 5, 1790987128.3436841)
    b = (KEY, CONTENT, CTX, None, "actuates", None, "5", 1790987128.3436842)
    assert M.node_hash_closure(*a, encoding="v1") == M.node_hash_closure(*b, encoding="v1")
    assert M.node_hash_closure(*a, encoding="v2") != M.node_hash_closure(*b, encoding="v2")


def test_schemes_are_domain_separated():
    """A row-scheme node and a closure-scheme node never share an encoding."""
    r = M.encode_node_v2("row", (KEY, CONTENT, CTX, None, "actuates"))
    c = M.encode_node_v2("closure", (KEY, CONTENT, CTX, None, "actuates", None, None, None))
    assert r != c and decode_node_v2(r)[0] == "row" and decode_node_v2(c)[0] == "closure"


# ------------------------------------------------------------------ 2. property: distinct tuples never encode equal
PIPE_HEAVY = [0x7C, 0x7C, 0x7C, 0x00, 0x01, ord("B"), ord("T"), ord("N"), ord("I"), ord("F"), 0xFF]


def _rand_bytes(rng):
    return bytes(rng.choice(PIPE_HEAVY) for _ in range(rng.choice([0, 0, 1, 2, 3, 5, 8, 15, 16, 17])))


def _rand_value(rng):
    k = rng.random()
    if k < 0.25:
        return None
    if k < 0.65:
        return _rand_bytes(rng)
    if k < 0.75:
        return _rand_bytes(rng).decode("latin-1")
    if k < 0.87:
        return rng.choice([0, 1, 5, -1, 702100, 2 ** 63 - 1, -(2 ** 63)])
    return rng.choice([0.0, -0.0, 1.0, 1790987128.343684, 1790987128.3436841, 1e-300, float("inf")])


def _splice_neighbours(t):
    """Every tuple whose v1 bytes equal t's because a 0x7C byte or an empty field moved across a separator."""
    blobs = [2, 3, 5]              # ctx, par, usr in node_hash_closure's argument order; v1 joins them adjacently
    region = b"|".join(t[i] or b"" for i in blobs)
    pipes = [i for i, ch in enumerate(region) if ch == 0x7C]
    for cut in itertools.combinations(pipes, len(blobs) - 1):
        parts, last = [], 0
        for c in cut:
            parts.append(region[last:c])
            last = c + 1
        parts.append(region[last:])
        for nulls in itertools.product([False, True], repeat=len(parts)):
            u = list(t)
            for j, i in enumerate(blobs):
                u[i] = None if (nulls[j] and parts[j] == b"") else parts[j]
            yield tuple(u)


def test_property_random_round_trip_and_distinctness():
    rng = random.Random(20261006)
    seen = {}
    for _ in range(20000):
        arity = rng.choice([5, 8])
        t = tuple(_rand_value(rng) for _ in range(arity))
        scheme = "closure" if arity == 8 else "row"
        enc = M.encode_node_v2(scheme, t)
        s2, back = decode_node_v2(enc)
        assert s2 == scheme and typed_tuple(back) == typed_tuple(t)
        prev = seen.setdefault(enc, (scheme, typed_tuple(t)))
        assert prev == (scheme, typed_tuple(t)), "two distinct tuples share a v2 encoding"


def test_property_splice_neighbours_always_distinct_under_v2():
    """For tuples built from pipe-heavy BLOBs, every v1-invisible rewrite changes the v2 hash."""
    rng = random.Random(7)
    checked = v1_collisions = 0
    for _ in range(3000):
        t = (KEY, CONTENT, _rand_bytes(rng) or None, _rand_bytes(rng) or None, "actuates",
             _rand_bytes(rng) or None, 702100, 1790987128.343684)
        h1 = M.node_hash_closure(*t, encoding="v1")
        h2 = M.node_hash_closure(*t, encoding="v2")
        for u in _splice_neighbours(t):
            if typed_tuple(u) == typed_tuple(t):
                continue
            checked += 1
            v1_equal = M.node_hash_closure(*u, encoding="v1") == h1
            v1_collisions += v1_equal
            assert M.node_hash_closure(*u, encoding="v2") != h2
    assert checked > 1000 and v1_collisions == checked   # every neighbour is a v1 collision; none survives v2


def test_property_exhaustive_small_domain():
    """ctx, par, usr each range over NULL and every BLOB of length 0..3 over {0x7C, 0x01}: 16 values, 4,096 tuples."""
    blobs = [None] + [bytes(p) for n in range(4) for p in itertools.product([0x7C, 0x01], repeat=n)]
    v1, v2 = {}, set()
    for ctx, par, usr in itertools.product(blobs, repeat=3):
        t = (KEY, CONTENT, ctx, par, "actuates", usr, 1, 2.5)
        v2.add(M.node_hash_closure(*t, encoding="v2"))
        v1.setdefault(M.node_hash_closure(*t, encoding="v1"), []).append(t)
    assert len(v2) == len(blobs) ** 3 == 4096
    assert len(v1) < 4096          # v1 is not injective on the same domain


def test_property_hypothesis_if_available():
    try:
        from hypothesis import given, settings, strategies as st
    except ImportError:            # optional; the seeded and exhaustive tests above carry the property
        return
    val = st.one_of(st.none(), st.binary(max_size=24), st.text(max_size=8),
                    st.integers(min_value=-(2 ** 63), max_value=2 ** 63 - 1),
                    st.floats(allow_nan=False))
    tup = st.lists(val, min_size=1, max_size=9).map(tuple)

    @settings(max_examples=3000, deadline=None)
    @given(tup, tup)
    def prop(a, b):
        if typed_tuple(a) != typed_tuple(b):
            assert M.encode_node_v2("closure", a) != M.encode_node_v2("closure", b)
        assert typed_tuple(decode_node_v2(M.encode_node_v2("closure", a))[1]) == typed_tuple(a)

    prop()


# ------------------------------------------------------------------ 3. v1 compatibility with the shipped monitor
def test_v1_golden_vectors_match_monitor_before_fix():
    """Computed with monitor/monitor.py at git HEAD b761199, so v1 chains still verify."""
    args = (KEY, CONTENT, CTX, PAR, "actuates")
    assert M.node_hash(*args, encoding="v1").hex() == \
        "e0ff67b0f56db325134c9e8b34b2b7ae29aac307723d442f46780b7103c34a66"
    assert M.node_hash_closure(*args, None, 702100, 1790987128.343684, encoding="v1").hex() == \
        "5028e12e3127991674680512b0ab0384662cd7aa1dfb6b9d82d462c889ef1175"
    nodes = [(1790987128.343684,) + args + (None, 702100, 1790987128.343684),
             (1790987128.5, "e:5", b'{"d":null}', CTX, None, "causes", None, None, None)]
    assert M.commit(nodes, encoding="v1")["second"] == {
        "1790987128": {"acc": "daaf47fec8af4b3c5808b4a6e4a8b8cdb1a6935e170f7f45190c3938139edb94", "n": 2}}


def test_default_encoding_is_v2():
    assert M.ENCODING == os.environ.get("HOMEPROV_ENCODING", "v2")
