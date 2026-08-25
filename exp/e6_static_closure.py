"""E6 (static arm) — is the renderer's dependency closure stable across releases?

E4 measured the closure for one release by mutation, and the paper now rests on
it. Whether that closure is a property of the platform or of the patch release
cannot be settled by reading a schema, so it has to be checked per release.

Booting each release to repeat the mutation test proved impractical: the
containers need a network for zeroconf to initialise, and several components
reached transitively from ``demo`` stall during setup on an isolated network. So
this arm answers the question the other way round. For each release we resolve,
INSIDE that release's own image, the exact column tuples its logbook selects and
the exact fields its attribution branch reads, and compare the resulting sets.

This is a weaker instrument than mutation and is reported as such: it establishes
whether the SET OF FIELDS CONSUMED changes between releases, not whether each
one still changes the rendered output. The dynamic confirmation exists for one
release (E4). What this arm can do, and what matters for the paper's claim, is
detect a release where the closure would be different.
"""
import json, subprocess, sys

PROBE = r'''
import json
out = {"version": None, "error": None, "columns": {}, "attribution_fields": []}
try:
    import homeassistant.const as c
    out["version"] = c.__version__
    from homeassistant.components.logbook.queries import common as C

    def resolve(el):
        got = []
        base = el.element if hasattr(el, "element") else el
        tab = getattr(getattr(base, "table", None), "name", None)
        nm = getattr(base, "name", None)
        if tab and nm:
            got.append("%s.%s" % (tab, nm))
        else:
            try:
                for sub in base.get_children():
                    got.extend(resolve(sub))
            except Exception:
                pass
        return got

    for grp in ("EVENT_COLUMNS", "STATE_COLUMNS", "EVENT_COLUMNS_FOR_STATE_SELECT",
                "STATE_CONTEXT_ONLY_COLUMNS"):
        tup = getattr(C, grp, ())
        cols = []
        for el in tup:
            cols.extend(resolve(el))
        out["columns"][grp] = sorted(set(cols))

    # Fields the attribution branch of the processor names, read from source so
    # a renamed or added positional constant is visible.
    import inspect
    from homeassistant.components.logbook import processor as P
    src = inspect.getsource(P)
    for tok in ("CONTEXT_ID_BIN_POS", "CONTEXT_PARENT_ID_BIN_POS",
                "CONTEXT_USER_ID_BIN_POS", "ENTITY_ID_POS", "STATE_POS",
                "EVENT_TYPE_POS", "ROW_ID_POS"):
        if tok in src:
            out["attribution_fields"].append(tok)
    out["attribution_fields"].sort()
    # The state-row filter predicates, which decide render ELIGIBILITY.
    from homeassistant.components.logbook.queries import common as C2
    fsrc = inspect.getsource(C2)
    out["eligibility"] = sorted({t for t in
        ("old_state_id", "last_changed_ts", "last_updated_ts", "attributes_id",
         "metadata_id") if t in fsrc})
except Exception as e:
    out["error"] = "%s: %s" % (type(e).__name__, e)
print(json.dumps(out))
'''

VERSIONS = sys.argv[1:] or ["2024.12", "2026.6.4", "2026.7.4", "2026.8.3"]
results = {}
for v in VERSIONS:
    img = "homeassistant/home-assistant:%s" % v
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "python3", img, "-c", PROBE],
            capture_output=True, text=True, timeout=300)
        line = [l for l in p.stdout.splitlines() if l.startswith("{")]
        results[v] = json.loads(line[-1]) if line else {
            "error": (p.stderr or p.stdout)[-300:]}
    except Exception as e:                                     # noqa: BLE001
        results[v] = {"error": "%s: %s" % (type(e).__name__, e)}
    r = results[v]
    print("%-10s version=%s error=%s" % (v, r.get("version"), (r.get("error") or "")[:70]))

# Compare the union of selected columns across releases.
def union(r):
    if r.get("error"):
        return None
    s = set()
    for cols in r.get("columns", {}).values():
        s |= set(cols)
    return s

sets = {v: union(r) for v, r in results.items()}
ok = {v: s for v, s in sets.items() if s}
ref = "2026.7.4" if sets.get("2026.7.4") else (list(ok) or [None])[0]
diffs = {}
if ref:
    for v, s in ok.items():
        if v == ref:
            continue
        diffs[v] = {"added_vs_ref": sorted(s - ok[ref]),
                    "removed_vs_ref": sorted(ok[ref] - s)}

out = {"reference": ref,
       "per_version": {v: {"version": r.get("version"), "error": r.get("error"),
                           "n_columns": len(sets[v]) if sets[v] else None,
                           "columns": sorted(sets[v]) if sets[v] else None,
                           "attribution_fields": r.get("attribution_fields"),
                           "eligibility": r.get("eligibility")}
                       for v, r in results.items()},
       "diff_vs_reference": diffs,
       "closure_stable": all(not d["added_vs_ref"] and not d["removed_vs_ref"]
                             for d in diffs.values()) if diffs else None,
       "instrument": "static resolution of the logbook query column tuples and "
                     "processor attribution fields inside each release's own "
                     "image; weaker than mutation, and detects a changed field "
                     "SET rather than a changed rendered output"}
json.dump(out, open("exp/out/e6_static.json", "w"), indent=2)
print("\nreference:", ref, "| stable across releases:", out["closure_stable"])
for v, d in diffs.items():
    print("  %-10s added=%s removed=%s" % (v, d["added_vs_ref"], d["removed_vs_ref"]))
