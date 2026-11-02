#!/usr/bin/env python3
"""R1 static renderer-closure probe (runs INSIDE a Home Assistant image).

Resolves the SELECTed columns of the logbook queries to ``table.column`` the
same way ``homeprov_e4.static_closure`` does, so the attribution-relevant field
set of a release can be compared with the 2026.7.4 baseline without a running
hub. Prints one JSON object to stdout; writes nothing. This is the STATIC half
of R1 item 1; the dynamic mutation half needs a live hub (r1 driver).
"""
import json

try:
    from homeassistant.components.logbook.queries import common as C
    import homeassistant.const as HC
    import importlib.metadata as _m
    frontend = None
    try:
        frontend = _m.version("home-assistant-frontend")
    except Exception:
        pass
except Exception as e:  # pragma: no cover
    print(json.dumps({"error": "import", "detail": repr(e)}))
    raise SystemExit(0)


def _resolve(el):
    out = []
    try:
        base = el.element if hasattr(el, "element") else el
    except Exception:
        base = el
    tab = getattr(getattr(base, "table", None), "name", None)
    nm = getattr(base, "name", None)
    if tab and nm:
        out.append("%s.%s" % (tab, nm))
    else:
        try:
            for sub in base.get_children():
                out.extend(_resolve(sub))
        except Exception:
            pass
    return out


groups = {}
for name in ("EVENT_COLUMNS", "STATE_COLUMNS", "EVENT_COLUMNS_FOR_STATE_SELECT",
             "STATE_CONTEXT_ONLY_COLUMNS"):
    tup = getattr(C, name, ())
    cols = []
    for el in tup:
        cols.append({"label": str(getattr(el, "name", "?")),
                     "columns": sorted(set(_resolve(el)))})
    groups[name] = cols

# Flat set of distinct columns across all four groups: the attribution-relevant
# field set the renderer can read.
flat = sorted({c for g in groups.values() for item in g for c in item["columns"]})

try:
    import homeassistant.components.recorder.const as RC
    schema_version = getattr(RC, "SCHEMA_VERSION", None)
except Exception:
    schema_version = None

print(json.dumps({
    "ha_version": getattr(HC, "__version__", None),
    "frontend_version": frontend,
    "recorder_schema_version": schema_version,
    "groups": groups,
    "flat_field_set": flat,
}, sort_keys=True))
