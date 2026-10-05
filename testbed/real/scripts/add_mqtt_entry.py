import json, uuid, datetime
P="/config/.storage/core.config_entries"
d=json.load(open(P))
if any(e["domain"]=="mqtt" for e in d["data"]["entries"]):
    print("mqtt entry already present"); raise SystemExit
tpl=d["data"]["entries"][0]
now=datetime.datetime.now(datetime.timezone.utc).isoformat()
d["data"]["entries"].append({
 "created_at": now, "modified_at": now,
 "data": {"broker":"broker","port":1883,"discovery":True,"discovery_prefix":"homeassistant"},
 "disabled_by": None, "discovery_keys": {}, "domain": "mqtt",
 "entry_id": uuid.uuid4().hex, "minor_version": 2, "options": {},
 "pref_disable_new_entities": False, "pref_disable_polling": False,
 "source": "user", "subentries": [], "title": "broker",
 "unique_id": None, "version": 1,
})
json.dump(d, open(P,"w"), indent=2)
print("mqtt config entry added")
