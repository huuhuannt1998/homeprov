#!/usr/bin/env python3
"""R1 browser-render prerequisite: onboard a fresh HA hub with an ADMIN owner
and a NON-ADMIN household viewer, and obtain an access token for each.

Admin's name map includes the auth user list (admin-only); non-admin's does not
-- this is the viewer distinction the member-account-swap claim turns on. Tokens
and ids are written to a scratchpad file (credentials never go to exp/out).

usage: r1_onboard.py <base_url> <auth_out_json>
"""
import json
import sys
import time

import requests
import websocket  # websocket-client

BASE = sys.argv[1].rstrip("/")
OUT = sys.argv[2]
CLIENT = BASE + "/"
ADMIN_USER, ADMIN_PW = "admin", "adminpass12345"
VIEWER_USER, VIEWER_PW = "viewer", "viewerpass12345"


def token_from_code(code):
    r = requests.post(BASE + "/auth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": CLIENT},
        timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


def login_flow_token(username, password):
    r = requests.post(BASE + "/auth/login_flow", json={
        "client_id": CLIENT, "handler": ["homeassistant", None],
        "redirect_uri": CLIENT}, timeout=20)
    r.raise_for_status()
    flow = r.json()["flow_id"]
    r = requests.post(BASE + "/auth/login_flow/" + flow, json={
        "client_id": CLIENT, "username": username, "password": password},
        timeout=20)
    r.raise_for_status()
    code = r.json()["result"]
    return token_from_code(code)


# 1. Onboard the owner (admin).
st = requests.get(BASE + "/api/onboarding", timeout=20).json()
done = {s["step"]: s["done"] for s in st}
if not done.get("user"):
    r = requests.post(BASE + "/api/onboarding/users", json={
        "client_id": CLIENT, "name": "Home Owner", "username": ADMIN_USER,
        "password": ADMIN_PW, "language": "en"}, timeout=30)
    r.raise_for_status()
    admin_code = r.json()["auth_code"]
    admin_token = token_from_code(admin_code)
else:
    admin_token = login_flow_token(ADMIN_USER, ADMIN_PW)

H = {"Authorization": "Bearer " + admin_token}
# Clear the remaining onboarding steps so the SPA loads the app, not the wizard.
for step, body in (("core_config", {}), ("analytics", {}), ("integration",
                   {"client_id": CLIENT, "redirect_uri": CLIENT})):
    try:
        requests.post(BASE + "/api/onboarding/" + step, headers=H, json=body,
                      timeout=20)
    except Exception:
        pass

# 2. Create a NON-ADMIN user + homeassistant credential over the websocket.
ws = websocket.create_connection(BASE.replace("http", "ws") + "/api/websocket",
                                 timeout=20)
assert json.loads(ws.recv())["type"] == "auth_required"
ws.send(json.dumps({"type": "auth", "access_token": admin_token}))
assert json.loads(ws.recv())["type"] == "auth_ok"


def ws_cmd(mid, payload):
    ws.send(json.dumps({"id": mid, **payload}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == mid and m.get("type") == "result":
            if not m.get("success"):
                raise RuntimeError(json.dumps(m.get("error")))
            return m.get("result")


# Is there already a non-admin viewer? (idempotent re-run)
users = ws_cmd(10, {"type": "config/auth/list"})
viewer = next((u for u in users if u.get("name") == "Household Viewer"), None)
if viewer is None:
    res = ws_cmd(11, {"type": "config/auth/create",
                      "name": "Household Viewer", "group_ids": ["system-users"]})
    viewer = res["user"]
    ws_cmd(12, {"type": "config/auth_provider/homeassistant/create",
                "user_id": viewer["id"], "username": VIEWER_USER,
                "password": VIEWER_PW})
viewer_id = viewer["id"]
admin_me = ws_cmd(13, {"type": "auth/current_user"})
ws.close()
time.sleep(1)
viewer_token = login_flow_token(VIEWER_USER, VIEWER_PW)

auth = {"base": BASE,
        "admin": {"username": ADMIN_USER, "token": admin_token,
                  "user_id": admin_me.get("id"), "is_admin": admin_me.get("is_admin")},
        "viewer": {"username": VIEWER_USER, "token": viewer_token,
                   "user_id": viewer_id, "is_admin": False}}
json.dump(auth, open(OUT, "w"), indent=1)
print(json.dumps({"admin_is_admin": admin_me.get("is_admin"),
                  "admin_id": admin_me.get("id"), "viewer_id": viewer_id,
                  "wrote": OUT}))
