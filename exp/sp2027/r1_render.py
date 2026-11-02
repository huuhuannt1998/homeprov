#!/usr/bin/env python3
"""R1 real-browser renderer (Playwright + Chromium).

Logs into a live HA hub as a given viewer by injecting a fresh token set into
localStorage (hassTokens), navigates the Activity (logbook) view, and extracts
the displayed cause for the target entity as TEXT FROM THE DOM (piercing shadow
roots) plus a full-page screenshot. Also opens the per-entry details / context
chain (the 2026.9 Activity Details dialog, frontend PR #53362) when asked.

This module is imported by the measurement drivers; run directly it performs a
reconnaissance capture and prints what it found.

usage (recon):  r1_render.py <auth_json> recon <entity_id>
"""
import json
import re
import sys
import time

import requests
from playwright.sync_api import sync_playwright

# JS: collect visible text across all shadow roots, and collect logbook rows.
_JS_ALLTEXT = r"""
() => {
  const out = [];
  const walk = (root) => {
    const tw = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    let n = root;
    const nodes = [];
    const rec = (el) => {
      nodes.push(el);
      if (el.shadowRoot) rec2(el.shadowRoot);
      for (const c of el.children) rec(c);
    };
    const rec2 = (sr) => { for (const c of sr.children) rec(c); };
    rec(root.documentElement || root);
    return nodes;
  };
  const nodes = walk(document);
  const texts = [];
  for (const el of nodes) {
    if (el.children.length === 0 && el.shadowRoot === null) {
      const t = (el.textContent || '').trim();
      if (t) texts.push(t);
    }
  }
  return texts;
}
"""


def full_token(base, username, password):
    client = base.rstrip("/") + "/"
    r = requests.post(base + "/auth/login_flow", json={
        "client_id": client, "handler": ["homeassistant", None],
        "redirect_uri": client}, timeout=20)
    r.raise_for_status()
    flow = r.json()["flow_id"]
    r = requests.post(base + "/auth/login_flow/" + flow, json={
        "client_id": client, "username": username, "password": password},
        timeout=20)
    r.raise_for_status()
    code = r.json()["result"]
    r = requests.post(base + "/auth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client},
        timeout=20)
    r.raise_for_status()
    return r.json(), client


def _hass_tokens(tok, base, client):
    return {"access_token": tok["access_token"], "token_type": "Bearer",
            "expires_in": tok.get("expires_in", 1800), "hassUrl": base,
            "clientId": client, "expires": int(time.time() * 1000) + 1000 * tok.get("expires_in", 1800),
            "refresh_token": tok.get("refresh_token", "")}


def alltext(page):
    try:
        return page.evaluate(_JS_ALLTEXT)
    except Exception:
        return []


def login_context(pw, base, username, password, headless=True):
    tok, client = full_token(base, username, password)
    ht = _hass_tokens(tok, base, client)
    browser = pw.chromium.launch(headless=headless)
    ctx = browser.new_context(viewport={"width": 1280, "height": 1600})
    ctx.add_init_script("window.localStorage.setItem('hassTokens', %s);"
                        "window.localStorage.setItem('selectedTheme','{\"dark\":false}');"
                        % json.dumps(json.dumps(ht)))
    return browser, ctx


_JS_ENTRIES = r"""
() => {
  const nodes=[]; const rec=(n)=>{if(!n)return; nodes.push(n);
    if(n.shadowRoot) for(const c of n.shadowRoot.children) rec(c);
    for(const c of (n.children||[])) rec(c);};
  rec(document.documentElement);
  const out=[];
  for(const n of nodes){
    const cls=(typeof n.className==='string')?n.className:'';
    if(/(^|\s)entry(\s|$)/.test(cls) && /node-icon/.test(cls)){
      let time='', title='', cause='';
      const tw=n.querySelector ? n : null;
      // walk this entry's subtree (incl shadow) for the pieces
      const sub=[]; const rec2=(m)=>{if(!m)return; sub.push(m);
        if(m.shadowRoot) for(const c of m.shadowRoot.children) rec2(c);
        for(const c of (m.children||[])) rec2(c);};
      rec2(n);
      for(const m of sub){
        const c2=(typeof m.className==='string')?m.className:'';
        const t=(m.textContent||'').trim().replace(/\s+/g,' ');
        if(/cause-line/.test(c2)) cause=t;
        if(/(^|\s)content(\s|$)/.test(c2) && !title) title=t;
      }
      const full=(n.textContent||'').trim().replace(/\s+/g,' ');
      const mt=full.match(/^(\d{1,2}:\d{2}:\d{2}\s*[AP]M)/);
      time=mt?mt[1]:'';
      // title without the trailing cause
      let name=title; if(cause && name.endsWith(cause)) name=name.slice(0,-cause.length).trim();
      out.push({time:time, name:name, cause:cause});
    }
  }
  return out;
}
"""


def extract_entries(page):
    try:
        return page.evaluate(_JS_ENTRIES)
    except Exception:
        return []


def render_activity(ctx, base, screenshot_path, settle_ms=4000, wait_s=18):
    """Load the Activity (logbook) view, wait for entries, return structured
    entries [{time,name,cause}] and write a full-page screenshot."""
    page = ctx.new_page()
    page.goto(base + "/logbook", wait_until="load", timeout=45000)
    entries = []
    for _ in range(int(wait_s / 1.5)):
        page.wait_for_timeout(1500)
        entries = extract_entries(page)
        if entries:
            break
    page.wait_for_timeout(settle_ms)
    entries = extract_entries(page)
    page.screenshot(path=screenshot_path, full_page=True)
    page.close()
    return entries


def capture_logbook(ctx, base, entity_id, screenshot_path, settle_ms=4500):
    page = ctx.new_page()
    url = base + "/logbook"
    page.goto(url, wait_until="networkidle", timeout=45000)
    page.wait_for_timeout(settle_ms)
    texts = alltext(page)
    page.screenshot(path=screenshot_path, full_page=True)
    # Lines mentioning the target entity's friendly bits.
    key = entity_id.split(".")[-1].replace("_", " ")
    hits = [t for t in texts if key.lower() in t.lower() or entity_id in t]
    page.close()
    return {"url": url, "n_text_nodes": len(texts), "entity_key": key,
            "hits": hits[:40], "all_text_sample": texts[:120]}


if __name__ == "__main__":
    auth = json.load(open(sys.argv[1]))
    mode = sys.argv[2] if len(sys.argv) > 2 else "recon"
    ent = sys.argv[3] if len(sys.argv) > 3 else "lock.front_door"
    base = auth["base"]
    with sync_playwright() as pw:
        br, ctx = login_context(pw, base, auth["admin"]["username"], "adminpass12345")
        res = capture_logbook(ctx, base, ent, "/tmp/r1_recon_admin.png")
        br.close()
    print(json.dumps({"hits": res["hits"],
                      "n_text_nodes": res["n_text_nodes"],
                      "sample": res["all_text_sample"][:60]}, indent=1)[:3000])
