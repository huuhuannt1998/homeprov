"""Minimal Domoticz JSON API client for the E-DZ harness (stdlib only).

The base URL is the host-side tunnel (tunnel.py), so every request reaches the hub from the harness container's
address on dz-net, authenticated with HTTP Basic credentials of one Domoticz account."""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("DZ_BASE", "http://127.0.0.1:18480")

# Accounts of the testbed household. Passwords are throwaway test credentials of an isolated testbed.
ACCOUNTS = {
    "owner": {"password": "dz-owner-pw", "rights": 2, "role": "admin"},
    "member": {"password": "dz-member-pw", "rights": 1, "role": "user"},
    "guest": {"password": "dz-guest-pw", "rights": 0, "role": "viewer"},
}


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


class Api:
    """One logged-in Domoticz web session of one account (logincheck, then the DMZSID session cookie), as the web UI
    does. Domoticz 2026.3 does not accept HTTP Basic credentials on json.htm from a non-trusted address."""

    def __init__(self, account, base=BASE):
        import http.cookiejar
        self.account = account
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.login_reply = self.login()

    def login(self):
        pw = ACCOUNTS[self.account]["password"]
        # The web UI posts multipart form data: username = base64(name), password = md5(password).
        fields = {"username": base64.b64encode(self.account.encode()).decode(), "password": md5(pw),
                  "rememberme": "false"}
        bnd = "----dzharness%d" % int(time.time() * 1000)
        body = b"".join(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (bnd, k, v)).encode()
                        for k, v in fields.items()) + ("--%s--\r\n" % bnd).encode()
        req = urllib.request.Request(self.base + "/json.htm?type=command&param=logincheck", data=body, method="POST",
                                     headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
        with self.opener.open(req, timeout=20) as r:
            d = json.loads(r.read())
        if d.get("status") != "OK":
            raise RuntimeError("login failed for %s: %r" % (self.account, d))
        return d

    def cmd(self, param, timeout=20, **kw):
        q = {"type": "command", "param": param}
        q.update({k: v for k, v in kw.items() if v is not None})
        return self.get("/json.htm?" + urllib.parse.urlencode(q), timeout=timeout)

    def get(self, path, timeout=20, retries=5):
        last = None
        for i in range(retries):
            req = urllib.request.Request(self.base + path)
            try:
                with self.opener.open(req, timeout=timeout) as r:
                    body = r.read()
                    try:
                        return json.loads(body)
                    except ValueError:
                        return {"_raw": body[:500].decode(errors="replace"), "_status": r.status}
            except urllib.error.HTTPError as e:
                if e.code == 401 and i + 1 < retries:
                    self.login()
                    continue
                return {"_http": e.code, "_body": e.read()[:300].decode(errors="replace")}
            except (urllib.error.URLError, ConnectionError, OSError) as e:
                last = e
                time.sleep(0.5 * (i + 1))
        return {"_err": repr(last)[:200]}

    def lightlog(self, idx):
        """The platform's renderer for the device Log page's Text log table (Date, Data, User)."""
        d = self.cmd("getlightlog", idx=idx)
        return d


def lightlog_by_row(api, idx):
    d = api.lightlog(idx)
    return {e["idx"]: {k: e.get(k) for k in ("Date", "Data", "Status", "Level", "User")}
            for e in (d.get("result") or [])}, d
