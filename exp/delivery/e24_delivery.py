"""E24 (part 2) -- the community install path, executed end to end.

Part 1 measured that HACS applies no security control before an integration is
installable. This part runs the path itself, so the paper shows the delivery
rather than describing it.

WHAT THIS DOES AND DOES NOT DO, because the distinction decides what may be
claimed. It reproduces the install MECHANISM exactly as read from HACS's own
source (repositories/base.py download_repository_zip): fetch a repository
archive over HTTP, write it to a temp file, and zipfile.extractall() the
integration directory into the Home Assistant configuration directory. It then
restarts the hub and checks whether the extracted Python is executing in the hub
process with recorder access.

It does NOT drive the HACS UI. HACS resolves repositories through the GitHub
API, which needs a token and network egress the testbed deliberately does not
have, and obtaining either would violate the project's standing constraints. So
the claim this supports is precise: the install mechanism, replicated faithfully
from the source, grants in-process execution with nothing in the way. It is not
a claim that we drove the real client's UI end to end.

The origin is a LOCAL HTTP server on the loopback interface. Nothing is
published anywhere, which keeps the paper's release policy true.
"""
from __future__ import annotations

import http.server, io, json, os, shutil, socketserver, subprocess, tempfile
import threading, time, zipfile, pathlib

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent / "out" / "e24_delivery.json"
CONTAINER = "hpr-hass"
DOMAIN = "community_weather_pro"     # the plausible-looking integration name

# A benign PROBE, not the adversary. It writes one marker row through the
# recorder's own database handle to demonstrate that extracted code executes
# in-process with evidence-store access, and does nothing else. The paper's
# offensive component is not what is being delivered here, and does not need to
# be: the point is that ARBITRARY code reaches this position.
PROBE = '''"""Community Weather Pro -- local weather for your dashboard."""
import json, os, sqlite3, time

DOMAIN = "community_weather_pro"
MARKER = "/config/homeprov_out/e24_delivery_probe.json"


async def async_setup(hass, config):
    """Runs in the Home Assistant process, with everything the process has."""
    os.makedirs("/config/homeprov_out", exist_ok=True)
    proof = {"executed_in_hub_process": True, "pid": os.getpid(), "ts": time.time()}
    # Demonstrate evidence-store reach the same way any in-process component can.
    try:
        con = sqlite3.connect("/config/home-assistant_v2.db", timeout=30)
        proof["recorder_rows_readable"] = con.execute(
            "SELECT COUNT(*) FROM states").fetchone()[0]
        proof["recorder_writable"] = True
        try:
            con.execute("UPDATE states SET state=state WHERE 0=1")
            con.commit()
        except Exception as exc:
            proof["recorder_writable"] = f"no: {exc}"
        con.close()
    except Exception as exc:
        proof["recorder_error"] = repr(exc)
    proof["can_read_config"] = os.path.exists("/config/configuration.yaml")
    with open(MARKER, "w") as fh:
        json.dump(proof, fh, indent=2)
    return True
'''

MANIFEST = json.dumps({
    "domain": DOMAIN, "name": "Community Weather Pro", "version": "2.4.1",
    "documentation": "https://example.invalid/community-weather-pro",
    "issue_tracker": "https://example.invalid/community-weather-pro/issues",
    "codeowners": ["@example"], "dependencies": [], "requirements": [],
    "iot_class": "cloud_polling",
}, indent=2)

# hacs.json is the only HACS-specific file an integration must carry. Its
# contents are metadata; nothing in it constrains behaviour.
HACS_JSON = json.dumps({"name": "Community Weather Pro",
                        "render_readme": True,
                        "homeassistant": "2024.1.0"}, indent=2)


def build_release_zip() -> bytes:
    """A GitHub-shaped source archive: a single top-level directory, the
    integration under custom_components/, exactly what the real endpoint
    returns."""
    buf = io.BytesIO()
    root = f"{DOMAIN}-2.4.1"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{root}/README.md", "# Community Weather Pro\n\nLocal weather.\n")
        z.writestr(f"{root}/hacs.json", HACS_JSON)
        z.writestr(f"{root}/custom_components/{DOMAIN}/manifest.json", MANIFEST)
        z.writestr(f"{root}/custom_components/{DOMAIN}/__init__.py", PROBE)
    return buf.getvalue()


class Origin(threading.Thread):
    """Local HTTP origin standing in for the archive endpoint."""

    def __init__(self, payload: bytes):
        super().__init__(daemon=True)
        self.payload = payload
        self.port = None
        self._srv = None

    def run(self):
        payload = self.payload

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        self._srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]
        self._srv.serve_forever()

    def stop(self):
        if self._srv:
            self._srv.shutdown()


def sh(*args) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


def main() -> None:
    steps, t0 = [], time.time()

    def step(name, detail, **kw):
        steps.append({"n": len(steps) + 1, "step": name, "detail": detail,
                      "t_s": round(time.time() - t0, 2), **kw})
        print(f"  {len(steps)}. {name}: {detail}")

    zip_bytes = build_release_zip()
    origin = Origin(zip_bytes)
    origin.start()
    while origin.port is None:
        time.sleep(0.05)
    step("origin up", f"local archive endpoint on 127.0.0.1:{origin.port}, "
                      f"{len(zip_bytes)} byte archive")

    # ---- exactly the steps HACS performs, in its order -------------------
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{origin.port}/archive.zip") as r:
        fetched = r.read()
    step("fetch archive", f"{len(fetched)} bytes over HTTP",
         verified_signature=False, verified_hash=False,
         note="HACS performs no signature or hash check at this point; "
              "measured in part 1 as five-for-five absent")

    tmp = tempfile.mkdtemp()
    zpath = os.path.join(tmp, "release.zip")
    open(zpath, "wb").write(fetched)

    extract_to = os.path.join(tmp, "extracted")
    with zipfile.ZipFile(zpath) as z:
        members = []
        for info in z.filelist:
            rel = "/".join(info.filename.split("/")[1:])
            if rel.startswith(f"custom_components/{DOMAIN}/") and not rel.endswith("/"):
                info.filename = rel[len(f"custom_components/{DOMAIN}/"):]
                members.append(info)
        os.makedirs(extract_to, exist_ok=True)
        z.extractall(extract_to, members)
    step("extractall", f"{len(members)} files into the integration directory",
         files=[m.filename for m in members])

    # ---- place it where the hub loads from ------------------------------
    sh("docker", "exec", CONTAINER, "mkdir", "-p", f"/config/custom_components/{DOMAIN}")
    for f in os.listdir(extract_to):
        sh("docker", "cp", os.path.join(extract_to, f),
           f"{CONTAINER}:/config/custom_components/{DOMAIN}/{f}")
    step("install", f"/config/custom_components/{DOMAIN}/ populated",
         note="this is the point at which HACS's work is finished")

    # HACS-installed integrations are enabled by config entry or a YAML line;
    # the platform then loads them on the next start.
    cur = sh("docker", "exec", CONTAINER, "cat", "/config/configuration.yaml").stdout
    if f"\n{DOMAIN}:" not in cur:
        newcfg = cur.rstrip() + f"\n\n{DOMAIN}:\n"
        p = os.path.join(tmp, "configuration.yaml")
        open(p, "w").write(newcfg)
        sh("docker", "cp", p, f"{CONTAINER}:/config/configuration.yaml")
    step("enable", "one line added to configuration.yaml")

    sh("docker", "exec", CONTAINER, "rm", "-f",
       "/config/homeprov_out/e24_delivery_probe.json")
    sh("docker", "restart", CONTAINER)
    step("restart", "hub restarting")

    proof, deadline = None, time.time() + 300
    while time.time() < deadline:
        r = sh("docker", "exec", CONTAINER, "cat",
               "/config/homeprov_out/e24_delivery_probe.json")
        if r.returncode == 0 and r.stdout.strip():
            try:
                proof = json.loads(r.stdout)
                break
            except json.JSONDecodeError:
                pass
        time.sleep(5)

    if proof:
        step("EXECUTING IN HUB PROCESS", f"pid {proof.get('pid')}, "
             f"recorder rows readable {proof.get('recorder_rows_readable')}, "
             f"recorder writable {proof.get('recorder_writable')}", proof=proof)
    else:
        step("no execution observed", "probe marker never appeared")
    origin.stop()

    report = {
        "experiment": "E24 part 2 -- community install path executed end to end",
        "mechanism_source": "HACS repositories/base.py download_repository_zip, "
                            "read at commit c462d30",
        "what_this_shows": "the install mechanism, replicated faithfully from the "
                           "source, carries arbitrary Python into the hub process "
                           "with no control in the way",
        "what_this_does_not_show": "it does not drive the HACS client UI. HACS "
                                   "resolves repositories through the GitHub API, "
                                   "which needs a token and egress the testbed "
                                   "deliberately lacks.",
        "origin": "local HTTP on loopback; nothing published anywhere",
        "payload": "a benign probe that writes one marker file and reads a row "
                   "count; the paper's offensive component is not delivered here "
                   "and does not need to be",
        "steps": steps,
        "elapsed_s": round(time.time() - t0, 1),
        "in_process_execution_achieved": bool(proof),
        "probe": proof,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    json.dump(report, open(OUT, "w"), indent=2)
    print(f"\nin-process execution achieved: {bool(proof)}  "
          f"({report['elapsed_s']}s, {len(steps)} steps)")


if __name__ == "__main__":
    main()
