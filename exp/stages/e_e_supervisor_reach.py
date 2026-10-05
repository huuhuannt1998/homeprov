"""E-E -- HA OS / Supervisor reach: does the isolation claim survive the dominant
install method?

THE OBJECTION (review 4c). The paper's isolation argument is that the monitor
"runs in its own container, on a network the hub is not attached to, and mounts
the hub's configuration directory read-only", and that the anchor lives on a
volume the hub never mounts inside a container the hub cannot enter. That is
measured on the CONTAINER install method. The dominant install method is Home
Assistant OS / Supervised, where the core container holds a Supervisor API token
and add-ons are managed through the Supervisor. If an in-process integration can
read that token and use it, it can stop, replace, or back up the add-on carrying
the monitor -- and the monitor's placement, which is the whole guarantee, is
defeated without touching the recorder at all.

THIS IS A DOCUMENTATION AND SOURCE FINDING, NOT A MEASUREMENT. No HA OS VM was
run. Every claim below is either (a) a verbatim quotation from Home Assistant's
own published developer documentation or from the Supervisor source at a pinned
release tag, or (b) a live measurement of the Container-install testbed this
project already runs, which is used only to establish the CONTRAST. Nothing is
inferred about behaviour that was not read directly out of the code that
implements it. Where the conclusion depends on how a deployment is packaged,
that dependency is stated rather than assumed away.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "exp", "out")
sys.path.insert(0, os.path.join(ROOT, "exp"))

from rig import capability                                         # noqa: E402

TAG = "2026.09.0"          # latest Supervisor release at retrieval time
SRC = "https://github.com/home-assistant/supervisor/blob/%s/%%s" % TAG
RAW = "https://raw.githubusercontent.com/home-assistant/supervisor/%s/%%s" % TAG
DOCS = "https://developers.home-assistant.io/docs/api/supervisor/endpoints/"


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()


FINDINGS = [
    {
        "id": "F1",
        "claim": "In HA OS / Supervised the Home Assistant core container is "
                 "given the Supervisor API token in its own environment, so any "
                 "code running in the core process can read it.",
        "source_kind": "official documentation",
        "source": DOCS,
        "quote": "For API endpoints marked with [lock] you need use an "
                 "authorization header with a Bearer token. The token is "
                 "available for apps (formerly known as add-ons) and Home "
                 "Assistant using the SUPERVISOR_TOKEN environment variable.",
        "corroborating_source_kind": "Supervisor source",
        "corroborating_source": SRC % "supervisor/docker/homeassistant.py",
        "corroborating_quote":
            "environment = {\n"
            "    \"SUPERVISOR\": str(self.sys_docker.network.supervisor),\n"
            "    \"HASSIO\": str(self.sys_docker.network.supervisor),\n"
            "    ENV_TIME: self.sys_timezone,\n"
            "    ENV_TOKEN: self.sys_homeassistant.supervisor_token,\n"
            "    ENV_TOKEN_OLD: self.sys_homeassistant.supervisor_token,\n"
            "}",
        "corroborating_note": "supervisor/docker/const.py defines "
                              "ENV_TOKEN = \"SUPERVISOR_TOKEN\".",
        "consequence": "The adversary of section 3.1 executes Python in the core "
                       "process and can therefore read os.environ['SUPERVISOR_TOKEN'] "
                       "with no privilege escalation and no exploit.",
    },
    {
        "id": "F2",
        "claim": "The Supervisor applies its role-based path restrictions ONLY to "
                 "add-ons. A request bearing the core container's token is "
                 "accepted for any path, with no role match at all.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/api/middleware/security.py",
        "quote":
            "        # Home-Assistant\n"
            "        if supervisor_token == self.sys_homeassistant.supervisor_token:\n"
            "            _LOGGER.debug(\"%s access from Home Assistant\", request.path)\n"
            "            request_from = self.sys_homeassistant\n"
            "        elif patterns.core_only.match(request.path):\n"
            "            _LOGGER.warning(\n"
            "                \"Attempted access to %s from client besides Home Assistant\",\n"
            "                request.path,\n"
            "            )\n"
            "            raise HTTPForbidden",
        "quote_2":
            "        # Check App API access\n"
            "        if app and patterns.api_bypass.match(request.path):\n"
            "            ...\n"
            "        elif app and app.access_hassio_api:\n"
            "            # Check Role\n"
            "            if patterns.role_access[app.hassio_role].match(request.path):\n"
            "                ...\n"
            "\n"
            "        if request_from:\n"
            "            request[REQUEST_FROM] = request_from\n"
            "            return await handler(request)",
        "quote_3": "    # Per-role allowed path patterns for installed apps\n"
                   "    role_access: dict[str, re.Pattern[str]]",
        "consequence": "role_access is consulted inside the `app` branch only. The "
                       "core-token branch sets request_from and falls through to "
                       "`return await handler(request)`. The documented roles "
                       "(default, homeassistant, backup, manager, admin) bound what "
                       "an ADD-ON may call; they do not bound the core container. "
                       "An add-on carrying hassio_role: homeassistant is restricted "
                       "to ^(?:|/.+/info|/core/.+|/homeassistant/.+)$ -- the core "
                       "container is restricted to nothing.",
    },
    {
        "id": "F3",
        "claim": "The only paths blacklisted for the core token are the two "
                 "Supervisor-proxy loops. Add-on lifecycle and backup endpoints "
                 "are not blacklisted.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/api/middleware/security.py",
        "quote":
            "BLACKLIST: Final = re.compile(\n"
            "    r\"^(?:/v2)?(?:\"  # both implicit v1 and v2 paths\n"
            "    r\"|/homeassistant/api/hassio(?:/|_).*\"\n"
            "    r\"|/core/api/hassio(?:/|_).*\"\n"
            "    r\")$\"\n"
            ")",
        "consequence": "Nothing in the blacklist protects an add-on from being "
                       "stopped or uninstalled by the core token.",
    },
    {
        "id": "F4",
        "claim": "The add-on lifecycle endpoints exist, are reachable with that "
                 "token, and their handlers perform no check on who is calling.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/api/__init__.py",
        "quote":
            "web.post(\"/addons/{app}/uninstall\", api_apps.uninstall),\n"
            "web.post(\"/addons/{app}/start\", api_apps.start),\n"
            "web.post(\"/addons/{app}/stop\", api_apps.stop),\n"
            "web.post(\"/addons/{app}/restart\", api_apps.restart),",
        "corroborating_source": SRC % "supervisor/api/apps.py",
        "corroborating_quote":
            "    @api_process\n"
            "    def stop(self, request: web.Request) -> Awaitable[None]:\n"
            "        \"\"\"Stop app.\"\"\"\n"
            "        app = self.get_app_for_request(request)\n"
            "        return asyncio.shield(app.stop())",
        "consequence": "POST /addons/homeprov_monitor/stop from inside the hub "
                       "process resolves the add-on and stops it. The monitor's "
                       "placement outside the hub does not make it outside the "
                       "adversary's REACH on this install method. The same applies "
                       "to /uninstall, and /addons/{app}/options can rewrite the "
                       "anchor URL the monitor posts to.",
        "note": "Both /addons/{app}/... and the newer /apps/{app}/... routes map "
                "to the same handlers at this tag.",
    },
    {
        "id": "F5",
        "claim": "Backup endpoints give the same token a read path to add-on data "
                 "and a rollback path over it.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/api/__init__.py",
        "quote":
            "web.post(\"/backups/new/full\", api_backups.backup_full),\n"
            "web.get(\"/backups/{slug}/download\", api_backups.download),\n"
            "web.post(\"/backups/{slug}/restore/partial\", ...),",
        "consequence": "A full backup includes add-on data. The adversary can "
                       "therefore read the anchor's chain without ever reaching the "
                       "anchor's socket, and restoring an earlier backup rolls the "
                       "chain back to a state that predates the evidence -- which "
                       "violates assumption A2 by a route A2 does not consider, "
                       "since no record is modified in place.",
    },
    {
        "id": "F6",
        "claim": "On HA OS / Supervised the core container is started PRIVILEGED "
                 "and on the HOST network. The container boundary the paper's "
                 "isolation argument rests on is not present on that install "
                 "method at all.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/docker/homeassistant.py",
        "quote":
            "await self._run(\n"
            "    tag=(self.sys_homeassistant.version),\n"
            "    name=self.name,\n"
            "    hostname=self.name,\n"
            "    detach=True,\n"
            "    privileged=self.sys_homeassistant.version != LANDINGPAGE,\n"
            "    init=False,\n"
            "    security_opt=self.security_opt,\n"
            "    network_mode=\"host\",\n"
            "    ...",
        "consequence": "Every anchor placement result the paper reports as "
                       "surviving --privileged was measured against a hub that was "
                       "NOT privileged. On HA OS the hub is privileged by default, "
                       "and host networking removes the network separation the "
                       "monitor's placement assumes.",
    },
    {
        "id": "F7",
        "claim": "The core container bind-mounts /share READ-WRITE, and the "
                 "project's own anchor add-on manifest stores its chain in share.",
        "source_kind": "Supervisor source",
        "source": SRC % "supervisor/docker/homeassistant.py",
        "quote":
            "DockerMount(\n"
            "    type=MountType.BIND,\n"
            "    source=self.sys_config.path_extern_share.as_posix(),\n"
            "    target=PATH_SHARE.as_posix(),\n"
            "    read_only=False,\n"
            "    bind_options=MountBindOptions(propagation=PropagationMode.RSLAVE),\n"
            ")",
        "corroborating_source_kind": "this repository",
        "corroborating_source": "addons/homeprov_anchor/config.yaml",
        "corroborating_quote": "map:\n  - share:rw",
        "consequence": "supervisor/docker/const.py sets PATH_SHARE = "
                       "PurePath(\"/share\"). On HA OS the anchor add-on AS "
                       "MANIFESTED IN THIS REPOSITORY would keep its append-only "
                       "chain on a filesystem the hub mounts read-write, so the "
                       "in-process adversary can rewrite or truncate the chain "
                       "directly, with no Supervisor call and no socket. This is a "
                       "defect in the add-on manifest, and it is fixable: an "
                       "add-on's own /data directory is not among the core "
                       "container's mounts.",
        "severity": "this is the cheapest of the three paths and the one entirely "
                    "within the paper's control",
    },
]

LOCAL = [
    {"what": "Supervisor token present in the hub container environment",
     "cmd": "docker exec hpr-hass sh -c 'env | grep -E \"SUPERVISOR|HASSIO\"'"},
    {"what": "hub container privileged flag",
     "cmd": "docker inspect hpr-hass --format '{{.HostConfig.Privileged}}'"},
    {"what": "hub container network mode",
     "cmd": "docker inspect hpr-hass --format '{{.HostConfig.NetworkMode}}'"},
    {"what": "hub container mounts",
     "cmd": "docker inspect hpr-hass --format "
            "'{{range .Mounts}}{{.Type}}:{{.Destination}}:rw={{.RW}} {{end}}'"},
    {"what": "monitor container mounts (config must be read-only)",
     "cmd": "docker inspect hpr-monitor --format "
            "'{{range .Mounts}}{{.Destination}}:rw={{.RW}} {{end}}'"},
    {"what": "anchor container mounts (hub must not share them)",
     "cmd": "docker inspect hpr-anchord --format "
            "'{{range .Mounts}}{{.Destination}}:rw={{.RW}} {{end}}'"},
]

DEPLOYMENT_TABLE = [
    {"install_method": "Container (docker run / compose)",
     "share_of_installs": "minority",
     "core_holds_supervisor_token": False,
     "core_privileged_by_default": False,
     "core_network": "the bridge network the operator chose",
     "monitor_placement_reachable_by_hub": "no: separate container, config mounted "
                                           "read-only, anchor volume not mounted",
     "what_breaks": "nothing beyond the documented residuals (Docker socket, host "
                    "compromise, pre-observation window)",
     "evidence": "measured live on this testbed (see local_measurements)",
     "covered_by_the_paper_as_written": True},
    {"install_method": "Home Assistant OS",
     "share_of_installs": "dominant",
     "core_holds_supervisor_token": True,
     "core_privileged_by_default": True,
     "core_network": "host",
     "monitor_placement_reachable_by_hub":
         "YES, three independent ways: (1) POST /addons/<monitor>/stop with the "
         "core token; (2) full backup then download/restore over the anchor's "
         "add-on data; (3) direct read-write access to /share, where the anchor "
         "add-on as manifested keeps its chain",
     "what_breaks": "the monitor's placement, which is the entire guarantee. A2 "
                    "('anchored records are not modified or removed') can be "
                    "violated without any in-place modification, by restoring a "
                    "backup or by stopping the observer.",
     "evidence": "documentation and Supervisor source at tag %s (see findings)" % TAG,
     "covered_by_the_paper_as_written": False},
    {"install_method": "Supervised (Supervisor on a generic Debian host)",
     "share_of_installs": "minority but non-trivial",
     "core_holds_supervisor_token": True,
     "core_privileged_by_default": True,
     "core_network": "host",
     "monitor_placement_reachable_by_hub": "same as HA OS: the Supervisor code "
                                           "path is identical",
     "what_breaks": "same as HA OS",
     "evidence": "same Supervisor source",
     "covered_by_the_paper_as_written": False},
    {"install_method": "Core (bare Python venv)",
     "share_of_installs": "small",
     "core_holds_supervisor_token": False,
     "core_privileged_by_default": "n/a (no container)",
     "core_network": "host",
     "monitor_placement_reachable_by_hub":
         "depends entirely on OS-level separation: with no container boundary the "
         "monitor must run as a different uid, and the anchor's store must not be "
         "writable by the hub's uid. Not evaluated.",
     "what_breaks": "unknown; the paper's placement argument is stated in terms of "
                    "containers and has no analogue here",
     "evidence": "not evaluated",
     "covered_by_the_paper_as_written": False},
]


def main():
    local = []
    for probe in LOCAL:
        local.append({**probe, "output": sh(probe["cmd"]) or "(empty)"})

    result = {
        "experiment": "E-E",
        "what": "whether HOMEPROV's monitor/anchor placement survives the Home "
                "Assistant OS and Supervised install methods",
        "method": "DOCUMENTATION AND SOURCE finding, plus live contrast "
                  "measurements on the Container-install testbed. No HA OS virtual "
                  "machine was run, and no number below is presented as a measured "
                  "rate on HA OS.",
        "not_run": {"what": "a live HA OS deployment",
                    "why": "the review asks for a scoping decision, and the "
                           "decision follows from the Supervisor's own "
                           "authorization code, which is read directly here. A VM "
                           "would demonstrate what the code already states.",
                    "what_would_change": "nothing in the verdict; it would convert "
                                         "F2 and F4 from source-verified to "
                                         "execution-verified."},
        "supervisor_version_pinned": TAG,
        "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": {"documentation": DOCS,
                    "source_tree": SRC % "",
                    "raw_files_read": [
                        RAW % "supervisor/api/middleware/security.py",
                        RAW % "supervisor/api/apps.py",
                        RAW % "supervisor/api/__init__.py",
                        RAW % "supervisor/docker/homeassistant.py",
                        RAW % "supervisor/docker/const.py"]},
        "findings": FINDINGS,
        "local_measurements": local,
        "deployment_model_table": DEPLOYMENT_TABLE,
        "verdict": {
            "is_container_only_scoping_sufficient": False,
            "why": "The paper does not currently say which install method its "
                   "isolation claim covers. Left unqualified, the claim reads as "
                   "covering Home Assistant generally, and on the dominant install "
                   "method it is false: an in-process integration holding "
                   "SUPERVISOR_TOKEN can stop or uninstall the add-on carrying the "
                   "monitor, and the Supervisor applies no role restriction to that "
                   "token. The isolation claim must be narrowed explicitly.",
            "required_changes": [
                "State the install method in the threat model and in the abstract's "
                "scope: the evaluated guarantee is for the Container install "
                "method, where the hub holds no Supervisor token.",
                "Add the deployment-model table (review 7) with the HA OS row "
                "marked as defeating the monitor's placement.",
                "Change the anchor add-on manifest from `share:rw` to the add-on's "
                "own /data directory. As manifested, the chain sits on a "
                "filesystem the core container mounts read-write on HA OS, which "
                "defeats the anchor with no Supervisor call at all.",
                "State that on HA OS the core container runs privileged and "
                "host-networked, so the anchor-placement results reported as "
                "surviving --privileged were measured against a hub that was not.",
                "Add 'holds a Supervisor API token' as a capability-record field, "
                "false for every result in this paper.",
            ],
            "what_survives": "The post-commit detection result itself is unaffected: "
                             "it is a statement about a commitment over recorder "
                             "rows, and it holds wherever the monitor and anchor are "
                             "genuinely out of reach. What HA OS breaks is the "
                             "claim that the shipped PLACEMENT achieves that.",
        },
    }
    result["capability"] = capability.record(
        actor_id="supervisor_token_holder", actor_position="in_process_integration",
        seed=None, budget_writes=0, window_s=None,
        knowledge={"supervisor_api": "documented and public",
                   "addon_slug_of_monitor": "readable via GET /addons"},
        constraints={"host_root": False, "anchor_key_access": False,
                     "holds_supervisor_token": "FALSE on the Container install "
                                               "method evaluated in this paper; "
                                               "TRUE on HA OS / Supervised",
                     "ha_os_vm_executed": False},
        substrate={"kind": "documentation and Supervisor source review",
                   "pinned_release": TAG,
                   "live_contrast": "Container-install testbed, measured"},
        mission="E-E HA OS / Supervisor reach (review 4c)")

    path = os.path.join(OUT, "e_e_supervisor_reach.json")
    dig = capability.stamp(result, path)
    print("== E-E HA OS / Supervisor reach ==")
    print("  Supervisor pinned at %s; %d findings, %d local contrast measurements"
          % (TAG, len(FINDINGS), len(local)))
    for p in local:
        print("   %-52s %s" % (p["what"][:52], p["output"][:80]))
    print("  VERDICT: Container-only scoping sufficient? %s"
          % result["verdict"]["is_container_only_scoping_sufficient"])
    print("  -> exp/out/e_e_supervisor_reach.json")
    print("  digest", dig)
    return result


if __name__ == "__main__":
    main()
