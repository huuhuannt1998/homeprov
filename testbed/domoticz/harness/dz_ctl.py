"""Host side of the integration's command channel: write /hpctl/cmd_<id>.json, wait for /hpctl/ack_<id>.json.
The directory is a bind mount shared with the Domoticz container; the integration polls it once per heartbeat (1 s)."""
import itertools
import json
import os
import time

_seq = itertools.count(1)


class Ctl:
    def __init__(self, hpctl_dir):
        self.dir = hpctl_dir
        os.makedirs(self.dir, exist_ok=True)

    def call(self, op, timeout=30, **kw):
        cid = "%d_%06d" % (int(time.time() * 1000), next(_seq))
        tmp = os.path.join(self.dir, ".cmd_%s.tmp" % cid)
        with open(tmp, "w") as fh:
            json.dump(dict(op=op, **kw), fh)
        os.replace(tmp, os.path.join(self.dir, "cmd_%s.json" % cid))
        ack = os.path.join(self.dir, "ack_%s.json" % cid)
        end = time.time() + timeout
        while time.time() < end:
            if os.path.exists(ack):
                try:
                    with open(ack) as fh:
                        d = json.load(fh)
                except ValueError:
                    time.sleep(0.1)
                    continue
                os.remove(ack)
                return d
            time.sleep(0.1)
        return {"ok": False, "err": "timeout waiting for ack of %s" % op}
