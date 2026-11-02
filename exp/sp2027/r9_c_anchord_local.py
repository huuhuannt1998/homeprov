"""R9 item (c) helper: run testbed/anchord/anchord.py as a LOCAL process.

PROTOCOL DEVIATION (stated, not hidden): the original e7b measurement ran the
anchor daemon in a Docker container (python:3.12-slim) with its port published
to the host. This launcher runs the UNMODIFIED anchord module in a plain host
Python process instead, bound to 127.0.0.1 only, with its chain/refusal/publish
files redirected into a temporary directory. No container is started.

The module is imported from its file, its three path globals are rebound
(CHAIN, REFUSALS, PUBLISH), KEY comes from HOMEPROV_ANCHOR_KEY exactly as in the
container, and the server is the module's own handler class H on a
socketserver.TCPServer, as anchord's __main__ does (only the bind address and
port differ: 127.0.0.1:<port> instead of 0.0.0.0:9900).

usage: r9_c_anchord_local.py <port> <data_dir> [key]
"""
import importlib.util, os, socketserver, sys, threading

port, data = int(sys.argv[1]), sys.argv[2]
key = sys.argv[3] if len(sys.argv) > 3 else ""
os.environ["HOMEPROV_ANCHOR_KEY"] = key        # read at import, as in the container
os.environ["PUBLISH_PERIOD"] = "3600"          # e_a_signed_anchor.py passes 3600

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                   "testbed", "anchord", "anchord.py"))
spec = importlib.util.spec_from_file_location("anchord_r9", SRC)
ad = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ad)

os.makedirs(os.path.join(data, "anchor"), exist_ok=True)
os.makedirs(os.path.join(data, "published"), exist_ok=True)
ad.CHAIN = os.path.join(data, "anchor", "chain.jsonl")
ad.REFUSALS = os.path.join(data, "anchor", "refusals.jsonl")
ad.PUBLISH = os.path.join(data, "published", "head.json")
assert ad.KEY == key.encode()

ad._rebuild_roots()
threading.Thread(target=ad._publisher, daemon=True).start()
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", port), ad.H) as s:
    print("READY", port, flush=True)
    s.serve_forever()
