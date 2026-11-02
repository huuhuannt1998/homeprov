"""R7 helper: run the hash-linked anchor daemon (testbed/anchord/anchord_linked.py, which wraps the unmodified evaluated
daemon anchord.py) as a LOCAL process, as r9_c_anchord_local.py does for anchord.py.

The modules are imported from their files with anchord's three path globals (CHAIN, REFUSALS, PUBLISH) rebound into
<data_dir>; HOMEPROV_ANCHOR_KEY, HOMEPROV_ANCHOR_LINK, HEAD_WITNESS_URL, HEAD_WITNESS_MODE and HOMEPROV_WITNESS_KEY come
from the environment exactly as in the container. The server is anchord's own handler on 127.0.0.1:<port>; the publisher
and (for async witness pushes) the witness worker start as anchord_linked's __main__ starts them.

usage: r7_anchord_local.py <port> <data_dir>
"""
import importlib.util, os, socketserver, sys

port, data = int(sys.argv[1]), sys.argv[2]
os.environ.setdefault("PUBLISH_PERIOD", "3600")
SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "testbed", "anchord", "anchord_linked.py"))
spec = importlib.util.spec_from_file_location("anchord_linked_r7", SRC)
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
A = L.A
os.makedirs(os.path.join(data, "anchor"), exist_ok=True)
os.makedirs(os.path.join(data, "published"), exist_ok=True)
A.CHAIN = os.path.join(data, "anchor", "chain.jsonl")
A.REFUSALS = os.path.join(data, "anchor", "refusals.jsonl")
A.PUBLISH = os.path.join(data, "published", "head.json")
A._rebuild_roots()
L.start_background()
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", port), A.H) as s:
    print("READY", port, L.LINK, flush=True)
    s.serve_forever()
