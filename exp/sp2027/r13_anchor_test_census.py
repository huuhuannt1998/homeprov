#!/usr/bin/env python3
"""Round 13c (2026-10-08): census of testbed/anchord/test_anchor_chain.py after E7 (the paper prints its check counts).

Collects the tests with pytest, groups them (linked-variant tests, the pin on the daemon the runs before E7 used, the
saved-chain checks), hashes the decompressed saved chains the parametrized check reads to count distinct chains and
copies, runs the file, and writes exp/out/r13_anchor_test_census.json.
"""
import collections, datetime, gzip, hashlib, json, os, re, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
T = "testbed/anchord/test_anchor_chain.py"
col = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", T], cwd=REPO, capture_output=True, text=True)
ids = [l.strip() for l in col.stdout.splitlines() if "::" in l]
fn = collections.Counter(re.sub(r"\[.*", "", i.split("::")[1]) for i in ids)
saved = [re.search(r"\[(.*)\]$", i).group(1) for i in ids if "saved_evaluation_chains" in i]
digests = {}
for p in saved:
    b = open(p, "rb").read()
    if p.endswith(".gz"):
        b = gzip.decompress(b)
    digests[os.path.relpath(p, REPO)] = hashlib.sha256(b).hexdigest()
run = subprocess.run([sys.executable, "-m", "pytest", "-q", T], cwd=REPO, capture_output=True, text=True)
tail = run.stdout.strip().splitlines()[-1]
out = {"what": "census of " + T, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "script_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
       "test_file_sha256": hashlib.sha256(open(os.path.join(REPO, T), "rb").read()).hexdigest(),
       "collected": len(ids), "by_function": dict(fn),
       "saved_chain_checks": len(saved), "distinct_saved_chains": len(set(digests.values())),
       "copies": len(saved) - len(set(digests.values())),
       "pinned_daemon_checks": fn.get("test_evaluated_daemon_is_unmodified", 0),
       "linked_variant_checks": len(ids) - len(saved) - fn.get("test_evaluated_daemon_is_unmodified", 0),
       "saved_chain_digests": digests, "pytest_result": tail, "pytest_returncode": run.returncode}
dst = os.path.join(REPO, "exp", "out", "r13_anchor_test_census.json")
assert not os.path.exists(dst)
json.dump(out, open(dst, "w"), indent=1)
print({k: out[k] for k in ("collected", "linked_variant_checks", "pinned_daemon_checks", "saved_chain_checks",
                           "distinct_saved_chains", "copies", "pytest_result")})
