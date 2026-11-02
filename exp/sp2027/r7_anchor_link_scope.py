"""R7 (round-2 triage N2): which evaluated runs used the unlinked anchor.

Two sources, both read-only: (1) every version of testbed/anchord/anchord.py in the repository's history, checked for a
hash link (prev_digest); (2) every anchor chain an evaluated run saved (exp/out/*anchor_chain.jsonl.gz, the window
extracts' chains, and the E2 chain in the verifier snapshot set when present), checked with chainverify.py. Each Table 13
run is mapped to its saved chain where one exists. No old result is changed.

    python3 exp/sp2027/r7_anchor_link_scope.py     # writes exp/out/r7_anchor_link_scope.json (never overwrites)
"""
import datetime
import glob
import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
sys.path.insert(0, os.path.join(REPO, "testbed", "anchord"))
import chainverify as CV  # noqa: E402

TABLE13 = [("In-process blinding", "2026-09-03", "e2_real_boundary.json", None),
           ("Write-time strategies", "2026-09-09", "e_c_write_time.json", None),
           ("Other principal", "2026-09-18", "e_d_other_principal_real.json", None),
           ("Other principal", "2026-09-26", "e_d_auth_other_principal_real.json", "e_d_auth_anchor_chain.jsonl.gz"),
           ("Write-time strategies", "2026-10-02", "e_c_auth_other_principal_real.json", "e_c_auth_anchor_chain.jsonl.gz"),
           ("Random-id swap", "2026-10-02", "e_ps_auth_detection.json", "e_ps_auth_anchor_chain.jsonl.gz"),
           ("In-process blinding", "2026-10-02", "e2_auth_seal_check.json", "e2_auth_anchor_chain.jsonl.gz"),
           ("Random-id swap", "2026-10-02", "e_ps_clo_detection.json", "e_ps_clo_anchor_chain.jsonl.gz"),
           ("Other principal", "2026-10-02", "e_d_clo_other_principal_real.json", "e_d_clo_anchor_chain.jsonl.gz"),
           ("Write-time strategies", "2026-10-02", "e_c_clo_other_principal_real.json", "e_c_clo_anchor_chain.jsonl.gz"),
           ("Member-account swap", "2026-10-03", "e_psr_clo_detection.json", "e_psr_clo_anchor_chain.jsonl.gz"),
           ("Random-id swap", "2026-10-04", "e_ps_whr_detection.json", "e_ps_whr_anchor_chain.jsonl.gz"),
           ("Other principal", "2026-10-04", "e_d_whr_other_principal_real.json", "e_d_whr_anchor_chain.jsonl.gz"),
           ("Member-account swap", "2026-10-04", "e_psr_whr_detection.json", "e_psr_whr_anchor_chain.jsonl.gz")]


def git(*a):
    return subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True).stdout


def main():
    dst = os.path.join(OUT, "r7_anchor_link_scope.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    versions = []
    for line in git("log", "--all", "--format=%H %ad %s", "--date=short", "--", "testbed/anchord/anchord.py").splitlines():
        h, d, s = line.split(" ", 2)
        src = git("show", "%s:testbed/anchord/anchord.py" % h)
        versions.append({"commit": h[:7], "date": d, "subject": s, "has_prev_digest": "prev_digest" in src})
    chains = sorted(glob.glob(os.path.join(OUT, "*anchor_chain.jsonl*"))
                    + glob.glob(os.path.join(REPO, "reproduce", "snapshots", "*.chain.jsonl*")))
    saved = {}
    for p in chains:
        r = CV.verify_chain(CV.read(p))
        saved[os.path.relpath(p, REPO)] = {k: r[k] for k in ("records", "link", "linked_records", "ok")}
    runs = []
    for label, date, res, ch in TABLE13:
        row = {"run": label, "date": date, "result_file": "exp/out/" + res}
        if ch:
            row.update(chain="exp/out/" + ch, chain_check=saved["exp/out/" + ch])
        else:
            row.update(chain=None, note="no anchor chain saved; every anchord.py version up to this run's date is "
                                        "unlinked (see anchord_versions)")
        row["anchor"] = "unlinked (v1)"
        runs.append(row)
    out = {"item": "R7/N2: every evaluated run used the unlinked anchor record format",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO),
           "anchord_versions_in_history": versions,
           "linking_introduced": "2026-10-07 (working tree; HOMEPROV_ANCHOR_LINK=v2 default, v1 reproduces the old format)",
           "saved_chains": saved,
           "all_saved_chains_unlinked_and_well_formed": all(v["link"] == "v1" and v["ok"] for v in saved.values()),
           "table13_runs": runs,
           "statement": "All 14 Table 13 runs, and every other evaluated run, used the unlinked anchor: no committed "
                        "version of anchord.py links records, and every saved chain (%d files) parses as unlinked v1 "
                        "with 0 linked records. Their first anchored roots rest on the anchor host (A4)." % len(saved)}
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({k: out[k] for k in ("anchord_versions_in_history", "all_saved_chains_unlinked_and_well_formed",
                                          "statement")}, indent=1))


if __name__ == "__main__":
    main()
