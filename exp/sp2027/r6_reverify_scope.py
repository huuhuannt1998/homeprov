"""R7 (round-2 triage N3/V1): bookkeeping for the typed-encoding re-verification.

Maps every run of the paper's run-provenance table (Table 13: 14 runs, identified by result file and its sha256 prefix)
to what round 6 re-verified, from the round-6 result files (no recomputation):

  - exp/out/r6_reverify_v2.json: the ten runs whose verifier snapshot is in the snapshot set; per run the trials, the
    edited rows, the edited rows in the at-risk class (a 0x7C byte in a context field the run's scheme hashes, before or
    after the edit), and the edited rows whose old-encoding (v1) node hash the edit left unchanged (the collision class);
  - exp/out/r6_e2_seal_v2.json: the authenticated in-process blinding run's single seal check, recomputed under both
    encodings (not a trial verdict, so not part of the 1,290);
  - the three runs whose verifier snapshot was never kept (not re-verifiable).

    python3 exp/sp2027/r6_reverify_scope.py     # writes exp/out/r6_reverify_scope.json (never overwrites)
"""
import datetime
import hashlib
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "exp", "out")

# Table 13 order: (run label, date, scheme, authenticated, result file, round-6 run id or None)
TABLE13 = [
    ("In-process blinding", "2026-09-03", "row", False, "e2_real_boundary.json", None),
    ("Write-time strategies", "2026-09-09", "row", False, "e_c_write_time.json", None),
    ("Other principal", "2026-09-18", "row", False, "e_d_other_principal_real.json", None),
    ("Other principal", "2026-09-26", "row", True, "e_d_auth_other_principal_real.json", "e_d_auth"),
    ("Write-time strategies", "2026-10-02", "row", True, "e_c_auth_other_principal_real.json", "e_c_auth"),
    ("Random-id swap", "2026-10-02", "row", True, "e_ps_auth_detection.json", "e_ps_auth"),
    ("In-process blinding", "2026-10-02", "row", True, "e2_auth_seal_check.json", "E2_SEAL"),
    ("Random-id swap", "2026-10-02", "closure", True, "e_ps_clo_detection.json", "e_ps_clo"),
    ("Other principal", "2026-10-02", "closure", True, "e_d_clo_other_principal_real.json", "e_d_clo"),
    ("Write-time strategies", "2026-10-02", "closure", True, "e_c_clo_other_principal_real.json", "e_c_clo"),
    ("Member-account swap", "2026-10-03", "closure", True, "e_psr_clo_detection.json", "e_psr_clo"),
    ("Random-id swap", "2026-10-04", "whole-row", True, "e_ps_whr_detection.json", "e_ps_whr"),
    ("Other principal", "2026-10-04", "whole-row", True, "e_d_whr_other_principal_real.json", "e_d_whr"),
    ("Member-account swap", "2026-10-04", "whole-row", True, "e_psr_whr_detection.json", "e_psr_whr"),
]
NOT_KEPT = {
    "e2_real_boundary.json": "verifier snapshot not kept (pre-authentication run on the earlier stack; its recorder and "
                             "anchor chain are not in the snapshot set)",
    "e_c_write_time.json": "verifier snapshot not kept (unauthenticated run; its recorder copy is not in the snapshot set)",
    "e_d_other_principal_real.json": "verifier snapshot not kept (unauthenticated run; its recorder copy is not in the "
                                     "snapshot set)",
}
USED_BY_BODY = {
    "e2_real_boundary.json": "section 7.4's 133,087 of 133,088 rows",
    "e_c_write_time.json": "App. A 'Row, no authentication' block and the benign floor 3/744",
    "e_d_other_principal_real.json": "the benign floor 1/558, part of the pooled 13/4,733",
}


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    dst = os.path.join(OUT, "r6_reverify_scope.json")
    if os.path.exists(dst):
        raise SystemExit("refusing to overwrite " + dst)
    rv = json.load(open(os.path.join(OUT, "r6_reverify_v2.json")))
    e2 = json.load(open(os.path.join(OUT, "r6_e2_seal_v2.json")))
    rows, tot = [], {"trials": 0, "edited_rows": 0, "edited_rows_at_risk_0x7C": 0, "edited_rows_v1_hash_unchanged": 0,
                     "trial_verdict_changes": 0}
    for label, date, scheme, auth, f, rid in TABLE13:
        r = {"run": label, "date": date, "scheme": scheme, "authenticated": auth, "result_file": "exp/out/" + f,
             "result_sha256_prefix": sha(os.path.join(OUT, f))[:12]}
        if rid in rv["runs"]:
            x = rv["runs"][rid]
            r.update(reverified_typed="yes, trial verdicts (r6_reverify_v2.json run %s)" % rid,
                     trials=sum(a["n"] for a in x["per_arm"].values()),
                     arms={a: v["n"] for a, v in x["per_arm"].items()},
                     edited_rows=x["edited_rows"],
                     edited_rows_at_risk_0x7C=len(x["edited_rows_with_0x7C_in_a_context_field"]),
                     edited_rows_v1_hash_unchanged=len(x["edited_rows_in_v1_collision_class"]),
                     trial_verdict_changes=len(x["trial_verdict_changes_v1_to_v2"]),
                     benign_floor_v1_v2=x["benign_floor_second"])
            for k in tot:
                tot[k] += r[k]
        elif rid == "E2_SEAL":
            p = e2["per_second"]
            r.update(reverified_typed="seal check only, both encodings (r6_e2_seal_v2.json); not a trial verdict, "
                                      "not in the 1,290",
                     seal_check={"adversary_seconds": [x["second"] for x in p],
                                 "v1_root_reproduced": all(x["v1_root_matches"] for x in p),
                                 "rows": sum(x["rows"] for x in p),
                                 "rows_with_0x7C_in_ctx_or_par": sum(x["rows_with_0x7C_in_ctx_or_par"] for x in p),
                                 "published_answer_reproduced": e2["v1_reproduces_published"]})
        else:
            r.update(reverified_typed="no", reason=NOT_KEPT[f], numbers_the_body_uses=USED_BY_BODY[f],
                     what_would_settle_it="a re-run of that arm with the v2 monitor image, keeping the verifier "
                                          "snapshot; its flagged trials stand under v2 by refinement (a v1 root "
                                          "mismatch implies distinct field tuples)")
        rows.append(r)
    out = {"item": "R7: scope and composition of the typed-encoding re-verification, per Table 13 run",
           "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "script": os.path.relpath(os.path.abspath(__file__), REPO), "script_sha256": sha(os.path.abspath(__file__)),
           "inputs_sha256": {"exp/out/r6_reverify_v2.json": sha(os.path.join(OUT, "r6_reverify_v2.json")),
                             "exp/out/r6_e2_seal_v2.json": sha(os.path.join(OUT, "r6_e2_seal_v2.json"))},
           "definitions": {
               "edited_rows_at_risk_0x7C": "edited rows with a 0x7C byte in a context field the run's scheme hashes "
                                           "(context, parent; plus user for closure and whole-row), before or after "
                                           "the edit: the rows a crafted splice could have targeted",
               "edited_rows_v1_hash_unchanged": "edited rows whose old-encoding node hash was the same before and "
                                                "after the edit (the collision class)"},
           "table13_runs": len(rows),
           "trial_verdicts_reverified": {"runs": sum(1 for r in rows if "trials" in r), **tot},
           "not_in_the_1290": [{"date": r["date"], "run": r["run"], "why": r.get("reason") or r["reverified_typed"]}
                               for r in rows if "trials" not in r],
           "runs": rows,
           "statement": ("Ten runs, 1,290 trials and 1,046 edited rows were re-verified with the typed encoding; no "
                         "verdict changed. 86 of the 1,046 edited rows were in the at-risk class, and the number of "
                         "edits that left a row's old-encoding node hash unchanged is 0. Of the other four Table 13 runs, "
                         "the authenticated in-process blinding run's seal check was recomputed under both encodings "
                         "and three runs could not be re-verified because their verifier snapshots were not kept.")}
    assert tot["trials"] == 1290 and tot["edited_rows"] == 1046, tot
    with open(dst, "x") as fh:
        json.dump(out, fh, indent=1)
    for r in rows:
        print(r["date"], r["run"], r["scheme"], "|", r.get("trials", "-"), r.get("edited_rows", "-"),
              r.get("edited_rows_at_risk_0x7C", "-"), r.get("edited_rows_v1_hash_unchanged", "-"), "|",
              r["reverified_typed"][:60])
    print("TOTAL", tot)


if __name__ == "__main__":
    main()
