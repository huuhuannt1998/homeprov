#!/usr/bin/env python3
"""Aggregate the controlled browser-render trials (r1_render_measure output) into
an exp/out result file: per-trial rendered causes, Clopper-Pearson proportions
for the displayed-cause change under each edit and viewer, agreement between the
rendered string and the transcribed display() rule, and provenance.

usage: r1_render_aggregate.py <ha_version> <member_hex>
"""
import json
import os
import sys

sys.path.insert(0, "<artifact-root>/exp/sp2027")
import r1_common as RC  # noqa: E402

VER = sys.argv[1]
SRC = "/tmp/r1_render_measure_%s.json" % VER
d = json.load(open(SRC))
trials = d["trials"]
SCR = "exp/out/r1_screens"

# Normalise a rendered cause-line string to the rule's label vocabulary so
# surface wording ("By Alex Rivera (household)" / "Via Lock") can be compared to
# the rule's ("user:...", "integration:lock"). Surface strings are also kept.
def norm(s):
    if s is None or s == "":
        return "none"
    if s.startswith("By automation") or s.startswith("By state change"):
        return "automation"
    if s.startswith("By "):
        return "user:" + s[3:]
    if s.startswith("Via "):
        return "integration:" + s[4:].lower()
    return s


rows = []
counts = {("admin", "member"): 0, ("non_admin", "member"): 0,
          ("admin", "random"): 0, ("non_admin", "random"): 0}
agree = 0
agree_total = 0
for t in trials:
    r = t["rendered"]; rule = t["rule"]
    row = {"trial": t["trial"], "state_id": t["state_id"], "rendered": {}, "rule": rule,
           "changed_vs_baseline": {}}
    for viewer in ("admin", "non_admin"):
        base = r["baseline"][viewer][0]
        row["rendered"][viewer] = {c: r[c][viewer][0] for c in ("baseline", "member", "random")}
        for cond in ("member", "random"):
            changed = (r[cond][viewer][0] or "") != (base or "")
            row["changed_vs_baseline"].setdefault(viewer, {})[cond] = changed
            if changed:
                counts[(viewer, cond)] += 1
            # rendered-vs-rule agreement (normalised vocabulary)
            agree_total += 1
            if norm(r[cond][viewer][0]) == rule[cond][viewer]:
                agree += 1
    rows.append(row)

n = len(trials)
payload = {
    "experiment": "R1-items3and4-render",
    "what": ("displayed cause of a member-account swap (PSR), a random-id swap (PS, "
             "control) and the integration baseline, RENDERED in a real browser "
             "(Playwright+Chromium) as an admin viewer and a non-admin viewer, "
             "before/after each recorder edit; compared to the transcribed display() rule"),
    "ha_version": VER,
    "member_account": {"user_id_hex": d["member_hex"], "name": "Alex Rivera (household)",
                       "in_admin_name_map": d.get("names_admin_has_member")},
    "n_trials": n,
    "rendered_displayed_cause_changed": {
        "member_swap_admin": RC.cp(counts[("admin", "member")], n),
        "member_swap_non_admin": RC.cp(counts[("non_admin", "member")], n),
        "random_id_admin": RC.cp(counts[("admin", "random")], n),
        "random_id_non_admin": RC.cp(counts[("non_admin", "random")], n),
    },
    "rendered_vs_rule_agreement": {"agree": agree, "total": agree_total,
                                   "prop": agree / agree_total if agree_total else None},
    "exact_rendered_strings_example": (rows[0]["rendered"] if rows else None),
    "deviation_surface_form": ("rendered strings are 'By <name>' and 'Via Lock'; the "
                               "transcribed rule emits 'user:<name>' and 'integration:lock'. "
                               "Semantics match after normalisation; surface wording differs. "
                               "The displayed cause had never been rendered before this run."),
    "screenshots": sorted(os.path.basename(p) for p in os.listdir(SCR)
                          if p.startswith("r1_%s_trial0" % VER) or
                          p.startswith("r1_%s_memberswap" % VER)),
    "per_trial": rows,
    "provenance": RC.provenance(VER, ["exp/sp2027/r1_render_measure.py",
                                      "exp/sp2027/r1_render.py",
                                      "exp/sp2027/r1_render_aggregate.py"]),
}
RC.write_result("r1_%s_member_swap_render.json" % VER, payload)
print("admin member %d/%d | nonadmin member %d/%d | admin random %d/%d | nonadmin random %d/%d | agree %d/%d" % (
    counts[("admin", "member")], n, counts[("non_admin", "member")], n,
    counts[("admin", "random")], n, counts[("non_admin", "random")], n, agree, agree_total))
