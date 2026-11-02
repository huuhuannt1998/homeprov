"""HOMEPROV predeclared catalog — frozen 2026-08-19, BEFORE any evaluation run.

Nothing in this file may be edited once a stage has produced data. Additions go
in a clearly labelled post-hoc appendix. This is what stops "damage",
"detection", and "plausible" being defined after the fact to fit the result.

Cross-references are to research_design_detailed.md sections 9.1-9.5.
"""

FROZEN = "2026-08-19"

# ---------------------------------------------------------------- 9.1 forgeries
# class: del | rep | inj | composed ; sev: predeclared severity (9.2)
FORGERY_CATALOG = {
    "FT-1":  dict(cls="del",      sev="SEV-1", desc="Delete the adversary's own action node"),
    "FT-2":  dict(cls="del",      sev="SEV-1", desc="Delete an intermediate trigger/condition, orphaning a subtree"),
    "FT-3":  dict(cls="del",      sev="SEV-3", desc="Delete an entire minute-segment of nodes"),
    "FT-4":  dict(cls="rep",      sev="SEV-2", desc="Re-point actuates edge onto an innocent automation"),
    "FT-5":  dict(cls="rep",      sev="SEV-2", desc="Re-point trigger->condition edge to flip the branch taken"),
    "FT-6":  dict(cls="rep",      sev="SEV-1", desc="Swap sibling edges so causal ordering inverts"),
    "FT-7":  dict(cls="inj",      sev="SEV-2", desc="Inject a fabricated trigger making an innocent automation explicable"),
    "FT-8":  dict(cls="inj",      sev="SEV-2", desc="Inject a fabricated principal (a person who was not there)"),
    "FT-9":  dict(cls="inj",      sev="SEV-3", desc="Inject an entire automation run that never occurred"),
    "FT-10": dict(cls="composed", sev="SEV-2", desc="FLAGSHIP causal laundering: FT-1 o FT-4 o FT-7"),
    "FT-11": dict(cls="composed", sev="SEV-2", desc="Branch laundering: FT-2 o FT-5"),
    "FT-12": dict(cls="composed", sev="SEV-3", desc="Segment substitution: FT-3 o FT-9"),
}

# ---------------------------------------------------------------- 9.2 severity
SEVERITY = {
    "SEV-0": "Cosmetic     — timeline differs, Attr unchanged for every actuation",
    "SEV-1": "Obscuring    — Attr(alpha) -> bottom for some alpha",
    "SEV-2": "Misattributing — Attr(alpha) -> a NAMED INNOCENT   [centre of gravity]",
    "SEV-3": "Fabricating  — an actuation appears that never occurred, or a real one vanishes",
    "SEV-4": "Systemic     — self-consistent across the full anchored epoch",
}

# ------------------------------------------------------------- 9.3 benign events
# Must NOT trigger tamper alarms. BE-11 was ADDED FROM MEASUREMENT in M1.
BENIGN_CATALOG = {
    "BE-1":  "Home Assistant restart",
    "BE-2":  "Recorder auto-purge at the retention boundary",
    "BE-3":  "Schema migration on version upgrade",
    "BE-4":  "Backup restore to an earlier snapshot",
    "BE-5":  "NTP step / DST transition",
    "BE-6":  "Integration reload",
    "BE-7":  "Device becomes unavailable mid-automation",
    "BE-8":  "Concurrent automation runs interleaving in one segment",
    "BE-9":  "Clean shutdown mid-segment",
    "BE-10": "Disk-full write failure",
    "BE-11": "Template-entity context loss (MEASURED in M1: a template lock's derived "
             "state row carries context_parent_id=NULL even for a genuine automation-driven "
             "actuation; adversary-independent benign attribution loss)",
}

# ------------------------------------------------ 9.4 semantic invariants (Plaus)
# REVISED AFTER M1: Plaus is DEFINED as agreement with Home Assistant's own
# logbook renderer. These are the ADDITIONAL checks layered on top.
# SI-4 and SI-5 were MEASURED in M1 to carry the entire composition-necessity
# argument -- against a checker omitting them, F_rep alone suffices at 3 writes.
SEMANTIC_INVARIANTS = {
    "SI-1": "No state transition to the state already held",
    "SI-2": "No automation action while the automation is disabled",
    "SI-3": "No event originating from an entity in state 'unavailable'",
    "SI-4": "Every actuation has a trigger or principal ancestor in-window; one "
            "automation run produces one actuation episode   [LOAD-BEARING]",
    "SI-5": "Monotonic timestamps within an entity's history; one automation "
            "context does not span disjoint actuation episodes   [LOAD-BEARING]",
    "SI-6": "Device capability match (a light cannot emit a lock transition)",
    "SI-7": "Referenced automation/integration entity ids existed at that time",
}
PLAUS_DEFINITION = ("agreement with homeassistant.components.logbook.processor."
                    "EventProcessor output, PLUS the SI checks above")

# --------------------------------------------------------- 9.5 success thresholds
THRESHOLDS = {
    "LR":              dict(op=">=", value=1.0,  hard=True,
                            note="SOUNDNESS REQUIREMENT. LR<1 means forged data entered the "
                                 "account: a design defect, not a poor score. Fires the M3 checkpoint."),
    "MISS_R_ASSERT":   dict(op="==", value=0,    hard=True,
                            note="Never assert an attribution that cannot be supported."),
    "TDR":             dict(op=">=", value=0.99, hard=False, note="post-anchor forgeries"),
    "OQ":              dict(op="<=", value=0.10, hard=False,
                            note="AND <= 0.1x baseline B3. HEADLINE METRIC."),
    "OQ_VS_B3":        dict(op="<=", value=0.10, hard=False, note="ratio to whole-log-void"),
    "BFP":             dict(op="<=", value=0.01, hard=False, note="over the 9.3 benign catalog"),
    "RA":              dict(op=">=", value=0.95, hard=False, note="on the surviving subgraph V\\Q"),
    "RHO":             dict(op="<=", value=1.15, hard=False, note="relative overhead"),
    "STORAGE_RATIO":   dict(op="<=", value=1.5,  hard=False, note="vs baseline recorder"),
}

# ------------------------------------------------------------------- baselines
BASELINES = {
    "B0": "Stock HA 2026.7 recorder, no integrity (floor; TDR = 0 by construction)",
    "B1": "Naive IN-DATABASE hash chain (strawman; must be SHOWN broken, not assumed)",
    "B2": "Record-level tamper-evident log anchored out-of-process, ported from "
          "Yagiz et al. 2026 (arXiv 2605.00065) and GIVEN HOMEPROV'S OWN ANCHOR so "
          "the contrast isolates graph-vs-flat.  *** THE HARDEST BASELINE ***",
    "B3": "Whole-log-void policy on any violation (generic tamper-evident behaviour; "
          "OQ -> 1 by construction)",
    "B4": "HOMEPROV with edge binding DISABLED (self-baseline; isolates insight I-1)",
}

# ------------------------------------------------------------------- ablations
ABLATIONS = {
    "AB-1": "Greedy (A6) vs exact ILP (A5) on all instances <= 10^4 -- TESTS PROPOSITION 2",
    "AB-2": "Minimum segment granularity in {second, minute, hour} -- the OQ/overhead knob",
    "AB-3": "Edge binding on/off (= B4) -- isolates I-1",
    "AB-4": "Nesting on/off (flat vs laminar) -- isolates I-3; flat should degrade OQ toward B3",
    "AB-5": "Anchor placement P1/P2/P3/P4 -- which forgery classes each actually stops",
    "AB-6": "L4-LEAK TEST: re-run every algorithm with L4 (ground truth) inputs zeroed. "
            "Any metric that changes is a harness bug.",
    "AB-7": "Abstention disabled (force attribution over Q) -- what soundness costs in completeness",
}

# ------------------------------------------- 11.5 preregistered contrast set (6)
CONTRASTS = [
    ("C1", "HOMEPROV vs B2 on F_rep detection (S1,S2)", "THE CENTRAL CONTRAST"),
    ("C2", "HOMEPROV vs B3 on OQ (S3)",                 "THE HEADLINE NUMBER"),
    ("C3", "HOMEPROV vs B4 on F_rep detection",         "isolates edge binding (I-1)"),
    ("C4", "Composed vs best single class on SEV achieved, AT MATCHED b (S1)", "anti-triviality"),
    ("C5", "rho vs anchoring frequency f (Stage 3)",    "the cost/benefit curve"),
    ("C6", "BFP: HOMEPROV vs B2 (S6)",                  "usability"),
]

# ---------------------------------------------------------------- 2.2 lattice
OBSERVABILITY = {
    "L0": "rendered timeline UI(D) only            -- homeowner; used for Plaus",
    "L1": "L0 + full recorder database D           -- investigator AND adversary; B0,B1",
    "L2": "L1 + local anchor commitment log        -- VERIFY/LOCALIZE/RECONSTRUCT under P1/P2",
    "L3": "L2 + external anchor transcript         -- same, under P3",
    "L4": "L3 + ground truth trace and true T      -- EVALUATION HARNESS ONLY, never an algorithm",
}
L4_IS_ORACLE = True   # enforced by AB-6
