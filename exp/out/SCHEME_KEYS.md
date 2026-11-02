# Artifact scheme keys → manuscript labels

The commitment schemes have one name in the code and result files and another in the paper. The keys below are the ones
`exp/rig/commit.py` defines and `exp/out/stage31_hp2.json` records (its `note` field states the same mapping).

| artifact key | manuscript label | what it commits (per `exp/rig/commit.py`) |
|---|---|---|
| `b2c` | Closure | the renderer closure: the fourteen recorder fields the logbook processor was measured to read, including the user column, `old_state_id` and `last_changed_ts` |
| `row` | Row | a chosen subset of the stored row: node key, content, context id, parent id, label. It omits the user column, `old_state_id` and `last_changed_ts`; it is **not** the whole physical row |
| `homeprov2` | Graph | graph-shaped commitment with the node's own key bound (the FT-6 node-key fix) |
| `b2` | Content-only (Cnt) | content only; excludes the context columns |
| `homeprov` | Gr⁻ | the graph scheme **before** the node-key fix; superseded |
| `b2b` | — (not reported) | content, context id, parent id and label, without the node key |
| `b4` | — (not reported) | the graph scheme with edge binding disabled (self-baseline) |
| `b2c_v2`, `row_v2` | — (round-6 check only) | the Closure and Row fields with the typed, length-prefixed node encoding v2 of monitor/monitor.py; exp/out/r6_rig_v2_paired.json |

The **whole-row** scheme of the paper (every stored column of the row) has no rig key: it is the deployed variant
`monitor/monitor_wholerow.py`, run only on the real deployment. The deployed monitor `monitor/monitor.py` runs the closure
scheme by default (`HOMEPROV_SCHEME=closure`) and the row scheme when `HOMEPROV_SCHEME=row`; every anchored payload records
its scheme.

Cross-check against `exp/out/stage31_hp2.json` (12 generated deployments per class, detected deployments):

| class | `b2c` = Closure | `row` = Row | `homeprov2` = Graph | `b2` = Cnt | `homeprov` = Gr⁻ | `b2b` |
|---|---|---|---|---|---|---|
| FT-4 | 12/12 | 12/12 | 12/12 | 0/12 | 12/12 | 12/12 |
| FT-5 | 12/12 | 12/12 | 12/12 | 0/12 | 12/12 | 12/12 |
| FT-6 | 12/12 | 12/12 | 12/12 | 11/12 | 11/12 | 12/12 |
| FT-U | 12/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 |
| FT-E | 12/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 |

`strict_separations` in the same file: `b2c>row` 24 and `b2c>homeprov2` 24 (the two closure-only classes, 12 deployments
each); `homeprov2>row` 0; `b2b>homeprov` 1 (FT-6, the node-key fix).

An earlier version of this file mislabeled the Graph and Row keys; the table above is the corrected mapping.
