# Artifact scheme keys → manuscript labels

The commitment schemes are named differently in the artifacts and in the paper.
**The artifact key `homeprov` is NOT the recommended scheme.** It is the graph
scheme *before* the node-key fix — the paper's `Gr⁻`. A reader who opens
`stage31_b2c.json`, greps for the system's own name and finds `homeprov: 11/12`
on FT-6 will wrongly conclude the paper's "Graph and Row are identical on all
twelve classes" is false.

| artifact key | manuscript label | what it commits |
|---|---|---|
| `b2b` | `Graph` | graph-shaped commitment, parent-identity and node-key omissions closed |
| `row` | `Row` | the whole physical recorder row |
| `b2`  | `Cnt` | content-only; the original record-level baseline, excludes the context columns |
| `homeprov` | `Gr⁻` | the graph scheme **before** the node-key fix — superseded |
| `b2c` | — | intermediate variant, not reported in the paper |

Cross-check on FT-6 (`exp/out_recal/stage31_b2c.json`), the class that separates them:

| | `b2b`=Graph | `row`=Row | `b2`=Cnt | `homeprov`=Gr⁻ |
|---|---|---|---|---|
| artifact | 12/12 | 12/12 | 11/12 | 11/12 |
| Table 2 | 12/12 | 12/12 | 11/12 | 11/12 |

`strict_separations` in the same file reads `"b2b>homeprov": 1` — one class on
which the fixed graph scheme strictly beats the pre-fix one. That is the FT-6
node-key fix the paper describes, stated in artifact keys.
