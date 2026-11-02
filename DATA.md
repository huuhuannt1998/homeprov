# DATA.md: files held out of this repository

This repository leaves out every file of the artifact at or above 50 MB (GitHub refuses files over 100 MB and warns above 50 MB). The 10 files below, 3,478,624,754 bytes in all, go into a data bundle on Zenodo (https://doi.org/10.5281/zenodo.23874619). Each belongs at the path given, relative to the repository root. Nothing else was left out for size; the code, the documents and every other result file are here.

To check a downloaded file, place it at its path and run, from the repository root:

```bash
shasum -a 256 -c DATA.sha256     # or: sha256sum -c DATA.sha256
```

with `DATA.sha256` holding the block at the end of this file.

## The files

| Path | Bytes | sha256 | Float source of the paper | NUMBERS.md rows | What it is |
|---|---:|---|---|---:|---|
| `exp/out/e10_main_e10s_copy_chain.jsonl.gz` | 91,391,072 | `5d1c09317224157fb81892a53397120709db30eb061eb79957e3720895a39be1` | no | 0 | E10's main scratch stack (e10s), copy monitor's anchor chain. |
| `exp/out/e10_main_e10s_direct_chain.jsonl.gz` | 91,484,045 | `4de782e09dc6796cc23317b53e0a31acbd38a631bb21b56a2e589bf035920072` | no | 0 | E10's main scratch stack (e10s), direct-read monitor's anchor chain. |
| `exp/out/e10b_main_e10bs_copy_chain.jsonl.gz` | 77,214,632 | `28530102629f0c3483d431454cca489e5664e7690b9b27a2adde5979f7da7436` | no | 0 | E10b's scratch stack (e10bs), copy monitor's anchor chain. |
| `exp/out/e10b_main_e10bs_direct_chain.jsonl.gz` | 77,239,251 | `fd375fe3880ad39280e89a9cb9d00561ccf4fa5982100b727e46f951026a9930` | no | 0 | E10b's scratch stack (e10bs), direct-read monitor's anchor chain. |
| `exp/out/e12_main_copy_chain.jsonl.gz` | 91,931,692 | `86494c1fa08d21b97a0f1ae90cddb2d9ee85b0b57bedd4f5a0d6b010882346f8` | yes | 0 | E12's anchor chain, copy monitor. |
| `exp/out/e12_main_direct_chain.jsonl.gz` | 92,696,813 | `843da57c1315610cc13a6dbf019a3c4acb12fad7afdfd50495af267ee32dedc9` | yes | 0 | E12's anchor chain, direct-read monitor. |
| `exp/out/e12_main_score.json` | 90,961,983 | `851efccda08f6bc504584eb8770537dd3ef37058ea48bb759f6855e770792ce1` | yes | 15 | E12's scorer output. Table S6 prints `851efccda08f`; this copy is byte for byte. |
| `exp/out/e9_main2_copy_chain.jsonl.gz` | 123,159,948 | `de0f347c89d0aa116eca4849829368f1667557da067378d555ce5b218ba7829c` | yes | 0 | E9's anchor chain, copy monitor. |
| `exp/out/e9_main2_direct_chain.jsonl.gz` | 124,961,582 | `4d5b8384df3605358320128d6ac9f5dd38cc7735d5dd60be73f5d23209cbda85` | yes | 0 | E9's anchor chain, direct-read monitor. |
| `exp/out/e9_main2_score.json` | 2,617,583,736 | `dd0dda21a7b55dcb5fe11cf0699504b68305a6d703fff47d01565150371ae657` | yes | 0 | E9's frozen scorer output (2.6 GB). Table S6 prints `3b41e792c1cc`, the digest of the file as scored; this copy differs from it only in one rewritten machine path (`reproduce/SANITIZED_r16.json`, `files`). `exp/out/r16_e9_score_compact.json`, in this repository, is the compact copy the round-16 analyses read; `exp/sp2027/r16_e9_score_compact.py` rebuilds it from this file. |

The digests are of the released copies, as `reproduce/SANITIZED_r16.json` (`files`, `sha256_after`) records them. Only `e9_main2_score.json` was changed by the release rules (one machine path, rewritten as described in README.md, "Anonymization"); its digest as scored was `3b41e792c1cc831cc5626b6e56005f46f25827349a1ca3a800c5ba3e92ec2320`.

## What needs them

None of the commands in README.md, "Re-verifying the reported numbers", reads a held-out file: `verify_all.py`, `recount_floats.py`, `verify_e7e8.py`, the pytest suites, `r6_reverify_v2.py`, `r2_localize.py` and `r10_coarse_roots.py` run on this repository alone. These steps need the bundle:

- **Float-source check (B9-style).** The paper's float manifest hashes 200 source files; six of them are here only on Zenodo: `e9_main2_score.json`, `e9_main2_direct_chain.jsonl.gz`, `e9_main2_copy_chain.jsonl.gz`, `e12_main_score.json`, `e12_main_direct_chain.jsonl.gz`, `e12_main_copy_chain.jsonl.gz`. Compare each with the digest above, or place it and compare as for the other sources.
- **Table S6's result-file prefixes** for E9 (`3b41e792c1cc`, the file as scored; see above) and E12 (`851efccda08f`).
- **The NUMBERS.md rows licensed by `e12_main_score.json`** (E12's day counts, purge nights, keep days, seal delay and poll cost; 15 rows).
- **Rebuilding `exp/out/r16_e9_score_compact.json`** with `exp/sp2027/r16_e9_score_compact.py`, which reads `e9_main2_score.json`. The compact copy itself is in this repository and is what the round-16 analyses and NUMBERS.md read.
- **Reading the E9, E10, E10b and E12 anchor chains** (records, links, roots). Re-running those runs' verifiers also needs their run directories, which are not released, and checking their signatures needs public keys, which are not released either (the configs carry the key fingerprints).

## Withheld until 25 January 2027 (coordinated disclosure)

These files are part of the artifact but are not published before 25 January 2027. They implement or describe, step by step, issues reported privately on 27 October 2026 to Home Assistant (the post-commit attribution rewrite and the Marketplace/community-store delivery path) and to the Domoticz maintainers (a post-commit rewrite of a device log row's user column). The paper describes these issues at the level it needs. Each file will be published at its path; until then its digest lets anyone check the later copy.

| Path | Bytes | sha256 | What it is |
|---|---:|---|---|
| `testbed/domoticz/harness/dz_arms.py` | 13,861 | `e76df9c6a89588613b83215b8cd5b2653a585049efb89dc00fafc910ffc0dc1e` | Domoticz arm driver: the plugin's edit steps (report to the Domoticz maintainers) |
| `exp/sp2027/r1_laundering_render.py` | 12,522 | `be821edea5f1735b68b0227ddfb2953cdb34216a7834ff052088c0bd702fc4f4` | laundering, rendered (Home Assistant attribution rewrite) |
| `exp/sp2027/r2_laundering_render.py` | 14,717 | `6a5df020e96ac6c702c0ee90b33b9d4499afee5b349a1176b35c8bbd65b04dc8` | laundering, rendered, release stacks (attribution rewrite) |
| `exp/sp2027/r1_memberswap_render.py` | 13,656 | `c8529ec7fae2d7c4157e55c72f01bde8eaaf42451e77dc32422a394e872fb93d` | member-account swap, rendered (attribution rewrite) |
| `exp/sp2027/r2_memberswap_render.py` | 12,720 | `94cf3228e5bc0a5381d4b0f24dce04eb3f8caeb81f59cc24ea1f8027bbc8548d` | member-account swap, rendered, release stacks (attribution rewrite) |
| `exp/sp2027/r1_render_measure.py` | 9,460 | `7a493799b46a3d833348f169700883763762358772477c2576692d4e0a80d07e` | member-account and random-id swaps, rendered (attribution rewrite) |
| `exp/sp2027/r1_laundering_trace.py` | 8,704 | `e4feef0e455c75beadf558b11ee19b30a26bd181308cbb349d106c8806c1b0ef` | laundering, Details chain and trace cross-check (attribution rewrite) |
| `exp/sp2027/r7_marketplace_delivery.py` | 9,020 | `2f31cc8ef5bb898dc2ef9e8cdb45c617e9b0238bd37ed0c39086d50e162e4946` | Marketplace delivery path, orchestrator (delivery-path report) |
| `exp/sp2027/r7_container_driver.py` | 9,693 | `f0f60a38cdc440d9eefd2ad6bdceb3c303eb86876637dd2645a3bdc933fe5217` | Marketplace delivery path, in-container driver (delivery-path report) |
| `exp/out/r7_marketplace_delivery.json` | 3,557 | `2ad3920bc308c69748be838d4e08ae7fe55ee45d52e2a4cab6a82c8eae3f2012` | Marketplace delivery path, result (delivery-path report) |
| `testbed/ha-config/custom_components/homeprov_e5/__init__.py` | 23,860 | `ff317b3d815cdf2c960e5213b017d03788ce8c35801d9479493b200003cbb743` | renderer-backed attack harness (attribution rewrite) |
| `testbed/ha-config/custom_components/homeprov_e5/manifest.json` | 275 | `bfa7e1f1f82639cd522d4a9b8cd62805cd51cd6b74da6a8e7ce6ba4b413a54da` | its manifest |
| `testbed/real/ha-config/custom_components/homeprov_e5/__init__.py` | 51,065 | `8ac203d314a8fb238bdd0a713e6e2443f179a20f3f7828fe5edfe9d019b3b0b0` | renderer-backed attack harness, real substrate (attribution rewrite) |
| `testbed/real/ha-config/custom_components/homeprov_e5/manifest.json` | 275 | `bfa7e1f1f82639cd522d4a9b8cd62805cd51cd6b74da6a8e7ce6ba4b413a54da` | its manifest |
| `results/S1_laundered_unlock.md` | 7,807 | `9660e0ebb4e3137a67b645385f3da2bd5fdc792bffc7b50d69e106bf4d460d17` | the laundered-unlock write-up (attribution rewrite) |
| `results/bundles/u_res_forgery.json` | 32,977 | `d9dbc329f53885d39efd05879abfc49a01af68027abac28acbd15862f9706869` | result bundle that embeds the write-up above |

None of these files is a float source of the paper, and no NUMBERS.md row cites one. The result files they produced are here: the render scripts' (`exp/out/r1_*`, `exp/out/r2_2026.*_render.json`) and `homeprov_e5`'s (for example `exp/out/e5_real_multiconfig.json`); no script that remains reads a withheld file. Without `homeprov_e5`, the arms that call it (`testbed/real/run_experiments.sh`, `witness/e3_broker_witness.sh`) do not run, and the testbed configurations that list it (`testbed/real/ha-config/configuration.yaml`, `testbed/ha-config/configuration.example.yaml`) log a missing integration for that one entry.

## Withheld until 28 January 2027 (coordinated disclosure)

These files read Home Assistant Supervisor's documentation and source for the routes by which code in the hub process reaches an add-on's placement on Home Assistant OS and Supervised installs (the paper's Table S9). They go beyond the paper's table. They describe an issue reported privately to Home Assistant on 30 October 2026, and are not published before 28 January 2027.

| Path | Bytes | sha256 | What it is |
|---|---:|---|---|
| `exp/stages/e_e_supervisor_reach.py` | 21,918 | `d66ed47abae083b25f2ffdef6648b3864e3f58e4ae2fddd7867a2f0ef18b213d` | Supervisor-token routes: source and documentation reading |
| `exp/out/e_e_supervisor_reach.json` | 17,048 | `f4d93949382f16d297365aa5830f7310dcb757740fb0ea9aefefa7e2f5a4aeed` | its result; a float source of the paper (Table S9) |

`exp/out/e_e_supervisor_reach.json` is a float source of the paper (Table S9), and NUMBERS.md row SI-S088-01 (`2026.09`, the pinned Supervisor release) cites it. A float-source check run on this repository finds it absent: it is withheld, not missing, and the digest above identifies the copy to be published. The other 199 float sources are here or, for six, in the Zenodo bundle.

## DATA.sha256

```
5d1c09317224157fb81892a53397120709db30eb061eb79957e3720895a39be1  exp/out/e10_main_e10s_copy_chain.jsonl.gz
4de782e09dc6796cc23317b53e0a31acbd38a631bb21b56a2e589bf035920072  exp/out/e10_main_e10s_direct_chain.jsonl.gz
28530102629f0c3483d431454cca489e5664e7690b9b27a2adde5979f7da7436  exp/out/e10b_main_e10bs_copy_chain.jsonl.gz
fd375fe3880ad39280e89a9cb9d00561ccf4fa5982100b727e46f951026a9930  exp/out/e10b_main_e10bs_direct_chain.jsonl.gz
86494c1fa08d21b97a0f1ae90cddb2d9ee85b0b57bedd4f5a0d6b010882346f8  exp/out/e12_main_copy_chain.jsonl.gz
843da57c1315610cc13a6dbf019a3c4acb12fad7afdfd50495af267ee32dedc9  exp/out/e12_main_direct_chain.jsonl.gz
851efccda08f6bc504584eb8770537dd3ef37058ea48bb759f6855e770792ce1  exp/out/e12_main_score.json
de0f347c89d0aa116eca4849829368f1667557da067378d555ce5b218ba7829c  exp/out/e9_main2_copy_chain.jsonl.gz
4d5b8384df3605358320128d6ac9f5dd38cc7735d5dd60be73f5d23209cbda85  exp/out/e9_main2_direct_chain.jsonl.gz
dd0dda21a7b55dcb5fe11cf0699504b68305a6d703fff47d01565150371ae657  exp/out/e9_main2_score.json
```
