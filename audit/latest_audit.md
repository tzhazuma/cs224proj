# Latest result release audit

Generated: 2026-11-13T19:26:32.271459+00:00  
Overall: **PASS**  
Checks: 56 PASS, 0 FAIL, 0 WARN, 0 INFO (56 total).

Scope: read-only audit of the 2026-11-14 additions — `pair_debias` (6 runs, 1,080 records), `evidence_verify` (4 arms), `dynamic_enhanced` (test 140), `hybrid_dynamic_enhanced` (280 requests), `static_extended` CodeQL (200 units, test 140), `analysis/schema_recovery` (102 invalid repair records), the latest literature files and preservation of the old results. No model API was called; prompts, joins, hashes, costs and metrics were recomputed from stored artifacts.

## Must fix

- None.

## Warnings

- None.

## Publication note

These publication summaries still cite the pre-fix 52 PASS / 4 WARN audit (A6/E6/F4/G3). This run reports PASS with 56 PASS / 0 WARN / 0 FAIL; the publication pass must refresh these lines. The audit itself does not edit README.md or docs/.

- `README.md:16` — > **最新一轮审计：** [`audit/latest_audit.md`](audit/latest_audit.md)，**Overall `PASS_WITH_WARNINGS`：52 PASS / 0 FAIL / 4 WARN（56 checks，2026-11-14 最近重跑）**。0 FAIL 已满足发布门禁；4 个 WARN 为 A6（缓存复用披露）、E6（F1(V) 标注）、F4（schema 成本价卡）、G3（文献
- `README.md:569` — 27. **最新一轮尚未进入主 leaderboard，但已通过只读审计。** 2026-11-13/14 的实验默认都是单次运行；除 `schema_recovery` 外都有 API/工具调用。`benchmark/results/` 的主表仍只覆盖 v2/postleakfix 工作树；最新审计（[`audit/latest_audit.md`](audit/latest_audit.md)，2026-11-14 最近重跑）为 5
- `README.md:583` — | [`audit/latest_audit.md`](audit/latest_audit.md) | **最新一轮（2026-11-14 最近重跑）：Overall `PASS_WITH_WARNINGS`，52 PASS / 0 FAIL / 4 WARN；发布门禁通过**。4 个 WARN 为 A6/E6/F4/G3 |
- `docs/GITHUB_RELEASE.md:13` — - **审计分两代。** 旧一轮 `audit/final_audit.md`（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`**，只覆盖 v2/postleakfix 工作树；它**不含** 2026-11-13/14 的 `pair_debias`、`evidence_verify`、`dynamic_e
- `docs/GITHUB_RELEASE.md:43` — 审计分两代。旧一轮（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO**，Overall **`PASS_WITH_WARNINGS`**，must-fix 为空，只覆盖 v2/postleakfix。**最新一轮：[`audit/latest_audit.md`](../audit/latest_audit.md)，Overall `PASS_WITH_WARNIN
- `docs/GITHUB_RELEASE.md:73` — 当前 `audit/latest_audit.md` 的 `Overall` 是 **PASS_WITH_WARNINGS**、FAIL=0；A6/E6/F4/G3 是 WARN，不阻断发布但必须保留说明。发布前仍应重跑审计确认工作树未变。新目录的发布范围至少包括：`pair_debias/`、`evidence_verify/`、`dynamic_enhanced/`、`hybrid_dynamic_enhanced/`、`stati
- `docs/GITHUB_RELEASE.md:413` — - 审计 FAIL 未清零（最新一轮 `audit/latest_audit.md` 为 0 FAIL；A6/E6/F4/G3 是 WARN，需保留说明）。
- `docs/GITHUB_RELEASE.md:627` — - [x] 最新一轮审计 `audit/latest_audit.md` 已落盘，为 **PASS_WITH_WARNINGS**（52 PASS / 0 FAIL / 4 WARN，2026-11-14 最近重跑）；覆盖六个新结果组（pair_debias、evidence_verify、dynamic_enhanced、hybrid_dynamic_enhanced、static_extended、schema_recovery），
- `docs/REPRODUCIBILITY.md:219` — `audit/` 目前有两代只读审计。旧一轮 `audit/final_audit.md`（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`，must-fix 为空**，覆盖 v2/postleakfix 工作树；它**不含** 2026-11-13/14 的 `pair_debias`、`evidence_v
- `docs/REPRODUCIBILITY.md:632` — - [x] **最新一轮**审计已落盘（`audit/latest_audit.md`），为 **PASS_WITH_WARNINGS（52 PASS / 0 FAIL / 4 WARN，2026-11-14 最近重跑）**；覆盖六个新结果组：`pair_debias`、`evidence_verify`、`dynamic_enhanced`、`hybrid_dynamic_enhanced`、`static_extended`、`an
- `docs/REPRODUCIBILITY.md:705` — | 最新审计 | `audit/latest_audit.md`、`audit/latest_audit.json`（2026-11-14 最近重跑；`PASS_WITH_WARNINGS`：52 PASS / 0 FAIL / 4 WARN） |

## All checks

| ID | Area | Status | Check | Result |
| --- | --- | --- | --- | --- |
| A1 | pair_debias | **PASS** | Six complete runs, 1,080 records | Six runs x 180 = 1,080 records, all ok, no partial run. |
| A2 | pair_debias | **PASS** | Forward/reverse maps exact, 90/90 | Forward maps equal the pair_joint base; reverse maps are exact complements; 90/90. |
| A3 | pair_debias | **PASS** | DA reproduces per condition | DA reproduces per condition, analysis JSON, summary and report. |
| A4 | pair_debias | **PASS** | Exchange consistency reproduces | Exchange-consistency DA, semantic agreement, same-letter rate and the 74.44% / 72.22% length baselines all reproduce. |
| A5 | pair_debias | **PASS** | Prompts are metadata/slot-free | All 1,080 prompts are metadata/slot-free outside code; only the documented CVE-2017-17969 comment remains in one pair's body. |
| A6 | pair_debias | **PASS** | Cache/checkpoint and resume are consistent | 1,080 stored records = 1,029 newly issued requests + 51 cached responses from test_mimo_open_rev; cache keys equal request fingerprints and README/report both state the split (129 newly issued requests for the resumed run). |
| A7 | pair_debias | **PASS** | Configured cost recomputes | New $0.676605; reused $0.225396; all-in $0.902001. |
| A8 | pair_debias | **PASS** | Manifests, hashes and credentials are clean | Six manifests complete/unpartial; dataset hash frozen; keys never stored; Authorization omitted. |
| B1 | evidence | **PASS** | Four arms complete at 60/60/58/58 | Arms complete at 60/60/58/58 planned records; verifier-invalid records are 0/2/1/0 and are handled fail-closed. |
| B2 | evidence | **PASS** | First-pass metrics reproduce | First-pass metrics reproduce (DeepSeek 159 valid + 1 invalid, MiMo 158 + 2). |
| B3 | evidence | **PASS** | Fail-closed post metrics reproduce | Fail-closed post metrics and retraction precision reproduce; negatives and pre-invalid rows are untouched. |
| B4 | evidence | **PASS** | Exact McNemar reproduces | Exact McNemar pre-vs-post reproduces for all four arms. |
| B5 | evidence | **PASS** | Prompts rebuild and stay label-free | All 236 verifier prompts rebuild byte-identically; wrapper has no label/project/path field. |
| B6 | evidence | **PASS** | Cache has no hits or cross-arm reuse | All 236 records have their own cache entry, zero hits and no cross-arm key reuse. |
| B7 | evidence | **PASS** | Verifier cost recomputes | Verifier cost totals $0.154333. |
| B8 | evidence | **PASS** | Post-hoc status is disclosed | Exploratory/post-hoc status and fail-closed/fail-open policies are explicit. |
| C1 | dynamic | **PASS** | Test140 units and labels match the freeze | 140 frozen test units, 70/70, exactly matching juliet/subset_units.jsonl. |
| C2 | dynamic | **PASS** | Confusion is 70/0/70/0 | 70 TP / 0 FP / 70 TN / 0 FN; coverage 1.000 and no undecided unit. |
| C3 | dynamic | **PASS** | Per-mode evidence and 12 new units are exact | Mode counts 58/7/63; the 12 newly observable units are exactly 7 realloc-fail + 5 no-global and attribute to their own sources. |
| C4 | dynamic | **PASS** | No failures or undecided units | No compile failure, timeout or undecided unit; verify.json and the build/run checks are clean (the failure map only contains leak/clean decisions). |
| C5 | dynamic | **PASS** | Default mode reproduces old ASan | Default mode agrees with the frozen old ASan run 140/140; old observable bad units remain 58/70. |
| C6 | dynamic | **PASS** | No API/model usage | Local tool run: no network/API client import and no model field in the results. |
| C7 | dynamic | **PASS** | README ceiling claims match rows | README ceiling 70/0/70/0, 12/12 new evidence and 0/70 good FPs match the rows. |
| D1 | hybrid | **PASS** | Two complete 140-unit runs | Two complete 140-unit runs, all ok/valid, zero API errors (280 requests). |
| D2 | hybrid | **PASS** | HDE accuracy reproduces | HDE confusion and accuracy reproduce (DeepSeek 137/140, MiMo 136/140). |
| D3 | hybrid | **PASS** | Paired McNemar contrasts reproduce | Paired counts, exact p-values and deltas reproduce for all four baselines. |
| D4 | hybrid | **PASS** | Prompts rebuild and stay sanitized | All 280 guided prompts rebuild byte-identically (140 unique); direct equals hybrid v2; evidence blocks are label/path/CWE-free. |
| D5 | hybrid | **PASS** | Evidence matches the dynamic modes | Enhanced evidence matches the dynamic mode decisions, has 13 distinct texts and covers the 12 new units. |
| D6 | hybrid | **PASS** | 280-request cost and smoke split | 280 requests cost $0.023561; two smoke calls add $0.000087716 (all-in $0.023648). |
| D7 | hybrid | **PASS** | Frozen v2 baselines are read-only | Frozen v2 baselines predate the new run; the v2 input pack hash still matches 1ec51f57... |
| D8 | hybrid | **PASS** | Copying caveat and flips reproduce | Tool agreement and flips vs v2 direct reproduce; the report refuses a semantic-reasoning claim. |
| E1 | codeql | **PASS** | 200 units/splits/labels match the freeze | 200 unique frozen units (100/100; test 140 / dev 60); input hash matches the Juliet freeze. |
| E2 | codeql | **PASS** | 194 ok / 6 compile_error, all documented | 194 ok / 6 compile_error; all six are _82 (4 test, 2 dev); no timeout or tool error. |
| E3 | codeql | **PASS** | Test140 confusion and metrics reproduce | Test140 end-to-end 68/23/47/2, evaluable 68/23/45/0; F1(V) 0.8447, macro-F1 0.8173, MCC 0.6739. |
| E4 | codeql | **PASS** | Per-query counts and 132 diagnostics | Per-query counts reproduce; 132 raw diagnostics, all in target files. |
| E5 | codeql | **PASS** | Output hashes and raw artifacts intact | Manifest output hashes match; 194 SARIF files and 6 compile-error stderr logs are present. |
| E6 | codeql | **PASS** | Clang/Cppcheck comparison; F1 caveat | Baselines and coverage gains reproduce (15 Clang-missed bad units recovered, no Clang positive missed, all 23 FP are C++). static_extended/README.md now labels both positive-class F1(V) (0.8447 vs Clang 0.8618) and Macro-F1 (0.8173 vs 0.8768), names Macro-F1 as the project primary endpoint and states the two are not i… |
| E7 | codeql | **PASS** | No API use and no Juliet modification | Local CodeQL run; the Juliet subset hash is unchanged and no model/API field is present. |
| E8 | codeql | **PASS** | Limitations are disclosed | README documents single-TU databases, compiler differences, compile errors and tools not run. |
| F1 | schema | **PASS** | 12 old runs are hash-identical | All 12 legacy result/config/metrics hashes match; 36 hashes verified, no old run rewritten. |
| F2 | schema | **PASS** | 102 invalid split 93 + 9 | 102 invalid split exactly into 93 missing-explanation (stop, fixed_function present) and 9 truncations (length, unparseable). |
| F3 | schema | **PASS** | Strict/code-only/usable totals reproduce | Official 822/924 (88.96%), code-only 915/924 (99.03%), usable 552→619 (+7.25 pp); salvage 67/69. |
| F4 | schema | **PASS** | Invalid costs recompute; price basis flagged | Both schema cost bases are present and reconcile exactly with analysis/cost_normalization.json: configured-peak cache-aware $2.521790096 (4,968 records) = legacy_test.configured_cache_aware_usd; off-peak list $1.572472286 = legacy_test.normalized_list_usd, delta $0 on both. The 102 invalid records also recompute at $0… |
| F5 | schema | **PASS** | MiMo 61/61 field drift reproduces | 61/61 drift remappable; 5 true / 56 false; 28/61 label agreement; 60+1 alias split with one both-key record. |
| F6 | schema | **PASS** | Zero API/network calls | Read-only replay: no network import and api_calls=0 in scope and sources. |
| F7 | schema | **PASS** | L0/non-accuracy caveats present | README states L0 (no compile/test/PoC), separates official/code-only and treats truncation as fatal. |
| F8 | schema | **PASS** | README rates match the JSON | All headline schema rates/denominators match the JSON and 924/102/93/9 counts. |
| G1 | literature | **PASS** | Latest literature files and index exist | Three research/latest_*.md files and docs/LITERATURE.md exist and are non-trivial. |
| G2 | literature | **PASS** | Reference sections and schema citations resolve | Reference sections exist and every schema_recovery letter-numbered citation resolves in latest_llm_methods. |
| G3 | literature | **PASS** | Snapshots are stale on the new experiments | Both research/latest_*.md files carry the 2026-11-14 dated status note. It scopes the original 2026-11-13 text as writing-time, lists schema recovery, pair_debias, evidence_verify, dynamic_enhanced, hybrid_dynamic_enhanced and CodeQL as completed, and says the historical body is intentionally unchanged (so the old '未实… |
| G4 | literature | **PASS** | Index maps the new groups | docs/LITERATURE.md maps all six new result groups to their literature basis and limitations. |
| H1 | preserve | **PASS** | Legacy results predate all new experiments | Newest legacy artifact audit/final_audit.md at 2026-11-11T21:58:24.203676+00:00 predates the first new run; final_audit.* untouched. |
| H2 | preserve | **PASS** | Frozen inputs and legacy hashes unchanged | Frozen Juliet, both splits, the hybrid v2 pack and all 12 legacy result files still match their recorded hashes. |
| H3 | preserve | **PASS** | New artifacts contain no credentials | Scanned 5404 text artifacts in the six new directories; no credential-like string found. |
| H4 | preserve | **PASS** | Only the two latest_audit files are written | Only audit/latest_audit.json and audit/latest_audit.md are written; final_audit.* is untouched. |
| H5 | preserve | **PASS** | Audit itself is offline | The audit script is offline; it only reads stored artifacts. |

## Reading notes

- **Cost bases differ.** `pair_debias`/`evidence_verify` use configured DeepSeek $0.30/$1.20/$0.006 and MiMo $0.14/$0.28/$0.0028; `hybrid_dynamic_enhanced` uses $0.15/$0.60/$0.003 for DeepSeek; `schema_recovery` calls its cache-aware configured-card number `normalized`, which is not the off-peak `normalized` card in `analysis/cost_normalization.md` (F4).
- **Records vs new calls.** `pair_debias` stores 1,080 records but issued 1,029 new API calls: `test_mimo_open_rev` resumed from 51 cached responses after an interrupted first attempt. `report.md` discloses the 51/129 split; A6 keeps it visible.
- **Tool ceilings are not model results.** `dynamic_enhanced` and the HDE tool are 70/0/70/0; the model rows are 137/140 and 136/140 and no semantic-reasoning improvement is claimed.
- **Post-hoc is not confirmation.** `evidence_verify` is exploratory on a test split already seen; `pair_debias` length matching is a post-hoc subset; `schema_recovery` salvage is an L0 structural proxy.
- **Out of scope.** `benchmark/extensions`, `report/`, `README.md` and git/gh operations are owned by the publication pass and were not modified.

## Files written

- `audit/latest_audit.json`
- `audit/latest_audit.md`

Reproduce with `python3 audit/run_latest_audit.py` (read-only; no network).
