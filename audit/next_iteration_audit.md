# Next-iteration release audit (2026-11-22)

Generated: 2026-11-23T04:11:06.850902+00:00  
Overall: **PASS_WITH_WARNINGS**  
Checks: 40 PASS, 0 FAIL, 1 WARN, 0 INFO (41 total).

Scope: read-only audit of the 2026-11-22 next-iteration results — `codeql_triage` (test 140, 23 CodeQL FPs, TP-deletion audit), `pair_diff` (8 full runs / 1,440 records), `verifier_conservative` (4 arms / 236 requests), `dynamic_coverage` (140 units x 3 modes) and `interpretable_baseline` (dev40 -> test160 isolation), plus prompt leakage, cost, preservation of the older results and report/benchmark consistency. No model API was called; prompts, joins, hashes, costs and metrics were recomputed from stored artifacts.

## Must fix

- None.

## Warnings

- **E5 — Pre-registration timestamp is not verifiable**: README claims the method was pre-registered before the test run, but its mtime is 40.8s after metrics.json; pre-registration cannot be verified from the artifacts. The selected rule and thresholds are nevertheless dev-only.

## All checks

| ID | Area | Status | Check | Result |
| --- | --- | --- | --- | --- |
| A1 | codeql_triage | **PASS** | Frozen test140 dataset and CodeQL status | 140 frozen units (70 bad / 70 good; C 58 / C++ 82); 136 analyzable, 4 _82 compile errors; hashes match. |
| A2 | codeql_triage | **PASS** | CodeQL confusion and metrics | CodeQL test140 confusion 68 TP / 23 FP / 47 TN / 2 FN; macro-F1 0.8173, MCC 0.6739; export matches. |
| A3 | codeql_triage | **PASS** | 23 FPs are one query and four C++ variants | All 23 CodeQL FPs are C++ good units on cpp/memory-may-not-be-freed (33:15, 22:3, 72:3, 54:2); never-freed has 0 FP. |
| A4 | codeql_triage | **PASS** | TP deletion: v1 7, v2/verified 0 | v1 deleted 7 CodeQL TPs, all malloc_realloc may-query units; v2 and the verifier deleted 0/68. |
| A5 | codeql_triage | **PASS** | v2 and verifier metrics reproduce | v2 one-shot 68/3/67/2 (0.9643); verifier flips exactly 3 _22 goods to 68/0/70/2 (0.9857, MCC 0.9718); no TP broken. |
| A6 | codeql_triage | **PASS** | Request counts, statuses and re-parsed units | 140 direct + 140 triage + 91 verify requests; 2 triage outputs re-parsed under the clarified schema; final coverage 140/140. |
| A7 | codeql_triage | **PASS** | Prompt leakage and credential hygiene | 280 stored first-pass prompt bodies contain no unit_id/group_id/CWE/label/path token; 91 verify prompts are distinct and the builder applies the same audit_prompt (verify bodies were not retained). |
| A8 | codeql_triage | **PASS** | Configured-price cost recomputes | Configured-price cost: direct $0.003021 + triage $0.030545 + verify $0.012229 = $0.045795. |
| A9 | codeql_triage | **PASS** | benchmark_export matches per-unit records | Export reproduces all 9 conditions from per-unit records; REPORT.md carries the same key numbers. |
| B1 | pair_diff | **PASS** | Frozen 180-pair dataset | Frozen 180-pair test split; SHA-256 matches every manifest; 180 unique pair ids with both versions. |
| B2 | pair_diff | **PASS** | 8 full runs x 180 = 1,440 records | 8 full runs x 180 = 1,440 records, all ok, no partial/limit; 8 pilot runs (64 records) kept separate. |
| B3 | pair_diff | **PASS** | 0 invalid; 2 schema-inexact disclosed | 0 invalid by decision validity (1,440/1,440 valid, 0 parse errors, 0 status errors); 2 outputs have an extra note key and are disclosed as 99.44% schema-exact. |
| B4 | pair_diff | **PASS** | Position maps are balanced and complemented | Every run has 180 assignments with 90/90 slot balance; reverse maps are exact complements; map and base hashes match. |
| B5 | pair_diff | **PASS** | Per-run DA reproduces | Per-run DA reproduces for all 8 runs (DeepSeek 68.33/70.56/68.89/69.44; MiMo 68.33/66.67/66.11/69.44). |
| B6 | pair_diff | **PASS** | Exchange-consistent DA reproduces | Exchange-consistent DA reproduces: DeepSeek diff 62.22% / ctrl 60.00%; MiMo diff 60.56% / ctrl 62.22%. |
| B7 | pair_diff | **PASS** | Prompt/slot leakage audit | All 8 leak audits are wrapper-clean and slot-clean; 180/180 diff directions A->B. The only body hits are source content: a CVE-2017-17969 comment (disclosed) and the identifier __func_name_from_ord, not the dataset func_name field. |
| B8 | pair_diff | **PASS** | Cost and token totals recompute | New runs cost $1.156871 (4,366,678 prompt / 453,037 completion tokens); open baseline reuses 720 pair_debias records ($0.304602 + $0.145586). |
| B9 | pair_diff | **PASS** | benchmark_export matches all conditions | benchmark_export reproduces all 12 conditions (DA, committed DA, abstention, cost); the unified report table matches. |
| C1 | verifier_conservative | **PASS** | Four arms, 236 first-pass positives | Four arms on first-pass positives: 60/60/58/58 = 236 requests; labels are 49 V / 11 NV per 60 arm and 47 V / 11 NV per 58 arm. |
| C2 | verifier_conservative | **PASS** | Statuses and fail-open handling | 233 ok / 2 invalid / 1 API error; all three failures keep the first-pass prediction (fail-open), not retract. |
| C3 | verifier_conservative | **PASS** | Retraction count and composition | 4/236 retractions (TP 3 / FP 1), precision 25.0%; all are grounded unsupported decisions; insufficient never retracts. |
| C4 | verifier_conservative | **PASS** | Verifier cost recomputes | Verifier cost recomputes to $0.151758 across 235 priced requests; the single API error has no usage and is not imputed. |
| C5 | verifier_conservative | **PASS** | Dry-run body hashes and isolation audit | All 236 real request bodies hash-match their dry runs; isolation violations 0; keys and Authorization never stored. |
| C6 | verifier_conservative | **PASS** | Prompt exposes only source and claim | 236 verifier prompts expose only func_body + claim evidence lines/mechanism; no sample id, commit or path; template forbidden-token list is empty. |
| C7 | verifier_conservative | **PASS** | Report and metrics agree | Report matches metrics: 4/236, precision 25.0%, macro-F1 deltas 0 to -0.0052, MCC +0.0139 only on mimo_cross; post-hoc/test-seen status explicit. |
| D1 | dynamic_coverage | **PASS** | 140 units x 3 modes, no coverage errors | 140 units x 3 modes = 420 runs; 70/70 labels; 0 compile/coverage errors; entry executed 140/140. |
| D2 | dynamic_coverage | **PASS** | Default vs union confusion and classes | Default path 58 TP / 0 FP / 70 TN / 12 FN; three-mode union 70 TP / 0 FP / 70 TN / 0 FN; 12 default cleans are bad. |
| D3 | dynamic_coverage | **PASS** | Line/branch coverage and latent FNs | Effective line coverage 100%, branch 52.7%, 21 branch-complete units all bad; the 12 default FNs split 7 realloc_fail + 5 nogobal and are all line-complete. |
| D4 | dynamic_coverage | **PASS** | verify.json and archived agreement | verify.json PASS, 0 problems, selftest PASS; default and union decisions agree with dynamic_enhanced 140/140. |
| D5 | dynamic_coverage | **PASS** | No model/API usage | Coverage tool imports no network/model client; raw records contain no model or API-key field. |
| E1 | interpretable_baseline | **PASS** | dev40/test160 isolation is exact | dev40/test160 isolation: idx, project, function-body MD5 and project+commit overlap all 0; both split hashes match. |
| E2 | interpretable_baseline | **PASS** | Feature and prediction record counts | 200 feature rows (40 dev / 160 test) and 1,800 predictions (9 methods x 200); all predictions binary. |
| E3 | interpretable_baseline | **PASS** | Thresholds and rule selection are dev-only | Thresholds are dev-only (chars 1504, calls 16, positive rate 0.8); length_short is the best of 7 rules on dev (0.4505 vs 0.4444). |
| E4 | interpretable_baseline | **PASS** | test160 metrics reproduce | test160: length_short 75/15/17/53, macro-F1 0.5107, MCC 0.0945; majority 0.4444; alloc_or_mem MCC 0.1833; 8 LLM runs 0.3456-0.4223. |
| E5 | interpretable_baseline | **WARN** | Pre-registration timestamp is not verifiable | README claims the method was pre-registered before the test run, but its mtime is 40.8s after metrics.json; pre-registration cannot be verified from the artifacts. The selected rule and thresholds are nevertheless dev-only. |
| E6 | interpretable_baseline | **PASS** | No model/API usage | run_baseline.py imports no network/model client and contains no api_key/model-client reference. |
| F1 | cross | **PASS** | Old results and frozen hashes are preserved | Old audit files and six frozen hashes are unchanged; old result counts still 1,080 pair_debias / 236 evidence / 140 dynamic / 280 hybrid / 200 static; the sampled old artifacts predate 2026-11-22. |
| F2 | cross | **PASS** | Unified report matches the audited numbers | Unified report and TeX carry the audited CodeQL, pair, conservative, coverage and interpretable numbers; the PDF exists. |
| F3 | cross | **PASS** | Benchmark aggregate/README refreshed | All 30 batch outputs exist; benchmark/results/next_iteration_summary.json (2026-11-22T14:01:12Z) validates 30/30 runs with 0 failed design checks and benchmark/results/NEXT_ITERATION.md carries the headline numbers. |
| F4 | cross | **PASS** | Publication paths and audit filename | Publication paths resolve, the audit uses the assigned filenames, and the report/TeX product map points to pair_diff/results/report.md. |
| F5 | cross | **PASS** | Audit is read-only and offline | Audit script uses only the standard library, makes no network/model call and runs no git/gh command; it writes only the two audit files. |

## Reading notes

- **CodeQL triage.** 140 frozen test units, 70/70; CodeQL is 68 TP / 23 FP / 47 TN / 2 FN. All 23 FPs are C++ good units on `cpp/memory-may-not-be-freed` (15 `_33`, 3 `_22`, 3 `_72`, 2 `_54`). v1 deletes 7 TPs, all `malloc_realloc_*`; v2 and the verifier delete 0/68. The final 68/0/70/2 depends on the 3 `_22` consistency flips, which the report states explicitly.
- **Pair diff.** 8 full runs x 180 = 1,440 records, all `ok`; 0 invalid by decision validity. Two MiMo outputs add a `confidence_note`/`rationale_note` key, so schema-exact is 1,438/1,440 (99.44%); the report discloses this. The open baseline is the published `pair_debias` 720 records, not a new run.
- **Conservative verifier.** 236 real requests (60/60/58/58), 233 ok / 2 invalid / 1 API error; 4 retractions (TP 3 / FP 1), precision 25.0%. All failures keep the first-pass prediction (fail-open); `insufficient` never retracts.
- **Coverage.** 140 units x 3 modes = 420 runs, 0 compile/coverage errors. Default 58/0/70/12; three-mode union 70/0/70/0. Effective line coverage is 100%, branch coverage 52.7%, and the 21 `branch_complete` units are all bad. The 12 default FNs are line-complete: coverage explains execution, not leak absence.
- **Interpretable baseline.** dev40/test160 idx, project, body-MD5 and project+commit overlaps are all 0. Thresholds (chars 1504, calls 16, positive rate 0.8) and the selected rule are dev-only. The README's pre-registration timestamp is not verifiable (README mtime is after metrics.json).
- **Report/benchmark.** `codeql_triage/benchmark_export.json` and `pair_diff/results/benchmark_export.json` reproduce from raw records and agree with `report/next_results_summary.md`. The benchmark import batch (`benchmark/extensions/configs/next_iteration_batch.json`, 30 runs) has 30/30 output directories, but `benchmark/results/extension_summary.json` is still 2026-11-13 and `benchmark/NEXT_ITERATION.md` is absent. Publication docs also reference `audit/next_audit.md`/`.json`, while this audit is assigned `audit/next_iteration_audit.md`/`.json`.
- **Out of scope.** No git/gh operation, no API call and no edit outside `audit/` were made by this audit. The older `pair_debias`, `evidence_verify`, `dynamic_enhanced`, `hybrid_dynamic_enhanced`, `static_extended` and `benchmark/results` artifacts keep their pre-2026-11-22 mtimes and record counts.

## Files written

- `audit/next_iteration_audit.json`
- `audit/next_iteration_audit.md`

Reproduce with `python3 audit/run_next_iteration_audit.py` (read-only; no network).
