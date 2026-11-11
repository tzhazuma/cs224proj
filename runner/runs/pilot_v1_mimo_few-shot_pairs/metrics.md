# SecVulEval run: pilot_v1_mimo_few-shot_pairs

- Dataset: `pairs`
- Strategy: `few-shot`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 9 / expected 9
- Cache hits: 0; API attempts: 9

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 6 |
| Valid predictions | 6 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 1 / 0 / 3 / 2 |
| precision (valid only) | 1.0000 (100.00%) |
| recall (valid only) | 0.3333 (33.33%) |
| specificity (valid only) | 1.0000 (100.00%) |
| f1 (valid only) | 0.5000 (50.00%) |
| accuracy (valid only) | 0.6667 (66.67%) |
| balanced_accuracy (valid only) | 0.6667 (66.67%) |
| mcc (valid only) | 0.4472 |
| predicted_positive_rate (valid only) | 0.1667 (16.67%) |
| strict accuracy (all samples) | 0.6667 (66.67%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 3 | 3 | 1 | 0.3333 (33.33%) |
| non_vulnerable | 3 | 3 | 0 | 0.0000 (0.00%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 3 | 3 | 1 | 0.3333 (33.33%) |
| fixed | 3 | 3 | 0 | 0.0000 (0.00%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 3 |
| Valid pairs | 3 |
| Coverage | 1.0000 (100.00%) |
| Discrimination accuracy (valid pairs) | 0.3333 (33.33%) |
| Discrimination accuracy (all pairs) | 0.3333 (33.33%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 1 | 0.3333 (33.33%) |
| both_flagged | 0 | 0.0000 (0.00%) |
| both_clean | 2 | 0.6667 (66.67%) |
| vulnerable_missed_fixed_flagged | 0 | 0.0000 (0.00%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 3 |
| schema_valid | 3 |
| schema_invalid | 0 |
| api_errors | 0 |
| complete_function | 3 |
| changed_from_input | 0 |
| complete_and_changed | 0 |
| reference_fixed_available | 3 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 1.0000 (100.00%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 1.0000 (100.00%) |
| changed_from_input_rate_of_schema_valid | 0.0000 (0.00%) |
| complete_and_changed_rate_of_schema_valid | 0.0000 (0.00%) |
| exact_match_reference_fixed_rate | 0.0000 (0.00%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0000 (0.00%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 25974 |
| Completion tokens (known sum) | 3493 |
| Cached prompt tokens (known sum) | 22272 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.001559 |
| Records with `usage.opencode` | 9 |
| OpenCode billing sources | `{'go': 9}` |
| Total cost (USD) | $0.001559 |
| Known cost (USD) | $0.001559 |
| Unknown cost records | 0 |
| Total request latency (s) | 95.8200 |
| Mean request latency (s) | 10.6467 |
| p50 request latency (s) | 10.0049 |
| p95 request latency (s) | 17.7377 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

No API errors or schema-invalid responses.

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
