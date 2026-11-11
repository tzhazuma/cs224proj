# SecVulEval run: pilot_v1_mimo_direct_pairs

- Dataset: `pairs`
- Strategy: `direct`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 9 / expected 9
- Cache hits: 0; API attempts: 11

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 6 |
| Valid predictions | 4 |
| Schema invalid | 2 |
| API errors | 0 |
| Coverage | 0.6667 (66.67%) |
| TP / FP / TN / FN | 0 / 0 / 2 / 2 |
| precision (valid only) | null |
| recall (valid only) | 0.0000 (0.00%) |
| specificity (valid only) | 1.0000 (100.00%) |
| f1 (valid only) | null |
| accuracy (valid only) | 0.5000 (50.00%) |
| balanced_accuracy (valid only) | 0.5000 (50.00%) |
| mcc (valid only) | null |
| predicted_positive_rate (valid only) | 0.0000 (0.00%) |
| strict accuracy (all samples) | 0.3333 (33.33%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 3 | 2 | 0 | 0.0000 (0.00%) |
| non_vulnerable | 3 | 2 | 0 | 0.0000 (0.00%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 3 | 2 | 0 | 0.0000 (0.00%) |
| fixed | 3 | 2 | 0 | 0.0000 (0.00%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 3 |
| Valid pairs | 2 |
| Coverage | 0.6667 (66.67%) |
| Discrimination accuracy (valid pairs) | 0.0000 (0.00%) |
| Discrimination accuracy (all pairs) | 0.0000 (0.00%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 0 | 0.0000 (0.00%) |
| both_flagged | 0 | 0.0000 (0.00%) |
| both_clean | 2 | 1.0000 (100.00%) |
| vulnerable_missed_fixed_flagged | 0 | 0.0000 (0.00%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 3 |
| schema_valid | 2 |
| schema_invalid | 0 |
| api_errors | 1 |
| complete_function | 2 |
| changed_from_input | 2 |
| complete_and_changed | 2 |
| reference_fixed_available | 2 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.6667 (66.67%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 0.6667 (66.67%) |
| changed_from_input_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_and_changed_rate_of_schema_valid | 1.0000 (100.00%) |
| exact_match_reference_fixed_rate | 0.0000 (0.00%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0000 (0.00%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 8359 |
| Completion tokens (known sum) | 7117 |
| Cached prompt tokens (known sum) | 0 |
| Records missing usage | 1 |
| OpenCode allowance consumed (known sum, USD) | $0.003163 |
| Records with `usage.opencode` | 8 |
| OpenCode billing sources | `{'go': 8}` |
| Total cost (USD) | null |
| Known cost (USD) | $0.003163 |
| Unknown cost records | 1 |
| Total request latency (s) | 514.0249 |
| Mean request latency (s) | 57.1139 |
| p50 request latency (s) | 24.6988 |
| p95 request latency (s) | 185.4558 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{'empty_content': 1}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 2}`
- Examples: `[{'sample_id': 'pair:7734:7735:vulnerable', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:7734:7735:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:7734:7735:vulnerable', 'task': 'repair', 'status': 'error', 'error': {'type': 'empty_content', 'message': 'API response has empty message content', 'retryable': True}}]`

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- Cost is null because at least one request lacks a complete cost record.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
