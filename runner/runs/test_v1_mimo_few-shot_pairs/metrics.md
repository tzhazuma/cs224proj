# SecVulEval run: test_v1_mimo_few-shot_pairs

- Dataset: `pairs`
- Strategy: `few-shot`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 540 / expected 540
- Cache hits: 0; API attempts: 540

## Detection

| Metric | Value |
| --- | --- |
| Requested | 360 |
| Valid predictions | 360 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 57 / 46 / 134 / 123 |
| precision (valid only) | 0.5534 (55.34%) |
| recall (valid only) | 0.3167 (31.67%) |
| specificity (valid only) | 0.7444 (74.44%) |
| f1 (valid only) | 0.4028 (40.28%) |
| accuracy (valid only) | 0.5306 (53.06%) |
| balanced_accuracy (valid only) | 0.5306 (53.06%) |
| mcc (valid only) | 0.0676 |
| predicted_positive_rate (valid only) | 0.2861 (28.61%) |
| strict accuracy (all samples) | 0.5306 (53.06%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 57 | 0.3167 (31.67%) |
| non_vulnerable | 180 | 180 | 46 | 0.2556 (25.56%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 57 | 0.3167 (31.67%) |
| fixed | 180 | 180 | 46 | 0.2556 (25.56%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 180 |
| Valid pairs | 180 |
| Coverage | 1.0000 (100.00%) |
| Discrimination accuracy (valid pairs) | 0.0944 (9.44%) |
| Discrimination accuracy (all pairs) | 0.0944 (9.44%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 17 | 0.0944 (9.44%) |
| both_flagged | 40 | 0.2222 (22.22%) |
| both_clean | 117 | 0.6500 (65.00%) |
| vulnerable_missed_fixed_flagged | 6 | 0.0333 (3.33%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 178 |
| schema_invalid | 2 |
| api_errors | 0 |
| complete_function | 177 |
| changed_from_input | 93 |
| complete_and_changed | 92 |
| reference_fixed_available | 178 |
| exact_match_reference_fixed | 4 |
| whitespace_collapsed_match_reference_fixed | 5 |
| schema_valid_rate | 0.9889 (98.89%) |
| complete_function_rate_of_schema_valid | 0.9944 (99.44%) |
| complete_function_rate_of_all | 0.9833 (98.33%) |
| changed_from_input_rate_of_schema_valid | 0.5225 (52.25%) |
| complete_and_changed_rate_of_schema_valid | 0.5169 (51.69%) |
| exact_match_reference_fixed_rate | 0.0225 (2.25%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0281 (2.81%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 1461726 |
| Completion tokens (known sum) | 178534 |
| Cached prompt tokens (known sum) | 760448 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.150298 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.150298 |
| Known cost (USD) | $0.150298 |
| Unknown cost records | 0 |
| Total request latency (s) | 6542.3342 |
| Mean request latency (s) | 12.1154 |
| p50 request latency (s) | 5.3505 |
| p95 request latency (s) | 40.9316 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{'invalid JSON: Unterminated string starting at: line 1 column 19 (char 18)': 2}`
- Examples: `[{'sample_id': 'pair:9912:9913:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': 'invalid JSON: Unterminated string starting at: line 1 column 19 (char 18)'}, {'sample_id': 'pair:8675:8676:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': 'invalid JSON: Unterminated string starting at: line 1 column 19 (char 18)'}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
