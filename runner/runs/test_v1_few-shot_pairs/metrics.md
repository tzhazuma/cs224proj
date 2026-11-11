# SecVulEval run: test_v1_few-shot_pairs

- Dataset: `pairs`
- Strategy: `few-shot`
- Task: `both`
- Model: `deepseek-v4.1-flash`
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
| TP / FP / TN / FN | 65 / 51 / 129 / 115 |
| precision (valid only) | 0.5603 (56.03%) |
| recall (valid only) | 0.3611 (36.11%) |
| specificity (valid only) | 0.7167 (71.67%) |
| f1 (valid only) | 0.4392 (43.92%) |
| accuracy (valid only) | 0.5389 (53.89%) |
| balanced_accuracy (valid only) | 0.5389 (53.89%) |
| mcc (valid only) | 0.0832 |
| predicted_positive_rate (valid only) | 0.3222 (32.22%) |
| strict accuracy (all samples) | 0.5389 (53.89%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 65 | 0.3611 (36.11%) |
| non_vulnerable | 180 | 180 | 51 | 0.2833 (28.33%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 65 | 0.3611 (36.11%) |
| fixed | 180 | 180 | 51 | 0.2833 (28.33%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 180 |
| Valid pairs | 180 |
| Coverage | 1.0000 (100.00%) |
| Discrimination accuracy (valid pairs) | 0.0889 (8.89%) |
| Discrimination accuracy (all pairs) | 0.0889 (8.89%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 16 | 0.0889 (8.89%) |
| both_flagged | 49 | 0.2722 (27.22%) |
| both_clean | 113 | 0.6278 (62.78%) |
| vulnerable_missed_fixed_flagged | 2 | 0.0111 (1.11%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 178 |
| schema_invalid | 2 |
| api_errors | 0 |
| complete_function | 177 |
| changed_from_input | 116 |
| complete_and_changed | 116 |
| reference_fixed_available | 178 |
| exact_match_reference_fixed | 9 |
| whitespace_collapsed_match_reference_fixed | 9 |
| schema_valid_rate | 0.9889 (98.89%) |
| complete_function_rate_of_schema_valid | 0.9944 (99.44%) |
| complete_function_rate_of_all | 0.9833 (98.33%) |
| changed_from_input_rate_of_schema_valid | 0.6517 (65.17%) |
| complete_and_changed_rate_of_schema_valid | 0.6517 (65.17%) |
| exact_match_reference_fixed_rate | 0.0506 (5.06%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0506 (5.06%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 1569520 |
| Completion tokens (known sum) | 192158 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.109281 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.701446 |
| Known cost (USD) | $0.701446 |
| Unknown cost records | 0 |
| Total request latency (s) | 4068.6549 |
| Mean request latency (s) | 7.5345 |
| p50 request latency (s) | 5.7119 |
| p95 request latency (s) | 17.7415 |

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
