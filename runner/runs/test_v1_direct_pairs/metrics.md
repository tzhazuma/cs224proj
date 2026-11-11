# SecVulEval run: test_v1_direct_pairs

- Dataset: `pairs`
- Strategy: `direct`
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
| TP / FP / TN / FN | 65 / 46 / 134 / 115 |
| precision (valid only) | 0.5856 (58.56%) |
| recall (valid only) | 0.3611 (36.11%) |
| specificity (valid only) | 0.7444 (74.44%) |
| f1 (valid only) | 0.4467 (44.67%) |
| accuracy (valid only) | 0.5528 (55.28%) |
| balanced_accuracy (valid only) | 0.5528 (55.28%) |
| mcc (valid only) | 0.1143 |
| predicted_positive_rate (valid only) | 0.3083 (30.83%) |
| strict accuracy (all samples) | 0.5528 (55.28%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 65 | 0.3611 (36.11%) |
| non_vulnerable | 180 | 180 | 46 | 0.2556 (25.56%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 65 | 0.3611 (36.11%) |
| fixed | 180 | 180 | 46 | 0.2556 (25.56%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 180 |
| Valid pairs | 180 |
| Coverage | 1.0000 (100.00%) |
| Discrimination accuracy (valid pairs) | 0.1167 (11.67%) |
| Discrimination accuracy (all pairs) | 0.1167 (11.67%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 21 | 0.1167 (11.67%) |
| both_flagged | 44 | 0.2444 (24.44%) |
| both_clean | 113 | 0.6278 (62.78%) |
| vulnerable_missed_fixed_flagged | 2 | 0.0111 (1.11%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 151 |
| schema_invalid | 29 |
| api_errors | 0 |
| complete_function | 151 |
| changed_from_input | 124 |
| complete_and_changed | 124 |
| reference_fixed_available | 151 |
| exact_match_reference_fixed | 3 |
| whitespace_collapsed_match_reference_fixed | 3 |
| schema_valid_rate | 0.8389 (83.89%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 0.8389 (83.89%) |
| changed_from_input_rate_of_schema_valid | 0.8212 (82.12%) |
| complete_and_changed_rate_of_schema_valid | 0.8212 (82.12%) |
| exact_match_reference_fixed_rate | 0.0199 (1.99%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0199 (1.99%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 489340 |
| Completion tokens (known sum) | 204536 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.115811 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.392245 |
| Known cost (USD) | $0.392245 |
| Unknown cost records | 0 |
| Total request latency (s) | 4534.0881 |
| Mean request latency (s) | 8.3965 |
| p50 request latency (s) | 6.1643 |
| p95 request latency (s) | 19.3417 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"repair JSON keys mismatch (missing=['explanation'], extra=[])": 27, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 2}`
- Examples: `[{'sample_id': 'pair:22910:22920:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:15421:15420:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:8369:8374:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:12528:12525:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:12557:12558:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
