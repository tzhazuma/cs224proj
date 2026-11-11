# SecVulEval run: test_v1_mimo_context_pairs

- Dataset: `pairs`
- Strategy: `context`
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
| Valid predictions | 345 |
| Schema invalid | 15 |
| API errors | 0 |
| Coverage | 0.9583 (95.83%) |
| TP / FP / TN / FN | 60 / 44 / 128 / 113 |
| precision (valid only) | 0.5769 (57.69%) |
| recall (valid only) | 0.3468 (34.68%) |
| specificity (valid only) | 0.7442 (74.42%) |
| f1 (valid only) | 0.4332 (43.32%) |
| accuracy (valid only) | 0.5449 (54.49%) |
| balanced_accuracy (valid only) | 0.5455 (54.55%) |
| mcc (valid only) | 0.0992 |
| predicted_positive_rate (valid only) | 0.3014 (30.14%) |
| strict accuracy (all samples) | 0.5222 (52.22%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 173 | 60 | 0.3468 (34.68%) |
| non_vulnerable | 180 | 172 | 44 | 0.2558 (25.58%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 173 | 60 | 0.3468 (34.68%) |
| fixed | 180 | 172 | 44 | 0.2558 (25.58%) |

## Context coverage

| Metric | Value |
| --- | --- |
| Requests using context | 540 |
| Non-empty context | 528 |
| Empty context | 12 |
| Context parse failures | 0 |

> Context availability itself may be correlated with the label in this dataset; report non-empty/empty subgroups rather than treating L3 as a pure prompt effect.

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 180 |
| Valid pairs | 166 |
| Coverage | 0.9222 (92.22%) |
| Discrimination accuracy (valid pairs) | 0.1145 (11.45%) |
| Discrimination accuracy (all pairs) | 0.1056 (10.56%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 19 | 0.1145 (11.45%) |
| both_flagged | 38 | 0.2289 (22.89%) |
| both_clean | 106 | 0.6386 (63.86%) |
| vulnerable_missed_fixed_flagged | 3 | 0.0181 (1.81%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 178 |
| schema_invalid | 2 |
| api_errors | 0 |
| complete_function | 177 |
| changed_from_input | 144 |
| complete_and_changed | 143 |
| reference_fixed_available | 178 |
| exact_match_reference_fixed | 5 |
| whitespace_collapsed_match_reference_fixed | 5 |
| schema_valid_rate | 0.9889 (98.89%) |
| complete_function_rate_of_schema_valid | 0.9944 (99.44%) |
| complete_function_rate_of_all | 0.9833 (98.33%) |
| changed_from_input_rate_of_schema_valid | 0.8090 (80.90%) |
| complete_and_changed_rate_of_schema_valid | 0.8034 (80.34%) |
| exact_match_reference_fixed_rate | 0.0281 (2.81%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0281 (2.81%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 490257 |
| Completion tokens (known sum) | 191801 |
| Cached prompt tokens (known sum) | 37440 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.117204 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.117203 |
| Known cost (USD) | $0.117203 |
| Unknown cost records | 0 |
| Total request latency (s) | 5077.2829 |
| Mean request latency (s) | 9.4024 |
| p50 request latency (s) | 5.0153 |
| p95 request latency (s) | 29.7985 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerative'])": 1, "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 14, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 2}`
- Examples: `[{'sample_id': 'pair:8565:8566:vulnerable', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerative'])"}, {'sample_id': 'pair:12528:12525:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:20003:20004:vulnerable', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:20003:20004:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:17834:17837:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
