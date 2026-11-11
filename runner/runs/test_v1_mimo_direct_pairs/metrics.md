# SecVulEval run: test_v1_mimo_direct_pairs

- Dataset: `pairs`
- Strategy: `direct`
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
| Valid predictions | 331 |
| Schema invalid | 29 |
| API errors | 0 |
| Coverage | 0.9194 (91.94%) |
| TP / FP / TN / FN | 47 / 37 / 130 / 117 |
| precision (valid only) | 0.5595 (55.95%) |
| recall (valid only) | 0.2866 (28.66%) |
| specificity (valid only) | 0.7784 (77.84%) |
| f1 (valid only) | 0.3790 (37.90%) |
| accuracy (valid only) | 0.5347 (53.47%) |
| balanced_accuracy (valid only) | 0.5325 (53.25%) |
| mcc (valid only) | 0.0747 |
| predicted_positive_rate (valid only) | 0.2538 (25.38%) |
| strict accuracy (all samples) | 0.4917 (49.17%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 164 | 47 | 0.2866 (28.66%) |
| non_vulnerable | 180 | 167 | 37 | 0.2216 (22.16%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 164 | 47 | 0.2866 (28.66%) |
| fixed | 180 | 167 | 37 | 0.2216 (22.16%) |

## Paired joint results

| Metric | Value |
| --- | --- |
| Pairs | 180 |
| Valid pairs | 154 |
| Coverage | 0.8556 (85.56%) |
| Discrimination accuracy (valid pairs) | 0.0909 (9.09%) |
| Discrimination accuracy (all pairs) | 0.0778 (7.78%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 14 | 0.0909 (9.09%) |
| both_flagged | 27 | 0.1753 (17.53%) |
| both_clean | 108 | 0.7013 (70.13%) |
| vulnerable_missed_fixed_flagged | 5 | 0.0325 (3.25%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 178 |
| schema_invalid | 2 |
| api_errors | 0 |
| complete_function | 177 |
| changed_from_input | 141 |
| complete_and_changed | 140 |
| reference_fixed_available | 178 |
| exact_match_reference_fixed | 3 |
| whitespace_collapsed_match_reference_fixed | 3 |
| schema_valid_rate | 0.9889 (98.89%) |
| complete_function_rate_of_schema_valid | 0.9944 (99.44%) |
| complete_function_rate_of_all | 0.9833 (98.33%) |
| changed_from_input_rate_of_schema_valid | 0.7921 (79.21%) |
| complete_and_changed_rate_of_schema_valid | 0.7865 (78.65%) |
| exact_match_reference_fixed_rate | 0.0169 (1.69%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0169 (1.69%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 455706 |
| Completion tokens (known sum) | 191274 |
| Cached prompt tokens (known sum) | 22400 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.114283 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.114282 |
| Known cost (USD) | $0.114282 |
| Unknown cost records | 0 |
| Total request latency (s) | 5528.7136 |
| Mean request latency (s) | 10.2384 |
| p50 request latency (s) | 5.4627 |
| p95 request latency (s) | 33.4644 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 29, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 2}`
- Examples: `[{'sample_id': 'pair:3822:3828:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:22910:22920:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:22834:22835:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:20228:20229:fixed', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'pair:8565:8566:vulnerable', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
