# SecVulEval run: test_v1_mimo_context_independent

- Dataset: `independent`
- Strategy: `context`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 288 / expected 288
- Cache hits: 0; API attempts: 288

## Detection

| Metric | Value |
| --- | --- |
| Requested | 160 |
| Valid predictions | 153 |
| Schema invalid | 7 |
| API errors | 0 |
| Coverage | 0.9563 (95.62%) |
| TP / FP / TN / FN | 31 / 5 / 25 / 92 |
| precision (valid only) | 0.8611 (86.11%) |
| recall (valid only) | 0.2520 (25.20%) |
| specificity (valid only) | 0.8333 (83.33%) |
| f1 (valid only) | 0.3899 (38.99%) |
| accuracy (valid only) | 0.3660 (36.60%) |
| balanced_accuracy (valid only) | 0.5427 (54.27%) |
| mcc (valid only) | 0.0799 |
| predicted_positive_rate (valid only) | 0.2353 (23.53%) |
| strict accuracy (all samples) | 0.3500 (35.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 123 | 31 | 0.2520 (25.20%) |
| non_vulnerable | 32 | 30 | 5 | 0.1667 (16.67%) |

## Context coverage

| Metric | Value |
| --- | --- |
| Requests using context | 288 |
| Non-empty context | 252 |
| Empty context | 36 |
| Context parse failures | 0 |

> Context availability itself may be correlated with the label in this dataset; report non-empty/empty subgroups rather than treating L3 as a pure prompt effect.

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

| Metric | Value |
| --- | --- |
| requested | 128 |
| schema_valid | 127 |
| schema_invalid | 1 |
| api_errors | 0 |
| complete_function | 125 |
| changed_from_input | 99 |
| complete_and_changed | 97 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.9922 (99.22%) |
| complete_function_rate_of_schema_valid | 0.9843 (98.43%) |
| complete_function_rate_of_all | 0.9766 (97.66%) |
| changed_from_input_rate_of_schema_valid | 0.7795 (77.95%) |
| complete_and_changed_rate_of_schema_valid | 0.7638 (76.38%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 283180 |
| Completion tokens (known sum) | 130961 |
| Cached prompt tokens (known sum) | 9856 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.074962 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.074962 |
| Known cost (USD) | $0.074962 |
| Unknown cost records | 0 |
| Total request latency (s) | 3132.2867 |
| Mean request latency (s) | 10.8760 |
| p50 request latency (s) | 5.9565 |
| p95 request latency (s) | 35.1122 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 6, "detection JSON keys mismatch (missing=[], extra=['is_vulnerability'])": 1, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 1}`
- Examples: `[{'sample_id': 'idx:22380', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:12359', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:17502', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=[], extra=['is_vulnerability'])"}, {'sample_id': 'idx:11782', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:6158', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
