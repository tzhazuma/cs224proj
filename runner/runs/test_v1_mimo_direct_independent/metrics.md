# SecVulEval run: test_v1_mimo_direct_independent

- Dataset: `independent`
- Strategy: `direct`
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
| Valid predictions | 150 |
| Schema invalid | 10 |
| API errors | 0 |
| Coverage | 0.9375 (93.75%) |
| TP / FP / TN / FN | 29 / 7 / 23 / 91 |
| precision (valid only) | 0.8056 (80.56%) |
| recall (valid only) | 0.2417 (24.17%) |
| specificity (valid only) | 0.7667 (76.67%) |
| f1 (valid only) | 0.3718 (37.18%) |
| accuracy (valid only) | 0.3467 (34.67%) |
| balanced_accuracy (valid only) | 0.5042 (50.42%) |
| mcc (valid only) | 0.0078 |
| predicted_positive_rate (valid only) | 0.2400 (24.00%) |
| strict accuracy (all samples) | 0.3250 (32.50%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 120 | 29 | 0.2417 (24.17%) |
| non_vulnerable | 32 | 30 | 7 | 0.2333 (23.33%) |

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

| Metric | Value |
| --- | --- |
| requested | 128 |
| schema_valid | 127 |
| schema_invalid | 1 |
| api_errors | 0 |
| complete_function | 124 |
| changed_from_input | 93 |
| complete_and_changed | 90 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.9922 (99.22%) |
| complete_function_rate_of_schema_valid | 0.9764 (97.64%) |
| complete_function_rate_of_all | 0.9688 (96.88%) |
| changed_from_input_rate_of_schema_valid | 0.7323 (73.23%) |
| complete_and_changed_rate_of_schema_valid | 0.7087 (70.87%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 265734 |
| Completion tokens (known sum) | 130249 |
| Cached prompt tokens (known sum) | 7808 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.072601 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.072601 |
| Known cost (USD) | $0.072601 |
| Unknown cost records | 0 |
| Total request latency (s) | 3620.7922 |
| Mean request latency (s) | 12.5722 |
| p50 request latency (s) | 6.7564 |
| p95 request latency (s) | 37.2992 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 10, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 1}`
- Examples: `[{'sample_id': 'idx:22421', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:13806', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:23559', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:7275', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}, {'sample_id': 'idx:17502', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
