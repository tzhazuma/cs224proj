# SecVulEval run: test_v1_direct_independent

- Dataset: `independent`
- Strategy: `direct`
- Task: `both`
- Model: `deepseek-v4.1-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 288 / expected 288
- Cache hits: 105; API attempts: 288

## Detection

| Metric | Value |
| --- | --- |
| Requested | 160 |
| Valid predictions | 160 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 38 / 8 / 24 / 90 |
| precision (valid only) | 0.8261 (82.61%) |
| recall (valid only) | 0.2969 (29.69%) |
| specificity (valid only) | 0.7500 (75.00%) |
| f1 (valid only) | 0.4368 (43.68%) |
| accuracy (valid only) | 0.3875 (38.75%) |
| balanced_accuracy (valid only) | 0.5234 (52.34%) |
| mcc (valid only) | 0.0414 |
| predicted_positive_rate (valid only) | 0.2875 (28.75%) |
| strict accuracy (all samples) | 0.3875 (38.75%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 128 | 38 | 0.2969 (29.69%) |
| non_vulnerable | 32 | 32 | 8 | 0.2500 (25.00%) |

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

| Metric | Value |
| --- | --- |
| requested | 128 |
| schema_valid | 109 |
| schema_invalid | 19 |
| api_errors | 0 |
| complete_function | 108 |
| changed_from_input | 85 |
| complete_and_changed | 84 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.8516 (85.16%) |
| complete_function_rate_of_schema_valid | 0.9908 (99.08%) |
| complete_function_rate_of_all | 0.8438 (84.38%) |
| changed_from_input_rate_of_schema_valid | 0.7798 (77.98%) |
| complete_and_changed_rate_of_schema_valid | 0.7706 (77.06%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 285818 |
| Completion tokens (known sum) | 139662 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.075516 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.253340 |
| Known cost (USD) | $0.253340 |
| Unknown cost records | 0 |
| Total request latency (s) | 2404.3749 |
| Mean request latency (s) | 8.3485 |
| p50 request latency (s) | 6.2856 |
| p95 request latency (s) | 18.2899 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"repair JSON keys mismatch (missing=['explanation'], extra=[])": 18, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 1}`
- Examples: `[{'sample_id': 'idx:7898', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:3526', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:6810', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:20504', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:15307', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
