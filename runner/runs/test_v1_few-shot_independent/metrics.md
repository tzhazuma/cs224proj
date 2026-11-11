# SecVulEval run: test_v1_few-shot_independent

- Dataset: `independent`
- Strategy: `few-shot`
- Task: `both`
- Model: `deepseek-v4.1-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 288 / expected 288
- Cache hits: 0; API attempts: 288

## Detection

| Metric | Value |
| --- | --- |
| Requested | 160 |
| Valid predictions | 160 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 41 / 8 / 24 / 87 |
| precision (valid only) | 0.8367 (83.67%) |
| recall (valid only) | 0.3203 (32.03%) |
| specificity (valid only) | 0.7500 (75.00%) |
| f1 (valid only) | 0.4633 (46.33%) |
| accuracy (valid only) | 0.4062 (40.62%) |
| balanced_accuracy (valid only) | 0.5352 (53.52%) |
| mcc (valid only) | 0.0610 |
| predicted_positive_rate (valid only) | 0.3063 (30.63%) |
| strict accuracy (all samples) | 0.4062 (40.62%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 128 | 41 | 0.3203 (32.03%) |
| non_vulnerable | 32 | 32 | 8 | 0.2500 (25.00%) |

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
| changed_from_input | 75 |
| complete_and_changed | 73 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.9922 (99.22%) |
| complete_function_rate_of_schema_valid | 0.9843 (98.43%) |
| complete_function_rate_of_all | 0.9766 (97.66%) |
| changed_from_input_rate_of_schema_valid | 0.5906 (59.06%) |
| complete_and_changed_rate_of_schema_valid | 0.5748 (57.48%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 904570 |
| Completion tokens (known sum) | 132139 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.073528 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.429938 |
| Known cost (USD) | $0.429938 |
| Unknown cost records | 0 |
| Total request latency (s) | 2360.1897 |
| Mean request latency (s) | 8.1951 |
| p50 request latency (s) | 6.0471 |
| p95 request latency (s) | 18.6251 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{'invalid JSON: Unterminated string starting at: line 1 column 19 (char 18)': 1}`
- Examples: `[{'sample_id': 'idx:7018', 'task': 'repair', 'status': 'invalid', 'error': 'invalid JSON: Unterminated string starting at: line 1 column 19 (char 18)'}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
