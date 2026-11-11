# SecVulEval run: pilot_v1_mimo_direct_independent

- Dataset: `independent`
- Strategy: `direct`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 12 / expected 12
- Cache hits: 0; API attempts: 12

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 6 |
| Valid predictions | 6 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 3 / 0 / 0 / 3 |
| precision (valid only) | 1.0000 (100.00%) |
| recall (valid only) | 0.5000 (50.00%) |
| specificity (valid only) | null |
| f1 (valid only) | 0.6667 (66.67%) |
| accuracy (valid only) | 0.5000 (50.00%) |
| balanced_accuracy (valid only) | null |
| mcc (valid only) | null |
| predicted_positive_rate (valid only) | 0.5000 (50.00%) |
| strict accuracy (all samples) | 0.5000 (50.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 6 | 6 | 3 | 0.5000 (50.00%) |
| non_vulnerable | 0 | 0 | 0 | null |

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

| Metric | Value |
| --- | --- |
| requested | 6 |
| schema_valid | 5 |
| schema_invalid | 1 |
| api_errors | 0 |
| complete_function | 5 |
| changed_from_input | 5 |
| complete_and_changed | 5 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.8333 (83.33%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 0.8333 (83.33%) |
| changed_from_input_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_and_changed_rate_of_schema_valid | 1.0000 (100.00%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 7870 |
| Completion tokens (known sum) | 22999 |
| Cached prompt tokens (known sum) | 5312 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.006813 |
| Records with `usage.opencode` | 12 |
| OpenCode billing sources | `{'go': 12}` |
| Total cost (USD) | $0.006813 |
| Known cost (USD) | $0.006813 |
| Unknown cost records | 0 |
| Total request latency (s) | 648.7474 |
| Mean request latency (s) | 54.0623 |
| p50 request latency (s) | 37.1199 |
| p95 request latency (s) | 139.3676 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 1}`
- Examples: `[{'sample_id': 'idx:11521', 'task': 'repair', 'status': 'invalid', 'error': 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)'}]`

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
