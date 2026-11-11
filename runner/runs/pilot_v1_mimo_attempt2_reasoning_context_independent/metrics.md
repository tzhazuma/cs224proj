# SecVulEval run: pilot_v1_mimo_context_independent

- Dataset: `independent`
- Strategy: `context`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 12 / expected 12
- Cache hits: 0; API attempts: 16

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 6 |
| Valid predictions | 5 |
| Schema invalid | 1 |
| API errors | 0 |
| Coverage | 0.8333 (83.33%) |
| TP / FP / TN / FN | 3 / 0 / 0 / 2 |
| precision (valid only) | 1.0000 (100.00%) |
| recall (valid only) | 0.6000 (60.00%) |
| specificity (valid only) | null |
| f1 (valid only) | 0.7500 (75.00%) |
| accuracy (valid only) | 0.6000 (60.00%) |
| balanced_accuracy (valid only) | null |
| mcc (valid only) | null |
| predicted_positive_rate (valid only) | 0.6000 (60.00%) |
| strict accuracy (all samples) | 0.5000 (50.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 6 | 5 | 3 | 0.6000 (60.00%) |
| non_vulnerable | 0 | 0 | 0 | null |

## Context coverage

| Metric | Value |
| --- | --- |
| Requests using context | 12 |
| Non-empty context | 12 |
| Empty context | 0 |
| Context parse failures | 0 |

> Context availability itself may be correlated with the label in this dataset; report non-empty/empty subgroups rather than treating L3 as a pure prompt effect.

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

| Metric | Value |
| --- | --- |
| requested | 6 |
| schema_valid | 6 |
| schema_invalid | 0 |
| api_errors | 0 |
| complete_function | 6 |
| changed_from_input | 6 |
| complete_and_changed | 6 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 1.0000 (100.00%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 1.0000 (100.00%) |
| changed_from_input_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_and_changed_rate_of_schema_valid | 1.0000 (100.00%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 8588 |
| Completion tokens (known sum) | 32851 |
| Cached prompt tokens (known sum) | 1856 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.010146 |
| Records with `usage.opencode` | 12 |
| OpenCode billing sources | `{'go': 12}` |
| Total cost (USD) | $0.010146 |
| Known cost (USD) | $0.010146 |
| Unknown cost records | 0 |
| Total request latency (s) | 2564.5776 |
| Mean request latency (s) | 213.7148 |
| p50 request latency (s) | 36.7800 |
| p95 request latency (s) | 875.0155 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])": 1}`
- Examples: `[{'sample_id': 'idx:6677', 'task': 'detection', 'status': 'invalid', 'error': "detection JSON keys mismatch (missing=['is_vulnerable'], extra=['is_vulnerability'])"}]`

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
