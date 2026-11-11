# SecVulEval run: test_v1_mimo_few-shot_independent

- Dataset: `independent`
- Strategy: `few-shot`
- Task: `both`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 288 / expected 288
- Cache hits: 0; API attempts: 290

## Detection

| Metric | Value |
| --- | --- |
| Requested | 160 |
| Valid predictions | 160 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 34 / 10 / 22 / 94 |
| precision (valid only) | 0.7727 (77.27%) |
| recall (valid only) | 0.2656 (26.56%) |
| specificity (valid only) | 0.6875 (68.75%) |
| f1 (valid only) | 0.3953 (39.53%) |
| accuracy (valid only) | 0.3500 (35.00%) |
| balanced_accuracy (valid only) | 0.4766 (47.66%) |
| mcc (valid only) | -0.0420 |
| predicted_positive_rate (valid only) | 0.2750 (27.50%) |
| strict accuracy (all samples) | 0.3500 (35.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 128 | 34 | 0.2656 (26.56%) |
| non_vulnerable | 32 | 32 | 10 | 0.3125 (31.25%) |

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
| changed_from_input | 59 |
| complete_and_changed | 57 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.9922 (99.22%) |
| complete_function_rate_of_schema_valid | 0.9764 (97.64%) |
| complete_function_rate_of_all | 0.9688 (96.88%) |
| changed_from_input_rate_of_schema_valid | 0.4646 (46.46%) |
| complete_and_changed_rate_of_schema_valid | 0.4488 (44.88%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 842886 |
| Completion tokens (known sum) | 121721 |
| Cached prompt tokens (known sum) | 424768 |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.093808 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.093808 |
| Known cost (USD) | $0.093808 |
| Unknown cost records | 0 |
| Total request latency (s) | 4580.7707 |
| Mean request latency (s) | 15.9055 |
| p50 request latency (s) | 6.6342 |
| p95 request latency (s) | 53.9304 |

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
