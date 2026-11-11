# SecVulEval run: test_v1_context_independent

- Dataset: `independent`
- Strategy: `context`
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
| TP / FP / TN / FN | 39 / 9 / 23 / 89 |
| precision (valid only) | 0.8125 (81.25%) |
| recall (valid only) | 0.3047 (30.47%) |
| specificity (valid only) | 0.7188 (71.88%) |
| f1 (valid only) | 0.4432 (44.32%) |
| accuracy (valid only) | 0.3875 (38.75%) |
| balanced_accuracy (valid only) | 0.5117 (51.17%) |
| mcc (valid only) | 0.0205 |
| predicted_positive_rate (valid only) | 0.3000 (30.00%) |
| strict accuracy (all samples) | 0.3875 (38.75%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 128 | 128 | 39 | 0.3047 (30.47%) |
| non_vulnerable | 32 | 32 | 9 | 0.2812 (28.12%) |

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
| schema_valid | 108 |
| schema_invalid | 20 |
| api_errors | 0 |
| complete_function | 107 |
| changed_from_input | 86 |
| complete_and_changed | 85 |
| reference_fixed_available | 0 |
| exact_match_reference_fixed | 0 |
| whitespace_collapsed_match_reference_fixed | 0 |
| schema_valid_rate | 0.8438 (84.38%) |
| complete_function_rate_of_schema_valid | 0.9907 (99.07%) |
| complete_function_rate_of_all | 0.8359 (83.59%) |
| changed_from_input_rate_of_schema_valid | 0.7963 (79.63%) |
| complete_and_changed_rate_of_schema_valid | 0.7870 (78.70%) |
| exact_match_reference_fixed_rate | null |
| whitespace_collapsed_match_reference_fixed_rate | null |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 305382 |
| Completion tokens (known sum) | 140135 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.077933 |
| Records with `usage.opencode` | 288 |
| OpenCode billing sources | `{'go': 288}` |
| Total cost (USD) | $0.259777 |
| Known cost (USD) | $0.259777 |
| Unknown cost records | 0 |
| Total request latency (s) | 2531.6238 |
| Mean request latency (s) | 8.7904 |
| p50 request latency (s) | 6.6023 |
| p95 request latency (s) | 19.7173 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"repair JSON keys mismatch (missing=['explanation'], extra=[])": 19, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 1}`
- Examples: `[{'sample_id': 'idx:7898', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:22675', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:21387', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:11143', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'idx:20504', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
