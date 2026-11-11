# SecVulEval run: test_v1_context_pairs

- Dataset: `pairs`
- Strategy: `context`
- Task: `both`
- Model: `deepseek-v4.1-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 540 / expected 540
- Cache hits: 0; API attempts: 540

## Detection

| Metric | Value |
| --- | --- |
| Requested | 360 |
| Valid predictions | 360 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 71 / 50 / 130 / 109 |
| precision (valid only) | 0.5868 (58.68%) |
| recall (valid only) | 0.3944 (39.44%) |
| specificity (valid only) | 0.7222 (72.22%) |
| f1 (valid only) | 0.4718 (47.18%) |
| accuracy (valid only) | 0.5583 (55.83%) |
| balanced_accuracy (valid only) | 0.5583 (55.83%) |
| mcc (valid only) | 0.1235 |
| predicted_positive_rate (valid only) | 0.3361 (33.61%) |
| strict accuracy (all samples) | 0.5583 (55.83%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 71 | 0.3944 (39.44%) |
| non_vulnerable | 180 | 180 | 50 | 0.2778 (27.78%) |

### Detection by pair side

| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 180 | 180 | 71 | 0.3944 (39.44%) |
| fixed | 180 | 180 | 50 | 0.2778 (27.78%) |

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
| Valid pairs | 180 |
| Coverage | 1.0000 (100.00%) |
| Discrimination accuracy (valid pairs) | 0.1222 (12.22%) |
| Discrimination accuracy (all pairs) | 0.1222 (12.22%) |

| Joint category | Count | Share of valid pairs |
| --- | ---: | ---: |
| vulnerable_detected_fixed_clean | 22 | 0.1222 (12.22%) |
| both_flagged | 49 | 0.2722 (27.22%) |
| both_clean | 108 | 0.6000 (60.00%) |
| vulnerable_missed_fixed_flagged | 1 | 0.0056 (0.56%) |

Correct pair handling requires the vulnerable side to be flagged and the fixed side to be accepted; `both_flagged`, `both_clean`, and `vulnerable_missed_fixed_flagged` are all failures of pair discrimination.

## Repair

| Metric | Value |
| --- | --- |
| requested | 180 |
| schema_valid | 149 |
| schema_invalid | 31 |
| api_errors | 0 |
| complete_function | 149 |
| changed_from_input | 128 |
| complete_and_changed | 128 |
| reference_fixed_available | 149 |
| exact_match_reference_fixed | 4 |
| whitespace_collapsed_match_reference_fixed | 7 |
| schema_valid_rate | 0.8278 (82.78%) |
| complete_function_rate_of_schema_valid | 1.0000 (100.00%) |
| complete_function_rate_of_all | 0.8278 (82.78%) |
| changed_from_input_rate_of_schema_valid | 0.8591 (85.91%) |
| complete_and_changed_rate_of_schema_valid | 0.8591 (85.91%) |
| exact_match_reference_fixed_rate | 0.0268 (2.68%) |
| whitespace_collapsed_match_reference_fixed_rate | 0.0470 (4.70%) |

Repair scores are structural proxies; reference matches are text comparisons, not proof of correctness or security equivalence.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 528265 |
| Completion tokens (known sum) | 203329 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.117525 |
| Records with `usage.opencode` | 540 |
| OpenCode billing sources | `{'go': 540}` |
| Total cost (USD) | $0.402474 |
| Known cost (USD) | $0.402474 |
| Unknown cost records | 0 |
| Total request latency (s) | 4467.7802 |
| Mean request latency (s) | 8.2737 |
| p50 request latency (s) | 6.1317 |
| p95 request latency (s) | 20.1841 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

- API error types: `{}`
- Schema-invalid reasons: `{"repair JSON keys mismatch (missing=['explanation'], extra=[])": 29, 'invalid JSON: Unterminated string starting at: line 1 column 20 (char 19)': 2}`
- Examples: `[{'sample_id': 'pair:4597:4598:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:3266:3267:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:655:656:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:12972:12976:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}, {'sample_id': 'pair:12557:12558:vulnerable', 'task': 'repair', 'status': 'invalid', 'error': "repair JSON keys mismatch (missing=['explanation'], extra=[])"}]`

## Notes

- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Repair scores are structural proxies (complete function and changed text); they do not prove that a vulnerability was removed or that behaviour was preserved.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
