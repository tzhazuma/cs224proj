# SecVulEval run: pilot_direct_detection_nothink_1

- Dataset: `independent`
- Strategy: `direct`
- Task: `detection`
- Model: `deepseek-v4.1-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 1 / expected 1
- Cache hits: 0; API attempts: 1

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 1 |
| Valid predictions | 1 |
| Schema invalid | 0 |
| API errors | 0 |
| Coverage | 1.0000 (100.00%) |
| TP / FP / TN / FN | 0 / 0 / 0 / 1 |
| precision (valid only) | null |
| recall (valid only) | 0.0000 (0.00%) |
| specificity (valid only) | null |
| f1 (valid only) | null |
| accuracy (valid only) | 0.0000 (0.00%) |
| balanced_accuracy (valid only) | null |
| mcc (valid only) | null |
| predicted_positive_rate (valid only) | 0.0000 (0.00%) |
| strict accuracy (all samples) | 0.0000 (0.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 1 | 1 | 0 | 0.0000 (0.00%) |
| non_vulnerable | 0 | 0 | 0 | null |

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

Not run.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | 660 |
| Completion tokens (known sum) | 86 |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 0 |
| OpenCode allowance consumed (known sum, USD) | $0.000090 |
| Records with `usage.opencode` | 1 |
| OpenCode billing sources | `{'go': 1}` |
| Total cost (USD) | $0.000301 |
| Known cost (USD) | $0.000301 |
| Unknown cost records | 0 |
| Total request latency (s) | 6.3980 |
| Mean request latency (s) | 6.3980 |
| p50 request latency (s) | 6.3980 |
| p95 request latency (s) | 6.3980 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.
`usage.opencode.allowance` is provider-reported Go-plan usage and is summed separately; it never populates `total_cost_usd`.

## Failures

No API errors or schema-invalid responses.

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- usage.opencode from the provider is preserved in each record's usage. opencode.allowance is Go-plan usage in USD and is summed separately; it is never used as cost_usd. cost_usd still comes only from explicit price arguments.
