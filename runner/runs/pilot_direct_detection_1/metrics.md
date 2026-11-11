# SecVulEval run: pilot_direct_detection_1

- Dataset: `independent`
- Strategy: `direct`
- Task: `detection`
- Model: `deepseek-v4.1-flash`
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions`
- Prompt version: `secvul-prompt-2026-11-11.1`
- Records: 1 / expected 1
- Cache hits: 0; API attempts: 3

> **PARTIAL RUN.** `--limit` selected only part of the dataset. These values are not full-dataset experimental results.

## Detection

| Metric | Value |
| --- | --- |
| Requested | 1 |
| Valid predictions | 0 |
| Schema invalid | 0 |
| API errors | 1 |
| Coverage | 0.0000 (0.00%) |
| TP / FP / TN / FN | 0 / 0 / 0 / 0 |
| precision (valid only) | null |
| recall (valid only) | null |
| specificity (valid only) | null |
| f1 (valid only) | null |
| accuracy (valid only) | null |
| balanced_accuracy (valid only) | null |
| mcc (valid only) | null |
| predicted_positive_rate (valid only) | null |
| strict accuracy (all samples) | 0.0000 (0.00%) |

### Detection by label

| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |
| --- | ---: | ---: | ---: | ---: |
| vulnerable | 1 | 0 | 0 | null |
| non_vulnerable | 0 | 0 | 0 | null |

## Paired joint results

Not available (requires the pairs dataset and detection task).

## Repair

Not run.

## Usage, cost, and latency

| Metric | Value |
| --- | --- |
| Prompt tokens (known sum) | null |
| Completion tokens (known sum) | null |
| Cached prompt tokens (known sum) | null |
| Records missing usage | 1 |
| Total cost (USD) | null |
| Known cost (USD) | null |
| Unknown cost records | 1 |
| Total request latency (s) | 257.5509 |
| Mean request latency (s) | 257.5509 |
| p50 request latency (s) | 257.5509 |
| p95 request latency (s) | 257.5509 |

Cost is `null` when token prices were not supplied or when any request lacks a complete cost record. The runner does not hardcode provider prices.

## Failures

- API error types: `{'empty_content': 1}`
- Schema-invalid reasons: `{}`
- Examples: `[{'sample_id': 'idx:10568', 'task': 'detection', 'status': 'error', 'error': {'type': 'empty_content', 'message': 'API response has empty message content', 'retryable': True}}]`

## Notes

- PARTIAL RUN: --limit selected only part of the dataset. Do not report these values as full-dataset experimental results.
- No valid detection predictions were recorded; all detection metrics are null or zero-coverage.
- Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples counts schema-invalid and API-error records as incorrect.
- Cost is null because at least one request lacks a complete cost record.
