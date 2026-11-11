# Benchmark metrics: `legacy__test_v1_mimo_context_independent`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:31Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 160 |
| `planned_units` | 160 |
| `by_task` | {'detection': 160} |
| `by_status` | {'ok': 153, 'schema_invalid': 7} |
| `missing_units` | 0 |

## Detection (valid-only, with strict view)

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 153 |
| `invalid` | 7 |
| `coverage` | 0.9563 |
| `precision` | 0.8611 |
| `recall` | 0.2520 |
| `specificity` | 0.8333 |
| `f1` | 0.3899 |
| `macro_f1` | 0.3650 |
| `balanced_accuracy` | 0.5427 |
| `accuracy` | 0.3660 |
| `strict_accuracy` | 0.3500 |
| `mcc` | 0.0799 |

Confusion: `{'tp': 31, 'fp': 5, 'tn': 25, 'fn': 92}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0256 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 792.6859 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 163029 |
| `completion_tokens_sum` | 12873 |
| `latency_ms_p50` | 4312.6727 |
| `latency_ms_p95` | 8380.4843 |
| `cost_per_100_units_usd` | 0.0160 |
| `cost_per_true_positive_usd` | 0.0008 |
| `wall_s_per_100_units` | 495.4287 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
