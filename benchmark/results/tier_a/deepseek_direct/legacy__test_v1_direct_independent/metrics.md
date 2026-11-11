# Benchmark metrics: `legacy__test_v1_direct_independent`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:27Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 160 |
| `planned_units` | 160 |
| `by_task` | {'detection': 160} |
| `by_status` | {'ok': 160} |
| `missing_units` | 0 |

## Detection (valid-only, with strict view)

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.8261 |
| `recall` | 0.2969 |
| `specificity` | 0.7500 |
| `f1` | 0.4368 |
| `macro_f1` | 0.3828 |
| `balanced_accuracy` | 0.5234 |
| `accuracy` | 0.3875 |
| `strict_accuracy` | 0.3875 |
| `mcc` | 0.0414 |

Confusion: `{'tp': 38, 'fp': 8, 'tn': 24, 'fn': 90}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0670 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 976.2111 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 165254 |
| `completion_tokens_sum` | 14510 |
| `latency_ms_p50` | 5654.1590 |
| `latency_ms_p95` | 10825.6979 |
| `cost_per_100_units_usd` | 0.0419 |
| `cost_per_true_positive_usd` | 0.0018 |
| `wall_s_per_100_units` | 610.1319 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
