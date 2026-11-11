# Benchmark metrics: `legacy__test_v1_context_independent`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:24Z`

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
| `precision` | 0.8125 |
| `recall` | 0.3047 |
| `specificity` | 0.7188 |
| `f1` | 0.4432 |
| `macro_f1` | 0.3813 |
| `balanced_accuracy` | 0.5117 |
| `accuracy` | 0.3875 |
| `strict_accuracy` | 0.3875 |
| `mcc` | 0.0205 |

Confusion: `{'tp': 39, 'fp': 9, 'tn': 23, 'fn': 89}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0703 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 1017.5757 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 175724 |
| `completion_tokens_sum` | 14659 |
| `latency_ms_p50` | 5633.4725 |
| `latency_ms_p95` | 10706.6812 |
| `cost_per_100_units_usd` | 0.0439 |
| `cost_per_true_positive_usd` | 0.0018 |
| `wall_s_per_100_units` | 635.9848 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
