# Benchmark metrics: `legacy__test_v1_few-shot_independent`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:29Z`

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
| `precision` | 0.8367 |
| `recall` | 0.3203 |
| `specificity` | 0.7500 |
| `f1` | 0.4633 |
| `macro_f1` | 0.3995 |
| `balanced_accuracy` | 0.5352 |
| `accuracy` | 0.4062 |
| `strict_accuracy` | 0.4062 |
| `mcc` | 0.0610 |

Confusion: `{'tp': 41, 'fp': 8, 'tn': 24, 'fn': 87}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.1367 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 942.2228 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 414214 |
| `completion_tokens_sum` | 10397 |
| `latency_ms_p50` | 5327.8260 |
| `latency_ms_p95` | 9691.4502 |
| `cost_per_100_units_usd` | 0.0855 |
| `cost_per_true_positive_usd` | 0.0033 |
| `wall_s_per_100_units` | 588.8892 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
