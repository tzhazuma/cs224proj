# Benchmark metrics: `legacy__test_v1_mimo_direct_independent`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:33Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 160 |
| `planned_units` | 160 |
| `by_task` | {'detection': 160} |
| `by_status` | {'ok': 150, 'schema_invalid': 10} |
| `missing_units` | 0 |

## Detection (valid-only, with strict view)

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 150 |
| `invalid` | 10 |
| `coverage` | 0.9375 |
| `precision` | 0.8056 |
| `recall` | 0.2417 |
| `specificity` | 0.7667 |
| `f1` | 0.3718 |
| `macro_f1` | 0.3456 |
| `balanced_accuracy` | 0.5042 |
| `accuracy` | 0.3467 |
| `strict_accuracy` | 0.3250 |
| `mcc` | 0.0078 |

Confusion: `{'tp': 29, 'fp': 7, 'tn': 23, 'fn': 91}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0244 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 910.6400 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 153666 |
| `completion_tokens_sum` | 12495 |
| `latency_ms_p50` | 4593.6459 |
| `latency_ms_p95` | 11995.2914 |
| `cost_per_100_units_usd` | 0.0152 |
| `cost_per_true_positive_usd` | 0.0008 |
| `wall_s_per_100_units` | 569.1500 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
