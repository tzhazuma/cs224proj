# Benchmark metrics: `legacy__test_v1_mimo_few-shot_pairs`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:36Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 360 |
| `planned_units` | 360 |
| `by_task` | {'pair_detection': 360} |
| `by_status` | {'ok': 360} |
| `missing_units` | 0 |

## Pair discrimination

| metric | value |
| --- | ---: |
| `n_pairs` | 180 |
| `valid_pairs` | 180 |
| `invalid_pairs` | 0 |
| `missing_pairs` | 0 |
| `coverage` | 1.0000 |
| `joint_accuracy_valid_pairs` | 0.0944 |
| `joint_accuracy_all_pairs` | 0.0944 |
| `consistent_rate` | 0.1278 |
| `swapped_rate` | 0.0333 |

Joint categories: `{'vulnerable_detected_fixed_clean': 17, 'both_flagged': 40, 'both_clean': 117, 'vulnerable_missed_fixed_flagged': 6}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0679 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 1816.8939 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 822772 |
| `completion_tokens_sum` | 23029 |
| `latency_ms_p50` | 4409.9482 |
| `latency_ms_p95` | 8548.6679 |
| `cost_per_100_units_usd` | 0.0377 |
| `cost_per_true_positive_usd` | — |
| `wall_s_per_100_units` | 1009.3855 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
