# Benchmark metrics: `legacy__test_v1_mimo_context_pairs`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:32Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 360 |
| `planned_units` | 360 |
| `by_task` | {'pair_detection': 360} |
| `by_status` | {'ok': 345, 'schema_invalid': 15} |
| `missing_units` | 0 |

## Pair discrimination

| metric | value |
| --- | ---: |
| `n_pairs` | 180 |
| `valid_pairs` | 166 |
| `invalid_pairs` | 14 |
| `missing_pairs` | 0 |
| `coverage` | 0.9222 |
| `joint_accuracy_valid_pairs` | 0.1145 |
| `joint_accuracy_all_pairs` | 0.1056 |
| `consistent_rate` | 0.1325 |
| `swapped_rate` | 0.0181 |

Joint categories: `{'vulnerable_detected_fixed_clean': 19, 'both_flagged': 38, 'both_clean': 106, 'vulnerable_missed_fixed_flagged': 3}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0500 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 1803.3487 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 327406 |
| `completion_tokens_sum` | 28958 |
| `latency_ms_p50` | 4287.0378 |
| `latency_ms_p95` | 9991.3001 |
| `cost_per_100_units_usd` | 0.0278 |
| `cost_per_true_positive_usd` | — |
| `wall_s_per_100_units` | 1001.8604 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
