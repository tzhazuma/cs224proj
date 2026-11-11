# Benchmark metrics: `legacy__test_v1_mimo_direct_pairs`

- protocol: `1.0.0`
- tier / track: `A` / `secvuleval`
- generated: `2026-11-11T19:20:34Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 360 |
| `planned_units` | 360 |
| `by_task` | {'pair_detection': 360} |
| `by_status` | {'ok': 331, 'schema_invalid': 29} |
| `missing_units` | 0 |

## Pair discrimination

| metric | value |
| --- | ---: |
| `n_pairs` | 180 |
| `valid_pairs` | 154 |
| `invalid_pairs` | 26 |
| `missing_pairs` | 0 |
| `coverage` | 0.8556 |
| `joint_accuracy_valid_pairs` | 0.0909 |
| `joint_accuracy_all_pairs` | 0.0778 |
| `consistent_rate` | 0.1234 |
| `swapped_rate` | 0.0325 |

Joint categories: `{'vulnerable_detected_fixed_clean': 14, 'both_flagged': 27, 'both_clean': 108, 'vulnerable_missed_fixed_flagged': 5}`


## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | 0.0483 |
| `usd_unknown_records` | 0 |
| `usd_complete` | true |
| `wall_s_sum` | 1992.5278 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | 304372 |
| `completion_tokens_sum` | 28681 |
| `latency_ms_p50` | 4444.0029 |
| `latency_ms_p95` | 10311.9257 |
| `cost_per_100_units_usd` | 0.0268 |
| `cost_per_true_positive_usd` | — |
| `wall_s_per_100_units` | 1106.9599 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
