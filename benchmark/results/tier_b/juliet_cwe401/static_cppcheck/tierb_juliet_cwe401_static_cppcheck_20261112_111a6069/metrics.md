# Benchmark metrics: `tierb_juliet_cwe401_static_cppcheck_20261112_111a6069`

- protocol: `1.0.0`
- tier / track: `B` / `juliet_cwe401`
- generated: `2026-11-11T19:17:13Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 200 |
| `planned_units` | 200 |
| `by_task` | {'leak_detection': 200} |
| `by_status` | {'ok': 200} |
| `missing_units` | 0 |

## Leak detection (CWE-401)

| metric | value |
| --- | ---: |
| `n` | 200 |
| `valid` | 200 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.8824 |
| `recall` | 0.3000 |
| `specificity` | 0.9600 |
| `f1` | 0.4478 |
| `macro_f1` | 0.5848 |
| `mcc` | 0.3461 |
| `strict_accuracy` | 0.6300 |

Coverage-inconclusive records: `0` (threshold `0.8`)

### Coverage strata

| stratum | n | valid | recall | specificity | macro_f1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ge_0.90` | 0 | 0 | — | — | — |
| `0.50_0.90` | 0 | 0 | — | — | — |
| `lt_0.50` | 0 | 0 | — | — | — |
| `unknown` | 200 | 200 | 0.3000 | 0.9600 | 0.5848 |

## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | — |
| `usd_unknown_records` | 200 |
| `usd_complete` | false |
| `wall_s_sum` | 8.9694 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | — |
| `completion_tokens_sum` | — |
| `latency_ms_p50` | 43.5530 |
| `latency_ms_p95` | 61.1186 |
| `cost_per_100_units_usd` | — |
| `cost_per_true_positive_usd` | — |
| `wall_s_per_100_units` | 4.4847 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
