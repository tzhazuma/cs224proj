# Benchmark metrics: `tierb_juliet_cwe401_dynamic_asan_20261111_a1390639`

- protocol: `1.0.0`
- tier / track: `B` / `juliet_cwe401`
- generated: `2026-11-11T19:17:08Z`

## Counts

| field | value |
| --- | ---: |
| `records` | 200 |
| `planned_units` | 200 |
| `by_task` | {'leak_detection': 200} |
| `by_status` | {'ok': 199, 'inconclusive': 1} |
| `missing_units` | 0 |

## Leak detection (CWE-401)

| metric | value |
| --- | ---: |
| `n` | 200 |
| `valid` | 199 |
| `invalid` | 1 |
| `coverage` | 0.9950 |
| `precision` | 1.0000 |
| `recall` | 0.7778 |
| `specificity` | 1.0000 |
| `f1` | 0.8750 |
| `macro_f1` | 0.8880 |
| `mcc` | 0.7985 |
| `strict_accuracy` | 0.8850 |

Coverage-inconclusive records: `1` (threshold `0.8`)

### Coverage strata

| stratum | n | valid | recall | specificity | macro_f1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ge_0.90` | 0 | 0 | — | — | — |
| `0.50_0.90` | 0 | 0 | — | — | — |
| `lt_0.50` | 0 | 0 | — | — | — |
| `unknown` | 200 | 199 | 0.7778 | 1.0000 | 0.8880 |

## Cost and latency

| field | value |
| --- | ---: |
| `usd_known_sum` | — |
| `usd_unknown_records` | 200 |
| `usd_complete` | false |
| `wall_s_sum` | 438.7090 |
| `cpu_s_sum` | — |
| `peak_rss_mb_max` | — |
| `prompt_tokens_sum` | — |
| `completion_tokens_sum` | — |
| `latency_ms_p50` | 2036.0000 |
| `latency_ms_p95` | 3432.9000 |
| `cost_per_100_units_usd` | — |
| `cost_per_true_positive_usd` | — |
| `wall_s_per_100_units` | 219.3545 |

## Notes

- Valid-only metrics exclude `status != "ok"`; `strict_accuracy` counts those records as wrong.
- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.
- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.
