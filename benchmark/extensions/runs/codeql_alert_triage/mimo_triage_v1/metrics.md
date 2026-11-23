# Extension metrics: `codeql_alert_triage`

- generated: `2026-11-22T13:28:35Z`
- extension: `ext.codeql_alert_triage.v1`
- runs: `{'run': 'next_codeql_triage_mimo_v1_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `valid` | 140 |
| `codeql_alerts` | 91 |
| `by_status` | {"ok": 140} |

## Primary

- **macro_f1**: 0.8999 (n=140, CI 0.8326–0.9565, cluster percentile bootstrap (case_family))
- note: triage_v1: valid-only leak detection; clean and bad are both scored

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.8013 | — | — | — | point estimate |
| `strict_accuracy` | 0.9000 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 140 |
| `valid` | 140 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.9242 |
| `recall` | 0.8714 |
| `specificity` | 0.9286 |
| `f1` | 0.8971 |
| `macro_f1` | 0.8999 |
| `balanced_accuracy` | 0.9000 |
| `mcc` | 0.8013 |
| `strict_accuracy` | 0.9000 |
| `confusion` | TP 61 / FP 5 / TN 65 / FN 9 |

## Limitations

- The verifier sees the first-pass JSON; the verified condition is not an independent blind review.
- The text rule and the verified condition produce identical predictions on this split.
- DeepSeek has no results; MiMo numbers are not imputed to DeepSeek.
- All 23 CodeQL false positives are C++ good units from cpp/memory-may-not-be-freed.
- Two CodeQL false negatives are compile-error units; triage cannot recover them.
- Single sample, temperature 0; no calibration or human adjudication.
