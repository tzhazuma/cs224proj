# Extension metrics: `codeql_alert_triage`

- generated: `2026-11-22T13:28:38Z`
- extension: `ext.codeql_alert_triage.v1`
- runs: `{'run': 'next_codeql_triage_mimo_v2_verified_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `valid` | 140 |
| `codeql_alerts` | 91 |
| `by_status` | {"ok": 140} |

## Primary

- **macro_f1**: 0.9857 (n=140, CI 0.9637–1.0000, cluster percentile bootstrap (case_family))
- note: verified: valid-only leak detection; clean and bad are both scored

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.9718 | — | — | — | point estimate |
| `strict_accuracy` | 0.9857 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 140 |
| `valid` | 140 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 1.0000 |
| `recall` | 0.9714 |
| `specificity` | 1.0000 |
| `f1` | 0.9855 |
| `macro_f1` | 0.9857 |
| `balanced_accuracy` | 0.9857 |
| `mcc` | 0.9718 |
| `strict_accuracy` | 0.9857 |
| `confusion` | TP 68 / FP 0 / TN 70 / FN 2 |

## Limitations

- The verifier sees the first-pass JSON; the verified condition is not an independent blind review.
- The text rule and the verified condition produce identical predictions on this split.
- DeepSeek has no results; MiMo numbers are not imputed to DeepSeek.
- All 23 CodeQL false positives are C++ good units from cpp/memory-may-not-be-freed.
- Two CodeQL false negatives are compile-error units; triage cannot recover them.
- Single sample, temperature 0; no calibration or human adjudication.
