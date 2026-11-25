# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:07Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_calls_high_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 67 |

## Primary

- **macro_f1**: 0.4158 (n=160, CI 0.3601–0.4912, cluster percentile bootstrap (project))
- note: rule:calls_high: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | -0.0190 | — | — | — | point estimate |
| `balanced_accuracy` | 0.4883 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.4188 | — | — | — | point estimate |
| `strict_accuracy` | 0.4437 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.7910 |
| `recall` | 0.4141 |
| `specificity` | 0.5625 |
| `f1` | 0.5436 |
| `macro_f1` | 0.4158 |
| `balanced_accuracy` | 0.4883 |
| `mcc` | -0.0190 |
| `strict_accuracy` | 0.4437 |
| `confusion` | TP 53 / FP 14 / TN 18 / FN 75 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
