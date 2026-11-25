# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:13Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_lr_unweighted_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 159 |

## Primary

- **macro_f1**: 0.4425 (n=160, CI 0.4113–0.4595, cluster percentile bootstrap (project))
- note: lr_unweighted: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | -0.0397 | — | — | — | point estimate |
| `balanced_accuracy` | 0.4961 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.9938 | — | — | — | point estimate |
| `strict_accuracy` | 0.7937 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.7987 |
| `recall` | 0.9922 |
| `specificity` | 0.0000 |
| `f1` | 0.8850 |
| `macro_f1` | 0.4425 |
| `balanced_accuracy` | 0.4961 |
| `mcc` | -0.0397 |
| `strict_accuracy` | 0.7937 |
| `confusion` | TP 127 / FP 32 / TN 0 / FN 1 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
