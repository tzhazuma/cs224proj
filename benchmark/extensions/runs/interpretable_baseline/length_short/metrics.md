# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:06Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_length_short_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 90 |

## Primary

- **macro_f1**: 0.5107 (n=160, CI 0.4222–0.5617, cluster percentile bootstrap (project))
- note: rule:length_short: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.0945 | — | — | — | point estimate |
| `balanced_accuracy` | 0.5586 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.5625 | — | — | — | point estimate |
| `strict_accuracy` | 0.5750 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.8333 |
| `recall` | 0.5859 |
| `specificity` | 0.5312 |
| `f1` | 0.6881 |
| `macro_f1` | 0.5107 |
| `balanced_accuracy` | 0.5586 |
| `mcc` | 0.0945 |
| `strict_accuracy` | 0.5750 |
| `confusion` | TP 75 / FP 15 / TN 17 / FN 53 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
