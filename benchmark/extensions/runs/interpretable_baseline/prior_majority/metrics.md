# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:03Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_prior_majority_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 160 |

## Primary

- **macro_f1**: 0.4444 (n=160, CI 0.4118–0.4603, cluster percentile bootstrap (project))
- note: rule:prior_majority: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.0000 | — | — | — | point estimate |
| `balanced_accuracy` | 0.5000 | — | — | — | point estimate |
| `predicted_positive_rate` | 1.0000 | — | — | — | point estimate |
| `strict_accuracy` | 0.8000 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.8000 |
| `recall` | 1.0000 |
| `specificity` | 0.0000 |
| `f1` | 0.8889 |
| `macro_f1` | 0.4444 |
| `balanced_accuracy` | 0.5000 |
| `mcc` | 0.0000 |
| `strict_accuracy` | 0.8000 |
| `confusion` | TP 128 / FP 32 / TN 0 / FN 0 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
