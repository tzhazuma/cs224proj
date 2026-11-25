# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:08Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_alloc_unbalanced_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 12 |

## Primary

- **macro_f1**: 0.2635 (n=160, CI 0.2052–0.3521, cluster percentile bootstrap (project))
- note: rule:alloc_unbalanced: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.1424 | — | — | — | point estimate |
| `balanced_accuracy` | 0.5469 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.0750 | — | — | — | point estimate |
| `strict_accuracy` | 0.2750 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 1.0000 |
| `recall` | 0.0938 |
| `specificity` | 1.0000 |
| `f1` | 0.1714 |
| `macro_f1` | 0.2635 |
| `balanced_accuracy` | 0.5469 |
| `mcc` | 0.1424 |
| `strict_accuracy` | 0.2750 |
| `confusion` | TP 12 / FP 0 / TN 32 / FN 116 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
