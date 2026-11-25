# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:11Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_alloc_or_mem_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 34 |

## Primary

- **macro_f1**: 0.3874 (n=160, CI 0.3237–0.5304, cluster percentile bootstrap (project))
- note: rule:alloc_or_mem: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.1833 | — | — | — | point estimate |
| `balanced_accuracy` | 0.5938 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.2125 | — | — | — | point estimate |
| `strict_accuracy` | 0.3875 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 0.9412 |
| `recall` | 0.2500 |
| `specificity` | 0.9375 |
| `f1` | 0.3951 |
| `macro_f1` | 0.3874 |
| `balanced_accuracy` | 0.5938 |
| `mcc` | 0.1833 |
| `strict_accuracy` | 0.3875 |
| `confusion` | TP 32 / FP 2 / TN 30 / FN 96 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
