# Extension metrics: `interpretable_baseline`

- generated: `2026-11-22T13:29:12Z`
- extension: `ext.interpretable_baseline.v1`
- runs: `{'run': 'next_interp_short_and_alloc_or_mem_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 160 |
| `by_status` | {"ok": 160} |
| `predicted_positive` | 11 |

## Primary

- **macro_f1**: 0.2559 (n=160, CI 0.2077–0.3234, cluster percentile bootstrap (project))
- note: rule:short_and_alloc_or_mem: valid-only detection on test-160

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.1359 | — | — | — | point estimate |
| `balanced_accuracy` | 0.5430 | — | — | — | point estimate |
| `predicted_positive_rate` | 0.0688 | — | — | — | point estimate |
| `strict_accuracy` | 0.2687 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 160 |
| `valid` | 160 |
| `invalid` | 0 |
| `coverage` | 1.0000 |
| `precision` | 1.0000 |
| `recall` | 0.0859 |
| `specificity` | 1.0000 |
| `f1` | 0.1583 |
| `macro_f1` | 0.2559 |
| `balanced_accuracy` | 0.5430 |
| `mcc` | 0.1359 |
| `strict_accuracy` | 0.2687 |
| `confusion` | TP 11 / FP 0 / TN 32 / FN 117 |

## Limitations

- Lexical features only; not a static analyzer and not a semantic model.
- The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.
- MCC ranking flips the macro-F1 ranking; report both.
- Dev-40 is too small and too imbalanced to select thresholds reliably.
- Test-tuned upper bounds use test labels and are not deployable results.
