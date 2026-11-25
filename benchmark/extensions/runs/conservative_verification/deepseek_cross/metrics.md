# Extension metrics: `conservative_verification`

- generated: `2026-11-22T13:28:45Z`
- extension: `ext.conservative_verification.v1`
- runs: `{'run': 'next_conservative_deepseek_cross_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 159 |
| `by_status` | {"ok": 159, "schema_invalid": 1} |
| `verifier_status` | {"not_sent": 100, "ok": 60} |
| `assessment` | {"None": 100, "supported": 44, "insufficient": 16} |
| `retractions` | 0 |
| `retracted_tp` | 0 |
| `retracted_fp` | 0 |

## Primary

- **macro_f1**: 0.4223 (n=159, CI 0.3231–0.5903, cluster percentile bootstrap (project))
- note: post-verifier valid-only detection; negatives unchanged

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | 0.0000 | — | — | — | point estimate |
| `mcc` | 0.0348 | — | — | — | point estimate |
| `strict_accuracy` | 0.4375 | — | — | — | point estimate |

## Limitations

- Exploratory and post hoc: the 160 test functions were already used by the first pass and the original verifier.
- Only schema-valid first-pass positives were sent to the verifier; first-pass invalid records stay invalid.
- The verifier output is model text; grounding checks line numbers, not semantic domination.
- Four retractions are too few to estimate retraction precision precisely; the 25% point estimate has a wide interval.
- Single run, temperature 0; no seed variance.
