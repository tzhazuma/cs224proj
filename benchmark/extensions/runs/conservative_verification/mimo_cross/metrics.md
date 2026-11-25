# Extension metrics: `conservative_verification`

- generated: `2026-11-22T13:28:48Z`
- extension: `ext.conservative_verification.v1`
- runs: `{'run': 'next_conservative_mimo_cross_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 158 |
| `by_status` | {"ok": 158, "schema_invalid": 2} |
| `verifier_status` | {"not_sent": 102, "ok": 57, "error": 1} |
| `assessment` | {"None": 103, "insufficient": 39, "supported": 15, "unsupported": 3} |
| `retractions` | 3 |
| `retracted_tp` | 2 |
| `retracted_fp` | 1 |

## Primary

- **macro_f1**: 0.4040 (n=158, CI 0.3017–0.5733, cluster percentile bootstrap (project))
- note: post-verifier valid-only detection; negatives unchanged

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | -0.0028 | — | — | — | point estimate |
| `mcc` | 0.0265 | — | — | — | point estimate |
| `strict_accuracy` | 0.4125 | — | — | — | point estimate |

## Limitations

- Exploratory and post hoc: the 160 test functions were already used by the first pass and the original verifier.
- Only schema-valid first-pass positives were sent to the verifier; first-pass invalid records stay invalid.
- The verifier output is model text; grounding checks line numbers, not semantic domination.
- Four retractions are too few to estimate retraction precision precisely; the 25% point estimate has a wide interval.
- Single run, temperature 0; no seed variance.
