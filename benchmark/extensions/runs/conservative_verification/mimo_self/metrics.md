# Extension metrics: `conservative_verification`

- generated: `2026-11-22T13:28:46Z`
- extension: `ext.conservative_verification.v1`
- runs: `{'run': 'next_conservative_mimo_self_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 158 |
| `by_status` | {"ok": 158, "schema_invalid": 2} |
| `verifier_status` | {"not_sent": 102, "ok": 56, "invalid": 2} |
| `assessment` | {"None": 104, "insufficient": 11, "supported": 45} |
| `retractions` | 0 |
| `retracted_tp` | 0 |
| `retracted_fp` | 0 |

## Primary

- **macro_f1**: 0.4067 (n=158, CI 0.3060–0.5956, cluster percentile bootstrap (project))
- note: post-verifier valid-only detection; negatives unchanged

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | 0.0000 | — | — | — | point estimate |
| `mcc` | 0.0126 | — | — | — | point estimate |
| `strict_accuracy` | 0.4188 | — | — | — | point estimate |

## Limitations

- Exploratory and post hoc: the 160 test functions were already used by the first pass and the original verifier.
- Only schema-valid first-pass positives were sent to the verifier; first-pass invalid records stay invalid.
- The verifier output is model text; grounding checks line numbers, not semantic domination.
- Four retractions are too few to estimate retraction precision precisely; the 25% point estimate has a wide interval.
- Single run, temperature 0; no seed variance.
