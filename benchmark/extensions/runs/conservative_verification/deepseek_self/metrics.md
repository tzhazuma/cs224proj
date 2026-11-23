# Extension metrics: `conservative_verification`

- generated: `2026-11-22T13:28:45Z`
- extension: `ext.conservative_verification.v1`
- runs: `{'run': 'next_conservative_deepseek_self_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `valid` | 159 |
| `by_status` | {"ok": 159, "schema_invalid": 1} |
| `verifier_status` | {"not_sent": 100, "ok": 60} |
| `assessment` | {"None": 100, "supported": 19, "insufficient": 40, "unsupported": 1} |
| `retractions` | 1 |
| `retracted_tp` | 1 |
| `retracted_fp` | 0 |

## Primary

- **macro_f1**: 0.4172 (n=159, CI 0.3205–0.5749, cluster percentile bootstrap (project))
- note: post-verifier valid-only detection; negatives unchanged

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | -0.0052 | — | — | — | point estimate |
| `mcc` | 0.0284 | — | — | — | point estimate |
| `strict_accuracy` | 0.4313 | — | — | — | point estimate |

## Limitations

- Exploratory and post hoc: the 160 test functions were already used by the first pass and the original verifier.
- Only schema-valid first-pass positives were sent to the verifier; first-pass invalid records stay invalid.
- The verifier output is model text; grounding checks line numbers, not semantic domination.
- Four retractions are too few to estimate retraction precision precisely; the 25% point estimate has a wide interval.
- Single run, temperature 0; no seed variance.
