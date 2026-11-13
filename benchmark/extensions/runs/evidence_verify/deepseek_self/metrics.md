# Extension metrics: `evidence_retraction`

- generated: `2026-11-13T17:11:31Z`
- extension: `ext.evidence_retraction.v1`
- runs: `{'run': 'ext_evidence_retraction_deepseek_self'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `first_pass_positive` | 60 |
| `retracted` | 54 |
| `sustained` | 6 |
| `verifier_invalid` | 0 |
| `fail_closed` | 0 |
| `by_status` | {"ok": 159, "schema_invalid": 1} |

## Primary

- **macro_f1**: 0.2181 (n=159, CI 0.1601–0.3033, cluster percentile bootstrap (project))
- note: Post-verification valid-only macro-F1; exploratory post-hoc, test seen.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | -0.2043 | 160 | -0.3208 | -0.1444 | cluster percentile bootstrap |

## Limitations

- Exploratory post-hoc: the 160 test functions were already used for the first-pass evidence run; this is not an independent confirmation.
- Only positive first-pass predictions are verified; negatives are unchanged by construction.
- Invalid/missing verifier output is fail-closed (retract), so a verifier API failure can look like a correct false-positive removal. The count is reported.
- The verifier sees source plus the first-pass claim, not the dataset label; claim construction and prompt are fixed per arm.
- Four arms are correlated (same 160 units); do not pool them as independent samples.
