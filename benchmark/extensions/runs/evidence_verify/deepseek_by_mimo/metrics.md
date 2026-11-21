# Extension metrics: `evidence_retraction`

- generated: `2026-11-13T17:16:25Z`
- extension: `ext.evidence_retraction.v1`
- runs: `{'run': 'ext_evidence_retraction_deepseek_by_mimo'}`

## Counts

| field | value |
| --- | --- |
| `units` | 160 |
| `first_pass_positive` | 60 |
| `retracted` | 26 |
| `sustained` | 32 |
| `verifier_invalid` | 2 |
| `fail_closed` | 2 |
| `by_status` | {"ok": 159, "schema_invalid": 1} |

## Primary

- **macro_f1**: 0.3522 (n=159, CI 0.2656–0.5586, cluster percentile bootstrap (project))
- note: Post-verification valid-only macro-F1; exploratory post-hoc, test seen.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `delta_macro_f1` | -0.0701 | 160 | -0.1319 | 0.0328 | cluster percentile bootstrap |

## Limitations

- Exploratory post-hoc: the 160 test functions were already used for the first-pass evidence run; this is not an independent confirmation.
- Only positive first-pass predictions are verified; negatives are unchanged by construction.
- Invalid/missing verifier output is fail-closed (retract), so a verifier API failure can look like a correct false-positive removal. The count is reported.
- The verifier sees source plus the first-pass claim, not the dataset label; claim construction and prompt are fixed per arm.
- Four arms are correlated (same 160 units); do not pool them as independent samples.
