# Extension metrics: `enhanced_dynamic`

- generated: `2026-11-13T17:36:19Z`
- extension: `ext.enhanced_dynamic.v1`
- runs: `{'run': 'ext_dynamic_enhanced_test140_v3'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `bad` | 70 |
| `good` | 70 |
| `leak` | 70 |
| `clean_inconclusive` | 70 |
| `clean_total` | 70 |
| `unobservable_in_default` | 12 |
| `resolved_by_enhanced_modes` | 12 |
| `evidence_modes` | {"default": 58, "nogobal": 63, "realloc_fail": 7} |
| `by_status` | {"ok": 70, "inconclusive": 70} |

## Primary

- **operational_macro_f1**: 1.0000 (n=140, CI 1.0000–1.0000, cluster percentile bootstrap (case_family))
- note: Operational view treats source clean as negative; coverage-unverified and not a protocol-valid TN.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `protocol_macro_f1` | — | 70 | — | — | cluster percentile bootstrap |
| `operational_macro_f1` | 1.0000 | 140 | 1.0000 | 1.0000 | cluster percentile bootstrap |
| `leak_recall` | 1.0000 | 70 | — | — | count |
| `clean_abstention` | 1.0000 | 70 | — | — | count |

## Limitations

- The run has no line/branch coverage instrumentation; protocol-valid clean is inconclusive, not TN.
- The 70/70 leak/clean is the producer operational view, not a protocol-valid confusion matrix. It must be labelled coverage-unverified.
- Fault injection is a realloc-failure wrapper and a global-root switch, not a fault-variant suite; do not pool with fault_injected_dynamic.
- Single run, single path per mode; no fuzzing or run-to-run variance.
- Never pool with the canonical 140-unit dynamic run or with other dynamic methods.
