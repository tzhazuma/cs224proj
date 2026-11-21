# Extension metrics: `new_static_tool`

- generated: `2026-11-13T18:31:21Z`
- extension: `ext.new_static_tool.v1`
- runs: `{'run': 'ext_static_codeql_cwe401_test140_20261114'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `valid` | 136 |
| `by_status` | {"ok": 136, "compile_error": 4} |
| `diagnostics` | {"raw_warning_count": 94, "dedup_warning_count": 94, "mapped_warning_count": 94, "unmapped_warning_count": 0, "out_of_scope_count": 0, "suppressed_count": 0} |
| `rules` | {"cpp/memory-may-not-be-freed": 48, "cpp/memory-never-freed": 46} |
| `severity` | {"high": 94} |

## Primary

- **macro_f1**: 0.8259 (n=136, CI 0.7884–0.8632, cluster percentile bootstrap (case_family))
- note: Valid-only static leak detection at the pre-registered any-mapped-in-scope threshold.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `mcc` | 0.7032 | — | — | — | point estimate |
| `strict_accuracy` | 0.8071 | — | — | — | point estimate |

### Detection scores

| metric | value |
| --- | ---: |
| `n` | 140 |
| `valid` | 136 |
| `invalid` | 4 |
| `coverage` | 0.9714 |
| `precision` | 0.7473 |
| `recall` | 1.0000 |
| `specificity` | 0.6618 |
| `f1` | 0.8553 |
| `macro_f1` | 0.8259 |
| `balanced_accuracy` | 0.8309 |
| `mcc` | 0.7032 |
| `strict_accuracy` | 0.8071 |
| `confusion` | TP 68 / FP 23 / TN 45 / FN 0 |

## Limitations

- A warning counts only if its rule maps to CWE-401 and its line is in the target scope; file-level warnings are not assigned to every function.
- compile_error/timeout/tool_error remain non-ok and are never y_pred=0.
- Severity is tool-specific; high-only is a within-tool sensitivity view, not a cross-tool severity comparison.
- Clang-tidy/clang-sa share an analysis engine; agreement between them is not independent validation.
- Static tools are evaluated on whole Juliet variants, not on incomplete Tier A snippets; do not compute Tier A static F1.
