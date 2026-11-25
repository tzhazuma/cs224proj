# Extension metrics: `coverage_instrumented_dynamic`

- generated: `2026-11-22T14:10:33Z`
- extension: `ext.coverage_instrumented_dynamic.v1`
- runs: `{'run': 'next_dynamic_coverage_test140_v2_20261122'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `valid` | 58 |
| `by_status` | {"ok": 58, "inconclusive": 82} |
| `tiers` | {"line_complete": 113, "partial": 6, "branch_complete": 21} |
| `tiers_by_label` | {"bad": {"line_complete": 49, "branch_complete": 21}, "good": {"line_complete": 64, "partial": 6}} |
| `branch_complete_bad` | 21 |
| `branch_complete_good` | 0 |
| `mean_line_coverage` | 0.9989379887119073 |
| `mean_branch_coverage` | 0.5273109243697479 |
| `latent_bad` | 12 |
| `latent_branch_complete` | 2 |
| `latent_realloc_evidence` | 7 |

## Primary

- **branch_complete_rate**: 0.1500 (n=140, CI 0.1003–0.2184, Wilson interval over units)
- note: 21/140 units are branch-complete; all 21 are bad

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |

## Limitations

- Line coverage is near 100% but branch coverage is about 50%; covering a line does not exercise the leak path.
- No clean unit reaches branch-complete coverage, so clean is inconclusive, never TN.
- The 12 latent bad units are not recovered by line coverage; 7 need the realloc-failure injection.
- Single run; gcov instrumentation can perturb timing but not leak verdicts.
