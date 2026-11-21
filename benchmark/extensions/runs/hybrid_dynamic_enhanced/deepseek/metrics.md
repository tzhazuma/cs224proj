# Extension metrics: `hybrid_enhanced_dynamic`

- generated: `2026-11-13T17:43:29Z`
- extension: `ext.hybrid_enhanced_dynamic.v1`
- runs: `{'run': 'ext_hybrid_enhanced_dynamic_deepseek'}`

## Counts

| field | value |
| --- | --- |
| `units` | 140 |
| `valid` | 140 |
| `by_status` | {"ok": 140} |
| `evidence_outcomes` | {"leak": 70, "clean": 70} |
| `tool_verdicts` | {"True": 70, "False": 70} |
| `overcall_vs_tool` | 3 |
| `undercall_vs_tool` | 0 |

## Primary

- **macro_f1**: 0.9786 (n=140, CI 0.9537–1.0000, cluster percentile bootstrap (case_family))
- note: Valid-only LLM leak detection with enhanced dynamic evidence.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `tool_agreement` | 0.9786 | 140 | — | — | count |
| `tool_accuracy` | 1.0000 | 140 | — | — | count |
| `overcall_vs_tool` | 3 | 140 | — | — | count |
| `undercall_vs_tool` | 0 | 140 | — | — | count |

## Limitations

- The 140/140 tool baseline makes LLM-tool agreement equal to accuracy; it is not an independent measure of evidence use.
- Enhanced dynamic evidence is sanitized but may still induce anchoring; the producer reports reason-level byte copying, not causal use.
- Frozen hybrid_v2 direct/combined baselines are from a different date/harness; compare descriptively, not as a controlled rerun.
- Single run per model; no seed/run-to-run variance.
- Do not pool with dynamic_enhanced tool metrics or canonical 140 dynamic runs.
