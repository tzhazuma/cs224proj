# Extension metrics: `diff_guided_pair`

- generated: `2026-11-22T13:54:55Z`
- extension: `ext.diff_guided_pair.v1`
- runs: `{'run': 'next_pair_diff_mimo_diff_rev_20261122'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 179 |
| `side_records` | 360 |
| `both` | 0 |
| `neither` | 42 |
| `decisive` | 137 |
| `by_status` | {"ok": 358, "schema_invalid": 2} |

## Primary

- **pair_da**: 0.6704 (n=179, CI 0.5986–0.7350, Wilson interval over pairs)
- note: vulnerable side predicted true and fixed side predicted false

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6704 | — | — | — | point estimate |
| `committed_da` | 0.8759 | — | — | — | point estimate |
| `decisive_rate` | 0.7654 | — | — | — | point estimate |
| `abstention_rate` | 0.2346 | — | — | — | point estimate |
| `both_rate` | 0.0000 | — | — | — | point estimate |
| `neither_rate` | 0.2346 | — | — | — | point estimate |
| `position_delta_a_minus_b` | -0.0969 | — | — | — | point estimate |

## Limitations

- The control block matches token length but is empty; it changes caution as well as content.
- The diff direction is fixed A-to-B and follows the slot swap; it can introduce a target-side prior.
- The open-choice arm is a cross-design reference from open_choice_pair, never pooled.
- Length strata and matched subsets are post-hoc diagnostics, not pre-registered baselines.
- Single greedy decode, temperature 0; no seed variance.
