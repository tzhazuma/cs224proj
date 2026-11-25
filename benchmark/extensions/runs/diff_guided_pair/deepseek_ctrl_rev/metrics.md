# Extension metrics: `diff_guided_pair`

- generated: `2026-11-22T13:54:49Z`
- extension: `ext.diff_guided_pair.v1`
- runs: `{'run': 'next_pair_diff_deepseek_ctrl_rev_20261122'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 180 |
| `side_records` | 360 |
| `both` | 4 |
| `neither` | 31 |
| `decisive` | 145 |
| `by_status` | {"ok": 360} |

## Primary

- **pair_da**: 0.6944 (n=180, CI 0.6237–0.7571, Wilson interval over pairs)
- note: vulnerable side predicted true and fixed side predicted false

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6944 | — | — | — | point estimate |
| `committed_da` | 0.8621 | — | — | — | point estimate |
| `decisive_rate` | 0.8056 | — | — | — | point estimate |
| `abstention_rate` | 0.1944 | — | — | — | point estimate |
| `both_rate` | 0.0222 | — | — | — | point estimate |
| `neither_rate` | 0.1722 | — | — | — | point estimate |
| `position_delta_a_minus_b` | -0.0333 | — | — | — | point estimate |

## Limitations

- The control block matches token length but is empty; it changes caution as well as content.
- The diff direction is fixed A-to-B and follows the slot swap; it can introduce a target-side prior.
- The open-choice arm is a cross-design reference from open_choice_pair, never pooled.
- Length strata and matched subsets are post-hoc diagnostics, not pre-registered baselines.
- Single greedy decode, temperature 0; no seed variance.
