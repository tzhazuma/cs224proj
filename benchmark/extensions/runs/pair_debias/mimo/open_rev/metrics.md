# Extension metrics: `open_choice_pair`

- generated: `2026-11-13T17:36:39Z`
- extension: `ext.open_choice_pair.v1`
- runs: `{'run': 'ext_pair_debias_mimo_open_rev'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 178 |
| `decisive_pairs` | 138 |
| `correct_pairs` | 117 |
| `records` | 360 |
| `choice_counts_valid` | {"A": 73, "neither": 33, "both": 7, "B": 65} |
| `by_status` | {"ok": 356, "schema_invalid": 4} |

## Primary

- **pair_da**: 0.6573 (n=178, CI 0.5899–0.7247, cluster percentile bootstrap (pair_id))
- note: Open-choice is a different task from forced choice; both/neither count as pair errors.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6573 | 178 | 0.5899 | 0.7247 | cluster percentile bootstrap |
| `pair_da_all` | 0.6500 | 180 | — | — | wilson |
| `pair_da_decisive` | 0.8478 | 138 | 0.7883 | 0.9030 | cluster percentile bootstrap |
| `decisive_rate` | 0.7753 | 178 | 0.7135 | 0.8316 | cluster percentile bootstrap |
| `decisive_rate_all` | 0.7667 | 180 | — | — | wilson |
| `both_rate` | 0.0393 | 178 | 0.0112 | 0.0674 | cluster percentile bootstrap |
| `neither_rate` | 0.1854 | 178 | 0.1292 | 0.2416 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.8714 | 70 | 0.7903 | 0.9420 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.8235 | 68 | 0.7353 | 0.9116 | cluster percentile bootstrap |
| `position_bias_index` | 0.0479 | 138 | -0.0709 | 0.1611 | cluster percentile bootstrap |

## Limitations

- Open-choice is a different task: forced choice has no both/neither answer. Do not subtract open-choice pair_da from forced-choice DA without stating the task change.
- Both and neither are substantive answers counted as pair errors; report decisive_rate and pair_da_decisive next to pair_da.
- The four-way distribution is design- and prompt-dependent; it is not an estimate of the natural prevalence of both/neither.
- One run per model/configuration; run-to-run variance is not estimated.
