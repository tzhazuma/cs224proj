# Extension metrics: `open_choice_pair`

- generated: `2026-11-13T17:36:34Z`
- extension: `ext.open_choice_pair.v1`
- runs: `{'run': 'ext_pair_debias_deepseek_open_fwd'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 180 |
| `decisive_pairs` | 142 |
| `correct_pairs` | 119 |
| `records` | 360 |
| `choice_counts_valid` | {"B": 66, "neither": 25, "both": 13, "A": 76} |
| `by_status` | {"ok": 360} |

## Primary

- **pair_da**: 0.6611 (n=180, CI 0.5943–0.7333, cluster percentile bootstrap (pair_id))
- note: Open-choice is a different task from forced choice; both/neither count as pair errors.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6611 | 180 | 0.5943 | 0.7333 | cluster percentile bootstrap |
| `pair_da_all` | 0.6611 | 180 | — | — | wilson |
| `pair_da_decisive` | 0.8380 | 142 | 0.7770 | 0.8978 | cluster percentile bootstrap |
| `decisive_rate` | 0.7889 | 180 | 0.7278 | 0.8500 | cluster percentile bootstrap |
| `decisive_rate_all` | 0.7889 | 180 | — | — | wilson |
| `both_rate` | 0.0722 | 180 | 0.0389 | 0.1111 | cluster percentile bootstrap |
| `neither_rate` | 0.1389 | 180 | 0.0833 | 0.1889 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.8841 | 69 | 0.8033 | 0.9565 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.7945 | 73 | 0.7031 | 0.8806 | cluster percentile bootstrap |
| `position_bias_index` | 0.0895 | 142 | -0.0304 | 0.2103 | cluster percentile bootstrap |

## Limitations

- Open-choice is a different task: forced choice has no both/neither answer. Do not subtract open-choice pair_da from forced-choice DA without stating the task change.
- Both and neither are substantive answers counted as pair errors; report decisive_rate and pair_da_decisive next to pair_da.
- The four-way distribution is design- and prompt-dependent; it is not an estimate of the natural prevalence of both/neither.
- One run per model/configuration; run-to-run variance is not estimated.
