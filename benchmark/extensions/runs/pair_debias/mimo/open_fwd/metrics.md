# Extension metrics: `open_choice_pair`

- generated: `2026-11-13T17:36:37Z`
- extension: `ext.open_choice_pair.v1`
- runs: `{'run': 'ext_pair_debias_mimo_open_fwd'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 180 |
| `decisive_pairs` | 141 |
| `correct_pairs` | 119 |
| `records` | 360 |
| `choice_counts_valid` | {"B": 80, "neither": 31, "both": 8, "A": 61} |
| `by_status` | {"ok": 360} |

## Primary

- **pair_da**: 0.6611 (n=180, CI 0.5944–0.7278, cluster percentile bootstrap (pair_id))
- note: Open-choice is a different task from forced choice; both/neither count as pair errors.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6611 | 180 | 0.5944 | 0.7278 | cluster percentile bootstrap |
| `pair_da_all` | 0.6611 | 180 | — | — | wilson |
| `pair_da_decisive` | 0.8440 | 141 | 0.7823 | 0.8993 | cluster percentile bootstrap |
| `decisive_rate` | 0.7833 | 180 | 0.7222 | 0.8444 | cluster percentile bootstrap |
| `decisive_rate_all` | 0.7833 | 180 | — | — | wilson |
| `both_rate` | 0.0444 | 180 | 0.0167 | 0.0724 | cluster percentile bootstrap |
| `neither_rate` | 0.1722 | 180 | 0.1167 | 0.2278 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.7826 | 69 | 0.6896 | 0.8732 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.9028 | 72 | 0.8260 | 0.9697 | cluster percentile bootstrap |
| `position_bias_index` | -0.1202 | 141 | -0.2334 | -0.0040 | cluster percentile bootstrap |

## Limitations

- Open-choice is a different task: forced choice has no both/neither answer. Do not subtract open-choice pair_da from forced-choice DA without stating the task change.
- Both and neither are substantive answers counted as pair errors; report decisive_rate and pair_da_decisive next to pair_da.
- The four-way distribution is design- and prompt-dependent; it is not an estimate of the natural prevalence of both/neither.
- One run per model/configuration; run-to-run variance is not estimated.
