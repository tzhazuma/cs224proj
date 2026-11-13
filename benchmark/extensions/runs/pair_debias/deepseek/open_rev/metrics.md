# Extension metrics: `open_choice_pair`

- generated: `2026-11-13T17:36:35Z`
- extension: `ext.open_choice_pair.v1`
- runs: `{'run': 'ext_pair_debias_deepseek_open_rev'}`

## Counts

| field | value |
| --- | --- |
| `pairs` | 180 |
| `valid_pairs` | 180 |
| `decisive_pairs` | 149 |
| `correct_pairs` | 115 |
| `records` | 360 |
| `choice_counts_valid` | {"A": 85, "neither": 24, "both": 7, "B": 64} |
| `by_status` | {"ok": 360} |

## Primary

- **pair_da**: 0.6389 (n=180, CI 0.5667–0.7111, cluster percentile bootstrap (pair_id))
- note: Open-choice is a different task from forced choice; both/neither count as pair errors.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `pair_da` | 0.6389 | 180 | 0.5667 | 0.7111 | cluster percentile bootstrap |
| `pair_da_all` | 0.6389 | 180 | — | — | wilson |
| `pair_da_decisive` | 0.7718 | 149 | 0.6978 | 0.8403 | cluster percentile bootstrap |
| `decisive_rate` | 0.8278 | 180 | 0.7722 | 0.8835 | cluster percentile bootstrap |
| `decisive_rate_all` | 0.8278 | 180 | — | — | wilson |
| `both_rate` | 0.0389 | 180 | 0.0111 | 0.0668 | cluster percentile bootstrap |
| `neither_rate` | 0.1333 | 180 | 0.0833 | 0.1833 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.8400 | 75 | 0.7534 | 0.9231 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.7027 | 74 | 0.5941 | 0.8028 | cluster percentile bootstrap |
| `position_bias_index` | 0.1373 | 149 | 0.0103 | 0.2735 | cluster percentile bootstrap |

## Limitations

- Open-choice is a different task: forced choice has no both/neither answer. Do not subtract open-choice pair_da from forced-choice DA without stating the task change.
- Both and neither are substantive answers counted as pair errors; report decisive_rate and pair_da_decisive next to pair_da.
- The four-way distribution is design- and prompt-dependent; it is not an estimate of the natural prevalence of both/neither.
- One run per model/configuration; run-to-run variance is not estimated.
