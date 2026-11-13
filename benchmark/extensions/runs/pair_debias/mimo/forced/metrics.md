# Extension metrics: `position_debiased_pair`

- generated: `2026-11-13T17:36:32Z`
- extension: `ext.position_debiased_pair.v1`
- runs: `{'fwd': 'ext_pair_debias_mimo_forced_fwd', 'rev': 'ext_pair_debias_mimo_forced_rev'}`

## Counts

| field | value |
| --- | --- |
| `pairs_all` | 180 |
| `pairs_in_both_orders` | 180 |
| `pairs_valid_both_orders` | 180 |
| `pairs_only_ab` | 0 |
| `pairs_only_ba` | 0 |
| `records_fwd` | 360 |
| `records_rev` | 360 |
| `by_status_fwd` | {"ok": 360} |
| `by_status_rev` | {"ok": 360} |

## Primary

- **position_avg_pair_da**: 0.8417 (n=180, CI 0.7972–0.8806, cluster percentile bootstrap (pair_id))
- note: Mean of AB and BA pair DA; the two presentations are not independent.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `position_avg_pair_da` | 0.8417 | 180 | 0.7972 | 0.8806 | cluster percentile bootstrap |
| `order_consensus_pair_da` | 0.7444 | 180 | 0.6778 | 0.8056 | cluster percentile bootstrap |
| `order_consistency` | 0.8056 | 180 | 0.7389 | 0.8556 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.9056 | 180 | 0.8611 | 0.9444 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.7778 | 180 | 0.7167 | 0.8333 | cluster percentile bootstrap |
| `position_bias_index` | 0.1278 | 180 | 0.0667 | 0.1944 | cluster percentile bootstrap |
| `order_flip_rate` | 0.1944 | 180 | 0.1444 | 0.2611 | cluster percentile bootstrap |
| `flip_to_correct` | 0.0722 | 180 | — | — | wilson |
| `flip_to_wrong` | 0.1222 | 180 | — | — | wilson |
| `order_da_fwd` | 0.8667 | 180 | — | — | wilson |
| `order_da_rev` | 0.8167 | 180 | — | — | wilson |
| `debiased_minus_order_avg` | -0.0972 | 180 | — | — | derived |

## Limitations

- Each pair is presented twice; pair_id is the resampling unit, not the presentation.
- Order swap removes slot bias but not length bias; inspect length_audit before claiming a pure position effect.
- position_avg_pair_da estimates expected accuracy under a random presentation order; order_consensus_pair_da is a stricter stability endpoint and is always <= position_avg_pair_da.
- Both presentations come from one model configuration; run-to-run variance is not estimated.
- The paired runs are not independent of the single-order runs used in earlier pair-joint reports.
