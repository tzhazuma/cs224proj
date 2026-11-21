# Extension metrics: `position_debiased_pair`

- generated: `2026-11-13T17:36:30Z`
- extension: `ext.position_debiased_pair.v1`
- runs: `{'fwd': 'ext_pair_debias_deepseek_forced_fwd', 'rev': 'ext_pair_debias_deepseek_forced_rev'}`

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

- **position_avg_pair_da**: 0.7722 (n=180, CI 0.7278–0.8139, cluster percentile bootstrap (pair_id))
- note: Mean of AB and BA pair DA; the two presentations are not independent.

## Metrics

| metric | value | n | CI low | CI high | method |
| --- | ---: | ---: | ---: | ---: | --- |
| `position_avg_pair_da` | 0.7722 | 180 | 0.7278 | 0.8139 | cluster percentile bootstrap |
| `order_consensus_pair_da` | 0.6167 | 180 | 0.5444 | 0.6833 | cluster percentile bootstrap |
| `order_consistency` | 0.6889 | 180 | 0.6222 | 0.7556 | cluster percentile bootstrap |
| `slot_accuracy_A` | 0.9278 | 180 | 0.8889 | 0.9611 | cluster percentile bootstrap |
| `slot_accuracy_B` | 0.6167 | 180 | 0.5444 | 0.6833 | cluster percentile bootstrap |
| `position_bias_index` | 0.3111 | 180 | 0.2444 | 0.3778 | cluster percentile bootstrap |
| `order_flip_rate` | 0.3111 | 180 | 0.2444 | 0.3778 | cluster percentile bootstrap |
| `flip_to_correct` | 0.1611 | 180 | — | — | wilson |
| `flip_to_wrong` | 0.1500 | 180 | — | — | wilson |
| `order_da_fwd` | 0.7667 | 180 | — | — | wilson |
| `order_da_rev` | 0.7778 | 180 | — | — | wilson |
| `debiased_minus_order_avg` | -0.1556 | 180 | — | — | derived |

## Limitations

- Each pair is presented twice; pair_id is the resampling unit, not the presentation.
- Order swap removes slot bias but not length bias; inspect length_audit before claiming a pure position effect.
- position_avg_pair_da estimates expected accuracy under a random presentation order; order_consensus_pair_da is a stricter stability endpoint and is always <= position_avg_pair_da.
- Both presentations come from one model configuration; run-to-run variance is not estimated.
- The paired runs are not independent of the single-order runs used in earlier pair-joint reports.
