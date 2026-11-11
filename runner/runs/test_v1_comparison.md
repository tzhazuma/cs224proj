# SecVulEval run comparison

> **Warning:** runs use different datasets; rows are not directly comparable

| Run | Dataset | Strategy | Task | Model | Records | Det. valid | Precision | Recall | F1 | Pair disc. (valid) | Repair complete / valid | Cost USD | p95 latency (s) |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| test_v1_direct_independent | independent | direct | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8261 | 0.2969 | 0.4368 | n/a | 108/109 | $0.253340 | 18.2899 |
| test_v1_direct_pairs | pairs | direct | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5856 | 0.3611 | 0.4467 | 0.1167 | 151/151 | $0.392245 | 19.3417 |
| test_v1_few-shot_independent | independent | few-shot | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8367 | 0.3203 | 0.4633 | n/a | 125/127 | $0.429938 | 18.6251 |
| test_v1_few-shot_pairs | pairs | few-shot | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5603 | 0.3611 | 0.4392 | 0.0889 | 177/178 | $0.701446 | 17.7415 |
| test_v1_context_independent | independent | context | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8125 | 0.3047 | 0.4432 | n/a | 107/108 | $0.259777 | 19.7173 |
| test_v1_context_pairs | pairs | context | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5868 | 0.3944 | 0.4718 | 0.1222 | 149/149 | $0.402474 | 20.1841 |

Detection precision/recall/F1 use valid predictions only. `null` cost means prices were not configured or usage was incomplete. A `(partial)` row used `--limit` and is not a full-dataset result.
