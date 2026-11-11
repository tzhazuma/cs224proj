# SecVulEval run comparison

> **Warning:** runs use different datasets; rows are not directly comparable

| Run | Dataset | Strategy | Task | Model | Records | Det. valid | Precision | Recall | F1 | Pair disc. (valid) | Repair complete / valid | Cost USD | p95 latency (s) |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| test_v1_mimo_direct_independent | independent | direct | both | mimo-v2.6-flash | 288/288 | 150 | 0.8056 | 0.2417 | 0.3718 | n/a | 124/127 | $0.072601 | 37.2992 |
| test_v1_mimo_direct_pairs | pairs | direct | both | mimo-v2.6-flash | 540/540 | 331 | 0.5595 | 0.2866 | 0.3790 | 0.0909 | 177/178 | $0.114282 | 33.4644 |
| test_v1_mimo_few-shot_independent | independent | few-shot | both | mimo-v2.6-flash | 288/288 | 160 | 0.7727 | 0.2656 | 0.3953 | n/a | 124/127 | $0.093808 | 53.9304 |
| test_v1_mimo_few-shot_pairs | pairs | few-shot | both | mimo-v2.6-flash | 540/540 | 360 | 0.5534 | 0.3167 | 0.4028 | 0.0944 | 177/178 | $0.150298 | 40.9316 |
| test_v1_mimo_context_independent | independent | context | both | mimo-v2.6-flash | 288/288 | 153 | 0.8611 | 0.2520 | 0.3899 | n/a | 125/127 | $0.074962 | 35.1122 |
| test_v1_mimo_context_pairs | pairs | context | both | mimo-v2.6-flash | 540/540 | 345 | 0.5769 | 0.3468 | 0.4332 | 0.1145 | 177/178 | $0.117203 | 29.7985 |
| test_v1_direct_independent | independent | direct | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8261 | 0.2969 | 0.4368 | n/a | 108/109 | $0.253340 | 18.2899 |
| test_v1_direct_pairs | pairs | direct | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5856 | 0.3611 | 0.4467 | 0.1167 | 151/151 | $0.392245 | 19.3417 |
| test_v1_few-shot_independent | independent | few-shot | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8367 | 0.3203 | 0.4633 | n/a | 125/127 | $0.429938 | 18.6251 |
| test_v1_few-shot_pairs | pairs | few-shot | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5603 | 0.3611 | 0.4392 | 0.0889 | 177/178 | $0.701446 | 17.7415 |
| test_v1_context_independent | independent | context | both | deepseek-v4.1-flash | 288/288 | 160 | 0.8125 | 0.3047 | 0.4432 | n/a | 107/108 | $0.259777 | 19.7173 |
| test_v1_context_pairs | pairs | context | both | deepseek-v4.1-flash | 540/540 | 360 | 0.5868 | 0.3944 | 0.4718 | 0.1222 | 149/149 | $0.402474 | 20.1841 |

Detection precision/recall/F1 use valid predictions only. `null` cost means prices were not configured or usage was incomplete. A `(partial)` row used `--limit` and is not a full-dataset result.
