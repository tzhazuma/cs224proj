# SecVulEval run comparison

> **Warning:** runs use different datasets; rows are not directly comparable
> **Warning:** at least one run is partial (--limit); do not report it as full-dataset evidence

| Run | Dataset | Strategy | Task | Model | Records | Det. valid | Precision | Recall | F1 | Pair disc. (valid) | Repair complete / valid | Cost USD | p95 latency (s) |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pilot_v1_mimo_direct_independent (partial) | independent | direct | both | mimo-v2.6-flash | 12/12 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | $0.001443 | 31.5282 |
| pilot_v1_mimo_direct_pairs (partial) | pairs | direct | both | mimo-v2.6-flash | 9/9 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | $0.001542 | 38.4060 |
| pilot_v1_mimo_few-shot_independent (partial) | independent | few-shot | both | mimo-v2.6-flash | 12/12 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | $0.001789 | 25.8085 |
| pilot_v1_mimo_few-shot_pairs (partial) | pairs | few-shot | both | mimo-v2.6-flash | 9/9 | 6 | 1.0000 | 0.3333 | 0.5000 | 0.3333 | 3/3 | $0.001559 | 17.7377 |
| pilot_v1_mimo_context_independent (partial) | independent | context | both | mimo-v2.6-flash | 12/12 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | $0.001730 | 31.9502 |
| pilot_v1_mimo_context_pairs (partial) | pairs | context | both | mimo-v2.6-flash | 9/9 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | $0.002085 | 18.8220 |
| dev_pilot_direct_independent (partial) | independent | direct | both | deepseek-v4.1-flash | 12/12 | 6 | n/a | 0.0000 | n/a | n/a | 4/4 | $0.008165 | 11.9138 |
| dev_pilot_direct_pairs (partial) | pairs | direct | both | deepseek-v4.1-flash | 9/9 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | $0.007627 | 27.5345 |
| dev_pilot_few-shot_independent (partial) | independent | few-shot | both | deepseek-v4.1-flash | 12/12 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | $0.015939 | 11.9733 |
| dev_pilot_few-shot_pairs (partial) | pairs | few-shot | both | deepseek-v4.1-flash | 9/9 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | $0.012907 | 16.6337 |
| dev_pilot_context_independent (partial) | independent | context | both | deepseek-v4.1-flash | 12/12 | 6 | 1.0000 | 0.1667 | 0.2857 | n/a | 6/6 | $0.008399 | 12.1063 |
| dev_pilot_context_pairs (partial) | pairs | context | both | deepseek-v4.1-flash | 9/9 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | $0.007828 | 16.6967 |

Detection precision/recall/F1 use valid predictions only. `null` cost means prices were not configured or usage was incomplete. A `(partial)` row used `--limit` and is not a full-dataset result.
