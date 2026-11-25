# Cost and latency — mimo-v2.6-flash-xiaomi-v1

Prices are the configured list prices used by the earlier runs, not the provider invoice.

| condition | n | valid | cost USD | prompt tokens | completion tokens | cached prompt tokens | cache hits | p50 s | p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| direct | 140 | 140 | 0.0126142352 | 77410 | 6534 | 384 | 0 | 2.4515 | 9.9291 |
| triage | 140 | 140 | 0.025050530400000003 | 131075 | 24305 | 768 | 0 | 6.8812 | 10.3802 |

The zero-cost query/rule baselines have no API cost. A cost-per-removed-FP or cost-per-retained-TP number is only meaningful together with the TP-deletion table; it is reported in `summary.json` via the raw totals rather than as a headline.