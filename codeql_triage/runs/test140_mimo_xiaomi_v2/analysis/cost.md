# Cost and latency — mimo-v2.6-flash-xiaomi-v2

Prices are the configured list prices used by the earlier runs, not the provider invoice.

| condition | n | valid | cost USD | prompt tokens | completion tokens | cached prompt tokens | cache hits | p50 s | p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| direct | 140 | 140 | 0.0030214576 | 77410 | 6676 | 70592 | 0 | 2.8332 | 5.7280 |
| triage | 140 | 140 | 0.030544500000000002 | 171675 | 23250 | 0 | 0 | 6.9133 | 14.1956 |
| verify | 91 | 91 | 0.012228720000000002 | n/a | n/a | n/a | 0 | 3.7974 | 6.4862 |

The zero-cost query/rule baselines have no API cost. A cost-per-removed-FP or cost-per-retained-TP number is only meaningful together with the TP-deletion table; it is reported in `summary.json` via the raw totals rather than as a headline.