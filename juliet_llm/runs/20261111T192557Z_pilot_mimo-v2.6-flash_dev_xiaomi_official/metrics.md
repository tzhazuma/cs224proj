# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T192557Z_pilot_mimo-v2.6-flash_dev_xiaomi_official`
- Model: `mimo-v2.6-flash`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 8 (valid 8, invalid 0, coverage 1.0000)
- Requests: 8; status {'ok': 8}
- Published-price cost: 0.0004 USD
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 2.5788 / 4.7842 / 5.2078 s

| Metric | Strict (all 8) | Valid-only (8) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 3 / 0 / 4 / 1 | 3 / 0 / 4 / 1 |
| Accuracy | 0.8750 | 0.8750 |
| Precision | 1.0000 | 1.0000 |
| Recall | 0.7500 | 0.7500 |
| Specificity | 1.0000 | 1.0000 |
| F1 | 0.8571 | 0.8571 |
| Balanced accuracy | 0.8750 | 0.8750 |
| MCC | 0.7746 | 0.7746 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 4 | 0.7500 | 0.6667 | 0.7500 | 0.6667 |
| cpp | 4 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 4349.0000 | 8 | 0 |
| Completion tokens | 345.0000 | 8 | 0 |
| Reasoning tokens | 0.0000 | 8 | 0 |
| Cached prompt tokens | 1984.0000 | 5 | 3 |
| Total tokens | 4694.0000 | 8 | 0 |

## Requests

- Status counts: `{"ok": 8}`
- Error types: `{}`
- Invalid reasons: `{}`
