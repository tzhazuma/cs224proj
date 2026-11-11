# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official`
- Model: `mimo-v2.6-flash`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 140 (valid 140, invalid 0, coverage 1.0000)
- Requests: 140; status {'ok': 140}
- Published-price cost: 0.0116 USD
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 3.1730 / 38.9035 / 62.3739 s

| Metric | Strict (all 140) | Valid-only (140) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 67 / 4 / 66 / 3 | 67 / 4 / 66 / 3 |
| Accuracy | 0.9500 | 0.9500 |
| Precision | 0.9437 | 0.9437 |
| Recall | 0.9571 | 0.9571 |
| Specificity | 0.9429 | 0.9429 |
| F1 | 0.9504 | 0.9504 |
| Balanced accuracy | 0.9500 | 0.9500 |
| MCC | 0.9001 | 0.9001 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 58 | 0.9310 | 0.9286 | 0.9310 | 0.9286 |
| cpp | 82 | 0.9634 | 0.9647 | 0.9634 | 0.9647 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 77416.0000 | 140 | 0 |
| Completion tokens | 6409.0000 | 140 | 0 |
| Reasoning tokens | 0.0000 | 140 | 0 |
| Cached prompt tokens | 7872.0000 | 30 | 110 |
| Total tokens | 83825.0000 | 140 | 0 |

## Requests

- Status counts: `{"ok": 140}`
- Error types: `{}`
- Invalid reasons: `{}`
