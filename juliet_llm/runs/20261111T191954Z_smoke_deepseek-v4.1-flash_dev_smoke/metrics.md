# Juliet LLM binary detection — deepseek-v4.1-flash

- Run: `20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke`
- Model: `deepseek-v4.1-flash`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 1 (valid 0, invalid 1, coverage 0.0000)
- Requests: 1; status {'error': 1}
- Published-price cost: n/a USD
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 0.9545 / 0.9545 / 0.9545 s

| Metric | Strict (all 1) | Valid-only (0) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 0 / 0 / 0 / 1 | 0 / 0 / 0 / 0 |
| Accuracy | 0.0000 | n/a |
| Precision | n/a | n/a |
| Recall | 0.0000 | n/a |
| Specificity | n/a | n/a |
| F1 | 0.0000 | 0.0000 |
| Balanced accuracy | n/a | n/a |
| MCC | 0.0000 | 0.0000 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| cpp | 1 | 0.0000 | 0.0000 | n/a | 0.0000 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | n/a | 0 | 1 |
| Completion tokens | n/a | 0 | 1 |
| Reasoning tokens | n/a | 0 | 1 |
| Cached prompt tokens | n/a | 0 | 1 |
| Total tokens | n/a | 0 | 1 |

## Requests

- Status counts: `{"error": 1}`
- Error types: `{"http_401": 1}`
- Invalid reasons: `{"http_401": 1}`
