# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://api.xiaomimimo.com/v1`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 140 (valid 140, invalid 0, coverage 1.0000)
- Requests: 140; status {'ok': 140}
- Reference-price cost: 0.0044 USD (https://opencode.ai/zen/go/v1/models snapshot 2026-11-11T19:27:47+00:00)
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 2.3113 / 5.2117 / 28.5799 s

| Metric | Strict (all 140) | Valid-only (140) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 68 / 4 / 66 / 2 | 68 / 4 / 66 / 2 |
| Accuracy | 0.9571 | 0.9571 |
| Precision | 0.9444 | 0.9444 |
| Recall | 0.9714 | 0.9714 |
| Specificity | 0.9429 | 0.9429 |
| F1 | 0.9577 | 0.9577 |
| Balanced accuracy | 0.9571 | 0.9571 |
| MCC | 0.9147 | 0.9147 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 58 | 0.9483 | 0.9474 | 0.9483 | 0.9474 |
| cpp | 82 | 0.9634 | 0.9647 | 0.9634 | 0.9647 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 77416.0000 | 140 | 0 |
| Completion tokens | 6547.0000 | 140 | 0 |
| Reasoning tokens | 0.0000 | 140 | 0 |
| Cached prompt tokens | 60096.0000 | 117 | 23 |
| Total tokens | 83963.0000 | 140 | 0 |

## Requests

- Status counts: `{"ok": 140}`
- Error types: `{}`
- Invalid reasons: `{}`
