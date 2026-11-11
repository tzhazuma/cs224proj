# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T204701Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://api.xiaomimimo.com/v1`
- Prompt: `juliet-llm-binary-2026-11-12.2`
- Units: 140 (valid 140, invalid 0, coverage 1.0000)
- Requests: 140; status {'ok': 140}
- Reference-price cost: 0.0037 USD (https://opencode.ai/zen/go/v1/models snapshot 2026-11-11T20:47:01+00:00)
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 2.5536 / 7.2788 / 10.9134 s

| Metric | Strict (all 140) | Valid-only (140) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 66 / 5 / 65 / 4 | 66 / 5 / 65 / 4 |
| Accuracy | 0.9357 | 0.9357 |
| Precision | 0.9296 | 0.9296 |
| Recall | 0.9429 | 0.9429 |
| Specificity | 0.9286 | 0.9286 |
| F1 | 0.9362 | 0.9362 |
| Balanced accuracy | 0.9357 | 0.9357 |
| MCC | 0.8715 | 0.8715 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 58 | 0.8966 | 0.8929 | 0.8966 | 0.8929 |
| cpp | 82 | 0.9634 | 0.9647 | 0.9634 | 0.9647 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 77410.0000 | 140 | 0 |
| Completion tokens | 6525.0000 | 140 | 0 |
| Reasoning tokens | 0.0000 | 140 | 0 |
| Cached prompt tokens | 65600.0000 | 132 | 8 |
| Total tokens | 83935.0000 | 140 | 0 |

## Requests

- Status counts: `{"ok": 140}`
- Error types: `{}`
- Invalid reasons: `{}`
