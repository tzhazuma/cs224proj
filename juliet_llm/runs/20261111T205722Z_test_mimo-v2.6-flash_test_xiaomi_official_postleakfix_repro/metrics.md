# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro`
- Model: `mimo-v2.6-flash`
- Endpoint: `https://api.xiaomimimo.com/v1`
- Prompt: `juliet-llm-binary-2026-11-12.2`
- Units: 140 (valid 140, invalid 0, coverage 1.0000)
- Requests: 140; status {'ok': 140}
- Reference-price cost: 0.0031 USD (https://opencode.ai/zen/go/v1/models snapshot 2026-11-11T20:57:22+00:00)
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 2.5962 / 6.1492 / 23.6995 s

| Metric | Strict (all 140) | Valid-only (140) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 68 / 5 / 65 / 2 | 68 / 5 / 65 / 2 |
| Accuracy | 0.9500 | 0.9500 |
| Precision | 0.9315 | 0.9315 |
| Recall | 0.9714 | 0.9714 |
| Specificity | 0.9286 | 0.9286 |
| F1 | 0.9510 | 0.9510 |
| Balanced accuracy | 0.9500 | 0.9500 |
| MCC | 0.9008 | 0.9008 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 58 | 0.9310 | 0.9310 | 0.9310 | 0.9310 |
| cpp | 82 | 0.9634 | 0.9647 | 0.9634 | 0.9647 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 77410.0000 | 140 | 0 |
| Completion tokens | 6827.0000 | 140 | 0 |
| Reasoning tokens | 0.0000 | 140 | 0 |
| Cached prompt tokens | 70464.0000 | 136 | 4 |
| Total tokens | 84237.0000 | 140 | 0 |

## Requests

- Status counts: `{"ok": 140}`
- Error types: `{}`
- Invalid reasons: `{}`
