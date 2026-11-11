# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `20261111T192121Z_smoke_mimo-v2.6-flash_dev_xiaomi_smoke`
- Model: `mimo-v2.6-flash`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 1 (valid 1, invalid 0, coverage 1.0000)
- Requests: 1; status {'ok': 1}
- Published-price cost: 0.0001 USD
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 5.2237 / 5.2237 / 5.2237 s

| Metric | Strict (all 1) | Valid-only (1) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 1 / 0 / 0 / 0 | 1 / 0 / 0 / 0 |
| Accuracy | 1.0000 | 1.0000 |
| Precision | 1.0000 | 1.0000 |
| Recall | 1.0000 | 1.0000 |
| Specificity | n/a | n/a |
| F1 | 1.0000 | 1.0000 |
| Balanced accuracy | n/a | n/a |
| MCC | 0.0000 | 0.0000 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| cpp | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 641.0000 | 1 | 0 |
| Completion tokens | 46.0000 | 1 | 0 |
| Reasoning tokens | 0.0000 | 1 | 0 |
| Cached prompt tokens | n/a | 0 | 1 |
| Total tokens | 687.0000 | 1 | 0 |

## Requests

- Status counts: `{"ok": 1}`
- Error types: `{}`
- Invalid reasons: `{}`
