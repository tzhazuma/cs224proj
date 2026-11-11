# Juliet LLM binary detection — mimo-v2.6-flash

- Run: `mimo_legacy_max_tokens`
- Model: `mimo-v2.6-flash`
- Prompt: `juliet-llm-binary-2026-11-12.1`
- Units: 4 (valid 4, invalid 0, coverage 1.0000)
- Requests: 4; status {'ok': 4}
- Published-price cost: 0.0001 USD
- API list cost: n/a USD
- API Go allowance: n/a USD
- Latency p50/p95/max: 3.2102 / 3.4891 / 3.4971 s

| Metric | Strict (all 4) | Valid-only (4) |
| --- | ---: | ---: |
| TP / FP / TN / FN | 1 / 0 / 2 / 1 | 1 / 0 / 2 / 1 |
| Accuracy | 0.7500 | 0.7500 |
| Precision | 1.0000 | 1.0000 |
| Recall | 0.5000 | 0.5000 |
| Specificity | 1.0000 | 1.0000 |
| F1 | 0.6667 | 0.6667 |
| Balanced accuracy | 0.7500 | 0.7500 |
| MCC | 0.5774 | 0.5774 |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| c | 2 | 0.5000 | 0.0000 | 0.5000 | 0.0000 |
| cpp | 2 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | 2600.0000 | 4 | 0 |
| Completion tokens | 191.0000 | 4 | 0 |
| Reasoning tokens | 0.0000 | 4 | 0 |
| Cached prompt tokens | 2432.0000 | 4 | 0 |
| Total tokens | 2791.0000 | 4 | 0 |

## Requests

- Status counts: `{"ok": 4}`
- Error types: `{}`
- Invalid reasons: `{}`
