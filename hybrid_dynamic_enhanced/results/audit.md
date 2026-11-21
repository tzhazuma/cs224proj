# Artifact audit

Status **PASS** · 12/12 checks passed.

| check | result | detail |
| --- | --- | --- |
| `preflight` | PASS | {"ok": true, "checks": 13, "failed": []} |
| `inputs` | PASS | {"units": 140, "sha256": "061546a40e5dd66d7a1fca2dd23dd1ec250d4705a48651dca1eb757488976dce"} |
| `evidence_sanitized` | PASS | {"errors": [], "units": 140} |
| `run_deepseek_complete` | PASS | {"records": 140, "unique": 140, "counts": {"ok": 140, "invalid": 0, "api_error": 0}, "prompt_version": "hde-juliet-llm-binary-2026-11-14.1", "cost": {"configured_usd": 0.011165106, "provider_list_usd": 0.01116554, "al... |
| `run_mimo_complete` | PASS | {"records": 140, "unique": 140, "counts": {"ok": 140, "invalid": 0, "api_error": 0}, "prompt_version": "hde-juliet-llm-binary-2026-11-14.1", "cost": {"configured_usd": 0.012395437600000002, "provider_list_usd": 0.0123... |
| `prompt_and_label_integrity` | PASS | {"errors": [], "checked": 280} |
| `cost_arithmetic` | PASS | {"errors": []} |
| `metrics_recomputed` | PASS | {"errors": []} |
| `predictions_csv` | PASS | {"rows": 1400} |
| `secret_scan` | PASS | {"key_available": true, "files_scanned": 20, "hits": []} |
| `baselines_untouched` | PASS | {"files": 50, "newer_than_new_run": [], "run_start_epoch": 1794589656.41552} |
| `report_present` | PASS | {"chars": 14172} |

The audit never prints or stores the credential; it checks that the key literal is absent from every generated file.
