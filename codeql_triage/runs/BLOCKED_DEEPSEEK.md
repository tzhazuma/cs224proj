# DeepSeek blocked — no experimental result

Date: 2026-11-22 (Asia/Shanghai). Scope: real API attempts from WSL.

| attempt | provider | model | HTTP | provider error | artifact |
| --- | --- | --- | ---: | --- | --- |
| official | `https://api.deepseek.com` | `deepseek-flash` | 402 | `Insufficient Balance` | `runs/blocked_deepseek_official_v1/` |
| OpenCode Go | `https://opencode.ai/zen/go/v1` | `deepseek-v4.1-flash` | 401 | `api_key_expired` | `runs/blocked_deepseek_opencode_go_v1/` |

Additional probes (not stored as run directories):

- Qwen Token Plan `https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`: `deepseek-v4-pro`, `deepseek-v4-flash-0731`, `deepseek-v4-pro-0813`, `deepseek-v4.1-flash`, `deepseek-v4.1-flash-1017` all returned `403 AccessDenied` / `Access to model denied`.
- OpenCode free tier `deepseek-v4.1-flash-free` returned `426 UpgradeRequired` (client 1.17.20) or `429 FreeUsageLimitError` when a 1.19.6 client header was used without a paid key.
- No local Ollama / LM Studio / vLLM DeepSeek endpoint was running.

The two run directories contain only **one** failed request each. Their `manifest.json` records
`status_counts: {"error": 1}` and `cost_usd: null`; they must not be reported as 140-unit
DeepSeek results. The `validation_errors: {"...": "empty_content"}` entry is a downstream
parse consequence of the HTTP error, not a model schema failure.

Rerun commands after the credential/balance is restored are in `../HANDOFF.md` §4.
