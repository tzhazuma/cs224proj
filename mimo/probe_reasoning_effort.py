"""One-off compatibility probe: does reasoning_effort="none" disable MiMo reasoning?

Run manually in WSL: python3 mimo/probe_reasoning_effort.py
It reads the OpenCode Go key from the Kimi Code config, never prints it, and
prints only status, usage, and content. Not used by run_mimo.sh.
"""

import json
import time
import tomllib

import httpx

with open("/mnt/c/Users/tzh03/.kimi-code/config.toml", "rb") as stream:
    config = tomllib.load(stream)
provider = config["providers"]["opencode-go"]
key = provider["api_key"].strip()

body = {
    "model": "mimo-v2.6-flash",
    "messages": [
        {
            "role": "user",
            "content": (
                "Return only JSON with keys is_vulnerable, confidence, rationale. "
                "Function:\nint add(int a, int b) { return a + b; }"
            ),
        }
    ],
    "temperature": 0.0,
    "max_completion_tokens": 512,
    "stream": False,
    "thinking": {"type": "disabled"},
    "reasoning_effort": "none",
}
started = time.monotonic()
response = httpx.post(
    "https://opencode.ai/zen/go/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "secvul-eval-runner/1.0",
        "x-opencode-session": "ses_probe_reasoning_effort_0001",
    },
    json=body,
    timeout=300.0,
)
elapsed = time.monotonic() - started
print("status", response.status_code, "elapsed", round(elapsed, 1))
try:
    data = response.json()
except Exception:
    print("non-json body", response.text[:500])
else:
    usage = data.get("usage") or {}
    message = ((data.get("choices") or [{}])[0].get("message") or {})
    print("usage", json.dumps(usage, ensure_ascii=False))
    print("finish", (data.get("choices") or [{}])[0].get("finish_reason"))
    print("message keys", sorted(message))
    print("content", (message.get("content") or "")[:300])
    print("reasoning chars", len(message.get("reasoning") or ""))
