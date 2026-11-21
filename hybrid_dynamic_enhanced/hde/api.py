"""Credential handling and model calls.

The key is read from the local Kimi Code config into process memory only.  It
is never printed, never written to a result, and every stored response body is
redacted by ``secvul_runner``.
"""

from __future__ import annotations

import os
import tomllib
from typing import Any
from urllib.parse import urlsplit

from secvul_runner.client import ApiConfig, ChatClient, normalize_endpoint

from .config import KIMI_CONFIG, MODEL_CONFIGS, PROVIDER


def load_api_key() -> str:
    with KIMI_CONFIG.open("rb") as stream:
        config = tomllib.load(stream)
    provider = config.get("providers", {}).get(PROVIDER)
    if not isinstance(provider, dict):
        raise SystemExit(f"provider {PROVIDER!r} not found in {KIMI_CONFIG}")
    key = provider.get("api_key")
    if not isinstance(key, str) or not key.strip():
        raise SystemExit(f"provider {PROVIDER!r} has no usable API key")
    return key.strip()


def api_config(model_key: str) -> ApiConfig:
    spec = MODEL_CONFIGS[model_key]
    return ApiConfig(
        base_url=spec["base_url"],
        endpoint=normalize_endpoint(spec["base_url"]),
        model=spec["model"],
        temperature=0.0,
        max_tokens=spec["max_tokens"],
        timeout_seconds=spec["timeout_seconds"],
        max_attempts=3,
        backoff_base_seconds=1.5,
        backoff_cap_seconds=30.0,
        response_format="json_object",
        thinking=spec["thinking"],
        reasoning_effort=spec["reasoning_effort"],
        max_tokens_field=spec["max_tokens_field"],
        input_price_usd_per_1m=spec["input_price_usd_per_1m"],
        output_price_usd_per_1m=spec["output_price_usd_per_1m"],
        cached_input_price_usd_per_1m=spec["cached_input_price_usd_per_1m"],
    )


def ensure_direct_network(base_url: str) -> dict[str, Any]:
    """Bypass the host proxy for the API host.

    The WSL shell inherits ``HTTP_PROXY=http://127.0.0.1:7890`` from Windows,
    where that loopback proxy is not the one the Windows host exposes.  The
    endpoint is directly reachable, so the host is added to NO_PROXY.  Only the
    host name is recorded; no environment value is written to disk.
    """
    host = urlsplit(base_url).hostname or ""
    if not host:
        raise SystemExit(f"cannot parse API host from {base_url!r}")
    changed = False
    for variable in ("NO_PROXY", "no_proxy"):
        current = [item for item in os.environ.get(variable, "").split(",") if item]
        if host not in current:
            current.append(host)
            os.environ[variable] = ",".join(current)
            changed = True
    return {"host": host, "no_proxy_extended": changed}


def chat(client: ChatClient, messages: list[dict[str, str]]) -> Any:
    return client.complete(messages)
