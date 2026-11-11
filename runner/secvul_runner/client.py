"""OpenAI-compatible Chat Completions client with bounded retries and OpenCode session headers."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
DEFAULT_USER_AGENT = "secvul-eval-runner/1.0"
SESSION_HEADER = "x-opencode-session"
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}")


class ApiConfigurationError(ValueError):
    """Raised for an invalid endpoint or generation configuration."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def generate_session_id() -> str:
    """Return a non-secret, per-run session identifier for OpenCode Go routing."""
    return f"ses_{secrets.token_hex(16)}"


def session_id_sha256(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def is_valid_session_id(value: Any) -> bool:
    return isinstance(value, str) and _SESSION_ID_RE.fullmatch(value) is not None


def normalize_endpoint(base_url: str) -> str:
    candidate = base_url.strip()
    if not candidate:
        raise ApiConfigurationError("base URL must not be empty")
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ApiConfigurationError("base URL must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise ApiConfigurationError("base URL must not contain credentials; use --api-key-env")
    path = parts.path.rstrip("/")
    if path.endswith("/chat/completions"):
        endpoint_path = path
    else:
        endpoint_path = f"{path}/chat/completions"
    return urlunsplit((parts.scheme, parts.netloc, endpoint_path, parts.query, ""))


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def request_fingerprint(
    *,
    endpoint: str,
    body: dict[str, Any],
    task: str,
    strategy: str,
    prompt_version: str,
) -> str:
    identity = {
        "endpoint": endpoint,
        "body": body,
        "task": task,
        "strategy": strategy,
        "prompt_version": prompt_version,
    }
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
)


def redact_secrets(text: str, secret: str | None = None) -> str:
    if secret:
        text = text.replace(secret, "<redacted>")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text


@dataclass(frozen=True)
class ApiConfig:
    base_url: str
    endpoint: str
    model: str
    temperature: float = 0.0
    max_tokens: int = 8192
    timeout_seconds: float = 120.0
    max_attempts: int = 3
    backoff_base_seconds: float = 1.5
    backoff_cap_seconds: float = 30.0
    response_format: str = "json_object"
    thinking: str | None = None
    reasoning_effort: str | None = None
    max_tokens_field: str = "max_tokens"
    user_agent: str = DEFAULT_USER_AGENT
    input_price_usd_per_1m: float | None = None
    output_price_usd_per_1m: float | None = None
    cached_input_price_usd_per_1m: float | None = None

    def validate(self) -> None:
        if not self.model.strip():
            raise ApiConfigurationError("model must not be empty")
        if not 0.0 <= self.temperature <= 2.0:
            raise ApiConfigurationError("temperature must be between 0 and 2")
        if self.max_tokens <= 0:
            raise ApiConfigurationError("max_tokens must be positive")
        if self.timeout_seconds <= 0:
            raise ApiConfigurationError("timeout must be positive")
        if self.max_attempts < 1:
            raise ApiConfigurationError("max_attempts must be at least 1")
        if self.backoff_base_seconds < 0 or self.backoff_cap_seconds < 0:
            raise ApiConfigurationError("backoff values must be non-negative")
        if self.response_format not in {"json_object", "none"}:
            raise ApiConfigurationError("response_format must be json_object or none")
        if self.thinking not in {None, "default", "enabled", "disabled"}:
            raise ApiConfigurationError(
                "thinking must be one of: default, enabled, disabled (omit for model default)"
            )
        if self.max_tokens_field not in {"max_tokens", "max_completion_tokens"}:
            raise ApiConfigurationError(
                "max_tokens_field must be max_tokens or max_completion_tokens"
            )
        if self.reasoning_effort not in {None, "minimal", "low", "medium", "high", "none"}:
            raise ApiConfigurationError(
                "reasoning_effort must be one of: minimal, low, medium, high, none"
            )
        if not self.user_agent.strip():
            raise ApiConfigurationError("user_agent must not be empty")
        if any(ord(char) < 32 or ord(char) > 126 for char in self.user_agent):
            raise ApiConfigurationError(
                "user_agent must contain printable ASCII characters only (no line breaks)"
            )
        prices = (
            self.input_price_usd_per_1m,
            self.output_price_usd_per_1m,
            self.cached_input_price_usd_per_1m,
        )
        if (prices[0] is None) != (prices[1] is None):
            raise ApiConfigurationError(
                "input and output prices must be provided together, or both omitted"
            )
        if prices[2] is not None and prices[0] is None:
            raise ApiConfigurationError(
                "a cached-input price requires input and output prices as well"
            )
        for price in prices:
            if price is not None and price < 0:
                raise ApiConfigurationError("prices must be non-negative")

    def public_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "endpoint": self.endpoint,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_seconds": self.timeout_seconds,
            "max_attempts": self.max_attempts,
            "backoff_base_seconds": self.backoff_base_seconds,
            "backoff_cap_seconds": self.backoff_cap_seconds,
            "response_format": self.response_format,
            "thinking": self.thinking,
            "reasoning_effort": self.reasoning_effort,
            "max_tokens_field": self.max_tokens_field,
            "user_agent": self.user_agent,
            "input_price_usd_per_1m": self.input_price_usd_per_1m,
            "output_price_usd_per_1m": self.output_price_usd_per_1m,
            "cached_input_price_usd_per_1m": self.cached_input_price_usd_per_1m,
        }

    def price_configured(self) -> bool:
        return self.input_price_usd_per_1m is not None and self.output_price_usd_per_1m is not None


def build_body(messages: list[dict[str, str]], config: ApiConfig) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": config.model,
        "messages": [dict(message) for message in messages],
        "temperature": config.temperature,
        config.max_tokens_field: config.max_tokens,
        "stream": False,
    }
    if config.response_format == "json_object":
        body["response_format"] = {"type": "json_object"}
    if config.reasoning_effort is not None:
        body["reasoning_effort"] = config.reasoning_effort
    if config.thinking == "default":
        pass
    elif config.thinking is not None:
        body["thinking"] = {"type": config.thinking}
    elif config.model.startswith("deepseek-"):
        body["thinking"] = {"type": "disabled"}
    return body


def _selected_headers(response: httpx.Response) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key, value in response.headers.items():
        lowered = key.lower()
        if (
            lowered in {"content-type", "retry-after"}
            or lowered.startswith("x-ratelimit")
            or lowered.startswith("x-opencode")
        ):
            selected[lowered] = value
    return selected


def _usage_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _non_negative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def cached_prompt_tokens(usage: dict[str, Any] | None) -> int | None:
    """Cached prompt tokens across the provider dialects seen so far.

    DeepSeek reports ``prompt_cache_hit_tokens``; OpenAI-compatible providers
    such as MiMo report ``prompt_tokens_details.cached_tokens``; Anthropic-style
    payloads use ``cache_read_input_tokens``.
    """
    if not usage:
        return None
    for key in ("prompt_cache_hit_tokens", "cache_read_input_tokens"):
        value = _non_negative_int(usage.get(key))
        if value is not None:
            return value
    details = _usage_dict(usage.get("prompt_tokens_details"))
    if details is not None:
        value = _non_negative_int(details.get("cached_tokens"))
        if value is not None:
            return value
    return None


def reasoning_tokens(usage: dict[str, Any] | None) -> int | None:
    """Reasoning tokens when the provider reports them."""
    if not usage:
        return None
    details = _usage_dict(usage.get("completion_tokens_details"))
    if details is None:
        return None
    return _non_negative_int(details.get("reasoning_tokens"))


def compute_cost(usage: dict[str, Any] | None, config: ApiConfig) -> dict[str, Any]:
    """Return a transparent USD cost record; null unless prices were supplied."""
    result: dict[str, Any] = {
        "cost_usd": None,
        "cost_basis": "pricing_not_configured",
        "prompt_tokens": None,
        "completion_tokens": None,
        "cached_prompt_tokens": None,
    }
    if not usage:
        result["cost_basis"] = "missing_usage"
        return result
    prompt = usage.get("prompt_tokens", usage.get("input_tokens"))
    completion = usage.get("completion_tokens", usage.get("output_tokens"))
    if isinstance(prompt, bool) or not isinstance(prompt, int):
        prompt = None
    if isinstance(completion, bool) or not isinstance(completion, int):
        completion = None
    cache_hit = cached_prompt_tokens(usage)
    if cache_hit is None:
        cache_hit = 0
    result.update(
        {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "cached_prompt_tokens": cache_hit,
        }
    )
    if not config.price_configured():
        return result
    if prompt is None or completion is None:
        result["cost_basis"] = "missing_token_counts"
        return result
    if cache_hit > prompt:
        cache_hit = 0
        result["cached_prompt_tokens"] = 0
    miss = prompt - cache_hit
    if cache_hit and config.cached_input_price_usd_per_1m is None:
        cost = (
            prompt * config.input_price_usd_per_1m
            + completion * config.output_price_usd_per_1m
        ) / 1_000_000.0
        basis = "input_output_prices_cache_discount_not_modeled"
    else:
        cached_price = config.cached_input_price_usd_per_1m
        if cached_price is None:
            cached_price = config.input_price_usd_per_1m
        cost = (
            miss * config.input_price_usd_per_1m
            + cache_hit * cached_price
            + completion * config.output_price_usd_per_1m
        ) / 1_000_000.0
        basis = "input_output_prices" if cached_price is not None else "input_output_prices"
    result["cost_usd"] = cost
    result["cost_basis"] = basis
    return result


@dataclass
class ApiCallResult:
    status: str
    http_status: int | None
    content: str | None
    usage: dict[str, Any] | None
    raw_body: str | None
    attempts: list[dict[str, Any]]
    request_latency_seconds: float
    wall_seconds: float
    error: dict[str, Any] | None
    response_meta: dict[str, Any]
    cost: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "http_status": self.http_status,
            "content": self.content,
            "usage": self.usage,
            "raw_body": self.raw_body,
            "attempts": self.attempts,
            "request_latency_seconds": self.request_latency_seconds,
            "wall_seconds": self.wall_seconds,
            "error": self.error,
            "response_meta": self.response_meta,
            "cost": self.cost,
        }


class ChatClient:
    def __init__(self, config: ApiConfig, api_key: str, *, session_id: str | None = None) -> None:
        config.validate()
        if not api_key.strip():
            raise ApiConfigurationError("API key is empty")
        if session_id is not None and not is_valid_session_id(session_id):
            raise ApiConfigurationError(
                "session_id must be 8-128 characters from [A-Za-z0-9._:-] and start alphanumeric"
            )
        self.config = config
        self.session_id = session_id or generate_session_id()
        self._api_key = api_key.strip()
        self._http = httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=False,
            trust_env=True,
            headers={
                "User-Agent": config.user_agent,
                SESSION_HEADER: self.session_id,
            },
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ChatClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float:
        value = response.headers.get("retry-after")
        if not value:
            return 0.0
        try:
            seconds = float(value)
        except ValueError:
            return 0.0
        return max(0.0, seconds)

    def _sleep_before_retry(self, attempt: int, retry_after: float) -> None:
        delay = min(
            self.config.backoff_cap_seconds,
            self.config.backoff_base_seconds * (2 ** (attempt - 1)),
        )
        delay = max(delay, min(retry_after, self.config.backoff_cap_seconds))
        if delay > 0:
            time.sleep(delay)

    def complete(self, messages: list[dict[str, str]]) -> ApiCallResult:
        body = build_body(messages, self.config)
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
            SESSION_HEADER: self.session_id,
        }
        attempts: list[dict[str, Any]] = []
        total_request_latency = 0.0
        started_wall = time.monotonic()
        last_error: dict[str, Any] | None = None
        last_http_status: int | None = None
        last_raw_body: str | None = None
        last_usage: dict[str, Any] | None = None
        last_response_meta: dict[str, Any] = {}

        for attempt_number in range(1, self.config.max_attempts + 1):
            attempt_started = time.monotonic()
            started_at = utc_now_iso()
            response: httpx.Response | None = None
            raw_body: str | None = None
            usage: dict[str, Any] | None = None
            response_meta: dict[str, Any] = {}
            error_type: str | None = None
            error_message: str | None = None
            retryable = False
            http_status: int | None = None

            try:
                response = self._http.post(self.config.endpoint, json=body, headers=headers)
                http_status = response.status_code
                last_http_status = http_status
                decoded_body = response.content.decode("utf-8", errors="replace")
                raw_body = redact_secrets(decoded_body, self._api_key)
                last_raw_body = raw_body
                if response.status_code == 200:
                    try:
                        envelope = json.loads(decoded_body)
                    except json.JSONDecodeError as exc:
                        error_type = "invalid_api_json"
                        error_message = f"API response is not valid JSON: {exc}"
                        retryable = True
                    else:
                        if not isinstance(envelope, dict):
                            error_type = "invalid_api_envelope"
                            error_message = "API response is not a JSON object"
                            retryable = True
                        else:
                            choices = envelope.get("choices")
                            if not isinstance(choices, list) or not choices:
                                error_type = "missing_choices"
                                error_message = "API response has no choices"
                                retryable = True
                            else:
                                choice = choices[0]
                                message = choice.get("message") if isinstance(choice, dict) else None
                                content = message.get("content") if isinstance(message, dict) else None
                                reasoning_content = (
                                    message.get("reasoning_content")
                                    if isinstance(message, dict)
                                    else None
                                )
                                reasoning_text = (
                                    message.get("reasoning")
                                    if isinstance(message, dict)
                                    else None
                                )
                                if not isinstance(content, str) or not content.strip():
                                    error_type = "empty_content"
                                    error_message = "API response has empty message content"
                                    if isinstance(reasoning_content, str) and reasoning_content.strip():
                                        error_message += " (reasoning_content was present)"
                                    retryable = True
                                else:
                                    usage = _usage_dict(envelope.get("usage"))
                                    last_usage = usage
                                    response_meta = {
                                        "id": envelope.get("id"),
                                        "model": envelope.get("model"),
                                        "created": envelope.get("created"),
                                        "system_fingerprint": envelope.get("system_fingerprint"),
                                        "finish_reason": choice.get("finish_reason")
                                        if isinstance(choice, dict)
                                        else None,
                                        "content_chars": len(content),
                                        "reasoning_content_chars": len(reasoning_content)
                                        if isinstance(reasoning_content, str)
                                        else 0,
                                        "reasoning_chars": len(reasoning_text)
                                        if isinstance(reasoning_text, str)
                                        else 0,
                                        "reasoning_tokens": reasoning_tokens(usage),
                                    }
                                    last_response_meta = response_meta
                                    latency = time.monotonic() - attempt_started
                                    total_request_latency += latency
                                    attempts.append(
                                        {
                                            "attempt": attempt_number,
                                            "started_at": started_at,
                                            "ended_at": utc_now_iso(),
                                            "latency_seconds": latency,
                                            "http_status": http_status,
                                            "outcome": "ok",
                                            "raw_body": raw_body,
                                            "headers": _selected_headers(response),
                                        }
                                    )
                                    return ApiCallResult(
                                        status="ok",
                                        http_status=http_status,
                                        content=content,
                                        usage=usage,
                                        raw_body=raw_body,
                                        attempts=attempts,
                                        request_latency_seconds=total_request_latency,
                                        wall_seconds=time.monotonic() - started_wall,
                                        error=None,
                                        response_meta=response_meta,
                                        cost=compute_cost(usage, self.config),
                                    )
                else:
                    retryable = response.status_code in RETRYABLE_STATUS
                    error_type = f"http_{response.status_code}"
                    error_message = f"HTTP {response.status_code}"
                    last_raw_body = raw_body
            except httpx.TimeoutException as exc:
                error_type = "timeout"
                error_message = redact_secrets(f"{type(exc).__name__}: {exc}", self._api_key)
                retryable = True
            except httpx.TransportError as exc:
                error_type = "transport_error"
                error_message = redact_secrets(f"{type(exc).__name__}: {exc}", self._api_key)
                retryable = True
            except httpx.HTTPError as exc:
                error_type = "http_client_error"
                error_message = redact_secrets(f"{type(exc).__name__}: {exc}", self._api_key)
                retryable = False

            latency = time.monotonic() - attempt_started
            total_request_latency += latency
            last_error = {
                "type": error_type,
                "message": error_message,
                "retryable": retryable,
            }
            attempts.append(
                {
                    "attempt": attempt_number,
                    "started_at": started_at,
                    "ended_at": utc_now_iso(),
                    "latency_seconds": latency,
                    "http_status": http_status,
                    "outcome": "error",
                    "error_type": error_type,
                    "error_message": error_message,
                    "retryable": retryable,
                    "raw_body": raw_body,
                    "headers": _selected_headers(response) if response is not None else {},
                }
            )
            if not retryable or attempt_number >= self.config.max_attempts:
                break
            retry_after = self._retry_after_seconds(response) if response is not None else 0.0
            self._sleep_before_retry(attempt_number, retry_after)

        return ApiCallResult(
            status="error",
            http_status=last_http_status,
            content=None,
            usage=last_usage,
            raw_body=last_raw_body,
            attempts=attempts,
            request_latency_seconds=total_request_latency,
            wall_seconds=time.monotonic() - started_wall,
            error=last_error,
            response_meta=last_response_meta,
            cost=compute_cost(last_usage, self.config),
        )
