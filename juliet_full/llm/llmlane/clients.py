"""HTTP clients: DeepSeek and Qwen (OpenAI-compatible chat) and Jev (TypeSafe System One).

stdlib only (urllib). Keys are read from cs224proj/.env at runtime and never logged;
error bodies are redacted before they are stored.
"""

from __future__ import annotations

import json
import random
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import ENV_PATH

DEEPSEEK_BASE = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-flash"
QWEN_BASE = "http://10.15.89.184:8001/v1"
QWEN_MODEL = "qwen3.5-4b"
JEV_BASE = "https://api.typesafe.ai/v1"
JEV_MODEL = "jev-latest"

RETRYABLE_HTTP = {408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524}
FATAL_HTTP = {401, 402, 403}  # bad key, no balance, forbidden: stop the whole run


def read_env_key(name: str) -> str:
    for line in ENV_PATH.read_text().splitlines():
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)", line)
        if match and not line.lstrip().startswith("#") and match.group(1) == name:
            return match.group(2).strip().strip('"').strip("'")
    raise KeyError(f"{name} not found in {ENV_PATH}")


def _redact(text: str, secret: str | None) -> str:
    if secret:
        text = text.replace(secret, "[REDACTED]")
    return re.sub(r"(?i)bearer\s+[A-Za-z0-9._\-]+", "Bearer [REDACTED]", text)


class FatalApiError(RuntimeError):
    """The run must stop (auth/balance problem or thinking mode detected).

    ``result`` holds the call record (with usage, if the provider billed it)."""

    result: "CallResult | None" = None


@dataclass
class CallResult:
    status: str  # "ok" | "error" | "timeout"
    content: str | None = None  # chat text; for Jev the JSON of the answer
    score: float | None = None  # Jev noul probability
    usage: dict[str, Any] | None = None
    model: str | None = None
    latency_s: float = 0.0  # wall time including retries
    attempts: list[dict[str, Any]] = field(default_factory=list)
    http_status: int | None = None
    error: str | None = None
    finish_reason: str | None = None
    raw: dict[str, Any] | None = None
    started_utc: float = 0.0
    ended_utc: float = 0.0


@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_seconds: float = 2.0
    cap_seconds: float = 60.0
    timeout_seconds: float = 180.0

    def delay(self, attempt: int, retry_after: float = 0.0) -> float:
        backoff = min(self.cap_seconds, self.base_seconds * 2 ** (attempt - 1))
        return max(backoff * (0.75 + 0.5 * random.random()), min(retry_after, self.cap_seconds))


def http_json(method: str, url: str, key: str | None, body: dict[str, Any] | None,
              timeout: float, headers: dict[str, str] | None = None) -> tuple[int, Any, dict[str, str]]:
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        hdrs["Authorization"] = f"Bearer {key}"
    hdrs.update(headers or {})
    request = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(text), dict(response.headers)
            except ValueError:
                return response.status, _redact(text[:800], key), dict(response.headers)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        return exc.code, _redact(text[:800], key), dict(exc.headers or {})


def _post_with_retries(url: str, key: str | None, body: dict[str, Any], policy: RetryPolicy,
                       handle_ok: Callable[[dict[str, Any], CallResult], None],
                       stop: threading.Event | None, headers: dict[str, str] | None = None) -> CallResult:
    result = CallResult(status="error", started_utc=time.time())
    started = time.monotonic()
    for attempt in range(1, policy.max_attempts + 1):
        t0 = time.monotonic()
        retry_after = 0.0
        try:
            status, payload, resp_headers = http_json("POST", url, key, body, policy.timeout_seconds, headers)
        except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as exc:
            kind = "timeout" if "timed out" in str(exc).lower() or isinstance(exc, TimeoutError) else "transport"
            result.attempts.append({"attempt": attempt, "latency_s": time.monotonic() - t0, "error": kind,
                                    "detail": _redact(f"{type(exc).__name__}: {exc}", key)[:300]})
            result.status, result.error = ("timeout" if kind == "timeout" else "error"), kind
        else:
            result.http_status = status
            entry = {"attempt": attempt, "latency_s": time.monotonic() - t0, "http_status": status}
            result.attempts.append(entry)
            if status == 200 and isinstance(payload, dict):
                try:
                    handle_ok(payload, result)
                except FatalApiError as exc:
                    result.status, result.error = "error", "fatal"
                    result.latency_s, result.ended_utc = time.monotonic() - started, time.time()
                    exc.result = result
                    raise
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    result.status, result.error = "error", f"malformed response: {exc}"
                    entry["error"] = result.error
                else:
                    result.status = "ok"
                    break
            else:
                detail = payload if isinstance(payload, str) else json.dumps(payload)[:800]
                entry["detail"] = detail
                result.status, result.error = "error", f"http_{status}"
                if status in FATAL_HTTP:
                    result.latency_s, result.ended_utc = time.monotonic() - started, time.time()
                    fatal = FatalApiError(f"HTTP {status} from {url}: {detail[:200]}")
                    fatal.result = result
                    raise fatal
                if status not in RETRYABLE_HTTP and status != 200:  # 200 here = non-JSON body
                    break
                try:
                    retry_after = float(resp_headers.get("Retry-After") or resp_headers.get("retry-after") or 0)
                except ValueError:
                    retry_after = 0.0
        if attempt < policy.max_attempts and not (stop is not None and stop.is_set()):
            time.sleep(policy.delay(attempt, retry_after))
        else:
            break
    result.latency_s = time.monotonic() - started
    result.ended_utc = time.time()
    return result


class ChatClient:
    """OpenAI-compatible /chat/completions client used for DeepSeek and the Qwen vLLM server."""

    def __init__(self, provider: str, base_url: str, model: str, api_key: str | None,
                 extra_body: dict[str, Any], policy: RetryPolicy | None = None,
                 response_format_json: bool = True) -> None:
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._key = api_key
        self.extra_body = extra_body
        self.policy = policy or RetryPolicy()
        self.response_format_json = response_format_json

    def request_body(self, messages: list[dict[str, str]], max_tokens: int) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": 0,
                                "max_tokens": max_tokens, "stream": False, **self.extra_body}
        if self.response_format_json:
            body["response_format"] = {"type": "json_object"}
        return body

    def public_config(self) -> dict[str, Any]:
        return {"provider": self.provider, "base_url": self.base_url, "model": self.model,
                "temperature": 0, "extra_body": self.extra_body,
                "response_format": "json_object" if self.response_format_json else None,
                "retry": vars(self.policy)}

    def complete(self, messages: list[dict[str, str]], max_tokens: int,
                 stop: threading.Event | None = None, json_mode: bool | None = None) -> CallResult:
        body = self.request_body(messages, max_tokens)
        if json_mode is False:
            body.pop("response_format", None)

        def handle_ok(payload: dict[str, Any], result: CallResult) -> None:
            usage = payload.get("usage") or {}
            details = usage.get("completion_tokens_details") or {}
            message = payload["choices"][0]["message"]
            reasoning_text = message.get("reasoning_content") or message.get("reasoning")
            result.usage = usage
            result.model = payload.get("model")
            reasoning_tokens = details.get("reasoning_tokens") or usage.get("reasoning_tokens") or 0
            if reasoning_tokens or reasoning_text:
                raise FatalApiError(f"{self.provider}: reasoning output present "
                                    f"(reasoning_tokens={reasoning_tokens}); thinking mode is on")
            result.content = message.get("content")
            result.finish_reason = payload["choices"][0].get("finish_reason")
            result.raw = {"id": payload.get("id"), "model": payload.get("model"),
                          "system_fingerprint": payload.get("system_fingerprint"), "usage": usage,
                          "finish_reason": result.finish_reason, "content": result.content}

        return _post_with_retries(f"{self.base_url}/chat/completions", self._key, body, self.policy,
                                  handle_ok, stop)

    def list_models(self, timeout: float = 10.0) -> Any:
        status, payload, _ = http_json("GET", f"{self.base_url}/models", self._key, None, timeout)
        return status, payload


def deepseek_client(policy: RetryPolicy | None = None) -> ChatClient:
    return ChatClient("deepseek", DEEPSEEK_BASE, DEEPSEEK_MODEL, read_env_key("DEEPSEEK_API_KEY"),
                      {"thinking": {"type": "disabled"}}, policy)


def qwen_client(base_url: str = QWEN_BASE, model: str = QWEN_MODEL,
                policy: RetryPolicy | None = None, response_format_json: bool = True) -> ChatClient:
    return ChatClient("qwen", base_url, model, None,
                      {"chat_template_kwargs": {"enable_thinking": False}}, policy, response_format_json)


def deepseek_balance() -> dict[str, Any] | None:
    try:
        status, payload, _ = http_json("GET", f"{DEEPSEEK_BASE}/user/balance",
                                       read_env_key("DEEPSEEK_API_KEY"), None, 20)
    except (urllib.error.URLError, OSError):
        return None
    return payload if status == 200 and isinstance(payload, dict) else None


class JevClient:
    def __init__(self, model: str = JEV_MODEL, policy: RetryPolicy | None = None,
                 long_context: bool = False) -> None:
        self.model = model
        self._key = read_env_key("TYPESAFE_API_KEY")
        self.policy = policy or RetryPolicy()
        self.headers = {"TypeSafe-Danger-Zone-Long-Context": "true"} if long_context else {}

    def public_config(self) -> dict[str, Any]:
        return {"provider": "jev", "base_url": JEV_BASE, "model": self.model,
                "headers": sorted(self.headers), "retry": vars(self.policy)}

    def list_models(self, timeout: float = 20.0) -> Any:
        status, payload, _ = http_json("GET", f"{JEV_BASE}/models", self._key, None, timeout)
        return status, payload

    def ask(self, state: str, question: dict[str, Any], name: str = "leak",
            stop: threading.Event | None = None) -> CallResult:
        body = {"model": self.model, "state": state, "questions": {name: question}}

        def handle_ok(payload: dict[str, Any], result: CallResult) -> None:
            answer = payload["answers"][name]
            probability = float(answer["noul"])
            if not 0.0 <= probability <= 1.0:
                raise ValueError(f"noul out of range: {probability}")
            result.score = probability
            result.usage = payload.get("usage")
            result.model = payload.get("model")
            result.content = json.dumps(answer)
            result.raw = {"model": result.model, "usage": result.usage, "answer": answer}

        return _post_with_retries(f"{JEV_BASE}/systemone", self._key, body, self.policy, handle_ok, stop,
                                  self.headers)
