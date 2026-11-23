"""Detector runners for the live demo. Every runner returns a `Result`; none raises.

The lane modules are imported read-only:
- juliet_full/static/run_static.py: grep_v0_pred, run_unit (Clang SA, same flags and leak mapping), evidence_row;
- juliet_full/llm/llmlane: prompts (PromptSet), clients, parse_verdict, ledger (Ledger, Budget), pricing (PeakGate);
- juliet_full/gpu/bench/bench_decide.py: QUESTION / OPTIONS of the Intern-Decision read-out.

Paid calls (DeepSeek, Jev) go through this module's own thin caller, because the off-peak gate and the budget
are enforced by llm/run_llm.py, not by the clients: the caller checks `pricing.PeakGate().check_start()` unless
--allow-peak, reserves against `ledger.Budget` (per-invocation cap + the global hard stop) and appends every call
to the shared ledger (llm/ledger.jsonl) with run_id "demo_<timestamp>" and purpose "demo". Nothing is written
under juliet_full/*/results/.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
JULIET_FULL = PROJECT_ROOT / "juliet_full"
for _path in (JULIET_FULL / "llm", JULIET_FULL / "static", JULIET_FULL / "gpu" / "bench"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_static  # noqa: E402
from llmlane import clients, pricing  # noqa: E402
from llmlane.ledger import GLOBAL_CAPS, Budget, BudgetExceeded, Ledger  # noqa: E402
from llmlane.parse import parse_verdict  # noqa: E402
from llmlane.prompts import PromptAuditError, PromptSet  # noqa: E402

FT_URL = "http://10.15.89.184:8003"
INTERN_URL = "http://10.15.89.184:8002"
QWEN_URL = "http://10.15.89.184:8001/v1"
REMOTE_TIMEOUT_S = 10.0
HEALTH_TIMEOUT_S = 3.0
CHAT_MAX_TOKENS = 64
CLANG_TIMEOUT_S = 30.0
WORK_ROOT = Path(tempfile.gettempdir()) / "cs224_demo" / "clang_work"

# method key -> (display name, short name used in the summary line)
METHODS = {
    "grep": ("grep v0", "grep"),
    "clang": ("Clang SA 23", "Clang SA"),
    "ft": ("Decision model", "decision model"),
    "ds_l1": ("DeepSeek L1", "DeepSeek L1"),
    "ds_l3": ("DeepSeek L3", "DeepSeek L3"),
    "jev": ("Jev L1", "Jev"),
}
METHOD_NOTES = {
    "grep": "no free/delete in code → leak",
    "clang": "unix.Malloc · NewDeleteLeaks",
    "ds_l1": "deepseek-flash · code only",
    "ds_l3": "deepseek-flash · + Clang SA warnings",
    "jev": "jev-latest · code only",
}
PAID = {"ds_l1": "deepseek", "ds_l3": "deepseek", "jev": "jev"}

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # LAN endpoints: never via a proxy


@dataclass
class Result:
    method: str
    status: str  # ok | invalid | error | timeout | offline | skipped | compile_error
    pred: int | None = None
    score: float | None = None
    score_kind: str | None = None  # "p" (probability of leak) or "logit" (FT score, compare to threshold)
    threshold: float | None = None
    latency_ms: float | None = None
    backend: str | None = None  # what actually answered (model / fallback)
    detail: str | None = None  # one short line for the table
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Result":
        return cls(**data)


def lan_json(method: str, url: str, body: dict[str, Any] | None, timeout: float) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with _NO_PROXY.open(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:300]
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text[:300]


def utc_iso(ts: float | None = None) -> str:
    moment = datetime.fromtimestamp(ts, timezone.utc) if ts else datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class DemoContext:
    """Settings and shared state of one demo invocation (budgets, decision backend, ledger)."""

    def __init__(self, run_id: str, allow_peak: bool = False, allow_eval: bool = False,
                 max_cost_cny: float = 0.02, max_cost_usd: float = 0.002, ft_url: str = FT_URL,
                 intern_url: str = INTERN_URL, qwen_url: str = QWEN_URL, ft_fold: int = 0,
                 ft_strategy: str = "L1", ledger: Ledger | None = None) -> None:
        self.run_id = run_id
        self.allow_peak = allow_peak
        self.allow_eval = allow_eval
        self.caps = {"deepseek": max_cost_cny, "jev": max_cost_usd}
        self.ft_url, self.intern_url, self.qwen_url = ft_url.rstrip("/"), intern_url.rstrip("/"), qwen_url.rstrip("/")
        self.ft_fold = ft_fold
        self.ft_strategy = ft_strategy
        self.ledger = ledger or Ledger()
        self._lock = threading.Lock()
        self._budgets: dict[str, Budget] = {}
        self._decision: tuple[str, Any] | None = None
        self.spent = {"deepseek": 0.0, "jev": 0.0}

    # ---------------------------------------------------------------- budgets / ledger
    def budget(self, provider: str) -> Budget:
        with self._lock:
            if provider not in self._budgets:
                self._budgets[provider] = Budget(provider, self.caps[provider], self.ledger.spent(provider))
            return self._budgets[provider]

    def log_call(self, provider: str, model: str, strategy: str, unit: dict[str, Any], result: Any,
                 cost: float, peak: bool | None) -> None:
        self.ledger.append({
            "kind": "call", "ts_utc": utc_iso(result.ended_utc or None), "run_id": self.run_id, "purpose": "demo",
            "provider": provider, "model_requested": model, "model_returned": result.model, "strategy": strategy,
            "set": unit.get("set") or "custom", "layer": "demo", "unit_id": unit["unit_id"],
            "status": result.status, "http_status": result.http_status, "attempts": len(result.attempts),
            "usage": result.usage, "peak_price": peak, "cost": round(cost, 10),
            "currency": "CNY" if provider == "deepseek" else "USD"})
        with self._lock:
            self.spent[provider] += cost

    # ---------------------------------------------------------------- decision model backend
    def decision_backend(self) -> tuple[str, Any]:
        """("ft", [models]) | ("intern", info) | ("qwen", info) | ("offline", reasons); probed once per run."""
        with self._lock:
            if self._decision is None:
                self._decision = probe_decision_backend(self.ft_url, self.intern_url, self.qwen_url)
            return self._decision


def probe_decision_backend(ft_url: str, intern_url: str, qwen_url: str) -> tuple[str, Any]:
    reasons = []
    for name, url, check in (
            ("ft", f"{ft_url}/health", lambda p: isinstance(p, dict) and p.get("ok") and p.get("models")),
            ("intern", f"{intern_url}/health", lambda p: isinstance(p, dict) and p.get("status") == "ok"),
            ("qwen", f"{qwen_url}/models", lambda p: isinstance(p, dict) and p.get("data"))):
        try:
            status, payload = lan_json("GET", url, None, HEALTH_TIMEOUT_S)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reasons.append(f"{name}: {type(exc).__name__}")
            continue
        if status == 200 and check(payload):
            return name, (payload.get("models") if name == "ft" else payload)
        reasons.append(f"{name}: HTTP {status}")
    return "offline", reasons


def ms_since(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


# -------------------------------------------------------------------- offline methods
def run_grep(unit: dict[str, Any]) -> Result:
    t0 = time.perf_counter()
    row = run_static.grep_v0_pred(run_static.make_unit(unit), "demo")
    latency = ms_since(t0)
    detail = "free/delete found" if row["pred"] == 0 else "no free/delete"
    return Result("grep", "ok", pred=row["pred"], latency_ms=latency, detail=detail)


def run_clang(unit: dict[str, Any]) -> tuple[Result, dict[str, Any] | None]:
    """Clang SA verdict plus the L3 evidence record (schema of run_static.evidence_row)."""
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    work_root = Path(tempfile.mkdtemp(prefix="run_", dir=WORK_ROOT))
    cfg = run_static.Config(tool="clang_sa", bins={"clang": str(run_static.DEFAULT_BINS["clang"])},
                            tu_mode="wrapper", timeout=CLANG_TIMEOUT_S, work_root=work_root, keep_work=False,
                            codeql_cache=work_root)
    try:
        static_unit = run_static.make_unit(unit)
        t0 = time.perf_counter()
        row, raw = run_static.run_unit(cfg, "demo", static_unit)
        latency = ms_since(t0)
        evidence = run_static.evidence_row(static_unit, raw.get("findings") or []) if row["status"] == "ok" else None
    except Exception as exc:  # noqa: BLE001
        return Result("clang", "error", detail=f"{type(exc).__name__}: {exc}"[:120]), None
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    if row["status"] != "ok":
        errors = (raw.get("errors") or [""])[0]
        return Result("clang", row["status"], latency_ms=latency, detail=errors[-120:]), None
    warnings = evidence["warnings"] if evidence else []
    if warnings:
        first = warnings[0]
        where = f"line {first['model_text_line']}: " if first.get("model_text_line") else ""
        detail = where + first["message"]
    else:
        detail = "no leak warning"
    return (Result("clang", "ok", pred=row["pred"], latency_ms=latency, detail=detail[:90],
                   extra={"warnings": warnings}), evidence)


# -------------------------------------------------------------------- decision model (LAN)
def run_decision(ctx: DemoContext, unit: dict[str, Any]) -> Result:
    kind, info = ctx.decision_backend()
    if kind == "offline":
        return Result("ft", "offline", backend="decision model: offline", detail="; ".join(info))
    t0 = time.perf_counter()
    try:
        if kind == "ft":
            fold = unit.get("fold") if unit.get("fold") is not None else ctx.ft_fold
            wanted = f"qwen3.5-4b-lora-{ctx.ft_strategy}-fold{fold}"
            models = [str(m) for m in info]
            model = wanted if wanted in models else next((m for m in models if f"-{ctx.ft_strategy}-" in m), models[0])
            status, payload = lan_json("POST", f"{ctx.ft_url}/score", {
                "code": unit["model_text"], "language": unit["language"], "strategy": ctx.ft_strategy,
                "evidence": None, "model": model}, REMOTE_TIMEOUT_S)
            latency = ms_since(t0)
            if status != 200 or not isinstance(payload, dict):
                return Result("ft", "error", latency_ms=latency, backend=model, detail=f"HTTP {status}")
            note = "" if model == wanted else f" (wanted {wanted})"
            return Result("ft", "ok", pred=int(payload["pred"]), score=float(payload["score"]), score_kind="logit",
                          threshold=float(payload["threshold"]), latency_ms=latency,
                          backend=f"{payload.get('model', model)}{note}",
                          extra={"latency_ms_server": payload.get("latency_ms_server")})
        if kind == "intern":
            import bench_decide  # QUESTION / OPTIONS of the gpu lane's read-out
            status, payload = lan_json("POST", f"{ctx.intern_url}/decide", {
                "state": unit["model_text"], "question": bench_decide.QUESTION, "options": bench_decide.OPTIONS},
                REMOTE_TIMEOUT_S)
            latency = ms_since(t0)
            if status != 200 or not isinstance(payload, dict):
                return Result("ft", "error", latency_ms=latency, backend="Intern-Decision-4B (fallback)",
                              detail=f"HTTP {status}")
            p_leak = float(payload["probs"]["leak"])
            return Result("ft", "ok", pred=int(payload["decision"] == "leak"), score=p_leak, score_kind="p",
                          latency_ms=latency, backend="Intern-Decision-4B zero-shot (fallback)",
                          extra={"latency_ms_server": payload.get("latency_ms_server")})
        client = clients.qwen_client(base_url=ctx.qwen_url,
                                     policy=clients.RetryPolicy(max_attempts=1, timeout_seconds=REMOTE_TIMEOUT_S))
        messages, _ = PromptSet("L1").messages(unit)
        result = client.complete(messages, CHAT_MAX_TOKENS)
        latency = ms_since(t0)
        if result.status != "ok":
            return Result("ft", result.status, latency_ms=latency, backend="Qwen3.5-4B zero-shot (fallback)",
                          detail=result.error)
        verdict = parse_verdict(result.content)
        return Result("ft", verdict.status, pred=verdict.pred, score=verdict.score, score_kind="p",
                      latency_ms=latency, backend="Qwen3.5-4B zero-shot L1 (fallback)", detail=verdict.note)
    except (urllib.error.URLError, OSError) as exc:
        status = "timeout" if "timed out" in str(exc).lower() else "error"
        return Result("ft", status, latency_ms=ms_since(t0), backend=kind, detail=type(exc).__name__)
    except (KeyError, TypeError, ValueError, PromptAuditError, clients.FatalApiError) as exc:
        return Result("ft", "error", latency_ms=ms_since(t0), backend=kind, detail=f"{exc}"[:100])


# -------------------------------------------------------------------- paid APIs (thin caller)
def paid_gate(ctx: DemoContext, method: str, unit: dict[str, Any]) -> Result | None:
    """A `skipped` result when the call must not be made, else None."""
    if unit.get("set") == "eval" and not ctx.allow_eval:
        return Result(method, "skipped", detail="eval unit: add --allow-eval")
    if PAID[method] == "deepseek" and not ctx.allow_peak:
        try:
            pricing.PeakGate().check_start()
        except pricing.PeakHours:
            return Result(method, "skipped", detail="Beijing peak hours: add --allow-peak")
    return None


def run_deepseek(ctx: DemoContext, unit: dict[str, Any], strategy: str,
                 evidence: dict[str, Any] | None = None) -> Result:
    method = "ds_l1" if strategy == "L1" else "ds_l3"
    gated = paid_gate(ctx, method, unit)
    if gated:
        return gated
    try:
        messages, info = PromptSet(strategy).messages(unit, evidence)
    except PromptAuditError as exc:
        return Result(method, "skipped", detail=f"prompt audit: {exc}"[:100])
    estimate = pricing.deepseek_estimate_cny(sum(len(m["content"]) for m in messages), CHAT_MAX_TOKENS)
    budget = ctx.budget("deepseek")
    try:
        budget.reserve(estimate)
    except BudgetExceeded as exc:
        return Result(method, "skipped", detail=str(exc)[:100])
    try:
        client = clients.deepseek_client(clients.RetryPolicy(max_attempts=1, timeout_seconds=REMOTE_TIMEOUT_S))
    except (KeyError, OSError) as exc:
        budget.settle(estimate, 0.0)
        return Result(method, "error", detail=f"key: {type(exc).__name__}")
    fatal = None
    try:
        result = client.complete(messages, CHAT_MAX_TOKENS)
    except clients.FatalApiError as exc:
        fatal, result = str(exc)[:100], exc.result
    peak = False
    cost = 0.0
    if result is not None:
        peak = any(pricing.is_deepseek_peak(datetime.fromtimestamp(t, timezone.utc))
                   for t in (result.started_utc, result.ended_utc) if t)
        cost = pricing.deepseek_cost_cny(result.usage, peak)
        ctx.log_call("deepseek", client.model, strategy, unit, result, cost, peak)
    budget.settle(estimate, cost)
    if result is None or fatal:
        return Result(method, "error", detail=fatal or "no result")
    extra = {"cost_cny": cost, "peak_price": peak, "usage": result.usage, "content": (result.content or "")[:200],
             **info}
    latency = result.latency_s * 1000.0
    if result.status != "ok":
        return Result(method, result.status, latency_ms=latency, backend=result.model, detail=result.error,
                      extra=extra)
    verdict = parse_verdict(result.content)
    return Result(method, verdict.status, pred=verdict.pred, score=verdict.score, score_kind="p",
                  latency_ms=latency, backend=result.model, detail=verdict.note, extra=extra)


def run_jev(ctx: DemoContext, unit: dict[str, Any]) -> Result:
    gated = paid_gate(ctx, "jev", unit)
    if gated:
        return gated
    prompts = PromptSet("L1", target="jev")
    try:
        state, _ = prompts.jev_state(unit)
    except PromptAuditError as exc:
        return Result("jev", "skipped", detail=f"prompt audit: {exc}"[:100])
    estimate = pricing.jev_estimate_usd(len(state))
    budget = ctx.budget("jev")
    try:
        budget.reserve(estimate)
    except BudgetExceeded as exc:
        return Result("jev", "skipped", detail=str(exc)[:100])
    try:
        client = clients.JevClient(policy=clients.RetryPolicy(max_attempts=1, timeout_seconds=REMOTE_TIMEOUT_S))
    except (KeyError, OSError) as exc:
        budget.settle(estimate, 0.0)
        return Result("jev", "error", detail=f"key: {type(exc).__name__}")
    fatal = None
    try:
        result = client.ask(state, prompts.jev_question)
    except clients.FatalApiError as exc:
        fatal, result = str(exc)[:100], exc.result
    cost = pricing.jev_cost_usd(result.usage) if result is not None else 0.0
    if result is not None:
        ctx.log_call("jev", client.model, "L1", unit, result, cost, None)
    budget.settle(estimate, cost)
    if result is None or fatal:
        return Result("jev", "error", detail=fatal or "no result")
    latency = result.latency_s * 1000.0
    if result.status != "ok":
        return Result("jev", result.status, latency_ms=latency, detail=result.error)
    return Result("jev", "ok", pred=int(result.score >= 0.5), score=result.score, score_kind="p",
                  latency_ms=latency, backend=result.model, extra={"cost_usd": cost})
