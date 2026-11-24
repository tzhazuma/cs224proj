"""Detector runners for the live demo. Every runner returns a `Result`; none raises.

The lane modules are imported read-only:
- juliet_full/static/run_static.py: grep_v0_pred, run_unit (Clang SA, same flags and leak mapping), evidence_row;
- juliet_full/llm/llmlane: prompts (PromptSet), clients, parse_verdict, ledger (Ledger, Budget), pricing (PeakGate);
- juliet_full/gpu/bench/bench_decide.py: QUESTION / OPTIONS of the Intern-Decision read-out;
- juliet_full/l4d: parse_sites.parse_unit + questions.make_questions (L4-D questions; need tree-sitter), and
  juliet_full/l4d_ft/prune.py: prune (only the questions the v1 rules read) and verdict (l4d/derive.py rules).

Paid calls (DeepSeek, Jev) go through this module's own thin caller, because the off-peak gate and the budget
are enforced by llm/run_llm.py, not by the clients: the caller checks `pricing.PeakGate().check_start()` unless
--allow-peak, reserves against `ledger.Budget` (per-invocation cap + the global hard stop) and appends every call
to the shared ledger (llm/ledger.jsonl) with run_id "demo_<timestamp>" and purpose "demo". Nothing is written
under juliet_full/*/results/.
"""

from __future__ import annotations

import functools
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
L4D_DIR = JULIET_FULL / "l4d"
L4D_FT_DIR = JULIET_FULL / "l4d_ft"
for _path in (JULIET_FULL / "llm", JULIET_FULL / "static", JULIET_FULL / "gpu" / "bench", L4D_FT_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_static  # noqa: E402
from llmlane import clients, pricing  # noqa: E402
from llmlane.ledger import GLOBAL_CAPS, Budget, BudgetExceeded, Ledger  # noqa: E402
from llmlane.parse import parse_verdict  # noqa: E402
from llmlane.prompts import PromptAuditError, PromptSet  # noqa: E402
import prune as l4d_prune  # noqa: E402  (l4d_ft/prune.py; puts juliet_full/l4d on sys.path, imports derive)

try:  # the l4d-data question builder (tree-sitter parser); without it only stored questions can be used
    import parse_sites as l4d_sites  # noqa: E402
    import questions as l4d_questions  # noqa: E402
    L4D_BUILDER_ERROR: str | None = None
except ImportError as _exc:
    L4D_BUILDER_ERROR = f"{type(_exc).__name__}: {_exc}"

FT_URL = "http://10.15.89.184:8003"
INTERN_URL = "http://10.15.89.184:8002"
QWEN_URL = "http://10.15.89.184:8001/v1"
L4D_URL = "http://10.15.89.184:8004"
REMOTE_TIMEOUT_S = 10.0
HEALTH_TIMEOUT_S = 1.0  # a stopped fallback endpoint must not hold up the demo
CHAT_MAX_TOKENS = 64
CLANG_TIMEOUT_S = 30.0
WORK_ROOT = Path(tempfile.gettempdir()) / "cs224_demo" / "clang_work"

# method key -> (display name, short name used in the summary line)
METHODS = {
    "grep": ("grep v0", "grep"),
    "clang": ("Clang SA 23", "Clang SA"),
    "ft": ("FT 4B, unit labels (L1)", "FT 4B unit labels"),
    "ft_l3": ("FT 4B, unit labels (L3)", "FT 4B unit labels L3"),
    "l4d": ("L4-D (ours, FT 4B)", "L4-D"),
    "ds_l1": ("DeepSeek L1", "DeepSeek L1"),
    "ds_l3": ("DeepSeek L3", "DeepSeek L3"),
    "jev": ("Jev L1", "Jev"),
}
METHOD_NOTES = {
    "grep": "no free/delete in code → leak",
    "clang": "unix.Malloc · NewDeleteLeaks",
    "l4d": "Yes/No facts → Datalog rules",
    "ds_l1": "deepseek-flash · code only",
    "ds_l3": "deepseek-flash · + Clang warnings",
    "jev": "jev-latest · code only",
}
PAID = {"ds_l1": "deepseek", "ds_l3": "deepseek", "jev": "jev"}

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # LAN endpoints: never via a proxy


@dataclass
class Result:
    method: str
    status: str  # ok | invalid | error | timeout | offline | skipped | compile_error | n/a
    pred: int | None = None
    score: float | None = None
    score_kind: str | None = None  # "p" (probability of leak), "logit" (FT score vs threshold), "l4d" (soft score)
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
                 intern_url: str = INTERN_URL, qwen_url: str = QWEN_URL, l4d_url: str = L4D_URL, ft_fold: int = 0,
                 ledger: Ledger | None = None) -> None:
        self.run_id = run_id
        self.allow_peak = allow_peak
        self.allow_eval = allow_eval
        self.caps = {"deepseek": max_cost_cny, "jev": max_cost_usd}
        self.ft_url, self.intern_url, self.qwen_url = ft_url.rstrip("/"), intern_url.rstrip("/"), qwen_url.rstrip("/")
        self.l4d_url = l4d_url.rstrip("/")
        self.ft_fold = ft_fold
        self.ledger = ledger or Ledger()
        self._lock = threading.Lock()
        self.ft_lock = threading.Lock()  # serialises /score requests of this run (see run_decision)
        self.l4d_lock = threading.Lock()  # same for /l4d (see run_l4d)
        self._budgets: dict[str, Budget] = {}
        self._decision: tuple[str, Any] | None = None
        self._l4d: tuple[str, Any] | None = None
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

    def l4d_backend(self) -> tuple[str, Any]:
        """("l4d", /health payload) | ("offline", reason); probed once per run."""
        with self._lock:
            if self._l4d is None:
                self._l4d = probe_l4d_backend(self.l4d_url)
            return self._l4d


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


def probe_l4d_backend(l4d_url: str) -> tuple[str, Any]:
    try:
        status, payload = lan_json("GET", f"{l4d_url}/health", None, HEALTH_TIMEOUT_S)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return "offline", f"L4-D :8004 {type(exc).__name__}"
    if status == 200 and isinstance(payload, dict) and payload.get("ok") and payload.get("folds"):
        return "l4d", payload
    return "offline", f"L4-D :8004 HTTP {status}"


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
def ft_model_name(strategy: str, fold: int) -> str:
    """The decision_ft adapter for a strategy; eval units use their held-out fold (juliet_full/README.md §6)."""
    return f"qwen3.5-4b-lora-{strategy}-fold{fold}"


def run_decision(ctx: DemoContext, unit: dict[str, Any], strategy: str = "L1",
                 evidence: dict[str, Any] | None = None) -> Result:
    """Decision model: the fine-tuned endpoint (:8003 /score) first, else the zero-shot fallbacks (L1 only).

    For L3 `evidence` is the live Clang SA evidence record; the endpoint gets its `warnings` list."""
    method = "ft" if strategy == "L1" else "ft_l3"
    kind, info = ctx.decision_backend()
    if kind != "ft":  # same model, stored verdict first; the zero-shot fallbacks are other models
        fold = unit.get("fold") if unit.get("fold") is not None else ctx.ft_fold
        row = ft_stored(unit, strategy, fold)
        if row is not None:
            return Result(method, "ok", pred=int(row["pred"]), score=float(row["score"]), score_kind="logit",
                          threshold=float(row["extra"]["threshold"]), backend="stored (:8003 offline)",
                          extra={"stored_model": row.get("model"), "checkpoint": row["extra"].get("checkpoint"),
                                 "offline_reason": info})
    if kind == "offline":
        return Result(method, "offline", backend="decision model: offline", detail="; ".join(info))
    if strategy != "L1" and kind != "ft":
        return Result(method, "offline", backend="decision model L3: FT endpoint down",
                      detail=f"FT :8003 down, {kind} fallback is L1 only")
    t0 = time.perf_counter()
    try:
        if kind == "ft":
            if strategy == "L3" and evidence is None:
                return Result(method, "skipped", backend="FT L3", detail="no Clang SA evidence")
            fold = unit.get("fold") if unit.get("fold") is not None else ctx.ft_fold
            wanted = ft_model_name(strategy, fold)
            models = [str(m) for m in info]
            model = wanted if wanted in models else next((m for m in models if f"-{strategy}-" in m), models[0])
            with ctx.ft_lock:  # the endpoint serves one request at a time: time ours, not the queue
                t0 = time.perf_counter()
                status, payload = lan_json("POST", f"{ctx.ft_url}/score", {
                    "code": unit["model_text"], "language": unit["language"], "strategy": strategy,
                    "evidence": evidence["warnings"] if strategy == "L3" else None, "model": model}, REMOTE_TIMEOUT_S)
                latency = ms_since(t0)
            if status != 200 or not isinstance(payload, dict):
                detail = payload.get("detail") if isinstance(payload, dict) else payload
                return Result(method, "error", latency_ms=latency, backend=model,
                              detail=f"HTTP {status}" + (f": {detail}"[:80] if detail else ""))
            note = "" if model == wanted else f" (wanted {wanted})"
            return Result(method, "ok", pred=int(payload["pred"]), score=float(payload["score"]),
                          score_kind="logit", threshold=float(payload["threshold"]), latency_ms=latency,
                          backend=f"{payload.get('model', model)}{note}",
                          extra={key: payload.get(key) for key in ("latency_ms_server", "forward_ms", "switch_ms",
                                                                     "checkpoint", "n_tokens", "prompt_sha256")})
        if kind == "intern":
            import bench_decide  # QUESTION / OPTIONS of the gpu lane's read-out
            status, payload = lan_json("POST", f"{ctx.intern_url}/decide", {
                "state": unit["model_text"], "question": bench_decide.QUESTION, "options": bench_decide.OPTIONS},
                REMOTE_TIMEOUT_S)
            latency = ms_since(t0)
            if status != 200 or not isinstance(payload, dict):
                return Result(method, "error", latency_ms=latency, backend="Intern-Decision-4B (fallback)",
                              detail=f"HTTP {status}")
            p_leak = float(payload["probs"]["leak"])
            return Result(method, "ok", pred=int(payload["decision"] == "leak"), score=p_leak, score_kind="p",
                          latency_ms=latency, backend="Intern-Decision-4B zero-shot (fallback)",
                          extra={"latency_ms_server": payload.get("latency_ms_server")})
        client = clients.qwen_client(base_url=ctx.qwen_url,
                                     policy=clients.RetryPolicy(max_attempts=1, timeout_seconds=REMOTE_TIMEOUT_S))
        messages, _ = PromptSet("L1").messages(unit)
        result = client.complete(messages, CHAT_MAX_TOKENS)
        latency = ms_since(t0)
        if result.status != "ok":
            return Result(method, result.status, latency_ms=latency, backend="Qwen3.5-4B zero-shot (fallback)",
                          detail=result.error)
        verdict = parse_verdict(result.content)
        return Result(method, verdict.status, pred=verdict.pred, score=verdict.score, score_kind="p",
                      latency_ms=latency, backend="Qwen3.5-4B zero-shot L1 (fallback)", detail=verdict.note)
    except (urllib.error.URLError, OSError) as exc:
        status = "timeout" if "timed out" in str(exc).lower() else "error"
        return Result(method, status, latency_ms=ms_since(t0), backend=kind, detail=type(exc).__name__)
    except (KeyError, TypeError, ValueError, PromptAuditError, clients.FatalApiError) as exc:
        return Result(method, "error", latency_ms=ms_since(t0), backend=kind, detail=f"{exc}"[:100])


# -------------------------------------------------------------------- stored records (offline fallbacks)
FT_RESULTS = JULIET_FULL / "decision_ft" / "results" / "decision_ft"
L4D_BUILD = L4D_DIR / "build"
L4D_ANSWERS = L4D_FT_DIR / "results" / "lora_l4d"  # stored per-question answers (full question set)
L4D_UNITS = L4D_FT_DIR / "results" / "lora_l4d_opt"  # stored unit verdicts of the pruned ("opt") inference


@functools.lru_cache(maxsize=64)
def _stored_rows(path: Path, unit_id: str) -> tuple[dict[str, Any], ...]:
    """Rows of one unit in a big jsonl (substring scan, ~0.1 s for 68 MB; cached)."""
    if not path.exists():
        return ()
    needle = f'"unit_id": "{unit_id}"'
    with path.open() as handle:
        return tuple(json.loads(line) for line in handle if needle in line)


def stored_source(unit: dict[str, Any]) -> tuple[str, str] | None:
    """(layer, unit_id) of the stored records of this exact code: layer1 for a Juliet unit, layer3 for the
    dead-free version that equals the stored layer-3 unit; None for --file input and other transforms."""
    transform = unit.get("transform")
    if transform is None:
        return ("layer1", unit["unit_id"]) if unit.get("set") in ("dev", "eval", "train") else None
    if transform.get("kind") == "stress" and transform.get("matches_layer3"):
        return "layer3", transform["source_unit_id"]
    return None


def ft_stored(unit: dict[str, Any], strategy: str, fold: int) -> dict[str, Any] | None:
    """Stored FT unit-label verdict of this code: eval units from the held-out-fold CV run, dev units from the
    `fold` adapter's dev run (layer 1 only); None if there is none."""
    source = stored_source(unit)
    if source is None:
        return None
    layer, unit_id = source
    name = f"{strategy}_cv_v1.jsonl" if unit.get("set") == "eval" else f"dev_{strategy}_fold{fold}_v1.jsonl"
    return next((r for r in _stored_rows(FT_RESULTS / layer / name, unit_id) if r.get("status") == "ok"), None)


def l4d_stored(layer: str, unit_id: str) -> dict[str, Any]:
    """Stored questions (gold fields dropped), sites, per-qid answers and the lora_l4d_opt unit row."""
    questions = [{k: v for k, v in q.items() if k not in ("gold", "gold_source")}
                 for q in _stored_rows(L4D_BUILD / f"questions_{layer}.jsonl", unit_id)]
    sites = next(iter(_stored_rows(L4D_BUILD / f"sites_{layer}.jsonl", unit_id)), {}).get("sites", [])
    answers = {a["qid"]: a for a in _stored_rows(L4D_ANSWERS / layer / "eval_r1.jsonl", unit_id)}
    unit_row = next(iter(_stored_rows(L4D_UNITS / layer / "eval_r1_units.jsonl", unit_id)), None)
    return {"questions": questions, "sites": sites, "answers": answers, "unit_row": unit_row}


def l4d_prefetch(unit: dict[str, Any]) -> None:
    """Read the stored L4-D and FT records of a unit ahead of time (keeps the file scan out of the live run)."""
    source = stored_source(unit)
    if source is not None:
        l4d_stored(*source)
        for strategy in ("L1", "L3"):
            ft_stored(unit, strategy, 0)


@functools.lru_cache(maxsize=1)
def l4d_frozen_tau() -> dict[int, float]:
    frozen = json.loads((L4D_FT_DIR / "FROZEN").read_text())
    return {int(k): float(v["tau"]) for k, v in frozen["folds"].items()}


def l4d_site_label(site_id: str, sites: list[dict[str, Any]]) -> str:
    site = next((s for s in sites if s["site_id"] == site_id), None)
    return site_id if site is None else f"{site.get('callee') or site['kind']} L{site['line']}"


def l4d_reason(verdict: dict[str, Any], kept: list[dict[str, Any]], p_of: dict[str, float], tau: float,
               sites: list[dict[str, Any]]) -> str:
    """One short line: why the first leaked allocation leaks, or why none does (read off the derived facts)."""
    def fact(qtype: str, *ids: str) -> bool:
        q = next((q for q in kept if q["qtype"] == qtype and tuple(q["site_ids"]) == ids), None)
        return q is not None and p_of[q["qid"]] >= tau

    def releases(a: str) -> list[str]:
        return [q["site_ids"][0] for q in kept
                if q["qtype"] == "rel" and q["site_ids"][1] == a and p_of[q["qid"]] >= tau]

    label = functools.partial(l4d_site_label, sites=sites)
    if verdict["leaks"]:
        a, why = verdict["leaks"][0]
        if why == "realloc_fail":
            return "lost if realloc fails"
        paired = releases(a)
        return "runs, never freed" if not paired else f"{label(paired[0])} may not run"
    allocs = l4d_prune.derive.unit_inputs(kept)["alloc"]
    if not allocs:
        return "no allocation site"
    a = allocs[0]
    if not fact("heap", a):
        return f"{label(a)}: not heap"
    if not fact("exec_any", a):
        return f"{label(a)} never runs"
    freed_by = [f for f in releases(a) if fact("exec_all", f)]
    return f"{label(freed_by[0])} always runs" if freed_by else f"{label(a)}: no leak derived"


def run_l4d(ctx: DemoContext, unit: dict[str, Any]) -> Result:
    """L4-D: build the unit's Yes/No questions, keep the ones the v1 rules read (prune.py), ask :8004 /l4d with the
    held-out fold's adapter, threshold p_yes at the fold's tau, derive the verdict (l4d/derive.py).

    Latency = question build + prune + HTTP round trip + derive. If :8004 is down, the stored answers of the same
    questions are used (Juliet units whose code equals a stored layer-1/layer-3 unit only; latency not measured)."""
    source = stored_source(unit)
    stored = l4d_stored(*source) if source is not None else None  # untimed (prefetched by demo.py)
    fold = unit.get("fold") if unit.get("fold") is not None else ctx.ft_fold
    t0 = time.perf_counter()
    if L4D_BUILDER_ERROR is None:
        layer, unit_id = source or ("custom", unit["unit_id"])
        parsed = l4d_sites.parse_unit(unit["model_text"], unit["language"])
        questions = l4d_questions.make_questions(
            {**unit, "unit_id": unit_id, "set": unit.get("set") or "custom", "fold": unit.get("fold")}, layer,
            parsed)
        sites = parsed["sites"]
    elif stored is not None and stored["questions"]:
        questions, sites = stored["questions"], stored["sites"]
    else:
        detail = "n/a for --file" if unit.get("set") == "custom" else "no question builder"
        return Result("l4d", "n/a", backend=f"L4-D: {L4D_BUILDER_ERROR}", detail=detail)
    kept = l4d_prune.prune(questions)
    build_ms = ms_since(t0)
    question_source = "built live"
    if stored is not None and stored["questions"]:
        if questions != stored["questions"]:  # keep the evaluated question set
            questions, sites, question_source = stored["questions"], stored["sites"], "stored (live build differs)"
            kept = l4d_prune.prune(questions)
        elif L4D_BUILDER_ERROR is None:
            question_source = "built live = stored"
    extra: dict[str, Any] = {"n_questions": len(questions), "n_asked": len(kept), "fold": fold,
                             "question_source": question_source, "build_ms": build_ms,
                             "stored": None if source is None else f"{source[0]}/{source[1]}"}
    if stored is not None and stored["unit_row"] is not None:
        extra["stored_pred"] = stored["unit_row"]["pred"]
    if not kept:  # no heap block: the rules answer without a model call
        extra.update(tau=None, leaks=[])
        return Result("l4d", "ok", pred=0, score=0.0, score_kind="l4d", latency_ms=build_ms,
                      backend="rules only (no question to ask)", detail="no allocation site", extra=extra)
    kind, info = ctx.l4d_backend()
    try:
        if kind == "l4d":
            with ctx.l4d_lock:  # one request at a time on the server: time ours, not the queue
                t1 = time.perf_counter()
                status, payload = lan_json("POST", f"{ctx.l4d_url}/l4d", {
                    "fold": fold, "questions": [{k: q[k] for k in ("qid", "state", "question")} for q in kept]},
                    REMOTE_TIMEOUT_S)
                http_ms = ms_since(t1)
            if status != 200 or not isinstance(payload, dict):
                detail = payload.get("detail") if isinstance(payload, dict) else payload
                return Result("l4d", "error", latency_ms=build_ms + http_ms, backend="L4-D :8004",
                              detail=f"HTTP {status}" + (f": {detail}"[:80] if detail else ""), extra=extra)
            p_of = {a["qid"]: float(a["p_yes"]) for a in payload["answers"]}
            tau = float(payload["tau"])
            extra.update({key: payload.get(key) for key in ("latency_ms_server", "forward_ms", "switch_ms",
                                                              "n_tokens", "checkpoint")})
            backend = f"qwen3.5-4b-lora-l4d-fold{fold}"
        elif stored is not None and all(q["qid"] in stored["answers"] for q in kept):
            http_ms, tau = None, l4d_frozen_tau()[fold]
            p_of = {q["qid"]: float(stored["answers"][q["qid"]]["p_yes"]) for q in kept}
            backend = "stored (:8004 offline)"
            extra["offline_reason"] = info
        else:
            return Result("l4d", "offline", backend="L4-D: offline", detail=str(info), extra=extra)
        t2 = time.perf_counter()
        verdict = l4d_prune.verdict(kept, p_of, tau)
        derive_ms = ms_since(t2)
    except (urllib.error.URLError, OSError) as exc:
        status = "timeout" if "timed out" in str(exc).lower() else "error"
        return Result("l4d", status, latency_ms=ms_since(t0), backend="L4-D :8004", detail=type(exc).__name__,
                      extra=extra)
    except (KeyError, TypeError, ValueError) as exc:
        return Result("l4d", "error", latency_ms=ms_since(t0), backend="L4-D", detail=f"{exc}"[:100], extra=extra)
    extra.update(tau=tau, leaks=verdict["leaks"], derive_ms=derive_ms,
                 leak_site=l4d_site_label(verdict["leaks"][0][0], sites) if verdict["leaks"] else None,
                 answers={q["qid"].split("/", 2)[2]: round(p_of[q["qid"]], 6) for q in kept})
    latency = None if http_ms is None else build_ms + http_ms + derive_ms
    return Result("l4d", "ok", pred=int(verdict["pred"]), score=float(verdict["score"]), score_kind="l4d",
                  threshold=tau, latency_ms=latency, backend=backend,
                  detail=l4d_reason(verdict, kept, p_of, tau, sites), extra=extra)


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
