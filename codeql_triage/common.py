"""Shared contract for CodeQL alert triage on the frozen Juliet CWE-401 split.

Only reads existing artefacts: ``juliet_llm/build/test.jsonl`` (de-identified
source views) and the frozen CodeQL run under ``static_extended/runs``.  The
model never sees the unit id, the split, a path, the label, or the CodeQL
finding's path; the prompt is audited against the same forbidden-token set as
``juliet_llm`` before a request is allowed.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
import statistics
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
TEST_VIEW = ROOT / "juliet_llm" / "build" / "test.jsonl"
CODEQL_RUN = ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full"
CODEQL_PREDICTIONS = CODEQL_RUN / "predictions.jsonl"

SCHEMA_VERSION = "codeql-triage-v1"
PROMPT_VERSION = "codeql-triage-ownership-2026-11-22.1"
PROMPT_VERSION_V2 = "codeql-triage-ownership-2026-11-22.2"
DIRECT_PROMPT_VERSION = "juliet-llm-binary-2026-11-12.2"

EXPECTED_UNITS = 140
EXPECTED_CODEQL_OK = 136

ALERT_TRUE = "true_positive"
ALERT_FALSE = "false_positive"
ALERT_UNCERTAIN = "uncertain"
ALERT_NONE = "no_alert"
ALERT_VALUES = {ALERT_TRUE, ALERT_FALSE, ALERT_UNCERTAIN, ALERT_NONE}

# Configured list prices used by the earlier runs, USD per 1M tokens.  They are
# reference prices, not the provider invoice.  Cache-hit prices are included so
# that a resumed run is costed consistently with the original requests.
PRICES = {
    "deepseek-v4.1-flash": (0.30, 1.20, 0.006),
    "deepseek-flash": (0.30, 1.20, 0.006),
    "mimo-v2.6-flash": (0.14, 0.28, 0.0028),
}

MODEL_PRESETS: dict[str, dict[str, Any]] = {
    "mimo-v2.6-flash": {
        "thinking": "disabled",
        "reasoning_effort": "none",
        "max_tokens_field": "max_completion_tokens",
    },
    "deepseek-v4.1-flash": {
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
    },
    "deepseek-flash": {
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
    },
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def _code_from_messages(messages: list[dict[str, str]], unit_id: str) -> tuple[str, str]:
    user = next((item["content"] for item in messages if item.get("role") == "user"), "")
    match = re.search(r"```(c|cpp)\n(.*?)\n```", user, re.DOTALL)
    if not match:
        raise ValueError(f"{unit_id}: cannot locate the source block in the direct prompt")
    language = match.group(1)
    code = match.group(2)
    if f"```{language}\n{code}\n```" not in user:
        raise ValueError(f"{unit_id}: source block is not exact")
    return language, code


def load_test_units(path: Path = TEST_VIEW) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    if len(rows) != EXPECTED_UNITS:
        raise ValueError(f"{path}: expected {EXPECTED_UNITS} units, found {len(rows)}")
    units: list[dict[str, Any]] = []
    for row in rows:
        unit_id = row["unit_id"]
        language, code = _code_from_messages(row["messages"], unit_id)
        if language != row["language"]:
            raise ValueError(f"{unit_id}: language mismatch")
        if sha256_text(code) != row["code_sha256"]:
            raise ValueError(f"{unit_id}: code hash does not match the frozen view")
        if row["label"] not in {"bad", "good"}:
            raise ValueError(f"{unit_id}: unexpected label")
        units.append(
            {
                "unit_id": unit_id,
                "group_id": row["group_id"],
                "family": row["family"],
                "variant": row["variant"],
                "language": row["language"],
                "label": row["label"],
                "y_true": 1 if row["label"] == "bad" else 0,
                "code": code,
                "code_sha256": row["code_sha256"],
                "direct_messages": row["messages"],
                "prompt_sha256": row["prompt_sha256"],
            }
        )
    units.sort(key=lambda item: item["unit_id"])
    if len({unit["unit_id"] for unit in units}) != len(units):
        raise ValueError("duplicate unit_id in the frozen test view")
    return units


def _finding(item: dict[str, Any]) -> dict[str, Any]:
    """Keep only non-identifying, stable diagnostic fields."""

    return {
        "query": str(item.get("query_id") or item.get("query_name") or "unknown"),
        "line": item.get("line"),
        "end_line": item.get("end_line"),
        "message": str(item.get("message") or ""),
        "severity": item.get("severity"),
    }


def load_codeql(path: Path = CODEQL_PREDICTIONS) -> dict[str, dict[str, Any]]:
    rows = [row for row in read_jsonl(path) if row["sample"]["split"] == "test"]
    if len(rows) != EXPECTED_UNITS:
        raise ValueError(f"{path}: expected {EXPECTED_UNITS} test rows, found {len(rows)}")
    ok = sum(1 for row in rows if row["status"] == "ok")
    if ok != EXPECTED_CODEQL_OK:
        raise ValueError(f"{path}: expected {EXPECTED_CODEQL_OK} analyzable units, found {ok}")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        unit_id = row["sample_id"]
        findings = [_finding(item) for item in row.get("diagnostics") or []]
        findings.sort(key=lambda item: (item["query"], item["line"] or 0, item["message"]))
        result[unit_id] = {
            "status": row["status"],
            "label": bool(row["label"]),
            "is_alert": bool(row["prediction"]["is_vulnerable"]),
            "by_query": dict(row["prediction"]["by_query"]),
            "finding_count": int(row["prediction"]["finding_count"]),
            "findings": findings,
            "runtime_seconds": (row.get("runtime") or {}).get("duration_seconds"),
        }
    units = load_test_units()
    missing = {unit["unit_id"] for unit in units} - set(result)
    extra = set(result) - {unit["unit_id"] for unit in units}
    if missing or extra:
        raise ValueError(f"CodeQL join mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    return result


def merge_units() -> list[dict[str, Any]]:
    units = load_test_units()
    codeql = load_codeql()
    for unit in units:
        unit["codeql"] = codeql[unit["unit_id"]]
    return units


TRIAGE_SYSTEM = """You are a senior C/C++ memory-safety auditor reviewing one static-analyzer report. The analyzer is an interprocedural relational engine. Its "may not be freed" query is deliberately conservative: it is often wrong when the release happens through a reference or a shadowed alias, through a container element, through a global or static flag set in another function, or inside a callee. Its "never freed" query is stricter.

Your job has two parts:
1. If the analyzer raised an alert, decide whether that alert is a true positive or a false positive. If it raised no alert, mark the alert assessment as no_alert.
2. Independently decide whether the executed code actually leaves heap memory unreleased.

Definition used for this audit:
- A defect is heap memory from malloc, calloc, realloc, strdup, or new/new[] that is not released with free, delete, or delete[] before the program ends.
- Memory that becomes unreachable, memory still held by a global or static pointer at exit, and memory released on only some feasible paths all count.
- Stack storage, static storage, and memory released on every feasible path do not count.
- Support code: print* helpers only write to stdout; ALLOCA(n) is stack storage in the current frame; twoIntsStruct and TwoIntsClass are plain data types with two int fields; the standard C and C++ libraries are available.

Reason explicitly about:
- the allocation expression and whether the object is heap or stack;
- ownership and every transfer of the owning pointer;
- aliasing, references, shadowing, and container elements that may hide the owning copy;
- global or static control flow, including flags written in one function and read in another;
- cross-function release, including free/delete in a callee or through a wrapper.

Hard rules:
- Do not use function length, file name, identifier name, formatting, comment text, analyzer severity, or the mere presence of an alert as evidence.
- If the code does not establish an ownership or release fact, write "unsupported" rather than guessing.
- "uncertain" is allowed when feasible paths cannot be resolved from the unit.
- For a unit with no alert, alert_verdict must be "no_alert"; still answer leak_present independently.
- Return one JSON object and nothing else.

Schema:
{"alert_verdict": "true_positive" | "false_positive" | "uncertain" | "no_alert",
 "leak_present": true | false | "uncertain",
 "allocation": "<allocation expression and heap/stack; at most 40 words>",
 "ownership": "<owner and transfers; at most 40 words>",
 "aliasing": "<aliases, shadowing, container elements; at most 40 words>",
 "global_control_flow": "<global/static flags and feasible paths; or not_applicable; at most 40 words>",
 "cross_function_release": "<callee or wrapper release path; or unsupported; at most 40 words>",
 "reason": "<at most 50 words>",
 "confidence": <number from 0 to 1>}"""

TRIAGE_SYSTEM_V2 = """You are a senior C/C++ memory-safety auditor reviewing one static-analyzer report. The analyzer is an interprocedural relational engine. Its "may not be freed" query is deliberately conservative: it is often wrong when release happens through a reference or a shadowed alias, through a container element, through a global or static flag set in another function, or inside a callee. Its "never freed" query is stricter.

Work in this order and keep the two answers separate:
1. First decide leak_present: does the executed code leave any heap allocation unreleased on any feasible path?
2. Then decide alert_verdict: is the analyzer's alert correct? This is not a question about whether an alert exists.
   - analyzer alerted and the code leaks at the reported site -> true_positive
   - analyzer alerted and the code does not leak -> false_positive
   - analyzer did not alert -> no_alert
   - the evidence is genuinely insufficient -> uncertain

Definition used for this audit:
- A defect is heap memory from malloc, calloc, realloc, strdup, or new/new[] that is not released with free, delete, or delete[] before the program ends.
- Memory that becomes unreachable, memory still held by a global or static pointer at exit, and memory released on only some feasible paths all count.
- Stack storage, static storage, and memory released on every feasible path do not count.
- Support code: print* helpers only write to stdout; ALLOCA(n) is stack storage in the current frame; twoIntsStruct and TwoIntsClass are plain data types with two int fields; the standard C and C++ libraries are available.

Special case that is often misjudged:
- `p = realloc(p, n)` writes the result into the only pointer to the old block. If realloc returns NULL, the old block is still allocated but its address is lost. That is a leak on a feasible allocation-failure path. Do not dismiss it as "not a normal path" or "infeasible" unless the unit proves realloc cannot fail (for example, the result is stored in a temporary and the old pointer is kept).

Reason explicitly about:
- the allocation expression and whether the object is heap or stack;
- ownership and every transfer of the owning pointer;
- aliasing, references, shadowing, and container elements that may hide the owning copy;
- global or static control flow, including flags written in one function and read in another;
- cross-function release, including free/delete in a callee or through a wrapper;
- whether every heap allocation in the unit has a release on every feasible path.

Hard rules:
- Do not use function length, file name, identifier name, formatting, comment text, analyzer severity, or the mere presence of an alert as evidence.
- If the code does not establish an ownership or release fact, write "unsupported" rather than guessing.
- If every heap allocation in the unit has a release on every feasible path, leak_present must be false.
- If you answer leak_present=true, name the allocation and the path that reaches program exit without a release; otherwise answer false.
- Do not mark alert_verdict=true_positive merely because an alert exists. If your own reason says the allocation is released on every feasible path, the alert is false_positive.

Self-check before returning:
- alert_verdict describes the correctness of the analyzer's alert, not its existence.
- If an alert exists and leak_present is false, alert_verdict must be false_positive.
- If an alert exists and leak_present is true, alert_verdict must be true_positive.
- If there is no alert, alert_verdict must be no_alert.
- Return one JSON object and nothing else.

Schema (keep this key order):
{"leak_present": true | false | "uncertain",
 "alert_verdict": "true_positive" | "false_positive" | "uncertain" | "no_alert",
 "allocation": "<allocation expression and heap/stack; at most 40 words>",
 "ownership": "<owner and transfers; at most 40 words>",
 "aliasing": "<aliases, shadowing, container elements; at most 40 words>",
 "global_control_flow": "<global/static flags and feasible paths; or not_applicable; at most 40 words>",
 "cross_function_release": "<callee or wrapper release path; or unsupported; at most 40 words>",
 "reason": "<at most 50 words>",
 "confidence": <number from 0 to 1>}"""

TRIAGE_USER_TEMPLATE = """Review the analyzer report for the code unit below.

Analyzer status: {status}
Analyzer alert: {alert}
{findings}
```{language}
{code}
```

Return only the JSON object."""


def _render_findings(codeql: dict[str, Any]) -> str:
    if codeql["status"] != "ok":
        return (
            "The analyzer could not build this unit. No alert is available; "
            "this is not evidence that the code is safe."
        )
    if not codeql["findings"]:
        return "The analyzer completed and reported no finding for this unit."
    lines = ["Findings (one per analyzer result):"]
    for item in codeql["findings"]:
        line = item.get("line")
        end_line = item.get("end_line")
        where = f"line {line}" if line is not None else "line unknown"
        if end_line is not None and end_line != line:
            where += f"-{end_line}"
        lines.append(
            f"- query: {item['query']}; {where}; severity: {item['severity']}; "
            f"message: {item['message']}"
        )
    return "\n".join(lines)


def build_triage_messages(unit: dict[str, Any], *, version: str = "v1") -> list[dict[str, str]]:
    codeql = unit["codeql"]
    status = "ok" if codeql["status"] == "ok" else codeql["status"]
    alert = "yes" if codeql["is_alert"] else ("unavailable" if status != "ok" else "none")
    user = TRIAGE_USER_TEMPLATE.format(
        status=status,
        alert=alert,
        findings=_render_findings(codeql),
        language="cpp" if unit["language"] == "cpp" else "c",
        code=unit["code"],
    )
    system = TRIAGE_SYSTEM_V2 if version == "v2" else TRIAGE_SYSTEM
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    audit_prompt(messages, unit)
    return messages


def build_direct_messages(unit: dict[str, Any]) -> list[dict[str, str]]:
    messages = [dict(item) for item in unit["direct_messages"]]
    audit_prompt(messages, unit)
    return messages


def audit_prompt(messages: list[dict[str, str]], unit: dict[str, Any]) -> None:
    from juliet_llm.cleaning import PROMPT_FORBIDDEN_PATTERNS, scan

    joined = "\n".join(item["content"] for item in messages)
    hits = {name: count for name, count in scan(joined, PROMPT_FORBIDDEN_PATTERNS).items() if count}
    if hits:
        raise ValueError(f"{unit['unit_id']}: prompt leak audit failed: {hits}")
    for identifier in (unit["unit_id"], unit["group_id"]):
        if identifier in joined:
            raise ValueError(f"{unit['unit_id']}: identifier leaked into the prompt")
    if "cwe-401" in joined.lower():
        raise ValueError(f"{unit['unit_id']}: defect id leaked into the prompt")


def normalize_alert(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "tp": ALERT_TRUE,
        "true": ALERT_TRUE,
        "real": ALERT_TRUE,
        "fp": ALERT_FALSE,
        "false": ALERT_FALSE,
        "false_alarm": ALERT_FALSE,
        "no_alert": ALERT_NONE,
        "none": ALERT_NONE,
        "no_finding": ALERT_NONE,
        "unknown": ALERT_UNCERTAIN,
    }
    text = aliases.get(text, text)
    return text if text in ALERT_VALUES else None


def normalize_leak(value: Any) -> bool | str | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "yes", "1", "leak", "leaking"}:
            return True
        if text in {"false", "no", "0", "no_leak", "not_leaking"}:
            return False
        if text in {"uncertain", "unknown", "unsupported"}:
            return ALERT_UNCERTAIN
    return None


def _extract_json(content: str) -> Any:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def parse_triage(content: str | None, *, has_alert: bool) -> dict[str, Any]:
    if not isinstance(content, str) or not content.strip():
        raise ValueError("empty_content")
    value = _extract_json(content)
    if not isinstance(value, dict):
        raise ValueError("not_a_json_object")
    alert = normalize_alert(value.get("alert_verdict"))
    leak = normalize_leak(value.get("leak_present"))
    if alert is None:
        raise ValueError(f"alert_verdict_invalid: {value.get('alert_verdict')!r}")
    if leak is None:
        raise ValueError(f"leak_present_invalid: {value.get('leak_present')!r}")
    if has_alert and alert == ALERT_NONE:
        raise ValueError("no_alert_on_an_alerted_unit")
    if not has_alert and alert not in {ALERT_NONE, ALERT_UNCERTAIN}:
        raise ValueError(f"alert_verdict_on_a_non_alerted_unit: {alert}")
    fields: dict[str, str] = {}
    for key in (
        "allocation",
        "ownership",
        "aliasing",
        "global_control_flow",
        "cross_function_release",
        "reason",
    ):
        raw = value.get(key)
        fields[key] = "" if raw is None else str(raw).strip()
    confidence = value.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        confidence_value = None
    else:
        confidence_value = float(confidence)
        if not math.isfinite(confidence_value) or not 0.0 <= confidence_value <= 1.0:
            raise ValueError(f"confidence_out_of_range: {confidence!r}")
    supported = [
        key
        for key in ("allocation", "ownership", "aliasing", "global_control_flow", "cross_function_release")
        if fields[key]
        and fields[key].strip().lower()
        not in {"unsupported", "not_applicable", "missing", "none", "unknown"}
    ]
    return {
        "alert_verdict": alert,
        "leak_present": leak,
        "confidence": confidence_value,
        "fields": fields,
        "evidence_fields_supported": len(supported),
        "evidence_fields_total": 5,
        "unsupported_drop": alert == ALERT_FALSE and len(supported) < 2,
    }


def parse_direct(content: str | None) -> dict[str, Any]:
    from juliet_llm.metrics import SchemaError, parse_verdict

    try:
        parsed = parse_verdict(content)
    except SchemaError as exc:
        raise ValueError(str(exc)) from exc
    return {
        "label": parsed["label"],
        "y_pred": 1 if parsed["label"] == "vulnerable" else 0,
        "confidence": parsed["confidence"],
        "reason": parsed["reason"],
        "extra_keys": parsed["extra_keys"],
    }


def confusion(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    if len(y_true) != len(y_pred):
        raise ValueError("length mismatch")
    tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 1)
    fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 0)
    fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    counts = confusion(y_true, y_pred)
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1_positive = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
    )
    f1_negative = (
        2 * specificity * (tn / (tn + fn)) / (specificity + tn / (tn + fn))
        if tn + fn and specificity + tn / (tn + fn)
        else 0.0
    )
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": total,
        **counts,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_positive": f1_positive,
        "f1_negative": f1_negative,
        "macro_f1": (f1_positive + f1_negative) / 2,
        "accuracy": (tp + tn) / total if total else None,
        "mcc": (tp * tn - fp * fn) / denominator if denominator else 0.0,
    }


def mcnemar_exact(b: int, c: int) -> dict[str, Any]:
    """Two-sided exact McNemar test on discordant counts b and c."""

    n = b + c
    if n == 0:
        return {"b": b, "c": c, "p_value": 1.0, "n_discordant": 0}
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2**n)
    p = min(1.0, 2 * tail)
    return {"b": b, "c": c, "p_value": p, "n_discordant": n}


def mcnemar_from_pairs(y_true: list[int], pred_a: list[int], pred_b: list[int]) -> dict[str, Any]:
    a_right_b_wrong = sum(1 for t, a, b in zip(y_true, pred_a, pred_b) if a == t and b != t)
    b_right_a_wrong = sum(1 for t, a, b in zip(y_true, pred_a, pred_b) if b == t and a != t)
    return mcnemar_exact(a_right_b_wrong, b_right_a_wrong)


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


def bootstrap_macro_f1(
    y_true: list[int],
    pred_a: list[int],
    pred_b: list[int],
    *,
    iterations: int = 10000,
    seed: int = 42,
) -> dict[str, Any]:
    """Percentile bootstrap for macro-F1(B) - macro-F1(A), paired by unit."""

    rng = random.Random(seed)
    n = len(y_true)
    diffs: list[float] = []
    for _ in range(iterations):
        indices = [rng.randrange(n) for _ in range(n)]
        truth = [y_true[i] for i in indices]
        a = [pred_a[i] for i in indices]
        b = [pred_b[i] for i in indices]
        diffs.append(metrics(truth, b)["macro_f1"] - metrics(truth, a)["macro_f1"])
    diffs.sort()
    lower = diffs[int(0.025 * (iterations - 1))]
    upper = diffs[int(0.975 * (iterations - 1))]
    observed = metrics(y_true, pred_b)["macro_f1"] - metrics(y_true, pred_a)["macro_f1"]
    return {
        "observed_delta_macro_f1": observed,
        "ci95": [lower, upper],
        "iterations": iterations,
        "seed": seed,
    }


def cost_for_usage(usage: dict[str, Any] | None, model: str) -> dict[str, Any]:
    prices = PRICES.get(model)
    if not usage or not prices:
        return {"cost_usd": None, "basis": "pricing_or_usage_missing"}
    prompt = usage.get("prompt_tokens", usage.get("input_tokens"))
    completion = usage.get("completion_tokens", usage.get("output_tokens"))
    if isinstance(prompt, bool) or not isinstance(prompt, int):
        prompt = None
    if isinstance(completion, bool) or not isinstance(completion, int):
        completion = None
    if prompt is None or completion is None:
        return {"cost_usd": None, "basis": "token_counts_missing"}
    cached = 0
    for key in ("prompt_cache_hit_tokens", "cache_read_input_tokens"):
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            cached = value
            break
    details = usage.get("prompt_tokens_details")
    if not cached and isinstance(details, dict):
        value = details.get("cached_tokens")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            cached = value
    if cached > prompt:
        cached = 0
    input_price, output_price, cached_price = prices
    cost = (
        (prompt - cached) * input_price
        + cached * cached_price
        + completion * output_price
    ) / 1_000_000.0
    return {
        "cost_usd": cost,
        "basis": "configured_list_price_not_invoice",
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "cached_prompt_tokens": cached,
        "input_price_usd_per_1m": input_price,
        "output_price_usd_per_1m": output_price,
        "cached_input_price_usd_per_1m": cached_price,
    }


def summarize_latencies(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    def pct(frac: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        position = (len(ordered) - 1) * frac
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return ordered[lower]
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight

    return {
        "n": len(ordered),
        "mean": statistics.fmean(ordered),
        "p50": pct(0.50),
        "p95": pct(0.95),
        "max": ordered[-1],
    }


def unit_is_compile_error(unit: dict[str, Any]) -> bool:
    return unit["codeql"]["status"] != "ok"
