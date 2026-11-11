"""Strict and valid-only metrics for the Juliet binary task.

Strict mode always uses the full denominator.  A request that failed or whose
answer did not match the required JSON schema is scored as an error: for a
truly leaking unit it becomes a false negative, for a truly non-leaking unit a
false positive.  Valid-only mode drops those records and reports coverage next
to every number, so the two views cannot be confused.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from typing import Any, Iterable

LABELS = ("vulnerable", "not_vulnerable")
POSITIVE = "vulnerable"


class SchemaError(ValueError):
    """Raised when a model answer does not match the requested schema."""


def parse_verdict(content: str | None) -> dict[str, Any]:
    if not isinstance(content, str) or not content.strip():
        raise SchemaError("empty_content")
    text = content.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"json_error: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaError("not_a_json_object")
    label = value.get("label")
    if label not in LABELS:
        raise SchemaError(f"label_invalid: {label!r}")
    confidence = value.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise SchemaError("confidence_not_numeric")
        if not math.isfinite(float(confidence)) or not 0.0 <= float(confidence) <= 1.0:
            raise SchemaError(f"confidence_out_of_range: {confidence!r}")
    reason = value.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise SchemaError("reason_not_string")
    extra = sorted(set(value) - {"label", "confidence", "reason"})
    return {
        "label": label,
        "confidence": float(confidence) if confidence is not None else None,
        "reason": reason,
        "extra_keys": extra,
    }


def _confusion(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 1)
    fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 0)
    fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    counts = _confusion(y_true, y_pred)
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
    )
    accuracy = (tp + tn) / total if total else None
    balanced = (
        (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None
    )
    denominator = math.sqrt(
        (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    )
    mcc = (
        (tp * tn - fp * fn) / denominator if denominator else 0.0
    )
    return {
        "n": total,
        **counts,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "balanced_accuracy": balanced,
        "mcc": mcc,
    }


def _rows(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if "y_true" in record]


def evaluate(records: list[dict[str, Any]]) -> dict[str, Any]:
    rows = _rows(records)
    if not rows:
        raise ValueError("no records to evaluate")
    truth = [int(row["y_true"]) for row in rows]
    valid = [bool(row.get("valid")) for row in rows]
    predicted = [int(row["y_pred"]) if row.get("valid") else None for row in rows]

    strict_predictions = [
        pred if pred is not None else 1 - truth_value
        for truth_value, pred in zip(truth, predicted)
    ]
    valid_pairs = [
        (truth_value, pred)
        for truth_value, pred in zip(truth, predicted)
        if pred is not None
    ]

    strict = _metrics(truth, strict_predictions)
    valid_only = _metrics(
        [pair[0] for pair in valid_pairs], [pair[1] for pair in valid_pairs]
    )
    valid_only["n_total"] = len(rows)
    strict["n_total"] = len(rows)
    strict["invalid"] = len(rows) - sum(valid)
    valid_only["invalid"] = len(rows) - sum(valid)
    strict["coverage"] = sum(valid) / len(rows)
    valid_only["coverage"] = sum(valid) / len(rows)

    by_language: dict[str, Any] = {}
    for language in sorted({row.get("language", "unknown") for row in rows}):
        subset = [row for row in rows if row.get("language", "unknown") == language]
        by_language[language] = evaluate_untyped(subset)

    return {
        "n_total": len(rows),
        "n_valid": sum(valid),
        "n_invalid": len(rows) - sum(valid),
        "coverage": sum(valid) / len(rows),
        "strict": strict,
        "valid_only": valid_only,
        "by_language": by_language,
    }


def evaluate_untyped(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate a subset without recursing into per-language breakdowns."""
    truth = [int(row["y_true"]) for row in rows]
    predicted = [int(row["y_pred"]) if row.get("valid") else None for row in rows]
    strict_predictions = [
        pred if pred is not None else 1 - truth_value
        for truth_value, pred in zip(truth, predicted)
    ]
    valid_pairs = [
        (truth_value, pred)
        for truth_value, pred in zip(truth, predicted)
        if pred is not None
    ]
    strict = _metrics(truth, strict_predictions)
    valid_only = _metrics(
        [pair[0] for pair in valid_pairs], [pair[1] for pair in valid_pairs]
    )
    strict["n_total"] = len(rows)
    valid_only["n_total"] = len(rows)
    strict["invalid"] = len(rows) - len(valid_pairs)
    valid_only["invalid"] = len(rows) - len(valid_pairs)
    strict["coverage"] = len(valid_pairs) / len(rows)
    valid_only["coverage"] = len(valid_pairs) / len(rows)
    return {
        "n_total": len(rows),
        "n_valid": len(valid_pairs),
        "n_invalid": len(rows) - len(valid_pairs),
        "coverage": len(valid_pairs) / len(rows),
        "strict": strict,
        "valid_only": valid_only,
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency_stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0, "mean": None, "p50": None, "p95": None, "max": None}
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
        "max": max(values),
    }


def _sum_optional(values: Iterable[Any]) -> tuple[float | None, int]:
    known = [float(value) for value in values if isinstance(value, (int, float))]
    present = sum(1 for value in values if isinstance(value, (int, float)))
    return (sum(known) if present else None), present


def aggregate_run(records: list[dict[str, Any]]) -> dict[str, Any]:
    rows = _rows(records)
    usage_prompt = []
    usage_completion = []
    usage_reasoning = []
    usage_cached = []
    usage_total = []
    published_cost = []
    api_list_cost = []
    api_allowance = []
    latencies = []
    wall = []
    statuses = Counter()
    errors = Counter()
    invalid_reasons = Counter()
    for row in rows:
        statuses[row.get("status", "missing")] += 1
        response = row.get("response") or {}
        usage = response.get("usage") or {}
        usage_prompt.append(usage.get("prompt_tokens"))
        usage_completion.append(usage.get("completion_tokens"))
        usage_total.append(usage.get("total_tokens"))
        details = usage.get("completion_tokens_details") or {}
        reasoning = details.get("reasoning_tokens")
        usage_reasoning.append(reasoning)
        prompt_details = usage.get("prompt_tokens_details") or {}
        cached = prompt_details.get("cached_tokens")
        if cached is None:
            cached = usage.get("prompt_cache_hit_tokens")
        usage_cached.append(cached)
        cost = row.get("cost") or {}
        published_cost.append(cost.get("cost_usd"))
        api_list_cost.append(cost.get("api_list_cost_usd"))
        api_allowance.append(cost.get("api_allowance_usd"))
        latencies.append(response.get("request_latency_seconds"))
        wall.append(response.get("wall_seconds"))
        if not row.get("valid"):
            invalid_reasons[row.get("validation", {}).get("error", "unknown")] += 1
        error = response.get("error")
        if isinstance(error, dict):
            errors[error.get("type", "unknown")] += 1

    def _known(values: list[Any]) -> dict[str, Any]:
        total, count = _sum_optional(values)
        return {"sum": total, "known_records": count, "unknown_records": len(values) - count}

    return {
        "records": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "error_types": dict(sorted(errors.items())),
        "invalid_reasons": dict(sorted(invalid_reasons.items())),
        "usage": {
            "prompt_tokens": _known(usage_prompt),
            "completion_tokens": _known(usage_completion),
            "total_tokens": _known(usage_total),
            "reasoning_tokens": _known(usage_reasoning),
            "cached_prompt_tokens": _known(usage_cached),
        },
        "cost": {
            "published_price_usd": _known(published_cost),
            "api_list_cost_usd": _known(api_list_cost),
            "api_allowance_usd": _known(api_allowance),
        },
        "latency_seconds": latency_stats(
            [float(value) for value in latencies if isinstance(value, (int, float))]
        ),
        "wall_seconds": latency_stats(
            [float(value) for value in wall if isinstance(value, (int, float))]
        ),
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def markdown_report(
    *,
    title: str,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
    aggregate: dict[str, Any],
) -> str:
    strict = metrics["strict"]
    valid = metrics["valid_only"]
    language_rows = "\n".join(
        "| {lang} | {n} | {sa} | {sf1} | {va} | {vf1} |".format(
            lang=language,
            n=data["n_total"],
            sa=_fmt(data["strict"]["accuracy"]),
            sf1=_fmt(data["strict"]["f1"]),
            va=_fmt(data["valid_only"]["accuracy"]),
            vf1=_fmt(data["valid_only"]["f1"]),
        )
        for language, data in metrics["by_language"].items()
    )
    usage = aggregate["usage"]
    cost = aggregate["cost"]
    latency = aggregate["latency_seconds"]
    return f"""# {title}

- Run: `{manifest['run_id']}`
- Model: `{manifest['model']}`
- Endpoint: `{manifest['api']['base_url']}`
- Prompt: `{manifest['prompt_version']}`
- Units: {metrics['n_total']} (valid {metrics['n_valid']}, invalid {metrics['n_invalid']}, coverage {_fmt(metrics['coverage'])})
- Requests: {aggregate['records']}; status {aggregate['status_counts']}
- Reference-price cost: {_fmt(cost['published_price_usd']['sum'])} USD ({manifest.get('price_source', 'n/a')})
- API list cost: {_fmt(cost['api_list_cost_usd']['sum'])} USD
- API Go allowance: {_fmt(cost['api_allowance_usd']['sum'])} USD
- Latency p50/p95/max: {_fmt(latency['p50'])} / {_fmt(latency['p95'])} / {_fmt(latency['max'])} s

| Metric | Strict (all {metrics['n_total']}) | Valid-only ({metrics['n_valid']}) |
| --- | ---: | ---: |
| TP / FP / TN / FN | {strict['tp']} / {strict['fp']} / {strict['tn']} / {strict['fn']} | {valid['tp']} / {valid['fp']} / {valid['tn']} / {valid['fn']} |
| Accuracy | {_fmt(strict['accuracy'])} | {_fmt(valid['accuracy'])} |
| Precision | {_fmt(strict['precision'])} | {_fmt(valid['precision'])} |
| Recall | {_fmt(strict['recall'])} | {_fmt(valid['recall'])} |
| Specificity | {_fmt(strict['specificity'])} | {_fmt(valid['specificity'])} |
| F1 | {_fmt(strict['f1'])} | {_fmt(valid['f1'])} |
| Balanced accuracy | {_fmt(strict['balanced_accuracy'])} | {_fmt(valid['balanced_accuracy'])} |
| MCC | {_fmt(strict['mcc'])} | {_fmt(valid['mcc'])} |

Invalid answers are scored as errors in strict mode: a false negative when the
unit truly leaks and a false positive when it does not.  Valid-only mode uses
only schema-valid answers and must be read together with coverage.

## By language

| Language | N | Strict acc | Strict F1 | Valid acc | Valid F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
{language_rows}

## Usage

| Field | Sum | Known | Unknown |
| --- | ---: | ---: | ---: |
| Prompt tokens | {_fmt(usage['prompt_tokens']['sum'])} | {usage['prompt_tokens']['known_records']} | {usage['prompt_tokens']['unknown_records']} |
| Completion tokens | {_fmt(usage['completion_tokens']['sum'])} | {usage['completion_tokens']['known_records']} | {usage['completion_tokens']['unknown_records']} |
| Reasoning tokens | {_fmt(usage['reasoning_tokens']['sum'])} | {usage['reasoning_tokens']['known_records']} | {usage['reasoning_tokens']['unknown_records']} |
| Cached prompt tokens | {_fmt(usage['cached_prompt_tokens']['sum'])} | {usage['cached_prompt_tokens']['known_records']} | {usage['cached_prompt_tokens']['unknown_records']} |
| Total tokens | {_fmt(usage['total_tokens']['sum'])} | {usage['total_tokens']['known_records']} | {usage['total_tokens']['unknown_records']} |

## Requests

- Status counts: `{json.dumps(aggregate['status_counts'], sort_keys=True)}`
- Error types: `{json.dumps(aggregate['error_types'], sort_keys=True)}`
- Invalid reasons: `{json.dumps(aggregate['invalid_reasons'], sort_keys=True)}`
"""


def write_report(path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
