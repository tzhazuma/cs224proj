#!/usr/bin/env python3
"""Shared, standard-library-only helpers for the unified benchmark.

This module deliberately contains no experiment-specific logic. It implements
the metric, interval, bootstrap and cost definitions that are normative in
``benchmark/PROTOCOL.md``. Both ``bench_metrics.py`` and ``bench_compare.py``
import it so that every track uses exactly the same arithmetic.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from statistics import NormalDist
from typing import Any, Callable, Iterable, Mapping, Sequence

PROTOCOL_VERSION = "1.0.0"
PREDICTION_SCHEMA_VERSION = "benchmark-prediction-v1"
RUN_SCHEMA_VERSION = "benchmark-run-v1"
METRICS_SCHEMA_VERSION = "benchmark-metrics-v1"

DEFAULT_CONFIDENCE = 0.95
DEFAULT_BOOTSTRAP_RESAMPLES = 10_000
DEFAULT_BOOTSTRAP_SEED = 42
PERCENTILE_METHOD = "linear"

TASKS = ("detection", "pair_detection", "leak_detection", "repair")
STATUSES = (
    "ok",
    "schema_invalid",
    "api_error",
    "timeout",
    "tool_error",
    "compile_error",
    "harness_error",
    "crash",
    "unsupported",
    "not_applicable",
    "inconclusive",
    "skipped_budget",
    "not_run",
)
FAMILIES = ("llm", "static", "dynamic", "hybrid")


class BenchError(Exception):
    """Raised when a run artifact cannot be interpreted unambiguously."""


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_binary(value: object) -> bool:
    return isinstance(value, bool) or (
        isinstance(value, int) and not isinstance(value, bool) and value in (0, 1)
    )


def as_bool(value: object) -> bool | None:
    """Normalise a JSON boolean or 0/1 integer; return None for anything else."""

    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    return None


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise BenchError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise BenchError(f"{path}:{line_number}: record must be a JSON object")
            records.append(value)
    return records


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_write_text(path: str | Path, text: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)


def atomic_write_json(path: str | Path, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    atomic_write_text(path, text)


def _z_value(confidence: float) -> float:
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be in (0, 1), got {confidence!r}")
    return NormalDist().inv_cdf(0.5 + confidence / 2.0)


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    return None if denominator == 0 else numerator / denominator


def wilson_interval(
    successes: int,
    total: int,
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any] | None:
    """Wilson score interval for a binomial proportion."""

    if total < 0:
        raise ValueError("total must be non-negative")
    if successes < 0 or successes > total:
        raise ValueError("successes must be in [0, total]")
    if total == 0:
        return None
    z = _z_value(confidence)
    p = successes / total
    denominator = 1.0 + z * z / total
    centre = (p + z * z / (2.0 * total)) / denominator
    half_width = (
        z
        * math.sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total))
        / denominator
    )
    return {
        "successes": successes,
        "total": total,
        "estimate": p,
        "low": max(0.0, centre - half_width),
        "high": min(1.0, centre + half_width),
        "confidence": confidence,
        "z": z,
        "method": "wilson",
    }


def detection_scores(
    labels: Sequence[bool],
    predictions: Sequence[bool | None],
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Binary detection metrics with valid-only and strict (end-to-end) views.

    ``predictions[i] is None`` means the unit did not produce a usable
    prediction. Valid-only metrics exclude it; ``strict_accuracy`` counts it as
    incorrect. F1/recall/precision are only defined on the valid subset, so
    they are always reported together with ``coverage`` and ``invalid``.
    """

    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal length")

    tp = fp = tn = fn = invalid = 0
    for label, prediction in zip(labels, predictions):
        if prediction is None:
            invalid += 1
            continue
        if label and prediction:
            tp += 1
        elif label and not prediction:
            fn += 1
        elif not label and prediction:
            fp += 1
        else:
            tn += 1

    n = len(labels)
    valid = tp + fp + tn + fn
    label_positive = tp + fn
    label_negative = tn + fp
    predicted_positive = tp + fp
    predicted_negative = tn + fn

    precision = _safe_ratio(tp, predicted_positive)
    recall = _safe_ratio(tp, label_positive)
    specificity = _safe_ratio(tn, label_negative)

    if label_positive == 0:
        positive_f1 = None
    elif predicted_positive == 0:
        positive_f1 = 0.0
    else:
        positive_f1 = 2.0 * tp / (2.0 * tp + fp + fn)

    if label_negative == 0:
        negative_f1 = None
    elif predicted_negative == 0:
        negative_f1 = 0.0
    else:
        negative_f1 = 2.0 * tn / (2.0 * tn + fn + fp)

    if positive_f1 is None or negative_f1 is None:
        macro_f1 = None
    else:
        macro_f1 = (positive_f1 + negative_f1) / 2.0

    if recall is None or specificity is None:
        balanced_accuracy = None
    else:
        balanced_accuracy = (recall + specificity) / 2.0

    accuracy = _safe_ratio(tp + tn, valid)
    strict_accuracy = _safe_ratio(tp + tn, n)
    coverage = _safe_ratio(valid, n)
    invalid_rate = _safe_ratio(invalid, n)
    predicted_positive_rate = _safe_ratio(predicted_positive, valid)

    mcc_denominator = math.sqrt(
        float(predicted_positive * label_positive * label_negative * predicted_negative)
    )
    if mcc_denominator == 0:
        mcc = 0.0 if valid > 0 else None
        mcc_degenerate = True
    else:
        mcc = (tp * tn - fp * fn) / mcc_denominator
        mcc_degenerate = False

    undefined = [
        name
        for name, value in (
            ("precision", precision),
            ("recall", recall),
            ("specificity", specificity),
            ("f1", positive_f1),
            ("negative_f1", negative_f1),
            ("macro_f1", macro_f1),
            ("balanced_accuracy", balanced_accuracy),
            ("accuracy", accuracy),
            ("strict_accuracy", strict_accuracy),
            ("mcc", mcc),
        )
        if value is None
    ]

    return {
        "n": n,
        "valid": valid,
        "invalid": invalid,
        "coverage": coverage,
        "invalid_rate": invalid_rate,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "label_counts": {
            "vulnerable": label_positive,
            "non_vulnerable": label_negative,
        },
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": positive_f1,
        "negative_f1": negative_f1,
        "macro_f1": macro_f1,
        "balanced_accuracy": balanced_accuracy,
        "accuracy": accuracy,
        "strict_accuracy": strict_accuracy,
        "mcc": mcc,
        "mcc_degenerate": mcc_degenerate,
        "predicted_positive_rate": predicted_positive_rate,
        "undefined_metrics": undefined,
        "wilson": {
            "precision": wilson_interval(tp, predicted_positive, confidence=confidence),
            "recall": wilson_interval(tp, label_positive, confidence=confidence),
            "specificity": wilson_interval(tn, label_negative, confidence=confidence),
            "accuracy": wilson_interval(tp + tn, valid, confidence=confidence),
            "strict_accuracy": wilson_interval(tp + tn, n, confidence=confidence),
            "coverage": wilson_interval(valid, n, confidence=confidence),
        },
    }


def pair_scores(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Joint discrimination metrics for vulnerable/fixed version pairs."""

    if len(vulnerable_predictions) != len(fixed_predictions):
        raise ValueError("pair sides must have equal length")

    n = 0
    valid_pairs = 0
    both_flagged = 0
    both_clean = 0
    vulnerable_detected_fixed_clean = 0
    vulnerable_missed_fixed_flagged = 0
    consistent = 0
    swapped = 0

    for vulnerable, fixed in zip(vulnerable_predictions, fixed_predictions):
        n += 1
        if vulnerable is None or fixed is None:
            continue
        valid_pairs += 1
        if vulnerable and not fixed:
            vulnerable_detected_fixed_clean += 1
            consistent += 1
        elif vulnerable and fixed:
            both_flagged += 1
        elif not vulnerable and not fixed:
            both_clean += 1
        else:
            vulnerable_missed_fixed_flagged += 1
            consistent += 1
            swapped += 1

    invalid_pairs = n - valid_pairs
    joint_valid = _safe_ratio(vulnerable_detected_fixed_clean, valid_pairs)
    joint_all = _safe_ratio(vulnerable_detected_fixed_clean, n)

    def rate(value: int) -> float | None:
        return _safe_ratio(value, valid_pairs)

    return {
        "n_pairs": n,
        "valid_pairs": valid_pairs,
        "invalid_pairs": invalid_pairs,
        "coverage": _safe_ratio(valid_pairs, n),
        "invalid_rate": _safe_ratio(invalid_pairs, n),
        "joint_correct_valid_pairs": vulnerable_detected_fixed_clean,
        "joint_correct_all_pairs": vulnerable_detected_fixed_clean,
        "joint_accuracy_valid_pairs": joint_valid,
        "joint_accuracy_all_pairs": joint_all,
        "joint_categories": {
            "vulnerable_detected_fixed_clean": vulnerable_detected_fixed_clean,
            "both_flagged": both_flagged,
            "both_clean": both_clean,
            "vulnerable_missed_fixed_flagged": vulnerable_missed_fixed_flagged,
        },
        "joint_rates_valid_pairs": {
            "vulnerable_detected_fixed_clean": rate(vulnerable_detected_fixed_clean),
            "both_flagged": rate(both_flagged),
            "both_clean": rate(both_clean),
            "vulnerable_missed_fixed_flagged": rate(vulnerable_missed_fixed_flagged),
        },
        "consistent": consistent,
        "swapped": swapped,
        "consistent_rate": rate(consistent),
        "swapped_rate": rate(swapped),
        "both_vulnerable_rate": rate(both_flagged),
        "both_safe_rate": rate(both_clean),
        "wilson": {
            "joint_accuracy_valid_pairs": wilson_interval(
                vulnerable_detected_fixed_clean, valid_pairs, confidence=confidence
            ),
            "joint_accuracy_all_pairs": wilson_interval(
                vulnerable_detected_fixed_clean, n, confidence=confidence
            ),
            "coverage": wilson_interval(valid_pairs, n, confidence=confidence),
            "consistent_rate": wilson_interval(consistent, valid_pairs, confidence=confidence),
            "swapped_rate": wilson_interval(swapped, valid_pairs, confidence=confidence),
            "both_vulnerable_rate": wilson_interval(both_flagged, valid_pairs, confidence=confidence),
            "both_safe_rate": wilson_interval(both_clean, valid_pairs, confidence=confidence),
        },
    }


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Linear-interpolated percentile (numpy's default ``linear`` method)."""

    if not values:
        return None
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be in [0, 1]")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def p50_p95(values: Sequence[float]) -> tuple[float | None, float | None]:
    return percentile(values, 0.5), percentile(values, 0.95)


def cluster_bootstrap(
    cluster_ids: Sequence[str],
    metric_fns: Mapping[str, Callable[[Sequence[int]], float | None]],
    *,
    resamples: int = DEFAULT_BOOTSTRAP_RESAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Percentile cluster bootstrap; all metric functions share each resample."""

    if len(cluster_ids) == 0:
        return {
            "enabled": False,
            "reason": "no units",
            "settings": {
                "method": "cluster percentile bootstrap",
                "resamples": resamples,
                "seed": seed,
                "confidence": confidence,
                "percentile_method": PERCENTILE_METHOD,
            },
            "metrics": {},
        }

    clusters: dict[str, list[int]] = {}
    for index, cluster_id in enumerate(cluster_ids):
        clusters.setdefault(str(cluster_id), []).append(index)
    names = sorted(clusters)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {name: [] for name in metric_fns}

    for _ in range(resamples):
        chosen = [names[rng.randrange(len(names))] for _ in range(len(names))]
        indices: list[int] = []
        for cluster_id in chosen:
            indices.extend(clusters[cluster_id])
        for name, fn in metric_fns.items():
            value = fn(indices)
            if value is None:
                continue
            numeric = float(value)
            if math.isfinite(numeric):
                samples[name].append(numeric)

    alpha = (1.0 - confidence) / 2.0
    metrics: dict[str, Any] = {}
    for name, values in samples.items():
        if values:
            metrics[name] = {
                "ci_low": percentile(values, alpha),
                "ci_high": percentile(values, 1.0 - alpha),
                "bootstrap_median": percentile(values, 0.5),
                "bootstrap_mean": sum(values) / len(values),
                "valid_resamples": len(values),
                "resamples": resamples,
                "unstable": len(values) < 0.9 * resamples,
            }
        else:
            metrics[name] = {
                "ci_low": None,
                "ci_high": None,
                "bootstrap_median": None,
                "bootstrap_mean": None,
                "valid_resamples": 0,
                "resamples": resamples,
                "unstable": True,
            }

    sizes = sorted((len(members) for members in clusters.values()), reverse=True)
    return {
        "enabled": resamples > 0,
        "settings": {
            "method": "cluster percentile bootstrap",
            "resamples": resamples,
            "seed": seed,
            "confidence": confidence,
            "alpha": round(alpha, 12),
            "percentile_method": PERCENTILE_METHOD,
            "resampling": "clusters with replacement; all units within a selected cluster",
            "paired_metrics": "the same resample is used for every metric function",
        },
        "cluster_count": len(names),
        "cluster_size_summary": {
            "min": sizes[-1] if sizes else None,
            "max": sizes[0] if sizes else None,
            "median": percentile(sizes, 0.5) if sizes else None,
            "total_units": sum(sizes),
        },
        "metrics": metrics,
    }


def mcnemar_exact(
    *,
    a_correct_b_wrong: int,
    a_wrong_b_correct: int,
    total: int,
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Exact two-sided McNemar test on paired binary correctness."""

    if a_correct_b_wrong < 0 or a_wrong_b_correct < 0:
        raise ValueError("discordant counts must be non-negative")
    if total <= 0:
        raise ValueError("total must be positive")
    b = a_correct_b_wrong
    c = a_wrong_b_correct
    discordant = b + c
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, i) for i in range(min(b, c) + 1)) / (
            2 ** discordant
        )
        p_value = min(1.0, 2.0 * tail)

    return {
        "a_correct_b_wrong": b,
        "a_wrong_b_correct": c,
        "discordant": discordant,
        "total": total,
        "p_value": p_value,
        "p_value_method": "exact two-sided binomial",
        "odds_ratio": (b / c) if c > 0 else None,
        "risk_difference": (b - c) / total,
        "significant_unadjusted_0_05": p_value < alpha,
        "alpha": alpha,
    }


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    """Holm step-down adjusted p-values, preserving input order."""

    if not p_values:
        return []
    m = len(p_values)
    for value in p_values:
        if not is_number(value) or not 0.0 <= float(value) <= 1.0:
            raise ValueError("p-values must be in [0, 1]")
    order = sorted(range(m), key=lambda i: (float(p_values[i]), i))
    adjusted = [1.0] * m
    running = 0.0
    for rank, index in enumerate(order):
        candidate = (m - rank) * float(p_values[index])
        running = max(running, candidate)
        adjusted[index] = min(1.0, running)
    return adjusted


def bootstrap_detection(
    labels: Sequence[bool],
    predictions: Sequence[bool | None],
    cluster_ids: Sequence[str],
    *,
    resamples: int = DEFAULT_BOOTSTRAP_RESAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Cluster bootstrap for detection metrics on one run."""

    def metric(indices: Sequence[int], name: str) -> float | None:
        subset_labels = [labels[i] for i in indices]
        subset_predictions = [predictions[i] for i in indices]
        scores = detection_scores(subset_labels, subset_predictions, confidence=confidence)
        value = scores.get(name)
        return None if value is None else float(value)

    return cluster_bootstrap(
        cluster_ids,
        {
            "macro_f1": lambda idx: metric(idx, "macro_f1"),
            "f1": lambda idx: metric(idx, "f1"),
            "mcc": lambda idx: metric(idx, "mcc"),
            "balanced_accuracy": lambda idx: metric(idx, "balanced_accuracy"),
            "accuracy": lambda idx: metric(idx, "accuracy"),
            "strict_accuracy": lambda idx: metric(idx, "strict_accuracy"),
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )


def bootstrap_pair(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    cluster_ids: Sequence[str],
    *,
    resamples: int = DEFAULT_BOOTSTRAP_RESAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, Any]:
    """Cluster bootstrap for pair joint accuracy."""

    def metric(indices: Sequence[int], name: str) -> float | None:
        subset_vulnerable = [vulnerable_predictions[i] for i in indices]
        subset_fixed = [fixed_predictions[i] for i in indices]
        scores = pair_scores(subset_vulnerable, subset_fixed, confidence=confidence)
        value = scores.get(name)
        return None if value is None else float(value)

    return cluster_bootstrap(
        cluster_ids,
        {
            "joint_accuracy_valid_pairs": lambda idx: metric(idx, "joint_accuracy_valid_pairs"),
            "joint_accuracy_all_pairs": lambda idx: metric(idx, "joint_accuracy_all_pairs"),
            "coverage": lambda idx: metric(idx, "coverage"),
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )


def count_by(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def record_is_ok(record: Mapping[str, Any]) -> bool:
    return record.get("status") == "ok" and as_bool(record.get("prediction", {}).get("y_pred")) is not None


def record_prediction(record: Mapping[str, Any]) -> bool | None:
    if record.get("status") != "ok":
        return None
    return as_bool(record.get("prediction", {}).get("y_pred"))


def record_label(record: Mapping[str, Any]) -> bool | None:
    return as_bool(record.get("label", {}).get("y_true"))


def load_run(run_dir: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]], Path]:
    """Load a run manifest and its predictions without modifying anything."""

    directory = Path(run_dir).resolve()
    manifest_path = directory / "run_manifest.json"
    if not manifest_path.exists():
        raise BenchError(f"missing run_manifest.json in {directory}")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise BenchError(f"{manifest_path}: manifest must be an object")
    artifacts = manifest.get("artifacts") or {}
    predictions_name = artifacts.get("predictions") or "predictions.jsonl"
    predictions_path = directory / predictions_name
    if not predictions_path.exists():
        raise BenchError(f"missing predictions file: {predictions_path}")
    records = read_jsonl(predictions_path)
    return manifest, records, predictions_path


def cost_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate cost and latency without inventing missing prices."""

    usd_values: list[float] = []
    unknown_usd = 0
    wall_values: list[float] = []
    cpu_values: list[float] = []
    rss_values: list[float] = []
    prompt_tokens: list[int] = []
    completion_tokens: list[int] = []
    cached_tokens: list[int] = []
    latencies_ms: list[float] = []
    cost_bases: dict[str, int] = {}

    for record in records:
        cost = record.get("cost") or {}
        usd = cost.get("usd")
        if is_number(usd) and float(usd) >= 0:
            usd_values.append(float(usd))
        else:
            unknown_usd += 1
        if is_number(cost.get("wall_s")) and float(cost["wall_s"]) >= 0:
            wall_values.append(float(cost["wall_s"]))
        if is_number(cost.get("cpu_s")) and float(cost["cpu_s"]) >= 0:
            cpu_values.append(float(cost["cpu_s"]))
        if is_number(cost.get("peak_rss_mb")) and float(cost["peak_rss_mb"]) >= 0:
            rss_values.append(float(cost["peak_rss_mb"]))
        basis = cost.get("cost_basis")
        if basis:
            cost_bases[str(basis)] = cost_bases.get(str(basis), 0) + 1

        usage = record.get("usage") or {}
        for key, target in (
            ("prompt_tokens", prompt_tokens),
            ("completion_tokens", completion_tokens),
            ("cached_prompt_tokens", cached_tokens),
        ):
            value = usage.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                target.append(value)
        latency = usage.get("latency_ms")
        if is_number(latency) and float(latency) >= 0:
            latencies_ms.append(float(latency))

    p50, p95 = p50_p95(latencies_ms)
    return {
        "currency": "USD",
        "usd_known_sum": sum(usd_values) if usd_values else None,
        "usd_unknown_records": unknown_usd,
        "usd_complete": bool(records) and unknown_usd == 0,
        "wall_s_sum": sum(wall_values) if wall_values else None,
        "cpu_s_sum": sum(cpu_values) if cpu_values else None,
        "peak_rss_mb_max": max(rss_values) if rss_values else None,
        "prompt_tokens_sum": sum(prompt_tokens) if prompt_tokens else None,
        "completion_tokens_sum": sum(completion_tokens) if completion_tokens else None,
        "cached_prompt_tokens_sum": sum(cached_tokens) if cached_tokens else None,
        "latency_ms_p50": p50,
        "latency_ms_p95": p95,
        "latency_samples": len(latencies_ms),
        "cost_basis_counts": cost_bases,
    }
