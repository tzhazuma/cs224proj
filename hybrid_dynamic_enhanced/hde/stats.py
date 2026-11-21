"""Paired statistics for the enhanced-dynamic-guidance comparison.

Formulas mirror ``hybrid/analyze.py`` so the new numbers are directly
comparable with the frozen v2 tables.
"""

from __future__ import annotations

import math
import random
from typing import Any

Z95 = 1.959963984540054
BOOTSTRAP_REPS = 10000
SEED = 20261114


def wilson(k: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denominator = 1 + Z95 * Z95 / n
    centre = (p + Z95 * Z95 / (2 * n)) / denominator
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95 * Z95 / (4 * n * n)) / denominator
    return [max(0.0, centre - half), min(1.0, centre + half)]


def confusion(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(y_true: list[int], y_pred: list[int], valid: list[bool] | None = None) -> dict[str, Any]:
    """Valid-only metrics plus strict accuracy over every planned unit."""
    n = len(y_true)
    if valid is None:
        valid = [True] * n
    strict = [pred if ok else 0 for pred, ok in zip(y_pred, valid)]
    strict_conf = confusion(y_true, strict)
    tv = [t for t, ok in zip(y_true, valid) if ok]
    pv = [p for p, ok in zip(y_pred, valid) if ok]
    counts = confusion(tv, pv)
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = len(tv)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
    )
    accuracy = (tp + tn) / total if total else None
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
    return {
        "n": n,
        "valid": total,
        "coverage": total / n if n else None,
        **counts,
        "accuracy": accuracy,
        "accuracy_ci95": wilson(tp + tn, total) if total else None,
        "strict_accuracy": (strict_conf["tp"] + strict_conf["tn"]) / n if n else None,
        "strict_confusion": strict_conf,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "balanced_accuracy": balanced,
        "mcc": mcc,
        "predicted_positive_rate": (tp + fp) / total if total else None,
    }


def mcnemar(y_true: list[int], pred_a: list[int], pred_b: list[int]) -> dict[str, Any]:
    assert len(y_true) == len(pred_a) == len(pred_b)
    a_right_b_wrong = 0
    a_wrong_b_right = 0
    for truth, a, b in zip(y_true, pred_a, pred_b):
        ra, rb = a == truth, b == truth
        if ra and not rb:
            a_right_b_wrong += 1
        elif rb and not ra:
            a_wrong_b_right += 1
    n = a_right_b_wrong + a_wrong_b_right
    if n == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(n, k) for k in range(0, min(a_right_b_wrong, a_wrong_b_right) + 1))
        p_value = min(1.0, 2.0 * tail / (2**n))
    return {
        "a_right_b_wrong": a_right_b_wrong,
        "a_wrong_b_right": a_wrong_b_right,
        "discordant": n,
        "p_value_exact": p_value,
    }


def bootstrap_delta(
    y_true: list[int],
    pred_a: list[int],
    pred_b: list[int],
    reps: int = BOOTSTRAP_REPS,
    seed: int = SEED,
) -> dict[str, Any]:
    """Percentile CI for accuracy(a) - accuracy(b), paired units."""
    n = len(y_true)
    observed = sum(a == t for a, t in zip(pred_a, y_true)) / n - sum(
        b == t for b, t in zip(pred_b, y_true)
    ) / n
    rng = random.Random(seed)
    deltas = []
    for _ in range(reps):
        indices = [rng.randrange(n) for _ in range(n)]
        right_a = sum(1 for i in indices if pred_a[i] == y_true[i])
        right_b = sum(1 for i in indices if pred_b[i] == y_true[i])
        deltas.append(right_a / n - right_b / n)
    ordered = sorted(deltas)
    low = ordered[int(math.floor(0.025 * (reps - 1)))]
    high = ordered[int(math.ceil(0.975 * (reps - 1)))]
    return {
        "delta": observed,
        "ci95": [low, high],
        "reps": reps,
        "seed": seed,
        "method": "paired percentile bootstrap over units",
    }


def holm(entries: list[dict[str, Any]], key: str = "p_value_exact") -> None:
    """Holm step-down adjustment, in place.  ``entries`` gain ``p_value_holm``."""
    ordered = sorted(entries, key=lambda item: item[key])
    m = len(ordered)
    running = 0.0
    for rank, entry in enumerate(ordered, start=1):
        adjusted = min(1.0, (m - rank + 1) * entry[key])
        running = max(running, adjusted)
        entry["p_value_holm"] = running
