"""Agreement statistics implemented with the Python standard library only."""

from __future__ import annotations

import random
from collections import Counter
from typing import Any, Sequence


def _confusion(
    a: Sequence[Any], b: Sequence[Any], categories: Sequence[Any]
) -> tuple[list[list[int]], list[int], list[int]]:
    index = {value: position for position, value in enumerate(categories)}
    matrix = [[0 for _ in categories] for _ in categories]
    for left, right in zip(a, b):
        if left not in index or right not in index:
            raise ValueError(f"value outside categories: {left!r}, {right!r}")
        matrix[index[left]][index[right]] += 1
    rows = [sum(row) for row in matrix]
    columns = [sum(matrix[i][j] for i in range(len(categories))) for j in range(len(categories))]
    return matrix, rows, columns


def cohen_kappa(
    a: Sequence[Any],
    b: Sequence[Any],
    *,
    categories: Sequence[Any],
    weighted: bool = False,
) -> dict[str, Any]:
    """Return unweighted or quadratic-weighted Cohen's kappa.

    ``kappa`` is ``None`` when the expected disagreement denominator is zero
    (for example both raters assigned the same constant to every item).  It is
    not silently replaced by 1.0.
    """
    if len(a) != len(b):
        raise ValueError("score vectors must have the same length")
    n = len(a)
    if n == 0:
        raise ValueError("score vectors must not be empty")
    matrix, rows, columns = _confusion(a, b, categories)
    observed = sum(matrix[i][i] for i in range(len(categories))) / n
    expected = sum(rows[i] * columns[i] for i in range(len(categories))) / (n * n)
    result: dict[str, Any] = {
        "n": n,
        "observed_agreement": observed,
        "expected_agreement": expected,
        "confusion": matrix,
        "weighted": "quadratic" if weighted else None,
        "kappa": None,
        "undefined_reason": None,
    }
    if weighted:
        count = len(categories)
        if count < 2:
            result["undefined_reason"] = "fewer_than_two_categories"
            return result
        maximum = max(float(categories[-1]) - float(categories[0]), 1.0)
        numerator = 0.0
        denominator = 0.0
        for i in range(count):
            for j in range(count):
                weight = (float(categories[i]) - float(categories[j])) ** 2 / (maximum**2)
                numerator += weight * matrix[i][j]
                denominator += weight * rows[i] * columns[j] / n
        if denominator == 0.0:
            result["undefined_reason"] = "expected_weighted_disagreement_is_zero"
        else:
            result["kappa"] = 1.0 - numerator / denominator
    else:
        if 1.0 - expected == 0.0:
            result["undefined_reason"] = "expected_agreement_is_one"
        else:
            result["kappa"] = (observed - expected) / (1.0 - expected)
    return result


def bootstrap_ci(
    a: Sequence[Any],
    b: Sequence[Any],
    *,
    categories: Sequence[Any],
    weighted: bool,
    iterations: int,
    seed: int,
) -> list[float] | None:
    """Percentile bootstrap CI resampling candidates (items) with replacement."""
    n = len(a)
    if iterations <= 0 or n < 2:
        return None
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(iterations):
        indices = [rng.randrange(n) for _ in range(n)]
        sample_a = [a[index] for index in indices]
        sample_b = [b[index] for index in indices]
        result = cohen_kappa(
            sample_a, sample_b, categories=categories, weighted=weighted
        )
        value = result["kappa"]
        if value is not None:
            values.append(float(value))
    if len(values) < max(20, int(iterations * 0.5)):
        return None
    values.sort()
    lower = values[int(0.025 * (len(values) - 1))]
    upper = values[int(0.975 * (len(values) - 1))]
    return [lower, upper]


def within_one_agreement(a: Sequence[Any], b: Sequence[Any]) -> float | None:
    if not a:
        return None
    total = 0
    for left, right in zip(a, b):
        try:
            if abs(int(left) - int(right)) <= 1:
                total += 1
        except (TypeError, ValueError):
            return None
    return total / len(a)


def mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def distribution(values: Sequence[int], allowed: Sequence[int] = (0, 1, 2)) -> dict[str, int]:
    counts = Counter(values)
    return {str(value): counts.get(value, 0) for value in allowed}


def rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def interpret_kappa(value: float | None) -> str:
    if value is None:
        return "undefined"
    if value < 0:
        return "poor"
    if value < 0.2:
        return "slight"
    if value < 0.4:
        return "fair"
    if value < 0.6:
        return "moderate"
    if value < 0.8:
        return "substantial"
    return "almost_perfect"


KAPPA_LABELS_ZH = {
    "undefined": "未定义",
    "poor": "差（<0）",
    "slight": "轻微（0–0.2）",
    "fair": "一般（0.2–0.4）",
    "moderate": "中等（0.4–0.6）",
    "substantial": "较好（0.6–0.8）",
    "almost_perfect": "很好（>0.8）",
}
