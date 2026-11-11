"""Standard-library statistics for SecVulEval analysis.

The functions in this module implement the interval and test definitions in
``research/evaluation_protocol.md`` sections 10 and 11:

* Wilson score intervals for proportions;
* detection confusion metrics including macro-F1, balanced accuracy and MCC;
* paired joint accuracy for vulnerable/fixed version pairs;
* exact two-sided McNemar tests;
* Holm adjustment;
* percentile cluster bootstrap with a fixed seed.

No third-party packages are used.
"""

from __future__ import annotations

import math
import random
from statistics import NormalDist
from typing import Callable, Iterable, Mapping, Sequence

DEFAULT_CONFIDENCE = 0.95
DEFAULT_BOOTSTRAP_RESAMPLES = 10_000
DEFAULT_BOOTSTRAP_SEED = 42
PERCENTILE_METHOD = "linear"


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _z_value(confidence: float) -> float:
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be in (0, 1), got {confidence!r}")
    return NormalDist().inv_cdf(0.5 + confidence / 2.0)


def wilson_interval(
    successes: int,
    total: int,
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, float | int | str] | None:
    """Return a Wilson score interval for ``successes / total``.

    ``None`` is returned for an empty denominator.  The point estimate is
    included so callers do not have to recompute it.
    """

    if total < 0:
        raise ValueError(f"total must be non-negative, got {total!r}")
    if successes < 0 or successes > total:
        raise ValueError(f"successes must be in [0, total], got {successes!r}/{total!r}")
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


def _indices(indices: Sequence[int] | None, n: int) -> Iterable[int]:
    return range(n) if indices is None else indices


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def detection_scores(
    labels: Sequence[bool],
    predictions: Sequence[bool | None],
    indices: Sequence[int] | None = None,
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, object]:
    """Compute detection metrics for a (possibly resampled) index sequence.

    ``predictions[i] is None`` marks a schema-invalid or API-error record.
    Valid-only metrics exclude those records; ``strict_accuracy`` treats them
    as incorrect, matching the runner's end-to-end view.
    """

    n_total = len(labels)
    if len(predictions) != n_total:
        raise ValueError("labels and predictions must have the same length")
    tp = fp = tn = fn = 0
    n = 0
    invalid = 0
    for i in _indices(indices, n_total):
        label = labels[i]
        prediction = predictions[i]
        n += 1
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

    valid = tp + fp + tn + fn
    label_positive = tp + fn
    label_negative = tn + fp
    predicted_positive = tp + fp
    predicted_negative = tn + fn

    precision = _safe_ratio(tp, predicted_positive)
    recall = _safe_ratio(tp, label_positive)
    specificity = _safe_ratio(tn, label_negative)

    positive_f1: float | None
    if label_positive == 0:
        positive_f1 = None
    elif predicted_positive == 0:
        positive_f1 = 0.0
    else:
        positive_f1 = 2.0 * tp / (2.0 * tp + fp + fn)

    negative_f1: float | None
    if label_negative == 0:
        negative_f1 = None
    elif predicted_negative == 0:
        negative_f1 = 0.0
    else:
        negative_f1 = 2.0 * tn / (2.0 * tn + fn + fp)

    macro_f1: float | None
    if label_positive == 0 or label_negative == 0:
        macro_f1 = None
    else:
        macro_f1 = ((positive_f1 or 0.0) + (negative_f1 or 0.0)) / 2.0

    balanced_accuracy: float | None
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

    undefined: list[str] = []
    for name, value in (
        ("precision", precision),
        ("recall", recall),
        ("specificity", specificity),
        ("positive_f1", positive_f1),
        ("negative_f1", negative_f1),
        ("macro_f1", macro_f1),
        ("balanced_accuracy", balanced_accuracy),
        ("accuracy", accuracy),
        ("mcc", mcc),
    ):
        if value is None:
            undefined.append(name)

    wilson = {
        "precision": wilson_interval(tp, predicted_positive, confidence=confidence),
        "recall": wilson_interval(tp, label_positive, confidence=confidence),
        "specificity": wilson_interval(tn, label_negative, confidence=confidence),
        "accuracy": wilson_interval(tp + tn, valid, confidence=confidence),
        "strict_accuracy": wilson_interval(tp + tn, n, confidence=confidence),
        "coverage": wilson_interval(valid, n, confidence=confidence),
    }

    return {
        "n": n,
        "valid": valid,
        "invalid": invalid,
        "coverage": coverage,
        "invalid_rate": invalid_rate,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "label_counts": {"vulnerable": label_positive, "non_vulnerable": label_negative},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "positive_f1": positive_f1,
        "negative_f1": negative_f1,
        "macro_f1": macro_f1,
        "balanced_accuracy": balanced_accuracy,
        "accuracy": accuracy,
        "strict_correct": tp + tn,
        "strict_accuracy": strict_accuracy,
        "mcc": mcc,
        "mcc_degenerate": mcc_degenerate,
        "predicted_positive_rate": predicted_positive_rate,
        "single_class_support": label_positive == 0 or label_negative == 0,
        "single_class_predicted": predicted_positive == 0 or predicted_negative == 0,
        "positive_class_not_predicted": label_positive > 0 and predicted_positive == 0,
        "negative_class_not_predicted": label_negative > 0 and predicted_negative == 0,
        "macro_f1_defined": macro_f1 is not None,
        "undefined_metrics": undefined,
        "wilson": wilson,
    }


def pair_scores(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    indices: Sequence[int] | None = None,
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, object]:
    """Compute paired joint metrics for vulnerable/fixed version pairs.

    A pair is valid only when both sides have a schema-valid prediction.  The
    all-pairs view counts an invalid pair as a failure, which is the
    end-to-end deployment view.  Category rates use valid pairs as the
    denominator.
    """

    n_total = len(vulnerable_predictions)
    if len(fixed_predictions) != n_total:
        raise ValueError("vulnerable and fixed predictions must have the same length")

    n = 0
    valid_pairs = 0
    both_flagged = 0
    both_clean = 0
    vulnerable_detected_fixed_clean = 0
    vulnerable_missed_fixed_flagged = 0
    consistent = 0
    swapped = 0
    joint_correct_valid = 0

    for i in _indices(indices, n_total):
        n += 1
        vulnerable = vulnerable_predictions[i]
        fixed = fixed_predictions[i]
        if vulnerable is None or fixed is None:
            continue
        valid_pairs += 1
        if vulnerable and not fixed:
            vulnerable_detected_fixed_clean += 1
            joint_correct_valid += 1
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
    joint_correct_all = joint_correct_valid
    joint_valid = _safe_ratio(joint_correct_valid, valid_pairs)
    joint_all = _safe_ratio(joint_correct_all, n)
    coverage = _safe_ratio(valid_pairs, n)
    invalid_rate = _safe_ratio(invalid_pairs, n)

    def rate(value: int) -> float | None:
        return _safe_ratio(value, valid_pairs)

    wilson = {
        "joint_accuracy_valid_pairs": wilson_interval(
            joint_correct_valid, valid_pairs, confidence=confidence
        ),
        "joint_accuracy_all_pairs": wilson_interval(
            joint_correct_all, n, confidence=confidence
        ),
        "coverage": wilson_interval(valid_pairs, n, confidence=confidence),
        "consistent_rate": wilson_interval(consistent, valid_pairs, confidence=confidence),
        "swapped_rate": wilson_interval(swapped, valid_pairs, confidence=confidence),
        "both_vulnerable_rate": wilson_interval(
            both_flagged, valid_pairs, confidence=confidence
        ),
        "both_safe_rate": wilson_interval(both_clean, valid_pairs, confidence=confidence),
    }

    return {
        "n_pairs": n,
        "valid_pairs": valid_pairs,
        "invalid_pairs": invalid_pairs,
        "coverage": coverage,
        "invalid_rate": invalid_rate,
        "joint_correct_valid_pairs": joint_correct_valid,
        "joint_correct_all_pairs": joint_correct_all,
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
        "wilson": wilson,
    }


def mcnemar_exact(
    *,
    a_correct_b_wrong: int,
    a_wrong_b_correct: int,
    total: int,
    alpha: float = 0.05,
) -> dict[str, object]:
    """Exact two-sided McNemar test on paired binary correctness.

    ``a_correct_b_wrong`` and ``a_wrong_b_correct`` are the two discordant
    counts.  Under the null hypothesis the smaller count follows
    ``Binomial(b + c, 0.5)``; the two-sided p-value is
    ``2 * min(P(X <= min(b, c)), 0.5)``.
    """

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

    if c > 0:
        odds_ratio: float | None = b / c
    else:
        odds_ratio = None

    return {
        "a_correct_b_wrong": b,
        "a_wrong_b_correct": c,
        "discordant": discordant,
        "total": total,
        "p_value": p_value,
        "p_value_method": "exact two-sided binomial",
        "odds_ratio": odds_ratio,
        "risk_difference": (b - c) / total,
        "significant_unadjusted_0_05": p_value < alpha,
        "alpha": alpha,
    }


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    """Holm step-down adjusted p-values, preserving input order."""

    if not p_values:
        return []
    m = len(p_values)
    for p in p_values:
        if not _is_number(p) or not 0.0 <= float(p) <= 1.0:
            raise ValueError(f"p-values must be in [0, 1], got {p!r}")
    order = sorted(range(m), key=lambda i: (float(p_values[i]), i))
    adjusted = [1.0] * m
    running = 0.0
    for rank, index in enumerate(order):
        candidate = (m - rank) * float(p_values[index])
        running = max(running, candidate)
        adjusted[index] = min(1.0, running)
    return adjusted


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Linear-interpolated percentile (numpy's default ``linear`` method)."""

    if not values:
        return None
    if not 0.0 <= fraction <= 1.0:
        raise ValueError(f"fraction must be in [0, 1], got {fraction!r}")
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


def cluster_bootstrap(
    cluster_ids: Sequence[str],
    metric_fns: Mapping[str, Callable[[Sequence[int]], float | None]],
    *,
    resamples: int = DEFAULT_BOOTSTRAP_RESAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = DEFAULT_CONFIDENCE,
) -> dict[str, object]:
    """Percentile cluster bootstrap for one or more metric functions.

    Clusters are resampled with replacement; every unit in a selected cluster
    is included.  The same resample is used for every metric function, so
    paired differences must be supplied as their own function rather than
    computed from two independent bootstrap runs.

    Metrics that return ``None`` are excluded from that resample.  The number
    of usable resamples is reported, and ``unstable`` is set when fewer than
    90% of resamples yield a finite value.
    """

    if resamples < 0:
        raise ValueError(f"resamples must be non-negative, got {resamples!r}")
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
    values: dict[str, list[float]] = {name: [] for name in metric_fns}

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
                values[name].append(numeric)

    alpha = (1.0 - confidence) / 2.0
    results: dict[str, object] = {}
    for name, samples in values.items():
        if samples:
            results[name] = {
                "ci_low": percentile(samples, alpha),
                "ci_high": percentile(samples, 1.0 - alpha),
                "bootstrap_median": percentile(samples, 0.5),
                "bootstrap_mean": sum(samples) / len(samples),
                "valid_resamples": len(samples),
                "resamples": resamples,
                "unstable": len(samples) < 0.9 * resamples,
            }
        else:
            results[name] = {
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
            "cluster_unit": None,
            "resamples": resamples,
            "seed": seed,
            "confidence": confidence,
            "alpha": round(alpha, 12),
            "percentile_method": PERCENTILE_METHOD,
            "resampling": "clusters with replacement; all units within a selected cluster",
            "paired_metrics": "same resample used for all metric functions",
        },
        "cluster_count": len(names),
        "cluster_size_summary": {
            "min": sizes[-1] if sizes else None,
            "max": sizes[0] if sizes else None,
            "median": percentile(sizes, 0.5) if sizes else None,
            "total_units": sum(sizes),
        },
        "metrics": results,
    }
