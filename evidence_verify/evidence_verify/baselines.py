"""Cheap shortcut baselines for the 160-function detection test set.

Four families are implemented, all without any API call:

* ``label_only``: constant predictors (always vulnerable / always safe);
* ``length``: one threshold on function lines or characters;
* ``function_count``: one threshold on the number of call-like expressions in
  the body;
* ``matched_budget`` (in :func:`matched_budget_table`): retract ``k`` positives
  with a fixed, untuned rule, where ``k`` is the verifier's retraction count.

Thresholds are fitted on ``splits/dev_detection_40.json`` and then applied
unchanged to the test split, so the test set is not used to pick them.  For
transparency the test-tuned best threshold is also reported as an upper bound
and labelled ``test_tuned_upper_bound``.

The point of these baselines is negative: if a shortcut already reaches the
verifier's macro-F1 or MCC, the verifier has not demonstrated that evidence
checking is what produced the gain.
"""

from __future__ import annotations

import math
import random
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from analysis.stats import detection_scores, percentile

CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

# Tokens that look like calls but are control flow or declarations.
NON_CALL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "alignof",
        "decltype",
        "static_cast",
        "dynamic_cast",
        "reinterpret_cast",
        "const_cast",
        "defined",
        "assert",
        "throw",
        "new",
        "delete",
        "do",
        "else",
        "case",
    }
)

FEATURES: tuple[str, ...] = ("lines", "chars", "code_lines", "call_count")
DIRECTIONS: tuple[str, ...] = ("high", "low")


@dataclass(frozen=True)
class FeatureSample:
    idx: int
    label: bool
    lines: int
    chars: int
    code_lines: int
    call_count: int

    def value(self, feature: str) -> float:
        return float(getattr(self, feature))


def extract_features(idx: int, label: bool, func_body: str) -> FeatureSample:
    text = func_body.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    brace = text.find("{")
    body_region = text[brace:] if brace >= 0 else text
    call_count = sum(
        1 for match in CALL_RE.finditer(body_region) if match.group(1) not in NON_CALL_KEYWORDS
    )
    return FeatureSample(
        idx=idx,
        label=label,
        lines=len(lines),
        chars=len(func_body),
        code_lines=sum(1 for line in lines if line.strip()),
        call_count=call_count,
    )


def _macro_f1(labels: Sequence[bool], predictions: Sequence[bool]) -> float:
    scores = detection_scores(labels, predictions)
    value = scores.get("macro_f1")
    return float(value) if isinstance(value, (int, float)) else 0.0


def _mcc(labels: Sequence[bool], predictions: Sequence[bool]) -> float:
    scores = detection_scores(labels, predictions)
    value = scores.get("mcc")
    return float(value) if isinstance(value, (int, float)) else 0.0


def _candidates(values: Sequence[float], direction: str) -> list[float]:
    unique = sorted({float(value) for value in values})
    if not unique:
        return []
    if direction == "high":
        # ``value >= threshold``; max+1 predicts negative for every sample.
        return unique + [unique[-1] + 1.0]
    # ``value <= threshold``; min-1 predicts negative for every sample.
    return unique + [unique[0] - 1.0]


def _predict(values: Sequence[float], threshold: float, direction: str) -> list[bool]:
    if direction == "high":
        return [value >= threshold for value in values]
    return [value <= threshold for value in values]


def fit_threshold(
    samples: Sequence[FeatureSample], feature: str
) -> dict[str, Any]:
    """Pick the threshold/direction that maximises dev macro-F1.

    Ties are broken deterministically by MCC and then by the smaller threshold
    value, so the fitted rule is reproducible.  Direction is fitted because the
    sign of the length/defect relation is not known a priori on dev.
    """
    labels = [sample.label for sample in samples]
    values = [sample.value(feature) for sample in samples]
    best: dict[str, Any] | None = None
    for direction in DIRECTIONS:
        for threshold in _candidates(values, direction):
            predicted = _predict(values, threshold, direction)
            macro = _macro_f1(labels, predicted)
            mcc = _mcc(labels, predicted)
            key = (round(macro, 12), round(mcc, 12), -threshold)
            if best is None or key > best["key"]:
                best = {
                    "key": key,
                    "feature": feature,
                    "direction": direction,
                    "threshold": threshold,
                    "dev_macro_f1": macro,
                    "dev_mcc": mcc,
                }
    if best is None:
        raise ValueError("no candidate thresholds")
    best.pop("key")
    return best


def _score_samples(
    samples: Sequence[FeatureSample], rule: dict[str, Any]
) -> dict[str, Any]:
    labels = [sample.label for sample in samples]
    values = [sample.value(rule["feature"]) for sample in samples]
    predicted = _predict(values, rule["threshold"], rule["direction"])
    scores = detection_scores(labels, predicted)
    return {
        "tp": scores["confusion"]["tp"],
        "fp": scores["confusion"]["fp"],
        "tn": scores["confusion"]["tn"],
        "fn": scores["confusion"]["fn"],
        "precision": scores["precision"],
        "recall": scores["recall"],
        "specificity": scores["specificity"],
        "positive_f1": scores["positive_f1"],
        "macro_f1": scores["macro_f1"],
        "balanced_accuracy": scores["balanced_accuracy"],
        "mcc": scores["mcc"],
        "accuracy": scores["accuracy"],
        "predicted_positive_rate": scores["predicted_positive_rate"],
    }


def label_only_baselines(samples: Sequence[FeatureSample]) -> dict[str, Any]:
    labels = [sample.label for sample in samples]
    always_positive = detection_scores(labels, [True] * len(labels))
    always_negative = detection_scores(labels, [False] * len(labels))

    def compact(scores: dict[str, Any]) -> dict[str, Any]:
        return {
            "tp": scores["confusion"]["tp"],
            "fp": scores["confusion"]["fp"],
            "tn": scores["confusion"]["tn"],
            "fn": scores["confusion"]["fn"],
            "precision": scores["precision"],
            "recall": scores["recall"],
            "specificity": scores["specificity"],
            "positive_f1": scores["positive_f1"],
            "macro_f1": scores["macro_f1"],
            "balanced_accuracy": scores["balanced_accuracy"],
            "mcc": scores["mcc"],
            "accuracy": scores["accuracy"],
            "predicted_positive_rate": scores["predicted_positive_rate"],
        }

    return {
        "always_positive": compact(always_positive),
        "always_negative": compact(always_negative),
        "positive_rate_in_split": sum(labels) / len(labels),
    }


def build_baselines(
    dev_samples: Sequence[FeatureSample], test_samples: Sequence[FeatureSample]
) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for feature in FEATURES:
        fitted = fit_threshold(dev_samples, feature)
        dev_scores = _score_samples(dev_samples, fitted)
        test_scores = _score_samples(test_samples, fitted)
        test_best = fit_threshold(test_samples, feature)
        test_best_scores = _score_samples(test_samples, test_best)
        rules.append(
            {
                "name": f"{feature}_threshold",
                "feature": feature,
                "direction": fitted["direction"],
                "threshold": fitted["threshold"],
                "fit_split": "dev_detection_40",
                "dev": dev_scores,
                "test": test_scores,
                "test_tuned_upper_bound": {
                    "direction": test_best["direction"],
                    "threshold": test_best["threshold"],
                    "test": test_best_scores,
                    "note": "fitted on the test split; descriptive upper bound only",
                },
            }
        )
    return {
        "features": {
            "lines": "physical line count of func_body",
            "chars": "character count of func_body",
            "code_lines": "non-blank line count",
            "call_count": "call-like expressions after the first '{', excluding control keywords",
        },
        "label_only": label_only_baselines(test_samples),
        "threshold_rules": rules,
        "dev_label_counts": {
            "vulnerable": sum(1 for sample in dev_samples if sample.label),
            "non_vulnerable": sum(1 for sample in dev_samples if not sample.label),
        },
        "test_label_counts": {
            "vulnerable": sum(1 for sample in test_samples if sample.label),
            "non_vulnerable": sum(1 for sample in test_samples if not sample.label),
        },
        "settings": {
            "fit_split": "dev_detection_40",
            "evaluation_split": "test_detection_160",
            "tie_break": "higher dev macro-F1, then higher dev MCC, then smaller threshold",
            "note": (
                "The dev split has 8 non-vulnerable functions, so fitted thresholds are "
                "unstable; the test-tuned upper bound shows the best a single threshold "
                "could do with full test knowledge."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Matched-budget retraction baselines
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PositiveRecord:
    idx: int
    label: bool
    first_pass_confidence: float | None
    evidence_line_count: int
    lines: int
    chars: int
    code_lines: int
    call_count: int

    def value(self, feature: str) -> float:
        if feature == "first_pass_confidence":
            return float(self.first_pass_confidence) if self.first_pass_confidence is not None else math.nan
        if feature == "evidence_line_count":
            return float(self.evidence_line_count)
        return float(getattr(self, feature))


def _retract_lowest(
    records: Sequence[PositiveRecord], feature: str, k: int
) -> list[PositiveRecord]:
    """Retract the ``k`` positives with the smallest finite feature value."""
    ranked = sorted(
        records,
        key=lambda record: (
            math.isnan(record.value(feature)),
            record.value(feature) if not math.isnan(record.value(feature)) else 0.0,
            record.idx,
        ),
    )
    return ranked[:k]


def _retract_highest(
    records: Sequence[PositiveRecord], feature: str, k: int
) -> list[PositiveRecord]:
    ranked = sorted(
        records,
        key=lambda record: (
            math.isnan(record.value(feature)),
            -(record.value(feature) if not math.isnan(record.value(feature)) else 0.0),
            record.idx,
        ),
    )
    return ranked[:k]


def _post_scores(
    labels: Sequence[bool],
    predictions: Sequence[bool | None],
    retracted_positions: set[int],
    indices: Sequence[int],
) -> dict[str, Any]:
    post = [predictions[i] and i not in retracted_positions for i in indices]
    scores = detection_scores([labels[i] for i in indices], post)
    return {
        "tp": scores["confusion"]["tp"],
        "fp": scores["confusion"]["fp"],
        "tn": scores["confusion"]["tn"],
        "fn": scores["confusion"]["fn"],
        "precision": scores["precision"],
        "recall": scores["recall"],
        "specificity": scores["specificity"],
        "positive_f1": scores["positive_f1"],
        "macro_f1": scores["macro_f1"],
        "balanced_accuracy": scores["balanced_accuracy"],
        "mcc": scores["mcc"],
        "accuracy": scores["accuracy"],
        "predicted_positive_rate": scores["predicted_positive_rate"],
    }


def matched_budget_table(
    *,
    labels: Sequence[bool],
    first_pass_predictions: Sequence[bool | None],
    positive_records: Sequence[PositiveRecord],
    sample_indices: Sequence[int],
    k: int,
    resamples: int = 10_000,
    seed: int = 42,
) -> dict[str, Any]:
    """Compare the verifier's retraction set with fixed-budget shortcuts.

    ``k`` is the number of positives the verifier retracted.  Every heuristic
    retracts exactly ``k`` positives, so differences are about *which*
    positives are dropped, not about the operating point.  The random baseline
    is the analytic null: a uniformly random ``k``-subset of the positives.

    ``sample_indices[i]`` is the dataset ``idx`` of array position ``i``; it is
    needed because predictions are indexed by position while the heuristics
    are keyed by ``idx``.
    """
    if len(sample_indices) != len(labels):
        raise ValueError("sample_indices and labels must have the same length")
    valid_indices = [
        position for position, prediction in enumerate(first_pass_predictions) if prediction is not None
    ]
    positive_positions = [i for i, prediction in enumerate(first_pass_predictions) if prediction is True]
    if k < 0 or k > len(positive_positions):
        raise ValueError("k must be between 0 and the number of positives")
    if len(positive_records) != len(positive_positions):
        raise ValueError(
            f"{len(positive_records)} positive records but {len(positive_positions)} positive predictions"
        )
    pos_by_idx = {record.idx: position for record, position in zip(positive_records, positive_positions)}
    expected_indices = [sample_indices[position] for position in positive_positions]
    if [record.idx for record in positive_records] != expected_indices:
        raise ValueError("positive_records are not in the same order as the positive predictions")
    all_indices = list(range(len(labels)))

    rules: dict[str, list[PositiveRecord]] = {"random": []}
    rules["confidence_lowest"] = _retract_lowest(positive_records, "first_pass_confidence", k)
    rules["confidence_highest"] = _retract_highest(positive_records, "first_pass_confidence", k)
    rules["evidence_lines_fewest"] = _retract_lowest(positive_records, "evidence_line_count", k)
    rules["evidence_lines_most"] = _retract_highest(positive_records, "evidence_line_count", k)
    rules["lines_shortest"] = _retract_lowest(positive_records, "lines", k)
    rules["lines_longest"] = _retract_highest(positive_records, "lines", k)
    rules["call_count_fewest"] = _retract_lowest(positive_records, "call_count", k)
    rules["call_count_most"] = _retract_highest(positive_records, "call_count", k)

    table: dict[str, Any] = {}
    for name, selected in rules.items():
        if name == "random":
            continue
        retracted_positions = {pos_by_idx[record.idx] for record in selected}
        table[name] = {
            "retracted": len(selected),
            "tp_retracted": sum(1 for record in selected if record.label),
            "fp_retracted": sum(1 for record in selected if not record.label),
            "post": _post_scores(labels, first_pass_predictions, retracted_positions, all_indices),
        }

    # Random k-subset null: exact expected confusion plus percentile intervals
    # from a fixed-seed simulation.
    positives = list(positive_records)
    tp_total = sum(1 for record in positives if record.label)
    fp_total = len(positives) - tp_total
    expected = {
        "tp_retracted": k * tp_total / len(positives) if positives else None,
        "fp_retracted": k * fp_total / len(positives) if positives else None,
    }
    rng = random.Random(seed)
    draws: dict[str, list[float]] = {"macro_f1": [], "mcc": [], "positive_f1": []}
    tp_draws: list[int] = []
    for _ in range(resamples):
        chosen = rng.sample(range(len(positives)), k) if k else []
        retracted_positions = {positive_positions[j] for j in chosen}
        tp_draws.append(sum(1 for j in chosen if positives[j].label))
        scores = detection_scores(
            labels,
            [
                prediction and position not in retracted_positions
                for position, prediction in enumerate(first_pass_predictions)
            ],
        )
        for key in draws:
            value = scores.get(key)
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                draws[key].append(float(value))
    random_block: dict[str, Any] = {
        "retracted": k,
        "expected_tp_retracted": expected["tp_retracted"],
        "expected_fp_retracted": expected["fp_retracted"],
        "tp_retracted_interval": [
            percentile([float(x) for x in tp_draws], 0.025),
            percentile([float(x) for x in tp_draws], 0.975),
        ],
        "macro_f1": {
            "mean": sum(draws["macro_f1"]) / len(draws["macro_f1"]) if draws["macro_f1"] else None,
            "p2_5": percentile(draws["macro_f1"], 0.025),
            "p97_5": percentile(draws["macro_f1"], 0.975),
        },
        "mcc": {
            "mean": sum(draws["mcc"]) / len(draws["mcc"]) if draws["mcc"] else None,
            "p2_5": percentile(draws["mcc"], 0.025),
            "p97_5": percentile(draws["mcc"], 0.975),
        },
        "positive_f1": {
            "mean": sum(draws["positive_f1"]) / len(draws["positive_f1"])
            if draws["positive_f1"]
            else None,
            "p2_5": percentile(draws["positive_f1"], 0.025),
            "p97_5": percentile(draws["positive_f1"], 0.975),
        },
        "resamples": resamples,
        "seed": seed,
        "valid_indices": len(valid_indices),
    }
    table["random"] = random_block
    return table
