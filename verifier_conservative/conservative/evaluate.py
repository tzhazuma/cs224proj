"""Evaluation for the conservative three-way verifier.

Every number here is descriptive or exploratory: the frozen test split was
already used to evaluate the first pass and the original verifier.  The module
reads existing artifacts only and writes under ``verifier_conservative/analysis``.

Comparison rows per arm:

* ``pre`` - frozen first pass;
* ``original_fail_closed`` - the original verifier's primary rule;
* ``original_fail_open`` - original rule with verifier failures kept;
* ``original_refutation_only`` - the original post-hoc rule (keep
  ``insufficient_evidence``);
* ``original_guard_only`` - replay of the original records under this
  experiment's strict rule (only grounded ``guard_present``);
* ``conservative`` - the three-way verifier and its decision rule.
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
for _path in (PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from analysis.stats import (  # noqa: E402
    cluster_bootstrap,
    detection_scores,
    holm_adjust,
    mcnemar_exact,
    percentile,
    wilson_interval,
)
from secvul_runner.datasets import FunctionSample, LoadedDataset, load_dataset  # noqa: E402
from secvul_runner.util import read_json, sha256_file  # noqa: E402

from . import (  # noqa: E402
    ANALYSIS_STATUS,
    ANALYSIS_STATUS_MEANING,
    PROMPT_VERSION,
)
from .prompt import split_source, template_sha256  # noqa: E402
from .schema import line_quality  # noqa: E402

DEFAULT_DATASET = PROJECT_ROOT / "splits" / "test_detection_160.json"
DEFAULT_OUT = PROJECT_ROOT / "verifier_conservative" / "analysis"
FIRST_PASS_ROOT = PROJECT_ROOT / "evidence_prompt" / "runs"
ORIGINAL_ROOT = PROJECT_ROOT / "evidence_verify" / "runs"
CONSERVATIVE_ROOT = PROJECT_ROOT / "verifier_conservative" / "runs"

FIRST_PASS_RUNS = {
    "deepseek": FIRST_PASS_ROOT / "test_evidence_deepseek",
    "mimo": FIRST_PASS_ROOT / "test_evidence_mimo",
}

ARMS: tuple[dict[str, str], ...] = (
    {
        "arm_id": "deepseek_self",
        "claim_model": "deepseek",
        "verifier_model": "deepseek",
        "kind": "self",
        "original_dir": "test_verify_deepseek_self",
        "conservative_dir": "test_conservative_deepseek_self",
        "dryrun_dir": "dryrun_conservative_deepseek_self",
    },
    {
        "arm_id": "deepseek_cross",
        "claim_model": "deepseek",
        "verifier_model": "mimo",
        "kind": "cross",
        "original_dir": "test_verify_deepseek_by_mimo",
        "conservative_dir": "test_conservative_deepseek_by_mimo",
        "dryrun_dir": "dryrun_conservative_deepseek_by_mimo",
    },
    {
        "arm_id": "mimo_self",
        "claim_model": "mimo",
        "verifier_model": "mimo",
        "kind": "self",
        "original_dir": "test_verify_mimo_self",
        "conservative_dir": "test_conservative_mimo_self",
        "dryrun_dir": "dryrun_conservative_mimo_self",
    },
    {
        "arm_id": "mimo_cross",
        "claim_model": "mimo",
        "verifier_model": "deepseek",
        "kind": "cross",
        "original_dir": "test_verify_mimo_by_deepseek",
        "conservative_dir": "test_conservative_mimo_by_deepseek",
        "dryrun_dir": "dryrun_conservative_mimo_by_deepseek",
    },
)

STRATEGY_LABELS = {
    "pre": "first pass (pre)",
    "original_fail_closed": "original verifier (fail-closed)",
    "original_fail_open": "original verifier (fail-open)",
    "original_refutation_only": "original verifier (refutation-only, post hoc)",
    "original_guard_only": "original records, strict guard-only replay",
    "conservative": "conservative three-way verifier",
}

METRIC_KEYS = (
    "precision",
    "recall",
    "specificity",
    "positive_f1",
    "macro_f1",
    "balanced_accuracy",
    "accuracy",
    "strict_accuracy",
    "mcc",
    "predicted_positive_rate",
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise SystemExit(f"{path}:{line_number}: record is not an object")
            records.append(record)
    return records


def load_split(path: Path) -> tuple[LoadedDataset, list[FunctionSample]]:
    dataset = load_dataset(path, "independent")
    samples = [sample for sample in dataset.units if isinstance(sample, FunctionSample)]
    if len(samples) != len(dataset.units):
        raise SystemExit(f"{path}: unexpected pair records in an independent split")
    return dataset, samples


def index_records(records: Sequence[dict[str, Any]], path: Path) -> dict[int, dict[str, Any]]:
    by_idx: dict[int, dict[str, Any]] = {}
    for record in records:
        idx = record.get("idx")
        if not isinstance(idx, int) or isinstance(idx, bool):
            raise SystemExit(f"{path}: record without an integer idx")
        if idx in by_idx:
            raise SystemExit(f"{path}: duplicate idx {idx}")
        by_idx[idx] = record
    return by_idx


def first_pass_predictions(
    samples: Sequence[FunctionSample], by_idx: dict[int, dict[str, Any]], path: Path
) -> tuple[list[bool | None], dict[int, dict[str, Any]]]:
    predictions: list[bool | None] = []
    parsed_by_idx: dict[int, dict[str, Any]] = {}
    for sample in samples:
        record = by_idx.get(sample.idx)
        if record is None:
            raise SystemExit(f"{path}: missing idx {sample.idx}")
        if bool(record.get("label")) != sample.label:
            raise SystemExit(f"{path}: label mismatch at idx {sample.idx}")
        parsed = record.get("parsed")
        if record.get("status") != "ok" or not isinstance(parsed, dict):
            predictions.append(None)
            continue
        value = parsed.get("is_vulnerable")
        if not isinstance(value, bool):
            predictions.append(None)
            continue
        predictions.append(value)
        parsed_by_idx[sample.idx] = parsed
    return predictions, parsed_by_idx


# ---------------------------------------------------------------------------
# Retraction sets
# ---------------------------------------------------------------------------


def _parsed_ok(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(record, dict):
        return None
    if record.get("status") != "ok":
        return None
    parsed = record.get("parsed")
    return parsed if isinstance(parsed, dict) else None


def original_retraction_sets(
    samples: Sequence[FunctionSample],
    by_idx: dict[int, dict[str, Any]],
) -> dict[str, set[int]]:
    """Build the original verifier's four decision sets from recorded outputs."""
    any_closed: set[int] = set()
    any_open: set[int] = set()
    refutation_closed: set[int] = set()
    guard_only: set[int] = set()
    for sample in samples:
        parsed = _parsed_ok(by_idx.get(sample.idx))
        if parsed is None:
            any_closed.add(sample.idx)
            refutation_closed.add(sample.idx)
            continue
        if parsed.get("verdict") != "retract":
            continue
        any_closed.add(sample.idx)
        any_open.add(sample.idx)
        rebuttal_type = parsed.get("rebuttal_type")
        if rebuttal_type != "insufficient_evidence":
            refutation_closed.add(sample.idx)
        if rebuttal_type == "guard_present":
            lines = parsed.get("rebuttal_lines")
            if isinstance(lines, list) and all(
                isinstance(value, int) and not isinstance(value, bool) for value in lines
            ):
                quality = line_quality(split_source(sample.func_body), lines)
                if quality["rebuttal_grounded"] and quality["code_line_cited"]:
                    guard_only.add(sample.idx)
    return {
        "original_fail_closed": any_closed,
        "original_fail_open": any_open,
        "original_refutation_only": refutation_closed,
        "original_guard_only": guard_only,
    }


def conservative_retraction_set(
    samples: Sequence[FunctionSample],
    by_idx: dict[int, dict[str, Any]],
) -> set[int]:
    retract: set[int] = set()
    for sample in samples:
        record = by_idx.get(sample.idx)
        decision = record.get("decision") if isinstance(record, dict) else None
        if isinstance(decision, dict) and decision.get("retract") is True:
            retract.add(sample.idx)
    return retract


def post_from_retraction(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    retract: set[int],
) -> list[bool | None]:
    return [
        False if (prediction is True and sample.idx in retract) else prediction
        for sample, prediction in zip(samples, pre)
    ]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def compact_scores(block: dict[str, Any]) -> dict[str, Any]:
    result = {key: block.get(key) for key in METRIC_KEYS}
    result["confusion"] = block.get("confusion")
    result["valid"] = block.get("valid")
    result["invalid"] = block.get("invalid")
    return result


def delta_block(pre: dict[str, Any], post: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in METRIC_KEYS:
        a, b = pre.get(key), post.get(key)
        result[key] = (
            (float(b) - float(a))
            if isinstance(a, (int, float)) and isinstance(b, (int, float))
            else None
        )
    for key in ("tp", "fp", "tn", "fn"):
        result[key] = int(post["confusion"][key]) - int(pre["confusion"][key])
    return result


def hypergeom_sf(population: int, successes: int, draws: int, observed: int) -> float:
    """P(X >= observed) for a hypergeometric draw without replacement."""
    if draws <= 0:
        return 1.0
    upper = min(successes, draws)
    if observed > upper:
        return 0.0
    numerator = sum(
        math.comb(successes, i) * math.comb(population - successes, draws - i)
        for i in range(max(0, observed), upper + 1)
        if 0 <= draws - i <= population - successes
    )
    denominator = math.comb(population, draws)
    return numerator / denominator


def mcnemar_block(
    labels: Sequence[bool],
    pre: Sequence[bool | None],
    post: Sequence[bool | None],
) -> dict[str, Any]:
    pre_correct = post_correct = both = neither = 0
    pre_right_post_wrong = pre_wrong_post_right = 0
    for label, a, b in zip(labels, pre, post):
        a_right = a is not None and bool(a) == bool(label)
        b_right = b is not None and bool(b) == bool(label)
        if a_right and b_right:
            both += 1
        elif a_right and not b_right:
            pre_right_post_wrong += 1
        elif not a_right and b_right:
            pre_wrong_post_right += 1
        else:
            neither += 1
        pre_correct += int(a_right)
        post_correct += int(b_right)
    test = mcnemar_exact(
        a_correct_b_wrong=pre_right_post_wrong,
        a_wrong_b_correct=pre_wrong_post_right,
        total=len(labels),
    )
    return {
        "n": len(labels),
        "pre_correct": pre_correct,
        "post_correct": post_correct,
        "both_correct": both,
        "both_wrong": neither,
        "pre_correct_post_wrong": pre_right_post_wrong,
        "pre_wrong_post_correct": pre_wrong_post_right,
        "discordant": test["discordant"],
        "p_value_exact_two_sided": test["p_value"],
        "method": "exact two-sided McNemar on strict-correctness outcomes",
    }


def retraction_block(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    retract: set[int],
    parsed_ids: set[int],
) -> dict[str, Any]:
    positives = [sample for sample, prediction in zip(samples, pre) if prediction is True]
    positive_ids = {sample.idx for sample in positives}
    selected = [sample for sample in positives if sample.idx in retract]
    if set(retract) - positive_ids:
        raise SystemExit("retraction set contains a non-positive sample")
    parsed_selected = [sample for sample in selected if sample.idx in parsed_ids]
    tp_retracted = sum(1 for sample in selected if sample.label)
    fp_retracted = sum(1 for sample in selected if not sample.label)
    tp_parsed = sum(1 for sample in parsed_selected if sample.label)
    fp_parsed = sum(1 for sample in parsed_selected if not sample.label)
    tp_total = sum(1 for sample in positives if sample.label)
    fp_total = len(positives) - tp_total
    k = len(selected)
    parsed_k = len(parsed_selected)
    population = len(positives)
    expected_fp = parsed_k * fp_total / population if population else None
    return {
        "verifiable_positives": population,
        "tp_positives": tp_total,
        "fp_positives": fp_total,
        "retracted": k,
        "parsed_retracted": parsed_k,
        "invalid_forced_retracted": k - parsed_k,
        "retract_rate_of_verified": (k / population) if population else None,
        "tp_retracted": tp_retracted,
        "fp_retracted": fp_retracted,
        "parsed_tp_retracted": tp_parsed,
        "parsed_fp_retracted": fp_parsed,
        "retraction_precision": (fp_parsed / parsed_k) if parsed_k else None,
        "retraction_precision_wilson": wilson_interval(fp_parsed, parsed_k)
        if parsed_k
        else None,
        "end_to_end_fp_share": (fp_retracted / k) if k else None,
        "tp_loss_rate": (tp_retracted / tp_total) if tp_total else None,
        "fp_correction_rate": (fp_retracted / fp_total) if fp_total else None,
        "base_fp_rate_among_positives": (fp_total / population) if population else None,
        "expected_fp_retracted_under_random": expected_fp,
        "excess_fp_retractions": (fp_parsed - expected_fp)
        if expected_fp is not None
        else None,
        "hypergeom_p_fp_enrichment": hypergeom_sf(
            population, fp_total, parsed_k, fp_parsed
        )
        if parsed_k
        else 1.0,
        "retracted_indices": sorted(sample.idx for sample in selected),
    }


def _quick_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    label_positive = tp + fn
    label_negative = tn + fp
    predicted_positive = tp + fp
    predicted_negative = tn + fn
    precision = tp / predicted_positive if predicted_positive else 0.0
    recall = tp / label_positive if label_positive else 0.0
    specificity = tn / label_negative if label_negative else 0.0
    positive_f1 = (
        2.0 * tp / (2.0 * tp + fp + fn) if label_positive and predicted_positive else 0.0
    )
    negative_f1 = (
        2.0 * tn / (2.0 * tn + fn + fp) if label_negative and predicted_negative else 0.0
    )
    macro_f1 = (positive_f1 + negative_f1) / 2.0
    denominator = math.sqrt(
        float(predicted_positive * label_positive * label_negative * predicted_negative)
    )
    mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "positive_f1": positive_f1,
        "macro_f1": macro_f1,
        "mcc": mcc,
    }


def _base_confusion(
    labels: Sequence[bool], pre: Sequence[bool | None]
) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, pre):
        if prediction is None:
            continue
        if label and prediction:
            tp += 1
        elif label:
            fn += 1
        elif prediction:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def random_budget(
    labels: Sequence[bool],
    pre: Sequence[bool | None],
    k: int,
    *,
    resamples: int = 10_000,
    seed: int = 42,
) -> dict[str, Any]:
    """Uniform k-subset retraction null, with exact expected confusion."""
    positive_positions = [i for i, prediction in enumerate(pre) if prediction is True]
    if k < 0 or k > len(positive_positions):
        raise ValueError("k must be between 0 and the number of positives")
    tp, fp, tn, fn = _base_confusion(labels, pre)
    tp_total = sum(1 for i in positive_positions if labels[i])
    fp_total = len(positive_positions) - tp_total
    expected_tp = k * tp_total / len(positive_positions) if positive_positions else None
    expected_fp = k * fp_total / len(positive_positions) if positive_positions else None

    rng = random.Random(seed)
    draws = {"macro_f1": [], "mcc": [], "positive_f1": [], "tp_retracted": []}
    for _ in range(resamples):
        chosen = rng.sample(range(len(positive_positions)), k) if k else []
        a = sum(1 for j in chosen if labels[positive_positions[j]])
        b = k - a
        metrics = _quick_metrics(tp - a, fp - b, tn + b, fn + a)
        for key in ("macro_f1", "mcc", "positive_f1"):
            draws[key].append(metrics[key])
        draws["tp_retracted"].append(float(a))

    def summary(values: list[float]) -> dict[str, Any]:
        return {
            "mean": sum(values) / len(values) if values else None,
            "p2_5": percentile(values, 0.025),
            "p97_5": percentile(values, 0.975),
        }

    base_metrics = _quick_metrics(tp, fp, tn, fn)
    return {
        "retracted": k,
        "expected_tp_retracted": expected_tp,
        "expected_fp_retracted": expected_fp,
        "tp_retracted_interval": [
            percentile(draws["tp_retracted"], 0.025),
            percentile(draws["tp_retracted"], 0.975),
        ],
        "macro_f1": {
            **summary(draws["macro_f1"]),
            "delta_vs_pre": summary(draws["macro_f1"])["mean"] - base_metrics["macro_f1"]
            if draws["macro_f1"]
            else None,
        },
        "mcc": {
            **summary(draws["mcc"]),
            "delta_vs_pre": summary(draws["mcc"])["mean"] - base_metrics["mcc"]
            if draws["mcc"]
            else None,
        },
        "positive_f1": summary(draws["positive_f1"]),
        "resamples": resamples,
        "seed": seed,
    }


def low_confidence_budget(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    parsed_by_idx: dict[int, dict[str, Any]],
    k: int,
) -> dict[str, Any]:
    """Retract the k positives with the lowest first-pass confidence."""
    positives = [sample for sample, prediction in zip(samples, pre) if prediction is True]

    def key(sample: FunctionSample) -> tuple[int, float, int]:
        parsed = parsed_by_idx.get(sample.idx) or {}
        value = parsed.get("confidence")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return (0, float(value), sample.idx)
        return (1, 0.0, sample.idx)

    ranked = sorted(positives, key=key)
    selected = ranked[:k]
    tp_retracted = sum(1 for sample in selected if sample.label)
    fp_retracted = len(selected) - tp_retracted
    tp_total = sum(1 for sample in positives if sample.label)
    fp_total = len(positives) - tp_total
    labels = [sample.label for sample in samples]
    post = post_from_retraction(samples, pre, {sample.idx for sample in selected})
    scores = detection_scores(labels, post)
    return {
        "retracted": len(selected),
        "tp_retracted": tp_retracted,
        "fp_retracted": fp_retracted,
        "retraction_precision": (fp_retracted / len(selected)) if selected else None,
        "tp_loss_rate": (tp_retracted / tp_total) if tp_total else None,
        "fp_correction_rate": (fp_retracted / fp_total) if fp_total else None,
        "macro_f1": scores["macro_f1"],
        "mcc": scores["mcc"],
        "positive_f1": scores["positive_f1"],
        "retracted_indices": sorted(sample.idx for sample in selected),
    }


def bootstrap_deltas(
    labels: Sequence[bool],
    pre: Sequence[bool | None],
    post: Sequence[bool | None],
    cluster_ids: Sequence[str],
    *,
    resamples: int = 10_000,
    seed: int = 42,
) -> dict[str, Any]:
    metric_names = ("macro_f1", "mcc", "positive_f1", "recall", "specificity")

    def make(metric: str):
        def fn(indices: Sequence[int]) -> float | None:
            a = detection_scores(labels, pre, indices).get(metric)
            b = detection_scores(labels, post, indices).get(metric)
            if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
                return None
            return float(b) - float(a)

        return fn

    block = cluster_bootstrap(
        cluster_ids,
        {name: make(name) for name in metric_names},
        resamples=resamples,
        seed=seed,
    )
    return {
        "settings": block.get("settings"),
        "cluster_count": block.get("cluster_count"),
        "deltas": block.get("metrics"),
    }


# ---------------------------------------------------------------------------
# Strategy assembly
# ---------------------------------------------------------------------------


def strategy_block(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    retract: set[int],
    parsed_ids: set[int],
    labels: Sequence[bool],
    pre_scores: dict[str, Any],
    parsed_by_idx: dict[int, dict[str, Any]],
    *,
    bootstrap: bool = False,
    cluster_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    post = post_from_retraction(samples, pre, retract)
    scores = detection_scores(labels, post)
    block = {
        "scores": compact_scores(scores),
        "delta_vs_pre": delta_block(pre_scores, scores),
        "mcnemar_vs_pre": mcnemar_block(labels, pre, post),
        "retraction": retraction_block(samples, pre, retract, parsed_ids),
        "matched_budget": {
            "random": random_budget(labels, pre, len(retract)),
            "low_confidence": low_confidence_budget(
                samples, pre, parsed_by_idx, len(retract)
            ),
        },
    }
    if bootstrap:
        if cluster_ids is None:
            raise ValueError("cluster_ids are required for a bootstrap block")
        block["bootstrap_delta"] = bootstrap_deltas(labels, pre, post, cluster_ids)
    return block


def taxonomy_block(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ok = [
        record
        for record in records
        if record.get("status") == "ok" and isinstance(record.get("parsed"), dict)
    ]
    types: dict[str, dict[str, int]] = {}
    for record in ok:
        parsed = record["parsed"]
        key = str(parsed.get("rebuttal_type"))
        bucket = types.setdefault(key, {"total": 0, "tp": 0, "fp": 0})
        bucket["total"] += 1
        bucket["tp" if bool(record.get("label")) else "fp"] += 1
    return {"rebuttal_types": types}


def conservative_taxonomy(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ok = [
        record
        for record in records
        if record.get("status") == "ok" and isinstance(record.get("parsed"), dict)
    ]
    by_assessment: dict[str, dict[str, int]] = {}
    by_kind: dict[str, dict[str, int]] = {}
    by_reason: dict[str, int] = {}
    confidence: dict[str, list[float]] = {}
    for record in ok:
        parsed = record["parsed"]
        label = bool(record.get("label"))
        bucket = by_assessment.setdefault(
            str(parsed.get("assessment")), {"total": 0, "tp": 0, "fp": 0}
        )
        bucket["total"] += 1
        bucket["tp" if label else "fp"] += 1
        kind = str(parsed.get("rebuttal_kind"))
        kind_bucket = by_kind.setdefault(kind, {"total": 0, "tp": 0, "fp": 0})
        kind_bucket["total"] += 1
        kind_bucket["tp" if label else "fp"] += 1
        reason = str((record.get("decision") or {}).get("reason"))
        by_reason[reason] = by_reason.get(reason, 0) + 1
        value = parsed.get("confidence")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            confidence.setdefault(str(parsed.get("assessment")), []).append(float(value))
    return {
        "by_assessment": by_assessment,
        "by_rebuttal_kind": by_kind,
        "by_decision_reason": by_reason,
        "mean_confidence_by_assessment": {
            key: (sum(values) / len(values)) if values else None
            for key, values in confidence.items()
        },
    }


def failure_block(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    failures = []
    families: dict[str, int] = {}
    for record in records:
        if record.get("status") == "ok":
            continue
        validation = record.get("validation") or {}
        response = record.get("response") or {}
        response_error = response.get("error") or {}
        family = str(validation.get("error_family"))
        families[family] = families.get(family, 0) + 1
        failures.append(
            {
                "idx": record.get("idx"),
                "label": record.get("label"),
                "status": record.get("status"),
                "error_family": family,
                "error": validation.get("error"),
                "http_status": response.get("http_status"),
                "response_error_type": response_error.get("type"),
                "response_error_message": response_error.get("message"),
            }
        )
    return {"count": len(failures), "by_family": families, "records": failures}


def agreement_block(
    left: set[int], right: set[int], positive_indices: Sequence[int]
) -> dict[str, Any]:
    common = sorted(set(positive_indices))
    a = [idx in left for idx in common]
    b = [idx in right for idx in common]
    agree = sum(1 for x, y in zip(a, b) if x == y)
    p_left = sum(a) / len(a) if a else 0.0
    p_right = sum(b) / len(b) if b else 0.0
    expected = p_left * p_right + (1 - p_left) * (1 - p_right)
    kappa = ((agree / len(a)) - expected) / (1 - expected) if expected < 1 else None
    return {
        "n": len(common),
        "agreement": agree / len(common) if common else None,
        "cohen_kappa": kappa,
        "both_retract": sum(1 for x, y in zip(a, b) if x and y),
        "both_keep": sum(1 for x, y in zip(a, b) if not x and not y),
        "left_retract_only": sum(1 for x, y in zip(a, b) if x and not y),
        "right_retract_only": sum(1 for x, y in zip(a, b) if not x and y),
        "left_retract_rate": p_left,
        "right_retract_rate": p_right,
    }


def prompt_audit(
    dryrun_dir: Path, records: Sequence[dict[str, Any]], manifest: dict[str, Any]
) -> dict[str, Any]:
    dry_path = dryrun_dir / "dry_run_requests.jsonl"
    if not dry_path.exists():
        return {"available": False, "reason": "dry_run_requests.jsonl missing"}
    dry = {record["cache_key"]: record for record in read_jsonl(dry_path)}
    matches = mismatches = missing = 0
    for record in records:
        key = (record.get("cache") or {}).get("key")
        reference = dry.get(key)
        if reference is None:
            missing += 1
            continue
        if reference.get("body_sha256") == (record.get("request") or {}).get("body_sha256"):
            matches += 1
        else:
            mismatches += 1
    isolation_violations = 0
    for record in records:
        prompt = record.get("prompt") or {}
        if prompt.get("only_source_and_claim_variable") is not True:
            isolation_violations += 1
        if prompt.get("source_reconstructed") is not True:
            isolation_violations += 1
        if prompt.get("claim_source") != "first_pass_model_output":
            isolation_violations += 1
        if prompt.get("input_fields") != [
            "func_body",
            "claim.evidence_lines",
            "claim.mechanism",
        ]:
            isolation_violations += 1
    api = manifest.get("api") or {}
    return {
        "available": True,
        "requests_compared": len(records),
        "body_sha256_matches": matches,
        "body_sha256_mismatches": mismatches,
        "body_sha256_missing": missing,
        "all_bodies_match_dry_run": mismatches == 0
        and missing == 0
        and matches == len(records),
        "isolation_violations": isolation_violations,
        "api_key_value_stored": api.get("api_key_value_stored"),
        "authorization_header_stored": manifest.get("authorization_header_stored"),
        "template_sha256": (manifest.get("config") or {}).get("template_sha256"),
    }


def token_cost_block(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    costs: list[float] = []
    prompt_tokens: list[int] = []
    completion_tokens: list[int] = []
    latencies: list[float] = []
    for record in records:
        response = record.get("response")
        if not isinstance(response, dict):
            continue
        cost = (response.get("cost") or {}).get("cost_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            costs.append(float(cost))
        usage = response.get("usage") or {}
        for key, target in (
            ("prompt_tokens", prompt_tokens),
            ("completion_tokens", completion_tokens),
        ):
            value = usage.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                target.append(value)
        latency = response.get("request_latency_seconds")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool):
            latencies.append(float(latency))
    ordered = sorted(latencies)
    return {
        "requests": len(records),
        "requests_with_cost": len(costs),
        "total_cost_usd": sum(costs) if costs else None,
        "mean_cost_usd": (sum(costs) / len(costs)) if costs else None,
        "prompt_tokens_sum": sum(prompt_tokens) if prompt_tokens else None,
        "completion_tokens_sum": sum(completion_tokens) if completion_tokens else None,
        "mean_prompt_tokens": (sum(prompt_tokens) / len(prompt_tokens))
        if prompt_tokens
        else None,
        "mean_completion_tokens": (sum(completion_tokens) / len(completion_tokens))
        if completion_tokens
        else None,
        "latency_seconds": {
            "mean": (sum(latencies) / len(latencies)) if latencies else None,
            "p50": percentile(ordered, 0.5) if ordered else None,
            "p95": percentile(ordered, 0.95) if ordered else None,
            "max": ordered[-1] if ordered else None,
        },
    }


def cost_block(
    first_pass_cost: float | None,
    verifier_cost: float | None,
    *,
    units: int,
    fp_corrected: int,
    tp_lost: int,
) -> dict[str, Any]:
    pipeline = (
        first_pass_cost + verifier_cost
        if first_pass_cost is not None and verifier_cost is not None
        else None
    )
    return {
        "first_pass_usd": first_pass_cost,
        "verifier_usd": verifier_cost,
        "pipeline_usd": pipeline,
        "verifier_increment_ratio": (verifier_cost / first_pass_cost)
        if verifier_cost is not None and first_pass_cost
        else None,
        "verifier_usd_per_100_units": (verifier_cost / units * 100)
        if verifier_cost is not None
        else None,
        "verifier_usd_per_fp_corrected": (verifier_cost / fp_corrected)
        if verifier_cost is not None and fp_corrected
        else None,
        "verifier_usd_per_tp_lost": (verifier_cost / tp_lost)
        if verifier_cost is not None and tp_lost
        else None,
        "baseline_incremental_usd": 0.0,
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_metrics(dataset_path: Path) -> dict[str, Any]:
    dataset, samples = load_split(dataset_path)
    labels = [sample.label for sample in samples]
    cluster_ids = [sample.project for sample in samples]
    sample_position = {sample.idx: position for position, sample in enumerate(samples)}

    first_pass: dict[str, Any] = {}
    first_pass_predictions_by_model: dict[str, list[bool | None]] = {}
    first_pass_parsed_by_model: dict[str, dict[int, dict[str, Any]]] = {}
    pre_scores_by_model: dict[str, dict[str, Any]] = {}

    for model, run_dir in FIRST_PASS_RUNS.items():
        path = run_dir / "results.jsonl"
        manifest = read_json(run_dir / "manifest.json")
        records = read_jsonl(path)
        by_idx = index_records(records, path)
        predictions, parsed_by_idx = first_pass_predictions(samples, by_idx, path)
        first_pass_predictions_by_model[model] = predictions
        first_pass_parsed_by_model[model] = parsed_by_idx
        scores = detection_scores(labels, predictions)
        pre_scores_by_model[model] = scores
        first_pass[model] = {
            "run_dir": str(run_dir),
            "results_sha256": sha256_file(path),
            "manifest_results_sha256": manifest.get("results_sha256"),
            "manifest_sha256": sha256_file(run_dir / "manifest.json"),
            "records": len(records),
            "status_counts": {
                status: sum(1 for record in records if record.get("status") == status)
                for status in sorted({str(record.get("status")) for record in records})
            },
            "scores": compact_scores(scores),
            "cost": token_cost_block(records),
            "manifest_summary": manifest.get("summary"),
        }

    arm_results: dict[str, Any] = {}
    for arm in ARMS:
        original_dir = ORIGINAL_ROOT / arm["original_dir"]
        conservative_dir = CONSERVATIVE_ROOT / arm["conservative_dir"]
        original_manifest = read_json(original_dir / "manifest.json")
        conservative_manifest = read_json(conservative_dir / "manifest.json")
        original_records = read_jsonl(original_dir / "results.jsonl")
        conservative_records = read_jsonl(conservative_dir / "results.jsonl")
        original_by_idx = index_records(original_records, original_dir / "results.jsonl")
        conservative_by_idx = index_records(
            conservative_records, conservative_dir / "results.jsonl"
        )

        claim_model = arm["claim_model"]
        pre = first_pass_predictions_by_model[claim_model]
        pre_scores = pre_scores_by_model[claim_model]
        parsed_by_idx = first_pass_parsed_by_model[claim_model]
        positive_ids = {
            sample.idx for sample, prediction in zip(samples, pre) if prediction is True
        }
        original_sets = {
            name: {idx for idx in values if idx in positive_ids}
            for name, values in original_retraction_sets(samples, original_by_idx).items()
        }
        conservative_set = conservative_retraction_set(samples, conservative_by_idx)
        original_parsed_ids = {
            sample.idx
            for sample in samples
            if _parsed_ok(original_by_idx.get(sample.idx)) is not None
        }
        conservative_parsed_ids = {
            sample.idx
            for sample in samples
            if isinstance(conservative_by_idx.get(sample.idx), dict)
            and conservative_by_idx[sample.idx].get("status") == "ok"
            and isinstance(conservative_by_idx[sample.idx].get("parsed"), dict)
        }

        strategies: dict[str, Any] = {
            "pre": {
                "scores": compact_scores(pre_scores),
                "delta_vs_pre": {key: 0.0 for key in METRIC_KEYS},
                "mcnemar_vs_pre": mcnemar_block(labels, pre, pre),
                "retraction": retraction_block(samples, pre, set(), set()),
                "matched_budget": {
                    "random": random_budget(labels, pre, 0),
                    "low_confidence": low_confidence_budget(samples, pre, parsed_by_idx, 0),
                },
            }
        }
        for name, retract in original_sets.items():
            strategies[name] = strategy_block(
                samples,
                pre,
                retract,
                original_parsed_ids,
                labels,
                pre_scores,
                parsed_by_idx,
                bootstrap=name == "original_fail_closed",
                cluster_ids=cluster_ids,
            )
        strategies["conservative"] = strategy_block(
            samples,
            pre,
            conservative_set,
            conservative_parsed_ids,
            labels,
            pre_scores,
            parsed_by_idx,
            bootstrap=True,
            cluster_ids=cluster_ids,
        )

        first_cost = first_pass[claim_model]["cost"]["total_cost_usd"]
        original_cost = token_cost_block(original_records)["total_cost_usd"]
        conservative_cost = token_cost_block(conservative_records)["total_cost_usd"]
        for name in (
            "original_fail_closed",
            "original_fail_open",
            "original_refutation_only",
            "original_guard_only",
        ):
            retraction = strategies[name]["retraction"]
            strategies[name]["cost"] = cost_block(
                first_cost,
                original_cost,
                units=len(samples),
                fp_corrected=retraction["fp_retracted"],
                tp_lost=retraction["tp_retracted"],
            )
        strategies["pre"]["cost"] = cost_block(
            first_cost,
            0.0,
            units=len(samples),
            fp_corrected=0,
            tp_lost=0,
        )
        retraction = strategies["conservative"]["retraction"]
        strategies["conservative"]["cost"] = cost_block(
            first_cost,
            conservative_cost,
            units=len(samples),
            fp_corrected=retraction["fp_retracted"],
            tp_lost=retraction["tp_retracted"],
        )

        positive_indices = [
            sample.idx for sample, prediction in zip(samples, pre) if prediction is True
        ]
        agreement = agreement_block(
            original_sets["original_fail_closed"],
            conservative_set,
            positive_indices,
        )

        retraction_cases: list[dict[str, Any]] = []
        for sample in samples:
            record = conservative_by_idx.get(sample.idx)
            if not isinstance(record, dict):
                continue
            decision = record.get("decision") or {}
            if decision.get("retract") is not True:
                continue
            parsed = record.get("parsed") or {}
            validation = record.get("validation") or {}
            lines = parsed.get("rebuttal_lines") or []
            line_texts = split_source(sample.func_body)
            retraction_cases.append(
                {
                    "idx": sample.idx,
                    "label": sample.label,
                    "project": sample.project,
                    "kind": parsed.get("rebuttal_kind"),
                    "assessment": parsed.get("assessment"),
                    "lines": lines,
                    "cited_texts": [
                        line_texts[line - 1]
                        for line in lines
                        if isinstance(line, int) and 1 <= line <= len(line_texts)
                    ],
                    "reason": parsed.get("reason"),
                    "counterexample": parsed.get("counterexample"),
                    "confidence": parsed.get("confidence"),
                    "audit": {
                        "rebuttal_grounded": validation.get("rebuttal_grounded"),
                        "code_line_cited": validation.get("code_line_cited"),
                        "guard_lexical_match": validation.get("guard_lexical_match"),
                        "counterexample_provided": validation.get(
                            "counterexample_provided"
                        ),
                    },
                    "decision_reason": decision.get("reason"),
                }
            )

        arm_results[arm["arm_id"]] = {
            "claim_model": claim_model,
            "verifier_model": arm["verifier_model"],
            "kind": arm["kind"],
            "original_run_dir": str(original_dir),
            "conservative_run_dir": str(conservative_dir),
            "original_results_sha256": sha256_file(original_dir / "results.jsonl"),
            "conservative_results_sha256": sha256_file(conservative_dir / "results.jsonl"),
            "original_manifest_sha256": sha256_file(original_dir / "manifest.json"),
            "conservative_manifest_sha256": sha256_file(
                conservative_dir / "manifest.json"
            ),
            "config": {
                "model": (conservative_manifest.get("config") or {})
                .get("api", {})
                .get("model"),
                "prompt_version": (conservative_manifest.get("config") or {}).get(
                    "prompt_version"
                ),
                "template_sha256": (conservative_manifest.get("config") or {}).get(
                    "template_sha256"
                ),
                "analysis_status": conservative_manifest.get("analysis_status"),
            },
            "conservative_status_counts": {
                status: sum(
                    1 for record in conservative_records if record.get("status") == status
                )
                for status in sorted(
                    {str(record.get("status")) for record in conservative_records}
                )
            },
            "original_status_counts": {
                status: sum(1 for record in original_records if record.get("status") == status)
                for status in sorted(
                    {str(record.get("status")) for record in original_records}
                )
            },
            "strategies": strategies,
            "original_taxonomy": taxonomy_block(original_records),
            "conservative_taxonomy": conservative_taxonomy(conservative_records),
            "conservative_failures": failure_block(conservative_records),
            "original_failures": failure_block(original_records),
            "agreement_original_vs_conservative": agreement,
            "cost": {
                "first_pass": first_pass[claim_model]["cost"],
                "original_verifier": token_cost_block(original_records),
                "conservative_verifier": token_cost_block(conservative_records),
            },
            "audit": prompt_audit(
                CONSERVATIVE_ROOT / arm["dryrun_dir"],
                conservative_records,
                conservative_manifest,
            ),
            "retraction_cases": retraction_cases,
            "conservative_manifest_summary": conservative_manifest.get("summary"),
        }

    # Holm across the four arms for the primary paired tests.
    for strategy in (
        "original_fail_closed",
        "original_refutation_only",
        "original_guard_only",
        "conservative",
    ):
        p_values = [
            arm_results[arm["arm_id"]]["strategies"][strategy]["mcnemar_vs_pre"][
                "p_value_exact_two_sided"
            ]
            for arm in ARMS
        ]
        adjusted = holm_adjust([float(value) for value in p_values])
        for arm, adjusted_p in zip(ARMS, adjusted):
            arm_results[arm["arm_id"]]["strategies"][strategy]["mcnemar_vs_pre"][
                "p_value_holm"
            ] = adjusted_p
        p_values = [
            arm_results[arm["arm_id"]]["strategies"][strategy]["retraction"][
                "hypergeom_p_fp_enrichment"
            ]
            for arm in ARMS
        ]
        adjusted = holm_adjust([float(value) for value in p_values])
        for arm, adjusted_p in zip(ARMS, adjusted):
            arm_results[arm["arm_id"]]["strategies"][strategy]["retraction"][
                "hypergeom_p_holm"
            ] = adjusted_p

    return {
        "artifact": "verifier_conservative_analysis",
        "analysis_status": ANALYSIS_STATUS,
        "analysis_status_meaning": ANALYSIS_STATUS_MEANING,
        "prompt_version": PROMPT_VERSION,
        "template_sha256": template_sha256(),
        "dataset": {
            "path": str(dataset_path),
            "sha256": dataset.sha256,
            "n": len(samples),
            "label_counts": {
                "vulnerable": sum(labels),
                "non_vulnerable": len(labels) - sum(labels),
            },
        },
        "first_pass": first_pass,
        "arms": arm_results,
        "settings": {
            "decision_rule": (
                "retract only when assessment=unsupported with a grounded guard_present "
                "or a grounded counterexample; insufficient, schema-invalid, and API-error "
                "records keep the first-pass prediction"
            ),
            "line_validity": (
                "in range, unique, at least one non-blank non-comment non-brace cited line; "
                "guard_present additionally needs a guard-like token on a cited code line"
            ),
            "fail_closed": False,
            "primary_arms": ["deepseek_cross", "mimo_cross"],
            "holm_scope": "four arms within each strategy",
            "bootstrap": {
                "unit": "project cluster",
                "resamples": 10_000,
                "seed": 42,
                "confidence": 0.95,
            },
            "random_baseline": {
                "draws": 10_000,
                "seed": 42,
                "k": "matched to each strategy's retraction count",
            },
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    from .report import render_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-file", default=str(DEFAULT_DATASET))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args(list(argv) if argv is not None else None)

    result = build_metrics(Path(args.dataset_file))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    from secvul_runner.util import atomic_write_json, atomic_write_text

    atomic_write_json(out / "metrics.json", result)

    comparison_arms: dict[str, Any] = {}
    for arm in ARMS:
        arm_result = result["arms"][arm["arm_id"]]
        comparison_arms[arm["arm_id"]] = {
            "claim_model": arm_result["claim_model"],
            "verifier_model": arm_result["verifier_model"],
            "kind": arm_result["kind"],
            "strategies": {
                name: {
                    "scores": block["scores"],
                    "delta_vs_pre": block["delta_vs_pre"],
                    "mcnemar_vs_pre": block["mcnemar_vs_pre"],
                    "retraction": dict(block["retraction"]),
                    "matched_budget": block["matched_budget"],
                    "cost": block.get("cost"),
                    "bootstrap_delta": block.get("bootstrap_delta"),
                }
                for name, block in arm_result["strategies"].items()
            },
            "agreement_original_vs_conservative": arm_result[
                "agreement_original_vs_conservative"
            ],
            "conservative_failures": arm_result["conservative_failures"],
            "original_failures": arm_result["original_failures"],
            "conservative_taxonomy": arm_result["conservative_taxonomy"],
            "original_taxonomy": arm_result["original_taxonomy"],
            "retraction_cases": arm_result["retraction_cases"],
            "cost": arm_result["cost"],
            "audit": arm_result["audit"],
        }
    comparison = {
        "analysis_status": ANALYSIS_STATUS,
        "analysis_status_meaning": ANALYSIS_STATUS_MEANING,
        "template_sha256": result["template_sha256"],
        "prompt_version": result["prompt_version"],
        "arms": comparison_arms,
    }
    atomic_write_json(out / "comparison.json", comparison)

    rows: list[dict[str, Any]] = []
    for arm in ARMS:
        arm_result = result["arms"][arm["arm_id"]]
        conservative_dir = CONSERVATIVE_ROOT / arm["conservative_dir"]
        records = read_jsonl(conservative_dir / "results.jsonl")
        by_idx = {record["idx"]: record for record in records}
        pre = first_pass_predictions_by_model_for_report(result, arm["claim_model"])
        _, samples = load_split(Path(args.dataset_file))
        for sample, prediction in zip(samples, pre):
            if prediction is not True:
                continue
            record = by_idx.get(sample.idx, {})
            parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
            validation = (
                record.get("validation")
                if isinstance(record.get("validation"), dict)
                else {}
            )
            lines = parsed.get("rebuttal_lines") or []
            line_texts = split_source(sample.func_body)
            rows.append(
                {
                    "arm": arm["arm_id"],
                    "claim_model": arm["claim_model"],
                    "verifier_model": arm["verifier_model"],
                    "idx": sample.idx,
                    "project": sample.project,
                    "label": sample.label,
                    "first_pass_confidence": (
                        first_pass_parsed_by_model_for_report(
                            result, arm["claim_model"]
                        ).get(sample.idx, {}).get("confidence")
                    ),
                    "status": record.get("status"),
                    "assessment": parsed.get("assessment"),
                    "rebuttal_kind": parsed.get("rebuttal_kind"),
                    "rebuttal_lines": lines,
                    "cited_texts": [
                        line_texts[line - 1]
                        for line in lines
                        if isinstance(line, int) and 1 <= line <= len(line_texts)
                    ],
                    "counterexample": parsed.get("counterexample"),
                    "reason": parsed.get("reason"),
                    "confidence": parsed.get("confidence"),
                    "decision": record.get("decision"),
                    "audit": validation,
                    "error": validation.get("error"),
                }
            )
    atomic_write_text(
        out / "decisions.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )
    atomic_write_text(out / "report.md", render_report(result))
    print(
        json.dumps(
            {
                "analysis_dir": str(out),
                "arms": {
                    arm["arm_id"]: {
                        "conservative_retracted": result["arms"][arm["arm_id"]][
                            "strategies"
                        ]["conservative"]["retraction"]["retracted"],
                        "conservative_tp_retracted": result["arms"][arm["arm_id"]][
                            "strategies"
                        ]["conservative"]["retraction"]["tp_retracted"],
                        "conservative_fp_retracted": result["arms"][arm["arm_id"]][
                            "strategies"
                        ]["conservative"]["retraction"]["fp_retracted"],
                        "macro_f1_pre": result["arms"][arm["arm_id"]]["strategies"]["pre"][
                            "scores"
                        ]["macro_f1"],
                        "macro_f1_conservative": result["arms"][arm["arm_id"]][
                            "strategies"
                        ]["conservative"]["scores"]["macro_f1"],
                        "mcc_pre": result["arms"][arm["arm_id"]]["strategies"]["pre"][
                            "scores"
                        ]["mcc"],
                        "mcc_conservative": result["arms"][arm["arm_id"]]["strategies"][
                            "conservative"
                        ]["scores"]["mcc"],
                    }
                    for arm in ARMS
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


# The decision dump re-reads first-pass predictions without carrying the large
# metrics object around; these helpers keep that lookup explicit.
def first_pass_predictions_by_model_for_report(
    result: dict[str, Any], model: str
) -> list[bool | None]:
    dataset = load_dataset(Path(result["dataset"]["path"]), "independent")
    samples = [sample for sample in dataset.units if isinstance(sample, FunctionSample)]
    run_dir = FIRST_PASS_RUNS[model]
    records = read_jsonl(run_dir / "results.jsonl")
    by_idx = {record["idx"]: record for record in records}
    predictions: list[bool | None] = []
    for sample in samples:
        record = by_idx[sample.idx]
        parsed = record.get("parsed")
        if record.get("status") != "ok" or not isinstance(parsed, dict):
            predictions.append(None)
            continue
        value = parsed.get("is_vulnerable")
        predictions.append(value if isinstance(value, bool) else None)
    return predictions


def first_pass_parsed_by_model_for_report(
    result: dict[str, Any], model: str
) -> dict[int, dict[str, Any]]:
    run_dir = FIRST_PASS_RUNS[model]
    records = read_jsonl(run_dir / "results.jsonl")
    parsed: dict[int, dict[str, Any]] = {}
    for record in records:
        value = record.get("parsed")
        if record.get("status") == "ok" and isinstance(value, dict):
            parsed[int(record["idx"])] = value
    return parsed


if __name__ == "__main__":
    sys.exit(main())
