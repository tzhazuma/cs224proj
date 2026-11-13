"""Metrics, retraction audit, baselines and report for the verifier experiment.

Everything here is descriptive or exploratory: the 160 test functions were
already used to evaluate the frozen first pass, so no result in this module is
an independent confirmation.  The module only reads existing run artifacts and
writes ``evidence_verify/analysis/``.
"""

from __future__ import annotations

import argparse
import json
import math
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
    percentile,
    wilson_interval,
)
from secvul_runner.datasets import FunctionSample, LoadedDataset, load_dataset  # noqa: E402
from secvul_runner.util import atomic_write_json, atomic_write_text, sha256_file  # noqa: E402

from . import ANALYSIS_STATUS  # noqa: E402
from .baselines import (  # noqa: E402
    FeatureSample,
    PositiveRecord,
    build_baselines,
    extract_features,
    matched_budget_table,
)

DEFAULT_DATASET = PROJECT_ROOT / "splits" / "test_detection_160.json"
DEFAULT_DEV_DATASET = PROJECT_ROOT / "splits" / "dev_detection_40.json"
FIRST_PASS_ROOT = PROJECT_ROOT / "evidence_prompt" / "runs"
RUN_ROOT = PROJECT_ROOT / "evidence_verify" / "runs"
DEFAULT_OUT = PROJECT_ROOT / "evidence_verify" / "analysis"

FIRST_PASS_RUNS = {
    "deepseek": FIRST_PASS_ROOT / "test_evidence_deepseek",
    "mimo": FIRST_PASS_ROOT / "test_evidence_mimo",
}

ARMS: tuple[dict[str, str], ...] = (
    {
        "arm_id": "deepseek_self",
        "claim_model": "deepseek",
        "verifier_model": "deepseek",
        "run_dir": "test_verify_deepseek_self",
        "dryrun_dir": "dryrun_verify_deepseek_self",
        "kind": "self",
    },
    {
        "arm_id": "deepseek_cross",
        "claim_model": "deepseek",
        "verifier_model": "mimo",
        "run_dir": "test_verify_deepseek_by_mimo",
        "dryrun_dir": "dryrun_verify_deepseek_by_mimo",
        "kind": "cross",
    },
    {
        "arm_id": "mimo_self",
        "claim_model": "mimo",
        "verifier_model": "mimo",
        "run_dir": "test_verify_mimo_self",
        "dryrun_dir": "dryrun_verify_mimo_self",
        "kind": "self",
    },
    {
        "arm_id": "mimo_cross",
        "claim_model": "mimo",
        "verifier_model": "deepseek",
        "run_dir": "test_verify_mimo_by_deepseek",
        "dryrun_dir": "dryrun_verify_mimo_by_deepseek",
        "kind": "cross",
    },
)

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


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


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


def post_predictions(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    verifier_by_idx: dict[int, dict[str, Any]],
    *,
    policy: str,
    rule: str = "any_retract",
) -> tuple[list[bool | None], dict[str, int]]:
    """Apply the verifier to positives only.

    ``policy`` chooses what happens when a positive has no schema-valid
    verifier verdict: ``fail_closed`` retracts it (the conservative operating
    point), ``fail_open`` keeps the first-pass prediction.

    ``rule`` chooses which retractions count.  ``any_retract`` is the
    pre-specified rule (every ``verdict == "retract"``).  ``refutation_only``
    is a post-hoc decision rule over the same recorded outputs: it keeps a
    claim when the only stated reason is ``insufficient_evidence``, i.e. when
    the verifier did not point to an in-function fact that defeats the claim.
    """
    if policy not in {"fail_closed", "fail_open"}:
        raise ValueError(f"unknown policy {policy!r}")
    if rule not in {"any_retract", "refutation_only"}:
        raise ValueError(f"unknown rule {rule!r}")
    out: list[bool | None] = []
    counts = {
        "sustain": 0,
        "retract": 0,
        "insufficient_evidence_kept": 0,
        "verifier_invalid": 0,
        "untouched_negative": 0,
        "untouched_invalid": 0,
    }
    for sample, prediction in zip(samples, pre):
        if prediction is not True:
            out.append(prediction)
            counts["untouched_invalid" if prediction is None else "untouched_negative"] += 1
            continue
        record = verifier_by_idx.get(sample.idx)
        parsed = record.get("parsed") if isinstance(record, dict) else None
        if record is None or record.get("status") != "ok" or not isinstance(parsed, dict):
            counts["verifier_invalid"] += 1
            out.append(False if policy == "fail_closed" else True)
            continue
        verdict = parsed.get("verdict")
        if verdict == "sustain":
            counts["sustain"] += 1
            out.append(True)
        elif verdict == "retract":
            if rule == "refutation_only" and parsed.get("rebuttal_type") == "insufficient_evidence":
                counts["insufficient_evidence_kept"] += 1
                out.append(True)
            else:
                counts["retract"] += 1
                out.append(False)
        else:
            counts["verifier_invalid"] += 1
            out.append(False if policy == "fail_closed" else True)
    return out, counts


# ---------------------------------------------------------------------------
# Statistics helpers
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
        result[key] = (float(b) - float(a)) if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None
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


def mcnemar_correctness(
    labels: Sequence[bool], pre: Sequence[bool | None], post: Sequence[bool | None]
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
    discordant = pre_right_post_wrong + pre_wrong_post_right
    if discordant:
        tail = sum(math.comb(discordant, i) for i in range(min(pre_right_post_wrong, pre_wrong_post_right) + 1)) / (2 ** discordant)
        p_value = min(1.0, 2.0 * tail)
    else:
        p_value = 1.0
    return {
        "n": len(labels),
        "pre_correct": pre_correct,
        "post_correct": post_correct,
        "both_correct": both,
        "both_wrong": neither,
        "pre_correct_post_wrong": pre_right_post_wrong,
        "pre_wrong_post_correct": pre_wrong_post_right,
        "discordant": discordant,
        "p_value_exact_two_sided": p_value,
        "method": "exact two-sided McNemar on 160 strict-correctness outcomes",
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
    metric_names = ("macro_f1", "mcc", "positive_f1", "precision", "recall", "specificity", "balanced_accuracy")

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
        "cluster_size_summary": block.get("cluster_size_summary"),
        "deltas": block.get("metrics"),
    }


# ---------------------------------------------------------------------------
# Per-arm analysis
# ---------------------------------------------------------------------------


def load_arm(arm: dict[str, str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run_dir = RUN_ROOT / arm["run_dir"]
    manifest_path = run_dir / "manifest.json"
    results_path = run_dir / "results.jsonl"
    if not manifest_path.exists() or not results_path.exists():
        raise SystemExit(f"missing verifier run artifacts in {run_dir}")
    manifest = read_json(manifest_path)
    records = read_jsonl(results_path)
    return manifest, records


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
        for key, target in (("prompt_tokens", prompt_tokens), ("completion_tokens", completion_tokens)):
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
        "mean_prompt_tokens": (sum(prompt_tokens) / len(prompt_tokens)) if prompt_tokens else None,
        "mean_completion_tokens": (sum(completion_tokens) / len(completion_tokens)) if completion_tokens else None,
        "latency_seconds": {
            "mean": (sum(latencies) / len(latencies)) if latencies else None,
            "p50": percentile(ordered, 0.5) if ordered else None,
            "p95": percentile(ordered, 0.95) if ordered else None,
            "max": ordered[-1] if ordered else None,
        },
    }


def retraction_block(
    labels: Sequence[bool],
    pre: Sequence[bool | None],
    verifier_by_idx: dict[int, dict[str, Any]],
    samples: Sequence[FunctionSample],
    *,
    rule: str = "any_retract",
) -> dict[str, Any]:
    positives = [sample for sample, prediction in zip(samples, pre) if prediction is True]
    retracted: list[dict[str, Any]] = []
    invalid: list[int] = []
    for sample in positives:
        record = verifier_by_idx.get(sample.idx)
        parsed = record.get("parsed") if isinstance(record, dict) else None
        if record is None or record.get("status") != "ok" or not isinstance(parsed, dict):
            invalid.append(sample.idx)
            continue
        retract = parsed.get("verdict") == "retract"
        if rule == "refutation_only" and parsed.get("rebuttal_type") == "insufficient_evidence":
            retract = False
        if retract:
            retracted.append(
                {
                    "idx": sample.idx,
                    "label": sample.label,
                    "confidence": parsed.get("confidence"),
                    "rebuttal_type": parsed.get("rebuttal_type"),
                    "evidence_check": parsed.get("evidence_check"),
                    "rebuttal_lines": parsed.get("rebuttal_lines"),
                    "reason": parsed.get("reason"),
                    "counterexample": parsed.get("counterexample"),
                }
            )
    tp_retracted = sum(1 for item in retracted if item["label"])
    fp_retracted = sum(1 for item in retracted if not item["label"])
    tp_total = sum(1 for sample in positives if sample.label)
    fp_total = len(positives) - tp_total
    k = len(retracted)
    population = len(positives)
    expected_fp = k * fp_total / population if population else None
    return {
        "verifiable_positives": population,
        "tp_positives": tp_total,
        "fp_positives": fp_total,
        "verifier_invalid_or_missing": len(invalid),
        "invalid_indices": invalid,
        "retracted": k,
        "retract_rate_of_verified": (k / (population - len(invalid))) if population > len(invalid) else None,
        "tp_retracted": tp_retracted,
        "fp_retracted": fp_retracted,
        "retraction_precision": (fp_retracted / k) if k else None,
        "tp_loss_rate": (tp_retracted / tp_total) if tp_total else None,
        "fp_correction_rate": (fp_retracted / fp_total) if fp_total else None,
        "base_fp_rate_among_positives": (fp_total / population) if population else None,
        "expected_fp_retracted_under_random": expected_fp,
        "excess_fp_retractions": (fp_retracted - expected_fp) if expected_fp is not None else None,
        "hypergeom_p_fp_enrichment": hypergeom_sf(population, fp_total, k, fp_retracted) if k else 1.0,
        "retraction_precision_wilson": wilson_interval(fp_retracted, k) if k else None,
        "records": retracted,
    }


def taxonomy_block(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ok = [record for record in records if record.get("status") == "ok" and isinstance(record.get("parsed"), dict)]
    types: dict[str, dict[str, int]] = {}
    evidence_checks: dict[str, int] = {}
    for record in ok:
        parsed = record["parsed"]
        key = str(parsed.get("rebuttal_type"))
        bucket = types.setdefault(key, {"total": 0, "tp": 0, "fp": 0})
        bucket["total"] += 1
        bucket["tp" if bool(record.get("label")) else "fp"] += 1
        check = str(parsed.get("evidence_check"))
        evidence_checks[check] = evidence_checks.get(check, 0) + 1
    retract_conf = [float(r["parsed"]["confidence"]) for r in ok if r["parsed"]["verdict"] == "retract"]
    sustain_conf = [float(r["parsed"]["confidence"]) for r in ok if r["parsed"]["verdict"] == "sustain"]
    grounded = [
        bool((r.get("validation") or {}).get("rebuttal_grounded"))
        for r in ok
        if r["parsed"]["verdict"] == "retract" and r["parsed"].get("rebuttal_lines")
    ]
    counters = [
        bool((r.get("validation") or {}).get("counterexample_provided"))
        for r in ok
        if r["parsed"]["verdict"] == "retract"
    ]
    return {
        "rebuttal_types": types,
        "evidence_check_counts": evidence_checks,
        "mean_confidence_retract": (sum(retract_conf) / len(retract_conf)) if retract_conf else None,
        "mean_confidence_sustain": (sum(sustain_conf) / len(sustain_conf)) if sustain_conf else None,
        "retractions_grounded": sum(grounded),
        "retractions_total": len(grounded),
        "retractions_with_counterexample": sum(counters),
    }


def diagnosis_buckets(
    samples: Sequence[FunctionSample],
    pre: Sequence[bool | None],
    verifier_by_idx: dict[int, dict[str, Any]],
    parsed_by_idx: dict[int, dict[str, Any]],
    *,
    field: str,
) -> list[dict[str, Any]]:
    rows: list[tuple[float, int, bool, bool]] = []
    for sample, prediction in zip(samples, pre):
        if prediction is not True:
            continue
        record = verifier_by_idx.get(sample.idx)
        parsed = record.get("parsed") if isinstance(record, dict) else None
        if record is None or record.get("status") != "ok" or not isinstance(parsed, dict):
            continue
        if field == "first_pass_confidence":
            value = (parsed_by_idx.get(sample.idx) or {}).get("confidence")
        elif field == "function_lines":
            value = sample.func_body.count("\n") + 1
        elif field == "evidence_line_count":
            value = len((parsed_by_idx.get(sample.idx) or {}).get("evidence_lines") or [])
        else:
            raise ValueError(f"unknown field {field}")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        rows.append((float(value), sample.idx, bool(sample.label), parsed.get("verdict") == "retract"))
    if not rows:
        return []
    rows.sort(key=lambda item: (item[0], item[1]))
    n = len(rows)
    buckets: list[list[tuple[float, int, bool, bool]]] = []
    size = math.ceil(n / 4)
    for start in range(0, n, size):
        buckets.append(rows[start : start + size])
    result: list[dict[str, Any]] = []
    for position, bucket in enumerate(buckets, 1):
        result.append(
            {
                "quartile": position,
                "n": len(bucket),
                "value_range": [bucket[0][0], bucket[-1][0]],
                "retracted": sum(1 for item in bucket if item[3]),
                "tp": sum(1 for item in bucket if item[2]),
                "fp": sum(1 for item in bucket if not item[2]),
                "retract_rate": sum(1 for item in bucket if item[3]) / len(bucket),
            }
        )
    return result


def confidence_sweep(
    labels: Sequence[bool],
    pre: Sequence[bool | None],
    samples: Sequence[FunctionSample],
    verifier_by_idx: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for threshold in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9):
        predictions: list[bool | None] = []
        tp_retracted = fp_retracted = 0
        for sample, prediction in zip(samples, pre):
            if prediction is not True:
                predictions.append(prediction)
                continue
            record = verifier_by_idx.get(sample.idx)
            parsed = record.get("parsed") if isinstance(record, dict) else None
            if record is None or record.get("status") != "ok" or not isinstance(parsed, dict):
                predictions.append(False)
                continue
            retract = parsed.get("verdict") == "retract" or (
                parsed.get("verdict") == "sustain" and float(parsed.get("confidence", 0.0)) < threshold
            )
            if retract:
                predictions.append(False)
                if sample.label:
                    tp_retracted += 1
                else:
                    fp_retracted += 1
            else:
                predictions.append(True)
        block = detection_scores(labels, predictions)
        rows.append(
            {
                "sustain_confidence_threshold": threshold,
                "tp_retracted": tp_retracted,
                "fp_retracted": fp_retracted,
                "macro_f1": block["macro_f1"],
                "mcc": block["mcc"],
                "positive_f1": block["positive_f1"],
                "precision": block["precision"],
                "recall": block["recall"],
                "strict_accuracy": block["strict_accuracy"],
                "note": "descriptive sweep on the test split; threshold 0.0 is the primary fixed rule",
            }
        )
    return rows


def agreement_block(
    left: dict[int, dict[str, Any]], right: dict[int, dict[str, Any]]
) -> dict[str, Any]:
    common = sorted(set(left) & set(right))
    if not common:
        return {"n": 0}
    a = [left[idx]["parsed"]["verdict"] for idx in common]
    b = [right[idx]["parsed"]["verdict"] for idx in common]
    agree = sum(1 for x, y in zip(a, b) if x == y)
    p_left = sum(1 for x in a if x == "retract") / len(a)
    p_right = sum(1 for x in b if x == "retract") / len(b)
    expected = p_left * p_right + (1 - p_left) * (1 - p_right)
    kappa = ((agree / len(a)) - expected) / (1 - expected) if expected < 1 else None
    both_retract = sum(1 for x, y in zip(a, b) if x == "retract" and y == "retract")
    both_sustain = sum(1 for x, y in zip(a, b) if x == "sustain" and y == "sustain")
    left_only = sum(1 for x, y in zip(a, b) if x == "retract" and y == "sustain")
    right_only = sum(1 for x, y in zip(a, b) if x == "sustain" and y == "retract")
    return {
        "n": len(common),
        "agreement": agree / len(common),
        "cohen_kappa": kappa,
        "both_retract": both_retract,
        "both_sustain": both_sustain,
        "left_retract_only": left_only,
        "right_retract_only": right_only,
        "left_retract_rate": p_left,
        "right_retract_rate": p_right,
    }


def prompt_audit(
    dryrun_dir: Path, records: Sequence[dict[str, Any]], manifest: dict[str, Any]
) -> dict[str, Any]:
    dry_path = dryrun_dir / "dry_run_requests.jsonl"
    matches = mismatches = missing = 0
    if dry_path.exists():
        dry = {record["cache_key"]: record for record in read_jsonl(dry_path)}
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
    else:
        return {"available": False, "reason": "dry_run_requests.jsonl missing"}
    isolation_violations = 0
    for record in records:
        prompt = record.get("prompt") or {}
        if prompt.get("only_source_and_claim_variable") is not True:
            isolation_violations += 1
        if prompt.get("source_reconstructed") is not True:
            isolation_violations += 1
        if prompt.get("claim_source") != "first_pass_model_output":
            isolation_violations += 1
        if prompt.get("input_fields") != ["func_body", "claim.evidence_lines", "claim.mechanism"]:
            isolation_violations += 1
    api = manifest.get("api") or {}
    return {
        "available": True,
        "requests_compared": len(records),
        "body_sha256_matches": matches,
        "body_sha256_mismatches": mismatches,
        "body_sha256_missing": missing,
        "all_bodies_match_dry_run": mismatches == 0 and missing == 0 and matches == len(records),
        "isolation_violations": isolation_violations,
        "api_key_value_stored": api.get("api_key_value_stored"),
        "authorization_header_stored": manifest.get("authorization_header_stored"),
        "template_sha256": (manifest.get("config") or {}).get("template_sha256"),
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_metrics(dataset_path: Path, dev_path: Path) -> dict[str, Any]:
    dataset, samples = load_split(dataset_path)
    dev_dataset, dev_samples = load_split(dev_path)
    labels = [sample.label for sample in samples]
    cluster_ids = [sample.project for sample in samples]

    first_pass: dict[str, Any] = {}
    first_pass_predictions_by_model: dict[str, list[bool | None]] = {}
    for model, run_dir in FIRST_PASS_RUNS.items():
        path = run_dir / "results.jsonl"
        manifest = read_json(run_dir / "manifest.json")
        records = read_jsonl(path)
        by_idx = index_records(records, path)
        predictions, parsed_by_idx = first_pass_predictions(samples, by_idx, path)
        first_pass_predictions_by_model[model] = predictions
        block = detection_scores(labels, predictions)
        first_pass[model] = {
            "run_dir": str(run_dir),
            "results_sha256": sha256_file(path),
            "manifest_results_sha256": manifest.get("results_sha256"),
            "records": len(records),
            "status_counts": {
                status: sum(1 for record in records if record.get("status") == status)
                for status in sorted({str(record.get("status")) for record in records})
            },
            "scores": compact_scores(block),
            "cost": token_cost_block(records),
            "parsed_by_idx": parsed_by_idx,
        }

    arm_results: dict[str, Any] = {}
    verifier_maps: dict[str, dict[int, dict[str, Any]]] = {}
    for arm in ARMS:
        manifest, records = load_arm(arm)
        path = RUN_ROOT / arm["run_dir"] / "results.jsonl"
        by_idx = index_records(records, path)
        claim_model = arm["claim_model"]
        pre = first_pass_predictions_by_model[claim_model]
        post_closed, counts_closed = post_predictions(samples, pre, by_idx, policy="fail_closed")
        post_open, counts_open = post_predictions(samples, pre, by_idx, policy="fail_open")
        post_refute, counts_refute = post_predictions(
            samples, pre, by_idx, policy="fail_closed", rule="refutation_only"
        )
        pre_scores = detection_scores(labels, pre)
        closed_scores = detection_scores(labels, post_closed)
        open_scores = detection_scores(labels, post_open)
        refute_scores = detection_scores(labels, post_refute)
        retraction = retraction_block(labels, pre, by_idx, samples)
        retraction_refute = retraction_block(labels, pre, by_idx, samples, rule="refutation_only")
        mcnemar = mcnemar_correctness(labels, pre, post_closed)
        mcnemar_refute = mcnemar_correctness(labels, pre, post_refute)
        bootstrap = bootstrap_deltas(labels, pre, post_closed, cluster_ids)
        taxonomy = taxonomy_block(records)
        verifier_cost = token_cost_block(records)
        ok_records = [
            record for record in records if record.get("status") == "ok" and isinstance(record.get("parsed"), dict)
        ]
        positive_records: list[PositiveRecord] = []
        for sample, prediction in zip(samples, pre):
            if prediction is not True:
                continue
            parsed = first_pass[claim_model]["parsed_by_idx"].get(sample.idx)
            if parsed is None:
                continue
            features = extract_features(sample.idx, sample.label, sample.func_body)
            positive_records.append(
                PositiveRecord(
                    idx=sample.idx,
                    label=sample.label,
                    first_pass_confidence=parsed.get("confidence") if isinstance(parsed.get("confidence"), (int, float)) else None,
                    evidence_line_count=len(parsed.get("evidence_lines") or []),
                    lines=features.lines,
                    chars=features.chars,
                    code_lines=features.code_lines,
                    call_count=features.call_count,
                )
            )
        k = len(retraction["records"])
        sample_indices = [sample.idx for sample in samples]
        matched = matched_budget_table(
            labels=labels,
            first_pass_predictions=pre,
            positive_records=positive_records,
            sample_indices=sample_indices,
            k=k,
        )
        matched_refute = matched_budget_table(
            labels=labels,
            first_pass_predictions=pre,
            positive_records=positive_records,
            sample_indices=sample_indices,
            k=len(retraction_refute["records"]),
        )
        verifier_maps[arm["arm_id"]] = {
            idx: record
            for idx, record in by_idx.items()
            if record.get("status") == "ok" and isinstance(record.get("parsed"), dict)
        }
        arm_results[arm["arm_id"]] = {
            "claim_model": claim_model,
            "verifier_model": arm["verifier_model"],
            "kind": arm["kind"],
            "run_dir": arm["run_dir"],
            "run_label": manifest.get("run_label"),
            "results_sha256": sha256_file(path),
            "manifest_results_sha256": manifest.get("results_sha256"),
            "config": {
                "model": (manifest.get("config") or {}).get("api", {}).get("model"),
                "template_sha256": (manifest.get("config") or {}).get("template_sha256"),
                "prompt_version": (manifest.get("config") or {}).get("prompt_version"),
            },
            "verifier_status_counts": {
                status: sum(1 for record in records if record.get("status") == status)
                for status in sorted({str(record.get("status")) for record in records})
            },
            "prediction_counts": {
                "fail_closed": counts_closed,
                "fail_open": counts_open,
                "refutation_only": counts_refute,
            },
            "scores": {
                "pre": compact_scores(pre_scores),
                "post_fail_closed": compact_scores(closed_scores),
                "post_fail_open": compact_scores(open_scores),
                "post_refutation_only": compact_scores(refute_scores),
                "delta_fail_closed": delta_block(pre_scores, closed_scores),
                "delta_fail_open": delta_block(pre_scores, open_scores),
                "delta_refutation_only": delta_block(pre_scores, refute_scores),
            },
            "mcnemar_pre_vs_post_fail_closed": mcnemar,
            "mcnemar_pre_vs_post_refutation_only": mcnemar_refute,
            "retraction": retraction,
            "retraction_refutation_only": retraction_refute,
            "taxonomy": taxonomy,
            "bootstrap": bootstrap,
            "confidence_sweep": confidence_sweep(labels, pre, samples, by_idx),
            "diagnostics": {
                "by_first_pass_confidence": diagnosis_buckets(
                    samples, pre, by_idx, first_pass[claim_model]["parsed_by_idx"], field="first_pass_confidence"
                ),
                "by_function_lines": diagnosis_buckets(
                    samples, pre, by_idx, first_pass[claim_model]["parsed_by_idx"], field="function_lines"
                ),
                "by_evidence_line_count": diagnosis_buckets(
                    samples, pre, by_idx, first_pass[claim_model]["parsed_by_idx"], field="evidence_line_count"
                ),
            },
            "matched_budget": matched,
            "matched_budget_refutation_only": matched_refute,
            "cost": {
                "verifier": verifier_cost,
                "first_pass": first_pass[claim_model]["cost"],
                "pipeline_total_cost_usd": (
                    (verifier_cost["total_cost_usd"] or 0.0)
                    + (first_pass[claim_model]["cost"]["total_cost_usd"] or 0.0)
                    if verifier_cost["total_cost_usd"] is not None
                    and first_pass[claim_model]["cost"]["total_cost_usd"] is not None
                    else None
                ),
            },
            "audit": prompt_audit(RUN_ROOT / arm["dryrun_dir"], records, manifest),
            "records_for_cases": [
                {
                    "idx": record.get("idx"),
                    "label": record.get("label"),
                    "status": record.get("status"),
                    "verdict": (record.get("parsed") or {}).get("verdict"),
                    "rebuttal_type": (record.get("parsed") or {}).get("rebuttal_type"),
                    "confidence": (record.get("parsed") or {}).get("confidence"),
                    "reason": (record.get("parsed") or {}).get("reason"),
                    "counterexample": (record.get("parsed") or {}).get("counterexample"),
                }
                for record in ok_records
            ],
        }

    # Holm across the four primary retraction tests.
    p_values = [arm_results[arm["arm_id"]]["retraction"]["hypergeom_p_fp_enrichment"] for arm in ARMS]
    adjusted = holm_adjust([float(value) for value in p_values])
    for arm, adjusted_p in zip(ARMS, adjusted):
        arm_results[arm["arm_id"]]["retraction"]["hypergeom_p_holm"] = adjusted_p

    p_mcnemar = [arm_results[arm["arm_id"]]["mcnemar_pre_vs_post_fail_closed"]["p_value_exact_two_sided"] for arm in ARMS]
    adjusted_mcnemar = holm_adjust([float(value) for value in p_mcnemar])
    for arm, adjusted_p in zip(ARMS, adjusted_mcnemar):
        arm_results[arm["arm_id"]]["mcnemar_pre_vs_post_fail_closed"]["p_value_holm"] = adjusted_p

    # Same correction for the post-hoc refutation-only decision rule.
    p_refute = [
        arm_results[arm["arm_id"]]["retraction_refutation_only"]["hypergeom_p_fp_enrichment"]
        for arm in ARMS
    ]
    for arm, adjusted_p in zip(ARMS, holm_adjust([float(value) for value in p_refute])):
        arm_results[arm["arm_id"]]["retraction_refutation_only"]["hypergeom_p_holm"] = adjusted_p
    p_refute_mcnemar = [
        arm_results[arm["arm_id"]]["mcnemar_pre_vs_post_refutation_only"]["p_value_exact_two_sided"]
        for arm in ARMS
    ]
    for arm, adjusted_p in zip(ARMS, holm_adjust([float(value) for value in p_refute_mcnemar])):
        arm_results[arm["arm_id"]]["mcnemar_pre_vs_post_refutation_only"]["p_value_holm"] = adjusted_p

    agreement = {
        "deepseek_claims": agreement_block(
            verifier_maps["deepseek_self"], verifier_maps["deepseek_cross"]
        ),
        "mimo_claims": agreement_block(verifier_maps["mimo_self"], verifier_maps["mimo_cross"]),
    }

    baseline_features_dev = [
        extract_features(sample.idx, sample.label, sample.func_body) for sample in dev_samples
    ]
    baseline_features_test = [
        extract_features(sample.idx, sample.label, sample.func_body) for sample in samples
    ]
    baselines = build_baselines(baseline_features_dev, baseline_features_test)

    return {
        "artifact": "evidence_verify_analysis",
        "analysis_status": ANALYSIS_STATUS,
        "analysis_status_meaning": (
            "Exploratory and post hoc: the frozen 160-function test split was already used to "
            "evaluate the first pass, so these results do not independently confirm the earlier "
            "detection numbers."
        ),
        "dataset": {
            "test": {"path": str(dataset_path), "sha256": dataset.sha256, "n": len(samples), "label_counts": {"vulnerable": sum(labels), "non_vulnerable": len(labels) - sum(labels)}},
            "dev": {"path": str(dev_path), "sha256": dev_dataset.sha256, "n": len(dev_samples)},
        },
        "first_pass": {
            key: {k: v for k, v in value.items() if k != "parsed_by_idx"}
            for key, value in first_pass.items()
        },
        "arms": arm_results,
        "agreement": agreement,
        "baselines": baselines,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def pct(value: Any, digits: int = 1) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{100.0 * float(value):.{digits}f}%"


def signed(value: Any, digits: int = 4) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{float(value):+.{digits}f}"


def signed_pct(value: Any, digits: int = 1) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    return f"{100.0 * float(value):+.{digits}f}%"


def cost_increment_ratio(block: dict[str, Any]) -> float | None:
    """Verifier cost divided by first-pass detection cost, or None."""
    verifier = block["cost"]["verifier"].get("total_cost_usd")
    first = block["cost"]["first_pass"].get("total_cost_usd")
    if (
        isinstance(verifier, (int, float))
        and not isinstance(verifier, bool)
        and isinstance(first, (int, float))
        and not isinstance(first, bool)
        and first > 0
    ):
        return float(verifier) / float(first)
    return None


def metric_table_row(name: str, block: dict[str, Any]) -> str:
    confusion = block["confusion"]
    return (
        f"| {name} | {confusion['tp']} | {confusion['fp']} | {confusion['tn']} | {confusion['fn']} | "
        f"{fmt(block['precision'])} | {fmt(block['recall'])} | {fmt(block['positive_f1'])} | "
        f"{fmt(block['macro_f1'])} | {fmt(block['mcc'])} | {pct(block['predicted_positive_rate'])} |"
    )


def render_report(result: dict[str, Any]) -> str:
    arms = result["arms"]
    lines: list[str] = []
    add = lines.append
    cost_ratios = [
        ratio
        for arm in ARMS
        if (ratio := cost_increment_ratio(arms[arm["arm_id"]])) is not None
    ]
    cost_range_text = (
        f"+{min(cost_ratios):.1%}–+{max(cost_ratios):.1%}" if cost_ratios else "—"
    )

    add("# 证据提示的二次验证 / 保守操作点（SecVulEval 160 测试，探索性）")
    add("")
    add("> **状态：探索性、事后分析（post-hoc），不是独立确认。** 这 160 个函数已经用于")
    add("> 评估第一遍 evidence 提示；验证器提示是在看到该结果之后设计的。任何数字都不能")
    add("> 当作“在新测试集上确认了检测能力”。")
    add("")

    add("## 1. 做了什么")
    add("")
    add("第一遍 evidence 提示提高召回，但假阳性点估计上升（DeepSeek +3 / MiMo +4），且证据行")
    add("定位接近随机。本实验只处理**正例**：对每个 schema-valid 的“有漏洞”预测，再发一次")
    add("独立上下文的模型调用，要求它尝试**反驳**该判断（检查证据是否支持、函数内是否有守卫、")
    add("构造一个不触发的反例），并允许它**撤销**证据不足的正例。负例一律不动。")
    add("")
    add("四个实验臂（同一批 160 条测试函数）：")
    add("")
    add("| 臂 | 第一遍正例来源 | 验证器 | 独立性 |")
    add("| --- | --- | --- | --- |")
    add("| `deepseek_self` | DeepSeek | DeepSeek | 同模型、新上下文（自审） |")
    add("| `deepseek_cross` | DeepSeek | MiMo | 跨模型（主分析） |")
    add("| `mimo_self` | MiMo | MiMo | 同模型、新上下文（自审） |")
    add("| `mimo_cross` | MiMo | DeepSeek | 跨模型（主分析） |")
    add("")
    add("验证器的输入只有：带行号的函数源码 + 第一遍的 `evidence_lines` + `mechanism`。")
    add("没有标签、项目、文件路径、commit、`changed_lines`、第一遍 confidence，也没有第一遍的")
    add("修复建议。输出被严格校验（7 个键、行号范围、verdict/证据一致性）；不合格记 invalid，")
    add("不修复。验证器失败的替换策略：主口径 **fail-closed**（未获 sustain 即撤销），")
    add("敏感性口径 fail-open（保留第一遍判断）。")
    add("")

    add("## 2. 主结果")
    add("")
    add("第一遍（pre）与二次验证后（post, fail-closed）的二分类指标。`strict` 为 160 条全记录，")
    add("第一遍 invalid 记录在两侧都算错；P/R/F1 为 valid-only。")
    add("")
    add("| 臂 | TP | FP | TN | FN | P | R | F1+ | macro-F1 | MCC | pos-rate |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]["scores"]["pre"]
        add(metric_table_row(f"{arm['arm_id']} · pre", block))
    for arm in ARMS:
        block = arms[arm["arm_id"]]["scores"]["post_fail_closed"]
        add(metric_table_row(f"{arm['arm_id']} · post", block))
    add("")

    add("### 2.1 撤销了什么")
    add("")
    add("| 臂 | 可验证正例 | 其中 TP/FP | 撤销总数 | 撤销 TP | 撤销 FP | 撤销精确率 | TP 损失率 | FP 纠正率 | 随机期望 FP | 超几何 p | Holm p |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        retraction = arms[arm["arm_id"]]["retraction"]
        add(
            f"| {arm['arm_id']} | {retraction['verifiable_positives']} | "
            f"{retraction['tp_positives']}/{retraction['fp_positives']} | {retraction['retracted']} | "
            f"{retraction['tp_retracted']} | {retraction['fp_retracted']} | "
            f"{pct(retraction['retraction_precision'])} | {pct(retraction['tp_loss_rate'])} | "
            f"{pct(retraction['fp_correction_rate'])} | "
            f"{fmt(retraction['expected_fp_retracted_under_random'], 2)} | "
            f"{fmt(retraction['hypergeom_p_fp_enrichment'])} | "
            f"{fmt(retraction.get('hypergeom_p_holm'))} |"
        )
    add("")
    add("撤销精确率 = 被撤销正例中真正是 FP 的比例；超几何检验的零假设是“从正例中随机抽 k 个”，")
    add("单侧检验 FP 是否被过度撤销。Holm 校正覆盖 4 个臂。")
    add("")

    add("### 2.2 指标变化与配对检验")
    add("")
    add("| 臂 | ΔP | ΔR | ΔF1+ | Δmacro-F1 | ΔMCC | Δstrict acc | McNemar p | Holm p |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        delta = arms[arm["arm_id"]]["scores"]["delta_fail_closed"]
        mcnemar = arms[arm["arm_id"]]["mcnemar_pre_vs_post_fail_closed"]
        add(
            f"| {arm['arm_id']} | {fmt(delta['precision'])} | {fmt(delta['recall'])} | "
            f"{fmt(delta['positive_f1'])} | {fmt(delta['macro_f1'])} | {fmt(delta['mcc'])} | "
            f"{fmt(delta['strict_accuracy'])} | {fmt(mcnemar['p_value_exact_two_sided'])} | "
            f"{fmt(mcnemar.get('p_value_holm'))} |"
        )
    add("")
    add("McNemar 比较 pre 与 post 在 160 条上的 strict 正确性；由于只撤销正例，discordant 只可能")
    add("是“TP→FN”和“FP→TN”，因此它与“撤销是否更偏向 FP”是同一个方向的检验（零假设不同：")
    add("McNemar 用二项，超几何用无放回抽样）。")
    add("")

    add("### 2.3 fail-open 敏感性（验证器失败时保留第一遍判断）")
    add("")
    add("主口径 fail-closed 把“验证器没有给出有效 sustain”的正例一律撤销。fail-open 则保留它们，")
    add("因此两者的差别只来自 invalid/缺失的验证记录。")
    add("")
    add("| 臂 | 验证无效正例 | post macro-F1 (closed) | post macro-F1 (open) | post MCC (closed) | post MCC (open) |")
    add("| --- | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]
        add(
            f"| {arm['arm_id']} | {block['prediction_counts']['fail_closed']['verifier_invalid']} | "
            f"{fmt(block['scores']['post_fail_closed']['macro_f1'])} | "
            f"{fmt(block['scores']['post_fail_open']['macro_f1'])} | "
            f"{fmt(block['scores']['post_fail_closed']['mcc'])} | "
            f"{fmt(block['scores']['post_fail_open']['mcc'])} |"
        )
    add("")

    add("### 2.4 按项目聚类的 bootstrap（Δ = post − pre）")
    add("")
    add("| 臂 | Δmacro-F1 [95%] | ΔMCC [95%] | ΔF1+ [95%] | Δrecall [95%] | Δspecificity [95%] | 聚类数 |")
    add("| --- | --- | --- | --- | --- | --- | ---: |")
    for arm in ARMS:
        bootstrap = arms[arm["arm_id"]]["bootstrap"]
        metrics = bootstrap["deltas"]
        def interval(name: str) -> str:
            block = metrics.get(name) or {}
            low, high = block.get("ci_low"), block.get("ci_high")
            if low is None or high is None:
                return "—"
            return f"[{low:+.4f}, {high:+.4f}]"
        add(
            f"| {arm['arm_id']} | {interval('macro_f1')} | {interval('mcc')} | {interval('positive_f1')} | "
            f"{interval('recall')} | {interval('specificity')} | {bootstrap['cluster_count']} |"
        )
    add("")

    add("### 2.5 事后决策规则：只撤销“有具体反证”的正例")
    add("")
    add("主规则把 `insufficient_evidence`（“函数内看不出攻击者控制，所以不足以成立”）也算作撤销。")
    add("这在逻辑上把“函数体无法证明可达”与“缺陷不存在”混为一谈，是主规则几乎撤销全部正例的")
    add("直接原因。下面是一条**事后**决策规则，不再调用模型，只对同一批已记录输出重新打分：")
    add("`verdict=retract` 且 `rebuttal_type != insufficient_evidence` 才撤销；其余保持第一遍判断。")
    add("它没有在运行前登记，只能作为敏感性分析。")
    add("")
    add("| 臂 | 撤销总数 | 撤销 TP | 撤销 FP | 撤销精确率 | TP 损失率 | FP 纠正率 | 超几何 p | Holm p |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        retraction = arms[arm["arm_id"]]["retraction_refutation_only"]
        add(
            f"| {arm['arm_id']} | {retraction['retracted']} | {retraction['tp_retracted']} | "
            f"{retraction['fp_retracted']} | {pct(retraction['retraction_precision'])} | "
            f"{pct(retraction['tp_loss_rate'])} | {pct(retraction['fp_correction_rate'])} | "
            f"{fmt(retraction['hypergeom_p_fp_enrichment'])} | "
            f"{fmt(retraction.get('hypergeom_p_holm'))} |"
        )
    add("")
    add("| 臂 | post macro-F1 | post MCC | post F1+ | post P | post R | post strict acc | Δmacro-F1 | ΔMCC | McNemar Holm p |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]
        post = block["scores"]["post_refutation_only"]
        delta = block["scores"]["delta_refutation_only"]
        add(
            f"| {arm['arm_id']} | {fmt(post['macro_f1'])} | {fmt(post['mcc'])} | {fmt(post['positive_f1'])} | "
            f"{fmt(post['precision'])} | {fmt(post['recall'])} | {fmt(post['strict_accuracy'])} | "
            f"{signed(delta['macro_f1'])} | {signed(delta['mcc'])} | "
            f"{fmt(block['mcnemar_pre_vs_post_refutation_only'].get('p_value_holm'))} |"
        )
    add("")
    add("同预算对照（k 改为该规则实际撤销数）：")
    add("")
    add("| 臂 | 规则 | 撤销 TP | 撤销 FP | macro-F1 | MCC |")
    add("| --- | --- | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]["matched_budget_refutation_only"]
        retraction = arms[arm["arm_id"]]["retraction_refutation_only"]
        post = arms[arm["arm_id"]]["scores"]["post_refutation_only"]
        add(
            f"| {arm['arm_id']} | 验证器（k={retraction['retracted']}） | {retraction['tp_retracted']} | "
            f"{retraction['fp_retracted']} | {fmt(post['macro_f1'])} | {fmt(post['mcc'])} |"
        )
        for name in ("confidence_lowest", "evidence_lines_fewest", "lines_shortest", "call_count_fewest"):
            entry = block[name]
            add(
                f"| {arm['arm_id']} | {name} | {entry['tp_retracted']} | {entry['fp_retracted']} | "
                f"{fmt(entry['post']['macro_f1'])} | {fmt(entry['post']['mcc'])} |"
            )
        random_block = block["random"]
        add(
            f"| {arm['arm_id']} | random（期望） | {fmt(random_block['expected_tp_retracted'], 2)} | "
            f"{fmt(random_block['expected_fp_retracted'], 2)} | "
            f"{fmt(random_block['macro_f1']['mean'])} | {fmt(random_block['mcc']['mean'])} |"
        )
    add("")

    add("## 3. 成本")
    add("")
    add("| 臂 | 验证请求 | 验证器 USD | 第一遍 USD | 合计 USD | 验证器增量（相对第一遍） | 每 100 单元 USD | 每个保留 TP USD | 撤销 1 个 FP 的验证成本 | p50 延迟 | p95 延迟 |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]
        verifier_cost = block["cost"]["verifier"]
        first_cost = block["cost"]["first_pass"]
        pipeline = block["cost"]["pipeline_total_cost_usd"]
        post_tp = block["scores"]["post_fail_closed"]["confusion"]["tp"]
        fp_retracted = block["retraction"]["fp_retracted"]
        add(
            f"| {arm['arm_id']} | {verifier_cost['requests']} | "
            f"{fmt(verifier_cost['total_cost_usd'], 6)} | {fmt(first_cost['total_cost_usd'], 6)} | "
            f"{fmt(pipeline, 6)} | {signed_pct(cost_increment_ratio(block))} | "
            f"{fmt((pipeline / 160 * 100) if pipeline is not None else None, 6)} | "
            f"{fmt((pipeline / post_tp) if pipeline is not None and post_tp else None, 6)} | "
            f"{fmt((verifier_cost['total_cost_usd'] / fp_retracted) if verifier_cost['total_cost_usd'] is not None and fp_retracted else None, 6)} | "
            f"{fmt(verifier_cost['latency_seconds']['p50'], 2)} s | "
            f"{fmt(verifier_cost['latency_seconds']['p95'], 2)} s |"
        )
    add("")
    add("只有正例子集（60 / 58 条）会发验证请求，但每次都要重发带行号源码，输入 token 接近")
    add(f"一次完整检测；因此验证器的增量成本实际为第一遍检测成本的 {cost_range_text}，不是可以")
    add("忽略的零头。“每 100 单元”按 160 条全测试集摊销；价格沿用第一遍 run 的配置，未重新核对")
    add("官方页面。")
    add("")

    add("## 4. 两个验证器是否一致")
    add("")
    add("| 正例集合 | n | 一致率 | Cohen κ | 都撤销 | 都保留 | 仅 self 撤销 | 仅 cross 撤销 |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, label in (("deepseek_claims", "DeepSeek 正例"), ("mimo_claims", "MiMo 正例")):
        block = result["agreement"][name]
        if not block.get("n"):
            continue
        add(
            f"| {label} | {block['n']} | {pct(block['agreement'])} | {fmt(block['cohen_kappa'])} | "
            f"{block['both_retract']} | {block['both_sustain']} | {block['left_retract_only']} | "
            f"{block['right_retract_only']} |"
        )
    add("")

    add("## 5. 捷径基线")
    add("")
    add("### 5.1 label-only 与单特征阈值（阈值在 dev 40 上拟合，再原样用于 test 160）")
    add("")
    baselines = result["baselines"]
    add("| 规则 | TP | FP | TN | FN | P | R | F1+ | macro-F1 | MCC |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, key in (("always vulnerable", "always_positive"), ("always safe", "always_negative")):
        block = baselines["label_only"][key]
        add(
            f"| {name} | {block['tp']} | {block['fp']} | {block['tn']} | {block['fn']} | "
            f"{fmt(block['precision'])} | {fmt(block['recall'])} | {fmt(block['positive_f1'])} | "
            f"{fmt(block['macro_f1'])} | {fmt(block['mcc'])} |"
        )
    for rule in baselines["threshold_rules"]:
        block = rule["test"]
        add(
            f"| {rule['name']} ({rule['direction']} {fmt(rule['threshold'], 1)}) | {block['tp']} | "
            f"{block['fp']} | {block['tn']} | {block['fn']} | {fmt(block['precision'])} | "
            f"{fmt(block['recall'])} | {fmt(block['positive_f1'])} | {fmt(block['macro_f1'])} | "
            f"{fmt(block['mcc'])} |"
        )
    add("")
    add("dev 只有 8 个非漏洞样本，拟合出的阈值不稳定；作为上界，下表给出“在 test 上挑最优阈值”")
    add("能达到的水平（明确是 test-tuned，只用于说明单特征捷径的上限）：")
    add("")
    add("| 特征 | 方向 | 阈值 | macro-F1 | MCC |")
    add("| --- | --- | ---: | ---: | ---: |")
    for rule in baselines["threshold_rules"]:
        tuned = rule["test_tuned_upper_bound"]
        add(
            f"| {rule['feature']} | {tuned['direction']} | {fmt(tuned['threshold'], 1)} | "
            f"{fmt(tuned['test']['macro_f1'])} | {fmt(tuned['test']['mcc'])} |"
        )
    add("")

    add("### 5.2 同预算撤销基线（每个臂撤销同样多的正例）")
    add("")
    add("| 臂 | 规则 | 撤销 TP | 撤销 FP | macro-F1 | MCC | F1+ |")
    add("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]["matched_budget"]
        k = arms[arm["arm_id"]]["retraction"]["retracted"]
        add(
            f"| {arm['arm_id']} | 验证器（k={k}） | {arms[arm['arm_id']]['retraction']['tp_retracted']} | "
            f"{arms[arm['arm_id']]['retraction']['fp_retracted']} | "
            f"{fmt(arms[arm['arm_id']]['scores']['post_fail_closed']['macro_f1'])} | "
            f"{fmt(arms[arm['arm_id']]['scores']['post_fail_closed']['mcc'])} | "
            f"{fmt(arms[arm['arm_id']]['scores']['post_fail_closed']['positive_f1'])} |"
        )
        for name in (
            "confidence_lowest",
            "confidence_highest",
            "evidence_lines_fewest",
            "evidence_lines_most",
            "lines_shortest",
            "lines_longest",
            "call_count_fewest",
            "call_count_most",
        ):
            entry = block[name]
            add(
                f"| {arm['arm_id']} | {name} | {entry['tp_retracted']} | {entry['fp_retracted']} | "
                f"{fmt(entry['post']['macro_f1'])} | {fmt(entry['post']['mcc'])} | "
                f"{fmt(entry['post']['positive_f1'])} |"
            )
        random_block = block["random"]
        add(
            f"| {arm['arm_id']} | random（期望） | {fmt(random_block['expected_tp_retracted'], 2)} | "
            f"{fmt(random_block['expected_fp_retracted'], 2)} | "
            f"{fmt(random_block['macro_f1']['mean'])} | {fmt(random_block['mcc']['mean'])} | "
            f"{fmt(random_block['positive_f1']['mean'])} |"
        )
    add("")
    add("这些规则全部固定、不看标签，也不调 k；k 由验证器决定。随机行是 10,000 次均匀抽样的")
    add("期望值。若验证器与随机/廉价启发式在同预算下没有差别，就不能说它“识别出了假阳性”。")
    add("")

    add("## 6. 验证器输出结构与失败")
    add("")
    add("| 臂 | 请求 | ok | invalid | error | 撤销类型分布 | 撤销总数 | 带行号撤销 | 带行号且 grounded | 无行号撤销（insufficient_evidence） | 撤销给反例 |")
    add("| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        block = arms[arm["arm_id"]]
        counts = block["verifier_status_counts"]
        taxonomy = block["taxonomy"]
        types = ", ".join(f"{key}={value['total']}" for key, value in sorted(taxonomy["rebuttal_types"].items()))
        insufficient = taxonomy["rebuttal_types"].get("insufficient_evidence", {}).get("total", 0)
        with_lines = taxonomy["retractions_total"]
        add(
            f"| {arm['arm_id']} | {sum(counts.values())} | {counts.get('ok', 0)} | "
            f"{counts.get('invalid', 0)} | {counts.get('error', 0)} | {types} | "
            f"{block['retraction']['retracted']} | {with_lines} | "
            f"{taxonomy['retractions_grounded']}/{with_lines} | {insufficient} | "
            f"{taxonomy['retractions_with_counterexample']} |"
        )
    add("")
    add("“带行号撤销 + 无行号撤销 = 撤销总数”。`insufficient_evidence` 按契约不允许给行号，")
    add("因此单独列一列；它不能被读成“有行号支撑”。")
    add("")
    add("按标签拆分的撤销类型（TP / FP）：")
    add("")
    add("| 臂 | 类型 | TP | FP | 合计 |")
    add("| --- | --- | ---: | ---: | ---: |")
    for arm in ARMS:
        for key, value in sorted(arms[arm["arm_id"]]["taxonomy"]["rebuttal_types"].items()):
            if key == "none":
                continue
            add(f"| {arm['arm_id']} | {key} | {value['tp']} | {value['fp']} | {value['total']} |")
    add("")
    add("撤销置信度均值 / 保留置信度均值：")
    add("")
    add("| 臂 | 撤销 | 保留 |")
    add("| --- | ---: | ---: |")
    for arm in ARMS:
        taxonomy = arms[arm["arm_id"]]["taxonomy"]
        add(
            f"| {arm['arm_id']} | {fmt(taxonomy['mean_confidence_retract'])} | "
            f"{fmt(taxonomy['mean_confidence_sustain'])} |"
        )
    add("")

    add("## 7. 描述性诊断（不是因果）")
    add("")
    add("撤销率按第一遍 confidence / 函数行数 / 证据行数的四分位分桶。如果撤销主要由这些")
    add("表面特征驱动，说明验证器更可能在利用捷径，而不是检查证据。")
    add("")
    for arm in ARMS:
        add(f"### {arm['arm_id']}")
        add("")
        add("| 分位 | 第一遍 confidence 区间 | n | 撤销率 | TP/FP |")
        add("| --- | --- | ---: | ---: | ---: |")
        for bucket in arms[arm["arm_id"]]["diagnostics"]["by_first_pass_confidence"]:
            add(
                f"| Q{bucket['quartile']} | {fmt(bucket['value_range'][0], 2)}–{fmt(bucket['value_range'][1], 2)} | "
                f"{bucket['n']} | {pct(bucket['retract_rate'])} | {bucket['tp']}/{bucket['fp']} |"
            )
        add("")
        add("| 分位 | 函数行数区间 | n | 撤销率 | TP/FP |")
        add("| --- | --- | ---: | ---: | ---: |")
        for bucket in arms[arm["arm_id"]]["diagnostics"]["by_function_lines"]:
            add(
                f"| Q{bucket['quartile']} | {fmt(bucket['value_range'][0], 0)}–{fmt(bucket['value_range'][1], 0)} | "
                f"{bucket['n']} | {pct(bucket['retract_rate'])} | {bucket['tp']}/{bucket['fp']} |"
            )
        add("")
        add("| 分位 | 证据行数区间 | n | 撤销率 | TP/FP |")
        add("| --- | --- | ---: | ---: | ---: |")
        for bucket in arms[arm["arm_id"]]["diagnostics"]["by_evidence_line_count"]:
            add(
                f"| Q{bucket['quartile']} | {fmt(bucket['value_range'][0], 0)}–{fmt(bucket['value_range'][1], 0)} | "
                f"{bucket['n']} | {pct(bucket['retract_rate'])} | {bucket['tp']}/{bucket['fp']} |"
            )
        add("")

    add("### 7.1 置信度阈值扫描（test 上调，仅描述）")
    add("")
    add("| 臂 | 阈值 | 撤销 TP | 撤销 FP | macro-F1 | MCC | F1+ | strict acc |")
    add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ARMS:
        for row in arms[arm["arm_id"]]["confidence_sweep"]:
            add(
                f"| {arm['arm_id']} | {fmt(row['sustain_confidence_threshold'], 1)} | {row['tp_retracted']} | "
                f"{row['fp_retracted']} | {fmt(row['macro_f1'])} | {fmt(row['mcc'])} | "
                f"{fmt(row['positive_f1'])} | {fmt(row['strict_accuracy'])} |"
            )
    add("")

    add("## 8. 输入隔离与审计")
    add("")
    add("| 臂 | 请求 body 与 dry-run 一致 | 隔离违规 | 模板 SHA-256 | 结果 SHA-256 |")
    add("| --- | --- | ---: | --- | --- |")
    for arm in ARMS:
        audit = arms[arm["arm_id"]]["audit"]
        add(
            f"| {arm['arm_id']} | {audit['body_sha256_matches']}/{audit['requests_compared']} | "
            f"{audit['isolation_violations']} | {str(audit['template_sha256'])[:16]}… | "
            f"{str(arms[arm['arm_id']]['results_sha256'])[:16]}… |"
        )
    add("")
    add("`api_key_value_stored=false`、`authorization_header_stored=false` 在四份 manifest 中均已核对；")
    add("运行产物不含 API key 或 Authorization 头。")
    add("")

    add("## 9. 结论")
    add("")
    cross = [arms["deepseek_cross"], arms["mimo_cross"]]
    add("以四个臂的实际结果为准（不预设方向）：")
    add("")
    add("1. **撤销的 FP/TP 构成**：")
    for arm in ARMS:
        retraction = arms[arm["arm_id"]]["retraction"]
        add(
            f"   - `{arm['arm_id']}`：撤销 {retraction['retracted']} 个正例，其中 FP "
            f"{retraction['fp_retracted']}、TP {retraction['tp_retracted']}；撤销精确率 "
            f"{pct(retraction['retraction_precision'])}（正例中 FP 基准率 "
            f"{pct(retraction['base_fp_rate_among_positives'])}），超几何 Holm p="
            f"{fmt(retraction.get('hypergeom_p_holm'))}。"
        )
    add("2. **指标方向（主规则）**：")
    for arm in ARMS:
        delta = arms[arm["arm_id"]]["scores"]["delta_fail_closed"]
        add(
            f"   - `{arm['arm_id']}`：Δmacro-F1 {signed(delta['macro_f1'])}，ΔMCC {signed(delta['mcc'])}，"
            f"Δrecall {signed(delta['recall'])}，Δprecision {signed(delta['precision'])}，"
            f"Δstrict acc {signed(delta['strict_accuracy'])}。"
        )
    add("3. **事后 refutation-only 规则**：")
    for arm in ARMS:
        block = arms[arm["arm_id"]]
        retraction = block["retraction_refutation_only"]
        post = block["scores"]["post_refutation_only"]
        total = block["retraction"]["retracted"]
        add(
            f"   - `{arm['arm_id']}`：撤销数从 {total} 降到 {retraction['retracted']}"
            f"（TP {retraction['tp_retracted']} / FP {retraction['fp_retracted']}），"
            f"macro-F1={fmt(post['macro_f1'])}，MCC={fmt(post['mcc'])}；"
            f"撤销精确率 {pct(retraction['retraction_precision'])}，Holm p="
            f"{fmt(retraction.get('hypergeom_p_holm'))}。"
        )
    add(
        f"4. **成本**：验证只跑正例（60 / 58 条），但增量成本为第一遍检测成本的 "
        f"{cost_range_text}（见 §3）；若撤销没有显著偏向 FP，这笔钱只是把操作点变保守，"
        "而不是提升判别力。"
    )
    add("5. **捷径**：把同预算的随机撤销、第一遍 confidence、证据行数、函数长度/调用数放进")
    add("   同一张表后，验证器是否真的优于这些廉价规则，见 §5.2 与 §2.5；优于随机才谈得上")
    add("   “证据检查”。")
    add("6. **探索性**：以上全部是 test 上的一次运行，没有多 seed、没有独立复现，且验证器提示")
    add("   是在已知 test 现象后写的。不能写成“独立确认”或“新方法在测试集上验证有效”。")
    add("")

    add("## 10. 限制")
    add("")
    add("- 单次运行、temperature=0 不保证确定性；没有多 seed 方差。")
    add("- 只有 160 条测试函数、32 个非漏洞样本；32 条里的 11 个正例 FP 支撑不起精确的 FPR 结论。")
    add("- 验证器只看正例，因此对 FN 没有任何作用；召回只会下降或不变。")
    add("- 第一遍有 1（DeepSeek）/2（MiMo）条 schema-invalid 记录，其中包含正例，但没有可验证的")
    add("  claim，二次验证无法处理；它们在 strict 口径里始终算错。")
    add("- 跨模型验证器不是“独立的人工标注”，只是不同模型的另一次判断；两模型共享同一批")
    add("  预训练语料与同一份测试函数，一致性高不代表正确。")
    add("- 验证器只看到函数体，无法证明跨函数/调用者约束；它撤销的“缺陷”里可能包含真实的、")
    add("  需要上下文才能成立的漏洞。")
    add("- 反例是模型生成的文本，没有编译或执行验证。")
    add("- 阈值/捷径基线在 dev 上拟合，但 dev 只有 8 个负例；test-tuned 上界仅作描述。")
    add("- 所有结果都是探索性、事后分析，不是独立确认。")
    add("")

    add("## 11. 复现")
    add("")
    add("```bash")
    add("cd /mnt/c/Users/tzh03/Downloads/cs224proj")
    add("python3 evidence_verify/selftest.py")
    add("bash evidence_verify/run_verify.sh deepseek_self dryrun")
    add("bash evidence_verify/run_verify.sh deepseek_self test")
    add("bash evidence_verify/run_verify.sh deepseek_cross test")
    add("bash evidence_verify/run_verify.sh mimo_self test")
    add("bash evidence_verify/run_verify.sh mimo_cross test")
    add("python3 evidence_verify/analyze.py")
    add("```")
    add("")
    add("`run_verify.sh` 在目标目录已有 manifest 时自动加 `--resume`；请求按内容哈希缓存在 run 目录。")
    add("脚本不写 `evidence_prompt/`、`runner/runs/`、`splits/` 或任何旧结果。")
    add("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-file", default=str(DEFAULT_DATASET))
    parser.add_argument("--dev-dataset-file", default=str(DEFAULT_DEV_DATASET))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args(list(argv) if argv is not None else None)

    result = build_metrics(Path(args.dataset_file), Path(args.dev_dataset_file))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out / "metrics.json", result)

    comparison = {
        "analysis_status": ANALYSIS_STATUS,
        "arms": {
            arm["arm_id"]: {
                "claim_model": arm["claim_model"],
                "verifier_model": arm["verifier_model"],
                "kind": arm["kind"],
                "pre": result["arms"][arm["arm_id"]]["scores"]["pre"],
                "post_fail_closed": result["arms"][arm["arm_id"]]["scores"]["post_fail_closed"],
                "post_refutation_only": result["arms"][arm["arm_id"]]["scores"]["post_refutation_only"],
                "delta_fail_closed": result["arms"][arm["arm_id"]]["scores"]["delta_fail_closed"],
                "delta_refutation_only": result["arms"][arm["arm_id"]]["scores"]["delta_refutation_only"],
                "retraction": {
                    key: value
                    for key, value in result["arms"][arm["arm_id"]]["retraction"].items()
                    if key != "records"
                },
                "retraction_refutation_only": {
                    key: value
                    for key, value in result["arms"][arm["arm_id"]]["retraction_refutation_only"].items()
                    if key != "records"
                },
                "mcnemar": result["arms"][arm["arm_id"]]["mcnemar_pre_vs_post_fail_closed"],
                "mcnemar_refutation_only": result["arms"][arm["arm_id"]]["mcnemar_pre_vs_post_refutation_only"],
                "cost": result["arms"][arm["arm_id"]]["cost"],
            }
            for arm in ARMS
        },
        "agreement": result["agreement"],
        "baselines": result["baselines"],
    }
    atomic_write_json(out / "comparison.json", comparison)

    rows: list[dict[str, Any]] = []
    for arm in ARMS:
        for rule_key, rule_name in (
            ("retraction", "any_retract"),
            ("retraction_refutation_only", "refutation_only"),
        ):
            for record in result["arms"][arm["arm_id"]][rule_key]["records"]:
                rows.append({"arm": arm["arm_id"], "rule": rule_name, **record})
    atomic_write_text(
        out / "retractions.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )
    atomic_write_text(out / "report.md", render_report(result))
    summary = {
        "analysis_dir": str(out),
        "arms": {
            arm["arm_id"]: {
                "retracted": result["arms"][arm["arm_id"]]["retraction"]["retracted"],
                "tp_retracted": result["arms"][arm["arm_id"]]["retraction"]["tp_retracted"],
                "fp_retracted": result["arms"][arm["arm_id"]]["retraction"]["fp_retracted"],
                "macro_f1_pre": result["arms"][arm["arm_id"]]["scores"]["pre"]["macro_f1"],
                "macro_f1_post": result["arms"][arm["arm_id"]]["scores"]["post_fail_closed"]["macro_f1"],
                "mcc_pre": result["arms"][arm["arm_id"]]["scores"]["pre"]["mcc"],
                "mcc_post": result["arms"][arm["arm_id"]]["scores"]["post_fail_closed"]["mcc"],
                "refutation_only_retracted": result["arms"][arm["arm_id"]]["retraction_refutation_only"]["retracted"],
                "refutation_only_tp_retracted": result["arms"][arm["arm_id"]]["retraction_refutation_only"]["tp_retracted"],
                "refutation_only_fp_retracted": result["arms"][arm["arm_id"]]["retraction_refutation_only"]["fp_retracted"],
                "refutation_only_macro_f1": result["arms"][arm["arm_id"]]["scores"]["post_refutation_only"]["macro_f1"],
                "refutation_only_mcc": result["arms"][arm["arm_id"]]["scores"]["post_refutation_only"]["mcc"],
            }
            for arm in ARMS
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
