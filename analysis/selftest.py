#!/usr/bin/env python3
"""End-to-end self-test for the SecVulEval analysis pipeline.

The test builds temporary synthetic runner directories in the system temp
directory, runs ``analysis/analyze_runs.py`` on them, asserts known values,
and deletes everything in a ``finally`` block.  It never writes fixture
results into ``analysis/aggregation.json`` or ``analysis/aggregation.md``.

The fixtures are explicitly marked ``fixture: true`` and use a model id that
contains ``SYNTHETIC-FIXTURE``.  The analyzer refuses to include them unless
``--allow-fixture`` is passed, and the generated JSON/Markdown carry a fixture
banner.  These are pipeline checks, not model results.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import analyze_runs, stats  # noqa: E402

ANALYZE = ROOT / "analysis" / "analyze_runs.py"
DATASETS = ROOT / "datasets"
MODEL = "SYNTHETIC-FIXTURE-NOT-A-MODEL"
FIXTURE_LABEL = "SELFTEST FIXTURE - NOT EXPERIMENTAL RESULTS"
BOOTSTRAP = 500


class SelfTestFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SelfTestFailure(message)


def approx(actual: Any, expected: float, message: str, tolerance: float = 5e-9) -> None:
    if actual is None or not isinstance(actual, (int, float)):
        raise SelfTestFailure(f"{message}: expected {expected}, got {actual!r}")
    if abs(float(actual) - expected) > tolerance:
        raise SelfTestFailure(f"{message}: expected {expected}, got {actual}")


def _predict(label: bool, idx: str, mode: str) -> bool:
    if mode == "perfect":
        return label
    if mode == "all_positive":
        return True
    if mode == "flip7":
        try:
            number = int(idx)
        except ValueError:
            number = 0
        return (not label) if number % 7 == 0 else label
    raise SelfTestFailure(f"unknown predictor mode {mode!r}")


def _context_state(classifier: analyze_runs.ContextClassifier, raw: Any) -> str:
    return classifier.state(raw)


def _result_record(
    *,
    dataset_type: str,
    sample_id: str,
    unit_id: str,
    pair_id: str | None,
    side: str | None,
    idx: str,
    label: bool,
    strategy: str,
    context_state: str,
    prediction: bool | None,
    status: str,
) -> dict[str, Any]:
    parsed = (
        {
            "is_vulnerable": bool(prediction),
            "confidence": 0.9,
            "rationale": "synthetic fixture for pipeline testing",
        }
        if status == "ok"
        else None
    )
    return {
        "dataset_type": dataset_type,
        "sample_id": sample_id,
        "unit_id": unit_id,
        "pair_id": pair_id,
        "side": side,
        "idx": int(idx) if str(idx).isdigit() else idx,
        "label": label,
        "task": "detection",
        "strategy": strategy,
        "prompt": {
            "prompt_version": "selftest-fixture",
            "task": "detection",
            "strategy": strategy,
            "context": {
                "used": strategy == "context",
                "nonempty": context_state == "nonempty" if strategy == "context" else False,
            },
            "function": {"function_chars": 10, "function_lines": 1, "code_sha256": "0" * 64},
            "message_count": 2,
        },
        "request": {
            "endpoint": "fixture://no-network",
            "model": MODEL,
            "request_fingerprint": "fixture",
            "body_sha256": "0" * 64,
        },
        "response": {
            "model": MODEL,
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            "request_latency_seconds": 0.01,
            "wall_seconds": 0.01,
        },
        "status": status,
        "parsed": parsed,
        "validation": {"schema_valid": status == "ok"},
        "created_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
    }


def _confusion(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for record in records:
        prediction = record.get("parsed")
        if record.get("status") != "ok" or not isinstance(prediction, Mapping):
            continue
        predicted = prediction.get("is_vulnerable")
        label = bool(record.get("label"))
        if label and predicted:
            tp += 1
        elif label and not predicted:
            fn += 1
        elif not label and predicted:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _joint_categories(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    by_pair: dict[str, dict[str, Mapping[str, Any]]] = {}
    for record in records:
        pair_id = record.get("pair_id")
        side = record.get("side")
        if pair_id and side in {"vulnerable", "fixed"}:
            by_pair.setdefault(str(pair_id), {})[str(side)] = record
    categories = {
        "vulnerable_detected_fixed_clean": 0,
        "both_flagged": 0,
        "both_clean": 0,
        "vulnerable_missed_fixed_flagged": 0,
    }
    valid_pairs = 0
    for sides in by_pair.values():
        vulnerable = sides.get("vulnerable")
        fixed = sides.get("fixed")
        if vulnerable is None or fixed is None:
            continue
        if vulnerable.get("status") != "ok" or fixed.get("status") != "ok":
            continue
        vulnerable_pred = (vulnerable.get("parsed") or {}).get("is_vulnerable")
        fixed_pred = (fixed.get("parsed") or {}).get("is_vulnerable")
        if not isinstance(vulnerable_pred, bool) or not isinstance(fixed_pred, bool):
            continue
        valid_pairs += 1
        if vulnerable_pred and not fixed_pred:
            categories["vulnerable_detected_fixed_clean"] += 1
        elif vulnerable_pred and fixed_pred:
            categories["both_flagged"] += 1
        elif not vulnerable_pred and not fixed_pred:
            categories["both_clean"] += 1
        else:
            categories["vulnerable_missed_fixed_flagged"] += 1
    return {"categories": categories, "valid_pairs": valid_pairs, "pairs": len(by_pair)}


def _metrics_document(
    *,
    run_id: str,
    dataset_type: str,
    dataset_path: Path,
    dataset_sha256: str,
    strategy: str,
    records: Sequence[Mapping[str, Any]],
    selected_units: int,
    partial: bool = False,
    missing_requests: int = 0,
) -> dict[str, Any]:
    detection_records = [record for record in records if record.get("task") == "detection"]
    confusion = _confusion(detection_records)
    valid = sum(confusion.values())
    invalid = sum(1 for record in detection_records if record.get("status") == "invalid")
    errors = sum(1 for record in detection_records if record.get("status") == "error")
    statuses = Counter(str(record.get("status")) for record in detection_records)
    detection = {
        "requested": len(detection_records),
        "valid_predictions": valid,
        "schema_invalid": invalid,
        "api_errors": errors,
        "coverage": valid / len(detection_records) if detection_records else None,
        "confusion": confusion,
    }
    pair_joint = None
    if dataset_type == "pairs":
        joint = _joint_categories(detection_records)
        pair_joint = {
            "pairs_requested": joint["pairs"],
            "valid_pairs": joint["valid_pairs"],
            "invalid_pairs": joint["pairs"] - joint["valid_pairs"],
            "joint_categories": joint["categories"],
            "discrimination_accuracy_valid_pairs": (
                joint["categories"]["vulnerable_detected_fixed_clean"] / joint["valid_pairs"]
                if joint["valid_pairs"]
                else None
            ),
            "discrimination_accuracy_all_pairs": (
                joint["categories"]["vulnerable_detected_fixed_clean"] / joint["pairs"]
                if joint["pairs"]
                else None
            ),
        }
    counts = {
        "records": len(detection_records),
        "by_task": {"detection": len(detection_records)},
        "by_status": dict(statuses),
        "expected_requests": len(detection_records) + missing_requests,
        "missing_requests": missing_requests,
        "complete_planned_requests": missing_requests == 0,
    }
    return {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "run_label": FIXTURE_LABEL,
            "dataset_type": dataset_type,
            "dataset_path": str(dataset_path),
            "dataset_sha256": dataset_sha256,
            "dataset_units": selected_units,
            "selected_units": selected_units,
            "strategy": strategy,
            "task": "detection",
            "model": MODEL,
            "temperature": 0.0,
            "limit": 0 if not partial else 10,
            "partial": partial,
            "expected_requests": len(detection_records) + missing_requests,
            "fixture": True,
            "completed_at": "2026-01-01T00:00:00Z",
        },
        "counts": counts,
        "detection": detection,
        "pair_joint": pair_joint,
        "repair": None,
    }


def _write_run(
    root: Path,
    *,
    run_id: str,
    dataset_type: str,
    dataset_path: Path,
    dataset_sha256: str,
    strategy: str,
    records: Sequence[Mapping[str, Any]],
    selected_units: int,
    partial: bool = False,
    missing_requests: int = 0,
) -> Path:
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    metrics = _metrics_document(
        run_id=run_id,
        dataset_type=dataset_type,
        dataset_path=dataset_path,
        dataset_sha256=dataset_sha256,
        strategy=strategy,
        records=records,
        selected_units=selected_units,
        partial=partial,
        missing_requests=missing_requests,
    )
    (run_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "results.jsonl").write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {"status": "completed", "run_id": run_id, "fixture": True},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return run_dir


def _independent_fixtures(
    root: Path,
    classifier: analyze_runs.ContextClassifier,
    dataset_path: Path,
    dataset_sha256: str,
) -> None:
    samples = json.loads(dataset_path.read_text(encoding="utf-8"))["samples"]
    spec = {
        "direct": ("all_positive", False),
        "few-shot": ("flip7", True),
        "context": ("perfect", False),
    }
    for strategy, (mode, has_invalid) in spec.items():
        records: list[dict[str, Any]] = []
        for position, sample in enumerate(samples):
            idx = str(sample["idx"])
            label = bool(sample["is_vulnerable"])
            status = "ok"
            prediction = _predict(label, idx, mode)
            if has_invalid and position == 0:
                status = "invalid"
                prediction = None
            records.append(
                _result_record(
                    dataset_type="independent",
                    sample_id=f"idx:{idx}",
                    unit_id=idx,
                    pair_id=None,
                    side=None,
                    idx=idx,
                    label=label,
                    strategy=strategy,
                    context_state=_context_state(classifier, sample.get("context")),
                    prediction=prediction,
                    status=status,
                )
            )
        _write_run(
            root,
            run_id=f"independent_{strategy.replace('-', '_')}_detection",
            dataset_type="independent",
            dataset_path=dataset_path,
            dataset_sha256=dataset_sha256,
            strategy=strategy,
            records=records,
            selected_units=len(samples),
        )


def _pair_fixtures(
    root: Path,
    classifier: analyze_runs.ContextClassifier,
    dataset_path: Path,
    dataset_sha256: str,
) -> None:
    pairs = json.loads(dataset_path.read_text(encoding="utf-8"))["pairs"]
    spec = {
        "direct": ("all_positive", False),
        "few-shot": ("flip7", True),
        "context": ("perfect", False),
    }
    for strategy, (mode, has_invalid) in spec.items():
        records: list[dict[str, Any]] = []
        for position, pair in enumerate(pairs):
            pair_id = str(pair["pair_id"])
            for side in ("vulnerable", "fixed"):
                sample = pair[side]
                idx = str(sample["idx"])
                label = side == "vulnerable"
                status = "ok"
                prediction = _predict(label, idx, mode)
                if has_invalid and position == 0 and side == "fixed":
                    status = "invalid"
                    prediction = None
                records.append(
                    _result_record(
                        dataset_type="pairs",
                        sample_id=f"pair:{pair_id}:{side}",
                        unit_id=pair_id,
                        pair_id=pair_id,
                        side=side,
                        idx=idx,
                        label=label,
                        strategy=strategy,
                        context_state=_context_state(classifier, sample.get("context")),
                        prediction=prediction,
                        status=status,
                    )
                )
        _write_run(
            root,
            run_id=f"pairs_{strategy.replace('-', '_')}_detection",
            dataset_type="pairs",
            dataset_path=dataset_path,
            dataset_sha256=dataset_sha256,
            strategy=strategy,
            records=records,
            selected_units=len(pairs),
        )


def _run_cli(runs_root: Path, out_dir: Path, *extra: str) -> dict[str, Any]:
    out_json = out_dir / "aggregation.json"
    out_md = out_dir / "aggregation.md"
    command = [
        sys.executable,
        str(ANALYZE),
        "--runs-root",
        str(runs_root),
        "--dataset-root",
        str(DATASETS),
        "--out-json",
        str(out_json),
        "--out-md",
        str(out_md),
        "--bootstrap",
        str(BOOTSTRAP),
        "--seed",
        "42",
        "--debug",
        *extra,
    ]
    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        raise SelfTestFailure(
            f"analyzer exited {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(out_json.read_text(encoding="utf-8"))


def _check_stats() -> None:
    check(stats.DEFAULT_BOOTSTRAP_RESAMPLES == 10_000, "default bootstrap resamples")
    check(stats.DEFAULT_BOOTSTRAP_SEED == 42, "default bootstrap seed")
    approx(stats.DEFAULT_CONFIDENCE, 0.95, "default confidence")
    wilson = stats.wilson_interval(160, 200)
    approx(wilson["estimate"], 0.8, "Wilson estimate")
    approx(wilson["low"], 0.7391448134346212, "Wilson low")
    approx(wilson["high"], 0.8495479907390189, "Wilson high")

    labels = [True] * 160 + [False] * 40
    all_positive = stats.detection_scores(labels, [True] * 200)
    approx(all_positive["macro_f1"], 4.0 / 9.0, "all-positive macro-F1")
    approx(all_positive["balanced_accuracy"], 0.5, "all-positive balanced accuracy")
    approx(all_positive["mcc"], 0.0, "all-positive MCC")
    approx(all_positive["accuracy"], 0.8, "all-positive accuracy")

    perfect = stats.detection_scores(labels, labels)
    approx(perfect["macro_f1"], 1.0, "perfect macro-F1")
    approx(perfect["balanced_accuracy"], 1.0, "perfect balanced accuracy")
    approx(perfect["mcc"], 1.0, "perfect MCC")

    mcnemar = stats.mcnemar_exact(a_correct_b_wrong=10, a_wrong_b_correct=2, total=160)
    approx(mcnemar["p_value"], 0.03857421875, "McNemar exact p")
    approx(mcnemar["odds_ratio"], 5.0, "McNemar odds ratio")

    holm = stats.holm_adjust([0.01, 0.04, 0.03])
    for actual, expected in zip(holm, [0.03, 0.06, 0.06]):
        approx(actual, expected, "Holm adjusted p")

    pair = stats.pair_scores([True, True, False], [False, True, True])
    check(pair["joint_categories"]["vulnerable_detected_fixed_clean"] == 1, "pair correct category")
    check(pair["joint_categories"]["both_flagged"] == 1, "pair both flagged category")
    check(pair["joint_categories"]["vulnerable_missed_fixed_flagged"] == 1, "pair swapped category")
    approx(pair["joint_accuracy_valid_pairs"], 1.0 / 3.0, "pair joint accuracy")

    check(stats.percentile([0.0, 10.0], 0.25) == 2.5, "linear percentile interpolation")
    print("[ok] stats: Wilson, macro-F1, balanced accuracy, MCC, McNemar, Holm, percentile")


def _check_aggregation(aggregation: Mapping[str, Any], runs_root: Path) -> None:
    check(aggregation["status"] == "ok", "fixture aggregation status should be ok")
    check(aggregation["fixture_mode"] is True, "fixture_mode should be true")
    check(aggregation["experimental_results"] is False, "fixture must not be experimental results")
    check(len(aggregation["groups"]) == 2, "expected two groups (independent + pairs)")

    groups = {group["dataset_type"]: group for group in aggregation["groups"]}
    independent = groups["independent"]
    pairs = groups["pairs"]

    check(independent["strategies"] == ["direct", "few-shot", "context"], "independent strategy order")
    check(independent["cohort"]["n"] == 200, "independent cohort n")
    check(independent["cohort"]["complete_case_n"] == 199, "independent complete-case n")
    check(pairs["cohort"]["n"] == 200, "pairs cohort n")
    check(pairs["cohort"]["complete_case_n"] == 199, "pairs complete-case n")

    # Run-level metrics use all 200 units; the direct all-positive predictor
    # has the known majority-baseline confusion matrix.
    direct_run = independent["run_level"]["direct"]["unit_metrics"]
    approx(direct_run["macro_f1"], 4.0 / 9.0, "independent direct run macro-F1")
    approx(direct_run["balanced_accuracy"], 0.5, "independent direct run balanced accuracy")
    approx(direct_run["mcc"], 0.0, "independent direct run MCC")
    check(direct_run["confusion"] == {"tp": 160, "fp": 40, "tn": 0, "fn": 0}, "direct confusion")

    context_run = independent["run_level"]["context"]["unit_metrics"]
    approx(context_run["macro_f1"], 1.0, "context run macro-F1")
    approx(context_run["mcc"], 1.0, "context run MCC")

    # End-to-end direct metric is on all 200 cohort units and has no invalid
    # records; the few-shot run has exactly one invalid record.
    approx(
        independent["end_to_end"]["direct"]["strict_accuracy"],
        0.8,
        "independent direct strict accuracy",
    )
    approx(
        independent["end_to_end"]["few-shot"]["coverage"],
        0.995,
        "independent few-shot coverage",
    )
    check(
        independent["end_to_end"]["few-shot"]["invalid"] == 1,
        "independent few-shot invalid count",
    )
    few_shot = independent["valid_only"]["few-shot"]
    check(few_shot["valid"] == 199, "independent few-shot valid count")
    check(few_shot["positive_class_not_predicted"] is False, "few-shot predicts positives")

    # Complete-case direct metrics exclude the one invalid unit; compute the
    # expected confusion from the fixture rather than hard-coding it.
    samples = json.loads((DATASETS / "independent_200.json").read_text(encoding="utf-8"))["samples"]
    all_labels = [bool(sample["is_vulnerable"]) for sample in samples]
    all_indices = [str(sample["idx"]) for sample in samples]
    invalid_idx = all_indices[0]
    keep = [i for i, idx in enumerate(all_indices) if idx != invalid_idx]
    kept_labels = [all_labels[i] for i in keep]
    kept_indices = [all_indices[i] for i in keep]
    direct_expected = {
        "tp": sum(1 for label in kept_labels if label),
        "fp": sum(1 for label in kept_labels if not label),
        "tn": 0,
        "fn": 0,
    }
    check(
        independent["valid_only"]["direct"]["confusion"] == direct_expected,
        "complete-case direct confusion",
    )
    approx(
        independent["valid_only"]["direct"]["macro_f1"],
        (2.0 * direct_expected["tp"] / (2.0 * direct_expected["tp"] + direct_expected["fp"])) / 2.0,
        "complete-case direct macro-F1",
    )

    # Pair joint metrics.
    check(
        pairs["run_level"]["direct"]["joint"]["joint_accuracy_all_pairs"] == 0.0,
        "pairs direct joint all should be zero",
    )
    check(
        pairs["run_level"]["direct"]["joint"]["joint_categories"]["both_flagged"] == 200,
        "pairs direct both flagged",
    )
    check(
        pairs["run_level"]["context"]["joint"]["joint_accuracy_all_pairs"] == 1.0,
        "pairs context joint all should be one",
    )
    approx(
        pairs["end_to_end"]["few-shot"]["coverage"],
        0.995,
        "pairs few-shot coverage",
    )
    check(
        pairs["run_level"]["few-shot"]["joint"]["valid_pairs"] == 199,
        "pairs few-shot valid pairs",
    )

    # McNemar + Holm: direct vs context is unambiguous and should survive Holm.
    primary = independent["pairwise"]["primary"]["comparisons"]
    comparison = next(
        row for row in primary if {row["strategy_a"], row["strategy_b"]} == {"direct", "context"}
    )
    check(comparison["a_correct_b_wrong"] == 0, "independent direct-context discordant b")
    check(comparison["a_wrong_b_correct"] == 40, "independent direct-context discordant c")
    check(comparison["reject_holm_0_05"] is True, "independent direct-context Holm reject")
    check(comparison["p_holm"] < 0.05, "independent direct-context Holm p")

    pair_primary = pairs["pairwise"]["primary"]["comparisons"]
    pair_comparison = next(
        row for row in pair_primary if {row["strategy_a"], row["strategy_b"]} == {"direct", "context"}
    )
    check(pair_comparison["a_wrong_b_correct"] == 200, "pairs direct-context discordant c")
    check(pair_comparison["reject_holm_0_05"] is True, "pairs direct-context Holm reject")

    # Bootstrap settings and deterministic values.
    independent_boot = independent["bootstrap"]["valid_only"]
    check(independent_boot["enabled"] is True, "independent bootstrap enabled")
    check(independent_boot["settings"]["resamples"] == BOOTSTRAP, "independent bootstrap resamples")
    check(independent_boot["settings"]["seed"] == 42, "independent bootstrap seed")
    check(independent_boot["settings"]["cluster_unit"] == "project", "independent cluster unit")
    check(independent_boot["cluster_count"] == 80, "independent cluster count")
    context_macro = independent_boot["metrics"]["context"]["macro_f1"]
    check(context_macro["valid_resamples"] > 0, "context macro bootstrap valid resamples")
    check(context_macro["ci_low"] <= context_macro["ci_high"], "context macro CI ordering")
    approx(context_macro["ci_low"], 1.0, "context macro bootstrap lower bound")
    delta = independent_boot["deltas"]["direct_vs_context"]["macro_f1"]
    check(delta["point"] is not None and delta["point"] < 0, "direct-context macro delta point")
    check(delta["ci_low"] <= delta["ci_high"], "direct-context macro delta CI ordering")

    pairs_boot = pairs["bootstrap"]["valid_only"]
    check(pairs_boot["settings"]["cluster_unit"] == "pair", "pairs cluster unit")
    check(pairs_boot["cluster_count"] == 199, "pairs cluster count on complete-case cohort")
    check(
        pairs_boot["metrics"]["context"]["joint_accuracy_valid_pairs"]["ci_low"] == 1.0,
        "pairs context joint bootstrap lower bound",
    )

    # Context strata and M3 risk.
    context_strata = independent["context_strata"]["strategies"]["context"]
    check(context_strata["nonempty"]["n"] == 156, "independent context nonempty n")
    check(context_strata["empty"]["n"] == 44, "independent context empty n")
    check(
        context_strata["nonempty"]["label_counts"] == {"vulnerable": 156, "non_vulnerable": 0},
        "independent nonempty label counts",
    )
    check(
        context_strata["empty"]["label_counts"] == {"vulnerable": 4, "non_vulnerable": 40},
        "independent empty label counts",
    )
    check(context_strata["nonempty"]["metrics"]["macro_f1"] is None, "nonempty single-class macro undefined")
    approx(context_strata["nonempty"]["metrics"]["positive_f1"], 1.0, "nonempty positive F1")
    approx(context_strata["empty"]["metrics"]["macro_f1"], 1.0, "empty macro-F1 under perfect context")
    check(
        independent["context_strata"]["l3_metadata_check"]["mismatch_count"] == 0,
        "L3 context metadata check",
    )
    check(
        independent["m3_artifact_risk"]["risk_level"] == "high",
        "independent M3 risk should be high",
    )
    check(
        "nonempty_stratum_single_class" in independent["m3_artifact_risk"]["flags"],
        "M3 risk flag",
    )
    m3_empty = independent["context_strata"]["m3_vs_m1"]["by_stratum"]["empty"]
    approx(m3_empty["delta"]["strict_accuracy"], 40.0 / 44.0, "M3-M1 empty strict accuracy delta")
    m3_nonempty = independent["context_strata"]["m3_vs_m1"]["by_stratum"]["nonempty"]
    approx(m3_nonempty["delta"]["strict_accuracy"], 0.0, "M3-M1 nonempty strict accuracy delta")

    pair_strata = pairs["context_strata"]["strategies"]["context"]
    check(pair_strata["empty"]["n_pairs"] == 5, "pairs empty context n")
    check(pair_strata["nonempty"]["n_pairs"] == 195, "pairs nonempty context n")
    check(pairs["m3_artifact_risk"]["risk_level"] == "low", "pairs M3 risk should be low")
    check("small_stratum" in pairs["m3_artifact_risk"]["flags"], "pairs small stratum flag")

    # Dataset-level audit is present even for fixture runs.
    audits = {dataset["dataset_type"]: dataset for dataset in aggregation["datasets"]}
    check(audits["independent"]["context_audit"]["risk_level"] == "high", "independent data audit risk")
    check(audits["pairs"]["context_audit"]["risk_level"] == "low", "pairs data audit risk")

    # Run inventory should show all six fixture runs with passing cross-checks.
    check(len(aggregation["runs"]["included"]) == 6, "six fixture runs included")
    check(
        all(run["cross_check"]["ok"] for run in aggregation["runs"]["included"]),
        "all fixture cross-checks pass",
    )

    markdown = (runs_root.parent / "out" / "aggregation.md").read_text(encoding="utf-8")
    check("SYNTHETIC FIXTURE" in markdown, "fixture banner in Markdown")
    check("M3 伪影风险评估" in markdown, "M3 risk section in Markdown")
    check("Wilcoxon" not in markdown, "no unsupported test names")


def _check_fixture_guard(aggregation: Mapping[str, Any]) -> None:
    check(aggregation["status"] == "no_real_runs", "fixture guard status")
    check(aggregation["experimental_results"] is False, "fixture guard experimental flag")
    check(not aggregation["groups"], "fixture guard groups empty")
    reasons = {skip["reason"] for skip in aggregation["runs"]["skipped"]}
    check("fixture_run_requires_allow_fixture" in reasons, "fixture guard skip reason")


def _check_skip_runs(
    temp_root: Path,
    classifier: analyze_runs.ContextClassifier,
    independent_path: Path,
    independent_sha: str,
) -> None:
    skip_root = temp_root / "skip_runs"
    skip_root.mkdir()
    samples = json.loads(independent_path.read_text(encoding="utf-8"))["samples"][:10]
    records = []
    for sample in samples:
        idx = str(sample["idx"])
        records.append(
            _result_record(
                dataset_type="independent",
                sample_id=f"idx:{idx}",
                unit_id=idx,
                pair_id=None,
                side=None,
                idx=idx,
                label=bool(sample["is_vulnerable"]),
                strategy="direct",
                context_state=_context_state(classifier, sample.get("context")),
                prediction=True,
                status="ok",
            )
        )
    _write_run(
        skip_root,
        run_id="partial_run",
        dataset_type="independent",
        dataset_path=independent_path,
        dataset_sha256=independent_sha,
        strategy="direct",
        records=records,
        selected_units=10,
        partial=True,
    )
    _write_run(
        skip_root,
        run_id="incomplete_run",
        dataset_type="independent",
        dataset_path=independent_path,
        dataset_sha256=independent_sha,
        strategy="context",
        records=records,
        selected_units=10,
        missing_requests=1,
    )
    # Both are fixtures; --allow-fixture lets the partial/incomplete checks run.
    out_dir = temp_root / "skip_out"
    out_dir.mkdir()
    aggregation = _run_cli(skip_root, out_dir, "--allow-fixture")
    check(aggregation["status"] == "no_real_runs", "skip runs status")
    reasons = {skip["reason"] for skip in aggregation["runs"]["skipped"]}
    check("partial_run" in reasons, "partial run skipped")
    check("incomplete_run" in reasons, "incomplete run skipped")


def _check_determinism(
    temp_root: Path,
    runs_root: Path,
    first: Mapping[str, Any],
) -> None:
    out_dir = temp_root / "out_again"
    out_dir.mkdir()
    second = _run_cli(runs_root, out_dir, "--allow-fixture")
    for group in first["groups"]:
        other = next(
            candidate
            for candidate in second["groups"]
            if candidate["group_id"] == group["group_id"]
        )
        check(
            group["bootstrap"] == other["bootstrap"],
            f"bootstrap determinism for {group['group_id']}",
        )
        check(group["pairwise"] == other["pairwise"], f"McNemar determinism for {group['group_id']}")


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="secvul_analysis_selftest_"))
    tracked_outputs = [
        ROOT / "analysis" / "aggregation.json",
        ROOT / "analysis" / "aggregation.md",
    ]
    before: dict[Path, tuple[int, str] | None] = {}
    for path in tracked_outputs:
        before[path] = (
            (path.stat().st_mtime_ns, analyze_runs.sha256_file(path))
            if path.exists()
            else None
        )
    try:
        _check_stats()
        classifier = analyze_runs.ContextClassifier()
        independent_path = DATASETS / "independent_200.json"
        pairs_path = DATASETS / "vulnerable_fixed_200_pairs.json"
        independent_sha = analyze_runs.sha256_file(independent_path)
        pairs_sha = analyze_runs.sha256_file(pairs_path)

        runs_root = temp_root / "runs"
        runs_root.mkdir()
        _independent_fixtures(runs_root, classifier, independent_path, independent_sha)
        _pair_fixtures(runs_root, classifier, pairs_path, pairs_sha)

        out_dir = temp_root / "out"
        out_dir.mkdir()
        aggregation = _run_cli(runs_root, out_dir, "--allow-fixture")
        _check_aggregation(aggregation, runs_root)
        print("[ok] end-to-end aggregation: independent + pairs, cohort, bootstrap, McNemar/Holm")
        print("[ok] context strata and M3 risk flags")

        guard_dir = temp_root / "guard_out"
        guard_dir.mkdir()
        guard = _run_cli(runs_root, guard_dir)
        _check_fixture_guard(guard)
        print("[ok] fixture guard: refuses to treat synthetic runs as real results")

        _check_skip_runs(temp_root, classifier, independent_path, independent_sha)
        print("[ok] partial and incomplete runs are skipped unless explicitly allowed")

        _check_determinism(temp_root, runs_root, aggregation)
        print("[ok] bootstrap and McNemar results are deterministic for a fixed seed")

        # The analyzer must not have written or changed fixture output in the
        # repository.  A legitimate aggregation produced by real runs may
        # already exist; in that case it must remain byte-identical.
        for path in tracked_outputs:
            if before[path] is None:
                check(
                    not path.exists(),
                    f"selftest created {path}; fixture output must stay in temp",
                )
            else:
                check(path.exists(), f"selftest removed existing {path}")
                after = (path.stat().st_mtime_ns, analyze_runs.sha256_file(path))
                check(
                    after == before[path],
                    f"selftest modified existing {path}; fixture output must stay in temp",
                )
        print("[ok] no fixture output was written into analysis/")
    except Exception:
        traceback.print_exc()
        print("SELF-TEST FAILED", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
    if temp_root.exists():
        print(f"WARNING: failed to remove temporary directory {temp_root}", file=sys.stderr)
        return 1
    print("All analysis self-tests passed; temporary fixtures were removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
