#!/usr/bin/env python3
"""Analyse pair-debias runs: order exchange, open choice, length and models.

The analysis joins four conditions per model:

``forced_fwd``
    The published :mod:`pair_joint` run (read-only).
``forced_rev``
    New run with every A/B slot exchanged.
``open_fwd`` / ``open_rev``
    New four-way runs (``A``, ``B``, ``both``, ``neither``) in both orders.

Primary statistics are exact McNemar tests on paired correctness, Wilson
intervals, and a project-cluster percentile bootstrap; a pair-level bootstrap is
reported as a sensitivity analysis.  Holm adjustments are applied inside each
pre-declared test family.  The module writes JSON and Markdown derived from
``results.jsonl``; no number is typed by hand.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.stats import (  # noqa: E402
    cluster_bootstrap,
    holm_adjust,
    mcnemar_exact,
    wilson_interval,
)

from pair_debias.common import (  # noqa: E402
    FORCED_PROMPT_VERSION,
    JOINT_PROMPT_VERSION,
    OPEN_PROMPT_VERSION,
    PairJointError,
    PairUnit,
    length_features,
    load_pairs,
    load_position_map,
    semantic_choice,
)

MODELS: dict[str, dict[str, str]] = {
    "deepseek-v4.1-flash": {"short": "deepseek", "label": "DeepSeek V4.1 Flash"},
    "mimo-v2.6-flash": {"short": "mimo", "label": "MiMo V2.6 Flash"},
}
CONDITION_ORDER = ("forced_fwd", "forced_rev", "open_fwd", "open_rev")
CONDITION_LABELS = {
    "forced_fwd": "强制二选一（正向）",
    "forced_rev": "强制二选一（反向）",
    "open_fwd": "开放四分类（正向）",
    "open_rev": "开放四分类（反向）",
}
CATEGORY_KEYS = ("correct", "swapped", "both_vulnerable", "both_safe", "invalid")
SEMANTIC_KEYS = ("vulnerable", "fixed", "both", "neither", "invalid")
MATCHED_THRESHOLDS = (0.05, 0.10, 0.20)
PRIMARY_MATCHED_THRESHOLD = 0.10


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairJointError(f"cannot read {path}: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairJointError(f"cannot read {path}: {exc}") from exc


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    if denominator == 0:
        return None
    return float(numerator) / float(denominator)


def _round(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(float(value), digits)


def _wilson(successes: int, total: int) -> dict[str, Any] | None:
    if total == 0:
        return None
    result = wilson_interval(successes, total)
    if result is None:
        return None
    return {
        "estimate": _round(result["estimate"]),
        "low": _round(result["low"]),
        "high": _round(result["high"]),
        "successes": successes,
        "total": total,
        "method": "wilson_95",
    }


def _binomial_two_sided(k: int, n: int, p: float = 0.5) -> float | None:
    if n == 0:
        return None
    if k < 0 or k > n:
        raise ValueError("k must be in [0, n]")
    observed = math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))
    total = 0.0
    for i in range(n + 1):
        probability = math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
        if probability <= observed + 1e-15:
            total += probability
    return min(1.0, total)


def _fisher_two_sided(a: int, b: int, c: int, d: int) -> float | None:
    row1 = a + b
    row2 = c + d
    col1 = a + c
    n = row1 + row2
    if n == 0:
        return None
    low = max(0, col1 - row2)
    high = min(row1, col1)
    denominator = math.comb(n, col1)

    def probability(x: int) -> float:
        return math.comb(row1, x) * math.comb(row2, col1 - x) / denominator

    observed = probability(a)
    total = 0.0
    for x in range(low, high + 1):
        value = probability(x)
        if value <= observed + 1e-15:
            total += value
    return min(1.0, total)


def _mean(values: list[float]) -> float | None:
    return _round(sum(values) / len(values)) if values else None


# ---------------------------------------------------------------------------
# Loading and integrity
# ---------------------------------------------------------------------------


@dataclass
class Run:
    condition: str
    path: Path
    manifest: dict[str, Any]
    results: list[dict[str, Any]]
    position: dict[str, Any]
    leak_audit: dict[str, Any] | None
    by_pair: dict[str, dict[str, Any]]

    @property
    def model(self) -> str:
        return str((self.manifest.get("api") or {}).get("model") or "")

    @property
    def assignments(self) -> dict[str, dict[str, Any]]:
        return self.position["assignments"]


def _load_run(path: Path, condition: str) -> Run:
    if not path.exists():
        raise PairJointError(f"run directory does not exist: {path}")
    manifest = _read_json(path / "manifest.json")
    position = load_position_map(path / "position_map.json")
    results = _read_jsonl(path / "results.jsonl")
    if manifest.get("order", {}).get("position_map_sha256") != position.get("sha256"):
        raise PairJointError(f"{path}: position map hash does not match the manifest")
    assignments = position["assignments"]
    if len(results) != len(assignments):
        raise PairJointError(
            f"{path}: {len(results)} result records vs {len(assignments)} position assignments"
        )
    by_pair: dict[str, dict[str, Any]] = {}
    for record in results:
        pair_id = str(record.get("pair_id"))
        if pair_id in by_pair:
            raise PairJointError(f"{path}: duplicate pair_id {pair_id}")
        by_pair[pair_id] = record
    if set(by_pair) != set(assignments):
        raise PairJointError(f"{path}: result pair ids differ from the position map")
    leak_path = path / "leak_audit.json"
    leak_audit = _read_json(leak_path) if leak_path.exists() else None
    return Run(
        condition=condition,
        path=path,
        manifest=manifest,
        results=results,
        position=position,
        leak_audit=leak_audit,
        by_pair=by_pair,
    )


def _run_metadata(run: Run) -> dict[str, Any]:
    manifest = run.manifest
    metrics = manifest.get("metrics") or {}
    return {
        "run_id": manifest.get("run_id") or run.path.name,
        "path": str(run.path),
        "condition": run.condition,
        "model": run.model,
        "prompt_version": manifest.get("prompt_version"),
        "status": manifest.get("status"),
        "partial": manifest.get("partial"),
        "limit": manifest.get("limit"),
        "selected_units": manifest.get("selected_units"),
        "dataset_sha256": manifest.get("dataset_sha256"),
        "position_map_sha256": run.position.get("sha256"),
        "base_map_sha256": manifest.get("base_map_sha256"),
        "vulnerable_slot_counts": run.position.get("counts"),
        "status_counts": (manifest.get("counts") or {}).get("by_status"),
        "metrics_usage": metrics.get("usage"),
        "metrics_latency": metrics.get("latency_seconds"),
        "api": {
            key: (manifest.get("api") or {}).get(key)
            for key in (
                "model",
                "temperature",
                "max_tokens",
                "response_format",
                "thinking",
                "reasoning_effort",
                "input_price_usd_per_1m",
                "output_price_usd_per_1m",
                "cached_input_price_usd_per_1m",
            )
        },
    }


def _config_integrity(models: dict[str, dict[str, Run]], dataset_sha256: str) -> dict[str, Any]:
    all_runs = [run for per_model in models.values() for run in per_model.values()]
    first = all_runs[0]
    checks: dict[str, Any] = {
        "same_dataset_sha256": all(
            run.manifest.get("dataset_sha256") == dataset_sha256 for run in all_runs
        ),
        "same_base_map": True,
        "reversal_exact": True,
        "open_forward_matches_base": True,
        "open_reverse_matches_reverse": True,
        "forced_reversal_exact": True,
        "prompt_versions": {},
        "wrapper_hashes": {},
        "leak_audits_clean": True,
        "slot_counts_balanced": True,
        "mismatches": [],
    }
    for model, per_model in models.items():
        fwd = per_model["forced_fwd"]
        rev = per_model["forced_rev"]
        open_fwd = per_model["open_fwd"]
        open_rev = per_model["open_rev"]
        checks["prompt_versions"][model] = {
            "forced_fwd": fwd.manifest.get("prompt_version"),
            "forced_rev": rev.manifest.get("prompt_version"),
            "open_fwd": open_fwd.manifest.get("prompt_version"),
            "open_rev": open_rev.manifest.get("prompt_version"),
        }
        expected_versions = {
            "forced_fwd": JOINT_PROMPT_VERSION,
            "forced_rev": FORCED_PROMPT_VERSION,
            "open_fwd": OPEN_PROMPT_VERSION,
            "open_rev": OPEN_PROMPT_VERSION,
        }
        for condition, expected in expected_versions.items():
            actual = per_model[condition].manifest.get("prompt_version")
            if actual != expected:
                checks["mismatches"].append(
                    f"{model}/{condition}: prompt version {actual!r}, expected {expected!r}"
                )
        base = fwd.assignments
        if set(base) != set(rev.assignments) or set(base) != set(open_fwd.assignments) or set(base) != set(
            open_rev.assignments
        ):
            checks["mismatches"].append(f"{model}: condition pair sets differ")
        for pair_id, assignment in base.items():
            expected_reverse = {
                "vulnerable_slot": "B" if assignment["vulnerable_slot"] == "A" else "A",
                "fixed_slot": assignment["vulnerable_slot"],
            }
            reverse = rev.assignments[pair_id]
            if (
                reverse["vulnerable_slot"] != expected_reverse["vulnerable_slot"]
                or reverse["fixed_slot"] != expected_reverse["fixed_slot"]
            ):
                checks["reversal_exact"] = False
                checks["forced_reversal_exact"] = False
                checks["mismatches"].append(f"{model}/{pair_id}: forced reversal is not exact")
                break
            if open_fwd.assignments[pair_id]["vulnerable_slot"] != assignment["vulnerable_slot"]:
                checks["open_forward_matches_base"] = False
                checks["mismatches"].append(f"{model}/{pair_id}: open forward slot differs")
                break
            if (
                open_rev.assignments[pair_id]["vulnerable_slot"]
                != expected_reverse["vulnerable_slot"]
            ):
                checks["open_reverse_matches_reverse"] = False
                checks["mismatches"].append(f"{model}/{pair_id}: open reverse slot differs")
                break
        for run in per_model.values():
            counts = run.position.get("counts") or {}
            if abs(int(counts.get("A", 0)) - int(counts.get("B", 0))) > 1:
                checks["slot_counts_balanced"] = False
                checks["mismatches"].append(f"{run.path}: unbalanced slots {counts}")
            if run.condition != "forced_fwd":
                if run.manifest.get("base_map_sha256") != fwd.position.get("sha256"):
                    checks["same_base_map"] = False
                    checks["mismatches"].append(
                        f"{run.path}: base map does not match the forced_fwd position map"
                    )
            if run.leak_audit:
                if not run.leak_audit.get("wrapper_clean_all") or run.leak_audit.get(
                    "slot_leak_all"
                ):
                    checks["leak_audits_clean"] = False
                    checks["mismatches"].append(f"{run.path}: leak audit failed")
    checks["same_base_map"] = checks["same_base_map"] and (
        len(
            {
                run.manifest.get("base_map_sha256")
                for run in all_runs
                if run.manifest.get("base_map_sha256")
            }
        )
        <= 1
    )
    checks["ok"] = not checks["mismatches"] and all(
        checks[key]
        for key in (
            "same_dataset_sha256",
            "same_base_map",
            "reversal_exact",
            "open_forward_matches_base",
            "open_reverse_matches_reverse",
            "leak_audits_clean",
            "slot_counts_balanced",
        )
    )
    return checks


# ---------------------------------------------------------------------------
# Per-condition metrics
# ---------------------------------------------------------------------------


def _semantic(record: dict[str, Any], assignment: dict[str, Any]) -> str:
    if record.get("status") != "ok":
        return "invalid"
    parsed = record.get("parsed")
    if not isinstance(parsed, dict):
        return "invalid"
    return semantic_choice(parsed.get("vulnerable_version"), assignment)


def _category(semantic: str) -> str:
    return {
        "vulnerable": "correct",
        "fixed": "swapped",
        "both": "both_vulnerable",
        "neither": "both_safe",
        "invalid": "invalid",
    }[semantic]


def _decision(record: dict[str, Any]) -> str:
    if record.get("status") != "ok":
        return "invalid"
    parsed = record.get("parsed")
    if not isinstance(parsed, dict):
        return "invalid"
    value = parsed.get("vulnerable_version")
    if value in {"A", "B", "both", "neither"}:
        return str(value)
    return "invalid"


@dataclass
class ConditionResult:
    condition: str
    run: Run
    metrics: dict[str, Any]
    correct: dict[str, bool]
    valid: dict[str, bool]
    abstained: dict[str, bool]
    semantic: dict[str, str]
    decision: dict[str, str]


def _condition_metrics(units: list[PairUnit], run: Run, condition: str) -> ConditionResult:
    n = len(units)
    categories: Counter[str] = Counter()
    valid = 0
    by_slot: dict[str, Counter[str]] = {"A": Counter(), "B": Counter()}
    selected: Counter[str] = Counter()
    selected_by_slot: dict[str, Counter[str]] = {"A": Counter(), "B": Counter()}
    correct: dict[str, bool] = {}
    valid_map: dict[str, bool] = {}
    abstained: dict[str, bool] = {}
    semantic_map: dict[str, str] = {}
    decision_map: dict[str, str] = {}
    invalid_reasons: Counter[str] = Counter()
    evidence_present = 0
    schema_exact = 0
    evidence_compliant = 0
    compliant_correct = 0
    evidence_items_total = 0
    evidence_text_matches = 0
    localization_scored = 0
    localization_hit = 0
    confidence_values: list[float] = []
    confidence_by_category: dict[str, list[float]] = {}
    per_pair: list[dict[str, Any]] = []

    for unit in units:
        record = run.by_pair[unit.pair_id]
        assignment = run.assignments[unit.pair_id]
        semantics = _semantic(record, assignment)
        category = _category(semantics)
        categories[category] += 1
        semantic_map[unit.pair_id] = semantics
        decision = _decision(record)
        decision_map[unit.pair_id] = decision
        correct[unit.pair_id] = category == "correct"
        valid_map[unit.pair_id] = category != "invalid"
        abstained[unit.pair_id] = category in {"both_vulnerable", "both_safe"}
        by_slot[str(assignment["vulnerable_slot"])][category] += 1
        selected[decision] += 1
        selected_by_slot[str(assignment["vulnerable_slot"])][decision] += 1
        per_pair.append(
            {
                "pair_id": unit.pair_id,
                "project": unit.project,
                "vulnerable_slot": assignment["vulnerable_slot"],
                "decision": decision,
                "semantic": semantics,
                "category": category,
                "status": record.get("status"),
            }
        )
        if category == "invalid":
            validation = record.get("validation") or {}
            invalid_reasons[str(validation.get("error_code") or record.get("status"))] += 1
            continue
        valid += 1
        validation = record.get("validation") or {}
        if validation.get("schema_exact"):
            schema_exact += 1
        evidence = validation.get("evidence") or {}
        if evidence.get("evidence_compliant"):
            evidence_compliant += 1
        if validation.get("compliant") and category == "correct":
            compliant_correct += 1
        parsed = record.get("parsed") or {}
        items = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
        if items:
            evidence_present += 1
        evidence_items_total += len(evidence.get("evidence_items") or [])
        evidence_text_matches += int(evidence.get("evidence_text_match_count") or 0)
        if isinstance(parsed.get("confidence"), (int, float)) and not isinstance(
            parsed.get("confidence"), bool
        ):
            confidence = float(parsed["confidence"])
            confidence_values.append(confidence)
            confidence_by_category.setdefault(category, []).append(confidence)
        if category == "correct" and evidence.get("localization_scored"):
            localization_scored += 1
            if evidence.get("localization_hit"):
                localization_hit += 1

    parsed_count = n - categories["invalid"]
    forced_picks = categories["correct"] + categories["swapped"]
    correct_count = categories["correct"]

    slot_metrics: dict[str, Any] = {}
    for slot in ("A", "B"):
        counts = by_slot[slot]
        slot_n = sum(counts.values())
        slot_correct = counts.get("correct", 0)
        slot_parsed = slot_n - counts.get("invalid", 0)
        slot_metrics[slot] = {
            "n": slot_n,
            "categories": {key: counts.get(key, 0) for key in CATEGORY_KEYS},
            "accuracy_all": _round(_ratio(slot_correct, slot_n)),
            "accuracy_parsed": _round(_ratio(slot_correct, slot_parsed)),
            "wilson_all": _wilson(slot_correct, slot_n),
            "wilson_parsed": _wilson(slot_correct, slot_parsed),
        }

    da_a = slot_metrics["A"]["accuracy_all"]
    da_b = slot_metrics["B"]["accuracy_all"]
    strict_a = slot_metrics["A"]["categories"]["correct"]
    strict_b = slot_metrics["B"]["categories"]["correct"]
    parsed_a = slot_metrics["A"]["n"] - slot_metrics["A"]["categories"]["invalid"]
    parsed_b = slot_metrics["B"]["n"] - slot_metrics["B"]["categories"]["invalid"]
    fisher_all = _fisher_two_sided(
        strict_a, slot_metrics["A"]["n"] - strict_a, strict_b, slot_metrics["B"]["n"] - strict_b
    )
    fisher_parsed = _fisher_two_sided(
        strict_a, parsed_a - strict_a, strict_b, parsed_b - strict_b
    )

    ab_selected = selected.get("A", 0) + selected.get("B", 0)
    slot_a_share = _ratio(selected.get("A", 0), ab_selected)
    binomial_p = _binomial_two_sided(selected.get("A", 0), ab_selected)

    categories_rate_all = {
        key: _round(_ratio(value, n)) for key, value in categories.items()
    }
    categories_rate_parsed = {
        key: _round(_ratio(value, parsed_count)) for key, value in categories.items()
    }

    bootstrap_project = _bootstrap(
        units,
        {"da": lambda indices: _flag_rate(indices, units, correct)},
        cluster="project",
    )
    bootstrap_pair = _bootstrap(
        units,
        {"da": lambda indices: _flag_rate(indices, units, correct)},
        cluster="pair",
    )

    metrics = {
        "condition": condition,
        "run": _run_metadata(run),
        "counts": {
            "pairs": n,
            "parsed_outputs": parsed_count,
            "forced_picks": forced_picks,
            "categories": {key: categories.get(key, 0) for key in CATEGORY_KEYS},
            "by_vulnerable_slot": {slot: slot_metrics[slot]["categories"] for slot in ("A", "B")},
            "invalid_reasons": dict(invalid_reasons),
            "selected_letter": dict(selected),
            "status": dict(Counter(str(record.get("status")) for record in run.results)),
        },
        "rates": {
            "over_all_pairs": categories_rate_all,
            "over_parsed_outputs": categories_rate_parsed,
        },
        "accuracy": {
            "all_pairs": _round(_ratio(correct_count, n)),
            "parsed_outputs": _round(_ratio(correct_count, parsed_count)),
            "committed_picks": _round(_ratio(correct_count, forced_picks)),
            "wilson_all_pairs": _wilson(correct_count, n),
            "wilson_parsed": _wilson(correct_count, parsed_count),
            "bootstrap_project": bootstrap_project,
            "bootstrap_pair": bootstrap_pair,
        },
        "abstention": {
            "both_vulnerable": categories.get("both_vulnerable", 0),
            "both_safe": categories.get("both_safe", 0),
            "abstained": categories.get("both_vulnerable", 0) + categories.get("both_safe", 0),
            "rate": _round(_ratio(categories.get("both_vulnerable", 0) + categories.get("both_safe", 0), n)),
        },
        "position_bias": {
            "by_vulnerable_slot": slot_metrics,
            "difference_da_A_minus_da_B_all": _round(None if da_a is None or da_b is None else da_a - da_b),
            "difference_da_A_minus_da_B_parsed": _round(
                None
                if slot_metrics["A"]["accuracy_parsed"] is None
                or slot_metrics["B"]["accuracy_parsed"] is None
                else slot_metrics["A"]["accuracy_parsed"] - slot_metrics["B"]["accuracy_parsed"]
            ),
            "fisher_exact_p_all": fisher_all,
            "fisher_exact_p_parsed": fisher_parsed,
            "selected_slot_counts": dict(selected),
            "selection_by_vulnerable_slot": {slot: dict(selected_by_slot[slot]) for slot in ("A", "B")},
            "slot_a_share_of_ab_selections": _round(slot_a_share),
            "binomial_p_select_A_vs_B": binomial_p,
        },
        "evidence": {
            "decisions_with_evidence": evidence_present,
            "evidence_present_rate": _round(_ratio(evidence_present, parsed_count)),
            "schema_exact": schema_exact,
            "schema_exact_rate": _round(_ratio(schema_exact, parsed_count)),
            "evidence_compliant": evidence_compliant,
            "evidence_compliance_rate": _round(_ratio(evidence_compliant, parsed_count)),
            "compliant_correct": compliant_correct,
            "compliant_correct_rate_all": _round(_ratio(compliant_correct, n)),
            "evidence_items_total": evidence_items_total,
            "evidence_text_matches": evidence_text_matches,
            "evidence_text_match_rate": _round(_ratio(evidence_text_matches, evidence_items_total)),
            "localization_scored_correct": localization_scored,
            "localization_hit_correct": localization_hit,
            "localization_hit_rate_correct": _round(_ratio(localization_hit, localization_scored)),
        },
        "confidence": {
            "mean_parsed": _mean(confidence_values),
            "mean_by_category": {
                key: _mean(values) for key, values in sorted(confidence_by_category.items())
            },
        },
        "length_confound": _length_block(units, correct, run.assignments),
        "per_pair": per_pair,
    }
    return ConditionResult(
        condition=condition,
        run=run,
        metrics=metrics,
        correct=correct,
        valid=valid_map,
        abstained=abstained,
        semantic=semantic_map,
        decision=decision_map,
    )


def _flag_rate(indices: Sequence[int], units: list[PairUnit], flags: dict[str, bool]) -> float | None:
    if len(indices) == 0:
        return None
    return sum(1 for index in indices if flags[units[index].pair_id]) / len(indices)


def _bootstrap(
    units: list[PairUnit],
    metric_fns: dict[str, Any],
    *,
    cluster: str,
    resamples: int = 10000,
    seed: int = 42,
) -> dict[str, Any]:
    cluster_ids = (
        [unit.pair_id for unit in units]
        if cluster == "pair"
        else [unit.project or "unknown" for unit in units]
    )
    block = cluster_bootstrap(cluster_ids, metric_fns, resamples=resamples, seed=seed)
    block["settings"]["cluster_unit"] = cluster
    return block


# ---------------------------------------------------------------------------
# Length analysis
# ---------------------------------------------------------------------------


def _body_for_slot(unit: PairUnit, assignment: dict[str, Any], slot: str) -> str:
    return unit.vulnerable_body if slot == assignment["vulnerable_slot"] else unit.fixed_body


def _pick_shorter_slot(unit: PairUnit, assignment: dict[str, Any], key: Any) -> str:
    body_a = _body_for_slot(unit, assignment, "A")
    body_b = _body_for_slot(unit, assignment, "B")
    size_a, size_b = key(body_a), key(body_b)
    if size_a < size_b:
        return "A"
    if size_b < size_a:
        return "B"
    return "A"


def _heuristic_correct(unit: PairUnit, assignment: dict[str, Any], key: Any) -> bool:
    return _pick_shorter_slot(unit, assignment, key) == assignment["vulnerable_slot"]


def _length_block(
    units: list[PairUnit],
    correct: dict[str, bool],
    assignments: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    strata: dict[str, dict[str, int]] = {
        "vulnerable_shorter": {"n": 0, "correct": 0},
        "vulnerable_longer": {"n": 0, "correct": 0},
        "tie": {"n": 0, "correct": 0},
    }
    bins: dict[str, dict[str, int]] = {
        "<=5%": {"n": 0, "correct": 0},
        "5-10%": {"n": 0, "correct": 0},
        "10-20%": {"n": 0, "correct": 0},
        ">20%": {"n": 0, "correct": 0},
    }
    heuristic_chars = 0
    heuristic_lines = 0
    model_only = 0
    heuristic_only = 0
    for unit in units:
        assignment = assignments[unit.pair_id]
        features = length_features(unit)
        is_correct = correct[unit.pair_id]
        strata[features["stratum"]]["n"] += 1
        strata[features["stratum"]]["correct"] += int(is_correct)
        rel = float(features["relative_char_difference"])
        label = "<=5%" if rel <= 0.05 else ("5-10%" if rel <= 0.10 else ("10-20%" if rel <= 0.20 else ">20%"))
        bins[label]["n"] += 1
        bins[label]["correct"] += int(is_correct)
        h_chars = _heuristic_correct(unit, assignment, len)
        h_lines = _heuristic_correct(unit, assignment, lambda body: len(body.splitlines()))
        heuristic_chars += int(h_chars)
        heuristic_lines += int(h_lines)
        if is_correct and not h_chars:
            model_only += 1
        elif h_chars and not is_correct:
            heuristic_only += 1

    n = len(units)
    for bucket in list(strata.values()) + list(bins.values()):
        bucket["accuracy"] = _round(_ratio(bucket["correct"], bucket["n"]))
    matched: dict[str, Any] = {}
    for threshold in MATCHED_THRESHOLDS:
        subset = [unit for unit in units if length_features(unit)["relative_char_difference"] <= threshold]
        subset_n = len(subset)
        model_correct = sum(1 for unit in subset if correct[unit.pair_id])
        heuristic = sum(
            1
            for unit in subset
            if _heuristic_correct(unit, assignments[unit.pair_id], len)
        )
        matched[f"{threshold:.2f}"] = {
            "threshold": threshold,
            "n": subset_n,
            "model_correct": model_correct,
            "model_da": _round(_ratio(model_correct, subset_n)),
            "wilson": _wilson(model_correct, subset_n),
            "heuristic_correct": heuristic,
            "heuristic_da": _round(_ratio(heuristic, subset_n)),
            "mcnemar_model_vs_heuristic": _safe_mcnemar(
                model_correct=model_correct,
                heuristic_correct=heuristic,
                total=subset_n,
                model_only=sum(
                    1
                    for unit in subset
                    if correct[unit.pair_id]
                    and not _heuristic_correct(unit, assignments[unit.pair_id], len)
                ),
                heuristic_only=sum(
                    1
                    for unit in subset
                    if not correct[unit.pair_id]
                    and _heuristic_correct(unit, assignments[unit.pair_id], len)
                ),
            ),
        }
    line_equal = [unit for unit in units if length_features(unit)["line_difference"] == 0]
    line_equal_correct = sum(1 for unit in line_equal if correct[unit.pair_id])
    line_equal_heuristic = sum(
        1 for unit in line_equal if _heuristic_correct(unit, assignments[unit.pair_id], len)
    )

    return {
        "definition": (
            "Post-hoc diagnostic, not a pre-registered baseline. The heuristic picks the shorter "
            "body (characters or line count) and breaks exact ties with slot A."
        ),
        "strata": strata,
        "relative_char_bins": bins,
        "shorter_body_heuristic": {
            "characters_correct": heuristic_chars,
            "characters_tie_A": _round(_ratio(heuristic_chars, n)),
            "lines_correct": heuristic_lines,
            "lines_tie_A": _round(_ratio(heuristic_lines, n)),
            "n": n,
        },
        "mcnemar_model_vs_shorter_characters": _safe_mcnemar(
            model_correct=sum(1 for value in correct.values() if value),
            heuristic_correct=heuristic_chars,
            total=n,
            model_only=model_only,
            heuristic_only=heuristic_only,
        ),
        "matched_subsets": matched,
        "primary_matched_threshold": PRIMARY_MATCHED_THRESHOLD,
        "line_equal_subset": {
            "n": len(line_equal),
            "model_correct": line_equal_correct,
            "model_da": _round(_ratio(line_equal_correct, len(line_equal))),
            "heuristic_correct": line_equal_heuristic,
            "heuristic_da": _round(_ratio(line_equal_heuristic, len(line_equal))),
        },
    }


def _safe_mcnemar(
    *,
    model_correct: int,
    heuristic_correct: int,
    total: int,
    model_only: int,
    heuristic_only: int,
) -> dict[str, Any] | None:
    if total == 0:
        return None
    result = mcnemar_exact(
        a_correct_b_wrong=model_only,
        a_wrong_b_correct=heuristic_only,
        total=total,
    )
    result["a_correct"] = model_correct
    result["b_correct"] = heuristic_correct
    result["a_accuracy"] = _round(_ratio(model_correct, total))
    result["b_accuracy"] = _round(_ratio(heuristic_correct, total))
    return result


# ---------------------------------------------------------------------------
# Exchange consistency
# ---------------------------------------------------------------------------


def _exchange_block(
    units: list[PairUnit], forward: ConditionResult, reverse: ConditionResult
) -> dict[str, Any]:
    n = len(units)
    transitions: Counter[str] = Counter()
    letter_transitions: Counter[str] = Counter()
    both_valid = 0
    same_semantic = 0
    same_semantic_all = 0
    both_ab = 0
    same_letter = 0
    same_letter_one_correct = 0
    same_letter_both_correct = 0
    stable_correct = 0
    one_correct = 0
    neither_correct = 0
    forward_correct = 0
    reverse_correct = 0
    for unit in units:
        pair_id = unit.pair_id
        forward_semantic = forward.semantic[pair_id]
        reverse_semantic = reverse.semantic[pair_id]
        transitions[f"{forward_semantic}->{reverse_semantic}"] += 1
        if forward_semantic == reverse_semantic:
            same_semantic_all += 1
        if forward_semantic != "invalid" and reverse_semantic != "invalid":
            both_valid += 1
            if forward_semantic == reverse_semantic:
                same_semantic += 1
        f_decision = forward.decision[pair_id]
        r_decision = reverse.decision[pair_id]
        if f_decision in {"A", "B"} and r_decision in {"A", "B"}:
            both_ab += 1
            if f_decision == r_decision:
                same_letter += 1
                if forward.correct[pair_id] != reverse.correct[pair_id]:
                    same_letter_one_correct += 1
                elif forward.correct[pair_id] and reverse.correct[pair_id]:
                    same_letter_both_correct += 1
            letter_transitions[f"{f_decision}->{r_decision}"] += 1
        f_correct = forward.correct[pair_id]
        r_correct = reverse.correct[pair_id]
        forward_correct += int(f_correct)
        reverse_correct += int(r_correct)
        if f_correct and r_correct:
            stable_correct += 1
        elif f_correct or r_correct:
            one_correct += 1
        else:
            neither_correct += 1

    order_mcnemar = mcnemar_exact(
        a_correct_b_wrong=sum(
            1
            for unit in units
            if forward.correct[unit.pair_id] and not reverse.correct[unit.pair_id]
        ),
        a_wrong_b_correct=sum(
            1
            for unit in units
            if not forward.correct[unit.pair_id] and reverse.correct[unit.pair_id]
        ),
        total=n,
    )
    letter_same_rate = _ratio(same_letter, both_ab)
    letter_p = _binomial_two_sided(same_letter, both_ab)
    return {
        "n": n,
        "forward_correct": forward_correct,
        "reverse_correct": reverse_correct,
        "forward_da": _round(_ratio(forward_correct, n)),
        "reverse_da": _round(_ratio(reverse_correct, n)),
        "mean_da": _round((forward_correct + reverse_correct) / (2 * n)),
        "da_both_orders": _round(_ratio(stable_correct, n)),
        "da_either_order": _round(_ratio(stable_correct + one_correct, n)),
        "stable_correct": stable_correct,
        "one_order_correct": one_correct,
        "neither_order_correct": neither_correct,
        "wilson_da_both_orders": _wilson(stable_correct, n),
        "both_valid": both_valid,
        "semantic_agreement": same_semantic,
        "semantic_agreement_rate_valid": _round(_ratio(same_semantic, both_valid)),
        "semantic_agreement_rate_all": _round(_ratio(same_semantic_all, n)),
        "semantic_transitions": dict(transitions),
        "both_ab": both_ab,
        "same_letter": same_letter,
        "same_letter_rate": _round(letter_same_rate),
        "same_letter_one_correct": same_letter_one_correct,
        "same_letter_both_correct": same_letter_both_correct,
        "one_order_correct_content_switch": one_correct - same_letter_one_correct,
        "single_order_minus_exchange_da": _round(
            _ratio(forward_correct + reverse_correct, 2 * n) - _ratio(stable_correct, n)
            if n
            else None
        ),
        "letter_transitions": dict(letter_transitions),
        "binomial_p_same_letter_vs_0_5": letter_p,
        "order_mcnemar": order_mcnemar,
        "order_da_gap_reverse_minus_forward": _round(_ratio(reverse_correct - forward_correct, n)),
        "interpretation": (
            "same_letter_rate near 0 means the chosen revision stayed the same while the letter flipped, "
            "i.e. content-driven answers; near 1 means the same letter was chosen in both orders, i.e. "
            "position-following; near 0.5 is consistent with a random letter choice. Accuracy must be read "
            "alongside this rate, because a stable but wrong semantic choice also produces a rate near 0."
        ),
    }


# ---------------------------------------------------------------------------
# Paired comparisons and bootstrap
# ---------------------------------------------------------------------------


def _comparison(
    units: list[PairUnit],
    flags_a: dict[str, bool],
    flags_b: dict[str, bool],
    *,
    label_a: str,
    label_b: str,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    n = len(units)
    a_only = sum(1 for unit in units if flags_a[unit.pair_id] and not flags_b[unit.pair_id])
    b_only = sum(1 for unit in units if not flags_a[unit.pair_id] and flags_b[unit.pair_id])
    both_true = sum(1 for unit in units if flags_a[unit.pair_id] and flags_b[unit.pair_id])
    both_false = n - a_only - b_only - both_true
    rate_a = _ratio(sum(1 for unit in units if flags_a[unit.pair_id]), n)
    rate_b = _ratio(sum(1 for unit in units if flags_b[unit.pair_id]), n)
    mcnemar = mcnemar_exact(
        a_correct_b_wrong=a_only, a_wrong_b_correct=b_only, total=n
    )

    def _metric_fns(indices: Sequence[int]) -> dict[str, Any]:
        return {
            "rate_a": _flag_rate(indices, units, flags_a),
            "rate_b": _flag_rate(indices, units, flags_b),
            "difference": (
                None
                if len(indices) == 0
                else _flag_rate(indices, units, flags_a) - _flag_rate(indices, units, flags_b)
            ),
        }

    metric_fns = {
        "rate_a": lambda indices: _metric_fns(indices)["rate_a"],
        "rate_b": lambda indices: _metric_fns(indices)["rate_b"],
        "difference": lambda indices: _metric_fns(indices)["difference"],
    }

    project = _bootstrap(units, metric_fns, cluster="project", resamples=resamples, seed=seed)
    pair = _bootstrap(units, metric_fns, cluster="pair", resamples=resamples, seed=seed)
    return {
        "label_a": label_a,
        "label_b": label_b,
        "n_pairs": n,
        "rate_a_all": _round(rate_a),
        "rate_b_all": _round(rate_b),
        "difference_all": _round(None if rate_a is None or rate_b is None else rate_a - rate_b),
        "table": {
            "both_true": both_true,
            "a_only": a_only,
            "b_only": b_only,
            "both_false": both_false,
        },
        "mcnemar": mcnemar,
        "bootstrap_project": project,
        "bootstrap_pair": pair,
    }


# ---------------------------------------------------------------------------
# Usage and cost
# ---------------------------------------------------------------------------


def _usage_block(run: Run) -> dict[str, Any]:
    prompt_tokens = completion_tokens = cached_tokens = reasoning_tokens = 0
    cost = 0.0
    records_with_cost = 0
    provider_list_cost = 0.0
    provider_allowance = 0.0
    provider_rows = 0
    with_usage = 0
    for record in run.results:
        response = record.get("response") or {}
        usage = response.get("usage")
        if isinstance(usage, dict):
            with_usage += 1
            for key in ("prompt_tokens", "completion_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    if key == "prompt_tokens":
                        prompt_tokens += value
                    else:
                        completion_tokens += value
            cached = usage.get("prompt_cache_hit_tokens")
            if not isinstance(cached, int):
                details = usage.get("prompt_tokens_details")
                cached = details.get("cached_tokens") if isinstance(details, dict) else None
            if isinstance(cached, int) and not isinstance(cached, bool):
                cached_tokens += cached
            details = usage.get("completion_tokens_details")
            reasoning = details.get("reasoning_tokens") if isinstance(details, dict) else None
            if isinstance(reasoning, int) and not isinstance(reasoning, bool):
                reasoning_tokens += reasoning
            provider = usage.get("opencode")
            if isinstance(provider, dict):
                provider_rows += 1
                if isinstance(provider.get("list_cost"), (int, float)):
                    provider_list_cost += float(provider["list_cost"])
                if isinstance(provider.get("allowance"), (int, float)):
                    provider_allowance += float(provider["allowance"])
        response_cost = response.get("cost")
        value = response_cost.get("cost_usd") if isinstance(response_cost, dict) else None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            cost += float(value)
            records_with_cost += 1
    api = run.manifest.get("api") or {}
    status_counts = Counter(str(record.get("status")) for record in run.results)
    return {
        "run_id": run.manifest.get("run_id") or run.path.name,
        "condition": run.condition,
        "model": run.model,
        "requests": len(run.results),
        "status": dict(status_counts),
        "with_usage": with_usage,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_prompt_tokens": cached_tokens,
        "reasoning_tokens": reasoning_tokens,
        "cost_usd_configured": _round(cost if records_with_cost else None),
        "records_with_cost": records_with_cost,
        "provider_list_cost_usd": _round(provider_list_cost if provider_rows else None),
        "provider_allowance_usd": _round(provider_allowance if provider_rows else None),
        "provider_rows": provider_rows,
        "prices": {
            "input_usd_per_1m": api.get("input_price_usd_per_1m"),
            "output_usd_per_1m": api.get("output_price_usd_per_1m"),
            "cached_input_usd_per_1m": api.get("cached_input_price_usd_per_1m"),
        },
        "cost_note": (
            "cost_usd_configured applies the run's configured list prices to reported tokens; "
            "provider_list_cost_usd is the provider's own usage snapshot and may use a peak/off-peak price."
        ),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{100.0 * value:.2f}%"


def _num(value: float | None, digits: int = 4) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def _pvalue(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.2e}" if value < 1e-4 else f"{value:.4f}"


def _ci(block: dict[str, Any] | None, metric: str = "da") -> str:
    if not block:
        return "—"
    cell = (block.get("metrics") or {}).get(metric)
    if not cell or cell.get("ci_low") is None:
        return "—"
    return f"[{100 * cell['ci_low']:.2f}, {100 * cell['ci_high']:.2f}]"


def _diff_ci(block: dict[str, Any]) -> str:
    cell = (block.get("metrics") or {}).get("difference")
    if not cell or cell.get("ci_low") is None:
        return "—"
    return f"[{100 * cell['ci_low']:+.2f}, {100 * cell['ci_high']:+.2f}]"


def _render_model_markdown(model: str, metrics: dict[str, Any]) -> str:
    conditions = metrics["conditions"]
    phase_label = "（pilot，仅接入验证）" if metrics.get("phase") == "pilot" else ""
    lines = [
        f"# Pair-debias：{MODELS[model]['label']}{phase_label}",
        "",
        f"- 数据集：`{metrics['dataset']['path']}`（SHA-256 `{metrics['dataset']['sha256']}`，{metrics['dataset']['pairs']} 对）",
        f"- 条件：强制二选一正向/反向、开放四分类正向/反向；每对每条件一次请求。",
        f"- 完整性：`{metrics['integrity']['ok']}`；泄漏审计 `{metrics['integrity']['leak_audits_clean']}`。",
        "",
        "## 1. 条件总览",
        "",
        "| 条件 | n | 正确 | DA | 95% CI（项目聚类） | swapped | both | neither | invalid | both+neither 率 |",
        "| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition in CONDITION_ORDER:
        block = conditions[condition]
        acc = block["accuracy"]
        cats = block["counts"]["categories"]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {block['counts']['pairs']} | "
            f"{cats['correct']} | {_pct(acc['all_pairs'])} | "
            f"{_ci(acc['bootstrap_project'])} | {cats['swapped']} | {cats['both_vulnerable']} | "
            f"{cats['both_safe']} | {cats['invalid']} | {_pct(block['abstention']['rate'])} |"
        )
    lines.extend(
        [
            "",
            "DA 的分母是全部配对（invalid 记错）；`committed_picks` 以实际给出 A/B 的输出为分母。",
            "",
            "## 2. 位置偏差（漏洞版本在 A vs 在 B）",
            "",
            "| 条件 | DA(vuln=A) | DA(vuln=B) | Δ(A−B) | Fisher p | 选 A 比例 | 二项 p |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for condition in CONDITION_ORDER:
        pos = conditions[condition]["position_bias"]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | "
            f"{_pct(pos['by_vulnerable_slot']['A']['accuracy_all'])} | "
            f"{_pct(pos['by_vulnerable_slot']['B']['accuracy_all'])} | "
            f"{_pct(pos['difference_da_A_minus_da_B_all'])} | "
            f"{_pvalue(pos['fisher_exact_p_all'])} | "
            f"{_pct(pos['slot_a_share_of_ab_selections'])} | "
            f"{_pvalue(pos['binomial_p_select_A_vs_B'])} |"
        )

    lines.extend(
        [
            "",
            "## 3. 双顺序交换一致性",
            "",
            "| 任务 | 正序 DA | 反序 DA | 两序都对 | 交换一致 DA | 仅一序对 | 其中同字母 | 语义一致率 | 同字母率 | 同字母 p | 顺序 McNemar p |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for task in ("forced", "open"):
        exchange = metrics["exchange"][task]
        lines.append(
            f"| {task} | {_pct(exchange['forward_da'])} | {_pct(exchange['reverse_da'])} | "
            f"{exchange['stable_correct']}/{exchange['n']} | {_pct(exchange['da_both_orders'])} | "
            f"{exchange['one_order_correct']} | {exchange['same_letter_one_correct']} | "
            f"{_pct(exchange['semantic_agreement_rate_valid'])} | "
            f"{_pct(exchange['same_letter_rate'])} | {_pvalue(exchange['binomial_p_same_letter_vs_0_5'])} | "
            f"{_pvalue(exchange['order_mcnemar']['p_value'])} |"
        )
    lines.extend(
        [
            "",
            "`同字母率` 只在两序都给出 A/B 的配对上计算：接近 0 表示选择跟随版本内容，接近 1 表示跟随槽位，约 0.5 与随机选字母一致。",
            "",
            "## 4. 长度混淆与长度匹配子集",
            "",
            "| 条件 | vuln 更短 DA | vuln 更长 DA | 等长 DA | 字符启发式 DA | 匹配≤10% n | 匹配 DA | 匹配启发式 | 匹配 McNemar p |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for condition in CONDITION_ORDER:
        block = conditions[condition]["length_confound"]
        strata = block["strata"]
        matched = block["matched_subsets"]["0.10"]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {_pct(strata['vulnerable_shorter']['accuracy'])} "
            f"({strata['vulnerable_shorter']['correct']}/{strata['vulnerable_shorter']['n']}) | "
            f"{_pct(strata['vulnerable_longer']['accuracy'])} "
            f"({strata['vulnerable_longer']['correct']}/{strata['vulnerable_longer']['n']}) | "
            f"{_pct(strata['tie']['accuracy'])} | "
            f"{_pct(block['shorter_body_heuristic']['characters_tie_A'])} | "
            f"{matched['n']} | {_pct(matched['model_da'])} | {_pct(matched['heuristic_da'])} | "
            f"{_pvalue((matched['mcnemar_model_vs_heuristic'] or {}).get('p_value'))} |"
        )
    lines.extend(
        [
            "",
            "## 5. 成本与完整性",
            "",
            "| 条件 | 请求 | ok | invalid | error | prompt tokens | completion tokens | 配置价 USD | provider 快照 USD | p95 延迟 s |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for condition in CONDITION_ORDER:
        usage = metrics["usage"][condition]
        status = usage["status"]
        latency = (metrics["conditions"][condition]["run"].get("metrics_latency") or {}).get("p95")
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {usage['requests']} | {status.get('ok', 0)} | "
            f"{status.get('invalid', 0)} | {status.get('error', 0)} | {usage['prompt_tokens']} | "
            f"{usage['completion_tokens']} | {_num(usage['cost_usd_configured'], 6)} | "
            f"{_num(usage['provider_list_cost_usd'], 6)} | {_num(latency, 2)} |"
        )
    total = metrics["usage"]["total"]
    lines.extend(
        [
            f"| **合计** | {total['requests']} | {total['status'].get('ok', 0)} | "
            f"{total['status'].get('invalid', 0)} | {total['status'].get('error', 0)} | "
            f"{total['prompt_tokens']} | {total['completion_tokens']} | "
            f"{_num(total['cost_usd_configured'], 6)} | {_num(total['provider_list_cost_usd'], 6)} | — |",
            "",
            "配置价按运行配置的 list price 计算；provider 快照可能处于峰谷价，两者不应混用。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_comparison_markdown(comparison: dict[str, Any]) -> str:
    phase_label = "（pilot，仅接入验证）" if comparison.get("phase") == "pilot" else ""
    lines = [
        f"# Pair-debias：跨模型与效应汇总{phase_label}",
        "",
        f"- 数据集 SHA-256：`{comparison['dataset']['sha256']}`；{comparison['dataset']['pairs']} 对。",
        f"- 完整性：`{comparison['integrity']['ok']}`。",
        "",
        "## 1. 跨模型比较（同一配对上）",
        "",
        "| 条件 | DeepSeek DA | MiMo DA | Δ(DS−MiMo) | McNemar p | Holm p | 项目聚类 Δ 95% CI |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for condition in CONDITION_ORDER:
        block = comparison["cross_model"][condition]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {_pct(block['rate_a_all'])} | {_pct(block['rate_b_all'])} | "
            f"{_pct(block['difference_all'])} | {_pvalue(block['mcnemar']['p_value'])} | "
            f"{_pvalue(block.get('holm_p'))} | {_diff_ci(block['bootstrap_project'])} |"
        )
    lines.extend(
        [
            "",
            f"### 1b. 跨模型（长度匹配子集，相对字符差 ≤10%，n={comparison['matched_length_n']}）",
            "",
            "| 条件 | DeepSeek DA | MiMo DA | Δ(DS−MiMo) | McNemar p |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for condition in CONDITION_ORDER:
        block = comparison["cross_model_matched"][condition]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {_pct(block['rate_a_all'])} | {_pct(block['rate_b_all'])} | "
            f"{_pct(block['difference_all'])} | {_pvalue(block['mcnemar']['p_value'])} |"
        )
    lines.extend(
        [
            "",
            "## 2. 顺序效应（反向 − 正向）",
            "",
            "| 模型 | 任务 | 正向 DA | 反向 DA | Δpp | McNemar p | Holm p | 同字母率 |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for task in ("forced", "open"):
            block = comparison["order_effects"][model][task]
            exchange = comparison["exchange"][model][task]
            lines.append(
                f"| {MODELS[model]['label']} | {task} | {_pct(exchange['forward_da'])} | "
                f"{_pct(exchange['reverse_da'])} | "
                f"{_pct(block['difference_all'])} | {_pvalue(block['mcnemar']['p_value'])} | "
                f"{_pvalue(block.get('holm_p'))} | {_pct(exchange['same_letter_rate'])} |"
            )
    lines.extend(
        [
            "",
            "## 3. 任务效应（开放四分类 − 强制二选一）",
            "",
            "| 模型 | 顺序 | 强制 DA | 开放 DA | Δpp（开放−强制） | McNemar p | Holm p | 开放 both+neither 率 |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for order in ("fwd", "rev"):
            block = comparison["task_effects"][model][order]
            open_condition = f"open_{order}"
            lines.append(
                f"| {MODELS[model]['label']} | {order} | {_pct(block['rate_b_all'])} | "
                f"{_pct(block['rate_a_all'])} | {_pct(block['difference_all'])} | "
                f"{_pvalue(block['mcnemar']['p_value'])} | {_pvalue(block.get('holm_p'))} | "
                f"{_pct(comparison['open_abstention'][model][order])} |"
            )
    lines.extend(
        [
            "",
            "## 4. 交换一致 DA（两序都判对）",
            "",
            "| 模型 | 任务 | 交换一致 DA | 仅一序对 | 语义一致率 | 同字母率 | 同字母 p |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for task in ("forced", "open"):
            exchange = comparison["exchange"][model][task]
            lines.append(
                f"| {MODELS[model]['label']} | {task} | {_pct(exchange['da_both_orders'])} | "
                f"{exchange['one_order_correct']} | {_pct(exchange['semantic_agreement_rate_valid'])} | "
                f"{_pct(exchange['same_letter_rate'])} | {_pvalue(exchange['binomial_p_same_letter_vs_0_5'])} |"
            )
    lines.extend(
        [
            "",
            "| 任务 | DeepSeek 交换一致 DA | MiMo 交换一致 DA | Δ(DS−MiMo) | McNemar p | Holm p |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for task in ("forced", "open"):
        block = comparison["exchange_model_effect"][task]
        lines.append(
            f"| {task} | {_pct(block['rate_a_all'])} | {_pct(block['rate_b_all'])} | "
            f"{_pct(block['difference_all'])} | {_pvalue(block['mcnemar']['p_value'])} | "
            f"{_pvalue(block.get('holm_p'))} |"
        )
    lines.extend(
        [
            "",
            "**交换一致 DA vs 长度启发式**（启发式 = 选较短版本，等长选 A；模型和启发式都要求两序同语义才对）：",
            "",
            "| 模型 | 任务 | 交换一致 DA | 长度启发式 DA（两序） | Δ(交换−启发式) | McNemar p | Holm p |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for task in ("forced", "open"):
            block = comparison["exchange_vs_heuristic"][model][task]
            lines.append(
                f"| {MODELS[model]['label']} | {task} | {_pct(block['rate_a_all'])} | "
                f"{_pct(block['rate_b_all'])} | {_pct(block['difference_all'])} | "
                f"{_pvalue(block['mcnemar']['p_value'])} | {_pvalue(block.get('holm_p'))} |"
            )
    reference = comparison["exchange_vs_heuristic"]["deepseek-v4.1-flash"]["forced"]
    lines.extend(
        [
            "",
            f"单向长度启发式 DA = {_pct(reference['heuristic_forward_rate'])}；"
            f"两序同语义的长度启发式 DA = {_pct(reference['heuristic_exchange_rate'])}。"
            "上表使用两序版本，与模型的交换一致 DA 口径一致。",
            "",
            "## 5. 可解释性检验",
            "",
            "| 模型 | 条件 | n | 匹配≤10% DA | 匹配启发式 | McNemar p | 全量启发式 DA | 全量 McNemar p |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for condition in CONDITION_ORDER:
            block = comparison["length_tests"][model][condition]
            matched = block["matched"]
            lines.append(
                f"| {MODELS[model]['label']} | {CONDITION_LABELS[condition]} | {matched['n']} | "
                f"{_pct(matched['model_da'])} | {_pct(matched['heuristic_da'])} | "
                f"{_pvalue((matched['mcnemar_model_vs_heuristic'] or {}).get('p_value'))} | "
                f"{_pct(block['heuristic_da_all'])} | {_pvalue(block['mcnemar_all']['p_value'])} |"
            )
    lines.extend(
        [
            "",
            "## 6. 成本",
            "",
            "| 模型 | 新增请求 | 配置价 USD | provider 快照 USD | 备注 |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for model in MODELS:
        cost = comparison["cost"][model]
        lines.append(
            f"| {MODELS[model]['label']} | {cost['new_requests']} | "
            f"{_num(cost['new_cost_usd_configured'], 6)} | "
            f"{_num(cost['new_provider_list_cost_usd'], 6)} | 不含已发布的 forced_fwd |"
        )
    lines.extend(
        [
            "",
            "## 7. 统计口径与限制",
            "",
            "1. **DA**：`correct / n`，invalid 记错；开放条件下 `both`/`neither` 属于错误（真实标签恰好一个版本有漏洞）。",
            "2. **交换一致 DA**：正序和反序都把漏洞版本判对才算对；这是比单序 DA 更严格、对位置偏差不敏感的主指标。",
            "3. **同字母率**：两序都给出 A/B 时选择同一字母的比例。接近 0 表示语义选择稳定、字母随槽位翻转（内容驱动）；接近 1 表示跟随槽位；约 0.5 与随机一致。",
            "4. **bootstrap**：10,000 次，种子 42；主区间按 project 聚类，配对级为敏感性。",
            "5. **Holm**：在每个预先声明的检验族内校正；未校正 p 同时列出。",
            "6. **长度匹配**：主阈值 10% 相对字符差，5%/20% 与等行数子集为敏感性；这是事后诊断，不是预注册基线。",
            "7. **单次贪心解码**：temperature=0，不含重复采样方差。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_summary(comparison: dict[str, Any]) -> str:
    phase_label = "（pilot，仅接入验证）" if comparison.get("phase") == "pilot" else ""
    lines = [
        f"# Pair-debias 结果摘要{phase_label}",
        "",
        f"数据集：`{comparison['dataset']['path']}`（{comparison['dataset']['pairs']} 对，SHA-256 `{comparison['dataset']['sha256']}`）。",
        "",
        "## 主表",
        "",
        "| 模型 | 条件 | n | correct | DA | 95% CI（项目聚类） | swapped | both | neither | invalid |",
        "| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for model in MODELS:
        for condition in CONDITION_ORDER:
            block = comparison["conditions"][model][condition]
            cats = block["counts"]["categories"]
            lines.append(
                f"| {MODELS[model]['label']} | {CONDITION_LABELS[condition]} | {block['counts']['pairs']} | "
                f"{cats['correct']} | {_pct(block['accuracy']['all_pairs'])} | "
                f"{_ci(block['accuracy']['bootstrap_project'])} | {cats['swapped']} | "
                f"{cats['both_vulnerable']} | {cats['both_safe']} | {cats['invalid']} |"
            )
    lines.extend(
        [
            "",
            "## 交换一致性",
            "",
            "| 模型 | 任务 | 交换一致 DA | 语义一致率 | 同字母率 | 顺序 McNemar p |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for task in ("forced", "open"):
            exchange = comparison["exchange"][model][task]
            lines.append(
                f"| {MODELS[model]['label']} | {task} | {_pct(exchange['da_both_orders'])} | "
                f"{_pct(exchange['semantic_agreement_rate_valid'])} | {_pct(exchange['same_letter_rate'])} | "
                f"{_pvalue(exchange['order_mcnemar']['p_value'])} |"
            )
    lines.extend(
        [
            "",
            "## 交换一致 DA vs 两序长度启发式",
            "",
            "| 模型 | 任务 | 交换一致 DA | 启发式 DA | Δ | McNemar p | Holm p |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for task in ("forced", "open"):
            block = comparison["exchange_vs_heuristic"][model][task]
            lines.append(
                f"| {MODELS[model]['label']} | {task} | {_pct(block['rate_a_all'])} | "
                f"{_pct(block['rate_b_all'])} | {_pct(block['difference_all'])} | "
                f"{_pvalue(block['mcnemar']['p_value'])} | {_pvalue(block.get('holm_p'))} |"
            )
    lines.extend(
        [
            "",
            "## 长度匹配子集（相对字符差 ≤10%）",
            "",
            "| 模型 | 条件 | n | 模型 DA | 启发式 DA | McNemar p |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for model in MODELS:
        for condition in CONDITION_ORDER:
            matched = comparison["length_tests"][model][condition]["matched"]
            lines.append(
                f"| {MODELS[model]['label']} | {CONDITION_LABELS[condition]} | {matched['n']} | "
                f"{_pct(matched['model_da'])} | {_pct(matched['heuristic_da'])} | "
                f"{_pvalue((matched['mcnemar_model_vs_heuristic'] or {}).get('p_value'))} |"
            )
    reference = (
        "`report.md`（全量）"
        if comparison.get("phase") != "pilot"
        else "`README.md`（pilot 仅用于接入/解析验证）"
    )
    lines.extend(
        [
            "",
            f"完整解释、限制与统计细节见 {reference}；逐对结果在 `analysis_<model>.json` 的 `per_pair`；"
            "跨模型对比在 `comparison.json`。",
            "",
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _default_paths(phase: str) -> tuple[Path, dict[str, dict[str, Path]]]:
    if phase == "pilot":
        dataset = ROOT / "splits" / "pilot_pairs_18.json"
        prefix = "pilot"
        joint_suffix = "_8"
    elif phase == "test":
        dataset = ROOT / "splits" / "test_pairs_180.json"
        prefix = "test"
        joint_suffix = "_180"
    else:
        raise PairJointError(f"unknown phase {phase!r}")
    paths: dict[str, dict[str, Path]] = {}
    for model, spec in MODELS.items():
        short = spec["short"]
        paths[model] = {
            "forced_fwd": ROOT / "pair_joint" / "runs" / f"{prefix}_{short}{joint_suffix}",
            "forced_rev": ROOT / "pair_debias" / "runs" / f"{prefix}_{short}_forced_rev",
            "open_fwd": ROOT / "pair_debias" / "runs" / f"{prefix}_{short}_open_fwd",
            "open_rev": ROOT / "pair_debias" / "runs" / f"{prefix}_{short}_open_rev",
        }
    return dataset, paths


def _analyse(phase: str, out_dir: Path, resamples: int, seed: int) -> dict[str, Any]:
    dataset_path, paths = _default_paths(phase)
    units_all, dataset_metadata, dataset_sha256 = load_pairs(dataset_path)

    runs: dict[str, dict[str, Run]] = {}
    for model, per_paths in paths.items():
        runs[model] = {
            condition: _load_run(per_paths[condition], condition)
            for condition in CONDITION_ORDER
        }

    pair_sets = {
        model: {condition: set(run.assignments) for condition, run in per_model.items()}
        for model, per_model in runs.items()
    }
    reference = pair_sets[next(iter(MODELS))]["forced_fwd"]
    for model, per_condition in pair_sets.items():
        for condition, pair_ids in per_condition.items():
            if pair_ids != reference:
                raise PairJointError(
                    f"{model}/{condition}: pair set differs from forced_fwd "
                    f"({len(pair_ids)} vs {len(reference)})"
                )
    units = [unit for unit in units_all if unit.pair_id in reference]
    if len(units) != len(reference):
        raise PairJointError("dataset does not contain every pair used by the runs")

    integrity = _config_integrity(runs, dataset_sha256)
    if not integrity["ok"]:
        raise PairJointError(f"run integrity check failed: {integrity['mismatches'][:3]}")

    model_analyses: dict[str, Any] = {}
    condition_results_by_model: dict[str, dict[str, ConditionResult]] = {}
    for model, per_model in runs.items():
        condition_results = {
            condition: _condition_metrics(units, per_model[condition], condition)
            for condition in CONDITION_ORDER
        }
        condition_results_by_model[model] = condition_results
        exchange = {
            "forced": _exchange_block(
                units, condition_results["forced_fwd"], condition_results["forced_rev"]
            ),
            "open": _exchange_block(
                units, condition_results["open_fwd"], condition_results["open_rev"]
            ),
        }
        order_effects = {
            "forced": _comparison(
                units,
                condition_results["forced_fwd"].correct,
                condition_results["forced_rev"].correct,
                label_a="forced_fwd",
                label_b="forced_rev",
                resamples=resamples,
                seed=seed,
            ),
            "open": _comparison(
                units,
                condition_results["open_fwd"].correct,
                condition_results["open_rev"].correct,
                label_a="open_fwd",
                label_b="open_rev",
                resamples=resamples,
                seed=seed,
            ),
        }
        task_effects = {
            "fwd": _comparison(
                units,
                condition_results["open_fwd"].correct,
                condition_results["forced_fwd"].correct,
                label_a="open_fwd",
                label_b="forced_fwd",
                resamples=resamples,
                seed=seed,
            ),
            "rev": _comparison(
                units,
                condition_results["open_rev"].correct,
                condition_results["forced_rev"].correct,
                label_a="open_rev",
                label_b="forced_rev",
                resamples=resamples,
                seed=seed,
            ),
        }
        abstention_effects = {
            "fwd": _comparison(
                units,
                condition_results["open_fwd"].abstained,
                condition_results["forced_fwd"].abstained,
                label_a="open_fwd_abstain",
                label_b="forced_fwd_abstain",
                resamples=resamples,
                seed=seed,
            ),
            "rev": _comparison(
                units,
                condition_results["open_rev"].abstained,
                condition_results["forced_rev"].abstained,
                label_a="open_rev_abstain",
                label_b="forced_rev_abstain",
                resamples=resamples,
                seed=seed,
            ),
        }
        usage = {
            condition: _usage_block(per_model[condition]) for condition in CONDITION_ORDER
        }
        total = {
            "requests": sum(block["requests"] for block in usage.values()),
            "status": dict(
                sum(
                    (Counter(block["status"]) for block in usage.values()),
                    Counter(),
                )
            ),
            "prompt_tokens": sum(block["prompt_tokens"] for block in usage.values()),
            "completion_tokens": sum(block["completion_tokens"] for block in usage.values()),
            "cached_prompt_tokens": sum(block["cached_prompt_tokens"] for block in usage.values()),
            "cost_usd_configured": _round(
                sum(
                    block["cost_usd_configured"] or 0.0
                    for block in usage.values()
                )
            ),
            "provider_list_cost_usd": _round(
                sum(block["provider_list_cost_usd"] or 0.0 for block in usage.values())
            ),
        }
        model_analyses[model] = {
            "schema_version": 1,
            "phase": phase,
            "dataset": {
                "path": str(dataset_path.relative_to(ROOT)),
                "sha256": dataset_sha256,
                "pairs": len(units),
                "metadata": {
                    key: dataset_metadata.get(key)
                    for key in ("schema_version", "split", "source_file", "source_sha256")
                    if key in dataset_metadata
                },
            },
            "model": model,
            "model_label": MODELS[model]["label"],
            "integrity": integrity,
            "conditions": {condition: condition_results[condition].metrics for condition in CONDITION_ORDER},
            "exchange": exchange,
            "order_effects": order_effects,
            "task_effects": task_effects,
            "abstention_effects": abstention_effects,
            "usage": {**usage, "total": total},
        }

    cross_model: dict[str, Any] = {}
    for condition in CONDITION_ORDER:
        ds = model_analyses["deepseek-v4.1-flash"]["conditions"][condition]
        mimo = model_analyses["mimo-v2.6-flash"]["conditions"][condition]
        ds_result = condition_results_by_model["deepseek-v4.1-flash"][condition]
        mimo_result = condition_results_by_model["mimo-v2.6-flash"][condition]
        cross_model[condition] = _comparison(
            units,
            ds_result.correct,
            mimo_result.correct,
            label_a="deepseek",
            label_b="mimo",
            resamples=resamples,
            seed=seed,
        )
        cross_model[condition]["rate_a_all"] = ds["accuracy"]["all_pairs"]
        cross_model[condition]["rate_b_all"] = mimo["accuracy"]["all_pairs"]

    exchange_model: dict[str, Any] = {}
    for task in ("forced", "open"):
        ds_stable = _stable_flags(
            units, condition_results_by_model["deepseek-v4.1-flash"], task
        )
        mimo_stable = _stable_flags(units, condition_results_by_model["mimo-v2.6-flash"], task)
        exchange_model[task] = _comparison(
            units,
            ds_stable,
            mimo_stable,
            label_a="deepseek_exchange",
            label_b="mimo_exchange",
            resamples=resamples,
            seed=seed,
        )

    matched_units = [
        unit
        for unit in units
        if length_features(unit)["relative_char_difference"] <= PRIMARY_MATCHED_THRESHOLD
    ]
    cross_model_matched: dict[str, Any] = {}
    for condition in CONDITION_ORDER:
        cross_model_matched[condition] = _comparison(
            matched_units,
            condition_results_by_model["deepseek-v4.1-flash"][condition].correct,
            condition_results_by_model["mimo-v2.6-flash"][condition].correct,
            label_a="deepseek_matched",
            label_b="mimo_matched",
            resamples=resamples,
            seed=seed,
        )

    exchange_vs_heuristic: dict[str, dict[str, Any]] = {}
    for model in MODELS:
        exchange_vs_heuristic[model] = {}
        forward_map = runs[model]["forced_fwd"].assignments
        reverse_map = runs[model]["forced_rev"].assignments
        heuristic_forward = {
            unit.pair_id: _heuristic_correct(unit, forward_map[unit.pair_id], len)
            for unit in units
        }
        heuristic_stable = {
            unit.pair_id: heuristic_forward[unit.pair_id]
            and _heuristic_correct(unit, reverse_map[unit.pair_id], len)
            for unit in units
        }
        for task in ("forced", "open"):
            stable = _stable_flags(units, condition_results_by_model[model], task)
            block = _comparison(
                units,
                stable,
                heuristic_stable,
                label_a="exchange_consistent",
                label_b="length_heuristic_characters_both_orders",
                resamples=resamples,
                seed=seed,
            )
            block["heuristic_forward_rate"] = _round(
                _ratio(sum(1 for value in heuristic_forward.values() if value), len(units))
            )
            block["heuristic_exchange_rate"] = _round(
                _ratio(sum(1 for value in heuristic_stable.values() if value), len(units))
            )
            exchange_vs_heuristic[model][task] = block

    # Holm adjustment inside each pre-declared family.
    families: dict[str, list[dict[str, Any]]] = {
        "order_effect": [],
        "task_effect": [],
        "model_effect": [],
        "exchange_model_effect": [],
        "exchange_vs_length": [],
    }
    for model in MODELS:
        for task in ("forced", "open"):
            families["order_effect"].append(model_analyses[model]["order_effects"][task])
            families["exchange_vs_length"].append(exchange_vs_heuristic[model][task])
        for order in ("fwd", "rev"):
            families["task_effect"].append(model_analyses[model]["task_effects"][order])
    for condition in CONDITION_ORDER:
        families["model_effect"].append(cross_model[condition])
    for task in ("forced", "open"):
        families["exchange_model_effect"].append(exchange_model[task])

    holm_families: dict[str, Any] = {}
    for name, tests in families.items():
        p_values = [float(test["mcnemar"]["p_value"]) for test in tests]
        adjusted = holm_adjust(p_values)
        for test, adjusted_p in zip(tests, adjusted):
            test["holm_p"] = adjusted_p
        holm_families[name] = {
            "tests": len(tests),
            "raw_p": p_values,
            "holm_p": adjusted,
        }

    length_tests: dict[str, dict[str, Any]] = {}
    for model in MODELS:
        length_tests[model] = {}
        for condition in CONDITION_ORDER:
            block = model_analyses[model]["conditions"][condition]["length_confound"]
            length_tests[model][condition] = {
                "heuristic_da_all": block["shorter_body_heuristic"]["characters_tie_A"],
                "mcnemar_all": block["mcnemar_model_vs_shorter_characters"],
                "matched": block["matched_subsets"]["0.10"],
            }

    cost: dict[str, Any] = {}
    for model in MODELS:
        new_usage = {
            condition: model_analyses[model]["usage"][condition]
            for condition in ("forced_rev", "open_fwd", "open_rev")
        }
        cost[model] = {
            "new_requests": sum(block["requests"] for block in new_usage.values()),
            "new_prompt_tokens": sum(block["prompt_tokens"] for block in new_usage.values()),
            "new_completion_tokens": sum(block["completion_tokens"] for block in new_usage.values()),
            "new_cost_usd_configured": _round(
                sum(block["cost_usd_configured"] or 0.0 for block in new_usage.values())
            ),
            "new_provider_list_cost_usd": _round(
                sum(block["provider_list_cost_usd"] or 0.0 for block in new_usage.values())
            ),
            "forced_fwd_cost_usd_configured": model_analyses[model]["usage"]["forced_fwd"][
                "cost_usd_configured"
            ],
        }

    comparison = {
        "schema_version": 1,
        "phase": phase,
        "method": "pair_debias",
        "dataset": {
            "path": str(dataset_path.relative_to(ROOT)),
            "sha256": dataset_sha256,
            "pairs": len(units),
        },
        "integrity": integrity,
        "conditions": {
            model: model_analyses[model]["conditions"] for model in MODELS
        },
        "cross_model": cross_model,
        "cross_model_matched": cross_model_matched,
        "matched_length_n": len(matched_units),
        "exchange": {
            model: model_analyses[model]["exchange"] for model in MODELS
        },
        "exchange_model_effect": exchange_model,
        "exchange_vs_heuristic": exchange_vs_heuristic,
        "order_effects": {
            model: model_analyses[model]["order_effects"] for model in MODELS
        },
        "task_effects": {
            model: model_analyses[model]["task_effects"] for model in MODELS
        },
        "open_abstention": {
            model: {
                "fwd": model_analyses[model]["conditions"]["open_fwd"]["abstention"]["rate"],
                "rev": model_analyses[model]["conditions"]["open_rev"]["abstention"]["rate"],
            }
            for model in MODELS
        },
        "abstention_effects": {
            model: model_analyses[model]["abstention_effects"] for model in MODELS
        },
        "length_tests": length_tests,
        "cost": cost,
        "holm": holm_families,
        "warnings": [],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        short = MODELS[model]["short"]
        payload = model_analyses[model]
        (out_dir / f"analysis_{short}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (out_dir / f"analysis_{short}.md").write_text(
            _render_model_markdown(model, payload) + "\n", encoding="utf-8"
        )
    (out_dir / "comparison.json").write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "comparison.md").write_text(
        _render_comparison_markdown(comparison) + "\n", encoding="utf-8"
    )
    (out_dir / "summary.md").write_text(_render_summary(comparison) + "\n", encoding="utf-8")
    export = {
        "schema_version": 1,
        "method": "pair_debias",
        "dataset_sha256": dataset_sha256,
        "dataset_units": len(units),
        "phase": phase,
        "conditions": {
            condition: {
                model: {
                    "n": comparison["conditions"][model][condition]["counts"]["pairs"],
                    "correct": comparison["conditions"][model][condition]["counts"]["categories"]["correct"],
                    "da": comparison["conditions"][model][condition]["accuracy"]["all_pairs"],
                    "exchange_consistent_da": (
                        comparison["exchange"][model]["forced" if condition.startswith("forced") else "open"][
                            "da_both_orders"
                        ]
                    ),
                }
                for model in MODELS
            }
            for condition in CONDITION_ORDER
        },
        "cross_model": {
            condition: {
                "difference_da_deepseek_minus_mimo": cross_model[condition]["difference_all"],
                "mcnemar_p": cross_model[condition]["mcnemar"]["p_value"],
                "holm_p": cross_model[condition].get("holm_p"),
            }
            for condition in CONDITION_ORDER
        },
        "cross_model_matched": {
            condition: {
                "n": comparison["cross_model_matched"][condition]["n_pairs"],
                "difference_da_deepseek_minus_mimo": comparison["cross_model_matched"][condition][
                    "difference_all"
                ],
                "mcnemar_p": comparison["cross_model_matched"][condition]["mcnemar"]["p_value"],
            }
            for condition in CONDITION_ORDER
        },
        "exchange": {
            model: {
                task: {
                    "da_both_orders": comparison["exchange"][model][task]["da_both_orders"],
                    "semantic_agreement_rate": comparison["exchange"][model][task][
                        "semantic_agreement_rate_valid"
                    ],
                    "same_letter_rate": comparison["exchange"][model][task]["same_letter_rate"],
                }
                for task in ("forced", "open")
            }
            for model in MODELS
        },
        "exchange_vs_length": {
            model: {
                task: {
                    "exchange_consistent_da": comparison["exchange_vs_heuristic"][model][task][
                        "rate_a_all"
                    ],
                    "heuristic_da": comparison["exchange_vs_heuristic"][model][task]["rate_b_all"],
                    "heuristic_forward_da": comparison["exchange_vs_heuristic"][model][task][
                        "heuristic_forward_rate"
                    ],
                    "mcnemar_p": comparison["exchange_vs_heuristic"][model][task]["mcnemar"][
                        "p_value"
                    ],
                    "holm_p": comparison["exchange_vs_heuristic"][model][task].get("holm_p"),
                }
                for task in ("forced", "open")
            }
            for model in MODELS
        },
    }
    (out_dir / "benchmark_export.json").write_text(
        json.dumps(export, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return comparison


def _stable_flags(
    units: list[PairUnit], condition_results: dict[str, ConditionResult], task: str
) -> dict[str, bool]:
    forward = condition_results["forced_fwd" if task == "forced" else "open_fwd"]
    reverse = condition_results["forced_rev" if task == "forced" else "open_rev"]
    return {
        unit.pair_id: forward.correct[unit.pair_id] and reverse.correct[unit.pair_id]
        for unit in units
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("pilot", "test"), default="test")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--bootstrap", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out_dir = args.out_dir or (ROOT / "pair_debias" / "results" / ("" if args.phase == "test" else args.phase))
    try:
        comparison = _analyse(args.phase, out_dir, args.bootstrap, args.seed)
    except PairJointError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Analysed {comparison['dataset']['pairs']} pairs; outputs in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
