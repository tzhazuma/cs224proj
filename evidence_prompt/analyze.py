#!/usr/bin/env python3
"""Metrics, evidence audit, and paired tests for the evidence-prompt runs.

This script reads the frozen split, the two baseline ``direct`` runs, and the
two new evidence-prompt runs.  It never writes into the run directories; all
outputs go to ``--out-dir`` (default ``evidence_prompt/analysis``).

Primary paired tests:
  * recall on labelled-vulnerable functions (McNemar exact on paired correctness)
  * false-positive rate on labelled-non-vulnerable functions (same test)
  * Holm adjustment across the four primary tests (2 models x 2 endpoints)

Secondary exploratory views: paired cluster bootstrap for delta F1, delta
macro-F1, delta accuracy, delta strict accuracy, and counterfactual/evidence
audited sensitivity analyses.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from analysis.stats import (  # noqa: E402
    cluster_bootstrap,
    detection_scores,
    holm_adjust,
    mcnemar_exact,
    percentile,
    wilson_interval,
)

DEFAULT_SPLIT = PROJECT_ROOT / "splits" / "test_detection_160.json"
DEFAULT_RUNS = {
    "deepseek": {
        "direct": PROJECT_ROOT / "runner/runs/test_v1_direct_independent",
        "evidence": PROJECT_ROOT / "evidence_prompt/runs/test_evidence_deepseek",
    },
    "mimo": {
        "direct": PROJECT_ROOT / "runner/runs/test_v1_mimo_direct_independent",
        "evidence": PROJECT_ROOT / "evidence_prompt/runs/test_evidence_mimo",
    },
}
DEFAULT_OUT = PROJECT_ROOT / "evidence_prompt" / "analysis"
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 42


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise SystemExit(f"{path}:{line_number}: record is not an object")
            records.append(value)
    return records


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def split_lines(func_body: str) -> tuple[str, ...]:
    return tuple(func_body.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def load_split(path: Path) -> dict[int, dict[str, Any]]:
    data = read_json(path)
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise SystemExit(f"{path}: no samples")
    result: dict[int, dict[str, Any]] = {}
    for sample in samples:
        if not isinstance(sample, dict) or not isinstance(sample.get("idx"), int):
            raise SystemExit(f"{path}: malformed sample")
        idx = sample["idx"]
        if idx in result:
            raise SystemExit(f"{path}: duplicate idx {idx}")
        result[idx] = {
            "idx": idx,
            "label": bool(sample["is_vulnerable"]),
            "project": str(sample.get("project", "")),
            "func_name": str(sample.get("func_name", "")),
            "func_body": str(sample.get("func_body", "")),
            "changed_lines": sample.get("changed_lines") or [],
        }
    return result


def load_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = run_dir / "manifest.json"
    results_path = run_dir / "results.jsonl"
    if not manifest_path.is_file():
        raise SystemExit(f"missing manifest: {manifest_path}")
    if not results_path.is_file():
        raise SystemExit(f"missing results: {results_path}")
    manifest = read_json(manifest_path)
    records = [r for r in read_jsonl(results_path) if r.get("task") == "detection"]
    return manifest, records


def _prediction_map(records: Sequence[dict[str, Any]]) -> dict[int, bool | None]:
    result: dict[int, bool | None] = {}
    for record in records:
        idx = record.get("idx")
        if not isinstance(idx, int):
            raise SystemExit("record has no integer idx")
        if idx in result:
            raise SystemExit(f"duplicate idx {idx} in results")
        parsed = record.get("parsed")
        if (
            record.get("status") == "ok"
            and isinstance(parsed, dict)
            and isinstance(parsed.get("is_vulnerable"), bool)
        ):
            result[idx] = bool(parsed["is_vulnerable"])
        else:
            result[idx] = None
    return result


def validate_run(
    name: str,
    manifest: dict[str, Any],
    records: Sequence[dict[str, Any]],
    split: dict[int, dict[str, Any]],
    expected_sha: str,
) -> None:
    config = manifest.get("config") if isinstance(manifest.get("config"), dict) else {}
    if name == "direct":
        dataset_sha = config.get("dataset_sha256") or manifest.get("dataset", {}).get(
            "sha256"
        )
        if config.get("strategy") != "direct":
            raise SystemExit(f"{name}: expected direct strategy, got {config.get('strategy')!r}")
    else:
        dataset_sha = config.get("dataset_sha256")
        if config.get("strategy") != "evidence":
            raise SystemExit(f"{name}: expected evidence strategy, got {config.get('strategy')!r}")
        if config.get("input_fields") != ["func_body"] or config.get("context_used") is not False:
            raise SystemExit(f"{name}: evidence run does not declare source-only input")
        audit = manifest.get("prompt_audit") or {}
        # The real run manifest stores the audit in the dry-run only; the
        # per-record prompt metadata is checked below.
    if dataset_sha != expected_sha:
        raise SystemExit(
            f"{name}: dataset sha mismatch ({dataset_sha} != {expected_sha})"
        )
    if config.get("partial"):
        raise SystemExit(f"{name}: partial run cannot be used for the frozen comparison")
    if len(records) != len(split):
        raise SystemExit(f"{name}: {len(records)} detection records != {len(split)} units")
    seen: set[int] = set()
    for record in records:
        idx = record["idx"]
        if idx in seen:
            raise SystemExit(f"{name}: duplicate idx {idx}")
        seen.add(idx)
        if idx not in split:
            raise SystemExit(f"{name}: idx {idx} is not in the frozen split")
        if bool(record.get("label")) is not split[idx]["label"]:
            raise SystemExit(f"{name}: label mismatch at idx {idx}")
        prompt = record.get("prompt") or {}
        if name != "direct":
            if prompt.get("only_source_variable") is not True:
                raise SystemExit(f"{name}: prompt not declared source-only at idx {idx}")
            if prompt.get("source_reconstructed") is not True:
                raise SystemExit(f"{name}: source not reconstructed at idx {idx}")
            if prompt.get("input_fields") != ["func_body"]:
                raise SystemExit(f"{name}: prompt input fields are not source-only at idx {idx}")
    if seen != set(split):
        raise SystemExit(f"{name}: missing idx values {sorted(set(split) - seen)[:5]}")


def map_changed_lines(
    sample: dict[str, Any],
) -> tuple[set[int], str, int, int, int | None]:
    """Map file-level changed lines into 1-based function-body lines.

    ``changed_lines`` entries are ``[file_line, source_text]``.  The function
    body is a contiguous slice of the file, so a constant file-line offset
    should exist.  Candidate offsets are voted by exact text matches; the
    winning offset is then used to map every changed statement.  This is an
    evaluation-side audit only and never enters a prompt.
    """
    changed = sample.get("changed_lines") or []
    if not changed:
        return set(), "none", 0, 0, None
    body = [_norm(line) for line in split_lines(sample["func_body"])]
    candidates: list[tuple[int, int]] = []
    for entry in changed:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        file_line, text = entry
        if not isinstance(file_line, int) or not isinstance(text, str):
            continue
        first = _norm(text.split("\n")[0])
        if not first:
            continue
        for position, line in enumerate(body):
            if line == first:
                candidates.append((file_line - position, position))
    if not candidates:
        return set(), "none", 0, len(changed), None
    counts = Counter(offset for offset, _ in candidates)
    offset = max(counts.items(), key=lambda item: (item[1], -abs(item[0])))[0]
    mapped: set[int] = set()
    for entry in changed:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        file_line, text = entry
        if not isinstance(file_line, int) or not isinstance(text, str):
            continue
        position = file_line - offset
        first = _norm(text.split("\n")[0])
        if 0 <= position < len(body) and body[position] == first:
            mapped.add(position + 1)
    quality = "full" if len(mapped) == len(changed) else ("partial" if mapped else "none")
    return mapped, quality, len(mapped), len(changed), offset


def _rate(numerator: float | int | None, denominator: float | int | None) -> float | None:
    if denominator in (None, 0):
        return None
    if numerator is None:
        return None
    return float(numerator) / float(denominator)


def _percentile_summary(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        return {"mean": None, "p50": None, "p95": None, "max": None, "n": 0}
    ordered = sorted(float(value) for value in values)
    return {
        "mean": sum(ordered) / len(ordered),
        "p50": percentile(ordered, 0.5),
        "p95": percentile(ordered, 0.95),
        "max": ordered[-1],
        "n": len(ordered),
    }


def scores_block(
    labels: Sequence[bool], predictions: Sequence[bool | None], indices: Sequence[int]
) -> dict[str, Any]:
    scores = detection_scores(labels, predictions, indices)
    return scores


def cost_latency(
    records: Sequence[dict[str, Any]], manifest: dict[str, Any]
) -> dict[str, Any]:
    costs: list[float] = []
    prompt_tokens: list[int] = []
    completion_tokens: list[int] = []
    cached_tokens: list[int] = []
    latencies: list[float] = []
    for record in records:
        response = record.get("response") or {}
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
        cached = (response.get("cost") or {}).get("cached_prompt_tokens")
        if isinstance(cached, int) and not isinstance(cached, bool):
            cached_tokens.append(cached)
        latency = response.get("request_latency_seconds")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool):
            latencies.append(float(latency))
    total_cost = sum(costs) if costs else None
    tp = sum(
        1
        for record in records
        if record.get("status") == "ok"
        and isinstance(record.get("parsed"), dict)
        and record["parsed"].get("is_vulnerable") is True
        and bool(record.get("label")) is True
    )
    config = manifest.get("config") or {}
    api = manifest.get("api") or {}
    created = manifest.get("created_at")
    completed = manifest.get("completed_at")
    wall = None
    if isinstance(created, str) and isinstance(completed, str):
        try:
            wall = (
                datetime.fromisoformat(completed) - datetime.fromisoformat(created)
            ).total_seconds()
        except ValueError:
            wall = None
    return {
        "requests": len(records),
        "total_cost_usd": total_cost,
        "mean_cost_usd": (total_cost / len(records)) if total_cost is not None and records else None,
        "cost_per_100_units_usd": (total_cost / len(records) * 100)
        if total_cost is not None and records
        else None,
        "cost_per_true_positive_usd": (total_cost / tp) if total_cost is not None and tp else None,
        "true_positives": tp,
        "prompt_tokens_sum": sum(prompt_tokens) if prompt_tokens else None,
        "completion_tokens_sum": sum(completion_tokens) if completion_tokens else None,
        "cached_prompt_tokens_sum": sum(cached_tokens) if cached_tokens else None,
        "mean_prompt_tokens": (sum(prompt_tokens) / len(prompt_tokens))
        if prompt_tokens
        else None,
        "mean_completion_tokens": (sum(completion_tokens) / len(completion_tokens))
        if completion_tokens
        else None,
        "latency_seconds": _percentile_summary(latencies),
        "manifest_wall_seconds": wall,
        "manifest_wall_scope": "detection+repair baseline"
        if config.get("task") == "both"
        else "detection",
        "pricing": {
            "input_usd_per_1m": api.get("input_price_usd_per_1m"),
            "output_usd_per_1m": api.get("output_price_usd_per_1m"),
            "cached_input_usd_per_1m": api.get("cached_input_price_usd_per_1m"),
            "model": api.get("model"),
            "endpoint": api.get("endpoint"),
        },
    }


def prompt_body_audit(
    dryrun_dir: Path, records: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    """Compare real request body hashes with the audited dry-run requests."""
    path = dryrun_dir / "dry_run_requests.jsonl"
    if not path.is_file():
        return None
    dry_hashes: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        dry_hashes[str(record.get("sample_id"))] = str(record.get("body_sha256"))
    real_hashes: dict[str, str] = {}
    for record in records:
        request = record.get("request") or {}
        real_hashes[str(record.get("sample_id"))] = str(request.get("body_sha256"))
    compared = sorted(set(dry_hashes) & set(real_hashes))
    matching = sum(1 for key in compared if dry_hashes[key] == real_hashes[key])
    return {
        "dryrun_dir": str(dryrun_dir),
        "compared": len(compared),
        "matching": matching,
        "all_match": len(compared) == len(records) == matching,
        "missing_in_dryrun": sorted(set(real_hashes) - set(dry_hashes))[:5],
        "missing_in_real": sorted(set(dry_hashes) - set(real_hashes))[:5],
    }


def invalid_label_counts(records: Sequence[dict[str, Any]]) -> dict[str, int]:
    invalid = [record for record in records if record.get("status") != "ok"]
    vulnerable = sum(1 for record in invalid if bool(record.get("label")))
    return {
        "total": len(invalid),
        "vulnerable": vulnerable,
        "non_vulnerable": len(invalid) - vulnerable,
    }


def failure_taxonomy(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(record.get("status")) for record in records)
    families = Counter()
    examples: dict[str, str] = {}
    for record in records:
        if record.get("status") == "ok":
            continue
        validation = record.get("validation") or {}
        family = str(validation.get("error_family") or "unknown")
        families[family] += 1
        examples.setdefault(family, str(validation.get("error", ""))[:240])
    return {
        "by_status": dict(status_counts),
        "invalid_by_family": dict(families),
        "family_examples": examples,
    }


def evidence_audit(
    records: Sequence[dict[str, Any]],
    split: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    valid = [
        record
        for record in records
        if record.get("status") == "ok"
        and isinstance(record.get("parsed"), dict)
        and isinstance(record["parsed"].get("is_vulnerable"), bool)
    ]
    positives = [record for record in valid if record["parsed"]["is_vulnerable"]]
    negatives = [record for record in valid if not record["parsed"]["is_vulnerable"]]
    tp = [record for record in positives if bool(record["label"])]
    fp = [record for record in positives if not bool(record["label"])]

    line_counts = [len(record["parsed"]["evidence_lines"]) for record in positives]
    grounded = [
        bool((record.get("validation") or {}).get("evidence_grounded")) for record in positives
    ]
    confirmed = [
        bool((record.get("validation") or {}).get("counterfactual_confirms"))
        for record in positives
    ]
    blank_records = [
        record
        for record in positives
        if (record.get("validation") or {}).get("blank_evidence_lines")
    ]

    mapping_cache: dict[int, tuple[set[int], str, int, int, int | None]] = {}
    vuln_quality: Counter[str] = Counter()
    vuln_mapped_entries = 0
    vuln_total_entries = 0
    for idx, sample in split.items():
        if not sample["label"]:
            continue
        mapped, quality, mapped_count, total_count, offset = map_changed_lines(sample)
        mapping_cache[idx] = (mapped, quality, mapped_count, total_count, offset)
        vuln_quality[quality] += 1
        vuln_mapped_entries += mapped_count
        vuln_total_entries += total_count

    tp_mapped: list[dict[str, Any]] = []
    chance_exact: list[float] = []
    chance_near3: list[float] = []
    cited_total = 0
    cited_exact_hits = 0
    cited_near3_hits = 0
    changed_total = 0
    changed_exact_hits = 0
    changed_near3_hits = 0
    for record in tp:
        sample = split[record["idx"]]
        mapped, quality, mapped_count, total_count, offset = mapping_cache[record["idx"]]
        cited = set(record["parsed"]["evidence_lines"])
        exact = bool(cited & mapped)
        near1 = any(abs(c - m) <= 1 for c in cited for m in mapped)
        near3 = any(abs(c - m) <= 3 for c in cited for m in mapped)
        near5 = any(abs(c - m) <= 5 for c in cited for m in mapped)
        changed_texts = {
            _norm(entry[1].split("\n")[0])
            for entry in (sample.get("changed_lines") or [])
            if isinstance(entry, (list, tuple)) and len(entry) == 2 and isinstance(entry[1], str)
        }
        line_texts = split_lines(sample["func_body"])
        text_hit = any(
            1 <= line <= len(line_texts) and _norm(line_texts[line - 1]) in changed_texts
            for line in cited
        )
        if quality != "none":
            tp_mapped.append(
                {
                    "idx": record["idx"],
                    "quality": quality,
                    "exact": exact,
                    "near1": near1,
                    "near3": near3,
                    "near5": near5,
                    "text_hit": text_hit,
                    "cited": sorted(cited),
                    "mapped": sorted(mapped),
                    "offset": offset,
                }
            )
            line_count = len(line_texts)
            k = len(cited)
            if k <= line_count:
                # Chance that a uniform random k-subset of the function lines
                # touches at least one mapped fix line (exact / +/-3 window).
                chance_exact.append(
                    1.0 - math.comb(line_count - len(mapped), k) / math.comb(line_count, k)
                )
                window = {
                    line
                    for mapped_line in mapped
                    for line in range(max(1, mapped_line - 3), min(line_count, mapped_line + 3) + 1)
                }
                chance_near3.append(
                    1.0 - math.comb(line_count - len(window), k) / math.comb(line_count, k)
                )
            cited_total += k
            cited_exact_hits += sum(1 for c in cited if c in mapped)
            cited_near3_hits += sum(
                1 for c in cited if any(abs(c - m) <= 3 for m in mapped)
            )
            changed_total += len(mapped)
            changed_exact_hits += sum(1 for m in mapped if m in cited)
            changed_near3_hits += sum(
                1 for m in mapped if any(abs(c - m) <= 3 for c in cited)
            )

    def _rate_for(records_subset: Sequence[dict[str, Any]], key: str) -> float | None:
        if not records_subset:
            return None
        values = [
            bool((record.get("validation") or {}).get(key)) for record in records_subset
        ]
        return sum(values) / len(values)

    mapped_count = len(tp_mapped)
    return {
        "valid_positives": len(positives),
        "valid_negatives": len(negatives),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "evidence_line_count": {
            "mean": (sum(line_counts) / len(line_counts)) if line_counts else None,
            "p50": percentile(line_counts, 0.5) if line_counts else None,
            "p95": percentile(line_counts, 0.95) if line_counts else None,
            "max": max(line_counts) if line_counts else None,
            "total": sum(line_counts),
        },
        "evidence_grounded_rate": (sum(grounded) / len(grounded)) if grounded else None,
        "records_with_blank_evidence": len(blank_records),
        "counterfactual_confirmed_rate": (sum(confirmed) / len(confirmed))
        if confirmed
        else None,
        "counterfactual_unconfirmed": sum(
            1
            for record in positives
            if (record.get("validation") or {}).get("counterfactual_unconfirmed")
        ),
        "tp_evidence_grounded_rate": _rate_for(tp, "evidence_grounded"),
        "fp_evidence_grounded_rate": _rate_for(fp, "evidence_grounded"),
        "tp_counterfactual_confirmed_rate": _rate_for(tp, "counterfactual_confirms"),
        "fp_counterfactual_confirmed_rate": _rate_for(fp, "counterfactual_confirms"),
        "changed_line_mapping": {
            "vulnerable_samples": sum(1 for sample in split.values() if sample["label"]),
            "full": vuln_quality.get("full", 0),
            "partial": vuln_quality.get("partial", 0),
            "none": vuln_quality.get("none", 0),
            "mapped_entries": vuln_mapped_entries,
            "total_entries": vuln_total_entries,
        },
        "tp_with_mapping": mapped_count,
        "tp_exact_hit": sum(1 for item in tp_mapped if item["exact"]),
        "tp_exact_hit_rate": _rate(
            sum(1 for item in tp_mapped if item["exact"]), mapped_count
        ),
        "tp_near1_hit": sum(1 for item in tp_mapped if item["near1"]),
        "tp_near1_hit_rate": _rate(
            sum(1 for item in tp_mapped if item["near1"]), mapped_count
        ),
        "tp_near3_hit": sum(1 for item in tp_mapped if item["near3"]),
        "tp_near3_hit_rate": _rate(
            sum(1 for item in tp_mapped if item["near3"]), mapped_count
        ),
        "tp_near5_hit": sum(1 for item in tp_mapped if item["near5"]),
        "tp_near5_hit_rate": _rate(
            sum(1 for item in tp_mapped if item["near5"]), mapped_count
        ),
        "tp_text_hit": sum(1 for item in tp_mapped if item["text_hit"]),
        "tp_text_hit_rate": _rate(
            sum(1 for item in tp_mapped if item["text_hit"]), mapped_count
        ),
        "tp_exact_chance_mean": (sum(chance_exact) / len(chance_exact))
        if chance_exact
        else None,
        "tp_near3_chance_mean": (sum(chance_near3) / len(chance_near3))
        if chance_near3
        else None,
        "tp_cited_line_precision_exact": _rate(cited_exact_hits, cited_total),
        "tp_cited_line_precision_near3": _rate(cited_near3_hits, cited_total),
        "tp_changed_line_recall_exact": _rate(changed_exact_hits, changed_total),
        "tp_changed_line_recall_near3": _rate(changed_near3_hits, changed_total),
        "tp_cited_lines_total": cited_total,
        "tp_changed_lines_total": changed_total,
    }


def _correctness(prediction: bool | None, label: bool) -> bool:
    return prediction is not None and prediction is label


def mcnemar_compare(
    labels: Sequence[bool],
    a_pred: Sequence[bool | None],
    b_pred: Sequence[bool | None],
    indices: Sequence[int],
) -> dict[str, Any]:
    b = 0
    c = 0
    for index in indices:
        a_correct = _correctness(a_pred[index], labels[index])
        b_correct = _correctness(b_pred[index], labels[index])
        if b_correct and not a_correct:
            b += 1
        elif a_correct and not b_correct:
            c += 1
    result = mcnemar_exact(
        a_correct_b_wrong=c, a_wrong_b_correct=b, total=len(indices)
    )
    result["n"] = len(indices)
    return result


def paired_compare(
    model: str,
    direct_records: Sequence[dict[str, Any]],
    evidence_records: Sequence[dict[str, Any]],
    split: dict[int, dict[str, Any]],
    direct_manifest: dict[str, Any],
    evidence_manifest: dict[str, Any],
) -> dict[str, Any]:
    ids = sorted(split)
    labels = [split[idx]["label"] for idx in ids]
    direct_map = _prediction_map(direct_records)
    evidence_map = _prediction_map(evidence_records)
    missing = [idx for idx in ids if idx not in direct_map or idx not in evidence_map]
    if missing:
        raise SystemExit(f"{model}: missing predictions for {missing[:5]}")
    a_pred = [direct_map[idx] for idx in ids]
    b_pred = [evidence_map[idx] for idx in ids]
    projects = [split[idx]["project"] or "unknown" for idx in ids]

    all_indices = list(range(len(ids)))
    common_indices = [
        index for index in all_indices if a_pred[index] is not None and b_pred[index] is not None
    ]
    common_ids = [ids[index] for index in common_indices]
    common_labels = [labels[index] for index in common_indices]
    common_a = [a_pred[index] for index in common_indices]
    common_b = [b_pred[index] for index in common_indices]
    common_projects = [projects[index] for index in common_indices]

    scores_direct_all = scores_block(labels, a_pred, all_indices)
    scores_evidence_all = scores_block(labels, b_pred, all_indices)
    scores_direct_common = scores_block(labels, a_pred, common_indices)
    scores_evidence_common = scores_block(labels, b_pred, common_indices)

    def score_pair(sel: Sequence[int]) -> tuple[dict[str, Any], dict[str, Any]]:
        return (
            detection_scores(common_labels, common_a, sel),
            detection_scores(common_labels, common_b, sel),
        )

    def delta_metric(name: str) -> Callable[[Sequence[int]], float | None]:
        def f(sel: Sequence[int]) -> float | None:
            a, b = score_pair(sel)
            av = a.get(name)
            bv = b.get(name)
            if av is None or bv is None:
                return None
            return float(bv) - float(av)

        return f

    def delta_fpr(sel: Sequence[int]) -> float | None:
        a, b = score_pair(sel)
        if a.get("specificity") is None or b.get("specificity") is None:
            return None
        return float(a["specificity"]) - float(b["specificity"])

    def delta_strict(sel: Sequence[int]) -> float | None:
        # Use the full 160-unit vectors; unresolved predictions count as wrong.
        local_labels = [labels[index] for index in sel]
        local_a = [a_pred[index] for index in sel]
        local_b = [b_pred[index] for index in sel]
        a = detection_scores(local_labels, local_a)
        b = detection_scores(local_labels, local_b)
        return float(b["strict_accuracy"]) - float(a["strict_accuracy"])

    def delta_coverage(sel: Sequence[int]) -> float | None:
        a = detection_scores(labels, a_pred, sel)
        b = detection_scores(labels, b_pred, sel)
        return float(b["coverage"]) - float(a["coverage"])

    metric_fns: dict[str, Callable[[Sequence[int]], float | None]] = {
        "delta_recall": delta_metric("recall"),
        "delta_fpr": delta_fpr,
        "delta_precision": delta_metric("precision"),
        "delta_positive_f1": delta_metric("positive_f1"),
        "delta_macro_f1": delta_metric("macro_f1"),
        "delta_accuracy": delta_metric("accuracy"),
        "delta_balanced_accuracy": delta_metric("balanced_accuracy"),
        "delta_mcc": delta_metric("mcc"),
    }
    bootstrap_common = cluster_bootstrap(
        common_projects,
        metric_fns,
        resamples=BOOTSTRAP_RESAMPLES,
        seed=BOOTSTRAP_SEED,
    )
    bootstrap_strict = cluster_bootstrap(
        projects,
        {"delta_strict_accuracy": delta_strict, "delta_coverage": delta_coverage},
        resamples=BOOTSTRAP_RESAMPLES,
        seed=BOOTSTRAP_SEED,
    )

    positive_indices = [
        index for index in common_indices if labels[index] is True
    ]
    negative_indices = [
        index for index in common_indices if labels[index] is False
    ]
    mcnemar_overall = mcnemar_compare(labels, a_pred, b_pred, common_indices)
    mcnemar_recall = mcnemar_compare(labels, a_pred, b_pred, positive_indices)
    mcnemar_fpr = mcnemar_compare(labels, a_pred, b_pred, negative_indices)
    mcnemar_strict = mcnemar_compare(labels, a_pred, b_pred, all_indices)

    def point_delta(name: str) -> float | None:
        a = scores_direct_common.get(name)
        b = scores_evidence_common.get(name)
        if a is None or b is None:
            return None
        return float(b) - float(a)

    deltas = {
        "recall": point_delta("recall"),
        "fpr": (float(scores_direct_common["specificity"]) - float(scores_evidence_common["specificity"]))
        if scores_direct_common.get("specificity") is not None
        and scores_evidence_common.get("specificity") is not None
        else None,
        "precision": point_delta("precision"),
        "positive_f1": point_delta("positive_f1"),
        "macro_f1": point_delta("macro_f1"),
        "accuracy": point_delta("accuracy"),
        "balanced_accuracy": point_delta("balanced_accuracy"),
        "mcc": point_delta("mcc"),
        "strict_accuracy": scores_evidence_all["strict_accuracy"]
        - scores_direct_all["strict_accuracy"]
        if scores_direct_all.get("strict_accuracy") is not None
        and scores_evidence_all.get("strict_accuracy") is not None
        else None,
        "coverage": scores_evidence_all["coverage"] - scores_direct_all["coverage"]
        if scores_direct_all.get("coverage") is not None
        and scores_evidence_all.get("coverage") is not None
        else None,
    }

    # Counterfactual-audited sensitivity: a positive counts only when its
    # cited lines are non-blank and the model says the repair removes the
    # defect.  This is a post-hoc view, not the primary endpoint.
    conservative_map: dict[int, bool | None] = {}
    abstain_map: dict[int, bool | None] = {}
    for record in evidence_records:
        idx = record["idx"]
        parsed = record.get("parsed")
        if record.get("status") != "ok" or not isinstance(parsed, dict):
            conservative_map[idx] = None
            abstain_map[idx] = None
            continue
        prediction = bool(parsed["is_vulnerable"])
        audit = record.get("validation") or {}
        supported = bool(audit.get("evidence_grounded")) and bool(
            audit.get("counterfactual_confirms")
        )
        if prediction and not supported:
            conservative_map[idx] = False
            abstain_map[idx] = None
        else:
            conservative_map[idx] = prediction
            abstain_map[idx] = prediction
    conservative_scores = detection_scores(
        labels, [conservative_map[idx] for idx in ids], all_indices
    )
    abstain_scores = detection_scores(labels, [abstain_map[idx] for idx in ids], all_indices)

    return {
        "model": model,
        "n_units": len(ids),
        "n_common_valid": len(common_indices),
        "n_direct_valid": sum(1 for value in a_pred if value is not None),
        "n_evidence_valid": sum(1 for value in b_pred if value is not None),
        "n_direct_valid_evidence_invalid": sum(
            1 for a, b in zip(a_pred, b_pred) if a is not None and b is None
        ),
        "n_direct_invalid_evidence_valid": sum(
            1 for a, b in zip(a_pred, b_pred) if a is None and b is not None
        ),
        "n_both_invalid": sum(1 for a, b in zip(a_pred, b_pred) if a is None and b is None),
        "direct_all": scores_direct_all,
        "evidence_all": scores_evidence_all,
        "direct_common": scores_direct_common,
        "evidence_common": scores_evidence_common,
        "deltas": deltas,
        "mcnemar": {
            "overall_common_valid": mcnemar_overall,
            "recall_positive_subset": mcnemar_recall,
            "fpr_negative_subset": mcnemar_fpr,
            "strict_all_160": mcnemar_strict,
        },
        "bootstrap": {
            "common_valid": bootstrap_common,
            "strict_all_160": bootstrap_strict,
        },
        "sensitivity": {
            "conservative_positive_requires_grounded_and_confirmed": conservative_scores,
            "abstain_unsupported_positive": abstain_scores,
        },
        "cost_latency_direct": cost_latency(direct_records, direct_manifest),
        "cost_latency_evidence": cost_latency(evidence_records, evidence_manifest),
        "failures_direct": failure_taxonomy(direct_records),
        "failures_evidence": failure_taxonomy(evidence_records),
        "invalid_label_counts": {
            "direct": invalid_label_counts(direct_records),
            "evidence": invalid_label_counts(evidence_records),
        },
        "evidence_audit": evidence_audit(evidence_records, split),
        "common_ids": common_ids,
    }


def _fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "—"
        return f"{value:.{digits}f}"
    return str(value)


def _rate_ci(block: dict[str, Any], key: str) -> str:
    wilson = (block.get("wilson") or {}).get(key)
    if not wilson:
        return "—"
    return f"{_fmt(wilson['estimate'])} [{_fmt(wilson['low'])}, {_fmt(wilson['high'])}]"


def _metric_row(name: str, direct: dict[str, Any], evidence: dict[str, Any]) -> str:
    return (
        f"| {name} | {_fmt(direct.get('valid'))}/{direct.get('n')} | "
        f"{_fmt(direct.get('coverage'))} | {_fmt(direct.get('precision'))} | "
        f"{_fmt(direct.get('recall'))} | {_fmt(direct.get('positive_f1'))} | "
        f"{_fmt(direct.get('macro_f1'))} | {_fmt(direct.get('strict_accuracy'))} | "
        f"{_fmt(evidence.get('precision'))} | {_fmt(evidence.get('recall'))} | "
        f"{_fmt(evidence.get('positive_f1'))} | {_fmt(evidence.get('macro_f1'))} | "
        f"{_fmt(evidence.get('strict_accuracy'))} |"
    )


def render_report(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# 证据行 / 反事实提示：SecVulEval 冻结 160 检测测试")
    lines.append("")
    lines.append(f"生成时间（UTC）：`{result['generated_at']}`")
    lines.append("")
    lines.append("## 1. 运行身份与输入隔离")
    lines.append("")
    lines.append(
        "| 模型 | 新证据提示 run | 直接提示基线 run | 模型输入 | 请求数 | 数据集 SHA-256 |"
    )
    lines.append("| --- | --- | --- | --- | ---: | --- |")
    for model, item in result["models"].items():
        lines.append(
            f"| {model} | `{item['evidence_run']}` | `{item['direct_run']}` | "
            f"仅 `func_body`（带行号） | {item['comparison']['n_units']} | "
            f"`{result['dataset']['sha256'][:16]}…` |"
        )
    lines.append("")
    lines.append(
        "两个新 run 都只把函数源码放进 `FUNCTION_SOURCE`，不含 `context`、标签、"
        "`changed_lines`、CVE/CWE、项目/文件路径、commit 信息、修复函数或 `fixed_func_idx`。"
        "逐样本的 `only_source_variable` 与 `source_reconstructed` 在分析前被强制校验。"
    )
    lines.append("")
    audits = []
    for model, item in result["models"].items():
        audit = item.get("prompt_body_audit")
        if audit:
            audits.append(
                f"{model} {audit['matching']}/{audit['compared']}"
                + ("（全部一致）" if audit.get("all_match") else "（存在不一致）")
            )
    if audits:
        lines.append(
            "请求体审计：" + "；".join(audits) + " 的 `body_sha256` 与 dry-run 请求逐条比对。"
        )
        lines.append("")
    lines.append("### 关键结果（先看这里）")
    lines.append("")
    for model, item in result["models"].items():
        comp = item["comparison"]
        primary = item["primary_tests"]
        lines.append(
            f"- **{model}**（共同 valid）：recall "
            f"{_fmt(comp['direct_common']['recall'])} → "
            f"{_fmt(comp['evidence_common']['recall'])}（Δ {_fmt(comp['deltas']['recall'])}，"
            f"Holm p={_fmt(primary['recall']['holm_adjusted_p'])}）；FPR "
            f"{_fmt(1 - comp['direct_common']['specificity'])} → "
            f"{_fmt(1 - comp['evidence_common']['specificity'])}（Δ "
            f"{_fmt(comp['deltas']['fpr'])}，Holm p={_fmt(primary['fpr']['holm_adjusted_p'])}）；"
            f"strict acc（全 160）{_fmt(comp['direct_all']['strict_accuracy'])} → "
            f"{_fmt(comp['evidence_all']['strict_accuracy'])}。"
        )
    lines.append("")
    lines.append(
        "结论先行：两个模型的召回都显著提高（Holm 校正后仍显著），但假阳性点估计也上升；"
        "FPR 的配对检验不显著，主要受 32 个非漏洞样本的限制。因此**不能声称“提高召回而不增加假阳性”已经实现**。"
    )
    lines.append("")
    lines.append("## 2. 主要检测指标")
    lines.append("")
    lines.append(
        "分母：每个模型 160 个冻结测试函数（128 漏洞 / 32 非漏洞）。"
        "`valid` 是 schema-valid 且成功返回的预测；`strict` 把所有 invalid/API error 算错。"
    )
    lines.append("")
    lines.append(
        "| 模型/提示 | valid | coverage | P | R | F1+ | macro-F1 | strict acc |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        for name, block in (
            ("direct", comp["direct_all"]),
            ("evidence", comp["evidence_all"]),
        ):
            lines.append(
                f"| {model} / {name} | {_fmt(block.get('valid'))}/{block.get('n')} | "
                f"{_fmt(block.get('coverage'))} | {_fmt(block.get('precision'))} | "
                f"{_fmt(block.get('recall'))} | {_fmt(block.get('positive_f1'))} | "
                f"{_fmt(block.get('macro_f1'))} | {_fmt(block.get('strict_accuracy'))} |"
            )
    lines.append("")
    lines.append("召回率与 FPR 的 Wilson 95% 区间（valid-only）：")
    lines.append("")
    lines.append("| 模型/提示 | recall [95% CI] | FPR [95% CI] |")
    lines.append("| --- | --- | --- |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        for name, block in (
            ("direct", comp["direct_all"]),
            ("evidence", comp["evidence_all"]),
        ):
            fpr_ci = "—"
            if block.get("wilson", {}).get("specificity"):
                spec = block["wilson"]["specificity"]
                fpr_ci = (
                    f"{_fmt(1 - spec['estimate'])} "
                    f"[{_fmt(1 - spec['high'])}, {_fmt(1 - spec['low'])}]"
                )
            lines.append(
                f"| {model} / {name} | {_rate_ci(block, 'recall')} | {fpr_ci} |"
            )
    lines.append("")
    lines.append("## 3. 与原 direct 的逐样本配对检验")
    lines.append("")
    lines.append(
        "主检验：在共同 valid 的样本上，用精确 McNemar 检验配对正确性；"
        "召回检验只用漏洞样本，FPR 检验只用非漏洞样本。"
        "四个主检验做 Holm 校正（2 模型 × 2 终点）。"
        "共同 valid 与子集规模："
        + "；".join(
            f"{model} 共同 {item['comparison']['n_common_valid']}，"
            f"召回 n={item['comparison']['mcnemar']['recall_positive_subset']['n']}，"
            f"FPR n={item['comparison']['mcnemar']['fpr_negative_subset']['n']}"
            for model, item in result["models"].items()
        )
        + "（invalid 记录被排除）。"
    )
    lines.append("")
    lines.append(
        "| 模型 | n 共同 valid | Δrecall | 召回 McNemar p | Holm p | ΔFPR | FPR McNemar p | Holm p |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        primary = item["primary_tests"]
        lines.append(
            f"| {model} | {comp['n_common_valid']} | {_fmt(comp['deltas']['recall'])} | "
            f"{_fmt(primary['recall']['p_value'])} | {_fmt(primary['recall']['holm_adjusted_p'])} | "
            f"{_fmt(comp['deltas']['fpr'])} | {_fmt(primary['fpr']['p_value'])} | "
            f"{_fmt(primary['fpr']['holm_adjusted_p'])} |"
        )
    lines.append("")
    lines.append("")
    lines.append("配对 discordant 计数（evidence 相对 direct）：")
    lines.append("")
    lines.append("| 模型 | 召回 新增 TP / 丢失 TP | FPR 新增 FP / 修复 FP |")
    lines.append("| --- | ---: | ---: |")
    for model, item in result["models"].items():
        m = item["comparison"]["mcnemar"]
        recall = m["recall_positive_subset"]
        fpr = m["fpr_negative_subset"]
        lines.append(
            f"| {model} | +{recall['a_wrong_b_correct']} / −{recall['a_correct_b_wrong']} | "
            f"+{fpr['a_correct_b_wrong']} / −{fpr['a_wrong_b_correct']} |"
        )
    lines.append("")
    lines.append(
        "两个模型都是“新增 TP 远多于丢失 TP”，但新增 FP 没有任何修复；"
        "这正是召回上升、FPR 也上升的来源。"
    )
    lines.append("")
    lines.append("配对 cluster bootstrap（10,000 次，seed 42，按项目聚类；95% 百分位区间）：")
    lines.append("")
    lines.append("| 模型 | Δrecall [95% CI] | ΔFPR [95% CI] | ΔF1+ [95% CI] | Δmacro-F1 [95% CI] |")
    lines.append("| --- | --- | --- | --- | --- |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        boot = comp["bootstrap"]["common_valid"]["metrics"]

        def ci(name: str) -> str:
            value = boot.get(name) or {}
            if value.get("ci_low") is None:
                return "—"
            return f"{_fmt(value['ci_low'])} … {_fmt(value['ci_high'])}"

        lines.append(
            f"| {model} | {ci('delta_recall')} | {ci('delta_fpr')} | "
            f"{ci('delta_positive_f1')} | {ci('delta_macro_f1')} |"
        )
    lines.append("")
    lines.append("严格口径（160 个记录，invalid/error 算错）的配对检验：")
    lines.append("")
    lines.append("| 模型 | direct strict acc | evidence strict acc | Δstrict | McNemar p | Δcoverage |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        lines.append(
            f"| {model} | {_fmt(comp['direct_all']['strict_accuracy'])} | "
            f"{_fmt(comp['evidence_all']['strict_accuracy'])} | "
            f"{_fmt(comp['deltas']['strict_accuracy'])} | "
            f"{_fmt(comp['mcnemar']['strict_all_160']['p_value'])} | "
            f"{_fmt(comp['deltas']['coverage'])} |"
        )
    lines.append("")
    lines.append("严格口径的构成（strict 把 invalid 算错，因此混入格式合规差异）：")
    lines.append("")
    lines.append(
        "| 模型 | direct invalid (V/N) | evidence invalid (V/N) | 共同 valid Δaccuracy | strict Δaccuracy |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        di = comp["invalid_label_counts"]["direct"]
        ei = comp["invalid_label_counts"]["evidence"]
        lines.append(
            f"| {model} | {di['total']} ({di['vulnerable']}/{di['non_vulnerable']}) | "
            f"{ei['total']} ({ei['vulnerable']}/{ei['non_vulnerable']}) | "
            f"{_fmt(comp['deltas']['accuracy'])} | {_fmt(comp['deltas']['strict_accuracy'])} |"
        )
    lines.append("")
    lines.append(
        "MiMo 的 strict 提升大于共同 valid 的 accuracy 提升，部分来自 schema 合规："
        "direct 的 10 条 invalid 中有 8 条漏洞样本和 2 条非漏洞样本，evidence 只有 2 条 invalid。"
        "因此 MiMo 的 strict 数字不能全部解释为检测能力提升。"
    )
    lines.append("")
    lines.append("### 操作点偏移与判别力")
    lines.append("")
    for model, item in result["models"].items():
        comp = item["comparison"]
        direct_block = comp["direct_common"]
        evidence_block = comp["evidence_common"]
        direct_rate = direct_block.get("predicted_positive_rate")
        evidence_rate = evidence_block.get("predicted_positive_rate")
        lines.append(
            f"- {model}（共同 valid）：predicted positive rate "
            f"{_fmt(direct_rate)} → {_fmt(evidence_rate)}；"
            f"Δbalanced accuracy {_fmt(comp['deltas']['balanced_accuracy'])}；"
            f"ΔMCC {_fmt(comp['deltas']['mcc'])}。"
        )
    lines.append("")
    lines.append(
        "证据提示明显提高了“报正例”的比例；balanced accuracy 和 MCC 在共同 valid 上"
        "没有提升（DeepSeek 基本持平，MiMo 略降）。因此召回/F1 的上升主要来自操作点向"
        "“多报”移动，而不是判别力提升。"
    )
    lines.append("")
    lines.append("## 4. 证据行可审计性")
    lines.append("")
    lines.append(
        "证据行按提示中打印的 1-based 行号审计。`grounded` 表示所引行都不是空行。"
        "漏洞样本的 `changed_lines` 被映射回函数体行号（文件级行号减去函数起始偏移）；"
        "映射只用于评估，不进入提示。`随机基线` 是：在同一个函数里随机抽同样多的行，"
        "至少碰到一个修复行的期望概率（按超几何分布计算，再对 TP 取平均）。"
    )
    lines.append("")
    lines.append(
        "| 模型 | valid 正例 | 平均引用行数 | grounded | 反事实确认 | TP | TP 映射样本 | exact hit | ±3 hit | 文本命中 |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        audit = item["comparison"]["evidence_audit"]
        lines.append(
            f"| {model} | {audit['valid_positives']} | "
            f"{_fmt(audit['evidence_line_count']['mean'])} | "
            f"{_fmt(audit['evidence_grounded_rate'])} | "
            f"{_fmt(audit['counterfactual_confirmed_rate'])} | "
            f"{audit['true_positives']} | {audit['tp_with_mapping']} | "
            f"{_fmt(audit['tp_exact_hit_rate'])} | {_fmt(audit['tp_near3_hit_rate'])} | "
            f"{_fmt(audit['tp_text_hit_rate'])} |"
        )
    lines.append("")
    lines.append(
        "与随机引用基线对比（仅 TP 且 `changed_lines` 可映射的样本）："
    )
    lines.append("")
    lines.append(
        "| 模型 | exact hit | exact 随机基线 | ±3 hit | ±3 随机基线 | 引用行精确率 | 引用行 ±3 精确率 | 修复行 exact 召回 | 修复行 ±3 召回 |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        audit = item["comparison"]["evidence_audit"]
        lines.append(
            f"| {model} | {_fmt(audit['tp_exact_hit_rate'])} | "
            f"{_fmt(audit['tp_exact_chance_mean'])} | {_fmt(audit['tp_near3_hit_rate'])} | "
            f"{_fmt(audit['tp_near3_chance_mean'])} | "
            f"{_fmt(audit['tp_cited_line_precision_exact'])} | "
            f"{_fmt(audit['tp_cited_line_precision_near3'])} | "
            f"{_fmt(audit['tp_changed_line_recall_exact'])} | "
            f"{_fmt(audit['tp_changed_line_recall_near3'])} |"
        )
    lines.append("")
    lines.append(
        "映射质量（全部 128 个漏洞样本）："
    )
    lines.append("")
    for model, item in result["models"].items():
        mapping = item["comparison"]["evidence_audit"]["changed_line_mapping"]
        lines.append(
            f"- {model}: full={mapping['full']}, partial={mapping['partial']}, "
            f"none={mapping['none']}, 修复行条目 {mapping['mapped_entries']}/"
            f"{mapping['total_entries']} 可映射。"
        )
    lines.append("")
    lines.append("真阳性与假阳性的证据质量对比：")
    lines.append("")
    lines.append("| 模型 | TP grounded | FP grounded | TP counterfactual | FP counterfactual |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        audit = item["comparison"]["evidence_audit"]
        lines.append(
            f"| {model} | {_fmt(audit['tp_evidence_grounded_rate'])} | "
            f"{_fmt(audit['fp_evidence_grounded_rate'])} | "
            f"{_fmt(audit['tp_counterfactual_confirmed_rate'])} | "
            f"{_fmt(audit['fp_counterfactual_confirmed_rate'])} |"
        )
    lines.append("")
    lines.append("事后敏感性分析（不是主终点）：把“未 grounded 或反事实未确认”的正例改判为负例，"
                 "或直接视为 abstain（invalid），重新计算指标：")
    lines.append("")
    lines.append("| 模型 | 策略 | valid | P | R | F1+ | strict acc |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        comp = item["comparison"]
        for label, block in (
            ("conservative", comp["sensitivity"]["conservative_positive_requires_grounded_and_confirmed"]),
            ("abstain", comp["sensitivity"]["abstain_unsupported_positive"]),
        ):
            lines.append(
                f"| {model} | {label} | {_fmt(block.get('valid'))}/{block.get('n')} | "
                f"{_fmt(block.get('precision'))} | {_fmt(block.get('recall'))} | "
                f"{_fmt(block.get('positive_f1'))} | {_fmt(block.get('strict_accuracy'))} |"
            )
    lines.append("")
    lines.append("## 5. 成本与延迟")
    lines.append("")
    lines.append(
        "成本按原 baseline 的价格配置计算（DeepSeek 0.30/1.20/0.006，MiMo 0.14/0.28/0.0028 USD/1M）。"
        "直接基线的 run 同时包含 detection+repair，因此其总成本/总 wall 不可与新 run 直接相加比较；"
        "这里只比较 detection 记录的逐请求成本与延迟。"
    )
    lines.append("")
    lines.append(
        "| 模型/提示 | 总 USD | 每 100 单元 USD | 每 TP USD | prompt tokens 均值 | completion tokens 均值 | 延迟 p50 s | 延迟 p95 s |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model, item in result["models"].items():
        for name, cost in (
            ("direct", item["comparison"]["cost_latency_direct"]),
            ("evidence", item["comparison"]["cost_latency_evidence"]),
        ):
            latency = cost.get("latency_seconds") or {}
            lines.append(
                f"| {model} / {name} | {_fmt(cost.get('total_cost_usd'), 6)} | "
                f"{_fmt(cost.get('cost_per_100_units_usd'), 6)} | "
                f"{_fmt(cost.get('cost_per_true_positive_usd'), 6)} | "
                f"{_fmt(cost.get('mean_prompt_tokens'), 1)} | "
                f"{_fmt(cost.get('mean_completion_tokens'), 1)} | "
                f"{_fmt(latency.get('p50'), 2)} | {_fmt(latency.get('p95'), 2)} |"
            )
    lines.append("")
    lines.append("## 6. 失败分类")
    lines.append("")
    lines.append("| 模型/提示 | ok | invalid | API error | invalid 家族 |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for model, item in result["models"].items():
        for name, failures in (
            ("direct", item["comparison"]["failures_direct"]),
            ("evidence", item["comparison"]["failures_evidence"]),
        ):
            status = failures["by_status"]
            lines.append(
                f"| {model} / {name} | {status.get('ok', 0)} | {status.get('invalid', 0)} | "
                f"{status.get('error', 0)} | `{failures['invalid_by_family']}` |"
            )
    lines.append("")
    lines.append(
        "MiMo direct 的 10 条 invalid 都是把 `is_vulnerable` 写成 `is_vulnerability`；"
        "旧 runner 没有 `error_family` 字段，因此表中显示为 `unknown`。"
    )
    lines.append("")
    lines.append("## 7. 结论与限制")
    lines.append("")
    lines.append(
        "- 这是**单模型、单次运行**；temperature=0 不保证确定性。所有 p 值和区间只描述这 160 个冻结样本。"
    )
    lines.append(
        "- 主终点是 recall 与 FPR 的配对 McNemar；Holm 只覆盖四个主检验。F1/macro-F1 的 bootstrap 区间是探索性的。"
    )
    lines.append(
        "- 非漏洞样本只有 32 个，FPR 的区间很宽；不能据此声称稳定的假阳性率。"
    )
    lines.append(
        "- `changed_lines` 到函数体行号的映射不是 100% 完整；exact/±3 hit 只在可映射的 TP 上计算，分母已列出。"
    )
    lines.append(
        "- 证据行是模型自报，不是执行证明；反事实修复没有编译或测试，只是模型自检。"
    )
    lines.append(
        "- 操作点分析：证据提示的 predicted positive rate 明显上升（共同 valid：DeepSeek "
        "28.3%→37.7%，MiMo 23.7%→35.1%）；Δbalanced accuracy 为 +0.0004 / −0.0143，"
        "ΔMCC 为 −0.0020 / −0.0276。召回/F1 的上升主要来自操作点向“多报”移动，"
        "而不是判别力提升。"
    )
    lines.append(
        "- 结构审计通过不等于定位正确：引用行全部在范围内且非空，但与 `changed_lines` 的 ±3 重合率"
        "接近同样引用行数下的随机基线；精确重合略高于随机基线。不能把证据行当作可靠的漏洞定位。"
    )
    lines.append(
        "- 反事实确认率在 TP 和 FP 上都接近 1，未表现出区分真伪正例的能力；它不能替代独立验证。"
    )
    lines.append(
        "- 两个模型的结果不可直接横比：DeepSeek 为 non-thinking，MiMo 在该端点上需要 `reasoning_effort=none` 才关闭推理；"
        "模型、价格和延迟口径不同。"
    )
    lines.append(
        "- 直接基线 run 还包含 repair 请求；本报告只取其中的 detection 记录，未改写任何旧结果。"
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, default=DEFAULT_SPLIT)
    parser.add_argument("--direct-deepseek", type=Path, default=DEFAULT_RUNS["deepseek"]["direct"])
    parser.add_argument(
        "--evidence-deepseek", type=Path, default=DEFAULT_RUNS["deepseek"]["evidence"]
    )
    parser.add_argument("--direct-mimo", type=Path, default=DEFAULT_RUNS["mimo"]["direct"])
    parser.add_argument("--evidence-mimo", type=Path, default=DEFAULT_RUNS["mimo"]["evidence"])
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    split = load_split(args.split)
    split_sha = sha256_file(args.split)
    labels = [split[idx]["label"] for idx in sorted(split)]

    runs = {
        "deepseek": {"direct": args.direct_deepseek, "evidence": args.evidence_deepseek},
        "mimo": {"direct": args.direct_mimo, "evidence": args.evidence_mimo},
    }
    loaded: dict[str, dict[str, Any]] = {}
    for model, item in runs.items():
        direct_manifest, direct_records = load_run(item["direct"])
        evidence_manifest, evidence_records = load_run(item["evidence"])
        validate_run("direct", direct_manifest, direct_records, split, split_sha)
        validate_run("evidence", evidence_manifest, evidence_records, split, split_sha)
        loaded[model] = {
            "direct_manifest": direct_manifest,
            "direct_records": direct_records,
            "evidence_manifest": evidence_manifest,
            "evidence_records": evidence_records,
        }

    comparisons: dict[str, Any] = {}
    for model, item in loaded.items():
        comparisons[model] = paired_compare(
            model,
            item["direct_records"],
            item["evidence_records"],
            split,
            item["direct_manifest"],
            item["evidence_manifest"],
        )

    # Holm over the four pre-specified primary tests.
    primary_order = [
        ("deepseek", "recall"),
        ("deepseek", "fpr"),
        ("mimo", "recall"),
        ("mimo", "fpr"),
    ]
    p_values = [
        comparisons[model]["mcnemar"][
            "recall_positive_subset" if metric == "recall" else "fpr_negative_subset"
        ]["p_value"]
        for model, metric in primary_order
    ]
    adjusted = holm_adjust(p_values)
    primary_tests: dict[str, dict[str, dict[str, Any]]] = {}
    for (model, metric), raw, adj in zip(primary_order, p_values, adjusted):
        key = "recall_positive_subset" if metric == "recall" else "fpr_negative_subset"
        block = dict(comparisons[model]["mcnemar"][key])
        block["holm_adjusted_p"] = adj
        primary_tests.setdefault(model, {})[metric] = block

    result: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "dataset": {
            "path": str(args.split),
            "sha256": split_sha,
            "units": len(split),
            "label_counts": {
                "vulnerable": sum(1 for value in labels if value),
                "non_vulnerable": sum(1 for value in labels if not value),
            },
            "split_id": "secvul-split-v1",
        },
        "models": {},
        "holm_family": {
            "tests": [
                f"{model}:{metric}" for model, metric in primary_order
            ],
            "raw_p_values": p_values,
            "holm_adjusted_p_values": adjusted,
        },
    }
    for model, item in loaded.items():
        comp = comparisons[model]
        item["primary_tests"] = primary_tests[model]
        result["models"][model] = {
            "direct_run": str(runs[model]["direct"]),
            "evidence_run": str(runs[model]["evidence"]),
            "direct_manifest": {
                "model": (item["direct_manifest"].get("api") or {}).get("model"),
                "prompt_version": (item["direct_manifest"].get("config") or {}).get(
                    "prompt_version"
                ),
                "task": (item["direct_manifest"].get("config") or {}).get("task"),
                "total_requests": (item["direct_manifest"].get("counts") or {}).get(
                    "recorded_requests"
                ),
            },
            "evidence_manifest": {
                "model": (item["evidence_manifest"].get("api") or {}).get("model"),
                "prompt_version": (item["evidence_manifest"].get("config") or {}).get(
                    "prompt_version"
                ),
                "task": (item["evidence_manifest"].get("config") or {}).get("task"),
                "total_requests": (item["evidence_manifest"].get("counts") or {}).get(
                    "recorded_requests"
                ),
            },
            "prompt_body_audit": prompt_body_audit(
                runs[model]["evidence"].parent / f"dryrun_evidence_{model}",
                item["evidence_records"],
            ),
            "comparison": comp,
            "primary_tests": item["primary_tests"],
        }

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    comparison_only = {
        "generated_at": result["generated_at"],
        "dataset": result["dataset"],
        "models": {
            model: {
                "direct_run": item["direct_run"],
                "evidence_run": item["evidence_run"],
                "comparison": item["comparison"],
                "primary_tests": item["primary_tests"],
            }
            for model, item in result["models"].items()
        },
        "holm_family": result["holm_family"],
    }
    (out / "comparison.json").write_text(
        json.dumps(comparison_only, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "report.md").write_text(render_report(result), encoding="utf-8")
    print(f"wrote {out / 'metrics.json'}")
    print(f"wrote {out / 'comparison.json'}")
    print(f"wrote {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
