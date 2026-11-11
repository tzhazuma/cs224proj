from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional


DECISIVE = {"leak", "clean"}


def wilson_ci(k: int, n: int, z: float = 1.96) -> Optional[list[float]]:
    if n <= 0:
        return None
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    margin = z * math.sqrt((p * (1.0 - p) / n) + (z * z / (4.0 * n * n))) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def confusion(cases: Iterable[dict[str, Any]], predicate) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    labeled = 0
    decisive = 0
    for case in cases:
        label = case.get("expected_label")
        if label not in (0, 1):
            continue
        labeled += 1
        prediction = predicate(case)
        if prediction not in (0, 1):
            continue
        decisive += 1
        if label == 1 and prediction == 1:
            tp += 1
        elif label == 0 and prediction == 1:
            fp += 1
        elif label == 0 and prediction == 0:
            tn += 1
        elif label == 1 and prediction == 0:
            fn += 1
    metrics = metric_block(tp, fp, tn, fn)
    metrics.update({"n_labeled": labeled, "n_decisive": decisive})
    return metrics


def metric_block(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    specificity = tn / (tn + fp) if (tn + fp) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    accuracy = (tp + tn) / n if n else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2.0 * precision * recall / (precision + recall)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n": n,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "fpr": fpr,
        "accuracy": accuracy,
        "f1": f1,
        "recall_ci95": wilson_ci(tp, tp + fn),
        "fpr_ci95": wilson_ci(fp, fp + tn),
    }


def _outcome_prediction(case: dict[str, Any]) -> Optional[int]:
    outcome = case.get("outcome")
    if outcome == "leak":
        return 1
    if outcome == "clean":
        return 0
    return None


def _detector_counts(cases: list[dict[str, Any]], name: str) -> dict[str, Any]:
    counts = Counter()
    for case in cases:
        detector = (case.get("detectors") or {}).get(name) or {}
        status = detector.get("status") or "missing"
        counts[status] += 1
        build = detector.get("build") or {}
        if build and not build.get("ok"):
            counts["build_failed"] += 1
        if detector.get("available") is False:
            counts["not_available"] += 1
    return dict(sorted(counts.items()))


def _group(cases: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        groups[str(case.get(key) or "unknown")].append(case)
    result: dict[str, dict[str, Any]] = {}
    for name, rows in sorted(groups.items()):
        block = confusion(rows, _outcome_prediction)
        block["n_cases"] = len(rows)
        block["n_inconclusive"] = sum(
            1 for row in rows if row.get("outcome") not in DECISIVE
        )
        result[name] = block
    return result


def compute_metrics(
    cases: list[dict[str, Any]],
    *,
    run_id: str,
    toolchain: dict[str, Any],
    config: dict[str, Any],
    generated_at_utc: str,
) -> dict[str, Any]:
    outcome_counts = Counter(str(case.get("outcome") or "unknown") for case in cases)
    label_counts = Counter(
        str(case.get("expected_label")) if case.get("expected_label") in (0, 1) else "unlabeled"
        for case in cases
    )
    failure_counts = Counter(
        str(case.get("failure_class"))
        for case in cases
        if case.get("failure_class")
    )
    runtime_counts = Counter(str(case.get("runtime_class") or "unknown") for case in cases)
    labeled = sum(1 for case in cases if case.get("expected_label") in (0, 1))
    decisive = sum(1 for case in cases if case.get("outcome") in DECISIVE)
    combined = confusion(cases, _outcome_prediction)
    detectors: dict[str, Any] = {}
    for name in ("asan", "valgrind"):
        block = confusion(
            cases,
            (lambda row, detector_name=name: _detector_prediction_value(row, detector_name)),
        )
        block["status_counts"] = _detector_counts(cases, name)
        block["n_cases"] = len(cases)
        detectors[name] = block

    metrics: dict[str, Any] = {
        "schema_version": "dynamic-cwe401/1.0",
        "kind": "traditional_dynamic_cwe401_metrics",
        "generated_at_utc": generated_at_utc,
        "run_id": run_id,
        "label_convention": {
            "positive": "vulnerable / memory leak",
            "negative": "non-vulnerable / no detected leak",
            "matrix_order": "[[TN, FP], [FN, TP]]",
            "matrix_rows": ["actual non-vulnerable", "actual vulnerable"],
            "matrix_columns": ["predicted non-vulnerable", "predicted vulnerable"],
        },
        "metrics_definitions": {
            "recall": "TP / (TP + FN)",
            "fpr": "FP / (FP + TN)",
            "precision": "TP / (TP + FP)",
            "specificity": "TN / (TN + FP)",
            "accuracy": "(TP + TN) / N",
            "f1": "2 * precision * recall / (precision + recall)",
            "inconclusive": "not counted in TP/FP/TN/FN; reported separately",
        },
        "counts": {
            "n_cases": len(cases),
            "n_labeled": labeled,
            "n_decisive": decisive,
            "n_inconclusive": sum(
                1 for case in cases if case.get("outcome") not in DECISIVE
            ),
            "outcomes": dict(sorted(outcome_counts.items())),
            "labels": dict(sorted(label_counts.items())),
            "runtime_classes": dict(sorted(runtime_counts.items())),
        },
        "combined": combined,
        "detectors": detectors,
        "breakdowns": {
            "by_language": _group(cases, "language"),
            "by_origin": _group(cases, "origin"),
            "by_variant": _group(cases, "variant"),
            "by_feature": _group(cases, "feature"),
        },
        "failure_classes": dict(sorted(failure_counts.items())),
        "toolchain": toolchain,
        "config": config,
    }
    return metrics


def _detector_prediction_value(case: dict[str, Any], name: str):
    detector = (case.get("detectors") or {}).get(name) or {}
    status = detector.get("status")
    if status == "leak":
        return 1
    if status == "clean":
        return 0
    return None


def _fmt(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _ci(value: Any) -> str:
    if not value:
        return "null"
    return f"[{value[0]:.3f}, {value[1]:.3f}]"


def render_markdown(metrics: dict[str, Any]) -> str:
    counts = metrics["counts"]
    lines: list[str] = []
    lines.append("# Dynamic CWE-401 evaluation metrics")
    lines.append("")
    lines.append(f"- Run ID: `{metrics['run_id']}`")
    lines.append(f"- Generated (UTC): `{metrics['generated_at_utc']}`")
    lines.append(f"- Cases: {counts['n_cases']} (labeled: {counts['n_labeled']})")
    lines.append(f"- Decisive / inconclusive: {counts['n_decisive']} / {counts['n_inconclusive']}")
    lines.append("")
    lines.append("## Outcomes")
    lines.append("")
    lines.append("| outcome | count |")
    lines.append("|---|---:|")
    for name, value in counts["outcomes"].items():
        lines.append(f"| {name} | {value} |")
    lines.append("")
    lines.append("## Combined detector (leak if any detector reports a leak)")
    lines.append("")
    lines.append("| TP | FP | TN | FN | precision | recall | FPR | specificity | F1 | accuracy |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    c = metrics["combined"]
    lines.append(
        "| {tp} | {fp} | {tn} | {fn} | {p} | {r} | {fpr} | {spec} | {f1} | {acc} |".format(
            tp=c["tp"],
            fp=c["fp"],
            tn=c["tn"],
            fn=c["fn"],
            p=_fmt(c["precision"]),
            r=_fmt(c["recall"]),
            fpr=_fmt(c["fpr"]),
            spec=_fmt(c["specificity"]),
            f1=_fmt(c["f1"]),
            acc=_fmt(c["accuracy"]),
        )
    )
    lines.append(
        f"\nRecall 95% Wilson CI: {_ci(c['recall_ci95'])}; "
        f"FPR 95% Wilson CI: {_ci(c['fpr_ci95'])}"
    )
    lines.append("")
    lines.append("## Per-detector results")
    lines.append("")
    lines.append("| detector | decisive | TP | FP | TN | FN | precision | recall | FPR | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name in ("asan", "valgrind"):
        d = metrics["detectors"][name]
        lines.append(
            f"| {name} | {d['n_decisive']} | {d['tp']} | {d['fp']} | {d['tn']} | {d['fn']} | "
            f"{_fmt(d['precision'])} | {_fmt(d['recall'])} | {_fmt(d['fpr'])} | {_fmt(d['f1'])} |"
        )
    lines.append("")
    lines.append("## Failure classes")
    lines.append("")
    lines.append("| class | count |")
    lines.append("|---|---:|")
    for name, value in metrics["failure_classes"].items():
        lines.append(f"| {name} | {value} |")
    if not metrics["failure_classes"]:
        lines.append("| (none) | 0 |")
    lines.append("")
    lines.append("## Breakdown by language")
    lines.append("")
    lines.append("| language | cases | labeled | decisive | TP | FP | TN | FN | recall | FPR |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, block in metrics["breakdowns"]["by_language"].items():
        lines.append(
            f"| {name} | {block['n_cases']} | {block['n_labeled']} | {block['n_decisive']} | "
            f"{block['tp']} | {block['fp']} | {block['tn']} | {block['fn']} | "
            f"{_fmt(block['recall'])} | {_fmt(block['fpr'])} |"
        )
    lines.append("")
    lines.append("## Breakdown by feature (top 20 by cases)")
    lines.append("")
    lines.append("| feature | cases | labeled | decisive | recall | FPR |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    features = sorted(
        metrics["breakdowns"]["by_feature"].items(),
        key=lambda item: (-item[1]["n_cases"], item[0]),
    )[:20]
    for name, block in features:
        lines.append(
            f"| {name} | {block['n_cases']} | {block['n_labeled']} | {block['n_decisive']} | "
            f"{_fmt(block['recall'])} | {_fmt(block['fpr'])} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- TP/FP/TN/FN are computed only on labeled cases with a decisive outcome.")
    lines.append("- `inconclusive`, `timeout`, `build_failed`, and `unavailable` are excluded from the confusion matrix.")
    lines.append("- A combined `clean` means at least one detector completed a normal no-leak run and no detector reported a leak.")
    lines.append("- Detection evidence comes from LeakSanitizer/Valgrind output; function names are never used as labels.")
    lines.append("")
    return "\n".join(lines)
