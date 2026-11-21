"""Audit the generated artifacts without modifying them.

Re-derives prompt hashes and accuracy, recomputes McNemar, checks cost
arithmetic, confirms the frozen v2 baselines were not touched, and scans every
generated text file for the API key.  Exits nonzero on failure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .analyze import METHODS, paired_arrays
from .config import (
    EXPECTED_UNITS,
    GUIDED_PROMPT_VERSION,
    HDE,
    INPUTS_DIR,
    METHOD,
    MODELS,
    RESULTS_DIR,
    ROOT,
    RUNS_DIR,
    V2_RUNS,
)
from .evidence import audit_evidence, read_jsonl, sha256_bytes
from .prompts import build_guided
from .stats import mcnemar, metrics

SECRET_MARKERS = ("sk-", "Bearer ", "OPENCODE_API_KEY")


def text_files() -> list[Path]:
    roots = [HDE / "inputs", HDE / "runs", HDE / "results"]
    files: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".md", ".csv", ".txt"}:
                if path.name in {"audit.json", "audit.md"}:
                    continue
                files.append(path)
    report = HDE / "REPORT.md"
    if report.is_file():
        files.append(report)
    readme = HDE / "README.md"
    if readme.is_file():
        files.append(readme)
    return sorted(set(files))


def load_key() -> str | None:
    from .api import load_api_key

    try:
        return load_api_key()
    except SystemExit:
        return None


def baseline_records(model: str, method: str) -> dict[str, dict[str, Any]]:
    name = method.replace("v2-", "")
    path = V2_RUNS / f"hybrid_v2_{model}_{name}" / "results.jsonl"
    return {record["unit_id"]: record for record in read_jsonl(path)}


def run_start_epoch(run_id: str) -> float:
    stamps = []
    for model in MODELS:
        manifest = json.loads((RUNS_DIR / f"{run_id}_{model}" / "manifest.json").read_text(encoding="utf-8"))
        stamps.append(datetime.fromisoformat(manifest["started_at_utc"]).timestamp())
    return min(stamps)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="enhanced_dynamic_v1")
    parser.add_argument("--out-json", type=Path, default=RESULTS_DIR / "audit.json")
    parser.add_argument("--out-md", type=Path, default=RESULTS_DIR / "audit.md")
    args = parser.parse_args(argv)

    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    def check(name: str, ok: bool, detail: Any) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        if not ok:
            failures.append(name)

    units = sorted(read_jsonl(INPUTS_DIR / "units.jsonl"), key=lambda unit: unit["unit_id"])
    units_by_id = {unit["unit_id"]: unit for unit in units}
    unit_ids = [unit["unit_id"] for unit in units]
    truth = {unit["unit_id"]: 1 if unit["label"] else 0 for unit in units}
    manifest = json.loads((INPUTS_DIR / "manifest.json").read_text(encoding="utf-8"))
    preflight = json.loads((RESULTS_DIR / "preflight.json").read_text(encoding="utf-8"))
    analysis = json.loads((RESULTS_DIR / "enhanced_dynamic_metrics.json").read_text(encoding="utf-8"))

    check(
        "preflight",
        preflight.get("ok") and all(c["ok"] for c in preflight.get("checks", [])),
        {
            "ok": preflight.get("ok"),
            "checks": len(preflight.get("checks", [])),
            "failed": [c["check"] for c in preflight.get("checks", []) if not c["ok"]],
        },
    )
    check(
        "inputs",
        len(units) == EXPECTED_UNITS
        and sha256_bytes((INPUTS_DIR / "units.jsonl").read_bytes()) == manifest["units_sha256"]
        and preflight["input_pack"]["units_sha256"] == manifest["units_sha256"],
        {"units": len(units), "sha256": manifest["units_sha256"]},
    )
    evidence_errors = []
    for unit in units:
        try:
            audit_evidence(unit["enhanced_evidence"], unit["unit_id"])
        except Exception as exc:  # noqa: BLE001
            evidence_errors.append(f"{unit['unit_id']}: {exc}")
    check("evidence_sanitized", not evidence_errors, {"errors": evidence_errors[:5], "units": len(units)})

    records_by_model: dict[str, dict[str, dict[str, Any]]] = {}
    run_details: dict[str, Any] = {}
    prompt_errors: list[str] = []
    for model in MODELS:
        run_dir = RUNS_DIR / f"{args.run_id}_{model}"
        run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
        records = read_jsonl(run_dir / "results.jsonl")
        index = {record["unit_id"]: record for record in records}
        records_by_model[model] = index
        counts = run_manifest.get("counts") or {}
        run_details[model] = {
            "records": len(records),
            "unique": len(index),
            "counts": counts,
            "prompt_version": run_manifest.get("prompt_version"),
            "cost": run_manifest.get("cost"),
        }
        check(
            f"run_{model}_complete",
            len(records) == EXPECTED_UNITS
            and len(index) == EXPECTED_UNITS
            and counts.get("ok") == EXPECTED_UNITS
            and config.get("prompt_version") == GUIDED_PROMPT_VERSION
            and run_manifest.get("method") == METHOD
            and (config.get("dataset") or {}).get("sha256") == manifest["units_sha256"],
            run_details[model],
        )
        for record in records:
            unit = units_by_id.get(record["unit_id"])
            if unit is None:
                prompt_errors.append(f"{model}: unknown unit {record['unit_id']}")
                continue
            messages, meta = build_guided(unit)
            if record["prompt"]["prompt_sha256"] != meta["prompt_sha256"]:
                prompt_errors.append(f"{model}: prompt sha mismatch {record['unit_id']}")
            if record["prompt"]["prompt_version"] != GUIDED_PROMPT_VERSION:
                prompt_errors.append(f"{model}: prompt version {record['unit_id']}")
            if record.get("evidence_sha256") != unit["enhanced_evidence_sha256"]:
                prompt_errors.append(f"{model}: evidence sha mismatch {record['unit_id']}")
            if record.get("y_true") != truth[record["unit_id"]]:
                prompt_errors.append(f"{model}: y_true mismatch {record['unit_id']}")
            if record.get("status") == "ok" and record.get("y_pred") != (
                1 if record.get("predicted_label") == "vulnerable" else 0
            ):
                prompt_errors.append(f"{model}: label/y_pred mismatch {record['unit_id']}")
    check(
        "prompt_and_label_integrity",
        not prompt_errors,
        {"errors": prompt_errors[:8], "checked": len(units) * len(MODELS)},
    )

    cost_errors = []
    for model in MODELS:
        run_dir = RUNS_DIR / f"{args.run_id}_{model}"
        run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        index = records_by_model[model]
        configured = sum(float((r.get("cost") or {}).get("cost_usd") or 0.0) for r in index.values())
        listed = sum(
            float(((r.get("usage") or {}).get("opencode") or {}).get("list_cost") or 0.0)
            for r in index.values()
        )
        recorded = (run_manifest.get("cost") or {}).get("configured_usd")
        if recorded is None or abs(configured - recorded) > 1e-9:
            cost_errors.append(f"{model}: configured {configured} != manifest {recorded}")
        if configured and abs(listed / configured - 1.0) > 0.02:
            cost_errors.append(f"{model}: provider list/configured ratio {listed / configured:.4f}")
    check("cost_arithmetic", not cost_errors, {"errors": cost_errors})

    metric_errors = []
    for model in MODELS:
        block = analysis["models"][model]
        for method in METHODS:
            if method == "tool":
                pred = {
                    unit_id: {
                        "valid": True,
                        "y_pred": 1 if units_by_id[unit_id]["enhanced_outcome"] == "leak" else 0,
                    }
                    for unit_id in unit_ids
                }
            elif method == "hde-guided":
                pred = records_by_model[model]
            else:
                pred = baseline_records(model, method)
            y_true, y_pred, valid = paired_arrays(unit_ids, pred, truth)
            recomputed = metrics(y_true, y_pred, valid)
            stored = block["methods"][method]
            if abs(recomputed["strict_accuracy"] - stored["strict_accuracy"]) > 1e-12:
                metric_errors.append(f"{model}/{method}: accuracy")
            for key in ("tp", "fp", "tn", "fn"):
                if recomputed[key] != stored[key]:
                    metric_errors.append(f"{model}/{method}: {key}")
        for entry in block["mcnemar"]:
            baseline = entry["b"]
            if baseline == "tool":
                base_pred = {
                    unit_id: {
                        "valid": True,
                        "y_pred": 1 if units_by_id[unit_id]["enhanced_outcome"] == "leak" else 0,
                    }
                    for unit_id in unit_ids
                }
            elif baseline == "hde-guided":
                base_pred = records_by_model[model]
            else:
                base_pred = baseline_records(model, baseline)
            y_true, pred_a, valid_a = paired_arrays(unit_ids, records_by_model[model], truth)
            _, pred_b, valid_b = paired_arrays(unit_ids, base_pred, truth)
            rec = mcnemar(
                y_true,
                [p if ok else 0 for p, ok in zip(pred_a, valid_a)],
                [p if ok else 0 for p, ok in zip(pred_b, valid_b)],
            )
            if rec["p_value_exact"] != entry["p_value_exact"]:
                metric_errors.append(f"{model}/{baseline}: mcnemar")
    check("metrics_recomputed", not metric_errors, {"errors": metric_errors[:8]})

    csv_path = RESULTS_DIR / "enhanced_dynamic_predictions.csv"
    csv_rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    check(
        "predictions_csv",
        len(csv_rows) == EXPECTED_UNITS * len(METHODS) * len(MODELS)
        and len({(r["model"], r["method"], r["unit_id"]) for r in csv_rows}) == len(csv_rows),
        {"rows": len(csv_rows)},
    )

    key = load_key()
    secret_hits = []
    scanned = 0
    if key:
        for path in text_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            scanned += 1
            if key in text:
                secret_hits.append(f"{path.relative_to(ROOT)}: key literal")
            if path.name != "README.md":
                for marker in SECRET_MARKERS:
                    if marker in text:
                        secret_hits.append(f"{path.relative_to(ROOT)}: {marker!r}")
            if re.search(r"sk-[A-Za-z0-9]{16,}", text):
                secret_hits.append(f"{path.relative_to(ROOT)}: sk- token")
    check(
        "secret_scan",
        key is not None and not secret_hits,
        {"key_available": key is not None, "files_scanned": scanned, "hits": secret_hits[:5]},
    )

    start = run_start_epoch(args.run_id)
    baseline_files = [p for p in V2_RUNS.glob("hybrid_v2_*/**/*") if p.is_file()]
    newer = [str(p.relative_to(ROOT)) for p in baseline_files if p.stat().st_mtime > start]
    check(
        "baselines_untouched",
        not newer,
        {"files": len(baseline_files), "newer_than_new_run": newer[:5], "run_start_epoch": start},
    )

    report_path = HDE / "REPORT.md"
    report_text = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
    check(
        "report_present",
        bool(report_text)
        and "semantic-reasoning" in report_text.lower()
        and "McNemar" in report_text
        and "copy" in report_text,
        {"chars": len(report_text)},
    )

    status = "PASS" if not failures else "FAIL"
    payload = {
        "status": status,
        "generated_at": datetime.now().astimezone().isoformat(),
        "run_id": args.run_id,
        "checks_total": len(checks),
        "passed": sum(1 for c in checks if c["ok"]),
        "failures": failures,
        "checks": checks,
        "runs": run_details,
    }
    args.out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Artifact audit",
        "",
        f"Status **{status}** · {payload['passed']}/{payload['checks_total']} checks passed.",
        "",
        "| check | result | detail |",
        "| --- | --- | --- |",
    ]
    for item in checks:
        detail = json.dumps(item["detail"], ensure_ascii=False)
        if len(detail) > 220:
            detail = detail[:217] + "..."
        lines.append(f"| `{item['check']}` | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines.append("")
    lines.append("The audit never prints or stores the credential; it checks that the key literal is absent from every generated file.")
    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "passed": payload["passed"], "total": len(checks), "failures": failures}, indent=2))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
