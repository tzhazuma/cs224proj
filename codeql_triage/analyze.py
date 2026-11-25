#!/usr/bin/env python3
"""Analyse a CodeQL triage run and write every number from the per-unit JSONL.

Policies are fixed before looking at the model output:

``triage_keep`` (primary)
    Keep a CodeQL alert unless the model explicitly says ``false_positive``.
    ``uncertain`` is kept, invalid output falls back to the CodeQL verdict.
``triage_keep_evidence`` (sensitivity)
    Same, but a ``false_positive`` supported by fewer than two evidence fields
    is treated as uncertain and kept.
``triage_drop_uncertain`` (sensitivity)
    Keep only explicit ``true_positive``; drop ``uncertain``.
``hybrid_leak`` (secondary)
    Use the model's independent ``leak_present`` answer, falling back to
    CodeQL on ``uncertain``/invalid.
``hybrid_or`` (secondary)
    Union of the kept alert and a positive independent leak verdict.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from codeql_triage.common import (  # noqa: F401
    ALERT_FALSE,
    ALERT_NONE,
    ALERT_TRUE,
    ALERT_UNCERTAIN,
    bootstrap_macro_f1,
    mcnemar_from_pairs,
    metrics,
    parse_triage,
    read_jsonl,
    wilson_interval,
)

VARIANT_PATTERNS = {
    "33": "reference / shadowed alias, separate stack path",
    "22": "global flag + cross-function release",
    "72": "container element across source files",
    "54": "deep wrapper chain",
}


def load_results(run_dir: Path, condition: str) -> dict[str, dict[str, Any]]:
    path = run_dir / f"results_{condition}.jsonl"
    if not path.exists():
        raise SystemExit(f"missing {path}")
    rows = read_jsonl(path)
    return {row["unit_id"]: row for row in rows}


def load_verify(run_dir: Path) -> dict[str, dict[str, Any]]:
    path = run_dir / "verify" / "results_verify.jsonl"
    if not path.exists():
        return {}
    return {row["unit_id"]: row for row in read_jsonl(path) if row.get("valid")}


def _bool(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    return None


def build_rows(run_dir: Path) -> list[dict[str, Any]]:
    direct = load_results(run_dir, "direct")
    triage = load_results(run_dir, "triage")
    verify = load_verify(run_dir)
    if set(direct) != set(triage):
        raise SystemExit("direct and triage unit sets differ")
    rows: list[dict[str, Any]] = []
    for unit_id in sorted(direct):
        d = direct[unit_id]
        t = triage[unit_id]
        unit = d["unit"]
        codeql = unit["codeql_is_alert"]
        y_true = int(unit["y_true"])
        d_parsed = d.get("parsed") or {}
        t_parsed = t.get("parsed") or {}
        d_valid = bool(d.get("valid"))
        t_valid = bool(t.get("valid"))
        raw_triage_valid = t_valid
        # Re-parse the raw response with the current schema.  This is not a new
        # API call; it only applies a clarified rule (an absent alert may be
        # answered with ``uncertain``) to the same stored content.
        if t.get("content"):
            try:
                t_parsed = parse_triage(t["content"], has_alert=codeql)
                t_valid = True
            except Exception:  # noqa: BLE001
                pass
        d_pred = int(d_parsed["y_pred"]) if d_valid else 1 - y_true
        alert = t_parsed.get("alert_verdict") if t_valid else None
        leak = t_parsed.get("leak_present") if t_valid else None
        leak_bool = leak if isinstance(leak, bool) else None
        unsupported = bool(t_parsed.get("unsupported_drop")) if t_valid else False
        supported = int(t_parsed.get("evidence_fields_supported", 0)) if t_valid else 0

        triage_keep = int(codeql) if not t_valid else (
            int(alert != ALERT_FALSE) if codeql else 0
        )
        triage_keep_evidence = triage_keep
        if t_valid and alert == ALERT_FALSE and unsupported:
            triage_keep_evidence = 1
        triage_drop_uncertain = 1 if not t_valid else int(alert == ALERT_TRUE)
        if not codeql:
            triage_drop_uncertain = 0
        hybrid_leak = int(codeql) if not t_valid else (
            int(leak_bool) if leak_bool is not None else int(codeql)
        )
        if not t_valid:
            hybrid_or = int(codeql)
        else:
            kept = bool(codeql) and alert != ALERT_FALSE
            positive = leak_bool is True
            if leak_bool is None:
                positive = bool(codeql) and alert != ALERT_FALSE
            hybrid_or = int(kept or positive)
        hybrid_and = 0
        if t_valid and codeql and alert != ALERT_FALSE and leak_bool is not False:
            hybrid_and = 1

        v = verify.get(unit_id)
        v_valid = bool(v and v.get("valid"))
        v_parsed = (v or {}).get("parsed") or {}
        v_alert = v_parsed.get("final_alert_verdict") if v_valid else None
        v_leak = v_parsed.get("final_leak_present") if v_valid else None
        v_leak_bool = v_leak if isinstance(v_leak, bool) else None
        triage_verified = triage_keep
        if codeql and v_valid:
            triage_verified = int(v_alert != ALERT_FALSE)
        elif not codeql:
            triage_verified = 0
        triage_verified_leak = triage_keep
        if v_valid and v_leak_bool is not None:
            triage_verified_leak = int(v_leak_bool)

        text = ""
        if t_valid:
            text = " ".join(
                [t_parsed.get("fields", {}).get("reason", "")]
                + list(t_parsed.get("fields", {}).values())
            ).lower()
        no_leak_markers = (
            "no heap leak",
            "no leak",
            "released on every",
            "released on all",
            "all heap allocations released",
            "both heap allocations are released",
            "false positive",
            "false_positive",
        )
        leak_markers = (
            "never freed",
            "not freed",
            "unreleased",
            "leak on",
            "leaks",
            "leaked",
            "no free",
            "without free",
            "is never released",
            "not released",
        )
        rule_text_consistency = triage_keep
        if codeql and t_valid and alert == ALERT_TRUE:
            if any(marker in text for marker in no_leak_markers) and not any(
                marker in text for marker in leak_markers
            ):
                rule_text_consistency = 0
        elif not codeql:
            rule_text_consistency = 0
        hybrid_cascade_direct = triage_verified if codeql else d_pred

        by_query = unit["codeql_by_query"]
        never = int(by_query.get("cpp/memory-never-freed", 0)) > 0
        may = int(by_query.get("cpp/memory-may-not-be-freed", 0)) > 0
        drop_may_cpp = int(
            bool(codeql) and not (unit["language"] == "cpp" and may and not never)
        )
        rows.append(
            {
                "unit_id": unit_id,
                "y_true": y_true,
                "label": unit["label"],
                "language": unit["language"],
                "variant": unit["variant"],
                "family": unit["family"],
                "codeql_status": unit["codeql_status"],
                "codeql_alert": int(codeql),
                "codeql_never": int(never),
                "codeql_may": int(may),
                "codeql_findings": unit["codeql_finding_count"],
                "direct_valid": int(d_valid),
                "direct_pred": d_pred,
                "direct_confidence": d_parsed.get("confidence"),
                "triage_valid": int(t_valid),
                "raw_triage_valid": int(raw_triage_valid),
                "alert_verdict": alert,
                "leak_present": leak if isinstance(leak, str) else leak_bool,
                "triage_keep": triage_keep,
                "triage_keep_evidence": triage_keep_evidence,
                "triage_drop_uncertain": triage_drop_uncertain,
                "triage_verified": triage_verified,
                "triage_verified_leak": triage_verified_leak,
                "rule_text_consistency": rule_text_consistency,
                "hybrid_cascade_direct": hybrid_cascade_direct,
                "verify_valid": int(v_valid),
                "verify_alert_verdict": v_alert,
                "verify_leak_present": v_leak,
                "verify_release_gap": v_parsed.get("release_gap"),
                "hybrid_leak": hybrid_leak,
                "hybrid_or": hybrid_or,
                "hybrid_and": hybrid_and,
                "query_never_only": int(never),
                "drop_may_cpp": drop_may_cpp,
                "evidence_fields_supported": supported,
                "unsupported_drop": int(unsupported),
                "triage_reason": (t_parsed.get("fields") or {}).get("reason"),
                "triage_fields": (t_parsed.get("fields") or {}),
                "direct_reason": d_parsed.get("reason"),
                "triage_status": t.get("status"),
                "direct_status": d.get("status"),
                "triage_validation_error": t.get("validation_error"),
                "direct_validation_error": d.get("validation_error"),
                "triage_cost_usd": (t.get("cost") or {}).get("cost_usd"),
                "direct_cost_usd": (d.get("cost") or {}).get("cost_usd"),
                "triage_usage": t.get("usage"),
                "direct_usage": d.get("usage"),
                "triage_wall_seconds": t.get("wall_seconds"),
                "direct_wall_seconds": d.get("wall_seconds"),
                "triage_cache_hit": (t.get("cache") or {}).get("hit", False),
                "direct_cache_hit": (d.get("cache") or {}).get("hit", False),
            }
        )
    return rows


def eval_row(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    return metrics([int(row["y_true"]) for row in rows], [int(row[key]) for row in rows])


def coverage(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    n = len(rows)
    return {
        "n": n,
        "positive": sum(int(row[key]) for row in rows),
        "coverage": sum(1 for row in rows if int(row[key]) == 1) / n if n else None,
    }


def delta_table(rows: list[dict[str, Any]], left: str, right: str) -> dict[str, Any]:
    y = [int(row["y_true"]) for row in rows]
    a = [int(row[left]) for row in rows]
    b = [int(row[right]) for row in rows]
    return {
        "left": left,
        "right": right,
        "mcnemar": mcnemar_from_pairs(y, a, b),
        "bootstrap": bootstrap_macro_f1(y, a, b, iterations=10000, seed=42),
        "macro_f1_left": metrics(y, a)["macro_f1"],
        "macro_f1_right": metrics(y, b)["macro_f1"],
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def metrics_table(rows: list[dict[str, Any]]) -> str:
    policies = [
        ("CodeQL", "codeql_alert"),
        ("direct (strict)", "direct_pred"),
        ("triage keep (primary)", "triage_keep"),
        ("triage keep + evidence gate", "triage_keep_evidence"),
        ("triage drop uncertain", "triage_drop_uncertain"),
        ("triage v2 + consistency verify", "triage_verified"),
        ("triage v2 + text consistency rule", "rule_text_consistency"),
        ("cascade: verified alert + direct on no-alert", "hybrid_cascade_direct"),
        ("verified leak-present", "triage_verified_leak"),
        ("hybrid leak-present", "hybrid_leak"),
        ("hybrid OR", "hybrid_or"),
        ("hybrid AND", "hybrid_and"),
        ("query: never-freed only", "query_never_only"),
        ("rule: drop C++ may-not-be-freed", "drop_may_cpp"),
    ]
    lines = [
        "| policy | TP | FP | TN | FN | P | R | F1(V) | macro-F1 | MCC | accuracy |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, key in policies:
        m = eval_row(rows, key)
        lines.append(
            f"| {label} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
            f"{_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1_positive'])} | "
            f"{_fmt(m['macro_f1'])} | {_fmt(m['mcc'])} | {_fmt(m['accuracy'])} |"
        )
    return "\n".join(lines)


def subset_table(rows: list[dict[str, Any]]) -> str:
    subsets = [
        ("all test", rows),
        ("CodeQL compile_error", [row for row in rows if row["codeql_status"] != "ok"]),
        ("CodeQL ok", [row for row in rows if row["codeql_status"] == "ok"]),
        ("CodeQL FP (23)", [row for row in rows if row["codeql_alert"] and not row["y_true"]]),
        ("CodeQL TP (68)", [row for row in rows if row["codeql_alert"] and row["y_true"]]),
        ("CodeQL FN (2)", [row for row in rows if not row["codeql_alert"] and row["y_true"]]),
    ]
    lines = [
        "| subset | n | CodeQL TP/FP | direct correct | triage keep TP/FP | triage dropped TP | triage dropped FP |",
        "| --- | ---: | --- | ---: | --- | ---: | ---: |",
    ]
    for label, subset in subsets:
        if not subset:
            continue
        c_tp = sum(1 for row in subset if row["codeql_alert"] and row["y_true"])
        c_fp = sum(1 for row in subset if row["codeql_alert"] and not row["y_true"])
        d_ok = sum(1 for row in subset if row["direct_pred"] == row["y_true"])
        t_tp = sum(1 for row in subset if row["triage_keep"] and row["y_true"])
        t_fp = sum(1 for row in subset if row["triage_keep"] and not row["y_true"])
        d_tp = sum(
            1 for row in subset if row["codeql_alert"] and row["y_true"] and not row["triage_keep"]
        )
        d_fp = sum(
            1 for row in subset if row["codeql_alert"] and not row["y_true"] and not row["triage_keep"]
        )
        lines.append(
            f"| {label} | {len(subset)} | {c_tp}/{c_fp} | {d_ok}/{len(subset)} | "
            f"{t_tp}/{t_fp} | {d_tp} | {d_fp} |"
        )
    return "\n".join(lines)


def fp_table(rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    fps = [row for row in rows if row["codeql_alert"] and not row["y_true"]]
    lines = [
        "| unit | variant | pattern | queries | alert verdict | leak present | supported | one-shot | verified | direct | reason |",
        "| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for row in fps:
        queries = []
        if row["codeql_never"]:
            queries.append("never")
        if row["codeql_may"]:
            queries.append("may")
        reason = (row["triage_reason"] or row["triage_validation_error"] or "").replace("|", "/")
        lines.append(
            f"| `{row['unit_id']}` | {row['variant']} | {VARIANT_PATTERNS.get(row['variant'], 'other')} | "
            f"{'+'.join(queries)} | {row['alert_verdict']} | {row['leak_present']} | "
            f"{row['evidence_fields_supported']} | {'keep' if row['triage_keep'] else 'drop'} | "
            f"{'keep' if row['triage_verified'] else 'drop'} | "
            f"{row['direct_pred']} | {reason} |"
        )
    groups: dict[str, dict[str, Any]] = {}
    for row in fps:
        group = groups.setdefault(
            row["variant"],
            {
                "n": 0,
                "dropped": 0,
                "kept": 0,
                "verified_dropped": 0,
                "uncertain": 0,
                "unsupported_drop": 0,
                "direct_correct": 0,
                "pattern": VARIANT_PATTERNS.get(row["variant"], "other"),
            },
        )
        group["n"] += 1
        group["dropped"] += 0 if row["triage_keep"] else 1
        group["kept"] += 1 if row["triage_keep"] else 0
        group["verified_dropped"] += 0 if row["triage_verified"] else 1
        group["uncertain"] += 1 if row["alert_verdict"] == ALERT_UNCERTAIN else 0
        group["unsupported_drop"] += int(row["unsupported_drop"])
        group["direct_correct"] += 1 if row["direct_pred"] == 0 else 0
    summary = {
        "n": len(fps),
        "dropped": sum(1 for row in fps if not row["triage_keep"]),
        "kept": sum(1 for row in fps if row["triage_keep"]),
        "verified_dropped": sum(1 for row in fps if not row["triage_verified"]),
        "verified_kept": sum(1 for row in fps if row["triage_verified"]),
        "uncertain": sum(1 for row in fps if row["alert_verdict"] == ALERT_UNCERTAIN),
        "explicit_false_positive": sum(1 for row in fps if row["alert_verdict"] == ALERT_FALSE),
        "unsupported_drop": sum(int(row["unsupported_drop"]) for row in fps),
        "direct_correct": sum(1 for row in fps if row["direct_pred"] == 0),
        "groups": groups,
    }
    return "\n".join(lines), summary


def tp_deleted(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tps = [row for row in rows if row["codeql_alert"] and row["y_true"]]
    deleted = [row for row in tps if not row["triage_keep"]]
    details = [
        {
            "unit_id": row["unit_id"],
            "variant": row["variant"],
            "queries": {
                "never": bool(row["codeql_never"]),
                "may": bool(row["codeql_may"]),
            },
            "alert_verdict": row["alert_verdict"],
            "leak_present": row["leak_present"],
            "evidence_fields_supported": row["evidence_fields_supported"],
            "reason": row["triage_reason"],
            "direct_pred": row["direct_pred"],
        }
        for row in deleted
    ]
    summary = {
        "n_codeql_tp": len(tps),
        "deleted": len(deleted),
        "deleted_rate": len(deleted) / len(tps) if tps else None,
        "verified_deleted": sum(1 for row in tps if not row["triage_verified"]),
        "verified_deleted_rate": (
            sum(1 for row in tps if not row["triage_verified"]) / len(tps) if tps else None
        ),
        "by_query": {
            "never_only": sum(1 for row in tps if row["codeql_never"] and not row["codeql_may"]),
            "may": sum(1 for row in tps if row["codeql_may"]),
        },
        "deleted_never_only": sum(
            1 for row in deleted if row["codeql_never"] and not row["codeql_may"]
        ),
        "deleted_may": sum(1 for row in deleted if row["codeql_may"]),
        "direct_also_wrong": sum(1 for row in deleted if row["direct_pred"] == 0),
    }
    return details, summary


def verify_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    alerts = [row for row in rows if row["codeql_alert"]]
    valid = [row for row in alerts if row["verify_valid"]]
    flips = []
    for row in valid:
        before = "keep" if row["triage_keep"] else "drop"
        after = "keep" if row["triage_verified"] else "drop"
        if before != after:
            flips.append(
                {
                    "unit_id": row["unit_id"],
                    "y_true": row["y_true"],
                    "variant": row["variant"],
                    "before": before,
                    "after": after,
                    "before_alert": row["alert_verdict"],
                    "after_alert": row["verify_alert_verdict"],
                    "before_leak": row["leak_present"],
                    "after_leak": row["verify_leak_present"],
                    "release_gap": row["verify_release_gap"],
                    "reason": row["triage_reason"],
                }
            )
    return {
        "n_alerts": len(alerts),
        "n_verified": len(valid),
        "coverage": len(valid) / len(alerts) if alerts else None,
        "flips": flips,
        "flip_count": len(flips),
        "fixed_fp": sum(1 for item in flips if item["before"] == "keep" and item["after"] == "drop" and item["y_true"] == 0),
        "broken_tp": sum(1 for item in flips if item["before"] == "keep" and item["after"] == "drop" and item["y_true"] == 1),
        "recovered_tp": sum(1 for item in flips if item["before"] == "drop" and item["after"] == "keep" and item["y_true"] == 1),
        "new_fp": sum(1 for item in flips if item["before"] == "drop" and item["after"] == "keep" and item["y_true"] == 0),
    }


def direct_relation(rows: list[dict[str, Any]]) -> dict[str, Any]:
    fps = [row for row in rows if row["codeql_alert"] and not row["y_true"]]
    tps = [row for row in rows if row["codeql_alert"] and row["y_true"]]
    both_right = sum(1 for row in rows if row["triage_keep"] == row["y_true"] == row["direct_pred"])
    agreement = sum(1 for row in rows if row["triage_keep"] == row["direct_pred"]) / len(rows)
    return {
        "agreement": agreement,
        "both_correct": both_right,
        "triage_right_direct_wrong": sum(
            1 for row in rows if row["triage_keep"] == row["y_true"] != row["direct_pred"]
        ),
        "direct_right_triage_wrong": sum(
            1 for row in rows if row["direct_pred"] == row["y_true"] != row["triage_keep"]
        ),
        "direct_fp_ids": [
            row["unit_id"] for row in rows if row["direct_pred"] == 1 and not row["y_true"]
        ],
        "direct_fn_ids": [
            row["unit_id"] for row in rows if row["direct_pred"] == 0 and row["y_true"]
        ],
        "on_codeql_fp": {
            "n": len(fps),
            "direct_correct": sum(1 for row in fps if row["direct_pred"] == 0),
            "triage_dropped": sum(1 for row in fps if not row["triage_keep"]),
            "both_correct": sum(1 for row in fps if row["direct_pred"] == 0 and not row["triage_keep"]),
            "both_wrong": sum(1 for row in fps if row["direct_pred"] == 1 and row["triage_keep"]),
            "direct_wrong_triage_right": sum(
                1 for row in fps if row["direct_pred"] == 1 and not row["triage_keep"]
            ),
            "direct_right_triage_wrong": sum(
                1 for row in fps if row["direct_pred"] == 0 and row["triage_keep"]
            ),
            "wrong_ids": [row["unit_id"] for row in fps if row["direct_pred"] == 1],
        },
        "on_codeql_tp": {
            "n": len(tps),
            "direct_correct": sum(1 for row in tps if row["direct_pred"] == 1),
            "triage_kept": sum(1 for row in tps if row["triage_keep"]),
            "both_correct": sum(1 for row in tps if row["direct_pred"] == 1 and row["triage_keep"]),
            "both_wrong": sum(1 for row in tps if row["direct_pred"] == 0 and not row["triage_keep"]),
            "triage_deleted_direct_right": sum(
                1 for row in tps if row["direct_pred"] == 1 and not row["triage_keep"]
            ),
            "wrong_ids": [row["unit_id"] for row in tps if row["direct_pred"] == 0],
        },
    }


def cost_summary(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    result: dict[str, Any] = {"conditions": {}, "model": (manifest.get("api") or {}).get("model")}
    for condition in ("direct", "triage"):
        path = run_dir / f"metrics_{condition}.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        result["conditions"][condition] = {
            "n": data["n"],
            "valid": data["valid"],
            "cost_usd": data["cost_usd"],
            "prompt_tokens": data["prompt_tokens"],
            "completion_tokens": data["completion_tokens"],
            "cached_prompt_tokens": data["cached_prompt_tokens"],
            "cache_hits": data["cache_hits"],
            "latency_seconds": data["latency_seconds"],
            "cost_basis": "configured list price, not invoice",
        }
    verify_manifest = run_dir / "verify" / "manifest.json"
    if verify_manifest.exists():
        data = json.loads(verify_manifest.read_text(encoding="utf-8"))
        result["conditions"]["verify"] = {
            "n": data["n_targets"],
            "valid": data["n_valid"],
            "cost_usd": data["cost_usd"],
            "prompt_tokens": None,
            "completion_tokens": None,
            "cached_prompt_tokens": None,
            "cache_hits": data["cache_hits"],
            "latency_seconds": data["latency_seconds"],
            "cost_basis": "configured list price, not invoice",
        }
    return result


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "unit_id",
        "y_true",
        "language",
        "variant",
        "codeql_status",
        "codeql_alert",
        "codeql_never",
        "codeql_may",
        "direct_valid",
        "direct_pred",
        "triage_valid",
        "alert_verdict",
        "leak_present",
        "triage_keep",
        "triage_verified",
        "rule_text_consistency",
        "verify_alert_verdict",
        "verify_release_gap",
        "hybrid_leak",
        "hybrid_or",
        "evidence_fields_supported",
        "unsupported_drop",
        "triage_reason",
        "direct_reason",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--label", default=None)
    args = parser.parse_args(argv)
    run_dir = args.run_dir
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    rows = build_rows(run_dir)
    label = args.label or (json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")).get("api", {}).get("model") if (run_dir / "manifest.json").exists() else run_dir.name)

    policies = [
        "codeql_alert",
        "direct_pred",
        "triage_keep",
        "triage_keep_evidence",
        "triage_drop_uncertain",
        "triage_verified",
        "triage_verified_leak",
        "rule_text_consistency",
        "hybrid_cascade_direct",
        "hybrid_leak",
        "hybrid_or",
        "hybrid_and",
        "query_never_only",
        "drop_may_cpp",
    ]
    summary: dict[str, Any] = {
        "run_dir": str(run_dir),
        "label": label,
        "n_units": len(rows),
        "metrics": {key: eval_row(rows, key) for key in policies},
        "coverage": {
            "codeql_analyzable": sum(1 for row in rows if row["codeql_status"] == "ok"),
            "codeql_coverage": sum(1 for row in rows if row["codeql_status"] == "ok") / len(rows),
            "triage_api_valid": sum(row["triage_valid"] for row in rows),
            "triage_api_coverage": sum(row["triage_valid"] for row in rows) / len(rows),
            "triage_raw_valid": sum(row["raw_triage_valid"] for row in rows),
            "triage_reparsed_units": [
                row["unit_id"]
                for row in rows
                if row["triage_valid"] and not row["raw_triage_valid"]
            ],
            "triage_decision_coverage_on_alerts": (
                sum(
                    1
                    for row in rows
                    if row["codeql_alert"] and row["triage_valid"] and row["alert_verdict"] != ALERT_UNCERTAIN
                )
                / sum(1 for row in rows if row["codeql_alert"])
            ),
            "compile_errors": [
                {"unit_id": row["unit_id"], "language": row["language"], "y_true": row["y_true"]}
                for row in rows
                if row["codeql_status"] != "ok"
            ],
            "invalid_triage": [
                {"unit_id": row["unit_id"], "error": row["triage_validation_error"]}
                for row in rows
                if not row["triage_valid"]
            ],
        },
        "deltas": {
            "triage_vs_codeql": delta_table(rows, "codeql_alert", "triage_keep"),
            "triage_vs_direct": delta_table(rows, "direct_pred", "triage_keep"),
            "verified_vs_codeql": delta_table(rows, "codeql_alert", "triage_verified"),
            "verified_vs_direct": delta_table(rows, "direct_pred", "triage_verified"),
            "verified_vs_triage": delta_table(rows, "triage_keep", "triage_verified"),
            "text_rule_vs_verified": delta_table(rows, "triage_verified", "rule_text_consistency"),
            "cascade_vs_verified": delta_table(rows, "triage_verified", "hybrid_cascade_direct"),
            "direct_vs_codeql": delta_table(rows, "codeql_alert", "direct_pred"),
            "drop_may_cpp_vs_direct": delta_table(rows, "direct_pred", "drop_may_cpp"),
            "hybrid_vs_direct": delta_table(rows, "direct_pred", "hybrid_leak"),
        },
        "codeql_confusion": metrics(
            [int(row["y_true"]) for row in rows], [int(row["codeql_alert"]) for row in rows]
        ),
        "direct_valid_only": (
            metrics(
                [int(row["y_true"]) for row in rows if row["direct_valid"]],
                [int(row["direct_pred"]) for row in rows if row["direct_valid"]],
            )
            if any(row["direct_valid"] for row in rows)
            else None
        ),
        "direct_coverage": sum(row["direct_valid"] for row in rows) / len(rows),
        "fp23": fp_table(rows)[1],
        "tp_deleted": tp_deleted(rows)[1],
        "verify": verify_summary(rows),
        "direct_relation": direct_relation(rows),
        "cost": cost_summary(run_dir),
    }
    summary["cost"]["conditions"]["triage"]["valid"] = summary["coverage"]["triage_api_valid"]
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_csv(out / "per_sample.csv", rows)
    (out / "per_unit.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    comparison = [
        f"# CodeQL triage comparison — {label}",
        "",
        f"Run: `{run_dir}`  ",
        f"Units: {len(rows)} (bad {sum(row['y_true'] for row in rows)} / good {sum(1-row['y_true'] for row in rows)})  ",
        "Primary policy: keep a CodeQL alert unless the model explicitly says `false_positive`; "
        "`uncertain` and invalid output fall back to keeping/CodeQL.",
        "",
        "## Main table (all 140, strict)",
        "",
        metrics_table(rows),
        "",
        "`triage drop uncertain` is a sensitivity analysis, not the primary policy. "
        "`query: never-freed only` and `rule: drop C++ may-not-be-freed` are zero-cost baselines.",
        "",
        "## Coverage and subsets",
        "",
        f"- CodeQL analyzable: {summary['coverage']['codeql_analyzable']}/140 "
        f"({summary['coverage']['codeql_coverage']:.4f})",
        f"- Triage API valid: {summary['coverage']['triage_api_valid']}/140 "
        f"({summary['coverage']['triage_api_coverage']:.4f})",
        f"- Decisive triage verdicts among the 91 CodeQL alerts: "
        f"{summary['coverage']['triage_decision_coverage_on_alerts']:.4f}",
        f"- Direct API valid: {summary['direct_coverage']:.4f}",
        "",
        subset_table(rows),
        "",
        "## Paired tests",
        "",
        "| comparison | left macro-F1 | right macro-F1 | delta | bootstrap 95% CI | McNemar p |",
        "| --- | ---: | ---: | ---: | --- | ---: |",
    ]
    for name, delta in summary["deltas"].items():
        comparison.append(
            f"| {name} | {delta['macro_f1_left']:.4f} | {delta['macro_f1_right']:.4f} | "
            f"{delta['bootstrap']['observed_delta_macro_f1']:+.4f} | "
            f"[{delta['bootstrap']['ci95'][0]:+.4f}, {delta['bootstrap']['ci95'][1]:+.4f}] | "
            f"{delta['mcnemar']['p_value']:.6f} |"
        )
    comparison += [
        "",
        "## CodeQL confusion (end-to-end, all 140)",
        "",
        f"TP/FP/TN/FN = {summary['codeql_confusion']['tp']}/{summary['codeql_confusion']['fp']}/"
        f"{summary['codeql_confusion']['tn']}/{summary['codeql_confusion']['fn']}; "
        f"P={summary['codeql_confusion']['precision']:.4f}, R={summary['codeql_confusion']['recall']:.4f}, "
        f"macro-F1={summary['codeql_confusion']['macro_f1']:.4f}, MCC={summary['codeql_confusion']['mcc']:.4f}.",
        "",
    ]
    (out / "comparison.md").write_text("\n".join(comparison), encoding="utf-8")

    fp_md, fp_summary = fp_table(rows)
    fp_lines = [
        f"# The 23 CodeQL false positives — {label}",
        "",
        f"Dropped: {fp_summary['dropped']}/23; kept: {fp_summary['kept']}; "
        f"verified dropped: {fp_summary['verified_dropped']}/23; "
        f"explicit false_positive: {fp_summary['explicit_false_positive']}; "
        f"uncertain: {fp_summary['uncertain']}; unsupported drops: {fp_summary['unsupported_drop']}. "
        f"Direct LLM already correct on {fp_summary['direct_correct']}/23.",
        "",
        fp_md,
        "",
        "## By pattern",
        "",
        "| variant | pattern | n | dropped | verified dropped | kept | uncertain | unsupported drop | direct correct |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for variant, group in sorted(fp_summary["groups"].items()):
        fp_lines.append(
            f"| {variant} | {group['pattern']} | {group['n']} | {group['dropped']} | "
            f"{group['verified_dropped']} | {group['kept']} | {group['uncertain']} | "
            f"{group['unsupported_drop']} | {group['direct_correct']} |"
        )
    (out / "fp23.md").write_text("\n".join(fp_lines), encoding="utf-8")

    details, tpsummary = tp_deleted(rows)
    tp_lines = [
        f"# CodeQL true positives deleted by triage — {label}",
        "",
        f"CodeQL TPs: {tpsummary['n_codeql_tp']}; one-shot deleted: {tpsummary['deleted']} "
        f"({tpsummary['deleted_rate']:.4f}); verified deleted: {tpsummary['verified_deleted']} "
        f"({tpsummary['verified_deleted_rate']:.4f}); deleted never-only: {tpsummary['deleted_never_only']}; "
        f"deleted may-not-be-freed: {tpsummary['deleted_may']}; direct also wrong on: "
        f"{tpsummary['direct_also_wrong']}.",
        "",
        "| unit | variant | queries | alert verdict | leak present | supported | direct | reason |",
        "| --- | --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for item in details:
        queries = "+".join(key for key, value in item["queries"].items() if value)
        tp_lines.append(
            f"| `{item['unit_id']}` | {item['variant']} | {queries} | {item['alert_verdict']} | "
            f"{item['leak_present']} | {item['evidence_fields_supported']} | "
            f"{item['direct_pred']} | {(item['reason'] or '').replace('|', '/')} |"
        )
    if not details:
        tp_lines.append("| — | — | — | — | — | — | — | no CodeQL TP was deleted |")
    (out / "tp_deleted.md").write_text("\n".join(tp_lines), encoding="utf-8")

    relation = summary["direct_relation"]
    rel_lines = [
        f"# Triage vs direct LLM — {label}",
        "",
        f"Agreement: {relation['agreement']:.4f}; both correct: {relation['both_correct']}/140; "
        f"triage right / direct wrong: {relation['triage_right_direct_wrong']}; "
        f"direct right / triage wrong: {relation['direct_right_triage_wrong']}.",
        f"Direct FP ids: {', '.join(relation['direct_fp_ids']) or 'none'}.",
        f"Direct FN ids: {', '.join(relation['direct_fn_ids']) or 'none'}.",
        "",
        "## On the 23 CodeQL FPs",
        "",
        f"- direct correct: {relation['on_codeql_fp']['direct_correct']}/23",
        f"- triage one-shot dropped: {relation['on_codeql_fp']['triage_dropped']}/23",
        f"- final two-stage dropped: "
        f"{sum(1 for row in rows if row['codeql_alert'] and not row['y_true'] and not row['triage_verified'])}/23",
        f"- both correct: {relation['on_codeql_fp']['both_correct']}",
        f"- both wrong: {relation['on_codeql_fp']['both_wrong']}",
        f"- direct wrong, triage right: {relation['on_codeql_fp']['direct_wrong_triage_right']}",
        f"- direct right, triage wrong: {relation['on_codeql_fp']['direct_right_triage_wrong']}",
        f"- direct wrong ids: {', '.join(relation['on_codeql_fp']['wrong_ids']) or 'none'}",
        "",
        "## On the 68 CodeQL TPs",
        "",
        f"- direct correct: {relation['on_codeql_tp']['direct_correct']}/68",
        f"- triage kept: {relation['on_codeql_tp']['triage_kept']}/68",
        f"- both correct: {relation['on_codeql_tp']['both_correct']}",
        f"- both wrong: {relation['on_codeql_tp']['both_wrong']}",
        f"- triage deleted while direct right: {relation['on_codeql_tp']['triage_deleted_direct_right']}",
        f"- direct wrong ids: {', '.join(relation['on_codeql_tp']['wrong_ids']) or 'none'}",
        "",
        "## Oracle combinations (not deployable; ceiling only)",
        "",
    ]
    # Explicit oracle numbers are computed below rather than baked into a policy.
    y = [int(row["y_true"]) for row in rows]
    cq = [int(row["codeql_alert"]) for row in rows]
    dr = [int(row["direct_pred"]) for row in rows]
    inter = [int(a and b) for a, b in zip(cq, dr)]
    union = [int(a or b) for a, b in zip(cq, dr)]
    for name, pred in (("CodeQL ∧ direct", inter), ("CodeQL ∨ direct", union)):
        m = metrics(y, pred)
        rel_lines.append(
            f"- {name}: TP/FP/TN/FN = {m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}, "
            f"P={m['precision']:.4f}, R={m['recall']:.4f}, macro-F1={m['macro_f1']:.4f}, MCC={m['mcc']:.4f}"
        )
    verified = summary["metrics"]["triage_verified"]
    delta = summary["deltas"]["verified_vs_direct"]
    rel_lines += [
        "",
        "## Two-stage final (v2 + consistency verify) vs direct",
        "",
        f"- final: TP/FP/TN/FN = {verified['tp']}/{verified['fp']}/{verified['tn']}/{verified['fn']}, "
        f"P={verified['precision']:.4f}, R={verified['recall']:.4f}, "
        f"macro-F1={verified['macro_f1']:.4f}, MCC={verified['mcc']:.4f}",
        f"- paired delta macro-F1: {delta['bootstrap']['observed_delta_macro_f1']:+.4f} "
        f"(95% CI [{delta['bootstrap']['ci95'][0]:+.4f}, {delta['bootstrap']['ci95'][1]:+.4f}]), "
        f"exact McNemar p={delta['mcnemar']['p_value']:.6f}",
        "",
        "The two-stage final is not a free improvement: it adds a second request per CodeQL alert "
        "and keeps the 2 CodeQL false negatives. The one-shot v2 result is reported separately.",
    ]
    (out / "direct_relation.md").write_text("\n".join(rel_lines), encoding="utf-8")

    verify = summary["verify"]
    verify_lines = [
        f"# Second-pass consistency verification — {label}",
        "",
        f"Targets: {verify['n_alerts']} CodeQL alerts; verified: {verify['n_verified']} "
        f"({verify['coverage']:.4f}); changed decisions: {verify['flip_count']}.",
        f"Fixed FP: {verify['fixed_fp']}; broken TP: {verify['broken_tp']}; "
        f"recovered TP: {verify['recovered_tp']}; new FP: {verify['new_fp']}.",
        "",
        "| unit | label | variant | before | after | first alert | verified alert | first leak | verified leak | release gap |",
        "| --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in verify["flips"]:
        verify_lines.append(
            f"| `{item['unit_id']}` | {item['y_true']} | {item['variant']} | {item['before']} | "
            f"{item['after']} | {item['before_alert']} | {item['after_alert']} | "
            f"{item['before_leak']} | {item['after_leak']} | "
            f"{(item['release_gap'] or '').replace('|', '/')} |"
        )
    if not verify["flips"]:
        verify_lines.append("| — | — | — | — | — | — | — | — | — | no decision changed |")
    (out / "verification.md").write_text("\n".join(verify_lines), encoding="utf-8")

    cost = summary["cost"]
    cost_lines = [
        f"# Cost and latency — {label}",
        "",
        "Prices are the configured list prices used by the earlier runs, not the provider invoice.",
        "",
        "| condition | n | valid | cost USD | prompt tokens | completion tokens | cached prompt tokens | cache hits | p50 s | p95 s |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition, data in cost["conditions"].items():
        latency = data.get("latency_seconds") or {}
        pt = data["prompt_tokens"] if data["prompt_tokens"] is not None else "n/a"
        ct = data["completion_tokens"] if data["completion_tokens"] is not None else "n/a"
        cached = (
            data["cached_prompt_tokens"]
            if data["cached_prompt_tokens"] is not None
            else "n/a"
        )
        cost_lines.append(
            f"| {condition} | {data['n']} | {data['valid']} | "
            f"{data['cost_usd'] if data['cost_usd'] is not None else 'n/a'} | "
            f"{pt} | {ct} | {cached} | "
            f"{data['cache_hits']} | {latency.get('p50', 'n/a'):.4f} | {latency.get('p95', 'n/a'):.4f} |"
        )
    cost_lines += [
        "",
        "The zero-cost query/rule baselines have no API cost. A cost-per-removed-FP or "
        "cost-per-retained-TP number is only meaningful together with the TP-deletion table; "
        "it is reported in `summary.json` via the raw totals rather than as a headline.",
    ]
    (out / "cost.md").write_text("\n".join(cost_lines), encoding="utf-8")

    compile_errors = summary["coverage"]["compile_errors"]
    ce_lines = [
        f"# Compile-error units — {label}",
        "",
        "These four test units are `compile_error` in the frozen CodeQL run. They are not "
        "silently scored as CodeQL negatives: the end-to-end table counts them as no alert, "
        "and this table shows what each model did on the cleaned source view.",
        "",
        "| unit | language | label | CodeQL | direct | triage alert | triage leak | triage final |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in compile_errors:
        row = next(row for row in rows if row["unit_id"] == item["unit_id"])
        ce_lines.append(
            f"| `{row['unit_id']}` | {row['language']} | {row['label']} | {row['codeql_status']} | "
            f"{row['direct_pred']} | {row['alert_verdict']} | {row['leak_present']} | "
            f"{'keep' if row['triage_keep'] else 'drop'} |"
        )
    (out / "compile_errors.md").write_text("\n".join(ce_lines), encoding="utf-8")

    print(json.dumps({k: summary["metrics"][k] for k in ("codeql_alert", "direct_pred", "triage_keep", "drop_may_cpp")}, indent=2))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
