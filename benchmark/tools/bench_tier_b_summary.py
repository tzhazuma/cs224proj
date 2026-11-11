#!/usr/bin/env python3
"""Summarise Tier B Juliet CWE-401 runs into split-aware views.

The canonical Tier B runs contain all 200 frozen units (dev 60 + test 140).
This tool keeps the two splits visible and reports:

* ``test_all``: primary, 140 test units with the frozen Juliet labels;
* ``test_runtime``: primary sensitivity, 128 test units whose labels are
  supported by the LSan runtime check;
* ``all_all`` / ``all_runtime``: full frozen set, reference only;
* ``dev_all`` / ``dev_runtime``: dev split, reference only.

Two dynamic views are reported. ``operational`` uses the dynamic pipeline's
own leak/no-leak outcome. ``conservative`` abstains on every clean prediction
because the dynamic run has no line-coverage instrumentation: a clean result
is "no leak observed", not a verified true negative. Static compile errors
remain non-ok and are never rewritten as ``y_pred=0``.

Output is Tier B only. No Tier A unit or metric is pooled into these tables.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    as_bool,
    atomic_write_json,
    atomic_write_text,
    bootstrap_detection,
    cost_summary,
    count_by,
    detection_scores,
    load_run,
    sha256_file,
    utc_now,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_VERSION = "benchmark-tier-b-summary-v1"
VIEWS = (
    ("test_all", "test", False, True),
    ("test_runtime", "test", True, True),
    ("all_all", None, False, False),
    ("all_runtime", None, True, False),
    ("dev_all", "dev", False, False),
    ("dev_runtime", "dev", True, False),
)
PRIMARY_VIEW = "test_all"
PRIMARY_RUNTIME_VIEW = "test_runtime"


def _predictions(records: Sequence[Mapping[str, Any]]) -> tuple[list[bool], list[bool | None], list[str]]:
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    for record in records:
        label = as_bool(record.get("label", {}).get("y_true"))
        if label is None:
            raise ValueError(f"{record.get('unit_id')}: non-binary label")
        labels.append(label)
        if record.get("status") == "ok":
            predictions.append(as_bool(record.get("prediction", {}).get("y_pred")))
        else:
            predictions.append(None)
        clusters.append(str(record.get("cluster_id")))
    return labels, predictions, clusters


def _conservative_predictions(
    records: Sequence[Mapping[str, Any]],
) -> tuple[list[bool], list[bool | None], list[str], int]:
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    abstained = 0
    for record in records:
        label = as_bool(record.get("label", {}).get("y_true"))
        if label is None:
            raise ValueError(f"{record.get('unit_id')}: non-binary label")
        labels.append(label)
        clusters.append(str(record.get("cluster_id")))
        prediction = None
        if record.get("status") == "ok":
            prediction = as_bool(record.get("prediction", {}).get("y_pred"))
        if prediction is False:
            coverage = record.get("coverage")
            line_coverage = coverage.get("line_coverage") if isinstance(coverage, dict) else None
            if line_coverage is None:
                prediction = None
                abstained += 1
        predictions.append(prediction)
    return labels, predictions, clusters, abstained


def _score_block(
    records: Sequence[Mapping[str, Any]],
    *,
    bootstrap: bool,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    labels, predictions, clusters = _predictions(records)
    scores = detection_scores(labels, predictions)
    block: dict[str, Any] = {
        "scores": scores,
        "status_counts": count_by(str(record.get("status")) for record in records),
        "side_counts": count_by(str(record.get("side")) for record in records),
        "cluster_count": len(set(clusters)),
        "cost": cost_summary(records),
        "bootstrap": None,
        "bootstrap_cluster_count": None,
        "bootstrap_cluster_size": None,
    }
    if bootstrap:
        result = bootstrap_detection(
            labels,
            predictions,
            clusters,
            resamples=resamples,
            seed=seed,
        )
        block["bootstrap"] = result.get("metrics")
        block["bootstrap_cluster_count"] = result.get("cluster_count")
        block["bootstrap_cluster_size"] = result.get("cluster_size_summary")
    cost = block["cost"]
    n = len(records)
    if n and cost.get("wall_s_sum") is not None:
        cost["wall_s_per_unit"] = cost["wall_s_sum"] / n
        cost["wall_s_per_100_units"] = cost["wall_s_sum"] / n * 100.0
    return block


def _conservative_block(
    records: Sequence[Mapping[str, Any]],
    *,
    bootstrap: bool,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    labels, predictions, clusters, abstained = _conservative_predictions(records)
    scores = detection_scores(labels, predictions)
    block: dict[str, Any] = {
        "scores": scores,
        "clean_abstained": abstained,
        "abstention_rate": (abstained / len(records)) if records else None,
        "bootstrap": None,
        "policy": (
            "clean dynamic prediction with line_coverage=null is treated as abstention; "
            "negative-class units therefore leave the valid set, so macro-F1 is undefined. "
            "Recall and precision remain defined; they are detection-only, not a safety score"
        ),
    }
    if bootstrap:
        result = bootstrap_detection(
            labels,
            predictions,
            clusters,
            resamples=resamples,
            seed=seed,
        )
        block["bootstrap"] = result.get("metrics")
        block["bootstrap_cluster_count"] = result.get("cluster_count")
    return block


def _view_records(
    records: Sequence[Mapping[str, Any]],
    split: str | None,
    runtime_only: bool,
) -> list[Mapping[str, Any]]:
    selected: list[Mapping[str, Any]] = []
    for record in records:
        extensions = record.get("extensions") or {}
        if split is not None and str(extensions.get("split")) != split:
            continue
        if runtime_only and not bool(extensions.get("runtime_supported")):
            continue
        selected.append(record)
    return selected


def _exclusions(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    status_counts = count_by(str(record.get("status")) for record in records)
    compile_errors = [
        str(record.get("unit_id"))
        for record in records
        if record.get("status") == "compile_error"
    ]
    inconclusive = [
        str(record.get("unit_id"))
        for record in records
        if record.get("status") == "inconclusive"
    ]
    return {
        "status_counts": status_counts,
        "compile_error_count": status_counts.get("compile_error", 0),
        "compile_error_units": compile_errors,
        "inconclusive_count": status_counts.get("inconclusive", 0),
        "inconclusive_units": inconclusive,
        "timeout_count": status_counts.get("timeout", 0),
        "tool_error_count": status_counts.get("tool_error", 0),
    }


def _method_meta(manifest: Mapping[str, Any]) -> dict[str, Any]:
    method = manifest.get("method") or {}
    family = str(method.get("family") or "")
    return {
        "method_id": str(method.get("method_id") or ""),
        "family": family,
        "name": str(method.get("name") or ""),
        "run_id": str(manifest.get("run_id") or ""),
        "tool": method.get("tool"),
        "config_sha256": method.get("config_sha256"),
    }


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _ci(block: Mapping[str, Any], name: str) -> str:
    bootstrap = block.get("bootstrap")
    if not isinstance(bootstrap, dict):
        return "—"
    item = bootstrap.get(name)
    if not isinstance(item, dict) or item.get("ci_low") is None:
        return "—"
    return f"[{item['ci_low']:.3f}, {item['ci_high']:.3f}]"


def _wilson(scores: Mapping[str, Any], name: str) -> str:
    wilson = scores.get("wilson")
    if not isinstance(wilson, dict):
        return "—"
    item = wilson.get(name)
    if not isinstance(item, dict) or item.get("low") is None:
        return "—"
    return f"[{item['low']:.3f}, {item['high']:.3f}]"


def _method_table(
    methods: Sequence[Mapping[str, Any]],
    view: Mapping[str, Any],
) -> list[str]:
    lines = [
        "| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |",
    ]
    for method in methods:
        block = view["methods"][method["method_id"]]
        scores = block["scores"]
        confusion = scores["confusion"]
        cost = block["cost"]
        exclusions = block["exclusions"]
        lines.append(
            "| {name} | {family} | {n} | {valid} | {cov} | {tp} | {fp} | {tn} | {fn} | {p} | {r} | {spec} | {f1} | {ci} | {mcc} | {strict} | {bad} | {wall} | {p50}/{p95} |".format(
                name=method["name"].replace("|", "/"),
                family=method["family"],
                n=scores["n"],
                valid=scores["valid"],
                cov=_fmt(scores["coverage"]),
                tp=confusion["tp"],
                fp=confusion["fp"],
                tn=confusion["tn"],
                fn=confusion["fn"],
                p=_fmt(scores["precision"]),
                r=_fmt(scores["recall"]),
                spec=_fmt(scores["specificity"]),
                f1=_fmt(scores["macro_f1"]),
                ci=_ci(block, "macro_f1"),
                mcc=_fmt(scores["mcc"]),
                strict=_fmt(scores["strict_accuracy"]),
                bad=f"{exclusions['compile_error_count']}/{exclusions['inconclusive_count']}",
                wall=_fmt(cost.get("wall_s_per_unit"), 4),
                p50=_fmt(cost.get("latency_ms_p50"), 1),
                p95=_fmt(cost.get("latency_ms_p95"), 1),
            )
        )
    return lines


def build_summary(run_dirs: Sequence[Path], *, resamples: int, seed: int) -> dict[str, Any]:
    loaded = []
    dataset_sha: str | None = None
    for run_dir in run_dirs:
        manifest, records, _ = load_run(run_dir)
        if manifest.get("tier") != "B" or manifest.get("track") != "juliet_cwe401":
            continue
        # Historical 5-tool view only. Round-2 LLM/hybrid/repair runs are
        # summarised by bench_final_summary.py; mixing their test-only records
        # into the all-200/dev-60 views would make those views incomparable.
        if (manifest.get("method") or {}).get("family") not in ("static", "dynamic"):
            continue
        sha = (manifest.get("dataset") or {}).get("sha256")
        if dataset_sha is None:
            dataset_sha = sha
        elif sha != dataset_sha:
            raise ValueError(f"{run_dir}: dataset SHA-256 differs from the first run")
        loaded.append((run_dir, manifest, records))
    if not loaded:
        raise ValueError("no Tier B runs found")

    methods = sorted(
        (_method_meta(manifest) for _, manifest, _ in loaded),
        key=lambda item: ({"static": 0, "dynamic": 1, "llm": 2, "hybrid": 3}.get(item["family"], 9), item["method_id"]),
    )
    by_method = {
        str(manifest.get("method", {}).get("method_id")): (run_dir, manifest, records)
        for run_dir, manifest, records in loaded
    }

    views: dict[str, Any] = {}
    for view_name, split, runtime_only, primary in VIEWS:
        view_methods: dict[str, Any] = {}
        view_n = None
        view_labels: dict[str, int] | None = None
        view_clusters: int | None = None
        for method in methods:
            method_id = method["method_id"]
            run_dir, manifest, records = by_method[method_id]
            selected = _view_records(records, split, runtime_only)
            if not selected:
                continue
            block = _score_block(
                selected,
                bootstrap=primary,
                resamples=resamples,
                seed=seed,
            )
            block["run_dir"] = str(run_dir)
            block["exclusions"] = _exclusions(selected)
            block["clean_verifiability"] = (
                "not_verified: no coverage instrumentation; clean = no leak observed"
                if method["family"] == "dynamic"
                else "not_applicable: static does not certify clean code"
                if method["family"] == "static"
                else "per_run"
            )
            block["conservative"] = (
                _conservative_block(
                    selected,
                    bootstrap=primary,
                    resamples=resamples,
                    seed=seed,
                )
                if method["family"] == "dynamic"
                else None
            )
            view_methods[method_id] = block
            view_n = block["scores"]["n"]
            view_labels = block["scores"]["label_counts"]
            view_clusters = block["cluster_count"]
        views[view_name] = {
            "split": split or "all",
            "runtime_supported_only": runtime_only,
            "primary": primary,
            "n": view_n,
            "label_counts": view_labels,
            "cluster_count": view_clusters,
            "methods": view_methods,
        }

    dataset = (by_method[methods[0]["method_id"]][1].get("dataset") or {}) if methods else {}
    return {
        "schema_version": SUMMARY_VERSION,
        "generated_at": utc_now(),
        "protocol_version": "1.0.0",
        "tier": "B",
        "track": "juliet_cwe401",
        "historical_view": {
            "status": "superseded",
            "scope": "5 traditional-tool runs only",
            "superseded_by": "benchmark/results/final_summary.json",
            "note": "Round-2 LLM/hybrid/repair are not in this historical summary.",
        },
        "dataset": {
            "dataset_id": dataset.get("dataset_id"),
            "sha256": dataset.get("sha256"),
            "unit_count": 200,
            "group_count": 100,
            "family_count": 42,
            "splits": {"dev": 60, "test": 140},
            "units_sha256": dataset_sha,
        },
        "primary_view": PRIMARY_VIEW,
        "primary_runtime_view": PRIMARY_RUNTIME_VIEW,
        "views": views,
        "methods": methods,
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "bootstrap_cohort": "cluster percentile bootstrap over case_family",
            "test_cluster_count": 29,
            "dev_cluster_count": 13,
            "reference_views_use_no_bootstrap": True,
            "strict_policy": "non-ok records count wrong; valid-only metrics exclude them",
            "static_compile_error_policy": "compile_error is non-ok, never y_pred=0",
            "dynamic_clean_policy": "operational view counts clean as no-leak; conservative view abstains because coverage was not measured",
        },
        "pending": {
            "note": "This tool reproduces the historical 5-tool view only; round-2 LLM/hybrid/repair are in final_summary.json and LEADERBOARD.md.",
            "juliet_llm": {
                "status": "out_of_scope_for_this_historical_view",
                "slots": ["B5", "B4"],
                "reason": "MiMo Xiaomi postleakfix and hybrid v2 runs are in the final summary; DeepSeek B4 remains unavailable (401/402).",
            },
            "juliet_hybrid": {
                "status": "out_of_scope_for_this_historical_view",
                "slots": ["B6", "B7", "B8"],
                "reason": "B6/B7 are done in the final summary; B8 cascade remains planned.",
            },
            "tier_a_static_feasibility": {
                "status": "planned",
                "slot": "A4",
                "reason": "160 SecVulEval functions are fragments; no Tier A static F1 is reported",
            },
        },
        "limitations": [
            "Juliet is synthetic, single-CWE and template-based; these numbers do not extrapolate to real projects.",
            "Static compile errors are retained as non-ok; they are not scored as zero, and valid-only coverage is reported.",
            "The dynamic run has no line/branch coverage instrumentation; a clean result is not a verified true negative.",
            "The runtime-supported 178/128 population was defined with an LSan preflight, so ASan scores on that subset are largely circular; Valgrind and static are the informative comparisons.",
            "Only 29 test families; cluster bootstrap is descriptive, not a high-power inference.",
            "This historical view excludes round-2 LLM/hybrid/repair; see LEADERBOARD.md and final_summary.json for those runs.",
        ],
    }


def build_markdown(summary: Mapping[str, Any]) -> str:
    methods = summary["methods"]
    views = summary["views"]
    lines = [
        "# Tier B leaderboard: Juliet CWE-401",
        "",
        "> **Historical detailed view (5 traditional-tool runs).** The current integrated leaderboard, including the Juliet LLM postleakfix run, the 1,400-request hybrid v2 suite and repair, is [`LEADERBOARD.md`](LEADERBOARD.md); machine-readable integrated results are in [`final_summary.json`](final_summary.json).",
        "",
        f"- dataset: `{summary['dataset']['dataset_id']}`",
        f"- units SHA-256: `{summary['dataset']['sha256']}`",
        f"- frozen units: {summary['dataset']['unit_count']} (dev 60 / test 140), 100 groups, 42 families",
        f"- primary view: `{summary['primary_view']}` (test 140, frozen labels)",
        f"- primary runtime view: `{summary['primary_runtime_view']}` (test 128)",
        f"- generated: `{summary['generated_at']}`",
        "",
        "> Tier B only. Do not pool these rows with Tier A (SecVulEval) or rank across tiers.",
        "",
        "## 1. Primary: test 140, frozen Juliet labels",
        "",
    ]
    lines += _method_table(methods, views[PRIMARY_VIEW])
    lines += [
        "",
        "`compile/inconcl` is the count of `compile_error` / `inconclusive` records in the view.",
        "`macro-F1` is valid-only; `strict` counts every non-ok record as wrong. "
        "Static compile failures are in the denominator of `strict` but not of `macro-F1`, and are never rewritten as `y_pred=0`.",
        "Dynamic rows use the operational reading `clean = NO_LEAK_OBSERVED`; §3 gives the conservative view where clean is abstained.",
        "The static adapter's raw `end_to_end` view counts compile errors as 'no leak observed'; canonical `strict` counts them wrong. "
        "They are different views and must not be compared directly.",
        "",
        "### 1b. Wilson 95% intervals for proportions (test 140)",
        "",
        "| method | coverage | recall | specificity |",
        "| --- | --- | --- | --- |",
    ]
    for method in methods:
        block = views[PRIMARY_VIEW]["methods"].get(method["method_id"])
        if not block:
            continue
        scores = block["scores"]
        lines.append(
            f"| {method['name']} | {_wilson(scores, 'coverage')} | "
            f"{_wilson(scores, 'recall')} | {_wilson(scores, 'specificity')} |"
        )
    lines += [
        "",
        "Wilson intervals use valid predictions; specificity is undefined when no negative-class unit is valid.",
        "",
        "## 2. Primary sensitivity: test 128, runtime-supported labels",
        "",
        "Runtime-supported means bad units with an observed LSan leak, plus good units with no observed leak. "
        "The 12 test bad units without an observed leak are excluded here but remain in the primary table.",
        "",
    ]
    lines += _method_table(methods, views[PRIMARY_RUNTIME_VIEW])
    lines += [
        "",
        "> The runtime-supported population is defined by an LSan preflight. ASan/LSan scores on this subset are largely circular; "
        "Valgrind and static numbers are the informative ones.",
        "",
        "## 3. Dynamic conservative view (clean abstained)",
        "",
        "The dynamic run has no line/branch coverage instrumentation. A clean prediction is `NO_LEAK_OBSERVED`, not proof of safety. "
        "This view abstains on every clean prediction; negative-class units leave the valid set, so macro-F1 is undefined. "
        "Recall and precision remain detection-only, not a safety score.",
        "",
        "| method | view | n | valid | cov | TP | FP | FN | recall | precision | clean abstained | macro-F1 | policy |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for view_name in (PRIMARY_VIEW, PRIMARY_RUNTIME_VIEW):
        for method in methods:
            if method["family"] != "dynamic":
                continue
            block = views[view_name]["methods"].get(method["method_id"])
            if not block:
                continue
            conservative = block["conservative"]
            scores = conservative["scores"]
            lines.append(
                f"| {method['name']} | `{view_name}` | {scores['n']} | {scores['valid']} | "
                f"{_fmt(scores['coverage'])} | {scores['confusion']['tp']} | "
                f"{scores['confusion']['fp']} | {scores['confusion']['fn']} | "
                f"{_fmt(scores['recall'])} | {_fmt(scores['precision'])} | "
                f"{conservative['clean_abstained']} | {_fmt(scores['macro_f1'])} | "
                "clean=no-leak-observed, not TN |"
            )
    lines += [
        "",
        "## 4. Reference: all 200 frozen units",
        "",
    ]
    lines += _method_table(methods, views["all_all"])
    lines += [
        "",
        "## 5. Reference: all 178 runtime-supported units",
        "",
    ]
    lines += _method_table(methods, views["all_runtime"])
    lines += [
        "",
        "## 6. Reference: dev 60 (not a test set)",
        "",
    ]
    lines += _method_table(methods, views["dev_all"])
    lines += [
        "",
        "## 7. Exclusions and denominators",
        "",
        "| method | test n | valid | compile_error | inconclusive | timeout | tool_error | coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in methods:
        block = views[PRIMARY_VIEW]["methods"].get(method["method_id"])
        if not block:
            continue
        exclusions = block["exclusions"]
        lines.append(
            f"| {method['name']} | {block['scores']['n']} | {block['scores']['valid']} | "
            f"{exclusions['compile_error_count']} | {exclusions['inconclusive_count']} | "
            f"{exclusions['timeout_count']} | {exclusions['tool_error_count']} | "
            f"{_fmt(block['scores']['coverage'])} |"
        )
    lines += [
        "",
        "## 8. Cost and latency",
        "",
        "Local static/dynamic tools have `usd=null` and `cost_basis=local_compute`; they are not priced at zero. "
        "Wall time is per analysed unit from the source run, not a cloud bill.",
        "",
        "| method | view | wall total s | wall/unit s | p50 ms | p95 ms |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for method in methods:
        for view_name in (PRIMARY_VIEW, PRIMARY_RUNTIME_VIEW):
            block = views[view_name]["methods"].get(method["method_id"])
            if not block:
                continue
            cost = block["cost"]
            lines.append(
                f"| {method['name']} | `{view_name}` | {_fmt(cost.get('wall_s_sum'), 2)} | "
                f"{_fmt(cost.get('wall_s_per_unit'), 4)} | {_fmt(cost.get('latency_ms_p50'), 1)} | "
                f"{_fmt(cost.get('latency_ms_p95'), 1)} |"
            )
    lines += [
        "",
        "## 9. Pending methods (no numbers)",
        "",
        "| slot | method | status | reason |",
        "| --- | --- | --- | --- |",
        "| B4 | DeepSeek sanitized function view | `blocked_gate` | OpenCode 401 / official 402; no result |",
        "| B5 | MiMo sanitized function view | `out_of_scope_here` | Xiaomi official postleakfix result is in the final summary |",
        "| B6 | H1 static evidence + LLM | `out_of_scope_here` | done in final summary |",
        "| B7 | H2 dynamic evidence + LLM | `out_of_scope_here` | done in final summary |",
        "| B8 | H3 static -> dynamic -> LLM cascade | `planned` | not run |",
        "| B9 | leakage audit | `partial` | sanitizer/prompt audit passed; label-only baseline not run |",
        "| A4 | Tier A static feasibility | `planned` | 160 fragment functions; existing 3-snippet smoke is not a benchmark |",
        "",
        "## 10. What is not here",
        "",
        "- This historical tool does not include round-2 LLM/hybrid/repair runs. See `LEADERBOARD.md` §3–§4 and `final_summary.json`.",
        "- No Tier A static F1 is reported. The existing SecVulEval static activity is a 3-snippet feasibility smoke, not a benchmark.",
        "- No cross-tier pooled score, and no claim that Juliet performance transfers to real projects.",
        "",
        "## 11. Limitations",
        "",
    ]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs-root",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_b" / "juliet_cwe401"),
    )
    parser.add_argument(
        "--out-json",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_b_summary.json"),
    )
    parser.add_argument(
        "--out-md",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_b_leaderboard.md"),
    )
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    args = parser.parse_args(argv)

    root = Path(args.runs_root).resolve()
    run_dirs = sorted({path.parent for path in root.rglob("run_manifest.json")})
    if not run_dirs:
        sys.stderr.write(f"no run_manifest.json under {root}\n")
        return 2
    try:
        summary = build_summary(run_dirs, resamples=args.bootstrap, seed=args.seed)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"summary failed: {exc}\n")
        return 2
    summary["provenance"] = {
        "run_manifests": {
            str(path): sha256_file(path / "run_manifest.json") for path in run_dirs
        },
        "builder": "bench_tier_b_summary.py",
    }
    atomic_write_json(args.out_json, summary)
    atomic_write_text(args.out_md, build_markdown(summary))
    sys.stderr.write(f"wrote {args.out_json} and {args.out_md}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
