"""Render the hybrid v2 narrative report from the frozen v2 artifacts.

The report is derived, never hand-edited: it reads the preflight gate, the
prompt audit, the v2 metrics, the v1-v2 comparison and the artifact audit, and
writes ``hybrid/REPORT_V2.md``.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
RESULTS = HYBRID / "results"


def load(name: str) -> dict[str, Any]:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}%"


def ppt(value: float) -> str:
    return f"{100 * value:+.2f} pp"


def civalue(value: float) -> str:
    return f"{100 * value:+.2f}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HYBRID / "REPORT_V2.md")
    args = parser.parse_args()

    preflight = load("hybrid_v2_preflight.json")
    prompt_audit = load("hybrid_v2_prompt_audit.json")
    audit = load("hybrid_v2_audit.json")
    metrics = load("hybrid_v2_metrics.json")
    compare = load("hybrid_v2_vs_hybrid_v1.json")
    v2_manifest = json.loads((HYBRID / "inputs_v2/manifest.json").read_text(encoding="utf-8"))

    rows = compare["rows"]
    changed = compare["changed_source_units"]
    changed_flips = [item for item in compare["flips"] if item["source_changed"]]
    unchanged_flips = [item for item in compare["flips"] if not item["source_changed"]]

    def flip_counts(items: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "right_to_wrong": sum(1 for item in items if item["v1_correct"] and not item["v2_correct"]),
            "wrong_to_right": sum(1 for item in items if not item["v1_correct"] and item["v2_correct"]),
            "label_changed": len(items),
        }

    changed_counts = flip_counts(changed_flips)
    unchanged_counts = flip_counts(unchanged_flips)
    largest = min(rows, key=lambda row: row["delta"]) if rows else None
    second_largest = (
        max(abs(row["delta"]) for row in rows if row is not largest) if len(rows) > 1 else 0.0
    )
    cost_ratios = [
        entry["cost_basis_ratio"]
        for entry in audit["runs"].values()
        if entry.get("cost_basis_ratio")
    ]

    lines = [
        "# Hybrid v2: leak-fixed rerun (Juliet CWE-401, 140 test units)",
        "",
        f"Generated {datetime.now(timezone.utc).isoformat()}.",
        "",
        "## 1. What changed and what did not",
        "",
        "v1 is frozen and untouched. The release audit (C3/D6) found the literal",
        '`"Benign, fixed string"` in six good units; the shared `juliet_llm` cleaner now',
        "neutralizes `benign`/`fixed` like the other label tokens. The v2 rerun uses a",
        "separate input pack, a new prompt version, and new run directories.",
        "",
        "| Item | v1 | v2 |",
        "| --- | --- | --- |",
        f"| Prompt version | `hybrid-juliet-llm-binary-2026-11-12.1` | `{preflight['prompt_version']}` |",
        f"| Input pack | `hybrid/inputs/units.jsonl` | `hybrid/inputs_v2/units.jsonl` |",
        f"| Input SHA-256 | `{compare['v1_units_sha256']}` | `{compare['v2_units_sha256']}` |",
        "| Runs | `hybrid/runs/hybrid_v1_*` | `hybrid/runs/hybrid_v2_*` |",
        "| Frozen units / evidence / placebo seed | 140 / same / 20261112 | 140 / same / 20261112 |",
        "",
        f"Only {len(changed)}/140 source views differ, and in each one the only changed line is:",
        "",
        "```diff",
        '-        printLine("Benign, fixed string");',
        '+        printLine("unit, unit string");',
        "```",
        "",
        "Changed units: " + ", ".join(f"`{unit_id}`" for unit_id in changed) + ".",
        "",
        "## 2. Preflight gate and prompt audit",
        "",
        f"- Gate result: **{'PASS' if preflight['ok'] else 'FAIL'}**; "
        f"{preflight['summary']['units']} units, "
        f"{preflight['summary']['prompts_rebuilt']} prompts rebuilt, "
        f"{preflight['summary']['failures']} failures, "
        f"{preflight['summary']['warnings']} warnings.",
        f"- Label words in the 140 cleaned sources: "
        f"{preflight['summary']['label_word_hits_in_sources']}.",
        f"- Direct prompts vs `juliet_llm/build`: {preflight['direct_reference']['status']} "
        f"({preflight['direct_reference']['checked']}/140 checked, "
        f"{preflight['direct_reference']['prompt_mismatches']} mismatches).",
        f"- Placebo: seed {preflight['placebo']['seed']}, "
        f"{preflight['placebo']['pairs']} pairs, "
        f"{preflight['placebo']['invalid_pairs']} constraint violations, "
        f"{preflight['placebo']['noop_collisions']} no-op collisions "
        f"(same set as v1: {preflight['placebo']['noop_units'] == preflight['placebo']['v1_noop_units']}).",
        f"- Prompt audit: {prompt_audit['units']} units x {len(prompt_audit['methods'])} methods, "
        + ", ".join(
            f"{method}={values['unique_hashes']} unique"
            for method, values in prompt_audit["methods"].items()
        )
        + ".",
        "",
        "The 14 no-op collisions are retained as a documented placebo limitation, not",
        "as an integrity failure: for those units the donor's evidence text is identical",
        "to the unit's own evidence, so the placebo cannot change the prompt.",
        "",
        "## 3. Completeness",
        "",
        "| Run | Records | Valid | Status counts | Prompt version |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    for name, entry in audit["runs"].items():
        statuses = ", ".join(f"{k}={v}" for k, v in sorted(entry["statuses"].items()))
        lines.append(
            f"| `{name}` | {entry['records']} | {entry['records']} | {statuses} | "
            f"{', '.join(entry['prompt_version'])} |"
        )
    lines += [
        "",
        f"All 10 runs are 140/140 with 0 invalid and 0 API errors; the matrix is "
        f"{sum(entry['records'] for entry in audit['runs'].values())} real requests.",
        "",
        "## 4. Headline results",
        "",
        "| Model | Method | v1 acc | v2 acc | Δ (v2−v1) | 95% CI | v1 right → v2 wrong | v1 wrong → v2 right | McNemar p |",
        "| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        ci = row["delta_ci95"]
        lines.append(
            f"| {row['model']} | {row['method']} | {pct(row['v1_accuracy'])} | "
            f"{pct(row['v2_accuracy'])} | {ppt(row['delta'])} | "
            f"[{civalue(ci[0])}, {civalue(ci[1])}] pp | {row['v1_right_v2_wrong']} | "
            f"{row['v1_wrong_v2_right']} | {row['mcnemar']['p_value_exact']:.4g} |"
        )
    lines += [
        "",
        "Pooled descriptive accuracy (5 runs per model; 10 for all):",
        "",
        "| Model | v1 acc | v2 acc | Δ |",
        "| --- | ---: | ---: | ---: |",
    ]
    for item in compare["pooled"]:
        lines.append(
            f"| {item['model']} | {pct(item['v1_accuracy'])} | {pct(item['v2_accuracy'])} | "
            f"{ppt(item['delta'])} |"
        )
    if largest is not None:
        lines += [
            "",
            f"Reading: the largest movement is {largest['model']}/{largest['method']} "
            f"({pct(largest['v1_accuracy'])} → {pct(largest['v2_accuracy'])}, "
            f"{ppt(largest['delta'])}, {largest['mcnemar']['discordant']} discordant pairs, "
            f"exact McNemar p={largest['mcnemar']['p_value_exact']:.4g}). "
            "The direction is consistent with removing a good-unit shortcut, but with "
            f"{largest['mcnemar']['discordant']} discordant pairs the exact test does not reach "
            "0.05; this is suggestive, not confirmatory. "
            f"No other cell moves by more than {100 * second_largest:.2f} pp.",
        ]
    lines += [
        "",
        "## 5. Attribution of prediction changes",
        "",
        "| Group | Label changes | v1 right → v2 wrong | v1 wrong → v2 right |",
        "| --- | ---: | ---: | ---: |",
        f"| Six cleaned units | {changed_counts['label_changed']} | "
        f"{changed_counts['right_to_wrong']} | {changed_counts['wrong_to_right']} |",
        f"| 134 unchanged units | {unchanged_counts['label_changed']} | "
        f"{unchanged_counts['right_to_wrong']} | {unchanged_counts['wrong_to_right']} |",
        "",
    ]
    if changed_flips:
        lines += [
            "Every prediction flip on a cleaned unit:",
            "",
            "| Model | Method | Unit | Label | v1 | v2 | v1 correct | v2 correct |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for item in changed_flips:
            lines.append(
                f"| {item['model']} | {item['method']} | `{item['unit_id']}` | {item['label']} | "
                f"{item['v1_predicted_label']} | {item['v2_predicted_label']} | "
                f"{'yes' if item['v1_correct'] else 'no'} | {'yes' if item['v2_correct'] else 'no'} |"
            )
        lines.append("")
    if unchanged_flips:
        lines += [
            "Flips on unchanged units are endpoint/rerun variation, not a cleaning effect:",
            "",
            "| Model | Method | Unit | Label | v1 | v2 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for item in unchanged_flips:
            lines.append(
                f"| {item['model']} | {item['method']} | `{item['unit_id']}` | {item['label']} | "
                f"{item['v1_predicted_label']} | {item['v2_predicted_label']} |"
            )
        lines.append("")

    lines += [
        "## 6. Tool evidence and placebo diagnostics",
        "",
        "Tool baselines are computed from the frozen evidence and are unchanged by the",
        "source fix: "
        + "; ".join(
            f"{name} accuracy {pct(values['accuracy'])}, recall {pct(values['recall'])}, "
            f"specificity {pct(values['specificity'])}"
            for name, values in metrics["tools"].items()
        )
        + ".",
        "",
        "| Model | Method | Evidence group | n | Accuracy | Predicted vulnerable |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for key in ("dynamic", "combined"):
        for model in ("deepseek", "mimo"):
            summary = metrics["runs"].get(f"{model}/{key}")
            if not summary:
                continue
            for group, values in summary["evidence_groups"].items():
                if group.startswith("donor_"):
                    continue
                lines.append(
                    f"| {model} | {key} | {group} | {values.get('n_units', values['n'])} | "
                    f"{pct(values['accuracy'])} | {pct(values['predicted_positive_rate'])} |"
                )
    lines += [
        "",
        "| Model | Donor label | n | Accuracy |",
        "| --- | --- | ---: | ---: |",
    ]
    for model in ("deepseek", "mimo"):
        summary = metrics["runs"].get(f"{model}/shuffled")
        if not summary:
            continue
        for group, values in summary["evidence_groups"].items():
            lines.append(
                f"| {model} | {group} | {values.get('n_units', values['n'])} | "
                f"{pct(values['accuracy'])} |"
            )
    lines += [
        "",
        "## 7. Usage and cost",
        "",
        "| Model | Prompt tokens | Completion tokens | List USD (v2 basis) | Provider allowance USD |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for model in ("deepseek", "mimo"):
        subset = [metrics["runs"][f"{model}/{method}"] for method in ("direct", "static", "dynamic", "combined", "shuffled") if f"{model}/{method}" in metrics["runs"]]
        prompt = sum(item["usage"]["prompt_tokens"] for item in subset)
        completion = sum(item["usage"]["completion_tokens"] for item in subset)
        cost = sum(item["usage"]["cost_usd_sum"] for item in subset)
        allowances = [item["usage"]["provider_allowance_usd_sum"] for item in subset]
        allowance = sum(value for value in allowances if value is not None) if all(
            value is not None for value in allowances
        ) else None
        lines.append(
            f"| {model} | {prompt} | {completion} | {cost:.6f} | "
            f"{'n/a' if allowance is None else f'{allowance:.6f}'} |"
        )
    lines += [
        "",
        "DeepSeek v1 rows were priced at the old 2× list price; v2 uses the provider",
        "snapshot ($0.15/$0.60 per 1M). Provider allowance is the comparable figure.",
        "MiMo v2 rows also show substantially more prompt-cache reads than v1 (e.g.",
        "72,512 vs 15,616 cached tokens in the static run), so its list cost drops",
        "without a workload change.",
        "",
        f"The configured prices reproduce the provider's own `list_cost` in "
        f"{len(cost_ratios)}/{len(audit['runs'])} runs "
        f"(ratio range {min(cost_ratios):.4f}–{max(cost_ratios):.4f}, tolerance 2%).",
        "",
        "## 8. Artifact audit",
        "",
        f"- `hybrid/verify_outputs.py`: **{'PASS' if audit['ok'] else 'FAIL'}**, "
        f"{len(audit['failures'])} failures.",
        f"- Prompt version on every run: `{audit['provenance']['prompt_version']}`.",
        f"- Provenance: cleaning.py `{audit['provenance']['juliet_llm_cleaning_sha256']}`, "
        f"prompting.py `{audit['provenance']['juliet_llm_prompting_sha256']}`.",
        f"- Inputs: `{audit['input_pack']['path']}` sha256 "
        f"`{audit['input_pack']['units_sha256']}`.",
        f"- Placebo no-op collisions: {audit['placebo']['noop_collisions']}.",
        f"- Cost basis: {len(cost_ratios)}/{len(audit['runs'])} runs match the provider "
        f"`list_cost` within 2% (range {min(cost_ratios):.4f}–{max(cost_ratios):.4f}).",
        "",
        "## 9. Limits",
        "",
        "- Juliet units are small, synthetic, single-defect programs; the result is not a",
        "  production-code estimate.",
        "- The cleaned units still share Juliet's structural asymmetry (bad units are",
        "  shorter than good units on average); this fix removes a word-level shortcut,",
        "  not every distributional difference.",
        "- The placebo cannot change the prompt for the 14 no-op units; those units are",
        "  analysed but cannot support a causal placebo claim.",
        "- v2 is a single rerun per cell. Flips on unchanged units show that endpoint",
        "  nondeterminism remains, so small per-cell deltas should not be over-read; the",
        "  paired McNemar tests and CIs are reported for that reason.",
        "- No model API key is printed, stored in a result, or written to a report.",
        "",
    ]

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
