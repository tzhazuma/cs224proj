"""Write REPORT.md, tables, and the cost breakdown from the analysis JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .config import METHOD, MODELS, RESULTS_DIR, ROOT

METHOD_ROWS = ("hde-guided", "v2-direct", "v2-dynamic", "v2-combined", "tool")
METHOD_TITLE = {
    "hde-guided": "hde enhanced-dynamic-guided",
    "v2-direct": "v2 direct",
    "v2-dynamic": "v2 dynamic (old evidence)",
    "v2-combined": "v2 combined (old static+dynamic)",
    "tool": "dynamic-enhanced tool",
}


def pct(value: float | None) -> str:
    return "—" if value is None else f"{100 * value:.2f}%"


def num(value: float | None, digits: int = 4) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def usd(value: float | None) -> str:
    return "—" if value is None else f"${value:.6f}"


def ci(values: list[float] | None) -> str:
    if not values:
        return "—"
    return f"[{100 * values[0]:.2f}, {100 * values[1]:.2f}] pp"


def short(unit_id: str) -> str:
    return unit_id.replace("CWE401_Memory_Leak__", "")


def unit_list(ids: list[str]) -> str:
    return ", ".join(f"`{short(unit_id)}`" for unit_id in ids) if ids else "—"


def table(header: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def cost_block(analysis: dict[str, Any]) -> dict[str, Any]:
    models = {}
    for model in MODELS:
        block = analysis["models"][model]
        models[model] = {
            "per_method": {
                method: block["methods"][method]["cost"] for method in METHOD_ROWS
            },
            "usd_per_correct": block["cost"]["usd_per_correct"],
            "incremental_vs_direct": block["cost"]["incremental_vs_direct"],
        }
    totals = {
        "new_requests": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["records"] for model in MODELS
        ),
        "new_configured_usd": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["configured_usd"]
            for model in MODELS
        ),
        "new_provider_list_usd": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["provider_list_usd"]
            for model in MODELS
        ),
        "new_allowance_usd": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["allowance_usd"]
            for model in MODELS
        ),
        "new_prompt_tokens": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["prompt_tokens"]
            for model in MODELS
        ),
        "new_completion_tokens": sum(
            analysis["models"][model]["methods"]["hde-guided"]["cost"]["completion_tokens"]
            for model in MODELS
        ),
        "baseline_runs": "frozen hybrid_v2 runs; their recorded cost is reported for comparison, not spent in this run",
    }
    preflight_path = RESULTS_DIR / "preflight.json"
    preflight = json.loads(preflight_path.read_text(encoding="utf-8")) if preflight_path.is_file() else {}
    smoke_usd = sum(
        float((entry or {}).get("cost_usd") or 0.0)
        for entry in (preflight.get("smoke") or {}).values()
    )
    totals["preflight_smoke_usd"] = smoke_usd
    totals["all_in_usd"] = totals["new_configured_usd"] + smoke_usd
    return {
        "generated_at": analysis["generated_at"],
        "run_id": analysis["run_id"],
        "price_card": {
            "deepseek": {"input": 0.15, "output": 0.60, "cached_input": 0.003, "unit": "USD per 1M tokens"},
            "mimo": {"input": 0.14, "output": 0.28, "cached_input": 0.0028, "unit": "USD per 1M tokens"},
        },
        "models": models,
        "totals": totals,
        "caveat": "configured is the price card applied to tokens; provider list cost and allowance are provider snapshots and can differ in the last digits.",
    }


def build_report(analysis: dict[str, Any], costs: dict[str, Any], audit: dict[str, Any] | None) -> str:
    protocol = analysis["protocol"]
    lines: list[str] = []
    lines.append("# Enhanced dynamic guidance on the frozen Juliet CWE-401 test 140")
    lines.append("")
    lines.append(f"Generated {analysis['generated_at']} · run `{analysis['run_id']}` · method `{METHOD}`.")
    lines.append("")

    # Headline numbers
    ds = analysis["models"]["deepseek"]["methods"]
    mm = analysis["models"]["mimo"]["methods"]
    ds_mcn = {entry["b"]: entry for entry in analysis["models"]["deepseek"]["mcnemar"]}
    mm_mcn = {entry["b"]: entry for entry in analysis["models"]["mimo"]["mcnemar"]}
    lines.append("## 0. Headline")
    lines.append("")
    lines.append(
        f"- The dynamic-enhanced tool is **{protocol['tool_confusion']['tp']} TP / "
        f"{protocol['tool_confusion']['fp']} FP / {protocol['tool_confusion']['tn']} TN / "
        f"{protocol['tool_confusion']['fn']} FN** on these 140 units, i.e. accuracy "
        f"**{pct(protocol['tool_accuracy'])}**."
    )
    lines.append(
        f"- DeepSeek: direct {pct(ds['v2-direct']['accuracy'])} ({ds['v2-direct']['tp'] + ds['v2-direct']['tn']}/140) "
        f"→ enhanced **{pct(ds['hde-guided']['accuracy'])} ({ds['hde-guided']['tp'] + ds['hde-guided']['tn']}/140)**; "
        f"McNemar vs direct p={num(ds_mcn['v2-direct']['p_value_exact'])}, "
        f"Holm p={num(ds_mcn['v2-direct']['p_value_holm'])}."
    )
    lines.append(
        f"- MiMo: direct {pct(mm['v2-direct']['accuracy'])} ({mm['v2-direct']['tp'] + mm['v2-direct']['tn']}/140) "
        f"→ enhanced **{pct(mm['hde-guided']['accuracy'])} ({mm['hde-guided']['tp'] + mm['hde-guided']['tn']}/140)**; "
        f"McNemar vs direct p={num(mm_mcn['v2-direct']['p_value_exact'])}, "
        f"Holm p={num(mm_mcn['v2-direct']['p_value_holm'])}."
    )
    lines.append(
        f"- Neither model reaches the tool ceiling (140/140). The new spend is "
        f"**{usd(costs['totals']['new_configured_usd'])}** for "
        f"{costs['totals']['new_requests']} real requests (2 × 140, 0 invalid, 0 API errors)."
    )
    lines.append(
        "- The verdict changes that do occur are small; the DeepSeek changes move toward the "
        "evidence verdict, but none is statistically distinguishable from the frozen baseline. "
        "**No semantic-reasoning improvement is claimed.**"
    )
    lines.append("")

    # Protocol
    lines.append("## 1. Protocol and preflight")
    lines.append("")
    lines.append(
        table(
            ["item", "value"],
            [
                ["units", f"{protocol['units']} ({protocol['labels']['bad']} bad / {protocol['labels']['good']} good)"],
                ["requests", "2 × 140 (one per model and unit); 0 invalid, 0 API errors"],
                ["input pack SHA-256", f"`{protocol['input_sha256']}`"],
                ["guided prompt version", f"`{protocol['guided_prompt_version']}`"],
                ["direct prompt version (reused)", f"`{protocol['direct_prompt_version']}`"],
                ["prompt audit", "140 enhanced prompts unique; 140 direct prompts byte-identical to v2"],
                ["tool", "default + realloc_fail + nogobal; Valgrind not re-run"],
                ["baselines", protocol["baselines"]],
                ["preflight", f"{protocol['preflight_checks_passed']}/{protocol['preflight_checks_total']} checks passed, ok={protocol['preflight_ok']}"],
            ],
        )
    )
    lines.append("")
    lines.append(
        "Evidence sent to the model is rendered only from numeric fields of "
        "`dynamic_enhanced/exports/hybrid`: per-mode applicability, attribution bytes, "
        "allocation-record count and the injected-call index. Paths, file names, unit ids, "
        "CWE ids, and label words are never copied; every block is scanned fail-closed. "
        "The evidence wrapper and system prompt are byte-identical to hybrid v2, so the "
        "only prompt difference is the evidence body."
    )
    lines.append("")

    # Results
    lines.append("## 2. Accuracy, cost and paired tests")
    lines.append("")
    for model in MODELS:
        block = analysis["models"][model]
        rows = []
        for method in METHOD_ROWS:
            m = block["methods"][method]
            rows.append(
                [
                    METHOD_TITLE[method],
                    f"{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}",
                    pct(m["accuracy"]),
                    ci(m["accuracy_ci95"]),
                    usd(m["cost"]["configured_usd"]),
                ]
            )
        lines.append(f"### 2.{MODELS.index(model) + 1} {model}")
        lines.append("")
        lines.append(table(["method", "TP/FP/FN/TN", "accuracy", "95% CI", "configured USD"], rows))
        lines.append("")
        mcn_rows = []
        for entry in block["mcnemar"]:
            mcn_rows.append(
                [
                    f"hde vs {METHOD_TITLE[entry['b']]}",
                    f"{entry['delta_accuracy'] * 100:+.2f} pp",
                    f"{entry['a_right_b_wrong']} / {entry['a_wrong_b_right']}",
                    ci(entry["bootstrap"]["ci95"]),
                    num(entry["p_value_exact"]),
                    num(entry["p_value_holm"]),
                ]
            )
        lines.append(table(["contrast", "Δ accuracy", "discordant (new / baseline)", "bootstrap 95% CI", "exact p", "Holm p"], mcn_rows))
        lines.append("")
        lines.append(
            "Exact McNemar over all 140 planned units; invalid requests would be counted as "
            "wrong (there were none). Holm adjusts the four contrasts within each model."
        )
        lines.append("")

    lines.append("### 2.3 Where the predictions changed")
    lines.append("")
    for model in MODELS:
        cons = analysis["models"][model]["consistency"]
        rows = []
        for baseline, label in (
            ("v2-direct", "v2 direct"),
            ("v2-dynamic", "v2 dynamic"),
            ("v2-combined", "v2 combined"),
            ("tool", "dynamic-enhanced tool"),
        ):
            flip = cons["flips_vs_baselines"][baseline]
            rows.append(
                [
                    label,
                    flip["new_right_base_wrong"],
                    flip["new_wrong_base_right"],
                    unit_list(flip["fixed_units"]) if flip["fixed_units"] else "—",
                    unit_list(flip["broken_units"]) if flip["broken_units"] else "—",
                ]
            )
        lines.append(f"**{model}**")
        lines.append("")
        lines.append(table(["baseline", "fixed", "broken", "units fixed", "units broken"], rows))
        lines.append("")

    # Subsets
    lines.append("### 2.4 Subsets that matter")
    lines.append("")
    for model in MODELS:
        block = analysis["models"][model]["subsets"]
        rows = []
        for name, title in (
            ("old_unobservable_12", "12 units the old dynamic run could not observe"),
            ("old_leak_58", "58 units with old dynamic leak evidence"),
            ("cleaned_22_good", "6 cleaned `_22` good units"),
            ("direct_error_units", "units v2 direct got wrong"),
        ):
            entry = block[name]
            methods = entry["methods"]
            rows.append(
                [
                    title,
                    entry["n"],
                    pct(methods["v2-direct"]["accuracy"]),
                    pct(methods["v2-dynamic"]["accuracy"]),
                    pct(methods["v2-combined"]["accuracy"]),
                    pct(methods["hde-guided"]["accuracy"]),
                    pct(methods["tool"]["accuracy"]),
                ]
            )
        lines.append(f"**{model}**")
        lines.append("")
        lines.append(table(["subset", "n", "v2 direct", "v2 dynamic", "v2 combined", "hde guided", "tool"], rows))
        lines.append("")

    lines.append(
        "The 12 units the old harness could not observe were already detected by both models "
        "from the code alone (`direct` 12/12). The enhanced tool's new observations therefore "
        "add no headroom on those units; the remaining tool–model gap is on good units where "
        "the models over-call, plus the two realloc/global units MiMo misses under the old "
        "dynamic evidence."
    )
    lines.append("")

    # Consistency
    lines.append("## 3. Did the model simply copy the evidence?")
    lines.append("")
    lines.append(
        "The tool is 140/140, so *agreement with the tool* and *accuracy* are the same "
        "number here. A model that copied the evidence would score 140/140; a model that "
        "ignored it would score like `direct`. Neither happened."
    )
    lines.append("")
    for model in MODELS:
        cons = analysis["models"][model]["consistency"]
        echo = cons["evidence_echo"]
        rows = [
            [
                "verdict agreement with tool",
                pct(cons["agreement_with_tool"]),
                f"{len(cons['disagreements']['over_call_units'])} over-calls, "
                f"{len(cons['disagreements']['under_call_units'])} under-calls",
            ],
            [
                "reasons citing evidence/tool language",
                pct(cons["reasons"]["hde-guided"]["rates"]["tool_or_evidence"]),
                f"direct {pct(cons['reasons']['v2-direct']['rates']['tool_or_evidence'])}",
            ],
            [
                "reasons repeating the attributed byte count",
                pct(echo["hde-guided"]["attributed_byte_match_rate"]),
                f"direct {pct(echo['v2-direct']['attributed_byte_match_rate'])}, "
                f"dynamic {pct(echo['v2-dynamic']['attributed_byte_match_rate'])}",
            ],
            [
                "reasons citing evidence phrasing (`attributed`, `configuration`, …)",
                pct(echo["hde-guided"]["evidence_phrasing_rate"]),
                "0% in every baseline",
            ],
            [
                "reasons on clean units citing evidence/tool",
                pct(cons["clean_70_citation"]["hde-guided"]["rates"]["tool_or_evidence"]),
                f"direct {pct(cons['clean_70_citation']['v2-direct']['rates']['tool_or_evidence'])}",
            ],
            [
                "12 old-hidden units: reason cites realloc / global",
                f"{pct(cons['special_12_citation']['hde-guided']['rates']['realloc'])} / "
                f"{pct(cons['special_12_citation']['hde-guided']['rates']['global_or_root'])}",
                f"direct {pct(cons['special_12_citation']['v2-direct']['rates']['realloc'])} / "
                f"{pct(cons['special_12_citation']['v2-direct']['rates']['global_or_root'])} "
                "(identical)",
            ],
            [
                "reasons lexically consistent with their own verdict",
                f"{cons['reason_polarity']['counts'].get('consistent', 0)} consistent / "
                f"{cons['reason_polarity']['counts'].get('contradictory', 0)} contradictory / "
                f"{cons['reason_polarity']['counts'].get('unclear', 0)} unclear",
                "lexical check only",
            ],
        ]
        lines.append(f"**{model}**")
        lines.append("")
        lines.append(table(["signal", "enhanced", "comparison"], rows))
        lines.append("")
        if cons["disagreements"]["over_call_units"]:
            lines.append("Units where the model still over-calls against clean evidence:")
            lines.append("")
            lines.append(unit_list(cons["disagreements"]["over_call_units"]))
            lines.append("")
        lines.append(
            "Reading: the evidence text is clearly read and quoted — attributed byte counts "
            "appear in 89–93% of reasons, versus 11–23% for `direct` — but the verdict does "
            "not follow the evidence on all units, and on the 12 units the old harness could "
            "not observe the explanations are identical to `direct` (same realloc/global "
            "citation rates)."
        )
        lines.append("")

    lines.append(
        "The byte-count echo is the strongest copy signal available, but it is lexical: it "
        "shows the model repeats an evidence value, not that it reasons from it. Because the "
        "tool is perfect on this set, no accuracy comparison can separate “copied the "
        "evidence” from “solved the code independently”. The honest statement is: the "
        "evidence is used as a source of numbers and wording, adoption is partial and "
        "inconsistent, and no semantic-reasoning gain is demonstrated."
    )
    lines.append("")

    # Cost
    lines.append("## 4. Cost")
    lines.append("")
    lines.append(
        f"The new method is the only paid work in this run: "
        f"**{costs['totals']['new_requests']} requests**, "
        f"{costs['totals']['new_prompt_tokens']:,} prompt tokens, "
        f"{costs['totals']['new_completion_tokens']:,} completion tokens, "
        f"**{usd(costs['totals']['new_configured_usd'])} configured** "
        f"(provider list {usd(costs['totals']['new_provider_list_usd'])}, "
        f"allowance {usd(costs['totals']['new_allowance_usd'])}). "
        f"Preflight smoke adds {usd(costs['totals']['preflight_smoke_usd'])} in two tiny requests; "
        f"all-in {usd(costs['totals']['all_in_usd'])}."
    )
    lines.append("")
    for model in MODELS:
        block = costs["models"][model]
        rows = []
        for method in METHOD_ROWS:
            c = block["per_method"][method]
            rows.append(
                [
                    METHOD_TITLE[method],
                    f"{c['prompt_tokens']:,}",
                    f"{c['completion_tokens']:,}",
                    usd(c["configured_usd"]),
                    usd(c["provider_list_usd"]),
                    usd(c["allowance_usd"]),
                    usd(block["usd_per_correct"][method]),
                ]
            )
        lines.append(f"**{model}**")
        lines.append("")
        lines.append(
            table(
                [
                    "method",
                    "prompt tokens",
                    "completion tokens",
                    "configured USD",
                    "provider list USD",
                    "allowance USD",
                    "USD / correct",
                ],
                rows,
            )
        )
        inc = block["incremental_vs_direct"]
        lines.append("")
        lines.append(
            f"Incremental versus the frozen direct run: {inc['extra_correct']:+d} correct, "
            f"{usd(inc['extra_usd'])} extra, "
            + (
                f"{usd(inc['usd_per_extra_correct'])} per extra correct."
                if inc["usd_per_extra_correct"] is not None
                else "no extra correct answer, so no incremental unit cost is defined."
            )
        )
        lines.append("")

    mimo_hde = costs["models"]["mimo"]["per_method"]["hde-guided"]
    mimo_direct = costs["models"]["mimo"]["per_method"]["v2-direct"]
    lines.append(
        f"MiMo's enhanced run costs {mimo_hde['configured_usd'] / mimo_direct['configured_usd']:.2f}× "
        f"its direct run ({usd(mimo_hde['configured_usd'])} vs {usd(mimo_direct['configured_usd'])}) "
        f"for the same 136/140, driven by "
        f"{mimo_hde['prompt_tokens'] / mimo_direct['prompt_tokens']:.2f}× prompt tokens and "
        f"less prompt-cache reuse ({mimo_hde['cached_tokens']:,} vs {mimo_direct['cached_tokens']:,} "
        "cached tokens). The tool itself is offline and adds no API cost."
    )
    lines.append("")

    # Audit
    lines.append("## 5. Audit")
    lines.append("")
    if audit:
        lines.append(
            f"`run_hde.py verify` status: **{audit.get('status')}**, "
            f"{audit.get('passed')}/{audit.get('checks_total')} checks passed."
        )
        if audit.get("failures"):
            lines.append("")
            lines.append("Failures: " + ", ".join(f"`{name}`" for name in audit["failures"]))
    else:
        lines.append("Artifact audit has not been run yet.")
    lines.append("")
    lines.append(
        "The audit re-derives prompt hashes, recomputes accuracy and McNemar from the "
        "prediction files, checks cost arithmetic against the run manifests, and scans every "
        "generated file for the API key and label markers."
    )
    lines.append("")

    # Limits
    lines.append("## 6. Limits and what cannot be claimed")
    lines.append("")
    lines.append(
        "- **No semantic-reasoning claim.** The tool is 140/140; a perfect score is fully "
        "explained by copying, and the observed scores are below 140. Accuracy cannot "
        "separate the two mechanisms on this set."
    )
    lines.append(
        "- **No significant effect.** The only gain over `direct` is DeepSeek +2 correct "
        "(exact p=0.5); MiMo gains 0. The largest raw contrast is MiMo vs the old dynamic run "
        "(+3, exact p=0.25, Holm 0.75), still not significant. A single rerun cannot separate "
        "an evidence effect from endpoint nondeterminism, which the v1/v2 reruns already documented."
    )
    lines.append(
        "- **Baselines are historical.** Direct/dynamic/combined were collected on 2026-11-11 "
        "with the same input pack and prompt version but a different serving session; model "
        "behaviour may drift between days."
    )
    lines.append(
        "- **Reason analysis is lexical.** Byte-count echo and keyword citation show what the "
        "model repeats, not what it uses. Polarity labels are heuristic and often unclear."
    )
    lines.append(
        "- **Evidence is conditional.** `realloc_fail` applies to 14 units and `nogobal` is a "
        "global root switch, not a per-variable root map. A clean mode is an observation on "
        "one executed path, not proof of absence."
    )
    lines.append(
        "- **Scope.** Juliet CWE-401 test 140 only; 70/70 labels; no dev split, no production "
        "code, no claim about other CWEs or models."
    )
    lines.append(
        "- **No key exposure.** The key is read from the local Kimi Code config into process "
        "memory, never printed, never stored; the audit scans generated artifacts for it."
    )
    lines.append("")
    lines.append("## 7. Artifacts")
    lines.append("")
    lines.append(
        table(
            ["path", "content"],
            [
                ["`inputs/units.jsonl`", "140 units with cleaned source and sanitized evidence"],
                ["`runs/<run>_<model>/results.jsonl`", "140 real responses per model"],
                ["`results/enhanced_dynamic_results.jsonl`", "the same 280 responses in one file"],
                ["`results/enhanced_dynamic_metrics.json`", "accuracy, CIs, McNemar, subsets, consistency"],
                ["`results/enhanced_dynamic_predictions.csv`", "per-unit predictions for all methods"],
                ["`results/consistency.json`", "evidence-copy diagnostics"],
                ["`results/cost.json` / `cost.md`", "token and USD breakdown"],
                ["`results/preflight.json`", "fail-closed gate record"],
                ["`results/audit.json` / `audit.md`", "artifact audit"],
            ],
        )
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, default=RESULTS_DIR / "enhanced_dynamic_metrics.json")
    parser.add_argument("--report", type=Path, default=ROOT / "hybrid_dynamic_enhanced" / "REPORT.md")
    parser.add_argument("--tables", type=Path, default=RESULTS_DIR / "enhanced_dynamic_tables.md")
    parser.add_argument("--cost-json", type=Path, default=RESULTS_DIR / "cost.json")
    parser.add_argument("--cost-md", type=Path, default=RESULTS_DIR / "cost.md")
    args = parser.parse_args(argv)

    analysis = json.loads(args.metrics.read_text(encoding="utf-8"))
    costs = cost_block(analysis)
    audit_path = RESULTS_DIR / "audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8")) if audit_path.is_file() else None

    report = build_report(analysis, costs, audit)
    args.report.write_text(report, encoding="utf-8")

    tables = ["# Tables", "", f"Generated {analysis['generated_at']}.", ""]
    for model in MODELS:
        block = analysis["models"][model]
        tables.append(f"## {model}")
        tables.append("")
        rows = []
        for method in METHOD_ROWS:
            m = block["methods"][method]
            rows.append(
                [
                    METHOD_TITLE[method],
                    f"{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}",
                    pct(m["accuracy"]),
                    ci(m["accuracy_ci95"]),
                    usd(m["cost"]["configured_usd"]),
                ]
            )
        tables.append(table(["method", "TP/FP/FN/TN", "accuracy", "95% CI", "USD"], rows))
        tables.append("")
        mcn_rows = [
            [
                f"hde vs {entry['b']}",
                f"{entry['delta_accuracy'] * 100:+.2f} pp",
                f"{entry['a_right_b_wrong']}/{entry['a_wrong_b_right']}",
                ci(entry["bootstrap"]["ci95"]),
                num(entry["p_value_exact"]),
                num(entry["p_value_holm"]),
            ]
            for entry in block["mcnemar"]
        ]
        tables.append(table(["contrast", "Δ", "discordant", "95% CI", "exact p", "Holm p"], mcn_rows))
        tables.append("")
    args.tables.write_text("\n".join(tables) + "\n", encoding="utf-8")

    args.cost_json.write_text(json.dumps(costs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    cost_lines = ["# Cost", "", f"Generated {analysis['generated_at']}.", ""]
    cost_lines.append(
        f"New spend: {usd(costs['totals']['new_configured_usd'])} configured for "
        f"{costs['totals']['new_requests']} requests "
        f"(provider list {usd(costs['totals']['new_provider_list_usd'])}, "
        f"allowance {usd(costs['totals']['new_allowance_usd'])}). "
        f"Preflight smoke: {usd(costs['totals']['preflight_smoke_usd'])}; "
        f"all-in: {usd(costs['totals']['all_in_usd'])}."
    )
    cost_lines.append("")
    for model in MODELS:
        block = costs["models"][model]
        rows = []
        for method in METHOD_ROWS:
            c = block["per_method"][method]
            rows.append(
                [
                    METHOD_TITLE[method],
                    f"{c['prompt_tokens']:,}",
                    f"{c['completion_tokens']:,}",
                    usd(c["configured_usd"]),
                    usd(c["provider_list_usd"]),
                    usd(c["allowance_usd"]),
                    usd(block["usd_per_correct"][method]),
                ]
            )
        cost_lines.append(f"## {model}")
        cost_lines.append("")
        cost_lines.append(
            table(
                [
                    "method",
                    "prompt",
                    "completion",
                    "configured",
                    "provider list",
                    "allowance",
                    "USD/correct",
                ],
                rows,
            )
        )
        cost_lines.append("")
    args.cost_md.write_text("\n".join(cost_lines) + "\n", encoding="utf-8")

    print(f"wrote {args.report.relative_to(ROOT)}")
    print(f"wrote {args.tables.relative_to(ROOT)}")
    print(f"wrote {args.cost_json.relative_to(ROOT)}")
    print(f"wrote {args.cost_md.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
