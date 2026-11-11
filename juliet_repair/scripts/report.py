#!/usr/bin/env python3
"""Aggregate one or two repair runs into honest Markdown/JSON reports."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import repair_lib as rl  # noqa: E402

REPORT = rl.ROOT / "report"


def load_run(run_dir: Path) -> dict:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    results = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((run_dir / "units").glob("*/result.json"))
    ]
    baselines = {}
    for path in (rl.BUILD / "baselines").glob("*/baseline.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        baselines[path.parent.name] = doc
    return {"manifest": manifest, "results": results, "baselines": baselines, "run_dir": run_dir}


def attempt_eval(result: dict, index: int) -> dict:
    attempts = result.get("attempts") or []
    if index < len(attempts):
        return attempts[index].get("evaluation") or {}
    return {}


def summarize(run: dict) -> dict:
    results = run["results"]
    baselines = run["baselines"]
    total = len(results)
    leak_observable = [
        r for r in results if baselines.get(r["unit_key"], {}).get("bad", {}).get("leak_detected")
    ]
    nonleak = [
        r for r in results if not baselines.get(r["unit_key"], {}).get("bad", {}).get("leak_detected")
    ]
    first = [attempt_eval(r, 0) for r in results]
    final = [
        {"compile_pass": r.get("compile_pass"), "leak_removed": r.get("leak_removed"),
         "behavior_preserved": r.get("behavior_preserved"), "strict_pass": r.get("strict_pass")}
        for r in results
    ]
    calls = [call for r in results for call in (r.get("attempts") or [])]
    parse_failures = [
        call for call in calls if call.get("parse_error") and call.get("parse_error") != "api_error"
    ]
    api_errors = [call for call in calls if call.get("parse_error") == "api_error"]
    iterations = [r for r in results if len(r.get("attempts") or []) > 1]
    schema_iterations = []
    runtime_iterations = []
    for result in iterations:
        request_path = (
            run["run_dir"] / "units" / result["unit_key"] / "attempt2" / "request.json"
        )
        feedback = ""
        if request_path.exists():
            messages = json.loads(request_path.read_text(encoding="utf-8")).get("messages", [])
            if messages:
                feedback = messages[-1].get("content", "")
        if "rejected by the harness" in feedback:
            schema_iterations.append(result)
        else:
            runtime_iterations.append(result)
    runtime_recovered = [
        result for result in runtime_iterations if result.get("strict_pass")
    ]

    def count(rows, key):
        return sum(1 for row in rows if row.get(key))

    observable_first = [
        attempt_eval(r, 0) for r in results if r in leak_observable
    ]
    observable_final = [
        {"compile_pass": r.get("compile_pass"), "leak_removed": r.get("leak_removed"),
         "behavior_preserved": r.get("behavior_preserved"), "strict_pass": r.get("strict_pass")}
        for r in leak_observable
    ]
    summary = {
        "run_id": run["manifest"].get("run_id"),
        "model": run["manifest"].get("model"),
        "units": total,
        "calls": len(calls),
        "iterated_units": len(iterations),
        "iterations_schema": len(schema_iterations),
        "iterations_runtime": len(runtime_iterations),
        "iterations_runtime_recovered": len(runtime_recovered),
        "parse_rejections": len(parse_failures),
        "api_errors": len(api_errors),
        "leak_observable": len(leak_observable),
        "non_leak_observable": len(nonleak),
        "first_attempt_compile": count(first, "compile_pass"),
        "first_attempt_leak_removed": count(first, "leak_removed"),
        "first_attempt_behavior": count(first, "behavior_preserved"),
        "first_attempt_strict": count(first, "strict_pass"),
        "compile_pass": count(final, "compile_pass"),
        "leak_removed": count(final, "leak_removed"),
        "behavior_preserved": count(final, "behavior_preserved"),
        "strict_pass": count(final, "strict_pass"),
        "compile_pass_observable": count(observable_final, "compile_pass"),
        "leak_removed_observable": count(observable_final, "leak_removed"),
        "behavior_preserved_observable": count(observable_final, "behavior_preserved"),
        "strict_pass_observable": count(observable_final, "strict_pass"),
        "strict_pass_first_observable": count(observable_first, "strict_pass"),
        "cost_usd": round(sum(r.get("cost_usd_sum") or 0.0 for r in results), 8),
        "cost_complete": all(r.get("cost_complete", True) for r in results),
        "prompt_tokens": sum(r.get("prompt_tokens_sum") or 0 for r in results),
        "completion_tokens": sum(r.get("completion_tokens_sum") or 0 for r in results),
        "final_parse_errors": count(results, "final_parse_error"),
        "schema_strict_units": count(results, "schema_strict"),
        "explanation_present_units": count(results, "explanation_present"),
        "errors": count(results, "final_parse_error")
        + sum(1 for r in results if r.get("error")),
        "nonleak_units": [r["unit_id"] for r in nonleak],
    }
    return summary


def failure_rows(run: dict) -> list[dict]:
    rows = []
    for result in run["results"]:
        if not result.get("strict_pass"):
            final = attempt_eval(result, len(result.get("attempts") or []) - 1)
            rows.append(
                {
                    "unit": result["unit_key"],
                    "unit_id": result["unit_id"],
                    "attempts": len(result.get("attempts") or []),
                    "compile": result.get("compile_pass"),
                    "leak": result.get("leak_removed"),
                    "behavior": result.get("behavior_preserved"),
                    "observable": result.get("behavior_observable"),
                    "parse_error": result.get("final_parse_error"),
                    "changed": result.get("changed_paths"),
                    "summary": (final.get("run") or {}).get("summary"),
                }
            )
    return rows


def case_patch(run_dir: Path, unit_key: str, attempt: int, max_lines: int = 60) -> str:
    path = run_dir / "units" / unit_key / f"attempt{attempt}" / "patch.diff"
    if not path.exists():
        return "(no patch)"
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["... (truncated)"]
    return "```diff\n" + "\n".join(lines) + "\n```"


def report_one(run: dict, summary: dict, out: Path) -> None:
    manifest = run["manifest"]
    lines = [
        f"# Juliet CWE-401 repair: {summary['model']}",
        "",
        f"- run: `{summary['run_id']}`",
        f"- model: `{summary['model']}`",
        f"- units: {summary['units']} frozen `split=test, label=bad` groups",
        f"- API calls: {summary['calls']} (initial + at most one feedback iteration)",
        f"- cost: ${summary['cost_usd']:.6f}" + ("" if summary["cost_complete"] else " (incomplete usage)"),
        f"- prompt/completion tokens: {summary['prompt_tokens']} / {summary['completion_tokens']}",
        "",
        "## Headline metrics",
        "",
        "| metric | all 70 | 58 LSan-observable |",
        "| --- | ---: | ---: |",
        f"| compile pass | {summary['compile_pass']} | {summary['compile_pass_observable']} |",
        f"| leak removed (12 non-observable are vacuous) | {summary['leak_removed']} | {summary['leak_removed_observable']} |",
        f"| behaviour preserved | {summary['behavior_preserved']} | {summary['behavior_preserved_observable']} |",
        f"| strict pass (non-evaluable counted as not pass) | {summary['strict_pass']} | {summary['strict_pass_observable']} |",
        "",
        "`strict pass` requires compile, LSan-clean run, identical observable data lines, "
        "a non-vacuous behaviour signature, and a baseline where LSan actually observed a leak. "
        "The 12 units whose baseline does not leak under LSan are not strict-evaluable; "
        "their compile/behaviour results are reported but cannot prove leak removal.",
        "",
        "## First attempt vs after feedback",
        "",
        "| stage | compile | leak removed | behaviour | strict (58) |",
        "| --- | ---: | ---: | ---: | ---: |",
        f"| first attempt | {summary['first_attempt_compile']} | {summary['first_attempt_leak_removed']} | "
        f"{summary['first_attempt_behavior']} | {summary['strict_pass_first_observable']} |",
        f"| final (after optional iteration) | {summary['compile_pass']} | {summary['leak_removed']} | "
        f"{summary['behavior_preserved']} | {summary['strict_pass_observable']} |",
        "",
        f"- units that used the feedback iteration: {summary['iterated_units']} "
        f"({summary['iterations_runtime']} after a real compile/LSan/behaviour failure, "
        f"{summary['iterations_schema']} after a schema/parse rejection)",
        f"- real-failure iterations that reached strict pass: {summary['iterations_runtime_recovered']}",
        f"- rejected responses (schema/parse): {summary['parse_rejections']}",
        f"- final responses with the exact top-level schema: {summary['schema_strict_units']}/70",
        f"- final responses including an explanation: {summary['explanation_present_units']}/70",
        f"- API errors: {summary['api_errors']}",
        "",
        "## Non-LSan-observable units",
        "",
        "These 12 units have no leak in the default LSan root set used here: 7 `malloc_realloc` "
        "cases leak only when `realloc` fails, and 5 variant-68 cases keep the only pointer in a "
        "global that LSan treats as reachable. They are listed, not silently counted as successes.",
        "",
    ]
    for unit_id in summary["nonleak_units"]:
        lines.append(f"- `{unit_id}`")
    lines += ["", "## Failures and non-strict outcomes", ""]
    rows = failure_rows(run)
    if not rows:
        lines.append("None.")
    else:
        lines += [
            "| unit | attempts | compile | leak | behaviour | observable | status | parse error |",
            "| --- | ---: | --- | --- | --- | --- | --- | --- |",
        ]
        for row in rows:
            if not row["observable"]:
                status = "behaviour not observable"
            elif row["compile"] and row["leak"] and row["behavior"]:
                status = "not strict-evaluable"
            else:
                status = "fail"
            lines.append(
                "| {unit} | {attempts} | {compile} | {leak} | {behavior} | {observable} | {status} | {error} |".format(
                    **row, error=(row["parse_error"] or "")[:60], status=status
                )
            )
    lines += ["", "## Case studies", ""]
    chosen = []
    for result in run["results"]:
        if result.get("strict_pass") and len(result.get("changed_paths") or []) > 1:
            chosen.append((result, "multi-file strict pass"))
            break
    for result in run["results"]:
        if result.get("strict_pass") and "wchar" in result["unit_id"]:
            chosen.append((result, "wide-character output preserved"))
            break
    for result in run["results"]:
        if result.get("strict_pass") and "_82" in result["unit_id"]:
            chosen.append((result, "virtual-dispatch variant strict pass"))
            break
    for result in run["results"]:
        if len(result.get("attempts") or []) > 1:
            chosen.append((result, "needed feedback iteration"))
            break
    for result in run["results"]:
        if (
            len(result.get("attempts") or []) > 1
            and result.get("strict_pass")
            and (result["attempts"][0].get("evaluation") or {}).get("strict_pass") is False
        ):
            chosen.append((result, "feedback iteration recovered a real failure"))
            break
    for result in run["results"]:
        failed = (
            not result.get("compile_pass")
            or not result.get("leak_removed")
            or (
                result.get("behavior_observable")
                and not result.get("behavior_preserved")
            )
        )
        if failed:
            chosen.append((result, "runtime or compile failure"))
            break
    for result in run["results"]:
        if not result.get("strict_pass") and result.get("strict_evaluable"):
            chosen.append((result, "strict failure"))
            break
    for result in run["results"]:
        if not result.get("strict_evaluable") and result.get("compile_pass"):
            chosen.append((result, "LSan-insensitive baseline (not strict-evaluable)"))
            break
    for result, label in chosen:
        attempts = result.get("attempts") or []
        final_attempt = attempts[-1]["attempt"] if attempts else 1
        lines += [f"### {label}: `{result['unit_id']}`", ""]
        lines.append(
            f"- attempts: {len(attempts)}; compile={result.get('compile_pass')}; "
            f"leak={result.get('leak_removed')}; behaviour={result.get('behavior_preserved')}; "
            f"strict={result.get('strict_pass')}"
        )
        lines.append("")
        lines.append(case_patch(run["run_dir"], result["unit_key"], final_attempt))
        lines.append("")
    lines += [
        "## Reproduction",
        "",
        "```bash",
        "python3 juliet_repair/scripts/prepare_inputs.py --force",
        "python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force",
        f"python3 juliet_repair/scripts/run_repair.py --model {manifest.get('model_alias', 'deepseek')} "
        f"--concurrency 8 --out-dir juliet_repair/runs/{summary['run_id']}",
        f"python3 juliet_repair/scripts/report.py --run juliet_repair/runs/{summary['run_id']}",
        "```",
        "",
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def report_compare(runs: list[dict], out_md: Path, out_json: Path) -> None:
    summaries = [summarize(run) for run in runs]
    doc = {
        "schema": "juliet-repair-comparison-v1",
        "units": 70,
        "leak_observable": summaries[0]["leak_observable"] if summaries else 0,
        "runs": summaries,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# DeepSeek vs MiMo on Juliet CWE-401 repair",
        "",
        "Same 70 frozen bad units, same sanitised inputs, same compile/LSan/behaviour harness. "
        "Each model got one initial request and at most one compiler/LSan/behaviour feedback iteration.",
        "",
        "| metric | DeepSeek V4.1 Flash | MiMo V2.6 Flash |",
        "| --- | ---: | ---: |",
    ]
    keys = [
        ("compile pass (all 70)", "compile_pass"),
        ("leak removed (all 70; 12 vacuous)", "leak_removed"),
        ("behaviour preserved (all 70)", "behavior_preserved"),
        ("strict pass (all 70; non-evaluable fail)", "strict_pass"),
        ("strict pass (58 observable)", "strict_pass_observable"),
        ("first-attempt strict (58 observable)", "strict_pass_first_observable"),
        ("units using feedback", "iterated_units"),
        ("  after real compile/LSan/behaviour failure", "iterations_runtime"),
        ("  after schema/parse rejection", "iterations_schema"),
        ("rejected responses", "parse_rejections"),
        ("API errors", "api_errors"),
        ("total calls", "calls"),
        ("cost USD", "cost_usd"),
    ]
    for label, key in keys:
        values = []
        for summary in summaries:
            value = summary[key]
            values.append(f"${value:.6f}" if key == "cost_usd" else str(value))
        lines.append(f"| {label} | " + " | ".join(values) + " |")
    lines += ["", "## Denominator", ""]
    lines.append(
        "58 of the 70 frozen bad units emit a LeakSanitizer leak under the harness's root-set "
        "configuration (`use_stacks=0:use_registers=0`). The other 12 are listed in each individual "
        "report; they cannot support a leak-removal claim. Strict pass is reported over both the "
        "full 70 and the 58 observable units."
    )
    lines += ["", "## Per-unit outcomes", ""]
    lines += ["| unit | " + " | ".join(s["model"] for s in summaries) + " |", "| --- |" + " --- |" * len(summaries)]
    by_run = [
        {result["unit_key"]: result for result in run["results"]} for run in runs
    ]
    keys = sorted(by_run[0])
    for unit_key in keys:
        cells = []
        for mapping in by_run:
            result = mapping.get(unit_key, {})
            if not result:
                cells.append("missing")
            elif not result.get("compile_pass") or not result.get("leak_removed") or (
                result.get("behavior_observable") and not result.get("behavior_preserved")
            ):
                cells.append(
                    "fail (c={c},l={l},b={b})".format(
                        c=result.get("compile_pass"),
                        l=result.get("leak_removed"),
                        b=result.get("behavior_preserved"),
                    )
                )
            elif result.get("strict_pass"):
                cells.append("strict pass")
            elif not result.get("strict_evaluable"):
                cells.append("not leak-observable")
            else:
                cells.append("not strict")
        lines.append(f"| {unit_key} | " + " | ".join(cells) + " |")
    lines.append("")
    out_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    runs = [load_run(path.resolve()) for path in args.run]
    summaries = [summarize(run) for run in runs]
    if len(runs) == 1:
        out = args.out or (REPORT / f"{summaries[0]['run_id']}.md")
        report_one(runs[0], summaries[0], out)
        print(f"wrote {out}")
    else:
        out_md = args.out or (REPORT / "comparison.md")
        out_json = out_md.with_suffix(".json")
        report_compare(runs, out_md, out_json)
        print(f"wrote {out_md} and {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
