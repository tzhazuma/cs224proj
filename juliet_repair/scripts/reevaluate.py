#!/usr/bin/env python3
"""Re-parse and re-evaluate saved responses without any new API call.

This is used after a parser fix: the raw model responses are unchanged, but
they are parsed with the current schema and compiled/run again.  It never
fabricates a response and never changes requests.jsonl.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import repair_lib as rl  # noqa: E402


def evaluate_saved(
    unit: rl.Unit,
    unit_input: dict,
    baseline: dict,
    attempt_dir: Path,
) -> dict:
    response_path = attempt_dir / "response.json"
    response = json.loads(response_path.read_text(encoding="utf-8"))
    entry = {
        "attempt": int(attempt_dir.name.replace("attempt", "")),
        "status": response.get("status"),
        "error": response.get("error"),
        "usage": response.get("usage"),
        "cost": response.get("cost"),
        "parse_error": None,
        "evaluation": None,
        "schema_strict": None,
        "explanation_present": None,
        "changed_paths": [],
        "usage_chars": len(response.get("content") or ""),
    }
    if response.get("status") != "ok" or not response.get("content"):
        entry["parse_error"] = "api_error"
        return entry
    try:
        parsed = rl.parse_output(response["content"], unit_input)
    except rl.OutputError as exc:
        entry["parse_error"] = str(exc)
        return entry
    entry["schema_strict"] = parsed.get("schema_strict")
    entry["explanation_present"] = parsed.get("explanation_present")
    entry["changed_paths"] = sorted(parsed["files"])
    entry["parsed_explanation"] = parsed["explanation"]
    original = {item["path"]: item["content"] for item in unit_input["files"]}
    diff = ""
    import difflib

    for path in sorted(parsed["files"]):
        diff += "".join(
            difflib.unified_diff(
                original[path].splitlines(keepends=True),
                parsed["files"][path].splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=3,
            )
        )
    (attempt_dir / "patch.diff").write_text(diff, encoding="utf-8")
    patch_dir = attempt_dir / "src"
    if patch_dir.exists():
        shutil.rmtree(patch_dir)
    patch_dir.mkdir(parents=True)
    for name, body in parsed["files"].items():
        (patch_dir / name).write_text(body, encoding="utf-8")
    evaluation = rl.evaluate_attempt(
        unit,
        unit_input,
        parsed["files"],
        attempt_dir / "eval",
        baseline["bad"],
        baseline["good"],
    )
    evaluation["parsed_explanation"] = parsed["explanation"]
    (attempt_dir / "eval.json").write_text(
        json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    entry["evaluation"] = {
        key: evaluation.get(key)
        for key in (
            "compile_pass",
            "leak_removed",
            "behavior_preserved",
            "behavior_observable",
            "strict_pass",
            "strict_evaluable",
        )
    }
    entry["evaluation"]["run"] = evaluation.get("run")
    return entry


def measurable(entry: dict) -> bool:
    evaluation = entry.get("evaluation") or {}
    return bool(
        evaluation.get("compile_pass")
        and evaluation.get("leak_removed")
        and (
            evaluation.get("behavior_preserved")
            if evaluation.get("behavior_observable")
            else True
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    run_dir = args.run.resolve()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    units = {unit.unit_key: unit for unit in rl.load_test_units()}
    inputs = rl.unit_inputs_by_key()
    results: list[dict] = []
    for unit_key in sorted(units):
        unit = units[unit_key]
        unit_dir = run_dir / "units" / unit_key
        result_path = unit_dir / "result.json"
        if not result_path.exists():
            continue
        previous = json.loads(result_path.read_text(encoding="utf-8"))
        baseline_path = rl.BUILD / "baselines" / unit_key / "baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        attempts: list[dict] = []
        for attempt_dir in sorted(unit_dir.glob("attempt*"), key=lambda p: int(p.name.replace("attempt", ""))):
            attempts.append(evaluate_saved(unit, inputs[unit_key], baseline, attempt_dir))
        if not attempts:
            continue
        # Keep the latest attempt that actually satisfies the observable
        # criteria; if none does, keep the latest parseable attempt; if none
        # parses, keep the last call.
        passing = [attempt for attempt in attempts if measurable(attempt)]
        usable = [attempt for attempt in attempts if attempt.get("evaluation")]
        selected = (passing or usable or attempts)[-1]
        selected_eval = selected.get("evaluation") or {}
        total_cost = 0.0
        cost_complete = True
        prompt_tokens = 0
        completion_tokens = 0
        cached_tokens = 0
        for attempt in attempts:
            cost = attempt.get("cost") or {}
            if isinstance(cost.get("cost_usd"), (int, float)):
                total_cost += float(cost["cost_usd"])
            else:
                cost_complete = False
            for key, target in (
                ("prompt_tokens", "prompt"),
                ("completion_tokens", "completion"),
                ("cached_prompt_tokens", "cached"),
            ):
                value = cost.get(key)
                if isinstance(value, int):
                    if target == "prompt":
                        prompt_tokens += value
                    elif target == "completion":
                        completion_tokens += value
                    else:
                        cached_tokens += value
        result = {
            "schema": "juliet-repair-result-v1",
            "unit_key": unit_key,
            "unit_id": unit.unit_id,
            "group_id": unit.group_id,
            "language": unit.language,
            "model_alias": previous.get("model_alias"),
            "model": previous.get("model"),
            "attempts": attempts,
            "final_attempt": selected["attempt"],
            "last_attempt": attempts[-1]["attempt"],
            "selection_reason": (
                "latest_observable_pass"
                if selected in passing
                else ("latest_parseable" if selected in usable else "last_call")
            ),
            "final_parse_error": selected.get("parse_error"),
            "schema_strict": bool(selected.get("schema_strict")),
            "explanation_present": bool(selected.get("explanation_present")),
            "compile_pass": bool(selected_eval.get("compile_pass")),
            "leak_removed": bool(selected_eval.get("leak_removed")),
            "behavior_preserved": bool(selected_eval.get("behavior_preserved")),
            "behavior_observable": bool(selected_eval.get("behavior_observable")),
            "strict_pass": bool(selected_eval.get("strict_pass")),
            "strict_evaluable": bool(selected_eval.get("strict_evaluable")),
            "changed_paths": selected.get("changed_paths") or [],
            "cost_usd_sum": round(total_cost, 8) if cost_complete else None,
            "cost_complete": cost_complete,
            "prompt_tokens_sum": prompt_tokens,
            "completion_tokens_sum": completion_tokens,
            "cached_prompt_tokens_sum": cached_tokens,
            "api_key_value_stored": False,
            "reevaluated_at_utc": rl.utc_now(),
        }
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        results.append(result)

    results.sort(key=lambda item: item["unit_key"])
    summary = {
        "run_id": manifest.get("run_id"),
        "model": manifest.get("model"),
        "units": len(results),
        "errors": sum(1 for item in results if item.get("error")),
        "strict_evaluable": sum(1 for item in results if item.get("strict_evaluable")),
        "compile_pass": sum(1 for item in results if item.get("compile_pass")),
        "leak_removed": sum(1 for item in results if item.get("leak_removed")),
        "behavior_preserved": sum(1 for item in results if item.get("behavior_preserved")),
        "strict_pass": sum(1 for item in results if item.get("strict_pass")),
        "strict_pass_evaluable_only": sum(
            1 for item in results if item.get("strict_pass") and item.get("strict_evaluable")
        ),
        "final_parse_error": sum(1 for item in results if item.get("final_parse_error")),
        "total_calls": sum(len(item.get("attempts") or []) for item in results),
        "cost_usd_sum": round(sum(item.get("cost_usd_sum") or 0.0 for item in results), 8),
        "cost_complete": all(item.get("cost_complete", True) for item in results),
        "prompt_tokens_sum": sum(item.get("prompt_tokens_sum") or 0 for item in results),
        "completion_tokens_sum": sum(item.get("completion_tokens_sum") or 0 for item in results),
        "results": results,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / "results.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "unit_key": item["unit_key"],
                    "unit_id": item["unit_id"],
                    "final_attempt": item["final_attempt"],
                    "compile_pass": item["compile_pass"],
                    "leak_removed": item["leak_removed"],
                    "behavior_preserved": item["behavior_preserved"],
                    "strict_pass": item["strict_pass"],
                    "strict_evaluable": item["strict_evaluable"],
                    "final_parse_error": item["final_parse_error"],
                    "cost_usd_sum": item["cost_usd_sum"],
                    "prompt_tokens_sum": item["prompt_tokens_sum"],
                    "completion_tokens_sum": item["completion_tokens_sum"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
            for item in results
        ),
        encoding="utf-8",
    )
    manifest["summary"] = {key: value for key, value in summary.items() if key != "results"}
    manifest["reevaluated_at_utc"] = rl.utc_now()
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: value for key, value in summary.items() if key != "results"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
