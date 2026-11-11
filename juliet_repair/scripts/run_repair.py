#!/usr/bin/env python3
"""Run DeepSeek or MiMo repairs on the 70 frozen Juliet CWE-401 test bad units.

Each unit gets one initial request.  If compilation, LSan, or behaviour fails,
the evaluator sends exactly one feedback request containing only compiler /
LSan / observable-output feedback.  Every response, patch, compile log and
run log is stored under juliet_repair/runs/<run_id>/.

The API key is read from the Kimi Code config in memory and is never printed
or written.  All artifacts record ``api_key_value_stored: false``.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import difflib
import hashlib
import json
import os
import sys
import threading
import time
import tomllib
import traceback
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR.parent.parent / "runner"))

import repair_lib as rl  # noqa: E402
from secvul_runner.client import (  # noqa: E402
    ApiConfig,
    ChatClient,
    build_body,
    normalize_endpoint,
    request_fingerprint,
)

RUNNER_VERSION = "juliet-repair-2026-11-12.1"
PROMPT_VERSION = "juliet-repair-prompt-2026-11-12.1"

MODELS = {
    "deepseek": {
        "model": "deepseek-v4.1-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "timeout_seconds": 180.0,
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
        "input_price_usd_per_1m": 0.30,
        "output_price_usd_per_1m": 1.20,
        "cached_input_price_usd_per_1m": 0.006,
    },
    "mimo": {
        "model": "mimo-v2.6-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "timeout_seconds": 300.0,
        "thinking": "disabled",
        "reasoning_effort": "none",
        "max_tokens_field": "max_completion_tokens",
        "input_price_usd_per_1m": 0.14,
        "output_price_usd_per_1m": 0.28,
        "cached_input_price_usd_per_1m": 0.0028,
    },
}


def load_api_key(config_path: Path, provider: str) -> str:
    with config_path.open("rb") as stream:
        config = tomllib.load(stream)
    entry = config.get("providers", {}).get(provider)
    if not isinstance(entry, dict):
        raise SystemExit(f"provider not found in Kimi config: {provider}")
    key = entry.get("api_key")
    if not isinstance(key, str) or not key.strip():
        raise SystemExit(f"provider has no usable API key: {provider}")
    return key.strip()


def make_config(alias: str) -> ApiConfig:
    spec = MODELS[alias]
    endpoint = normalize_endpoint(spec["base_url"])
    return ApiConfig(
        base_url=spec["base_url"],
        endpoint=endpoint,
        model=spec["model"],
        temperature=0.0,
        max_tokens=8192,
        timeout_seconds=spec["timeout_seconds"],
        max_attempts=3,
        response_format="json_object",
        thinking=spec["thinking"],
        reasoning_effort=spec["reasoning_effort"],
        max_tokens_field=spec["max_tokens_field"],
        input_price_usd_per_1m=spec["input_price_usd_per_1m"],
        output_price_usd_per_1m=spec["output_price_usd_per_1m"],
        cached_input_price_usd_per_1m=spec["cached_input_price_usd_per_1m"],
    )


def unified_diff(original: dict[str, str], replacements: dict[str, str]) -> str:
    chunks: list[str] = []
    for path in sorted(replacements):
        before = original[path].splitlines(keepends=True)
        after = replacements[path].splitlines(keepends=True)
        chunks.extend(
            difflib.unified_diff(
                before,
                after,
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=3,
            )
        )
    return "".join(chunks)


def feedback_message(evaluation: dict, parse_error: str | None) -> str:
    if parse_error:
        return (
            "The previous response was rejected by the harness: "
            f"{parse_error}. Return exactly one JSON object with the required "
            '"files" and "explanation" keys and complete file contents.'
        )
    lines = ["The previous repair did not pass the evaluator."]
    if not evaluation.get("compile_pass"):
        tail = (evaluation.get("compile") or {}).get("stderr_tail", "")[-2500:]
        lines.append("Compiler feedback:\n" + (tail or "compilation failed"))
    else:
        run = evaluation.get("run") or {}
        if run.get("leak_detected"):
            lines.append("LeakSanitizer still reports a leak: " + str(run.get("summary")))
        if run.get("other_asan_error"):
            lines.append("AddressSanitizer reported a non-leak error; see the run log.")
        if run.get("timed_out"):
            lines.append("The fixed program timed out.")
        if evaluation.get("behavior_observable") and not evaluation.get("behavior_preserved"):
            lines.append(
                "Observable output changed. Expected data lines: "
                + json.dumps(evaluation.get("baseline_behavior_lines"))
                + "; observed: "
                + json.dumps(evaluation.get("fixed_behavior_lines"))
            )
    lines.append(
        "Return a corrected JSON object with the same schema. Include complete "
        "replacement files for every file you change."
    )
    return "\n".join(lines)


class RunWriter:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.lock = threading.Lock()

    def request_row(self, row: dict) -> None:
        with self.lock:
            with (self.run_dir / "requests.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def result_row(self, row: dict) -> None:
        with self.lock:
            with (self.run_dir / "results.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def attempt_call(
    client: ChatClient,
    config: ApiConfig,
    messages: list[dict[str, str]],
    unit_key: str,
    attempt: int,
    attempt_dir: Path,
) -> dict:
    body = build_body(messages, config)
    fingerprint = request_fingerprint(
        endpoint=config.endpoint,
        body=body,
        task="repair",
        strategy="direct",
        prompt_version=PROMPT_VERSION,
    )
    request_doc = {
        "schema": "juliet-repair-request-v1",
        "unit_key": unit_key,
        "attempt": attempt,
        "prompt_version": PROMPT_VERSION,
        "endpoint": config.endpoint,
        "model": config.model,
        "messages": messages,
        "request_body_sha256": hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "request_fingerprint": fingerprint,
        "api_key_value_stored": False,
    }
    attempt_dir.mkdir(parents=True, exist_ok=True)
    (attempt_dir / "request.json").write_text(
        json.dumps(request_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    result = client.complete(messages)
    response_doc = {
        "schema": "juliet-repair-response-v1",
        "unit_key": unit_key,
        "attempt": attempt,
        "status": result.status,
        "http_status": result.http_status,
        "content": result.content,
        "usage": result.usage,
        "cost": result.cost,
        "error": result.error,
        "request_latency_seconds": result.request_latency_seconds,
        "wall_seconds": result.wall_seconds,
        "response_meta": result.response_meta,
        "attempts": result.attempts,
        "api_key_value_stored": False,
    }
    (attempt_dir / "response.json").write_text(
        json.dumps(response_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return response_doc


def process_unit(
    unit: rl.Unit,
    unit_input: dict,
    baseline: dict,
    model_alias: str,
    client: ChatClient,
    config: ApiConfig,
    max_attempts: int,
    run_dir: Path,
    writer: RunWriter,
) -> dict:
    unit_dir = run_dir / "units" / unit.unit_key
    unit_dir.mkdir(parents=True, exist_ok=True)
    messages = rl.build_messages(unit_input)
    original = {item["path"]: item["content"] for item in unit_input["files"]}
    attempts: list[dict] = []
    parse_error: str | None = None
    evaluation: dict | None = None
    replacements: dict[str, str] = {}
    total_cost: float | None = 0.0
    total_prompt = 0
    total_completion = 0
    total_cached = 0
    cost_complete = True

    for attempt_no in range(1, max_attempts + 1):
        attempt_dir = unit_dir / f"attempt{attempt_no}"
        if attempt_dir.exists():
            import shutil

            shutil.rmtree(attempt_dir)
        started = time.monotonic()
        response = attempt_call(client, config, messages, unit.unit_key, attempt_no, attempt_dir)
        elapsed = round(time.monotonic() - started, 3)
        cost = response.get("cost") or {}
        usage = response.get("usage") or {}
        if isinstance(cost.get("cost_usd"), (int, float)):
            total_cost = (total_cost or 0.0) + float(cost["cost_usd"])
        else:
            cost_complete = False
        for key, bucket in (("prompt_tokens", "prompt"), ("completion_tokens", "completion"), ("cached_prompt_tokens", "cached")):
            value = cost.get(key)
            if isinstance(value, int):
                if bucket == "prompt":
                    total_prompt += value
                elif bucket == "completion":
                    total_completion += value
                else:
                    total_cached += value
        writer.request_row(
            {
                "unit_key": unit.unit_key,
                "unit_id": unit.unit_id,
                "model": config.model,
                "attempt": attempt_no,
                "status": response["status"],
                "http_status": response["http_status"],
                "error": response["error"],
                "usage": usage,
                "cost": cost,
                "latency_seconds": response["request_latency_seconds"],
                "wall_seconds": response["wall_seconds"],
                "response_meta": response["response_meta"],
                "response_file": str((attempt_dir / "response.json").relative_to(run_dir)),
                "response_sha256": rl.sha256_text(response.get("content") or ""),
                "api_key_value_stored": False,
            }
        )
        entry: dict = {
            "attempt": attempt_no,
            "status": response["status"],
            "error": response["error"],
            "usage": usage,
            "cost": cost,
            "parse_error": None,
            "evaluation": None,
            "elapsed_seconds": elapsed,
        }
        if response["status"] != "ok" or not response.get("content"):
            entry["parse_error"] = "api_error"
            parse_error = f"API call failed: {(response.get('error') or {}).get('type')}"
            attempts.append(entry)
            evaluation = None
            break

        try:
            parsed = rl.parse_output(response["content"], unit_input)
        except rl.OutputError as exc:
            entry["parse_error"] = str(exc)
            parse_error = str(exc)
            attempts.append(entry)
            evaluation = None
            if attempt_no >= max_attempts:
                break
            messages = messages + [
                {"role": "assistant", "content": response["content"]},
                {"role": "user", "content": feedback_message({}, parse_error)},
            ]
            continue

        parse_error = None
        replacements = parsed["files"]
        entry["parsed_explanation"] = parsed["explanation"]
        entry["schema_strict"] = parsed.get("schema_strict")
        entry["explanation_present"] = parsed.get("explanation_present")
        entry["changed_paths"] = sorted(replacements)
        diff = unified_diff(original, replacements)
        (attempt_dir / "patch.diff").write_text(diff, encoding="utf-8")
        patch_dir = attempt_dir / "src"
        if patch_dir.exists():
            import shutil

            shutil.rmtree(patch_dir)
        patch_dir.mkdir(parents=True)
        for name, body in replacements.items():
            (patch_dir / name).write_text(body, encoding="utf-8")

        eval_dir = attempt_dir / "eval"
        evaluation = rl.evaluate_attempt(
            unit,
            unit_input,
            replacements,
            eval_dir,
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
        attempts.append(entry)

        observable_pass = bool(
            evaluation.get("compile_pass")
            and evaluation.get("leak_removed")
            and (
                evaluation.get("behavior_preserved")
                if evaluation.get("behavior_observable")
                else True
            )
        )
        if observable_pass or attempt_no >= max_attempts:
            break
        messages = messages + [
            {"role": "assistant", "content": response["content"]},
            {"role": "user", "content": feedback_message(evaluation, None)},
        ]

    last = attempts[-1] if attempts else {}
    last_eval = last.get("evaluation") or {}
    result = {
        "schema": "juliet-repair-result-v1",
        "unit_key": unit.unit_key,
        "unit_id": unit.unit_id,
        "group_id": unit.group_id,
        "language": unit.language,
        "model_alias": model_alias,
        "model": config.model,
        "attempts": attempts,
        "final_attempt": last.get("attempt"),
        "final_parse_error": last.get("parse_error"),
        "schema_strict": bool(last.get("schema_strict")),
        "explanation_present": bool(last.get("explanation_present")),
        "compile_pass": bool(last_eval.get("compile_pass")),
        "leak_removed": bool(last_eval.get("leak_removed")),
        "behavior_preserved": bool(last_eval.get("behavior_preserved")),
        "behavior_observable": bool(last_eval.get("behavior_observable")),
        "strict_pass": bool(last_eval.get("strict_pass")),
        "strict_evaluable": bool(last_eval.get("strict_evaluable")),
        "changed_paths": last.get("changed_paths") or [],
        "cost_usd_sum": round(total_cost, 8) if cost_complete and total_cost is not None else None,
        "cost_complete": cost_complete,
        "prompt_tokens_sum": total_prompt,
        "completion_tokens_sum": total_completion,
        "cached_prompt_tokens_sum": total_cached,
        "api_key_value_stored": False,
    }
    (unit_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    writer.result_row(
        {
            "unit_key": result["unit_key"],
            "unit_id": result["unit_id"],
            "final_attempt": result["final_attempt"],
            "compile_pass": result["compile_pass"],
            "leak_removed": result["leak_removed"],
            "behavior_preserved": result["behavior_preserved"],
            "strict_pass": result["strict_pass"],
            "strict_evaluable": result["strict_evaluable"],
            "final_parse_error": result["final_parse_error"],
            "cost_usd_sum": result["cost_usd_sum"],
            "prompt_tokens_sum": result["prompt_tokens_sum"],
            "completion_tokens_sum": result["completion_tokens_sum"],
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=sorted(MODELS), required=True)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=1, help="Extra feedback attempts (0 or 1).")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--kimi-config",
        type=Path,
        default=Path("/mnt/c/Users/tzh03/.kimi-code/config.toml"),
    )
    parser.add_argument("--kimi-provider", default="opencode-go")
    parser.add_argument("--dry-run", action="store_true", help="Build prompts and manifest, no API calls.")
    args = parser.parse_args()
    if args.iterations not in (0, 1):
        raise SystemExit("--iterations must be 0 or 1")
    if args.concurrency < 1 or args.concurrency > 16:
        raise SystemExit("--concurrency must be 1..16")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out_dir or (rl.RUNS / f"repair_{args.model}_test70_{stamp}")
    run_dir = run_dir.resolve()
    if run_dir.exists() and any(run_dir.iterdir()):
        if not args.resume:
            raise SystemExit(f"refusing to overwrite existing run directory: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)

    units = rl.load_test_units(limit=args.limit)
    inputs = rl.unit_inputs_by_key()
    if not args.limit and len(units) != 70:
        raise SystemExit(f"expected 70 units, got {len(units)}")
    missing = [unit.unit_key for unit in units if unit.unit_key not in inputs]
    if missing:
        raise SystemExit(f"inputs missing for {missing[:5]}; run prepare_inputs.py")
    baselines: dict[str, dict] = {}
    for unit in units:
        path = rl.BUILD / "baselines" / unit.unit_key / "baseline.json"
        if not path.exists():
            raise SystemExit(f"missing baseline {path}; run check_baselines.py")
        baselines[unit.unit_key] = json.loads(path.read_text(encoding="utf-8"))

    api_key = None
    if not args.dry_run:
        api_key = load_api_key(args.kimi_config, args.kimi_provider)
    config = make_config(args.model)
    manifest = {
        "schema": "juliet-repair-run-v1",
        "runner_version": RUNNER_VERSION,
        "run_id": run_dir.name,
        "model_alias": args.model,
        "model": config.model,
        "api": {
            **config.public_dict(),
            "api_key_env": "OPENCODE_API_KEY",
            "api_key_value_stored": False,
        },
        "prompt_version": PROMPT_VERSION,
        "input_units_sha256": rl.sha256_file(rl.INPUTS / "units.jsonl"),
        "input_manifest_sha256": rl.sha256_file(rl.INPUTS / "manifest.json"),
        "dataset_id": "juliet-cwe401-v1.3-subset-v1",
        "selection": "split=test, label=bad",
        "units": len(units),
        "max_attempts": 1 + args.iterations,
        "concurrency": args.concurrency,
        "dry_run": args.dry_run,
        "started_at_utc": rl.utc_now(),
        "api_key_value_stored": False,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.dry_run:
        for unit in units:
            unit_dir = run_dir / "units" / unit.unit_key
            unit_dir.mkdir(parents=True, exist_ok=True)
            messages = rl.build_messages(inputs[unit.unit_key])
            (unit_dir / "request.json").write_text(
                json.dumps(
                    {
                        "unit_key": unit.unit_key,
                        "messages": messages,
                        "messages_chars": sum(len(message["content"]) for message in messages),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        print(f"dry run: {len(units)} prompts written to {run_dir}")
        return 0

    writer = RunWriter(run_dir)
    client = ChatClient(config, api_key, session_id=None)
    results: list[dict] = []

    def work(unit: rl.Unit) -> dict:
        existing = run_dir / "units" / unit.unit_key / "result.json"
        if args.resume and existing.exists():
            return json.loads(existing.read_text(encoding="utf-8"))
        return process_unit(
            unit,
            inputs[unit.unit_key],
            baselines[unit.unit_key],
            args.model,
            client,
            config,
            manifest["max_attempts"],
            run_dir,
            writer,
        )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(work, unit): unit for unit in units}
            for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
                unit = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - one unit must not kill the run
                    result = {
                        "unit_key": unit.unit_key,
                        "unit_id": unit.unit_id,
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(),
                    }
                results.append(result)
                print(
                    f"[{done}/{len(units)}] {unit.unit_key} {unit.unit_id} "
                    f"compile={result.get('compile_pass')} leak={result.get('leak_removed')} "
                    f"behaviour={result.get('behavior_preserved')} strict={result.get('strict_pass')} "
                    f"attempts={result.get('final_attempt')}",
                    file=sys.stderr,
                    flush=True,
                )
    finally:
        client.close()

    results.sort(key=lambda item: item["unit_key"])
    strict_evaluable = sum(1 for item in results if item.get("strict_evaluable"))
    summary = {
        "run_id": run_dir.name,
        "model": config.model,
        "units": len(results),
        "errors": sum(1 for item in results if item.get("error")),
        "strict_evaluable": strict_evaluable,
        "compile_pass": sum(1 for item in results if item.get("compile_pass")),
        "leak_removed": sum(1 for item in results if item.get("leak_removed")),
        "behavior_preserved": sum(1 for item in results if item.get("behavior_preserved")),
        "strict_pass": sum(1 for item in results if item.get("strict_pass")),
        "strict_pass_evaluable_only": sum(
            1 for item in results if item.get("strict_pass") and item.get("strict_evaluable")
        ),
        "final_parse_error": sum(1 for item in results if item.get("final_parse_error")),
        "total_calls": sum(len(item.get("attempts") or []) for item in results),
        "cost_usd_sum": round(
            sum(item.get("cost_usd_sum") or 0.0 for item in results), 8
        ),
        "cost_complete": all(item.get("cost_complete", True) for item in results),
        "prompt_tokens_sum": sum(item.get("prompt_tokens_sum") or 0 for item in results),
        "completion_tokens_sum": sum(item.get("completion_tokens_sum") or 0 for item in results),
    }
    summary["results"] = results
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest["completed_at_utc"] = rl.utc_now()
    manifest["summary"] = {key: value for key, value in summary.items() if key != "results"}
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: value for key, value in summary.items() if key != "results"}, indent=2))
    return 0 if summary["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
