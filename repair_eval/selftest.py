"""Temporary synthetic fixture for end-to-end verification.

Everything is created under a TemporaryDirectory and deleted when the test
returns.  The fixture is never written into the project and must never be
reported as an experimental result.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .rubric import DIMENSION_CODES
from .sampling import KNOWN_STRATEGIES
from .util import canonical_json, sha256_text, write_json, write_jsonl, write_tsv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_MODEL = "synthetic-selftest-model"
FIXTURE_ENDPOINT = "https://repair-eval-selftest.invalid/v1/chat/completions"


def _make_code(index: int, target_length: int, fixed: bool) -> str:
    body = [
        f"int func_{index:03d}(int x) {{",
        "    int y = x + 1;",
    ]
    if fixed:
        body.append("    if (x < 0) { return -1; }")
    body.append("    return y;")
    body.append("}")
    code = "\n".join(body) + "\n"
    padding = max(0, target_length - len(code) - 20)
    if padding:
        code = code.replace(
            "    int y = x + 1;\n",
            "    int y = x + 1;\n    /* " + "p" * padding + " */\n",
        )
    return code


def _make_dataset(path: Path) -> dict[str, Any]:
    pairs = []
    length_cycle = (240, 620, 1100, 1900)
    cwe_cycle = ("CWE-125", "CWE-79", "CWE-476", "CWE-416", "CWE-20")
    for index in range(40):
        if index < 8:
            project = f"long_project_{index:02d}"
            cwe = "CWE-119"
            target_length = 4200
        elif index < 10:
            project = f"short_project_{index:02d}"
            cwe = "CWE-476"
            target_length = 300
        else:
            project = f"proj_{((index - 10) // 3):02d}"
            cwe = cwe_cycle[(index - 10) % len(cwe_cycle)]
            target_length = length_cycle[(index - 10) % len(length_cycle)]
        vulnerable_code = _make_code(index, target_length, fixed=False)
        fixed_code = _make_code(index, target_length, fixed=True)
        pair_id = f"{10000 + index}:{20000 + index}"
        pairs.append(
            {
                "pair_id": pair_id,
                "vulnerable": {
                    "idx": 10000 + index,
                    "project": project,
                    "filepath": f"src/file_{index:03d}.c",
                    "func_name": f"func_{index:03d}",
                    "is_vulnerable": True,
                    "func_body": vulnerable_code,
                    "cwe_list": [cwe],
                    "fixed_func_idx": 20000 + index,
                },
                "fixed": {
                    "idx": 20000 + index,
                    "project": project,
                    "filepath": f"src/file_{index:03d}.c",
                    "func_name": f"func_{index:03d}",
                    "is_vulnerable": False,
                    "func_body": fixed_code,
                },
            }
        )
    payload = {
        "metadata": {
            "schema_version": 1,
            "dataset_type": "vulnerable_fixed_pairs",
            "pair_count": len(pairs),
            "function_count": len(pairs) * 2,
            "seed": 4242,
            "note": "SYNTHETIC SELFTEST FIXTURE; NOT EXPERIMENTAL DATA",
        },
        "pairs": pairs,
    }
    write_json(path, payload)
    return payload


def _candidate_code(pair: dict[str, Any], strategy: str) -> str:
    fixed = pair["fixed"]["func_body"]
    if strategy == "direct":
        return fixed
    if strategy == "few-shot":
        return fixed.replace("    if (x < 0)", "    /* variant A */\n    if (x < 0)")
    return fixed.replace("    if (x < 0)", "    /* variant B */\n    if (x < 0)")


def _repair_record(
    pair: dict[str, Any],
    strategy: str,
    *,
    status: str = "ok",
) -> dict[str, Any]:
    pair_id = pair["pair_id"]
    vulnerable = pair["vulnerable"]
    fixed_code = _candidate_code(pair, strategy) if status == "ok" else ""
    explanation = (
        "Synthetic explanation: rejects negative input before use."
        if status == "ok"
        else ""
    )
    if status == "ok":
        validation = {
            "schema_valid": True,
            "complete_function": True,
            "balanced_delimiters": True,
            "function_like_prefix": True,
            "contains_markdown_fence": False,
            "starts_like_diff": False,
            "changed_from_input": fixed_code != vulnerable["func_body"],
            "whitespace_changed_from_input": True,
            "fixed_line_count": fixed_code.count("\n") + 1,
            "fixed_code_sha256": sha256_text(fixed_code),
        }
        parsed = {"fixed_function": fixed_code, "explanation": explanation}
        response = {
            "status": "ok",
            "http_status": 200,
            "content": canonical_json(parsed),
            "usage": {"prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200},
            "raw_body": "{}",
            "attempts": [],
            "request_latency_seconds": 0.1,
            "wall_seconds": 0.1,
            "error": None,
            "response_meta": {"model": FIXTURE_MODEL},
            "cost": {"cost_usd": None, "cost_basis": "pricing_not_configured"},
        }
    elif status == "invalid":
        validation = {"schema_valid": False, "error": "synthetic invalid JSON"}
        parsed = None
        response = {
            "status": "ok",
            "http_status": 200,
            "content": "not JSON",
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            "raw_body": "not JSON",
            "attempts": [],
            "request_latency_seconds": 0.1,
            "wall_seconds": 0.1,
            "error": None,
            "response_meta": {"model": FIXTURE_MODEL},
            "cost": {"cost_usd": None, "cost_basis": "pricing_not_configured"},
        }
    else:
        validation = {"schema_valid": False, "error": "api_error"}
        parsed = None
        response = {
            "status": "error",
            "http_status": 401,
            "content": None,
            "usage": None,
            "raw_body": None,
            "attempts": [],
            "request_latency_seconds": 0.1,
            "wall_seconds": 0.1,
            "error": {"type": "http_error", "status": 401},
            "response_meta": {},
            "cost": {"cost_usd": None, "cost_basis": "missing_usage"},
        }
    return {
        "dataset_type": "pairs",
        "sample_id": f"pair:{pair_id}:vulnerable",
        "unit_id": pair_id,
        "pair_id": pair_id,
        "side": "vulnerable",
        "idx": vulnerable["idx"],
        "label": True,
        "task": "repair",
        "strategy": strategy,
        "prompt": {
            "prompt_version": "selftest",
            "task": "repair",
            "strategy": strategy,
            "context": {"used": False},
            "dev_example_ids": [],
            "dev_examples_sha256": None,
            "function": {
                "function_chars": len(vulnerable["func_body"]),
                "function_lines": vulnerable["func_body"].count("\n") + 1,
                "code_sha256": sha256_text(vulnerable["func_body"]),
            },
            "message_count": 1,
        },
        "request": {
            "endpoint": FIXTURE_ENDPOINT,
            "model": FIXTURE_MODEL,
            "request_fingerprint": sha256_text(f"{pair_id}:{strategy}"),
            "body_sha256": sha256_text(f"{pair_id}:{strategy}:body"),
        },
        "response": response,
        "status": status,
        "parsed": parsed,
        "validation": validation,
        "created_at": "2026-11-11T00:00:00+00:00",
        "completed_at": "2026-11-11T00:00:01+00:00",
    }


def _write_run(
    root: Path,
    dataset_path: Path,
    dataset_sha: str,
    dataset: dict[str, Any],
    strategy: str,
) -> Path:
    run_dir = root / f"run_{strategy}"
    run_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for index, pair in enumerate(dataset["pairs"]):
        if 8 <= index < 10 and strategy != "direct":
            records.append(_repair_record(pair, strategy, status="invalid" if strategy == "few-shot" else "error"))
            continue
        records.append(_repair_record(pair, strategy))
    if strategy == "direct":
        detection = dict(records[0])
        detection.update(
            {
                "task": "detection",
                "parsed": {"is_vulnerable": True, "confidence": 0.9, "rationale": "synthetic"},
                "validation": {"schema_valid": True},
            }
        )
        records.insert(0, detection)
    write_jsonl(run_dir / "results.jsonl", records)
    manifest = {
        "schema_version": 1,
        "run_id": f"selftest_{strategy}",
        "status": "completed",
        "dataset": {"type": "pairs", "path": str(dataset_path), "sha256": dataset_sha},
        "config": {
            "dataset_type": "pairs",
            "dataset_path": str(dataset_path),
            "dataset_sha256": dataset_sha,
            "strategy": strategy,
            "task": "repair",
            "limit": 0,
            "partial": False,
        },
        "api": {"model": FIXTURE_MODEL, "endpoint": FIXTURE_ENDPOINT},
        "outputs": {"results": "results.jsonl"},
        "note": "SYNTHETIC SELFTEST FIXTURE; NOT EXPERIMENTAL RESULTS",
    }
    write_json(run_dir / "manifest.json", manifest)
    return run_dir / "results.jsonl"


def _run_cli(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "repair_eval", *args],
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )


def _assert_ok(proc: subprocess.CompletedProcess[str], label: str) -> None:
    if proc.returncode != 0:
        raise AssertionError(
            f"{label} failed with exit code {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def _score_for(candidate_id: str, dimension: str, rater: str) -> int:
    value = int(sha256_text(f"{candidate_id}:{dimension}")[:8], 16) % 3
    if rater == "B" and int(sha256_text(f"flip:{candidate_id}:{dimension}")[:8], 16) % 6 == 0:
        value = (value + 1) % 3
    return value


def _write_rater_tsv(path: Path, package: dict[str, Any], rater: str) -> None:
    rows = []
    for case in package["cases"]:
        for candidate in case["candidates"]:
            candidate_id = candidate["candidate_id"]
            scores = [_score_for(candidate_id, dimension, rater) for dimension in DIMENSION_CODES]
            compile_status = "UNVERIFIED"
            if rater == "B" and int(sha256_text(f"compile:{candidate_id}")[:8], 16) % 11 == 0:
                compile_status = "NOT_RUN"
            rows.append(
                [candidate_id, case["case_id"], *scores, compile_status, f"synthetic {rater} note"]
            )
    write_tsv(
        path,
        ["candidate_id", "case_id", *DIMENSION_CODES, "compile_status", "notes"],
        rows,
    )


def _write_rater_json(path: Path, package: dict[str, Any], rater: str) -> None:
    scores = []
    for case in package["cases"]:
        for candidate in case["candidates"]:
            candidate_id = candidate["candidate_id"]
            item: dict[str, Any] = {
                "candidate_id": candidate_id,
                "case_id": case["case_id"],
                "compile_status": "UNVERIFIED",
                "notes": f"synthetic {rater} note",
            }
            for dimension in DIMENSION_CODES:
                item[dimension] = _score_for(candidate_id, dimension, rater)
            if rater == "B" and int(sha256_text(f"compile:{candidate_id}")[:8], 16) % 9 == 0:
                item["compile_status"] = "NOT_RUN"
            scores.append(item)
    write_json(path, {"rater_id": rater, "scores": scores})


def _fill_adjudication(source: Path, destination: Path) -> int:
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    filled = []
    for row in rows:
        if row["dimension"] == "COMPILE_STATUS":
            final_value = "UNVERIFIED"
        else:
            final_value = row["rater_A"]
        filled.append(
            [
                row["candidate_id"],
                row["case_id"],
                row["dimension"],
                row["rater_A"],
                row["rater_B"],
                final_value,
                "synthetic selftest adjudication",
            ]
        )
    write_tsv(
        destination,
        ["candidate_id", "case_id", "dimension", "rater_A", "rater_B", "final_value", "rationale"],
        filled,
    )
    return len(filled)


def run_selftest(*, bootstrap: int = 200) -> None:
    if bootstrap < 0:
        raise ValueError("bootstrap must be non-negative")
    with tempfile.TemporaryDirectory(prefix="repair_eval_selftest_") as temporary:
        root = Path(temporary)
        dataset_path = root / "synthetic_pairs.json"
        dataset = _make_dataset(dataset_path)
        dataset_sha = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
        result_paths = [
            _write_run(root, dataset_path, dataset_sha, dataset, strategy)
            for strategy in KNOWN_STRATEGIES
        ]

        package_dir = root / "package"
        build = _run_cli(
            [
                "build",
                "--results",
                *[str(path) for path in result_paths],
                "--dataset",
                str(dataset_path),
                "--out-dir",
                str(package_dir),
                "--pairs",
                "24",
                "--seed",
                "987654",
                "--max-per-project",
                "2",
                "--min-candidates-per-case",
                "2",
            ],
            cwd=root,
        )
        _assert_ok(build, "build")

        manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
        blind = json.loads((package_dir / "blind" / "blind_package.json").read_text(encoding="utf-8"))
        assert manifest["counts"]["cases"] == 24, manifest["counts"]
        assert manifest["counts"]["candidates"] == 72, manifest["counts"]
        assert blind["upstream_fix_visibility"] == "context_only"
        assert all("upstream_fixed_version" in case for case in blind["cases"])
        forbidden = {
            "strategy",
            "model",
            "pair_id",
            "sample_id",
            "validation",
            "exact_match_reference_fixed",
            "reference_match",
            "run_id",
            "request",
            "response",
            "project",
            "filepath",
        }
        leaked = _walk_keys(blind) & forbidden
        assert not leaked, f"blind package leaked keys: {leaked}"
        blind_text = (package_dir / "blind" / "blind_package.json").read_text(encoding="utf-8")
        assert "few-shot" not in blind_text, "few-shot strategy name leaked into blind package"
        assert "strategy_name" not in blind_text
        assert len(blind["cases"]) == 24
        assert all(len(case["candidates"]) == 3 for case in blind["cases"])

        template_lines = (
            package_dir / "blind" / "rater_A.tsv"
        ).read_text(encoding="utf-8").splitlines()
        assert len(template_lines) == 73, len(template_lines)
        assert not any("strategy" in line.lower() for line in template_lines)

        key = json.loads((package_dir / "private" / "blind_key.json").read_text(encoding="utf-8"))
        order_changed = False
        for case in blind["cases"]:
            case_key = key["cases"][case["case_id"]]
            strategy_order = [
                key["candidates"][candidate_id]["strategy"]
                for candidate_id in case_key["candidate_ids"]
            ]
            if strategy_order != list(KNOWN_STRATEGIES):
                order_changed = True
            assert sorted(strategy_order) == sorted(KNOWN_STRATEGIES)
        assert order_changed, "candidate display order was never randomized"

        rater_a = root / "rater_A.tsv"
        rater_b = root / "rater_B.json"
        _write_rater_tsv(rater_a, blind, "A")
        _write_rater_json(rater_b, blind, "B")
        agreement_dir = root / "agreement"
        agreement = _run_cli(
            [
                "agreement",
                "--package",
                str(package_dir),
                "--rater-a",
                str(rater_a),
                "--rater-b",
                str(rater_b),
                "--out-dir",
                str(agreement_dir),
                "--bootstrap",
                str(bootstrap),
            ],
            cwd=root,
        )
        _assert_ok(agreement, "agreement")
        agreement_json = json.loads(
            (agreement_dir / "agreement.json").read_text(encoding="utf-8")
        )
        assert agreement_json["n_candidates"] == 72
        assert agreement_json["disagreement_summary"]["total_dimension_disagreements"] > 0
        assert agreement_json["compile_status"]["disagreement_count"] > 0
        assert (agreement_dir / "adjudication.tsv").exists()

        adjudication_filled = root / "adjudication_filled.tsv"
        adjudicated = _fill_adjudication(
            agreement_dir / "adjudication.tsv", adjudication_filled
        )
        assert adjudicated == agreement_json["disagreement_summary"]["total_dimension_disagreements"]

        final_dir = root / "final"
        final = _run_cli(
            [
                "finalize",
                "--package",
                str(package_dir),
                "--rater-a",
                str(rater_a),
                "--rater-b",
                str(rater_b),
                "--adjudication",
                str(adjudication_filled),
                "--out-dir",
                str(final_dir),
                "--bootstrap",
                str(bootstrap),
            ],
            cwd=root,
        )
        _assert_ok(final, "finalize")
        summary = json.loads((final_dir / "summary.json").read_text(encoding="utf-8"))
        assert summary["n_candidates"] == 72
        assert summary["final"]["overall"]["primary_pass_rate"] is not None
        assert set(summary["final"]["by_strategy"]) == set(KNOWN_STRATEGIES)
        assert summary["posthoc_structural_checks"]["available"] is True
        assert any("PoC" in item for item in summary["limitations"])
        assert (final_dir / "final_scores.tsv").exists()

        verify = _run_cli(["verify", "--package", str(package_dir)], cwd=root)
        _assert_ok(verify, "verify")
        verify_json = json.loads(verify.stdout)
        assert verify_json["ok"] is True

        hidden_dir = root / "package_hidden"
        hidden = _run_cli(
            [
                "build",
                "--results",
                *[str(path) for path in result_paths],
                "--dataset",
                str(dataset_path),
                "--out-dir",
                str(hidden_dir),
                "--pairs",
                "24",
                "--seed",
                "987654",
                "--hide-reference",
            ],
            cwd=root,
        )
        _assert_ok(hidden, "build --hide-reference")
        hidden_blind = json.loads(
            (hidden_dir / "blind" / "blind_package.json").read_text(encoding="utf-8")
        )
        assert hidden_blind["upstream_fix_visibility"] == "hidden"
        assert all("upstream_fixed_version" not in case for case in hidden_blind["cases"])

        first_sampling = json.loads(
            (package_dir / "private" / "sampling.json").read_text(encoding="utf-8")
        )
        second_sampling = json.loads(
            (hidden_dir / "private" / "sampling.json").read_text(encoding="utf-8")
        )
        assert sorted(item["pair_id"] for item in first_sampling["selected"]) == sorted(
            item["pair_id"] for item in second_sampling["selected"]
        ), "fixed seed did not reproduce the same pair set"

        failing_run = root / "run_error"
        failing_run.mkdir()
        error_record = _repair_record(dataset["pairs"][10], "direct", status="error")
        write_jsonl(failing_run / "results.jsonl", [error_record])
        write_json(
            failing_run / "manifest.json",
            {
                "schema_version": 1,
                "run_id": "selftest_error",
                "status": "completed",
                "dataset": {"type": "pairs", "path": str(dataset_path), "sha256": dataset_sha},
                "config": {
                    "dataset_type": "pairs",
                    "dataset_sha256": dataset_sha,
                    "strategy": "direct",
                    "task": "repair",
                },
                "api": {"model": FIXTURE_MODEL, "endpoint": FIXTURE_ENDPOINT},
                "outputs": {"results": "results.jsonl"},
            },
        )
        no_results = _run_cli(
            [
                "build",
                "--results",
                str(failing_run / "results.jsonl"),
                "--dataset",
                str(dataset_path),
                "--out-dir",
                str(root / "must_fail"),
            ],
            cwd=root,
        )
        assert no_results.returncode == 2, no_results
        assert "no schema-valid repair candidates" in no_results.stderr

    print("SELFTEST PASSED")
    print("Synthetic fixture was created under a TemporaryDirectory and removed.")
    print("This was a tooling check, not an experimental result.")
