"""Non-network self-checks for the Juliet LLM package.

These checks never call a model.  They verify the frozen subset hash, the
leak-free prompt construction, the answer parser, the strict/valid-only metric
definitions, and the consistency of every run directory under
``juliet_llm/runs`` (including that no credential-shaped string was written).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(__file__).resolve().parent
JULIET_DIR = PROJECT_ROOT / "juliet"
BUILD_DIR = PACKAGE_DIR / "build"
RUNS_DIR = PACKAGE_DIR / "runs"

from .cleaning import (  # noqa: E402
    forbidden_hits,
    neutralize_identifiers,
    scan,
    sha256_text,
)
from .metrics import evaluate, parse_verdict, SchemaError  # noqa: E402
from .prompting import STRICT_PROMPT_PATTERNS  # noqa: E402

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{20,}|Bearer\s+[A-Za-z0-9._~+/-]{20,})")


class CheckFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def check_freeze() -> None:
    freeze = json.loads((JULIET_DIR / "FREEZE.json").read_text(encoding="utf-8"))
    subset = JULIET_DIR / "subset_units.jsonl"
    manifest = JULIET_DIR / "manifest.json"
    check(
        sha256_text(subset.read_text(encoding="utf-8")) == freeze["subset_units_sha256"],
        "subset_units.jsonl no longer matches FREEZE.json",
    )
    check(
        hashlib.sha256(manifest.read_bytes()).hexdigest() == freeze["manifest_sha256"],
        "manifest.json no longer matches FREEZE.json",
    )
    units = load_jsonl(subset)
    check(len(units) == 200, f"expected 200 frozen units, found {len(units)}")
    check(
        sum(unit["split"] == "test" for unit in units) == 140,
        "frozen test split is not 140 units",
    )
    check(
        sum(unit["split"] == "dev" for unit in units) == 60,
        "frozen dev split is not 60 units",
    )
    check(
        sum(unit["label"] == "bad" for unit in units if unit["split"] == "test") == 70,
        "frozen test split is not 70/70",
    )


def check_inputs() -> None:
    expected = {"dev": 60, "test": 140}
    for split, count in expected.items():
        path = BUILD_DIR / f"{split}.jsonl"
        records = load_jsonl(path)
        check(len(records) == count, f"{split}: expected {count} inputs, found {len(records)}")
        check(
            len({record["unit_id"] for record in records}) == count,
            f"{split}: duplicate unit ids",
        )
        for record in records:
            messages = record["messages"]
            check(
                [message["role"] for message in messages] == ["system", "user"],
                f"{record['unit_id']}: unexpected message roles",
            )
            joined = "\n".join(message["content"] for message in messages)
            leaks = {
                name: value
                for name, value in scan(joined, STRICT_PROMPT_PATTERNS).items()
                if value
            }
            check(not leaks, f"{record['unit_id']}: prompt leak {leaks}")
            check(
                record["unit_id"] not in joined and record["group_id"] not in joined,
                f"{record['unit_id']}: unit identifier in prompt",
            )
            check(
                record["prompt_sha256"]
                == sha256_text(
                    json.dumps(
                        messages,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ),
                f"{record['unit_id']}: prompt hash mismatch",
            )
            code = messages[1]["content"]
            check("// ---- part" in code, f"{record['unit_id']}: no part marker")
            check("#if" not in code, f"{record['unit_id']}: preprocessor conditional survived")
            check("raw/" not in code, f"{record['unit_id']}: path survived")
            lines = code.splitlines()
            fence_start = next(
                index for index, line in enumerate(lines) if line.startswith("```")
            )
            fence_end = max(
                index
                for index, line in enumerate(lines)
                if index > fence_start and line.strip() == "```"
            )
            extracted_code = "\n".join(lines[fence_start + 1 : fence_end])
            check(
                record["code_sha256"] == sha256_text(extracted_code),
                f"{record['unit_id']}: code hash mismatch",
            )
    audit = json.loads((BUILD_DIR / "audit.json").read_text(encoding="utf-8"))
    check(audit["summary"]["after_hits"] and all(
        value == 0 for value in audit["summary"]["after_hits"].values()
    ), "build audit reports residual forbidden tokens")
    check(
        audit["summary"]["checks"]["braces_balanced"] == 200,
        "build audit reports unbalanced braces",
    )


def check_parser() -> None:
    good = parse_verdict('{"label": "vulnerable", "confidence": 0.5, "reason": "x"}')
    check(good["label"] == "vulnerable", "valid answer rejected")
    check(
        parse_verdict('{"label": "not_vulnerable", "confidence": 0}')["label"]
        == "not_vulnerable",
        "confidence 0 rejected",
    )
    for payload in (
        "not json",
        '{"label": "safe"}',
        '{"label": "vulnerable", "confidence": 2}',
        '{"label": "vulnerable", "confidence": true}',
        '{"label": "vulnerable"} trailing',
        "```json\n{\"label\": \"vulnerable\"}\n```",
        "",
    ):
        try:
            parse_verdict(payload)
        except SchemaError:
            continue
        raise CheckFailure(f"invalid answer accepted: {payload!r}")


def check_metrics() -> None:
    rows = [
        {"unit_id": "a", "y_true": 1, "y_pred": 1, "valid": True, "language": "c"},
        {"unit_id": "b", "y_true": 1, "y_pred": 1, "valid": True, "language": "cpp"},
        {"unit_id": "c", "y_true": 0, "y_pred": 0, "valid": True, "language": "c"},
        {"unit_id": "d", "y_true": 0, "y_pred": 1, "valid": True, "language": "cpp"},
        {"unit_id": "e", "y_true": 1, "y_pred": None, "valid": False, "language": "c"},
    ]
    result = evaluate(rows)
    strict = result["strict"]
    valid = result["valid_only"]
    check(
        (strict["tp"], strict["fp"], strict["tn"], strict["fn"]) == (2, 1, 1, 1),
        f"strict confusion wrong: {strict}",
    )
    check(
        (valid["tp"], valid["fp"], valid["tn"], valid["fn"]) == (2, 1, 1, 0),
        f"valid-only confusion wrong: {valid}",
    )
    check(strict["n"] == 5 and valid["n"] == 4, "metric denominators wrong")
    check(abs(strict["accuracy"] - 0.6) < 1e-12, "strict accuracy wrong")
    check(abs(valid["accuracy"] - 0.75) < 1e-12, "valid accuracy wrong")
    check(result["coverage"] == 0.8, "coverage wrong")


def check_string_scrub() -> None:
    payload = (
        'printLine("bad good CWE401 memory_leak OMITBAD flaw std_testcase '
        'benign fixed safe clean patched remediated raw/testcases");'
    )
    scrubbed, _ = neutralize_identifiers(payload)
    hits = {name: value for name, value in forbidden_hits(scrubbed).items() if value}
    check(not hits, f"string scrub left audited tokens: {hits}")
    check("Benign, fixed string" not in scrubbed, "reported leak string survived the scrub")


def check_runs() -> None:
    run_dirs = sorted(path for path in RUNS_DIR.iterdir() if path.is_dir())
    check(bool(run_dirs), "no run directories")
    for run_dir in run_dirs:
        manifest_path = run_dir / "manifest.json"
        results_path = run_dir / "results.jsonl"
        if not manifest_path.exists() or not results_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        results = load_jsonl(results_path)
        check(
            len(results) == manifest["expected_requests"],
            f"{run_dir.name}: result count mismatch",
        )
        inputs_path = run_dir / "inputs.jsonl"
        if inputs_path.exists():
            inputs = {item["unit_id"]: item for item in load_jsonl(inputs_path)}
        else:
            inputs = {}
        for record in results:
            check(
                record["y_true"] == (1 if record["label"] == "bad" else 0),
                f"{run_dir.name}/{record['unit_id']}: y_true mismatch",
            )
            if record["valid"]:
                check(record["y_pred"] in (0, 1), f"{run_dir.name}: valid record without y_pred")
                check(record["parsed"]["label"] in ("vulnerable", "not_vulnerable"), "bad parsed label")
            if record["unit_id"] in inputs:
                check(
                    record["prompt_sha256"] == inputs[record["unit_id"]]["prompt_sha256"],
                    f"{run_dir.name}/{record['unit_id']}: prompt hash differs from frozen input",
                )
        metrics_path = run_dir / "metrics.json"
        if metrics_path.exists():
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            check(
                metrics["evaluation"]["n_total"] == len(results),
                f"{run_dir.name}: metrics record count mismatch",
            )


def check_no_secrets() -> None:
    hits = []
    for path in PACKAGE_DIR.rglob("*"):
        if not path.is_file() or path.suffix in {".pyc"}:
            continue
        if path.name == "selfcheck.py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if SECRET_RE.search(text):
            hits.append(str(path.relative_to(PROJECT_ROOT)))
    check(not hits, f"credential-shaped strings found in: {hits[:5]}")


def main() -> int:
    checks = [
        ("frozen subset integrity", check_freeze),
        ("leak-free inputs", check_inputs),
        ("answer parser", check_parser),
        ("strict / valid-only metrics", check_metrics),
        ("string scrub vocabulary", check_string_scrub),
        ("run consistency", check_runs),
        ("no credential-shaped artefacts", check_no_secrets),
    ]
    failures = 0
    for name, function in checks:
        try:
            function()
        except CheckFailure as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        else:
            print(f"PASS {name}")
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
