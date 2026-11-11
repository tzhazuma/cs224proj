"""Build the leak-free inputs and the source-audit artefacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cleaning import (
    JULIET_DIR,
    PROJECT_ROOT,
    SUBSET_PATH,
    CleanedUnit,
    clean_all,
    load_units,
    sha256_text,
)
from .prompting import PROMPT_VERSION, input_record

BUILD_DIR = PROJECT_ROOT / "juliet_llm" / "build"


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> str:
    payload = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )
    path.write_text(payload, encoding="utf-8")
    return sha256_text(payload)


def _count_matrix(units: list[CleanedUnit]) -> dict[str, Any]:
    labels = Counter()
    languages = Counter()
    for unit in units:
        labels[unit.label] += 1
        languages[unit.language] += 1
    return {"labels": dict(sorted(labels.items())), "languages": dict(sorted(languages.items()))}


def _example(unit: CleanedUnit, original: str, max_lines: int = 28) -> str:
    after = unit.code.splitlines()
    before = original.splitlines()
    return "\n".join(
        [
            f"### {unit.unit_id}",
            "",
            "Original (label-bearing) excerpt:",
            "",
            "```c",
            "\n".join(before[:max_lines]),
            "```",
            "",
            "Cleaned excerpt:",
            "",
            "```c",
            "\n".join(after[:max_lines]),
            "```",
            "",
        ]
    )


def _audit_report(
    units: list[CleanedUnit],
    summary: dict[str, Any],
    examples: list[tuple[CleanedUnit, str]],
) -> str:
    before = summary["before_hits"]
    after = summary["after_hits"]
    rows = "\n".join(
        f"| `{name}` | {before.get(name, 0)} | {after.get(name, 0)} |"
        for name in before
    )
    checks = summary["checks"]
    check_rows = "\n".join(
        f"| `{name}` | {value}/{summary['units']} |"
        for name, value in sorted(checks.items())
    )
    example_text = "\n".join(_example(unit, original) for unit, original in examples)
    return f"""# Juliet CWE-401 source cleaning audit

Generated at {datetime.now(timezone.utc).isoformat(timespec="seconds")} UTC.

- Input: `juliet/subset_units.jsonl` (frozen, read-only)
- Units: {summary['units']} ({summary['by_split']})
- Labels: {summary['by_label']}
- Languages: {summary['by_language']}
- Prompt version: `{PROMPT_VERSION}`
- Prompt construction code: `juliet_llm/cleaning.py`, `juliet_llm/prompting.py`

## Pipeline

1. Strip `//` and `/* */` comments with a string-literal-aware scanner.
2. Resolve `#ifdef`/`#ifndef`/`#endif` with the unit's compile defines, keeping
   only the branch that the frozen build compiles.
3. Inline unit-local headers referenced by quoted `#include` directives; drop
   the support header.
4. Rename every identifier containing `bad`, `good`, `cwe`, `memory_leak`,
   `benign`, or `fixed` to a unit-local `sym_N` name; scrub those words plus
   `safe`/`clean`/`patched`/`remediated` inside string literals.
5. Audit the result; the build fails if any forbidden token survives.  The
   scrub vocabulary and the audit vocabulary are kept in sync, and the
   self-check exercises the scrub on a synthetic literal built from every
   audited class.

## Forbidden-token counts

Counts are token occurrences over the concatenated raw sources and over the
final cleaned source views. `source_path` covers `raw/testcases`, `/mnt/`, and
`juliet/`.

| Pattern | Raw sources | Cleaned views |
| --- | ---: | ---: |
{rows}

The cleaned counts are all zero; every cleaned unit passed the audit.

## Per-unit checks

| Check | Passed |
| --- | ---: |
{check_rows}

## Examples

{example_text}
"""


def build(output_dir: Path = BUILD_DIR) -> dict[str, Any]:
    units = load_units(SUBSET_PATH)
    cleaned, summary = clean_all(units)
    output_dir.mkdir(parents=True, exist_ok=True)

    by_split: dict[str, list[CleanedUnit]] = {"dev": [], "test": []}
    for unit in cleaned:
        if unit.split not in by_split:
            raise ValueError(f"unexpected split {unit.split!r}")
        by_split[unit.split].append(unit)

    inputs: dict[str, Path] = {}
    input_hashes: dict[str, str] = {}
    for split, split_units in by_split.items():
        records = sorted((input_record(unit) for unit in split_units), key=lambda r: r["unit_id"])
        path = output_dir / f"{split}.jsonl"
        input_hashes[split] = _write_jsonl(path, records)
        inputs[split] = path

    audit_records = [unit.audit_record() for unit in cleaned]
    audit = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "prompt_version": PROMPT_VERSION,
        "subset_units": str(SUBSET_PATH.relative_to(PROJECT_ROOT)),
        "subset_units_sha256": sha256_text(SUBSET_PATH.read_text(encoding="utf-8")),
        "summary": summary,
        "units": audit_records,
        "inputs": {
            split: {
                "path": str(path.relative_to(PROJECT_ROOT)),
                "sha256": input_hashes[split],
                "units": len(by_split[split]),
                "counts": _count_matrix(by_split[split]),
            }
            for split, path in inputs.items()
        },
        "code_sha256": {
            "cleaning.py": sha256_text((PROJECT_ROOT / "juliet_llm" / "cleaning.py").read_text(encoding="utf-8")),
            "prompting.py": sha256_text((PROJECT_ROOT / "juliet_llm" / "prompting.py").read_text(encoding="utf-8")),
        },
    }
    (output_dir / "audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    examples: list[tuple[CleanedUnit, str]] = []
    for wanted_label, wanted_language in (("bad", "cpp"), ("good", "c")):
        for unit in cleaned:
            if unit.label == wanted_label and unit.language == wanted_language and unit.split == "test":
                raw = "\n\n".join(
                    (JULIET_DIR / source).read_text(encoding="utf-8")
                    for source in next(
                        item["sources"] for item in units if item["unit_id"] == unit.unit_id
                    )
                )
                examples.append((unit, raw))
                break

    report = _audit_report(cleaned, summary, examples)
    (output_dir / "audit_report.md").write_text(report, encoding="utf-8")

    manifest = {
        "generated_at_utc": audit["generated_at_utc"],
        "prompt_version": PROMPT_VERSION,
        "units": len(cleaned),
        "summary": summary,
        "inputs": audit["inputs"],
        "audit_sha256": sha256_text(
            (output_dir / "audit_report.md").read_text(encoding="utf-8")
        ),
        "code_sha256": audit["code_sha256"],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=BUILD_DIR)
    args = parser.parse_args(argv)
    manifest = build(args.out_dir)
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
