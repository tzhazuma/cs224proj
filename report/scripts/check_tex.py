#!/usr/bin/env python3
"""Non-compiling structural checks for report_zh.tex.

Checks environment pairing, brace balance, label/ref consistency, cite keys
against references.bib, tabular column counts, and that no result placeholder
(``\\TBD``) remains. It cannot replace XeLaTeX: fonts, page count, line breaking
and package behaviour are not checked.

Run from the project root:

    python3 report/scripts/check_tex.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEX = ROOT / "report" / "report_zh.tex"
BIB = ROOT / "report" / "references.bib"


def strip_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        match = re.search(r"(?<!\\)%", line)
        lines.append(line[: match.start()] if match else line)
    return "\n".join(lines)


def strip_group(spec: str, start: int) -> int:
    """Return the index just after a balanced {...} group starting at start."""
    depth = 0
    index = start
    while index < len(spec):
        if spec[index] == "{":
            depth += 1
        elif spec[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return index


def column_count(spec: str) -> int:
    spec = spec.strip()
    for marker in ("@", ">", "<", "!"):
        while True:
            index = spec.find(marker)
            if index < 0:
                break
            end = strip_group(spec, index + 1) if index + 1 < len(spec) else index + 1
            spec = spec[:index] + spec[end:]
    for marker in ("p", "m", "b"):
        while True:
            index = spec.find(marker)
            if index < 0:
                break
            end = strip_group(spec, index + 1) if index + 1 < len(spec) else index + 1
            spec = spec[:index] + "P" + spec[end:]
    return sum(1 for char in spec if char in "lcrPXSP")


def main() -> int:
    text = TEX.read_text(encoding="utf-8")
    clean = strip_comments(text)
    problems: list[str] = []

    stack: list[str] = []
    for match in re.finditer(r"\\(begin|end)\{([^}]+)\}", clean):
        kind, name = match.group(1), match.group(2)
        if kind == "begin":
            stack.append(name)
        elif not stack:
            problems.append(f"unmatched \\end{{{name}}}")
        else:
            opened = stack.pop()
            if opened != name:
                problems.append(f"mismatch \\begin{{{opened}}} ... \\end{{{name}}}")
    if stack:
        problems.append("unclosed environments: " + ", ".join(stack))

    without_escaped = re.sub(r"\\[{}]", "", clean)
    depth = 0
    minimum = 0
    for char in without_escaped:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            minimum = min(minimum, depth)
    if depth != 0 or minimum < 0:
        problems.append(f"brace depth ends at {depth}, minimum {minimum}")

    labels = re.findall(r"\\label\{([^}]+)\}", clean)
    duplicates = sorted({name for name in labels if labels.count(name) > 1})
    if duplicates:
        problems.append("duplicate labels: " + ", ".join(duplicates))
    refs = set(re.findall(r"\\(?:ref|eqref)\{([^}]+)\}", clean))
    missing_refs = sorted(refs - set(labels))
    if missing_refs:
        problems.append("missing refs: " + ", ".join(missing_refs))

    cites: set[str] = set()
    for match in re.finditer(r"\\cite\{([^}]+)\}", clean):
        cites.update(key.strip() for key in match.group(1).split(","))
    bib_text = BIB.read_text(encoding="utf-8")
    bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib_text))
    missing_cites = sorted(cites - bib_keys)
    if missing_cites:
        problems.append("missing cite keys: " + ", ".join(missing_cites))

    for match in re.finditer(r"\\begin\{tabular\}\{([^}]*)\}", clean):
        columns = column_count(match.group(1))
        if columns == 0:
            continue
        end = clean.find("\\end{tabular}", match.end())
        body = clean[match.end() : end]
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith(("\\toprule", "\\midrule", "\\bottomrule", "\\cmidrule")):
                continue
            if "\\multicolumn" in line:
                continue
            ampersands = len(re.findall(r"(?<!\\)&", line))
            if ampersands + 1 != columns:
                problems.append(
                    f"tabular declares {columns} columns but row has {ampersands + 1}: "
                    f"{line[:80]}"
                )

    model_rows = [
        line for line in clean.splitlines() if re.match(r"\s*M[123] .*&", line)
    ]
    tbd_count = clean.count("\\TBD")
    if tbd_count:
        problems.append(f"result placeholder \\TBD remains ({tbd_count} occurrences)")

    print(
        f"labels={len(labels)} refs={len(refs)} cites={len(cites)} "
        f"bib_keys={len(bib_keys)} model_rows={len(model_rows)} "
        f"TBD={tbd_count}"
    )
    if problems:
        print(f"PROBLEMS={len(problems)}")
        for problem in problems:
            print(" -", problem)
        return 1
    print("STATIC_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
