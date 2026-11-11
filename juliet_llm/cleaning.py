"""Construct leak-free source views for the frozen Juliet CWE-401 subset.

The frozen subset stores the original Juliet files.  Those files carry the
label in several places: file names, the ``bad``/``good`` identifier stems,
``OMITBAD``/``OMITGOOD`` preprocessor guards, namespace and class names with
``CWE401``/``Memory_Leak``, label-bearing comments, and the literal
``"Benign, fixed string"`` that Juliet prints on some paths.  This module
removes all of them before any text can reach a model request.

Pipeline per unit:

1. strip C/C++ comments (a real scanner, not a regex, so string literals that
   contain ``//`` survive);
2. resolve the small preprocessor subset used by the frozen units
   (``#ifdef``/``#ifndef``/``#endif`` with the unit's compile defines) so only
   the branch that the harness actually compiles remains;
3. inline unit-local headers referenced by quoted ``#include`` directives and
   drop the support header ``std_testcase.h``;
4. rename every identifier whose spelling contains a label stem
   (``bad``/``good``/``CWE``/``Memory_Leak``/``benign``/``fixed``) to a
   unit-local neutral name, and scrub label words inside string literals;
5. audit the result and fail closed if any forbidden token survives.  The
   scrub set and the audit set are kept in sync; the self-check exercises the
   scrub on a synthetic literal built from every audited class.

Nothing here reads or writes model credentials.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
JULIET_DIR = PROJECT_ROOT / "juliet"
SUBSET_PATH = JULIET_DIR / "subset_units.jsonl"

# Tokens that must never reach a prompt.  ``memory_leak`` is allowed in
# instruction and tool-evidence text (it names the defect class, not a CWE
# identifier), so the prompt-level scan keeps it out and ``juliet_llm``
# enforces that extra class locally.  ``label_remediated`` covers the generic
# remediation wording that would otherwise act as a label; it is code-only for
# the same reason (guidance text explains "not a clean result").
FORBIDDEN_PATTERNS: dict[str, str] = {
    "label_bad": r"(?i)bad",
    "label_good": r"(?i)good",
    "cwe": r"(?i)cwe",
    "memory_leak": r"(?i)memory[_ ]leak",
    "omit_macro": r"(?i)omit",
    "flaw_marker": r"(?i)flaw",
    "support_header": r"(?i)std_testcase",
    "source_path": r"(?i)(raw/testcases|/mnt/|juliet/)",
    "label_benign": r"(?i)benign",
    "label_fixed": r"(?i)fixed",
    "label_remediated": r"(?i)\b(?:safe|clean|patched|remediated)\b",
}
PROMPT_FORBIDDEN_PATTERNS = {
    key: pattern
    for key, pattern in FORBIDDEN_PATTERNS.items()
    if key not in {"memory_leak", "label_remediated"}
}

_LEAKY_IDENTIFIER_RE = re.compile(r"(?i)(bad|good|cwe|memory_leak|benign|fixed)")
# Must stay in sync with the audited classes: every audited token is replaced
# here, so ``clean_unit`` can only fail closed on something this scrub missed.
_STRING_TOKEN_RE = re.compile(
    r"(?i)(?:bad|good|cwe\d*|memory[_ ]leak|flaw|omit|std_testcase|benign|fixed"
    r"|raw/testcases|/mnt/|juliet/|\b(?:safe|clean|patched|remediated)\b)"
)
_DIRECTIVE_RE = re.compile(r"^\s*#\s*([A-Za-z_]+)\b(.*)$")
_CONDITIONAL_DIRECTIVE_RE = re.compile(
    r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif|include\s+\")"
)


class CleanError(RuntimeError):
    """Raised when a source view cannot be made leak-free."""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_units(path: Path | str = SUBSET_PATH) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            unit = json.loads(line)
            for key in (
                "unit_id",
                "group_id",
                "family",
                "label",
                "language",
                "sources",
                "split",
                "variant",
                "defines",
            ):
                if key not in unit:
                    raise CleanError(f"{path}:{line_number}: missing key {key!r}")
            units.append(unit)
    if len(units) != len({unit["unit_id"] for unit in units}):
        raise CleanError(f"{path}: duplicate unit_id values")
    return units


def strip_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments while preserving newlines."""
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        following = text[index + 1] if index + 1 < length else ""
        if char == "/" and following == "/":
            index += 2
            while index < length and text[index] != "\n":
                index += 1
        elif char == "/" and following == "*":
            index += 2
            while index < length:
                if text[index] == "*" and index + 1 < length and text[index + 1] == "/":
                    index += 2
                    break
                if text[index] == "\n":
                    out.append("\n")
                index += 1
        elif char in {'"', "'"}:
            quote = char
            out.append(char)
            index += 1
            while index < length:
                out.append(text[index])
                if text[index] == "\\":
                    index += 1
                    if index < length:
                        out.append(text[index])
                    index += 1
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _eval_condition(kind: str, rest: str, defines: set[str]) -> bool:
    expression = rest.strip()
    if kind == "ifdef":
        return expression.split()[0] in defines
    if kind == "ifndef":
        return expression.split()[0] not in defines
    match = re.fullmatch(r"(!?)\s*defined\s*\(?\s*([A-Za-z_]\w*)\s*\)?", expression)
    if match:
        negated, name = match.groups()
        present = name in defines
        return not present if negated else present
    if expression in {"0", "1"}:
        return expression == "1"
    raise CleanError(f"unsupported preprocessor condition: #{kind} {expression}")


def _resolve_file(
    path: Path,
    defines: set[str],
    seen_headers: set[str],
    depth: int,
) -> str:
    if depth > 12:
        raise CleanError(f"include depth exceeded at {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CleanError(f"cannot decode {path}: {exc}") from exc
    text = strip_comments(raw)
    output: list[str] = []
    stack: list[tuple[bool, bool]] = []
    active = True
    for line in text.splitlines():
        match = _DIRECTIVE_RE.match(line)
        if match is None:
            if active:
                output.append(line)
            continue
        kind, rest = match.group(1), match.group(2).strip()
        if kind in {"ifdef", "ifndef", "if"}:
            condition = _eval_condition(kind, rest, defines)
            stack.append((active, condition))
            active = active and condition
        elif kind == "else":
            if not stack:
                raise CleanError(f"{path}: #else without #if")
            parent, condition = stack[-1]
            active = parent and not condition
        elif kind == "endif":
            if not stack:
                raise CleanError(f"{path}: #endif without #if")
            parent, _ = stack.pop()
            active = parent
        elif kind == "elif":
            raise CleanError(f"{path}: #elif is not used by the frozen units")
        elif kind == "include":
            if not active:
                continue
            if rest.startswith('"'):
                closing = rest.find('"', 1)
                if closing < 0:
                    raise CleanError(f"{path}: malformed include {rest!r}")
                name = rest[1:closing]
                local = (path.parent / name).resolve()
                if local.is_file() and JULIET_DIR in local.parents:
                    if str(local) not in seen_headers:
                        seen_headers.add(str(local))
                        output.extend(
                            _resolve_file(local, defines, seen_headers, depth + 1).splitlines()
                        )
                # Quoted support headers are dropped; their declarations are
                # described neutrally in the prompt instead.
            else:
                output.append(line.strip())
        elif kind in {"define", "undef", "pragma"}:
            if active:
                output.append(line.strip())
        else:
            raise CleanError(f"{path}: unsupported preprocessor directive #{kind}")
    if stack:
        raise CleanError(f"{path}: unclosed preprocessor conditional")
    return "\n".join(output)


def _normalize_whitespace(text: str) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    output: list[str] = []
    blank_run = 0
    for line in lines:
        if not line.strip():
            blank_run += 1
            if blank_run > 1:
                continue
        else:
            blank_run = 0
        output.append(line)
    while output and not output[0].strip():
        output.pop(0)
    while output and not output[-1].strip():
        output.pop()
    return "\n".join(output)


def _sanitize_string_literal(literal: str) -> str:
    if len(literal) < 2:
        return literal
    return literal[0] + _STRING_TOKEN_RE.sub("unit", literal[1:-1]) + literal[-1]


def _identifier_is_leaky(identifier: str) -> bool:
    return _LEAKY_IDENTIFIER_RE.search(identifier) is not None


def neutralize_identifiers(
    code: str, mapping: dict[str, str] | None = None
) -> tuple[str, dict[str, str]]:
    """Rename label-bearing identifiers and scrub label-bearing strings."""
    mapping = {} if mapping is None else mapping
    output: list[str] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        if char in {'"', "'"}:
            end = index + 1
            while end < length:
                if code[end] == "\\":
                    end += 2
                    continue
                if code[end] == char:
                    end += 1
                    break
                end += 1
            literal = code[index:end]
            if char == '"':
                literal = _sanitize_string_literal(literal)
            output.append(literal)
            index = end
        elif char.isalpha() or char == "_":
            end = index
            while end < length and (code[end].isalnum() or code[end] == "_"):
                end += 1
            token = code[index:end]
            if _identifier_is_leaky(token):
                if token not in mapping:
                    mapping[token] = f"sym_{len(mapping)}"
                output.append(mapping[token])
            else:
                output.append(token)
            index = end
        elif char.isdigit():
            end = index
            while end < length and (code[end].isalnum() or code[end] in "._"):
                end += 1
            token = code[index:end]
            if _identifier_is_leaky(token):
                raise CleanError(f"label token inside numeric literal {token!r}")
            output.append(token)
            index = end
        else:
            output.append(char)
            index += 1
    return "".join(output), mapping


def _string_aware_scan(code: str) -> Iterable[str]:
    """Yield characters outside string and character literals."""
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        if char in {'"', "'"}:
            quote = char
            index += 1
            while index < length:
                if code[index] == "\\":
                    index += 2
                    continue
                if code[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        yield char
        index += 1


def brace_balance(code: str) -> tuple[bool, int]:
    depth = 0
    lowest = 0
    for char in _string_aware_scan(code):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            lowest = min(lowest, depth)
    return depth == 0 and lowest >= 0, depth


def scan(text: str, patterns: dict[str, str]) -> dict[str, int]:
    return {name: len(re.findall(pattern, text)) for name, pattern in patterns.items()}


def forbidden_hits(text: str) -> dict[str, int]:
    return scan(text, FORBIDDEN_PATTERNS)


def prompt_forbidden_hits(text: str) -> dict[str, int]:
    return scan(text, PROMPT_FORBIDDEN_PATTERNS)


@dataclass(frozen=True)
class CleanedUnit:
    unit_id: str
    group_id: str
    family: str
    split: str
    label: str
    language: str
    variant: str
    code: str
    code_sha256: str
    mapping: dict[str, str]
    before_hits: dict[str, int]
    after_hits: dict[str, int]
    checks: dict[str, Any]

    def audit_record(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "group_id": self.group_id,
            "family": self.family,
            "split": self.split,
            "label": self.label,
            "language": self.language,
            "variant": self.variant,
            "code_chars": len(self.code),
            "code_sha256": self.code_sha256,
            "before_hits": self.before_hits,
            "after_hits": self.after_hits,
            "checks": self.checks,
            "renamed_identifier_count": len(self.mapping),
            "renamed_identifiers_sha256": sha256_text(
                json.dumps(self.mapping, sort_keys=True)
            ),
        }


def clean_unit(unit: dict[str, Any]) -> CleanedUnit:
    defines = set(unit["defines"])
    seen_headers: set[str] = set()
    raw_parts: list[str] = []
    for relative in unit["sources"]:
        path = (JULIET_DIR / relative).resolve()
        if JULIET_DIR not in path.parents:
            raise CleanError(f"{unit['unit_id']}: source outside juliet/: {relative}")
        raw_parts.append(path.read_text(encoding="utf-8"))

    cleaned_parts: list[str] = []
    mapping: dict[str, str] = {}
    for relative in unit["sources"]:
        path = (JULIET_DIR / relative).resolve()
        resolved = _normalize_whitespace(_resolve_file(path, defines, seen_headers, 0))
        if not resolved.strip():
            continue
        neutral, mapping = neutralize_identifiers(resolved, mapping)
        normalized = _normalize_whitespace(neutral)
        if normalized.strip():
            cleaned_parts.append(normalized)
    if not cleaned_parts:
        raise CleanError(f"{unit['unit_id']}: cleaning removed every line")

    body = "\n\n".join(cleaned_parts)
    before_hits = forbidden_hits("\n\n".join(raw_parts))
    after_hits = forbidden_hits(body)
    balanced, depth = brace_balance(body)
    remaining_directives = [
        line
        for line in body.splitlines()
        if _CONDITIONAL_DIRECTIVE_RE.match(line)
    ]
    comment_residue = re.findall(r"/\*|\*/", body)
    checks = {
        "forbidden_tokens_absent": all(count == 0 for count in after_hits.values()),
        "unit_id_absent": unit["unit_id"] not in body,
        "group_id_absent": unit["group_id"] not in body,
        "no_conditional_directives": not remaining_directives,
        "no_comment_residue": not comment_residue,
        "braces_balanced": balanced,
        "brace_depth": depth,
        "nonempty": bool(body.strip()),
        "no_empty_parts": len(cleaned_parts) == len(
            [part for part in cleaned_parts if part.strip()]
        ),
    }
    failed = [name for name, ok in checks.items() if isinstance(ok, bool) and not ok]
    if failed:
        detail = {
            "after_hits": after_hits,
            "remaining_directives": remaining_directives[:3],
            "checks": checks,
        }
        raise CleanError(f"{unit['unit_id']}: cleaning audit failed {failed}: {detail}")

    code = "\n\n".join(
        f"// ---- part {index} ----\n{part}"
        for index, part in enumerate(cleaned_parts, 1)
    )
    return CleanedUnit(
        unit_id=unit["unit_id"],
        group_id=unit["group_id"],
        family=unit["family"],
        split=unit["split"],
        label=unit["label"],
        language=unit["language"],
        variant=unit["variant"],
        code=code,
        code_sha256=sha256_text(code),
        mapping=mapping,
        before_hits=before_hits,
        after_hits=after_hits,
        checks=checks,
    )


def clean_all(
    units: Iterable[dict[str, Any]],
) -> tuple[list[CleanedUnit], dict[str, Any]]:
    cleaned: list[CleanedUnit] = []
    seen: set[str] = set()
    for unit in units:
        if unit["unit_id"] in seen:
            raise CleanError(f"duplicate unit in input: {unit['unit_id']}")
        seen.add(unit["unit_id"])
        cleaned.append(clean_unit(unit))
    summary = {
        "units": len(cleaned),
        "by_split": {},
        "by_label": {},
        "by_language": {},
        "before_hits": {},
        "after_hits": {},
        "checks": {},
        "renamed_identifiers_total": sum(len(item.mapping) for item in cleaned),
    }
    for item in cleaned:
        for key, bucket in (
            ("split", summary["by_split"]),
            ("label", summary["by_label"]),
            ("language", summary["by_language"]),
        ):
            value = getattr(item, key)
            bucket[value] = bucket.get(value, 0) + 1
        for name, count in item.before_hits.items():
            summary["before_hits"][name] = summary["before_hits"].get(name, 0) + count
        for name, count in item.after_hits.items():
            summary["after_hits"][name] = summary["after_hits"].get(name, 0) + count
        for name, value in item.checks.items():
            if isinstance(value, bool):
                summary["checks"][name] = summary["checks"].get(name, 0) + int(value)
    return cleaned, summary


def load_manifest_units() -> dict[str, dict[str, Any]]:
    manifest_path = JULIET_DIR / "manifest.json"
    with manifest_path.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    return {unit["unit_id"]: unit for unit in manifest.get("units", [])}
