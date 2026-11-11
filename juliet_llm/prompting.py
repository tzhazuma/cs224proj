"""Prompt construction for the frozen Juliet CWE-401 binary task.

The instruction text never contains a CWE number, a path, or a label token.
The code block is produced by :mod:`juliet_llm.cleaning`, which fails closed if
any such token survives.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .cleaning import (
    FORBIDDEN_PATTERNS,
    CleanedUnit,
    PROMPT_FORBIDDEN_PATTERNS,
    prompt_forbidden_hits,  # re-exported for audit/run_final_audit.py
    scan,
    sha256_text,
)

PROMPT_VERSION = "juliet-llm-binary-2026-11-12.2"

# The shipped prompt never names the defect class as ``memory_leak``; this
# local set enforces that in addition to the shared prompt scan, which keeps
# ``memory_leak`` allowed for instruction and tool-evidence text elsewhere.
STRICT_PROMPT_PATTERNS = {
    **PROMPT_FORBIDDEN_PATTERNS,
    "memory_leak": FORBIDDEN_PATTERNS["memory_leak"],
}

SYSTEM_PROMPT = """You are a careful C/C++ memory-safety auditor. You receive one code unit: the translation units that a test harness compiles together and runs to completion. Decide whether the executed code leaks heap memory.

Definition used for this audit:
- A leak is heap memory obtained from malloc, calloc, realloc, strdup, or new/new[] that is never released with free, delete, or delete[] before the program ends.
- This includes memory that becomes unreachable, memory still held by a global or static pointer at exit, and memory that leaks only on some paths, for example when a reallocation fails.
- Stack storage, static storage, and memory released on every path are not leaks.

Support code outside the audited unit: the print* helpers (printLine, printIntLine, printLongLongLine, printWLine, printHexCharLine, printStructLine, and similar) only write to stdout; ALLOCA(n) reserves n bytes in the current stack frame; twoIntsStruct and TwoIntsClass are plain data types with two int fields; the standard C and C++ libraries are available.

Answer with one JSON object and nothing else:
{"label": "vulnerable" or "not_vulnerable", "confidence": <number from 0 to 1>, "reason": "<at most 30 words>"}
Use "vulnerable" when the unit leaks heap memory and "not_vulnerable" otherwise."""

USER_TEMPLATE = """Audit the code unit below and return the verdict.

```{language}
{code}
```

Return only the JSON object."""


def build_messages(unit: CleanedUnit) -> list[dict[str, str]]:
    code = unit.code
    if "```" in code:
        raise ValueError(f"{unit.unit_id}: code contains a Markdown fence")
    language = "cpp" if unit.language == "cpp" else "c"
    user = USER_TEMPLATE.format(language=language, code=code)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    audit_prompt(messages, unit)
    return messages


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    return sha256_text(
        json.dumps(messages, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


def audit_prompt(messages: list[dict[str, str]], unit: CleanedUnit) -> None:
    joined = "\n".join(message["content"] for message in messages)
    hits = scan(joined, STRICT_PROMPT_PATTERNS)
    leaks = {name: count for name, count in hits.items() if count}
    if leaks:
        raise ValueError(f"{unit.unit_id}: prompt leak audit failed: {leaks}")
    for identifier in (unit.unit_id, unit.group_id):
        if identifier in joined:
            raise ValueError(f"{unit.unit_id}: identifier leaked into prompt")


def input_record(unit: CleanedUnit) -> dict[str, Any]:
    messages = build_messages(unit)
    return {
        "unit_id": unit.unit_id,
        "group_id": unit.group_id,
        "split": unit.split,
        "label": unit.label,
        "language": unit.language,
        "variant": unit.variant,
        "family": unit.family,
        "code_sha256": unit.code_sha256,
        "prompt_sha256": prompt_sha256(messages),
        "messages": messages,
        "code_chars": len(unit.code),
        "prompt_chars": sum(len(message["content"]) for message in messages),
        "estimated_prompt_tokens": round(
            sum(len(message["content"]) for message in messages) / 4
        ),
        "audit": {
            "before_hits": unit.before_hits,
            "after_hits": unit.after_hits,
            "checks": unit.checks,
        },
    }
