"""Prompt builders for the enhanced-dynamic-guidance run.

``direct`` delegates byte-for-byte to the frozen v2 builder
(``hybrid/prompts.py`` -> ``juliet_llm.prompting.build_messages``).  The new
method keeps the same system prompt and the same evidence wrapper as v2; only
the evidence block body changes.  Preflight asserts both equalities.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import prompts as v2_prompts  # hybrid/prompts.py (ROOT/hybrid is on sys.path)
from juliet_llm.cleaning import prompt_forbidden_hits

from .config import GUIDED_PROMPT_VERSION, METHOD
from .evidence import audit_evidence

EVIDENCE_TEMPLATE = """Audit the code unit below and return the verdict.

<Tool evidence>
{evidence}
</Tool evidence>

```{language}
{code}
```

Tool evidence is machine-generated and may be incomplete or wrong. A tool that
reports no finding does not prove the code is clean, a failed analysis is not a
clean result, and a dynamic result marked inconclusive is NOT a clean result.

Return only the JSON object."""

_EXTENDED_LABEL = re.compile(r"(?i)\b(?:benign|fixed)\b")


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    payload = json.dumps(messages, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _audit(messages: list[dict[str, str]], unit: dict[str, Any], evidence: str | None) -> None:
    joined = "\n".join(message["content"] for message in messages)
    hits = {name: count for name, count in prompt_forbidden_hits(joined).items() if count}
    if hits:
        raise ValueError(f"{unit['unit_id']}: prompt leak audit failed: {hits}")
    extended = sorted(set(_EXTENDED_LABEL.findall(joined)))
    if extended:
        raise ValueError(f"{unit['unit_id']}: prompt contains label word(s) {extended}")
    if unit["unit_id"] in joined or unit["group_id"] in joined:
        raise ValueError(f"{unit['unit_id']}: unit identifier leaked into prompt")
    if evidence is not None:
        audit_evidence(evidence, f"{unit['unit_id']} evidence")
        if joined.count(evidence) != 1:
            raise ValueError(f"{unit['unit_id']}: evidence block is not present exactly once")


def build_direct(unit: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    messages, metadata = v2_prompts.build_messages(unit, "direct")
    _audit(messages, unit, None)
    return messages, {
        **metadata,
        "prompt_version": v2_prompts.PROMPT_VERSION,
        "method": "direct",
        "evidence_included": False,
        "evidence_sha256": None,
    }


def build_guided(unit: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    evidence = unit["enhanced_evidence"]
    language = "cpp" if unit["language"] == "cpp" else "c"
    user = EVIDENCE_TEMPLATE.format(
        evidence=evidence,
        language=language,
        code=unit["source_text"],
    )
    messages = [
        {"role": "system", "content": v2_prompts.SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    _audit(messages, unit, evidence)
    return messages, {
        "prompt_version": GUIDED_PROMPT_VERSION,
        "method": METHOD,
        "evidence_included": True,
        "evidence_sha256": unit["enhanced_evidence_sha256"],
        "message_count": len(messages),
        "prompt_sha256": prompt_sha256(messages),
    }
