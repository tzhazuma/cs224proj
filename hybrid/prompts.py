"""Prompt construction for the hybrid evidence-guidance experiment.

``direct`` reuses ``juliet_llm.prompting.build_messages`` byte-for-byte, so the
baseline is exactly the Juliet LLM baseline.  Guided methods keep that system
prompt and output schema and only add a delimited tool-evidence block to the
user message.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from juliet_llm.cleaning import CleanedUnit, prompt_forbidden_hits  # noqa: E402
from juliet_llm.prompting import (  # noqa: E402
    PROMPT_VERSION as JULIET_PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_messages as build_direct_messages,
)

PROMPT_VERSION = f"hybrid-v2-{JULIET_PROMPT_VERSION}"
METHODS = ("direct", "static", "dynamic", "combined", "shuffled")
EVIDENCE_METHODS = ("static", "dynamic", "combined", "shuffled")

# The release audit (C3/D6) found ``benign``/``fixed`` string literals in six
# good units.  The shared cleaner now removes them; this second gate makes the
# hybrid prompt builder fail closed even if that cleaner regresses.
_EXTENDED_LABEL = re.compile(r"(?i)\b(?:benign|fixed)\b")

_EVIDENCE_TEMPLATE = """Audit the code unit below and return the verdict.

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


def prompt_sha256(messages: list[dict[str, str]]) -> str:
    payload = json.dumps(messages, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _audit(messages: list[dict[str, str]], unit_id: str, group_id: str) -> None:
    joined = "\n".join(message["content"] for message in messages)
    hits = {name: count for name, count in prompt_forbidden_hits(joined).items() if count}
    if hits:
        raise ValueError(f"{unit_id}: prompt leak audit failed: {hits}")
    extended = sorted(set(_EXTENDED_LABEL.findall(joined)))
    if extended:
        raise ValueError(f"{unit_id}: prompt contains label word(s) {extended}")
    if unit_id in joined or group_id in joined:
        raise ValueError(f"{unit_id}: unit identifier leaked into prompt")


def build_messages(unit: dict[str, Any], method: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if method not in METHODS:
        raise ValueError(f"unknown method {method!r}")
    cleaned = CleanedUnit(
        unit_id=unit["unit_id"],
        group_id=unit["group_id"],
        family=unit["family"],
        split=unit["split"],
        label="bad" if unit["label"] else "good",
        language=unit["language"],
        variant=unit["variant"],
        code=unit["source_text"],
        code_sha256=unit["source_sha256"],
        mapping={},
        before_hits={},
        after_hits={},
        checks=unit.get("cleaning_checks", {}),
    )
    if method == "direct":
        messages = build_direct_messages(cleaned)
    else:
        evidence = unit["placebo_evidence"] if method == "shuffled" else unit["evidence"][method]
        language = "cpp" if unit["language"] == "cpp" else "c"
        user = _EVIDENCE_TEMPLATE.format(
            evidence=evidence,
            language=language,
            code=unit["source_text"],
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ]
    _audit(messages, unit["unit_id"], unit["group_id"])
    metadata = {
        "prompt_version": PROMPT_VERSION,
        "method": method,
        "evidence_included": method in EVIDENCE_METHODS,
        "message_count": len(messages),
        "prompt_sha256": prompt_sha256(messages),
    }
    return messages, metadata
