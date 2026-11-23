"""Prompt assembly from the files in llm/prompts/ (hashes go into run meta).

Generative models (DeepSeek, Qwen) get identical messages:
  system = task.txt + answer_format.txt [+ l2_examples.txt]      (L1, L2, L3)
  system = l4_system.txt                                         (L4)
  user   = user_L1.txt | user_L3.txt (+ user_suffix.txt) | l4_user.txt
Fixed text is in the system message so it forms a cacheable prefix; the code comes last.
Jev gets state = task.txt [+ l2_examples.txt] + the filled user template, without the JSON
answer-format lines (its answer is the noul probability of jev_question.json).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from . import PROJECT_ROOT, PROMPT_DIR

sys.path.insert(0, str(PROJECT_ROOT))
from juliet_llm.cleaning import FORBIDDEN_PATTERNS, PROMPT_FORBIDDEN_PATTERNS, scan  # noqa: E402

AUDIT_PATTERNS = {**PROMPT_FORBIDDEN_PATTERNS, "memory_leak": FORBIDDEN_PATTERNS["memory_leak"]}
STRATEGIES = ("L1", "L2", "L3", "L4")


class PromptAuditError(ValueError):
    pass


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_prompt(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8").rstrip()


def audit(text: str, unit_id: str, group_id: str, tool_evidence: str = "") -> None:
    """Forbidden-token scan. `tool_evidence` (analyzer messages, already part of `text`) is scanned with
    PROMPT_FORBIDDEN_PATTERNS only: Clang's "Potential memory leak" names the defect class, as
    juliet_llm/cleaning.py allows for tool-evidence text; everything else also excludes memory_leak."""
    rest = text.replace(tool_evidence, "") if tool_evidence else text
    hits = {k: v for k, v in scan(rest, AUDIT_PATTERNS).items() if v}
    if tool_evidence:
        for k, v in scan(tool_evidence, PROMPT_FORBIDDEN_PATTERNS).items():
            if v:
                hits[k] = hits.get(k, 0) + v
    if hits:
        raise PromptAuditError(f"forbidden tokens in prompt: {hits}")
    if unit_id in text or group_id in text:
        raise PromptAuditError("unit identifier in prompt")


def number_lines(code: str) -> str:
    """L4 listing: `<n>| <line>` with n counted from 1, the numbering of model_text_line and L4 Line facts."""
    lines = code.split("\n")
    width = len(str(len(lines)))
    return "\n".join(f"{i:>{width}}| {line}".rstrip() for i, line in enumerate(lines, 1))


def fence_language(unit: dict[str, Any]) -> str:
    return "cpp" if unit.get("language") == "cpp" else "c"


def _line_lookup(unit: dict[str, Any]) -> dict[tuple[str, int], int]:
    lookup = {}
    for source_file, source_line, model_line in unit.get("line_map") or []:
        lookup[(os.path.basename(str(source_file)), int(source_line))] = int(model_line)
    return lookup


def render_evidence(record: dict[str, Any] | None, unit: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Text block for L3 plus bookkeeping. Accepted record keys (static lane):
    unit_id, optional status ("ok" when the analyzer completed; absent means ok), warnings:
    [{checker, message, model_text_line | (source_file, source_line) | (file, line)}] as written by
    static/run_static.py evidence_row. Warnings without a model_text line are shown without a number."""
    if record is None:
        return "The analyzer produced no result for this code unit.", {"evidence": "missing", "n_warnings": 0}
    status = record.get("status", "ok")
    if status != "ok":
        return ("The analyzer did not complete on this code unit, so no warnings are available.",
                {"evidence": f"analysis_{status}", "n_warnings": 0})
    warnings = record.get("warnings") or []
    if not warnings:
        return "The analyzer reported no warnings.", {"evidence": "no_warnings", "n_warnings": 0}
    lookup = _line_lookup(unit)
    lines, unmapped = [], 0
    for warning in warnings:
        model_line = warning.get("model_text_line")
        source_file = warning.get("source_file") or warning.get("file")
        source_line = warning.get("source_line") if warning.get("source_line") is not None else warning.get("line")
        if model_line is None and source_file and source_line is not None:
            model_line = lookup.get((os.path.basename(str(source_file)), int(source_line)))
        message = " ".join(str(warning.get("message", "")).split())
        checker = warning.get("checker")
        suffix = f" [{checker}]" if checker else ""
        if model_line is None:
            unmapped += 1
            lines.append(f"- {message}{suffix}")
        else:
            lines.append(f"- line {model_line}: {message}{suffix}")
    n = len(warnings)
    head = f"The analyzer reported {n} warning{'s' if n != 1 else ''}:"
    return head + "\n" + "\n".join(lines), {"evidence": "warnings", "n_warnings": n, "unmapped_lines": unmapped}


@dataclass
class PromptSet:
    strategy: str
    target: str = "chat"  # "chat" (DeepSeek, Qwen) or "jev"
    files: dict[str, str] = field(default_factory=dict)  # prompt file name -> sha256

    def __post_init__(self) -> None:
        if self.strategy not in STRATEGIES:
            raise ValueError(f"unknown strategy {self.strategy}")
        if self.target not in ("chat", "jev") or (self.target == "jev" and self.strategy == "L4"):
            raise ValueError(f"strategy {self.strategy} does not apply to target {self.target}")
        self._text: dict[str, str] = {}
        for name in self.file_names():
            self._text[name] = read_prompt(name)
            self.files[name] = sha256_text(self._text[name])

    def file_names(self) -> list[str]:
        if self.strategy == "L4":
            return ["l4_system.txt", "l4_user.txt"]
        names = ["task.txt"]
        names += ["answer_format.txt", "user_suffix.txt"] if self.target == "chat" else ["jev_question.json"]
        names.append("user_L3.txt" if self.strategy == "L3" else "user_L1.txt")
        if self.strategy == "L2":
            names.append("l2_examples.txt")
        return names

    @property
    def prompt_hash(self) -> str:
        return sha256_text(json.dumps(sorted(self.files.items())))

    @property
    def system(self) -> str:
        if self.strategy == "L4":
            return self._text["l4_system.txt"]
        parts = [self._text["task.txt"], self._text["answer_format.txt"]]
        if self.strategy == "L2":
            parts.append(self._text["l2_examples.txt"])
        return "\n\n".join(parts)

    @property
    def jev_prefix(self) -> str:
        parts = [self._text["task.txt"]]
        if self.strategy == "L2":
            parts.append(self._text["l2_examples.txt"])
        return "\n\n".join(parts)

    @property
    def jev_question(self) -> dict[str, Any]:
        return json.loads(self._text["jev_question.json"])

    def user_body(self, unit: dict[str, Any], evidence: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        code = unit["model_text"].rstrip()
        if "```" in code:
            raise PromptAuditError("code contains a Markdown fence")
        if self.strategy == "L4":
            code = number_lines(code)
        name = {"L3": "user_L3.txt", "L4": "l4_user.txt"}.get(self.strategy, "user_L1.txt")
        text = self._text[name].replace("{language}", fence_language(unit)).replace("{code}", code)
        info: dict[str, Any] = {}
        if self.strategy == "L3":
            evidence_text, info = render_evidence(evidence, unit)
            text = text.replace("{evidence}", evidence_text)
            info["_evidence_text"] = evidence_text
        return text, info

    def messages(self, unit: dict[str, Any], evidence: dict[str, Any] | None = None) \
            -> tuple[list[dict[str, str]], dict[str, Any]]:
        user, info = self.user_body(unit, evidence)
        evidence_text = info.pop("_evidence_text", "")
        if self.strategy != "L4":
            user = user + "\n\n" + self._text["user_suffix.txt"]
        messages = [{"role": "system", "content": self.system}, {"role": "user", "content": user}]
        audit(self.system + "\n" + user, unit["unit_id"], unit["group_id"], evidence_text)
        return messages, info

    def jev_state(self, unit: dict[str, Any], evidence: dict[str, Any] | None = None) \
            -> tuple[str, dict[str, Any]]:
        user, info = self.user_body(unit, evidence)
        evidence_text = info.pop("_evidence_text", "")
        state = self.jev_prefix + "\n\n" + user
        audit(state + "\n" + json.dumps(self.jev_question), unit["unit_id"], unit["group_id"], evidence_text)
        return state, info
