from __future__ import annotations

import re
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LEAK_HEADER = "ERROR: LeakSanitizer: detected memory leaks"
DIRECT_RE = re.compile(
    r"(?P<kind>Direct|Indirect) leak of (?P<bytes>[\d,]+) byte\(s\) in "
    r"(?P<objects>[\d,]+) object\(s\) allocated from:"
)
SUMMARY_RE = re.compile(
    r"SUMMARY: AddressSanitizer: (?P<bytes>[\d,]+) byte\(s\) leaked in "
    r"(?P<allocations>[\d,]+) allocation\(s\)"
)
ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: (?P<kind>[A-Za-z0-9_./-]+)")
ASAN_SUMMARY_KIND_RE = re.compile(r"SUMMARY: AddressSanitizer: (?P<kind>[a-z][a-z0-9-]+)")
FATAL_RE = re.compile(
    r"LeakSanitizer has encountered a fatal error|"
    r"AddressSanitizer: CHECK failed|"
    r"ASan runtime does not come first|"
    r"AddressSanitizer: failed to intercept"
)
FRAME_RE = re.compile(r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<fn>.+?)(?:\s+(?P<where>\(?[^()]+\)?))?$")


def _number(text: str) -> int:
    try:
        return int(text.replace(",", ""))
    except (TypeError, ValueError):
        return 0


def parse_lsan(text: str) -> dict[str, Any]:
    """Parse LeakSanitizer/ASan output.

    A leak is reported only from tool output, never from an exit code alone.
    The same parser is used for LSan reports written to stderr and for reports
    redirected through ``ASAN_OPTIONS=log_path=...``.
    """
    text = ANSI_RE.sub("", text or "")
    lines = text.splitlines()
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    memory_errors: list[str] = []
    evidence_lines: list[str] = []
    saw_header = False
    summary_bytes = 0
    summary_allocations = 0
    fatal = False

    for line in lines:
        stripped = line.strip()
        if LEAK_HEADER in line:
            saw_header = True
            if current is not None:
                records.append(current)
                current = None
            evidence_lines.append(stripped)
            continue
        match = DIRECT_RE.search(line)
        if match:
            if current is not None:
                records.append(current)
            current = {
                "kind": match.group("kind").lower(),
                "bytes": _number(match.group("bytes")),
                "objects": _number(match.group("objects")),
                "stack": [],
            }
            evidence_lines.append(stripped)
            continue
        if current is not None:
            frame = FRAME_RE.match(line)
            if frame and len(current["stack"]) < 8:
                current["stack"].append(
                    {
                        "function": frame.group("fn").strip(),
                        "location": (frame.group("where") or "").strip(),
                    }
                )
                continue
            if stripped.startswith("SUMMARY:"):
                records.append(current)
                current = None
            elif not stripped:
                continue
        if stripped.startswith("SUMMARY:"):
            summary = SUMMARY_RE.search(line)
            if summary:
                summary_bytes = _number(summary.group("bytes"))
                summary_allocations = _number(summary.group("allocations"))
            kind_match = ASAN_SUMMARY_KIND_RE.search(line)
            if kind_match:
                kind = kind_match.group("kind")
                if kind not in memory_errors:
                    memory_errors.append(kind)
            evidence_lines.append(stripped)
            continue
        error = ASAN_ERROR_RE.search(line)
        if error:
            kind = error.group("kind")
            if "attempting free on address" in line or "attempting free" in line:
                kind = "bad-free"
            elif "attempting double-free" in line:
                kind = "double-free"
            if kind not in {"LeakSanitizer", "DEADLYSIGNAL"}:
                if kind not in memory_errors:
                    memory_errors.append(kind)
                evidence_lines.append(stripped)
            elif kind == "DEADLYSIGNAL":
                if "DEADLYSIGNAL" not in memory_errors:
                    memory_errors.append("DEADLYSIGNAL")
                evidence_lines.append(stripped)
        if FATAL_RE.search(line):
            fatal = True
            evidence_lines.append(stripped)
        if "Suppressions used:" in line:
            evidence_lines.append(stripped)

    if current is not None:
        records.append(current)

    direct_records = [item for item in records if item["kind"] == "direct"]
    indirect_records = [item for item in records if item["kind"] == "indirect"]
    direct_bytes = sum(item["bytes"] for item in direct_records)
    indirect_bytes = sum(item["bytes"] for item in indirect_records)
    record_bytes = direct_bytes + indirect_bytes
    leaked_bytes = max(record_bytes, summary_bytes)
    leak_detected = bool(saw_header or direct_records or indirect_records or summary_bytes > 0)

    return {
        "tool": "lsan",
        "leak_detected": leak_detected,
        "leaked_bytes": leaked_bytes if leak_detected else 0,
        "direct_bytes": direct_bytes,
        "indirect_bytes": indirect_bytes,
        "summary_bytes": summary_bytes,
        "summary_allocations": summary_allocations,
        "records": records[:20],
        "record_count": len(records),
        "memory_errors": memory_errors,
        "fatal_error": fatal,
        "suppressed_count": sum(1 for line in lines if "Suppressions used:" in line),
        "evidence_excerpt": "\n".join(evidence_lines[:30]),
    }


def detector_status(
    parsed: dict[str, Any],
    *,
    exit_code: int | None,
    timed_out: bool,
    spawn_error: str | None,
    signal_name: str | None,
) -> tuple[str, list[str]]:
    """Turn parsed LSan evidence plus process outcome into a detector status."""
    notes: list[str] = []
    if spawn_error:
        return "error", [spawn_error]
    if timed_out:
        return "inconclusive", ["execution timed out before leak check"]
    if signal_name:
        notes.append(f"process terminated by {signal_name}")
    if parsed.get("fatal_error"):
        return "error", notes + ["LeakSanitizer/ASan fatal runtime error"]
    if parsed.get("leak_detected"):
        if parsed.get("memory_errors"):
            notes.append("non-leak ASan errors also present: " + ", ".join(parsed["memory_errors"]))
        return "leak", notes
    if parsed.get("memory_errors"):
        return "inconclusive", notes + ["ASan reported memory errors: " + ", ".join(parsed["memory_errors"])]
    if exit_code is None:
        return "error", notes + ["process did not return an exit code"]
    if signal_name:
        return "inconclusive", notes
    if exit_code != 0:
        return "inconclusive", notes + [f"nonzero exit code {exit_code} without leak evidence"]
    return "clean", notes
