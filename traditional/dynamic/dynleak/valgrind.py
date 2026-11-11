from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

LEAK_KINDS = {
    "Leak_DefinitelyLost": "definite",
    "Leak_IndirectlyLost": "indirect",
    "Leak_PossiblyLost": "possible",
    "Leak_StillReachable": "still_reachable",
}
BYTES_RE = re.compile(r"(?P<bytes>[\d,]+) bytes? in (?P<blocks>[\d,]+) blocks?")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in node:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_text(node: ET.Element, name: str) -> str:
    for child in node.iter():
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _number(text: str) -> int:
    try:
        return int((text or "0").replace(",", ""))
    except ValueError:
        return 0


def parse_valgrind_xml(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tool": "valgrind",
        "xml_path": str(path),
        "leak_detected": False,
        "definite_bytes": 0,
        "indirect_bytes": 0,
        "possible_bytes": 0,
        "still_reachable_bytes": 0,
        "definite_records": 0,
        "indirect_records": 0,
        "possible_records": 0,
        "still_reachable_records": 0,
        "other_errors": [],
        "records": [],
        "program_exit_code": None,
        "fatal_signal": None,
        "parse_error": None,
        "evidence_excerpt": "",
    }
    if not path.is_file():
        result["parse_error"] = "Valgrind XML file is missing"
        return result
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
        return result

    evidence: list[str] = []
    for node in root.iter():
        tag = _local(node.tag)
        if tag == "error":
            kind = _child_text(node, "kind")
            kind_base = kind.split(" ")[0] if kind else ""
            xwhat_text = _find_text(node, "text")
            leaked_bytes = _number(_find_text(node, "leakedbytes"))
            if not leaked_bytes:
                match = BYTES_RE.search(xwhat_text)
                if match:
                    leaked_bytes = _number(match.group("bytes"))
            frames: list[dict[str, str]] = []
            for frame in node.iter():
                if _local(frame.tag) != "frame":
                    continue
                frames.append(
                    {
                        "function": _find_text(frame, "fn"),
                        "file": _find_text(frame, "file"),
                        "line": _find_text(frame, "line"),
                    }
                )
                if len(frames) >= 12:
                    break
            kind_group = LEAK_KINDS.get(kind_base)
            record = {
                "kind": kind,
                "bytes": leaked_bytes,
                "text": xwhat_text,
                "frames": frames,
            }
            if kind_group is not None:
                result[f"{kind_group}_bytes"] += leaked_bytes
                result[f"{kind_group}_records"] += 1
                result["records"].append(record)
                if len(evidence) < 20:
                    evidence.append(f"{kind}: {xwhat_text}")
            else:
                result["other_errors"].append(
                    {"kind": kind, "text": xwhat_text, "frames": frames[:5]}
                )
                if len(evidence) < 20:
                    evidence.append(f"{kind}: {xwhat_text}")
        elif tag == "fatal_signal":
            result["fatal_signal"] = _find_text(node, "signame") or _find_text(node, "sicode")
        elif tag == "status":
            exit_text = _child_text(node, "exitcode")
            if exit_text:
                try:
                    result["program_exit_code"] = int(exit_text)
                except ValueError:
                    pass

    result["leak_detected"] = bool(result["definite_records"] or result["definite_bytes"])
    result["evidence_excerpt"] = "\n".join(evidence)
    return result


def detector_status(
    parsed: dict[str, Any],
    *,
    exit_code: int | None,
    timed_out: bool,
    spawn_error: str | None,
    signal_name: str | None,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    if spawn_error:
        return "error", [spawn_error]
    if timed_out:
        return "inconclusive", ["Valgrind execution timed out"]
    if parsed.get("parse_error"):
        return "error", [parsed["parse_error"]]
    if parsed.get("leak_detected"):
        if parsed.get("fatal_signal"):
            notes.append(f"program received {parsed['fatal_signal']}")
        return "leak", notes
    if parsed.get("fatal_signal") or signal_name:
        return "inconclusive", notes + [
            f"program terminated by signal {parsed.get('fatal_signal') or signal_name}"
        ]
    if parsed.get("other_errors"):
        return "inconclusive", notes + [
            "Valgrind reported non-leak memory errors: "
            + ", ".join(sorted({item["kind"] for item in parsed["other_errors"] if item.get("kind")}))
        ]
    if exit_code is None:
        return "error", notes + ["process did not return an exit code"]
    if exit_code not in (0,):
        return "inconclusive", notes + [f"nonzero exit code {exit_code} without definite leak evidence"]
    return "clean", notes
