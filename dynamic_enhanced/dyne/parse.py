"""Parse LeakSanitizer reports and attribute a leak to the unit under test.

LSan prints one block per leaked allocation, with the allocation stack.  The
first frame that carries a source location *outside* the toolchain and the
sanitizer runtime is the allocation site that matters.  A block is attributed
to the unit only when that frame points into the unit's own sources (or a
group-local header).  This is what keeps the 1 KB glibc stdio buffer and the
libstdc++ runtime allocations -- both of which become visible when global
roots are disabled -- from being counted as unit leaks.

Attribution is a property of the runtime stack, not of the file name of the
test case, so it cannot be used to predict a label before running the unit.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .units import Unit

BLOCK_START = re.compile(
    r"^(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:$"
)
FRAME = re.compile(r"^\s+#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.*)$")
LOCATION = re.compile(r"(\S+):(\d+)(?:\s|$)")
LSAN_SUMMARY = re.compile(r"SUMMARY: AddressSanitizer: (\d+) byte\(s\) leaked in (\d+) allocation\(s\)")
ASAN_ERROR = re.compile(r"ERROR: AddressSanitizer: ([A-Za-z0-9_\-]+)")
DEADLY = re.compile(r"DEADLYSIGNAL|SUMMARY: AddressSanitizer: SEGV")

SYSTEM_PREFIXES = (
    "/usr/",
    "/lib/",
    "/lib64/",
    "/opt/",
    "/proc/",
    "/sys/",
    "<",
)
SYSTEM_MARKERS = ("libsanitizer", "asan_malloc", "asan_interceptors", "sanitizer_common")


@dataclass
class Frame:
    index: int
    function: str
    file: str | None
    line: int | None
    raw: str

    @property
    def is_system(self) -> bool:
        if self.file is None:
            return True
        lowered = self.file.lower()
        if lowered.startswith(SYSTEM_PREFIXES):
            return True
        if "dynamic_enhanced/" in lowered or "inject_realloc.c" in lowered:
            # The evaluator's link wrapper is not part of the unit; the next
            # frame is the caller that owns the allocation.
            return True
        return any(marker in lowered for marker in SYSTEM_MARKERS)

    @property
    def is_probe(self) -> bool:
        return self.file is not None and "__dynenh_probe_main" in self.file


@dataclass
class LeakBlock:
    kind: str
    bytes: int
    records: int
    frames: list[Frame] = field(default_factory=list)
    deciding_frame: Frame | None = None
    attributed: bool = False

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "bytes": self.bytes,
            "records": self.records,
            "attributed": self.attributed,
            "deciding_frame": None
            if self.deciding_frame is None
            else {
                "function": self.deciding_frame.function,
                "file": self.deciding_frame.file,
                "line": self.deciding_frame.line,
            },
            "allocation_site": None
            if not self.frames
            else {
                "function": self.frames[0].function,
                "file": self.frames[0].file,
                "line": self.frames[0].line,
            },
        }


def _parse_frame(line: str) -> Frame | None:
    match = FRAME.match(line)
    if not match:
        return None
    index = int(match.group(1))
    rest = match.group(2).strip()
    location = LOCATION.search(rest)
    if location:
        function = rest[: location.start()].strip()
        return Frame(
            index=index,
            function=function,
            file=location.group(1),
            line=int(location.group(2)),
            raw=line.strip(),
        )
    return Frame(index=index, function=rest, file=None, line=None, raw=line.strip())


def parse_leaks(stderr: str) -> list[LeakBlock]:
    blocks: list[LeakBlock] = []
    current: LeakBlock | None = None
    for line in stderr.splitlines():
        match = BLOCK_START.match(line.strip())
        if match:
            current = LeakBlock(
                kind=match.group(1),
                bytes=int(match.group(2)),
                records=int(match.group(3)),
            )
            blocks.append(current)
            continue
        if current is None:
            continue
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            frame = _parse_frame(line)
            if frame is not None:
                current.frames.append(frame)
            continue
        # Any other non-frame line ends the current block (SUMMARY, ==pid==, ...).
        if not line.startswith(" "):
            current = None
    return blocks


def owned_names(unit: Unit) -> set[str]:
    names = set(unit.source_names)
    for parent in {path.parent for path in unit.sources}:
        for header in parent.glob(unit.group_id + "*.h"):
            names.add(header.name)
    return names


def attribute_blocks(blocks: list[LeakBlock], unit: Unit) -> None:
    owned = owned_names(unit)
    owned_paths = {os.path.normpath(path) for path in unit.source_paths}
    for block in blocks:
        deciding = None
        for frame in block.frames:
            if frame.is_system or frame.is_probe:
                continue
            deciding = frame
            break
        block.deciding_frame = deciding
        if deciding is None or deciding.file is None:
            block.attributed = False
            continue
        normalized = os.path.normpath(deciding.file)
        block.attributed = normalized in owned_paths or Path(normalized).name in owned
    return


def parse_injection(stderr: str) -> dict:
    calls = len(re.findall(r"^\[dynenh\] realloc #", stderr, flags=re.M))
    injected = re.search(r"^\[dynenh\] injected NULL at call (\d+)$", stderr, flags=re.M)
    null_calls = len(re.findall(r"^\[dynenh\] realloc ptr=NULL$", stderr, flags=re.M))
    nonnull_calls = len(re.findall(r"^\[dynenh\] realloc ptr=nonnull$", stderr, flags=re.M))
    return {
        "realloc_calls": calls,
        "realloc_null_calls": null_calls,
        "realloc_nonnull_calls": nonnull_calls,
        "injected": bool(injected),
        "injected_at_call": int(injected.group(1)) if injected else None,
    }


def summarize_run(stderr: str, unit: Unit) -> dict:
    blocks = parse_leaks(stderr)
    attribute_blocks(blocks, unit)
    attributed = [block for block in blocks if block.attributed]
    errors = ASAN_ERROR.findall(stderr)
    deadly = bool(DEADLY.search(stderr))
    summary = LSAN_SUMMARY.search(stderr)
    injection = parse_injection(stderr)
    if deadly and "SEGV" not in errors:
        errors.append("SEGV")
    return {
        "leak_raw": bool(blocks),
        "leak_attributed": bool(attributed),
        "leak_blocks": [block.as_dict() for block in blocks],
        "attributed_blocks": [block.as_dict() for block in attributed],
        "attributed_bytes": sum(block.bytes for block in attributed),
        "raw_bytes": sum(block.bytes for block in blocks),
        "leak_kinds": sorted({block.kind for block in attributed}),
        "leak_summary": summary.group(0) if summary else None,
        "leak_summary_bytes": int(summary.group(1)) if summary else None,
        "leak_summary_records": int(summary.group(2)) if summary else None,
        "asan_errors": errors,
        "deadly_signal": deadly,
        "injection": injection,
    }


def classify(summary: dict, timed_out: bool, returncode: int | None) -> str:
    if timed_out:
        return "timeout"
    if summary["asan_errors"]:
        return "asan_error:" + summary["asan_errors"][0]
    if summary["leak_raw"]:
        return "leak"
    if returncode is None:
        return "no_returncode"
    if returncode != 0:
        return f"exit_{returncode}"
    return "clean"
