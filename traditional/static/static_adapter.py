#!/usr/bin/env python3
"""CWE-401 static-analysis adapter (Clang Static Analyzer and Cppcheck).

The adapter consumes a manifest of labelled C/C++ units, runs one or more
static analysers, normalises every diagnostic to a tool-independent record,
and writes:

  * ``predictions.jsonl`` -- one row per (sample, tool), including the raw
    diagnostic text, runtime, status, errors and the input label;
  * ``metrics.json``      -- confusion matrices and detection/timing metrics;
  * ``metrics.md``        -- a compact human-readable summary;
  * ``manifest.json``     -- input/output hashes, tool versions and commands;
  * ``raw/``              -- verbatim stdout/stderr for every tool invocation.

Only the Python standard library is used.  The script never modifies the
input files; when a sample carries inline code or a preamble, the analysed
translation unit is materialised under ``<out>/work/``.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

SCHEMA_VERSION = "static-cwe401-v1"
METRICS_SCHEMA_VERSION = "static-cwe401-metrics-v1"
TARGET_CWE = "CWE-401"

# Clang Static Analyzer diagnostics that indicate a memory leak.  unix.Malloc
# also reports double free / use after free, so the message must be checked.
CLANG_LEAK_CHECKERS = {
    "unix.Malloc": re.compile(r"potential leak of memory", re.I),
    "cplusplus.NewDeleteLeaks": re.compile(r"leak of memory", re.I),
    "alpha.unix.MallocWithAnnotations": re.compile(r"leak", re.I),
}

# Cppcheck ids that are memory leaks (CWE-401).  Cppcheck usually also emits a
# cwe="401" attribute; the id list is the fallback and cross-check.
CPPCHECK_LEAK_IDS = {
    "memleak",
    "memleakOnRealloc",
}

DIAG_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): "
    r"(?P<sev>warning|error|note|remark|fatal error): "
    r"(?P<msg>.*?)(?: \[(?P<checker>[^\]]+)\])?$"
)
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.I)

LABEL_TRUE = {"true", "1", "vulnerable", "vuln", "bad", "yes", "positive"}
LABEL_FALSE = {
    "false",
    "0",
    "non_vulnerable",
    "non-vulnerable",
    "nonvulnerable",
    "good",
    "clean",
    "no",
    "negative",
}


class AdapterError(RuntimeError):
    """Configuration or input error; reported with exit code 2."""


@dataclass
class Sample:
    index: int
    sample_id: str
    path: Path | None
    paths: list[Path]
    code: str | None
    language: str
    label: bool | None
    cwes: list[str]
    split: str | None
    project: str | None
    function: str | None
    preamble: str | None
    line_start: int | None
    line_end: int | None
    pair_id: str | None
    defines: list[str] = field(default_factory=list)
    include_dirs: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "source_path": str(self.path) if self.path else None,
            "source_paths": [str(path) for path in self.paths],
            "language": self.language,
            "label": self.label,
            "cwe": self.cwes,
            "split": self.split,
            "project": self.project,
            "function": self.function,
            "pair_id": self.pair_id,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "inline_code": self.code is not None,
            "preamble": self.preamble is not None,
            "defines": self.defines,
            "include_dirs": self.include_dirs,
        }


@dataclass
class PreparedSource:
    path: Path
    origin_path: Path | None
    origin_paths: list[Path]
    analyzed_sha256: str
    origin_sha256: str | None
    generated: bool
    combined: bool = False


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def slugify(value: str, limit: int = 60) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return (slug or "sample")[:limit]


def normalize_cwes(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int)):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return []
    found: set[int] = set()
    for item in items:
        text = str(item)
        parts = re.split(r"[,;\s]+", text) if isinstance(item, str) else [text]
        for part in parts:
            for match in CWE_RE.finditer(part):
                found.add(int(match.group(1)))
            if part.isdigit():
                found.add(int(part))
    return [f"CWE-{number}" for number in sorted(found)]


def normalize_label(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in LABEL_TRUE:
            return True
        if lowered in LABEL_FALSE:
            return False
    return None


def normalize_language(value: Any, path: Path | None) -> str:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"c", "c11", "c99", "c17"}:
            return "c"
        if lowered in {"c++", "cpp", "cxx", "c++17", "cplusplus"}:
            return "cpp"
    if path is not None:
        suffix = path.suffix.lower()
        if suffix in {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"}:
            return "cpp"
    return "c"


def infer_extension(language: str, path: Path | None) -> str:
    if path is not None and path.suffix:
        return path.suffix.lstrip(".")
    return "cpp" if language == "cpp" else "c"


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first_present(record: dict[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
    return None


def flatten_input(data: Any, base_dir: Path) -> list[dict[str, Any]]:
    """Return a flat list of raw sample records from the supported schemas."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        raise AdapterError("input JSON must be an object, a list, or JSONL")

    for key in ("samples", "units", "records", "testcases", "functions"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    pairs = data.get("pairs")
    if isinstance(pairs, list):
        flat: list[dict[str, Any]] = []
        for pair in pairs:
            if not isinstance(pair, dict):
                continue
            pair_id = pair.get("pair_id", pair.get("id"))
            for slot in ("vulnerable", "fixed"):
                member = pair.get(slot)
                if not isinstance(member, dict):
                    continue
                item = dict(member)
                item.setdefault("pair_id", pair_id)
                item.setdefault("pair_slot", slot)
                flat.append(item)
        return flat
    raise AdapterError(
        "input JSON has no supported sample list "
        "(samples/units/records/testcases/functions/pairs)"
    )


def load_raw_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        records = []
        with path.open("r", encoding="utf-8-sig") as fh:
            for line_number, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AdapterError(
                        f"{path}:{line_number}: invalid JSON: {exc}"
                    ) from exc
                if not isinstance(item, dict):
                    raise AdapterError(f"{path}:{line_number}: expected an object")
                records.append(item)
        return records
    if suffix == ".json":
        with path.open("r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return flatten_input(data, path.parent)
    raise AdapterError(f"unsupported input extension: {path.suffix!r}")


def resolve_input_path(candidate: str | Path, base_dir: Path) -> Path:
    """Resolve a manifest path against the manifest dir, then the cwd.

    Juliet manifests store project-relative paths such as
    ``juliet/raw/testcases/...`` while living inside ``juliet/``; a plain
    manifest-relative join would duplicate the prefix.  Prefer the first
    existing candidate, otherwise keep the manifest-relative path so the
    later "file not found" error is explicit.
    """
    path = Path(candidate).expanduser()
    if path.is_absolute():
        return path.resolve()
    primary = (base_dir / path).resolve()
    if primary.exists():
        return primary
    secondary = (Path.cwd() / path).resolve()
    if secondary.exists():
        return secondary
    return primary


def build_samples(records: Iterable[dict[str, Any]], base_dir: Path) -> list[Sample]:
    samples: list[Sample] = []
    seen_ids: Counter[str] = Counter()
    for index, record in enumerate(records, 1):
        raw_path = first_present(record, ("path", "file", "source_path"))
        paths: list[Path] = []
        if isinstance(raw_path, str) and raw_path.strip():
            paths.append(resolve_input_path(raw_path, base_dir))
        elif raw_path is not None:
            raise AdapterError(f"sample {index}: path must be a string")

        raw_sources = first_present(
            record, ("sources", "source_files", "files", "paths", "filenames")
        )
        if isinstance(raw_sources, list):
            for item in raw_sources:
                if isinstance(item, dict):
                    item = item.get("path") or item.get("file")
                if not isinstance(item, str) or not item.strip():
                    raise AdapterError(
                        f"sample {index}: sources must contain paths or {{'path': ...}} objects"
                    )
                paths.append(resolve_input_path(item, base_dir))
        elif isinstance(raw_sources, str) and raw_sources.strip():
            paths.append(resolve_input_path(raw_sources, base_dir))
        elif raw_sources is not None:
            raise AdapterError(f"sample {index}: sources must be a list of paths")

        deduped: list[Path] = []
        seen_paths: set[str] = set()
        for candidate in paths:
            resolved = candidate.resolve()
            if str(resolved) not in seen_paths:
                seen_paths.add(str(resolved))
                deduped.append(resolved)
        paths = deduped
        path: Path | None = paths[0] if paths else None

        code_value = first_present(record, ("code", "source", "func_body", "body"))
        code = code_value if isinstance(code_value, str) else None
        if not paths and code is None:
            raise AdapterError(f"sample {index}: needs a path or inline code")

        label = normalize_label(
            first_present(record, ("label", "is_vulnerable", "vulnerable", "target"))
        )
        if label is None and isinstance(record.get("pair_slot"), str):
            slot = record["pair_slot"].lower()
            if slot in {"vulnerable", "fixed"}:
                label = slot == "vulnerable"

        cwes = normalize_cwes(
            first_present(record, ("cwe", "cwe_id", "cwe_list", "cwes"))
        )
        path_for_language = path
        if path_for_language is None:
            filepath = first_present(record, ("filepath", "filename"))
            if isinstance(filepath, str):
                path_for_language = Path(filepath)
        language = normalize_language(
            first_present(record, ("language", "lang")), path_for_language
        )

        sample_id_value = first_present(
            record, ("sample_id", "unit_id", "id", "idx", "pair_id")
        )
        if sample_id_value is None:
            sample_id = f"sample-{index:05d}"
        else:
            sample_id = str(sample_id_value)
            if record.get("pair_slot"):
                sample_id = f"{sample_id}:{record['pair_slot']}"
        seen_ids[sample_id] += 1
        if seen_ids[sample_id] > 1:
            sample_id = f"{sample_id}#{seen_ids[sample_id]}"

        line_start = as_int(
            first_present(record, ("line_start", "start_line", "begin_line"))
        )
        line_end = as_int(
            first_present(record, ("line_end", "end_line", "stop_line"))
        )
        location = record.get("location")
        if isinstance(location, dict):
            line_start = line_start if line_start is not None else as_int(
                location.get("start_line") or location.get("line_start")
            )
            line_end = line_end if line_end is not None else as_int(
                location.get("end_line") or location.get("line_end")
            )

        preamble_value = record.get("preamble")
        preamble = preamble_value if isinstance(preamble_value, str) else None

        defines_value = first_present(
            record, ("defines", "definitions", "macro_defines")
        )
        defines: list[str] = []
        if isinstance(defines_value, list):
            for item in defines_value:
                text = str(item).strip()
                if text.startswith("-D"):
                    text = text[2:]
                if text:
                    defines.append(text)
        elif isinstance(defines_value, str) and defines_value.strip():
            defines.append(defines_value.strip().removeprefix("-D"))

        include_value = first_present(
            record, ("include_dirs", "include_paths", "includes")
        )
        per_sample_includes: list[str] = []
        include_items = include_value if isinstance(include_value, list) else []
        if isinstance(include_value, str):
            include_items = [include_value]
        for item in include_items:
            if isinstance(item, dict):
                item = item.get("path")
            if isinstance(item, str) and item.strip():
                per_sample_includes.append(
                    str(resolve_input_path(item, base_dir))
                )

        split_value = first_present(record, ("split", "subset"))
        project_value = first_present(record, ("project", "project_name"))
        function_value = first_present(record, ("function", "func_name", "name"))
        pair_value = first_present(record, ("pair_id",))

        samples.append(
            Sample(
                index=index,
                sample_id=sample_id,
                path=path,
                paths=paths,
                code=code,
                language=language,
                label=label,
                cwes=cwes,
                split=str(split_value) if split_value is not None else None,
                project=str(project_value) if project_value is not None else None,
                function=str(function_value) if function_value is not None else None,
                preamble=preamble,
                line_start=line_start,
                line_end=line_end,
                pair_id=str(pair_value) if pair_value is not None else None,
                defines=defines,
                include_dirs=per_sample_includes,
                extra={
                    key: record[key]
                    for key in ("pair_slot", "origin", "dataset")
                    if key in record
                },
            )
        )
    return samples


def filter_samples(
    samples: Sequence[Sample],
    filter_cwe: str | None,
    only_label: str | None,
    limit: int | None,
) -> tuple[list[Sample], dict[str, int]]:
    counts = Counter()
    selected: list[Sample] = []
    target = normalize_cwes(filter_cwe)[0] if filter_cwe else None
    if filter_cwe and target is None:
        raise AdapterError(f"invalid --filter-cwe value: {filter_cwe!r}")
    for sample in samples:
        if target is not None:
            if not sample.cwes:
                counts["filtered_out_missing_cwe"] += 1
                continue
            if target not in sample.cwes:
                counts["filtered_out_other_cwe"] += 1
                continue
        if only_label == "vulnerable" and sample.label is not True:
            counts["filtered_out_label"] += 1
            continue
        if only_label == "non_vulnerable" and sample.label is not False:
            counts["filtered_out_label"] += 1
            continue
        selected.append(sample)
        if limit is not None and len(selected) >= limit:
            break
    counts["selected"] = len(selected)
    counts["input_records"] = len(samples)
    return selected, dict(counts)


def prepare_source(sample: Sample, work_dir: Path) -> PreparedSource:
    if sample.code is not None:
        text = sample.code
        if sample.preamble:
            text = sample.preamble.rstrip("\n") + "\n" + text
        if not text.endswith("\n"):
            text += "\n"
        ext = infer_extension(sample.language, sample.path)
        target = work_dir / f"{sample.index:05d}_{slugify(sample.sample_id)}.{ext}"
        target.write_text(text, encoding="utf-8", newline="\n")
        origin_sha = (
            sha256_file(sample.paths[0])
            if sample.paths and sample.paths[0].exists()
            else None
        )
        return PreparedSource(
            path=target,
            origin_path=sample.paths[0] if sample.paths else None,
            origin_paths=list(sample.paths),
            analyzed_sha256=sha256_text(text),
            origin_sha256=origin_sha,
            generated=True,
        )

    if not sample.paths:
        raise AdapterError(f"sample {sample.sample_id}: no source path")
    for path in sample.paths:
        if not path.exists():
            raise AdapterError(f"sample {sample.sample_id}: file not found: {path}")

    ext = infer_extension(sample.language, sample.path)
    target = work_dir / f"{sample.index:05d}_{slugify(sample.sample_id)}.{ext}"

    if len(sample.paths) > 1:
        include_lines = "\n".join(
            '#include "' + str(path).replace('"', '\\"') + '"'
            for path in sample.paths
        )
        text = ""
        if sample.preamble:
            text += sample.preamble.rstrip("\n") + "\n"
        text += include_lines + "\n"
        target.write_text(text, encoding="utf-8", newline="\n")
        joined = "\n".join(f"{path}:{sha256_file(path)}" for path in sample.paths)
        return PreparedSource(
            path=target,
            origin_path=None,
            origin_paths=list(sample.paths),
            analyzed_sha256=sha256_text(text),
            origin_sha256=sha256_text(joined),
            generated=True,
            combined=True,
        )

    source = sample.paths[0]
    origin_sha = sha256_file(source)
    if sample.preamble:
        text = sample.preamble.rstrip("\n") + "\n"
        text += source.read_text(encoding="utf-8", errors="replace")
        if not text.endswith("\n"):
            text += "\n"
        target.write_text(text, encoding="utf-8", newline="\n")
        return PreparedSource(
            path=target,
            origin_path=source,
            origin_paths=[source],
            analyzed_sha256=sha256_text(text),
            origin_sha256=origin_sha,
            generated=True,
        )
    return PreparedSource(
        path=source,
        origin_path=source,
        origin_paths=[source],
        analyzed_sha256=origin_sha,
        origin_sha256=origin_sha,
        generated=False,
    )


def include_dirs_for(sample: Sample, prepared: PreparedSource, extra: Sequence[str]) -> list[str]:
    dirs: list[str] = []
    for item in extra:
        dirs.append(str(Path(item).expanduser().resolve()))
    dirs.extend(sample.include_dirs)
    for origin in prepared.origin_paths:
        dirs.append(str(origin.parent))
    if prepared.origin_path is not None:
        dirs.append(str(prepared.origin_path.parent))
    if not dirs and sample.path is not None:
        dirs.append(str(sample.path.parent))
    seen: set[str] = set()
    unique = []
    for item in dirs:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def write_raw(out_dir: Path, stem: str, tool: str, stdout: str, stderr: str, command: Sequence[str]) -> dict[str, Any]:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {}
    for stream, text in (("stdout", stdout), ("stderr", stderr)):
        name = f"{stem}.{tool}.{stream}.txt"
        path = raw_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        result[stream] = {
            "path": str(path.relative_to(out_dir)),
            "sha256": sha256_text(text),
            "bytes": len(text.encode("utf-8")),
        }
    cmd_name = f"{stem}.{tool}.cmd.txt"
    cmd_text = shlex.join(command) + "\n"
    (raw_dir / cmd_name).write_text(cmd_text, encoding="utf-8", newline="\n")
    result["command"] = {
        "path": str((raw_dir / cmd_name).relative_to(out_dir)),
        "sha256": sha256_text(cmd_text),
    }
    return result


def clang_diagnostics(stdout: str, stderr: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse text-mode Clang Static Analyzer output into warning groups."""
    diagnostics: list[dict[str, Any]] = []
    errors: list[str] = []
    current: dict[str, Any] | None = None
    for line in (stdout + "\n" + stderr).splitlines():
        match = DIAG_RE.match(line)
        if not match:
            continue
        severity = match.group("sev")
        message = match.group("msg").strip()
        if severity in {"error", "fatal error"}:
            errors.append(line)
            continue
        if severity != "warning":
            if severity == "note" and current is not None:
                current["trace"].append(
                    {
                        "file": match.group("file"),
                        "line": int(match.group("line")),
                        "column": int(match.group("col")),
                        "message": message,
                    }
                )
            continue
        checker = match.group("checker") or ""
        current = {
            "tool": "clang",
            "checker": checker,
            "severity": severity,
            "message": message,
            "file": match.group("file"),
            "line": int(match.group("line")),
            "column": int(match.group("col")),
            "trace": [],
        }
        diagnostics.append(current)
    return diagnostics, errors


def cppcheck_diagnostics(report_path: Path, stderr: str) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    diagnostics: list[dict[str, Any]] = []
    errors: list[str] = []
    syntax_errors: list[str] = []
    if not report_path.exists():
        return diagnostics, errors, syntax_errors
    try:
        root = ET.parse(report_path).getroot()
    except ET.ParseError as exc:
        errors.append(f"cannot parse cppcheck XML: {exc}")
        return diagnostics, errors, syntax_errors
    for element in root.findall(".//error"):
        attrs = dict(element.attrib)
        error_id = attrs.get("id", "")
        severity = attrs.get("severity", "")
        message = attrs.get("msg", "") or attrs.get("verbose", "")
        if error_id in {"syntaxError", "cppcheckError", "internalError"}:
            syntax_errors.append(f"{error_id}: {message}")
        locations = [dict(loc.attrib) for loc in element.findall("location")]
        primary = locations[0] if locations else {}
        cwe_ids = normalize_cwes(attrs.get("cwe"))
        for location in locations:
            cwe_ids.extend(normalize_cwes(location.get("cwe")))
        cwe_ids = sorted(set(cwe_ids), key=lambda item: int(item.split("-")[1]))
        diagnostics.append(
            {
                "tool": "cppcheck",
                "checker": error_id,
                "severity": severity,
                "message": message,
                "file": primary.get("file") or attrs.get("file0") or "",
                "line": as_int(primary.get("line")),
                "column": as_int(primary.get("column")),
                "cwe": cwe_ids,
                "trace": [
                    {
                        "file": loc.get("file", ""),
                        "line": as_int(loc.get("line")),
                        "column": as_int(loc.get("column")),
                        "info": loc.get("info", ""),
                    }
                    for loc in locations[1:]
                ],
            }
        )
    return diagnostics, errors, syntax_errors


def cwe_for_diagnostic(tool: str, diagnostic: dict[str, Any]) -> tuple[bool, list[str]]:
    checker = diagnostic.get("checker", "")
    message = diagnostic.get("message", "")
    if tool == "clang":
        pattern = CLANG_LEAK_CHECKERS.get(checker)
        if pattern is not None and pattern.search(message):
            return True, [TARGET_CWE]
        return False, []
    if tool == "cppcheck":
        declared = diagnostic.get("cwe") or []
        by_id = checker in CPPCHECK_LEAK_IDS
        by_cwe = TARGET_CWE in declared
        if by_id or by_cwe:
            return True, declared or [TARGET_CWE]
        return False, declared
    return False, []


def normalize_diag_path(value: str, cwd: Path) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        path = cwd / path
    return str(path.resolve())


def run_clang(
    source: Path,
    language: str,
    include_dirs: Sequence[str],
    defines: Sequence[str],
    std_c: str,
    std_cxx: str,
    timeout: float,
    clang_bin: str,
    extra_args: Sequence[str],
    analyze_headers: bool = False,
) -> dict[str, Any]:
    command = [
        clang_bin,
        "--analyze",
        "-fno-color-diagnostics",
        "-Xanalyzer",
        "-analyzer-output=text",
    ]
    if analyze_headers:
        command.extend(["-Xclang", "-analyzer-opt-analyze-headers"])
    command.extend(
        [
            "-x",
            "c++" if language == "cpp" else "c",
            f"-std={std_cxx if language == 'cpp' else std_c}",
        ]
    )
    for directory in include_dirs:
        command.extend(["-I", directory])
    for define in defines:
        command.append(f"-D{define}")
    command.extend(extra_args)
    command.append(str(source))

    started = utc_now()
    start = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=str(source.parent),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        exit_code = None
    duration = time.perf_counter() - start
    ended = utc_now()

    diagnostics, errors = clang_diagnostics(stdout, stderr)
    if timed_out:
        status = "timeout"
    elif exit_code != 0 and (errors or "error:" in stderr or "error:" in stdout):
        status = "compile_error"
    elif exit_code not in (0, None):
        status = "tool_error"
        errors.append(f"clang exited with code {exit_code}")
    else:
        status = "ok"
    return {
        "tool": "clang",
        "command": command,
        "cwd": str(source.parent),
        "started_at": started,
        "ended_at": ended,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "status": status,
        "stdout": stdout,
        "stderr": stderr,
        "diagnostics": diagnostics,
        "errors": errors,
    }


def run_cppcheck(
    source: Path,
    language: str,
    include_dirs: Sequence[str],
    defines: Sequence[str],
    std_c: str,
    std_cxx: str,
    timeout: float,
    cppcheck_bin: str,
    extra_args: Sequence[str],
    force: bool,
    report_path: Path,
) -> dict[str, Any]:
    command = [
        cppcheck_bin,
        "--enable=warning,performance,portability",
        "--inconclusive",
        "--quiet",
        "--xml",
        "--xml-version=2",
        f"--output-file={report_path}",
        f"--language={'c++' if language == 'cpp' else 'c'}",
        f"--std={std_cxx if language == 'cpp' else std_c}",
        "--template={file}:{line}:{column}:{severity}:{id}:{message}",
    ]
    if force:
        command.append("--force")
    for directory in include_dirs:
        command.append(f"-I{directory}")
    for define in defines:
        command.append(f"-D{define}")
    command.extend(extra_args)
    command.append(str(source))

    started = utc_now()
    start = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=str(source.parent),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        exit_code = None
    duration = time.perf_counter() - start
    ended = utc_now()

    diagnostics, errors, syntax_errors = cppcheck_diagnostics(report_path, stderr)
    if timed_out:
        status = "timeout"
    elif syntax_errors:
        status = "compile_error"
        errors.extend(syntax_errors)
    elif exit_code not in (0, None) and not diagnostics:
        status = "tool_error"
        errors.append(f"cppcheck exited with code {exit_code}")
    elif not report_path.exists():
        status = "tool_error"
        errors.append("cppcheck produced no XML report")
    else:
        status = "ok"
    return {
        "tool": "cppcheck",
        "command": command,
        "cwd": str(source.parent),
        "started_at": started,
        "ended_at": ended,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "status": status,
        "stdout": stdout,
        "stderr": stderr,
        "diagnostics": diagnostics,
        "errors": errors,
    }


def attribute_diagnostics(
    sample: Sample,
    prepared: PreparedSource,
    run: dict[str, Any],
    include_external: bool,
) -> list[dict[str, Any]]:
    cwd = Path(run["cwd"])
    target_paths = {str(prepared.path.resolve())}
    target_paths.update(str(path.resolve()) for path in prepared.origin_paths)
    attributed: list[dict[str, Any]] = []
    for diagnostic in run["diagnostics"]:
        normalized_path = normalize_diag_path(diagnostic.get("file", ""), cwd)
        in_target = normalized_path in target_paths
        line = diagnostic.get("line")
        in_region = True
        if sample.line_start is not None and line is not None:
            in_region = line >= sample.line_start
        if sample.line_end is not None and line is not None:
            in_region = in_region and line <= sample.line_end
        is_target_cwe, cwes = cwe_for_diagnostic(run["tool"], diagnostic)
        item = dict(diagnostic)
        item.update(
            {
                "file": normalized_path,
                "in_target_file": in_target,
                "in_target_region": in_region,
                "cwe": cwes,
                "is_cwe401": is_target_cwe,
                "counts_as_finding": bool(
                    is_target_cwe
                    and in_region
                    and (in_target or include_external)
                ),
            }
        )
        attributed.append(item)
    return attributed


def run_one_tool(
    tool: str,
    sample: Sample,
    prepared: PreparedSource,
    args: argparse.Namespace,
    out_dir: Path,
    stem: str,
    include_dirs: Sequence[str],
) -> dict[str, Any]:
    if tool == "clang":
        run = run_clang(
            source=prepared.path,
            language=sample.language,
            include_dirs=include_dirs,
            defines=list(args.define) + list(sample.defines),
            std_c=args.std_c,
            std_cxx=args.std_cxx,
            timeout=args.timeout,
            clang_bin=args.clang_bin,
            extra_args=args.clang_arg,
            analyze_headers=prepared.combined,
        )
    elif tool == "cppcheck":
        report_path = out_dir / "raw" / f"{stem}.cppcheck.xml"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        run = run_cppcheck(
            source=prepared.path,
            language=sample.language,
            include_dirs=include_dirs,
            defines=list(args.define) + list(sample.defines),
            std_c=args.std_c,
            std_cxx=args.std_cxx,
            timeout=args.timeout,
            cppcheck_bin=args.cppcheck_bin,
            extra_args=args.cppcheck_arg,
            force=args.cppcheck_force,
            report_path=report_path,
        )
        if report_path.exists():
            run["report"] = {
                "path": str(report_path.relative_to(out_dir)),
                "sha256": sha256_file(report_path),
                "bytes": report_path.stat().st_size,
            }
    else:
        raise AdapterError(f"unknown tool: {tool}")

    attributed = attribute_diagnostics(sample, prepared, run, args.include_external)
    findings = [d for d in attributed if d["counts_as_finding"]]
    run["raw"] = write_raw(
        out_dir, stem, tool, run.pop("stdout"), run.pop("stderr"), run["command"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "method": "clang-static-analyzer" if tool == "clang" else "cppcheck",
        "tool": tool,
        "sample_id": sample.sample_id,
        "sample": sample.public(),
        "source": {
            "analyzed_path": str(prepared.path),
            "origin_path": str(prepared.origin_path) if prepared.origin_path else None,
            "origin_paths": [str(path) for path in prepared.origin_paths],
            "analyzed_sha256": prepared.analyzed_sha256,
            "origin_sha256": prepared.origin_sha256,
            "generated": prepared.generated,
            "combined": prepared.combined,
        },
        "label": sample.label,
        "prediction": {
            "is_vulnerable": bool(findings),
            "cwe": TARGET_CWE if findings else None,
            "finding_count": len(findings),
        },
        "diagnostics": attributed,
        "diagnostic_counts": {
            "total": len(attributed),
            "cwe401": len(findings),
            "target_file": sum(1 for d in attributed if d["in_target_file"]),
        },
        "status": run["status"],
        "runtime": {
            "started_at": run["started_at"],
            "ended_at": run["ended_at"],
            "duration_seconds": run["duration_seconds"],
            "exit_code": run["exit_code"],
            "timed_out": run["timed_out"],
        },
        "errors": run["errors"],
        "command": run["command"],
        "cwd": run["cwd"],
        "raw": run["raw"],
        "report": run.get("report"),
    }


def run_tool_on_samples(
    tool: str,
    samples: Sequence[Sample],
    prepared: Sequence[PreparedSource],
    args: argparse.Namespace,
    out_dir: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = [None] * len(samples)  # type: ignore[list-item]
    environment_errors: list[str] = []

    def work(position: int) -> tuple[int, dict[str, Any] | None, str | None]:
        sample = samples[position]
        stem = f"{sample.index:05d}_{slugify(sample.sample_id)}"
        include_dirs = include_dirs_for(sample, prepared[position], args.include_dir)
        try:
            row = run_one_tool(
                tool, sample, prepared[position], args, out_dir, stem, include_dirs
            )
            return position, row, None
        except AdapterError as exc:
            return position, None, str(exc)
        except Exception as exc:  # keep one bad sample from killing the run
            return position, None, f"{type(exc).__name__}: {exc}"

    if args.jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for position, row, error in pool.map(work, range(len(samples))):
                if row is not None:
                    rows[position] = row
                else:
                    environment_errors.append(f"{samples[position].sample_id}: {error}")
    else:
        for position in range(len(samples)):
            _, row, error = work(position)
            if row is not None:
                rows[position] = row
            else:
                environment_errors.append(f"{samples[position].sample_id}: {error}")
    return [row for row in rows if row is not None], environment_errors


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(tp: int, fp: int, fn: int) -> float | None:
    if tp + fn == 0:  # class absent from the labelled set
        return None
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn)
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def _mcc(tp: int, fp: int, fn: int, tn: int) -> float | None:
    numerator = tp * tn - fp * fn
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denominator == 0:
        return None
    return numerator / (denominator ** 0.5)


def wilson_interval(k: int, n: int, z: float = 1.959963984540054) -> dict[str, Any] | None:
    if n == 0:
        return None
    p = k / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    margin = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denominator
    return {
        "low": max(0.0, center - margin),
        "high": min(1.0, center + margin),
        "confidence": 0.95,
    }


def confusion_from_rows(rows: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unlabelled": 0}
    for row in rows:
        label = row.get("label")
        if label is None:
            counts["unlabelled"] += 1
            continue
        predicted = bool(row["prediction"]["is_vulnerable"])
        if label and predicted:
            counts["tp"] += 1
        elif label and not predicted:
            counts["fn"] += 1
        elif not label and predicted:
            counts["fp"] += 1
        else:
            counts["tn"] += 1
    return counts


def metrics_from_confusion(counts: dict[str, int]) -> dict[str, Any]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    n = tp + fp + tn + fn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    accuracy = _ratio(tp + tn, n)
    f1_vuln = _f1(tp, fp, fn)
    f1_nonvuln = _f1(tn, fn, fp)
    macro = None
    if f1_vuln is not None and f1_nonvuln is not None:
        macro = (f1_vuln + f1_nonvuln) / 2
    balanced = (
        (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None
    )
    return {
        "n": n,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1_vulnerable": f1_vuln,
        "f1_non_vulnerable": f1_nonvuln,
        "macro_f1": macro,
        "balanced_accuracy": balanced,
        "mcc": _mcc(tp, fp, fn, tn),
        "wilson_95": {
            "precision": wilson_interval(tp, tp + fp),
            "recall": wilson_interval(tp, tp + fn),
            "specificity": wilson_interval(tn, tn + fp),
            "accuracy": wilson_interval(tp + tn, n),
        },
    }


def timing_summary(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    durations = sorted(float(row["runtime"]["duration_seconds"]) for row in rows)
    if not durations:
        return {"n": 0}
    index = min(len(durations) - 1, max(0, int(round(0.95 * (len(durations) - 1)))))
    return {
        "n": len(durations),
        "total_seconds": sum(durations),
        "mean_seconds": statistics.fmean(durations),
        "median_seconds": statistics.median(durations),
        "p95_seconds": durations[index],
        "max_seconds": max(durations),
    }


def group_metrics(rows: Sequence[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        value = row.get("sample", {}).get(key)
        groups.setdefault(str(value), []).append(row)
    result = {}
    for value, subset in sorted(groups.items()):
        counts = confusion_from_rows(subset)
        result[value] = {
            "confusion": counts,
            "metrics": metrics_from_confusion(counts),
        }
    return result


def tool_metrics(tool: str, rows: Sequence[dict[str, Any]], info: dict[str, Any]) -> dict[str, Any]:
    labelled = [row for row in rows if row.get("label") is not None]
    evaluable = [row for row in labelled if row["status"] == "ok"]
    end_to_end_statuses = {"ok", "compile_error", "timeout"}
    end_to_end = [row for row in labelled if row["status"] in end_to_end_statuses]
    status_counts = Counter(row["status"] for row in rows)
    rule_counts = Counter(
        diagnostic.get("checker", "")
        for row in rows
        for diagnostic in row["diagnostics"]
    )
    target_rule_counts = Counter(
        diagnostic.get("checker", "")
        for row in rows
        for diagnostic in row["diagnostics"]
        if diagnostic.get("is_cwe401")
    )
    error_examples: list[str] = []
    for row in rows:
        for error in row.get("errors", []):
            if len(error_examples) < 10:
                error_examples.append(f"{row['sample_id']}: {error}")

    evaluable_counts = confusion_from_rows(evaluable)
    end_to_end_counts = confusion_from_rows(end_to_end)
    return {
        "tool": tool,
        "method": "clang-static-analyzer" if tool == "clang" else "cppcheck",
        "available": info.get("available", False),
        "version": info.get("version"),
        "binary": info.get("binary"),
        "runs": len(rows),
        "labelled": len(labelled),
        "evaluable": len(evaluable),
        "coverage_labelled": _ratio(len(evaluable), len(labelled)),
        "status_counts": dict(status_counts),
        "confusion_evaluable": evaluable_counts,
        "metrics_evaluable": metrics_from_confusion(evaluable_counts),
        "confusion_end_to_end": end_to_end_counts,
        "metrics_end_to_end": metrics_from_confusion(end_to_end_counts),
        "by_language": group_metrics(evaluable, "language"),
        "by_split": group_metrics(evaluable, "split"),
        "diagnostics": {
            "total": sum(len(row["diagnostics"]) for row in rows),
            "cwe401": sum(
                1
                for row in rows
                for diagnostic in row["diagnostics"]
                if diagnostic.get("is_cwe401")
            ),
            "samples_with_cwe401": sum(
                1 for row in rows if row["prediction"]["is_vulnerable"]
            ),
            "by_rule": dict(rule_counts.most_common()),
            "by_cwe401_rule": dict(target_rule_counts.most_common()),
        },
        "timing": timing_summary(rows),
        "error_examples": error_examples,
        "environment_errors": info.get("environment_errors", []),
    }


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def build_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# CWE-401 静态检测结果（自动生成）\n")
    lines.append(f"- 生成时间：`{summary['generated_at']}`")
    lines.append(f"- 数据集：`{summary['dataset']['path']}`")
    lines.append(
        f"- 样本：{summary['dataset']['n_selected']} / 输入 {summary['dataset']['n_input']}；"
        f"有标签 {summary['dataset']['n_labelled']}；"
        f"漏洞 {summary['dataset']['label_counts'].get('vulnerable', 0)}，"
        f"非漏洞 {summary['dataset']['label_counts'].get('non_vulnerable', 0)}"
    )
    lines.append(
        f"- 语言：{summary['dataset']['language_counts']}；"
        f"CWE-401 过滤：`{summary['settings'].get('filter_cwe')}`"
    )
    lines.append(f"- 运行墙钟时间：{fmt(summary['wall_seconds'], 2)} s\n")

    lines.append("## 工具可用性\n")
    lines.append("| 工具 | 可用 | 版本 | 二进制 |")
    lines.append("| --- | --- | --- | --- |")
    for tool, info in summary["tool_info"].items():
        lines.append(
            f"| {tool} | {info.get('available')} | {fmt(info.get('version'))} | "
            f"`{fmt(info.get('binary'))}` |"
        )
    lines.append("")

    for tool, metrics in summary["tools"].items():
        if not metrics.get("runs"):
            lines.append(f"## {tool}\n\n未运行：{metrics.get('environment_errors')}\n")
            continue
        lines.append(f"## {tool}\n")
        lines.append(
            f"状态：{metrics['status_counts']}；可评估 {metrics['evaluable']}/"
            f"{metrics['labelled']}（覆盖率 {fmt(metrics['coverage_labelled'])}）。\n"
        )
        lines.append("| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for view, key in (("可评估", "evaluable"), ("端到端", "end_to_end")):
            conf = metrics[f"confusion_{key}"]
            met = metrics[f"metrics_{key}"]
            lines.append(
                f"| {view} | {conf['tp']} | {conf['fp']} | {conf['tn']} | {conf['fn']} | "
                f"{fmt(met['precision'])} | {fmt(met['recall'])} | {fmt(met['specificity'])} | "
                f"{fmt(met['f1_vulnerable'])} | {fmt(met['macro_f1'])} | "
                f"{fmt(met['accuracy'])} | {fmt(met['mcc'])} |"
            )
        lines.append("")
        timing = metrics["timing"]
        lines.append(
            f"运行时间：总计 {fmt(timing.get('total_seconds'), 2)} s，"
            f"均值 {fmt(timing.get('mean_seconds'), 3)} s，"
            f"中位 {fmt(timing.get('median_seconds'), 3)} s，"
            f"P95 {fmt(timing.get('p95_seconds'), 3)} s，"
            f"最大 {fmt(timing.get('max_seconds'), 3)} s。\n"
        )
        lines.append(
            f"原始诊断：{metrics['diagnostics']['total']} 条，其中 CWE-401 "
            f"{metrics['diagnostics']['cwe401']} 条；"
            f"CWE-401 规则：{metrics['diagnostics']['by_cwe401_rule']}。\n"
        )
        if metrics["by_language"]:
            lines.append("| 语言 | N | TP | FP | TN | FN | Recall | Precision | F1(V) |")
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
            for language, item in metrics["by_language"].items():
                conf, met = item["confusion"], item["metrics"]
                lines.append(
                    f"| {language} | {met['n']} | {conf['tp']} | {conf['fp']} | "
                    f"{conf['tn']} | {conf['fn']} | {fmt(met['recall'])} | "
                    f"{fmt(met['precision'])} | {fmt(met['f1_vulnerable'])} |"
                )
            lines.append("")
        if metrics["error_examples"]:
            lines.append("错误样例：\n")
            for example in metrics["error_examples"]:
                lines.append(f"- `{example}`")
            lines.append("")

    lines.append("## 口径与限制\n")
    lines.append(
        "- 正类为“存在 CWE-401 内存泄漏诊断”，负类为“无 CWE-401 诊断”。"
    )
    lines.append(
        "- `可评估` 只含工具正常完成（status=ok）的样本；编译失败、超时和工具错误不计入。"
    )
    lines.append(
        "- `端到端` 把编译失败和超时按“未报泄漏”计入混淆矩阵，工具错误与不可用工具仍排除；"
        "该视图更接近部署成本，但会惩罚无法解析的输入。"
    )
    lines.append(
        "- Clang 仅把 `unix.Malloc`/`cplusplus.NewDeleteLeaks` 中含 leak 语义的诊断映射为 CWE-401；"
        "double free、use-after-free 等不计入。Cppcheck 使用 `memleak`/`memleakOnRealloc` 或 `cwe=401`。"
    )
    lines.append(
        "- 文件级标签会把文件中任意位置的泄漏算作命中；若清单提供 `line_start`/`line_end`，"
        "只统计目标区间。函数级基准应由数据清单给出精确区间或独立翻译单元。"
    )
    lines.append("")
    return "\n".join(lines)


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def tool_info(tool: str, binary: str) -> dict[str, Any]:
    resolved = shutil.which(binary)
    if resolved is None and Path(binary).expanduser().exists():
        resolved = str(Path(binary).expanduser().resolve())
    info: dict[str, Any] = {
        "available": bool(resolved and Path(resolved).exists()),
        "binary": resolved or binary,
        "version": None,
    }
    if not info["available"]:
        return info
    try:
        completed = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        info["version"] = output.strip().splitlines()[0] if output.strip() else None
    except Exception as exc:
        info["version"] = f"version probe failed: {type(exc).__name__}: {exc}"
    return info


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Clang Static Analyzer / Cppcheck for CWE-401 and emit unified JSONL + metrics."
    )
    parser.add_argument("--input", required=True, help="JSON/JSONL manifest of samples")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument(
        "--tool",
        action="append",
        choices=["clang", "cppcheck", "both"],
        default=None,
        help="tool to run; repeat or use 'both' (default: clang)",
    )
    parser.add_argument("--clang-bin", default=os.environ.get("CLANG_BIN", "clang"))
    parser.add_argument("--cppcheck-bin", default=os.environ.get("CPPCHECK_BIN", "cppcheck"))
    parser.add_argument("--include-dir", action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--clang-arg", action="append", default=[])
    parser.add_argument("--cppcheck-arg", action="append", default=[])
    parser.add_argument("--std-c", default="c11")
    parser.add_argument("--std-cxx", default="c++17")
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds per invocation")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--filter-cwe", default=None, help="keep samples whose CWE list contains this CWE")
    parser.add_argument(
        "--assume-cwe",
        default=None,
        help="assign this CWE to records that have no cwe field (e.g. CWE-401 for Juliet manifests)",
    )
    parser.add_argument(
        "--only-label",
        choices=["vulnerable", "non_vulnerable"],
        default=None,
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--include-external", action="store_true", help="count findings in included files")
    parser.add_argument("--cppcheck-force", action="store_true")
    parser.add_argument(
        "--allow-missing-tools",
        action="store_true",
        help="run the available tools instead of failing when one is missing",
    )
    parser.add_argument("--dataset-name", default=None)
    parser.add_argument("--dry-run", action="store_true", help="validate input and tool availability only")
    args = parser.parse_args(argv)
    if args.tool is None:
        args.tool = ["clang"]
    if "both" in args.tool:
        args.tool = ["clang", "cppcheck"]
    args.tool = list(dict.fromkeys(args.tool))
    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    start = time.perf_counter()
    input_path = Path(args.input).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    if not input_path.exists():
        raise AdapterError(f"input not found: {input_path}")
    if out_dir.exists() and not out_dir.is_dir():
        raise AdapterError(f"output path is not a directory: {out_dir}")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise AdapterError(
            f"output directory is not empty: {out_dir} (refusing to overwrite)"
        )

    raw_records = load_raw_records(input_path)
    samples = build_samples(raw_records, input_path.parent)
    if args.assume_cwe:
        assumed = normalize_cwes(args.assume_cwe)
        if not assumed:
            raise AdapterError(f"invalid --assume-cwe value: {args.assume_cwe!r}")
        for sample in samples:
            if not sample.cwes:
                sample.cwes = assumed
    samples, filter_counts = filter_samples(
        samples, args.filter_cwe, args.only_label, args.limit
    )
    if not samples:
        raise AdapterError("no samples selected after filtering")

    tool_infos = {tool: tool_info(tool, getattr(args, f"{tool}_bin")) for tool in args.tool}
    missing = [tool for tool, info in tool_infos.items() if not info["available"]]
    if missing and not args.allow_missing_tools:
        raise AdapterError(
            "requested tool(s) not found: "
            + ", ".join(f"{tool} ({getattr(args, f'{tool}_bin')})" for tool in missing)
            + "; install them, pass --{tool}-bin, or use --allow-missing-tools"
        )
    runnable = [tool for tool in args.tool if tool_infos[tool]["available"]]
    if not runnable:
        raise AdapterError("no requested tool is available")

    if args.dry_run:
        print(
            json.dumps(
                {
                    "input": str(input_path),
                    "n_selected": len(samples),
                    "tools": tool_infos,
                    "missing": missing,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    prepared: list[PreparedSource] = []
    for sample in samples:
        prepared.append(prepare_source(sample, work_dir))

    all_rows: dict[str, list[dict[str, Any]]] = {}
    environment_errors: dict[str, list[str]] = {}
    for tool in runnable:
        rows, errors = run_tool_on_samples(tool, samples, prepared, args, out_dir)
        all_rows[tool] = rows
        environment_errors[tool] = errors
        tool_infos[tool]["environment_errors"] = errors

    with (out_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for tool in runnable:
            for row in all_rows[tool]:
                fh.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")

    labels = Counter()
    for sample in samples:
        if sample.label is True:
            labels["vulnerable"] += 1
        elif sample.label is False:
            labels["non_vulnerable"] += 1
        else:
            labels["unlabelled"] += 1
    language_counts = Counter(sample.language for sample in samples)

    tools_metrics = {}
    for tool in args.tool:
        info = dict(tool_infos[tool])
        info["environment_errors"] = environment_errors.get(tool, [])
        tools_metrics[tool] = tool_metrics(tool, all_rows.get(tool, []), info)

    wall_seconds = time.perf_counter() - start
    summary = {
        "schema_version": METRICS_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "started_at": started_at,
        "wall_seconds": wall_seconds,
        "dataset": {
            "path": str(input_path),
            "sha256": sha256_file(input_path),
            "bytes": input_path.stat().st_size,
            "name": args.dataset_name,
            "n_input": filter_counts["input_records"],
            "n_selected": len(samples),
            "n_labelled": sum(1 for sample in samples if sample.label is not None),
            "label_counts": dict(labels),
            "language_counts": dict(language_counts),
            "filter_counts": filter_counts,
            "filter_cwe": args.filter_cwe,
        },
        "settings": {
            "tools": runnable,
            "missing_tools": missing,
            "std_c": args.std_c,
            "std_cxx": args.std_cxx,
            "timeout_seconds": args.timeout,
            "jobs": args.jobs,
            "include_dirs": args.include_dir,
            "defines": args.define,
            "clang_args": args.clang_arg,
            "cppcheck_args": args.cppcheck_arg,
            "cppcheck_force": args.cppcheck_force,
            "include_external": args.include_external,
            "filter_cwe": args.filter_cwe,
            "assume_cwe": args.assume_cwe,
            "only_label": args.only_label,
            "limit": args.limit,
        },
        "tool_info": tool_infos,
        "tools": tools_metrics,
        "target_cwe": TARGET_CWE,
        "rule_mapping": {
            "clang": {
                "checkers": sorted(CLANG_LEAK_CHECKERS),
                "message_rule": "checker-specific leak phrase (leak of memory)",
            },
            "cppcheck": {"ids": sorted(CPPCHECK_LEAK_IDS), "cwe_attribute": "401"},
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "hostname": socket.gethostname(),
        },
        "limitations": [
            "Static analysis needs a parsable translation unit; isolated function snippets often fail to compile.",
            "A file-level label attributes any leak in the file to the sample; use line ranges or per-function units for function-level claims.",
            "Clang text diagnostics are parsed from stdout/stderr; raw output is retained for audit.",
            "Only CWE-401 leak diagnostics are mapped; other memory errors are recorded but not counted.",
        ],
        "errors": {
            "per_tool": environment_errors,
        },
    }
    write_json(out_dir / "metrics.json", summary)
    (out_dir / "metrics.md").write_text(
        build_markdown(summary), encoding="utf-8", newline="\n"
    )

    outputs = {}
    for name in ("predictions.jsonl", "metrics.json", "metrics.md"):
        path = out_dir / name
        outputs[name] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "command": shlex.join([sys.executable, str(Path(__file__).resolve())] + list(argv or sys.argv[1:])),
        "adapter": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "input": {
            "path": str(input_path),
            "sha256": sha256_file(input_path),
            "bytes": input_path.stat().st_size,
        },
        "outputs": outputs,
        "tools": tool_infos,
        "settings": summary["settings"],
    }
    write_json(out_dir / "manifest.json", manifest)

    print(
        json.dumps(
            {
                "out": str(out_dir),
                "samples": len(samples),
                "tools": runnable,
                "wall_seconds": round(wall_seconds, 3),
                "predictions": str(out_dir / "predictions.jsonl"),
                "metrics": str(out_dir / "metrics.json"),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
