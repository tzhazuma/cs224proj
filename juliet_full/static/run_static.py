#!/usr/bin/env python3
"""Run a static CWE-401 detector on juliet_full units and write contract predictions.

Contract: juliet_full/README.md sections 3 (units) and 4 (predictions).  Tools:
clang_sa, cppcheck, codeql, infer (per unit, or batched for codeql/infer) and the lexical
baseline grep_v0.  The CWE-401 verdict mapping (which checkers count as leak evidence) is
fixed in the *_LEAK_* constants below and documented in static/README.md; it was chosen on
dev units only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

STATIC_DIR = Path(__file__).resolve().parent
JULIET_FULL = STATIC_DIR.parent
PROJECT_ROOT = JULIET_FULL.parent
TOOLS_ROOT = Path("/home/barton/tools/cs224")

DEFAULT_BINS = {
    "clang": TOOLS_ROOT / "llvm-23.1.6" / "bin" / "clang",
    "cppcheck": TOOLS_ROOT / "cppcheck-2.22.0" / "bin" / "cppcheck",
    "codeql": TOOLS_ROOT / "codeql-2.27.5" / "codeql" / "codeql",
    "infer": TOOLS_ROOT / "infer-1.3.0" / "bin" / "infer",
}
TOOLS = ("clang_sa", "cppcheck", "codeql", "infer", "grep_v0")
UNIT_TIMEOUT_S = 60.0

# Added to every compile-like invocation, as in the old Tier-B baseline
# (traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu): Juliet assumes a GNU
# build and ALLOCA needs a declaration of alloca().  Cppcheck only receives the define.
COMPAT_DEFINES = ["_GNU_SOURCE"]
COMPAT_COMPILER_ARGS = ["-include", "alloca.h"]

# ---------------------------------------------------------------------------
# CWE-401 verdict mapping.  A unit is predicted leaky iff at least one finding located in
# the unit's own files (under program_dir) matches.  Chosen on dev units (README.md §3).
# ---------------------------------------------------------------------------
CLANG_LEAK_RULES: dict[str, re.Pattern[str]] = {
    "unix.Malloc": re.compile(r"\bleak\b", re.I),
    "cplusplus.NewDeleteLeaks": re.compile(r"\bleak\b", re.I),
}
CPPCHECK_LEAK_IDS = {"memleak", "memleakOnRealloc", "leakReturnValNotUsed", "leakNoVarFunctionCall"}
CODEQL_QUERIES = {  # rule id -> query path inside the bundled codeql/cpp-queries pack
    "cpp/memory-never-freed": "Critical/MemoryNeverFreed.ql",
    "cpp/memory-may-not-be-freed": "Critical/MemoryMayNotBeFreed.ql",
    "cpp/memory-leak-on-failed-call-to-realloc": "experimental/Security/CWE/CWE-401/MemoryLeakOnFailedCallToRealloc.ql",
}
CODEQL_LEAK_RULES = set(CODEQL_QUERIES)
INFER_LEAK_TYPES = {"MEMORY_LEAK_C", "MEMORY_LEAK_CPP"}
# MEMORY_LEAK_CPP is off by default in Infer 1.3.  Infer's bundled clang would pick
# /usr/lib/gcc/x86_64-linux-gnu/14, which has no libstdc++ headers on dell.
INFER_ARGS = ["--pulse-only", "--enable-issue-type", "MEMORY_LEAK_CPP", "--jobs", "1", "--no-progress-bar",
              "--keep-going", "--Xclang", "--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13"]

# -analyzer-opt-analyze-headers: without it the path-sensitive engine only analyzes functions of the main
# file, so a wrapper TU (#include of every unit source) got syntax-only checks and every multi-file unit
# was predicted "no leak" (dev: recall 0/102 on flow 51-68 and 71-84).
CLANG_ANALYZER_ARGS = ["-Xanalyzer", "-analyzer-output=text", "-Xanalyzer", "-analyzer-opt-analyze-headers"]

DIAG_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): "
    r"(?P<sev>warning|error|note|remark|fatal error): "
    r"(?P<msg>.*?)(?: \[(?P<checker>[^\]]+)\])?$"
)
RAW_TEXT_CAP = 100_000
BUILD_FAILED_MARK = "UNIT_BUILD_FAILED"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(unit_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", unit_id)


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------
@dataclass
class Unit:
    record: dict[str, Any]
    unit_id: str
    group_id: str
    program_dir: Path
    language: str  # "c" or "cpp", from build.compiler
    std: str
    unit_sources: list[Path]  # sources inside program_dir: analysed
    include_dirs: list[Path]
    defines: list[str]
    copies: list[Path] = field(default_factory=list)  # guarded copies of program_dir made by tu_inputs

    @property
    def ext(self) -> str:
        return "cpp" if self.language == "cpp" else "c"

    def canonical(self, path: str) -> Path:
        """Reported path with a guarded copy (see tu_inputs) mapped back to program_dir."""
        resolved = Path(path).resolve()
        for copy in self.copies:
            if copy in resolved.parents:
                return self.program_dir / resolved.relative_to(copy)
        return resolved

    def owns(self, path: str) -> bool:
        """True if a reported file is part of this unit's own code (not support/system headers)."""
        return self.program_dir in self.canonical(path).parents


def own_findings(unit: Unit, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**f, "file": str(unit.canonical(f["file"]))} for f in findings if f["file"] and unit.owns(f["file"])]


def make_unit(record: dict[str, Any]) -> Unit:
    build = record["build"]
    program_dir = Path(record["program_dir"]).resolve()
    unit_sources = []
    for item in build["sources"]:
        path = Path(item)
        resolved = path.resolve() if path.is_absolute() else (program_dir / path).resolve()
        if program_dir in resolved.parents:  # absolute support files (io.c, ...) are not analysed
            unit_sources.append(resolved)
    includes = [Path(d) if Path(d).is_absolute() else (program_dir / d).resolve() for d in build.get("include_dirs", [])]
    language = "cpp" if build.get("compiler", "gcc") in ("g++", "clang++", "c++") else "c"
    std = build.get("std") or ("c++17" if language == "cpp" else "c11")
    return Unit(record, record["unit_id"], record["group_id"], program_dir, language, std,
                unit_sources, includes, list(build.get("defines", [])))


def load_units(path: Path, set_name: str | None, subset: str | None, subsets_path: Path) -> list[Unit]:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if set_name:
        records = [r for r in records if r.get("set") == set_name]
    if subset:
        groups = set(json.loads(subsets_path.read_text())[subset])
        records = [r for r in records if r["group_id"] in groups]
    return [make_unit(r) for r in records]


# ---------------------------------------------------------------------------
# Translation units and subprocesses
# ---------------------------------------------------------------------------
LOCAL_HEADER_SUFFIXES = {".h", ".hpp"}
TYPE_BLOCK_RE = re.compile(r"^typedef struct \w+\n\{.*?\n\} \w+;$", re.M | re.S)


def blank_repeated_type_blocks(texts: list[str]) -> list[str]:
    """Replace a top-level `typedef struct X {...} Y;` block that an earlier source already defines verbatim by
    blank lines (same line count).  Flow variant _67 defines its struct in every file, which is legal across
    translation units but a redefinition inside one wrapper TU."""
    seen: set[str] = set()
    out = []
    for text in texts:
        def blank(match: re.Match[str]) -> str:
            return "\n" * match.group(0).count("\n") if match.group(0) in seen else match.group(0)
        new_text = TYPE_BLOCK_RE.sub(blank, text)
        seen.update(TYPE_BLOCK_RE.findall(text))
        out.append(new_text)
    return out


def tu_inputs(unit: Unit, work: Path, tu_mode: str) -> list[Path]:
    """wrapper: one TU #including every unit source (old Tier-B baseline); per_file: sources as is.

    Two constructs that are legal across translation units break a single wrapper TU, so the wrapper then
    includes an edited copy of program_dir (line numbers unchanged; findings are mapped back by Unit.canonical):
    testcase headers without include guard (e.g. unit.h of _82) get "#pragma once" appended, and struct typedefs
    repeated verbatim in several sources (_67) are blanked after their first definition."""
    if tu_mode != "wrapper" or len(unit.unit_sources) == 1:
        return list(unit.unit_sources)
    sources = list(unit.unit_sources)
    headers = [p for p in unit.program_dir.rglob("*") if p.suffix in LOCAL_HEADER_SUFFIXES]
    texts = [src.read_text(errors="replace") for src in sources]
    edited = blank_repeated_type_blocks(texts)
    if headers or edited != texts:
        copy = work / "guarded_src"
        shutil.copytree(unit.program_dir, copy, dirs_exist_ok=True)
        for header in headers:
            target = copy / header.relative_to(unit.program_dir)
            target.write_text(target.read_text(errors="replace") + "\n#pragma once\n")
        sources = [copy / src.relative_to(unit.program_dir) for src in sources]
        for target, text, original in zip(sources, edited, texts):
            if text != original:
                target.write_text(text)
        unit.copies.append(copy.resolve())
    wrapper = work / f"{safe_name(unit.unit_id)}_tu.{unit.ext}"
    wrapper.write_text("".join('#include "' + str(src) + '"\n' for src in sources))
    return [wrapper]


def compile_flags(unit: Unit) -> list[str]:
    flags = [f"-std={unit.std}"]
    for directory in unit.include_dirs:
        flags += ["-I", str(directory)]
    flags += [f"-D{d}" for d in unit.defines + COMPAT_DEFINES]
    return flags + COMPAT_COMPILER_ARGS


def run_cmd(command: list[str], cwd: Path, timeout: float) -> dict[str, Any]:
    start = time.perf_counter()
    timed_out = False
    try:
        done = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, errors="replace", timeout=timeout)
        stdout, stderr, code = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        code = None
    return {"command": command, "cwd": str(cwd), "exit_code": code, "timed_out": timed_out,
            "duration_s": round(time.perf_counter() - start, 4),
            "stdout": stdout[-RAW_TEXT_CAP:], "stderr": stderr[-RAW_TEXT_CAP:]}


def finding(checker: str, message: str, file: str, line: int | None, **extra: Any) -> dict[str, Any]:
    return {"checker": checker, "message": message, "file": file, "line": line, **extra}


def is_leak(tool: str, item: dict[str, Any]) -> bool:
    checker = item["checker"]
    if tool == "clang_sa":
        rule = CLANG_LEAK_RULES.get(checker)
        return bool(rule and rule.search(item["message"]))
    if tool == "cppcheck":
        return checker in CPPCHECK_LEAK_IDS
    if tool == "codeql":
        return checker in CODEQL_LEAK_RULES
    if tool == "infer":
        return checker in INFER_LEAK_TYPES
    raise ValueError(tool)


# ---------------------------------------------------------------------------
# Clang Static Analyzer
# ---------------------------------------------------------------------------
@dataclass
class Config:
    tool: str
    bins: dict[str, str]
    tu_mode: str
    timeout: float
    work_root: Path
    keep_work: bool
    codeql_cache: Path
    tool_args: list[str] = field(default_factory=list)


def clang_command(cfg: Config, unit: Unit, inputs: list[Path]) -> list[str]:
    return ([cfg.bins["clang"], "--analyze", "-fno-color-diagnostics", *CLANG_ANALYZER_ARGS,
             "-x", "c++" if unit.language == "cpp" else "c"]
            + compile_flags(unit) + cfg.tool_args + [str(p) for p in inputs])


def parse_clang(text: str, cwd: Path) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = DIAG_RE.match(line)
        if not match:
            continue
        sev = match.group("sev")
        file = str((cwd / match.group("file")).resolve())
        if sev in ("error", "fatal error"):
            errors.append(line)
        elif sev == "warning":
            current = finding(match.group("checker") or "", match.group("msg").strip(), file,
                              int(match.group("line")), column=int(match.group("col")), notes=[])
            findings.append(current)
        elif sev == "note" and current is not None:
            current["notes"].append([file, int(match.group("line")), match.group("msg").strip()])
    return findings, errors


def run_clang(cfg: Config, unit: Unit, work: Path) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    multi = len(unit.unit_sources) > 1
    raw = run_cmd(clang_command(cfg, unit, tu_inputs(unit, work, cfg.tu_mode)), work, cfg.timeout)
    findings, errors = parse_clang(raw["stdout"] + "\n" + raw["stderr"], work)
    tu_used = ("wrapper_guarded" if unit.copies else cfg.tu_mode) if multi else "single"
    if cfg.tu_mode == "wrapper" and multi and errors and not raw["timed_out"]:
        # e.g. a testcase header without include guard included by two sources
        first = raw
        raw = run_cmd(clang_command(cfg, unit, list(unit.unit_sources)), work, cfg.timeout)
        raw["wrapper_attempt"] = {k: first[k] for k in ("command", "exit_code", "stderr")}
        findings, errors = parse_clang(raw["stdout"] + "\n" + raw["stderr"], work)
        tu_used = "per_file_fallback"
    raw["tu_mode"] = tu_used
    raw["errors"] = errors[:20]
    if raw["timed_out"]:
        return "timeout", findings, raw
    if raw["exit_code"] != 0:
        return ("compile_error" if errors else "error"), findings, raw
    return "ok", findings, raw


# ---------------------------------------------------------------------------
# Cppcheck
# ---------------------------------------------------------------------------
CPPCHECK_FAILURE_IDS = {"syntaxError", "preprocessorErrorDirective", "cppcheckError", "internalError",
                        "internalAstError", "unknownMacro"}


def cppcheck_command(cfg: Config, unit: Unit, inputs: list[Path], report: Path) -> list[str]:
    command = [cfg.bins["cppcheck"], "--enable=warning,performance,portability", "--inconclusive", "--quiet",
               "--xml", "--xml-version=2", f"--output-file={report}",
               f"--language={'c++' if unit.language == 'cpp' else 'c'}", f"--std={unit.std}"]
    command += [f"-I{d}" for d in unit.include_dirs]
    command += [f"-D{d}" for d in unit.defines + COMPAT_DEFINES]
    return command + cfg.tool_args + [str(p) for p in inputs]


def parse_cppcheck(report: Path) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    if not report.exists():
        return findings, ["no cppcheck XML report"]
    try:
        root = ET.parse(report).getroot()
    except ET.ParseError as exc:
        return findings, [f"cannot parse cppcheck XML: {exc}"]
    for element in root.findall(".//error"):
        attrs = element.attrib
        error_id = attrs.get("id", "")
        message = attrs.get("msg", "") or attrs.get("verbose", "")
        if error_id in CPPCHECK_FAILURE_IDS:
            errors.append(f"{error_id}: {message}")
        locations = element.findall("location")
        primary = locations[0].attrib if locations else {}
        file = str(Path(primary["file"]).resolve()) if primary.get("file") else ""
        line = primary.get("line")
        findings.append(finding(error_id, message, file, int(line) if line and line.isdigit() else None,
                                severity=attrs.get("severity"), cwe=attrs.get("cwe")))
    return findings, errors


def run_cppcheck(cfg: Config, unit: Unit, work: Path) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    report = work / "cppcheck.xml"
    raw = run_cmd(cppcheck_command(cfg, unit, tu_inputs(unit, work, cfg.tu_mode), report), work, cfg.timeout)
    findings, errors = parse_cppcheck(report)
    raw["tu_mode"] = ("wrapper_guarded" if unit.copies else cfg.tu_mode) if len(unit.unit_sources) > 1 else "single"
    raw["errors"] = errors[:20]
    if raw["timed_out"]:
        return "timeout", findings, raw
    if errors:
        return "compile_error", findings, raw
    if raw["exit_code"] != 0:
        return "error", findings, raw
    return "ok", findings, raw


# ---------------------------------------------------------------------------
# CodeQL and Infer: one database / results dir over one or many units
# ---------------------------------------------------------------------------
SYMBOL_RE = re.compile(r"\bsym_\d+\b")


def batch_renames(unit: Unit, tag: str) -> list[str]:
    """-D flags giving this unit's anonymized identifiers (sym_N) a batch-unique spelling.

    CodeQL and Infer merge same-named external functions across the translation units of one database / results
    dir, and every unit defines sym_0, sym_1, ...; without renaming, units in a batch contaminate each other."""
    names: set[str] = set()
    for path in unit.program_dir.rglob("*"):
        if path.is_file():
            names.update(SYMBOL_RE.findall(path.read_text(errors="replace")))
    return [f"-D{name}={name}_{tag}" for name in sorted(names, key=lambda n: int(n[4:]))]


def build_command(unit: Unit, source: Path, obj: Path, renames: list[str] | None = None) -> list[str]:
    return (["g++" if unit.language == "cpp" else "gcc"] + compile_flags(unit) + (renames or [])
            + ["-c", str(source), "-o", str(obj)])


def codeql_query_paths(codeql_bin: str) -> list[str]:
    packs = Path(codeql_bin).parent / "qlpacks" / "codeql" / "cpp-queries"
    version_dir = sorted(p for p in packs.iterdir() if p.is_dir())[-1]
    return [str(version_dir / rel) for rel in CODEQL_QUERIES.values()]


def parse_sarif(path: Path, source_root: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    out = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "").removeprefix("file://")
            file = uri if uri.startswith("/") else str((source_root / uri).resolve()) if uri else ""
            out.append(finding(result.get("ruleId", ""), result.get("message", {}).get("text", ""), file,
                               loc.get("region", {}).get("startLine")))
    return out


def batch_tus(cfg: Config, units: list[Unit], work: Path) -> list[tuple[Unit, Path, Path, Path, list[str]]]:
    """(unit, unit work dir, TU source, object file, rename flags) for every compile command of the batch."""
    out = []
    for position, unit in enumerate(units):
        unit_work = work / "tu" / safe_name(unit.unit_id)
        unit_work.mkdir(parents=True, exist_ok=True)
        renames = batch_renames(unit, f"u{position}") if len(units) > 1 else []
        for index, src in enumerate(tu_inputs(unit, unit_work, cfg.tu_mode)):
            out.append((unit, unit_work, src, unit_work / f"o{index}.o", renames))
    return out


def tu_files(tus: list[tuple[Unit, Path, Path, Path, list[str]]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for unit, _, src, _, _ in tus:
        out.setdefault(unit.unit_id, []).append(str(src))
    return out


def codeql_batch(cfg: Config, units: list[Unit], work: Path, timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    lines = ["set -u"]
    tus = batch_tus(cfg, units, work)
    for unit, _, src, obj, renames in tus:
        lines.append(f"{shlex.join(build_command(unit, src, obj, renames))} || echo {BUILD_FAILED_MARK} {shlex.quote(unit.unit_id)}")
    (work / "build.sh").write_text("\n".join(lines) + "\n")
    db = work / "db"
    # Queries only report files under the source root, so it must contain every program_dir.
    source_root = Path(os.path.commonpath([str(work)] + [str(u.program_dir) for u in units]))
    create = run_cmd([cfg.bins["codeql"], "database", "create", str(db), "--language=cpp",
                      f"--source-root={source_root}", "--overwrite", "--threads=1",
                      f"--command=bash {work / 'build.sh'}"], work, timeout)
    raw: dict[str, Any] = {"create": create, "tu_files": tu_files(tus)}
    if create["timed_out"] or create["exit_code"] != 0:
        return raw, []
    sarif = work / "results.sarif"
    analyze = run_cmd([cfg.bins["codeql"], "database", "analyze", str(db), *codeql_query_paths(cfg.bins["codeql"]),
                       "--format=sarif-latest", f"--output={sarif}", "--threads=1",
                       f"--compilation-cache={cfg.codeql_cache}"], work, max(1.0, timeout - create["duration_s"]))
    raw["analyze"] = analyze
    if analyze["timed_out"] or analyze["exit_code"] != 0 or not sarif.exists():
        return raw, []
    return raw, parse_sarif(sarif, source_root)


def infer_batch(cfg: Config, units: list[Unit], work: Path, timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    entries_units = batch_tus(cfg, units, work)
    entries = [{"directory": str(unit_work), "file": str(src), "arguments": build_command(unit, src, obj, renames)}
               for unit, unit_work, src, obj, renames in entries_units]
    cdb = work / "compile_commands.json"
    cdb.write_text(json.dumps(entries, indent=1))
    results = work / "infer-out"
    run = run_cmd([cfg.bins["infer"], "run", "--results-dir", str(results), *INFER_ARGS,
                   "--compilation-database", str(cdb)], work, timeout)
    raw: dict[str, Any] = {"run": run, "tu_files": tu_files(entries_units)}
    report = results / "report.json"
    if run["timed_out"] or not report.exists():
        return raw, []
    raw["report_json"] = str(report)
    out = []
    for issue in json.loads(report.read_text()):
        file = issue.get("file", "")
        if file and not file.startswith("/"):
            file = str((work / file).resolve())
        out.append(finding(issue.get("bug_type", ""), issue.get("qualifier", ""), file, issue.get("line"),
                           procedure=issue.get("procedure")))
    return raw, out


def batch_unit_status(tool: str, raw: dict[str, Any], unit: Unit) -> str:
    if "exception" in raw:
        return "error"
    step = raw["create"] if tool == "codeql" else raw["run"]
    log = step["stdout"] + step["stderr"]
    if step["timed_out"]:
        return "timeout"
    if tool == "codeql":
        if f"{BUILD_FAILED_MARK} {unit.unit_id}" in log:
            return "compile_error"
        if step["exit_code"] != 0 or "analyze" not in raw:
            return "error"
        if raw["analyze"]["timed_out"]:
            return "timeout"
        return "ok" if raw["analyze"]["exit_code"] == 0 else "error"
    # with --keep-going Infer names each translation unit it failed to capture; a TU whose frontend reports
    # errors is still captured (partially) without that message, so error diagnostics in the unit's own files
    # (sources, guarded copies, wrapper TU) count as compile errors too.
    tus = raw.get("tu_files", {}).get(unit.unit_id, [])
    if any(f"Error running compilation for '{tu}'" in log for tu in tus):
        return "compile_error"
    for line in log.splitlines():
        match = DIAG_RE.match(line)
        if match and match["sev"] in ("error", "fatal error") and (match["file"] in tus or unit.owns(match["file"])):
            return "compile_error"
    return "ok" if step["exit_code"] == 0 and "report_json" in raw else "error"


def run_batch_tool(cfg: Config, units: list[Unit], work: Path, timeout: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    runner = codeql_batch if cfg.tool == "codeql" else infer_batch
    try:
        return runner(cfg, units, work, timeout)
    except Exception as exc:  # recorded; the run continues
        return {"exception": repr(exc)}, []


# ---------------------------------------------------------------------------
# Predictions
# ---------------------------------------------------------------------------
def compact(item: dict[str, Any]) -> dict[str, Any]:
    return {"checker": item["checker"], "file": Path(item["file"]).name, "line": item["line"],
            "message": item["message"][:200]}


def prediction(tool: str, layer: str, unit: Unit, status: str, findings: list[dict[str, Any]], latency: float,
               extra: dict[str, Any]) -> dict[str, Any]:
    own = own_findings(unit, findings)
    leaks = [f for f in own if is_leak(tool, f)]
    pred = (1 if leaks else 0) if status == "ok" else None
    extra = {**extra, "n_findings": len(own), "leak_findings": [compact(f) for f in leaks],
             "other_checkers": sorted({f["checker"] for f in own if not is_leak(tool, f)})}
    return {"unit_id": unit.unit_id, "method": tool, "strategy": None, "model": None, "layer": layer,
            "pred": pred, "score": None, "latency_s": round(latency, 4), "status": status, "extra": extra}


def grep_v0_pred(unit: Unit, layer: str) -> dict[str, Any]:
    start = time.perf_counter()
    text = unit.record["model_text"]
    pred = 0 if ("free(" in text or "delete" in text) else 1
    return {"unit_id": unit.unit_id, "method": "grep_v0", "strategy": None, "model": None, "layer": layer,
            "pred": pred, "score": None, "latency_s": round(time.perf_counter() - start, 6), "status": "ok", "extra": {}}


PER_UNIT_RUNNERS = {"clang_sa": run_clang, "cppcheck": run_cppcheck}


def run_unit(cfg: Config, layer: str, unit: Unit) -> tuple[dict[str, Any], dict[str, Any]]:
    """One unit at a time (codeql/infer: a database of one unit)."""
    work = cfg.work_root / safe_name(unit.unit_id)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    start = time.perf_counter()
    if cfg.tool in PER_UNIT_RUNNERS:
        try:
            status, findings, raw = PER_UNIT_RUNNERS[cfg.tool](cfg, unit, work)
        except Exception as exc:
            status, findings, raw = "error", [], {"exception": repr(exc)}
        extra = {"tu_mode": raw.get("tu_mode")}
    else:
        raw, findings = run_batch_tool(cfg, [unit], work, cfg.timeout)
        status, extra = batch_unit_status(cfg.tool, raw, unit), {}
    latency = time.perf_counter() - start
    if not cfg.keep_work:
        shutil.rmtree(work, ignore_errors=True)
    return (prediction(cfg.tool, layer, unit, status, findings, latency, extra),
            {"unit_id": unit.unit_id, **raw, "findings": findings})


def make_batches(units: list[Unit], size: int) -> list[list[Unit]]:
    """Batches of <= size units, never two units of one group together (they share symbol names)."""
    batches: list[tuple[list[Unit], set[str]]] = []
    for unit in units:
        for batch, groups in batches:
            if len(batch) < size and unit.group_id not in groups:
                batch.append(unit)
                groups.add(unit.group_id)
                break
        else:
            batches.append(([unit], {unit.group_id}))
    return [batch for batch, _ in batches]


def run_batched(cfg: Config, layer: str, units: list[Unit], size: int, jobs: int,
                sink: Callable[[dict[str, Any]], None]) -> list[dict[str, Any]]:
    def one(item: tuple[int, list[Unit]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        index, batch = item
        work = cfg.work_root / f"batch_{index:04d}"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        start = time.perf_counter()
        raw, findings = run_batch_tool(cfg, batch, work, cfg.timeout * len(batch))
        wall = time.perf_counter() - start
        preds = [prediction(cfg.tool, layer, unit, batch_unit_status(cfg.tool, raw, unit), findings, wall / len(batch),
                            {"batch": index, "batch_size": len(batch), "batch_wall_s": round(wall, 3)})
                 for unit in batch]
        if not cfg.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        print(f"batch {index}: {len(batch)} units {wall:.1f}s", file=sys.stderr, flush=True)
        return preds, {"batch": index, "units": [u.unit_id for u in batch], "wall_s": wall, **raw, "findings": findings}

    preds: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for batch_preds, raw in pool.map(one, enumerate(make_batches(units, size))):
            preds.extend(batch_preds)
            sink(raw)
    return preds


# ---------------------------------------------------------------------------
# L3 evidence (Clang SA)
# ---------------------------------------------------------------------------
def source_keys(unit: Unit, source_file: str) -> list[str]:
    """Spellings under which line_map may name a unit file: absolute, program_dir-relative, basename."""
    path = Path(source_file)
    absolute = (path if path.is_absolute() else unit.program_dir / path).resolve()
    keys = [str(absolute), path.name]
    if unit.program_dir in absolute.parents:
        keys.append(str(absolute.relative_to(unit.program_dir)))
    return keys


def evidence_row(unit: Unit, findings: list[dict[str, Any]]) -> dict[str, Any]:
    line_index: dict[tuple[str, int], int] = {}
    for source_file, source_line, model_line in unit.record.get("line_map") or []:
        for key in source_keys(unit, source_file):
            line_index.setdefault((key, int(source_line)), model_line)
    warnings = []
    for item in own_findings(unit, findings):
        if not is_leak("clang_sa", item):
            continue
        path = Path(item["file"])
        try:
            statement = path.read_text(errors="replace").splitlines()[item["line"] - 1].strip()
        except (OSError, IndexError):
            statement = None
        model_line = next((line_index[(key, item["line"])] for key in source_keys(unit, str(path))
                           if (key, item["line"]) in line_index), None)
        warnings.append({"checker": item["checker"], "message": item["message"],
                         "source_file": str(path.relative_to(unit.program_dir)), "source_line": item["line"],
                         "model_text_line": model_line, "statement_text": statement})
    return {"unit_id": unit.unit_id, "warnings": warnings}


def write_evidence(rows: list[dict[str, Any]], run_path: Path, layer_path: Path) -> None:
    """Per-run file plus the layer-wide evidence.jsonl (merged by unit_id, newest run wins)."""
    run_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    merged: dict[str, dict[str, Any]] = {}
    if layer_path.exists():
        for line in layer_path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                merged[row["unit_id"]] = row
    merged.update({row["unit_id"]: row for row in rows})
    layer_path.write_text("".join(json.dumps(merged[k]) + "\n" for k in sorted(merged)))


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
def first_line(command: list[str]) -> str:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    lines = [ln.strip() for ln in (done.stdout + done.stderr).splitlines() if ln.strip() and "warning:" not in ln]
    return lines[0] if lines else ""


def tool_versions(tool: str, bins: dict[str, str]) -> dict[str, Any]:
    if tool == "clang_sa":
        cfgs = {}
        for name in ("clang.cfg", "clang++.cfg"):
            path = Path(bins["clang"]).parent / name
            if path.exists():
                cfgs[str(path)] = path.read_text().strip()
        return {"clang": first_line([bins["clang"], "--version"]), "clang_cfg_files": cfgs}
    if tool == "cppcheck":
        return {"cppcheck": first_line([bins["cppcheck"], "--version"])}
    if tool == "codeql":
        return {"codeql": first_line([bins["codeql"], "version"]), "queries": codeql_query_paths(bins["codeql"]),
                "gcc": first_line(["gcc", "--version"]), "g++": first_line(["g++", "--version"])}
    if tool == "infer":
        return {"infer": first_line([bins["infer"], "--version"]), "gcc": first_line(["gcc", "--version"])}
    return {"python": sys.version.split()[0]}


def command_template(cfg: Config, batch_size: int | None) -> str:
    bins, extra = cfg.bins, " ".join(cfg.tool_args)
    flags = "-std=<build.std> -I <build.include_dirs> -D<build.defines> -D_GNU_SOURCE -include alloca.h"
    tu = (f"<TU> (tu_mode={cfg.tu_mode}: one wrapper file #including all unit sources when >1 source; "
          "if program_dir has headers or repeated struct typedefs, the wrapper includes a copy whose headers end with "
          "'#pragma once' and whose repeated typedef blocks are blanked)")
    if cfg.tool == "clang_sa":
        return (f"{bins['clang']} --analyze -fno-color-diagnostics {' '.join(CLANG_ANALYZER_ARGS)} -x <c|c++> {flags} "
                f"{extra} {tu}; on compile error of the wrapper: same command with the unit sources (per_file_fallback)")
    if cfg.tool == "cppcheck":
        return (f"{bins['cppcheck']} --enable=warning,performance,portability --inconclusive --quiet --xml "
                "--xml-version=2 --output-file=<report.xml> --language=<c|c++> --std=<build.std> -I<include_dirs> "
                f"-D<build.defines> -D_GNU_SOURCE {extra} {tu}")
    if cfg.tool == "codeql":
        return (f"{bins['codeql']} database create <db> --language=cpp "
                "--source-root=<common ancestor of work dir and all program_dirs> --overwrite --threads=1 "
                f"--command='bash <work>/build.sh' (build.sh: <gcc|g++> {flags} [-Dsym_N=sym_N_u<k> for every sym_N of "
                f"unit k when units per database > 1] -c {tu} -o <obj>, one line per TU); "
                f"{bins['codeql']} database analyze <db> {' '.join(CODEQL_QUERIES.values())} --format=sarif-latest "
                f"--output=<sarif> --threads=1 --compilation-cache=<cache>  (units per database: {batch_size or 1})")
    if cfg.tool == "infer":
        return (f"{bins['infer']} run --results-dir <out> {' '.join(INFER_ARGS)} "
                f"--compilation-database compile_commands.json (entries: <gcc|g++> {flags} [-Dsym_N=sym_N_u<k> when "
                f"units per run > 1] -c {tu}; "
                f"units per run: {batch_size or 1})")
    return "pred = 1 iff 'free(' not in model_text and 'delete' not in model_text"


def mapping_description(tool: str) -> Any:
    return {
        "clang_sa": {k: v.pattern for k, v in CLANG_LEAK_RULES.items()},
        "cppcheck": sorted(CPPCHECK_LEAK_IDS),
        "codeql": sorted(CODEQL_LEAK_RULES),
        "infer": sorted(INFER_LEAK_TYPES),
        "grep_v0": "pred 1 iff model_text contains neither 'free(' nor 'delete'",
    }[tool]


def git_head() -> str | None:
    try:
        done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    except OSError:
        return None
    return done.stdout.strip() or None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tool", required=True, choices=TOOLS)
    parser.add_argument("--units", required=True, type=Path)
    parser.add_argument("--set", choices=("dev", "eval"))
    parser.add_argument("--subset", help="subset name in --subsets-file (list of group ids)")
    parser.add_argument("--subsets-file", type=Path, default=JULIET_FULL / "data" / "build" / "subsets.json")
    parser.add_argument("--layer", default="layer1")
    parser.add_argument("--out", type=Path, help="default: static/results/<tool>/<layer>/<run_id>.jsonl")
    parser.add_argument("--run-id")
    parser.add_argument("--limit", type=int, help="first N selected units only (smoke tests)")
    parser.add_argument("-j", "--jobs", type=int, default=1, help="parallel units (or batches); recorded in meta")
    parser.add_argument("--timeout", type=float, default=UNIT_TIMEOUT_S, help="seconds per unit (batch: x units)")
    parser.add_argument("--tu-mode", choices=("wrapper", "per_file"),
                        help="default: per_file for infer (it links TUs itself and skips functions defined in "
                             "#included files), wrapper for the other tools (chosen on dev)")
    parser.add_argument("--batch-size", type=int, default=1, help="codeql/infer: units per database/run")
    parser.add_argument("--clang-bin", default=str(DEFAULT_BINS["clang"]))
    parser.add_argument("--cppcheck-bin", default=str(DEFAULT_BINS["cppcheck"]))
    parser.add_argument("--codeql-bin", default=str(DEFAULT_BINS["codeql"]))
    parser.add_argument("--infer-bin", default=str(DEFAULT_BINS["infer"]))
    parser.add_argument("--tool-arg", action="append", default=[], help="extra clang/cppcheck argument (repeatable)")
    parser.add_argument("--keep-work", action="store_true")
    parser.add_argument("--no-evidence", action="store_true", help="clang_sa: do not export L3 evidence")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    units = load_units(args.units, args.set, args.subset, args.subsets_file)
    if args.limit:
        units = units[: args.limit]
    if not units:
        raise SystemExit("no units selected")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = args.run_id or f"{args.set or 'all'}{'_' + args.subset if args.subset else ''}_{stamp}"
    out = (args.out or STATIC_DIR / "results" / args.tool / args.layer / f"{run_id}.jsonl").resolve()
    run_id = out.stem
    out.parent.mkdir(parents=True, exist_ok=True)
    raw_path = out.parent / "raw_logs" / f"{run_id}.raw.jsonl.gz"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    bins = {"clang": args.clang_bin, "cppcheck": args.cppcheck_bin, "codeql": args.codeql_bin, "infer": args.infer_bin}
    if args.tu_mode is None:
        args.tu_mode = "per_file" if args.tool == "infer" else "wrapper"
    cfg = Config(args.tool, bins, args.tu_mode, args.timeout,
                 STATIC_DIR / "scratch" / "work" / f"{args.tool}_{run_id}", args.keep_work,
                 STATIC_DIR / "scratch" / "codeql_compilation_cache", list(args.tool_arg))
    batched = args.tool in ("codeql", "infer") and args.batch_size > 1
    if args.tool == "grep_v0":
        timing_mode = "per_unit_inprocess"
    elif batched:
        timing_mode = "batched"
    else:
        timing_mode = "per_unit_c1" if args.jobs == 1 else f"per_unit_parallel_j{args.jobs}"
    meta: dict[str, Any] = {
        "method": args.tool, "layer": args.layer, "run_id": run_id,
        "versions": tool_versions(args.tool, bins),
        "command_template": command_template(cfg, args.batch_size if batched else None),
        "argv": [sys.executable] + sys.argv, "script_sha256": sha256_file(Path(__file__)), "git_head": git_head(),
        "units_file": str(args.units.resolve()), "units_sha256": sha256_file(args.units), "set": args.set,
        "subset": args.subset, "n_units": len(units), "timeout_s_per_unit": args.timeout, "tu_mode": args.tu_mode,
        "compat_defines": COMPAT_DEFINES, "compat_compiler_args": COMPAT_COMPILER_ARGS,
        "leak_mapping": mapping_description(args.tool), "concurrency": args.jobs, "timing_mode": timing_mode,
        "batch_size": args.batch_size if batched else None,
        "latency_note": ("latency_s = batch wall time / units in batch (amortized)" if batched else
                         "latency_s = wall time of the per-unit step (TU preparation + tool run + parsing)"),
        "host": socket.gethostname(), "platform": platform.platform(), "cpu_count": os.cpu_count(),
        "loadavg_start": os.getloadavg(), "start_utc": utc_now(),
    }
    wall_start = time.perf_counter()
    evidence_rows: list[dict[str, Any]] = []
    unit_map = {u.unit_id: u for u in units}
    with gzip.open(raw_path, "wt") as raw_handle:
        def sink(row: dict[str, Any]) -> None:
            raw_handle.write(json.dumps(row) + "\n")
            if args.tool == "clang_sa" and not args.no_evidence:
                evidence_rows.append(evidence_row(unit_map[row["unit_id"]], row.get("findings", [])))

        if args.tool == "grep_v0":
            preds = [grep_v0_pred(u, args.layer) for u in units]
        elif batched:
            cfg.work_root.mkdir(parents=True, exist_ok=True)
            preds = run_batched(cfg, args.layer, units, args.batch_size, args.jobs, sink)
        else:
            cfg.work_root.mkdir(parents=True, exist_ok=True)
            preds = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                for index, (pred, raw) in enumerate(pool.map(lambda u: run_unit(cfg, args.layer, u), units), 1):
                    preds.append(pred)
                    sink(raw)
                    if index % 100 == 0:
                        print(f"{index}/{len(units)}", file=sys.stderr, flush=True)
    order = {u.unit_id: i for i, u in enumerate(units)}
    preds.sort(key=lambda p: order[p["unit_id"]])
    out.write_text("".join(json.dumps(p) + "\n" for p in preds))
    statuses: dict[str, int] = {}
    for pred in preds:
        statuses[pred["status"]] = statuses.get(pred["status"], 0) + 1
    meta.update({"end_utc": utc_now(), "loadavg_end": os.getloadavg(),
                 "wall_total_s": round(time.perf_counter() - wall_start, 3), "status_counts": statuses,
                 "predictions": str(out), "raw_logs": str(raw_path)})
    if evidence_rows:
        evidence_rows.sort(key=lambda r: order[r["unit_id"]])
        ev_run = out.with_suffix(".evidence.jsonl")
        write_evidence(evidence_rows, ev_run, out.parent / "evidence.jsonl")
        meta["evidence"] = {"run": str(ev_run), "layer": str(out.parent / "evidence.jsonl")}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    if not args.keep_work:
        shutil.rmtree(cfg.work_root, ignore_errors=True)
    print(json.dumps({"out": str(out), "status_counts": statuses, "wall_total_s": meta["wall_total_s"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
