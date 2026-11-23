"""Run gcov and turn its JSON into per-unit line/branch coverage.

Counts come from ``gcov -j -b -c``.  Every number in the report is an
aggregate of those records; when a line or branch never ran, its count is 0
and it is listed explicitly.  There is no sampling, no estimated percentage
and no threshold that turns an unexecuted line into a covered one.
"""

from __future__ import annotations

import gzip
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .units import Unit, owned_paths

ALLOC_SITE = re.compile(r"\b(?:malloc|calloc|realloc)\s*\(|\bnew\b")
FREE_SITE = re.compile(r"\bfree\s*\(|\bdelete\b")
LINE_SUMMARY = re.compile(r"Lines executed:([\d.]+)% of (\d+)")


def _stdout_total(stdout: str) -> int | None:
    matches = LINE_SUMMARY.findall(stdout)
    return int(matches[-1][1]) if matches else None


def _stdout_hit(stdout: str) -> int | None:
    matches = LINE_SUMMARY.findall(stdout)
    if not matches:
        return None
    percent, total = matches[-1]
    return int(round(float(percent) * int(total) / 100.0))


@dataclass
class FileCoverage:
    path: Path
    lines: dict[int, int] = field(default_factory=dict)
    branches: dict[tuple, int] = field(default_factory=dict)
    functions: dict[str, int] = field(default_factory=dict)

    def merge(self, other: "FileCoverage") -> None:
        for line, count in other.lines.items():
            self.lines[line] = max(self.lines.get(line, 0), count)
        for key, count in other.branches.items():
            self.branches[key] = max(self.branches.get(key, 0), count)
        for name, count in other.functions.items():
            self.functions[name] = max(self.functions.get(name, 0), count)


@dataclass
class Coverage:
    files: dict[str, FileCoverage] = field(default_factory=dict)
    gcov_runs: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_line_records: int = 0

    def merge(self, other: "Coverage") -> None:
        for key, file_cov in other.files.items():
            if key not in self.files:
                self.files[key] = FileCoverage(path=file_cov.path)
            self.files[key].merge(file_cov)
        self.errors.extend(other.errors)


def parse_gcov_json(path: Path, cwd: Path) -> Coverage:
    coverage = Coverage()
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - recorded as a coverage error
        coverage.errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
        return coverage
    for record in data.get("files", []):
        raw_path = record.get("file")
        if not raw_path:
            continue
        file_path = Path(raw_path)
        if not file_path.is_absolute():
            file_path = (cwd / file_path).resolve()
        key = str(file_path.resolve())
        file_cov = coverage.files.setdefault(key, FileCoverage(path=file_path.resolve()))
        for line in record.get("lines", []):
            coverage.raw_line_records += 1
            number = line.get("line_number")
            if number is None:
                continue
            count = int(line.get("count") or 0)
            file_cov.lines[number] = max(file_cov.lines.get(number, 0), count)
            function = line.get("function_name")
            if function:
                file_cov.functions[function] = max(
                    file_cov.functions.get(function, 0), count
                )
            for branch in line.get("branches", []):
                branch_key = (
                    number,
                    branch.get("source_block_id"),
                    branch.get("destination_block_id"),
                    bool(branch.get("throw")),
                    bool(branch.get("fallthrough")),
                )
                branch_count = int(branch.get("count") or 0)
                file_cov.branches[branch_key] = max(
                    file_cov.branches.get(branch_key, 0), branch_count
                )
    return coverage


def run_gcov(
    mode_dir: Path,
    sources: list[Path],
    object_dir: Path,
) -> Coverage:
    mode_dir.mkdir(parents=True, exist_ok=True)
    coverage = Coverage()
    for source in sources:
        cmd = ["gcov", "-j", "-b", "-c", "-o", str(object_dir), str(source)]
        try:
            proc = subprocess.run(
                cmd, cwd=str(mode_dir), capture_output=True, text=True, timeout=120
            )
            stdout = proc.stdout
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            stdout = ""
            returncode = None
        json_file = mode_dir / f"{source.stem}.gcov.json.gz"
        per_source = (
            parse_gcov_json(json_file, mode_dir) if json_file.exists() else Coverage()
        )
        parsed_total = per_source.raw_line_records
        parsed_hit = sum(
            1
            for file_cov in per_source.files.values()
            for count in file_cov.lines.values()
            if count > 0
        )
        coverage.gcov_runs.append(
            {
                "source": str(source),
                "command": cmd,
                "returncode": returncode,
                "lines_total": _stdout_total(stdout),
                "lines_hit": _stdout_hit(stdout),
                "lines_total_parsed": parsed_total,
                "lines_hit_parsed": parsed_hit,
                "stdout": stdout[-4000:],
            }
        )
        if returncode != 0:
            coverage.errors.append(f"gcov failed for {source.name}: rc={returncode}")
        if not json_file.exists():
            coverage.errors.append(f"gcov produced no JSON for {source.name}")
        coverage.merge(per_source)
    return coverage


def merge_coverages(coverages: list[Coverage]) -> Coverage:
    merged = Coverage()
    for coverage in coverages:
        merged.merge(coverage)
    return merged


def filter_owned(coverage: Coverage, unit: Unit) -> Coverage:
    owned = owned_paths(unit)
    filtered = Coverage(gcov_runs=coverage.gcov_runs, errors=list(coverage.errors))
    for key, file_cov in coverage.files.items():
        try:
            resolved = Path(key).resolve()
        except OSError:
            continue
        if resolved in owned:
            filtered.files[key] = file_cov
    return filtered


def _branch_dict(key: tuple, count: int) -> dict:
    line, source_block, destination_block, throw, fallthrough = key
    return {
        "line": line,
        "source_block_id": source_block,
        "destination_block_id": destination_block,
        "throw": throw,
        "fallthrough": fallthrough,
        "count": count,
    }


def summarize(coverage: Coverage) -> dict:
    files = []
    lines_total = lines_hit = branches_total = branches_hit = 0
    uncovered_lines: list[dict] = []
    uncovered_branches: list[dict] = []
    functions: dict[str, int] = {}
    for key in sorted(coverage.files):
        file_cov = coverage.files[key]
        file_lines_total = len(file_cov.lines)
        file_lines_hit = sum(1 for count in file_cov.lines.values() if count > 0)
        file_branches_total = len(file_cov.branches)
        file_branches_hit = sum(1 for count in file_cov.branches.values() if count > 0)
        lines_total += file_lines_total
        lines_hit += file_lines_hit
        branches_total += file_branches_total
        branches_hit += file_branches_hit
        for name, count in file_cov.functions.items():
            if name == "__gcov_format_version__":
                continue
            functions[name] = max(functions.get(name, 0), count)
        missing_lines = sorted(number for number, count in file_cov.lines.items() if count == 0)
        missing_branches = [
            _branch_dict(branch_key, count)
            for branch_key, count in sorted(
                file_cov.branches.items(), key=lambda item: str(item[0])
            )
            if count == 0
        ]
        try:
            rel = Path(key).resolve().relative_to(config.PROJECT)
            display = str(rel)
        except ValueError:
            display = key
        for number in missing_lines:
            uncovered_lines.append({"file": display, "line": number})
        for branch in missing_branches:
            branch["file"] = display
            uncovered_branches.append(branch)
        files.append(
            {
                "file": display,
                "lines_total": file_lines_total,
                "lines_hit": file_lines_hit,
                "line_pct": file_lines_hit / file_lines_total if file_lines_total else None,
                "branches_total": file_branches_total,
                "branches_hit": file_branches_hit,
                "branch_pct": file_branches_hit / file_branches_total if file_branches_total else None,
                "uncovered_lines": missing_lines,
                "uncovered_branches": len(missing_branches),
            }
        )
    return {
        "lines_total": lines_total,
        "lines_hit": lines_hit,
        "line_pct": lines_hit / lines_total if lines_total else None,
        "branches_total": branches_total,
        "branches_hit": branches_hit,
        "branch_pct": branches_hit / branches_total if branches_total else None,
        "files": files,
        "uncovered_lines": uncovered_lines,
        "uncovered_branches": uncovered_branches[:400],
        "uncovered_branch_count": branches_total - branches_hit,
        "functions": functions,
    }


def tier(summary: dict, coverage_error: bool = False, effective: bool = False) -> str:
    if coverage_error:
        return "coverage_error"
    total_key = "effective_lines_total" if effective else "lines_total"
    total = summary.get(total_key, 0)
    if total == 0:
        return "no_coverage"
    if summary["lines_hit"] == 0:
        return "not_executed"
    if summary["lines_hit"] < total:
        return "partial"
    if summary["branches_total"] and summary["branches_hit"] < summary["branches_total"]:
        return "line_complete"
    return "branch_complete"


def annotate_dead_code(summary: dict, unit: Unit) -> dict:
    """Separate Juliet's declared CWE-561 dead lines from reachable gaps.

    Some good variants contain a branch guarded by a constant-false global and
    a line commented ``INCIDENTAL: CWE 561 Dead Code``.  That line is
    genuinely unreachable in the shipped test; treating it as "insufficient
    execution" would overstate the coverage gap.  Both the raw and the
    dead-code-adjusted totals stay in the record, and the exact lines are
    listed, so the adjustment is auditable rather than a threshold.
    """
    dead: list[dict] = []
    cache: dict[str, list[str]] = {}
    for item in summary.get("uncovered_lines", []):
        relative = item.get("file")
        line = item.get("line")
        if not relative or not isinstance(line, int):
            continue
        if relative not in cache:
            try:
                cache[relative] = (config.PROJECT / relative).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                cache[relative] = []
        text = cache[relative]
        context = text[max(0, line - 6) : line]
        if any("CWE 561 Dead Code" in row for row in context):
            dead.append(item)
    summary["dead_code_uncovered"] = dead
    summary["effective_lines_total"] = max(0, summary["lines_total"] - len(dead))
    summary["effective_line_pct"] = (
        summary["lines_hit"] / summary["effective_lines_total"]
        if summary["effective_lines_total"]
        else None
    )
    return summary


def entry_executed(summary: dict, entry: str) -> bool:
    """Whether the probe's entry function has at least one executed line.

    C++ names arrive mangled from gcov (e.g. ``_ZN...3badEv``); the Itanium
    token for a 3-letter ``bad`` is ``3bad``, so both the plain and the
    mangled forms are accepted.  A namespace-qualified demangled name
    (``...::bad``) is accepted too.
    """
    if summary["lines_hit"] == 0:
        return False
    mangled_token = f"{len(entry)}{entry}"
    for name, count in summary["functions"].items():
        if count <= 0:
            continue
        if name == entry or name.endswith("::" + entry) or mangled_token in name:
            return True
    return False


def site_coverage(unit: Unit, coverage: Coverage) -> dict:
    """Whether the unit's own allocation / release call sites were executed.

    Only lines that gcov marks executable are counted.  A site on a line that
    the compiler attributed to a header is therefore not silently included.
    """
    alloc_total = alloc_hit = free_total = free_hit = 0
    missing: list[dict] = []
    for source in unit.sources:
        resolved = source.resolve()
        file_cov = coverage.files.get(str(resolved))
        if file_cov is None:
            continue
        try:
            text_lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, text in enumerate(text_lines, 1):
            if number not in file_cov.lines:
                continue
            alloc = bool(ALLOC_SITE.search(text))
            free = bool(FREE_SITE.search(text))
            if not (alloc or free):
                continue
            hit = file_cov.lines[number] > 0
            if alloc:
                alloc_total += 1
                alloc_hit += int(hit)
            if free:
                free_total += 1
                free_hit += int(hit)
            if not hit:
                missing.append(
                    {
                        "file": str(resolved.relative_to(config.PROJECT)),
                        "line": number,
                        "allocation": alloc,
                        "release": free,
                    }
                )
    return {
        "allocation_sites_total": alloc_total,
        "allocation_sites_hit": alloc_hit,
        "release_sites_total": free_total,
        "release_sites_hit": free_hit,
        "uncovered_sites": missing,
    }
