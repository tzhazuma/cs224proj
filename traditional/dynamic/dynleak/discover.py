from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .util import short_hash, slugify


C_EXTENSIONS = {".c"}
CPP_EXTENSIONS = {".cc", ".cpp", ".cxx"}
SOURCE_EXTENSIONS = C_EXTENSIONS | CPP_EXTENSIONS


def infer_language(path: Path) -> str:
    return "c" if path.suffix.lower() in C_EXTENSIONS else "cpp"


def normalize_label(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int) and value in (0, 1):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "vulnerable", "bad", "positive", "leak"}:
            return 1
        if text in {"0", "false", "clean", "fixed", "good", "negative", "non_vulnerable", "non-vulnerable"}:
            return 0
    raise ValueError(f"unsupported expected_label: {value!r}")


def _resolve(base: Path, value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


@dataclass
class CaseSpec:
    case_id: str
    source: Path
    sources: list[Path]
    language: str
    expected_label: Optional[int]
    origin: str = "manifest"
    variant: Optional[str] = None
    label_source: Optional[str] = None
    cwe: str = "CWE-401"
    defines: list[str] = field(default_factory=list)
    include_dirs: list[Path] = field(default_factory=list)
    cflags: list[str] = field(default_factory=list)
    ldflags: list[str] = field(default_factory=list)
    argv: list[str] = field(default_factory=list)
    stdin_data: Optional[str] = None
    timeout_s: float = 10.0
    cwd: Optional[Path] = None
    env: dict[str, str] = field(default_factory=dict)
    feature: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_manifest_row(self, root: Optional[Path] = None) -> dict[str, Any]:
        def rel(path: Path) -> str:
            if root is not None:
                try:
                    return str(path.resolve().relative_to(root.resolve()))
                except ValueError:
                    pass
            return str(path)

        row: dict[str, Any] = {
            "case_id": self.case_id,
            "source": rel(self.source),
            "sources": [rel(path) for path in self.sources],
            "language": self.language,
            "expected_label": self.expected_label,
            "origin": self.origin,
            "variant": self.variant,
            "label_source": self.label_source,
            "cwe": self.cwe,
            "defines": list(self.defines),
            "include_dirs": [rel(path) for path in self.include_dirs],
            "cflags": list(self.cflags),
            "ldflags": list(self.ldflags),
            "argv": list(self.argv),
            "stdin": self.stdin_data,
            "timeout_s": self.timeout_s,
            "env": dict(self.env),
            "feature": self.feature,
            "metadata": self.metadata,
        }
        if self.cwd is not None:
            row["cwd"] = rel(self.cwd)
        return row


def load_manifest(path: Path) -> list[CaseSpec]:
    base = path.resolve().parent
    cases: list[CaseSpec] = []
    seen: set[str] = set()
    existence: dict[Path, bool] = {}

    def is_file(candidate: Path) -> bool:
        if candidate not in existence:
            existence[candidate] = candidate.is_file()
        return existence[candidate]

    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            source_value = row.get("source")
            if not source_value:
                raise ValueError(f"{path}:{line_no}: missing 'source'")
            source = _resolve(base, source_value)
            if not is_file(source):
                raise ValueError(f"{path}:{line_no}: source does not exist: {source}")
            sources_raw = row.get("sources") or [source_value]
            sources: list[Path] = []
            for item in sources_raw:
                candidate = _resolve(base, item)
                if not is_file(candidate):
                    raise ValueError(f"{path}:{line_no}: source does not exist: {candidate}")
                if candidate not in sources:
                    sources.append(candidate)
            if source not in sources:
                sources.insert(0, source)
            language = str(row.get("language") or infer_language(source)).lower()
            if language not in {"c", "cpp", "c++"}:
                raise ValueError(f"{path}:{line_no}: unsupported language {language!r}")
            language = "cpp" if language in {"cpp", "c++"} else "c"
            timeout_s = float(row.get("timeout_s", 10.0))
            if timeout_s <= 0:
                raise ValueError(f"{path}:{line_no}: timeout_s must be positive")
            case_id = str(row.get("case_id") or f"manifest__{slugify(source.stem)}__{short_hash(str(source))}")
            if case_id in seen:
                raise ValueError(f"{path}:{line_no}: duplicate case_id {case_id!r}")
            seen.add(case_id)
            include_dirs = [_resolve(base, item) for item in row.get("include_dirs", [])]
            source_dir = source.parent
            if source_dir not in include_dirs:
                include_dirs.insert(0, source_dir)
            cwd_value = row.get("cwd")
            cwd = _resolve(base, cwd_value) if cwd_value else None
            cases.append(
                CaseSpec(
                    case_id=case_id,
                    source=source,
                    sources=sources,
                    language=language,
                    expected_label=normalize_label(row.get("expected_label")),
                    origin=str(row.get("origin") or "manifest"),
                    variant=row.get("variant"),
                    label_source=row.get("label_source"),
                    cwe=str(row.get("cwe") or "CWE-401"),
                    defines=[str(item) for item in row.get("defines", [])],
                    include_dirs=include_dirs,
                    cflags=[str(item) for item in row.get("cflags", [])],
                    ldflags=[str(item) for item in row.get("ldflags", [])],
                    argv=[str(item) for item in row.get("argv", [])],
                    stdin_data=row.get("stdin"),
                    timeout_s=timeout_s,
                    cwd=cwd,
                    env={str(key): str(value) for key, value in (row.get("env") or {}).items()},
                    feature=row.get("feature"),
                    metadata=dict(row.get("metadata") or {}),
                )
            )
    if not cases:
        raise ValueError(f"{path}: manifest contains no cases")
    return cases


_MAIN_RE = re.compile(r"#\s*ifdef\s+INCLUDEMAIN\b")
_INT_MAIN_RE = re.compile(r"\bint\s+main\s*\(")
_VARIANT_RE = re.compile(r"^(?P<prefix>.*_\d+)(?P<suffix>[A-Za-z_][A-Za-z0-9_]*)?$")


def _feature_from_name(path: Path) -> str:
    match = re.match(r"^CWE401_Memory_Leak__(?P<feature>.+?)_\d+", path.stem)
    if match:
        return match.group(1)
    return path.stem


def _variant_suffix(path: Path) -> str:
    match = _VARIANT_RE.match(path.stem)
    return match.group("suffix") if match and match.group("suffix") else ""


def _is_standalone_variant(path: Path) -> bool:
    suffix = _variant_suffix(path)
    return suffix == "_bad" or suffix.startswith("_good")


def _group_sources(root: Path, files_by_dir: Optional[dict[Path, list[Path]]] = None) -> list[Path]:
    """Return root plus Juliet sibling translation units.

    Juliet splits some flow variants across ``_22a``/``_22b`` or
    ``_81a``/``_81_bad`` files.  The group is the filename prefix up to and
    including the numeric template id.
    """
    match = _VARIANT_RE.match(root.stem)
    if not match or _is_standalone_variant(root):
        return [root]
    prefix = match.group("prefix")
    directory = root.parent
    pattern = re.compile(
        r"^" + re.escape(prefix) + r"(?:[A-Za-z_][A-Za-z0-9_]*)?\.(?:c|cc|cpp|cxx)$"
    )
    directory_files = (
        files_by_dir.get(directory.resolve(), [])
        if files_by_dir is not None
        else sorted(directory.iterdir())
    )
    siblings = [
        candidate
        for candidate in directory_files
        if candidate.suffix.lower() in SOURCE_EXTENSIONS
        and pattern.match(candidate.name)
    ]
    siblings.sort(key=lambda item: item.name)
    if root not in siblings:
        siblings.insert(0, root)
    else:
        siblings.remove(root)
        siblings.insert(0, root)
    return siblings


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _index_sources(root: Path) -> tuple[dict[Path, list[Path]], list[Path]]:
    files_by_dir: dict[Path, list[Path]] = {}
    sources: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in {"testcasesupport", ".git"}
        )
        directory = Path(dirpath).resolve()
        for name in sorted(filenames):
            path = directory / name
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            files_by_dir.setdefault(directory, []).append(path)
            sources.append(path)
    return files_by_dir, sources


def _has_macro(text: str, name: str) -> bool:
    return re.search(r"#\s*(?:ifdef|ifndef|if\s+defined)\s*\(?\s*" + re.escape(name) + r"\b", text) is not None


def discover_juliet(
    root: Path,
    support_dir: Optional[Path] = None,
    *,
    exclude_wchar: bool = False,
    exclude_patterns: Optional[Iterable[str]] = None,
    timeout_s: float = 10.0,
) -> list[CaseSpec]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Juliet CWE-401 root is not a directory: {root}")
    if support_dir is None:
        support_dir = root.parent.parent / "testcasesupport"
    support_dir = support_dir.resolve()
    if not (support_dir / "std_testcase.h").is_file():
        raise ValueError(f"Juliet testcasesupport not found at {support_dir}")
    excluded = [item for item in (exclude_patterns or []) if item]

    files_by_dir, all_sources = _index_sources(root)
    candidates: list[Path] = []
    for source in all_sources:
        relative = source.relative_to(root)
        text_name = str(relative).lower()
        if "testcasesupport" in text_name or "w32" in text_name:
            continue
        if exclude_wchar and "wchar_t" in text_name:
            continue
        if any(pattern in str(relative) for pattern in excluded):
            continue
        candidates.append(source)

    texts: dict[Path, str] = {}
    workers = min(16, max(2, (os.cpu_count() or 4) * 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for source, text in zip(candidates, pool.map(_read_text, candidates)):
            texts[source] = text
    roots: list[Path] = [
        source
        for source in candidates
        if _MAIN_RE.search(texts[source]) and _INT_MAIN_RE.search(texts[source])
    ]

    cases: list[CaseSpec] = []
    seen: set[str] = set()
    for source in roots:
        text = texts[source]
        sources = _group_sources(source, files_by_dir)
        relative = source.relative_to(root)
        feature = _feature_from_name(source)
        has_bad = _has_macro(text, "OMITBAD")
        has_good = _has_macro(text, "OMITGOOD")
        if has_bad and has_good:
            variants = [("bad", "OMITGOOD", 1), ("good", "OMITBAD", 0)]
        elif has_bad:
            variants = [("bad", "OMITGOOD", 1)]
        elif has_good:
            variants = [("good", "OMITBAD", 0)]
        else:
            variants = [("default", None, None)]

        for variant, define, label in variants:
            identity = f"{relative.as_posix()}|{variant}"
            case_id = (
                f"juliet__{slugify(feature, 40)}__{variant}__{short_hash(identity)}"
            )
            if case_id in seen:
                raise ValueError(f"duplicate Juliet case id: {case_id}")
            seen.add(case_id)
            defines = ["INCLUDEMAIN"]
            if define:
                defines.append(define)
            cases.append(
                CaseSpec(
                    case_id=case_id,
                    source=source,
                    sources=sources,
                    language=infer_language(source),
                    expected_label=label,
                    origin="juliet",
                    variant=variant,
                    label_source="juliet_preprocessor_variant",
                    cwe="CWE-401",
                    defines=defines,
                    include_dirs=[support_dir, source.parent],
                    timeout_s=timeout_s,
                    feature=feature,
                    metadata={
                        "juliet_relpath": relative.as_posix(),
                        "juliet_root": str(root),
                        "support_dir": str(support_dir),
                        "group_sources": [item.name for item in sources],
                        "omitted_path": define,
                    },
                )
            )
    cases.sort(key=lambda item: (item.metadata.get("juliet_relpath", ""), item.variant or ""))
    if not cases:
        raise ValueError(f"no Juliet CWE-401 roots found under {root}")
    return cases
