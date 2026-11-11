#!/usr/bin/env python3
"""Shared helpers for the Juliet CWE-401 subset.

The module deliberately relies only on the Python standard library and on
the original Juliet layout: every test case is a group of one or more
translation units whose ``bad``/``good`` entry points are gated by
``OMITBAD``/``OMITGOOD`` and whose ``main`` is gated by ``INCLUDEMAIN``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
CWE_DIR = RAW / "testcases" / "CWE401_Memory_Leak"
SUPPORT = RAW / "testcasesupport"

NAME_RE = re.compile(
    r"^CWE401_Memory_Leak__(?P<family>.+?)_(?P<variant>\d{2})(?P<suffix>[a-z]?)"
    r"(?:_(?P<part>bad|good[A-Za-z0-9]*))?\.(?P<ext>c|cpp|h)$"
)
FUNC_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|virtual\s+|extern\s+)*"
    r"(?:void|int|char|short|long|float|double|size_t|wchar_t|"
    r"unsigned|signed|bool|struct\s+\w+|[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)"
    r"\s*[\*&]?\s*([A-Za-z_~]\w*(?:::[~A-Za-z_]\w*)?)\s*\([^;{}]*\)"
    r"\s*(?:const)?\s*(\{)?\s*$"
)
CONTROL = {"if", "for", "while", "switch", "catch", "return", "sizeof"}


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def parse_name(name: str) -> dict | None:
    m = NAME_RE.match(name)
    if not m:
        return None
    d = m.groupdict()
    d["group_id"] = f"CWE401_Memory_Leak__{d['family']}_{d['variant']}"
    return d


@dataclass
class FuncDef:
    name: str
    line: int
    guards: tuple[tuple[str, str], ...]
    included: dict[str, bool] = field(default_factory=dict)

    @property
    def short_name(self) -> str:
        return self.name.rsplit("::", 1)[-1]


@dataclass
class TestCase:
    group_id: str
    family: str
    variant: str
    language: str
    sources: list[Path]
    headers: list[Path]
    entries_bad: list[FuncDef] = field(default_factory=list)
    entries_good: list[FuncDef] = field(default_factory=list)
    main_defs: list[tuple[Path, FuncDef]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def variant_key(self) -> tuple[int, str]:
        return (int(self.variant), "")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _eval_expr(expr: str, defines: set[str]) -> bool:
    expr = expr.strip()
    expr = re.sub(
        r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)",
        lambda m: "1" if m.group(1) in defines else "0",
        expr,
    )
    expr = re.sub(
        r"defined\s+([A-Za-z_]\w*)",
        lambda m: "1" if m.group(1) in defines else "0",
        expr,
    )
    expr = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: "1" if m.group(0) in defines else "0", expr)
    expr = expr.replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r"(?<![=!<>])!(?!=)", " not ", expr)
    if not re.fullmatch(r"[01\s()andornot]+", expr):
        raise ValueError(f"unsupported preprocessor expression: {expr!r}")
    return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - sanitised above


def parse_functions(path: Path) -> tuple[list[FuncDef], list[dict]]:
    """Return top-level-ish function definitions and the guard frames seen.

    The parser is intentionally small: Juliet sources put one definition
    signature per line and the opening brace on the next line.  It tracks
    ``#if/#ifdef/#ifndef/#else/#endif`` so a function can be associated with
    the exact guards that control its compilation.
    """
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    text = _strip_comments(raw_text)
    lines = text.splitlines()
    guards: list[tuple[str, str]] = []
    stack: list[list] = []  # [expr, line, else_expr]
    funcs: list[FuncDef] = []
    frames_seen: list[dict] = []

    def current_guards() -> tuple[tuple[str, str], ...]:
        return tuple((expr, f"line {line}") for expr, line, _ in stack)

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            directive = stripped[1:].strip()
            word = directive.split(None, 1)[0] if directive else ""
            rest = directive[len(word):].strip()
            if word in ("if", "ifdef", "ifndef"):
                if word == "ifdef":
                    expr = f"defined({rest})"
                elif word == "ifndef":
                    expr = f"!defined({rest})"
                else:
                    expr = rest
                stack.append([expr, idx, None])
                frames_seen.append({"directive": f"#{word}", "expr": expr, "line": idx})
            elif word == "elif":
                if not stack:
                    continue
                prev = stack[-1][0]
                stack[-1][0] = f"!({prev}) && ({rest})"
                frames_seen.append({"directive": "#elif", "expr": stack[-1][0], "line": idx})
            elif word == "else":
                if stack:
                    stack[-1][0] = f"!({stack[-1][0]})"
                    frames_seen.append({"directive": "#else", "expr": stack[-1][0], "line": idx})
            elif word == "endif":
                if stack:
                    stack.pop()
            continue
        if not stripped or stripped == "{":
            continue
        m = FUNC_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        if name in CONTROL:
            continue
        opening = bool(m.group(2))
        if not opening:
            nxt = idx
            while nxt < len(lines) and not lines[nxt].strip():
                nxt += 1
            if nxt >= len(lines) or not lines[nxt].lstrip().startswith("{"):
                continue
        if "::" in name and "~" in name:
            continue
        fn = FuncDef(name=name, line=idx, guards=current_guards())
        fn.included = {
            "bad_build": all(_eval_expr(e, {"OMITGOOD", "INCLUDEMAIN"}) for e, _ in fn.guards),
            "good_build": all(_eval_expr(e, {"OMITBAD", "INCLUDEMAIN"}) for e, _ in fn.guards),
        }
        funcs.append(fn)
    return funcs, frames_seen


def _is_bad_entry(name: str) -> bool:
    short = name.rsplit("::", 1)[-1]
    return short == "bad" or (short.endswith("_bad") and not short.endswith("Sink"))


def _is_good_entry(name: str) -> bool:
    short = name.rsplit("::", 1)[-1]
    return short == "good" or (short.endswith("_good") and not short.endswith("Sink"))


def discover_groups() -> list[TestCase]:
    groups: dict[str, dict] = {}
    for path in sorted(CWE_DIR.rglob("*")):
        if not path.is_file():
            continue
        info = parse_name(path.name)
        if info is None or info["ext"] == "h":
            continue
        g = groups.setdefault(
            info["group_id"],
            {
                "family": info["family"],
                "variant": info["variant"],
                "langs": set(),
                "sources": [],
                "headers": [],
            },
        )
        g["langs"].add(info["ext"])
        g["sources"].append(path)
    for path in sorted(CWE_DIR.rglob("*.h")):
        info = parse_name(path.name)
        if info is None:
            continue
        if info["group_id"] in groups:
            groups[info["group_id"]]["headers"].append(path)

    out: list[TestCase] = []
    for gid, g in sorted(groups.items()):
        if len(g["langs"]) != 1:
            raise SystemExit(f"mixed language group: {gid}")
        lang = "cpp" if "cpp" in g["langs"] else "c"
        tc = TestCase(
            group_id=gid,
            family=g["family"],
            variant=g["variant"],
            language=lang,
            sources=sorted(g["sources"]),
            headers=sorted(g["headers"]),
        )
        for src in tc.sources:
            funcs, _ = parse_functions(src)
            for fn in funcs:
                if _is_bad_entry(fn.name):
                    tc.entries_bad.append(fn)
                if _is_good_entry(fn.name):
                    tc.entries_good.append(fn)
                if fn.short_name == "main" and fn.included["bad_build"]:
                    tc.main_defs.append((src, fn))
        bad_ok = [
            f for f in tc.entries_bad
            if f.included["bad_build"] and not f.included["good_build"]
        ]
        good_ok = [
            f for f in tc.entries_good
            if f.included["good_build"] and not f.included["bad_build"]
        ]
        if len(bad_ok) != 1:
            tc.problems.append(f"bad entries included only in bad build: {len(bad_ok)}")
        if len(good_ok) != 1:
            tc.problems.append(f"good entries included only in good build: {len(good_ok)}")
        if not tc.main_defs:
            tc.problems.append("no INCLUDEMAIN main")
        out.append(tc)
    return out


def source_hashes(tc: TestCase) -> dict[str, str]:
    return {rel(p): sha256_file(p) for p in tc.sources + tc.headers}


def normalize_code(text: str) -> str:
    """Token skeleton used only for the near-duplicate audit."""
    text = _strip_comments(text)
    text = re.sub(r"^\s*#.*$", "", text, flags=re.M)
    text = re.sub(r'"(?:\\.|[^"\\])*"', "<str>", text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "<chr>", text)
    text = re.sub(r"\b(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?)\b", "<num>", text)
    tokens = re.findall(r"[A-Za-z_]\w*|::|->|[^\sA-Za-z_]", text)
    out = []
    for tok in tokens:
        if re.fullmatch(r"[A-Za-z_]\w*", tok):
            out.append("<id>")
        else:
            out.append(tok)
    return " ".join(out)


def shingles(text: str, n: int = 5) -> set[str]:
    toks = text.split()
    if len(toks) < n:
        return {" ".join(toks)}
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def iter_group_code(tc: TestCase) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in tc.sources)


def checked_rel_files(paths: Iterable[Path]) -> list[str]:
    return sorted(rel(p) for p in paths)
