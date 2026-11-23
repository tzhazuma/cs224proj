"""L4: parse LLM-extracted heap facts (l4/SCHEMA.md) and derive leaks with Souffle (l4/leak.dl)."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import LLM_DIR

SOUFFLE_BIN = Path("/home/barton/tools/cs224/souffle-2.5/usr/bin/souffle")
SOUFFLE_LIB = SOUFFLE_BIN.parent.parent / "lib"
RULES_PATH = LLM_DIR / "l4" / "leak.dl"

# Fact schema v3 (l4/SCHEMA.md). Line = 1-based line of the numbered listing (model_text line).
ARITY = {"alloc": 4, "realloc": 5, "free": 3, "assign": 4, "pass": 5, "retval": 4, "ret": 3, "call": 3,
         "global": 1, "dead": 1}
VAR_POSITIONS = {"alloc": [1], "realloc": [1, 2], "free": [0], "assign": [0, 1], "pass": [1, 2], "retval": [0],
                 "ret": [1], "global": [0]}
FUNC_POSITIONS = {"alloc": [2], "realloc": [3], "free": [1], "assign": [2], "pass": [0, 3], "retval": [1, 2],
                  "ret": [0], "call": [0, 1]}
LINE_POSITION = {"alloc": 3, "realloc": 4, "free": 2, "assign": 3, "pass": 4, "retval": 3, "ret": 2, "call": 2,
                 "dead": 0}
# Fact names the model uses for a schema fact with the same arguments (the C++ spelling of free).
FACT_ALIASES = {"delete": "free"}
_FACT_RE = re.compile(r"^([A-Za-z_]+)\s*\((.*)\)\s*\.?\s*$")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# What the cited line must contain for the fact to be kept (grounding check against the code).
_LINE_KEYWORD = {"alloc": re.compile(r"\b(malloc|calloc|strdup|wcsdup|new)\b"),
                 "realloc": re.compile(r"\brealloc\b"), "free": re.compile(r"\b(free|delete)\b"),
                 "ret": re.compile(r"\breturn\b")}
# Argument positions of which at least one identifier must occur on the cited line.
_LINE_NAMES = {"alloc": [1], "realloc": [1, 2], "free": [0], "assign": [0, 1], "pass": [0, 2], "retval": [0, 1],
               "ret": [1]}
# A pointer variable cannot be named like the allocator or operator that produced it.
_NOT_A_VAR = {"new", "malloc", "calloc", "realloc", "strdup", "wcsdup", "free", "delete", "NULL", "nullptr"}


@dataclass
class FactParse:
    facts: dict[str, list[tuple[str, ...]]] = field(default_factory=lambda: {k: [] for k in ARITY})
    bad_lines: list[str] = field(default_factory=list)
    ungrounded: list[str] = field(default_factory=list)
    n_lines: int = 0
    said_none: bool = False

    @property
    def n_facts(self) -> int:
        return sum(len(v) for v in self.facts.values())

    @property
    def strict_ok(self) -> bool:
        """Every non-empty line is a well-formed fact (or the single line ``none``)."""
        return not self.bad_lines and (self.n_facts + len(self.ungrounded) > 0 or self.said_none)


def _split_args(text: str) -> list[str]:
    args, depth, current = [], 0, []
    for char in text:
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        if char == "," and depth == 0:
            args.append("".join(current))
            current = []
        else:
            current.append(char)
    args.append("".join(current))
    return [a.strip().strip("`'\"").strip() for a in args]


def _normalize_var(name: str) -> str:
    """Field- and element-insensitive: s.f, s->f, a[], a[i] all denote the node of the base variable."""
    name = name.replace("->", ".").replace(" ", "")
    while name.startswith(("*", "&")):
        name = name[1:]
    return re.split(r"[.\[]", name, maxsplit=1)[0] or name


def _normalize_func(name: str) -> str:
    """Namespaces and classes are dropped from function names (sym_1::sym_0 -> sym_0, C::~C -> ~C), so that a
    function is one node however the model qualifies it; renamed Juliet functions are unique per unit."""
    return name.replace(" ", "").rsplit("::", 1)[-1]


def _grounded(name: str, args: list[str], code_lines: list[str]) -> bool:
    if any(args[i] in _NOT_A_VAR for i in VAR_POSITIONS.get(name, [])):
        return False
    if name == "call" and args[1] == "main":
        return False  # main is the entry; an edge into it is a reversed call edge
    line_no = int(args[LINE_POSITION[name]])
    if not 1 <= line_no <= len(code_lines):
        return False
    text = code_lines[line_no - 1]
    keyword = _LINE_KEYWORD.get(name)
    if keyword is not None and not keyword.search(text):
        return False
    words = set(_IDENT_RE.findall(text))
    positions = _LINE_NAMES.get(name)
    if positions is None:
        return True
    return any(set(_IDENT_RE.findall(args[i].replace("::~", "::"))) & words for i in positions)


def parse_facts(text: str | None, code: str | None = None) -> FactParse:
    """Parse fact lines. With `code` (the unit's model_text), facts whose Line does not hold the statement
    (keyword and one of its names) go to `ungrounded` instead of `facts`."""
    result = FactParse()
    code_lines = code.split("\n") if code is not None else None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("```") or line.startswith("//") or line.startswith("#"):
            continue
        result.n_lines += 1
        if line.rstrip(".").strip().lower() == "none":
            result.said_none = True
            continue
        line = re.sub(r"^[-*]\s+", "", line)
        match = _FACT_RE.match(line)
        name = FACT_ALIASES.get(match.group(1), match.group(1)) if match else None
        if name not in ARITY:
            result.bad_lines.append(line[:200])
            continue
        args = [a.removesuffix("()").strip() for a in _split_args(match.group(2))]
        if len(args) != ARITY[name] or any(not a or "\t" in a for a in args):
            result.bad_lines.append(line[:200])
            continue
        if name in LINE_POSITION and not re.fullmatch(r"\d+", args[LINE_POSITION[name]]):
            result.bad_lines.append(line[:200])
            continue
        positions = VAR_POSITIONS.get(name, [])
        args = [(_normalize_var(a) if i in positions else a) for i, a in enumerate(args)]
        for i in FUNC_POSITIONS.get(name, []):
            args[i] = _normalize_func(args[i])
        if name in LINE_POSITION:
            args[LINE_POSITION[name]] = str(int(args[LINE_POSITION[name]]))
        if code_lines is not None and name in LINE_POSITION and not _grounded(name, args, code_lines):
            result.ungrounded.append(line[:200])
            continue
        result.facts[name].append(tuple(args))
    return result


@dataclass
class SouffleResult:
    status: str  # "ok" | "error" | "timeout"
    leaks: list[tuple[str, str]]
    seconds: float
    error: str | None = None


def souffle_env() -> dict[str, str]:
    env = dict(os.environ)
    if SOUFFLE_LIB.is_dir():
        env["LD_LIBRARY_PATH"] = f"{SOUFFLE_LIB}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    return env


def run_souffle(parsed: FactParse, rules: Path = RULES_PATH, timeout: float = 60.0) -> SouffleResult:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="l4_") as tmp:
        work = Path(tmp)
        for name, rows in parsed.facts.items():
            (work / f"{name}.facts").write_text("".join("\t".join(r) + "\n" for r in rows), encoding="utf-8")
        try:
            proc = subprocess.run([str(SOUFFLE_BIN), "-F", str(work), "-D", str(work), str(rules)],
                                  capture_output=True, text=True, timeout=timeout, env=souffle_env())
        except subprocess.TimeoutExpired:
            return SouffleResult("timeout", [], time.monotonic() - started, "souffle timeout")
        output = work / "leak.csv"
        if proc.returncode != 0 or not output.exists():
            return SouffleResult("error", [], time.monotonic() - started,
                                 (proc.stderr or proc.stdout or f"rc={proc.returncode}")[-400:])
        leaks = [tuple(line.split("\t")) for line in output.read_text().splitlines() if line.strip()]
        return SouffleResult("ok", leaks, time.monotonic() - started)


def souffle_version() -> str:
    proc = subprocess.run([str(SOUFFLE_BIN), "--version"], capture_output=True, text=True, env=souffle_env())
    match = re.search(r"Version:\s*(\S+)", proc.stdout)
    return match.group(1) if match else proc.stdout.strip()[:40]
