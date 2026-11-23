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

ARITY = {"alloc": 3, "free": 2, "assign": 3, "pass": 4, "retval": 3, "ret": 2, "call": 2,
         "global": 1, "dead": 3, "realloc_fail": 2}
DEAD_KINDS = {"alloc", "free", "assign", "pass"}
_FACT_RE = re.compile(r"^([A-Za-z_]+)\s*\((.*)\)\s*\.?\s*$")


@dataclass
class FactParse:
    facts: dict[str, list[tuple[str, ...]]] = field(default_factory=lambda: {k: [] for k in ARITY})
    bad_lines: list[str] = field(default_factory=list)
    n_lines: int = 0
    said_none: bool = False

    @property
    def n_facts(self) -> int:
        return sum(len(v) for v in self.facts.values())

    @property
    def strict_ok(self) -> bool:
        """Every non-empty line is a well-formed fact (or the single line ``none``)."""
        return not self.bad_lines and (self.n_facts > 0 or self.said_none)


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
    name = name.replace("->", ".").replace(" ", "")
    while name.startswith(("*", "&")):
        name = name[1:]
    return name


def parse_facts(text: str | None) -> FactParse:
    result = FactParse()
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
        if not match or match.group(1) not in ARITY:
            result.bad_lines.append(line[:200])
            continue
        name = match.group(1)
        args = [a.removesuffix("()").strip() for a in _split_args(match.group(2))]
        if len(args) != ARITY[name] or any(not a or "\t" in a for a in args):
            result.bad_lines.append(line[:200])
            continue
        if name in ("alloc", "free", "assign", "pass", "retval", "ret", "global", "dead"):
            positions = {"alloc": [1], "free": [0], "assign": [0, 1], "pass": [1, 2], "retval": [0],
                         "ret": [1], "global": [0], "dead": [1]}[name]
            args = [(_normalize_var(a) if i in positions else a) for i, a in enumerate(args)]
        if name == "dead" and args[2] not in DEAD_KINDS:
            result.bad_lines.append(line[:200])
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
