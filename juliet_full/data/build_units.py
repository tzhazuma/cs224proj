#!/usr/bin/env python3
"""Build the layer-1 (debiased) and original-Juliet CWE-401 unit files.

Layer 1 (PLAN 2.3, README section 3):
  bad  = the bad entry plus the helpers/files/classes it reaches (OMITGOOD build);
  good = ONE good entry (G2B or B2G, seeded and stratified ~50/50 per flow category)
         plus only the helpers it reaches (OMITBAD build); the ..._good() wrapper is dropped.
  `static` is removed from every function definition/prototype in both labels; file-scope
  variables keep their storage class. A generated driver main (same text for both labels)
  calls the entry once.
Original control (original.jsonl): bad = the layer-1 bad unit; good = the whole OMITBAD
  program (all goods + wrapper, `static` kept), driver calls the wrapper, good_kind "orig".

The compiled program files are already cleaned (comments removed, OMIT/INCLUDEMAIN/_WIN32
conditionals resolved, label-bearing identifiers renamed sym_N with the juliet_llm/cleaning.py
rules plus the extra tokens of the leakage test). model_text = those files with
`std_testcase.h` dropped and the testcase-local header inlined once, joined with the
cleaning.py part separators.

Usage: python build_units.py [--sample-only]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DATA_DIR.parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "juliet" / "scripts"))
sys.path.insert(0, str(PROJECT_ROOT / "juliet_llm"))
import cleaning  # noqa: E402  (juliet_llm/cleaning.py)
import lib_juliet  # noqa: E402  (juliet/scripts/lib_juliet.py)

SEED = 20261123
SPLIT_PATH = PROJECT_ROOT / "juliet" / "full_split_v1.json"
SUPPORT_DIR = (PROJECT_ROOT / "juliet" / "raw" / "testcasesupport").resolve()
BUILD_DIR = DATA_DIR / "build"
PROGRAMS_DIR = BUILD_DIR / "programs"
VERIFY_RESULTS = BUILD_DIR / "verify_results.jsonl"

# cleaning.py renames (bad|good|cwe|memory_leak|benign|fixed); the leakage test of the task
# also forbids G2B, B2G, Leak, OMIT, flaw, FIX, so the renaming regex is the union.
LEAKY_IDENTIFIER_RE = re.compile(r"(?i)(bad|good|g2b|b2g|cwe|leak|omit|flaw|fix|benign)")
LEAKY_STRING_RE = re.compile(
    r"(?i)(?:bad|good|g2b|b2g|cwe\d*|leak|flaw|omit|fix|std_testcase|benign"
    r"|raw/testcases|/mnt/|juliet/|\b(?:safe|clean|patched|remediated)\b)"
)
LEAKAGE_TEST_RE = re.compile(r"(?i)(bad|good|g2b|b2g|cwe|leak|omit|flaw|fix)")

IDENT_RE = re.compile(r"[A-Za-z_]\w*")
DIRECTIVE_RE = re.compile(r"^\s*#\s*([A-Za-z_]+)\b(.*)$")
TYPE_KEYWORDS = {"class", "struct", "union", "enum", "typedef"}
C_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "return", "sizeof", "break",
    "continue", "default", "goto", "const", "static", "extern", "void", "int", "char",
    "long", "short", "unsigned", "signed", "float", "double", "struct", "class", "union",
    "enum", "typedef", "public", "private", "protected", "virtual", "new", "delete",
    "namespace", "using", "operator", "this", "template", "typename", "inline",
}


# ---------------------------------------------------------------- source parsing
def resolve_conditionals(text: str, defines: set[str], path: Path) -> list[tuple[str, bool]]:
    """Resolve #if/#ifdef/#ifndef with `defines`; return (line, inside_label_guard) pairs.

    Only OMITBAD/OMITGOOD/INCLUDEMAIN/_WIN32 conditionals occur in the CWE-401 testcases.
    """
    out: list[tuple[str, bool]] = []
    stack: list[tuple[bool, bool, bool]] = []  # (parent_active, condition, is_label_guard)
    active = True
    for line in text.splitlines():
        match = DIRECTIVE_RE.match(line)
        if match is None or match.group(1) not in {"if", "ifdef", "ifndef", "else", "endif", "elif"}:
            if active:
                out.append((line, any(entry[2] for entry in stack)))
            continue
        kind, rest = match.group(1), match.group(2).strip()
        if kind in {"ifdef", "ifndef", "if"}:
            condition = cleaning._eval_condition(kind, rest, defines)
            label_guard = rest.split()[0] in {"OMITBAD", "OMITGOOD"} if rest else False
            stack.append((active, condition, label_guard))
            active = active and condition
        elif kind == "else":
            parent, condition, label_guard = stack[-1]
            active = parent and not condition
        elif kind == "endif":
            parent, _, _ = stack.pop()
            active = parent
        else:
            raise RuntimeError(f"{path}: unsupported #{kind}")
    if stack:
        raise RuntimeError(f"{path}: unclosed conditional")
    return out


def code_only(text: str) -> str:
    """Blank out string and character literals (keeps length)."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(c + " " * max(0, min(j, n) - i - 1) + (c if j < n else ""))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


@dataclass
class Item:
    kind: str  # directive | namespace_open | namespace_close | function | prototype | type | variable | other
    lines: list[str]
    start: int  # 0-based index in the resolved line list
    guarded: bool
    names: set[str] = field(default_factory=set)  # names this item defines
    owner: str | None = None  # class name for out-of-class member definitions
    refs: set[str] = field(default_factory=set)
    namespace: str | None = None


def classify(item: Item) -> None:
    text = code_only("\n".join(item.lines))
    item.refs = set(IDENT_RE.findall(text))
    brace = text.find("{")
    semi = text.find(";")
    if brace >= 0 and (semi < 0 or brace < semi):
        header = text[:brace].strip()
        first_word = header.split()[0] if header.split() else ""
        paren = header.find("(")
        eq = header.find("=")
        if first_word in TYPE_KEYWORDS or paren < 0 or (0 <= eq < paren):
            if first_word in TYPE_KEYWORDS:
                item.kind = "type"
                words = IDENT_RE.findall(header)
                if len(words) > 1:
                    item.names.add(words[1])
                tail = text[text.rfind("}") + 1:]
                item.names.update(IDENT_RE.findall(tail))
            else:
                item.kind = "variable"
                names = IDENT_RE.findall(header[: eq if eq >= 0 else len(header)])
                if names:
                    item.names.add(names[-1])
            return
        item.kind = "function"
        match = re.search(r"([A-Za-z_]\w*(?:\s*::\s*~?\s*[A-Za-z_]\w*)*)\s*$", header[:paren])
        if match is None:
            raise RuntimeError(f"cannot parse function header: {header!r}")
        qualified = re.sub(r"\s+", "", match.group(1))
        parts = qualified.split("::")
        if len(parts) > 1:
            item.owner = parts[-2]
            item.names.add(qualified)
        else:
            item.names.add(parts[0])
        return
    body = text.strip().rstrip(";")
    words = body.split()
    if not words or words[0] == "using":
        item.kind = "other"
        return
    paren = body.find("(")
    eq = body.find("=")
    if paren >= 0 and (eq < 0 or paren < eq):
        match = re.search(r"([A-Za-z_]\w*)\s*$", body[:paren])
        if match and match.group(1) not in C_KEYWORDS and "(*" not in body.replace(" ", "")[:paren + 2]:
            item.kind = "prototype"
            item.names.add(match.group(1))
            return
    item.kind = "variable"
    decl = body[: eq if eq >= 0 else len(body)]
    decl = decl.split("[")[0]
    names = [w for w in IDENT_RE.findall(decl) if w not in C_KEYWORDS]
    if names:
        item.names.add(names[-1])


def brace_delta(line: str) -> int:
    code = code_only(line)
    return code.count("{") - code.count("}")


def split_items(lines: list[tuple[str, bool]], path: Path) -> list[Item]:
    """Split resolved top-level code into items (namespaces are flattened with markers)."""
    items: list[Item] = []
    ns_stack: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        line, guarded = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("#"):
            items.append(Item("directive", [line], i, guarded))
            i += 1
            continue
        ns_match = re.match(r"namespace\s+([A-Za-z_]\w*)\s*(\{)?\s*$", stripped)
        if ns_match:
            block = [line]
            if not ns_match.group(2):
                i += 1
                while not lines[i][0].strip():
                    i += 1
                if lines[i][0].strip() != "{":
                    raise RuntimeError(f"{path}:{i}: namespace without brace")
                block.append(lines[i][0])
            items.append(Item("namespace_open", block, i, guarded, namespace=ns_match.group(1)))
            ns_stack.append(ns_match.group(1))
            i += 1
            continue
        if stripped in {"}", "};"} and ns_stack:
            items.append(Item("namespace_close", [line], i, guarded, namespace=ns_stack.pop()))
            i += 1
            continue
        start = i
        block: list[str] = []
        depth = 0
        is_guarded = False
        while True:
            line, guarded = lines[i]
            block.append(line)
            is_guarded = is_guarded or guarded
            depth += brace_delta(line)
            code = code_only(line).rstrip()
            i += 1
            if depth == 0 and (code.endswith(";") or (code.endswith("}") and "{" in code_only("\n".join(block)))):
                # a closing brace followed by a lone ';' line belongs to this item
                break
            if i >= n:
                raise RuntimeError(f"{path}: unterminated item at line {start}")
        item = Item("other", block, start, is_guarded, namespace=ns_stack[-1] if ns_stack else None)
        classify(item)
        items.append(item)
    if ns_stack:
        raise RuntimeError(f"{path}: unclosed namespace")
    return items


# ---------------------------------------------------------------- group analysis
@dataclass
class FileView:
    raw_path: Path
    is_header: bool
    items: list[Item]


def load_views(case: lib_juliet.TestCase, defines: set[str]) -> list[FileView]:
    views = []
    for path, is_header in [(p, False) for p in case.sources] + [(p, True) for p in case.headers]:
        text = cleaning.strip_comments(path.read_text(encoding="utf-8"))
        views.append(FileView(path, is_header, split_items(resolve_conditionals(text, defines, path), path)))
    return views


def find_function(views: list[FileView], name: str) -> tuple[FileView, Item]:
    hits = [(v, it) for v in views for it in v.items if it.kind == "function" and name in it.names]
    if len(hits) != 1:
        raise RuntimeError(f"expected one definition of {name}, found {len(hits)}")
    return hits[0]


def wrapper_name(case: lib_juliet.TestCase) -> str:
    return case.entries_good[0].name


def bad_entry_name(case: lib_juliet.TestCase) -> str:
    return case.entries_bad[0].name


def good_entry_candidates(views: list[FileView], wrapper: str) -> list[str]:
    _, item = find_function(views, wrapper)
    body = code_only("\n".join(item.lines))
    body = body[body.find("{"):]
    return re.findall(r"\b([A-Za-z_]\w*)\s*\(\s*\)\s*;", body)


def entry_kind(name: str) -> str:
    if "G2B" in name:
        return "G2B"
    if "B2G" in name:
        return "B2G"
    return "other"


def reachable(views: list[FileView], entry: str) -> set[int]:
    """ids of label-guarded items reachable from `entry` (unguarded items are always kept)."""
    by_name: dict[str, list[Item]] = defaultdict(list)
    by_owner: dict[str, list[Item]] = defaultdict(list)
    for view in views:
        for item in view.items:
            for name in item.names:
                by_name[name].append(item)
            if item.owner:
                by_owner[item.owner].append(item)
    kept: set[int] = set()
    queue = [entry]
    seen_names: set[str] = set()
    while queue:
        name = queue.pop()
        if name in seen_names:
            continue
        seen_names.add(name)
        for item in by_name.get(name, []) + by_owner.get(name, []):
            if id(item) in kept:
                continue
            kept.add(id(item))
            queue.extend(item.refs)
    return kept


# ---------------------------------------------------------------- program emission
def strip_static(lines: list[str]) -> list[str]:
    out = list(lines)
    for index, line in enumerate(out):
        if line.strip():
            out[index] = re.sub(r"^(\s*)static\s+", r"\1", line, count=1)
            break
    return out


def neutral_name(index: int, total: int, ext: str) -> str:
    return f"unit_{index}{ext}"


@dataclass
class Program:
    files: list[tuple[str, list[str]]]  # (relative name, lines) in model_text order; headers last
    header_names: set[str]
    language: str
    entry: str  # neutral entry name (sym_0 or ns::sym_0)
    mapping: dict[str, str]


def emit_program(
    case: lib_juliet.TestCase,
    views: list[FileView],
    entry: str,
    *,
    prune: bool,
    remove_static: bool,
) -> Program:
    keep_ids = reachable(views, entry) if prune else None
    ext = ".cpp" if case.language == "cpp" else ".c"
    header_rename = {v.raw_path.name: "unit.h" for v in views if v.is_header}
    if len(header_rename) > 1:
        raise RuntimeError(f"{case.group_id}: more than one local header")

    _, entry_item = find_function(views, entry)
    mapping: dict[str, str] = {entry: "sym_0"}
    if entry_item.namespace:
        mapping[entry_item.namespace] = "sym_1"

    pruned: list[tuple[FileView, list[str]]] = []
    for view in views:
        out_lines: list[str] = []
        has_code = False
        ns_open_index: list[int] = []
        ns_has_code: list[bool] = []
        for item in view.items:
            if item.kind == "directive":
                line = item.lines[0]
                inc = re.match(r'\s*#\s*include\s+"([^"]+)"', line)
                if inc and inc.group(1) in header_rename:
                    line = f'#include "{header_rename[inc.group(1)]}"'
                out_lines.append(line)
                continue
            if item.kind == "namespace_open":
                ns_open_index.append(len(out_lines))
                ns_has_code.append(False)
                out_lines.extend(item.lines)
                continue
            if item.kind == "namespace_close":
                start = ns_open_index.pop()
                if not ns_has_code.pop():
                    del out_lines[start:]
                else:
                    out_lines.extend(item.lines)
                continue
            if prune and item.guarded and id(item) not in keep_ids:
                continue
            lines = item.lines
            if remove_static and item.kind in {"function", "prototype"}:
                lines = strip_static(lines)
            if out_lines and out_lines[-1].strip():
                out_lines.append("")
            out_lines.extend(lines)
            if item.kind != "other" or item.guarded:
                has_code = True
            if ns_has_code:
                ns_has_code = [True] * len(ns_has_code)
        if view.is_header or has_code:
            pruned.append((view, out_lines))

    # neutralize identifiers in a fixed order: entry file first, then sources, then header
    entry_view = next(v for v in views if any(it is entry_item for it in v.items))
    ordered = sorted(
        pruned,
        key=lambda pair: (pair[0].is_header, pair[0] is not entry_view, pair[0].raw_path.name),
    )
    files: list[tuple[str, list[str]]] = []
    source_index = 0
    for view, lines in ordered:
        text = "\n".join(lines)
        neutral, mapping = neutralize(text, mapping)
        if view.is_header:
            name = "unit.h"
        else:
            source_index += 1
            name = neutral_name(source_index, len(ordered), ext)
        files.append((name, normalize_lines(neutral.splitlines())))

    ns = mapping.get(entry_item.namespace) if entry_item.namespace else None
    entry_call = f"{ns}::sym_0" if ns else "sym_0"
    driver = [
        "",
        "int main(int argc, char * argv[])",
        "{",
        "    srand( (unsigned)time(NULL) );",
        f"    {entry_call}();",
        "    return 0;",
        "}",
    ]
    name0, lines0 = files[0]
    files[0] = (name0, lines0 + driver)
    return Program(files, {"unit.h"} & {n for n, _ in files}, case.language, entry_call, mapping)


def neutralize(code: str, mapping: dict[str, str]) -> tuple[str, dict[str, str]]:
    """cleaning.neutralize_identifiers with the extended leakage regex.

    #include lines are left alone (std_testcase.h must still be found by the compiler; the
    local header was already renamed to unit.h).
    """
    saved_id, saved_str = cleaning._LEAKY_IDENTIFIER_RE, cleaning._STRING_TOKEN_RE
    cleaning._LEAKY_IDENTIFIER_RE, cleaning._STRING_TOKEN_RE = LEAKY_IDENTIFIER_RE, LEAKY_STRING_RE
    try:
        out = []
        for line in code.split("\n"):
            if re.match(r"\s*#\s*include\b", line):
                out.append(line)
            else:
                line, mapping = cleaning.neutralize_identifiers(line, mapping)
                out.append(line)
        return "\n".join(out), mapping
    finally:
        cleaning._LEAKY_IDENTIFIER_RE, cleaning._STRING_TOKEN_RE = saved_id, saved_str


def normalize_lines(lines: list[str]) -> list[str]:
    return cleaning._normalize_whitespace("\n".join(lines)).splitlines()


def build_model_text(program: Program) -> tuple[str, list[list]]:
    """Inline the local header once, drop quoted support includes, join parts."""
    headers = {name: lines for name, lines in program.files if name in program.header_names}
    seen: set[str] = set()
    parts: list[list[tuple[str | None, int | None, str]]] = []
    for name, lines in program.files:
        if name in program.header_names:
            continue
        part: list[tuple[str | None, int | None, str]] = []
        for lineno, line in enumerate(lines, 1):
            inc = re.match(r'\s*#\s*include\s+"([^"]+)"', line)
            if inc:
                target = inc.group(1)
                if target in headers and target not in seen:
                    seen.add(target)
                    for hno, hline in enumerate(headers[target], 1):
                        if re.match(r'\s*#\s*include\s+"', hline):
                            continue
                        part.append((target, hno, hline))
                continue
            part.append((name, lineno, line))
        parts.append(normalize_tagged(part))
    out_lines: list[str] = []
    line_map: list[list] = []
    for index, part in enumerate(parts, 1):
        if out_lines:
            out_lines.append("")
        out_lines.append(f"// ---- part {index} ----")
        for src, srcno, text in part:
            out_lines.append(text)
            line_map.append([src, srcno, len(out_lines)])
    return "\n".join(out_lines), line_map


def normalize_tagged(part: list[tuple]) -> list[tuple]:
    """Same rules as cleaning._normalize_whitespace, keeping source tags."""
    out: list[tuple] = []
    blank = 0
    for src, no, text in part:
        text = text.rstrip()
        if not text.strip():
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        out.append((src, no, text))
    while out and not out[0][2].strip():
        out.pop(0)
    while out and not out[-1][2].strip():
        out.pop()
    return out


def audit_model_text(unit_id: str, text: str) -> None:
    body = "\n".join(line for line in text.splitlines() if not line.startswith("// ---- part "))
    problems = []
    hits = {k: v for k, v in cleaning.forbidden_hits(body).items() if v}
    if hits:
        problems.append(f"forbidden {hits}")
    leak = leakage_hits(body)
    if leak:
        problems.append(f"leakage {sorted(leak)[:5]}")
    if cleaning.strip_comments(body) != body:
        problems.append("comment residue")
    if re.search(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", body, re.M):
        problems.append("conditional directive")
    if not cleaning.brace_balance(body)[0]:
        problems.append("unbalanced braces")
    if problems:
        raise RuntimeError(f"{unit_id}: model_text audit failed: {problems}")


def leakage_hits(text: str) -> set[str]:
    """Identifiers or comment text matching the leakage regex (strings were scrubbed)."""
    hits = {tok for tok in IDENT_RE.findall(code_only(text)) if LEAKAGE_TEST_RE.search(tok)}
    for comment in re.findall(r"//[^\n]*|/\*.*?\*/", code_only(text), re.S):
        if comment.startswith("// ---- part "):
            continue
        if LEAKAGE_TEST_RE.search(comment):
            hits.add(comment)
    for literal in re.findall(r'"(?:\\.|[^"\\])*"', text):
        if LEAKAGE_TEST_RE.search(literal):
            hits.add(literal)
    return hits


# ---------------------------------------------------------------- good-entry selection
def choose_good_entries(cases: dict[str, lib_juliet.TestCase], split_rows: list[dict]) -> dict[str, tuple[str, str]]:
    """group_id -> (entry name, good_kind). Seeded; ~50/50 G2B/B2G per (set, flow, mechanism)."""
    candidates: dict[str, list[str]] = {}
    for row in split_rows:
        case = cases[row["group_id"]]
        views = load_views(case, {"OMITBAD"})
        candidates[row["group_id"]] = good_entry_candidates(views, wrapper_name(case))
    strata: dict[tuple, list[str]] = defaultdict(list)
    for row in sorted(split_rows, key=lambda r: r["group_id"]):
        kinds = {entry_kind(name) for name in candidates[row["group_id"]]}
        if {"G2B", "B2G"} <= kinds:
            strata[(row["set"], row["flow_category"], row["mechanism"])].append(row["group_id"])
    kind_of: dict[str, str] = {}
    rng = random.Random(SEED)
    for key in sorted(strata):
        groups = list(strata[key])
        rng.shuffle(groups)
        half = len(groups) // 2
        extra = rng.random() < 0.5  # odd strata: coin flip for the middle group
        cut = half + (1 if (len(groups) % 2 and extra) else 0)
        for index, gid in enumerate(groups):
            kind_of[gid] = "G2B" if index < cut else "B2G"
    chosen: dict[str, tuple[str, str]] = {}
    for gid in sorted(candidates):
        rng_g = random.Random(f"{SEED}:{gid}")
        names = candidates[gid]
        if gid in kind_of:
            pool = sorted(n for n in names if entry_kind(n) == kind_of[gid])
            chosen[gid] = (rng_g.choice(pool), kind_of[gid])
        else:
            # realloc_fail and destructor groups have only good1/good2 (no G2B/B2G split)
            if any(entry_kind(n) != "other" for n in names):
                raise RuntimeError(f"{gid}: only one of G2B/B2G present: {names}")
            chosen[gid] = (rng_g.choice(sorted(names)), "other")
    return chosen


# ---------------------------------------------------------------- unit records
def write_program(unit_id: str, program: Program, root: Path) -> Path:
    pdir = root / unit_id
    if pdir.exists():
        shutil.rmtree(pdir)
    pdir.mkdir(parents=True)
    for name, lines in program.files:
        (pdir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return pdir


def make_record(row: dict, label: str, good_kind: str | None, good_entry: str | None,
                program: Program, pdir: Path, verify: dict | None) -> dict:
    unit_id = f"{row['group_id']}__{label}"
    model_text, line_map = build_model_text(program)
    audit_model_text(unit_id, model_text)
    sources = [name for name, _ in program.files if name not in program.header_names]
    sources.append(str(SUPPORT_DIR / "io.c"))
    record = {
        "unit_id": unit_id,
        **{k: row[k] for k in ("group_id", "family", "variant", "flow_category", "mechanism",
                               "language", "set", "fold")},
        "label": label,
        "truth": 1 if label == "bad" else 0,
        "good_kind": good_kind,
        "good_entry": good_entry,
        "program_dir": str(pdir),
        "build": {
            "compiler": "g++" if program.language == "cpp" else "gcc",
            "sources": sources,
            "include_dirs": [str(SUPPORT_DIR)],
            "defines": [],
            "std": "gnu++11" if program.language == "cpp" else "gnu11",
        },
        "entry": program.entry,
        "model_text": model_text,
        "line_map": line_map,
        "verify": verify or {"compile_gcc": None, "compile_clang": None, "asan_leak": None,
                             "valgrind_leak": None, "note": None},
    }
    return record


def load_verify(layer: str) -> dict[str, dict]:
    if not VERIFY_RESULTS.exists():
        return {}
    out = {}
    for line in VERIFY_RESULTS.read_text().splitlines():
        rec = json.loads(line)
        if rec["layer"] == layer:
            out[rec["unit_id"]] = rec["verify"]
    return out


def build(rows: list[dict], cases: dict, chosen: dict, out_path: Path, original_path: Path | None) -> None:
    verify_l1 = load_verify("layer1")
    verify_orig = load_verify("original")
    layer1: list[dict] = []
    original: list[dict] = []
    for row in rows:
        gid = row["group_id"]
        case = cases[gid]
        bad_views = load_views(case, {"OMITGOOD"})
        bad_prog = emit_program(case, bad_views, bad_entry_name(case), prune=True, remove_static=True)
        bad_dir = write_program(f"{gid}__bad", bad_prog, PROGRAMS_DIR)
        good_views = load_views(case, {"OMITBAD"})
        entry, kind = chosen[gid]
        good_prog = emit_program(case, good_views, entry, prune=True, remove_static=True)
        good_dir = write_program(f"{gid}__good", good_prog, PROGRAMS_DIR)
        bad_rec = make_record(row, "bad", None, None, bad_prog, bad_dir, verify_l1.get(f"{gid}__bad"))
        layer1.append(bad_rec)
        layer1.append(make_record(row, "good", kind, entry, good_prog, good_dir,
                                  verify_l1.get(f"{gid}__good")))
        if original_path is not None:
            orig_prog = emit_program(case, good_views, wrapper_name(case), prune=False, remove_static=False)
            orig_dir = write_program(f"{gid}__good", orig_prog, BUILD_DIR / "programs_original")
            orig_bad = dict(bad_rec)
            orig_bad["verify"] = verify_orig.get(f"{gid}__bad") or bad_rec["verify"]
            original.append(orig_bad)
            original.append(make_record(row, "good", "orig", wrapper_name(case), orig_prog, orig_dir,
                                        verify_orig.get(f"{gid}__good")))
    write_jsonl(out_path, layer1)
    if original_path is not None:
        write_jsonl(original_path, original)


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for rec in records:
            handle.write(json.dumps(rec, ensure_ascii=False, sort_keys=False) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"wrote {path} ({len(records)} units) sha256={digest}")


def sample_rows(rows: list[dict]) -> list[dict]:
    """>= 20 dev groups covering every dev flow category, mechanism and good kind."""
    dev = sorted((r for r in rows if r["set"] == "dev"), key=lambda r: r["group_id"])
    rng = random.Random(SEED)
    by_key: dict[tuple, list[dict]] = defaultdict(list)
    for row in dev:
        by_key[(row["flow_category"], row["mechanism"], row["variant"])].append(row)
    picked: dict[str, dict] = {}
    for key in sorted(by_key):
        picked[rng.choice(by_key[key])["group_id"]] = None
    # top up to 24 groups
    pool = [r for r in dev if r["group_id"] not in picked]
    rng.shuffle(pool)
    for row in pool[: max(0, 24 - len(picked))]:
        picked[row["group_id"]] = None
    return [r for r in dev if r["group_id"] in picked]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-only", action="store_true")
    args = parser.parse_args()
    split = json.loads(SPLIT_PATH.read_text())
    rows = sorted(split["groups"], key=lambda r: r["group_id"])
    cases = {c.group_id: c for c in lib_juliet.discover_groups()}
    missing = [r["group_id"] for r in rows if r["group_id"] not in cases]
    if missing:
        raise SystemExit(f"groups missing from raw data: {missing[:5]}")
    chosen = choose_good_entries(cases, rows)
    (BUILD_DIR).mkdir(parents=True, exist_ok=True)
    (BUILD_DIR / "good_entries.json").write_text(
        json.dumps({gid: {"entry": e, "good_kind": k} for gid, (e, k) in sorted(chosen.items())}, indent=1)
        + "\n"
    )
    sample = sample_rows(rows)
    build(sample, cases, chosen, BUILD_DIR / "layer1_sample.jsonl", None)
    if args.sample_only:
        return
    build(rows, cases, chosen, BUILD_DIR / "layer1.jsonl", BUILD_DIR / "original.jsonl")
    table = Counter((r["flow_category"], chosen[r["group_id"]][1]) for r in rows)
    print("good_kind per flow_category:", dict(sorted(table.items())))


if __name__ == "__main__":
    main()
