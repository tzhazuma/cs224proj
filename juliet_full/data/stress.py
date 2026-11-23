#!/usr/bin/env python3
"""Layer 3 (stress) and placebo transforms of the layer-1 units (PLAN 2.5).

Stress: every real free/delete in a unit is wrapped in an always-true guard; every Juliet
flaw site (the empty statement `;` that stands where the good sink frees) is replaced by a
dead free under an always-false guard; `extra` more dead frees go next to the anchor (the
first flaw site / real free of the target pointer; for realloc_fail right after the realloc,
freeing its result). Guards test file-local constants `static const int sym_N = V;`.
The free-statement count is equal inside every bad/good pair (so its distribution matches):
  c_alloc / cpp_new / destructor: bad = 1 site + e dead, B2G good = 1 real + e dead,
  G2B good = 1 site + e dead; realloc_fail / virtual_destructor (no flaw site in either
  label): 1 + e dead in both, plus the real frees both labels already have; e in {0, 1}
  is drawn per group with the seed.
Placebo: the same guards at the same places, but each dead statement is a printLine call;
real frees stay unwrapped.

Guard pool (shared by both labels): forms `== 5`, `> 4`, `!= 4`, `!= 5`, `< 5`, `== 4`.
GUARD_VALUES = (5,) gives the PLAN form (true guards ==5/>4/!=4, false guards !=5/<5/==4);
the build uses (4, 5): the constant's value is 4 or 5, so every form occurs as a true and a
false guard and only the constant's definition decides it (see README, layer 3).

API (no side effects on import):
  transform_unit(record, kind="stress", seed=SEED, n_dead=None) -> new record
  transform_source(code, language, func=None, ...) -> (new_code, info)
CLI:
  python3 stress.py build                     # build/layer3.jsonl, build/placebo.jsonl
  python3 stress.py demo --unit-id X --kind stress   # print the model_text diff
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import random
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
BUILD = DATA_DIR / "build"
sys.path.insert(0, str(DATA_DIR))
import build_units  # noqa: E402

SEED = 20261123
KINDS = ("stress", "placebo")
GUARD_VALUES: tuple[int, ...] = (4, 5)
FORMS = [("==", 5), (">", 4), ("!=", 4), ("!=", 5), ("<", 5), ("==", 4)]
PLACEBO_STRINGS = ["Processing", "Value checked", "Status ok", "Step complete"]
OUTPUTS = {"stress": ("layer3.jsonl", "programs_layer3", "verify_layer3.jsonl"),
           "placebo": ("placebo.jsonl", "programs_placebo", "verify_layer3.jsonl")}
LAYER_NAME = {"stress": "layer3", "placebo": "placebo"}

FREE_RE = re.compile(
    r"^(?P<ind>\s*)(?:free\s*\(\s*(?P<farg>[\w>.-]+)\s*\)|delete\s*(?P<arr>\[\s*\])?\s*(?P<darg>[\w>.-]+))\s*;\s*$")
EMPTY_RE = re.compile(r"^(?P<ind>\s*);\s*$")
REALLOC_RE = re.compile(r"\b(?P<lhs>\w+)\s*=\s*\([^()]*\)\s*realloc\s*\(\s*(?P<arg>\w+)\s*,")
DTOR_RE = re.compile(r"~\w+\s*\(\s*\)\s*$")
SYM_RE = re.compile(r"\bsym_(\d+)\b")
NAME_RANGE = (10, 100)  # guard constants get sym_10 .. sym_99 (layer-1 units use sym_0 .. sym_6)


@dataclass
class Guard:
    name: str
    value: int
    op: str
    const: int
    truth: bool


def holds(value: int, op: str, const: int) -> bool:
    return {"==": value == const, "!=": value != const, "<": value < const, ">": value > const}[op]


def draw_guard(rng: random.Random, truth: bool, name: str, values: tuple[int, ...]) -> Guard:
    if values == (5,):
        op, const = rng.choice([f for f in FORMS if holds(5, *f) == truth])
        return Guard(name, 5, op, const, truth)
    op, const = rng.choice(FORMS)
    value = next(v for v in values if holds(v, op, const) == truth)
    return Guard(name, value, op, const, truth)


def guard_block(indent: str, guard: Guard, stmt: str) -> list[str]:
    return [f"{indent}if({guard.name} {guard.op} {guard.const})", f"{indent}{{", f"{indent}    {stmt}", f"{indent}}}"]


def _code(line: str) -> str:
    """Line without string contents and single-line comments (layer-1 units have no comments;
    raw Juliet input for transform_source does)."""
    return re.sub(r"/\*.*?\*/|//.*$", "", build_units.code_only(line))


def free_arg(line: str) -> str | None:
    m = FREE_RE.match(_code(line))
    return None if m is None else (m.group("farg") or m.group("darg"))


def dead_free_stmt(pointer: str, form: str) -> str:
    return {"free": f"free({pointer});", "delete": f"delete {pointer};", "delete[]": f"delete [] {pointer};"}[form]


def infer_free_form(lines: list[str], pointer: str, language: str) -> str:
    for line in lines:
        m = FREE_RE.match(_code(line))
        if m and (m.group("farg") or m.group("darg")) == pointer:
            return "free" if m.group("farg") else ("delete[]" if m.group("arr") else "delete")
    for line in lines:
        code = _code(line)
        m = re.search(rf"\b{re.escape(pointer)}\s*=\s*(?:\([^()]*\)\s*)?(new\b[^;\[]*(\[)?|\w+\s*\()", code)
        if m:
            if m.group(1).startswith("new"):
                return "delete[]" if m.group(2) else "delete"
            return "free"
    return "delete" if language == "cpp" else "free"


def unit_free_form(record: dict) -> str:
    if record["mechanism"] in {"c_alloc", "realloc_fail"}:
        return "free"
    if record["mechanism"] == "destructor":
        return "delete[]"
    return "delete[]" if record["family"].startswith("new_array") else "delete"


# ---------------------------------------------------------------- core engine
@dataclass
class Edit:
    file: int
    line: int  # 0-based line index in that file
    action: str  # wrap | replace | before | after | into
    guard: Guard
    stmt: str
    role: str  # real | site | extra


def braced_context(lines: list[str], index: int) -> bool:
    """The statement at `index` sits directly in a { } block (previous code line ends a statement or block)."""
    for j in range(index - 1, -1, -1):
        prev = _code(lines[j]).strip()
        if prev:
            return prev.endswith(("{", ";", "}", ":"))
    return True


def find_sites(files: list[list[str]]) -> tuple[list[tuple[int, int]], list[tuple[int, int, str]]]:
    """(flaw sites `;`, real frees (file, line, pointer)) in file/line order."""
    sites, frees = [], []
    for f, lines in enumerate(files):
        for i, line in enumerate(lines):
            if EMPTY_RE.match(_code(line)):
                sites.append((f, i))
            else:
                arg = free_arg(line)
                if arg is not None:
                    frees.append((f, i, arg))
    return sites, frees


def empty_destructor(files: list[list[str]]) -> tuple[int, int] | None:
    """(file, index of `{`) of a destructor whose body is empty."""
    for f, lines in enumerate(files):
        for i, line in enumerate(lines[:-1]):
            if DTOR_RE.search(_code(line)) and lines[i + 1].strip() == "{":
                j = i + 2
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and lines[j].strip() == "}":
                    return f, i + 1
    return None


def pick_pointer(files: list[list[str]], frees: list[tuple[int, int, str]], realloc_line: tuple | None) -> str:
    if realloc_line is not None:
        return realloc_line[2]
    text = "\n".join(_code("\n".join(lines)) for lines in files)
    if re.search(r"\bdata\b", text):
        return "data"
    if frees:
        return frees[0][2]
    m = re.search(r"this->(\w+)\s*=\s*new\b", text)
    if m:
        return m.group(1)
    raise ValueError("cannot determine the pointer to free: no `data`, no free/delete, no `this->x = new`")


def find_realloc(files: list[list[str]]) -> tuple[int, int, str] | None:
    for f, lines in enumerate(files):
        for i, line in enumerate(lines):
            m = REALLOC_RE.search(_code(line))
            if m and m.group("arg") != "NULL":
                return f, i, m.group("lhs")
    return None


def plan_and_apply(files: list[list[str]], *, kind: str, rng_group: random.Random, rng_guard: random.Random,
                   language: str, free_form: str | None, pointer: str | None, n_dead: int | None,
                   base_dead: int, realloc_anchor: bool, values: tuple[int, ...], sym_start: int | None,
                   scope: list[tuple[int, int, int]] | None = None) -> tuple[list[list[str]], dict]:
    """Rewrite `files` (lists of lines). `scope` = [(file, first, last)] restricts the edits."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, got {kind!r}")

    def in_scope(f: int, i: int) -> bool:
        return scope is None or any(f == sf and a <= i <= b for sf, a, b in scope)

    sites, frees = find_sites(files)
    sites = [s for s in sites if in_scope(*s)]
    frees = [fr for fr in frees if in_scope(fr[0], fr[1])]
    realloc_line = find_realloc(files) if realloc_anchor else None
    if realloc_anchor and realloc_line is None:
        raise ValueError("realloc anchor requested but no `x = (T *)realloc(p, ...)` statement found")
    pointer = pointer or pick_pointer(files, frees, realloc_line)
    form = free_form or infer_free_form([l for lines in files for l in lines], pointer, language)
    into_site = None
    if not sites and not any(arg == pointer for _, _, arg in frees) and realloc_line is None:
        into_site = empty_destructor(files)
    n_sites = len(sites) + (1 if into_site else 0)

    extra = int(rng_group.random() < 0.5)  # e in {0, 1}, shared by the group
    position = rng_group.choice(["before", "after"])
    if n_dead is None:
        n_dead = n_sites + base_dead + extra
    if n_dead < n_sites:
        raise ValueError(f"n_dead={n_dead} is smaller than the number of flaw sites ({n_sites}) to replace")
    n_extra = n_dead - n_sites

    # anchor for the extra dead statements
    if realloc_line is not None:
        anchor, anchor_pos = (realloc_line[0], realloc_line[1]), "after"
    elif sites:
        anchor, anchor_pos = sites[0], position
    elif any(arg == pointer for _, _, arg in frees):
        f, i, _ = next(fr for fr in frees if fr[2] == pointer)
        anchor, anchor_pos = (f, i), position
    elif into_site is not None:
        anchor, anchor_pos = into_site, "into"
    elif n_extra:
        raise ValueError(f"no anchor: no flaw site, no free of {pointer!r}, no realloc, no empty destructor")
    else:
        anchor, anchor_pos = None, None
    if anchor is not None and anchor_pos in {"before", "after"} and not braced_context(files[anchor[0]], anchor[1]):
        raise ValueError(f"anchor statement at file {anchor[0]} line {anchor[1] + 1} is not inside a braced block")

    # guard names: random unused sym_N from a fixed range, so they do not track how many
    # identifiers the unit already has (sequential names separated B2G bad/good on dev)
    used = {int(n) for lines in files for line in lines for n in SYM_RE.findall(line)}
    low = max(NAME_RANGE[0], max(used, default=-1) + 1) if sym_start is None else sym_start
    free_names = [n for n in range(low, low + NAME_RANGE[1] - NAME_RANGE[0]) if n not in used]
    if sym_start is None:
        rng_guard.shuffle(free_names)
    names = iter(free_names)

    def new_guard(truth: bool) -> Guard:
        return draw_guard(rng_guard, truth, f"sym_{next(names)}", values)

    def dead_stmt() -> str:
        if kind == "stress":
            return dead_free_stmt(pointer, form)
        return f'printLine("{rng_guard.choice(PLACEBO_STRINGS)}");'

    edits: list[Edit] = []
    events = sorted([("site", s[0], s[1]) for s in sites] + [("real", f, i) for f, i, _ in frees]
                    + ([("into", *into_site)] if into_site else []), key=lambda e: (e[1], e[2]))
    for role, f, i in events:
        if role == "real":
            if kind == "stress":
                edits.append(Edit(f, i, "wrap", new_guard(True), files[f][i].strip(), "real"))
        elif role == "site":
            edits.append(Edit(f, i, "replace", new_guard(False), dead_stmt(), "site"))
        else:
            edits.append(Edit(f, i, "into", new_guard(False), dead_stmt(), "site"))
        if anchor == (f, i) and n_extra:
            for _ in range(n_extra):
                edits.append(Edit(f, i, anchor_pos if anchor_pos != "into" else "into", new_guard(False),
                                  dead_stmt(), "extra"))
    if anchor is not None and n_extra and not any(e.role == "extra" for e in edits):
        f, i = anchor  # realloc anchor is not itself an event
        for _ in range(n_extra):
            edits.append(Edit(f, i, anchor_pos, new_guard(False), dead_stmt(), "extra"))

    # apply
    new_files: list[list[str]] = []
    placed: list[tuple[Edit, int, int]] = []  # (edit, file, 0-based index of `if(` line in new file)
    guards_per_file: dict[int, list[Guard]] = {}
    for e in edits:
        guards_per_file.setdefault(e.file, []).append(e.guard)
    for f, lines in enumerate(files):
        by_line: dict[int, list[Edit]] = {}
        for e in edits:
            if e.file == f:
                by_line.setdefault(e.line, []).append(e)
        decl_at = decl_index(lines) if f in guards_per_file else None
        out: list[str] = []
        for i, line in enumerate(lines):
            if decl_at == i:
                out.extend(["", *[f"static const int {g.name} = {g.value};" for g in guards_per_file[f]]])
            here = by_line.get(i, [])
            indent = re.match(r"\s*", line).group(0)
            for e in [e for e in here if e.action == "before"]:
                placed.append((e, f, len(out)))
                out.extend(guard_block(indent, e.guard, e.stmt))
            main = [e for e in here if e.action in {"wrap", "replace"}]
            if main:
                e = main[0]
                placed.append((e, f, len(out)))
                out.extend(guard_block(indent, e.guard, e.stmt))
            else:
                out.append(line)
            for e in [e for e in here if e.action == "after"]:
                placed.append((e, f, len(out)))
                out.extend(guard_block(indent, e.guard, e.stmt))
            into = [e for e in here if e.action == "into"]
            for e in into:
                placed.append((e, f, len(out)))
                out.extend(guard_block(indent + "    ", e.guard, e.stmt))
        if decl_at == len(lines):
            out.extend(["", *[f"static const int {g.name} = {g.value};" for g in guards_per_file[f]]])
        new_files.append(out)
    info = {
        "kind": kind,
        "pointer": pointer,
        "free_form": form,
        "n_dead": n_dead,
        "n_sites": n_sites,
        "extra": n_extra,
        "position": anchor_pos,
        "guards": [asdict(e.guard) for e in edits],
        "placed": [(e, f, idx) for e, f, idx in placed],
        "n_guarded_frees": sum(1 for e in edits if kind == "stress" and e.role in {"real", "site", "extra"}),
    }
    return new_files, info


def decl_index(lines: list[str]) -> int:
    """Index after the leading block of preprocessor lines (0 if there is none).

    Comment lines are skipped (raw Juliet input); the block ends at the first code line or at the
    first conditional (`#if...`), so the declarations never land inside an OMITBAD/OMITGOOD region.
    """
    last = -1
    in_comment = False
    for i, line in enumerate(lines):
        s = line.strip()
        if in_comment or s.startswith(("/*", "//")):
            in_comment = (in_comment or s.startswith("/*")) and "*/" not in s
            continue
        if s.startswith("#if"):
            break
        if s.startswith("#"):
            last = i
        elif s:
            break
    return last + 1


def _placed_json(info: dict, locate) -> tuple[list[dict], list[dict]]:
    """`line`/`file_line` point at the guarded statement, `guard_line` at its `if(` line."""
    inserted, wrapped = [], []
    for e, f, idx in info.pop("placed"):
        where = locate(f, idx + 2)  # guard_block: if(, {, stmt, }
        entry = {**where, "guard_line": locate(f, idx)["line"], "stmt": e.stmt, "guard": e.guard.name}
        if e.role == "real":
            wrapped.append(entry)
        else:
            inserted.append({**entry, "role": e.role, "reachable": False})
    return inserted, wrapped


# ---------------------------------------------------------------- public API
def transform_source(code: str, language: str, func: str | None = None, *, kind: str = "stress",
                     seed: int = SEED, n_dead: int | None = None, pointer: str | None = None,
                     free_form: str | None = None, values: tuple[int, ...] = GUARD_VALUES,
                     realloc_anchor: bool = False, sym_start: int | None = None) -> tuple[str, dict]:
    """Transform one C/C++ file (best effort). `func` restricts the edits to that function.

    Returns (new_code, info); info["inserted"]/["wrapped_real_frees"] use 1-based lines of new_code.
    Raises ValueError when no anchor, pointer or function can be found.
    """
    if language not in {"c", "cpp"}:
        raise ValueError("language must be 'c' or 'cpp'")
    lines = code.split("\n")
    scope = None
    if func is not None:
        span = function_span(lines, func)
        scope = [(0, span[0], span[1])]
    rng = random.Random(f"{seed}:source:{kind}")
    new_files, info = plan_and_apply([lines], kind=kind, rng_group=rng, rng_guard=rng, language=language,
                                     free_form=free_form, pointer=pointer, n_dead=n_dead,
                                     base_dead=0 if n_dead is not None else 1, realloc_anchor=realloc_anchor,
                                     values=values, sym_start=sym_start, scope=scope)
    inserted, wrapped = _placed_json(info, lambda f, idx: {"line": idx + 1})
    info.update(inserted=inserted, wrapped_real_frees=wrapped, seed=seed)
    return "\n".join(new_files[0]), info


def function_span(lines: list[str], func: str) -> tuple[int, int]:
    pattern = re.compile(rf"(^|[\s*&:]){re.escape(func)}\s*\([^;]*$")
    for i, line in enumerate(lines):
        if pattern.search(_code(line)):
            j = i
            while j < len(lines) and "{" not in _code(lines[j]):
                if ";" in _code(lines[j]):
                    break
                j += 1
            if j >= len(lines) or "{" not in _code(lines[j]):
                continue
            depth = 0
            for k in range(j, len(lines)):
                depth += _code(lines[k]).count("{") - _code(lines[k]).count("}")
                if depth == 0:
                    return i, k
    raise ValueError(f"function {func!r} not found (need a definition with its body)")


def program_files(record: dict) -> list[tuple[str, list[str]]]:
    pdir = Path(record["program_dir"])
    names = [s for s in record["build"]["sources"] if not s.startswith("/")]
    if (pdir / "unit.h").exists():
        names.append("unit.h")
    return [(n, (pdir / n).read_text(encoding="utf-8").rstrip("\n").split("\n")) for n in names]


def transform_unit(record: dict, kind: str = "stress", seed: int = SEED, n_dead: int | None = None,
                   values: tuple[int, ...] = GUARD_VALUES) -> dict:
    """New record (layer-1 schema + `transform`, `program_files`); reads record["program_dir"] only."""
    files = program_files(record)
    names = [n for n, _ in files]
    no_site_family = record["mechanism"] == "realloc_fail" or record["family"] == "virtual_destructor"
    rng_group = random.Random(f"{seed}:{record['group_id']}")
    rng_guard = random.Random(f"{seed}:{record['unit_id']}:guards")
    new_files, info = plan_and_apply(
        [lines for _, lines in files], kind=kind, rng_group=rng_group, rng_guard=rng_guard,
        language=record["language"], free_form=unit_free_form(record), pointer=None, n_dead=n_dead,
        base_dead=1 if no_site_family else 0, realloc_anchor=record["mechanism"] == "realloc_fail",
        values=values, sym_start=None)
    program = build_units.Program(
        files=list(zip(names, new_files)), header_names={"unit.h"} & set(names), language=record["language"],
        entry=record["entry"], mapping={})
    model_text, line_map = build_units.build_model_text(program)
    build_units.audit_model_text(record["unit_id"], model_text)
    to_model = {(src, no): m for src, no, m in line_map}

    def locate(f: int, idx: int) -> dict:
        return {"line": to_model.get((names[f], idx + 1)), "file": names[f], "file_line": idx + 1}

    inserted, wrapped = _placed_json(info, locate)
    new = dict(record)
    new["model_text"] = model_text
    new["line_map"] = line_map
    new["verify"] = {"compile_gcc": None, "compile_clang": None, "asan_leak": None, "valgrind_leak": None,
                     "note": None}
    new["transform"] = {
        "kind": kind,
        "guards": info["guards"],
        "inserted": inserted,
        "wrapped_real_frees": wrapped,
        "seed": seed,
        "guard_values": list(values),
        "pointer": info["pointer"],
        "dead_stmt_form": info["free_form"] if kind == "stress" else "printLine",
        "n_dead": info["n_dead"],
        "n_flaw_sites": info["n_sites"],
        "extra_position": info["position"],
    }
    new["program_files"] = {n: "\n".join(lines) + "\n" for n, lines in zip(names, new_files)}
    return new


# ---------------------------------------------------------------- build / demo
def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def build(kinds: tuple[str, ...] = KINDS, values: tuple[int, ...] = GUARD_VALUES, only_set: str | None = None,
          out_suffix: str = "") -> None:
    layer1 = load_jsonl(BUILD / "layer1.jsonl")
    if only_set:
        layer1 = [r for r in layer1 if r["set"] == only_set]
    verify_path = BUILD / "verify_layer3.jsonl"
    verify = {}
    if verify_path.exists() and not out_suffix:
        for line in verify_path.read_text().splitlines():
            r = json.loads(line)
            verify[(r["layer"], r["unit_id"])] = r["verify"]
    for kind in kinds:
        jsonl, progdir, _ = OUTPUTS[kind]
        root = BUILD / (progdir + out_suffix)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        records = []
        for rec in layer1:
            new = transform_unit(rec, kind=kind, values=values)
            pdir = root / rec["unit_id"]
            pdir.mkdir()
            for name, text in new.pop("program_files").items():
                (pdir / name).write_text(text, encoding="utf-8")
            new["program_dir"] = str(pdir)
            new["verify"] = verify.get((LAYER_NAME[kind], rec["unit_id"]), new["verify"])
            records.append(new)
        out = BUILD / (jsonl.replace(".jsonl", out_suffix + ".jsonl"))
        build_units.write_jsonl(out, records)


def demo(unit_id: str, kind: str, seed: int, n_dead: int | None) -> None:
    rec = next((r for r in load_jsonl(BUILD / "layer1.jsonl") if r["unit_id"] == unit_id), None)
    if rec is None:
        raise SystemExit(f"unknown unit_id {unit_id}")
    new = transform_unit(rec, kind=kind, seed=seed, n_dead=n_dead)
    sys.stdout.writelines(difflib.unified_diff(rec["model_text"].splitlines(True), new["model_text"].splitlines(True),
                                               "layer1/" + unit_id, f"{kind}/" + unit_id))
    print()
    print(json.dumps({k: v for k, v in new["transform"].items()}, indent=1))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--values", default=",".join(map(str, GUARD_VALUES)), help="guard constant values, e.g. 5 or 4,5")
    b.add_argument("--set", dest="only_set", default=None, help="only this split set (dev) -> *_<suffix> files")
    b.add_argument("--suffix", default="", help="suffix for output files/dirs (experiments)")
    d = sub.add_parser("demo")
    d.add_argument("--unit-id", required=True)
    d.add_argument("--kind", choices=KINDS, default="stress")
    d.add_argument("--seed", type=int, default=SEED)
    d.add_argument("--n-dead", type=int, default=None)
    args = parser.parse_args()
    if args.cmd == "build":
        values = tuple(int(v) for v in args.values.split(","))
        build(values=values, only_set=args.only_set, out_suffix=args.suffix)
    else:
        demo(args.unit_id, args.kind, args.seed, args.n_dead)


if __name__ == "__main__":
    main()
