"""Dead-free insertion for the live demo ("attack" step).

The edit: a file-scope constant plus a never-executed release of the allocated pointer, right after the
allocation statement, e.g.

    static const int sym_k = 5;          (after the last #include of the file)
    ...
    data = (int *)malloc(100*sizeof(int));
    if (sym_k != 5) free(data);          (C: free, C++: delete / delete [] matching the new)

The guard is always false and decidable inside the file, so the program still leaks (truth unchanged).

`transformer(name)` returns the function the demo uses:
- "stress": `juliet_full/data/stress.py:transform_unit` (data lane, the layer-3 transform of the experiments),
  used when it exists and returns a record whose model_text changed; its `program_files` are written to a
  scratch copy of program_dir (the data lane's function only reads program_dir);
- "local": `transform_unit` below (same signature), the fallback;
- "auto": stress when usable, else local.
Both return a new unit record (schema of juliet_full/README.md section 3) with an extra "transform" dict
({"inserter", "kind", "sites": [...], ...}); the input record is not modified.
"""

from __future__ import annotations

import copy
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "juliet_full" / "data"
SCRATCH_ROOT = Path(tempfile.gettempdir()) / "cs224_demo"

C_ALLOC_RE = re.compile(
    r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][\w\s\*\.\->\[\]]*?)\s*=\s*(?:\([^()]*\)\s*)?"
    r"(?P<fn>malloc|calloc|realloc|strdup|wcsdup|_strdup|_wcsdup)\s*\(")
NEW_RE = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][\w\s\*\.\->\[\]:<>]*?)\s*=\s*new\b(?P<rest>.*)$")
DECL_LHS_RE = re.compile(r"^(?:[A-Za-z_][\w:<>]*[\s\*]+)+(?P<name>[A-Za-z_]\w*)$")  # `struct T * data`
INCLUDE_RE = re.compile(r"^\s*#\s*include\b")
PART_RE = re.compile(r"^// ---- part \d+ ----$")


class InsertError(ValueError):
    pass


def pointer_expr(lhs: str) -> str:
    """`int * data` (declaration) -> `data`; `data`, `*p`, `s.ptr` stay as written."""
    lhs = " ".join(lhs.split())
    match = DECL_LHS_RE.match(lhs)
    return match.group("name") if match else lhs


def find_alloc_sites(lines: list[str], language: str) -> list[dict[str, Any]]:
    """Heap allocation statements: [{"line": 0-based index of the statement's last line, "indent", "release"}]."""
    sites = []
    i = 0
    while i < len(lines):
        line = lines[i]
        release = None
        match = C_ALLOC_RE.match(line)
        if match:
            release = f"free({pointer_expr(match.group('lhs'))});"
        elif language == "cpp":
            match = NEW_RE.match(line)
            if match:
                statement = match.group("rest").split(";")[0]
                array = "[" in statement.split("(")[0]
                release = f"delete{' []' if array else ''} {pointer_expr(match.group('lhs'))};"
        if match and release:
            end = i
            while ";" not in lines[end] and end + 1 < len(lines):
                end += 1
            sites.append({"line": end, "alloc_line": i, "indent": match.group("indent"), "release": release,
                          "statement": line.strip()})
            i = end + 1
            continue
        i += 1
    return sites


def fresh_name(text: str, base: str = "sym_k") -> str:
    name, n = base, 1
    while re.search(rf"\b{re.escape(name)}\b", text):
        n += 1
        name = f"{base}{n}"
    return name


def part_bounds(lines: list[str], index: int) -> tuple[int, int]:
    """[start, end) of the model_text part (// ---- part i ----) containing line `index`."""
    start = 0
    for j in range(index, -1, -1):
        if PART_RE.match(lines[j]):
            start = j
            break
    end = len(lines)
    for j in range(index + 1, len(lines)):
        if PART_RE.match(lines[j]):
            end = j
            break
    return start, end


def plan_insertions(text: str, language: str, kind: str = "stress", seed: int | None = None,
                    n_dead: int | None = None) -> tuple[list[tuple[int, str, list[str]]], dict[str, Any]]:
    """Insertions as (0-based anchor line, "after"|"before", new lines) on `text`, plus info."""
    if kind not in ("stress", "placebo"):
        raise ValueError(f"unknown kind {kind}")
    lines = text.split("\n")
    sites = find_alloc_sites(lines, language)
    if not sites:
        raise InsertError("no heap allocation (malloc/calloc/realloc/strdup/new) found")
    if n_dead is not None:
        sites = sites[:n_dead]
    value = 5 if seed is None else random.Random(seed).randint(2, 9)
    name = fresh_name(text)
    insertions: list[tuple[int, str, list[str]]] = []
    decl_parts: set[int] = set()
    for site in sites:
        start, end = part_bounds(lines, site["line"])
        if start not in decl_parts:
            decl_parts.add(start)
            includes = [j for j in range(start, end) if INCLUDE_RE.match(lines[j])]
            decl = [f"static const int {name} = {value};"]
            if includes:
                insertions.append((includes[-1], "after", decl))
            else:
                first = start + 1 if PART_RE.match(lines[start]) else start
                insertions.append((first, "before", decl))
        body = site["release"] if kind == "stress" else "printIntLine(0);"
        site["inserted"] = f"{site['indent']}if ({name} != {value}) {body}"
        insertions.append((site["line"], "after", [site["inserted"]]))
    info = {"kind": kind, "guard_name": name, "guard_value": value,
            "sites": [{k: s[k] for k in ("statement", "inserted")} for s in sites]}
    return insertions, info


def apply_insertions(lines: list[str], insertions: list[tuple[int, str, list[str]]]) \
        -> tuple[list[str], list[int], list[list[int]]]:
    """New lines, the new 0-based index of every old line, and the new 0-based indices of each insertion."""
    before: dict[int, list[int]] = {}
    after: dict[int, list[int]] = {}
    for k, (anchor, where, _) in enumerate(insertions):
        (after if where == "after" else before).setdefault(anchor, []).append(k)
    out: list[str] = []
    new_index: list[int] = []
    placed: list[list[int]] = [[] for _ in insertions]

    def emit(ks: list[int]) -> None:
        for k in ks:
            for new_line in insertions[k][2]:
                placed[k].append(len(out))
                out.append(new_line)

    for i, line in enumerate(lines):
        emit(before.get(i, []))
        new_index.append(len(out))
        out.append(line)
        emit(after.get(i, []))
    return out, new_index, placed


def transform_source(code: str, language: str, func: str | None = None, kind: str = "stress",
                     seed: int | None = None, n_dead: int | None = None) -> tuple[str, dict[str, Any]]:
    """Single source text version (same interface as the data lane's stress.transform_source).

    `func` is accepted for interface compatibility; the local inserter always uses the allocating function."""
    insertions, info = plan_insertions(code, language, kind, seed, n_dead)
    new_lines, _, _ = apply_insertions(code.split("\n"), insertions)
    return "\n".join(new_lines), {**info, "inserter": "local", "func": func}


def transform_unit(record: dict[str, Any], kind: str = "stress", seed: int | None = None,
                   n_dead: int | None = None, out_root: Path | None = None) -> dict[str, Any]:
    """Edit model_text and the program_dir sources consistently (via line_map); return the new record."""
    text = record["model_text"]
    lines = text.split("\n")
    insertions, info = plan_insertions(text, record["language"], kind, seed, n_dead)
    new_lines, new_index, model_placed = apply_insertions(lines, insertions)

    # model_text line (1-based) -> (source file, source line); every anchor must be mapped
    by_model = {int(m): (str(s), int(sl)) for s, sl, m in record.get("line_map") or []}
    source_edits: dict[str, list[tuple[int, str, list[str]]]] = {}
    edit_slot: list[tuple[str, int]] = []  # insertion k -> (source file, index in source_edits[file])
    for anchor, where, new in insertions:
        if anchor + 1 not in by_model:
            raise InsertError(f"model_text line {anchor + 1} is not in line_map")
        source_file, source_line = by_model[anchor + 1]
        edit_slot.append((source_file, len(source_edits.get(source_file, []))))
        source_edits.setdefault(source_file, []).append((source_line - 1, where, new))

    program_dir = Path(record["program_dir"])
    root = Path(out_root or SCRATCH_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    new_dir = Path(tempfile.mkdtemp(prefix=f"{program_dir.name}__{kind}_", dir=root))
    shutil.copytree(program_dir, new_dir, dirs_exist_ok=True)
    source_shift: dict[str, list[int]] = {}
    source_placed: dict[str, list[list[int]]] = {}
    for source_file, edits in source_edits.items():
        path = Path(source_file) if Path(source_file).is_absolute() else new_dir / source_file
        if program_dir in path.parents:
            path = new_dir / path.relative_to(program_dir)
        if new_dir not in path.parents:
            raise InsertError(f"{source_file} is outside program_dir")
        src_lines = path.read_text(errors="replace").split("\n")
        edited, shift, placed = apply_insertions(src_lines, edits)
        path.write_text("\n".join(edited))
        source_shift[source_file] = shift
        source_placed[source_file] = placed

    line_map = []
    for source_file, source_line, model_line in record.get("line_map") or []:
        shift = source_shift.get(str(source_file))
        new_source_line = shift[source_line - 1] + 1 if shift else source_line
        line_map.append([source_file, new_source_line, new_index[model_line - 1] + 1])
    for k, (source_file, slot) in enumerate(edit_slot):
        for model_at, src_at in zip(model_placed[k], source_placed[source_file][slot]):
            line_map.append([source_file, src_at + 1, model_at + 1])
    line_map.sort(key=lambda row: row[2])

    out = copy.deepcopy(record)
    out.update({"unit_id": f"{record['unit_id']}__{kind}", "model_text": "\n".join(new_lines),
                "program_dir": str(new_dir), "line_map": line_map,
                "transform": {**info, "inserter": "local", "source_unit_id": record["unit_id"],
                              "inserted_model_lines": sorted(i + 1 for ks in model_placed for i in ks)}})
    return out


def _stress_transform() -> Callable[..., dict[str, Any]] | None:
    if not (DATA_DIR / "stress.py").exists():
        return None
    if str(DATA_DIR) not in sys.path:
        sys.path.insert(0, str(DATA_DIR))
    try:
        import stress  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - any import problem means: use the local inserter
        return None
    func = getattr(stress, "transform_unit", None)
    return func if callable(func) else None


def transformer(name: str = "auto") -> tuple[str, Callable[..., dict[str, Any]]]:
    """(inserter name actually used, transform_unit-compatible function)."""
    if name == "local":
        return "local", transform_unit
    stress_func = _stress_transform()
    if stress_func is None:
        if name == "stress":
            raise InsertError("juliet_full/data/stress.py:transform_unit is not available")
        return "local", transform_unit

    def via_stress(record: dict[str, Any], kind: str = "stress", seed: int | None = None,
                   n_dead: int | None = None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"kind": kind, "n_dead": n_dead}
        if seed is not None:
            kwargs["seed"] = seed
        try:
            out = stress_func(record, **kwargs)
            usable = (isinstance(out, dict) and bool(out.get("model_text"))
                      and out["model_text"] != record["model_text"] and isinstance(out.get("program_files"), dict))
            reason = "stress.transform_unit left model_text unchanged or returned no program_files"
        except Exception as exc:  # noqa: BLE001
            if name == "stress":
                raise
            usable, reason = False, f"stress.transform_unit failed: {exc!r}"[:200]
        if usable:
            out = dict(out)
            program_dir = Path(record["program_dir"])
            SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
            new_dir = Path(tempfile.mkdtemp(prefix=f"{program_dir.name}__{kind}_", dir=SCRATCH_ROOT))
            shutil.copytree(program_dir, new_dir, dirs_exist_ok=True)
            for file_name, text in out.pop("program_files").items():
                (new_dir / file_name).write_text(text, encoding="utf-8")
            out["program_dir"] = str(new_dir)
            out["unit_id"] = f"{record['unit_id']}__{kind}"
            out["transform"] = {**out.get("transform", {}), "inserter": "stress",
                                "source_unit_id": record["unit_id"]}
            return out
        if name == "stress":
            raise InsertError(reason)
        local = transform_unit(record, kind=kind, seed=seed, n_dead=n_dead)
        local["transform"]["fallback_reason"] = reason
        return local

    return "stress" if name == "stress" else "auto", via_stress
