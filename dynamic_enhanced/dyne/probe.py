"""Generate an evaluator-side probe main that calls the raw bad/good entry.

The probe is the same for every mode of a unit, so the bad and good binaries
differ only in the -DOMITGOOD/-DOMITBAD define.  No label information is used
beyond choosing which entry the probe calls, and that choice is fixed by the
frozen unit record, not by the observed result.
"""

from __future__ import annotations

import re
from pathlib import Path

from .units import Unit

FUNC_DEF = re.compile(
    r"^\s*(?:static\s+)?(?:void)\s+([A-Za-z_]\w*(?:::\w+)?)\s*\(\s*(?:void)?\s*\)\s*$",
    re.M,
)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def find_entry(unit: Unit, label: str) -> tuple[str, str | None]:
    wanted = "bad" if label == "bad" else "good"
    found: list[str] = []
    for path in unit.sources:
        text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for match in FUNC_DEF.finditer(text):
            name = match.group(1)
            if (name == wanted or name.endswith("_" + wanted)) and name not in found:
                found.append(name)
    if len(found) != 1:
        raise ValueError(f"{unit.unit_id}: expected one {wanted} entry, found {found}")
    name = found[0]
    namespace = unit.group_id if (unit.language == "cpp" and name == wanted) else None
    return name, namespace


def probe_text(unit: Unit, label: str) -> str:
    name, namespace = find_entry(unit, label)
    if unit.language == "c":
        return f"void {name}(void);\nint main(void) {{ {name}(); return 0; }}\n"
    if namespace:
        return (
            f"namespace {namespace} {{ void {name}(); }}\n"
            f"int main() {{ {namespace}::{name}(); return 0; }}\n"
        )
    return f"void {name}();\nint main() {{ {name}(); return 0; }}\n"


def probe_suffix(unit: Unit) -> str:
    return "cpp" if unit.language == "cpp" else "c"


def write_probe(unit: Unit, label: str, directory: Path) -> tuple[Path, str]:
    text = probe_text(unit, label)
    path = directory / f"__dynenh_probe_main.{probe_suffix(unit)}"
    path.write_text(text, encoding="utf-8")
    return path, text
