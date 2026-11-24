"""Fixed L4-D question templates (contract l4d/README.md section 2). Do not edit after the freeze.

TEMPLATE_SHA256 is the sha256 of the canonical JSON of TEMPLATES + MARKER + NUMBERING; l4d-train records it in
l4d_ft/FROZEN.  `python3 templates.py` prints it.
"""
from __future__ import annotations

import hashlib
import json

MARKER = "__TARGET__();"
NUMBERING = "{n:>{width}}| {line}"  # same listing as the chat-model L4 prompts (llmlane/prompts.py:number_lines)
CODE_MAX = 120  # longer site statements are cut to CODE_MAX characters + "..."

TEMPLATES = {
    "heap": ("Does the call at line {line} (`{code}`) allocate heap memory that the program must release? "
             "Stack memory such as ALLOCA/alloca, static buffers and string literals do not count."),
    "exec_any": ("The statement at line {line} has been hidden and replaced by the marker `__TARGET__();`. "
                 "Can the statement at line {line} execute on at least one run of the program?"),
    "exec_all": ("The statement at line {line} has been hidden and replaced by the marker `__TARGET__();`. "
                 "Does the statement at line {line} execute on every run of the program?"),
    "rel": ("Does the release at line {line_f} (`{code_f}`) free the block obtained at line {line_a} "
            "(`{code_a}`)? The block may have been passed to another function or copied to another variable."),
    "realloc_safe": ("If the realloc at line {line} (`{code}`) fails and returns NULL, is the original block "
                     "still released later?"),
}
QTYPES = tuple(TEMPLATES)
EXEC_QTYPES = ("exec_any", "exec_all")


def code_snippet(text: str) -> str:
    return text if len(text) <= CODE_MAX else text[:CODE_MAX] + "..."


def number_lines(code: str) -> str:
    lines = code.split("\n")
    width = len(str(len(lines)))
    return "\n".join(NUMBERING.format(n=i, width=width, line=line).rstrip() for i, line in enumerate(lines, 1))


def render(qtype: str, **slots) -> str:
    return TEMPLATES[qtype].format(**slots)


def _canonical() -> str:
    return json.dumps({"templates": TEMPLATES, "marker": MARKER, "numbering": NUMBERING, "code_max": CODE_MAX},
                      sort_keys=True, separators=(",", ":"))


TEMPLATE_SHA256 = hashlib.sha256(_canonical().encode("utf-8")).hexdigest()

if __name__ == "__main__":
    print(TEMPLATE_SHA256)
