#!/usr/bin/env python3
"""L4-D candidate-site parser (lexical only: tree-sitter syntax tree of model_text, no constant evaluation).

Site kinds (contract l4d/README.md section 1):
  alloc    statement containing a call to an allocator (ALLOC_FUNCS) or a `new` expression
  realloc  statement containing a call to `realloc` (one site; it both allocates and consumes its input)
  release  statement containing `free(...)`, `delete x` or `delete[] x`
  stmt     any other simple statement (expression statement, declaration with initializer, return) that is the
           first statement of a guarded block (if / else / while / for / do / switch case / catch), or a call
           statement
Kind priority on one statement: realloc > alloc > release > stmt.  Only statements inside function bodies are
sites, and nothing inside the driver `main` (identical in every unit).

    from parse_sites import parse_unit
    parsed = parse_unit(model_text, language)      # {"sites": [...], "guards": [...]}

CLI: .venv/bin/python parse_sites.py --layer layer1_sample   (writes build/sites_<layer>.jsonl)
"""
from __future__ import annotations

import argparse
import json
import re
from functools import lru_cache
from pathlib import Path

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Node, Parser

L4D_DIR = Path(__file__).resolve().parent
DATA_BUILD = L4D_DIR.parent / "data" / "build"
BUILD = L4D_DIR / "build"

ALLOC_FUNCS = {"malloc", "calloc", "strdup", "wcsdup", "strndup", "ALLOCA", "alloca", "_alloca",
               "aligned_alloc", "valloc"}
REALLOC_FUNCS = {"realloc"}
RELEASE_FUNCS = {"free"}
SIMPLE_STMTS = {"expression_statement", "declaration", "return_statement"}
CONTROL_STMTS = {"if_statement", "while_statement", "for_statement", "do_statement", "switch_statement",
                 "try_statement", "for_range_loop"}
KIND_ORDER = ("realloc", "alloc", "release", "stmt")
DRIVER = "main"


@lru_cache(maxsize=2)
def _parser(language: str) -> Parser:
    lang = tree_sitter_cpp.language() if language == "cpp" else tree_sitter_c.language()
    return Parser(Language(lang))


def _text(node: Node | None) -> str:
    return "" if node is None else node.text.decode("utf-8", "replace")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _descendants(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _strip_parens(node: Node) -> Node:
    while node is not None and node.type in ("parenthesized_expression", "cast_expression"):
        node = node.child_by_field_name("value") if node.type == "cast_expression" else node.named_children[0]
    return node


def _callee(call: Node) -> str:
    fn = call.child_by_field_name("function")
    name = _text(fn)
    return name.split("::")[-1]


def _declarator_name(decl: Node | None) -> str | None:
    """Identifier of a declarator (strips pointer/reference/array/init wrappers)."""
    while decl is not None and decl.type not in ("identifier", "field_identifier", "qualified_identifier"):
        nxt = decl.child_by_field_name("declarator")
        if nxt is None:
            named = [c for c in decl.named_children if c.type not in ("type_qualifier",)]
            nxt = named[0] if named else None
        decl = nxt
    return _text(decl) if decl is not None else None


def _function_name(fdef: Node) -> str:
    fdecl = next((d for d in _descendants(fdef.child_by_field_name("declarator") or fdef)
                  if d.type == "function_declarator"), None)
    name = _text(fdecl.child_by_field_name("declarator")) if fdecl is not None else "?"
    parent = fdef.parent
    while parent is not None:
        if parent.type in ("class_specifier", "struct_specifier") and parent.child_by_field_name("name"):
            return f"{_text(parent.child_by_field_name('name'))}::{name}"
        if parent.type == "function_definition":
            break
        parent = parent.parent
    return name


def _first_simple(node: Node | None) -> Node | None:
    """First simple statement of a guarded block (descends into nested plain blocks)."""
    while node is not None:
        if node.type == "compound_statement":
            stmts = [c for c in node.named_children if c.type != "comment"]
            node = stmts[0] if stmts else None
            continue
        if node.type in SIMPLE_STMTS:
            return node
        return None
    return None


def _case_body_first(case: Node) -> Node | None:
    seen_colon = False
    for c in case.children:
        if not seen_colon:
            seen_colon = c.type == ":"
            continue
        if c.is_named and c.type != "comment":
            return _first_simple(c)
    return None


def _statement_info(stmt: Node) -> dict | None:
    """Classify a simple statement; None if it is neither an alloc/release/realloc site nor a call statement."""
    calls, news, deletes = [], [], []
    for d in _descendants(stmt):
        if d.type == "call_expression":
            calls.append(d)
        elif d.type == "new_expression":
            news.append(d)
        elif d.type == "delete_expression":
            deletes.append(d)
    names = [_callee(c) for c in calls]
    info: dict = {"var": None}
    target = _assigned_var(stmt)
    if any(n in REALLOC_FUNCS for n in names):
        call = calls[[n in REALLOC_FUNCS for n in names].index(True)]
        args = call.child_by_field_name("arguments").named_children
        info.update(kind="realloc", callee="realloc", var=target, src=_norm(_text(args[0])) if args else None)
    elif any(n in ALLOC_FUNCS for n in names) or news:
        if news:
            callee = "new[]" if any(c.type == "[" or c.type == "new_declarator" for c in _descendants(news[0])) \
                else "new"
        else:
            callee = next(n for n in names if n in ALLOC_FUNCS)
        info.update(kind="alloc", callee=callee, var=target)
    elif any(n in RELEASE_FUNCS for n in names) or deletes:
        if deletes:
            d = deletes[0]
            callee = "delete[]" if any(c.type == "[" for c in d.children) else "delete"
            var = _norm(_text(d.named_children[-1])) if d.named_children else None
        else:
            call = calls[[n in RELEASE_FUNCS for n in names].index(True)]
            args = call.child_by_field_name("arguments").named_children
            callee, var = "free", (_norm(_text(args[0])) if args else None)
        info.update(kind="release", callee=callee, var=var)
    elif _is_call_statement(stmt):
        info.update(kind="stmt", callee=_callee(_top_call(stmt)), var=None)
    else:
        info.update(kind="stmt", callee=None, var=None)
        info["plain"] = True
    return info


def _top_expr(stmt: Node) -> Node | None:
    if stmt.type == "expression_statement":
        return stmt.named_children[0] if stmt.named_children else None
    if stmt.type == "return_statement":
        return stmt.named_children[0] if stmt.named_children else None
    if stmt.type == "declaration":
        init = next((c for c in stmt.named_children if c.type == "init_declarator"), None)
        return init.child_by_field_name("value") if init is not None else None
    return None


def _top_call(stmt: Node) -> Node | None:
    expr = _top_expr(stmt)
    if expr is not None and expr.type == "assignment_expression":
        expr = expr.child_by_field_name("right")
    expr = _strip_parens(expr) if expr is not None else None
    return expr if expr is not None and expr.type == "call_expression" else None


def _is_call_statement(stmt: Node) -> bool:
    return _top_call(stmt) is not None


def _assigned_var(stmt: Node) -> str | None:
    expr = _top_expr(stmt)
    if stmt.type == "expression_statement" and expr is not None and expr.type == "assignment_expression":
        return _norm(_text(expr.child_by_field_name("left")))
    if stmt.type == "declaration":
        init = next((c for c in stmt.named_children if c.type == "init_declarator"), None)
        if init is not None:
            return _declarator_name(init.child_by_field_name("declarator"))
    return None


def _is_meaningful(stmt: Node) -> bool:
    if stmt.type == "expression_statement":
        return bool(stmt.named_children)
    if stmt.type == "declaration":
        return any(c.type == "init_declarator" for c in stmt.named_children)
    return stmt.type == "return_statement"


def parse_unit(model_text: str, language: str) -> dict:
    src = model_text.encode("utf-8")
    tree = _parser(language).parse(src)
    guarded_first: dict[int, str] = {}  # start_byte of statement -> guard kind
    guards = []
    stmts: list[tuple[Node, str]] = []

    def visit(node: Node, func: str | None):
        if node.type == "function_definition":
            func = _function_name(node)
        if func is not None and func != DRIVER:
            kind = None
            if node.type == "if_statement":
                kind = "if"
                first = _first_simple(node.child_by_field_name("consequence"))
                if first is not None:
                    guarded_first.setdefault(first.start_byte, "if")
                alt = node.child_by_field_name("alternative")
                if alt is not None:
                    body = alt.named_children[0] if alt.type == "else_clause" and alt.named_children else alt
                    if body.type != "if_statement":
                        guards.append({"line": alt.start_point[0] + 1, "kind": "else", "text": "else", "func": func})
                        first = _first_simple(body)
                        if first is not None:
                            guarded_first.setdefault(first.start_byte, "else")
            elif node.type in ("while_statement", "for_statement", "do_statement", "for_range_loop"):
                kind = {"while_statement": "while", "for_statement": "for", "do_statement": "do",
                        "for_range_loop": "for"}[node.type]
                first = _first_simple(node.child_by_field_name("body"))
                if first is not None:
                    guarded_first.setdefault(first.start_byte, kind)
            elif node.type == "switch_statement":
                kind = "switch"
            elif node.type == "case_statement":
                kind = "case"
                first = _case_body_first(node)
                if first is not None:
                    guarded_first.setdefault(first.start_byte, "case")
            elif node.type == "catch_clause":
                kind = "catch"
                first = _first_simple(node.child_by_field_name("body"))
                if first is not None:
                    guarded_first.setdefault(first.start_byte, "catch")
            if kind is not None:
                if node.type == "for_statement":
                    head = _text(node).split("{", 1)[0]
                    gtext = _norm(head)
                elif node.type == "case_statement":
                    gtext = _norm(_text(node).split(":", 1)[0])
                else:
                    cond = node.child_by_field_name("condition")
                    gtext = _norm(_text(cond)) if cond is not None else kind
                guards.append({"line": node.start_point[0] + 1, "kind": kind, "text": gtext, "func": func})
            if node.type in SIMPLE_STMTS and node.parent is not None and node.parent.type != "for_statement" \
                    and _is_meaningful(node):
                stmts.append((node, func))
                return  # no sites nested inside a simple statement
        for c in node.children:
            visit(c, func)

    visit(tree.root_node, None)
    sites = []
    for node, func in sorted(stmts, key=lambda x: x[0].start_byte):
        info = _statement_info(node)
        first_of = guarded_first.get(node.start_byte)
        if info["kind"] == "stmt" and info.get("plain") and first_of is None:
            continue
        info.pop("plain", None)
        site = {"site_id": None, "kind": info["kind"], "line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1, "span": [node.start_byte, node.end_byte], "func": func,
                "text": _norm(_text(node)), "var": info["var"], "callee": info["callee"], "guard_first": first_of}
        if "src" in info:
            site["src"] = info["src"]
        sites.append(site)
    for i, s in enumerate(sites):
        s["site_id"] = f"s{i:02d}"
    guards.sort(key=lambda g: g["line"])
    return {"sites": sites, "guards": guards, "parse_errors": int(tree.root_node.has_error)}


def mask_statement(model_text: str, span: list[int], marker: str) -> str:
    """Replace the statement span by `marker`, keeping every line number (newlines of the span are kept)."""
    start, end = span
    removed = model_text[start:end]
    return model_text[:start] + marker + "\n" * removed.count("\n") + model_text[end:]


def layer_path(layer: str) -> Path:
    return DATA_BUILD / f"{layer}.jsonl"


def site_rows(layer: str, units: list[dict]) -> list[dict]:
    rows = []
    for u in units:
        parsed = parse_unit(u["model_text"], u["language"])
        rows.append({"unit_id": u["unit_id"], "layer": layer_name(layer), **parsed})
    return rows


def layer_name(layer: str) -> str:
    return "layer1" if layer == "layer1_sample" else layer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", required=True)
    args = ap.parse_args()
    units = [json.loads(l) for l in layer_path(args.layer).open()]
    BUILD.mkdir(exist_ok=True)
    rows = site_rows(args.layer, units)
    with (BUILD / f"sites_{args.layer}.jsonl").open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"{len(rows)} units, {sum(len(r['sites']) for r in rows)} sites, "
          f"{sum(r['parse_errors'] for r in rows)} units with parse errors")


if __name__ == "__main__":
    main()
