#!/usr/bin/env python3
"""Live demo for the CS224 talk: CWE-401 detectors side by side, then a dead-free "attack".

  demo.py                                   default eval group (bad unit + its B2G good twin)
  demo.py --group <group_id> | --unit <unit_id> | --flow 02-22 [--mechanism cpp_new]
  demo.py --file my.c [--truth leak|no-leak]   your own program through the same detectors
  demo.py --record [out.json] / --replay recordings/<run>.json    offline backup
  demo.py --warm                            ping endpoints, warm up clang (before the talk)
  demo.py --check                           doctor (check.sh runs this)

See README.md for the stage script. Paid calls are logged to juliet_full/llm/ledger.jsonl with run_id demo_<ts>
and purpose "demo"; nothing is written to juliet_full/*/results/.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import difflib
import json
import os
import random
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DEMO_DIR = Path(__file__).resolve().parent
VENV_PYTHON = DEMO_DIR / ".venv" / "bin" / "python"
try:
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.spinner import Spinner
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
except ImportError:  # system python without rich: re-run inside the demo venv
    if VENV_PYTHON.exists() and Path(sys.executable).resolve() != VENV_PYTHON.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__, *sys.argv[1:]])
    raise

import dead_free  # noqa: E402
import demo_methods as dm  # noqa: E402

UNITS_PATH = dm.JULIET_FULL / "data" / "build" / "layer1.jsonl"
LAYER3_PATH = dm.JULIET_FULL / "data" / "build" / "layer3.jsonl"  # the stored stress layer the experiments ran on
SUPPORT_DIR = dm.PROJECT_ROOT / "juliet" / "raw" / "testcasesupport"
RECORDINGS = DEMO_DIR / "recordings"
DEFAULT_GROUP = "CWE401_Memory_Leak__strdup_char_01"  # eval fold 0, C, flow 01, good twin = B2G
WARM_UNIT = "CWE401_Memory_Leak__char_malloc_18__bad"  # dev unit, Clang SA reports its leak
DEFAULT_METHODS = ["grep", "clang", "ft", "ds_l1", "ds_l3"]
RECORD_FORMAT = "cs224-demo-run/1"


# ===================================================================== cases
def load_units(path: Path = UNITS_PATH) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pick_group(units: list[dict[str, Any]], args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(bad unit, good twin or None) for --unit / --group / --flow / the default group."""
    by_group: dict[str, dict[str, dict[str, Any]]] = {}
    for unit in units:
        by_group.setdefault(unit["group_id"], {})[unit["label"]] = unit
    if args.unit:
        unit = next((u for u in units if u["unit_id"] == args.unit), None)
        if unit is None:
            raise SystemExit(f"unknown unit_id {args.unit}")
        group = by_group[unit["group_id"]]
    elif args.group or not args.flow:
        name = args.group or DEFAULT_GROUP
        if name not in by_group:
            raise SystemExit(f"unknown group_id {name}")
        group = by_group[name]
    else:
        def ok(group: dict[str, dict[str, Any]]) -> bool:
            bad = group["bad"]
            return (bad["flow_category"] == args.flow and bad["set"] == args.set
                    and bad["mechanism"] == (args.mechanism or bad["mechanism"])
                    and bad["mechanism"] in (("c_alloc", "cpp_new") if not args.mechanism else (args.mechanism,))
                    and (args.good_kind == "any" or group["good"]["good_kind"] == args.good_kind))
        candidates = sorted((g for g in by_group.values() if ok(g)), key=lambda g: g["bad"]["group_id"])
        if not candidates:
            raise SystemExit("no group matches --flow/--mechanism/--set/--good-kind")
        shortest = min(len(g["bad"]["model_text"].splitlines()) for g in candidates)
        candidates = [g for g in candidates if len(g["bad"]["model_text"].splitlines()) <= shortest + args.slack]
        group = random.Random(args.seed).choice(candidates)
    return group["bad"], (None if args.no_twin else group.get("good"))


def custom_unit(path: Path, language: str | None) -> dict[str, Any]:
    """A unit record (README section 3 schema) for a presenter-written file; comments are stripped."""
    if str(dm.PROJECT_ROOT) not in sys.path:
        sys.path.append(str(dm.PROJECT_ROOT))
    from juliet_llm.cleaning import strip_comments  # the comment stripping used to build the units
    language = language or ("cpp" if path.suffix in (".cpp", ".cc", ".cxx", ".C") else "c")
    text = strip_comments(path.read_text(errors="replace")).rstrip() + "\n"
    program_dir = Path(dead_free.SCRATCH_ROOT) / f"custom_{path.stem}_{os.getpid()}"
    program_dir.mkdir(parents=True, exist_ok=True)
    source = f"unit_1.{'cpp' if language == 'cpp' else 'c'}"
    (program_dir / source).write_text(text)
    n = len(text.split("\n"))
    return {"unit_id": f"custom_{path.stem}", "group_id": f"custom_{path.stem}", "label": None, "truth": None,
            "set": "custom", "fold": None, "flow_category": None, "mechanism": None, "good_kind": None,
            "language": language, "program_dir": str(program_dir), "model_text": text,
            "build": {"compiler": "g++" if language == "cpp" else "gcc", "sources": [source],
                      "include_dirs": [str(SUPPORT_DIR)], "defines": [],
                      "std": "gnu++11" if language == "cpp" else "gnu11"},
            "line_map": [[source, i, i] for i in range(1, n + 1)], "entry": "main"}


def case(key: str, title: str, unit: dict[str, Any], truth: int | None, highlight: list[int] | None = None) \
        -> dict[str, Any]:
    return {"key": key, "title": title, "truth": truth, "unit": unit, "highlight": highlight or []}


def case_public(c: dict[str, Any]) -> dict[str, Any]:
    """What a recording keeps of a case (no paths)."""
    unit = c["unit"]
    keep = ("unit_id", "group_id", "language", "set", "fold", "flow_category", "mechanism", "good_kind", "model_text",
            "transform")
    return {"key": c["key"], "title": c["title"], "truth": c["truth"], "highlight": c["highlight"],
            "unit": {k: unit.get(k) for k in keep}}


# ===================================================================== rendering
def truth_text(truth: int | None) -> str:
    return {1: "LEAK", 0: "no leak"}.get(truth, "?") if truth is not None else "?"


def display_code(text: str, highlight: list[int]) -> tuple[str, set[int]]:
    """Display-only compaction: blank lines and a lone part header dropped; highlight lines renumbered."""
    lines = text.split("\n")
    parts = sum(1 for line in lines if dead_free.PART_RE.match(line))
    out, marks = [], set()
    for number, line in enumerate(lines, start=1):
        if not line.strip() or (parts == 1 and dead_free.PART_RE.match(line)):
            continue
        out.append(line)
        if number in highlight:
            marks.add(len(out))
    return "\n".join(out), marks


def code_panel(c: dict[str, Any], theme: str) -> Panel:
    unit = c["unit"]
    code, marks = display_code(unit["model_text"], c["highlight"])
    syntax = Syntax(code, "cpp" if unit["language"] == "cpp" else "c", theme=theme, highlight_lines=marks,
                    word_wrap=False, background_color="default")
    return Panel(syntax, title=f"[b]{c['title']}[/b]  ·  truth: [b]{truth_text(c['truth'])}[/b]",
                 border_style="red" if c["truth"] == 1 else "green" if c["truth"] == 0 else "white")


def header(console: Console, cases: list[dict[str, Any]], replay_note: str | None) -> None:
    console.print(Rule("[b]CWE-401 memory-leak detectors · live demo[/b]", style="cyan"))
    unit = cases[0]["unit"]
    if unit.get("set") == "custom":
        info = f"your program · {unit['language']}"
    else:
        fold = f" fold {unit['fold']}" if unit.get("fold") is not None else ""
        info = (f"{unit['group_id'].replace('CWE401_Memory_Leak__', '')} · flow {unit['flow_category']} · "
                f"{unit['mechanism']} · {unit['set']}{fold}")
    line = Text(info, style="bold")
    if replay_note:
        line.append(f"   ⏵ REPLAY of {replay_note}", style="bold yellow")
    console.print(line, justify="center")


def show_codes(console: Console, cases: list[dict[str, Any]], theme: str) -> None:
    panels = [code_panel(c, theme) for c in cases]
    if len(panels) == 2 and console.width >= 100:
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(*panels)
        console.print(grid)
    else:
        for panel in panels:
            console.print(panel)


def diff_panel(original: dict[str, Any], attacked: dict[str, Any]) -> Panel:
    diff = difflib.unified_diff(original["unit"]["model_text"].split("\n"), attacked["unit"]["model_text"].split("\n"),
                                lineterm="", n=1)
    body = "\n".join(line for line in diff if not line.startswith(("---", "+++")))
    info = attacked["unit"].get("transform") or {}
    if info.get("guards"):  # data lane (stress.py): one constant per guard, several guard forms
        consts = ", ".join(f"{g['name']} = {g['value']}" for g in info["guards"] if not g.get("truth"))
        if any(g.get("truth") for g in info["guards"]):
            consts += "; real frees wrapped in always-true guards"
    else:
        consts = f"{info.get('guard_name', 'sym_k')} = {info.get('guard_value', 5)}"
    what = "dead free inserted" if info.get("kind", "stress") == "stress" else "placebo edit inserted"
    return Panel(Syntax(body, "diff", theme="ansi_dark", background_color="default"),
                 title=f"[b]attack: {what}[/b] (guard always false: {consts}, file-local constant)",
                 subtitle=f"inserter: {info.get('inserter', '?')}{layer3_note(attacked['unit'])} · truth stays LEAK",
                 border_style="yellow")


def layer3_note(unit: dict[str, Any]) -> str:
    """' = stored layer 3' when the attacked code is exactly the experiments' layer-3 unit."""
    match = (unit.get("transform") or {}).get("matches_layer3")
    return "" if match is None else " = stored layer 3" if match else " ≠ stored layer 3"


def matches_layer3(source_unit_id: str, model_text: str) -> bool | None:
    """None when the unit has no stored layer-3 record (dev groups have one too; custom files do not)."""
    if not LAYER3_PATH.exists():
        return None
    for line in LAYER3_PATH.read_text().splitlines():
        if f'"unit_id": "{source_unit_id}"' in line:
            return json.loads(line)["model_text"] == model_text
    return None


def score_text(r: dm.Result) -> str:
    if r.score is None:
        return ""
    if r.score_kind == "logit":
        return f"s={r.score:+.2f} (thr {r.threshold:+.2f})" if r.threshold is not None else f"s={r.score:+.2f}"
    return f"p={r.score:.2f}"


def latency_text(ms: float | None) -> str:
    if ms is None:
        return ""
    return f"{ms:.2f} ms" if ms < 1 else f"{ms:.0f} ms" if ms < 10_000 else f"{ms / 1000:.1f} s"


def server_ms_text(r: dm.Result) -> str:
    """Server-side handler time of the decision model (excludes the LAN round trip and an adapter switch)."""
    server_ms = r.extra.get("latency_ms_server") if r.extra else None
    return f"server {latency_text(server_ms)}" if isinstance(server_ms, (int, float)) else ""


def verdict_cell(r: dm.Result | None, truth: int | None, before: dm.Result | None) -> Any:
    if r is None:
        return Spinner("dots", text=Text("running", style="yellow"))
    if r.status != "ok" or r.pred is None:
        style = "dim" if r.status in ("offline", "skipped") else "yellow"
        return Text.assemble((r.status, f"bold {style}"), "\n", ((r.detail or "")[:30], "dim"))
    verdict = "LEAK" if r.pred == 1 else "no leak"
    if truth is None:
        top = Text(verdict, style="bold")
    elif r.pred == truth:
        top = Text(f"✔ {verdict}", style="bold green")
    else:
        top = Text(f"✘ {verdict}", style="bold red")
    if before is not None and before.status == "ok" and before.pred is not None and before.pred != r.pred:
        top.append("  ⚡flipped", style="bold yellow")
    if r.score_kind == "logit":  # decision model: score vs threshold, then end-to-end and server-side time
        timing = " · ".join(x for x in (latency_text(r.latency_ms), server_ms_text(r)) if x)
        return Text.assemble(top, "\n", (score_text(r), "dim"), "\n", (timing, "dim"))
    bottom = " · ".join(x for x in (score_text(r), latency_text(r.latency_ms)) if x)
    return Text.assemble(top, "\n", (bottom, "dim"))


def method_cell(method: str, results: dict[str, dict[str, dm.Result | None]]) -> Text:
    name = dm.METHODS[method][0]
    note = dm.METHOD_NOTES.get(method, "")
    if method in ("ft", "ft_l3"):
        backends = [r.backend for per in results.values() if (r := per.get(method)) is not None and r.backend]
        note = backends[0] if backends else "fine-tuned Qwen3.5-4B LoRA"
    return Text.assemble((name, "bold"), "\n", (note[:34], "dim"))


def results_table(cases: list[dict[str, Any]], methods: list[str],
                  results: dict[str, dict[str, dm.Result | None]], before_of: dict[str, str]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=False, pad_edge=False, padding=(0, 1))
    table.add_column("detector", no_wrap=True)
    for c in cases:
        table.add_column(f"{c['title']}\ntruth: {truth_text(c['truth'])}", no_wrap=True, min_width=18)
    for method in methods:
        cells = []
        for c in cases:
            per = results.get(c["key"], {})
            if method not in per:
                cells.append(Text(""))
                continue
            prior = results.get(before_of.get(c["key"], ""), {}).get(method)
            cells.append(verdict_cell(per[method], c["truth"], prior))
        table.add_row(method_cell(method, results), *cells)
    return table


def summary_lines(cases: list[dict[str, Any]], methods: list[str],
                  results: dict[str, dict[str, dm.Result | None]]) -> list[str]:
    """Built from the actual results only."""
    keys = {c["key"]: c for c in cases}
    lines = []
    original_key = next((k for k in ("bad", "custom") if k in keys), None)
    attacked_key = next((k for k in ("attacked", "custom_attacked") if k in keys), None)
    if original_key and attacked_key:
        truth = keys[attacked_key]["truth"]
        parts = []
        for method in methods:
            name = dm.METHODS[method][1]
            r0, r1 = results[original_key].get(method), results[attacked_key].get(method)
            if r0 is None or r1 is None:
                continue
            if r0.status != "ok" or r1.status != "ok" or r0.pred is None or r1.pred is None:
                parts.append(f"{name} {r1.status if r1.status != 'ok' else r0.status}")
            elif truth is None:
                parts.append(f"{name} {'flipped' if r0.pred != r1.pred else 'unchanged'}")
            elif r0.pred == truth and r1.pred != truth:
                parts.append(f"{name} fooled")
            elif r0.pred == truth:
                parts.append(f"{name} robust")
            elif r1.pred == truth:
                parts.append(f"{name} wrong before, right after")
            else:
                parts.append(f"{name} wrong before and after")
        lines.append(", ".join(parts))
    if "good" in keys:
        wrong = [dm.METHODS[m][1] for m in methods
                 if (r := results["good"].get(m)) is not None and r.status == "ok" and r.pred is not None
                 and r.pred != keys["good"]["truth"]]
        lines.append("good twin: false alarm by " + ", ".join(wrong) if wrong else "good twin: no false alarm")
    if original_key == "bad":
        missed = [dm.METHODS[m][1] for m in methods
                  if (r := results["bad"].get(m)) is not None and r.status == "ok" and r.pred == 0]
        if missed:
            lines.append("leaking unit missed by " + ", ".join(missed))
    return lines


# ===================================================================== running
def run_cases(ctx: dm.DemoContext, cases: list[dict[str, Any]], methods: list[str],
              results: dict[str, dict[str, dm.Result | None]], refresh: Callable[[], None]) -> None:
    """Run every method on every case concurrently; `results` is filled in place (None = running)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures: dict[tuple[str, str], concurrent.futures.Future] = {}
        for c in cases:
            unit = c["unit"]
            results[c["key"]] = {m: None for m in methods}
            clang = pool.submit(dm.run_clang, unit) if {"clang", "ds_l3", "ft_l3"} & set(methods) else None

            def with_evidence(runner: Callable[[dict[str, Any], dict[str, Any] | None], dm.Result],
                              unit: dict[str, Any] = unit, clang: concurrent.futures.Future = clang) -> dm.Result:
                clang_result, evidence = clang.result()
                r = runner(unit, evidence)
                if r.latency_ms is not None and clang_result.latency_ms is not None:
                    r.extra["clang_ms"] = clang_result.latency_ms
                    r.latency_ms += clang_result.latency_ms  # pipeline time: analyzer + model
                return r

            jobs: dict[str, Callable[[], dm.Result]] = {
                "grep": lambda unit=unit: dm.run_grep(unit),
                "clang": lambda clang=clang: clang.result()[0],
                "ft": lambda unit=unit: dm.run_decision(ctx, unit),
                "ft_l3": lambda wrap=with_evidence: wrap(lambda u, ev: dm.run_decision(ctx, u, "L3", ev)),
                "ds_l1": lambda unit=unit: dm.run_deepseek(ctx, unit, "L1"),
                "ds_l3": lambda wrap=with_evidence: wrap(lambda u, ev: dm.run_deepseek(ctx, u, "L3", ev)),
                "jev": lambda unit=unit: dm.run_jev(ctx, unit),
            }
            for method in methods:
                futures[(c["key"], method)] = pool.submit(jobs[method])
        pending = dict(futures)
        while pending:
            for key, future in list(pending.items()):
                if future.done():
                    try:
                        results[key[0]][key[1]] = future.result()
                    except Exception as exc:  # noqa: BLE001 - a runner bug must not kill the demo
                        results[key[0]][key[1]] = dm.Result(key[1], "error", detail=repr(exc)[:80])
                    del pending[key]
            refresh()
            time.sleep(0.05)


def replay_cases(recorded: dict[str, dict[str, Any]], cases: list[dict[str, Any]], methods: list[str],
                 results: dict[str, dict[str, dm.Result | None]], refresh: Callable[[], None], cap_s: float) -> None:
    """Reveal recorded results in recorded latency order (each delay capped at cap_s)."""
    schedule = []
    for c in cases:
        results[c["key"]] = {m: None for m in methods if m in recorded.get(c["key"], {})}
        for method in results[c["key"]]:
            r = dm.Result.from_json(recorded[c["key"]][method])
            schedule.append((min((r.latency_ms or 0) / 1000.0, cap_s), c["key"], method, r))
    start = time.monotonic()
    for delay, key, method, r in sorted(schedule, key=lambda item: item[0]):
        while time.monotonic() - start < delay:
            refresh()
            time.sleep(0.05)
        results[key][method] = r
    refresh()


class Show:
    def __init__(self, console: Console, args: argparse.Namespace, replay_note: str | None) -> None:
        self.console = console
        self.args = args
        self.replay_note = replay_note
        self.pause_enabled = not args.no_pause and sys.stdin.isatty()

    def pause(self, prompt: str) -> None:
        if self.args.auto_pause is not None:  # unattended recording: hold the screen, then continue
            self.console.print(f"[dim]⏎  {prompt}[/dim]")
            time.sleep(self.args.auto_pause)
        elif self.pause_enabled:
            self.console.input(f"[dim]⏎  {prompt}[/dim] ")

    def screen(self, cases: list[dict[str, Any]], *body: Any) -> None:
        if not self.args.no_clear:
            self.console.clear()
        header(self.console, cases, self.replay_note)
        for item in body:
            self.console.print(item)

    def live_table(self, cases: list[dict[str, Any]], methods: list[str], results: dict[str, Any],
                   before_of: dict[str, str], fill: Callable[[Callable[[], None]], None], above: list[Any]) -> None:
        if not self.args.no_clear:  # without clearing, `above` is already on screen
            self.screen(cases[:1], *above)
        with Live(results_table(cases, methods, results, before_of), console=self.console,
                  refresh_per_second=12, transient=False) as live:
            fill(lambda: live.update(results_table(cases, methods, results, before_of)))


def summary_panel(lines: list[str], spent: dict[str, float]) -> Panel:
    body = Text()
    for i, line in enumerate(lines):
        body.append(line + ("\n" if i < len(lines) - 1 else ""), style="bold" if i == 0 else "")
    cost = []
    if spent.get("deepseek"):
        cost.append(f"DeepSeek ¥{spent['deepseek']:.4f}")
    if spent.get("jev"):
        cost.append(f"Jev ${spent['jev']:.5f}")
    return Panel(body, title="[b]summary[/b]", subtitle=" · ".join(cost) or None, border_style="cyan")


# ===================================================================== doctor / warm-up
def endpoint_rows(ctx: dm.DemoContext) -> list[tuple[str, str, str]]:
    rows = []
    for name, url, method in (("decision FT :8003", f"{ctx.ft_url}/health", "GET"),
                              ("Intern-Decision :8002", f"{ctx.intern_url}/health", "GET"),
                              ("Qwen vLLM :8001", f"{ctx.qwen_url}/models", "GET")):
        t0 = time.perf_counter()
        try:
            status, payload = dm.lan_json(method, url, None, dm.HEALTH_TIMEOUT_S)
            ok = status == 200
            if ok and isinstance(payload, dict) and isinstance(payload.get("models"), list):  # the FT endpoint
                detail = f"{len(payload['models'])} adapters, active {payload.get('active')}"
            else:
                detail = json.dumps(payload)[:70] if ok else f"HTTP {status}"
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, type(exc).__name__
        rows.append((name, "up" if ok else "DOWN", f"{detail} ({dm.ms_since(t0):.0f} ms)"))
    for name, func in (("DeepSeek /models", lambda: dm.clients.deepseek_client().list_models(timeout=8)),
                       ("Jev /models", lambda: dm.clients.JevClient().list_models(timeout=8))):
        t0 = time.perf_counter()
        try:
            status, _ = func()
            rows.append((name, "up" if status == 200 else "DOWN", f"HTTP {status} ({dm.ms_since(t0):.0f} ms)"))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, "DOWN", type(exc).__name__))
    return rows


def warm_clang() -> tuple[str, str, str]:
    """One Clang SA run on a dev unit (loads the binary and headers into the page cache)."""
    unit = next(u for u in load_units() if u["unit_id"] == WARM_UNIT)
    r, _ = dm.run_clang(unit)
    ok = r.status == "ok" and r.pred == 1
    return ("Clang SA warm-up", "ok" if ok else "FAIL", f"{r.status} pred={r.pred} {latency_text(r.latency_ms)}")


def warm_decision(ctx: dm.DemoContext) -> tuple[str, str, str]:
    """One /score request per fine-tuned adapter on a dev unit (first-request CUDA setup, adapter load).

    The L1 adapter of the default stage group goes last, so the first stage request needs no adapter switch."""
    kind, info = ctx.decision_backend()
    if kind != "ft":
        return ("decision FT warm-up", "SKIP", f"FT endpoint not up (backend: {kind})")
    units = load_units()
    unit = next(u for u in units if u["unit_id"] == WARM_UNIT)
    stage_fold = next(u["fold"] for u in units if u["group_id"] == DEFAULT_GROUP)
    server, failed = [], []
    for model in sorted(info, key=lambda m: m == dm.ft_model_name("L1", stage_fold)):
        strategy = "L3" if "-L3-" in model else "L1"
        try:
            status, payload = dm.lan_json("POST", f"{ctx.ft_url}/score", {
                "code": unit["model_text"], "language": unit["language"], "strategy": strategy,
                "evidence": [] if strategy == "L3" else None, "model": model}, dm.REMOTE_TIMEOUT_S)
            ok = status == 200 and isinstance(payload, dict) and payload.get("model") == model
        except Exception:  # noqa: BLE001
            ok, payload = False, None
        if ok:
            server.append(float(payload["latency_ms_server"]))
        else:
            failed.append(model)
    detail = f"{len(server)}/{len(info)} adapters answered"
    if server:
        detail += f", server {min(server):.0f}-{max(server):.0f} ms"
    return ("decision FT warm-up", "ok" if not failed else "FAIL", detail + (f"; failed {failed}" if failed else ""))


def doctor(ctx: dm.DemoContext, console: Console, full: bool) -> int:
    table = Table(title="demo doctor" if full else "pre-warm", box=box.SIMPLE)
    for col in ("check", "state", "detail"):
        table.add_column(col)
    problems = 0

    def add(row: tuple[str, str, str]) -> None:
        nonlocal problems
        style = "green" if row[1] in ("ok", "up", "off-peak", "yes") else "yellow"
        problems += style != "green" and row[1] not in ("info",)
        table.add_row(row[0], f"[{style}]{row[1]}[/]", row[2])

    clang_bin = Path(dm.run_static.DEFAULT_BINS["clang"])
    if full:
        add(("clang binary", "ok" if clang_bin.exists() else "FAIL", str(clang_bin)))
        cfgs = [n for n in ("clang.cfg", "clang++.cfg") if (clang_bin.parent / n).exists()]
        add(("clang cfg files", "ok" if len(cfgs) == 2 else "FAIL", ", ".join(cfgs) or "missing"))
        env_text = dm.clients.ENV_PATH.read_text() if dm.clients.ENV_PATH.exists() else ""
        for key in ("DEEPSEEK_API_KEY", "TYPESAFE_API_KEY"):
            try:
                present = bool(dm.clients.read_env_key(key))
            except KeyError:
                present = False
            add((f"key {key}", "yes" if present and env_text else "MISSING", "value not shown"))
        add(("units file", "ok" if UNITS_PATH.exists() else "FAIL", str(UNITS_PATH.relative_to(dm.PROJECT_ROOT))))
        inserter, _ = dead_free.transformer("auto")
        add(("dead-free inserter", "info", f"{inserter} (data/stress.py "
                                           f"{'present' if (dead_free.DATA_DIR / 'stress.py').exists() else 'absent'})"))
    add(warm_clang())
    for row in endpoint_rows(ctx):
        add(row)
    if not full:
        add(warm_decision(ctx))
    if full:
        balance = dm.clients.deepseek_balance()
        if balance:
            info = (balance.get("balance_infos") or [{}])[0]
            add(("DeepSeek balance", "ok", f"{info.get('total_balance')} {info.get('currency')}"))
        else:
            add(("DeepSeek balance", "UNKNOWN", "balance query failed"))
        now = datetime.now(timezone.utc)
        local = now.astimezone(dm.pricing.SHANGHAI)
        if dm.pricing.is_deepseek_peak(now):
            nxt = dm.pricing.next_offpeak(now).astimezone(dm.pricing.SHANGHAI)
            add(("DeepSeek peak gate", "PEAK", f"Beijing {local:%a %H:%M}; off-peak at {nxt:%a %H:%M}; "
                                               "demo needs --allow-peak (2x price)"))
        else:
            add(("DeepSeek peak gate", "off-peak", f"Beijing {local:%a %H:%M}"))
        records = ctx.ledger.records()
        for provider, cur in (("deepseek", "CNY"), ("jev", "USD")):
            total = sum(float(r.get("cost") or 0) for r in records if r.get("kind") == "call"
                        and r.get("provider") == provider)
            demo = sum(float(r.get("cost") or 0) for r in records if r.get("kind") == "call"
                       and r.get("provider") == provider and r.get("purpose") == "demo")
            cap = dm.GLOBAL_CAPS[provider][1]
            add((f"ledger {provider}", "ok" if total < cap else "STOP",
                 f"total {total:.4f} {cur} (hard stop {cap}); demo {demo:.4f} {cur}"))
        size = os.get_terminal_size() if sys.stdout.isatty() else None
        cols, rows = (size.columns, size.lines) if size else (console.width, console.height)
        add(("terminal size", "ok" if cols >= 110 and rows >= 34 else "SMALL", f"{cols}x{rows} (want >= 110x34)"))
    console.print(table)
    console.print(f"{problems} item(s) need attention" if problems else "all checks passed",
                  style="yellow" if problems else "green")
    return 0 if problems == 0 else 1


# ===================================================================== main flow
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sel = p.add_argument_group("unit selection")
    sel.add_argument("--unit", help="unit_id (bad or good; the other unit of the group is the twin)")
    sel.add_argument("--group", help=f"group_id (default {DEFAULT_GROUP})")
    sel.add_argument("--flow", choices=("01", "02-22", "31-45", "51-68", "71-84"), help="pick a group by flow category")
    sel.add_argument("--mechanism", choices=("c_alloc", "cpp_new", "realloc_fail", "destructor"))
    sel.add_argument("--set", default="eval", choices=("dev", "eval"), help="with --flow (default eval)")
    sel.add_argument("--good-kind", default="B2G", choices=("B2G", "G2B", "other", "any"), help="with --flow")
    sel.add_argument("--seed", type=int, default=0, help="with --flow: choice among the shortest groups")
    sel.add_argument("--slack", type=int, default=2, help="with --flow: allowed extra lines over the shortest")
    sel.add_argument("--file", type=Path, help="run your own C/C++ file instead of a Juliet unit")
    sel.add_argument("--language", choices=("c", "cpp"), help="with --file (default from the extension)")
    sel.add_argument("--truth", choices=("leak", "no-leak"), help="with --file: ground truth to score against")
    sel.add_argument("--no-twin", action="store_true", help="do not show/run the good twin")
    sel.add_argument("--no-attack", action="store_true", help="skip the dead-free step")
    run = p.add_argument_group("detectors")
    run.add_argument("--methods", default=",".join(DEFAULT_METHODS),
                     help=f"comma list from {','.join(dm.METHODS)} (default {','.join(DEFAULT_METHODS)})")
    run.add_argument("--jev", action="store_true", help="add Jev L1")
    run.add_argument("--ft-l3", action="store_true", help="add the decision model L3 row (code + Clang SA warnings)")
    run.add_argument("--offline", action="store_true", help="no paid API calls (drops DeepSeek and Jev)")
    run.add_argument("--allow-peak", action="store_true", help="allow DeepSeek in Beijing peak hours (2x price)")
    run.add_argument("--allow-eval", action="store_true", help="allow paid calls on eval units")
    run.add_argument("--max-cost-cny", type=float, default=0.02, help="DeepSeek cap for this invocation")
    run.add_argument("--max-cost-usd", type=float, default=0.002, help="Jev cap for this invocation")
    run.add_argument("--ft-url", default=dm.FT_URL)
    run.add_argument("--intern-url", default=dm.INTERN_URL)
    run.add_argument("--qwen-url", default=dm.QWEN_URL)
    run.add_argument("--ft-fold", type=int, default=0, help="adapter fold for dev/custom units (eval: unit fold)")
    run.add_argument("--inserter", default="auto", choices=("auto", "local", "stress"))
    run.add_argument("--attack-kind", default="stress", choices=("stress", "placebo"))
    run.add_argument("--attack-seed", type=int, default=None,
                     help="inserter seed (default: data lane SEED; local inserter: constant 5)")
    run.add_argument("--attack-n-dead", type=int, default=0,
                     help="dead frees to insert (default 0 = inserter default; with stress.py that is exactly the "
                          "stored layer-3 unit)")
    ui = p.add_argument_group("stage")
    ui.add_argument("--record", nargs="?", const="auto", help="save the run (default recordings/demo_<ts>.json)")
    ui.add_argument("--replay", type=Path, help="replay a recorded run (no network, no tools)")
    ui.add_argument("--replay-cap", type=float, default=1.5, help="max seconds per revealed result in replay")
    ui.add_argument("--no-pause", action="store_true", help="do not wait for Enter between steps")
    ui.add_argument("--auto-pause", type=float, metavar="SECONDS",
                    help="instead of waiting for Enter, hold each step this long (record.sh)")
    ui.add_argument("--no-clear", action="store_true", help="do not clear the screen between steps")
    ui.add_argument("--theme", default="monokai", help="pygments theme of the code panels")
    ui.add_argument("--warm", action="store_true", help="pre-warm: ping endpoints, run clang once")
    ui.add_argument("--check", action="store_true", help="doctor: tools, keys, endpoints, balance, peak gate")
    args = p.parse_args(argv)
    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    unknown = [m for m in methods if m not in dm.METHODS]
    if unknown:
        p.error(f"unknown method(s) {unknown}")
    if args.ft_l3 and "ft_l3" not in methods:
        methods.insert(methods.index("ft") + 1 if "ft" in methods else len(methods), "ft_l3")
    if args.jev and "jev" not in methods:
        methods.append("jev")
    if args.offline:
        methods = [m for m in methods if m not in dm.PAID]
    args.method_list = methods
    return args


def build_cases(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.file:
        truth = {"leak": 1, "no-leak": 0}.get(args.truth) if args.truth else None
        return [case("custom", "your code", custom_unit(args.file, args.language), truth)]
    bad, good = pick_group(load_units(), args)
    cases = [case("bad", "leaking unit", bad, 1)]
    if good is not None:
        cases.append(case("good", f"good twin ({good['good_kind']})", good, 0))
    return cases


def attack_case(args: argparse.Namespace, original: dict[str, Any]) -> dict[str, Any]:
    _, transform = dead_free.transformer(args.inserter)
    unit = transform(original["unit"], kind=args.attack_kind, seed=args.attack_seed,
                     n_dead=args.attack_n_dead or None)
    if args.attack_kind == "stress" and original["key"] != "custom":
        unit["transform"] = {**unit.get("transform", {}),
                             "matches_layer3": matches_layer3(original["unit"]["unit_id"], unit["model_text"])}
    old, new = original["unit"]["model_text"].split("\n"), unit["model_text"].split("\n")
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    lines = [j + 1 for tag, _, _, j1, j2 in matcher.get_opcodes() if tag in ("insert", "replace")
             for j in range(j1, j2)]  # highlight what the edit added (both inserters)
    key = "custom_attacked" if original["key"] == "custom" else "attacked"
    title = "+ dead free" if args.attack_kind == "stress" else "+ placebo edit"
    return case(key, title, unit, original["truth"], lines)


def save_record(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n")
    return path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    console = Console(highlight=False)
    run_id = "demo_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ctx = dm.DemoContext(run_id, allow_peak=args.allow_peak, allow_eval=args.allow_eval,
                         max_cost_cny=args.max_cost_cny, max_cost_usd=args.max_cost_usd, ft_url=args.ft_url,
                         intern_url=args.intern_url, qwen_url=args.qwen_url, ft_fold=args.ft_fold)
    if args.check or args.warm:
        return doctor(ctx, console, full=args.check)

    recorded: dict[str, Any] | None = None
    if args.replay:
        recorded = json.loads(args.replay.read_text())
        if recorded.get("format") != RECORD_FORMAT:
            raise SystemExit(f"{args.replay}: not a {RECORD_FORMAT} file")
        cases = [c for c in recorded["cases"] if c["key"] in ("bad", "good", "custom")]
        attacked = next((c for c in recorded["cases"] if c["key"] in ("attacked", "custom_attacked")), None)
        methods = recorded["methods"]
        replay_note = f"{recorded['created_utc']} run"
    else:
        cases = build_cases(args)
        attacked = None
        methods = args.method_list
        replay_note = None
        if {"ft", "ft_l3"} & set(methods):  # probe the decision-model endpoints while the code is on screen
            concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(ctx.decision_backend)

    show = Show(console, args, replay_note)
    results: dict[str, dict[str, dm.Result | None]] = {}
    before_of: dict[str, str] = {}

    def fill(phase_cases: list[dict[str, Any]]) -> Callable[[Callable[[], None]], None]:
        if recorded is not None:
            return lambda refresh: replay_cases(recorded["results"], phase_cases, methods, results, refresh,
                                                args.replay_cap)
        return lambda refresh: run_cases(ctx, phase_cases, methods, results, refresh)

    # step 1: the code
    show.screen(cases)
    show_codes(console, cases, args.theme)
    show.pause("run the detectors")
    # step 2: detectors on the unit (and its good twin)
    show.live_table(cases, methods, results, before_of, fill(cases), [])
    original = cases[0]
    do_attack = (attacked is not None) if recorded is not None else not args.no_attack
    if do_attack:
        show.pause("attack: insert a dead free into the leaking unit")
        if recorded is None:
            try:
                attacked = attack_case(args, original)
            except dead_free.InsertError as exc:
                console.print(Panel(f"dead-free insertion failed: {exc}", border_style="red"))
                do_attack = False
    if do_attack and attacked is not None:
        before_of[attacked["key"]] = original["key"]
        show.screen(cases, diff_panel(original, attacked))
        if console.height >= 60:  # tall terminal: also show the whole edited unit
            console.print(code_panel(attacked, args.theme))
        show.pause("rerun the detectors on the edited unit")
        all_cases = cases + [attacked]
        show.live_table(all_cases, methods, results, before_of, fill([attacked]), [diff_panel(original, attacked)])
    all_cases = cases + ([attacked] if do_attack and attacked is not None else [])
    lines = summary_lines(all_cases, methods, results)
    spent = recorded.get("spent", {}) if recorded is not None else ctx.spent
    console.print(summary_panel(lines, spent))

    if args.record and recorded is None:
        out = RECORDINGS / f"{run_id}.json" if args.record == "auto" else Path(args.record)
        payload = {
            "format": RECORD_FORMAT, "created_utc": dm.utc_iso(), "run_id": run_id, "host": socket.gethostname(),
            "argv": sys.argv[1:], "methods": methods, "cases": [case_public(c) for c in all_cases],
            "attack": (attacked["unit"].get("transform") if do_attack and attacked else None),
            "results": {k: {m: (r.to_json() if r else None) for m, r in per.items()} for k, per in results.items()},
            "summary": lines, "spent": ctx.spent}
        console.print(f"[dim]recorded → {save_record(out, payload)}[/dim]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
