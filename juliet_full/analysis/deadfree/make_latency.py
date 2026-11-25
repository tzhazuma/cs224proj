#!/usr/bin/env python3
"""DeadFree concurrency-1 latency table (latency300 layer3 units, measured from dell) -> latency_deadfree.csv.

Rerunnable: each method row is filled from its run file once that exists, otherwise "pending".
End-to-end definitions (per unit, then median / p90 / mean over the units):
  L1, L2                     = model call (client wall time on dell)
  L3                         = Clang SA time of the same unit (static/results/clang_sa/layer3/lat300_c1.jsonl) + model call
  L4 (generative)            = model call + fact parsing + Souffle derive (run_llm.py latency_s; souffle_s reported)
  L4-D                       = sites + questions (+ prune) + forwards + derive (latency_s of the L4-D latency runs)
  static / dynamic           = per-unit tool step (TU preparation + tool + parsing / compile + executions)
Then `python make_table.py` merges this table with the quality table into deadfree_pareto.json.
"""
from __future__ import annotations

import csv
import glob
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
JF = HERE.parents[1]
CLANG_C1 = JF / "static/results/clang_sa/layer3/lat300_c1.jsonl"
DELL = "dell i5-12500 (12 threads), CPU"
GPU1 = "1x RTX 3090 (184-toast GPU 1); client dell"
GPU_L4D = "1x RTX 3090 (184-toast, see run meta gpu_note); client dell"
COLUMNS = ["method", "role", "quality_key", "model", "strategy", "group", "n", "median_s", "p90_s", "mean_s", "components",
           "hardware", "kernel", "run_file", "measured_utc", "note"]


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def stats(values: list[float]) -> dict:
    return {"median_s": round(statistics.median(values), 6), "p90_s": round(pct(values, 0.9), 6),
            "mean_s": round(statistics.fmean(values), 6)}


def comp(values: list[float]) -> dict:
    return {"median": round(statistics.median(values), 4), "p90": round(pct(values, 0.9), 4),
            "mean": round(statistics.fmean(values), 4)}


def clang_times() -> dict | None:
    if not CLANG_C1.exists():
        return None
    return {r["unit_id"]: r["latency_s"] for r in read_jsonl(CLANG_C1)}


def newest(patterns: list[str]) -> Path | None:
    hits = [Path(p) for pat in patterns for p in glob.glob(str(JF / pat)) if not p.endswith(".meta.json")]
    return max(hits, key=lambda p: p.stat().st_mtime) if hits else None


# (method, quality_key, model, strategy, group, hardware, kernel, run file pattern(s), kind)
SPECS = []
for k in ("L1", "L2", "L3", "L4"):
    SPECS.append((f"DeepSeek {k}", f"deepseek_{k}", "deepseek-flash", k, "cloud-LLM", "DeepSeek API (cloud); client dell",
                  "", [f"llm/results/deepseek_flash/layer3/lat300_c1_{k}.jsonl"], "llm"))
for k in ("L1", "L2", "L3"):
    SPECS.append((f"Jev {k}", f"jev_{k}", "jev-latest", k, "cloud-decision", "Jev API (cloud); client dell", "",
                  [f"llm/results/jev/layer3/lat300_c1_{k}.jsonl"], "llm"))
for k in ("L1", "L2", "L3", "L4"):
    SPECS.append((f"Qwen3.5-4B {k} (gen.)", f"qwen_{k}", "qwen3.5-4b", k, "local-LLM", GPU1, "vLLM (unaffected)",
                  [f"llm/results/qwen3_5_4b/layer3/lat300_c1_{k}.jsonl"], "llm"))
FALLBACK = "causal_conv1d reference fallback (transformers) = config of the reported predictions"
KERNEL = "kernel (not score-identical, |Δp| ≤ 0.03)"
for k in ("L1", "L2", "L3"):
    SPECS.append((f"Intern-Decision {k}", f"intern_{k}", "Intern-Decision-4B", k, "local-decision", GPU1,
                  FALLBACK, [f"gpu/results/intern_decision/layer3/lat300_c1_{k}.jsonl"], "intern"))
for k in ("L1", "L2", "L3"):
    SPECS.append((f"Intern-Decision {k} (kernel, secondary)", f"intern_{k}", "Intern-Decision-4B", k,
                  "local-decision", GPU1, KERNEL,
                  [f"gpu/results/intern_decision/layer3/lat300_c1_{k}_kernel.jsonl"], "intern"))
SPECS += [
    ("Intern-Decision L4-D", "intern_l4d", "Intern-Decision-4B", "L4D", "local-decision", GPU1,
     FALLBACK, ["l4d_ft/results/intern_l4d/layer3/lat300_c1.jsonl"], "l4d"),
    ("Intern-Decision L4-D (kernel, secondary)", "intern_l4d", "Intern-Decision-4B", "L4D", "local-decision", GPU1,
     KERNEL, ["l4d_ft/results/intern_l4d/layer3/lat300_c1_kernel.jsonl"], "l4d"),
    # Jev L4-D: primary = the questions of a unit sent concurrently; secondary = parse/prune + sum of per-call
    # latencies + derive (sequential, the way Intern-Decision L4-D was measured); both from the same run file
    ("Jev L4-D", "jev_l4d", "jev-latest", "L4D", "cloud-decision", "Jev API (cloud); client dell",
     "questions of a unit concurrent", ["l4d_ft/results/jev_l4d/layer3/lat300_c1.jsonl"], "l4d_api"),
    ("Jev L4-D (sequential, secondary)", "jev_l4d", "jev-latest", "L4D", "cloud-decision",
     "Jev API (cloud); client dell", "sum of per-call latencies", ["l4d_ft/results/jev_l4d/layer3/lat300_c1.jsonl"],
     "l4d_api"),
]
# LoRA rows (l4d-train lane runs): primary = fallback conv (the prediction configuration), "(kernel)" = secondary
for suffix, label, kern in (("fallback", "", FALLBACK), ("kernel", " (kernel, secondary)", KERNEL)):
    SPECS += [
        (f"LoRA L4-D (opt.){label}", "lora_l4d_opt", "qwen3.5-4b + LoRA (L4-D facts)", "L4D", "local-FT", GPU_L4D,
         kern, [f"l4d_ft/results/lora_l4d_opt/layer3/lat300_c1_{suffix}.jsonl"], "l4d"),
        (f"LoRA L4-D (fact FT){label}", "lora_l4d", "qwen3.5-4b + LoRA (L4-D facts)", "L4D", "local-FT", GPU_L4D,
         kern, [f"l4d_ft/results/lora_l4d/layer3/lat300_c1_{suffix}.jsonl"], "l4d"),
        *[(f"LoRA {k} (unit-label FT){label}", f"lora_{k}", "qwen3.5-4b + LoRA (unit label)", k, "local-FT",
           GPU_L4D, kern, [f"l4d_ft/results/kernel/decision_ft/{suffix}/layer3/latency300_{k}_v1.jsonl"], "lora")
          for k in (("L1", "L3") if suffix == "fallback" else ())]]  # old LoRA: DeadFree fallback run only
SPECS += [
    ("VulnLLM-R-7B (policy)", "vulnllmr", "VulnLLM-R-7B", "policy", "other-local", "1x RTX 3090 (184-toast GPU 1); "
     "client dell", "vLLM", ["vulnllmr/results/vulnllm_r_7b/layer3/lat300_c1_policy_r1.jsonl"], "plain"),
    ("Clang SA", "clang_sa", "clang 23.1.6", "", "static", DELL, "", ["static/results/clang_sa/layer3/lat300_c1.jsonl"],
     "plain"),
    ("Cppcheck", "cppcheck", "cppcheck 2.22.0", "", "static", DELL, "",
     ["static/results/cppcheck/layer3/lat300_c1.jsonl"], "plain"),
    ("Infer", "infer", "infer 1.3.0", "", "static", DELL, "", ["static/results/infer/layer3/lat300_c1.jsonl"], "plain"),
    ("grep v0", "grep_v0", "grep v0", "", "static", DELL, "", ["static/results/grep_v0/layer3/lat300_c1.jsonl"],
     "plain"),
    ("CodeQL (per unit, 100 units)", "codeql", "codeql 2.27.5", "", "static", DELL, "",
     ["static/results/codeql/layer3/lat100_c1.jsonl"], "plain"),
    ("ASan/LSan (dynamic)", "asan_lsan", "ASan+LSan", "", "dynamic-reference", DELL, "",
     ["data/results/asan_lsan/stress/lat300_c1.jsonl"], "plain"),
    ("Dynamic enhanced", "dynamic_enhanced", "ASan+LSan enhanced", "", "dynamic-reference", DELL, "",
     ["data/results/dynamic_enhanced/stress/lat300_c1.jsonl"], "plain"),
]


def build_row(spec, clang: dict | None) -> dict:
    method, qkey, model, strategy, group, hardware, kernel, patterns, kind = spec
    role = "secondary" if "secondary" in method else "primary"
    row = {"method": method, "role": role, "quality_key": qkey, "model": model, "strategy": strategy, "group": group,
           "hardware": hardware, "kernel": kernel, "n": "", "median_s": "pending", "p90_s": "pending",
           "mean_s": "pending", "components": "", "run_file": " | ".join(patterns), "measured_utc": "", "note": ""}
    path = newest(patterns)
    if path is None:
        row["note"] = "pending: run file missing"
        return row
    rows = read_jsonl(path)
    meta_path = path.with_suffix(".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    row["run_file"] = str(path.relative_to(JF))
    row["measured_utc"] = meta.get("start_utc") or (meta.get("latency_lock") or {}).get("start_utc", "")
    bad = [r for r in rows if r.get("status") != "ok"]
    ok = [r for r in rows if r.get("status") == "ok" and r.get("latency_s") is not None]
    notes = [f"{len(bad)} non-ok rows excluded"] if bad else []
    model_s = [r["latency_s"] for r in ok]
    components = {}
    if kind in ("llm", "intern", "lora"):
        components["model_call_s"] = comp(model_s)
        if kind == "lora":
            components["server_s"] = comp([r["extra"]["server_latency_s"] for r in ok])
            components["forward_s"] = comp([r["extra"]["server_forward_s"] for r in ok])
        if kind == "intern":
            components["server_s"] = comp([r["extra"]["latency_ms_server"] / 1000 for r in ok])
            components["forward_s"] = comp([r["extra"]["forward_ms"] / 1000 for r in ok])
        if strategy == "L4":
            components["souffle_s"] = comp([r["extra"].get("souffle_s") or 0.0 for r in ok])
            components["model_call_s"] = comp([r["latency_s"] - (r["extra"].get("souffle_s") or 0.0) for r in ok])
        e2e = model_s
        if strategy == "L3" and not meta.get("includes_clang_sa"):
            if clang is None:
                row.update(n=len(ok), components=json.dumps(components),
                           note="pending: Clang SA layer3 lat300_c1 missing (L3 = clang + model call)")
                return row
            missing = [r["unit_id"] for r in ok if r["unit_id"] not in clang]
            assert not missing, f"{path}: {len(missing)} units without Clang SA c1 time"
            components["clang_sa_s"] = comp([clang[r["unit_id"]] for r in ok])
            e2e = [r["latency_s"] + clang[r["unit_id"]] for r in ok]
    elif kind == "l4d":
        ex = [r["extra"] for r in ok]
        for key in ("parse_s", "parse_prune_s", "http_s", "derive_s", "server_latency_s", "server_forward_s",
                    "n_questions"):
            if ex and key in ex[0]:
                components[key] = comp([e[key] for e in ex])
        e2e = model_s
        if meta.get("gpu_note"):
            notes.append(f"gpu_note: {meta['gpu_note']}")
    elif kind == "l4d_api":
        ex = [r["extra"] for r in ok]
        for key in ("parse_prune_s", "http_s", "max_call_s", "sum_call_s", "derive_s", "n_questions"):
            components[key] = comp([e[key] for e in ex])
        if "sequential" in method:
            e2e = [e["sequential_s"] for e in ex]
            notes.append("parse/prune + sum of per-call latencies + derive")
        else:
            e2e = model_s
            notes.append("questions of a unit sent concurrently (one thread per question)")
    else:
        e2e = model_s
    if qkey == "codeql":
        notes.append("first 100 latency300 units, per-unit database build + query")
    row.update(n=len(ok), components=json.dumps(components), note="; ".join(notes), **stats(e2e))
    return row


def main() -> None:
    clang = clang_times()
    rows = [build_row(spec, clang) for spec in SPECS]
    with open(HERE / "latency_deadfree.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(f"{r['method']:<40} n={r['n']!s:<4} median={r['median_s']!s:<9} p90={r['p90_s']!s:<9} {r['note']}")


if __name__ == "__main__":
    main()
