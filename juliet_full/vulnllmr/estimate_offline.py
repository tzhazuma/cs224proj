#!/usr/bin/env python3
"""Offline (CPU) checks for the VulnLLM-R-7B runs: render prompts, count tokens, estimate GPU wall-clock.

    .venv/bin/python estimate_offline.py            # writes build/estimate.json and prints a summary

Prompt tokens: the model's own tokenizer + chat template over the exact requests run_vulnllmr.py would send
(20 rendered dev units are also written to build/prompts/layer1/dev20_policy.txt for eyeballing).
Output tokens: paper sec. 5.3 reports a mean of 362 output tokens for VulnLLM-R (max 8192); the teacher
trajectories it was distilled from (~/.cache/vllmr/Distill-*.parquet, before summary-based training) give an
upper bound, measured here on their Juliet-derived rows.
Throughput: assumed decode rates for Qwen2.5-7B bf16 on one RTX 3090 under vLLM (stated in the output).
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_vulnllmr  # noqa: E402
import vulnllmr_prompt as prompt  # noqa: E402

MODEL_DIR = Path.home() / "tools" / "cs224" / "models" / "VulnLLM-R-7B"
DISTILL = [Path.home() / ".cache" / "vllmr" / f"Distill-{t}.parquet" for t in ("DeepSeek", "QwQ")]
TEST_401 = Path.home() / ".cache" / "vllmr" / "test-401.json"
PAPER_MEAN_OUTPUT = 362
# Assumed aggregate rates on one RTX 3090 (vLLM 0.x, bf16 7B, ~64 concurrent short sequences): decode is
# memory-bandwidth bound (936 GB/s / 15.2 GB weights = ~60 steps/s upper bound); batched decode 1000-1500 tok/s;
# prefill ~6000 tok/s.  Single-stream (c1) decode ~45 tok/s.
DECODE_TOK_S = {"low": 1000, "high": 1500}
PREFILL_TOK_S = 6000
C1_DECODE_TOK_S = 45


def pct(values: list[int], q: float) -> int:
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def stats(values: list[int]) -> dict[str, float]:
    return {"n": len(values), "mean": round(statistics.mean(values), 1), "median": statistics.median(values),
            "p95": pct(values, 0.95), "max": max(values)}


def main() -> int:
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)

    def prompt_tokens(code: str, unit_id: str, hint: str) -> int:
        ids = tok.apply_chat_template(prompt.messages(code, unit_id, hint), add_generation_prompt=True,
                                      tokenize=True)
        return len(ids)

    out: dict = {"tokenizer": str(MODEL_DIR), "prompt_tokens": {}, "assumptions": {
        "paper_mean_output_tokens": PAPER_MEAN_OUTPUT, "decode_tok_s_one_3090": DECODE_TOK_S,
        "prefill_tok_s_one_3090": PREFILL_TOK_S, "c1_decode_tok_s": C1_DECODE_TOK_S,
        "two_gpus": "two independent servers (data parallel), units split between them: time / 2"}}

    # 20 dev units, rendered and counted
    units = [json.loads(line) for line in (run_vulnllmr.DATA_BUILD / "layer1.jsonl").read_text().splitlines()]
    dev20 = [u for u in units if u["set"] == "dev"][:20]
    dump = HERE / "build" / "prompts" / "layer1" / "dev20_policy.txt"
    dump.parent.mkdir(parents=True, exist_ok=True)
    with dump.open("w") as handle:
        for u in dev20:
            text = tok.apply_chat_template(prompt.messages(u["model_text"], u["unit_id"], "policy"),
                                           add_generation_prompt=True, tokenize=False)
            handle.write(f"===== {u['unit_id']}\n{text}\n")
    out["prompt_tokens"]["layer1_dev20_policy"] = stats([prompt_tokens(u["model_text"], u["unit_id"], "policy")
                                                         for u in dev20])
    out["prompt_tokens"]["layer1_dev20_nohint"] = stats([prompt_tokens(u["model_text"], u["unit_id"], "none")
                                                         for u in dev20])
    # all units of every layer (policy hint)
    per_layer: dict[str, dict[str, list[int]]] = {}
    for layer in run_vulnllmr.LAYERS:
        rows = [json.loads(line) for line in (run_vulnllmr.DATA_BUILD / f"{layer}.jsonl").read_text().splitlines()]
        counts = {"dev": [], "eval": []}
        for u in rows:
            counts[u["set"]].append(prompt_tokens(u["model_text"], u["unit_id"], "policy"))
        per_layer[layer] = counts
        out["prompt_tokens"][f"{layer}_all_policy"] = stats(counts["dev"] + counts["eval"])
    # their own Juliet CWE-401 test rows, same template
    if TEST_401.exists():
        rows = json.loads(TEST_401.read_text())
        out["prompt_tokens"]["authors_test401_juliet_policy"] = stats(
            [prompt_tokens(r["code"], str(r["idx"]), "policy") for r in rows if r["dataset"] == "juliet 1.3"])

    # teacher output lengths (upper bound: pre-summary distillation data)
    try:
        import pandas as pd
        teacher: dict[str, dict] = {}
        for path in DISTILL:
            df = pd.read_parquet(path)
            lens_all, lens_juliet = [], []
            for conv in df.conversations:
                n = len(tok(conv[1]["value"])["input_ids"])
                lens_all.append(n)
                if "std_testcase" in conv[0]["value"]:
                    lens_juliet.append(n)
            teacher[path.stem] = {"all": stats(lens_all), "juliet_rows": stats(lens_juliet)}
        out["teacher_output_tokens"] = teacher
    except (ImportError, FileNotFoundError) as exc:
        out["teacher_output_tokens"] = f"skipped: {exc}"

    # wall-clock estimates
    teacher_juliet_mean = statistics.mean(v["juliet_rows"]["mean"] for v in out["teacher_output_tokens"].values()) \
        if isinstance(out["teacher_output_tokens"], dict) else 1500
    scenarios = {"paper_mean": PAPER_MEAN_OUTPUT, "2x_paper": 2 * PAPER_MEAN_OUTPUT,
                 "teacher_juliet_mean": round(teacher_juliet_mean)}
    jobs = {"a_layer1_dev_eval": [("layer1", ("dev", "eval"))],
            "b_layer3_placebo_original_eval": [(layer, ("eval",)) for layer in ("layer3", "placebo", "original")],
            "b_one_layer_eval_layer3": [("layer3", ("eval",))]}
    est: dict = {}
    for job, parts in jobs.items():
        n_units = sum(len(per_layer[layer][s]) for layer, sets in parts for s in sets)
        n_prompt = sum(sum(per_layer[layer][s]) for layer, sets in parts for s in sets)
        est[job] = {"units": n_units, "prompt_tokens": n_prompt}
        for name, out_len in scenarios.items():
            prefill_h = n_prompt / PREFILL_TOK_S / 3600
            hours = {f"{gpus}gpu_{k}": round((prefill_h + n_units * out_len / rate / 3600) / gpus, 2)
                     for gpus in (1, 2) for k, rate in (("fast", DECODE_TOK_S["high"]), ("slow", DECODE_TOK_S["low"]))}
            est[job][f"hours_out{out_len}_{name}"] = hours
    est["c1_latency300"] = {"units": 300, **{
        f"hours_out{v}_{k}": round(300 * (v / C1_DECODE_TOK_S + 0.2) / 3600, 2) for k, v in scenarios.items()}}
    out["estimates"] = est
    (HERE / "build" / "estimate.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
