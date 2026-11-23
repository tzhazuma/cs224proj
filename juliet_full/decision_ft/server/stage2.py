"""Decision-model stage 2 on 184-toast (README of juliet_full/decision_ft, sections 8-10).

  stage2.py predict --strategy L1 --fold 0   selected adapter of job <strategy>_fold<k>: layer-1 held-out fold unmerged
                                             (appendix check) and merged, then the merged model on the eval units of
                                             fold k of the other layers (L1: layer3, placebo, original; L3: layer3,
                                             placebo); dev predictions of stage 1 are copied with the final model name
  stage2.py readout --strategy L1            zero-shot read-out: base Qwen3.5-4B + step-0 head (tied Yes/No rows),
                                             s = logit_Yes - logit_No, pred = s > 0; layer-1 eval + dev, layer3 eval
  stage2.py combine                          per layer and strategy: <strategy>_cv_v1.jsonl = the three fold files
  stage2.py serve --port 8003                HTTP endpoint (contract section 6), one merged fold model at a time

Outputs follow contract section 4 under $DFT/results/<method>/<layer>/ (collect.sh copies them to dell).
Every unit is scored at batch size 1, one forward, with the threshold the fold model chose on its merged dev scores.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dft import (DFT, MODEL_DIR, Scorer, auroc, best_threshold, load_checkpoint, macro_f1,  # noqa: E402
                 read_jsonl, sha256_text, utc_now, versions, write_json)

RUN_TAG = "v1"
OTHER_LAYERS = {"L1": ("layer3", "placebo", "original"), "L3": ("layer3", "placebo")}
QUESTION = "Does the executed code unit leak heap memory? Answer Yes or No."  # = render_data.QUESTION
RESULTS = DFT / "results"
LATENCY_NOTE = ("latency_s = server-side time per unit at batch size 1 on one RTX 3090 with no other job on that GPU: "
                "host tensor build + H2D + forward + head + readout; excludes tokenisation and network")


def model_name(strategy: str, fold: int) -> str:
    return f"qwen3.5-4b-lora-{strategy}-fold{fold}"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    tmp.replace(path)


def encode_rows(rows: list[dict], scorer: Scorer, entry: dict) -> list[list[int]]:
    ids = scorer.encode([r["text"] for r in rows])
    mismatch = [r["unit_id"] for r, x in zip(rows, ids) if len(x) != r["n_tokens"]]
    assert not mismatch, f"token count differs from dell rendering: {mismatch[:3]}"
    assert entry["chat_template_sha256"] == sha256_text(scorer.tokenizer.chat_template)
    return ids


def metrics(scores: list[float], truth: list[int], threshold: float) -> dict:
    return {"n": len(scores), "auroc": auroc(scores, truth), "macro_f1": macro_f1(scores, truth, threshold),
            "accuracy": sum((s > threshold) == (t == 1) for s, t in zip(scores, truth)) / len(scores)}


def data_meta(entry: dict) -> dict:
    return {k: entry[k] for k in ("units_file", "units_sha256", "evidence_file", "evidence_sha256", "prompt_files",
                                  "question_sha256", "chat_template_sha256")}


# ----------------------------------------------------------------------------------------------- predict

def cmd_predict(args) -> None:
    strategy, fold = args.strategy, args.fold
    job_dir = DFT / strategy / f"fold{fold}"
    run_id = f"{strategy}_fold{fold}_{RUN_TAG}"
    status = json.loads((DFT / "status" / f"{strategy}_fold{fold}.json").read_text())
    assert status["state"] == "done", status
    selection = json.loads((job_dir / "selection.json").read_text())
    threshold, checkpoint = selection["threshold"], selection["checkpoint"]
    manifest = json.loads((DFT / "data" / "manifest.json").read_text())
    name = model_name(strategy, fold)
    scorer = Scorer("cuda")
    load_checkpoint(scorer, job_dir)  # = ckpt/<checkpoint>, copied to the job directory by dft.py train
    scorer.text_model.eval()
    common = {"method": "decision_ft", "strategy": strategy, "model": name, "base_model": str(MODEL_DIR),
              "versions": versions(), "kernels": scorer.kernels, "host": socket.gethostname(),
              "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"), "concurrency": 1,
              "selection": selection, "latency_note": LATENCY_NOTE}

    def rows_out(rows, scores, lat, layer, split, merged):
        return [{"unit_id": r["unit_id"], "method": "decision_ft", "strategy": strategy, "model": name,
                 "layer": layer, "pred": 1 if s > threshold else 0, "score": s, "latency_s": t, "status": "ok",
                 "extra": {"fold": fold, "checkpoint": checkpoint, "threshold": threshold, "split": split,
                           "unit_set": r["set"], "unit_fold": r["fold"], "merged": merged}}
                for r, s, t in zip(rows, scores, lat)]

    def emit(path: Path, rows, scores, lat, layer, split, merged, entry, start, load_start, extra=None):
        write_jsonl(path, rows_out(rows, scores, lat, layer, split, merged))
        truth = [r["truth"] for r in rows]
        write_json(path.with_suffix(".meta.json"),
                   {**common, "layer": layer, "run_id": path.stem, "split": split, "merged": merged,
                    "n_units": len(rows), **data_meta(entry), "start_utc": start, "end_utc": utc_now(),
                    "loadavg_start": load_start, "loadavg_end": os.getloadavg(),
                    "metrics_at_threshold": metrics(scores, truth, threshold),
                    "latency_median_s": sorted(lat)[len(lat) // 2], **(extra or {})})

    # layer 1 held-out fold: unmerged (appendix check), then merged (reported)
    layer1_rows = read_jsonl(DFT / "data" / strategy / f"fold{fold}" / "pred.jsonl")
    assert all(r["set"] == "eval" and r["fold"] == fold for r in layer1_rows)
    layer1_ids = encode_rows(layer1_rows, scorer, manifest[strategy])
    scorer.score_timed(layer1_ids[:20])
    start, load_start = utc_now(), os.getloadavg()
    unmerged, unmerged_lat = scorer.score_timed(layer1_ids)
    emit(RESULTS / "decision_ft" / "layer1" / f"unmerged_{run_id}.jsonl", layer1_rows, unmerged, unmerged_lat,
         "layer1", "heldout_fold", False, manifest[strategy], start, load_start)
    scorer.peft_model.merge_adapter()  # W <- W + (alpha/r) B A in GPU memory (BF16); never saved
    scorer.score_timed(layer1_ids[:20])
    start, load_start = utc_now(), os.getloadavg()
    merged, merged_lat = scorer.score_timed(layer1_ids)
    stage1 = {r["unit_id"]: r["score"] for r in read_jsonl(job_dir / "results" / f"{run_id}.jsonl")}
    d_stage1 = [abs(stage1[r["unit_id"]] - s) for r, s in zip(layer1_rows, merged)]
    d_merge = [abs(a - b) for a, b in zip(merged, unmerged)]
    checks = {"stage1_rescore": {"max_abs_diff": max(d_stage1), "n_abs_diff_gt_1e-3": sum(d > 1e-3 for d in d_stage1),
                                 "note": "same merged model, stage-1 prediction file; L3 fold 0 had 28 units with "
                                         "pre-fix (full_v1) Clang evidence in stage 1"},
              "merged_vs_unmerged": {"max_abs_diff": max(d_merge), "mean_abs_diff": sum(d_merge) / len(d_merge)}}
    emit(RESULTS / "decision_ft" / "layer1" / f"{run_id}.jsonl", layer1_rows, merged, merged_lat, "layer1",
         "heldout_fold", True, manifest[strategy], start, load_start, {"checks": checks})
    print(json.dumps({"job": run_id, "layer1": checks}), flush=True)

    # dev predictions of stage 1 (merged, batch 1; the threshold was chosen on them), final model name
    dev = read_jsonl(job_dir / "results" / f"dev_{run_id}.jsonl")
    for r in dev:
        r["model"] = name
        r["extra"]["merged"] = True
    write_jsonl(RESULTS / "decision_ft" / "layer1" / f"dev_{run_id}.jsonl", dev)
    dev_meta = json.loads((job_dir / "results" / f"dev_{run_id}.meta.json").read_text())
    write_json(RESULTS / "decision_ft" / "layer1" / f"dev_{run_id}.meta.json",
               {**dev_meta, "model": name, "note": "stage-1 file (dft.py train) with the final model name"})

    for layer in OTHER_LAYERS[strategy]:
        entry = manifest[f"{layer}/{strategy}"]
        rows = [r for r in read_jsonl(DFT / "data" / layer / strategy / "eval.jsonl") if r["fold"] == fold]
        ids = encode_rows(rows, scorer, entry)
        start, load_start = utc_now(), os.getloadavg()
        scores, lat = scorer.score_timed(ids)
        emit(RESULTS / "decision_ft" / layer / f"{run_id}.jsonl", rows, scores, lat, layer, "heldout_fold", True,
             entry, start, load_start)
        print(json.dumps({"job": run_id, "layer": layer, **metrics(scores, [r["truth"] for r in rows], threshold)}),
              flush=True)


# ----------------------------------------------------------------------------------------------- read-out

def cmd_readout(args) -> None:
    strategy = args.strategy
    manifest = json.loads((DFT / "data" / "manifest.json").read_text())
    scorer = Scorer("cuda", lora=False)  # base model + head = tied Yes/No rows (the step-0 model)
    scorer.text_model.eval()
    inputs = {
        "dev_layer1": ("layer1", "dev", read_jsonl(DFT / "data" / strategy / "fold0" / "dev.jsonl"), manifest[strategy]),
        "layer1": ("layer1", "eval", [r for k in (0, 1, 2)
                                      for r in read_jsonl(DFT / "data" / strategy / f"fold{k}" / "pred.jsonl")],
                   manifest[strategy]),
        "layer3": ("layer3", "eval", read_jsonl(DFT / "data" / "layer3" / strategy / "eval.jsonl"),
                   manifest[f"layer3/{strategy}"]),
    }
    scores_by = {}
    for key, (layer, split, rows, entry) in inputs.items():
        ids = encode_rows(rows, scorer, entry)
        scorer.score_timed(ids[:20])
        start, load_start = utc_now(), os.getloadavg()
        scores, lat = scorer.score_timed(ids)
        scores_by[key] = (layer, split, rows, entry, scores, lat, start, load_start)
    _, _, dev_rows, _, dev_scores, _, _, _ = scores_by["dev_layer1"]
    dev_truth = [r["truth"] for r in dev_rows]
    dev_threshold, dev_f1 = best_threshold(dev_scores, dev_truth)
    for key, (layer, split, rows, entry, scores, lat, start, load_start) in scores_by.items():
        run_id = f"{'dev_' if split == 'dev' else ''}{strategy}_{RUN_TAG}"
        path = RESULTS / "qwen_readout_zeroshot" / layer / f"{run_id}.jsonl"
        write_jsonl(path, [{"unit_id": r["unit_id"], "method": "qwen_readout_zeroshot", "strategy": strategy,
                            "model": "qwen3.5-4b", "layer": layer, "pred": 1 if s > 0 else 0, "score": s,
                            "latency_s": t, "status": "ok",
                            "extra": {"threshold_rule": "s > 0", "split": split, "unit_set": r["set"],
                                      "unit_fold": r["fold"], "dev_threshold": dev_threshold,
                                      "pred_at_dev_threshold": 1 if s > dev_threshold else 0}}
                           for r, s, t in zip(rows, scores, lat)])
        truth = [r["truth"] for r in rows]
        write_json(path.with_suffix(".meta.json"), {
            "method": "qwen_readout_zeroshot", "strategy": strategy, "model": "qwen3.5-4b", "layer": layer,
            "run_id": run_id, "split": split, "n_units": len(rows), "base_model": str(MODEL_DIR),
            "readout": "base Qwen3.5-4B (no adapter), FP32 2x2560 head = tied output rows of Yes/No (= step-0 head of "
                       "decision_ft), s = logit_Yes - logit_No at the last prompt position, same prompts as decision_ft",
            "primary_rule": "pred = s > 0",
            "secondary_rule": {"dev_threshold": dev_threshold, "dev_macro_f1_at_dev_threshold": dev_f1,
                               "note": "threshold maximising macro-F1 on layer-1 dev; extra.pred_at_dev_threshold"},
            **data_meta(entry), "versions": versions(), "kernels": scorer.kernels, "host": socket.gethostname(),
            "concurrency": 1, "start_utc": start, "end_utc": utc_now(), "loadavg_start": load_start,
            "loadavg_end": os.getloadavg(), "latency_note": LATENCY_NOTE,
            "latency_median_s": sorted(lat)[len(lat) // 2],
            "metrics_at_0": metrics(scores, truth, 0.0), "metrics_at_dev_threshold": metrics(scores, truth, dev_threshold)})
        print(json.dumps({"readout": run_id, "layer": layer, **metrics(scores, truth, 0.0),
                          "macro_f1_at_dev_threshold": macro_f1(scores, truth, dev_threshold)}), flush=True)


# ----------------------------------------------------------------------------------------------- combine

def cmd_combine(args) -> None:
    """<strategy>_cv_v1.jsonl per layer: the eval units of all three folds, each from its held-out fold model."""
    for layer in ("layer1", "layer3", "placebo", "original"):
        for strategy in ("L1", "L3"):
            parts = [RESULTS / "decision_ft" / layer / f"{strategy}_fold{k}_{RUN_TAG}.jsonl" for k in (0, 1, 2)]
            if not all(p.exists() for p in parts):
                continue
            rows = [r for p in parts for r in read_jsonl(p)]
            assert len({r["unit_id"] for r in rows}) == len(rows)
            run_id = f"{strategy}_cv_{RUN_TAG}"
            write_jsonl(RESULTS / "decision_ft" / layer / f"{run_id}.jsonl", rows)
            metas = [json.loads(p.with_suffix(".meta.json").read_text()) for p in parts]
            write_json(RESULTS / "decision_ft" / layer / f"{run_id}.meta.json", {
                "method": "decision_ft", "strategy": strategy, "layer": layer, "run_id": run_id,
                "model": f"qwen3.5-4b-lora-{strategy}-fold{{0,1,2}} (per unit: extra.fold)",
                "n_units": len(rows), "parts": [p.name for p in parts],
                "start_utc": min(m["start_utc"] for m in metas), "end_utc": max(m["end_utc"] for m in metas),
                "fold_meta": metas})
            print(layer, strategy, len(rows))


# ----------------------------------------------------------------------------------------------- serve

def load_prompt_renderer():
    """PromptSet / task.txt from server/vendor/ (upload.sh copies them from the repo, read-only)."""
    sys.path.insert(0, str(DFT / "server" / "vendor" / "juliet_full" / "llm"))
    from llmlane.prompts import PromptSet, read_prompt
    return {s: PromptSet(s) for s in ("L1", "L3")}, read_prompt("task.txt")


def render_prompt(tokenizer, prompts: dict, system: str, code: str, language: str, strategy: str, evidence) -> str:
    """Same text as render_data.render: user = PromptSet(strategy).user_body + "\n\n" + QUESTION, chat template with
    add_generation_prompt=True, enable_thinking=False. L3 evidence: a list of Clang SA warnings ({checker, message,
    model_text_line}) or a full evidence record ({status, warnings}); null renders "no result" as for a missing record."""
    unit = {"model_text": code, "language": language, "line_map": None}
    record = None
    if strategy == "L3":
        record = {"warnings": evidence} if isinstance(evidence, list) else evidence
    body, _ = prompts[strategy].user_body(unit, record)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": body + "\n\n" + QUESTION}]
    return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)


def cmd_render_check(args) -> None:
    """CPU check: render_prompt on dell-exported units (unit_id, model_text, language, warnings) == rendered data."""
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    prompts, system = load_prompt_renderer()
    units = {r["unit_id"]: r for r in read_jsonl(Path(args.units))}
    out = {}
    for spec in args.data:
        strategy = "L3" if "/L3/" in f"/{spec}" else "L1"
        rows = read_jsonl(DFT / "data" / spec)
        bad = [r["unit_id"] for r in rows
               if render_prompt(tokenizer, prompts, system, units[r["unit_id"]]["model_text"],
                                units[r["unit_id"]]["language"], strategy,
                                units[r["unit_id"]]["warnings"]) != r["text"]]
        out[spec] = {"n": len(rows), "n_mismatch": len(bad), "first": bad[:3]}
    print(json.dumps(out, indent=1))
    assert not any(v["n_mismatch"] for v in out.values())

class FoldModels:
    """All six selected adapters + heads cached on the GPU; one is merged into the BF16 weights at a time.
    Switching restores the exact base weights of the LoRA-targeted layers (kept as a GPU copy, so no BF16
    unmerge drift), loads the adapter and merges it: the merged weights equal those of `predict`."""

    def __init__(self):
        from peft import set_peft_model_state_dict
        from peft.tuners.lora import LoraLayer
        from safetensors.torch import load_file
        self._set_state = set_peft_model_state_dict
        self.scorer = Scorer("cuda")
        self.scorer.text_model.eval()
        self.lora_layers = {n: m for n, m in self.scorer.peft_model.named_modules() if isinstance(m, LoraLayer)}
        self.base_weights = {n: m.base_layer.weight.detach().clone() for n, m in self.lora_layers.items()}
        self.models = {}
        for strategy in ("L1", "L3"):
            for fold in (0, 1, 2):
                job_dir = DFT / strategy / f"fold{fold}"
                selection = json.loads((job_dir / "selection.json").read_text())
                adapter = {k: v.to("cuda") for k, v in load_file(str(job_dir / "adapter_model.safetensors")).items()}
                head = torch.load(job_dir / "head.pt")["weight"].to("cuda")
                self.models[model_name(strategy, fold)] = {"strategy": strategy, "fold": fold, "adapter": adapter,
                                                           "head": head, "threshold": selection["threshold"],
                                                           "checkpoint": selection["checkpoint"]}
        self.active = None
        self.lock = threading.Lock()
        self.prompts, self.system = load_prompt_renderer()

    @torch.no_grad()
    def activate(self, name: str) -> float:
        if name == self.active:
            return 0.0
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        peft_model = self.scorer.peft_model
        if self.active is not None:
            peft_model.unmerge_adapter()
            for n, m in self.lora_layers.items():
                m.base_layer.weight.copy_(self.base_weights[n])
        result = self._set_state(peft_model, self.models[name]["adapter"])
        assert not getattr(result, "unexpected_keys", []), result
        self.scorer.head.weight.copy_(self.models[name]["head"])
        peft_model.merge_adapter()
        torch.cuda.synchronize()
        self.active = name
        return time.perf_counter() - t0

    def render(self, code: str, language: str, strategy: str, evidence) -> str:
        return render_prompt(self.scorer.tokenizer, self.prompts, self.system, code, language, strategy, evidence)

    @torch.no_grad()
    def score(self, req: dict) -> dict:
        name = req.get("model")
        if name not in self.models:
            raise ValueError(f"unknown model {name!r}; available: {sorted(self.models)}")
        spec = self.models[name]
        strategy = req.get("strategy") or spec["strategy"]
        if strategy != spec["strategy"]:
            raise ValueError(f"model {name} was trained on {spec['strategy']} inputs, request says {strategy}")
        if req.get("language") not in ("c", "cpp") or not isinstance(req.get("code"), str):
            raise ValueError("need code (string) and language c|cpp")
        with self.lock:
            switch_s = self.activate(name)
            t0 = time.perf_counter()
            text = self.render(req["code"], req["language"], strategy, req.get("evidence"))
            ids = self.scorer.encode([text])
            scores, lat = self.scorer.score_timed(ids)
            total = time.perf_counter() - t0
        s = scores[0]
        return {"score": s, "threshold": spec["threshold"], "pred": 1 if s > spec["threshold"] else 0,
                "latency_ms_server": total * 1000, "forward_ms": lat[0] * 1000, "switch_ms": switch_s * 1000,
                "model": name, "checkpoint": spec["checkpoint"], "n_tokens": len(ids[0]),
                "prompt_sha256": sha256_text(text)}


def cmd_serve(args) -> None:
    import uvicorn
    from fastapi import Body, FastAPI, HTTPException

    models = FoldModels()
    started = utc_now()
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"ok": True, "models": sorted(models.models), "active": models.active, "started_utc": started,
                "thresholds": {k: v["threshold"] for k, v in models.models.items()},
                "switch_ms_steady": getattr(models, "switch_ms_steady", None),
                "gpu": torch.cuda.get_device_name(0),
                "gpu_mem_allocated_gb": round(torch.cuda.memory_allocated() / 2**30, 2)}

    @app.post("/score")
    async def score(req: dict = Body(...)):  # no Request annotation: postponed annotations would not resolve it
        try:
            return await __import__("asyncio").to_thread(models.score, req)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    warm_code = "#include <stdlib.h>\n\nvoid sym_0()\n{\n    char * data = (char *)malloc(10);\n    free(data);\n}"
    switch_ms = {}
    for _ in range(2):  # warm-up (Triton JIT) and switch cost (second round = steady state)
        for name in sorted(models.models):
            out = models.score({"model": name, "code": warm_code, "language": "c", "evidence": []})
            switch_ms[name] = round(out["switch_ms"], 1)
    models.switch_ms_steady = switch_ms
    print(json.dumps({"ready": utc_now(), "models": sorted(models.models), "switch_ms_steady": switch_ms,
                      "gpu_mem_allocated_gb": round(torch.cuda.memory_allocated() / 2**30, 2),
                      "gpu_mem_peak_gb": round(torch.cuda.max_memory_allocated() / 2**30, 2)}), flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("predict")
    p.add_argument("--strategy", choices=("L1", "L3"), required=True)
    p.add_argument("--fold", type=int, choices=(0, 1, 2), required=True)
    p = sub.add_parser("readout")
    p.add_argument("--strategy", choices=("L1", "L3"), required=True)
    sub.add_parser("combine")
    p = sub.add_parser("render-check")
    p.add_argument("--units", required=True, help="jsonl: unit_id, model_text, language, warnings")
    p.add_argument("data", nargs="+", help="files under $DFT/data, e.g. L3/fold0/dev.jsonl")
    p = sub.add_parser("serve")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8003)
    args = parser.parse_args()
    {"predict": cmd_predict, "readout": cmd_readout, "combine": cmd_combine, "render-check": cmd_render_check,
     "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
