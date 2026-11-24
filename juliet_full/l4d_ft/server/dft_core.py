"""Copied from juliet_full/decision_ft/server/dft.py (lane decision_ft, read-only there) for lane l4d-train.

Kept unchanged: Scorer (Qwen3.5-4B BF16 text stack + LoRA r16/a32/dropout 0.05 on LORA_TARGET_REGEX, FP32 2x2560
head initialised from the tied Yes/No rows, s = logit_Yes - logit_No at the last prompt position), metrics
(auroc, macro_f1, best_threshold), lr_lambda, save_checkpoint/load_checkpoint, versions and the small helpers.
Changed: DFT -> L4D root, MODEL_DIR unchanged; the decision_ft-specific data/train/eval code is not copied
(l4dft.py has the L4-D versions).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import torch
import torch.nn.functional as F  # noqa: F401

L4D = Path(os.environ.get("L4D", Path.home() / "disk4/cs224/l4d_ft"))

MODEL_DIR = Path.home() / "disk4/cs224/models/Qwen3.5-4B"
SEED = 20261123
LORA_TARGET_REGEX = (r"model\.layers\.\d+\.(?:self_attn\.(?:q_proj|k_proj|v_proj|o_proj)"
                     r"|linear_attn\.(?:in_proj_qkv|in_proj_z|in_proj_a|in_proj_b|out_proj)"
                     r"|mlp\.(?:gate_proj|up_proj|down_proj))")
EXPECTED_LORA_PARAMS = 32_464_896


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    tmp.replace(path)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ----------------------------------------------------------------------------------------------- metrics

def auroc(scores: list[float], truth: list[int]) -> float:
    """Mann-Whitney AUROC with average ranks for ties."""
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    n_pos = sum(truth)
    n_neg = len(truth) - n_pos
    rank_pos = sum(r for r, t in zip(ranks, truth) if t == 1)
    return (rank_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def macro_f1(scores: list[float], truth: list[int], threshold: float) -> float:
    pred = [1 if s > threshold else 0 for s in scores]
    f1s = []
    for cls in (1, 0):
        tp = sum(1 for p, t in zip(pred, truth) if p == cls and t == cls)
        fp = sum(1 for p, t in zip(pred, truth) if p == cls and t != cls)
        fn = sum(1 for p, t in zip(pred, truth) if p != cls and t == cls)
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0)
    return sum(f1s) / 2


def best_threshold(scores: list[float], truth: list[int]) -> tuple[float, float]:
    """Threshold on s maximising dev macro-F1 (pred = s > threshold). Candidates: midpoints between consecutive
    distinct scores plus one below the minimum and one above the maximum; ties -> the candidate closest to 0."""
    values = sorted(set(scores))
    candidates = [values[0] - 1.0] + [(a + b) / 2 for a, b in zip(values, values[1:])] + [values[-1] + 1.0]
    best = max(candidates, key=lambda c: (round(macro_f1(scores, truth, c), 12), -abs(c)))
    return best, macro_f1(scores, truth, best)


# ----------------------------------------------------------------------------------------------- model

class Scorer:
    def __init__(self, device: str, lora: bool = True):
        from transformers import AutoTokenizer, Qwen3_5ForCausalLM
        import transformers.models.qwen3_5.modeling_qwen3_5 as qwen_mod

        self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
        yes = self.tokenizer.encode("Yes", add_special_tokens=False)
        no = self.tokenizer.encode("No", add_special_tokens=False)
        assert len(yes) == 1 and len(no) == 1, (yes, no)
        self.yes_id, self.no_id = yes[0], no[0]
        # Text stack only: Qwen3_5ForCausalLM ignores model.visual.* and mtp.* in the checkpoint.
        model, info = Qwen3_5ForCausalLM.from_pretrained(str(MODEL_DIR), dtype=torch.bfloat16,
                                                         attn_implementation="sdpa", output_loading_info=True)
        assert not info["missing_keys"] and not info["mismatched_keys"], info
        assert model.lm_head.weight.data_ptr() == model.model.embed_tokens.weight.data_ptr(), "lm_head not tied"
        model.to(device)
        model.config.use_cache = False
        for p in model.parameters():
            p.requires_grad_(False)
        self.kernels = {}
        for name in ("torch_chunk_gated_delta_rule", "causal_conv1d_fn"):
            fn = getattr(qwen_mod, name)
            impl = __import__("inspect").getclosurevars(fn).nonlocals.get("implementation", fn) if fn else None
            self.kernels[name] = f"{impl.__module__}.{impl.__qualname__}" if impl is not None else "?"
        self.causal_lm = model
        rows = model.lm_head.weight[[self.yes_id, self.no_id]].detach().float().clone()
        self.head = torch.nn.Linear(2560, 2, bias=False, device=device, dtype=torch.float32)
        with torch.no_grad():
            self.head.weight.copy_(rows)
        self.tied_rows = rows
        self.peft_model = None
        self.n_lora_params = 0
        if lora:
            from peft import LoraConfig, get_peft_model
            config = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
                                target_modules=LORA_TARGET_REGEX)
            self.peft_model = get_peft_model(model, config)
            self.n_lora_params = sum(p.numel() for n, p in self.peft_model.named_parameters()
                                     if p.requires_grad and "lora_" in n)
            other = [n for n, p in self.peft_model.named_parameters() if p.requires_grad and "lora_" not in n]
            bad = [n for n, _ in self.peft_model.named_parameters() if "lora_" in n
                   and ("visual" in n or "mtp" in n or "embed" in n)]
            assert not other and not bad, (other[:3], bad[:3])
            assert self.n_lora_params == EXPECTED_LORA_PARAMS, self.n_lora_params
            self.lora_dtype = str(next(p.dtype for n, p in self.peft_model.named_parameters() if "lora_" in n))
        # Checkpointing is switched per micro-batch (set_grad_ckpt): without it ~10 MB activations per token.
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        from transformers.modeling_layers import GradientCheckpointingLayer
        self.ckpt_layers = [m for m in model.modules() if isinstance(m, GradientCheckpointingLayer)]
        assert len(self.ckpt_layers) == 32, len(self.ckpt_layers)
        self.text_model = model.model  # LoRA layers are injected in place, so this includes them.

    def set_grad_ckpt(self, on: bool) -> None:
        for layer in self.ckpt_layers:
            layer.gradient_checkpointing = on

    def lora_parameters(self):
        return [p for n, p in self.peft_model.named_parameters() if p.requires_grad and "lora_" in n]

    def encode(self, texts: list[str]) -> list[list[int]]:
        return [self.tokenizer(t, add_special_tokens=False)["input_ids"] for t in texts]

    def batch(self, ids: list[list[int]]) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Right padding; the score position (last prompt token) never attends to padding (causal model)."""
        n = max(len(x) for x in ids)
        pad = self.tokenizer.pad_token_id if self.tokenizer.pad_token_id is not None else 0
        input_ids = torch.full((len(ids), n), pad, dtype=torch.long)
        mask = torch.zeros((len(ids), n), dtype=torch.long)
        for i, x in enumerate(ids):
            input_ids[i, :len(x)] = torch.tensor(x)
            mask[i, :len(x)] = 1
        last = torch.tensor([len(x) - 1 for x in ids])
        return input_ids.to(self.device), mask.to(self.device), last.to(self.device)

    def hidden_last(self, ids: list[list[int]]) -> torch.Tensor:
        input_ids, mask, last = self.batch(ids)
        out = self.text_model(input_ids=input_ids, attention_mask=mask, use_cache=False)
        hidden = out.last_hidden_state  # post final norm
        return hidden[torch.arange(len(ids), device=self.device), last]

    def logits(self, ids: list[list[int]]) -> torch.Tensor:
        return self.head(self.hidden_last(ids).float())

    @torch.no_grad()
    def logits_batched(self, ids: list[list[int]], max_tokens: int = 8192) -> torch.Tensor:
        """Head logits [n, 2] (CPU, input order), length-sorted batches of at most max_tokens padded tokens."""
        order = sorted(range(len(ids)), key=lambda i: len(ids[i]))
        out = torch.zeros(len(ids), 2)
        start = 0
        while start < len(order):
            end = start + 1
            while end < len(order) and len(ids[order[end]]) * (end - start + 1) <= max_tokens:
                end += 1
            chunk = order[start:end]
            out[chunk] = self.logits([ids[i] for i in chunk]).float().cpu()
            start = end
        return out

    def score_batched(self, ids: list[list[int]], max_tokens: int = 8192) -> list[float]:
        lg = self.logits_batched(ids, max_tokens)
        return (lg[:, 0] - lg[:, 1]).tolist()

    @torch.no_grad()
    def score_timed(self, ids: list[list[int]]) -> tuple[list[float], list[float]]:
        """Batch size 1, one forward per unit; latency = host tensor build + H2D + forward + head + readout."""
        scores, latency = [], []
        for x in ids:
            torch.cuda.synchronize()
            t0 = time.perf_counter()
            lg = self.logits([x])
            s = (lg[0, 0] - lg[0, 1]).item()
            latency.append(time.perf_counter() - t0)
            scores.append(s)
        return scores, latency


# ----------------------------------------------------------------------------------------------- training

def lr_lambda(total_steps: int, warmup_steps: int):
    def f(step: int) -> float:
        if step < warmup_steps:
            return (step + 1) / warmup_steps
        progress = (step - warmup_steps) / max(1, total_steps - warmup_steps)
        return 0.5 * (1 + math.cos(math.pi * min(1.0, progress)))
    return f


def save_checkpoint(scorer: Scorer, path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    scorer.peft_model.save_pretrained(str(path))
    torch.save({"weight": scorer.head.weight.detach().cpu().clone(), "rows": ["Yes", "No"],
                "token_ids": [scorer.yes_id, scorer.no_id]}, path / "head.pt")


def load_checkpoint(scorer: Scorer, path: Path) -> None:
    from peft import set_peft_model_state_dict
    from safetensors.torch import load_file
    result = set_peft_model_state_dict(scorer.peft_model, load_file(str(path / "adapter_model.safetensors")))
    unexpected = getattr(result, "unexpected_keys", [])
    assert not unexpected, unexpected[:3]
    with torch.no_grad():
        scorer.head.weight.copy_(torch.load(path / "head.pt")["weight"].to(scorer.device))


def versions() -> dict:
    import peft
    import transformers
    out = {"torch": torch.__version__, "cuda": torch.version.cuda, "transformers": transformers.__version__,
           "peft": peft.__version__, "python": platform.python_version()}
    try:
        import fla
        out["flash_linear_attention"] = getattr(fla, "__version__", "?")
    except ImportError:
        out["flash_linear_attention"] = None
    import triton
    out["triton"] = triton.__version__
    out["gpu"] = torch.cuda.get_device_name(0)
    return out


