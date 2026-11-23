"""Decision-model fine-tuning on 184-toast (README of juliet_full/decision_ft).

Qwen3.5-4B text stack (BF16, frozen) + LoRA r16/a32/dropout 0.05 on all language-model linear projections
+ a separate FP32 2x2560 head initialised from the tied output rows of "Yes" and "No".
Score s = logit_Yes - logit_No at the last prompt position (post final norm). Full-vocabulary logits are only
computed once, at batch size 1 and logits_to_keep=1, as the step-0 reference.

  dft.py train --strategy L1 --fold 0 [--max-epochs 3]   full job: step-0 check, train, select, merge, predict
  dft.py speedtest --steps 60 [--groups-per-micro 2] [--no-grad-ckpt]   dev units as training data, weights discarded
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
import torch.nn.functional as F

DFT = Path(os.environ.get("DFT", Path.home() / "disk4/cs224/decision_ft"))
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


def pair_loss_terms(s: torch.Tensor, logits: torch.Tensor, truth: torch.Tensor, class_weight: torch.Tensor,
                    tau: float, lam: float) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Rows come as (bad, good) pairs of the same group: rows 2i (bad) and 2i+1 (good).
    Head row 0 = Yes (leak, class 1), row 1 = No (class 0); CE target index = 1 - truth."""
    ce = F.cross_entropy(logits, 1 - truth, weight=class_weight)
    rank = -F.logsigmoid((s[0::2] - s[1::2]) / tau).mean()
    return ce + lam * rank, ce, rank


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
            nonlocals = __import__("inspect").getclosurevars(getattr(qwen_mod, name)).nonlocals
            impl = nonlocals.get("implementation")
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


# ----------------------------------------------------------------------------------------------- data

def load_split(strategy: str, job: str, split: str, scorer: Scorer, manifest: dict) -> tuple[list[dict], list]:
    rows = read_jsonl(DFT / "data" / strategy / job / f"{split}.jsonl")
    ids = scorer.encode([r["text"] for r in rows])
    mismatch = [r["unit_id"] for r, x in zip(rows, ids) if len(x) != r["n_tokens"]]
    assert not mismatch, f"token count differs from dell rendering: {mismatch[:3]}"
    assert manifest[strategy]["chat_template_sha256"] == sha256_text(scorer.tokenizer.chat_template)
    assert manifest[strategy]["yes_token_id"] == scorer.yes_id and manifest[strategy]["no_token_id"] == scorer.no_id
    return rows, ids


def groups_of(rows: list[dict]) -> list[tuple[str, int, int]]:
    """(group_id, index of bad, index of good), sorted by group_id."""
    by_group: dict[str, dict[int, int]] = {}
    for i, r in enumerate(rows):
        by_group.setdefault(r["group_id"], {})[r["truth"]] = i
    out = []
    for g in sorted(by_group):
        assert set(by_group[g]) == {0, 1}, g
        out.append((g, by_group[g][1], by_group[g][0]))
    return out


# ----------------------------------------------------------------------------------------------- eval

@torch.no_grad()
def evaluate(scorer: Scorer, rows: list[dict], ids: list, class_weight: torch.Tensor, args) -> dict:
    scorer.text_model.eval()
    t0 = time.perf_counter()
    order = [i for _, b, g in groups_of(rows) for i in (b, g)]
    logits = scorer.logits_batched([ids[i] for i in order], args.eval_max_tokens)
    truth = torch.tensor([rows[i]["truth"] for i in order])
    s = logits[:, 0] - logits[:, 1]
    loss, ce, rank = pair_loss_terms(s, logits, truth, class_weight.cpu(), args.tau, args.lam)
    sl, tl = s.tolist(), truth.tolist()
    thr, f1 = best_threshold(sl, tl)
    return {"dev_auroc": auroc(sl, tl), "dev_loss": loss.item(), "dev_ce": ce.item(), "dev_rank": rank.item(),
            "dev_acc_at0": sum((v > 0) == (t == 1) for v, t in zip(sl, tl)) / len(sl),
            "dev_pair_acc": (s[0::2] > s[1::2]).float().mean().item(),
            "dev_best_macro_f1": f1, "dev_best_threshold": thr,
            "dev_s_mean_bad": s[0::2].mean().item(), "dev_s_mean_good": s[1::2].mean().item(),
            "eval_s": time.perf_counter() - t0, "_scores": {rows[i]["unit_id"]: v for i, v in zip(order, sl)}}


@torch.no_grad()
def step0_check(scorer: Scorer, rows: list[dict], ids: list, batched_scores: dict) -> dict:
    """With B=0 the head score must equal the base model's Yes-No logit difference."""
    scorer.text_model.eval()
    ref_full, head_same_hidden, rows_check = [], [], []
    ctx = scorer.peft_model.disable_adapter() if scorer.peft_model is not None else torch.no_grad()
    with ctx:
        for x in ids:
            input_ids = torch.tensor([x], device=scorer.device)
            out = scorer.causal_lm(input_ids=input_ids, use_cache=False, logits_to_keep=1,
                                   output_hidden_states=False)
            lg = out.logits[0, -1].float()
            ref_full.append((lg[scorer.yes_id] - lg[scorer.no_id]).item())
            h = scorer.text_model(input_ids=input_ids, use_cache=False).last_hidden_state[0, -1].float()
            hl = scorer.head(h)
            head_same_hidden.append((hl[0] - hl[1]).item())
            tied = h @ scorer.tied_rows.T
            rows_check.append(abs((tied[0] - tied[1]).item() - head_same_hidden[-1]))
    uids = [r["unit_id"] for r in rows]
    batched = [batched_scores[u] for u in uids]
    truth = [r["truth"] for r in rows]
    d_full = [abs(a - b) for a, b in zip(head_same_hidden, ref_full)]
    d_batch = [abs(a - b) for a, b in zip(head_same_hidden, batched)]
    return {"n": len(ids),
            "max_abs_head_minus_tied_rows_same_hidden": max(rows_check),
            "max_abs_head_bs1_minus_base_lm_head_bf16": max(d_full),
            "mean_abs_head_bs1_minus_base_lm_head_bf16": sum(d_full) / len(d_full),
            "max_abs_batched_padded_minus_bs1": max(d_batch),
            "mean_abs_batched_padded_minus_bs1": sum(d_batch) / len(d_batch),
            "zero_shot_dev_auroc_base_lm_head": auroc(ref_full, truth),
            "zero_shot_dev_auroc_head_bs1": auroc(head_same_hidden, truth),
            "zero_shot_dev_auroc_head_batched": auroc(batched, truth),
            "note": "base_lm_head = Qwen3_5ForCausalLM forward (adapter disabled), logits_to_keep=1, BF16 logits"}


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


def train_loop(scorer: Scorer, rows: list[dict], ids: list, args, log, on_eval=None,
               max_steps: int | None = None) -> dict:
    groups = groups_of(rows)
    truth_all = [r["truth"] for r in rows]
    n_pos = sum(truth_all)
    n_neg = len(truth_all) - n_pos
    # class-balanced CE weights (index 0 = Yes/leak, 1 = No); 1.0/1.0 when the set is balanced
    class_weight = torch.tensor([len(truth_all) / (2 * n_pos), len(truth_all) / (2 * n_neg)], device=scorer.device)
    steps_per_epoch = math.ceil(len(groups) / args.groups_per_step)
    total_steps = steps_per_epoch * args.max_epochs if max_steps is None else max_steps
    warmup = max(1, math.ceil(args.warmup_frac * total_steps))
    eval_steps = sorted({math.ceil(h * steps_per_epoch / 2) for h in range(1, 2 * args.max_epochs + 1)})
    optimizer = torch.optim.AdamW([
        {"params": scorer.lora_parameters(), "lr": args.lr_lora},
        {"params": list(scorer.head.parameters()), "lr": args.lr_head}],
        betas=(0.9, 0.999), eps=1e-8, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda(total_steps, warmup))
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)
    step, tokens, t_start = 0, 0, time.perf_counter()
    n_micro = n_ckpt_micro = 0
    plan = {"steps_per_epoch": steps_per_epoch, "total_steps": total_steps, "warmup_steps": warmup,
            "eval_steps": eval_steps if max_steps is None else [], "class_weight": class_weight.tolist(),
            "n_groups": len(groups)}
    log({"type": "plan", **plan})
    torch.cuda.reset_peak_memory_stats()
    epoch = 0
    while step < total_steps:
        gen = torch.Generator().manual_seed(SEED + epoch)
        perm = torch.randperm(len(groups), generator=gen).tolist()
        for s0 in range(0, len(perm), args.groups_per_step):
            if step >= total_steps:
                break
            step_groups = [groups[i] for i in perm[s0:s0 + args.groups_per_step]]
            scorer.text_model.train()
            scorer.head.train()
            optimizer.zero_grad(set_to_none=True)
            agg = {"loss": 0.0, "ce": 0.0, "rank": 0.0}
            step_tokens = 0
            for m0 in range(0, len(step_groups), args.groups_per_micro):
                micro = step_groups[m0:m0 + args.groups_per_micro]
                index = [i for _, b, g in micro for i in (b, g)]
                batch_ids = [ids[i] for i in index]
                step_tokens += sum(len(x) for x in batch_ids)
                padded = len(batch_ids) * max(len(x) for x in batch_ids)
                scorer.set_grad_ckpt(padded > args.gc_above_tokens)
                n_ckpt_micro += padded > args.gc_above_tokens
                n_micro += 1
                logits = scorer.logits(batch_ids)
                s = logits[:, 0] - logits[:, 1]
                truth = torch.tensor([rows[i]["truth"] for i in index], device=scorer.device)
                loss, ce, rank = pair_loss_terms(s, logits, truth, class_weight, args.tau, args.lam)
                frac = len(micro) / len(step_groups)
                (loss * frac).backward()
                agg["loss"] += loss.item() * frac
                agg["ce"] += ce.item() * frac
                agg["rank"] += rank.item() * frac
            grad_norm = torch.nn.utils.clip_grad_norm_(scorer.lora_parameters() + list(scorer.head.parameters()),
                                                       args.max_grad_norm)
            lrs = [g["lr"] for g in optimizer.param_groups]
            optimizer.step()
            scheduler.step()
            step += 1
            tokens += step_tokens
            elapsed = time.perf_counter() - t_start
            log({"type": "train", "step": step, "epoch": round(step / steps_per_epoch, 4), **agg,
                 "grad_norm": grad_norm.item(), "lr_lora": lrs[0], "lr_head": lrs[1], "tokens": step_tokens,
                 "elapsed_s": round(elapsed, 2), "tokens_per_s": round(tokens / elapsed, 1),
                 "peak_mem_gb": round(torch.cuda.max_memory_allocated() / 2**30, 2),
                 "ckpt_micro_frac": round(n_ckpt_micro / n_micro, 3)})
            if on_eval is not None and step in eval_steps:
                on_eval(step, step / steps_per_epoch, class_weight)
        epoch += 1
    plan["train_tokens"] = tokens
    plan["train_s"] = time.perf_counter() - t_start
    plan["peak_mem_gb"] = torch.cuda.max_memory_allocated() / 2**30
    plan["grad_ckpt_micro_batches"] = [n_ckpt_micro, n_micro]
    return plan


def contract_rows(rows, scores, latency, strategy, fold, checkpoint, threshold, split):
    out = []
    for r, s, lat in zip(rows, scores, latency):
        out.append({"unit_id": r["unit_id"], "method": "decision_ft", "strategy": strategy,
                    "model": f"qwen3.5-4b-lora-fold{fold}", "layer": "layer1", "pred": 1 if s > threshold else 0,
                    "score": s, "latency_s": lat, "status": "ok",
                    "extra": {"fold": fold, "checkpoint": checkpoint, "threshold": threshold, "split": split,
                              "unit_set": r["set"], "unit_fold": r["fold"]}})
    return out


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


def cmd_train(args) -> None:
    job = f"{args.strategy}_fold{args.fold}"
    run_id = f"{args.strategy}_fold{args.fold}_{args.run_tag}"
    root = DFT / "smoke" if args.smoke else DFT
    out_dir = root / args.strategy / f"fold{args.fold}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (root / "status").mkdir(exist_ok=True)
    status_path = root / "status" / f"{job}.json"
    status = {"job": job, "state": "running", "phase": "load", "host": socket.gethostname(), "pid": os.getpid(),
              "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"), "started_utc": utc_now()}

    def set_status(**kw):
        status.update(kw, updated_utc=utc_now())
        write_json(status_path, status)

    set_status()
    log_path = out_dir / "train_log.jsonl"
    log_file = log_path.open("w")

    def log(obj):
        log_file.write(json.dumps({"t": utc_now(), **obj}) + "\n")
        log_file.flush()

    manifest = json.loads((DFT / "data" / "manifest.json").read_text())
    torch.manual_seed(SEED)
    scorer = Scorer("cuda")
    config = {"job": job, "run_id": run_id, "strategy": args.strategy, "fold": args.fold, "seed": SEED,
              "model_dir": str(MODEL_DIR), "lora": {"r": 16, "alpha": 32, "dropout": 0.05,
                                                    "target_regex": LORA_TARGET_REGEX,
                                                    "n_params": scorer.n_lora_params, "dtype": scorer.lora_dtype},
              "head": {"shape": [2, 2560], "dtype": "float32", "init": "tied output rows of Yes/No",
                       "token_ids": [scorer.yes_id, scorer.no_id]},
              "score": "s = logit_Yes - logit_No at last prompt position (post final norm); pred = s > threshold",
              "loss": {"ce": "class-balanced CE over 2 logits", "rank": "-log sigmoid((s_bad - s_good)/tau)",
                       "tau": args.tau, "lambda": args.lam},
              "optim": {"name": "AdamW", "lr_lora": args.lr_lora, "lr_head": args.lr_head,
                        "weight_decay": args.weight_decay, "betas": [0.9, 0.999], "warmup_frac": args.warmup_frac,
                        "schedule": "linear warmup then cosine to 0", "max_grad_norm": args.max_grad_norm,
                        "groups_per_step": args.groups_per_step, "groups_per_micro": args.groups_per_micro},
              "max_epochs": args.max_epochs, "gc_above_tokens": args.gc_above_tokens,
              "selection": "dev AUROC every half epoch (step-0 is not a candidate); tie -> lower dev loss",
              "threshold": "dev macro-F1 on merged batch-1 dev scores; pred = s > threshold",
              "kernels": scorer.kernels, "versions": versions(),
              "data_manifest": manifest[args.strategy]}
    write_json(out_dir / "config.json", config)
    log({"type": "config", "kernels": scorer.kernels, "n_lora_params": scorer.n_lora_params})

    set_status(phase="tokenize")
    train_rows, train_ids = load_split(args.strategy, f"fold{args.fold}", "train", scorer, manifest)
    dev_rows, dev_ids = load_split(args.strategy, f"fold{args.fold}", "dev", scorer, manifest)
    pred_rows, pred_ids = load_split(args.strategy, f"fold{args.fold}", "pred", scorer, manifest)
    assert all(r["set"] == "eval" and r["fold"] != args.fold for r in train_rows)
    assert all(r["set"] == "dev" for r in dev_rows)
    assert all(r["set"] == "eval" and r["fold"] == args.fold for r in pred_rows)
    if args.smoke:  # pipeline test: 16 train groups, 20 dev groups, 20 held-out units, 1 epoch
        keep = {g for g, _, _ in groups_of(train_rows)[:16]}
        train_ids = [x for r, x in zip(train_rows, train_ids) if r["group_id"] in keep]
        train_rows = [r for r in train_rows if r["group_id"] in keep]
        dev_rows, dev_ids, pred_rows, pred_ids = dev_rows[:40], dev_ids[:40], pred_rows[:20], pred_ids[:20]
        args.max_epochs, args.groups_per_step = 1, 4

    set_status(phase="step0")
    ones = torch.tensor([1.0, 1.0], device="cuda")
    ev0 = evaluate(scorer, dev_rows, dev_ids, ones, args)
    check = step0_check(scorer, dev_rows, dev_ids, ev0.pop("_scores"))
    log({"type": "eval", "step": 0, "epoch": 0.0, **ev0, "step0_check": check})
    set_status(phase="train", step0={k: check[k] for k in ("zero_shot_dev_auroc_base_lm_head",
                                                            "max_abs_head_bs1_minus_base_lm_head_bf16")},
               dev_auroc_step0=ev0["dev_auroc"])
    evals = [{"step": 0, "epoch": 0.0, **{k: v for k, v in ev0.items()}}]
    ckpt_root = out_dir / "ckpt"

    def on_eval(step, epoch, class_weight):
        set_status(phase=f"eval step {step}")
        ev = evaluate(scorer, dev_rows, dev_ids, class_weight, args)
        ev.pop("_scores")
        save_checkpoint(scorer, ckpt_root / f"step{step}")
        log({"type": "eval", "step": step, "epoch": round(epoch, 4), **ev})
        evals.append({"step": step, "epoch": round(epoch, 4), **ev})
        set_status(phase="train", last_eval={"step": step, "epoch": round(epoch, 4), "dev_auroc": ev["dev_auroc"],
                                             "dev_loss": ev["dev_loss"]})

    plan = train_loop(scorer, train_rows, train_ids, args, log, on_eval)
    candidates = [e for e in evals if e["step"] > 0]
    best = max(candidates, key=lambda e: (e["dev_auroc"], -e["dev_loss"]))
    checkpoint = f"step{best['step']}"
    log({"type": "select", "checkpoint": checkpoint, "dev_auroc": best["dev_auroc"], "dev_loss": best["dev_loss"]})

    set_status(phase="predict", selected=checkpoint)
    load_checkpoint(scorer, ckpt_root / checkpoint)
    for name in ("adapter_config.json", "adapter_model.safetensors", "head.pt"):
        (out_dir / name).write_bytes((ckpt_root / checkpoint / name).read_bytes())
    scorer.text_model.eval()
    warm = dev_ids[:20]
    scorer.score_timed(warm)
    dev_unmerged, dev_unmerged_lat = scorer.score_timed(dev_ids)
    scorer.peft_model.merge_adapter()  # W <- W + (alpha/r) B A in GPU memory (BF16); never saved
    scorer.score_timed(warm)
    dev_merged, dev_merged_lat = scorer.score_timed(dev_ids)
    pred_scores, pred_lat = scorer.score_timed(pred_ids)
    dev_truth = [r["truth"] for r in dev_rows]
    threshold, dev_f1 = best_threshold(dev_merged, dev_truth)
    diffs = [abs(a - b) for a, b in zip(dev_merged, dev_unmerged)]
    merge_check = {"max_abs_merged_minus_unmerged": max(diffs), "mean_abs_merged_minus_unmerged": sum(diffs) / len(diffs),
                   "dev_auroc_unmerged_bs1": auroc(dev_unmerged, dev_truth),
                   "dev_auroc_merged_bs1": auroc(dev_merged, dev_truth),
                   "latency_median_unmerged_s": sorted(dev_unmerged_lat)[len(dev_unmerged_lat) // 2],
                   "latency_median_merged_s": sorted(dev_merged_lat)[len(dev_merged_lat) // 2]}
    pred_truth = [r["truth"] for r in pred_rows]
    selection = {"checkpoint": checkpoint, "epoch": best["epoch"], "threshold": threshold,
                 "dev_macro_f1_at_threshold": dev_f1, "dev_auroc": best["dev_auroc"], "dev_loss": best["dev_loss"],
                 "threshold_rule": config["threshold"], "selection_rule": config["selection"]}
    write_json(out_dir / "selection.json", selection)
    write_json(out_dir / "dev_metrics.json", {"evals": evals, "step0_check": check, "merge_check": merge_check,
                                              "selected": selection, "train_plan": plan})
    results = out_dir / "results"
    results.mkdir(exist_ok=True)
    for prefix, rws, sc, lat, split in (("", pred_rows, pred_scores, pred_lat, "heldout_fold"),
                                        ("dev_", dev_rows, dev_merged, dev_merged_lat, "dev")):
        with (results / f"{prefix}{run_id}.jsonl").open("w") as f:
            for row in contract_rows(rws, sc, lat, args.strategy, args.fold, checkpoint, threshold, split):
                f.write(json.dumps(row) + "\n")
        meta = {"method": "decision_ft", "strategy": args.strategy, "model": f"qwen3.5-4b-lora-fold{args.fold}",
                "layer": "layer1", "run_id": f"{prefix}{run_id}", "split": split, "n_units": len(rws),
                "base_model": str(MODEL_DIR), "versions": config["versions"], "kernels": scorer.kernels,
                "prompt_files": manifest[args.strategy]["prompt_files"],
                "question_sha256": manifest[args.strategy]["question_sha256"],
                "chat_template_sha256": manifest[args.strategy]["chat_template_sha256"],
                "units_sha256": manifest[args.strategy]["units_sha256"],
                "evidence_sha256": manifest[args.strategy]["evidence_sha256"],
                "selection": selection, "merge_check": merge_check,
                "start_utc": status["started_utc"], "end_utc": utc_now(), "host": socket.gethostname(),
                "concurrency": 1, "loadavg_end": os.getloadavg(),
                "latency_note": "latency_s = server-side time per unit at batch size 1 on one RTX 3090 with no other "
                                "job on that GPU: host tensor build + H2D + forward (LoRA merged) + head + readout; "
                                "excludes tokenisation and network",
                "auroc_heldout": auroc(pred_scores, pred_truth)}
        write_json(results / f"{prefix}{run_id}.meta.json", meta)
    log({"type": "done", "selection": selection, "merge_check": merge_check})
    log_file.close()
    set_status(state="done", phase="done", selected=checkpoint, threshold=threshold, finished_utc=utc_now())


def cmd_speedtest(args) -> None:
    manifest = json.loads((DFT / "data" / "manifest.json").read_text())
    scorer = Scorer("cuda")
    rows, ids = load_split(args.strategy, "fold0", "dev", scorer, manifest)
    records = []

    def log(obj):
        records.append(obj)
        if obj.get("type") == "train" and obj["step"] % 10 == 0:
            print(json.dumps(obj), flush=True)

    args.max_epochs = 3
    plan = train_loop(scorer, rows, ids, args, log, max_steps=args.steps)
    train = [r for r in records if r["type"] == "train"]
    skip = min(5, len(train) - 1)  # exclude Triton JIT warm-up steps
    t = train[-1]["elapsed_s"] - train[skip - 1]["elapsed_s"] if skip else train[-1]["elapsed_s"]
    tok = sum(r["tokens"] for r in train[skip:])
    scorer.text_model.eval()
    t0 = time.perf_counter()
    scorer.score_batched(ids, args.eval_max_tokens)
    eval_s = time.perf_counter() - t0
    scorer.score_timed(ids[:10])
    _, lat = scorer.score_timed(ids[:100])
    report = {"strategy": args.strategy, "steps": args.steps, "groups_per_step": args.groups_per_step,
              "groups_per_micro": args.groups_per_micro, "gc_above_tokens": args.gc_above_tokens,
              "kernels": scorer.kernels, "n_lora_params": scorer.n_lora_params,
              "train_tokens_per_s": tok / t, "s_per_step": t / (len(train) - skip),
              "peak_mem_gb": plan["peak_mem_gb"], "loss_first5": [r["loss"] for r in train[:5]],
              "loss_last5": [r["loss"] for r in train[-5:]],
              "dev_eval_660_units_s": eval_s, "bs1_latency_median_s": sorted(lat)[len(lat) // 2],
              "versions": versions(), "utc": utc_now()}
    print(json.dumps(report, indent=2))
    out = DFT / "speedtest"
    out.mkdir(exist_ok=True)
    tag = f"{args.strategy}_m{args.groups_per_micro}_gc{args.gc_above_tokens}"
    write_json(out / f"speedtest_{tag}.json", {**report, "log": records})


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("train", "speedtest"):
        p = sub.add_parser(name)
        p.add_argument("--strategy", choices=("L1", "L3"), default="L1")
        p.add_argument("--groups-per-step", type=int, default=8)
        p.add_argument("--groups-per-micro", type=int, default=1)
        p.add_argument("--lr-lora", type=float, default=1e-4)
        p.add_argument("--lr-head", type=float, default=1e-3)
        p.add_argument("--weight-decay", type=float, default=0.0)
        p.add_argument("--warmup-frac", type=float, default=0.05)
        p.add_argument("--max-grad-norm", type=float, default=1.0)
        p.add_argument("--tau", type=float, default=1.0)
        p.add_argument("--lam", type=float, default=1.0)
        p.add_argument("--eval-max-tokens", type=int, default=8192)
        p.add_argument("--gc-above-tokens", type=int, default=1200,
                       help="gradient checkpointing only for micro-batches with more padded tokens (0 = always)")
        if name == "train":
            p.add_argument("--fold", type=int, choices=(0, 1, 2), required=True)
            p.add_argument("--max-epochs", type=int, default=3)
            p.add_argument("--run-tag", default="v1")
            p.add_argument("--smoke", action="store_true", help="tiny end-to-end test under $DFT/smoke/")
        else:
            p.add_argument("--steps", type=int, default=60)
    args = parser.parse_args()
    {"train": cmd_train, "speedtest": cmd_speedtest}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
