"""LoRA L4-D on 184-toast (lane l4d-train; contract juliet_full/l4d/README.md sections 4-5).

Same model as decision_ft (dft_core.Scorer): Qwen3.5-4B BF16 + LoRA r16/a32/dropout 0.05, FP32 2x2560 head from the
tied Yes/No rows, s = logit_Yes - logit_No at the last prompt position, p_yes = sigmoid(s). One prompt per question
(server/l4d_prompt.py), rendered on dell (render.py) with n_tokens checked here.

  l4dft.py train --fold k --train data/train_fold<k>.jsonl --dev data/q_layer1.jsonl --epochs E --evals-per-epoch 2
      step-0 check, class-balanced CE (row weight from render.py), checkpoints + unmerged dev answers at every eval
      point -> runs/fold<k>/{config.json,train_log.jsonl,ckpt/step<N>/,dev_answers/step<N>.jsonl}
  l4dft.py predict --fold k --ckpt step<N> --input data/q_<layer>.jsonl [--set eval] [--unit-fold k] --out <jsonl>
      merged adapter (W + (alpha/r) B A in GPU memory, never saved); all questions of one unit in one forward batch
  l4dft.py readout --input ... --out ...    base model + step-0 head (no adapter), same batching
  l4dft.py serve --port 8004 [--frozen FROZEN]    POST /l4d, GET /health (one merged fold model at a time)

Answer rows (contract section 4): {qid, unit_id, qtype, p_yes, logit_diff, model, fold}; prediction runs add
unit_forward_s (server-side time of the unit's batch: host tensor build + H2D + forward + head + readout) and
unit_n_questions.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import socket
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

import torch
import torch.nn.functional as F

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dft_core import (L4D, MODEL_DIR, SEED, LORA_TARGET_REGEX, Scorer, auroc, load_checkpoint,  # noqa: E402
                      lr_lambda, read_jsonl, save_checkpoint, sha256_text, utc_now, versions, write_json)
from l4d_prompt import TEMPLATE_SHA256, render  # noqa: E402


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    tmp.replace(path)


def p_yes(s: float) -> float:
    return 1.0 / (1.0 + math.exp(-s)) if s >= 0 else math.exp(s) / (1.0 + math.exp(s))


def load_rows(path: Path, scorer: Scorer, manifest_key: str | None = None) -> tuple[list[dict], list[list[int]]]:
    rows = read_jsonl(path)
    ids = scorer.encode([r["text"] for r in rows])
    bad = [r["qid"] for r, x in zip(rows, ids) if len(x) != r["n_tokens"]]
    assert not bad, f"token count differs from dell rendering: {bad[:3]}"
    manifest = json.loads((L4D / "data" / "manifest.json").read_text())
    entry = manifest[manifest_key or path.stem]
    if "chat_template_sha256" in entry:
        assert entry["chat_template_sha256"] == sha256_text(scorer.tokenizer.chat_template)
        assert entry["template_sha256"] == TEMPLATE_SHA256
    return rows, ids


def question_auroc(scores: list[float], gold: list[int]) -> float | None:
    return auroc(scores, gold) if 0 < sum(gold) < len(gold) else None


def answer_metrics(rows: list[dict], scores: list[float]) -> dict:
    """Question-level AUROC / accuracy at p_yes >= 0.5, overall and per qtype (rows need gold in {0, 1})."""
    out = {}
    by = defaultdict(list)
    for r, s in zip(rows, scores):
        if r.get("gold") in (0, 1):
            by["all"].append((s, r["gold"]))
            by[r["qtype"]].append((s, r["gold"]))
    for k, v in by.items():
        sc, g = [a for a, _ in v], [b for _, b in v]
        out[k] = {"n": len(v), "n_yes": sum(g), "auroc": question_auroc(sc, g),
                  "acc_at_0": sum((a > 0) == (b == 1) for a, b in v) / len(v)}
    return out


# ----------------------------------------------------------------------------------------------- scoring

def unit_batches(rows: list[dict]) -> list[list[int]]:
    """Row indices grouped by unit_id, units in order of first appearance."""
    order, groups = [], {}
    for i, r in enumerate(rows):
        if r["unit_id"] not in groups:
            groups[r["unit_id"]] = []
            order.append(r["unit_id"])
        groups[r["unit_id"]].append(i)
    return [groups[u] for u in order]


@torch.no_grad()
def score_units(scorer: Scorer, rows: list[dict], ids: list[list[int]], max_tokens: int) -> tuple[list, dict, dict]:
    """All questions of one unit in one forward batch (split only if the padded batch exceeds max_tokens).
    Returns per-row s, per-unit forward seconds, per-unit number of forward chunks."""
    scores = [0.0] * len(rows)
    unit_s, unit_chunks = {}, {}
    for idx in unit_batches(rows):
        idx = sorted(idx, key=lambda i: len(ids[i]))
        chunks, cur = [], []
        for i in idx:
            if cur and len(ids[i]) * (len(cur) + 1) > max_tokens:
                chunks.append(cur)
                cur = []
            cur.append(i)
        chunks.append(cur)
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        for chunk in chunks:
            lg = scorer.logits([ids[i] for i in chunk])
            s = (lg[:, 0] - lg[:, 1]).tolist()
            for i, v in zip(chunk, s):
                scores[i] = v
        uid = rows[idx[0]]["unit_id"]
        unit_s[uid] = time.perf_counter() - t0
        unit_chunks[uid] = len(chunks)
    return scores, unit_s, unit_chunks


def answer_rows(rows, scores, model, fold, unit_s=None) -> list[dict]:
    n_q = defaultdict(int)
    for r in rows:
        n_q[r["unit_id"]] += 1
    out = []
    for r, s in zip(rows, scores):
        row = {"qid": r["qid"], "unit_id": r["unit_id"], "qtype": r["qtype"], "p_yes": p_yes(s), "logit_diff": s,
               "model": model, "fold": fold}
        if unit_s is not None:
            row["unit_forward_s"] = unit_s[r["unit_id"]]
            row["unit_n_questions"] = n_q[r["unit_id"]]
        out.append(row)
    return out


@torch.no_grad()
def step0_check(scorer: Scorer, ids: list[list[int]], batched: list[float]) -> dict:
    """B = 0: head score (bs 1) must equal the tied-row score on the same hidden state, and the base lm_head
    Yes-No logit difference up to BF16 rounding; batched padded scores must match bs 1."""
    scorer.text_model.eval()
    ref_full, head_bs1, rows_check = [], [], []
    ctx = scorer.peft_model.disable_adapter() if scorer.peft_model is not None else torch.no_grad()
    with ctx:
        for x in ids:
            input_ids = torch.tensor([x], device=scorer.device)
            lg = scorer.causal_lm(input_ids=input_ids, use_cache=False, logits_to_keep=1).logits[0, -1].float()
            ref_full.append((lg[scorer.yes_id] - lg[scorer.no_id]).item())
            h = scorer.text_model(input_ids=input_ids, use_cache=False).last_hidden_state[0, -1].float()
            hl = scorer.head(h)
            head_bs1.append((hl[0] - hl[1]).item())
            tied = h @ scorer.tied_rows.T
            rows_check.append(abs((tied[0] - tied[1]).item() - head_bs1[-1]))
    d_full = [abs(a - b) for a, b in zip(head_bs1, ref_full)]
    d_batch = [abs(a - b) for a, b in zip(head_bs1, batched)]
    return {"n": len(ids), "max_abs_head_minus_tied_rows_same_hidden": max(rows_check),
            "max_abs_head_bs1_minus_base_lm_head_bf16": max(d_full),
            "mean_abs_head_bs1_minus_base_lm_head_bf16": sum(d_full) / len(d_full),
            "max_abs_unit_batched_minus_bs1": max(d_batch), "mean_abs_unit_batched_minus_bs1": sum(d_batch) / len(d_batch)}


# ----------------------------------------------------------------------------------------------- train

def micro_batches(index: list[int], ids: list[list[int]], max_tokens: int) -> list[list[int]]:
    """Length-sorted packing of one step's questions into micro-batches of <= max_tokens padded tokens."""
    index = sorted(index, key=lambda i: len(ids[i]))
    out, cur = [], []
    for i in index:
        if cur and len(ids[i]) * (len(cur) + 1) > max_tokens:
            out.append(cur)
            cur = []
        cur.append(i)
    out.append(cur)
    return out


def cmd_train(args) -> None:
    """Single GPU, or data parallel under torchrun (WORLD_SIZE > 1): every rank holds the full model, takes
    index[rank::world] of each step's questions, gradients are summed with all_reduce (the loss is normalised by
    the step's global weight sum, so the update equals the single-GPU one); dev answers are split by unit."""
    import torch.distributed as dist
    world = int(os.environ.get("WORLD_SIZE", "1"))
    rank = int(os.environ.get("RANK", "0"))
    if world > 1:
        torch.cuda.set_device(int(os.environ["LOCAL_RANK"]))
        dist.init_process_group("nccl")
    main_proc = rank == 0
    name = (f"smoke_fold{args.fold}" if args.smoke else f"fold{args.fold}") + (args.run_suffix or "")
    run_dir = L4D / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    status_path = L4D / "status" / f"{name}.json"
    status_path.parent.mkdir(exist_ok=True)
    status = {"job": name, "state": "running", "phase": "load", "host": socket.gethostname(),
              "pid": os.getpid(), "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
              "world_size": world, "started_utc": utc_now()}

    def set_status(**kw):
        if main_proc:
            status.update(kw, updated_utc=utc_now())
            write_json(status_path, status)

    def barrier():
        if world > 1:
            dist.barrier()

    set_status()
    log_file = (run_dir / "train_log.jsonl").open("a") if main_proc else None

    def log(obj):
        if main_proc:
            log_file.write(json.dumps({"t": utc_now(), **obj}) + "\n")
            log_file.flush()

    torch.manual_seed(SEED)
    scorer = Scorer("cuda")
    train_rows, train_ids = load_rows(L4D / args.train, scorer)
    dev_all, dev_ids_all = load_rows(L4D / args.dev, scorer)
    keep = [i for i, r in enumerate(dev_all) if r["set"] == "dev" or args.smoke]
    dev_rows, dev_ids = [dev_all[i] for i in keep], [dev_ids_all[i] for i in keep]
    if not args.smoke:
        assert all(r["set"] == "eval" and r["fold"] != args.fold and r["layer"] == "layer1" for r in train_rows)
        assert all(r["layer"] == "layer1" for r in dev_rows)
    if args.dev_units:
        units = set(sorted({r["unit_id"] for r in dev_rows})[:args.dev_units])
        sel = [i for i, r in enumerate(dev_rows) if r["unit_id"] in units]
        dev_rows, dev_ids = [dev_rows[i] for i in sel], [dev_ids[i] for i in sel]
    n_steps_epoch = math.ceil(len(train_rows) / args.questions_per_step)
    total_steps = args.max_steps or math.ceil(n_steps_epoch * args.epochs)
    eval_every = max(1, round(n_steps_epoch / args.evals_per_epoch))
    eval_steps = [] if args.no_eval else sorted(set(range(eval_every, total_steps + 1, eval_every)) | {total_steps})
    config = {"job": name, "fold": args.fold, "seed": SEED, "model_dir": str(MODEL_DIR), "world_size": world,
              "lora": {"r": 16, "alpha": 32, "dropout": 0.05, "target_regex": LORA_TARGET_REGEX,
                       "n_params": scorer.n_lora_params, "dtype": scorer.lora_dtype},
              "head": {"shape": [2, 2560], "dtype": "float32", "init": "tied output rows of Yes/No",
                       "token_ids": [scorer.yes_id, scorer.no_id]},
              "score": "s = logit_Yes - logit_No at the last prompt position; p_yes = sigmoid(s)",
              "loss": "class-balanced CE per (qtype, gold): sum_i w_i CE_i / sum_i w_i per step, w from render.py",
              "optim": {"name": "AdamW", "lr_lora": args.lr_lora, "lr_head": args.lr_head, "weight_decay": 0.0,
                        "betas": [0.9, 0.999], "warmup_frac": args.warmup_frac, "max_grad_norm": 1.0,
                        "schedule": "linear warmup then cosine to 0"},
              "questions_per_step": args.questions_per_step, "micro_tokens": args.micro_tokens,
              "grad_ckpt_above_tokens": args.gc_above_tokens, "epochs": args.epochs, "steps_per_epoch": n_steps_epoch,
              "total_steps": total_steps, "eval_steps": eval_steps, "train_file": args.train, "dev_file": args.dev,
              "n_train": len(train_rows), "n_dev": len(dev_rows), "n_dev_units": len({r["unit_id"] for r in dev_rows}),
              "template_sha256": TEMPLATE_SHA256, "chat_template_sha256": sha256_text(scorer.tokenizer.chat_template),
              "kernels": scorer.kernels, "versions": versions()}
    if main_proc:
        write_json(run_dir / "config.json", config)
    log({"type": "config", **{k: config[k] for k in ("n_train", "n_dev", "total_steps", "eval_steps", "world_size")}})
    dev_units = [r["unit_id"] for r in dev_rows]
    dev_unit_order = sorted(set(dev_units))
    mine = {u for j, u in enumerate(dev_unit_order) if j % world == rank}

    def dev_answers(tag: str) -> dict | None:
        """Unmerged dev answers of the current weights; returns metrics + scores on rank 0."""
        set_status(phase=f"dev answers {tag}")
        scorer.text_model.eval()
        t0 = time.perf_counter()
        idx = [i for i, u in enumerate(dev_units) if u in mine]
        sub_rows, sub_ids = [dev_rows[i] for i in idx], [dev_ids[i] for i in idx]
        scores, _, _ = score_units(scorer, sub_rows, sub_ids, args.max_unit_tokens)
        part = run_dir / "dev_answers" / f"{tag}.rank{rank}.json"
        part.parent.mkdir(exist_ok=True)
        part.write_text(json.dumps(dict(zip([dev_rows[i]["qid"] for i in idx], scores))))
        barrier()
        if not main_proc:
            return None
        by_qid = {}
        for r in range(world):
            p = run_dir / "dev_answers" / f"{tag}.rank{r}.json"
            by_qid.update(json.loads(p.read_text()))
            p.unlink()
        all_scores = [by_qid[r["qid"]] for r in dev_rows]
        write_jsonl(run_dir / "dev_answers" / f"{tag}.jsonl",
                    answer_rows(dev_rows, all_scores, f"qwen3.5-4b-lora-l4d-fold{args.fold}-{tag}", args.fold))
        return {"metrics": answer_metrics(dev_rows, all_scores), "dev_s": time.perf_counter() - t0,
                "_scores": all_scores}

    # step 0: zero-shot dev answers of the step-0 model, then the step-0 check on the first questions (rank 0)
    set_status(phase="step0")
    if not args.no_eval:
        ev0 = dev_answers("step0")
        if main_proc:
            n0 = min(args.step0_n, len(dev_ids))
            check = step0_check(scorer, dev_ids[:n0], ev0.pop("_scores")[:n0])
            log({"type": "eval", "step": 0, **ev0, "step0_check": check})
            write_json(run_dir / "step0_check.json", check)
            assert check["max_abs_head_minus_tied_rows_same_hidden"] < 1e-3, check
        barrier()

    weights = torch.tensor([r["weight"] for r in train_rows], dtype=torch.float32)
    gold = torch.tensor([r["gold"] for r in train_rows])
    params = scorer.lora_parameters() + list(scorer.head.parameters())
    optimizer = torch.optim.AdamW([{"params": scorer.lora_parameters(), "lr": args.lr_lora},
                                   {"params": list(scorer.head.parameters()), "lr": args.lr_head}],
                                  betas=(0.9, 0.999), eps=1e-8, weight_decay=0.0)
    warmup = max(1, math.ceil(args.warmup_frac * total_steps))
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda(total_steps, warmup))
    torch.cuda.reset_peak_memory_stats()
    step, tokens, t_start, epoch = 0, 0, time.perf_counter(), 0
    n_micro = n_ckpt = 0
    set_status(phase="train", total_steps=total_steps)
    while step < total_steps:
        perm = list(range(len(train_rows)))
        random.Random(SEED + epoch).shuffle(perm)
        for s0 in range(0, len(perm), args.questions_per_step):
            if step >= total_steps:
                break
            index = perm[s0:s0 + args.questions_per_step]
            w_step = weights[index].sum().item()
            local = sorted(index, key=lambda i: len(train_ids[i]))[rank::world]  # balanced tokens across ranks
            scorer.text_model.train()
            scorer.head.train()
            optimizer.zero_grad(set_to_none=False)
            loss_sum, step_tokens = 0.0, 0
            for micro in (micro_batches(local, train_ids, args.micro_tokens) if local else []):
                batch = [train_ids[i] for i in micro]
                padded = len(batch) * max(len(x) for x in batch)
                scorer.set_grad_ckpt(padded > args.gc_above_tokens)
                n_ckpt += padded > args.gc_above_tokens
                n_micro += 1
                step_tokens += sum(len(x) for x in batch)
                logits = scorer.logits(batch)
                target = (1 - gold[micro]).to("cuda")  # head row 0 = Yes (gold 1), row 1 = No
                ce = F.cross_entropy(logits, target, reduction="none")
                loss = (ce * weights[micro].to("cuda")).sum() / w_step
                loss.backward()
                loss_sum += loss.item()
            if world > 1:
                for p in params:
                    if p.grad is None:
                        p.grad = torch.zeros_like(p)
                flat = torch.cat([p.grad.reshape(-1) for p in params])
                dist.all_reduce(flat)
                off = 0
                for p in params:
                    p.grad.copy_(flat[off:off + p.numel()].view_as(p))
                    off += p.numel()
                stats = torch.tensor([loss_sum, float(step_tokens)], device="cuda")
                dist.all_reduce(stats)
                loss_sum, step_tokens = stats[0].item(), int(stats[1].item())
            grad_norm = torch.nn.utils.clip_grad_norm_(params, 1.0)
            lrs = [g["lr"] for g in optimizer.param_groups]
            optimizer.step()
            scheduler.step()
            step += 1
            tokens += step_tokens
            elapsed = time.perf_counter() - t_start
            log({"type": "train", "step": step, "epoch": round(step / n_steps_epoch, 4), "loss": loss_sum,
                 "grad_norm": grad_norm.item(), "lr_lora": lrs[0], "lr_head": lrs[1], "tokens": step_tokens,
                 "elapsed_s": round(elapsed, 2), "tokens_per_s": round(tokens / elapsed, 1),
                 "peak_mem_gb": round(torch.cuda.max_memory_allocated() / 2**30, 2),
                 "ckpt_micro_frac": round(n_ckpt / max(1, n_micro), 3)})
            if step % 10 == 0:
                set_status(phase="train", step=step, total_steps=total_steps, elapsed_s=round(elapsed),
                           eta_train_s=round(elapsed / step * (total_steps - step)), loss=loss_sum)
            if step in eval_steps:
                tag = f"step{step}"
                if main_proc:
                    save_checkpoint(scorer, run_dir / "ckpt" / tag)
                ev = dev_answers(tag)
                if main_proc:
                    ev.pop("_scores")
                    log({"type": "eval", "step": step, "epoch": round(step / n_steps_epoch, 4), **ev})
                    set_status(phase="train", last_eval={"step": step, "auroc": ev["metrics"]["all"]["auroc"]})
        epoch += 1
    log({"type": "done", "train_s": time.perf_counter() - t_start, "train_tokens": tokens,
         "peak_mem_gb": torch.cuda.max_memory_allocated() / 2**30, "grad_ckpt_micro": [n_ckpt, n_micro]})
    if main_proc:
        log_file.close()
    set_status(state="done", phase="done", finished_utc=utc_now(), train_s=round(time.perf_counter() - t_start))
    if world > 1:
        dist.destroy_process_group()


# ----------------------------------------------------------------------------------------------- predict

def select_rows(rows, ids, args):
    keep = [i for i, r in enumerate(rows)
            if (args.set is None or r["set"] == args.set) and (args.unit_fold is None or r["fold"] == args.unit_fold)]
    return [rows[i] for i in keep], [ids[i] for i in keep]


def run_scoring(scorer, rows, ids, model, fold, out: Path, meta_extra: dict, args) -> None:
    scorer.text_model.eval()
    warm = unit_batches(rows)[:5]
    score_units(scorer, [rows[i] for b in warm for i in b], [ids[i] for b in warm for i in b], args.max_unit_tokens)
    start, load_start = utc_now(), os.getloadavg()
    scores, unit_s, unit_chunks = score_units(scorer, rows, ids, args.max_unit_tokens)
    write_jsonl(out, answer_rows(rows, scores, model, fold, unit_s))
    lat = sorted(unit_s.values())
    nq = sorted(len(b) for b in unit_batches(rows))
    meta = {"model": model, "fold": fold, "input": args.input, "n_questions": len(rows), "n_units": len(unit_s),
            "set_filter": args.set, "unit_fold_filter": args.unit_fold, "base_model": str(MODEL_DIR),
            "template_sha256": TEMPLATE_SHA256, "chat_template_sha256": sha256_text(scorer.tokenizer.chat_template),
            "versions": versions(), "kernels": scorer.kernels, "host": socket.gethostname(),
            "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"), "start_utc": start, "end_utc": utc_now(),
            "loadavg_start": load_start, "loadavg_end": os.getloadavg(),
            "unit_forward_s_median": lat[len(lat) // 2], "unit_forward_s_p90": lat[int(0.9 * (len(lat) - 1))],
            "questions_per_unit_median": nq[len(nq) // 2], "questions_per_unit_max": nq[-1],
            "units_split_into_chunks": sum(c > 1 for c in unit_chunks.values()), "max_unit_tokens": args.max_unit_tokens,
            "question_metrics": answer_metrics(rows, scores),
            "latency_note": "unit_forward_s = server-side time of one unit's batch on one RTX 3090: host tensor build + "
                            "H2D + forward + head + readout; excludes tokenisation and network", **meta_extra}
    write_json(out.with_suffix(".meta.json"), meta)
    print(json.dumps({"out": str(out), "n": len(rows), "unit_forward_s_median": meta["unit_forward_s_median"],
                      "all": meta["question_metrics"].get("all")}), flush=True)


def freeze_guard(args, fold: int | None, ckpt_dir: Path | None) -> dict:
    """Freeze rule (contract section 5): anything but layer1 dev needs this fold's (or the readout's) FROZEN entry,
    and a fold prediction must use exactly the frozen checkpoint (adapter + head sha256)."""
    import hashlib
    dev_only = args.set == "dev" and Path(args.input).name.startswith("q_layer1")
    frozen_path = L4D / "FROZEN"
    if dev_only and not frozen_path.exists():
        return {"freeze_guard": "layer1 dev only (pre-freeze)"}
    if not frozen_path.exists():
        raise SystemExit("freeze rule: FROZEN missing; only --set dev on q_layer1 is allowed")
    frozen = json.loads(frozen_path.read_text())
    if fold is None:
        entry = frozen.get("readout")
        if entry is None and not dev_only:
            raise SystemExit("freeze rule: readout not frozen")
        return {"freeze_guard": "readout", "frozen_utc": entry and entry["frozen_utc"]}
    entry = frozen["folds"].get(str(fold))
    if entry is None:
        if dev_only:
            return {"freeze_guard": "layer1 dev only (pre-freeze)"}
        raise SystemExit(f"freeze rule: fold {fold} not frozen")
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    if not dev_only:
        assert ckpt_dir.resolve() == (L4D / entry["checkpoint_dir"]).resolve(), (ckpt_dir, entry["checkpoint_dir"])
        assert sha(ckpt_dir / "adapter_model.safetensors") == entry["adapter_sha256"]
        assert sha(ckpt_dir / "head.pt") == entry["head_sha256"]
    return {"freeze_guard": f"fold {fold} frozen", "frozen_utc": entry["frozen_utc"], "tau": entry["tau"]}


def cmd_predict(args) -> None:
    ckpt_dir = L4D / "runs" / f"fold{args.fold}" / "ckpt" / args.ckpt if not args.ckpt_dir else Path(args.ckpt_dir)
    guard = freeze_guard(args, args.fold, ckpt_dir)
    scorer = Scorer("cuda")
    load_checkpoint(scorer, ckpt_dir)
    scorer.text_model.eval()
    rows, ids = select_rows(*load_rows(L4D / args.input, scorer), args)
    extra = {"checkpoint": str(ckpt_dir), "merged": not args.unmerged, **guard}
    if not args.unmerged:
        scorer.peft_model.merge_adapter()  # W <- W + (alpha/r) B A in GPU memory (BF16); never saved
    run_scoring(scorer, rows, ids, args.model or f"qwen3.5-4b-lora-l4d-fold{args.fold}", args.fold,
                L4D / args.out, extra, args)


def cmd_readout(args) -> None:
    guard = freeze_guard(args, None, None)
    scorer = Scorer("cuda", lora=False)  # base model + head = tied Yes/No rows (the step-0 model)
    rows, ids = select_rows(*load_rows(L4D / args.input, scorer), args)
    run_scoring(scorer, rows, ids, "qwen3.5-4b-readout", None, L4D / args.out,
                {"readout": "base Qwen3.5-4B, FP32 head = tied Yes/No rows, s = logit_Yes - logit_No", **guard}, args)


# ----------------------------------------------------------------------------------------------- serve

class FoldModels:
    """The three frozen fold adapters + heads cached on the GPU; one is merged into the BF16 weights at a time.
    Switching restores the exact base weights (GPU copy), loads the adapter and merges it (as decision_ft stage2)."""

    def __init__(self, frozen: dict):
        from peft import set_peft_model_state_dict
        from peft.tuners.lora import LoraLayer
        from safetensors.torch import load_file
        self._set_state = set_peft_model_state_dict
        self.scorer = Scorer("cuda")
        self.scorer.text_model.eval()
        self.lora_layers = {n: m for n, m in self.scorer.peft_model.named_modules() if isinstance(m, LoraLayer)}
        self.base_weights = {n: m.base_layer.weight.detach().clone() for n, m in self.lora_layers.items()}
        self.models = {}
        for fold_key, spec in frozen["folds"].items():
            path = L4D / spec["checkpoint_dir"]
            adapter = {k: v.to("cuda") for k, v in load_file(str(path / "adapter_model.safetensors")).items()}
            head = torch.load(path / "head.pt")["weight"].to("cuda")
            self.models[int(fold_key)] = {"adapter": adapter, "head": head, "checkpoint": spec["checkpoint"],
                                          "tau": spec["tau"]}
        self.active = None
        self.lock = threading.Lock()

    @torch.no_grad()
    def activate(self, fold: int) -> float:
        if fold == self.active:
            return 0.0
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        pm = self.scorer.peft_model
        if self.active is not None:
            pm.unmerge_adapter()
            for n, m in self.lora_layers.items():
                m.base_layer.weight.copy_(self.base_weights[n])
        result = self._set_state(pm, self.models[fold]["adapter"])
        assert not getattr(result, "unexpected_keys", []), result
        self.scorer.head.weight.copy_(self.models[fold]["head"])
        pm.merge_adapter()
        torch.cuda.synchronize()
        self.active = fold
        return time.perf_counter() - t0

    @torch.no_grad()
    def answer(self, req: dict) -> dict:
        fold = req.get("fold")
        if fold not in self.models:
            raise ValueError(f"unknown fold {fold!r}; available {sorted(self.models)}")
        qs = req.get("questions")
        if not isinstance(qs, list) or not qs or not all(isinstance(q, dict) and isinstance(q.get("state"), str)
                                                         and isinstance(q.get("question"), str) for q in qs):
            raise ValueError("need questions: [{qid, state, question}, ...]")
        with self.lock:
            switch_s = self.activate(fold)
            t0 = time.perf_counter()
            texts = [render(self.scorer.tokenizer, q["state"], q["question"]) for q in qs]
            ids = self.scorer.encode(texts)
            t1 = time.perf_counter()
            rows = [{"qid": q.get("qid"), "unit_id": "req"} for q in qs]
            scores, unit_s, chunks = score_units(self.scorer, rows, ids, req.get("max_unit_tokens", 32768))
            total = time.perf_counter() - t0
        return {"answers": [{"qid": q.get("qid"), "p_yes": p_yes(s), "logit_diff": s} for q, s in zip(qs, scores)],
                "fold": fold, "checkpoint": self.models[fold]["checkpoint"], "tau": self.models[fold]["tau"],
                "n_questions": len(qs), "n_tokens": sum(len(x) for x in ids), "n_forward_chunks": chunks["req"],
                "render_tokenize_ms": (t1 - t0) * 1000, "forward_ms": unit_s["req"] * 1000,
                "latency_ms_server": total * 1000, "switch_ms": switch_s * 1000,
                "prompt_sha256": [sha256_text(t) for t in texts] if req.get("return_prompt_sha256") else None}


def cmd_serve(args) -> None:
    import uvicorn
    from fastapi import Body, FastAPI, HTTPException
    frozen = json.loads((L4D / args.frozen).read_text())
    models = FoldModels(frozen)
    started = utc_now()
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"ok": True, "folds": sorted(models.models), "active": models.active,
                "tau": {k: v["tau"] for k, v in models.models.items()},
                "started_utc": started, "template_sha256": TEMPLATE_SHA256, "gpu": torch.cuda.get_device_name(0),
                "gpu_mem_allocated_gb": round(torch.cuda.memory_allocated() / 2**30, 2)}

    @app.post("/l4d")
    async def l4d(req: dict = Body(...)):
        try:
            return await __import__("asyncio").to_thread(models.answer, req)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    warm = {"state": "1: #include <stdlib.h>\n2: void sym_0()\n3: {\n4:     char * data = (char *)malloc(10);\n"
                     "5:     free(data);\n6: }", "question": "Does the call at line 4 allocate heap memory?"}
    for _ in range(2):
        for fold in sorted(models.models):
            models.answer({"fold": fold, "questions": [warm] * 8})
    print(json.dumps({"ready": utc_now(), "folds": sorted(models.models),
                      "gpu_mem_allocated_gb": round(torch.cuda.memory_allocated() / 2**30, 2)}), flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("train")
    p.add_argument("--fold", type=int, choices=(0, 1, 2), required=True)
    p.add_argument("--train", required=True, help="path under $L4D, e.g. data/train_fold0.jsonl")
    p.add_argument("--dev", required=True, help="path under $L4D; rows with set == dev are used")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--evals-per-epoch", type=int, default=2)
    p.add_argument("--max-steps", type=int, default=0)
    p.add_argument("--questions-per-step", type=int, default=32)
    p.add_argument("--micro-tokens", type=int, default=1200)
    p.add_argument("--gc-above-tokens", type=int, default=1200)
    p.add_argument("--lr-lora", type=float, default=1e-4)
    p.add_argument("--lr-head", type=float, default=1e-3)
    p.add_argument("--warmup-frac", type=float, default=0.05)
    p.add_argument("--max-unit-tokens", type=int, default=32768)
    p.add_argument("--dev-units", type=int, default=0, help="use only the first N dev units (smoke)")
    p.add_argument("--step0-n", type=int, default=32)
    p.add_argument("--smoke", action="store_true", help="runs/smoke_fold<k>; no set/fold assertions")
    p.add_argument("--no-eval", action="store_true", help="no step-0 / dev answers / checkpoints (speed tests)")
    p.add_argument("--run-suffix", default="", help="appended to the run directory name")
    for name in ("predict", "readout"):
        p = sub.add_parser(name)
        p.add_argument("--input", required=True)
        p.add_argument("--out", required=True)
        p.add_argument("--set", choices=("dev", "eval"))
        p.add_argument("--unit-fold", type=int, choices=(0, 1, 2))
        p.add_argument("--max-unit-tokens", type=int, default=32768)
        if name == "predict":
            p.add_argument("--fold", type=int, choices=(0, 1, 2), required=True)
            p.add_argument("--ckpt", default="")
            p.add_argument("--ckpt-dir", default="")
            p.add_argument("--model", default="")
            p.add_argument("--unmerged", action="store_true")
    p = sub.add_parser("serve")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8004)
    p.add_argument("--frozen", default="FROZEN", help="l4d_ft/FROZEN (JSON), path under $L4D")
    args = parser.parse_args()
    {"train": cmd_train, "predict": cmd_predict, "readout": cmd_readout, "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
