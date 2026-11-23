# juliet_full/decision_ft — fine-tuned decision model (Qwen3.5-4B + LoRA + 2-way head)

PLAN §3.2 ③ and §5.2. Six independent jobs = folds {0,1,2} × inputs {L1, L3}, trained on 184-toast
(2× RTX 3090, one job per GPU). Everything below was fixed **before** the first real training job started
(2026-11-23 ~19:10 UTC).

## 1. Files

| Path | What |
|---|---|
| `render_data.py` | dell: renders `data/<L1\|L3>/fold<k>/{train,dev,pred}.jsonl` + `data/manifest.json` (input hashes, counts) |
| `server/dft.py` | 184-toast: `train` (one full job) and `speedtest` |
| `server/queue.sh`, `server/start_queue.sh`, `server/status.sh` | queue worker per GPU, starter, status overview |
| `server/env.sh` | sources the gpu lane's `~/disk4/cs224/gpu/server/env.sh` (caches on ~/disk4, `HF_HUB_OFFLINE`, `CPATH` for Triton) |
| `collect.sh` | dell: pull predictions + small artifacts from 184-toast (re-runnable) |
| `results/decision_ft/layer1/` | predictions, contract §4 format (`<strategy>_fold<k>_v1.jsonl`, `dev_<strategy>_fold<k>_v1.jsonl`, `.meta.json`) |
| `runs/<strategy>/fold<k>/` | collected config, selection, dev metrics, train log; `runs/speedtest/` |
| `.venv/` (git-ignored) | dell venv for rendering: transformers 5.22.2 (tokenizer + chat template only) |

Server layout (`~/disk4/cs224/decision_ft/`): `server/` (code copy), `data/` (rsync of `data/`), `queue.txt`,
`status/<job>.json` (+ `<job>.claim/info` with GPU and exit code), `logs/{worker0,worker1,<job>}.log`,
`<strategy>/fold<k>/` (job outputs: `adapter_config.json`, `adapter_model.safetensors`, `head.pt`, `train_log.jsonl`,
`dev_metrics.json`, `selection.json`, `config.json`, `ckpt/step<N>/`, `results/`).

## 2. Data

- Units: `data/build/layer1.jsonl`, verified against `data/build/SHA256SUMS` (sha256 `d4d913c4…`), `changed_units.json` empty.
- Fold-k job: **train** = eval units with fold ≠ k (856/904/896 groups for k = 0/1/2), **dev** = 330 dev groups
  (validation only, never trained on), **pred** = eval units of fold k (472/424/432 groups). Fold k is never seen in training.
- Input text: system = `llm/prompts/task.txt`; user = `PromptSet(L1|L3).user_body(unit, evidence)` (evidence rendered by
  `llm/llmlane/prompts.py:render_evidence`, unchanged) + `"\n\n"` + `Does the executed code unit leak heap memory? Answer Yes or No.`;
  Qwen chat template with `add_generation_prompt=True, enable_thinking=False` (template sha256 in `data/manifest.json`).
  L3 evidence: `static/results/clang_sa/layer1/evidence.jsonl` (all 3,316 units; sha256 in the manifest).
- Token counts (mean / max): L1 ≈ 490–520 / 785, L3 ≈ 540–570 / 830. The server re-tokenises and asserts the same counts.
- Prompt audit: as `llmlane.prompts.audit`, except that the L3 evidence block is scanned without the `memory_leak`
  pattern, because Clang SA's own message "Potential memory leak" occurs in 28 units (code and fixed text still get the full audit).

## 3. Model, loss, optimisation

- Base: `~/disk4/cs224/models/Qwen3.5-4B`, loaded as `Qwen3_5ForCausalLM` (text stack only; `model.visual.*` and `mtp.*` are
  not loaded), BF16, frozen, SDPA attention.
- LoRA (PEFT): r=16, α=32, dropout 0.05, regex
  `model\.layers\.\d+\.(?:self_attn\.(?:q_proj|k_proj|v_proj|o_proj)|linear_attn\.(?:in_proj_qkv|in_proj_z|in_proj_a|in_proj_b|out_proj)|mlp\.(?:gate_proj|up_proj|down_proj))`;
  32,464,896 trainable parameters (asserted), FP32. No LoRA on vision, MTP, embeddings.
- Head: separate `Linear(2560, 2, bias=False)` in FP32, rows initialised from the tied output-matrix rows of `Yes` (id 9175)
  and `No` (id 2665), both single tokens. Input = post-final-norm hidden state at the last prompt position (right padding).
  Score `s = logit_Yes − logit_No` (Yes = leak). Full-vocabulary logits are never computed in training/prediction.
- Loss = class-balanced CE over the 2 logits (weights 1/1, the sets are balanced) + λ·mean_groups −log σ((s_bad − s_good)/τ),
  τ=1, λ=1. Every micro-batch holds whole groups (bad + good).
- AdamW (β 0.9/0.999, weight decay 0), LoRA lr 1e-4, head lr 1e-3, linear warmup 5 % of steps then cosine to 0,
  grad-norm clip 1.0, **8 groups (16 units) per optimizer step**, micro-batch 1 group. Seed 20261123; group order per epoch
  = `torch.randperm` with seed 20261123+epoch over group_ids sorted by name.
- Gradient checkpointing only for micro-batches with > 1200 padded tokens (without it ≈ 10 MB activations/token; a
  1400-token pair already needs 21.9 GB).
- Kernels: `flash-linear-attention` 0.6.0 (`fla.ops.gated_delta_rule.chunk.chunk_gated_delta_rule`, checked at load time and
  written to `config.json`); `causal_conv1d` not installable (no nvcc), so the PyTorch depthwise-conv fallback is used.

## 4. Validation and selection rules (fixed before training; PLAN §3.2 "验证与选择规则")

1. At most **3 epochs** (speed test projects < 6 h wall for all 6 jobs, so no reduction to 2).
2. Dev evaluation every half epoch (optimizer steps ⌈h·steps_per_epoch/2⌉, h = 1…6), plus a step-0 evaluation.
   Dev loss uses the same loss as training.
3. Checkpoint = the evaluated half-epoch checkpoint with the highest **dev AUROC**; ties → lower dev loss.
   Step 0 (the untrained model) is not a candidate.
4. Threshold: per fold model, on s of the dev units, maximising dev **macro-F1**; `pred = 1 if s > threshold`.
   Candidates = midpoints between consecutive distinct dev scores (plus one below/above); ties → candidate closest to 0.
   The threshold is chosen on the merged, batch-size-1 dev scores, i.e. the same scores it is applied to.
5. Dev scores never enter the result tables; all three fold models predict dev (stability). AUROC is reported too.

## 5. Checks

- Step 0 (B = 0): on all 660 dev units, head score vs (a) the tied rows applied to the same hidden state (must be exactly 0)
  and (b) the base model's own `lm_head` Yes−No logit difference (`Qwen3_5ForCausalLM`, adapter disabled, batch 1,
  `logits_to_keep=1`, BF16 logits → differences up to ~0.1 are BF16 rounding of the logits). Also batched (padded) vs
  batch-1 scores, and the zero-shot dev AUROC. Logged in `train_log.jsonl` (step-0 eval) and `dev_metrics.json`.
- Merge: selected adapter merged into the BF16 weights in GPU memory (`merge_adapter`); merged vs unmerged dev scores
  (batch 1) in `dev_metrics.json:merge_check`. Merged full models are never saved.

## 6. Prediction and latency

Held-out fold units and all dev units, one forward each, batch size 1, merged model. `latency_s` = server-side time per
unit on one RTX 3090 with no other job on that GPU (tensor build + H2D + forward + head + readout, synchronised; excludes
tokenisation and LAN). Note this differs from contract §4 "measured on dell". Output rows: method `decision_ft`,
strategy `L1|L3`, model `qwen3.5-4b-lora-fold{k}`, `score` = s, `pred` from the dev threshold,
`extra = {fold, checkpoint, threshold, split, unit_set, unit_fold}`.

## 7. Operating

```bash
# dell: render + upload
PYTHONPYCACHEPREFIX=/tmp/dft-pycache .venv/bin/python render_data.py --strategy L1 --strategy L3
rsync -a server data 184-toast:~/disk4/cs224/decision_ft/
# server: queue (jobs in ~/disk4/cs224/decision_ft/queue.txt: "<strategy> <fold> <max_epochs>")
ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/start_queue.sh'
ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/status.sh'      # monitor
./collect.sh                                                        # dell: pull results (./collect.sh --adapters for weights)
```
Re-run a failed job: remove `status/<job>.claim` and `status/<job>.json` on the server, then `start_queue.sh`.
