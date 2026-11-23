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
| `upload.sh` | dell: rsync `server/`, `data/` and `server/vendor/` (read-only copy of the repo prompt code for the endpoint) |
| `server/stage2.py` | 184-toast: `predict` (merged/unmerged, all layers), `readout` (zero-shot ablation), `combine`, `render-check`, `serve` (:8003) |
| `server/stage2_run.sh`, `server/serve.sh`, `server/release_gpu1.sh` | stage-2 chain on GPU 0, endpoint start/stop/status, GPU-1 hand-off marker |
| `endpoint_client.py` | dell: endpoint spot check and latency300 measurement |
| `score_all.py` | dell: `analysis/score.py --set eval` on all result files + per-fold AUROC → `runs/score/` |
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
  L3 evidence: the frozen Clang SA run `static/results/clang_sa/layer1/EVIDENCE_FROZEN` = `full_v2`
  (`evidence.jsonl` = `full_v2.evidence.jsonl`, sha256 `00897f54…`, all 3,316 units). **All L3 training, dev and prediction
  data use full_v2**; the sha256 is in `data/manifest.json` and in every prediction `.meta.json`.
- v1 evidence incident (2026-11-23): the first L3 render used the earlier `full_v1` (`0bb13404…`, before the static lane's
  `_67` fix), which lacks the leak warning on 28 fold-0 bad `_67` units. Only L3 fold-1/fold-2 training data and L3 fold-0
  prediction data differed (28 units each; dev identical). L3_fold0 had already trained on fold-1+2 data that is identical
  under v1 and v2, so it was kept and its fold-0 predictions were re-done with v2. L3_fold1 (killed at step ~95) and L3_fold2
  (killed right after start) were restarted from scratch on v2 data; the killed runs are kept on the server under
  `superseded/`.
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
strategy `L1|L3`, model `qwen3.5-4b-lora-<L>-fold<k>` (stage 2; stage-1 files used `qwen3.5-4b-lora-fold{k}`), `score` = s, `pred` from the dev threshold,
`extra = {fold, checkpoint, threshold, split, unit_set, unit_fold}`.

## 7. Operating

```bash
# dell: render + upload
PYTHONPYCACHEPREFIX=/tmp/dft-pycache .venv/bin/python render_data.py --strategy L1 --strategy L3
./upload.sh                                                         # server/, server/vendor/, data/
# server: queue (jobs in ~/disk4/cs224/decision_ft/queue.txt: "<strategy> <fold> <max_epochs>")
ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/start_queue.sh'
ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/status.sh'      # monitor
./collect.sh                                                        # dell: pull results (./collect.sh --adapters for weights)
```
Re-run a failed job: remove `status/<job>.claim` and `status/<job>.json` on the server, then `start_queue.sh`.

## 8. Stage 2: reported variant and predictions on all layers

- **Reported variant = MERGED model** (parent decision, PLAN §3.2): all F1, AUROC and latency numbers in the result
  tables come from the merged model (adapter merged into the BF16 weights in GPU memory), and the dev threshold was chosen
  on merged dev scores. The unmerged scores of the layer-1 held-out folds (`results/decision_ft/layer1/unmerged_*`) are an
  appendix check only (§11.2). Merged and unmerged differ by BF16 rounding of `W + (α/r)BA` (merge_check in §11.1).
- Each eval unit is scored by its held-out fold model `qwen3.5-4b-lora-<L>-fold<k>` (k = the unit's fold) with that model's
  dev threshold, with no re-selection and no re-thresholding on any other layer. Batch size 1, one forward per unit, GPU 0
  only, no other job on that GPU.
- Inputs (`render_data.py --layer <layer> --strategy <L>` → `data/<layer>/<L>/eval.jsonl`, 2,656 eval units; hashes in
  `data/manifest.json` under `<layer>/<L>`): L1 on layer3, placebo, original; L3 on layer3 and placebo with the frozen Clang
  evidence of that layer (`static/results/clang_sa/<layer>/EVIDENCE_FROZEN` → `<run_id>.evidence.jsonl`, sha256 checked).
  `original` has no frozen evidence, so it gets L1 only.
- Outputs (contract §4, + `.meta.json` with unit/evidence/prompt/template hashes, metrics at the threshold, load average):
  `results/decision_ft/<layer>/<L>_fold<k>_v1.jsonl` (held-out fold k) and `<L>_cv_v1.jsonl` (all three folds; use this one
  for tables); layer 1 also `dev_<L>_fold<k>_v1.jsonl` and `unmerged_<L>_fold<k>_v1.jsonl`.
- Check: the merged layer-1 held-out scores are re-computed in stage 2 and compared with the stage-1 prediction file
  (`checks.stage1_rescore` in the meta file).

## 9. Zero-shot read-out ablation (`qwen_readout_zeroshot`)

Base Qwen3.5-4B with no adapter and the step-0 head (FP32 rows = tied output rows of `Yes`/`No`), the same prompts and the same
single forward: `s = logit_Yes − logit_No`, primary rule `pred = s > 0`. Secondary: the dev macro-F1 threshold (stored
as `extra.dev_threshold` / `extra.pred_at_dev_threshold`, metrics in the meta file). Run for L1 and L3 on layer-1 eval,
layer-3 eval and layer-1 dev: `results/qwen_readout_zeroshot/<layer>/{,dev_}<L>_v1.jsonl`. This measures what the LoRA adds
over reading the base model's Yes/No logits.

## 10. Endpoint :8003 (contract §6)

`http://10.15.89.184:8003`, GPU 0 of 184-toast, `server/stage2.py serve`.
- `GET /health` → `{"ok": true, "models": [...6 names...], "active", "thresholds", "switch_ms_steady", ...}`.
- `POST /score` `{"code", "language": "c"|"cpp", "strategy": "L1"|"L3", "evidence": <list of Clang warnings {checker, message,
  model_text_line} | null>, "model": "qwen3.5-4b-lora-<L>-fold<k>"}` → `{"score", "threshold", "pred", "latency_ms_server",
  "model", "forward_ms", "switch_ms", "checkpoint", "n_tokens", "prompt_sha256"}`. The server renders the prompt with the
  training template (`render_prompt` = vendored `llmlane.prompts.PromptSet.user_body` + question + chat template;
  `stage2.py render-check` reproduced all rendered training/dev/prediction texts exactly). For L3, `evidence = []` means
  "Clang ran, no warnings"; `null` renders the "no result" text. A model's strategy must match the request strategy.
- All six adapters and heads stay on the GPU; one model is merged at a time. Switching = unmerge, restore the exact
  base weights from a GPU copy, load the other adapter, merge (so the weights equal those used by `predict`). Requests are
  serialised (one lock). Group requests by model to avoid switch costs.
- Start / stop / status (on 184-toast; `serve.sh` sources the env scripts):
  ```bash
  ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/serve.sh start'    # ready when logs/serve.log prints "ready"
  ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/serve.sh status'   # pid + /health
  ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/serve.sh stop'
  ```
- dell checks: `python3 endpoint_client.py check` (20 held-out + 2 dev units, → `runs/endpoint/spot_check.json`);
  `flock /tmp/cs224_latency.lock python3 endpoint_client.py latency` (latency300, → `results/decision_ft/layer1/latency300_<L>_v1.jsonl`).

## 11. Results (2026-11-23, collected to dell; scored with `analysis/score.py --set eval` via `score_all.py`)

All rows: `runs/score/summary.json` (full score.py reports per file in `runs/score/`). Macro-F1 = end-to-end, family
bootstrap 95 % CI; no invalid or missing units. AUROC per fold = within each held-out fold model; the pooled AUROC mixes
three score scales and is lower (layer 1: L1 0.978, L3 0.977), so the per-fold values are the meaningful ones.

### 11.1 Selection (rule §4: dev AUROC, ties → lower dev loss)

Dev AUROC is 1.0 at almost every half-epoch evaluation (step-0: L1 0.8918, L3 0.9075 batched). In practice the
selection is therefore made by the lowest dev loss. Dev macro-F1 is 1.0 at the threshold for all six models.

| job | selected | epoch | evals with AUROC 1.0 | dev loss | threshold | merge_check dev max / mean abs Δ | dev bs1 latency merged / unmerged |
|---|---|---|---|---|---|---|---|
| L1 fold0 | step107 | 1.0 | 6/6 | 2.4e-7 | 2.5137 | 0.482 / 0.102 | 0.091 / 0.120 s |
| L1 fold1 | step170 | 1.5 | 5/6 (step57 0.9995) | 1.6e-20 | −2.6556 | 0.354 / 0.076 | 0.087 / 0.116 s |
| L1 fold2 | step336 | 3.0 | 6/6 | 2.2e-7 | −2.0862 | 0.322 / 0.059 | 0.086 / 0.115 s |
| L3 fold0 | step268 | 2.5 | 5/6 (step54 0.9961) | 4.8e-22 | −0.7383 | 0.404 / 0.093 | 0.119 / 0.152 s |
| L3 fold1 | step57 | 0.5 | 6/6 | 9.0e-10 | 9.8103 | 2.010 / 0.107 | 0.112 / 0.144 s |
| L3 fold2 | step336 | 3.0 | 6/6 | 1.7e-7 | −0.2781 | 0.348 / 0.123 | 0.119 / 0.151 s |

The L3 fold1 threshold (9.81) is the single midpoint between the highest good dev score (−13.6) and the lowest bad
dev score (33.2). Merged-vs-unmerged differences come from BF16 rounding of `W + (α/r)BA`; they are larger in absolute
terms because the scores are large (|s| ≈ 15–40). No held-out prediction flips between merged and unmerged (0 of 2,656
for L1 and for L3). The stage-2 re-score of the merged layer-1 held-out fold equals the stage-1 file exactly
(max |Δ| = 0), except for L3 fold0's 28 `_67` units, whose evidence changed from full_v1 to full_v2.

### 11.2 Eval scores (merged = reported; `<L>_cv_v1.jsonl`, 2,656 eval units per layer)

| method / input | layer | macro-F1 [95 % CI] | P_leak | R_leak | spec. | AUROC per fold (0/1/2) |
|---|---|---|---|---|---|---|
| decision_ft L1 | layer1 | 0.984 [0.982, 0.986] | 0.999 | 0.969 | 0.999 | 0.999 / 0.957 / 1.000 |
| decision_ft L3 | layer1 | 0.983 [0.981, 0.986] | 0.993 | 0.974 | 0.993 | 0.999 / 0.981 / 1.000 |
| decision_ft L1 | layer3 | 0.372 [0.346, 0.404] | 0.647 | 0.041 | 0.977 | 0.691 / 0.677 / 0.703 |
| decision_ft L3 | layer3 | 0.639 [0.615, 0.665] | 0.903 | 0.379 | 0.959 | 0.911 / 0.867 / 0.888 |
| decision_ft L1 | placebo | 0.976 [0.969, 0.982] | 0.999 | 0.953 | 0.999 | 0.999 / 0.948 / 1.000 |
| decision_ft L3 | placebo | 0.970 [0.962, 0.976] | 0.994 | 0.945 | 0.995 | 0.999 / 0.982 / 1.000 |
| decision_ft L1 | original | 0.944 [0.937, 0.949] | 0.922 | 0.969 | 0.918 | 0.991 / 0.943 / 1.000 |

Per fold on layer 1: macro-F1 L1 0.998 / 0.953 / 1.000 and L3 0.999 / 0.952 / 0.998. Fold 1 is the weak fold for both inputs.

Appendix: unmerged layer-1 held-out (`unmerged_<L>_fold<k>_v1.jsonl`, same dev thresholds): L1 macro-F1 0.984
[0.982, 0.986], AUROC per fold 0.999 / 0.956 / 1.000; L3 0.983 [0.981, 0.986], AUROC per fold 0.999 / 0.981 / 1.000.

### 11.3 Zero-shot read-out ablation (`qwen_readout_zeroshot`, base model + step-0 head)

| input | layer | macro-F1 at s > 0 (primary) | macro-F1 at dev threshold | AUROC (pooled; one model) |
|---|---|---|---|---|
| L1 | layer1 dev | 0.356 | 0.794 (thr −1.203) | 0.884 |
| L3 | layer1 dev | 0.337 | 0.833 (thr −1.651) | 0.905 |
| L1 | layer1 eval | 0.375 [0.367, 0.384] | 0.703 | 0.789 |
| L3 | layer1 eval | 0.345 [0.337, 0.356] | 0.773 | 0.862 |
| L1 | layer3 eval | 0.351 [0.345, 0.358] | 0.619 | 0.729 |
| L3 | layer3 eval | 0.334 [0.333, 0.336] | 0.671 | 0.820 |

At s > 0 the base model almost always answers "No" (recall_leak 0.001–0.039). The ranking signal is real but uncalibrated.

### 11.4 Endpoint and latency

- :8003 runs on GPU 0 (15.3 GB allocated, all six adapters cached). Steady model switch cost ≈ 211 ms (unmerge, restore
  base weights, load, merge). Spot check (`runs/endpoint/spot_check.json`): 20 held-out eval units from all six models
  plus 2 dev units (L1 fold1 bad, L3 fold2 good). Score |Δ| vs the stored merged predictions = 0.0 for all 22, prompt
  sha256 equal to the rendered data text for all 22, and all preds equal.
- dell concurrency-1 latency, latency300 (300 eval units, held-out fold models, grouped by model, 5 warm-ups each,
  `flock /tmp/cs224_latency.lock`). The lock was acquired at 22:56:05Z with load1 1.16, so there was no quiet wait.
  Results in `results/decision_ft/layer1/latency300_<L>_v1.jsonl`:

| input | load1 start → end | end-to-end median / p90 | server handler median / p90 | GPU forward median |
|---|---|---|---|---|
| L1 | 1.16 → 1.61 | 0.105 / 0.130 s | 0.084 / 0.111 s | 0.083 s |
| L3 | 1.61 → 2.16 | 0.133 / 0.148 s | 0.113 / 0.116 s | 0.112 s |

  Server handler = render + tokenise + forward. End-to-end adds about 20 ms (JSON over the LAN plus HTTP). Note: a short
  single-core `score.py` run overlapped part of the L1 measurement on dell. load1 stayed below 2.5 throughout.
