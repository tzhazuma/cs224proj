# L4-D LoRA decision model — stage 1 report (lane l4d-train)

Status 2026-11-24 09:20 PST. All accuracy and latency results are final (latency: §6; GPU-0 chain: §8).
Primary latency everywhere = the prediction configuration (PyTorch causal_conv1d fallback).

## 1. Verdict (contract §6, PLAN §4.2)

Primary comparison, per the user decision of 2026-11-24 07:05: DeadFree (layer3) only. The speed goal is "faster than
the DeepSeek API" (c1 median 0.715 s).

| | macro-F1 nested25 [95% CI] | DeepSeek L1 same units | Δ [95% family-cluster CI] | near-LLM (≥ ref−0.02) | equivalent (CI low ≥ −0.02) |
|---|---|---|---|---|---|
| **DeadFree, L4-D (lora_l4d)** | 0.831 [0.798, 0.862] | 0.881 | −0.049 [−0.085, −0.016] | FAIL | FAIL |
| DeadFree, L4-D (opt.) (post-hoc) | identical verdicts → 0.831 | 0.881 | −0.049 [−0.085, −0.016] | FAIL | FAIL |
| Debiased (layer1), L4-D, full eval 2,656 | 0.959 [0.954, 0.964] | 0.995 | −0.037 [−0.042, −0.031] | FAIL | FAIL |
| Placebo, L4-D | 0.958 [0.945, 0.970] | 0.995 | −0.038 [−0.051, −0.025] | FAIL | FAIL |
| Original, L4-D | 0.928 [0.913, 0.942] | 0.961 | −0.033 [−0.049, −0.018] | FAIL | FAIL |

- L4-D fails "near-LLM quality" on every layer. On DeadFree, the best DeepSeek strategy (L4, 0.895) is
  0.063 [0.023, 0.105] ahead.
- On DeadFree L4-D is a large improvement over the old single-question LoRA (L1 0.372, L3 0.639), over the zero-shot
  read-out (0.752 full eval) and over the structure-only baseline (0.333). Gain over structure-only: +0.493 full eval.
- On Original, L4-D (0.931 full eval) is **below** the structure-only baseline (0.935).
- **Speed (DeadFree latency300, c1, end to end from dell; primary = fallback config).**
  - L4-D (opt.): median 0.472 s, p90 1.018 s. This is < 0.715 s, so it is faster than the DeepSeek API.
  - Full L4-D: median 1.006 s, p90 2.257 s. This is slower than DeepSeek.
  - Neither variant meets the original §6 limit of 0.36 s on DeadFree. On Debiased (layer1): opt 0.214 s, full 0.645 s.
  - Old LoRA L1/L3 on DeadFree latency300: 0.120 / 0.125 s (same prediction config).
- Overall, per PLAN §4.2: **no strong support**. Strong support needs near-LLM quality on all 4 layers plus speed;
  quality fails everywhere. What L4-D does show is the DeadFree robustness gain over the old LoRA (+0.19 over L3,
  +0.46 over L1), still 5–6 points below DeepSeek.

## 2. Training (contract §5)

- Model, as in decision_ft:
  - Qwen3.5-4B (BF16, sdpa) + LoRA r16 α32 dropout 0.05 on the explicit language-model linear modules (32,464,896
    trainable).
  - FP32 2×2560 head initialised from the tied Yes/No rows (ids 9175/2665); s = logit_Yes − logit_No.
  - Chat template with enable_thinking=False.
  - Prompt template sha 28386a4f…5756 (`server/l4d_prompt.py`).
- Step-0 check: head − tied rows 0.0; bs1 vs base lm_head max 0.116, mean 0.048; unit-batched vs bs1 max 0.141 (BF16).
- Data:
  - fold k trains on layer1 eval units with fold ≠ k; gold null dropped.
  - 14,000 questions per fold (13,999 for folds 1/2), subsampled per (qtype, label) cell with a cap
    (4171/4573/4037).
  - Class-balanced CE weights n_kept/(n_cells·n_cell); `render.py train`.
  - Train-file sha256 ad73249e…, cfd54c61…, bd6c4414….
- Optimiser: AdamW, LoRA lr 1e-4, head lr 1e-3, wd 0, warmup 5 % + cosine, clip 1.0, 32 questions/step,
  micro-batches ≤ 1200 tokens.
  - 1.5 epochs = 657 steps; dev evals at steps 0/219/438/657 (2 per epoch).
- Parallelism: option (a), 2-GPU DDP per fold, folds sequential. Measured 2.00× speed-up (`build/speedtest.json`);
  co-locating two jobs on one GPU gave only 0.67×.

| fold | wall (UTC) | train s | GPU-h (2 GPUs, incl. 4 dev evals ≈ 20 min) | peak mem/GPU | tokens |
|---|---|---|---|---|---|
| 0 | 06:44–07:53 | 3,550 | ≈2.3 | 20.09 GB | 9.78 M |
| 1 | 08:05–09:12 | 3,371 | ≈2.2 | 20.09 GB | 9.18 M |
| 2 | 09:12–10:20 | 3,445 | ≈2.3 | 20.09 GB | 9.61 M |

## 3. Dev selection (layer1 dev, 660 units, 6,332 questions; unit macro-F1 through derive.py, τ grid sigmoid(0.5 t))

| fold | step0 mF1 / q-AUROC | step219 | step438 | step657 | selected |
|---|---|---|---|---|---|
| 0 | 0.868 / 0.604 | **0.991 / 0.9991 (τ 0.8176)** | 0.965 / 0.9985 | 0.965 / 0.9985 | step219 |
| 1 | 0.868 / 0.604 | **1.000 / 1.000 (τ 0.5)** | 1.000 / 1.000 | 1.000 / 1.000 | step219 (tie → earliest) |
| 2 | 0.868 / 0.604 | **1.000 / 1.000 (τ 0.5)** | 1.000 / 1.000 | 1.000 / 1.000 | step219 (tie → earliest) |

- These are unmerged in-training evals. The frozen τ was re-chosen on merged dev answers: fold0 τ 0.817574 (merged
  dev mF1 0.989), folds 1/2 τ 0.5 (1.0).
- Layer1 dev is saturated. Fold1 dev = 1.0 but fold1 eval = 0.931. Selection was therefore close to arbitrary, and
  step219 = 0.5 epoch for every fold.

## 4. FROZEN (`l4d_ft/FROZEN`, sha256 8019da174a526de2632da72fbf0e552c2ec86c81bc04f1ac3a1184e5bf8edd1b)

| entry | checkpoint | adapter sha256 | head sha256 | τ | frozen UTC |
|---|---|---|---|---|---|
| fold0 | runs/fold0/ckpt/step219 | 77f9f88b4c561ee1bf80837dde9ce9dcab14fbadcdb10ef34ff21485e3f1a7a1 | ff0c2de16846eed9d4cd640b3da193e5343db9fbb44bd1cb4677eb402db9132d | 0.817574 | 2026-11-24T08:07:18Z |
| fold1 | runs/fold1/ckpt/step219 | 6b50c79fe2aa20fce6f65ae2424892287b3308d9f4aef927007b2e4ea620e1e0 | 41c0b71e86e64e59478e07e888a4061540d90914ba8f5cdb29f5950c47be7b86 | 0.5 | 2026-11-24T12:01:17Z |
| fold2 | runs/fold2/ckpt/step219 | 0d994bede1ca9357943d49440105a0724757f8c4e63d81ddc1b3f191dc4ccfd7 | c9be7de9a1e6cbdb43c89a38a8ddc4aebb6d8d05376032b961d8fd2b882b6b5a | 0.5 | 2026-11-24T11:02:13Z |
| readout (qwen_readout_l4d) | base + step-0 head | – | – | 0.268941 (dev mF1 0.868, q-AUROC 0.604) | 2026-11-24T08:07:18Z |

Common hashes (sha256):
- l4d templates 316429b2…7516; templates.py 678d7c74…; prompt 28386a4f…5756; chat template a4aee8af…f715
- derive.py f3a0e634…65b7; rules l4d.dl ca2d6380…14ec
- questions_layer1 510e38b1…1de30; rendered q_layer1 06193a97…6bf
- questions_other (recorded 08:07:45Z): layer3 0264524d…, placebo b0e816e5…, original cdb4bdbe…

The adapter config sha is identical for all folds (2d712e91…).

Freeze rule:
- Every fold's eval predictions started after its entry: fold0 eval at 10:20Z, fold2 eval at 13:04Z, fold1 eval at
  12:52Z.
- Non-layer1 questions were rendered only after 08:07:45Z.
- `server/l4dft.py` `freeze_guard` re-checks the checkpoint dir and the adapter/head sha against FROZEN before every
  eval or non-layer1 prediction.

## 5. Optimized inference (post-hoc, user-approved 2026-11-24)

- `lora_l4d_opt` ("L4-D (opt.)") asks only the questions the v1 rules read, by site kind (`prune.py needed()`; the
  rule is static, from the l4d.dl rule bodies):
  - keep `heap` on alloc sites; `exec_any` on alloc/realloc; `exec_all` on release/realloc; all `rel`; all
    `realloc_safe`.
  - Everything else is never joined by a rule body, so it cannot change any leak/freed fact. A unit with no kept
    question has no heap/realloc fact, so it gets pred 0 and score 0 without a model call.
- Tests (`prune.py test` → `results/scores/prune_test.json`, PASS):
  - gold oracle, pruned vs full, every layer and set: 0 pred / score / leak-list differences.
  - stored answers of 3 folds × 4 layers: 0 differences.
- Predictions `results/lora_l4d_opt/<layer>/eval_r1_units.jsonl` are derived from the stored lora_l4d answers
  (`extra.derived_from`), so the scores are identical to lora_l4d.

Questions per unit, full → opt:

| layer | eval median/p90 | latency300 median/p90 | kept on eval |
|---|---|---|---|
| layer1 | 9/17 → 2/7 | 9/18 → 2/7 (21 zero-question units) | 32 % |
| layer3 | 13/21 → 6/10 | 13/22 → 6/10 | 42 % |
| placebo | 11/19 → 2/7 | 11/20 → 2/7 | 26 % |
| original | 18/48 → 4/18 | 18/48 → 4/18 | 33 % |

Pruning happens client-side in `latency.py --prune` (parse → questions → prune → one POST /l4d with the kept
questions → derive), not as a server flag. It is inside the timed e2e.

## 6. Latency (latency300, concurrency 1, e2e from dell, `flock /tmp/cs224_latency.lock`, load1 < 2.5, GPU0 only)

- e2e = live tree-sitter parse + question building (+ prune) on dell + POST /l4d (server: chat-template render,
  tokenise, one forward batch of all of the unit's questions, merged fold model) + derive on dell.
- Adapter switches are excluded (one warm-up per fold).
- GPU1 was busy with other lanes (VulnLLM-R, then the latency-deadfree lane's Qwen/Intern); this is recorded in
  each meta `gpu_note`.

| layer | variant | conv1d | e2e median / p90 s | server forward median / p90 | parse median | q/unit median | status |
|---|---|---|---|---|---|---|---|
| layer3 | L4-D (opt.) | **fallback (primary)** | **0.472 / 1.018** | 0.426 / 0.953 | 1.6 ms | 6 | done |
| layer3 | L4-D full | **fallback (primary)** | **1.006 / 2.257** | 0.945 / 2.181 | 1.6 ms | 13 | done |
| layer3 | L4-D (opt.) | kernel (secondary) | 0.445 / 0.958 | 0.399 / 0.884 | 1.6 ms | 6 | done |
| layer3 | L4-D full | kernel (secondary) | 0.933 / 2.097 | 0.879 / 2.023 | 1.4 ms | 13 | done |
| layer1 | L4-D (opt.) | **fallback (primary)** | **0.214 / 0.619** | 0.192 / 0.583 | 1.6 ms | 2 (21 units no model call) | done |
| layer1 | L4-D full | **fallback (primary)** | **0.645 / 1.479** | 0.599 / 1.420 | 1.4 ms | 9 | done |
| layer1 | L4-D (opt.) / full | kernel (secondary) | not measured | | | | aborted: kernel not equivalent (rule 08:00) |
| layer3 | old LoRA L1 (:8003, decision_ft) | fallback (prediction config) | 0.120 / 0.135 | 0.108 / 0.123 | – | 1 | done |
| layer3 | old LoRA L3 (:8003, decision_ft) | fallback (prediction config) | 0.125 / 0.145 | 0.112 / 0.129 | – | 1 | done |

- Reference points: DeepSeek API c1 0.715 s (DeadFree); old LoRA L1 layer1 0.105 s e2e (decision_ft README).
- Old LoRA rows: `decision_ft/endpoint_client.py cmd_latency` unchanged (its own e2e definition, 5 warm-ups per fold
  model, DeadFree units + frozen clang_sa layer3 evidence `full_v1`), outputs `results/kernel/decision_ft/fallback/layer3/latency300_L{1,3}_v1.jsonl` + meta;
  live scores equal the stored `decision_ft/results/decision_ft/layer3/L{1,3}_cv_v1.jsonl` (max |Δscore| 0.0,
  0 pred flips; `results/scores/kernel_equiv_decision_ft_layer3_fallback.json`).
- Debiased (layer1) speed: opt 0.214 s median meets the original 0.36 s limit (post-hoc variant); full 0.645 s does
  not. Both are below DeepSeek's DeadFree 0.715 s; L4-D is 2–8× slower than the old single-question LoRA.
- §6 speed criterion, original definition (median ≤ 0.36 s): FAIL for both (opt 0.472, full 1.006).
- User-revised speed goal (faster than DeepSeek 0.715 s): **opt PASS (post-hoc variant); full FAIL (1.006 s)**.
- Placebo/original latency were skipped as optional (user decision 07:05).

## 7. Kernel (causal_conv1d 1.7.0) and equivalence

- Build:
  - Built from the PyPI sdist for sm_86, against the venv's CUDA 13 headers, with `-DCCCL_DISABLE_CTK_COMPATIBILITY_CHECK`.
  - Wheel sha256 5a988e13…a48d, installed into `~/disk4/cs224/pyext_cc1d`; enabled only via PYTHONPATH. The shared
    venv is untouched.
- Standalone kernel vs reference conv on GPU0: max abs diff 0.0296 (BF16, ref scale 5.3).
- Equivalence, live endpoint vs the stored frozen fallback answers (`kernel/compare_l4d.py` →
  `results/scores/kernel_equiv_*.json`), DeadFree latency300:

| live run | questions | max / mean abs Δp_yes | question flips @0.5 | unit verdict flips |
|---|---|---|---|---|
| opt, kernel | 1,779 | 0.985 / 0.0030 | 5 | 1 |
| full, kernel | 4,206 | 0.985 / 0.0022 | 11 | 3 |
| opt, fallback | 1,779 | 0.984 / 0.0024 | 6 | 2 |
| **full, fallback** | 4,206 | **0.0 / 0.0** | **0** | **0** |
| Debiased (layer1): opt, fallback | 1,010 | 0.196 / 0.0008 | 1 | 0 |
| Debiased (layer1): **full, fallback** | 3,065 | **0.0 / 0.0** | **0** | **0** |

- Kernel vs fallback live (opt, same batches): max abs Δp 0.501, mean 0.0027, 1 verdict flip.
- **Findings.**
  - The live endpoint in the prediction config, with the same per-unit batch (full L4-D, fallback), reproduces the
    stored predictions bit-exactly: Δp 0, 0 flips.
  - The kernel changes p even with the same batch: 3/300 verdict flips.
  - Pruning (opt) changes the batch composition per forward (fewer questions, different padding). Under BF16 this
    moves borderline questions a lot, e.g. `layer3/CWE401_Memory_Leak__new_char_16__good/exec_all/s02`: p 0.012
    stored vs 0.996 live (opt; both kernel settings). The result is 2/300 verdict flips, although the prune rule
    itself is exactly verdict-preserving (prune test with stored answers: 0 flips).
  - The fine-tuned model is numerically sensitive on a small set of questions. Mean |Δp| is about 0.002–0.003.
  - So the reported `lora_l4d_opt` accuracy (derived from the stored full-batch answers) matches the live opt
    endpoint on 298/300 DeadFree units.
- Consequence, following the project rule of 08:00:
  - Primary latency = fallback; kernel rows are secondary.
  - `serve_l4d.sh` defaults to the fallback (`L4D_KERNEL=0`).
  - :8003 is restored in its prediction config (plain `serve.sh start`).
  - Full L4-D live verdicts equal the stored results; opt live verdicts differ on ~0.7 % of DeadFree units.
- Not done, for lack of time/priority: decision_ft :8003 with kernel; Intern-Decision (skipped per parent 07:45 — the
  latency-deadfree lane measures it).

## 8. GPU-0 chain (done)

The detached chain `kernel/gpu0_chain.sh` ran from 16:33:08Z to 17:05:56Z (log `raw_logs/gpu0_chain.log`):
1. `kernel/lat_all.sh fallback … opt:layer3 full:layer3 opt:layer1 full:layer1` (log `raw_logs/lat_fallback.log`;
   all done 16:55:39Z).
2. `serve_l4d.sh stop` on GPU0 (GPU0 then 38 MiB).
3. `bash ~/disk4/cs224/decision_ft/server/serve.sh start` (:8003, prediction config, no kernel PYTHONPATH) at
   16:56:21Z; /health ok at 16:56:44Z.
4. `flock /tmp/cs224_latency.lock python3 kernel/dft_lat300.py --tag fallback --layer layer3` (exit 0, 17:05:55Z).
5. `touch ~/disk4/cs224/GPU0_L4D_DONE` at 17:05:56Z; :8003 left running (GPU0 16.3 GB).

## 9. Demo interface — :8004 (`server/serve_l4d.sh`, also at `184-toast:~/disk4/cs224/l4d_ft/server/serve_l4d.sh`)

- `L4D_GPU=1 bash ~/disk4/cs224/l4d_ft/server/serve_l4d.sh start|stop|health|status`
  - Defaults: GPU 1, port 8004, `l4dft.py serve --port 8004 --frozen FROZEN`, L4D_KERNEL=0.
  - Log `~/disk4/cs224/l4d_ft/logs/serve_l4d.log`; ready in ~20 s; ~15.8 GB on the GPU (3 merged fold models cached).
- `GET /health` → `{"ok", "folds", "active", "tau": {"0":0.817574,"1":0.5,"2":0.5}, "template_sha256", "gpu", "kernels", ...}`.
- `POST /l4d` request:
  `{"fold": k, "questions": [{"qid": "...", "state": "<numbered model_text>", "question": "<question text>"}, ...]}`
  - All questions of one unit go in one request; they are answered in one forward batch.
  - `fold` = the fold model to use: for an eval unit, its own fold; for new code (demo), use any fold (e.g. 2, the
    strongest on eval) and report it.
- Response:
  `{"fold", "checkpoint", "tau", "n_questions", "n_tokens", "n_forward_chunks", "answers": [{"qid", "p_yes",
  "logit_diff"}, ...] (same order), "render_tokenize_ms", "forward_ms", "latency_ms_server", "switch_ms"}`.
  - The first request after a fold change pays a ~0.2 s adapter switch (`switch_ms`).
- E2E verdict recipe (as in `latency.py`; Python on the client, using `juliet_full/l4d` read-only):

```python
import sys; sys.path.insert(0, "juliet_full/l4d"); sys.path.insert(0, "juliet_full/l4d_ft")
import derive; from questions import make_questions; from prune import prune
unit = {...}                          # unit row: model_text, language, unit_id, ... (data/build/<layer>.jsonl schema)
qs = prune(make_questions(unit, layer))   # sites -> questions -> keep only rule-relevant ones (opt); drop prune() for full
if not qs: pred, score = 0, 0.0      # no heap/realloc fact -> no leak, no model call
else:
    r = POST(":8004/l4d", {"fold": k, "questions": [{"qid": q["qid"], "state": q["state"], "question": q["question"]} for q in qs]})
    p = {(q["qtype"], tuple(q["site_ids"])): a["p_yes"] for q, a in zip(qs, r["answers"])}
    res = derive.evaluate_unit(derive.unit_inputs(qs), p, r["tau"])   # tau = the fold's frozen tau, from the response
    pred, score, leaks = res["pred"], res["score"], res["leaks"]
```

## 10. Services

- 22:43 PST (11-23): all three services were stopped for training (nvidia-smi verified only they used the GPUs).
- GPU1 was handed over at 14:26:47Z (`GPU1_FREE_FOR_VULNLLMR`). :8001/:8002 are restored by the VulnLLM-R /
  latency-deadfree lanes on GPU1, not by this lane (revised plan); at 16:13Z Qwen vLLM and decide_server were running
  on GPU1.
- :8003 restored on GPU0 by the chain (§8), prediction config. Health 2026-11-24 ~17:15Z (dell,
  `curl http://10.15.89.184:8003/health`): `{"ok":true,"models":[L1-fold0..2, L3-fold0..2],...}`; also ok at
  16:56:44Z and 17:05:55Z. `GPU0_L4D_DONE` touched 17:05:56Z.
- :8001 and :8002 (GPU1, owned by the latency-deadfree lane) both answered /health HTTP 200 at the same time;
  not touched by this lane.
- `SERVE_L4D_READY` touched at 16:14:10Z.

## 11. Deviations and risks

- Speed: the §6 0.36 s median is missed. Only the post-hoc opt variant beats DeepSeek (0.715 s).
- Dev saturation: layer1 dev macro-F1 is 1.0 for folds 1/2, so checkpoint selection was uninformative.
  - step219 (0.5 epoch) for every fold; later steps overfit completely (fold0 loss exactly 0).
  - Fold quality varies: fold1 eval is weakest (layer1 0.931, rel accuracy 0.83).
- The fold0 τ (0.8176) differs from folds 1/2 (0.5).
- Oracle ceiling: derive with gold facts gives layer1 eval 0.991 (variant-12 complementary frees); original 0.985
  per the l4d-data lane.
- causal_conv1d is not installed in the shared venv. Every stored prediction used the PyTorch fallback conv; the kernel
  is not equivalent at verdict level (§7).
- Live opt endpoint vs stored batch predictions: 2 verdict flips per 300 DeadFree units, from BF16 batch-shape effects (§7). Full L4-D is bit-exact.
- On Original, L4-D is below the structure-only baseline (0.931 vs 0.935). The cross-function `rel` facts are weak
  there (accuracy 0.732).
- The latency lock was shared with other lanes. My runs waited ~35 min (VulnLLM-R run) and are now waiting again for
  the latency-deadfree lane; the timing itself ran with GPU0 otherwise idle.
- `results/intern_l4d/` inside l4d_ft was not written by this lane.
- `results/` holds question-level files (~120 MB). Only `data/` and `build/` are git-ignored, as per my
  `.gitignore`.

## 12. Context: other systems (eval macro-F1)

| layer | L4-D (all eval) | L4-D (opt.) | zero-shot readout L4-D | structure-only | old LoRA L1 / L3 (decision_ft) | DeepSeek L1 / best (same units as §1) |
|---|---|---|---|---|---|---|
| layer1 (Debiased) | 0.959 | 0.959 | 0.868 | 0.792 | 0.984 / 0.983 | 0.995 / 0.998 (L2) |
| layer3 (DeadFree) | 0.826 | 0.826 | 0.752 | 0.333 | 0.372 / 0.639 | 0.881 / 0.895 (L4) |
| placebo | 0.963 | 0.963 | 0.871 | 0.792 | 0.976 / 0.970 | 0.995 / 0.995 (L1) |
| original | 0.931 | 0.931 | 0.737 | 0.935 | 0.944 / – | 0.961 / 0.961 (L1) |

# Appendix A: generated tables (`python3 report_tables.py`, from `results/scores/*.json`)

## Unit level, all eval units (analysis/score.py --set eval)

| layer | method | n | macro-F1 [95% CI] | P(leak) | R(leak) | specificity | invalid | latency_s median (model+derive) |
|---|---|---|---|---|---|---|---|---|
| layer1 | lora_l4d | 2656 | 0.959 [0.954, 0.964] | 0.962 | 0.956 | 0.962 | 0 | 0.606 |
| layer1 | qwen_readout_l4d | 2656 | 0.868 [0.845, 0.886] | 0.835 | 0.916 | 0.819 | 0 | 0.591 |
| layer1 | structure-only (all Yes, τ 0.5) | all eval | 0.792 | | | | | |
| layer3 | lora_l4d | 2656 | 0.826 [0.811, 0.843] | 0.829 | 0.823 | 0.830 | 0 | 1.011 |
| layer3 | qwen_readout_l4d | 2656 | 0.752 [0.730, 0.772] | 0.826 | 0.647 | 0.864 | 0 | 1.024 |
| layer3 | structure-only (all Yes, τ 0.5) | all eval | 0.333 | | | | | |
| placebo | lora_l4d | 2656 | 0.963 [0.958, 0.967] | 0.969 | 0.956 | 0.970 | 0 | 0.885 |
| placebo | qwen_readout_l4d | 2656 | 0.871 [0.848, 0.891] | 0.830 | 0.935 | 0.809 | 0 | 0.892 |
| placebo | structure-only (all Yes, τ 0.5) | all eval | 0.792 | | | | | |
| original | lora_l4d | 2656 | 0.931 [0.925, 0.936] | 0.910 | 0.956 | 0.906 | 0 | 1.504 |
| original | qwen_readout_l4d | 2656 | 0.737 [0.714, 0.756] | 0.682 | 0.916 | 0.572 | 0 | 1.448 |
| original | structure-only (all Yes, τ 0.5) | all eval | 0.935 | | | | | |

## Same units as the DeepSeek reference (layer1: full eval 2,656; others: nested25 eval 664)

| layer | system | macro-F1 [95% CI] | P(leak) | R(leak) | Δ model − this (paired family bootstrap) [95% CI] |
|---|---|---|---|---|---|
| layer1 | **lora_l4d** (full eval, n=2656) | 0.959 [0.954, 0.964] | 0.962 | 0.956 | |
| layer1 | **qwen_readout_l4d** (full eval, n=2656) | 0.868 [0.845, 0.886] | 0.835 | 0.916 | |
| layer1 | DeepSeek L1 | 0.995 [0.993, 0.998] | 0.991 | 1.000 | lora_l4d: -0.037 [-0.042, -0.031]; qwen_readout_l4d: -0.128 [-0.152, -0.109] |
| layer1 | DeepSeek L2 (best DeepSeek) | 0.998 [0.996, 0.999] | 0.996 | 1.000 | lora_l4d: -0.039 [-0.044, -0.034]; qwen_readout_l4d: -0.130 [-0.154, -0.111] |
| layer1 | DeepSeek L3 | 0.995 [0.992, 0.998] | 0.990 | 1.000 | lora_l4d: -0.036 [-0.041, -0.032]; qwen_readout_l4d: -0.128 [-0.152, -0.108] |
| layer1 | DeepSeek L4 | 0.976 [0.973, 0.980] | 0.978 | 0.974 | lora_l4d: -0.017 [-0.023, -0.012]; qwen_readout_l4d: -0.109 [-0.134, -0.090] |
| layer3 | **lora_l4d** (nested25 eval, n=664) | 0.831 [0.798, 0.862] | 0.825 | 0.840 | |
| layer3 | **qwen_readout_l4d** (nested25 eval, n=664) | 0.742 [0.708, 0.774] | 0.817 | 0.633 | |
| layer3 | DeepSeek L1 | 0.881 [0.852, 0.906] | 0.850 | 0.925 | lora_l4d: -0.049 [-0.085, -0.016]; qwen_readout_l4d: -0.139 [-0.169, -0.111] |
| layer3 | DeepSeek L2 | 0.887 [0.857, 0.912] | 0.848 | 0.943 | lora_l4d: -0.055 [-0.091, -0.020]; qwen_readout_l4d: -0.145 [-0.173, -0.117] |
| layer3 | DeepSeek L3 | 0.890 [0.863, 0.915] | 0.845 | 0.955 | lora_l4d: -0.058 [-0.093, -0.024]; qwen_readout_l4d: -0.147 [-0.180, -0.119] |
| layer3 | DeepSeek L4 (best DeepSeek) | 0.895 [0.865, 0.924] | 0.907 | 0.880 | lora_l4d: -0.063 [-0.105, -0.023]; qwen_readout_l4d: -0.152 [-0.195, -0.113] |
| placebo | **lora_l4d** (nested25 eval, n=664) | 0.958 [0.945, 0.970] | 0.966 | 0.949 | |
| placebo | **qwen_readout_l4d** (nested25 eval, n=664) | 0.858 [0.832, 0.882] | 0.812 | 0.934 | |
| placebo | DeepSeek L1 (best DeepSeek) | 0.995 [0.990, 1.000] | 0.994 | 0.997 | lora_l4d: -0.038 [-0.051, -0.025]; qwen_readout_l4d: -0.138 [-0.163, -0.115] |
| placebo | DeepSeek L3 | 0.994 [0.988, 0.999] | 0.988 | 1.000 | lora_l4d: -0.036 [-0.050, -0.023]; qwen_readout_l4d: -0.136 [-0.162, -0.113] |
| original | **lora_l4d** (nested25 eval, n=664) | 0.928 [0.913, 0.942] | 0.910 | 0.949 | |
| original | **qwen_readout_l4d** (nested25 eval, n=664) | 0.728 [0.695, 0.757] | 0.674 | 0.916 | |
| original | DeepSeek L1 (best DeepSeek) | 0.961 [0.948, 0.973] | 0.927 | 1.000 | lora_l4d: -0.033 [-0.049, -0.018]; qwen_readout_l4d: -0.233 [-0.264, -0.205] |

## Contract §6 criteria (reference DeepSeek L1, same units)

| layer | method | near-LLM: mF1 ≥ ref−0.02 | equivalent: CI low of Δ ≥ −0.02 |
|---|---|---|---|
| layer1 | lora_l4d | 0.959 vs 0.975 → FAIL | -0.042 → FAIL |
| layer1 | qwen_readout_l4d | 0.868 vs 0.975 → FAIL | -0.152 → FAIL |
| layer3 | lora_l4d | 0.831 vs 0.861 → FAIL | -0.085 → FAIL |
| layer3 | qwen_readout_l4d | 0.742 vs 0.861 → FAIL | -0.169 → FAIL |
| placebo | lora_l4d | 0.958 vs 0.975 → FAIL | -0.051 → FAIL |
| placebo | qwen_readout_l4d | 0.858 vs 0.975 → FAIL | -0.163 → FAIL |
| original | lora_l4d | 0.928 vs 0.941 → FAIL | -0.049 → FAIL |
| original | qwen_readout_l4d | 0.728 vs 0.941 → FAIL | -0.264 → FAIL |

## Gain over the structure-only baseline (all eval units)

| layer | lora_l4d − const | qwen_readout_l4d − const |
|---|---|---|
| layer1 | +0.167 | +0.076 |
| layer3 | +0.493 | +0.419 |
| placebo | +0.171 | +0.079 |
| original | -0.004 | -0.198 |

## Per-fold macro-F1 (all eval units of each fold; lora_l4d = that fold's own model)

| layer | method | fold 0 | fold 1 | fold 2 |
|---|---|---|---|---|
| layer1 | lora_l4d | 0.960 (n=944) | 0.931 (n=848) | 0.985 (n=864) |
| layer1 | qwen_readout_l4d | 0.850 (n=944) | 0.878 (n=848) | 0.876 (n=864) |
| layer3 | lora_l4d | 0.816 (n=944) | 0.793 (n=848) | 0.865 (n=864) |
| layer3 | qwen_readout_l4d | 0.769 (n=944) | 0.729 (n=848) | 0.754 (n=864) |
| placebo | lora_l4d | 0.963 (n=944) | 0.931 (n=848) | 0.993 (n=864) |
| placebo | qwen_readout_l4d | 0.856 (n=944) | 0.876 (n=848) | 0.884 (n=864) |
| original | lora_l4d | 0.925 (n=944) | 0.905 (n=848) | 0.961 (n=864) |
| original | qwen_readout_l4d | 0.703 (n=944) | 0.743 (n=848) | 0.765 (n=864) |

## By flow category (all eval units)

| layer | method | flow_category | n | macro-F1 | accuracy |
|---|---|---|---|---|---|
| layer1 | lora_l4d | 01 | 84 | 0.964 | 0.964 |
| layer1 | lora_l4d | 02-22 | 1176 | 0.938 | 0.938 |
| layer1 | lora_l4d | 31-45 | 420 | 1.000 | 1.000 |
| layer1 | lora_l4d | 51-68 | 624 | 0.978 | 0.978 |
| layer1 | lora_l4d | 71-84 | 352 | 0.946 | 0.946 |
| layer1 | qwen_readout_l4d | 01 | 84 | 0.843 | 0.845 |
| layer1 | qwen_readout_l4d | 02-22 | 1176 | 0.814 | 0.815 |
| layer1 | qwen_readout_l4d | 31-45 | 420 | 0.926 | 0.926 |
| layer1 | qwen_readout_l4d | 51-68 | 624 | 0.936 | 0.936 |
| layer1 | qwen_readout_l4d | 71-84 | 352 | 0.860 | 0.861 |
| layer3 | lora_l4d | 01 | 84 | 0.869 | 0.869 |
| layer3 | lora_l4d | 02-22 | 1176 | 0.823 | 0.823 |
| layer3 | lora_l4d | 31-45 | 420 | 0.843 | 0.843 |
| layer3 | lora_l4d | 51-68 | 624 | 0.848 | 0.848 |
| layer3 | lora_l4d | 71-84 | 352 | 0.770 | 0.770 |
| layer3 | qwen_readout_l4d | 01 | 84 | 0.869 | 0.869 |
| layer3 | qwen_readout_l4d | 02-22 | 1176 | 0.724 | 0.724 |
| layer3 | qwen_readout_l4d | 31-45 | 420 | 0.793 | 0.795 |
| layer3 | qwen_readout_l4d | 51-68 | 624 | 0.762 | 0.768 |
| layer3 | qwen_readout_l4d | 71-84 | 352 | 0.752 | 0.761 |

## Question level, eval questions, all fold models pooled (threshold p_yes ≥ 0.5; gold null excluded)

| layer | method | qtype | n | n_yes | accuracy | AUROC |
|---|---|---|---|---|---|---|
| layer1 | lora_l4d | all | 27102 | 22349 | 0.954 | 0.961 |
| layer1 | lora_l4d | exec_all | 11335 | 9180 | 0.934 | 0.936 |
| layer1 | lora_l4d | exec_any | 11335 | 9704 | 0.971 | 0.989 |
| layer1 | lora_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| layer1 | lora_l4d | realloc_safe | 523 | 439 | 0.945 | 0.993 |
| layer1 | lora_l4d | rel | 1642 | 1181 | 0.916 | 0.943 |
| layer1 | lora_l4d | exec_any/null_check_target | 1243 | 0 | 1.000 | – |
| layer1 | lora_l4d | exec_any/other | 10092 | 9704 | 0.968 | 0.969 |
| layer1 | lora_l4d | rel/cross_function | 431 | 344 | 0.882 | 0.889 |
| layer1 | lora_l4d | rel/same_function | 1211 | 837 | 0.928 | 0.956 |
| layer1 | qwen_readout_l4d | all | 27102 | 22349 | 0.442 | 0.697 |
| layer1 | qwen_readout_l4d | exec_all | 11335 | 9180 | 0.338 | 0.704 |
| layer1 | qwen_readout_l4d | exec_any | 11335 | 9704 | 0.432 | 0.551 |
| layer1 | qwen_readout_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| layer1 | qwen_readout_l4d | realloc_safe | 523 | 439 | 0.191 | 0.798 |
| layer1 | qwen_readout_l4d | rel | 1642 | 1181 | 0.543 | 0.675 |
| layer1 | qwen_readout_l4d | exec_any/null_check_target | 1243 | 0 | 0.694 | – |
| layer1 | qwen_readout_l4d | exec_any/other | 10092 | 9704 | 0.400 | 0.776 |
| layer1 | qwen_readout_l4d | rel/cross_function | 431 | 344 | 0.780 | 0.983 |
| layer1 | qwen_readout_l4d | rel/same_function | 1211 | 837 | 0.459 | 0.589 |
| layer3 | lora_l4d | all | 33838 | 22349 | 0.923 | 0.960 |
| layer3 | lora_l4d | exec_all | 14703 | 9180 | 0.906 | 0.946 |
| layer3 | lora_l4d | exec_any | 14703 | 9704 | 0.930 | 0.973 |
| layer3 | lora_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| layer3 | lora_l4d | realloc_safe | 523 | 439 | 0.895 | 0.976 |
| layer3 | lora_l4d | rel | 1642 | 1181 | 0.909 | 0.935 |
| layer3 | lora_l4d | exec_any/null_check_target | 1243 | 0 | 1.000 | – |
| layer3 | lora_l4d | exec_any/other | 13460 | 9704 | 0.923 | 0.967 |
| layer3 | lora_l4d | rel/cross_function | 431 | 344 | 0.865 | 0.869 |
| layer3 | lora_l4d | rel/same_function | 1211 | 837 | 0.924 | 0.951 |
| layer3 | qwen_readout_l4d | all | 33838 | 22349 | 0.567 | 0.820 |
| layer3 | qwen_readout_l4d | exec_all | 14703 | 9180 | 0.484 | 0.840 |
| layer3 | qwen_readout_l4d | exec_any | 14703 | 9704 | 0.603 | 0.804 |
| layer3 | qwen_readout_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| layer3 | qwen_readout_l4d | realloc_safe | 523 | 439 | 0.184 | 0.861 |
| layer3 | qwen_readout_l4d | rel | 1642 | 1181 | 0.500 | 0.776 |
| layer3 | qwen_readout_l4d | exec_any/null_check_target | 1243 | 0 | 0.831 | – |
| layer3 | qwen_readout_l4d | exec_any/other | 13460 | 9704 | 0.582 | 0.847 |
| layer3 | qwen_readout_l4d | rel/cross_function | 431 | 344 | 0.664 | 0.979 |
| layer3 | qwen_readout_l4d | rel/same_function | 1211 | 837 | 0.442 | 0.700 |
| placebo | lora_l4d | all | 33838 | 22349 | 0.941 | 0.967 |
| placebo | lora_l4d | exec_all | 14703 | 9180 | 0.926 | 0.954 |
| placebo | lora_l4d | exec_any | 14703 | 9704 | 0.950 | 0.980 |
| placebo | lora_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| placebo | lora_l4d | realloc_safe | 523 | 439 | 0.935 | 0.975 |
| placebo | lora_l4d | rel | 1642 | 1181 | 0.914 | 0.941 |
| placebo | lora_l4d | exec_any/null_check_target | 1243 | 0 | 1.000 | – |
| placebo | lora_l4d | exec_any/other | 13460 | 9704 | 0.945 | 0.976 |
| placebo | lora_l4d | rel/cross_function | 431 | 344 | 0.879 | 0.857 |
| placebo | lora_l4d | rel/same_function | 1211 | 837 | 0.926 | 0.962 |
| placebo | qwen_readout_l4d | all | 33838 | 22349 | 0.563 | 0.812 |
| placebo | qwen_readout_l4d | exec_all | 14703 | 9180 | 0.463 | 0.860 |
| placebo | qwen_readout_l4d | exec_any | 14703 | 9704 | 0.610 | 0.788 |
| placebo | qwen_readout_l4d | heap | 2267 | 1845 | 1.000 | 1.000 |
| placebo | qwen_readout_l4d | realloc_safe | 523 | 439 | 0.176 | 0.960 |
| placebo | qwen_readout_l4d | rel | 1642 | 1181 | 0.557 | 0.687 |
| placebo | qwen_readout_l4d | exec_any/null_check_target | 1243 | 0 | 0.832 | – |
| placebo | qwen_readout_l4d | exec_any/other | 13460 | 9704 | 0.590 | 0.825 |
| placebo | qwen_readout_l4d | rel/cross_function | 431 | 344 | 0.821 | 0.974 |
| placebo | qwen_readout_l4d | rel/same_function | 1211 | 837 | 0.462 | 0.592 |
| original | lora_l4d | all | 58415 | 45966 | 0.913 | 0.939 |
| original | lora_l4d | exec_all | 23409 | 19621 | 0.906 | 0.922 |
| original | lora_l4d | exec_any | 23409 | 20319 | 0.937 | 0.977 |
| original | lora_l4d | heap | 3874 | 2834 | 0.999 | 1.000 |
| original | lora_l4d | realloc_safe | 798 | 714 | 0.964 | 0.992 |
| original | lora_l4d | rel | 6925 | 2478 | 0.804 | 0.935 |
| original | lora_l4d | exec_any/null_check_target | 1902 | 0 | 1.000 | – |
| original | lora_l4d | exec_any/other | 21507 | 20319 | 0.931 | 0.966 |
| original | lora_l4d | rel/cross_function | 4701 | 734 | 0.732 | 0.897 |
| original | lora_l4d | rel/same_function | 2224 | 1744 | 0.957 | 0.957 |
| original | qwen_readout_l4d | all | 58415 | 45966 | 0.377 | 0.755 |
| original | qwen_readout_l4d | exec_all | 23409 | 19621 | 0.235 | 0.644 |
| original | qwen_readout_l4d | exec_any | 23409 | 20319 | 0.321 | 0.552 |
| original | qwen_readout_l4d | heap | 3874 | 2834 | 0.999 | 1.000 |
| original | qwen_readout_l4d | realloc_safe | 798 | 714 | 0.201 | 0.749 |
| original | qwen_readout_l4d | rel | 6925 | 2478 | 0.717 | 0.857 |
| original | qwen_readout_l4d | exec_any/null_check_target | 1902 | 0 | 0.764 | – |
| original | qwen_readout_l4d | exec_any/other | 21507 | 20319 | 0.281 | 0.673 |
| original | qwen_readout_l4d | rel/cross_function | 4701 | 734 | 0.881 | 0.939 |
| original | qwen_readout_l4d | rel/same_function | 2224 | 1744 | 0.371 | 0.555 |

## Question level per fold model (l4d/score_facts.py rows, eval questions, p_yes ≥ 0.5)

| layer | model | qtype | n | n_yes | accuracy | AUROC | majority |
|---|---|---|---|---|---|---|---|
| layer1 | qwen3.5-4b-lora-l4d-fold0 | all | 8958 | 7533 | 0.965 | 0.996 | 0.841 |
| layer1 | qwen3.5-4b-lora-l4d-fold0 | exec_all | 3792 | 3199 | 0.933 | 0.994 | 0.844 |
| layer1 | qwen3.5-4b-lora-l4d-fold0 | exec_any | 3792 | 3199 | 0.994 | 0.997 | 0.844 |
| layer1 | qwen3.5-4b-lora-l4d-fold0 | heap | 761 | 615 | 1.000 | 1.000 | 0.808 |
| layer1 | qwen3.5-4b-lora-l4d-fold0 | realloc_safe | 195 | 165 | 0.882 | 1.000 | 0.846 |
| layer1 | qwen3.5-4b-lora-l4d-fold0 | rel | 418 | 355 | 0.971 | 1.000 | 0.849 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | all | 9873 | 7744 | 0.908 | 0.940 | 0.784 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | exec_all | 4098 | 2992 | 0.882 | 0.943 | 0.730 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | exec_any | 4098 | 3516 | 0.929 | 0.988 | 0.858 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | heap | 765 | 615 | 1.000 | 1.000 | 0.804 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | realloc_safe | 180 | 150 | 0.967 | 1.000 | 0.833 |
| layer1 | qwen3.5-4b-lora-l4d-fold1 | rel | 732 | 471 | 0.828 | 0.941 | 0.643 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | all | 8271 | 7072 | 0.997 | 1.000 | 0.855 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | exec_all | 3445 | 2989 | 0.996 | 1.000 | 0.868 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | exec_any | 3445 | 2989 | 0.996 | 1.000 | 0.868 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | heap | 741 | 615 | 1.000 | 1.000 | 0.830 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | realloc_safe | 148 | 124 | 1.000 | 1.000 | 0.838 |
| layer1 | qwen3.5-4b-lora-l4d-fold2 | rel | 492 | 355 | 1.000 | 1.000 | 0.722 |
| layer1 | qwen3.5-4b-readout | all | 27102 | 22349 | 0.442 | 0.697 | 0.825 |
| layer1 | qwen3.5-4b-readout | exec_all | 11335 | 9180 | 0.338 | 0.704 | 0.810 |
| layer1 | qwen3.5-4b-readout | exec_any | 11335 | 9704 | 0.432 | 0.551 | 0.856 |
| layer1 | qwen3.5-4b-readout | heap | 2267 | 1845 | 1.000 | 1.000 | 0.814 |
| layer1 | qwen3.5-4b-readout | realloc_safe | 523 | 439 | 0.191 | 0.798 | 0.839 |
| layer1 | qwen3.5-4b-readout | rel | 1642 | 1181 | 0.543 | 0.675 | 0.719 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | all | 11390 | 7533 | 0.929 | 0.983 | 0.661 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | exec_all | 5008 | 3199 | 0.905 | 0.971 | 0.639 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | exec_any | 5008 | 3199 | 0.942 | 0.990 | 0.639 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | heap | 761 | 615 | 1.000 | 1.000 | 0.808 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | realloc_safe | 195 | 165 | 0.846 | 1.000 | 0.846 |
| layer3 | qwen3.5-4b-lora-l4d-fold0 | rel | 418 | 355 | 0.967 | 1.000 | 0.849 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | all | 12063 | 7744 | 0.876 | 0.943 | 0.642 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | exec_all | 5193 | 2992 | 0.854 | 0.944 | 0.576 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | exec_any | 5193 | 3516 | 0.885 | 0.968 | 0.677 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | heap | 765 | 615 | 1.000 | 1.000 | 0.804 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | realloc_safe | 180 | 150 | 0.994 | 1.000 | 0.833 |
| layer3 | qwen3.5-4b-lora-l4d-fold1 | rel | 732 | 471 | 0.814 | 0.942 | 0.643 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | all | 10385 | 7072 | 0.970 | 0.991 | 0.681 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | exec_all | 4502 | 2989 | 0.967 | 0.990 | 0.664 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | exec_any | 4502 | 2989 | 0.968 | 0.989 | 0.664 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | heap | 741 | 615 | 1.000 | 1.000 | 0.830 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | realloc_safe | 148 | 124 | 0.838 | 0.971 | 0.838 |
| layer3 | qwen3.5-4b-lora-l4d-fold2 | rel | 492 | 355 | 1.000 | 1.000 | 0.722 |
| layer3 | qwen3.5-4b-readout | all | 33838 | 22349 | 0.567 | 0.820 | 0.660 |
| layer3 | qwen3.5-4b-readout | exec_all | 14703 | 9180 | 0.484 | 0.840 | 0.624 |
| layer3 | qwen3.5-4b-readout | exec_any | 14703 | 9704 | 0.603 | 0.804 | 0.660 |
| layer3 | qwen3.5-4b-readout | heap | 2267 | 1845 | 1.000 | 1.000 | 0.814 |
| layer3 | qwen3.5-4b-readout | realloc_safe | 523 | 439 | 0.184 | 0.861 | 0.839 |
| layer3 | qwen3.5-4b-readout | rel | 1642 | 1181 | 0.500 | 0.776 | 0.719 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | all | 11390 | 7533 | 0.954 | 0.991 | 0.661 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | exec_all | 5008 | 3199 | 0.931 | 0.980 | 0.639 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | exec_any | 5008 | 3199 | 0.972 | 0.999 | 0.639 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | heap | 761 | 615 | 1.000 | 1.000 | 0.808 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | realloc_safe | 195 | 165 | 0.862 | 1.000 | 0.846 |
| placebo | qwen3.5-4b-lora-l4d-fold0 | rel | 418 | 355 | 0.971 | 1.000 | 0.849 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | all | 12063 | 7744 | 0.884 | 0.944 | 0.642 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | exec_all | 5193 | 2992 | 0.866 | 0.945 | 0.576 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | exec_any | 5193 | 3516 | 0.890 | 0.970 | 0.677 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | heap | 765 | 615 | 1.000 | 1.000 | 0.804 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | realloc_safe | 180 | 150 | 0.961 | 0.992 | 0.833 |
| placebo | qwen3.5-4b-lora-l4d-fold1 | rel | 732 | 471 | 0.822 | 0.939 | 0.643 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | all | 10385 | 7072 | 0.993 | 1.000 | 0.681 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | exec_all | 4502 | 2989 | 0.990 | 1.000 | 0.664 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | exec_any | 4502 | 2989 | 0.993 | 1.000 | 0.664 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | heap | 741 | 615 | 1.000 | 1.000 | 0.830 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | realloc_safe | 148 | 124 | 1.000 | 1.000 | 0.838 |
| placebo | qwen3.5-4b-lora-l4d-fold2 | rel | 492 | 355 | 1.000 | 1.000 | 0.722 |
| placebo | qwen3.5-4b-readout | all | 33838 | 22349 | 0.563 | 0.812 | 0.660 |
| placebo | qwen3.5-4b-readout | exec_all | 14703 | 9180 | 0.463 | 0.860 | 0.624 |
| placebo | qwen3.5-4b-readout | exec_any | 14703 | 9704 | 0.610 | 0.788 | 0.660 |
| placebo | qwen3.5-4b-readout | heap | 2267 | 1845 | 1.000 | 1.000 | 0.814 |
| placebo | qwen3.5-4b-readout | realloc_safe | 523 | 439 | 0.176 | 0.960 | 0.839 |
| placebo | qwen3.5-4b-readout | rel | 1642 | 1181 | 0.557 | 0.687 | 0.719 |
| original | qwen3.5-4b-lora-l4d-fold0 | all | 19763 | 15814 | 0.946 | 0.989 | 0.800 |
| original | qwen3.5-4b-lora-l4d-fold0 | exec_all | 7979 | 6913 | 0.911 | 0.989 | 0.866 |
| original | qwen3.5-4b-lora-l4d-fold0 | exec_any | 7979 | 6913 | 0.987 | 0.999 | 0.866 |
| original | qwen3.5-4b-lora-l4d-fold0 | heap | 1322 | 942 | 1.000 | 1.000 | 0.713 |
| original | qwen3.5-4b-lora-l4d-fold0 | realloc_safe | 294 | 264 | 0.922 | 1.000 | 0.898 |
| original | qwen3.5-4b-lora-l4d-fold0 | rel | 2189 | 782 | 0.898 | 0.971 | 0.643 |
| original | qwen3.5-4b-lora-l4d-fold1 | all | 19586 | 14888 | 0.812 | 0.878 | 0.760 |
| original | qwen3.5-4b-lora-l4d-fold1 | exec_all | 7890 | 6092 | 0.815 | 0.871 | 0.772 |
| original | qwen3.5-4b-lora-l4d-fold1 | exec_any | 7890 | 6790 | 0.830 | 0.982 | 0.861 |
| original | qwen3.5-4b-lora-l4d-fold1 | heap | 1246 | 906 | 0.997 | 1.000 | 0.727 |
| original | qwen3.5-4b-lora-l4d-fold1 | realloc_safe | 258 | 228 | 0.977 | 1.000 | 0.884 |
| original | qwen3.5-4b-lora-l4d-fold1 | rel | 2302 | 872 | 0.618 | 0.865 | 0.621 |
| original | qwen3.5-4b-lora-l4d-fold2 | all | 19066 | 15264 | 0.983 | 0.997 | 0.801 |
| original | qwen3.5-4b-lora-l4d-fold2 | exec_all | 7540 | 6616 | 0.995 | 1.000 | 0.877 |
| original | qwen3.5-4b-lora-l4d-fold2 | exec_any | 7540 | 6616 | 0.995 | 1.000 | 0.877 |
| original | qwen3.5-4b-lora-l4d-fold2 | heap | 1306 | 986 | 1.000 | 1.000 | 0.755 |
| original | qwen3.5-4b-lora-l4d-fold2 | realloc_safe | 246 | 222 | 1.000 | 1.000 | 0.902 |
| original | qwen3.5-4b-lora-l4d-fold2 | rel | 2434 | 824 | 0.896 | 0.997 | 0.661 |
| original | qwen3.5-4b-readout | all | 58415 | 45966 | 0.377 | 0.755 | 0.787 |
| original | qwen3.5-4b-readout | exec_all | 23409 | 19621 | 0.235 | 0.644 | 0.838 |
| original | qwen3.5-4b-readout | exec_any | 23409 | 20319 | 0.321 | 0.552 | 0.868 |
| original | qwen3.5-4b-readout | heap | 3874 | 2834 | 0.999 | 1.000 | 0.732 |
| original | qwen3.5-4b-readout | realloc_safe | 798 | 714 | 0.201 | 0.749 | 0.895 |
| original | qwen3.5-4b-readout | rel | 6925 | 2478 | 0.717 | 0.857 | 0.642 |

# Appendix B: files (sha256)

```
e0c9400361940399e97fc495ad509311ca857c3eedc4eb39b22fef1bf6503f39  aggregate.py
0d841dafc4af88fc8a82e7ad8d311f5d03effec52b95fa6656cd0d5d85d2fee7  latency.py
79a12d540ff5e417017f5b5f5fd637e5566c2ea10bcb8e5521358ec6e6a22c6b  prune.py
47dabbac651d4ff3ddf75a5643cfda3e26dc945dbcb80bb52599b63d0e9a0761  render.py
eec24f3fce693d1f94858d0e66c1d68c0c3430d046fcaf8218edebb60bdee53b  report_tables.py
e18e811cb240ad4cc084d0f6f785dda93fb8f67b8360c82d999f0f089b6ee91a  select_fold.py
e3fefbf95e6feafad4b4e449622eae4033c4299fbfa96f84d6e86c0cf02b7572  collect.sh
7892f1244c47c42366e13f9d56f8ba794783c675ebf9893d3d5926eb7483ec6e  upload.sh
29531d16255c223c10e88f653256702c867635e496bd4632715eee59fe737c8e  server/dft_core.py
b146d3ff6050d6629c28e95722e883fb45843c07d7b42293552952457deba18f  server/l4dft.py
37c59ac9604f5c0b7c5ab87a7718f556d170950b51fd5b8ff7353a45e15b0343  server/l4d_prompt.py
89f2220da76a9fea81bb05af088110770353531c6ebb044e65e60ed0fb974fb2  server/after.sh
48b003f0b8f15a6980af2aecaf2e402b82dfedc259f9b742f8db9236610d71e6  server/chain_train.sh
2386dd98450414fb2d0621d5ce40772b8dc9a05ef00d0ed538c23e2e927ca81d  server/env.sh
d4453854f6ae06e539dea7bec70b59b2901d7fa09baec7ff151dfee562933026  server/job.sh
bbf83c559dc493daecd6328db070c946212d053e822060ea144ada9e4f8cfb9e  server/queue.sh
0aaa8c718632b8714260a5d1b9579814b1349b30af0059d1d8a411e553280bc4  server/serve_l4d.sh
3fe652804f602b9b7fcd73116e55f5123278f6d17f1922a0eff266002ee727f4  kernel/compare_l4d.py
9ec275db48594420de837a30b97ab408fbbf273a52b9aaa43e9ab93f180da294  kernel/dft_lat300.py
2091898555f7f5644a1fd784a53105a6075b42e2dbeeef61a5924bd40850727f  kernel/intern_lat300.py
db2e3c97a336ec2ab9deca6cf5b4cfe79f0a9d86396ca2ba4155b40265f6c2f8  kernel/gpu0_chain.sh
7bab26d0fe1d70510df45c850be792dc46282dea505108c0b17ec6bff4a37b5e  kernel/lat_all.sh
8019da174a526de2632da72fbf0e552c2ec86c81bc04f1ac3a1184e5bf8edd1b  FROZEN
c77c133c774a2410e8167afe4451a6b79656e047fb4a0073af5218b08fddfbbd  .gitignore
7c54c8bb62675a153b5e86c193b3da3a35f122de7fdc80603cbe500513b192a7  PROGRESS.md
```

Result files: `results/<lora_l4d|lora_l4d_opt|qwen_readout_l4d>/<layer>/eval_r1.jsonl` (question level; not for opt), `eval_r1_units.jsonl` + `.meta.json` (unit level), `results/scores/*.json` (machine-readable scores, criteria, facts, prune test, kernel equivalence), latency `results/lora_l4d*/<layer>/lat300_c1_<fallback|kernel>.jsonl` + meta. Checkpoints: `184-toast:~/disk4/cs224/l4d_ft/runs/fold<k>/ckpt/step219` (local copy `build/runs/fold<k>/ckpt/step219`).
