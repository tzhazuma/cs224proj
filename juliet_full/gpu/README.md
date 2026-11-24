# juliet_full/gpu — 184-toast services and LineVul (gpu lane)

Scripts in this directory are the source of truth; they are copied to `184-toast:~/disk4/cs224/gpu/`
(`rsync -a server linevul_infer.py 184-toast:~/disk4/cs224/gpu/`). Measured 2026-11-23 (UTC 18:2x).

## 1. Layout

| Path | What |
|---|---|
| `server/env.sh` | sourced by every server script: all caches/temp (`HF_HOME`, `XDG_CACHE_HOME`, `TRITON_CACHE_DIR`, `TORCHINDUCTOR_CACHE_DIR`, `VLLM_CACHE_ROOT`, `TMPDIR`, ...) under `~/disk4/cs224/`; `CPATH` for Python headers (see caveats) |
| `server/svc.sh` | `svc.sh qwen\|decide start\|stop\|health\|status` (nohup + setsid, pid `~/disk4/cs224/run/<name>.pid`, log `~/disk4/cs224/logs/<name>.log`) |
| `server/decide_server.py` | Intern-Decision-4B forward-only read-out (FastAPI/uvicorn) |
| `linevul_infer.py` | LineVul zero-shot inference, methods `linevul_cpu` / `linevul_gpu` |
| `run_linevul.sh` | `run_linevul.sh <units.jsonl> <run_id> [set] [layer]`: CPU run on dell, then GPU run on 184-toast GPU 1, results synced back |
| `run_decide.py` | Intern-Decision zero-shot runs (`run` / `freeze` / `score`) against `/decide` with the frozen Jev prompts of the LLM lane; outputs `results/intern_decision/<layer>/<run_id>.jsonl` + `.meta.json`, thresholds in `results/intern_decision/FROZEN` |
| `run_decide_stage2.sh` | resumable stage-2 sequence: layer1 dev L1–L3 → freeze → layer1 eval → layer3 eval → placebo L1/L3 → original L1 → determinism rerun (50 units) |
| `bench/quiet_run.sh` | `quiet_run.sh <label> <cmd...>`: latency runs under `flock /tmp/cs224_latency.lock` after dell load1 < 2.5 (20-min cap, else labelled LOADED); log `results/bench/quiet_runs.log` |
| `bench/bench_qwen.py`, `bench/bench_decide.py` | probes + latency/throughput from dell (stdlib only, keep-alive HTTP) |
| `bench/l1_probe_prompt.txt` | L1-style probe prompt (copy of the 2026-11-23 DeepSeek probe prompt; not the frozen L1 prompt) |
| `results/bench/*.json` | raw benchmark reports; `results/linevul_{cpu,gpu}/layer1/*.jsonl` predictions (contract §4) |
| `score_stage2.py` | scores every stage-2 eval run with `analysis/score.py` (primary 0.5 and frozen secondary threshold) and `analysis/robustness.py`, checks determinism; writes `results/STAGE2_SCORES.md`, `results/stage2_scores.json`, `results/scores/`, `results/robustness/`, and the secondary-threshold copies `results/intern_decision_th2/<layer>/<run_id>.jsonl` (method `intern_decision_th2`, pred := `extra.pred_secondary`) |
| `.venv/` | dell CPU venv for LineVul (git-ignored): torch 2.14.0+cpu, transformers 5.22.2 |

## 2. Start / stop

**Current state (started 2026-11-23 13:39 PST, still RUNNING and healthy at 16:25 PST after the stage-2 runs): both
services on GPU 1**; GPU 0 belongs to the
fine-tuning lane (decision_ft, :8003) and must not be used. Started after the FT lane touched
`184-toast:~/disk4/cs224/GPU1_FREE_FOR_SERVICES` (13:37) and nvidia-smi listed no compute process on GPU 1
(uuid GPU-3b11ffc9-...; 15 MiB used). `svc.sh` defaults are now GPU 1 for both (`QWEN_GPU=1`, `DECIDE_GPU=1`)
and `QWEN_GPU_UTIL=0.45`. Start qwen first: vLLM checks at start-up that util × 24 GiB is still free.

```bash
ssh 184-toast 'nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory --format=csv'  # nothing on GPU 1
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh qwen start'    # GPU 1, healthy after ~40 s (compile cache warm)
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh decide start'  # GPU 1, healthy after ~15 s
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh qwen health; bash ~/disk4/cs224/gpu/server/svc.sh decide health'
# from dell:
curl -s --noproxy '*' http://10.15.89.184:8001/v1/models   # lists qwen3.5-4b
curl -s --noproxy '*' http://10.15.89.184:8002/health      # {"status":"ok","model":"Intern-Decision-4B",...}
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh decide stop; bash ~/disk4/cs224/gpu/server/svc.sh qwen stop'
```
`health` prints `<name> healthy (...)` and exits 0 when the endpoint answers; `status` shows pid or `not running`.
Stage-1 layout (qwen on GPU 0 with util 0.55, decide on GPU 1) is `QWEN_GPU=0 QWEN_GPU_UTIL=0.55 svc.sh qwen start`;
all §4 Qwen numbers were measured in that layout. Serving a fine-tuned adapter needs new vLLM flags
(`--enable-lora --lora-modules ...`), not covered here.

## 3. Endpoints (both bound to 0.0.0.0, reachable from dell without a tunnel)

**Qwen3.5-4B** — `http://10.15.89.184:8001/v1` (OpenAI API), served name `qwen3.5-4b`, GPU 1 (stage 1: GPU 0).
`vllm serve ~/disk4/cs224/models/Qwen3.5-4B --language-model-only --max-model-len 8192 --enable-prefix-caching
--dtype bfloat16 --gpu-memory-utilization 0.45 (stage 1: 0.55) --max-num-seqs 64 --generation-config vllm
--default-chat-template-kwargs '{"enable_thinking": false}'`. Vision encoder is not loaded (`--language-model-only`).
Thinking is off by server default; clients should still send `"chat_template_kwargs": {"enable_thinking": false}`
and `temperature: 0`. Probe on 6 layer1 dev units: 6/6 valid JSON, no `<think>` text, no reasoning field.

**Intern-Decision-4B** — `http://10.15.89.184:8002`, GPU 1.
```
POST /decide {"state": <str|obj>, "question": <str>, "options": [<str>, ...] | {<value>: <description>, ...}}
  -> {"probs": {<value>: p, ...}, "probs_raw": {...}, "decision": <value>, "input_tokens": n,
      "forward_ms": f, "latency_ms_server": t, "model": "Intern-Decision-4B", "temperature": 1.99241824}
GET  /health
```
Uses the checkpoint's own `inference.py` (model card): JSON skeleton with one `<decision>` placeholder (field name
`answer`, type `choice`, options mapped to symbols A, B, ... in the given order), one HF forward
(`Qwen3_5ForConditionalGeneration`, bf16, sdpa, no `generate()`), logits at the position before the placeholder,
softmax over the option symbols only (`probs_raw`), then `probs = softmax(log(p)/T)`, T = 1.99241824.
Inputs above 8192 tokens are rejected (HTTP 400), never truncated. Requests are serialised (one GPU forward at a time).
`latency_ms_server` = handler time (validation + tokenisation + forward + read-out); `forward_ms` = GPU forward only.

## 4. Measured latency / throughput (from dell, layer1 dev units, keep-alive connections)

Raw: `results/bench/qwen_20261123T183002Z.json`, `results/bench/decide_20261123T182852Z.json` (dell load average
~18 from other lanes) and repeat runs `qwen_20261123T184616Z.json`, `decide_20261123T184508Z.json` (dell load ~4);
the two agree within 5 %, so client-side load on dell does not distort these numbers. Table = first run; repeat:
Qwen c1 0.659 / 0.750 s, c16 8.4 req/s (median 1.78 s), c32 9.3 req/s (median 3.30 s); decide c1 82.6 / 85.2 ms.
LAN: ping RTT 0.08 ms; keep-alive HTTP GET /health 1.2 ms; client-minus-server time for /decide 2.7 ms (median).

| Qwen3.5-4B, probe prompt (~530 prompt tok, ~47 output tok incl. a 30-word reason), max_tokens 128 | value |
|---|---|
| concurrency 1, 30 requests: median / p90 | **0.665 s / 0.749 s** |
| server (vLLM /metrics, mean): TTFT / prefill / decode / inter-token | 98 ms / 91 ms / 595 ms / 12.4 ms |
| concurrency 16, 128 requests | 8.1 req/s (29.3k units/h), latency median 1.89 s, p90 2.40 s; 4.3k prompt tok/s, 371 gen tok/s |
| concurrency 32, 256 requests | 9.0 req/s (32.3k units/h), latency median 3.43 s, p90 4.60 s; 4.7k prompt tok/s, 408 gen tok/s |

Decoding dominates single-request latency (~12.4 ms/token): an output of only `{"label","confidence"}` (~17 tokens)
should give roughly 0.3 s at concurrency 1.

| Intern-Decision-4B, /decide (median 418 input tokens) | value |
|---|---|
| concurrency 1, 30 requests: client median / p90 | **82.7 ms / 85.3 ms** |
| server `latency_ms_server` median / p90; `forward_ms` median | 80.0 / 82.5 ms; 78.4 ms |
| concurrency 4 (server serialises), 32 requests | 11.8 req/s, latency median 0.33 s |

| LineVul zero-shot, batch 1 | latency median / p90 per unit |
|---|---|
| `linevul_gpu` (184-toast GPU 1, fp32; host-local time, no LAN) | 5.9 ms / 7.0 ms (eval) |
| `linevul_cpu` (dell, 6 torch threads; `deveval_v1`, dell load average 10–22, LOADED) | 0.161 s / 0.388 s (eval), 0.147 / 0.388 s (dev) |
| `linevul_cpu` quiet, latency300 (300 eval units, `bench/quiet_run.sh`, load1 1.66 before) | **88.4 ms / 124.1 ms** (`results/linevul_cpu/layer1/lat300_cpu_quiet.jsonl`) |

### 4.1 Stage 2: concurrency-1 latency on the latency300 sample (300 layer1 eval units), services on GPU 1

Measured 2026-11-24 00:21–00:24 UTC from dell under `bench/quiet_run.sh` (lock `/tmp/cs224_latency.lock`,
dell load1 1.68–1.85 before each run, labelled quiet in `results/bench/quiet_runs.log`), after all bulk runs of
every lane had finished: GPU 1 utilisation 0 %, vLLM 0 running / 0 waiting requests before and after
(`/tmp/jfull_gpu/lat300.sh` log). Real frozen prompts, not the stage-1 probe prompt.

| Run | Prompt | client median / p90 | server side |
|---|---|---|---|
| Intern-Decision `/decide`, `results/intern_decision/layer1/lat300_L1_c1.jsonl` | Jev L1 state (median 703 input tokens) | **132 ms / 149 ms** | `latency_ms_server` 129.6 / 146.3 ms, forward 127.4 ms, client − server 3.1 ms |
| Qwen3.5-4B via `llm/run_llm.py --model qwen`, `results/bench/lat300/qwen3_5_4b/layer1/lat300_c1_L1_gpuidle.jsonl` | frozen chat L1 (535 prompt / 17.3 completion tokens per call, max_tokens 64) | **333 ms / 357 ms** | – |

The LLM lane's own `llm/results/qwen3_5_4b/layer1/lat300_c1_L1.jsonl` (00:08–00:11 UTC, dell quiet) reports
635 / 687 ms for the identical requests (same 300 predictions): during that window this lane's
`orig_eval_L1_r1` decide bulk run (00:08:34–00:17:10 UTC, concurrency 2) was using the same GPU 1, so that number
is GPU-contended. Use the 333 ms run for the Qwen c1 latency.

## 5. GPU memory

Stage 2 (now, both services on GPU 1; nvidia-smi 2026-11-23 13:39 PST): GPU 1 **19.5 GiB of 24 used**
(vLLM 10.4 GiB: weights 7.94 GiB + KV/mamba cache 2.39 GiB = 31,597 tokens, 3.86 × 8192; decide_server 9.1 GiB);
LineVul GPU runs add < 1 GiB. After the stage-2 runs (16:21 PST) GPU 1 shows 20.6 GiB (vLLM 10.8 GiB,
decide_server 9.8 GiB: PyTorch caching allocator kept the peak of the longest inputs). GPU 0 is used only by the FT lane.

Stage 1 (qwen GPU 0 util 0.55, decide GPU 1):

| GPU | Process | Used | Breakdown |
|---|---|---|---|
| 0 | vLLM Qwen3.5-4B | 13.3 GiB of 24 | weights 7.94 GiB (text only), KV/mamba cache 3.78 GiB = 83,870 tokens (10.2 × 8192), CUDA graphs 0.29 GiB |
| 1 | decide_server | 9.4 GiB of 24 | bf16 weights incl. vision tower (~8.6 GiB) + activations |

## 6. Zero-shot results, eval set (`analysis/score.py --set eval`, 2656 units, invalid counted wrong)

Full tables incl. family-cluster bootstrap CIs (2000) and robustness: `results/STAGE2_SCORES.md`
(`python3 score_stage2.py`). TP FN FP TN; AUROC from the scores of all units.

### 6.1 Intern-Decision-4B (frozen Jev prompts, noul yes/no, score = calibrated P(yes))

Secondary thresholds frozen on layer1 dev (652 units, L2 example groups excluded) before any eval call,
`results/intern_decision/FROZEN` (2026-11-23T21:53:15Z): L1 0.8230, L2 0.6729, L3 0.5391 (argmax dev macro-F1).
Dev: L1 macro-F1@0.5 0.861 / AUROC 0.967; L2 0.884 / 0.965; L3 0.898 / 0.976.

| Strategy | Layer | macro-F1 @0.5 [95% CI] | TP FN FP TN @0.5 | macro-F1 @secondary [95% CI] | TP FN FP TN @sec. | AUROC |
|---|---|---|---|---|---|---|
| L1 | layer1 | **0.825** [0.805, 0.843] | 1217 111 350 978 | 0.827 [0.795, 0.854] | 1016 312 146 1182 | 0.920 |
| L2 | layer1 | **0.844** [0.831, 0.857] | 1274 54 356 972 | 0.859 [0.836, 0.879] | 1188 140 234 1094 | 0.935 |
| L3 | layer1 | **0.876** [0.862, 0.893] | 1305 23 302 1026 | 0.875 [0.858, 0.892] | 1284 44 285 1043 | 0.943 |
| L1 | layer3 | 0.583 [0.546, 0.622] | 1307 21 950 378 | 0.630 [0.593, 0.667] | 635 693 265 1063 | 0.729 |
| L2 | layer3 | 0.500 [0.475, 0.527] | 1314 14 1094 234 | 0.625 [0.599, 0.651] | 1151 177 769 559 | 0.734 |
| L3 | layer3 | 0.664 [0.636, 0.693] | 1309 19 796 532 | 0.700 [0.675, 0.724] | 1305 23 720 608 | 0.879 |
| L1 | placebo | 0.814 [0.794, 0.834] | 1209 119 371 957 | 0.825 [0.786, 0.860] | 1022 306 157 1171 | 0.907 |
| L3 | placebo | 0.871 [0.856, 0.888] | 1314 14 324 1004 | 0.868 [0.854, 0.884] | 1294 34 312 1016 | 0.936 |
| L1 | original | 0.642 [0.614, 0.670] | 1217 111 779 549 | 0.769 [0.744, 0.793] | 1016 312 302 1026 | 0.851 |

Robustness layer1 → layer3 (`analysis/robustness.py`, Δmacro-F1 [95% CI]; adjusted = stress − placebo):
L1 @0.5 −0.242 [−0.269, −0.211], adjusted −0.230 [−0.258, −0.202]; L1 @sec −0.197, adjusted −0.195 [−0.217, −0.171];
L2 @0.5 −0.343 [−0.369, −0.318], @sec −0.234 [−0.251, −0.215] (no L2 placebo run);
L3 @0.5 −0.212 [−0.238, −0.189], adjusted −0.207 [−0.236, −0.182]; L3 @sec −0.176, adjusted −0.169 [−0.192, −0.147].
The drop is almost entirely new false positives on good units (good flip rate L1 0.456, L3 0.390 at 0.5;
placebo flips 0.04–0.05); recall stays ≥ 0.98 at 0.5.

Determinism: `det50_L1_r2` (50 layer1 eval units, rerun after all other runs) vs `eval_L1_r1`: 50/50 identical
`pred` and `pred_secondary`, scores bit-identical (max |Δ| 0.0).

### 6.2 LineVul (threshold 0.5; no secondary threshold)

Checkpoint `MickyMike/LineVul` `pytorch_model.bin` (sha256 be824c90...), tokenizer `microsoft/codebert-base`,
512-token truncation (`tokenize(code)[:510]` + `<s>`/`</s>`), head on the `<s>` vector as in the LineVul repo.
CPU and GPU predictions agree on every unit: `deveval_v1` 3316/3316 identical `pred`, max |Δscore| 4.0e-5.

| Run | Units | TP FN FP TN | P / R / F1 | truncated |
|---|---|---|---|---|
| `smoke_sample` (layer1_sample, dev) | 48 | 12 12 13 11 | 0.48 / 0.50 / 0.49 | 1 |
| `deveval_v1` dev | 660 | 188 142 195 135 | 0.49 / 0.57 / 0.53 | 1 |
| `deveval_v1` eval | 2656 | 884 444 851 477 | 0.51 / 0.67 / 0.58 | 19 |

Eval-set scores (`analysis/score.py`, `linevul_gpu`; `linevul_cpu` layer1 is identical):

| Layer (run) | macro-F1 [95% CI] | F1_leak | TP FN FP TN | AUROC | truncated (all 3316) |
|---|---|---|---|---|---|
| layer1 (`deveval_v1`) | 0.501 [0.479, 0.520] | 0.577 | 884 444 851 477 | 0.504 | 20 |
| layer3 (`all_v1`) | 0.449 [0.428, 0.469] | 0.622 | 1084 244 1075 253 | 0.492 | 203 |
| placebo (`all_v1`) | 0.480 [0.460, 0.499] | 0.624 | 1058 270 1005 323 | 0.519 | 144 |
| original (`all_v1`) | 0.356 [0.338, 0.377] | 0.527 | 884 444 1146 182 | 0.331 | 955 |

Robustness layer1 → layer3: Δmacro-F1 −0.051 [−0.070, −0.034], placebo-adjusted −0.031 [−0.047, −0.014].
`all_v1` latency is not usable (runs shared GPU 1 with the decide bulk runs; median 28 ms vs 5.9 ms alone).

Accuracy is ≈ 0.5: LineVul (Big-Vul) does not separate the debiased bad/good units. `deveval_v1` was run on
`data/build/layer1.jsonl` sha256 `5c15ac96...` (snapshot 2026-11-23 10:23 PST), both `linevul_cpu` and
`linevul_gpu`. If the data lane rebuilds units (`data/build/changed_units.json`), rerun those units; the CPU path
alone suffices while GPUs are busy with fine-tuning (`.venv/bin/python linevul_infer.py --method linevul_cpu ...`).

## 7. Versions

184-toast: Ubuntu 24.04.4, driver 580.178.04, CUDA 13.0, 2× RTX 3090 24 GiB; venv `~/disk4/cs224/venv`
(Python 3.12.3): torch 2.14.0+cu130, vllm 0.34.0, transformers 5.22.2, peft 0.22.0, flashinfer-python 0.7.3,
**flash-linear-attention / fla-core 0.6.0 (added by this lane)**. Models in `~/disk4/cs224/models/`
(Qwen3.5-4B, Intern-Decision-4B, LineVul, codebert-base), sha256 of every weight file identical to dell.
dell: `juliet_full/gpu/.venv` (Python 3.12.3, torch 2.14.0+cpu, transformers 5.22.2).

## 8. Caveats

- **Python headers**: Triton JIT-compiles a C launcher and needs `Python.h`; 184-toast has no `python3.12-dev` and
  no sudo. The identical 3.12.3-1ubuntu0.17 headers were copied from dell to `~/disk4/cs224/pyinclude/` and
  `env.sh` puts them on `CPATH`. Any other GPU job on 184-toast (e.g. Phase C training) must `source server/env.sh`.
- **Prefix caching** (vLLM mamba "align" mode) works at 576-token block granularity: the ~400-token L1 system prompt
  never hits (0 hits in the benchmark); a repeated 1,462-token prompt hit 1,152 of its tokens. L2 prompts with a long
  fixed prefix will benefit; L1/L3 latency is effectively cache-free.
- FlashInfer kernels are disabled (no nvcc / flashinfer-cubin); vLLM uses FLASH_ATTN. HF path (decide server) uses
  fla for the gated delta rule but the PyTorch fallback for `causal_conv1d` (not installable without nvcc); the model
  card reports 44 ms on a 4090, we measure ~78 ms forward for ~420 tokens on a 3090.
- vLLM logs `Attempted to load weight layers.N.linear_attn.norm.weight with dtype torch.float32 into ... bfloat16`:
  the checkpoint stores those norms in fp32; harmless.
- A new TCP connection from dell adds ~11 ms before the first byte (keep-alive: ~1 ms). Use pooled clients
  (OpenAI SDK, httpx, requests.Session); the benches use one keep-alive connection per thread.
- `linevul_gpu` latency is host-local on 184-toast (no LAN hop, LAN RTT 0.08 ms). `linevul_cpu` latency on dell is
  very load-dependent (load average 18 on 12 threads during `deveval_v1` because other lanes were running; median
  0.13 s on a quieter dell for the 40-unit pre-plan smoke); re-measure on `latency300` with an idle dell before reporting.
- The decide service, vLLM and the LineVul GPU runs share GPU 1 in stage 2: any latency measured while another
  lane's bulk run uses GPU 1 is contended (see §4.1); bulk-run `latency_s` in `results/intern_decision/*` is
  concurrency-2 wall time incl. queueing and GPU sharing, not a latency figure.
- `results/intern_decision/original/orig_eval_L1_r1`: in `data/build/original.jsonl` every bad unit's
  `model_text` equals layer1's (1658/1658) and every good unit's differs, so TP/FN equal layer1's for a
  deterministic method; only the good-unit side (FP/TN) measures the original-vs-debiased effect.
- The cs253-pre SGLang containers stay stopped (not touched by these scripts).
