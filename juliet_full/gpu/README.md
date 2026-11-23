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
| `bench/bench_qwen.py`, `bench/bench_decide.py` | probes + latency/throughput from dell (stdlib only, keep-alive HTTP) |
| `bench/l1_probe_prompt.txt` | L1-style probe prompt (copy of the 2026-11-23 DeepSeek probe prompt; not the frozen L1 prompt) |
| `results/bench/*.json` | raw benchmark reports; `results/linevul_{cpu,gpu}/layer1/*.jsonl` predictions (contract §4) |
| `.venv/` | dell CPU venv for LineVul (git-ignored): torch 2.14.0+cpu, transformers 5.22.2 |

## 2. Start / stop

**Current state (2026-11-23 10:46 PST): both services STOPPED on purpose** so the fine-tuning lane gets both
GPUs (marker file `184-toast:~/disk4/cs224/GPU_FREE_FOR_FT` created after nvidia-smi showed 38 / 15 MiB used and no
compute processes). Restart only after fine-tuning has released the GPUs:

```bash
ssh 184-toast 'nvidia-smi --query-compute-apps=pid,used_memory --format=csv'  # must list nothing on GPU 0/1
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh qwen start'    # GPU 0, ~100 s until healthy (profiling + CUDA graphs)
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh decide start'  # GPU 1, ~40 s
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh qwen health; bash ~/disk4/cs224/gpu/server/svc.sh decide health'
# from dell:
curl -s --noproxy '*' http://10.15.89.184:8001/v1/models   # lists qwen3.5-4b
curl -s --noproxy '*' http://10.15.89.184:8002/health      # {"status":"ok","model":"Intern-Decision-4B",...}
ssh 184-toast 'bash ~/disk4/cs224/gpu/server/svc.sh qwen stop; bash ~/disk4/cs224/gpu/server/svc.sh decide stop'
```
`health` prints `<name> healthy (...)` and exits 0 when the endpoint answers; `status` shows pid or `not running`.
Re-verify after restart: `cd juliet_full/gpu/bench && python3 bench_qwen.py && python3 bench_decide.py`
(~90 s; writes new `results/bench/*.json`). If the fine-tuned adapter is to be served, that is a new vLLM flag
(`--enable-lora --lora-modules ...`), not covered here.
`QWEN_GPU_UTIL=0.45 svc.sh qwen start` lowers the vLLM memory share (default 0.55).

## 3. Endpoints (both bound to 0.0.0.0, reachable from dell without a tunnel)

**Qwen3.5-4B** — `http://10.15.89.184:8001/v1` (OpenAI API), served name `qwen3.5-4b`, GPU 0.
`vllm serve ~/disk4/cs224/models/Qwen3.5-4B --language-model-only --max-model-len 8192 --enable-prefix-caching
--dtype bfloat16 --gpu-memory-utilization 0.55 --max-num-seqs 64 --generation-config vllm
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
| `linevul_cpu` (dell, 6 torch threads; `deveval_v1`, dell load average 10–22) | 0.161 s / 0.388 s (eval), 0.147 / 0.388 s (dev) |

## 5. GPU memory (nvidia-smi, both services up)

| GPU | Process | Used | Breakdown |
|---|---|---|---|
| 0 | vLLM Qwen3.5-4B | 13.3 GiB of 24 | weights 7.94 GiB (text only), KV/mamba cache 3.78 GiB = 83,870 tokens (10.2 × 8192), CUDA graphs 0.29 GiB |
| 1 | decide_server | 9.4 GiB of 24 | bf16 weights incl. vision tower (~8.6 GiB) + activations; LineVul GPU runs add < 1 GiB transiently |

Room for Phase C (LoRA r16 on Qwen3.5-4B, PLAN §5.2 estimate 12–16 GiB): ~11 GiB free on GPU 0, ~15 GiB free on
GPU 1. Recommended: train on GPU 1 after `svc.sh decide stop` (whole 24 GiB card), or on GPU 1 next to the
decide service only if the run stays under ~14 GiB and no latency measurement is running. Restarting vLLM with
`QWEN_GPU_UTIL=0.45` frees ~2.4 GiB more on GPU 0 (KV cache then ~1.4 GiB, still > 4 × 8192 tokens).

## 6. LineVul results (zero-shot, threshold 0.5; quick counts, the official scorer is analysis/score.py)

Checkpoint `MickyMike/LineVul` `pytorch_model.bin` (sha256 be824c90...), tokenizer `microsoft/codebert-base`,
512-token truncation (`tokenize(code)[:510]` + `<s>`/`</s>`), head on the `<s>` vector as in the LineVul repo.
CPU and GPU predictions agree on every unit: `deveval_v1` 3316/3316 identical `pred`, max |Δscore| 4.0e-5.

| Run | Units | TP FN FP TN | P / R / F1 | truncated |
|---|---|---|---|---|
| `smoke_sample` (layer1_sample, dev) | 48 | 12 12 13 11 | 0.48 / 0.50 / 0.49 | 1 |
| `deveval_v1` dev | 660 | 188 142 195 135 | 0.49 / 0.57 / 0.53 | 1 |
| `deveval_v1` eval | 2656 | 884 444 851 477 | 0.51 / 0.67 / 0.58 | 19 |

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
- The decide service and the LineVul GPU runs share GPU 1; do not measure decide latency while LineVul runs.
- The cs253-pre SGLang containers stay stopped (not touched by these scripts).
