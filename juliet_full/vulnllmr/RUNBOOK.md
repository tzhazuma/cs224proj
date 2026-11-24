# VulnLLM-R-7B run plan

Launch this plan only after the GPUs on 184-toast have been released to this lane. Everything below runs from
**dell**: the runner is the client, and `ssh 184-toast` manages the server.

## One command

```bash
cd /home/barton/Documents/projects/cs224/cs224proj/juliet_full
nohup vulnllmr/run_all.sh 1 > vulnllmr/raw_logs/run_all.log 2>&1 &     # one 3090 (GPU 1)
# or: nohup vulnllmr/run_all.sh 0,1 > ...  (both 3090s, data parallel)
tail -f vulnllmr/raw_logs/run_all.log                                  # poll; ends with "all done"
```

`run_all.sh` stops the server on exit, including on failure; set `VULNLLMR_KEEP=1` to keep it running.
`VULNLLMR_NOHINT=1` adds the optional no-hint run. Every step is resumable: rerun the same command after any failure.
A runner exit code of 3 means some units ended `error` after retries, and the script stops there; rerunning retries
only those units.

## What it does (equivalent manual steps)

### 1. GPU
- Use one *empty* RTX 3090. GPU 1 is the default; the services GPU had marker `GPU1_FREE_FOR_SERVICES` at prep time.
- `0,1` uses both GPUs as `--data-parallel-size 2` behind port 8005. This is untested on vllm 0.34. If it fails to
  start, use `1` alone.
- `serve_vulnllmr.sh` refuses to start if a requested GPU already has > 1 GiB in use or port 8005 is taken.

### 2. Start the server and check health
```bash
ssh 184-toast 'bash ~/disk4/cs224/vulnllmr/serve_vulnllmr.sh start 1'
ssh 184-toast 'bash ~/disk4/cs224/vulnllmr/serve_vulnllmr.sh health'   # repeat until healthy (~1-3 min)
curl -s http://10.15.89.184:8005/v1/models                              # from dell: lists vulnllm-r-7b
```
- Server log: `184-toast:~/disk4/cs224/vulnllmr/logs/vulnllmr.log`.
- Flags: `--gpu-memory-utilization 0.90 --max-model-len 12288 --max-num-seqs 64 --enable-prefix-caching
  --generation-config vllm --dtype bfloat16`. See `serve_vulnllmr.sh` for the memory arithmetic.
- If dell cannot reach port 8005 (not tested; the server was never started), tunnel it with
  `ssh -N -L 8005:127.0.0.1:8005 184-toast &` and set `VULNLLMR_BASE_URL=http://127.0.0.1:8005/v1`.

### 3. Smoke test (optional, about 1 min)
```bash
python3 vulnllmr/run_vulnllmr.py --layer layer1 --set dev --limit 8 --run-id smoke_policy_r1
```
Check `results/vulnllm_r_7b/layer1/smoke_policy_r1.meta.json`:
- `invalid_rate` should be near 0;
- `generation` should be temperature 0;
- `completion_tokens_mean` gives a first read on output length.

### 4. Run order (bulk, concurrency 64)

| # | command (`python3 vulnllmr/run_vulnllmr.py ...`) | units | est. h, 1 GPU (362–1427 out tok) |
|---|---|---|---|
| 1 | `--layer layer1 --set dev` → `layer1/dev_policy_r1` | 660 | 0.07–0.28 |
| 2 | `--layer layer1 --set eval` → `layer1/eval_policy_r1` | 2,656 | 0.27–1.15 |
| 3 | `--layer layer3 --set eval` | 2,656 | 0.27–1.15 |
| 4 | `--layer placebo --set eval` | 2,656 | 0.27–1.15 |
| 5 | `--layer original --set eval` | 2,656 | 0.28–1.16 |
| 6 | `--layer layer1 --c1-latency` → `layer1/lat300_c1_policy_r1` | 300 | 0.7–2.7 (single stream) |
| 7 (opt.) | `--layer layer1 --set eval --subset nested25 --cwe-hint none` → `layer1/n25_nohint_r1` | 664 | 0.05–0.2 |

- Steps 1+2 total 3,316 units: 0.34–1.43 h on 1 GPU, 0.17–0.71 h on 2.
- Steps 3–5 total 7,968 units: 0.83–3.45 h on 1 GPU, 0.41–1.73 h on 2.
- Basis: `build/estimate.json`. Rows 1, 4 and 5 use the same formula with each layer's mean prompt length. The range runs from the paper's mean of 362 output tokens to the teacher Juliet mean of
  1427, at an assumed 1000–1500 tok/s aggregate decode per 3090.
- After step 1, read `completion_tokens_mean` in the meta and re-estimate.

c1 latency (step 6):
- Takes `flock /tmp/cs224_latency.lock` on dell and needs dell load1 < 2.5 for 2 minutes.
- Refuses if the server has running requests, so it must run after the bulk runs.
- Keep dell otherwise idle during it.

### 5. Score
```bash
python3 analysis/score.py --pred vulnllmr/results/vulnllm_r_7b/layer1/eval_policy_r1.jsonl --set eval --json
python3 analysis/score.py --pred vulnllmr/results/vulnllm_r_7b/layer3/eval_policy_r1.jsonl \
    --units data/build/layer3.jsonl --set eval --json        # likewise placebo, original
python3 analysis/score.py --pred vulnllmr/results/vulnllm_r_7b/layer1/dev_policy_r1.jsonl --set dev --json
python3 analysis/score.py --pred vulnllmr/results/vulnllm_r_7b/layer1/lat300_c1_policy_r1.jsonl \
    --set eval --subset latency300 --json
```
- `run_all.sh` writes each report to `results/vulnllm_r_7b/<layer>/<run_id>.score.json`.
- `pred` is the lenient verdict (`#judge: yes`, any CWE). The strict authors' rule (yes AND type CWE-401) is
  `extra.pred_strict`.
- Report `invalid_rate` and `yes_type_counts` from each `.meta.json`.

### 6. Stop the server
```bash
ssh 184-toast 'bash ~/disk4/cs224/vulnllmr/serve_vulnllmr.sh stop'
ssh 184-toast 'bash ~/disk4/cs224/vulnllmr/serve_vulnllmr.sh status'   # GPU memory back to ~0
```
