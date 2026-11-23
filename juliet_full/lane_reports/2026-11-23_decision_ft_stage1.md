I built and smoke-tested the pipeline, ran the speed test, and started the queue on both GPUs. The first two L1 jobs passed their first half-epoch dev evaluation, and the rendered L3 data is on the server and queued. Training is still running, so there are no fold predictions yet.

**Job status (19:21 UTC):**

| Job | GPU | Status | Dev AUROC, step 0 → half epoch | Dev loss, step 0 → half epoch |
|---|---|---|---|---|
| L1 fold0 | 0 | training, step 79 of 321 | 0.892 → 1.000 | 1.03 → 2e-6 |
| L1 fold1 | 1 | training, step 91 of 339 | 0.892 → 0.9995 | 1.03 → 0.23 |
| L1 fold2, L3 fold0/1/2 | — | queued | — | — |

**Results so far:**
- **Step-0 check:** the head and the tied Yes/No rows give exactly the same score on the same hidden state (difference 0.0). Against the base model's own Yes−No logit difference (batch size 1, 660 dev units) the max difference is 0.121 and the mean 0.041, which is BF16 rounding. Padded batches vs batch size 1: max 0.357, mean 0.045.
- **Zero-shot dev AUROC (L1):** 0.8825 from the base model's own output layer, 0.8842 from my head at batch size 1, 0.8918 batched. The L3 zero-shot number is only from the 40-unit smoke test (0.955); the real one will be logged when the L3 jobs start.
- **Kernels:** `flash-linear-attention` 0.6.0. I checked at load time that transformers really calls its Triton kernel, and this is written to each job's `config.json`. `causal_conv1d` can't be installed without nvcc, so the slower PyTorch fallback is used.
- **LoRA:** 32,464,896 trainable parameters, matching the expected count (asserted). Only the text stack is loaded; vision and MTP are skipped.

**Speed and memory** (8 groups per optimizer step, 1 group per micro-batch):

| Setting | tokens/s | s/step | peak memory |
|---|---|---|---|
| L1, no gradient checkpointing | 1741 | 4.5 | 20.3 GB |
| L1, always checkpointing | 1186 | 6.6 | 9.8 GB |
| L3, checkpointing only above 1200 padded tokens | 1542 | 5.5 | 20.0 GB |

- The real jobs run at about 1550–1730 tokens/s with a peak of about 20 GB on each 24 GB card.
- I chose the 1200-token cutoff because activations cost about 10 MB per token without checkpointing and a 1400-token pair already needs 21.9 GB.
- A dev evaluation (660 units) takes 70–80 s. Latency at batch size 1 has a median of 0.10–0.16 s.

**ETA:** about 45 min per L1 job and 50 min per L3 job, so roughly 2.5 h wall for all six. All jobs should be done around 21:40 UTC. That is under 6 h, so max epochs stays at 3.

**Monitor and collect:**
- Status: `ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/status.sh'`.
- Per-job logs and status are under `~/disk4/cs224/decision_ft/logs/` and `status/`.
- Pull results to dell with `./collect.sh` (add `--adapters` to also pull the weights).
- To re-run a failed job, delete `status/<job>.claim` and `status/<job>.json` on the server, then run `start_queue.sh`.

**Deviations:**
- **Latency** is measured on the server (one 3090, nothing else on that card, tokenisation and network excluded), not on dell as contract section 4 says.
- **L3 prompt check:** `prompts.audit()` rejects 28 L3 units because Clang's own message says "Potential memory leak". I check the evidence block with the other forbidden patterns only; code and fixed text still get the full check.
- **Threshold:** chosen on the merged model's batch-size-1 dev scores, which are the same scores it is applied to.
- **Merged vs unmerged scores (smoke test):** differ by up to 0.36 (mean 0.23), more than plain BF16 rounding. This is the rounding of small LoRA changes when merged into BF16 weights; dev AUROC was the same either way. The real numbers will be in each job's `dev_metrics.json` under `merge_check`.

**Issues:**
- **Suspiciously easy task:** dev AUROC reaches about 1.0 after half an epoch and training loss drops to about 1e-8. Selection will mostly be decided by dev loss, because the AUROC values tie. The bad and good units may differ in surface features the model can pick up. That is for the data lane to check; I didn't change anything.
- **Loss spikes:** there are occasional spikes with gradient norm up to about 145 early on; gradient clipping at 1.0 is on.
- **Untracked files:** everything is untracked under `juliet_full/decision_ft/`. I added a `.gitignore` for `.venv/` (174 MB). The rendered `data/` (48 MB) is not ignored; that's your call. Nothing is staged.

Changed files (all in `juliet_full/decision_ft/`):
- `README.md`: the training and selection rules, written before training started.
- `render_data.py` and `data/`: the rendered training, dev and prediction JSONL plus `manifest.json`.
- `server/`: `dft.py`, `queue.sh`, `start_queue.sh`, `status.sh`, `env.sh`.
- `collect.sh`, `.gitignore`, and `runs/`: train logs, configs and speed tests pulled by `collect.sh`.

Validation: the end-to-end smoke test (L3 fold 0: train, select, merge, predict, all output files) passed. The data on the server matches dell (19 checksums), and the scripts pass `bash -n`.

Recommended next step: after about 21:40 UTC, run `./collect.sh` and check each job's selection and `merge_check`.