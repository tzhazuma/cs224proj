# l4d-train progress (2026-11-24 ~04:05 PST = 12:05Z)

## Done
- Code: server/{dft_core.py, l4d_prompt.py, l4dft.py, env.sh, job.sh, queue.sh, after.sh, chain_train.sh}, render.py,
  select_fold.py, aggregate.py, latency.py, report_tables.py, upload.sh, collect.sh, .gitignore.
- Smoke + speed test: build/speedtest.json. Chose option (a), 2-GPU DDP per fold (speedup 2.00×).
- Training (DDP 0,1, 14k questions/fold, 1.5 epochs, 657 steps, evals at 219/438/657): fold0 06:44–07:53Z,
  fold1 08:05–09:12Z, fold2 09:12–10:20Z. That is about 68 min wall × 2 GPUs, ≈2.3 GPU-h per fold. All three use step219.
- FROZEN (JSON) entries:
  - fold0 08:07:18Z, τ 0.817574
  - readout 08:07:18Z, τ 0.268941
  - questions_other 08:07:45Z
  - fold2 11:02:13Z, τ 0.5
  - fold1 12:01:17Z, τ 0.5 (merged dev macro-F1 1.0, AUROC 1.0; adapter 6b50c79f…, head 41c0b71e…)
- FROZEN sha256 8019da17… (local and remote identical).
- Eval predictions done:
  - lora fold0 on all 4 layers
  - readout layer1 (aggregated: macro-F1 0.868)
  - dev answers for folds 0 and 2, and readout dev

## Running / queued on 184-toast (status/*.queue, logs/*.log; after.sh waiters)
- GPU0: g0b1 (fold1 merged dev predict → results/lora_l4d/layer1/dev_fold1.jsonl), then g0b2 (readout layer3), then
  g0c (fold1 eval on 4 layers + readout placebo). g0c waits for frozen:1. ETA ~15:15Z.
- GPU1: g1b2 (readout original, ETA ~13:12Z), then g1c (fold2 eval on 4 layers). ETA ~14:40Z.
- Rebalance proposal (parent, 03:55): declined by agreement. The current assignment is the most balanced.

## Next steps (exact)
1. ~~Freeze fold1~~ Done at 12:01:17Z; progress update sent.
2. When all queues are done:
   - `bash collect.sh`
   - For M in lora_l4d, qwen_readout_l4d and L in layer1, layer3, placebo, original, run
     `../l4d/.venv/bin/python aggregate.py units|score|facts --method M --layer L`
   - Then `python3 report_tables.py > build/report_tables.md`
3. Latency (GPUs idle):
   - Start the endpoint: `ssh 184-toast 'cd ~/disk4/cs224/l4d_ft; CUDA_VISIBLE_DEVICES=0 nohup … server/l4dft.py serve --port 8004'`.
   - Run on dell: `flock /tmp/cs224_latency.lock ../l4d/.venv/bin/python latency.py` (requires load1 < 2.5).
   - Stop :8004 afterwards.
4. Restore services, in this order:
   - `bash ~/disk4/cs224/gpu/server/svc.sh qwen start`
   - `svc.sh decide start`
   - `bash ~/disk4/cs224/decision_ft/server/serve.sh start`
   - Check health of :8001, :8002, :8003. Deadline: 2026-11-25 12:00 PST.
5. Write REPORT_stage1.md. Include the structure-only baseline (analysis/l4d_const/RESULT.txt) and the DeadFree gain.
