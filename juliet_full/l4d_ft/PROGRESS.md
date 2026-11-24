# l4d-train progress (2026-11-24 08:40 PST = 16:40Z)

## Done
- Training, all FROZEN entries, all eval predictions (lora_l4d 3 folds × 4 layers, qwen_readout_l4d 4 layers).
- Aggregation, scores, facts and the prune test are in `results/scores/`. lora_l4d_opt units are derived (identical
  verdicts).
- GPU1 handed over at 14:26:47Z (GPU1_FREE_FOR_VULNLLMR).
- `server/serve_l4d.sh` written (default GPU1, fallback). The same file is on 184-toast. SERVE_L4D_READY touched
  16:14:10Z.
- Kernel equivalence: FAIL. Fallback is primary.
- Latency done for DeadFree (layer3), fallback and kernel, opt and full.
- REPORT_stage1.md written. The rows still marked "pending" are layer1 L4-D latency, old LoRA L1/L3 DeadFree
  latency, and the :8003 health check.

## Running (detached, needs no agent)
- `kernel/lat_all.sh fallback … opt:layer3 full:layer3 opt:layer1 full:layer1`, log `raw_logs/lat_fallback.log`.
  The layer3 runs are done; layer1 is running or waiting for the lock.
- `kernel/gpu0_chain.sh` (dell, setsid; started 16:33:08Z), log `raw_logs/gpu0_chain.log`. It does the following:
  1. waits for lat_all
  2. runs `serve_l4d.sh stop` (GPU0 :8004)
  3. runs `serve.sh start` (:8003, prediction config) and waits for /health
  4. runs `flock /tmp/cs224_latency.lock python3 kernel/dft_lat300.py --tag fallback --layer layer3`, which writes
     `results/kernel/decision_ft/fallback/layer3/latency300_L{1,3}_v1.*` and
     `results/scores/kernel_equiv_decision_ft_layer3_fallback.json`
  5. touches `~/disk4/cs224/GPU0_L4D_DONE`

## Next steps after GPU0_L4D_DONE
1. `tail raw_logs/gpu0_chain.log raw_logs/lat_fallback.log`
2. Read `results/lora_l4d*/layer1/lat300_c1_fallback.meta.json` (e2e_s, server_forward_s, parse_s,
   questions_per_unit).
3. Read `results/scores/kernel_equiv_lora_l4d*_layer1_lat300_c1_fallback.json` and
   `kernel_equiv_decision_ft_layer3_fallback.json`.
4. Check health: `curl -s --noproxy '*' http://10.15.89.184:8003/health`. Also :8001/:8002, owned by the GPU1 lanes.
5. Fill the "pending" rows in REPORT_stage1.md §6/§10, then send the final report.
