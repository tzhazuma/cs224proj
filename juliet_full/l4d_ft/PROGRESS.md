# l4d-train progress (2026-11-24 09:20 PST = 17:20Z) — stage 1 COMPLETE

## Done
- Training, all FROZEN entries (FROZEN sha 8019da17…), all eval predictions (lora_l4d 3 folds × 4 layers,
  qwen_readout_l4d 4 layers), aggregation, scores, facts and the prune test (`results/scores/`).
- lora_l4d_opt units derived from the stored answers (identical verdicts).
- GPU1 handed over at 14:26:47Z (GPU1_FREE_FOR_VULNLLMR). `server/serve_l4d.sh` (default GPU1, fallback);
  SERVE_L4D_READY touched 16:14:10Z.
- Kernel equivalence FAILS → fallback (prediction config) is primary everywhere.
- Latency latency300 c1 e2e (fallback, median/p90 s):
  - DeadFree: opt 0.472/1.018, full 1.006/2.257; old LoRA L1 0.120/0.135, L3 0.125/0.145.
  - Debiased: opt 0.214/0.619, full 0.645/1.479.
  - Kernel (secondary, DeadFree only): opt 0.445/0.958, full 0.933/2.097.
  - Summary: `results/scores/latency_summary.json`; equivalence `results/scores/kernel_equiv_*.json`.
- GPU-0 chain `kernel/gpu0_chain.sh` (log `raw_logs/gpu0_chain.log`) finished 17:05:56Z: :8004 on GPU0 stopped,
  :8003 started with `serve.sh start` (prediction config) and healthy, GPU0_L4D_DONE touched.
- REPORT_stage1.md complete (no pending rows).

## Nothing left running from this lane
- :8003 on GPU0 stays up (decision_ft serve.sh). :8001/:8002/:8004 on GPU1 belong to the latency-deadfree lane.
