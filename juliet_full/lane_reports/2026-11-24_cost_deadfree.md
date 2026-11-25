I've built the DeadFree cost comparison. Per 1,000 units, our FT L4-D (opt.) costs $0.070 on a rented RTX 3090. That is about the same as DeepSeek L1, more than Jev L1/L3, and cheaper than DeepSeek L4 and Jev L4-D. `make_cost.py` was run twice and gave identical output. All sanity targets were hit and nothing is staged.

**Key table** (cloud = what we were billed, 0 % of DeepSeek calls at peak price; local = $0.50/h rental × batch GPU time)

| method | macro-F1 | c1 median latency | $ / 1k units | other figures per 1k |
|---|---|---|---|---|
| DeepSeek L1 | 0.863 | 0.895 s | $0.0654 | ¥0.436; all at peak $0.131 |
| DeepSeek L2 | 0.873 | 0.860 s | $0.0640 | ¥0.427 |
| DeepSeek L3 | 0.875 | 0.810 s | $0.0420 | ¥0.280 |
| DeepSeek L4 | 0.900 | 1.008 s | $0.1098 | ¥0.731; all at peak $0.220 |
| Jev L1 | 0.946 | 0.912 s | $0.0364 | |
| Jev L2 | 0.942 | 0.956 s | $0.0660 | |
| Jev L3 | 0.949 | 0.923 s | $0.0386 | |
| Jev L4-D | 0.907 | 0.967 s | $0.1824 | 5.9 calls per unit |
| **FT L4-D (opt.), ours** | 0.826 | 0.472 s | **$0.0703** | c1 basis $0.0705; electricity only $0.0058 |
| FT L1 (secondary) | 0.372 | 0.120 s | $0.0157 | |
| FT L3 (secondary) | 0.639 | 0.143 s | $0.0169 | |

**How the numbers were checked**
- **Coverage:** every cloud run set covers the 2,656 eval units exactly once. For Jev L4-D, each question id appears once and the call count per unit matches the kept questions.
- **Billing:** recomputing cost from the logged tokens with `pricing.py` matches the billed amount exactly for every method.
- **Our GPU time:** the stored eval predictions used the full question sets (1.204 GPU-s per unit). I scaled each unit by its own kept/full question count (15,619 of 37,376 kept), giving 0.506 GPU-s per unit. The measured latency300 run of the pruned set gives 0.508 s.

**One-off cost (ours)**
- **Training one model:** 2.327 GPU-h (fold0, 2 GPUs × wall time, the largest fold), which is $1.16 at the rental rate. The 3-fold CV total is 6.809 GPU-h ($3.40). This matches the ≈2.3 GPU-h in `REPORT_stage1.md`.
- **Labelling:** 0.139 CPU-h for the dynamic gold labels of the layer1 training units ($0.07 even at the GPU rate). Layer3 labels are only used for evaluation and are not counted.

**Break-even** (after how many units ours, one-off + rental per unit, gets cheaper)

| vs | units |
|---|---|
| DeepSeek L1 | never |
| DeepSeek L4 | 31,277 |
| Jev L3 | never |
| Jev L4-D | 11,001 |

With the cheaper RunPod Community price ($0.22/h) these become 15.7k, 6.9k, 70.7k and 3.6k units. On an owned GPU paying only electricity, ours wins after 0.6k–3.1k units.

**Sources** (all fetched 2026-11-25, URLs in the JSON)
- **Exchange rate:** 0.15005 USD/CNY from Frankfurter (ECB reference rate dated 2026-11-24). A second source, open.er-api, gives 0.149742.
- **Rental:** RunPod pricing page, RTX 3090: $0.50/h Secure Cloud (used) and $0.22/h Community Cloud.
- **Power:** NVIDIA's RTX 3090 spec page lists 350 W board power.
- **Electricity:** GlobalPetrolPrices China business tariff, CNY 0.791/kWh (March 2026), which works out to $0.0415 per GPU-hour. EIA's US commercial average, 14.27 ¢/kWh, is in the JSON as a comparison.
- **Hardware purchase row:** left out, because I couldn't read a public RTX 3090 street-price page (one returned 403, the other no longer lists the 3090).

**Decisions for you**
1. **Rental tier:** I used RunPod Secure Cloud ($0.50/h). Switching to Community ($0.22/h) turns "never" vs DeepSeek L1 and Jev L3 into a finite break-even.
2. **Electricity tariff:** I used the China national business average, not a Shanghai tariff, because I didn't try a Shanghai page.
3. **Fold files:** the per-fold eval files are in `l4d_ft/build/remote_results/lora_l4d/layer3/`, not `results/lora_l4d/layer3/` as the brief said. Together they match `results/lora_l4d/layer3/eval_r1.jsonl` exactly.
4. **Training cost caveats:** "one model" is fold0's training. A deployment model trained on all the data would see about 1.5× the questions, which wasn't measured. Smoke tests, dev re-selection, other-layer evals and the old LoRA training are not counted.
5. **Slide message:** the suggested 3 lines are in `REPORT_cost.md`, and they say plainly that cost is not where we win. The cloud models are already well under $0.20 per 1k with higher macro-F1. Our case is the latency and keeping code on our own machine.

Files are in `juliet_full/analysis/deadfree/`:
- make_cost.py
- cost_deadfree.json
- cost_deadfree.csv
- cost_deadfree.md
- REPORT_cost.md
- COST_READY