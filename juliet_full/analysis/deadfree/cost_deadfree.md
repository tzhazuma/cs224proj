# DeadFree (layer3 eval, 2,656 units) — cost per 1,000 units

FX 0.15005 USD/CNY (Frankfurter API = ECB euro foreign exchange reference rates (cross rate CNY->USD), ECB date 2026-11-24, fetched 2026-11-25). RTX 3090 rental $0.5/h (RunPod Secure Cloud, 2026-11-25); electricity 350 W × $0.11869/kWh = $0.04154/GPU-h.

| method | where | macro-F1 | c1 median s | $ / 1k units | native / 1k | notes |
|---|---|---|---|---|---|---|
| DeepSeek L1 | cloud | 0.863 | 0.895 | $0.0654 | ¥0.4359 | peak $0.1308 / off-peak $0.0654; 0% calls at peak |
| DeepSeek L2 | cloud | 0.873 | 0.860 | $0.0640 | ¥0.4266 | peak $0.1280 / off-peak $0.0640; 0% calls at peak |
| DeepSeek L3 | cloud | 0.875 | 0.810 | $0.0420 | ¥0.2797 | peak $0.0839 / off-peak $0.0420; 0% calls at peak |
| DeepSeek L4 | cloud | 0.900 | 1.008 | $0.1098 | ¥0.7315 | peak $0.2195 / off-peak $0.1098; 0% calls at peak |
| Jev L1 @0.5 | cloud | 0.946 | 0.912 | $0.0364 | $0.0364 | 867 input tok/unit |
| Jev L2 @0.5 | cloud | 0.942 | 0.956 | $0.0660 | $0.0660 | 1572 input tok/unit |
| Jev L3 @0.5 | cloud | 0.949 | 0.923 | $0.0386 | $0.0386 | 920 input tok/unit |
| Jev L4-D @0.5 | cloud | 0.907 | 0.967 | $0.1824 | $0.1824 | 4344 input tok/unit |
| LoRA L4-D (opt.) | local | 0.826 | 0.472 | $0.0703 | – | batch 0.506 GPU-s/unit; c1 $0.0705; electricity $0.0058 |
| LoRA L1 (unit-label FT) | local | 0.372 | 0.120 | $0.0157 | – | batch 0.113 GPU-s/unit; c1 $0.0143; electricity $0.0013 (secondary) |
| LoRA L3 (unit-label FT) | local | 0.639 | 0.143 | $0.0169 | – | batch 0.122 GPU-s/unit; c1 $0.0159; electricity $0.0014 (secondary) |

One-off (ours): training 2.327 GPU-h for one fold model ($1.16 at rental), 3-fold CV total 6.809 GPU-h ($3.40); labelling 0.1391 CPU-h ($0.0695).

Break-even (units after which ours = one-off + batch rental per unit is cheaper):

| vs | units |
|---|---|
| deepseek_L1 | never |
| deepseek_L4 | 31,277 |
| jev_L3 | never |
| jev_l4d | 11,001 |

Break-even sensitivity:

| scenario | deepseek_L1 | deepseek_L4 | jev_L3 | jev_l4d |
|---|---|---|---|---|
| c1_rental | never | 31,421 | never | 11,019 |
| community_rental_batch | 15,744 | 6,885 | 70,668 | 3,582 |
| owned_electricity_only | 1,720 | 986 | 3,126 | 581 |
| deepseek_all_offpeak | never | 31,277 | – | – |
| deepseek_all_peak | 20,386 | 8,266 | – | – |
