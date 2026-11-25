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
