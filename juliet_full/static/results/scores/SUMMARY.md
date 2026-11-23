# Static baselines: scores (stage 2)

End-to-end metrics (invalid or missing = wrong), positive class = leak; 95% family-cluster bootstrap CIs
(2000 resamples, seed 20261126). Main slice = eval (2,656 units, 1,328 groups); `eval_api` = eval ∩ api_subset
(secondary); `eval_n25` = eval ∩ nested25 (332 groups, for paired comparisons with DeepSeek). The same frozen
configuration and checker mapping (chosen on layer-1 dev) is used on every layer. Runs:

| layer | clang_sa | codeql | infer | cppcheck | grep_v0 |
|---|---|---|---|---|---|
| layer1 | `full_v2` | `full_batch50_merged` | `full_per_file_merged` | `full_v2` | `full_v1` |
| layer3 | `full_v1` | `full_batch50` | `full_per_file` | `full_v1` | `full_v1` |
| placebo | `full_v1` | `full_batch50` | `full_per_file` | `full_v1` | `full_v1` |
| original | `full_v1` | `full_batch50` | `full_per_file` | `full_v1` | `full_v1` |

## eval: all layers

| tool | layer | n | macro-F1 [95% CI] | F1_leak | P_leak | R_leak | spec | MCC | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | layer1 | 2656 | 0.855 [0.806, 0.899] | 0.842 | 0.928 | 0.771 | 0.941 | 0.722 | 0 | 0.036 / 0.066 |
| clang_sa | layer3 | 2656 | 0.855 [0.806, 0.899] | 0.842 | 0.928 | 0.771 | 0.941 | 0.722 | 0 | 0.045 / 0.085 |
| clang_sa | placebo | 2656 | 0.855 [0.806, 0.899] | 0.842 | 0.928 | 0.771 | 0.941 | 0.722 | 0 | 0.048 / 0.085 |
| clang_sa | original | 2656 | 0.822 [0.778, 0.862] | 0.813 | 0.859 | 0.771 | 0.873 | 0.648 | 0 | 0.049 / 0.079 |
| codeql | layer1 | 2656 | 0.882 [0.866, 0.897] | 0.891 | 0.829 | 0.963 | 0.802 | 0.775 | 0 | 0.549 / 0.616 |
| codeql | layer3 | 2656 | 0.766 [0.750, 0.785] | 0.758 | 0.787 | 0.730 | 0.802 | 0.534 | 0 | 0.856 / 0.989 |
| codeql | placebo | 2656 | 0.882 [0.866, 0.897] | 0.891 | 0.829 | 0.963 | 0.802 | 0.775 | 0 | 0.895 / 0.996 |
| codeql | original | 2656 | 0.785 [0.765, 0.806] | 0.822 | 0.717 | 0.963 | 0.619 | 0.620 | 0 | 0.823 / 0.909 |
| infer | layer1 | 2656 | 0.815 [0.741, 0.874] | 0.789 | 0.939 | 0.681 | 0.956 | 0.662 | 0 | 0.293 / 0.669 |
| infer | layer3 | 2656 | 0.815 [0.741, 0.874] | 0.789 | 0.939 | 0.681 | 0.956 | 0.662 | 0 | 0.693 / 1.332 |
| infer | placebo | 2656 | 0.815 [0.741, 0.874] | 0.789 | 0.939 | 0.681 | 0.956 | 0.662 | 0 | 0.686 / 1.288 |
| infer | original | 2656 | 0.770 [0.707, 0.819] | 0.749 | 0.832 | 0.681 | 0.862 | 0.552 | 0 | 0.520 / 0.972 |
| cppcheck | layer1 | 2656 | 0.493 [0.436, 0.553] | 0.287 | 0.897 | 0.171 | 0.980 | 0.258 | 0 | 0.015 / 0.024 |
| cppcheck | layer3 | 2656 | 0.493 [0.436, 0.553] | 0.287 | 0.897 | 0.171 | 0.980 | 0.258 | 0 | 0.021 / 0.034 |
| cppcheck | placebo | 2656 | 0.493 [0.436, 0.553] | 0.287 | 0.897 | 0.171 | 0.980 | 0.258 | 0 | 0.022 / 0.035 |
| cppcheck | original | 2656 | 0.467 [0.421, 0.518] | 0.271 | 0.652 | 0.171 | 0.909 | 0.118 | 0 | 0.024 / 0.037 |
| grep_v0 | layer1 | 2656 | 0.701 [0.685, 0.717] | 0.749 | 0.658 | 0.870 | 0.548 | 0.441 | 0 | 0.000 / 0.000 |
| grep_v0 | layer3 | 2656 | 0.333 [0.333, 0.333] | 0.000 | - | 0.000 | 1.000 | 0.000 | 0 | 0.000 / 0.000 |
| grep_v0 | placebo | 2656 | 0.701 [0.685, 0.717] | 0.749 | 0.658 | 0.870 | 0.548 | 0.441 | 0 | 0.000 / 0.000 |
| grep_v0 | original | 2656 | 0.935 [0.906, 0.955] | 0.930 | 1.000 | 0.870 | 1.000 | 0.877 | 0 | 0.000 / 0.000 |

McNemar (eval, per layer; clang_sa vs each other tool, Holm within layer):

| layer | comparison | clang-only right | other-only right | test | p | Holm p |
|---|---|---|---|---|---|---|
| layer1 | clang_sa vs codeql | 248 | 319 | chi2_continuity | 0.00329 | 0.00329 |
| layer1 | clang_sa vs infer | 309 | 209 | chi2_continuity | 1.36e-05 | 2.73e-05 |
| layer1 | clang_sa vs cppcheck | 810 | 66 | chi2_continuity | 4.54e-139 | 1.82e-138 |
| layer1 | clang_sa vs grep_v0 | 740 | 350 | chi2_continuity | 4.81e-32 | 1.44e-31 |
| layer3 | clang_sa vs codeql | 468 | 230 | chi2_continuity | 2.95e-19 | 5.9e-19 |
| layer3 | clang_sa vs infer | 309 | 209 | chi2_continuity | 1.36e-05 | 1.36e-05 |
| layer3 | clang_sa vs cppcheck | 810 | 66 | chi2_continuity | 4.54e-139 | 1.36e-138 |
| layer3 | clang_sa vs grep_v0 | 1024 | 79 | chi2_continuity | 1.02e-177 | 4.09e-177 |
| placebo | clang_sa vs codeql | 248 | 319 | chi2_continuity | 0.00329 | 0.00329 |
| placebo | clang_sa vs infer | 309 | 209 | chi2_continuity | 1.36e-05 | 2.73e-05 |
| placebo | clang_sa vs cppcheck | 810 | 66 | chi2_continuity | 4.54e-139 | 1.82e-138 |
| placebo | clang_sa vs grep_v0 | 740 | 350 | chi2_continuity | 4.81e-32 | 1.44e-31 |
| original | clang_sa vs codeql | 430 | 347 | chi2_continuity | 0.00326 | 0.00326 |
| original | clang_sa vs infer | 368 | 233 | chi2_continuity | 4.6e-08 | 9.21e-08 |
| original | clang_sa vs cppcheck | 863 | 113 | chi2_continuity | 5.08e-127 | 2.03e-126 |
| original | clang_sa vs grep_v0 | 140 | 439 | chi2_continuity | 3.17e-35 | 9.52e-35 |

## eval_api: all layers

| tool | layer | n | macro-F1 [95% CI] | F1_leak | P_leak | R_leak | spec | MCC | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | layer1 | 1328 | 0.840 [0.784, 0.887] | 0.825 | 0.920 | 0.747 | 0.935 | 0.695 | 0 | 0.035 / 0.066 |
| clang_sa | layer3 | 1328 | 0.840 [0.784, 0.887] | 0.825 | 0.920 | 0.747 | 0.935 | 0.695 | 0 | 0.045 / 0.087 |
| clang_sa | placebo | 1328 | 0.840 [0.784, 0.887] | 0.825 | 0.920 | 0.747 | 0.935 | 0.695 | 0 | 0.048 / 0.089 |
| clang_sa | original | 1328 | 0.808 [0.760, 0.850] | 0.796 | 0.852 | 0.747 | 0.870 | 0.622 | 0 | 0.049 / 0.081 |
| codeql | layer1 | 1328 | 0.867 [0.844, 0.889] | 0.879 | 0.813 | 0.956 | 0.780 | 0.748 | 0 | 0.551 / 0.616 |
| codeql | layer3 | 1328 | 0.758 [0.737, 0.782] | 0.753 | 0.770 | 0.736 | 0.780 | 0.517 | 0 | 0.856 / 0.990 |
| codeql | placebo | 1328 | 0.867 [0.844, 0.889] | 0.879 | 0.813 | 0.956 | 0.780 | 0.748 | 0 | 0.886 / 0.996 |
| codeql | original | 1328 | 0.774 [0.748, 0.800] | 0.814 | 0.708 | 0.956 | 0.605 | 0.600 | 0 | 0.826 / 0.909 |
| infer | layer1 | 1328 | 0.811 [0.737, 0.875] | 0.786 | 0.932 | 0.679 | 0.950 | 0.654 | 0 | 0.292 / 0.678 |
| infer | layer3 | 1328 | 0.811 [0.737, 0.875] | 0.786 | 0.932 | 0.679 | 0.950 | 0.654 | 0 | 0.699 / 1.307 |
| infer | placebo | 1328 | 0.811 [0.737, 0.875] | 0.786 | 0.932 | 0.679 | 0.950 | 0.654 | 0 | 0.685 / 1.326 |
| infer | original | 1328 | 0.760 [0.698, 0.810] | 0.740 | 0.813 | 0.679 | 0.843 | 0.530 | 0 | 0.523 / 0.975 |
| cppcheck | layer1 | 1328 | 0.488 [0.434, 0.548] | 0.280 | 0.894 | 0.166 | 0.980 | 0.252 | 0 | 0.015 / 0.025 |
| cppcheck | layer3 | 1328 | 0.488 [0.434, 0.548] | 0.280 | 0.894 | 0.166 | 0.980 | 0.252 | 0 | 0.021 / 0.033 |
| cppcheck | placebo | 1328 | 0.488 [0.434, 0.548] | 0.280 | 0.894 | 0.166 | 0.980 | 0.252 | 0 | 0.022 / 0.035 |
| cppcheck | original | 1328 | 0.464 [0.419, 0.516] | 0.264 | 0.655 | 0.166 | 0.913 | 0.118 | 0 | 0.024 / 0.037 |
| grep_v0 | layer1 | 1328 | 0.706 [0.685, 0.725] | 0.751 | 0.663 | 0.867 | 0.559 | 0.448 | 0 | 0.000 / 0.000 |
| grep_v0 | layer3 | 1328 | 0.333 [0.333, 0.333] | 0.000 | - | 0.000 | 1.000 | 0.000 | 0 | 0.000 / 0.000 |
| grep_v0 | placebo | 1328 | 0.706 [0.685, 0.725] | 0.751 | 0.663 | 0.867 | 0.559 | 0.448 | 0 | 0.000 / 0.000 |
| grep_v0 | original | 1328 | 0.933 [0.903, 0.955] | 0.929 | 1.000 | 0.867 | 1.000 | 0.875 | 0 | 0.000 / 0.000 |

McNemar (eval_api, per layer; clang_sa vs each other tool, Holm within layer):

| layer | comparison | clang-only right | other-only right | test | p | Holm p |
|---|---|---|---|---|---|---|
| layer1 | clang_sa vs codeql | 138 | 174 | chi2_continuity | 0.0475 | 0.0836 |
| layer1 | clang_sa vs infer | 157 | 122 | chi2_continuity | 0.0418 | 0.0836 |
| layer1 | clang_sa vs cppcheck | 390 | 34 | chi2_continuity | 1.32e-66 | 5.29e-66 |
| layer1 | clang_sa vs grep_v0 | 360 | 190 | chi2_continuity | 5.75e-13 | 1.73e-12 |
| layer3 | clang_sa vs codeql | 237 | 127 | chi2_continuity | 1.11e-08 | 2.22e-08 |
| layer3 | clang_sa vs infer | 157 | 122 | chi2_continuity | 0.0418 | 0.0418 |
| layer3 | clang_sa vs cppcheck | 390 | 34 | chi2_continuity | 1.32e-66 | 3.97e-66 |
| layer3 | clang_sa vs grep_v0 | 496 | 43 | chi2_continuity | 2.01e-84 | 8.04e-84 |
| placebo | clang_sa vs codeql | 138 | 174 | chi2_continuity | 0.0475 | 0.0836 |
| placebo | clang_sa vs infer | 157 | 122 | chi2_continuity | 0.0418 | 0.0836 |
| placebo | clang_sa vs cppcheck | 390 | 34 | chi2_continuity | 1.32e-66 | 5.29e-66 |
| placebo | clang_sa vs grep_v0 | 360 | 190 | chi2_continuity | 5.75e-13 | 1.73e-12 |
| original | clang_sa vs codeql | 224 | 187 | chi2_continuity | 0.0758 | 0.0758 |
| original | clang_sa vs infer | 193 | 130 | chi2_continuity | 0.000561 | 0.00112 |
| original | clang_sa vs cppcheck | 415 | 57 | chi2_continuity | 1.12e-60 | 4.5e-60 |
| original | clang_sa vs grep_v0 | 67 | 233 | chi2_continuity | 1.63e-21 | 4.89e-21 |

## eval_n25: all layers

| tool | layer | n | macro-F1 [95% CI] | F1_leak | P_leak | R_leak | spec | MCC | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | layer1 | 664 | 0.828 [0.766, 0.880] | 0.811 | 0.913 | 0.729 | 0.931 | 0.673 | 0 | 0.035 / 0.065 |
| clang_sa | layer3 | 664 | 0.828 [0.766, 0.880] | 0.811 | 0.913 | 0.729 | 0.931 | 0.673 | 0 | 0.045 / 0.081 |
| clang_sa | placebo | 664 | 0.828 [0.766, 0.880] | 0.811 | 0.913 | 0.729 | 0.931 | 0.673 | 0 | 0.048 / 0.086 |
| clang_sa | original | 664 | 0.800 [0.744, 0.848] | 0.786 | 0.852 | 0.729 | 0.873 | 0.609 | 0 | 0.049 / 0.082 |
| codeql | layer1 | 664 | 0.860 [0.829, 0.889] | 0.873 | 0.808 | 0.949 | 0.774 | 0.734 | 0 | 0.551 / 0.616 |
| codeql | layer3 | 664 | 0.747 [0.718, 0.777] | 0.740 | 0.761 | 0.720 | 0.774 | 0.495 | 0 | 0.854 / 0.989 |
| codeql | placebo | 664 | 0.860 [0.829, 0.889] | 0.873 | 0.808 | 0.949 | 0.774 | 0.734 | 0 | 0.897 / 0.998 |
| codeql | original | 664 | 0.772 [0.742, 0.803] | 0.811 | 0.708 | 0.949 | 0.608 | 0.593 | 0 | 0.829 / 0.909 |
| infer | layer1 | 664 | 0.810 [0.733, 0.874] | 0.785 | 0.923 | 0.684 | 0.943 | 0.649 | 0 | 0.291 / 0.678 |
| infer | layer3 | 664 | 0.810 [0.733, 0.874] | 0.785 | 0.923 | 0.684 | 0.943 | 0.649 | 0 | 0.696 / 1.298 |
| infer | placebo | 664 | 0.810 [0.733, 0.874] | 0.785 | 0.923 | 0.684 | 0.943 | 0.649 | 0 | 0.687 / 1.320 |
| infer | original | 664 | 0.756 [0.691, 0.810] | 0.738 | 0.802 | 0.684 | 0.831 | 0.521 | 0 | 0.525 / 0.971 |
| cppcheck | layer1 | 664 | 0.481 [0.416, 0.554] | 0.267 | 0.897 | 0.157 | 0.982 | 0.245 | 0 | 0.016 / 0.026 |
| cppcheck | layer3 | 664 | 0.481 [0.416, 0.554] | 0.267 | 0.897 | 0.157 | 0.982 | 0.245 | 0 | 0.021 / 0.033 |
| cppcheck | placebo | 664 | 0.481 [0.416, 0.554] | 0.267 | 0.897 | 0.157 | 0.982 | 0.245 | 0 | 0.022 / 0.035 |
| cppcheck | original | 664 | 0.462 [0.407, 0.520] | 0.255 | 0.684 | 0.157 | 0.928 | 0.132 | 0 | 0.024 / 0.036 |
| grep_v0 | layer1 | 664 | 0.717 [0.690, 0.743] | 0.757 | 0.675 | 0.861 | 0.584 | 0.464 | 0 | 0.000 / 0.000 |
| grep_v0 | layer3 | 664 | 0.333 [0.333, 0.333] | 0.000 | - | 0.000 | 1.000 | 0.000 | 0 | 0.000 / 0.000 |
| grep_v0 | placebo | 664 | 0.717 [0.690, 0.743] | 0.757 | 0.675 | 0.861 | 0.584 | 0.464 | 0 | 0.000 / 0.000 |
| grep_v0 | original | 664 | 0.930 [0.899, 0.954] | 0.926 | 1.000 | 0.861 | 1.000 | 0.870 | 0 | 0.000 / 0.000 |

McNemar (eval_n25, per layer; clang_sa vs each other tool, Holm within layer):

| layer | comparison | clang-only right | other-only right | test | p | Holm p |
|---|---|---|---|---|---|---|
| layer1 | clang_sa vs codeql | 73 | 94 | chi2_continuity | 0.122 | 0.243 |
| layer1 | clang_sa vs infer | 78 | 67 | chi2_continuity | 0.406 | 0.406 |
| layer1 | clang_sa vs cppcheck | 192 | 19 | chi2_continuity | 2.4e-32 | 9.59e-32 |
| layer1 | clang_sa vs grep_v0 | 174 | 103 | chi2_continuity | 2.6e-05 | 7.8e-05 |
| layer3 | clang_sa vs codeql | 127 | 72 | chi2_continuity | 0.000129 | 0.000258 |
| layer3 | clang_sa vs infer | 78 | 67 | chi2_continuity | 0.406 | 0.406 |
| layer3 | clang_sa vs cppcheck | 192 | 19 | chi2_continuity | 2.4e-32 | 7.19e-32 |
| layer3 | clang_sa vs grep_v0 | 242 | 23 | chi2_continuity | 6.77e-41 | 2.71e-40 |
| placebo | clang_sa vs codeql | 73 | 94 | chi2_continuity | 0.122 | 0.243 |
| placebo | clang_sa vs infer | 78 | 67 | chi2_continuity | 0.406 | 0.406 |
| placebo | clang_sa vs cppcheck | 192 | 19 | chi2_continuity | 2.4e-32 | 9.59e-32 |
| placebo | clang_sa vs grep_v0 | 174 | 103 | chi2_continuity | 2.6e-05 | 7.8e-05 |
| original | clang_sa vs codeql | 116 | 101 | chi2_continuity | 0.342 | 0.342 |
| original | clang_sa vs infer | 96 | 67 | chi2_continuity | 0.0283 | 0.0566 |
| original | clang_sa vs cppcheck | 202 | 30 | chi2_continuity | 3.02e-29 | 1.21e-28 |
| original | clang_sa vs grep_v0 | 36 | 122 | chi2_continuity | 1.36e-11 | 4.08e-11 |

## dev: all layers

| tool | layer | n | macro-F1 [95% CI] | F1_leak | P_leak | R_leak | spec | MCC | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | layer1 | 660 | 0.808 [0.754, 0.853] | 0.780 | 0.940 | 0.667 | 0.958 | 0.652 | 0 | 0.034 / 0.076 |
| clang_sa | layer3 | 660 | 0.808 [0.754, 0.853] | 0.780 | 0.940 | 0.667 | 0.958 | 0.652 | 0 | 0.044 / 0.095 |
| clang_sa | placebo | 660 | 0.808 [0.754, 0.853] | 0.780 | 0.940 | 0.667 | 0.958 | 0.652 | 0 | 0.047 / 0.102 |
| clang_sa | original | 660 | 0.788 [0.736, 0.828] | 0.761 | 0.887 | 0.667 | 0.915 | 0.601 | 0 | 0.049 / 0.099 |
| codeql | layer1 | 660 | 0.918 [0.902, 0.933] | 0.923 | 0.871 | 0.982 | 0.855 | 0.843 | 0 | 0.549 / 0.616 |
| codeql | layer3 | 660 | 0.815 [0.797, 0.835] | 0.808 | 0.842 | 0.776 | 0.855 | 0.632 | 0 | 0.856 / 0.989 |
| codeql | placebo | 660 | 0.918 [0.902, 0.933] | 0.923 | 0.871 | 0.982 | 0.855 | 0.843 | 0 | 0.886 / 0.996 |
| codeql | original | 660 | 0.843 [0.824, 0.862] | 0.864 | 0.771 | 0.982 | 0.709 | 0.718 | 0 | 0.823 / 0.909 |
| infer | layer1 | 660 | 0.784 [0.715, 0.843] | 0.750 | 0.924 | 0.630 | 0.948 | 0.611 | 0 | 0.375 / 0.638 |
| infer | layer3 | 660 | 0.784 [0.715, 0.843] | 0.750 | 0.924 | 0.630 | 0.948 | 0.611 | 0 | 0.663 / 1.134 |
| infer | placebo | 660 | 0.784 [0.715, 0.843] | 0.750 | 0.924 | 0.630 | 0.948 | 0.611 | 0 | 0.665 / 1.140 |
| infer | original | 660 | 0.733 [0.677, 0.781] | 0.705 | 0.800 | 0.630 | 0.842 | 0.484 | 0 | 0.469 / 0.819 |
| cppcheck | layer1 | 660 | 0.468 [0.414, 0.524] | 0.242 | 0.920 | 0.139 | 0.988 | 0.240 | 0 | 0.015 / 0.024 |
| cppcheck | layer3 | 660 | 0.468 [0.414, 0.524] | 0.242 | 0.920 | 0.139 | 0.988 | 0.240 | 0 | 0.021 / 0.033 |
| cppcheck | placebo | 660 | 0.468 [0.414, 0.524] | 0.242 | 0.920 | 0.139 | 0.988 | 0.240 | 0 | 0.022 / 0.035 |
| cppcheck | original | 660 | 0.450 [0.400, 0.502] | 0.231 | 0.676 | 0.139 | 0.933 | 0.120 | 0 | 0.024 / 0.037 |
| grep_v0 | layer1 | 660 | 0.721 [0.689, 0.752] | 0.776 | 0.667 | 0.927 | 0.536 | 0.504 | 0 | 0.000 / 0.000 |
| grep_v0 | layer3 | 660 | 0.333 [0.333, 0.333] | 0.000 | - | 0.000 | 1.000 | 0.000 | 0 | 0.000 / 0.000 |
| grep_v0 | placebo | 660 | 0.721 [0.689, 0.752] | 0.776 | 0.667 | 0.927 | 0.536 | 0.504 | 0 | 0.000 / 0.000 |
| grep_v0 | original | 660 | 0.964 [0.935, 0.989] | 0.962 | 1.000 | 0.927 | 1.000 | 0.930 | 0 | 0.000 / 0.000 |

## Robustness on eval: layer1 → layer3 (stress), placebo as control

Flip = the effective verdict changed (invalid = wrong). right→wrong on bad = lost detection, on good = new FP.
Δ = layer − layer1; adjusted = (layer3 − layer1) − (placebo − layer1) = layer3 − placebo.

Flip rate = right→wrong + wrong→right.

| tool | Δmacro-F1 L3 | ΔF1_leak L3 | bad flip L3 (r→w / w→r) | good flip L3 (r→w / w→r) | Δmacro-F1 placebo | bad / good flip placebo | adjusted Δmacro-F1 | adjusted ΔF1_leak | adjusted bad / good flip |
|---|---|---|---|---|---|---|---|---|---|
| clang_sa | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| codeql | -0.116 [-0.132, -0.097] | -0.134 [-0.154, -0.111] | 0.233 [0.196, 0.265] (0.233 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.116 [-0.132, -0.097] | -0.134 [-0.154, -0.111] | +0.233 / +0.000 |
| infer | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| cppcheck | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| grep_v0 | -0.368 [-0.383, -0.352] | -0.749 [-0.766, -0.728] | 0.870 [0.814, 0.910] (0.870 / 0.000) | 0.452 [0.417, 0.483] (0.000 / 0.452) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.368 [-0.383, -0.352] | -0.749 [-0.766, -0.728] | +0.870 / +0.452 |

Layer1 → original Juliet control (eval; bad units identical, good = whole OMITBAD program):

| tool | macro-F1 layer1 | macro-F1 original | Δmacro-F1 [95% CI] | ΔF1_leak [95% CI] | spec layer1 → original | bad flip | good flip (r→w / w→r) |
|---|---|---|---|---|---|---|---|
| clang_sa | 0.855 | 0.822 | -0.033 [-0.039, -0.027] | -0.030 [-0.036, -0.024] | 0.941 → 0.873 | 0.000 | 0.067 (0.067 / 0.000) |
| codeql | 0.882 | 0.785 | -0.097 [-0.111, -0.084] | -0.070 [-0.078, -0.061] | 0.802 → 0.619 | 0.000 | 0.191 (0.187 / 0.004) |
| infer | 0.815 | 0.770 | -0.045 [-0.057, -0.033] | -0.041 [-0.051, -0.030] | 0.956 → 0.862 | 0.000 | 0.093 (0.093 / 0.000) |
| cppcheck | 0.493 | 0.467 | -0.025 [-0.041, -0.012] | -0.016 [-0.030, -0.007] | 0.980 → 0.909 | 0.000 | 0.072 (0.072 / 0.000) |
| grep_v0 | 0.701 | 0.935 | +0.233 [+0.212, +0.252] | +0.181 [+0.168, +0.192] | 0.548 → 1.000 | 0.000 | 0.452 (0.000 / 0.452) |

## Robustness on eval_api: layer1 → layer3 (stress), placebo as control

Flip = the effective verdict changed (invalid = wrong). right→wrong on bad = lost detection, on good = new FP.
Δ = layer − layer1; adjusted = (layer3 − layer1) − (placebo − layer1) = layer3 − placebo.

Flip rate = right→wrong + wrong→right.

| tool | Δmacro-F1 L3 | ΔF1_leak L3 | bad flip L3 (r→w / w→r) | good flip L3 (r→w / w→r) | Δmacro-F1 placebo | bad / good flip placebo | adjusted Δmacro-F1 | adjusted ΔF1_leak | adjusted bad / good flip |
|---|---|---|---|---|---|---|---|---|---|
| clang_sa | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| codeql | -0.109 [-0.131, -0.088] | -0.126 [-0.152, -0.102] | 0.220 [0.177, 0.263] (0.220 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.109 [-0.131, -0.088] | -0.126 [-0.152, -0.102] | +0.220 / +0.000 |
| infer | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| cppcheck | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| grep_v0 | -0.373 [-0.392, -0.352] | -0.751 [-0.771, -0.727] | 0.867 [0.808, 0.911] (0.867 / 0.000) | 0.441 [0.398, 0.478] (0.000 / 0.441) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.373 [-0.392, -0.352] | -0.751 [-0.771, -0.727] | +0.867 / +0.441 |

Layer1 → original Juliet control (eval_api; bad units identical, good = whole OMITBAD program):

| tool | macro-F1 layer1 | macro-F1 original | Δmacro-F1 [95% CI] | ΔF1_leak [95% CI] | spec layer1 → original | bad flip | good flip (r→w / w→r) |
|---|---|---|---|---|---|---|---|
| clang_sa | 0.840 | 0.808 | -0.032 [-0.040, -0.023] | -0.028 [-0.036, -0.021] | 0.935 → 0.870 | 0.000 | 0.065 (0.065 / 0.000) |
| codeql | 0.867 | 0.774 | -0.093 [-0.109, -0.078] | -0.065 [-0.076, -0.055] | 0.780 → 0.605 | 0.000 | 0.187 (0.181 / 0.006) |
| infer | 0.811 | 0.760 | -0.052 [-0.066, -0.037] | -0.046 [-0.058, -0.032] | 0.950 → 0.843 | 0.000 | 0.107 (0.107 / 0.000) |
| cppcheck | 0.488 | 0.464 | -0.024 [-0.039, -0.011] | -0.015 [-0.027, -0.006] | 0.980 → 0.913 | 0.000 | 0.068 (0.068 / 0.000) |
| grep_v0 | 0.706 | 0.933 | +0.227 [+0.202, +0.249] | +0.178 [+0.162, +0.190] | 0.559 → 1.000 | 0.000 | 0.441 (0.000 / 0.441) |

## Robustness on eval_n25: layer1 → layer3 (stress), placebo as control

Flip = the effective verdict changed (invalid = wrong). right→wrong on bad = lost detection, on good = new FP.
Δ = layer − layer1; adjusted = (layer3 − layer1) − (placebo − layer1) = layer3 − placebo.

Flip rate = right→wrong + wrong→right.

| tool | Δmacro-F1 L3 | ΔF1_leak L3 | bad flip L3 (r→w / w→r) | good flip L3 (r→w / w→r) | Δmacro-F1 placebo | bad / good flip placebo | adjusted Δmacro-F1 | adjusted ΔF1_leak | adjusted bad / good flip |
|---|---|---|---|---|---|---|---|---|---|
| clang_sa | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| codeql | -0.114 [-0.144, -0.083] | -0.133 [-0.171, -0.096] | 0.229 [0.168, 0.288] (0.229 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.114 [-0.144, -0.083] | -0.133 [-0.171, -0.096] | +0.229 / +0.000 |
| infer | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| cppcheck | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | 0.000 [0.000, 0.000] (0.000 / 0.000) | 0.000 [0.000, 0.000] (0.000 / 0.000) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | +0.000 [+0.000, +0.000] | +0.000 [+0.000, +0.000] | +0.000 / +0.000 |
| grep_v0 | -0.384 [-0.410, -0.357] | -0.757 [-0.779, -0.729] | 0.861 [0.801, 0.908] (0.861 / 0.000) | 0.416 [0.362, 0.467] (0.000 / 0.416) | +0.000 [+0.000, +0.000] | 0.000 / 0.000 | -0.384 [-0.410, -0.357] | -0.757 [-0.779, -0.729] | +0.861 / +0.416 |

Layer1 → original Juliet control (eval_n25; bad units identical, good = whole OMITBAD program):

| tool | macro-F1 layer1 | macro-F1 original | Δmacro-F1 [95% CI] | ΔF1_leak [95% CI] | spec layer1 → original | bad flip | good flip (r→w / w→r) |
|---|---|---|---|---|---|---|---|
| clang_sa | 0.828 | 0.800 | -0.028 [-0.039, -0.016] | -0.025 [-0.035, -0.015] | 0.931 → 0.873 | 0.000 | 0.057 (0.057 / 0.000) |
| codeql | 0.860 | 0.772 | -0.088 [-0.107, -0.069] | -0.062 [-0.075, -0.049] | 0.774 → 0.608 | 0.000 | 0.178 (0.172 / 0.006) |
| infer | 0.810 | 0.756 | -0.054 [-0.073, -0.035] | -0.047 [-0.064, -0.031] | 0.943 → 0.831 | 0.000 | 0.111 (0.111 / 0.000) |
| cppcheck | 0.481 | 0.462 | -0.019 [-0.036, -0.006] | -0.012 [-0.026, -0.003] | 0.982 → 0.928 | 0.000 | 0.054 (0.054 / 0.000) |
| grep_v0 | 0.717 | 0.930 | +0.213 [+0.183, +0.243] | +0.169 [+0.149, +0.187] | 0.584 → 1.000 | 0.000 | 0.416 (0.000 / 0.416) |

## Latency (layer1, latency300 subset, concurrency 1, no evidence export)

| tool | run | timing_mode | n | median (s) | p90 (s) | mean (s) | loadavg start → end |
|---|---|---|---|---|---|---|---|
| clang_sa | `lat300_c1` | per_unit_c1 | 300 | 0.018 | 0.022 | 0.024 | 1.99 2.26 4.37 → 1.99 2.25 4.35 |
| codeql | `lat300_per_unit20_c1` | per_unit_c1 | 20 | 7.357 | 7.909 | 7.496 | 2.68 2.41 4.16 → 4.02 3.02 4.12 |
| codeql | `lat300_batch50_c1` | batched | 300 | 0.318 | 0.334 | 0.310 | 4.02 3.02 4.12 → 4.95 3.41 4.14 |
| infer | `lat300_c1` | per_unit_c1 | 300 | 0.278 | 0.647 | 0.362 | 1.99 2.25 4.34 → 2.68 2.41 4.16 |
| cppcheck | `lat300_c1` | per_unit_c1 | 300 | 0.008 | 0.010 | 0.009 | 1.99 2.25 4.35 → 1.99 2.25 4.34 |
| grep_v0 | `lat300_c1` | per_unit_inprocess | 300 | 0.000 | 0.000 | 0.000 | 1.99 2.25 4.34 → 1.99 2.25 4.34 |

## Guard-pruning probes (scratch/make_guard_probes.py; one C function, calloc + guarded free)

pred bad / good (bad = free under an always-false guard, good = free under an always-true guard)

| guard form | clang_sa | codeql | infer | cppcheck | grep_v0 |
|---|---|---|---|---|---|
| none | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 |
| literal | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 | 0 / 0 |
| static_const | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 | 0 / 0 |
| enum | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 | 0 / 0 |
| static_nonconst | 1 / 1 | 1 / 0 | 1 / 1 | 1 / 0 | 0 / 0 |
| global_nonconst | 1 / 1 | 1 / 0 | 1 / 1 | 0 / 0 | 0 / 0 |
| callee_static_const | 1 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 |

