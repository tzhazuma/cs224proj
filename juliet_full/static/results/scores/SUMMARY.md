| tool | slice | n | macro-F1 [95% CI] | P_leak | R_leak | spec | MCC | acc | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | dev | 660 | 0.808 [0.754, 0.853] | 0.940 | 0.667 | 0.958 | 0.652 | 0.812 | 0 | 0.034 / 0.076 |
| codeql | dev | 660 | 0.918 [0.902, 0.933] | 0.871 | 0.982 | 0.855 | 0.843 | 0.918 | 0 | 0.549 / 0.616 |
| infer | dev | 660 | 0.784 [0.715, 0.843] | 0.924 | 0.630 | 0.948 | 0.611 | 0.789 | 0 | 0.375 / 0.638 |
| cppcheck | dev | 660 | 0.468 [0.414, 0.524] | 0.920 | 0.139 | 0.988 | 0.240 | 0.564 | 0 | 0.015 / 0.024 |
| grep_v0 | dev | 660 | 0.721 [0.689, 0.752] | 0.667 | 0.927 | 0.536 | 0.504 | 0.732 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | dev | 660 | clang-only right 34, codeql-only right 104 | chi2_continuity | p=4.26e-09 | Holm p=1.28e-08 | | | | |
|  McNemar clang_sa vs infer | dev | 660 | clang-only right 71, infer-only right 56 | chi2_continuity | p=0.214 | Holm p=0.214 | | | | |
|  McNemar clang_sa vs cppcheck | dev | 660 | clang-only right 174, cppcheck-only right 10 | chi2_continuity | p=2.91e-33 | Holm p=1.16e-32 | | | | |
|  McNemar clang_sa vs grep_v0 | dev | 660 | clang-only right 177, grep_v0-only right 124 | chi2_continuity | p=0.00272 | Holm p=0.00545 | | | | |
| clang_sa | eval | 2656 | 0.855 [0.806, 0.899] | 0.928 | 0.771 | 0.941 | 0.722 | 0.856 | 0 | 0.036 / 0.066 |
| codeql | eval | 2656 | 0.882 [0.866, 0.897] | 0.829 | 0.963 | 0.802 | 0.775 | 0.883 | 0 | 0.549 / 0.616 |
| infer | eval | 2656 | 0.815 [0.741, 0.874] | 0.939 | 0.681 | 0.956 | 0.662 | 0.818 | 0 | 0.293 / 0.669 |
| cppcheck | eval | 2656 | 0.493 [0.436, 0.553] | 0.897 | 0.171 | 0.980 | 0.258 | 0.576 | 0 | 0.015 / 0.024 |
| grep_v0 | eval | 2656 | 0.701 [0.685, 0.717] | 0.658 | 0.870 | 0.548 | 0.441 | 0.709 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | eval | 2656 | clang-only right 248, codeql-only right 319 | chi2_continuity | p=0.00329 | Holm p=0.00329 | | | | |
|  McNemar clang_sa vs infer | eval | 2656 | clang-only right 309, infer-only right 209 | chi2_continuity | p=1.36e-05 | Holm p=2.73e-05 | | | | |
|  McNemar clang_sa vs cppcheck | eval | 2656 | clang-only right 810, cppcheck-only right 66 | chi2_continuity | p=4.54e-139 | Holm p=1.82e-138 | | | | |
|  McNemar clang_sa vs grep_v0 | eval | 2656 | clang-only right 740, grep_v0-only right 350 | chi2_continuity | p=4.81e-32 | Holm p=1.44e-31 | | | | |
| clang_sa | eval_api | 1328 | 0.840 [0.784, 0.887] | 0.920 | 0.747 | 0.935 | 0.695 | 0.841 | 0 | 0.035 / 0.066 |
| codeql | eval_api | 1328 | 0.867 [0.844, 0.889] | 0.813 | 0.956 | 0.780 | 0.748 | 0.868 | 0 | 0.551 / 0.616 |
| infer | eval_api | 1328 | 0.811 [0.737, 0.875] | 0.932 | 0.679 | 0.950 | 0.654 | 0.815 | 0 | 0.292 / 0.678 |
| cppcheck | eval_api | 1328 | 0.488 [0.434, 0.548] | 0.894 | 0.166 | 0.980 | 0.252 | 0.573 | 0 | 0.015 / 0.025 |
| grep_v0 | eval_api | 1328 | 0.706 [0.685, 0.725] | 0.663 | 0.867 | 0.559 | 0.448 | 0.713 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | eval_api | 1328 | clang-only right 138, codeql-only right 174 | chi2_continuity | p=0.0475 | Holm p=0.0836 | | | | |
|  McNemar clang_sa vs infer | eval_api | 1328 | clang-only right 157, infer-only right 122 | chi2_continuity | p=0.0418 | Holm p=0.0836 | | | | |
|  McNemar clang_sa vs cppcheck | eval_api | 1328 | clang-only right 390, cppcheck-only right 34 | chi2_continuity | p=1.32e-66 | Holm p=5.29e-66 | | | | |
|  McNemar clang_sa vs grep_v0 | eval_api | 1328 | clang-only right 360, grep_v0-only right 190 | chi2_continuity | p=5.75e-13 | Holm p=1.73e-12 | | | | |
