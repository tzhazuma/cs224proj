## intern_decision_L2_th2: robustness (2656 units, 42 families)

| layer | macro-F1 | F1_leak | recall | specificity | invalid |
|---|---|---|---|---|---|
| base | 0.859 [0.836, 0.879] | 0.864 [0.837, 0.886] | 0.895 | 0.824 | 0 |
| stress | 0.625 [0.599, 0.651] | 0.709 [0.689, 0.726] | 0.867 | 0.421 | 0 |

| comparison | Δmacro-F1 | ΔF1_leak | bad flip | bad right→wrong | good flip | good right→wrong |
|---|---|---|---|---|---|---|
| stress | -0.234 [-0.251, -0.215] | -0.155 [-0.171, -0.137] | 0.183 [0.146, 0.227] | 0.105 [0.088, 0.122] | 0.422 [0.385, 0.465] | 0.413 [0.375, 0.455] |
