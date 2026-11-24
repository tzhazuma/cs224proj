## intern_decision_L2_th05: robustness (2656 units, 42 families)

| layer | macro-F1 | F1_leak | recall | specificity | invalid |
|---|---|---|---|---|---|
| base | 0.844 [0.831, 0.857] | 0.861 [0.849, 0.873] | 0.959 | 0.732 | 0 |
| stress | 0.500 [0.475, 0.527] | 0.703 [0.696, 0.712] | 0.989 | 0.176 | 0 |

| comparison | Δmacro-F1 | ΔF1_leak | bad flip | bad right→wrong | good flip | good right→wrong |
|---|---|---|---|---|---|---|
| stress | -0.343 [-0.369, -0.318] | -0.158 [-0.170, -0.146] | 0.051 [0.030, 0.080] | 0.011 [0.006, 0.016] | 0.560 [0.522, 0.600] | 0.558 [0.520, 0.597] |
