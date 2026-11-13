# Tables

Generated 2026-11-13T17:21:03.214375+00:00.

## deepseek

| method | TP/FP/FN/TN | accuracy | 95% CI | USD |
| --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 70/3/0/67 | 97.86% | [93.89, 99.27] pp | $0.011165 |
| v2 direct | 70/5/0/65 | 96.43% | [91.91, 98.47] pp | $0.010185 |
| v2 dynamic (old evidence) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.011471 |
| v2 combined (old static+dynamic) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.011891 |
| dynamic-enhanced tool | 70/0/0/70 | 100.00% | [97.33, 100.00] pp | $0.000000 |

| contrast | Δ | discordant | 95% CI | exact p | Holm p |
| --- | --- | --- | --- | --- | --- |
| hde vs v2-direct | +1.43 pp | 2/0 | [0.00, 3.57] pp | 0.5000 | 1.0000 |
| hde vs v2-dynamic | +0.71 pp | 1/0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| hde vs v2-combined | +0.71 pp | 1/0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| hde vs tool | -2.14 pp | 0/3 | [-5.00, 0.00] pp | 0.2500 | 1.0000 |

## mimo

| method | TP/FP/FN/TN | accuracy | 95% CI | USD |
| --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.012395 |
| v2 direct | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.004718 |
| v2 dynamic (old evidence) | 68/5/2/65 | 95.00% | [90.04, 97.56] pp | $0.005735 |
| v2 combined (old static+dynamic) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.004813 |
| dynamic-enhanced tool | 70/0/0/70 | 100.00% | [97.33, 100.00] pp | $0.000000 |

| contrast | Δ | discordant | 95% CI | exact p | Holm p |
| --- | --- | --- | --- | --- | --- |
| hde vs v2-direct | +0.00 pp | 0/0 | [0.00, 0.00] pp | 1.0000 | 1.0000 |
| hde vs v2-dynamic | +2.14 pp | 3/0 | [0.00, 5.00] pp | 0.2500 | 0.7500 |
| hde vs v2-combined | +0.00 pp | 1/1 | [-2.14, 2.14] pp | 1.0000 | 1.0000 |
| hde vs tool | -2.86 pp | 0/4 | [-5.71, -0.71] pp | 0.1250 | 0.5000 |

