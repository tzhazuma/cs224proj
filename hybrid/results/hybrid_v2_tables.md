# Hybrid evidence-guidance results

Generated 2026-11-11T20:55:58.167199+00:00.

Frozen test units: 140 ({'bad': 70, 'good': 70}).

## Per-run metrics

| Model | Method | Valid | Coverage | Acc (strict) | Precision | Recall | F1 | Balanced | List USD | Allowance USD | p95 s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | direct | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.010185 | 0.006111 | 2.15 |
| deepseek | static | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.011730 | 0.007038 | 2.07 |
| deepseek | dynamic | 140/140 | 100.00% | 97.14% | 94.59% | 100.00% | 0.9722 | 97.14% | 0.011471 | 0.006883 | 2.19 |
| deepseek | combined | 140/140 | 100.00% | 97.14% | 94.59% | 100.00% | 0.9722 | 97.14% | 0.011891 | 0.007134 | 2.25 |
| deepseek | shuffled | 140/140 | 100.00% | 95.71% | 92.11% | 100.00% | 0.9589 | 95.71% | 0.010860 | 0.006516 | 2.50 |
| mimo | direct | 140/140 | 100.00% | 97.14% | 94.59% | 100.00% | 0.9722 | 97.14% | 0.004718 | 0.004718 | 7.62 |
| mimo | static | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.006287 | 0.006287 | 8.90 |
| mimo | dynamic | 140/140 | 100.00% | 95.00% | 93.15% | 97.14% | 0.9510 | 95.00% | 0.005735 | 0.005735 | 13.39 |
| mimo | combined | 140/140 | 100.00% | 97.14% | 94.59% | 100.00% | 0.9722 | 97.14% | 0.004813 | 0.004813 | 8.09 |
| mimo | shuffled | 140/140 | 100.00% | 95.00% | 92.00% | 98.57% | 0.9517 | 95.00% | 0.004645 | 0.004645 | 6.53 |

## Paired comparisons (strict scoring, exact McNemar)

| Model | Baseline | Method | n | Acc base | Acc method | Diff | 95% CI | p |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: |
| deepseek | direct | static | 140 | 96.43% | 96.43% | +0.0000 | [+0.0000, +0.0000] | 1 |
| deepseek | direct | dynamic | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | direct | combined | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | direct | shuffled | 140 | 96.43% | 95.71% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | static | direct | 140 | 96.43% | 96.43% | +0.0000 | [+0.0000, +0.0000] | 1 |
| deepseek | static | dynamic | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | static | combined | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | static | shuffled | 140 | 96.43% | 95.71% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | dynamic | direct | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | dynamic | static | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | dynamic | combined | 140 | 97.14% | 97.14% | +0.0000 | [-0.0214, +0.0214] | 1 |
| deepseek | dynamic | shuffled | 140 | 97.14% | 95.71% | -0.0143 | [-0.0357, +0.0000] | 0.5 |
| deepseek | combined | direct | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | combined | static | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | combined | dynamic | 140 | 97.14% | 97.14% | +0.0000 | [-0.0214, +0.0214] | 1 |
| deepseek | combined | shuffled | 140 | 97.14% | 95.71% | -0.0143 | [-0.0357, +0.0000] | 0.5 |
| deepseek | shuffled | direct | 140 | 95.71% | 96.43% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | shuffled | static | 140 | 95.71% | 96.43% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | shuffled | dynamic | 140 | 95.71% | 97.14% | +0.0143 | [+0.0000, +0.0357] | 0.5 |
| deepseek | shuffled | combined | 140 | 95.71% | 97.14% | +0.0143 | [+0.0000, +0.0357] | 0.5 |
| mimo | direct | static | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| mimo | direct | dynamic | 140 | 97.14% | 95.00% | -0.0214 | [-0.0500, +0.0000] | 0.25 |
| mimo | direct | combined | 140 | 97.14% | 97.14% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | direct | shuffled | 140 | 97.14% | 95.00% | -0.0214 | [-0.0500, +0.0000] | 0.25 |
| mimo | static | direct | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| mimo | static | dynamic | 140 | 96.43% | 95.00% | -0.0143 | [-0.0357, +0.0000] | 0.5 |
| mimo | static | combined | 140 | 96.43% | 97.14% | +0.0071 | [+0.0000, +0.0214] | 1 |
| mimo | static | shuffled | 140 | 96.43% | 95.00% | -0.0143 | [-0.0357, +0.0000] | 0.5 |
| mimo | dynamic | direct | 140 | 95.00% | 97.14% | +0.0214 | [+0.0000, +0.0500] | 0.25 |
| mimo | dynamic | static | 140 | 95.00% | 96.43% | +0.0143 | [+0.0000, +0.0357] | 0.5 |
| mimo | dynamic | combined | 140 | 95.00% | 97.14% | +0.0214 | [+0.0000, +0.0500] | 0.25 |
| mimo | dynamic | shuffled | 140 | 95.00% | 95.00% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | combined | direct | 140 | 97.14% | 97.14% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | combined | static | 140 | 97.14% | 96.43% | -0.0071 | [-0.0214, +0.0000] | 1 |
| mimo | combined | dynamic | 140 | 97.14% | 95.00% | -0.0214 | [-0.0500, +0.0000] | 0.25 |
| mimo | combined | shuffled | 140 | 97.14% | 95.00% | -0.0214 | [-0.0500, +0.0000] | 0.25 |
| mimo | shuffled | direct | 140 | 95.00% | 97.14% | +0.0214 | [+0.0000, +0.0500] | 0.25 |
| mimo | shuffled | static | 140 | 95.00% | 96.43% | +0.0143 | [+0.0000, +0.0357] | 0.5 |
| mimo | shuffled | dynamic | 140 | 95.00% | 95.00% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | shuffled | combined | 140 | 95.00% | 97.14% | +0.0214 | [+0.0000, +0.0500] | 0.25 |

## Tool evidence vs labels

- dynamic: accuracy 91.43%, precision 100.00%, recall 82.86%, specificity 100.00%.
- static_any: accuracy 85.00%, precision 92.98%, recall 75.71%, specificity 94.29%.

## Dynamic-evidence conditioned results

- deepseek/dynamic: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.20, acc=0.95
- deepseek/combined: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.20, acc=0.95
- mimo/dynamic: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.18, acc=0.91
- mimo/combined: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.20, acc=0.95

## Placebo diagnostics

- deepseek/shuffled by donor label: donor_bad: n=70, acc=0.96; donor_good: n=70, acc=0.96
- mimo/shuffled by donor label: donor_bad: n=70, acc=0.94; donor_good: n=70, acc=0.96
