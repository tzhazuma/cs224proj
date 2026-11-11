# Hybrid evidence-guidance results

Generated 2026-11-11T19:37:44.747305+00:00.

Frozen test units: 140 ({'bad': 70, 'good': 70}).

## Per-run metrics

| Model | Method | Valid | Coverage | Acc (strict) | Precision | Recall | F1 | Balanced | List USD | Allowance USD | p95 s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | direct | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.020570 | 0.006171 | 6.09 |
| deepseek | static | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.023492 | 0.007048 | 6.27 |
| deepseek | dynamic | 140/140 | 100.00% | 99.29% | 98.59% | 100.00% | 0.9929 | 99.29% | 0.022894 | 0.006868 | 6.28 |
| deepseek | combined | 140/140 | 100.00% | 100.00% | 100.00% | 100.00% | 1.0000 | 100.00% | 0.029260 | 0.008778 | 15.65 |
| deepseek | shuffled | 140/140 | 100.00% | 96.43% | 93.33% | 100.00% | 0.9655 | 96.43% | 0.022316 | 0.006695 | 6.95 |
| mimo | direct | 140/140 | 100.00% | 96.43% | 94.52% | 98.57% | 0.9650 | 96.43% | 0.006470 | 0.006470 | 37.94 |
| mimo | static | 140/140 | 100.00% | 97.14% | 94.59% | 100.00% | 0.9722 | 97.14% | 0.014098 | 0.014099 | 6.25 |
| mimo | dynamic | 140/140 | 100.00% | 96.43% | 95.77% | 97.14% | 0.9645 | 96.43% | 0.013544 | 0.013544 | 8.02 |
| mimo | combined | 140/140 | 100.00% | 98.57% | 97.22% | 100.00% | 0.9859 | 98.57% | 0.011963 | 0.011963 | 7.95 |
| mimo | shuffled | 140/140 | 100.00% | 96.43% | 94.52% | 98.57% | 0.9650 | 96.43% | 0.009256 | 0.009256 | 7.14 |

## Paired comparisons (strict scoring, exact McNemar)

| Model | Baseline | Method | n | Acc base | Acc method | Diff | 95% CI | p |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: |
| deepseek | direct | static | 140 | 96.43% | 96.43% | +0.0000 | [+0.0000, +0.0000] | 1 |
| deepseek | direct | dynamic | 140 | 96.43% | 99.29% | +0.0286 | [+0.0071, +0.0571] | 0.125 |
| deepseek | direct | combined | 140 | 96.43% | 100.00% | +0.0357 | [+0.0071, +0.0714] | 0.0625 |
| deepseek | direct | shuffled | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| deepseek | static | direct | 140 | 96.43% | 96.43% | +0.0000 | [+0.0000, +0.0000] | 1 |
| deepseek | static | dynamic | 140 | 96.43% | 99.29% | +0.0286 | [+0.0071, +0.0571] | 0.125 |
| deepseek | static | combined | 140 | 96.43% | 100.00% | +0.0357 | [+0.0071, +0.0714] | 0.0625 |
| deepseek | static | shuffled | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| deepseek | dynamic | direct | 140 | 99.29% | 96.43% | -0.0286 | [-0.0571, -0.0071] | 0.125 |
| deepseek | dynamic | static | 140 | 99.29% | 96.43% | -0.0286 | [-0.0571, -0.0071] | 0.125 |
| deepseek | dynamic | combined | 140 | 99.29% | 100.00% | +0.0071 | [+0.0000, +0.0214] | 1 |
| deepseek | dynamic | shuffled | 140 | 99.29% | 96.43% | -0.0286 | [-0.0571, -0.0071] | 0.125 |
| deepseek | combined | direct | 140 | 100.00% | 96.43% | -0.0357 | [-0.0714, -0.0071] | 0.0625 |
| deepseek | combined | static | 140 | 100.00% | 96.43% | -0.0357 | [-0.0714, -0.0071] | 0.0625 |
| deepseek | combined | dynamic | 140 | 100.00% | 99.29% | -0.0071 | [-0.0214, +0.0000] | 1 |
| deepseek | combined | shuffled | 140 | 100.00% | 96.43% | -0.0357 | [-0.0714, -0.0071] | 0.0625 |
| deepseek | shuffled | direct | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| deepseek | shuffled | static | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| deepseek | shuffled | dynamic | 140 | 96.43% | 99.29% | +0.0286 | [+0.0071, +0.0571] | 0.125 |
| deepseek | shuffled | combined | 140 | 96.43% | 100.00% | +0.0357 | [+0.0071, +0.0714] | 0.0625 |
| mimo | direct | static | 140 | 96.43% | 97.14% | +0.0071 | [-0.0143, +0.0287] | 1 |
| mimo | direct | dynamic | 140 | 96.43% | 96.43% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | direct | combined | 140 | 96.43% | 98.57% | +0.0214 | [-0.0071, +0.0571] | 0.375 |
| mimo | direct | shuffled | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| mimo | static | direct | 140 | 97.14% | 96.43% | -0.0071 | [-0.0287, +0.0143] | 1 |
| mimo | static | dynamic | 140 | 97.14% | 96.43% | -0.0071 | [-0.0286, +0.0143] | 1 |
| mimo | static | combined | 140 | 97.14% | 98.57% | +0.0143 | [+0.0000, +0.0357] | 0.5 |
| mimo | static | shuffled | 140 | 97.14% | 96.43% | -0.0071 | [-0.0357, +0.0143] | 1 |
| mimo | dynamic | direct | 140 | 96.43% | 96.43% | +0.0000 | [-0.0214, +0.0214] | 1 |
| mimo | dynamic | static | 140 | 96.43% | 97.14% | +0.0071 | [-0.0143, +0.0286] | 1 |
| mimo | dynamic | combined | 140 | 96.43% | 98.57% | +0.0214 | [-0.0071, +0.0571] | 0.375 |
| mimo | dynamic | shuffled | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| mimo | combined | direct | 140 | 98.57% | 96.43% | -0.0214 | [-0.0571, +0.0071] | 0.375 |
| mimo | combined | static | 140 | 98.57% | 97.14% | -0.0143 | [-0.0357, +0.0000] | 0.5 |
| mimo | combined | dynamic | 140 | 98.57% | 96.43% | -0.0214 | [-0.0571, +0.0071] | 0.375 |
| mimo | combined | shuffled | 140 | 98.57% | 96.43% | -0.0214 | [-0.0500, +0.0000] | 0.25 |
| mimo | shuffled | direct | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| mimo | shuffled | static | 140 | 96.43% | 97.14% | +0.0071 | [-0.0143, +0.0357] | 1 |
| mimo | shuffled | dynamic | 140 | 96.43% | 96.43% | +0.0000 | [-0.0286, +0.0286] | 1 |
| mimo | shuffled | combined | 140 | 96.43% | 98.57% | +0.0214 | [+0.0000, +0.0500] | 0.25 |

## Tool evidence vs labels

- dynamic: accuracy 91.43%, precision 100.00%, recall 82.86%, specificity 100.00%.
- static_any: accuracy 85.00%, precision 92.98%, recall 75.71%, specificity 94.29%.

## Dynamic-evidence conditioned results

- deepseek/dynamic: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.16, acc=0.99
- deepseek/combined: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.15, acc=1.00
- mimo/dynamic: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.16, acc=0.94
- mimo/combined: leak: n=58, pred-vuln=1.00, acc=1.00; clean: n=82, pred-vuln=0.17, acc=0.98

## Placebo diagnostics

- deepseek/shuffled by donor label: donor_bad: n=70, acc=0.94; donor_good: n=70, acc=0.99
- mimo/shuffled by donor label: donor_bad: n=70, acc=0.94; donor_good: n=70, acc=0.99
