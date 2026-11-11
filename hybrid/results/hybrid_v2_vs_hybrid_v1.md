# Hybrid v1 vs v2 (leak-fixed sources)

Generated 2026-11-11T21:04:31.837641+00:00.

- v1 input pack: `hybrid/inputs`  
  sha256 `f01db633e971b334075faa570418bf86b182046b6c8d47d75508559cb9d73e83`
- v2 input pack: `hybrid/inputs_v2`  
  sha256 `1ec51f5744a1b0c6da329b716a868f5992afec17178311c4c83010f07b6457d6`
- Source views changed in 6/140 units: `CWE401_Memory_Leak__int_malloc_22__good`, `CWE401_Memory_Leak__malloc_realloc_int64_t_09__good`, `CWE401_Memory_Leak__new_array_char_22__good`, `CWE401_Memory_Leak__new_array_int_22__good`, `CWE401_Memory_Leak__new_int_22__good`, `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good`

## Per-run accuracy

| Model | Method | n | v1 acc | v2 acc | Δ (v2−v1) | 95% CI | v1 right / v2 wrong | v1 wrong / v2 right | McNemar p |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| deepseek | direct | 140 | 96.43% | 96.43% | +0.00 pp | [+0.00, +0.00] pp | 0 | 0 | 1 |
| deepseek | static | 140 | 96.43% | 96.43% | +0.00 pp | [+0.00, +0.00] pp | 0 | 0 | 1 |
| deepseek | dynamic | 140 | 99.29% | 97.14% | -2.14 pp | [-5.00, +0.00] pp | 3 | 0 | 0.25 |
| deepseek | combined | 140 | 100.00% | 97.14% | -2.86 pp | [-5.71, -0.71] pp | 4 | 0 | 0.125 |
| deepseek | shuffled | 140 | 96.43% | 95.71% | -0.71 pp | [-3.57, +1.43] pp | 2 | 1 | 1 |
| mimo | direct | 140 | 96.43% | 97.14% | +0.71 pp | [+0.00, +2.14] pp | 0 | 1 | 1 |
| mimo | static | 140 | 97.14% | 96.43% | -0.71 pp | [-2.14, +0.00] pp | 1 | 0 | 1 |
| mimo | dynamic | 140 | 96.43% | 95.00% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |
| mimo | combined | 140 | 98.57% | 97.14% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |
| mimo | shuffled | 140 | 96.43% | 95.00% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |

## Pooled descriptive accuracy

| Model | Runs | v1 acc | v2 acc | Δ |
| --- | ---: | ---: | ---: | ---: |
| deepseek | 5 | 97.71% | 96.57% | -1.14 pp |
| mimo | 5 | 97.00% | 96.14% | -0.86 pp |
| all | 10 | 97.36% | 96.36% | -1.00 pp |

## Prediction flips

- v1 right → v2 wrong: 16
- v1 wrong → v2 right: 2

| Model | Method | Unit | Label | v1 | v2 | v1 correct | v2 correct | Source changed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| deepseek | combined | `CWE401_Memory_Leak__int_malloc_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | combined | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | combined | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | combined | `CWE401_Memory_Leak__new_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | dynamic | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | dynamic | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | dynamic | `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | shuffled | `CWE401_Memory_Leak__malloc_realloc_int64_t_09__good` | good | vulnerable | not_vulnerable | no | yes | yes |
| deepseek | shuffled | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| deepseek | shuffled | `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | combined | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | combined | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | direct | `CWE401_Memory_Leak__malloc_realloc_int_01__bad` | bad | not_vulnerable | vulnerable | no | yes | no |
| mimo | dynamic | `CWE401_Memory_Leak__int_malloc_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | dynamic | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | shuffled | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | shuffled | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |
| mimo | static | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no | yes |

## Usage and cost

| Model | Method | v1 tokens (in/out) | v2 tokens (in/out) | v1 list USD | v2 list USD | v1 allowance USD | v2 allowance USD |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| deepseek | direct | 78097/6837 | 78091/6892 | 0.020570 | 0.010185 | 0.006171 | 0.006111 |
| deepseek | static | 103764/6964 | 103758/7064 | 0.023492 | 0.011730 | 0.007048 | 0.007038 |
| deepseek | dynamic | 98189/7138 | 98183/7211 | 0.022894 | 0.011471 | 0.006868 | 0.006883 |
| deepseek | combined | 115596/7182 | 115590/7228 | 0.029260 | 0.011891 | 0.008778 | 0.007134 |
| deepseek | shuffled | 115596/7228 | 115590/7297 | 0.022316 | 0.010860 | 0.006695 | 0.006516 |
| mimo | direct | 77416/6477 | 77410/6557 | 0.006470 | 0.004718 | 0.006470 | 0.004718 |
| mimo | static | 102773/6617 | 102767/6601 | 0.014098 | 0.006287 | 0.014099 | 0.006287 |
| mimo | dynamic | 97264/6639 | 97258/6631 | 0.013544 | 0.005735 | 0.013544 | 0.005735 |
| mimo | combined | 114501/6675 | 114495/6700 | 0.011963 | 0.004813 | 0.011963 | 0.004813 |
| mimo | shuffled | 114501/6727 | 114495/6820 | 0.009256 | 0.004645 | 0.009256 | 0.004645 |

DeepSeek v1 rows were priced at the old 2× list price ($0.30/$1.20); v2 uses the
provider snapshot ($0.15/$0.60), so DeepSeek list-cost movement is not a workload change.
Provider allowance is unaffected by the configured list price and is the comparable figure.
MiMo v2 rows also show substantially more prompt-cache reads than v1 (e.g. 72,512 vs
15,616 cached tokens in the static run), so its list cost drops without a workload change.

