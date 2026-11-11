# Hybrid v2: leak-fixed rerun (Juliet CWE-401, 140 test units)

Generated 2026-11-11T21:04:42.875260+00:00.

## 1. What changed and what did not

v1 is frozen and untouched. The release audit (C3/D6) found the literal
`"Benign, fixed string"` in six good units; the shared `juliet_llm` cleaner now
neutralizes `benign`/`fixed` like the other label tokens. The v2 rerun uses a
separate input pack, a new prompt version, and new run directories.

| Item | v1 | v2 |
| --- | --- | --- |
| Prompt version | `hybrid-juliet-llm-binary-2026-11-12.1` | `hybrid-v2-juliet-llm-binary-2026-11-12.2` |
| Input pack | `hybrid/inputs/units.jsonl` | `hybrid/inputs_v2/units.jsonl` |
| Input SHA-256 | `f01db633e971b334075faa570418bf86b182046b6c8d47d75508559cb9d73e83` | `1ec51f5744a1b0c6da329b716a868f5992afec17178311c4c83010f07b6457d6` |
| Runs | `hybrid/runs/hybrid_v1_*` | `hybrid/runs/hybrid_v2_*` |
| Frozen units / evidence / placebo seed | 140 / same / 20261112 | 140 / same / 20261112 |

Only 6/140 source views differ, and in each one the only changed line is:

```diff
-        printLine("Benign, fixed string");
+        printLine("unit, unit string");
```

Changed units: `CWE401_Memory_Leak__int_malloc_22__good`, `CWE401_Memory_Leak__malloc_realloc_int64_t_09__good`, `CWE401_Memory_Leak__new_array_char_22__good`, `CWE401_Memory_Leak__new_array_int_22__good`, `CWE401_Memory_Leak__new_int_22__good`, `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good`.

## 2. Preflight gate and prompt audit

- Gate result: **PASS**; 140 units, 700 prompts rebuilt, 0 failures, 14 warnings.
- Label words in the 140 cleaned sources: 0.
- Direct prompts vs `juliet_llm/build`: matched (140/140 checked, 0 mismatches).
- Placebo: seed 20261112, 140 pairs, 0 constraint violations, 14 no-op collisions (same set as v1: True).
- Prompt audit: 140 units x 5 methods, direct=140 unique, static=140 unique, dynamic=140 unique, combined=140 unique, shuffled=140 unique.

The 14 no-op collisions are retained as a documented placebo limitation, not
as an integrity failure: for those units the donor's evidence text is identical
to the unit's own evidence, so the placebo cannot change the prompt.

## 3. Completeness

| Run | Records | Valid | Status counts | Prompt version |
| --- | ---: | ---: | --- | --- |
| `hybrid_v2_deepseek_direct` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_deepseek_static` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_deepseek_dynamic` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_deepseek_combined` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_deepseek_shuffled` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_mimo_direct` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_mimo_static` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_mimo_dynamic` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_mimo_combined` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |
| `hybrid_v2_mimo_shuffled` | 140 | 140 | ok=140 | hybrid-v2-juliet-llm-binary-2026-11-12.2 |

All 10 runs are 140/140 with 0 invalid and 0 API errors; the matrix is 1400 real requests.

## 4. Headline results

| Model | Method | v1 acc | v2 acc | Δ (v2−v1) | 95% CI | v1 right → v2 wrong | v1 wrong → v2 right | McNemar p |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| deepseek | direct | 96.43% | 96.43% | +0.00 pp | [+0.00, +0.00] pp | 0 | 0 | 1 |
| deepseek | static | 96.43% | 96.43% | +0.00 pp | [+0.00, +0.00] pp | 0 | 0 | 1 |
| deepseek | dynamic | 99.29% | 97.14% | -2.14 pp | [-5.00, +0.00] pp | 3 | 0 | 0.25 |
| deepseek | combined | 100.00% | 97.14% | -2.86 pp | [-5.71, -0.71] pp | 4 | 0 | 0.125 |
| deepseek | shuffled | 96.43% | 95.71% | -0.71 pp | [-3.57, +1.43] pp | 2 | 1 | 1 |
| mimo | direct | 96.43% | 97.14% | +0.71 pp | [+0.00, +2.14] pp | 0 | 1 | 1 |
| mimo | static | 97.14% | 96.43% | -0.71 pp | [-2.14, +0.00] pp | 1 | 0 | 1 |
| mimo | dynamic | 96.43% | 95.00% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |
| mimo | combined | 98.57% | 97.14% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |
| mimo | shuffled | 96.43% | 95.00% | -1.43 pp | [-3.57, +0.00] pp | 2 | 0 | 0.5 |

Pooled descriptive accuracy (5 runs per model; 10 for all):

| Model | v1 acc | v2 acc | Δ |
| --- | ---: | ---: | ---: |
| deepseek | 97.71% | 96.57% | -1.14 pp |
| mimo | 97.00% | 96.14% | -0.86 pp |
| all | 97.36% | 96.36% | -1.00 pp |

Reading: the largest movement is deepseek/combined (100.00% → 97.14%, -2.86 pp, 4 discordant pairs, exact McNemar p=0.125). The direction is consistent with removing a good-unit shortcut, but with 4 discordant pairs the exact test does not reach 0.05; this is suggestive, not confirmatory. No other cell moves by more than 2.14 pp.

## 5. Attribution of prediction changes

| Group | Label changes | v1 right → v2 wrong | v1 wrong → v2 right |
| --- | ---: | ---: | ---: |
| Six cleaned units | 17 | 16 | 1 |
| 134 unchanged units | 1 | 0 | 1 |

Every prediction flip on a cleaned unit:

| Model | Method | Unit | Label | v1 | v2 | v1 correct | v2 correct |
| --- | --- | --- | --- | --- | --- | --- | --- |
| deepseek | dynamic | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | dynamic | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | dynamic | `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | combined | `CWE401_Memory_Leak__int_malloc_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | combined | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | combined | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | combined | `CWE401_Memory_Leak__new_int_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | shuffled | `CWE401_Memory_Leak__malloc_realloc_int64_t_09__good` | good | vulnerable | not_vulnerable | no | yes |
| deepseek | shuffled | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no |
| deepseek | shuffled | `CWE401_Memory_Leak__twoIntsStruct_realloc_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | static | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | dynamic | `CWE401_Memory_Leak__int_malloc_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | dynamic | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | combined | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | combined | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | shuffled | `CWE401_Memory_Leak__new_array_char_22__good` | good | not_vulnerable | vulnerable | yes | no |
| mimo | shuffled | `CWE401_Memory_Leak__new_array_int_22__good` | good | not_vulnerable | vulnerable | yes | no |

Flips on unchanged units are endpoint/rerun variation, not a cleaning effect:

| Model | Method | Unit | Label | v1 | v2 |
| --- | --- | --- | --- | --- | --- |
| mimo | direct | `CWE401_Memory_Leak__malloc_realloc_int_01__bad` | bad | not_vulnerable | vulnerable |

## 6. Tool evidence and placebo diagnostics

Tool baselines are computed from the frozen evidence and are unchanged by the
source fix: dynamic accuracy 91.43%, recall 82.86%, specificity 100.00%; static_any accuracy 85.00%, recall 75.71%, specificity 94.29%.

| Model | Method | Evidence group | n | Accuracy | Predicted vulnerable |
| --- | --- | --- | ---: | ---: | ---: |
| deepseek | dynamic | leak | 58 | 100.00% | 100.00% |
| deepseek | dynamic | clean | 82 | 95.12% | 19.51% |
| mimo | dynamic | leak | 58 | 100.00% | 100.00% |
| mimo | dynamic | clean | 82 | 91.46% | 18.29% |
| deepseek | combined | leak | 58 | 100.00% | 100.00% |
| deepseek | combined | clean | 82 | 95.12% | 19.51% |
| mimo | combined | leak | 58 | 100.00% | 100.00% |
| mimo | combined | clean | 82 | 95.12% | 19.51% |

| Model | Donor label | n | Accuracy |
| --- | --- | ---: | ---: |
| deepseek | donor_bad | 70 | 95.71% |
| deepseek | donor_good | 70 | 95.71% |
| mimo | donor_bad | 70 | 94.29% |
| mimo | donor_good | 70 | 95.71% |

## 7. Usage and cost

| Model | Prompt tokens | Completion tokens | List USD (v2 basis) | Provider allowance USD |
| --- | ---: | ---: | ---: | ---: |
| deepseek | 511212 | 35692 | 0.056137 | 0.033682 |
| mimo | 506425 | 33309 | 0.026198 | 0.026197 |

DeepSeek v1 rows were priced at the old 2× list price; v2 uses the provider
snapshot ($0.15/$0.60 per 1M). Provider allowance is the comparable figure.
MiMo v2 rows also show substantially more prompt-cache reads than v1 (e.g.
72,512 vs 15,616 cached tokens in the static run), so its list cost drops
without a workload change.

The configured prices reproduce the provider's own `list_cost` in 10/10 runs (ratio range 1.0000–1.0001, tolerance 2%).

## 8. Artifact audit

- `hybrid/verify_outputs.py`: **PASS**, 0 failures.
- Prompt version on every run: `hybrid-v2-juliet-llm-binary-2026-11-12.2`.
- Provenance: cleaning.py `8b10aa6ef6bc7d443eb98e4bc9f1d37349d6baad9c6129854344c1875156ef8b`, prompting.py `2fe5f8184a17fc2f9656fb8b55843499aa41e516e2e69e6b031a41b14ff80384`.
- Inputs: `hybrid/inputs_v2/units.jsonl` sha256 `1ec51f5744a1b0c6da329b716a868f5992afec17178311c4c83010f07b6457d6`.
- Placebo no-op collisions: 14.
- Cost basis: 10/10 runs match the provider `list_cost` within 2% (range 1.0000–1.0001).

## 9. Limits

- Juliet units are small, synthetic, single-defect programs; the result is not a
  production-code estimate.
- The cleaned units still share Juliet's structural asymmetry (bad units are
  shorter than good units on average); this fix removes a word-level shortcut,
  not every distributional difference.
- The placebo cannot change the prompt for the 14 no-op units; those units are
  analysed but cannot support a causal placebo claim.
- v2 is a single rerun per cell. Flips on unchanged units show that endpoint
  nondeterminism remains, so small per-cell deltas should not be over-read; the
  paired McNemar tests and CIs are reported for that reason.
- No model API key is printed, stored in a result, or written to a report.

