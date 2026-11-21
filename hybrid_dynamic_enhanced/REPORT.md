# Enhanced dynamic guidance on the frozen Juliet CWE-401 test 140

Generated 2026-11-13T17:21:03.214375+00:00 · run `enhanced_dynamic_v1` · method `enhanced-dynamic-guided`.

## 0. Headline

- The dynamic-enhanced tool is **70 TP / 0 FP / 70 TN / 0 FN** on these 140 units, i.e. accuracy **100.00%**.
- DeepSeek: direct 96.43% (135/140) → enhanced **97.86% (137/140)**; McNemar vs direct p=0.5000, Holm p=1.0000.
- MiMo: direct 97.14% (136/140) → enhanced **97.14% (136/140)**; McNemar vs direct p=1.0000, Holm p=1.0000.
- Neither model reaches the tool ceiling (140/140). The new spend is **$0.023561** for 280 real requests (2 × 140, 0 invalid, 0 API errors).
- The verdict changes that do occur are small; the DeepSeek changes move toward the evidence verdict, but none is statistically distinguishable from the frozen baseline. **No semantic-reasoning improvement is claimed.**

## 1. Protocol and preflight

| item | value |
| --- | --- |
| units | 140 (70 bad / 70 good) |
| requests | 2 × 140 (one per model and unit); 0 invalid, 0 API errors |
| input pack SHA-256 | `061546a40e5dd66d7a1fca2dd23dd1ec250d4705a48651dca1eb757488976dce` |
| guided prompt version | `hde-juliet-llm-binary-2026-11-14.1` |
| direct prompt version (reused) | `hybrid-v2-juliet-llm-binary-2026-11-12.2` |
| prompt audit | 140 enhanced prompts unique; 140 direct prompts byte-identical to v2 |
| tool | default + realloc_fail + nogobal; Valgrind not re-run |
| baselines | frozen hybrid_v2 runs (2026-11-11), not re-requested |
| preflight | 13/13 checks passed, ok=True |

Evidence sent to the model is rendered only from numeric fields of `dynamic_enhanced/exports/hybrid`: per-mode applicability, attribution bytes, allocation-record count and the injected-call index. Paths, file names, unit ids, CWE ids, and label words are never copied; every block is scanned fail-closed. The evidence wrapper and system prompt are byte-identical to hybrid v2, so the only prompt difference is the evidence body.

## 2. Accuracy, cost and paired tests

### 2.1 deepseek

| method | TP/FP/FN/TN | accuracy | 95% CI | configured USD |
| --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 70/3/0/67 | 97.86% | [93.89, 99.27] pp | $0.011165 |
| v2 direct | 70/5/0/65 | 96.43% | [91.91, 98.47] pp | $0.010185 |
| v2 dynamic (old evidence) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.011471 |
| v2 combined (old static+dynamic) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.011891 |
| dynamic-enhanced tool | 70/0/0/70 | 100.00% | [97.33, 100.00] pp | $0.000000 |

| contrast | Δ accuracy | discordant (new / baseline) | bootstrap 95% CI | exact p | Holm p |
| --- | --- | --- | --- | --- | --- |
| hde vs v2 direct | +1.43 pp | 2 / 0 | [0.00, 3.57] pp | 0.5000 | 1.0000 |
| hde vs v2 dynamic (old evidence) | +0.71 pp | 1 / 0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| hde vs v2 combined (old static+dynamic) | +0.71 pp | 1 / 0 | [0.00, 2.14] pp | 1.0000 | 1.0000 |
| hde vs dynamic-enhanced tool | -2.14 pp | 0 / 3 | [-5.00, 0.00] pp | 0.2500 | 1.0000 |

Exact McNemar over all 140 planned units; invalid requests would be counted as wrong (there were none). Holm adjusts the four contrasts within each model.

### 2.2 mimo

| method | TP/FP/FN/TN | accuracy | 95% CI | configured USD |
| --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.012395 |
| v2 direct | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.004718 |
| v2 dynamic (old evidence) | 68/5/2/65 | 95.00% | [90.04, 97.56] pp | $0.005735 |
| v2 combined (old static+dynamic) | 70/4/0/66 | 97.14% | [92.88, 98.88] pp | $0.004813 |
| dynamic-enhanced tool | 70/0/0/70 | 100.00% | [97.33, 100.00] pp | $0.000000 |

| contrast | Δ accuracy | discordant (new / baseline) | bootstrap 95% CI | exact p | Holm p |
| --- | --- | --- | --- | --- | --- |
| hde vs v2 direct | +0.00 pp | 0 / 0 | [0.00, 0.00] pp | 1.0000 | 1.0000 |
| hde vs v2 dynamic (old evidence) | +2.14 pp | 3 / 0 | [0.00, 5.00] pp | 0.2500 | 0.7500 |
| hde vs v2 combined (old static+dynamic) | +0.00 pp | 1 / 1 | [-2.14, 2.14] pp | 1.0000 | 1.0000 |
| hde vs dynamic-enhanced tool | -2.86 pp | 0 / 4 | [-5.71, -0.71] pp | 0.1250 | 0.5000 |

Exact McNemar over all 140 planned units; invalid requests would be counted as wrong (there were none). Holm adjusts the four contrasts within each model.

### 2.3 Where the predictions changed

**deepseek**

| baseline | fixed | broken | units fixed | units broken |
| --- | --- | --- | --- | --- |
| v2 direct | 2 | 0 | `int_malloc_22__good`, `twoIntsStruct_realloc_22__good` | — |
| v2 dynamic | 1 | 0 | `twoIntsStruct_realloc_22__good` | — |
| v2 combined | 1 | 0 | `int_malloc_22__good` | — |
| dynamic-enhanced tool | 0 | 3 | — | `new_array_char_22__good`, `new_array_int_22__good`, `new_int_22__good` |

**mimo**

| baseline | fixed | broken | units fixed | units broken |
| --- | --- | --- | --- | --- |
| v2 direct | 0 | 0 | — | — |
| v2 dynamic | 3 | 0 | `int_malloc_22__good`, `malloc_realloc_int_01__bad`, `malloc_realloc_int_18__bad` | — |
| v2 combined | 1 | 1 | `int_malloc_22__good` | `new_int_22__good` |
| dynamic-enhanced tool | 0 | 4 | — | `new_array_char_22__good`, `new_array_int_22__good`, `new_int_22__good`, `twoIntsStruct_realloc_22__good` |

### 2.4 Subsets that matter

**deepseek**

| subset | n | v2 direct | v2 dynamic | v2 combined | hde guided | tool |
| --- | --- | --- | --- | --- | --- | --- |
| 12 units the old dynamic run could not observe | 12 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| 58 units with old dynamic leak evidence | 58 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| 6 cleaned `_22` good units | 6 | 16.67% | 33.33% | 33.33% | 50.00% | 100.00% |
| units v2 direct got wrong | 5 | 0.00% | 20.00% | 20.00% | 40.00% | 100.00% |

**mimo**

| subset | n | v2 direct | v2 dynamic | v2 combined | hde guided | tool |
| --- | --- | --- | --- | --- | --- | --- |
| 12 units the old dynamic run could not observe | 12 | 100.00% | 83.33% | 100.00% | 100.00% | 100.00% |
| 58 units with old dynamic leak evidence | 58 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| 6 cleaned `_22` good units | 6 | 33.33% | 16.67% | 33.33% | 33.33% | 100.00% |
| units v2 direct got wrong | 4 | 0.00% | 0.00% | 25.00% | 0.00% | 100.00% |

The 12 units the old harness could not observe were already detected by both models from the code alone (`direct` 12/12). The enhanced tool's new observations therefore add no headroom on those units; the remaining tool–model gap is on good units where the models over-call, plus the two realloc/global units MiMo misses under the old dynamic evidence.

## 3. Did the model simply copy the evidence?

The tool is 140/140, so *agreement with the tool* and *accuracy* are the same number here. A model that copied the evidence would score 140/140; a model that ignored it would score like `direct`. Neither happened.

**deepseek**

| signal | enhanced | comparison |
| --- | --- | --- |
| verdict agreement with tool | 97.86% | 3 over-calls, 0 under-calls |
| reasons citing evidence/tool language | 9.29% | direct 0.00% |
| reasons repeating the attributed byte count | 92.86% | direct 11.43%, dynamic 77.14% |
| reasons citing evidence phrasing (`attributed`, `configuration`, …) | 0.00% | 0% in every baseline |
| reasons on clean units citing evidence/tool | 0.00% | direct 0.00% |
| 12 old-hidden units: reason cites realloc / global | 58.33% / 41.67% | direct 58.33% / 41.67% (identical) |
| reasons lexically consistent with their own verdict | 38 consistent / 0 contradictory / 102 unclear | lexical check only |

Units where the model still over-calls against clean evidence:

`new_array_char_22__good`, `new_array_int_22__good`, `new_int_22__good`

Reading: the evidence text is clearly read and quoted — attributed byte counts appear in 89–93% of reasons, versus 11–23% for `direct` — but the verdict does not follow the evidence on all units, and on the 12 units the old harness could not observe the explanations are identical to `direct` (same realloc/global citation rates).

**mimo**

| signal | enhanced | comparison |
| --- | --- | --- |
| verdict agreement with tool | 97.14% | 4 over-calls, 0 under-calls |
| reasons citing evidence/tool language | 2.86% | direct 0.00% |
| reasons repeating the attributed byte count | 88.57% | direct 22.86%, dynamic 67.14% |
| reasons citing evidence phrasing (`attributed`, `configuration`, …) | 1.43% | 0% in every baseline |
| reasons on clean units citing evidence/tool | 0.00% | direct 0.00% |
| 12 old-hidden units: reason cites realloc / global | 58.33% / 41.67% | direct 58.33% / 41.67% (identical) |
| reasons lexically consistent with their own verdict | 46 consistent / 2 contradictory / 92 unclear | lexical check only |

Units where the model still over-calls against clean evidence:

`new_array_char_22__good`, `new_array_int_22__good`, `new_int_22__good`, `twoIntsStruct_realloc_22__good`

Reading: the evidence text is clearly read and quoted — attributed byte counts appear in 89–93% of reasons, versus 11–23% for `direct` — but the verdict does not follow the evidence on all units, and on the 12 units the old harness could not observe the explanations are identical to `direct` (same realloc/global citation rates).

The byte-count echo is the strongest copy signal available, but it is lexical: it shows the model repeats an evidence value, not that it reasons from it. Because the tool is perfect on this set, no accuracy comparison can separate “copied the evidence” from “solved the code independently”. The honest statement is: the evidence is used as a source of numbers and wording, adoption is partial and inconsistent, and no semantic-reasoning gain is demonstrated.

## 4. Cost

The new method is the only paid work in this run: **280 requests**, 224,028 prompt tokens, 13,904 completion tokens, **$0.023561 configured** (provider list $0.023561, allowance $0.019094). Preflight smoke adds $0.000088 in two tiny requests; all-in $0.023648.

**deepseek**

| method | prompt tokens | completion tokens | configured USD | provider list USD | allowance USD | USD / correct |
| --- | --- | --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 112,671 | 7,187 | $0.011165 | $0.011166 | $0.006699 | $0.000081 |
| v2 direct | 78,091 | 6,892 | $0.010185 | $0.010185 | $0.006111 | $0.000075 |
| v2 dynamic (old evidence) | 98,183 | 7,211 | $0.011471 | $0.011471 | $0.006883 | $0.000084 |
| v2 combined (old static+dynamic) | 115,590 | 7,228 | $0.011891 | $0.011891 | $0.007134 | $0.000087 |
| dynamic-enhanced tool | 0 | 0 | $0.000000 | $0.000000 | $0.000000 | $0.000000 |

Incremental versus the frozen direct run: +2 correct, $0.000980 extra, $0.000490 per extra correct.

**mimo**

| method | prompt tokens | completion tokens | configured USD | provider list USD | allowance USD | USD / correct |
| --- | --- | --- | --- | --- | --- | --- |
| hde enhanced-dynamic-guided | 111,357 | 6,717 | $0.012395 | $0.012395 | $0.012395 | $0.000091 |
| v2 direct | 77,410 | 6,557 | $0.004718 | $0.004718 | $0.004718 | $0.000035 |
| v2 dynamic (old evidence) | 97,258 | 6,631 | $0.005735 | $0.005735 | $0.005735 | $0.000043 |
| v2 combined (old static+dynamic) | 114,495 | 6,700 | $0.004813 | $0.004813 | $0.004813 | $0.000035 |
| dynamic-enhanced tool | 0 | 0 | $0.000000 | $0.000000 | $0.000000 | $0.000000 |

Incremental versus the frozen direct run: +0 correct, $0.007677 extra, no extra correct answer, so no incremental unit cost is defined.

MiMo's enhanced run costs 2.63× its direct run ($0.012395 vs $0.004718) for the same 136/140, driven by 1.44× prompt tokens and less prompt-cache reuse (36,992 vs 57,984 cached tokens). The tool itself is offline and adds no API cost.

## 5. Audit

`run_hde.py verify` status: **PASS**, 12/12 checks passed.

The audit re-derives prompt hashes, recomputes accuracy and McNemar from the prediction files, checks cost arithmetic against the run manifests, and scans every generated file for the API key and label markers.

## 6. Limits and what cannot be claimed

- **No semantic-reasoning claim.** The tool is 140/140; a perfect score is fully explained by copying, and the observed scores are below 140. Accuracy cannot separate the two mechanisms on this set.
- **No significant effect.** The only gain over `direct` is DeepSeek +2 correct (exact p=0.5); MiMo gains 0. The largest raw contrast is MiMo vs the old dynamic run (+3, exact p=0.25, Holm 0.75), still not significant. A single rerun cannot separate an evidence effect from endpoint nondeterminism, which the v1/v2 reruns already documented.
- **Baselines are historical.** Direct/dynamic/combined were collected on 2026-11-11 with the same input pack and prompt version but a different serving session; model behaviour may drift between days.
- **Reason analysis is lexical.** Byte-count echo and keyword citation show what the model repeats, not what it uses. Polarity labels are heuristic and often unclear.
- **Evidence is conditional.** `realloc_fail` applies to 14 units and `nogobal` is a global root switch, not a per-variable root map. A clean mode is an observation on one executed path, not proof of absence.
- **Scope.** Juliet CWE-401 test 140 only; 70/70 labels; no dev split, no production code, no claim about other CWEs or models.
- **No key exposure.** The key is read from the local Kimi Code config into process memory, never printed, never stored; the audit scans generated artifacts for it.

## 7. Artifacts

| path | content |
| --- | --- |
| `inputs/units.jsonl` | 140 units with cleaned source and sanitized evidence |
| `runs/<run>_<model>/results.jsonl` | 140 real responses per model |
| `results/enhanced_dynamic_results.jsonl` | the same 280 responses in one file |
| `results/enhanced_dynamic_metrics.json` | accuracy, CIs, McNemar, subsets, consistency |
| `results/enhanced_dynamic_predictions.csv` | per-unit predictions for all methods |
| `results/consistency.json` | evidence-copy diagnostics |
| `results/cost.json` / `cost.md` | token and USD breakdown |
| `results/preflight.json` | fail-closed gate record |
| `results/audit.json` / `audit.md` | artifact audit |
