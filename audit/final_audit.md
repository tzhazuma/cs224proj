# Final quality and leakage audit

Generated: 2026-11-11T21:58:05.180132+00:00 (UTC)
Overall: **PASS_WITH_WARNINGS**  
Checks: 58 PASS, 0 FAIL, 3 WARN, 1 INFO.

Scope: read-only audit of `juliet/`, `juliet_llm/`, `hybrid/`, `juliet_repair/`,
`pair_joint/`, `traditional/static/`, `traditional/dynamic/`, `benchmark/` and the
derived `analysis/`/`report/` artifacts. No model API was called. The audit script
recomputes prompts, hashes, joins, costs and metrics from the stored artifacts; it does
not trust the per-directory summaries. Official results are the `hybrid_v2` runs and the
`juliet_llm` postleakfix runs; `hybrid_v1` and the pre-leakfix build are retained as the
superseded, leak-observable contrast and are checked as such.

## Must fix

- None.

## Warnings

- **B5 — Residual structural asymmetry between bad and good units**: Bad units average 600.4 chars vs good 937.9 (ratio 0.640); this is Juliet's structure, not a cleaning artifact, but it is a possible shortcut signal.
- **D5 — Shuffled runs use the donor's combined evidence, not the unit's own**: hybrid_v2: shuffled prompts are built from donor evidence for all 280 unit-runs; 14/140 units have donor evidence text identical to their own, so the placebo is a no-op for those units (not an integrity failure).
- **F4 — Repair prompt still contains class/entry identifiers**: Repair prompts contain `bad`/`CWE`/`Memory_Leak` in 70/70, 70/70, 70/70 units; good identifiers 0/70. The bad/CWE tokens are the repair task premise, but the input is not label-neutral.

## All checks

| ID | Area | Status | Check | Result |
| --- | --- | --- | --- | --- |
| A1 | frozen | **PASS** | Juliet freeze hashes match FREEZE.json | All three frozen Juliet hashes recomputed. |
| A2 | frozen | **PASS** | Frozen subset composition is 200 (60 dev / 140 test) | 200 units: dev 60 (30/30), test 140 (70/70), C 88 / C++ 112, 100 groups. |
| A3 | frozen | **PASS** | Cross-split near-duplicate gate passes | Cross-split max Jaccard 0.8231 < threshold 0.85; violations 0. |
| A4 | frozen | **PASS** | SHA256SUMS verifies every raw Juliet file | 2853 raw files listed; missing 0, hash mismatches 0. |
| B1 | cleaning | **PASS** | Juliet cleaner passes its fail-closed audit on all 200 units | clean_unit() rebuilt all 200 units; every audit check true; all forbidden counts zero. |
| B2 | cleaning | **PASS** | Rebuilt code and prompts equal the frozen juliet_llm build | Rebuilt prompts match juliet_llm/build for 60 dev + 140 test units. |
| B3 | cleaning | **PASS** | Cleaned code passes the built-in forbidden-token scan (11 classes) | Cleaned code contains no bad/good/CWE/memory-leak/macro/support-header/label-word token under the built-in 11-class scan. |
| B4 | cleaning | **PASS** | Cleaning preserves program semantics (compile/runtime checks) | Original 200 compile; 100 bad / 100 good runtime semantics reproduced; independent rebuild PASS; repair inputs 70/70 clean. |
| B5 | cleaning | **WARN** | Residual structural asymmetry between bad and good units | Bad units average 600.4 chars vs good 937.9 (ratio 0.640); this is Juliet's structure, not a cleaning artifact, but it is a possible shortcut signal. |
| C1 | prompt_leak | **PASS** | juliet_llm prompts pass the built-in 11-class token scan | 200 prompts: only system+user, one code block, zero hits under the built-in 11-class list (bad/good/CWE/label words/...). |
| C2 | prompt_leak | **PASS** | Sent juliet_llm prompts match their build (postleakfix and archived pre-fix) | Postleakfix official+repro: 280/280 sent prompts byte-identical to the current build; pre-leakfix v1: 280/280 byte-identical to the archived pre-leakfix build. |
| C3 | prompt_leak | **PASS** | Current prompts have no label words; archived v1 keeps the leak contrast | 0/200 current prompts contain benign/fixed/safe/clean/patched/remediated; the archived pre-leakfix v1 build still holds 8 hits (2 dev + 6 test, all good) as the leak contrast. |
| D1 | hybrid | **PASS** | Hybrid v2 source views equal current cleaning; v1 preserved | hybrid/inputs_v2/units.jsonl is exactly the current cleaner's output for the frozen test140; the frozen v1 inputs still match the archived pre-leakfix build 140/140. |
| D2 | hybrid | **PASS** | Hybrid evidence blocks reproduce from frozen tool runs | All 140 x 4 evidence blocks reproduced from the frozen static/dynamic runs (560 blocks). |
| D3 | hybrid | **PASS** | Placebo is a reproducible group-separated derangement | 140/140 placebo donors: no self-map, no same-group donor, permutation, and reproducible with seed 20261112. |
| D4 | hybrid | **PASS** | Hybrid prompts: direct == juliet_llm; all methods label-free | 1400 v2 hybrid prompts rebuilt; direct is byte-identical to juliet_llm in 140/140 units (280 run-level matches); all prompts pass the built-in audits. |
| D5 | hybrid | **WARN** | Shuffled runs use the donor's combined evidence, not the unit's own | hybrid_v2: shuffled prompts are built from donor evidence for all 280 unit-runs; 14/140 units have donor evidence text identical to their own, so the placebo is a no-op for those units (not an integrity failure). |
| D6 | hybrid | **PASS** | Hybrid v2 code blocks are label-word free; v1 keeps the leak contrast | 0/140 v2 hybrid source views contain benign/fixed/safe/clean words; the frozen v1 pack keeps exactly 6 good-unit hits as the leak contrast. |
| E1 | pair | **PASS** | Pair dataset loads as 180 valid pairs | 180 unique pairs loaded; dataset SHA-256 21218fd8db79f75f...; each side non-empty and distinct. |
| E2 | pair | **PASS** | Pair A/B order is exactly 90/90 and shared by both models | HMAC order map is exactly 90/90 (vulnerable in A: 90, in B: 90); both runs carry the same SHA-256 82c40fd03b1d0ae6... |
| E3 | pair | **PASS** | Pair prompts are metadata-free and match the frozen order map | Both models' 360 requests rebuilt; wrapper is free of pair_id/idx/commit/filepath/func_name/project; no slot leak. |
| E4 | pair | **PASS** | Pair DA reproduces the reported 138/180 and 156/180 | Pair DA reproduces the report: DeepSeek 138/180 (76.67%), MiMo 156/180 (86.67%), 0 invalid. |
| F1 | repair | **PASS** | Repair inputs are the frozen 70 test-bad units and all hashes match | 70 frozen test-bad units; 70 groups; 29 C / 41 C++; 70/70 leak-audit clean; every file hash recomputed. |
| F2 | repair | **PASS** | Repair baseline is leak-observable for exactly 58/70 units | Baselines: 58/70 bad leak observed, 12/70 unobservable, 70/70 good clean; 70/70 behavior observable. |
| F3 | repair | **PASS** | Repair metrics reproduce: 58/58 strict, 70/70 compile and behavior | Both final runs: 70 results, 70/72 calls, 70 compile/leak/behavior, 58/58 strict among the 58 observable units (DeepSeek 58 first-try, MiMo 57). |
| F4 | repair | **WARN** | Repair prompt still contains class/entry identifiers | Repair prompts contain `bad`/`CWE`/`Memory_Leak` in 70/70, 70/70, 70/70 units; good identifiers 0/70. The bad/CWE tokens are the repair task premise, but the input is not label-neutral. |
| F5 | repair | **PASS** | Repair cost sums recompute from usage | Repair costs recompute from per-request usage and configured prices (see evidence for provider allowance). |
| G1 | static | **PASS** | Static run has exactly 4 test clang compile failures | 400 tool rows; test clang compile errors 4, dev 2; cppcheck has 0 errors. |
| G2 | static | **PASS** | Static metrics count compile errors as FN end-to-end | Static metrics: clang evaluable 194/200 with compile errors excluded then counted as FN end-to-end (TP 73 / FN 27 / TN 100); cppcheck TP 30 / FP 4 / TN 96 / FN 70. |
| G3 | static | **PASS** | Hybrid renders compile failures as no-conclusion | The 4 test compile failures are rendered as "analysis failed ... not a clean result", never as clean. |
| H1 | dynamic | **PASS** | Full dynamic run has 3316 cases with one documented inconclusive | 3316 real cases/results: leak 1467, clean 1848, inconclusive 1. |
| H2 | dynamic | **PASS** | Frozen 200 units join to dynamic results exactly | Frozen 200 all join: bad 78 leak / 22 clean; good 100 clean; no frozen inconclusive. |
| H3 | dynamic | **PASS** | Test140 has 58 observable and 12 unobservable bad units | Test140: 58 bad leak / 12 bad unobservable / 70 good clean; the 12 are the documented LSan blind spots. |
| H4 | dynamic | **PASS** | Dynamic clean evidence is never presented as proof of no leak | All 12 bad-but-clean-evidence units carry "no leak detected in this run ... not proof of absence"; inconclusive is never clean. |
| I1 | cost | **PASS** | Hybrid v2 cost totals recompute from per-request usage | hybrid_v2: 10 runs / 1400 requests; list $0.082335, allowance $0.059878; every row recomputes from usage and the provider-matched price card. |
| I2 | cost | **PASS** | juliet_llm postleakfix cost recomputes at the documented Xiaomi prices | juliet_llm postleakfix official+repro: 280 rows; $0.003180274 and $0.003081299 at Xiaomi published prices; provider allowance is not returned on that endpoint (documented). |
| I3 | cost | **PASS** | Repair documented all-in cost matches recorded requests | Recorded repair spend $0.082550; README all-in claim $0.082550; delta $-0.000000318 (the previously omitted parser_dev/mimo_test70_v1 is included: $0.005034). |
| I4 | cost | **PASS** | Pair-joint cost totals recompute from usage | Pair costs recompute: DeepSeek $0.153593 / MiMo $0.071803 list; allowance $0.046078 / $0.071803. |
| I5 | cost | **PASS** | Hybrid v2 DeepSeek prices match the provider snapshot; v1 peak card documented | hybrid_v2 prices DeepSeek at $0.15/$0.60/$0.003 and MiMo at $0.14/$0.28/$0.0028; all 10 configured totals match the provider list_cost within 2%. The frozen v1 rows keep the old 0.30/1.20 peak card (ratio 0.5), documented in analysis/cost_normalization as the off-peak snapshot. |
| I6 | cost | **PASS** | Legacy runner cost totals are internally consistent | All 12 legacy runner runs' cost totals recompute from their results and config. |
| I7 | cost | **PASS** | Normalized provider-list costs are complete and reconcile to the artifacts | analysis/cost_normalization.json: 79 stored runs / 9584 requests; verification PASS, 0 peak rows, 0 changed source artifacts; 10/10 hybrid_v2 runs match configured = normalized = provider list; repair all-in normalized at $0.052549. |
| J1 | endpoint | **PASS** | Every experiment uses its documented endpoint | Headline runs use the documented endpoints: OpenCode Go for hybrid/repair/pair, Xiaomi official only for the labeled juliet_llm fallback; smoke evidence is 401/402/403 as documented. |
| J2 | endpoint | **PASS** | Xiaomi fallback is explicitly labelled and not passed off as OpenCode | The MiMo postleakfix official/repro (and the preserved pre-fix runs) are explicitly labelled Xiaomi official-endpoint fallbacks, not OpenCode Go results. |
| K1 | manifest | **PASS** | Legacy runner test manifests are complete | 12 legacy test_v1 runs: status completed, planned == recorded == rows (288 or 540), no missing requests, unique ids. |
| K2 | manifest | **PASS** | Hybrid v2 manifests report 140/140 with zero invalid | hybrid_v2: 10 runs, 140 expected, 140 recorded, 140 ok, 0 invalid, 0 API error, partial=false. |
| K3 | manifest | **PASS** | juliet_llm postleakfix test runs are complete at 140/140 | Both postleakfix MiMo test140 runs: 140 recorded, 140 valid, 0 invalid, 0 API errors, partial=false, prompt .2. |
| K4 | manifest | **PASS** | Pair-joint runs are complete at 180/180 | Both pair runs: status completed, 180 planned, 180 recorded, 180 ok, partial=false. |
| K5 | manifest | **PASS** | Benchmark legacy imports are complete | 12 imported legacy benchmark manifests are completed with planned == recorded. |
| K6 | manifest | **PASS** | evidence_prompt test runs are complete and source-only | evidence_prompt test runs: both 160/160 with 0 API errors, OpenCode Go, and prompts restricted to func_body (no label/context fields). |
| L1 | preserve | **PASS** | Old DeepSeek/MiMo runner results are byte-identical to their import | All 12 benchmark imports still match the current runner results.jsonl byte-for-byte. |
| L2 | preserve | **PASS** | Old DeepSeek metrics are stable under the benchmark import | DeepSeek legacy detection/pair metrics recompute identically from the current runner results. |
| L3 | preserve | **PASS** | Legacy results predate all new experiment files on disk | Newest legacy DeepSeek file 2026-11-11T12:05:01.723998+00:00 <= earliest new-experiment file 2026-11-11T19:13:10.921222+00:00. |
| L4 | preserve | **PASS** | Derived analysis uses a reproducible repository path | analysis/aggregation.json references 14 run paths, all under the current repository root; datasets root is /mnt/c/Users/tzh03/Downloads/cs224proj/datasets. |
| L5 | preserve | **PASS** | Frozen v1 artifacts are retained as the superseded leak contrast | v1 is preserved and untouched: 140 inputs match the archived pre-leakfix build, 10/10 v1 runs are complete, and the 2 pre-fix juliet_llm runs plus 2 superseded post-fix runs remain on disk. |
| M1 | claims | **PASS** | Hybrid v2 report numbers match the artifacts | REPORT_V2 headline percentages and per-model costs recompute from hybrid_v2_metrics; the matrix is labelled 1400 real requests. |
| M2 | claims | **PASS** | Pair report numbers match the artifacts | Pair report states 138/180 (76.67%), 156/180 (86.67%), and the 74.44% length heuristic. |
| M3 | claims | **PASS** | Repair report carries the recomputed headline numbers | Repair README carries the 58/58 headline, 70 calls, and the corrected all-in $0.082550. |
| M4 | claims | **PASS** | juliet_llm report numbers match the postleakfix artifact | juliet_llm README carries the postleakfix 140/140, accuracy 0.9500, F1 0.9510, MCC 0.9008, cost $0.003180, and keeps the pre-fix 0.9571. |
| M5 | claims | **PASS** | Static/dynamic baseline numbers are consistent across reports | Tool baselines are consistently reported in hybrid/REPORT_V2.md as static 85.00% and dynamic 91.43%. |
| N1 | secrets | **PASS** | No credentials in any experiment artifact | 2241 text artifacts scanned; no key/Bearer/Authorization material found. |
| N2 | scope | **PASS** | Audit stays inside audit/ | The audit writes only audit/final_audit.{json,md} and its script. |
| N3 | scope | **INFO** | Repository state for the later GitHub push | Git repository exists (HEAD ref: refs/heads/main; remotes: origin). |

## Key evidence

### C2: Sent juliet_llm prompts match their build (postleakfix and archived pre-fix)

- Status: **PASS**
- Postleakfix official+repro: 280/280 sent prompts byte-identical to the current build; pre-leakfix v1: 280/280 byte-identical to the archived pre-leakfix build.

```json
{
  "postleakfix": {
    "runs": [
      "20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix",
      "20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro"
    ],
    "prompt_versions": [
      "juliet-llm-binary-2026-11-12.2"
    ],
    "checked": 280,
    "matched": 280
  },
  "pre_leakfix": {
    "runs": [
      "20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official",
      "20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final"
    ],
    "prompt_versions": [
      "juliet-llm-binary-2026-11-12.1"
    ],
    "checked": 280,
    "matched": 280
  },
  "problems": []
}
```

### C3: Current prompts have no label words; archived v1 keeps the leak contrast

- Status: **PASS**
- 0/200 current prompts contain benign/fixed/safe/clean/patched/remediated; the archived pre-leakfix v1 build still holds 8 hits (2 dev + 6 test, all good) as the leak contrast.

```json
{
  "hits": [],
  "test_hits": 0,
  "all_good": true,
  "pre_leakfix_hits": [
    {
      "split": "dev",
      "unit_id": "CWE401_Memory_Leak__malloc_realloc_struct_twoIntsStruct_09__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "dev",
      "unit_id": "CWE401_Memory_Leak__malloc_realloc_wchar_t_09__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__int_malloc_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__malloc_realloc_int64_t_09__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__new_array_char_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__new_array_int_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__new_int_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "split": "test",
      "unit_id": "CWE401_Memory_Leak__twoIntsStruct_realloc_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    }
  ],
  "pre_leakfix_test_hits": 6,
  "pre_leakfix_all_good": true,
  "root_cause": "v1 cleaner omitted benign/fixed; prompt .2 neutralises them"
}
```

### D1: Hybrid v2 source views equal current cleaning; v1 preserved

- Status: **PASS**
- hybrid/inputs_v2/units.jsonl is exactly the current cleaner's output for the frozen test140; the frozen v1 inputs still match the archived pre-leakfix build 140/140.

```json
{
  "units": 140,
  "legacy_units": 140,
  "problems": [],
  "legacy_problems": []
}
```

### D6: Hybrid v2 code blocks are label-word free; v1 keeps the leak contrast

- Status: **PASS**
- 0/140 v2 hybrid source views contain benign/fixed/safe/clean words; the frozen v1 pack keeps exactly 6 good-unit hits as the leak contrast.

```json
{
  "units": [],
  "legacy_units": [
    {
      "unit_id": "CWE401_Memory_Leak__int_malloc_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "unit_id": "CWE401_Memory_Leak__malloc_realloc_int64_t_09__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "unit_id": "CWE401_Memory_Leak__new_array_char_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "unit_id": "CWE401_Memory_Leak__new_array_int_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "unit_id": "CWE401_Memory_Leak__new_int_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    },
    {
      "unit_id": "CWE401_Memory_Leak__twoIntsStruct_realloc_22__good",
      "label": "good",
      "tokens": [
        "benign",
        "fixed"
      ]
    }
  ],
  "methods_per_unit": 5,
  "models": 2,
  "note": "v2 uses the current cleaner; v1 is retained unchanged as the leak contrast"
}
```

### D3: Placebo is a reproducible group-separated derangement

- Status: **PASS**
- 140/140 placebo donors: no self-map, no same-group donor, permutation, and reproducible with seed 20261112.

```json
{
  "pairs": 140,
  "fixed_points": 0,
  "same_group": 0,
  "donor_label": {
    "bad": 70,
    "good": 70
  },
  "problems": [],
  "recomputed_matches": true
}
```

### D4: Hybrid prompts: direct == juliet_llm; all methods label-free

- Status: **PASS**
- 1400 v2 hybrid prompts rebuilt; direct is byte-identical to juliet_llm in 140/140 units (280 run-level matches); all prompts pass the built-in audits.

```json
{
  "run_id": "hybrid_v2",
  "checked": 1400,
  "direct_matches": 280,
  "direct_units": 140,
  "prompt_versions": [
    "hybrid-v2-juliet-llm-binary-2026-11-12.2"
  ],
  "problems": []
}
```

### E2: Pair A/B order is exactly 90/90 and shared by both models

- Status: **PASS**
- HMAC order map is exactly 90/90 (vulnerable in A: 90, in B: 90); both runs carry the same SHA-256 82c40fd03b1d0ae6...

```json
{
  "vulnerable_A": 90,
  "vulnerable_B": 90,
  "order_map_sha256": "82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8",
  "runs": {
    "test_deepseek_180": {
      "counts": {
        "A": 90,
        "B": 90
      },
      "sha256": "82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8"
    },
    "test_mimo_180": {
      "counts": {
        "A": 90,
        "B": 90
      },
      "sha256": "82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8"
    }
  },
  "problems": []
}
```

### F2: Repair baseline is leak-observable for exactly 58/70 units

- Status: **PASS**
- Baselines: 58/70 bad leak observed, 12/70 unobservable, 70/70 good clean; 70/70 behavior observable.

```json
{
  "baselines": 70,
  "stats": {
    "bad_leak": 58,
    "good_clean": 70,
    "bad_behavior_observable": 70,
    "bad_clean": 12
  },
  "unobservable_units": [
    "CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad",
    "CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad",
    "CWE401_Memory_Leak__malloc_realloc_int_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_int_18__bad",
    "CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad",
    "CWE401_Memory_Leak__new_TwoIntsClass_68__bad",
    "CWE401_Memory_Leak__new_array_twointsStruct_68__bad",
    "CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad",
    "CWE401_Memory_Leak__wchar_t_calloc_68__bad",
    "CWE401_Memory_Leak__wchar_t_malloc_68__bad"
  ]
}
```

### F3: Repair metrics reproduce: 58/58 strict, 70/70 compile and behavior

- Status: **PASS**
- Both final runs: 70 results, 70/72 calls, 70 compile/leak/behavior, 58/58 strict among the 58 observable units (DeepSeek 58 first-try, MiMo 57).

```json
{
  "runs": {
    "deepseek_test70_final": {
      "results": 70,
      "requests": 70,
      "strict_pass": 58,
      "strict_evaluable": 58,
      "first_attempt_strict_pass": 58,
      "compile_pass": 70,
      "leak_removed": 70,
      "behavior_preserved": 70,
      "summary_strict_pass": 58,
      "summary_strict_evaluable": 58,
      "cost_usd_sum": 0.02699044,
      "total_calls": 70
    },
    "mimo_test70_final": {
      "results": 70,
      "requests": 72,
      "strict_pass": 58,
      "strict_evaluable": 58,
      "first_attempt_strict_pass": 57,
      "compile_pass": 70,
      "leak_removed": 70,
      "behavior_preserved": 70,
      "summary_strict_pass": 58,
      "summary_strict_evaluable": 58,
      "cost_usd_sum": 0.00584091,
      "total_calls": 72
    }
  },
  "problems": []
}
```

### H3: Test140 has 58 observable and 12 unobservable bad units

- Status: **PASS**
- Test140: 58 bad leak / 12 bad unobservable / 70 good clean; the 12 are the documented LSan blind spots.

```json
{
  "counts": {
    "bad/clean": 12,
    "bad/leak": 58,
    "good/clean": 70
  },
  "unobservable_units": [
    "CWE401_Memory_Leak__malloc_realloc_int_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_int_18__bad",
    "CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad",
    "CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad",
    "CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad",
    "CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad",
    "CWE401_Memory_Leak__new_TwoIntsClass_68__bad",
    "CWE401_Memory_Leak__new_array_twointsStruct_68__bad",
    "CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad",
    "CWE401_Memory_Leak__wchar_t_calloc_68__bad",
    "CWE401_Memory_Leak__wchar_t_malloc_68__bad"
  ],
  "families": {
    "malloc_realloc_int": 2,
    "malloc_realloc_int64_t": 3,
    "malloc_realloc_twoIntsStruct": 2,
    "new_TwoIntsClass": 1,
    "new_array_twointsStruct": 1,
    "twoIntsStruct_malloc": 1,
    "wchar_t_calloc": 1,
    "wchar_t_malloc": 1
  }
}
```

### I1: Hybrid v2 cost totals recompute from per-request usage

- Status: **PASS**
- hybrid_v2: 10 runs / 1400 requests; list $0.082335, allowance $0.059878; every row recomputes from usage and the provider-matched price card.

```json
{
  "run_id": "hybrid_v2",
  "runs": {
    "deepseek/direct": {
      "list_usd": 0.010185234,
      "allowance_usd": 0.00611102,
      "provider_list_usd": 0.01018542,
      "max_row_cost_delta": 0.0
    },
    "deepseek/static": {
      "list_usd": 0.011730036,
      "allowance_usd": 0.00703785,
      "provider_list_usd": 0.01172994,
      "max_row_cost_delta": 0.0
    },
    "deepseek/dynamic": {
      "list_usd": 0.011471202,
      "allowance_usd": 0.00688256,
      "provider_list_usd": 0.01147108,
      "max_row_cost_delta": 0.0
    },
    "deepseek/combined": {
      "list_usd": 0.01189098,
      "allowance_usd": 0.00713438,
      "provider_list_usd": 0.0118912,
      "max_row_cost_delta": 0.0
    },
    "deepseek/shuffled": {
      "list_usd": 0.010859868,
      "allowance_usd": 0.00651569,
      "provider_list_usd": 0.01086032,
      "max_row_cost_delta": 0.0
    },
    "mimo/direct": {
      "list_usd": 0.004717955,
      "allowance_usd": 0.0047177,
      "provider_list_usd": 0.0047177,
      "max_row_cost_delta": 0.0
    },
    "mimo/static": {
      "list_usd": 0.006287014,
      "allowance_usd": 0.00628686,
      "provider_list_usd": 0.00628686,
      "max_row_cost_delta": 0.0
    },
    "mimo/dynamic": {
      "list_usd": 0.005734893,
      "allowance_usd": 0.00573469,
      "provider_list_usd": 0.00573469,
      "max_row_cost_delta": 0.0
    },
    "mimo/combined": {
      "list_usd": 0.004813127,
      "allowance_usd": 0.00481298,
      "provider_list_usd": 0.00481298,
      "max_row_cost_delta": 0.0
    },
    "mimo/shuffled": {
      "list_usd": 0.004644769,
      "allowance_usd": 0.00464462,
      "provider_list_usd": 0.00464462,
      "max_row_cost_delta": 0.0
    }
  },
  "total_list_usd": 0.082335078,
  "total_allowance_usd": 0.05987835,
  "by_model": {
    "deepseek": {
      "list_usd": 0.05613732,
      "allowance_usd": 0.0336815,
      "provider_list_usd": 0.05613796
    },
    "mimo": {
      "list_usd": 0.026197758,
      "allowance_usd": 0.02619685,
      "provider_list_usd": 0.02619685
    }
  },
  "problems": []
}
```

### I2: juliet_llm postleakfix cost recomputes at the documented Xiaomi prices

- Status: **PASS**
- juliet_llm postleakfix official+repro: 280 rows; $0.003180274 and $0.003081299 at Xiaomi published prices; provider allowance is not returned on that endpoint (documented).

```json
{
  "runs": {
    "20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix": {
      "rows": 140,
      "recomputed_usd": 0.003180274,
      "published_usd": 0.003180274,
      "max_row_cost_delta": 0.0,
      "prompt_version": "juliet-llm-binary-2026-11-12.2"
    },
    "20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro": {
      "rows": 140,
      "recomputed_usd": 0.003081299,
      "published_usd": 0.003081299,
      "max_row_cost_delta": 0.0,
      "prompt_version": "juliet-llm-binary-2026-11-12.2"
    }
  },
  "problems": []
}
```

### I5: Hybrid v2 DeepSeek prices match the provider snapshot; v1 peak card documented

- Status: **PASS**
- hybrid_v2 prices DeepSeek at $0.15/$0.60/$0.003 and MiMo at $0.14/$0.28/$0.0028; all 10 configured totals match the provider list_cost within 2%. The frozen v1 rows keep the old 0.30/1.20 peak card (ratio 0.5), documented in analysis/cost_normalization as the off-peak snapshot.

```json
{
  "v2_samples": [
    {
      "run": "hybrid_v2_deepseek_direct",
      "configured_list_usd": 0.010185234,
      "provider_list_usd": 0.01018542,
      "ratio": 1.000018,
      "configured_prices": {
        "input": 0.15,
        "output": 0.6,
        "cached": 0.003
      }
    },
    {
      "run": "hybrid_v2_deepseek_static",
      "configured_list_usd": 0.011730036,
      "provider_list_usd": 0.01172994,
      "ratio": 0.999992,
      "configured_prices": {
        "input": 0.15,
        "output": 0.6,
        "cached": 0.003
      }
    },
    {
      "run": "hybrid_v2_deepseek_dynamic",
      "configured_list_usd": 0.011471202,
      "provider_list_usd": 0.01147108,
      "ratio": 0.999989,
      "configured_prices": {
        "input": 0.15,
        "output": 0.6,
        "cached": 0.003
      }
    },
    {
      "run": "hybrid_v2_deepseek_combined",
      "configured_list_usd": 0.01189098,
      "provider_list_usd": 0.0118912,
      "ratio": 1.000019,
      "configured_prices": {
        "input": 0.15,
        "output": 0.6,
        "cached": 0.003
      }
    },
    {
      "run": "hybrid_v2_deepseek_shuffled",
      "configured_list_usd": 0.010859868,
      "provider_list_usd": 0.01086032,
      "ratio": 1.000042,
      "configured_prices": {
        "input": 0.15,
        "output": 0.6,
        "cached": 0.003
      }
    },
    {
      "run": "hybrid_v2_mimo_direct",
      "configured_list_usd": 0.004717955,
      "provider_list_usd": 0.0047177,
      "ratio": 0.999946,
      "configured_prices": {
        "input": 0.14,
        "output": 0.28,
        "cached": 0.0028
      }
    },
    {
      "run": "hybrid_v2_mimo_static",
      "configured_list_usd": 0.006287014,
      "provider_list_usd": 0.00628686,
      "ratio": 0.999976,
      "configured_prices": {
        "input": 0.14,
        "output": 0.28,
        "cached": 0.0028
      }
    },
    {
      "run": "hybrid_v2_mimo_dynamic",
      "configured_list_usd": 0.005734893,
      "provider_list_usd": 0.00573469,
      "ratio": 0.999965,
      "configured_prices": {
        "input": 0.14,
        "output": 0.28,
        "cached": 0.0028
      }
    },
    {
      "run": "hybrid_v2_mimo_combined",
      "configured_list_usd": 0.004813127,
      "provider_list_usd": 0.00481298,
      "ratio": 0.999969,
      "configured_prices": {
        "input": 0.14,
        "output": 0.28,
        "cached": 0.0028
      }
    },
    {
      "run": "hybrid_v2_mimo_shuffled",
      "configured_list_usd": 0.004644769,
      "provider_list_usd": 0.00464462,
      "ratio": 0.999968,
      "configured_prices": {
        "input": 0.14,
        "output": 0.28,
        "cached": 0.0028
      }
    }
  ],
  "legacy_samples": [
    {
      "run": "hybrid_v1_deepseek_direct",
      "configured_list_usd": 0.020569692,
      "provider_list_usd": 0.01028502,
      "ratio": 0.500008
    },
    {
      "run": "hybrid_v1_deepseek_combined",
      "configured_list_usd": 0.029260464,
      "provider_list_usd": 0.01463039,
      "ratio": 0.500005
    }
  ],
  "juliet_llm_deepseek_prices": {
    "cached_input": 0.003,
    "input": 0.15,
    "output": 0.6
  },
  "cost_normalization": {
    "audit_resolution_I5": {
      "finding": "configured DeepSeek 0.30/1.20/0.006 is the peak card; provider usage.opencode.list_cost is the off-peak card 0.15/0.60/0.003",
      "all_requests_off_peak": true,
      "configured_results_unchanged": true,
      "normalized_costs_in": "analysis/cost_normalization.json (per-run and aggregates)"
    },
    "verification": "PASS"
  },
  "problems": []
}
```

### I7: Normalized provider-list costs are complete and reconcile to the artifacts

- Status: **PASS**
- analysis/cost_normalization.json: 79 stored runs / 9584 requests; verification PASS, 0 peak rows, 0 changed source artifacts; 10/10 hybrid_v2 runs match configured = normalized = provider list; repair all-in normalized at $0.052549.

```json
{
  "entries": 79,
  "verification": {
    "status": "PASS",
    "source_artifacts_checked": 158,
    "source_artifacts_changed": [],
    "usage_rows": 9584,
    "provider_rows": 9007,
    "token_mismatch_rows": 0,
    "missing_cost_rows": 0,
    "peak_rows": 0,
    "unexplained_configured_runs": [],
    "provider_mismatch_runs": [],
    "max_provider_row_rel_dev": 0.0003788400606143652,
    "first_request_utc": "2026-11-11T11:12:13.447000+00:00",
    "last_request_utc": "2026-11-11T20:58:21.952000+00:00",
    "complete_usage_runs": 71,
    "incomplete_usage_runs": [
      "mimo_test70_v1",
      "pilot_v1_mimo_attempt2_reasoning_direct_pairs"
    ],
    "skipped_runs": []
  },
  "checked_hybrid_v2_runs": 10,
  "repair": {
    "headline_runs": [
      "deepseek_test70_final",
      "mimo_test70_final"
    ],
    "headline_configured_usd": 0.032831094,
    "headline_normalized_usd": 0.019335936,
    "headline_provider_list_usd": 0.01933584,
    "headline_allowance_usd": 0.013938,
    "all_configured_usd": 0.082549682,
    "all_normalized_usd": 0.052549346,
    "all_provider_list_usd": 0.05254922,
    "all_allowance_usd": 0.04054951,
    "readme_old_all_in_usd": 0.077516,
    "readme_new_all_in_usd": 0.08255,
    "delta_vs_old_readme_usd": 0.005033682,
    "headline_unchanged": true,
    "mimo_v1_configured_usd": 0.005033773
  },
  "audit_resolution": {
    "I5": {
      "finding": "configured DeepSeek 0.30/1.20/0.006 is the peak card; provider usage.opencode.list_cost is the off-peak card 0.15/0.60/0.003",
      "all_requests_off_peak": true,
      "configured_results_unchanged": true,
      "normalized_costs_in": "analysis/cost_normalization.json (per-run and aggregates)"
    },
    "I3": {
      "readme_old_all_in_usd": 0.077516,
      "readme_new_all_in_usd": 0.08255,
      "delta_usd": 0.005033682,
      "headline_unchanged": true
    }
  },
  "problems": []
}
```

### I3: Repair documented all-in cost matches recorded requests

- Status: **PASS**
- Recorded repair spend $0.082550; README all-in claim $0.082550; delta $-0.000000318 (the previously omitted parser_dev/mimo_test70_v1 is included: $0.005034).

```json
{
  "runs": {
    "deepseek_test70_final": {
      "requests": 70,
      "cost_usd": 0.026990316
    },
    "mimo_test70_final": {
      "requests": 72,
      "cost_usd": 0.005840778
    },
    "deepseek_test70_v1": {
      "requests": 81,
      "cost_usd": 0.032689656
    },
    "mimo_test70_v1": {
      "requests": 44,
      "cost_usd": 0.005033773
    },
    "mimo_test70_v2": {
      "requests": 86,
      "cost_usd": 0.011578
    },
    "smoke_deepseek_u0001": {
      "requests": 1,
      "cost_usd": 0.0003207
    },
    "smoke_mimo_u0001": {
      "requests": 1,
      "cost_usd": 9.646e-05
    }
  },
  "headline_usd": 0.032831094,
  "all_recorded_usd": 0.082549682,
  "readme_all_in_usd": 0.08255,
  "delta_usd": -3.18e-07,
  "problems": []
}
```

### L4: Derived analysis uses a reproducible repository path

- Status: **PASS**
- analysis/aggregation.json references 14 run paths, all under the current repository root; datasets root is /mnt/c/Users/tzh03/Downloads/cs224proj/datasets.

```json
{
  "run_paths": 14,
  "missing": 0,
  "stale_roots": [
    "/mnt/c/Users/tzh03/Downloads/cs224proj"
  ],
  "dataset_root": "/mnt/c/Users/tzh03/Downloads/cs224proj/datasets",
  "problems": []
}
```

### L5: Frozen v1 artifacts are retained as the superseded leak contrast

- Status: **PASS**
- v1 is preserved and untouched: 140 inputs match the archived pre-leakfix build, 10/10 v1 runs are complete, and the 2 pre-fix juliet_llm runs plus 2 superseded post-fix runs remain on disk.

```json
{
  "v1_inputs": 140,
  "v1_runs": {
    "hybrid_v1_deepseek_direct": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_deepseek_static": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_deepseek_dynamic": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_deepseek_combined": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_deepseek_shuffled": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_mimo_direct": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_mimo_static": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_mimo_dynamic": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_mimo_combined": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    },
    "hybrid_v1_mimo_shuffled": {
      "rows": 140,
      "prompt_version": "hybrid-juliet-llm-binary-2026-11-12.1"
    }
  },
  "pre_leakfix_juliet_runs": [
    "20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official",
    "20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final"
  ],
  "superseded_juliet_runs": [
    {
      "run": "20261111T204701Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix",
      "rows": 140
    },
    {
      "run": "20261111T204833Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro",
      "rows": 140
    }
  ],
  "problems": []
}
```

## Reproduction

All checks run offline in WSL and write only `audit/final_audit.{json,md}`:

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 audit/run_final_audit.py
```

## Limits of this audit

- The audit verifies what the stored artifacts and frozen inputs can prove. It cannot
  re-run the model calls, the compilers or the sanitizers; those results are inherited.
- The current `juliet_llm` build and `hybrid_v2` inputs contain no `benign`/`fixed` label
  words. The frozen `juliet_llm/build_pre_leakfix_v1` and `hybrid/inputs` still contain
  the 8/200 (6 test) and 6/140 hits respectively; they are retained only as a leak contrast.
- `juliet_repair` is a bad-only repair task; its prompts intentionally state that the
  program leaks. The `bad`/`CWE`/`Memory_Leak` entry identifiers are therefore not a
  hidden ground-truth label, but the input is not label-neutral (see F4).
- v2 prices DeepSeek at the off-peak list card ($0.15/$0.60/$0.003); the frozen v1 rows
  keep the peak card ($0.30/$1.20/$0.006). `analysis/cost_normalization.json` provides
  the normalized provider-list view and the independent allowance; it is not an invoice.
- The full dynamic run has one inconclusive case outside the frozen 200; the frozen
  test140 has none, so the inconclusive branch is verified by renderer/selftest only.
- `analysis/aggregation.json` was regenerated under the current repository root; the
  derived numbers are checked here, not re-estimated.
