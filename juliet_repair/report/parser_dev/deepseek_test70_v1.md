# Juliet CWE-401 repair: deepseek-v4.1-flash

- run: `deepseek_test70_v1`
- model: `deepseek-v4.1-flash`
- units: 70 frozen `split=test, label=bad` groups
- API calls: 81 (initial + at most one feedback iteration)
- cost: $0.032690
- prompt/completion tokens: 41126 / 19845

## Headline metrics

| metric | all 70 | 58 LSan-observable |
| --- | ---: | ---: |
| compile pass | 70 | 58 |
| leak removed | 70 | 58 |
| behaviour preserved | 70 | 58 |
| strict pass | 58 | 58 |

`strict pass` requires compile, LSan-clean run, identical observable data lines, a non-vacuous behaviour signature, and a baseline where LSan actually observed a leak. The 12 units whose baseline does not leak under LSan are not strict-evaluable; their compile/behaviour results are reported but cannot prove leak removal.

## First attempt vs after feedback

| stage | compile | leak removed | behaviour | strict (58) |
| --- | ---: | ---: | ---: | ---: |
| first attempt | 70 | 70 | 70 | 58 |
| final (after optional iteration) | 70 | 70 | 70 | 58 |

- units that used the feedback iteration: 11
- rejected responses (schema/parse): 0
- API errors: 0

## Non-LSan-observable units

These 12 units have no leak in the default LSan root set used here: 8 `malloc_realloc` cases leak only when `realloc` fails, and 4 variant-68 cases keep the only pointer in a global that LSan treats as reachable. They are listed, not silently counted as successes.

- `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad`
- `CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad`
- `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad`
- `CWE401_Memory_Leak__malloc_realloc_int_01__bad`
- `CWE401_Memory_Leak__malloc_realloc_int_18__bad`
- `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad`
- `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad`
- `CWE401_Memory_Leak__new_TwoIntsClass_68__bad`
- `CWE401_Memory_Leak__new_array_twointsStruct_68__bad`
- `CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad`
- `CWE401_Memory_Leak__wchar_t_calloc_68__bad`
- `CWE401_Memory_Leak__wchar_t_malloc_68__bad`

## Failures and non-strict outcomes

| unit | attempts | compile | leak | behaviour | observable | parse error |
| --- | ---: | --- | --- | --- | --- | --- |
| u0022 | 1 | True | True | True | True |  |
| u0023 | 1 | True | True | True | True |  |
| u0024 | 1 | True | True | True | True |  |
| u0025 | 1 | True | True | True | True |  |
| u0026 | 1 | True | True | True | True |  |
| u0027 | 1 | True | True | True | True |  |
| u0028 | 1 | True | True | True | True |  |
| u0030 | 1 | True | True | True | True |  |
| u0038 | 1 | True | True | True | True |  |
| u0059 | 2 | True | True | True | True |  |
| u0065 | 1 | True | True | True | True |  |
| u0068 | 2 | True | True | True | True |  |

## Case studies

### wide-character output preserved: `CWE401_Memory_Leak__new_array_wchar_t_01__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_array_wchar_t_01.cpp
+++ b/CWE401_Memory_Leak__new_array_wchar_t_01.cpp
@@ -16,7 +16,7 @@
     wcscpy(data, L"A String");
     printWLine(data);
 
-    ;
+    delete [] data;
 }
 
 
```

### needed feedback iteration: `CWE401_Memory_Leak__new_array_char_22__bad`

- attempts: 2; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_array_char_22a.cpp
+++ b/CWE401_Memory_Leak__new_array_char_22a.cpp
@@ -21,6 +21,7 @@
     printLine(data);
     badGlobal = 1;
     badSink(data);
+    delete[] data;
 }
 
 
```

## Reproduction

```bash
python3 juliet_repair/scripts/prepare_inputs.py --force
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force
python3 juliet_repair/scripts/run_repair.py --model deepseek --concurrency 8 --out-dir juliet_repair/runs/deepseek_test70_v1
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/deepseek_test70_v1
```
