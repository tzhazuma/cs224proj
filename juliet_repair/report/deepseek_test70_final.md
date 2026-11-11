# Juliet CWE-401 repair: deepseek-v4.1-flash

- run: `deepseek_test70_final`
- model: `deepseek-v4.1-flash`
- units: 70 frozen `split=test, label=bad` groups
- API calls: 70 (initial + at most one feedback iteration)
- cost: $0.026990
- prompt/completion tokens: 30405 / 16835

## Headline metrics

| metric | all 70 | 58 LSan-observable |
| --- | ---: | ---: |
| compile pass | 70 | 58 |
| leak removed (12 non-observable are vacuous) | 70 | 58 |
| behaviour preserved | 70 | 58 |
| strict pass (non-evaluable counted as not pass) | 58 | 58 |

`strict pass` requires compile, LSan-clean run, identical observable data lines, a non-vacuous behaviour signature, and a baseline where LSan actually observed a leak. The 12 units whose baseline does not leak under LSan are not strict-evaluable; their compile/behaviour results are reported but cannot prove leak removal.

## First attempt vs after feedback

| stage | compile | leak removed | behaviour | strict (58) |
| --- | ---: | ---: | ---: | ---: |
| first attempt | 70 | 70 | 70 | 58 |
| final (after optional iteration) | 70 | 70 | 70 | 58 |

- units that used the feedback iteration: 0 (0 after a real compile/LSan/behaviour failure, 0 after a schema/parse rejection)
- real-failure iterations that reached strict pass: 0
- rejected responses (schema/parse): 0
- final responses with the exact top-level schema: 69/70
- final responses including an explanation: 69/70
- API errors: 0

## Non-LSan-observable units

These 12 units have no leak in the default LSan root set used here: 7 `malloc_realloc` cases leak only when `realloc` fails, and 5 variant-68 cases keep the only pointer in a global that LSan treats as reachable. They are listed, not silently counted as successes.

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

| unit | attempts | compile | leak | behaviour | observable | status | parse error |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| u0022 | 1 | True | True | True | True | not strict-evaluable |  |
| u0023 | 1 | True | True | True | True | not strict-evaluable |  |
| u0024 | 1 | True | True | True | True | not strict-evaluable |  |
| u0025 | 1 | True | True | True | True | not strict-evaluable |  |
| u0026 | 1 | True | True | True | True | not strict-evaluable |  |
| u0027 | 1 | True | True | True | True | not strict-evaluable |  |
| u0028 | 1 | True | True | True | True | not strict-evaluable |  |
| u0030 | 1 | True | True | True | True | not strict-evaluable |  |
| u0038 | 1 | True | True | True | True | not strict-evaluable |  |
| u0059 | 1 | True | True | True | True | not strict-evaluable |  |
| u0065 | 1 | True | True | True | True | not strict-evaluable |  |
| u0068 | 1 | True | True | True | True | not strict-evaluable |  |

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

### virtual-dispatch variant strict pass: `CWE401_Memory_Leak__new_twoIntsStruct_82__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_twoIntsStruct_82_bad.cpp
+++ b/CWE401_Memory_Leak__new_twoIntsStruct_82_bad.cpp
@@ -7,7 +7,7 @@
 void CWE401_Memory_Leak__new_twoIntsStruct_82_bad::action(twoIntsStruct * data)
 {
 
-    ;
+    delete data;
 }
 
 }
```

### LSan-insensitive baseline (not strict-evaluable): `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=False

```diff
--- a/CWE401_Memory_Leak__malloc_realloc_int64_t_01.c
+++ b/CWE401_Memory_Leak__malloc_realloc_int64_t_01.c
@@ -12,12 +12,14 @@
         data[0] = 5LL;
         printLongLongLine(data[0]);
 
-        data = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
-        if (data != NULL)
         {
-
-            data[0] = 10LL;
-            printLongLongLine(data[0]);
+            int64_t *tmp = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
+            if (tmp != NULL)
+            {
+                data = tmp;
+                data[0] = 10LL;
+                printLongLongLine(data[0]);
+            }
             free(data);
         }
     }
```

## Reproduction

```bash
python3 juliet_repair/scripts/prepare_inputs.py --force
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force
python3 juliet_repair/scripts/run_repair.py --model deepseek --concurrency 8 --out-dir juliet_repair/runs/deepseek_test70_final
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/deepseek_test70_final
```
