# Juliet CWE-401 repair: mimo-v2.6-flash

- run: `mimo_test70_v2`
- model: `mimo-v2.6-flash`
- units: 70 frozen `split=test, label=bad` groups
- API calls: 86 (initial + at most one feedback iteration)
- cost: $0.011578
- prompt/completion tokens: 48068 / 26724

## Headline metrics

| metric | all 70 | 58 LSan-observable |
| --- | ---: | ---: |
| compile pass | 70 | 58 |
| leak removed | 69 | 58 |
| behaviour preserved | 69 | 58 |
| strict pass | 58 | 58 |

`strict pass` requires compile, LSan-clean run, identical observable data lines, a non-vacuous behaviour signature, and a baseline where LSan actually observed a leak. The 12 units whose baseline does not leak under LSan are not strict-evaluable; their compile/behaviour results are reported but cannot prove leak removal.

## First attempt vs after feedback

| stage | compile | leak removed | behaviour | strict (58) |
| --- | ---: | ---: | ---: | ---: |
| first attempt | 69 | 67 | 67 | 56 |
| final (after optional iteration) | 70 | 69 | 69 | 58 |

- units that used the feedback iteration: 16
- rejected responses (schema/parse): 1
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
| u0024 | 2 | True | False | False | True |  |
| u0025 | 1 | True | True | True | True |  |
| u0026 | 1 | True | True | True | True |  |
| u0027 | 2 | True | True | True | True |  |
| u0028 | 1 | True | True | True | True |  |
| u0030 | 1 | True | True | True | True |  |
| u0038 | 1 | True | True | True | True |  |
| u0059 | 1 | True | True | True | True |  |
| u0065 | 1 | True | True | True | True |  |
| u0068 | 1 | True | True | True | True |  |

## Case studies

### multi-file strict pass: `CWE401_Memory_Leak__new_wchar_t_82__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_wchar_t_82.h
+++ b/CWE401_Memory_Leak__new_wchar_t_82.h
@@ -10,6 +10,7 @@
 public:
 
     virtual void action(wchar_t * data) = 0;
+    virtual ~CWE401_Memory_Leak__new_wchar_t_82_base() {}
 };
 
 
--- a/CWE401_Memory_Leak__new_wchar_t_82_bad.cpp
+++ b/CWE401_Memory_Leak__new_wchar_t_82_bad.cpp
@@ -6,8 +6,7 @@
 
 void CWE401_Memory_Leak__new_wchar_t_82_bad::action(wchar_t * data)
 {
-
-    ;
+    delete data;
 }
 
 }
```

### wide-character output preserved: `CWE401_Memory_Leak__new_array_wchar_t_01__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_array_wchar_t_01.cpp
+++ b/CWE401_Memory_Leak__new_array_wchar_t_01.cpp
@@ -16,7 +16,8 @@
     wcscpy(data, L"A String");
     printWLine(data);
 
-    ;
+    delete[] data;
+    data = NULL;
 }
 
 
```

### needed feedback iteration: `CWE401_Memory_Leak__char_malloc_01__bad`

- attempts: 2; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__char_malloc_01.c
+++ b/CWE401_Memory_Leak__char_malloc_01.c
@@ -14,5 +14,5 @@
     strcpy(data, "A String");
     printLine(data);
 
-    ;
+    free(data);
 }
```

### runtime or compile failure: `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad`

- attempts: 2; compile=True; leak=False; behaviour=False; strict=False

```diff
--- a/CWE401_Memory_Leak__malloc_realloc_int64_t_18.c
+++ b/CWE401_Memory_Leak__malloc_realloc_int64_t_18.c
@@ -14,13 +14,21 @@
         data[0] = 5LL;
         printLongLongLine(data[0]);
 
+        int64_t * oldData = data;
         data = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
         if (data != NULL)
         {
-
+            if (data != oldData)
+            {
+                free(oldData);
+            }
             data[0] = 10LL;
             printLongLongLine(data[0]);
             free(data);
         }
+        else
+        {
+            free(oldData);
+        }
     }
 }
```

## Reproduction

```bash
python3 juliet_repair/scripts/prepare_inputs.py --force
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force
python3 juliet_repair/scripts/run_repair.py --model mimo --concurrency 8 --out-dir juliet_repair/runs/mimo_test70_v2
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/mimo_test70_v2
```
