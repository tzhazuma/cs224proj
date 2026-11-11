# Juliet CWE-401 repair: mimo-v2.6-flash

- run: `mimo_test70_final`
- model: `mimo-v2.6-flash`
- units: 70 frozen `split=test, label=bad` groups
- API calls: 72 (initial + at most one feedback iteration)
- cost: $0.005841
- prompt/completion tokens: 30826 / 15733

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
| first attempt | 69 | 68 | 68 | 57 |
| final (after optional iteration) | 70 | 70 | 70 | 58 |

- units that used the feedback iteration: 2 (1 after a real compile/LSan/behaviour failure, 1 after a schema/parse rejection)
- real-failure iterations that reached strict pass: 1
- rejected responses (schema/parse): 1
- final responses with the exact top-level schema: 66/70
- final responses including an explanation: 66/70
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
| u0023 | 2 | True | True | True | True | not strict-evaluable |  |
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

### virtual-dispatch variant strict pass: `CWE401_Memory_Leak__new_twoIntsStruct_82__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_twoIntsStruct_82a.cpp
+++ b/CWE401_Memory_Leak__new_twoIntsStruct_82a.cpp
@@ -18,6 +18,7 @@
     CWE401_Memory_Leak__new_twoIntsStruct_82_base* baseObject = new CWE401_Memory_Leak__new_twoIntsStruct_82_bad;
     baseObject->action(data);
     delete baseObject;
+    delete data;
 }
 
 
```

### needed feedback iteration: `CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad`

- attempts: 2; compile=True; leak=True; behaviour=True; strict=False

```diff
--- a/CWE401_Memory_Leak__malloc_realloc_int64_t_09.c
+++ b/CWE401_Memory_Leak__malloc_realloc_int64_t_09.c
@@ -14,12 +14,16 @@
             data[0] = 5LL;
             printLongLongLine(data[0]);
 
-            data = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
-            if (data != NULL)
+            int64_t * newData = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
+            if (newData != NULL)
             {
-
+                data = newData;
                 data[0] = 10LL;
                 printLongLongLine(data[0]);
+                free(data);
+            }
+            else
+            {
                 free(data);
             }
         }
```

### feedback iteration recovered a real failure: `CWE401_Memory_Leak__new_char_01__bad`

- attempts: 2; compile=True; leak=True; behaviour=True; strict=True

```diff
--- a/CWE401_Memory_Leak__new_char_01.cpp
+++ b/CWE401_Memory_Leak__new_char_01.cpp
@@ -11,12 +11,13 @@
     char * data;
     data = NULL;
 
-    data = new char;
+    data = new char[1];
 
     *data = 'A';
     printHexCharLine(*data);
 
-    ;
+    delete [] data;
+    data = NULL;
 }
 
 
```

### LSan-insensitive baseline (not strict-evaluable): `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad`

- attempts: 1; compile=True; leak=True; behaviour=True; strict=False

```diff
--- a/CWE401_Memory_Leak__malloc_realloc_int64_t_01.c
+++ b/CWE401_Memory_Leak__malloc_realloc_int64_t_01.c
@@ -12,13 +12,17 @@
         data[0] = 5LL;
         printLongLongLine(data[0]);
 
-        data = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
-        if (data != NULL)
+        int64_t * newData = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
+        if (newData != NULL)
         {
-
+            data = newData;
             data[0] = 10LL;
             printLongLongLine(data[0]);
             free(data);
         }
+        else
+        {
+            free(data);
+        }
     }
 }
```

## Reproduction

```bash
python3 juliet_repair/scripts/prepare_inputs.py --force
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force
python3 juliet_repair/scripts/run_repair.py --model mimo --concurrency 8 --out-dir juliet_repair/runs/mimo_test70_final
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/mimo_test70_final
```
