# Compile-error units — mimo-v2.6-flash-xiaomi-v2

These four test units are `compile_error` in the frozen CodeQL run. They are not silently scored as CodeQL negatives: the end-to-end table counts them as no alert, and this table shows what each model did on the cleaned source view.

| unit | language | label | CodeQL | direct | triage alert | triage leak | triage final |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CWE401_Memory_Leak__new_twoIntsStruct_82__bad` | cpp | bad | compile_error | 1 | uncertain | True | drop |
| `CWE401_Memory_Leak__new_twoIntsStruct_82__good` | cpp | good | compile_error | 0 | no_alert | False | drop |
| `CWE401_Memory_Leak__new_wchar_t_82__bad` | cpp | bad | compile_error | 1 | uncertain | True | drop |
| `CWE401_Memory_Leak__new_wchar_t_82__good` | cpp | good | compile_error | 0 | no_alert | False | drop |