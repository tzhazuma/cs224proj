# Second-pass consistency verification — mimo-v2.6-flash-xiaomi-v2

Targets: 91 CodeQL alerts; verified: 91 (1.0000); changed decisions: 3.
Fixed FP: 3; broken TP: 0; recovered TP: 0; new FP: 0.

| unit | label | variant | before | after | first alert | verified alert | first leak | verified leak | release gap |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| `CWE401_Memory_Leak__new_array_char_22__good` | 0 | 22 | keep | drop | true_positive | false_positive | True | False | none |
| `CWE401_Memory_Leak__new_array_int_22__good` | 0 | 22 | keep | drop | true_positive | false_positive | True | False | none |
| `CWE401_Memory_Leak__new_int_22__good` | 0 | 22 | keep | drop | true_positive | false_positive | True | False | none |