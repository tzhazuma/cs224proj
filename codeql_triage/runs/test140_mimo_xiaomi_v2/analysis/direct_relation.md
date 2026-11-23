# Triage vs direct LLM — mimo-v2.6-flash-xiaomi-v2

Agreement: 0.9643; both correct: 132/140; triage right / direct wrong: 3; direct right / triage wrong: 2.
Direct FP ids: CWE401_Memory_Leak__int_malloc_22__good, CWE401_Memory_Leak__new_array_char_22__good, CWE401_Memory_Leak__new_array_int_22__good, CWE401_Memory_Leak__new_int_22__good, CWE401_Memory_Leak__twoIntsStruct_realloc_22__good.
Direct FN ids: CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad.

## On the 23 CodeQL FPs

- direct correct: 20/23
- triage one-shot dropped: 20/23
- final two-stage dropped: 23/23
- both correct: 20
- both wrong: 3
- direct wrong, triage right: 0
- direct right, triage wrong: 0
- direct wrong ids: CWE401_Memory_Leak__new_array_char_22__good, CWE401_Memory_Leak__new_array_int_22__good, CWE401_Memory_Leak__new_int_22__good

## On the 68 CodeQL TPs

- direct correct: 67/68
- triage kept: 68/68
- both correct: 67
- both wrong: 0
- triage deleted while direct right: 0
- direct wrong ids: CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad

## Oracle combinations (not deployable; ceiling only)

- CodeQL ∧ direct: TP/FP/TN/FN = 67/3/67/3, P=0.9571, R=0.9571, macro-F1=0.9571, MCC=0.9143
- CodeQL ∨ direct: TP/FP/TN/FN = 70/25/45/0, P=0.7368, R=1.0000, macro-F1=0.8155, MCC=0.6882

## Two-stage final (v2 + consistency verify) vs direct

- final: TP/FP/TN/FN = 68/0/70/2, P=1.0000, R=0.9714, macro-F1=0.9857, MCC=0.9718
- paired delta macro-F1: +0.0286 (95% CI [-0.0072, +0.0714]), exact McNemar p=0.289062

The two-stage final is not a free improvement: it adds a second request per CodeQL alert and keeps the 2 CodeQL false negatives. The one-shot v2 result is reported separately.