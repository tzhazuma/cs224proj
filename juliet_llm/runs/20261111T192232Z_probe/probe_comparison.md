# MiMo / DeepSeek request-configuration probe

Units: `CWE401_Memory_Leak__new_array_TwoIntsClass_54__bad`, `CWE401_Memory_Leak__malloc_realloc_char_01__bad`, `CWE401_Memory_Leak__new_array_TwoIntsClass_54__good`, `CWE401_Memory_Leak__malloc_realloc_char_01__good`

| Config | Model | Field | reasoning_effort | thinking | Valid | Reasoning tokens | p50 latency |
| --- | --- | --- | --- | --- | ---: | ---: | ---: |
| mimo_reasoning_none_max_completion_tokens | mimo-v2.6-flash | max_completion_tokens | none | disabled | 4/4 | 0.0 | 2.30 |
| mimo_legacy_max_tokens | mimo-v2.6-flash | max_tokens | None | disabled | 4/4 | 0.0 | 3.21 |

## Per-answer evidence

### mimo_reasoning_none_max_completion_tokens

- `CWE401_Memory_Leak__new_array_TwoIntsClass_54__bad` status=ok valid=True label=vulnerable reasoning_tokens=0 finish=stop latency=2.4211345890071243: {"label": "vulnerable", "confidence": 1.0, "reason": "new TwoIntsClass[100] allocated in sym_2 is passed through sym_1..sym_5 but never deleted, leaking at exit
- `CWE401_Memory_Leak__malloc_realloc_char_01__bad` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=3.043953375003184: {"label": "not_vulnerable", "confidence": 0.95, "reason": "Original pointer freed on success; realloc failure path leaves original block reachable only via lost
- `CWE401_Memory_Leak__new_array_TwoIntsClass_54__good` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=2.176514935999876: {"label": "not_vulnerable", "confidence": 0.95, "reason": "sym_5 allocates with new[] and sym_12 deletes it; sym_2 uses stack array, no leak."}
- `CWE401_Memory_Leak__malloc_realloc_char_01__good` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=2.0243637200037483: {"label": "not_vulnerable", "confidence": 0.95, "reason": "data is freed on all paths; realloc failure path still frees original pointer, no leak."}

### mimo_legacy_max_tokens

- `CWE401_Memory_Leak__new_array_TwoIntsClass_54__bad` status=ok valid=True label=vulnerable reasoning_tokens=0 finish=stop latency=3.4970863350026775: {"label": "vulnerable", "confidence": 1.0, "reason": "new TwoIntsClass[100] allocated in sym_2 is passed through sym_1..sym_5 but never deleted, leaking heap me
- `CWE401_Memory_Leak__malloc_realloc_char_01__bad` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=2.976350935001392: {"label": "not_vulnerable", "confidence": 0.95, "reason": "Original pointer freed on success; realloc failure path leaks only if realloc fails, which is rare an
- `CWE401_Memory_Leak__new_array_TwoIntsClass_54__good` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=3.444179666999844: {"label": "not_vulnerable", "confidence": 0.95, "reason": "sym_5 allocates with new[] and sym_12 deletes it; sym_2 uses stack array, no leak."}
- `CWE401_Memory_Leak__malloc_realloc_char_01__good` status=ok valid=True label=not_vulnerable reasoning_tokens=0 finish=stop latency=2.779885762996855: {"label": "not_vulnerable", "confidence": 0.95, "reason": "data is freed on all paths; realloc failure leaves original pointer valid and still freed."}
