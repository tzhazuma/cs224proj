# DeepSeek vs MiMo on Juliet CWE-401 repair

Same 70 frozen bad units, same sanitised inputs, same compile/LSan/behaviour harness. Each model got one initial request and at most one compiler/LSan/behaviour feedback iteration.

| metric | DeepSeek V4.1 Flash | MiMo V2.6 Flash |
| --- | ---: | ---: |
| compile pass (all 70) | 70 | 70 |
| leak removed (all 70; 12 vacuous) | 70 | 70 |
| behaviour preserved (all 70) | 70 | 70 |
| strict pass (all 70; non-evaluable fail) | 58 | 58 |
| strict pass (58 observable) | 58 | 58 |
| first-attempt strict (58 observable) | 58 | 57 |
| units using feedback | 0 | 2 |
|   after real compile/LSan/behaviour failure | 0 | 1 |
|   after schema/parse rejection | 0 | 1 |
| rejected responses | 0 | 1 |
| API errors | 0 | 0 |
| total calls | 70 | 72 |
| cost USD | $0.026990 | $0.005841 |

## Denominator

58 of the 70 frozen bad units emit a LeakSanitizer leak under the harness's root-set configuration (`use_stacks=0:use_registers=0`). The other 12 are listed in each individual report; they cannot support a leak-removal claim. Strict pass is reported over both the full 70 and the 58 observable units.

## Per-unit outcomes

| unit | deepseek-v4.1-flash | mimo-v2.6-flash |
| --- | --- | --- |
| u0001 | strict pass | strict pass |
| u0002 | strict pass | strict pass |
| u0003 | strict pass | strict pass |
| u0004 | strict pass | strict pass |
| u0005 | strict pass | strict pass |
| u0006 | strict pass | strict pass |
| u0007 | strict pass | strict pass |
| u0008 | strict pass | strict pass |
| u0009 | strict pass | strict pass |
| u0010 | strict pass | strict pass |
| u0011 | strict pass | strict pass |
| u0012 | strict pass | strict pass |
| u0013 | strict pass | strict pass |
| u0014 | strict pass | strict pass |
| u0015 | strict pass | strict pass |
| u0016 | strict pass | strict pass |
| u0017 | strict pass | strict pass |
| u0018 | strict pass | strict pass |
| u0019 | strict pass | strict pass |
| u0020 | strict pass | strict pass |
| u0021 | strict pass | strict pass |
| u0022 | not leak-observable | not leak-observable |
| u0023 | not leak-observable | not leak-observable |
| u0024 | not leak-observable | not leak-observable |
| u0025 | not leak-observable | not leak-observable |
| u0026 | not leak-observable | not leak-observable |
| u0027 | not leak-observable | not leak-observable |
| u0028 | not leak-observable | not leak-observable |
| u0029 | strict pass | strict pass |
| u0030 | not leak-observable | not leak-observable |
| u0031 | strict pass | strict pass |
| u0032 | strict pass | strict pass |
| u0033 | strict pass | strict pass |
| u0034 | strict pass | strict pass |
| u0035 | strict pass | strict pass |
| u0036 | strict pass | strict pass |
| u0037 | strict pass | strict pass |
| u0038 | not leak-observable | not leak-observable |
| u0039 | strict pass | strict pass |
| u0040 | strict pass | strict pass |
| u0041 | strict pass | strict pass |
| u0042 | strict pass | strict pass |
| u0043 | strict pass | strict pass |
| u0044 | strict pass | strict pass |
| u0045 | strict pass | strict pass |
| u0046 | strict pass | strict pass |
| u0047 | strict pass | strict pass |
| u0048 | strict pass | strict pass |
| u0049 | strict pass | strict pass |
| u0050 | strict pass | strict pass |
| u0051 | strict pass | strict pass |
| u0052 | strict pass | strict pass |
| u0053 | strict pass | strict pass |
| u0054 | strict pass | strict pass |
| u0055 | strict pass | strict pass |
| u0056 | strict pass | strict pass |
| u0057 | strict pass | strict pass |
| u0058 | strict pass | strict pass |
| u0059 | not leak-observable | not leak-observable |
| u0060 | strict pass | strict pass |
| u0061 | strict pass | strict pass |
| u0062 | strict pass | strict pass |
| u0063 | strict pass | strict pass |
| u0064 | strict pass | strict pass |
| u0065 | not leak-observable | not leak-observable |
| u0066 | strict pass | strict pass |
| u0067 | strict pass | strict pass |
| u0068 | not leak-observable | not leak-observable |
| u0069 | strict pass | strict pass |
| u0070 | strict pass | strict pass |
