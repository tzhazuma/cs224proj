# L4 freeze proposal (v3c) — dev only, no eval calls made

Pipeline: DeepSeek (deepseek-flash, thinking off, temperature 0, JSON mode off, max_tokens 512) lists facts
from a line-numbered listing → `llmlane/l4.py:parse_facts(text, model_text)` (schema check, name
normalisation, grounding check against the cited line, alias `delete(...)` → `free(...)`) → Souffle 2.5
`l4/leak.dl` → pred = 1 iff `leak/2` non-empty. Schema and rules: `l4/SCHEMA.md`.

## Artifacts to freeze
| item | value |
|---|---|
| prompt hash (PromptSet("L4","chat").prompt_hash) | `00a81aa6fe372e612d3ea9430b11a7087b6c569a2ed8b0ecacf89958045365e6` |
| prompts/l4_system.txt sha256 | `a2585147df59859980a769a98e8173a40582acdebf151fddcc4a6148e8ffe657` |
| prompts/l4_user.txt sha256 | `1c9e7f86eeef3954732efdb22bfa65479e6b89856007699e2d04ac63ef0bfad6` |
| l4/leak.dl sha256 | `ee9cc78ed05b5c496a60e77b33f69584dc6bd58408e77dac2f8a76b3fb057dbc` |
| llmlane/l4.py sha256 (parser + grounding) | `22f3e53c49456df424c7c922af0b446a13f0c6d500f575605eb8f68320eeffff` |

## Dev numbers (all DEV; `l4_eval.py` offline re-parse of stored answers with the frozen parser/rules)
Samples (`make_dev_check.py`, stratified flow × mechanism, L2 example groups excluded, disjoint):
design30 (60 units, seed 20261124), confirm60 (120, seed 20261125), holdout40 (80, seed 20261126).

| prompt | sample | n | strict parse | grounded facts | agree | FP | FN | cost CNY |
|---|---|---|---|---|---|---|---|---|
| v3 (9f8c5857) | design30 | 59 | 1.000 | 175/184 | 0.932 | 0 | 4 | 0.0349 |
| v3b (06467f5e) | design30 | 60 | 1.000 | 192/192 | 0.983 | 1 | 0 | 0.0352 |
| v3b (06467f5e) | confirm60 | 120 | 1.000 | 431/432 | 0.975 | 3 | 0 | 0.0684 |
| **v3c (00a81aa6)** | **holdout40** | 80 | 1.000 | 298/298 | **1.000** | 0 | 0 | 0.0480 |
| **v3c (00a81aa6)** | confirm60 | 120 | 1.000 | 448/448 | 1.000 | 0 | 0 | 0.0712 |

- Clean held-out estimate for v3c: holdout40 only (80/80; it was run after the v3c prompt was fixed).
  confirm60 is not held out: its v3b errors motivated v3c (the container `push_back` example) and its one
  v3c error (`delete(data, …)` fact name, FP on new_TwoIntsClass_17__good) motivated the `delete` alias;
  without the alias v3c confirm60 is 119/120 parse, 119/120 agree.
- v3c over 200 units (holdout40 + confirm60): parse 200/200, agreement 200/200, realloc_fail bad 8/8 and
  realloc 'other' good 8/8 (the v2 failure: identical facts for the leaking and fixed realloc versions).
- Mean cost per unit ≈ 0.00060 CNY off-peak (≈1150 prompt tokens, ~51 completion tokens); full eval
  (2656 units) ≈ CNY 1.6 projected.
- Caveats: dev samples are small (200 units; 95% lower bound for 80/80 ≈ 0.955); realloc units are few
  (8+8); the facts are flow-insensitive, so programs where reachability depends on control flow beyond
  constant-dead branches rely on the model's `dead(Line)` facts; Juliet memorisation by the model cannot be
  excluded (as for L1–L3).

## Proposed freeze
Freeze the five artifacts above as L4 v3c. If an eval run is approved: `run_llm.py --model deepseek
--strategy L4 --set eval --allow-eval` after adding the L4 hash to `FROZEN_PROMPT_HASHES` (currently eval
L4 is refused by design), `--max-cost 2.0`, off-peak.
