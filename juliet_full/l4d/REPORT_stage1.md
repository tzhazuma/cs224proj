# L4-D data lane — stage 1 report (lane l4d-data, dell, 2026-11-24)

Scope: contract `README.md` §0–3 and §6 inputs. The lane built the parser, the questions, the dynamic gold labels,
the rules and derive.py, the oracle check, and score_facts.py for layer1 (incl. the 48-unit sample), layer3, placebo
and original. Markers `build/SAMPLE_READY`, `build/LAYER1_READY` and `build/ALL_READY` are touched. Formats are in
`SCHEMA.md`.

## Files (sha256)

Code (all in `juliet_full/l4d/`):

| file | sha256 | role |
|---|---|---|
| parse_sites.py | 17f758c7fd367b4a543fbabb5e0f54685ac36f433c71bbc0dcc7d43463705ea6 | tree-sitter lexical site parser, masking |
| templates.py | 678d7c743c63b3e8d96005def26f10a2c0b3f9fef48dccc09189635ae76a56f1 | fixed templates; TEMPLATE_SHA256 = 316429b266c0258383724c8c9129e2ea17946a9013d72cb61b267261ef827516 |
| questions.py | f6a826f8cb2ff5e1d7646ac6c7c80ac6b516dbab025f8796a2143037b835005a | question rows (+ gold attach) |
| gold.py | 9420eb6837904def92a502f6758b3a47faa50b10afd94f01de07a435de21eea4 | gcov + alloc trace + realloc injection |
| gold/l4d_trace.c | 096bc3f4b0805d87e08aad8969d37930a7310deb9365d6be132d83026b5344dc | --wrap hooks |
| gold/l4d_trace_new.cpp | 3ac120fec91b101c410650989aa672a717a6fc99fc134cccdcfad28f8b3d3bbf | operator new/delete hooks |
| l4d.dl | ca2d6380230812ea92726aca0666fe3b4ae83dff9659d1d3764c3e1d01e714ec | contract v1 rules (unit-keyed) |
| derive.py | f3a0e6344b7c0d7d49eb72993f1fe53b4eea819600b6a670feddbc46c71265b7 | facts → verdict + soft score |
| oracle.py | 04ffc4f26164168fa0ccf11d2cd6e608f7552e84df6d0bf926854a2182cc89ce | gold-facts oracle + parser recall |
| score_facts.py | f31740b09522c3373549bdfa76c2eb84c680a5bfa46d95bb63f30d8c88ac3811 | question-level accuracy / AUROC |
| stats.py | 66c231aebcfdb00ef4581caa25c104b95b1e33a1ab56fe78f7973919fcdb8424 | per-unit counts + label balance |
| tests/test_l4d.py | 7356b7661e4c98f86d8ec111056e6095c705835c5bcaebcb83d8ecfaca215c3d | self-checks |
| SCHEMA.md | 17195780c1d36f30a8968d6381673d61d396824f6e9e0f9314f83ff63d5d27ce | formats |

Data (`juliet_full/l4d/build/`):

| file | sha256 |
|---|---|
| questions_layer1_sample.jsonl | 7402ec29580ff348f153f0280869702dd6363ad101dd92af6fdcf05e86344af0 |
| sites_layer1_sample.jsonl | eb18c4868c867aad3ca62f6df9743deb7f2d9c4614b7ab603a1171e82ea83dfa |
| questions_layer1.jsonl | 510e38b126aa90627023c6d43cb45d2ef3a27a8004747d6238f037f1e7d1de30 |
| sites_layer1.jsonl | 446e4630be228734ef659abd4d00d144e94498e4a647a98f7b1da81df3de4735 |
| questions_layer3.jsonl | 0264524d9a6d9898f351a2bc4c6f323b4f89f87636db9c1b3a0ddea17e5ae8f6 |
| sites_layer3.jsonl | 577979d6a589b07e5df6b7d9b1a85b6309c7f35dd729cf54ff3acd966bab0f87 |
| questions_placebo.jsonl | b0e816e5ef206b42bb5fae0647871c84a370e1836fc497de6b87c14d87721d89 |
| sites_placebo.jsonl | a0901fefc91e428c06b9e1606c9cffc43f1586b848cae80e7ecfcae80bde9ac0 |
| questions_original.jsonl | cdb4bdbe2309525c63f3e70c52684d5d75b64980805bf1dc25693eab29d2df98 |
| sites_original.jsonl | cd3d5b6ba9003f74d3a8e1d16a06276df566bb216e059f317541e33f776cc6ff |
| gold_layer1.jsonl / _layer1_sample / _layer3 / _placebo / _original | af62cf91… / b55da79e… / 414129c2… / f2d8941e… / c77af2d8… |
| layer1_stats.json, layer3_stats.json, placebo_stats.json, original_stats.json | f97eb6fc… / 3c8f5682… / 5cc93535… / b7081a0f… |
| oracle_<layer>.json, oracle_pred_<layer>.jsonl, qcounts_<layer>.json | see `sha256sum build/*` |

Logs: `raw_logs/gold_<layer>.log`, `raw_logs/questions_<layer>.log`.

## Method summary

- **Parser** (lexical, tree-sitter C / C++ over `model_text`, no constant evaluation): sites of kind alloc / release
  / realloc / stmt; stmt = first simple statement of every if/else/loop/case/default/catch block, plus every call
  statement; nothing in the fixed `main`. Parse errors: 0 on all layers.
- **Questions**: heap (alloc), exec_any + exec_all (every site, target masked by `__TARGET__();`, line numbers kept),
  rel (every (release ∪ realloc, alloc ∪ realloc) pair, f ≠ a), realloc_safe (realloc).
- **Gold**: instrumented copy of every unit in /tmp (each site on its own lines), `--coverage -O0 -no-pie`, 8 runs
  with `time()` → 1..8 (variant-12 `rand()` covers all branch combinations), gcov per run → exec_any/exec_all;
  backtrace-attributed malloc/calloc/realloc/strdup/wcsdup/free + operator new/delete trace → heap and rel; one
  extra run per distinct realloc call with that call failing → realloc_safe. Never-executed sites: heap by allocator
  name, rel and realloc_safe null. Runtime (8 jobs): layer1 63 s, layer3 78 s, placebo 86 s, original 90 s; 3,316/3,316
  units status ok on every layer, no notes (no nonzero exit codes).

## Question counts and label balance

Per unit (all units; full distributions per set and qtype in `build/<layer>_stats.json`):

| layer | units | questions | median / max per unit | sites alloc / release / realloc / stmt |
|---|---|---|---|---|
| layer1_sample | 48 | 512 | 9 / 23 | 34 / 22 / 18 / 137 |
| layer1 | 3,316 | 33,454 | 9 / 54 | 2,784 / 1,167 / 652 / 9,427 |
| layer3 | 3,316 | 46,273 | 13 / 66 | 2,784 / 5,396 / 652 / 9,427 |
| placebo | 3,316 | 41,912 | 11 / 58 | 2,784 / 1,167 / 652 / 13,656 |
| original | 3,316 | 71,124 | 18 / 74 | 4,714 / 2,599 / 978 / 20,354 |

Labels (yes / no / null):

| layer/set | exec_any | exec_all | heap | rel | realloc_safe |
|---|---|---|---|---|---|
| layer1 dev | 2367/328/0 | 2367/328/0 | 427/90/0 | 249/48/0 | 104/24/0 |
| layer1 eval | 9704/1631/0 | 9180/2155/0 | 1845/422/0 | 1181/461/19 | 439/84/1 |
| layer3 dev | 2367/1189/0 | 2367/1189/0 | 427/90/0 | 249/48/843 | 104/24/0 |
| layer3 eval | 9704/4999/0 | 9180/5523/0 | 1845/422/0 | 1181/461/3537 | 439/84/1 |
| placebo dev | 2367/1189/0 | 2367/1189/0 | 427/90/0 | 249/48/0 | 104/24/0 |
| placebo eval | 9704/4999/0 | 9180/5523/0 | 1845/422/0 | 1181/461/19 | 439/84/1 |
| original dev | 4668/568/0 | 4668/568/0 | 620/220/0 | 494/706/0 | 156/24/0 |
| original eval | 20319/3090/0 | 19621/3788/0 | 2834/1040/0 | 2478/4447/17 | 714/84/0 |

Sample (dev): exec_any 185/26, exec_all 185/26, heap 32/2, rel 30/8, realloc_safe 14/4.

## Oracle check (gold facts → derive.py --gold --souffle, rules v1 unchanged)

| layer | dev macro-F1 (n) | eval macro-F1 (n) | eval errors | criterion ≥ 0.99 |
|---|---|---|---|---|
| layer1_sample | 1.000 (48) | – | – | met |
| layer1 | 1.000 (660) | 0.9910 (2,656) | 24 FP | met |
| layer3 | 1.000 (660) | 0.9910 (2,656) | 24 FP | met |
| placebo | 1.000 (660) | 0.9910 (2,656) | 24 FP | met |
| original | 1.000 (660) | 0.9849 (2,656) | 40 FP | **not met** on eval |

Soufflé (one batch run of `l4d.dl` per layer, 0.05–0.15 s for 3,316 units) gave the same leak set as the Python
evaluator for every unit on every layer. `tests/test_l4d.py` also checks this on 300 random fact sets × 3 thresholds.

**Every failure is a variant-12 good unit** (layer1 dev has no variant-12 units, so no dev failure exists and no rule
was refined — the contract allows refinements only from layer1 dev failures).
- 36 leaked blocks on layer1/layer3/placebo (68 on original) are freed by two complementary frees
  `if(globalReturnsTrueOrFalse()) {free(data);} else {free(data);}`: each free has exec_any = 1, exec_all = 0, so
  `freed(a) :- rel(f,a), exec_all(f)` never fires.
- 24 leaked blocks (all layers) are the realloc_fail variant-12 goods: alloc and free inside the same random branch, so
  the only free has exec_all = 0.
- This is the ceiling of v1 for any answerer. It is a path-insensitivity limitation of the rule set: the facts are
  per-statement, and "some free on every path" cannot be expressed by them.
- Failing units (eval): layer1 / layer3 / placebo — the same 24 units: `CWE401_Memory_Leak__` + {char_malloc,
  int64_t_calloc, int64_t_malloc, int64_t_realloc, int_malloc, malloc_realloc_char, malloc_realloc_int64_t,
  malloc_realloc_int, malloc_realloc_struct_twoIntsStruct, malloc_realloc_twoIntsStruct, malloc_realloc_wchar_t,
  new_array_char, new_array_int64_t, new_array_int, new_array_twointsStruct, new_char, new_int64_t, new_int,
  new_struct_twoIntsStruct, new_wchar_t, strdup_char, strdup_wchar_t, struct_twoIntsStruct_malloc,
  twoIntsStruct_calloc} + `_12__good`. Original: 40 `_12__good` units (20 c_alloc, 14 cpp_new, 6 realloc_fail) = the 24 above
  plus {char_calloc, char_realloc, int_calloc, int_realloc, new_TwoIntsClass, new_array_TwoIntsClass,
  new_array_struct_twoIntsStruct, new_array_wchar_t, new_twoIntsStruct, struct_twoIntsStruct_calloc,
  struct_twoIntsStruct_realloc, twoIntsStruct_malloc, twoIntsStruct_realloc, wchar_t_calloc, wchar_t_malloc,
  wchar_t_realloc} + `_12__good` (their layer1 good units pass; the original goods also contain Juliet's goodB2G
  function with the complementary frees). Leaked sites per unit: `build/oracle_<layer>.json` → `failures`.
- The optional post-hoc variant v1b (complementary-branch rule) was **not** implemented.

**Parser recall** of trace-observed allocation lines: layer1 2,910/2,910, layer3 2,910/2,910, placebo 2,910/2,910,
original 4,420/4,420 (100% each, no missed unit).

## Derive timing

Python evaluator, per unit (fact building + rules + soft score), gold answers on dell: median 0.006 ms (layer1),
0.007 ms (layer3), 0.007 ms (placebo), 0.010 ms (original); p99 ≤ 0.07 ms; max 22–31 ms (one outlier per run,
first-call / GC). Soufflé is kept as the reference (`--souffle` batch check), not used for timing.
`latency_s` in the derive output is the derive time only; l4d-train must add the model time.

## Deviations from the contract

1. **realloc = one site kind `realloc`** that plays both roles (alloc in rel's `a`, release in rel's `f`;
   `heap_block(r) :- realloc(r)`, so no heap question for realloc sites). The contract lists "a realloc that consumes
   its input" under release and also has kind realloc; one site per statement keeps exec questions unique.
2. **Never-executed sites**: rel and realloc_safe gold null (cannot be observed); gold mode maps null → 0. This cannot
   change a v1 verdict because both rules require exec_any of the block site, and freed needs exec_all(f).
3. **Statements without code** (gcov has no line record: `default:` of `switch(6)`, `if(sym_N != 5)` dead frees on
   C++ `static const`, unused inline copy constructors / operator=): exec gold 0 with `gold_source gcov8:no_code`.
4. **Derive output layer names** use README §4 (`layer3` → `stress`); question rows keep `layer3`.
5. Extra fields beyond the contract: sites `end_line, span, callee, guard_first, src`; questions `lines` (=
   contract `line(s)`) and `site_kinds`; sites rows `parse_errors`.

## Risks for the training lane

- **Shortcut cue in exec negatives:** in layer1, 1,532 of 1,959 `exec_any = 0` questions are the masked line
  `if (data == NULL) {__TARGET__();}` (malloc never fails in the runs); original 2,322 of 3,658. A model can learn
  "target inside a NULL check → never". Other negatives are `__TARGET__();` on its own line (427 layer1; 4,656 on
  layer3/placebo — dead frees and placebo printLine under always-false guards).
- **Imbalance:** exec_any yes fraction ≈ 0.86–0.88 on layer1; heap ≈ 0.82; rel ≈ 0.71–0.84; realloc_safe ≈ 0.81–0.84.
  Reweight or subsample.
- **No "sometimes" in layer1 dev:** dev has no variant-12 unit, so exec_any = exec_all on every dev question; the
  only exec_any = 1 ∧ exec_all = 0 examples are the 80 variant-12 eval units (524 questions). Dev cannot validate the
  "sometimes" distinction.
- **rel cross-function cue (original):** 4,613 of 5,153 original rel = 0 pairs have f and a in different functions
  (different good/bad helper functions); on layer1 only 87 of 493 cross-function pairs are 0. A function-name
  heuristic works on original but not on layer1.
- **Null gold:** layer3 rel has 843 (dev) / 3,537 (eval) null labels (dead frees never execute); drop null questions in
  training and in fact scoring (score_facts.py skips them).
- **Unmasked code in non-exec questions** shows every statement, including the hidden target of exec questions about
  the same unit; exec masking is per-question only.
- **v1 ceiling:** with perfect facts, eval macro-F1 is 0.9910 (layer1/3/placebo) and 0.9849 (original); model
  results cannot exceed this ceiling except by compensating errors.
- Gold is from 8 seeded runs with gcc -O0; realloc injection fails each distinct realloc call once; the variant-12
  "sometimes" labels depend on glibc `rand()` with seeds 1..8 (checked during design: these seeds produce every
  combination of the random branches of the variant-12 drivers).

## Commands (reproduce)

```
cd juliet_full/l4d
.venv/bin/python gold.py --layer <layer> --jobs 8       # layer1_sample, layer1, layer3, placebo, original
.venv/bin/python questions.py --layer <layer>
python3 stats.py --layer <layer>
.venv/bin/python oracle.py --layer <layer>
.venv/bin/python tests/test_l4d.py
```
