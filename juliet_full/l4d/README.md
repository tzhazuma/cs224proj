# juliet_full/l4d — L4-D contract (parent-owned, 2026-11-23 22:30 PST)

L4-D is the **decision-model version of L4**. It works in three steps:

1. A lexical parser lists the candidate sites in a unit.
2. A decision model answers typed **Yes/No** questions about those sites. The answers are its facts.
3. Datalog rules derive the leak verdict from the facts.

The main method is **LoRA L4-D**: Qwen3.5-4B + LoRA, trained to answer the fact questions. The training labels come
automatically from dynamic analysis. The research question is whether LoRA L4-D reaches **near-LLM quality at
decision-model speed on all four layers** (Debiased = layer1, DeadFree = layer3, Placebo = placebo, Orig = original).

Only the parent edits this file, `../../PLAN.md` and `../STATUS.md`. If a lane needs an interface change, it reports
the request instead of editing.

The general rules of `../README.md` §1 apply to every lane:
- Write only in your own directories.
- No git commands that change state.
- Never print or copy API keys.
- No system-wide installs; bulk outputs go under `build/`, `scratch/` or `raw_logs/`.

## 0. Lanes and write boundaries

| Lane | Directory | Machine |
|---|---|---|
| **l4d-data** | `juliet_full/l4d/` (this directory) | dell (CPU) |
| **l4d-train** | `juliet_full/l4d_ft/` and `184-toast:~/disk4/cs224/l4d_ft/` | dell + 184-toast GPUs |

**l4d-data owns** the parser, the sites, the questions, the gold labels, the Datalog rules, the derivation script and
the oracle check.

**l4d-train owns** training, prediction, the endpoint and latency. It may *run* the scripts of l4d-data, but must not
edit them.

**Inputs** (read-only):
- `juliet_full/data/build/{layer1,layer3,placebo,original}.jsonl`, with fields `unit_id, group_id, family, variant,
  flow_category, mechanism, language, set (dev|eval), fold (0|1|2|null), label, truth, good_kind, program_dir, build,
  entry, model_text, line_map`
- the compiled program dirs `data/build/programs*/`
- `juliet_full/data/build/subsets.json` (`nested25`, `latency300`, ...)

## 1. Candidate sites (l4d-data → `build/sites_<layer>.jsonl`, one row per unit)

Each row is
`{unit_id, layer, sites: [{site_id, kind, line, func, text, var}], guards: [...]}`.

- `kind` is one of:
  - `alloc`: a call to `malloc`, `calloc`, `realloc`, `strdup`, `wcsdup`, `new`, `new[]`, `ALLOCA`, `alloca`, …
  - `release`: `free`, `delete`, `delete[]`, or a `realloc` that consumes its input
  - `realloc`
  - `stmt`: any other statement that is the first statement of a guarded block (`if`/`else`/loop/`switch case`), or a
    call statement
- `line` is the 1-based line in `model_text`, which is what the model sees.
- The parser is **lexical only**: regex or tree-sitter over `model_text`. It must not evaluate conditions or constants.
- Listing ALLOCA/alloca as `alloc` candidates is intended. The `heap` question decides them.

## 2. Questions (l4d-data → `build/questions_<layer>.jsonl`, one row per question)

Each row is
`{qid, unit_id, layer, set, fold, qtype, site_ids, line(s), state, question, gold, gold_source}`.

All questions are binary (Yes = 1). The fixed templates live in `l4d/templates.py`; their hash is recorded.

| qtype | Asked for | Question (meaning) |
|---|---|---|
| `heap` | every `alloc` site | Does the call at line L allocate heap memory that the program must release? Stack memory such as `ALLOCA`/`alloca`, static buffers and string literals do not count. |
| `exec_any` | every `alloc`, `release`, `realloc` and `stmt` site | Can the statement at line L execute on at least one run? |
| `exec_all` | the same sites | Does the statement at line L execute on every run? |
| `rel` | every (release f, alloc a) pair in the unit | Does the release at line Lf free the block obtained at line La? The block may have been passed to another function or copied to another variable. |
| `realloc_safe` | every `realloc` site | If this realloc fails and returns NULL, is the original block still released later? |

- **`state`** is the numbered `model_text` that the model sees.
- **Masking for `exec_*` questions (mandatory).** The target statement is replaced by one fixed neutral marker
  statement, for example `__TARGET__();`, and the question refers to it. The answer must therefore depend on the
  control flow (guards, calls, loops) and not on what the statement is. Use the same masking for every site kind and
  on every layer.
- **`gold`** comes from dynamic analysis of the compiled programs; `gold_source` says which method.
  - **Line coverage** (e.g. gcc `--coverage` + gcov, mapped to `model_text` lines through `line_map`) gives `exec_any`
    and `exec_all`. Use ≥ 8 runs per program, so that variant-12 randomness yields "sometimes": `exec_any` = 1 and
    `exec_all` = 0.
  - **An allocation/release trace** gives `rel` and `heap` for executed sites. For example: `-Wl,--wrap=` wrappers for
    the C allocators and `free`, plus overridden global `operator new/new[]/delete/delete[]` that use
    `__builtin_return_address(0)` → addr2line. Sites that never execute fall back to the allocator name.
  - **`realloc_safe`** comes from realloc-failure injection, as in the data lane's `dynamic_enhanced`, or from the
    Juliet structure if that is documented and checked.
  - Gold labels are produced for **all** layers. Training may use **layer1 training folds only**; gold labels of other
    layers are used only for fact-accuracy reporting.
- **Question volume.** Record the distribution of questions per unit. Training lanes subsample; prediction asks every
  question.

## 3. Derivation (l4d-data → `l4d/l4d.dl` + `l4d/derive.py`)

Rules, v1. Lane l4d-data may refine them **on layer1 dev only**, and every refinement must keep passing the oracle check.

```
freed(a)  :- rel(f, a), exec_all(f).
leak(a)   :- heap(a), exec_any(a), !freed(a).
leak(a)   :- realloc(a), exec_any(a), !realloc_safe(a).
unit_leak :- leak(_).
```

`derive.py --answers <qid→p_yes jsonl> --questions <questions jsonl> --tau <τ> [--souffle]` writes unit-level
predictions in the standard format of `../README.md` §4: `{unit_id, method, strategy:"L4D", model, layer, pred,
score, latency_s, status, extra}`.
- **Hard verdict:** each fact is true when `p_yes ≥ τ`; then Soufflé, or an exactly equivalent Python evaluator that
  has been tested against Soufflé, derives the verdict.
- **Soft score** (for AUROC):
  `max_a [ p_heap(a) · p_any(a) · Π_f (1 − p_rel(f,a) · p_all(f)) ]`, plus the analogous realloc term.

**Oracle check (acceptance of the decomposition).**
- Gold facts → `derive.py` must give macro-F1 ≥ 0.99 on every layer (dev and eval). List each failure with its cause.
- The parser must find ≥ 99.5% of the allocation sites seen in the dynamic trace.

## 4. Model answers (l4d-train → `l4d_ft/results/<method>/<layer>/<run_id>.jsonl`)

- **Question level:** `{qid, unit_id, qtype, p_yes, logit_diff, model, fold}`.
- **Unit level:** the output of `derive.py` in the same directory, `<run_id>_units.jsonl`, plus a `.meta.json`.
- **Methods:**
  - `lora_l4d`: the main method. Each fold model predicts only its held-out eval fold; the dev predictions come from
    each fold model.
  - `qwen_readout_l4d`: the base model with the step-0 head, zero-shot. Required.
  - `intern_l4d`: optional.

## 5. Training rules (l4d-train)

- **Model:** the same architecture as `../decision_ft/README.md` §3 (Qwen3.5-4B, LoRA r16 α32 dropout 0.05 on the
  explicit language-model linear modules, FP32 2×2560 head initialised from the tied Yes/No rows,
  s = logit_Yes − logit_No, chat template with `enable_thinking=False`).
- **Data:**
  - Fold k trains on the layer1 **eval** units of the other two folds. Layer1 **dev** (330 groups) is validation only.
  - No layer3, placebo or original data may be used in any form before the freeze.
- **Loss:** cross-entropy, class-balanced per (qtype, label). Subsample questions so that one fold job takes
  ≤ ~2.5 GPU-h (≤ 1–2 epochs).
- **Selection:** choose the checkpoint and τ on layer1 dev. Use the unit-level macro-F1 obtained through `derive.py`;
  break ties by question-level AUROC. Then write `l4d_ft/FROZEN` with the adapter/head hashes, τ, the template hash,
  the rules hash and the derive.py hash. Notify the parent **before** running any eval-set or non-layer1 prediction.
- **Prediction:** merged weights, as in decision_ft. Batch all questions of one unit into one forward batch.
- **Parallelism (user 2026-11-23 22:16: "务必并行训练，节省时间").** Keep both GPUs busy throughout; no serial step where parallel is possible.
  - Default schedule: folds 0 and 1 start together, one per GPU. Fold 2 starts the moment either GPU is free.
  - Use the smoke-test measurements to choose whichever option gives the smaller wall-clock time:
    - (a) 2-GPU DDP per fold (torchrun), with the folds run one after another, if the speedup is ≥ 1.6×;
    - (b) two jobs co-located on one GPU, if the peak memory per job is ≤ 11 GB.
  - Selection is **per fold**: fold k's checkpoint and τ are chosen on layer1 dev from fold k's model only.
  - Its entry, with a timestamp, goes into `l4d_ft/FROZEN` (one entry per fold) before **that fold's** eval or non-layer1 predictions start.
  - While one GPU trains fold 2, the other GPU runs the work that is already allowed: dev selection for folds 0 and 1, their frozen eval predictions, and `qwen_readout_l4d`. CPU work (rendering, scoring) runs in parallel with the GPU jobs.
- No old-LoRA-on-L4-D control (user decision 22:16).
- **Latency:** end to end, measured from dell at concurrency 1 on the `latency300` units of layer1, GPU otherwise idle.
  The time covers parse + questions + derive. Wrap the measurement in `flock /tmp/cs224_latency.lock` and start only
  when load1 < 2.5.

## 6. Pre-registered success criteria (PLAN §4.2, fixed before any L4-D run)

- **Reference:** DeepSeek L1 on the same units. Layer1 = full eval, 2,656 units. Layer3, placebo and original =
  nested25, 664 units. Also report the best DeepSeek strategy.
- **near-LLM on a layer:** macro-F1 ≥ ref − 0.02.
- **equivalent within 2 points:** the lower bound of the 95% family-cluster paired bootstrap CI of Δ is ≥ −0.02.
- **decision-model speed:** e2e c1 median ≤ 0.36 s.
- Report every layer whatever the outcome.

## 7. GPU schedule on 184-toast (hard constraint)

- **Running now:** the `:8003` LoRA endpoint on GPU 0; Qwen vLLM `:8001` and Intern-Decision `:8002` on GPU 1.
- l4d-train may stop them for training:
  - `bash ~/disk4/cs224/decision_ft/server/serve.sh stop`
  - `bash ~/disk4/cs224/gpu/server/svc.sh decide stop; bash ~/disk4/cs224/gpu/server/svc.sh qwen stop`
- **All three must be running and healthy again by 2026-11-25 12:00 PST**, because the presentation with the live demo
  is on Thursday 11-26 (Beijing). Start Qwen first (`svc.sh qwen start`, then `svc.sh decide start`; see
  `../gpu/README.md` §2), then `serve.sh start`. If training is not finished by then: checkpoint, restore the
  services, report, and resume only after the parent agrees.
