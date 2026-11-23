# Speaker notes: "Do Memory-Leak Detectors Read Code or Templates?"

Talk: 17:00 for the slides and demo, then about 3 min of Q&A (course slot 15–20 min).
Numbers on the result slides come from `figures/numbers.tex`, so they change when `make` is rerun. Before the
talk, check that what you say matches the PDF. Every result is **preliminary**, so say so once on slide 13.

| # | Slide | Time | Running |
|---|-------|------|---------|
| 0 | Title | 0:20 | 0:20 |
| 1 | A one-line rule beats the analyzers | 1:00 | 1:20 |
| 2 | Where the shortcut comes from | 1:00 | 2:20 |
| 3 | Task and research questions | 0:50 | 3:10 |
| 4 | Layer ①: one entry per good unit | 1:00 | 4:10 |
| 5 | Shortcut probes before vs after | 1:00 | 5:10 |
| 6 | Are the labels still right? | 0:50 | 6:00 |
| 7 | Three evaluation layers | 1:10 | 7:10 |
| 8 | Split by flow variant | 0:50 | 8:00 |
| 9 | Method matrix | 0:50 | 8:50 |
| 10 | Four prompting strategies | 0:50 | 9:40 |
| 11 | L4: facts + Datalog | 1:10 | 10:50 |
| 12 | One 4B model, three uses | 1:00 | 11:50 |
| 13 | P / R / F1 | 1:00 | 12:50 |
| 14 | Accuracy vs latency | 0:50 | 13:40 |
| 15 | F1 by flow category | 0:50 | 14:30 |
| 16 | Live demo | 1:40 | 16:10 |
| 17 | Next steps and timeline | 0:40 | 16:50 |
| — | Thank you / Q&A | 0:10 | 17:00 |

Section-divider slides take no time; just click through them.

---

## 0. Title (0:20)
"We are rebuilding the Juliet memory-leak benchmark so that it measures leak detection, not template
reading. Then we compare static analyzers, LLMs and decision models on it."

## 1. A one-line rule beats the analyzers (1:00)
- Start with the table. The rule "if there is no free or delete in the unit, it leaks" gets macro-F1
  **0.940** on all 3,316 CWE-401 units.
- That beats ASan/LSan (0.914), Clang SA (0.888) and CodeQL (0.817). Be honest about the comparison: those
  three numbers come from our earlier 140-unit subset.
- `static void` appears in every good unit and in no bad unit. This is a label leak.
- Others have found this too: Germano et al. (ICAART'25), and Risse & Böhme (USENIX Sec'24, ISSTA'25).
- Punchline: high Juliet scores may measure template reading.

## 2. Where the shortcut comes from (1:00)
- Left: a bad unit. One function allocates and never frees.
- Right: the original good unit, a `good()` wrapper that calls two `static void` helpers. G2B uses
  stack memory (ALLOCA); B2G mallocs and then frees.
- Good units are longer, have more functions, and always contain `static`, so a classifier learns the
  shape.
- Note that we already rename functions to `sym_N`, so the name `good` is not the cue.

## 3. Task and research questions (0:50)
- Task: one unit in, leak / no-leak out. 1,658 bad/good pairs, 42 families, 48 flow variants.
- Read the four RQs: validity, strategy, efficiency, robustness.
- The main axis is the prompting strategy L1–L4, on an API LLM and on a 4B local model.

## 4. Layer ①: one entry per good unit (1:00)
- We split each original good unit into two good units, one per entry: G2B and B2G.
- We drop the wrapper and strip `static`. Now good and bad have the same shape.
- The G2B/B2G split is about 50/50 in every flow category.
- G2B good units contain no free at all (stack memory), so grep's rule is now wrong on half the good units.

## 5. Shortcut probes before vs after (1:00)
- Orange is the original, blue is layer ①. Read the probes from top to bottom.
- Format probes (`static void`, number of functions, lines, tokens) fall to about chance; the `static void` probe ends at 0.333.
- grep falls from 0.935 to 0.701.
- Bag-of-words still gets 0.979. That is fine, because its cues (free, delete, ALLOCA) are the task itself.
  Layer ③ attacks exactly those cues.
- Our acceptance rule: every format probe must be ≤ 0.60 on eval, and all of them pass.

## 6. Are the labels still right? (0:50)
- Both gcc and clang compile all 3,316 units.
- ASan/LSan reports all 1,658 good units as leak-free.
- On bad units LSan misses some leaks, and we know why: a failing realloc (0/108), memory still reachable
  from a global at exit, or a random branch. We never relabel. We explain the disagreements in the
  backup slide.
- So dynamic tools are a reference line, not ground truth.

## 7. Three evaluation layers (1:10)
- ① is the debiased main layer. ② is a filter of ①: bad units that do contain a free (harder for lexical
  rules).
- ③ is the stress test. We add frees that never run, guarded by conditions that can be decided inside one
  file. In a bad unit the dead free leaves it a leak. In a good unit the real free gets an always-true
  guard.
- Placebo: the same guards with no free, which separates the effect of "a free appeared" from "the code
  changed".
- Both labels get guarded frees, so grep drops to 0.333 on ③. Every transformed unit still compiles and
  passes the ASan check.
- RQ4 asks how far F1 drops from ① to ③, compared with the placebo drop.

## 8. Split by flow variant (0:50)
- Families differ mostly by data type (char_malloc vs int_malloc). A family split would therefore put the
  same program structure in train and test.
- So we split by flow variant. Dev has 9 variants (330 groups). Eval has 39 variants, 1,328 groups =
  2,656 units, in 3 folds.
- The fine-tuned model trains on two folds and predicts the third. Dev only selects prompts, thresholds and
  checkpoints, and we never report it.
- Metrics: P/R/F1 with leak as positive, macro-F1, family-bootstrap CI, McNemar + Holm.

## 9. Method matrix (0:50)
- Map the methods to the course. Cppcheck is intraprocedural dataflow. Clang SA is path-sensitive symbolic
  execution. CodeQL is Datalog-style queries. Infer Pulse uses interprocedural summaries.
- The learned baseline is LineVul, zero-shot.
- LLM API: DeepSeek V4.1 Flash. SLM: Qwen3.5-4B. Both run L1–L4.
- Decision models: Jev, Intern-Decision-4B, and our own LoRA model.
- ASan/LSan and Valgrind are shown but not ranked.
- A missing answer, a timeout or a compile error counts as wrong.

## 10. Four prompting strategies (0:50)
- L1 is direct. L2 adds fixed few-shot examples from dev; the shared prefix makes the API cache cheap.
- L3 adds the Clang SA warnings for this unit. L4 is neuro-symbolic (next slide).
- DeepSeek and Qwen get the same prompt text, at temperature 0 with thinking off. Prompts were frozen in
  git before any eval run.
- L3 latency includes running Clang, and L4 latency includes running Soufflé.

## 11. L4: facts + Datalog (1:10)
- The LLM does not decide. It only lists facts: alloc, realloc, free, assign, pass, ret, call, global,
  dead lines.
- Soufflé runs `leak.dl`: reachability from main, then Andersen-style points-to, then `freed`.
  `leak(o)` holds when an object is never freed, or when a failing realloc loses the old block.
- This is the lecture material made executable: Datalog, pointer analysis, interprocedural reach.
- Facts on dead lines are ignored, which is exactly what layer ③ tests.
- On dev (12 units), DeepSeek's facts parse 12/12 and the verdicts agree 10/12.

## 12. One 4B model, three uses (1:00)
- One set of Qwen3.5-4B weights is used three ways: generating answers (SLM line), reading out P(Yes)
  vs P(No) (zero-shot decision model), and fine-tuning a LoRA binary head.
- Score s = logit_Yes − logit_No, trained with balanced CE plus a ranking loss that pushes bad above good.
- LoRA r16, α32: 32.5 M trainable parameters = 0.70 %. 3 folds × {L1, L3}. Merged at inference, so it adds
  no latency.
- Deployment: IDE / pre-commit on a laptop CPU, a CI runner, or a nightly GPU server. Cascade: the cheap
  decision model goes first, and low-confidence cases go to DeepSeek.

## 13. P / R / F1 (1:00) — say "preliminary" here
- The grey slots are pending runs. We do not invent numbers for them.
- grep drops to macro-F1 ~0.70. LineVul is near chance. CodeQL is the best analyzer (~0.89), with Clang
  SA at ~0.84.
- DeepSeek L1–L3 is close to perfect (~0.996), and Jev is around 0.97–0.98.
- Caveat: Juliet is public, so the LLMs may have seen it. That is why layer ③ and latency/cost decide the
  ranking.

## 14. Accuracy vs latency (0:50)
- The x axis is log-scale median latency per unit. grep runs in microseconds, Clang SA in ~36 ms, and the
  APIs take ~0.6–0.9 s.
- The dashed line is the Pareto front of the methods we have so far.
- Hollow markers are batched or concurrent runs, so their latency is not per call at concurrency 1.
- Still missing: Intern-Decision (read-out ~83 ms on dev) and the LoRA model. They should land between
  Clang SA and the APIs, which is the region that matters for a laptop or a CI runner. Qwen generation is
  ~0.67 s on dev.

## 15. F1 by flow category (0:50)
- Rows are flow categories: baseline, control flow, data flow, cross-file, C++ objects.
- Cppcheck scores 0.00 on cross-file (51–68) and C++ objects (71–84). Clang SA is weakest on C++ objects
  (~0.60). LineVul is worst on the baseline (0.16).
- The LLMs look uniform on layer ①, so any per-category differences will have to show up on ② and ③.

## 16. Live demo (1:40)
- Switch to the terminal. `presentation/demo/demo.py` is owned by the demo lane; warm it up before the talk
  (`--warm`, `--check`).
- Step 1: run one eval unit through grep, Clang SA, the fine-tuned decision model (the fold that never saw
  this unit) and DeepSeek. Read out each verdict and its latency.
- Step 2: insert `if (sym_7 != 5) free(data);`, a free that never runs. The unit still leaks. Ask the room
  which verdicts will flip, then run it.
- If the network or the GPU fails: `demo.py --replay recordings/<run>.json`, or go to the backup screenshot
  slide.

## 17. Next steps and timeline (0:40)
- Until Dec 6: main runs on layer ① for all methods.
- Then L4 evaluation, the LoRA folds, and layer ③ + placebo.
- Then robustness analysis, the cascade and significance tests. The final report (IEEE, ≥10 pages) is due
  by Dec 24.
- Budget: DeepSeek stays under CNY 10. Qwen, Intern-Decision and LoRA run on 2× RTX 3090.

## Thank you (0:10)
"Do detectors read code or templates? Rebuild the benchmark before you rank them." Then open for questions.

---

## Q&A prep (≈3 min)

**Q: DeepSeek is at 0.996. Isn't the benchmark solved?**
On layer ①, yes, nearly, but Juliet is public and may be in the training data. That is why we built
layer ③: frees that never run, with a placebo control. A model that reads code keeps its verdict; a model
that pattern-matches "free means safe" flips. Latency and cost are the other ranking axes.

**Q: How do you know the new labels are correct?**
We never change a label. Every unit compiles with gcc and clang, and ASan/LSan reports all 1,658 good
units leak-free. The bad units LSan misses are explained: a failing realloc (108), memory reachable from a
global at exit (68), a random branch (8). See the backup slide.

**Q: Why `use_stacks=0` for LSan?**
With the defaults, stale -O0 stack slots of functions that have already returned still point to the
block, so LSan misses 175 more bad units. use_stacks=0 removes that false reachability.

**Q: Bag-of-words still gets 0.979 on layer ①. Isn't that a shortcut too?**
Its cues are free, delete and ALLOCA, which is what the task is about, not formatting. Layer ③ targets
exactly those cues: there BoW AUROC drops to 0.81 overall and 0.61 on B2G.

**Q: Why split by flow variant and not by family?**
Families differ mainly by data type, so a family split puts the same control/data-flow structure in train
and test. A flow-variant split tests unseen program structure.

**Q: Is the comparison with static analyzers fair? They were not built for Juliet.**
We map only each tool's leak checkers to the verdict (the mapping is documented in the static lane). A
compile error or missing output counts as wrong, and coverage is reported separately. The heatmap shows
where each tool breaks (Cppcheck on cross-file and C++).

**Q: Why does Infer recall less than CodeQL?**
Pulse reports only leaks it can prove, so its precision is high (~0.94) and its recall lower. The capture
setup matters a lot. When each source file was analyzed alone, Infer saw nothing in the cross-file and C++
categories (F1 0.56). Analyzing all of a unit's files as one translation unit, which is the run shown,
raises F1 to ~0.79. The static lane is still finalizing this, so treat it as preliminary.

**Q: What does L4 add if the LLM already gets 0.99?**
An auditable derivation: the leak follows from facts plus rules, and dead lines are excluded explicitly,
so we expect it to be the most robust strategy on layer ③. On dev, parsing works 12/12 and the verdicts
agree 10/12; the failure is identical facts for leaking and fixed realloc code.

**Q: Fine-tuning reaches AUROC 1.0 on dev after half an epoch. Overfitting?**
Layer ① is easy once a model is trained, which matches BoW. The model is trained only on layer ① and
tested on held-out flow variants, and layer ③ is the real robustness test. We will report merged-model
scores (the merge changes raw scores by up to 0.36, but not the ranking).

**Q: How much did the APIs cost?**
DeepSeek: about CNY 3 so far, with a cap of CNY 10 and a client hard stop at 9.5. Jev: about $0.04 of
$4.8. See the budget backup slide.

**Q: Why is the latency marker of some methods hollow?**
Those runs were batched (CodeQL, 50 units per database) or sent concurrently (APIs at concurrency 16), so
the median is not a single-call latency. Concurrency-1 latency samples come in the final report.

**Q: What about real-world code?**
Our earlier study on SecVulEval pairs found order and length biases (MiMo 86.7 % → 74.4 % when the order is
swapped; DeepSeek below a length heuristic). It is in the backup slides and the report appendix. Juliet
lets us control the labels exactly.
