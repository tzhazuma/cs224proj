# Speaker notes: "Near-LLM Quality at Decision-Model Speed?"

Talk: 17:00 for slides and live demo, then about 3 min of Q&A (course slot 15–20 min).
Every result number on the slides comes from `figures/numbers.tex` (written by `make figures` from the result
files), so a rerun of `make` may move the third decimal. Check the PDF before the talk. All scores are macro-F1 on
the eval set (2,656 units, 39 flow variants never used for prompt or threshold choice) unless a slide says otherwise.
Grey "pending" cells are runs that had not landed at the last `make`: say "pending", never guess.

| # | Slide | Time | Running |
|---|-------|------|---------|
| 0 | Title | 0:20 | 0:20 |
| 1 | On original Juliet, a one-line rule beats every static analyzer | 1:00 | 1:20 |
| 2 | Where the shortcut comes from | 0:40 | 2:00 |
| 3 | Task and research questions | 0:40 | 2:40 |
| 4 | Layer ①: one entry per good unit | 0:50 | 3:30 |
| 5 | Shortcut probes before vs after | 0:40 | 4:10 |
| 6 | Layer ③: frees that never run (+ placebo) | 1:00 | 5:10 |
| 7 | Split by flow variant | 0:40 | 5:50 |
| 8 | Method matrix | 0:40 | 6:30 |
| 9 | Strategy ladder L1–L4 | 0:50 | 7:20 |
| 10 | One 4B model, three uses | 0:40 | 8:00 |
| 11 | Layer ① results | 0:50 | 8:50 |
| 12 | Accuracy vs latency | 0:50 | 9:40 |
| 13 | **Robustness (key slide)** | 1:20 | 11:00 |
| 14 | Fine-tuning teaches the shortcut | 1:10 | 12:10 |
| 15 | L4: facts + Datalog | 0:50 | 13:00 |
| 16 | Live demo | 2:40 | 15:40 |
| 17 | Limitations | 0:40 | 16:20 |
| 18 | Take-aways and next steps | 0:30 | 16:50 |
| — | Thank you / Questions | 0:10 | 17:00 |

Section dividers take no time; click through them. If the demo fails, switch to the replay (backup "demo
replay" slide) and keep the 2:40.

---

## 0. Title (0:20)
"Juliet is the standard benchmark for memory leaks. We show that on its original form a one-line rule wins,
rebuild it, and then ask which detectors actually read the code."

## 1. On original Juliet, a one-line rule beats every static analyzer (1:00)
- The table is the original benchmark, all methods on the same eval units.
- The probe "`static void` ⇒ good" gets **1.000**: `static void` is in every good unit and no bad unit.
- The rule "no `free`/`delete` ⇒ leak" gets **0.935**, above Clang SA 0.822, CodeQL 0.785 and Infer 0.770.
- The right column is our debiased layer ①: both shortcuts collapse (0.333 and 0.701).
- DeepSeek's original number (0.961†) is on the nested25 subset of 664 units, because of the API budget.
- Others saw template shortcuts too: Germano et al. (ICAART'25), Risse & Böhme (USENIX Sec'24, ISSTA'25).

## 2. Where the shortcut comes from (0:40)
- Left, a bad unit: one function allocates and never frees.
- Right, the original good unit: two `static` helpers (G2B on the stack, B2G with a free) plus a wrapper.
- Length, number of functions and `static` all give the label away. Names are already anonymized to `sym_N`.

## 3. Task and research questions (0:40)
- One unit in, leak / no leak out. 1,658 bad/good groups, 42 families, 48 flow variants.
- RQ1 validity, RQ2 strategy L1–L4, RQ3 accuracy vs latency, RQ4 robustness to a `free` that never runs.

## 4. Layer ①: one entry per good unit (0:50)
- Split every original good unit into its two entries, G2B and B2G; drop the wrapper; strip `static`.
- Now good and bad have the same shape. G2B/B2G is about 50/50 in every flow category.
- G2B goods have no free at all (stack memory), so grep's rule is wrong on half of the goods.

## 5. Shortcut probes before vs after (0:40)
- Format probes (`static void`, function count, lines) fall to about chance; `static void` ends at 0.333.
- grep drops from 0.935 to 0.701.
- Bag-of-words still gets 0.979: its cues (`free`, `delete`, `ALLOCA`) are the task itself. Layer ③ attacks exactly
  those cues.

## 6. Layer ③: frees that never run, plus placebo (1:00)
- Stress test: add a `free` under a guard that can be decided inside the file. In a bad unit it never runs, so the
  unit still leaks. In a good unit the real free gets an always-true guard.
- Placebo: the same guard with no `free`. It separates "a free appeared" from "the code changed".
- Both labels get guarded frees, so "has a free" no longer says anything: grep goes to 0.333.
- Every transformed unit compiles with gcc and clang, and labels are re-checked dynamically.

## 7. Split by flow variant (0:40)
- Families differ mostly by data type (char vs int), so a family split leaks program structure into test.
- Dev = 9 variants (330 groups) for prompts, thresholds, checkpoints. Eval = 39 variants (1,328 groups) in 3 folds.
- Our LoRA trains on two folds and predicts the third; all three held-out folds together give one prediction per
  eval unit.

## 8. Method matrix (0:40)
- Static tools map to the course: Cppcheck dataflow, Clang SA path-sensitive symbolic execution, CodeQL
  Datalog-style queries, Infer interprocedural summaries.
- LineVul zero-shot, DeepSeek and Qwen with L1–L4, three decision models.
- Dynamic tools are shown grey: they run the program, so they answer a different question (Q&A).
- A missing answer, timeout or compile error counts as wrong.

## 9. Strategy ladder L1–L4 (0:50)
- L1 direct, L2 few-shot, L3 adds Clang SA's warnings, L4 neuro-symbolic.
- L4: the LLM only lists facts (alloc, free, assign, pass, ret, call, global, dead lines). Soufflé runs `leak.dl`,
  reachability + Andersen-style points-to. The verdict comes from Datalog, not from the LLM.
- Same prompt text for DeepSeek and Qwen, temperature 0, prompts frozen in git before any eval run.

## 10. One 4B model, three uses (0:40)
- Same Qwen3.5-4B weights: generate (SLM line), read out P(Yes) vs P(No) (zero-shot ablation; Intern-Decision-4B
  is the tuned decision model), and fine-tune a LoRA binary head.
- s = logit_Yes − logit_No; balanced CE + a ranking loss that puts bad above good. r16, α32, 0.70 % trainable.
- Deployment targets: laptop IDE / pre-commit, CI runner, nightly GPU server.

## 11. Layer ① results (0:50)
- Bars are macro-F1 with 95 % CI; the tick is precision and the circle recall of the leak class.
- Best analyzer CodeQL 0.882; Clang SA 0.855; grep 0.701; LineVul about chance (0.501).
- DeepSeek L1 0.995, our LoRA 0.984, Jev 0.97–0.98. Qwen and Intern-Decision zero-shot are 0.75–0.88.
- Juliet is public, so near-ceiling numbers here prove little. Layer ③ is the real test. (L2 rows: backup.)

## 12. Accuracy vs latency (0:50)
- x = per-unit latency at concurrency 1, log scale; bands are deployment budgets (IDE < 0.1 s, pre-commit ~1 s,
  CI ~10 s). Dashed line = ASan/LSan reference 0.945.
- IDE: Clang SA (18 ms) or our LoRA (0.1 s, 0.984). Pre-commit: DeepSeek L1 (0.72 s). CodeQL needs 7.4 s per unit
  (0.32 s amortized, hollow marker). grep is at 1 µs, drawn at the left edge.

## 13. Robustness: add a free that never runs (1:20) — key slide
- Open circle = layer ①, filled = layer ③, same units (paired); diamond = placebo; number = Δ.
- Path-sensitive Clang SA and Infer: **zero flips**. The enhanced dynamic run also stays at 1.0.
- Two failure modes. **Misses**: grep → 0.333, CodeQL −0.116 (309 detections lost), our LoRA L1 −0.612.
  **False alarms**: Qwen L1 −0.221 and Intern-Decision L1 −0.242 start flagging good units whose real free is now
  behind an always-true guard.
- DeepSeek −0.08 to −0.12 (nested25, †), Jev only about −0.03.
- Placebo moves much less (largest: Qwen L1 −0.06 vs −0.22 on layer ③): the drop is caused by the `free`, not by
  the edit itself. Check the diamonds again after the last `make`, more placebo runs may have landed.

## 14. Fine-tuning on a shortcut benchmark teaches the shortcut (1:10)
- Our LoRA L1 is 0.984 on layer ①, then 0.372 on layer ③; leak recall 0.041. It learned "free present ⇒ safe".
- Same base without LoRA (read-out ablation): 0.703 → 0.619, and its errors go the other way (false alarms).
  Fine-tuning turned a weak reader into a strong shortcut user.
- L3 input (Clang's warnings) recovers part: 0.639, recall 0.379.
- Placebo 0.976: the cue is the word `free`, not the guard.
- Lesson: layer ① accuracy is not evidence of program understanding.

## 15. L4: facts + Datalog (0:50)
- DeepSeek L4 is 0.976 on layer ① (L1 0.995), but on layer ③ it drops only −0.078, the smallest of L1–L4.
- Its errors turn into misses (FP/FN 30/40 vs L1 54/25): when it fails it is because a fact was wrong, and
  `!dead(l)` drops the dead free.
- 99.87 % of facts are grounded to a source line.
- Qwen L4 is weaker (0.790 → 0.706): a 4B model's facts are noisier.

## 16. Live demo (2:40)
- Stage unit `CWE401_Memory_Leak__strdup_char_01`, held-out fold. Show the bad unit and its good twin (≈30 s).
- Run grep, Clang SA, our LoRA L1/L3, DeepSeek L1/L3, Jev; read verdicts and latency (≈50 s).
- Attack: add `static const int sym_61 = 4;` and `if(sym_61 > 4) { free(data); }`: still a leak (≈30 s).
- Rerun (≈40 s): in the dry run grep and both LoRA models flipped to "no leak"; Clang SA, DeepSeek and Jev stayed
  right. Whatever happens live is what we report.
- Summary panel (≈10 s). Fallback: `demo.py --replay recordings/stage_dryrun.json`.

## 17. Limitations (0:40)
- Synthetic, single-file units; our leak definition includes globals at exit and realloc failure paths.
- Dev AUROC is saturated (1.0), so dev cannot pick the robust checkpoint.
- DeepSeek on nested25 for layer ③/placebo/original (budget); thresholds are descriptive; Juliet is public.

## 18. Take-aways and next steps (0:30)
- Rebuild the benchmark before ranking; near-ceiling layer ① scores hide very different robustness; path
  sensitivity (Clang, Infer, L4 Datalog) resists dead frees; fine-tuning on a biased set does not.
- Until Dec 24: remaining Qwen/Intern-Decision layers, cascade, repeats + significance, IEEE report.

## Thank you (0:10)

---

## Q&A prep (≈3 min)

**Q: Juliet is public. Are the LLM scores just memorization (contamination)?**
Possibly on the original; that is why we never rank on layer ① alone. Layer ③ units did not exist before this
project, the edit keeps the label, and the drops are measured on the same units (paired). The placebo shows that
the drop is caused by the `free`, not by "unfamiliar code".

**Q: Why are ASan/LSan and Valgrind not ranked? They look best.**
They need a build, a run and the right input, so they answer "did this execution leak", not "does this code
leak". Plain ASan/LSan misses all realloc-failure leaks (0/84 eval), memory reachable from a global at exit
(variants 45/68), and untaken random branches (variant 12). The enhanced run reaches 1.0 only because we know which
seed, option (`use_globals=0`) and fault to inject. Precision is 1.000, so it is a good reference line, not a
competitor. We run LSan with `use_stacks=0`; with default options 175 more bad units are missed.

**Q: Why does DeepSeek run on a subset for layer ③?**
The user cap is ¥10 for DeepSeek; the ledger is at ≈ ¥8.13 in total (Jev ≈ $1.89). Layer ①: full eval set.
Layer ③, placebo and original: the fixed nested25 subset (664 units), and every comparison is paired on those
same units. Costs per run are in the backup slide.

**Q: How did you choose the LoRA checkpoint? Could another one be robust?**
By dev AUROC, then dev loss. Dev AUROC is 1.0 at almost every evaluation, so the choice is effectively by tiny
dev-loss differences: a weak signal. A checkpoint that is more robust on layer ③ may exist, but we cannot pick it
without looking at layer ③, which would be test-set tuning. That is the point: on this benchmark, dev data cannot
tell a robust model from a shortcut model.

**Q: Why is LineVul not fine-tuned?**
The plan replaced "fine-tune LineVul" with the Qwen3.5-4B LoRA: one 4B model lets us compare generate, read-out
and fine-tune on the same weights. LineVul stays as the public Big-Vul checkpoint, zero-shot, as the
"pre-trained vulnerability model" baseline (about chance, 0.501). Our LoRA result also suggests that fine-tuning
any classifier on layer ① would mostly teach it the `free` cue.

**Q: Merged vs unmerged adapters?**
We report merged weights. Unmerged give the same held-out predictions (0 flips of 2,656 for L1 and L3); scores
differ only by BF16 rounding of large logits.

**Q: Why does CodeQL drop on layer ③ if it does dataflow?**
Its leak query does not rule out the never-taken guard here, so a `free` on that path counts: it loses 309
detections. Separately, batching
50 units per database adds 4 false positives on `_08` units (shared helper names); frozen, documented in backup.

**Q: Is L4 just Clang SA in disguise?**
No: L4 never sees Clang's output. The LLM extracts facts; Soufflé decides. It is the only LLM strategy whose layer ③
errors become misses rather than false alarms, which is what we expect from a sound-ish analysis with noisy facts.

**Q: Are the thresholds tuned?**
Jev uses the pre-registered 0.5; our LoRA uses the threshold chosen on dev macro-F1. Budget bands on the Pareto
plot are descriptive only, fixed after seeing results, and stated as such.
