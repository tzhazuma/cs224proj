# Speaker notes (v4): "Near-Cloud Quality on a Local Device?"

Subtitle: Program-Analysis-Guided Decision Models for C/C++ Memory-Leak Detection.
Talk: 17:00 for slides and live demo, then Q&A (course slot 15–20 min). Structure: Introduction → Methods →
Results (ends with the live demo) → Discussion. Section divider pages take no time.

All numbers on the slides come from `figures/numbers.tex`, written by `make figures` from the result files
(DeadFree quality: `juliet_full/analysis/deadfree/deadfree_quality.json`; DeadFree latency:
`juliet_full/analysis/deadfree/latency_deadfree.csv`). Values not yet measured print as *pending* and fill in on the
next `make`. **Read numbers off the slide, not off these notes**: the values quoted below are the build of
2026-11-24 ~09:45 PST (Intern L4-D final; some latencies still being measured). From the dataset slide on, every model
comparison is on **DeadFree** (eval set, 2,656 units, 39 flow variants never used for prompts, τ or checkpoints).

Main line in one sentence: **the strategy does most of the work — an untuned local decision model answering
program-analysis fact questions, with Datalog deciding (L4-D), already closes ~81 % of the gap to the cloud on
DeadFree; fine-tuning on those facts adds +.027 (→ 89 %), fine-tuning on unit labels makes it worse — and it is
still not near-cloud by our own pre-registered criterion.**

| # | Section | Slide (assertion title) | Time | Running |
|---|---------|-------------------------|------|---------|
| 0 | — | Title | 0:20 | 0:20 |
| 1 | Intro | Leak checks must fit a developer's time budget | 0:45 | 1:05 |
| 2 | Intro | On DeadFree, cloud models are far ahead of local ones | 0:45 | 1:50 |
| 3 | Intro | Original Juliet can be gamed: a one-line rule beats Clang SA | 0:50 | 2:40 |
| 4 | Intro | Question: near-cloud quality on a local device? | 0:30 | 3:10 |
| 5 | Methods | Debiased: good units now look like bad units | 0:35 | 3:45 |
| 6 | Methods | DeadFree adds a free that never runs | 0:45 | 4:30 |
| 7 | Methods | We test on unseen flow variants | 0:25 | 4:55 |
| 8 | Methods | L1–L3: ask for the verdict, with more or less help | 0:30 | 5:25 |
| 9 | Methods | L4 and L4-D: the model supplies facts, Datalog decides | 0:50 | 6:15 |
| 10 | Methods | Three rules turn the answers into a verdict | 0:40 | 6:55 |
| 11 | Methods | The design follows the course's program-analysis ideas | 0:45 | 7:40 |
| 12 | Methods | Asking only what the rules read halves the questions | 0:40 | 8:20 |
| 13 | Methods | With correct facts the rules are near-perfect; exec_all is the bottleneck | 0:40 | 9:00 |
| 14 | Methods | Fine-tuning: one recipe, different labels per strategy | 0:40 | 9:40 |
| 15 | Results | DeadFree removes the label shortcuts; one cue is left in G2B goods | 0:35 | 10:15 |
| 16 | Results | Two cloud services, three local models, one fine-tuned model | 0:20 | 10:35 |
| 17 | Results | The strategy does most of the work: L4-D lifts an untuned decision model | 0:45 | 11:20 |
| 18 | Results | **Fine-tuning on unit labels hurts; fine-tuning on facts helps** (key slide) | 1:00 | 12:20 |
| 19 | Results | FT L4-D is the most accurate local model, still below the cloud (Pareto) | 0:50 | 13:10 |
| 20 | Results | L4-D closes 81 % of the gap untuned, 89 % fine-tuned; not near-cloud | 0:35 | 13:45 |
| 21 | Results | Live: one dead free fools grep and the old LoRA, not L4-D | 2:00 | 15:45 |
| 22 | Discussion | Take-aways: the strategy does most of the work | 0:35 | 16:20 |
| 23 | Discussion | Limitations | 0:30 | 16:50 |
| 24 | Discussion | Near-cloud quality on a local device? (+ Questions) | 0:10 | 17:00 |

If time runs short: cut slide 7 and slide 16 to one sentence each, and slide 11 to the first two rows. Never cut
slides 18, 19, 20 or the demo (21). If the demo fails, show the backup slide "demo, all detectors on the stage unit".

## 0. Title (0:20)
"We ask whether a model on one consumer GPU can match cloud quality for C/C++ memory-leak detection. Cloud here
means two APIs: DeepSeek V4.1 Flash, a generative LLM, and Jev, a decision-model API. Local means anything not in
the cloud — for us one RTX 3090 with 24 GB."

## 1. Leak checks must fit a developer's time budget (0:45)
- Three budgets: IDE under 0.1 s, pre-commit under 1 s, CI under 10 s.
- Local models skip the network round-trip; cloud APIs pay it on every unit.
- Bars are median latency per DeadFree unit at concurrency 1, same client. Grey = still being measured; the
  slide fills in on `make`. Current values: FT L4-D (opt.) 445 ms; cloud rows pending.

## 2. On DeadFree, cloud models are far ahead of local ones (0:45)
- Dots are the strategies L1–L4 per model. Cloud: DeepSeek .863–.900, Jev .942–.949.
- Local, untuned: Qwen3.5-4B .533–.760, Intern-Decision-4B .500–.664; VulnLLM-R-7B, a published
  vulnerability-tuned model, .471.
- "So locally we are fast but bad. Before we try to fix that, we have to make sure the benchmark measures leaks."

## 3. Original Juliet can be gamed (0:50)
- On the original Juliet CWE-401 units, grep "no free/delete ⇒ leak" reaches .935 and the rule "has static void ⇒
  good" reaches 1.000 — both beat Clang SA (.822).
- Reason: in Juliet the good functions are `static void` helpers; the label is in the template.
- Any learned model can pick this up. So a high score on Original Juliet says nothing.

## 4. The question (0:30)
- Three sub-questions: which strategy helps a local model most, does fine-tuning help and on which labels, how
  close to the cloud do we get and how fast. Task is one unit → leak / no leak, judged on DeadFree.

## 5. Debiased (0:35)
- One entry function per unit, wrapper and `static` removed. Each good unit is either G2B (no heap) or B2G
  (malloc + free). Bad units unchanged. Shape and length no longer reveal the label.

## 6. DeadFree (0:45)
- Every unit gets an unreachable `free` under a constant guard, in both labels. The good unit's real free is moved
  under an always-true guard. Labels do not change; both labels now contain a free; only path feasibility decides.
- Placebo is the control: the same guard with a print instead of a free. If a model drops on DeadFree but not on
  Placebo, the dead free — not the extra branch — fooled it.
- All 3,316 units per layer compile with gcc and clang and the labels were re-checked by running them (backup).

## 7. Split (0:25)
- Split by flow variant, not by unit: 9 dev variants (prompts, τ, checkpoints frozen there), 39 eval variants in
  three folds. Fine-tuned models train on two folds and predict the third.

## 8. L1–L3 (0:30)
- L1 direct, L2 few-shot, L3 adds Clang SA warnings as evidence. Generative models write the label; decision
  models do one forward pass and compare P(Yes) and P(No). Brief — the interesting strategy is next.

## 9. L4 and L4-D (0:50)
- L4: the LLM extracts facts as JSON, Soufflé Datalog decides.
- L4-D: the decision model never sees the whole verdict. A parser finds the sites; we ask typed yes/no questions:
  is this call a heap allocation, can this statement run on some run, does it run on every run, does this release
  free that block, is the old block safe if realloc fails. The statement under test is masked so the model has to
  reason about the control flow around it.

## 10. Three rules (0:40)
- `freed(a) :- rel(f,a), exec_all(f).` A block is freed only if a matching release runs on every run.
- `leak(a) :- heap(a), exec_any(a), !freed(a).` A leak is a heap block that may be allocated and is not
  must-freed. The realloc rule is the same idea for a failing realloc.
- The dead free fails `exec_all`, so the leak survives.

## 11. Course ideas (0:45)
- Allocation-site abstraction: one fact set per allocation site (Lecture 10, Pointer Analysis).
- exec_any is a may analysis, exec_all a must analysis — like reaching definitions vs available expressions
  (Lectures 3–4, Data Flow Analysis). Leak = may-allocated and not must-freed: the safe approximation direction.
- Facts plus rules with negation: Datalog-based program analysis (Lecture 17).
- Ask only what the query needs: demand-driven analysis (Lecture 10).
- Caveat: model facts can be wrong, so there is no soundness guarantee — but most real analyzers are "soundy"
  anyway (Lectures 1 and 18).

## 12. Pruning (0:40)
- Walk the rule dependency graph backwards from `leak`; a fact no rule reads is never asked (e.g. exec_any on a
  release, exec_all on an allocation, exec_* on plain statements).
- Median questions per DeadFree unit 13 → 6, verdicts identical on all four layers (0 differences).
- Say clearly: this is an inference optimization decided post-hoc and approved on 2026-11-24; same trained models,
  same τ. "L4-D (opt.)" on the following slides.

## 13. Oracle and attribution (0:40)
- With gold facts (from dynamic analysis) the frozen rules score .991; all errors are 24 false positives on
  flow-variant-12 goods (frees in both random branches, the rules cannot express "some free on every path").
- So the remaining errors come from wrong facts. Substituting only the gold exec_all facts lifts DeadFree .826 →
  .957: path feasibility is the bottleneck.

## 14. Fine-tuning (0:40)
- One recipe: Qwen3.5-4B + LoRA r16 α32 on all language-model linear layers (32.5 M, 0.70 %), head from the tied
  Yes/No rows, score = logit_Yes − logit_No.
- What changes is the label: L1/L3 train on the unit label (balanced CE + bad > good ranking loss). L4-D trains on
  fact labels from dynamic analysis (gcov coverage, alloc/free trace, realloc failure injection), class-balanced
  per question type and label; rules frozen. 3-fold CV, dev picks checkpoint and τ; ≈68 min per fold on two
  RTX 3090s. L2 is not trained.

## 15. Shortcut table (0:35)
- grep .935 → .701 → .333, static-void 1.000 → .333, bag-of-words logistic regression 1.000 → .979 → .752.
- Honest residual: on DeadFree, G2B goods are still separable (AUROC .986) because they use ALLOCA or new instead
  of malloc. B2G goods are not (.609).
- Clang SA is the reference row. **From here on, everything is on DeadFree only.**

## 16. Models (0:20)
- Two cloud references, three local models (Qwen3.5-4B generative, Intern-Decision-4B decision, VulnLLM-R-7B),
  and ours. Static and dynamic tools are references, not competitors. Read-out = untuned Qwen answering the L4-D
  questions.

## 17. Strategies × local models (0:45)
- Left quality, right latency. Few-shot barely helps; Clang evidence helps both untuned models (Qwen .533 → .760).
- The big jump is the strategy: untuned Intern-Decision goes from its best prompt (L3 .664) to .799 with L4-D facts
  + Datalog. Be precise: for untuned Qwen the L4-D read-out (.752) is only on par with Qwen's own L3 (.760), so
  "facts beat every prompt" holds for the decision models, not for every model.
- Fine-tuned L4-D is the best local result, .826.

## 18. Before vs after fine-tuning — key slide (1:00)
- L1: untuned .533 / .584 → fine-tuned .372. L3: .760 / .664 → .639. Fine-tuning on unit labels makes it
  **worse** than untuned on DeadFree.
- Why: the L1 model's leak recall is .041 — it learned "a free() means no leak". On Debiased that shortcut was
  almost always right (.984), so the training loss could not see it.
- L4-D: read-out .752 / Intern .799 → fine-tuned .826, +.027 [+.003, +.054] over the best untuned (Intern L4-D,
  paired bootstrap). Small but the CI excludes zero.
- "The strategy does most of the work; fine-tuning on facts adds a little; fine-tuning on verdicts hurts."

## 19. Pareto (0:50)
- x = median latency at concurrency 1 (log), y = DeadFree macro-F1 with CI. Budget bands as on slide 1. Static
  tools grey; dynamic analysis dashed as an upper reference (it runs the code with chosen inputs).
- FT L4-D is the most accurate local point (.826 at ≈0.47 s); cloud points are higher at ≈0.9 s. Untuned
  Qwen is faster (≈0.35 s) but much worse. Read latencies off the slide.

## 20. Gap and criterion (0:35)
- Gap measured from untuned Qwen L1 (.533) to the cloud model. Untuned Intern L4-D: −.064 vs DeepSeek L1, 81 %
  of the gap. FT L4-D: −.037 [−.055, −.017], 89 %; vs DeepSeek L4 −.074, 80 %.
- Pre-registered criterion (before L4-D ran): near if ≥ reference − 0.02. **Not met.** Jev (.949) is well ahead.
- Speed-up vs DeepSeek L1 is on the slide (≈1.9× at the 09:45 build): local is faster, but not by an order of
  magnitude at concurrency 1.

## 21. Live demo (2:00)
- Unit `CWE401_Memory_Leak__strdup_char_01`: bad, good twin, and the DeadFree bad version with `if(sym_61 > 4)
  { free(data); }` — the free never runs.
- grep and the old unit-label LoRA (L1 and L3) flip to "no leak". Clang SA, DeepSeek, Jev and FT L4-D stay
  correct. L4-D answers exec_all(free) = no, so the block is not freed, so leak.
- If the L4-D row is marked *, it comes from the frozen eval run, not the live recording — say so.
- Fallback: `demo.py --replay recordings/<file>` or the mp4.

## 22. Take-aways (0:35)
1. Check the benchmark first. 2. Facts + Datalog do most of the work (untuned Intern L4-D, 81 % of the gap).
3. Unit labels teach shortcuts. 4. Fact labels add a little (+.027, 89 %). 5. Ask only what the rules read.
6. The remaining gap is path feasibility.

## 23. Limitations (0:30)
- Clang SA is as good (.855) and faster, without a GPU: path-sensitive analysis still matters.
- Synthetic data; post-hoc pruning; τ and checkpoints chosen on a near-saturated dev set; one local device.
- Intern L4-D threshold: τ = 0.5 (as for Intern L1–L3) was set as primary after seeing eval; it favours the
  baseline (the frozen dev τ 0.18 gives .373). Say this out loud.

## 24. Take-home (0:10)
"Close — about 89 % of the gap — but not yet near-cloud. Program-analysis facts do most of the work; fine-tune on
facts, not on verdicts."

## Q&A prep

**Why not just use Clang SA?**
On DeadFree Clang SA scores .855, slightly above FT L4-D (.826), and it runs on a CPU in milliseconds. We say this on
the limitations slide. Our question is different: how far can a *local learned* model get, and what to train it on.
Clang's recall is limited (.771 on DeadFree) and it needs a buildable unit; L4-D needs only source text. The fact
attribution says the same thing from the other side: the missing piece is path feasibility, which is exactly what
a path-sensitive analyzer does. A natural next step is to feed Clang's path facts into L4-D (L3-style evidence for
`exec_all`).

**Is L4-D really near-cloud?**
No, and we say so. Δ vs DeepSeek L1 is −.037 [−.055, −.017]; the pre-registered threshold was −.02 on the point
estimate. It closes ≈89 % of the gap to DeepSeek L1 and ≈80 % to DeepSeek L4. Jev is far ahead (.949). Most of that
comes from the strategy: untuned Intern with L4-D already closes ≈81 %. Fact fine-tuning is the only fine-tuning
that helps on DeadFree, by +.027 [+.003, +.054].

**Was the Intern L4-D threshold chosen fairly?**
No — and in the baseline's favour. The frozen dev τ (0.18, tuned on Debiased) makes Intern answer Yes to every
exec/release question, so dead frees count as "runs on every path" and leak recall is .037 (macro-F1 .373). The
primary was switched to τ = 0.5 after seeing eval, to match Intern L1–L3 (calibrated default). Our fine-tuned model
keeps its dev-chosen τ. Backup slide "Intern-Decision L4-D and its threshold".

**If the strategy does most of the work, why fine-tune at all?**
+.027 is significant (paired CI excludes 0) and it is the step from 81 % to 89 % of the gap, with τ chosen on dev
rather than after eval. But the honest headline is the strategy.

**Is DeadFree fair?**
Labels do not change and are re-checked by compiling and running every unit. Dead frees appear in both labels, so
"has a free" carries no information. The Placebo control (same guard, no free) shows the extra branch alone does
not hurt (e.g. FT L1 .984 → .976 Placebo, but .372 DeadFree). Residual: G2B goods are still separable by
ALLOCA/new (BoW AUROC .986); B2G goods are not (.609). Constant guards are one kind of edit; real code has more.
It is adversarial to the "free ⇒ safe" shortcut on purpose — that is the shortcut we found.

**Why is fine-tuned L1 worse than untuned?**
On Debiased, "contains a free ⇒ no leak" is almost always right, so the unit-label loss rewards it (.984 Debiased).
DeadFree breaks exactly that cue; recall falls to .041.

**Is the post-hoc pruning cheating?**
It changes no model and no threshold; it skips questions whose answers no rule reads. Verdicts are identical on all
four layers (0 differences, checked on stored answers). It only changes latency. Approved by the user on
2026-11-24 and labelled "post-hoc" on the slide.

**Do the fact labels leak test information?**
Fact labels come from dynamic analysis on the training folds only; eval-fold gold facts are used only for the
oracle and the attribution analysis, never for training or τ.

**Why is Jev so much better?**
Jev is a production decision-model API; we do not know its size or training data. It shows that a decision
model can be strong on DeadFree; our 4B model is not there yet.

**Contamination?**
Juliet is public, so cloud models may have seen it. DeadFree edits are new, which is one reason to judge on it.

**How long does training take / what does it cost?**
≈68 min per fold on two RTX 3090s (≈2.3 GPU-h); inference is free locally. API totals are on the cost backup.

**Does this generalize beyond CWE-401?**
Not tested. The fact questions are leak-specific; the recipe (typed facts + frozen rules + fact labels from
dynamic analysis) is general.

**Soundness?**
None: facts come from a model. Real analyzers are mostly "soundy" too (Lecture 18), but ours can also be wrong on
the facts it is asked; the oracle shows the rules themselves are near-perfect on this data.
