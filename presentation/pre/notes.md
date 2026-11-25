# Speaker notes (v4): "Near-Cloud Quality on a Local Device?"

Subtitle: Program-Analysis-Guided Decision Models for C/C++ Memory-Leak Detection.
Talk: 17:00 for slides and live demo, then Q&A (course slot 15–20 min). Structure: Introduction → Methods →
Results (ends with the live demo) → Discussion. Section divider pages take no time.

All numbers on the slides come from `figures/numbers.tex`, written by `make figures` from the result files
(DeadFree quality: `juliet_full/analysis/deadfree/deadfree_quality.json`; DeadFree latency:
`juliet_full/analysis/deadfree/latency_deadfree.csv`, primary rows). **Read numbers off the slide, not off these
notes**: the values quoted below are the build of 2026-11-24 ~10:30 PST (quality and latency final; the Qwen
read-out L4-D latency was not measured and shows as "not measured"; v4.3 adds the two-track results; v4.4 (~20:10)
adds Jev L4-D, final: .907 at τ 0.5, 967 ms). Sources (datasets, tools, models, papers) are numbered superscripts at
the mention with a numbered footer per slide (`\sref`, short forms in `sources.tex` from
`report/final_en/references.bib` or official URLs); course lectures, DeepSeek and Jev are named without a citation. From the dataset slide on, every model
comparison is on **DeadFree** (eval set, 2,656 units, 39 flow variants never used for prompts, τ or checkpoints).

Main line in one sentence: **the strategy does most of the work — an untuned local decision model answering
the same untuned Qwen3.5-4B, asked program-analysis fact questions with Datalog deciding (L4-D), goes from .351
(L1) to .752 (+.401) and closes 66 % of the local–cloud gap on DeadFree; fine-tuning on those facts adds +.074
(→ .826, 89 % of the gap, 1.9× faster than DeepSeek L1); fine-tuning on unit labels does not help — and it is not yet near-cloud by our own pre-registered test.**

Wording rule (v4.5): "near-cloud" names only the pre-registered yes/no test (macro-F1 ≥ DeepSeek L1 − 0.02 on
DeadFree). The positive claim is always quantitative: "closes X of the local–cloud gap" (gap = untuned Qwen L1 →
DeepSeek L1) plus the speed-up vs DeepSeek L1. Never say "close" as an adjective.

| # | Section | Slide (assertion title) | Time | Running |
|---|---------|-------------------------|------|---------|
| 0 | — | Title | 0:15 | 0:15 |
| 1 | Intro | Leak checks must fit a developer's time budget | 0:45 | 1:00 |
| 2 | Intro | On DeadFree, cloud models are far ahead of local ones | 0:45 | 1:45 |
| 3 | Intro | Original Juliet can be gamed: a one-line rule beats Clang SA | 0:35 | 2:20 |
| 4 | Intro | Question: near-cloud quality on a local device? | 0:30 | 2:50 |
| 5 | Methods | Original Juliet CWE-401: synthetic, templated, gameable | 0:40 | 3:30 |
| 6 | Methods | Debiased: good units now look like bad units | 0:30 | 4:00 |
| 7 | Methods | DeadFree adds a free that never runs | 0:45 | 4:45 |
| 8 | Methods | We test on unseen flow variants | 0:15 | 5:00 |
| 9 | Methods | L1–L3: ask for the verdict, with more or less help | 0:30 | 5:30 |
| 10 | Methods | L4 and L4-D: the model supplies facts, Datalog decides | 0:50 | 6:20 |
| 11 | Methods | Three rules turn the answers into a verdict | 0:40 | 7:00 |
| 12 | Methods | The design follows the course's program-analysis ideas | 0:45 | 7:45 |
| 13 | Methods | Asking only what the rules read halves the questions | 0:40 | 8:25 |
| 14 | Methods | Which wrong facts cost the most? Fix one fact type at a time | 0:40 | 9:05 |
| 15 | Methods | Fine-tuning: one recipe, different labels per strategy | 0:40 | 9:45 |
| 16 | Results | DeadFree removes the label shortcuts; one cue is left in G2B goods | 0:35 | 10:20 |
| 17 | Results | Two cloud services, three local models, one fine-tuned model | 0:10 | 10:30 |
| 18 | Results | Facts lift every local decision model; the 4B generator cannot write them | 0:40 | 11:10 |
| 19 | Results | **Same Qwen3.5-4B: unit-label FT < untuned generator < fact-label FT** (key slide) | 0:55 | 12:05 |
| 20 | Results | Clang SA dominates every local LM; FT L4-D is the most accurate of them (Pareto) | 0:40 | 12:45 |
| 21 | Results | Cost: rented GPU ≈ DeepSeek L1; owned GPU pays only electricity | 0:40 | 13:25 |
| 22 | Results | Not yet near-cloud: L4-D closes 66 % of the gap untuned, 89 % fine-tuned | 0:30 | 13:55 |
| 23 | Results | Live: one dead free fools grep and the old LoRA, not L4-D | 1:30 | 15:25 |
| 24 | Discussion | Privacy: a local model sends no code; a cloud model sends every unit | 0:30 | 15:55 |
| 25 | Discussion | Take-aways: the strategy does most of the work | 0:30 | 16:25 |
| 26 | Discussion | Limitations | 0:20 | 16:45 |
| 27 | Discussion | Team and division of labor | 0:05 | 16:50 |
| 28 | Discussion | Near-cloud quality on a local device? (+ Questions) | 0:10 | 17:00 |

If time runs short: cut slides 8 and 17 to one sentence each, and slide 12 to the first two rows. Never cut
slides 18, 19, 20, 22 or the demo (23); slide 21 (cost) can shrink to its take-away line; slide 24 (privacy) can shrink to its orange line. If the demo fails, show the backup slide "demo, all detectors on the stage unit".

## 0. Title (0:15)
"We ask whether a model on one consumer GPU can match cloud quality for C/C++ memory-leak detection. Cloud here
means two APIs: DeepSeek V4.1 Flash, a generative LLM, and Jev, a decision-model API. Local means anything not in
the cloud — for us one RTX 3090 with 24 GB."

## 1. Leak checks must fit a developer's time budget (0:45)
- Three budgets: IDE under 0.1 s, pre-commit under 1 s, CI under 10 s.
- Local models skip the network round-trip; cloud APIs pay it on every unit.
- Bars are median latency per DeadFree unit at concurrency 1, same client: DeepSeek L1 895 ms, Jev L1 912 ms,
  Qwen L1 347 ms, Intern L1 135 ms, FT L4-D (opt.) 472 ms. All local rows fit the pre-commit budget; none of the
  model-based methods fits the IDE budget.

## 2. On DeadFree, cloud models are far ahead of local ones (0:45)
- Dots are the strategies L1–L4 per model. Cloud: DeepSeek .863–.900, Jev .942–.949.
- Local, untuned: Qwen3.5-4B .533–.760, Intern-Decision-4B .500–.664; VulnLLM-R-7B, a published
  vulnerability-tuned model, .471.
- "So locally we are fast but bad. Before we try to fix that, we have to make sure the benchmark measures leaks."

## 3. Original Juliet can be gamed (0:35)
- On the original Juliet CWE-401 units, grep "no free/delete ⇒ leak" reaches .935 and the rule "has static void ⇒
  good" reaches 1.000 — both beat Clang SA (.822).
- Reason: in Juliet the good functions are `static void` helpers; the label is in the template.
- Any learned model can pick this up. So a high score on Original Juliet says nothing.

## 4. The question (0:30)
- Three sub-questions: which strategy helps a local model most, does fine-tuning help and on which labels, how
  close to the cloud do we get and how fast (a question; the answer is a number, slide 22). Task is one unit → leak / no leak, judged on DeadFree.

## 5. Original Juliet CWE-401 (0:40)
- What the data looks like (bullets): NIST SARD Juliet C/C++ 1.3, 1,658 CWE-401 cases, 42 families (allocation call
  × data type) × 48 flow variants; one bad + one good unit per case = 3,316 units.
- Point at the three-line listing: bad leaks; the goods are `static void`; goodG2B uses the stack (ALLOCA, no heap),
  goodB2G frees. The table: two one-line cues — "no free ⇒ leak" .935, "static void ⇒ good" 1.000 — and Clang SA,
  a real analysis, only .822 (grey reference row).
- Closing line: Debiased removes the structure cue, DeadFree the free-token cue. (Slide 3 already made the "gamed"
  point; do not repeat it here, just show where the cues come from.)

## 6. Debiased (0:30)
- One entry function per unit, wrapper and `static` removed. Each good unit is either G2B (no heap) or B2G
  (malloc + free). Bad units unchanged. Shape and length no longer reveal the label.

## 7. DeadFree (0:45)
- Every unit gets an unreachable `free` under a constant guard, in both labels. The good unit's real free is moved
  under an always-true guard. Labels do not change; both labels now contain a free; only path feasibility decides.
- Placebo is the control: the same guard with a print instead of a free. If a model drops on DeadFree but not on
  Placebo, the dead free — not the extra branch — fooled it.
- All 3,316 units per layer compile with gcc and clang and the labels were re-checked by running them (backup).

## 8. Split (0:15)
- Split by flow variant, not by unit: 9 dev variants (prompts, decision thresholds, checkpoints frozen there), 39
  eval variants in three folds. Fine-tuned models train on two folds and predict the third.
- Metric: macro-F1 = mean of the F1 for "leak" and for "no leak" (always-leak scores .33). 95 % CIs resample the 42
  families 2,000 times.

## 9. L1–L3 (0:30)
- L1 direct, L2 few-shot, L3 adds Clang SA warnings as evidence; same prompt input for both kinds of model.
- Output: a generative model writes text, e.g. `{"label": "vulnerable", "confidence": 0.99}`, which we parse. A
  decision model writes nothing: one forward pass, leak if P(Yes) ≥ τ (τ chosen on dev for our models; 0.5 for Jev
  and Intern-Decision). Brief — the interesting strategy is next.

## 10. L4 and L4-D (0:50)
- L4: the LLM extracts facts as JSON, the Datalog engine Soufflé decides. Related work does the same with
  LLM-evaluated relations (NESA, LLMDFA; footnote).
- L4-D: the decision model never sees the whole verdict. A parser finds the sites; we ask typed yes/no questions:
  is this call a heap allocation, can this statement run on some run, does it run on every run, does this release
  free that block, is the old block safe if realloc fails. The statement under test is masked so the model has to
  reason about the control flow around it.

## 11. Three rules (0:40)
- `freed(a) :- rel(f,a), exec_all(f).` A block is freed only if a matching release runs on every run.
- `leak(a) :- heap(a), exec_any(a), !freed(a).` A leak is a heap block that may be allocated and is not
  must-freed. The realloc rule is the same idea for a failing realloc.
- The dead free fails `exec_all`, so the leak survives.

## 12. Course ideas (0:45)
- Allocation-site abstraction: one fact set per allocation site (Lecture 10, Pointer Analysis).
- exec_any is a may analysis, exec_all a must analysis — like reaching definitions vs available expressions
  (Lectures 3–4, Data Flow Analysis). Leak = may-allocated and not must-freed: the safe approximation direction.
- Facts plus rules with negation: Datalog-based program analysis (Lecture 17).
- Ask only what the query needs: demand-driven analysis (Lecture 10).
- Caveat: model facts can be wrong, so there is no soundness guarantee — but most real analyzers are "soundy"
  anyway (Lectures 1 and 18).

## 13. Pruning (0:40)
- Walk the rule dependency graph backwards from `leak`; a fact no rule reads is never asked (e.g. exec_any on a
  release, exec_all on an allocation, exec_* on plain statements).
- The table: kept = facts some rule reads (heap on allocation sites; exec_any on allocation/realloc; exec_all on
  release/realloc; rel on (release, allocation) pairs; realloc_safe on realloc); dropped = the rest. An arrow in the
  graph means "the rule reads this fact".
- Median questions per DeadFree unit 13 → 6, verdicts identical on all four layers (0 differences). Demo unit
  strdup_char_01: 2 of 5 questions asked for the bad version, 4 of 8 for the good one.
- Say clearly: this is an inference optimization decided post-hoc and approved on 2026-11-24; same trained models,
  same τ. "L4-D (opt.)" on the following slides.

## 14. Which wrong facts cost the most (0:40)
- With gold facts (from dynamic analysis) the frozen rules score .991; all errors are 24 false positives on
  flow-variant-12 goods (frees in both random branches, the rules cannot express "some free on every path").
- So the remaining errors come from wrong facts. Substituting only the gold exec_all facts lifts DeadFree .826 →
  .957: path feasibility is the bottleneck.

## 15. Fine-tuning (0:40)
- One recipe: Qwen3.5-4B + LoRA r16 α32 on all language-model linear layers (32.5 M, 0.70 %), head from the tied
  Yes/No rows, score = logit_Yes − logit_No.
- What changes is the label: L1/L3 train on the unit label (balanced CE + bad > good ranking loss). L4-D trains on
  fact labels from dynamic analysis (gcov coverage, alloc/free trace, realloc failure injection), class-balanced
  per question type and label; rules frozen. 3-fold CV, dev picks checkpoint and τ; ≈68 min per fold on two
  RTX 3090s. L2 is not trained.

## 16. Shortcut table (0:35)
- grep .935 → .701 → .333, static-void 1.000 → .333, bag-of-words logistic regression 1.000 → .979 → .752.
- Honest residual: on DeadFree, G2B goods are still separable (AUROC .986) because they use ALLOCA or new instead
  of malloc. B2G goods are not (.609).
- Clang SA is the reference row. **From here on, everything is on DeadFree only.**

## 17. Models (0:10)
- Two cloud references, three local models (Qwen3.5-4B generative, Intern-Decision-4B decision, VulnLLM-R-7B),
  and ours. Define **Qwen read-out**: the untuned Qwen3.5-4B used as a decision model (same yes/no question, read
  P(Yes) vs P(No) instead of letting it write) — exactly our LoRA's starting point. Static and dynamic tools are
  references, not competitors. Sources are in the footnote of each slide.

## 18. Facts lift every local decision model (figure) (0:40)
- Two panels, same y-axis. Left: generative (writes text; Qwen3.5-4B local, DeepSeek cloud; L1–L4). Right:
  decision (one forward pass, P(Yes) vs P(No); Qwen read-out, Intern-Decision, ours, Jev; L1, L2, L3, L4-D).
  Bars grouped by model, colour = strategy (light → dark blue L1 → L3, orange L4 / L4-D), hatched = cloud,
  green bold = ours. Every bar carries its value; "–†" = strategy not run.
- Decision panel: L4-D is the best strategy for every LOCAL decision model — read-out .351/.334 → .752, Intern
  .664 (best prompt) → .799, ours .372 (L1) → .826. The cloud decision model is already strong at L1–L3 (Jev L3
  .949); with the same facts Jev L4-D (τ 0.5, pre-specified) is .907: ≈ DeepSeek L4 (+.007 [−.028, +.039], n.s.)
  but below Jev L3 (−.042 [−.071, −.013]).
- Generative panel: DeepSeek gains from writing facts + Datalog (L4 .900 is its best); the 4B model writes them
  poorly (L4 .706 < L3 .760).
- If asked (not on the slide): same Qwen weights — asking the facts (read-out L4-D .752) beats writing them (gen.
  L4 .706). Jev answers the path question well (exec_all fact accuracy .975 vs .831 for our LoRA); most of its 238
  false leaks contain a wrong realloc_safe answer (a gold-convention case, `realloc(NULL)` + exit).
- "–†" slot: no L2 for read-out and FT — FT already saw ≈1,800 labelled units, and the L2 prompt is 2.4×
  longer. All numbers: backup "two tracks, all numbers".

## 19. Fine-tuning, strategy by strategy — key slide (0:55)
- Vertical comparison only: the same Qwen3.5-4B weights before (read-out) and after LoRA, plus the dotted line =
  the same weights untuned in generative format. Intern-Decision is another model and is NOT used to explain our
  gains (it appears side by side on slides 17, 18, 20). Paired Δ FT − read-out: L1 +.021 [−.007, +.054] (n.s.),
  L3 +.304 [+.280, +.331], L4-D +.074 [+.053, +.097].
- What FT trains on decides what it learns. L1/L3 learn unit labels: the shortcut "a free means no leak". FT L1
  scored .984 on Debiased and .372 on DeadFree, leak recall .041; FT L1 .372 and FT L3 .639 both stay below the
  untuned generator (gen. L1 .533, L3 .760).
- L4-D learns fact labels from dynamic analysis; that transfers: .752 → .826, and FT L4-D beats every untuned Qwen
  form, +.067 [+.039, +.099] over the best one (gen. L3 .760).
- "The strategy does most of the work; fine-tuning on facts adds a little; fine-tuning on verdicts hurts."

## 20. Pareto: Clang SA dominates every local LM (0:40)
- x = median latency per DeadFree unit at concurrency 1 (log), y = DeadFree macro-F1 with CI. Shape = track
  (circle generative, diamond decision), colour = cloud (orange) / local (blue); green star = our FT L4-D (opt.).
  Grey squares = static tools; dashed lines = dynamic analysis as an upper reference (it runs the code with chosen
  inputs; not part of the front). Small unlabelled markers are the other strategies; all labels are in backup.
- The front now covers model-based AND static methods: grep (.333, 1 µs) → Cppcheck (.492, 9 ms) → Clang SA (.855,
  18 ms) → DeepSeek L3 (.875, 810 ms) → Jev L1 (.946, 912 ms) → Jev L3 (.949, 923 ms).
- Clang SA is above every local LM and faster, so no local LM is on the front. FT L4-D (.826 at 472 ms) is the most
  accurate local LM; side by side it also dominates untuned Intern L4-D (.799 at 658 ms); the cloud is higher at 0.81–1.01 s.
- Other grey squares: Infer .815 at 256 ms, CodeQL .766 at 7.4 s. Dynamic: ASan/LSan .948 at 135 ms,
  Dynamic-enhanced 1.0 at 1.17 s, both need a build, a run and the right inputs.
- Jev L4-D (.907 at 967 ms) is the orange diamond just below Jev L1; its questions are sent concurrently; our FT L4-D batches a
  unit's questions in one forward pass, Intern-Decision L4-D asks them one by one.

## 21. Cost per 1,000 units (0:40)
- Same DeadFree run, priced per 1,000 units. Cloud rows are what we were billed (DeepSeek off-peak with prefix
  cache; at peak it would be 2×, DeepSeek L1 $0.131). Ours on a rented RTX 3090 (RunPod Secure, $0.50/h): $0.070 —
  about the same as DeepSeek L1 ($0.065), more than Jev L3 ($0.039), less than DeepSeek L4 ($0.110) and Jev L4-D
  ($0.182, ≈5.9 calls per unit).
- On a GPU we already own, only electricity counts: 350 W × China business tariff = $0.006 per 1,000 units. That is
  a lower bound: no hardware, host or idle time.
- One-off: one training run 2.3 GPU-h ≈ $1.16 rented, plus 0.14 CPU-h of dynamic labelling. Break-even at the
  rental price: ≈11k units vs Jev L4-D, ≈31k vs DeepSeek L4; never vs DeepSeek L1 or Jev L3, which are cheaper per
  unit.
- Say: "Cost is not where local wins. Local wins on latency, 1.9× faster than DeepSeek L1, and on keeping the code
  on-premise." Price sources and the community-cloud sensitivity are in backup "cost details".

## 22. Gap and criterion (0:30)
- Title percentages: read-out L4-D (same untuned weights) 66 %, FT L4-D 89 %.
- Gap = untuned Qwen L1 (.533) → cloud model. Same untuned weights with L4-D (read-out): −.111 [−.127, −.095] vs
  DeepSeek L1, closes 66 % of the gap. FT L4-D: −.037 [−.055, −.017], closes 89 %; vs DeepSeek L4 −.074, 80 %.
- Near-cloud test, pre-registered before L4-D ran: macro-F1 ≥ DeepSeek L1 − 0.02. FT L4-D: **not yet near-cloud**;
  no local LM passes. Grey row: Clang SA, −.008 [−.066, +.043], closes 97 % — a static analyzer, not an LM, meets
  the near-cloud test (its CI is wide; the test is on the point estimate).
- Latency: FT L4-D 472 ms vs DeepSeek L1 895 ms — FT L4-D is 1.9× faster (DeadFree
  numbers; the ≈7× of the Debiased backup was single-prompt LoRA L1 vs DeepSeek and does not apply here).
- Same facts, cloud decision model: Jev L4-D .907, +.081 [+.047, +.111] over FT L4-D; Jev L3 .949 stays the
  decision-track ceiling. The fact interface is not the bottleneck for a strong model; our 4B model's fact answers
  are (see slide 14: exec_all).

## 23. Live demo (1:30)
- Unit `CWE401_Memory_Leak__strdup_char_01`: bad, good twin, and the DeadFree bad version with `if(sym_61 > 4)
  { free(data); }` — the free never runs.
- grep and the old unit-label LoRA (L1 and L3) flip to "no leak". Clang SA, DeepSeek, Jev and FT L4-D stay
  correct. L4-D answers exec_all(free) = no, so the block is not freed, so leak.
- If the L4-D row is marked *, it comes from the frozen eval run, not the live recording — say so.
- Fallback: `demo.py --replay recordings/<file>` or the mp4.

## 24. Privacy (0:30)
- Structural, not measured: a local model (FT L4-D on our 3090, or Clang SA) reads the code where it lives; a cloud
  model only works if every unit is sent to the provider. For leak detection the code under analysis is, by
  definition, possibly vulnerable and unpatched — sending it out discloses it before the fix.
- Retention and use of what we send are set by the provider's terms, not by us; offline / air-gapped use is
  impossible; the model behind an alias can change on the provider side (we asked for jev-latest and got 1.14.0).
- Our own count (ledger, all dev+eval+demo calls): 91,503 requests, ≈84 M input tokens of code and prompts to
  DeepSeek (27,747) and Jev (63,756).
- Line to say: "For proprietary or unpatched code, privacy is the strongest reason to stay local: FT L4-D reaches
  .826 with zero bytes of code leaving the device." Do not claim any provider misuses data.

## 25. Take-aways (0:30)
1. Check the benchmark first. 2. Facts + Datalog do most of the work (same untuned Qwen: L1 .351 → L4-D .752,
+.401, 66 % of the gap). 3. Unit labels teach shortcuts. 4. Fine-tuning on facts adds a little more (+.074 → .826,
89 % of the gap, 1.9× faster than DeepSeek L1). 5. Ask only what the rules read.
6. The remaining gap is path feasibility.

## 26. Limitations (0:20)
- Clang SA is as good (.855) and faster (18 ms vs 472 ms), without a GPU: path-sensitive analysis still matters.
- Synthetic data; post-hoc pruning; τ and checkpoints chosen on a near-saturated dev set; one local device.
- Intern L4-D threshold: τ = 0.5 (as for Intern L1–L3) was set as primary after seeing eval; it favours the
  baseline (the frozen dev τ 0.18 gives .373). Say this out loud.

## 27. Team and division of labor (0:05)
One sentence: who did what (table on the slide); then go to the closing slide.

## 28. Take-home (0:10)
"Not yet: L4-D closes 89 % of the gap, 1.9× faster than the cloud. Program-analysis facts do most of the work;
fine-tune on facts, not on verdicts."

## Q&A prep

**Is the privacy claim measured?**
No — it holds by construction: a cloud request has to contain the code, a local forward pass does not send anything.
What we measured is how much we sent (91,503 requests, ≈84 M input tokens). We make no claim about how a provider
stores or uses data; the point is that it is their policy, not ours.

**Is local cheaper?**
Not per unit at rental prices. On DeadFree, FT L4-D on a rented RTX 3090 costs $0.070 per 1,000 units, about
DeepSeek L1 ($0.065, billed off-peak with caching) and more than Jev L3 ($0.039); it is cheaper than DeepSeek L4
($0.110) and Jev L4-D ($0.182), so it breaks even after ≈31k and ≈11k units given the $1.23 one-off (training +
labelling). On a GPU you already own, electricity is $0.006 per 1,000 units, but that excludes the hardware. The
real reasons to run locally are latency (472 ms vs 895 ms, 1.9×) and that the code never leaves the machine.

**Why not just use Clang SA?**
On DeadFree Clang SA scores .855, slightly above FT L4-D (.826), and it runs on a CPU in milliseconds. We say this on
the limitations slide. Our question is different: how far can a *local learned* model get, and what to train it on.
Clang's recall is limited (.771 on DeadFree) and it needs a buildable unit; L4-D needs only source text. The fact
attribution says the same thing from the other side: the missing piece is path feasibility, which is exactly what
a path-sensitive analyzer does. A natural next step is to feed Clang's path facts into L4-D (L3-style evidence for
`exec_all`).

**Is L4-D really near-cloud?**
Not yet, and we say so. Δ vs DeepSeek L1 is −.037 [−.055, −.017]; the pre-registered threshold was −.02 on the
point estimate. The only local method that passes is Clang SA (−.008), which is not an LM. FT L4-D closes 89 % of the gap to DeepSeek L1 and ≈80 % to DeepSeek L4. Jev is far ahead (.949); even with
our exact fact questions and rules Jev L4-D reaches .907 (+.081 over FT L4-D), so the remaining gap is the quality
of the 4B model's fact answers (mainly exec_all), not the L4-D interface. Most of the 89 % comes from the
strategy: the same untuned weights with L4-D already close 66 %. Fact fine-tuning adds +.074 [+.053, +.097].

**Jev L4-D is below Jev L3 — does that sink L4-D?**
For a strong cloud decision model the whole-unit question is already good (L3 .949); L4-D at the pre-specified
τ 0.5 gives .907 (−.042 [−.071, −.013]), ≈ DeepSeek L4. Its errors are false leaks (238 FP, 7 FN), mostly from
wrong realloc_safe answers in vacuous `realloc(NULL)` + exit cases (a gold convention our LoRA learned). With the
dev-chosen τ 0.27 it reaches .944 (backup only; τ 0.5 was fixed before any call). L4-D's value is for the local
models: it is the best strategy for every one of them.

**Was the Intern L4-D threshold chosen fairly?**
No — and in the baseline's favour. The frozen dev τ (0.18, tuned on Debiased) makes Intern answer Yes to every
exec/release question, so dead frees count as "runs on every path" and leak recall is .037 (macro-F1 .373). The
primary was switched to τ = 0.5 after seeing eval, to match Intern L1–L3 (calibrated default). Our fine-tuned model
keeps its dev-chosen τ. Backup slide "Intern-Decision L4-D and its threshold".

**If the strategy does most of the work, why fine-tune at all?**
On the same weights, +.074 [+.053, +.097] (read-out L4-D .752 → .826), the step from 66 % to 89 % of the gap, and
it is the only fine-tuning that beats every untuned Qwen form (+.067 over gen. L3). Unit-label FT does not
(L1 +.021 n.s.; FT L1/L3 stay below the untuned generator). But the honest headline is the strategy (+.401).

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
