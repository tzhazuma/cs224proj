# Speaker notes (v3, IMRaD): "Near-LLM Quality at Decision-Model Speed?"

Talk: 17:00 for slides and live demo, then Q&A (course slot 15–20 min). Structure: Introduction → Methods →
Results (ends with the live demo) → Discussion (ends with the take-home). Section divider pages take no time.
Result numbers on the slides come from `figures/numbers.tex` (written by `make figures` from the result files);
the paired-bootstrap numbers come from the parent analysis `juliet_full/analysis/near_llm_bootstrap.py` (seed 20261123) and are typed into the
slides with a `% src:` comment. All scores are macro-F1 on the eval set (2,656 units, 39 flow variants never used
for prompts or thresholds) unless a slide says otherwise.

Main line, in one sentence: **a small decision model reaches near-LLM quality at about 7× the speed in
distribution, but not (yet) under DeadFree.**

| # | Section | Slide (assertion title) | Time | Running |
|---|---------|-------------------------|------|---------|
| 0 | — | Title | 0:20 | 0:20 |
| 1 | Intro | Can a decision model give LLM quality at IDE speed? | 1:00 | 1:20 |
| 2 | Intro | On original Juliet, a one-line rule beats every static analyzer | 1:00 | 2:20 |
| 3 | Methods | Debiased: good units now look like bad units | 0:45 | 3:05 |
| 4 | Methods | DeadFree adds a free that never runs | 0:50 | 3:55 |
| 5 | Methods | We test on unseen flow variants, with paired statistics | 0:35 | 4:30 |
| 6 | Methods | Main axis: generative LLMs vs decision models | 0:40 | 5:10 |
| 7 | Methods | Our decision model: Qwen3.5-4B + LoRA, one score per unit | 0:40 | 5:50 |
| 8 | Results | Debiasing removes the template shortcuts | 0:35 | 6:25 |
| 9 | Results | The three best detectors on Debiased are LLM-based | 0:45 | 7:10 |
| 10 | Results | Our decision model is 1.1 points below DeepSeek, above Jev | 0:50 | 8:00 |
| 11 | Results | About 7× faster than DeepSeek, at the IDE budget edge | 0:40 | 8:40 |
| 12 | Results | **DeadFree breaks learned models in two opposite ways** (key slide) | 1:10 | 9:50 |
| 13 | Results | Fine-tuning learned the free-shortcut | 0:50 | 10:40 |
| 14 | Results | Clang SA evidence (L3) helps weak models most | 0:35 | 11:15 |
| 15 | Results | Path-sensitive analyzers ignore dead frees | 0:30 | 11:45 |
| 16 | Results | Live: one dead free fools grep and our model | 2:30 | 14:15 |
| 17 | Discussion | In distribution, a decision model reaches near-LLM quality | 0:40 | 14:55 |
| 18 | Discussion | Under DeadFree it does not, yet: robust ≠ sound | 0:40 | 15:35 |
| 19 | Discussion | In progress: L4-D lets the decision model answer facts, not verdicts | 0:45 | 16:20 |
| 20 | Discussion | Four caveats limit these claims | 0:25 | 16:45 |
| 21 | Discussion | Take-home: yes in distribution, not yet under DeadFree (+ Questions) | 0:15 | 17:00 |

If time runs short: shorten slide 5 and slide 14 to one sentence each; never cut slides 12 or 16.

## 0. Title (0:20)
We compare LLM-based ways to find C/C++ memory leaks. The title asks a question; by the end we answer: yes in
distribution, not yet under a hard but label-preserving edit.

## 1. Can a decision model give LLM quality at IDE speed? (1:00)
Leak checks run in three places: the IDE, where we have about a tenth of a second; pre-commit, about one second;
and CI, about ten seconds. Large generative LLMs are accurate, but they write text, so they are slow and every
call costs money. A decision model reads the same code but only outputs one score, with no text generation. Our
question: can such a model reach near-LLM quality? The task is memory leaks (CWE-401) in Juliet test units.

## 2. On original Juliet, a one-line rule beats every static analyzer (1:00)
Before comparing models we checked the benchmark. On the original Juliet, the rule "`static void` means good" is
perfect, 1.000, because good units are written as static helper functions. The rule "no free or delete means
leak" scores 0.935, better than Clang SA (0.822), CodeQL (0.785) and Infer (0.770). So a high Juliet score may
mean the model reads templates, not memory. We had to rebuild the benchmark first.

## 3. Debiased: good units now look like bad units (0:45)
An original good unit has two static helpers and a wrapper. We keep one helper per group, drop the wrapper and
strip `static`, so good and bad units have the same shape and length. Bad units are unchanged. Half of the good
units are G2B, which use stack memory and have no free at all, so the grep rule is now wrong on them.

## 4. DeadFree adds a free that never runs (0:50)
DeadFree is our stress test. In a bad unit we add a `free` under a guard that is always false, so it is still a
leak. In a good unit the real `free` moves under an always-true guard, so it is still safe. Labels do not change,
and both classes now contain a `free`, so "has a free" says nothing. Placebo is the control: the same guard, but
with a print instead of a free. If a model drops on DeadFree but not on Placebo, the dead free is the cause. All
3,316 units compile with gcc and clang, and we re-checked labels with ASan/LSan.

## 5. We test on unseen flow variants, with paired statistics (0:35)
We split by flow variant, not by family, because families differ mostly by data type. Dev is only for prompts
and thresholds. Eval is 39 unseen flow variants, 2,656 units. Our LoRA model trains on two folds and predicts the
third. We report macro-F1, median latency per unit at concurrency one, and paired tests: family-cluster bootstrap
and McNemar with Holm correction.

## 6. Main axis: generative LLMs vs decision models (0:40)
The main comparison is generative LLMs, DeepSeek over its API and Qwen3.5-4B locally, against decision models:
Jev over its API, Intern-Decision, and our LoRA decision model. Static analyzers are baselines. Dynamic tools run
the code, so we show them as a reference, not a competitor. Prompt strategies are secondary: L1 direct, L2
few-shot, L3 adds Clang SA warnings, L4 lets the LLM list facts and a Datalog program decides.

## 7. Our decision model: Qwen3.5-4B + LoRA, one score per unit (0:40)
Our model is Qwen3.5-4B with a LoRA adapter. The score is the logit of "Yes" minus the logit of "No", from a
single forward pass; a threshold chosen on dev turns it into a verdict. We train only 0.70% of the weights, with
balanced cross-entropy plus a ranking loss that puts each bad unit above its good twin. It runs on one local GPU.

## 8. Debiasing removes the template shortcuts (0:35)
After the rebuild, format probes fall to chance: `static void` drops from 1.000 to 0.333, and grep from 0.935 to
0.701. Bag-of-words still scores high, but its cues are task words such as `free`, `delete` and `ALLOCA`, which a
real detector should use. So Debiased measures the task, not the template.

## 9. The three best detectors on Debiased are LLM-based (0:45)
On Debiased, DeepSeek L1 leads with 0.995, then our LoRA decision model at 0.984 and Jev at 0.971. The best static
analyzer is CodeQL at 0.882. Qwen3.5-4B used as a generator is weak, 0.754. The grey line is ASan/LSan, which runs
the code, at 0.945.

## 10. Our decision model is 1.1 points below DeepSeek, above Jev (0:50)
This is the in-distribution answer. Our model is 0.011 below DeepSeek, with a paired 95% interval from −0.014 to
−0.008. So DeepSeek is significantly better, but the gap is inside the 0.02 margin we fixed before running eval.
Our model is also 0.013 above the Jev API. Precision is 0.999 and recall 0.969. On the right: 0.105 s per unit,
against 0.715 s for DeepSeek.

## 11. About 7× faster than DeepSeek, at the IDE budget edge (0:40)
On the accuracy–latency plot, our model sits at the edge of the IDE band, about seven times faster than DeepSeek,
which is in the pre-commit band. Clang SA is faster still, 18 ms, but at 0.855. DeepSeek also costs about ¥0.40
per thousand units; our model has no API cost. Latency is the median at concurrency one.

## 12. DeadFree breaks learned models in two opposite ways — key slide (1:10)
Each row goes from Debiased (open circle) to DeadFree (filled). Clang SA and Infer do not move: zero flips. Jev
drops a little. Then two failure modes. Red: misses. grep, CodeQL and our LoRA model treat any `free` as "freed",
so the dead free hides the leak; our model loses 1,234 detections. Orange: false alarms. Qwen3.5-4B and
Intern-Decision doubt a real free inside a guard and flag safe code. DeepSeek also mostly over-flags: 0.998 to
0.881 on the 664-unit subset. The grey diamonds are Placebo: they stay close to Debiased, so the drop is caused by
the dead free, not by an unfamiliar edit.

## 13. Fine-tuning learned the free-shortcut (0:50)
Our LoRA model goes from 0.984 to 0.372 on DeadFree; leak recall falls to 0.041. The same base model without
LoRA drops much less, 0.703 to 0.619. On Placebo it stays at 0.976. So training sharpened one cue: "free present
means safe". High accuracy on Debiased was not evidence of program understanding.

## 14. Clang SA evidence (L3) helps weak models most (0:35)
Adding Clang SA warnings to the input (L3) does nothing for DeepSeek or for our model on Debiased. It helps the
weaker models: Qwen3.5-4B from 0.754 to 0.858. Under DeadFree it helps most: our model recovers from 0.372 to
0.639. Evidence helps, but it does not fix the shortcut.

## 15. Path-sensitive analyzers ignore dead frees (0:30)
Clang SA, Infer, Cppcheck and the enhanced dynamic run have zero flips: they prune the infeasible branch, so the
dead free never runs for them. But robust is not complete: Clang SA still finds only 77% of the leaks.

## 16. Live demo (2:30)
Stage unit `CWE401_Memory_Leak__strdup_char_01`, a bad unit. First run: everyone says leak. Then add
`static const int sym_61 = 4;` and `if(sym_61 > 4) { free(data); }`. The free never runs, so it is still a leak.
Run again: grep and our LoRA model flip to "safe"; Clang SA, DeepSeek and Jev still say leak. Command:
`./demo.py --allow-eval --allow-peak` (with `--ft-l3 --jev`). If the network or GPU fails, play
`../demo/recordings/stage_final.mp4` or run `./demo.py --replay recordings/stage_final.json`. The backup slide
"demo dry run" shows the expected table.

## 17. In distribution, a decision model reaches near-LLM quality (0:40)
What holds: 0.984 vs 0.995, a gap of 0.011, inside our margin, at about seven times the speed, on a local 4B model
that also beats the Jev API. So on in-distribution code, the answer to the title is yes.

## 18. Under DeadFree it does not, yet: robust ≠ sound (0:40)
What does not hold: one dead free drops our model to 0.372. The most robust LLM-based detectors are Jev, 0.946,
and DeepSeek, 0.881 on the subset. Clang SA is robust but misses 23% of leaks, so robust is not the same as sound.
Lesson: test with edits that keep the label.

## 19. In progress: L4-D lets the decision model answer facts, not verdicts (0:45)
Our next step keeps decision-model speed but moves reasoning into rules. A lexical parser finds candidate sites;
the decision model answers short fact questions, such as "does this branch always, never or sometimes run?";
Datalog rules derive the verdict. Fact labels come from dynamic analysis. With gold facts, the rules reach 0.991 on
Debiased, DeadFree and Placebo, and 0.985 on Original: that is the ceiling, not a result. Training is running; we
have no L4-D results yet.

## 20. Four caveats limit these claims (0:25)
Juliet is synthetic and public, so contamination is possible. DeepSeek on DeadFree and Placebo uses a 664-unit
subset because of the API budget. We have one LoRA run, and dev was saturated, so checkpoint choice is weak.
LineVul is zero-shot.

## 21. Take-home (0:15)
Near-LLM quality at decision-model speed: yes in distribution, not yet under DeadFree. And check the benchmark
before ranking models. Thank you — questions?

## Q&A prep

**Q: Juliet is public. Are the LLM scores just memorization (contamination)?**
Possibly on Original; that is why we never rank on Debiased alone. DeadFree units did not exist before this
project, the edit keeps the label, and the drops are measured on the same units (paired). Placebo shows that the
drop is caused by the `free`, not by "unfamiliar code".

**Q: Why are ASan/LSan and Valgrind not ranked? They look best.**
They need a build, a run and the right input, so they answer "did this execution leak", not "does this code
leak". Plain ASan/LSan misses all realloc-failure leaks (0/84 eval), memory reachable from a global at exit
(variants 45/68), and untaken random branches (variant 12). Dynamic-enhanced reaches 1.000 only because we know
which seed, option (`use_globals=0`) and fault to inject. We run LSan with `use_stacks=0`; with default options 175
more bad units are missed.

**Q: Why does DeepSeek run on a subset for DeadFree?**
The DeepSeek cap is ¥10 (total spent ¥8.21; Jev $1.90). Debiased: full eval set. DeadFree, Placebo and Original:
the fixed nested25 subset (664 units); every comparison is paired on those units. On that subset DeepSeek L1's
Debiased score is 0.998, so its DeadFree drop is 0.998 → 0.881.

**Q: Is the 0.02 margin post hoc?**
No. PLAN §4.2 fixed "near-LLM" as macro-F1 ≥ DeepSeek L1 − 0.02 (lower CI bound ≥ −0.02 for equivalence) and the
speed target c1 ≤ 0.36 s before eval. Both hold: CI lower bound −0.014, latency 0.105 s.

**Q: How did you choose the LoRA checkpoint? Could another one be robust?**
By dev AUROC, then dev loss. Dev AUROC is 1.0 at almost every evaluation, so the choice rests on tiny dev-loss
differences. A more robust checkpoint may exist, but picking it by DeadFree would be test-set tuning. That is the
point: on this benchmark, dev data cannot tell a robust model from a shortcut model.

**Q: Why is LineVul not fine-tuned?**
We replaced "fine-tune LineVul" with the Qwen3.5-4B LoRA, so one 4B model can be compared as generator, read-out
and fine-tuned decision model. LineVul stays zero-shot (0.501). Our LoRA result suggests fine-tuning any classifier
on Debiased would mostly teach it the `free` cue.

**Q: Merged vs unmerged adapters?**
We report merged weights. Unmerged give the same held-out predictions (0 flips of 2,656 for L1 and L3).

**Q: Why does CodeQL drop on DeadFree if it does dataflow?**
Its leak query does not rule out the never-taken guard, so the dead `free` counts: it loses 309 detections.
Separately, batching 50 units per database adds 4 false positives on `_08` units (shared helper names); frozen,
documented in backup.

**Q: What about L4 (LLM facts + Datalog) with DeepSeek?**
Backup slide. DeepSeek L4 is lower on Debiased (0.976) but has the smallest DeadFree drop of L1–L4 (−0.078), and
its errors turn into misses instead of false alarms. L4 never sees Clang's output.

**Q: Are the thresholds tuned?**
Jev uses the pre-registered 0.5; our LoRA model uses the threshold chosen on dev macro-F1. Budget bands on the
Pareto plot are descriptive.

**Q: Is L4-D just the old L4 with a smaller model?**
No: in L4 the LLM writes all facts freely; in L4-D the candidate sites come from a parser and the decision model
only answers typed yes/no or multiple-choice questions, trained on labels from dynamic analysis. No results yet.
