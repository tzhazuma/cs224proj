I've written §V, §VI and the appendix and checked the rendered pages. `make figures && make pdf OUTDIR=build_results && make check OUTDIR=build_results` prints `clean`, 16 pages, and no `\res` value shows up as *pending* in the PDF. Two things are outstanding: §V runs to about 3.4 pages against the 2.75 budget, and I had to work around a `\balance` problem in main.tex.

**Files written** (all in report/final_en/)
- `sections/05_results.tex`, `sections/06_discussion.tex`, `sections/10_appendix_results.tex`
- `figures/make_figures.py`, `figures/methods.json` (slides registry plus Jev/Intern-Decision secondary-threshold entries), `figures/latency_c1.csv`, `figures/pareto.pdf`, `figures/robust.pdf`
- `generated/numbers.tex`, `generated/results_summary.json`
- `tables/res_{probes,orig,main,flow,latency,robust,lora,repeat,mcnemar,full_main,full_layers,folds,provenance}.tex`

`references_results.bib` holds only its header comment.

**Macros, labels and page estimate**
- **Macros:** all 1,555 original slide keys in `numbers.tex` are kept with identical values; there are about 3,500 keys in total. New metrics per run include `dci`, `adj`, `lost`, `gained`, `flips`, `r_<mech>`, `spec_<kind>` and `flow_<cat>`. New `\res{x}{…}` keys cover probes, unit counts, repeats, cost per 1k units, GPU-hours, latencies, McNemar results, per-fold AUROC, training hours and the error-breakdown counts used in §VI.
- **Labels:**
  - Sections: `sec:results`, `sec:rq1`…`sec:rq4`, `sec:discussion`, `sec:errors`, `sec:implications`, `app:results`, `app:provenance`.
  - Figures: `fig:pareto`, `fig:robust`.
  - Tables: `tab:probes`, `tab:orig`, `tab:main`, `tab:flow` (full-width), `tab:latency`, `tab:robust`, `tab:lora`, `tab:repeat`, `tab:mcnemar`, `tab:full-main`, `tab:full-layers`, `tab:folds`.
- **Pages:** §V ≈ 3.4 (counting the full-width flow table), §VI ≈ 0.95, appendix ≈ 3.

**McNemar/Holm** (18 tests on the 2,656 paired \Deb units, Holm over all 18)
- 14 of 18 are significant after Holm, and for each of those the family-clustered bootstrap CI of the accuracy difference excludes zero.
- **Not significant:**
  - DeepSeek L1 vs L2: Holm .57
  - DeepSeek L1 vs L3: Holm 1
  - DeepSeek L2 vs L3: Holm .26
  - Qwen L2 vs L4: Holm .57
- **DeepSeek L4** is worse than L1, L2 and L3 (Holm 6.2e-8, 1.7e-10, 1.3e-7).
- **Qwen**, other pairs:
  - L1–L2: 5.6e-9
  - L1–L3: 9.4e-27
  - L1–L4: 7.5e-4
  - L2–L3: 2.0e-7
  - L3–L4: 2.2e-9
- **DeepSeek vs Qwen:** DeepSeek wins under every strategy (Holm ≤ 2.4e-79).
- **Best LLM vs best static analyzer:** DeepSeek L2 vs CodeQL, only-A-right 306 vs only-B-right 0, Holm 5.7e-67.
- **Best method vs grep:** DeepSeek L2 vs grep, 773 vs 6, Holm 1.4e-164.

Like the static lane's analysis, the test is unclustered, which the paper says. The clustered CI is my addition.

**Conflicts between the lane reports and the score files**
- None in the metrics: the scores recomputed with score.py match the reports, and the latency recomputation raised no warnings.
- **CodeQL latency:** the static_stage1 report gives 23.7 s per unit, measured under load. I used the quiet 7.36 s from the static_stage2 latency file.
- **Qwen latency:** the LLM lane's 635 ms was measured while the GPU was shared. I used the idle-GPU 0.333 s.
- **grep on \Orig:** .935 is on the eval split; the full set gives .940. The paper says "eval units" throughout.
- **Task examples that don't hold on eval:**
  - new_TwoIntsClass_68 and new_array_char_18 are dev units, so I used the eval unit new_array_char_01 instead.
  - "L4 writes identical facts for leaking vs fixed realloc" happened with the v1 prompt on dev. On eval only the virtual_destructor_01 pair has identical facts, and the text says so.

**New finding in §VI.** Clang SA misses all 132 eval `new` leaks whose pointer is passed to a print helper, but only 44 of 429 such `malloc` leaks. CodeQL reports all 132 and Infer 62. The text presents this as the checker treating the pointer as escaped.

**Bib keys added:** none. Every key I cite is already in references.bib.

**Open issues and requests**
1. **main.tex `\balance`:** it causes `Overfull \vbox` warnings on the pages after the bibliography. Commenting it out removes them all. As a workaround, the generated `res_provenance.tex` starts with `\nobalance`, so the last page is not balanced. Better fix: drop `\balance`, or move it so nothing follows it.
2. **tab:orig:** I `\input` it in §V RQ1, since §I only `\ref`s it. The front lane must not `\input` it as well, or the label will be defined twice.
3. **§V length:** about 0.65 pages over budget. Moving `tab:repeat` and/or `tab:lora` to the appendix would recover most of it. That's your call.
4. **DeepSeek \Plac:** there is a placebo run only for L1, so placebo-adjusted deltas for DeepSeek L2–L4 show "--".
5. The optional cascade simulation was not done.