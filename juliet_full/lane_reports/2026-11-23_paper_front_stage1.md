I've written all the front-lane sections, tables, the overview figure and the bibliography. `make pdf OUTDIR=build_front` and `make check OUTDIR=build_front` both pass ("clean", 16 pages). My sections come to about 6.45 pages against the 6.25-page budget.

**Files written** (all under `report/final_en/`):
- `sections/00_abstract.tex`, `01_introduction.tex`, `02_background.tex`, `03_benchmark.tex`, `04_methods.tex`, `07_threats.tex`, `08_conclusion.tex`, `09_appendix_front.tex`
- `tables/front_dataset.tex` (tab:dataset), `tables/front_split.tex` (tab:split), `tables/front_methods.tex` (tab:methods)
- `figures_front/overview.tex` and `overview.pdf` (fig:overview)
- `references.bib` (82 entries) and `references_KEYS.md`

**Your mid-run steer:**
- `tab:orig` is only `\ref`'d in my sections. I had briefly `\input` it in §III, which gave a "multiply defined" warning; that's removed.
- `tab:probes` is `\input` only in §III. I checked that §V doesn't input it.
- I didn't touch `\balance`. Your removal is already in `main.tex`.
- None of my sections state the grep, DeepSeek-placebo or McNemar facts in a way that conflicts with yours.

**Page count:**
- The body runs from page 1 to the top of page 11, about 10.5 pages, so it meets the ≥10 requirement.
- Per section (estimated from the page renders, with section starts found by `pdftotext`):

| Section | Budget | Actual |
|---|---|---|
| I (with title, abstract, figure) | 1.0 | ≈1.2 |
| II | 1.0 | ≈1.0 |
| III (with 3 tables) | 1.75 | ≈1.6 |
| IV (with table) | 1.75 | ≈1.8 |
| VII | 0.5 | ≈0.5 |
| VIII | 0.25 | ≈0.25 |

- I rendered pages 1–7, 10, 11, 13 and 14 at 60 dpi and found no layout problems.

**Bibliography** (details in `references_KEYS.md`):
- **Added 24 keys:** germano2025biased, calcagno2009biabduction, le2022pulse, inferpulse, king1976symbolic, avgustinov2016ql, jordan2016souffle, wang2026nesa, wang2024llmdfa, wen2024llm4sa, li2024llift, nie2025vulnllmr, zhu2026interndecision, zhao2026cyberjev, dewachter2026lookhere, zhang2026anyjev, typesafe2026jev, kwon2023vllm, qwen35card, deepseek2026v4, deepseekdocs, black2018juliet13, sardjuliet13, plus hu2022lora (reworked).
- **Wrong seed entries, now fixed:**
  - ding2025primevul: page numbers.
  - boland2012juliet: title.
  - cppcheck: version note.
  - holm1979: JSTOR URL added.
  - zhou2019devign: an author was "Wang" instead of "Du".
  - hu2022lora: now cited as arXiv only. I couldn't confirm the ICLR venue because OpenReview blocked the check.
  - cppreference_realloc: URL had moved.
- Nothing was removed.

**Where the typed numbers come from** (each also has a `% src:` comment in the file):
- **Probe and result numbers:** abstract, intro and the §III audit use `\res` macros.
- **Benchmark counts** (1,658 / 42 / 48 / 868 / 790; mechanisms 960 / 588 / 108 / 2; dev 330/660; eval 1,328/2,656; folds; subsets): `juliet/full_split_v1.json` and `juliet_full/data/README.md`.
- **Label verification:**
  - From `verify_report.md`: 3,316/3,316 compile, 175 more misses without `use_stacks=0`, 1,474/1,658 bad leaks, the 68 / 108 / 8 explained misses, and Valgrind 100/100, 99 and 87.
  - From `verify_layer3_report.md`: 3,236 units outside variant 12 keep their verdict on \Dead.
- **Good-entry sampling:** 110 groups, 6,632 records and the leakage test from `juliet_full/data/README.md`; guard AUROCs 0.989 and 0.572 from `lane_reports/data_stage3.md`.
- **§IV:**
  - Jev thresholds 0.58 / 0.635 / 0.585: `jev_thresholds.json`.
  - Intern-Decision thresholds 0.823 / 0.673 / 0.539: `gpu/README.md:139-140`.
  - LoRA setup (32,464,896 trainable parameters, τ=1, λ=1, learning rates 1e-4 / 1e-3): `decision_ft/README.md`.
  - Budget caps ¥9.5 / $4: `llm/README.md`.
  - Tool versions: `STATUS.md:33`.
  - Dell hardware: `lscpu` / `free`.
  - DeepSeek coverage per layer: line counts of the result files.
- **Pilot appendix:** `report/report_latest_zh.tex:70` (.383/.399/.381, .346/.346/.365, 61.7% / 74.4% vs 72.2%, p=.029 / .644).

**Open issues:**
1. Three small overfull vboxes (≤1.9 pt) remain, all in your appendix around `tables/res_provenance.tex`. `make check` didn't flag them in the final run but did earlier.
2. I removed the SecVulEval citation from §II to save space; it is now cited only in the appendix pilot.
3. Fact to keep consistent with §V: DeepSeek also has \Dead runs for L1–L3 on the larger `api_subset`. §IV says this, while the threats section and §V describe the paired comparisons, which use `nested25` only.
4. No changes needed in `main.tex`.