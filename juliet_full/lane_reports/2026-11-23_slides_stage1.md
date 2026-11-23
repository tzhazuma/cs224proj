I built the deck, figures pipeline, speaker notes and README in `presentation/pre/`. `main.pdf` is 30 pages at 16:9, and a clean `make` gives zero errors, zero overfull boxes and no missing fonts. I looked at every page as a PNG and fixed the layout problems I found.

The 30 pages are the title, 5 section dividers, 17 numbered content slides, a Thank-you slide and 6 backup slides. The backups cover demo screenshots (placeholder), dynamic blind spots (108 / 68 / 8) and the LSan `use_stacks=0` rationale, the budget, dev feasibility checks, the SecVulEval note, and a table of which result file each figure used. Every result slide carries a "preliminary" badge and every figure a "PRELIMINARY · eval set · date" stamp.

**Files** (all under `presentation/pre/`):
- `main.tex`, plus `sections/01_motivation.tex`, `02_benchmark.tex`, `03_methods.tex`, `04_results.tex`, `05_demo_plan.tex`, `99_appendix.tex`
- `Makefile`: `make` (figures + PDF), `make figures`, `make pdf`, `make check`, `make pngs`, `make clean`
- `figures/make_figures.py` and `figures/methods.json` (the list of methods and where their result files are). Generated outputs: `probes.pdf`, `prf1.pdf`, `pareto.pdf`, `heatmap.pdf`, `numbers.tex`, `provenance.tex`, `results_summary.json`
- `notes.md`: script per slide adding up to 17:00, plus 12 likely Q&A questions with answers
- `README.md`, `fontconfig/fonts.conf`, `tools/contact_sheet.py`, `.gitignore` (ignores `build/`)

**Packages installed** with `tlmgr`, user tree only: `beamertheme-metropolis`, `pgfopts`, `fira`, `pgfplots`, `appendixnumberbeamer`. Fontconfig can't see the TeX Live Fira fonts, so the Makefile points `FONTCONFIG_FILE` at a local config. That affects only processes `make` starts.

**Numbers shown now (preliminary, eval set of 2,656 units):**

| Method | F1 |
|---|---|
| DeepSeek L1 / L2 / L3 | .996 / .998 / .995 |
| Jev L1–L3 | about .97–.98 |
| ASan/LSan (reference, not ranked) | .950 |
| CodeQL | .891 |
| Clang SA | .842 |
| Infer | .789 |
| grep | .749 (macro-F1 .701) |
| LineVul | .577 |
| Cppcheck | .287 |

- **Infer changed mid-task.** The static lane added a new run that analyses all of a unit's files together; it scores .789, against .556 for the older per-unit run. The pipeline now picks the newer run. I updated the slide text, notes and README to match, but the static lane hasn't called its runs final.
- **DeepSeek near-ceiling.** Since DeepSeek is near-perfect on layer ①, the slides say the stress-test layer ③ and latency/cost decide the ranking, and note that Juliet is public so contamination can't be ruled out.

**Still pending** (drawn as grey "pending", never as numbers):
- DeepSeek L4
- Qwen3.5-4B L1–L4
- Intern-Decision-4B L1–L3
- the LoRA decision model, L1 and L3
- all results on layer ② and on layer ③ + placebo (the slides describe these layers but have no result figures yet)
- single-call latency: DeepSeek's latency comes from a run with 16 concurrent requests and CodeQL's from batches of 50, so both are drawn hollow

**Refreshing later:**
1. Run `make` in `presentation/pre/`. A clean build takes about 6 s and re-scores whatever result files exist, using `juliet_full/analysis/score.py`.
2. Run `make check` and `make pngs`, then look at pages 18–20 and 30.
3. Reread the wording of the bullets on slides 13–15. The numbers update automatically, but phrases like "best analyzer" may need editing if the ranking changes.

**Two paths are guesses:**
- **Intern-Decision:** `gpu/results/intern_decision*/layer1/*.jsonl`. No run or code for it exists yet.
- **LoRA:** `decision_ft/...`. Its results are written on the GPU host by default and must be synced into `juliet_full/decision_ft/` before the pipeline can find them.

If either lands elsewhere, edit only that method's `globs` in `figures/methods.json`.

**Other open items:**
- The backup screenshot slide stays a placeholder until the demo lane provides recordings.
- STATUS hasn't settled whether merged or unmerged LoRA scores get reported.
- I wrote nothing outside `presentation/pre/`. The other modified files in `git status` belong to other lanes (llm, data).

Next step for you: copy this report to `juliet_full/lane_reports/` and commit `presentation/pre/`.