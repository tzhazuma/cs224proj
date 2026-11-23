# Pre slides: CS224 course project (Beamer, metropolis, 16:9)

"Do Memory-Leak Detectors Read Code or Templates? Rebuilding Juliet CWE-401 to compare static analysis, LLMs
and decision models". The talk is on Nov 26, 2026, and runs 17 min plus Q&A. The speaker script is in `notes.md`.

## Build

```bash
cd presentation/pre
make            # = make figures + make pdf  -> main.pdf
make figures    # re-render figures/*.pdf, numbers.tex, provenance.tex from the current result files
make pdf        # latexmk -xelatex into build/, copies build/main.pdf to main.pdf
make check      # errors / overfull boxes / missing fonts in build/main.log
make pngs       # page previews in build/pages/ (pdftoppm -r 50)
make clean
```

`tools/contact_sheet.py <first> <count> <out.png>` tiles the previews from `build/pages/`, two per row,
for layout review.

You need TeX Live 2026 in `~/.local/share/texlive/2026`, with `xelatex` and `latexmk` in `~/.local/bin`; the
Makefile puts that directory on `PATH`. The figures need Python 3 with matplotlib (tested with 3.12 /
matplotlib 3.6.3) and nothing else.

### Packages installed with `tlmgr install` (user tree only, nothing system-wide)
- `beamertheme-metropolis`
- `pgfopts` (dependency of metropolis)
- `fira` (Fira Sans / Fira Mono OTF)
- `pgfplots`
- `appendixnumberbeamer`

### Fonts
fontconfig does not see the TeX Live font tree, so metropolis would fall back from Fira Sans. To fix that,
`fontconfig/fonts.conf` adds `~/.local/share/texlive/2026/texmf-dist/fonts/opentype/public/fira` to the
system configuration, and the Makefile exports `FONTCONFIG_FILE`. This only affects the processes that
`make` starts. Fira Mono is loaded by file name in `main.tex`, because the family name resolves to the
oblique face. matplotlib registers the same Fira Sans files directly.

## Files

| Path | What |
|------|------|
| `main.tex` | preamble (theme, palette, listings/TikZ styles, `\res`, `\prelim`) and the section list |
| `sections/01_motivation.tex` | hook (grep 0.940), where the shortcut comes from, task + RQ1–RQ4 |
| `sections/02_benchmark.tex` | layer ① transformation (TikZ), probes, label verification, three layers + stress/placebo code, split |
| `sections/03_methods.tex` | method matrix, L1–L4, L4 pipeline (TikZ) + `leak.dl` rules, one 4B model three uses |
| `sections/04_results.tex` | P/R/F1, latency Pareto, flow-category heatmap (all marked preliminary) |
| `sections/05_demo_plan.tex` | live demo plan, timeline to Dec 24, Thank you |
| `sections/99_appendix.tex` | backup slides: demo screenshots placeholder, dynamic blind spots + LSan options, budget, dev feasibility, SecVulEval, provenance table |
| `figures/make_figures.py` | figure pipeline (read-only on `juliet_full/`) |
| `figures/methods.json` | method registry: label, family, strategy, result-file globs |
| `figures/{probes,prf1,pareto,heatmap}.pdf` | generated figures |
| `figures/numbers.tex` | generated `\res{<key>}{p\|r\|f1\|macro\|lat}` macros; a method without a run prints "pending" |
| `figures/provenance.tex` | generated backup table: run file, coverage, F1, sha256 prefix per method |
| `figures/results_summary.json` | generated, machine-readable version of the same scores |
| `fontconfig/fonts.conf` | local fontconfig (see Fonts) |
| `tools/contact_sheet.py` | page-preview tiler |
| `notes.md` | speaker script with a time budget and Q&A prep |
| `.gitignore` | ignores `build/` (latexmk output, fontconfig cache, page previews) |

The deck has 30 pages: the title, 17 numbered content frames, 5 section dividers, the Thank-you frame, and 6
backup frames.

## How the figures work

`make_figures.py` reads `figures/methods.json`. Each method entry lists globs relative to `juliet_full/`,
in the lane-contract layout `<lane>/results/<method>/<layer>/<run_id>.jsonl`. There are two modes:
- `pick` (default) takes the best single file. A file qualifies if it covers ≥ 90 % of the eval set
  (2,656 units, 39 flow variants); an earlier glob wins, then the newest file. `*.evidence.jsonl`,
  `raw_logs/`, `scratch/` and `.venv` are ignored.
- `union` merges all matching files, and the newer file wins per unit. This is used for the LoRA model;
  with `own_fold` it keeps only rows where `extra.fold == extra.unit_fold`.

Scoring imports `juliet_full/analysis/score.py`, which also supplies the family-bootstrap 95 % CIs
(2,000 resamples) used as Pareto error bars. If that file is missing, a small fallback scorer with the same
rule is used: missing, invalid or timed-out predictions count as wrong. The fallback gives no CIs, so the
error bars are omitted. Methods with no qualifying file are drawn as grey "pending"
slots and are never given a number. Every figure carries a "PRELIMINARY · eval set · date" stamp.
Latency points are hollow when the run was batched or concurrent, according to `timing_mode`,
`concurrency`, `source_metas` or `extra.batch_size` in the meta/rows.

### Refreshing later (parent)
1. Let the lanes write their result files, then run `make` here. A clean build takes about 6 s.
2. Run `make check`; it should print `clean: no errors, overfull boxes or missing fonts`. Then run
   `make pngs` and look at pages 18–20 (results) and 30 (provenance).
3. Read the bullets on slides 13–15 again. They quote numbers through `\res`, so the values update, but
   the wording ("near-perfect", "best analyzer") may need editing if the ranking changes.
4. If a method's files live somewhere else, edit only its `globs` in `figures/methods.json`.

### Paths that are guesses (check when the runs land)
- Intern-Decision-4B: `gpu/results/intern_decision*/layer1/*.jsonl`. No such run or code existed yet.
- LoRA decision model: `decision_ft/**/results/*.jsonl` and `decision_ft/results/decision_ft/layer1/*.jsonl`.
  The default DFT output directory is on the GPU host, so results must be synced into `juliet_full/decision_ft/`.
  Rows are expected to be `method=decision_ft`, `model=qwen3.5-4b-lora-fold{k}`, `extra.fold` / `extra.unit_fold`, and
  `strategy` L1 or L3.
- Qwen3.5-4B: `llm/results/qwen3_5_4b/layer1/eval_*.jsonl` (from `llm/run_llm.py` METHOD map).
- DeepSeek L4: `llm/results/deepseek_flash/layer1/eval_*.jsonl` with `strategy == "L4"`.

## Pending numbers (as of the last `make`, 2026-11-23)
Shown as "pending" in the figures:
- DeepSeek V4.1 Flash L4
- Qwen3.5-4B L1–L4
- Intern-Decision-4B L1–L3
- Qwen3.5-4B LoRA decision model L1, L3 (3-fold CV, training)

Other open items:
- All layer ② and layer ③ / placebo results. The slides only describe the layers; there are no result
  figures for them yet.
- Concurrency-1 latency. DeepSeek has `latency30_c1_L1.jsonl`, but the figures still use the c16 bulk run
  (hollow marker). Batched CodeQL is also hollow.
- Static runs are marked not yet final by the static lane. Infer currently resolves to
  `full_per_file_merged.jsonl` (all of a unit's files as one TU, F1 ≈ 0.79); the older per-unit run had
  F1 0.556.
- Merged vs unmerged LoRA scores: STATUS says the choice is still TODO.
- The backup demo screenshots slide is a placeholder until the demo lane provides recordings.
