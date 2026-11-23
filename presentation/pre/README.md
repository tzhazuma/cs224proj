# Pre slides: CS224 course project (Beamer, metropolis, 16:9)

"Do Memory-Leak Detectors Read Code or Templates? Rebuilding Juliet CWE-401 to compare static analysis, LLMs
and decision models". The talk is on Nov 26, 2026, and runs 17 min plus Q&A. The speaker script is in `notes.md`.

## Build

```bash
cd presentation/pre
make            # = make figures + make pdf  -> main.pdf
make figures    # re-score every result file and re-render figures/*.pdf and the generated figures/*.tex
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
| `main.tex` | preamble (theme, palette, listings/TikZ styles, `\res`, `\cmark`/`\xmark`) and the section list |
| `sections/01_motivation.tex` | hook table on ORIGINAL Juliet (`figures/original.tex`), where the shortcut comes from, task + RQs |
| `sections/02_benchmark.tex` | layer ① transformation (TikZ), probes, layer ③ stress + placebo (TikZ + code), flow-variant split |
| `sections/03_methods.tex` | method matrix, strategy ladder L1–L4 with the L4 pipeline (TikZ), one 4B model three uses |
| `sections/04_results.tex` | layer ① P/R/F1, latency Pareto, robustness (key slide), LoRA shortcut, L4 + `leak.dl` |
| `sections/05_demo_plan.tex` | live demo (stage unit + dry-run table), limitations, take-aways/next steps, Thank you |
| `sections/99_appendix.tex` | backup: full P/R/F1 and robustness, flow-category heatmap, mechanisms, repeats + merged/unmerged, CodeQL batching, cost, latency table, label checks, dynamic reference, demo replay, SecVulEval, result files |
| `figures/make_figures.py` | figure + number pipeline (read-only on `juliet_full/` and `presentation/demo/`) |
| `figures/methods.json` | method registry: label, family, ranked, per-layer result-file globs, subset, repeats |
| `figures/latency_c1.csv` | concurrency-1 latency per method with its source (the Pareto x axis) |
| `figures/*.pdf` | generated: `probes`, `prf1` (main, no L2/Valgrind), `prf1_full`, `pareto`, `robustness` (main), `robustness_full`, `lora`, `heatmap`, `mechanism` |
| `figures/numbers.tex` | generated `\res{<key>-<layer>}{p\|r\|f1\|macro\|spec\|ci\|n\|tp\|fp\|tn\|fn\|base\|d\|lost\|gained\|flips\|r_<mech>}` and `\res{x}{…}` extras; "pending" when no run |
| `figures/{original,demo,repeat,cost,latency}.tex` | generated tables (hook, demo dry run, repeat agreement, API ledger, latency) |
| `figures/provenance.tex` | generated backup frames: run file + sha256 prefix for every scored method × layer, then the pending list |
| `figures/results_summary.json` | generated, machine-readable scores (incl. paired deltas) |
| `fontconfig/fonts.conf` | local fontconfig (see Fonts) |
| `tools/contact_sheet.py` | page-preview tiler |
| `notes.md` | speaker script (17:00) and Q&A prep |
| `.gitignore` | ignores `build/` |

The deck has 41 pages: title, 5 section dividers, 18 numbered content frames, Thank you, and 16 backup frames
(4 of them are the generated result-file list; the count grows if more files land).

## How the numbers are made

- `make_figures.py` reads `figures/methods.json`. Each method has `runs: {layer: [globs]}` relative to
  `juliet_full/`; layers are `layer1`, `layer3` (dynamic: dir `stress`), `placebo`, `original`.
  Files whose names start with `dev_`, `rep_`, `det50_`, `lat300`, `latency`, `unmerged_`, … are excluded
  (`exclude_prefixes`). A file qualifies if it covers ≥ 99.5 % of the eval set (a run still being written stays pending) (or of the method's `subset`);
  the earliest glob wins, then the newest file.
- Picks follow `juliet_full/static/results/scores/SUMMARY.md`: Clang SA `full_v2`, CodeQL `full_batch50_merged`,
  Infer `full_per_file_merged`. LoRA = `decision_ft/results/decision_ft/<layer>/L{1,3}_cv_v1.jsonl` (merged
  adapters, three held-out folds combined). Read-out ablation = `decision_ft/results/qwen_readout_zeroshot/`
  (`pred_at_dev_threshold`).
- Scoring imports `juliet_full/analysis/score.py` (`--set eval` semantics): eval set 2,656 units, missing or
  invalid predictions count as wrong, family-bootstrap 95 % CI with 2,000 resamples.
- DeepSeek layer ③ / placebo / original use the nested25 subset (`data/build/subsets.json`, 664 eval units);
  every layer-③ and placebo delta is PAIRED: layer 1 is re-scored on exactly the units of the other layer.
- Latency (Pareto x) comes only from `figures/latency_c1.csv` (concurrency-1 numbers from the lane reports and
  STATUS), never from `latency_s` in bulk files.
- A method × layer without a qualifying file is drawn grey "pending" and prints "pending" in the text; it never
  gets a number. Figures carry no PRELIMINARY stamp any more.

### Refreshing when the late results land (parent)

```bash
cd presentation/pre && make && make check && make pngs
```

- `make` re-scores everything (≈ 10 s), so new Qwen3.5-4B / Intern-Decision files in
  `llm/results/qwen3_5_4b/<layer>/` and `gpu/results/intern_decision/<layer>/` (names `l3_*`, `pl_*`, `orig_*`,
  any name not starting with an excluded prefix) are picked up without edits.
- Then read slides 11–15: numbers update through `\res`, but sentences such as "False alarms: Qwen, Intern-D"
  name methods, so check that the wording still matches the figure.
- If a lane writes to a new path, edit only that method's `runs` globs in `figures/methods.json`.

## Pending (as of the last `make`, 2026-11-23 ~15:45 PST)

See the last result-file backup frame or `figures/results_summary.json` → `pending_by_figure`. At the last build:
- Qwen3.5-4B: L1 placebo, L1 original, L3 placebo (layer ③ L1–L4 are in).
- Intern-Decision-4B: L3 layer ③, L1 placebo, L1 original.
- Qwen repeat runs (`rep_*`) for the repeat-agreement table.
