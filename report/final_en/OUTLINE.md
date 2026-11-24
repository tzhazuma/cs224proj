# Final paper — contract (owner: parent / orchestrator)

User request (2026-11-23 17:40): "请同时编写新版本的proposal, final project paper，使用ieee conference模板".
Earlier fixed decisions:
- English.
- IEEE conference template (`\documentclass[conference]{IEEEtran}`, XeLaTeX); preamble and authors copied from `proposal/proposal_en.tex`.
- No division-of-labour section.
- Existing `proposal/*` and `report/*` files are never modified.

Course requirement (CS224 guide):
- Paper ≥ 10 pages, IEEE format.
- Must cover: task definition, data, the 2–3+ LLM approaches, the shared runner, metrics (P/R/F1, time, cost, variation), results broken down by program type, and error cases.

## 1. Files and ownership (one writer per file)

| file(s) | owner |
|---|---|
| `main.tex`, `Makefile`, `fontconfig/`, `OUTLINE.md`, `.gitignore` | parent (lanes: request changes in report) |
| `sections/00_abstract.tex` `01_introduction.tex` `02_background.tex` `03_benchmark.tex` `04_methods.tex` `07_threats.tex` `08_conclusion.tex` `09_appendix_front.tex` | **front lane** |
| `references.bib` | **front lane** (seed = 58 merged, UNVERIFIED entries from old bibs) |
| `figures_front/` (e.g. TikZ pipeline/overview figure), `tables/front_*.tex` | **front lane** |
| `sections/05_results.tex` `06_discussion.tex` `10_appendix_results.tex` | **results lane** |
| `figures/` (incl. `figures/make_figures.py`), `tables/res_*.tex`, `generated/` (incl. `generated/numbers.tex`) | **results lane** |
| `references_results.bib` | **results lane** (only keys NOT in references.bib) |

- **Builds:** each lane builds into its own dir:
  - front: `make pdf OUTDIR=build_front && make check OUTDIR=build_front`
  - results: `OUTDIR=build_results`
  - `make` with no args (→ `main.pdf`) is the parent's build.
- **Git:** never commit, stage, or touch git state.
- **Off limits:** no API or GPU calls; nothing outside `report/final_en/` is written.

## 2. Storyline, research questions, page budget (body through Conclusion ≥ 10 pages; refs + appendix after)

Title (fixed in main.tex): *Do Memory-Leak Detectors Read Code or Templates? Rebuilding Juliet CWE-401 to Compare Static Analyzers, LLMs, and Decision Models.*

Research questions:
- **RQ1 benchmark validity:** Can trivial shortcuts solve original Juliet CWE-401, and does our debiasing remove them?
- **RQ2 approaches:** How do prompting strategies L1–L4 (DeepSeek-V4.1-Flash, Qwen3.5-4B), decision models (Jev, Intern-Decision-4B, our LoRA decision model) and static analyzers compare on \Deb?
- **RQ3 efficiency:** What accuracy–latency–cost trade-offs suit IDE / pre-commit / CI deployment?
- **RQ4 robustness:** Do detectors reason about path feasibility when never-executed frees are added (\Dead, controlled by \Plac)? Does fine-tuning amplify shortcuts?

Contributions:
1. A shortcut audit of Juliet CWE-401: `static void` ⇒ good gives 1.000; the "no free/delete ⇒ leak" grep rule gives .935.
2. A debiased CWE-401 benchmark (3,316 units, label-verified) plus a dead-free stress layer and a placebo control.
3. A unified comparison across 20+ detector configurations on accuracy, latency and cost.
4. Findings:
   - path-sensitive analyzers are fully robust;
   - LLMs and decision models fail in two opposite ways;
   - fine-tuning learns the shortcut;
   - L4 (LLM facts + Datalog) is the most robust prompting strategy.

| § | file | owner | pages |
|---|---|---|---|
| Abstract | 00 | front | – |
| I Introduction | 01 | front | 1.0 |
| II Background & Related Work | 02 | front | 1.0 |
| III Benchmark Construction | 03 | front | 1.75 |
| IV Approaches & Experimental Setup | 04 | front | 1.75 |
| V Results (RQ1–RQ4) | 05 | results | 2.75 |
| VI Error Analysis & Discussion | 06 | results | 1.0 |
| VII Threats to Validity | 07 | front | 0.5 |
| VIII Conclusion | 08 | front | 0.25 |
| Appendix A–: SecVulEval pilot, prompts, Datalog rules, split lists | 09 | front | free |
| Appendix: full result tables, per-fold, unmerged, repeats | 10 | results | free |

The front-lane abstract and introduction quote headline numbers through `\res{...}` macros where possible.

## 3. Notation and naming (defined in main.tex — use, do not redefine)

**Layers.** Slides used circled numbers; the paper uses names.

| macro | layer | slides name | result-file layer |
|---|---|---|---|
| `\Orig` | original Juliet units | — | original |
| `\Deb` | main benchmark | layer ① | layer1 |
| `\Dead` | stress test: never-executed frees | layer ③ | layer3 (`stress` dir in data/results) |
| `\Plac` | control: never-executed non-free statement | — | placebo |

**Strategies.**
- **L1 Direct:** code → label.
- **L2 Few-shot:** 4 fixed dev examples.
- **L3 Analysis-guided:** + Clang SA warnings.
- **L4 Neuro-symbolic:** LLM extracts facts, then Soufflé Datalog decides.

**Method names.**
- **LLMs:** DeepSeek-V4.1-Flash (API name `deepseek-flash`); Qwen3.5-4B (zero-shot, vLLM).
- **Decision models:** Jev (`jev-latest` = jev-1.14.0, TypeSafe System One API); Intern-Decision-4B; "our LoRA decision model" (Qwen3.5-4B + LoRA r16, binary read-out head, 3-fold CV, merged weights).
- **Static analyzers:** Clang Static Analyzer 23.1.6 (Clang SA); Infer 1.3.0 (Pulse); CodeQL 2.27.5; Cppcheck 2.22.0.
- **Baselines:** LineVul (public Big-Vul checkpoint, zero-shot); the grep rule.
- **Dynamic, reference only (never ranked):**
  - ASan/LSan (GCC 13.3, `use_stacks=0`);
  - Valgrind 3.28.0;
  - dynamic-enhanced: realloc-failure injection + global still-reachable + variant-12 repetition.

**Units.**
- Metrics are reported to three decimals, matching the macros.
- Macro-F1 is the primary metric; also report leak-class P/R/F1.
- CIs: 95% family-cluster bootstrap, ≥2,000 resamples, as computed by `juliet_full/analysis/score.py`.
- Latency: median seconds per unit at concurrency 1.

## 4. Number provenance rule (hard)

Every number must come from one of:
- `generated/numbers.tex` macros;
- a generated table;
- a file you cite in a `% src: <path>` comment next to the typed number.

Additional rules:
- Never type a number from memory or from slides prose.
- `generated/numbers.tex` is currently a copy of `presentation/pre/figures/numbers.tex` (keys `\res{<key>-<layer>}{<metric>}`, see the header of that file). The results lane regenerates it with the same key scheme plus additions; keep existing keys stable.
- Score any file with `python3 juliet_full/analysis/score.py --pred <file> --set eval --json` from the repo root.

## 5. Source material (read before writing)

Plans and contracts:
- `PLAN.md` (design and all 【已定】 decisions);
- `juliet_full/STATUS.md` (decision log, artifacts, results, budget);
- `juliet_full/README.md` (schemas).

Lane reports in `juliet_full/lane_reports/`:
- data: stage1 / stage3 / stage4;
- static: stage1 / stage2;
- llm: stage1 / 2a / 2b / 2c / 2d;
- gpu: stage1 / stage2;
- decision_ft: stage1 / stage2;
- demo: stage1 / stage2;
- slides: stage1 / stage2.

Per-lane READMEs and summaries:
- `juliet_full/data/README.md`, `juliet_full/data/build/verify_report.md`, `juliet_full/data/build/probes.*`;
- `juliet_full/static/results/scores/{SUMMARY,ROBUSTNESS}.md`;
- `juliet_full/llm/README.md`, `juliet_full/llm/prompts/`, `juliet_full/llm/l4/leak.dl`, `juliet_full/llm/results/SUMMARY.md`;
- `juliet_full/gpu/README.md`, `juliet_full/gpu/results/STAGE2_SCORES.md`;
- `juliet_full/decision_ft/README.md`;
- `juliet_full/data/results/dynamic_report.md`.

Research notes:
- `research/juliet_dataset_adjustment.md`;
- `research/decision_models_2026.md`;
- `research/latest_memory_tools_2026.md`;
- `research/related_work.md`;
- `research/cwe401_scope.md`.

Storyline and figures (slides):
- `presentation/pre/notes.md` and `presentation/pre/sections/*.tex`;
- `presentation/pre/figures/make_figures.py` + `methods.json` — the result-file registry; reuse it.

Older work for the appendix: the SecVulEval pilot in `report/report_latest_zh.tex`, `report/latest_results_summary.md`, `benchmark/results/LEADERBOARD.md`.

## 6. Bibliography rule

- Cite only what you verified online: title, authors, venue, year, and a DOI/arXiv id or official URL.
- Seed entries are unverified, so check each before citing.
- No invented references. If you cannot verify a reference, drop the claim or cite the tool's official documentation.
- Likely needed (verify):
  - Juliet/SARD; Germano et al. ICAART 2025 (Juliet biases); Risse & Böhme USENIX Sec 2024; Risse et al. ISSTA 2025;
  - Clang SA; Infer/Pulse; CodeQL; Cppcheck; ASan/LSan; Valgrind; Soufflé;
  - LLMSA/NESA (arXiv 2412.14399); LLMDFA; LLM4SA; KNighter; IRIS; LAMeD; MemHint; LeakGuard;
  - LineVul; CodeBERT; VulnLLM-R; Intern-Decision (arXiv 2610.22131); Cyber-JEV (arXiv 2611.02957); "Look Here, Then Decide" (arXiv 2611.16565); AnyJev (arXiv 2610.00831); Jev docs (docs.typesafe.ai);
  - LoRA (Hu et al. ICLR 2022); vLLM (Kwon et al. SOSP 2023); Qwen3.5 model card; DeepSeek API docs; bootstrap (Efron); McNemar; Holm.

## 7. Style

- IEEE two-column. Figures sized to `\columnwidth` (use `figure*` only if essential).
- Vector PDF figures, ~8 pt fonts (TeX Gyre Termes / Times-like), colour-blind safe.
- Label prefixes: `sec:`, `fig:`, `tab:`, `eq:`.
- Agreed labels:
  - results lane: `fig:pareto`, `fig:robust`, `tab:main`, `tab:robust`, `tab:latency`, `tab:lora`, `tab:flow`, `tab:repeat`, `tab:probes` (→ `tables/res_probes.tex`, which the front lane `\input`s in §III), `tab:orig` (→ `tables/res_orig.tex`, used in §I or §III);
  - front lane: `fig:overview`, `tab:dataset`, `tab:split`, `tab:methods`, `sec:benchmark`, `sec:methods`, `sec:results`, `sec:discussion`, `sec:threats`.
- Tone: precise, no hype. Keep the honest limitations:
  - synthetic benchmark;
  - the leak definition includes globals at exit and realloc failure;
  - dev AUROC saturated → weak checkpoint selection;
  - DeepSeek covers \Dead/\Plac/\Orig only on nested25 (664 units) because of the ¥10 budget;
  - thresholds are descriptive;
  - Qwen repeat agreement is about .985;
  - CodeQL batching artifact.
