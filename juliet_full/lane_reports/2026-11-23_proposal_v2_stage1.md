I wrote the revised proposal in `proposal/v2/`. `make && make check` prints `clean` and `Pages: 6`, with no undefined citations or references and no overfull boxes. The body runs from page 1 to the middle of page 5 (about 4.5 pages), and the references fill the rest of page 5 and page 6.

## Files written (all in `proposal/v2/`)
- **`proposal_v2.tex`**:
  - Preamble and author block copied from `proposal/proposal_en.tex`, plus the notation macros from `report/final_en/main.tex`.
  - I added `multirow` and `tikz` for the method table and the figure. Only `pdftitle` changed, to match the new title.
  - The title is the one you specified, with "Revised Project Proposal" as the subtitle line.
- **`Makefile`**: modelled on `report/final_en/Makefile`. `make` builds into `build/` and copies the PDF to `proposal_v2.pdf`; `make check` and `make clean` work the same way.
- **`fontconfig/fonts.conf`**: copied unchanged.
- **`.gitignore`**: `build/`.
- **`references.bib`**: rewritten to contain only the 32 verified entries that are cited.
- **`references_seed_unverified.bib`**: the original 58-entry seed, kept untouched and not used by the build.
- **`proposal_v2.pdf`**: the built output.

## Sections
1. **Introduction:** memory leaks, then LLMs and decision models as new detector families, compared against classic program analysis.
2. **Revision note:** what the original plan was, the three reasons for the pivot (each with its source), what we keep (items i–vi), and that the SecVulEval pilot moves to a paper appendix.
3. **Research questions:** RQ1–RQ4, with L1–L4 on two LLMs as the primary axis and detector families as the secondary axis.
4. **Dataset:** source and counts, the pilot audit of shortcuts, how \Deb is built and its labels verified, the \Dead / \Plac layers, the frozen split with Table I, and the TikZ pipeline figure at `\columnwidth`.
5. **Approaches:** L1–L4, the two LLMs, the three decision models, the static and learned baselines, and the dynamic tools as an unranked reference. Table II is the methods × strategies matrix.
6. **Evaluation plan:** the shared runner with strict scoring, accuracy with family-clustered bootstrap CIs and McNemar + Holm on the five pre-registered tests, latency and cost, Pareto plots with deployment bands, placebo-adjusted robustness, breakdowns and repeats, and error analysis.
7. **Feasibility:** infrastructure plus four headline numbers marked preliminary (below).
8. **Timeline and deliverables:** presentation, final paper, artifacts.
9. **Risks:** seven items with mitigations.

## Citations (32), all checked online on 2026-11-24
- **Crossref (by DOI):**
  - Germano et al. ICAART 2025, 10.5220/0013156800003890
  - Black, NIST TN 1995
  - Boland & Black 2012
  - Risse et al. 2025, 10.1145/3728887
  - LineVul
  - Valgrind
  - Soufflé, 10.1007/978-3-319-41540-6_23
  - Infer, 10.1007/978-3-319-17524-9_1
  - Pulse, 10.1145/3527325
  - LLM4SA (Wen et al., TKDD), 10.1145/3653718
  - vLLM
  - McNemar
  - Efron
- **arXiv API:**
  - NESA 2412.14399
  - LLMDFA 2402.10754; its NeurIPS 2024 listing also confirmed on papers.nips.cc
  - Intern-Decision 2610.22131
  - Cyber-JEV 2611.02957
  - LoRA 2106.09685
  - LeakGuard 2504.04422
- **Other checks:**
  - Holm 1979: zbMATH (Scand. J. Stat. 6, 65–70) and the Wikipedia record (JSTOR 4615733).
  - The SecVulEval DOI comes from the earlier check recorded in `research/related_work.md`; I did not re-verify it this session.
- **Official pages (HTTP 200, expected title):**
  - SARD test suite 112
  - CWE-401
  - Risse & Böhme on usenix.org
  - ASan on usenix.org
  - Clang SA
  - LeakSanitizer
  - CodeQL docs
  - Cppcheck
  - TypeSafe Jev blog post (Sep 15, 2026) and docs
  - DeepSeek pricing page (`deepseek-flash` → DeepSeek-V4.1-Flash-1017)
  - Qwen3.5-4B model card (I used its official citation)
- **Fixes against the seed:** dropped the stale Cppcheck version note, dropped the broken `chakraborty2021reveal` entry, and removed LNCS volume numbers that Crossref does not confirm.

## Typed numbers
All 61 have a `% src:` comment beside them. The main sources are:
- `juliet/full_split_v1.json`: counts, split, seed, folds; SHA-256 prefix from `sha256sum`.
- `juliet_full/data/README.md` and `juliet_full/data/build/{probes,probes_layer3,verify,verify_layer3}_report.md`.
- `research/cwe401_scope.md:3` (4 CWE-401 functions) and `research/evaluation_protocol.md:30` (0/20 clang pilot).
- PLAN.md §§2.7, 3, 4.2 and 5.
- `research/decision_models_2026.md:8` (Jev price).
- `presentation/pre/figures/numbers.tex`, STATUS.md lines 33/45/48, `lane_reports/2026-11-23_static_stage2.md:21` and `lane_reports/2026-11-23_llm_stage2d.md:36`.

The four preliminary numbers:
- **Clang SA:** macro-F1 .855 on both \Deb and \Dead with no verdict changes; .822 on \Orig.
- **DeepSeek L1:** .995 on \Deb. On the nested \Dead subset (664 units) it falls from .998 to .881 (Δ −.118); on \Plac it changes by only −.003.
- **Our LoRA model:** .984 on \Deb but .372 on \Dead.
- **Median latency at concurrency 1:** about 18 ms for Clang SA, 0.105 s for the LoRA model, 0.715 s for DeepSeek L1.

## Changes from the brief and open issues
- **Grep figure .935:** this is measured on the eval split (2,656 units), not the full set as the brief says. PLAN.md gives .940 for the raw full set. The text says "evaluation units".
- **No `\balance` at the end:** it caused an overfull vbox because the references span two pages. I replaced it with `\IEEEtriggeratref{28}`, which balances the last page.
- **Two corrections after checking the actual prompts:**
  - The L1–L3 answer is a JSON object with `vulnerable`/`not_vulnerable` plus a confidence, not a leak flag.
  - L4 outputs fact lines in a strict grammar, not JSON. So the risk item says unparseable facts count as failures, instead of claiming constrained JSON decoding.
- **LoRA venue:** "ICLR 2022" could not be confirmed on OpenReview (browser check blocked); the arXiv entry is verified.
- **Preliminary numbers may move:** they come from `numbers.tex`, which the paper lanes may still regenerate.
- **Remaining warnings:** 13 underfull-box warnings (badness only) remain, mostly from long monospace tokens; `make check` does not flag them.
- No git operations, API calls or GPU calls; nothing outside `proposal/v2/` was modified.