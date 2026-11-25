# REPORT v4: slides "Near-Cloud Quality on a Local Device?"

## v4.4 update (2026-11-24 ~20:15 PST, parent 19:45 / 19:50 / 20:08)

Build: `make && make check && make pngs` clean ("clean: no errors, overfull boxes or missing fonts";
"citations: ok (30 pages with sources, 85 footer entries, every entry has a superscript)"). main.pdf **61 pages**
(24 numbered main frames unchanged; backup +3: two-track tables, all-labels Pareto, Jev L4-D).

Changed frames
- Main 5 "Original Juliet CWE-401: synthetic, templated, gameable": one frame, lighter. Full-width three-line
  listing (`lstdefinestyle{unitbig}`, \small) with aligned comments (leak / no heap / freed); three bullets (1,658
  cases; 42 families × 48 variants; 1 bad + 1 good = 3,316 units); table with the two one-line cues (.935, 1.000) and a
  grey Clang SA reference row (.822); one closing line. Dropped vs v4.3: the "why" column of the cue table and the
  goodB2G body lines. No split, timing unchanged (0:40).
- Main 18 is now a FIGURE `figures/df_tracks.pdf` ("Facts lift every local decision model; the 4B generator cannot
  write them"): two panels (generative L1–L4 | decision L1, L2, L3, L4-D), same y-range, one line per model, cloud
  dashed + hollow, local solid, ours = green star + thick line, missing L2 joined by a thin dotted segment, best
  point per model annotated, shared legend below. Two take-away lines + one caption line. The generated tables moved
  to backup "Backup: two tracks × four strategies, all numbers".
- Main 20 Pareto: title "Clang SA dominates every local LM; FT L4-D is the most accurate of them". Front now over
  model-based AND static methods (dynamic stays a reference line):
  **grep (.333, 1 µs) → Cppcheck (.492, 9 ms) → Clang SA (.855, 18 ms) → DeepSeek L3 (.875, 810 ms) → Jev L1 (.946,
  912 ms) → Jev L3 (.949, 923 ms)**; no local LM is on the front. Plot sized for slide scale ≈1 (fonts ≈9 pt), legend
  outside right, budget shading dropped (dotted lines + small labels), labels only for front, ours, static tools and
  each model's best strategy, hand-placed (`PARETO_LABEL_AT`) without overlaps; one-line caption, long text in
  notes §20. Backup "DeadFree Pareto, every point labelled" (`figures/df_pareto_full.pdf`).
- Main 21: bullet "Same facts, cloud decision model: Jev L4-D .907 (+0.081 vs FT L4-D); Jev L3 .949"; CI header
  cites the bootstrap.
- Backup "Jev L4-D, the cloud decision model on the same facts" (new): τ 0.5 pre-specified (.907 [.875, .935], P
  .847, R .995, gap 113 %) and **dev-chosen τ 0.27** (.944, backup only); paired vs DeepSeek L4 +.007 [−.028, +.039]
  n.s., vs Jev L3 −.042, vs FT L4-D +.081; exec_all accuracy .975 vs .831 (FT); realloc_safe FPs; latency 967 ms
  with concurrent questions. Hand-typed fact accuracies carry `% src: REPORT_jev_l4d.md`.
- Backup two-track caption no longer says "Jev L4-D = cloud ceiling" (it is not: Jev L3 is higher).
- Citations everywhere: `\sref{key}` superscript at the first mention, per-frame numbered footer (6.5 pt, at most two
  lines, `\smash`ed above the page number). `tools/check_citations.py` (run by `make check`) reads
  `build/main.sref` (B = superscript, F = footer entry, H = footer height, per page) and fails if the sets differ,
  a number maps to two keys, numbers are not 1..k in first-mention order, a footer is taller than two lines
  (19 pt), or a section still uses `\slidecite`. Removed citations: CS224 lectures (lecture names stay as plain
  text on the course-ideas slide), DeepSeek (deepseekdocs, deepseek2026v4), Jev (typesafe2026jev). Short forms in
  `sources.tex` shortened (the tool name is at the mention).
- Frame-level sources dropped because the name appears only inside a generated table/macro (no place for a
  superscript): Clang SA on main 22 (demo) and backup demo; Qwen/Intern/LoRA on backup "strategy × local model";
  Qwen/Intern/Clang SA on backup "by flow category"; Soufflé on backup "L4 v3 rules"; vLLM on backup method matrix and
  Debiased latency. Each is still cited on other frames. Main 20 Pareto has no citations (short caption).

Data (Jev L4-D landed, JEV_L4D_READY 20:01): jev_l4d .907 [.875, .935], latency .967 s (questions of a unit sent
concurrently; local L4-D is sequential); jev_l4d_devtau .944 (secondary). Nothing pending in main.pdf.

## v4.3 update (2026-11-24 ~19:30 PST, user review fixes 1–10)
- Build: `make && make check && make pngs` clean; main.pdf 58 pages (24 numbered main frames + backup); no undefined
  `\res`, no "??" citation key in the PDF text.
- Fixes 1–8 (frames by footer number): new slide 5 "Original Juliet CWE-401: synthetic, templated, gameable" (listing,
  cue table grep / static void, Clang SA reference; counts from `\res{x}{juliet_*}`); slide 8 split + plain macro-F1
  and family bootstrap CI (`\res{x}{boot_*}`), τ no longer defined there; slide 9 prompt input / output per model kind
  (τ: dev for our models, 0.5 for Jev and Intern-Decision); slide 10 "Datalog engine (Soufflé, leak.dl)" + site
  footnote; slide 13 kept/dropped table, "arrow = the rule reads this fact", demo counts 2 of 5 / 4 of 8
  (`\res{x}{demo_l4d_*}`); slide 14 retitled "Which wrong facts cost the most? Fix one fact type at a time"; slide 17
  defines Qwen read-out (table row + footnote).
- Fix 9, two tracks (DeadFree full eval only, all via macros): slide 18 "Two tracks × four strategies (DeadFree)",
  generated tables `figures/df_track_generative.tex` (Qwen3.5-4B, DeepSeek; L1–L4) and `figures/df_track_decision.tex`
  (Qwen read-out, Intern-Decision, ours (LoRA), Jev; L1, L2, L3, L4-D) from `methods.json deadfree.tracks`; bold = best
  cell per row (computed); read-out L1/L3 (.351/.334) moved into the main table; "–†" for no L2 (FT saw ≈1,800
  labelled units; L2 prompt 2.4× longer; src PLAN.md). Slide 19 "FT: unit labels stay below the baselines, fact labels
  beat them": same-weights bars read-out → LoRA per strategy with Intern (dashed) and Qwen gen. (dotted) reference
  lines, Debiased .984 → DeadFree .372, paired Δ FT L4-D − Intern L4-D +.027 [+.003, +.054]. The earlier title "only
  fact labels transfer" was dropped because FT L3 is +.304 over its read-out. Slide 20 Pareto: shape = track (circle
  generative, diamond decision), colour = cloud/local, star = ours, static grey, dynamic dashed reference; legend
  9.5 pt. Slides 17, 21, 23 made consistent (Jev role "L1–L3, L4-D"; "decision-track cloud ceiling: Jev L3, Jev L4-D";
  take-away 3 with Debiased → DeadFree FT L1).
- Jev L4-D: `deadfree.expected: ["jev_l4d"]`. Until `juliet_full/analysis/deadfree/JEV_L4D_READY` and the rows exist,
  the slide 18 cell and slide 21 value print grey "pending" and the Pareto shows "pending: Jev L4-D"; a plain `make`
  fills them (and the bold cell of the Jev row is recomputed). Wording is neutral ("cloud ceiling of the decision
  track"). `jev_l4d_devtau` is excluded from the Pareto (backup only). Paired deltas with jev_l4d appear as
  `\res{df-x}{pd_jev_l4d__<b>}` once the JSON has them; they are not yet referenced on a slide.
- Fix 10, per-slide sources: `\slidecite{...}` (main.tex) prints a 5.5 pt grey line in the frame footer, left of the
  page number; short forms in `sources.tex` keyed by `report/final_en/references.bib` keys. Keys used: sardjuliet13,
  black2018juliet13, mitrecwe401, germano2025biased, risse2024limits, risse2025topscore, clangsa, inferpulse,
  codeqldocs, cppcheck, serebryany2012asan, lsan, nethercote2007valgrind, jordan2016souffle, deepseekdocs,
  deepseek2026v4, typesafe2026jev, qwen35card, zhu2026interndecision, nie2025vulnllmr, fu2022linevul, hu2022lora,
  zhang2026anyjev, zhao2026cyberjev, kwon2023vllm, wang2026nesa, wang2024llmdfa, efron1979, mcnemar1947, holm1979.
  Without a bib entry: gcov (gcc.gnu.org/onlinedocs/gcc/Gcov.html), tree-sitter (tree-sitter.github.io). Lectures:
  CS224 Lecture 1 (Introduction), 3–4 (Data Flow Analysis), 10 (Pointer Analysis), 17 (Datalog-Based Program
  Analysis), 18 (Soundiness).
- notes.md: timing table rebuilt for 25 rows (still 17:00), new section 5, sections 8–10, 13, 14, 17–21 rewritten for
  the two tracks; Q&A unchanged.

## v4.2 final pass (2026-11-24 ~10:30 PST, latency csv final, commit aa001d0 of the latency lane)
- Rebuilt from the final `latency_deadfree.csv` (primary rows). `make && make check && make pngs`: clean, 57 pages; no
  undefined `\res`; no "pending" in any figure or slide text (only the provenance page explains the mechanism).
- Numbers per slide (DeadFree, concurrency-1 median): slide 1 DeepSeek L1 895 ms, Jev L1 912 ms, Qwen L1 347 ms,
  Intern L1 135 ms, FT L4-D (opt.) 472 ms; slide 17 latency panel Qwen 347/382/360 ms/1.18 s, Intern 135/267/167/658 ms,
  LoRA L1 120 ms, L3 143 ms, L4-D 472 ms; slide 19 adds DeepSeek 0.81–1.01 s, Jev 0.91–0.96 s, VulnLLM-R 8.05 s,
  Clang SA 18 ms, Cppcheck 9 ms, Infer 256 ms, CodeQL 7.41 s, grep 1 µs (drawn off-scale at the left edge, labelled so),
  ASan/LSan 135 ms and Dynamic-enhanced 1.17 s (markers on their reference lines); slide 20 FT L4-D 472 ms, Intern L4-D
  658 ms, DeepSeek L1 895 ms, 1.9× (DeadFree values); slide 23 Clang SA 0.855 at 18 ms.
- Claims checked against the points: FT L4-D (.826, 472 ms) dominates untuned Intern L4-D (.799, 658 ms) and is the
  most accurate local model; the model-based front is FT L1 → Intern L1 → FT L3 → Intern L3 → Qwen L3 → FT L4-D →
  DeepSeek L3 → Jev L1 → Jev L3. Clang SA (.855, 18 ms) is above and left of every local model (limitations slide).
- Qwen read-out L4-D has no latency row: new `methods.json` key `deadfree.latency_not_measured: ["readout_l4d"]`;
  it is excluded from the Pareto plot, the slide 17 panel shows "not measured", the backup table "n/m".
- Pareto labels: `label_points(..., obstacles)` now avoids unlabelled markers (cloud points, the star), which fixes the
  FT L4-D / Infer overlap.
- Slide 18: "Fact FT vs Intern L4-D" → "FT vs Intern L4-D" (line no longer wraps).
- The only remaining "×faster" outside slide 20 is the Debiased backup (LoRA L1 0.105 s vs DeepSeek 0.715 s, ≈7×),
  explicitly labelled Debiased.
- notes.md: all latency numbers updated to the final values (slides 1, 17, 19, 20, 23).
- Open: the demo slide still cites `demo/recordings/stage_final.json`; the parent rebuilds it after `stage_final_v2.json`.

## v4.1 update (2026-11-24 ~09:45 PST, English fixes only; the Chinese version was cancelled by the user)
- Intern-Decision L4-D is final (`intern_l4d`, τ 0.5): .799 [.770, .823], gap closed 81 % vs DeepSeek L1. Its dev-τ
  variant (`intern_l4d_devtau`, τ 0.18) .373, recall .037 appears in backup only. A new backup frame, "Intern-Decision
  L4-D and its threshold", discloses that τ 0.5 was chosen after seeing eval (it favours the baseline) and explains
  the dev-τ failure (from `deadfree_quality.json` notes).
- Paired deltas come from `deadfree_quality.json` `paired_deltas` via `\res{df-x}{pd_<a>__<b>}` (+`_ci`):
  FT L4-D − Intern L4-D +.027 [+.003, +.054]; Intern L4-D − Qwen read-out L4-D +.047 [+.029, +.064].
- Main message is now "the strategy does most of the work". Reworded claims:
  - slide 2 "best untuned local" → "best untuned local prompt (L1–L4): Qwen L3" (because untuned Intern L4-D .799 is higher);
  - slide 17 title "For local models, fact questions beat every prompt strategy" → "The strategy does most of the
    work: L4-D lifts an untuned decision model". The old title was false for untuned Qwen (read-out L4-D .752 < Qwen L3 .760);
  - slide 18: Intern L4-D bar added; "FT vs best untuned" on L4-D is +.027 (vs Intern L4-D), no longer +.074; paired CI on the slide;
  - slide 19 title "best local point" → "most accurate local model" (untuned Qwen L1–L3 are faster);
  - slide 20 title → "L4-D closes 81 % of the gap untuned, 89 % fine-tuned; not near-cloud" (both percentages via `\res`).
    Its table now has an Intern L4-D row, and the latency/speed-up lines are bullets;
  - take-aways title → "the strategy does most of the work", with new points "Facts + Datalog do most of the work" and
    "Fact labels add a little (+.027)";
  - limitations: the "Pending" item is replaced by the Intern L4-D τ disclosure;
  - standout: "Program-analysis facts do most of the work; fine-tune on facts, not on verdicts."
- Latency: `load_deadfree` now reads only `role == primary` rows of `latency_deadfree.csv` (the prediction configuration,
  i.e. the fallback kernel). The Debiased backup line adds L4-D (opt.) 0.214 s (`% src: juliet_full/l4d_ft/REPORT_stage1.md:137`).
- Pareto: one label per cloud service ("DeepSeek L1–L4", "Jev L1–L3"); "all questions" point for unpruned L4-D; the
  grey "latency pending" strip disappears automatically when nothing is pending.
- Backup by-flow table: Intern L4-D row added. Deck now 57 pages (title, 4 dividers, 23 numbered main frames, standout, 28 backup pages); the frame list below shows v4 titles, the reworded ones are listed above.
- notes.md is updated for all of the above (+ Q&A "Was the Intern L4-D threshold chosen fairly?" and "If the strategy does
  most of the work, why fine-tune at all?").
- Pending at 09:45: DeadFree latency for Intern L1–L3, Intern L4-D, Qwen read-out L4-D, CodeQL, Infer, grep, ASan/LSan,
  Dynamic-enhanced. `readout_l4d` has **no row at all** in `latency_deadfree.csv`, so it will stay pending unless the
  latency lane adds one.


Lane slides-v4, 2026-11-24 (build ~08:10 PST). Deck: `presentation/pre/main.pdf`, v4: 56 pages = title + 4 section
dividers + 23 numbered main frames + standout + 27 backup pages (incl. generated provenance pages); v4.1: 57. Beamer metropolis, 16:9,
English. Build: `make && make check && make pngs` → "clean: no errors, overfull boxes or missing fonts".

v3 sources (main.tex, sections/, make_figures.py, methods.json, latency_c1.csv, notes.md, main.pdf, REPORT_v3.md)
were copied to `presentation/pre/archive_v3/` before any edit. `presentation/pre_v1_backup_20261124/` and
`presentation/demo/` were not touched. No git, API or GPU calls.

## Narrative
Strategy × fine-tuning on DeadFree. Cloud = DeepSeek V4.1 Flash (generative API) and Jev (TypeSafe decision API);
local = one RTX 3090. Unit-label fine-tuning (L1/L3) learns "a free() means no leak" and is worse than untuned;
fact-label fine-tuning (L4-D) is the only fine-tuning that helps (.826), closes ≈89 % of the gap to DeepSeek L1,
but misses the pre-registered near-cloud criterion (−.037 vs ≥ −.02). From the dataset slide on, every model
comparison is DeadFree only.

## Frame list (main, numbered n/23)

| # | Section | Title | Content / source |
|---|---------|-------|------------------|
| – | – | Title | Near-Cloud Quality on a Local Device? / Program-Analysis-Guided Decision Models… |
| 1 | Intro | Leak checks must fit a developer's time budget | `df_intro_time.pdf` (DeadFree c1 latency, budget bands IDE/pre-commit/CI) |
| 2 | Intro | On DeadFree, cloud models are far ahead of local ones | `df_intro_quality.pdf` (DeepSeek, Jev, Qwen, Intern, VulnLLM-R; ranges over L1–L4) |
| 3 | Intro | Original Juliet can be gamed: a one-line rule beats Clang SA | `hook_original.pdf`; grep .935, static-void 1.000, Clang .822 |
| 4 | Intro | Question: near-cloud quality on a local device? | TikZ, 3 sub-questions |
| 5 | Methods | Debiased: good units now look like bad units | TikZ |
| 6 | Methods | DeadFree adds a free that never runs | code listing + Placebo control |
| 7 | Methods | We test on unseen flow variants | TikZ split (dev 9 variants, 3 folds 472/424/432 groups) |
| 8 | Methods | L1–L3: ask for the verdict, with more or less help | table; generative vs decision |
| 9 | Methods | L4 and L4-D: the model supplies facts, Datalog decides | TikZ pipeline + 5 question types |
| 10 | Methods | Three rules turn the answers into a verdict | Datalog listing (rules v1) |
| 11 | Methods | The design follows the course's program-analysis ideas | table with lecture citations (verified, see below) |
| 12 | Methods | Asking only what the rules read halves the questions | rule-dependency graph; 13 → 6 questions, 0 verdict differences; "Optimized inference, post-hoc (user-approved 2026-11-24)" |
| 13 | Methods | With correct facts the rules are near-perfect; exec_all is the bottleneck | `df_attribution.pdf`; oracle .991 (FP only), exec_all .826 → .957 |
| 14 | Methods | Fine-tuning: one recipe, different labels per strategy | LoRA r16 α32, 32.5 M (0.70 %), labels per strategy, ≈68 min/fold |
| 15 | Results | DeadFree removes the label shortcuts; one cue is left in G2B goods | probe table Orig/Debiased/DeadFree + Clang ref; G2B AUROC .986; "DeadFree only" |
| 16 | Results | Two cloud services, three local models, one fine-tuned model | model table |
| 17 | Results | For local models, fact questions beat every prompt strategy | `df_strategies.pdf` (quality + log latency) |
| 18 | Results | Fine-tuning on unit labels hurts; fine-tuning on facts helps | `df_before_after.pdf`; L1 .533/.584 → .372, L3 .760/.664 → .639, L4-D .752 → .826 |
| 19 | Results | FT L4-D is the best local point, still below the cloud | `df_pareto.pdf` (x c1 latency log, y DeadFree macro-F1, front, static grey, dynamic dashed) |
| 20 | Results | We close most of the gap, but not near-cloud by our own criterion | Δ/CI/gap vs DeepSeek L1 and L4; criterion not met; latency line |
| 21 | Results | Live: one dead free fools grep and the old LoRA, not L4-D | `strdup_char_01` DeadFree code, flipped/held lists, exec_all(free)=no |
| 22 | Discussion | Take-aways: what to fine-tune matters more than whether | 5 points |
| 23 | Discussion | Limitations | Clang SA as good and faster; synthetic; post-hoc pruning; τ/dev; one GPU; pending |
| – | – | Standout | "Close (89 % of the gap), not yet near-cloud" + Questions |

## Backup frames
Shortcut origin (code); task and data; Original vs Debiased all detectors (`original.tex`); Debiased near-cloud
(`nearllm.pdf`, LoRA L1 .984 vs DeepSeek .995, Δ −0.011 [−0.014, −0.008] typed with `% src:
near_llm_bootstrap.py`, Debiased latencies labelled "Debiased"); Placebo control table; paired tests Debiased
(McNemar/Holm, `% src: report/final_en/tables/res_mcnemar.tex`); fact attribution table; oracle; L4-D per fold;
DeadFree by flow category (`df_by_flow.tex`); strategy × local model table (`df_strategies.tex`); VulnLLM-R-7B;
prompts + 5 L4-D templates; L4-D rules v1 complete; v3 L4 `leak.dl`; method matrix; cost (+FT cost); Debiased
latency (v3, labelled); label re-check; dynamic reference; demo table (`demo.tex`); DeadFree result files;
provenance (generated, run file + sha256).

## Data sources
- DeadFree quality: `juliet_full/analysis/deadfree/deadfree_quality.json` (methods: tp/fp/tn/fn, P/R, macro-F1 +
  CI, Δ and gap closed vs DeepSeek L1/L4 + CIs, by_flow; `strategy_x_ft` table). → `\res{df-<key>}{…}`.
- DeadFree latency: `juliet_full/analysis/deadfree/latency_deadfree.csv` (median/p90, hardware). First row per
  `quality_key` is used; Intern "(fallback kernel)" rows are ignored. → `\res{df-<key>}{lat|p90}`, figure x-axes.
- Probes: `juliet_full/data/build/probes_layer3.json` (static_void, grep_v0, bow_lr macro-F1 and AUROC per subset).
- Pruning: `juliet_full/l4d_ft/results/scores/prune_test.json` (questions full vs pruned, verdict differences).
- Fact attribution / oracle: `juliet_full/analysis/l4d_peek/fact_error_attribution.out.txt`.
- L4-D per fold: `juliet_full/l4d_ft/results/scores/lora_l4d_opt_<layer>_eval_r1.json`.
- L4-D unit answers (demo row): `juliet_full/l4d_ft/results/lora_l4d_opt/<layer>/eval_r1_units.jsonl`.
- Debiased/Original/Placebo per-method scores: existing v3 machinery (`figures/methods.json` registry, scored with
  `juliet_full/analysis/score.py`), unchanged except the new `lora_l4d_opt` entry.
- Demo: `presentation/demo/recordings/stage_final_v2.json` if present, else `stage_final.json` (+ L4-D row from the
  frozen eval run, marked `*`), else `stage_dryrun.json`.
- Typed numbers with `% src:` comments: Debiased bootstrap (near_llm_bootstrap.py, seed 20261123), McNemar rows,
  fold sizes (`juliet_full/data/build/layer3.jsonl`), criterion (`PLAN.md:224-226`, not met `PLAN.md:34`), G2B cue
  (`juliet_full/lane_reports/2026-11-23_data_stage3.md:52`), FT cost (`juliet_full/l4d_ft/PROGRESS.md:8`), rules
  equivalence (`juliet_full/l4d/REPORT_stage1.md:99-100`), oracle FPs (`REPORT_stage1.md:91-97,102-110`), demo
  exec_all answer (`juliet_full/l4d_ft/results/lora_l4d/layer3/eval_r1.jsonl`, p_yes 1.8e-07).
- Lecture citations verified with pdftotext on `/home/barton/Documents/projects/cs224/slides/`: Lecture 10 Pointer
  Analysis (allocation-site abstraction; demand-driven), Lecture 3–4 Data Flow Analysis (may/must, reaching
  definitions vs available expressions), Lecture 17 Datalog-Based Program Analysis (EDB/IDB, negation), Lectures 1
  and 18 (sound/complete; soundiness). Magic sets are NOT covered by Lecture 17 and are not mentioned.

## Pending placeholders (fill in automatically on `make`)
As of 08:10 PST `latency_deadfree.csv` has only two measured rows: FT L4-D (opt.) 0.4447 s (p90 0.958 s) and
VulnLLM-R-7B 8.0465 s. Pending, drawn grey / printed *pending*:
- DeadFree latency of DeepSeek L1–L4, Jev L1–L3, Qwen L1–L4, Intern L1–L3, Intern L4-D, LoRA L1/L3, LoRA L4-D
  (unpruned), Clang SA, Cppcheck, Infer, grep, CodeQL, ASan/LSan, Dynamic-enhanced → slides 1, 17, 19 (figures),
  20 (speed-up vs DeepSeek L1, latency line), 23 (Clang SA latency), backup strategy table.
- Intern-Decision L4-D quality (`intern_l4d`, status pending) → slide 18 (bar + number line), slide 17, backup.
- Demo `stage_final_v2.json` (live L4-D row) → slide 21 footnote and backup demo table switch automatically.

## Open issues
- Near-cloud criterion is not met (−.037 vs DeepSeek L1); the deck says so on slides 20 and the standout.
- Intern-Decision quality on DeadFree is .584 in the data (task text said .583); the slides use the data.
- When latencies land, re-read slides 1, 17, 19, 20: sentences are generic, but the Pareto front and the "best
  local point" wording should be re-checked against the plotted positions.
- If Intern L4-D beats FT L4-D, the titles of slides 17–19 ("best local result") must be revised by hand.
- Pruning is post-hoc (user-approved 2026-11-24) and labelled as such; residual G2B cue (ALLOCA/new) stated.
- Main-frame count 23 (+ title, standout); within the ≤ ~25 budget; timing table in `notes.md` sums to 17:00.

## v4.5 update (2026-11-24, parent 21:20 + 21:30)

- Slide 18: back to grouped bars (figures/make_figures.py `plot_df_tracks`, `DF_STRATEGY_COLOR`): two panels with a shared
  0–1 y axis, groups = models, colour = strategy (L1→L3 light→dark blue, L4/L4-D orange), cloud hatched + "(cloud)",
  ours green/bold, missing L2 = "–†", 3-digit value on every bar (7.5 pt, rotated), one legend.
- Wording: "near-cloud" = only the pre-registered test (≥ DeepSeek L1 − 0.02); positive claim = "closes X of the gap"
  + speed-up. Slide 21 title "Not yet near-cloud: L4-D closes 66 % of the gap untuned, 89 % fine-tuned"; grey Clang SA
  row (−.008 [−.066, +.043], 97 %) + bullet "a static analyzer, not an LM, meets the near-cloud test". Standout:
  "Not yet: L4-D closes 89 % of the gap, 1.9× faster than the cloud." Backup title "on Debiased, the unit-label LoRA
  passed the near-cloud test". notes.md + README ("Wording and comparison rules (v4.5)") updated.
- Vertical vs horizontal comparison (user rule): slide 19 retitled "Same Qwen3.5-4B: unit-label FT < untuned
  generator < fact-label FT", Intern line removed, paired FT − read-out deltas per strategy from paired_deltas
  (L1 +.021 n.s., L3 +.304, L4-D +.074) and +.067 over gen. L3; slide 21 first row = Qwen read-out L4-D (66 %);
  take-aways 2/3/4 use read-out (+.401) and FT (+.074) only; model table role of Intern "side-by-side decision baseline".
