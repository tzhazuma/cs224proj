# REPORT v4: slides "Near-Cloud Quality on a Local Device?"

Lane slides-v4, 2026-11-24 (build ~08:10 PST). Deck: `presentation/pre/main.pdf`, 56 pages = title + 4 section
dividers + 23 numbered main frames + 29 backup pages (incl. generated provenance pages). Beamer metropolis, 16:9,
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
