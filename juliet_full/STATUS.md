# Orchestration status (parent-owned)

The parent (orchestrator) keeps this file up to date. Lanes may READ it but must not edit it.
It records progress and is how information passes between the parent and the lanes.
- Binding interface between lanes: `juliet_full/README.md` (lane contract).
- Plan (Chinese): `PLAN.md`.
- Each lane's final report is copied to `juliet_full/lane_reports/<date>_<lane>_<stage>.md`.

Last update: 2026-11-23 11:44 PST (dell clock is America/Los_Angeles; Beijing = PST + 16 h).

## 1. Decisions log (newest first; source = user message or parent)
- 2026-11-23 22:05 user (main line decided + new stage):
  - **Main line, qualified version: "Near-LLM quality at decision-model speed — in distribution, but not (yet) under DeadFree."** It is now written into PLAN §1, and the primary axis is now model type (generative LLM vs decision model).
  - **New stage: LoRA L4-D.** Qwen3.5-4B + LoRA is trained on the L4-D fact questions, with labels produced automatically by dynamic analysis, and it uses layer1 training folds only. This replaces the earlier "LoRA = N/A" for L4-D. The question is whether it reaches near-LLM quality on all four layers.
  - **Criteria were pre-registered in PLAN §4.2 before any L4-D run:**
    - near-LLM: macro-F1 ≥ DeepSeek L1 − 0.02 on the same units;
    - equivalent within 2 points: the lower bound of the cluster-CI for Δ is ≥ −0.02;
    - speed: c1 e2e median ≤ 0.36 s.
  - Contract: `juliet_full/l4d/README.md`.
  - Zero-shot read-outs: the Qwen base read-out is required, Intern-Decision is optional, and Jev is not run for now.
- 2026-11-23 user: do ONLY option 1 = L4-D. L4-D is the decision-model version of L4: a lexical parser lists candidate sites, the decision model answers typed questions (heap? / which allocation does this release free? / does this branch always, never or sometimes run? / is the old pointer still freed if realloc fails?), and Soufflé derives the leak verdict. It runs zero-shot on Jev, Intern-Decision-4B and the Qwen base read-out; LoRA is N/A. It does not use DeepSeek. There is NO generative fine-tuning of Qwen. Details are in PLAN.md §3.1. (Main line decided later, see the 22:05 entry; L4-D LoRA was added later as well.)
- 2026-11-23 18:18 user: both documents in English; the new proposal goes in a new directory (`proposal/v2/`). For the Thursday demo either a live run or the recording is fine (keep both ready). The demo slides (incl. the 43-row demo) need the user's review before confirmation. Do NOT push to GitHub for now.
- 2026-11-23 17:40 user: "请同时编写新版本的proposal, final project paper，使用ieee conference模板" (write the new proposal and the final paper at the same time, IEEE conference template). Parent defaults (not yet confirmed by the user): both in English; new dirs `proposal/v2/` and `report/final_en/`; existing proposal/report files untouched; preamble and authors from `proposal/proposal_en.tex`; contract = `report/final_en/OUTLINE.md`.
- 2026-11-23 user: DeepSeek main experiment may use the FULL eval set (2,656 units) instead of the 1,328-unit api_subset. Total DeepSeek spend is still capped at CNY 10, with a client hard stop at CNY 9.5. Priority order: main L1 → L3 → L2 → L4 → repeats → stress layer ③ → placebo → original Juliet.
- 2026-11-23 user: the cs253-pre SGLang containers on 184-toast stay stopped and need not be restored.
- 2026-11-23 user: the presentation (Thu 2026-11-26) uses Beamer, in English, with no prescribed template (use metropolis, 16:9, authors from `proposal/proposal_en.tex`), and must include a LIVE DEMO. A recorded backup video is still advisable.
- 2026-11-23 user: do not damage files unrelated to the experiment. Keep records for progress and for passing information to lanes (this file).
- 2026-11-23 user: decision-model fine-tuning starts now, while the GPUs are idle. Each fold trains on the OTHER TWO folds only; dev is the validation set (epoch/checkpoint by dev AUROC every half epoch, threshold by dev macro-F1). 6 jobs = 3 folds x {L1, L3}, one job per GPU, L1 first. Max 3 epochs (2 if the projection exceeds 6 h).
- 2026-11-23 user: option A, so the only training in the project is the Qwen3.5-4B LoRA decision model. LineVul is a zero-shot baseline only.
- 2026-11-23 parent/user: three evaluation layers. ① debiased original (main); ② natural hard subset (filter of ①); ③ stress test (dead frees under file-local decidable guards, real good frees wrapped in always-true guards) plus placebo. Trained methods train on ① only.
- Split frozen: `juliet/full_split_v1.json` (SHA-256 08017a6f…0065). Dev = 9 flow variants (04 10 17 18 31 41 65 68 73; 330 groups). Eval = 39 variants (1,328 groups) in 3 folds (472 / 424 / 432).

## 2. Frozen artifacts
- **L4 v3c FROZEN 2026-11-23 12:15 PST** (parent; `llm/l4/FREEZE_PROPOSAL.md`): chat L4 prompt hash `00a81aa6…`, `llm/l4/leak.dl` sha256 `ee9cc78e…`, `llm/llmlane/l4.py` sha256 `22f3e53c…`. `run_llm.py` refuses eval L4 unless all three match (`FROZEN_L4_FILES`). Dev: holdout40 80/80 agree (clean estimate); confirm60 120/120 only after the `delete`→free alias, which its own error motivated (119/120 without it). The same frozen L4 prompt is used for Qwen.
- Commit `190679c`: plan freeze plus the lane contract. Commit `d2e6def`: layer-1 data, LLM lane code, PLAN updates.
- `juliet_full/data/build/SHA256SUMS`: layer1.jsonl `d4d913c4…cafad9`, original.jsonl `bf7d3538…7abb`, subsets.json `4380855f…8c83`. `changed_units.json` is empty.
- **LLM prompts FROZEN 2026-11-23 11:08 PST** (parent, after stage-2a dev check; lane_reports/2026-11-23_llm_stage2a.md). Files `juliet_full/llm/prompts/*` at commit of this freeze; L2 examples rebuilt from full dev (strdup_char_18 bad, new_int_41 good, new_int_65 bad, int_malloc_73 good; both units of these 4 groups excluded from dev runs). Prompt-set hashes: chat L1 `ed8676d1…`, L2 `a932f4394ee07909…`, L3 `1b4e5f65…`; Jev L1 `6de1c2a4…`, L2 `b623ac7f8d24e75b…`, L3 `668f6ef9…`. Any later change = new prompt hash + rerun of that strategy.
- Jev decision threshold: primary = fixed 0.5 (zero-shot, no tuning; pre-registered); secondary = threshold chosen on dev macro-F1, reported as such; AUROC always reported.
- L3 evidence FROZEN by the static lane: `static/results/clang_sa/layer1/EVIDENCE_FROZEN` = `full_v2 00897f5445fbc1085cedac05f549886ccbdf9e3f3d5e1737bc78f9196890eec5`. The Clang SA baseline that gets reported must be this same run, full_v2.

- 12:50 PST evidence incident (decision_ft): the L3 FT data had been rendered at 10:44 from clang_sa full_v1 (0bb13404…) instead of the frozen full_v2 (00897f54…). The only difference is 28 fold-0 bad `_67` units (no warning in v1). Fix (parent decision): L3_fold2 and L3_fold1 restarted with v2 data in parallel on GPU 0 / GPU 1 (ETA ≈ 13:30 PST); killed runs kept under superseded/; L3_fold0's model is clean and only its fold-0 predictions are redone with v2. GPU 1 goes to the gpu lane after the marker `~/disk4/cs224/GPU1_FREE_FOR_SERVICES`. The LLM lane's L3 runs were already on v2 (sha in their meta).

## 3. Machines, tools, endpoints
- dell (this host): every client and CPU tool. Tools live under `~/tools/cs224/`; see `VERSIONS.txt`: clang 23.1.6, cppcheck 2.22.0, valgrind 3.28.0, codeql 2.27.5, infer 1.3.0, souffle 2.5.
  - `clang.cfg` and `clang++.cfg` in `llvm-23.1.6/bin` force gcc 13 headers (without them, gcc 14 is picked and has no libstdc++).
- 184-toast (`ssh 184-toast`, LAN 10.15.89.184): 2x RTX 3090. Run `source ~/disk4/cs224/gpu/server/env.sh` before any GPU job; it sets the caches, HF offline mode and the CPATH for Python.h.
  - Venv `~/disk4/cs224/venv`: torch 2.14, vllm 0.34, transformers 5.22.2, peft 0.22, fla 0.6.0.
  - Models in `~/disk4/cs224/models/`.
- Services: vLLM Qwen3.5-4B (:8001, GPU 0) and Intern-Decision `/decide` (:8002, GPU 1) were STOPPED at 10:46 PST for fine-tuning. Restart with `juliet_full/gpu/README.md` §2, then rerun `bench_qwen.py` and `bench_decide.py`.
  - Marker `~/disk4/cs224/GPU_FREE_FOR_FT` = the GPUs belong to the fine-tuning lane.

## 4. Lanes
| lane | dir (write boundary) | run id (latest) | status | next |
|---|---|---|---|---|
| data | juliet_full/data/ | 958e867b (stage 4 done) | stages 1–4 DONE (lane_reports/2026-11-23_data_stage{1,3,4}.md). Stage 4 = dynamic reference line: asan_lsan (use_stacks=0) eval R .891 macro-F1 .945 [.917,.966] on layer1/original, P 1.000; valgrind .946; dynamic_enhanced 1.000 on layer1/layer3/placebo (identical predictions across layers; 0 FP on all goods); misses of plain dynamic: realloc_fail 0/84, globals at exit (31-45 176/210), variant-12 random. Bug fixed: wcsdup leak attribution (48 strdup_wchar_t bads were invisible; 336 jobs rerun). c1 latency (compile incl., quiet): asan_lsan 0.134 s, valgrind 0.407 s, dynamic_enhanced 1.194 s | — |
| static | juliet_full/static/, juliet_full/analysis/ | 6d144219 (stage 2 done) | stages 1–2 DONE (lane_reports/2026-11-23_static_stage{1,2}.md; `static/results/scores/{SUMMARY,ROBUSTNESS}.md`). Eval macro-F1 layer1/layer3/placebo/original: clang .855/.855/.855/.822; codeql .882/.766/.882/.785; infer .815/.815/.815/.770; cppcheck .493/.493/.493/.467; grep .701/.333/.701/.935. Clang, Infer, Cppcheck: 0 verdict flips on layer3 and placebo (they prune constant guards, also across calls); CodeQL loses 309/1,279 bad detections on layer3 (its 'never freed' rule is satisfied by any free). c1 latency (quiet): clang 18 ms, cppcheck 8 ms, grep <1 ms, infer 0.278 s, codeql per-unit 7.36 s / batch50 amortized 0.318 s. Known artifact: CodeQL batching causes 4 eval FPs on `_08` goods (shared helper names; −0.002 macro-F1; frozen, not fixed) | — |
| llm | juliet_full/llm/ | abfae8d0 (stage 2d done 16:20) | stage 2d DONE (lane_reports/2026-11-23_llm_stage2d.md): Qwen3.5-4B eval layer1 L1 .754 / L2 .806 / L3 .858 / L4 .790; layer3 .533/.595/.760/.706; placebo L1 .690, L3 .838; original L1 .572; repeat agreement .985/.995/.985 (vLLM batching nondeterminism); L4 strict parse 70.3%, grounded facts 63.5% (DeepSeek 100%/99.9%). Quiet c1 latency300 L1: DeepSeek 0.715/1.026 s, Jev 0.907/0.931, Qwen 0.635/0.687 (GPU shared). Earlier: stage 2c DONE (lane_reports/2026-11-23_llm_stage2c.md; `llm/results/SUMMARY.md` 40 runs). DeepSeek L4 eval layer ① .976 (facts 99.87% grounded); layer ③ Δ macro-F1 vs ① nested25 L1 −.118, L2 −.112, L3 −.104, L4 −.078 (placebo Δ ≈ 0); api_subset L1–L3 −.128/−.122/−.114; Jev Δ −.025 to −.031 (placebo-adjusted −.002 to −.010); DeepSeek ③ errors mainly FP on B2G goods with a guarded real free + a dead free (37/76); original-Juliet FPs on multi-function goods (variants 21, 22, 11). Quiet-latency remeasure skipped (lock busy) | RUNNING stage 2d (run 98b264d0): Qwen3.5-4B frozen L1–L4 (dev sanity → eval layer1 L1–L3 ×3 + L4 → layer3 L1–L4 → placebo L1+L3 → original L1 → c1 latency); DeepSeek+Jev quiet-latency remeasure only if dell is quiet (≤ ¥0.10). Qwen eval layer1 r1: L1 .754, L2 .806, L3 .858, L4 running; r2/r3 only on repeat100 (parent steer 14:04) |
| gpu | juliet_full/gpu/, 184-toast ~/disk4/cs224/gpu | c5290c70 (stage 2 resumed 14:46 after 2 h timeout; 4 h) | Qwen :8001 + Intern-Decision :8002 on GPU 1; dell driver `gpu/run_decide_stage2.sh` (log /tmp/jfull_gpu/decide_stage2.log, resumable). Intern-Decision FROZEN 13:53 (dev L1 AUROC .967; thresholds secondary L1 0.823). Eval layer1 prelim @0.5: L1 P.777 R.916 mF1 .825; L2 .844; L3 running. LineVul layer3/placebo/original done (gpu results/linevul_gpu/) | — |
| decision_ft | juliet_full/decision_ft/, 184-toast ~/disk4/cs224/decision_ft | 55892055 (stage 2 DONE) | stages 1–2 DONE (lane_reports/2026-11-23_decision_ft_stage{1,2}.md). Merged = reported. Eval macro-F1 (held-out folds): L1 layer1 .984 [.982,.986], L3 .983; layer3 L1 .372 (recall .04), L3 .639 (recall .38); placebo L1 .976, L3 .970; original L1 .944. Fold 1 weakest (.953). Read-out ablation (no LoRA, dev threshold) layer1 L1 .703 / L3 .773 (AUROC .789/.862). c1 latency dell: L1 0.105 s (server 0.084), L3 0.133 s. :8003 LIVE on GPU 0 (22/22 spot checks exact). Selection weak (dev AUROC saturated 1.0, chosen by dev loss) | — |
| slides | presentation/pre/ | b1ffc33b (stage 2 done 15:48) | stage 2 DONE (lane_reports/2026-11-23_slides_stage2.md): main.pdf 41 pages, 18 numbered + 16 backup; notes.md 17:00; opening table from original-layer runs; robustness figure (paired, placebo) = slide 13; LoRA shortcut slide 14; L4 slide 15; demo slide from stage_dryrun.json; latency table figures/latency_c1.csv (hand-typed, source column); min_coverage 0.995; new finding: two failure modes on layer ③ — misses (trust dead free: grep −1,155 detections, CodeQL −309, LoRA L1 −1,234) vs false alarms (doubt guarded real free: Qwen L1 +674, Intern-D L1 +603, L3 +506) | after Qwen + Intern-Decision finish: update latency_c1.csv with quiet DeepSeek/Jev/Qwen c1 numbers, then `cd presentation/pre && make && make check && make pngs`; re-read slides 13–15 wording |
| demo | presentation/demo/ | 7df114f2 (stage 2 done 15:12) | FINAL backup recorded 16:30 PST by parent: `presentation/demo/recordings/stage_final.{json,cast,gif,mp4}` (REC_ROWS=43, --allow-eval --allow-peak --ft-l3 --jev; decision model via :8003 fold0 adapters, no fallback; verdicts = stored: grep + FT L1/L3 flipped, Clang SA/DeepSeek L1,L3/Jev robust, good twin no false alarm; spend ¥0.0016/$0.00009). stage 2 DONE (lane_reports/2026-11-23_demo_stage2.md): :8003 primary decision path (fold adapter of the unit; fallback :8002 → :8001 → offline); `--attack-n-dead` default 0 = stress.py construction = stored layer3 exactly; stage unit `CWE401_Memory_Leak__strdup_char_01` (C, 24 lines, B2G twin, one dead `if(sym_61 > 4) { free(data); }`), backups `int64_t_malloc_01`, `new_array_int64_t_01`; dry run demo_20261123T230820Z 21/21 verdicts = stored (grep + FT L1/L3 flipped; Clang SA, DeepSeek L1/L3, Jev robust; good twin no false alarm); 10 tests pass; demo spend total ¥0.0079 / $0.00025. Stage needs 38 rows (+3 --ft-l3, +2 --jev) | services left running for Thursday: 184-toast :8003 (GPU 0), :8001 Qwen + :8002 Intern-Decision (GPU 1); before the talk run `./check.sh && ./check.sh --warm` |
| paper-front | report/final_en/ sections 00–04, 07–09, references.bib, figures_front/, tables/front_* | 5bab5535 (DONE ~18:18) | DONE (lane_reports/2026-11-23_paper_front_stage1.md): sections + tab:dataset/split/methods + fig:overview; references.bib 82 entries (24 added, 7 seed fixes; LoRA arXiv only) | integrated by parent 18:35: `report/final_en/main.pdf` 16 pages (body p1–p11, refs p11–12, appendix A–E p12–16), make check clean, 0 overfull; parent edits: removed \balance, intro Δ wording, provenance list → generated/provenance.tsv (119 files) + short paragraph, res_folds moved before full tables |
| paper-results | report/final_en/ sections 05, 06, 10, figures/, tables/res_*, generated/, references_results.bib | 720ac9fe (DONE ~18:15) | DONE (lane_reports/2026-11-23_paper_results_stage1.md): §V/§VI/app written; `make figures` regenerates numbers.tex (all slide keys kept) + 13 tables + pareto/robust PDFs; McNemar 18 pre-registered tests, 14 sig after Holm (DeepSeek L1/L2/L3 n.s. among themselves; L4 worse); new finding: Clang SA misses all 132 eval new[] leaks passed to print helper; §V ≈3.4 pages (over budget); cascade not done | parent removed \balance from main.tex 18:20 |
| proposal-v2 | proposal/v2/ | 06cb6a43 (DONE ~18:00) | DONE (lane_reports/2026-11-23_proposal_v2_stage1.md): `proposal/v2/proposal_v2.pdf` 6 pages (body ≈4.5 + refs), make check clean; 32 verified refs (seed kept as references_seed_unverified.bib); 61 typed numbers with % src; 4 preliminary numbers from presentation/pre/figures/numbers.tex (re-sync if paper numbers.tex changes); grep .935 = eval split | re-sync preliminary numbers after paper results lane |
| l4d-data | juliet_full/l4d/ (contract README.md parent-owned) | f7c755d8 (launched 22:10, 6 h) | RUNNING: parser + masked question templates + dynamic gold (gcov coverage ≥8 runs, alloc/free trace, realloc injection) + Datalog/derive.py + oracle check; markers build/SAMPLE_READY → LAYER1_READY → ALL_READY; report l4d/REPORT_stage1.md | — |
| l4d-train | juliet_full/l4d_ft/, 184-toast ~/disk4/cs224/l4d_ft | 4b9d8f2d (launched 22:12, 6 h) | RUNNING: code + smoke test on sample → stop services → 3 fold jobs (≤2.5 GPU-h each) → dev selection → l4d_ft/FROZEN → eval 4 layers + qwen_readout_l4d → latency :8004 → restore :8001/:8002/:8003 by 2026-11-25 12:00 PST | — |

## 5. Results so far (sanity checks / preliminary, NOT final)
- Data probes, eval macro-F1, original → layer 1: static-void 1.000 → 0.333; function count 0.924 → 0.499; lines 0.906 → 0.544; grep v0 0.935 → 0.701 (B2G 0.959, G2B 0.354); BoW LR 1.000 → 0.979 (AUROC 0.982; the cues are free/delete/ALLOCA, which are task-intrinsic).
- Label verification: gcc and clang compile 3316/3316 for both layers; good units 1658/1658 show no leak. Bad units with a leak reported: c_alloc 914/960, cpp_new 558/588, realloc_fail 0/108, destructor 2/2.
  - Known LSan blind spots: realloc_fail 108; still reachable from a global at exit (variants 45 and 68) 68; variant-12 random branch 8.
  - LSan uses `use_stacks=0`; with default options, 175 more bad units are missed (stale -O0 stack slots).
  - 16 variant-12 bad units trigger ASan bad-free (Juliet's own ALLOCA + free path).
- LineVul zero-shot, layer 1, eval: P 0.51, R 0.67, F1 0.58, accuracy ≈ 0.5. CPU and GPU predictions are identical. Latency: GPU 5.9 ms median (server); CPU 0.16 s median (dell loaded; re-measure when idle).
- Qwen3.5-4B vLLM from dell: c1 median 0.665 s / p90 0.749 s; c16 8.1 req/s; c32 9.0 req/s (L1-style, ~530 in / ~47 out).
- Intern-Decision-4B `/decide` from dell: median 82.7 ms (server 80.0 ms, network ~2.7 ms).
- DeepSeek per call (off-peak, measured): L1 ¥0.00045, L2 ¥0.00041, L3 ¥0.00026–0.0005, L4 ¥0.00047. Smoke correct/20 on L1/L2/L3: DeepSeek 19/20/20, Jev 19/19/19, Qwen 18/18/19 (L3 on mock evidence, meaningless).
- L4: DeepSeek facts parse 12/12 and agree with the truth on 10/12. Failure mode: identical facts for the leaking and fixed realloc versions, plus one hallucinated free.

- Decision FT (stage 1): step-0 head = tied Yes/No rows exactly (diff 0.0). Zero-shot L1 dev AUROC 0.8825 (base lm head) / 0.8842 (head, bs1). After half an epoch, dev AUROC is 1.000 (fold0) and 0.9995 (fold1), and train loss reaches about 1e-8. So layer ① is easy for a trained model, which matches the BoW LR 0.979: free/delete/ALLOCA are task-intrinsic cues. Layer ③ is where robustness will be measured, and the FT model is trained only on layer ①.
  - LoRA has 32,464,896 trainable parameters; fla 0.6.0 Triton kernels are used. Speed: L1 4.5 s per step (20.3 GB, no grad checkpointing).
  - Merged and unmerged scores differ by up to 0.36 (mean 0.23; BF16 merge rounding), while dev AUROC is the same. TODO: decide which scores to report once each job's merge_check arrives.
  - Latency is measured server-side for now; dell-side latency comes via :8003.

- Layer ③ (stress) and placebo layer (data stage 3): all 3,316 units; probes on eval (all / B2G): grep v0 .333/.333, v1 .333/.333, v2 .498/.499, BoW AUROC .810/.609 (limit B2G ≤.65; G2B subset .986 from ALLOCA/new = task-intrinsic); format probes ≤.525. Deviations from PLAN §2.5 (decided on dev): guard constants take values 4 or 5 so every comparison form occurs as both true & false (fixed 5 → BoW B2G .989); random guard names sym_10–sym_99; G2B goods also get 1–2 dead frees (flaw-site match); realloc_fail/destructor families get 1–2 dead frees in both labels; object deletes wrapped. Verification gcc/clang 3316/3316 both layers; same verdict as stage 1 for all 3,236 non-variant-12 units (variant 12 random path: 67/80 and 71/80).

- PRELIMINARY layer-① eval scores (2,656 units; parent ran analysis/score.py at 11:30 PST; static runs not yet final). Columns are P / R / F1(leak) / macro-F1, then median latency.
  - DeepSeek L1 .991 / 1.000 / .996 / .995, 0.76 s (c16 bulk; p90 5.7 s queueing).
  - DeepSeek L2 .996 / 1.000 / .998 / .998.
  - DeepSeek L3 .990 / 1.000 / .995 / .995.
  - Jev L1 .953 / .991 / .972 / .971, 0.89 s.
  - Jev L2 .947 / .999 / .973 / .972.
  - Jev L3 .962 / 1.000 / .980 / .980.
  - Clang SA full_v2 .928 / .771 / .842 / .855, 36 ms.
  - CodeQL batch50_merged .829 / .963 / .891 / .882.
  - Infer: the per-unit run gave .925 / .398 / .556 / .655 at 0.39 s and is SUPERSEDED. The final run, full_per_file_merged, gives macro-F1 .815 [.741, .874].
  - Cppcheck .897 / .171 / .287 / .493, 9–15 ms.
  - grep v0 .658 / .870 / .749 / .701.
  - LineVul .510 / .666 / .577 / .501, 5.9 ms (GPU).

- PRELIMINARY stage 2c (12:28 PST, from llm/scratch/stage2c/status.txt; macro-F1, FP/FN):
  - DeepSeek L4 eval layer ①: .976 (29/34), ¥1.68.
  - Layer ③ nested25 (664): DeepSeek L1 .881 (54/25), L2 .887 (56/19), L3 .890 (58/15), L4 .895 (30/40). api_subset rest (664): L1 .857, L2 .867.
  - Placebo nested25: DeepSeek L1 .995, L3 .994, so the drop comes from the dead frees, not from any perturbation.
  - Original Juliet nested25: DeepSeek L1 .961 (26 FP).
  - Jev layer ③ full eval: L1 .946, L2 .942, L3 .949 (vs about .97–.98 on ①). Jev drops less than DeepSeek; the paired check is pending.
- Parent authorized one extra DeepSeek run, l3_apirest_L3_r1 (≈ ¥0.23; cumulative cap ¥8.25). L4 on apirest was NOT authorized; L4 on layer ③ stays nested25-only.

## 6. Budget
- 16:20 PST: DeepSeek ledger ¥8.2098 (balance ¥2.69; consistent with ¥10.50 at 11:00 minus ledger spend since then), Jev $1.9043. Remaining under ¥9.5 hard stop ≈ ¥1.29 → demo only.
- 15:12 PST: DeepSeek ledger ≈ ¥8.13 (balance ¥2.72); demo reserve ¥0.05 inside the ¥9.5 hard stop.
- 13:05 PST after LLM stage 2c: DeepSeek ledger ¥8.126 (account balance ¥2.91); ≤ ¥1.87 left under the user's ¥10 cap → reserve for demo + quiet-latency remeasure + emergencies only. Jev ledger $1.894 of $4.8.
- 12:10 PST after LLM stage 2b: DeepSeek ledger ¥3.70; Jev ledger $1.218 of $4.8 (3 full eval repeats × L1–L3 cost more than the ~$1.4 plan assumed for everything; the rest of the Jev plan ≈ $0.8).
- DeepSeek (11:20 PST, demo check.sh): ledger total ≈ ¥3.09, balance ¥8.58 (LLM stage 2b eval runs in progress). Earlier: ledger total ≈ ¥0.362 (stage 2a ¥0.329) + parent probes ≈ ¥0.02; balance ¥10.50 at 11:00 PST. Ledger `juliet_full/llm/ledger.jsonl`.
- Jev: ledger total $0.0427 of $4.8.

## 7. Open items / TODO (parent)
- **NOW (22:12):** LoRA L4-D stage. When the lanes report: check the oracle check (≥0.99 per layer), FROZEN before eval (timestamps), the per-layer pass/fail of the §4.2 criteria, and that the services are restored. Then commit and copy the reports to lane_reports/. Then rewrite paper/proposal/slides for the qualified main line. The title is still undecided (user to choose); the slides need user review; no push.
0. Key finding to watch: DeepSeek is at the ceiling on the debiased dev set (macro-F1 1.000), so layer ③ stress, placebo, and latency/cost become the differentiators. A contamination caveat applies (Juliet is public).
1. ✅ Prompts frozen at 11:08 PST (commit 780ec1e). LLM stage 2b launched (4c6356a0); its budget is ≤ ¥4.0 and ≤ $1.30.
2. After FT: restart the services; add an FT-model forward endpoint (for latency from dell and for the demo); run Qwen L1–L3 and Intern-Decision zero-shot on full dev+eval.
3. ✅ Static stage 1 (160da46). Main comparisons on full eval; api_subset secondary. Latency c1 measurement convention: only when load1 < 2.5, record load; all lanes serialize c1 latency runs with `flock /tmp/cs224_latency.lock` (quiet check after the lock; steered 12:13 PST).
4. Slides lane plus demo lane (live demo; backup recording).
5. Layer ③ stress and placebo construction (data lane, stage 3).
6. Re-measure CPU latencies on an idle dell. The DeepSeek and Jev lat300_c1_L1 runs were measured at load ≈21 (11:52–11:57 PST); remeasure them once dell is quiet (≈ ¥0.08 + $0.01) and keep both, with the load recorded.
7. Commit after each lane completes (no push). Do not touch files unrelated to the experiment.
