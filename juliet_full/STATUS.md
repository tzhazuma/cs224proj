# Orchestration status (parent-owned)

The parent (orchestrator) keeps this file up to date. Lanes may READ it but must not edit it.
It records progress and is how information passes between the parent and the lanes.
- Binding interface between lanes: `juliet_full/README.md` (lane contract).
- Plan (Chinese): `PLAN.md`.
- Each lane's final report is copied to `juliet_full/lane_reports/<date>_<lane>_<stage>.md`.

Last update: 2026-11-23 11:02 PST (dell clock is America/Los_Angeles; Beijing = PST + 16 h).

## 1. Decisions log (newest first; source = user message or parent)
- 2026-11-23 user: DeepSeek main experiment may use the FULL eval set (2,656 units) instead of the 1,328-unit api_subset. Total DeepSeek spend is still capped at CNY 10, with a client hard stop at CNY 9.5. Priority order: main L1 → L3 → L2 → L4 → repeats → stress layer ③ → placebo → original Juliet.
- 2026-11-23 user: the cs253-pre SGLang containers on 184-toast stay stopped and need not be restored.
- 2026-11-23 user: the presentation (Thu 2026-11-26) uses Beamer, in English, with no prescribed template (use metropolis, 16:9, authors from `proposal/proposal_en.tex`), and must include a LIVE DEMO. A recorded backup video is still advisable.
- 2026-11-23 user: do not damage files unrelated to the experiment. Keep records for progress and for passing information to lanes (this file).
- 2026-11-23 user: decision-model fine-tuning starts now, while the GPUs are idle. Each fold trains on the OTHER TWO folds only; dev is the validation set (epoch/checkpoint by dev AUROC every half epoch, threshold by dev macro-F1). 6 jobs = 3 folds x {L1, L3}, one job per GPU, L1 first. Max 3 epochs (2 if the projection exceeds 6 h).
- 2026-11-23 user: option A, so the only training in the project is the Qwen3.5-4B LoRA decision model. LineVul is a zero-shot baseline only.
- 2026-11-23 parent/user: three evaluation layers. ① debiased original (main); ② natural hard subset (filter of ①); ③ stress test (dead frees under file-local decidable guards, real good frees wrapped in always-true guards) plus placebo. Trained methods train on ① only.
- Split frozen: `juliet/full_split_v1.json` (SHA-256 08017a6f…0065). Dev = 9 flow variants (04 10 17 18 31 41 65 68 73; 330 groups). Eval = 39 variants (1,328 groups) in 3 folds (472 / 424 / 432).

## 2. Frozen artifacts
- Commit `190679c`: plan freeze plus the lane contract. Commit `d2e6def`: layer-1 data, LLM lane code, PLAN updates.
- `juliet_full/data/build/SHA256SUMS`: layer1.jsonl `d4d913c4…cafad9`, original.jsonl `bf7d3538…7abb`, subsets.json `4380855f…8c83`. `changed_units.json` is empty.
- **LLM prompts FROZEN 2026-11-23 11:08 PST** (parent, after stage-2a dev check; lane_reports/2026-11-23_llm_stage2a.md). Files `juliet_full/llm/prompts/*` at commit of this freeze; L2 examples rebuilt from full dev (strdup_char_18 bad, new_int_41 good, new_int_65 bad, int_malloc_73 good; both units of these 4 groups excluded from dev runs). Prompt-set hashes: chat L1 `ed8676d1…`, L2 `a932f4394ee07909…`, L3 `1b4e5f65…`; Jev L1 `6de1c2a4…`, L2 `b623ac7f8d24e75b…`, L3 `668f6ef9…`. L4 NOT frozen (dev design continues). Any later change = new prompt hash + rerun of that strategy.
- Jev decision threshold: primary = fixed 0.5 (zero-shot, no tuning; pre-registered); secondary = threshold chosen on dev macro-F1, reported as such; AUROC always reported.
- L3 evidence: waits for `juliet_full/static/results/clang_sa/layer1/EVIDENCE_FROZEN` (static lane writes run id + sha; currently evidence.jsonl == full_v2.evidence.jsonl, sha 00897f54…).

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
| data | juliet_full/data/ | ce4bccc8 (resumed 24301f44) | DONE stage 1 (report: lane_reports/2026-11-23_data_stage1.md) | stage 3: build layer ③ and placebo (Phase D; maybe earlier for the demo) |
| static | juliet_full/static/, juliet_full/analysis/ | 3c1d3649 (resumed 02f56008) | RUNNING: mapping, full clang/cppcheck/grep, evidence, CodeQL/Infer, score.py | — |
| llm | juliet_full/llm/ | 6d6db797 (stage 2a done) | stage 2a DONE (lane_reports/2026-11-23_llm_stage2a.md): DeepSeek dev macro-F1 L1 1.000 / L2 1.000 / L3 0.997; Jev 0.977 / 0.950 / 0.987 (AUC ≥0.999); prompts frozen | stage 2b: eval runs |
| gpu | juliet_full/gpu/, 184-toast ~/disk4/cs224/gpu | 9f90dfc5 (resumed 046b1350) | DONE stage 1 (report: lane_reports/2026-11-23_gpu_stage1.md) | after FT: restart services, add a fine-tuned-model endpoint, Qwen and Intern-Decision zero-shot runs |
| decision_ft | juliet_full/decision_ft/, 184-toast ~/disk4/cs224/decision_ft | abb53eac | RUNNING: pipeline, speed test, queue of 6 jobs | collect predictions when the jobs finish |
| slides | presentation/pre/ | a1c38326 | RUNNING: Beamer metropolis 16:9, figures pipeline (`make figures`), notes.md speaker script | parent refreshes figures once results land |
| demo | presentation/demo/ | 4467045b | RUNNING: rich TUI demo.py (grep / Clang SA / FT decision model :8003 with fallbacks / DeepSeek / Jev), live dead-free insertion, --replay/--record, check.sh, record.sh | needs :8003 endpoint after FT; record backup video |

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

## 6. Budget
- DeepSeek: ledger total ≈ ¥0.362 (stage 2a ¥0.329) + parent probes ≈ ¥0.02; balance ¥10.50 at 11:00 PST. Ledger `juliet_full/llm/ledger.jsonl`.
- Jev: ledger total $0.0427 of $4.8.

## 7. Open items / TODO (parent)
1. Freeze the prompts after the stage-2a report, then launch LLM stage 2b (DeepSeek full eval L1/L3/L2, Jev full, in off-peak windows).
2. After FT: restart the services; add an FT-model forward endpoint (for latency from dell and for the demo); run Qwen L1–L3 and Intern-Decision zero-shot on full dev+eval.
3. Static: review the checker mapping, then run CodeQL/Infer (batched if needed).
4. Slides lane plus demo lane (live demo; backup recording).
5. Layer ③ stress and placebo construction (data lane, stage 3).
6. Re-measure CPU latencies on an idle dell.
7. Commit after each lane completes (no push). Do not touch files unrelated to the experiment.
