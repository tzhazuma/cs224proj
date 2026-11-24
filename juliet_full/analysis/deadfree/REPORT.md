# Lane latency-deadfree: report (2026-11-24)

Scope: per the user decision of 2026-11-24, every cross-model comparison is on **DeadFree** (results dirs: `layer3`; data lane dynamic dirs: `stress`), and every concurrency-1 latency is re-measured on DeadFree. Topic: "Near-Cloud Quality on a Local Device?"

Regenerate everything with `python3 make_latency.py && python3 make_table.py` (in this directory). Both scripts can be rerun at any time and pick up run files that appear later.

| file | content |
|---|---|
| `deadfree_quality.{csv,json,md}`, `deadfree_by_flow.csv` | quality table, 35 methods (all OK, none pending), strategy × FT sub-table, per-flow breakdown, paired deltas, notes |
| `latency_deadfree.csv` | c1 latency per method (role primary/secondary, components, hardware, kernel, run file) |
| `deadfree_pareto.json` | merged time–quality points; Pareto flags computed only over rows that are primary for both latency and quality |
| `kernel_check_{kernel,fallback}.json` | :8002 causal_conv1d check against the stored predictions (50 units × L1/L3) |
| `run_latency.py`, `dyn_latency.py`, `kernel_check.py`, `make_latency.py`, `make_table.py` | lane scripts |
| `raw_logs/` | `latency_cpu_cloud.log`, `latency_gpu.log`, `gpu_chain.sh`, `intern_l4d_{dev,eval}_r1.log` |
| markers | `QUALITY_READY` (07:39 PST), `PRIMARY_LATENCY_READY` (10:03 PST), `184-toast:~/disk4/cs224/L4D_8004_UP` (10:11 PST) |

## 1. DeadFree quality (eval, 2,656 units, 42 families)

Macro-F1 with a family-cluster bootstrap 95% CI (2,000 resamples, seed 20261123, the `near_llm_bootstrap.py` resampler). All Δ and gap-closed CIs are paired, using the same resamples. Gap closed = (F1_m − F1_QwenL1)/(F1_ref − F1_QwenL1), where Qwen3.5-4B L1 (untuned) is the naive local baseline. A missing or null prediction counts as wrong. No method has invalid rows. The cross-check against previously reported numbers passes: DS L1 .863, L4 .900, Jev L3 .949, Qwen L1 .533, L4-D .826, VulnLLM-R .471.

| group | method | macro-F1 [CI] | Δ vs DS L1 [CI] | Δ vs DS L4 [CI] | gap closed vs DS L1 / L4 |
|---|---|---|---|---|---|
| cloud-LLM | DeepSeek L1 | .863 [.841, .881] | — | −.037 [−.063, −.014] | 1 / .90 |
| cloud-LLM | DeepSeek L2 | .873 [.847, .894] | +.010 [+.000, +.019] | −.027 [−.056, −.002] | 1.03 / .93 |
| cloud-LLM | DeepSeek L3 | .875 [.859, .890] | +.012 [+.002, +.023] | −.025 [−.046, −.005] | 1.04 / .93 |
| cloud-LLM | DeepSeek L4 | .900 [.887, .912] | +.037 [+.014, +.063] | — | 1.11 / 1 |
| cloud-decision | Jev L1 / L2 / L3 @0.5 | .946 / .942 / .949 [.918, .970] | +.083 / +.079 / +.086 | +.046 / +.042 / +.049 | 1.25–1.26 / 1.12–1.13 |
| local-LLM | Qwen3.5-4B L1 / L2 / L3 / L4 (gen.) | .533 / .595 / .760 / .706 | −.330 / −.269 / −.103 / −.157 | −.367 / −.306 / −.140 / −.194 | 0 / .19 / .69 / .52 |
| local-decision | Intern-Decision L1 / L2 / L3 @0.5 | .584 / .500 / .664 | −.280 / −.363 / −.199 | −.317 / −.400 / −.236 | .15 / −.10 / .40 |
| local-decision | **Intern-Decision L4-D (@0.5)** | .799 [.770, .823] | −.064 [−.084, −.046] | −.101 [−.136, −.073] | .81 [.75, .86] / .72 |
| local-decision | Qwen read-out L4-D (pre-FT) | .752 [.730, .770] | −.111 | −.148 | .67 / .60 |
| local-FT | **LoRA L4-D (fact FT; opt. = identical verdicts)** | .826 [.809, .842] | −.037 [−.055, −.017] | −.074 [−.092, −.055] | .89 [.84, .95] / .80 [.75, .85] |
| local-FT | LoRA L1 / L3 (unit-label FT) | .372 / .639 | −.491 / −.225 | −.528 / −.262 | −.49 / .32 |
| other-local | VulnLLM-R-7B (policy) | .471 [.448, .495] | −.392 | −.429 | −.19 |
| static | Clang SA / Infer / CodeQL / Cppcheck / grep v0 | .855 / .815 / .766 / .492 / .333 | −.008 [−.066, +.043] / −.049 / −.097 / −.371 / −.530 | −.045 / −.086 / −.134 / −.408 / −.567 | .97 / .85 / .70 / −.12 / −.60 |
| dynamic-reference | ASan/LSan / dynamic enhanced | .948 / 1.000 | +.085 / +.137 | +.048 / +.100 | 1.26 / 1.41 |

Secondary/backup rows (in the full table): Intern L1–L3 with the dev threshold (.630/.625/.700), Intern L4-D with dev τ 0.18 (.373), Qwen read-out L1/L3 (.351/.334), and LineVul (.450).

Paired differences (same resamples): **LoRA L4-D − Intern L4-D@0.5 = +.027 [+.003, +.054]**; **Intern L4-D@0.5 − Qwen read-out L4-D = +.047 [+.029, +.064]**.

Strategy × fine-tuning (macro-F1):

| | Qwen gen. | Intern-Decision | read-out (pre-FT) | our FT |
|---|---|---|---|---|
| L1 | .533 | .584 | .351 | .372 |
| L3 | .760 | .664 | .334 | .639 |
| L4 / L4-D | .706 | .799 (dev τ: .373) | .752 | .826 |

## 2. Intern-Decision L4-D (deliverable 2)

- `juliet_full/gpu/run_decide_l4d.py`. Per unit it takes the L4-D questions from `l4d/build/questions_<layer>.jsonl` and prunes them with `l4d_ft/prune.py` `prune()`, the same pruning as lora_l4d_opt (layer3 eval: 37,376 → 15,619 questions; layer1 dev: 6,332 → 1,916). Each question is one POST `/decide` to :8002 with `{"state", "question" (unchanged), "options": ["Yes","No"]}`. `p_yes` is the calibrated `probs["Yes"]`. Answer rows follow §4 (`qid, unit_id, qtype, p_yes, logit_diff, model "intern-decision-4b", fold null`, plus server timings). Verdicts come from `l4d/derive.py --souffle`: Soufflé agrees with the Python evaluator on 2,656/2,656 units. Every eval unit has at least one kept question.
- **τ selection** used the `l4d_ft/select_fold.py` read-out rule: TAU_GRID sigmoid(0.5t), maximum layer1-dev unit macro-F1 over all 660 dev units, ties broken towards |τ−.5|. Validation: the same code run on the Qwen read-out dev answers reproduces τ .268941 and mF1 .86817 exactly. Result: **τ = 0.182426, dev mF1 .964** (τ = 0.5 gives .785).
- **FROZEN**: `l4d_ft/results/intern_l4d/FROZEN`, written 2026-11-24T16:03:34Z, before any eval call, with sha256 `2abe4da8bc604517184a687141596b5757268d31b3d52628f9943192f5cec52a`. It records τ, the secondary τ 0.5, sha256 of TEMPLATE/templates.py/questions.py/derive.py/l4d.dl/prune.py/script/decide_server.py/questions files, server health, server kernel = fallback, and UTC. The script refuses eval calls when the hashes or the kernel differ.
- Eval: `l4d_ft/results/intern_l4d/layer3/eval_r1.jsonl` (15,619 answers), `eval_r1_units.jsonl` (dev τ), and `eval_r1_tau05_units.jsonl` (τ 0.5), each with `.meta.json`.
- **Reporting decision (parent, 08:55)**: the primary `intern_l4d` is **τ = 0.5** (.799), consistent with Intern L1–L3, whose primary is the calibrated default and whose dev threshold is secondary. `intern_l4d_devtau` (.373) is secondary. FROZEN had listed the dev τ as primary. The parent switched to 0.5 after seeing the eval results, and the switch favours the baseline.
- **Why dev τ fails**: Intern's calibrated p_yes for exec_all/exec_any/rel questions lie in about 0.45–0.65, and with the low τ every one of them becomes "Yes". On Debiased there are no dead frees, so only the heap question has to discriminate (dev .964). On DeadFree, "the release executes on every path" is then accepted for dead frees, and leak recall collapses to .037 (P .98). A threshold tuned on Debiased does not transfer to DeadFree. The Qwen read-out τ .269 does not show this failure (.752).

## 3. c1 latency on DeadFree (latency300 = 150 groups = 300 layer3 eval units; client = dell)

Every run took `flock /tmp/cs224_latency.lock` and then checked that the machine was quiet (dell load1 < 2.5). No run hit the LOADED path. The lock was released between methods, and each run's meta records `latency_lock`. End-to-end definitions: L3 = per-unit Clang SA time (from the `clang_sa/layer3/lat300_c1` run) + model call; L4 = model call + Soufflé (`souffle_s` is shown separately; fact parsing is included in the client time and is negligible); L4-D = live sites + questions (tree-sitter) + prune + one forward per kept question, run sequentially + derive.

| method | median s | p90 s | mean s | components (medians) | hardware / kernel |
|---|---|---|---|---|---|
| DeepSeek L1 / L2 | .895 / .860 | 1.432 / 1.205 | .983 / .878 | API call | DeepSeek API |
| DeepSeek L3 | .810 | 1.192 | .876 | call .790 + clang .019 | |
| DeepSeek L4 | 1.008 | 1.409 | 1.050 | call .971 + Soufflé .034 | |
| Jev L1 / L2 / L3 | .912 / .956 / .923 | 1.319 / 1.737 / 1.123 | .999 / 1.160 / 1.007 | L3: call .903 + clang .019 | Jev API |
| Qwen3.5-4B L1 / L2 / L3 | .347 / .382 / .360 | .363 / .401 / .377 | .349 / .377 / .364 | L3: call .342 + clang .019 | RTX 3090 GPU1, vLLM |
| Qwen3.5-4B L4 | 1.177 | 2.082 | 1.475 | call 1.142 + Soufflé .036 | |
| Intern-Decision L1 / L2 / L3 | .135 / .267 / .167 | .152 / .284 / .186 | .141 / .268 / .172 | server .132 / .263 / .146 (+ clang for L3) | GPU1, fallback conv (primary) |
| Intern-Decision L4-D | .658 | 1.343 | .728 | parse+prune .002, HTTP .657 (server .643, 6 q/unit), derive .0001 | GPU1, fallback (primary) |
| LoRA L4-D opt. / full | .472 / 1.006 | 1.018 / 2.257 | .556 / 1.235 | server .431 / .959; 6 / 13 q per unit | GPU0 :8004, fallback (l4d-train lane run) |
| LoRA L1 / L3 (unit label) | .120 / .143 | .135 / .167 | .117 / .151 | server .109 / .113 (+ clang for L3) | GPU0 :8003, fallback (l4d-train lane run) |
| VulnLLM-R-7B (policy) | 8.047 | 10.468 | 8.237 | | GPU1, vLLM (vulnllmr lane run) |
| Clang SA / Cppcheck / Infer | .019 / .009 / .256 | .022 / .010 / .627 | .023 / .009 / .342 | | dell CPU |
| grep v0 | .000001 | .000001 | .000001 | | dell CPU |
| CodeQL (per unit, first 100 units) | 7.414 | 7.886 | 7.562 | DB build + query | dell CPU |
| ASan/LSan / dynamic enhanced | .135 / 1.169 | .209 / 2.187 | .139 / 1.476 | compile + run(s) | dell CPU |

Secondary rows, measured with the built causal_conv1d kernel ("kernel (not score-identical, |Δp| ≤ 0.03)"): Intern L1/L2/L3 .127/.250/.160 s; Intern L4-D .623 s (max |Δp| vs eval_r1 .062 at question level); LoRA L4-D opt./full .445/.933 s. The kernel saves 5–8 %.

The c1 runs reproduce the stored eval predictions: Intern L1/L3 300/300, Intern L4-D fallback |Δp| = 0 on all questions, Clang 300/300, Qwen L1 298/300, Jev L3 297/300, DS L1 287/300, DS L4 283/300 (the cloud models are not deterministic).

Pareto frontier (primary rows only; quality = DeadFree eval macro-F1): grep v0 → Cppcheck → **Clang SA (.019 s, .855)** → **ASan/LSan (.135 s, .948)** → Jev L3 (.923 s, .949) → dynamic enhanced (1.169 s, 1.000). Among model-based methods only (LLM/decision/FT), the frontier is LoRA L1 (.120 s, .372) → Intern L1 (.135, .584) → LoRA L3 (.143, .639) → Intern L3 (.167, .664) → Qwen L3 (.360, .760) → **LoRA L4-D opt. (.472, .826)** → DS L3 (.810, .875) → Jev L1 (.912, .946) → Jev L3 (.923, .949). This list is read off the csv; the json flags only the global frontier. DeepSeek L4 (1.008 s, .900) is dominated by Jev L1/L3.

## 4. :8002 causal_conv1d kernel check (decision: parent, 08:00)

On the first 50 latency300 DeadFree units × L1/L3, compared with `gpu/results/intern_decision/layer3/l3_eval_L{1,3}_r1.jsonl`:

| server | max \|Δp\| L1 / L3 | mean \|Δp\| | verdict flips @0.5 | median forward ms L1 / L3 |
|---|---|---|---|---|
| built kernel (`PYTHONPATH=~/disk4/cs224/pyext_cc1d`, no fallback warning) | .031 / .030 | .007 / .006 | 1/50 L1, 0/50 L3 | 121 / 134 |
| reference fallback (transformers) | 0 / 0 | 0 | 0 | 128 / 143 |

The kernel is not score-identical: it moves p by more than BF16 output rounding, and it is only about 5 % faster. The stored ~300 ms forward times came from a busy GPU, not from the fallback kernel. Decision taken: Intern L4-D τ/eval and all primary Intern latency rows use the fallback, and the kernel rows are secondary. The same rule applies to the LoRA rows; the parent fixed it at 08:42: primary files are `*_fallback`, matched explicitly and never by glob order.

## 5. GPU 1 hand-over (deliverable 4)

At 18:08Z all GPU-1 work was done. I ran `svc.sh decide stop` and `svc.sh qwen stop`, which left GPU1 at 15 MiB. `SERVE_L4D_READY` was present, so I ran `L4D_GPU=1 bash ~/disk4/cs224/l4d_ft/server/serve_l4d.sh start` (kernel 0 = prediction config). `curl --noproxy '*' http://10.15.89.184:8004/health` returned ok: folds 0–2, 14.97 GB, started 18:11:24Z. I touched `~/disk4/cs224/L4D_8004_UP` at 10:11 PST, well before the 11-25 10:00 PST deadline. :8003 on GPU0 is still healthy.

## 6. Deviations and problems

- **Seed**: `analysis/score.py` uses BOOTSTRAP_SEED 20261126, but the task (and `near_llm_bootstrap.py`) uses 20261123. I used 20261123 with the near_llm resampler.
- **Intern L4-D primary** switched from dev τ to 0.5 after the eval (parent decision; see §2). The `lat300_c1` latency runs used the frozen τ for their verdicts, which does not affect timing.
- **Kernel**: the task asked to "measure with the kernel". Because the kernel is not score-identical, the primary rows use the fallback and the kernel rows are secondary (parent decision; see §4).
- **Contention**: DeepSeek L1 c1 (16:00–16:02Z) overlapped my Intern dev bulk run on GPU1, which only loads the dell client lightly (load ~1). The l4d-train lane's LoRA L4-D fallback run partly overlapped my Intern eval bulk run on GPU1 (their meta `gpu_note` says so). Both runs passed the quiet rule.
- The old LoRA L1/L3 DeadFree runs exist only in fallback (l4d-train lane, `l4d_ft/results/kernel/decision_ft/fallback/layer3/latency300_L{1,3}_v1.jsonl`), so there is no kernel row for them. Their latency_s excludes Clang, so make_latency adds Clang per unit for L3.
- `data/dynamic_runs.py latency()` is hard-wired to layer1, so `dyn_latency.py` drives the same per-unit compile+run definition on the stress layer.
- Lesson learned: `ps | grep -v grep` hides jobs named `grep_v0`, so use `pgrep -af`. Detached chains need `setsid -f` because of the 60 s bash guardrail.

## 7. Spend (this lane)

DeepSeek: L1 ¥0.0774, L2 ¥0.0820, L3 ¥0.0801, L4 ¥0.1590 = **¥0.398** (budget ¥0.8; global ledger stays below the ¥12.3 stop). Jev: L1 $0.0109, L2 $0.0198, L3 $0.0116 = **$0.042** (budget $0.05). GPU: Intern L4-D dev (1,916 q) + eval (15,619 q) + all c1 runs on GPU1, 07:54–10:08 PST.
