# juliet_full/static — static-analysis lane

Static baselines for the CWE-401 layer-1 benchmark (contract: `juliet_full/README.md` sections 3–5).

| file | purpose |
|---|---|
| `run_static.py` | runs one tool over a units JSONL, writes contract predictions + `.meta.json` (+ Clang L3 evidence) |
| `merge_runs.py` | merges runs by `unit_id` (a later run replaces earlier lines) for partial reruns |
| `../analysis/score.py` | scorer (contract section 5), paired McNemar + Holm, `--self-test` |
| `results/<tool>/layer1/<run_id>.jsonl` | predictions; `<run_id>.meta.json`; raw tool output in `raw_logs/` (git-ignored) |
| `results/clang_sa/layer1/evidence.jsonl` | L3 evidence for all 3,316 units, frozen = `full_v2.evidence.jsonl` (`EVIDENCE_FROZEN`) |
| `results/scores/` | score reports (`<tool>_<dev|eval|eval_api>.json`) and `SUMMARY.md` |
| `scratch/` (git-ignored) | fixture builder, dev mapping tables (`rule_table.py`, `checker_table.py`), `score_all.py`, logs |

## Usage

```
python3 run_static.py --tool clang_sa --units ../data/build/layer1.jsonl [--set dev|eval] [--subset api_subset] \
    --layer layer1 --run-id <id>            # -> results/clang_sa/layer1/<id>.jsonl (+ .meta.json, evidence)
python3 run_static.py --tool codeql --units ../data/build/layer1.jsonl --batch-size 50 -j 3 --run-id <id>
python3 merge_runs.py --out results/codeql/layer1/<id>_merged.jsonl <base>.jsonl <rerun>.jsonl
python3 ../analysis/score.py --pred results/clang_sa/layer1/full_v2.jsonl --set eval [--subset api_subset] \
    [--compare results/codeql/layer1/full_batch50_merged.jsonl]
python3 ../analysis/score.py --self-test
```

Defaults: concurrency 1 (`timing_mode=per_unit_c1`), timeout 60 s per unit (batch: 60 s x units).
`-j N` runs units (or batches) in parallel and is recorded (`per_unit_parallel_jN`). Batched CodeQL/Infer
(`--batch-size N`) records `timing_mode=batched` and `latency_s = batch wall time / units in batch`.
Do not rerun `clang_sa` without `--no-evidence` on layer1: the layer evidence file is frozen for the LLM lane
(evidence rows are merged into `evidence.jsonl` by `unit_id`).

## Tools (`/home/barton/tools/cs224`, `VERSIONS.txt` 2026-11-23T18:14:39Z)

| tool | version | notes |
|---|---|---|
| clang_sa | clang 23.1.6 | `clang.cfg`/`clang++.cfg` next to the binary: `--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13` (gcc 14 dir has no libstdc++ headers); recorded in meta |
| cppcheck | 2.22.0 | |
| codeql | 2.27.5, `codeql/cpp-queries` 1.10.1 | build traced with system gcc/g++ 13.3.0 |
| infer | v1.3.0 (Pulse) | needs `--Xclang --gcc-install-dir=.../13`, otherwise C++ fails with `std_testcase.h:58:10: fatal error: 'new' file not found` |
| grep_v0 | — | pred 1 iff `model_text` contains neither `free(` nor `delete` |

All tools work. souffle 2.5 and valgrind 3.28.0 are installed but not used by this lane.

## Inputs to the tools

- Build spec of each unit: `-std=<build.std>`, `-I<include_dirs>`, `-D<defines>`, plus the compatibility flags of
  the old Tier-B run (`-D_GNU_SOURCE`, `-include alloca.h`; cppcheck only gets `-D_GNU_SOURCE`).
- Only findings in the unit's own files (under `program_dir`) count; support files (`io.c`, `std_testcase.h`)
  and system headers are ignored. `io.c` is not analyzed.
- Multi-file units (flows 51–68, 71–84; `tu_mode=wrapper`): one TU `#include`s every unit source, so the
  single-TU analyzers see cross-file flows. Two constructs that are legal across TUs break one wrapper TU, so the
  wrapper then includes an edited copy of `program_dir` with unchanged line numbers (`tu_mode=wrapper_guarded`;
  findings are mapped back to the original paths): headers without include guards (`unit.h` of `_82`, `_83`,
  `_84`) get `#pragma once` appended, and a `typedef struct` block repeated verbatim in a later source (`_67`)
  is blanked. If the wrapper still fails, Clang falls back to the sources one by one (`per_file_fallback`; 0
  units in `full_v2`).
- Clang needs `-analyzer-opt-analyze-headers`: without it the path-sensitive engine only runs on functions of the
  main file, and every wrapper unit got syntax-only checks (dev recall 0 on flows 51–84; `dev_v1`).
- Infer uses `tu_mode=per_file` (each source is a compilation-database entry; Infer links them itself). Infer does
  not analyze functions defined in `#include`d files, so the wrapper gave recall 0 on flows 51–84; on dev
  per_file raised macro-F1 from 0.710 to 0.784 (`full_per_unit_merged` vs `dev_per_file`).
- Batched CodeQL/Infer: every unit defines `main`, `sym_0`, `sym_1`, … and both tools merge same-named external
  functions across the TUs of one database. Each unit in a batch is compiled with `-Dsym_N=sym_N_u<k>` for every
  `sym_N` in its files, and a batch never holds two units of one group. Without renaming, 5 of 20 sample units
  changed verdict (good realloc units became `memory-leak-on-failed-call-to-realloc` FPs); with renaming, batch and per-unit verdicts agree on all 78 units
  checked (20 sample + 6 probe + 52 stratified), with one rule label differing on 2 C++ `_73` bad units
  (`memory-never-freed` vs `memory-may-not-be-freed`, same verdict).

## CWE-401 verdict mapping (chosen on dev units only)

pred = 1 iff at least one mapped finding lies in the unit's own files; pred = null (invalid) for
compile_error/timeout/error. Unit counts on dev (330 bad / 330 good) from `scratch/rule_table.py` and
`scratch/checker_table.py`:

| tool | counts as leak | dev bad / good units hit | not mapped (dev units hit, bad/good) |
|---|---|---|---|
| clang_sa | `unix.Malloc` and `cplusplus.NewDeleteLeaks` with message matching `\bleak\b` ("Potential leak of memory pointed to by …") | unix.Malloc 164/10, NewDeleteLeaks 56/4 | deadcode.DeadStores 102/46, core.StackAddressEscape 0/18; `unix.MismatchedDeallocator` never fired |
| cppcheck | `memleak`, `memleakOnRealloc`, `leakReturnValNotUsed`, `leakNoVarFunctionCall` | memleak 22/4, memleakOnRealloc 24/0, the other two 0/0 | allocaCalled 0/90, passedByValue 34/24, dangerousTypeCast 9/6, danglingLifetime 0/7; `mismatchAllocDealloc` never fired |
| codeql | `cpp/memory-never-freed`, `cpp/memory-may-not-be-freed`, `cpp/memory-leak-on-failed-call-to-realloc` (only these three queries are run) | 196/0, 128/48, 18/0 | — |
| infer | `MEMORY_LEAK_C`, `MEMORY_LEAK_CPP` (the latter enabled with `--enable-issue-type`) | 96/3, 60/2 | USE_AFTER_FREE (24 units), PULSE_UNINITIALIZED_VALUE; `PULSE_RESOURCE_LEAK` never fired |

Decisions:
- Every leak rule is kept: on dev each mapped rule adds true positives and the union has the best macro-F1 of
  all rule subsets (clang 0.808 vs 0.718 unix.Malloc only; cppcheck 0.468; codeql 0.918 for all three, the same
  as never+may; infer 0.710 wrapper / 0.784 per_file).
- CodeQL `memory-may-not-be-freed` causes all 48 dev FPs (all on B2G good units) but also 128 TPs; dropping it
  lowers dev macro-F1 to 0.819, so it stays.
- Mismatched-deallocator checks (Clang `unix.MismatchedDeallocator`, Cppcheck `mismatchAllocDealloc`) are not
  mapped: they are CWE-762 rather than leaks, and neither fired on dev.
- DeadStores / StackAddressEscape / USE_AFTER_FREE etc. are not leak evidence. They stay in the raw logs and
  in `extra.other_checkers`.

## L3 evidence

`results/clang_sa/layer1/evidence.jsonl` has one row per unit (3,316), with `warnings: []` when nothing was
found. It contains the mapped leak warnings only:
`{checker, message, source_file, source_line, model_text_line, statement_text}`. `model_text_line` comes from the
unit's `line_map` (null if unmapped; all 1,309 warnings of `full_v2` are mapped), and `statement_text` is that
`model_text` line, stripped. Clang reports a leak where the last reference dies, so the line is often a closing
`}` or the statement after the leak. Frozen: `EVIDENCE_FROZEN` = `full_v2 00897f54…`.

## Final runs (layer1, all 3,316 units, all `status=ok`)

| tool | run | mode | wall | notes |
|---|---|---|---|---|
| clang_sa | `full_v2` | per_unit_c1 | 150 s | load 11–17 |
| cppcheck | `full_v2` | per_unit_c1 | 57 s | load 17–18 |
| grep_v0 | `full_v1` | per_unit_inprocess | 0.01 s | |
| codeql | `full_batch50_merged` = `full_batch50` + `full_batch50_rerun67` | batched, 50 units/db, -j 3 | 638 s + 16 s | `_67` (68 units) were compile errors before the typedef fix and were rerun |
| infer | `full_per_file_merged` = `dev_per_file` + `eval_per_file` | per_unit_c1, tu_mode per_file | 286 s + 1002 s | load 5–11 |

Earlier iterations kept for the record: `clang_sa/dev_v1` (no analyze-headers), `dev_v2`/`dev_v3` (same predictions
as `full_v2` on dev), `full_v1` (before the `_67` fix: 28 more `_67` bad units missed), `infer/full_per_unit_merged`
(wrapper mode).

### Per-unit cost (machine loaded: loadavg 7–22 from LineVul + data lane; to be re-measured when quiet)

| tool | per unit, c1 | batched (amortized) |
|---|---|---|
| clang_sa | median 0.034 s, p90 0.076 s | — |
| cppcheck | median 0.015 s, p90 0.024 s | — |
| codeql | median 23.7 s (20 sample units, c1); 15.4 s at -j 3 (52 units); old Tier-B 42.5 s | batch 50: median 0.55 s/unit (batch wall ≈ 26–30 s), whole layer 638 s at -j 3 |
| infer | median 0.29–0.38 s, p90 0.64–0.67 s (per_file) | batch 20: ≈ 0.16 s/unit (not needed) |

At c1, per-unit CodeQL would take about 22 h for 3,316 units, so the CodeQL baseline uses batched mode. Per-unit
Infer is cheap enough, so it runs per unit.

## Scores

End-to-end (invalid counted wrong; there were no invalid units), positive class = leak, 95% family-cluster
bootstrap CI (2000 resamples, seed 20261126). The api_subset (664 groups) lies entirely in eval, so
`eval_api` = eval ∩ api_subset (1,328 units). Full reports: `results/scores/`.

| tool | slice | n | macro-F1 [95% CI] | P_leak | R_leak | spec | MCC | acc | invalid | lat med / p90 (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| clang_sa | dev | 660 | 0.808 [0.754, 0.853] | 0.940 | 0.667 | 0.958 | 0.652 | 0.812 | 0 | 0.034 / 0.076 |
| codeql | dev | 660 | 0.918 [0.902, 0.933] | 0.871 | 0.982 | 0.855 | 0.843 | 0.918 | 0 | 0.549 / 0.616 |
| infer | dev | 660 | 0.784 [0.715, 0.843] | 0.924 | 0.630 | 0.948 | 0.611 | 0.789 | 0 | 0.375 / 0.638 |
| cppcheck | dev | 660 | 0.468 [0.414, 0.524] | 0.920 | 0.139 | 0.988 | 0.240 | 0.564 | 0 | 0.015 / 0.024 |
| grep_v0 | dev | 660 | 0.721 [0.689, 0.752] | 0.667 | 0.927 | 0.536 | 0.504 | 0.732 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | dev | 660 | clang-only right 34, codeql-only right 104 | chi2_continuity | p=4.26e-09 | Holm p=1.28e-08 | | | | |
|  McNemar clang_sa vs infer | dev | 660 | clang-only right 71, infer-only right 56 | chi2_continuity | p=0.214 | Holm p=0.214 | | | | |
|  McNemar clang_sa vs cppcheck | dev | 660 | clang-only right 174, cppcheck-only right 10 | chi2_continuity | p=2.91e-33 | Holm p=1.16e-32 | | | | |
|  McNemar clang_sa vs grep_v0 | dev | 660 | clang-only right 177, grep_v0-only right 124 | chi2_continuity | p=0.00272 | Holm p=0.00545 | | | | |
| clang_sa | eval | 2656 | 0.855 [0.806, 0.899] | 0.928 | 0.771 | 0.941 | 0.722 | 0.856 | 0 | 0.036 / 0.066 |
| codeql | eval | 2656 | 0.882 [0.866, 0.897] | 0.829 | 0.963 | 0.802 | 0.775 | 0.883 | 0 | 0.549 / 0.616 |
| infer | eval | 2656 | 0.815 [0.741, 0.874] | 0.939 | 0.681 | 0.956 | 0.662 | 0.818 | 0 | 0.293 / 0.669 |
| cppcheck | eval | 2656 | 0.493 [0.436, 0.553] | 0.897 | 0.171 | 0.980 | 0.258 | 0.576 | 0 | 0.015 / 0.024 |
| grep_v0 | eval | 2656 | 0.701 [0.685, 0.717] | 0.658 | 0.870 | 0.548 | 0.441 | 0.709 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | eval | 2656 | clang-only right 248, codeql-only right 319 | chi2_continuity | p=0.00329 | Holm p=0.00329 | | | | |
|  McNemar clang_sa vs infer | eval | 2656 | clang-only right 309, infer-only right 209 | chi2_continuity | p=1.36e-05 | Holm p=2.73e-05 | | | | |
|  McNemar clang_sa vs cppcheck | eval | 2656 | clang-only right 810, cppcheck-only right 66 | chi2_continuity | p=4.54e-139 | Holm p=1.82e-138 | | | | |
|  McNemar clang_sa vs grep_v0 | eval | 2656 | clang-only right 740, grep_v0-only right 350 | chi2_continuity | p=4.81e-32 | Holm p=1.44e-31 | | | | |
| clang_sa | eval_api | 1328 | 0.840 [0.784, 0.887] | 0.920 | 0.747 | 0.935 | 0.695 | 0.841 | 0 | 0.035 / 0.066 |
| codeql | eval_api | 1328 | 0.867 [0.844, 0.889] | 0.813 | 0.956 | 0.780 | 0.748 | 0.868 | 0 | 0.551 / 0.616 |
| infer | eval_api | 1328 | 0.811 [0.737, 0.875] | 0.932 | 0.679 | 0.950 | 0.654 | 0.815 | 0 | 0.292 / 0.678 |
| cppcheck | eval_api | 1328 | 0.488 [0.434, 0.548] | 0.894 | 0.166 | 0.980 | 0.252 | 0.573 | 0 | 0.015 / 0.025 |
| grep_v0 | eval_api | 1328 | 0.706 [0.685, 0.725] | 0.663 | 0.867 | 0.559 | 0.448 | 0.713 | 0 | 0.000 / 0.000 |
|  McNemar clang_sa vs codeql | eval_api | 1328 | clang-only right 138, codeql-only right 174 | chi2_continuity | p=0.0475 | Holm p=0.0836 | | | | |
|  McNemar clang_sa vs infer | eval_api | 1328 | clang-only right 157, infer-only right 122 | chi2_continuity | p=0.0418 | Holm p=0.0836 | | | | |
|  McNemar clang_sa vs cppcheck | eval_api | 1328 | clang-only right 390, cppcheck-only right 34 | chi2_continuity | p=1.32e-66 | Holm p=5.29e-66 | | | | |
|  McNemar clang_sa vs grep_v0 | eval_api | 1328 | clang-only right 360, grep_v0-only right 190 | chi2_continuity | p=5.75e-13 | Holm p=1.73e-12 | | | | |

Notes:
- McNemar is the paired test on per-unit correctness (exact binomial when there are ≤ 25 discordant pairs).
  It ignores family clustering, and the Holm adjustment here is across the comparisons within one slice only.
  These are exploratory, not the preregistered comparisons.
- Clang SA misses mostly C++ `new` (dev recall 0.44, eval 0.52) and flows 71–84 (container/virtual-call
  flows). Its FPs are on B2G good units. CodeQL has the highest recall (0.96–0.98) but low specificity on B2G
  good units (0.58–0.69), caused by `memory-may-not-be-freed`. Cppcheck is precise but finds almost only
  realloc-failure leaks. grep_v0 has specificity 0 on G2B good units by construction.
- Old Tier-B (140 units, different construction): Clang SA 0.888, CodeQL 0.817, Cppcheck 0.588.
