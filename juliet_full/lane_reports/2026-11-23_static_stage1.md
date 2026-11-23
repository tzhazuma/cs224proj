I finished all five priorities: the mapping is fixed on dev, and every tool has a full 3,316-unit layer1 run, all `status=ok`. The Clang SA evidence is frozen for L3: `static/results/clang_sa/layer1/EVIDENCE_FROZEN` holds `full_v2 00897f5445fbc1085cedac05f549886ccbdf9e3f3d5e1737bc78f9196890eec5`. That run is also the Clang SA baseline I report.

Changed files: `juliet_full/static/run_static.py`, `juliet_full/static/merge_runs.py`, `juliet_full/static/README.md`, `juliet_full/analysis/score.py`, results under `static/results/`, scratch helpers.

**Tool versions** (all work): clang 23.1.6 with your `clang.cfg` (gcc 13 dir), recorded in meta; Cppcheck 2.22.0; CodeQL 2.27.5 with cpp-queries 1.10.1; Infer v1.3.0, which needs `--Xclang --gcc-install-dir=.../13` or C++ fails on `'new' file not found`. souffle and valgrind are installed but this lane doesn't use them.

**Checker mapping** (dev only; bad/good units hit):
- **clang_sa:** `unix.Malloc` 164/10 and `cplusplus.NewDeleteLeaks` 56/4, "leak" messages only.
- **cppcheck:** `memleak` 22/4, `memleakOnRealloc` 24/0; `leakReturnValNotUsed` and `leakNoVarFunctionCall` are mapped but never fired.
- **codeql:** `memory-never-freed` 196/0, `memory-may-not-be-freed` 128/48 (all 48 FPs are B2G good units, but dropping it lowers dev macro-F1 from 0.918 to 0.819), realloc query 18/0.
- **infer:** `MEMORY_LEAK_C` 96/3, `MEMORY_LEAK_CPP` 60/2.
- **Not mapped:** the mismatched-deallocator checks (a different weakness, CWE-762, and zero dev hits), DeadStores, StackAddressEscape, USE_AFTER_FREE.

**Runner fixes that changed results** (all in `run_static.py`):
- **Clang on multi-file units:** it now runs with `-analyzer-opt-analyze-headers`. Without it, units whose sources are combined into one file got only syntax checks, and dev recall on flows 51–84 was 0.
- **Files that couldn't be combined:** headers without include guards (`_82`–`_84`) and a struct repeated in each file (`_67`) are now handled on a copy with line numbers unchanged. The `_67` fix found 28 more eval bad units.
- **Infer:** it compiles each source file separately, because it skips functions in included files. Dev macro-F1 went from 0.710 to 0.784.
- **CodeQL batched mode:** each unit's `sym_N` names are made unique per batch, because CodeQL merges same-named functions across units. Without this, 5 of 20 sample units changed verdict. With it, batched and per-unit verdicts agree on all 78 units checked.

**Final runs and timing** (load 5–22, so latency needs re-measuring):

| tool | run | mode | per-unit median | full layer wall |
|---|---|---|---|---|
| clang_sa | `full_v2` | per unit, 1 at a time | 0.034 s (p90 0.076) | 150 s |
| cppcheck | `full_v2` | per unit, 1 at a time | 0.015 s | 57 s |
| grep_v0 | `full_v1` | in-process | ~0 s | 0.01 s |
| codeql | `full_batch50_merged` | batched, 50 units per database, `-j 3` | 0.55 s amortized | 638 s |
| infer | `full_per_file_merged` | per unit, 1 at a time | 0.29–0.38 s | 286 s + 1002 s |

Per-unit CodeQL is 23.7 s per unit (about 22 h for all units), so its baseline is batched. Infer is cheap enough per unit, so no batch was needed.

**Scores** (macro-F1 with 95% family-cluster bootstrap CI; no invalid units; `api_subset` is entirely in eval):

| tool | dev (660) | eval (2,656) | eval ∩ api_subset (1,328) |
|---|---|---|---|
| clang_sa | 0.808 [.754, .853] | 0.855 [.806, .899] (P .928, R .771) | 0.840 |
| codeql | 0.918 [.902, .933] | 0.882 [.866, .897] (R .963, spec .802) | 0.867 |
| infer | 0.784 | 0.815 [.741, .874] | 0.811 |
| grep_v0 | 0.721 | 0.701 | 0.706 |
| cppcheck | 0.468 | 0.493 | 0.488 |

On eval ∩ api_subset, the McNemar tests of Clang SA against CodeQL (p 0.048) and against Infer (p 0.042) both become p 0.084 after the Holm correction. Full reports are in `static/results/scores/` (`SUMMARY.md` plus one JSON per tool and slice).

**Validation:** `analysis/score.py --self-test` passes; it checks synthetic confusions, invalid/missing handling, CIs, latency, McNemar and Holm, and its binomial value matches scipy (0.109375). All three scripts compile. Full dev runs reproduce the earlier dev runs' predictions exactly. Evidence has 3,316 rows, and all 1,309 warnings map to a `model_text` line. Nothing is staged; HEAD is now 88b6067 because other lanes have committed.

**Open risks:**
- My McNemar tests ignore family clustering, and the Holm correction is per slice, so treat them as exploratory.
- The two partial reruns (CodeQL on `_67`, the Infer eval half) were merged by `unit_id` with `merge_runs.py`, so those two runs mix script versions; each meta records the sources.
- Infer only flags compile errors in the unit's own files, not in system headers.
- `layer1.jsonl` was rewritten at 10:41 with only the verify field filled, so the units sha in some metas differs; `changed_units.json` is empty.
- Running `clang_sa` again on layer1 without `--no-evidence` would merge into the frozen `evidence.jsonl`.

**Recommended next step:** re-measure clang_sa, cppcheck and infer latency at concurrency 1 (`--no-evidence`) on the `latency300` subset when the machine is quiet. The main comparisons belong on eval ∩ api_subset.