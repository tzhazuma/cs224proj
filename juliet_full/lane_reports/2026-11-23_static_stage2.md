I finished every item in your follow-up. All 5 tools have results on layer3, placebo and original (3,316 units each, all ok), and robustness, SUMMARY and README are written; nothing is committed or staged. One problem turned up: CodeQL's batched mode adds 4 false positives on `_08` units (details under Problems).

**Your three questions:**
- **Infer latency:** already measured in the earlier latency sequence (`lat300_c1`, 300 units, quiet machine, under the shared lock), so I did not rerun it.
- **The `_08` CodeQL diagnostic (pid 3497482):** I had started it to explain why two units in the batched latency run disagreed with the full run. It was short, so I let it finish: 80 units, all ok, 350 s.
- **Robustness:** written for full eval, eval ∩ api_subset and eval ∩ nested25, as `static/results/scores/ROBUSTNESS.md` plus JSON.

**Scores on eval (2,656 units; macro-F1 with 95% CI; P, R, specificity are for the leak class):**

| tool | layer1 | layer3 | placebo | original |
|---|---|---|---|---|
| clang_sa | 0.855 [.806,.899] (P .928, R .771, spec .941) | 0.855 | 0.855 | 0.822 [.778,.862] (spec .873) |
| codeql | 0.882 [.866,.897] (P .829, R .963, spec .802) | 0.766 [.750,.785] (P .787, R .730) | 0.882 | 0.785 [.765,.806] (spec .619) |
| infer | 0.815 [.741,.874] (P .939, R .681) | 0.815 | 0.815 | 0.770 [.707,.819] |
| cppcheck | 0.493 [.436,.553] (P .897, R .171) | 0.493 | 0.493 | 0.467 |
| grep_v0 | 0.701 [.685,.717] | 0.333 (predicts no-leak everywhere) | 0.701 | 0.935 [.906,.955] |

McNemar on layer1 eval: Clang SA vs CodeQL p = .0033, vs Infer p = 1.4e-5.

**Robustness on eval (layer1 → layer3; "adjusted" subtracts the placebo change; flip = verdict changed):**
- **Clang SA, Infer, Cppcheck:** not one verdict changes, on layer3 or placebo, for any of the 3,316 units.
- **CodeQL:** macro-F1 Δ −0.116 [−0.132, −0.097], leak-class F1 Δ −0.134. 23.3% of bad units flip, all of them lost detections (309 of 1,279). Good units: 0 flips.
- **grep_v0:** macro-F1 Δ −0.368 [−0.383, −0.352], leak-class F1 Δ −0.749. Bad units flip 0.870 (lost); good units flip 0.452 (all wrong → right).
- **Placebo:** no tool changes any verdict, so the adjusted Δ equals the raw Δ.
- **Paired slices:** api_subset gives CodeQL −0.109, grep −0.373; nested25 gives CodeQL −0.114 [−.144, −.083], grep −0.384.

**Original vs layer1 (eval macro-F1 Δ, then the share of good units whose verdict flips):**

| tool | Δ macro-F1 | good units flipped |
|---|---|---|
| clang_sa | −0.033 [−.039, −.027] | .067 |
| codeql | −0.097 [−.111, −.084] | .191 |
| infer | −0.045 | .093 |
| cppcheck | −0.025 | .072 |
| grep_v0 | +0.233 | .452 |

Bad units never flip.

**Which tools prune infeasible branches:** Clang SA and Infer treat literal, `static const` and enum guards as constants and prune them, also across function calls. CodeQL resolves guards inside one function, but a guarded free inside a callee silences it; its "memory never freed" rule only checks whether any free exists.

**Latency (layer1, latency300 = 300 units, concurrency 1):** I took the lock first (661 s wait), then waited until load1 < 2.5 for 60 s.

| tool | how measured | median | p90 | load1 before → after |
|---|---|---|---|---|
| clang_sa | per unit | 0.018 s | 0.022 s | 1.99 → 1.99 |
| cppcheck | per unit | 0.008 s | 0.010 s | 1.99 → 1.99 |
| grep_v0 | in-process | < 1 ms | < 1 ms | 1.99 → 1.99 |
| infer | per unit | 0.278 s | 0.647 s | 1.99 → 2.68 |
| codeql | per unit, 20 units (database creation + queries) | 7.36 s | 7.91 s | 2.68 → 4.02 |
| codeql | batched, 50 per database, amortized | 0.318 s | 0.334 s | 4.02 → 4.95 |

The bulk-run wall times were measured under load 5–23, so they are not latency figures.

**Problems:**
- **CodeQL batching false positives:** `_08` units each define helpers `staticReturnsTrue`/`staticReturnsFalse`. They are not renamed per unit, so one 50-unit database holds many copies, CodeQL cannot resolve the guard, and "may not be freed" fires. A per-unit run shows exactly 4 eval good units affected. They appear on layer1, layer3 and placebo, not on original. The cost is about −0.003 specificity and about −0.002 macro-F1, and the layer-3 deltas are unaffected.
- **Not corrected:** the configuration is frozen, so I did not fix this. The fix would be to rename every non-`main` function per unit. Four of the five "original goods predicted no-leak" exceptions I reported earlier are this artifact.
- **Batch composition:** `int64_t_calloc_74__bad` is detected in the full batched run and per unit, but missed in the latency batch run.
- **Latency script bug:** my first latency attempt crashed in `lat300.py` after the Clang run (NameError). I fixed it and reran the whole sequence under the lock; the first log is kept as `lat300_attempt1.log`.
- **Load during CodeQL timing:** load rose to 4–5. CodeQL runs with `--threads=1`, but its JVM still uses extra threads; I can't rule out other processes.

Changed files: `juliet_full/static/README.md`, `juliet_full/static/results/scores/` (`SUMMARY.md`, `ROBUSTNESS.md`, `ROBUSTNESS.json`, the per-tool JSONs, `layer3/`, `placebo/`, `original/`, `robustness/`), the new result directories under `juliet_full/static/results/<tool>/`, `juliet_full/analysis/robustness.py` (new) and these scripts: `static/scratch/score_layers.py`, `lat300.py`, `make_guard_probes.py`, `stage2_runs.sh`. Clang evidence files (frozen layer1/layer3/placebo) still match their recorded checksums.

Validation: both self-tests pass (`score.py`, `robustness.py`). All 15 bulk runs and all 6 latency runs finished with every unit ok. Every latency run predicts the same as its full run, except the 2 CodeQL batch units above.

Open risks/questions: the 4 batch-induced CodeQL false positives remain in the layer1, layer3 and placebo CodeQL runs.

Recommended next step: rerun Clang SA and CodeQL latency once the machine is fully idle if exact CodeQL numbers matter. Batched CodeQL with full function renaming could be a fixed rerun later, outside the frozen comparison.