# juliet_full/data — CWE-401 units (data lane)

Builds the layer-1 debiased units and the original-Juliet control for the 1,658 groups of
`juliet/full_split_v1.json`, verifies the labels with ASan/LSan (+ clang 23, valgrind sample),
draws the evaluation subsets and runs the shortcut probes.

## Rebuild

```sh
cd juliet_full/data
python3 build_units.py                 # ~7 s: build/programs/, programs_original/, layer1*.jsonl, original.jsonl, good_entries.json
python3 verify_labels.py --jobs 8      # ~15 min: build/verify_results.jsonl + verify_report.md (use nohup)
python3 build_units.py                 # merge verify_results.jsonl into the verify field of every record
python3 subsets.py                     # build/subsets.json
.venv/bin/python probes.py             # build/probes.json + probes_report.md (needs scikit-learn, tokenizers)
python3 check_build.py                 # validation, recompiles 20 random units; exit 0 = all checks pass
cd build && sha256sum -c SHA256SUMS
```

`.venv` is created with `uv venv .venv && uv pip install --python .venv scikit-learn numpy tokenizers`
(the system python's sklearn is broken). `build_units.py` is deterministic (seed 20261123): two runs give
the same SHA-256 for every jsonl. The verify results are not fully deterministic (variant 12 depends on
`time(NULL)`), so `verify_results.jsonl` is the frozen record that the build merges.
`verify_labels.py --report-only` rewrites the report from the results file.

## Files (build/)

| file | content |
|---|---|
| layer1.jsonl | 3,316 units, 1 bad + 1 good per group, schema of `juliet_full/README.md` section 3 |
| layer1_sample.jsonl | 48 dev units (24 groups, every flow category and mechanism present in dev); records identical to layer1 |
| original.jsonl | 3,316 control units: bad = the layer-1 bad record; good = whole original OMITBAD program, good_kind `orig` |
| good_entries.json | the good entry chosen per group (kind, original function name) |
| subsets.json | api_subset 664 ⊃ nested25 332 ⊃ repeat100 100; latency300 150 ⊂ api_subset (eval only, stratified flow_category × mechanism) |
| verify_results.jsonl, verify_report.md | label verification |
| probes.json, probes_report.md | shortcut probes original vs layer 1 |
| changed_units.json | units changed after the 10:23 release (none; only the verify field was filled) |
| SHA256SUMS | hashes of the released files |
| programs/<unit_id>/, programs_original/<group_id>__good/ | compiled sources (git-ignored) |

## Construction (layer 1)

- bad: OMITGOOD view of the group; the bad entry plus every helper, file, class and global it reaches.
- good: one good entry (G2B or B2G) plus what it reaches; the `..._good()` wrapper is dropped. The kind is
  stratified per (set, flow_category, mechanism), shuffled with seed 20261123, half G2B / half B2G (odd
  stratum: seeded coin flip). Numbered entries (goodG2B1/goodG2B2...) count as one kind; the number is
  picked by `Random("20261123:<group_id>")`.
- `static` is removed from every function definition and prototype in both labels; file-scope variables
  keep `static`. The entry is renamed `sym_0` (C++: in namespace `sym_1`), Juliet identifiers become
  `sym_N`, comments are removed, `OMITBAD`/`OMITGOOD`/`INCLUDEMAIN` conditionals are resolved.
- Driver appended to the entry file, identical in both labels:
  `int main(int argc, char * argv[]) { srand( (unsigned)time(NULL) ); sym_0(); return 0; }`.
- model_text = the compiled files, `#include "std_testcase.h"` dropped, the local header `unit.h` inlined
  once, files separated by `// ---- part i ----`. `line_map` entries are `[source_file, source_line,
  model_text_line]` (1-based). Leakage test: no identifier, comment or string in model_text matches
  `bad|good|g2b|b2g|cwe|leak|omit|flaw|fix` (case-insensitive) — passes on all 6,632 records (not even
  as a raw substring).

Schema notes beyond the contract: `good_entry` (original Juliet name of the good entry, null for bad);
`good_kind` is `G2B`, `B2G`, `other` or (original.jsonl) `orig`. `other` = 110 groups that have no
G2B/B2G goods (realloc_fail 108 with good1/good2, destructor 2 with good1); their good is `good1`/`good2`.
Entry functions keep Juliet's `void f()` signature (empty parameter list) in both labels.

## Verification

gcc/g++ 13 `-fsanitize=address -g -O0`, `ASAN_OPTIONS=detect_leaks=1`, stdin closed, 10 s timeout;
clang/clang++ 23 compile+link; valgrind 3.28 on 200 stratified units. Labels are never changed;
`verify.asan_leak` and `verify.note` record mismatches.

**`LSAN_OPTIONS=use_stacks=0`** is the primary setting. With default options LSan treats stack contents
as roots, and at `-O0` the pointer of the leaked buffer often survives in a dead stack slot of the frame
that already returned (e.g. `char_calloc_31` bad: valgrind reports the leak, default LSan does not).
175 layer-1 bad units leak only under `use_stacks=0`; no good unit changes. Both results are kept
(`note: default LSan options ... asan_leak=False`).

Known LSan blind spots (label bad, `asan_leak=false`, recorded as `mismatch ... [known blind spot: ...]`):

- realloc_fail (108): the leak happens only when `realloc` fails.
- variants 45 and 68 (68): the buffer is still reachable from a global when the program exits.
- variant 12 (random branches via `rand()` seeded by `time(NULL)`): up to 6 runs ≥ 1 s apart, leak if any
  run leaks; 8 bad units never leaked. Juliet's variant-12 bad function also frees an `ALLOCA` buffer on
  one of its four paths (`ALLOCA` + `free(data)`), which ASan aborts as
  `attempting free on address which was not malloc()-ed` (16 bad units, identical in original). This is
  in the raw Juliet code, not the construction; no good unit has any ASan error.

## Layer 3 (stress) and placebo (PLAN 2.5)

Both are derived from layer 1 for all 3,316 units (same unit_id, label and split fields) by `stress.py`;
records add `transform` = {kind, guards [{name, value, op, const, truth}], inserted [{line, guard_line,
file, file_line, stmt, guard, role, reachable: false}], wrapped_real_frees [{line, guard_line, file,
file_line, stmt, guard}], seed, guard_values, pointer, dead_stmt_form, n_dead, n_flaw_sites,
extra_position}. `line`/`guard_line` are model_text lines of the guarded statement / its `if(` line.

```sh
python3 stress.py build                       # ~10 s: build/layer3.jsonl, placebo.jsonl, programs_layer3/, programs_placebo/
nohup python3 verify_layer3.py --jobs 6 &     # ~11 min: build/verify_layer3.jsonl + verify_layer3_report.md
python3 stress.py build                       # merge the verify results into the records
python3 check_layer3.py                       # structural checks; exit 0 = pass
.venv/bin/python probes_layer3.py             # build/probes_layer3.json + probes_layer3_report.md
python3 stress.py demo --unit-id CWE401_Memory_Leak__char_malloc_84__good --kind stress   # diff vs layer 1
```

Stress construction (seed 20261123):

- every real `free(x)` / `delete x` / `delete[] x` of both labels is wrapped in an always-true guard;
- every flaw site (layer-1 `;` where the good sink frees) is replaced by a dead free of the sink pointer
  under an always-false guard; the dead form matches the allocation (C `free`, `new` → `delete`,
  `new[]` → `delete[]`); empty destructors (destructor_01 bad) get the dead free inside;
- extra dead frees: `e ∈ {0,1}` drawn per group (`Random("20261123:<group_id>")`), placed before/after the
  same anchor in bad and good (the flaw site in bad, the real free of the same pointer in good; realloc:
  right after `x = realloc(...)`, freeing the new pointer: bad `data`, good `tmpData`); realloc_fail and
  virtual_destructor (no flaw site) get one more in both labels. Result: free-statement count and guard
  count are equal within every pair (distribution 1:720, 2:838, 3:98, 4:2 groups);
- guards: `static const int sym_N = V;` after the leading `#include` lines of the file that uses them,
  `N` drawn from the unused names in 10..99, `V ∈ {4,5}`, comparison drawn from the six PLAN forms
  (`==5 >4 !=4 !=5 <5 ==4`); for a form, the value that gives the needed truth is used, so every form
  occurs as true and as false guard. No globals, no external functions.

Placebo: identical insertion points, guards and counts, but the dead statement is
`printLine("<Processing|Value checked|Status ok|Step complete>");` and real frees are not wrapped.

Deviations from PLAN 2.5 (all decided on dev only, see `probes_layer3.py --dev-check`, leave-variant-out
BoW AUROC on dev B2G): (1) PLAN form with fixed `k = 5` → 0.989 (true guards are exactly `==5 >4 !=4`, so
the form tells which free is real); constants 4/5 with every form used both ways → 0.605; plus random
guard names instead of sequential `sym_N` → 0.572 (chosen). (2) G2B goods also have a flaw site (`;`),
which gets a dead free too, so G2B goods carry 1–2 dead frees and real-free-less G2B goods look like bad
units (needed for count matching). (3) realloc_fail/virtual_destructor: 1–2 dead frees in both labels.
(4) object `delete`s (e.g. `delete baseObject`) are wrapped like data frees.

Verification (`verify_layer3.py`, 6 jobs, LSAN `use_stacks=0`): gcc and clang 23 compile 3,316/3,316 in
both layers; all 3,236 non-variant-12 units per layer have the stage-1 verdict; goods 0 leaks.
Variant 12 (random branches): layer3 67/80, placebo 71/80 same verdict, varying between runs in both
directions as in stage 1. The only non-leak ASan error is Juliet's own variant-12 `ALLOCA` bad-free:
every occurrence (21 layer3, 15 placebo) was rerun and located at a real free/delete, never at an
inserted dead statement.

Probes (eval, `probes_layer3_report.md`), layer 3: format probes ≤ 0.525, grep v0 B2G 0.333, v1 0.333,
v2 0.498, BoW AUROC B2G 0.609 (all 0.810; G2B 0.986 because ALLOCA / stack buffers are intrinsic to G2B
goods) → PASS. Placebo: format probes PASS; grep and BoW stay at layer-1 level (0.70–0.99) by design.
`stress.py` is importable without side effects: `transform_unit(record, kind, seed, n_dead)` and
`transform_source(code, language, func=None, ...)` (best effort on any single C/C++ file, raises
`ValueError`). Both builds are deterministic (two runs, same SHA-256; lines added to SHA256SUMS).

## Dynamic reference line (stage 4)

Predictions in the contract format (`juliet_full/README.md` §4) under `results/<method>/<layer>/<run_id>.jsonl`
+ `.meta.json`; `full_v1` = all 3,316 units per layer (bulk, 6 jobs, latency not meaningful), `lat300_c1` =
latency300 subset of layer 1 at concurrency 1. Code: `dynamic_runs.py` (`bulk --jobs 6`, `latency --wait-quiet`;
resumable via `results/_work/<run_id>/rows.jsonl`), `dynamic/inject.c` (link-time hooks), `dynamic/latency.sh`
(`flock /tmp/cs224_latency.lock`, quiet check load1 < 2.5 for one minute only after the lock is held; meta records
lock wait, quiet wait, load before/after), `dynamic_report.py` → `results/dynamic_report.md`, `results/dynamic_scores.json`,
`results/scores/*.json` (score.py output, eval set, bootstrap 2000).

Methods (all gcc/g++ 13, `-O0 -g -fno-omit-frame-pointer`, stdin closed, timeout 10 s):
- `asan_lsan`: `-fsanitize=address`, `LSAN_OPTIONS=use_stacks=0`, one run; pred = 1 iff a leak report is
  attributed to the unit. Attribution: first stack frame with an absolute source path, skipping sanitizer frames,
  `inject.c` and glibc frames (relative paths such as `wcsmbs/wcsdup.c`); it must lie in the unit's program dir.
  Non-leak ASan errors (Juliet's variant-12 ALLOCA bad-free) go to `extra.asan_error`, pred from leaks only.
- `asan_lsan_default`: same with default LSan options (stale `-O0` stack slots hide ~10% of bad leaks).
- `valgrind`: plain build, `--leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=definite,indirect`;
  pred = 1 iff definitely + indirectly lost > 0; still-reachable bytes (total and first-frame-in-unit) in `extra`.
- `dynamic_enhanced`: ASan build linked with `inject.c` (`-Wl,--wrap=realloc -Wl,--wrap=time`); 3 configs × 8
  seeds = 24 executions, pred = OR: `base` (as asan_lsan), `globals` (`use_globals=0`: memory still reachable only
  from globals at exit counts as leak; stdio buffers are dropped by the attribution rule because their first
  absolute frame is `io.c`), `realloc` (`DYNENH_REALLOC_FAIL=1`: the first `realloc` of a non-NULL pointer returns
  NULL). Seeds: `time()` returns 1..8 (`DYNENH_TIME`), which covers all four branch combinations of variant 12's
  two `rand()%2` decisions under glibc `srand`. FP risk checked on all goods of layer1/stress/placebo: 0 flagged;
  the realloc_fail goods were injected in 108/108 and show no leak under injection; goods never leave unit memory
  reachable from globals.

Bulk was run once (11,606 unit jobs) and the 336 jobs of family `strdup_wchar_t` were rerun after the attribution
fix (wcsdup allocates inside glibc; the first pass took `wcsmbs/wcsdup.c` as leak site and missed all 48 bad units).
No other job had non-unit leak blocks outside `use_globals=0` runs. Valgrind's still-reachable attribution keeps
the first non-`vg_replace` frame, so the 4 wcsdup units of variants 45/68 count as non-unit there (extra only).

Eval scores (2,656 units, P/R/macro-F1): asan_lsan layer1 1.000/0.891/0.945, original same, stress 0.897 R / 0.948,
placebo 0.895 / 0.947; asan_lsan_default 1.000/0.786/0.892; valgrind 1.000/0.892/0.946; dynamic_enhanced
1.000/1.000/1.000 on layer1, stress and placebo. Misses of asan_lsan/valgrind: realloc_fail (84 eval), variants
45/68 (global), variant-12 random branch. Latency c1 (median / p90 s, compile included): asan_lsan 0.134/0.209,
valgrind 0.407/0.548, dynamic_enhanced 1.194/2.203 (load1 1.7 → 2.4). Details in `results/dynamic_report.md`.
