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
