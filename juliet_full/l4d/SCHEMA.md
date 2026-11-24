# L4-D data formats (lane l4d-data)

Contract: `README.md` sections 1–3. Everything below is produced by the scripts in this directory; `<layer>` is
`layer1_sample`, `layer1`, `layer3`, `placebo` or `original` (input `../data/build/<layer>.jsonl`).

```
.venv/bin/python gold.py --layer <layer> --jobs 8      # build/gold_<layer>.jsonl (instrumented copies in /tmp)
.venv/bin/python questions.py --layer <layer>          # build/sites_, questions_, qcounts_<layer>.json(l)
.venv/bin/python oracle.py --layer <layer>             # build/oracle_<layer>.json, build/oracle_pred_<layer>.jsonl
.venv/bin/python derive.py --questions Q --answers A --tau 0.5 --method M --model X --out P [--souffle]
.venv/bin/python score_facts.py --answers A [A ...] --questions Q [Q ...] [--tau 0.5] [--out S.json]
python3 stats.py --layer <layer>                       # build/<layer>_stats.json (per-unit counts, label balance)
.venv/bin/python tests/test_l4d.py                     # self-checks (template hash, AUROC, Python == Souffle, masking)
```

`.venv` holds tree-sitter 0.27, tree-sitter-c 0.24.2, tree-sitter-cpp 0.23.4 (parser only).

## Sites — `build/sites_<layer>.jsonl`, one row per unit

```json
{"unit_id": "...", "layer": "layer1", "parse_errors": 0,
 "sites": [{"site_id": "s00", "kind": "alloc", "line": 9, "end_line": 9, "span": [94, 135], "func": "sym_0",
            "text": "data = (char *)calloc(100, sizeof(char));", "var": "data", "callee": "calloc",
            "guard_first": null}],
 "guards": [{"line": 10, "kind": "if", "text": "(data == NULL)", "func": "sym_0"}]}
```

- Contract fields: `site_id` (`s00`, `s01`, … in source order), `kind`, `line` (1-based `model_text` line of the
  statement start), `func` (enclosing function, `Class::method` for methods), `text` (statement text, whitespace
  collapsed), `var` (assigned / released variable or member expression, else null).
- Extra fields: `end_line`, `span` (byte offsets of the statement in `model_text`, used for masking), `callee`
  (`malloc`, `calloc`, `strdup`, `wcsdup`, `strndup`, `ALLOCA`, `alloca`, `_alloca`, `aligned_alloc`, `valloc`,
  `realloc`, `new`, `new[]`, `free`, `delete`, `delete[]`, or the called function of a `stmt`), `guard_first` (`if`,
  `else`, `for`, `while`, `do`, `case` (also `default:`), `catch` when the statement is the first statement of such a
  block, else null).
  `src` (realloc only): the variable passed as the old block.
- `kind` priority when a statement matches several: `realloc` > `alloc` > `release` > `stmt`.
  - `alloc`: statement containing a call of an allocator above or a `new` expression (incl. ALLOCA/alloca — the heap
    question decides them).
  - `release`: `free(...)`, `delete`, `delete[]` statement.
  - `realloc`: statement with a `realloc(...)` call. **Deviation:** the contract lists "a realloc that consumes its
    input" under `release` and also has a `realloc` kind; here a realloc is one site of kind `realloc` that plays both
    roles: it is an allocation (rel's `a`; `heap_block(r) :- realloc(r)`, so no heap question is asked for it) and a
    release (rel's `f`, it frees its input on success). One site per statement keeps exec questions unique.
  - `stmt`: every other simple statement (expression statement, declaration with initializer, `return`) that is the
    first statement of an `if`/`else`/loop/`case`/`default`/`catch` block (descending into nested plain `{}` blocks),
    or any call statement. Empty statements `;` and everything in `main` (the fixed driver) are excluded.
- `guards`: every `if`/`else`/`while`/`for`/`do`/`switch`/`case`/`catch` with its line and condition text (lexical,
  for reference).
- Parser: tree-sitter (C for `language == "c"`, C++ otherwise) over `model_text`; no constant evaluation.
  `parse_errors` counts ERROR/MISSING nodes (0 on all layers built so far).

## Questions — `build/questions_<layer>.jsonl`, one row per question

```json
{"qid": "layer1/<unit_id>/rel/s05+s00", "unit_id": "...", "layer": "layer1", "set": "dev", "fold": null,
 "qtype": "rel", "site_ids": ["s05", "s00"], "lines": [29, 15], "site_kinds": ["release", "alloc"],
 "state": " 1| // ---- part 1 ----\n 2| ...", "question": "Does the release at line 29 (...) ...",
 "gold": 1, "gold_source": "trace"}
```

- `qid` = `<layer>/<unit_id>/<qtype>/<site_ids joined by +>` (layer1_sample rows use layer `layer1`, so their qids
  equal the layer1 qids).
- `lines` (contract "line(s)") parallels `site_ids`; for `rel` the order is `[f, a]`.
- Asked: `heap` for every `alloc` site; `exec_any` and `exec_all` for every site; `rel` for every ordered pair
  (f, a), f ∈ release ∪ realloc, a ∈ alloc ∪ realloc, f ≠ a; `realloc_safe` for every `realloc` site.
- `state`: `model_text` numbered with `templates.NUMBERING` (`{n:>width}| line`, trailing spaces stripped). For
  `exec_any`/`exec_all` the target statement span (all its lines) is replaced by `__TARGET__();` on its first line and
  empty lines for the rest, so line numbers are unchanged; same masking for every site kind and layer. The question
  then refers only to the line number. Other qtypes show the unmasked code and quote the site text (cut at 120 chars).
- Templates: `templates.py`, `TEMPLATE_SHA256 = 316429b266c0258383724c8c9129e2ea17946a9013d72cb61b267261ef827516`
  (sha256 of the canonical JSON of templates, marker, numbering, code_max; `python3 templates.py` prints it).
- `gold` ∈ {1, 0, null}, `gold_source`:
  - exec: `gcov8` (gcc `--coverage -O0`, 8 runs with `time()` → 1..8 so variant-12 `rand()` covers all branch
    combinations; any = ≥1 run, all = every run) or `gcov8:no_code` (no line record: gcc emitted no code for the
    statement, e.g. the `default:` of `switch(6)` or an unused inline method → never executes, gold 0).
  - heap: `trace` (site executed: 1 iff a traced allocation event came from it) or `name` (never executed: 0 for
    ALLOCA/alloca/_alloca, else 1).
  - rel: `trace` (1 iff, in some run, a release event at f freed a block allocated at a) or `not_executed` (gold
    null: f or a never executes, so the fact cannot be observed; derive treats null as 0 in gold mode — harmless for
    the rules because such a pair can never make a block freed/leaked).
  - realloc_safe: `inject` (for every distinct realloc call in the base runs, rerun with that call failing; 1 iff the
    old block is released later in every injected run), `inject:no_block` (the realloc input is always NULL: nothing
    can leak, gold 1), `not_executed` (null).
- `build/qcounts_<layer>.json`: template sha, label counts per `set/qtype`, `per_unit` question counts per qtype.
- `build/<layer>_stats.json`: `per_unit_questions[all|dev|eval][total|qtype]` = {n_units, sum, mean, min, p50, p90,
  p99, max}; `label_balance["set/qtype"]` = {yes, no, null, n, frac_yes}.
- Training must drop questions with `gold` null (rel of never-executed pairs; many on layer3 dead frees).

## Gold — `build/gold_<layer>.jsonl`, one row per unit (internal; questions carry the labels)

`{unit_id, layer, status, note, n_sites, sites: {sid: {exec_runs, exec_any, exec_all, exec_source, heap,
heap_source, realloc_safe, realloc_safe_source}}, rel: {"f|a": 0|1|null}, seeds, n_inject_runs, trace_alloc_lines,
trace_release_lines, untracked_release_lines, trace_alloc_missed, seconds}`.
Method: the unit's sources are copied to /tmp with every site statement moved onto its own lines (newlines inserted
before/after when a line is shared, so gcov/addr2line lines identify sites), compiled with the unit's compiler,
standard, include dirs and defines plus `--coverage -O0 -g -no-pie`, linked with `gold/l4d_trace.c`
(`-Wl,--wrap=` malloc, calloc, realloc, free, strdup, wcsdup, and `time`, which returns the seed `L4D_TIME`) and for C++ `gold/l4d_trace_new.cpp`
(global `operator new/new[]/delete/delete[]`). Each event records `backtrace()` addresses; addr2line maps them to
the copied source and on to `model_text` lines through `line_map`. An event belongs to the innermost frame that is a
site of the needed role (allocator call for A, release for F, realloc for R), which handles virtual deleting
destructors and wrapper functions. Events from the gcov runtime are ignored. `free` of a pointer that was never
allocated (variant-12 bad frees an ALLOCA buffer) is logged as untracked (`U`) and not passed to the real free.
`trace_alloc_missed` = traced allocation lines that are not a parser `alloc`/`realloc` site (parser recall).

## Oracle — `build/oracle_<layer>.json`

`{layer, sets: {dev|eval: {f1_1, f1_0, macro_f1, n, errors}}, failures: [{unit_id, set, label, pred, variant,
flow_category, mechanism, leaks}], parser_recall: {trace_alloc_lines, missed, recall, missed_units},
failure_summary}` (label/pred: 1 = leak; the unit truth is the `truth` field of the data record).
`build/oracle_pred_<layer>.jsonl`: the derive output rows of the oracle run.

## Fact scores — `score_facts.py --out`

`{tau, answers, questions, n_answers_unknown_qid, rows: [{model, layer, set, qtype (or "all"), n, n_yes,
n_gold_null, n_unanswered, accuracy, auroc, majority_baseline}]}`; also printed as a table.

## Derive output — standard prediction rows (`../README.md` §4)

`{unit_id, method, strategy: "L4D", model, layer, pred, score, latency_s, status, extra: {tau, n_questions,
n_missing, leaks: [[site_id, "never_freed"|"realloc_fail"]], derive_s}}`.
`layer` uses the §4 names (`layer3` → `stress`). Rules: `l4d.dl` = contract v1, unchanged. Known ceiling of v1
with gold facts: variant-12 goods whose block is freed by complementary frees in both branches of a random `if`
(each exec_all = 0) are derived as leaks (path-insensitivity of the rule set; see REPORT_stage1.md). `latency_s` is the derive time only; the model time must be added by
the caller. A unit with any unanswered question: `pred` null, `status` `invalid`. `--gold` = oracle mode
(method `l4d_oracle`, model `gold`).
