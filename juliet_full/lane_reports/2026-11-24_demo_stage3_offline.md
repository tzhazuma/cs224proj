# Demo lane, stage 3: L4-D row

Request (parent, 2026-11-24 07:50 PST): add an L4-D row to the live demo, keep the old LoRA row as the contrast,
build and test offline, then (once `:8004` is up, marker `184-toast:~/disk4/cs224/L4D_8004_UP`) check, live dry
run and a new backup recording `stage_final_v2`. Write boundary `presentation/demo/`; no git.

## Status

- **Offline part: done.** L4-D row implemented, tests pass, the offline stage run shows the intended contrast from
  the stored answers.
- **Live part: pending `:8004`.** At the time of writing (2026-11-24 07:54 PST) the marker does not exist. A
  temporary `:8004` was answering `/health` on 184-toast (GPU 0, used by the L4-D lane for DeadFree latency runs
  under `/tmp/cs224_latency.lock`), so the demo did **not** call `/l4d` and did not run `./check.sh` against it, to
  keep those latency numbers clean. `:8003`, `:8002`, `:8001` were not listening at 07:38 PST (the stage-2 FT
  endpoint was down at that moment).
- See "Live run" at the end for the result of the live dry run and the recording, once done.

## What the row does

Label **"L4-D (ours, FT 4B)"**; the old LoRA rows are now **"FT 4B, unit labels (L1)"** / **"(L3)"** (summary
names "FT 4B unit labels", "L4-D").

Per unit (`demo_methods.run_l4d(ctx, unit) -> Result`):

1. **Questions.** Built live with the l4d lane's builder (`juliet_full/l4d/parse_sites.py` +
   `juliet_full/l4d/questions.py make_questions`, tree-sitter in `.venv`, 0.2–0.5 ms). For Juliet units whose code
   is a stored unit (layer 1 for the clean units; layer 3 for the attacked unit, which equals the stored DeadFree
   unit when `--attack-n-dead` is 0, the default) the live questions are compared with
   `juliet_full/l4d/build/questions_<layer>.jsonl` (outside the timed path); on a mismatch the stored ones are
   used. `--file`: built live, fold = `--ft-fold`; without tree-sitter the row says `n/a for --file`.
2. **Prune** (`juliet_full/l4d_ft/prune.py prune`): only the questions the rules read ("asked k of n").
3. **Ask** `POST :8004/l4d {"fold": k, "questions": [{"qid","state","question"}]}`, k = the unit's held-out fold,
   one request, under a lock, 10 s timeout; `/health` probed once per run with a 1 s timeout.
4. **Derive** (`prune.verdict` → `juliet_full/l4d/derive.py evaluate_unit`, p_yes ≥ τ of the response, i.e. the
   fold's frozen τ): verdict, leaked allocation site and a reason read off the facts: `runs, never freed`,
   `<release> may not run` (rel yes, exec_all no), `lost if realloc fails`, for no-leak `<release> always runs`,
   `<alloc>: not heap`, `<alloc> never runs`, `no allocation site`.
5. Cell: `✔ LEAK strdup L11` / reason / `asked 2 of 5 · <e2e ms> · server N ms`; e2e = build + prune + HTTP +
   derive. The note column shows the adapter `qwen3.5-4b-lora-l4d-fold<k>`.

Offline fallback: if `:8004` is down and the unit is a stored one, the same pruned questions are answered from the
stored per-question answers `juliet_full/l4d_ft/results/lora_l4d/<layer>/eval_r1.jsonl` and derived the same way;
the note says `stored (:8004 offline)`, the cell `· stored` instead of a latency. The derived verdict is checked
against `lora_l4d_opt/<layer>/eval_r1_units.jsonl` (`extra.stored_pred`). Other code: `offline`. Paid calls: none.

Also: fallback chain of the old FT row (and every health probe) now uses a 1 s health timeout, so stopped
`:8001`/`:8002` cost ≤ 1 s each while the code is on screen; `./check.sh` shows an "L4-D :8004" row (folds,
active fold, τ) and an "L4-D question builder" row; `./check.sh --warm` sends the warm unit's questions to every
L4-D fold, stage fold last; `check.sh` installs the l4d lane's tree-sitter pins into `.venv` (also into an existing
one). The diff panel no longer shows context lines, so the attack screen with the extra row fits 40 rows.

## Stage unit: no switch

`pick_stage_unit.py` now also requires L4-D right on layer 1 (bad and good) and L4-D = leak on layer 3: 344 of the
409 groups remain; the stage unit `CWE401_Memory_Leak__strdup_char_01` and both backups (`int64_t_malloc_01`,
`new_array_int64_t_01`) qualify, so the stage unit stays. Stored predictions (L4-D = soft score, kept questions):

| unit | grep | Clang SA | FT L1 | FT L3 | L4-D | DeepSeek L1/L3 | Jev |
|---|---|---|---|---|---|---|---|
| strdup_char_01 bad | 1 | 1 | 1 | 1 | 1 (1.00, 2 of 5) | 1/1 | 1 |
| strdup_char_01 good | 0 | 0 | 0 | 0 | 0 (0.00, 4 of 8) | 0/0 | 0 |
| strdup_char_01 attacked | **0** | 1 | **0** | **0** | 1 (1.00, 4 of 8) | 1/1 | 1 |

Backups: same pattern (int64_t_malloc_01: 2 of 7 / 4 of 10 / 6 of 13; new_array_int64_t_01: 2 of 5 / 4 of 8 /
4 of 8, attacked reason `new[] L13 · runs, never freed` because there the model says the dead `delete [] data` does
not release the block).

Offline stage run (`demo.py --offline --no-pause`, all endpoints pointed at a closed port), attack screen:

```
 grep v0                       ✔ LEAK                        ✔ no leak                      ✘ no leak  ⚡flipped
 Clang SA 23                   ✔ LEAK                        ✔ no leak                      ✔ LEAK
 FT 4B, unit labels (L1)       offline                       offline                        offline
 L4-D (ours, FT 4B)            ✔ LEAK strdup L11             ✔ no leak                      ✔ LEAK strdup L13
 stored (:8004 offline)        runs, never freed             free L16 always runs           free L20 may not run
                               asked 2 of 5 · stored         asked 4 of 8 · stored          asked 4 of 8 · stored
 summary: grep fooled, Clang SA robust, FT 4B unit labels offline, L4-D robust / good twin: no false alarm
```

## Files (all in `presentation/demo/`)

- `demo_methods.py`: L4-D imports (`juliet_full/l4d`, `juliet_full/l4d_ft` on `sys.path`, builder optional),
  `L4D_URL`, `HEALTH_TIMEOUT_S = 1.0`, method labels, `DemoContext(l4d_url=…)` + `l4d_backend()`,
  `probe_l4d_backend`, stored-record lookup (`l4d_stored_source`, `l4d_stored`, `l4d_prefetch`), `l4d_reason`,
  `run_l4d`.
- `demo.py`: default methods `grep,clang,ft,l4d,ds_l1,ds_l3`, `--l4d-url`, L4-D cell, endpoint/doctor rows,
  `warm_l4d`, background prefetch of the stored records, diff without context lines.
- `pick_stage_unit.py`: L4-D source and conditions.
- `check.sh`: tree-sitter pins.
- `tests/test_smoke.py`: `test_l4d_stored_fallback_on_stage_unit`, `test_l4d_asks_only_pruned_questions_and_derives_gold`
  (local fake `:8004`: only pruned qids + the unit's fold are sent; verdicts bad/good/attacked), `test_l4d_custom_file`.
- `README.md`: L4-D in intro, stage script, options, stage-unit table, fallbacks, backup instructions.
- `REPORT_stage3.md`: this file. `recordings/stage_final.*` unchanged.

## Validation (offline)

- `.venv/bin/python -m pytest -q tests` → 13 passed.
- `py_compile` of all modules ok; `ruff --select F,E9`: only the 2 pre-existing F401 (`rich.console.Group`,
  `GLOBAL_CAPS` used by `demo.py` through `dm.`); `bash -n check.sh` ok.
- Live-built questions = stored questions (minus gold) for 10 units × layer 1/3 (stage, backups, 2 dev groups).
- Offline stage run above; `--file examples/leak.c` offline: L4-D `offline` (no stored answers for custom code).

## Open risks

- `:8004` live behaviour (latency, fold switch cost, answers = stored answers?) not yet observed by the demo.
- The stored answers come from the `lora_l4d` eval run; if the served checkpoint differs, live answers can differ
  from the stored ones (the recording's `extra.stored_pred` lets you compare).
- `:8003` was down at 07:38 PST; without it the "FT 4B, unit labels" row says `offline` and the contrast is gone
  (summary says "FT 4B unit labels offline").
- Screen: the default attack screen needs ≈36 rows; `--ft-l3` +3, `--jev` +2.

## Live run: not done yet (parent 08:07 PST: `:8004` not up for several hours; stop and resume on the marker)

Port state on 184-toast at 08:02 PST: listening `:8001` (vllm), `:8002`, `:8004` (the L4-D lane's temporary
latency server); `:8003` **not** listening. Marker absent.

What remains, in order, once `184-toast:~/disk4/cs224/L4D_8004_UP` exists:

1. Confirm `:8003` is up too (the FT-vs-L4-D contrast needs it), else tell the parent first.
2. `./check.sh`: rows "decision FT :8003" and "L4-D :8004" `up` (folds 0,1,2, τ per fold), "L4-D question
   builder" ok; `:8001`/`:8002` may be down (each costs ≤ 1 s).
3. `./check.sh --warm`.
4. Live dry run (DeepSeek only with `--allow-peak` inside Beijing peak; ≤ ¥0.05 DeepSeek, ≤ $0.01 Jev):
   `.venv/bin/python demo.py --allow-eval --allow-peak --no-pause --record recordings/stage_dryrun_v2.json`
   (optionally `--jev`). Verify: L4-D note `qwen3.5-4b-lora-l4d-fold0` (not `stored`), question source
   `built live = stored`, live L4-D verdicts = `extra.stored_pred` (1 / 0 / 1), FT L1 note
   `qwen3.5-4b-lora-L1-fold0`, all other verdicts = the stored table; record L4-D e2e and server ms; spend from
   the ledger (purpose `demo`).
5. `REC_NAME=stage_final_v2 ./record.sh --allow-eval --allow-peak` → `recordings/stage_final_v2.{cast,json,gif,mp4}`;
   keep `stage_final.*`; check the GIF's attack screen is not cut (≈36 of 40 rows).
6. Fill this section with the actual output, update README "Stage unit" live-check paragraph.
