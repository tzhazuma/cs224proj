# Demo lane, stage 3: L4-D row

Request (parent, 2026-11-24 07:50 PST): add an L4-D row to the live demo, keep the old LoRA row as the contrast,
build and test offline, then (once `:8004` is up, marker `184-toast:~/disk4/cs224/L4D_8004_UP`) check, live dry
run and a new backup recording `stage_final_v2`. Follow-up (10:20 PST, marker up): also a stored-verdict fallback
for the old-LoRA rows, live dry run on the stage unit + both backups, record `stage_final_v2`. Write boundary
`presentation/demo/`; no git.

## Status

- **Done.** L4-D row live on `:8004` (GPU 1) next to the old LoRA rows on `:8003` (GPU 0); stored fallback for
  both; all 72 live verdicts of the stage unit and both backups equal the stored ones; no L4-D flip; backup
  `recordings/stage_final_v2.{gif,mp4,cast,json}` recorded (old `stage_final.*` kept).
- Morning (07:38–08:10 PST) the marker was absent and a temporary `:8004` served the L4-D lane's latency runs, so
  the demo did not call it until the parent's go at 10:20.

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

## Old-LoRA stored fallback (follow-up 10:20)

`demo_methods.run_decision`: if `:8003` is not up, both FT rows ("FT 4B, unit labels (L1)/(L3)") first look for the
stored verdict of the same code (`ft_stored(unit, strategy, fold)`: eval units from
`juliet_full/decision_ft/results/decision_ft/<layer>/<L1|L3>_cv_v1.jsonl` = held-out fold, dev units from
`dev_<L>_fold<k>_v1.jsonl`; layer 3 for the dead-free version via `stored_source`, the lookup shared with L4-D)
and show it with note `stored (:8003 offline)` and `· stored` instead of a latency. The zero-shot fallbacks
(Intern `:8002`, Qwen `:8001`) only answer code without a stored verdict (`--file`), since they are other models.

## Files (all in `presentation/demo/`)

- `demo_methods.py`: L4-D imports (`juliet_full/l4d`, `juliet_full/l4d_ft` on `sys.path`, builder optional),
  `L4D_URL`, `HEALTH_TIMEOUT_S = 1.0`, method labels, `DemoContext(l4d_url=…)` + `l4d_backend()`,
  `probe_l4d_backend`, stored-record lookup (`stored_source`, `ft_stored`, `l4d_stored`, `l4d_prefetch`),
  `l4d_reason`, `run_l4d`; `run_decision` stored fallback.
- `demo.py`: default methods `grep,clang,ft,l4d,ds_l1,ds_l3`, `--l4d-url`, L4-D cell, FT cell `· stored`,
  endpoint/doctor rows, `warm_l4d`, background prefetch of the stored records, diff without context lines.
- `pick_stage_unit.py`: L4-D source and conditions.
- `check.sh`: tree-sitter pins.
- `tests/test_smoke.py`: `test_l4d_stored_fallback_on_stage_unit`, `test_ft_stored_fallback_on_stage_unit`,
  `test_l4d_asks_only_pruned_questions_and_derives_gold` (local fake `:8004`: only pruned qids + the unit's fold are
  sent; verdicts bad/good/attacked), `test_l4d_custom_file`.
- `README.md`: L4-D in intro, stage script, options, stage-unit table + live check, fallbacks, backup.
- `REPORT_stage3.md`: this file.
- `recordings/`: new `stage_dryrun_v2.json`, `backup_int64_t_malloc_01_dryrun_v2.json`,
  `backup_new_array_int64_t_01_dryrun_v2.json`, `stage_final_v2.{cast,json,gif,mp4}`; `stage_final.*` unchanged.

## Validation

- `.venv/bin/python -m pytest -q tests` → 14 passed.
- `py_compile` of all modules ok; `ruff --select F,E9`: only the 2 pre-existing F401 (`rich.console.Group`,
  `GLOBAL_CAPS` used by `demo.py` through `dm.`); `bash -n check.sh` ok.
- Live-built questions = stored questions (minus gold) for 10 units × layer 1/3 (stage, backups, 2 dev groups).
- Offline stage run (all endpoints on a closed port): L4-D and FT rows from the stored records, same verdicts.
- `./check.sh` (10:17 PST): clang ok, keys present, L4-D builder ok, `decision FT :8003` up (6 adapters),
  `L4-D :8004` up (folds 0,1,2, τ 0:0.818 1:0.500 2:0.500), `:8002`/`:8001` DOWN after 1001 ms each (stopped, as
  announced), DeepSeek/Jev up, off-peak (Beijing Wed 02:17), balance ¥2.25, ledger DeepSeek ¥11.57 of hard stop
  12.3. `./check.sh --warm`: 6/6 FT adapters (server 81–83 ms), 3/3 L4-D folds (server 128–149 ms).

## Live run (2026-11-24 10:17–10:19 PST)

Command per group: `.venv/bin/python demo.py [--group CWE401_Memory_Leak__<g>] --allow-eval --allow-peak --ft-l3
--jev --no-pause --record recordings/<name>.json` (off-peak, so `--allow-peak` was not needed).

Live vs stored (live pred = stored pred for every cell; L4-D = asked of n questions; every live L4-D p_yes on
the same side of τ as the stored answer):

| group · unit | grep | Clang SA | FT L1 | FT L3 | L4-D | DS L1 | DS L3 | Jev |
|---|---|---|---|---|---|---|---|---|
| strdup_char_01 bad | 1 = 1 | 1 = 1 | 1 = 1 (+17.64) | 1 = 1 (+23.52) | 1 = 1 (2 of 5, strdup L11 runs, never freed) | 1 = 1 | 1 = 1 | 1 = 1 |
| strdup_char_01 good | 0 = 0 | 0 = 0 | 0 = 0 (−26.82) | 0 = 0 (−31.36) | 0 = 0 (4 of 8, free L16 always runs) | 0 = 0 | 0 = 0 | 0 = 0 |
| strdup_char_01 attacked | **0** = 0 | 1 = 1 | **0** = 0 (−18.43) | **0** = 0 (−30.87) | 1 = 1 (4 of 8, strdup L13, free L20 may not run) | 1 = 1 | 1 = 1 | 1 = 1 |
| int64_t_malloc_01 bad / good / attacked | 1 0 **0** | 1 0 1 | 1 0 **0** | 1 0 **0** | 1 0 1 (2/7, 4/10, 6/13) | 1 0 1 | 1 0 1 | 1 0 1 |
| new_array_int64_t_01 bad / good / attacked | 1 0 **0** | 1 0 1 | 1 0 **0** | 1 0 **0** | 1 0 1 (2/5, 4/8, 4/8) | 1 0 1 | 1 0 1 | 1 0 1 |

72 of 72 verdicts equal the stored ones. FT scores equal the stored scores to 2 decimals. L4-D max |p_live −
p_stored| per unit: ≤ 1.3e-5 everywhere except int64_t_malloc_01 attacked 0.028 (no τ crossing). So the BF16
batch-shape flip (~0.7 % of DeadFree units, l4d-train lane) does not hit any demo unit; no switch needed.
Summary line on all three groups: `grep fooled, Clang SA robust, FT 4B unit labels fooled, FT 4B unit labels L3
fooled, L4-D robust, DeepSeek L1 robust, DeepSeek L3 robust, Jev robust` / `good twin: no false alarm`.

Latency per row, stage unit (end-to-end ms from dell, bad / good / attacked; server-side ms in brackets):

| row | bad | good | attacked |
|---|---|---|---|
| grep v0 | 1 | 2 | 0.6 |
| Clang SA 23 | 20 | 37 | 24 |
| FT 4B unit labels L1 | 168 (95) | 326 (80) | 338 (81) |
| FT 4B unit labels L3 (incl. Clang SA) | 351 (82) | 362 (83) | 357 (85) |
| L4-D (build + prune + `/l4d` + derive) | 169 (134) | 255 (218) | 278 (233) |
| DeepSeek L1 | 863 | 569 | 1097 |
| DeepSeek L3 (incl. Clang SA) | 593 | 839 | 587 |
| Jev L1 | 954 | 938 | 940 |

FT e2e − server ≈ 210 ms = adapter switch (`switch_ms`), because L1 and L3 requests alternate on `:8003`; with
only the L1 row the stage adapter stays loaded (168 ms). L4-D: question build + prune 0.4–0.5 ms, switch 0 ms
(fold 0 warmed last), server time grows with the number of questions (2 → 134 ms, 4 → 218–233 ms; backups
6 questions → 393 ms). Backups L4-D e2e: int64_t_malloc_01 229 / 262 / 440 ms, new_array_int64_t_01
158 / 288 / 289 ms.

Recording: `REC_NAME=stage_final_v2 REC_ROWS=47 ./record.sh --allow-eval --allow-peak --ft-l3 --jev` (10:19 PST,
run_id `demo_20261124T181925Z`) → `recordings/stage_final_v2.cast` (169 KB), `.json` (18 KB), `.gif` (451 KB),
`.mp4` (386 KB, 21 s, 1468×1344). Same row set as `stage_final` plus L4-D. Rows 47 instead of 40: with
`--ft-l3 --jev` and L4-D the attack screen needs 41 rows + the `recorded →` line; checked on the mp4's last frame
(header, diff, all 8 rows × 3 columns, summary visible) and the run screen. Recording verdicts = stored; notes
`qwen3.5-4b-lora-L1-fold0`, `…-L3-fold0`, `qwen3.5-4b-lora-l4d-fold0`.

Spend (shared ledger `juliet_full/llm/ledger.jsonl`, purpose `demo`, run_ids `demo_20261124T18*`): DeepSeek 24
calls ¥0.00635, Jev 12 calls $0.00038 (3 dry runs + the recording). Demo totals since stage 1: DeepSeek 54 calls
¥0.0158, Jev 23 calls $0.00072. Nothing written under `juliet_full/*/results/`.

## Open risks

- DeepSeek balance ¥2.25 and ledger total ¥11.57 of hard stop 12.3: enough for the talk (≈¥0.0016 per stage run),
  but other lanes' spend can reach the hard stop; then the DeepSeek rows show an error and the summary still works.
- `:8003` and `:8004` are on different GPUs; if either is down on stage, the rows fall back to the stored verdicts
  (`stored (…offline)`), which keeps the contrast but shows no latency.
- Screen: default stage command ≈36 rows; `--ft-l3` +3, `--jev` +2 (≈42 with both).
- A +210 ms adapter switch shows in the FT end-to-end time when `--ft-l3` is on.
