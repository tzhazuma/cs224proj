# Live demo: CWE-401 detectors side by side, then a dead-free attack

PLAN.md §7 Phase A, item 7 (≈3 min on stage). One Juliet group is shown: the leaking unit and its good
twin. grep v0, Clang SA 23, the fine-tuned decision model, DeepSeek L1/L3 and optionally Jev run live,
with verdict, score, latency and ✔/✘ against the truth. Then a never-executed `free` under an always-false
file-local guard goes into the leaking unit, everything runs again, and a summary line is built from the
actual results, e.g. `grep fooled, Clang SA robust, decision model offline, DeepSeek L1 robust, …`.

| file | what |
|---|---|
| `demo.py` | the demo (rich terminal UI): selection, live table, attack, summary, `--record`/`--replay`, `--check`/`--warm` |
| `demo_methods.py` | detectors: grep v0 and Clang SA via `juliet_full/static/run_static.py`, decision model (fine-tuned `:8003` first, then fallbacks), DeepSeek/Jev thin caller via `juliet_full/llm/llmlane` |
| `dead_free.py` | attack inserter: uses `juliet_full/data/stress.py:transform_unit` (data lane, the layer-3 transform) when it works, else the local fallback (`static const int sym_k = 5;` … `if (sym_k != 5) free(p);` after the allocation; C++ `delete`/`delete []` matching the `new`) |
| `pick_stage_unit.py` | ranks eval groups for the stage from the stored predictions (read-only; see "Stage unit") |
| `check.sh` | doctor; `./check.sh --warm` = pre-warm |
| `record.sh` | unattended backup recording → `recordings/<name>.{json,cast,gif,mp4}` |
| `examples/leak.c` | a small program for the `--file` part |
| `tests/test_smoke.py` | offline smoke test on 2 dev groups: grep, Clang SA, both inserters, attack = stored layer 3, decision-model request/response against a local fake of the `:8003` contract, record + replay |
| `recordings/` | `stage_dryrun.json` (the stage group, all rows live incl. decision model L1/L3 and Jev, 2026-11-23; replayable), `dev_char_malloc_18.*` (dev group, decision model offline), `stage_offline.json` (old stage group `int_malloc_01`, grep + Clang only) |

## Setup (dell)

```bash
cd ~/Documents/projects/cs224/cs224proj/presentation/demo
./check.sh                     # creates .venv with uv if missing (python 3.12, rich, pytest), then the doctor
.venv/bin/python -m pytest -q tests/        # offline, ~1 s
```

`demo.py` re-executes itself in `.venv` when started with a python without `rich`, so `./demo.py …` works.
The agg binary for gif rendering lives in `.tools/agg` (git-ignored). To fetch it again:
`curl -sSL -o .tools/agg https://github.com/asciinema/agg/releases/latest/download/agg-x86_64-unknown-linux-gnu && chmod +x .tools/agg`.

## Terminal

- At least **110×34** characters (the doctor checks this); **120×40** is the layout everything was tuned for.
  The three-column results table needs ≥110 columns, and the side-by-side code panels need ≥100.
  Height: the stage command needs 38 rows (code panels + table). Each extra row costs lines: `--ft-l3` +3,
  `--jev` +2, so `--ft-l3 --jev` needs 43 rows (smaller font, or the top of the code panels scrolls away).
- Font: 18–20 pt on a 1080p projector gives 120×40 in full screen. Use a dark theme. The code panels use the
  pygments `monokai` theme (`--theme` changes it).
- Use a UTF-8 locale (✔ ✘ ⚡ and the box lines). Over ssh: `LANG=C.UTF-8` and `TERM=xterm-256color`.

**Presenting from dell directly:** open a full-screen terminal, set the font size, check with `tput cols; tput lines`.

**Presenting from a laptop over ssh:** set the size and font in the *laptop's* terminal (the projector shows the
laptop), then `ssh -t barton@dell 'cd ~/Documents/projects/cs224/cs224proj/presentation/demo && LANG=C.UTF-8 ./demo.py --allow-eval --allow-peak'`.
The endpoints (10.15.89.184) and the API calls are reached from dell, so the laptop only needs ssh to dell.
If ssh itself is the risk, copy `recordings/` to the laptop and play the mp4/gif.

## Before the talk (T-30 min)

```bash
./check.sh                     # clang + cfg, keys present (values never printed), endpoints, DeepSeek balance,
                               # Beijing peak gate, ledger totals, terminal size, recording tools
./check.sh --warm              # one Clang SA run + endpoint pings (page cache, TLS, the decision model's first request)
REC_NAME=stage_final ./record.sh --allow-eval --allow-peak     # fresh backup of the stage run (~40 s, < CNY 0.01)
```

Peak gate: DeepSeek peak is Beijing Mon–Fri 09:00–12:00 and 14:00–18:00. On **Thu 2026-11-26 (PST)** that is
00:00–02:00, 17:00–20:00 and 22:00–24:00 PST, so a daytime talk (02:00–17:00 PST) is off-peak. `--allow-peak`
is still on the stage command, so the demo does not depend on the clock. In peak hours a demo call costs
twice as much (a stage run is ≈ CNY 0.002 off-peak).

## Stage script (≈3 min)

```bash
./demo.py --allow-eval --allow-peak
```

Default group: `CWE401_Memory_Leak__strdup_char_01` (eval, fold 0, flow 01, C, B2G good twin, 24 lines; why and
what to expect: "Stage unit" below). Paid calls on eval units need `--allow-eval`. They are demo calls, logged to the shared ledger with
purpose "demo", and they are never written as predictions. Press ⏎ to advance:

1. **Code (≈40 s).** On the left the leaking unit, on the right its good twin (B2G). Say: "Same program, the only
   difference is the `free(data);` in the sink; identifiers are anonymized (`sym_0`), no comments, no names."
2. **⏎ Run the detectors (≈50 s).** The table fills in live as results arrive: grep < 1 ms, Clang SA ≈20–40 ms,
   decision model ≈0.1–0.4 s, then DeepSeek ≈0.5–1.2 s (L3 = Clang SA + LLM time, it waits for Clang's warnings).
   Point out the ✔ against the truth, and the scores (`p=` probability of leak; for the fine-tuned decision
   model `s=` score vs the adapter's threshold, leak if s ≥ thr). The decision-model row shows the adapter
   (`qwen3.5-4b-lora-L1-fold0`: the held-out fold of the unit) and two times: end-to-end from dell, and the
   server-side handler time. A request that needs another adapter pays ≈210 ms switch in the end-to-end time
   only (`./check.sh --warm` leaves the stage adapter loaded).
3. **⏎ Attack (≈30 s).** The diff panel shows the edit: a file-local constant and a `free(data)` under a guard
   that is always false. "The program still leaks: the free can never run."
4. **⏎ Rerun (≈40 s).** The fourth column is the edited unit. `⚡flipped` marks a verdict that changed. grep
   flips to "no leak" and is wrong (✘). Clang SA is path-sensitive and still reports the leak. The fine-tuned
   decision model flips too (its layer-3 recall is 0.04), DeepSeek stays right on this unit; whatever happens
   live is what the table and the summary show.
5. **Summary (≈20 s).** The panel is computed from the table: fooled / robust / wrong before and after,
   whether the good twin got a false alarm, and the money spent.

Options if there is time or a question:
- `./demo.py --file examples/leak.c --truth leak --allow-peak`: a small program; edit it live (`nano examples/leak.c`).
  Custom files are comment-stripped, compiled with the Juliet support include path, and attacked with the
  local inserter.
- Another group: `--group <group_id>`, `--unit <unit_id>`, or by flow: `--flow 02-22 --seed 1`
  (`--mechanism cpp_new` for C++, `--good-kind G2B`, `--set dev`).
- `--ft-l3` adds the decision model L3 row (code + the live Clang SA warnings, `qwen3.5-4b-lora-L3-fold<k>`): on the
  stage unit it is fooled as well, even with Clang's leak warning in its input. `--jev` adds the Jev row. Both need
  more rows (see Terminal).
- `--attack-kind placebo` inserts a harmless `printLine` under the same guard (control: nothing should flip).
  The attack defaults to the data lane's construction, so on Juliet units the attacked code is exactly the stored
  layer-3 unit (diff panel subtitle `= stored layer 3`); `--attack-n-dead N` inserts N dead frees instead.
- `--no-twin` gives a narrower table on a small screen.

## Stage unit

Chosen with `python3 pick_stage_unit.py` from the stored eval predictions (2026-11-23). Rule: on layer 1 Clang SA,
DeepSeek L1/L3 and the fine-tuned decision model (L1 and L3, held-out fold adapter) are right on the bad unit and on
its good twin; on layer 3 (the stored dead-free version of the bad unit) Clang SA still says leak while grep v0 and
the decision model L1 say no leak; DeepSeek has layer-3 predictions (API subsets). 409 groups qualify. Ranking: grep
right on the good twin too (B2G twin), Jev right on layer 1, DeepSeek right on layer 3, shortest code.
`int64_t_malloc_01` ranks first but its layer-3 version has two dead `free(data)` (looks like a double free on a
slide); the stage group has one.

| role | group (eval, fold 0, flow 01, B2G twin) | lang | lines | dead frees |
|---|---|---|---|---|
| **stage** (default) | `CWE401_Memory_Leak__strdup_char_01` | C | 24 | 1: `if(sym_61 > 4) { free(data); }` |
| backup 1 | `CWE401_Memory_Leak__int64_t_malloc_01` | C | 23 | 2 (`sym_66 != 4`, `sym_29 != 5`) |
| backup 2 | `CWE401_Memory_Leak__new_array_int64_t_01` | C++ | 25 | 1: `if(sym_43 < 5) { delete [] data; }` |

Stored predictions (pred, score in brackets: decision model = score vs threshold L1 +2.51 / L3 −0.74, LLMs =
probability of leak). "bad"/"good" = layer 1, "attacked" = layer 3 bad unit (= what the demo inserts):

| group | unit | grep v0 | Clang SA | FT L1 | FT L3 | DeepSeek L1 | DeepSeek L3 | Jev L1 |
|---|---|---|---|---|---|---|---|---|
| strdup_char_01 | bad | 1 | 1 | 1 (+17.64) | 1 (+23.52) | 1 (0.99) | 1 (0.99) | 1 (0.97) |
| | good | 0 | 0 | 0 (−26.82) | 0 (−31.36) | 0 (0.01) | 0 (0.01) | 0 (0.06) |
| | attacked | **0** | 1 | **0 (−18.43)** | **0 (−30.87)** | 1 (0.99) | 1 (0.99) | 1 (0.98) |
| int64_t_malloc_01 | bad | 1 | 1 | 1 (+18.00) | 1 (+23.94) | 1 (0.99) | 1 (0.99) | 1 (0.98) |
| | good | 0 | 0 | 0 (−26.87) | 0 (−31.31) | 0 (0.01) | 0 (0.01) | 0 (0.05) |
| | attacked | **0** | 1 | **0 (−15.45)** | **0 (−19.22)** | 1 (0.99) | 1 (0.99) | 1 (0.97) |
| new_array_int64_t_01 | bad | 1 | 1 | 1 (+17.88) | 1 (+23.56) | 1 (0.99) | 1 (0.99) | 1 (0.98) |
| | good | 0 | 0 | 0 (−26.51) | 0 (−31.38) | 0 (0.01) | 0 (0.01) | 0 (0.04) |
| | attacked | **0** | 1 | **0 (−16.95)** | **0 (−25.96)** | 1 (0.99) | 1 (0.95) | 1 (0.98) |

Sources: `juliet_full/static/results/{grep_v0,clang_sa}/layer1/full_v{1,2}.jsonl` and `layer3/full_v1.jsonl`;
`juliet_full/decision_ft/results/decision_ft/{layer1,layer3}/{L1,L3}_cv_v1.jsonl`;
`juliet_full/llm/results/deepseek_flash/layer1/eval_L{1,3}_r1.jsonl`, `layer3/l3_apirest_L{1,3}_r1.jsonl` +
`l3_n25_L{1,3}_r1.jsonl`; `juliet_full/llm/results/jev/layer1/eval_L1_r1.jsonl`, `layer3/l3_eval_L1_r1.jsonl`.

Live check (2026-11-23 15:08 PST, run_id `demo_20261123T230820Z`, `--allow-eval --allow-peak --ft-l3 --jev`, `recordings/stage_dryrun.json`): all 21
live verdicts equal the stored ones. The decision-model scores are identical to two decimals (the server renders
the training prompt; the live Clang SA warnings equal the frozen evidence). DeepSeek and Jev probabilities equal
the stored ones except Jev on the bad unit (0.98 live vs 0.97). Summary line: `grep fooled, Clang SA robust,
decision model L1 fooled, decision model L3 fooled, DeepSeek L1 robust, DeepSeek L3 robust, Jev robust` / `good
twin: no false alarm`. The backups were checked live for grep, Clang SA and decision model L1/L3 (`--offline
--ft-l3`): same verdicts and scores as above.

## Fallbacks on stage

| problem | what to do |
|---|---|
| decision model endpoint down | nothing: the row says `offline` (probe order: fine-tuned `:8003/score` → Intern-Decision `:8002/decide` zero-shot → Qwen3.5-4B vLLM `:8001` zero-shot, 3 s health probe, 10 s request timeout). The row's note shows which backend answered: an adapter name `qwen3.5-4b-lora-…` = the fine-tuned model, `… (fallback)` = zero-shot. The L3 row has no fallback (`offline`). |
| DeepSeek / Jev slow or failing | each call has a 10 s timeout and 1 attempt; the cell shows `timeout`/`error` and the demo goes on. `--offline` drops the paid rows. |
| network gone | `./demo.py --replay recordings/stage_final.json`: the same screens, the recorded results revealed in recorded latency order (`--replay-cap` = max seconds per result). The header says REPLAY. |
| demo.py itself broken | play `recordings/stage_final.mp4` (or the `.gif` on a backup slide). |
| peak hours and no `--allow-peak` | DeepSeek rows say `skipped: Beijing peak hours`. |

## Backup recording

```bash
REC_NAME=stage_final ./record.sh --allow-eval --allow-peak      # any demo.py arguments; default: --allow-eval
```

The script runs `demo.py --auto-pause 4 --record recordings/<name>.json …` inside
`uvx --from 'asciinema>=2.4,<3' asciinema rec --cols 120 --rows 40`, renders the cast with `.tools/agg` (font 20,
monokai) to a gif, and converts the gif to an mp4 with `/usr/bin/ffmpeg`. If asciinema fails, it falls back to
`script --log-timing` (play with `scriptreplay`). Environment: `REC_COLS`, `REC_ROWS`, `REC_HOLD` (seconds per
step), `REC_FONT`. `.cast`, `.typescript` and `.timing` are git-ignored. The replay `.json` and the `.gif`/`.mp4`
are small (≈0.3 MB each) and are not ignored.

**Final backup (when GPU 1 is idle, i.e. no bulk eval on 184-toast):** `./check.sh` (row "decision FT :8003" must be
`up`), `./check.sh --warm`, then the command above. Check that the decision-model row's note shows
`qwen3.5-4b-lora-L1-fold0` (the stage unit is fold 0) and not `(fallback)`, and that the verdicts match the table
in "Stage unit", then copy `recordings/stage_final.{mp4,gif}` to the slides.

## Cost and ledger rules

- DeepSeek and Jev go through `demo_methods.py`, a thin caller over `llmlane.clients`. The off-peak gate lives
  in `juliet_full/llm/run_llm.py` (`PeakGate().check_start()`), not in the clients, so the demo checks
  `pricing.PeakGate` itself and skips DeepSeek in peak hours unless `--allow-peak` is given.
- Every paid call is appended to `juliet_full/llm/ledger.jsonl` (`Ledger.append`, flock + fsync) with
  `run_id: demo_<UTC timestamp>`, `purpose: "demo"`, `layer: "demo"` and the real cost. The global hard stops
  (CNY 9.5 / USD 4.0, `llmlane.ledger.GLOBAL_CAPS`) apply through `Budget`. The per-invocation caps are
  `--max-cost-cny 0.02` and `--max-cost-usd 0.002`.
- Nothing is written under `juliet_full/*/results/`. Prompts come from `llmlane.prompts.PromptSet`, including
  its audit, so a leaking token in a custom file makes the paid rows `skipped: prompt audit`.
- Clang SA and attacked programs live in `/tmp/cs224_demo/`.
