# Live demo: CWE-401 detectors side by side, then a dead-free attack

PLAN.md §7 Phase A, item 7 (≈3 min on stage). One Juliet group is shown: the leaking unit and its good
twin. grep v0, Clang SA 23, the fine-tuned decision model, DeepSeek L1/L3 and optionally Jev run live,
with verdict, score, latency and ✔/✘ against the truth. Then a never-executed `free` under an always-false
file-local guard goes into the leaking unit, everything runs again, and a summary line is built from the
actual results, e.g. `grep fooled, Clang SA robust, decision model offline, DeepSeek L1 robust, …`.

| file | what |
|---|---|
| `demo.py` | the demo (rich terminal UI): selection, live table, attack, summary, `--record`/`--replay`, `--check`/`--warm` |
| `demo_methods.py` | detectors: grep v0 and Clang SA via `juliet_full/static/run_static.py`, decision model (LAN, fallbacks), DeepSeek/Jev thin caller via `juliet_full/llm/llmlane` |
| `dead_free.py` | attack inserter: uses `juliet_full/data/stress.py:transform_unit` (data lane, the layer-3 transform) when it works, else the local fallback (`static const int sym_k = 5;` … `if (sym_k != 5) free(p);` after the allocation; C++ `delete`/`delete []` matching the `new`) |
| `check.sh` | doctor; `./check.sh --warm` = pre-warm |
| `record.sh` | unattended backup recording → `recordings/<name>.{json,cast,gif,mp4}` |
| `examples/leak.c` | a small program for the `--file` part |
| `tests/test_smoke.py` | offline smoke test (grep, Clang SA, both inserters, record + replay) on 2 dev groups |
| `recordings/` | `dev_char_malloc_18.*` (full run on a dev group, DeepSeek + Jev, decision model offline), `stage_offline.json` (stage group, grep + Clang only) |

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

Default group: `CWE401_Memory_Leak__int_malloc_01` (eval, fold 0, flow 01, C, B2G good twin, 23 lines).
Paid calls on eval units need `--allow-eval`. They are demo calls, logged to the shared ledger with
purpose "demo", and they are never written as predictions. Press ⏎ to advance:

1. **Code (≈40 s).** On the left the leaking unit, on the right its good twin (B2G). Say: "Same program, the only
   difference is the `free(data);` in the sink; identifiers are anonymized (`sym_0`), no comments, no names."
2. **⏎ Run the detectors (≈50 s).** The table fills in live as results arrive: grep < 1 ms, Clang SA ≈20–40 ms,
   decision model, then DeepSeek ≈0.6–1.2 s (L3 = Clang SA + LLM time, it waits for Clang's warnings).
   Point out the ✔ against the truth, and the scores (`p=` probability of leak; for the fine-tuned model
   `s=` logit vs its threshold).
3. **⏎ Attack (≈30 s).** The diff panel shows the edit: a file-local constant and a `free(data)` under a guard
   that is always false. "The program still leaks: the free can never run."
4. **⏎ Rerun (≈40 s).** The fourth column is the edited unit. `⚡flipped` marks a verdict that changed. grep
   flips to "no leak" and is wrong (✘). Clang SA is path-sensitive and still reports the leak. Whatever the
   LLM rows and the decision model do is shown as it happens.
5. **Summary (≈20 s).** The panel is computed from the table: fooled / robust / wrong before and after,
   whether the good twin got a false alarm, and the money spent.

Options if there is time or a question:
- `./demo.py --file examples/leak.c --truth leak --allow-peak`: a small program; edit it live (`nano examples/leak.c`).
  Custom files are comment-stripped, compiled with the Juliet support include path, and attacked with the
  local inserter.
- Another group: `--group <group_id>`, `--unit <unit_id>`, or by flow: `--flow 02-22 --seed 1`
  (`--mechanism cpp_new` for C++, `--good-kind G2B`, `--set dev`).
- `--jev` adds the Jev row. `--attack-kind placebo` inserts a harmless `printLine` under the same guard
  (control: nothing should flip). `--attack-n-dead 0` uses the data lane's own number of dead frees.
- `--no-twin` gives a narrower table on a small screen.

## Fallbacks on stage

| problem | what to do |
|---|---|
| decision model endpoint down | nothing: the row says `offline` (probe order: FT `:8003/score` → Intern-Decision `:8002/decide` zero-shot → Qwen3.5-4B vLLM `:8001` zero-shot, 3 s health probe, 10 s request timeout). The row's note shows which backend answered. |
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

**Re-record once the `:8003` endpoint is up:** `./check.sh` (row "decision FT :8003" must be `up`), then the
command above. Check that the decision-model row's note shows `qwen3.5-4b-lora-L1-fold0` (the stage unit is
fold 0) and not `(fallback)`, then copy `recordings/stage_final.{mp4,gif}` to the slides.

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
