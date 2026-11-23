# LLM lane (juliet_full/llm)

DeepSeek (deepseek-flash), Qwen (qwen3.5-4b on the GPU-lane vLLM server) and Jev (TypeSafe System One)
on the CWE-401 units of `../data/build/*.jsonl`. Predictions and meta files follow `../README.md` section 4.

## Layout
| path | what |
|---|---|
| `run_llm.py` | driver: one model x strategy x unit set → `results/<method>/<layer>/<run_id>.jsonl` + `.meta.json` |
| `llmlane/clients.py` | stdlib HTTP clients: `deepseek_client()` (thinking disabled), `qwen_client()` (`chat_template_kwargs.enable_thinking=false`), `JevClient` (one `noul` question, score = probability). Temperature 0, jittered exponential backoff on 408/409/425/429/5xx/transport errors, no retry on other 4xx, HTTP 401/402/403 stop the run, any non-zero `reasoning_tokens` or reasoning text stops the run |
| `llmlane/pricing.py` | prices, Beijing peak windows (Mon-Fri 09-12, 14-18 Asia/Shanghai), `PeakGate` |
| `llmlane/ledger.py` | append-only `ledger.jsonl` (flock + fsync), `Budget` (per-run cap + global hard stop: DeepSeek CNY 9.5, Jev USD 4.0) |
| `llmlane/parse.py` | `parse_verdict`: JSON object (fences/prose tolerated) → pred/score; anything else → `status invalid`, `pred null`; valid label with missing/bad confidence → pred kept, score null |
| `llmlane/prompts.py` | `PromptSet` (prompt files + SHA-256), label-token audit (fail closed), L3 evidence rendering |
| `llmlane/units.py` | unit loading (final schema; old `{lab, variant, code}` adapter), subsets, stratified `--limit`, evidence loading |
| `llmlane/l4.py`, `l4/leak.dl` | L4 draft: fact parser + Souffle rules |
| `build_l2_examples.py` | deterministic L2 example selection → `prompts/l2_examples.{txt,json}` |
| `prompts/` | all prompt text; `meta.prompt_files` records each file's SHA-256, `meta.prompt_hash` the combination |
| `tests/` | `python3 -m unittest discover -s tests` (32 tests, offline: local mock server, simulated clocks) |
| `scratch/` (gitignored) | smoke-test outputs, mock evidence, raw logs of smoke runs |

## Strategies (identical text for DeepSeek and Qwen; Jev gets the same content as `state`)
- **L1** system = `task.txt` + `answer_format.txt`; user = `user_L1.txt` (code unit in a fence) + `user_suffix.txt`.
- **L2** = L1 with `l2_examples.txt` appended to the system prompt (cacheable prefix). Selection rule
  (`build_l2_examples.py` docstring): 4 DEV units, 2 bad / 2 good, one per dev flow category, slots
  bad 02-22 c_alloc, good G2B 31-45 cpp_new, bad 51-68 cpp_new, good B2G 71-84 c_alloc; shortest
  `model_text` per slot, distinct groups; relaxation order good_kind, then mechanism, then both
  (recorded in `l2_examples.json`). Both units of every example group are dropped from all runs unless
  `--keep-l2-examples`. Current examples come from `layer1_sample.jsonl` (48 units); rerun
  `python3 build_l2_examples.py --units <full dev unit file>` once it exists (the L2 prompt hash then changes).
- **L3** = L1 + Clang SA warnings from `static/results/clang_sa/<layer>/evidence.jsonl` (`--evidence` overrides),
  schema of `static/run_static.py:evidence_row` (`model_text_line`; fallback via `line_map`). No record →
  "The analyzer produced no result for this code unit."; empty list → "The analyzer reported no warnings."
- **L4** (draft, DeepSeek/Qwen only): the model lists facts (`prompts/l4_system.txt`), `llmlane/l4.py` parses them,
  Souffle (`/home/barton/tools/cs224/souffle-2.5/usr/bin/souffle`, interpreted mode, no LD_LIBRARY_PATH needed)
  derives `leak/2` (`never_freed`, `realloc_fail`); pred = 1 iff a leak is derived. JSON mode is off for L4.
- Jev: `jev_question.json` (one `noul` question); pred = 1 iff score >= 0.5.

## Running
```
python3 run_llm.py --model deepseek --strategy L2 --units ../data/build/layer1_sample.jsonl --set dev \
    --layer layer1 --concurrency 8 --max-cost 0.2            # add --subset nested25 etc.
python3 run_llm.py ... --dry-run                             # prompt audit + no-cache cost upper bound, no calls
```
- DeepSeek: refuses to start during Beijing peak; pauses (polls) if a peak window opens mid-run; one DeepSeek run
  at a time (`scratch/deepseek_run.lock`); balance recorded before/after in the ledger and meta.
- Warm-up: 1 request, sleep `--warmup-wait` (5 s), then the concurrent burst (chat models).
- `--set eval` for paid models requires `--allow-eval`. `--max-cost` is required for DeepSeek and Jev.
- Exit codes: 0 finished, 2 refused to start, 3 aborted mid-run (remaining units `status error`).

## Measured on DEV smoke runs (layer1_sample, 2026-11-23, off-peak, medians per call)
| model | strategy | input tok | cache hit | output tok | cost/call |
|---|---|---|---|---|---|
| deepseek | L1 | 508 | 128 | 16 | CNY 0.00045 |
| deepseek | L2 | 1216 | 896 | 16.5 | CNY 0.00041 |
| deepseek | L3 | 564 | 384* | 16.5 | CNY 0.00026 |
| deepseek | L4 | 706 | 384 | 36 | CNY 0.00047 |
| jev | L1 / L2 / L3 | 805 / 1555 / 862 | - | 21 (free) | USD 3.4e-5 / 6.5e-5 / 3.6e-5 |

\* L3 ran right after L1 on the same units, so the shared prefix up to the code was cached; cost depends on run
order (outputs do not).
