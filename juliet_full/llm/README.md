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
| `llmlane/l4.py`, `l4/leak.dl` | L4: fact parser (schema, grounding, `delete`→`free` alias) + Souffle rules; `l4/SCHEMA.md`, `l4/FREEZE_PROPOSAL.md` (v3c, dev numbers) |
| `l4_eval.py` | offline re-parse/re-derive of stored L4 raw logs with the current parser and rules (no API calls) |
| `stage2b.py` | stage-2b nohup driver (frozen-prompt eval, repeats, latency300 c1); status in `scratch/stage2b/status.txt`; scores to `results/scores/<method>/<run_id>.json` |
| `stage2c.py` | stage-2c nohup driver (DeepSeek L4 eval; layer3/placebo/original runs on nested25 and `dev_check/api_rest332_subsets.json` = api_subset − nested25; Jev full-eval layer3/placebo/original; quiet latency remeasure serialized via `flock /tmp/cs224_latency.lock`); restartable, status in `scratch/stage2c/status.txt` |
| `stage2d.py` | stage-2d nohup driver (Qwen3.5-4B on vLLM :8001, frozen chat prompts, c16): waits for `/v1/models` (5-min polls, ≤ 60 min); dev layer1 L1–L4 sanity (stops before eval if > 5% invalid/error); eval layer1 L1–L4, layer3 L1–L4, placebo L1+L3, original L1 (all eval), repeats `rep_L{1,2,3}_r{2,3}` on eval ∩ repeat100; then under `/tmp/cs224_latency.lock` + quiet check (load1 < 2.5 for 2 min) Qwen `lat300_c1_L1` and, only if quiet, DeepSeek (cap CNY 0.10) / Jev (cap USD 0.02) `lat300_c1_L1_quiet`; records vLLM /metrics request counts; status `scratch/stage2d/status.txt` |
| `summarize.py` | builds `results/SUMMARY.md` (all scored runs incl. Qwen, breakdowns, L4 fact quality per method, c1 latency (quiet/loaded, GPU shared), Jev at the frozen thresholds, repeat agreement, ROBUSTNESS via `analysis/robustness.py` with JSON in `results/robustness/`, DeepSeek-vs-Jev on the same subsets, layer3 errors by transform category, original-Juliet FP analysis); `results/jev_thresholds.json` (frozen; only computed if missing) |
| `build_l2_examples.py` | deterministic L2 example selection → `prompts/l2_examples.{txt,json}` |
| `make_dev_check.py`, `dev_check/` | `dev_minus_l2_subsets.json` = dev minus the L2 example groups (326 groups; use it to score full-dev runs); stratified DEV check sample (150 groups, flow_category x mechanism, seed 20261123, L2 groups excluded) as a `--subsets-file`; score.py reports `dev_check/score_*.json`; `latency30_unit_ids.txt` = 30 other dev units for the concurrency-1 latency probe |
| `prompts/` | all prompt text; `meta.prompt_files` records each file's SHA-256, `meta.prompt_hash` the combination |
| `tests/` | `python3 -m unittest discover -s tests` (39 tests, offline: local mock server, simulated clocks) |
| `scratch/` (gitignored) | smoke-test outputs, mock evidence, raw logs of smoke runs |

## Strategies (identical text for DeepSeek and Qwen; Jev gets the same content as `state`)
- **L1** system = `task.txt` + `answer_format.txt`; user = `user_L1.txt` (code unit in a fence) + `user_suffix.txt`.
- **L2** = L1 with `l2_examples.txt` appended to the system prompt (cacheable prefix). Selection rule
  (`build_l2_examples.py` docstring): 4 DEV units, 2 bad / 2 good, one per dev flow category, slots
  bad 02-22 c_alloc, good G2B 31-45 cpp_new, bad 51-68 cpp_new, good B2G 71-84 c_alloc; shortest
  `model_text` per slot, distinct groups; relaxation order good_kind, then mechanism, then both
  (recorded in `l2_examples.json`). Both units of every example group are dropped from all runs unless
  `--keep-l2-examples`. Current examples come from the full dev set of `layer1.jsonl` (d4d913c4…):
  strdup_char_18__bad, new_int_41__good, new_int_65__bad, int_malloc_73__good (no relaxation needed).
- **L3** = L1 + Clang SA warnings from `static/results/clang_sa/<layer>/evidence.jsonl` (`--evidence` overrides),
  schema of `static/run_static.py:evidence_row` (`model_text_line`; fallback via `line_map`). No record →
  "The analyzer produced no result for this code unit."; empty list → "The analyzer reported no warnings."
- **L4** (draft, DeepSeek/Qwen only): the model lists facts (`prompts/l4_system.txt`), `llmlane/l4.py` parses them,
  Souffle (`/home/barton/tools/cs224/souffle-2.5/usr/bin/souffle`, interpreted mode, no LD_LIBRARY_PATH needed)
  derives `leak/2` (`never_freed`, `realloc_fail`); pred = 1 iff a leak is derived. JSON mode is off for L4.
- Jev: `jev_question.json` (one `noul` question); pred = 1 iff score >= 0.5 (primary). Secondary threshold per
  strategy, chosen on `dev_<L>_r1` by macro-F1, is applied only in `summarize.py`.
- `--layer`: `layer1` (main), `layer3` (stress: dead frees under always-false guards, real frees of B2G/realloc goods
  wrapped in always-true guards), `placebo`, `original`; units from `data/build/<layer>.jsonl`, L3 evidence from
  `static/results/clang_sa/<layer>/`.
- Eval runs refuse unless the prompt hash equals `run_llm.py:FROZEN_PROMPT_HASHES` (L1-L3, commit 780ec1e); L3
  eval uses only the evidence named by `static/results/clang_sa/<layer>/EVIDENCE_FROZEN` (sha verified, meta
  `evidence_frozen`).

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
