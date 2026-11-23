# juliet_full — pipeline contract (Phase A, 2026-11-23)

The authoritative plan is `../PLAN.md` (Chinese). Background on the dataset changes is in
`../research/juliet_dataset_adjustment.md`. This file fixes the interfaces between the work lanes.
Only the parent session edits `PLAN.md` and this file. If a lane needs an interface change,
it reports the request instead of editing this file.

## 1. Lanes and write boundaries

| Directory | Lane | Content |
|---|---|---|
| `juliet_full/data/` | data | `build_units.py`, `verify_labels.py`, `probes.py`, `subsets.py`, later `stress.py`; outputs in `data/build/` |
| `juliet_full/static/`, `juliet_full/analysis/` | static | `run_static.py`, tool wrappers, `results/`; the shared scorer `analysis/score.py` |
| `juliet_full/llm/` | llm | API/vLLM clients, prompts, `run_llm.py`, cost ledger, `results/` |
| `juliet_full/gpu/` (+ `184-toast:~/disk4/cs224/`) | gpu | serving scripts for 184-toast, Intern-Decision read-out, LineVul, `results/` |

Rules for every lane:
- Write only inside your own directories (plus `/tmp/` scratch; the gpu lane also writes under `184-toast:~/disk4/cs224/`).
- Everything else in the repo is read-only: `juliet/raw/`, `juliet/full_split_v1.json`, `juliet_llm/`, `juliet/scripts/`,
  `traditional/`, `runner/`, other lanes' directories. Import or copy code from them instead of editing.
- No git commands that change state (`add`, `commit`, `stash`, `checkout`, `reset`, `clean`). The parent commits.
- Never print, log or copy API keys. They are in `cs224proj/.env` (`DEEPSEEK_API_KEY`, `TYPESAFE_API_KEY`).
- Do not install anything system-wide (no apt, no sudo, no edits to shell rc files). Python deps go in a lane-local
  venv (`uv venv`) or `uv run --with ...`.
- Generated bulk files go under `build/`, `scratch/` or `raw_logs/` subdirectories (git-ignored).

## 2. Inputs

- Juliet v1.3 C/C++: `juliet/raw/testcases/CWE401_Memory_Leak/` and `juliet/raw/testcasesupport/`
  (`io.c`, `std_testcase.h`, `std_testcase_io.h`, `main_linux.cpp`, ...).
- Split: `juliet/full_split_v1.json`, key `groups`: 1,658 rows
  `{group_id, family, variant, flow_category, mechanism, language, set, fold}`.
  - `flow_category` ∈ `01`, `02-22`, `31-45`, `51-68`, `71-84`; `mechanism` ∈ `c_alloc`, `cpp_new`, `realloc_fail`, `destructor`;
    `language` ∈ `c`, `cpp`; `set` ∈ `dev` (330 groups), `eval` (1,328); `fold` ∈ 0/1/2 for eval, null for dev.
- Existing helpers: `juliet/scripts/lib_juliet.py` (`discover_groups`), `juliet/scripts/verify.py`,
  `juliet_llm/cleaning.py` (`clean_unit`), `juliet_llm/prompting.py`, `traditional/static/static_adapter.py`.

## 3. Unit records (owner: data lane)

`data/build/layer1.jsonl` — layer ① (debiased main layer), one JSON object per line, 2 units per group:

| Field | Meaning |
|---|---|
| `unit_id` | `"<group_id>__bad"` or `"<group_id>__good"` |
| `group_id`, `family`, `variant`, `flow_category`, `mechanism`, `language`, `set`, `fold` | copied from the split |
| `label` | `"bad"` or `"good"`; `truth` = 1 for bad (leaks), 0 for good |
| `good_kind` | `"G2B"` or `"B2G"` for good units (one entry function sampled per group, seed 20261123, ~50/50 within each flow category); `null` for bad |
| `program_dir` | absolute path of a directory holding the compilable debiased program: unit sources + a small driver `main` that calls the single entry function |
| `build` | `{"compiler": "gcc"\|"g++", "sources": [...], "include_dirs": [...], "defines": [...], "std": "..."}` (paths relative to `program_dir`, support files referenced by absolute path) |
| `entry` | name of the entry function in the compiled sources |
| `model_text` | the cleaned code shown to every model. It must be the same code as the compiled program, cleaned by the `juliet_llm/cleaning.py` rules (comments removed, OMIT macros resolved, testcase-local headers inlined, Juliet identifiers renamed `sym_N`; `std_testcase.h` is not inlined) |
| `line_map` | list of `[source_file, source_line, model_text_line]` for lines kept in `model_text` (used to cite L3 evidence) |
| `verify` | filled by `verify_labels.py`: `{"compile_gcc", "compile_clang", "asan_leak", "valgrind_leak", "note"}` (null when not run) |

`data/build/original.jsonl` — the original-Juliet control (PLAN RQ1): same schema, but the good unit is the original
OMITBAD program (both `static` good functions and the `..._good()` wrapper), `good_kind = "orig"`.

`data/build/subsets.json` — `{"api_subset": [group_id...], "nested25": [...], "repeat100": [...], "latency300": [...]}`.
api_subset = 664 eval groups stratified by flow_category × mechanism (seed 20261123); nested25 = 332 groups ⊂ api_subset;
repeat100 = 100 groups ⊂ nested25; latency300 = 150 groups ⊂ api_subset (300 units). See PLAN §2.7.

`data/build/layer1_sample.jsonl` — early milestone: ≥ 40 units (both labels, every flow category and mechanism, dev set
only) in the final schema, so other lanes can integrate before the full build is finished.

## 4. Predictions (every method)

Path: `<lane>/results/<method>/<layer>/<run_id>.jsonl`, one line per unit:

```json
{"unit_id": "...", "method": "clang_sa", "strategy": null, "model": null, "layer": "layer1",
 "pred": 1, "score": null, "latency_s": 0.12, "status": "ok", "extra": {}}
```

- `pred`: 1 = leak (positive class), 0 = no leak, `null` = no valid prediction (counted as wrong: bad → FN, good → FP).
- `score`: P(leak) or another monotone score when available (for AUROC/thresholds), else null.
- `latency_s`: wall time per unit measured on dell (includes LAN/network for remote methods).
- `status`: `ok`, `invalid` (unparseable output), `compile_error`, `timeout`, `error`.
- `strategy`: `L1`–`L4` for model methods; `model`: the model string the provider returned.
- `layer`: `layer1`, `original`, `stress`, `placebo`.
- Next to it, `<run_id>.meta.json`: method, tool/model versions, prompt file hash, start/end time (UTC), host,
  concurrency, `os.getloadavg()` at start/end, token usage and cost (API methods).

## 5. Scorer (owner: static lane)

`analysis/score.py --pred <file.jsonl> [--units data/build/layer1.jsonl] [--subset api_subset] [--set eval] [--bootstrap 2000]`
reports leak-class precision/recall/F1, macro-F1, MCC, accuracy, coverage, invalid count, latency median/p90,
breakdowns by flow_category, mechanism and good_kind, and family-cluster bootstrap CIs. Units missing from the
prediction file count as invalid.

## 6. Machines and endpoints

- **dell** (this host, America/Los_Angeles): runs tests, CPU tools and all clients. Tools are installed under
  `~/tools/cs224/` (see `~/tools/cs224/VERSIONS.txt`); pass binaries by absolute path.
- **184-toast** (`ssh 184-toast`, LAN IP 10.15.89.184): 2× RTX 3090; venv `~/disk4/cs224/venv`
  (torch 2.14.0+cu130, vllm 0.34.0, transformers 5.22.2, peft 0.22.0); models in `~/disk4/cs224/models/`
  (copied from dell `~/tools/cs224/models/`). Use only `~/disk4`. Do not restart the stopped `cs253-pre-*` containers.
- Endpoints: Qwen3.5-4B via vLLM OpenAI API at `http://10.15.89.184:8001/v1` (served name `qwen3.5-4b`; now GPU 1);
  Intern-Decision-4B read-out at `http://10.15.89.184:8002` (GPU 1). The gpu lane documents the final details in
  `juliet_full/gpu/README.md`.
- Status 2026-11-23 15:05 PST: Qwen :8001 and Intern-Decision :8002 run together on GPU 1; the fine-tuned decision
  model :8003 runs on GPU 0. Before any GPU job, source `~/disk4/cs224/gpu/server/env.sh` on 184-toast (it sets the
  caches, HF offline mode, and the CPATH for Python.h).
- Fine-tuned decision model endpoint (LIVE since 2026-11-23 ~14:55 PST, GPU 0, 6 models, ~211 ms to switch model):
  `http://10.15.89.184:8003`. Start/stop/status: `bash ~/disk4/cs224/decision_ft/server/serve.sh start|stop|status`
  (see `juliet_full/decision_ft/README.md` §10). Use the held-out fold model for an eval unit (unit `fold` = k).
  - `GET /health` returns `{"ok": true, "models": [...]}`.
  - `POST /score` takes `{"code": <model_text>, "language": "c"|"cpp", "strategy": "L1"|"L3", "evidence": <list or null>, "model": "qwen3.5-4b-lora-<L1|L3>-fold<k>"}`
    and returns `{"score": s, "threshold": t, "pred": 0|1, "latency_ms_server": ..., "model": ...}`.
  - The server renders the prompt itself, using the same template as training (decision_ft lane).
- Parent progress and decisions log: `juliet_full/STATUS.md` (read it for the current state). Lane reports are in
  `juliet_full/lane_reports/`.

## 7. Budget rules (API)

- DeepSeek `deepseek-flash`: total project cap ¥10 (client hard stop at ¥9.5 cumulative, one shared ledger
  `llm/ledger.jsonl`); thinking must be disabled (`"thinking": {"type": "disabled"}`), abort if `reasoning_tokens`
  appear; run only in off-peak hours (peak = Beijing Mon–Fri 09:00–12:00 and 14:00–18:00). Development tests in
  Phase A: ≤ ¥0.3, dev units only.
- Jev (TypeSafe, `jev-latest`): balance $4.8; development tests ≤ $0.05, dev units only.
- No eval-set API calls until the parent freezes the prompts.
