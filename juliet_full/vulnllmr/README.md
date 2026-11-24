# vulnllmr — VulnLLM-R-7B appendix baseline

Lane `vulnllmr`. Runs the released VulnLLM-R-7B checkpoint (arXiv 2512.07533, github.com/ucsb-mlsec/VulnLLM-R) with
**the authors' function-level prompt and parser** over the juliet_full layers (layer1, layer3, placebo, original),
through a vLLM OpenAI server on 184-toast port 8005. The run plan is in `RUNBOOK.md`, and the prep report is in
`REPORT_prep.md`.

| file | purpose |
|---|---|
| `vulnllmr_prompt.py` | authors' system prompt, user template, CWE hint and answer parser, copied verbatim (sources in its docstring) |
| `run_vulnllmr.py` | bulk / `--c1-latency` runner (stdlib only), resumable, writes the §4 prediction format |
| `run_all.sh` | one-command plan (server start → health → runs → score → stop), see `RUNBOOK.md` |
| `serve_vulnllmr.sh` | start/stop/health/status of vLLM on 184-toast:8005 (copy at `~/disk4/cs224/vulnllmr/`) |
| `estimate_offline.py` | CPU-only token counts + wall-clock estimate → `build/estimate.json` |
| `tests/test_vulnllmr.py` | template/CWE-list identity checks, parser cases, fake-server bulk/retry/resume tests |
| `model_files.sha256` | sha256 of all 21 checkpoint files (identical on dell and 184-toast) |
| `build/` `scratch/` `raw_logs/` `.venv/` | git-ignored: raw outputs, rendered prompts, logs, uv venv (transformers 4.51.3, pytest) |

The authors' repo was read at commit `5357371a2271df1048666220415a3bc937af5f9d` (2026-03-25). Below, `R:` means
`https://github.com/ucsb-mlsec/VulnLLM-R/blob/5357371a2271df1048666220415a3bc937af5f9d/`.

## 1. Model

- HF `Virtue-AI-HUB/VulnLLM-R-7B`, revision `8cd13d7a35f13b187102dba166413d4450836a40`. The model card and the authors'
  README call it `UCSB-SURFI/VulnLLM-R-7B`. Architecture: Qwen2ForCausalLM (base Qwen/Qwen2.5-7B-Instruct), bf16,
  `max_position_embeddings` 32768, 15,247,766,004 bytes.
- Local copies: `dell:~/tools/cs224/models/VulnLLM-R-7B` and `184-toast:~/disk4/cs224/models/VulnLLM-R-7B`. Every file's
  sha256 is in `model_files.sha256`. The 6 LFS files match the HF etags, and the remote copy is byte-identical.
- The checkpoint's `generation_config.json` sets `do_sample: true, temperature 0.7, top_k 20, top_p 0.8,
  repetition_penalty 1.05`. These are **not** the authors' evaluation settings. The server runs with
  `--generation-config vllm`, and the runner sends every sampling parameter explicitly.

## 2. Authors' inference setup (function-level detection)

### 2.1 Entry point and the headline command
- `R:README.md#L39-L40`, the VulnLLM-R-7B reproduction command:
  `python -m vulscan.test.test --output_dir results/test_data --dataset_path ./datasets/test/function_level/ ./datasets/test/repo_level/ --language python c java --model UCSB-SURFI/VulnLLM-R-7B --requests_per_minute 1000 --save --use_cot --batch_size 4 --tp 2 --vllm --max_tokens 8192 --random_cwe`
  This command does **not** pass `--use_policy`, so no CWE list goes into the prompt.
- `R:README.md#L224-L258` ("Test the trained models", which includes "# our model"), `R:vulscan/test/run_test.sh#L8`
  (`max_tokens=8192`), `R:vulscan/test/run_test.sh#L133-L156` (baselines) and `R:scripts/train_test.py#L76-L89`
  (`run_testing` defaults) all use `--use_cot --use_policy ... --random_cwe`.
- `R:vulscan/test/test.py#L97` seed 42. `#L109` `--max_tokens` default 16384 (the commands above pass 8192). `#L130`
  temperature 0.0. `#L118` `--use_policy`, `#L121` `--use_cot`, `#L122` `--random_cwe`. `#L386`
  `policy if args.use_policy else ""`.

### 2.2 System prompt and chat template
- `R:vulscan/test/test.py#L225-L249`:
  - The HF id `UCSB-SURFI/VulnLLM-R-7B` matches none of the special cases, so `system_prompt=None` and the Qwen2.5 chat
    template inserts its default system turn `You are Qwen, created by Alibaba Cloud. You are a helpful assistant.`
  - For local or `secmlr/...` checkpoints (`"secmlr" in base_model or os.path.exists(base_model)`), the system prompt is
    `qwen_sys_prompt` with model_type `"ds"`.
- `R:vulscan/utils/sys_prompts.py#L23` `qwen_sys_prompt = "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step."`
  This is also the system field of every training row (`~/.cache/vllmr/Distill-{DeepSeek,QwQ}.parquet`).
- Chat template: the checkpoint's `tokenizer_config.json`, i.e. the Qwen2.5 template `<|im_start|>{role}\n…<|im_end|>\n`
  plus `<|im_start|>assistant\n` as the generation prompt. Messages are `[system?, user]`, and the call is
  `LLM.chat(add_generation_prompt=True)` (`R:vulscan/model_zoo/src/model_zoo/vllm_model.py#L62-L152`).

### 2.3 User prompt
- Template: `R:vulscan/utils/sys_prompts.py#L78-L111` `reasoning_user_prompt`. Its sha256 is
  `20bd58e69cf4ae56459e03b5a42cc8043db9680ab94994114d2331aeeb124e61`, and a test checks that the copy is byte-identical.
  The long-context variant at `#L42-L77` is used only when the row has `stack_trace`.
- Filling: `R:vulscan/test/test_utils/utils.py#L361-L434` `create_reasoning_test_sample`:
  - `#L377-L386`: CWE list = `CWE_ID + RELATED_CWE`, shuffled with `random.sample` when `--random_cwe` is set.
  - `#L388-L393`: if policy, `policy += f"\n- {cwe_id}: {get_cwe_info(n)}"` per CWE.
  - `#L399-L400`: `if "QwQ" or "deepseek" in model_name:` is always true, so REASONING is
    `"You should STRICTLY structure your response as follows:"`. `--use_cot` does not change the prompt text; only
    `--use_own_cot` would.
  - `#L425`: `reasoning_user_prompt.format(CODE=code, CWE_INFO=policy, REASONING=reasoning, ADDITIONAL_CONSTRAINT="")`.
- Policy header: `R:vulscan/utils/sys_prompts.py#L40`. CWE text: `R:vulscan/utils/get_cwe_info.py#L10-L18` builds
  `Name + ". " + (Extended Description or Description)` from `datasets/cwe-details.csv` (LFS oid `70d35cc5…3283c3`).
- Their Juliet CWE-401 test file `datasets/test/function_level/c/CWE-401.json` is byte-identical to
  `~/.cache/vllmr/test-401.json` (sha256 `12955dc6…1abc`). All 41 rows have `CWE_ID ['CWE-401']` and
  `RELATED_CWE ['CWE-1333','CWE-703','CWE-404']`. Juliet accounts for 20 of the rows (10 files × bad/good), PrimeVul for 21.

### 2.4 Generation
- vLLM `SamplingParams(n=1, temperature=0.0, top_p=0.9, top_k=-1, max_tokens=8192, seed=42)`. Sources:
  `R:vulscan/test/test.py#L287-L312`, `R:vulscan/test/test_utils/generation_utils.py#L209-L217` (`run_default_model`:
  temperature 0 when n == 1, top_p 0.9) and `R:vulscan/model_zoo/src/model_zoo/vllm_model.py#L62-L152`.
- Paper §5.3: maximum output length 8,192 tokens. VulnLLM-R averages **362** output tokens (Fig. 4).
- For model_type `"ds"` only, `R:vulscan/test/test_utils/generation_utils.py#L239-L313` `run_sft_model` stops at
  `"## Final Answer"`, appends `"\n</think>\n## Final Answer\n"` if it is missing, and continues for 200 tokens.
- The paper's §3.2/§4.2 test-time strategies ("truncated generation" and "policy-based generation": sample 4 times →
  2–5 CWE candidates → re-prompt) appear in the repo only as `--multi_run_with_related_cwe` (`test.py#L412-L841`). They
  are not part of the README command.

### 2.5 Output format and verdict parsing
- The model writes `<think>…</think>` reasoning, then `## Final Answer\n#judge: yes|no\n#type: CWE-xx|N/A`. The
  training targets have the same shape.
- `R:vulscan/test/test_utils/generation_utils.py#L133-L157` `extract_answer`:
  - Takes `output.split("## Final Answer")[-1].lower()`.
  - judge = text between `#judge: ` and `#type: `, falling back to `judge:`/`type:`. Only `yes` → yes, only `no` → no,
    anything else → `Invalid format`.
  - type = the rest of the `#type: ` line, upper-cased, or `N/A`.
- Scoring `#L450-L505`: invalid counts as wrong. A `yes` on a vulnerable sample is a TP only if the type holds exactly
  one `CWE-\d+` (`check_single_cwe`, `#L108-L112`) that matches the target.

## 3. What our runs send (exact)

`vulnllmr_prompt.py` copies the strings above. The user message for one unit, with `{model_text}` being the unit's
`model_text` and the four CWE bullets in a per-unit shuffled order (section 3.1), is:

````
You are an advanced vulnerability detection model. Your task is to check if a specific vulnerability exists in a given piece of code. You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx). 

## You are given the following code snippet:
```
{model_text}
```


You should only focus on checking and reasoning if the code contains one of the following CWEs:
- CWE-401: Missing Release of Memory after Effective Lifetime. This is often triggered by improper handling of malformed data or unexpectedly interrupted sessions. In some languages, developers are responsible for tracking memory allocation and releasing the memory. If there are no more pointers or references to the memory, then it can no longer be tracked and identified for release.
- CWE-404: Improper Resource Shutdown or Release. When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set period of time or revocation.
- CWE-1333: Inefficient Regular Expression Complexity. Some regular expression engines have a feature called backtracking. If the token cannot match, the engine backtracks to a position that may result in a different token that can match. Backtracking becomes a weakness if all of these conditions are met: The number of possible backtracking attempts are exponential relative to the length of the input. The input can fail to match the regular expression. The input can be long enough. Attackers can create crafted inputs that intentionally cause the regular expression to use excessive backtracking in a way that causes the CPU consumption to spike.
- CWE-703: Improper Check or Handling of Exceptional Conditions. The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product.


You should STRICTLY structure your response as follows: 


## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.


## Example
- If the code is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A
````

(There is a trailing space after `(CWE-xx).` and after `follows:`, exactly as in the authors' literal.) Twenty fully
chat-templated dev prompts are in `build/prompts/layer1/dev20_policy.txt`.

- **System:** `You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step.`
- **CWE hint (`--cwe-hint policy`, default, supervisor-approved):** the `--use_policy` block with exactly the list in
  their Juliet CWE-401 rows (CWE-401, CWE-1333, CWE-703, CWE-404). The order is shuffled per unit as `--random_cwe`
  does, with `random.Random(int(sha256(f"{unit_id}|20261123")[:8 bytes])).sample(...)`, so it is deterministic and
  recorded in `extra.cwe_order`. The authors shuffle with the global `random` state (seed 42) in dataset order, so
  their exact per-row orders cannot be matched for our units.
- **`--cwe-hint none` (optional secondary run):** CWE_INFO = "", i.e. the README:40 command. This is also the
  training-prompt form: the non-long-context training prompts (8343/8343 DeepSeek rows, 8089/8089 QwQ rows) equal this
  rendering with the empty CWE line removed (`` ```\n\n\nYou should ``). The paper (§4.1) notes that the guideline was
  removed from training prompts.
- **Generation:** `temperature 0.0, top_p 0.9, top_k -1, repetition_penalty 1.0, seed 42, max_tokens 8192`, one call
  per unit. vLLM 0.34 accepts `top_k=-1` and treats it as disabled (`sampling_params.py:685`).
- **Prompt sha256** (`vulnllmr_prompt.prompt_sha256`, which covers system, template, header, reasoning, CWE list,
  descriptions and order rule): policy `275b9b80d866fcefb12cebdc9bc144a4055838f3742fe2357219292f8deb3d86`, none
  `13fd77f3f412d6316bd7fcce0a97892f5bdcf06d5507f854e86005c0c73f0262`. Both are recorded in every `.meta.json`.

### 3.1 Choices that are ours (documented deviations)
1. **System prompt `qwen_sys_prompt` instead of the template default.** Reason: this is the system prompt of all
   training rows, and the authors use it for local/secmlr checkpoints (test.py:225-249). Running the HF id literally
   would yield "You are Qwen, created by Alibaba Cloud…".
2. **No `"ds"` stop-at-`## Final Answer`-then-continue trick.** We make one plain greedy call, which is the authors'
   path for the HF id. Outputs that hit 8192 tokens are marked invalid.
3. **Policy hint on by default (supervisor decision).** Our L1 prompt names CWE-401, so a CWE-401 hint is the
   comparable setting. The `none` variant is kept as an optional secondary run.
4. **Code is our `model_text`.** Files are joined with `// ---- part i ----`, `#include "std_testcase.h"` is dropped
   and identifiers are `sym_N`. Their Juliet rows keep `#include "std_testcase.h"`, `namespace _A_namespace` and
   `f_xxxxxxxx` names.

## 4. Verdict mapping (supervisor decision)

`vulnllmr_prompt.verdict(output, finish_reason)` applies the authors' `extract_answer`, then:
- `pred = 1` iff `#judge: yes`, whatever `#type` says; `pred = 0` iff `#judge: no`.
- `pred = null`, `status = invalid` if the judge is unparseable (`Invalid format`) **or** `finish_reason == "length"`
  (truncated at max_tokens, even when a judge was emitted). `score.py` counts null as wrong. The invalid rate is in the
  meta.
- `extra.pred_strict` = 1 iff `#judge: yes` and `#type` is exactly CWE-401 (authors' TP rule).
  `extra.pred_type` / `pred_type_cwes` give the type. The meta's `yes_type_counts` shows how often "yes" names
  CWE-404, CWE-703, etc.

## 5. Prediction files

`results/vulnllm_r_7b/<layer>/<run_id>.jsonl` (README §4 format):
- Row fields: `method vulnllm_r_7b`, `strategy policy|nohint`, `model VulnLLM-R-7B`, `score null`, `pred`, `latency_s`
  (client-side request wall time) and `status ok|invalid|error`.
- `extra` holds `prompt_tokens, completion_tokens, finish_reason, judge, pred_type, pred_strict, truncated, cwe_order,
  attempts, errors, output_tail` (last 300 chars) and `raw` (path of the full outputs).

Full outputs go to `build/raw/<layer>/<run_id>.raw.jsonl`. This file is append-only: the last record per unit wins.
Resume skips units whose last record is ok/invalid. A config change (prompt sha, generation params, served name, layer,
units-file sha) refuses to reuse a run_id.

The `.meta.json` holds:
- status/pred/finish counts, invalid rate, token totals and means;
- prompt sha256 and full prompt spec, prompt module sha, generation params;
- model sha (HF revision, safetensors sha256s, sha of `model_files.sha256`) and the server `/v1/models` listing;
- start/end UTC, host, concurrency, `os.getloadavg()` at start and end;
- lock info (c1) and git HEAD.

Default run_ids: `<dev|eval|n25|api|rep100|lat300>[_c1]_<policy|nohint>_r1`.

## 6. `--c1-latency`

Runs on `latency300` (150 eval groups, 300 units) with concurrency 1:
- Takes `flock /tmp/cs224_latency.lock` on the client host (waits up to `--lock-wait`, 1200 s).
- Then requires load1 < 2.5 in every 15-s sample for 2 consecutive minutes.
- Refuses if the server reports `vllm:num_requests_running > 0`.
- Sends one unrecorded warm-up request.

Latency = client-measured HTTP round trip from dell to 184-toast (LAN), with no other request on the server.

## 7. Tests

`.venv/bin/python -m pytest -q tests/` (or `python3 -m unittest discover -s tests`): 17 tests.
- Template sha and byte equality with the authors' `sys_prompts.py` literals (when `/tmp/vulnllmr_repo` is cloned).
- CWE list = `test-401.json` rows; policy block; render.
- 9 hand-written outputs: yes/401, yes/404 (lenient 1, strict 0), no, last-Final-Answer-wins, no-`#` fallback,
  two CWEs, missing judge, `yes/no`, truncated.
- Fake vLLM server: bulk + 503 retry + resume, nohint run_id, refusal on changed config.
