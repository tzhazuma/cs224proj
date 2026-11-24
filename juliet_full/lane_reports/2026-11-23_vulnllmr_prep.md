# vulnllmr-prep report (2026-11-24)

VulnLLM-R-7B is ready to run: the model is on both hosts, the server script, runner, tests and run plan are written,
and offline estimates are done. Nothing was started on the 184-toast GPUs, and no running service there was touched.
To launch, follow `RUNBOOK.md` (`nohup vulnllmr/run_all.sh 1 > vulnllmr/raw_logs/run_all.log 2>&1 &`).

## 1. What the model is told

The user message is the verbatim chat form of the authors' `reasoning_user_prompt`
(`vulscan/utils/sys_prompts.py:78-111` @ `5357371a`), filled as in `vulscan/test/test_utils/utils.py:361-434`.

- **System:** `You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step.`
  (`sys_prompts.py:23`; the system field of every training row.)
- **User:** the full text is in `README.md` §3, and a test checks it byte-for-byte against `vulnllmr_prompt.render_user`.
  It is:
  - the fixed task sentence;
  - `## You are given the following code snippet:` + the unit's `model_text` in a code fence;
  - the CWE hint;
  - `You should STRICTLY structure your response as follows:` and the `## Final Answer / #judge: <yes/no> / #type:`
    format, the "exactly one CWE" constraints, and the CWE-79 / N/A examples.
- **CWE hint (default `policy`):** `You should only focus on checking and reasoning if the code contains one of the
  following CWEs:` followed by 4 bullets, `- CWE-xxx: <Name>. <Extended description>`:
  - the CWEs are CWE-401, CWE-1333, CWE-703 and CWE-404, i.e. `CWE_ID + RELATED_CWE` of every row of their Juliet
    CWE-401 test file (identical to `~/.cache/vllmr/test-401.json`, sha256 `12955dc6…1abc`);
  - the descriptions come from their `datasets/cwe-details.csv`;
  - the order is shuffled per unit (`--random_cwe` analogue, deterministic seed `sha256(unit_id|20261123)`).

  This is their `--use_policy` path, which `README.md:224-258` "our model", `run_test.sh` and `train_test.py` use.
- **Optional `--cwe-hint none`:** no CWE list. This is their headline README:40 command and matches the training-prompt
  form.
- **Chat template:** Qwen2.5 (`<|im_start|>system … <|im_end|><|im_start|>user … <|im_end|><|im_start|>assistant\n`)
  from the checkpoint's tokenizer_config. 20 rendered dev prompts are in `build/prompts/layer1/dev20_policy.txt`.
- **Prompt sha256:** policy `275b9b80d866fcefb12cebdc9bc144a4055838f3742fe2357219292f8deb3d86`, none
  `13fd77f3f412d6316bd7fcce0a97892f5bdcf06d5507f854e86005c0c73f0262`. The prompt module `vulnllmr_prompt.py` has
  sha256 `4c2629edcef5bcb748bc92f043e35b63c7ee6b5676c18aae8af152ad9bb0e223`.

## 2. Generation parameters and parsing (sources)

| param | value | source |
|---|---|---|
| temperature | 0.0 | `vulscan/test/test.py:130`; `generation_utils.py:209-217` (0 when n==1) |
| top_p | 0.9 (no effect at T=0) | `generation_utils.py:209-217` |
| top_k | -1 (off) | `vulscan/model_zoo/src/model_zoo/vllm_model.py:62-152` |
| repetition_penalty | 1.0 | vLLM default in their offline `LLM.chat`. Sent explicitly because the checkpoint's generation_config has 1.05 |
| seed | 42 | `test.py:97` |
| max_tokens | 8192 | `README.md:40`, `run_test.sh:8`, `train_test.py:76-89`, paper §5.3 (`test.py:109` default is 16384) |
| n | 1, one greedy call | `test.py` default. The paper's policy-based multi-sampling is not used in the README command |

Parsing follows the authors' `extract_answer` (`generation_utils.py:133-157`): it reads the last `## Final Answer` block
and `#judge: yes|no`. Supervisor-approved mapping:
- `pred=1` iff `#judge: yes`, whatever the type;
- `pred=null` (invalid) if the judge is unparseable or the output is truncated at 8192 tokens;
- `extra.pred_strict` = yes AND `#type` CWE-401, which is the authors' TP rule (`generation_utils.py:473-483`).

## 3. Files and sha256

Model `Virtue-AI-HUB/VulnLLM-R-7B` @ `8cd13d7a35f13b187102dba166413d4450836a40`: 15,247,766,004 bytes, 21 files. All
sha256s are in `model_files.sha256`. The safetensors are:

| file | sha256 |
|---|---|
| model-00001-of-00004.safetensors | `d4144e04a93cc1cc9597e0f6be4482dd4c3fdc977d05750ca5e75070a8a77b9f` |
| model-00002-of-00004.safetensors | `98f08b8b8aa161bb8e09372a0722bb2526bc2715118f6159f922607c9fde7233` |
| model-00003-of-00004.safetensors | `24df8ea9836da349bb165dfac07269c61919f32554fb1d80400e9e67141680f4` |
| model-00004-of-00004.safetensors | `87e8a73cb26cdb9e5f963b420d52b0d1af812374ff5808b2a9bac3b33e5b718d` |

Other model files: `config.json` `fbf2c04b…3ada3161` and `tokenizer.json` `9c5ae00e…fdafa`.

- The 6 LFS files match the HF etags.
- `184-toast:~/disk4/cs224/models/VulnLLM-R-7B` was re-hashed on the host and matches all 21 files.
- The copy was made with `nice -n 19 ionice -c3 rsync -a --partial --bwlimit=40000 --exclude=.cache`.

Lane files in `juliet_full/vulnllmr/`:
- `vulnllmr_prompt.py`, `run_vulnllmr.py`, `serve_vulnllmr.sh`, `run_all.sh`, `estimate_offline.py`,
  `tests/test_vulnllmr.py`;
- `README.md`, `RUNBOOK.md`, `REPORT_prep.md`, `model_files.sha256`, `.gitignore`;
- git-ignored: `build/`, `scratch/`, `raw_logs/`, `.venv/`.

`serve_vulnllmr.sh` sha256 is `63950964560d27cb7cac4d4b00d485edaab352348e9c508155ca7cacf5918d5d`, identical to the copy
at `184-toast:~/disk4/cs224/vulnllmr/serve_vulnllmr.sh`.

## 4. Token and time estimates (`build/estimate.json`; CPU tokenizer, chat-templated, policy hint)

**Prompt tokens** (mean / p95 / max):

| set | mean | p95 | max |
|---|---|---|---|
| dev 20 units | 703.7 | 767 | 767 |
| dev 20 units, nohint | 397.7 | 461 | 461 |
| layer1 | 735.4 | 818 | 995 |
| layer3 | 780.1 | 873 | 1075 |
| placebo | 774.5 | 864 | 1027 |
| original | 830.7 | 1068 | 1262 |
| their Juliet CWE-401 rows | 992.2 | — | 1303 |

The max prompt plus 8192 output tokens is about 9.5k, which fits in `--max-model-len 12288`.

**Output tokens:**
- The paper (§5.3) gives a VulnLLM-R mean of 362.
- The teacher trajectories on Juliet rows are longer: DeepSeek mean 1190 (median 769, p95 3329); QwQ mean 1665
  (median 921, p95 5201). These are upper bounds, from before the authors' summary-based training.

**GPU wall-clock (h).** Assumes 1000–1500 tok/s aggregate decode and 6000 tok/s prefill per 3090; 2 GPUs = half.

| job | out 362 (1 GPU) | out 362 (2 GPUs) | out 724 (1 GPU) | out 724 (2 GPUs) | out 1427 (1 GPU) | out 1427 (2 GPUs) |
|---|---|---|---|---|---|---|
| (a) layer1 dev+eval, 3,316 units | 0.34–0.45 | 0.17–0.22 | 0.56–0.78 | 0.28–0.39 | 0.99–1.43 | 0.49–0.71 |
| (b) layer3+placebo+original eval, 7,968 units | 0.83–1.10 | 0.41–0.55 | 1.36–1.90 | 0.68–0.95 | 2.40–3.45 | 1.20–1.73 |
| (b) one layer eval, 2,656 units (layer3) | 0.27–0.36 | 0.14–0.18 | 0.45–0.63 | 0.23–0.32 | 0.80–1.15 | 0.40–0.57 |
| c1 latency300, 300 units, about 45 tok/s single stream | 0.69 | — | 1.36 | — | 2.66 | — |

- The throughput numbers are assumptions, not measurements; nothing was run on a GPU.
- Re-estimate after the layer1 dev run, using `completion_tokens_mean` and `wall_s` in its meta.

## 5. Disk on 184-toast

- `~/disk4` had 49G free before the copy and **34G free after** (67G used of 100G), so the ≥ 25 GB rule holds.
- The model takes 15.25 GB. `~/disk4/cs224/vulnllmr/` holds only the serve script; at run time it will also hold logs
  and a pid file, a few MB.
- Results stay on dell.

## 6. Open questions and risks

1. **CWE-hint fairness vs our L1.**
   - The policy hint gives the model the target CWE (with 3 distractors), like our CWE-401-specific L1 prompt. It
     also gives CWE-404, which is semantically close to 401. "Yes" answers typed CWE-404 count as positives under
     `pred` but not under `pred_strict`. Report both, with `yes_type_counts`.
   - The no-hint variant (their README:40 command and their training form) is only an optional nested25 run.
2. **Contamination and training scope.**
   - Their training data (Distill-DeepSeek 8775 rows, Distill-QwQ 8484 rows) has no CWE-401 label (`cwe` column), and
     no user prompt contains "CWE-401".
   - It does contain about 2.3k Juliet-template rows over 19 other CWEs: 121, 134, 176, 190, 191, 23, 319, 327, 338,
     367, 369, 400, 416, 457, 476, 526, 758, 761, 843. So the Juliet scaffolding (printLine, the STATIC_CONST_* flow
     variants, good/bad structure) was seen in training.
   - The teacher reasoning mentions "CWE-401" in 48 DeepSeek and 26 QwQ rows (34 and 18 of them Juliet-like), as a
     considered alternative.
   - Their CWE-401 test set has 10 Juliet CWE-401 files (20 rows, e.g. `CWE401_Memory_Leak__new_array_TwoIntsClass_15.cpp`)
     plus PrimeVul rows. Their train split `CWE-401.json` has 7 PrimeVul benign rows only.
   - We did not check whether those 10 Juliet files overlap our units. Their test rows mark test, not training, so
     overlap would not be contamination.
3. **Distribution shift in code form.** Our `model_text` drops `#include "std_testcase.h"`, renames identifiers to
   `sym_N`, and concatenates multiple files with `// ---- part i ----` markers. Their Juliet rows keep the include,
   `namespace _A_namespace` and `f_xxxxxxxx` names.
4. **System prompt.** We use `qwen_sys_prompt`, the training system prompt and the authors' path for local
   checkpoints. Their exact README command with the HF id would instead get the Qwen2.5 default system prompt. We also
   skip the `"ds"` stop-at-Final-Answer/continue trick and make one plain greedy call.
5. **Not tested against a real server** (GPUs busy):
   - `--data-parallel-size 2` on vllm 0.34. The fallback is a single GPU.
   - Reachability of `10.15.89.184:8005` from dell. The fallback is an ssh tunnel (RUNBOOK §2).
   - The 0.90 memory split. Weights 14.2 GiB plus about 5.5 GiB KV fits only on an otherwise empty 3090, and the
     script refuses if the GPU has > 1 GiB in use.
6. **Truncation:** 8192-token outputs count as invalid (null → wrong in score.py). The teacher-length tails (p95 3.3–5.2k)
   suggest this will be rare, but `finish_reason_counts` in the meta must be checked.
7. **Latency semantics:** `latency_s` is the client round trip from dell over the LAN with concurrency 1 on an idle
   server. It includes network and HTTP overhead and is not comparable to on-device timings.
