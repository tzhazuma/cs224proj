# VulnLLM-R-7B — run report (appendix baseline)

Run 2026-11-24, 06:27–07:54 PST, on 184-toast GPU 1 (one RTX 3090). vLLM 0.34.0 on :8005, `--max-model-len 12288`,
KV cache 105,472 tokens, 21.0 GiB on GPU 1. GPU 0 was not touched.
Model: `Virtue-AI-HUB/VulnLLM-R-7B` rev `8cd13d7a35f13b187102dba166413d4450836a40`; file sha256 in `model_files.sha256`.
Prompt/setup: the authors' own format, documented in `README.md` and `REPORT_prep.md`:
- system prompt `qwen_sys_prompt`, then the function-level detection user prompt with a 4-CWE "policy" hint list
  (CWE-401, CWE-1333, CWE-703, CWE-404, shuffled per unit, like their Juliet test rows);
- `#judge: yes/no` + `#type:` parse;
- T=0, top_p 0.9, top_k −1, repetition penalty 1.0, seed 42, max_tokens 8192;
- prompt sha256 policy `275b9b80d866fcefb12cebdc9bc144a4055838f3742fe2357219292f8deb3d86`.

Metrics: `pred` = **lenient** (`#judge: yes`, any type). `pred_strict` = yes **and** `#type: CWE-401`.
Scores come from `juliet_full/analysis/score.py` (bootstrap 2000) via `score_all.py`. JSON is in
`results/scores/` (`summary.json` plus one file per run and its `__strict` file).

## Scope (what was run and what was not)

| step | status |
|---|---|
| smoke (8 layer1 dev units) | done, not scored |
| layer1 dev (660) | done |
| layer1 eval (2,656) | done |
| layer3 / DeadFree eval (2,656) | done |
| placebo eval | **stopped at 07:06 PST after the user decided that cross-model comparisons use DeadFree only.** 829/2,656 units were done. The partial file was moved to `build/partial/placebo__eval_policy_r1.partial.{jsonl,meta.json}`. It is **NOT reported** and not scored. |
| original eval | **not run** (same decision) |
| no-hint secondary | DeadFree nested25 (664 units) |
| c1 latency | DeadFree latency300 (all 300 units; the 100-unit cap was not needed because 300 took 41 min) |

## Quality (eval set unless noted)

| run | n | macro-F1 [95% CI] | P | R | spec | FP | FN | invalid | strict macro-F1 [CI] | strict R |
|---|---|---|---|---|---|---|---|---|---|---|
| layer1 dev | 660 | .404 [.367, .445] | .569 | .088 | .933 | 22 | 301 | 0 | .391 [.356, .433] | .067 |
| layer1 eval | 2,656 | .398 [.384, .413] | .628 | .074 | .956 | 58 | 1,230 | 1 | .387 [.373, .403] | .058 |
| **DeadFree eval** | 2,656 | **.471 [.449, .495]** | .563 | .209 | .837 | 216 | 1,050 | 0 | .453 [.431, .475] | .161 |
| DeadFree latency300 (c1 run) | 300 | .450 [.406, .493] | .542 | .173 | .853 | 22 | 124 | 0 | .438 [.394, .478] | .133 |
| DeadFree nested25, policy hint | 664 | .458 [.423, .497] | .533 | .196 | .828 | 57 | 267 | 0 | – | – |
| DeadFree nested25, **no hint** | 664 | .399 [.373, .424] | .371 | .208 | .648 | 117 | 263 | 0 | .336 [.332, .344] | .003 |

- **Δ layer1 → DeadFree:** macro-F1 +.073 (strict +.066). McNemar on the same 2,656 units:
  - both right 1,089; DeadFree-only right 301; layer1-only right 279; both wrong 987;
  - p = 0.383, so the per-unit correctness does not change significantly.
  - The higher macro-F1 on DeadFree comes from more "yes" answers (recall .074 → .209), paid for with FPs
    (58 → 216). It is not better discrimination. Both layers are near the all-"no" floor (.333).
- **Placebo Δ:** not available (placebo not reported, see Scope).
- **Specificity by good kind:**

  | good kind | layer1 FP | layer1 spec | DeadFree FP | DeadFree spec |
  |---|---|---|---|---|
  | B2G (n = 621) | 48 | .923 | 86 | .862 |
  | G2B (n = 621) | 6 | .990 | 111 | .821 |
  | other (n = 86) | 4 | .953 | 19 | .779 |

  So DeadFree mainly creates FPs on G2B goods.
- **Invalid / truncation:** 1 of 9,592 scored generations was invalid
  (`CWE401_Memory_Leak__struct_twoIntsStruct_malloc_82__good`, layer1 eval). It hit the 8,192-token limit in a
  repetitive reasoning loop and gives `pred` null. It counts as wrong for end-to-end. No other run had a
  truncation; DeadFree eval has 0 invalid.
- **Hint vs no hint (DeadFree nested25, paired):**
  - with hint .458, without hint .399; McNemar policy-only right 137, no-hint-only right 81, p = 1.95e-4.
  - Without the hint, the model almost never says CWE-401: strict recall .003; yes types CWE-415 82, CWE-416 82,
    CWE-476 8, CWE-761 6, CWE-121 3, CWE-401 2, other 3.
  - The dead `free` that DeadFree inserts is read as a double free / use-after-free.
  - So the 4-CWE hint is needed for the model to name the target CWE at all.

### Predicted CWE types (`#type:` on "yes" answers)

| run | yes types |
|---|---|
| layer1 dev | CWE-401 36, CWE-703 8, CWE-404 7 |
| layer1 eval | CWE-401 111, CWE-703 23, CWE-404 21 |
| DeadFree eval | CWE-401 359, CWE-404 128, CWE-703 7 |
| DeadFree c1 | CWE-401 33, CWE-404 13, CWE-416 1, CWE-703 1 |
| DeadFree no-hint | see the hint section above |

The hint distractor CWE-1333 was never predicted.

### Comparison rows

These rows come from other lanes (`juliet_full/STATUS.md`, 2026-11-24). They are not recomputed here, and the unit
sets are the full eval unless noted.

| method | layer1 (L1) | DeadFree |
|---|---|---|
| **VulnLLM-R-7B (this run)** | **.398** | **.471** |
| DeepSeek L1 | .995 | .863 (L4 .900) |
| Qwen3.5-4B L1 | .754 | .533 (L3 .760) |
| LoRA (decision_ft) L1 | .984 | .372 (L3 .639) |
| Jev L1 | .971 | n/a here (nested25 Δ −.025 to −.031 vs layer1) |
| Intern-Decision L1 | .825 | n/a in STATUS.md |
| L4-D (preliminary, pooled 3 folds) | – | .826 |
| grep / clang SA / Infer / CodeQL | .701 / .855 / .815 / .882 | .333 / .855 / .815 / .766 |

On DeadFree, VulnLLM-R-7B scores below every other LLM row except the LoRA L1 row (.372). Like the LoRA L1 row, it
stays only slightly above the all-negative floor.

## Output length and time

| run | out tokens mean / median / p90 / max | latency median / p90 (s) | wall (s) | units/s | out tok/s |
|---|---|---|---|---|---|
| layer1 dev (conc. 64) | 372.7 / 371 / 477 / 654 | 19.06 / 24.43 | 202 | 3.26 | 1,216 |
| layer1 eval (conc. 64) | 374.2 / 365 / 475 / 8,192 | 19.09 / 24.63 | 901 | 2.95 | 1,104 |
| DeadFree eval (conc. 64) | 407.0 / 395 / 520 / 1,554 | 20.71 / 27.22 | 889 | 2.99 | 1,217 |
| DeadFree no-hint n25 (conc. 64) | 400.3 / 388 / 511 / 1,024 | 16.10 / 21.18 | 177 | 3.75 | 1,501 |
| **DeadFree c1 latency300 (conc. 1)** | 409.8 / 400 / 524 / 912 | **8.05 / 10.48** | 2,480 | 0.121 | 49.6 |

- **c1 conditions:**
  - `flock /tmp/cs224_latency.lock` acquired after 0 s, then a 2-min quiet wait; load1 0.51 at start;
  - one warm-up request (8.76 s, not recorded); 300/300 ok;
  - the GPU was used only by this server (GPU 1).
- **c1 latency** is end-to-end from dell over the LAN and includes about 400 reasoning tokens per unit at about
  50 tok/s.
- **Offline prep estimate vs measured** (`REPORT_prep.md` §4):
  - Output tokens: the paper's mean of 362 was close; measured 374 on layer1 and 407 on DeadFree. The Distill
    teacher lengths (≈ 1.2–1.7k) were far too long.
  - Wall time: 1 GPU, 362 tokens predicted 0.34–0.45 h for layer1 dev+eval; measured 0.31 h (1,103 s).
    For one 2,656-unit layer it predicted 0.27–0.36 h; measured 0.25 h.
  - c1: it predicted 0.69 h; measured 0.69 h (2,480 s).

## Error analysis (raw outputs in `build/raw/<layer>/<run_id>.raw.jsonl`)

Counted with a keyword regex over the full reasoning. This is approximate.
- DeadFree eval: 845 of 1,050 FN mention "leak". 532 match the pattern "leak … not listed/specified/among …".
- layer1 eval: 1,201 of 1,230 FN mention "leak"; 790 match the same pattern.

So the main error is not missing the leak. The model **sees the missing free and then argues that a memory leak is
not one of the listed CWEs**, even though CWE-401 is in the list.

1. **FN, rejects its own finding** — `CWE401_Memory_Leak__char_calloc_01__bad` (DeadFree):
   "The key issue is the memory leak, but since the listed CWEs don't include memory leaks, there's no applicable
   vulnerability." → `#judge: no`.
2. **FN, redefines CWE-401** — `CWE401_Memory_Leak__char_calloc_10__bad` (layer1 dev):
   "'data' is allocated but never freed, but since it's not used after allocation, it's a leak, not a failure to
   release after effective lifetime. Thus, CWE-401 doesn't apply." → `no`.
3. **FN, fooled by the dead free** — `CWE401_Memory_Leak__char_calloc_05__bad` (DeadFree):
   "CWE-401 … doesn't apply because the code does free data in the first block." The free it cites is the inserted
   dead free.
4. **FP, use-after-free read as CWE-401** — `CWE401_Memory_Leak__char_calloc_12__good` (G2B, DeadFree):
   it reads the dead free plus a later use as "use-after-free … This directly corresponds to CWE-401". → `yes CWE-401`.
5. **FP without hint, double free** — `CWE401_Memory_Leak__char_calloc_22__good` (B2G, DeadFree no-hint):
   "when sym_1 is zero, 'data' is freed twice … double free … CWE-415". → `yes CWE-415`.
6. **Invalid** — `CWE401_Memory_Leak__struct_twoIntsStruct_malloc_82__good` (layer1 eval): it loops in "But wait …"
   reasoning until the 8,192-token limit.

## Services after the run (07:54–07:55 PST)

- :8005 VulnLLM-R stopped. GPU 1 was at 15 MiB, then `svc.sh qwen start`.
- :8001 qwen is healthy locally and over the LAN (HTTP 200), then `svc.sh decide start`.
- :8002 decide is healthy locally and over the LAN (HTTP 200). GPU 1 is at 19.5 GiB.
- **:8003 NOT up** (connection refused). GPU 0 had 17.1 GiB in use, :8004 was listening, and
  `~/disk4/cs224/GPU0_L4D_DONE` was absent, so per the rule it was **not** started.
- `~/disk4/cs224/GPU1_FREE_FOR_LATENCY` was touched at 07:54 PST.

## Files (sha256)

```
dafd71a07694bcb40475656dd91a41d4244e199db0c9d0b006a52b36339a8570  results/vulnllm_r_7b/layer1/dev_policy_r1.jsonl
9ae701a679e93710cdd0017ba92c4860eb0b74c0269dceebee42a57335d53401  results/vulnllm_r_7b/layer1/eval_policy_r1.jsonl
1af1fa002bc5e4b69cd8ed6abf9edd54990fd1c9eade637bda1a4750f8ebeead  results/vulnllm_r_7b/layer3/eval_policy_r1.jsonl
6a9d19ed735d6420196411774e368a09428883deaaedd266ea22b9cecf698987  results/vulnllm_r_7b/layer3/lat300_c1_policy_r1.jsonl
7b5fe5912b1c4c537acfce7a8694b60159aa80604db5527e93129b7be6ac72c0  results/vulnllm_r_7b/layer3/n25_nohint_r1.jsonl
```

Each run has a `.meta.json` next to it with the prompt sha, generation params, model sha, server listing, units
sha256, loadavg and lock info. `smoke_policy_r1` is a check run only. Rerun the scoring with
`python3 score_all.py --bootstrap 2000`, which rewrites `results/scores/` and `build/report_tables.md`.

## Caveats

- **Hint fairness:** VulnLLM-R gets a 4-CWE list that contains CWE-401, as its Juliet test set does. Our L1 prompt
  names memory leaks directly. Without the hint, the model almost never names CWE-401 (strict recall .003), so
  the hint run is its best fair setting here.
- **Contamination:**
  - Their training data contains Juliet templates of 19 other CWEs, but no CWE-401 labels. CWE-401 appears only in
    some teacher reasoning (48 DeepSeek / 26 QwQ rows).
  - Their test set contains 10 Juliet CWE-401 files.
  - Our units are renamed (`sym_N`) and reformatted, so exact overlap is unlikely, but it was not checked per unit.
- **Single run:** greedy decoding, one run per setting, no repeat runs. vLLM batching nondeterminism is not measured
  for this model.
- **Placebo and original:** no VulnLLM-R numbers, by the user's DeadFree-only decision. The partial placebo file
  must not be used.
