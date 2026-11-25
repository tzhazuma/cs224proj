# Jev L4-D (`jev_l4d`): cloud decision-model ceiling on DeadFree

Jev (TypeSafe System One API, `jev-latest`, returned version **jev-1.14.0** on every one of the 19,477 calls) answers
the same pruned L4-D fact questions as Intern-Decision L4-D (`intern_l4d`) and LoRA L4-D (opt.) (`lora_l4d_opt`).
There is one noul question per request, and the unit verdict comes from `l4d/derive.py --souffle`.
Script: `llm/run_jev_l4d.py`. Outputs: `l4d_ft/results/jev_l4d/`. Freeze file: `l4d_ft/results/jev_l4d/FROZEN`.

## Protocol (mirrors `gpu/run_decide_l4d.py`)

- **Questions.** `l4d/build/questions_{layer1,layer3}.jsonl`, pruned by `l4d_ft/prune.py prune()` (the user-approved
  "opt" pruning).
  - layer1 dev: 6,332 → 1,916 questions over 660 units (63 units have no kept question, so pred 0 with no call).
  - layer3 eval: 37,376 → 15,619 questions over 2,656 units (every unit has a kept question).
- **Request.** `{"model": "jev-latest", "state": <question state, unchanged>, "questions": {"answer": {"type": "noul",
  "instructions": <question text, unchanged>, "criteria": {"true": "The answer to the question is Yes.", "false":
  "The answer to the question is No."}}}}`. p_yes is the noul probability. Answer rows follow the l4d/README §4
  schema (`logit_diff` null, `fold` null), plus token, cost and latency fields.
- **Criteria were not refined** after the 40-unit layer1-dev pilot (`pilot_r1`, 143 q, $0.0037). In the pilot the
  only weak qtype was realloc_safe (acc 0.23). There the gold is Yes in the vacuous `realloc(NULL)` + `exit` on NULL
  cases, while Jev gives p≈0.25–0.34. Neutral wording cannot address this, and leaving the criteria alone avoids a
  free parameter. Every other qtype had acc ≥ 0.84.
- **Thresholds.** Primary τ = 0.5 was fixed before any call (parent, 2026-11-24 19:05). The secondary τ is the
  `run_decide_l4d.py` select rule on all 660 layer1-dev units: max unit macro-F1 over TAU_GRID, ties broken by
  smallest |τ−0.5|.
- **FROZEN** (2026-11-25T03:18:13Z, written before any eval call) contains τ 0.5, τ_secondary 0.268941, dev F1 at
  both τ, the request template, the criteria, the client/retry config, the model version and the hashes.
  - Every hash shared with `l4d_ft/results/intern_l4d/FROZEN` is identical: templates, templates.py, questions.py,
    derive.py, l4d.dl, prune.py, questions_layer1/3.
  - It also hashes the script, `llm/llmlane/clients.py` and `llm/llmlane/prompts.py`.
  - The eval, units and latency commands refuse to run unless FROZEN matches.
- **Ledger.** Calls go through the existing `JevClient.ask`, retry policy and ledger. Ledger rows use provider `jev`,
  purpose `jev_l4d`, strategy `L4D`, plus run_id/layer/set/unit_id. Concurrency was 8 for dev and eval (same as the
  earlier Jev eval runs). There were 0 failed calls and 0 retries in dev and eval.

## Dev (layer1 dev, 660 units)

| τ | macro-F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|
| 0.5 (primary) | 0.9453 | 330 | 36 | 294 | 0 |
| 0.268941 (secondary, dev-selected) | 0.9818 | 321 | 3 | 327 | 9 |

## Eval (layer3 = DeadFree, 2,656 units; family-cluster bootstrap 2,000, seed 20261123)

| method | macro-F1 [95% CI] | P(leak) | R(leak) | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|
| **Jev L4-D @0.5 (primary)** | **0.907 [0.875, 0.935]** | 0.847 | 0.995 | 1321 | 238 | 1090 | 7 |
| Jev L4-D (dev τ 0.27, secondary) | 0.944 [0.918, 0.963] | 0.947 | 0.941 | 1249 | 70 | 1258 | 79 |
| Jev L3 @0.5 | 0.949 [0.918, 0.970] | 0.956 | 0.941 | 1249 | 57 | 1271 | 79 |
| Jev L1 @0.5 | 0.946 [0.915, 0.968] | 0.950 | 0.941 | 1250 | 66 | 1262 | 78 |
| DeepSeek L4 | 0.900 [0.887, 0.913] | 0.914 | 0.884 | 1174 | 111 | 1217 | 154 |
| LoRA L4-D (opt.) | 0.826 [0.809, 0.842] | 0.829 | 0.823 | 1093 | 226 | 1102 | 235 |
| Intern-Decision L4-D @0.5 | 0.799 [0.770, 0.823] | 0.805 | 0.791 | 1050 | 255 | 1073 | 278 |

Paired differences (a − b, same family-cluster resamples):

| a − b | Δ macro-F1 [95% CI] |
|---|---|
| Jev L4-D − Jev L3 | −0.042 [−0.071, −0.013] |
| Jev L4-D − LoRA L4-D (opt.) | +0.081 [+0.047, +0.111] |
| Jev L4-D − DeepSeek L4 | +0.007 [−0.028, +0.039] |
| Jev L4-D − Jev L1 | −0.039 [−0.069, −0.009] |

Versus DeepSeek: Jev L4-D − DeepSeek L1 is +0.044 [+0.015, +0.071], and the gap closed is 1.13 for DS-L1 and 1.02 for
DS-L4.

**Reading.**
- With the same fact questions and the same symbolic derivation, Jev beats both local decision models by a wide margin
  (+0.081 over LoRA L4-D (opt.)).
- Jev L4-D is still significantly below Jev's own whole-unit L1/L3 noul questions. It ties DeepSeek L4.
- At 0.5 the errors are almost all false leaks (FP 238, FN 7). 169 of the 238 FP units contain a wrong realloc_safe
  answer (112 have only realloc_safe wrong), 36 have only exec_all wrong and 28 only rel wrong.
- The dev τ 0.27 removes most of these FP, but this threshold is secondary by the pre-specification.

## Per-qtype fact accuracy vs gold (same 12,081 pruned eval questions with non-null gold)

Gold is the question's `gold` field. LoRA L4-D (opt.) is lora_l4d `eval_r1` restricted to the pruned qids, with the
per-fold τ of `l4d_ft/FROZEN` (0.817574 / 0.5 / 0.5). Each cell is acc (FP/FN).

| qtype | n (gold Yes) | Jev @0.5 | Jev @0.27 | Intern @0.5 | LoRA L4-D (opt.) |
|---|---|---|---|---|---|
| heap | 2267 (1845) | 1.000 (0/0) | 1.000 (0/0) | 1.000 (0/1) | 1.000 (0/0) |
| exec_any | 2791 (2776) | 0.996 (0/10) | 0.999 (2/0) | 0.986 (15/24) | 0.975 (4/67) |
| exec_all | 4858 (1362) | 0.975 (1/119) | 0.984 (13/67) | 0.784 (946/104) | 0.831 (530/292) |
| rel | 1642 (1181) | 0.851 (177/68) | 0.797 (294/39) | 0.719 (182/280) | 0.907 (136/17) |
| realloc_safe | 523 (439) | 0.216 (0/410) | 0.709 (84/68) | 0.145 (32/415) | 0.924 (15/25) |
| **all** | 12081 | **0.935** | 0.953 | 0.835 | 0.910 |

- Jev is the best of the three on exec_any/exec_all. These are the path questions that sink Intern (946 exec_all FP).
- Jev is weaker than the fact-FT LoRA on rel and especially realloc_safe. In the vacuous `realloc(NULL)` cases Jev
  says the original block is *not* released (p≈0.25–0.35) where gold says Yes. That is a gold-convention question,
  which the LoRA learned from training labels and a zero-shot model does not share.
- Source: `analysis/deadfree/jev_l4d_facts.py` → `jev_l4d_facts.json`.

## Per flow category (macro-F1; FP/FN)

| method | 01 (n=84) | 02-22 (n=1176) | 31-45 (n=420) | 51-68 (n=624) | 71-84 (n=352) |
|---|---|---|---|---|---|
| Jev L4-D @0.5 | 0.904 (7/1) | 0.867 (154/0) | 0.921 (33/0) | 0.949 (26/6) | 0.949 (18/0) |
| Jev L4-D (dev τ 0.27) | 0.916 (0/7) | 0.897 (58/63) | 0.974 (11/0) | 0.998 (1/0) | 0.974 (0/9) |
| Jev L3 @0.5 | 0.916 (0/7) | 0.906 (39/71) | 0.962 (16/0) | 0.998 (0/1) | 0.994 (2/0) |
| LoRA L4-D (opt.) | 0.869 (8/3) | 0.823 (106/102) | 0.843 (27/39) | 0.848 (45/50) | 0.770 (40/41) |
| Intern-Decision L4-D | 0.797 (10/7) | 0.779 (127/133) | 0.843 (43/23) | 0.810 (35/83) | 0.795 (40/32) |

## Latency (DeadFree latency300: the 300 layer3 eval units of `data/build/subsets.json` key latency300; c1)

- **End to end** = live tree-sitter site/question building (`l4d/questions.py make_questions`, `l4d/.venv` python)
  + prune + the unit's Jev calls + derive. The client is this machine (dell), the model runs in the cloud.
- **Setup.** Unit-level concurrency was 1 and the warm-up call was not timed. The run held
  `flock /tmp/cs224_latency.lock` (meta `latency_lock.held: true`); load1 was 1.59 at start (< 2.5, checked again
  after taking the lock) and 1.36 at end. Run window: 2026-11-25T03:53:39Z–03:58:57Z.
- All 300 units ok, 1,780 calls, 0 failed.

| figure | median s | p90 s | mean s |
|---|---|---|---|
| **Jev L4-D, primary: questions of a unit sent concurrently** (one thread per question) | **0.967** | **1.218** | 1.051 |
| Jev L4-D, secondary: sequential = parse/prune + Σ per-call latencies + derive | 5.487 | 10.860 | 5.806 |
| per call | 0.931 | 1.115 | 0.979 |
| parse + prune | 0.0018 | 0.0030 | |
| derive | 0.00007 | 0.00009 | |
| *reference:* Intern-Decision L4-D (sequential, local GPU) | 0.658 | 1.343 | 0.728 |
| *reference:* LoRA L4-D (opt.) | 0.472 | 1.018 | 0.556 |
| *reference:* Jev L3 | 0.923 | 1.123 | 1.007 |

- Questions per unit in latency300: median 6, p90 10, max 31. On full eval: mean 5.88, median 6, max 36.
- **Disclosure: the measurement modes differ.** Intern-Decision L4-D was measured *sequentially* (one /decide per
  question). The Jev primary is *concurrent within a unit*, the API analogue of the LoRA batching all of a unit's
  questions into one forward. The Jev sequential figure is the sum of the same calls' individual latencies, not a
  separate sequential run.
- **Live vs stored eval answers (same 300 units).** Max |Δp_yes| was 0.16. Jev is not bit-deterministic and p is
  returned to 2 decimals. **5 verdict flips out of 300** (accuracy vs truth 0.900 live):
  - `CWE401_Memory_Leak__int64_t_malloc_61__bad`
  - `CWE401_Memory_Leak__twoIntsStruct_malloc_61__bad`
  - `CWE401_Memory_Leak__malloc_realloc_int64_t_05__good`
  - `CWE401_Memory_Leak__malloc_realloc_int64_t_09__good`
  - `CWE401_Memory_Leak__malloc_realloc_struct_twoIntsStruct_07__good`

  Most are realloc units, whose p sits near 0.5. Quality numbers use the stored `eval_r1` answers.
- **Pareto.** In `deadfree_pareto.json` Jev L4-D (0.907, 0.97 s) is not on the frontier, because Jev L3 (0.949,
  0.92 s) dominates it. Adding it changed no other point's pareto flag.

## Tokens and cost

| run | calls | input tokens | cost USD |
|---|---|---|---|
| pilot_r1 (layer1 dev, 40 units) | 143 | 89,124 | 0.003743 |
| dev_r1 (layer1 dev, 660 units) | 1,916 | (2 segments) | 0.049854 |
| eval_r1 (layer3 eval) | 15,619 | 11,536,307 (mean 739/q, median 723; output 312,380) | 0.484525 |
| lat_smoke (3 units, pre-check of the latency code) | 19 | 11,582 | 0.000486 |
| lat300_c1 | 1,780 | 1,311,427 | 0.055080 |
| **lane total (ledger, purpose jev_l4d)** | 19,477 | | **0.593688** |

- The ledger's Jev total went from $1.946962 to **$2.540650**, of the user's $4.8 balance. The lane cap was $1.00 and
  the stop at $3.2 was never approached.
- No DeepSeek calls were made.

## Table changes (`analysis/deadfree/`)

- **`make_table.py`:**
  - New rows: `jev_l4d` (primary, "Jev L4-D @0.5") and `jev_l4d_devtau` (secondary, "Jev L4-D (dev τ 0.27)").
  - Four new `PAIRED_DELTAS` and one new NOTES entry.
  - The strategy × FT grid gets a new **last column "Jev (cloud)"** (parent decision, option A):
    L1 → `jev_L1` 0.946, L3 → `jev_L3` 0.949, L4 / L4-D → `jev_l4d` 0.907 (dev τ 0.27: 0.944).
- **`make_latency.py`:** new specs "Jev L4-D" (primary, concurrent) and "Jev L4-D (sequential, secondary)", both read
  from `l4d_ft/results/jev_l4d/layer3/lat300_c1.jsonl`.
- **Byte check.** Backups of every pre-existing output and generator are in `raw_logs/backup_pre_jev_l4d/`.
  `raw_logs/compare_pre_jev_l4d.py` checks that:
  - JSON lists match by key/method/(a,b), with order checked;
  - CSV and md lines are an ordered subset;
  - the grid matches with its last column stripped.

  Output is in `raw_logs/compare_pre_jev_l4d.out`. It reports 0 changed or removed values. Its one flagged item, "LEN
  notes 2 → 3", is the appended jev_l4d note; the old notes are an exact prefix. Everything else is additions only.
- Marker file `JEV_L4D_READY` written.

## Deviations and limitations

- **Primary τ 0.5 is not the dev optimum.** The dev optimum is 0.27, which reaches eval 0.944, on par with Jev L3. The
  primary was pre-specified, so the 0.27 figure is secondary only. Both τ were fixed before eval.
- **realloc_safe gold convention** (vacuous realloc(NULL)) drives most of the false leaks at 0.5. The criteria were
  deliberately not tuned (see Protocol).
- **Interrupted dev segment.** The first dev segment was killed by a tool timeout after 484 rows. It was resumed with
  qid skipping. Up to 8 in-flight calls may have been billed without a ledger row (≤ ~$0.0003).
- **Lost raw log.** The 3-unit `lat_smoke` raw API log was overwritten by its own units file when files were moved
  (`raw_logs/layer3/lat_smoke_units.jsonl`). Its 19 ledger rows are intact.
- **Non-determinism.** Jev answers are not deterministic: 5/300 latency verdicts differ from the stored eval answers.
  The eval is a single run (r1).
- **Different latency modes across methods:** concurrent vs sequential (see the Latency disclosure). The client is not
  the GPU host, and the API's network RTT is included.
