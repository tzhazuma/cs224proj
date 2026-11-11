# Hybrid evidence-guidance experiment (Juliet CWE-401, 140 test units)

This directory answers one question: does **real static/dynamic tool evidence**
make an LLM better at deciding whether a Juliet unit leaks memory, or does the
model merely react to the presence of tool output?

It is isolated from every other workflow. It reads the frozen Juliet subset,
the frozen static run, and the frozen dynamic run; it writes only under
`hybrid/`. No existing result is overwritten.

## 1. Fixed inputs

| Input | Path | SHA-256 |
| --- | --- | --- |
| Frozen units | `juliet/subset_units.jsonl` | `4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24` |
| Static predictions | `traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl` | `f9d2f59af172dd3b68af5ee84bc17ac784f53a95a3f07d61c2441bda66e26fa5` |
| Dynamic cases | `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/cases.jsonl` | `cc8db43b84f5eb106461cea6d86ac2b9934173c7ea5fe4abfb36690af1a7bc42` |
| Dynamic results | `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl` | `405381672467c146ac9e183f427be27fbff677be26844b6782d28a0f02218f64` |

The 140 test units are 70 bad / 70 good, 58 C / 82 C++. Dynamic cases are
joined by the exact source-set + compile-define key; all 140 units map to a
real case. Static rows already use the frozen `unit_id`.

## 2. Source cleaning

Sources use `juliet_llm.cleaning.clean_unit`, the shared cleaner, so `direct`
sees exactly the same code as the Juliet LLM baseline. That cleaner removes
comments, resolves `OMITBAD`/`OMITGOOD` with the unit defines, inlines local
headers, renames label-bearing identifiers, scrubs label-bearing strings, and
fails closed if a forbidden token survives. `hybrid/inputs/manifest.json`
records each unit's cleaning checks and code hash.

## 3. Tool evidence

Static evidence is rendered from the real Clang Static Analyzer and Cppcheck
rows: status, diagnostic count, memory-leak-related finding count, and up to
five sanitized messages. A compile failure is rendered as “analysis failed,
no conclusion”, never as clean.

Dynamic evidence is rendered from the real ASan/LSan and Valgrind results:
each detector's status, leaked byte counts for leaks, and the overall outcome.
The renderer distinguishes `leak`, `clean`, and `inconclusive`, and states
explicitly that **inconclusive is not clean**, as does every guided prompt.
Evidence text is scrubbed of absolute paths, file names, line references,
`CWE` identifiers, `OMIT*` macros, and `bad`/`good` identifiers. A regex gate
(`hybrid/sanitize.py:assert_clean`) fails the build if any survives.

`combined` concatenates the static and dynamic blocks. `shuffled` uses the
combined block of a different unit, chosen by a fixed-seed derangement
(seed `20261112`) that forbids both self-mapping and same-group donors, so a
placebo never receives evidence from its own bad/good sibling. The donor id is
stored for audit but never appears in a prompt.

## 4. Methods and prompt alignment

| Method | Evidence in the prompt |
| --- | --- |
| `direct` | none; byte-identical to `juliet_llm.prompting.build_messages` |
| `static` | static block |
| `dynamic` | dynamic block |
| `combined` | static + dynamic blocks |
| `shuffled` | combined block of a different unit (placebo) |

All methods use `juliet_llm`'s system prompt, leak definition, output schema
(`{"label": "vulnerable"|"not_vulnerable", "confidence": ..., "reason": ...}`),
temperature 0, JSON-object response format, and 8192 output tokens.
`run_hybrid.py --dry-run` rebuilds all prompts, audits them, and verifies the
140 direct prompt hashes against `juliet_llm/build/test.jsonl`; the recorded
audit is `hybrid/inputs/prompt_audit.json`.

Models:

| Key | Model ID | Endpoint | Prices (input/output/cached per 1M) |
| --- | --- | --- | --- |
| `deepseek` | `deepseek-v4.1-flash` | `https://opencode.ai/zen/go/v1` | $0.15 / $0.60 / $0.003 |
| `mimo` | `mimo-v2.6-flash` | `https://opencode.ai/zen/go/v1` | $0.14 / $0.28 / $0.0028 |

MiMo is run with `thinking=disabled`, `reasoning_effort=none`, and
`max_completion_tokens=8192`, matching the previously verified non-reasoning
configuration. DeepSeek keeps its prior non-thinking configuration.

Credentials are read from `/mnt/c/Users/tzh03/.kimi-code/config.toml` into
process memory only. They are never printed, stored in config files, or written
to results. `config.json` contains only the public API configuration.

## 5. Running

```bash
# prompt audit only (no network)
python3 hybrid/run_hybrid.py --model all --inputs-dir hybrid/inputs --dry-run

# full matrix: 2 models x 5 methods x 140 units = 1400 real requests
python3 hybrid/run_hybrid.py --model all --concurrency 12 \
  --inputs-dir hybrid/inputs --out-root hybrid/runs --run-id hybrid_v1

# analysis (writes per-run metrics and global tables)
python3 hybrid/analyze.py --runs-root hybrid/runs --run-id hybrid_v1 \
  --inputs-dir hybrid/inputs

# artifact audit
python3 hybrid/verify_outputs.py --runs-root hybrid/runs --run-id hybrid_v1 \
  --inputs-dir hybrid/inputs
```

`--limit N` marks a run as partial in its manifest; partial runs are never
used in the final comparison. `--resume` skips units already recorded.

### 5.1 Leak-fixed v2 rerun

The release audit (C3/D6) found `benign`/`fixed` string literals in six good
units. v1 is frozen and untouched. After `juliet_llm.cleaning` was updated to
neutralize those words, the v2 rerun uses a separate input pack and run id:

```bash
# rebuild the input pack from the updated shared cleaner
python3 hybrid/build_inputs.py --out hybrid/inputs_v2

# fail-closed gate: rebuilds all 140 sources and 700 prompts, refuses on a
# single label word, stale pack, changed placebo, or lost no-op collision
python3 hybrid/preflight.py --inputs-dir hybrid/inputs_v2 --run-id hybrid_v2

# prompt audit (no network)
python3 hybrid/run_hybrid.py --model all --inputs-dir hybrid/inputs_v2 \
  --run-id hybrid_v2 --preflight-report hybrid/results/hybrid_v2_preflight.json --dry-run

# full matrix: 2 models x 5 methods x 140 units = 1400 real requests
python3 hybrid/run_hybrid.py --model all --inputs-dir hybrid/inputs_v2 \
  --run-id hybrid_v2 --concurrency 12 \
  --preflight-report hybrid/results/hybrid_v2_preflight.json

python3 hybrid/analyze.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2
python3 hybrid/verify_outputs.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2 --out hybrid/results/hybrid_v2_audit.json
python3 hybrid/compare_versions.py
python3 hybrid/make_report_v2.py
```

`--preflight-report` is a hard gate: the run aborts unless the report says
`ok`, its prompt version equals the current builder, and its input-pack hash
matches the units being sent. The v2 prompt version is
`hybrid-v2-juliet-llm-binary-2026-11-12.2`. DeepSeek list prices now match the
provider snapshot ($0.15/$0.60 per 1M); provider allowance is unchanged.

## 6. Outputs

Each run directory `hybrid/runs/<run-id>_<model>_<method>/` (v1: `hybrid_v1_*`,
v2: `hybrid_v2_*`) contains:

- `config.json` — public model config, prices, prompt version, input hash;
- `manifest.json` — planned/recorded counts, status counts, elapsed time;
- `requests.jsonl` — per-request prompt hash, usage, cost, latency, status;
- `results.jsonl` — per-unit prediction, label, confidence, reason, usage, cost,
  latency, dynamic-evidence metadata, placebo donor (for `shuffled`);
- `metrics.json` — per-run metrics written by `analyze.py`.

Global outputs: `hybrid/results/hybrid_v1_metrics.json` (all metrics, paired
tests, tool baselines), `hybrid/results/hybrid_v1_tables.md`, and
`hybrid/results/hybrid_v1_predictions.csv` (all 1,400 per-unit predictions with
label, prediction, confidence, cost, allowance and latency). The narrative
report is `hybrid/REPORT.md`.

The v2 rerun writes the same artifacts with the `hybrid_v2` prefix, plus
`hybrid/results/hybrid_v2_preflight.json`, `hybrid_v2_prompt_audit.json`,
`hybrid_v2_audit.json`, and the v1↔v2 comparison
`hybrid_v2_vs_hybrid_v1.{json,md}`. Its narrative report is `hybrid/REPORT_V2.md`.

## 7. Scoring and statistics

- **Strict**: all 140 planned units; an invalid or failed request is counted as
  wrong, never as a correct negative. This is the headline number.
- **Valid-only**: drops invalid/failed requests and is always reported next to
  coverage.
- **Paired comparisons**: exact two-sided McNemar on strict correctness, plus a
  paired bootstrap 95% CI for the accuracy difference (10,000 resamples, seed
  `20261112`). Units are the resampling unit.
- Dynamic evidence diagnostics group model accuracy by the evidence outcome
  (`leak` / `clean` / `inconclusive`). A clean dynamic result on a truly bad
  unit is a false negative of the tool, not a clean label.
- The `shuffled` run is additionally broken down by donor label to check
  whether predictions track the donor's evidence rather than the code.

## 8. Limits

- Juliet units are small, synthetic, and single-defect; results may not transfer
  to production code.
- The static and dynamic evidence come from the same frozen runs used elsewhere;
  their errors are inherited.
- The dynamic run executes the harness's default path; a bad unit whose leak is
  not observed is still labelled bad (12 such units in test140). The LLM sees
  the “no leak detected in this run” message plus the explicit warning that this
  is not proof of absence.
- ASan and Valgrind statuses can be `inconclusive`; those are rendered and
  analysed as not clean. Test140 happens to contain no inconclusive dynamic
  case; the full 3,316-case run contains one, outside this split.
- The placebo tests whether *mismatched* evidence helps; it cannot prove that a
  model uses evidence causally in every individual answer.
