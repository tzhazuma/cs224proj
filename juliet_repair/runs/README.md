# Run inventory

## Headline runs (used by `report/`)

| directory | model | units | calls | status |
| --- | --- | ---: | ---: | --- |
| `deepseek_test70_final` | `deepseek-v4.1-flash` | 70 | 70 | complete, 58/58 observable strict pass |
| `mimo_test70_final` | `mimo-v2.6-flash` | 70 | 72 | complete, 58/58 observable strict pass |

Each run contains:

- `manifest.json` — model/endpoint/prices/input hashes; no API key;
- `requests.jsonl` — one row per real HTTP call (usage, cost, latency, response hash);
- `results.jsonl` — one row per unit;
- `units/<unit_key>/attemptN/` — `request.json`, `response.json`, `patch.diff`,
  `eval.json`, `src/` and the compiled `eval/fixed` binary + stderr log;
- `summary.json` — aggregate metrics and cost.

## Parser-development runs

`parser_dev/` keeps earlier real runs made while the output parser was being
tightened/relaxed. They are not used for headline numbers:

- `deepseek_test70_v1` — 70/70 compile and 58/58 strict after offline re-parse, but
  11 units were retried because the live parser rejected responses that listed an
  unchanged file or omitted `explanation`.
- `mimo_test70_v2` — 70/70 compile and 58/58 strict after offline re-parse; the live
  parser rejected per-file `explanation` objects.
- `mimo_test70_v1` — partial run stopped after 12 units when the strict schema
  rejected a missing top-level `explanation`.
- `dryrun_deepseek`, `smoke_*` — prompt-size and one-unit API smoke checks.

The final runs use the parser that accepts a missing top-level explanation and
ignores unchanged files; the only remaining iteration triggers are real compile,
LSan, behaviour, or path/schema errors.
