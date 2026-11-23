# Reparse note — v2 triage raw validity 138/140

`results_triage.jsonl` was written with the original parser, which required
`alert_verdict = "no_alert"` whenever CodeQL raised no alert. Two units answered
`"uncertain"` instead:

- `CWE401_Memory_Leak__new_twoIntsStruct_82__bad`
- `CWE401_Memory_Leak__new_wchar_t_82__bad`

Both are CodeQL `compile_error` units. The model's `leak_present` was `true` and
its reason correctly described the unreleased `new` allocation; it used
`uncertain` because there was no alert to judge. The parser now accepts
`uncertain` on an absent alert, and `analyze.py` re-parses the stored `content`
in memory. **No API call was made for this reparse and the raw result files were
not modified.** The effective triage coverage is 140/140; the raw coverage is
138/140 and is reported as `triage_raw_valid` in `analysis/summary.json`.

The two units remain false negatives under the pure triage policy because there
is no CodeQL alert to keep or drop. The cascade policy can use `direct` on
no-alert units and recovers them, at the cost of 2 direct false positives.
