I've updated the deck for stage 2. `make` re-scores every result file and rebuilds `main.pdf` (41 pages), `make check` reports no errors or overfull boxes on any page, and I checked the rendered pages by eye. Qwen/Intern-Decision runs that land later are picked up with no edits; anything still missing is drawn grey and printed as "pending".

**How the talk runs (18 numbered slides, 17:00 in `notes.md`):**
- **Motivation (1–3):**
  - The opening table now uses only original-Juliet runs. `static void` ⇒ good scores 1.000; grep scores .935; DeepSeek .961 (nested25); Clang SA .822, CodeQL .785, Infer .770.
  - Then the template example and the research questions.
- **Benchmark (4–7):** layer ①, probes, layer ③ with placebo, flow-variant split.
- **Methods (8–10):** method matrix, L1–L4 with the Datalog pipeline, "one 4B model, three uses".
- **Results (11–15):**
  - **Layer ① bar chart:** I decluttered it by leaving out the L2 rows and Valgrind. The full version is in backup.
  - **Pareto:** deployment bands and the ASan/LSan dashed line.
  - **Robustness (the key slide):** paired, with placebo.
  - **LoRA shortcut:** .984 → .372, leak recall .041; without LoRA .703 → .619.
  - **L4:** Δ −.078, the smallest drop; errors shift to misses (false positives/misses 30/40, against 54/25 for L1).
- **Demo, limitations, take-aways (16–18):**
  - The demo slide shows the stage unit, the edit, and the dry-run verdict table.
  - The limitations slide covers all five points from your brief, plus contamination.
- **Backup (16 frames):** full bar chart and robustness figure, heatmap, mechanisms, repeat runs plus merged vs unmerged (0 of 2,656 predictions differ), CodeQL batching (+4 false positives), cost (DeepSeek ≈ ¥8.13, Jev ≈ $1.89), latency table with sources, label checks, dynamic reference, demo replay, SecVulEval, and 4 generated frames listing every result file.

**New finding:** the robustness figure shows two different ways to fail on layer ③, and I added this to slide 13:
- **Misses (they trust the dead `free`):** grep loses 1,155 detections, CodeQL 309, LoRA L1 1,234.
- **False alarms (they doubt a guarded real `free` in good units):** Qwen L1 adds 674, Intern-D L1 603, Intern-D L3 506.

**Changes to check:**
- **Coverage rule:** I raised `min_coverage` from 0.9 to 0.995. Otherwise a run file that is still being written could be scored with its missing units counted as wrong. A finished run that is missing more than about 13 of 2,656 units will stay "pending" until you lower it.
- **Placebo wording:** Qwen L1's placebo landed during the session at −.063 (against −.221 on layer ③), so the slide now says "placebo moves much less", not "barely moves". Re-read slides 13–15 after the late runs: the numbers update themselves, but sentences naming methods may not.

**Where the numbers come from:**
- **Result numbers:** through `\res`, computed by `score.py` (eval set, bootstrap CIs) from the exact files listed with hashes in the backup frames.
  - On the slides: grep original .935; CodeQL .882; DeepSeek L1 .995; LoRA L1 .984 / .372 (recall .041) / placebo .976; read-out L1 .703 → .619; LoRA L3 .639 (recall .379); DeepSeek L4 .976 with Δ −.078 against L1's −.118; Qwen L4 .790 → .706.
  - In backup: unmerged .984 / .983 with 0 / 0 differing predictions; ASan/LSan .945; dynamic_enhanced 1.000.
- **Generated tables:**
  - Opening table: original runs; the probe row comes from `data/build/probes.json`.
  - Demo table: `presentation/demo/recordings/stage_dryrun.json`.
  - Cost table: `juliet_full/llm/ledger.jsonl`.
  - Repeat table: the eval and rep run files.
  - Latency: `figures/latency_c1.csv`, which has a source column (lane reports and STATUS).
- **Typed into the slides:**
  - Dataset counts, the G2B/B2G 323/323 split, and the split sizes: `data_stage1.md` and STATUS.
  - Probe values .935→.701 and BoW .979: STATUS §5.
  - LoRA size (r16, α32, 0.70 %): `decision_ft_stage1`.
  - 99.87 % of L4 facts grounded: `llm_stage2c.md`.
  - Dynamic catch counts (1,448 / 34 / 68 / 108), realloc 0/84, and the 175 extra misses with default LSan: `data_stage4.md` and STATUS.
  - CodeQL 4 false positives and 7.36 s → 0.32 s: `static_stage2.md`.
  - BF16 rounding (|s| ≈ 15–40): `decision_ft_stage2.md`.
  - Budget cap ¥10 / hard stop ¥9.5: STATUS.
  - SecVulEval percentages: carried over from stage 1.

**Still pending at the last build (about 15:45 PST):**
- Qwen L1 original and L3 placebo.
- Intern-D L1 placebo, L1 original and L3 placebo.
- Qwen repeat runs, which only feed the backup repeat table.

Qwen L1 placebo and Intern-D L3 layer ③ arrived during the session and are already in.

To rebuild once the rest lands:
```bash
cd /home/barton/Documents/projects/cs224/cs224proj/presentation/pre && make && make check && make pngs
```

Everything I changed is under `presentation/pre/`. Nothing is staged or committed, and I made no API or GPU calls.