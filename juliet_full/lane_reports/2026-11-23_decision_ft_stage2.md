I finished stage 2. All six jobs, held-out predictions on every layer, and the zero-shot read-out ablation are done, collected to dell and scored with `analysis/score.py --set eval`. The :8003 endpoint is running on GPU 0 and matches the stored predictions exactly, and dell concurrency-1 latency was measured for L1 and L3. Nothing is committed or staged, and I did not touch GPU 1 after L3_fold1 ended.

**Selection** (dev AUROC is 1.0 at almost every half-epoch eval, so the choice is effectively by lowest dev loss; dev macro-F1 at the threshold is 1.0 for all six):

| job | checkpoint (epoch) | threshold | merge_check dev max / mean \|Δ\| |
|---|---|---|---|
| L1 fold0 | step107 (1.0) | 2.514 | 0.482 / 0.102 |
| L1 fold1 | step170 (1.5) | −2.656 | 0.354 / 0.076 |
| L1 fold2 | step336 (3.0) | −2.086 | 0.322 / 0.059 |
| L3 fold0 | step268 (2.5) | −0.738 | 0.404 / 0.093 |
| L3 fold1 | step57 (0.5) | 9.810 | 2.010 / 0.107 |
| L3 fold2 | step336 (3.0) | −0.278 | 0.348 / 0.123 |

- L3 fold1's threshold of 9.81 is the only midpoint in the dev gap (highest good −13.6, lowest bad 33.2).
- The merged vs unmerged differences are BF16 rounding on large scores (|s| ≈ 15–40). No held-out prediction flips between the two (0 of 2,656, for L1 and for L3).
- The stage-2 re-score equals the stage-1 files exactly, except L3 fold0's 28 `_67` units, whose evidence changed from full_v1 to full_v2.

**Eval scores** (merged, the reported variant; 2,656 eval units per layer; macro-F1 with 95% bootstrap CI; AUROC per fold 0/1/2):

| input | layer | macro-F1 | AUROC per fold |
|---|---|---|---|
| L1 | layer1 | 0.984 [0.982, 0.986] | 0.999 / 0.957 / 1.000 |
| L3 | layer1 | 0.983 [0.981, 0.986] | 0.999 / 0.981 / 1.000 |
| L1 | layer3 | 0.372 [0.346, 0.404] (recall 0.04) | 0.691 / 0.677 / 0.703 |
| L3 | layer3 | 0.639 [0.615, 0.665] (recall 0.38) | 0.911 / 0.867 / 0.888 |
| L1 | placebo | 0.976 [0.969, 0.982] | 0.999 / 0.948 / 1.000 |
| L3 | placebo | 0.970 [0.962, 0.976] | 0.999 / 0.982 / 1.000 |
| L1 | original | 0.944 [0.937, 0.949] | 0.991 / 0.943 / 1.000 |

- Fold 1 is the weak fold for both inputs (layer-1 macro-F1 0.953 for L1, 0.952 for L3).
- AUROC pooled over the three folds is lower (layer1 0.978 / 0.977) because it mixes three score scales, so I report per-fold values.
- Appendix, unmerged layer 1: L1 0.984 (AUROC 0.999 / 0.956 / 1.000), L3 0.983 (0.999 / 0.981 / 1.000).

**Read-out ablation** (base model + step-0 head):

| input | layer | macro-F1 at s > 0 | macro-F1 at dev threshold | AUROC |
|---|---|---|---|---|
| L1 | dev | 0.356 | 0.794 (thr −1.20) | 0.884 |
| L3 | dev | 0.337 | 0.833 (thr −1.65) | 0.905 |
| L1 | layer1 eval | 0.375 | 0.703 | 0.789 |
| L3 | layer1 eval | 0.345 | 0.773 | 0.862 |
| L1 | layer3 eval | 0.351 | 0.619 | 0.729 |
| L3 | layer3 eval | 0.334 | 0.671 | 0.820 |

At s > 0 the base model almost always answers "No" (leak recall 0.001–0.039). It ranks reasonably but is badly calibrated, so most of the F1 gain comes from the LoRA.

**Endpoint :8003** (GPU 0, pid 1336344, 15.3 GB; start/stop/status documented in README §10):
- The first start returned HTTP 422 on every `/score` call. The cause was a `Request` type annotation that FastAPI could not resolve. I changed the handler to `req: dict = Body(...)` in `server/stage2.py`, re-uploaded and restarted the server.
- `/health` returns ok with all 6 models. Switching models costs about 211 ms.
- Spot check: 20 held-out units from all six models plus 2 dev units (L1 fold1 bad, L3 fold2 good). All 22 match the stored scores exactly (|Δ| = 0.0), with identical prompt hashes and preds.

**Latency** (latency300, dell, concurrency 1, under `flock /tmp/cs224_latency.lock`): dell was already quiet (load1 1.16) when the lock was taken, so there was no wait.

| input | load1 start → end | end-to-end median / p90 | server median / p90 |
|---|---|---|---|
| L1 | 1.16 → 1.61 | 0.105 / 0.130 s | 0.084 / 0.111 s |
| L3 | 1.61 → 2.16 | 0.133 / 0.148 s | 0.113 / 0.116 s |

A short single-core `score.py` run of mine overlapped part of the L1 measurement; load stayed under 2.5 throughout. This is noted in the README.

**GPU 0:** only the :8003 server; idle at 0% utilisation, 16.3 GB used. GPU 1 runs the gpu lane's vLLM and Intern services.

Changed files: in `juliet_full/decision_ft/`: `README.md` (§1, §2 full_v2 evidence and v1 incident, §6, §7, new §8–§11), `server/stage2.py`, `server/stage2_run.sh`, `server/serve.sh`, `upload.sh`, `collect.sh`, `endpoint_client.py` (now also checks 2 dev units), new `score_all.py`, plus collected `results/` and `runs/` (`score/`, `endpoint/`, `logs/`, `L*/fold*` small artifacts). On the server, only `~/disk4/cs224/decision_ft/` changed.

Validation: render-check showed 0 mismatches; the endpoint spot check passed (max |Δ| 0.0, 22 of 22); `score_all.py` ran on all 13 result sets with no missing or invalid units; shell syntax checks pass; nothing is staged.

Open risks/questions:
- `juliet_full/README.md` §6 still says the :8003 endpoint is "not built yet". That file is outside my write area, so the parent should update it.
- The `latency_s` in the prediction files is server-side time, not dell-measured as contract §4 says. The dell end-to-end numbers are in the `latency300_*` files.
- Adapters stay on the server only (`./collect.sh --adapters` pulls them), as you asked.
- Dev AUROC saturates at 1.0, so selection is decided by dev loss values between 1e-7 and 1e-22. That is a weak selection signal.

Recommended next step: the parent updates contract §6 to show :8003 is live and puts the per-fold AUROC and the read-out ablation into the main tables.