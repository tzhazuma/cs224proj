# 复现指南（REPRODUCIBILITY）

本文说明如何在 **WSL Ubuntu** 中从本仓库恢复数据、重算指标、重跑实验，以及哪些步骤需要网络/凭证、哪些结果不能逐字节复现。根目录 README 给出项目总览；本文只讲“怎么做”和“怎么验收”。

> 原则：**不覆盖原始结果**。所有重算/重跑都写到新目录（`/tmp/...` 或 `repro_*`），不要用 `--force` 覆盖 `runner/runs/`、`benchmark/results/`、`traditional/*/runs/`、`juliet_repair/runs/` 等冻结产物。

---

## 1. 环境

已在以下环境验证（2026-11-12，WSL2）：

| 组件 | 版本/说明 |
| --- | --- |
| WSL | Ubuntu，`Linux 6.18.*-microsoft-standard-WSL2` |
| Python | 3.14.8 |
| GCC / G++ | 15.3.0 |
| Clang / Clang++ | 22.1.8 |
| Cppcheck | 2.21.0（本机未装系统包；正式 run 用 `/tmp` 解包二进制） |
| Valgrind | 3.27.1（本机未装系统包；正式 run 用 `/tmp` 解包） |
| `httpx` | 0.28.1（runner 依赖） |
| `jsonschema` | 4.19.2（`bench_validate.py --jsonschema` 可选） |
| `openpyxl` | 3.1.5（仅 `build_datasets.py` 需要；本机未装） |
| Tectonic | 0.17.0（报告 PDF 编译；本机在 `/tmp/secvul-tectonic/`） |

安装 Python 依赖（按需）：

```bash
python3 -m pip install --user "httpx==0.28.1" "jsonschema>=4" "openpyxl==3.1.5"
```

Cppcheck/Valgrind 不要求 root 安装；`traditional/static/README.md` §1 和 `traditional/dynamic/README.md` §1.2 给出无 sudo 的解包方式。正式结果记录的是解包路径与版本，换机器后必须重新准备并记录。

---

## 2. 获取仓库与数据

### 2.1 仓库本身

```bash
git clone <your-private-repo-url> cs224proj
cd cs224proj
```

本仓库的 `.gitignore` **有意不提交**以下可再生数据：

| 路径 | 体积（本机） | 恢复方式 |
| --- | ---: | --- |
| `juliet/cache/juliet-c-cplusplus-v1.3.zip` | 146 MB | `python3 juliet/scripts/fetch_juliet.py` |
| `juliet/raw/` | 58 MB / 2,839 文件 | 同上（从归档提取） |
| `juliet/build/` | 27 MB | `python3 juliet/scripts/build_subset.py --jobs 6` 或 `verify.py --build` |
| `traditional/dynamic/runs/*/cases/` | 326 MB | 重跑 `run_dynamic_eval.py` |
| `**/runs/*/cache/` | 约 50 MB | 重跑对应 runner；缓存可由 `requests.jsonl` 重建 |
| `juliet_repair/build/baselines/`、`sanitized/`、`support/`、`selftest/` | 约 14 MB | `juliet_repair/scripts/check_baselines.py` |
| `repair_eval/packages/*/private/` | 约 100 KB | 不公开；盲评汇总仍保留在 `repair_eval/analysis/` |

**不要**为了“让 `sha256sum -c` 通过”而修改 `juliet/SHA256SUMS`；先恢复 `raw/`，再校验。

### 2.2 恢复 Juliet

```bash
python3 juliet/scripts/fetch_juliet.py
python3 juliet/scripts/verify.py
```

预期输出（本机实际运行）：

```text
manifest: juliet-cwe401-v1.3-subset-v1  units=200
  provenance: archive + 2839 raw files verified
  units: files/hashes/guards/split isolation verified (42 families)
  splits: dev=60 test=140
  near-duplicates: cross max=0.8231 < 0.85 (0 violations)
  SHA256SUMS: 2853 files verified
PASS
```

`fetch_juliet.py` 默认复用已有归档并做 HEAD/哈希核验；`--redownload` 强制重新下载，`--force` 重新解压。归档 SHA-256 必须等于：

```text
ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
```

若只需要数据卡而不恢复 raw：

```bash
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
# dataset validation ok: 200 units, 100 groups, 42 families
```

### 2.3 重建 SecVulEval 派生数据与 split（可选）

`build_datasets.py` 只依赖 `openpyxl` 和标准库。它默认写 `datasets/`；为避免覆盖冻结文件，先写到临时目录再比对：

```bash
python3 build_datasets.py --seed 42 --output-dir /tmp/secvul_datasets
sha256sum /tmp/secvul_datasets/*.json
```

冻结哈希（必须逐字节一致）：

| 文件 | SHA-256 |
| --- | --- |
| `SecVulEval.xlsx` | `3402fb572c1702491e121dbaa49f100ed0060ece06e18e2f6967766278a78a11` |
| `datasets/independent_200.json` | `055eccc29f640d47653f5289e6b7a9468fead248c05b137aec8779ba7461dc3d` |
| `datasets/vulnerable_fixed_200_pairs.json` | `7028b98d6f2c13b960bd08dd2e737e2ba61732b89dba03e3f173fe44c27214d5` |
| `splits/test_detection_160.json` | `bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8` |
| `splits/test_pairs_180.json` | `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d` |
| `juliet/subset_units.jsonl` | `4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24` |
| `juliet/manifest.json` | `8df222f84a4295f3b90ae7cabe165adc04858d91def3fda19a073db6e17cafd6` |
| `traditional/dynamic/.../cases.jsonl` | `cc8db43b84f5eb106461cea6d86ac2b9934173c7ea5fe4abfb36690af1a7bc42` |
| `traditional/dynamic/.../results.jsonl` | `405381672467c146ac9e183f427be27fbff677be26844b6782d28a0f02218f64` |
| `traditional/static/.../predictions.jsonl` | `f9d2f59af172dd3b68af5ee84bc17ac784f53a95a3f07d61c2441bda66e26fa5` |

验证 split（只读，不写文件）：

```bash
python3 splits/make_splits.py verify
```

> `splits/make_splits.py build` 会重写 `splits/` 并改变 `FREEZE.txt`；只有明确要创建新 split 时才使用，且必须同时改 `SPLIT_ID`。

---

## 3. 复现层级

| 层级 | 需要网络/凭证 | 做什么 | 典型耗时 |
| --- | --- | --- | --- |
| **L0** | 否 | 自检、数据卡校验、JSON 解析、哈希核对 | 1–2 分钟 |
| **L1** | 否 | 从已冻结 run 重算指标/leaderboard 到 `/tmp` | 1–5 分钟 |
| **L2** | 否 | 重跑 Clang/Cppcheck、ASan/LSan、Valgrind | 10 秒–20 分钟 |
| **L3** | 是 | 重跑 LLM/混合/修复实验 | 数分钟–数十分钟，按 API 计费 |

L0/L1/L2 是发布验收的核心；L3 受凭证、端点、价格和服务端非确定性影响。

---

## 4. L0：无网络自检

在项目根目录执行（WSL）：

```bash
export PYTHONDONTWRITEBYTECODE=1
cd /mnt/c/Users/tzh03/Downloads/cs224proj
```

### 4.1 工具自检

```bash
python3 benchmark/tools/selftest.py
python3 analysis/selftest.py
python3 -m juliet_llm.selfcheck
python3 hybrid/selftest.py
python3 pair_joint/selftest.py
python3 juliet_repair/scripts/selftest.py
python3 evidence_prompt/selftest.py
python3 -m repair_eval selftest
```

本次实际结果：

| 命令 | 结果 |
| --- | --- |
| `benchmark/tools/selftest.py` | `PASS: validator + detection/pair/leak metric arithmetic` |
| `analysis/selftest.py` | 7 项全 `[ok]`；fixture 已清理 |
| `python3 -m juliet_llm.selfcheck` | 6 项 `PASS`，含 `no credential-shaped artefacts` |
| `hybrid/selftest.py` | `ok: true`，140 units，5 methods |
| `pair_joint/selftest.py` | `all checks passed` |
| `juliet_repair/scripts/selftest.py` | `status: PASS`，4/4 control |
| `evidence_prompt/selftest.py` | prompt/validation/mapping/stats 全 `PASS` |
| `python3 -m repair_eval selftest` | `SELFTEST PASSED`，临时目录已删除 |

注意：`juliet_llm/selfcheck.py` 必须用 `python3 -m juliet_llm.selfcheck`（或 `juliet_llm/launch.py`），直接 `python3 juliet_llm/selfcheck.py` 会因相对导入失败。

### 4.2 数据卡与哈希

```bash
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
python3 juliet/scripts/verify.py          # 需要先恢复 juliet/raw/
```

`bench_validate_dataset.py` 的预期输出包含：

```json
{
  "ok": true,
  "counts": {"units": 200, "labels": {"bad": 100, "good": 100},
             "groups": 100, "families": 42,
             "splits": {"dev": {"units": 60}, "test": {"units": 140}}},
  "hashes": {"units_sha256": "4827d1da...", "archive_sha256": "ada9d7e1..."}
}
```

### 4.3 Secret scan（只读）

```bash
grep -rIl -E 'sk-[A-Za-z0-9_-]{16,}|Bearer [A-Za-z0-9._-]{20,}' \
  --exclude-dir=.git --exclude-dir=raw --exclude-dir=cache \
  --exclude-dir=build --exclude-dir=cases --exclude-dir=__pycache__ .
```

本机运行结果：**无匹配文件**。发布前仍应重跑，并按 `docs/SECURITY.md` 使用 `gitleaks`/`trufflehog` 做独立扫描。

### 4.4 最终质量/泄漏审计

`audit/final_audit.md` 是只读综合审计。**最新重跑（2026-11-11T21:30:46Z）为 58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`，must-fix 为空。** 5 个原 must-fix 均已关闭：

- **C3/D6**：`juliet_llm/cleaning.py` 已把 `benign`/`fixed`/`safe`/`clean` 纳入标识符与字符串清洗，prompt 版本升到 `juliet-llm-binary-2026-11-12.2`；`juliet_llm/build/audit_report.md` 的 11 类禁用 token 计数全为 0，`hybrid/inputs_v2` 的 700 条模板 / 1,400 条 run-level prompt 审计通过；v1 hybrid 的 6 个 test good 与 juliet_llm v1 的 8/200 全部保留为泄漏对照。
- **I3**：repair all-in 统一为 `$0.082550`（headline `$0.032831`；含 `parser_dev/mimo_test70_v1` 的 `$0.005034`），审计重算 delta `-0.000000318`。
- **I5**：v2 的 DeepSeek 已按 `$0.15/$0.60/$0.003` 配置，10/10 run 与 provider `list_cost` 在 2% 内一致；v1 的高峰价 `$0.30/$1.20` 与 `analysis/cost_normalization.md` 的 off-peak/normalized 口径一并记录。
- **L4**：`analysis/aggregation.json` 已用仓库内路径重生成（2026-11-12 04:48），14 个 run 路径均存在。
- **L5/I7**：v1 与 pre-leakfix 产物原样保留为对照；79 个 run / 9,584 条请求的 normalized 成本账 verification PASS、0 peak rows、0 changed source artifacts。

需要复核时在冻结工作树上重跑：

```bash
python3 audit/run_final_audit.py
grep -n '^Overall:' audit/final_audit.md
grep -n '^Checks:' audit/final_audit.md
```

预期 `Overall: **PASS_WITH_WARNINGS**`、`Checks: 58 PASS, 0 FAIL, 3 WARN, 1 INFO`。3 个 WARN 是 B5（Juliet bad/good 长度不对称，600.4 vs 937.9 字符）、D5（hybrid_v2 安慰剂 14/140 个 donor 文本与自身相同）、F4（repair prompt 仍含 `bad`/`CWE`/`Memory_Leak` 任务前提 token）；这些不阻断发布，但必须保留说明。

---

## 5. L1：从冻结 run 重算指标

### 5.1 统一 benchmark

`bench_metrics.py` 默认把 `metrics.json`/`metrics.md` 写在 run 目录；用 `--out-dir` 写到临时目录，避免覆盖。

```bash
python3 benchmark/tools/bench_metrics.py \
  --run-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent \
  --out-dir /tmp/secvul_check/tier_a_direct

python3 benchmark/tools/bench_metrics.py \
  --run-dir benchmark/results/tier_b/juliet_cwe401/static_clang/tierb_juliet_cwe401_static_clang_20261112_4c5800c4 \
  --out-dir /tmp/secvul_check/tier_b_clang
```

校验 run 结构/schema（可选 `--jsonschema`）：

```bash
python3 benchmark/tools/bench_validate.py \
  --run-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent \
  --jsonschema --json-out /tmp/secvul_check/validation.json
```

读取已冻结的两层 leaderboard：`benchmark/results/tier_a_leaderboard.md`、`tier_b_leaderboard.md`、`LEADERBOARD.md`。

> **当前已知不一致（2026-11-12）**：`benchmark/results/` 现含 16 个 Tier A run（12 个正式矩阵 + 4 个创新导入），`bench_tier_a_summary.py` 仍断言 12 个，直接运行会失败。`bench_tier_b_summary.py` 是历史 5-tool 视图，主动排除 round-2 LLM/hybrid/repair，不再因 `hybrid_*` 报 `KeyError`；Tier B 的完整 v2 结果看 `final_summary.json` 与 `LEADERBOARD.md`。若必须重算 Tier A，先把 12 个 canonical run **复制**（不要用符号链接，汇总脚本不跟随 symlink）到临时 `--runs-root`，输出到 `/tmp`；不要覆盖 `benchmark/results/`。

### 5.2 Tier A 三策略聚合

```bash
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --out-json /tmp/secvul_check/aggregation.json \
  --out-md /tmp/secvul_check/aggregation.md \
  --bootstrap 10000 --seed 42
```

预期：12 个 run 入组（DeepSeek/MiMo × 3 策略 × 2 任务），`bootstrap=10000`、`seed=42`；`status=ok`。如果出现 `no_real_runs`，说明扫描路径或 run 完整性不对，不要改用 `--allow-fixture`。

### 5.3 跨模型比较

```bash
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --out-json /tmp/secvul_check/aggregation.json \
  --out-md /tmp/secvul_check/aggregation.md

python3 report/scripts/fill_tables.py \
  runner/runs/test_v1_direct_independent runner/runs/test_v1_direct_pairs \
  runner/runs/test_v1_few-shot_independent runner/runs/test_v1_few-shot_pairs \
  runner/runs/test_v1_context_independent runner/runs/test_v1_context_pairs \
  --model deepseek-v4.1-flash
```

`analysis/model_comparison.json` 是已有的跨模型/跨策略专项产物；`analysis/analyze_runs.py` 只生成 `aggregation.json/.md`，不生成该文件。跨模型比较表也可从 `benchmark/tools/bench_tier_a_summary.py` 的 `comparisons.model` 读取（该脚本当前受 16-run 断言限制，见 §5.1）。不要手工改写 `model_comparison.json`；如需重算，先用临时 `--runs-root` 生成对比，再与现有 JSON 核对。

### 5.4 成本口径与 normalized

`analysis/cost_normalization/rebuild.py` 只读取已保存的 `results.jsonl` / `requests.jsonl` 和 manifest，不调用 API，也不改原始 `cost_usd`；它重写 `analysis/cost_normalization.{json,md}` 和 `analysis/cost_normalization/runs/` 的逐 run 台账：

```bash
python3 analysis/cost_normalization/rebuild.py
```

本机快照（2026-11-11）：73 个有 usage 的 run、9,584 条请求；71 个完整 run 的 configured 为 `$3.886970`、normalized 为 `$2.146513`，73 个 all-recorded 为 `$3.895167` / `$2.154710`。DeepSeek 的 `$0.30/$1.20` 是高峰价，`$0.15/$0.60` 是非高峰价；本批 peak rows=0。normalized 价卡为 DeepSeek `$0.15/$0.60/$0.003`、MiMo `$0.14/$0.28/$0.0028` per 1M tokens；allowance 是 provider 额度，不是账单。`hybrid_v2` 已直接按非高峰价配置，configured 与 normalized 相同。

---

## 6. L2：重跑传统静态/动态

### 6.1 静态（Juliet 200 单元）

前置：Clang 22.1.8；Cppcheck 2.21.0（系统包或用 `--cppcheck-bin` 指向解包二进制）；`juliet/raw/` 已恢复。

```bash
python3 traditional/static/static_adapter.py \
  --input juliet/subset_units.jsonl \
  --out traditional/static/runs/repro_clang_cppcheck \
  --tool both \
  --cppcheck-bin /path/to/cppcheck \
  --include-dir juliet/raw/testcasesupport \
  --assume-cwe CWE-401 --define _GNU_SOURCE \
  --clang-arg=-include --clang-arg=alloca.h \
  --timeout 120 --jobs 8 \
  --dataset-name juliet-cwe401-v1.3-subset-v1
```

- `--out` 必须是**不存在或空**的目录；适配器拒绝覆盖。
- 主结果使用 `_GNU_SOURCE` 对齐 Juliet 的 GNU 构建；`strict_c11` 对照会有 12 个 Clang 编译失败，不能当主结果。
- 预期：400 行 `predictions.jsonl`（200 单元 × 2 工具），Clang 194 ok / 6 `compile_error`，Cppcheck 200 ok / 4 FP。
- 重新生成 178 runtime-supported 子群：

```bash
python3 traditional/static/verified_subset.py \
  --manifest juliet/manifest.json \
  --predictions traditional/static/runs/repro_clang_cppcheck/predictions.jsonl \
  --out traditional/static/runs/repro_clang_cppcheck/metrics_verified.json
```

### 6.2 动态（Juliet 全量 3,316 case）

```bash
cd traditional/dynamic
python3 run_dynamic_eval.py check-tools --json
python3 run_dynamic_eval.py run \
  --juliet-root ../juliet/raw/testcases/CWE401_Memory_Leak \
  --support-dir ../juliet/raw/testcasesupport \
  --out runs/repro_asan_valgrind --run-id repro_asan_valgrind \
  --detectors asan,valgrind --jobs 8
```

- 本机全量耗时约 990.9 s（16.5 分钟，8 workers）。
- 预期：3,316 case（1,658 bad / 1,658 good），`results.jsonl` 3,316 行；合并 1,467 TP / 0 FP / 1,658 TN / 190 FN / 1 inconclusive；recall 0.8853、precision 1.000、accuracy 0.9427。
- 没有 Valgrind 时 `detectors.valgrind.status=unavailable`，不会被当成 clean；`check-tools` 会真实编译并运行泄漏/干净程序。
- `run_dynamic_eval.py selftest` 只创建临时程序并清理，不是正式结果。

### 6.3 重跑 Tier B 映射

```bash
python3 benchmark/tools/bench_collect_tier_b.py \
  --out-root /tmp/secvul_check/tier_b_runs
```

该工具把 `traditional/static` 与 `traditional/dynamic` 的产物只读映射到冻结 200 单元；`--out-root` 写到临时目录，避免覆盖 `benchmark/results/tier_b/`。若源 run 已存在，需显式 `--force`；不要用它覆盖正式结果。

---

## 7. L3：重跑 LLM / 混合 / 修复

### 7.1 凭证

所有 LLM 实验都从环境变量或本地 Kimi Code TOML 读取 key，**不写入任何产物**。推荐使用共享 wrapper：

```bash
export KIMI_CONFIG="/mnt/c/Users/<you>/.kimi-code/config.toml"
export KIMI_PROVIDER="opencode-go"     # 或 xiaomi
```

`runner/run_with_kimi_config.py` 会读取 `providers.<name>.api_key`，只放入子进程环境变量；`juliet_llm/launch.py` 复用同一路径。不要把 key 写进命令行、`.env`、脚本或 notebook。

> 可移植性注意：`pair_joint/run_pair_joint.sh`、`hybrid/run_hybrid.py` 和 `juliet_repair/scripts/run_repair.py` 的默认值把 config 路径写死为 `/mnt/c/Users/tzh03/.kimi-code/config.toml`。换机器/用户名时，先改脚本顶部或传 `--kimi-config`（支持该参数的工具）；仓库不包含该 TOML。

### 7.2 Tier A：runner

```bash
export SECVUL_MODEL="deepseek-v4.1-flash"

python3 runner/run_experiment.py \
  --dataset independent --dataset-file splits/test_detection_160.json \
  --strategy direct --task both \
  --model "$SECVUL_MODEL" \
  --base-url https://opencode.ai/zen/go/v1 \
  --api-key-env OPENCODE_API_KEY \
  --out-dir runner/runs/repro_direct_independent
```

`--resume` 只在配置指纹一致时复用缓存；`--limit` 会产生 `partial=true`，不能当正式结果。`temperature=0` 不保证服务端逐字节确定性。

### 7.3 Juliet LLM

```bash
KIMI_CONFIG="$KIMI_CONFIG" KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh run \
  --model mimo-v2.6-flash --split test --kind test \
  --tag xiaomi_official_postleakfix --concurrency 8
```

- 先跑 `python3 -m juliet_llm.build_inputs --out-dir /tmp/juliet_llm_build` 与 `python3 -m juliet_llm.selfcheck`。正式运行前默认 `build/` 必须与冻结输入一致；`build_inputs.py` 不加 `--out-dir` 会重写 `juliet_llm/build/`，先备份或确认可复现。
- 主结果是 prompt `.2`（`juliet-llm-binary-2026-11-12.2`）的 postleakfix 正式/复现 run：两者均 140/140 有效，accuracy 0.9500、F1 0.9510、MCC 0.9008；修复前的 0.9571 只作为历史对照保留。
- MiMo 必须用 `max_completion_tokens` + `reasoning_effort=none`；`max_tokens` 会被忽略，推理可能耗尽输出预算。
- 本实验的 DeepSeek 140 test 因 `401 api_key_expired` / `402` / `403` **没有完成**；MiMo 140 是 Xiaomi 官方端点 fallback，不是 OpenCode Go。复现时不要把两者混为一谈。

### 7.4 Hybrid 证据（v2 主结果）

```bash
python3 hybrid/build_inputs.py --out hybrid/inputs_v2
python3 hybrid/preflight.py --inputs-dir hybrid/inputs_v2 --run-id hybrid_v2
python3 hybrid/run_hybrid.py --model all --inputs-dir hybrid/inputs_v2 \
  --run-id hybrid_v2 --concurrency 12 \
  --preflight-report hybrid/results/hybrid_v2_preflight.json
python3 hybrid/analyze.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2
python3 hybrid/verify_outputs.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2 --out hybrid/results/hybrid_v2_audit.json
```

预期：5 方法 × 140 单元 × 2 模型 = 1,400 请求；`ok=1400`、`invalid=0`、`api_error=0`；prompt 版本 `hybrid-v2-juliet-llm-binary-2026-11-12.2`。v1（`hybrid/inputs`、`hybrid/runs/hybrid_v1_*`）保留只读，不再作为主结果。`--dry-run` 只审计 prompt，不发请求；默认 `--out hybrid/inputs` 会重写已跟踪的 v1 输入包，验证时请用单独的 `/tmp` 目录或 `hybrid/inputs_v2`。

### 7.5 Pair-joint A/B

```bash
python3 pair_joint/selftest.py
bash pair_joint/run_pair_joint.sh pilot
bash pair_joint/run_pair_joint.sh full
python3 -m pair_joint.analyze \
  --run-dir pair_joint/runs/test_deepseek_180 \
  --run-dir pair_joint/runs/test_mimo_180 \
  --out-dir /tmp/pair_joint_results \
  --bootstrap 10000 --seed 42
```

预期：每个模型 180 请求，`status=ok` 180/180；A/B 映射 90/90 平衡；`position_map.json` 两模型一致。

### 7.6 Evidence-prompt

```bash
python3 evidence_prompt/selftest.py
bash evidence_prompt/run_evidence.sh deepseek dryrun
bash evidence_prompt/run_evidence.sh mimo dryrun
bash evidence_prompt/run_evidence.sh deepseek test
bash evidence_prompt/run_evidence.sh mimo test
python3 evidence_prompt/analyze.py --out-dir /tmp/evidence_analysis
```

预期：每个模型 160 检测请求；DeepSeek 159 valid / 1 invalid；MiMo 158 valid / 2 invalid；0 API error。`dryrun` 不调用 API。

### 7.7 Juliet 修复

```bash
python3 juliet_repair/scripts/prepare_inputs.py --force
python3 juliet_repair/scripts/check_baselines.py --jobs 8 --force
python3 juliet_repair/scripts/run_repair.py --model deepseek --concurrency 8 \
  --out-dir juliet_repair/runs/repro_deepseek
python3 juliet_repair/scripts/report.py --run juliet_repair/runs/repro_deepseek \
  --out /tmp/repair_report.md
python3 juliet_repair/scripts/audit.py --run juliet_repair/runs/repro_deepseek
```

- `prepare_inputs.py` / `check_baselines.py` 默认拒绝覆盖已有冻结输入；`--force` 只用于明确重建。
- 每个单元一次初始请求，失败后至多一次反馈；`strict_pass` 只在 baseline 可观测泄漏时定义。
- 预期：70/70 编译、70/70 LSan 干净、70/70 行为保持；58 个可观测单元 58/58；全 70 的 strict 为 58/70。

### 7.8 修复盲评

```bash
python3 -m repair_eval selftest
python3 -m repair_eval build \
  --results <run_direct>/results.jsonl <run_fewshot>/results.jsonl <run_context>/results.jsonl \
  --dataset datasets/vulnerable_fixed_200_pairs.json \
  --out-dir repair_eval/packages/repro_blind \
  --seed 20261111 --pairs 30
```

正式包需要两位评分者和第三人裁决；`repair_eval/analysis/repair_blind_v1/final/summary.md` 是已完成的 LLM 辅助盲评汇总（30 案例 / 81 候选 / VR=2 17/81），不是人类评审。

---

## 8. 报告与 PDF

```bash
python3 report/scripts/check_tex.py          # 静态检查
# 若本机有 Tectonic：
/tmp/secvul-tectonic/tectonic -X compile report/report_zh.tex --outdir report --keep-intermediates
pdfinfo report/report_zh.pdf | head -5
```

预期：`Pages: 17`，无 unresolved references/citations，无缺字。报告源稿中的唯一 `TODO` 是作者/单位信息，不是结果占位。

---

## 9. 验收清单

发布或提交前逐项确认：

- [ ] `python3 benchmark/tools/selftest.py` 等 L0 自检全部通过（见 §4.1）。
- [ ] `bench_validate_dataset.py --jsonschema` 返回 `ok: true`，200 units / 42 families。
- [ ] `juliet/scripts/verify.py` 在恢复 raw 后输出 `PASS`。
- [ ] 关键数据文件哈希与 §2.3 一致（`sha256sum` 逐项）。
- [ ] `git status` 中没有 `juliet/raw/`、`juliet/cache/`、`juliet/build/`、`traditional/dynamic/runs/*/cases/`、`**/runs/*/cache/`、`__pycache__/`。
- [ ] `git ls-files` 中没有 >100 MB 文件；本地 `juliet/cache` 的 146 MB 归档是未跟踪缓存，`find` 会看到但不应被提交。
- [ ] secret scan 无 `sk-...` / `Bearer ...` / `api_key` 值泄漏；`repair_eval/packages/*/private/` 未被跟踪。
- [ ] `report/report_zh.pdf` 可打开，`pdfinfo` 显示 17 页。
- [ ] `audit/final_audit.md` 为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO**、Overall `PASS_WITH_WARNINGS`；C3/D6/I3/I5/L4 已关闭，B5/D5/F4 的 WARN 说明保留。
- [ ] `benchmark/results/tier_a_leaderboard.md`、`tier_b_leaderboard.md` 与 `tier_a_summary.json`、`tier_b_summary.json` 时间戳/内容一致。
- [ ] 没有把 Tier A 与 Tier B 的数字合并成“总排行榜”。

> 本指南作者没有执行 `git`/`gh` 命令；上述 git 检查留给发布者执行。

---

## 10. 常见坑

1. **Windows 路径 / WSL 路径**：项目在 `/mnt/c/Users/<you>/Downloads/cs224proj`；不要在 Windows Python 下运行（`pandas`/`openpyxl` 环境不同）。所有 Python/编译器命令都在 WSL 中执行。
2. **CRLF 与哈希**：`.gitattributes` 对 `*.json`/`*.jsonl` 设置 `-text`，防止 checkout 改变字节；不要手工把 JSON 转成 CRLF。`juliet/raw/` 的 C 源码是 CRLF，哈希按原始字节计算，`fetch_juliet.py` 会保留。
3. **`juliet/SHA256SUMS` 校验失败**：先确认 `juliet/raw/` 已恢复；未恢复时失败是预期的，不要修改清单。
4. **Cppcheck 找不到 `std.cfg`**：解包到 `/tmp` 后需要把二进制中的 `FILESDIR` 指向 cfg 目录，或直接安装系统包；详见 `traditional/static/README.md` §1。
5. **Valgrind 不在 PATH**：用 `--valgrind-bin` + `VALGRIND_LIB` 指向解包目录；没有 Valgrind 时状态是 `unavailable`，不是 `clean`。
6. **MiMo 输出为空/截断**：`max_tokens` 被忽略；必须用 `--max-tokens-field max_completion_tokens --reasoning-effort none`。OpenCode Go 上 `thinking=disabled` 也可能被忽略。
7. **DeepSeek 401/402/403**：先确认凭证与端点；不要用过期 key 重跑全量，也不要用 mock/其他模型冒充。
8. **`bench_metrics.py` 拒绝覆盖**：默认不覆盖已有 `metrics.json`；用 `--out-dir` 或 `--force`（仅在明确要重写时）。
9. **`bench_tier_a_summary.py` 当前不能直接重跑**：脚本仍按 12 个 Tier A canonical run 断言；`benchmark/results/` 已扩展到 16 个，会报 `expected 12 ... found 16`。`bench_tier_b_summary.py` 是历史 5-tool 视图，主动排除 round-2 LLM/hybrid/repair，不再报 `KeyError`；Tier B 的完整结果看 `final_summary.json`。重算 Tier A 时用 `--out-json`/`--out-md` 指向 `/tmp`，并只在临时 `--runs-root` 放 12 个 canonical run；不要覆盖 `benchmark/results/`。
10. **`juliet_llm/selfcheck.py` 相对导入**：用 `python3 -m juliet_llm.selfcheck`，不要直接运行文件。
11. **`repair_eval verify` 需要 private key**：公开仓库不含 `repair_eval/packages/*/private/`；只在保留 private 的原始工作区运行。
12. **Tectonic 不在 PATH**：本机在 `/tmp/secvul-tectonic/tectonic`；换机器需安装 Tectonic 或 TeX Live。
13. **`output/pdf/` 是空目录**：Git 不跟踪空目录；提交报告请用 `report/report_zh.pdf` 或显式放文件。

---

## 11. 不能逐字节复现的部分

- **模型输出**：`temperature=0` 不保证服务端确定性；MiMo 修复前两次真实运行为 0.9571 vs 0.9500，修复后两次都是 0.9500，但 2 个 bad 单元判定不同（混淆矩阵相同）。`hybrid_v2` 的 134 个未清洗单元中仍有 1 条预测翻转。重跑只能验证管线与量级，不能要求逐字节一致。
- **端点/价格**：OpenCode Go 的模型路由、价格、`x-opencode-session` 行为可能变化；成本按运行日价格快照计算，不是长期报价。
- **随机分支**：约 256 个 Juliet 文件用 `srand(time(NULL))` + `rand()%2` 选分支；动态结果是单次真实运行样本，190 个 FN 中有 14 个归因于随机分支。
- **Valgrind 版本/配置**：不同版本的 leak kind 分类与 still-reachable 语义可能不同；正式结果记录 3.27.1。
- **LLM 盲评**：`repair_eval` 的评分是 LLM 辅助、主观 rubric；κ 只说明一致性，不说明正确性。

---

## 12. 产物索引

| 产物 | 路径 |
| --- | --- |
| 两层 leaderboard | `benchmark/results/LEADERBOARD.md`、`tier_a_leaderboard.md`、`tier_b_leaderboard.md` |
| Tier A 机器可读汇总 | `benchmark/results/tier_a_summary.json` |
| Tier B 机器可读汇总 | `benchmark/results/tier_b_summary.json` |
| 三策略统计 | `analysis/aggregation.json`、`aggregation.md` |
| 跨模型比较 | `analysis/model_comparison.json`、`model_comparison.md` |
| 联合 A/B | `pair_joint/report.md`、`pair_joint/results/comparison.json` |
| 证据提示 | `evidence_prompt/analysis/metrics.json`、`report.md` |
| 工具证据（v2 主结果） | `hybrid/REPORT_V2.md`、`hybrid/results/hybrid_v2_metrics.json`、`hybrid_v2_tables.md`、`hybrid_v2_audit.json` |
| 工具证据（v1 对照） | `hybrid/REPORT.md`、`hybrid/results/hybrid_v1_metrics.json` |
| 成本归一化 | `analysis/cost_normalization.md`、`analysis/cost_normalization.json`、`analysis/cost_normalization/runs/` |
| Juliet 修复 | `juliet_repair/report/comparison.md`、`runs/*_final/summary.json` |
| Juliet LLM | `juliet_llm/runs/*_postleakfix*/metrics.json`、`metrics.md`；修复前结果保留在 `runs/*_final/` |
| 修复盲评 | `repair_eval/analysis/repair_blind_v1/final/summary.json`、`summary.md` |
| 传统静态 | `traditional/static/runs/*/metrics.json`、`metrics.md` |
| 传统动态 | `traditional/dynamic/runs/*/metrics.json`、`metrics.md`、`results.jsonl` |
| 最终审计 | `audit/final_audit.json`、`final_audit.md`（58 PASS / 0 FAIL / 3 WARN / 1 INFO，`PASS_WITH_WARNINGS`；见 §4.4） |
| 报告 | `report/report_zh.tex`、`report_zh.pdf`、`results_summary.md` |
| 创新结论分级 | `research/innovation_findings.md` |
